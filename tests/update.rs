//! AC-054 (REQ-044): an update replaces the product base and keeps the
//! user's own state by meaning. A new base fixes one scenario while a
//! compatible personal delta fixes another, both observed in one process;
//! explicit off/pins/disables/deletions survive; the receipt classifies every
//! persistent asset this build writes; a base whose predecessor is not the
//! recorded one is refused typed; and an interrupted cutover leaves the
//! previous base serving with the new one staged (PROH-004, EDGE-005,
//! EDGE-006, INV-005, INV-010a).
//!
//! The cutover's own recoveries are proved here too: a checkpoint this build
//! cannot resume is replaced by the document it offers — including through the
//! production open, which reports the discard — while the refusals that must win
//! (a changed recorded document, a newer build's checkpoint, a skipped step)
//! keep the ledger exactly as it was.
//!
//! Every case drives the production seams — the base document seam
//! (`resolve_effective_on`/`composed`), `Broker::prepare` for the request the
//! update's outcome shows up in, `TaskStore` for the ledger and the receipt,
//! `Runtime::open` for the cutover a real start runs, and `runtime.status` for
//! the served payload — and asserts a durable, positive observation. The
//! loopback provider is the only provider; no network and no credential is
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

use rivect::commands::Runtime;
use rivect::config::{
    self, BaseSource, ConfigIssue, EffortAssign, EffortLevel, ModelAssign, SHIPPED_BASE_VERSION,
    SHIPPED_DEFAULTS_TOML, UpdateState,
};
use rivect::contracts::ErrorCode;
use rivect::learning::{
    ConditionFact, ConditionFacts, CorpusCase, DeltaCandidate, DeltaChange, DeltaError,
    DeltaPayload, DeltaState,
};
use rivect::model::Broker;
use rivect::providers::LoopbackProvider;
use rivect::state::{StoreError, TaskStore};
use rivect::update::{
    CleanupState, EmitMapCollision, EvidenceStore, Failure, FailureReason, SECONDARY_MAX,
    StoreTuple, Terminal, UpdateBoundary, UpdateError, UpdateEvidence, UpdatePhase,
    discard_checkpoint, owner_refusal_diagnostics, snapshot, validate_emit_map,
};
use serde_json::{Value, json};
use std::path::Path;

const WORLD: &str = "/world/update";
const SUBJECT_PURPOSE: &str = "main";
const PROBE_PURPOSE: &str = "review";
const PROBE: &str = "probe-purpose";
const PROBE_TEXT: &str = "the review purpose runs one mechanical leg before its report";
const DELTA_TEXT: &str =
    "carry the chosen form into the first paragraph before the explanation begins";
const DELTA: &str = "carry-chosen-form";

// ----- fixtures -----

/// A user document that declares only what is the user's to declare: its
/// connection and the default model slots the file schema requires. Everything
/// a base can supply stays with the base, so the two layers are told apart by
/// their own values rather than by a re-spelling.
fn user_config(extra: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.local]\n\
         kind = \"local\"\n\
         endpoint = \"http://127.0.0.1:11434\"\n\
         [models.defaults]\n\
         model = {{ mode = \"auto\" }}\n\
         effort = {{ mode = \"auto\" }}\n\
         fallback = {{ mode = \"auto\" }}\n\
         {extra}"
    )
}

/// One base document: the shipped defaults plus a purpose row, so a new base
/// can carry the fix for a scenario without touching the user's document.
fn base_document(purpose: &str) -> String {
    format!(
        "config_version = 1\n\
         [workflow]\n\
         enabled = true\n\
         [decisions]\n\
         mode = \"ask\"\n\
         [context]\n\
         auto_compact = false\n\
         [models.defaults]\n\
         model = {{ mode = \"auto\" }}\n\
         effort = {{ mode = \"auto\" }}\n\
         fallback = {{ mode = \"auto\" }}\n\
         {purpose}"
    )
}

/// The base this build ships: no purpose row, so the defaults answer.
fn base_v1() -> String {
    base_document("")
}

/// The next base: it fixes the scenario the defaults left under-powered by
/// naming the subject purpose's effort, and moves the context guard's default.
fn base_v2() -> String {
    base_document(
        "[models.purposes.main]\n\
         effort = { mode = \"fixed\", value = \"high\" }\n",
    )
    .replace("auto_compact = false", "auto_compact = true")
}

fn temp_root(prefix: &str) -> tempfile::TempDir {
    tempfile::TempDir::with_prefix(format!("rivect-update-{prefix}-")).expect("fixture root")
}

fn open_store(root: &Path) -> TaskStore {
    TaskStore::open(&root.join("state.db")).expect("store opens")
}

fn install(root: &Path, source: BaseSource<'_>) -> config::BaseInstall {
    config::BaseInstall::new(source, root.join("config.toml"), root)
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

fn candidate(delta_id: &str, change: DeltaChange) -> DeltaCandidate {
    DeltaCandidate {
        delta_id: delta_id.to_string(),
        base_version: 1,
        change,
        evidence: format!("tests/update.rs {delta_id}"),
    }
}

/// The control delta the negative-control case names: a recorded experience
/// that provably applies to its own purpose.
fn probe_candidate() -> DeltaCandidate {
    candidate(PROBE, instruction(PROBE_TEXT, Some(PROBE_PURPOSE)))
}

fn instruction_corpus() -> Vec<CorpusCase> {
    vec![
        CorpusCase::Transfer {
            facts: ConditionFacts::for_purpose(SUBJECT_PURPOSE),
        },
        CorpusCase::Composition {
            facts: ConditionFacts::for_purpose(SUBJECT_PURPOSE),
        },
        CorpusCase::NegativeControl {
            facts: ConditionFacts::for_purpose(PROBE_PURPOSE),
            control: PROBE.to_string(),
        },
    ]
}

/// Records, judges and activates the personal delta — the lifecycle a verified
/// low-risk experience takes — and returns the definition the store composes.
fn verified_delta(store: &mut TaskStore) -> rivect::learning::LearningDefinition {
    if store.learning_delta(PROBE).is_err() {
        store
            .record_learning_delta(&probe_candidate())
            .expect("probe delta recorded");
    }
    store
        .record_learning_delta(&candidate(
            DELTA,
            instruction(DELTA_TEXT, Some(SUBJECT_PURPOSE)),
        ))
        .expect("candidate recorded");
    let verdicts = store
        .record_learning_corpus(DELTA, &instruction_corpus())
        .expect("corpus recorded");
    assert!(
        verdicts.iter().all(|verdict| verdict.passed),
        "the delta's corpus must pass: {verdicts:?}"
    );
    store.activate_learning_delta(DELTA, 1).expect("activation")
}

// ----- p1: one process observes both effects -----

/// AC-054: the new base's effort for the subject purpose and the personal
/// delta's instruction part both reach the request in one process, after the
/// store recorded the cutover — no restart and no second resolver.
#[test]
fn joint_run_observes_both_effects_p1() {
    let root = temp_root("p1");
    std::fs::create_dir_all(root.path().join("store")).expect("store dir");
    let mut store = open_store(&root.path().join("store"));
    store
        .serve_base(&install(root.path(), BaseSource::new(1, &base_v1())))
        .expect("the first base is recorded");

    let definition = verified_delta(&mut store);
    let user = user_config("");
    let mut broker = broker();
    broker.set_learning_definition(definition.clone());

    let before = config::resolve_effective_on(BaseSource::new(1, &base_v1()), Some(&user))
        .expect("the served base resolves");
    assert_eq!(
        before.base_version(),
        1,
        "the resolved layer names the base it read"
    );
    let first = broker
        .prepare(SUBJECT_PURPOSE, &before.composed(), WORLD, "goal: explain")
        .expect("first prepare");
    assert_eq!(
        first.effort,
        EffortAssign::Auto,
        "the first base leaves the purpose's effort at the defaults"
    );
    assert!(
        first.instructions.contains(DELTA_TEXT),
        "the personal delta already applies: {}",
        first.instructions
    );

    // The update: the new base arrives through the seam, the ledger records it
    // and the same store still composes the personal delta.
    let served = store
        .serve_base(&install(root.path(), BaseSource::new(2, &base_v2())))
        .expect("the new base is recorded");
    assert_eq!(served.receipt.base_version, 2);
    assert_eq!(served.receipt.state, UpdateState::Active);
    assert_eq!(
        served.abandoned, None,
        "an update over a ledger with no checkpoint discards nothing"
    );
    assert_eq!(
        store
            .active_base()
            .expect("base read")
            .map(|base| base.version),
        Some(2),
        "the ledger serves the new base"
    );

    let after = config::resolve_effective_on(BaseSource::new(2, &base_v2()), Some(&user))
        .expect("the new base resolves");
    assert_eq!(
        after.base_version(),
        2,
        "the resolved layer and the ledger name one base"
    );
    let second = broker
        .prepare(SUBJECT_PURPOSE, &after.composed(), WORLD, "goal: explain")
        .expect("second prepare");

    // Scenario A, fixed by the new base: the subject purpose's effort.
    assert_eq!(
        second.effort,
        EffortAssign::Fixed {
            value: EffortLevel::High
        },
        "the new base's purpose row reaches the request"
    );
    // Scenario B, fixed by the personal delta: the instruction part.
    assert!(
        second.instructions.contains(DELTA_TEXT),
        "the compatible delta still applies after the update: {}",
        second.instructions
    );
    assert_eq!(
        broker.accounted_requests(),
        0,
        "neither effect costs a model call: the base is a document and the condition is code"
    );
    assert_eq!(
        store.learning_status().expect("status").active.len(),
        1,
        "the update leaves the activated delta active"
    );
}

// ----- p2: explicit settings survive by meaning -----

/// AC-054: `workflow: false`, a model/effort pin, a disabled delta and a
/// deletion each keep their own meaning across the update — the layer that
/// supplied a value decides it, never a comparison against the new base.
#[test]
fn explicit_settings_survive_by_meaning_p2() {
    let root = temp_root("p2");
    std::fs::create_dir_all(root.path().join("store")).expect("store dir");
    let mut store = open_store(&root.path().join("store"));
    store
        .serve_base(&install(root.path(), BaseSource::new(1, &base_v1())))
        .expect("the first base is recorded");

    // The disabled experience: it was rolled back before the update, and the
    // tombstone is the user's decision, not a candidate the base may revive.
    let definition = verified_delta(&mut store);
    store
        .roll_back_learning_delta(DELTA, 2)
        .expect("the delta is withdrawn");

    // The user's own document: an explicit off, a pin on both slots of the
    // subject purpose, and no `[context]` table at all — the guard override was
    // deleted rather than set to the base's old value.
    let user = user_config(
        "[workflow]\n\
         enabled = false\n\
         [models.purposes.main]\n\
         model = { mode = \"fixed\", connection = \"local\", model_id = \"pinned-model\" }\n\
         effort = { mode = \"fixed\", value = \"low\" }\n",
    );
    assert!(
        !user.contains("[context]"),
        "the fixture's guard override is a deletion, not a value"
    );

    let before = config::resolve_effective_on(BaseSource::new(1, &base_v1()), Some(&user))
        .expect("v1 resolves");
    assert_eq!(
        before.workflow_entry.source.kind, "user",
        "an explicit off is the user's layer"
    );
    let served = store
        .serve_base(&install(root.path(), BaseSource::new(2, &base_v2())))
        .expect("the update runs");
    assert_eq!(served.receipt.state, UpdateState::Active);

    let after = config::resolve_effective_on(BaseSource::new(2, &base_v2()), Some(&user))
        .expect("v2 resolves");
    // 1. Off survives: the new base says `true`, the user said `false`.
    assert_eq!(
        after.workflow_entry.effective,
        config::ConfigViewValue::Visible {
            value: Value::Bool(false)
        },
        "workflow: false survives the new base"
    );
    assert_eq!(
        after.workflow_entry.source.kind, "user",
        "the off keeps its own layer after the update"
    );
    assert_eq!(
        after.composed().workflow.enabled,
        Some(false),
        "the dispatch view still carries the explicit off"
    );
    // 2. The pin survives: both slots stay the user's, not the base's new row.
    let purpose = after
        .composed()
        .resolve_purpose(SUBJECT_PURPOSE)
        .expect("the purpose resolves");
    assert_eq!(
        purpose.model,
        ModelAssign::Fixed(config::FixedModel {
            connection: "local".to_string(),
            model_id: "pinned-model".to_string(),
        }),
        "the pinned model survives"
    );
    assert_eq!(
        purpose.effort,
        EffortAssign::Fixed {
            value: EffortLevel::Low
        },
        "the pinned effort survives over the base's new purpose row"
    );
    assert_eq!(
        purpose.effort_source, "models.purposes.main",
        "the pin keeps the layer that supplied it"
    );
    // 3. The disable survives: the withdrawn delta is still withdrawn and is
    // not part of the definition the next request composes.
    let status = store.learning_status().expect("status");
    assert_eq!(
        status.rolled_back.len(),
        1,
        "the tombstone survives the update: {status:?}"
    );
    assert_eq!(status.rolled_back[0].delta_id, DELTA);
    assert!(
        status.active.is_empty(),
        "the withdrawn delta did not come back active: {status:?}"
    );
    assert!(
        store
            .learning_definition()
            .expect("definition")
            .deltas()
            .iter()
            .all(|delta| delta.delta_id != DELTA),
        "a disabled delta contributes nothing to the next request"
    );
    assert!(
        definition
            .deltas()
            .iter()
            .any(|delta| delta.delta_id == DELTA),
        "the fixture's delta was part of the definition before it was withdrawn"
    );
    // 4. The deletion survives: the user layer still carries no guard override,
    // and the new base's default answers in its place.
    assert_eq!(
        after
            .parsed
            .as_ref()
            .expect("the user document is parsed")
            .context
            .auto_compact,
        None,
        "the deleted override stayed deleted instead of being restored"
    );
    assert!(
        after.composed().auto_compact(),
        "the new base's guard default answers where the user deleted their override"
    );
    assert!(
        !after.retained().auto_compact(),
        "the base's guard default never reads as a value the user set"
    );
}

// ----- p3: the receipt classifies every asset that exists here -----

/// AC-054/REQ-044: the receipt served on `runtime.status` names each persistent
/// asset this build writes — config file, SQLite rows, workspace directories and
/// index rows — with the policy the update follows for it, and names nothing
/// this build does not write.
#[test]
fn receipt_classifies_every_existing_asset_p3() {
    let mut world = support::open_world("update-p3", Some(&user_config("")));
    let session = world.open_session("update-bootstrap-p3");
    let response: Value = world.dispatch(&support::corpus_status(&session));
    assert!(response["error"].is_null(), "runtime.status: {response}");
    let update = &response["result"]["update"];

    assert_eq!(
        update["base_version"],
        json!(SHIPPED_BASE_VERSION),
        "the served base version is the one this build compiles in: {update}"
    );
    let receipt = &update["receipt"];
    assert_eq!(receipt["base_version"], json!(SHIPPED_BASE_VERSION));
    assert_eq!(
        receipt["state"], "active",
        "a completed install serves, it is not left staged: {receipt}"
    );
    let assets = receipt["assets"]
        .as_array()
        .expect("the receipt has assets");
    let names: Vec<&str> = assets
        .iter()
        .map(|asset| asset["asset"].as_str().expect("asset name"))
        .collect();
    assert_eq!(
        names,
        vec![
            "config_file",
            "sqlite_rows",
            "workspace_directories",
            "index_rows"
        ],
        "every asset that exists in this build is classified, in the canonical order"
    );
    let policies: Vec<&str> = assets
        .iter()
        .map(|asset| asset["policy"].as_str().expect("asset policy"))
        .collect();
    assert_eq!(
        policies,
        vec!["merge_by_meaning", "preserve", "preserve", "rebuild"],
        "each asset carries the policy the update follows for it"
    );
    let config_file = assets[0]["location"]
        .as_str()
        .expect("the config file location");
    assert!(
        config_file.ends_with("config.toml"),
        "the receipt names the user's config file: {config_file}"
    );
    assert!(
        Path::new(config_file).is_absolute(),
        "the location is a real path, not a label: {config_file}"
    );
    let sqlite = assets[1]["location"].as_str().expect("the sqlite location");
    assert!(
        sqlite.ends_with("rivect.db"),
        "the receipt names the database this build writes: {sqlite}"
    );
    assert_eq!(
        assets[2]["location"].as_str(),
        Some(world.root.to_str().expect("utf-8 root")),
        "the directory tree the runtime writes is classified where it is"
    );
    assert!(
        !receipt.to_string().contains("installer"),
        "the installer's artifact list belongs to position 10, not here: {receipt}"
    );
    // The receipt is the serving base's, and the store agrees with it.
    assert_eq!(
        world
            .runtime
            .store()
            .active_base()
            .expect("base read")
            .map(|base| base.version),
        Some(SHIPPED_BASE_VERSION)
    );
    assert!(
        response["result"]["base_recovery"].is_null(),
        "an open that had no checkpoint to clear reports no recovery: {response}"
    );
}

// ----- p4: a skipped base version is refused -----

/// EDGE-005: the offered base's predecessor is not the recorded base, so a
/// supported step is missing. The refusal is typed and durable state is
/// unchanged: the recorded base still serves and nothing was staged.
#[test]
fn skipped_base_version_is_refused_p4() {
    let root = temp_root("p4");
    std::fs::create_dir_all(root.path().join("store")).expect("store dir");
    let mut store = open_store(&root.path().join("store"));
    store
        .serve_base(&install(root.path(), BaseSource::new(1, &base_v1())))
        .expect("the first base is recorded");
    store
        .serve_base(&install(root.path(), BaseSource::new(2, &base_v2())))
        .expect("the second base is recorded");

    // v4's predecessor is v3, which this ledger never recorded: v3 is skipped.
    let refused = store
        .serve_base(&install(root.path(), BaseSource::new(4, &base_v2())))
        .expect_err("a skipped base version is refused");
    let message = refused.to_string();
    assert!(
        message.contains("base version"),
        "the refusal names the version domain: {message}"
    );
    assert_eq!(
        refused.code(),
        ErrorCode::Conflict,
        "the base version domain carries its own code"
    );
    // Read the durable value back: nothing applied, nothing staged.
    assert_eq!(
        store
            .active_base()
            .expect("base read")
            .map(|base| base.version),
        Some(2),
        "the recorded base still serves after the refusal"
    );
    assert_eq!(
        store.staged_base().expect("staged read"),
        None,
        "a refused base leaves nothing staged"
    );
    assert!(
        store.update_receipt(4).is_err(),
        "the refused base has no receipt a later run could resume from"
    );
    assert_eq!(
        store.update_receipt(2).expect("the recorded receipt").state,
        UpdateState::Active
    );

    // A cutover of a version the ledger never staged moves nothing either: the
    // retirement of the serving base is part of the same transaction, so a
    // refused cutover cannot leave a store with no base at all.
    let unstaged = store
        .commit_base(5)
        .expect_err("a version that was never staged cannot cut over");
    assert!(unstaged.to_string().contains("not staged"), "{unstaged}");
    assert_eq!(
        store
            .active_base()
            .expect("base read")
            .map(|base| base.version),
        Some(2),
        "the refused cutover rolled back the retirement of the serving base"
    );

    // The neighbour that does not skip is still accepted, so the refusal is
    // about the missing step and not about updates in general.
    store
        .serve_base(&install(root.path(), BaseSource::new(3, &base_v2())))
        .expect("the next step is accepted");
    assert_eq!(
        store
            .active_base()
            .expect("base read")
            .map(|base| base.version),
        Some(3)
    );
}

// ----- p5: an interrupted cutover stages the new base -----

/// EDGE-006/PROH-004: an update that stops between staging and cutover leaves
/// the previous base serving, the new one staged and its checkpoint readable —
/// no file is rewritten in place, so the interrupted state is a resumable one.
#[test]
fn interrupted_update_stages_the_new_base_p5() {
    let root = temp_root("p5");
    std::fs::create_dir_all(root.path().join("store")).expect("store dir");
    let path = root.path().join("store").join("state.db");
    {
        let mut store = TaskStore::open(&path).expect("store opens");
        store
            .serve_base(&install(root.path(), BaseSource::new(1, &base_v1())))
            .expect("the first base is recorded");
        let staged = store
            .stage_base(&install(root.path(), BaseSource::new(2, &base_v2())))
            .expect("the new base stages");
        assert_eq!(staged.state, UpdateState::Staged);
        // The run stops here: the process ends before the cutover.
    }

    let mut store = TaskStore::open(&path).expect("the store reopens");
    assert_eq!(
        store
            .active_base()
            .expect("base read")
            .map(|base| base.version),
        Some(1),
        "the previous base still serves after the interruption"
    );
    assert_eq!(
        store
            .staged_base()
            .expect("staged read")
            .map(|base| base.version),
        Some(2),
        "the new base is staged, not applied"
    );
    let checkpoint = store.update_receipt(2).expect("the checkpoint is readable");
    assert_eq!(checkpoint.state, UpdateState::Staged);
    assert_eq!(
        checkpoint.assets.len(),
        config::UPDATE_ASSETS.len(),
        "the staged checkpoint classifies every asset: {checkpoint:?}"
    );
    assert_ne!(
        checkpoint.digest,
        store.update_receipt(1).expect("the serving receipt").digest,
        "the staged checkpoint belongs to the new base's bytes"
    );

    // A re-run offering different bytes for the staged version would rewrite
    // the checkpoint: the staged document is the one its receipt names, so it
    // is refused and the checkpoint still names the first document.
    let other =
        base_document("[models.purposes.main]\neffort = { mode = \"fixed\", value = \"low\" }\n");
    let refusal = store
        .stage_base(&install(root.path(), BaseSource::new(2, &other)))
        .expect_err("the staged checkpoint is not rewritten in place");
    assert!(refusal.to_string().contains("already staged"), "{refusal}");
    assert_eq!(
        store
            .staged_base()
            .expect("staged read")
            .map(|base| base.digest),
        Some(BaseSource::new(2, &base_v2()).digest()),
        "the checkpoint still belongs to the stage that arrived first"
    );

    // The safe re-run resumes the staged cutover instead of replaying it.
    let resumed = store
        .serve_base(&install(root.path(), BaseSource::new(2, &base_v2())))
        .expect("the re-run resumes");
    assert_eq!(resumed.receipt.state, UpdateState::Active);
    assert_eq!(resumed.abandoned, None, "the checkpoint was resumed");
    assert_eq!(
        store.update_receipt(2).expect("receipt").assets.len(),
        config::UPDATE_ASSETS.len(),
        "the re-run did not duplicate the receipt's asset rows"
    );
    assert_eq!(
        store
            .active_base()
            .expect("base read")
            .map(|base| base.version),
        Some(2),
        "the resumed run cut over to the new base"
    );
    assert_eq!(
        store.update_receipt(1).expect("receipt").state,
        UpdateState::Retired,
        "the previous base stops serving once the new one commits"
    );
}

// ----- p6: an incompatible delta stays inactive with its diagnosis -----

/// INV-005: a delta whose judgement failed stays inactive, keeps its recorded
/// diagnosis and does not disappear when the base moves — a conflict is a
/// temporary state, never a deletion.
#[test]
fn incompatible_delta_stays_inactive_with_its_diagnosis_p6() {
    let root = temp_root("p6");
    std::fs::create_dir_all(root.path().join("store")).expect("store dir");
    let mut store = open_store(&root.path().join("store"));
    store
        .serve_base(&install(root.path(), BaseSource::new(1, &base_v1())))
        .expect("the first base is recorded");
    store
        .record_learning_delta(&probe_candidate())
        .expect("probe recorded");

    // The candidate would apply to the subject purpose but its corpus asks it
    // to transfer to a purpose it does not apply to: the case fails.
    store
        .record_learning_delta(&candidate(
            "conflicting",
            instruction("a conflicting instruction", Some(SUBJECT_PURPOSE)),
        ))
        .expect("candidate recorded");
    let verdicts = store
        .record_learning_corpus(
            "conflicting",
            &[CorpusCase::Transfer {
                facts: ConditionFacts::for_purpose(PROBE_PURPOSE),
            }],
        )
        .expect("corpus recorded");
    assert!(
        verdicts.iter().any(|verdict| !verdict.passed),
        "the fixture's case fails: {verdicts:?}"
    );
    let refused = store
        .activate_learning_delta("conflicting", 1)
        .expect_err("a failed corpus activates nothing");
    assert!(
        matches!(
            refused,
            StoreError::Delta(DeltaError::CorpusRejected { .. })
        ),
        "the activation names the case that failed: {refused}"
    );

    store
        .serve_base(&install(root.path(), BaseSource::new(2, &base_v2())))
        .expect("the update runs");

    let record = store
        .learning_delta("conflicting")
        .expect("the delta did not disappear");
    assert_eq!(record.state, DeltaState::Inactive);
    let kept = store
        .learning_corpus("conflicting")
        .expect("the diagnosis is readable");
    assert!(
        kept.iter().any(|verdict| !verdict.passed),
        "the diagnosis survives the update: {kept:?}"
    );
    let status = store.learning_status().expect("status");
    assert!(
        status.active.is_empty(),
        "an unjudged candidate composes nothing: {status:?}"
    );
}

// ----- p7: explicit off survives the real migration -----

/// AC-024/AC-054 (I1): the migration this build really runs — the schema
/// generation batch and the base-ledger install — leaves the user's explicit
/// `workflow.enabled = false` in force; it is never rewritten to the base's
/// value and never dropped from the effective view.
#[test]
fn off_survives_the_real_migration_p7() {
    let off = user_config("[workflow]\nenabled = false\n");
    let mut world = support::open_world("update-p7", Some(&off));

    let before = world.runtime.effective().workflow_entry.clone();
    assert_eq!(before.source.kind, "user");
    assert_eq!(
        before.effective,
        config::ConfigViewValue::Visible {
            value: Value::Bool(false)
        }
    );
    // The migration this build runs on every open: the schema batch names its
    // generation and the base ledger records the base it serves.
    let generation = world
        .runtime
        .store()
        .schema_generation()
        .expect("generation read");
    assert!(
        generation >= 2,
        "the store reports this position's schema generation: {generation}"
    );
    assert_eq!(
        world
            .runtime
            .store()
            .update_status()
            .expect("update status")
            .base_version,
        Some(SHIPPED_BASE_VERSION),
        "the base ledger records the base the runtime serves"
    );

    world.reopen();

    assert_eq!(
        world
            .runtime
            .store()
            .schema_generation()
            .expect("generation read"),
        generation,
        "the migration leaves the store at the generation it wrote"
    );
    let after = world.runtime.effective().workflow_entry.clone();
    assert_eq!(
        after.effective,
        config::ConfigViewValue::Visible {
            value: Value::Bool(false)
        },
        "workflow: false survives the migration"
    );
    assert_eq!(
        after.source.kind, "user",
        "the flag keeps its own layer after the migration"
    );
    assert_eq!(
        world.runtime.effective().composed().workflow.enabled,
        Some(false),
        "the dispatch view carries the explicit off after the migration"
    );
    assert_eq!(
        world
            .runtime
            .store()
            .update_status()
            .expect("update status")
            .receipt
            .map(|receipt| receipt.state),
        Some(UpdateState::Active),
        "the reopened runtime serves the same recorded base"
    );
}

// ----- p8: the version domains are distinct -----

/// DX-I5/INV-010a: the schema generation, the base version, the config version
/// and the request schema version each name their own domain and each refusal
/// carries the code of the domain it belongs to — one shared "version" code for
/// all four would hide which one was refused.
#[test]
fn version_domains_are_distinct_p8() {
    // 1. The store's schema generation.
    let root = temp_root("p8");
    std::fs::create_dir_all(root.path().join("store")).expect("store dir");
    let path = root.path().join("store").join("state.db");
    {
        let store = TaskStore::open(&path).expect("store opens");
        drop(store);
    }
    let newer = rusqlite::Connection::open(&path).expect("raw connection");
    newer
        .execute_batch("PRAGMA user_version = 99")
        .expect("a newer write");
    drop(newer);
    let Err(schema) = TaskStore::open(&path) else {
        panic!("a newer store is refused");
    };
    let schema_message = schema.to_string();
    assert_eq!(schema.code(), ErrorCode::UnsupportedVersion);
    assert!(
        schema_message.contains("schema generation"),
        "the schema generation names its own domain: {schema_message}"
    );

    // 2. The base version: the ledger refuses a base that skips a step.
    std::fs::create_dir_all(root.path().join("ledger")).expect("ledger dir");
    let mut store = open_store(&root.path().join("ledger"));
    store
        .serve_base(&install(root.path(), BaseSource::new(1, &base_v1())))
        .expect("first base");
    let base = store
        .serve_base(&install(root.path(), BaseSource::new(3, &base_v2())))
        .expect_err("a skipped base is refused");
    let base_message = base.to_string();
    assert_eq!(base.code(), ErrorCode::Conflict);
    assert!(
        base_message.contains("base version"),
        "the base version names its own domain: {base_message}"
    );

    // 3. The config document's version.
    let config = config::Config::parse_validated(
        "config_version = 2\n[connections.local]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:11434\"\n",
    )
    .expect_err("an unsupported config version is refused");
    let config_message = config.to_string();
    assert!(
        matches!(config.issue, ConfigIssue::UnsupportedConfigVersion),
        "the config version has its own issue"
    );
    assert!(
        config_message.contains("config_version"),
        "the config version names its own key: {config_message}"
    );

    // 4. The request schema version on the wire.
    let mut world = support::open_world("update-p8", Some(&user_config("")));
    let session = world.open_session("update-bootstrap-p8");
    let response: Value = world.dispatch(
        &json!({
            "jsonrpc": "2.0", "id": 8801, "method": "runtime.status",
            "params": { "schema_version": 2, "session_id": session.0 }
        })
        .to_string(),
    );
    let request = &response["error"]["data"];
    assert_eq!(request["code"], "unsupported_version");
    assert!(
        request["message"]
            .as_str()
            .expect("a message")
            .contains("schema_version"),
        "the request schema version names its own domain: {request}"
    );

    // The four domains are four names, and the three that are typed refusals
    // do not collapse onto one shared code.
    let names = [
        schema_message,
        base_message,
        config_message,
        request["message"].as_str().expect("message").to_string(),
    ];
    let distinct: std::collections::BTreeSet<&String> = names.iter().collect();
    assert_eq!(
        distinct.len(),
        names.len(),
        "each version domain keeps its own name: {names:?}"
    );
    assert_ne!(
        schema.code(),
        base.code(),
        "the base ledger's code is not the schema generation's"
    );
}

// ----- p9: the context guard reads as the layer that supplied it -----

/// AC-054/AC-072: `context.auto_compact` is served by the layer that supplies
/// it — the base and its revision when the user's document carries no override,
/// the user when it does — so a base that moves the guard moves the read with it
/// instead of leaving a base value attributed to the user.
#[test]
fn context_guard_reads_as_the_layer_that_supplied_it_p9() {
    let user = user_config("");
    assert!(
        !user.contains("[context]"),
        "the fixture leaves the guard to the base layer"
    );

    // The wire serves this entry: with the shipped base and no user override,
    // the guard names the base, not the user's document.
    let mut world = support::open_world("update-p9", Some(&user));
    let session = world.open_session("update-bootstrap-p9");
    let read: Value = world.dispatch(
        &json!({
            "jsonrpc": "2.0", "id": 9101, "method": "config.read",
            "params": { "schema_version": 1, "session_id": session.0,
                        "keys": ["context.auto_compact"] }
        })
        .to_string(),
    );
    assert!(read["error"].is_null(), "{read}");
    let served = &read["result"]["entries"]["items"][0];
    assert_eq!(served["key"], "context.auto_compact");
    assert_eq!(
        served["source"]["kind"], "shipped",
        "the guard's absent override is the base layer's, not the user's: {read}"
    );
    assert_eq!(
        served["source"]["revision"],
        config::shipped_revision(),
        "the entry names the base bytes that answered it: {read}"
    );
    assert_eq!(
        served["effective"]["value"],
        json!(false),
        "the shipped base leaves the guard off: {read}"
    );

    // A user override names the user, so the two layers stay distinguishable.
    let overridden = user_config("[context]\nauto_compact = true\n");
    let mut world = support::open_world("update-p9-own", Some(&overridden));
    let session = world.open_session("update-bootstrap-p9-own");
    let read: Value = world.dispatch(
        &json!({
            "jsonrpc": "2.0", "id": 9102, "method": "config.read",
            "params": { "schema_version": 1, "session_id": session.0,
                        "keys": ["context.auto_compact"] }
        })
        .to_string(),
    );
    let served = &read["result"]["entries"]["items"][0];
    assert_eq!(served["source"]["kind"], "user", "{read}");
    assert_eq!(served["effective"]["value"], json!(true), "{read}");
    assert_eq!(
        served["source"]["revision"],
        world
            .runtime
            .effective()
            .parsed
            .as_ref()
            .expect("the user document is retained")
            .revision(),
        "the user's entry names the user's own bytes: {read}"
    );

    // An explicit value wins the slot even when it equals the shipped default:
    // the layer supplies the value, never a comparison against another layer.
    let equal = user_config("[context]\nauto_compact = false\n");
    let explicit = config::resolve_effective_on(BaseSource::new(2, &base_v2()), Some(&equal))
        .expect("the explicit off composes");
    assert_eq!(
        explicit.context_entry.source.kind, "user",
        "an explicit off stays the user's over a base that sets the guard"
    );
    assert_eq!(
        explicit.context_entry.effective,
        config::ConfigViewValue::Visible {
            value: Value::Bool(false)
        },
        "the explicit off wins the slot the base would fill"
    );

    // The next base moves the guard: the entry the wire serves follows the base
    // value and names the base's bytes, never the user's document.
    let moved = config::resolve_effective_on(BaseSource::new(2, &base_v2()), Some(&user))
        .expect("the next base composes");
    let entry = serde_json::to_value(moved.context_entry.clone()).expect("the entry serializes");
    assert_eq!(entry["key"], "context.auto_compact");
    assert_eq!(
        entry["effective"]["value"],
        json!(true),
        "the next base's guard answers, and never reads null: {entry}"
    );
    assert_eq!(
        entry["source"]["kind"], "shipped",
        "the moved guard is the base layer's: {entry}"
    );
    assert_eq!(
        entry["source"]["revision"],
        BaseSource::new(2, &base_v2()).digest(),
        "the entry names the base bytes that answered it: {entry}"
    );
    assert_ne!(
        entry["source"]["revision"],
        moved
            .parsed
            .as_ref()
            .expect("the user document is retained")
            .revision(),
        "a base value is never attributed to the user's bytes: {entry}"
    );
    assert_eq!(
        moved.composed().context.auto_compact,
        Some(true),
        "the dispatch view carries the moved guard"
    );
}

// ----- p10: the recorded version never answers another document -----

/// AC-054/INV-010a: an offer of the recorded version whose bytes differ is
/// refused typed. The ledger never answers the receipt of a document this open
/// did not compose, so `runtime.status` cannot name bytes that are not serving
/// while `sources_digest`/`shipped_revision` hash the text that was read.
#[test]
fn changed_bytes_under_a_recorded_version_are_refused_p10() {
    let root = temp_root("p10");
    std::fs::create_dir_all(root.path().join("store")).expect("store dir");
    let mut store = open_store(&root.path().join("store"));
    let recorded_text = base_v1();
    store
        .serve_base(&install(root.path(), BaseSource::new(1, &recorded_text)))
        .expect("the first base is recorded");
    let recorded = store.update_receipt(1).expect("the recorded receipt");
    assert_eq!(recorded.digest, BaseSource::new(1, &recorded_text).digest());

    // The same version with other bytes: the document changed without a bump.
    let changed_text =
        base_document("[models.purposes.review]\neffort = { mode = \"fixed\", value = \"low\" }\n");
    assert_ne!(changed_text, recorded_text);
    let changed = BaseSource::new(1, &changed_text);
    assert_ne!(changed.digest(), recorded.digest);
    let refusal = store
        .serve_base(&install(root.path(), changed))
        .expect_err("changed bytes under the recorded version are refused");
    assert!(
        matches!(refusal, config::BaseError::DocumentChanged { version: 1 }),
        "the same version with other bytes is its own typed refusal: {refusal}"
    );
    assert!(
        refusal
            .to_string()
            .contains("recorded with another document"),
        "the refusal names the changed document: {refusal}"
    );
    assert_eq!(
        refusal.code(),
        ErrorCode::Conflict,
        "the base document domain carries its own code: {refusal}"
    );

    // The durable value reads back: the receipt still names the bytes that
    // serve, and the offered document left no row behind.
    assert_eq!(
        store
            .update_receipt(1)
            .expect("the recorded receipt")
            .digest,
        recorded.digest,
        "the receipt still belongs to the document that serves"
    );
    assert_eq!(
        store
            .active_base()
            .expect("base read")
            .map(|base| base.digest),
        Some(recorded.digest.clone()),
        "the serving base did not move"
    );
    assert_eq!(
        store.staged_base().expect("staged read"),
        None,
        "the refused offer staged nothing"
    );

    // The same version with the same bytes is the resume it always was.
    let resumed = store
        .serve_base(&install(root.path(), BaseSource::new(1, &recorded_text)))
        .expect("the recorded document resumes");
    assert_eq!(resumed.receipt.state, UpdateState::Active);
    assert_eq!(resumed.receipt.digest, recorded.digest);

    // The refusal is not a wedge: a document that changed hands must name the
    // new version, and stepping it moves the base.
    let stepped = store
        .serve_base(&install(root.path(), BaseSource::new(2, &changed_text)))
        .expect("the next version installs the changed document");
    assert_eq!(stepped.receipt.state, UpdateState::Active);
    assert_eq!(
        store
            .active_base()
            .expect("base read")
            .map(|base| base.digest),
        Some(changed.digest()),
        "the version the changed document names is what serves"
    );
}

// ----- p11: a stale checkpoint is abandoned and the base then moves -----

/// EDGE-006/PROH-004: a checkpoint written by a stopped run that will never be
/// committed can be abandoned, and the base then moves. Without that typed path
/// the staged row refuses every later open with the same answer and no surface
/// can discard it.
#[test]
fn abandoned_checkpoint_unblocks_the_cutover_p11() {
    let root = temp_root("p11");
    std::fs::create_dir_all(root.path().join("store")).expect("store dir");
    let mut store = open_store(&root.path().join("store"));
    store
        .serve_base(&install(root.path(), BaseSource::new(1, &base_v1())))
        .expect("the first base is recorded");

    // The run that stops here staged bytes a later build no longer offers.
    let stopped =
        base_document("[models.purposes.main]\neffort = { mode = \"fixed\", value = \"high\" }\n");
    store
        .stage_base(&install(root.path(), BaseSource::new(2, &stopped)))
        .expect("the stopped run staged its checkpoint");
    let offered =
        base_document("[models.purposes.main]\neffort = { mode = \"fixed\", value = \"low\" }\n");
    assert_ne!(offered, stopped);
    let wedged = store
        .stage_base(&install(root.path(), BaseSource::new(2, &offered)))
        .expect_err("a different document is refused while the checkpoint stands");
    assert!(wedged.to_string().contains("already staged"), "{wedged}");

    // The typed path out: the stale checkpoint leaves with its receipt, and the
    // base that serves is untouched.
    let abandoned = store
        .abandon_base(2)
        .expect("the stale checkpoint can be abandoned");
    assert_eq!(
        abandoned.digest,
        BaseSource::new(2, &stopped).digest(),
        "the abandoned checkpoint reports the bytes it discarded"
    );
    assert_eq!(
        store.staged_base().expect("staged read"),
        None,
        "the checkpoint left the ledger"
    );
    assert!(
        store.update_receipt(2).is_err(),
        "its receipt left with it, so nothing still names those bytes"
    );
    assert_eq!(
        store
            .active_base()
            .expect("base read")
            .map(|base| base.version),
        Some(1),
        "abandoning a checkpoint installs nothing"
    );

    // Abandoning again is a typed refusal, not a silent success.
    let again = store
        .abandon_base(2)
        .expect_err("nothing is staged any more");
    assert!(
        again.to_string().contains("not staged"),
        "the second abandon names the state: {again}"
    );
    assert_eq!(again.code(), ErrorCode::Conflict);
    assert_eq!(
        store
            .active_base()
            .expect("base read")
            .map(|base| base.version),
        Some(1),
        "the refused abandon moved nothing"
    );

    // The base actually moves to the document that is offered now.
    let moved = store
        .serve_base(&install(root.path(), BaseSource::new(2, &offered)))
        .expect("the cutover runs once the checkpoint left");
    assert_eq!(moved.receipt.state, UpdateState::Active);
    assert_eq!(moved.receipt.digest, BaseSource::new(2, &offered).digest());
    assert_eq!(
        store
            .active_base()
            .expect("base read")
            .map(|base| base.digest),
        Some(BaseSource::new(2, &offered).digest()),
        "the ledger serves the document the update offered"
    );

    // The receipt the cutover wrote classifies every asset once, in the
    // canonical order, even though this checkpoint was staged twice.
    let names: Vec<&str> = moved
        .receipt
        .assets
        .iter()
        .map(|asset| asset.asset.as_str())
        .collect();
    assert_eq!(
        names,
        vec![
            "config_file",
            "sqlite_rows",
            "workspace_directories",
            "index_rows"
        ],
        "the resumed receipt classifies every asset once, in the canonical order"
    );

    // A checkpoint re-classified by the run that resumes it names the
    // installation that commits, not the one that staged first.
    let staging = temp_root("p11-staging");
    store
        .stage_base(&config::BaseInstall::new(
            BaseSource::new(3, &stopped),
            staging.path().join("config.toml"),
            staging.path(),
        ))
        .expect("the checkpoint stages");
    let resumed = store
        .serve_base(&install(root.path(), BaseSource::new(3, &stopped)))
        .expect("the re-run resumes the staged checkpoint");
    let config_file = resumed
        .receipt
        .assets
        .iter()
        .find(|asset| asset.asset == config::UpdateAsset::ConfigFile)
        .expect("the receipt classifies the config file");
    assert_eq!(
        config_file.location,
        root.path().join("config.toml").display().to_string(),
        "the resumed receipt names the installation that committed"
    );
}

// ----- p12: an older base is refused with the base domain's own code -----

/// I-6/INV-010a/DX-I5: an older build offered to a newer ledger is refused typed
/// with the base domain's own code — not the store's schema generation code —
/// and the base that serves is untouched. Deleting the downgrade guard must fail
/// this case.
#[test]
fn older_base_is_refused_with_the_base_domain_code_p12() {
    let root = temp_root("p12");
    std::fs::create_dir_all(root.path().join("store")).expect("store dir");
    let mut store = open_store(&root.path().join("store"));
    let first = base_v1();
    let second = base_v2();
    let third =
        base_document("[models.purposes.review]\neffort = { mode = \"fixed\", value = \"low\" }\n");
    for (version, text) in [(1, &first), (2, &second), (3, &third)] {
        store
            .serve_base(&install(root.path(), BaseSource::new(version, text)))
            .expect("the base lands");
    }
    let serving = store.update_receipt(3).expect("the serving receipt");

    // A downgrade to the previous base: the newer ledger refuses it.
    let refusal = store
        .serve_base(&install(root.path(), BaseSource::new(2, &second)))
        .expect_err("an older base is refused");
    assert!(
        matches!(
            refusal,
            config::BaseError::NewerRecorded {
                offered: 2,
                recorded: 3
            }
        ),
        "the downgrade is its own typed refusal: {refusal}"
    );
    assert_eq!(
        refusal.code(),
        ErrorCode::Conflict,
        "the base ledger's code is its own, not the store's generation code: {refusal}"
    );
    assert_ne!(
        refusal.code(),
        ErrorCode::UnsupportedVersion,
        "a base downgrade is not the schema generation's refusal: {refusal}"
    );
    assert!(
        refusal
            .to_string()
            .contains("older than the recorded base 3"),
        "the refusal names the direction and the recorded base: {refusal}"
    );

    // The durable value reads back: the base that served still serves, its
    // receipt still belongs to the same bytes and nothing was staged.
    assert_eq!(
        store
            .active_base()
            .expect("base read")
            .map(|base| base.version),
        Some(3),
        "the serving base did not move"
    );
    assert_eq!(
        store.update_receipt(3).expect("the serving receipt"),
        serving,
        "the serving receipt is unchanged"
    );
    assert_eq!(store.staged_base().expect("staged read"), None);
    assert_eq!(
        store.update_receipt(2).expect("the retired receipt").state,
        UpdateState::Retired,
        "the base the downgrade offered keeps its retired receipt"
    );
}

// ----- p13: retention keeps the serving and staged receipts -----

/// INV-010: the retention window ages out retired bases beyond it with their
/// receipts, while the base that serves and the checkpoint a cutover stages stay
/// readable — the evidence an update reads back is never pruned.
#[test]
fn retention_keeps_serving_and_staged_receipts_p13() {
    let root = temp_root("p13");
    std::fs::create_dir_all(root.path().join("store")).expect("store dir");
    let mut store = open_store(&root.path().join("store"));
    let texts: Vec<String> = (1..=7u64)
        .map(|version| {
            base_document(&format!(
                "[models.purposes.review]\neffort = {{ mode = \"fixed\", value = \"low\" }}\n# base {version}\n"
            ))
        })
        .collect();
    for version in 1..=6u64 {
        store
            .serve_base(&install(
                root.path(),
                BaseSource::new(version, &texts[version as usize - 1]),
            ))
            .expect("the base lands");
    }

    // Only the retired bases beyond the window (BASE_VERSION_RETENTION, four)
    // aged out: the first one left with its receipt, its successors did not.
    assert!(
        store.update_receipt(1).is_err(),
        "the retired base beyond the window left the ledger"
    );
    for version in 2..=5u64 {
        assert_eq!(
            store
                .update_receipt(version)
                .expect("a retired receipt inside the window")
                .state,
            UpdateState::Retired,
            "retired base {version} stays readable"
        );
    }
    assert_eq!(
        store.update_receipt(6).expect("the serving receipt").state,
        UpdateState::Active,
        "the base that serves is readable after the window moved"
    );

    // A checkpoint staged after the window moved is outside the statements'
    // reach: only retired rows are aged out.
    let staged = store
        .stage_base(&install(root.path(), BaseSource::new(7, &texts[6])))
        .expect("the new base stages");
    assert_eq!(staged.state, UpdateState::Staged);
    assert_eq!(
        store.update_receipt(7).expect("the staged receipt").state,
        UpdateState::Staged,
        "a checkpoint staged after the prune stays readable"
    );
    assert_eq!(
        store.update_receipt(7).expect("the staged receipt").digest,
        BaseSource::new(7, &texts[6]).digest(),
        "the checkpoint still belongs to the bytes that were staged"
    );

    // The cutover prunes the next retired base — never the staged checkpoint
    // that became the serving one.
    store.commit_base(7).expect("the cutover runs");
    assert!(
        store.update_receipt(2).is_err(),
        "the next retired base aged out with its receipt"
    );
    for version in 3..=6u64 {
        assert_eq!(
            store
                .update_receipt(version)
                .expect("a retired receipt inside the window")
                .state,
            UpdateState::Retired,
            "retired base {version} stays readable"
        );
    }
    assert_eq!(
        store.update_receipt(7).expect("the serving receipt").state,
        UpdateState::Active
    );
    assert_eq!(
        store.update_status().expect("update status").base_version,
        Some(7)
    );
}

// ----- p14: the composed document's references are checked -----

/// AC-054: the composed document is validated by the same referential checks a
/// file document runs, so a base that names an unknown connection or group is
/// refused where it composes instead of failing far from the cause.
#[test]
fn composed_document_references_are_checked_p14() {
    let user = user_config("");
    assert!(
        config::Config::parse_validated(&user).is_ok(),
        "the user document alone is valid: the refusals below come from the base"
    );

    let ghost_connection = base_document(
        "[models.purposes.main]\n\
         model = { mode = \"fixed\", connection = \"ghost\", model_id = \"unknown\" }\n",
    );
    let refused = config::resolve_effective_on(BaseSource::new(2, &ghost_connection), Some(&user))
        .expect_err("a base naming an unknown connection is refused");
    assert!(
        refused.to_string().contains("models.purposes.main.model"),
        "the refusal names the composed key: {refused}"
    );
    assert!(
        matches!(
            refused.issue,
            ConfigIssue::UnknownConnectionReference { ref connection } if connection == "ghost"
        ),
        "the refusal is the same issue a file document carries: {refused}"
    );

    let ghost_group = base_document("[models.purposes.main]\ngroup = \"ghost-group\"\n");
    let refused = config::resolve_effective_on(BaseSource::new(2, &ghost_group), Some(&user))
        .expect_err("a base naming an unknown group is refused");
    assert!(
        refused.to_string().contains("models.purposes.main.group"),
        "the refusal names the composed key: {refused}"
    );
    assert!(
        matches!(
            refused.issue,
            ConfigIssue::UnknownGroupReference { ref group } if group == "ghost-group"
        ),
        "the group reference is checked by the same rule: {refused}"
    );

    // The file document's own dangling reference reports the same issue at the
    // same key, so the composed check is the file check and not a second one.
    let dangling = user_config("[models.purposes.main]\ngroup = \"ghost-group\"\n");
    let refused = config::Config::parse_validated(&dangling)
        .expect_err("the file document's reference is checked");
    assert!(matches!(
        refused.issue,
        ConfigIssue::UnknownGroupReference { .. }
    ));

    // A base whose references resolve composes, and the row it supplies
    // resolves through the group it declared.
    let sound = base_document(
        "[models.groups.fast]\nmodel = { mode = \"auto\" }\n\
         [models.purposes.main]\ngroup = \"fast\"\n",
    );
    let effective = config::resolve_effective_on(BaseSource::new(2, &sound), Some(&user))
        .expect("resolvable references compose");
    assert_eq!(
        effective
            .composed()
            .resolve_purpose(SUBJECT_PURPOSE)
            .expect("the purpose resolves")
            .model_source,
        "models.groups.fast"
    );
}

// ----- p15: the defaults merge the slots the user defers -----

/// AC-054/DEC-009: `[models.defaults]` merges slot by slot — a slot the user
/// states is the user's, a slot the user defers to the layer below (`inherit`,
/// the only deferred spelling a required slot has) takes the base's value, and a
/// store with no user document reads the base as its only layer.
#[test]
fn defaults_merge_the_slots_the_user_defers_p15() {
    let base = base_document("").replace(
        "effort = { mode = \"auto\" }",
        "effort = { mode = \"fixed\", value = \"high\" }",
    );
    assert!(
        base.contains("effort = { mode = \"fixed\", value = \"high\" }"),
        "the fixture's base fixes the default effort"
    );

    // The deferred slot takes the base's value: the section is not taken whole
    // from the user row, so a base that fixes a default reaches a user who has
    // a document and defers the slot.
    let deferring = user_config("").replace(
        "effort = { mode = \"auto\" }",
        "effort = { mode = \"inherit\" }",
    );
    assert!(
        deferring.contains("effort = { mode = \"inherit\" }"),
        "the fixture's user document defers the default effort"
    );
    let effective = config::resolve_effective_on(BaseSource::new(2, &base), Some(&deferring))
        .expect("the deferred slot composes");
    let resolved = effective
        .composed()
        .resolve_purpose(SUBJECT_PURPOSE)
        .expect("the purpose resolves");
    assert_eq!(
        resolved.effort,
        EffortAssign::Fixed {
            value: EffortLevel::High
        },
        "the slot the user deferred takes the base's value"
    );
    assert_eq!(
        resolved.effort_source, "models.defaults",
        "the deferral resolves through the key the user deferred from"
    );

    // A slot the user states is the user's, even where the base fixes the same
    // slot: the layer supplies its own value.
    let stating = user_config("");
    let effective = config::resolve_effective_on(BaseSource::new(2, &base), Some(&stating))
        .expect("the stated slot composes");
    assert_eq!(
        effective
            .composed()
            .resolve_purpose(SUBJECT_PURPOSE)
            .expect("the purpose resolves")
            .effort,
        EffortAssign::Auto,
        "the base never rewrites a slot the user stated"
    );

    // No user document at all: the base is the only layer, not a merge.
    let effective = config::resolve_effective_on(BaseSource::new(2, &base), None)
        .expect("the base alone composes");
    assert_eq!(
        effective
            .composed()
            .resolve_purpose(SUBJECT_PURPOSE)
            .expect("the purpose resolves")
            .effort,
        EffortAssign::Fixed {
            value: EffortLevel::High
        },
        "the base's defaults answer where no user document exists"
    );
}

// ----- p16: a purpose row the user writes keeps its slots -----

/// AC-054: a purpose row the user writes is the user's — the base never fills a
/// slot inside it, so the user's group binding keeps the model it named and the
/// source names the binding that supplied it, while a slot the user left to the
/// defaults stays with the defaults instead of being filled from the base's row
/// under the user's key.
#[test]
fn user_row_keeps_its_slots_over_the_base_row_p16() {
    let base = base_document(
        "[models.purposes.main]\n\
         model = { mode = \"fixed\", connection = \"local\", model_id = \"base-model\" }\n\
         fallback = { mode = \"off\" }\n",
    );
    let user = user_config(
        "[models.groups.fast]\n\
         model = { mode = \"fixed\", connection = \"local\", model_id = \"fast-model\" }\n\
         [models.purposes.main]\n\
         group = \"fast\"\n",
    );

    let effective = config::resolve_effective_on(BaseSource::new(2, &base), Some(&user))
        .expect("the layers compose");
    let resolved = effective
        .composed()
        .resolve_purpose(SUBJECT_PURPOSE)
        .expect("the purpose resolves");
    assert_eq!(
        resolved.model,
        ModelAssign::Fixed(config::FixedModel {
            connection: "local".to_string(),
            model_id: "fast-model".to_string(),
        }),
        "the user's group binding keeps the model it named"
    );
    assert_eq!(
        resolved.model_source, "models.groups.fast",
        "the model is attributed to the binding that supplied it"
    );
    assert_eq!(
        resolved.fallback,
        config::FallbackAssign::Auto { chain: Vec::new() },
        "the slot the user left to the defaults stays with the defaults"
    );
    assert_eq!(
        resolved.fallback_source, "models.defaults",
        "a base value is never attributed to the user's purpose key"
    );

    // The base's row still answers a purpose the user's document leaves alone,
    // so the row-level rule keeps the base reachable.
    let user = user_config("");
    let effective = config::resolve_effective_on(BaseSource::new(2, &base), Some(&user))
        .expect("the layers compose");
    let resolved = effective
        .composed()
        .resolve_purpose(SUBJECT_PURPOSE)
        .expect("the purpose resolves");
    assert_eq!(
        resolved.model,
        ModelAssign::Fixed(config::FixedModel {
            connection: "local".to_string(),
            model_id: "base-model".to_string(),
        }),
        "a purpose the user's document leaves alone takes the base's row"
    );
    assert_eq!(
        resolved.fallback,
        config::FallbackAssign::Off,
        "the base's fallback reaches the row it supplies whole"
    );
}

// ----- p17: the cutover replaces a checkpoint it cannot resume -----

/// EDGE-006: a checkpoint this build cannot resume — the bytes a stopped
/// cutover staged under the version this build ships — is replaced by the
/// cutover instead of wedging every later open with `already staged`. The
/// abandon is the cutover's own step, so the ledger ends up naming the document
/// that arrived and no row still names the checkpoint's bytes.
#[test]
fn stale_checkpoint_is_replaced_by_the_cutover_p17() {
    let root = temp_root("p17");
    std::fs::create_dir_all(root.path().join("store")).expect("store dir");
    let mut store = open_store(&root.path().join("store"));
    store
        .serve_base(&install(root.path(), BaseSource::new(1, &base_v1())))
        .expect("the first base is recorded");

    // A run that stopped here staged this build's version with other bytes: the
    // build's document was corrected between the crash and this open.
    let stopped =
        base_document("[models.purposes.main]\neffort = { mode = \"fixed\", value = \"high\" }\n");
    store
        .stage_base(&install(root.path(), BaseSource::new(2, &stopped)))
        .expect("the stopped run staged its checkpoint");
    let stale_digest = BaseSource::new(2, &stopped).digest();
    let offered = base_v2();
    assert_ne!(offered, stopped, "the fixture offers other bytes");

    let served = store
        .serve_base(&install(root.path(), BaseSource::new(2, &offered)))
        .expect("the cutover replaces the checkpoint it cannot resume");
    assert_eq!(
        served.abandoned.as_ref().map(|base| base.digest.clone()),
        Some(stale_digest.clone()),
        "the cutover reports the checkpoint it discarded"
    );
    assert_eq!(served.receipt.state, UpdateState::Active);
    assert_eq!(
        served.receipt.digest,
        BaseSource::new(2, &offered).digest(),
        "the receipt belongs to the document that arrived"
    );

    // The ledger reads back: the offered document serves, no staged row is left,
    // and no readable receipt still names the checkpoint's bytes.
    assert_eq!(
        store.staged_base().expect("staged read"),
        None,
        "the checkpoint left the ledger"
    );
    assert_eq!(
        store
            .active_base()
            .expect("base read")
            .map(|base| base.version),
        Some(2)
    );
    assert_eq!(
        store.update_receipt(2).expect("the serving receipt").digest,
        BaseSource::new(2, &offered).digest()
    );
    for version in [1, 2] {
        assert_ne!(
            store.update_receipt(version).expect("receipt").digest,
            stale_digest,
            "base {version} names some other document, never the discarded bytes"
        );
    }

    // The same document again is the resume it always was: nothing is discarded,
    // so the recovery is not a silent rewrite on every open.
    let resumed = store
        .serve_base(&install(root.path(), BaseSource::new(2, &offered)))
        .expect("the recorded document resumes");
    assert_eq!(resumed.abandoned, None, "a resume discards nothing");
    assert_eq!(resumed.receipt.state, UpdateState::Active);
}

// ----- p18: a changed recorded document keeps the waiting checkpoint -----

/// AC-054/INV-010a: the recorded version's changed bytes are refused before a
/// checkpoint is examined, so the refusal names the recovery it leaves a build —
/// the changed document must ship under a new base version — and the checkpoint a
/// build that can step needs stays exactly where it is.
#[test]
fn changed_recorded_document_keeps_the_waiting_checkpoint_p18() {
    let root = temp_root("p18");
    std::fs::create_dir_all(root.path().join("store")).expect("store dir");
    let mut store = open_store(&root.path().join("store"));
    let recorded = base_v1();
    store
        .serve_base(&install(root.path(), BaseSource::new(1, &recorded)))
        .expect("the first base is recorded");
    // A stopped cutover waits on the next version while the recorded one is
    // offered again with other bytes.
    store
        .stage_base(&install(root.path(), BaseSource::new(2, &base_v2())))
        .expect("the stopped run staged its checkpoint");
    let waiting = store.staged_base().expect("staged read");

    let changed_text =
        base_document("[models.purposes.review]\neffort = { mode = \"fixed\", value = \"low\" }\n");
    let refusal = store
        .serve_base(&install(root.path(), BaseSource::new(1, &changed_text)))
        .expect_err("changed bytes under the recorded version are refused");
    assert!(
        matches!(refusal, config::BaseError::DocumentChanged { version: 1 }),
        "the recorded version's own refusal wins: {refusal}"
    );
    assert!(
        refusal.to_string().contains("recovery:"),
        "the refusal names the recovery it leaves: {refusal}"
    );

    // Nothing moved: the checkpoint is still the one a build that can step from
    // version 1 resumes, and the recorded bytes still serve.
    assert_eq!(
        store.staged_base().expect("staged read"),
        waiting,
        "the waiting checkpoint is never discarded by a refusal"
    );
    assert_eq!(
        store
            .active_base()
            .expect("base read")
            .map(|base| base.digest),
        Some(BaseSource::new(1, &recorded).digest())
    );
}

// ----- p19: an older build never discards a newer checkpoint -----

/// EDGE-006/I-6: a checkpoint a newer build staged is not discarded by an
/// older build's open — the offer is refused typed with the state and the
/// recovery, and the ledger keeps the checkpoint for the build that can resume
/// it. The older build installs nothing.
#[test]
fn newer_checkpoint_is_kept_when_an_older_build_opens_p19() {
    let root = temp_root("p19");
    std::fs::create_dir_all(root.path().join("store")).expect("store dir");
    let mut store = open_store(&root.path().join("store"));
    // No base serves yet: a build shipping version 2 staged its document and
    // stopped before the cutover.
    let newer = base_v2();
    store
        .stage_base(&install(root.path(), BaseSource::new(2, &newer)))
        .expect("the newer build staged its checkpoint");

    let refusal = store
        .serve_base(&install(root.path(), BaseSource::new(1, &base_v1())))
        .expect_err("an older build does not write over a newer checkpoint");
    assert!(
        matches!(refusal, config::BaseError::AlreadyStaged { version: 2 }),
        "the newer checkpoint's own refusal wins: {refusal}"
    );
    assert!(
        refusal.to_string().contains("recovery:"),
        "the refusal names the recovery it leaves: {refusal}"
    );

    // The ledger reads back: the checkpoint is untouched and nothing installed.
    assert_eq!(
        store
            .staged_base()
            .expect("staged read")
            .map(|base| base.digest),
        Some(BaseSource::new(2, &newer).digest()),
        "the newer checkpoint is kept for the build that staged it"
    );
    assert_eq!(
        store.active_base().expect("base read"),
        None,
        "the older build installed nothing"
    );
}

// ----- p20: an interrupted first install serves the offered document -----

/// EDGE-006: with no base serving, the document this build offers is what
/// ends up serving — a checkpoint holding exactly those bytes is resumed, and a
/// checkpoint holding others is replaced, because a document that never served
/// retires nothing and installs nothing.
#[test]
fn interrupted_first_install_serves_the_offered_document_p20() {
    // The checkpoint holds the document this build offers: the install resumes.
    let resumed_root = temp_root("p20-resumed");
    std::fs::create_dir_all(resumed_root.path().join("store")).expect("store dir");
    let mut resumed = open_store(&resumed_root.path().join("store"));
    resumed
        .stage_base(&install(
            resumed_root.path(),
            BaseSource::new(1, &base_v1()),
        ))
        .expect("the stopped install staged its checkpoint");
    let served = resumed
        .serve_base(&install(
            resumed_root.path(),
            BaseSource::new(1, &base_v1()),
        ))
        .expect("the interrupted install is completed");
    assert_eq!(
        served.abandoned, None,
        "a resumed checkpoint is not discarded"
    );
    assert_eq!(served.receipt.state, UpdateState::Active);
    assert_eq!(
        resumed
            .active_base()
            .expect("base read")
            .map(|base| base.digest),
        Some(BaseSource::new(1, &base_v1()).digest()),
        "the resumed document is what serves"
    );
    assert_eq!(
        resumed.staged_base().expect("staged read"),
        None,
        "the resumed checkpoint committed"
    );

    // The checkpoint holds other bytes: the corrected build replaces it.
    let replaced_root = temp_root("p20-replaced");
    std::fs::create_dir_all(replaced_root.path().join("store")).expect("store dir");
    let mut replaced = open_store(&replaced_root.path().join("store"));
    let stale =
        base_document("[models.purposes.main]\neffort = { mode = \"fixed\", value = \"low\" }\n");
    replaced
        .stage_base(&install(replaced_root.path(), BaseSource::new(1, &stale)))
        .expect("the stopped install staged its checkpoint");
    let served = replaced
        .serve_base(&install(
            replaced_root.path(),
            BaseSource::new(1, &base_v1()),
        ))
        .expect("the offered document is what serves");
    assert_eq!(
        served.abandoned.as_ref().map(|base| base.digest.clone()),
        Some(BaseSource::new(1, &stale).digest()),
        "the cutover reports the stale first-install checkpoint"
    );
    assert_eq!(
        replaced
            .active_base()
            .expect("base read")
            .map(|base| base.digest),
        Some(BaseSource::new(1, &base_v1()).digest()),
        "the ledger serves the document this build offers"
    );
    assert_eq!(replaced.staged_base().expect("staged read"), None);
}

// ----- p21: the open clears a stale checkpoint and reports the recovery -----

/// EDGE-006/DX-I2: the production open is the writer that clears a checkpoint
/// it cannot resume — the process serves this build's base instead of exiting —
/// and it reports the recovery where this build's surfaces can read it: the boot
/// diagnostic channel and the `runtime.status` payload. `doctor` is unbuilt and
/// the ledger has no command of its own, so those two are the discovery path
/// (DX-I2).
#[test]
fn open_clears_a_stale_checkpoint_and_reports_the_recovery_p21() {
    let root = temp_root("p21");
    std::fs::create_dir_all(root.path().join("runtime")).expect("runtime dir");
    let path = root.path().join("runtime").join("rivect.db");
    let stale = base_v2();
    let stale_digest = BaseSource::new(SHIPPED_BASE_VERSION, &stale).digest();
    {
        let mut store = TaskStore::open(&path).expect("store opens");
        store
            .stage_base(&install(
                root.path(),
                BaseSource::new(SHIPPED_BASE_VERSION, &stale),
            ))
            .expect("the stopped install left its checkpoint");
    }

    // The open recovers: it serves this build's base with no staged row left.
    let mut world = support::open_world_at(root.path(), Some(&user_config("")));
    let active = world
        .runtime
        .store()
        .active_base()
        .expect("base read")
        .expect("a base serves");
    assert_eq!(active.version, SHIPPED_BASE_VERSION);
    assert_eq!(active.digest, config::shipped_revision());
    assert_eq!(
        world.runtime.store().staged_base().expect("staged read"),
        None,
        "the stale checkpoint left the ledger"
    );
    assert_eq!(
        world
            .runtime
            .store()
            .update_receipt(SHIPPED_BASE_VERSION)
            .expect("the serving receipt")
            .digest,
        config::shipped_revision(),
        "the receipt belongs to the document that arrived"
    );

    // Discovery 1: the boot line names the checkpoint it discarded and the
    // resolution, in the shape every boot recovery is reported in.
    let boot = &world.runtime.boot_diagnostics;
    let line = boot
        .iter()
        .find(|line| line.contains("base recovery"))
        .unwrap_or_else(|| panic!("the recovery is reported at boot: {boot:?}"));
    assert!(
        line.contains(&stale_digest),
        "the boot line names the discarded bytes: {line}"
    );
    assert!(
        line.contains("resolution:"),
        "the boot line names what is left to resolve: {line}"
    );

    // Discovery 2: the status payload names the same checkpoint, so a surface
    // that only reads `runtime.status` still sees the recovery.
    let session = world.open_session("update-bootstrap-p21");
    let status: Value = world.dispatch(&support::corpus_status(&session));
    assert!(status["error"].is_null(), "runtime.status: {status}");
    let recovery = &status["result"]["base_recovery"];
    assert_eq!(
        recovery["version"],
        json!(SHIPPED_BASE_VERSION),
        "the status names the version whose checkpoint was discarded: {status}"
    );
    assert_eq!(
        recovery["digest"],
        json!(stale_digest),
        "the status names the bytes that were discarded: {status}"
    );
    assert_eq!(
        status["result"]["update"]["receipt"]["state"], "active",
        "the base serving now is the one the recovery installed: {status}"
    );
}

// ----- p22: the open refuses a changed recorded document, naming the recovery -----

/// AC-054/INV-010a: a recorded base whose shipped bytes changed under the
/// same version is refused at open with the base ledger's cause inside the open
/// failure and the recovery it leaves — the changed document must ship under a
/// new base version — and the refusal leaves every row where it was. Shipping it
/// under the next version is then the step that serves.
#[test]
fn open_refuses_a_changed_recorded_document_with_its_recovery_p22() {
    let root = temp_root("p22");
    std::fs::create_dir_all(root.path().join("runtime")).expect("runtime dir");
    let path = root.path().join("runtime").join("rivect.db");
    let recorded_text = base_v2();
    let recorded_digest = BaseSource::new(SHIPPED_BASE_VERSION, &recorded_text).digest();
    {
        let mut store = TaskStore::open(&path).expect("store opens");
        store
            .serve_base(&install(
                root.path(),
                BaseSource::new(SHIPPED_BASE_VERSION, &recorded_text),
            ))
            .expect("the recorded base serves");
    }

    let Err(failure) = Runtime::open(root.path(), Box::new(LoopbackProvider::new())) else {
        panic!("a recorded document this build changed is refused at open");
    };
    let cause = error_chain(&failure);
    assert!(
        cause.contains("recorded with another document"),
        "the open names the base ledger's cause: {cause}"
    );
    assert!(
        cause.contains("recovery:"),
        "the open names the recovery it leaves: {cause}"
    );
    // INV-010a/P-001: the open keeps the base domain's own class. Read through
    // the storage wrap it would report an unavailable backend for a document
    // conflict, and the operator would look for a broken store instead of the
    // version that has to move.
    let refusal = failure
        .base_refusal()
        .expect("the open keeps the base ledger's refusal typed");
    assert!(
        matches!(
            refusal,
            config::BaseError::DocumentChanged { version } if *version == SHIPPED_BASE_VERSION
        ),
        "the open names the refusal the ledger returned: {refusal}"
    );
    assert_eq!(
        refusal.code(),
        ErrorCode::Conflict,
        "the open reports the base document domain's code, not the store's: {refusal}"
    );

    // The refusal touched nothing: the recorded bytes still serve and no
    // checkpoint or receipt row appeared.
    let mut store = TaskStore::open(&path).expect("the store reopens");
    assert_eq!(
        store
            .active_base()
            .expect("base read")
            .map(|base| base.digest),
        Some(recorded_digest),
        "the recorded document still serves after the refusal"
    );
    assert_eq!(store.staged_base().expect("staged read"), None);

    // The recovery the refusal names is the step that serves: the changed
    // document shipped under the next version installs.
    let served = store
        .serve_base(&install(
            root.path(),
            BaseSource::new(SHIPPED_BASE_VERSION + 1, SHIPPED_DEFAULTS_TOML),
        ))
        .expect("the changed document under a new version serves");
    assert_eq!(served.receipt.base_version, SHIPPED_BASE_VERSION + 1);
    assert_eq!(
        store
            .active_base()
            .expect("base read")
            .map(|base| base.version),
        Some(SHIPPED_BASE_VERSION + 1)
    );
}

/// Every `Display` of one open failure's source chain: the open reports the
/// ledger's cause inside its own, so a surface reads the typed cause here.
fn error_chain(failure: &(dyn std::error::Error + 'static)) -> String {
    let mut lines = vec![failure.to_string()];
    let mut source = failure.source();
    while let Some(err) = source {
        lines.push(err.to_string());
        source = err.source();
    }
    lines.join(": ")
}

// ----- p23: a refused guard edit serves the entry that landed -----

/// AC-054/DEC-009: the guarded edit refreshes the served entry before the
/// admission decides, so a refusal must put the pre-edit entry back — value,
/// layer and revision alike. A read that answered the refreshed entry would name
/// a user document for an edit that never landed.
#[test]
fn refused_guard_edit_serves_the_entry_that_landed_p23() {
    let guard = user_config("[context]\nauto_compact = true\n");
    let mut world = support::open_world("update-p23", Some(&guard));
    let session = world.open_session("update-bootstrap-p23");
    let read: Value = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 9201, "method": "config.read",
        "params": { "schema_version": 1, "session_id": session.0,
                    "keys": ["context.auto_compact"] }
    }));
    assert!(read["error"].is_null(), "{read}");
    let landed = read["result"]["entries"]["items"][0].clone();
    assert_eq!(landed["effective"]["value"], json!(true), "{read}");
    assert_eq!(landed["source"]["kind"], "user", "{read}");

    // The publication target leaves after the open: the edit reaches the
    // admission and is refused there, after the entry was refreshed for it.
    std::fs::remove_file(world.root.join("config.toml")).expect("target deleted after open");
    let refused: Value = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 9202, "method": "command.execute",
        "params": { "schema_version": 1, "session_id": session.0,
                    "command": { "kind": "config.set" },
                    "key": "context.auto_compact", "value": false }
    }));
    assert!(!refused["error"].is_null(), "{refused}");
    assert!(
        refused["error"]["data"]["message"]
            .as_str()
            .expect("typed refusal")
            .contains("publication target does not exist"),
        "the admission itself is refused: {refused}"
    );

    // No surface serves the refused edit: the guard, its layer and the bytes
    // the entry names are the ones that landed before it.
    let read: Value = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 9203, "method": "config.read",
        "params": { "schema_version": 1, "session_id": session.0,
                    "keys": ["context.auto_compact"] }
    }));
    assert!(read["error"].is_null(), "{read}");
    let served = &read["result"]["entries"]["items"][0];
    assert_eq!(
        served["effective"]["value"], landed["effective"]["value"],
        "the refused edit's value is not served: {read}"
    );
    assert_eq!(
        served["source"]["kind"], "user",
        "the entry is still the user's, not the refused edit's: {read}"
    );
    assert_eq!(
        served["source"]["revision"], landed["source"]["revision"],
        "the entry names the bytes that landed, not the refused edit's: {read}"
    );
    assert_eq!(
        world
            .runtime
            .effective()
            .parsed
            .as_ref()
            .expect("the retained document")
            .context
            .auto_compact,
        Some(true),
        "the retained document did not move for a refused edit"
    );

    // The base supplies the guard: the same refusal must not leave a *user*
    // entry for an edit that never landed, so the served entry keeps the base's
    // layer and the base's revision even though the value is the same.
    let mut world = support::open_world("update-p23-base", Some(&user_config("")));
    let session = world.open_session("update-bootstrap-p23-base");
    let read: Value = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 9204, "method": "config.read",
        "params": { "schema_version": 1, "session_id": session.0,
                    "keys": ["context.auto_compact"] }
    }));
    assert!(read["error"].is_null(), "{read}");
    let landed = read["result"]["entries"]["items"][0].clone();
    assert_eq!(
        landed["source"]["kind"], "shipped",
        "the fixture's guard is the base's: {read}"
    );
    std::fs::remove_file(world.root.join("config.toml")).expect("target deleted after open");
    let refused: Value = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 9205, "method": "command.execute",
        "params": { "schema_version": 1, "session_id": session.0,
                    "command": { "kind": "config.set" },
                    "key": "context.auto_compact", "value": true }
    }));
    assert!(!refused["error"].is_null(), "{refused}");
    let read: Value = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 9206, "method": "config.read",
        "params": { "schema_version": 1, "session_id": session.0,
                    "keys": ["context.auto_compact"] }
    }));
    let served = &read["result"]["entries"]["items"][0];
    assert_eq!(
        served["source"]["kind"], "shipped",
        "the guard is still the base's, never the refused edit's: {read}"
    );
    assert_eq!(
        served["source"]["revision"], landed["source"]["revision"],
        "the entry names the base bytes that answered it: {read}"
    );
    assert_eq!(
        served["effective"]["value"],
        json!(false),
        "the refused edit's value is not served: {read}"
    );
}

// ----- p24: the shipped base version names one document -----

/// The identity this build ships (AC-054, INV-010a): the base version compiled
/// in beside the shipped document, and the digest of that exact document.
///
/// Both halves are pinned because every other reference derives the digest from
/// the live text: an edit to the shipped document that keeps its version leaves
/// this suite green, while every store that recorded the previous bytes under
/// that version is refused `base version 1 is recorded with another document` on
/// its next open — a repair only a differently built binary can perform. A
/// changed document is therefore a deliberate step: ship it under the next
/// `SHIPPED_BASE_VERSION` and move this pair with it.
const SHIPPED_BASE_IDENTITY: (u64, &str) = (
    2,
    "4c5534393b44d8221036dd94c23549136670d1448af9b6d04ddc5f7cbf5cadca",
);

/// AC-054/INV-010a: the base version and the shipped document are one identity,
/// so a document edited in place under a version that already recorded other
/// bytes cannot ship.
#[test]
fn shipped_base_version_names_the_document_it_ships_p24() {
    assert_eq!(
        SHIPPED_BASE_VERSION, SHIPPED_BASE_IDENTITY.0,
        "the version moves only with the document it names"
    );
    assert_eq!(
        config::shipped_revision(),
        SHIPPED_BASE_IDENTITY.1,
        "the shipped document is the one this version names: an in-place edit is refused by \
         every store that recorded the previous bytes, so bump the version and this pin together"
    );
}

// ----- p25: the update snapshot, its fence and its retained record -----

/// One staged cutover on a fresh store: the state a snapshot is owed in.
fn staged_cutover(root: &Path) -> TaskStore {
    std::fs::create_dir_all(root).expect("the store root exists");
    let mut store = open_store(root);
    store
        .stage_base(&install(root, BaseSource::new(2, &base_v2())))
        .expect("the offered base stages");
    store
}

/// AC-055/INV-002: the snapshot is taken only while a cutover waits, a record
/// confirmed after it survives both the commit and a reopen, and the snapshot
/// is a reference — the primary is never replaced by it.
#[test]
fn checkpoint_then_owner_ack_survives_recovery() {
    let root = temp_root("checkpoint-ack");
    let mut store = open_store(root.path());

    // No staged base: an ordinary open owns no snapshot, and the answer is
    // absence rather than an empty file.
    assert!(
        snapshot(&store, root.path())
            .expect("an idle store answers")
            .is_none(),
        "a store with no waiting cutover copies nothing"
    );
    assert!(
        !root.path().join("runtime").join("checkpoints").exists(),
        "no snapshot was written for an idle store"
    );

    store
        .stage_base(&install(root.path(), BaseSource::new(2, &base_v2())))
        .expect("the offered base stages");
    let taken = snapshot(&store, root.path())
        .expect("a waiting cutover owns one snapshot")
        .expect("the snapshot is reported");
    assert!(taken.bytes > 0, "the snapshot is not empty");
    let path = root
        .path()
        .join("runtime")
        .join("checkpoints")
        .join(&taken.name);
    assert!(path.is_file(), "the snapshot file exists: {path:?}");
    let snapshot_rows: i64 = rusqlite::Connection::open(&path)
        .expect("the snapshot is a database")
        .query_row("SELECT COUNT(*) FROM tasks", [], |row| row.get(0))
        .expect("the snapshot answers");
    assert_eq!(snapshot_rows, 0, "the snapshot precedes every record");

    // The acknowledged write strictly after the snapshot.
    let session = store
        .open_session("checkpoint-bootstrap", "fixture", None)
        .expect("a session opens")
        .0;
    let task = store
        .create_task(
            &session,
            "cmd-checkpoint-ack",
            "human",
            "survive the cutover",
            (&["one criterion".to_string()], &[]),
        )
        .expect("the task opens")
        .task_id;
    store
        .materialize_obligations(&task)
        .expect("the criteria materialize");
    store
        .insert_evidence_for_task(&task, WORLD, "acknowledged after the snapshot", "ab12")
        .expect("the record is confirmed");
    let confirmed = store.evidence_for_task(&task).expect("the record reads");
    assert_eq!(confirmed.len(), 1, "one record is committed");

    let receipt = store.commit_base(2).expect("the cutover commits");
    assert_eq!(receipt.state, UpdateState::Active);
    drop(store);

    let reopened = open_store(root.path());
    let after = reopened.evidence_for_task(&task).expect("the record reads");
    assert_eq!(after.len(), 1, "the record survived the cutover");
    assert_eq!(after[0].evidence_id.0, confirmed[0].evidence_id.0);
    assert_eq!(after[0].scope, confirmed[0].scope);
    assert_eq!(after[0].observation, confirmed[0].observation);
    assert_eq!(
        after[0].scope, WORLD,
        "the surviving record keeps the scope it was written under"
    );

    // The primary holds what the snapshot did not, so nothing was restored.
    let live_rows: i64 = rusqlite::Connection::open(root.path().join("state.db"))
        .expect("the primary opens")
        .query_row(
            "SELECT COUNT(*) FROM tasks WHERE task_id = ?1",
            [&task.0],
            |row| row.get(0),
        )
        .expect("the primary answers");
    assert_eq!(live_rows, 1, "the post-snapshot write is in the primary");
    let reference_rows: i64 = rusqlite::Connection::open(&path)
        .expect("the snapshot opens")
        .query_row("SELECT COUNT(*) FROM tasks", [], |row| row.get(0))
        .expect("the snapshot answers");
    assert_eq!(
        reference_rows, 0,
        "the snapshot is the point-in-time reference, not a replay source"
    );
}

/// AC-055: an orphaned snapshot is removed only after a coherent outcome, and
/// removing it never touches the primary — the confirmed record is still there
/// and the cleanup names no other file.
#[test]
fn checkpoint_orphan_cleanup_preserves_primary() {
    let root = temp_root("checkpoint-orphan");
    let mut store = staged_cutover(root.path());
    let session = store
        .open_session("orphan-bootstrap", "fixture", None)
        .expect("a session opens")
        .0;
    let task = store
        .create_task(
            &session,
            "cmd-orphan",
            "human",
            "keep the confirmed record",
            (&["one criterion".to_string()], &[]),
        )
        .expect("the task opens")
        .task_id;
    store
        .materialize_obligations(&task)
        .expect("the criteria materialize");
    store
        .insert_evidence_for_task(&task, WORLD, "the confirmed observation", "ab12")
        .expect("the record is confirmed");
    let taken = snapshot(&store, root.path())
        .expect("the snapshot is taken")
        .expect("a snapshot is reported");

    // The cutover stops: the staged checkpoint is abandoned, which is the
    // rollback path, and only then may the snapshot leave.
    let abandoned = store.abandon_base(2).expect("the checkpoint is abandoned");
    assert_eq!(abandoned.version, 2);
    discard_checkpoint(root.path(), &taken.name).expect("the snapshot is removed");
    let path = root
        .path()
        .join("runtime")
        .join("checkpoints")
        .join(&taken.name);
    assert!(!path.exists(), "the orphaned snapshot is gone");

    assert_eq!(
        store
            .evidence_for_task(&task)
            .expect("the record reads")
            .len(),
        1,
        "the primary keeps the confirmed record"
    );
    let live: i64 = rusqlite::Connection::open(root.path().join("state.db"))
        .expect("the primary opens")
        .query_row(
            "SELECT COUNT(*) FROM tasks WHERE task_id = ?1",
            [&task.0],
            |row| row.get(0),
        )
        .expect("the primary answers");
    assert_eq!(live, 1, "cleanup removed a copy, never the primary's row");

    // A name this module did not generate is refused, so a caller cannot turn
    // cleanup into a delete of something else.
    let other = root.path().join("state.db");
    let refusal =
        discard_checkpoint(root.path(), "../state.db").expect_err("a caller path is refused");
    assert_eq!(refusal.boundary(), UpdateBoundary::CheckpointSync);
    assert!(matches!(refusal, UpdateError::SnapshotName));
    assert!(other.exists(), "the refused cleanup deleted nothing");
}

/// AC-055: the surviving record of a failed attempt projects its original
/// boundary and code through the existing wire error after the attempt is
/// re-read from disk — the cause an operator acts on, never prose.
#[test]
fn update_evidence_round_trip_projects_wire_error() {
    let root = temp_root("evidence-round-trip");
    let store = EvidenceStore::open(root.path()).expect("the record directory opens");
    let mut record = UpdateEvidence::fresh(Some(2));
    record.phase = Some(UpdatePhase::Checked);
    record.old_tuple = Some(StoreTuple {
        schema: 2,
        base: 1,
        policy: "0".repeat(64),
    });
    record.note_failure(Failure::at(
        UpdateBoundary::CheckpointCreate,
        ErrorCode::StorageUnavailable,
        None,
    ));
    record.note_failure(Failure::at(
        UpdateBoundary::CheckpointSync,
        ErrorCode::StorageUnavailable,
        None,
    ));
    record.terminal = Terminal::CleanupFailure;
    record.cleanup = CleanupState::Failed;
    let name = store.write(&record).expect("the record lands");
    assert!(name.ends_with(".json"));

    let read = store.read(&name).expect("the record reads back");
    assert_eq!(read, record, "the round trip is byte-stable across fields");
    let wire = read.wire_error().expect("the original cause projects");
    assert_eq!(wire.boundary_id.as_deref(), Some("upd.checkpoint.create"));
    assert_eq!(wire.code, ErrorCode::StorageUnavailable);
    assert_eq!(
        wire.message,
        UpdateBoundary::CheckpointCreate.correction(),
        "the wire message is the closed correction, not assembled prose"
    );
    // A secondary cleanup failure never overwrites the original cause.
    assert_eq!(
        read.first_failure.expect("the first cause").boundary,
        UpdateBoundary::CheckpointCreate
    );
    assert_eq!(read.secondary.len(), 1);

    // The record lives outside the checkpoint tree, so a snapshot cleanup
    // cannot reach it.
    let dir = root.path().join("reports").join("update");
    assert_eq!(
        std::fs::read_dir(&dir)
            .expect("the record directory")
            .count(),
        1
    );
    let mode = std::os::unix::fs::PermissionsExt::mode(
        &std::fs::metadata(dir.join(&name))
            .expect("the record")
            .permissions(),
    ) & 0o777;
    assert_eq!(mode, 0o600, "the record is private");
    let dir_mode = std::os::unix::fs::PermissionsExt::mode(
        &std::fs::metadata(root.path().join("reports").join("update"))
            .expect("the directory")
            .permissions(),
    ) & 0o777;
    assert_eq!(dir_mode, 0o700, "the record directory is private");
}

/// AC-055: every seam this slice opens retains its own token and its own
/// correction, and each token of this half is produced by a real failing call — the map
/// is finite and injective, not a list of promises. Two of the three activation-state
/// seams — `upd.tx.rollback` and `upd.outcome.read` — are retained here but produced by
/// the quarantine child (`rollback_failure_quarantines_until_tuple_readback`).
/// `upd.evidence.terminal` is not produced from a refused call by this suite; see the
/// note in `update_emit_map_rejects_alias_collision` for why it is asserted at its own
/// type instead.
#[test]
fn update_each_emit_seam_retains_its_boundary() {
    let root = temp_root("emit-seams");
    let mut seen: Vec<UpdateBoundary> = Vec::new();

    // upd.identity — the store path no longer names the admitted inode.
    let db_root = root.path().join("identity-root");
    std::fs::create_dir_all(&db_root).expect("the store root");
    let store = staged_cutover(&db_root);
    let db = db_root.join("state.db");
    std::fs::rename(&db, db_root.join("moved.db")).expect("the store is replaced");
    std::fs::write(&db, b"substituted").expect("a substitute appears");
    let identity = snapshot(&store, &db_root).expect_err("a substituted path is refused");
    assert_eq!(identity.boundary(), UpdateBoundary::Identity);
    assert!(matches!(identity, UpdateError::Identity { .. }));
    drop(store);

    // upd.evidence.reserve — the reports path is not a private directory.
    let blocked = root.path().join("reserve-root");
    std::fs::create_dir_all(blocked.join("reports")).expect("the reports parent");
    std::fs::write(blocked.join("reports").join("update"), b"not a directory")
        .expect("a file squats on the record directory");
    let reserve = EvidenceStore::open(&blocked).expect_err("the directory is refused");
    assert_eq!(reserve.boundary(), UpdateBoundary::EvidenceReserve);
    assert_eq!(reserve.code(), ErrorCode::StorageUnavailable);

    // upd.evidence.write — the directory cannot accept the replacement, so the
    // previous record stands.
    let write_root = root.path().join("write-root");
    let writing = EvidenceStore::open(&write_root).expect("the directory opens");
    let mut previous = UpdateEvidence::fresh(None);
    previous.note_failure(Failure::at(
        UpdateBoundary::EvidenceWrite,
        ErrorCode::StorageUnavailable,
        None,
    ));
    let previous_name = writing.write(&previous).expect("the first record lands");
    std::fs::set_permissions(
        write_root.join("reports").join("update"),
        std::os::unix::fs::PermissionsExt::from_mode(0o500),
    )
    .expect("the directory is sealed");
    let mut next = UpdateEvidence::fresh(None);
    next.terminal = Terminal::Rejected;
    let write = writing
        .write(&next)
        .expect_err("the sealed directory refuses");
    assert_eq!(write.boundary(), UpdateBoundary::EvidenceWrite);
    assert_eq!(
        writing
            .read(&previous_name)
            .expect("the previous record survives"),
        previous,
        "a failed replacement never damages the committed record"
    );
    std::fs::set_permissions(
        write_root.join("reports").join("update"),
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .expect("the harness unseals its own directory");

    // upd.checkpoint.space — the checkpoint tree cannot be created.
    let space_root = root.path().join("space-root");
    std::fs::create_dir_all(&space_root).expect("the data root");
    std::fs::write(space_root.join("runtime"), b"not a directory").expect("runtime is a file");
    let space_store = staged_cutover(&space_root);
    let space = snapshot(&space_store, &space_root).expect_err("capacity is refused");
    assert_eq!(space.boundary(), UpdateBoundary::CheckpointSpace);
    drop(space_store);

    // upd.checkpoint.create — the snapshot operation itself cannot run: the
    // ledger it reads is gone.
    let create_root = root.path().join("create-root");
    let create_store = staged_cutover(&create_root);
    rusqlite::Connection::open(create_root.join("state.db"))
        .expect("a second connection")
        .execute_batch("DROP TABLE base_state")
        .expect("the ledger is gone");
    let create = snapshot(&create_store, &create_root).expect_err("the snapshot cannot run");
    assert_eq!(create.boundary(), UpdateBoundary::CheckpointCreate);
    assert_eq!(create.code(), ErrorCode::StorageUnavailable);
    drop(create_store);

    // upd.checkpoint.sync — the snapshot cannot be made durable or removed.
    let sync_root = root.path().join("sync-root");
    let sync_store = staged_cutover(&sync_root);
    let taken = snapshot(&sync_store, &sync_root)
        .expect("the snapshot is taken")
        .expect("a snapshot is reported");
    let snapshot_path = sync_root
        .join("runtime")
        .join("checkpoints")
        .join(&taken.name);
    std::fs::remove_file(&snapshot_path).expect("the file leaves");
    std::fs::create_dir(&snapshot_path).expect("a directory squats on the name");
    let sync = discard_checkpoint(&sync_root, &taken.name).expect_err("durability is refused");
    assert_eq!(sync.boundary(), UpdateBoundary::CheckpointSync);
    std::fs::remove_dir(&snapshot_path).expect("the harness removes its own debris");
    drop(sync_store);

    seen.extend([identity, reserve, write, space, create, sync].map(|error| error.boundary()));

    // The map is finite, injective and fully reachable, and every token is
    // projected with its own correction.
    let mapped: Vec<UpdateBoundary> = UpdateBoundary::CHECKPOINT_SEAMS.to_vec();
    assert_eq!(seen.len(), mapped.len(), "every seam is exercised once");
    for boundary in &mapped {
        assert!(seen.contains(boundary), "{boundary:?} is never produced");
        assert_eq!(
            boundary.wire(ErrorCode::StorageUnavailable).code,
            ErrorCode::StorageUnavailable,
            "{boundary:?} carries the store's own class, not a caller error"
        );
        let wire = boundary.wire(ErrorCode::StorageUnavailable);
        assert_eq!(wire.boundary_id.as_deref(), Some(boundary.token()));
        assert_eq!(wire.message, boundary.correction());
    }
    let tokens: std::collections::BTreeSet<&str> = mapped.iter().map(|b| b.token()).collect();
    assert_eq!(tokens.len(), mapped.len(), "no two seams share a token");
    let corrections: std::collections::BTreeSet<&str> =
        mapped.iter().map(|b| b.correction()).collect();
    assert_eq!(
        corrections.len(),
        mapped.len(),
        "no two seams share a correction"
    );
    for correction in corrections {
        assert!(!correction.ends_with('.'), "corrections carry no full stop");
        assert!(
            correction.is_ascii() && correction.chars().next().is_some_and(char::is_lowercase),
            "a correction is one lowercase english line: {correction}"
        );
    }
}

/// AC-055: each of these three refusals is produced by a cause the correction must
/// actually name. A checkpoint path that is a regular file is not a full disk; a
/// checkpoint statement that failed reads a ledger that was already writable and
/// private; an undecodable record is the ordinary cross-build shape, not a space or
/// permission fault. The case asserts the object each correction names, never its
/// prose.
#[test]
fn checkpoint_and_record_corrections_name_their_own_cause() {
    // The checkpoint path is a regular file: the correction names the path shape.
    let space_root = temp_root("correction-space");
    std::fs::create_dir_all(space_root.path()).expect("the data root");
    std::fs::write(space_root.path().join("runtime"), b"not a directory")
        .expect("runtime is a file");
    let space_store = staged_cutover(space_root.path());
    let space = snapshot(&space_store, space_root.path()).expect_err("the path is refused");
    assert_eq!(space.boundary(), UpdateBoundary::CheckpointSpace);
    drop(space_store);
    let space_correction = UpdateBoundary::CheckpointSpace.correction();
    assert!(
        space_correction.contains("checkpoint")
            && (space_correction.contains("path")
                || space_correction.contains("directory")
                || space_correction.contains("runtime")),
        "capacity is not this cause: the correction must name the checkpoint path: {space_correction}"
    );
    assert!(
        !space_correction.contains("free space"),
        "a regular file squatting on the path is not a full disk: {space_correction}"
    );

    // The snapshot statement failed because the ledger it reads is gone, after the
    // directory was proved writable and private: the correction names that read.
    let create_root = temp_root("correction-create");
    std::fs::create_dir_all(create_root.path().join("runtime")).expect("runtime dir");
    let create_store = staged_cutover(create_root.path());
    rusqlite::Connection::open(create_root.path().join("state.db"))
        .expect("a second connection")
        .execute_batch("DROP TABLE base_state")
        .expect("the ledger is gone");
    let create = snapshot(&create_store, create_root.path()).expect_err("the snapshot refuses");
    assert_eq!(create.boundary(), UpdateBoundary::CheckpointCreate);
    drop(create_store);
    let create_correction = UpdateBoundary::CheckpointCreate.correction();
    assert!(
        create_correction.contains("ledger") || create_correction.contains("snapshot"),
        "a failed snapshot statement is not an unwritable directory: {create_correction}"
    );
    assert!(
        !create_correction.contains("writable"),
        "the directory was already proved writable and private: {create_correction}"
    );

    // `upd.evidence.write` carries three causes: a refused write (the tree), a refused
    // read, and an undecodable record from another build. The one sentence must serve
    // all three without telling an operator to delete a record they still have to
    // resolve — `test-plan.md` forbids exactly that.
    let write_correction = UpdateBoundary::EvidenceWrite.correction();
    assert!(
        write_correction.contains("reports/update")
            && (write_correction.contains("writable")
                || write_correction.contains("private")
                || write_correction.contains("space")),
        "a refused write names the record tree's own condition: {write_correction}"
    );
    assert!(
        write_correction.contains("record") && write_correction.contains("build"),
        "an undecodable record names the record and the build that wrote it: {write_correction}"
    );
    assert!(
        !write_correction.contains("remove") && !write_correction.contains("delete"),
        "the correction never advises deleting a record an operator has not resolved: {write_correction}"
    );

    // `TerminalWrite` is the terminal record's own refusal: it forwards the inner
    // refusal's recovery instead of the permission sentence its boundary carries, so a
    // saturation refusal that happens at the terminal write still says "resolve the
    // retained records".
    let terminal = UpdateError::TerminalWrite {
        source: Box::new(UpdateError::Saturated),
    };
    assert_eq!(terminal.boundary(), UpdateBoundary::EvidenceTerminal);
    assert_eq!(
        terminal.correction(),
        UpdateError::Saturated.correction(),
        "the terminal write keeps the recovery of the refusal that caused it"
    );
    assert!(
        terminal.correction().contains("reports/update"),
        "the forwarded sentence names the records to resolve: {}",
        terminal.correction()
    );
    assert_ne!(
        terminal.correction(),
        UpdateBoundary::EvidenceTerminal.correction(),
        "a saturation refusal is not cleared by fixing permissions"
    );
}

/// AC-055/INV-002: the retained record survives cleanup, is bounded in size,
/// count, depth and detail, refuses an unknown schema, and never evicts an
/// unresolved failure while a resolved success is what becomes prunable.
#[test]
fn update_evidence_trust_and_bounds() {
    let root = temp_root("evidence-bounds");
    let store = EvidenceStore::open(root.path()).expect("the directory opens");

    // A well-formed non-secret token survives classification verbatim.
    let kept = Failure::at(
        UpdateBoundary::CheckpointCreate,
        ErrorCode::StorageUnavailable,
        Some("checkpoint.volume.2"),
    );
    assert_eq!(kept.reason, None);
    assert_eq!(kept.detail.as_deref(), Some("checkpoint.volume.2"));
    // Secret material is dropped with the fixed code, never retained.
    let secret = Failure::at(
        UpdateBoundary::EvidenceReserve,
        ErrorCode::StorageUnavailable,
        Some("token-abc"),
    );
    assert_eq!(secret.reason, Some(FailureReason::RedactedSecret));
    assert_eq!(secret.detail, None, "the secret is not retained at all");
    // Hostile, path-shaped, control-bearing and overlength detail are fixed.
    for hostile in [
        "../../etc/passwd",
        "/absolute/path",
        "Upper",
        "esc\u{1b}[31m",
        &"a".repeat(65),
        "has space",
    ] {
        let failure = Failure::at(
            UpdateBoundary::EvidenceWrite,
            ErrorCode::StorageUnavailable,
            Some(hostile),
        );
        assert_eq!(
            (failure.reason, failure.detail),
            (Some(FailureReason::InvalidDetail), None),
            "{hostile:?} is not retainable"
        );
    }
    // An unknown outcome without detail still names its class.
    let unknown = Failure::at(
        UpdateBoundary::CheckpointCreate,
        ErrorCode::OutcomeUnknown,
        None,
    );
    assert_eq!(unknown.reason, Some(FailureReason::OutcomeUnknown));

    // The ninth secondary failure collapses into the fixed overflow row.
    let mut record = UpdateEvidence::fresh(Some(2));
    for _ in 0..(SECONDARY_MAX + 4) {
        record.note_failure(Failure::at(
            UpdateBoundary::CheckpointSpace,
            ErrorCode::StorageUnavailable,
            None,
        ));
    }
    assert_eq!(
        record.secondary.len(),
        SECONDARY_MAX,
        "the array is bounded"
    );
    assert_eq!(
        record.secondary[SECONDARY_MAX - 1].reason,
        Some(FailureReason::AdditionalFailures)
    );
    let name = store.write(&record).expect("the record lands");
    let encoded = std::fs::metadata(root.path().join("reports").join("update").join(&name))
        .expect("the record")
        .len();
    assert!(
        encoded <= rivect::update::EVIDENCE_MAX_BYTES as u64,
        "one record fits its byte bound: {encoded}"
    );

    // An unknown key, an unknown version and an over-deep document are refused
    // before anything is projected.
    let dir = root.path().join("reports").join("update");
    let tampered = dir.join(format!("{}.json", uuid::Uuid::new_v4()));
    let text = std::fs::read_to_string(dir.join(&name)).expect("the record");
    let unknown_key = text.replacen('{', "{\"unmapped\":1,", 1);
    std::fs::write(&tampered, &unknown_key).expect("a tampered record");
    std::fs::set_permissions(
        &tampered,
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    )
    .expect("the tampered record is private");
    let name_of = |path: &Path| {
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_string()
    };
    let refusal = store
        .read(&name_of(&tampered))
        .expect_err("an unknown key is refused");
    assert_eq!(refusal.boundary(), UpdateBoundary::EvidenceWrite);
    let bad_version = text.replacen("\"version\":1", "\"version\":2", 1);
    std::fs::write(&tampered, bad_version).expect("a wrong-version record");
    std::fs::set_permissions(
        &tampered,
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    )
    .expect("the record stays private");
    assert!(
        store.read(&name_of(&tampered)).is_err(),
        "a v2 record is refused"
    );
    let deep = format!(
        "{{\"version\":1,\"attempt_id\":\"{}\",\"deep\":{}{}}}",
        uuid::Uuid::new_v4(),
        "[".repeat(rivect::update::EVIDENCE_MAX_DEPTH + 1),
        "]".repeat(rivect::update::EVIDENCE_MAX_DEPTH + 1)
    );
    std::fs::write(&tampered, deep).expect("a deep record");
    std::fs::set_permissions(
        &tampered,
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    )
    .expect("the record stays private");
    assert!(store.read(&name_of(&tampered)).is_err(), "depth is bounded");
    std::fs::remove_file(&tampered).expect("the harness removes its debris");

    // A symlink and a hard link are not records.
    let link = dir.join(format!("{}.json", uuid::Uuid::new_v4()));
    std::os::unix::fs::symlink(dir.join(&name), &link).expect("a symlink record");
    assert!(
        store.read(&name_of(&link)).is_err(),
        "a symlink is never followed"
    );
    std::fs::remove_file(&link).expect("the harness removes its link");
    let hard = dir.join(format!("{}.json", uuid::Uuid::new_v4()));
    std::fs::hard_link(dir.join(&name), &hard).expect("a hard-linked record");
    assert!(
        store.read(&name_of(&hard)).is_err(),
        "a multiply-linked record is refused"
    );
    std::fs::remove_file(&hard).expect("the harness removes its link");
    // A record name this module did not generate is not addressable at all.
    assert!(store.read("../../../etc/passwd").is_err());
    assert!(store.read("not-a-uuid.json").is_err());

    // Saturation: 32 unresolved failures block a *new* attempt and evict none.
    let saturating = temp_root("evidence-saturation");
    let full = EvidenceStore::open(saturating.path()).expect("the directory opens");
    for _ in 0..rivect::update::EVIDENCE_MAX_RECORDS {
        let mut failure = UpdateEvidence::fresh(Some(2));
        failure.note_failure(Failure::at(
            UpdateBoundary::EvidenceWrite,
            ErrorCode::StorageUnavailable,
            None,
        ));
        full.write(&failure).expect("the failure record lands");
    }
    let overflow = full
        .write(&UpdateEvidence::fresh(Some(3)))
        .expect_err("a new attempt is refused while the failures stand");
    assert_eq!(overflow.boundary(), UpdateBoundary::EvidenceReserve);
    assert_eq!(
        full.names().expect("the directory lists").len(),
        rivect::update::EVIDENCE_MAX_RECORDS,
        "saturation evicts no unresolved record"
    );

    // A same-base attempt is still admitted, and its success resolves the set:
    // that is the one producer `resolved` has, and only then does the pruner
    // remove anything.
    let mut success = UpdateEvidence::fresh(Some(2));
    success.terminal = Terminal::Success;
    success.cleanup = CleanupState::Done;
    full.write(&success).expect("the resolving success lands");
    let resolved = full.settle_success().expect("the pass resolves the set");
    assert_eq!(
        resolved.resolved,
        rivect::update::EVIDENCE_MAX_RECORDS,
        "every earlier unresolved failure is marked resolved"
    );
    let after = full.names().expect("the directory lists");
    // The pruner never evicts a record that carries a cause, so the settled backlog
    // stays beside the success that settled it: 32 causes plus the one record that
    // proves the convergence. A count bound is not worth the cause an operator has
    // not acted on yet.
    assert_eq!(
        after.len(),
        rivect::update::EVIDENCE_MAX_RECORDS + 1,
        "the causes and the success that settled them are retained"
    );
    let survivors: Vec<UpdateEvidence> = after
        .iter()
        .map(|name| full.read(name).expect("a surviving record reads"))
        .collect();
    assert_eq!(
        survivors
            .iter()
            .filter(|record| record.terminal == Terminal::Success)
            .count(),
        1,
        "the success that proves the convergence is still on disk"
    );
    assert!(
        survivors
            .iter()
            .filter(|record| record.terminal != Terminal::Success)
            .all(|record| record.resolved),
        "every record the success supersedes was marked resolved"
    );

    // Pruning removes a *resolved* record and nothing else: a data root of
    // resolved records accepts the new attempt that the pruner makes room for.
    let prunable = temp_root("evidence-prunable");
    let room = EvidenceStore::open(prunable.path()).expect("the directory opens");
    for _ in 0..rivect::update::EVIDENCE_MAX_RECORDS {
        let mut done = UpdateEvidence::fresh(Some(2));
        done.terminal = Terminal::Success;
        done.resolved = true;
        room.write(&done).expect("a resolved record lands");
    }
    let added = room
        .write(&UpdateEvidence::fresh(Some(2)))
        .expect("the pruner made room for one more attempt");
    assert_eq!(
        room.names().expect("the directory lists").len(),
        rivect::update::EVIDENCE_MAX_RECORDS,
        "the bound holds after the new record"
    );
    assert!(room.read(&added).is_ok(), "the new record is readable");
}

/// AC-055 / `architecture.md:73`: saturation refuses only a *new* attempt whose
/// `offered_base` differs from the last unresolved one. An attempt repeating that
/// base is admitted — otherwise no success could ever pass at 32 unresolved records
/// and `resolved` would never get a producer — and its success settles the backlog
/// and prunes the tree back to the bound.
#[test]
fn evidence_bound_admits_only_the_resolving_success() {
    let root = temp_root("evidence-continuation");
    let store = EvidenceStore::open(root.path()).expect("the directory opens");
    for _ in 0..rivect::update::EVIDENCE_MAX_RECORDS {
        let mut failure = UpdateEvidence::fresh(Some(SHIPPED_BASE_VERSION));
        failure.note_failure(Failure::at(
            UpdateBoundary::EvidenceWrite,
            ErrorCode::StorageUnavailable,
            None,
        ));
        store.write(&failure).expect("the failure record lands");
    }

    // A new attempt of another base is refused: the window is a bound, so no
    // sequence of different attempts can widen it.
    let refused = store
        .write(&UpdateEvidence::fresh(Some(SHIPPED_BASE_VERSION + 1)))
        .expect_err("another base is refused at the bound");
    assert_eq!(refused.boundary(), UpdateBoundary::EvidenceReserve);
    assert!(matches!(refused, UpdateError::Saturated));
    assert_eq!(
        store.names().expect("the directory lists").len(),
        rivect::update::EVIDENCE_MAX_RECORDS,
        "the refusal grew nothing"
    );

    // The saturation refusal's own correction names the recovery that can actually
    // move a count bound, not the permission sentence its boundary carries.
    assert_ne!(
        refused.correction(),
        UpdateBoundary::EvidenceReserve.correction(),
        "a count bound is not cleared by fixing permissions"
    );
    assert!(
        refused.correction().contains("reports/update"),
        "the correction names the records an operator must resolve: {}",
        refused.correction()
    );

    // An attempt repeating the offered base of the newest unresolved record is
    // admitted at the bound: that is the recorded exception, and it is what gives
    // `resolved` a producer at all.
    let mut repeat = UpdateEvidence::fresh(Some(SHIPPED_BASE_VERSION));
    repeat.note_failure(Failure::at(
        UpdateBoundary::EvidenceWrite,
        ErrorCode::StorageUnavailable,
        None,
    ));
    store
        .write(&repeat)
        .expect("a same-offered-base attempt is admitted at the bound");

    // Its success is the write that settles the backlog.
    let mut success = UpdateEvidence::fresh(Some(SHIPPED_BASE_VERSION));
    success.terminal = Terminal::Success;
    success.cleanup = CleanupState::Done;
    store.write(&success).expect("the resolving success lands");

    // The resolve marks the whole backlog — the 32 failures plus the same-base attempt
    // the exception admitted — and the prune then evicts nothing that carries a cause,
    // so the settled set stays beside the success that settled it. `DEC-025` records
    // that cost: the count bound bounds the pruner's work, not the retained evidence.
    assert_eq!(
        store
            .settle_success()
            .expect("the pass resolves the set")
            .resolved,
        rivect::update::EVIDENCE_MAX_RECORDS + 1,
        "every earlier unresolved record is resolved"
    );
    let survivors: Vec<UpdateEvidence> = store
        .names()
        .expect("the directory lists")
        .iter()
        .map(|name| store.read(name).expect("a surviving record reads"))
        .collect();
    assert_eq!(
        survivors.len(),
        rivect::update::EVIDENCE_MAX_RECORDS + 2,
        "the causes and the success that settled them are retained"
    );
    assert!(
        survivors
            .iter()
            .filter(|record| record.terminal != Terminal::Success)
            .all(|record| record.resolved),
        "every record the success supersedes was marked resolved"
    );
}

/// AC-055/DEC-024: a settled success keeps its exact meaning past the count bound —
/// every earlier unresolved record of the data root becomes `resolved` and the pruner
/// restores the bound — while the pass itself holds no tree in memory. The case holds
/// more records than the bound, so a settlement that bounded itself by skipping older
/// records would answer a smaller count here and be refused.
#[test]
fn settlement_covers_every_earlier_record_past_the_bound() {
    let root = temp_root("bounded-settlement");
    let store = EvidenceStore::open(root.path()).expect("the record directory opens");
    let dir = root.path().join("reports").join("update");
    let excess = rivect::update::EVIDENCE_MAX_RECORDS * 2 + 1;
    let mut ordered = Vec::with_capacity(excess + 1);
    for _ in 0..excess {
        let mut failure = UpdateEvidence::fresh(Some(SHIPPED_BASE_VERSION));
        failure.note_failure(Failure::at(
            UpdateBoundary::EvidenceWrite,
            ErrorCode::StorageUnavailable,
            None,
        ));
        ordered.push(store.write(&failure).expect("the failure record lands"));
    }
    let mut success = UpdateEvidence::fresh(Some(SHIPPED_BASE_VERSION));
    success.terminal = Terminal::Success;
    success.cleanup = CleanupState::Done;
    let success_name = store.write(&success).expect("the resolving success lands");
    ordered.push(success_name.clone());
    // Attempt order is the durable write time, so the fixture stamps it: a
    // coarse-grained filesystem would otherwise leave the order to the names, and
    // the settlement's rewrite is exactly what moves a record's write time.
    let epoch = std::time::SystemTime::now() - std::time::Duration::from_secs(86_400);
    for (index, name) in ordered.iter().enumerate() {
        std::fs::File::options()
            .write(true)
            .open(dir.join(name))
            .expect("the record opens")
            .set_times(
                std::fs::FileTimes::new()
                    .set_modified(epoch + std::time::Duration::from_secs(index as u64)),
            )
            .expect("the record is stamped");
    }

    let settlement = store
        .settle_success()
        .expect("the pass settles the backlog");
    assert_eq!(
        settlement.resolved, excess,
        "every earlier unresolved record is resolved, however far past the bound the tree runs"
    );
    // The walk is bounded in what it retains, not in what it touches: the newest-first
    // search stops at the success (one read, since the success is the newest record) and
    // the rewrite walk reads each earlier record once. The pass therefore decodes the
    // tree once, never a second time from a listing it kept.
    assert_eq!(
        settlement.decoded,
        excess + 1,
        "the settlement streams the tree once and retains no decoded record between walks"
    );

    // Nothing this pass may remove left the tree: every earlier record still carries
    // the cause an operator acts on, and the success is the only evidence the
    // convergence happened.
    let survivors = store.names().expect("the directory lists");
    assert_eq!(
        survivors.len(),
        excess + 1,
        "the settled backlog is retained, not evicted as room the success made"
    );
    assert!(
        survivors.contains(&success_name),
        "the success that proves the convergence is still on disk"
    );
    assert!(
        survivors
            .iter()
            .filter(|name| **name != success_name)
            .all(|name| store.read(name).expect("the record reads").resolved),
        "every record the success supersedes was marked resolved"
    );
}

/// AC-055: the process-death hatches are test-only and cannot place a file at a
/// caller's path. A value that is not the data root's own generated marker is
/// refused typed, before any write, and an unarmed hatch does nothing at all.
#[test]
fn process_hatches_write_only_their_generated_marker() {
    let root = temp_root("hatch-paths");
    let marker = rivect::update::hatch_marker(root.path(), "update-pause-after-commit");
    assert!(
        marker.starts_with(root.path()),
        "the marker is the data root's own: {marker:?}"
    );
    // An unarmed run copies nothing: the public hatches return without writing.
    rivect::update::pause_after_commit(root.path());
    rivect::update::pause_after_validation(root.path());
    assert!(
        !root.path().join("runtime").exists(),
        "an unarmed hatch creates no runtime directory"
    );

    // Another data root's marker, an absolute caller path and a traversal are all
    // refused as invalid input, and none of them creates anything.
    let other = temp_root("hatch-other");
    let foreign_marker = rivect::update::hatch_marker(other.path(), "update-pause-after-commit");
    let arbitrary = root.path().join("arbitrary.pid");
    for armed in [
        foreign_marker.as_path(),
        arbitrary.as_path(),
        Path::new("../escape.pid"),
        Path::new("/tmp/escape.pid"),
    ] {
        let error = rivect::update::armed_marker(root.path(), "update-pause-after-commit", armed)
            .expect_err("only the generated marker is armed");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }
    assert!(!arbitrary.exists(), "the refused hatch wrote nothing");
    assert!(
        rivect::update::armed_marker(root.path(), "update-pause-after-commit", &marker).is_ok(),
        "the generated marker itself is armed"
    );

    // A release build carries no reachable block: the exact generated marker is
    // armed and the hatch still writes nothing, because the probe is compiled out
    // rather than refused at runtime. The debug build's arming is proved by the
    // child-entry cases that kill a real process at each milestone.
    if !cfg!(debug_assertions) {
        let armed = temp_root("hatch-release");
        let marker = rivect::update::hatch_marker(armed.path(), "update-pause-after-commit");
        let child = std::process::Command::new(std::env::current_exe().expect("test binary"))
            .args([
                "release_hatch_is_inert_child",
                "--exact",
                "--ignored",
                "--nocapture",
            ])
            .env_clear()
            .env("RIVECT_DATA_ROOT", armed.path())
            .env("RIVECT_UPDATE_PAUSE_AFTER_COMMIT", &marker)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("the child starts");
        let output = child.wait_with_output().expect("the child is reaped");
        assert!(
            output.status.success(),
            "the release hatch returned instead of blocking: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert!(
            !marker.exists(),
            "the release build carries no reachable pause marker"
        );
    }
}

/// Child entry of [`process_hatches_write_only_their_generated_marker`] under a
/// release build: the armed hatch returns immediately, so a shipped process never
/// blocks while it holds the writer lock.
#[test]
#[ignore = "child entry: spawned by process_hatches_write_only_their_generated_marker"]
fn release_hatch_is_inert_child() {
    let data_root = std::env::var_os("RIVECT_DATA_ROOT").expect("the root names the data root");
    let root = Path::new(&data_root);
    rivect::update::pause_after_commit(root);
    rivect::update::pause_after_validation(root);
}

/// AC-055: an interrupted durable replacement leaves the previous committed
/// record readable, and a pending boundary is durable before the effect it
/// names.
#[test]
fn update_evidence_write_interruption_keeps_previous_record() {
    let root = temp_root("evidence-interruption");
    let store = EvidenceStore::open(root.path()).expect("the directory opens");

    // The durable order: pending is committed first, then the effect.
    let mut record = UpdateEvidence::fresh(Some(2));
    record.pending = Some(UpdateBoundary::CheckpointCreate);
    let name = store.write(&record).expect("the pending boundary lands");
    let pending = store.read(&name).expect("the pending record reads");
    assert_eq!(pending.pending, Some(UpdateBoundary::CheckpointCreate));
    assert_eq!(pending.terminal, Terminal::InProgress);

    // The replacement is interrupted twice before it can commit: the old
    // record keeps its terminal, and no half-written record appears.
    let before = store.read(&name).expect("the pending record reads");
    record.pending = None;
    record.terminal = Terminal::Success;
    record.cleanup = CleanupState::Done;
    let dir = root.path().join("reports").join("update");
    let temp = dir.join(format!("{name}.tmp"));
    std::fs::write(&temp, b"{\"version\":1,\"attempt_id\":\"half").expect("a torn temp");
    let names = store.names().expect("the directory lists");
    assert_eq!(names, vec![name.clone()], "a torn temp is not a record");

    // A wider mode on a leftover temp is narrowed, not trusted.
    std::fs::write(&temp, b"stale").expect("a stale temp");
    std::fs::set_permissions(&temp, std::os::unix::fs::PermissionsExt::from_mode(0o644))
        .expect("the stale temp is wide");
    store.write(&record).expect("the replacement commits");
    assert_eq!(
        store.read(&name).expect("the record reads").terminal,
        Terminal::Success,
        "the committed replacement is the new record"
    );
    assert!(!temp.exists(), "the temp is renamed away");
    let mode = std::os::unix::fs::PermissionsExt::mode(
        &std::fs::metadata(dir.join(&name))
            .expect("the record")
            .permissions(),
    ) & 0o777;
    assert_eq!(mode, 0o600, "the replacement is private");
    assert!(
        !before.resolved,
        "the interrupted replacement committed nothing"
    );
    assert_eq!(
        std::fs::read_dir(root.path().join("reports").join("update"))
            .expect("the record directory")
            .count(),
        1,
        "one record, one temp at most, and no debris"
    );
}

// ----- p26: the transactional bootstrap -----

/// AC-055: an ordinary open with no pending cutover copies nothing, so the
/// no-snapshot rule is a property of the store, not of the update path.
#[test]
fn clean_open_without_pending_cutover_creates_no_checkpoint() {
    let root = temp_root("clean-open");
    let mut store = open_store(root.path());
    store
        .serve_base(&install(root.path(), BaseSource::new(1, &base_v1())))
        .expect("the first base is installed");
    drop(store);
    let reopened = open_store(root.path());
    assert!(
        snapshot(&reopened, root.path())
            .expect("an idle store answers")
            .is_none(),
        "no cutover waits, so no snapshot is owed"
    );
    assert!(
        !root.path().join("runtime").join("checkpoints").exists(),
        "an ordinary open wrote no checkpoint directory"
    );
}

/// AC-055: a staged receipt read back after a crash answers the staged shape —
/// `phase` absent and the blocker count present — never a storage refusal. The
/// staged row is not legacy and not activated, and a reopen adds nothing.
#[test]
fn staged_receipt_survives_crash_before_validation() {
    let root = temp_root("staged-receipt");
    let path = root.path().join("state.db");
    {
        let mut store = TaskStore::open(&path).expect("store opens");
        store
            .serve_base(&install(root.path(), BaseSource::new(1, &base_v1())))
            .expect("the first base is recorded");
        store
            .stage_base(&install(root.path(), BaseSource::new(2, &base_v2())))
            .expect("the next base stages");
        // The process ends here: validation never ran.
    }
    let store = TaskStore::open(&path).expect("the store reopens");
    let receipt = store.update_receipt(2).expect("the staged receipt reads");
    assert_eq!(receipt.state, UpdateState::Staged);
    assert_eq!(receipt.phase, None, "a staged base carries no phase");
    assert_eq!(receipt.schema_generation, None);
    assert_eq!(receipt.policy_generation, None);
    let blockers = receipt.blockers.expect("the staged row is not legacy");
    assert!(blockers.items.is_empty());
    assert_eq!(blockers.snapshot_generation, 2);
    let status = store.update_status().expect("the status answers");
    assert_eq!(status.phase, None, "nothing was validated");
    assert_eq!(
        status.base_version,
        Some(1),
        "the previous base still serves while the new one waits"
    );
}

/// AC-055: abandoning a staged set and staging the same version again allocates a
/// fresh epoch from the never-deleted sequence, so a page cursor minted for the
/// discarded set can never address the replacement.
#[test]
fn abandon_then_restage_allocates_a_fresh_set_epoch() {
    let root = temp_root("set-epoch");
    let path = root.path().join("state.db");
    let mut store = TaskStore::open(&path).expect("store opens");
    store
        .serve_base(&install(root.path(), BaseSource::new(1, &base_v1())))
        .expect("the first base is recorded");
    store
        .stage_base(&install(root.path(), BaseSource::new(2, &base_v2())))
        .expect("the checkpoint stages");
    let first = read_set_epoch(&path, 2);
    assert!(first > 0, "the sequence issued an epoch for the first set");
    store.abandon_base(2).expect("the checkpoint is discarded");
    store
        .stage_base(&install(root.path(), BaseSource::new(2, &base_v2())))
        .expect("the same version stages again");
    let second = read_set_epoch(&path, 2);
    assert!(
        second > first,
        "the replacement set carries a fresh epoch, not the discarded one: {first} then {second}"
    );
    drop(store);

    // A reopen does not reset the sequence: the abandoned attempt's epoch stays
    // consumed, so the next set is still newer.
    let mut store = TaskStore::open(&path).expect("the store reopens");
    store
        .abandon_base(2)
        .expect("the second checkpoint is discarded");
    store
        .stage_base(&install(root.path(), BaseSource::new(2, &base_v2())))
        .expect("a third set stages");
    let third = read_set_epoch(&path, 2);
    assert!(third > second, "{second} then {third}");
}

/// AC-085/REQ-004: re-staging the same document under the same version and digest against
/// a changed user layer replaces the sealed set, so the epoch must rotate *whatever path
/// the seal came from*. `INSERT OR IGNORE` keeps the staged row and therefore its epoch,
/// so a staging transaction that reads "I allocated this row's epoch" would replace the
/// members under the epoch a cursor was minted for. The rule is the recorded set, not the
/// caller: a cursor from before the change must answer `BlockerSetMoved`.
#[test]
fn restaging_a_changed_layer_rotates_the_set_epoch() {
    let root = temp_root("restage-epoch");
    std::fs::create_dir_all(root.path().join("runtime")).expect("runtime dir");
    let path = root.path().join("state.db");
    // One keyed purpose record stating two fields the generation declares no purpose for:
    // a two-row set, so the set pages and a cursor exists to invalidate.
    let first_user = user_config(
        "[models.purposes.\"legacy-000\"]\n\
         model = { mode = \"fixed\", connection = \"local\", model_id = \"m000\" }\n\
         effort = { mode = \"fixed\", value = \"high\" }\n",
    );
    std::fs::write(root.path().join("config.toml"), &first_user).expect("the user document lands");
    let mut store = TaskStore::open(&path).expect("the store opens");
    store
        .serve_base(&install(root.path(), BaseSource::new(1, &base_v1())))
        .expect("the first base is recorded");

    // The staged document is the shipped one; only the user's own layer changes below.
    let first_effective =
        config::resolve_effective_on(BaseSource::new(2, &base_v2()), Some(&first_user))
            .expect("the view resolves");
    let staged = install(root.path(), BaseSource::new(2, &base_v2())).pinning(&first_effective);
    store.stage_base(&staged).expect("the checkpoint stages");
    let epoch = read_set_epoch(&path, 2);
    let cursor = store
        .update_status_page(&config::UpdatePage {
            page_size: 1,
            base: Some(2),
            cursor: None,
        })
        .expect("the staged set pages")
        .blockers
        .expect("the staged row carries a set")
        .next_cursor
        .expect("a three-row set needs a second page");

    // The user layer gains another unplaceable record: same version, same digest, a
    // different sealed set. This is the ordinary startup route, not an abandonment.
    let second_user = user_config(
        "[models.purposes.\"legacy-000\"]\n\
         model = { mode = \"fixed\", connection = \"local\", model_id = \"m000\" }\n\
         effort = { mode = \"fixed\", value = \"high\" }\n\
         [models.purposes.\"legacy-001\"]\n\
         model = { mode = \"fixed\", connection = \"local\", model_id = \"m001\" }\n",
    );
    std::fs::write(root.path().join("config.toml"), &second_user).expect("the user document lands");
    let second_effective =
        config::resolve_effective_on(BaseSource::new(2, &base_v2()), Some(&second_user))
            .expect("the view resolves");
    let restaged = install(root.path(), BaseSource::new(2, &base_v2())).pinning(&second_effective);
    store
        .stage_base(&restaged)
        .expect("the same document stages again against the changed layer");
    let rotated = read_set_epoch(&path, 2);
    assert_ne!(
        rotated, epoch,
        "a changed set under the same staged row carries a fresh epoch: {epoch} then {rotated}"
    );

    // The cursor minted for the old set is refused, naming both epochs — never served the
    // replacement's members at its own offset.
    let stale = store
        .update_status_page(&config::UpdatePage {
            page_size: 1,
            base: Some(2),
            cursor: Some(cursor),
        })
        .expect("a moved set is a page-scoped refusal");
    assert!(
        stale.blockers.is_none(),
        "the stale cursor served the replacement set: {stale:?}"
    );
    let conflict = stale
        .page_conflict
        .expect("the stale cursor is refused inside the status");
    let message = conflict.message;
    assert!(
        message.contains(&format!("requested epoch {epoch}"))
            && message.contains(&format!("stored epoch {rotated}")),
        "the refusal names both epochs: {message}"
    );
}

/// The epoch one base row carries, read through its own connection.
fn read_set_epoch(path: &Path, version: u64) -> u64 {
    let raw: i64 = rusqlite::Connection::open(path)
        .expect("the primary opens")
        .query_row(
            "SELECT set_epoch FROM base_state WHERE base_version = ?1",
            [i64::try_from(version).expect("version fits")],
            |row| row.get(0),
        )
        .expect("the row carries its epoch");
    u64::try_from(raw).expect("an epoch is non-negative")
}

/// AC-055: the production startup publishes schema, base and pinned policy as one
/// generation, and the runtime it exposes serves exactly that generation — the
/// same validated object the open resolved, read back through `runtime.status`.
#[test]
fn runtime_open_publishes_only_a_whole_generation() {
    // The root outlives the first world, so the second open below really is a
    // second open of the same data root rather than another first install.
    let root = temp_root("update-startup");
    let mut world = support::open_world_at(root.path(), Some(&user_config("")));
    let session = world.open_session("update-startup-bootstrap");
    let response: Value = world.dispatch(&support::corpus_status(&session));
    let update = &response["result"]["update"];
    assert_eq!(
        update["receipt"]["state"], "active",
        "the base serving now is a whole generation: {response}"
    );
    assert_eq!(
        update["phase"], "activated",
        "the activated row carries its phase: {response}"
    );
    assert_eq!(
        update["schema_generation"], 2,
        "the row names the ledger it was published under"
    );
    let pinned = update["policy_generation"]
        .as_str()
        .expect("the row names the validated policy");
    assert_eq!(pinned.len(), 64, "a policy generation is a sha-256 digest");
    assert_eq!(
        update["receipt"]["policy_generation"], pinned,
        "the receipt and the status name one object"
    );

    // The runtime's effective configuration is the one the row pinned, so the
    // exposure and the durable tuple are the same generation.
    let digest = world.runtime.effective().sources_digest.clone();
    assert_eq!(
        pinned, digest,
        "the exposed configuration is the one the commit recorded"
    );
    // An ordinary open runs the cheap path: no cutover waits, so it copies no
    // snapshot and retains no attempt record.
    let recorded = || {
        EvidenceStore::open(root.path())
            .expect("the record directory opens")
            .names()
            .expect("the records list")
    };
    assert!(
        recorded().is_empty(),
        "an open with no cutover waiting reserves no record"
    );
    assert!(
        !root.path().join("runtime").join("checkpoints").exists(),
        "an open with no cutover waiting copies nothing"
    );
    let pinned = pinned.to_string();
    drop(world);

    // A second open of the same data root publishes nothing new: the whole tuple
    // is already there and the committed generation is read, not rewritten.
    let world = support::open_world_at(root.path(), Some(&user_config("")));
    let status = world.runtime.store().update_status().expect("status reads");
    assert_eq!(status.phase, Some(UpdatePhase::Activated));
    assert_eq!(status.policy_generation.as_deref(), Some(pinned.as_str()));
    assert!(
        recorded().is_empty(),
        "the reopen with no cutover waiting reserves no record either"
    );
}

/// AC-055/EDGE-001: a real child is killed inside the one `IMMEDIATE` the startup
/// publishes, between its DDL batches and the base it was about to write. A
/// compatible reopen then reads the whole old schema/base/policy tuple and the
/// record the owner confirmed after the snapshot.
#[test]
fn bootstrap_kill_between_ddl_reopens_old_tuple() {
    let root = temp_root("bootstrap-kill");
    std::fs::create_dir_all(root.path().join("runtime")).expect("runtime dir");
    let path = root.path().join("runtime").join("rivect.db");
    let marker = rivect::update::hatch_marker(root.path(), "startup-pause");

    // A compatible old generation is already published, and the owner confirms a
    // record after the snapshot it took. The next startup's generation is what the
    // child publishes when it is killed.
    let old = {
        let mut store = TaskStore::open(&path).expect("the old store opens");
        store
            .serve_base(&install(root.path(), BaseSource::new(1, &base_v1())))
            .expect("the first base serves");
        store
            .stage_base(&install(root.path(), BaseSource::new(2, &base_v2())))
            .expect("a cutover waits");
        let session = store
            .open_session("kill-bootstrap", "fixture", None)
            .expect("a session opens")
            .0;
        let task = store
            .create_task(
                &session,
                "cmd-kill-bootstrap",
                "human",
                "survive a killed generation",
                (&["one criterion".to_string()], &[]),
            )
            .expect("the task opens")
            .task_id;
        store
            .materialize_obligations(&task)
            .expect("the criteria materialize");
        // The snapshot comes first, because a record confirmed after it is the one
        // INV-002 is about.
        let taken = snapshot(&store, root.path())
            .expect("the snapshot is taken")
            .expect("a cutover waits");
        store
            .insert_evidence_for_task(&task, WORLD, "confirmed after the snapshot", "ab12")
            .expect("the record is confirmed");
        let record = store
            .evidence_for_task(&task)
            .expect("the record reads")
            .into_iter()
            .next()
            .expect("the record is there");
        let tuple = (store.schema_generation().expect("ledger"), 0u64);
        (task, record, tuple, taken)
    };
    assert!(old.3.bytes > 0);

    let mut child = std::process::Command::new(std::env::current_exe().expect("test binary"))
        .args([
            "bootstrap_startup_child",
            "--exact",
            "--ignored",
            "--nocapture",
        ])
        .env_clear()
        .env("RIVECT_DATA_ROOT", root.path())
        .env("RIVECT_STARTUP_PAUSE", &marker)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("the child starts");
    wait_for_marker(&marker);
    child
        .kill()
        .expect("the child is killed inside the transaction");
    drop(child.wait());

    // The sidecars are read *here*, before any reopen: the open this case performs
    // below replays and removes whatever journal the killed child left, so a check
    // taken after it would answer zero for every implementation, including one that
    // left a hot journal behind. The names are the killed primary's own sidecars.
    let hot_before_recovery = hot_sidecars(&path);
    assert!(
        path.exists(),
        "the measured primary is the database the child was killed over: {path:?}"
    );
    // The same reading must find a journal that really is there, or the arm cannot
    // tell "consumed by recovery" from "never written".
    let control_root = temp_root("hot-journal-control");
    std::fs::create_dir_all(control_root.path()).expect("the control root");
    let control = control_root.path().join("rivect.db");
    std::fs::write(&control, b"primary").expect("the control primary");
    std::fs::write(control.with_file_name("rivect.db-wal"), b"hot frames")
        .expect("the control journal");
    assert_eq!(
        hot_sidecars(&control),
        vec![("rivect.db-wal".to_string(), 10)],
        "the reading detects a deliberately left hot journal"
    );

    // The kill left nothing that a journal replay would apply: the child was inside
    // its own transaction and never committed.
    assert!(
        hot_before_recovery.iter().all(|(_, bytes)| *bytes == 0),
        "the killed child left a hot sidecar the reopen would replay: {hot_before_recovery:?}"
    );

    // The primary holds no trace of the killed generation: the whole old tuple is
    // still what a compatible reopen reads, and no hot journal survived.
    let reopened = TaskStore::open(&path).expect("a compatible reopen reads the store");
    assert_eq!(
        reopened.schema_generation().expect("ledger read"),
        old.2.0,
        "the schema ledger is the old one"
    );
    let (task, record, _, taken) = old;
    let records = reopened.evidence_for_task(&task).expect("the record reads");
    assert_eq!(records.len(), 1, "the confirmed record survived the kill");
    assert_eq!(records[0].evidence_id.0, record.evidence_id.0);
    assert_eq!(records[0].scope, record.scope);
    assert_eq!(records[0].observation, record.observation);
    let status = reopened.update_status().expect("the status answers");
    assert_eq!(
        status.base_version,
        Some(1),
        "the base serving now is the whole old one"
    );
    assert_eq!(
        reopened
            .active_base()
            .expect("base read")
            .map(|base| base.version),
        Some(1),
        "the base that serves is the one the old generation published"
    );
    let newest = status
        .receipt
        .expect("the staged checkpoint is still readable");
    assert_eq!(
        newest.state,
        UpdateState::Staged,
        "the killed generation never activated"
    );
    assert_eq!(newest.phase, None, "nothing of this build activated it");
    assert_eq!(status.phase, None);
    drop(reopened);
    // The reopen consumed whatever the kill left, so the surviving sidecars answer
    // the same reading the pre-recovery measurement used.
    assert!(
        hot_sidecars(&path).iter().all(|(_, bytes)| *bytes == 0),
        "the reopen left a hot sidecar: {:?}",
        hot_sidecars(&path)
    );
    // The snapshot is a reference and never a replay source: the primary still
    // owns the record the snapshot predates.
    let live: i64 = rusqlite::Connection::open(&path)
        .expect("the primary opens")
        .query_row(
            "SELECT COUNT(*) FROM evidence WHERE evidence_id = ?1",
            [&record.evidence_id.0],
            |row| row.get(0),
        )
        .expect("the primary answers");
    assert_eq!(live, 1, "the primary kept the confirmed record");
    let reference: i64 = rusqlite::Connection::open(
        root.path()
            .join("runtime")
            .join("checkpoints")
            .join(&taken.name),
    )
    .expect("the snapshot opens")
    .query_row("SELECT COUNT(*) FROM evidence", [], |row| row.get(0))
    .expect("the snapshot answers");
    assert_eq!(reference, 0, "the snapshot predates the confirmed record");
}

/// The child entry of [`bootstrap_kill_between_ddl_reopens_old_tuple`]: the
/// production startup, which the parent kills while it holds the one transaction
/// that publishes a generation.
#[test]
#[ignore = "child entry: spawned by bootstrap_kill_between_ddl_reopens_old_tuple"]
fn bootstrap_startup_child() {
    let data_root = std::env::var_os("RIVECT_DATA_ROOT").expect("the root names the data root");
    drop(Runtime::open(
        Path::new(&data_root),
        Box::new(LoopbackProvider::new()),
    ));
}

/// The hot sidecars of one primary: every journal or WAL file beside it that holds
/// bytes, named and sized. A sidecar a clean close removed is absent and so is not
/// reported; the caller reads this before a reopen so recovery cannot hide what the
/// writer left.
fn hot_sidecars(primary: &Path) -> Vec<(String, u64)> {
    let Some(name) = primary
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
    else {
        return Vec::new();
    };
    let mut hot = Vec::new();
    for suffix in ["-journal", "-wal"] {
        let sidecar = format!("{name}{suffix}");
        match std::fs::metadata(primary.with_file_name(&sidecar)) {
            Ok(meta) if meta.len() > 0 => hot.push((sidecar, meta.len())),
            Ok(_) => {}
            // SQLite removes a journal and the WAL beside a cleanly closed primary, so
            // absence is not a hot sidecar.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("the sidecar {sidecar:?} cannot be inspected: {error}"),
        }
    }
    hot
}

/// Waits for the child's pause marker under a bounded deadline.
fn wait_for_marker(marker: &Path) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while std::time::Instant::now() < deadline {
        if std::fs::read_to_string(marker).is_ok() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    panic!("the child never reached the startup pause");
}

// ----- activation phase, paged blocker sets and the honest receipt -----

/// AC-055/REQ-001: the status a running runtime serves carries the durable
/// metadata the base row holds — phase, schema generation and the policy digest —
/// read back through storage rather than from memory, and the receipt and status
/// name one page when the request names that receipt's base from the first page.
#[test]
fn runtime_status_consumes_durable_receipt_metadata() {
    let mut world = support::open_world("status-metadata", Some(&user_config("")));
    let session = world.open_session("status-metadata-bootstrap");
    let response: Value = world.dispatch(&support::corpus_status(&session));
    assert!(response["error"].is_null(), "runtime.status: {response}");
    let update = &response["result"]["update"];
    assert_eq!(update["phase"], "activated");
    assert_eq!(update["schema_generation"], 2);
    let policy = update["policy_generation"]
        .as_str()
        .expect("the row names the pinned policy");
    assert_eq!(policy.len(), 64, "a policy generation is a sha-256 digest");
    assert_eq!(update["receipt"]["phase"], "activated");
    assert_eq!(update["receipt"]["schema_generation"], 2);
    assert_eq!(update["receipt"]["policy_generation"], policy);
    let blockers = &update["blockers"];
    assert_eq!(blockers["items"], json!([]));
    assert_eq!(
        blockers["snapshot_generation"],
        json!(SHIPPED_BASE_VERSION),
        "the page names the base its set is immutable under: {response}"
    );
    assert!(blockers.get("next_cursor").is_none(), "one page, terminal");

    // The request names the receipt's base from the first page: the two pages
    // are the same page.
    let named = world
        .runtime
        .store()
        .update_receipt_page(
            SHIPPED_BASE_VERSION,
            &config::UpdatePage {
                page_size: 20,
                base: Some(SHIPPED_BASE_VERSION),
                cursor: None,
            },
        )
        .expect("the receipt pages");
    assert_eq!(
        named.blockers.as_ref(),
        Some(&rivect::contracts::Page::new(
            Vec::new(),
            SHIPPED_BASE_VERSION
        ))
    );
}

/// AC-055/EDGE-012: an attempt that failed validation reports the record it
/// retained — original boundary, code and pointer — through the same status a
/// running runtime serves, and a clean convergence afterwards does not erase it.
#[test]
fn recovered_status_consumes_retained_failure() {
    let root = temp_root("retained-failure");
    std::fs::create_dir_all(root.path().join("runtime")).expect("runtime dir");
    std::fs::create_dir_all(root.path().join("reports")).expect("reports dir");

    let evidence = EvidenceStore::open(root.path()).expect("the record directory opens");
    let mut attempt = UpdateEvidence::fresh(Some(SHIPPED_BASE_VERSION));
    attempt.note_failure(Failure::at(
        UpdateBoundary::Smoke,
        ErrorCode::Conflict,
        Some("smoke-refused"),
    ));
    attempt.terminal = Terminal::Rejected;
    attempt.phase = Some(UpdatePhase::RolledBack);
    attempt.cleanup = CleanupState::Done;
    let name = evidence.write(&attempt).expect("the cause is durable");

    let mut world = support::open_world_at(root.path(), Some(&user_config("")));
    let session = world.open_session("retained-failure-bootstrap");
    let response: Value = world.dispatch(&support::corpus_status(&session));
    assert!(response["error"].is_null(), "runtime.status: {response}");
    let update = &response["result"]["update"];
    let failure = &update["failure"];
    assert_eq!(failure["code"], "conflict", "{response}");
    assert_eq!(failure["boundary_id"], "upd.smoke");
    assert_eq!(
        update["evidence"],
        json!(format!("reports/update/{name}")),
        "the pointer is relative to the data root: {response}"
    );
    assert_eq!(update["receipt"]["state"], "active");
    assert_eq!(update["phase"], "rolled_back");

    // A later clean convergence resolves the record without erasing its cause.
    let mut later = UpdateEvidence::fresh(Some(SHIPPED_BASE_VERSION));
    later.terminal = Terminal::Success;
    later.cleanup = CleanupState::Done;
    later.phase = Some(UpdatePhase::Activated);
    evidence.write(&later).expect("the success lands");
    evidence
        .settle_success()
        .expect("the earlier record resolves");
    let projection = evidence.projection().expect("the records project");
    let failure = projection.failure.expect("the cause survived convergence");
    assert_eq!(failure.boundary_id.as_deref(), Some("upd.smoke"));
    assert_eq!(failure.code, ErrorCode::Conflict);
    assert_eq!(
        projection
            .evidence
            .as_deref()
            .map(|n| format!("reports/update/{n}")),
        Some(format!("reports/update/{name}")),
        "the pointer still names the record that holds the cause"
    );
}

/// AC-055/EDGE-012: with two failed attempts retained the projection names the
/// newest one, so an operator acts on the cause the run actually left behind
/// rather than on the oldest one still on disk.
#[test]
fn projection_names_the_newest_retained_failure() {
    let root = temp_root("newest-failure");
    let evidence = EvidenceStore::open(root.path()).expect("the record directory opens");

    let mut older = UpdateEvidence::fresh(Some(SHIPPED_BASE_VERSION));
    older.note_failure(Failure::at(
        UpdateBoundary::CheckpointCreate,
        ErrorCode::StorageUnavailable,
        None,
    ));
    older.terminal = Terminal::Rejected;
    older.phase = Some(UpdatePhase::RolledBack);
    older.cleanup = CleanupState::Done;
    let older_name = evidence.write(&older).expect("the older cause is durable");
    assert_eq!(
        evidence
            .projection()
            .expect("the record projects")
            .evidence
            .as_deref(),
        Some(older_name.as_str()),
        "the first cause projects while it is the only one"
    );

    // The two records are ordered by durable write time, so the older byte is
    // stamped an hour back: a filesystem with coarse timestamps cannot then make
    // the newer write tie with it.
    let older_path = root.path().join("reports").join("update").join(&older_name);
    std::fs::File::options()
        .write(true)
        .open(&older_path)
        .expect("the older record opens")
        .set_times(
            std::fs::FileTimes::new()
                .set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(3600)),
        )
        .expect("the older record is stamped");
    let mut newer = UpdateEvidence::fresh(Some(SHIPPED_BASE_VERSION));
    newer.note_failure(Failure::at(
        UpdateBoundary::Smoke,
        ErrorCode::Conflict,
        Some("smoke-refused"),
    ));
    newer.terminal = Terminal::Rejected;
    newer.phase = Some(UpdatePhase::RolledBack);
    newer.cleanup = CleanupState::Done;
    let newer_name = evidence.write(&newer).expect("the newer cause is durable");
    assert_ne!(older_name, newer_name);

    let projection = evidence.projection().expect("the records project");
    let failure = projection.failure.expect("a cause survives");
    assert_eq!(failure.boundary_id.as_deref(), Some("upd.smoke"));
    assert_eq!(failure.code, ErrorCode::Conflict);
    assert_eq!(
        projection.evidence.as_deref(),
        Some(newer_name.as_str()),
        "the pointer names the record the newest cause is in"
    );
}

/// AC-055/`DEC.md` DEC-024/INV-007: the recorded admission admits one same-base attempt
/// per open while the cutover stays pending, so the record tree can legitimately hold far
/// more than the count bound. The read side has to stay bounded regardless: a status read
/// decodes a fixed number of the newest records plus the newest one carrying a cause, says
/// so in the projection, and never decodes the records a prune would leave alone.
#[test]
fn saturated_projection_reads_a_bounded_number_of_records() {
    let root = temp_root("bounded-projection");
    let evidence = EvidenceStore::open(root.path()).expect("the record directory opens");
    // Far past the bound: the admission admits these same-base attempts, so the tree
    // really can hold them.
    let excess = rivect::update::EVIDENCE_MAX_RECORDS * 2;
    let dir = root.path().join("reports").join("update");
    let mut names = Vec::with_capacity(excess);
    for _ in 0..excess {
        let mut attempt = UpdateEvidence::fresh(Some(SHIPPED_BASE_VERSION));
        attempt.terminal = Terminal::InProgress;
        attempt.cleanup = CleanupState::Pending;
        names.push(evidence.write(&attempt).expect("the attempt lands"));
    }
    // One older record carrying the cause, placed at the window's own edge: the last
    // record before the newest window. The projection reads the window and then finds
    // the cause on its first reverse step, so the exact decoded total is the window
    // plus one — a mutant that scans even two records further decodes more and fails.
    let mut failed = UpdateEvidence::fresh(Some(SHIPPED_BASE_VERSION));
    failed.note_failure(Failure::at(
        UpdateBoundary::CheckpointCreate,
        ErrorCode::StorageUnavailable,
        None,
    ));
    failed.terminal = Terminal::Rejected;
    failed.phase = Some(UpdatePhase::RolledBack);
    failed.cleanup = CleanupState::Done;
    let cause = evidence.write(&failed).expect("the cause lands");
    // Attempt order is the durable write time, so the fixture stamps it: coarse
    // filesystem timestamps would otherwise leave the order to the generated names.
    let cause_slot = excess + 1 - rivect::update::PROJECTION_MAX_RECORDS - 1;
    let mut ordered = names;
    ordered.insert(cause_slot, cause.clone());
    let epoch = std::time::SystemTime::now() - std::time::Duration::from_secs(86_400);
    for (index, name) in ordered.iter().enumerate() {
        std::fs::File::options()
            .write(true)
            .open(dir.join(name))
            .expect("the record opens")
            .set_times(
                std::fs::FileTimes::new()
                    .set_modified(epoch + std::time::Duration::from_secs(index as u64)),
            )
            .expect("the record is stamped");
    }

    let read = evidence
        .projection()
        .expect("the projection answers over a tree past the bound");
    assert_eq!(
        read.decoded,
        rivect::update::PROJECTION_MAX_RECORDS + 1,
        "the newest window plus exactly one reverse step to the cause at its edge"
    );
    assert!(
        read.decoded < excess,
        "the read is bounded, not linear in the tree: {} of {excess}",
        read.decoded
    );
    assert_eq!(
        read.failure
            .expect("the cause survives the bounded read")
            .boundary_id
            .as_deref(),
        Some("upd.checkpoint.create"),
        "a record carrying a cause is read outside the newest window"
    );
    assert_eq!(
        read.evidence.as_deref(),
        Some(cause.as_str()),
        "the pointer names the record the cause is in"
    );
    assert!(
        read.truncated,
        "the projection says the tree holds more than it read"
    );

    // A tree inside the ceiling reads all of it and reports no truncation.
    let small_root = temp_root("bounded-projection-small");
    let small = EvidenceStore::open(small_root.path()).expect("the record directory opens");
    let mut attempt = UpdateEvidence::fresh(Some(SHIPPED_BASE_VERSION));
    attempt.terminal = Terminal::InProgress;
    small.write(&attempt).expect("the attempt lands");
    let read = small.projection().expect("the projection answers");
    assert_eq!(read.decoded, 1, "a small tree is read whole");
    assert!(
        !read.truncated,
        "a tree inside the ceiling is not truncated"
    );
}

/// AC-055/DEC-024: a projection that read only part of the record tree must say so on the
/// status the caller reads. When the only failure record lies past the bounded scan, a
/// status that reports neither the cause nor the truncation is indistinguishable from a
/// data root where no attempt ever ran — the exact defect the bounded read must not
/// reintroduce.
#[test]
fn truncated_projection_is_reported_on_the_status() {
    let root = temp_root("truncated-status");
    let evidence = EvidenceStore::open(root.path()).expect("the record directory opens");
    let dir = root.path().join("reports").join("update");

    // The oldest record is the only one carrying a cause, and it sits past the newest
    // window *and* past the bounded backward scan, so this read cannot reach it.
    let mut failed = UpdateEvidence::fresh(Some(SHIPPED_BASE_VERSION));
    failed.note_failure(Failure::at(
        UpdateBoundary::CheckpointCreate,
        ErrorCode::StorageUnavailable,
        None,
    ));
    failed.terminal = Terminal::Rejected;
    failed.phase = Some(UpdatePhase::RolledBack);
    failed.cleanup = CleanupState::Done;
    let mut ordered = vec![evidence.write(&failed).expect("the cause lands")];

    let total = rivect::update::PROJECTION_MAX_RECORDS * 3;
    for _ in 0..total {
        let mut attempt = UpdateEvidence::fresh(Some(SHIPPED_BASE_VERSION));
        attempt.terminal = Terminal::InProgress;
        attempt.cleanup = CleanupState::Pending;
        ordered.push(evidence.write(&attempt).expect("the attempt lands"));
    }
    // Attempt order is the durable write time, so the fixture stamps it: the cause stays
    // the oldest record and every attempt sits after it.
    let epoch = std::time::SystemTime::now() - std::time::Duration::from_secs(86_400);
    for (index, name) in ordered.iter().enumerate() {
        std::fs::File::options()
            .write(true)
            .open(dir.join(name))
            .expect("the record opens")
            .set_times(
                std::fs::FileTimes::new()
                    .set_modified(epoch + std::time::Duration::from_secs(index as u64)),
            )
            .expect("the record is stamped");
    }

    let projection = evidence.projection().expect("the projection answers");
    assert!(
        projection.truncated,
        "the fixture must be past the read's ceiling"
    );
    assert!(
        projection.failure.is_none(),
        "the only cause lies past the bounded scan: {projection:?}"
    );

    let store = open_store(root.path());
    let status =
        rivect::update::project_status(&store, &config::UpdatePage::default(), root.path())
            .expect("the status answers");
    let truncated = status.evidence_truncated.clone().unwrap_or_else(|| {
        panic!("the status hides that its projection was truncated: {status:?}")
    });
    assert!(
        truncated.contains("reports/update"),
        "the report names the directory that holds the rest: {truncated}"
    );
    assert!(
        truncated.contains("a retained cause older than the newest records is not reported"),
        "the report says what was not read: {truncated}"
    );

    // A tree inside the ceiling reports no truncation at all.
    let small_root = temp_root("truncated-status-small");
    let small = EvidenceStore::open(small_root.path()).expect("the record directory opens");
    let mut attempt = UpdateEvidence::fresh(Some(SHIPPED_BASE_VERSION));
    attempt.terminal = Terminal::InProgress;
    small.write(&attempt).expect("the attempt lands");
    let store = open_store(small_root.path());
    let status =
        rivect::update::project_status(&store, &config::UpdatePage::default(), small_root.path())
            .expect("the status answers");
    assert!(
        status.evidence_truncated.is_none(),
        "a whole read reports nothing: {status:?}"
    );
}

/// AC-055/DEC-024: a settled tree and a tree that never attempted must not answer
/// alike. `DEC-024` admits a same-base attempt per open, so the record set can grow past
/// the read's window; a settled successor then converges it. The cause the operator has
/// to act on must survive that convergence, and the success that settled it must stay on
/// disk — otherwise the status answers `failure: None` with no truncation, which is
/// exactly the answer an empty data root gives.
#[test]
fn settled_tree_still_answers_its_cause_while_an_empty_tree_answers_none() {
    let root = temp_root("settled-cause");
    let evidence = EvidenceStore::open(root.path()).expect("the record directory opens");
    let dir = root.path().join("reports").join("update");

    // The only cause is the oldest record: the shape a convergence rewrites first, and
    // so the one a later prune would evict if it ordered by write time.
    let mut cause = UpdateEvidence::fresh(Some(SHIPPED_BASE_VERSION));
    cause.note_failure(Failure::at(
        UpdateBoundary::CheckpointCreate,
        ErrorCode::StorageUnavailable,
        None,
    ));
    cause.terminal = Terminal::Rejected;
    cause.phase = Some(UpdatePhase::RolledBack);
    cause.cleanup = CleanupState::Done;
    let cause_name = evidence.write(&cause).expect("the cause lands");
    let mut ordered = vec![cause_name.clone()];
    for _ in 0..rivect::update::EVIDENCE_MAX_RECORDS {
        let mut attempt = UpdateEvidence::fresh(Some(SHIPPED_BASE_VERSION));
        attempt.terminal = Terminal::InProgress;
        ordered.push(evidence.write(&attempt).expect("the attempt lands"));
    }
    let mut success = UpdateEvidence::fresh(Some(SHIPPED_BASE_VERSION));
    success.terminal = Terminal::Success;
    success.cleanup = CleanupState::Done;
    success.phase = Some(UpdatePhase::Activated);
    let success_name = evidence.write(&success).expect("the success lands");
    ordered.push(success_name.clone());
    // Attempt order is the durable write time, so the fixture stamps it: the cause stays
    // the oldest record, and the success the newest.
    let epoch = std::time::SystemTime::now() - std::time::Duration::from_secs(86_400);
    for (index, name) in ordered.iter().enumerate() {
        std::fs::File::options()
            .write(true)
            .open(dir.join(name))
            .expect("the record opens")
            .set_times(
                std::fs::FileTimes::new()
                    .set_modified(epoch + std::time::Duration::from_secs(index as u64)),
            )
            .expect("the record is stamped");
    }

    evidence
        .settle_success()
        .expect("the pass settles the backlog");
    let projection = evidence.projection().expect("the records project");
    assert_eq!(
        projection
            .failure
            .as_ref()
            .expect("the settled tree still answers the cause an operator acts on")
            .boundary_id
            .as_deref(),
        Some("upd.checkpoint.create"),
        "the retained cause is the one the oldest attempt recorded"
    );
    assert!(
        projection.phase.is_none(),
        "the converged attempt projects no phase: the ledger's own row answers"
    );
    assert_eq!(
        projection.evidence.as_deref(),
        Some(cause_name.as_str()),
        "the pointer names the record the cause is in, not the success"
    );

    // A data root that never attempted answers none of it, and is not confused with the
    // settled tree above: no cause, no record, no truncation.
    let empty_root = temp_root("never-attempted");
    let empty = EvidenceStore::open(empty_root.path()).expect("the record directory opens");
    let projection = empty.projection().expect("an empty tree projects");
    assert!(projection.failure.is_none(), "no attempt ever ran");
    assert!(
        projection.evidence.is_none(),
        "no record exists to point at"
    );
    assert!(
        !projection.truncated,
        "an empty tree is read whole, so it owes no truncation"
    );
}

/// AC-055/DEC-025: the retention rule holds on every prune, not only on the pass that
/// settles. A cause that survived a convergence must survive the ordinary write that
/// follows it — the reserve of the next attempt, the first milestone every open takes —
/// or the tree answers `failure: None, truncated: false`, which is the answer a data root
/// that never attempted gives. A resolved record with no cause stays evictable, so one
/// cause does not freeze the tree.
#[test]
fn settled_cause_survives_the_next_ordinary_write() {
    let root = temp_root("settled-cause-next-write");
    let evidence = EvidenceStore::open(root.path()).expect("the record directory opens");
    let dir = root.path().join("reports").join("update");

    // The only cause is the oldest record, the shape the settlement rewrites first.
    let mut cause = UpdateEvidence::fresh(Some(SHIPPED_BASE_VERSION));
    cause.note_failure(Failure::at(
        UpdateBoundary::CheckpointCreate,
        ErrorCode::StorageUnavailable,
        None,
    ));
    cause.terminal = Terminal::Rejected;
    cause.phase = Some(UpdatePhase::RolledBack);
    cause.cleanup = CleanupState::Done;
    let cause_name = evidence.write(&cause).expect("the cause lands");
    let mut ordered = vec![cause_name.clone()];
    for _ in 0..rivect::update::EVIDENCE_MAX_RECORDS {
        let attempt = UpdateEvidence::fresh(Some(SHIPPED_BASE_VERSION));
        ordered.push(evidence.write(&attempt).expect("the attempt lands"));
    }
    let mut success = UpdateEvidence::fresh(Some(SHIPPED_BASE_VERSION));
    success.terminal = Terminal::Success;
    success.cleanup = CleanupState::Done;
    success.phase = Some(UpdatePhase::Activated);
    let success_name = evidence.write(&success).expect("the success lands");
    ordered.push(success_name.clone());
    // Attempt order is the durable write time, so the fixture stamps it: the cause stays
    // the oldest record and the success the newest — the shape that made the settling
    // pass's own listing insufficient.
    let epoch = std::time::SystemTime::now() - std::time::Duration::from_secs(86_400);
    for (index, name) in ordered.iter().enumerate() {
        std::fs::File::options()
            .write(true)
            .open(dir.join(name))
            .expect("the record opens")
            .set_times(
                std::fs::FileTimes::new()
                    .set_modified(epoch + std::time::Duration::from_secs(index as u64)),
            )
            .expect("the record is stamped");
    }
    evidence
        .settle_success()
        .expect("the pass settles the backlog");

    // One further ordinary write: the reserve a real open commits before anything else.
    evidence
        .write(&UpdateEvidence::fresh(Some(SHIPPED_BASE_VERSION)))
        .expect("the next attempt's reserve lands");

    let projection = evidence.projection().expect("the records project");
    assert_eq!(
        projection
            .failure
            .as_ref()
            .expect("the settled tree still answers its cause after an ordinary write")
            .boundary_id
            .as_deref(),
        Some("upd.checkpoint.create"),
        "the prune kept the record that carries the cause"
    );
    assert_eq!(
        projection.evidence.as_deref(),
        Some(cause_name.as_str()),
        "the pointer still names the record the cause is in"
    );
    assert!(
        evidence.read(&success_name).is_ok(),
        "the success that proves the convergence is still on disk"
    );

    // A resolved record with no cause is still evicted when the write needs the room.
    let bound = temp_root("resolved-no-cause-evicted");
    let room = EvidenceStore::open(bound.path()).expect("the record directory opens");
    for _ in 0..rivect::update::EVIDENCE_MAX_RECORDS {
        let mut done = UpdateEvidence::fresh(Some(SHIPPED_BASE_VERSION));
        done.terminal = Terminal::Success;
        done.cleanup = CleanupState::Done;
        done.resolved = true;
        room.write(&done).expect("a resolved record lands");
    }
    room.write(&UpdateEvidence::fresh(Some(SHIPPED_BASE_VERSION)))
        .expect("the pruner made room for one more attempt");
    assert_eq!(
        room.names().expect("the directory lists").len(),
        rivect::update::EVIDENCE_MAX_RECORDS,
        "a record that carries no cause left to restore the bound"
    );

    // A cause a newer record repeats is a duplicate: the newest carrier is retained and an
    // older one may be evicted, so the bound is restored without losing the cause. The
    // older duplicate is exactly what a cause-carrying record freed here.
    let dupes = temp_root("duplicate-cause-evicted");
    let repeated = EvidenceStore::open(dupes.path()).expect("the record directory opens");
    for _ in 0..rivect::update::EVIDENCE_MAX_RECORDS {
        let mut same = UpdateEvidence::fresh(Some(SHIPPED_BASE_VERSION));
        same.note_failure(Failure::at(
            UpdateBoundary::CheckpointCreate,
            ErrorCode::StorageUnavailable,
            None,
        ));
        same.terminal = Terminal::Rejected;
        same.cleanup = CleanupState::Done;
        same.resolved = true;
        repeated.write(&same).expect("the repeated cause lands");
    }
    let before = repeated.names().expect("the directory lists");
    let oldest = before.first().expect("the oldest record").clone();
    let newest_carrier = before.last().expect("the newest record").clone();
    let added = repeated
        .write(&UpdateEvidence::fresh(Some(SHIPPED_BASE_VERSION)))
        .expect("the pruner made room for the newest attempt");
    let after = repeated.names().expect("the directory lists");
    assert_eq!(
        after.len(),
        rivect::update::EVIDENCE_MAX_RECORDS,
        "an older duplicate of the cause is evictable, so the bound holds"
    );
    assert!(
        !after.contains(&oldest),
        "the oldest duplicate is the one record the pass removed"
    );
    assert!(
        after.contains(&newest_carrier),
        "the newest carrier of the cause is retained"
    );
    assert_eq!(
        before.len() + 1 - after.len(),
        1,
        "one record made the room; the bound stops the pass"
    );
    assert!(repeated.read(&added).is_ok(), "the new record lands");
}

/// AC-055/REQ-001: the `checked` milestone is durable before the activation and
/// projected from the record, so a kill between them reopens as checked and never
/// as activated, while a clean run activates and removes its snapshot.
#[test]
fn checked_phase_projects_and_survives_kill_before_activation() {
    let clean = temp_root("checked-clean");
    let mut store = staged_cutover(clean.path());
    let evidence = EvidenceStore::open(clean.path()).expect("the record directory opens");
    let taken = snapshot(&store, clean.path())
        .expect("the snapshot is taken")
        .expect("a cutover waits");
    let mut attempt = UpdateEvidence::fresh(Some(2));
    let pinned = install(clean.path(), BaseSource::new(2, &base_v2()));
    let outcome = rivect::update::activate(
        &mut store,
        clean.path(),
        &evidence,
        &mut attempt,
        Some(&taken.name),
        |store| rivect::update::validate_generation(store, &pinned),
        |store| store.commit_base(2).map(|_receipt| ()),
    )
    .expect("the activation runs");
    assert_eq!(outcome, rivect::update::ActivationOutcome::Activated);
    assert!(
        !clean
            .path()
            .join("runtime")
            .join("checkpoints")
            .join(&taken.name)
            .exists(),
        "the snapshot leaves after the outcome is durable"
    );
    let status = store.update_status().expect("the status answers");
    assert_eq!(status.phase, Some(UpdatePhase::Activated));
    assert_eq!(status.base_version, Some(2));
    let projection = evidence.projection().expect("the record projects");
    assert_eq!(
        projection.phase, None,
        "a converged attempt defers to the row"
    );

    // The kill: a real child runs the production open, reaches the validation
    // milestone inside it, and is killed there. The milestone is durable before
    // the activation, so the reopened data root reads `checked` from the record
    // and `staged` from the ledger — never an apply that had not happened.
    let killed = temp_root("checked-killed");
    std::fs::create_dir_all(killed.path().join("runtime")).expect("runtime dir");
    let path = killed.path().join("runtime").join("rivect.db");
    {
        // The cutover the production open finds waiting: this build's own
        // document, staged and not yet activated.
        let mut store = TaskStore::open(&path).expect("the store opens");
        store
            .stage_base(&install(killed.path(), BaseSource::SHIPPED))
            .expect("the offered base stages");
    }
    let marker = rivect::update::hatch_marker(killed.path(), "update-pause-after-validation");
    let mut child = std::process::Command::new(std::env::current_exe().expect("test binary"))
        .args([
            "checked_milestone_kill_child",
            "--exact",
            "--ignored",
            "--nocapture",
        ])
        .env_clear()
        .env("RIVECT_DATA_ROOT", killed.path())
        .env("RIVECT_UPDATE_PAUSE_AFTER_VALIDATION", &marker)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("the child starts");
    wait_for_marker(&marker);
    child
        .kill()
        .expect("the child is killed at the validation milestone");
    drop(child.wait());

    let evidence = EvidenceStore::open(killed.path()).expect("the record directory opens");
    let names = evidence.names().expect("the records list");
    assert_eq!(names.len(), 1, "the attempt left exactly one record");
    let attempt = evidence.read(&names[0]).expect("the attempt reads");
    assert_eq!(
        attempt.phase,
        Some(UpdatePhase::Checked),
        "the milestone is durable before the activation"
    );
    assert_eq!(
        attempt.pending,
        Some(UpdateBoundary::BaseActivate),
        "the kill left the pending activation boundary"
    );
    assert_eq!(attempt.terminal, Terminal::InProgress);
    let projection = evidence.projection().expect("the records project");
    assert_eq!(
        projection.phase,
        Some(UpdatePhase::Checked),
        "a kill before activation reopens as checked, never as activated"
    );
    let reopened = TaskStore::open(&path).expect("the store reopens");
    assert_eq!(
        reopened
            .staged_base()
            .expect("staged read")
            .map(|base| base.version),
        Some(2),
        "the ledger still holds the base as staged"
    );
    assert_eq!(
        reopened
            .update_status()
            .expect("status")
            .receipt
            .map(|r| r.state),
        Some(UpdateState::Staged),
        "the ledger never claims the activation"
    );
    assert_eq!(
        reopened.update_status().expect("status").phase,
        None,
        "the ledger row never claims checked"
    );
    // Cleanup had not run: the reference snapshot the killed attempt took is
    // still there for the operator, and no terminal record replaced the milestone.
    let snapshots: Vec<std::path::PathBuf> =
        std::fs::read_dir(killed.path().join("runtime").join("checkpoints"))
            .expect("the snapshot directory exists at the kill")
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .collect();
    assert_eq!(snapshots.len(), 1, "the snapshot outlives the kill");
}

/// Child entry of [`checked_phase_projects_and_survives_kill_before_activation`]:
/// the production open, which stops at its own validation milestone.
#[test]
#[ignore = "child entry: spawned by checked_phase_projects_and_survives_kill_before_activation"]
fn checked_milestone_kill_child() {
    let data_root = std::env::var_os("RIVECT_DATA_ROOT").expect("the root names the data root");
    let root = Path::new(&data_root);
    match Runtime::open(root, Box::new(LoopbackProvider::new())) {
        Ok(runtime) => drop(runtime.release()),
        Err(failure) => panic!(
            "the open did not reach its milestone: {}",
            failure.diagnostics().join("; ")
        ),
    }
}

/// AC-055: each seam this slice opens is reachable and retains its own token and
/// correction; a failed validation reports `rolled_back` with its retained seam.
#[test]
fn update_activation_seams_retain_their_boundaries() {
    let root = temp_root("activation-seams");

    // upd.base.stage — the offered base was never staged.
    let mut store = open_store(root.path());
    let evidence = EvidenceStore::open(&root.path().join("stage")).expect("records open");
    let mut attempt = UpdateEvidence::fresh(Some(2));
    let refusal = rivect::update::activate(
        &mut store,
        root.path(),
        &evidence,
        &mut attempt,
        None,
        |_| Ok(()),
        |store| store.commit_base(2).map(|_receipt| ()),
    )
    .expect_err("an unstaged base is refused");
    assert_eq!(refusal.boundary(), UpdateBoundary::BaseStage);
    assert_eq!(
        refusal.code(),
        ErrorCode::Conflict,
        "the base ledger's own class, not the store's"
    );

    // upd.semantic / upd.smoke — the checks fail and the attempt rolls back.
    for (tag, fault, expected) in [
        (
            "semantic",
            "DROP TABLE learning_deltas",
            UpdateBoundary::Semantic,
        ),
        (
            "smoke",
            "UPDATE base_state SET phase = 'bogus' WHERE state = 'staged'",
            UpdateBoundary::Smoke,
        ),
    ] {
        let case = root.path().join(tag);
        let mut store = staged_cutover(&case);
        let evidence =
            EvidenceStore::open(&root.path().join(format!("{tag}-records"))).expect("records open");
        rusqlite::Connection::open(case.join("state.db"))
            .expect("a second connection")
            .execute_batch(fault)
            .expect("the readback is gone");
        let pinned = install(&case, BaseSource::new(2, &base_v2()));
        let mut attempt = UpdateEvidence::fresh(Some(2));
        let outcome = rivect::update::activate(
            &mut store,
            &case,
            &evidence,
            &mut attempt,
            None,
            |store| rivect::update::validate_generation(store, &pinned),
            |store| store.commit_base(2).map(|_receipt| ()),
        )
        .expect("a failed validation rolls the attempt back");
        assert_eq!(outcome, rivect::update::ActivationOutcome::RolledBack);
        let recorded = evidence
            .read(&format!("{}.json", attempt.attempt_id))
            .expect("the attempt is durable");
        assert_eq!(
            recorded
                .first_failure
                .expect("the cause is retained")
                .boundary,
            expected,
            "{tag}: the seam names the check that failed"
        );
        assert_eq!(recorded.phase, Some(UpdatePhase::RolledBack), "{tag}");
    }

    // upd.policy — the pinned generation is not a digest.
    let case = root.path().join("policy");
    let mut store = staged_cutover(&case);
    let evidence = EvidenceStore::open(&root.path().join("policy-records")).expect("records open");
    let mut unpinned = install(&case, BaseSource::new(2, &base_v2()));
    unpinned.policy_generation = "not-a-digest".to_string();
    let mut attempt = UpdateEvidence::fresh(Some(2));
    let outcome = rivect::update::activate(
        &mut store,
        &case,
        &evidence,
        &mut attempt,
        None,
        |store| rivect::update::validate_generation(store, &unpinned),
        |store| store.commit_base(2).map(|_receipt| ()),
    )
    .expect("an unpinned policy rolls the attempt back");
    assert_eq!(outcome, rivect::update::ActivationOutcome::RolledBack);
    assert_eq!(
        evidence
            .read(&format!("{}.json", attempt.attempt_id))
            .expect("the attempt is durable")
            .first_failure
            .expect("the cause is retained")
            .boundary,
        UpdateBoundary::Policy
    );

    // upd.base.activate — a reopened store holds no staged pin to activate with.
    let case = root.path().join("activate");
    drop(staged_cutover(&case));
    let mut store = TaskStore::open(&case.join("state.db")).expect("the store reopens");
    let evidence =
        EvidenceStore::open(&root.path().join("activate-records")).expect("records open");
    let pinned = install(&case, BaseSource::new(2, &base_v2()));
    let mut attempt = UpdateEvidence::fresh(Some(2));
    let refusal = rivect::update::activate(
        &mut store,
        &case,
        &evidence,
        &mut attempt,
        None,
        |store| rivect::update::validate_generation(store, &pinned),
        |store| store.commit_base(2).map(|_receipt| ()),
    )
    .expect_err("the activation cannot record a pin it does not hold");
    assert_eq!(refusal.boundary(), UpdateBoundary::BaseActivate);
    assert_eq!(refusal.code(), ErrorCode::StorageUnavailable);

    // upd.base.stage — the validation refuses and the abandonment that follows it
    // also refuses. The cause is the abandonment's, so the reported seam must be the
    // abandonment's too: pairing the semantic seam's correction with a refused
    // rollback would send an operator to fix the store contract while it is the
    // rollback that never landed.
    let case = root.path().join("abandon-refused");
    let mut store = staged_cutover(&case);
    let evidence =
        EvidenceStore::open(&root.path().join("abandon-refused-records")).expect("records open");
    let pinned = install(&case, BaseSource::new(2, &base_v2()));
    rusqlite::Connection::open(case.join("state.db"))
        .expect("a second connection")
        .execute_batch(
            "DROP TABLE learning_deltas;
             CREATE TRIGGER refuse_abandon BEFORE DELETE ON base_state
             WHEN OLD.state = 'staged'
             BEGIN SELECT RAISE(ABORT, 'the checkpoint refuses to leave'); END;",
        )
        .expect("the semantic check is broken and the abandonment is refused");
    let mut attempt = UpdateEvidence::fresh(Some(2));
    let refusal = rivect::update::activate(
        &mut store,
        &case,
        &evidence,
        &mut attempt,
        None,
        |store| rivect::update::validate_generation(store, &pinned),
        |store| store.commit_base(2).map(|_receipt| ()),
    )
    .expect_err("a refused abandonment is a refusal");
    assert_ne!(
        refusal.boundary(),
        UpdateBoundary::Semantic,
        "the correction describes the seam whose result never arrived"
    );
    assert_eq!(
        refusal.boundary(),
        UpdateBoundary::BaseStage,
        "the abandonment is the step that refused"
    );
    // The first cause stays the validation's — it is immutable by construction — while
    // the refusal names the step whose result never arrived, so the two surfaces answer
    // different questions and neither is rewritten.
    assert_eq!(
        evidence
            .read(&format!("{}.json", attempt.attempt_id))
            .expect("the attempt is durable")
            .first_failure
            .expect("the cause is retained")
            .boundary,
        UpdateBoundary::Semantic,
        "the first cause is never overwritten by the step that followed it"
    );

    // upd.checkpoint.cleanup — the snapshot cannot be removed after a success.
    let case = root.path().join("cleanup");
    let mut store = staged_cutover(&case);
    let evidence = EvidenceStore::open(&root.path().join("cleanup-records")).expect("records open");
    let pinned = install(&case, BaseSource::new(2, &base_v2()));
    let taken = snapshot(&store, &case)
        .expect("the snapshot is taken")
        .expect("a cutover waits");
    let snapshot_path = case.join("runtime").join("checkpoints").join(&taken.name);
    std::fs::remove_file(&snapshot_path).expect("the file leaves");
    std::fs::create_dir(&snapshot_path).expect("a directory squats on the name");
    let mut attempt = UpdateEvidence::fresh(Some(2));
    let refusal = rivect::update::activate(
        &mut store,
        &case,
        &evidence,
        &mut attempt,
        Some(&taken.name),
        |store| rivect::update::validate_generation(store, &pinned),
        |store| store.commit_base(2).map(|_receipt| ()),
    )
    .expect_err("a removal that cannot finish is a cleanup refusal");
    assert_eq!(refusal.boundary(), UpdateBoundary::CheckpointCleanup);
    assert_eq!(
        store.update_status().expect("status").base_version,
        Some(2),
        "the activation already committed; only its cleanup failed"
    );
    std::fs::remove_dir(&snapshot_path).expect("the harness removes its own debris");

    let mapped: Vec<UpdateBoundary> = UpdateBoundary::ACTIVATION_SEAMS.to_vec();
    assert_eq!(mapped.len(), 6, "this slice opens six seams");
    let tokens: std::collections::BTreeSet<&str> = mapped.iter().map(|b| b.token()).collect();
    assert_eq!(tokens.len(), mapped.len(), "no two seams share a token");
    let corrections: std::collections::BTreeSet<&str> =
        mapped.iter().map(|b| b.correction()).collect();
    assert_eq!(
        corrections.len(),
        mapped.len(),
        "no two seams share a correction"
    );
    for boundary in mapped {
        let wire = boundary.wire(ErrorCode::Conflict);
        assert_eq!(wire.boundary_id.as_deref(), Some(boundary.token()));
        assert_eq!(wire.message, boundary.correction());
        assert!(!boundary.correction().ends_with('.'));
    }
}

/// One status request with the nested `update_blockers` object, sibling to the
/// task collections' own `page`.
fn status_with_blockers(session: &rivect::contracts::SessionId, blockers: Value) -> String {
    json!({
        "jsonrpc": "2.0", "id": 2, "method": "runtime.status",
        "params": {
            "schema_version": 1,
            "session_id": session.0,
            "page": { "page_size": 20 },
            "update_blockers": blockers,
        }
    })
    .to_string()
}

/// AC-055: the blocker page is a real bounded projection — a set larger than one
/// page traverses completely and in order, the request's own domains are checked
/// before the store's, a re-created set is a page-scoped conflict that leaves the
/// rest of the status intact, and the two page sizes keep their different rules.
#[test]
fn blocker_page_traverses_and_refuses_by_domain() {
    let mut world = support::open_world("blocker-page", Some(&user_config("")));
    let session = world.open_session("blocker-page-bootstrap");
    let root = world.root.clone();
    let db = root.join("runtime").join("rivect.db");

    // A set of 201 addresses: two full pages of 200 then 200, plus the tail.
    let addresses: Vec<String> = (0..201)
        .map(|index| format!("learning/delta-{index:03}/condition_json"))
        .collect();
    {
        let conn = rusqlite::Connection::open(&db).expect("the store opens");
        conn.execute_batch("BEGIN IMMEDIATE")
            .expect("the write begins");
        for address in &addresses {
            conn.execute(
                "INSERT INTO base_blockers (base_version, address) VALUES (?1, ?2)",
                rusqlite::params![
                    i64::try_from(SHIPPED_BASE_VERSION).expect("version"),
                    address
                ],
            )
            .expect("the row lands");
        }
        conn.execute(
            "UPDATE base_state SET blocker_count = ?2 WHERE base_version = ?1",
            rusqlite::params![
                i64::try_from(SHIPPED_BASE_VERSION).expect("version"),
                i64::try_from(addresses.len()).expect("count")
            ],
        )
        .expect("the count follows the rows");
        conn.execute_batch("COMMIT").expect("the set commits");
    }

    // The default page is 20 and `PAGE_MAX` is served at 200; both traverse.
    let first = world
        .runtime
        .store()
        .update_status_page(&config::UpdatePage::default())
        .expect("the default page serves");
    let page = first.blockers.expect("the base holds a set");
    assert_eq!(page.items.len(), 20, "the default page size is 20");
    assert_eq!(page.snapshot_generation, SHIPPED_BASE_VERSION);
    let cursor = page.next_cursor.expect("a next page exists");

    let mut seen: Vec<String> = page.items.clone();
    let mut cursor = Some(cursor);
    let mut pages = 1;
    while let Some(next) = cursor {
        let page = world
            .runtime
            .store()
            .update_status_page(&config::UpdatePage {
                page_size: 200,
                base: Some(SHIPPED_BASE_VERSION),
                cursor: Some(next),
            })
            .expect("the next page serves")
            .blockers
            .expect("the set is still there");
        assert_eq!(page.snapshot_generation, SHIPPED_BASE_VERSION);
        pages += 1;
        seen.extend(page.items);
        cursor = page.next_cursor;
    }
    assert!(pages >= 2, "a 201-row set needs more than one page");
    assert_eq!(
        seen, addresses,
        "complete traversal, exact order, no repeats"
    );

    // A whole traversal at the default page size: every cursor resumes after the
    // rows the previous page served, so 20-row pages walk 201 rows to a terminal
    // cursor instead of re-reading the first page.
    let mut walked: Vec<String> = Vec::new();
    let mut cursor: Option<String> = None;
    let mut pages = 0usize;
    loop {
        let page = world
            .runtime
            .store()
            .update_status_page(&config::UpdatePage {
                page_size: 20,
                base: Some(SHIPPED_BASE_VERSION),
                cursor: cursor.clone(),
            })
            .expect("the page serves")
            .blockers
            .expect("the set is still there");
        pages += 1;
        walked.extend(page.items);
        cursor = page.next_cursor;
        if cursor.is_none() {
            break;
        }
        assert!(pages <= addresses.len(), "every page makes progress");
    }
    assert_eq!(pages, 11, "201 rows at 20 per page");
    assert_eq!(walked, addresses, "complete traversal at the default size");

    // A page size outside its range is the caller's refusal, while the task
    // collections' own page size still clamps: the two rules stay told apart.
    let response: Value =
        world.dispatch(&status_with_blockers(&session, json!({ "page_size": 500 })));
    assert_eq!(
        response["error"]["data"]["code"], "invalid_input",
        "500 is outside update_blockers.page_size: {response}"
    );
    let clamped: Value = world.dispatch(
        &json!({
            "jsonrpc": "2.0", "id": 3, "method": "runtime.status",
            "params": {
                "schema_version": 1,
                "session_id": session.0,
                "page": { "page_size": 500 },
            }
        })
        .to_string(),
    );
    assert!(
        clamped["error"].is_null(),
        "page.page_size still clamps: {clamped}"
    );
    assert_eq!(
        clamped["result"]["tasks"]["items"].as_array().map(Vec::len),
        Some(0),
        "the clamped page answers rows rather than refusing"
    );

    // A base outside its domain and a malformed or foreign cursor are all caller
    // errors, checked before the store sees them.
    for blockers in [
        json!({ "base": 18446744073709551615u64 }),
        json!({ "cursor": "gen:1:offset:0" }),
        json!({ "cursor": "blk:2:1:offset:99999999999999999999" }),
        json!({ "base": SHIPPED_BASE_VERSION, "cursor": "blk:1:1:offset:0" }),
    ] {
        let response: Value = world.dispatch(&status_with_blockers(&session, blockers.clone()));
        assert_eq!(
            response["error"]["data"]["code"], "invalid_input",
            "{blockers} is refused as caller input: {response}"
        );
    }

    // A stale set epoch is the page-scoped conflict: the status still answers with
    // every other collection, and the conflict names the requested base.
    let stale: Value = world.dispatch(&status_with_blockers(
        &session,
        json!({ "base": SHIPPED_BASE_VERSION, "cursor": "blk:2:9999:offset:0" }),
    ));
    assert!(
        stale["error"].is_null(),
        "the conflict is not the envelope: {stale}"
    );
    let update = &stale["result"]["update"];
    assert_eq!(update["page_conflict"]["code"], "conflict", "{stale}");
    assert!(
        update["page_conflict"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("restart from the first page")),
        "the refusal names the restart: {stale}"
    );
    assert!(
        update.get("blockers").is_none(),
        "the conflict serves no page"
    );
    for collection in ["tasks", "todo", "scheduler"] {
        assert!(
            stale["result"][collection]["items"].is_array(),
            "{collection} survives the page conflict: {stale}"
        );
    }
    assert!(
        stale["result"]["learning"].is_object(),
        "learning survives the page conflict: {stale}"
    );
    assert!(
        stale["result"].get("base_recovery").is_some(),
        "base_recovery survives the page conflict: {stale}"
    );

    // A well-formed cursor whose offset lands past the set is the caller's
    // refusal, not store corruption: it rides the same page-scoped conflict the
    // caller still reads, and the ledger is not reported unavailable.
    let beyond: Value = world.dispatch(&status_with_blockers(
        &session,
        json!({ "base": SHIPPED_BASE_VERSION, "cursor": "blk:2:1:offset:9000" }),
    ));
    assert!(
        beyond["error"].is_null(),
        "an out-of-range cursor is never a whole-request failure: {beyond}"
    );
    let update = &beyond["result"]["update"];
    assert_eq!(
        update["page_conflict"]["code"], "conflict",
        "the refusal is page-scoped: {beyond}"
    );
    assert!(
        update["page_conflict"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("restart from the first page")),
        "the refusal names the restart: {beyond}"
    );
    assert!(
        update.get("blockers").is_none(),
        "the refused page serves no rows: {beyond}"
    );
    for collection in ["tasks", "todo", "scheduler"] {
        assert!(
            beyond["result"][collection]["items"].is_array(),
            "{collection} survives the out-of-range cursor: {beyond}"
        );
    }
}

/// AC-055: the store-level page readers own the page-size domain. A size of zero
/// would mint a cursor that never advances — `LIMIT 1` answers a probe row, `more`
/// is true and the page serves nothing — and a size above `PAGE_MAX` would issue an
/// unbounded `LIMIT`. Both are the caller's refusal, and neither writes.
#[test]
fn store_page_readers_refuse_a_page_size_outside_its_domain() {
    let root = temp_root("page-size-domain");
    std::fs::create_dir_all(root.path().join("runtime")).expect("runtime dir");
    let path = root.path().join("state.db");
    let mut store = TaskStore::open(&path).expect("the store opens");
    store
        .serve_base(&install(root.path(), BaseSource::new(2, &base_v2())))
        .expect("the base serves");
    let before = tree_state(root.path());

    for size in [0, rivect::contracts::PAGE_MAX + 1] {
        let status = store
            .update_status_page(&config::UpdatePage {
                page_size: size,
                base: Some(2),
                cursor: None,
            })
            .expect_err("a page size outside its range is the caller's refusal");
        assert!(
            matches!(status, config::BaseError::InvalidPage { .. }),
            "page size {size} answers the page refusal, not the store's: {status}"
        );
        let receipt = store
            .update_receipt_page(
                2,
                &config::UpdatePage {
                    page_size: size,
                    base: Some(2),
                    cursor: None,
                },
            )
            .expect_err("the receipt page enforces the same domain");
        assert!(
            matches!(receipt, config::BaseError::InvalidPage { .. }),
            "page size {size} answers the page refusal on the receipt: {receipt}"
        );
    }
    assert_eq!(
        tree_state(root.path()),
        before,
        "a refused page size writes nothing"
    );
}

// ----- p27: the ownership pre-check and the AFTER-COMMIT crash -----

/// Child entry: elects the owner of the data root and holds it until the parent
/// kills it, so the refusal is proved against a live second process rather than a
/// second handle in this one.
#[test]
#[ignore = "child entry: spawned by cutover_refuses_live_old_worker_and_incompatible_version"]
fn owner_holder_child() {
    let data_root = std::env::var_os("RIVECT_DATA_ROOT").expect("the root names the data root");
    let marker = std::env::var_os("RIVECT_OWNER_PAUSE").expect("the marker names a file");
    let owner =
        rivect::owner::Owner::elect(Path::new(&data_root)).expect("the child holds the root");
    std::fs::write(&marker, format!("{}\n", std::process::id())).expect("the marker lands");
    drop(std::io::copy(
        &mut std::io::stdin().lock(),
        &mut std::io::sink(),
    ));
    drop(owner);
}

/// Every path under `root` with its length: the zero-write observation for a
/// refused open, taken without reading any file's bytes.
fn tree_state(root: &Path) -> Vec<(std::path::PathBuf, u64)> {
    let mut seen = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries {
            let entry = entry.expect("the fixture lists");
            let path = entry.path();
            let metadata = std::fs::symlink_metadata(&path).expect("the entry inspects");
            if metadata.is_dir() {
                pending.push(path.clone());
            }
            seen.push((path, metadata.len()));
        }
    }
    seen.sort();
    seen
}

/// AC-055/REQ-002/EDGE-002: the update path is refused by a live second process
/// before any DDL of its own, the refusal is discoverable on the failed-open
/// diagnostics as the `upd.owner` seam with the lock file it names, and a store a
/// newer build wrote is refused before it is touched.
#[test]
fn cutover_refuses_live_old_worker_and_incompatible_version() {
    let root = temp_root("live-owner");
    std::fs::create_dir_all(root.path().join("runtime")).expect("runtime dir");
    let marker = root.path().join("owner.pid");
    let mut child = std::process::Command::new(std::env::current_exe().expect("test binary"))
        .args(["owner_holder_child", "--exact", "--ignored", "--nocapture"])
        .env_clear()
        .env("RIVECT_DATA_ROOT", root.path())
        .env("RIVECT_OWNER_PAUSE", &marker)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("the holder starts");
    wait_for_marker(&marker);
    let holder: i32 = std::fs::read_to_string(&marker)
        .expect("the holder names itself")
        .trim()
        .parse()
        .expect("the marker holds a pid");
    assert_ne!(holder, i32::try_from(std::process::id()).expect("this pid"));

    // The update path: the production open. The live holder is refused typed —
    // the owner's own error, not a storage slot's — and the refusal names the
    // seam, the lock file and the correction on the diagnostics channel, so an
    // operator reading the failed open sees which process to close.
    let before = tree_state(root.path());
    let Err(failure) = Runtime::open(root.path(), Box::new(LoopbackProvider::new())) else {
        panic!("a live second owner refuses the update path");
    };
    let cause = std::error::Error::source(&failure)
        .and_then(|source| source.downcast_ref::<rivect::owner::OwnerError>())
        .expect("the refusal keeps the owner's typed cause");
    assert!(
        matches!(cause, rivect::owner::OwnerError::AlreadyOwned),
        "the second process is the refusal: {cause}"
    );
    // The refusal is discoverable on the failed open itself: the seam's own two
    // lines — the boundary token with the lock another process holds, and the
    // one-line correction — ride `OpenError::diagnostics()`, the vector
    // `Runtime::open` prints to boot stderr. `WireError` is unreachable before an
    // open, so this is the pre-open channel, not a second one.
    let diagnostics = failure.diagnostics();
    let pointer = diagnostics
        .iter()
        .find(|line| line.contains("upd.owner"))
        .unwrap_or_else(|| panic!("the refusal is not silent: {diagnostics:?}"));
    assert!(
        pointer.contains("runtime/owner.lock"),
        "the refusal names the lock the other process holds: {pointer}"
    );
    assert!(
        diagnostics
            .iter()
            .any(|line| line.starts_with("update next: ")),
        "the refusal carries the boundary's correction: {diagnostics:?}"
    );
    assert_eq!(
        tree_state(root.path()),
        before,
        "a refused update wrote nothing: no DDL, no snapshot, no record"
    );

    child.kill().expect("the holder is killed");
    drop(child.wait());
    // The refusal left no lock behind of its own: the next update path serves.
    let world = support::open_world_at(root.path(), Some(&user_config("")));
    assert_eq!(
        world
            .runtime
            .store()
            .active_base()
            .expect("base read")
            .map(|base| base.version),
        Some(SHIPPED_BASE_VERSION),
        "the cutover completes once the holder is gone"
    );
    drop(world);

    // The pre-DDL version guard: a generation this build does not know is refused
    // after the cutover and before any byte of DDL or ledger write.
    let db = root.path().join("runtime").join("rivect.db");
    rusqlite::Connection::open(&db)
        .expect("the primary opens")
        .execute_batch("PRAGMA user_version = 99")
        .expect("a newer generation is recorded");
    let before = tree_state(root.path());
    let Err(refusal) = Runtime::open(root.path(), Box::new(LoopbackProvider::new())) else {
        panic!("a newer generation is refused");
    };
    let cause = error_chain(&refusal);
    assert!(
        cause.contains("schema generation"),
        "the version guard names its own domain: {cause}"
    );
    assert_eq!(
        tree_state(root.path()),
        before,
        "the refused generation is never rewritten"
    );
    let ledger: i64 = rusqlite::Connection::open(&db)
        .expect("the primary opens")
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .expect("the ledger reads");
    assert_eq!(
        ledger, 99,
        "the newer generation stays where it was written"
    );
}

/// Child entry of [`after_commit_crash_reopens_new_tuple_and_preserves_owner_ack`]:
/// the real update attempt, which the parent kills after the activation committed
/// and before any cleanup or exposure.
#[test]
#[ignore = "child entry: spawned by after_commit_crash_reopens_new_tuple_and_preserves_owner_ack"]
fn after_commit_update_child() {
    let data_root = std::env::var_os("RIVECT_DATA_ROOT").expect("the root names the data root");
    let root = Path::new(&data_root);
    let mut store = TaskStore::open(&root.join("runtime").join("rivect.db")).expect("store opens");
    store
        .stage_base(&install(root, BaseSource::SHIPPED))
        .expect("the offered base stages");
    let taken = snapshot(&store, root)
        .expect("the snapshot is taken")
        .expect("a cutover waits");
    let session = store
        .open_session("after-commit", "fixture", None)
        .expect("a session opens")
        .0;
    let task = store
        .create_task(
            &session,
            "cmd-after-commit",
            "human",
            "survive a killed activation",
            (&["one criterion".to_string()], &[]),
        )
        .expect("the task opens")
        .task_id;
    store
        .materialize_obligations(&task)
        .expect("the criteria materialize");
    store
        .insert_evidence_for_task(&task, WORLD, "confirmed after the snapshot", "ab12")
        .expect("the record is confirmed");
    let evidence = EvidenceStore::open(root).expect("the record directory opens");
    let mut attempt = UpdateEvidence::fresh(Some(SHIPPED_BASE_VERSION));
    let pinned = install(root, BaseSource::SHIPPED);
    rivect::update::activate(
        &mut store,
        root,
        &evidence,
        &mut attempt,
        Some(&taken.name),
        |store| rivect::update::validate_generation(store, &pinned),
        |store| store.commit_base(SHIPPED_BASE_VERSION).map(|_receipt| ()),
    )
    .expect("the activation commits");
}

/// AC-055/REQ-001/EDGE-001: a real child commits the activation and is killed
/// AFTER COMMIT and BEFORE cleanup or exposure. A compatible reopen reads the
/// whole new schema/base/policy tuple, the record the owner confirmed after the
/// snapshot by id/scope/content, and the retained evidence of the attempt; the
/// snapshot is removed only after that readback.
#[test]
fn after_commit_crash_reopens_new_tuple_and_preserves_owner_ack() {
    let root = temp_root("after-commit");
    std::fs::create_dir_all(root.path().join("runtime")).expect("runtime dir");
    let marker = rivect::update::hatch_marker(root.path(), "update-pause-after-commit");
    let mut child = std::process::Command::new(std::env::current_exe().expect("test binary"))
        .args([
            "after_commit_update_child",
            "--exact",
            "--ignored",
            "--nocapture",
        ])
        .env_clear()
        .env("RIVECT_DATA_ROOT", root.path())
        .env("RIVECT_UPDATE_PAUSE_AFTER_COMMIT", &marker)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("the child starts");
    wait_for_marker(&marker);
    let snapshot_dir = root.path().join("runtime").join("checkpoints");
    let at_kill: Vec<std::path::PathBuf> = std::fs::read_dir(&snapshot_dir)
        .expect("the snapshot directory exists at the kill")
        .map(|entry| entry.expect("the fixture lists").path())
        .collect();
    assert_eq!(
        at_kill.len(),
        1,
        "the snapshot is still on disk at the kill: {at_kill:?}"
    );
    child.kill().expect("the child is killed after COMMIT");
    drop(child.wait());

    // The compatible reopen: the whole new tuple, read back through the
    // production path rather than from the child's memory.
    let world = support::open_world_at(root.path(), Some(&user_config("")));
    assert_eq!(
        world
            .runtime
            .store()
            .schema_generation()
            .expect("ledger read"),
        2,
        "the reopened store is the new schema generation"
    );
    let active = world
        .runtime
        .store()
        .active_base()
        .expect("base read")
        .expect("a base serves");
    assert_eq!(active.version, SHIPPED_BASE_VERSION);
    assert_eq!(active.digest, config::shipped_revision());
    let status = world
        .runtime
        .store()
        .update_status()
        .expect("status answers");
    assert_eq!(status.phase, Some(UpdatePhase::Activated));
    assert_eq!(
        status.policy_generation.as_deref(),
        Some(config::shipped_revision().as_str()),
        "the pinned policy is the whole config object the cutover validated"
    );

    // The record confirmed after the snapshot, by id, scope and content.
    let task = {
        let conn = rusqlite::Connection::open(root.path().join("runtime").join("rivect.db"))
            .expect("the primary opens");
        let id: String = conn
            .query_row("SELECT task_id FROM tasks", [], |row| row.get(0))
            .expect("the task survives the cutover");
        rivect::contracts::TaskId(id)
    };
    let records = world
        .runtime
        .store()
        .evidence_for_task(&task)
        .expect("the record reads");
    assert_eq!(records.len(), 1, "one record is committed");
    assert_eq!(records[0].scope, WORLD);
    assert_eq!(records[0].observation, "confirmed after the snapshot");
    assert_eq!(
        records[0].digest, "ab12",
        "the content digest survives unchanged"
    );

    // The attempt's own evidence survived the kill with cleanup still pending, so
    // no cleanup ran before the outcome was read back.
    let evidence = EvidenceStore::open(root.path()).expect("the record directory opens");
    let names = evidence.names().expect("the records list");
    assert_eq!(names.len(), 1, "the attempt left exactly one record");
    let attempt = evidence.read(&names[0]).expect("the attempt reads");
    assert_eq!(attempt.terminal, Terminal::Success);
    assert_eq!(
        attempt.cleanup,
        CleanupState::Pending,
        "the kill preceded cleanup"
    );
    assert_eq!(
        attempt.observed_tuple.as_ref().map(|tuple| tuple.base),
        Some(SHIPPED_BASE_VERSION),
        "the record names the tuple it activated"
    );
    assert!(
        at_kill[0].exists(),
        "the snapshot outlives the crash until the outcome is read back"
    );

    // Cleanup happens only now, after the readback: it removes the snapshot and
    // nothing of the primary.
    let snapshot_name = at_kill[0]
        .file_name()
        .and_then(|name| name.to_str())
        .expect("the snapshot is a generated name")
        .to_string();
    discard_checkpoint(root.path(), &snapshot_name)
        .expect("the snapshot is removed after the readback");
    assert!(!at_kill[0].exists(), "the snapshot is gone");
    assert_eq!(
        world
            .runtime
            .store()
            .evidence_for_task(&task)
            .expect("the record reads")
            .len(),
        1,
        "cleanup removed a copy, never the confirmed record"
    );
    drop(world);
    let reopened = TaskStore::open(&root.path().join("runtime").join("rivect.db"))
        .expect("the store reopens again");
    assert_eq!(
        reopened
            .active_base()
            .expect("base read")
            .map(|base| base.version),
        Some(SHIPPED_BASE_VERSION),
        "the repeat reopen is idempotent"
    );
}

/// AC-055: the `upd.owner` seam on its own — its token and correction, and the
/// injection restricted to that seam: a held owner makes the production open
/// refuse exactly this boundary, retains no record, and names no other seam.
#[test]
fn owner_seam_refuses_a_held_root_before_any_effect() {
    let root = temp_root("owner-seam");
    std::fs::create_dir_all(root.path().join("runtime")).expect("runtime dir");
    let evidence = EvidenceStore::open(root.path()).expect("the record directory opens");

    // The seam is one row of the closed map, with its own token and correction.
    assert_eq!(UpdateBoundary::OWNER_SEAMS, [UpdateBoundary::Owner]);
    assert_eq!(UpdateBoundary::Owner.token(), "upd.owner");
    let correction = UpdateBoundary::Owner.correction();
    assert!(!correction.ends_with('.'), "corrections carry no full stop");
    assert!(
        correction.chars().next().is_some_and(char::is_lowercase),
        "a correction is one lowercase english line: {correction}"
    );
    let wire = UpdateBoundary::Owner.wire(ErrorCode::Denied);
    assert_eq!(wire.boundary_id.as_deref(), Some("upd.owner"));
    assert_eq!(wire.message, correction);

    // The injection: a held owner, and the production open as the update path.
    let held = rivect::owner::Owner::elect(root.path()).expect("the fixture holds the root");
    let Err(failure) = Runtime::open(root.path(), Box::new(LoopbackProvider::new())) else {
        panic!("a held root refuses the update path");
    };
    assert!(
        matches!(
            std::error::Error::source(&failure)
                .and_then(|source| source.downcast_ref::<rivect::owner::OwnerError>()),
            Some(rivect::owner::OwnerError::AlreadyOwned)
        ),
        "the refusal keeps the owner's typed cause"
    );

    // The diagnostics name this seam and nothing else: no other retained token
    // appears, so the injection is restricted to `upd.owner`.
    let lines = failure.diagnostics();
    let seam_lines: Vec<&String> = lines
        .iter()
        .filter(|line| line.contains("update boundary: "))
        .collect();
    assert_eq!(seam_lines.len(), 1, "one boundary is named: {lines:?}");
    assert!(
        seam_lines[0].contains("upd.owner") && seam_lines[0].contains("runtime/owner.lock"),
        "the line names the seam and the lock: {}",
        seam_lines[0]
    );
    assert!(
        !lines.iter().any(|line| line.contains("upd.identity")
            || line.contains("upd.evidence")
            || line.contains("upd.checkpoint")
            || line.contains("upd.base")
            || line.contains("upd.semantic")
            || line.contains("upd.policy")
            || line.contains("upd.smoke")),
        "no other seam is claimed by this refusal: {lines:?}"
    );
    assert!(
        evidence.names().expect("the records list").is_empty(),
        "the refused admission wrote no record"
    );

    // The correction rides the same channel, and a failure that is not the
    // competing holder adds no line of its own.
    assert!(
        lines
            .iter()
            .any(|line| line == &format!("update next: {correction}")),
        "the correction is the boundary's own row: {lines:?}"
    );
    assert!(
        owner_refusal_diagnostics(&rivect::owner::OwnerError::Io(std::io::Error::other(
            "unrelated",
        )))
        .is_empty(),
        "only the competing-holder refusal is diagnosed here"
    );

    // The injection is the held root, not a permanent refusal: releasing it lets
    // the same path serve.
    drop(held);
    let world = support::open_world_at(root.path(), Some(&user_config("")));
    assert_eq!(
        world
            .runtime
            .store()
            .active_base()
            .expect("base read")
            .map(|base| base.version),
        Some(SHIPPED_BASE_VERSION),
        "the released root serves"
    );
}

// ----- p28: rollback, current policy, reopen consent and the downgrade recovery -----

/// AC-055/INV-002/INV-003: the snapshot is taken before the current owner's
/// deletion and revocation, so the file itself still holds the deleted record and
/// the pre-revocation consent; the primary stays authoritative — the deleted
/// record is absent, the revoked principal is denied and only a fresh explicit
/// grant lets a control principal read the retained bytes.
#[test]
fn rollback_preserves_current_deletion_and_policy() {
    let root = temp_root("rollback-policy");
    std::fs::create_dir_all(root.path().join("runtime")).expect("runtime dir");
    let mut store = staged_cutover(root.path());

    let session = store
        .open_session("rollback-policy-bootstrap", "fixture", None)
        .expect("a session opens")
        .0;
    let task = store
        .create_task(
            &session,
            "cmd-rollback-policy",
            "human",
            "keep the retained record",
            (&["one criterion".to_string()], &[]),
        )
        .expect("the task opens")
        .task_id;
    store
        .materialize_obligations(&task)
        .expect("the criteria materialize");
    store
        .insert_evidence_for_task(&task, WORLD, "retained bytes", "ab12")
        .expect("the record is confirmed");
    let kept = store
        .evidence_for_task(&task)
        .expect("the record reads")
        .into_iter()
        .next()
        .expect("one record");
    store
        .insert_evidence_for_task(&task, WORLD, "deleted bytes", "cd34")
        .expect("the second record is confirmed");
    let deleted = store
        .evidence_for_task(&task)
        .expect("the records read")
        .into_iter()
        .find(|record| record.observation == "deleted bytes")
        .expect("the second record is present");
    let scope = root.path().join("read-scope");
    std::fs::create_dir_all(&scope).expect("the scope exists");
    let consent_scope = rivect::policy::preapproval_scope(
        rivect::contracts::EffectClass::Read,
        "grant-1",
        &scope.display().to_string(),
    )
    .expect("a canonical preapproval key");
    store
        .record_preapproval(&consent_scope, "fixture", 600)
        .expect("the consent is recorded");
    assert!(
        store.is_preapproved(&consent_scope).expect("the row reads"),
        "the pre-revocation consent is durable before the snapshot"
    );

    // The rehearsal snapshot is taken BEFORE the deletion and the revocation, so
    // the file itself holds both; the primary is what an operator reads.
    let taken = snapshot(&store, root.path())
        .expect("the snapshot is taken")
        .expect("a cutover waits");
    let snapshot_path = root
        .path()
        .join("runtime")
        .join("checkpoints")
        .join(&taken.name);
    let archived: i64 = rusqlite::Connection::open(&snapshot_path)
        .expect("the snapshot is a database")
        .query_row(
            "SELECT COUNT(*) FROM evidence WHERE evidence_id = ?1",
            [&deleted.evidence_id.0],
            |row| row.get(0),
        )
        .expect("the snapshot answers");
    assert_eq!(
        archived, 1,
        "the snapshot file holds the record the primary deleted"
    );
    let archived_consent: i64 = rusqlite::Connection::open(&snapshot_path)
        .expect("the snapshot is a database")
        .query_row(
            "SELECT COUNT(*) FROM preapprovals WHERE scope = ?1",
            [&consent_scope],
            |row| row.get(0),
        )
        .expect("the snapshot answers");
    assert_eq!(
        archived_consent, 1,
        "the snapshot file holds the pre-revocation consent"
    );
    // The current owner then confirms a write AFTER the snapshot and before the
    // recovery: the rehearsal owes both halves, and this record is the one the
    // snapshot cannot hold.
    store
        .insert_evidence_for_task(&task, WORLD, "confirmed after the snapshot", "ef56")
        .expect("the owner confirms a record after the snapshot");
    let after_snapshot = store
        .evidence_for_task(&task)
        .expect("the records read")
        .into_iter()
        .find(|record| record.observation == "confirmed after the snapshot")
        .expect("the confirmed record is in the primary");
    let archived_after: i64 = rusqlite::Connection::open(&snapshot_path)
        .expect("the snapshot is a database")
        .query_row(
            "SELECT COUNT(*) FROM evidence WHERE evidence_id = ?1",
            [&after_snapshot.evidence_id.0],
            |row| row.get(0),
        )
        .expect("the snapshot answers");
    assert_eq!(
        archived_after, 0,
        "the record confirmed after the snapshot is not in it"
    );

    // The current owner then deletes one record and the live grant is revoked:
    // the primary is what stays authoritative.
    store
        .delete_scoped_record(&task, &deleted.evidence_id.0)
        .expect("the record is deleted in the primary");
    // The primary stays authoritative: the deleted record is absent, and the
    // retained record reads exactly as it was written.
    let live = store.evidence_for_task(&task).expect("the records read");
    assert_eq!(
        live.len(),
        2,
        "the deletion holds in the primary and the post-snapshot record stays"
    );
    assert_eq!(live[0].observation, "retained bytes");
    assert_eq!(live[0].scope, WORLD);
    assert_eq!(live[0].digest, "ab12");

    // A live revocation outranks any earlier consent, and a fresh explicit grant
    // is what lets the control principal read the retained bytes.
    let mut policy = rivect::policy::Policy::default();
    let grant = policy.grant_read(scope.clone());
    let context = |approved: bool| rivect::policy::AdmissionContext {
        mode: rivect::policy::PermissionMode::Auto,
        in_grant_scope: true,
        budget_remaining: true,
        in_trusted_scope: true,
        has_checkpoint: false,
        previously_approved: approved,
        within_declared_bounds: false,
        dry_run: false,
    };
    assert_eq!(
        policy.decide(&scope, rivect::contracts::EffectClass::Read, &context(true)),
        rivect::policy::ModeDecision::Allow,
        "the live grant admits the retained scope"
    );
    policy.revoke(&grant);
    let denied = policy.admit(&grant, rivect::contracts::EffectClass::Read);
    assert!(
        matches!(denied, Err(rivect::policy::PolicyError::Revoked { .. })),
        "the live revocation survives the rehearsal: {denied:?}"
    );
    let fresh = policy.grant_read(scope.clone());
    assert!(
        policy
            .admit(&fresh, rivect::contracts::EffectClass::Read)
            .is_ok(),
        "a fresh explicit grant is what admits the retained bytes again"
    );

    // Rollback, not restoration: the cutover is abandoned, the snapshot removed,
    // and a reopen reads the primary's own tuple.
    store.abandon_base(2).expect("the cutover is rolled back");
    drop(store);
    discard_checkpoint(root.path(), &taken.name).expect("the snapshot is removed");
    assert!(
        !snapshot_path.exists(),
        "the reference snapshot leaves after the outcome"
    );
    let reopened = open_store(root.path());
    let after = reopened.evidence_for_task(&task).expect("the records read");
    assert_eq!(
        after.len(),
        2,
        "no archived row was replayed into the primary"
    );
    assert_eq!(after[0].evidence_id.0, kept.evidence_id.0);
    assert_eq!(after[0].observation, "retained bytes");
    assert_eq!(after[0].scope, WORLD);
    // The write the current owner confirmed after the snapshot, read back by id,
    // scope and content once recovery has run.
    let recovered = after
        .iter()
        .find(|record| record.evidence_id.0 == after_snapshot.evidence_id.0)
        .expect("the post-snapshot record survives recovery");
    assert_eq!(recovered.scope, WORLD);
    assert_eq!(recovered.observation, "confirmed after the snapshot");
    assert_eq!(recovered.digest, "ef56");
    assert_eq!(
        reopened
            .staged_base()
            .expect("staged read")
            .map(|base| base.version),
        None,
        "the rolled-back cutover left no checkpoint"
    );
    drop(reopened);

    // After recovery, the same two verdicts on the executor's own read path against the
    // retained bytes: the control principal's permitted read returns exactly what was
    // written, and the revoked principal is refused on that same seam rather than on a
    // bare policy call.
    let mut world = support::open_world_at(root.path(), Some(&user_config("")));
    let control_session = world.open_session("rollback-policy-control");
    let control_task = world.create_task(&control_session, "cmd-rollback-policy-control");
    // The same verdicts on the executor's own read path, against the retained bytes:
    // the control principal's permitted read returns exactly what was written, and the
    // revoked principal is refused on that same seam rather than on a bare policy call.
    let retained_file = scope.join("retained.txt");
    std::fs::write(&retained_file, b"retained bytes").expect("the retained bytes are on disk");
    let control = world.runtime.policy_writer().grant_read(scope.clone());
    let mut worker = support::PlatformWorker::default();
    let admitted = world
        .runtime
        .executor_with_worker(&mut worker)
        .admit(
            &control_task,
            rivect::executor::EffectRequest::Read {
                grant_id: control.clone(),
                path: retained_file.clone(),
            },
            rivect::policy::PermissionMode::Manual,
        )
        .expect("the control principal's scoped read admits");
    let outcome = world
        .runtime
        .executor_with_worker(&mut worker)
        .execute(&admitted)
        .expect("the control principal's read reaches the retained bytes");
    let rivect::executor::EffectOutcome::Read { bytes, .. } = outcome else {
        panic!("the control principal's read returns the bytes it read");
    };
    assert_eq!(
        bytes, b"retained bytes",
        "the permitted control read returns the retained bytes unchanged"
    );
    world.runtime.policy_writer().revoke(&control);
    let denied = world
        .runtime
        .executor_with_worker(&mut worker)
        .admit(
            &control_task,
            rivect::executor::EffectRequest::Read {
                grant_id: control,
                path: retained_file,
            },
            rivect::policy::PermissionMode::Manual,
        )
        .expect_err("the revoked principal is denied on the same read seam");
    assert!(
        matches!(
            denied,
            rivect::executor::ExecutorError::Policy(rivect::policy::PolicyError::Revoked { .. })
        ),
        "the revocation is what refuses the read: {denied:?}"
    );
    drop(world);
}

/// AC-055/INV-003: a new process starts deny-by-default and imports no consent
/// from a snapshot. The one durable consent surface a snapshot could resurrect is
/// the `preapprovals` row, so the tests write it into the store `Runtime::open`
/// actually opens — `runtime/rivect.db` — and hold the same admission context
/// against a live row and against a revoked one: the verdict flips exactly when
/// the primary's row changes, so the denial is about the row, not about the
/// fixture.
#[test]
fn reopen_never_imports_snapshot_grants() {
    let root = temp_root("reopen-grants");
    let data_root = root.path().to_path_buf();
    let scope = data_root.join("read-scope");
    std::fs::create_dir_all(&scope).expect("the scope exists");
    let consent_scope = rivect::policy::preapproval_scope(
        rivect::contracts::EffectClass::Read,
        "grant-1",
        &scope.display().to_string(),
    )
    .expect("a canonical preapproval key");
    // The reopened path, which is the database the runtime reads.
    std::fs::create_dir_all(data_root.join("runtime")).expect("runtime dir");
    let primary = data_root.join("runtime").join("rivect.db");
    let target = scope.clone();
    let context = |store: &TaskStore| {
        rivect::executor::admission_context(
            store,
            rivect::policy::PermissionMode::PreapprovedOnly,
            rivect::contracts::EffectClass::Read,
            "grant-1",
            &scope,
            &target,
        )
        .expect("the admission context reads")
    };

    let taken = {
        let mut store = TaskStore::open(&primary).expect("the store opens");
        store
            .stage_base(&install(&data_root, BaseSource::new(2, &base_v2())))
            .expect("the offered base stages");
        store
            .record_preapproval(&consent_scope, "fixture", 600)
            .expect("the consent is recorded");
        // The negative control: while the row is live in the primary, the very
        // same admission is admitted, so the assertion below discriminates.
        assert!(
            context(&store).previously_approved,
            "the live row is what admits the read"
        );
        assert_eq!(
            rivect::policy::Policy::default().decide(
                &target,
                rivect::contracts::EffectClass::Read,
                &context(&store)
            ),
            rivect::policy::ModeDecision::Allow,
            "a live consent admits the read before the revocation"
        );
        let taken = snapshot(&store, &data_root)
            .expect("a snapshot is taken")
            .expect("a cutover waits");
        // The live row leaves the primary: the revocation the snapshot must not
        // undo when the next process opens this root.
        store
            .record_preapproval(&consent_scope, "fixture", -600)
            .expect("the consent is revoked in the primary");
        assert!(
            !store.is_preapproved(&consent_scope).expect("the row reads"),
            "the revocation holds in the primary"
        );
        taken
    };
    let snapshot_path = data_root
        .join("runtime")
        .join("checkpoints")
        .join(&taken.name);
    let archived: i64 = rusqlite::Connection::open(&snapshot_path)
        .expect("the snapshot is a database")
        .query_row(
            "SELECT COUNT(*) FROM preapprovals WHERE scope = ?1",
            [&consent_scope],
            |row| row.get(0),
        )
        .expect("the snapshot answers");
    assert_eq!(
        archived, 1,
        "the snapshot really holds the row a restore would have imported"
    );
    // The snapshot stays on disk across the measured open. An implementation that
    // restored grants from a snapshot would find this file — it is the only
    // surviving copy of the live consent — so the assertions below can red.
    assert!(
        snapshot_path.exists(),
        "the resurrection source is on disk before the next process opens"
    );

    let mut runtime = Runtime::open(&data_root, Box::new(LoopbackProvider::new()))
        .expect("the reopened runtime serves");
    // The measured window is over: the archive the snapshot held was readable
    // throughout it, and the fresh process still admits nothing from it.
    assert!(
        snapshot_path.exists(),
        "the open neither restored from nor removed the rehearsal's snapshot"
    );
    let still_archived: i64 = rusqlite::Connection::open(&snapshot_path)
        .expect("the surviving snapshot is still a database")
        .query_row(
            "SELECT COUNT(*) FROM preapprovals WHERE scope = ?1",
            [&consent_scope],
            |row| row.get(0),
        )
        .expect("the surviving snapshot answers");
    assert_eq!(
        still_archived, 1,
        "the row a restore would import was readable for the whole measured window"
    );
    // A new process mints no grant: the id the snapshot's row was keyed for is
    // simply absent from the live policy.
    assert!(
        runtime.policy().grant("grant-1").is_none(),
        "a new process starts with no grant at all"
    );
    let before = context(runtime.store());
    assert!(
        !before.previously_approved,
        "the reopened store carries no live consent row"
    );
    assert_eq!(
        runtime
            .policy()
            .decide(&target, rivect::contracts::EffectClass::Read, &before),
        rivect::policy::ModeDecision::Deny,
        "the reopened policy denies the read the snapshot still holds"
    );

    let grant = runtime.policy_writer().grant_read(scope.clone());
    let after = rivect::executor::admission_context(
        runtime.store(),
        rivect::policy::PermissionMode::Auto,
        rivect::contracts::EffectClass::Read,
        &grant,
        &scope,
        &target,
    )
    .expect("the admission context reads after the grant");
    assert_eq!(
        runtime
            .policy()
            .decide(&target, rivect::contracts::EffectClass::Read, &after),
        rivect::policy::ModeDecision::Allow,
        "the fresh explicit grant is what admits the retained scope"
    );
    drop(runtime);
    let checkpoints: Vec<std::path::PathBuf> =
        std::fs::read_dir(data_root.join("runtime").join("checkpoints"))
            .map(|entries| {
                entries
                    .filter_map(Result::ok)
                    .map(|entry| entry.path())
                    .collect()
            })
            .unwrap_or_default();
    assert_eq!(
        checkpoints,
        vec![snapshot_path.clone()],
        "the production open removed its own snapshot and left the rehearsal's alone: {checkpoints:?}"
    );
    // The archive outlives the whole test, so nothing above could have passed by
    // the snapshot being gone.
    assert!(
        snapshot_path.exists(),
        "the resurrection source survived every assertion in this case"
    );
}

/// AC-055/REQ-003: an incompatible downgrade is refused without rewriting the
/// primary, names a recovery, and the compatible runtime that recovery names
/// opens and reaches every usable-state assertion.
#[test]
fn downgrade_recovery_opens_compatible_runtime() {
    let root = temp_root("downgrade-recovery");
    std::fs::create_dir_all(root.path().join("runtime")).expect("runtime dir");
    let data_root = root.path().to_path_buf();
    let path = data_root.join("runtime").join("rivect.db");
    std::fs::write(
        data_root.join("config.toml"),
        user_config("[workflow]\nenabled = false\n"),
    )
    .expect("config write");

    // The installation records the base this build ships, with a record and an
    // explicit setting that must survive both the refusal and the recovery.
    let task;
    let recorded_id;
    {
        let mut store = TaskStore::open(&path).expect("the primary opens");
        let session = store
            .open_session("downgrade-bootstrap", "fixture", None)
            .expect("a session opens")
            .0;
        task = store
            .create_task(
                &session,
                "cmd-downgrade",
                "human",
                "survive an incompatible downgrade",
                (&["one criterion".to_string()], &[]),
            )
            .expect("the task opens")
            .task_id;
        store
            .materialize_obligations(&task)
            .expect("the criteria materialize");
        store
            .insert_evidence_for_task(&task, WORLD, "pre-downgrade bytes", "ab12")
            .expect("the record is confirmed");
        recorded_id = store
            .evidence_for_task(&task)
            .expect("the record reads back")
            .into_iter()
            .next()
            .expect("the record is there")
            .evidence_id
            .0;
        let served = store
            .serve_base(&install(&data_root, BaseSource::SHIPPED))
            .expect("the shipped base serves");
        assert_eq!(served.receipt.base_version, SHIPPED_BASE_VERSION);
    }

    // The incompatible runtime offers the predecessor the ledger has passed.
    let refusal = {
        let mut store = TaskStore::open(&path).expect("the store opens");
        store
            .serve_base(&install(&data_root, BaseSource::new(1, &base_v1())))
            .expect_err("the downgrade is refused")
    };
    assert!(
        matches!(
            refusal,
            config::BaseError::NewerRecorded {
                offered: 1,
                recorded: SHIPPED_BASE_VERSION
            }
        ),
        "the downgrade is its own typed refusal: {refusal}"
    );
    assert_eq!(refusal.code(), ErrorCode::Conflict);
    let message = refusal.to_string();
    assert!(
        message.contains("recovery:"),
        "the refusal names its recovery: {message}"
    );
    assert!(
        message.contains(&format!("recorded base {SHIPPED_BASE_VERSION}")),
        "the recovery names the generation to restore: {message}"
    );
    // The primary is not rewritten and not truncated: the recorded base still
    // serves and nothing was staged.
    {
        let store = TaskStore::open(&path).expect("the store opens");
        assert_eq!(
            store
                .active_base()
                .expect("base read")
                .map(|base| base.version),
            Some(SHIPPED_BASE_VERSION),
            "the refused downgrade rewrote nothing"
        );
        assert_eq!(
            store.staged_base().expect("staged read"),
            None,
            "the refused downgrade staged nothing"
        );
    }

    // The recovery the refusal names, executed: the compatible runtime opens and
    // all five usable-state assertions hold.
    let world = support::open_world_at(&data_root, None);
    assert_eq!(
        world
            .runtime
            .store()
            .schema_generation()
            .expect("ledger read"),
        2,
        "the compatible runtime opens"
    );
    let status = world
        .runtime
        .store()
        .update_status()
        .expect("status answers");
    assert_eq!(
        status.base_version,
        Some(SHIPPED_BASE_VERSION),
        "runtime.status names the generation"
    );
    let records = world
        .runtime
        .store()
        .evidence_for_task(&task)
        .expect("the pre-downgrade record reads");
    assert_eq!(records.len(), 1, "the record survives by id");
    assert_eq!(
        records[0].evidence_id.0, recorded_id,
        "the record read back is the one captured before the downgrade"
    );
    assert_eq!(records[0].observation, "pre-downgrade bytes");
    assert_eq!(records[0].digest, "ab12");
    assert_eq!(
        world.runtime.effective().workflow_entry.source.kind,
        "user",
        "the explicit setting keeps its own layer"
    );
    assert_eq!(
        world.runtime.effective().composed().workflow.enabled,
        Some(false),
        "workflow stays explicit after the recovery"
    );
    assert_eq!(
        status.receipt.map(|receipt| receipt.base_version),
        Some(SHIPPED_BASE_VERSION),
        "the refusal is typed and names the restored generation"
    );
}

/// AC-055/data-integrity: an explicit rollback that fails, and a `COMMIT` whose
/// result never arrives, both quarantine the store. Nothing is exposed, retried or
/// cleaned up until a compatible reopen reads the whole tuple back, and the
/// attempt's original cause survives that convergence.
#[test]
fn rollback_failure_quarantines_until_tuple_readback() {
    // `RIVECT_UPDATE_FAULT_STEP` is compiled out of a build without debug
    // assertions, so there is no seam left to arm there and the case proves itself
    // only in the debug build. A release build skips it rather than asserting a
    // quarantine no environment can request.
    if !cfg!(debug_assertions) {
        return;
    }
    let root = temp_root("rollback-quarantine");
    std::fs::create_dir_all(root.path().join("runtime")).expect("runtime dir");
    let marker = root.path().join("rollback.pid");
    for step in ["rollback", "commit"] {
        let child = std::process::Command::new(std::env::current_exe().expect("test binary"))
            .args([
                "rollback_quarantine_child",
                "--exact",
                "--ignored",
                "--nocapture",
            ])
            .env_clear()
            .env("RIVECT_DATA_ROOT", root.path())
            .env("RIVECT_UPDATE_FAULT_STEP", step)
            .env("RIVECT_ROLLBACK_MARKER", &marker)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("the child starts");
        let output = child.wait_with_output().expect("the child is reaped");
        assert!(
            output.status.success(),
            "{step}: the child reached every assertion it owns: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        let reported = std::fs::read_to_string(&marker).expect("the child reports");
        std::fs::remove_file(&marker).expect("the marker is cleared");
        assert!(
            reported.contains(step),
            "{step}: the child reached the quarantined path: {reported}"
        );
    }

    // The compatible reopen reads the whole tuple back; the attempt's cause is
    // still the one an operator acts on.
    let path = root.path().join("state.db");
    let reopened = TaskStore::open(&path).expect("the compatible reopen succeeds");
    let tuple = reopened.generation_tuple().expect("the tuple reads");
    assert_eq!(tuple.schema, 2, "the schema the primary holds");
    assert_eq!(tuple.base, None, "no activation landed");
    assert!(tuple.policy.is_none(), "no policy was pinned");

    let evidence = EvidenceStore::open(root.path()).expect("the record directory opens");
    let mut attempt = UpdateEvidence::fresh(Some(2));
    attempt.note_failure(Failure::at(
        UpdateBoundary::BaseActivate,
        ErrorCode::Conflict,
        Some("activation-refused"),
    ));
    attempt.terminal = Terminal::Rejected;
    evidence.write(&attempt).expect("the cause is durable");
    let projection = evidence.projection().expect("the records project");
    assert_eq!(
        projection
            .failure
            .expect("the cause survived")
            .boundary_id
            .as_deref(),
        Some("upd.base.activate"),
        "the retained cause is the one the attempt first failed on"
    );
}

/// Child entry of [`rollback_failure_quarantines_until_tuple_readback`]: one real
/// staged cutover, one armed fault, and the quarantine assertion that follows it.
#[test]
#[ignore = "child entry: spawned by rollback_failure_quarantines_until_tuple_readback"]
fn rollback_quarantine_child() {
    let data_root = std::env::var_os("RIVECT_DATA_ROOT").expect("the root names the data root");
    let step = std::env::var("RIVECT_UPDATE_FAULT_STEP").expect("the step is armed");
    let marker = std::env::var_os("RIVECT_ROLLBACK_MARKER").expect("the marker names a file");
    let root = Path::new(&data_root);
    let mut store = staged_cutover(root);
    // The rollback fault needs a refusal that reaches the explicit rollback: a
    // version the ledger never staged is the one refusal available without a
    // second staged base. The commit fault needs the activation itself.
    let offered = if step == "rollback" { 99 } else { 2 };
    let refusal = store
        .commit_base(offered)
        .expect_err("the injected fault refuses the activation");
    assert!(
        matches!(
            refusal,
            config::BaseError::RollbackFailed { .. } | config::BaseError::OutcomeUnread { .. }
        ),
        "{step}: the refusal names the step whose result never arrived: {refusal}"
    );
    assert_eq!(refusal.code(), ErrorCode::StorageUnavailable);
    // The two refusals this child really produces are exactly the update activation's
    // own state seams: a rollback that never reported, and a commit outcome that could
    // not be read. This is the mapping `activate` performs over the same two variants, so
    // each token is derived from a real refusal rather than declared.
    let seam = match &refusal {
        config::BaseError::RollbackFailed { .. } => UpdateBoundary::TransactionRollback,
        config::BaseError::OutcomeUnread { .. } => UpdateBoundary::OutcomeRead,
        other => panic!("{step}: the fault produced another class: {other}"),
    };
    let expected_token = if step == "rollback" {
        "upd.tx.rollback"
    } else {
        "upd.outcome.read"
    };
    assert_eq!(
        seam.token(),
        expected_token,
        "{step}: the activation reports this refusal at its own seam"
    );
    assert!(
        matches!(store.schema_generation(), Err(StoreError::Closed)),
        "{step}: the store refuses every call until a compatible reopen"
    );
    assert!(
        store.generation_tuple().is_err(),
        "{step}: no tuple is claimed while the outcome is unknown"
    );
    std::fs::write(&marker, step).expect("the marker lands");
}

/// AC-055: the emit map is a bijection over the whole closed set this module
/// owns, and an alias mutant — two different actionable seams mapped onto one
/// retained fingerprint — is rejected. Different message text cannot rescue it.
#[test]
fn update_emit_map_rejects_alias_collision() {
    let map: Vec<(UpdateBoundary, &str)> = UpdateBoundary::ALL
        .iter()
        .map(|seam| (*seam, seam.token()))
        .collect();
    validate_emit_map(&map).expect("the closed map is a bijection");
    assert_eq!(
        map.len(),
        UpdateBoundary::ALL.len(),
        "the map is the whole set"
    );
    let corrections: std::collections::BTreeSet<&str> = UpdateBoundary::ALL
        .iter()
        .map(|seam| seam.correction())
        .collect();
    assert_eq!(
        corrections.len(),
        UpdateBoundary::ALL.len(),
        "every seam carries its own correction"
    );

    // The mutant: the snapshot-creation seam answers the cleanup seam's token.
    let mut aliased = map.clone();
    for (seam, token) in &mut aliased {
        if *seam == UpdateBoundary::CheckpointCreate {
            *token = UpdateBoundary::CheckpointCleanup.token();
        }
    }
    assert_eq!(
        validate_emit_map(&aliased),
        Err(EmitMapCollision::Token {
            first: UpdateBoundary::CheckpointCreate,
            second: UpdateBoundary::CheckpointCleanup,
        }),
        "an aliased pair is refused even though both seams still print their own text"
    );
    assert_ne!(
        UpdateBoundary::CheckpointCreate.correction(),
        UpdateBoundary::CheckpointCleanup.correction(),
        "the alias carries different prose and is still refused"
    );

    // The rollback and readback seams this slice opens are their own rows, and both are
    // produced from a real refusal: the quarantine child derives `upd.tx.rollback` and
    // `upd.outcome.read` from the refusals it provokes. `upd.evidence.terminal` is the one
    // seam this suite does not produce from a refused call — the terminal write of an
    // activation lands inside `settle`, and every state that would refuse it refuses an
    // earlier commit in the same attempt — so it is asserted at its own type: the variant,
    // its boundary, and the inner refusal's forwarded correction in
    // `checkpoint_and_record_corrections_name_their_own_cause`.
    assert_eq!(
        UpdateBoundary::TransactionRollback.token(),
        "upd.tx.rollback"
    );
    assert_eq!(UpdateBoundary::OutcomeRead.token(), "upd.outcome.read");
    assert_eq!(
        UpdateBoundary::EvidenceTerminal.token(),
        "upd.evidence.terminal"
    );
    // The page-scoped conflict is a row of the same closed map, so the namespace
    // `upd.*` holds every boundary a caller can read: its token, its own correction,
    // and its membership of the whole set.
    assert_eq!(UpdateBoundary::BasePage.token(), "upd.base.page");
    assert!(
        UpdateBoundary::BasePage.token().starts_with("upd."),
        "the page conflict stays inside the closed namespace"
    );
    assert!(
        UpdateBoundary::ALL.contains(&UpdateBoundary::BasePage),
        "the page conflict is enumerated with the rest of the emit map"
    );
    assert!(
        UpdateBoundary::BasePage.correction().contains("first page"),
        "the correction names the recovery a page refusal has: {}",
        UpdateBoundary::BasePage.correction()
    );
}

/// AC-055: the terminal record of one attempt is the seam a failed durable write
/// reports, and the retained cause an earlier record holds survives it — cleanup
/// cannot delete or overwrite the original boundary, code or detail.
#[test]
fn update_failure_evidence_survives_cleanup() {
    let root = temp_root("failure-survives-cleanup");
    let evidence = EvidenceStore::open(root.path()).expect("the record directory opens");
    let mut failed = UpdateEvidence::fresh(Some(2));
    failed.note_failure(Failure::at(
        UpdateBoundary::Semantic,
        ErrorCode::Conflict,
        Some("delta-mapping"),
    ));
    failed.terminal = Terminal::Rejected;
    failed.phase = Some(UpdatePhase::RolledBack);
    failed.cleanup = CleanupState::Done;
    let name = evidence.write(&failed).expect("the cause is durable");
    let before = std::fs::read_to_string(root.path().join("reports").join("update").join(&name))
        .expect("the record reads");

    // A later success converges the set; the cause stays byte-equivalent.
    let mut later = UpdateEvidence::fresh(Some(2));
    later.terminal = Terminal::Success;
    later.cleanup = CleanupState::Done;
    later.phase = Some(UpdatePhase::Activated);
    evidence.write(&later).expect("the success lands");
    evidence.settle_success().expect("the pass resolves");
    let after = std::fs::read_to_string(root.path().join("reports").join("update").join(&name))
        .expect("the record still reads");
    // `resolved` is the one field the success producer writes; the cause itself —
    // boundary, code and detail — is byte-equivalent across the convergence.
    let read = |text: &str| {
        let record: UpdateEvidence = serde_json::from_str(text).expect("the record decodes");
        (
            record.first_failure,
            serde_json::to_string(&record.secondary).expect("secondary encodes"),
            record.terminal,
            record.phase,
        )
    };
    assert_eq!(
        read(&before),
        read(&after),
        "cleanup neither deletes nor rewrites the retained cause"
    );
    let projection = evidence.projection().expect("the records project");
    let failure = projection.failure.expect("the cause survives");
    assert_eq!(failure.boundary_id.as_deref(), Some("upd.semantic"));
    assert_eq!(failure.code, ErrorCode::Conflict);
    assert_eq!(
        projection.evidence.as_deref(),
        Some(name.as_str()),
        "the projection names the record that holds the cause"
    );

    // The terminal seam itself: a sealed directory refuses the terminal write, and
    // the cause already on disk is untouched.
    std::fs::set_permissions(
        root.path().join("reports").join("update"),
        std::os::unix::fs::PermissionsExt::from_mode(0o500),
    )
    .expect("the directory is sealed");
    let mut terminal = failed.clone();
    terminal.attempt_id = uuid::Uuid::new_v4().to_string();
    let refusal = evidence
        .write(&terminal)
        .expect_err("a sealed directory refuses the terminal write");
    assert_eq!(refusal.boundary(), UpdateBoundary::EvidenceWrite);
    std::fs::set_permissions(
        root.path().join("reports").join("update"),
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .expect("the harness unseals its own directory");
    let surviving = std::fs::read_to_string(root.path().join("reports").join("update").join(&name))
        .expect("the cause still reads");
    assert_eq!(
        read(&surviving).0,
        read(&before).0,
        "a refused terminal write leaves the previous cause standing"
    );
}

// ----- REQ-004/AC-085: the deterministic migration and its scoped blockers -----

/// AC-085/PROH-003: neither the actual activation nor the actual rollback this
/// build performs reaches a provider. Both outcomes are driven through the
/// production open — a waiting cutover it activates, and a stale checkpoint it
/// rolls back — and the counter is the `support::World` provider's own, so the
/// zero is measured at the seam the send would happen on. The positive control at
/// the end proves the same counter observes a real send.
#[test]
fn deterministic_update_and_rollback_make_zero_provider_calls() {
    use std::sync::atomic::Ordering;

    let off = user_config(
        "[workflow]\n\
         enabled = false\n\
         [models.purposes.main]\n\
         model = { mode = \"fixed\", connection = \"local\", model_id = \"pinned-model\" }\n",
    );

    // 1. The actual activation: a cutover waits and the production open runs it.
    let root = temp_root("zero-provider");
    std::fs::create_dir_all(root.path().join("runtime")).expect("runtime dir");
    std::fs::write(root.path().join("config.toml"), &off).expect("the user document lands");
    let primary = root.path().join("runtime").join("rivect.db");
    let (task, kept) = {
        let mut store = TaskStore::open(&primary).expect("the store opens");
        store
            .stage_base(&install(root.path(), BaseSource::SHIPPED))
            .expect("the offered base stages");
        let session = store
            .open_session("zero-provider-bootstrap", "fixture", None)
            .expect("a session opens")
            .0;
        let task = store
            .create_task(
                &session,
                "cmd-zero-provider",
                "human",
                "survive a model-free migration",
                (&["one criterion".to_string()], &[]),
            )
            .expect("the task opens")
            .task_id;
        store
            .materialize_obligations(&task)
            .expect("the criteria materialize");
        store
            .insert_evidence_for_task(&task, WORLD, "model-free bytes", "ab12")
            .expect("the record is confirmed");
        let kept = store
            .evidence_for_task(&task)
            .expect("the record reads")
            .into_iter()
            .next()
            .expect("one record");
        (task, kept)
    };

    let world = support::open_world_at(root.path(), Some(&off));
    assert_eq!(
        world
            .runtime
            .store()
            .active_base()
            .expect("base read")
            .map(|base| base.version),
        Some(SHIPPED_BASE_VERSION),
        "the production open activated the waiting base"
    );
    assert_eq!(
        world.provider_calls.load(Ordering::SeqCst),
        0,
        "the activation reached the provider"
    );
    // The record the cutover had to carry, by id, scope and content.
    let carried = world
        .runtime
        .store()
        .evidence_for_task(&task)
        .expect("the record reads")
        .into_iter()
        .next()
        .expect("one record");
    assert_eq!(carried.evidence_id.0, kept.evidence_id.0);
    assert_eq!(carried.scope, WORLD);
    assert_eq!(carried.observation, "model-free bytes");

    // Both outcomes preserved the explicit settings and the off.
    let after = world.runtime.effective();
    assert_eq!(
        after.workflow_entry.effective,
        config::ConfigViewValue::Visible {
            value: Value::Bool(false)
        },
        "workflow: false survived the model-free migration"
    );
    assert_eq!(after.workflow_entry.source.kind, "user");
    let purpose = after
        .composed()
        .resolve_purpose(SUBJECT_PURPOSE)
        .expect("the purpose resolves");
    assert!(
        matches!(&purpose.model, ModelAssign::Fixed(fixed) if fixed.model_id == "pinned-model"),
        "the explicit pin survived: {purpose:?}"
    );
    drop(world);

    // 2. The actual rollback: a root that already serves base 1 takes a waiting
    // cutover, and that cutover's validation then fails, so the production open
    // reports `RolledBack` — the serving base stays, the checkpoint leaves and no
    // activation is claimed.
    let stale_root = temp_root("zero-provider-rollback");
    std::fs::create_dir_all(stale_root.path().join("runtime")).expect("runtime dir");
    std::fs::write(stale_root.path().join("config.toml"), &off).expect("the user document lands");
    let stale_primary = stale_root.path().join("runtime").join("rivect.db");
    let rollback_task;
    let kept_rollback;
    {
        let mut store = TaskStore::open(&stale_primary).expect("the store opens");
        store
            .serve_base(&install(stale_root.path(), BaseSource::new(1, &base_v1())))
            .expect("base 1 serves");
        store
            .stage_base(&install(stale_root.path(), BaseSource::SHIPPED))
            .expect("the successor stages");
        // The record this case has to carry: written BEFORE the snapshot the open
        // takes, so a rollback that discarded it would be observable.
        let session = store
            .open_session("zero-provider-rollback-bootstrap", "fixture", None)
            .expect("a session opens")
            .0;
        let task = store
            .create_task(
                &session,
                "cmd-zero-provider-rollback",
                "human",
                "keep the record through the rollback",
                (&["one criterion".to_string()], &[]),
            )
            .expect("the task opens")
            .task_id;
        store
            .materialize_obligations(&task)
            .expect("the criteria materialize");
        store
            .insert_evidence_for_task(&task, WORLD, "rollback bytes", "cd34")
            .expect("the record is confirmed");
        kept_rollback = store
            .evidence_for_task(&task)
            .expect("the record reads")
            .into_iter()
            .next()
            .expect("one record");
        rollback_task = task;
    }
    // The validation then fails at the smoke readback: the staged base's receipt
    // is gone, so the store cannot answer the generation it holds. The staged row
    // itself stays, which is what the activation abandons.
    rusqlite::Connection::open(&stale_primary)
        .expect("a second connection")
        .execute(
            "DELETE FROM update_receipts WHERE base_version = ?1",
            [SHIPPED_BASE_VERSION as i64],
        )
        .expect("the staged receipt leaves");

    // The counted provider is live for this whole window: it is wrapped into the
    // broker before `publish_startup` runs, and a zero afterwards is an absence of
    // a send, not an absence of a counter.
    let mut world = support::open_world_at(stale_root.path(), Some(&off));
    assert_eq!(
        world
            .runtime
            .store()
            .active_base()
            .expect("base read")
            .map(|base| base.version),
        Some(1),
        "the rollback left the previous base serving"
    );
    assert_eq!(
        world.runtime.store().staged_base().expect("staged read"),
        None,
        "the rollback discarded no-surviving checkpoint"
    );
    assert_eq!(
        world.provider_calls.load(Ordering::SeqCst),
        0,
        "the rollback reached the provider"
    );
    // The outcome really was a rollback: the attempt record carries the phase the
    // activation reaches only after the abandonment answered.
    let records = EvidenceStore::open(stale_root.path()).expect("the record directory opens");
    let names = records.names().expect("the records list");
    let rolled = names
        .iter()
        .filter_map(|name| records.read(name).ok())
        .find(|record| record.phase == Some(UpdatePhase::RolledBack))
        .unwrap_or_else(|| panic!("no rolled-back record among {names:?}"));
    assert_eq!(
        rolled.terminal,
        Terminal::Rejected,
        "the rollback is a refusal"
    );
    assert_eq!(
        rolled.first_failure.expect("the seam is retained").boundary,
        UpdateBoundary::Smoke,
        "the check that failed is the one the record names"
    );

    // The other conjuncts AC-085 requires of *each* case, judged in this rollback
    // world: the explicit settings, the off, and the record by id/scope/content.
    let rolled_back = world.runtime.effective();
    assert_eq!(
        rolled_back.workflow_entry.effective,
        config::ConfigViewValue::Visible {
            value: Value::Bool(false)
        },
        "workflow: false survived the rollback"
    );
    assert_eq!(
        rolled_back.workflow_entry.source.kind, "user",
        "the off keeps its own layer through the rollback"
    );
    let rolled_purpose = rolled_back
        .composed()
        .resolve_purpose(SUBJECT_PURPOSE)
        .expect("the purpose resolves");
    assert!(
        matches!(&rolled_purpose.model, ModelAssign::Fixed(fixed) if fixed.model_id == "pinned-model"),
        "the explicit pin survived the rollback: {rolled_purpose:?}"
    );

    // The positive control: this world's own counter observes a real send on the
    // very broker seam the update would have gone through, so the zero above is
    // the absence of a call and not the absence of a counter.
    let config = world.runtime.config_for_broker();
    let manifest = world
        .runtime
        .broker
        .prepare(SUBJECT_PURPOSE, &config, WORLD, "goal: explain")
        .expect("the fixture request prepares");
    world
        .runtime
        .broker
        .dispatch(WORLD, &manifest)
        .expect("the loopback answers");
    assert_eq!(
        world.provider_calls.load(Ordering::SeqCst),
        1,
        "the fixture counter observes a real send"
    );
    drop(world);

    // The record by id, scope and content, re-read from this rollback root: it was
    // written before the snapshot and survives the rollback.
    let replayed = TaskStore::open(&stale_primary)
        .expect("the rollback root reopens")
        .evidence_for_task(&rollback_task)
        .expect("the record reads back by id");
    // The conjunct is about the record that existed BEFORE the rollback: the id, scope
    // and content asserted here are the ones read before the open ran, so a rollback that
    // dropped or rewrote it cannot pass by comparing a record to itself.
    assert_eq!(
        replayed
            .iter()
            .map(|record| (
                record.evidence_id.0.clone(),
                record.scope.clone(),
                record.observation.clone(),
                record.digest.clone()
            ))
            .collect::<Vec<_>>(),
        vec![(
            kept_rollback.evidence_id.0.clone(),
            WORLD.to_string(),
            "rollback bytes".to_string(),
            "cd34".to_string()
        )],
        "the record written before the rollback survives it by id, scope and content"
    );

    // The activated root still carries the record the cutover had to keep.
    let reopened =
        TaskStore::open(&root.path().join("runtime").join("rivect.db")).expect("the store reopens");
    let reread = reopened
        .evidence_for_task(&task)
        .expect("the record reads after the rollback");
    assert_eq!(reread.len(), 1);
    assert_eq!(reread[0].evidence_id.0, kept.evidence_id.0);
    assert_eq!(reread[0].scope, kept.scope);
    assert_eq!(reread[0].observation, kept.observation);
}

/// One user document that pins a keyed purpose: the explicit value a generation
/// either maps or leaves scoped (REQ-004).
fn user_with_pin(key: &str, model_id: &str) -> String {
    user_config(&format!(
        "[models.purposes.\"{key}\"]\n\
         model = {{ mode = \"fixed\", connection = \"local\", model_id = \"{model_id}\" }}\n"
    ))
}

/// The one install path a release takes: the base's own rows are read from the
/// document and the user's layer is the object the cutover pins, so the scoped set
/// is judged between the two real layers.
fn release_install(root: &Path, version: u64, user: &str, extra: &str) -> config::BaseInstall {
    let text = format!("{}\n{}", base_document(""), extra);
    let source = BaseSource::new(version, &text);
    let effective = config::resolve_effective_on(source, Some(user)).expect("the view resolves");
    install(root, source).pinning(&effective)
}

/// AC-085/REQ-004: a semantic conflict is scoped to the one record field that
/// cannot be placed — a native learning id on the field a role rule would have
/// moved, and the keyed config record the user wrote — and never spreads to the
/// records the generation still declares. The address is a canonical
/// JSON-Pointer pair that decodes exactly one layer and re-encodes bytewise.
#[test]
fn semantic_conflict_blocks_only_its_record_field() {
    let root = temp_root("semantic-scope");
    let user = user_with_pin("personal:api-review", "review-model");
    std::fs::write(root.path().join("config.toml"), &user).expect("the user document lands");
    let mut store = open_store(root.path());
    store
        .serve_base(&install(root.path(), BaseSource::new(1, &base_v1())))
        .expect("the first base is recorded");

    // A healthy record the generation declares: it must stay usable.
    verified_delta(&mut store);
    // The user-owned record the generation has no mapping for: a non-UUID id on
    // the field a role rule would have moved.
    store
        .record_learning_delta(&candidate(
            "retired",
            instruction(DELTA_TEXT, Some("retired_role")),
        ))
        .expect("the unplaceable record is recorded");
    let retired = store.learning_delta("retired").expect("stored");

    // The generation declares the purposes the healthy records are bound to, and
    // no row for the user's keyed record.
    let released = release_install(
        root.path(),
        2,
        &user,
        "[models.purposes.main]\n\
         model = { mode = \"inherit\" }\n\
         effort = { mode = \"inherit\" }\n\
         [models.purposes.review]\n\
         model = { mode = \"inherit\" }\n\
         effort = { mode = \"inherit\" }\n",
    );
    let mut document = config::Config::parse_validated(&user).expect("the document validates");
    let cutover = store
        .cut_over_base(&released, &[], &mut document)
        .expect("the generation installs with its scoped conflicts");

    let blockers = cutover
        .served
        .receipt
        .blockers
        .expect("an installed base carries its set");
    assert_eq!(blockers.snapshot_generation, 2);
    assert_eq!(
        blockers.items,
        vec![
            "config/~1models~1purposes~1personal:api-review/~1model".to_string(),
            "learning/retired/condition_json".to_string(),
        ],
        "one blocker per unplaceable record field, in BINARY order"
    );
    assert!(
        blockers.next_cursor.is_none(),
        "a two-row set is one terminal page"
    );

    // The address decodes one outer layer and re-encodes bytewise.
    for address in &blockers.items {
        let (owner, record, field) =
            config::blocker_address_parts(address).expect("the address is canonical");
        assert_eq!(
            config::blocker_address(&owner, &record, &field),
            *address,
            "the re-encode is not the stored spelling"
        );
    }
    let (owner, record, field) =
        config::blocker_address_parts(&blockers.items[0]).expect("the config address");
    assert_eq!(owner, "config");
    assert_eq!(record, "/models/purposes/personal:api-review");
    assert_eq!(field, "/model");
    let (owner, record, _) =
        config::blocker_address_parts(&blockers.items[1]).expect("the learning address");
    assert_eq!(owner, "learning");
    assert_eq!(record, "retired", "the supplied native id was reminted");
    for malformed in [
        "learning/a~2b/condition_json",
        "learning/a~b/condition_json",
        "learning/a/condition_json~",
        "task/a/condition_json",
        "learning/a",
        "learning/a/condition_json/extra",
    ] {
        assert!(
            config::blocker_address_parts(malformed).is_none(),
            "{malformed} is not a canonical address"
        );
    }
    // A key carrying the escaping characters round-trips losslessly.
    let escaped = config::blocker_address("config", "/models/purposes/a~1b~0c", "/model");
    let (_, record, field) =
        config::blocker_address_parts(&escaped).expect("the escaped key decodes");
    assert_eq!(record, "/models/purposes/a~1b~0c");
    assert_eq!(field, "/model");

    // Nothing spread: the declared record still composes, and the keyed record
    // the user wrote keeps its explicit pin.
    let definition = store.learning_definition().expect("the definition reads");
    assert!(
        definition
            .deltas()
            .iter()
            .any(|delta| delta.delta_id == DELTA),
        "the declared record stopped composing: {definition:?}"
    );
    assert_eq!(
        store.learning_delta("retired").expect("stored"),
        retired,
        "the blocked record was rewritten or reminted"
    );
    assert_eq!(cutover.served.receipt.identity.base_version, 2);
    let pin = document
        .resolve_purpose("personal:api-review")
        .expect("the user's keyed record still resolves");
    assert!(
        matches!(&pin.model, ModelAssign::Fixed(fixed) if fixed.model_id == "review-model"),
        "the explicit control was dropped: {pin:?}"
    );

    // The conflict is enforced at its exact address, not by a non-empty set.
    assert!(
        store
            .base_blocker(2, "learning/retired/condition_json")
            .expect("the lookup answers")
    );
    assert!(
        !store
            .base_blocker(2, &format!("learning/{DELTA}/condition_json"))
            .expect("the lookup answers"),
        "a declared record was reported as a conflict"
    );
}

/// AC-085/REQ-004: the set is not capped at one page. Independently at 200 and
/// 201 conflicts every page of the real `runtime.status` projection is walked:
/// exact set equality, order, no duplicates, a terminal cursor absent, the record
/// the generation still declares stays usable, and a conflict past the first page
/// is still enforced at its exact address. The provider counter stays zero.
#[test]
fn semantic_conflicts_traverse_every_status_page() {
    use std::sync::atomic::Ordering;

    for count in [200usize, 201] {
        let root = temp_root(&format!("semantic-pages-{count}"));
        let keys: Vec<String> = (0..count)
            .map(|index| format!("legacy-{index:03}"))
            .collect();
        let mut rows = String::new();
        for key in &keys {
            rows.push_str(&format!(
                "[models.purposes.\"{key}\"]\n\
                 model = {{ mode = \"fixed\", connection = \"local\", model_id = \"{key}\" }}\n"
            ));
        }
        let user = user_config(&format!("[workflow]\nenabled = false\n{rows}"));
        std::fs::write(root.path().join("config.toml"), &user).expect("the user document lands");
        let expected: Vec<String> = keys
            .iter()
            .map(|key| format!("config/~1models~1purposes~1{key}/~1model"))
            .collect();

        {
            let mut store = open_store(root.path());
            let released = release_install(root.path(), 2, &user, "");
            let mut document = config::Config::parse_validated(&user).expect("validates");
            let cutover = store
                .cut_over_base(&released, &[], &mut document)
                .expect("the generation installs");
            // The receipt serves the first page of that base's set.
            let first = cutover
                .served
                .receipt
                .blockers
                .expect("the base carries its set");
            assert_eq!(
                first.items.len(),
                count.min(rivect::contracts::PAGE_DEFAULT as usize),
                "{count}: the receipt's first page"
            );
            assert_eq!(first.snapshot_generation, 2);
        }

        // The real runtime reads that ledger back and serves it.
        let mut world = support::open_world_at(root.path(), Some(&user));
        let session = world.open_session("semantic-pages-bootstrap");
        let mut seen: Vec<String> = Vec::new();
        let mut cursor: Option<String> = None;
        let mut pages = 0usize;
        loop {
            let request = match &cursor {
                None => json!({ "page_size": 200, "base": 2 }),
                Some(cursor) => json!({ "page_size": 200, "base": 2, "cursor": cursor }),
            };
            let response: Value = world.dispatch(&status_with_blockers(&session, request));
            assert!(response["error"].is_null(), "{count}: {response}");
            let page = &response["result"]["update"]["blockers"];
            assert_eq!(page["snapshot_generation"], 2, "{count}: {response}");
            let items: Vec<String> = page["items"]
                .as_array()
                .expect("items")
                .iter()
                .map(|item| item.as_str().expect("an address").to_string())
                .collect();
            seen.extend(items);
            pages += 1;
            cursor = page["next_cursor"].as_str().map(str::to_string);
            if cursor.is_none() {
                break;
            }
        }
        assert_eq!(
            seen, expected,
            "{count}: complete traversal, order, no repeats"
        );
        assert_eq!(
            pages,
            count.div_ceil(200),
            "{count}: one page per 200 conflicts, and no total-count refusal"
        );

        // A conflict past the first page is still enforced at its exact address.
        let beyond = &expected[count - 1];
        assert!(
            world
                .runtime
                .store()
                .base_blocker(2, beyond)
                .expect("the lookup answers"),
            "{count}: {beyond} is not enforced"
        );
        assert_eq!(
            world.runtime.effective().workflow_entry.effective,
            config::ConfigViewValue::Visible {
                value: Value::Bool(false)
            },
            "{count}: the explicit off was rewritten"
        );
        assert_eq!(
            world.provider_calls.load(Ordering::SeqCst),
            0,
            "{count}: the migration reached a provider"
        );
    }
}

/// AC-085: a staged successor does not disturb the set the serving base already
/// sealed. Every page of N stays enumerable while N+1 waits, no page is drawn from
/// N+1, and a set re-created under the same version refuses the cursor minted for
/// the discarded one instead of serving new members under it.
#[test]
fn staged_successor_keeps_serving_base_pageable() {
    let root = temp_root("staged-successor");
    let count = 201usize;
    let mut rows = String::new();
    for index in 0..count {
        rows.push_str(&format!(
            "[models.purposes.\"legacy-{index:03}\"]\n\
             model = {{ mode = \"fixed\", connection = \"local\", model_id = \"m{index:03}\" }}\n"
        ));
    }
    let user = user_config(&rows);
    std::fs::write(root.path().join("config.toml"), &user).expect("the user document lands");
    let expected: Vec<String> = (0..count)
        .map(|index| format!("config/~1models~1purposes~1legacy-{index:03}/~1model"))
        .collect();

    let mut store = open_store(root.path());
    let released = release_install(root.path(), 2, &user, "");
    let mut document = config::Config::parse_validated(&user).expect("validates");
    let cutover = store
        .cut_over_base(&released, &[], &mut document)
        .expect("the serving base installs");
    // The receipt serves the first page of that base's set.
    let first = cutover.served.receipt.blockers.expect("the set is sealed");
    assert_eq!(
        first.items.len(),
        usize::try_from(rivect::contracts::PAGE_DEFAULT).expect("a page default"),
        "the receipt serves one page, not the whole set"
    );
    assert_eq!(first.snapshot_generation, 2);

    // The successor waits; the serving base keeps serving its whole set.
    let successor_install = release_install(root.path(), 3, &user, "");
    store
        .stage_base(&successor_install)
        .expect("the successor stages");

    let mut seen: Vec<String> = Vec::new();
    let mut cursor: Option<String> = None;
    let mut first_cursor: Option<String> = None;
    loop {
        let page = store
            .update_status_page(&config::UpdatePage {
                page_size: 200,
                base: Some(2),
                cursor: cursor.clone(),
            })
            .expect("the serving base pages while a successor waits");
        if first_cursor.is_none() {
            first_cursor = page
                .blockers
                .as_ref()
                .and_then(|page| page.next_cursor.clone());
        }
        let page = page.blockers.expect("the base holds its set");
        assert_eq!(
            page.snapshot_generation, 2,
            "a page was drawn from the staged successor"
        );
        seen.extend(page.items);
        cursor = page.next_cursor;
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(seen, expected, "the serving base's whole set");
    let old_cursor = first_cursor.expect("two pages, so a cursor exists");

    // A cursor of another base than the request names is the caller's refusal.
    let refused = store
        .update_status_page(&config::UpdatePage {
            page_size: 200,
            base: Some(3),
            cursor: Some("blk:2:1:offset:0".to_string()),
        })
        .expect_err("a cursor of another base is not an offset into this set");
    assert!(
        matches!(refused, config::BaseError::InvalidPage { .. }),
        "{refused}"
    );

    // The status names one base's page — never two.
    let successor = store
        .update_status_page(&config::UpdatePage {
            page_size: 20,
            base: Some(3),
            cursor: None,
        })
        .expect("the staged base answers");
    let successor_page = successor.blockers.expect("the staged base holds its set");
    assert_eq!(successor_page.snapshot_generation, 3);
    let successor_cursor = successor_page
        .next_cursor
        .expect("the staged set needs more than one page");

    // Abandoning and re-staging the same version re-creates *that* set under a
    // fresh epoch: the cursor minted for the discarded set is refused, never
    // served the replacement's members under the old offset.
    store.abandon_base(3).expect("the checkpoint is discarded");
    store
        .stage_base(&successor_install)
        .expect("the same version stages again");
    let stale = store
        .update_status_page(&config::UpdatePage {
            page_size: 200,
            base: Some(3),
            cursor: Some(successor_cursor),
        })
        .expect("a moved set is a page-scoped refusal, not an RPC error");
    assert!(
        stale.page_conflict.is_some(),
        "the stale cursor served the re-created set"
    );
    assert!(
        stale.blockers.is_none(),
        "the page-scoped conflict serves no page"
    );

    // The serving base's sealed set was never touched by the successor's
    // re-creation: its cursor is the same one it issued before.
    let unchanged = store
        .update_status_page(&config::UpdatePage {
            page_size: 200,
            base: Some(2),
            cursor: None,
        })
        .expect("the sealed set is unchanged");
    assert_eq!(
        unchanged
            .blockers
            .as_ref()
            .and_then(|page| page.next_cursor.clone()),
        Some(old_cursor),
        "the serving base's cursor moved with the successor's re-creation"
    );
}

// ----- p29a: a re-seal rotates the set epoch it replaces -----

/// AC-085/REQ-004: a re-seal that replaces a non-empty set rotates the epoch in the
/// same transaction as the rows, so a cursor minted for the discarded set answers
/// `BlockerSetMoved` naming both epochs instead of resuming into the replacement's
/// members under the old offset. An identical re-seal writes the same set and must
/// not rotate, or a replayed release would invalidate cursors it never moved.
#[test]
fn re_seal_rotates_the_epoch_only_when_the_set_changes() {
    use rivect::identity::{IdentityKind, IdentityMigration, MigrationRule};

    let root = temp_root("re-seal-epoch");
    std::fs::create_dir_all(root.path().join("runtime")).expect("runtime dir");
    let path = root.path().join("state.db");
    // Three keyed records the generation declares no purpose for: a three-row set, so
    // the set pages even after a rule removes one member.
    let user = user_config(
        "[models.purposes.\"legacy-000\"]\n\
         model = { mode = \"fixed\", connection = \"local\", model_id = \"m000\" }\n\
         [models.purposes.\"legacy-001\"]\n\
         model = { mode = \"fixed\", connection = \"local\", model_id = \"m001\" }\n\
         [models.purposes.\"legacy-002\"]\n\
         model = { mode = \"fixed\", connection = \"local\", model_id = \"m002\" }\n",
    );
    std::fs::write(root.path().join("config.toml"), &user).expect("the user document lands");
    let mut store = TaskStore::open(&path).expect("the store opens");

    // The serving base's set holds the user's keyed record as a conflict.
    let first = release_install(root.path(), 2, &user, "");
    let mut document = config::Config::parse_validated(&user).expect("validates");
    store
        .cut_over_base(&first, &[], &mut document)
        .expect("the serving base installs");
    let epoch = read_set_epoch(&path, 2);
    let first_page = store
        .update_status_page(&config::UpdatePage {
            page_size: 1,
            base: Some(2),
            cursor: None,
        })
        .expect("the set pages");
    let old_cursor = first_page
        .blockers
        .expect("the base carries a set")
        .next_cursor
        .expect("a set of one needs a second page to be observable");

    // A rule that places the user's record removes it from the set: the same row now
    // holds different members, so the epoch rotates and the old cursor is a
    // page-scoped conflict naming both epochs.
    let rule = IdentityMigration {
        base_version: 2,
        kind: IdentityKind::Role,
        old_id: "legacy-000".to_string(),
        new_id: "main".to_string(),
        rule: MigrationRule::Merge,
        subject: None,
    };
    let mut moved = config::Config::parse_validated(&user).expect("validates");
    store
        .cut_over_base(&first, std::slice::from_ref(&rule), &mut moved)
        .expect("the re-seal replaces the set");
    let rotated = read_set_epoch(&path, 2);
    assert_ne!(
        rotated, epoch,
        "a replacement set under the same row carries a fresh epoch"
    );
    let stale = store
        .update_status_page(&config::UpdatePage {
            page_size: 1,
            base: Some(2),
            cursor: Some(old_cursor),
        })
        .expect("a moved set is a page-scoped refusal");
    let conflict = stale
        .page_conflict
        .expect("the stale cursor is refused inside the status");
    assert_eq!(conflict.code, ErrorCode::Conflict);
    let message = conflict.message;
    assert!(
        message.contains(&format!("requested epoch {epoch}"))
            && message.contains(&format!("stored epoch {rotated}")),
        "the refusal names both epochs: {message}"
    );
    assert!(stale.blockers.is_none(), "the refusal serves no page");

    // An identical re-seal — the same release and the same already-recorded rule
    // replayed — writes the same set, so it must not rotate. The rule is not empty,
    // so `record_release_rules` runs its whole transaction and `seal_blockers_on`
    // evaluates the no-rotation branch; an empty rule set would return before either
    // ran and prove nothing. A cursor minted after the rotation stays valid.
    let fresh_cursor = store
        .update_status_page(&config::UpdatePage {
            page_size: 1,
            base: Some(2),
            cursor: None,
        })
        .expect("the replacement set pages")
        .blockers
        .expect("the base carries a set")
        .next_cursor
        .expect("a two-row set needs a second page");
    let mut replay = config::Config::parse_validated(&user).expect("validates");
    store
        .cut_over_base(&first, std::slice::from_ref(&rule), &mut replay)
        .expect("the replay answers the receipt it holds");
    assert_eq!(
        read_set_epoch(&path, 2),
        rotated,
        "a replay of the same set is not a move"
    );
    let unchanged = store
        .update_status_page(&config::UpdatePage {
            page_size: 1,
            base: Some(2),
            cursor: Some(fresh_cursor),
        })
        .expect("the cursor still addresses the same set");
    assert!(
        unchanged.page_conflict.is_none(),
        "the replay refused a cursor it never moved: {unchanged:?}"
    );
}

// ----- p29: the metadata of a row an earlier build staged -----

/// AC-055: a staged row an earlier build wrote carries no epoch. `INSERT OR IGNORE`
/// keeps that row, so the epoch the staging transaction allocated is not the one the
/// row holds — and an activated row whose set has no epoch is metadata every reader
/// refuses. The hand-written pre-column row must therefore activate and answer.
#[test]
fn pre_column_staged_row_activates_into_readable_metadata() {
    let root = temp_root("legacy-staged");
    std::fs::create_dir_all(root.path().join("runtime")).expect("runtime dir");
    let path = root.path().join("state.db");
    let document_text = base_v2();
    let document = BaseSource::new(SHIPPED_BASE_VERSION, &document_text);
    {
        let mut store = TaskStore::open(&path).expect("the store opens");
        store
            .serve_base(&install(root.path(), BaseSource::new(1, &base_v1())))
            .expect("the first base is recorded");
        store
            .stage_base(&install(root.path(), document))
            .expect("the next base stages");
    }
    // The row an earlier build left: the columns exist, added by this build, but the
    // staged row predates them and holds NULL in all five.
    rusqlite::Connection::open(&path)
        .expect("a second connection")
        .execute_batch(
            "UPDATE base_state SET phase = NULL, blocker_count = NULL,
                 schema_generation = NULL, policy_generation = NULL, set_epoch = NULL
                 WHERE state = 'staged';",
        )
        .expect("the staged row is put back to the pre-column shape");

    let mut store = TaskStore::open(&path).expect("the store reopens");
    assert_eq!(
        store
            .staged_base()
            .expect("staged read")
            .map(|base| base.version),
        Some(SHIPPED_BASE_VERSION),
        "the pre-column row is still the waiting checkpoint"
    );
    let served = store
        .serve_base(&install(root.path(), document))
        .expect("the waiting cutover activates");
    assert_eq!(served.receipt.state, UpdateState::Active);
    let receipt = store
        .update_status()
        .expect("the status answers")
        .receipt
        .expect("the receipt of the activated base");
    assert_eq!(
        receipt.phase,
        Some(UpdatePhase::Activated),
        "the activated row carries its milestone"
    );
    assert_eq!(
        receipt.blockers.map(|page| page.snapshot_generation),
        Some(SHIPPED_BASE_VERSION),
        "the activated row carries its set: the epoch was written onto the surviving row"
    );
}

/// AC-055/architecture § Exact additive API: a legacy serving row is the one shape
/// whose legal metadata is NULL in all five columns. This build must not stamp an
/// `activated` milestone, a schema generation or its own resolved policy digest onto
/// a base it never validated.
#[test]
fn legacy_serving_row_keeps_its_unvalidated_shape() {
    let root = temp_root("legacy-shape");
    std::fs::create_dir_all(root.path().join("runtime")).expect("runtime dir");
    // The database the production open serves, not a fixture-side one.
    let path = root.path().join("runtime").join("rivect.db");
    {
        let mut store = TaskStore::open(&path).expect("the store opens");
        store
            .serve_base(&install(
                root.path(),
                BaseSource::new(SHIPPED_BASE_VERSION, SHIPPED_DEFAULTS_TOML),
            ))
            .expect("the shipped base is recorded");
    }
    rusqlite::Connection::open(&path)
        .expect("a second connection")
        .execute_batch(
            "UPDATE base_state SET phase = NULL, blocker_count = NULL,
                 schema_generation = NULL, policy_generation = NULL, set_epoch = NULL;",
        )
        .expect("the serving row is put back to the legacy shape");

    // Reopening through the production startup runs the pass that used to fill
    // those columns in; a direct `TaskStore::open` does not reach it.
    let world = support::open_world_at(root.path(), None);
    assert_eq!(
        world
            .runtime
            .store()
            .active_base()
            .expect("base read")
            .map(|base| base.version),
        Some(SHIPPED_BASE_VERSION),
        "the startup kept serving the base it found"
    );
    drop(world);
    struct LegacyColumns {
        phase: Option<String>,
        blocker_count: Option<i64>,
        schema_generation: Option<i64>,
        policy_generation: Option<String>,
        set_epoch: Option<i64>,
    }
    let columns = rusqlite::Connection::open(&path)
        .expect("the primary opens")
        .query_row(
            "SELECT phase, blocker_count, schema_generation, policy_generation,
                 set_epoch FROM base_state WHERE base_version = ?1",
            [SHIPPED_BASE_VERSION as i64],
            |row| {
                Ok(LegacyColumns {
                    phase: row.get(0)?,
                    blocker_count: row.get(1)?,
                    schema_generation: row.get(2)?,
                    policy_generation: row.get(3)?,
                    set_epoch: row.get(4)?,
                })
            },
        )
        .expect("the legacy row is still in the ledger");
    assert_eq!(
        (
            columns.phase,
            columns.blocker_count,
            columns.schema_generation,
            columns.policy_generation,
            columns.set_epoch
        ),
        (None, None, None, None, None),
        "the legacy row keeps the NULL shape the legal-shape table records"
    );

    // A status read of that row reports no page and no conflict: there is no set
    // to restart from, so a page-scoped refusal would name a page that never
    // existed. A cursor into it is still the page-scoped refusal.
    let store = TaskStore::open(&path).expect("the primary reopens");
    let quiet = store.update_status().expect("the status answers");
    assert!(
        quiet.blockers.is_none(),
        "a legacy row holds no page to serve: {quiet:?}"
    );
    assert!(
        quiet.page_conflict.is_none(),
        "a legacy row reports no phantom page conflict: {quiet:?}"
    );
    let cursor = store
        .update_status_page(&config::UpdatePage {
            page_size: 20,
            base: Some(SHIPPED_BASE_VERSION),
            cursor: Some(format!("blk:{SHIPPED_BASE_VERSION}:1:offset:0")),
        })
        .expect("a cursor into a legacy row is page-scoped, not an RPC error");
    assert!(
        cursor.page_conflict.is_some(),
        "the cursor names rows the row does not hold: {cursor:?}"
    );
    assert!(cursor.blockers.is_none(), "the refusal serves no page");
}

/// AC-055: a serving row an earlier build wrote — NULL in all five metadata
/// columns — that a newer base retires keeps its receipt readable. Retirement
/// writes no metadata of its own, so the retired row keeps the all-NULL shape of a
/// base this build never validated, and every reader accepts it.
#[test]
fn retired_legacy_row_keeps_its_receipt_readable() {
    let root = temp_root("legacy-retired");
    std::fs::create_dir_all(root.path().join("runtime")).expect("runtime dir");
    let path = root.path().join("state.db");
    let mut store = TaskStore::open(&path).expect("the store opens");
    store
        .serve_base(&install(root.path(), BaseSource::new(1, &base_v1())))
        .expect("the first base serves");
    rusqlite::Connection::open(&path)
        .expect("a second connection")
        .execute_batch(
            "UPDATE base_state SET phase = NULL, blocker_count = NULL,
                 schema_generation = NULL, policy_generation = NULL, set_epoch = NULL
                 WHERE state = 'active';",
        )
        .expect("the serving row is put back to the pre-column shape");

    // A newer base retires it. Retirement writes no metadata, so the row keeps the
    // all-NULL shape of a base this build never validated.
    store
        .serve_base(&install(root.path(), BaseSource::new(2, &base_v2())))
        .expect("the newer base retires the legacy row");
    assert_eq!(
        store
            .active_base()
            .expect("base read")
            .map(|base| base.version),
        Some(2),
        "the newer base serves"
    );

    let receipt = store
        .update_receipt(1)
        .expect("the retired row still answers its receipt");
    assert_eq!(receipt.state, UpdateState::Retired);
    assert_eq!(
        receipt.phase, None,
        "retirement invents no validation milestone"
    );
    assert_eq!(
        (receipt.schema_generation, receipt.policy_generation),
        (None, None),
        "retirement invents no generation"
    );
    let page = store
        .update_receipt_page(1, &config::UpdatePage::default())
        .expect("the retired receipt pages");
    assert!(
        page.blockers.is_none(),
        "a row that records no set answers no page"
    );
}

/// AC-055/INV-007: a release replay re-seals the set of the base that already serves.
/// A serving row an earlier build wrote records no set and no activation metadata, so
/// the re-seal must leave it exactly as it found it: a count without the epoch beside it
/// is a shape every reader refuses, and the installation serving that base could no
/// longer start.
#[test]
fn re_seal_leaves_a_legacy_serving_row_readable() {
    use rivect::identity::{IdentityKind, IdentityMigration, MigrationRule};

    let root = temp_root("legacy-re-seal");
    std::fs::create_dir_all(root.path().join("runtime")).expect("runtime dir");
    let path = root.path().join("runtime").join("rivect.db");
    let user = user_config(
        "[models.purposes.\"legacy-000\"]\n\
         model = { mode = \"fixed\", connection = \"local\", model_id = \"m000\" }\n",
    );
    std::fs::write(root.path().join("config.toml"), &user).expect("the user document lands");
    let mut store = TaskStore::open(&path).expect("the store opens");
    store
        .serve_base(&install(root.path(), BaseSource::SHIPPED))
        .expect("the shipped base serves");
    rusqlite::Connection::open(&path)
        .expect("a second connection")
        .execute_batch(
            "UPDATE base_state SET phase = NULL, blocker_count = NULL,
                 schema_generation = NULL, policy_generation = NULL, set_epoch = NULL;
             DELETE FROM base_blockers;",
        )
        .expect("the serving row is put back to the pre-column shape");

    // The release replays the rules it shipped with, so the served set is re-sealed in
    // the same transaction. That seal is what used to write a count with no epoch.
    let effective =
        config::resolve_effective_on(BaseSource::SHIPPED, Some(&user)).expect("the view resolves");
    let replay = install(root.path(), BaseSource::SHIPPED).pinning(&effective);
    let mut document = config::Config::parse_validated(&user).expect("validates");
    store
        .cut_over_base(
            &replay,
            &[IdentityMigration {
                base_version: SHIPPED_BASE_VERSION,
                kind: IdentityKind::Role,
                old_id: "legacy-000".to_string(),
                new_id: "main".to_string(),
                rule: MigrationRule::Merge,
                subject: None,
            }],
            &mut document,
        )
        .expect("the replay re-seals the served base's set");
    drop(store);

    // The installation serves that base, so the next production open has to start.
    let world = support::open_world_at(root.path(), Some(&user));
    assert_eq!(
        world
            .runtime
            .store()
            .active_base()
            .expect("base read")
            .map(|base| base.version),
        Some(SHIPPED_BASE_VERSION),
        "the re-sealed row is still the base serving now"
    );
    let status = world
        .runtime
        .store()
        .update_status()
        .expect("the status answers");
    assert!(
        status.blockers.is_none(),
        "a legacy row still records no set: {status:?}"
    );
    assert!(
        status.page_conflict.is_none(),
        "a legacy row serves no phantom page: {status:?}"
    );
    drop(world);

    let row = rusqlite::Connection::open(&path)
        .expect("the primary opens")
        .query_row(
            "SELECT phase, blocker_count, schema_generation, policy_generation, set_epoch
                 FROM base_state WHERE base_version = ?1",
            [SHIPPED_BASE_VERSION as i64],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<i64>>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                ))
            },
        )
        .expect("the row is still in the ledger");
    assert_eq!(
        row,
        (None, None, None, None, None),
        "the re-seal left the row's unvalidated shape alone"
    );
}

/// AC-055: the page-scoped refusal for a base the ledger does not hold names the recovery
/// that clears it — the base that serves, or no `base` key at all. A restart re-requests
/// the same absent base and re-enters the same arm forever.
#[test]
fn absent_base_page_conflict_names_the_recovery_that_works() {
    let root = temp_root("absent-base-page");
    let mut store = open_store(root.path());
    store
        .serve_base(&install(root.path(), BaseSource::new(2, &base_v2())))
        .expect("the base serves");
    let absent = store
        .update_status_page(&config::UpdatePage {
            page_size: 20,
            base: Some(99),
            cursor: None,
        })
        .expect("an absent base is a page-scoped refusal, not an RPC error");
    let conflict = absent.page_conflict.expect("the refusal rides the status");
    assert_eq!(conflict.code, ErrorCode::Conflict);
    assert_eq!(
        conflict.boundary_id.as_deref(),
        Some(UpdateBoundary::BasePage.token()),
        "the page conflict is a row of the closed upd.* namespace: {conflict:?}"
    );
    assert_eq!(
        conflict.boundary_id.as_deref(),
        Some("upd.base.page"),
        "and its token is the one the map publishes"
    );
    assert!(
        conflict.message.contains("serving base 2"),
        "the refusal names the base that answers: {}",
        conflict.message
    );
    assert!(
        conflict.message.contains("omit the base key"),
        "the refusal names the key it cannot serve: {}",
        conflict.message
    );
    assert!(
        !conflict.message.contains("restart from the first page"),
        "a restart re-enters the same arm: {}",
        conflict.message
    );
}

// ----- p30: the projection, the activation outcome and the record tree -----

/// AC-055: one failed attempt followed by a converged one projects no phase. The
/// success rewrites the earlier record as `resolved`, which moves its write time,
/// so a projection that decides "newest" from the file alone resurfaces the rollback
/// the activation already resolved.
#[test]
fn converged_projection_clears_a_resolved_rollback_phase() {
    let root = temp_root("converged-phase");
    let evidence = EvidenceStore::open(root.path()).expect("the record directory opens");

    let mut failed = UpdateEvidence::fresh(Some(SHIPPED_BASE_VERSION));
    failed.note_failure(Failure::at(
        UpdateBoundary::Semantic,
        ErrorCode::Conflict,
        None,
    ));
    failed.terminal = Terminal::Rejected;
    failed.phase = Some(UpdatePhase::RolledBack);
    failed.cleanup = CleanupState::Done;
    evidence.write(&failed).expect("the failure lands");
    assert_eq!(
        evidence.projection().expect("the record projects").phase,
        Some(UpdatePhase::RolledBack),
        "the rollback projects while it is the newest unresolved attempt"
    );

    let mut success = UpdateEvidence::fresh(Some(SHIPPED_BASE_VERSION));
    success.terminal = Terminal::Success;
    success.phase = Some(UpdatePhase::Activated);
    success.cleanup = CleanupState::Done;
    evidence.write(&success).expect("the success lands");
    evidence
        .settle_success()
        .expect("the earlier record resolves");
    let projection = evidence.projection().expect("the records project");
    assert_eq!(
        projection.phase, None,
        "a converged attempt projects no phase; the ledger's own row answers"
    );
    assert_eq!(
        projection
            .failure
            .expect("the cause survives")
            .boundary_id
            .as_deref(),
        Some("upd.semantic"),
        "the convergence never erases the cause an operator acts on"
    );
}

/// AC-055: a rolled-back attempt removes the snapshot it took, under the same rule
/// the success path follows — after the outcome is durable, never before.
#[test]
fn rolled_back_attempt_discards_its_snapshot() {
    let root = temp_root("rollback-cleanup");
    let mut store = staged_cutover(root.path());
    let evidence = EvidenceStore::open(root.path()).expect("the record directory opens");
    let taken = snapshot(&store, root.path())
        .expect("the snapshot is taken")
        .expect("a cutover waits");
    let snapshot_path = root
        .path()
        .join("runtime")
        .join("checkpoints")
        .join(&taken.name);
    assert!(snapshot_path.exists(), "the attempt really took a copy");
    let mut attempt = UpdateEvidence::fresh(Some(2));
    let outcome = rivect::update::activate(
        &mut store,
        root.path(),
        &evidence,
        &mut attempt,
        Some(&taken.name),
        |_| Err(UpdateBoundary::Smoke),
        |store| store.commit_base(2).map(|_receipt| ()),
    )
    .expect("a failed validation rolls the attempt back");
    assert_eq!(outcome, rivect::update::ActivationOutcome::RolledBack);
    assert!(
        !snapshot_path.exists(),
        "a rolled-back attempt leaves no snapshot under runtime/checkpoints"
    );
    let recorded = evidence
        .read(&format!("{}.json", attempt.attempt_id))
        .expect("the attempt is durable");
    assert_eq!(recorded.phase, Some(UpdatePhase::RolledBack));
    assert_eq!(recorded.cleanup, CleanupState::Done);
}

/// AC-055/EDGE-012: a record tree this build cannot read is not the same answer as
/// a root where no attempt ever ran. The status read still answers, and the
/// success-shaped refusal names the tree instead of silently reporting absence.
#[test]
fn unreadable_evidence_tree_is_reported_not_silently_absent() {
    let root = temp_root("evidence-fault");
    std::fs::create_dir_all(root.path().join("runtime")).expect("runtime dir");
    std::fs::create_dir_all(root.path().join("reports")).expect("reports dir");
    let mut world = support::open_world_at(root.path(), Some(&user_config("")));
    let session = world.open_session("evidence-fault-bootstrap");
    let quiet: Value = world.dispatch(&support::corpus_status(&session));
    assert!(
        quiet["result"]["update"]["page_conflict"].is_null(),
        "an untouched root reports no record fault: {quiet}"
    );

    // A record directory this build cannot open: a plain file squats on the name.
    std::fs::remove_dir_all(root.path().join("reports").join("update"))
        .expect("the record directory the open created leaves");
    std::fs::write(
        root.path().join("reports").join("update"),
        b"not a directory",
    )
    .expect("a file squats on the record directory");
    let faulted: Value = world.dispatch(&support::corpus_status(&session));
    assert!(
        faulted["error"].is_null(),
        "the status read still answers: {faulted}"
    );
    let conflict = &faulted["result"]["update"]["page_conflict"];
    assert_eq!(
        conflict["boundary_id"], "upd.evidence.reserve",
        "the record tree names its own seam: {faulted}"
    );
    assert!(
        conflict["message"]
            .as_str()
            .is_some_and(|message| message.contains("reports/update")),
        "the refusal names the tree it could not read: {faulted}"
    );
}

/// AC-055: a failed open from the pending-cutover path keeps the base domain's own
/// class. The update refusal wraps the ledger refusal, so `base_refusal()` has to
/// unwrap both carriers or a document conflict is reported as a broken store.
#[test]
fn pending_cutover_refusal_keeps_its_typed_base_domain() {
    let root = temp_root("cutover-typed");
    std::fs::create_dir_all(root.path().join("runtime")).expect("runtime dir");
    let path = root.path().join("runtime").join("rivect.db");
    let recorded = base_v2();
    {
        let mut store = TaskStore::open(&path).expect("the store opens");
        store
            .serve_base(&install(
                root.path(),
                BaseSource::new(SHIPPED_BASE_VERSION, &recorded),
            ))
            .expect("the recorded base serves");
        // A successor waits, so the next open takes the pending-cutover path; that
        // path then offers this build's document under the recorded version, whose
        // bytes differ. The refusal is the ledger's, carried through the update.
        store
            .stage_base(&install(
                root.path(),
                BaseSource::new(SHIPPED_BASE_VERSION + 1, &base_document("")),
            ))
            .expect("the successor stages");
    }
    let Err(failure) = Runtime::open(root.path(), Box::new(LoopbackProvider::new())) else {
        panic!("a changed document under the recorded version is refused");
    };
    let refusal = failure
        .base_refusal()
        .expect("the update refusal still carries the base ledger's typed cause");
    assert!(
        matches!(
            refusal,
            config::BaseError::DocumentChanged { version } if *version == SHIPPED_BASE_VERSION
        ),
        "the base domain names the version that has to move: {refusal}"
    );
    assert_eq!(refusal.code(), ErrorCode::Conflict);
    assert!(
        failure
            .diagnostics()
            .iter()
            .any(|line| line.contains("upd.base.")),
        "the update seam survives beside the typed base class: {:?}",
        failure.diagnostics()
    );
}

/// AC-055: the activation is the commit. A receipt read that faults after the commit
/// landed must leave `Activated` as the outcome — and no `upd.base.activate` cause —
/// because the store already serves the new tuple and an operator told to fix the
/// activation would chase a cutover that succeeded.
#[test]
fn post_commit_receipt_fault_still_reports_the_landed_activation() {
    let root = temp_root("receipt-fault");
    let mut store = staged_cutover(root.path());
    let evidence = EvidenceStore::open(root.path()).expect("the record directory opens");
    let pinned = install(root.path(), BaseSource::new(2, &base_v2()));
    let mut attempt = UpdateEvidence::fresh(Some(2));
    let outcome = rivect::update::activate(
        &mut store,
        root.path(),
        &evidence,
        &mut attempt,
        None,
        |store| rivect::update::validate_generation(store, &pinned),
        |store| {
            // The commit lands, then the read the old seam made its outcome from
            // cannot answer: the receipt rows are gone.
            store.commit_base(2)?;
            rusqlite::Connection::open(root.path().join("state.db"))
                .and_then(|conn| conn.execute_batch("DELETE FROM update_receipts"))
                .map_err(|error| config::BaseError::Store(StoreError::Storage(Box::new(error))))?;
            Ok(())
        },
    )
    .expect("the commit landed, so the attempt activated");
    assert_eq!(
        outcome,
        rivect::update::ActivationOutcome::Activated,
        "a post-commit read fault never turns a landed activation into a refusal"
    );
    assert_eq!(
        store
            .active_base()
            .expect("base read")
            .map(|base| base.version),
        Some(2),
        "the new tuple really serves"
    );
    let recorded = evidence
        .read(&format!("{}.json", attempt.attempt_id))
        .expect("the attempt is durable");
    assert_eq!(recorded.terminal, Terminal::Success);
    assert_ne!(
        recorded
            .first_failure
            .as_ref()
            .map(|failure| failure.boundary),
        Some(UpdateBoundary::BaseActivate),
        "the landed activation is not reported at the activation seam"
    );
}

// ----- p32a: every evidence-directory refusal names what is really there -----

/// AC-055: each evidence-directory refusal names the seam, the correction, and a path
/// that exists. A pointer to a record the refusal never wrote sends an operator to a
/// file that is not there; when the directory itself is what refused, the directory is
/// the only honest answer.
#[test]
fn evidence_refusals_name_a_path_that_exists() {
    let user = user_config("");

    // Arm 1: the record directory itself refuses. A plain file squats on the name, so
    // no attempt record can exist and the line names the directory.
    let blocked = temp_root("evidence-refusal-open");
    std::fs::create_dir_all(blocked.path().join("runtime")).expect("runtime dir");
    std::fs::write(blocked.path().join("config.toml"), &user).expect("the user document lands");
    {
        let mut store = TaskStore::open(&blocked.path().join("runtime").join("rivect.db"))
            .expect("the store opens");
        store
            .stage_base(&install(blocked.path(), BaseSource::SHIPPED))
            .expect("the cutover waits");
    }
    std::fs::create_dir_all(blocked.path().join("reports")).expect("reports dir");
    std::fs::write(
        blocked.path().join("reports").join("update"),
        b"not a directory",
    )
    .expect("a file squats on the record directory");
    let Err(failure) = Runtime::open(blocked.path(), Box::new(LoopbackProvider::new())) else {
        panic!("a record directory that cannot be opened refuses the open");
    };
    let lines = failure.diagnostics();
    assert!(
        lines
            .iter()
            .any(|line| line.contains("update evidence directory: reports/update")),
        "the refusal names the directory that refused: {lines:?}"
    );
    assert!(
        lines.iter().any(|line| line
            == "update next: make the update reports directory private and writable, then retry"),
        "the refusal carries the seam's correction: {lines:?}"
    );
    assert!(
        !lines.iter().any(|line| line.contains(".json")),
        "no refusal names a record it never wrote: {lines:?}"
    );

    // Arm 2: the reserve write fails inside a proven directory. `private_dir`
    // restores 0700 on every open, so a narrowed mode cannot arm this arm from a
    // test; what it owes is the same Directory pointer arm 1 proves, and the
    // saturation arm below proves the same mapping through the other refusal that
    // leaves no record.

    // Arm 3: the tree is saturated by another offered base, so the reserve is refused
    // for capacity and still no record of this attempt exists.
    let full = temp_root("evidence-refusal-saturated");
    std::fs::create_dir_all(full.path().join("runtime")).expect("runtime dir");
    std::fs::write(full.path().join("config.toml"), &user).expect("the user document lands");
    {
        let mut store = TaskStore::open(&full.path().join("runtime").join("rivect.db"))
            .expect("the store opens");
        store
            .stage_base(&install(full.path(), BaseSource::SHIPPED))
            .expect("the cutover waits");
    }
    let store_evidence = EvidenceStore::open(full.path()).expect("the record directory opens");
    for _ in 0..rivect::update::EVIDENCE_MAX_RECORDS {
        let mut failure = UpdateEvidence::fresh(Some(SHIPPED_BASE_VERSION + 9));
        failure.note_failure(Failure::at(
            UpdateBoundary::CheckpointCreate,
            ErrorCode::StorageUnavailable,
            None,
        ));
        failure.terminal = Terminal::Rejected;
        failure.cleanup = CleanupState::Done;
        store_evidence
            .write(&failure)
            .expect("the failure record lands");
    }
    let Err(failure) = Runtime::open(full.path(), Box::new(LoopbackProvider::new())) else {
        panic!("a saturated tree refuses a new attempt");
    };
    let lines = failure.diagnostics();
    assert!(
        !lines.iter().any(|line| line.contains(".json")),
        "a saturated reserve names no record it did not write: {lines:?}"
    );
    assert!(
        lines
            .iter()
            .any(|line| line.starts_with("update evidence directory: reports/update")),
        "the refusal names the directory to clear: {lines:?}"
    );
}

/// AC-055/I-14: a record write that refuses because of the *tree* names the directory, never
/// this attempt's own generated name. `EvidenceStore::write` lists, decodes and prunes the
/// records already present before it renames this attempt's file, so an unreadable or
/// tampered neighbour fails the write with nothing of this attempt on disk; a `Read` or
/// `Record` refusal there would otherwise print `reports/update/<this-attempt>.json` for a
/// file that was never written.
#[test]
fn record_write_refusals_name_only_a_path_that_exists() {
    let record = format!("{}.json", uuid::Uuid::new_v4());
    let io = || std::io::Error::other("fixture");
    for refusal in [
        // The tree itself: nothing of this attempt reached the directory.
        UpdateError::Reserve { source: io() },
        UpdateError::Write { source: io() },
        UpdateError::Read { source: io() },
        UpdateError::Record {
            detail: "the record is not schema v1",
        },
        UpdateError::Saturated,
    ] {
        let refusal_name = refusal.to_string();
        let pointer = rivect::update::refusal_pointer(&refusal, &record);
        assert_eq!(
            pointer,
            rivect::update::EvidencePointer::Directory,
            "{refusal_name} must name the directory"
        );
        let lines = rivect::update::refusal_diagnostics(pointer, refusal.boundary(), "fix it");
        assert!(
            !lines.iter().any(|line| line.contains(".json")),
            "{refusal_name} named a record it never wrote: {lines:?}"
        );
        assert!(
            lines
                .iter()
                .any(|line| line.starts_with("update evidence directory: reports/update")),
            "{refusal_name} names the directory: {lines:?}"
        );
    }

    // A refusal after this attempt's terminal record landed still names that record:
    // the file really is there to read.
    for refusal in [
        UpdateError::TerminalWrite {
            source: Box::new(UpdateError::Saturated),
        },
        UpdateError::Identity {
            source: StoreError::Closed,
        },
    ] {
        let pointer = rivect::update::refusal_pointer(&refusal, &record);
        let rivect::update::EvidencePointer::Record(name) = pointer else {
            panic!("{refusal} happens with the attempt's record durable: {pointer:?}");
        };
        assert_eq!(name, record);
    }
}

/// AC-055: an unreadable record tree is the secondary fact. When the ledger already set a
/// page-scoped conflict — a cursor whose offset is past the set it names — the status must
/// keep telling that caller to restart; a record-tree fault that overwrote it would leave
/// the caller with the wrong instruction and no way to resume.
#[test]
fn record_tree_fault_does_not_overwrite_a_ledger_page_conflict() {
    let root = temp_root("conflict-precedence");
    let mut store = open_store(root.path());
    store
        .serve_base(&install(root.path(), BaseSource::new(2, &base_v2())))
        .expect("the base serves");
    let ledger_conflict = store
        .update_status_page(&config::UpdatePage {
            page_size: 20,
            base: Some(2),
            cursor: Some("blk:2:1:offset:9000".to_string()),
        })
        .expect("an out-of-range cursor is page-scoped");
    let ledger_message = ledger_conflict
        .page_conflict
        .expect("the ledger sets the conflict")
        .message;

    // The record tree becomes unreadable behind the same read.
    std::fs::create_dir_all(root.path().join("reports")).expect("reports dir");
    std::fs::write(
        root.path().join("reports").join("update"),
        b"not a directory",
    )
    .expect("a file squats on the record directory");
    let status = rivect::update::project_status(
        &store,
        &config::UpdatePage {
            page_size: 20,
            base: Some(2),
            cursor: Some("blk:2:1:offset:9000".to_string()),
        },
        root.path(),
    )
    .expect("the status still answers");
    let conflict = status.page_conflict.expect("the read still conflicts");
    assert_eq!(
        conflict.message, ledger_message,
        "the ledger's own instruction survives the record-tree fault"
    );
    assert!(
        conflict.message.contains("restart from the first page"),
        "the caller holding the stale cursor is told to restart: {}",
        conflict.message
    );
    assert_ne!(
        conflict.boundary_id.as_deref(),
        Some("upd.evidence.reserve"),
        "the record tree did not replace the page decision: {conflict:?}"
    );

    // The record-tree fault still surfaces when nothing else answered: the fact is not
    // lost, only outranked.
    let quiet = rivect::update::project_status(&store, &config::UpdatePage::default(), root.path())
        .expect("the status answers");
    assert_eq!(
        quiet
            .page_conflict
            .expect("the unreadable tree is still reported")
            .boundary_id
            .as_deref(),
        Some("upd.evidence.reserve"),
        "a read with no page conflict reports the tree"
    );
}

/// AC-093: a recovery that refuses after collecting a human verdict reports that
/// verdict on the failed open. The compatible path returns before the generation
/// transaction, so its diagnostics must carry what the recovery already found — the
/// same splice the post-commit path performs — or the operator loses the verdict
/// the open just read.
#[test]
fn refused_compatible_recovery_keeps_the_verdict_it_collected() {
    let root = temp_root("compatible-verdict");
    std::fs::create_dir_all(root.path().join("runtime")).expect("runtime dir");
    let user = user_config("");
    std::fs::write(root.path().join("config.toml"), &user).expect("the user document lands");
    let primary = root.path().join("runtime").join("rivect.db");
    {
        let mut store = TaskStore::open(&primary).expect("the store opens");
        let mut parsed = config::Config::parse_validated(&user).expect("validates");
        let edit = parsed
            .set("context.auto_compact", config::ConfigValue::Bool(true))
            .expect("the edit builds");
        config::stage_publication(&mut store, "cli", &root.path().join("config.toml"), &edit)
            .expect("the pending publication is durable");
    }
    // The target no longer holds the staged bytes, so the recovery reads a verdict
    // a human has to resolve instead of receipting the write.
    std::fs::write(root.path().join("config.toml"), &user).expect("the target holds other bytes");

    // The reconcile that follows then refuses: the attempt is already settled, so it
    // owes no new row, but its recorded attempt root does not name an allocation and
    // the cleanup cannot proceed on a cause it cannot parse. The refusal is typed and
    // needs no fault seam.
    let attempt = "compatible-verdict-attempt";
    let settled = serde_json::json!({
        "attempt_id": attempt,
        "boundary_id": format!("ret:check:{attempt}:close.unrecovered"),
        "stage": "terminal",
        "cause": "unrecorded interruption",
        "digest": "0".repeat(64),
        "build_attempt": attempt,
    })
    .to_string();
    let root_locator = serde_json::json!({
        "attempt_id": attempt,
        "boundary_id": format!("ret:check:{attempt}:attempt.root"),
        "stage": "terminal",
        "cause": "not an allocation locator",
        "digest": "1".repeat(64),
        "build_attempt": attempt,
    })
    .to_string();
    {
        let conn = rusqlite::Connection::open(&primary).expect("the primary opens");
        conn.execute(
            "INSERT INTO attempts (attempt_id, task_id, action_id, effect_class, describe, state)
             VALUES (?1, 'task-1', 'action-1', 'exec', 'fixture', 'running')",
            [attempt],
        )
        .expect("the claimed attempt exists");
        for (site, record) in [
            ("admit.claim", "{\"site\":\"admit.claim\"}"),
            ("close.unrecovered", settled.as_str()),
            ("attempt.root", root_locator.as_str()),
        ] {
            conn.execute(
                "INSERT INTO retained (boundary_id, record_json) VALUES (?1, ?2)",
                rusqlite::params![format!("ret:check:{attempt}:{site}"), record],
            )
            .expect("the recovery row exists");
        }
    }

    let Err(failure) = Runtime::open(root.path(), Box::new(LoopbackProvider::new())) else {
        panic!("a recovery that cannot settle its attempt refuses the open");
    };
    assert!(
        failure
            .diagnostics()
            .iter()
            .any(|line| line.starts_with("publication recovery:")),
        "the collected verdict survived the refusal: {:?}",
        failure.diagnostics()
    );
}

/// INV-007: a saturated record tree is not closed to an installed, usable version.
/// A pending cutover whose 32 unresolved failures all name the base the startup
/// offers still opens and reaches the new generation, because the recorded exception
/// admits that same-offered-base attempt — the one whose terminal record can settle
/// the set. A different-base newcomer is still refused, and a resolving success
/// settles the backlog and prunes the tree back to the bound.
#[test]
fn saturated_tree_still_opens_the_offered_base() {
    let root = temp_root("saturated-open");
    std::fs::create_dir_all(root.path().join("runtime")).expect("runtime dir");
    std::fs::write(root.path().join("config.toml"), user_config(""))
        .expect("the user document lands");
    let primary = root.path().join("runtime").join("rivect.db");
    {
        let mut store = TaskStore::open(&primary).expect("the store opens");
        store
            .stage_base(&install(root.path(), BaseSource::SHIPPED))
            .expect("the offered base stages");
    }
    // The tree a run of failing attempts leaves: the bound is full of unresolved
    // failures that all name the base the startup is about to offer.
    let evidence = EvidenceStore::open(root.path()).expect("the record directory opens");
    for _ in 0..rivect::update::EVIDENCE_MAX_RECORDS {
        let mut failure = UpdateEvidence::fresh(Some(SHIPPED_BASE_VERSION));
        failure.note_failure(Failure::at(
            UpdateBoundary::CheckpointCreate,
            ErrorCode::StorageUnavailable,
            None,
        ));
        failure.terminal = Terminal::Rejected;
        failure.cleanup = CleanupState::Done;
        evidence.write(&failure).expect("the failure record lands");
    }

    // The installed version still starts: the open repeats the offered base, and that
    // attempt is admitted at the bound so its success can settle the set.
    let world = support::open_world_at(root.path(), Some(&user_config("")));
    assert_eq!(
        world
            .runtime
            .store()
            .active_base()
            .expect("base read")
            .map(|base| base.version),
        Some(SHIPPED_BASE_VERSION),
        "a saturated tree bricked an installed, usable version"
    );
    drop(world);

    // The landed success resolved the backlog, and the pruner removed only records
    // that carry no cause: the settled causes stay beside the success that settled
    // them (the cost `DEC-025` records), so the admission is bounded in what one read
    // decodes rather than in what the directory may retain.
    let names = evidence.names().expect("the records list");
    assert_eq!(
        names.len(),
        rivect::update::EVIDENCE_MAX_RECORDS + 1,
        "the causes and the success that settled them are retained"
    );
    assert!(
        names
            .iter()
            .filter_map(|name| evidence.read(name).ok())
            .all(|record| record.resolved || record.terminal == Terminal::Success),
        "the prune removed nothing an operator still has to act on"
    );
    assert!(
        names
            .iter()
            .filter_map(|name| evidence.read(name).ok())
            .any(|record| record.resolved),
        "the success marked the earlier failures resolved: {names:?}"
    );

    // A newcomer of another base is still refused, and its refusal names the count
    // bound's own recovery rather than the permission sentence. The window is filled
    // again first, because the prune above legitimately left it below the bound.
    for _ in 0..rivect::update::EVIDENCE_MAX_RECORDS {
        let mut failure = UpdateEvidence::fresh(Some(SHIPPED_BASE_VERSION));
        failure.note_failure(Failure::at(
            UpdateBoundary::CheckpointCreate,
            ErrorCode::StorageUnavailable,
            None,
        ));
        failure.terminal = Terminal::Rejected;
        failure.cleanup = CleanupState::Done;
        evidence
            .write(&failure)
            .expect("the replacement window fills to the bound");
    }
    let refused = evidence
        .write(&UpdateEvidence::fresh(Some(SHIPPED_BASE_VERSION + 1)))
        .expect_err("another base is a new attempt and is refused at the bound");
    assert!(matches!(refused, UpdateError::Saturated), "{refused}");
    let grew = evidence.names().expect("the directory lists").len();
    assert_eq!(
        grew,
        rivect::update::EVIDENCE_MAX_RECORDS + 1,
        "the refusal appended nothing; the settled set stays because DEC-025 records that cost"
    );
    assert_ne!(
        refused.correction(),
        UpdateBoundary::EvidenceReserve.correction(),
        "a count bound is not cleared by fixing permissions"
    );
    assert!(
        refused.correction().contains("reports/update"),
        "the correction names the records an operator must resolve: {}",
        refused.correction()
    );
}
