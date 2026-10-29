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
