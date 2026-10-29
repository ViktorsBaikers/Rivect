//! AC-056 (REQ-046): a rename, split or merge rebinds pins, learned deltas and
//! disables by meaning — the key name, never an array position — without
//! capturing the user's reserved namespace, widening grants, or activating
//! unknown executable content, and an unknown user field survives byte-identical
//! (EDGE-007, PROH-005).
//!
//! Every case drives the production write surfaces — the cutover entry
//! [`TaskStore::cut_over_base`] for a base release and its rules,
//! [`Config::rebind_purpose`] for a role's binding on its own — and
//! then reads the durable rows, the effective definition and the policy back in
//! the same process. A rebinding that only reports success therefore fails
//! these cases: the value it names has to be the value the next read answers.
//!
//! The store is the real one (a temporary SQLite file), the config is parsed by
//! the production schema, and the loopback corpus runs the production learning
//! lifecycle. No network and no credential is involved.

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
    ASSESS_SECURITY, AUDIT_TESTS, DIAGNOSE_ISSUE, REVIEW_CHANGE, RequestKind, Surface,
};
use rivect::config::{
    BaseError, BaseInstall, BaseSource, Config, ConfigIssue, FallbackAssign, FixedModel,
    ModelAssign, UpdateState, resolve_effective_on,
};
use rivect::contracts::{EffectClass, ErrorCode};
use rivect::identity::{
    IdentityError, IdentityKind, IdentityMigration, IdentityRebind, IdentityRules, MigrationRule,
    Placement, claims_personal_namespace,
};
use rivect::learning::{
    ConditionFact, ConditionFacts, CorpusCase, DEFINITION_MAX_BYTES, DELTA_INSTRUCTION_MAX_BYTES,
    DeltaCandidate, DeltaChange, DeltaPayload, DeltaState, PredicateEffect,
};
use rivect::policy::PolicyError;
use rivect::state::TaskStore;
use std::collections::BTreeSet;
use std::path::PathBuf;

/// The id a rename, a split and a merge all start from: one catalog capability
/// that is also the request purpose it names, so one identity carries both the
/// instruction experience (a role) and the selection experience (an action).
const ROLE: &str = REVIEW_CHANGE;

const PROBE_PURPOSE: &str = "probe_purpose";
const PROBE: &str = "probe-delta";
const PROBE_TEXT: &str = "the probe purpose names the leg it runs before its report";

const INSTRUCTION_TEXT: &str =
    "treat every supplied path as untrusted input and name the boundary it enters";
const ROUTE_TEXT: &str = "the audit reads the diff before it reads the report";

// ----- fixtures -----

fn local_config() -> String {
    "config_version = 1\n\
     [connections.local]\n\
     kind = \"local\"\n\
     endpoint = \"http://127.0.0.1:11434\"\n\
     [models.defaults]\n\
     model = { mode = \"auto\" }\n\
     effort = { mode = \"auto\" }\n\
     fallback = { mode = \"auto\" }\n"
        .to_string()
}

/// The user's document with one pinned purpose row per `(name, model_id)` — the
/// binding a rename has to carry to the migrated name.
fn pinned_config(pins: &[(&str, &str)]) -> String {
    let mut text = local_config();
    for (purpose, model_id) in pins {
        text.push_str(&format!(
            "[models.purposes.{purpose}]\nmodel = {{ mode = \"fixed\", connection = \"local\", model_id = \"{model_id}\" }}\n"
        ));
    }
    text
}

/// A base document this build's schema accepts: the versioned layer a rule set
/// is bound to.
fn base_document() -> String {
    "config_version = 1\n\
     [models.defaults]\n\
     model = { mode = \"auto\" }\n\
     effort = { mode = \"auto\" }\n\
     fallback = { mode = \"auto\" }\n"
        .to_string()
}

fn temp_root(prefix: &str) -> tempfile::TempDir {
    tempfile::TempDir::with_prefix(format!("rivect-identity-{prefix}-")).expect("fixture root")
}

fn open_store(root: &tempfile::TempDir) -> TaskStore {
    TaskStore::open(&root.path().join("state.db")).expect("store opens")
}

fn instruction(delta_id: &str, text: &str, purpose: &str) -> DeltaCandidate {
    DeltaCandidate {
        delta_id: delta_id.to_string(),
        base_version: 0,
        change: DeltaChange {
            payload: DeltaPayload::Instruction {
                text: text.to_string(),
            },
            when: Some(ConditionFact::Purpose(purpose.to_string())),
        },
        evidence: format!("tests/identity.rs {delta_id}"),
    }
}

fn applicability_with(delta_id: &str, capability: &str, effect: PredicateEffect) -> DeltaCandidate {
    applicability_on(
        delta_id,
        capability,
        effect,
        ConditionFact::Surface(Surface::PublicApi),
    )
}

/// The same candidate under the fact the caller names: two conclusions only
/// disagree where one request can hold both of them (AC-056).
fn applicability_on(
    delta_id: &str,
    capability: &str,
    effect: PredicateEffect,
    when: ConditionFact,
) -> DeltaCandidate {
    DeltaCandidate {
        delta_id: delta_id.to_string(),
        base_version: 0,
        change: DeltaChange {
            payload: DeltaPayload::Applicability {
                capability: capability.to_string(),
                effect,
            },
            when: Some(when),
        },
        evidence: format!("tests/identity.rs {delta_id}"),
    }
}

fn applicability(delta_id: &str, capability: &str) -> DeltaCandidate {
    applicability_with(delta_id, capability, PredicateEffect::Require)
}

fn probe_candidate() -> DeltaCandidate {
    instruction(PROBE, PROBE_TEXT, PROBE_PURPOSE)
}

/// The three cases an instruction delta must pass (the lifecycle the store
/// pins): it transfers to its purpose, it composes with what is active, and it
/// stays out of a purpose where a different, recorded delta provably applies.
fn instruction_corpus(purpose: &str) -> Vec<CorpusCase> {
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

fn selection_facts() -> ConditionFacts {
    ConditionFacts::for_selection(
        RequestKind::Audit,
        Some(BTreeSet::from([Surface::PublicApi])),
    )
}

fn applicability_corpus() -> Vec<CorpusCase> {
    applicability_corpus_on(&selection_facts())
}

/// The same three cases run under the facts the candidate's own condition reads.
fn applicability_corpus_on(facts: &ConditionFacts) -> Vec<CorpusCase> {
    vec![
        CorpusCase::Transfer {
            facts: facts.clone(),
        },
        CorpusCase::Composition {
            facts: facts.clone(),
        },
        CorpusCase::NegativeControl {
            facts: ConditionFacts::for_purpose(PROBE_PURPOSE),
            control: PROBE.to_string(),
        },
    ]
}

/// The corpus probe every activation needs as its negative control: fixture
/// machinery, not an experience any mapping speaks about.
fn ensure_probe(store: &mut TaskStore) {
    if store.learning_delta(PROBE).is_err() {
        store
            .record_learning_delta(&probe_candidate())
            .expect("probe delta recorded");
    }
}

/// Records one candidate, runs its corpus and activates it: the lifecycle a
/// verified low-risk delta takes before an identity rule can move it.
fn verified(store: &mut TaskStore, candidate: &DeltaCandidate, corpus: &[CorpusCase]) {
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
        .expect("activation");
}

/// The subjects a pass left named, minus the corpus probe every activation
/// needs: the probe is fixture machinery, not an experience the mapping speaks
/// about. An empty answer means every binding the fixture wrote was placed.
fn named_beyond_probe(report: &IdentityRebind) -> Vec<String> {
    report
        .unassigned
        .iter()
        .filter(|named| named.subject != PROBE_PURPOSE)
        .map(|named| format!("{} {}", named.kind, named.subject))
        .collect()
}

/// The base a cutover installs: the next version after the one serving, or the
/// shipped base when nothing serves yet — a release steps one base at a time.
fn next_base(store: &TaskStore) -> u64 {
    match store.active_base().expect("base read") {
        Some(active) => active.version + 1,
        None => rivect::config::SHIPPED_BASE_VERSION,
    }
}

/// The install of `version` under a root of its own: the ledger records the base
/// document and the two locations the receipt names.
fn base_install(version: u64, root: &tempfile::TempDir) -> BaseInstall {
    let document = base_document();
    BaseInstall::new(
        BaseSource::new(version, &document),
        root.path().join("config.toml"),
        root.path(),
    )
}

/// A user document the cutover can carry pins in: no purpose row yet.
fn local_document() -> Config {
    Config::parse_validated(&local_config()).expect("a valid local document")
}

/// Applies one rule set the way a release does (AC-056): the base the rules are
/// released with is installed through the one cutover entry, so the rules record,
/// the stored bindings move inside the transaction that activates that base and
/// the document follows it. A binding has no other seam — a store cannot move one
/// without committing the base that names it — so a case that wants the pass to
/// answer reads it here.
fn cut_over(
    store: &mut TaskStore,
    rules: &[IdentityMigration],
) -> Result<IdentityRebind, IdentityError> {
    let version = next_base(store);
    let released = rules
        .iter()
        .map(|rule| IdentityMigration {
            base_version: version,
            ..rule.clone()
        })
        .collect::<Vec<_>>();
    let root = temp_root("cutover");
    let install = base_install(version, &root);
    match store.cut_over_base(&install, &released, &mut local_document()) {
        Ok(cutover) => Ok(cutover.served.receipt.identity),
        Err(BaseError::Identity(error)) => Err(error),
        Err(refusal) => panic!("the cutover ledger refused the fixture base: {refusal}"),
    }
}

fn role_rule(
    old_id: &str,
    new_id: &str,
    rule: MigrationRule,
    subject: Option<&str>,
) -> IdentityMigration {
    IdentityMigration {
        base_version: rivect::config::SHIPPED_BASE_VERSION,
        kind: IdentityKind::Role,
        old_id: old_id.to_string(),
        new_id: new_id.to_string(),
        rule,
        subject: subject.map(str::to_string),
    }
}

fn action_rule(
    old_id: &str,
    new_id: &str,
    rule: MigrationRule,
    subject: Option<&str>,
) -> IdentityMigration {
    IdentityMigration {
        kind: IdentityKind::Action,
        ..role_rule(old_id, new_id, rule, subject)
    }
}

/// The policy state every migration case compares before and after its run,
/// read through the production surfaces: a runtime owns the policy, the
/// first-task seam mints its scoped read grant, and the runtime's writer
/// enrolls one deny path inside it. A migration that minted a grant or enrolled
/// a deny anywhere the runtime serves would move this read — grants are policy
/// state, never a field a config document writes (PROH-005).
///
/// p5 proves the read can move at all: a control mutation through the same
/// writer changes both halves, so an unchanged read after a migration is the
/// migration's doing rather than a value compared with itself.
struct Grants {
    world: support::World,
    grant: String,
    denied: PathBuf,
    free: PathBuf,
    /// The spellings the deny set is read through — the enrolled path, a
    /// traversal spelling of it and the free sibling — so an enrolled or
    /// revoked rule moves the read instead of staying unobserved.
    probes: Vec<PathBuf>,
    _tree: support::TempTree,
}

/// What the runtime's policy answers: its grant registry by the sequential ids
/// it mints, the coverage verdict for every probe spelling, and the two verdicts
/// the fixture pins.
#[derive(Debug, PartialEq, Eq)]
struct PolicyRead {
    grants: Vec<(String, Vec<EffectClass>, bool)>,
    covers: Vec<(String, bool)>,
    covers_enrolled: bool,
    covers_free: bool,
}

/// How many grant ids the registry read probes. The policy mints its ids in one
/// sequence, so every live grant is inside this window and a minted one is read
/// back instead of being assumed absent.
const GRANT_PROBES: u64 = 8;

impl Grants {
    fn new(name: &str) -> Self {
        let tree = support::TempTree::new("identity", name);
        let denied = tree.path.join("denied").join("file.txt");
        let free = tree.path.join("free").join("file.txt");
        std::fs::create_dir_all(denied.parent().expect("denied parent")).expect("denied root");
        std::fs::create_dir_all(free.parent().expect("free parent")).expect("free root");
        let probes = vec![
            denied.clone(),
            tree.path
                .join("denied")
                .join("..")
                .join("denied")
                .join("file.txt"),
            free.clone(),
        ];
        let mut world = support::open_world(&format!("identity-{name}-policy"), None);
        let grant = world
            .runtime
            .set_read_scope(tree.path.clone(), free.clone());
        assert_eq!(
            grant, "grant-1",
            "fixture: the scoped read is the policy's first grant"
        );
        world
            .runtime
            .policy_writer()
            .enroll_deny(&denied)
            .expect("deny enrollment");
        Self {
            world,
            grant,
            denied,
            free,
            probes,
            _tree: tree,
        }
    }

    fn read(&self) -> PolicyRead {
        let policy = self.world.runtime.policy();
        assert!(
            policy.grant(&self.grant).is_some(),
            "the fixture grant left the runtime's registry"
        );
        PolicyRead {
            grants: (1..=GRANT_PROBES)
                .filter_map(|number| {
                    let grant = policy.grant(&format!("grant-{number}"))?;
                    Some((grant.grant_id.clone(), grant.classes.clone(), grant.revoked))
                })
                .collect(),
            covers: self
                .probes
                .iter()
                .map(|path| (path.display().to_string(), policy.covers(path)))
                .collect(),
            covers_enrolled: policy.covers(&self.denied),
            covers_free: policy.covers(&self.free),
        }
    }
}

// ----- p1: a rename moves a pin and a disable -----

#[test]
fn rename_rebinds_pin_and_disable_p1() {
    let grants = Grants::new("rename");
    let policy_before = grants.read();

    // The pin: the role's own model binding, moved to the renamed key.
    let mut config = Config::parse_validated(&pinned_config(&[(ROLE, "reviewer-model")]))
        .expect("a pinned purpose row is valid");
    let before = config.resolve_purpose(ROLE).expect("the pin resolves");
    assert!(
        matches!(&before.model, ModelAssign::Fixed(fixed) if fixed.model_id == "reviewer-model"),
        "fixture: the purpose carries a fixed pin: {before:?}"
    );

    // The disable: an experience activated once and withdrawn.
    let root = temp_root("rename");
    let mut store = open_store(&root);
    verified(
        &mut store,
        &instruction("keeper", INSTRUCTION_TEXT, ROLE),
        &instruction_corpus(ROLE),
    );
    verified(
        &mut store,
        &instruction("withdrawn", ROUTE_TEXT, ROLE),
        &instruction_corpus(ROLE),
    );
    let withdrawn = store.learning_delta("withdrawn").expect("stored");
    assert_eq!(withdrawn.state, DeltaState::Active);
    store
        .roll_back_learning_delta("withdrawn", withdrawn.version)
        .expect("the experience is withdrawn");
    assert_eq!(
        store.learning_delta("withdrawn").expect("stored").state,
        DeltaState::RolledBack
    );

    let rule = role_rule(ROLE, ASSESS_SECURITY, MigrationRule::Rename, None);
    store
        .record_identity_migration(&rule)
        .expect("the rule set records under the serving base");
    let report = cut_over(&mut store, &[rule]).expect("the rule set rebinds the stored rows");
    assert!(
        named_beyond_probe(&report).is_empty(),
        "a rename left a binding it was released with unplaced: {report:?}"
    );
    assert_eq!(report.rebound.len(), 2, "both rows move: {report:?}");
    assert_eq!(
        report.base_version,
        rivect::config::SHIPPED_BASE_VERSION,
        "the pass did not name the base it applied"
    );

    // The pin moved by meaning and the old key no longer answers it.
    let edit = config
        .rebind_purpose(ROLE, ASSESS_SECURITY)
        .expect("the binding moves")
        .expect("the source row exists");
    let moved = config.resolve_purpose(ASSESS_SECURITY).expect("resolves");
    assert_eq!(
        moved.model_source,
        format!("models.purposes.{ASSESS_SECURITY}"),
        "the pin did not move with the rename"
    );
    assert!(
        matches!(&moved.model, ModelAssign::Fixed(fixed) if fixed.model_id == "reviewer-model"),
        "the moved binding is not the one the old key carried: {moved:?}"
    );
    let left_behind = config.resolve_purpose(ROLE).expect("resolves");
    assert_eq!(
        left_behind.model_source, "models.defaults",
        "the old key still answers the pin after the rename"
    );
    let bytes = String::from_utf8(edit.bytes).expect("edited TOML is utf-8");
    assert!(
        bytes.contains(&format!("[models.purposes.{ASSESS_SECURITY}]")),
        "the moved binding is not in the document: {bytes}"
    );
    assert!(
        !bytes.contains(&format!("[models.purposes.{ROLE}]")),
        "the old key stayed readable in the document: {bytes}"
    );

    // The disable moved too: still withdrawn, now bound to the new name.
    let withdrawn = store.learning_delta("withdrawn").expect("stored");
    assert_eq!(
        withdrawn.state,
        DeltaState::RolledBack,
        "the rename re-activated a withdrawn experience"
    );
    assert_eq!(
        withdrawn.change.when,
        Some(ConditionFact::Purpose(ASSESS_SECURITY.to_string())),
        "the disable stayed under the retired name"
    );
    let definition = store.learning_definition().expect("definition");
    let part = definition.instruction_part(ASSESS_SECURITY, "base");
    assert!(
        part.contains(INSTRUCTION_TEXT),
        "the active experience did not move: {part}"
    );
    assert!(
        !part.contains(ROUTE_TEXT),
        "the withdrawn experience applies again: {part}"
    );
    assert_eq!(
        definition.instruction_part(ROLE, "base"),
        "base",
        "the retired name still carries the experience"
    );

    assert_eq!(
        grants.read(),
        policy_before,
        "a rename widened the effect policy"
    );
}

// ----- a role's fallback order follows its binding, never the row's position -----

#[test]
fn fallback_binding_follows_meaning_not_position() {
    const STYLE: &str = "review_style";
    const HEADER: &str = "config_version = 1\n\
         [connections.local]\n\
         kind = \"local\"\n\
         endpoint = \"http://127.0.0.1:11434\"\n\
         [connections.local-second]\n\
         kind = \"local\"\n\
         endpoint = \"http://127.0.0.1:11435\"\n\
         [models.defaults]\n\
         model = { mode = \"auto\" }\n\
         effort = { mode = \"auto\" }\n\
         fallback = { mode = \"auto\" }\n";
    // The chain names the second connection first, so an order rebuilt from the
    // connection table or from the alphabet (`local` sorts before
    // `local-second`) would answer different bytes than the release shipped.
    let chain = FallbackAssign::Auto {
        chain: vec![
            FixedModel {
                connection: "local-second".to_string(),
                model_id: "second".to_string(),
            },
            FixedModel {
                connection: "local".to_string(),
                model_id: "first".to_string(),
            },
        ],
    };
    let role_row = format!(
        "[models.purposes.{ROLE}]\n\
         model = {{ mode = \"fixed\", connection = \"local\", model_id = \"reviewer-model\" }}\n\
         fallback = {{ mode = \"auto\", chain = [ {{ connection = \"local-second\", model_id = \"second\" }}, {{ connection = \"local\", model_id = \"first\" }} ] }}\n"
    );
    let style_row = format!(
        "[models.purposes.{STYLE}]\n\
         model = {{ mode = \"fixed\", connection = \"local-second\", model_id = \"style-model\" }}\n"
    );
    // The same two rows declared in both orders: an answer keyed by the row's
    // index would swap the two bindings, and the same move has to produce the
    // same answers either way.
    for (order, rows) in [
        ("the source row first", format!("{role_row}{style_row}")),
        ("the sibling row first", format!("{style_row}{role_row}")),
    ] {
        let document = format!("{HEADER}{rows}");
        let mut config = Config::parse_validated(&document).expect("an ordered chain is valid");
        let before = config.resolve_purpose(ROLE).expect("the pin resolves");
        assert_eq!(
            before.fallback, chain,
            "{order}: fixture: the purpose carries an ordered chain with the second connection first"
        );
        let style_before = config.resolve_purpose(STYLE).expect("the sibling resolves");
        let role_at = document
            .find(&format!("[models.purposes.{ROLE}]"))
            .expect("the source row is declared");
        let style_at = document
            .find(&format!("[models.purposes.{STYLE}]"))
            .expect("the sibling row is declared");
        assert_eq!(
            role_at < style_at,
            order == "the source row first",
            "{order}: fixture: the rows are declared in the order the case names"
        );

        let edit = config
            .rebind_purpose(ROLE, ASSESS_SECURITY)
            .expect("the binding moves")
            .expect("the source row exists");
        let bytes = String::from_utf8(edit.bytes).expect("edited TOML is utf-8");
        assert!(
            bytes.contains(&format!("[models.purposes.{ASSESS_SECURITY}]")),
            "{order}: the binding did not move in the document: {bytes}"
        );
        assert!(
            !bytes.contains(&format!("[models.purposes.{ROLE}]")),
            "{order}: the retired key stayed readable in the document: {bytes}"
        );

        // The binding moved by meaning: the chain keeps its own order and its
        // own entries, it is attributed to the migrated key, and the sibling
        // declared at the other index keeps its own answer.
        let moved = config.resolve_purpose(ASSESS_SECURITY).expect("resolves");
        assert_eq!(
            moved.fallback, chain,
            "{order}: the fallback order was rebuilt from position instead of meaning"
        );
        assert_eq!(
            moved.fallback_source,
            format!("models.purposes.{ASSESS_SECURITY}"),
            "{order}: the chain is not attributed to the migrated key: {moved:?}"
        );
        assert_eq!(
            config.resolve_purpose(STYLE).expect("resolves").fallback,
            style_before.fallback,
            "{order}: a sibling's chain moved with another row's document position"
        );
        assert_eq!(
            config
                .resolve_purpose(ROLE)
                .expect("resolves")
                .fallback_source,
            "models.defaults",
            "{order}: the retired key still answers a chain"
        );
    }
}

// ----- p2: a split routes each subject into one compatible part -----

#[test]
fn split_does_not_copy_the_delta_p2() {
    let grants = Grants::new("split");
    let policy_before = grants.read();

    let root = temp_root("split");
    let mut store = open_store(&root);
    verified(
        &mut store,
        &instruction("input-trust", INSTRUCTION_TEXT, ROLE),
        &instruction_corpus(ROLE),
    );
    verified(
        &mut store,
        &applicability("profile-route", ROLE),
        &applicability_corpus(),
    );
    assert_eq!(
        store
            .learning_definition()
            .expect("definition")
            .deltas()
            .len(),
        2,
        "fixture: two active experiences"
    );

    // The confirmed mapping: the role's instruction experience stays with the
    // security part, the action's selection experience moves to the tests part.
    let to_security = role_rule(ROLE, ASSESS_SECURITY, MigrationRule::Split, Some(ROLE));
    let to_tests = action_rule(ROLE, AUDIT_TESTS, MigrationRule::Split, Some(ROLE));
    store
        .record_identity_migration(&to_security)
        .expect("the role part records");
    store
        .record_identity_migration(&to_tests)
        .expect("the action part records");
    let report =
        cut_over(&mut store, &[to_security, to_tests]).expect("the split rebinds each subject");
    assert!(
        named_beyond_probe(&report).is_empty(),
        "the mapping confirmed both parts: {report:?}"
    );

    let trust = store.learning_delta("input-trust").expect("stored");
    assert_eq!(
        trust.change.when,
        Some(ConditionFact::Purpose(ASSESS_SECURITY.to_string())),
        "the instruction experience did not follow its part"
    );
    let route = store.learning_delta("profile-route").expect("stored");
    assert!(
        matches!(
            &route.change.payload,
            DeltaPayload::Applicability { capability, .. } if capability == AUDIT_TESTS
        ),
        "the selection experience did not follow its part: {route:?}"
    );
    assert_eq!(
        store
            .learning_definition()
            .expect("definition")
            .deltas()
            .len(),
        2,
        "the split copied an experience into a second row"
    );

    // The same read the two seams perform: only the compatible part carries it.
    let definition = store.learning_definition().expect("definition");
    assert!(
        definition
            .instruction_part(ASSESS_SECURITY, "base")
            .contains(INSTRUCTION_TEXT)
    );
    assert_eq!(
        definition.instruction_part(AUDIT_TESTS, "base"),
        "base",
        "the instruction experience was copied into the incompatible part"
    );
    assert_eq!(
        definition.applicability(AUDIT_TESTS, &selection_facts()),
        Some(PredicateEffect::Require),
        "the selection experience did not follow its part"
    );
    assert_eq!(
        definition.applicability(ASSESS_SECURITY, &selection_facts()),
        None,
        "the selection experience was copied into the incompatible part"
    );

    // Copying into both parts is not expressible: a second part claiming the
    // same subject is refused, and the refusal leaves the stored set alone.
    let second_action_part = action_rule(ROLE, DIAGNOSE_ISSUE, MigrationRule::Split, Some(ROLE));
    let refused = store
        .record_identity_migration(&second_action_part)
        .expect_err("two parts claiming one subject is the copy-to-both defect");
    assert!(
        matches!(refused, IdentityError::Ambiguous { .. }),
        "{refused}"
    );
    let rules = store.identity_rules().expect("rules");
    assert_eq!(rules.migrations().len(), 2, "the refused rule was recorded");
    assert!(
        rules
            .migrations()
            .iter()
            .all(|migration| migration.new_id != DIAGNOSE_ISSUE),
        "the refused rule is readable: {rules:?}"
    );
    let pure = IdentityRules::new(
        rivect::config::SHIPPED_BASE_VERSION,
        vec![
            role_rule(ROLE, ASSESS_SECURITY, MigrationRule::Split, Some(ROLE)),
            role_rule(ROLE, AUDIT_TESTS, MigrationRule::Split, Some(ROLE)),
        ],
    )
    .expect_err("a rule set cannot route one subject into two parts");
    assert!(matches!(pure, IdentityError::Ambiguous { .. }), "{pure}");

    // Order is not identity: the same two parts recorded the other way round
    // place each subject exactly where it was placed before.
    let reversed = IdentityRules::new(
        rivect::config::SHIPPED_BASE_VERSION,
        vec![
            action_rule(ROLE, AUDIT_TESTS, MigrationRule::Split, Some(ROLE)),
            role_rule(ROLE, ASSESS_SECURITY, MigrationRule::Split, Some(ROLE)),
        ],
    )
    .expect("the same parts in another record order");
    assert_eq!(
        reversed.place(IdentityKind::Role, ROLE),
        Placement::Rebound(ASSESS_SECURITY.to_string()),
        "the role's experience moved with the record order"
    );
    assert_eq!(
        reversed.place(IdentityKind::Action, ROLE),
        Placement::Rebound(AUDIT_TESTS.to_string()),
        "the action's experience moved with the record order"
    );

    assert_eq!(
        grants.read(),
        policy_before,
        "a split widened the effect policy"
    );
}

// ----- p2 pinned: one part per subject, and it takes the whole subject -----

#[test]
fn split_places_every_binding_of_one_subject() {
    let root = temp_root("split-subject");
    let mut store = open_store(&root);
    verified(
        &mut store,
        &instruction("input-trust", INSTRUCTION_TEXT, ROLE),
        &instruction_corpus(ROLE),
    );
    verified(
        &mut store,
        &instruction("route-trust", ROUTE_TEXT, ROLE),
        &instruction_corpus(ROLE),
    );
    assert_eq!(
        store
            .learning_definition()
            .expect("definition")
            .deltas()
            .len(),
        2,
        "fixture: two experiences recorded under one subject"
    );

    // The mapping states one target for the subject, so both of its
    // experiences move into that part: a release cannot say "this row here and
    // that row there", and leaving one behind would strand experience no later
    // rule could ever place.
    store
        .record_identity_migration(&role_rule(
            ROLE,
            ASSESS_SECURITY,
            MigrationRule::Split,
            Some(ROLE),
        ))
        .expect("the part records");
    let report = cut_over(
        &mut store,
        &[role_rule(
            ROLE,
            ASSESS_SECURITY,
            MigrationRule::Split,
            Some(ROLE),
        )],
    )
    .expect("the split places the subject it names");
    assert_eq!(
        report.rebound.len(),
        2,
        "the mapping states one target for the subject: {report:?}"
    );
    assert!(
        named_beyond_probe(&report).is_empty(),
        "the mapping confirmed the subject: {report:?}"
    );
    for delta_id in ["input-trust", "route-trust"] {
        assert_eq!(
            store.learning_delta(delta_id).expect("stored").change.when,
            Some(ConditionFact::Purpose(ASSESS_SECURITY.to_string())),
            "{delta_id} did not follow the subject it was recorded under"
        );
    }
    let definition = store.learning_definition().expect("definition");
    let part = definition.instruction_part(ASSESS_SECURITY, "base");
    assert!(
        part.contains(INSTRUCTION_TEXT) && part.contains(ROUTE_TEXT),
        "the part lost one of its subject's experiences: {part}"
    );
    assert_eq!(
        definition.instruction_part(DIAGNOSE_ISSUE, "base"),
        "base",
        "an experience was copied into a second part"
    );

    // A second part for the same subject is the shape that would split them, and
    // it is refused before any row moves.
    let second = role_rule(ROLE, DIAGNOSE_ISSUE, MigrationRule::Split, Some(ROLE));
    let refused = store
        .record_identity_migration(&second)
        .expect_err("one subject has one part");
    assert!(
        matches!(refused, IdentityError::Ambiguous { .. }),
        "{refused}"
    );
    assert_eq!(
        store.identity_rules().expect("rules").migrations().len(),
        1,
        "the refused part was recorded"
    );
}

// ----- p3: a merge keeps two independent reviewers independent -----

#[test]
fn merge_keeps_two_reviewers_independent_p3() {
    const STYLE: &str = "review_style";
    const TESTS: &str = "review_tests";
    let grants = Grants::new("merge");
    let policy_before = grants.read();

    let root = temp_root("merge");
    let mut store = open_store(&root);
    verified(
        &mut store,
        &instruction("style-rule", INSTRUCTION_TEXT, STYLE),
        &instruction_corpus(STYLE),
    );
    verified(
        &mut store,
        &instruction("tests-rule", ROUTE_TEXT, TESTS),
        &instruction_corpus(TESTS),
    );

    let style_rule = role_rule(STYLE, ROLE, MigrationRule::Merge, None);
    let tests_rule = role_rule(TESTS, ROLE, MigrationRule::Merge, None);
    store
        .record_identity_migration(&style_rule)
        .expect("the first reviewer merges");
    store
        .record_identity_migration(&tests_rule)
        .expect("the second reviewer merges");
    let report = cut_over(&mut store, &[style_rule, tests_rule]).expect("both reviewers rebind");
    assert_eq!(report.rebound.len(), 2, "both rows move: {report:?}");

    // Two rows, two conclusions: the merge does not collapse them into one.
    assert_eq!(
        store
            .learning_definition()
            .expect("definition")
            .deltas()
            .len(),
        2,
        "the merge collapsed two reviewers into one row"
    );
    let part = store
        .learning_definition()
        .expect("definition")
        .instruction_part(ROLE, "base");
    assert!(
        part.contains(INSTRUCTION_TEXT) && part.contains(ROUTE_TEXT),
        "the merged role lost one reviewer's conclusion: {part}"
    );

    // Independence survives activation state: one withdrawal keeps the other.
    let style = store.learning_delta("style-rule").expect("stored");
    assert_eq!(
        style.change.when,
        Some(ConditionFact::Purpose(ROLE.to_string())),
        "the first reviewer did not follow the merge"
    );
    store
        .roll_back_learning_delta("style-rule", style.version)
        .expect("one reviewer is withdrawn");
    assert_eq!(
        store.learning_delta("tests-rule").expect("stored").state,
        DeltaState::Active,
        "withdrawing one reviewer withdrew the other"
    );
    let part = store
        .learning_definition()
        .expect("definition")
        .instruction_part(ROLE, "base");
    assert!(
        !part.contains(INSTRUCTION_TEXT) && part.contains(ROUTE_TEXT),
        "the two reviewers are not independent: {part}"
    );

    // The pins of two reviewers do not collapse either: two different
    // bindings are refused, one identical binding replays.
    let mut conflicting = Config::parse_validated(&pinned_config(&[
        (ROLE, "merged-model"),
        (STYLE, "style-model"),
    ]))
    .expect("two pinned rows are valid");
    let refused = conflicting
        .rebind_purpose(STYLE, ROLE)
        .expect_err("two different pins do not collapse");
    assert!(
        matches!(refused.issue, ConfigIssue::ConflictingPurposeDefinitions),
        "{refused}"
    );
    assert!(
        conflicting.models.purposes.contains_key(STYLE)
            && conflicting.models.purposes.contains_key(ROLE),
        "the refused merge dropped a reviewer's binding"
    );
    let mut identical = Config::parse_validated(&pinned_config(&[
        (ROLE, "merged-model"),
        (STYLE, "merged-model"),
    ]))
    .expect("two pinned rows are valid");
    let edit = identical
        .rebind_purpose(STYLE, ROLE)
        .expect("an identical binding replays")
        .expect("the source row exists");
    let bytes = String::from_utf8(edit.bytes).expect("edited TOML is utf-8");
    assert!(
        !bytes.contains(&format!("[models.purposes.{STYLE}]")),
        "the merged-away key stayed readable: {bytes}"
    );
    assert!(
        bytes.contains(&format!("[models.purposes.{ROLE}]")),
        "the merged binding is not in the document: {bytes}"
    );

    assert_eq!(
        grants.read(),
        policy_before,
        "a merge widened the effect policy"
    );
}

// ----- a merge does not collapse conclusions that disagree -----

#[test]
fn merge_refuses_bindings_that_disagree() {
    let root = temp_root("merge-disagree");
    let mut store = open_store(&root);
    verified(
        &mut store,
        &applicability_with("require-tests", AUDIT_TESTS, PredicateEffect::Require),
        &applicability_corpus(),
    );
    verified(
        &mut store,
        &applicability_with("decline-diagnose", DIAGNOSE_ISSUE, PredicateEffect::Decline),
        &applicability_corpus(),
    );

    store
        .record_identity_migration(&action_rule(AUDIT_TESTS, ROLE, MigrationRule::Merge, None))
        .expect("the first capability merges");
    store
        .record_identity_migration(&action_rule(
            DIAGNOSE_ISSUE,
            ROLE,
            MigrationRule::Merge,
            None,
        ))
        .expect("the second capability merges");
    let refused = cut_over(
        &mut store,
        &[
            action_rule(AUDIT_TESTS, ROLE, MigrationRule::Merge, None),
            action_rule(DIAGNOSE_ISSUE, ROLE, MigrationRule::Merge, None),
        ],
    )
    .expect_err("a merge cannot leave require and decline on one capability");
    assert!(
        matches!(
            &refused,
            IdentityError::ConflictingBindings {
                kind: IdentityKind::Action,
                subject,
                first,
                second,
            } if subject.as_str() == ROLE
                && matches!((*first, *second), ("require", "decline") | ("decline", "require"))
        ),
        "{refused}"
    );
    assert_eq!(
        refused.code(),
        ErrorCode::Conflict,
        "a refused merge reports a conflict"
    );
    // The refused pass wrote nothing: both conclusions stay under the
    // capability that recorded them, at the version their activation left.
    for (delta_id, capability) in [
        ("require-tests", AUDIT_TESTS),
        ("decline-diagnose", DIAGNOSE_ISSUE),
    ] {
        let held = store.learning_delta(delta_id).expect("stored");
        assert!(
            matches!(&held.change.payload, DeltaPayload::Applicability { capability: named, .. } if named == capability),
            "{delta_id} moved under a refused pass: {held:?}"
        );
        assert_eq!(
            held.state,
            DeltaState::Active,
            "a refused pass changed {delta_id}"
        );
    }
    let versions = [
        store
            .learning_delta("require-tests")
            .expect("stored")
            .version,
        store
            .learning_delta("decline-diagnose")
            .expect("stored")
            .version,
    ];
    assert_eq!(
        versions,
        [2, 2],
        "fixture: one recorded version and one activation version"
    );

    // The refusal is the disagreement, not the merge: two conclusions that agree
    // merge onto one capability and keep answering it.
    let root = temp_root("merge-agree");
    let mut agree = open_store(&root);
    verified(
        &mut agree,
        &applicability("require-tests", AUDIT_TESTS),
        &applicability_corpus(),
    );
    verified(
        &mut agree,
        &applicability("require-review", REVIEW_CHANGE),
        &applicability_corpus(),
    );
    agree
        .record_identity_migration(&action_rule(
            AUDIT_TESTS,
            DIAGNOSE_ISSUE,
            MigrationRule::Merge,
            None,
        ))
        .expect("the first capability merges");
    agree
        .record_identity_migration(&action_rule(
            REVIEW_CHANGE,
            DIAGNOSE_ISSUE,
            MigrationRule::Merge,
            None,
        ))
        .expect("the second capability merges");
    let report = cut_over(
        &mut agree,
        &[
            action_rule(AUDIT_TESTS, DIAGNOSE_ISSUE, MigrationRule::Merge, None),
            action_rule(REVIEW_CHANGE, DIAGNOSE_ISSUE, MigrationRule::Merge, None),
        ],
    )
    .expect("two conclusions that agree merge");
    assert_eq!(report.rebound.len(), 2, "both rows move: {report:?}");
    assert_eq!(
        agree
            .learning_definition()
            .expect("definition")
            .applicability(DIAGNOSE_ISSUE, &selection_facts()),
        Some(PredicateEffect::Require),
        "the merged capability lost the conclusion both rows agreed on"
    );
}

// ----- only the conclusions the definition composes are judged -----

#[test]
fn withdrawn_conclusion_does_not_block_a_move() {
    let root = temp_root("withdrawn-conclusion");
    let mut store = open_store(&root);
    verified(
        &mut store,
        &applicability_with("require-audit", AUDIT_TESTS, PredicateEffect::Require),
        &applicability_corpus(),
    );
    verified(
        &mut store,
        &applicability_with("decline-audit", AUDIT_TESTS, PredicateEffect::Decline),
        &applicability_corpus(),
    );
    // One of the two conclusions is withdrawn before the capability moves: a
    // rolled-back delta is not in the definition, so the pass leaves one
    // conclusion on the capability and has nothing to refuse. This is the
    // recovery the refusal names, run end to end (AC-056).
    let withdrawn = store
        .learning_delta("decline-audit")
        .expect("stored")
        .version;
    store
        .roll_back_learning_delta("decline-audit", withdrawn)
        .expect("one conclusion is withdrawn");

    store
        .record_identity_migration(&action_rule(
            AUDIT_TESTS,
            DIAGNOSE_ISSUE,
            MigrationRule::Rename,
            None,
        ))
        .expect("the capability renames");
    let report = cut_over(
        &mut store,
        &[action_rule(
            AUDIT_TESTS,
            DIAGNOSE_ISSUE,
            MigrationRule::Rename,
            None,
        )],
    )
    .expect("one conclusion on the capability is not a disagreement");
    assert_eq!(
        report.rebound.len(),
        2,
        "both rows follow the capability, the withdrawn one included: {report:?}"
    );
    for delta_id in ["require-audit", "decline-audit"] {
        let held = store.learning_delta(delta_id).expect("stored");
        assert!(
            matches!(&held.change.payload, DeltaPayload::Applicability { capability: named, .. } if named == DIAGNOSE_ISSUE),
            "{delta_id} did not follow the rename: {held:?}"
        );
    }
    assert_eq!(
        store.learning_delta("require-audit").expect("stored").state,
        DeltaState::Active,
        "a move wrote a state it does not own"
    );
    assert_eq!(
        store.learning_delta("decline-audit").expect("stored").state,
        DeltaState::RolledBack,
        "the move re-activated a withdrawn experience"
    );
    assert_eq!(
        store
            .learning_definition()
            .expect("definition")
            .applicability(DIAGNOSE_ISSUE, &selection_facts()),
        Some(PredicateEffect::Require),
        "the capability the rename left lost its one conclusion"
    );
}

// ----- conclusions one request can never hold at once are not a disagreement -----

#[test]
fn conclusions_on_different_kinds_do_not_block_a_move() {
    let root = temp_root("kind-conclusions");
    let mut store = open_store(&root);
    let audit_facts = selection_facts();
    let change_facts = ConditionFacts::for_selection(
        RequestKind::Change,
        Some(BTreeSet::from([Surface::PublicApi])),
    );
    verified(
        &mut store,
        &applicability_on(
            "require-audit",
            AUDIT_TESTS,
            PredicateEffect::Require,
            ConditionFact::Kind(RequestKind::Audit),
        ),
        &applicability_corpus_on(&audit_facts),
    );
    verified(
        &mut store,
        &applicability_on(
            "decline-change",
            AUDIT_TESTS,
            PredicateEffect::Decline,
            ConditionFact::Kind(RequestKind::Change),
        ),
        &applicability_corpus_on(&change_facts),
    );
    store
        .record_identity_migration(&action_rule(
            AUDIT_TESTS,
            DIAGNOSE_ISSUE,
            MigrationRule::Rename,
            None,
        ))
        .expect("the capability renames");
    let report = cut_over(
        &mut store,
        &[action_rule(
            AUDIT_TESTS,
            DIAGNOSE_ISSUE,
            MigrationRule::Rename,
            None,
        )],
    )
    .expect("two conclusions no one request holds at once do not disagree");
    assert_eq!(
        report.rebound.len(),
        2,
        "both conclusions follow the capability: {report:?}"
    );
    let definition = store.learning_definition().expect("definition");
    assert_eq!(
        definition.applicability(DIAGNOSE_ISSUE, &audit_facts),
        Some(PredicateEffect::Require),
        "the audited request lost the conclusion its own facts read"
    );
    assert_eq!(
        definition.applicability(DIAGNOSE_ISSUE, &change_facts),
        Some(PredicateEffect::Decline),
        "the changing request lost the conclusion its own facts read"
    );

    // The condition decides whether two conclusions meet, never whether they
    // exist: a surface-conditioned require and a kind-conditioned decline both
    // hold for an audited request carrying that surface, so they disagree and
    // the move is refused with nothing written.
    let root = temp_root("mixed-conclusions");
    let mut mixed = open_store(&root);
    verified(
        &mut mixed,
        &applicability_with("require-audit", AUDIT_TESTS, PredicateEffect::Require),
        &applicability_corpus(),
    );
    verified(
        &mut mixed,
        &applicability_on(
            "decline-audit",
            AUDIT_TESTS,
            PredicateEffect::Decline,
            ConditionFact::Kind(RequestKind::Audit),
        ),
        &applicability_corpus_on(&audit_facts),
    );
    mixed
        .record_identity_migration(&action_rule(
            AUDIT_TESTS,
            DIAGNOSE_ISSUE,
            MigrationRule::Rename,
            None,
        ))
        .expect("the capability renames");
    let refused = cut_over(
        &mut mixed,
        &[action_rule(
            AUDIT_TESTS,
            DIAGNOSE_ISSUE,
            MigrationRule::Rename,
            None,
        )],
    )
    .expect_err("the two conclusions meet on an audited request");
    assert!(
        matches!(
            &refused,
            IdentityError::ConflictingBindings {
                kind: IdentityKind::Action,
                subject,
                first,
                second,
            } if subject.as_str() == DIAGNOSE_ISSUE
                && matches!((*first, *second), ("require", "decline") | ("decline", "require"))
        ),
        "{refused}"
    );
    for delta_id in ["require-audit", "decline-audit"] {
        let held = mixed.learning_delta(delta_id).expect("stored");
        assert!(
            matches!(&held.change.payload, DeltaPayload::Applicability { capability: named, .. } if named == AUDIT_TESTS),
            "{delta_id} moved under a refused pass: {held:?}"
        );
        assert_eq!(
            held.version, 2,
            "a refused pass rewrote {delta_id} past its recorded and activated versions"
        );
    }
}

// ----- the disagreement a move lands is judged, even when one member moves -----

#[test]
fn one_moved_conclusion_still_disagrees() {
    let root = temp_root("one-moved");
    let mut store = open_store(&root);
    verified(
        &mut store,
        &applicability_with("require-tests", AUDIT_TESTS, PredicateEffect::Require),
        &applicability_corpus(),
    );
    verified(
        &mut store,
        &applicability_with("decline-diagnose", DIAGNOSE_ISSUE, PredicateEffect::Decline),
        &applicability_corpus(),
    );

    // Only one member of the pair moves: the rule renames the audited capability
    // onto the one that already answers a different conclusion, and no rule names
    // that one. The two would end up on one capability answering a public-api
    // audit both can hold, so the pass is refused although a single row moves.
    store
        .record_identity_migration(&action_rule(
            AUDIT_TESTS,
            DIAGNOSE_ISSUE,
            MigrationRule::Rename,
            None,
        ))
        .expect("the audited capability renames");
    let refused = cut_over(
        &mut store,
        &[action_rule(
            AUDIT_TESTS,
            DIAGNOSE_ISSUE,
            MigrationRule::Rename,
            None,
        )],
    )
    .expect_err("one moved conclusion is enough to land a disagreement");
    assert!(
        matches!(
            &refused,
            IdentityError::ConflictingBindings {
                kind: IdentityKind::Action,
                subject,
                first,
                second,
            } if subject.as_str() == DIAGNOSE_ISSUE
                && matches!((*first, *second), ("require", "decline") | ("decline", "require"))
        ),
        "{refused}"
    );
    assert_eq!(
        refused.code(),
        ErrorCode::Conflict,
        "a disagreement a move lands reports a conflict"
    );
    // Nothing was written: the mover keeps its capability and the row it would
    // have landed on is untouched.
    for (delta_id, capability) in [
        ("require-tests", AUDIT_TESTS),
        ("decline-diagnose", DIAGNOSE_ISSUE),
    ] {
        let held = store.learning_delta(delta_id).expect("stored");
        assert!(
            matches!(&held.change.payload, DeltaPayload::Applicability { capability: named, .. } if named == capability),
            "{delta_id} moved under a refused pass: {held:?}"
        );
        assert_eq!(
            held.version, 2,
            "a refused pass rewrote {delta_id} past its recorded and activated versions"
        );
        assert_eq!(
            held.state,
            DeltaState::Active,
            "a refused pass changed {delta_id}"
        );
    }

    // The refusal is the disagreement, not the partial shape: one moved
    // conclusion landing beside an agreeing one commits, and both rows end where
    // the rules leave them — the mover under the capability its rule names, the
    // row it landed beside exactly where it was recorded.
    let root = temp_root("one-moved-agree");
    let mut agree = open_store(&root);
    verified(
        &mut agree,
        &applicability_with("require-tests", AUDIT_TESTS, PredicateEffect::Require),
        &applicability_corpus(),
    );
    verified(
        &mut agree,
        &applicability_with("require-review", REVIEW_CHANGE, PredicateEffect::Require),
        &applicability_corpus(),
    );
    let before = agree
        .learning_definition()
        .expect("definition")
        .applicability(REVIEW_CHANGE, &selection_facts());
    assert_eq!(
        before,
        Some(PredicateEffect::Require),
        "fixture: the capability the move lands on answers its own conclusion"
    );
    agree
        .record_identity_migration(&action_rule(
            AUDIT_TESTS,
            REVIEW_CHANGE,
            MigrationRule::Rename,
            None,
        ))
        .expect("the audited capability renames onto the reviewed one");
    let report = cut_over(
        &mut agree,
        &[action_rule(
            AUDIT_TESTS,
            REVIEW_CHANGE,
            MigrationRule::Rename,
            None,
        )],
    )
    .expect("one moved conclusion that agrees is not a disagreement");
    assert_eq!(
        report.rebound.len(),
        1,
        "only the renamed row moves: {report:?}"
    );
    assert!(
        report
            .unassigned
            .iter()
            .any(|named| named.kind == IdentityKind::Action && named.subject == REVIEW_CHANGE),
        "the capability no rule claims was not named for reconciliation: {report:?}"
    );
    for delta_id in ["require-tests", "require-review"] {
        let held = agree.learning_delta(delta_id).expect("stored");
        assert!(
            matches!(&held.change.payload, DeltaPayload::Applicability { capability, .. } if capability == REVIEW_CHANGE),
            "{delta_id} did not end under the capability the rules leave it on: {held:?}"
        );
        assert_eq!(
            held.state,
            DeltaState::Active,
            "the move wrote a state it does not own"
        );
    }
    assert_eq!(
        agree
            .learning_delta("require-review")
            .expect("stored")
            .version,
        2,
        "the row the move landed beside was rewritten"
    );
    assert_eq!(
        agree
            .learning_delta("require-tests")
            .expect("stored")
            .version,
        3,
        "the moved row's version did not advance with its binding"
    );
    assert_eq!(
        agree
            .learning_definition()
            .expect("definition")
            .applicability(REVIEW_CHANGE, &selection_facts()),
        before,
        "the capability the partial merge landed answers a different conclusion"
    );
}

#[test]
fn second_moved_conclusion_still_disagrees() {
    let root = temp_root("second-moved");
    let mut store = open_store(&root);
    // The pair above, recorded the other way round: the definition reads these
    // conclusions in record order, so here the member the rule moves is the
    // second one read. The disagreement is a property of the pair, not of the
    // position the move lands in, so this pass is refused as well.
    verified(
        &mut store,
        &applicability_with("decline-diagnose", DIAGNOSE_ISSUE, PredicateEffect::Decline),
        &applicability_corpus(),
    );
    verified(
        &mut store,
        &applicability_with("require-tests", AUDIT_TESTS, PredicateEffect::Require),
        &applicability_corpus(),
    );
    store
        .record_identity_migration(&action_rule(
            AUDIT_TESTS,
            DIAGNOSE_ISSUE,
            MigrationRule::Rename,
            None,
        ))
        .expect("the audited capability renames");
    let refused = cut_over(
        &mut store,
        &[action_rule(
            AUDIT_TESTS,
            DIAGNOSE_ISSUE,
            MigrationRule::Rename,
            None,
        )],
    )
    .expect_err("a moved conclusion disagrees whichever member of the pair it is");
    assert!(
        matches!(
            &refused,
            IdentityError::ConflictingBindings {
                kind: IdentityKind::Action,
                subject,
                first,
                second,
            } if subject.as_str() == DIAGNOSE_ISSUE
                && matches!((*first, *second), ("require", "decline") | ("decline", "require"))
        ),
        "{refused}"
    );
    assert_eq!(
        refused.code(),
        ErrorCode::Conflict,
        "a disagreement a move lands reports a conflict"
    );
    // Nothing was written: the mover keeps its capability and the row it would
    // have landed on is untouched.
    for (delta_id, capability) in [
        ("decline-diagnose", DIAGNOSE_ISSUE),
        ("require-tests", AUDIT_TESTS),
    ] {
        let held = store.learning_delta(delta_id).expect("stored");
        assert!(
            matches!(&held.change.payload, DeltaPayload::Applicability { capability: named, .. } if named == capability),
            "{delta_id} moved under a refused pass: {held:?}"
        );
        assert_eq!(
            held.version, 2,
            "a refused pass rewrote {delta_id} past its recorded and activated versions"
        );
        assert_eq!(
            held.state,
            DeltaState::Active,
            "a refused pass changed {delta_id}"
        );
    }
}

// ----- a pair the pass leaves alone keeps serving; a pair it moves is judged -----

#[test]
fn untouched_disagreeing_pair_survives_an_unrelated_move() {
    let root = temp_root("untouched-pair");
    let mut store = open_store(&root);
    // Two conclusions the store already holds under one capability. Activation
    // admits both, so the definition carries a disagreement this build has no
    // rule to remove: it answers the last of the two, and the pass below is the
    // one path that could still move them.
    verified(
        &mut store,
        &applicability_with("require-audit", AUDIT_TESTS, PredicateEffect::Require),
        &applicability_corpus(),
    );
    verified(
        &mut store,
        &applicability_with("decline-audit", AUDIT_TESTS, PredicateEffect::Decline),
        &applicability_corpus(),
    );
    verified(
        &mut store,
        &instruction("route-trust", ROUTE_TEXT, ROLE),
        &instruction_corpus(ROLE),
    );
    let held = store
        .learning_definition()
        .expect("definition")
        .applicability(AUDIT_TESTS, &selection_facts());
    assert!(
        matches!(
            held,
            Some(PredicateEffect::Require | PredicateEffect::Decline)
        ),
        "fixture: the stored pair answers the audited request: {held:?}"
    );

    // An unrelated rename: the instruction experience moves, the pair does not,
    // so the pass commits instead of refusing a disagreement it did not make.
    store
        .record_identity_migration(&role_rule(
            ROLE,
            ASSESS_SECURITY,
            MigrationRule::Rename,
            None,
        ))
        .expect("the purpose renames");
    let report = cut_over(
        &mut store,
        &[role_rule(
            ROLE,
            ASSESS_SECURITY,
            MigrationRule::Rename,
            None,
        )],
    )
    .expect("a pair the pass leaves where it found it is not judged");
    assert_eq!(
        report.rebound.len(),
        1,
        "only the renamed row moves: {report:?}"
    );
    assert_eq!(
        store
            .learning_delta("route-trust")
            .expect("stored")
            .change
            .when,
        Some(ConditionFact::Purpose(ASSESS_SECURITY.to_string())),
        "the unrelated move did not commit"
    );
    for delta_id in ["require-audit", "decline-audit"] {
        let pair = store.learning_delta(delta_id).expect("stored");
        assert!(
            matches!(&pair.change.payload, DeltaPayload::Applicability { capability, .. } if capability == AUDIT_TESTS),
            "{delta_id} moved with an unrelated rule: {pair:?}"
        );
        assert_eq!(pair.version, 2, "the untouched pair was rewritten");
        assert_eq!(
            pair.state,
            DeltaState::Active,
            "the pass changed the pair's state"
        );
    }
    assert_eq!(
        store
            .learning_definition()
            .expect("definition")
            .applicability(AUDIT_TESTS, &selection_facts()),
        held,
        "the untouched pair answers a different conclusion after the pass"
    );

    // The tolerance is the pass's own silence, never the shape: once a rule moves
    // one of the pair, the same disagreement is refused with nothing written,
    // and the move the store already committed stays.
    store
        .record_identity_migration(&action_rule(
            AUDIT_TESTS,
            DIAGNOSE_ISSUE,
            MigrationRule::Rename,
            None,
        ))
        .expect("the audited capability renames");
    let refused = cut_over(
        &mut store,
        &[action_rule(
            AUDIT_TESTS,
            DIAGNOSE_ISSUE,
            MigrationRule::Rename,
            None,
        )],
    )
    .expect_err("a pair the rules move and that disagrees is refused");
    assert!(
        matches!(
            &refused,
            IdentityError::ConflictingBindings {
                kind: IdentityKind::Action,
                subject,
                first,
                second,
            } if subject.as_str() == DIAGNOSE_ISSUE
                && matches!((*first, *second), ("require", "decline") | ("decline", "require"))
        ),
        "{refused}"
    );
    for delta_id in ["require-audit", "decline-audit"] {
        let pair = store.learning_delta(delta_id).expect("stored");
        assert!(
            matches!(&pair.change.payload, DeltaPayload::Applicability { capability, .. } if capability == AUDIT_TESTS),
            "{delta_id} moved under a refused pass: {pair:?}"
        );
        assert_eq!(pair.version, 2, "a refused pass rewrote {delta_id}");
    }
    assert_eq!(
        store
            .learning_delta("route-trust")
            .expect("stored")
            .change
            .when,
        Some(ConditionFact::Purpose(ASSESS_SECURITY.to_string())),
        "a refused pass undid the move the store had committed"
    );
}

// ----- a rebinding is measured before it commits -----

#[test]
fn rebind_refuses_a_definition_past_the_bound() {
    let root = temp_root("rebind-bound");
    let mut store = open_store(&root);
    // Two maximal bodies, each verified and activated alone: on their own
    // purposes they compose inside the bound, which the activations below prove.
    const FILLER: &str = "the merged purpose keeps the reasoning of both reviewers intact ";
    let body = FILLER
        .repeat(DELTA_INSTRUCTION_MAX_BYTES / FILLER.len() + 1)
        .as_bytes()[..DELTA_INSTRUCTION_MAX_BYTES]
        .to_vec();
    let body = String::from_utf8(body).expect("the filler is ascii");
    verified(
        &mut store,
        &instruction("style-rule", &body, "review_style"),
        &instruction_corpus("review_style"),
    );
    verified(
        &mut store,
        &instruction("tests-rule", &body, "review_tests"),
        &instruction_corpus("review_tests"),
    );

    // The merge lands both bodies on one purpose. Activation measures the
    // definition it composes, and the cutover measures it too: a merge that
    // commits here would ship an assembled part past the bound.
    let refused = cut_over(
        &mut store,
        &[
            role_rule("review_style", ROLE, MigrationRule::Merge, None),
            role_rule("review_tests", ROLE, MigrationRule::Merge, None),
        ],
    )
    .expect_err("the merged part is past the definition bound");
    assert!(
        matches!(
            &refused,
            IdentityError::CompositionExceeded { size, limit, .. }
                if *size > *limit && *limit == DEFINITION_MAX_BYTES
        ),
        "{refused}"
    );
    assert_eq!(
        refused.code(),
        ErrorCode::Conflict,
        "an over-bound rebinding reports a conflict"
    );
    for (delta_id, purpose) in [
        ("style-rule", "review_style"),
        ("tests-rule", "review_tests"),
    ] {
        let held = store.learning_delta(delta_id).expect("stored");
        assert_eq!(
            held.change.when,
            Some(ConditionFact::Purpose(purpose.to_string())),
            "{delta_id} moved under a refused pass"
        );
        assert_eq!(
            held.version, 2,
            "a refused pass rewrote {delta_id} past its recorded and activated versions"
        );
        assert_eq!(
            held.state,
            DeltaState::Active,
            "a refused pass changed {delta_id}"
        );
    }
}

// ----- a pass that moves nothing is not measured -----

#[test]
fn pass_without_moves_keeps_serving_past_the_bound() {
    let root = temp_root("rebind-past-bound");
    let path = root.path().join("state.db");
    let mut store = open_store(&root);
    verified(
        &mut store,
        &instruction("style-rule", INSTRUCTION_TEXT, "review_style"),
        &instruction_corpus("review_style"),
    );
    // A row another build wrote under a larger delta bound: this build's own
    // writes cannot compose it (every activation measures the definition), so
    // the fixture writes the body straight to the row instead of asking an
    // activation this build refuses.
    const FILLER: &str = "an oversized body another build wrote past the shipped delta bound ";
    let body = FILLER
        .repeat(2 * DELTA_INSTRUCTION_MAX_BYTES / FILLER.len() + 1)
        .as_bytes()[..2 * DELTA_INSTRUCTION_MAX_BYTES]
        .to_vec();
    let body = String::from_utf8(body).expect("the filler is ascii");
    drop(store);
    {
        let database = rusqlite::Connection::open(&path).expect("raw store");
        let written = database
            .execute(
                "UPDATE learning_deltas SET instruction = ?2 WHERE delta_id = ?1",
                rusqlite::params!["style-rule", body],
            )
            .expect("the oversized body lands");
        assert_eq!(written, 1, "fixture: one row carries the oversized body");
    }
    let mut store = open_store(&root);
    let carried = store
        .learning_definition()
        .expect("definition")
        .instruction_part("review_style", "")
        .len();
    assert!(
        carried > DEFINITION_MAX_BYTES,
        "fixture: the store sits at {carried} bytes, over the {DEFINITION_MAX_BYTES}-byte bound"
    );

    // A rule set that places no row moves nothing, so the definition the pass
    // leaves is the one it read: a store already past the bound keeps serving
    // instead of refusing every later pass.
    let report = cut_over(&mut store, &[])
        .expect("a pass that moves nothing keeps serving a store past the bound");
    assert!(
        report.rebound.is_empty(),
        "fixture: an empty rule set moves no row: {report:?}"
    );
    assert_eq!(
        store
            .learning_definition()
            .expect("definition")
            .instruction_part("review_style", "")
            .len(),
        carried,
        "the pass changed a definition it left unmeasured"
    );

    // The same store, moved: the bound is the reason the pass refuses, not the
    // store's own state.
    let refused = cut_over(
        &mut store,
        &[role_rule("review_style", ROLE, MigrationRule::Rename, None)],
    )
    .expect_err("a move leaves the body on a purpose past the bound");
    assert!(
        matches!(
            &refused,
            IdentityError::CompositionExceeded { size, limit, .. }
                if *size > *limit && *limit == DEFINITION_MAX_BYTES
        ),
        "{refused}"
    );
    let held = store.learning_delta("style-rule").expect("stored");
    assert_eq!(
        held.change.when,
        Some(ConditionFact::Purpose("review_style".to_string())),
        "a refused pass moved the row"
    );
    assert_eq!(
        held.version, 2,
        "a refused pass rewrote the row past its recorded and activated versions"
    );
}

// ----- p4: the user's namespace cannot be claimed by a release -----

#[test]
fn personal_namespace_is_not_captured_p4() {
    let grants = Grants::new("personal");
    let policy_before = grants.read();

    // The guard reads the namespace, folded and at a segment boundary: a word
    // that merely contains the letters is not a claim.
    assert!(claims_personal_namespace("personal:mine"));
    assert!(claims_personal_namespace("Personal:Mine"));
    assert!(claims_personal_namespace("role:personal:audit"));
    assert!(!claims_personal_namespace("personal"));
    assert!(!claims_personal_namespace("my-personal:thing"));

    // The user keeps the namespace: their own purpose row stays valid.
    let user = Config::parse_validated(&support::config_learned_role())
        .expect("a user's own personal id is theirs");
    assert!(
        user.models.purposes.contains_key("personal:api-review"),
        "the guard captured the user's own namespace"
    );

    // A release base may not claim it: the base document is a config document
    // and is refused typed before any value is served.
    let base_document = "config_version = 1\n\
         [models.defaults]\n\
         model = { mode = \"auto\" }\n\
         effort = { mode = \"auto\" }\n\
         fallback = { mode = \"auto\" }\n\
         [models.purposes.\"personal:api-review\"]\n\
         model = { mode = \"inherit\" }\n";
    let base = BaseSource::new(2, base_document);
    let refused = resolve_effective_on(base, None)
        .expect_err("a base document may not claim the user's namespace");
    assert!(
        matches!(
            &refused.issue,
            ConfigIssue::PersonalNamespaceClaimed { id } if id == "personal:api-review"
        ),
        "{refused}"
    );

    // A migration rule may not claim it either, in either direction.
    let root = temp_root("personal");
    let mut store = open_store(&root);
    for claim in ["personal:mine", "Role:Personal:Mine"] {
        let rule = role_rule(claim, ASSESS_SECURITY, MigrationRule::Rename, None);
        let refused = store
            .record_identity_migration(&rule)
            .expect_err("a release rule may not name the user's namespace");
        assert!(
            matches!(&refused, IdentityError::PersonalNamespace { id } if id == claim),
            "{refused}"
        );
    }
    let claimed = role_rule(ROLE, "personal:mine", MigrationRule::Rename, None);
    let refused = store
        .record_identity_migration(&claimed)
        .expect_err("a release rule may not capture the user's namespace");
    assert!(
        matches!(&refused, IdentityError::PersonalNamespace { id } if id == "personal:mine"),
        "{refused}"
    );
    assert!(
        store
            .identity_rules()
            .expect("rules")
            .migrations()
            .is_empty(),
        "a refused rule was recorded anyway"
    );

    // The user's own experience keeps its name: nothing in the refused run
    // touched a row bound to it.
    store
        .record_learning_delta(&instruction(
            "personal-rule",
            INSTRUCTION_TEXT,
            "personal:mine",
        ))
        .expect("the user's own delta records");
    let report = cut_over(&mut store, &[]).expect("an empty rule set rebinds nothing");
    assert!(report.rebound.is_empty(), "the empty set moved a row");
    let personal = store.learning_delta("personal-rule").expect("stored");
    assert_eq!(
        personal.change.when,
        Some(ConditionFact::Purpose("personal:mine".to_string())),
        "the user's own binding was reassigned"
    );

    assert_eq!(
        grants.read(),
        policy_before,
        "the namespace guard widened the effect policy"
    );
}

// ----- p5: a migration never widens grants -----

#[test]
fn grants_are_not_widened_p5() {
    let mut grants = Grants::new("grants");
    let before = grants.read();
    assert!(before.covers_enrolled, "fixture: the deny path is covered");
    assert!(!before.covers_free, "fixture: the sibling path is free");
    assert_eq!(
        before.grants,
        vec![("grant-1".to_string(), vec![EffectClass::Read], false)],
        "fixture: the runtime holds one read grant and no other"
    );

    let root = temp_root("grants");
    let mut store = open_store(&root);
    verified(
        &mut store,
        &instruction("keeper", INSTRUCTION_TEXT, ROLE),
        &instruction_corpus(ROLE),
    );
    let mut config = Config::parse_validated(&pinned_config(&[(ROLE, "reviewer-model")]))
        .expect("a pinned purpose row is valid");

    // p1's shape: a rename.
    store
        .record_identity_migration(&role_rule(
            ROLE,
            ASSESS_SECURITY,
            MigrationRule::Rename,
            None,
        ))
        .expect("rename records");
    cut_over(
        &mut store,
        &[role_rule(
            ROLE,
            ASSESS_SECURITY,
            MigrationRule::Rename,
            None,
        )],
    )
    .expect("rename rebinds");
    config
        .rebind_purpose(ROLE, ASSESS_SECURITY)
        .expect("the pin moves");
    assert_eq!(
        grants.read(),
        before,
        "the rename minted a grant or moved the deny set"
    );

    // p2's shape: a split into two confirmed parts.
    let root_split = temp_root("grants-split");
    let mut split_store = open_store(&root_split);
    verified(
        &mut split_store,
        &applicability("profile-route", ASSESS_SECURITY),
        &applicability_corpus(),
    );
    split_store
        .record_identity_migration(&action_rule(
            ASSESS_SECURITY,
            AUDIT_TESTS,
            MigrationRule::Split,
            Some(ASSESS_SECURITY),
        ))
        .expect("split records");
    cut_over(
        &mut split_store,
        &[action_rule(
            ASSESS_SECURITY,
            AUDIT_TESTS,
            MigrationRule::Split,
            Some(ASSESS_SECURITY),
        )],
    )
    .expect("split rebinds");
    assert_eq!(
        grants.read(),
        before,
        "the split minted a grant or moved the deny set"
    );

    // p3's shape: a merge of two roles.
    let root_merge = temp_root("grants-merge");
    let mut merge_store = open_store(&root_merge);
    merge_store
        .record_identity_migration(&role_rule("review_style", ROLE, MigrationRule::Merge, None))
        .expect("merge records");
    cut_over(
        &mut merge_store,
        &[role_rule("review_style", ROLE, MigrationRule::Merge, None)],
    )
    .expect("merge rebinds");
    assert_eq!(
        grants.read(),
        before,
        "the merge minted a grant or moved the deny set"
    );

    // No grant was minted by any of the three rounds: the next id the writer
    // mints is the one the fixture left behind, and the registry above already
    // reads every live id.
    let minted = {
        let mut writer = grants.world.runtime.policy_writer();
        writer.grant_read(PathBuf::from("/world/identity/next"))
    };
    assert_eq!(minted, "grant-2", "a migration consumed a grant id");

    // The read is discriminating, not a return of what the fixture wrote: the
    // control below mints a write grant and enrolls a second deny through the
    // same production writer, and both halves of the read move.
    let free = grants.free.clone();
    {
        let mut writer = grants.world.runtime.policy_writer();
        assert_eq!(
            writer.grant_classes(
                PathBuf::from("/world/identity/widened"),
                vec![EffectClass::Write]
            ),
            "grant-3",
            "the writer mints ids in one sequence"
        );
        writer
            .enroll_deny(&free)
            .expect("the control enrolls a deny");
    }
    let control = grants.read();
    assert_ne!(
        control, before,
        "the policy read cannot observe a minted grant or an enrolled deny"
    );
    assert!(
        control.covers_free,
        "the control's deny is not in the read: {control:?}"
    );
    assert!(
        control
            .grants
            .contains(&("grant-3".to_string(), vec![EffectClass::Write], false)),
        "the control's write grant is not in the registry read: {control:?}"
    );

    // The fixture grant still admits only the class it was minted for.
    assert!(
        matches!(
            grants
                .world
                .runtime
                .policy()
                .admit("grant-1", EffectClass::Write),
            Err(PolicyError::ClassNotAdmitted { .. })
        ),
        "a migration widened the granted classes"
    );
    assert!(
        grants
            .world
            .runtime
            .policy()
            .admit("grant-1", EffectClass::Read)
            .is_ok(),
        "the minted grant lost the class it was minted for"
    );
}

// ----- p6: an unknown id stays named and an unknown field survives -----

#[test]
fn unknown_id_stays_unassigned_and_unknown_fields_survive_p6() {
    let grants = Grants::new("unknown");
    let policy_before = grants.read();

    let root = temp_root("unknown");
    let mut store = open_store(&root);
    store
        .record_learning_delta(&instruction("known", INSTRUCTION_TEXT, ROLE))
        .expect("a known subject records");
    store
        .record_learning_delta(&instruction("retired", ROUTE_TEXT, "retired_role"))
        .expect("an unknown subject records");
    // An experience whose body looks executable and whose subject no release
    // names: it must stay exactly as recorded and never compose.
    store
        .record_learning_delta(&instruction(
            "unplaced-body",
            "run sh -c 'touch /world/executed' before reporting",
            "retired_role",
        ))
        .expect("an unknown subject's body records");
    let retired_before = store.learning_delta("retired").expect("stored");

    store
        .record_identity_migration(&role_rule(
            ROLE,
            ASSESS_SECURITY,
            MigrationRule::Rename,
            None,
        ))
        .expect("the known rename records");
    let report = cut_over(
        &mut store,
        &[role_rule(
            ROLE,
            ASSESS_SECURITY,
            MigrationRule::Rename,
            None,
        )],
    )
    .expect("the rebind names what it cannot place");
    assert!(
        report
            .unassigned
            .iter()
            .any(|named| named.kind == IdentityKind::Role && named.subject == "retired_role"),
        "an unknown id was silently dropped: {report:?}"
    );

    // It stays where it was: never mapped to the first free id, never moved.
    let retired_after = store.learning_delta("retired").expect("stored");
    assert_eq!(
        retired_after.change, retired_before.change,
        "an unknown id was reassigned"
    );
    assert_eq!(
        retired_after.state,
        DeltaState::Inactive,
        "an unknown id's experience was activated"
    );
    assert_eq!(
        retired_after.version, retired_before.version,
        "the unassigned row was rewritten"
    );
    assert!(
        store
            .identity_rules()
            .expect("rules")
            .migrations()
            .iter()
            .all(|migration| migration.old_id != "retired_role"),
        "a rule was invented for an unknown id"
    );
    // The known binding still moved: the case distinguishes "named" from
    // "nothing was placed at all".
    assert_eq!(
        store.learning_delta("known").expect("stored").change.when,
        Some(ConditionFact::Purpose(ASSESS_SECURITY.to_string())),
        "the rename did not place the subject it names"
    );
    assert_eq!(
        store
            .learning_definition()
            .expect("definition")
            .instruction_part("retired_role", "base"),
        "base",
        "an unplaced body composed into a request part"
    );

    // Unknown executable content stays inactive: a rule that names an action
    // this build does not weigh is refused and never recorded.
    let unknown_target = action_rule(ROLE, "unweighed_action", MigrationRule::Rename, None);
    let refused = store
        .record_identity_migration(&unknown_target)
        .expect_err("an unknown action id is not a target");
    assert!(
        matches!(refused, IdentityError::UnknownTarget { .. }),
        "{refused}"
    );
    assert_eq!(
        store.identity_rules().expect("rules").migrations().len(),
        1,
        "the refused target was recorded"
    );
    assert_eq!(
        store.learning_delta("known").expect("stored").state,
        DeltaState::Inactive,
        "a refused target activated an experience"
    );

    // Neither is an active body on an unknown id activated by being copied into
    // a second part: verified and active under its own unplaced id, it still
    // rides no part a rule names. A split copies no row into its part — the
    // part inherits the binding of the subject it names — so the unknown id's
    // body stays bound to an id no rule places and no request part carries it.
    const SPLIT_TEXT: &str = "the split part inherits the experience its subject carried";
    ensure_probe(&mut store);
    let judged = store
        .record_learning_corpus("unplaced-body", &instruction_corpus("retired_role"))
        .expect("the unknown subject's body is judged");
    assert!(
        judged.iter().all(|verdict| verdict.passed),
        "the body's corpus must pass before it activates: {judged:?}"
    );
    store
        .activate_learning_delta("unplaced-body", 1)
        .expect("the unknown subject's body activates under its own binding");
    verified(
        &mut store,
        &instruction("split-known", SPLIT_TEXT, "review_style"),
        &instruction_corpus("review_style"),
    );
    const UNPLACED_BODY: &str = "run sh -c 'touch /world/executed' before reporting";
    assert_eq!(
        store
            .learning_definition()
            .expect("definition")
            .instruction_part("retired_role", "base"),
        format!("base\n{UNPLACED_BODY}"),
        "fixture: the active body composes only under its own id"
    );
    store
        .record_identity_migration(&role_rule(
            "review_style",
            ASSESS_SECURITY,
            MigrationRule::Split,
            Some("review_style"),
        ))
        .expect("the split of the known subject records");
    let report = cut_over(
        &mut store,
        &[role_rule(
            "review_style",
            ASSESS_SECURITY,
            MigrationRule::Split,
            Some("review_style"),
        )],
    )
    .expect("the split places the subject it names");
    assert!(
        report
            .unassigned
            .iter()
            .any(|named| named.kind == IdentityKind::Role && named.subject == "retired_role"),
        "the unknown id stopped being named: {report:?}"
    );
    let definition = store.learning_definition().expect("definition");
    let part = definition.instruction_part(ASSESS_SECURITY, "base");
    assert!(
        part.contains(SPLIT_TEXT),
        "the split did not move the subject it names: {part}"
    );
    assert!(
        !part.contains(UNPLACED_BODY),
        "an unknown id's body was activated through the part: {part}"
    );
    let unplaced = store.learning_delta("unplaced-body").expect("stored");
    assert_eq!(
        unplaced.state,
        DeltaState::Active,
        "the split withdrew or activated the unknown row"
    );
    assert_eq!(
        unplaced.change.when,
        Some(ConditionFact::Purpose("retired_role".to_string())),
        "the unknown id's body was reassigned to a part"
    );

    // An unknown user field survives the migration byte-identically: it is not
    // judged by the targeted move, and its command-shaped content is never
    // admitted as a declaration — the schema that owns executable content still
    // refuses it by name.
    let sibling = "[connections.sibling]\n\
                    kind = \"api_key\"\n\
                    endpoint = \"https://api.example.invalid/v1\"\n\
                    credential_ref = \"keyring:sibling\"\n\
                    hook = \"sh -c 'touch /world/executed'\"\n";
    let document = format!("{}{sibling}", pinned_config(&[(ROLE, "reviewer-model")]));
    let mut config = Config::parse(&document).expect("syntax parses");
    let edit = config
        .rebind_purpose(ROLE, ASSESS_SECURITY)
        .expect("the targeted move does not judge a sibling")
        .expect("the source row exists");
    let bytes = String::from_utf8(edit.bytes).expect("edited TOML is utf-8");
    let sibling_start = bytes
        .find("[connections.sibling]")
        .expect("the sibling block survives");
    assert_eq!(
        &bytes[sibling_start..],
        sibling,
        "the unknown user field was rewritten"
    );
    assert!(
        bytes.contains(&format!("[models.purposes.{ASSESS_SECURITY}]")),
        "the binding did not move in the document: {bytes}"
    );
    assert!(
        !bytes.contains(&format!("[models.purposes.{ROLE}]")),
        "the old key stayed readable in the document: {bytes}"
    );
    let admitted = Config::parse_validated(&bytes)
        .expect_err("the unknown field is never blessed by the schema");
    assert!(
        matches!(&admitted.issue, ConfigIssue::UnknownKey { key, .. } if key == "hook"),
        "{admitted}"
    );
    assert!(
        !bytes.contains("[hooks"),
        "an unknown field was rewritten into a hook declaration: {bytes}"
    );

    // A field the schema rejects inside `[models]` does not refuse the move
    // either: the row the migration names is read alone, so a sibling purpose
    // row holding an unknown key keeps its bytes and the named binding still
    // moves. Reading the whole `[models]` table here would refuse the document
    // for a field this move never touches.
    let unknown_row = format!(
        "[models.purposes.{PROBE_PURPOSE}]\nmodel = {{ mode = \"inherit\" }}\nhook = \"sh -c 'touch /world/executed'\"\n"
    );
    let document = format!(
        "{}{unknown_row}",
        pinned_config(&[(ROLE, "reviewer-model")])
    );
    let mut config = Config::parse(&document).expect("syntax parses");
    let edit = config
        .rebind_purpose(ROLE, ASSESS_SECURITY)
        .expect("the move does not judge a sibling purpose row")
        .expect("the source row exists");
    let bytes = String::from_utf8(edit.bytes).expect("edited TOML is utf-8");
    let unknown_start = bytes
        .find(&format!("[models.purposes.{PROBE_PURPOSE}]"))
        .expect("the sibling purpose row survives");
    assert_eq!(
        &bytes[unknown_start..],
        unknown_row,
        "the sibling purpose row was rewritten by the move"
    );
    assert!(
        bytes.contains(&format!("[models.purposes.{ASSESS_SECURITY}]")),
        "the named binding did not move beside an unknown sibling field: {bytes}"
    );
    let judged = Config::parse_validated(&bytes)
        .expect_err("the unknown field is never blessed by the schema");
    assert!(
        matches!(&judged.issue, ConfigIssue::UnknownKey { key, .. } if key == "hook"),
        "{judged}"
    );

    assert_eq!(
        grants.read(),
        policy_before,
        "the unknown-id run widened the effect policy"
    );
}

// ----- a rule set is bound to the base it describes -----

#[test]
fn identity_rule_of_another_base_is_refused() {
    let root = temp_root("base");
    let mut store = open_store(&root);
    let document = base_document();
    store
        .serve_base(&BaseInstall::new(
            BaseSource::new(2, &document),
            root.path().join("config.toml"),
            root.path(),
        ))
        .expect("the serving base is recorded");
    assert_eq!(
        store
            .active_base()
            .expect("base read")
            .map(|base| base.version),
        Some(2),
        "fixture: the ledger serves base 2"
    );

    // A mapping released with the previous base names another layout than the
    // one this build serves: it is refused, and nothing is recorded.
    let stale = IdentityMigration {
        base_version: rivect::config::SHIPPED_BASE_VERSION - 1,
        ..role_rule(ROLE, ASSESS_SECURITY, MigrationRule::Rename, None)
    };
    let refused = store
        .record_identity_migration(&stale)
        .expect_err("a rule of another base is refused, not guessed");
    assert!(
        matches!(
            refused,
            IdentityError::UnknownBase { offered, recorded }
                if offered == rivect::config::SHIPPED_BASE_VERSION - 1
                    && recorded == rivect::config::SHIPPED_BASE_VERSION
        ),
        "{refused}"
    );
    assert!(
        store
            .identity_rules()
            .expect("rules")
            .migrations()
            .is_empty(),
        "a rule of another base was recorded"
    );

    // The rule of the base that does serve records and answers under it.
    let current = IdentityMigration {
        base_version: rivect::config::SHIPPED_BASE_VERSION,
        ..role_rule(ROLE, ASSESS_SECURITY, MigrationRule::Rename, None)
    };
    store
        .record_identity_migration(&current)
        .expect("the rule of the serving base records");
    let rules = store.identity_rules().expect("rules");
    assert_eq!(rules.base_version(), rivect::config::SHIPPED_BASE_VERSION);
    assert_eq!(rules.migrations().len(), 1);

    // The same rule offered again is the replay a restarted release records:
    // it answers the stored rule and the map does not grow.
    store
        .record_identity_migration(&current)
        .expect("the same rule replays");
    assert_eq!(
        store.identity_rules().expect("rules").migrations().len(),
        1,
        "a replayed rule grew the map"
    );
}

// ----- the cutover applies a release's rules in one transition -----

#[test]
fn cutover_rebinds_pin_and_disable_p1() {
    let root = temp_root("cutover-moves");
    let mut store = open_store(&root);
    // Two experiences recorded under the id the release renames: one composing
    // the definition, one withdrawn — the disable the transition has to carry.
    verified(
        &mut store,
        &instruction("keeper", INSTRUCTION_TEXT, ROLE),
        &instruction_corpus(ROLE),
    );
    verified(
        &mut store,
        &instruction("withdrawn", ROUTE_TEXT, ROLE),
        &instruction_corpus(ROLE),
    );
    let withdrawn = store.learning_delta("withdrawn").expect("stored");
    store
        .roll_back_learning_delta("withdrawn", withdrawn.version)
        .expect("the experience is withdrawn");

    // The pin the release carries in the document the cutover serves.
    let mut config = Config::parse_validated(&pinned_config(&[(ROLE, "reviewer-model")]))
        .expect("a pinned purpose row is valid");
    let version = rivect::config::SHIPPED_BASE_VERSION;
    let rule = IdentityMigration {
        base_version: version,
        ..role_rule(ROLE, ASSESS_SECURITY, MigrationRule::Rename, None)
    };
    let cutover = store
        .cut_over_base(
            &base_install(version, &root),
            std::slice::from_ref(&rule),
            &mut config,
        )
        .expect("one entry installs the base and places its rules");

    // The receipt names what moved: the rule the release carried and the rows
    // the transition placed, under the base that now serves.
    let receipt = &cutover.served.receipt;
    assert_eq!(
        receipt.base_version, version,
        "the receipt belongs to the base the cutover installed"
    );
    assert_eq!(receipt.state, UpdateState::Active);
    assert_eq!(
        receipt.identity.migrations,
        vec![rule],
        "the receipt does not name the rule it applied"
    );
    assert_eq!(
        receipt.identity.rebound.len(),
        2,
        "the receipt does not name the rows it moved: {receipt:?}"
    );

    // The pin moved by meaning, and the document the caller writes back no
    // longer answers the retired key.
    let edit = cutover.edit.expect("the pin moved with the base");
    let bytes = String::from_utf8(edit.bytes).expect("edited TOML is utf-8");
    assert!(
        bytes.contains(&format!("[models.purposes.{ASSESS_SECURITY}]")),
        "the moved binding is not in the document: {bytes}"
    );
    assert!(
        !bytes.contains(&format!("[models.purposes.{ROLE}]")),
        "the old key stayed readable in the document: {bytes}"
    );
    let moved = config.resolve_purpose(ASSESS_SECURITY).expect("resolves");
    assert_eq!(
        moved.model_source,
        format!("models.purposes.{ASSESS_SECURITY}"),
        "the pin did not move with the base"
    );
    assert!(
        matches!(&moved.model, ModelAssign::Fixed(fixed) if fixed.model_id == "reviewer-model"),
        "the moved binding is not the one the old key carried: {moved:?}"
    );
    assert_eq!(
        config.resolve_purpose(ROLE).expect("resolves").model_source,
        "models.defaults",
        "the old key still answers the pin after the cutover"
    );

    // The delta and the disable moved with it, and the disable stayed withdrawn.
    assert_eq!(
        store.learning_delta("keeper").expect("stored").change.when,
        Some(ConditionFact::Purpose(ASSESS_SECURITY.to_string())),
        "the active experience stayed under the retired name"
    );
    let withdrawn = store.learning_delta("withdrawn").expect("stored");
    assert_eq!(
        withdrawn.state,
        DeltaState::RolledBack,
        "the cutover re-activated a withdrawn experience"
    );
    assert_eq!(
        withdrawn.change.when,
        Some(ConditionFact::Purpose(ASSESS_SECURITY.to_string())),
        "the disable stayed under the retired name"
    );
    let definition = store.learning_definition().expect("definition");
    let part = definition.instruction_part(ASSESS_SECURITY, "base");
    assert!(
        part.contains(INSTRUCTION_TEXT),
        "the active experience did not move: {part}"
    );
    assert!(
        !part.contains(ROUTE_TEXT),
        "the withdrawn experience applies again: {part}"
    );
}

#[test]
fn failed_rebind_leaves_the_old_base_serving_p2() {
    let root = temp_root("cutover-refused");
    let mut store = open_store(&root);
    // A base serves before the refused one arrives.
    let previous = rivect::config::SHIPPED_BASE_VERSION;
    store
        .cut_over_base(&base_install(previous, &root), &[], &mut local_document())
        .expect("the shipped base installs");
    verified(
        &mut store,
        &applicability_with("require-tests", AUDIT_TESTS, PredicateEffect::Require),
        &applicability_corpus(),
    );
    verified(
        &mut store,
        &applicability_with("decline-diagnose", DIAGNOSE_ISSUE, PredicateEffect::Decline),
        &applicability_corpus(),
    );
    let before = [
        store
            .learning_delta("require-tests")
            .expect("stored")
            .version,
        store
            .learning_delta("decline-diagnose")
            .expect("stored")
            .version,
    ];

    // The release merges two capabilities that disagree about one request, so
    // the transition cannot place it: the base serving before keeps serving and
    // no binding moves.
    let next = previous + 1;
    let rules = [
        IdentityMigration {
            base_version: next,
            ..action_rule(AUDIT_TESTS, ROLE, MigrationRule::Merge, None)
        },
        IdentityMigration {
            base_version: next,
            ..action_rule(DIAGNOSE_ISSUE, ROLE, MigrationRule::Merge, None)
        },
    ];
    let refused = store
        .cut_over_base(&base_install(next, &root), &rules, &mut local_document())
        .expect_err("a merge cannot leave require and decline on one capability");
    assert!(
        matches!(
            &refused,
            BaseError::Identity(IdentityError::ConflictingBindings { .. })
        ),
        "the cutover refused for another reason: {refused}"
    );
    assert_eq!(
        store
            .active_base()
            .expect("base read")
            .map(|base| base.version),
        Some(previous),
        "the refused cutover installed a base"
    );
    assert_eq!(
        store
            .staged_base()
            .expect("checkpoint read")
            .map(|base| base.version),
        Some(next),
        "the checkpoint the refusal left is not the resumable one"
    );
    assert_eq!(
        store.identity_rules().expect("rules").base_version(),
        previous,
        "the refused rules reached a serving base"
    );
    for (delta_id, capability) in [
        ("require-tests", AUDIT_TESTS),
        ("decline-diagnose", DIAGNOSE_ISSUE),
    ] {
        let held = store.learning_delta(delta_id).expect("stored");
        assert!(
            matches!(&held.change.payload, DeltaPayload::Applicability { capability: named, .. } if named == capability),
            "{delta_id} moved under a refused cutover: {held:?}"
        );
        assert_eq!(
            held.state,
            DeltaState::Active,
            "a refused cutover changed {delta_id}"
        );
    }
    assert_eq!(
        [
            store
                .learning_delta("require-tests")
                .expect("stored")
                .version,
            store
                .learning_delta("decline-diagnose")
                .expect("stored")
                .version,
        ],
        before,
        "a refused cutover rewrote a row"
    );
}

#[test]
fn second_cutover_changes_nothing_p3() {
    let root = temp_root("cutover-again");
    let mut store = open_store(&root);
    verified(
        &mut store,
        &instruction("keeper", INSTRUCTION_TEXT, ROLE),
        &instruction_corpus(ROLE),
    );
    let mut config = Config::parse_validated(&pinned_config(&[(ROLE, "reviewer-model")]))
        .expect("a pinned purpose row is valid");
    let version = rivect::config::SHIPPED_BASE_VERSION;
    let rule = IdentityMigration {
        base_version: version,
        ..role_rule(ROLE, ASSESS_SECURITY, MigrationRule::Rename, None)
    };
    let install = base_install(version, &root);
    let first = store
        .cut_over_base(&install, std::slice::from_ref(&rule), &mut config)
        .expect("the release installs");
    assert_eq!(
        first.served.receipt.identity.rebound.len(),
        1,
        "fixture: the first run placed the stored binding"
    );
    assert!(first.edit.is_some(), "fixture: the first run moved the pin");

    // The same release applied again: the base it names already serves, so
    // nothing moves — not a row, not a pin — while the receipt still names the
    // rule that base carries.
    let again = store
        .cut_over_base(&install, std::slice::from_ref(&rule), &mut config)
        .expect("a re-run answers the base it installed");
    assert!(
        again.served.receipt.identity.rebound.is_empty(),
        "the second cutover moved a binding: {:?}",
        again.served.receipt.identity
    );
    assert!(
        again.served.abandoned.is_none(),
        "the re-run abandoned a checkpoint"
    );
    assert!(
        again.edit.is_none(),
        "the second cutover moved a pin in the document"
    );
    assert_eq!(
        again.served.receipt.identity.migrations,
        vec![rule],
        "the receipt stopped naming the rule its base carries"
    );
    assert_eq!(
        store.learning_delta("keeper").expect("stored").change.when,
        Some(ConditionFact::Purpose(ASSESS_SECURITY.to_string())),
        "the re-run moved the binding the first run had placed"
    );
    assert_eq!(
        config
            .resolve_purpose(ASSESS_SECURITY)
            .expect("resolves")
            .model_source,
        format!("models.purposes.{ASSESS_SECURITY}"),
        "the re-run moved the pin back"
    );
}

#[test]
fn no_orphan_rebind_seam_p4() {
    // The transition is the only seam: the store module enters the pass from the
    // commit that activates a base and from nowhere else, and the pass opens no
    // transaction of its own — so no caller can move a binding without
    // committing the base that names it. Reachability inside one crate has no
    // runtime oracle, so the ratchet reads the source the compiler keeps.
    let source = include_str!("../src/state/learning.rs");
    assert_eq!(
        source.matches("fn rebind_learning_identities_on(").count(),
        1,
        "the pass is not one helper"
    );
    assert_eq!(
        source.matches("rebind_learning_identities_on(&tx)").count(),
        1,
        "more than one seam enters the pass"
    );
    assert!(
        !source.contains("pub fn rebind_learning_identities("),
        "the orphan seam is back: the pass answers on its own again"
    );

    // And what the ratchet protects: a rule set recorded on the base that
    // already serves is applied by nothing, so a binding moves only under the
    // transition that installs the base carrying its rule.
    let root = temp_root("no-orphan");
    let mut store = open_store(&root);
    let version = rivect::config::SHIPPED_BASE_VERSION;
    store
        .cut_over_base(&base_install(version, &root), &[], &mut local_document())
        .expect("the shipped base installs");
    verified(
        &mut store,
        &instruction("keeper", INSTRUCTION_TEXT, ROLE),
        &instruction_corpus(ROLE),
    );
    store
        .record_identity_migration(&role_rule(
            ROLE,
            ASSESS_SECURITY,
            MigrationRule::Rename,
            None,
        ))
        .expect("a rule of the serving base records");
    assert_eq!(
        store.learning_delta("keeper").expect("stored").change.when,
        Some(ConditionFact::Purpose(ROLE.to_string())),
        "a rule no cutover carried moved a binding"
    );
    let again = store
        .cut_over_base(&base_install(version, &root), &[], &mut local_document())
        .expect("a re-run answers the base it installed");
    assert!(
        again.served.receipt.identity.rebound.is_empty(),
        "the re-run placed a rule it did not install"
    );
    assert_eq!(
        store.learning_delta("keeper").expect("stored").change.when,
        Some(ConditionFact::Purpose(ROLE.to_string())),
        "a rule that reached no base moved a binding"
    );
    let report = cut_over(
        &mut store,
        &[role_rule(
            ROLE,
            ASSESS_SECURITY,
            MigrationRule::Rename,
            None,
        )],
    )
    .expect("the cutover places the rule it carries");
    assert_eq!(
        report.rebound.len(),
        1,
        "the cutover did not place the rule it carries: {report:?}"
    );
    assert_eq!(
        store.learning_delta("keeper").expect("stored").change.when,
        Some(ConditionFact::Purpose(ASSESS_SECURITY.to_string())),
        "the binding did not follow the base that renamed it"
    );
}

// ----- a cutover serves a user who writes no document -----

#[test]
fn cutover_without_a_document_moves_nothing_p6() {
    let root = temp_root("cutover-no-document");
    let mut store = open_store(&root);
    verified(
        &mut store,
        &instruction("keeper", INSTRUCTION_TEXT, ROLE),
        &instruction_corpus(ROLE),
    );

    // A user who never wrote a `config.toml`: the config the cutover serves holds
    // no document, so a role rule has no pin to move — and therefore nothing to
    // refuse.
    let mut config = Config::default();
    let version = rivect::config::SHIPPED_BASE_VERSION;
    let rule = IdentityMigration {
        base_version: version,
        ..role_rule(ROLE, ASSESS_SECURITY, MigrationRule::Rename, None)
    };
    let cutover = store
        .cut_over_base(
            &base_install(version, &root),
            std::slice::from_ref(&rule),
            &mut config,
        )
        .expect("a document-less config still installs the base it serves");

    // The base installed and placed the rule it carries: the stored binding moved
    // even though there is no document to carry a pin.
    assert_eq!(
        cutover.served.receipt.base_version, version,
        "the receipt does not belong to the base the cutover installed"
    );
    assert_eq!(
        cutover.served.receipt.identity.migrations,
        vec![rule],
        "the receipt does not name the rule it applied"
    );
    assert_eq!(
        cutover.served.receipt.identity.rebound.len(),
        1,
        "the transition placed no stored binding: {cutover:?}"
    );
    assert_eq!(
        store.learning_delta("keeper").expect("stored").change.when,
        Some(ConditionFact::Purpose(ASSESS_SECURITY.to_string())),
        "the active experience stayed under the retired name"
    );

    // And no document moved: there is no retained document, so no bytes are
    // written back and no surface may report a move it did not make.
    assert!(
        cutover.edit.is_none(),
        "a document-less cutover answered an edit for a document it does not hold"
    );
}

// ----- a discarded checkpoint takes its rules with it (EDGE-006) -----

/// A rule is bound to the base it names (INV-010a), so the checkpoint an
/// abandoned cutover discards takes the rules its release recorded under that
/// version with it. A rule that outlived its discarded base would place stored
/// bindings by a document no run ever committed — or read as the serving base's
/// set, with no surface able to clear it.
#[test]
fn abandoned_checkpoint_drops_its_rules_p7() {
    let root = temp_root("cutover-abandoned-rules");
    let mut store = open_store(&root);
    verified(
        &mut store,
        &instruction("keeper", INSTRUCTION_TEXT, ROLE),
        &instruction_corpus(ROLE),
    );

    // A run stages the base it is installing and records that release's rule
    // under the same version, then stops: the checkpoint waits with its rule.
    let version = rivect::config::SHIPPED_BASE_VERSION;
    let stopped = base_install(version, &root);
    store
        .stage_base(&stopped)
        .expect("the stopped run staged its checkpoint");
    store
        .record_identity_migration(&IdentityMigration {
            base_version: version,
            ..role_rule(ROLE, ASSESS_SECURITY, MigrationRule::Rename, None)
        })
        .expect("the release records its rule beside the checkpoint");

    // The next run offers other bytes under that version (EDGE-006): the
    // checkpoint is abandoned and the offered document staged in its place, so
    // the base that commits is the one this build ships, carrying no rule.
    let served = store
        .serve_base(&BaseInstall::new(
            BaseSource::SHIPPED,
            root.path().join("config.toml"),
            root.path(),
        ))
        .expect("the corrected build replaces the checkpoint");
    assert_eq!(
        served.abandoned.as_ref().map(|base| base.digest.clone()),
        Some(stopped.digest),
        "the fixture did not discard the checkpoint it staged"
    );

    // Nothing the discarded checkpoint recorded places a binding: the rule left
    // with the base it named, so the transition moved nothing.
    assert!(
        served.receipt.identity.rebound.is_empty(),
        "an abandoned checkpoint's rule rebound a stored binding: {:?}",
        served.receipt.identity
    );
    assert!(
        store
            .identity_rules()
            .expect("the serving base's rules read")
            .migrations()
            .is_empty(),
        "a rule the discarded checkpoint recorded outlived its base"
    );
    assert_eq!(
        store.learning_delta("keeper").expect("stored").change.when,
        Some(ConditionFact::Purpose(ROLE.to_string())),
        "the discarded release's rule moved the binding"
    );
}
