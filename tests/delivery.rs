//! AC-080 (REQ-066): one delivery of the exact activated candidate through the
//! existing publication journal.
//!
//! The preparation checks the exact candidate, destination, retention bound,
//! current grant and provenance/integrity/compatibility before any write; a
//! matching grant produces one observable local effect and one retained receipt;
//! a revoked or mismatched grant produces zero effects; and an outcome the
//! journal cannot prove is reported unknown without repeating an applied effect.
//!
//! Every case drives the production seams — `Runtime::prepare_delivery`/
//! `Runtime::deliver_change`, the real `Policy` grant, the managed-write
//! executor, and `TaskStore`'s publication journal — and asserts a durable
//! observation. The effect's absence is proven the hard way: once the intended
//! bytes hold, the destination is sealed read-only and its `(dev, ino)`, length
//! and timestamps are recorded, so a repeated managed write would fail the call
//! and an in-place rewrite would move a timestamp this compares. The destination
//! is an operator-owned file in a private fixture; no external destination or
//! real publication is touched.

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

use rivect::config::{self, BaseError, PublicationAdmission, PublicationIntent};
use rivect::contracts::{
    DeliveryCandidate, DeliveryIntent, DeliveryOutcome, DeliveryReceipt, EffectClass, ErrorCode,
};
use rivect::executor::{FileIdentity, Unattested, WorkerError, WriteIdentity};
use rivect::policy::PolicyError;
use rivect::state::{ConflictCause, StoreError, TaskStore};
use rivect::update::{DELIVERY_OWNER, DeliveryError};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::fs::{MetadataExt as _, symlink};
use std::path::Path;

/// The journal owner the CLI config carrier admits under (`commands`'s private
/// label): a config edit and a delivery are different owners of one journal.
const CONFIG_CARRIER_OWNER: &str = "cli";

fn temp_root(prefix: &str) -> tempfile::TempDir {
    tempfile::TempDir::with_prefix(format!("rivect-delivery-{prefix}-")).expect("fixture root")
}

/// The exact candidate a fresh runtime serves: the shipped base document's
/// bytes and the digest the ledger's activation receipt records for it.
fn served_candidate() -> (DeliveryCandidate, Vec<u8>) {
    (
        DeliveryCandidate {
            base_version: config::SHIPPED_BASE_VERSION,
            digest: config::shipped_revision(),
        },
        config::SHIPPED_DEFAULTS_TOML.as_bytes().to_vec(),
    )
}

/// An existing destination seeded with the previous release's bytes, named by
/// the absolute spelling the journal stores.
fn seeded_destination(scope: &Path, seed: &[u8]) -> String {
    let path = scope.join("delivered-base.toml");
    std::fs::write(&path, seed).expect("seed the destination");
    path.to_str().expect("utf-8 destination").to_string()
}

/// The intent the cases start from, before preparation has staged a row.
fn intent(candidate: &DeliveryCandidate, destination: &str, grant_id: &str) -> DeliveryIntent {
    DeliveryIntent {
        candidate: candidate.clone(),
        destination: destination.to_string(),
        grant_id: grant_id.to_string(),
        admission_seq: None,
    }
}

/// The journal rows this delivery owns on one destination: `(pending, applied)`.
fn delivery_rows(store: &TaskStore, destination: &str) -> (usize, usize) {
    let count = |rows: Vec<PublicationIntent>| {
        rows.into_iter()
            .filter(|row| row.owner == DELIVERY_OWNER && row.target == destination)
            .count()
    };
    (
        count(store.pending_publications().expect("pending rows")),
        count(store.applied_publications().expect("applied rows")),
    )
}

fn applied_row(store: &TaskStore, destination: &str) -> PublicationIntent {
    store
        .applied_publications()
        .expect("applied rows")
        .into_iter()
        .find(|row| row.owner == DELIVERY_OWNER && row.target == destination)
        .expect("one applied delivery row")
}

/// The durable state a repeated call must leave exactly as it was: the file's
/// identity, its length, and the two timestamps an in-place rewrite moves. A
/// second identical managed write changes the content's producer but never the
/// digest, so this is what makes "no write" observable.
#[derive(Debug, PartialEq, Eq)]
struct Observed {
    dev: u64,
    ino: u64,
    len: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

fn observed(path: &str) -> Observed {
    let metadata = std::fs::metadata(path).expect("destination metadata");
    Observed {
        dev: metadata.dev(),
        ino: metadata.ino(),
        len: metadata.len(),
        modified: (metadata.mtime(), metadata.mtime_nsec()),
        changed: (metadata.ctime(), metadata.ctime_nsec()),
    }
}

/// Seals the destination read-only, so a managed write that must not run fails
/// the call instead of staying invisible.
fn seal_destination(path: &str) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o444))
        .expect("seal the destination");
}

/// One prepared world: an open runtime, one operator-owned destination seeded
/// with the previous release's bytes, the exact candidate that runtime serves,
/// and the live write grant its scope admits.
struct Fixture {
    world: support::World,
    scope: tempfile::TempDir,
    candidate: DeliveryCandidate,
    bytes: Vec<u8>,
    seed: Vec<u8>,
    destination: String,
    grant: String,
}

impl Fixture {
    fn open(tag: &str) -> Self {
        // The managed write launches the confined helper: a suite that never
        // built it fails its first effect with `SandboxSpawnFailed`, so the
        // fixture builds it before any case can write.
        support::ensure_helper();
        let mut world = support::open_world(tag, None);
        let scope = temp_root(&format!("{tag}-scope"));
        let (candidate, bytes) = served_candidate();
        let seed = b"the previous release bytes".to_vec();
        let destination = seeded_destination(scope.path(), &seed);
        let grant = world
            .runtime
            .policy_writer()
            .grant_classes(scope.path().to_path_buf(), vec![EffectClass::Write]);
        Self {
            world,
            scope,
            candidate,
            bytes,
            seed,
            destination,
            grant,
        }
    }

    fn intent(&self) -> DeliveryIntent {
        intent(&self.candidate, &self.destination, &self.grant)
    }

    fn prepare(&mut self) -> DeliveryIntent {
        self.world
            .runtime
            .prepare_delivery(self.intent())
            .expect("the exact serving base is prepared")
    }

    fn deliver(&mut self, prepared: &DeliveryIntent) -> Result<DeliveryReceipt, DeliveryError> {
        self.world.runtime.deliver_change(prepared, &self.bytes)
    }

    fn destination_bytes(&self) -> Vec<u8> {
        std::fs::read(&self.destination).expect("destination bytes")
    }

    fn rows(&self) -> (usize, usize) {
        delivery_rows(self.world.runtime.store(), &self.destination)
    }

    fn applied(&self) -> PublicationIntent {
        applied_row(self.world.runtime.store(), &self.destination)
    }

    fn observed(&self) -> Observed {
        observed(&self.destination)
    }

    fn scope(&self) -> &Path {
        self.scope.path()
    }

    fn seed(&self) -> &[u8] {
        &self.seed
    }
}

// ----- prepare-only is not authorization and writes nothing -----

/// AC-080/PROH-002: preparation is not authorization. An absent grant refuses
/// before any journal row or destination byte exists.
#[test]
fn prepare_without_a_grant_writes_nothing() {
    let mut fixture = Fixture::open("prepare-open");

    let error = fixture
        .world
        .runtime
        .prepare_delivery(intent(
            &fixture.candidate,
            &fixture.destination,
            "grant-absent",
        ))
        .expect_err("an unknown grant must refuse preparation");

    assert!(
        matches!(
            error,
            DeliveryError::Grant(PolicyError::UnknownGrant { .. })
        ),
        "wrong preparation refusal: {error}"
    );
    assert_eq!(
        fixture.destination_bytes(),
        fixture.seed(),
        "preparation without a grant writes no destination byte"
    );
    assert_eq!(
        fixture.rows(),
        (0, 0),
        "preparation without a grant stages no journal row"
    );
}

// ----- the destination must be the exact admissible local file -----

/// AC-080: a relative spelling, a policy-denied path, a target past the
/// managed-write bound and a symlinked destination are refused before any
/// effect, and none of them stages a journal row or moves a seed byte.
#[test]
fn an_inadmissible_destination_is_refused_before_any_effect() {
    let mut fixture = Fixture::open("destination");

    let error = fixture
        .world
        .runtime
        .prepare_delivery(intent(
            &fixture.candidate,
            "delivered-base.toml",
            &fixture.grant,
        ))
        .expect_err("a relative destination is not the exact local file");
    assert!(
        matches!(error, DeliveryError::NotAbsolute { .. }),
        "wrong absolute-path refusal: {error}"
    );

    fixture
        .world
        .runtime
        .policy_writer()
        .enroll_deny(Path::new(&fixture.destination))
        .expect("deny enrolled");
    let error = fixture
        .world
        .runtime
        .prepare_delivery(fixture.intent())
        .expect_err("a denied destination must refuse");
    assert!(
        matches!(error, DeliveryError::Denied { .. }),
        "wrong deny refusal: {error}"
    );
    assert_eq!(
        fixture.destination_bytes(),
        fixture.seed(),
        "a refused destination holds its bytes"
    );

    let oversized_bytes = vec![b'x'; (1 << 20) + 1];
    let oversized = fixture.scope().join("oversized-base.toml");
    std::fs::write(&oversized, &oversized_bytes).expect("oversized destination");
    let oversized = oversized.to_str().expect("utf-8 destination").to_string();
    let error = fixture
        .world
        .runtime
        .prepare_delivery(intent(&fixture.candidate, &oversized, &fixture.grant))
        .expect_err("a destination past the managed-write bound must refuse");
    assert!(
        matches!(error, DeliveryError::TargetTooLarge { .. }),
        "wrong size refusal: {error}"
    );
    assert_eq!(
        std::fs::read(&oversized).expect("oversized bytes"),
        oversized_bytes,
        "an oversized destination keeps its bytes"
    );

    // A symlink is not the exact local file: the in-scope regular file it names
    // is admitted by the grant, and the delivery's own open refuses to follow it.
    let real = fixture.scope().join("real-base.toml");
    std::fs::write(&real, fixture.seed()).expect("the linked file");
    let link = fixture.scope().join("linked-base.toml");
    symlink(&real, &link).expect("symlink the destination");
    let link = link.to_str().expect("utf-8 destination").to_string();
    let error = fixture
        .world
        .runtime
        .prepare_delivery(intent(&fixture.candidate, &link, &fixture.grant))
        .expect_err("a symlinked destination is not this file");
    assert!(
        matches!(error, DeliveryError::Target { .. }),
        "wrong symlink refusal: {error}"
    );
    assert_eq!(
        std::fs::read(&real).expect("linked bytes"),
        fixture.seed(),
        "the file a refused symlink names keeps its bytes"
    );

    assert_eq!(
        fixture.rows(),
        (0, 0),
        "no refused destination stages a journal row"
    );
}

// ----- the carriers are closed wire shapes -----

/// AC-080: the delivery carriers round-trip through the real encoder/decoder and
/// refuse an undeclared field, so no surface can widen the contract a caller
/// names.
#[test]
fn delivery_carriers_round_trip_the_journal_projection() {
    let candidate = DeliveryCandidate {
        base_version: 7,
        digest: "a".repeat(64),
    };
    let intent = DeliveryIntent {
        candidate: candidate.clone(),
        destination: "/operator/destination".to_string(),
        grant_id: "grant-1".to_string(),
        admission_seq: Some(3),
    };
    let encoded = serde_json::to_value(&intent).expect("intent encodes");
    assert_eq!(encoded["candidate"]["base_version"], serde_json::json!(7));
    assert_eq!(
        encoded["candidate"]["digest"],
        serde_json::json!("a".repeat(64))
    );
    assert_eq!(encoded["admission_seq"], serde_json::json!(3));
    let decoded: DeliveryIntent = serde_json::from_value(encoded).expect("intent decodes");
    assert_eq!(decoded, intent);

    let mut widened = serde_json::to_value(&intent).expect("intent encodes");
    widened["root"] = serde_json::json!("/elsewhere");
    assert!(
        serde_json::from_value::<DeliveryIntent>(widened).is_err(),
        "an undeclared field must be refused"
    );

    let receipt = DeliveryReceipt {
        candidate,
        target: intent.destination.clone(),
        intended_digest: intent.candidate.digest.clone(),
        admission_seq: 3,
        applied: true,
        outcome: DeliveryOutcome::Retained,
    };
    let encoded = serde_json::to_value(&receipt).expect("receipt encodes");
    assert_eq!(encoded["outcome"], serde_json::json!("retained"));
    let decoded: DeliveryReceipt = serde_json::from_value(encoded).expect("receipt decodes");
    assert_eq!(decoded, receipt);

    let mut widened = serde_json::to_value(&receipt).expect("receipt encodes");
    widened["published_at"] = serde_json::json!("2026-11-09T00:00:00Z");
    assert!(
        serde_json::from_value::<DeliveryReceipt>(widened).is_err(),
        "an undeclared receipt field must be refused"
    );
}

// ----- the positive delivery: one effect, one retained receipt -----

/// AC-080: a matching grant produces exactly one observable effect and one
/// retained receipt, the journal row names the exact candidate and destination,
/// and a second call answers the retained receipt with zero new effects — with
/// the destination sealed read-only, so a repeated managed write could not pass
/// silently. The regression it kills is a second `write_once` in the applied
/// branch: the digest and the row counts would look identical, and the sealed
/// destination is what refuses it.
#[test]
fn a_matching_grant_publishes_one_effect_and_one_receipt() {
    let mut fixture = Fixture::open("positive");

    let request = fixture.intent();
    let prepared = fixture.prepare();
    assert!(prepared.admission_seq.is_some(), "a row was staged");
    assert_eq!(
        fixture.destination_bytes(),
        fixture.seed(),
        "preparation is not an effect"
    );
    assert_eq!(
        fixture.rows(),
        (1, 0),
        "preparation stages exactly one pending intent"
    );
    // A retry of the same preparation reuses the staged row.
    let again = fixture
        .world
        .runtime
        .prepare_delivery(request)
        .expect("the staged intent is reused");
    assert_eq!(
        again.admission_seq, prepared.admission_seq,
        "preparation does not mint a second intent"
    );
    assert_eq!(fixture.rows(), (1, 0), "still one pending intent");

    let receipt = fixture
        .deliver(&prepared)
        .expect("the effect is admitted and receipted");
    assert_eq!(receipt.outcome, DeliveryOutcome::Published);
    assert!(receipt.applied);
    assert_eq!(
        receipt.candidate, fixture.candidate,
        "the receipt references the activation record by (base_version, digest)"
    );
    assert_eq!(receipt.target, fixture.destination);
    assert_eq!(receipt.intended_digest, fixture.candidate.digest);
    assert_eq!(
        fixture.destination_bytes(),
        fixture.bytes,
        "the exact candidate bytes landed at the destination"
    );
    assert_eq!(fixture.rows(), (0, 1), "one effect, one retained receipt");
    let row = fixture.applied();
    assert_eq!(row.target, fixture.destination);
    assert_eq!(row.intended_digest, fixture.candidate.digest);
    assert_eq!(row.admission_seq, receipt.admission_seq);
    assert_eq!(
        row.base_digest.as_deref(),
        Some(config::hex(&seed_digest(fixture.seed())).as_str()),
        "the row retains the pre-effect digest it was staged against"
    );

    // Zero repeat, observed instead of counted: the destination cannot accept a
    // write any more, so a duplicate managed write fails the call, and the
    // identity and timestamps prove no in-place rewrite ran either.
    seal_destination(&fixture.destination);
    let untouched = fixture.observed();
    let retained = fixture
        .deliver(&prepared)
        .expect("the retained receipt answers without a write");
    assert_eq!(retained.outcome, DeliveryOutcome::Retained);
    assert!(retained.applied);
    assert_eq!(retained.admission_seq, receipt.admission_seq);
    assert_eq!(
        fixture.observed(),
        untouched,
        "the applied effect is never repeated: same inode, length and timestamps"
    );
    assert_eq!(
        fixture.destination_bytes(),
        fixture.bytes,
        "the applied bytes still hold"
    );
    assert_eq!(
        fixture.rows(),
        (0, 1),
        "a second call mints no second receipt"
    );
}

/// The pre-effect digest the journal records is the digest of the seed bytes.
fn seed_digest(seed: &[u8]) -> [u8; 32] {
    use sha2::Digest as _;
    sha2::Sha256::digest(seed).into()
}

// ----- the second receipt is refused -----

/// The store invariant behind the producer's zero-repeat: one journal row owns
/// one receipt, and completing it twice is a typed conflict. The producer's own
/// second call is answered in `a_matching_grant_publishes_one_effect_and_one_receipt`;
/// this case proves the row itself cannot be receipted again, which is what makes
/// that answer the only possible one.
#[test]
fn a_second_receipt_for_one_intent_conflicts() {
    let mut fixture = Fixture::open("second-receipt");
    let prepared = fixture.prepare();
    let receipt = fixture.deliver(&prepared).expect("delivered");

    let error = fixture
        .world
        .runtime
        .store_writer()
        .complete_publication(DELIVERY_OWNER, &fixture.destination, receipt.admission_seq)
        .expect_err("a second receipt must conflict");

    assert!(
        matches!(
            error,
            StoreError::Conflict(ConflictCause::PublicationNotPending { .. })
        ),
        "wrong second-receipt refusal: {error}"
    );
    assert_eq!(fixture.rows(), (0, 1), "the refusal changes no journal row");
}

// ----- revoked and mismatched grants: zero effects -----

/// AC-080: a grant revoked between preparation and delivery produces zero
/// effects; the staged intent stays retained for reconciliation.
#[test]
fn a_revoked_grant_produces_no_effect() {
    let mut fixture = Fixture::open("revoked");
    let prepared = fixture.prepare();

    fixture.world.runtime.policy_writer().revoke(&fixture.grant);

    let error = fixture
        .deliver(&prepared)
        .expect_err("a revoked grant must refuse the effect");
    assert!(
        matches!(error, DeliveryError::Grant(PolicyError::Revoked { .. })),
        "wrong revocation refusal: {error}"
    );
    assert_eq!(
        fixture.destination_bytes(),
        fixture.seed(),
        "a revoked grant writes no destination byte"
    );
    assert_eq!(
        fixture.rows(),
        (1, 0),
        "no effect and no receipt; only the retained intent remains"
    );
}

/// AC-080: a deny enrolled after preparation refuses the delivery-time
/// re-check, so no byte moves under the current policy and the intent stays
/// retained.
#[test]
fn a_deny_enrolled_after_preparation_produces_no_effect() {
    let mut fixture = Fixture::open("late-deny");
    let prepared = fixture.prepare();

    fixture
        .world
        .runtime
        .policy_writer()
        .enroll_deny(Path::new(&fixture.destination))
        .expect("deny enrolled");

    let error = fixture
        .deliver(&prepared)
        .expect_err("the current policy refuses the destination");
    assert!(
        matches!(error, DeliveryError::Denied { .. }),
        "wrong delivery-time deny refusal: {error}"
    );
    assert_eq!(
        fixture.destination_bytes(),
        fixture.seed(),
        "a denied destination writes no byte"
    );
    assert_eq!(
        fixture.rows(),
        (1, 0),
        "the refused intent stays pending with no receipt"
    );
}

/// AC-080/PROH-002: a grant that admits another class or another scope is not
/// this delivery's grant, and it produces zero effects.
#[test]
fn a_mismatched_grant_produces_no_effect() {
    let mut fixture = Fixture::open("mismatched");
    let other = temp_root("mismatched-other");

    // The class does not admit a write.
    let scope_root = fixture.scope().to_path_buf();
    let read_grant = fixture
        .world
        .runtime
        .policy_writer()
        .grant_classes(scope_root, vec![EffectClass::Read]);
    let error = fixture
        .world
        .runtime
        .prepare_delivery(intent(
            &fixture.candidate,
            &fixture.destination,
            &read_grant,
        ))
        .expect_err("a read-only grant must refuse a delivery");
    assert!(
        matches!(
            error,
            DeliveryError::Grant(PolicyError::ClassNotAdmitted { .. })
        ),
        "wrong class refusal: {error}"
    );

    // The scope does not contain the destination.
    let foreign_grant = fixture
        .world
        .runtime
        .policy_writer()
        .grant_classes(other.path().to_path_buf(), vec![EffectClass::Write]);
    let error = fixture
        .world
        .runtime
        .prepare_delivery(intent(
            &fixture.candidate,
            &fixture.destination,
            &foreign_grant,
        ))
        .expect_err("a grant on another root must refuse this destination");
    assert!(
        matches!(
            error,
            DeliveryError::Write(WorkerError::OutsideScope { .. })
        ),
        "wrong scope refusal: {error}"
    );

    assert_eq!(
        fixture.destination_bytes(),
        fixture.seed(),
        "no mismatched grant writes a destination byte"
    );
    assert_eq!(
        fixture.rows(),
        (0, 0),
        "no mismatched grant stages a journal row"
    );
}

/// AC-080/PROH-002: completing a receipt is an effect, so the retained path
/// re-derives the destination under the *current* grant's scope. An intent
/// prepared under a grant whose scope excludes the destination cannot be
/// finished under another grant even when its bytes already hold.
#[test]
fn a_grant_swapped_after_preparation_completes_no_receipt() {
    let mut fixture = Fixture::open("grant-swap");
    let prepared = fixture.prepare();
    // The crash window the journal exists for: the effect landed in place and
    // the receipt did not, so this call would otherwise complete it.
    std::fs::write(&fixture.destination, &fixture.bytes).expect("effect without its receipt");
    let mut swapped = prepared.clone();
    let other_scope = temp_root("grant-swap-other");
    swapped.grant_id = fixture
        .world
        .runtime
        .policy_writer()
        .grant_classes(other_scope.path().to_path_buf(), vec![EffectClass::Write]);

    let error = fixture
        .deliver(&swapped)
        .expect_err("a grant outside the destination's scope completes no receipt");
    assert!(
        matches!(
            error,
            DeliveryError::Write(WorkerError::OutsideScope { .. })
        ),
        "wrong swapped-grant refusal: {error}"
    );
    assert_eq!(
        fixture.rows(),
        (1, 0),
        "the landed bytes keep their intent pending, un-receipted"
    );
}

// ----- a differing candidate is refused before any effect -----

/// AC-080: a candidate the ledger did not activate, or bytes that differ from
/// the recorded digest, are refused before any publication and repeat no effect.
#[test]
fn a_differing_candidate_is_refused_before_any_effect() {
    let mut fixture = Fixture::open("candidate");

    let mut wrong_digest = fixture.intent();
    wrong_digest.candidate.digest = "0".repeat(64);
    let error = fixture
        .world
        .runtime
        .prepare_delivery(wrong_digest)
        .expect_err("a digest the ledger did not record must refuse");
    assert!(
        matches!(error, DeliveryError::DigestMismatch),
        "wrong digest refusal: {error}"
    );

    let mut unrecorded_version = fixture.intent();
    unrecorded_version.candidate.base_version = config::SHIPPED_BASE_VERSION + 1;
    let error = fixture
        .world
        .runtime
        .prepare_delivery(unrecorded_version)
        .expect_err("a base the ledger never recorded must refuse");
    assert!(
        matches!(
            error,
            DeliveryError::Candidate(BaseError::ReceiptMissing { .. })
        ),
        "wrong provenance refusal: {error}"
    );

    // Prepared against the right candidate, the bytes at delivery must still be
    // the exact candidate: changed bytes never overwrite the destination.
    let prepared = fixture.prepare();
    let error = fixture
        .world
        .runtime
        .deliver_change(&prepared, b"bytes that are not the candidate")
        .expect_err("differing bytes must refuse before the effect");
    assert!(
        matches!(error, DeliveryError::Integrity),
        "wrong integrity refusal: {error}"
    );
    assert_eq!(
        fixture.destination_bytes(),
        fixture.seed(),
        "a differing candidate never overwrites the destination"
    );
    assert_eq!(
        fixture.rows(),
        (1, 0),
        "the refusal performs no effect and records no receipt"
    );
}

// ----- the remaining refusals: no row, a foreign row, a refused write -----

/// AC-080: an intent that names no staged row runs no effect, and a row this
/// intent never staged is refused rather than retried: a caller-chosen sequence
/// or a row of another candidate cannot address an effect.
#[test]
fn an_unprepared_or_foreign_intent_runs_no_effect() {
    let mut fixture = Fixture::open("unprepared");
    let unprepared = fixture.intent();
    let error = fixture
        .deliver(&unprepared)
        .expect_err("an intent without a staged row has no admission");
    assert!(
        matches!(error, DeliveryError::NotPrepared),
        "wrong unprepared refusal: {error}"
    );

    let foreign_seq = fixture
        .world
        .runtime
        .store_writer()
        .append_publication(
            DELIVERY_OWNER,
            &fixture.destination,
            &"0".repeat(64),
            None,
            None,
        )
        .expect("a row of another candidate is staged");
    let mut foreign = fixture.intent();
    foreign.admission_seq = Some(foreign_seq);
    let error = fixture
        .deliver(&foreign)
        .expect_err("a row of another candidate is not this intent's admission");
    assert!(
        matches!(error, DeliveryError::JournalMismatch),
        "wrong foreign-row refusal: {error}"
    );

    foreign.admission_seq = Some(foreign_seq + 1);
    let error = fixture
        .deliver(&foreign)
        .expect_err("a sequence no row carries is not an admission");
    assert!(
        matches!(error, DeliveryError::JournalMismatch),
        "wrong missing-row refusal: {error}"
    );

    assert_eq!(
        fixture.destination_bytes(),
        fixture.seed(),
        "no unadmitted intent writes a byte"
    );
    assert_eq!(
        fixture.rows(),
        (1, 0),
        "only the staged foreign row remains, with no receipt"
    );
}

/// AC-080: a managed write the destination refuses is a typed refusal, and the
/// intent stays pending — the crash-window recovery owns it, so no receipt is
/// invented for bytes that never landed.
#[test]
fn a_refused_managed_write_keeps_the_intent_pending() {
    let mut fixture = Fixture::open("write-refused");
    let prepared = fixture.prepare();
    seal_destination(&fixture.destination);

    let error = fixture
        .deliver(&prepared)
        .expect_err("a destination that refuses the write is a typed refusal");
    assert!(
        matches!(error, DeliveryError::Write(WorkerError::WriteFailed { .. })),
        "wrong managed-write refusal: {error}"
    );
    assert_eq!(
        fixture.destination_bytes(),
        fixture.seed(),
        "a refused write leaves the destination as it was"
    );
    assert_eq!(
        fixture.rows(),
        (1, 0),
        "the landed nothing keeps its intent pending with no receipt"
    );
}

// ----- unknown: no blind retry -----

/// AC-080/INV-005: when the retained intent cannot prove the destination state
/// (the receipt is absent and the bytes are neither the intended nor the
/// recorded base), the outcome is unknown, nothing is written, and a repeated
/// call is not a blind retry. Restoring the recorded base state lets the same
/// intent deliver exactly once.
#[test]
fn an_unprovable_destination_is_unknown_without_a_blind_retry() {
    let mut fixture = Fixture::open("unknown");
    let prepared = fixture.prepare();

    // The crash window a lost receipt leaves: the intent is durable, no receipt
    // exists, and a foreign publication now sits at the target.
    let foreign = b"an unrelated publication landed here".to_vec();
    std::fs::write(&fixture.destination, &foreign).expect("foreign bytes");
    assert_eq!(
        fixture.rows(),
        (1, 0),
        "the intent is retained and the receipt is absent"
    );

    let unknown = fixture
        .deliver(&prepared)
        .expect("the unprovable state is answered, not crashed");
    assert_eq!(unknown.outcome, DeliveryOutcome::Unknown);
    assert!(!unknown.applied, "an unknown outcome is not a receipt");
    assert_eq!(
        fixture.destination_bytes(),
        foreign,
        "an unknown outcome writes nothing"
    );

    let again = fixture
        .deliver(&prepared)
        .expect("a repeated call is answered the same way");
    assert_eq!(again.outcome, DeliveryOutcome::Unknown);
    assert_eq!(
        fixture.destination_bytes(),
        foreign,
        "a repeated call is not a blind retry"
    );
    assert_eq!(
        fixture.rows(),
        (1, 0),
        "the retained intent still holds and no receipt was invented"
    );

    // The recorded base state returns: the same intent delivers exactly once.
    std::fs::write(&fixture.destination, fixture.seed()).expect("restore the recorded base");
    let published = fixture
        .deliver(&prepared)
        .expect("the recorded base state admits the one effect");
    assert_eq!(published.outcome, DeliveryOutcome::Published);
    assert_eq!(
        fixture.destination_bytes(),
        fixture.bytes,
        "the one admitted effect landed"
    );
    assert_eq!(fixture.rows(), (0, 1));
}

/// AC-080: identical bytes at another inode are not this delivery's effect. The
/// staged occupant is gone, so the state is unknown — never a receipt for bytes
/// another file wrote.
#[test]
fn a_byte_identical_file_at_another_inode_is_not_this_delivery() {
    let mut fixture = Fixture::open("third-file");
    let prepared = fixture.prepare();
    std::fs::remove_file(&fixture.destination).expect("replace the destination");
    std::fs::write(&fixture.destination, &fixture.bytes).expect("a third file's bytes");

    let unknown = fixture
        .deliver(&prepared)
        .expect("a third file's bytes are answered, not receipted");
    assert_eq!(unknown.outcome, DeliveryOutcome::Unknown);
    assert!(!unknown.applied, "a third file's bytes are not a receipt");
    assert_eq!(
        fixture.destination_bytes(),
        fixture.bytes,
        "an unknown outcome writes nothing"
    );
    assert_eq!(
        fixture.rows(),
        (1, 0),
        "the intent stays pending and no receipt was invented"
    );
}

/// AC-080: the staged occupant is what attributes the write. A destination
/// swapped to another inode still holding the recorded base bytes is refused
/// before any byte moves, so the managed write can never land on a file this
/// intent never observed.
#[test]
fn a_destination_swapped_to_another_inode_is_refused_before_the_effect() {
    let mut fixture = Fixture::open("swapped-inode");
    let prepared = fixture.prepare();
    std::fs::remove_file(&fixture.destination).expect("replace the destination");
    std::fs::write(&fixture.destination, fixture.seed())
        .expect("the same base bytes at a new inode");

    let error = fixture
        .deliver(&prepared)
        .expect_err("the staged occupant is gone");
    assert!(
        matches!(
            error,
            DeliveryError::Write(WorkerError::TargetChanged { .. })
        ),
        "wrong occupant refusal: {error}"
    );
    assert_eq!(
        fixture.destination_bytes(),
        fixture.seed(),
        "a refused write leaves the new file as it was"
    );
    assert_eq!(fixture.rows(), (1, 0), "the refusal records no receipt");
}

// ----- a lost receipt reconciles without repeating the effect -----

/// AC-080: when the effect landed and its receipt was lost (the crash window
/// the journal exists for), the next call completes the retained receipt from
/// the exact bytes and writes nothing. It kills a second `write_once` in the
/// exact-bytes branch: the digest and the row counts would look identical, and
/// the sealed destination plus its recorded identity and timestamps are what
/// refuse it.
#[test]
fn a_lost_receipt_reconciles_without_repeating_the_effect() {
    let mut fixture = Fixture::open("lost-receipt");
    let prepared = fixture.prepare();

    // The effect landed in place and the receipt was never recorded.
    std::fs::write(&fixture.destination, &fixture.bytes).expect("effect without its receipt");
    assert_eq!(
        fixture.rows(),
        (1, 0),
        "the row is still pending although the bytes hold"
    );

    seal_destination(&fixture.destination);
    let untouched = fixture.observed();
    let retained = fixture
        .deliver(&prepared)
        .expect("the exact bytes complete the retained receipt");
    assert_eq!(retained.outcome, DeliveryOutcome::Retained);
    assert!(retained.applied);
    assert_eq!(
        fixture.observed(),
        untouched,
        "completing the receipt repeats no write"
    );
    assert_eq!(
        fixture.destination_bytes(),
        fixture.bytes,
        "the exact bytes still hold"
    );
    assert_eq!(
        fixture.rows(),
        (0, 1),
        "the lost receipt is completed once and the effect is not repeated"
    );
}

// ----- the receipt is retained across a reopen -----

/// AC-080: the applied receipt is the journal's durable row. A reopened data
/// root serves the same row, and preparation reuses it instead of minting a
/// second intent or a second activation receipt.
#[test]
fn the_applied_receipt_survives_a_reopen() {
    support::ensure_helper();
    let root = temp_root("reopen-root");
    let scope = temp_root("reopen-scope");
    let (candidate, bytes) = served_candidate();
    let destination = seeded_destination(scope.path(), b"the previous release bytes");
    let receipt = {
        let mut world = support::open_world_at(root.path(), None);
        let grant = world
            .runtime
            .policy_writer()
            .grant_classes(scope.path().to_path_buf(), vec![EffectClass::Write]);
        let prepared = world
            .runtime
            .prepare_delivery(intent(&candidate, &destination, &grant))
            .expect("prepared");
        world
            .runtime
            .deliver_change(&prepared, &bytes)
            .expect("delivered")
    };

    let mut world = support::open_world_at(root.path(), None);
    let row = applied_row(world.runtime.store(), &destination);
    assert_eq!(row.target, destination);
    assert_eq!(row.intended_digest, candidate.digest);
    assert_eq!(row.admission_seq, receipt.admission_seq);

    let grant = world
        .runtime
        .policy_writer()
        .grant_classes(scope.path().to_path_buf(), vec![EffectClass::Write]);
    let prepared = world
        .runtime
        .prepare_delivery(intent(&candidate, &destination, &grant))
        .expect("the applied delivery is reused");
    assert_eq!(prepared.admission_seq, Some(receipt.admission_seq));
    assert_eq!(
        delivery_rows(world.runtime.store(), &destination),
        (0, 1),
        "no second intent or receipt is minted after a reopen"
    );
    let retained = world
        .runtime
        .deliver_change(&prepared, &bytes)
        .expect("the retained receipt answers");
    assert_eq!(retained.outcome, DeliveryOutcome::Retained);
    assert_eq!(
        std::fs::read(&destination).expect("destination bytes"),
        bytes
    );
}

/// AC-080: a pending intent whose effect already landed survives the process.
/// The startup recovery classifies it, receipts exactly the write it can
/// attribute, and never rewrites the destination — the bytes and their inode
/// are the same ones the killed process left. It covers the owner this span
/// otherwise leaves unproven: the startup path (`config::recover_publications`
/// through `Runtime::open`), not the in-process reconcile.
#[test]
fn a_pending_effect_that_survived_a_restart_is_receipted_once() {
    support::ensure_helper();
    let root = temp_root("restart-root");
    let scope = temp_root("restart-scope");
    let (candidate, bytes) = served_candidate();
    let destination = seeded_destination(scope.path(), b"the previous release bytes");
    let (landed, admission_seq) = {
        let mut world = support::open_world_at(root.path(), None);
        let grant = world
            .runtime
            .policy_writer()
            .grant_classes(scope.path().to_path_buf(), vec![EffectClass::Write]);
        let prepared = world
            .runtime
            .prepare_delivery(intent(&candidate, &destination, &grant))
            .expect("prepared");
        // The effect landed and the process died before the receipt.
        std::fs::write(&destination, &bytes).expect("effect without its receipt");
        assert_eq!(
            delivery_rows(world.runtime.store(), &destination),
            (1, 0),
            "the killed process leaves one pending intent"
        );
        (
            observed(&destination),
            prepared.admission_seq.expect("a staged row"),
        )
    };

    let mut world = support::open_world_at(root.path(), None);
    assert_eq!(
        delivery_rows(world.runtime.store(), &destination),
        (0, 1),
        "the boot receipts the landed write exactly once"
    );
    assert_eq!(
        observed(&destination),
        landed,
        "the boot never rewrites the bytes it receipts"
    );
    let row = applied_row(world.runtime.store(), &destination);
    assert_eq!(row.admission_seq, admission_seq);

    let grant = world
        .runtime
        .policy_writer()
        .grant_classes(scope.path().to_path_buf(), vec![EffectClass::Write]);
    let prepared = world
        .runtime
        .prepare_delivery(intent(&candidate, &destination, &grant))
        .expect("the receipted delivery is reused");
    let retained = world
        .runtime
        .deliver_change(&prepared, &bytes)
        .expect("the retained receipt answers");
    assert_eq!(retained.outcome, DeliveryOutcome::Retained);
    assert_eq!(
        delivery_rows(world.runtime.store(), &destination),
        (0, 1),
        "the retry mints no second receipt"
    );
    assert_eq!(
        std::fs::read(&destination).expect("destination bytes"),
        bytes,
        "the retry moves no byte"
    );
}

// ----- the applied row must still hold its bytes -----

/// AC-080: an applied row is only the answer while its bytes still hold there.
/// A destination that now carries foreign bytes is refused, never re-certified
/// as retained, and the applied row is left exactly as it was.
#[test]
fn an_applied_row_that_no_longer_holds_its_bytes_is_refused() {
    let mut fixture = Fixture::open("drift");
    let prepared = fixture.prepare();
    fixture
        .deliver(&prepared)
        .expect("the effect is admitted and receipted");
    let row = fixture.applied();

    let foreign = b"another release landed over the delivered bytes".to_vec();
    std::fs::write(&fixture.destination, &foreign).expect("foreign bytes");

    let error = fixture
        .deliver(&prepared)
        .expect_err("an applied destination that changed is not retained");
    assert!(
        matches!(error, DeliveryError::Differing),
        "wrong drift refusal: {error}"
    );
    assert_eq!(
        fixture.destination_bytes(),
        foreign,
        "a refused drift writes nothing"
    );
    assert_eq!(
        fixture.applied(),
        row,
        "the applied row is not rewritten by the refusal"
    );
    assert_eq!(
        fixture.rows(),
        (0, 1),
        "no second receipt is minted for the drifted destination"
    );
}

// ----- one journal, two owners -----

/// AC-080/AC-095: the publication journal is shared, so a pending delivery row
/// whose digest equals a config edit's rendered bytes is not that edit's
/// admission. The edit stages its own row, lands its bytes, and the delivery row
/// stays pending and untouched — a foreign row can never answer an edit that was
/// never written.
#[test]
fn a_delivery_row_never_satisfies_a_config_edit() {
    support::ensure_helper();
    let root = temp_root("crossing-root");
    let user = support::base_config();
    let mut world = support::open_world_at(root.path(), Some(&user));
    let config_path = root.path().join("config.toml");
    let mut parsed = config::Config::parse_validated(&user).expect("the document validates");
    let edit = parsed
        .set("context.auto_compact", config::ConfigValue::Bool(true))
        .expect("the edit builds");

    // The delivery's pending intent names the same file and the same bytes the
    // edit would render: before the owner rule this row was the edit's answer.
    let target_key = config_path.to_str().expect("utf-8 config path").to_string();
    let delivery_seq = world
        .runtime
        .store_writer()
        .append_publication(DELIVERY_OWNER, &target_key, &edit.digest, None, None)
        .expect("a delivery intent is staged");

    let admission = world
        .runtime
        .store_writer()
        .admit_publication(CONFIG_CARRIER_OWNER, &config_path, &edit)
        .expect("the edit is admitted");
    let staged = match admission {
        PublicationAdmission::Staged(staged) => staged,
        other => unreachable!("a delivery row is not this edit's admission: {other:?}"),
    };
    assert_eq!(staged.owner, CONFIG_CARRIER_OWNER);
    assert_ne!(
        staged.admission_seq, delivery_seq,
        "the edit mints its own admission"
    );

    world
        .runtime
        .store_writer()
        .publish_intent(&staged, &edit.bytes)
        .expect("the edit lands");
    assert_eq!(
        std::fs::read(&config_path).expect("config bytes"),
        edit.bytes,
        "the user's edit is on disk, not lost to the delivery row"
    );
    let pending = world.runtime.store().pending_publications().expect("rows");
    assert!(
        pending
            .iter()
            .any(|row| row.owner == DELIVERY_OWNER && row.admission_seq == delivery_seq),
        "the delivery's own intent is left exactly as it was staged"
    );
}

// ----- an occupant the filesystem cannot attest -----

/// AC-080: a journaled occupant no reuse token can confirm answers the
/// capability class itself. The row is staged with an unattested identity (the
/// journal reads such a row back as `Unrecorded`), so both the admission and the
/// retained delivery refuse it as a capability fact — never as another file's
/// row and never as an unprovable state whose bytes could be receipted. It kills
/// the collapse of `Unverifiable` into `Different`: that rule would admit a
/// second intent for the same bytes and answer `Unknown` — or, worse, a
/// receipt — at delivery.
#[test]
fn an_unattested_occupant_is_a_capability_refusal() {
    let mut fixture = Fixture::open("unattested");
    let base_digest = config::hex(&seed_digest(fixture.seed()));
    let identity = {
        let metadata = std::fs::metadata(&fixture.destination).expect("destination metadata");
        WriteIdentity::new(
            FileIdentity::from_metadata(&metadata),
            Err(Unattested::Unrecorded),
        )
    };
    let admission_seq = fixture
        .world
        .runtime
        .store_writer()
        .append_publication(
            DELIVERY_OWNER,
            &fixture.destination,
            &fixture.candidate.digest,
            Some(&base_digest),
            Some(identity),
        )
        .expect("a row with an unattested occupant is staged");

    let error = fixture
        .world
        .runtime
        .prepare_delivery(fixture.intent())
        .expect_err("an unattested occupant is not this delivery's row");
    assert!(
        matches!(
            &error,
            DeliveryError::Write(WorkerError::WriteIdentityUnattested { .. })
        ),
        "wrong unattested admission: {error}"
    );
    assert_eq!(
        error.code(),
        ErrorCode::CapabilityUnavailable,
        "the admission names the capability, never a conflict"
    );
    assert_eq!(fixture.rows(), (1, 0), "the admission stages no second row");

    // The intended bytes already hold, and the retained row still cannot prove
    // its occupant: it neither receipts them nor calls the state unknown.
    std::fs::write(&fixture.destination, &fixture.bytes).expect("the intended bytes hold");
    let mut prepared = fixture.intent();
    prepared.admission_seq = Some(admission_seq);
    let error = fixture
        .deliver(&prepared)
        .expect_err("an unattested occupant completes no receipt");
    assert!(
        matches!(
            &error,
            DeliveryError::Write(WorkerError::WriteIdentityUnattested { .. })
        ),
        "wrong unattested delivery: {error}"
    );
    assert_eq!(
        error.code(),
        ErrorCode::CapabilityUnavailable,
        "the delivery names the capability, never a conflict"
    );
    assert_eq!(
        fixture.rows(),
        (1, 0),
        "no receipt is invented for an occupant no rule confirmed"
    );
    assert_eq!(
        fixture.destination_bytes(),
        fixture.bytes,
        "the refusal moves no byte"
    );
}
