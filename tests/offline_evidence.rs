//! Offline evidence receipt validation (TD-16/TD-17): the checked-in
//! manifest binds 222 rows, the current receipt projects 216 passes and six
//! terminal unserved rows, and every malformed/stale/duplicate/shrunken/
//! unmarked target or receipt is refused. The producer's argument surface is
//! exercised without running a target.

#![allow(
    clippy::expect_used,
    clippy::panic,
    reason = "receipt assertions fail loudly with the offending mutant; src/ stays strict (standards §14)"
)]

use rivect::verification::{
    EvidenceRow, OFFLINE_EVIDENCE_PRODUCER_VERSION, OFFLINE_EVIDENCE_SCHEMA, OfflineEvidenceCounts,
    OfflineEvidenceManifest, OfflineEvidenceReceipt, OfflineEvidenceTarget, TrialExpectation,
    TrialOutcome,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::process::Command;

fn manifest_bytes() -> Vec<u8> {
    std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/provider-trials.json"
    ))
    .expect("the checked-in provider trial manifest is readable")
}

fn manifest() -> OfflineEvidenceManifest {
    OfflineEvidenceManifest::load(&manifest_bytes()).expect("the manifest validates")
}

fn digest(bytes: &[u8]) -> String {
    rivect::config::hex(&Sha256::digest(bytes))
}

fn current_receipt() -> OfflineEvidenceReceipt {
    let manifest = manifest();
    let rows: Vec<EvidenceRow> = manifest
        .rows
        .iter()
        .map(|row| EvidenceRow {
            case_id: row.case_id.clone(),
            evidence: row.oracle.first().expect("one oracle").clone(),
            marker: row.marker.clone(),
            outcome: match row.expected {
                TrialExpectation::Pass => TrialOutcome::Pass,
                TrialExpectation::Unserved => TrialOutcome::Unserved,
            },
        })
        .collect();
    let mut cases: BTreeMap<String, u32> = BTreeMap::new();
    for row in &rows {
        let target = row
            .evidence
            .split_once("::")
            .expect("target::test")
            .0
            .to_string();
        *cases.entry(target).or_default() += 1;
    }
    let targets = cases
        .into_iter()
        .map(|(target, cases)| OfflineEvidenceTarget {
            command: format!("cargo test --locked --test {target} -- --nocapture"),
            target,
            exit: 0,
            output_sha256: "a".repeat(64),
            cases,
        })
        .collect();
    OfflineEvidenceReceipt {
        schema_version: OFFLINE_EVIDENCE_SCHEMA,
        producer_version: OFFLINE_EVIDENCE_PRODUCER_VERSION.to_string(),
        family: "provider".to_string(),
        candidate_manifest_sha256: "b".repeat(64),
        manifest_sha256: digest(&manifest_bytes()),
        targets,
        rows,
        counts: OfflineEvidenceCounts {
            rows: 222,
            pass: 216,
            unserved: 6,
        },
    }
}

#[test]
fn current_receipt_projects_216_pass_and_6_unserved() {
    let manifest_bytes = manifest_bytes();
    let manifest = OfflineEvidenceManifest::load(&manifest_bytes).expect("the manifest");
    let receipt = current_receipt();
    receipt
        .validate(&manifest_bytes, &manifest)
        .expect("the current receipt validates");
    assert_eq!(receipt.rows.len(), 222);
    assert_eq!(receipt.counts.pass, 216);
    assert_eq!(receipt.counts.unserved, 6);
    assert_eq!(
        receipt
            .rows
            .iter()
            .filter(|row| row.outcome == TrialOutcome::Pass)
            .count(),
        216
    );
    assert_eq!(
        receipt
            .rows
            .iter()
            .filter(|row| row.outcome == TrialOutcome::Unserved)
            .count(),
        6
    );
    assert_eq!(
        receipt
            .rows
            .iter()
            .filter(|row| row.outcome == TrialOutcome::Unserved)
            .map(|row| row.case_id.as_str())
            .collect::<Vec<_>>(),
        vec![
            "TP-PROVIDER-AUTH::cursor",
            "TP-PROVIDER-WIRE::cursor",
            "TP-PROVIDER-RECOVERY::cursor",
            "TP-PROVIDER-AUTH::devin",
            "TP-PROVIDER-WIRE::devin",
            "TP-PROVIDER-RECOVERY::devin",
        ]
    );
}

fn refused(receipt: &mut OfflineEvidenceReceipt, manifest: &OfflineEvidenceManifest) {
    assert!(
        receipt.validate(&manifest_bytes(), manifest).is_err(),
        "the mutant must be refused: {receipt:?}"
    );
}

#[test]
fn malformed_stale_duplicate_and_shrunken_receipts_are_refused() {
    let manifest_bytes = manifest_bytes();
    let manifest = OfflineEvidenceManifest::load(&manifest_bytes).expect("the manifest");

    let mut wrong_schema = current_receipt();
    wrong_schema.schema_version = 2;
    refused(&mut wrong_schema, &manifest);

    let mut wrong_producer = current_receipt();
    wrong_producer.producer_version = "2".to_string();
    refused(&mut wrong_producer, &manifest);

    let mut unknown_family = current_receipt();
    unknown_family.family = "mystery".to_string();
    refused(&mut unknown_family, &manifest);

    let mut stale = current_receipt();
    stale.manifest_sha256 = "c".repeat(64);
    refused(&mut stale, &manifest);

    let mut candidate_short = current_receipt();
    candidate_short.candidate_manifest_sha256 = "b".repeat(63);
    refused(&mut candidate_short, &manifest);

    let mut candidate_non_hex = current_receipt();
    candidate_non_hex.candidate_manifest_sha256 = "z".repeat(64);
    refused(&mut candidate_non_hex, &manifest);

    let mut shrunken = current_receipt();
    shrunken.rows.pop().expect("one row");
    shrunken.counts.pass = shrunken
        .rows
        .iter()
        .filter(|row| row.outcome == TrialOutcome::Pass)
        .count();
    shrunken.counts.unserved = shrunken
        .rows
        .iter()
        .filter(|row| row.outcome == TrialOutcome::Unserved)
        .count();
    shrunken.counts.rows = shrunken.rows.len();
    refused(&mut shrunken, &manifest);

    let mut duplicate = current_receipt();
    let duplicate_row = duplicate.rows[0].clone();
    duplicate.rows[1] = duplicate_row;
    refused(&mut duplicate, &manifest);

    let mut unknown_case = current_receipt();
    unknown_case.rows[0].case_id = "TP-PROVIDER-AUTH::unrecorded".to_string();
    unknown_case.rows[0].marker = "ROW TP-PROVIDER-AUTH::unrecorded ok".to_string();
    refused(&mut unknown_case, &manifest);

    let mut missing_case = current_receipt();
    missing_case.rows.remove(0);
    refused(&mut missing_case, &manifest);

    let mut empty_evidence = current_receipt();
    empty_evidence.rows[0].evidence.clear();
    refused(&mut empty_evidence, &manifest);

    let mut empty_marker = current_receipt();
    empty_marker.rows[0].marker.clear();
    refused(&mut empty_marker, &manifest);

    let mut lib_target = current_receipt();
    lib_target.rows[0].evidence = "lib::some_test".to_string();
    refused(&mut lib_target, &manifest);

    let mut bin_target = current_receipt();
    bin_target.rows[0].evidence = "bin::some_test".to_string();
    refused(&mut bin_target, &manifest);

    let mut missing_target = current_receipt();
    missing_target.rows[0].evidence =
        "provider_registry::roster_matches_the_recorded_dialect_arms".to_string();
    refused(&mut missing_target, &manifest);

    let mut failed_target = current_receipt();
    failed_target.targets[0].exit = 1;
    refused(&mut failed_target, &manifest);

    let mut malformed_output = current_receipt();
    malformed_output.targets[0].output_sha256 = "not-a-digest".to_string();
    refused(&mut malformed_output, &manifest);

    let mut wrong_marker = current_receipt();
    wrong_marker.rows[0].marker = "ROW TP-PROVIDER-AUTH::meta ok".to_string();
    refused(&mut wrong_marker, &manifest);

    let mut wrong_outcome = current_receipt();
    let first_pass = wrong_outcome
        .rows
        .iter_mut()
        .find(|row| row.outcome == TrialOutcome::Pass)
        .expect("one pass row");
    first_pass.outcome = TrialOutcome::Unserved;
    wrong_outcome.counts.pass = wrong_outcome
        .rows
        .iter()
        .filter(|row| row.outcome == TrialOutcome::Pass)
        .count();
    wrong_outcome.counts.unserved = wrong_outcome
        .rows
        .iter()
        .filter(|row| row.outcome == TrialOutcome::Unserved)
        .count();
    refused(&mut wrong_outcome, &manifest);

    let mut counts_mismatch = current_receipt();
    counts_mismatch.counts.pass = 215;
    refused(&mut counts_mismatch, &manifest);

    let mut unserved_outside = current_receipt();
    let row = unserved_outside
        .rows
        .iter_mut()
        .find(|row| row.case_id == "TP-PROVIDER-AUTH::openai")
        .expect("the openai auth row");
    row.outcome = TrialOutcome::Unserved;
    unserved_outside.counts.pass -= 1;
    unserved_outside.counts.unserved += 1;
    refused(&mut unserved_outside, &manifest);
}

#[test]
fn roster_test_without_its_marker_is_refused() {
    let manifest_bytes = manifest_bytes();
    let mut manifest = OfflineEvidenceManifest::load(&manifest_bytes).expect("the manifest");
    manifest.rows[0].oracle =
        vec!["provider_registry::roster_matches_the_recorded_dialect_arms".to_string()];
    manifest.rows[0].marker.clear();

    let mut receipt = current_receipt();
    receipt.rows[0].evidence =
        "provider_registry::roster_matches_the_recorded_dialect_arms".to_string();
    receipt.rows[0].marker.clear();
    assert!(
        receipt.validate(&manifest_bytes, &manifest).is_err(),
        "a generic roster row without its marker is refused"
    );

    let mut unmarked = current_receipt();
    unmarked.rows[0].marker = String::new();
    refused(&mut unmarked, &manifest);
}

#[test]
fn producer_help_and_bad_arguments_exit_two() {
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/offline-evidence.sh");
    let help = Command::new("sh")
        .arg(script)
        .arg("--help")
        .output()
        .expect("the producer script runs");
    assert!(help.status.success(), "{help:?}");
    assert!(
        String::from_utf8_lossy(&help.stdout).contains("usage: offline-evidence.sh"),
        "{help:?}"
    );

    let no_args = Command::new("sh")
        .arg(script)
        .output()
        .expect("the producer script runs");
    assert_eq!(no_args.status.code(), Some(2), "{no_args:?}");

    let unknown = Command::new("sh")
        .arg(script)
        .arg("--nope")
        .output()
        .expect("the producer script runs");
    assert_eq!(unknown.status.code(), Some(2), "{unknown:?}");

    let missing = Command::new("sh")
        .arg(script)
        .args([
            "--manifest",
            "tests/fixtures/provider-trials.json",
            "--receipt",
            "target/provider-trials.json",
            "--bundle",
            "/nonexistent-rivect-bundle",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("the producer script runs");
    assert_eq!(missing.status.code(), Some(2), "{missing:?}");
}
