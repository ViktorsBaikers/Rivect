//! AC-082 (REQ-068): the final release conjunction. One counted plan carries
//! A01–A36, §17–§17.2, the upgrade confirmation and the two installed-release
//! legs, the 74 provider rows under five trial classes plus both alias rows
//! (74×5+2 = 372, of which the installed TP contributes 76), and the
//! 19×G×I installed UI matrix. A row bound to another candidate is stale; a
//! missing, stale, failed, censored or unattributed row prevents a full pass.
//!
//! The ordinary installed-release leg is passed on the repaired candidate:
//! the packaged artifact publishes and settles an ordinary first task. The
//! installed UI matrix renders all 19 states under each theme through the
//! packaged `--ui-review` entry: its report carries 285 state×theme
//! observations with per-state status/dock/composer/modal SGR fingerprints,
//! so the row is PASS evidence when the candidate, every cell and every
//! renderer-only claim match. The run prints the stable verdict line; the
//! full-pass claim stays SLICE-010/Seal, while real provider, publication
//! and platform legs stay NOT_RUN.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::let_underscore_must_use,
    let_underscore_drop,
    clippy::redundant_clone,
    reason = "final-acceptance assertions fail loudly with the counted row or verdict; src/ stays strict (standards §14)"
)]

mod support;

use rivect::contracts::RELEASE_MANIFEST_NAME;
use rivect::executor::verify_release_bundle;
use rivect::providers::{Dialect, dialect_for};
use rivect::verification::{
    ALIAS_ROWS, EvidenceRow, FINAL_INSTALLED_ROWS, FINAL_PROVIDER_ROWS, FINAL_UI_CELLS,
    FinalAcceptanceError, FinalDeclaration, FinalRow, INSTALLED_ORDINARY_CASE, INSTALLED_UI_CASE,
    OfflineEvidenceCounts, OfflineEvidenceManifest, OfflineEvidenceReceipt, OfflineEvidenceTarget,
    PROVIDER_ROWS, PROVIDER_TRIALS, RELEASE_CASE_IDS, RELEASE_SECTIONS, SEARCH_SERVICES,
    SEARCH_TRIALS, SOURCE_SCENARIOS, TrialExpectation, TrialOutcome, UI_GEOMETRIES, UI_INPUTS,
    UI_STATES, UPGRADE_CASE, alias_case, conjunction_cells, evaluate_final, final_required_cases,
    is_unserved_case, provider_case, ui_case,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const INSTALLED_ORDINARY_EVIDENCE_MARKER: &str = "#installed-ordinary";
const INSTALLED_UI_EVIDENCE_MARKER: &str = "#installed-ui";

/// The three rendered themes and the observation each state must carry.
const THEMES: [&str; 3] = ["light", "dark", "high-contrast"];
/// Every state carries one observation per geometry and theme.
const THEME_OBSERVATIONS: usize = UI_STATES.len() * UI_GEOMETRIES.len() * THEMES.len();
/// One mono probe per state, geometry and theme.
const MONO_PROBES: usize = THEME_OBSERVATIONS;
/// One `TERM=dumb` label probe per state.
const DUMB_PROBES: usize = UI_STATES.len();
/// The recorded matrix gate.
const MATRIX_BUDGET_SECONDS: f64 = 900.0;

/// The renderer-only claim each of these states' passing cells must carry,
/// character for character. A missing or altered claim is a malformed report:
/// a seeded frame must never read as production evidence.
const RENDERER_ONLY_CLAIMS: [(&str, &str); 4] = [
    (
        "awaiting-permission",
        "renderer-only: no production approval/decision path opens the permission panel; the Ask verdict carries no class or target and the sole constructor is the passive `--ui-review` renderer in src/ui/review.rs (DEC-017)",
    ),
    (
        "streaming-long-output",
        "renderer-only: no production producer feeds view.output (the step-driver feed is deferred); the frame proves the renderer paints the seeded stream",
    ),
    (
        "error-offline-partial",
        "renderer-only: no production producer feeds view.output (the step-driver feed is deferred); the frame proves the renderer paints the seeded stream",
    ),
    (
        "non-tty",
        "renderer-only: the non-TTY entry routes to the structured headless loop; the TUI cannot paint this state in production",
    ),
];

fn renderer_only_claim(state: &str) -> Option<&'static str> {
    RENDERER_ONLY_CLAIMS
        .iter()
        .find(|(claimed, _)| *claimed == state)
        .map(|(_, claim)| *claim)
}

fn passed(case_id: String, candidate: &str, evidence: String) -> FinalRow {
    FinalRow {
        case_id,
        candidate: candidate.to_string(),
        outcome: TrialOutcome::Pass,
        evidence: Some(evidence),
        cause: None,
    }
}

fn censored(case_id: String, candidate: &str, cause: String) -> FinalRow {
    FinalRow {
        case_id,
        candidate: candidate.to_string(),
        outcome: TrialOutcome::Censored,
        evidence: None,
        cause: Some(cause),
    }
}

fn failed(case_id: String, candidate: &str, cause: String) -> FinalRow {
    FinalRow {
        case_id,
        candidate: candidate.to_string(),
        outcome: TrialOutcome::Fail,
        evidence: None,
        cause: Some(cause),
    }
}

fn counted(candidate: &str, rows: &[FinalRow]) -> rivect::verification::FinalAcceptance {
    evaluate_final(candidate, FinalDeclaration::release(), rows).expect("counted final conjunction")
}

fn expected_required_rows() -> usize {
    SOURCE_SCENARIOS.len()
        + RELEASE_SECTIONS.len()
        + RELEASE_CASE_IDS.len()
        + FINAL_PROVIDER_ROWS
        + SEARCH_SERVICES.len() * SEARCH_TRIALS.len()
        + FINAL_UI_CELLS
}

fn complete_rows(candidate: &str) -> Vec<FinalRow> {
    final_required_cases()
        .into_iter()
        .map(|case_id| passed(case_id.clone(), candidate, format!("fixture:{case_id}")))
        .collect()
}

#[test]
fn final_conjunction_fails_closed_on_missing_stale_and_shrunken_rows() {
    let candidate = "candidate-bytes";

    let complete = complete_rows(candidate);
    assert_eq!(FINAL_PROVIDER_ROWS, 372, "74x5+2 = 372");
    assert_eq!(
        FINAL_INSTALLED_ROWS, 76,
        "74 provider + 2 alias installed rows"
    );
    assert_eq!(FINAL_UI_CELLS, 1330, "19 x 5 x 14");
    assert_eq!(
        final_required_cases().len(),
        1764,
        "42 acceptance + 372 provider/alias + 20 search + 1330 ui"
    );
    let report = counted(candidate, &complete);
    assert!(
        report.full_pass,
        "a complete current set is a full pass: {report:?}"
    );
    assert_eq!(report.required, 1764);
    assert_eq!(report.passed, expected_required_rows());
    assert_eq!(
        report.provider_rows,
        PROVIDER_ROWS.len() * PROVIDER_TRIALS.len(),
        "74 x 5 provider trial rows"
    );
    assert_eq!(
        report.provider_rows + report.alias_rows,
        FINAL_PROVIDER_ROWS,
        "74x5+2 = 372"
    );
    assert_eq!(
        report.installed_rows, FINAL_INSTALLED_ROWS,
        "installed rows"
    );
    assert_eq!(report.ui_cells, FINAL_UI_CELLS, "19xGxI cells");

    // A missing required row is not a smaller denominator.
    let absent = provider_case("WIRE", "openai");
    let mut missing = complete.clone();
    missing.retain(|row| row.case_id != absent);
    let report = counted(candidate, &missing);
    assert!(!report.full_pass);
    assert!(report.blockers.missing.contains(&absent), "{report:?}");
    assert_eq!(report.present, expected_required_rows() - 1);
    assert_eq!(report.passed, expected_required_rows() - 1);

    // An evidence pointer bound to another candidate never substitutes for
    // current bytes.
    let mut stale = complete.clone();
    for row in &mut stale {
        if row.case_id == absent {
            row.candidate = "another-candidate".to_string();
        }
    }
    let report = counted(candidate, &stale);
    assert!(!report.full_pass);
    assert!(report.blockers.stale.contains(&absent), "{report:?}");
    assert_eq!(report.current, expected_required_rows() - 1);
    assert_eq!(report.passed, expected_required_rows() - 1);

    // A shrunken UI denominator is counted as missing cells, not as a pass.
    let mut shrunken = complete.clone();
    shrunken.retain(|row| !row.case_id.starts_with("UI::"));
    let report = counted(candidate, &shrunken);
    assert!(!report.full_pass);
    assert_eq!(report.ui_cells, 0);
    assert_eq!(report.blockers.missing.len(), FINAL_UI_CELLS);

    // A 372 installed-row claim is a rejected declaration.
    let claimed = FinalDeclaration {
        installed_rows: 372,
        ..FinalDeclaration::release()
    };
    assert!(matches!(
        evaluate_final(candidate, claimed, &complete),
        Err(FinalAcceptanceError::InstalledDenominator {
            declared: 372,
            expected: FINAL_INSTALLED_ROWS,
        })
    ));

    // A shrunken provider denominator is a rejected declaration.
    let shrunken_declaration = FinalDeclaration {
        provider_rows: FINAL_PROVIDER_ROWS - 1,
        ..FinalDeclaration::release()
    };
    assert!(matches!(
        evaluate_final(candidate, shrunken_declaration, &complete),
        Err(FinalAcceptanceError::ProviderDenominator { declared, expected })
            if declared == FINAL_PROVIDER_ROWS - 1 && expected == FINAL_PROVIDER_ROWS
    ));

    // A duplicated row is a rejected plan, not two pieces of evidence.
    let mut duplicated = complete.clone();
    duplicated.push(complete[0].clone());
    assert!(matches!(
        evaluate_final(candidate, FinalDeclaration::release(), &duplicated),
        Err(FinalAcceptanceError::RowCollision { .. })
    ));

    // A pass without a retained pointer is unattributed, never green.
    let mut pointerless = complete.clone();
    pointerless[0].evidence = None;
    let report = counted(candidate, &pointerless);
    assert!(!report.full_pass);
    assert_eq!(
        report.blockers.unattributed,
        vec![complete[0].case_id.clone()]
    );
}

fn provider_row_frame(id: u64, provider: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "provider.row",
        "params": {"schema_version": 1, "id": provider},
    })
}

fn run_packaged_frames(bundle: &Path, cwd: &Path, data_root: &str, frames: &[Value]) -> Output {
    let mut command = Command::new(bundle.join("rivect"));
    command
        .args(["--headless", "--data-root", data_root])
        .current_dir(cwd)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for name in ["PATH", "HOME", "TMPDIR", "LANG", "LC_ALL"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    let mut child = command.spawn().expect("spawn the packaged rivect");
    {
        let mut stdin = child.stdin.take().expect("packaged stdin");
        for frame in frames {
            writeln!(stdin, "{frame}").expect("write one frame");
        }
    }
    child
        .wait_with_output()
        .expect("wait for the packaged rivect")
}

fn responses(output: &Output) -> Vec<Value> {
    support::release::stdout_of(output)
        .lines()
        .map(|line| serde_json::from_str(line).expect("one JSON response frame"))
        .collect()
}

fn answer(answers: &[Value], id: u64) -> &Value {
    answers
        .iter()
        .find(|answer| answer["id"] == json!(id))
        .unwrap_or_else(|| panic!("no answer for id {id}: {answers:?}"))
}

fn recorded_dialect(provider: &str) -> &'static str {
    PROVIDER_ROWS
        .iter()
        .find(|(id, _dialect)| *id == provider)
        .map(|(_id, dialect)| *dialect)
        .expect("a recorded provider row")
}

fn expected_state(provider: &str) -> &'static str {
    match dialect_for(provider) {
        Some(Dialect::CursorAgent | Dialect::DevinAgent) => "unserved",
        Some(_) => "installed",
        None => "unrecorded",
    }
}

fn packaged_row(
    case_id: String,
    candidate: &str,
    result: &Value,
    provider: &str,
    alias_of: Option<&str>,
) -> FinalRow {
    let matches = result["kind"] == json!("provider.row")
        && result["id"] == json!(provider)
        && result["dialect"] == json!(recorded_dialect(provider))
        && result["state"] == json!(expected_state(provider))
        && alias_of.is_none_or(|canonical| result["alias_of"] == json!(canonical));
    if matches {
        passed(
            case_id,
            candidate,
            format!("packaged provider.row {provider} @ {candidate}"),
        )
    } else {
        failed(
            case_id,
            candidate,
            format!("packaged provider.row mismatch for {provider}: {result}"),
        )
    }
}

fn installed_rows(bundle: &Path, candidate: &str) -> Vec<FinalRow> {
    let root = tempfile::TempDir::with_prefix("rivect-final-installed-").expect("fixture root");
    let data = root.path().join("data root");
    let cwd = root.path().join("nested working dir");
    std::fs::create_dir_all(&data).expect("data root");
    std::fs::create_dir_all(&cwd).expect("nested cwd");
    let data_argument = data.to_str().expect("utf-8 data root");

    let mut frames = Vec::with_capacity(FINAL_INSTALLED_ROWS);
    for (index, (id, _dialect)) in PROVIDER_ROWS.iter().enumerate() {
        frames.push(provider_row_frame(index as u64 + 1, id));
    }
    for (index, (id, _canonical)) in ALIAS_ROWS.iter().enumerate() {
        let frame_id = PROVIDER_ROWS.len() as u64 + index as u64 + 1;
        frames.push(provider_row_frame(frame_id, id));
    }
    let output = run_packaged_frames(bundle, &cwd, data_argument, &frames);
    assert!(
        output.status.success(),
        "the packaged rows answered: {}",
        support::release::stderr_of(&output)
    );
    let answers = responses(&output);
    assert_eq!(answers.len(), frames.len(), "one answer per frame");

    let mut rows = Vec::with_capacity(FINAL_INSTALLED_ROWS);
    for (index, (id, _dialect)) in PROVIDER_ROWS.iter().enumerate() {
        let result = &answer(&answers, index as u64 + 1)["result"];
        rows.push(packaged_row(
            provider_case("INSTALLED", id),
            candidate,
            result,
            id,
            None,
        ));
    }
    for (index, (id, canonical)) in ALIAS_ROWS.iter().enumerate() {
        let frame_id = PROVIDER_ROWS.len() as u64 + index as u64 + 1;
        let result = &answer(&answers, frame_id)["result"];
        rows.push(packaged_row(
            alias_case(id),
            candidate,
            result,
            id,
            Some(canonical),
        ));
    }
    rows
}

fn catalog_rows(candidate: &str) -> Vec<FinalRow> {
    PROVIDER_ROWS
        .iter()
        .map(|(id, dialect)| {
            let case_id = provider_case("CATALOG", id);
            match dialect_for(id) {
                Some(observed) if observed.to_string() == *dialect => passed(
                    case_id,
                    candidate,
                    format!("providers::dialect_for({id}) = {observed}"),
                ),
                Some(observed) => failed(
                    case_id,
                    candidate,
                    format!("providers::dialect_for({id}) = {observed}, not {dialect}"),
                ),
                None => failed(
                    case_id,
                    candidate,
                    format!("providers::dialect_for({id}) answers no dialect"),
                ),
            }
        })
        .collect()
}

const PROVIDER_PRODUCER: &str = "sh scripts/offline-evidence.sh --manifest tests/fixtures/provider-trials.json --receipt target/provider-trials.json --bundle <dir>";

fn provider_manifest_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("provider-trials.json")
}

fn provider_receipt_path() -> PathBuf {
    std::env::var_os("RIVECT_PROVIDER_TRIALS_RECEIPT")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("target")
                .join("provider-trials.json")
        })
}

fn censored_provider_rows(candidate: &str, cause: String) -> Vec<FinalRow> {
    let mut rows = Vec::with_capacity(PROVIDER_ROWS.len() * 3);
    for (id, _dialect) in PROVIDER_ROWS {
        for trial in ["AUTH", "WIRE", "RECOVERY"] {
            rows.push(censored(provider_case(trial, id), candidate, cause.clone()));
        }
    }
    rows
}

/// Consume the candidate-current provider receipt. A missing, stale,
/// malformed or unmarked receipt contributes censored rows only; an
/// `unserved` row stays a terminal denial carried in its own count.
fn provider_trial_rows_from(
    manifest_path: &Path,
    receipt_path: &Path,
    candidate: &str,
) -> Vec<FinalRow> {
    let manifest_bytes = match std::fs::read(manifest_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            println!(
                "OFFLINE_ACCEPTANCE pending family=provider producer=\"{PROVIDER_PRODUCER}\" cause=\"{error}\""
            );
            return censored_provider_rows(
                candidate,
                format!("missing receipt: run {PROVIDER_PRODUCER}"),
            );
        }
    };
    let manifest = match OfflineEvidenceManifest::load(&manifest_bytes) {
        Ok(manifest) => manifest,
        Err(error) => {
            return censored_provider_rows(candidate, format!("malformed manifest: {error}"));
        }
    };
    let receipt_bytes = match std::fs::read(receipt_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            println!(
                "OFFLINE_ACCEPTANCE pending family=provider producer=\"{PROVIDER_PRODUCER}\" cause=\"{error}\""
            );
            return censored_provider_rows(
                candidate,
                format!("missing receipt: run {PROVIDER_PRODUCER}"),
            );
        }
    };
    let receipt = match OfflineEvidenceReceipt::load(&receipt_bytes) {
        Ok(receipt) => receipt,
        Err(error) => {
            return censored_provider_rows(candidate, format!("malformed receipt: {error}"));
        }
    };
    if let Err(error) = receipt.validate(&manifest_bytes, &manifest) {
        return censored_provider_rows(candidate, format!("invalid receipt: {error}"));
    }
    if receipt.candidate_manifest_sha256 != candidate {
        return censored_provider_rows(
            candidate,
            format!(
                "stale receipt: {} is not {candidate}",
                receipt.candidate_manifest_sha256
            ),
        );
    }
    receipt
        .rows
        .into_iter()
        .map(|row| {
            let evidence = format!("{}#{}", receipt_path.display(), row.evidence);
            match row.outcome {
                TrialOutcome::Pass => passed(row.case_id, candidate, evidence),
                TrialOutcome::Unserved => FinalRow {
                    case_id: row.case_id,
                    candidate: candidate.to_string(),
                    outcome: TrialOutcome::Unserved,
                    evidence: Some(evidence),
                    cause: Some("unserved: no installed adapter".to_string()),
                },
                TrialOutcome::Fail => failed(row.case_id, candidate, evidence),
                TrialOutcome::Censored => censored(
                    row.case_id,
                    candidate,
                    format!("receipt censored: {evidence}"),
                ),
            }
        })
        .collect()
}

fn provider_trial_rows(candidate: &str) -> Vec<FinalRow> {
    provider_trial_rows_from(
        &provider_manifest_path(),
        &provider_receipt_path(),
        candidate,
    )
}

fn provider_receipt(
    manifest_bytes: &[u8],
    manifest: &OfflineEvidenceManifest,
    candidate: &str,
) -> OfflineEvidenceReceipt {
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
        schema_version: 1,
        producer_version: "1".to_string(),
        family: "provider".to_string(),
        candidate_manifest_sha256: candidate.to_string(),
        manifest_sha256: rivect::config::hex(&Sha256::digest(manifest_bytes)),
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
fn provider_receipt_missing_stale_or_unmarked_is_never_pass() {
    let candidate = "b".repeat(64);
    let manifest_bytes = std::fs::read(provider_manifest_path()).expect("the manifest is readable");
    let manifest = OfflineEvidenceManifest::load(&manifest_bytes).expect("the manifest validates");
    let root = tempfile::TempDir::with_prefix("rivect-provider-receipt-").expect("temp");
    let receipt_path = root.path().join("provider-trials.json");
    let manifest_path = provider_manifest_path();

    let current = provider_receipt(&manifest_bytes, &manifest, &candidate);
    std::fs::write(
        &receipt_path,
        serde_json::to_vec(&current).expect("serialize the receipt"),
    )
    .expect("write the current receipt");
    let rows = provider_trial_rows_from(&manifest_path, &receipt_path, &candidate);
    assert_eq!(rows.len(), 222);
    assert_eq!(
        rows.iter()
            .filter(|row| row.outcome == TrialOutcome::Pass)
            .count(),
        216
    );
    assert_eq!(
        rows.iter()
            .filter(|row| row.outcome == TrialOutcome::Unserved)
            .count(),
        6
    );
    assert!(
        rows.iter()
            .all(|row| matches!(row.outcome, TrialOutcome::Pass | TrialOutcome::Unserved))
    );

    std::fs::remove_file(&receipt_path).expect("remove the receipt");
    let rows = provider_trial_rows_from(&manifest_path, &receipt_path, &candidate);
    assert_eq!(rows.len(), 222);
    assert!(
        rows.iter().all(|row| row.outcome == TrialOutcome::Censored),
        "a missing receipt is censored, never pass"
    );

    std::fs::write(
        &receipt_path,
        serde_json::to_vec(&provider_receipt(
            &manifest_bytes,
            &manifest,
            &"c".repeat(64),
        ))
        .expect("serialize the stale receipt"),
    )
    .expect("write the stale receipt");
    let rows = provider_trial_rows_from(&manifest_path, &receipt_path, &candidate);
    assert!(
        rows.iter().all(|row| row.outcome == TrialOutcome::Censored),
        "a stale receipt is censored, never pass"
    );

    let mut unmarked = provider_receipt(&manifest_bytes, &manifest, &candidate);
    unmarked.rows[0].marker.clear();
    std::fs::write(
        &receipt_path,
        serde_json::to_vec(&unmarked).expect("serialize the unmarked receipt"),
    )
    .expect("write the unmarked receipt");
    let rows = provider_trial_rows_from(&manifest_path, &receipt_path, &candidate);
    assert!(
        rows.iter().all(|row| row.outcome == TrialOutcome::Censored),
        "an unmarked receipt is censored, never pass"
    );

    let mut shrunken = provider_receipt(&manifest_bytes, &manifest, &candidate);
    shrunken.rows.pop();
    shrunken.counts.rows = shrunken.rows.len();
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
    std::fs::write(
        &receipt_path,
        serde_json::to_vec(&shrunken).expect("serialize the shrunken receipt"),
    )
    .expect("write the shrunken receipt");
    let rows = provider_trial_rows_from(&manifest_path, &receipt_path, &candidate);
    assert!(
        rows.iter().all(|row| row.outcome == TrialOutcome::Censored),
        "a shrunken receipt is censored, never pass"
    );
}

fn acceptance_receipt(
    manifest_bytes: &[u8],
    manifest: &OfflineEvidenceManifest,
    candidate: &str,
) -> OfflineEvidenceReceipt {
    let rows: Vec<EvidenceRow> = manifest
        .rows
        .iter()
        .map(|row| EvidenceRow {
            case_id: row.case_id.clone(),
            evidence: row.oracle.first().expect("one oracle").clone(),
            marker: row.marker.clone(),
            outcome: TrialOutcome::Pass,
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
        schema_version: 1,
        producer_version: "1".to_string(),
        family: "acceptance".to_string(),
        candidate_manifest_sha256: candidate.to_string(),
        manifest_sha256: rivect::config::hex(&Sha256::digest(manifest_bytes)),
        targets,
        counts: OfflineEvidenceCounts {
            rows: rows.len(),
            pass: rows.len(),
            unserved: 0,
        },
        rows,
    }
}

#[test]
fn acceptance_group_receipts_missing_stale_unmarked_short_or_swapped_are_never_pass() {
    let candidate = "d".repeat(64);
    let root = tempfile::TempDir::with_prefix("rivect-acceptance-receipts-").expect("temp");
    let mut groups: Vec<(&str, PathBuf, PathBuf)> = Vec::new();
    for group in ACCEPTANCE_GROUPS {
        let manifest_path = acceptance_manifest_path(group);
        let manifest_bytes = std::fs::read(&manifest_path).expect("checked manifest");
        let manifest = OfflineEvidenceManifest::load(&manifest_bytes).expect("manifest validates");
        let receipt_path = root.path().join(format!("{group}.json"));
        std::fs::write(
            &receipt_path,
            serde_json::to_vec(&acceptance_receipt(&manifest_bytes, &manifest, &candidate))
                .expect("serialize"),
        )
        .expect("write receipt");
        groups.push((group, manifest_path, receipt_path));
    }

    let rows = acceptance_rows_from(&groups, &candidate);
    assert_eq!(rows.len(), 40);
    assert!(
        rows.iter().all(|row| row.outcome == TrialOutcome::Pass),
        "every current marker-checked group row passes"
    );
    assert!(rows.iter().all(|row| row.evidence.is_some()));

    // A missing receipt censors its whole group, never a smaller denominator.
    let missing = groups.clone();
    let missing_path = missing[0].2.clone();
    std::fs::remove_file(&missing_path).expect("remove receipt");
    let rows = acceptance_rows_from(&missing, &candidate);
    assert_eq!(rows.len(), 40);
    assert!(
        group_is_censored(&rows, "a01-a12"),
        "a missing group receipt is censored"
    );
    let manifest = OfflineEvidenceManifest::load(
        &std::fs::read(acceptance_manifest_path("a01-a12")).expect("manifest"),
    )
    .expect("manifest");
    let manifest_bytes = std::fs::read(acceptance_manifest_path("a01-a12")).expect("manifest");
    std::fs::write(
        &missing_path,
        serde_json::to_vec(&acceptance_receipt(&manifest_bytes, &manifest, &candidate))
            .expect("serialize"),
    )
    .expect("restore receipt");

    // A stale receipt is censored.
    let stale = groups.clone();
    let stale_manifest_bytes =
        std::fs::read(acceptance_manifest_path("a13-a24")).expect("manifest");
    let stale_manifest = OfflineEvidenceManifest::load(&stale_manifest_bytes).expect("manifest");
    std::fs::write(
        &stale[1].2,
        serde_json::to_vec(&acceptance_receipt(
            &stale_manifest_bytes,
            &stale_manifest,
            &"e".repeat(64),
        ))
        .expect("serialize"),
    )
    .expect("write stale receipt");
    let rows = acceptance_rows_from(&stale, &candidate);
    assert!(
        group_is_censored(&rows, "a13-a24"),
        "a stale group receipt is censored"
    );

    // An unmarked receipt is censored.
    let unmarked = groups.clone();
    let unmarked_manifest_bytes =
        std::fs::read(acceptance_manifest_path("a25-a36")).expect("manifest");
    let unmarked_manifest =
        OfflineEvidenceManifest::load(&unmarked_manifest_bytes).expect("manifest");
    let mut unmarked_receipt =
        acceptance_receipt(&unmarked_manifest_bytes, &unmarked_manifest, &candidate);
    unmarked_receipt.rows[0].marker.clear();
    std::fs::write(
        &unmarked[2].2,
        serde_json::to_vec(&unmarked_receipt).expect("serialize"),
    )
    .expect("write unmarked receipt");
    let rows = acceptance_rows_from(&unmarked, &candidate);
    assert!(
        group_is_censored(&rows, "a25-a36"),
        "an unmarked group receipt is censored"
    );

    // A short receipt is a group-denominator refusal, censored whole.
    let short = groups.clone();
    let short_manifest_bytes =
        std::fs::read(acceptance_manifest_path("sections")).expect("manifest");
    let short_manifest = OfflineEvidenceManifest::load(&short_manifest_bytes).expect("manifest");
    let mut short_receipt = acceptance_receipt(&short_manifest_bytes, &short_manifest, &candidate);
    short_receipt.rows.pop();
    short_receipt.counts = OfflineEvidenceCounts {
        rows: short_receipt.rows.len(),
        pass: short_receipt.rows.len(),
        unserved: 0,
    };
    std::fs::write(
        &short[3].2,
        serde_json::to_vec(&short_receipt).expect("serialize"),
    )
    .expect("write short receipt");
    let rows = acceptance_rows_from(&short, &candidate);
    assert!(
        group_is_censored(&rows, "sections"),
        "a short group receipt is censored"
    );

    // A manifest carrying another group's rows is refused before the receipt.
    let mut swapped = groups.clone();
    swapped[0].1 = acceptance_manifest_path("sections");
    let rows = acceptance_rows_from(&swapped, &candidate);
    assert!(
        group_is_censored(&rows, "a01-a12"),
        "a cross-group manifest is censored"
    );
}

fn group_is_censored(rows: &[FinalRow], group: &str) -> bool {
    let ids: BTreeSet<String> = acceptance_group_ids(group).into_iter().collect();
    let mut count = 0;
    for row in rows.iter().filter(|row| ids.contains(&row.case_id)) {
        if row.outcome != TrialOutcome::Censored {
            return false;
        }
        count += 1;
    }
    count == ids.len()
}

#[test]
fn unserved_rows_are_terminal_and_never_passed() {
    let candidate = "candidate-current";
    let mut rows = complete_rows(candidate);
    let unserved: BTreeSet<String> = rivect::verification::unserved_cases().into_iter().collect();
    for row in &mut rows {
        if unserved.contains(&row.case_id) {
            row.outcome = TrialOutcome::Unserved;
            row.evidence = Some(format!("receipt#{}", row.case_id));
            row.cause = Some("unserved: no installed adapter".to_string());
        }
    }
    let report = counted(candidate, &rows);
    assert!(report.full_pass, "{report:?}");
    assert_eq!(report.unserved, 6);
    assert_eq!(report.passed, report.required - 6);
    assert!(report.blockers.is_empty(), "{report:?}");

    let mut promoted = rows.clone();
    let victim = promoted
        .iter_mut()
        .find(|row| row.case_id == "TP-PROVIDER-AUTH::openai")
        .expect("the openai auth row");
    victim.outcome = TrialOutcome::Unserved;
    assert!(matches!(
        evaluate_final(candidate, FinalDeclaration::release(), &promoted),
        Err(FinalAcceptanceError::UnservedOutsideRecordedSet { .. })
    ));
    assert!(!is_unserved_case("TP-PROVIDER-AUTH::openai"));
}

const SEARCH_PRODUCER: &str = "sh scripts/offline-evidence.sh --manifest tests/fixtures/search-trials.json --receipt target/search-trials.json --bundle <dir>";

fn search_manifest_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("search-trials.json")
}

fn search_receipt_path() -> PathBuf {
    std::env::var_os("RIVECT_SEARCH_TRIALS_RECEIPT")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("target")
                .join("search-trials.json")
        })
}

fn censored_search_rows(candidate: &str, cause: String) -> Vec<FinalRow> {
    conjunction_cells()
        .into_iter()
        .filter(|(case_id, _mode)| case_id.starts_with("TP-SEARCH-"))
        .map(|(case_id, _mode)| censored(case_id, candidate, cause.clone()))
        .collect()
}

/// Consume the candidate-current search receipt. A missing, stale, malformed
/// or unmarked receipt contributes the 20 censored cells only; a current one
/// maps every executed row to its terminal outcome.
fn search_rows_from(manifest_path: &Path, receipt_path: &Path, candidate: &str) -> Vec<FinalRow> {
    let manifest_bytes = match std::fs::read(manifest_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            println!(
                "OFFLINE_ACCEPTANCE pending family=search producer=\"{SEARCH_PRODUCER}\" cause=\"{error}\""
            );
            return censored_search_rows(
                candidate,
                format!("missing manifest: run {SEARCH_PRODUCER}"),
            );
        }
    };
    let manifest = match OfflineEvidenceManifest::load(&manifest_bytes) {
        Ok(manifest) => manifest,
        Err(error) => {
            return censored_search_rows(candidate, format!("malformed manifest: {error}"));
        }
    };
    let receipt_bytes = match std::fs::read(receipt_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            println!(
                "OFFLINE_ACCEPTANCE pending family=search producer=\"{SEARCH_PRODUCER}\" cause=\"{error}\""
            );
            return censored_search_rows(
                candidate,
                format!("missing receipt: run {SEARCH_PRODUCER}"),
            );
        }
    };
    let receipt = match OfflineEvidenceReceipt::load(&receipt_bytes) {
        Ok(receipt) => receipt,
        Err(error) => {
            return censored_search_rows(candidate, format!("malformed receipt: {error}"));
        }
    };
    if let Err(error) = receipt.validate(&manifest_bytes, &manifest) {
        return censored_search_rows(candidate, format!("invalid receipt: {error}"));
    }
    if receipt.candidate_manifest_sha256 != candidate {
        return censored_search_rows(
            candidate,
            format!(
                "stale receipt: {} is not {candidate}",
                receipt.candidate_manifest_sha256
            ),
        );
    }
    receipt
        .rows
        .into_iter()
        .map(|row| {
            let evidence = format!("{}#{}", receipt_path.display(), row.evidence);
            match row.outcome {
                TrialOutcome::Pass => passed(row.case_id, candidate, evidence),
                TrialOutcome::Unserved => FinalRow {
                    case_id: row.case_id,
                    candidate: candidate.to_string(),
                    outcome: TrialOutcome::Unserved,
                    evidence: Some(evidence),
                    cause: Some("unserved: no recorded search service".to_string()),
                },
                TrialOutcome::Fail => failed(row.case_id, candidate, evidence),
                TrialOutcome::Censored => censored(
                    row.case_id,
                    candidate,
                    format!("receipt censored: {evidence}"),
                ),
            }
        })
        .collect()
}

fn search_rows(candidate: &str) -> Vec<FinalRow> {
    search_rows_from(&search_manifest_path(), &search_receipt_path(), candidate)
}

fn search_receipt(
    manifest_bytes: &[u8],
    manifest: &OfflineEvidenceManifest,
    candidate: &str,
) -> OfflineEvidenceReceipt {
    let rows: Vec<EvidenceRow> = manifest
        .rows
        .iter()
        .map(|row| EvidenceRow {
            case_id: row.case_id.clone(),
            evidence: row.oracle.first().expect("one oracle").clone(),
            marker: row.marker.clone(),
            outcome: TrialOutcome::Pass,
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
        schema_version: 1,
        producer_version: "1".to_string(),
        family: "search".to_string(),
        candidate_manifest_sha256: candidate.to_string(),
        manifest_sha256: rivect::config::hex(&Sha256::digest(manifest_bytes)),
        targets,
        rows,
        counts: OfflineEvidenceCounts {
            rows: 20,
            pass: 20,
            unserved: 0,
        },
    }
}

#[test]
fn search_receipt_missing_stale_or_unmarked_is_never_pass() {
    let candidate = "d".repeat(64);
    let manifest_bytes = std::fs::read(search_manifest_path()).expect("the search manifest reads");
    let manifest =
        OfflineEvidenceManifest::load(&manifest_bytes).expect("the search manifest validates");
    let root = tempfile::TempDir::with_prefix("rivect-search-receipt-").expect("temp");
    let receipt_path = root.path().join("search-trials.json");
    let manifest_path = search_manifest_path();

    std::fs::write(
        &receipt_path,
        serde_json::to_vec(&search_receipt(&manifest_bytes, &manifest, &candidate))
            .expect("serialize the receipt"),
    )
    .expect("write the current receipt");
    let rows = search_rows_from(&manifest_path, &receipt_path, &candidate);
    assert_eq!(rows.len(), 20);
    assert!(
        rows.iter().all(|row| row.outcome == TrialOutcome::Pass),
        "a current receipt maps all 20 cells: {rows:?}"
    );

    std::fs::remove_file(&receipt_path).expect("remove the receipt");
    let rows = search_rows_from(&manifest_path, &receipt_path, &candidate);
    assert_eq!(rows.len(), 20);
    assert!(
        rows.iter().all(|row| row.outcome == TrialOutcome::Censored),
        "a missing receipt is censored, never pass"
    );

    std::fs::write(
        &receipt_path,
        serde_json::to_vec(&search_receipt(&manifest_bytes, &manifest, &"e".repeat(64)))
            .expect("serialize the stale receipt"),
    )
    .expect("write the stale receipt");
    let rows = search_rows_from(&manifest_path, &receipt_path, &candidate);
    assert!(
        rows.iter().all(|row| row.outcome == TrialOutcome::Censored),
        "a stale receipt is censored, never pass"
    );

    let mut unmarked = search_receipt(&manifest_bytes, &manifest, &candidate);
    unmarked.rows[0].marker.clear();
    std::fs::write(
        &receipt_path,
        serde_json::to_vec(&unmarked).expect("serialize the unmarked receipt"),
    )
    .expect("write the unmarked receipt");
    let rows = search_rows_from(&manifest_path, &receipt_path, &candidate);
    assert!(
        rows.iter().all(|row| row.outcome == TrialOutcome::Censored),
        "an unmarked receipt is censored, never pass"
    );
}

fn installed_receipt_path() -> PathBuf {
    std::env::var_os("RIVECT_INSTALLED_ORDINARY_RECEIPT")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("target")
                .join("installed-ordinary.json")
        })
}

fn read_receipt(path: &Path) -> Result<Value, String> {
    let bytes = std::fs::read(path).map_err(|error| format!("missing receipt: {error}"))?;
    serde_json::from_slice(&bytes).map_err(|error| format!("malformed receipt: {error}"))
}

fn check_candidate(receipt: &Value, candidate: &str) -> Result<(), String> {
    let recorded = receipt["candidate_manifest_sha256"]
        .as_str()
        .ok_or_else(|| "receipt names no candidate".to_string())?;
    if recorded != candidate {
        return Err(format!("receipt candidate {recorded} is stale"));
    }
    Ok(())
}

fn installed_ordinary_evidence(path: &Path, candidate: &str) -> Result<String, String> {
    let receipt = read_receipt(path)?;
    check_candidate(&receipt, candidate)?;
    if receipt["schema_version"] != json!(1) {
        return Err("receipt schema_version is not 1".to_string());
    }
    if receipt["status"] != json!("pass") {
        return Err(format!(
            "receipt status is {}",
            receipt["status"].as_str().unwrap_or("missing")
        ));
    }
    if receipt["sends"] != json!(1) || receipt["settlements"] != json!(1) {
        return Err("receipt does not record sends=1 settlements=1".to_string());
    }
    Ok(format!("{}#installed-ordinary", path.display()))
}

/// Parses the exact 19×5×14 identity once, shared by the acceptance receipt
/// and the cell projection. A duplicate, unknown or absent cell is refused.
fn matrix_identity(report: &Value) -> Result<BTreeMap<(String, String, String), String>, String> {
    let Some(cells) = report["cell_verdicts"].as_array() else {
        return Err("matrix carries no cell verdicts".to_string());
    };
    if cells.len() != FINAL_UI_CELLS {
        return Err(format!("matrix carries {} cells", cells.len()));
    }
    let mut expected = BTreeSet::new();
    for state in UI_STATES {
        for geometry in UI_GEOMETRIES {
            for input in UI_INPUTS {
                expected.insert((state.to_string(), geometry.to_string(), input.to_string()));
            }
        }
    }
    let mut observed = BTreeMap::new();
    for cell in cells {
        let (Some(state), Some(geometry), Some(input), Some(verdict)) = (
            cell["state"].as_str(),
            cell["geometry"].as_str(),
            cell["input"].as_str(),
            cell["verdict"].as_str(),
        ) else {
            return Err("matrix cell is missing a coordinate or verdict".to_string());
        };
        match verdict {
            "PASS" | "FAIL" => {}
            "NOT_RUN" => {
                return Err(format!(
                    "cell {state}/{geometry}/{input} is NOT_RUN; the theme cells are observations now, so no UI cell may stay unproven"
                ));
            }
            _ => {
                return Err(format!(
                    "cell {state}/{geometry}/{input} carries unknown verdict {verdict}"
                ));
            }
        }
        let key = (state.to_string(), geometry.to_string(), input.to_string());
        if !expected.contains(&key) {
            return Err(format!("matrix carries an unknown cell {key:?}"));
        }
        if observed.insert(key, verdict.to_string()).is_some() {
            return Err("matrix repeats a cell".to_string());
        }
    }
    if observed.len() != expected.len() {
        return Err("matrix is missing cells".to_string());
    }
    let pass = observed
        .values()
        .filter(|verdict| *verdict == "PASS")
        .count();
    let fail = observed
        .values()
        .filter(|verdict| *verdict == "FAIL")
        .count();
    let not_run = observed.len() - pass - fail;
    if report["cells"].as_u64() != Some(observed.len() as u64)
        || report["pass"].as_u64() != Some(pass as u64)
        || report["fail"].as_u64() != Some(fail as u64)
        || report["not_run"].as_u64() != Some(not_run as u64)
    {
        return Err("matrix summary does not match its cells".to_string());
    }
    Ok(observed)
}

/// One parsed surface fingerprint: `fg=Default|Idx(n);bg=Default;bold=bool`
/// with exactly those three fields. The format is pinned, so a placeholder
/// such as `a/b/c` or an RGB/truecolor claim is refused.
#[derive(Debug, PartialEq, Eq)]
struct Fingerprint {
    fg: Option<u8>,
    bold: bool,
}

fn parse_fingerprint(value: &str) -> Option<Fingerprint> {
    let mut fg = None;
    let mut background = false;
    let mut bold = None;
    let mut fields = 0usize;
    for field in value.split(';') {
        fields += 1;
        if field == "fg=Default" {
            fg = Some(None);
        } else if let Some(index) = field
            .strip_prefix("fg=Idx(")
            .and_then(|rest| rest.strip_suffix(')'))
        {
            fg = Some(Some(index.parse::<u8>().ok()?));
        } else if field == "bg=Default" {
            background = true;
        } else if field == "bold=false" {
            bold = Some(false);
        } else if field == "bold=true" {
            bold = Some(true);
        } else {
            return None;
        }
    }
    if fields != 3 || !background {
        return None;
    }
    Some(Fingerprint {
        fg: fg?,
        bold: bold?,
    })
}

/// The expected fingerprint per theme and surface, pinned independently of
/// the producer: light Blue/Magenta, dark Cyan/bright Magenta, high contrast
/// LightYellow/LightCyan/White with bold; body rows are Reset.
fn expected_fingerprint(theme: &str, surface: &str) -> &'static str {
    match (theme, surface) {
        ("light", "status" | "modal") => "fg=Idx(4);bg=Default;bold=false",
        ("light", "composer") => "fg=Idx(5);bg=Default;bold=false",
        ("light", "dock" | "transcript") => "fg=Default;bg=Default;bold=false",
        ("dark", "status" | "modal") => "fg=Idx(6);bg=Default;bold=false",
        ("dark", "composer") => "fg=Idx(13);bg=Default;bold=false",
        ("dark", "dock" | "transcript") => "fg=Default;bg=Default;bold=false",
        ("high-contrast", "status") => "fg=Idx(11);bg=Default;bold=true",
        ("high-contrast", "composer") => "fg=Idx(14);bg=Default;bold=true",
        ("high-contrast", "modal") => "fg=Idx(15);bg=Default;bold=true",
        ("high-contrast", "dock" | "transcript") => "fg=Default;bg=Default;bold=true",
        _ => panic!("no expected fingerprint for {theme}/{surface}"),
    }
}

fn require_fingerprint(
    state: &str,
    geometry: &str,
    theme: &str,
    surface: &str,
    value: &str,
) -> Result<(), String> {
    let Some(parsed) = parse_fingerprint(value) else {
        return Err(format!(
            "theme observation {state}/{geometry}/{theme} {surface} is not a fingerprint: {value:?}"
        ));
    };
    let Some(expected) = parse_fingerprint(expected_fingerprint(theme, surface)) else {
        return Err(format!(
            "the expected {theme}/{surface} fingerprint is malformed"
        ));
    };
    if parsed != expected {
        return Err(format!(
            "theme observation {state}/{geometry}/{theme} {surface} is {parsed:?}, not {expected:?}"
        ));
    }
    Ok(())
}

/// The report's 285 state×theme observations: every state, geometry and theme
/// appears exactly once; each carrier matches the pinned expected palette;
/// the two card states carry a painted modal and every other state `none`;
/// and the mono/dumb probes cover their whole sets.
fn theme_observations(report: &Value) -> Result<(), String> {
    if report["theme_observations"].as_u64() != Some(THEME_OBSERVATIONS as u64) {
        return Err("matrix carries no 285 state×theme observations".to_string());
    }
    let Some(observations) = report["theme_fingerprints"].as_array() else {
        return Err("matrix carries no theme fingerprints".to_string());
    };
    if observations.len() != THEME_OBSERVATIONS {
        return Err(format!(
            "matrix carries {} theme fingerprints",
            observations.len()
        ));
    }
    let mut seen = BTreeSet::new();
    for observation in observations {
        let (Some(state), Some(geometry), Some(theme)) = (
            observation["state"].as_str(),
            observation["geometry"].as_str(),
            observation["theme"].as_str(),
        ) else {
            return Err("theme observation is missing a coordinate".to_string());
        };
        if !UI_STATES.contains(&state)
            || !UI_GEOMETRIES.contains(&geometry)
            || !THEMES.contains(&theme)
        {
            return Err(format!(
                "theme observation names an unknown coordinate: {state}/{geometry}/{theme}"
            ));
        }
        if !seen.insert((state.to_string(), geometry.to_string(), theme.to_string())) {
            return Err(format!(
                "theme observation repeats a coordinate: {state}/{geometry}/{theme}"
            ));
        }
        for surface in ["status", "dock", "composer", "transcript"] {
            let Some(value) = observation[surface].as_str() else {
                return Err(format!(
                    "theme observation {state}/{geometry}/{theme} misses its {surface} fingerprint"
                ));
            };
            require_fingerprint(state, geometry, theme, surface, value)?;
        }
        let modal_state = matches!(state, "awaiting-decision" | "awaiting-permission");
        let Some(modal) = observation["modal"].as_str() else {
            return Err(format!(
                "theme observation {state}/{geometry}/{theme} misses its modal fingerprint"
            ));
        };
        if modal_state {
            require_fingerprint(state, geometry, theme, "modal", modal)?;
        } else if modal != "none" {
            return Err(format!(
                "theme observation {state}/{geometry}/{theme} paints a modal in a state with none"
            ));
        }
        if modal_state && modal == "none" {
            return Err(format!(
                "theme observation {state}/{geometry}/{theme} misses its painted modal"
            ));
        }
    }
    if seen.len() != THEME_OBSERVATIONS {
        return Err("theme observations do not cover every coordinate".to_string());
    }
    for state in UI_STATES {
        for theme in THEMES {
            let count = seen
                .iter()
                .filter(|(cell_state, _, cell_theme)| cell_state == state && cell_theme == theme)
                .count();
            if count != UI_GEOMETRIES.len() {
                return Err(format!(
                    "{state}/{theme} carries {count} observations, not one per geometry"
                ));
            }
        }
    }
    let mono = &report["mono_probes"];
    if mono["total"].as_u64() != Some(MONO_PROBES as u64)
        || mono["pass"].as_u64() != Some(MONO_PROBES as u64)
    {
        return Err(format!(
            "mono probes are not the full {MONO_PROBES}/{MONO_PROBES} set: {mono}"
        ));
    }
    let dumb = &report["dumb_probes"];
    if dumb["total"].as_u64() != Some(DUMB_PROBES as u64)
        || dumb["pass"].as_u64() != Some(DUMB_PROBES as u64)
    {
        return Err(format!(
            "dumb probes are not the full {DUMB_PROBES}/{DUMB_PROBES} set: {dumb}"
        ));
    }
    let inline = &report["inline_probes"];
    if inline["total"].as_u64() != Some(THEMES.len() as u64)
        || inline["pass"].as_u64() != Some(THEMES.len() as u64)
    {
        return Err(format!(
            "inline probes are not the full {}/{} set: {inline}",
            THEMES.len(),
            THEMES.len()
        ));
    }
    let runtime = report["runtime_seconds"].as_f64().unwrap_or(f64::INFINITY);
    if !(0.0..MATRIX_BUDGET_SECONDS).contains(&runtime) {
        return Err(format!(
            "matrix runtime {runtime:.1}s is outside the {MATRIX_BUDGET_SECONDS:.0}s gate"
        ));
    }
    Ok(())
}

fn installed_ui_evidence(path: &Path, candidate: &str) -> Result<String, String> {
    let report = read_receipt(path)?;
    check_candidate(&report, candidate)?;
    if report["schema_version"] != json!(1) {
        return Err("matrix schema_version is not 1".to_string());
    }
    let cells = matrix_identity(&report)?;
    theme_observations(&report)?;
    let pass = cells.values().filter(|verdict| *verdict == "PASS").count();
    let fail = cells.values().filter(|verdict| *verdict == "FAIL").count();
    if report["cells"] != json!(FINAL_UI_CELLS)
        || report["fail"] != json!(0)
        || report["pass"] != json!(FINAL_UI_CELLS)
        || report["not_run"] != json!(0)
        || pass != FINAL_UI_CELLS
        || fail != 0
    {
        return Err("matrix summary is not the declared all-PASS split".to_string());
    }
    // A passing renderer-only cell carries the exact claim that names its
    // evidence class; the mutant that drops or alters it is refused here.
    let Some(verdicts) = report["cell_verdicts"].as_array() else {
        return Err("matrix carries no cell verdicts".to_string());
    };
    for cell in verdicts {
        let state = cell["state"].as_str().unwrap_or_default();
        let Some(claim) = renderer_only_claim(state) else {
            continue;
        };
        if cell["verdict"] == "PASS" && cell["reason"].as_str() != Some(claim) {
            return Err(format!(
                "passing renderer-only cell {state}/{}/{} misses its claim: {}",
                cell["geometry"].as_str().unwrap_or_default(),
                cell["input"].as_str().unwrap_or_default(),
                cell["reason"].as_str().unwrap_or_default()
            ));
        }
    }
    Ok(format!("{}#installed-ui", path.display()))
}

/// The four checked acceptance-row groups: the three A-scenario blocks and
/// the sections+upgrade block. Each group carries its own receipt; the
/// conjunction refuses to count a group short of its checked rows.
const ACCEPTANCE_GROUPS: [&str; 4] = ["a01-a12", "a13-a24", "a25-a36", "sections"];

fn acceptance_group_ids(group: &str) -> Vec<String> {
    match group {
        "a01-a12" => SOURCE_SCENARIOS[..12]
            .iter()
            .map(|id| (*id).to_string())
            .collect(),
        "a13-a24" => SOURCE_SCENARIOS[12..24]
            .iter()
            .map(|id| (*id).to_string())
            .collect(),
        "a25-a36" => SOURCE_SCENARIOS[24..]
            .iter()
            .map(|id| (*id).to_string())
            .collect(),
        "sections" => RELEASE_SECTIONS
            .iter()
            .map(|id| (*id).to_string())
            .chain(std::iter::once(UPGRADE_CASE.to_string()))
            .collect(),
        other => panic!("unknown acceptance group {other}"),
    }
}

fn acceptance_manifest_path(group: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(format!("acceptance-rows-{group}.json"))
}

fn acceptance_receipt_path(group: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join(format!("acceptance-rows-{group}.json"))
}

fn acceptance_producer(group: &str) -> String {
    format!(
        "sh scripts/offline-evidence.sh --manifest tests/fixtures/acceptance-rows-{group}.json --receipt target/acceptance-rows-{group}.json --bundle <dir>"
    )
}

fn censored_acceptance_group(candidate: &str, group: &str, cause: String) -> Vec<FinalRow> {
    acceptance_group_ids(group)
        .into_iter()
        .map(|case_id| censored(case_id, candidate, cause.clone()))
        .collect()
}

/// Consume one checked acceptance group's candidate-current receipt. The
/// manifest must carry exactly that group's checked ids; the receipt must
/// validate against the checked-in bytes, name the acting candidate and carry
/// every marker. Any shortfall censors the whole group, never a smaller
/// denominator.
fn acceptance_group_rows(
    group: &str,
    manifest_path: &Path,
    receipt_path: &Path,
    candidate: &str,
) -> Vec<FinalRow> {
    let producer = acceptance_producer(group);
    let manifest_bytes = match std::fs::read(manifest_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            return censored_acceptance_group(
                candidate,
                group,
                format!("missing manifest: {error}; run {producer}"),
            );
        }
    };
    let manifest = match OfflineEvidenceManifest::load(&manifest_bytes) {
        Ok(manifest) => manifest,
        Err(error) => {
            return censored_acceptance_group(
                candidate,
                group,
                format!("malformed manifest: {error}"),
            );
        }
    };
    let expected: BTreeSet<String> = acceptance_group_ids(group).into_iter().collect();
    let observed: BTreeSet<String> = manifest
        .rows
        .iter()
        .map(|row| row.case_id.clone())
        .collect();
    if observed != expected {
        return censored_acceptance_group(
            candidate,
            group,
            "manifest rows are not the checked group".to_string(),
        );
    }
    let receipt_bytes = match std::fs::read(receipt_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            return censored_acceptance_group(
                candidate,
                group,
                format!("missing receipt: {error}; run {producer}"),
            );
        }
    };
    let receipt = match OfflineEvidenceReceipt::load(&receipt_bytes) {
        Ok(receipt) => receipt,
        Err(error) => {
            return censored_acceptance_group(
                candidate,
                group,
                format!("malformed receipt: {error}"),
            );
        }
    };
    if let Err(error) = receipt.validate(&manifest_bytes, &manifest) {
        return censored_acceptance_group(candidate, group, format!("invalid receipt: {error}"));
    }
    if receipt.candidate_manifest_sha256 != candidate {
        return censored_acceptance_group(
            candidate,
            group,
            format!(
                "stale receipt: {} is not {candidate}",
                receipt.candidate_manifest_sha256
            ),
        );
    }
    receipt
        .rows
        .into_iter()
        .map(|row| {
            let evidence = format!("{}#{}", receipt_path.display(), row.evidence);
            match row.outcome {
                TrialOutcome::Pass => passed(row.case_id, candidate, evidence),
                TrialOutcome::Fail => failed(row.case_id, candidate, evidence),
                TrialOutcome::Censored => censored(
                    row.case_id,
                    candidate,
                    format!("receipt censored: {evidence}"),
                ),
                TrialOutcome::Unserved => censored(
                    row.case_id,
                    candidate,
                    format!("acceptance rows are never unserved: {evidence}"),
                ),
            }
        })
        .collect()
}

fn acceptance_rows_from(groups: &[(&str, PathBuf, PathBuf)], candidate: &str) -> Vec<FinalRow> {
    let mut rows = Vec::with_capacity(40);
    for (group, manifest_path, receipt_path) in groups {
        rows.extend(acceptance_group_rows(
            group,
            manifest_path,
            receipt_path,
            candidate,
        ));
    }
    let mut seen = BTreeSet::new();
    assert_eq!(rows.len(), 40, "the four groups total 40 rows");
    for row in &rows {
        assert!(
            seen.insert(row.case_id.as_str()),
            "acceptance row {} appears in two groups",
            row.case_id
        );
    }
    let required: BTreeSet<String> = SOURCE_SCENARIOS
        .iter()
        .map(|id| (*id).to_string())
        .chain(RELEASE_SECTIONS.iter().map(|id| (*id).to_string()))
        .chain(std::iter::once(UPGRADE_CASE.to_string()))
        .collect();
    assert_eq!(
        seen.into_iter().map(String::from).collect::<BTreeSet<_>>(),
        required,
        "the group union is exactly the checked acceptance roster"
    );
    rows
}

fn acceptance_rows(candidate: &str) -> Vec<FinalRow> {
    let default_paths: Vec<(&str, PathBuf, PathBuf)> = ACCEPTANCE_GROUPS
        .iter()
        .map(|group| {
            (
                *group,
                acceptance_manifest_path(group),
                acceptance_receipt_path(group),
            )
        })
        .collect();
    let mut rows = acceptance_rows_from(&default_paths, candidate);
    rows.push(
        match installed_ordinary_evidence(&installed_receipt_path(), candidate) {
            Ok(evidence) => passed(INSTALLED_ORDINARY_CASE.to_string(), candidate, evidence),
            Err(cause) => censored(INSTALLED_ORDINARY_CASE.to_string(), candidate, cause),
        },
    );
    rows.push(match installed_ui_evidence(&ui_report_path(), candidate) {
        Ok(evidence) => passed(INSTALLED_UI_CASE.to_string(), candidate, evidence),
        Err(cause) => censored(INSTALLED_UI_CASE.to_string(), candidate, cause),
    });
    rows
}

fn ui_report_path() -> PathBuf {
    std::env::var_os("RIVECT_UI_MATRIX_REPORT")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("target")
                .join("installed-tui-matrix.json")
        })
}

/// Reads the retained matrix report. An absent, malformed or short report
/// yields no cell, so the conjunction counts those cells as missing instead
/// of treating the report's own summary as evidence.
fn matrix_rows(path: &Path) -> Vec<FinalRow> {
    let Ok(bytes) = std::fs::read(path) else {
        return Vec::new();
    };
    let Ok(report) = serde_json::from_slice::<Value>(&bytes) else {
        return Vec::new();
    };
    let Some(candidate) = report["candidate_manifest_sha256"].as_str() else {
        return Vec::new();
    };
    let Ok(observed) = matrix_identity(&report) else {
        return Vec::new();
    };
    let mut rows = Vec::with_capacity(FINAL_UI_CELLS);
    for state in UI_STATES {
        for geometry in UI_GEOMETRIES {
            for input in UI_INPUTS {
                let case_id = ui_case(state, geometry, input);
                let Some(verdict) =
                    observed.get(&(state.to_string(), geometry.to_string(), input.to_string()))
                else {
                    continue;
                };
                let evidence = format!("{}#{case_id}", path.display());
                rows.push(match verdict.as_str() {
                    "PASS" => passed(case_id, candidate, evidence),
                    "FAIL" => failed(
                        case_id,
                        candidate,
                        format!("matrix verdict fail: {verdict}"),
                    ),
                    other => censored(case_id, candidate, format!("matrix verdict {other}")),
                });
            }
        }
    }
    rows
}

fn honest_ui_cells() -> Vec<Value> {
    let mut cells = Vec::with_capacity(FINAL_UI_CELLS);
    for state in UI_STATES {
        for geometry in UI_GEOMETRIES {
            for input in UI_INPUTS {
                cells.push(json!({
                    "state": state,
                    "geometry": geometry,
                    "input": input,
                    "verdict": "PASS",
                    "reason": renderer_only_claim(state).unwrap_or_default(),
                }));
            }
        }
    }
    cells
}

fn honest_theme_fingerprints() -> Vec<Value> {
    let mut observations = Vec::with_capacity(THEME_OBSERVATIONS);
    for state in UI_STATES {
        for geometry in UI_GEOMETRIES {
            for theme in THEMES {
                let modal_state = matches!(state, "awaiting-decision" | "awaiting-permission");
                observations.push(json!({
                    "state": state,
                    "geometry": geometry,
                    "theme": theme,
                    "status": expected_fingerprint(theme, "status"),
                    "dock": expected_fingerprint(theme, "dock"),
                    "composer": expected_fingerprint(theme, "composer"),
                    "transcript": expected_fingerprint(theme, "transcript"),
                    "modal": if modal_state {
                        expected_fingerprint(theme, "modal")
                    } else {
                        "none"
                    },
                }));
            }
        }
    }
    observations
}

fn honest_ui_report(cells: &[Value], observations: &[Value]) -> Value {
    json!({
        "schema_version": 1,
        "candidate_manifest_sha256": "candidate-current",
        "states": 19,
        "geometries": 5,
        "inputs": 14,
        "cells": FINAL_UI_CELLS,
        "pass": FINAL_UI_CELLS,
        "fail": 0,
        "not_run": 0,
        "cell_verdicts": cells,
        "theme_observations": observations.len(),
        "theme_fingerprints": observations,
        "mono_probes": { "total": MONO_PROBES, "pass": MONO_PROBES },
        "dumb_probes": { "total": DUMB_PROBES, "pass": DUMB_PROBES },
        "inline_probes": { "total": THEMES.len(), "pass": THEMES.len() },
        "runtime_seconds": 300.0,
    })
}

#[test]
fn installed_receipts_absent_stale_or_failed_are_never_pass() {
    let root = tempfile::TempDir::with_prefix("rivect-receipt-negative-").expect("temp");
    let ordinary = root.path().join("ordinary.json");
    let ui = root.path().join("ui.json");
    let candidate = "candidate-current";

    assert!(installed_ordinary_evidence(&ordinary, candidate).is_err());
    assert!(installed_ui_evidence(&ui, candidate).is_err());

    std::fs::write(
        &ordinary,
        json!({
            "schema_version": 1,
            "status": "pass",
            "candidate_manifest_sha256": "candidate-stale",
            "sends": 1,
            "settlements": 1,
        })
        .to_string(),
    )
    .expect("stale receipt");
    let stale = installed_ordinary_evidence(&ordinary, candidate).expect_err("stale receipt");
    assert!(stale.contains("stale"), "{stale}");

    std::fs::write(
        &ordinary,
        json!({
            "schema_version": 1,
            "status": "fail",
            "candidate_manifest_sha256": candidate,
            "sends": 1,
            "settlements": 1,
        })
        .to_string(),
    )
    .expect("failed receipt");
    assert!(installed_ordinary_evidence(&ordinary, candidate).is_err());

    std::fs::write(
        &ordinary,
        json!({
            "schema_version": 1,
            "status": "pass",
            "candidate_manifest_sha256": candidate,
            "sends": 1,
            "settlements": 1,
        })
        .to_string(),
    )
    .expect("current receipt");
    assert!(installed_ordinary_evidence(&ordinary, candidate).is_ok());

    std::fs::write(
        &ui,
        json!({
            "schema_version": 1,
            "candidate_manifest_sha256": "candidate-stale",
            "states": 19,
            "geometries": 5,
            "inputs": 14,
            "cells": 1330,
            "pass": 1330,
            "fail": 0,
            "not_run": 0,
            "cell_verdicts": [],
        })
        .to_string(),
    )
    .expect("stale matrix");
    assert!(installed_ui_evidence(&ui, candidate).is_err());

    // The honest matrix: every cell PASS, the four renderer-only states carry
    // their exact claims, and 285 state×theme fingerprints.
    let honest = honest_ui_cells();
    let observations = honest_theme_fingerprints();
    std::fs::write(&ui, honest_ui_report(&honest, &observations).to_string())
        .expect("honest matrix");
    let evidence = installed_ui_evidence(&ui, candidate).expect("the honest matrix passes");
    assert!(
        evidence.ends_with(INSTALLED_UI_EVIDENCE_MARKER),
        "the passing row points at its retained matrix: {evidence}"
    );
    let ui_rows = matrix_rows(&ui);
    assert_eq!(ui_rows.len(), FINAL_UI_CELLS, "every cell is counted");
    assert_eq!(
        ui_rows
            .iter()
            .filter(|row| row.outcome == TrialOutcome::Pass)
            .count(),
        FINAL_UI_CELLS,
        "every cell passes"
    );
    let mut complete: Vec<FinalRow> = complete_rows(candidate)
        .into_iter()
        .filter(|row| !row.case_id.starts_with("UI::"))
        .collect();
    complete.extend(ui_rows);
    let honest_report = counted(candidate, &complete);
    assert!(honest_report.full_pass, "{honest_report:?}");

    // A passing renderer-only cell that drops its claim is refused.
    let mut missing_claim = honest.clone();
    let victim = missing_claim
        .iter_mut()
        .find(|cell| {
            cell["state"] == json!("awaiting-permission") && cell["input"] == json!("keyboard-only")
        })
        .expect("the renderer-only cell exists");
    victim["reason"] = json!("");
    std::fs::write(
        &ui,
        honest_ui_report(&missing_claim, &observations).to_string(),
    )
    .expect("missing-claim mutant");
    let refused = installed_ui_evidence(&ui, candidate)
        .expect_err("a missing renderer-only claim is refused");
    assert!(refused.contains("claim"), "{refused}");

    // A dropped state×theme fingerprint is refused.
    let mut dropped = observations.clone();
    dropped.pop();
    std::fs::write(&ui, honest_ui_report(&honest, &dropped).to_string())
        .expect("dropped fingerprint");
    let refused =
        installed_ui_evidence(&ui, candidate).expect_err("a dropped fingerprint is refused");
    assert!(refused.contains("285"), "{refused}");

    // A cell that keeps the old NOT_RUN claim is refused.
    let mut not_run = honest.clone();
    not_run[0]["verdict"] = json!("NOT_RUN");
    std::fs::write(&ui, honest_ui_report(&not_run, &observations).to_string())
        .expect("NOT_RUN matrix");
    let refused = installed_ui_evidence(&ui, candidate).expect_err("a NOT_RUN cell is refused");
    assert!(refused.contains("NOT_RUN"), "{refused}");

    // Placeholder fingerprints are not fingerprints.
    let mut placeholder = observations.clone();
    placeholder[0]["status"] = json!("a");
    placeholder[0]["dock"] = json!("b");
    placeholder[0]["composer"] = json!("c");
    placeholder[0]["transcript"] = json!("d");
    std::fs::write(&ui, honest_ui_report(&honest, &placeholder).to_string())
        .expect("placeholder fingerprints");
    let refused =
        installed_ui_evidence(&ui, candidate).expect_err("placeholder fingerprints are refused");
    assert!(refused.contains("fingerprint"), "{refused}");

    // 285 reported observations with only 284 entries is a short report.
    let mut short_report = honest_ui_report(&honest, &dropped);
    short_report["theme_observations"] = json!(THEME_OBSERVATIONS);
    std::fs::write(&ui, short_report.to_string()).expect("short observation list");
    let refused =
        installed_ui_evidence(&ui, candidate).expect_err("a short observation list is refused");
    assert!(refused.contains("284"), "{refused}");

    // The card states must paint a modal; all-`none` is refused.
    let mut no_modal = observations.clone();
    for observation in &mut no_modal {
        if observation["state"] == json!("awaiting-decision") {
            observation["modal"] = json!("none");
        }
    }
    std::fs::write(&ui, honest_ui_report(&honest, &no_modal).to_string())
        .expect("missing modal fingerprints");
    let refused =
        installed_ui_evidence(&ui, candidate).expect_err("a missing painted modal is refused");
    assert!(refused.contains("modal"), "{refused}");

    // A swapped theme label no longer matches the pinned palette.
    let mut swapped = observations.clone();
    swapped[0]["theme"] = json!("dark");
    std::fs::write(&ui, honest_ui_report(&honest, &swapped).to_string())
        .expect("swapped theme label");
    let refused =
        installed_ui_evidence(&ui, candidate).expect_err("a swapped theme label is refused");
    assert!(refused.contains("theme observation"), "{refused}");

    // The mono probe set must be the full 285.
    let mut short_mono = honest_ui_report(&honest, &observations);
    short_mono["mono_probes"]["pass"] = json!(MONO_PROBES - 1);
    std::fs::write(&ui, short_mono.to_string()).expect("short mono probes");
    let refused =
        installed_ui_evidence(&ui, candidate).expect_err("a short mono probe set is refused");
    assert!(refused.contains("mono probes"), "{refused}");

    // A runtime outside the recorded gate is refused.
    let mut slow = honest_ui_report(&honest, &observations);
    slow["runtime_seconds"] = json!(MATRIX_BUDGET_SECONDS + 1.0);
    std::fs::write(&ui, slow.to_string()).expect("slow matrix");
    let refused = installed_ui_evidence(&ui, candidate).expect_err("a slow matrix is refused");
    assert!(refused.contains("runtime"), "{refused}");

    let assert_refused = |path: &Path| {
        assert!(installed_ui_evidence(path, candidate).is_err());
        let mut rows: Vec<FinalRow> = complete_rows(candidate)
            .into_iter()
            .filter(|row| !row.case_id.starts_with("UI::"))
            .collect();
        rows.extend(matrix_rows(path));
        let report = counted(candidate, &rows);
        assert!(
            !report.full_pass,
            "a malformed matrix is never a full pass: {report:?}"
        );
        assert_eq!(
            report.blockers.missing.len(),
            FINAL_UI_CELLS,
            "a malformed matrix contributes no cells"
        );
    };

    let mut duplicate = honest.clone();
    duplicate.pop();
    duplicate.push(honest[0].clone());
    std::fs::write(&ui, honest_ui_report(&duplicate, &observations).to_string())
        .expect("duplicate matrix");
    assert_refused(&ui);

    let mut unknown = honest.clone();
    unknown[0]["state"] = json!("state-unlisted");
    std::fs::write(&ui, honest_ui_report(&unknown, &observations).to_string())
        .expect("unknown-coordinate matrix");
    assert_refused(&ui);

    std::fs::write(
        &ui,
        json!({
            "schema_version": 1,
            "candidate_manifest_sha256": candidate,
            "states": 19,
            "geometries": 5,
            "inputs": 14,
            "cells": 1329,
            "pass": 0,
            "fail": 0,
            "not_run": 0,
            "cell_verdicts": honest,
            "theme_observations": observations.len(),
            "theme_fingerprints": observations,
        })
        .to_string(),
    )
    .expect("short-summary matrix");
    assert_refused(&ui);
}

/// The verdict's full-pass claim: the counted report must pass and no
/// retained leg may exist. One retained row means one proof did not execute.
fn full_pass_with_retained(
    report: &rivect::verification::FinalAcceptance,
    retained: usize,
) -> bool {
    report.full_pass && retained == 0
}

/// Surfaces each retained leg row as a NOT_RUN line and returns the number
/// of unique legs. Retained legs are their own blocker family: they never
/// enter `blockers.not_run`, whose membership is the declared-vs-observed
/// comparison, but a real retained row still forbids a full pass.
fn surface_retained_not_run(retained_not_run: &[Value]) -> usize {
    let mut retained_legs: BTreeSet<&str> = BTreeSet::new();
    for row in retained_not_run {
        assert_eq!(
            row["status"], "not_run",
            "a retained leg row is a NOT_RUN: {row}"
        );
        let leg = row["leg"].as_str().expect("retained leg names its leg");
        assert!(!leg.is_empty(), "a retained leg row names its leg: {row}");
        let prerequisite = row["prerequisite"].as_str().unwrap_or("<no prerequisite>");
        // The reader strips control characters; a row that still carries one
        // could forge a terminal line and is refused here as well.
        assert!(
            !leg.chars().any(char::is_control) && !prerequisite.chars().any(char::is_control),
            "a retained row carries no control character: {row}"
        );
        if retained_legs.insert(leg) {
            println!("LEG_NOT_RUN {leg}: {prerequisite}");
        }
    }
    println!("LEGS_NOT_RUN retained={}", retained_legs.len());
    retained_legs.len()
}

/// The retained leg files this run can read, walked independently of
/// [`support::not_run::records`]: the closed leg set, the byte cap, UTF-8,
/// and a first row naming its own leg. The conjunction compares the reader
/// against this set, so a reader that returns no rows cannot hide a file.
fn retained_legs_on_disk() -> BTreeSet<String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join(support::not_run::DIR);
    support::not_run::LEGS
        .into_iter()
        .filter(|leg| {
            let Ok(bytes) = std::fs::read(root.join(format!("{leg}.jsonl"))) else {
                return false;
            };
            if bytes.len() > 8 * 1024 {
                return false;
            }
            let Ok(text) = String::from_utf8(bytes) else {
                return false;
            };
            !support::not_run::parse_rows(leg, &text).is_empty()
        })
        .map(str::to_string)
        .collect()
}

#[test]
fn a_retained_leg_not_run_is_surfaced_and_forbids_a_full_pass() {
    let candidate = "candidate";
    let report = counted(candidate, &complete_rows(candidate));
    assert!(report.full_pass, "the fixture set is complete: {report:?}");
    assert!(
        full_pass_with_retained(&report, 0),
        "a complete report with no retained leg keeps the full pass"
    );
    let retained = vec![json!({
        "schema_version": 1,
        "leg": "auth.keychain",
        "status": "not_run",
        "prerequisite": "fixture prerequisite",
    })];
    let retained_legs = surface_retained_not_run(&retained);
    assert_eq!(retained_legs, 1, "the retained NOT_RUN leg is surfaced");
    assert!(
        !full_pass_with_retained(&report, retained_legs),
        "a complete report plus one retained row is not a full pass"
    );
}

#[test]
fn retained_rows_dedupe_by_leg_and_never_forge_a_verdict() {
    let duplicate = json!({
        "schema_version": 1,
        "leg": "ingress.exec",
        "status": "not_run",
        "prerequisite": "no git",
    });
    let other = json!({
        "schema_version": 1,
        "leg": "ingress.pty",
        "status": "not_run",
        "prerequisite": "no pty",
    });
    let retained = vec![duplicate.clone(), duplicate, other];
    assert_eq!(
        surface_retained_not_run(&retained),
        2,
        "the counted total is the unique-leg count"
    );
}

/// The retained reader's file walk: only a closed-set leg file that fits the
/// cap, decodes as UTF-8 and names its own leg is evidence, and its duplicate
/// rows still count one leg.
#[test]
fn retained_reader_reads_only_a_bounded_regular_leg_file() {
    let root = tempfile::TempDir::with_prefix("rivect-retained-reader-").expect("temp root");
    std::fs::write(
        root.path().join("auth.keychain.jsonl"),
        concat!(
            r#"{"schema_version":1,"leg":"auth.keychain","status":"not_run","prerequisite":"first"}"#,
            "\n",
            r#"{"schema_version":1,"leg":"auth.keychain","status":"not_run","prerequisite":"second"}"#,
            "\n",
        ),
    )
    .expect("duplicate rows");
    std::fs::write(
        root.path().join("auth.secret_service.jsonl"),
        [0xff, 0xfe, 0xfd],
    )
    .expect("invalid utf-8");
    std::fs::write(
        root.path().join("ingress.exec.jsonl"),
        vec![b'x'; 8 * 1024 + 1],
    )
    .expect("over cap");
    std::fs::write(
        root.path().join("ingress.vision.jsonl"),
        r#"{"schema_version":1,"leg":"ingress.exec","status":"not_run","prerequisite":"forged"}"#,
    )
    .expect("forged leg");

    let rows = support::not_run::records_in(root.path());
    assert_eq!(rows.len(), 1, "one deduped leg survives: {rows:?}");
    assert_eq!(rows[0]["leg"], "auth.keychain");
    assert_eq!(
        rows[0]["prerequisite"], "first",
        "the first row of a leg names it once"
    );
}

#[test]
fn retained_reader_ignores_conflicting_and_control_bearing_rows() {
    let good =
        r#"{"schema_version":1,"leg":"ingress.exec","status":"not_run","prerequisite":"no git"}"#;
    let conflicting =
        r#"{"schema_version":1,"leg":"auth.keychain","status":"not_run","prerequisite":"forged"}"#;
    let control = r#"{"schema_version":1,"leg":"ingress.exec","status":"not_run","prerequisite":"evil\u001b[2Jforged\nLEG_NOT_RUN"}"#;
    let wrong_status =
        r#"{"schema_version":1,"leg":"ingress.exec","status":"pass","prerequisite":"forged"}"#;
    let wrong_schema =
        r#"{"schema_version":2,"leg":"ingress.exec","status":"not_run","prerequisite":"forged"}"#;
    let rows = support::not_run::parse_rows(
        "ingress.exec",
        &format!("{good}\n{conflicting}\n{control}\n{wrong_status}\n{wrong_schema}"),
    );
    assert_eq!(
        rows.len(),
        2,
        "only rows naming this leg and status parse: {rows:?}"
    );
    assert_eq!(rows[0]["leg"], "ingress.exec");
    assert_eq!(
        rows[1]["prerequisite"], "evil[2JforgedLEG_NOT_RUN",
        "control characters are stripped before printing"
    );
    assert!(
        rows.iter().all(|row| {
            !row["prerequisite"]
                .as_str()
                .unwrap_or_default()
                .chars()
                .any(char::is_control)
        }),
        "no parsed prerequisite can forge a terminal line: {rows:?}"
    );
}

#[test]
fn final_acceptance_passes_the_installed_rows_and_prints_the_verdict() {
    let bundle = support::release::baseline_bundle();
    assert!(
        !bundle.starts_with(env!("CARGO_MANIFEST_DIR")),
        "the conjunction runs on the bundle outside the checkout: {}",
        bundle.display()
    );
    let activation = verify_release_bundle(bundle).expect("the packaged artifact activates");
    let candidate = activation.manifest_sha256.clone();
    assert_eq!(
        candidate,
        support::release::sha256_file(&bundle.join(RELEASE_MANIFEST_NAME)),
        "the candidate is the manifest bytes on disk"
    );
    println!("final conjunction candidate manifest sha256: {candidate}");

    let mut rows = acceptance_rows(&candidate);
    rows.extend(catalog_rows(&candidate));
    rows.extend(provider_trial_rows(&candidate));
    let installed = installed_rows(bundle, &candidate);
    assert_eq!(
        installed.len(),
        FINAL_INSTALLED_ROWS,
        "74 provider rows plus both aliases"
    );
    rows.extend(installed);
    rows.extend(search_rows(&candidate));

    let acceptance_ids: BTreeSet<String> = SOURCE_SCENARIOS
        .iter()
        .map(|id| (*id).to_string())
        .chain(RELEASE_SECTIONS.iter().map(|id| (*id).to_string()))
        .chain(RELEASE_CASE_IDS.iter().map(|id| (*id).to_string()))
        .collect();
    let mut expected_not_run = BTreeSet::new();
    for case_id in &acceptance_ids {
        match rows.iter().find(|row| &row.case_id == case_id) {
            Some(row) if row.outcome == TrialOutcome::Pass => {}
            _ => {
                expected_not_run.insert(case_id.clone());
            }
        }
    }
    for row in &rows {
        if (row.case_id.starts_with("TP-PROVIDER-") || row.case_id.starts_with("TP-SEARCH-"))
            && row.outcome == TrialOutcome::Censored
        {
            expected_not_run.insert(row.case_id.clone());
        }
    }

    let ui = matrix_rows(&ui_report_path());
    let ui_count = ui.len();
    let ui_missing = FINAL_UI_CELLS.saturating_sub(ui_count);
    let ui_stale = ui.iter().filter(|row| row.candidate != candidate).count();
    println!("UI-CELLS counted={ui_count} missing={ui_missing} stale={ui_stale}");
    rows.extend(ui);

    let report = counted(&candidate, &rows);
    println!(
        "FINAL required={} present={} current={} passed={} provider_rows={} alias_rows={} installed_rows={} ui_cells={}",
        report.required,
        report.present,
        report.current,
        report.passed,
        report.provider_rows,
        report.alias_rows,
        report.installed_rows,
        report.ui_cells
    );
    println!(
        "FINAL blockers missing={} stale={} failed={} not_run={} unattributed={}",
        report.blockers.missing.len(),
        report.blockers.stale.len(),
        report.blockers.failed.len(),
        report.blockers.not_run.len(),
        report.blockers.unattributed.len()
    );

    assert_eq!(report.required, expected_required_rows());
    assert_eq!(
        report.present + report.blockers.missing.len(),
        report.required
    );
    assert_eq!(
        report.provider_rows,
        PROVIDER_ROWS.len() * PROVIDER_TRIALS.len(),
        "74 x 5 provider trial rows"
    );
    assert_eq!(
        report.provider_rows + report.alias_rows,
        FINAL_PROVIDER_ROWS,
        "74x5+2 = 372"
    );
    assert_eq!(
        report.installed_rows, FINAL_INSTALLED_ROWS,
        "74 provider INSTALLED rows plus 2 alias INSTALLED rows = 76"
    );
    assert!(report.blockers.failed.is_empty(), "{report:?}");
    assert!(report.blockers.unattributed.is_empty(), "{report:?}");
    assert_eq!(
        report.unserved,
        rows.iter()
            .filter(|row| row.outcome == TrialOutcome::Unserved)
            .count(),
        "unserved is counted outside passed"
    );

    let observed_not_run: BTreeSet<&str> =
        report.blockers.not_run.iter().map(String::as_str).collect();
    let declared_not_run: BTreeSet<&str> = expected_not_run.iter().map(String::as_str).collect();
    assert_eq!(
        observed_not_run, declared_not_run,
        "only the declared families stay not run"
    );

    if ui_count == 0 {
        let missing_ui = report
            .blockers
            .missing
            .iter()
            .filter(|case_id| case_id.starts_with("UI::"))
            .count();
        assert_eq!(
            missing_ui, FINAL_UI_CELLS,
            "an absent matrix is not a smaller denominator"
        );
    } else {
        assert_eq!(
            report.ui_cells, FINAL_UI_CELLS,
            "every 19xGxI cell is counted in the report"
        );
        assert_eq!(ui_missing, 0, "every 19xGxI cell is counted");
        assert_eq!(
            ui_stale, 0,
            "the matrix binds the acting candidate on every cell"
        );
        assert_eq!(
            report.passed,
            expected_required_rows() - declared_not_run.len() - report.unserved,
            "every current row and cell passes; unserved stays outside passed"
        );
    }

    let ordinary = rows
        .iter()
        .find(|row| row.case_id == INSTALLED_ORDINARY_CASE)
        .expect("release row");
    assert_eq!(ordinary.outcome, TrialOutcome::Pass);
    let evidence = ordinary
        .evidence
        .as_deref()
        .expect("retained receipt pointer");
    assert!(
        evidence.ends_with(INSTALLED_ORDINARY_EVIDENCE_MARKER),
        "the row points at its retained receipt: {evidence}"
    );
    assert!(
        !report
            .blockers
            .not_run
            .contains(&INSTALLED_ORDINARY_CASE.to_string())
    );
    println!("PASSED {INSTALLED_ORDINARY_CASE}: {evidence}");

    // The UI row passes on its candidate-bound matrix: every cell PASS, the
    // 285 state×theme observations present, and every renderer-only claim
    // intact.
    let ui_row = rows
        .iter()
        .find(|row| row.case_id == INSTALLED_UI_CASE)
        .expect("release row");
    if let Some(cause) = ui_row.cause.as_deref() {
        println!("UI-ROW cause: {cause}");
    }
    assert_eq!(ui_row.outcome, TrialOutcome::Pass);
    let evidence = ui_row.evidence.as_deref().expect("retained matrix pointer");
    assert!(
        evidence.ends_with(INSTALLED_UI_EVIDENCE_MARKER),
        "the row points at its retained matrix: {evidence}"
    );
    assert!(
        !report
            .blockers
            .not_run
            .contains(&INSTALLED_UI_CASE.to_string())
    );
    assert_eq!(
        ui_count, FINAL_UI_CELLS,
        "the matrix counts every one of the 1330 cells"
    );
    println!("PASSED {INSTALLED_UI_CASE}: {evidence}");

    // Host-conditional legs retain a machine-readable NOT_RUN row instead of
    // returning green. The conjunction surfaces every retained row as NOT_RUN
    // and cannot claim a full pass while one exists.
    let retained_not_run = support::not_run::records();
    let retained_legs_not_run = surface_retained_not_run(&retained_not_run);
    let surfaced: BTreeSet<String> = retained_not_run
        .iter()
        .map(|row| {
            row["leg"]
                .as_str()
                .expect("a surfaced row names its leg")
                .to_string()
        })
        .collect();
    assert_eq!(
        surfaced,
        retained_legs_on_disk(),
        "the retained reader surfaces every leg file on disk exactly once"
    );
    assert_eq!(
        retained_legs_not_run,
        surfaced.len(),
        "the counted total is the deduped unique-leg count it prints"
    );

    let blocker_count = report.blockers.missing.len()
        + report.blockers.stale.len()
        + report.blockers.failed.len()
        + report.blockers.not_run.len()
        + report.blockers.unattributed.len()
        + retained_legs_not_run;
    let full_pass = full_pass_with_retained(&report, retained_legs_not_run);
    println!(
        "FINAL_ACCEPTANCE verdict={} blockers={blocker_count}",
        if full_pass {
            "full-pass"
        } else {
            "not-full-pass"
        }
    );

    assert!(
        !report.full_pass,
        "the full-pass claim stays SLICE-010/Seal: {report:?}"
    );
}
