//! AC-082 (REQ-068): the final release conjunction. One counted plan carries
//! A01–A36, §17–§17.2, the upgrade confirmation and the two installed-release
//! legs, the 74 provider rows under five trial classes plus both alias rows
//! (74×5+2 = 372, of which the installed TP contributes 76), and the
//! 19×G×I installed UI matrix. A row bound to another candidate is stale; a
//! missing, stale, failed, censored or unattributed row prevents a full pass.
//!
//! The ordinary installed-release leg is passed on the repaired candidate:
//! the packaged artifact publishes and settles an ordinary first task. The
//! installed UI matrix renders all 19 states through the packaged
//! `--ui-review` entry, but the 285 theme cells declare distinct
//! light/dark/high-contrast palettes NOT_RUN, so that row is censored rather
//! than passed. The run prints the stable verdict line; the full-pass claim
//! stays SLICE-010/Seal, while real provider, publication and platform legs
//! stay NOT_RUN.

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
    ALIAS_ROWS, FINAL_INSTALLED_ROWS, FINAL_PROVIDER_ROWS, FINAL_UI_CELLS, FinalAcceptanceError,
    FinalDeclaration, FinalRow, INSTALLED_ORDINARY_CASE, INSTALLED_UI_CASE, PROVIDER_ROWS,
    PROVIDER_TRIALS, RELEASE_CASE_IDS, RELEASE_SECTIONS, SEARCH_SERVICES, SEARCH_TRIALS,
    SOURCE_SCENARIOS, TrialOutcome, UI_GEOMETRIES, UI_INPUTS, UI_STATES, UPGRADE_CASE, alias_case,
    conjunction_cells, evaluate_final, final_required_cases, provider_case, ui_case,
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const INSTALLED_ORDINARY_EVIDENCE_MARKER: &str = "#installed-ordinary";
const INSTALLED_UI_EVIDENCE_MARKER: &str = "#installed-ui";

/// The three input modes whose distinct palettes the matrix declares NOT_RUN:
/// each theme cell must carry exactly its mode's claim as the reason, and no
/// other cell may be NOT_RUN.
const THEME_NOT_RUN_CLAIMS: [(&str, &str); 3] = [
    (
        "light",
        "theme-agnostic rendering; distinct light palette NOT_RUN",
    ),
    (
        "dark",
        "theme-agnostic rendering; distinct dark palette NOT_RUN",
    ),
    (
        "high-contrast",
        "theme-agnostic rendering; distinct high-contrast palette NOT_RUN",
    ),
];

/// 19 states × 5 geometries × the three theme inputs.
const UI_NOT_RUN_CELLS: usize = UI_STATES.len() * UI_GEOMETRIES.len() * THEME_NOT_RUN_CLAIMS.len();
/// The cells a complete matrix passes: every cell that is not a theme cell.
const UI_PASS_CELLS: usize = FINAL_UI_CELLS - UI_NOT_RUN_CELLS;

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

fn provider_trial_rows(candidate: &str) -> Vec<FinalRow> {
    let mut rows = Vec::with_capacity(PROVIDER_ROWS.len() * 3);
    for (id, _dialect) in PROVIDER_ROWS {
        for trial in ["AUTH", "WIRE", "RECOVERY"] {
            rows.push(censored(
                provider_case(trial, id),
                candidate,
                format!(
                    "not run: the {trial} leg is owned by its own target and is not consumed by this conjunction"
                ),
            ));
        }
    }
    rows
}

fn search_rows(candidate: &str) -> Vec<FinalRow> {
    conjunction_cells()
        .into_iter()
        .filter(|(case_id, _mode)| case_id.starts_with("TP-SEARCH-"))
        .map(|(case_id, _mode)| {
            censored(
                case_id,
                candidate,
                "not run: the search target is not consumed by this conjunction".to_string(),
            )
        })
        .collect()
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
        let reason = cell["reason"].as_str().unwrap_or_default();
        // The declared NOT_RUN family is exactly the theme inputs, each with
        // its own claim as the reason: a theme cell that says PASS is the
        // overclaim this matrix must never carry.
        match (
            THEME_NOT_RUN_CLAIMS.iter().find(|(mode, _)| *mode == input),
            verdict,
        ) {
            (Some((_, claim)), "NOT_RUN") if reason == *claim => {}
            (Some((_, claim)), "NOT_RUN") => {
                return Err(format!(
                    "theme cell {state}/{geometry}/{input} carries {reason:?}, not its claim {claim:?}"
                ));
            }
            (Some(_), _) => {
                return Err(format!(
                    "theme cell {state}/{geometry}/{input} is {verdict}, not NOT_RUN"
                ));
            }
            (None, "NOT_RUN") => {
                return Err(format!(
                    "cell {state}/{geometry}/{input} is NOT_RUN outside the declared theme family"
                ));
            }
            (None, "PASS" | "FAIL") => {}
            (None, _) => {
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

fn installed_ui_evidence(path: &Path, candidate: &str) -> Result<String, String> {
    let report = read_receipt(path)?;
    check_candidate(&report, candidate)?;
    if report["schema_version"] != json!(1) {
        return Err("matrix schema_version is not 1".to_string());
    }
    // The identity pass requires the exact NOT_RUN family (reason text
    // included) and the summary that matches it.
    let cells = matrix_identity(&report)?;
    let pass = cells.values().filter(|verdict| *verdict == "PASS").count();
    let not_run = cells
        .values()
        .filter(|verdict| *verdict == "NOT_RUN")
        .count();
    if report["cells"] != json!(FINAL_UI_CELLS)
        || report["fail"] != json!(0)
        || report["pass"] != json!(UI_PASS_CELLS)
        || report["not_run"] != json!(UI_NOT_RUN_CELLS)
        || pass != UI_PASS_CELLS
        || not_run != UI_NOT_RUN_CELLS
    {
        return Err("matrix summary is not the declared pass/NOT_RUN split".to_string());
    }
    // The matrix is honest, and that honesty is why the row cannot pass: the
    // theme palettes it declares NOT_RUN are not rendered evidence.
    Err(format!(
        "not run: {not_run} theme cells declare distinct light/dark/high-contrast palettes NOT_RUN ({pass} of {} cells pass, 0 fail) ({}#installed-ui)",
        cells.len(),
        path.display()
    ))
}

fn acceptance_rows(candidate: &str) -> Vec<FinalRow> {
    let mut rows = Vec::with_capacity(SOURCE_SCENARIOS.len() + RELEASE_SECTIONS.len() + 3);
    for id in SOURCE_SCENARIOS.iter().chain(RELEASE_SECTIONS.iter()) {
        rows.push(censored(
            (*id).to_string(),
            candidate,
            format!(
                "not run: the owning target is recorded in docs/acceptance-manifest.md#{id} and is not consumed by this conjunction"
            ),
        ));
    }
    rows.push(censored(
        UPGRADE_CASE.to_string(),
        candidate,
        "not run: the N to N+1 to N+2 upgrade gates are owned by tests/update.rs and are not consumed by this conjunction".to_string(),
    ));
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

    // The honest cell set: the three theme inputs are NOT_RUN with their own
    // claim as the reason, every other cell passes.
    let honest: Vec<Value> = UI_STATES
        .iter()
        .flat_map(|state| {
            UI_GEOMETRIES.iter().flat_map(move |geometry| {
                UI_INPUTS.iter().map(move |input| {
                    let claim = THEME_NOT_RUN_CLAIMS
                        .iter()
                        .find(|(mode, _)| mode == input)
                        .map(|(_, claim)| *claim);
                    match claim {
                        Some(claim) => json!({
                            "state": state,
                            "geometry": geometry,
                            "input": input,
                            "verdict": "NOT_RUN",
                            "reason": claim,
                        }),
                        None => json!({
                            "state": state,
                            "geometry": geometry,
                            "input": input,
                            "verdict": "PASS",
                        }),
                    }
                })
            })
        })
        .collect();
    let honest_summary = |cells: &[Value]| {
        json!({
            "schema_version": 1,
            "candidate_manifest_sha256": candidate,
            "states": 19,
            "geometries": 5,
            "inputs": 14,
            "cells": FINAL_UI_CELLS,
            "pass": UI_PASS_CELLS,
            "fail": 0,
            "not_run": UI_NOT_RUN_CELLS,
            "cell_verdicts": cells,
        })
    };

    // The overclaim the matrix must never carry: every cell PASS while the
    // theme claims are declared NOT_RUN. The consumer refuses it for the
    // theme cells themselves, not merely for a summary mismatch.
    let all_pass: Vec<Value> = honest
        .iter()
        .map(|cell| {
            let mut cell = cell.clone();
            cell["verdict"] = json!("PASS");
            cell["reason"] = json!("");
            cell
        })
        .collect();
    std::fs::write(&ui, honest_summary(&all_pass).to_string()).expect("all-pass matrix");
    let refused = installed_ui_evidence(&ui, candidate).expect_err("an all-PASS matrix is refused");
    assert!(
        refused.contains("not NOT_RUN"),
        "the all-PASS matrix is refused for its overclaim: {refused}"
    );
    assert!(matrix_identity(&read_receipt(&ui).expect("all-pass report")).is_err());

    // The honest matrix validates and still censors the row: the theme
    // palettes it declares NOT_RUN are not rendered evidence.
    std::fs::write(&ui, honest_summary(&honest).to_string()).expect("honest matrix");
    let censored = installed_ui_evidence(&ui, candidate)
        .expect_err("the declared NOT_RUN family censors the row");
    assert!(
        censored.contains("NOT_RUN") && censored.contains(INSTALLED_UI_EVIDENCE_MARKER),
        "the censoring cause names the NOT_RUN family and the report: {censored}"
    );
    let ui_rows = matrix_rows(&ui);
    assert_eq!(ui_rows.len(), FINAL_UI_CELLS, "every cell is counted");
    assert_eq!(
        ui_rows
            .iter()
            .filter(|row| row.outcome == TrialOutcome::Pass)
            .count(),
        UI_PASS_CELLS,
        "the passing cells are exactly the non-theme cells"
    );
    let honest_report = counted(candidate, &ui_rows);
    assert_eq!(
        honest_report.blockers.not_run.len(),
        UI_NOT_RUN_CELLS,
        "the theme cells are counted NOT_RUN, never PASS"
    );
    assert!(!honest_report.full_pass, "{honest_report:?}");

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
    std::fs::write(&ui, honest_summary(&duplicate).to_string()).expect("duplicate matrix");
    assert_refused(&ui);

    let mut unknown = honest.clone();
    unknown[0]["state"] = json!("state-unlisted");
    std::fs::write(&ui, honest_summary(&unknown).to_string()).expect("unknown-coordinate matrix");
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

    let mut expected_not_run = BTreeSet::new();
    for id in SOURCE_SCENARIOS.iter().chain(RELEASE_SECTIONS.iter()) {
        expected_not_run.insert((*id).to_string());
    }
    expected_not_run.extend(RELEASE_CASE_IDS.iter().map(|id| (*id).to_string()));
    for case_id in [INSTALLED_ORDINARY_CASE, INSTALLED_UI_CASE] {
        match rows.iter().find(|row| row.case_id == case_id) {
            Some(row) if row.outcome == TrialOutcome::Pass => {
                expected_not_run.remove(case_id);
            }
            _ => {
                expected_not_run.insert(case_id.to_string());
            }
        }
    }
    for (id, _dialect) in PROVIDER_ROWS {
        for trial in ["AUTH", "WIRE", "RECOVERY"] {
            expected_not_run.insert(provider_case(trial, id));
        }
    }
    for (case_id, _mode) in conjunction_cells() {
        if case_id.starts_with("TP-SEARCH-") {
            expected_not_run.insert(case_id);
        }
    }
    // The matrix's declared NOT_RUN family: the theme cells carry their own
    // claim as the reason, and no other UI cell may be NOT_RUN.
    for state in UI_STATES {
        for geometry in UI_GEOMETRIES {
            for (input, _claim) in THEME_NOT_RUN_CLAIMS {
                expected_not_run.insert(ui_case(state, geometry, input));
            }
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
            expected_required_rows() - declared_not_run.len(),
            "every current row and cell passes"
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

    // The UI row is censored, never passed: the matrix declares the theme
    // palettes NOT_RUN, and the cause names that declaration and the report.
    let ui_row = rows
        .iter()
        .find(|row| row.case_id == INSTALLED_UI_CASE)
        .expect("release row");
    assert_eq!(ui_row.outcome, TrialOutcome::Censored);
    let cause = ui_row.cause.as_deref().expect("the censoring cause");
    assert!(
        cause.contains(INSTALLED_UI_EVIDENCE_MARKER) && cause.contains("NOT_RUN"),
        "the censored row points at its retained matrix and its NOT_RUN family: {cause}"
    );
    assert!(
        report
            .blockers
            .not_run
            .contains(&INSTALLED_UI_CASE.to_string())
    );
    assert_eq!(
        ui_count, FINAL_UI_CELLS,
        "the matrix still counts every one of the 1330 cells"
    );
    println!("CENSORED {INSTALLED_UI_CASE}: {cause}");

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
