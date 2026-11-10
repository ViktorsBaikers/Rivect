//! AC-082 (REQ-068): the final release conjunction. One counted plan carries
//! A01–A36, §17–§17.2, the upgrade confirmation and the two installed-release
//! legs, the 74 provider rows under five trial classes plus both alias rows
//! (74×5+2 = 372, of which the installed TP contributes 76), and the
//! 19×G×I installed UI matrix. A row bound to another candidate is stale; a
//! missing, stale, failed, censored or unattributed row prevents a full pass.
//!
//! The two installed-release legs are passed on the repaired candidate: the
//! packaged artifact publishes and settles an ordinary first task, and the 19
//! states render through the packaged `--ui-review` entry. The run prints the
//! stable verdict line; the full-pass claim stays SLICE-010/Seal, while real
//! provider, publication and platform legs stay NOT_RUN.

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
    if report["cells"] != json!(FINAL_UI_CELLS)
        || report["pass"] != json!(FINAL_UI_CELLS)
        || report["fail"] != json!(0)
        || report["not_run"] != json!(0)
    {
        return Err("matrix summary is not a complete pass".to_string());
    }
    let cells = matrix_identity(&report)?;
    if cells.values().any(|verdict| verdict != "PASS") {
        return Err("matrix carries a non-PASS cell".to_string());
    }
    Ok(format!("{}#installed-ui", path.display()))
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

    let cells: Vec<Value> = UI_STATES
        .iter()
        .flat_map(|state| {
            UI_GEOMETRIES.iter().flat_map(move |geometry| {
                UI_INPUTS.iter().map(move |input| {
                    json!({
                        "state": state,
                        "geometry": geometry,
                        "input": input,
                        "verdict": "PASS",
                    })
                })
            })
        })
        .collect();
    std::fs::write(
        &ui,
        json!({
            "schema_version": 1,
            "candidate_manifest_sha256": candidate,
            "states": 19,
            "geometries": 5,
            "inputs": 14,
            "cells": 1330,
            "pass": 1330,
            "fail": 0,
            "not_run": 0,
            "cell_verdicts": cells,
        })
        .to_string(),
    )
    .expect("current matrix");
    assert!(installed_ui_evidence(&ui, candidate).is_ok());

    let mut duplicate = cells.clone();
    duplicate.pop();
    duplicate.push(cells[0].clone());
    std::fs::write(
        &ui,
        json!({
            "schema_version": 1,
            "candidate_manifest_sha256": candidate,
            "states": 19,
            "geometries": 5,
            "inputs": 14,
            "cells": 1330,
            "pass": 1330,
            "fail": 0,
            "not_run": 0,
            "cell_verdicts": duplicate,
        })
        .to_string(),
    )
    .expect("duplicate matrix");
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
    assert_refused(&ui);

    let mut unknown = cells.clone();
    unknown[0]["state"] = json!("state-unlisted");
    std::fs::write(
        &ui,
        json!({
            "schema_version": 1,
            "candidate_manifest_sha256": candidate,
            "states": 19,
            "geometries": 5,
            "inputs": 14,
            "cells": 1330,
            "pass": 1330,
            "fail": 0,
            "not_run": 0,
            "cell_verdicts": unknown,
        })
        .to_string(),
    )
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
            "cell_verdicts": cells,
        })
        .to_string(),
    )
    .expect("short-summary matrix");
    assert_refused(&ui);
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
    assert_eq!(report.ui_cells, ui_count);
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
        assert_eq!(ui_missing, 0, "every 19xGxI cell is counted");
        assert!(
            ui_stale == 0 || ui_stale == FINAL_UI_CELLS,
            "the matrix binds one candidate for every cell"
        );
        if ui_stale == 0 {
            assert_eq!(
                report.passed,
                expected_required_rows() - declared_not_run.len(),
                "every current row and cell passes"
            );
        }
    }

    for (case_id, marker) in [
        (INSTALLED_ORDINARY_CASE, INSTALLED_ORDINARY_EVIDENCE_MARKER),
        (INSTALLED_UI_CASE, INSTALLED_UI_EVIDENCE_MARKER),
    ] {
        let row = rows
            .iter()
            .find(|row| row.case_id == case_id)
            .expect("release row");
        assert_eq!(row.outcome, TrialOutcome::Pass);
        let evidence = row.evidence.as_deref().expect("retained receipt pointer");
        assert!(
            evidence.ends_with(marker),
            "the row points at its retained receipt: {evidence}"
        );
        assert!(!report.blockers.not_run.contains(&case_id.to_string()));
        if case_id == INSTALLED_UI_CASE {
            assert_eq!(
                ui_count, FINAL_UI_CELLS,
                "the passing UI row counts every one of the 1330 cells"
            );
        }
        println!("PASSED {case_id}: {evidence}");
    }

    let blocker_count = report.blockers.missing.len()
        + report.blockers.stale.len()
        + report.blockers.failed.len()
        + report.blockers.not_run.len()
        + report.blockers.unattributed.len();
    println!(
        "FINAL_ACCEPTANCE verdict={} blockers={blocker_count}",
        if report.full_pass {
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
