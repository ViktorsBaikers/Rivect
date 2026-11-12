//! Evaluator integrity (AC-081, EDGE-004, PROH-003): the protected oracle is
//! read from an out-of-tree path and materialized in a `TempDir` outside the
//! candidate, a defect or a fake PASS is rejected, a correct alternative is
//! accepted, failed/censored trials are retained, deterministic/replay/live are
//! told apart, and the custom3×5TP / search5×4TP rows stay conjunctive with
//! nonzero cases. No real service runs here: the installed/live cells stay
//! censored NOT_RUN, never a fabricated pass.

#![allow(
    clippy::expect_used,
    clippy::panic,
    reason = "test assertions fail loudly with the observed payload (standards §14)"
)]

use rivect::verification::{
    CUSTOM_DIALECTS, CUSTOM_TRIALS, CandidateRun, ConformanceError, ExpectedOutcome, Observation,
    ProtectedOracle, Rejection, SEARCH_SERVICES, SEARCH_TRIALS, TrialMode, TrialOutcome,
    conjunction_cells, evaluate, verify_conjunction,
};
use serde_json::{Value, json};
use std::path::PathBuf;

/// The candidate tree this evaluation is measured against: the checkout the
/// test binary was built from. The oracle must never live under it.
fn candidate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// One out-of-tree oracle file: the `TempDir` is the only holder and drops
/// with the fixture, so no repo-local copy survives a run.
struct OracleFixture {
    _directory: tempfile::TempDir,
    path: PathBuf,
}

impl OracleFixture {
    fn write(cases: &[Value]) -> Self {
        let directory =
            tempfile::TempDir::with_prefix("rivect-oracle-fixture-").expect("oracle directory");
        let path = directory.path().join("oracle.json");
        let plan = json!({"schema_version": 1, "cases": cases});
        std::fs::write(&path, serde_json::to_vec(&plan).expect("oracle encodes"))
            .expect("oracle writes");
        Self {
            _directory: directory,
            path,
        }
    }
}

fn case(case_id: &str, expected: &str, mode: &str) -> Value {
    json!({"case_id": case_id, "expected": expected, "mode": mode})
}

fn observation(case_id: &str, mode: TrialMode, outcome: TrialOutcome) -> Observation {
    Observation {
        case_id: case_id.to_string(),
        mode,
        outcome,
        evidence: Some(format!("evidence/{case_id}.txt")),
        cause: None,
    }
}

fn censored(case_id: &str, mode: TrialMode, cause: &str) -> Observation {
    Observation {
        case_id: case_id.to_string(),
        mode,
        outcome: TrialOutcome::Censored,
        evidence: Some(format!("evidence/{case_id}.txt")),
        cause: Some(cause.to_string()),
    }
}

/// Every required conjunction cell, declared by the source roster: the offline
/// classes run deterministically, the installed class is audit-time live.
fn conjunction_plan() -> Vec<Value> {
    conjunction_cells()
        .into_iter()
        .map(|(case_id, mode)| {
            json!({"case_id": case_id, "expected": "not_run", "mode": mode.as_str()})
        })
        .collect()
}

/// A run over the roster: no real service is claimed; every cell is retained
/// as a censored trial and the installed/live rows carry their own cause.
fn conjunction_run() -> CandidateRun {
    let observations = conjunction_cells()
        .into_iter()
        .map(|(case_id, mode)| {
            let cause = if mode == TrialMode::Live {
                "installed live trial is action-time gated"
            } else {
                "no admitted service adapter in this build"
            };
            censored(&case_id, mode, cause)
        })
        .collect();
    CandidateRun {
        implementation: "source-roster".to_string(),
        observations,
    }
}

#[test]
fn oracle_must_live_outside_the_candidate() {
    // A repo-local oracle is not protected, so binding it is refused instead
    // of silently reading bytes the candidate can rewrite. An existing
    // candidate file is the mutant: no fixture is written inside the checkout.
    let leaked = candidate_root().join("Cargo.toml");
    let error =
        ProtectedOracle::bind(&candidate_root(), &leaked).expect_err("repo-local is a leak");
    assert!(
        matches!(error, ConformanceError::OracleInsideCandidate { .. }),
        "{error:?}"
    );

    let fixture = OracleFixture::write(&[case("A01", "pass", "deterministic")]);
    let protected = ProtectedOracle::bind(&candidate_root(), &fixture.path).expect("binds");
    assert!(
        !protected.path().starts_with(candidate_root()),
        "the materialized oracle is outside the checkout: {:?}",
        protected.path()
    );
    assert!(
        !protected.directory().starts_with(candidate_root()),
        "the temp fixture is outside the checkout"
    );
    assert!(
        protected.path().starts_with(protected.directory()),
        "the materialized fixture lives in the evaluator's own tempdir"
    );
    assert!(
        protected.path().exists(),
        "the materialized bytes are readable by the evaluator"
    );
    assert!(
        protected.digest().len() == 64,
        "the oracle bytes are digested"
    );
    drop(protected);
}

#[test]
fn defect_fake_pass_zero_selection_and_missing_cells_are_rejected() {
    let fixture = OracleFixture::write(&[
        case("A01", "pass", "deterministic"),
        case("A02", "fail", "deterministic"),
    ]);
    let protected = ProtectedOracle::bind(&candidate_root(), &fixture.path).expect("binds");

    // A correct reference run is accepted.
    let reference = CandidateRun {
        implementation: "reference".to_string(),
        observations: vec![
            observation("A01", TrialMode::Deterministic, TrialOutcome::Pass),
            observation("A02", TrialMode::Deterministic, TrialOutcome::Fail),
        ],
    };
    let report = evaluate(&protected, &reference);
    assert!(report.accepted, "{report:?}");
    assert_eq!(report.rejection, None);
    assert_eq!(report.counts.deterministic.passed, 1);
    assert_eq!(report.counts.deterministic.failed, 1);

    // A defect: the positive case fails.
    let defect = CandidateRun {
        implementation: "defect".to_string(),
        observations: vec![
            observation("A01", TrialMode::Deterministic, TrialOutcome::Fail),
            observation("A02", TrialMode::Deterministic, TrialOutcome::Fail),
        ],
    };
    let report = evaluate(&protected, &defect);
    assert!(!report.accepted, "{report:?}");
    assert_eq!(
        report.rejection,
        Some(Rejection::ProductDefect {
            case_id: "A01".to_string()
        })
    );
    assert_eq!(report.rows[0].expected, ExpectedOutcome::Pass);
    assert!(
        report
            .retained()
            .any(|row| row.case_id == "A01" && row.observed == TrialOutcome::Fail),
        "the failed trial is retained: {report:?}"
    );

    // A fake PASS: a pass with no evidence pointer.
    let fake = Observation {
        case_id: "A01".to_string(),
        mode: TrialMode::Deterministic,
        outcome: TrialOutcome::Pass,
        evidence: None,
        cause: None,
    };
    let report = evaluate(
        &protected,
        &CandidateRun {
            implementation: "fake-pass".to_string(),
            observations: vec![
                fake,
                observation("A02", TrialMode::Deterministic, TrialOutcome::Fail),
            ],
        },
    );
    assert!(!report.accepted, "{report:?}");
    assert!(
        matches!(
            report.rejection,
            Some(Rejection::FakePass { ref case_id, .. }) if case_id == "A01"
        ),
        "{report:?}"
    );
    assert_eq!(
        report.counts.deterministic.passed, 0,
        "a pass without evidence is never counted as a pass: {report:?}"
    );

    // A fake PASS: the negative control passes instead of failing.
    let report = evaluate(
        &protected,
        &CandidateRun {
            implementation: "fake-control".to_string(),
            observations: vec![
                observation("A01", TrialMode::Deterministic, TrialOutcome::Pass),
                observation("A02", TrialMode::Deterministic, TrialOutcome::Pass),
            ],
        },
    );
    assert!(!report.accepted, "{report:?}");
    assert!(
        matches!(
            report.rejection,
            Some(Rejection::FakePass { ref case_id, .. }) if case_id == "A02"
        ),
        "{report:?}"
    );

    // An unsupported citation: a case the oracle never declared.
    let unsupported = Observation {
        case_id: "ZZ-unsupported".to_string(),
        mode: TrialMode::Deterministic,
        outcome: TrialOutcome::Pass,
        evidence: Some("evidence/elsewhere.txt".to_string()),
        cause: None,
    };
    let report = evaluate(
        &protected,
        &CandidateRun {
            implementation: "citation".to_string(),
            observations: vec![
                observation("A01", TrialMode::Deterministic, TrialOutcome::Pass),
                observation("A02", TrialMode::Deterministic, TrialOutcome::Fail),
                unsupported,
            ],
        },
    );
    assert!(!report.accepted, "{report:?}");
    assert!(
        matches!(
            report.rejection,
            Some(Rejection::FakePass { ref cause, .. }) if cause == "unsupported case"
        ),
        "{report:?}"
    );

    // Zero selection: no executed case proves nothing, even at exit 0.
    let report = evaluate(
        &protected,
        &CandidateRun {
            implementation: "empty".to_string(),
            observations: Vec::new(),
        },
    );
    assert!(!report.accepted, "{report:?}");
    assert_eq!(report.rejection, Some(Rejection::ZeroSelection));
    assert!(report.rows.is_empty(), "nothing is invented for zero cases");

    // An omitted plan case is a rejected shrunken denominator.
    let report = evaluate(
        &protected,
        &CandidateRun {
            implementation: "omission".to_string(),
            observations: vec![observation(
                "A01",
                TrialMode::Deterministic,
                TrialOutcome::Pass,
            )],
        },
    );
    assert!(!report.accepted, "{report:?}");
    assert_eq!(
        report.rejection,
        Some(Rejection::Omission {
            case_id: "A02".to_string()
        })
    );
    println!("ROW A02 ok");
}

/// A syntax/setup failure is censored evidence, never credited as the
/// symptom's RED: the failing case stays NotRun until a real RED is observed,
/// and the fixed GREEN run still carries its regression case.
#[test]
fn setup_gap_red_is_not_credited_and_green_plus_regressions_are_checked() {
    let fixture = OracleFixture::write(&[
        case("A01", "pass", "deterministic"),
        case("A02", "fail", "deterministic"),
        case("A03", "pass", "deterministic"),
    ]);
    let protected = ProtectedOracle::bind(&candidate_root(), &fixture.path).expect("binds");

    let mut setup = censored("A01", TrialMode::Deterministic, "setup gap: syntax error");
    setup.evidence = None;
    let report = evaluate(
        &protected,
        &CandidateRun {
            implementation: "setup-red".to_string(),
            observations: vec![
                setup,
                observation("A02", TrialMode::Deterministic, TrialOutcome::Fail),
                observation("A03", TrialMode::Deterministic, TrialOutcome::Pass),
            ],
        },
    );
    assert!(!report.accepted, "{report:?}");
    assert_eq!(
        report.rejection,
        Some(Rejection::NotRun {
            case_id: "A01".to_string()
        }),
        "a setup gap is not the symptom's RED"
    );
    assert_eq!(
        report.counts.deterministic.passed, 1,
        "the independent regression case still passed"
    );

    let report = evaluate(
        &protected,
        &CandidateRun {
            implementation: "green".to_string(),
            observations: vec![
                observation("A01", TrialMode::Deterministic, TrialOutcome::Pass),
                observation("A02", TrialMode::Deterministic, TrialOutcome::Fail),
                observation("A03", TrialMode::Deterministic, TrialOutcome::Pass),
            ],
        },
    );
    assert!(report.accepted, "{report:?}");
    assert_eq!(report.counts.deterministic.passed, 2);
    assert_eq!(report.counts.deterministic.failed, 1);
    println!("ROW A07 ok");
}

#[test]
fn a_correct_alternative_is_accepted_while_a_mode_claim_is_not() {
    let fixture = OracleFixture::write(&[
        case("A01", "pass", "deterministic"),
        case("R01", "pass", "replay"),
    ]);
    let protected = ProtectedOracle::bind(&candidate_root(), &fixture.path).expect("binds");

    // The alternative reaches the same contract by another implementation:
    // acceptance is about the observed contract, never the implementation id.
    // Its trials arrive in another order and from another evidence tree, so a
    // relabelled reference run does not pass this case.
    let alternative = CandidateRun {
        implementation: "alternative-a".to_string(),
        observations: vec![
            Observation {
                case_id: "R01".to_string(),
                mode: TrialMode::Replay,
                outcome: TrialOutcome::Pass,
                evidence: Some("alternative/replay-r01.log".to_string()),
                cause: None,
            },
            Observation {
                case_id: "A01".to_string(),
                mode: TrialMode::Deterministic,
                outcome: TrialOutcome::Pass,
                evidence: Some("alternative/run-a01.log".to_string()),
                cause: None,
            },
        ],
    };
    let report = evaluate(&protected, &alternative);
    assert!(report.accepted, "{report:?}");
    assert_eq!(report.candidate, "alternative-a");
    assert_eq!(report.counts.deterministic.passed, 1);
    assert_eq!(report.counts.replay.passed, 1);
    assert_eq!(report.counts.live.passed, 0);

    // A replay case claimed as a live trial is false provenance.
    let mislabelled = CandidateRun {
        implementation: "alternative-a".to_string(),
        observations: vec![
            observation("A01", TrialMode::Deterministic, TrialOutcome::Pass),
            observation("R01", TrialMode::Live, TrialOutcome::Pass),
        ],
    };
    let report = evaluate(&protected, &mislabelled);
    assert!(!report.accepted, "{report:?}");
    assert!(
        matches!(
            report.rejection,
            Some(Rejection::FakePass { ref cause, .. }) if cause == "mode mismatch"
        ),
        "{report:?}"
    );
}

#[test]
fn failed_and_censored_trials_are_retained_and_live_is_never_a_pass() {
    let fixture = OracleFixture::write(&[
        case("A01", "pass", "deterministic"),
        case("L01", "not_run", "live"),
        case("C01", "fail", "deterministic"),
    ]);
    let protected = ProtectedOracle::bind(&candidate_root(), &fixture.path).expect("binds");
    let mut live = censored("L01", TrialMode::Live, "real service is action-time gated");
    live.evidence = None;
    let run = CandidateRun {
        implementation: "offline-surface".to_string(),
        observations: vec![
            observation("A01", TrialMode::Deterministic, TrialOutcome::Pass),
            live,
            // A failed control is a retained failed trial, not a rejection.
            observation("C01", TrialMode::Deterministic, TrialOutcome::Fail),
        ],
    };
    let report = evaluate(&protected, &run);
    assert!(report.accepted, "{report:?}");
    assert_eq!(report.counts.not_run(), 1);
    assert_eq!(report.counts.deterministic.failed, 1);
    assert_eq!(report.counts.live.censored, 1);
    assert_eq!(report.counts.live.passed, 0);
    let retained = report.retained().collect::<Vec<_>>();
    assert_eq!(
        retained.len(),
        2,
        "the failed and censored rows stay: {report:?}"
    );
    assert!(retained.iter().any(|row| row.case_id == "C01"));
    assert!(retained.iter().any(|row| row.case_id == "L01"));
    let live_row = retained
        .iter()
        .find(|row| row.case_id == "L01")
        .expect("the live row");
    assert_eq!(live_row.observed, TrialOutcome::Censored);
    assert_eq!(
        live_row.cause.as_deref(),
        Some("real service is action-time gated")
    );

    // The same report survives a round trip with its rows intact.
    let encoded = serde_json::to_value(&report).expect("report encodes");
    let decoded: rivect::verification::ConformanceReport =
        serde_json::from_value(encoded).expect("report decodes");
    assert_eq!(decoded, report);
}

#[test]
fn a_censored_required_case_is_not_run_never_a_pass() {
    let fixture = OracleFixture::write(&[case("A01", "pass", "deterministic")]);
    let protected = ProtectedOracle::bind(&candidate_root(), &fixture.path).expect("binds");
    let run = CandidateRun {
        implementation: "skipped".to_string(),
        observations: vec![censored(
            "A01",
            TrialMode::Deterministic,
            "setup gap: missing fixture",
        )],
    };
    let report = evaluate(&protected, &run);
    assert!(!report.accepted, "{report:?}");
    assert_eq!(
        report.rejection,
        Some(Rejection::NotRun {
            case_id: "A01".to_string()
        })
    );
    assert_eq!(report.counts.deterministic.censored, 1);
    assert_eq!(report.counts.deterministic.passed, 0);
    assert!(
        report.retained().any(|row| row.case_id == "A01"),
        "the censored trial is retained"
    );
}

#[test]
fn custom_three_by_five_and_search_five_by_four_stay_conjunctive() {
    assert_eq!(CUSTOM_DIALECTS.len(), 3);
    assert_eq!(CUSTOM_TRIALS.len(), 5);
    assert_eq!(SEARCH_SERVICES.len(), 5);
    assert_eq!(SEARCH_TRIALS.len(), 4);
    let cells = conjunction_cells();
    assert_eq!(
        cells.len(),
        3 * 5 + 5 * 4,
        "the custom3×5TP and search5×4TP roster is 35 cells"
    );

    let fixture = OracleFixture::write(&conjunction_plan());
    let protected = ProtectedOracle::bind(&candidate_root(), &fixture.path).expect("binds");
    let report = evaluate(&protected, &conjunction_run());
    assert!(report.accepted, "{report:?}");
    assert_eq!(report.rows.len(), 35, "every cell has its own case row");
    assert_eq!(report.counts.not_run(), 35);
    let counts = verify_conjunction(&report.rows).expect("the roster is conjunctive");
    assert_eq!(counts.custom, 15, "three custom paths × five trials");
    assert_eq!(counts.search, 20, "five search services × four trials");
    assert_eq!(counts.present, 35);
    assert_eq!(counts.executed, 0, "no real service is claimed as executed");

    // Per-family, per-trial nonzero: every row keeps its own cell.
    for dialect in CUSTOM_DIALECTS {
        for trial in CUSTOM_TRIALS {
            let case_id = format!("TP-PROVIDER-{trial}::{dialect}");
            assert!(
                report.rows.iter().any(|row| row.case_id == case_id),
                "{case_id} is present"
            );
        }
    }
    for service in SEARCH_SERVICES {
        for trial in SEARCH_TRIALS {
            let case_id = format!("TP-SEARCH-{service}-{trial}");
            assert!(
                report.rows.iter().any(|row| row.case_id == case_id),
                "{case_id} is present"
            );
        }
    }

    // A dropped cell is a rejection, not a smaller denominator.
    let mut shrunken = report.rows.clone();
    shrunken.retain(|row| row.case_id != "TP-SEARCH-tavily-RESULT");
    let error = verify_conjunction(&shrunken).expect_err("an omission is rejected");
    assert_eq!(
        error.code(),
        rivect::contracts::ErrorCode::InvalidInput,
        "{error:?}"
    );

    // A duplicated cell is a collision, never two rows counted as one.
    let mut duplicated = report.rows.clone();
    let extra = report
        .rows
        .iter()
        .find(|row| row.case_id == "TP-PROVIDER-WIRE::custom-responses")
        .cloned()
        .expect("the source row");
    duplicated.push(extra);
    assert!(
        verify_conjunction(&duplicated).is_err(),
        "a duplicated cell is rejected"
    );

    // An installed cell claimed as a deterministic offline trial is a false
    // provenance claim.
    let mut mislabelled = report.rows;
    for row in &mut mislabelled {
        if row.case_id == "TP-SEARCH-exa-INSTALLED" {
            row.mode = TrialMode::Deterministic;
        }
    }
    assert!(
        verify_conjunction(&mislabelled).is_err(),
        "an installed row cannot be relabelled offline"
    );
}

#[test]
fn an_unreadable_or_invalid_oracle_is_a_typed_failure() {
    let directory = tempfile::TempDir::with_prefix("rivect-oracle-invalid-").expect("tempdir");
    let missing = directory.path().join("absent.json");
    let error = ProtectedOracle::bind(&candidate_root(), &missing).expect_err("absent fails");
    assert_eq!(
        error.code(),
        rivect::contracts::ErrorCode::DependencyBlocked
    );

    let invalid = directory.path().join("invalid.json");
    std::fs::write(&invalid, b"{not json").expect("fixture writes");
    let error = ProtectedOracle::bind(&candidate_root(), &invalid).expect_err("invalid fails");
    assert_eq!(error.code(), rivect::contracts::ErrorCode::InvalidInput);

    let empty = directory.path().join("empty.json");
    std::fs::write(&empty, b"{\"schema_version\":1,\"cases\":[]}").expect("fixture writes");
    let error = ProtectedOracle::bind(&candidate_root(), &empty).expect_err("empty fails");
    assert_eq!(error.code(), rivect::contracts::ErrorCode::InvalidInput);

    let future = directory.path().join("future.json");
    std::fs::write(
        &future,
        b"{\"schema_version\":2,\"cases\":[{\"case_id\":\"A01\",\"expected\":\"pass\",\"mode\":\"deterministic\"}]}",
    )
    .expect("fixture writes");
    let error = ProtectedOracle::bind(&candidate_root(), &future).expect_err("schema fails");
    assert_eq!(
        error.code(),
        rivect::contracts::ErrorCode::UnsupportedVersion
    );

    // The plan's expectations are its own: `ExpectedOutcome` is a closed set,
    // so a plan cannot spell an unsupported verdict.
    let bad_expectation = directory.path().join("bad-expectation.json");
    std::fs::write(
        &bad_expectation,
        b"{\"schema_version\":1,\"cases\":[{\"case_id\":\"A01\",\"expected\":\"maybe\",\"mode\":\"deterministic\"}]}",
    )
    .expect("fixture writes");
    assert!(
        ProtectedOracle::bind(&candidate_root(), &bad_expectation).is_err(),
        "an undeclared expectation is refused"
    );
}

/// The oracle holdout is external input, so a non-regular target is refused
/// before the open that would block forever, and a regular file past the byte
/// bound is still refused.
#[cfg(unix)]
#[test]
fn an_oracle_target_must_be_regular_and_byte_bounded() {
    use rivect::verification::ORACLE_MAX_BYTES;
    use std::sync::mpsc;
    use std::time::Duration;

    let directory = tempfile::TempDir::with_prefix("rivect-oracle-bound-").expect("tempdir");
    let path = directory.path().join("oracle.json");
    let status = std::process::Command::new("mkfifo")
        .arg(&path)
        .status()
        .expect("mkfifo");
    assert!(status.success(), "mkfifo failed: {status}");

    // No writer ever opens the FIFO: only a pre-open regular-file refusal
    // returns here, because `File::open` on a reader FIFO blocks forever.
    let (answer, answered) = mpsc::channel();
    let root = candidate_root();
    let reader_path = path.clone();
    let reader = std::thread::spawn(move || {
        answer
            .send(ProtectedOracle::bind(&root, &reader_path))
            .expect("send the fifo binding");
    });
    let observed = answered
        .recv_timeout(Duration::from_secs(15))
        .expect("a non-regular target is refused before the blocking open");
    reader.join().expect("the reader finishes");
    match observed {
        Err(ConformanceError::OracleRead { source, .. }) => {
            assert_eq!(
                source.kind(),
                std::io::ErrorKind::InvalidInput,
                "the refusal is typed at the open boundary"
            );
        }
        Ok(_) => panic!("a non-regular oracle never binds"),
        Err(other) => panic!("a non-regular oracle is refused: {other:?}"),
    }

    std::fs::remove_file(&path).expect("replace the fifo");
    std::fs::write(&path, vec![b' '; ORACLE_MAX_BYTES + 1]).expect("over-bound oracle");
    match ProtectedOracle::bind(&candidate_root(), &path) {
        Err(ConformanceError::OracleTooLarge { limit, .. }) => assert_eq!(limit, ORACLE_MAX_BYTES),
        Ok(_) => panic!("an over-bound oracle never binds"),
        Err(other) => panic!("an over-bound oracle is refused at the bound: {other:?}"),
    }
}
