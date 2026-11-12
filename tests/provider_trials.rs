//! The checked-in 222-row provider trial manifest: every TP-PROVIDER-{AUTH,
//! WIRE,RECOVERY} row names its exact integration oracles and the marker
//! their output carries. The six cursor/devin rows are terminal `unserved`
//! denials; every other row is an offline adapter-surface pass.

#![allow(
    clippy::expect_used,
    clippy::panic,
    reason = "manifest assertions fail loudly with the offending row; src/ stays strict (standards §14)"
)]

use rivect::verification::{
    OFFLINE_PROVIDER_ROWS, OFFLINE_PROVIDER_TRIALS, OfflineEvidenceManifest, PROVIDER_ROWS,
    TrialExpectation, is_unserved_case, provider_case, unserved_cases,
};
use std::collections::BTreeSet;

fn manifest() -> (Vec<u8>, OfflineEvidenceManifest) {
    let bytes = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/provider-trials.json"
    ))
    .expect("the checked-in provider trial manifest is readable");
    let parsed = OfflineEvidenceManifest::load(&bytes).expect("the manifest validates");
    (bytes, parsed)
}

#[test]
fn provider_manifest_carries_exactly_the_expected_222_case_rows() {
    let (_bytes, manifest) = manifest();
    assert_eq!(manifest.family, "provider");
    assert_eq!(manifest.rows.len(), OFFLINE_PROVIDER_ROWS);
    assert_eq!(manifest.rows.len(), 222, "74 providers x three trials");

    let expected: BTreeSet<String> = PROVIDER_ROWS
        .iter()
        .flat_map(|(provider, _dialect)| {
            OFFLINE_PROVIDER_TRIALS
                .iter()
                .map(move |trial| provider_case(trial, provider))
        })
        .collect();
    let observed: BTreeSet<&str> = manifest
        .rows
        .iter()
        .map(|row| row.case_id.as_str())
        .collect();
    assert_eq!(observed.len(), expected.len(), "no duplicate case id");
    assert_eq!(
        observed,
        expected.iter().map(String::as_str).collect(),
        "no missing or extra case"
    );
    assert_eq!(
        manifest
            .rows
            .iter()
            .map(|row| row.provider.as_str())
            .collect::<BTreeSet<_>>()
            .len(),
        PROVIDER_ROWS.len(),
        "every recorded provider has rows"
    );

    let mut pass = 0usize;
    let mut unserved = 0usize;
    for row in &manifest.rows {
        let (trial, provider) = row
            .case_id
            .strip_prefix("TP-PROVIDER-")
            .and_then(|rest| rest.split_once("::"))
            .expect("the case id is the provider_case shape");
        assert_eq!(row.provider, provider, "{}", row.case_id);
        assert!(OFFLINE_PROVIDER_TRIALS.contains(&trial), "{}", row.case_id);
        assert_eq!(row.marker, format!("ROW {} ok", row.case_id));
        assert!(
            !row.observation.trim().is_empty() && !row.observation.contains('\n'),
            "{} carries a one-line observation",
            row.case_id
        );
        assert!(!row.oracle.is_empty(), "{} names an oracle", row.case_id);
        for oracle in &row.oracle {
            let (target, test) = oracle.split_once("::").expect("an oracle is target::test");
            assert!(!matches!(target, "lib" | "bin"), "{oracle}");
            assert!(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("tests")
                    .join(format!("{target}.rs"))
                    .is_file(),
                "{oracle} names an integration target"
            );
            assert!(!test.trim().is_empty(), "{oracle}");
            assert!(
                target != "provider_registry"
                    || !test.contains("roster_matches_the_recorded_dialect_arms"),
                "a generic roster test is not a row oracle: {oracle}"
            );
        }
        match row.expected {
            TrialExpectation::Pass => {
                pass += 1;
                assert!(
                    !is_unserved_case(&row.case_id),
                    "{} is not the recorded unserved class",
                    row.case_id
                );
                assert!(
                    row.oracle
                        .iter()
                        .all(|oracle| !oracle.starts_with("provider_unserved::")),
                    "{} maps to an adapter-surface oracle",
                    row.case_id
                );
            }
            TrialExpectation::Unserved => {
                unserved += 1;
                assert!(
                    is_unserved_case(&row.case_id),
                    "{} is one of the six recorded denials",
                    row.case_id
                );
                assert!(
                    row.oracle.iter().all(|oracle| {
                        matches!(
                            oracle.as_str(),
                            "provider_unserved::cursor_send_denies_unserved_with_zero_requests"
                                | "provider_unserved::devin_send_denies_unserved_with_zero_requests"
                                | "provider_unserved::unserved_denial_names_the_recorded_transport"
                        )
                    }),
                    "{} maps only to the typed zero-request denials",
                    row.case_id
                );
            }
        }
    }
    assert_eq!((pass, unserved), (216, 6), "216 pass + 6 unserved");
    let recorded: BTreeSet<String> = unserved_cases().into_iter().collect();
    let observed: BTreeSet<String> = manifest
        .rows
        .iter()
        .filter(|row| row.expected == TrialExpectation::Unserved)
        .map(|row| row.case_id.clone())
        .collect();
    assert_eq!(observed, recorded, "the six unserved ids are exact");
    assert_eq!(
        manifest
            .rows
            .iter()
            .flat_map(|row| {
                row.oracle
                    .iter()
                    .map(|oracle| oracle.split_once("::").expect("target::test").0.to_string())
            })
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "provider_anthropic".to_string(),
            "provider_bedrock".to_string(),
            "provider_cloudcode".to_string(),
            "provider_copilot".to_string(),
            "provider_gemini".to_string(),
            "provider_gitlab".to_string(),
            "provider_local".to_string(),
            "provider_openai".to_string(),
            "provider_unserved".to_string(),
            "provider_vertex".to_string(),
        ]),
        "the manifest names only provider integration targets"
    );
}
