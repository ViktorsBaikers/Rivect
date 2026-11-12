//! Acceptance-row oracles that no existing integration target discriminates.
//! A20: green local parts do not prove a shared candidate whose declared
//! contract is incompatible, and the refusal records no candidate attempt.

mod support;

use rivect::actions::{
    ActionError, ActionInput, ActionRegistry, CandidateEvidence, ValidateIntegrationInput,
};
use rivect::config::Config;
use rivect::contracts::ErrorCode;

#[test]
fn incompatible_shared_contract_is_refused_and_no_attempt_is_recorded() {
    let mut world = support::open_world("acceptance-incompatible-contract", None);
    let session = world.open_session("acceptance-incompatible-session");
    let task = world.create_task(&session, "acceptance-incompatible-contract-task");
    let config = Config::parse_validated(&support::base_config()).expect("config parses");
    let error = ActionRegistry::new()
        .execute(
            ActionInput::ValidateIntegration(ValidateIntegrationInput {
                task_id: task.clone(),
                candidate: CandidateEvidence {
                    digest: "candidate-digest".to_string(),
                    consumers: vec!["controller".to_string(), "cli".to_string()],
                    compatibility: vec!["incompatible: shared envelope v2".to_string()],
                },
                local_passes: vec!["cargo test --test acceptance_rows".to_string()],
            }),
            &mut world.runtime.action_context(&session, &config),
        )
        .expect_err("an incompatible shared contract fails the joint candidate");
    assert!(
        matches!(error, ActionError::IntegrationIncompatible { .. }),
        "the refusal names the broken contract: {error}"
    );
    assert_eq!(error.error_code(), ErrorCode::Conflict);
    let snapshot = world.runtime.store().snapshot(&task).expect("snapshot");
    assert_eq!(
        snapshot.attempts.items.len(),
        0,
        "green parts alone record no candidate attempt"
    );
    println!("ROW A20 ok");
}
