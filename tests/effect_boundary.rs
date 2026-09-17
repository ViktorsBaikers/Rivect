#![allow(
    clippy::expect_used,
    clippy::panic,
    reason = "test fixtures use expect for setup failures and panic on wrong outcomes (standards §14)"
)]

mod support;

use rivect::contracts::{SessionId, TaskId};
use rivect::executor::macos::{FileIdentity, WRITE_MAX_BYTES};
use rivect::executor::{
    EffectRequest, Executor, ExecutorError, ReadObservation, ReadWorker, WorkerError,
};
use rivect::policy::{Policy, PolicyError};
use std::path::{Path, PathBuf};
use support::open_world;

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

fn managed_write_fixture(tag: &str) -> (support::World, SessionId, TaskId, PathBuf, String) {
    let mut world = open_world(tag, None);
    let session = world.open_session(&format!("{tag}-session"));
    let task = world.create_task(&session, &format!("{tag}-task"));
    let scope = world.root.join("scope");
    std::fs::create_dir_all(&scope).expect("create managed-write scope");
    let file = scope.join("target.txt");
    std::fs::write(&file, b"original").expect("create managed-write target");
    let grant = world.runtime.set_read_scope(scope, file.clone());
    world.runtime.read_worker = Box::new(rivect::executor::macos::MacosReadWorker);
    (world, session, task, file, grant)
}

#[test]
fn read_admit_fails_closed_when_deny_covers_target() {
    let (mut world, _session, task, file, grant) = managed_write_fixture("mode-deny-read-admit");
    world
        .runtime
        .policy
        .enroll_deny(&file)
        .expect("deny enrollment on read target");
    let error = {
        let mut executor = Executor::new(
            &mut world.runtime.policy,
            &mut world.runtime.owner.store,
            world.runtime.read_worker.as_mut(),
        );
        executor
            .admit(
                &task,
                EffectRequest::Read {
                    grant_id: grant,
                    path: file.clone(),
                },
            )
            .expect_err("mode consult must deny the covered read")
    };
    assert!(matches!(error, ExecutorError::ModeDenied));
    assert_eq!(
        world
            .runtime
            .owner
            .store
            .latest_unresolved_attempt(&task)
            .expect("read unresolved attempts"),
        None,
        "the denied attempt must be settled in the ledger"
    );
    assert_eq!(
        std::fs::read(&file).expect("read target after deny"),
        b"original"
    );
}

#[test]
fn decision_step_denies_dispatch_when_deny_covers_scoped_file() {
    let (mut world, session, task, file, grant) = managed_write_fixture("mode-deny-decision-step");
    let question = world.publish(&session, &task);
    let answer = world.dispatch(&support::corpus_answer_option(
        &session,
        "mode-deny-answer",
        &task,
        &question,
        "brief",
        serde_json::json!(1),
    ));
    assert!(answer["error"].is_null(), "{answer}");
    world
        .runtime
        .policy
        .enroll_deny(&file)
        .expect("deny enrollment on scoped file");
    let outcome = world
        .runtime
        .run_decision_step(
            &session,
            &task,
            &rivect::contracts::AnswerSelection::Option {
                option_id: rivect::contracts::OptionId("brief".to_string()),
            },
            &grant,
            false,
        )
        .expect("decision step runs");
    match outcome {
        rivect::controller::StepOutcome::EffectDenied { reason, .. } => {
            assert_eq!(reason, rivect::executor::MODE_DENY_REASON);
        }
        other => panic!("expected effect denial, got {other:?}"),
    }
    assert_eq!(world.runtime.provider_calls, 0);
}

#[test]
fn decision_step_fails_closed_when_scope_is_unobservable() {
    let mut world = open_world("decision-ask-gate", None);
    let session = world.open_session("ask-gate-session");
    let task = world.create_task(&session, "ask-gate-task");
    // A scope pair that cannot be observed on disk: the derived scope
    // input fails closed and the fixed interim manual mode turns the
    // dispatch read into an ask, which must gate the dispatch exactly
    // like a deny instead of falling through to the provider.
    let missing_root = world.root.join("never-created");
    let grant = world
        .runtime
        .set_read_scope(missing_root.clone(), missing_root.join("file.txt"));
    let outcome = world
        .runtime
        .run_decision_step(
            &session,
            &task,
            &rivect::contracts::AnswerSelection::Custom {
                text: "read nothing".to_string(),
            },
            &grant,
            false,
        )
        .expect("decision step runs");
    match outcome {
        rivect::controller::StepOutcome::EffectDenied { reason, .. } => {
            assert_eq!(reason, rivect::executor::MODE_ASK_REASON);
        }
        other => panic!("expected ask-gated effect denial, got {other:?}"),
    }
    assert_eq!(world.runtime.provider_calls, 0);
}

#[test]
fn read_rechecks_mode_verdict_between_admit_and_execute() {
    let (mut world, _session, task, file, grant) = managed_write_fixture("read-redecide-deny");
    let admitted = {
        let mut executor = Executor::new(
            &mut world.runtime.policy,
            &mut world.runtime.owner.store,
            world.runtime.read_worker.as_mut(),
        );
        executor
            .admit(
                &task,
                EffectRequest::Read {
                    grant_id: grant,
                    path: file.clone(),
                },
            )
            .expect("manual scoped read admits")
    };
    world
        .runtime
        .policy
        .enroll_deny(&file)
        .expect("deny enrolled after admission");

    let error = {
        let mut executor = Executor::new(
            &mut world.runtime.policy,
            &mut world.runtime.owner.store,
            world.runtime.read_worker.as_mut(),
        );
        executor
            .execute(&admitted)
            .expect_err("a deny enrolled after admission must block the read")
    };

    assert!(matches!(error, ExecutorError::ModeDenied), "{error}");
    let (_, state, detail) = world
        .runtime
        .owner
        .store
        .attempt_record(&admitted.attempt_id)
        .expect("read attempt readable")
        .expect("read attempt exists");
    assert_eq!(state, "rejected");
    assert_eq!(detail.as_deref(), Some(rivect::executor::MODE_DENY_REASON));
}

#[test]
fn execute_settles_rejected_when_context_fails() {
    let (mut world, _session, task, file, grant) = managed_write_fixture("execute-context-fail");
    let admitted = {
        let mut executor = Executor::new(
            &mut world.runtime.policy,
            &mut world.runtime.owner.store,
            world.runtime.read_worker.as_mut(),
        );
        executor
            .admit(
                &task,
                EffectRequest::Read {
                    grant_id: grant,
                    path: file.clone(),
                },
            )
            .expect("manual scoped read admits")
    };
    // Swap the target for a symlink pointing outside the admitted scope
    // between admission and execution: the context re-consult now fails
    // with the worker's typed out-of-scope denial.
    let outside = world.root.join("outside.txt");
    std::fs::write(&outside, b"outside").expect("create outside target");
    std::fs::remove_file(&file).expect("remove scoped target");
    symlink(&outside, &file).expect("swap target for out-of-scope symlink");

    let error = {
        let mut executor = Executor::new(
            &mut world.runtime.policy,
            &mut world.runtime.owner.store,
            world.runtime.read_worker.as_mut(),
        );
        executor
            .execute(&admitted)
            .expect_err("an out-of-scope target must fail the re-consult")
    };
    assert!(
        matches!(
            &error,
            ExecutorError::Worker(WorkerError::OutsideScope { .. })
        ),
        "{error}"
    );
    // Settled-ness oracle: the attempt is rejected with the error's
    // reason, never left planned forever.
    let (_, state, detail) = world
        .runtime
        .owner
        .store
        .attempt_record(&admitted.attempt_id)
        .expect("read attempt readable")
        .expect("read attempt exists");
    assert_eq!(state, "rejected");
    assert_eq!(detail, Some(error.to_string()));
}

#[test]
fn execute_unconfirmed_settles_rejected_when_context_fails() {
    let (mut world, _session, task, file, grant) =
        managed_write_fixture("unconfirmed-context-fail");
    let admitted = {
        let mut executor = Executor::new(
            &mut world.runtime.policy,
            &mut world.runtime.owner.store,
            world.runtime.read_worker.as_mut(),
        );
        executor
            .admit(
                &task,
                EffectRequest::Read {
                    grant_id: grant,
                    path: file.clone(),
                },
            )
            .expect("manual scoped read admits")
    };
    let outside = world.root.join("outside.txt");
    std::fs::write(&outside, b"outside").expect("create outside target");
    std::fs::remove_file(&file).expect("remove scoped target");
    symlink(&outside, &file).expect("swap target for out-of-scope symlink");

    let error = {
        let mut executor = Executor::new(
            &mut world.runtime.policy,
            &mut world.runtime.owner.store,
            world.runtime.read_worker.as_mut(),
        );
        executor
            .execute_unconfirmed(&admitted)
            .expect_err("an out-of-scope target must fail the re-consult")
    };
    assert!(
        matches!(
            &error,
            ExecutorError::Worker(WorkerError::OutsideScope { .. })
        ),
        "{error}"
    );
    let (_, state, detail) = world
        .runtime
        .owner
        .store
        .attempt_record(&admitted.attempt_id)
        .expect("read attempt readable")
        .expect("read attempt exists");
    assert_eq!(state, "rejected");
    assert_eq!(detail, Some(error.to_string()));
}

#[test]
fn execute_settles_rejected_when_grant_revoked() {
    let (mut world, _session, task, file, grant) = managed_write_fixture("execute-grant-revoked");
    let admitted = {
        let mut executor = Executor::new(
            &mut world.runtime.policy,
            &mut world.runtime.owner.store,
            world.runtime.read_worker.as_mut(),
        );
        executor
            .admit(
                &task,
                EffectRequest::Read {
                    grant_id: grant.clone(),
                    path: file,
                },
            )
            .expect("manual scoped read admits")
    };
    world.runtime.policy.revoke(&grant);

    let error = {
        let mut executor = Executor::new(
            &mut world.runtime.policy,
            &mut world.runtime.owner.store,
            world.runtime.read_worker.as_mut(),
        );
        executor
            .execute(&admitted)
            .expect_err("revoked grant must reject the read")
    };

    assert!(matches!(
        &error,
        ExecutorError::Policy(PolicyError::Revoked { grant_id: revoked })
            if revoked == &grant
    ));
    // Settled-ness oracle: the failed grant gate settles the attempt
    // rejected with the error's reason, never planned forever.
    let (_, state, detail) = world
        .runtime
        .owner
        .store
        .attempt_record(&admitted.attempt_id)
        .expect("read attempt readable")
        .expect("read attempt exists");
    assert_eq!(state, "rejected");
    assert_eq!(detail, Some(error.to_string()));
}

#[test]
fn execute_unconfirmed_settles_rejected_when_grant_revoked() {
    let (mut world, _session, task, file, grant) =
        managed_write_fixture("unconfirmed-grant-revoked");
    let admitted = {
        let mut executor = Executor::new(
            &mut world.runtime.policy,
            &mut world.runtime.owner.store,
            world.runtime.read_worker.as_mut(),
        );
        executor
            .admit(
                &task,
                EffectRequest::Read {
                    grant_id: grant.clone(),
                    path: file,
                },
            )
            .expect("manual scoped read admits")
    };
    world.runtime.policy.revoke(&grant);

    let error = {
        let mut executor = Executor::new(
            &mut world.runtime.policy,
            &mut world.runtime.owner.store,
            world.runtime.read_worker.as_mut(),
        );
        executor
            .execute_unconfirmed(&admitted)
            .expect_err("revoked grant must reject the read")
    };

    assert!(matches!(
        &error,
        ExecutorError::Policy(PolicyError::Revoked { grant_id: revoked })
            if revoked == &grant
    ));
    // Settled-ness oracle: the failed grant gate settles the attempt
    // rejected with the error's reason, never planned forever.
    let (_, state, detail) = world
        .runtime
        .owner
        .store
        .attempt_record(&admitted.attempt_id)
        .expect("read attempt readable")
        .expect("read attempt exists");
    assert_eq!(state, "rejected");
    assert_eq!(detail, Some(error.to_string()));
}

#[test]
fn execute_settles_rejected_when_grant_unknown() {
    let (mut world, _session, task, file, grant) = managed_write_fixture("execute-grant-unknown");
    let admitted = {
        let mut executor = Executor::new(
            &mut world.runtime.policy,
            &mut world.runtime.owner.store,
            world.runtime.read_worker.as_mut(),
        );
        executor
            .admit(
                &task,
                EffectRequest::Read {
                    grant_id: grant.clone(),
                    path: file,
                },
            )
            .expect("manual scoped read admits")
    };
    // The grant registry forgets the admission between admission and
    // execution (an owner restart reopens a fresh policy): the grant
    // re-check must settle the attempt rejected with the typed
    // unknown-grant error, never leave it planned forever.
    world.runtime.policy = Policy::default();

    let error = {
        let mut executor = Executor::new(
            &mut world.runtime.policy,
            &mut world.runtime.owner.store,
            world.runtime.read_worker.as_mut(),
        );
        executor
            .execute(&admitted)
            .expect_err("unknown grant must reject the read")
    };

    assert!(matches!(
        &error,
        ExecutorError::Policy(PolicyError::UnknownGrant { grant_id: unknown })
            if unknown == &grant
    ));
    // Settled-ness oracle: the failed grant gate settles the attempt
    // rejected with the error's reason, never planned forever.
    let (_, state, detail) = world
        .runtime
        .owner
        .store
        .attempt_record(&admitted.attempt_id)
        .expect("read attempt readable")
        .expect("read attempt exists");
    assert_eq!(state, "rejected");
    assert_eq!(detail, Some(error.to_string()));
}

struct PostMutationFailureWorker;

impl ReadWorker for PostMutationFailureWorker {
    fn read_once(
        &mut self,
        _scope_root: &Path,
        _target: &Path,
    ) -> Result<ReadObservation, WorkerError> {
        Err(WorkerError::ReadFailed {
            source: std::io::Error::other("unused read path"),
        })
    }

    fn write_once(
        &mut self,
        _scope_root: &Path,
        target: &Path,
        _expected: FileIdentity,
        _bytes: &[u8],
    ) -> Result<(), WorkerError> {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(target)
            .map_err(|source| WorkerError::WriteFailed { source })?;
        file.set_len(0)
            .map_err(|source| WorkerError::WriteMutationFailed { source })?;
        Err(WorkerError::WriteMutationFailed {
            source: std::io::Error::other("injected post-mutation failure"),
        })
    }
}

#[test]
fn managed_write_rejects_occupant_swap_without_touching_new_file() {
    let (mut world, _session, task, file, grant) = managed_write_fixture("managed-write-occupant");
    let admitted = {
        let mut executor = Executor::new(
            &mut world.runtime.policy,
            &mut world.runtime.owner.store,
            world.runtime.read_worker.as_mut(),
        );
        executor
            .admit_managed_write(
                &task,
                EffectRequest::Write {
                    grant_id: grant,
                    path: file.clone(),
                    bytes: b"replacement".to_vec(),
                },
            )
            .expect("managed write admission")
    };
    std::fs::remove_file(&file).expect("remove admitted occupant");
    std::fs::write(&file, b"new occupant").expect("replace admitted occupant");

    let error = {
        let mut executor = Executor::new(
            &mut world.runtime.policy,
            &mut world.runtime.owner.store,
            world.runtime.read_worker.as_mut(),
        );
        executor
            .execute_managed_write(&admitted)
            .expect_err("occupant swap must deny the write")
    };

    assert!(matches!(
        error,
        ExecutorError::Worker(WorkerError::TargetChanged { target })
            if target.as_path() == file.as_path()
    ));
    assert_eq!(
        world
            .runtime
            .owner
            .store
            .latest_unresolved_attempt(&task)
            .expect("read unresolved managed write attempt"),
        None
    );
    assert_eq!(
        std::fs::read(&file).expect("read new occupant"),
        b"new occupant"
    );
}

#[test]
fn managed_write_writes_exact_bytes_on_checked_fd() {
    let (mut world, _session, task, file, grant) = managed_write_fixture("managed-write-control");
    let admitted = {
        let mut executor = Executor::new(
            &mut world.runtime.policy,
            &mut world.runtime.owner.store,
            world.runtime.read_worker.as_mut(),
        );
        executor
            .admit_managed_write(
                &task,
                EffectRequest::Write {
                    grant_id: grant,
                    path: file.clone(),
                    bytes: b"exact control bytes".to_vec(),
                },
            )
            .expect("managed write admission")
    };

    {
        let mut executor = Executor::new(
            &mut world.runtime.policy,
            &mut world.runtime.owner.store,
            world.runtime.read_worker.as_mut(),
        );
        executor
            .execute_managed_write(&admitted)
            .expect("matching managed write")
    }

    assert_eq!(
        std::fs::read(&file).expect("read managed write"),
        b"exact control bytes"
    );
}

#[test]
fn managed_write_records_unknown_after_post_mutation_failure() {
    let (mut world, _session, task, file, grant) = managed_write_fixture("managed-write-unknown");
    world.runtime.read_worker = Box::new(PostMutationFailureWorker);
    let admitted = {
        let mut executor = Executor::new(
            &mut world.runtime.policy,
            &mut world.runtime.owner.store,
            world.runtime.read_worker.as_mut(),
        );
        executor
            .admit_managed_write(
                &task,
                EffectRequest::Write {
                    grant_id: grant,
                    path: file.clone(),
                    bytes: b"uncertain bytes".to_vec(),
                },
            )
            .expect("managed write admission")
    };

    let error = {
        let mut executor = Executor::new(
            &mut world.runtime.policy,
            &mut world.runtime.owner.store,
            world.runtime.read_worker.as_mut(),
        );
        executor
            .execute_managed_write(&admitted)
            .expect_err("post-mutation failure must surface")
    };

    assert!(matches!(
        error,
        ExecutorError::Worker(WorkerError::WriteMutationFailed { .. })
    ));
    let attempt_id = world
        .runtime
        .owner
        .store
        .snapshot(&task)
        .expect("read managed write snapshot")
        .attempts
        .items
        .last()
        .expect("managed write attempt exists")
        .attempt_id
        .0
        .clone();
    let (_, state, detail) = world
        .runtime
        .owner
        .store
        .attempt_record(&attempt_id)
        .expect("read managed write attempt")
        .expect("managed write attempt exists");
    assert_eq!(state, "unknown");
    assert!(
        detail
            .as_deref()
            .is_some_and(|detail| detail.contains("after mutation")),
        "unknown attempt should retain mutation detail"
    );
    assert_eq!(std::fs::read(&file).expect("read mutated target"), b"");
}

#[test]
fn managed_write_truncates_longer_occupant_to_exact_bytes() {
    let (mut world, _session, task, file, grant) = managed_write_fixture("managed-write-shrink");
    let admitted = {
        let mut executor = Executor::new(
            &mut world.runtime.policy,
            &mut world.runtime.owner.store,
            world.runtime.read_worker.as_mut(),
        );
        executor
            .admit_managed_write(
                &task,
                EffectRequest::Write {
                    grant_id: grant,
                    path: file.clone(),
                    bytes: b"short".to_vec(),
                },
            )
            .expect("managed write admission")
    };

    {
        let mut executor = Executor::new(
            &mut world.runtime.policy,
            &mut world.runtime.owner.store,
            world.runtime.read_worker.as_mut(),
        );
        executor
            .execute_managed_write(&admitted)
            .expect("shrinking managed write")
    }

    assert_eq!(
        std::fs::read(&file).expect("read shrunk managed write"),
        b"short"
    );
}

#[test]
fn managed_write_rejects_opened_fd_identity_mismatch_after_path_swap() {
    let (_world, _session, _task, file, _grant) =
        managed_write_fixture("managed-write-fd-identity");
    let mut opened = std::fs::OpenOptions::new()
        .write(true)
        .open(&file)
        .expect("open admitted occupant");
    let original = file.with_file_name("original-occupant.txt");
    std::fs::rename(&file, &original).expect("move admitted occupant");
    std::fs::write(&file, b"new occupant").expect("replace admitted occupant");

    let path_metadata = std::fs::metadata(&file).expect("inspect new occupant");
    let opened_metadata = opened.metadata().expect("inspect opened occupant");
    assert_ne!(
        (path_metadata.dev(), path_metadata.ino()),
        (opened_metadata.dev(), opened_metadata.ino()),
        "path and opened-fd identities must diverge"
    );
    let expected = FileIdentity {
        dev: path_metadata.dev(),
        ino: path_metadata.ino(),
    };
    let error = rivect::executor::macos::write_once_on_opened_file(
        file.parent().expect("managed-write scope"),
        &file,
        &mut opened,
        expected,
        b"must not land",
    )
    .expect_err("mismatched opened identity must deny");

    assert!(matches!(
        error,
        WorkerError::TargetChanged { target }
            if target.as_path() == file.as_path()
    ));
    assert_eq!(
        std::fs::read(&file).expect("read new occupant"),
        b"new occupant"
    );
    assert_eq!(
        std::fs::read(&original).expect("read original occupant"),
        b"original"
    );
}

#[test]
fn managed_write_rejects_oversized_payload_without_touching_target() {
    let (_world, _session, _task, file, _grant) = managed_write_fixture("managed-write-too-large");
    let bytes = vec![b'x'; WRITE_MAX_BYTES + 1];
    let error = rivect::executor::macos::write_once(
        file.parent().expect("managed-write scope"),
        &file,
        FileIdentity { dev: 0, ino: 0 },
        &bytes,
    )
    .expect_err("oversized managed write must deny");

    assert!(matches!(error, WorkerError::WriteTooLarge));
    assert_eq!(
        std::fs::read(&file).expect("read unchanged target"),
        b"original"
    );
}

#[test]
fn managed_write_rechecks_revoked_grant_before_writing() {
    let (mut world, _session, task, file, grant) = managed_write_fixture("managed-write-revoked");
    let admitted = {
        let mut executor = Executor::new(
            &mut world.runtime.policy,
            &mut world.runtime.owner.store,
            world.runtime.read_worker.as_mut(),
        );
        executor
            .admit_managed_write(
                &task,
                EffectRequest::Write {
                    grant_id: grant.clone(),
                    path: file.clone(),
                    bytes: b"must not land".to_vec(),
                },
            )
            .expect("managed write admission")
    };
    world.runtime.policy.revoke(&grant);

    let error = {
        let mut executor = Executor::new(
            &mut world.runtime.policy,
            &mut world.runtime.owner.store,
            world.runtime.read_worker.as_mut(),
        );
        executor
            .execute_managed_write(&admitted)
            .expect_err("revoked grant must reject the write")
    };

    assert!(matches!(
        &error,
        ExecutorError::Policy(PolicyError::Revoked { grant_id })
            if grant_id == &grant
    ));
    assert_eq!(
        std::fs::read(&file).expect("read revoked target"),
        b"original"
    );
    // Settled-ness oracle: the failed grant gate settles the attempt
    // rejected with the error's reason, never planned forever.
    let attempt_id = world
        .runtime
        .owner
        .store
        .snapshot(&task)
        .expect("read managed write snapshot")
        .attempts
        .items
        .last()
        .expect("managed write attempt exists")
        .attempt_id
        .0
        .clone();
    let (_, state, detail) = world
        .runtime
        .owner
        .store
        .attempt_record(&attempt_id)
        .expect("managed write attempt readable")
        .expect("managed write attempt exists");
    assert_eq!(state, "rejected");
    assert_eq!(detail, Some(error.to_string()));
}

#[test]
fn managed_write_rechecks_cancel_before_writing() {
    let (mut world, session, task, file, grant) = managed_write_fixture("managed-write-cancel");
    let admitted = {
        let mut executor = Executor::new(
            &mut world.runtime.policy,
            &mut world.runtime.owner.store,
            world.runtime.read_worker.as_mut(),
        );
        executor
            .admit_managed_write(
                &task,
                EffectRequest::Write {
                    grant_id: grant,
                    path: file.clone(),
                    bytes: b"must not land".to_vec(),
                },
            )
            .expect("managed write admission")
    };
    world
        .runtime
        .owner
        .store
        .cancel_task(&session, &task, 1, Some("cancel before managed write"))
        .expect("cancel managed write task");

    let error = {
        let mut executor = Executor::new(
            &mut world.runtime.policy,
            &mut world.runtime.owner.store,
            world.runtime.read_worker.as_mut(),
        );
        executor
            .execute_managed_write(&admitted)
            .expect_err("cancelled task must reject the write")
    };

    assert!(matches!(error, ExecutorError::Cancelled));
    assert_eq!(
        std::fs::read(&file).expect("read cancelled target"),
        b"original"
    );
}

#[test]
fn managed_write_rechecks_deny_before_writing() {
    let (mut world, _session, task, file, grant) = managed_write_fixture("managed-write-deny");
    let admitted = {
        let mut executor = Executor::new(
            &mut world.runtime.policy,
            &mut world.runtime.owner.store,
            world.runtime.read_worker.as_mut(),
        );
        executor
            .admit_managed_write(
                &task,
                EffectRequest::Write {
                    grant_id: grant,
                    path: file.clone(),
                    bytes: b"must not land".to_vec(),
                },
            )
            .expect("managed write admission")
    };
    world
        .runtime
        .policy
        .enroll_deny(&file)
        .expect("enroll deny between admission and write");

    let error = {
        let mut executor = Executor::new(
            &mut world.runtime.policy,
            &mut world.runtime.owner.store,
            world.runtime.read_worker.as_mut(),
        );
        executor
            .execute_managed_write(&admitted)
            .expect_err("mid-flight deny must reject the write")
    };

    assert!(matches!(error, ExecutorError::PolicyDenied));
    assert_eq!(
        std::fs::read(&file).expect("read denied target"),
        b"original"
    );
}

struct TempTree {
    path: PathBuf,
}

impl TempTree {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "rivect-effect-boundary-{name}-{}",
            std::process::id()
        ));
        if path.exists() {
            std::fs::remove_dir_all(&path).expect("remove stale fixture");
        }
        std::fs::create_dir_all(&path).expect("create fixture");
        Self { path }
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        if self.path.exists() {
            drop(std::fs::remove_dir_all(&self.path));
        }
    }
}

#[cfg(unix)]
struct UnreadableDir {
    path: PathBuf,
    original_mode: u32,
}

#[cfg(unix)]
impl UnreadableDir {
    fn new(path: PathBuf) -> Self {
        let mut permissions = std::fs::metadata(&path)
            .expect("inspect directory")
            .permissions();
        let original_mode = permissions.mode();
        permissions.set_mode(0o000);
        std::fs::set_permissions(&path, permissions).expect("remove directory permissions");
        Self {
            path,
            original_mode,
        }
    }
}

#[cfg(unix)]
impl Drop for UnreadableDir {
    fn drop(&mut self) {
        let Ok(metadata) = std::fs::metadata(&self.path) else {
            return;
        };
        let mut permissions = metadata.permissions();
        permissions.set_mode(self.original_mode);
        drop(std::fs::set_permissions(&self.path, permissions));
    }
}

#[test]
fn collapsed_tail_reentry_is_denied_without_denial_of_strict_prefix() {
    let fixture = TempTree::new("collapsed-tail");
    std::fs::create_dir_all(fixture.path.join("R")).expect("create R");
    let mut policy = Policy::default();
    policy
        .enroll_deny(fixture.path.join("R/y/.."))
        .expect("deny enrollment");

    assert!(
        policy.covers(fixture.path.join("R/x/../../R/kid")),
        "collapsed-tail re-entry must remain denied"
    );
    assert!(
        !policy.covers(fixture.path.join("R")),
        "strict-prefix ancestor must remain allowed"
    );
}

#[test]
fn existing_cancelled_tail_keeps_strict_prefix_allowed() {
    let fixture = TempTree::new("existing-tail");
    std::fs::create_dir_all(fixture.path.join("R/y")).expect("create existing tail");
    let mut policy = Policy::default();
    policy
        .enroll_deny(fixture.path.join("R/y/.."))
        .expect("deny enrollment");

    assert!(!policy.covers(fixture.path.join("R")));
    assert!(policy.covers(fixture.path.join("R/sibling")));
}

#[cfg(unix)]
#[test]
fn missing_prefix_reentry_resumes_symlink_resolution() {
    let fixture = TempTree::new("missing-reentry");
    std::fs::create_dir_all(fixture.path.join("allowed")).expect("create allowed");
    std::fs::create_dir_all(fixture.path.join("denied")).expect("create denied");
    std::fs::write(fixture.path.join("denied/kid"), b"denied").expect("create denied target");
    symlink(
        fixture.path.join("denied/kid"),
        fixture.path.join("allowed/link_to_denied"),
    )
    .expect("create denied link");

    let mut policy = Policy::default();
    policy
        .enroll_deny(fixture.path.join("denied/kid"))
        .expect("deny enrollment");

    assert!(policy.covers(fixture.path.join("allowed/link_to_denied")));
    assert!(policy.covers(fixture.path.join("allowed/nope/../link_to_denied")));
}

#[test]
fn fold_equivalent_reentry_keeps_missing_suffix() {
    let fixture = TempTree::new("fold");
    let mut policy = Policy::default();
    policy
        .enroll_deny(fixture.path.join("other"))
        .expect("deny enrollment");

    assert!(
        policy.covers(fixture.path.join("root/x/../../Other")),
        "fold-equivalent re-entry must remain denied"
    );
}

#[test]
fn nfd_and_nfc_names_share_deny_identity() {
    let fixture = TempTree::new("unicode");
    let mut policy = Policy::default();
    policy
        .enroll_deny(fixture.path.join("caf\u{00e9}"))
        .expect("deny enrollment");

    assert!(policy.covers(fixture.path.join("cafe\u{0301}")));
}

#[test]
fn full_casefold_is_not_ascii_lowercasing() {
    let fixture = TempTree::new("casefold");
    let mut policy = Policy::default();
    policy
        .enroll_deny(fixture.path.join("Maße"))
        .expect("deny enrollment");

    assert!(policy.covers(fixture.path.join("MASSE")));
}

#[test]
fn deny_can_be_revoked_without_affecting_other_paths() {
    let fixture = TempTree::new("revoke");
    let mut policy = Policy::default();
    policy
        .enroll_deny(fixture.path.join("other"))
        .expect("deny enrollment");
    policy
        .enroll_deny(fixture.path.join("another"))
        .expect("deny enrollment");
    assert!(policy.covers(fixture.path.join("other")));

    policy
        .revoke_deny(fixture.path.join("other"))
        .expect("deny revocation");

    assert!(!policy.covers(fixture.path.join("other")));
    assert!(policy.covers(fixture.path.join("another")));
}

#[test]
fn revoke_matches_components_after_collapsed_enrollment() {
    let fixture = TempTree::new("revoke-collapsed");
    std::fs::create_dir_all(fixture.path.join("R")).expect("create R");
    let mut policy = Policy::default();
    policy
        .enroll_deny(fixture.path.join("R/y/.."))
        .expect("deny enrollment");

    policy
        .revoke_deny(fixture.path.join("R"))
        .expect("deny revocation");

    assert!(!policy.covers(fixture.path.join("R/kid")));
}

#[test]
fn revoke_matches_components_after_widening() {
    let fixture = TempTree::new("revoke-widened");
    std::fs::create_dir_all(fixture.path.join("R")).expect("create R");
    let mut policy = Policy::default();
    policy
        .enroll_deny(fixture.path.join("R/y/.."))
        .expect("strict enrollment");
    policy
        .enroll_deny(fixture.path.join("R"))
        .expect("wide enrollment");
    policy
        .enroll_deny(fixture.path.join("S"))
        .expect("other enrollment");
    assert!(policy.covers(fixture.path.join("R")));

    policy
        .revoke_deny(fixture.path.join("R/y/.."))
        .expect("deny revocation");

    assert!(!policy.covers(fixture.path.join("R")));
    assert!(policy.covers(fixture.path.join("S/kid")));
}

#[test]
fn revoke_matches_component_set_for_each_tail_flag() {
    fn covers_after_revoke(enrollments: &[&Path], revoke: &Path, request: &Path) -> bool {
        let mut policy = Policy::default();
        for enrollment in enrollments {
            policy.enroll_deny(enrollment).expect("deny enrollment");
        }
        policy.revoke_deny(revoke).expect("deny revocation");
        policy.covers(request)
    }

    let fixture = TempTree::new("revoke-tail-flags");
    std::fs::create_dir_all(fixture.path.join("R")).expect("create R");
    let strict = fixture.path.join("R/y/..");
    let wide = fixture.path.join("R");
    let root = fixture.path.join("R");
    let descendant = fixture.path.join("R/kid");

    assert!(!covers_after_revoke(
        &[strict.as_path()],
        &strict,
        &descendant,
    ));
    assert!(!covers_after_revoke(
        &[strict.as_path()],
        &wide,
        &descendant,
    ));
    assert!(!covers_after_revoke(
        &[strict.as_path(), wide.as_path()],
        &strict,
        &root,
    ));
    assert!(!covers_after_revoke(
        &[wide.as_path(), strict.as_path()],
        &wide,
        &root,
    ));
}

#[test]
fn relative_paths_are_rejected_and_covered_fail_closed() {
    let fixture = TempTree::new("relative");
    let denied = fixture.path.join("P0/other");
    let mut policy = Policy::default();
    policy.enroll_deny(&denied).expect("deny enrollment");

    assert!(matches!(
        policy.enroll_deny(Path::new("P0/other")),
        Err(PolicyError::InvalidPath)
    ));
    assert!(matches!(
        policy.revoke_deny(Path::new("P0/other")),
        Err(PolicyError::InvalidPath)
    ));
    assert!(matches!(
        policy.covers_report(Path::new("P0/other")),
        Err(PolicyError::InvalidPath)
    ));
    assert!(matches!(
        policy.covers_report(fixture.path.join("allowed")),
        Ok(false)
    ));
    assert!(policy.covers(Path::new("P0/other")));
}

#[test]
fn re_enrollment_after_lookup_state_change_matches_fresh_policy() {
    let fixture = TempTree::new("reenroll");
    let expression = fixture.path.join("R/y/..");
    std::fs::create_dir_all(fixture.path.join("R")).expect("create R");
    let mut policy = Policy::default();
    policy.enroll_deny(&expression).expect("initial enrollment");
    std::fs::create_dir(fixture.path.join("R/y")).expect("create y");
    policy.enroll_deny(&expression).expect("re-enrollment");

    assert!(!policy.covers(fixture.path.join("R")));
    assert!(policy.covers(fixture.path.join("R/kid")));
}

#[test]
fn wider_flagless_identity_replaces_strict_identity() {
    let fixture = TempTree::new("identity-width");
    std::fs::create_dir_all(fixture.path.join("R")).expect("create R");
    let mut policy = Policy::default();
    policy
        .enroll_deny(fixture.path.join("R/y/.."))
        .expect("strict enrollment");
    policy
        .enroll_deny(fixture.path.join("R"))
        .expect("wide enrollment");

    assert!(policy.covers(fixture.path.join("R")));
}

#[test]
fn wider_flagless_identity_wins_in_reverse_order() {
    let fixture = TempTree::new("identity-width-reverse");
    std::fs::create_dir_all(fixture.path.join("R")).expect("create R");
    let mut policy = Policy::default();
    policy
        .enroll_deny(fixture.path.join("R"))
        .expect("wide enrollment");
    policy
        .enroll_deny(fixture.path.join("R/y/.."))
        .expect("strict enrollment");

    assert!(policy.covers(fixture.path.join("R")));
}

#[cfg(unix)]
#[test]
fn leaf_symlink_reentry_uses_target_identity() {
    let fixture = TempTree::new("leaf-symlink");
    std::fs::create_dir_all(fixture.path.join("denied/R")).expect("create denied tree");
    std::fs::write(fixture.path.join("denied/R/kid"), b"denied").expect("create denied leaf");
    symlink(fixture.path.join("denied/R/kid"), fixture.path.join("trap"))
        .expect("create leaf symlink");

    let mut policy = Policy::default();
    policy
        .enroll_deny(fixture.path.join("denied/R/kid"))
        .expect("deny enrollment");

    assert!(policy.covers(fixture.path.join("trap")));
}

#[cfg(unix)]
#[test]
fn symlink_reentry_uses_target_identity() {
    let fixture = TempTree::new("directory-symlink");
    std::fs::create_dir_all(fixture.path.join("R")).expect("create fixture");
    symlink(fixture.path.join("R"), fixture.path.join("alias")).expect("create symlink");

    let mut policy = Policy::default();
    policy
        .enroll_deny(fixture.path.join("R/y/.."))
        .expect("deny enrollment");

    assert!(policy.covers(fixture.path.join("alias/x/../../R/kid")));
    assert!(!policy.covers(fixture.path.join("alias")));
}

#[cfg(unix)]
#[test]
fn observation_failure_fails_closed() {
    let fixture = TempTree::new("symlink-loop");
    let loop_path = fixture.path.join("loop");
    symlink("loop", &loop_path).expect("create symlink loop");
    let policy = Policy::default();

    assert!(matches!(
        policy.covers_report(&loop_path),
        Err(PolicyError::SymlinkLoop)
    ));
    assert!(policy.covers(&loop_path));
}

#[cfg(unix)]
#[test]
fn unreadable_directory_observation_fails_closed() {
    let fixture = TempTree::new("unreadable-directory");
    let blocked = fixture.path.join("blocked");
    std::fs::create_dir(&blocked).expect("create blocked directory");
    let _permissions = UnreadableDir::new(blocked.clone());
    let policy = Policy::default();
    let request = blocked.join("child");

    assert!(matches!(
        policy.covers_report(&request),
        Err(PolicyError::PathInspection {
            kind: std::io::ErrorKind::PermissionDenied
        })
    ));
    assert!(policy.covers(&request));
}
