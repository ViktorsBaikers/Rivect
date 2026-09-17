//! Seatbelt confinement proofs for the macOS effect worker (AC-008/AC-070,
//! EDGE-009/EDGE-010, PROH-001): read/write/exec/egress escapes are rejected
//! by the OS boundary, the worker probes sandbox conformance before its
//! first effect, the `sandbox-exec` deprecation stderr is filtered by exact
//! prefix, and a missing or non-enforcing boundary fails closed with
//! `capability_unavailable` — never an ambient effect.

#![cfg(target_os = "macos")]
#![allow(
    clippy::expect_used,
    clippy::panic,
    reason = "test fixtures use expect for setup failures and panic on wrong outcomes (standards §14)"
)]

mod support;

use rivect::contracts::ErrorCode;
use rivect::executor::macos::{self, ConfinedOutcome, ReadObservation, SANDBOX_EXEC, WorkerError};
use rivect::executor::{
    AdmittedEffect, EffectOutcome, EffectRequest, Executor, ExecutorError, ReadWorker,
};
use rivect::policy::{AdmissionContext, ModeDecision, PermissionMode, Policy};
use std::net::TcpListener;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
struct TempTree {
    path: PathBuf,
}

impl TempTree {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "rivect-sandbox-macos-{name}-{}",
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

fn sandbox_exec() -> PathBuf {
    PathBuf::from(SANDBOX_EXEC)
}

fn confined(
    profile: &str,
    program: &Path,
    args: &[&std::ffi::OsStr],
) -> Result<ConfinedOutcome, WorkerError> {
    macos::run_confined(&sandbox_exec(), profile, program, args)
}

/// World fixture mirroring the effect-boundary one: a scoped read grant and
/// the real macOS worker behind the executor.
fn sandbox_world(tag: &str) -> (support::World, rivect::contracts::TaskId, PathBuf, String) {
    let mut world = support::open_world(tag, None);
    let session = world.open_session(&format!("{tag}-session"));
    let task = world.create_task(&session, &format!("{tag}-task"));
    let scope = world.root.join("scope");
    std::fs::create_dir_all(&scope).expect("create sandbox scope");
    let file = scope.join("target.txt");
    std::fs::write(&file, b"scoped-by-seatbelt").expect("create sandbox target");
    let grant = world.runtime.set_read_scope(scope, file.clone());
    world.runtime.read_worker = Box::new(macos::MacosReadWorker);
    (world, task, file, grant)
}

#[test]
fn denies_read_outside_scope_at_the_os_boundary() {
    let fixture = TempTree::new("read-escape");
    let inside = fixture.path.join("inside.txt");
    std::fs::write(&inside, b"inside-marker").expect("create inside target");
    let outside_tree = TempTree::new("read-escape-outside");
    let outside = outside_tree.path.join("secret.txt");
    std::fs::write(&outside, b"secret").expect("create outside target");
    // Seatbelt filters match canonical paths, so the confined legs address
    // the canonical spelling, exactly like the worker does.
    let inside = inside.canonicalize().expect("canonical inside target");
    let outside = outside.canonicalize().expect("canonical outside target");

    let profile = macos::read_profile(&fixture.path).expect("read profile");
    let admitted =
        confined(&profile, Path::new("/bin/cat"), &[inside.as_os_str()]).expect("confined read");
    assert!(
        admitted.exit_ok,
        "in-scope read must be admitted: {admitted:?}"
    );

    let denied = confined(&profile, Path::new("/bin/cat"), &[outside.as_os_str()])
        .expect("confined read run");
    assert!(
        !denied.exit_ok,
        "an out-of-scope read must be rejected by the OS boundary: {denied:?}"
    );
    assert!(
        denied.stderr.contains("Operation not permitted"),
        "the OS boundary names its denial: {denied:?}"
    );
}
#[test]
fn denies_write_outside_scope_at_the_os_boundary() {
    let fixture = TempTree::new("write-escape");
    let inside = fixture.path.join("inside.txt");
    std::fs::write(&inside, b"original").expect("create inside target");
    let outside_tree = TempTree::new("write-escape-outside");
    let outside = outside_tree.path.join("victim.txt");
    std::fs::write(&outside, b"untouched").expect("create outside target");
    let before = std::fs::metadata(&outside).expect("outside metadata");
    let inside = inside.canonicalize().expect("canonical inside target");
    let outside = outside.canonicalize().expect("canonical outside target");

    let profile = macos::write_profile(&fixture.path).expect("write profile");
    let admitted = confined(&profile, Path::new("/usr/bin/touch"), &[inside.as_os_str()])
        .expect("confined write probe");
    assert!(
        admitted.exit_ok,
        "in-scope write must be admitted: {admitted:?}"
    );

    let denied = confined(
        &profile,
        Path::new("/usr/bin/touch"),
        &[outside.as_os_str()],
    )
    .expect("confined write run");
    assert!(
        !denied.exit_ok,
        "an out-of-scope write must be rejected by the OS boundary: {denied:?}"
    );
    assert!(
        denied.stderr.contains("Operation not permitted"),
        "the OS boundary names the write denial: {denied:?}"
    );
    let after = std::fs::metadata(&outside).expect("outside metadata after denial");
    assert_eq!(
        (before.dev(), before.ino(), before.mtime()),
        (after.dev(), after.ino(), after.mtime()),
        "a denied write must leave the outside target untouched"
    );
}

#[test]
fn denies_exec_outside_scope_at_the_os_boundary() {
    let fixture = TempTree::new("exec-escape");
    // In-scope control leg: the same profile must admit executing a
    // binary inside the scope, so the denial below discriminates the
    // scope boundary from an exec broken everywhere.
    let scoped = fixture.path.join("true");
    std::fs::copy("/usr/bin/true", &scoped).expect("copy in-scope executable");
    let scoped = scoped
        .canonicalize()
        .expect("canonical in-scope executable");
    let profile = macos::exec_profile(&fixture.path).expect("exec profile");
    let admitted = confined(&profile, &scoped, &[]).expect("confined exec control run");
    assert!(
        admitted.exit_ok,
        "an in-scope exec must be admitted under the same profile: {admitted:?}"
    );

    let denied = confined(
        &profile,
        Path::new("/bin/sleep"),
        &[std::ffi::OsStr::new("0")],
    )
    .expect("confined exec run");
    assert!(
        !denied.exit_ok,
        "an exec outside the scope must be rejected by the OS boundary: {denied:?}"
    );
    assert!(
        denied.stderr.contains("Operation not permitted"),
        "the OS boundary names the exec denial: {denied:?}"
    );
}
#[test]
fn denies_egress_at_the_os_boundary() {
    // Control leg first: a held-open loopback listener accepts the bare
    // connection, so the confined denial below proves the OS boundary,
    // not a dead port.
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback listener");
    let port = listener
        .local_addr()
        .expect("listener address")
        .port()
        .to_string();
    let bare = std::process::Command::new("/usr/bin/nc")
        .arg("-w")
        .arg("1")
        .arg("127.0.0.1")
        .arg(&port)
        .stdin(std::process::Stdio::null())
        .output()
        .expect("bare connect control run");
    assert!(
        bare.status.success(),
        "control leg must connect without confinement: {bare:?}"
    );

    let denied = confined(
        &macos::egress_profile(),
        Path::new("/usr/bin/nc"),
        &[
            std::ffi::OsStr::new("-w"),
            std::ffi::OsStr::new("1"),
            std::ffi::OsStr::new("127.0.0.1"),
            std::ffi::OsStr::new(&port),
        ],
    )
    .expect("confined egress run");
    assert!(
        !denied.exit_ok,
        "egress must be rejected by the OS boundary under the confined profile: {denied:?}"
    );

    // Confined control leg: the same profile plus exactly a network
    // allowance admits the connection, so the denial above names the
    // missing egress allowance — never a helper that cannot connect
    // under confinement at all.
    let admitting =
        macos::egress_profile().replacen("(version 1)\n", "(version 1)\n    (allow network*)\n", 1);
    let admitted = confined(
        &admitting,
        Path::new("/usr/bin/nc"),
        &[
            std::ffi::OsStr::new("-w"),
            std::ffi::OsStr::new("1"),
            std::ffi::OsStr::new("127.0.0.1"),
            std::ffi::OsStr::new(&port),
        ],
    )
    .expect("confined egress control run");
    assert!(
        admitted.exit_ok,
        "the confined profile with a network allowance must admit the egress: {admitted:?}"
    );
}
#[test]
fn worker_fails_closed_when_boundary_does_not_enforce() {
    // A mechanism that never denies is not a boundary: the conformance
    // probe must report capability unavailability instead of letting the
    // checked effect run unconfined (PROH-001, EDGE-009).
    let fixture = TempTree::new("non-enforcing");
    let target = fixture.path.join("target.txt");
    std::fs::write(&target, b"original").expect("create target");

    let error = macos::probe_read_conformance(Path::new("/usr/bin/true"), &fixture.path, &target)
        .expect_err("a non-enforcing boundary must fail the read conformance probe");
    assert!(
        matches!(
            error,
            WorkerError::SandboxUnavailable { ref reason } if reason.contains("admitted the denied read")
        ),
        "{error}"
    );
    let write_error = macos::probe_write_conformance(Path::new("/usr/bin/true"), &fixture.path)
        .expect_err("a non-enforcing boundary must fail the write conformance probe");
    assert!(
        matches!(
            write_error,
            WorkerError::SandboxUnavailable { ref reason } if reason.contains("admitted the denied write")
        ),
        "{write_error}"
    );

    // Control: the real mechanism passes the same probes for a confinable
    // scope, so the failures above name enforcement, not the probe shape.
    macos::probe_read_conformance(&sandbox_exec(), &fixture.path, &target)
        .expect("real boundary conforms for a confinable scope");
    macos::probe_write_conformance(&sandbox_exec(), &fixture.path)
        .expect("real write boundary conforms for a confinable scope");
}

#[test]
fn filters_deprecation_stderr_by_exact_prefix() {
    let raw = concat!(
        "WARNING: sandbox-exec is deprecated; see the manpage\n",
        "sandbox-exec: execvp() of '/bin/cat' failed: Operation not permitted\n",
        "not-the-prefix WARNING: sandbox-exec is deprecated kept\n",
    );
    let (retained, notices) = macos::split_deprecation_stderr(raw);
    assert_eq!(
        retained,
        concat!(
            "sandbox-exec: execvp() of '/bin/cat' failed: Operation not permitted\n",
            "not-the-prefix WARNING: sandbox-exec is deprecated kept",
        ),
        "only exact-prefix lines may be filtered"
    );
    assert_eq!(
        notices, "WARNING: sandbox-exec is deprecated; see the manpage",
        "the filtered warning is retained as a diagnostic notice"
    );
}

#[test]
fn sandbox_exec_init_failure_maps_to_capability_unavailable() {
    let fixture = TempTree::new("missing-mechanism");
    let target = fixture.path.join("target.txt");
    std::fs::write(&target, b"unchanged").expect("create target");
    let profile = macos::read_profile(&fixture.path).expect("read profile");

    let error = macos::run_confined(
        Path::new("/nonexistent/rivect-sandbox-exec"),
        &profile,
        Path::new("/bin/cat"),
        &[target.as_os_str()],
    )
    .expect_err("a missing sandbox mechanism must fail closed");
    assert!(
        matches!(error, WorkerError::SandboxSpawnFailed { .. }),
        "{error}"
    );
    let wire = ExecutorError::Worker(error);
    assert_eq!(wire.error_code(), ErrorCode::CapabilityUnavailable);
    let message = wire.to_string();
    assert!(message.contains("sandbox-exec"), "{message}");
    assert!(message.contains("recovery"), "{message}");
}

#[test]
fn worker_probes_conformance_before_first_effect() {
    // A scope that already covers the boundary's denied-probe target is not
    // confinable: the conformance probe must fail closed with
    // capability_unavailable before any effect byte moves, even though the
    // checked in-process leg would happily write the target.
    let fixture = TempTree::new("probe-order");
    let target = fixture.path.join("target.txt");
    std::fs::write(&target, b"original").expect("create target");
    let mut worker = macos::MacosReadWorker;

    let read_error = worker
        .read_once(Path::new("/"), &target)
        .expect_err("a non-confining scope must deny reads");
    assert!(
        matches!(
            read_error,
            WorkerError::SandboxUnavailable { ref reason } if reason.contains("conformance probe")
        ),
        "{read_error}"
    );

    let write_error = worker
        .write_once(
            Path::new("/"),
            &target,
            macos::FileIdentity { dev: 0, ino: 0 },
            b"must never land",
        )
        .expect_err("a non-confining scope must deny writes");
    assert!(
        matches!(write_error, WorkerError::SandboxUnavailable { .. }),
        "{write_error}"
    );
    assert_eq!(
        ExecutorError::Worker(write_error).error_code(),
        ErrorCode::CapabilityUnavailable
    );
    assert_eq!(
        std::fs::read(&target).expect("target survives probe failure"),
        b"original",
        "no ambient fallback: the probe failure must precede the write"
    );
}

#[test]
fn sandbox_worker_reads_scope_and_lands_checked_managed_write() {
    let (mut world, task, file, grant) = sandbox_world("worker-happy-path");
    let mut worker = macos::MacosReadWorker;
    let scope_root = file.parent().expect("scope root").to_path_buf();

    let ReadObservation { bytes, digest } = worker
        .read_once(&scope_root, &file)
        .expect("confined scoped read");
    assert_eq!(bytes, b"scoped-by-seatbelt");
    assert_eq!(digest, support::sha256_hex(&bytes));

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
                    bytes: b"replacement-by-seatbelt".to_vec(),
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
            .expect("checked managed write under seatbelt");
    }
    assert_eq!(
        std::fs::read(&file).expect("read managed write target"),
        b"replacement-by-seatbelt"
    );
}

/// The DEC-014 matrix verdicts the policy pins for one decision context.
fn matrix_verdict(mode: PermissionMode, class: rivect::contracts::EffectClass) -> ModeDecision {
    let policy = Policy::default();
    let ctx = AdmissionContext {
        mode,
        in_grant_scope: true,
        budget_remaining: true,
        in_trusted_scope: true,
        has_checkpoint: true,
        previously_approved: true,
        within_declared_bounds: true,
        dry_run: false,
    };
    policy.decide(Path::new("/scope/target"), class, &ctx)
}

#[test]
fn six_permission_modes_gate_the_seatbelt_worker() {
    use rivect::contracts::EffectClass as Class;
    // Verdicts per the §14.13 matrix with every granting input observed.
    for (mode, read, write, exec, egress) in [
        (
            PermissionMode::Manual,
            ModeDecision::Allow,
            ModeDecision::Ask,
            ModeDecision::Ask,
            ModeDecision::Ask,
        ),
        (
            PermissionMode::AcceptEdits,
            ModeDecision::Allow,
            ModeDecision::Allow,
            ModeDecision::Ask,
            ModeDecision::Ask,
        ),
        (
            PermissionMode::ReadOnly,
            ModeDecision::Allow,
            ModeDecision::Deny,
            ModeDecision::Deny,
            ModeDecision::Deny,
        ),
        (
            PermissionMode::Auto,
            ModeDecision::Allow,
            ModeDecision::Allow,
            ModeDecision::Allow,
            ModeDecision::Allow,
        ),
        (
            PermissionMode::PreapprovedOnly,
            ModeDecision::Allow,
            ModeDecision::Allow,
            ModeDecision::Allow,
            ModeDecision::Allow,
        ),
        (
            PermissionMode::Yolo,
            ModeDecision::Allow,
            ModeDecision::Allow,
            ModeDecision::Allow,
            ModeDecision::Allow,
        ),
    ] {
        assert_eq!(matrix_verdict(mode, Class::Read), read, "{mode:?} read");
        assert_eq!(matrix_verdict(mode, Class::Write), write, "{mode:?} write");
        assert_eq!(matrix_verdict(mode, Class::Exec), exec, "{mode:?} exec");
        assert_eq!(
            matrix_verdict(mode, Class::Egress),
            egress,
            "{mode:?} egress"
        );
    }
    // PreapprovedOnly without a recorded preapproval denies every class.
    let ctx = AdmissionContext {
        mode: PermissionMode::PreapprovedOnly,
        in_grant_scope: true,
        budget_remaining: true,
        in_trusted_scope: true,
        has_checkpoint: true,
        previously_approved: false,
        within_declared_bounds: true,
        dry_run: false,
    };
    for class in [Class::Read, Class::Write, Class::Exec, Class::Egress] {
        assert_eq!(
            Policy::default().decide(Path::new("/scope/target"), class, &ctx),
            ModeDecision::Deny,
            "preapproved-only without preapproval denies {class:?}"
        );
    }
    // Yolo is never the default mode.
    assert_ne!(
        PermissionMode::default(),
        PermissionMode::Yolo,
        "yolo must not be the default permission mode"
    );

    // Confined-path leg: the pinned verdicts must gate the worker the
    // executor runs. The mode carrier is the DEC-015 interim manual
    // default until the Settings surface lands, so the executor's live
    // consult evaluates exactly the manual column above — the pin and
    // the live consult may not drift apart — and that column's single
    // Allow cell (read) must cross the real Seatbelt worker. Every other
    // mode reaches the executor only through the preview seam until a
    // mode carrier exists (follow-up, DEC-015): no mode's verdict may
    // execute an effect there.
    let mut world = support::open_world("matrix-worker", None);
    let session = world.open_session("matrix-worker-session");
    let task = world.create_task(&session, "matrix-worker-task");
    let scope = world.root.join("scope");
    std::fs::create_dir_all(&scope).expect("create matrix scope");
    let file = scope.join("target.txt");
    std::fs::write(&file, b"scoped-by-seatbelt").expect("create matrix target");
    let grant = world.runtime.set_read_scope(scope, file.clone());

    for class in [Class::Read, Class::Write, Class::Exec, Class::Egress] {
        let ctx = rivect::executor::admission_context(
            &world.runtime.owner.store,
            class,
            file.parent().expect("scope root"),
            &file,
        )
        .expect("executor admission context");
        assert_eq!(ctx.mode, PermissionMode::default());
        assert_eq!(
            world.runtime.policy.decide(&file, class, &ctx),
            matrix_verdict(PermissionMode::Manual, class),
            "the live mode consult must stay pinned to the manual column for {class:?}"
        );
    }

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
                    path: file.clone(),
                },
            )
            .unwrap_or_else(|error| panic!("manual-mode read admits: {error}"))
    };
    let outcome = {
        let mut executor = Executor::new(
            &mut world.runtime.policy,
            &mut world.runtime.owner.store,
            world.runtime.read_worker.as_mut(),
        );
        executor
            .execute(&admitted)
            .unwrap_or_else(|error| panic!("confined read executes: {error}"))
    };
    match outcome {
        EffectOutcome::Read { bytes, digest } => {
            assert_eq!(bytes, b"scoped-by-seatbelt");
            assert_eq!(digest, support::sha256_hex(b"scoped-by-seatbelt"));
        }
        other => panic!("expected a read outcome, got {other:?}"),
    }
    assert_eq!(
        world.worker_reads(),
        1,
        "the manual column's Allow crossed the Seatbelt worker exactly once"
    );

    let reads_after_live_crossing = world.worker_reads();
    for mode in [
        PermissionMode::Manual,
        PermissionMode::AcceptEdits,
        PermissionMode::ReadOnly,
        PermissionMode::Auto,
        PermissionMode::PreapprovedOnly,
        PermissionMode::Yolo,
    ] {
        for (class, request) in [
            (
                Class::Read,
                EffectRequest::Read {
                    grant_id: grant.clone(),
                    path: file.clone(),
                },
            ),
            (
                Class::Write,
                EffectRequest::Write {
                    grant_id: grant.clone(),
                    path: file.clone(),
                    bytes: b"preview must not land".to_vec(),
                },
            ),
            (
                Class::Exec,
                EffectRequest::Exec {
                    grant_id: grant.clone(),
                    program: PathBuf::from("/bin/sleep"),
                },
            ),
            (
                Class::Egress,
                EffectRequest::Egress {
                    grant_id: grant.clone(),
                    url: "https://example.invalid".to_string(),
                },
            ),
        ] {
            let ctx = AdmissionContext {
                mode,
                in_grant_scope: true,
                budget_remaining: true,
                in_trusted_scope: true,
                has_checkpoint: true,
                previously_approved: true,
                within_declared_bounds: true,
                dry_run: false,
            };
            let verdict = {
                let mut executor = Executor::new(
                    &mut world.runtime.policy,
                    &mut world.runtime.owner.store,
                    world.runtime.read_worker.as_mut(),
                );
                executor
                    .submit_preview(&task, request, &ctx)
                    .unwrap_or_else(|error| panic!("{mode:?} {class:?} preview consults: {error}"))
            };
            assert_eq!(
                verdict,
                matrix_verdict(mode, class),
                "{mode:?} {class:?} preview matches the pinned matrix"
            );
        }
    }
    assert_eq!(
        world.worker_reads(),
        reads_after_live_crossing,
        "no mode's verdict may execute an effect through the preview seam"
    );
}

#[test]
fn allowed_manual_read_executes_through_the_seatbelt_worker() {
    let (mut world, task, file, grant) = sandbox_world("matrix-allow-read");
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
                    path: file,
                },
            )
            .expect("manual scoped read admits")
    };
    let outcome = {
        let mut executor = Executor::new(
            &mut world.runtime.policy,
            &mut world.runtime.owner.store,
            world.runtime.read_worker.as_mut(),
        );
        executor.execute(&admitted).expect("confined read executes")
    };
    match outcome {
        EffectOutcome::Read { bytes, digest } => {
            assert_eq!(bytes, b"scoped-by-seatbelt");
            assert_eq!(digest, support::sha256_hex(b"scoped-by-seatbelt"));
        }
        other => panic!("expected a read outcome, got {other:?}"),
    }
}

#[test]
fn non_read_effects_have_no_ambient_path_in_any_mode() {
    let (mut world, task, file, grant) = sandbox_world("no-ambient-exec");
    for request in [
        EffectRequest::Write {
            grant_id: grant.clone(),
            path: file.clone(),
            bytes: b"must not land".to_vec(),
        },
        EffectRequest::Exec {
            grant_id: grant.clone(),
            program: PathBuf::from("/bin/sleep"),
        },
        EffectRequest::Egress {
            grant_id: grant,
            url: "https://example.invalid".to_string(),
        },
    ] {
        let class = request.class();
        let attempt_id = world
            .runtime
            .owner
            .store
            .plan_attempt(&task, class, &request.describe())
            .expect("plan forged attempt");
        let admitted = AdmittedEffect {
            task_id: task.clone(),
            attempt_id,
            request,
            scope_root: file.parent().expect("scope root").to_path_buf(),
        };
        let outcome = {
            let mut executor = Executor::new(
                &mut world.runtime.policy,
                &mut world.runtime.owner.store,
                world.runtime.read_worker.as_mut(),
            );
            executor
                .execute(&admitted)
                .expect("readonly rejection is an outcome")
        };
        match outcome {
            EffectOutcome::Denied { reason } => {
                assert!(
                    reason.contains("no ambient fallback"),
                    "readonly rejection names the missing fallback: {reason}"
                );
            }
            other => panic!("expected a denied outcome for {class:?}, got {other:?}"),
        }
    }
    assert_eq!(
        std::fs::read(&file).expect("read untouched target"),
        b"scoped-by-seatbelt"
    );
    assert_eq!(world.runtime.provider_calls, 0);
}

#[test]
fn passthrough_boundary_performs_no_in_scope_io() {
    // A mechanism that ignores its profile must be detected by the probe
    // before any confined leg touches the user's target: the denied legs
    // run first on system or worker-owned files, so a passthrough leaves
    // the scope untouched and fails closed as a capability error.
    let fixture = TempTree::new("passthrough");
    let scope = fixture.path.join("scope");
    std::fs::create_dir_all(&scope).expect("create scope");
    let target = scope.join("target.txt");
    std::fs::write(&target, b"original").expect("create target");
    let passthrough = fixture.path.join("passthrough-sandbox-exec");
    std::fs::write(&passthrough, "#!/bin/sh\nshift 2\nexec \"$@\"\n")
        .expect("write passthrough mechanism");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&passthrough, std::fs::Permissions::from_mode(0o755))
            .expect("make passthrough executable");
    }

    let read_error = macos::probe_read_conformance(&passthrough, &scope, &target)
        .expect_err("a passthrough mechanism must fail the read probe");
    assert!(
        matches!(&read_error, WorkerError::SandboxUnavailable { reason } if reason.contains("admitted the denied read")),
        "{read_error}"
    );
    let write_error = macos::probe_write_conformance(&passthrough, &scope)
        .expect_err("a passthrough mechanism must fail the write probe");
    assert!(
        matches!(&write_error, WorkerError::SandboxUnavailable { reason } if reason.contains("admitted the denied write")),
        "{write_error}"
    );
    assert_eq!(
        ExecutorError::Worker(write_error).error_code(),
        ErrorCode::CapabilityUnavailable
    );
    assert_eq!(
        std::fs::read(&target).expect("target survives the failed probes"),
        b"original",
        "no ambient write may touch the user target"
    );
    let strays: Vec<String> = std::fs::read_dir(&scope)
        .expect("scope readable")
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with(".rivect"))
        .collect();
    assert!(
        strays.is_empty(),
        "the probe must not create in-scope artifacts before proving enforcement: {strays:?}"
    );

    // Control: the real boundary conforms and owns its probe artifact.
    let artifact = macos::probe_write_conformance(&sandbox_exec(), &scope)
        .expect("real write boundary conforms");
    assert!(
        artifact.is_file(),
        "the probe owns its in-scope artifact: {}",
        artifact.display()
    );
    macos::probe_read_conformance(&sandbox_exec(), &scope, &target)
        .expect("real read boundary conforms");
}

#[test]
fn unwritable_scope_is_an_effect_denial_not_a_capability_failure() {
    // A scope this process cannot write (a root-owned grant on a non-root
    // run) is a typed write denial, never a capability failure that
    // re-probes on every spawn forever.
    let fixture = TempTree::new("unwritable-scope");
    let scope = fixture.path.join("scope");
    std::fs::create_dir_all(&scope).expect("create scope");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&scope, std::fs::Permissions::from_mode(0o555))
            .expect("drop scope write permission");
    }
    let result = macos::probe_write_conformance(&sandbox_exec(), &scope);
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&scope, std::fs::Permissions::from_mode(0o755))
            .expect("restore scope write permission");
    }
    match result {
        // A privileged run can write the scope regardless of the mode:
        // still no false capability failure either way.
        Ok(_) => {}
        Err(error) => {
            assert!(matches!(error, WorkerError::WriteFailed { .. }), "{error}");
            assert_eq!(ExecutorError::Worker(error).error_code(), ErrorCode::Denied);
        }
    }
}

#[test]
fn unreadable_target_is_an_effect_denial_not_a_capability_failure() {
    // A target this process cannot read fails the read probe's admitted
    // leg, but that is a typed read denial, never a capability failure.
    let fixture = TempTree::new("unreadable-target");
    let scope = fixture.path.join("scope");
    std::fs::create_dir_all(&scope).expect("create scope");
    let target = scope.join("target.txt");
    std::fs::write(&target, b"original").expect("create target");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o000))
            .expect("drop target read permission");
    }
    let result = macos::probe_read_conformance(&sandbox_exec(), &scope, &target);
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644))
            .expect("restore target read permission");
    }
    match result {
        // A privileged run reads the mode-0 target regardless.
        Ok(()) => {}
        Err(error) => {
            assert!(matches!(error, WorkerError::ReadFailed { .. }), "{error}");
            assert_eq!(ExecutorError::Worker(error).error_code(), ErrorCode::Denied);
        }
    }
}

#[test]
fn confined_child_stdout_is_never_captured() {
    // Gates decide on the exit status alone: a confined read far larger
    // than any sane capture buffer streams to /dev/null, and the outcome
    // type carries no stdout at all.
    let fixture = TempTree::new("stream-bound");
    let big = fixture.path.join("big.txt");
    {
        use std::io::Write as _;
        let chunk = vec![b'x'; 1 << 20];
        let mut handle = std::fs::File::create(&big).expect("create big target");
        for _ in 0..8 {
            handle.write_all(&chunk).expect("write stream chunk");
        }
    }
    let big = big.canonicalize().expect("canonical big target");
    let profile = macos::read_profile(&fixture.path).expect("read profile");
    let outcome = confined(&profile, Path::new("/bin/cat"), &[big.as_os_str()])
        .expect("confined stream read runs");
    assert!(
        outcome.exit_ok,
        "the streamed in-scope read is admitted: {outcome:?}"
    );
}

#[test]
fn free_write_once_is_confined_for_every_caller() {
    // The config publication path calls the free write function directly,
    // so confinement must be intrinsic to it: a non-confinable scope fails
    // the probe before any byte moves, exactly as for the executor's
    // managed-write leg.
    let fixture = TempTree::new("free-write-confined");
    let target = fixture.path.join("target.txt");
    std::fs::write(&target, b"original").expect("create target");
    let error = macos::write_once(
        Path::new("/"),
        &target,
        macos::FileIdentity { dev: 0, ino: 0 },
        b"publication",
    )
    .expect_err("a non-confining scope must deny the free write");
    assert!(
        matches!(error, WorkerError::SandboxUnavailable { .. }),
        "{error}"
    );
    assert_eq!(
        ExecutorError::Worker(error).error_code(),
        ErrorCode::CapabilityUnavailable
    );
    assert_eq!(
        std::fs::read(&target).expect("target survives the denied write"),
        b"original",
        "no ambient fallback: the probe failure must precede the write"
    );
}
