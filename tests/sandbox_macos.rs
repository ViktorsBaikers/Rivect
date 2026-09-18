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
use rivect::policy::{AdmissionContext, ModeDecision, PermissionMode, Policy, preapproval_scope};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Once;
use std::sync::atomic::{AtomicU64, Ordering};
use support::{TempTree, matrix_verdict};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

fn sandbox_exec() -> PathBuf {
    ensure_helper();
    PathBuf::from(SANDBOX_EXEC)
}

fn confined(
    profile: &str,
    program: &Path,
    args: &[&std::ffi::OsStr],
) -> Result<ConfinedOutcome, WorkerError> {
    ensure_helper();
    macos::run_confined(&sandbox_exec(), profile, program, args)
}

/// World fixture mirroring the effect-boundary one: a scoped read grant and
/// the real macOS worker behind the executor.
fn sandbox_world(tag: &str) -> (support::World, rivect::contracts::TaskId, PathBuf, String) {
    ensure_helper();
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

fn ensure_helper() {
    static BUILD: Once = Once::new();
    BUILD.call_once(|| {
        let status = std::process::Command::new(env!("CARGO"))
            .args(["build", "-p", "rivect-sandbox-helper"])
            .status()
            .expect("spawn helper build");
        assert!(status.success(), "helper build failed: {status}");
    });
}

#[test]
fn denies_read_outside_scope_at_the_os_boundary() {
    let fixture = TempTree::new("sandbox-macos", "read-escape");
    let inside = fixture.path.join("inside.txt");
    std::fs::write(&inside, b"inside-marker").expect("create inside target");
    let outside_tree = TempTree::new("sandbox-macos", "read-escape-outside");
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
    let fixture = TempTree::new("sandbox-macos", "write-escape");
    let inside = fixture.path.join("inside.txt");
    std::fs::write(&inside, b"original").expect("create inside target");
    let outside_tree = TempTree::new("sandbox-macos", "write-escape-outside");
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
    let fixture = TempTree::new("sandbox-macos", "exec-escape");
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
    let fixture = TempTree::new("sandbox-macos", "non-enforcing");
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
    let fixture = TempTree::new("sandbox-macos", "missing-mechanism");
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
    let fixture = TempTree::new("sandbox-macos", "probe-order");
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

#[test]
fn mode_gated_write_denies_occupant_swap_between_admit_and_execute() {
    // INV-029 on the mode-carrying agent write path, never through
    // admit_managed_write: admit pins the occupant identity under the
    // caller's mode, so an unlink/recreate swap between admit and execute
    // denies with the typed TargetChanged error and the swapped file
    // keeps its bytes.
    let (mut world, task, file, _grant) = sandbox_world("mode-write-occupant");
    let scope_root = file.parent().expect("scope root").to_path_buf();
    let write_grant = world.runtime.policy.grant_classes(
        scope_root,
        vec![
            rivect::contracts::EffectClass::Read,
            rivect::contracts::EffectClass::Write,
        ],
    );
    let admitted = {
        let mut executor = Executor::new(
            &mut world.runtime.policy,
            &mut world.runtime.owner.store,
            world.runtime.read_worker.as_mut(),
        );
        executor
            .admit(
                &task,
                EffectRequest::Write {
                    grant_id: write_grant,
                    path: file.clone(),
                    bytes: b"agent payload".to_vec(),
                },
                PermissionMode::Yolo,
            )
            .expect("yolo write admission")
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
            .execute(&admitted)
            .expect_err("an occupant swap must deny the mode-gated write")
    };

    assert!(matches!(
        &error,
        ExecutorError::Worker(WorkerError::TargetChanged { target })
            if target.as_path() == file.as_path()
    ));
    assert_eq!(
        std::fs::read(&file).expect("read new occupant"),
        b"new occupant"
    );
    assert_eq!(
        world
            .runtime
            .owner
            .store
            .latest_unresolved_attempt(&task)
            .expect("read unresolved mode write attempt"),
        None,
        "the denied write attempt must be settled in the ledger"
    );
}

/// Local counting oracle around the real Seatbelt worker: support's
/// default counting worker counts reads only, so the macOS matrix tests
/// carry their own per-class counters. Every leg counts invocations,
/// not successes — a denied worker leg still proves the executor
/// presented the effect to the worker.
struct CountingSeatbeltWorker {
    reads: Arc<AtomicU64>,
    writes: Arc<AtomicU64>,
    execs: Arc<AtomicU64>,
    egresses: Arc<AtomicU64>,
}

impl ReadWorker for CountingSeatbeltWorker {
    fn read_once(
        &mut self,
        scope_root: &Path,
        target: &Path,
    ) -> Result<ReadObservation, WorkerError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        macos::MacosReadWorker.read_once(scope_root, target)
    }

    fn write_once(
        &mut self,
        scope_root: &Path,
        target: &Path,
        expected: rivect::executor::FileIdentity,
        bytes: &[u8],
    ) -> Result<(), WorkerError> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        macos::MacosReadWorker.write_once(scope_root, target, expected, bytes)
    }

    fn exec_once(&mut self, scope_root: &Path, program: &Path) -> Result<(), WorkerError> {
        self.execs.fetch_add(1, Ordering::SeqCst);
        macos::MacosReadWorker.exec_once(scope_root, program)
    }

    fn egress_once(&mut self, url: &str) -> Result<(), WorkerError> {
        self.egresses.fetch_add(1, Ordering::SeqCst);
        macos::MacosReadWorker.egress_once(url)
    }
}

/// Admit leg of one live matrix cell: an Allow expectation must return
/// the admitted effect; ask and deny expectations must fail closed with
/// the typed mode error before any worker leg exists.
fn admit_live_cell(
    world: &mut support::World,
    task: &rivect::contracts::TaskId,
    mode: PermissionMode,
    request: EffectRequest,
    expected: ModeDecision,
) -> Option<AdmittedEffect> {
    let label = request.describe();
    let mut executor = Executor::new(
        &mut world.runtime.policy,
        &mut world.runtime.owner.store,
        world.runtime.read_worker.as_mut(),
    );
    match executor.admit(task, request, mode) {
        Ok(admitted) => {
            assert_eq!(
                expected,
                ModeDecision::Allow,
                "{label}: {mode:?} admitted a cell pinned {expected:?}"
            );
            Some(admitted)
        }
        Err(error) => {
            let typed = match expected {
                ModeDecision::Ask => matches!(error, ExecutorError::ModeAsk),
                ModeDecision::Deny => matches!(error, ExecutorError::ModeDenied),
                ModeDecision::Allow => false,
            };
            assert!(
                typed,
                "{label}: {mode:?} expected {expected:?}, got {error}"
            );
            None
        }
    }
}

/// Execute leg of one live matrix cell behind a fresh executor.
fn execute_live_cell(
    world: &mut support::World,
    admitted: &AdmittedEffect,
) -> Result<EffectOutcome, ExecutorError> {
    let mut executor = Executor::new(
        &mut world.runtime.policy,
        &mut world.runtime.owner.store,
        world.runtime.read_worker.as_mut(),
    );
    executor.execute(admitted)
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

    // Live mode-carrying legs (DEC-016; DEC-017 D-003; DEC-018): every
    // mode × class pair runs the real admit→execute path with the mode
    // injected at admit, never admit_managed_write. The executor's own
    // admission context now derives in-grant-scope, exec declared bounds,
    // and recorded preapprovals; budget and checkpoint stay unobserved
    // unless tests seed them (T11). Auto exec therefore Allows on an
    // in-scope program; Auto egress Asks because no bounds signal exists
    // yet. Auto write stays Ask without a budget. Allow cells cross the
    // real Seatbelt worker — the read lands, the write lands, the
    // confined exec runs a binary copied into the scope (the exec
    // profile's allowance is the scope subpath), and an egress Allow cell
    // (preapproved-only / yolo) meets the OS denial the boundary imposes
    // (an egress target admits no filesystem scope, so it is out of scope
    // by construction); ask and deny cells fail closed at admit and never
    // invoke the worker.
    ensure_helper();
    let mut world = support::open_world("matrix-worker", None);
    let session = world.open_session("matrix-worker-session");
    let task = world.create_task(&session, "matrix-worker-task");
    let scope = world.root.join("scope");
    std::fs::create_dir_all(&scope).expect("create matrix scope");
    let file = scope.join("target.txt");
    std::fs::write(&file, b"scoped-by-seatbelt").expect("create matrix target");
    let grant = world.runtime.set_read_scope(scope.clone(), file.clone());
    let reads = Arc::new(AtomicU64::new(0));
    let writes = Arc::new(AtomicU64::new(0));
    let execs = Arc::new(AtomicU64::new(0));
    let egresses = Arc::new(AtomicU64::new(0));
    world.runtime.read_worker = Box::new(CountingSeatbeltWorker {
        reads: reads.clone(),
        writes: writes.clone(),
        execs: execs.clone(),
        egresses: egresses.clone(),
    });
    // Exec Allow cells run an in-scope copy of a system binary: the
    // exec profile's allowance is the scope subpath, so a target inside
    // it is admitted while anything outside is denied (see
    // denies_exec_outside_scope_at_the_os_boundary).
    let exec_program = scope.join("true");
    std::fs::copy("/usr/bin/true", &exec_program).expect("copy in-scope executable");
    // Seatbelt filters match the exec path's literal spelling, so the
    // target carries the canonical /private/var form the profile's
    // canonical scope subpath admits.
    let exec_program = exec_program
        .canonicalize()
        .expect("canonical in-scope executable");
    let write_grant = world.runtime.policy.grant_classes(
        file.parent().expect("scope root").to_path_buf(),
        vec![Class::Write],
    );
    let exec_grant = world.runtime.policy.grant_classes(scope, vec![Class::Exec]);
    let egress_url = "https://example.invalid/matrix";
    let egress_grant = world.runtime.policy.grant_classes(
        file.parent().expect("scope root").to_path_buf(),
        vec![Class::Egress],
    );
    for (class, target) in [
        (
            Class::Read,
            file.canonicalize()
                .expect("canonical read target")
                .display()
                .to_string(),
        ),
        (
            Class::Write,
            file.canonicalize()
                .expect("canonical write target")
                .display()
                .to_string(),
        ),
        (Class::Exec, exec_program.display().to_string()),
        (Class::Egress, egress_url.to_string()),
    ] {
        world
            .runtime
            .owner
            .store
            .record_preapproval(&preapproval_scope(class, &target), "human:matrix", 600)
            .expect("record matrix preapproval");
    }

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
            ModeDecision::Ask,
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
            ModeDecision::Ask,
            ModeDecision::Allow,
            ModeDecision::Ask,
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
        let payload = format!("landed-under-{}", mode.id());
        std::fs::write(&file, b"scoped-by-seatbelt").expect("seed matrix target");

        let read_before = reads.load(Ordering::SeqCst);
        let request = EffectRequest::Read {
            grant_id: grant.clone(),
            path: file.clone(),
        };
        if let Some(admitted) = admit_live_cell(&mut world, &task, mode, request, read) {
            let outcome = execute_live_cell(&mut world, &admitted)
                .unwrap_or_else(|error| panic!("{mode:?} read allow executes: {error}"));
            match outcome {
                EffectOutcome::Read { bytes, digest } => {
                    assert_eq!(bytes, b"scoped-by-seatbelt");
                    assert_eq!(digest, support::sha256_hex(b"scoped-by-seatbelt"));
                }
                other => panic!("{mode:?} read allow outcome: {other:?}"),
            }
            assert_eq!(
                reads.load(Ordering::SeqCst),
                read_before + 1,
                "the {mode:?} read Allow cell crossed the seatbelt worker once"
            );
        } else {
            assert_eq!(
                reads.load(Ordering::SeqCst),
                read_before,
                "the {mode:?} non-allow read cell never reaches the worker"
            );
        }

        let write_before = writes.load(Ordering::SeqCst);
        let request = EffectRequest::Write {
            grant_id: write_grant.clone(),
            path: file.clone(),
            bytes: payload.clone().into_bytes(),
        };
        if let Some(admitted) = admit_live_cell(&mut world, &task, mode, request, write) {
            let outcome = execute_live_cell(&mut world, &admitted)
                .unwrap_or_else(|error| panic!("{mode:?} write allow executes: {error}"));
            match outcome {
                EffectOutcome::Executed { detail } => {
                    assert!(
                        detail.starts_with("write-performed sha256="),
                        "the write observation names its digest: {detail}"
                    );
                }
                other => panic!("{mode:?} write allow outcome: {other:?}"),
            }
            assert_eq!(
                std::fs::read(&file).expect("read the write-allow target"),
                payload.as_bytes(),
                "the {mode:?} write Allow cell landed through the confined worker"
            );
            assert_eq!(
                writes.load(Ordering::SeqCst),
                write_before + 1,
                "the {mode:?} write Allow cell crossed the seatbelt worker once"
            );
        } else {
            assert_eq!(
                std::fs::read(&file).expect("read the non-allow write target"),
                b"scoped-by-seatbelt",
                "the {mode:?} non-allow write cell must not touch the target"
            );
            assert_eq!(
                writes.load(Ordering::SeqCst),
                write_before,
                "the {mode:?} non-allow write cell never reaches the worker"
            );
        }

        let exec_before = execs.load(Ordering::SeqCst);
        let request = EffectRequest::Exec {
            grant_id: exec_grant.clone(),
            program: exec_program.clone(),
        };
        if let Some(admitted) = admit_live_cell(&mut world, &task, mode, request, exec) {
            let outcome = execute_live_cell(&mut world, &admitted)
                .unwrap_or_else(|error| panic!("{mode:?} exec allow executes: {error}"));
            assert!(
                matches!(outcome, EffectOutcome::Executed { .. }),
                "{mode:?} exec allow outcome: {outcome:?}"
            );
            assert_eq!(
                execs.load(Ordering::SeqCst),
                exec_before + 1,
                "the {mode:?} exec Allow cell crossed the seatbelt worker once"
            );
        } else {
            assert_eq!(
                execs.load(Ordering::SeqCst),
                exec_before,
                "the {mode:?} non-allow exec cell never reaches the worker"
            );
        }

        let egress_before = egresses.load(Ordering::SeqCst);
        let request = EffectRequest::Egress {
            grant_id: egress_grant.clone(),
            url: egress_url.to_string(),
        };
        if let Some(admitted) = admit_live_cell(&mut world, &task, mode, request, egress) {
            let error = execute_live_cell(&mut world, &admitted)
                .expect_err("the egress Allow cell is os-denied by the boundary, never ambient");
            assert!(
                matches!(
                    error,
                    ExecutorError::Worker(WorkerError::SandboxDenied { ref target })
                        if target == &PathBuf::from(egress_url)
                ),
                "{mode:?} egress allow denial: {error}"
            );
            assert_eq!(
                egresses.load(Ordering::SeqCst),
                egress_before + 1,
                "the {mode:?} egress Allow cell was presented to the seatbelt worker once"
            );
        } else {
            assert_eq!(
                egresses.load(Ordering::SeqCst),
                egress_before,
                "the {mode:?} non-allow egress cell never reaches the worker"
            );
        }
    }

    let reads_after_live_crossing = reads.load(Ordering::SeqCst);
    let writes_after_live_crossing = writes.load(Ordering::SeqCst);
    let execs_after_live_crossing = execs.load(Ordering::SeqCst);
    let egresses_after_live_crossing = egresses.load(Ordering::SeqCst);
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
    assert_eq!(reads.load(Ordering::SeqCst), reads_after_live_crossing);
    assert_eq!(
        writes.load(Ordering::SeqCst),
        writes_after_live_crossing,
        "no mode's verdict may execute a write through the preview seam"
    );
    assert_eq!(
        execs.load(Ordering::SeqCst),
        execs_after_live_crossing,
        "no mode's verdict may execute an exec through the preview seam"
    );
    assert_eq!(
        egresses.load(Ordering::SeqCst),
        egresses_after_live_crossing,
        "no mode's verdict may attempt an egress through the preview seam"
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
                PermissionMode::Manual,
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
fn allow_mode_write_cells_execute_through_the_seatbelt_worker() {
    // The matrix's Write Allow cells must hold on the live mode-carrying
    // path, never through admit_managed_write: for every mode, the write
    // cell admits with the injected mode and the verdict decides whether
    // the confined Seatbelt worker runs. The executor context observes
    // no trusted scope, checkpoint, or budget, so only preapproved-only
    // (with its recorded consent) and yolo reach a live write; every
    // other mode fails closed at admit and the worker never runs.
    use rivect::contracts::EffectClass as Class;
    ensure_helper();
    for (mode, expected) in [
        (PermissionMode::Manual, ModeDecision::Ask),
        (PermissionMode::AcceptEdits, ModeDecision::Ask),
        (PermissionMode::ReadOnly, ModeDecision::Deny),
        (PermissionMode::Auto, ModeDecision::Ask),
        (PermissionMode::PreapprovedOnly, ModeDecision::Allow),
        (PermissionMode::Yolo, ModeDecision::Allow),
    ] {
        let tag = format!("matrix-write-{}", mode.id());
        let mut world = support::open_world(&tag, None);
        let session = world.open_session(&format!("{tag}-session"));
        let task = world.create_task(&session, &format!("{tag}-task"));
        let scope = world.root.join("scope");
        std::fs::create_dir_all(&scope).expect("create matrix scope");
        let file = scope.join("target.txt");
        std::fs::write(&file, b"scoped-by-seatbelt").expect("create matrix target");
        let grant = world
            .runtime
            .policy
            .grant_classes(scope, vec![Class::Read, Class::Write]);
        if mode == PermissionMode::PreapprovedOnly {
            world
                .runtime
                .owner
                .store
                .record_preapproval(
                    &preapproval_scope(
                        Class::Write,
                        &file
                            .canonicalize()
                            .expect("canonical write target")
                            .display()
                            .to_string(),
                    ),
                    "human:matrix-write",
                    600,
                )
                .expect("record write preapproval");
        }
        let writes = Arc::new(AtomicU64::new(0));
        world.runtime.read_worker = Box::new(CountingSeatbeltWorker {
            reads: Arc::new(AtomicU64::new(0)),
            writes: writes.clone(),
            execs: Arc::new(AtomicU64::new(0)),
            egresses: Arc::new(AtomicU64::new(0)),
        });
        let payload = format!("landed-under-{tag}");
        let request = EffectRequest::Write {
            grant_id: grant,
            path: file.clone(),
            bytes: payload.clone().into_bytes(),
        };
        if let Some(admitted) = admit_live_cell(&mut world, &task, mode, request, expected) {
            let outcome = execute_live_cell(&mut world, &admitted)
                .unwrap_or_else(|error| panic!("{mode:?} confined write executes: {error}"));
            assert!(
                matches!(outcome, EffectOutcome::Executed { .. }),
                "{mode:?} write outcome: {outcome:?}"
            );
            assert_eq!(
                std::fs::read(&file).expect("read the write target"),
                payload.as_bytes(),
                "the {mode:?} Allow cell's write landed through the confined worker"
            );
            assert_eq!(
                writes.load(Ordering::SeqCst),
                1,
                "the {mode:?} Allow cell crossed the seatbelt worker exactly once"
            );
        } else {
            assert_eq!(
                std::fs::read(&file).expect("read untouched write target"),
                b"scoped-by-seatbelt",
                "the {mode:?} non-allow cell's write must not land"
            );
            assert_eq!(
                writes.load(Ordering::SeqCst),
                0,
                "the {mode:?} non-allow cell never reaches the worker"
            );
        }
    }
    // Managed control writes stay policy-gated and mode-free, pinned by
    // sandbox_worker_reads_scope_and_lands_checked_managed_write.
}

#[test]
fn non_read_effects_have_no_ambient_path_in_any_mode() {
    // A forged admission must not bypass the mode gate: with an
    // all-class grant and the interim manual mode, every non-read cell
    // of the manual column asks at the execute-time reconsult, the typed
    // error settles the ledger, and no worker leg runs — there is no
    // ambient path around the gate.
    let (mut world, task, file, _grant) = sandbox_world("no-ambient-exec");
    let scope_root = file.parent().expect("scope root").to_path_buf();
    // The exec target lives inside the granted scope so the mode gate —
    // not the scope consult — is the discriminator for the leg.
    let scoped_exec = scope_root.join("scoped-exec.sh");
    std::fs::write(&scoped_exec, "#!/bin/sh\nexit 0\n").expect("write scoped exec target");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&scoped_exec, std::fs::Permissions::from_mode(0o755))
            .expect("make scoped exec target executable");
    }
    let all_classes = world.runtime.policy.grant_classes(
        scope_root.clone(),
        vec![
            rivect::contracts::EffectClass::Read,
            rivect::contracts::EffectClass::Write,
            rivect::contracts::EffectClass::Exec,
            rivect::contracts::EffectClass::Egress,
        ],
    );
    for request in [
        EffectRequest::Write {
            grant_id: all_classes.clone(),
            path: file.clone(),
            bytes: b"must not land".to_vec(),
        },
        EffectRequest::Exec {
            grant_id: all_classes.clone(),
            program: scoped_exec,
        },
        EffectRequest::Egress {
            grant_id: all_classes,
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
            mode: PermissionMode::Manual,
            expected_identity: None,
            scope_root: scope_root.clone(),
        };
        let error = {
            let mut executor = Executor::new(
                &mut world.runtime.policy,
                &mut world.runtime.owner.store,
                world.runtime.read_worker.as_mut(),
            );
            executor
                .execute(&admitted)
                .expect_err("a forged manual-mode non-read effect must ask at the mode gate")
        };
        assert!(
            matches!(error, ExecutorError::ModeAsk),
            "{class:?}: {error}"
        );
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
    let fixture = TempTree::new("sandbox-macos", "passthrough");
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

    // Control: the real boundary conforms and leaves no leftover probe file.
    macos::probe_write_conformance(&sandbox_exec(), &scope).expect("real write boundary conforms");
    let leftovers: Vec<String> = std::fs::read_dir(&scope)
        .expect("scope readable")
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with(".rivect-write-probe"))
        .collect();
    assert!(
        leftovers.is_empty(),
        "write conformance must unlink its probe artifact: {leftovers:?}"
    );
    macos::probe_read_conformance(&sandbox_exec(), &scope, &target)
        .expect("real read boundary conforms");
}

#[test]
fn unwritable_scope_is_an_effect_denial_not_a_capability_failure() {
    // A scope this process cannot write (a root-owned grant on a non-root
    // run) is a typed write denial, never a capability failure that
    // re-probes on every spawn forever.
    let fixture = TempTree::new("sandbox-macos", "unwritable-scope");
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
    let fixture = TempTree::new("sandbox-macos", "unreadable-target");
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
    let fixture = TempTree::new("sandbox-macos", "stream-bound");
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
    ensure_helper();
    let fixture = TempTree::new("sandbox-macos", "free-write-confined");
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

#[test]
fn admitted_read_and_write_execute_inside_the_seatbelt_helper_not_the_host_process() {
    ensure_helper();
    let helper = rivect_sandbox_helper::helper_binary().expect("helper binary");
    assert!(
        helper.is_file(),
        "the confined child must be a built helper, got {}",
        helper.display()
    );
    let (mut world, task, file, grant) = sandbox_world("helper-data-plane");
    {
        let mut executor = Executor::new(
            &mut world.runtime.policy,
            &mut world.runtime.owner.store,
            world.runtime.read_worker.as_mut(),
        );
        let admitted = executor
            .admit(
                &task,
                EffectRequest::Read {
                    grant_id: grant,
                    path: file.clone(),
                },
                PermissionMode::Manual,
            )
            .expect("admit read");
        match executor.execute(&admitted).expect("helper read") {
            EffectOutcome::Read { bytes, .. } => assert_eq!(bytes, b"scoped-by-seatbelt"),
            other => panic!("expected a helper read, got {other:?}"),
        }
    }
    let write_grant = world.runtime.policy.grant_classes(
        file.parent().expect("scope").to_path_buf(),
        vec![rivect::contracts::EffectClass::Write],
    );
    {
        let mut executor = Executor::new(
            &mut world.runtime.policy,
            &mut world.runtime.owner.store,
            world.runtime.read_worker.as_mut(),
        );
        let admitted = executor
            .admit(
                &task,
                EffectRequest::Write {
                    grant_id: write_grant,
                    path: file.clone(),
                    bytes: b"from-helper".to_vec(),
                },
                PermissionMode::Yolo,
            )
            .expect("admit write");
        executor.execute(&admitted).expect("helper write");
    }
    assert_eq!(
        std::fs::read(&file).expect("read helper write"),
        b"from-helper"
    );
}

#[test]
fn run_confined_kills_a_hung_fifo_gate() {
    ensure_helper();
    let fixture = TempTree::new("sandbox-macos", "hung-fifo");
    let fifo = fixture.path.join("hung.fifo");
    let status = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .expect("mkfifo");
    assert!(status.success(), "mkfifo failed: {status}");
    let fifo = fifo.canonicalize().expect("canonical fifo");
    let profile = macos::read_profile(&fixture.path).expect("read profile");
    let error = confined(&profile, Path::new("/bin/cat"), &[fifo.as_os_str()])
        .expect_err("a hung fifo must hit the wall deadline");
    assert!(matches!(error, WorkerError::ConfinedRunTimedOut), "{error}");
}

#[test]
fn macos_write_gate_proves_write_open_on_a_fresh_artifact() {
    ensure_helper();
    let fixture = TempTree::new("sandbox-macos", "fresh-write-gate");
    let target = fixture.path.join("target.txt");
    std::fs::write(&target, b"seed").expect("seed target");
    let meta = std::fs::metadata(&target).expect("meta");
    macos::write_once(
        &fixture.path,
        &target,
        macos::FileIdentity {
            dev: meta.dev(),
            ino: meta.ino(),
        },
        b"gate-landed",
    )
    .expect("write through fresh gate");
    assert_eq!(std::fs::read(&target).expect("read"), b"gate-landed");
    let leftovers: Vec<_> = std::fs::read_dir(&fixture.path)
        .expect("list")
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with(".rivect-write-gate-"))
        .collect();
    assert!(
        leftovers.is_empty(),
        "write gate must use a fresh artifact and remove it: {leftovers:?}"
    );
}

#[test]
fn macos_exec_once_deny_first_probe_fails_closed_when_sandbox_does_not_enforce() {
    ensure_helper();
    let fixture = TempTree::new("sandbox-macos", "exec-deny-first");
    let program = fixture.path.join("true");
    std::fs::copy("/usr/bin/true", &program).expect("copy true");
    let error = macos::exec_once_with(Path::new("/usr/bin/true"), &fixture.path, &program)
        .expect_err("passthrough sandbox-exec must fail closed");
    assert!(
        matches!(error, WorkerError::SandboxUnavailable { .. }),
        "{error}"
    );
}

#[test]
fn macos_exec_profile_does_not_allow_dev_read() {
    let fixture = TempTree::new("sandbox-macos", "exec-no-dev");
    let profile = macos::exec_profile(&fixture.path).expect("exec profile");
    assert!(
        !profile.contains("subpath \"/dev\""),
        "exec profile must not grant file-read* on /dev: {profile}"
    );
}

#[test]
fn live_admission_context_allow_cells_reach_the_seatbelt_worker_when_granting_signals_are_present()
{
    ensure_helper();
    use rivect::contracts::EffectClass as Class;
    let mut world = support::open_world("live-signals", None);
    let session = world.open_session("live-signals-session");
    let task = world.create_task(&session, "live-signals-task");
    let scope = world.root.join("scope");
    std::fs::create_dir_all(&scope).expect("scope");
    let file = scope.join("target.txt");
    std::fs::write(&file, b"seed").expect("seed");
    let grant = world
        .runtime
        .policy
        .grant_classes(scope.clone(), vec![Class::Read, Class::Write, Class::Exec]);
    let canonical = scope.canonicalize().expect("canonical scope");
    let key = canonical.display().to_string();
    world
        .runtime
        .owner
        .store
        .open_budget(&key, 8)
        .expect("open budget");
    world
        .runtime
        .owner
        .store
        .retain(
            "checkpoint",
            &rivect::executor::checkpoint_boundary_id(&key),
        )
        .expect("retain checkpoint");
    let writes = Arc::new(AtomicU64::new(0));
    world.runtime.read_worker = Box::new(CountingSeatbeltWorker {
        reads: Arc::new(AtomicU64::new(0)),
        writes: writes.clone(),
        execs: Arc::new(AtomicU64::new(0)),
        egresses: Arc::new(AtomicU64::new(0)),
    });
    let ctx = rivect::executor::admission_context(
        &world.runtime.owner.store,
        PermissionMode::Auto,
        Class::Write,
        &scope,
        &file,
    )
    .expect("live write context");
    assert!(ctx.budget_remaining);
    assert!(ctx.in_trusted_scope);
    assert!(ctx.has_checkpoint);
    assert!(ctx.in_grant_scope);
    for mode in [PermissionMode::Auto, PermissionMode::AcceptEdits] {
        std::fs::write(&file, b"seed").expect("reseed");
        let admitted = admit_live_cell(
            &mut world,
            &task,
            mode,
            EffectRequest::Write {
                grant_id: grant.clone(),
                path: file.clone(),
                bytes: format!("live-{mode:?}").into_bytes(),
            },
            ModeDecision::Allow,
        )
        .unwrap_or_else(|| panic!("{mode:?} write must Allow when signals are seeded"));
        execute_live_cell(&mut world, &admitted).unwrap_or_else(|e| panic!("{mode:?}: {e}"));
        assert_eq!(
            std::fs::read(&file).expect("landed"),
            format!("live-{mode:?}").as_bytes()
        );
    }
    assert_eq!(writes.load(Ordering::SeqCst), 2);
}
