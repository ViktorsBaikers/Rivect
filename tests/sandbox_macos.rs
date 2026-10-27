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
    AdmittedEffect, EffectOutcome, EffectRequest, ExecutorError, ReadWorker,
    helper_confined_command,
};
use rivect::policy::{AdmissionContext, ModeDecision, PermissionMode, Policy, preapproval_scope};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use support::{HELPER_IO_WITNESS, TempTree, ensure_helper, install_helper_io_shim, matrix_verdict};

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

/// Compiles the loopback connect probe the network control runs — a real
/// `socket`+`connect` pair `/bin/sh` cannot express. The parent compiles
/// unconfined; only the confined leg runs under the control profile.
fn compile_netprobe(dir: &Path, owner: &mut TempTree) -> PathBuf {
    let source = dir.join("netprobe.c");
    std::fs::write(
        &source,
        concat!(
            "#include <arpa/inet.h>\n",
            "#include <errno.h>\n",
            "#include <stdio.h>\n",
            "#include <stdlib.h>\n",
            "#include <string.h>\n",
            "#include <sys/socket.h>\n",
            "#include <unistd.h>\n",
            "int main(int argc, char **argv) {\n",
            "    if (argc != 2) { fprintf(stderr, \"usage: netprobe port\\n\"); return 2; }\n",
            "    int port = atoi(argv[1]);\n",
            "    int fd = socket(AF_INET, SOCK_STREAM, 0);\n",
            "    if (fd < 0) { perror(\"socket\"); return 3; }\n",
            "    struct sockaddr_in addr;\n",
            "    memset(&addr, 0, sizeof addr);\n",
            "    addr.sin_family = AF_INET;\n",
            "    addr.sin_port = htons((short)port);\n",
            "    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);\n",
            "    if (connect(fd, (struct sockaddr *)&addr, sizeof addr) < 0) {\n",
            "        perror(\"connect\"); return 4;\n",
            "    }\n",
            "    close(fd);\n",
            "    return 0;\n",
            "}\n",
        ),
    )
    .expect("write netprobe.c");
    let binary = dir.join("netprobe");
    let compiled = std::process::Command::new("/usr/bin/cc")
        .args(["-O0", "-o"])
        .arg(&binary)
        .arg(&source)
        .output();
    if compiled.is_err() {
        owner.retain();
    }
    let compiled = compiled.expect("spawn cc for netprobe");
    assert!(
        compiled.status.success(),
        "cc failed for netprobe: {}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    binary
}

/// World fixture mirroring the effect-boundary one: a scoped read grant and
/// the real macOS worker behind the executor.
fn sandbox_world(tag: &str) -> (support::World, rivect::contracts::TaskId, PathBuf, String) {
    support::sandbox_world(tag, b"scoped-by-seatbelt", macos::MacosReadWorker)
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
    ensure_helper();
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
    ensure_helper();
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
    ensure_helper();
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
            macos::WriteIdentity::new(
                macos::FileIdentity::new(0, 0),
                Err(macos::Unattested::Unrecorded),
            ),
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
        let mut executor = world.runtime.executor();
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
        let mut executor = world.runtime.executor();
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
    let write_grant = world
        .runtime
        .policy_writer()
        .grant_classes(scope_root, vec![EffectClass::Read, EffectClass::Write]);
    let admitted = {
        let mut executor = world.runtime.executor();
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
    // Pin the old inode under a sibling name so the recreated occupant
    // cannot reuse its (dev, ino): the swap stays a different file.
    std::fs::hard_link(&file, file.with_file_name("admitted-occupant.pinned"))
        .expect("pin the admitted occupant's inode");
    std::fs::remove_file(&file).expect("remove admitted occupant");
    std::fs::write(&file, b"new occupant").expect("replace admitted occupant");

    let error = {
        let mut executor = world.runtime.executor();
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
            .store()
            .latest_unresolved_attempt(&task)
            .expect("read unresolved mode write attempt"),
        None,
        "the denied write attempt must be settled in the ledger"
    );
}

/// The same `(dev, ino)` under a different reuse token: what a later file
/// reusing the admitted occupant's pair looks like to the write check.
fn reused_token(token: rivect_sandbox_helper::ReuseToken) -> rivect_sandbox_helper::ReuseToken {
    let mut bytes = token.as_bytes().to_vec();
    let last = bytes.last_mut().expect("a reuse token carries a payload");
    *last ^= 0xff;
    rivect_sandbox_helper::ReuseToken::from_bytes(&bytes).expect("a flipped token keeps its shape")
}

#[test]
fn write_once_refuses_unattested_and_reused_occupants() {
    // INV-029 reuse discriminator on the real worker: the write fd must
    // carry the admitted (dev, ino) and the admitted reuse token, so an
    // unattested identity and a reused pair both deny with no byte moved,
    // and only the genuine identity writes.
    ensure_helper();
    let (_world, _task, file, _grant) = sandbox_world("write-identity-reuse");
    let scope_root = file.parent().expect("scope root").to_path_buf();
    let genuine =
        rivect::executor::write_target_identity(&scope_root, &file).expect("target write identity");
    let Ok(token) = genuine.reuse() else {
        panic!("capability: the test filesystem must report a reuse discriminator");
    };
    let mut worker = macos::MacosReadWorker;

    let unattested = rivect::executor::WriteIdentity::new(
        genuine.file(),
        Err(rivect::executor::Unattested::Unrecorded),
    );
    match worker.write_once(&scope_root, &file, unattested, b"unattested-bytes") {
        Ok(()) => panic!("unattested case: the write returned Ok"),
        Err(error) => assert!(
            matches!(
                error,
                WorkerError::WriteIdentityUnattested {
                    cause: rivect::executor::Unattested::Unrecorded
                }
            ),
            "{error}"
        ),
    }
    assert_eq!(
        std::fs::read(&file).expect("read target after the unattested write"),
        b"scoped-by-seatbelt",
        "no byte may move for an unattested identity"
    );

    let reused = rivect::executor::WriteIdentity::new(genuine.file(), Ok(reused_token(token)));
    match worker.write_once(&scope_root, &file, reused, b"reused-bytes") {
        Ok(()) => panic!("reused case: the write returned Ok"),
        Err(error) => assert!(
            matches!(
                &error,
                WorkerError::TargetChanged { target } if target.as_path() == file.as_path()
            ),
            "{error}"
        ),
    }
    assert_eq!(
        std::fs::read(&file).expect("read target after the reused write"),
        b"scoped-by-seatbelt",
        "no byte may move for a reused (dev, ino)"
    );

    worker
        .write_once(&scope_root, &file, genuine, b"genuine-bytes")
        .expect("the genuine occupant identity writes");
    assert_eq!(
        std::fs::read(&file).expect("read target after the genuine write"),
        b"genuine-bytes"
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
        expected: rivect::executor::WriteIdentity,
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
    let mut executor = world.runtime.executor();
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
    let mut executor = world.runtime.executor();
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
    // in-scope program; Auto egress Allows when the URL was pre-approved
    // (a recorded approval is the declared bound) and Asks otherwise.
    // Auto write stays Ask without a budget. Allow cells cross the
    // real Seatbelt worker — the read lands, the write lands, the
    // confined exec runs a binary copied into the scope (the exec
    // profile's allowance is the scope subpath), and an egress Allow cell
    // (auto-with-preapproval / preapproved-only / yolo) meets the OS
    // denial the boundary imposes
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
    let write_grant = world.runtime.policy_writer().grant_classes(
        file.parent().expect("scope root").to_path_buf(),
        vec![Class::Write],
    );
    let exec_grant = world
        .runtime
        .policy_writer()
        .grant_classes(scope, vec![Class::Exec]);
    let egress_url = "https://example.invalid/matrix";
    let egress_grant = world.runtime.policy_writer().grant_classes(
        file.parent().expect("scope root").to_path_buf(),
        vec![Class::Egress],
    );
    for (class, grant_id, target) in [
        (
            Class::Read,
            grant.clone(),
            file.canonicalize()
                .expect("canonical read target")
                .display()
                .to_string(),
        ),
        (
            Class::Write,
            write_grant.clone(),
            file.canonicalize()
                .expect("canonical write target")
                .display()
                .to_string(),
        ),
        (
            Class::Exec,
            exec_grant.clone(),
            exec_program.display().to_string(),
        ),
        (Class::Egress, egress_grant.clone(), egress_url.to_string()),
    ] {
        world
            .runtime
            .store_writer()
            .record_preapproval(
                &preapproval_scope(class, &grant_id, &target).expect("utf-8 preapproval scope"),
                "human:matrix",
                600,
            )
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
                let mut executor = world.runtime.executor();
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
        let mut executor = world.runtime.executor();
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
        let mut executor = world.runtime.executor();
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
            .policy_writer()
            .grant_classes(scope, vec![Class::Read, Class::Write]);
        if mode == PermissionMode::PreapprovedOnly {
            world
                .runtime
                .store_writer()
                .record_preapproval(
                    &preapproval_scope(
                        Class::Write,
                        &grant,
                        &file
                            .canonicalize()
                            .expect("canonical write target")
                            .display()
                            .to_string(),
                    )
                    .expect("utf-8 preapproval scope"),
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
    let all_classes = world.runtime.policy_writer().grant_classes(
        scope_root.clone(),
        vec![
            EffectClass::Read,
            EffectClass::Write,
            EffectClass::Exec,
            EffectClass::Egress,
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
            .store_writer()
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
            let mut executor = world.runtime.executor();
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
    ensure_helper();
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
        macos::WriteIdentity::new(
            macos::FileIdentity::new(0, 0),
            Err(macos::Unattested::Unrecorded),
        ),
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
    {
        let (mut world, task, file, grant) = sandbox_world("helper-witness");
        let write_witness = world.root.join("write-witness");
        let shim = install_helper_io_shim(&world.root, &write_witness);
        rivect_sandbox_helper::override_helper_binary(Some(shim));
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                rivect_sandbox_helper::override_helper_binary(None);
            }
        }
        let _reset = Reset;
        {
            let mut executor = world.runtime.executor();
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
            match executor.execute(&admitted).expect("shim helper read") {
                EffectOutcome::Read { bytes, .. } => {
                    let text = String::from_utf8_lossy(&bytes);
                    assert!(
                        text.contains("scoped-by-seatbelt"),
                        "shim must still deliver the target bytes, got {text:?}"
                    );
                    assert!(
                        text.contains(HELPER_IO_WITNESS),
                        "a host read would omit the shim marker: {text:?}"
                    );
                }
                other => panic!("expected a shim helper read, got {other:?}"),
            }
        }
        let write_grant = world.runtime.policy_writer().grant_classes(
            file.parent().expect("scope").to_path_buf(),
            vec![EffectClass::Write],
        );
        let payload = b"from-shim";
        {
            let mut executor = world.runtime.executor();
            let admitted = executor
                .admit(
                    &task,
                    EffectRequest::Write {
                        grant_id: write_grant,
                        path: file,
                        bytes: payload.to_vec(),
                    },
                    PermissionMode::Yolo,
                )
                .expect("admit write");
            executor.execute(&admitted).expect("shim helper write");
        }
        let recorded = std::fs::read_to_string(&write_witness)
            .expect("confined write must record payload length; a host write produces no witness");
        assert_eq!(
            recorded.trim(),
            payload.len().to_string(),
            "shim write witness must match the payload length"
        );
    }
    {
        let (mut world, task, file, grant) = sandbox_world("helper-missing");
        rivect_sandbox_helper::override_helper_binary(Some(PathBuf::from(
            "/no/such/rivect-sandbox-helper",
        )));
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                rivect_sandbox_helper::override_helper_binary(None);
            }
        }
        let _reset = Reset;
        let mut executor = world.runtime.executor();
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
        let error = executor
            .execute(&admitted)
            .expect_err("a missing helper must fail closed, never host-read");
        assert!(
            matches!(
                error,
                ExecutorError::Worker(WorkerError::SandboxUnavailable { .. })
            ),
            "missing helper is SandboxUnavailable, got {error}"
        );
        assert_eq!(
            std::fs::read(&file).expect("target survives"),
            b"scoped-by-seatbelt",
            "a missing helper must not host-read or mutate the target"
        );
    }
    let (mut world, task, file, grant) = sandbox_world("helper-data-plane");
    {
        let scope = file.parent().expect("scope");
        let mut command = helper_confined_command(
            "macos",
            "not-a-mode",
            &macos::read_profile(scope).expect("read profile"),
        )
        .expect("data-plane confined command");
        command
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped());
        let output = command.run(&[]).expect("run data-plane confined helper");
        assert_eq!(
            output.status.code(),
            Some(rivect_sandbox_helper::EXIT_PROTOCOL),
            "confined helper protocol miss: {output:?}"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr
                .lines()
                .any(|line| line.starts_with("rivect-sandbox-helper:")),
            "the confined helper prefixes protocol misses; a host or shim cannot forge that: {stderr:?}"
        );
        assert!(
            stderr.contains("confined mode must be read or write"),
            "the inner confined-mode protocol miss must name the mode: {stderr:?}"
        );
        assert!(
            !stderr.contains("launch requires") && !stderr.contains("unknown mode"),
            "an outer launch-mode protocol miss is not this confined-mode miss: {stderr:?}"
        );
        assert!(
            !stderr.contains("exec failed") && !stderr.contains("failed to execute"),
            "a launch-exec failure is 126/127, not a confined protocol miss: {stderr:?}"
        );
        let name = helper
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        assert_eq!(
            name,
            "rivect-sandbox-helper",
            "the confined child must be the helper binary, got {}",
            helper.display()
        );
    }
    {
        let mut executor = world.runtime.executor();
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
    let write_grant = world.runtime.policy_writer().grant_classes(
        file.parent().expect("scope").to_path_buf(),
        vec![EffectClass::Write],
    );
    {
        let mut executor = world.runtime.executor();
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
    let mut fixture = TempTree::new("sandbox-macos", "hung-fifo");
    let fifo = fixture.path.join("hung.fifo");
    let status = std::process::Command::new("mkfifo").arg(&fifo).status();
    if status.is_err() {
        fixture.retain();
    }
    let status = status.expect("mkfifo");
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
    macos::write_once(
        &fixture.path,
        &target,
        rivect::executor::write_target_identity(&fixture.path, &target)
            .expect("target write identity"),
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
    let grant = world.runtime.policy_writer().grant_classes(
        scope.clone(),
        vec![Class::Read, Class::Write, Class::Exec, Class::Egress],
    );
    let egress_grant = world
        .runtime
        .policy_writer()
        .grant_classes(scope.clone(), vec![Class::Egress]);
    let canonical = scope.canonicalize().expect("canonical scope");
    let key = canonical.display().to_string();
    world
        .runtime
        .store_writer()
        .open_budget(&key, 8)
        .expect("open budget");
    world
        .runtime
        .store_writer()
        .retain(
            "checkpoint",
            &rivect::executor::checkpoint_boundary_id(&key),
        )
        .expect("retain checkpoint");
    let egress_url = "https://example.invalid/t11";
    world
        .runtime
        .store_writer()
        .record_preapproval(
            &preapproval_scope(Class::Egress, &egress_grant, egress_url)
                .expect("utf-8 egress preapproval"),
            "human:t11-egress",
            600,
        )
        .expect("record egress preapproval");
    let writes = Arc::new(AtomicU64::new(0));
    let egresses = Arc::new(AtomicU64::new(0));
    world.runtime.read_worker = Box::new(CountingSeatbeltWorker {
        reads: Arc::new(AtomicU64::new(0)),
        writes: writes.clone(),
        execs: Arc::new(AtomicU64::new(0)),
        egresses: egresses.clone(),
    });
    let ctx = rivect::executor::admission_context(
        world.runtime.store(),
        PermissionMode::Auto,
        Class::Write,
        &grant,
        &scope,
        &file,
    )
    .expect("live write context");
    assert!(ctx.budget_remaining);
    assert!(ctx.in_trusted_scope);
    assert!(ctx.has_checkpoint);
    assert!(ctx.in_grant_scope);
    let egress_ctx = rivect::executor::admission_context(
        world.runtime.store(),
        PermissionMode::Auto,
        Class::Egress,
        &egress_grant,
        &scope,
        Path::new(egress_url),
    )
    .expect("live egress context");
    assert!(
        egress_ctx.previously_approved,
        "seeded URL preapproval is the declared egress bound"
    );
    assert!(
        egress_ctx.within_declared_bounds,
        "Auto egress Allow is reachable when the URL was pre-approved"
    );
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
    let admitted = admit_live_cell(
        &mut world,
        &task,
        PermissionMode::Auto,
        EffectRequest::Egress {
            grant_id: egress_grant,
            url: egress_url.to_string(),
        },
        ModeDecision::Allow,
    )
    .expect("Auto egress must Allow when the URL was pre-approved");
    let error = execute_live_cell(&mut world, &admitted)
        .expect_err("the egress Allow cell is os-denied by the boundary, never ambient");
    assert!(
        matches!(
            error,
            ExecutorError::Worker(WorkerError::SandboxDenied { ref target })
                if target == &PathBuf::from(egress_url)
        ),
        "Auto egress allow denial: {error}"
    );
    assert_eq!(
        egresses.load(Ordering::SeqCst),
        1,
        "Auto egress Allow cell reached the seatbelt worker once"
    );
}

// ---------------------------------------------------------------------------
// Confined Cargo check (SLICE-178, DEC-040/041/042)
// ---------------------------------------------------------------------------

use rivect::contracts::{EffectClass, SessionId};
use rivect::executor::{
    CheckError, CheckRun, CheckTarget, CleanupClaim, ConfinedCheck, check_boundary_id,
    workspace_digest,
};
use std::sync::atomic::AtomicBool;

/// The canonical toolchain cargo of this test run: `CARGO` resolves to a
/// real toolchain binary in CI/docker layouts; under rustup it is the
/// proxy, whose directory has no sibling `rustc`, so `rustup which cargo`
/// resolves the real one — exactly the layout rule the executor enforces.
fn toolchain_cargo() -> PathBuf {
    let raw = PathBuf::from(env!("CARGO"));
    let canonical = raw.canonicalize().expect("canonicalize CARGO");
    if canonical
        .parent()
        .expect("cargo parent")
        .join("rustc")
        .is_file()
    {
        return canonical;
    }
    let resolved = std::process::Command::new("rustup")
        .args(["which", "cargo"])
        .output()
        .expect("rustup which cargo");
    assert!(
        resolved.status.success(),
        "rustup which cargo failed: {}",
        String::from_utf8_lossy(&resolved.stderr)
    );
    PathBuf::from(String::from_utf8_lossy(&resolved.stdout).trim())
        .canonicalize()
        .expect("canonical toolchain cargo")
}

fn host_cargo_home() -> PathBuf {
    dirs_home().join(".cargo")
}

fn dirs_home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .expect("HOME is set for the test host")
}

/// The `cfg-if` identity Rivect's own lock pins, read from the repo lock
/// at test time — the fixture lock carries exactly this checksum.
fn cfg_if_lock_entry() -> (String, String, String) {
    let lock = std::fs::read_to_string("Cargo.lock").expect("repo Cargo.lock");
    let mut name = None;
    let mut version = None;
    let mut checksum = None;
    for line in lock.lines() {
        if line.starts_with("name = ") && name.is_none() {
            name = line.split('"').nth(1).map(str::to_string);
        } else if line.starts_with("version = ") && name.is_some() && version.is_none() {
            version = line.split('"').nth(1).map(str::to_string);
        } else if line.starts_with("checksum = ") && name.is_some() && checksum.is_none() {
            checksum = line.split('"').nth(1).map(str::to_string);
        }
        if let (Some(n), Some(v), Some(c)) = (&name, &version, &checksum) {
            if n == "cfg-if" {
                return (n.clone(), v.clone(), c.clone());
            }
            name = None;
            version = None;
            checksum = None;
        }
    }
    panic!("cfg-if entry not found in the repo lock");
}

struct CheckFixture {
    tree: TempTree,
    answer: PathBuf,
}

impl CheckFixture {
    fn root(&self) -> &Path {
        &self.tree.path
    }

    fn set_answer(&self, content: &str) {
        std::fs::write(&self.answer, content).expect("write answer");
    }
}

/// Authors the dependency-free (or cfg-if-bearing) fixture crate the
/// confined check runs: a lib that exposes `answer.txt`, a `check` test
/// target with the green/env/capture tests, and a lock Cargo accepts
/// under `--locked --offline`.
fn check_fixture(tag: &str, answer_text: &str, with_dependency: bool) -> CheckFixture {
    let tree = TempTree::new("confined-check", tag);
    let root = tree.path.clone();
    std::fs::create_dir_all(root.join("src")).expect("src");
    std::fs::create_dir_all(root.join("tests")).expect("tests");
    let (dep_name, dep_version, dep_checksum) = cfg_if_lock_entry();
    let dependency_line = if with_dependency {
        format!("{dep_name} = \"={dep_version}\"")
    } else {
        String::new()
    };
    let dep_block = if with_dependency {
        format!("\n[dependencies]\n{dependency_line}\n")
    } else {
        String::new()
    };
    std::fs::write(
        root.join("Cargo.toml"),
        format!(
            "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n{dep_block}"
        ),
    )
    .expect("Cargo.toml");
    std::fs::write(
        root.join("src/lib.rs"),
        "pub fn answer() -> &'static str {\n    include_str!(\"../answer.txt\")\n}\n",
    )
    .expect("lib.rs");
    std::fs::write(
        root.join("tests/check.rs"),
        concat!(
            "#[test]\n",
            "fn green_passes() {\n",
            "    assert_eq!(fixture::answer(), \"ok\", \"the observed candidate answer\");\n",
            "}\n\n",
            "#[test]\n",
            "fn env_is_fixed_allowlist() {\n",
            // The exact allowlist. Everything NOT named here is absent
            // (RUSTC_WRAPPER, CC, BASH_ENV, LD_DEBUG, every other host
            // leak — the parent env_clears). The additions each platform
            // admits are injected INSIDE the sanctioned chain, never
            // ambient: the CARGO family is cargo's own test-harness
            // injection; DYLD_FALLBACK_LIBRARY_PATH is the loader path
            // the toolchain cargo exports for the test binary; PWD and
            // SSL_CERT_DIR are the Linux chain's sh/rustup-proxy
            // injections, kept in this shared source for symmetry.
            "    let allowed: &[&str] = if cfg!(target_os = \"macos\") {\n",
            "        &[\"CARGO_HOME\", \"HOME\", \"PATH\", \"TMPDIR\", \"SDKROOT\", \"DYLD_FALLBACK_LIBRARY_PATH\"]\n",
            "    } else {\n",
            "        &[\"CARGO_HOME\", \"HOME\", \"PATH\", \"TMPDIR\", \"LD_LIBRARY_PATH\", \"PWD\", \"SSL_CERT_DIR\", \"SSL_CERT_FILE\"]\n",
            "    };\n",
            "    for key in [\"CARGO_HOME\", \"HOME\", \"PATH\", \"TMPDIR\"] {\n",
            "        assert!(std::env::var_os(key).is_some(), \"missing {key}\");\n",
            "    }\n",
            "    let mut offenders: Vec<String> = Vec::new();\n",
            "    for (key, _) in std::env::vars_os() {\n",
            "        let key = key.to_string_lossy().to_string();\n",
            "        if !(allowed.contains(&key.as_str()) || key.starts_with(\"CARGO\")) {\n",
            "            offenders.push(key.clone());\n",
            "        }\n",
            "    assert!(\n",
            "        offenders.is_empty(),\n",
            "        \"keys outside the fixed allowlist leaked into the check env: {offenders:?}\"\n",
            "    );\n",
            "        let hostile = key.starts_with(\"RUSTUP_\")\n",
            "            || key.starts_with(\"CARGO_REGISTRY\")\n",
            "            || key.starts_with(\"CARGO_CREDENTIAL\")\n",
            "            || key.ends_with(\"_KEY\")\n",
            "            || key.ends_with(\"_TOKEN\");\n",
            "        assert!(!hostile, \"hostile ambient key leaked into the check env: {key}\");\n",
            "    }\n",
            "    let cargo_home = std::env::var(\"CARGO_HOME\").unwrap_or_default();\n",
            "    assert!(cargo_home.ends_with(\"/rw/cargo-home\"), \"private cargo home, got {cargo_home}\");\n",
            "}\n\n",
            "#[test]\n",
            "fn capture_prints_boundedly() {\n",
            "    println!(\"CAPTURE-HEAD-MARKER\");\n",
            "    for i in 0..40 {\n",
            "        println!(\"capture filler line {i:04} {}\", \"y\".repeat(1024));\n",
            "    }\n",
            "    println!(\"CAPTURE-TAIL-MARKER\");\n",
            "}\n",
        ),
    )
    .expect("check.rs");
    // A lock Cargo accepts under `--locked`: the dependency edge on the
    // fixture package must be present, or vendor refuses to keep the
    // hand-authored lock byte-identical.
    let (dep_deps_entry, dep_lock_entry) = if with_dependency {
        (
            format!("dependencies = [\n \"{dep_name}\",\n]\n"),
            format!(
                "\n[[package]]\nname = \"{dep_name}\"\nversion = \"{dep_version}\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"{dep_checksum}\"\n"
            ),
        )
    } else {
        (String::new(), String::new())
    };
    std::fs::write(
        root.join("Cargo.lock"),
        format!(
            "# This file is automatically @generated by Cargo.\nversion = 4\n\n[[package]]\nname = \"fixture\"\nversion = \"0.1.0\"\n{dep_deps_entry}{dep_lock_entry}"
        ),
    )
    .expect("Cargo.lock");
    let answer = root.join("answer.txt");
    std::fs::write(&answer, answer_text).expect("answer");
    CheckFixture { tree, answer }
}

/// Records the task's plan selection the way the server does — one
/// stable facts digest, so every harness run of a task pins revision 1
/// and the executor's admission binding has a current selection to
/// compare against.
fn record_plan_selection(
    world: &mut support::World,
    session: &SessionId,
    task: &rivect::contracts::TaskId,
) -> u64 {
    let config = rivect::config::Config::parse_validated(&support::base_config())
        .expect("harness config parses");
    let request = rivect::actions::PlanRequest {
        task_id: task.clone(),
        kind: rivect::actions::RequestKind::PlanOnly,
        surfaces: rivect::actions::SurfaceScan::Known([rivect::actions::Surface::Local].into()),
        contract: rivect::actions::ContractBasis::Absent,
        parts: Vec::new(),
        delegation: None,
        author: None,
    };
    let selection = rivect::actions::ActionRegistry::new()
        .select(
            &request,
            &[],
            &mut world.runtime.action_context(session, &config),
        )
        .expect("the harness records the task selection");
    selection.revision
}

/// Admits and runs one confined check through the real executor. Returns
/// the run for Ok, or the typed executor error.
fn run_confined_check(
    world: &mut support::World,
    session: &SessionId,
    task: &rivect::contracts::TaskId,
    fixture_root: &Path,
    dependencies: bool,
    exact_test: &str,
) -> Result<CheckRun, ExecutorError> {
    let expected = workspace_digest(fixture_root).expect("workspace digest");
    run_confined_check_with_digest(
        world,
        session,
        task,
        fixture_root,
        expected,
        dependencies,
        exact_test,
    )
}

/// [`run_confined_check`] for a candidate digest the harness bound before
/// a hostile mutation made the live tree uninventoryable.
fn run_confined_check_with_digest(
    world: &mut support::World,
    session: &SessionId,
    task: &rivect::contracts::TaskId,
    fixture_root: &Path,
    expected: String,
    dependencies: bool,
    exact_test: &str,
) -> Result<CheckRun, ExecutorError> {
    run_confined_check_on_home_with_digest(
        world,
        session,
        task,
        fixture_root,
        host_cargo_home(),
        expected,
        dependencies,
        exact_test,
    )
}

fn check_error_site(result: &Result<CheckRun, ExecutorError>) -> &'static str {
    match result {
        Err(ExecutorError::Check(error)) => error.site(),
        other => panic!("expected a typed check failure, got {other:?}"),
    }
}

#[test]
fn confined_check_runs_a_real_cargo_test_red_and_green() {
    ensure_helper();
    let fixture = check_fixture("red-green", "fail", false);
    let mut world = support::open_world("confined-check-red-green", None);
    let session = world.open_session("confined-check-red-green");
    let task = world.create_task(&session, "red-green");

    // RED: the observed candidate's exact test fails; that is a result,
    // never an Err.
    let red = run_confined_check(
        &mut world,
        &session,
        &task,
        fixture.root(),
        false,
        "green_passes",
    )
    .expect("the RED run completes");
    assert_ne!(red.exit_code, Some(0), "the failing candidate is RED");
    let summary = red.summary.as_deref().unwrap_or_default();
    assert!(
        summary.contains("FAILED. 0 passed; 1 failed; 0 ignored"),
        "the bounded cargo summary pins the counts, not the elapsed time: {summary:?}"
    );

    // GREEN: the same identity after the fix — same digests recomputed on
    // the new candidate, exit zero.
    fixture.set_answer("ok");
    let green = run_confined_check(
        &mut world,
        &session,
        &task,
        fixture.root(),
        false,
        "green_passes",
    )
    .expect("the GREEN run completes");
    assert_eq!(green.exit_code, Some(0), "the passing candidate is GREEN");
    assert!(green.summary.as_deref().unwrap_or("").contains("ok."));
    assert_eq!(green.cleanup, CleanupClaim::MacosBestEffort);
    assert!(
        green.attempt_root.is_some(),
        "transport success keeps the attempt root in place: the executor never decides the verdict or removes the root (DEC-047), and strict cleanup (DEC-056) refuses the destructive emptying"
    );
    assert!(
        green.vendor_digest.is_none(),
        "a dependency-free run vendors nothing"
    );
    assert_ne!(green.check_digest_v1, green.check_digest_v2);
    // The durable pre-effect row exists for the run's attempt: every
    // settled attempt of the task has one (checked via the retained
    // boundary of the latest attempt below is not exposed; the seam test
    // asserts the row directly with the attempt id).
}

#[test]
fn confined_check_env_is_the_fixed_allowlist() {
    ensure_helper();
    let fixture = check_fixture("env", "ok", false);
    let mut world = support::open_world("confined-check-env", None);
    let session = world.open_session("confined-check-env");
    let task = world.create_task(&session, "env");
    let run = run_confined_check(
        &mut world,
        &session,
        &task,
        fixture.root(),
        false,
        "env_is_fixed_allowlist",
    )
    .expect("the env fixture passes inside the sandbox");
    let env_stderr = String::from_utf8_lossy(&run.stderr.tail);
    assert_eq!(
        run.exit_code,
        Some(0),
        "the fixed env satisfies the fixture; stderr tail: {env_stderr}"
    );
    // A positive selected-test count proves cargo really ran the env
    // discriminator — a zero-selection exit 0 must not pass (TA env).
    let summary = run.summary.as_deref().unwrap_or_default();
    assert!(
        summary.contains("1 passed; 0 failed"),
        "exactly the env test was selected: {summary}"
    );
}

#[test]
fn confined_check_capture_keeps_head_and_tail() {
    ensure_helper();
    let fixture = check_fixture("capture", "ok", false);
    let mut world = support::open_world("confined-check-capture", None);
    let session = world.open_session("confined-check-capture");
    let task = world.create_task(&session, "capture");
    let run = run_confined_check(
        &mut world,
        &session,
        &task,
        fixture.root(),
        false,
        "capture_prints_boundedly",
    )
    .expect("the capture fixture passes");
    assert_eq!(run.exit_code, Some(0));
    let head = String::from_utf8_lossy(&run.stdout.head);
    let tail = String::from_utf8_lossy(&run.stdout.tail);
    assert!(head.contains("CAPTURE-HEAD-MARKER"), "head: {head}");
    assert!(tail.contains("CAPTURE-TAIL-MARKER"), "tail: {tail}");
    assert!(
        !head.contains("CAPTURE-TAIL-MARKER"),
        "the overflowing head dropped the tail"
    );
    assert!(
        run.stdout.total > (rivect::executor::CHECK_CAPTURE_EDGE_BYTES as u64) * 2,
        "the total counts every produced byte: {}",
        run.stdout.total
    );
}

#[test]
fn confined_check_dependency_project_uses_verified_offline_sources() {
    ensure_helper();
    let fixture = check_fixture("deps", "ok", true);
    let mut world = support::open_world("confined-check-deps", None);
    let session = world.open_session("confined-check-deps");
    let task = world.create_task(&session, "deps");
    let revision = record_plan_selection(&mut world, &session, &task);
    let cargo = toolchain_cargo();
    let expected = workspace_digest(fixture.root()).expect("workspace digest");
    let check = ConfinedCheck {
        task_id: task.clone(),
        expected_selection_revision: revision,
        project_grant_id: world
            .runtime
            .policy_writer()
            .grant_read(fixture.root().to_path_buf()),
        project_root: fixture.root().to_path_buf(),
        manifest_rel: PathBuf::from("Cargo.toml"),
        cargo: cargo.clone(),
        cargo_home: host_cargo_home(),
        target: CheckTarget::Integration("check".to_string()),
        harness_threads: 1,
        exact_test: "green_passes".to_string(),
        expected_phase: "candidate-review".to_string(),
        expected_assertion_identity: "green_passes".to_string(),
        expected_candidate_digest: expected,
    };
    let exec_grant = world.runtime.policy_writer().grant_classes(
        cargo.parent().expect("toolchain dir").to_path_buf(),
        vec![EffectClass::Exec],
    );
    let handoff = world.runtime.check_handoff(&task);
    let mut admission = {
        let mut executor = world.runtime.executor();
        executor
            .admit_check(
                &task,
                EffectRequest::Exec {
                    grant_id: exec_grant,
                    program: cargo,
                },
                PermissionMode::Yolo,
                &check,
                &handoff,
            )
            .expect("admission")
    };
    let runtime = &mut world.runtime;
    runtime
        .policy_writer()
        .issue_check_dependencies(&mut admission)
        .expect("the sanctioned dependency pair issues");
    let mut executor = world.runtime.executor();
    let run = executor
        .execute_check(&mut admission, &check, &AtomicBool::new(false))
        .expect("the dependency-bearing fixture passes offline");
    assert_eq!(run.exit_code, Some(0));
    let vendor = run.vendor_digest.expect("a verified vendor digest");
    assert!(!vendor.is_empty());
    // DEC-048: the pair is consumed on the admitted exit — re-presenting
    // the same admission refuses as a claim replay, never re-admitting
    // the cache/index roots; the project and Exec grants survive.
    let replay = executor.execute_check(&mut admission, &check, &AtomicBool::new(false));
    assert_eq!(
        check_error_site(&replay),
        "admit.replay",
        "the claimed admission never dispatches twice"
    );
}

#[test]
fn confined_check_dependency_grants_are_validated_before_the_first_cache_byte() {
    ensure_helper();
    let fixture = check_fixture("dep-validate", "ok", true);
    let mut world = support::open_world("confined-check-dep-validate", None);
    let session = world.open_session("confined-check-dep-validate");
    let task = world.create_task(&session, "dep-validate");
    // A registry lock without a pair is the typed setup gap, not a RED.
    let missing = run_confined_check(
        &mut world,
        &session,
        &task,
        fixture.root(),
        false,
        "green_passes",
    );
    assert_eq!(check_error_site(&missing), "dep.cache_scope");
    // A released pair (the issuer-side revocation twin of the old
    // aliased/wide-root construction legs, which the opaque receipt
    // made inexpressible): the allocation ended, so the presentation
    // refuses at the issuer before any cache byte, staging, or spawn.
    let stopped = run_confined_check_released(&mut world, &session, &task, fixture.root());
    assert_eq!(
        check_error_site(&stopped),
        "admit.issuer",
        "a released allocation never dispatches"
    );
}

/// Runs one check whose pair was issued and immediately released: the
/// admission is Spent before any presentation, exactly like a mid-flight
/// revocation under the opaque-receipt design.
fn run_confined_check_released(
    world: &mut support::World,
    session: &SessionId,
    task: &rivect::contracts::TaskId,
    fixture_root: &Path,
) -> Result<CheckRun, ExecutorError> {
    let revision = record_plan_selection(world, session, task);
    let cargo = toolchain_cargo();
    let expected = workspace_digest(fixture_root).expect("workspace digest");
    let check = ConfinedCheck {
        task_id: task.clone(),
        expected_selection_revision: revision,
        project_grant_id: world
            .runtime
            .policy_writer()
            .grant_read(fixture_root.to_path_buf()),
        project_root: fixture_root.to_path_buf(),
        manifest_rel: PathBuf::from("Cargo.toml"),
        cargo: cargo.clone(),
        cargo_home: host_cargo_home(),
        target: CheckTarget::Integration("check".to_string()),
        harness_threads: 1,
        exact_test: "green_passes".to_string(),
        expected_phase: "candidate-review".to_string(),
        expected_assertion_identity: "green_passes".to_string(),
        expected_candidate_digest: expected,
    };
    let exec_grant = world.runtime.policy_writer().grant_classes(
        cargo.parent().expect("toolchain dir").to_path_buf(),
        vec![EffectClass::Exec],
    );
    let handoff = world.runtime.check_handoff(task);
    let mut admission = {
        let mut executor = world.runtime.executor();
        executor.admit_check(
            task,
            EffectRequest::Exec {
                grant_id: exec_grant,
                program: cargo,
            },
            PermissionMode::Yolo,
            &check,
            &handoff,
        )?
    };
    let runtime = &mut world.runtime;
    runtime
        .policy_writer()
        .issue_check_dependencies(&mut admission)
        .expect("the pair issues before the release");
    runtime
        .policy_writer()
        .release_check_dependencies(&mut admission);
    let mut executor = world.runtime.executor();
    executor.execute_check(&mut admission, &check, &AtomicBool::new(false))
}

#[test]
fn confined_check_dependency_grants_revocation_stops_staging_and_both_phases() {
    ensure_helper();
    let fixture = check_fixture("dep-revoke", "ok", true);
    let mut world = support::open_world("confined-check-dep-revoke", None);
    let session = world.open_session("confined-check-dep-revoke");
    let task = world.create_task(&session, "dep-revoke");
    // The issuer-side revocation: a released allocation stops before
    // any cache byte, staging, or spawn — the pair died at its owner.
    let stopped = run_confined_check_released(&mut world, &session, &task, fixture.root());
    assert_eq!(
        check_error_site(&stopped),
        "admit.issuer",
        "a released pair stops before any staging or spawn"
    );
}

/// Runs one dependency-bearing check whose issued pair died while the
/// admission stayed Pending (the entries unregistered without a spend):
/// the unregistered receipt must fail the pre-claim validation, before
/// any claim, root, or copied project byte. Returns the attempt id with
/// the outcome so the planned-attempt invariant is observable.
fn run_confined_check_unregistered(
    world: &mut support::World,
    session: &SessionId,
    task: &rivect::contracts::TaskId,
    fixture_root: &Path,
) -> (String, Result<CheckRun, ExecutorError>) {
    let revision = record_plan_selection(world, session, task);
    let cargo = toolchain_cargo();
    let expected = workspace_digest(fixture_root).expect("workspace digest");
    let check = ConfinedCheck {
        task_id: task.clone(),
        expected_selection_revision: revision,
        project_grant_id: world
            .runtime
            .policy_writer()
            .grant_read(fixture_root.to_path_buf()),
        project_root: fixture_root.to_path_buf(),
        manifest_rel: PathBuf::from("Cargo.toml"),
        cargo: cargo.clone(),
        cargo_home: host_cargo_home(),
        target: CheckTarget::Integration("check".to_string()),
        harness_threads: 1,
        exact_test: "green_passes".to_string(),
        expected_phase: "candidate-review".to_string(),
        expected_assertion_identity: "green_passes".to_string(),
        expected_candidate_digest: expected,
    };
    let exec_grant = world.runtime.policy_writer().grant_classes(
        cargo.parent().expect("toolchain dir").to_path_buf(),
        vec![EffectClass::Exec],
    );
    let handoff = world.runtime.check_handoff(task);
    let mut admission = {
        let mut executor = world.runtime.executor();
        executor
            .admit_check(
                task,
                EffectRequest::Exec {
                    grant_id: exec_grant,
                    program: cargo,
                },
                PermissionMode::Yolo,
                &check,
                &handoff,
            )
            .expect("the admission mints")
    };
    let attempt_id = admission.bound_attempt_id().to_string();
    let runtime = &mut world.runtime;
    runtime
        .policy_writer()
        .issue_check_dependencies(&mut admission)
        .expect("the pair issues before the unregistration");
    runtime.policy_writer().consume_check_pair(&mut admission);
    assert_eq!(
        admission.phase(),
        rivect::executor::CheckPhase::Pending,
        "the unregistration keeps the phase pending"
    );
    let mut executor = world.runtime.executor();
    (
        attempt_id,
        executor.execute_check(&mut admission, &check, &AtomicBool::new(false)),
    )
}

#[test]
fn confined_check_unregistered_pending_receipt_refuses_before_the_claim() {
    ensure_helper();
    let fixture = check_fixture("dep-unregistered", "ok", true);
    let mut world = support::open_world("confined-check-dep-unregistered", None);
    let session = world.open_session("confined-check-dep-unregistered");
    let task = world.create_task(&session, "dep-unregistered");
    let (attempt_id, stopped) =
        run_confined_check_unregistered(&mut world, &session, &task, fixture.root());
    assert_eq!(
        check_error_site(&stopped),
        "admit.dep",
        "an unregistered pending receipt refuses at the pair seam"
    );
    assert_eq!(
        world
            .runtime
            .store()
            .attempt_state(&attempt_id)
            .expect("attempt state")
            .as_deref(),
        Some("planned"),
        "the pre-claim refusal never claims or settles the attempt"
    );
    assert!(
        !rivect::executor::attempt_root_of(&attempt_id).exists(),
        "no attempt root was created"
    );
}

#[test]
fn confined_check_refuses_a_preexisting_attempt_root_name() {
    ensure_helper();
    let fixture = check_fixture("root-squatted", "ok", false);
    let mut world = support::open_world("confined-check-root-squatted", None);
    let session = world.open_session("confined-check-root-squatted");
    let task = world.create_task(&session, "root-squatted");
    let revision = record_plan_selection(&mut world, &session, &task);
    let cargo = toolchain_cargo();
    let expected = workspace_digest(fixture.root()).expect("workspace digest");
    let check = ConfinedCheck {
        task_id: task.clone(),
        expected_selection_revision: revision,
        project_grant_id: world
            .runtime
            .policy_writer()
            .grant_read(fixture.root().to_path_buf()),
        project_root: fixture.root().to_path_buf(),
        manifest_rel: PathBuf::from("Cargo.toml"),
        cargo: cargo.clone(),
        cargo_home: host_cargo_home(),
        target: CheckTarget::Integration("check".to_string()),
        harness_threads: 1,
        exact_test: "green_passes".to_string(),
        expected_phase: "candidate-review".to_string(),
        expected_assertion_identity: "green_passes".to_string(),
        expected_candidate_digest: expected,
    };
    let exec_grant = world.runtime.policy_writer().grant_classes(
        cargo.parent().expect("toolchain dir").to_path_buf(),
        vec![EffectClass::Exec],
    );
    let handoff = world.runtime.check_handoff(&task);
    let mut admission = {
        let mut executor = world.runtime.executor();
        executor
            .admit_check(
                &task,
                EffectRequest::Exec {
                    grant_id: exec_grant,
                    program: cargo,
                },
                PermissionMode::Yolo,
                &check,
                &handoff,
            )
            .expect("the admission mints")
    };
    // A foreign directory squats on the attempt's root name: the
    // exclusive creation must refuse — the existing path is never
    // adopted, deleted from, or written into.
    let squatted = rivect::executor::attempt_root_of(admission.bound_attempt_id());
    std::fs::create_dir_all(&squatted).expect("the squatter directory");
    std::fs::write(squatted.join("foreign-sentinel"), b"not this allocation")
        .expect("the foreign sentinel");
    let mut executor = world.runtime.executor();
    let refused = executor.execute_check(&mut admission, &check, &AtomicBool::new(false));
    assert_eq!(
        check_error_site(&refused),
        "snapshot.copy",
        "the exclusive creation refuses at its own seam"
    );
    assert!(
        squatted.join("foreign-sentinel").exists(),
        "the foreign directory survives the refusal byte-for-byte"
    );
}

#[test]
fn confined_check_dependency_grants_are_consumed_only_for_their_attempt() {
    ensure_helper();
    let fixture = check_fixture("dep-consume", "ok", true);
    let mut world = support::open_world("confined-check-dep-consume", None);
    let session = world.open_session("confined-check-dep-consume");
    let task = world.create_task(&session, "dep-consume");
    let first = run_confined_check(
        &mut world,
        &session,
        &task,
        fixture.root(),
        true,
        "green_passes",
    )
    .expect("the first attempt succeeds");
    assert_eq!(first.exit_code, Some(0));
    // A fresh intentional attempt with a fresh issuance on the same
    // task is independent (fresh attempt, fresh pair) — only the SAME
    // admission can never dispatch twice.
    let fixture2 = check_fixture("dep-consume-2", "ok", true);
    let second = run_confined_check(
        &mut world,
        &session,
        &task,
        fixture2.root(),
        true,
        "green_passes",
    )
    .expect("a fresh attempt with a fresh pair succeeds");
    assert_eq!(second.exit_code, Some(0));
}

#[test]
fn confined_check_dependency_grants_hide_the_host_registry_from_the_sandbox() {
    // The read control of every executed check targets the host registry
    // itself; proving that leg denies under the real profile is the
    // child-side invisibility proof. The env fixture additionally pins
    // the private CARGO_HOME spelling. The target is a REGULAR file —
    // the real cfg-if archive from the host cache — because a directory
    // target made /bin/cat fail EISDIR whether or not the boundary
    // denied, and the probe runs under the CONTROL profile: its read
    // allowances are the check profile's own (a pure exec superset), and
    // without the cat exec allowance the leg only ever observed the EXEC
    // denial — the exact confound the control predicate rejects (TA
    // M-profile survived both).
    ensure_helper();
    let toolchain = toolchain_cargo()
        .parent()
        .expect("toolchain dir")
        .to_path_buf();
    let attempt_owner =
        tempfile::TempDir::with_prefix("rivect-control-proof-").expect("control proof root");
    let attempt_root = attempt_owner.path().to_path_buf();
    std::fs::create_dir_all(attempt_root.join("src")).expect("control src");
    std::fs::create_dir_all(attempt_root.join("rw")).expect("control rw");
    let control_bin = attempt_root.join("control").join("bin");
    std::fs::create_dir_all(&control_bin).expect("control bin");
    let profile = macos::check_control_profile(
        &macos::CheckProfile {
            toolchain,
            snapshot: attempt_root.join("src"),
            rw: attempt_root.join("rw"),
            test_binaries: false,
        },
        &control_bin,
    )
    .expect("check control profile");
    let (archive, _, _, _) = cfg_if_identity();
    let denied = confined(&profile, Path::new("/bin/cat"), &[archive.as_os_str()])
        .expect("confined read control run");
    assert!(
        !denied.exit_ok,
        "the host registry's real archive is invisible to the confined child: {denied:?}"
    );
    assert!(
        denied.stderr.contains("Operation not permitted"),
        "the denial carries the OS permission cause, not a kind error: {denied:?}"
    );
    assert!(
        denied.stderr.contains("cat"),
        "the denial names the probe's own operation: {denied:?}"
    );
    assert!(
        !denied.stderr.contains("Is a directory"),
        "a regular-file target cannot fail with EISDIR: {denied:?}"
    );
}

#[test]
fn confined_check_dependency_ancestor_swap_refused_before_any_byte() {
    // A private cargo home whose index `.cache` ancestor — below the
    // granted canonical index root, above the leaf entry — is renamed out
    // and replaced by a symlink: the leaf keeps its inode and checksum
    // behind the link, the pair and root anchoring still pass, and the
    // fd-anchored shard walk must refuse the symlinked component before
    // staging any index byte (D-122).
    ensure_helper();
    let (_, dep_name, dep_version, dep_checksum) = cfg_if_identity();
    let holder = TempTree::new("confined-check", "ancestor-swap");
    let cargo_home = holder.path.join("home");
    populate_fake_registry(&cargo_home, &dep_name, &dep_version, &dep_checksum);
    // Move the index cache ancestor out and symlink it back: the granted
    // roots stay canonical, the leaf identity survives behind the link.
    let (registry_dir, _, _) = registry_layout();
    let cache_ancestor = cargo_home
        .join("registry/index")
        .join(&registry_dir)
        .join(".cache");
    std::fs::rename(&cache_ancestor, holder.path.join("stolen")).expect("rename ancestor away");
    std::os::unix::fs::symlink(holder.path.join("stolen"), &cache_ancestor)
        .expect("symlink ancestor back");

    let fixture = check_fixture("ancestor", "ok", true);
    let mut world = support::open_world("confined-check-ancestor", None);
    let session = world.open_session("confined-check-ancestor");
    let task = world.create_task(&session, "ancestor");
    let cargo = toolchain_cargo();
    let expected = workspace_digest(fixture.root()).expect("digest");
    let canonical_home = cargo_home.canonicalize().expect("canonical fake home");
    let check = ConfinedCheck {
        task_id: task.clone(),
        // Bound by `direct_execute_check` when it records the selection.
        expected_selection_revision: 0,
        project_grant_id: world
            .runtime
            .policy_writer()
            .grant_read(fixture.root().to_path_buf()),
        project_root: fixture.root().to_path_buf(),
        manifest_rel: PathBuf::from("Cargo.toml"),
        cargo,
        cargo_home: canonical_home,
        target: CheckTarget::Integration("check".to_string()),
        harness_threads: 1,
        exact_test: "green_passes".to_string(),
        expected_phase: "candidate-review".to_string(),
        expected_assertion_identity: "green_passes".to_string(),
        expected_candidate_digest: expected,
    };
    let error = direct_execute_check(&mut world, &session, &task, check, true);
    assert!(
        matches!(
            &error,
            ExecutorError::Check(error) if matches!(
                error,
                CheckError::CacheComponent { .. }
                    | CheckError::CacheRootFd { .. }
                    | CheckError::CacheAncestry { .. }
            )
        ),
        "a swapped ancestor refuses before any byte, got {error:?}"
    );
}

#[test]
fn confined_check_dependency_fd_anchor_only_reads_authorized_inode() {
    // The nested sparse-index layout (`.cache/cf/gf/cfg-if`) opened
    // through pinned fds on a private cargo home: the positive proves the
    // fd anchor reads exactly the authorized nested inode.
    ensure_helper();
    let (_, dep_name, dep_version, dep_checksum) = cfg_if_identity();
    // A tag distinct from the fixture's: TempTree paths key on pid alone,
    // so a shared tag would let the fixture erase the fake home.
    let holder = TempTree::new("confined-check", "fd-anchor-registry");
    let cargo_home = holder.path.join("home");
    populate_fake_registry(&cargo_home, &dep_name, &dep_version, &dep_checksum);
    let fixture = check_fixture("fd-anchor", "ok", true);
    let mut world = support::open_world("confined-check-fd-anchor", None);
    let session = world.open_session("confined-check-fd-anchor");
    let task = world.create_task(&session, "fd-anchor");
    let canonical_home = cargo_home.canonicalize().expect("canonical fake home");
    let run = run_confined_check_on_home(
        &mut world,
        &session,
        &task,
        fixture.root(),
        canonical_home,
        true,
    )
    .expect("the fd-anchored nested index read stages the dependency");
    assert_eq!(run.exit_code, Some(0));
    assert!(run.vendor_digest.is_some());
}

#[test]
fn confined_check_index_member_revocation_stops_before_any_byte() {
    // A7: the death of the pair — the issuer-side revocation under the
    // opaque receipt — refuses at presentation for each member shape.
    // The released-allocation leg covers both single-member and
    // both-members revocation: the pair is one allocation, and the old
    // per-member generic revocation path is inexpressible through the
    // opaque receipt (entries live in the issuer, not the grant map).
    ensure_helper();
    let fixture = check_fixture("dep-revoke-index", "ok", true);
    let mut world = support::open_world("confined-check-dep-revoke-index", None);
    let session = world.open_session("confined-check-dep-revoke-index");
    let task = world.create_task(&session, "dep-revoke-index");
    let stopped = run_confined_check_released(&mut world, &session, &task, fixture.root());
    assert_eq!(
        check_error_site(&stopped),
        "admit.issuer",
        "a dead pair refuses before any cache byte"
    );
    // In-run revocation between the per-leaf reconsults stays a recorded
    // black-box gap: no hook can interleave it (existing justification).
}

#[test]
fn confined_check_dependency_consumption_compiles_the_dependency_in() {
    // B3: the dependent fixture's GREEN body CONSUMES cfg-if — a passing
    // `cfg_if_is_compiled_in` proves the vendored dependency was really
    // staged and compiled, and the dependent RED→GREEN runs with FRESH
    // grants on each side.
    ensure_helper();
    let fixture = check_fixture("dep-use", "fail", true);
    // The lib grows a cfg-if macro call; the check target grows the
    // consuming test beside the answer test.
    std::fs::write(
        fixture.root().join("src/lib.rs"),
        concat!(
            "use cfg_if::cfg_if;\n",
            "pub fn answer() -> &'static str {\n",
            "    include_str!(\"../answer.txt\")\n",
            "}\n",
            "pub fn pointer_width() -> u32 {\n",
            "    cfg_if! { if #[cfg(target_pointer_width = \"64\")] { 64 } else { 32 } }\n",
            "}\n",
        ),
    )
    .expect("dep-consuming lib.rs");
    // The check target keeps ONE test on both sides of the transition
    // (AC-018: GREEN preserves the RED run's test source and selection
    // identity): `green_passes` consumes cfg-if in its own body — the
    // pointer-width assert only passes if the macro from the vendored
    // dependency really compiled in.
    std::fs::write(
        fixture.root().join("tests/check.rs"),
        concat!(
            "#[test]\n",
            "fn green_passes() {\n",
            "    assert_eq!(fixture::answer(), \"ok\", \"the observed candidate answer\");\n",
            "    assert_eq!(fixture::pointer_width(), 64, \"cfg-if's macro ran\");\n",
            "}\n",
        ),
    )
    .expect("dep-consuming check.rs");
    let mut world = support::open_world("confined-check-dep-use", None);
    let session = world.open_session("confined-check-dep-use");
    let task = world.create_task(&session, "dep-use");
    // RED: the same single test fails on the answer assert while the
    // dependency itself stages and compiles.
    let red = run_confined_check(
        &mut world,
        &session,
        &task,
        fixture.root(),
        true,
        "green_passes",
    )
    .expect("the dependent RED run completes");
    assert_ne!(red.exit_code, Some(0), "the dependent candidate is RED");
    let red_summary = red.summary.as_deref().unwrap_or_default();
    assert!(
        red_summary.contains("FAILED. 0 passed; 1 failed"),
        "the dependent RED names its one selected test: {red_summary}"
    );
    // GREEN with a FRESH issuance on the SAME selector and test count:
    // only the product bytes changed (answer.txt), and the passing body
    // itself proves cfg-if was compiled into the executed binary.
    fixture.set_answer("ok");
    let green = run_confined_check(
        &mut world,
        &session,
        &task,
        fixture.root(),
        true,
        "green_passes",
    )
    .expect("the dependent GREEN run completes");
    assert_eq!(green.exit_code, Some(0), "the consuming test passes");
    let green_summary = green.summary.as_deref().unwrap_or_default();
    assert!(
        green_summary.contains("1 passed; 0 failed"),
        "exactly the same single test was selected on GREEN: {green_summary}"
    );
    assert!(
        green.vendor_digest.as_deref().unwrap_or("").len() == 64,
        "a verified vendor digest lands for the consuming run"
    );
}

#[test]
fn confined_check_dependency_negative_matrix_refuses_at_staging_seams() {
    // B3 negatives: each broken-cache leg refuses at its own typed
    // staging seam — before any phase-B spawn.
    ensure_helper();
    let (_, dep_name, dep_version, dep_checksum) = cfg_if_identity();
    let (registry_dir, _, _) = registry_layout();
    type NegativeLeg = Box<dyn Fn(&Path)>;
    let legs: [(&str, &str, NegativeLeg); 8] = [
        ("missing-archive", "dep.cache_missing", {
            let registry_dir = registry_dir.clone();
            Box::new(move |home: &Path| {
                let (_, name, version, _) = cfg_if_identity();
                drop(std::fs::remove_file(
                    home.join("registry/cache")
                        .join(&registry_dir)
                        .join(format!("{name}-{version}.crate")),
                ));
            })
        }),
        ("corrupt-archive", "dep.checksum", {
            let registry_dir = registry_dir.clone();
            Box::new(move |home: &Path| {
                let (_, name, version, _) = cfg_if_identity();
                std::fs::write(
                    home.join("registry/cache")
                        .join(&registry_dir)
                        .join(format!("{name}-{version}.crate")),
                    b"corrupted archive bytes",
                )
                .expect("corrupt the archive");
            })
        }),
        // The D-124 leaf refusals executed, not constructed: a hard
        // link on the archive (nlink > 1), a symlink in its place, and
        // a sparse oversize — each refuses at its own distinct seam.
        ("hardlinked-archive", "dep.cache_links", {
            let registry_dir = registry_dir.clone();
            Box::new(move |home: &Path| {
                let (_, name, version, _) = cfg_if_identity();
                let archive = home
                    .join("registry/cache")
                    .join(&registry_dir)
                    .join(format!("{name}-{version}.crate"));
                std::fs::hard_link(&archive, archive.with_extension("crate.alias"))
                    .expect("hard link the archive");
            })
        }),
        ("symlinked-archive", "dep.cache_leaf", {
            let registry_dir = registry_dir.clone();
            Box::new(move |home: &Path| {
                let (_, name, version, _) = cfg_if_identity();
                let archive = home
                    .join("registry/cache")
                    .join(&registry_dir)
                    .join(format!("{name}-{version}.crate"));
                let stolen = archive.with_extension("crate.stolen");
                std::fs::rename(&archive, &stolen).expect("move the archive out");
                std::os::unix::fs::symlink(&stolen, &archive).expect("symlink the archive back");
            })
        }),
        ("oversize-archive", "dep.cache_size", {
            let registry_dir = registry_dir.clone();
            Box::new(move |home: &Path| {
                let (_, name, version, _) = cfg_if_identity();
                let archive = home
                    .join("registry/cache")
                    .join(&registry_dir)
                    .join(format!("{name}-{version}.crate"));
                let file = std::fs::OpenOptions::new()
                    .write(true)
                    .open(&archive)
                    .expect("open the archive for growth");
                file.set_len(rivect::executor::DEP_ARCHIVE_MAX_BYTES + 1)
                    .expect("grow the archive past the bound");
                drop(file);
            })
        }),
        ("missing-index-entry", "dep.cache_missing", {
            let registry_dir = registry_dir.clone();
            let dep_name = dep_name.clone();
            Box::new(move |home: &Path| {
                let chars: Vec<char> = dep_name.chars().collect();
                let mut entry = home
                    .join("registry/index")
                    .join(&registry_dir)
                    .join(".cache");
                for shard in [
                    &chars[..2].iter().collect::<String>(),
                    &chars[2..4].iter().collect::<String>(),
                ] {
                    entry = entry.join(shard);
                }
                drop(std::fs::remove_file(entry.join(&dep_name)));
            })
        }),
        (
            "git-source-lock",
            "dep.config",
            Box::new(move |_home: &Path| {}),
        ),
        // A cargo home whose registry carries no familiar
        // index.crates.io-* spelling refuses at the config seam — the
        // anchor fails closed instead of guessing a layout (T9
        // config-source sibling).
        ("unfamiliar-registry-layout", "dep.config", {
            Box::new(move |home: &Path| {
                for branch in ["registry/cache", "registry/index"] {
                    let dir = home.join(branch).join(&registry_dir);
                    let weird = home.join(branch).join("mirror.example-invalid-0000");
                    std::fs::rename(&dir, &weird).expect("rename the registry dir away");
                }
            })
        }),
    ];
    for (tag, expected_site, mutate) in legs {
        let fixture = check_fixture(&format!("dep-neg-{tag}"), "ok", true);
        if tag == "git-source-lock" {
            // The lock's dependency source becomes a git URL: the lock
            // parse refuses the non-registry source before any staging.
            let lock = std::fs::read_to_string(fixture.root().join("Cargo.lock"))
                .expect("lock")
                .replace(
                    "registry+https://github.com/rust-lang/crates.io-index",
                    "git+https://github.com/example/cfg-if",
                );
            std::fs::write(fixture.root().join("Cargo.lock"), lock).expect("git-source lock");
        }
        let holder = TempTree::new("confined-check", &format!("neg-{tag}"));
        let cargo_home = holder.path.join("home");
        populate_fake_registry(&cargo_home, &dep_name, &dep_version, &dep_checksum);
        mutate(&cargo_home);
        let mut world = support::open_world(&format!("confined-check-dep-neg-{tag}"), None);
        let session = world.open_session(&format!("confined-check-dep-neg-{tag}"));
        let task = world.create_task(&session, &format!("dep-neg-{tag}"));
        let canonical_home = cargo_home.canonicalize().expect("canonical home");
        let refused = run_confined_check_on_home(
            &mut world,
            &session,
            &task,
            fixture.root(),
            canonical_home,
            true,
        );
        assert_eq!(
            check_error_site(&refused),
            expected_site,
            "the {tag} leg refuses at its own seam, got {:?}",
            refused.err()
        );
    }
}

#[test]
fn confined_check_live_digest_drift_refuses_at_snapshot_digest() {
    // The inventory-digest sibling (T9): the live tree drifting from the
    // recorded candidate digest refuses at snapshot.digest before any
    // copy or spawn — the ABA test's positive twin.
    ensure_helper();
    let fixture = check_fixture("digest-drift", "ok", false);
    let mut world = support::open_world("confined-check-digest-drift", None);
    let session = world.open_session("confined-check-digest-drift");
    let task = world.create_task(&session, "digest-drift");
    let expected = workspace_digest(fixture.root()).expect("digest");
    fixture.set_answer("drifted");
    let refused = run_confined_check_with_digest(
        &mut world,
        &session,
        &task,
        fixture.root(),
        expected,
        false,
        "green_passes",
    );
    assert_eq!(
        check_error_site(&refused),
        "snapshot.digest",
        "a drifted live tree refuses at the digest seam"
    );
}

#[test]
fn confined_check_stage_fault_retains_its_site_and_restart_never_respawns() {
    // T4 staging-time fault: a missing archive refuses at dep.cache_missing,
    // the terminal row for that seam survives the attempt-root cleanup,
    // and RE-RUNNING the same admission never reaches staging again —
    // the consumed pair refuses the restart typed at admit.dep.
    ensure_helper();
    let (_, dep_name, dep_version, dep_checksum) = cfg_if_identity();
    let (registry_dir, _, _) = registry_layout();
    // A tag distinct from the fixture's: TempTree paths key on pid and
    // tag alone, so a shared tag would let the fixture's tree erase the
    // populated fake home.
    let holder = TempTree::new("confined-check", "stage-fault-registry");
    let cargo_home = holder.path.join("home");
    populate_fake_registry(&cargo_home, &dep_name, &dep_version, &dep_checksum);
    drop(std::fs::remove_file(
        cargo_home
            .join("registry/cache")
            .join(&registry_dir)
            .join(format!("{dep_name}-{dep_version}.crate")),
    ));
    let fixture = check_fixture("stage-fault", "ok", true);
    let mut world = support::open_world("confined-check-stage-fault", None);
    let session = world.open_session("confined-check-stage-fault");
    let task = world.create_task(&session, "stage-fault");
    let cargo = toolchain_cargo();
    let expected = workspace_digest(fixture.root()).expect("digest");
    let canonical_home = cargo_home.canonicalize().expect("canonical fake home");
    let revision = record_plan_selection(&mut world, &session, &task);
    let check = ConfinedCheck {
        task_id: task.clone(),
        expected_selection_revision: revision,
        project_grant_id: world
            .runtime
            .policy_writer()
            .grant_read(fixture.root().to_path_buf()),
        project_root: fixture.root().to_path_buf(),
        manifest_rel: PathBuf::from("Cargo.toml"),
        cargo: cargo.clone(),
        cargo_home: canonical_home,
        target: CheckTarget::Integration("check".to_string()),
        harness_threads: 1,
        exact_test: "green_passes".to_string(),
        expected_phase: "candidate-review".to_string(),
        expected_assertion_identity: "green_passes".to_string(),
        expected_candidate_digest: expected,
    };
    let exec_grant = world.runtime.policy_writer().grant_classes(
        cargo.parent().expect("toolchain dir").to_path_buf(),
        vec![EffectClass::Exec],
    );
    let handoff = world.runtime.check_handoff(&task);
    let mut admitted = {
        let mut executor = world.runtime.executor();
        executor
            .admit_check(
                &task,
                EffectRequest::Exec {
                    grant_id: exec_grant,
                    program: cargo,
                },
                PermissionMode::Yolo,
                &check,
                &handoff,
            )
            .expect("admission")
    };
    let runtime = &mut world.runtime;
    runtime
        .policy_writer()
        .issue_check_dependencies(&mut admitted)
        .expect("the sanctioned pair issues");
    let attempt_id = admitted.bound_attempt_id().to_string();
    let mut executor = world.runtime.executor();
    executor
        .execute_check(&mut admitted, &check, &AtomicBool::new(false))
        .expect_err("the missing archive refuses the stage");
    assert!(
        world
            .runtime
            .store()
            .has_retained(&check_boundary_id(&attempt_id, "dep.cache_missing"))
            .expect("retained lookup"),
        "the staging fault's terminal row survived the cleanup"
    );
    // Restart: the first-only claim already committed, so the second
    // presentation of the same admission refuses typed as a replay —
    // never a second staging or spawn.
    let mut executor = world.runtime.executor();
    let restart = executor.execute_check(&mut admitted, &check, &AtomicBool::new(false));
    assert_eq!(
        check_error_site(&restart),
        "admit.replay",
        "a restart after a settled staging fault refuses at the claim replay"
    );
}

#[test]
fn confined_check_vendor_failure_retains_the_result_site() {
    // T4 phase-A fault: a manifest cargo vendor rejects makes phase A
    // exit nonzero — the vendor.result seam retains its terminal row and
    // the typed refusal carries the bounded excerpt.
    ensure_helper();
    let fixture = check_fixture("vendor-fault", "ok", false);
    std::fs::write(
        fixture.root().join("Cargo.toml"),
        "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies\n",
    )
    .expect("broken manifest");
    let mut world = support::open_world("confined-check-vendor-fault", None);
    let session = world.open_session("confined-check-vendor-fault");
    let task = world.create_task(&session, "vendor-fault");
    let cargo = toolchain_cargo();
    let expected = workspace_digest(fixture.root()).expect("digest of the broken tree");
    let revision = record_plan_selection(&mut world, &session, &task);
    let check = ConfinedCheck {
        project_grant_id: world
            .runtime
            .policy_writer()
            .grant_read(fixture.root().to_path_buf()),
        ..base_check(&task, &fixture, cargo.clone(), expected, revision)
    };
    let exec_grant = world.runtime.policy_writer().grant_classes(
        check.cargo.parent().expect("toolchain").to_path_buf(),
        vec![EffectClass::Exec],
    );
    let handoff = world.runtime.check_handoff(&task);
    let mut admitted = {
        let mut executor = world.runtime.executor();
        executor
            .admit_check(
                &task,
                EffectRequest::Exec {
                    grant_id: exec_grant,
                    program: cargo,
                },
                PermissionMode::Yolo,
                &check,
                &handoff,
            )
            .expect("admission")
    };
    let attempt_id = admitted.bound_attempt_id().to_string();
    let mut executor = world.runtime.executor();
    let refused = executor
        .execute_check(&mut admitted, &check, &AtomicBool::new(false))
        .expect_err("the broken manifest fails the vendor phase");
    assert_eq!(check_error_site(&Err(refused)), "vendor.result");
    assert!(
        world
            .runtime
            .store()
            .has_retained(&check_boundary_id(&attempt_id, "vendor.result"))
            .expect("retained lookup"),
        "the vendor result fault's terminal row exists"
    );
}

#[test]
fn confined_check_pre_effect_retention_collision_preserves_the_root() {
    // B2: a hostile row already occupying this attempt's `pre.effect`
    // boundary makes the durable retention fail — the run refuses BEFORE
    // any spawn, the attempt root stays in place (the retention failure
    // deliberately never cleans it), and no close.confirmed row exists.
    ensure_helper();
    let fixture = check_fixture("collision", "ok", false);
    let mut world = support::open_world("confined-check-collision", None);
    let session = world.open_session("confined-check-collision");
    let task = world.create_task(&session, "collision");
    let cargo = toolchain_cargo();
    let expected = workspace_digest(fixture.root()).expect("digest");
    let revision = record_plan_selection(&mut world, &session, &task);
    let check = ConfinedCheck {
        project_grant_id: world
            .runtime
            .policy_writer()
            .grant_read(fixture.root().to_path_buf()),
        ..base_check(&task, &fixture, cargo.clone(), expected, revision)
    };
    let exec_grant = world.runtime.policy_writer().grant_classes(
        check.cargo.parent().expect("toolchain").to_path_buf(),
        vec![EffectClass::Exec],
    );
    let handoff = world.runtime.check_handoff(&task);
    let mut admitted = {
        let mut executor = world.runtime.executor();
        executor
            .admit_check(
                &task,
                EffectRequest::Exec {
                    grant_id: exec_grant,
                    program: cargo,
                },
                PermissionMode::Yolo,
                &check,
                &handoff,
            )
            .expect("admission before the hostile seed")
    };
    // The hostile pre-seed occupies the pre.effect boundary with a
    // different cause — the one-shot retention discipline must refuse.
    // A SECOND seed occupies the settle path's own terminal site
    // (evidence_retention_failed): without it the settle retains its
    // terminal row, rejects the attempt, and REMOVES the root — the
    // preservation claim below describes the early-return branch where
    // the terminal retention itself collides and the root is
    // deliberately left in place. Scanning the shared temp for any
    // matching root only ever passed by racing a sibling's live root;
    // the second seed makes this test's own root survive
    // deterministically.
    let attempt_id = admitted.bound_attempt_id().to_string();
    let hostile_cause = "hostile pre-seed";
    for site in ["pre.effect", "evidence_retention_failed"] {
        world
            .runtime
            .store_writer()
            .retain_attempt(&rivect::verification::RetainedAttempt {
                attempt_id: attempt_id.clone(),
                boundary_id: check_boundary_id(&attempt_id, site),
                stage: rivect::verification::RetainedStage::PreEffect,
                cause: hostile_cause.to_string(),
                digest: rivect::verification::record_digest(&attempt_id, hostile_cause),
                build_attempt: attempt_id.clone(),
                admitted_attempt_id: Some(attempt_id.clone()),
            })
            .expect("seed the hostile row");
    }
    let error = {
        let mut executor = world.runtime.executor();
        executor.execute_check(&mut admitted, &check, &AtomicBool::new(false))
    };
    let detail = match &error {
        Err(ExecutorError::Check(CheckError::EvidenceRetention { detail })) => detail.clone(),
        other => panic!("the pre-effect collision is a retention failure, got {other:?}"),
    };
    assert!(
        detail.contains("pre.effect"),
        "the retention failure names its site: {detail}"
    );
    assert!(
        !world
            .runtime
            .store()
            .has_retained(&check_boundary_id(&attempt_id, "close.confirmed"))
            .expect("retained lookup"),
        "no close.confirmed row follows a pre-effect retention failure"
    );
    // The retention failure leaves the attempt root in place: the root
    // name is the server-owned attempt id, so the exact path names this
    // attempt's root with no sibling race, and its rw carries no vendor
    // bytes (nothing ever ran).
    let preserved_root = std::env::temp_dir().join(format!("rivect-check-{attempt_id}"));
    assert!(
        std::fs::read_to_string(preserved_root.join("src/answer.txt"))
            .is_ok_and(|text| text == "ok"),
        "the preserved root holds the copied fixture"
    );
    assert!(
        preserved_root
            .join("rw")
            .join("vendor")
            .read_dir()
            .map(|entries| entries.count())
            .unwrap_or(0)
            == 0,
        "the preserved root carries no vendor bytes — no phase ever spawned"
    );
    // Restart (T4): re-running the same admission after the retention
    // failure meets the first-only claim marker — the typed claim
    // replay, never a silent second spawn.
    let mut executor = world.runtime.executor();
    let restart = executor.execute_check(&mut admitted, &check, &AtomicBool::new(false));
    assert_eq!(
        check_error_site(&restart),
        "admit.replay",
        "a restart after the pre-effect collision refuses at the claim replay"
    );
    assert!(
        !world
            .runtime
            .store()
            .has_retained(&check_boundary_id(&attempt_id, "close.confirmed"))
            .expect("retained lookup"),
        "the restart leaves no close.confirmed row either"
    );
}

#[test]
fn confined_check_refuses_hardlinks_special_files_and_oversized_workspaces_before_spawn() {
    ensure_helper();
    let mut world = support::open_world("confined-check-inventory", None);
    let session = world.open_session("confined-check-inventory");
    let task = world.create_task(&session, "inventory");

    // Each leg binds the candidate digest to the tree BEFORE the hostile
    // mutation: the harness cannot inventory a tree it built to be
    // refused — the executor's own walk must be the discriminator.
    //
    // A hard link inside the workspace refuses at snapshot.inventory.
    let fixture = check_fixture("inventory", "ok", false);
    let expected = workspace_digest(fixture.root()).expect("digest of the clean tree");
    std::fs::hard_link(
        fixture.root().join("Cargo.toml"),
        fixture.root().join("Cargo.toml.alias"),
    )
    .expect("hard link");
    let refused = run_confined_check_with_digest(
        &mut world,
        &session,
        &task,
        fixture.root(),
        expected,
        false,
        "green_passes",
    );
    assert_eq!(check_error_site(&refused), "snapshot.inventory");

    // A special file refuses the same way: a FIFO, which no SUN_LEN path
    // limit applies to.
    let mut fixture = check_fixture("inventory-special", "ok", false);
    let expected = workspace_digest(fixture.root()).expect("digest of the clean tree");
    let fifo = fixture.root().join("special.fifo");
    let mkfifo = std::process::Command::new("mkfifo").arg(&fifo).status();
    if mkfifo.is_err() {
        fixture.tree.retain();
    }
    let mkfifo = mkfifo.expect("mkfifo spawn");
    assert!(mkfifo.success(), "mkfifo creates the special file");
    let refused = run_confined_check_with_digest(
        &mut world,
        &session,
        &task,
        fixture.root(),
        expected,
        false,
        "green_passes",
    );
    assert_eq!(check_error_site(&refused), "snapshot.inventory");

    // An oversized file refuses before any spawn.
    let fixture = check_fixture("inventory-oversize", "ok", false);
    let expected = workspace_digest(fixture.root()).expect("digest of the clean tree");
    let big = std::fs::File::create(fixture.root().join("big.bin")).expect("big create");
    big.set_len(rivect::executor::INVENTORY_FILE_MAX_BYTES + 1)
        .expect("sparse oversize");
    drop(big);
    let refused = run_confined_check_with_digest(
        &mut world,
        &session,
        &task,
        fixture.root(),
        expected,
        false,
        "green_passes",
    );
    assert_eq!(check_error_site(&refused), "snapshot.inventory");
}

#[test]
fn confined_check_rejects_wrong_or_revoked_grants_before_spawn() {
    ensure_helper();
    let fixture = check_fixture("grants", "ok", false);
    let cargo = toolchain_cargo();
    let expected = workspace_digest(fixture.root()).expect("digest");

    // Wrong Exec program (a /usr/bin binary instead of the toolchain
    // cargo) refuses at admit.exec.
    let mut world = support::open_world("confined-check-grants", None);
    let session = world.open_session("confined-check-grants");
    let task = world.create_task(&session, "grants");
    let revision = record_plan_selection(&mut world, &session, &task);
    let exec_grant = world
        .runtime
        .policy_writer()
        .grant_classes(Path::new("/usr/bin").to_path_buf(), vec![EffectClass::Exec]);
    let check = base_check(&task, &fixture, cargo.clone(), expected.clone(), revision);
    let handoff = world.runtime.check_handoff(&task);
    let mut wrong_program = {
        let mut executor = world.runtime.executor();
        executor
            .admit_check(
                &task,
                EffectRequest::Exec {
                    grant_id: exec_grant,
                    program: PathBuf::from("/usr/bin/true"),
                },
                PermissionMode::Yolo,
                &check,
                &handoff,
            )
            .expect("admit the wrong program")
    };
    let error = {
        let mut executor = world.runtime.executor();
        executor.execute_check(&mut wrong_program, &check, &AtomicBool::new(false))
    };
    assert!(
        matches!(
            error,
            Err(ExecutorError::Check(CheckError::ExecGrant { .. }))
        ),
        "a wrong Exec program refuses at admit.exec, got {:?}",
        error.err()
    );

    // A revoked Exec grant: admit succeeds, the execute-time reconsult
    // refuses at admit.exec before any spawn.
    let exec_grant = world.runtime.policy_writer().grant_classes(
        cargo.parent().expect("toolchain").to_path_buf(),
        vec![EffectClass::Exec],
    );
    let revision = record_plan_selection(&mut world, &session, &task);
    let check = base_check(&task, &fixture, cargo.clone(), expected.clone(), revision);
    let handoff = world.runtime.check_handoff(&task);
    let mut admitted = {
        let mut executor = world.runtime.executor();
        executor
            .admit_check(
                &task,
                EffectRequest::Exec {
                    grant_id: exec_grant.clone(),
                    program: cargo.clone(),
                },
                PermissionMode::Yolo,
                &check,
                &handoff,
            )
            .expect("admit before the revocation lands at execute")
    };
    world.runtime.policy_writer().revoke(&exec_grant);
    let error = {
        let mut executor = world.runtime.executor();
        executor.execute_check(&mut admitted, &check, &AtomicBool::new(false))
    };
    assert!(
        matches!(
            &error,
            Err(ExecutorError::Check(CheckError::ExecGrant { .. }))
        ),
        "a revoked exec grant refuses at admit.exec, got {error:?}"
    );

    // A revoked project Read grant refuses at admit.read.
    let project_grant = world
        .runtime
        .policy_writer()
        .grant_read(fixture.root().to_path_buf());
    world.runtime.policy_writer().revoke(&project_grant);
    let revision = record_plan_selection(&mut world, &session, &task);
    let check = ConfinedCheck {
        project_grant_id: project_grant,
        ..base_check(&task, &fixture, cargo, expected, revision)
    };
    let error = {
        let exec_grant = world.runtime.policy_writer().grant_classes(
            check.cargo.parent().expect("toolchain").to_path_buf(),
            vec![EffectClass::Exec],
        );
        let handoff = world.runtime.check_handoff(&task);
        let mut executor = world.runtime.executor();
        let mut admitted = executor
            .admit_check(
                &task,
                EffectRequest::Exec {
                    grant_id: exec_grant,
                    program: check.cargo.clone(),
                },
                PermissionMode::Yolo,
                &check,
                &handoff,
            )
            .expect("admit");
        executor.execute_check(&mut admitted, &check, &AtomicBool::new(false))
    };
    assert!(
        matches!(
            &error,
            Err(ExecutorError::Check(CheckError::ProjectReadGrant { .. }))
        ),
        "a revoked project read grant refuses at admit.read, got {error:?}"
    );
}

/// Joins the ABA helper threads even when an assertion unwinds mid-test:
/// a leaked swapper would corrupt sibling fixtures' answers forever.
struct SwapGuard {
    stop: Arc<AtomicBool>,
    swapper: Option<std::thread::JoinHandle<bool>>,
    watcher: Option<std::thread::JoinHandle<Result<(), String>>>,
}

impl SwapGuard {
    /// The honest shutdown: stop, join, and hand the outcomes back for
    /// the assertions that make the test non-vacuous.
    fn finish(mut self) -> (bool, Result<(), String>) {
        self.stop.store(true, Ordering::Relaxed);
        let applied = self
            .swapper
            .take()
            .expect("swapper handle")
            .join()
            .expect("swapper thread joins");
        let watched = self
            .watcher
            .take()
            .expect("watcher handle")
            .join()
            .expect("watcher thread joins");
        (applied, watched)
    }
}

impl Drop for SwapGuard {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.swapper.take() {
            drop(handle.join());
        }
        if let Some(handle) = self.watcher.take() {
            drop(handle.join());
        }
    }
}

#[test]
fn confined_check_snapshot_resists_live_aba() {
    ensure_helper();
    let fixture = check_fixture("aba", "fail", false);
    let mut world = support::open_world("confined-check-aba", None);
    let session = world.open_session("confined-check-aba");
    let task = world.create_task(&session, "aba");
    // The run is bound to the recorded candidate digest of "fail" and the
    // executor copies the tree before any phase runs; an ABA swap of the
    // LIVE source after that copy must not change the run's outcome. The
    // handshake is copied → swap-applied → release: the watcher flags the
    // snapshot copy, the swapper applies one verified swap cycle and
    // holds the replacement through the phases, and only the observed
    // swap-applied acknowledgment releases the post-run assertions — a
    // run whose window never opened is a vacuous pass.
    // The marker sorts after every other root entry (`answer.txt`,
    // `Cargo.*`, `src`, `tests`) in the executor's sorted copy order, so
    // observing it copied proves `answer.txt` was already copied.
    let marker = format!(
        "zz-aba-marker-{}-{}.txt",
        std::process::id(),
        rivect::contracts::TaskId::generate().0
    );
    std::fs::write(fixture.root().join(&marker), b"bound").expect("write marker");
    let expected = workspace_digest(fixture.root()).expect("digest with marker");
    // The watcher scans for any check root of this process; the unique
    // snapshot marker inside `src` identifies OUR root — the root name
    // is the server-owned attempt id (uuid), no longer pid-prefixed.
    let root_prefix = "rivect-check-".to_string();
    let snapshot_marker = marker;
    let copied = Arc::new(AtomicBool::new(false));
    let stop = Arc::new(AtomicBool::new(false));
    // The watcher flags the copy; a timeout is an Err the test fails on,
    // never a silently discarded thread.
    let watcher = {
        let copied = copied.clone();
        let temp = std::env::temp_dir();
        std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
            while std::time::Instant::now() < deadline {
                let found = std::fs::read_dir(&temp)
                    .map(|entries| {
                        entries.filter_map(|entry| entry.ok()).any(|entry| {
                            entry
                                .file_name()
                                .to_string_lossy()
                                .starts_with(&root_prefix)
                                && entry.path().join("src").join(&snapshot_marker).is_file()
                        })
                    })
                    .unwrap_or(false);
                if found {
                    copied.store(true, Ordering::Relaxed);
                    return Ok(());
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            Err("the snapshot copy was never observed within the deadline".to_string())
        })
    };
    // ABA on the live source, strictly after the copy: each cycle writes
    // the replacement, HOLDS it while the phases consume, then restores.
    // The thread carries its own deadline, so a watcher timeout can never
    // leave it waiting forever on the copied flag.
    let answer = fixture.answer.clone();
    let swapper = {
        let stop = stop.clone();
        std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
            while !copied.load(Ordering::Relaxed) {
                if std::time::Instant::now() > deadline {
                    return false;
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            let mut applied = false;
            while !stop.load(Ordering::Relaxed) {
                let held = std::fs::write(&answer, "ok").is_ok()
                    && std::fs::read_to_string(&answer).is_ok_and(|text| text == "ok");
                applied |= held;
                // Hold the replacement through the phases' consumption.
                std::thread::sleep(std::time::Duration::from_millis(1));
                drop(std::fs::write(&answer, "fail"));
            }
            applied
        })
    };
    let guard = SwapGuard {
        stop,
        swapper: Some(swapper),
        watcher: Some(watcher),
    };
    let run = run_confined_check_with_digest(
        &mut world,
        &session,
        &task,
        fixture.root(),
        expected.clone(),
        false,
        "green_passes",
    )
    .expect("the ABA run completes on the copied candidate");
    let (applied, watched) = guard.finish();
    assert_eq!(watched, Ok(()), "the snapshot copy was observed");
    assert!(
        applied,
        "the live swap cycle verified itself applied while the phases ran"
    );
    assert_eq!(
        run.project_digest, expected,
        "the run proves exactly the candidate it bound"
    );
    fixture.set_answer("fail");
    assert_ne!(
        run.exit_code,
        Some(0),
        "the run observes the recorded candidate, not the live swap"
    );
    assert_eq!(
        std::fs::read_to_string(fixture.answer).expect("restored answer"),
        "fail"
    );
}

#[test]
fn confined_check_denies_project_writes_network_and_outside_reads() {
    ensure_helper();
    let toolchain = toolchain_cargo()
        .parent()
        .expect("toolchain dir")
        .to_path_buf();
    let mut root = TempTree::new("sandbox-macos", "denied-controls");
    let src = root.path.join("src");
    let rw = root.path.join("rw");
    let control = root.path.join("control");
    let control_bin = control.join("bin");
    std::fs::create_dir_all(&src).expect("src");
    std::fs::create_dir_all(&rw).expect("rw");
    std::fs::create_dir_all(&control_bin).expect("control bin");
    std::fs::write(src.join("sealed.txt"), b"sealed").expect("sealed file");
    // The read control targets a REGULAR secret beside its own probe
    // directory — the old directory target made /bin/cat fail EISDIR
    // whether or not the boundary denied.
    let secret = control.join("secret");
    std::fs::write(&secret, b"host-cache-secret").expect("secret");
    let deny = control.join("deny");
    let probe = compile_netprobe(&control_bin, &mut root);
    let profile = macos::check_control_profile(
        &macos::CheckProfile {
            toolchain,
            snapshot: src.clone(),
            rw,
            test_binaries: false,
        },
        &control_bin,
    )
    .expect("control profile");

    // Both probes prove themselves UNCONFINED first: a broken probe would
    // make every confined leg "succeed at failing".
    let read_ok = std::process::Command::new("/bin/cat").arg(&secret).output();
    if read_ok.is_err() {
        root.retain();
    }
    let read_ok = read_ok.expect("unconfined cat probe");
    assert!(
        read_ok.status.success() && read_ok.stdout == b"host-cache-secret",
        "the read probe works unconfined: {read_ok:?}"
    );
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("listener");
    let port = listener.local_addr().expect("addr").port();
    let connected = std::process::Command::new(&probe)
        .arg(port.to_string())
        .output();
    if connected.is_err() {
        root.retain();
    }
    let connected = connected.expect("unconfined network probe");
    assert!(
        connected.status.success(),
        "the compiled network probe connects unconfined: {}",
        String::from_utf8_lossy(&connected.stderr)
    );

    // Write outside rw denied with its own cause and target.
    let denied = confined(
        &profile,
        Path::new("/bin/sh"),
        &[
            std::ffi::OsStr::new("-c"),
            std::ffi::OsStr::new(&format!("echo x > {}", deny.display())),
        ],
    )
    .expect("confined write control run");
    assert!(!denied.exit_ok, "a write outside rw is denied: {denied:?}");
    assert!(
        denied.stderr.contains("Operation not permitted"),
        "the write denial is the OS boundary's: {denied:?}"
    );
    assert!(!deny.exists(), "the denied write target was never created");
    assert_eq!(
        std::fs::read(src.join("sealed.txt")).expect("sealed file intact"),
        b"sealed"
    );

    // A write INTO the sealed snapshot itself is denied the same way:
    // the snapshot keeps a read-only allowance, so even its own path
    // cannot mutate the sealed candidate (T8 — the write leg used to
    // target only paths outside every root).
    let denied = confined(
        &profile,
        Path::new("/bin/sh"),
        &[
            std::ffi::OsStr::new("-c"),
            std::ffi::OsStr::new(&format!("echo x > {}", src.join("sealed.txt").display())),
        ],
    )
    .expect("confined snapshot write control run");
    assert!(
        !denied.exit_ok,
        "a write into the sealed snapshot is denied: {denied:?}"
    );
    assert!(
        denied.stderr.contains("Operation not permitted"),
        "the snapshot write denial is the OS boundary's: {denied:?}"
    );
    assert_eq!(
        std::fs::read(src.join("sealed.txt")).expect("sealed bytes unchanged"),
        b"sealed",
        "the sealed snapshot's bytes are unchanged — its digest cannot have moved"
    );

    // Network denied: the compiled socket+connect pair a shell cannot
    // express, refused by the boundary with the probe's own operation.
    let denied = confined(&profile, &probe, &[std::ffi::OsStr::new(&port.to_string())])
        .expect("confined network control run");
    assert!(!denied.exit_ok, "a network connect is denied: {denied:?}");
    assert!(
        denied.stderr.contains("Operation not permitted"),
        "the network denial is the OS boundary's: {denied:?}"
    );
    assert!(
        denied.stderr.contains("socket") || denied.stderr.contains("connect"),
        "the network denial names its own operation: {denied:?}"
    );

    // Read outside the roots denied: the regular secret under the control
    // DATA directory, which keeps no read allowance.
    let denied = confined(&profile, Path::new("/bin/cat"), &[secret.as_os_str()])
        .expect("confined read control run");
    assert!(!denied.exit_ok, "an outside read is denied: {denied:?}");
    assert!(
        denied.stderr.contains("Operation not permitted"),
        "the read denial is the OS boundary's: {denied:?}"
    );
}

#[test]
fn non_enforcing_mechanism_fails_the_denied_controls_first() {
    // `/usr/bin/true` as the "sandbox" launcher admits every control leg:
    // the control set discriminates a non-enforcing mechanism, and the
    // executor refuses to run a real phase when one admits.
    ensure_helper();
    let toolchain = toolchain_cargo()
        .parent()
        .expect("toolchain dir")
        .to_path_buf();
    let attempt_owner =
        tempfile::TempDir::with_prefix("rivect-control-proof-").expect("control proof root");
    let attempt_root = attempt_owner.path().to_path_buf();
    std::fs::create_dir_all(attempt_root.join("src")).expect("src");
    std::fs::create_dir_all(attempt_root.join("rw")).expect("rw");
    let control_bin = attempt_root.join("control").join("bin");
    std::fs::create_dir_all(&control_bin).expect("control bin");
    let profile = macos::check_control_profile(
        &macos::CheckProfile {
            toolchain,
            snapshot: attempt_root.join("src"),
            rw: attempt_root.join("rw"),
            test_binaries: false,
        },
        &control_bin,
    )
    .expect("control profile");
    // `/usr/bin/true` as the launcher never confines: it exits 0 without
    // running the control, so the denied-write control leg ADMITS — the
    // discriminator `run_check_controls` fails closed on.
    let admitted = macos::run_confined(
        Path::new("/usr/bin/true"),
        &profile,
        Path::new("/bin/sh"),
        &[
            std::ffi::OsStr::new("-c"),
            std::ffi::OsStr::new(&format!(
                "echo x > {}",
                attempt_root.join("outside-deny").display()
            )),
        ],
    )
    .expect("the non-enforcing control run itself");
    assert!(
        admitted.exit_ok,
        "a non-enforcing mechanism admits the denied control: {admitted:?}"
    );
    drop(std::fs::remove_file(attempt_root.join("outside-deny")));
}

/// Restores the thread's helper-binary override even when an assertion
/// unwinds: a leaked override would poison every sibling test's helper
/// resolution.
struct HelperOverrideGuard;

impl HelperOverrideGuard {
    fn install(shim: PathBuf) -> Self {
        rivect_sandbox_helper::override_helper_binary(Some(shim));
        HelperOverrideGuard
    }
}

impl Drop for HelperOverrideGuard {
    fn drop(&mut self) {
        rivect_sandbox_helper::override_helper_binary(None);
    }
}

#[test]
fn exec_denied_but_read_allowed_control_fails_typed_at_the_read_leg() {
    // The CR probe as an injection (P1): a mechanism whose EXEC is
    // denied while reads stay allowed makes the read control exit
    // nonzero naming cat with a permission wording and ZERO read
    // attempts — the exact shape the old predicate accepted as a read
    // denial. The fake helper plays that mechanism: every launch dies
    // with sandbox-exec's execvp wording, so the control set must
    // refuse the run typed AT THE READ LEG for its exec cause, never
    // pass the read leg and surface at a later one.
    ensure_helper();
    let shim_tree = TempTree::new("sandbox-macos", "exec-denied-helper");
    let shim = shim_tree.path.join("rivect-exec-denied-helper");
    std::fs::write(
        &shim,
        concat!(
            "#!/bin/sh\n",
            "echo \"sandbox-exec: execvp() of '/bin/cat' failed: Operation not permitted\" >&2\n",
            "exit 71\n",
        ),
    )
    .expect("write the exec-denied helper shim");
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755))
            .expect("chmod the exec-denied helper shim");
    }
    let fixture = check_fixture("exec-denied", "ok", false);
    let mut world = support::open_world("confined-check-exec-denied", None);
    let session = world.open_session("confined-check-exec-denied");
    let task = world.create_task(&session, "exec-denied");
    let _guard = HelperOverrideGuard::install(shim);
    let refused = run_confined_check(
        &mut world,
        &session,
        &task,
        fixture.root(),
        false,
        "green_passes",
    );
    let detail = match &refused {
        Err(ExecutorError::Check(CheckError::VendorSetup { detail })) => detail.clone(),
        other => panic!("the exec-denied control set is a typed setup refusal, got {other:?}"),
    };
    assert!(
        detail.contains("read control") && detail.contains("exec failure"),
        "the refusal names the READ leg's exec-failure cause, got {detail:?}"
    );
}

#[test]
fn toolchain_and_root_layout_refused_before_spawn() {
    ensure_helper();
    let fixture = check_fixture("layout", "ok", false);
    let mut world = support::open_world("confined-check-layout", None);
    let session = world.open_session("confined-check-layout");
    let task = world.create_task(&session, "layout");

    // A non-toolchain cargo (no sibling rustc — the rustup proxy layout)
    // refuses at admit.target. The proxy dir is always synthesized: a
    // real rustup shim directory DOES carry a rustc shim beside cargo,
    // so it is not the layout this seam names.
    let holder = TempTree::new("confined-check", "proxy-layout");
    let dir = holder.path.join("bin");
    std::fs::create_dir_all(&dir).expect("proxy bin");
    std::fs::copy(toolchain_cargo(), dir.join("cargo")).expect("proxy copy");
    use std::os::unix::fs::PermissionsExt as _;
    drop(std::fs::set_permissions(
        dir.join("cargo"),
        std::fs::Permissions::from_mode(0o755),
    ));
    let proxy = dir.join("cargo");
    let cargo = proxy.canonicalize().expect("canonical proxy");
    let expected = workspace_digest(fixture.root()).expect("digest");
    // A valid project Read grant: `admit.read` precedes the target-layout
    // seam, so the proxy layout must pass every earlier admission check.
    let revision = record_plan_selection(&mut world, &session, &task);
    let check = ConfinedCheck {
        project_grant_id: world
            .runtime
            .policy_writer()
            .grant_read(fixture.root().to_path_buf()),
        ..base_check(&task, &fixture, cargo, expected, revision)
    };
    let error = {
        let exec_grant = world.runtime.policy_writer().grant_classes(
            check.cargo.parent().expect("dir").to_path_buf(),
            vec![EffectClass::Exec],
        );
        let handoff = world.runtime.check_handoff(&task);
        let mut executor = world.runtime.executor();
        let mut admitted = executor
            .admit_check(
                &task,
                EffectRequest::Exec {
                    grant_id: exec_grant,
                    program: check.cargo.clone(),
                },
                PermissionMode::Yolo,
                &check,
                &handoff,
            )
            .expect("admit");
        executor.execute_check(&mut admitted, &check, &AtomicBool::new(false))
    };
    assert!(
        matches!(
            &error,
            Err(ExecutorError::Check(CheckError::TargetLayout { .. }))
        ),
        "the rustup proxy layout refuses at admit.target, got {error:?}"
    );
}

#[test]
fn confined_check_allows_linker_but_denies_unrelated_system_exec() {
    ensure_helper();
    let toolchain = toolchain_cargo()
        .parent()
        .expect("toolchain dir")
        .to_path_buf();
    let attempt_owner =
        tempfile::TempDir::with_prefix("rivect-control-proof-").expect("control proof root");
    let attempt_root = attempt_owner.path().to_path_buf();
    std::fs::create_dir_all(attempt_root.join("src")).expect("src");
    std::fs::create_dir_all(attempt_root.join("rw")).expect("rw");
    let control_bin = attempt_root.join("control").join("bin");
    std::fs::create_dir_all(&control_bin).expect("control bin");
    let profile = macos::check_control_profile(
        &macos::CheckProfile {
            toolchain,
            snapshot: attempt_root.join("src"),
            rw: attempt_root.join("rw"),
            test_binaries: false,
        },
        &control_bin,
    )
    .expect("control profile");
    let denied = confined(&profile, Path::new("/usr/bin/true"), &[])
        .expect("confined unrelated-exec control run");
    assert!(
        !denied.exit_ok,
        "an unrelated system binary is denied execution: {denied:?}"
    );
    assert!(
        denied.stderr.contains("Operation not permitted"),
        "the denial is the OS boundary's, not the binary's own exit: {denied:?}"
    );
    // The finite linker set only: an Xcode tool from the very developer
    // tree the profile READS (git, beside the resolved clang) must stay
    // denied — the old whole-tree exec allowance made it executable
    // (CR-I4).
    if let Some(linker) = macos::check_linker_toolchain() {
        let xcode_tool = linker.developer.join("usr/bin/git");
        if xcode_tool.is_file() {
            let denied = confined(&profile, &xcode_tool, &[std::ffi::OsStr::new("--version")])
                .expect("confined xcode-tool exec control run");
            assert!(
                !denied.exit_ok,
                "an Xcode tool outside the linker set is denied execution: {denied:?}"
            );
        }
    }
    // The production linker executes: cargo pins the real clang the
    // resolved developer tree holds — the /usr/bin/cc/ld shims shell out
    // to xcrun, whose cache writes outside rw are correctly denied.
    let linker = macos::check_linker_toolchain()
        .map(|resolved| resolved.clang)
        .or_else(|| {
            macos::check_linker_literals()
                .into_iter()
                .find(|literal| literal.contains("/ld"))
                .map(|literal| PathBuf::from(literal.replace("\\\"", "\"")))
        })
        .expect("a resolved platform linker");
    let linker = linker.canonicalize().unwrap_or(linker);
    let allowed = confined(&profile, &linker, &[std::ffi::OsStr::new("--version")])
        .expect("confined linker run");
    assert!(
        allowed.exit_ok,
        "the canonical linker is executable inside the check boundary: {allowed:?}"
    );
}

/// Finds a live survivor's pid in the process table: the re-exec'd leg's
/// argv carries its unique libtest filter, and the outer harness's own
/// argv never does (T11 transport 2).
fn survivor_pid_from_table() -> Option<String> {
    let table = std::process::Command::new("ps")
        .args(["-eo", "pid=,command="])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&table.stdout);
    text.lines()
        .filter(|line| line.contains("survivor_sleeps"))
        .find(|line| !line.contains("cargo test") && !line.contains("deps/sandbox_macos"))
        .and_then(|line| line.split_whitespace().next().map(str::to_string))
}

#[test]
fn macos_check_records_setsid_survivor_without_false_cleanup() {
    ensure_helper();
    let fixture = check_fixture("survivor", "ok", false);
    // Both halves live in the `check` target the run actually executes
    // (`--test check --exact spawns_the_survivor`): the discriminator
    // spawns this binary re-exec'd ASYNC in its own process group — the
    // setpgid escape the check's killpg cannot reach — echoes the pid,
    // and returns while the survivor still sleeps; the ignored
    // `survivor_sleeps` leg writes its witness IMMEDIATELY (the cleanup
    // race removes the attempt root before the sleep ends, so a late
    // write would only ever see ENOENT) and then sleeps past the run.
    std::fs::write(
        fixture.root().join("tests/check.rs"),
        concat!(
            "#[test]\n",
            "fn spawns_the_survivor() {\n",
            "    use std::os::unix::process::CommandExt as _;\n",
            "    let exe = std::env::current_exe().expect(\"current exe\");\n",
            "    let survivor = std::process::Command::new(exe)\n",
            "        .arg(\"survivor_sleeps\")\n",
            "        .arg(\"--ignored\")\n",
            "        .arg(\"--exact\")\n",
            "        .arg(\"--test-threads=1\")\n",
            "        .stdin(std::process::Stdio::null())\n",
            "        .stdout(std::process::Stdio::null())\n",
            "        .stderr(std::process::Stdio::null())\n",
            "        .process_group(0)\n",
            "        .spawn()\n",
            "        .expect(\"spawn survivor\");\n",
            "    drop(survivor);\n",
            "}\n\n",
            "#[test]\n",
            "#[ignore = \"re-exec'd survivor leg: sleeps past the check's cleanup\"]\n",
            "fn survivor_sleeps() {\n",
            "    let witness = std::env::var(\"TMPDIR\")\n",
            "        .map(std::path::PathBuf::from)\n",
            "        .unwrap_or_else(|_| std::env::temp_dir());\n",
            "    // libtest captures a passing test's stdout, so the pid\n",
            "    // travels as a witness FILE. The witness is REWRITTEN in a\n",
            "    // bounded loop instead of written once (TA T11): a single\n",
            "    // write could land after a slow start only to be cleaned\n",
            "    // away before the outer watcher looked — under load the\n",
            "    // re-exec's startup outran the phase tail once and the\n",
            "    // watcher burned its whole deadline. The rw subpath keeps\n",
            "    // its write allowance after cleanup removes the root, so\n",
            "    // recreating the directory reopens the delivery window; the\n",
            "    // loop ends when the path stops being creatable or the\n",
            "    // bound passes, and no exact scheduling is required.\n",
            "    let pid = std::process::id().to_string();\n",
            "    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(45);\n",
            "    while std::time::Instant::now() < deadline {\n",
            "        if std::fs::write(witness.join(\"survivor.pid\"), &pid).is_err() {\n",
            "            drop(std::fs::create_dir_all(&witness));\n",
            "        }\n",
            "        drop(std::fs::write(witness.join(\"survivor-witness\"), b\"alive\"));\n",
            "        std::thread::sleep(std::time::Duration::from_millis(50));\n",
            "    }\n",
            "    std::thread::sleep(std::time::Duration::from_secs(2));\n",
            "}\n",
        ),
    )
    .expect("check.rs survivor legs");
    let mut world = support::open_world("confined-check-survivor", None);
    let session = world.open_session("confined-check-survivor");
    let task = world.create_task(&session, "survivor");
    // The survivor is still alive AFTER the executor returned: the
    // setpgid escape outlived the check's killpg and root cleanup. The
    // pid travels as a witness file the watcher reads while the attempt
    // root still exists (libtest captures a passing test's stdout).
    // The root name is the server-owned attempt id (uuid), no longer
    // pid-prefixed; the survivor witness file inside rw/tmp identifies
    // OUR root.
    let root_prefix = "rivect-check-".to_string();
    let seen_pid = Arc::new(std::sync::Mutex::new(None));
    let watcher = {
        let seen_pid = seen_pid.clone();
        std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
            while std::time::Instant::now() < deadline {
                // Transport 1: the witness file the survivor rewrites in
                // its bounded loop (T11).
                let from_file = std::fs::read_dir(std::env::temp_dir())
                    .ok()
                    .and_then(|entries| {
                        entries.filter_map(|entry| entry.ok()).find_map(|entry| {
                            if !entry
                                .file_name()
                                .to_string_lossy()
                                .starts_with(&root_prefix)
                            {
                                return None;
                            }
                            let pid = entry.path().join("rw/tmp/survivor.pid");
                            std::fs::read_to_string(&pid).ok()
                        })
                    });
                if let Some(pid) = from_file {
                    *seen_pid.lock().expect("pid lock") = Some(pid);
                    return;
                }
                // Transport 2: the process table. The survivor's argv
                // carries its unique libtest filter, so a live survivor
                // is findable regardless of when its first writable
                // window opens — the Linux twin's probe shape.
                if let Some(pid) = survivor_pid_from_table() {
                    *seen_pid.lock().expect("pid lock") = Some(pid);
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        })
    };
    let run = run_confined_check(
        &mut world,
        &session,
        &task,
        fixture.root(),
        false,
        "spawns_the_survivor",
    )
    .expect("the survivor fixture passes");
    let survived_stderr = String::from_utf8_lossy(&run.stderr.tail);
    assert_eq!(
        run.exit_code,
        Some(0),
        "the survivor fixture must pass; stderr tail: {survived_stderr}"
    );
    // The name echo proves a POSITIVE selected-test count: cargo ran the
    // discriminator itself, not an empty filter over absent targets.
    let stdout = String::from_utf8_lossy(&run.stdout.head);
    assert!(
        stdout.contains("spawns_the_survivor"),
        "the executed discriminator is named in the output: {stdout}"
    );
    let summary = run.summary.as_deref().unwrap_or_default();
    assert!(
        summary.contains("1 passed; 0 failed"),
        "exactly one test was selected and passed: {summary}"
    );
    watcher.join().expect("watcher joins");
    let pid = seen_pid
        .lock()
        .expect("pid lock")
        .as_deref()
        .and_then(|pid| pid.trim().parse::<i32>().ok())
        .expect("the survivor's pid witness was observed mid-run");
    assert!(pid > 0, "a real pid was witnessed: {pid}");
    let alive = pid_alive(pid);
    assert!(
        alive,
        "the survivor outlived the executor's cleanup (kill -0 pid={pid})"
    );
    // Reap explicitly: the survivor is not our child, so signal it and
    // wait for the pid to leave. A false "cleaned up" claim is exactly
    // what DEC-041 forbids — the claim below never asserts it.
    let killed = std::process::Command::new("/bin/kill")
        .args(["-9", &pid.to_string()])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("kill the survivor");
    assert!(killed.success(), "the survivor reap signal was delivered");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while pid_alive(pid) && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(!pid_alive(pid), "the reaped survivor pid is gone");
    assert_eq!(
        run.cleanup,
        CleanupClaim::MacosBestEffort,
        "the claim never asserts full macOS cleanup"
    );
    assert!(
        run.attempt_root.is_some(),
        "DEC-047: transport success keeps the attempt root present for the \
        journey disposition — only the survivor escaped the stop"
    );
}

/// `kill -0` liveness probe: the pid exists and is signalable. The outer
/// test binary runs unconfined, so it may signal the survivor.
fn pid_alive(pid: i32) -> bool {
    std::process::Command::new("/bin/kill")
        .args(["-0", &pid.to_string()])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// The decoded non-authoritative pre-claim denial rows of this world's
/// store (DEC-048 item 6) as `(boundary_id, record)` in boundary order,
/// read through a separate read-only connection so the owner's writer is
/// never touched.
fn rejection_rows(world: &support::World) -> Vec<(String, serde_json::Value)> {
    let db = world.runtime.owner().runtime_dir().join("rivect.db");
    let conn =
        rusqlite::Connection::open_with_flags(&db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("read-only store connection");
    let mut statement = conn
        .prepare(
            "SELECT boundary_id, record_json FROM retained
             WHERE boundary_id LIKE 'ret:check-rejection:%' ORDER BY boundary_id",
        )
        .expect("prepare the denial read");
    statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .expect("query the denial rows")
        .map(|row| {
            let (boundary, json) = row.expect("denial row");
            (
                boundary,
                serde_json::from_str(&json).expect("decoded record"),
            )
        })
        .collect()
}

/// The approved pre-claim refusal contract (DEC-048 items 6-7): one
/// invocation-scoped UUID denial row naming only the fixed site, cause,
/// and binding digest; the admission spent; the legitimate attempt still
/// planned; no attempt-keyed terminal, marker, root, or cleanup row.
fn assert_preclaim_denial(
    world: &support::World,
    admission: &rivect::executor::CheckAdmission,
    before: &[(String, serde_json::Value)],
    site: &str,
) {
    let attempt_id = admission.bound_attempt_id();
    assert_eq!(
        admission.phase(),
        rivect::executor::CheckPhase::Spent,
        "the refusal spends its own admission"
    );
    assert_eq!(
        world
            .runtime
            .store()
            .attempt_state(attempt_id)
            .expect("attempt state lookup")
            .as_deref(),
        Some("planned"),
        "the legitimate attempt stays planned, never rejected"
    );
    for attempt_site in [
        site,
        "admit.claim",
        "admit.claim_commit",
        "pre.effect",
        "cleanup.root",
    ] {
        assert!(
            !world
                .runtime
                .store()
                .has_retained(&check_boundary_id(attempt_id, attempt_site))
                .expect("retained lookup"),
            "no attempt-keyed {attempt_site} row exists"
        );
    }
    assert!(
        !rivect::executor::attempt_root_of(attempt_id).exists(),
        "no attempt root exists for the refused presentation"
    );
    let after = rejection_rows(world);
    let added: Vec<_> = after.iter().filter(|row| !before.contains(row)).collect();
    assert_eq!(
        added.len(),
        1,
        "exactly one invocation-scoped denial row lands: {added:?}"
    );
    let (boundary, record) = added[0];
    let suffix = format!(":{site}");
    let identity = boundary
        .strip_prefix("ret:check-rejection:")
        .and_then(|rest| rest.strip_suffix(suffix.as_str()))
        .expect("the boundary names the refusing site");
    assert!(
        uuid::Uuid::parse_str(identity).is_ok(),
        "the rejection identity is a UUID, never the attempt id: {boundary}"
    );
    assert!(
        !boundary.contains(attempt_id) && !record.to_string().contains(attempt_id),
        "no forged admitted-attempt relation: {boundary} {record}"
    );
    assert_eq!(record["site"], site);
    assert_eq!(record["cause"], "pre-claim refusal");
    assert!(
        record["binding"]
            .as_str()
            .is_some_and(|digest| !digest.is_empty()),
        "the record carries the binding digest: {record}"
    );
    assert_eq!(
        record.as_object().map(serde_json::Map::len),
        Some(3),
        "the record holds only the fixed site, cause, and binding: {record}"
    );
}

#[test]
fn confined_check_failure_seams_survive_cleanup_without_collision() {
    ensure_helper();
    let fixture = check_fixture("seams", "ok", false);
    let mut world = support::open_world("confined-check-seams", None);
    let session = world.open_session("confined-check-seams");
    let task = world.create_task(&session, "seams");
    let cargo = toolchain_cargo();
    let expected = workspace_digest(fixture.root()).expect("digest");

    // Fault 1: a revoked Exec grant refuses before the claim. The
    // refusal is the invocation-scoped denial plus the release of its
    // OWN admission; a bystander minted over the same task keeps its
    // own allocation and stays Pending.
    let exec_grant = world.runtime.policy_writer().grant_classes(
        cargo.parent().expect("toolchain").to_path_buf(),
        vec![EffectClass::Exec],
    );
    let bystander_exec = world.runtime.policy_writer().grant_classes(
        cargo.parent().expect("toolchain").to_path_buf(),
        vec![EffectClass::Exec],
    );
    let revision = record_plan_selection(&mut world, &session, &task);
    let mut check = base_check(&task, &fixture, cargo.clone(), expected, revision);
    check.project_grant_id = world
        .runtime
        .policy_writer()
        .grant_read(fixture.root().to_path_buf());
    let handoff = world.runtime.check_handoff(&task);
    let (mut admitted, mut bystander) = {
        let mut executor = world.runtime.executor();
        let first = executor
            .admit_check(
                &task,
                EffectRequest::Exec {
                    grant_id: exec_grant.clone(),
                    program: cargo.clone(),
                },
                PermissionMode::Yolo,
                &check,
                &handoff,
            )
            .expect("admit");
        let second = executor
            .admit_check(
                &task,
                EffectRequest::Exec {
                    grant_id: bystander_exec,
                    program: cargo.clone(),
                },
                PermissionMode::Yolo,
                &check,
                &handoff,
            )
            .expect("admit the bystander");
        (first, second)
    };
    world.runtime.policy_writer().revoke(&exec_grant);
    let before = rejection_rows(&world);
    let error = {
        let mut executor = world.runtime.executor();
        executor.execute_check(&mut admitted, &check, &AtomicBool::new(false))
    };
    let attempt_id = admitted.bound_attempt_id().to_string();
    assert!(
        matches!(
            &error,
            Err(ExecutorError::Check(CheckError::ExecGrant { .. }))
        ),
        "the revoked exec grant fails typed: {error:?}"
    );
    assert_preclaim_denial(&world, &admitted, &before, "admit.exec");
    assert_eq!(
        bystander.phase(),
        rivect::executor::CheckPhase::Pending,
        "an unrelated allocation is never disposed by the refusal"
    );

    // The bystander still presents: it reaches its own pre-claim
    // cancellation, proving its binding and owner context stayed live.
    let live = {
        let mut executor = world.runtime.executor();
        executor.execute_check(&mut bystander, &check, &AtomicBool::new(true))
    };
    assert!(
        matches!(
            &live,
            Err(ExecutorError::Check(CheckError::VendorCancel { .. }))
        ),
        "the bystander is still a live admission: {live:?}"
    );

    // Fault 2 on a different seam proves the sites never alias: a
    // revoked project Read grant keeps its own `admit.read` denial row.
    let fixture2 = check_fixture("seams-2", "ok", false);
    let expected2 = workspace_digest(fixture2.root()).expect("digest");
    let project_grant = world
        .runtime
        .policy_writer()
        .grant_read(fixture2.root().to_path_buf());
    world.runtime.policy_writer().revoke(&project_grant);
    let revision = record_plan_selection(&mut world, &session, &task);
    let check2 = ConfinedCheck {
        project_grant_id: project_grant,
        ..base_check(&task, &fixture2, cargo, expected2, revision)
    };
    let before2 = rejection_rows(&world);
    let (admitted2, outcome2) = {
        let exec_grant = world.runtime.policy_writer().grant_classes(
            check2.cargo.parent().expect("toolchain").to_path_buf(),
            vec![EffectClass::Exec],
        );
        let handoff = world.runtime.check_handoff(&task);
        let mut executor = world.runtime.executor();
        let mut admitted2 = executor
            .admit_check(
                &task,
                EffectRequest::Exec {
                    grant_id: exec_grant,
                    program: check2.cargo.clone(),
                },
                PermissionMode::Yolo,
                &check2,
                &handoff,
            )
            .expect("admit 2");
        let outcome = executor.execute_check(&mut admitted2, &check2, &AtomicBool::new(false));
        (admitted2, outcome)
    };
    assert!(
        matches!(
            &outcome2,
            Err(ExecutorError::Check(CheckError::ProjectReadGrant { .. }))
        ),
        "the second fault keeps its own seam: {outcome2:?}"
    );
    assert_preclaim_denial(&world, &admitted2, &before2, "admit.read");
    assert_ne!(
        attempt_id,
        admitted2.bound_attempt_id(),
        "the attempts are distinct"
    );
    let all = rejection_rows(&world);
    assert_eq!(
        all.len(),
        before.len() + 3,
        "three distinct refusals wrote three distinct denial rows: {all:?}"
    );
}

// ----- helpers ------------------------------------------------------------

fn base_check(
    task: &rivect::contracts::TaskId,
    fixture: &CheckFixture,
    cargo: PathBuf,
    expected: String,
    revision: u64,
) -> ConfinedCheck {
    ConfinedCheck {
        task_id: task.clone(),
        expected_selection_revision: revision,
        project_grant_id: String::new(),
        project_root: fixture.root().to_path_buf(),
        manifest_rel: PathBuf::from("Cargo.toml"),
        cargo,
        cargo_home: host_cargo_home(),
        target: CheckTarget::Integration("check".to_string()),
        harness_threads: 1,
        exact_test: "green_passes".to_string(),
        expected_phase: "candidate-review".to_string(),
        expected_assertion_identity: "green_passes".to_string(),
        expected_candidate_digest: expected,
    }
}

/// Admits inline through the sanctioned issuer, issues the optional
/// dependency pair from the admission binding, then runs the check and
/// returns the expected typed failure.
fn direct_execute_check(
    world: &mut support::World,
    session: &SessionId,
    task: &rivect::contracts::TaskId,
    mut check: ConfinedCheck,
    dependencies: bool,
) -> ExecutorError {
    check.expected_selection_revision = record_plan_selection(world, session, task);
    let exec_grant = world.runtime.policy_writer().grant_classes(
        check.cargo.parent().expect("toolchain").to_path_buf(),
        vec![EffectClass::Exec],
    );
    let cargo = check.cargo.clone();
    let handoff = world.runtime.check_handoff(task);
    let mut admission = {
        let mut executor = world.runtime.executor();
        executor
            .admit_check(
                task,
                EffectRequest::Exec {
                    grant_id: exec_grant,
                    program: cargo,
                },
                PermissionMode::Yolo,
                &check,
                &handoff,
            )
            .expect("admission")
    };
    if dependencies {
        let runtime = &mut world.runtime;
        runtime
            .policy_writer()
            .issue_check_dependencies(&mut admission)
            .expect("the sanctioned dependency pair issues");
    }
    let mut executor = world.runtime.executor();
    executor
        .execute_check(&mut admission, &check, &AtomicBool::new(false))
        .expect_err("the direct leg expects a typed failure")
}

fn run_confined_check_on_home(
    world: &mut support::World,
    session: &SessionId,
    task: &rivect::contracts::TaskId,
    fixture_root: &Path,
    cargo_home: PathBuf,
    dependencies: bool,
) -> Result<CheckRun, ExecutorError> {
    let expected = workspace_digest(fixture_root).expect("workspace digest");
    run_confined_check_on_home_with_digest(
        world,
        session,
        task,
        fixture_root,
        cargo_home,
        expected,
        dependencies,
        "green_passes",
    )
}

/// The one inline run helper: mints the opaque issuer-bound admission,
/// optionally issues the sanctioned dependency pair from its binding,
/// and executes the check through the real executor.
#[allow(
    clippy::too_many_arguments,
    reason = "mirror of the executor check shape"
)]
fn run_confined_check_on_home_with_digest(
    world: &mut support::World,
    session: &SessionId,
    task: &rivect::contracts::TaskId,
    fixture_root: &Path,
    cargo_home: PathBuf,
    expected: String,
    dependencies: bool,
    exact_test: &str,
) -> Result<CheckRun, ExecutorError> {
    let revision = record_plan_selection(world, session, task);
    let cargo = toolchain_cargo();
    let project_grant_id = world
        .runtime
        .policy_writer()
        .grant_read(fixture_root.to_path_buf());
    let exec_grant = world.runtime.policy_writer().grant_classes(
        cargo.parent().expect("toolchain dir").to_path_buf(),
        vec![EffectClass::Exec],
    );
    let check = ConfinedCheck {
        task_id: task.clone(),
        expected_selection_revision: revision,
        project_grant_id,
        project_root: fixture_root.to_path_buf(),
        manifest_rel: PathBuf::from("Cargo.toml"),
        cargo: cargo.clone(),
        cargo_home,
        target: CheckTarget::Integration("check".to_string()),
        harness_threads: 1,
        exact_test: exact_test.to_string(),
        expected_phase: "candidate-review".to_string(),
        expected_assertion_identity: exact_test.to_string(),
        expected_candidate_digest: expected,
    };
    let handoff = world.runtime.check_handoff(task);
    let mut admission = {
        let mut executor = world.runtime.executor();
        executor.admit_check(
            task,
            EffectRequest::Exec {
                grant_id: exec_grant,
                program: cargo,
            },
            PermissionMode::Yolo,
            &check,
            &handoff,
        )?
    };
    if dependencies {
        let runtime = &mut world.runtime;
        runtime
            .policy_writer()
            .issue_check_dependencies(&mut admission)
            .expect("the sanctioned dependency pair issues");
    }
    let mut executor = world.runtime.executor();
    let cancel = AtomicBool::new(false);
    executor.execute_check(&mut admission, &check, &cancel)
}

/// EVID-478, DEC-047 recovery: the Runtime-open reconcile settles an
/// unresolved attempt exactly once and re-decides the cleanup for every
/// surviving root. Three crash windows (journey disposition, pre-return
/// finalisation, recovery row), restart idempotency, no replay, and no
/// fabricated `admit.claim_commit` — every durable row is preserved
/// byte-for-byte, and strict cleanup (DEC-056) refuses each present
/// root before any destructive effect: the debris survives, no
/// `cleanup.root` row lands, and the obligation stays pending.
#[test]
fn unresolved_attempt_is_recovered_then_cleaned_without_replay() {
    ensure_helper();
    let fixture = check_fixture("recovery", "ok", false);
    let world_root =
        tempfile::TempDir::with_prefix("rivect-confined-check-recovery-").expect("world root");
    let mut world = support::open_world_at(world_root.path(), None);
    let session = world.open_session("confined-check-recovery");
    let task = world.create_task(&session, "recovery");
    let attempt_of = |run: &CheckRun| -> String {
        let root = run.attempt_root.as_ref().expect("the root is retained");
        root.file_name()
            .expect("the root has a name")
            .to_string_lossy()
            .strip_prefix("rivect-check-")
            .expect("the root name is the attempt id")
            .to_string()
    };
    let retained_row =
        |attempt_id: &str, site: &str, cause: &str| rivect::verification::RetainedAttempt {
            attempt_id: attempt_id.to_string(),
            boundary_id: check_boundary_id(attempt_id, site),
            stage: rivect::verification::RetainedStage::Terminal,
            cause: cause.to_string(),
            digest: rivect::verification::record_digest(attempt_id, cause),
            build_attempt: attempt_id.to_string(),
            admitted_attempt_id: Some(attempt_id.to_string()),
        };

    // Crash window 3 — the recovery row: a real transport success, no
    // journey disposition, the process dies before any close.
    let unresolved = run_confined_check(
        &mut world,
        &session,
        &task,
        fixture.root(),
        false,
        "green_passes",
    )
    .expect("the unresolved window's run completes");
    let unresolved_id = attempt_of(&unresolved);
    let unresolved_root = unresolved.attempt_root.expect("retained root");
    assert!(
        unresolved_root.is_dir(),
        "the transport success leaves the root in place"
    );
    let pre_effect = world
        .runtime
        .store()
        .retained(&check_boundary_id(&unresolved_id, "pre.effect"))
        .expect("retained lookup");
    assert!(
        pre_effect.is_some(),
        "the durable pre-effect row precedes any recovery"
    );

    // Crash window 1 — journey disposition: a second real run, the
    // disposition row lands (the SLICE-024 shape), the crash precedes
    // the journey's disposition-gated cleanup.
    let journey_task = world.create_task(&session, "recovery-journey");
    let journey = run_confined_check(
        &mut world,
        &session,
        &journey_task,
        fixture.root(),
        false,
        "green_passes",
    )
    .expect("the journey window's run completes");
    let journey_id = attempt_of(&journey);
    let journey_root = journey.attempt_root.expect("retained root");
    let journey_row = retained_row(
        &journey_id,
        "close.phase_closed",
        "expected phase observed: red failed",
    );
    world
        .runtime
        .store_writer()
        .retain_attempt(&journey_row)
        .expect("the disposition row retains");

    // Crash window 2 — pre-return finalisation: a third real run leaves
    // its retained root; the transport row and the ledger rejection are
    // durable and the crash precedes the root removal.
    let finalised_task = world.create_task(&session, "recovery-finalised");
    let finalised = run_confined_check(
        &mut world,
        &session,
        &finalised_task,
        fixture.root(),
        false,
        "green_passes",
    )
    .expect("the finalised window's run completes");
    let finalised_id = attempt_of(&finalised);
    let finalised_root = finalised.attempt_root.expect("retained root");
    let finalised_row = retained_row(
        &finalised_id,
        "vendor.spawn",
        "the confined vendor phase refused to spawn",
    );
    world
        .runtime
        .store_writer()
        .retain_attempt(&finalised_row)
        .expect("the transport row retains");
    world
        .runtime
        .store_writer()
        .attempt_rejected(&finalised_id, "the confined vendor phase refused to spawn")
        .expect("the ledger rejection lands");

    // The crash: the whole world dies without any cleanup.
    drop(world);

    // Reopen: the reconcile runs inside the open, before any surface.
    let world = support::open_world_at(world_root.path(), None);
    let settled_json;
    {
        let store = world.runtime.store();
        // Window 3: exactly one settlement row, the pre-effect row is
        // byte-identical, the marker survived, no COMMIT row was
        // fabricated, and the root is gone.
        settled_json = store
            .retained(&check_boundary_id(&unresolved_id, "close.unrecovered"))
            .expect("retained lookup")
            .expect("the unresolved attempt settles on reopen");
        assert!(
            settled_json.contains("close.unrecovered"),
            "the settlement row names its site: {settled_json}"
        );
        assert_eq!(
            store
                .retained(&check_boundary_id(&unresolved_id, "pre.effect"))
                .expect("retained lookup"),
            pre_effect,
            "the durable pre-effect row is preserved byte-for-byte"
        );
        assert!(
            store
                .has_retained(&check_boundary_id(&unresolved_id, "admit.claim"))
                .expect("retained lookup"),
            "the first-only marker survives recovery"
        );
        assert!(
            !store
                .has_retained(&check_boundary_id(&unresolved_id, "admit.claim_commit"))
                .expect("retained lookup"),
            "recovery never fabricates admit.claim_commit from an absent row"
        );
        assert!(
            unresolved_root.is_dir(),
            "the settled root stays: strict cleanup (DEC-056) refuses the destructive emptying"
        );
        assert!(
            !store
                .has_retained(&check_boundary_id(&unresolved_id, "cleanup.root"))
                .expect("retained lookup"),
            "the refused cleanup retired no authority"
        );
        // Window 1: cleanup-resume only — byte-identical disposition, no
        // recovery row, root preserved by the refusal.
        assert_eq!(
            store
                .retained(&check_boundary_id(&journey_id, "close.phase_closed"))
                .expect("retained lookup"),
            Some(serde_json::to_string(&journey_row).expect("row json")),
            "the journey disposition row is preserved byte-for-byte"
        );
        assert!(
            !store
                .has_retained(&check_boundary_id(&journey_id, "close.unrecovered"))
                .expect("retained lookup"),
            "a settled disposition never gains close.unrecovered"
        );
        assert!(
            journey_root.is_dir(),
            "the journey window's root stays: the refusal preserves the debris"
        );
        assert!(
            !store
                .has_retained(&check_boundary_id(&journey_id, "cleanup.root"))
                .expect("retained lookup"),
            "the refused cleanup retired no authority"
        );
        // Window 2: the finalised failure keeps its own row, gains no
        // recovery row, and loses its root.
        assert_eq!(
            store
                .retained(&check_boundary_id(&finalised_id, "vendor.spawn"))
                .expect("retained lookup"),
            Some(serde_json::to_string(&finalised_row).expect("row json")),
            "the finalised transport row is preserved byte-for-byte"
        );
        assert!(
            !store
                .has_retained(&check_boundary_id(&finalised_id, "close.unrecovered"))
                .expect("retained lookup"),
            "a finalised pre-return failure is cleanup-resume only"
        );
        assert!(
            finalised_root.is_dir(),
            "the finalised window's root stays: the refusal preserves the debris"
        );
        assert!(
            !store
                .has_retained(&check_boundary_id(&finalised_id, "cleanup.root"))
                .expect("retained lookup"),
            "the refused cleanup retired no authority"
        );
    }
    // No replay: the recovery open spawned nothing and sent nothing.
    assert_eq!(
        world.provider_calls.load(Ordering::SeqCst),
        0,
        "the recovery reconcile replays no provider traffic"
    );
    drop(world);

    // Restart idempotency: a third open settles nothing new — the row
    // set is unchanged, the refused roots keep their debris, and no
    // cleanup.root row ever appears.
    let world = support::open_world_at(world_root.path(), None);
    {
        let store = world.runtime.store();
        assert_eq!(
            store
                .retained(&check_boundary_id(&unresolved_id, "close.unrecovered"))
                .expect("retained lookup"),
            Some(settled_json),
            "the second reopen leaves the settlement row byte-identical"
        );
        assert!(
            !store
                .has_retained(&check_boundary_id(&journey_id, "close.unrecovered"))
                .expect("retained lookup")
                && !store
                    .has_retained(&check_boundary_id(&finalised_id, "close.unrecovered"))
                    .expect("retained lookup"),
            "no settled attempt is resettled on restart"
        );
        for id in [&unresolved_id, &journey_id, &finalised_id] {
            assert!(
                !store
                    .has_retained(&check_boundary_id(id, "cleanup.root"))
                    .expect("retained lookup"),
                "the still-refused cleanup keeps retiring nothing"
            );
        }
        assert!(
            unresolved_root.is_dir() && journey_root.is_dir() && finalised_root.is_dir(),
            "the refused debris survives the restart untouched"
        );
    }
    assert_eq!(
        world.provider_calls.load(Ordering::SeqCst),
        0,
        "the idempotent reopen replays no provider traffic"
    );
}

/// The cfg-if identity (name, version, checksum) with the archive source
/// path for fake-registry fixtures.
fn cfg_if_identity() -> (PathBuf, String, String, String) {
    let (name, version, checksum) = cfg_if_lock_entry();
    let archive = host_cargo_home()
        .join("registry/cache")
        .read_dir()
        .expect("host registry cache")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .find(|path| path.is_dir())
        .expect("a registry cache dir")
        .join(format!("{name}-{version}.crate"));
    (archive, name, version, checksum)
}

/// Populates a private cargo home with the cfg-if archive and its nested
/// sparse-index entry, both copied from the canonical host cache (the
/// bytes keep their lock checksums).
fn populate_fake_registry(cargo_home: &Path, name: &str, version: &str, _checksum: &str) {
    let (archive, _, _, _) = cfg_if_identity();
    let (registry_dir, _, _) = registry_layout();
    let cache_dir = cargo_home.join("registry/cache").join(&registry_dir);
    std::fs::create_dir_all(&cache_dir).expect("fake cache dir");
    std::fs::copy(&archive, cache_dir.join(format!("{name}-{version}.crate")))
        .expect("copy archive");

    let index_root = host_cargo_home().join("registry/index");
    let index_dir = index_root
        .read_dir()
        .expect("host registry index")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .find(|path| path.is_dir())
        .expect("a registry index dir");
    let chars: Vec<char> = name.chars().collect();
    let shards = [
        chars[..2].iter().collect::<String>(),
        chars[2..4].iter().collect::<String>(),
    ];
    let mut source = index_dir.join(".cache");
    for shard in &shards {
        source = source.join(shard);
    }
    source = source.join(name);
    let mut dest = cargo_home
        .join("registry/index")
        .join(&registry_dir)
        .join(".cache");
    for shard in &shards {
        dest = dest.join(shard);
    }
    std::fs::create_dir_all(&dest).expect("fake index dir");
    std::fs::copy(&source, dest.join(name)).expect("copy index entry");
    // The registry root descriptor the offline sparse index needs beside
    // its .cache tree.
    let fake_index_root = cargo_home.join("registry/index").join(&registry_dir);
    std::fs::create_dir_all(&fake_index_root).expect("fake index root");
    std::fs::copy(
        index_dir.join("config.json"),
        fake_index_root.join("config.json"),
    )
    .expect("copy index config.json");
}

/// The registry directory spelling present under the host cache root.
fn registry_layout() -> (String, PathBuf, PathBuf) {
    let cache_root = host_cargo_home().join("registry/cache");
    let index_root = host_cargo_home().join("registry/index");
    for spelling in [
        "index.crates.io-6f17d22bba15001f",
        "index.crates.io-1949cf8c6b5b557f",
    ] {
        if cache_root.join(spelling).is_dir() && index_root.join(spelling).is_dir() {
            return (spelling.to_string(), cache_root, index_root);
        }
    }
    panic!("no familiar registry layout under the host cargo home");
}
