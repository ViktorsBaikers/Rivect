//! Landlock/seccomp/netns confinement proofs for the Linux effect worker
//! (AC-008/AC-070, EDGE-009, PROH-001): read/write/exec/egress escapes are
//! rejected by the OS boundary, the worker probes conformance before its
//! first effect, a missing or non-enforcing mechanism — including a
//! missing Landlock ABI or an unavailable user/net namespace — fails
//! closed with `capability_unavailable` naming the failed mechanism and
//! the recovery, never an ambient effect.

#![cfg(target_os = "linux")]
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::exit,
    reason = "test fixtures use expect for setup failures, panic on wrong outcomes, and the dropped-privilege probe helpers exit with verdict codes (standards §14)"
)]

mod support;

use rivect::contracts::ErrorCode;
use rivect::executor::linux::{
    self, ConfinedOutcome, Confinement, SETPRIV, SandboxLauncher, UNSHARE,
};
use rivect::executor::{
    AdmittedEffect, EffectOutcome, EffectRequest, Executor, ExecutorError, ReadWorker, WorkerError,
};
use rivect::policy::{AdmissionContext, ModeDecision, PermissionMode, Policy, preapproval_scope};
use std::net::TcpListener;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use support::{TempTree, matrix_verdict};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

fn launcher() -> SandboxLauncher {
    SandboxLauncher::default()
}

fn confined(
    confinement: &Confinement,
    program: &Path,
    args: &[&std::ffi::OsStr],
) -> Result<ConfinedOutcome, WorkerError> {
    linux::run_confined(&launcher(), confinement, program, args)
}

/// Local counting oracle around the real Linux worker: support's default
/// counting worker delegates to the macOS backend, so the Linux matrix
/// tests carry their own counters. Every leg counts invocations, not
/// successes — a denied worker leg still proves the executor presented
/// the effect to the worker.
struct CountingLinuxWorker {
    reads: Arc<AtomicU64>,
    writes: Arc<AtomicU64>,
    execs: Arc<AtomicU64>,
    egresses: Arc<AtomicU64>,
}

impl ReadWorker for CountingLinuxWorker {
    fn read_once(
        &mut self,
        scope_root: &Path,
        target: &Path,
    ) -> Result<rivect::executor::ReadObservation, WorkerError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        linux::LinuxWorker.read_once(scope_root, target)
    }

    fn write_once(
        &mut self,
        scope_root: &Path,
        target: &Path,
        expected: rivect::executor::FileIdentity,
        bytes: &[u8],
    ) -> Result<(), WorkerError> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        linux::LinuxWorker.write_once(scope_root, target, expected, bytes)
    }

    fn exec_once(&mut self, scope_root: &Path, program: &Path) -> Result<(), WorkerError> {
        self.execs.fetch_add(1, Ordering::SeqCst);
        linux::LinuxWorker.exec_once(scope_root, program)
    }

    fn egress_once(&mut self, url: &str) -> Result<(), WorkerError> {
        self.egresses.fetch_add(1, Ordering::SeqCst);
        linux::LinuxWorker.egress_once(url)
    }
}

/// World fixture mirroring the effect-boundary one: a scoped read grant
/// and the real Linux worker behind the executor.
fn sandbox_world(tag: &str) -> (support::World, rivect::contracts::TaskId, PathBuf, String) {
    let mut world = support::open_world(tag, None);
    let session = world.open_session(&format!("{tag}-session"));
    let task = world.create_task(&session, &format!("{tag}-task"));
    let scope = world.root.join("scope");
    std::fs::create_dir_all(&scope).expect("create sandbox scope");
    let file = scope.join("target.txt");
    std::fs::write(&file, b"scoped-by-landlock").expect("create sandbox target");
    let grant = world.runtime.set_read_scope(scope, file.clone());
    world.runtime.read_worker = Box::new(linux::LinuxWorker);
    (world, task, file, grant)
}

#[test]
fn denies_read_outside_scope_at_the_os_boundary() {
    let fixture = TempTree::new("sandbox-linux", "read-escape");
    let inside = fixture.path.join("inside.txt");
    std::fs::write(&inside, b"inside-marker").expect("create inside target");
    let outside_tree = TempTree::new("sandbox-linux", "read-escape-outside");
    let outside = outside_tree.path.join("secret.txt");
    std::fs::write(&outside, b"secret").expect("create outside target");
    // Landlock rules anchor at resolved paths, so the confined legs
    // address the canonical spelling, exactly like the worker does.
    let inside = inside.canonicalize().expect("canonical inside target");
    let outside = outside.canonicalize().expect("canonical outside target");

    let confinement = linux::read_confinement(&fixture.path).expect("read confinement");
    let admitted = confined(
        &confinement,
        Path::new("/usr/bin/cat"),
        &[inside.as_os_str()],
    )
    .expect("confined read");
    assert!(
        admitted.exit_ok,
        "in-scope read must be admitted: {admitted:?}"
    );

    let denied = confined(
        &confinement,
        Path::new("/usr/bin/cat"),
        &[outside.as_os_str()],
    )
    .expect("confined read run");
    assert!(
        !denied.exit_ok,
        "an out-of-scope read must be rejected by the OS boundary: {denied:?}"
    );
    assert!(
        denied.stderr.contains("Permission denied"),
        "the OS boundary names its denial: {denied:?}"
    );
}

#[test]
fn denies_write_outside_scope_at_the_os_boundary() {
    let fixture = TempTree::new("sandbox-linux", "write-escape");
    let inside = fixture.path.join("inside.txt");
    std::fs::write(&inside, b"original").expect("create inside target");
    let outside_tree = TempTree::new("sandbox-linux", "write-escape-outside");
    let outside = outside_tree.path.join("victim.txt");
    std::fs::write(&outside, b"untouched").expect("create outside target");
    let before = std::fs::metadata(&outside).expect("outside metadata");
    let inside = inside.canonicalize().expect("canonical inside target");
    let outside = outside.canonicalize().expect("canonical outside target");

    // `tee` opens its target for write (O_WRONLY|O_CREAT|O_TRUNC), so the
    // boundary is proven by a real open-for-write; `touch` only calls
    // utimensat, which Landlock does not govern.
    let confinement = linux::write_confinement(&fixture.path).expect("write confinement");
    let admitted = confined(
        &confinement,
        Path::new("/usr/bin/tee"),
        &[inside.as_os_str()],
    )
    .expect("confined write probe");
    assert!(
        admitted.exit_ok,
        "in-scope write must be admitted: {admitted:?}"
    );

    let denied = confined(
        &confinement,
        Path::new("/usr/bin/tee"),
        &[outside.as_os_str()],
    )
    .expect("confined write run");
    assert!(
        !denied.exit_ok,
        "an out-of-scope write must be rejected by the OS boundary: {denied:?}"
    );
    assert!(
        denied.stderr.contains("Permission denied"),
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
    // The exec boundary discriminates by granted root on image binaries:
    // executing a binary created at runtime stays denied under Landlock
    // on this container kernel (overlay-upper files never execute
    // beneath any allowance), so the admitted control leg grants the
    // binary's own image tree instead of a runtime scope.
    let scope = Path::new("/usr/bin");
    let confinement = linux::exec_confinement(scope).expect("exec confinement");
    let admitted =
        confined(&confinement, Path::new("/usr/bin/true"), &[]).expect("confined exec control run");
    assert!(
        admitted.exit_ok,
        "an in-scope exec must be admitted under the same confinement: {admitted:?}"
    );

    let denied =
        confined(&confinement, Path::new("/usr/sbin/agetty"), &[]).expect("confined exec run");
    assert!(
        !denied.exit_ok,
        "an exec outside the scope must be rejected by the OS boundary: {denied:?}"
    );
    assert!(
        denied.stderr.contains("failed to execute") && denied.stderr.contains("Permission denied"),
        "the OS boundary names the exec denial: {denied:?}"
    );
}

#[test]
fn denies_egress_at_the_os_boundary() {
    // Control leg first: a held-open loopback listener accepts the bare
    // connection, so the confined denials below prove the OS boundary,
    // not a dead port.
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback listener");
    let port = listener
        .local_addr()
        .expect("listener address")
        .port()
        .to_string();
    let devtcp = format!("exec 3<>/dev/tcp/127.0.0.1/{port}");
    let bare = std::process::Command::new("/usr/bin/bash")
        .arg("-c")
        .arg(&devtcp)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("bare connect control run");
    assert!(
        bare.status.success(),
        "control leg must connect without confinement: {bare:?}"
    );

    // The full egress confinement composes the netns with the seccomp
    // net-deny: the socket syscall itself returns EPERM.
    let denied = confined(
        &linux::egress_confinement(),
        Path::new("/usr/bin/bash"),
        &[std::ffi::OsStr::new("-c"), std::ffi::OsStr::new(&devtcp)],
    )
    .expect("confined egress run");
    assert!(
        !denied.exit_ok,
        "egress must be rejected by the OS boundary under the composed confinement: {denied:?}"
    );
    assert!(
        denied.stderr.contains("socket") && denied.stderr.contains("Operation not permitted"),
        "the seccomp net-deny names the egress denial: {denied:?}"
    );

    // Discriminating leg — seccomp alone (no netns): the same filter on
    // the reachable listener denies the socket syscall, so the composed
    // denial above names seccomp, never an unreachable helper.
    let filter = linux::net_deny_filter_file().expect("seccomp filter file");
    let seccomp_only = std::process::Command::new(SETPRIV)
        .arg("--nnp")
        .arg("--seccomp-filter")
        .arg(&filter)
        .arg("/usr/bin/bash")
        .arg("-c")
        .arg(&devtcp)
        .env_clear()
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("seccomp-only egress run");
    assert!(
        !seccomp_only.status.success(),
        "seccomp alone must deny the egress: {seccomp_only:?}"
    );
    assert!(
        String::from_utf8_lossy(&seccomp_only.stderr).contains("Operation not permitted"),
        "the seccomp leg names its denial: {seccomp_only:?}"
    );

    // Discriminating leg — netns alone (no filter): a fresh network
    // namespace has no route to the listener, so the composed denial
    // above names the netns mechanism too.
    let netns_only = std::process::Command::new(UNSHARE)
        .arg("--net")
        .arg("--")
        .arg("/usr/bin/bash")
        .arg("-c")
        .arg(&devtcp)
        .env_clear()
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("netns-only egress run");
    assert!(
        !netns_only.status.success(),
        "the netns alone must deny the egress: {netns_only:?}"
    );
    assert!(
        String::from_utf8_lossy(&netns_only.stderr).contains("Network is unreachable"),
        "the netns leg names its denial: {netns_only:?}"
    );
}

#[test]
fn worker_fails_closed_when_boundary_does_not_enforce() {
    // A mechanism that never denies is not a boundary: the conformance
    // probe must report capability unavailability instead of letting the
    // checked effect run unconfined (PROH-001, EDGE-009). `/usr/bin/true`
    // consumes every launcher argument and exits 0, so every leg is
    // "admitted".
    let fixture = TempTree::new("sandbox-linux", "non-enforcing");
    let target = fixture.path.join("target.txt");
    std::fs::write(&target, b"original").expect("create target");
    let passthrough = SandboxLauncher {
        unshare: PathBuf::from("/usr/bin/true"),
        setpriv: PathBuf::from("/usr/bin/true"),
    };

    let error = linux::probe_read_conformance(&passthrough, &fixture.path, &target)
        .expect_err("a non-enforcing boundary must fail the read conformance probe");
    assert!(
        matches!(
            error,
            WorkerError::SandboxUnavailable { ref reason } if reason.contains("admitted the denied read")
        ),
        "{error}"
    );
    let write_error = linux::probe_write_conformance(&passthrough, &fixture.path)
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
    linux::probe_read_conformance(&launcher(), &fixture.path, &target)
        .expect("real boundary conforms for a confinable scope");
    linux::probe_write_conformance(&launcher(), &fixture.path)
        .expect("real write boundary conforms for a confinable scope");
}

/// Writes a launcher shim that prints one stderr line and exits nonzero.
fn failing_shim(dir: &Path, name: &str, message: &str) -> PathBuf {
    let shim = dir.join(name);
    std::fs::write(&shim, format!("#!/bin/sh\necho '{message}' >&2\nexit 1\n"))
        .expect("write launcher shim");
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755))
        .expect("make shim executable");
    shim
}

#[test]
fn missing_landlock_abi_maps_to_capability_unavailable() {
    // A kernel without the Landlock ABI fails `setpriv` before any child
    // runs: every confined leg dies with the launcher's own error. The
    // probe's admitted leg surfaces that failure as an honest
    // capability_unavailable whose reason names the failed mechanism and
    // the recovery (EDGE-009). A shim reproduces the launcher error a
    // pre-Landlock kernel produces.
    let fixture = TempTree::new("sandbox-linux", "missing-abi");
    let scope = fixture.path.join("scope");
    std::fs::create_dir_all(&scope).expect("create scope");
    let target = scope.join("target.txt");
    std::fs::write(&target, b"original").expect("create target");
    let shim = failing_shim(
        &fixture.path,
        "setpriv-no-landlock",
        "setpriv: failed to apply Landlock ruleset: Operation not permitted",
    );
    let shimmed = SandboxLauncher {
        unshare: PathBuf::from(UNSHARE),
        setpriv: shim,
    };

    let read_error = linux::probe_read_conformance(&shimmed, &scope, &target)
        .expect_err("a kernel without the landlock abi must fail the read probe");
    assert!(
        matches!(read_error, WorkerError::SandboxUnavailable { ref reason } if reason.to_lowercase().contains("landlock")),
        "{read_error}"
    );
    let wire = ExecutorError::Worker(read_error);
    assert_eq!(wire.error_code(), ErrorCode::CapabilityUnavailable);
    let message = wire.to_string();
    assert!(message.contains("recovery"), "{message}");

    let write_error = linux::probe_write_conformance(&shimmed, &scope)
        .expect_err("a kernel without the landlock abi must fail the write probe");
    assert!(
        matches!(write_error, WorkerError::SandboxUnavailable { ref reason } if reason.to_lowercase().contains("landlock")),
        "{write_error}"
    );
    assert_eq!(
        ExecutorError::Worker(write_error).error_code(),
        ErrorCode::CapabilityUnavailable
    );
    // No ambient fallback: the user target survives the failed probes.
    assert_eq!(
        std::fs::read(&target).expect("target survives the failed probes"),
        b"original"
    );
}

#[test]
fn missing_userns_maps_to_capability_unavailable() {
    // An environment that cannot unshare the network namespace fails
    // `unshare` before any confinement exists: every leg dies with the
    // launcher's own error, and the probe surfaces it as an honest
    // capability_unavailable naming the failed mechanism (EDGE-009). A
    // shim reproduces the error a container without SYS_ADMIN produces.
    let fixture = TempTree::new("sandbox-linux", "missing-userns");
    let scope = fixture.path.join("scope");
    std::fs::create_dir_all(&scope).expect("create scope");
    let target = scope.join("target.txt");
    std::fs::write(&target, b"original").expect("create target");
    let shim = failing_shim(
        &fixture.path,
        "unshare-no-userns",
        "unshare: unshare failed: Operation not permitted",
    );
    let shimmed = SandboxLauncher {
        unshare: shim,
        setpriv: PathBuf::from(SETPRIV),
    };

    let read_error = linux::probe_read_conformance(&shimmed, &scope, &target)
        .expect_err("an unavailable user/net namespace must fail the read probe");
    assert!(
        matches!(read_error, WorkerError::SandboxUnavailable { ref reason } if reason.to_lowercase().contains("unshare")),
        "{read_error}"
    );
    let wire = ExecutorError::Worker(read_error);
    assert_eq!(wire.error_code(), ErrorCode::CapabilityUnavailable);
    assert!(wire.to_string().contains("recovery"));

    let write_error = linux::probe_write_conformance(&shimmed, &scope)
        .expect_err("an unavailable user/net namespace must fail the write probe");
    assert!(
        matches!(write_error, WorkerError::SandboxUnavailable { ref reason } if reason.to_lowercase().contains("unshare")),
        "{write_error}"
    );
    assert_eq!(
        ExecutorError::Worker(write_error).error_code(),
        ErrorCode::CapabilityUnavailable
    );
}

#[test]
fn launcher_init_failure_maps_to_capability_unavailable() {
    let fixture = TempTree::new("sandbox-linux", "missing-mechanism");
    let target = fixture.path.join("target.txt");
    std::fs::write(&target, b"unchanged").expect("create target");
    let confinement = linux::read_confinement(&fixture.path).expect("read confinement");

    let error = linux::run_confined(
        &SandboxLauncher {
            unshare: PathBuf::from("/nonexistent/rivect-unshare"),
            setpriv: PathBuf::from(SETPRIV),
        },
        &confinement,
        Path::new("/usr/bin/cat"),
        &[target.as_os_str()],
    )
    .expect_err("a missing launcher must fail closed");
    assert!(
        matches!(error, WorkerError::SandboxSpawnFailed { .. }),
        "{error}"
    );
    let wire = ExecutorError::Worker(error);
    assert_eq!(wire.error_code(), ErrorCode::CapabilityUnavailable);
    assert!(wire.to_string().contains("recovery"));
}

#[test]
fn worker_probes_conformance_before_first_effect() {
    // A scope that already covers the boundary's denied-probe target is
    // not confinable: the conformance probe must fail closed with
    // capability_unavailable before any effect byte moves, even though
    // the checked in-process leg would happily write the target.
    let fixture = TempTree::new("sandbox-linux", "probe-order");
    let target = fixture.path.join("target.txt");
    std::fs::write(&target, b"original").expect("create target");
    let mut worker = linux::LinuxWorker;

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
            rivect::executor::FileIdentity { dev: 0, ino: 0 },
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
fn passthrough_boundary_performs_no_in_scope_io() {
    // A mechanism that ignores its confinement must be detected by the
    // probe before any confined leg touches the user's target: the denied
    // legs run first on system or worker-owned files, so a passthrough
    // leaves the scope untouched and fails closed as a capability error.
    let fixture = TempTree::new("sandbox-linux", "passthrough");
    let scope = fixture.path.join("scope");
    std::fs::create_dir_all(&scope).expect("create scope");
    let target = scope.join("target.txt");
    std::fs::write(&target, b"original").expect("create target");
    let passthrough = SandboxLauncher {
        unshare: PathBuf::from("/usr/bin/true"),
        setpriv: PathBuf::from("/usr/bin/true"),
    };

    let read_error = linux::probe_read_conformance(&passthrough, &scope, &target)
        .expect_err("a passthrough mechanism must fail the read probe");
    assert!(
        matches!(&read_error, WorkerError::SandboxUnavailable { reason } if reason.contains("admitted the denied read")),
        "{read_error}"
    );
    let write_error = linux::probe_write_conformance(&passthrough, &scope)
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

    // Control: the real boundary conforms, and conformance leaves no
    // artifact behind — every write leg runs on a fresh probe file that
    // is removed after its leg.
    linux::probe_write_conformance(&launcher(), &scope).expect("real write boundary conforms");
    linux::probe_read_conformance(&launcher(), &scope, &target)
        .expect("real read boundary conforms");
    let strays: Vec<String> = std::fs::read_dir(&scope)
        .expect("scope readable")
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with(".rivect"))
        .collect();
    assert!(
        strays.is_empty(),
        "conformance leaves no probe artifacts in the scope: {strays:?}"
    );
}

/// Positional filter arguments a probe parent passes to this test binary
/// (they are absolute paths); empty on an ordinary harness run, so the
/// probe helpers below are no-ops there.
fn probe_args() -> Vec<String> {
    std::env::args()
        .skip(1)
        .filter(|arg| arg.starts_with('/'))
        .collect()
}

/// Runs this test binary in helper mode with dropped privileges
/// (`setpriv --reuid` nobody): root bypasses DAC modes, so a
/// typed-denial leg only discriminates as an unprivileged child.
fn nobody_probe(helper: &str, paths: &[&Path]) -> std::process::Output {
    std::process::Command::new(SETPRIV)
        .arg("--reuid=65534")
        .arg("--regid=65534")
        .arg("--clear-groups")
        .arg(std::env::current_exe().expect("test binary path"))
        .arg("--exact")
        .arg("--nocapture")
        .arg(helper)
        .args(paths.iter().map(|path| path.as_os_str()))
        .env_clear()
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("run the dropped-privilege probe child")
}

fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .expect("set fixture permissions");
}

/// Helper leg for `unwritable_scope_is_an_effect_denial_not_a_capability_failure`:
/// with the scope and target paths as filter arguments it runs one
/// managed write through the real worker and exits 1 when the scope is
/// writable (the honest capability failure of an unprivileged
/// environment), 2 for the typed `WriteFailed` denial, 4 for anything
/// else.
#[test]
fn nobody_write_denial_probe_helper() {
    let args = probe_args();
    let (Some(scope), Some(target)) = (args.first(), args.get(1)) else {
        return;
    };
    match linux::write_once(
        Path::new(scope),
        Path::new(target),
        rivect::executor::FileIdentity { dev: 0, ino: 0 },
        b"probe",
    ) {
        Err(error @ WorkerError::WriteFailed { .. }) => {
            eprintln!("nobody-write denied: {error}");
            std::process::exit(2);
        }
        Err(error @ WorkerError::SandboxUnavailable { .. }) => {
            eprintln!("nobody-write writable scope: {error}");
            std::process::exit(1);
        }
        other => {
            eprintln!("nobody-write unexpected: {other:?}");
            std::process::exit(4);
        }
    }
}

#[test]
fn unwritable_scope_is_an_effect_denial_not_a_capability_failure() {
    // 0o555 stops no root, so the leg runs as a dropped-privilege child:
    // for nobody only DAC denies the write, and the probe must classify
    // it as the typed WriteFailed effect denial, never a capability
    // failure that re-probes on every spawn forever. Flipping the scope
    // mode flips the verdict, so the leg discriminates (EDGE-009).
    let fixture = TempTree::new("sandbox-linux", "unwritable-scope");
    let scope = fixture.path.join("scope");
    std::fs::create_dir_all(&scope).expect("create scope");
    set_mode(&scope, 0o755);
    let target = scope.join("target.txt");
    std::fs::write(&target, b"original").expect("create target");
    set_mode(&scope, 0o555);
    let denied = nobody_probe("nobody_write_denial_probe_helper", &[&scope, &target]);
    let stderr = String::from_utf8_lossy(&denied.stderr).into_owned();
    assert_eq!(
        denied.status.code(),
        Some(2),
        "an unwritable scope is the typed WriteFailed denial: {denied:?}\n{stderr}"
    );
    assert!(
        stderr.contains("nobody-write denied") && stderr.contains("Permission denied"),
        "the typed denial names the write and the permission: {stderr}"
    );
    // Control: the same child with a world-writable scope (a root-owned
    // 0o755 directory still denies nobody's create) reaches the honest
    // capability failure instead — the verdict above named the mode, not
    // the child.
    set_mode(&scope, 0o777);
    let allowed = nobody_probe("nobody_write_denial_probe_helper", &[&scope, &target]);
    set_mode(&scope, 0o755);
    assert_eq!(
        allowed.status.code(),
        Some(1),
        "a writable scope must not produce the typed denial: {allowed:?}"
    );
}

/// Helper leg for `unreadable_target_is_an_effect_denial_not_a_capability_failure`:
/// with the scope and target paths as filter arguments it runs one read
/// through the real worker and exits 1 when the target is readable (the
/// honest capability failure of an unprivileged environment), 2 for the
/// typed `ReadFailed` denial, 4 for anything else.
#[test]
fn nobody_read_denial_probe_helper() {
    let args = probe_args();
    let (Some(scope), Some(target)) = (args.first(), args.get(1)) else {
        return;
    };
    match linux::read_once(Path::new(scope), Path::new(target)) {
        Err(error @ WorkerError::ReadFailed { .. }) => {
            eprintln!("nobody-read denied: {error}");
            std::process::exit(2);
        }
        Err(error @ WorkerError::SandboxUnavailable { .. }) => {
            eprintln!("nobody-read readable target: {error}");
            std::process::exit(1);
        }
        other => {
            eprintln!("nobody-read unexpected: {other:?}");
            std::process::exit(4);
        }
    }
}

#[test]
fn unreadable_target_is_an_effect_denial_not_a_capability_failure() {
    // 0o000 stops no root, so the leg runs as a dropped-privilege child:
    // for nobody only DAC denies the read, and the probe must classify
    // it as the typed ReadFailed effect denial, never a capability
    // failure. Flipping the target mode flips the verdict, so the leg
    // discriminates (EDGE-009).
    let fixture = TempTree::new("sandbox-linux", "unreadable-target");
    let scope = fixture.path.join("scope");
    std::fs::create_dir_all(&scope).expect("create scope");
    set_mode(&scope, 0o755);
    let target = scope.join("target.txt");
    std::fs::write(&target, b"original").expect("create target");
    set_mode(&target, 0o000);
    let denied = nobody_probe("nobody_read_denial_probe_helper", &[&scope, &target]);
    set_mode(&target, 0o644);
    let stderr = String::from_utf8_lossy(&denied.stderr).into_owned();
    assert_eq!(
        denied.status.code(),
        Some(2),
        "an unreadable target is the typed ReadFailed denial: {denied:?}\n{stderr}"
    );
    assert!(
        stderr.contains("nobody-read denied") && stderr.contains("Permission denied"),
        "the typed denial names the read and the permission: {stderr}"
    );
    // Control: the same child with a readable target reaches the honest
    // capability failure instead — the verdict above named the mode, not
    // the child.
    let allowed = nobody_probe("nobody_read_denial_probe_helper", &[&scope, &target]);
    assert_eq!(
        allowed.status.code(),
        Some(1),
        "a readable target must not produce the typed denial: {allowed:?}"
    );
}

#[test]
fn confined_child_stdout_is_never_captured() {
    // Gates decide on the exit status alone: a confined read far larger
    // than any sane capture buffer streams to /dev/null, and the outcome
    // type carries no stdout at all.
    let fixture = TempTree::new("sandbox-linux", "stream-bound");
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
    let confinement = linux::read_confinement(&fixture.path).expect("read confinement");
    let outcome = confined(&confinement, Path::new("/usr/bin/cat"), &[big.as_os_str()])
        .expect("confined stream read runs");
    assert!(
        outcome.exit_ok,
        "the streamed in-scope read is admitted: {outcome:?}"
    );
}

#[test]
fn free_write_once_is_confined_for_every_caller() {
    // Confinement must be intrinsic to the free write function: a
    // non-confinable scope fails the probe before any byte moves.
    let fixture = TempTree::new("sandbox-linux", "free-write-confined");
    let target = fixture.path.join("target.txt");
    std::fs::write(&target, b"original").expect("create target");
    let error = linux::write_once(
        Path::new("/"),
        &target,
        rivect::executor::FileIdentity { dev: 0, ino: 0 },
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
fn sandbox_worker_reads_scope_and_lands_checked_managed_write() {
    let (mut world, task, file, grant) = sandbox_world("worker-happy-path");
    let mut worker = linux::LinuxWorker;
    let scope_root = file.parent().expect("scope root").to_path_buf();

    let rivect::executor::ReadObservation { bytes, digest } = worker
        .read_once(&scope_root, &file)
        .expect("confined scoped read");
    assert_eq!(bytes, b"scoped-by-landlock");
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
                    bytes: b"replacement-by-landlock".to_vec(),
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
            .expect("checked managed write under landlock");
    }
    assert_eq!(
        std::fs::read(&file).expect("read managed write target"),
        b"replacement-by-landlock"
    );
}

#[test]
fn linux_worker_write_once_rechecks_the_opened_occupant() {
    // The write fd is the checked fd: an occupant swap between the
    // identity check and the open denies on the post-open re-check, and
    // the new file never receives the admitted bytes (INV-029).
    let (mut world, task, file, grant) = sandbox_world("occupant-swap");
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
                    bytes: b"admitted-bytes".to_vec(),
                },
            )
            .expect("managed write admission")
    };
    std::fs::remove_file(&file).expect("remove admitted occupant");
    std::fs::write(&file, b"swapped-occupant").expect("plant swapped occupant");

    let error = {
        let mut executor = Executor::new(
            &mut world.runtime.policy,
            &mut world.runtime.owner.store,
            world.runtime.read_worker.as_mut(),
        );
        executor
            .execute_managed_write(&admitted)
            .expect_err("an occupant swap must deny the managed write")
    };
    assert!(
        matches!(
            error,
            ExecutorError::Worker(WorkerError::TargetChanged { .. })
        ),
        "{error}"
    );
    assert_eq!(
        std::fs::read(&file).expect("swapped occupant survives"),
        b"swapped-occupant",
        "no admitted byte may land on the swapped occupant"
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

#[test]
fn allowed_manual_read_executes_through_the_linux_worker() {
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
            assert_eq!(bytes, b"scoped-by-landlock");
            assert_eq!(digest, support::sha256_hex(b"scoped-by-landlock"));
        }
        other => panic!("expected a read outcome, got {other:?}"),
    }
}

#[test]
fn non_read_effects_have_no_ambient_path_in_any_mode() {
    // A forged admission must not bypass the mode gate: with an
    // all-class grant and the interim manual mode, every non-read cell
    // of the manual column asks at the execute-time reconsult, the
    // typed error settles the ledger, and no worker leg runs — there is
    // no ambient path around the gate.
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
            attempt_id: attempt_id.clone(),
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
        let (_, state, detail) = world
            .runtime
            .owner
            .store
            .attempt_record(&attempt_id)
            .expect("forged attempt readable")
            .expect("forged attempt exists");
        assert_eq!(state, "rejected");
        assert_eq!(detail.as_deref(), Some(rivect::executor::MODE_ASK_REASON));
    }
    assert_eq!(
        std::fs::read(&file).expect("read untouched target"),
        b"scoped-by-landlock"
    );
    assert_eq!(world.runtime.provider_calls, 0);
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
fn six_permission_modes_gate_the_linux_worker() {
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

    // Live mode-carrying legs (DEC-016): every mode × class pair runs
    // the real admit→execute path with the mode injected at admit, never
    // admit_managed_write. The executor's own admission context observes
    // only in-grant-scope and the recorded preapprovals — every other
    // granting input stays unobserved — so the live verdicts differ from
    // the all-inputs pin above exactly there: only preapproved-only
    // (with its recorded consents) and yolo allow the non-read classes.
    // Allow cells cross the real Linux worker — the read lands, the
    // write lands, the confined exec runs, and the egress Allow cell
    // meets the OS denial the boundary imposes (an egress target admits
    // no filesystem scope, so it is out of scope by construction); ask
    // and deny cells fail closed at admit and never invoke the worker.
    let mut world = support::open_world("matrix-worker", None);
    let session = world.open_session("matrix-worker-session");
    let task = world.create_task(&session, "matrix-worker-task");
    let scope = world.root.join("scope");
    std::fs::create_dir_all(&scope).expect("create matrix scope");
    let file = scope.join("target.txt");
    let grant = world.runtime.set_read_scope(scope, file.clone());
    let reads = Arc::new(AtomicU64::new(0));
    let writes = Arc::new(AtomicU64::new(0));
    let execs = Arc::new(AtomicU64::new(0));
    let egresses = Arc::new(AtomicU64::new(0));
    world.runtime.read_worker = Box::new(CountingLinuxWorker {
        reads: reads.clone(),
        writes: writes.clone(),
        execs: execs.clone(),
        egresses: egresses.clone(),
    });
    // Exec Allow cells run an image binary under the exec confinement:
    // a runtime-created binary never executes beneath a Landlock
    // allowance on this container kernel, so the exec grant anchors at
    // the binary's own image tree (see
    // denies_exec_outside_scope_at_the_os_boundary).
    let exec_program = PathBuf::from("/usr/bin/true");
    let write_grant = world.runtime.policy.grant_classes(
        file.parent().expect("scope root").to_path_buf(),
        vec![Class::Write],
    );
    let exec_grant = world
        .runtime
        .policy
        .grant_classes(PathBuf::from("/usr/bin"), vec![Class::Exec]);
    let egress_url = "https://example.invalid/matrix";
    let egress_grant = world.runtime.policy.grant_classes(
        file.parent().expect("scope root").to_path_buf(),
        vec![Class::Egress],
    );
    for (class, target) in [
        (Class::Read, file.display().to_string()),
        (Class::Write, file.display().to_string()),
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
            ModeDecision::Ask,
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
        std::fs::write(&file, b"scoped-by-landlock").expect("seed matrix target");

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
                    assert_eq!(bytes, b"scoped-by-landlock");
                    assert_eq!(digest, support::sha256_hex(b"scoped-by-landlock"));
                }
                other => panic!("{mode:?} read allow outcome: {other:?}"),
            }
            assert_eq!(
                reads.load(Ordering::SeqCst),
                read_before + 1,
                "the {mode:?} read Allow cell crossed the linux worker once"
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
                "the {mode:?} write Allow cell crossed the linux worker once"
            );
        } else {
            assert_eq!(
                std::fs::read(&file).expect("read the non-allow write target"),
                b"scoped-by-landlock",
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
                "the {mode:?} exec Allow cell crossed the linux worker once"
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
                "the {mode:?} egress Allow cell was presented to the linux worker once"
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
                    program: PathBuf::from("/usr/bin/sleep"),
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

/// Helper leg for `degraded_environment_fails_closed_naming_the_mechanism`:
/// with the scope and target paths as filter arguments it runs one read
/// through the real worker and exits 0 only for a capability_unavailable
/// whose reason names the launcher mechanism (`unshare`/`setpriv`).
#[test]
fn degraded_read_probe_helper() {
    let args = probe_args();
    let (Some(scope), Some(target)) = (args.first(), args.get(1)) else {
        return;
    };
    match linux::read_once(Path::new(scope), Path::new(target)) {
        Err(error @ WorkerError::SandboxUnavailable { .. }) => {
            let reason = format!("{error}");
            eprintln!("degraded-read: {reason}");
            let names_mechanism = reason.contains("unshare") || reason.contains("setpriv");
            let capability =
                ExecutorError::Worker(error).error_code() == ErrorCode::CapabilityUnavailable;
            if names_mechanism && capability {
                std::process::exit(0);
            }
            std::process::exit(4);
        }
        other => {
            eprintln!("degraded-read unexpected: {other:?}");
            std::process::exit(4);
        }
    }
}

#[test]
fn degraded_environment_fails_closed_naming_the_mechanism() {
    // Real degraded-environment leg, not a shim: without CAP_SYS_ADMIN
    // the launcher cannot create the netns, and the worker fails closed
    // with capability_unavailable naming the failed launcher mechanism —
    // never an ambient read. The leg runs as a dropped-privilege child
    // because the proof container grants the test process SYS_ADMIN
    // (EDGE-009).
    let fixture = TempTree::new("sandbox-linux", "degraded-env");
    let scope = fixture.path.join("scope");
    std::fs::create_dir_all(&scope).expect("create scope");
    set_mode(&scope, 0o755);
    let target = scope.join("target.txt");
    std::fs::write(&target, b"readable").expect("create target");
    set_mode(&target, 0o644);
    let out = nobody_probe("degraded_read_probe_helper", &[&scope, &target]);
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(
        out.status.code(),
        Some(0),
        "the degraded environment must fail closed naming the mechanism: {out:?}\n{stderr}"
    );
    assert!(
        stderr.to_lowercase().contains("unshare"),
        "the mechanism name reaches the reason: {stderr}"
    );
    assert!(
        stderr.to_lowercase().contains("recovery"),
        "the recovery hint reaches the reason: {stderr}"
    );
}

#[test]
fn exec_confinement_denies_unix_socket_connect() {
    // Pathname AF_UNIX sockets cross the network namespace, so a program
    // running inside the exec scope reaches host-side unix services
    // outside it — the netns is never the egress carrier for a scoped
    // program, and the exec leg must load the seccomp net-deny.
    let fixture = TempTree::new("sandbox-linux", "unix-egress");
    let socket_path = fixture.path.join("service.sock");
    // Held binding, no accept: a backlog connect is a real connect, and
    // curl's own --max-time bounds every leg.
    let _listener = UnixListener::bind(&socket_path).expect("bind the host-side unix service");
    let request = [
        std::ffi::OsStr::new("-sS"),
        std::ffi::OsStr::new("--unix-socket"),
        socket_path.as_os_str(),
        std::ffi::OsStr::new("--max-time"),
        std::ffi::OsStr::new("2"),
        std::ffi::OsStr::new("http://127.0.0.1/"),
    ];
    // Control: same socket, no confinement — curl connects (backlog),
    // sends, and times out waiting for the answer; a refused or filtered
    // connect exits 7 before any timeout.
    let control = std::process::Command::new("/usr/bin/curl")
        .args(request)
        .env_clear()
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("unconfined unix connect control run");
    assert_eq!(
        control.status.code(),
        Some(28),
        "the control leg must connect and time out, proving the service is reachable: {control:?}"
    );
    // Confined leg: the exec scope is the image's curl tree; the seccomp
    // net-deny must own the connect.
    let confinement = linux::exec_confinement(Path::new("/usr")).expect("exec confinement");
    let denied =
        confined(&confinement, Path::new("/usr/bin/curl"), &request).expect("confined exec run");
    assert!(
        !denied.exit_ok,
        "a scoped program must not connect to a unix service outside the scope: {denied:?}"
    );
    assert!(
        denied.stderr.contains("Failed to connect"),
        "the boundary names the connect denial: {denied:?}"
    );
}

#[test]
fn managed_writes_never_truncate_a_planted_alias_or_leave_debris() {
    // The write gate proves its allowance on a fresh unpredictable probe
    // artifact per leg: a file pre-planted at any guessable probe name
    // (the pid-only scheme an earlier gate reused) is never opened,
    // truncated, or followed, and every artifact is removed after its
    // leg.
    let (mut world, task, file, grant) = sandbox_world("alias-truncation");
    let scope = file.parent().expect("scope root").to_path_buf();
    let planted = scope.join(format!(".rivect-write-probe-{}", std::process::id()));
    std::fs::write(&planted, b"planted-alias-must-survive").expect("plant the alias");
    for payload in ["first-managed-write", "second-managed-write"] {
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
                        bytes: payload.as_bytes().to_vec(),
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
                .expect("confined managed write executes");
        }
    }
    assert_eq!(
        std::fs::read(&planted).expect("planted alias survives"),
        b"planted-alias-must-survive",
        "no gate leg may truncate or follow a pre-planted probe name"
    );
    assert_eq!(
        std::fs::read(&file).expect("managed write target"),
        b"second-managed-write"
    );
    let planted_name = planted
        .file_name()
        .expect("planted name")
        .to_string_lossy()
        .into_owned();
    let strays: Vec<String> = std::fs::read_dir(&scope)
        .expect("scope readable")
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with(".rivect-write-probe") && *name != planted_name)
        .collect();
    assert!(
        strays.is_empty(),
        "the gate leaves no probe artifacts behind: {strays:?}"
    );
}

#[test]
fn allow_mode_write_cells_execute_through_the_linux_worker() {
    // The matrix's Write Allow cells must hold on the live mode-carrying
    // path, never through admit_managed_write: for every mode, the write
    // cell admits with the injected mode and the verdict decides whether
    // the confined worker runs. The executor context observes no trusted
    // scope, checkpoint, or budget, so only preapproved-only (with its
    // recorded consent) and yolo reach a live write; every other mode
    // fails closed at admit and the worker never runs.
    use rivect::contracts::EffectClass as Class;
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
        std::fs::write(&file, b"scoped-by-landlock").expect("create matrix target");
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
                    &preapproval_scope(Class::Write, &file.display().to_string()),
                    "human:matrix-write",
                    600,
                )
                .expect("record write preapproval");
        }
        let writes = Arc::new(AtomicU64::new(0));
        world.runtime.read_worker = Box::new(CountingLinuxWorker {
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
                "the {mode:?} Allow cell crossed the linux worker exactly once"
            );
        } else {
            assert_eq!(
                std::fs::read(&file).expect("read untouched write target"),
                b"scoped-by-landlock",
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
    // sandbox_worker_reads_scope_and_lands_checked_managed_write and
    // managed_writes_never_truncate_a_planted_alias_or_leave_debris.
}

#[test]
fn backend_selects_the_linux_worker_platform() {
    assert_eq!(rivect::executor::backend(), linux::BACKEND);
    assert_eq!(linux::BACKEND, "linux");
}
