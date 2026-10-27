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

use rivect::contracts::{EffectClass, ErrorCode, SessionId};
use rivect::executor::linux::{
    self, ConfinedOutcome, Confinement, SETPRIV, SandboxLauncher, UNSHARE,
};
use rivect::executor::{
    AdmittedEffect, CheckError, CheckRun, CheckTarget, CleanupClaim, ConfinedCheck, EffectOutcome,
    EffectRequest, ExecutorError, ReadWorker, WorkerError, check_boundary_id,
    helper_confined_command, workspace_digest,
};
use rivect::policy::{AdmissionContext, ModeDecision, PermissionMode, Policy, preapproval_scope};
use std::net::TcpListener;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use support::{HELPER_IO_WITNESS, TempTree, ensure_helper, install_helper_io_shim, matrix_verdict};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

#[test]
fn owned_launch_unexposed_filter_is_removed_on_drop() {
    let filter = linux::net_deny_filter_file().expect("prepare the filter");
    let path = AsRef::<Path>::as_ref(&filter).to_path_buf();
    assert!(path.is_file(), "the filter exists before exposure");
    drop(filter);
    assert!(!path.exists(), "an unexposed artifact is removed on drop");
}

fn launcher() -> SandboxLauncher {
    SandboxLauncher::default()
}

fn confined(
    confinement: &Confinement,
    program: &Path,
    args: &[&std::ffi::OsStr],
) -> Result<ConfinedOutcome, WorkerError> {
    ensure_helper();
    linux::run_confined(&launcher(), confinement, program, args)
}

/// Local counting oracle around the real Linux worker. Every leg counts
/// invocations, not
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
        expected: rivect::executor::WriteIdentity,
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
    support::sandbox_world(tag, b"scoped-by-landlock", linux::LinuxWorker)
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
    // binary's own image tree instead of a runtime scope. The denied
    // control is the worker-owned copy of `true` — never a system
    // binary such as agetty, whose existence is not the discriminator.
    let scope = Path::new("/usr/bin");
    let confinement = linux::exec_confinement(scope).expect("exec confinement");
    let admitted =
        confined(&confinement, Path::new("/usr/bin/true"), &[]).expect("confined exec control run");
    assert!(
        admitted.exit_ok,
        "an in-scope exec must be admitted under the same confinement: {admitted:?}"
    );

    let control = linux::denied_exec_control().expect("owned denied-exec control");
    let denied = linux::run_confined_owned(&SandboxLauncher::default(), &confinement, control, &[])
        .expect("confined exec run");
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
    let mut seccomp_only = rivect::executor::PreparedLaunch::direct(SETPRIV);
    seccomp_only
        .arg("--nnp")
        .arg("--seccomp-filter")
        .artifact_arg(filter)
        .arg("/usr/bin/bash")
        .arg("-c")
        .arg(&devtcp)
        .env_clear()
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped());
    let seccomp_only = seccomp_only.run(&[]).expect("seccomp-only egress run");
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
        .args(["--user", "--map-current-user"])
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
    ensure_helper();
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
    ensure_helper();
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
    ensure_helper();
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
    if let WorkerError::SandboxUnavailable { reason } = &read_error {
        for word in [
            "linux user namespace unavailable (unshare --user)",
            "kernel.apparmor_restrict_unprivileged_userns",
            "user.max_user_namespaces",
            "util-linux 2.38",
            "docs/operations/linux-prerequisites.md",
        ] {
            assert!(reason.contains(word), "missing {word}: {reason}");
        }
        assert!(!reason.contains("in-scope"), "{reason}");
    }
    let wire = ExecutorError::Worker(read_error);
    assert_eq!(wire.error_code(), ErrorCode::CapabilityUnavailable);
    assert!(wire.to_string().contains("recovery"));

    let write_error = linux::probe_write_conformance(&shimmed, &scope)
        .expect_err("an unavailable user/net namespace must fail the write probe");
    assert!(
        matches!(write_error, WorkerError::SandboxUnavailable { ref reason } if reason.to_lowercase().contains("unshare")),
        "{write_error}"
    );
    if let WorkerError::SandboxUnavailable { reason } = &write_error {
        for word in [
            "linux user namespace unavailable (unshare --user)",
            "kernel.apparmor_restrict_unprivileged_userns",
            "user.max_user_namespaces",
            "util-linux 2.38",
            "docs/operations/linux-prerequisites.md",
        ] {
            assert!(reason.contains(word), "missing {word}: {reason}");
        }
        assert!(!reason.contains("in-scope"), "{reason}");
    }
    assert_eq!(
        ExecutorError::Worker(write_error).error_code(),
        ErrorCode::CapabilityUnavailable
    );
}

fn assert_owned_bootstrap_fault(
    error: &WorkerError,
    boundary: &str,
    operation: u8,
    errno: i32,
) -> String {
    use rivect::executor::OwnedLaunchError;
    let WorkerError::OwnedLaunch { source } = error else {
        panic!("the native bootstrap must retain its owned error: {error:?}");
    };
    let OwnedLaunchError::Unproven {
        primary,
        release,
        locators,
        expected_identities,
        stop,
    } = source.as_ref()
    else {
        panic!("the native bootstrap never established successful entry or release: {error:?}");
    };
    assert!(std::error::Error::source(error).is_some());
    assert!(std::error::Error::source(source.as_ref()).is_some());
    assert_eq!(*stop, None);
    assert!(
        release.is_none(),
        "the complete singleton bootstrap fault has no later release failure"
    );
    assert!(
        !locators.is_empty(),
        "exposed native custody retains its original locators"
    );
    assert_eq!(locators.len(), expected_identities.len());
    for (locator, expected) in locators.iter().zip(expected_identities) {
        let observed =
            std::fs::symlink_metadata(locator).expect("observe the retained native artifact");
        assert!(observed.file_type().is_dir());
        assert_eq!(
            (observed.dev(), observed.ino()),
            (expected.dev(), expected.ino()),
            "the observed artifact still matches its separately frozen expected identity"
        );
    }
    let WorkerError::OwnedLaunch { source: primary } = primary.as_ref() else {
        panic!("the original helper fault remains typed");
    };
    assert!(std::error::Error::source(primary.as_ref()).is_some());
    let OwnedLaunchError::Helper {
        fault,
        secondary,
        source: native,
    } = primary.as_ref()
    else {
        panic!("retain the actual native bootstrap fault");
    };
    assert_eq!(fault.boundary(), boundary);
    assert_eq!(
        fault.cause(),
        rivect_sandbox_helper::OwnedFaultCause::Io {
            operation,
            field: 0,
            errno
        }
    );
    assert_eq!(native.raw_os_error(), Some(errno));
    assert!(
        secondary.is_none(),
        "the complete singleton frame has no later init-close/wait fault"
    );
    format!(
        "owned bootstrap custody: boundary={boundary} locators={locators:?} expected={expected_identities:?} release={release:?} secondary={secondary:?}"
    )
}

#[test]
fn launcher_init_failure_maps_to_capability_unavailable() {
    ensure_helper();
    let fixture = TempTree::new("sandbox-linux", "missing-mechanism");
    let target = fixture.path.join("target.txt");
    std::fs::write(&target, b"unchanged").expect("create target");
    let confinement = linux::read_confinement(&fixture.path).expect("read confinement");

    assert_eq!(
        std::process::Command::new("/nonexistent/rivect-unshare")
            .env_clear()
            .spawn()
            .expect_err("independent native missing launcher control")
            .raw_os_error(),
        Some(2)
    );
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
    println!(
        "{}",
        assert_owned_bootstrap_fault(&error, "owned.child.spawn", 25, 2)
    );
    assert_eq!(
        std::fs::read(&target).expect("observe the unchanged target"),
        b"unchanged"
    );
    let wire = ExecutorError::Worker(error);
    assert_eq!(wire.error_code(), ErrorCode::CapabilityUnavailable);
    assert!(wire.to_string().contains("recovery"));
}

#[test]
fn worker_probes_conformance_before_first_effect() {
    ensure_helper();
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
            rivect::executor::WriteIdentity::new(
                rivect::executor::FileIdentity::new(0, 0),
                Err(rivect::executor::Unattested::Unrecorded),
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
fn passthrough_boundary_performs_no_in_scope_io() {
    ensure_helper();
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

/// Drops root's DAC bypass for denial probes; other callers keep their uid.
fn nobody_probe(helper: &str, paths: &[&Path], owner: &mut TempTree) -> std::process::Output {
    let exe = std::env::current_exe().expect("test binary path");
    let mut command = if std::fs::metadata("/proc/self")
        .expect("process metadata")
        .uid()
        == 0
    {
        let mut command = std::process::Command::new(SETPRIV);
        command
            .args(["--reuid=65534", "--regid=65534", "--clear-groups"])
            .arg(&exe);
        command
    } else {
        std::process::Command::new(&exe)
    };
    let output = command
        .args(["--exact", "--nocapture", "--ignored", helper])
        .args(paths.iter().map(|path| path.as_os_str()))
        .env_clear()
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output();
    if output.is_err() {
        owner.retain();
    }
    output.expect("run the denial probe child")
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
#[ignore = "probe leg: only the parent test launches it via --ignored"]
fn nobody_write_denial_probe_helper() {
    let args = probe_args();
    let (Some(scope), Some(target)) = (args.first(), args.get(1)) else {
        return;
    };
    match linux::write_once(
        Path::new(scope),
        Path::new(target),
        rivect::executor::write_target_identity(Path::new(scope), Path::new(target))
            .expect("target write identity"),
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
        Ok(_) => std::process::exit(0),
        other => {
            eprintln!("nobody-write unexpected: {other:?}");
            std::process::exit(4);
        }
    }
}

#[test]
fn unwritable_scope_is_an_effect_denial_not_a_capability_failure() {
    ensure_helper();
    // 0o555 stops no root, so the leg runs as a dropped-privilege child:
    // for nobody only DAC denies the write, and the probe must classify
    // it as the typed WriteFailed effect denial, never a capability
    // failure that re-probes on every spawn forever. Flipping the scope
    // mode flips the verdict, so the leg discriminates (EDGE-009).
    let mut fixture = TempTree::new("sandbox-linux", "unwritable-scope");
    let scope = fixture.path.join("scope");
    std::fs::create_dir_all(&scope).expect("create scope");
    set_mode(&scope, 0o755);
    let target = scope.join("target.txt");
    std::fs::write(&target, b"original").expect("create target");
    set_mode(&scope, 0o555);
    let denied = nobody_probe(
        "nobody_write_denial_probe_helper",
        &[&scope, &target],
        &mut fixture,
    );
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
    // DAC admits the control, so the confined write must land.
    set_mode(&scope, 0o777);
    set_mode(&target, 0o666);
    let allowed = nobody_probe(
        "nobody_write_denial_probe_helper",
        &[&scope, &target],
        &mut fixture,
    );
    set_mode(&scope, 0o755);
    assert_eq!(
        allowed.status.code(),
        Some(0),
        "the writable control executes: {allowed:?}"
    );
    assert_eq!(std::fs::read(&target).expect("written target"), b"probe");
}

/// Helper leg for `unreadable_target_is_an_effect_denial_not_a_capability_failure`:
/// with the scope and target paths as filter arguments it runs one read
/// through the real worker and exits 1 when the target is readable (the
/// honest capability failure of an unprivileged environment), 2 for the
/// typed `ReadFailed` denial, 4 for anything else.
#[test]
#[ignore = "probe leg: only the parent test launches it via --ignored"]
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
        Ok(_) => std::process::exit(0),
        other => {
            eprintln!("nobody-read unexpected: {other:?}");
            std::process::exit(4);
        }
    }
}

#[test]
fn unreadable_target_is_an_effect_denial_not_a_capability_failure() {
    ensure_helper();
    // 0o000 stops no root, so the leg runs as a dropped-privilege child:
    // for nobody only DAC denies the read, and the probe must classify
    // it as the typed ReadFailed effect denial, never a capability
    // failure. Flipping the target mode flips the verdict, so the leg
    // discriminates (EDGE-009).
    let mut fixture = TempTree::new("sandbox-linux", "unreadable-target");
    let scope = fixture.path.join("scope");
    std::fs::create_dir_all(&scope).expect("create scope");
    set_mode(&scope, 0o755);
    let target = scope.join("target.txt");
    std::fs::write(&target, b"original").expect("create target");
    set_mode(&target, 0o000);
    let denied = nobody_probe(
        "nobody_read_denial_probe_helper",
        &[&scope, &target],
        &mut fixture,
    );
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
    let allowed = nobody_probe(
        "nobody_read_denial_probe_helper",
        &[&scope, &target],
        &mut fixture,
    );
    assert_eq!(
        allowed.status.code(),
        Some(0),
        "the readable control executes: {allowed:?}"
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
        rivect::executor::WriteIdentity::new(
            rivect::executor::FileIdentity::new(0, 0),
            Err(rivect::executor::Unattested::Unrecorded),
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
fn publish_intent_lands_bytes_through_the_linux_writer() {
    ensure_helper();
    let fixture = TempTree::new("sandbox-linux", "publish-intent-linux");
    let target = fixture.path.join("config.toml");
    let old = support::base_config();
    std::fs::write(&target, &old).expect("seed target");
    let write_witness = fixture.path.join("write-witness");
    let shim = install_helper_io_shim(&fixture.path, &write_witness);
    rivect_sandbox_helper::override_helper_binary(Some(shim));
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            rivect_sandbox_helper::override_helper_binary(None);
        }
    }
    let _reset = Reset;

    let mut store =
        rivect::state::TaskStore::open(&fixture.path.join("state.db")).expect("open store");
    let mut config = rivect::config::Config::parse_validated(&old).expect("valid config");
    let edit = config
        .set("workflow.enabled", rivect::config::ConfigValue::Bool(false))
        .expect("workflow edit");
    let intent = rivect::config::stage_publication(&mut store, "file", &target, &edit)
        .expect("stage publication intent");
    rivect::config::publish_intent(&mut store, &intent, &edit.bytes)
        .expect("linux writer publishes the staged intent");
    assert_eq!(
        std::fs::read(&target).expect("published bytes"),
        edit.bytes,
        "publication must land through the linux writer"
    );
    let recorded = std::fs::read_to_string(&write_witness)
        .expect("confined write must record payload length; a host write produces no witness");
    assert_eq!(
        recorded.trim(),
        edit.bytes.len().to_string(),
        "shim write witness must match the payload length"
    );
    assert_eq!(
        store.pending_publications().expect("pending intents").len(),
        0,
        "receipt completes the journal row"
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
        let mut executor = world.runtime.executor();
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
        let mut executor = world.runtime.executor();
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
        let mut executor = world.runtime.executor();
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
    // Pin the old inode under a sibling name so the recreated occupant
    // cannot reuse its (dev, ino): the swap stays a different file.
    std::fs::hard_link(&file, file.with_file_name("admitted-occupant.pinned"))
        .expect("pin the admitted occupant's inode");
    std::fs::remove_file(&file).expect("remove admitted occupant");
    std::fs::write(&file, b"swapped-occupant").expect("plant swapped occupant");

    let error = {
        let mut executor = world.runtime.executor();
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
    let mut worker = linux::LinuxWorker;

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
        b"scoped-by-landlock",
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
        b"scoped-by-landlock",
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

#[test]
fn allowed_manual_read_executes_through_the_linux_worker() {
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
            attempt_id: attempt_id.clone(),
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
        let (_, state, detail) = world
            .runtime
            .store()
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
fn six_permission_modes_gate_the_linux_worker() {
    ensure_helper();
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

    // Live mode-carrying legs (DEC-016; DEC-018): every mode × class
    // pair runs the real admit→execute path with the mode injected at
    // admit, never admit_managed_write. The executor's own admission
    // context derives in-grant-scope, exec declared bounds, and
    // recorded preapprovals; budget and checkpoint stay unobserved
    // unless tests seed them. Auto exec therefore Allows on an in-scope
    // program; Auto egress Allows when the URL was pre-approved (a
    // recorded approval is the declared bound) and Asks otherwise.
    // Auto write stays Ask without a budget. Allow cells cross the real
    // Linux worker — the read lands, the write lands, the confined exec
    // runs, and an egress Allow cell (auto-with-preapproval /
    // preapproved-only / yolo) meets the OS denial the boundary imposes
    // (an egress target admits no filesystem scope, so it is out of
    // scope by construction); ask and deny cells fail closed at admit
    // and never invoke the worker.
    let mut world = support::open_world("matrix-worker", None);
    let session = world.open_session("matrix-worker-session");
    let task = world.create_task(&session, "matrix-worker-task");
    let scope = world.root.join("scope");
    std::fs::create_dir_all(&scope).expect("create matrix scope");
    let file = scope.join("target.txt");
    std::fs::write(&file, b"scoped-by-landlock").expect("create matrix target");
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
    let write_grant = world.runtime.policy_writer().grant_classes(
        file.parent().expect("scope root").to_path_buf(),
        vec![Class::Write],
    );
    let exec_grant = world
        .runtime
        .policy_writer()
        .grant_classes(PathBuf::from("/usr/bin"), vec![Class::Exec]);
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

/// Helper leg for `degraded_environment_fails_closed_naming_the_mechanism`:
/// with the scope and target paths as filter arguments it runs one read
/// through the real worker and exits 0 only for a capability_unavailable
/// whose reason names the launcher mechanism (`unshare`/`setpriv`).
#[test]
#[ignore = "probe leg: only the parent test launches it via --ignored"]
fn degraded_read_probe_helper() {
    let args = probe_args();
    let (Some(scope), Some(target)) = (args.first(), args.get(1)) else {
        return;
    };
    if std::env::args().any(|arg| arg == "exec-egress") {
        for (label, code, outcome) in [
            (
                "exec",
                5,
                linux::exec_once(Path::new(scope), Path::new("/usr/bin/true")),
            ),
            ("egress", 6, linux::egress_once("http://127.0.0.1:9/")),
        ] {
            match outcome {
                Err(error @ WorkerError::OwnedLaunch { .. }) => {
                    println!(
                        "{}",
                        assert_owned_bootstrap_fault(&error, "owned.namespace.user", 3, 1)
                    );
                    let reason = error.to_string();
                    eprintln!("degraded-{label}: {reason}");
                    if reason.contains("linux user namespace unavailable (unshare --user)")
                        && ExecutorError::Worker(error).error_code()
                            == ErrorCode::CapabilityUnavailable
                    {
                        continue;
                    }
                    std::process::exit(code);
                }
                other => {
                    eprintln!("degraded-{label} unexpected: {other:?}");
                    std::process::exit(code);
                }
            }
        }
        std::process::exit(0);
    }
    match linux::read_once(Path::new(scope), Path::new(target)) {
        Err(error @ WorkerError::OwnedLaunch { .. }) => {
            println!(
                "{}",
                assert_owned_bootstrap_fault(&error, "owned.namespace.user", 3, 1)
            );
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
    // Denying unshare itself reproduces namespace unavailability for any uid.
    ensure_helper();
    let mut fixture = TempTree::new("sandbox-linux", "degraded-env");
    let scope = fixture.path.join("scope");
    std::fs::create_dir_all(&scope).expect("create scope");
    set_mode(&scope, 0o755);
    let target = scope.join("target.txt");
    std::fs::write(&target, b"readable").expect("create target");
    set_mode(&target, 0o644);
    #[cfg(target_arch = "x86_64")]
    let (arch, syscall) = (0xc000_003e_u32, 272_u32);
    #[cfg(target_arch = "aarch64")]
    let (arch, syscall) = (0xc000_00b7_u32, 97_u32);
    let mut bytes = Vec::new();
    // Foreign architectures and every syscall except unshare remain admitted.
    for (code, jt, jf, value) in [
        (0x20_u16, 0_u8, 0_u8, 4_u32),
        (0x15, 0, 3, arch),
        (0x20, 0, 0, 0),
        (0x15, 0, 1, syscall),
        (0x06, 0, 0, 0x0005_0001),
        (0x06, 0, 0, 0x7fff_0000),
    ] {
        bytes.extend_from_slice(&code.to_le_bytes());
        bytes.extend_from_slice(&[jt, jf]);
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    let filter = fixture.path.join("deny-unshare.bpf");
    eprintln!(
        "owned namespace consumer filter: arch={arch} syscall={syscall} flags=268435456 filter={bytes:?}"
    );
    std::fs::write(&filter, bytes).expect("write the namespace-denial filter");
    let mut command = std::process::Command::new(SETPRIV);
    command
        .arg("--nnp")
        .arg("--seccomp-filter")
        .arg(&filter)
        .arg("--")
        .arg(std::env::current_exe().expect("test binary"))
        .args([
            "--exact",
            "--nocapture",
            "--ignored",
            "degraded_read_probe_helper",
        ])
        .arg(&scope)
        .arg(&target)
        .env_clear()
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let out = command.output();
    let exec_egress = command.arg("exec-egress").output();
    if out.is_err() || exec_egress.is_err() {
        fixture.retain();
    }
    let out = out.expect("run the namespace-denied read child");
    let exec_egress = exec_egress.expect("run the namespace-denied controls");
    println!(
        "namespace-denied read custody: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    println!(
        "namespace-denied exec/egress custody: {}",
        String::from_utf8_lossy(&exec_egress.stdout)
    );
    eprintln!("namespace-denied exec/egress: {exec_egress:?}");
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
    for word in [
        "linux user namespace unavailable (unshare --user)",
        "kernel.apparmor_restrict_unprivileged_userns",
        "user.max_user_namespaces",
        "util-linux 2.38",
        "docs/operations/linux-prerequisites.md",
    ] {
        assert!(stderr.contains(word), "missing {word}: {stderr}");
    }
    assert_eq!(
        exec_egress.status.code(),
        Some(0),
        "exec and egress must name namespace unavailability: {exec_egress:?}"
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
            let mut executor = world.runtime.executor();
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
            let mut executor = world.runtime.executor();
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
    ensure_helper();
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
}

#[test]
fn admitted_read_and_write_execute_inside_the_landlock_helper_not_the_host_process() {
    ensure_helper();
    let helper = rivect_sandbox_helper::helper_binary().expect("helper binary");
    assert!(helper.is_file(), "{}", helper.display());
    {
        let mut world = support::open_world("helper-witness", None);
        let session = world.open_session("helper-witness-session");
        let task = world.create_task(&session, "helper-witness-task");
        let scope = world.root.join("scope");
        std::fs::create_dir_all(&scope).expect("scope");
        let file = scope.join("target.txt");
        std::fs::write(&file, b"scoped-by-landlock").expect("seed");
        let grant = world.runtime.set_read_scope(scope.clone(), file.clone());
        world.runtime.read_worker = Box::new(linux::LinuxWorker);
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
                        text.contains("scoped-by-landlock"),
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
        let write_grant = world
            .runtime
            .policy_writer()
            .grant_classes(scope, vec![EffectClass::Write]);
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
        let mut world = support::open_world("helper-missing", None);
        let session = world.open_session("helper-missing-session");
        let task = world.create_task(&session, "helper-missing-task");
        let scope = world.root.join("scope");
        std::fs::create_dir_all(&scope).expect("scope");
        let file = scope.join("target.txt");
        std::fs::write(&file, b"scoped-by-landlock").expect("seed");
        let grant = world.runtime.set_read_scope(scope, file.clone());
        world.runtime.read_worker = Box::new(linux::LinuxWorker);
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
            b"scoped-by-landlock",
            "a missing helper must not host-read or mutate the target"
        );
    }
    let mut world = support::open_world("helper-data-plane", None);
    let session = world.open_session("helper-data-plane-session");
    let task = world.create_task(&session, "helper-data-plane-task");
    let scope = world.root.join("scope");
    std::fs::create_dir_all(&scope).expect("scope");
    let file = scope.join("target.txt");
    std::fs::write(&file, b"scoped-by-landlock").expect("seed");
    let grant = world.runtime.set_read_scope(scope.clone(), file.clone());
    world.runtime.read_worker = Box::new(linux::LinuxWorker);
    {
        let mut command = helper_confined_command("linux", "not-a-mode", "")
            .expect("data-plane confined command");
        // Inner-mode stderr proves `cmd_confined` ran; the wrap argv is
        // what pins launch/unshare/setpriv in the data-plane command.
        assert_eq!(
            command.get_program(),
            helper.as_os_str(),
            "data-plane program must be the helper, got {:?}",
            command.get_program()
        );
        let argv: Vec<std::ffi::OsString> = command
            .get_args()
            .map(std::ffi::OsStr::to_os_string)
            .collect();
        let wrap = [
            std::ffi::OsStr::new("launch"),
            std::ffi::OsStr::new("--"),
            std::ffi::OsStr::new(UNSHARE),
            std::ffi::OsStr::new("--user"),
            std::ffi::OsStr::new("--map-current-user"),
            std::ffi::OsStr::new("--net"),
            std::ffi::OsStr::new("--"),
            std::ffi::OsStr::new(SETPRIV),
            std::ffi::OsStr::new("--nnp"),
            std::ffi::OsStr::new("--seccomp-filter"),
            std::ffi::OsStr::new(""),
            std::ffi::OsStr::new("--"),
            helper.as_os_str(),
            std::ffi::OsStr::new("confined"),
            std::ffi::OsStr::new("linux"),
            std::ffi::OsStr::new("not-a-mode"),
        ];
        assert!(
            {
                let mut rest = argv.iter();
                wrap.iter()
                    .all(|want| rest.any(|got| got.as_os_str() == *want))
            },
            "data-plane argv must wrap launch/unshare/setpriv around confined, got {argv:?}"
        );
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
            EffectOutcome::Read { bytes, .. } => assert_eq!(bytes, b"scoped-by-landlock"),
            other => panic!("expected a helper read, got {other:?}"),
        }
    }
    let write_grant = world
        .runtime
        .policy_writer()
        .grant_classes(scope, vec![EffectClass::Write]);
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
    assert_eq!(std::fs::read(&file).expect("read"), b"from-helper");
}

#[test]
fn run_confined_kills_a_hung_fifo_gate() {
    ensure_helper();
    let mut fixture = TempTree::new("sandbox-linux", "hung-fifo");
    let fifo = fixture.path.join("hung.fifo");
    let status = std::process::Command::new("mkfifo").arg(&fifo).status();
    if status.is_err() {
        fixture.retain();
    }
    let status = status.expect("mkfifo");
    assert!(status.success(), "mkfifo failed: {status}");
    let fixture = support::BorrowedNativeRoot::arm(fixture).expect("arm borrowed FIFO root");
    let confinement = linux::read_confinement(fixture.path()).expect("read confinement");
    let error = confined(&confinement, Path::new("/bin/cat"), &[fifo.as_os_str()])
        .expect_err("a hung fifo must hit the wall deadline");
    let error = fixture
        .finalize(error)
        .expect("verify borrowed FIFO release and close");
    assert!(matches!(error, WorkerError::ConfinedRunTimedOut), "{error}");
}

#[test]
fn linux_exec_seccomp_denies_io_uring_ptrace_process_vm_pidfd_getfd_unshare_bpf_and_mmsg() {
    let numbers = linux::seccomp_denied_syscalls().expect("native seccomp table");
    for n in [425u32, 426, 427, 434, 435, 438] {
        assert!(
            numbers.contains(&n),
            "missing io_uring/pidfd_open/clone3/pidfd_getfd {n}"
        );
    }
    let extras: &[u32] = match std::env::consts::ARCH {
        "aarch64" => &[
            198, 200, 201, 202, 203, 206, 211, 212, 242, 243, 269, 97, 117, 154, 157, 268, 270,
            271, 280,
        ],
        "x86_64" => &[
            41, 42, 43, 44, 46, 47, 49, 50, 288, 299, 307, 101, 109, 112, 272, 308, 310, 311, 321,
        ],
        other => panic!("unexpected arch {other}"),
    };
    for n in extras {
        assert!(numbers.contains(n), "missing syscall {n}");
    }
    // socket()/connect()/sendto()/sendmsg() membership is the egress
    // pin: dropping `socket` from the table would otherwise stay green.
    // socketpair()/recvfrom() stay admitted — Rust std's fork-path
    // Command::spawn exec handshake needs the AF_UNIX pair plus its
    // recvfrom — so their ABSENCE from the denylist is pinned too: an
    // accidental re-denial breaks every Rust child (cargo→rustc).
    let admitted: &[u32] = match std::env::consts::ARCH {
        "aarch64" => &[199, 207],
        "x86_64" => &[53, 45],
        other => panic!("unexpected arch {other}"),
    };
    for n in admitted {
        assert!(
            !numbers.contains(n),
            "syscall {n} must stay admitted for the std spawn handshake"
        );
    }
}

/// Table census above pins the denylist numbers. This probe is the OS
/// enforcement: a confined child that invokes a denied syscall must get
/// EPERM from the filter, not a table membership check.
#[test]
fn confined_exec_denies_unshare_newuser_with_eperm() {
    ensure_helper();
    let mut fixture = TempTree::new("sandbox-linux", "unshare-newuser-eperm");
    let probe = compile_c_probe(
        &fixture.path.clone(),
        "newuser_probe",
        r#"
    #define _GNU_SOURCE
    #include <errno.h>
    #include <sched.h>
    #include <stdio.h>
    #include <unistd.h>
    int main(void) {
        if (unshare(CLONE_NEWUSER) < 0) {
    dprintf(2, "errno=%d\n", errno);
    return errno;
        }
        return 0;
    }
    "#,
        &mut fixture,
    );
    let confinement = linux::exec_confinement(&fixture.path).expect("exec confinement");
    let outcome = confined(&confinement, &probe, &[]).expect("confined unshare probe");
    assert_eperm(&outcome, "unshare(CLONE_NEWUSER)");
}

#[test]
fn landlock_scope_path_with_colon_does_not_break_path_beneath_rule() {
    let fixture = TempTree::new("sandbox-linux", "colon-scope");
    let scope = fixture.path.join("has:colon");
    std::fs::create_dir_all(&scope).expect("colon dir");
    let confinement = linux::read_confinement(&scope).expect("confinement");
    let rules = linux::landlock_rules(&confinement);
    let canon = scope.canonicalize().expect("canon");
    let expected = canon.display().to_string();
    let rule = rules
        .iter()
        .find(|r| r.contains(&expected))
        .expect("scope rule");
    let rest = rule
        .splitn(3, ':')
        .nth(2)
        .expect("remainder after two colons");
    assert_eq!(rest, expected, "{rule}");
}

#[test]
fn confined_read_under_colon_scope_path_is_admitted() {
    ensure_helper();
    let fixture = TempTree::new("sandbox-linux", "colon-scope-run");
    let scope = fixture.path.join("has:colon");
    std::fs::create_dir_all(&scope).expect("colon dir");
    let file = scope.join("inside.txt");
    std::fs::write(&file, b"colon-scope").expect("seed");
    let file = file.canonicalize().expect("canon file");
    let confinement = linux::read_confinement(&scope).expect("confinement");
    let admitted = confined(&confinement, Path::new("/usr/bin/cat"), &[file.as_os_str()])
        .expect("confined read under colon scope");
    assert!(
        admitted.exit_ok,
        "colon in a Landlock scope path must not break the confined execute: {admitted:?}"
    );
}

#[test]
fn linux_exec_denied_control_is_an_owned_artifact_not_agetty_existence() {
    let path = linux::denied_exec_control().expect("owned control");
    assert!(path.is_file(), "{}", path.display());
    let text = path.to_string_lossy();
    assert!(
        text.contains("rivect-denied-exec"),
        "denied control must be worker-owned, got {text}"
    );
    assert!(!text.ends_with("agetty"), "{text}");
}

#[test]
fn loader_execute_rules_do_not_grant_execute_on_usr_lib() {
    let fixture = TempTree::new("sandbox-linux", "loader-execute");
    let confinement = linux::exec_confinement(&fixture.path).expect("exec confinement");
    for rule in linux::landlock_rules(&confinement) {
        if let Some(path) = rule
            .strip_prefix("path-beneath:execute:")
            .or_else(|| rule.strip_prefix("path-beneath:execute,read-file:"))
        {
            assert_ne!(path, "/usr/lib");
            assert_ne!(path, "/lib");
            assert!(!path.ends_with("/usr/lib"), "{rule}");
            assert!(!path.ends_with("/lib"), "{rule}");
        }
    }
}

#[test]
fn live_admission_context_allow_cells_reach_the_linux_worker_when_granting_signals_are_present() {
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
        vec![Class::Read, Class::Write, Class::Egress],
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
    world.runtime.read_worker = Box::new(CountingLinuxWorker {
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
        "Auto egress Allow reached the linux worker once"
    );
}

#[test]
fn confined_exec_glibc_fork_works_because_clone3_returns_enosys() {
    ensure_helper();
    let bash = Path::new("/usr/bin/bash");
    assert!(bash.is_file(), "need /usr/bin/bash");
    let confinement = linux::exec_confinement(Path::new("/usr/bin")).expect("exec confinement");
    let outcome = confined(
        &confinement,
        bash,
        &[
            std::ffi::OsStr::new("-c"),
            std::ffi::OsStr::new("echo ok | /usr/bin/cat"),
        ],
    )
    .expect("confined bash pipeline");
    assert!(
        outcome.exit_ok,
        "glibc fork must work under clone3 ENOSYS: {outcome:?}"
    );
}

fn assert_eperm(outcome: &ConfinedOutcome, what: &str) {
    assert!(
        !outcome.stderr.contains("failed to execute"),
        "{what} must run under confinement, not be Landlock-denied: {outcome:?}"
    );
    assert!(!outcome.exit_ok, "{what} must fail closed, got {outcome:?}");
    let stderr_lower = outcome.stderr.to_ascii_lowercase();
    let from_launcher = stderr_lower.contains("setpriv")
        || stderr_lower.contains("unshare")
        || stderr_lower.contains("sandbox-exec");
    let errno_evidence =
        outcome.stderr.lines().any(|line| line.trim() == "errno=1") && !from_launcher;
    let eperm_evidence = stderr_lower.contains("operation not permitted") && !from_launcher;
    assert!(
        errno_evidence || eperm_evidence,
        "{what} must surface EPERM, got {outcome:?}"
    );
}

/// Compiles a tiny C probe into `dir` and returns the executable path.
fn compile_c_probe(dir: &Path, name: &str, source: &str, owner: &mut TempTree) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let src = dir.join(format!("{name}.c"));
    std::fs::write(&src, source).expect("write C probe");
    let bin = dir.join(name);
    let status = std::process::Command::new("cc")
        .args(["-O0", "-o"])
        .arg(&bin)
        .arg(&src)
        .status();
    if status.is_err() {
        owner.retain();
    }
    let status = status.expect("spawn cc");
    assert!(status.success(), "cc failed for {name}: {status}");
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).expect("chmod C probe");
    bin
}

#[test]
fn confined_exec_denies_setsid_so_a_forked_grandchild_cannot_escape_killpg() {
    ensure_helper();
    let mut fixture = TempTree::new("sandbox-linux", "setsid-eperm");
    // Fork first so the caller is not already a process-group leader
    // (the helper spawned with process_group(0)). The child then calls
    // setsid(); seccomp must return EPERM. The parent exits with that
    // errno so the confined outcome is a nonzero status — not a
    // translated strerror.
    let probe = compile_c_probe(
        &fixture.path.clone(),
        "setsid_probe",
        r#"
    #define _GNU_SOURCE
    #include <errno.h>
    #include <stdio.h>
    #include <sys/wait.h>
    #include <unistd.h>
    int main(void) {
        pid_t pid = fork();
        if (pid < 0) return 1;
        if (pid == 0) {
    if (setsid() < 0) {
        dprintf(2, "errno=%d\n", errno);
        _exit(errno);
    }
    _exit(0);
        }
        int st = 0;
        if (waitpid(pid, &st, 0) < 0) return 1;
        if (WIFEXITED(st)) return WEXITSTATUS(st);
        return 1;
    }
    "#,
        &mut fixture,
    );
    let confinement = linux::exec_confinement(&fixture.path).expect("exec confinement");
    let outcome = confined(&confinement, &probe, &[]).expect("confined setsid probe");
    assert_eperm(&outcome, "setsid after fork");
}

#[test]
fn confined_read_and_write_load_seccomp_so_setsid_is_eperm() {
    ensure_helper();
    let fixture = TempTree::new("sandbox-linux", "rw-setsid-eperm");
    // `setsid -f -w` forks and waits for the child: the child calls
    // setsid() (EPERM under seccomp) and exits 1, the parent returns that
    // status — no custom binary needed, and /usr/bin/setsid already sits
    // inside the read/write legs' system execute allowances.
    let setsid = if Path::new("/usr/bin/setsid").is_file() {
        Path::new("/usr/bin/setsid")
    } else {
        Path::new("/bin/setsid")
    };
    assert!(setsid.is_file(), "need setsid");
    let true_bin = if Path::new("/usr/bin/true").is_file() {
        "/usr/bin/true"
    } else {
        "/bin/true"
    };
    for (name, confinement) in [
        (
            "write",
            linux::write_confinement(&fixture.path).expect("write confinement"),
        ),
        (
            "read",
            linux::read_confinement(&fixture.path).expect("read confinement"),
        ),
    ] {
        let outcome = confined(
            &confinement,
            setsid,
            &[
                std::ffi::OsStr::new("-f"),
                std::ffi::OsStr::new("-w"),
                std::ffi::OsStr::new(true_bin),
            ],
        )
        .unwrap_or_else(|error| panic!("{name}-confined setsid must run: {error}"));
        assert_eperm(&outcome, &format!("{name}-confined setsid"));
    }
}

#[test]
fn confined_run_killpg_on_success_reaps_a_forked_grandchild() {
    ensure_helper();
    let fixture = TempTree::new("sandbox-linux", "killpg-success");
    let pidfile = fixture.path.join("grandchild.pid");
    let sleep = if Path::new("/usr/bin/sleep").is_file() {
        "/usr/bin/sleep"
    } else {
        "/bin/sleep"
    };
    assert!(Path::new(sleep).is_file(), "need sleep");
    let bash = Path::new("/usr/bin/bash");
    assert!(bash.is_file(), "need /usr/bin/bash");
    let script = format!("{sleep} 60 &\necho $! > '{}'\n", pidfile.display());
    let confinement = linux::write_confinement(&fixture.path).expect("write confinement");
    let outcome = confined(
        &confinement,
        bash,
        &[std::ffi::OsStr::new("-c"), std::ffi::OsStr::new(&script)],
    )
    .expect("confined background sleep");
    assert!(
        outcome.exit_ok,
        "the leader must exit successfully so killpg-on-success runs: {outcome:?}"
    );
    let pid = std::fs::read_to_string(&pidfile)
        .expect("grandchild pid")
        .trim()
        .parse::<u32>()
        .expect("pid");
    let proc = PathBuf::from(format!("/proc/{pid}"));
    // Reaped-by-killpg can linger as a zombie (orphaned, reparented to the
    // harness, never wait()ed) and the pid can be recycled by a parallel
    // test's process. Gone, zombie, or a different comm all prove the
    // SIGKILL landed; only a live `sleep` at that pid is a real escape.
    let mut gone = !is_live_sleep(&proc);
    for _ in 0..50 {
        if gone {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
        gone = !is_live_sleep(&proc);
    }
    assert!(
        gone,
        "killpg after the leader exits must reap grandchild pid {pid}"
    );
}

fn is_live_sleep(proc: &Path) -> bool {
    let Ok(stat) = std::fs::read_to_string(proc.join("stat")) else {
        return false;
    };
    let Some(rest) = stat.rsplit(')').nth(1) else {
        return false;
    };
    rest.trim_start().starts_with('S') && stat.contains("(sleep)")
}

#[test]
fn confined_program_runs_as_the_caller_without_capabilities() {
    let mut fixture = TempTree::new("sandbox-linux", "caller-credentials");
    let probe = compile_c_probe(
        &fixture.path.clone(),
        "credentials",
        r#"
    #define _GNU_SOURCE
    #include <linux/capability.h>
    #include <stdio.h>
    #include <stdlib.h>
    #include <sys/syscall.h>
    #include <unistd.h>
    int main(int argc, char **argv) {
        unsigned u = strtoul(argv[1], 0, 10), g = strtoul(argv[2], 0, 10);
        if (argc == 3) {
    struct __user_cap_header_struct h = { _LINUX_CAPABILITY_VERSION_3, 0 };
    struct __user_cap_data_struct d[2];
    if (getuid() != u || geteuid() != u) { dprintf(2, "caller uid mismatch\n"); return 2; }
    if (syscall(SYS_capget, &h, d)) return 3;
    if (u && (d[0].effective || d[1].effective)) return 4;
    return 0;
        }
        const char *paths[] = { "/proc/self/uid_map", "/proc/self/gid_map" };
        unsigned ids[] = {u, g};
        for (int i = 0; i < 2; i++) {
    FILE *f = fopen(paths[i], "r"); unsigned a, b, n; char extra;
    if (!f) return 5;
    int fields = fscanf(f, "%u %u %u", &a, &b, &n);
    int trailing = fscanf(f, " %c", &extra); fclose(f);
    if (fields != 3 || a != ids[i] || b != ids[i] || n != 1 || trailing != EOF) {
        dprintf(2, "invalid or empty %s\n", paths[i]); return 6;
    }
        }
        return 0;
    }
    "#,
        &mut fixture,
    );
    let metadata = std::fs::metadata("/proc/self").expect("process credentials");
    let uid = metadata.uid().to_string();
    let gid = metadata.gid().to_string();
    let args = [std::ffi::OsStr::new(&uid), std::ffi::OsStr::new(&gid)];
    let exec = linux::exec_confinement(&fixture.path).expect("exec confinement");
    let outcome = confined(&exec, &probe, &args).expect("confined credentials");
    assert!(outcome.exit_ok, "caller credentials: {outcome:?}");
    let maps = confined(
        &linux::egress_confinement(),
        &probe,
        &[args[0], args[1], std::ffi::OsStr::new("maps")],
    )
    .expect("confined maps");
    assert!(maps.exit_ok, "caller mapping: {maps:?}");
}

#[test]
fn confined_exec_denies_clone_new_namespace_flags_but_allows_plain_fork() {
    ensure_helper();
    let mut fixture = TempTree::new("sandbox-linux", "clone-flags");
    let fork_ok = compile_c_probe(
        &fixture.path.clone(),
        "clone_fork",
        r#"
    #define _GNU_SOURCE
    #include <sys/syscall.h>
    #include <unistd.h>
    int main(void) {
        long r = syscall(SYS_clone, 17, 0);
        if (r < 0) return 1;
        if (r == 0) _exit(0);
        return 0;
    }
    "#,
        &mut fixture,
    );
    let newpid = compile_c_probe(
        &fixture.path.clone(),
        "clone_newpid",
        r#"
    #define _GNU_SOURCE
    #include <errno.h>
    #include <stdio.h>
    #include <sys/syscall.h>
    #include <unistd.h>
    int main(void) {
        long r = syscall(SYS_clone, 0x20000000 | 17, 0);
        if (r < 0) {
    dprintf(2, "errno=%d\n", errno);
    return errno;
        }
        if (r == 0) _exit(0);
        return 0;
    }
    "#,
        &mut fixture,
    );
    let newipc = compile_c_probe(
        &fixture.path.clone(),
        "clone_newipc",
        r#"
    #define _GNU_SOURCE
    #include <errno.h>
    #include <stdio.h>
    #include <sys/syscall.h>
    #include <unistd.h>
    int main(void) {
        long r = syscall(SYS_clone, 0x08000000 | 17, 0);
        if (r < 0) {
    dprintf(2, "errno=%d\n", errno);
    return errno;
        }
        if (r == 0) _exit(0);
        return 0;
    }
    "#,
        &mut fixture,
    );
    let newuser_newpid = compile_c_probe(
        &fixture.path.clone(),
        "clone_newuser_newpid",
        r#"
    #define _GNU_SOURCE
    #include <errno.h>
    #include <stdio.h>
    #include <sys/syscall.h>
    #include <unistd.h>
    int main(void) {
        long r = syscall(SYS_clone, 0x10000000 | 0x20000000 | 17, 0);
        if (r < 0) {
    dprintf(2, "errno=%d\n", errno);
    return errno;
        }
        if (r == 0) _exit(0);
        return 0;
    }
    "#,
        &mut fixture,
    );
    let unfiltered = std::process::Command::new("/usr/bin/unshare")
        .args(["--user", "--map-current-user", "--net", "--"])
        .arg(&newuser_newpid)
        .env_clear()
        .output()
        .expect("unfiltered control launch");
    assert!(
        unfiltered.status.success(),
        "unfiltered control requires nested user namespaces: {unfiltered:?}"
    );
    let confinement = linux::exec_confinement(&fixture.path).expect("exec confinement");
    let fork_outcome = confined(&confinement, &fork_ok, &[]).expect("confined clone SIGCHLD");
    assert!(
        fork_outcome.exit_ok,
        "plain clone(SIGCHLD) must work: {fork_outcome:?}"
    );
    let newpid_outcome = confined(&confinement, &newpid, &[]).expect("confined clone NEWPID");
    assert_eperm(&newpid_outcome, "clone(CLONE_NEWPID)");
    let newipc_outcome = confined(&confinement, &newipc, &[]).expect("confined clone NEWIPC");
    assert_eperm(&newipc_outcome, "clone(CLONE_NEWIPC)");
    let newuser_newpid_outcome =
        confined(&confinement, &newuser_newpid, &[]).expect("confined clone NEWUSER|NEWPID");
    assert_eperm(&newuser_newpid_outcome, "clone(CLONE_NEWUSER|CLONE_NEWPID)");
}

// ----- confined Cargo check (DEC-040..042, SLICE-178) ----------------------

/// The canonical toolchain cargo this test binary runs under: the CARGO
/// at compile time when its directory also holds `rustc` (the Docker
/// toolchain layout), else the rustup-resolved one.
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

/// The host cargo home the dependency grants root at: the ambient
/// `CARGO_HOME` (the Docker image pins `/usr/local/cargo`), else
/// `$HOME/.cargo`.
fn host_cargo_home() -> PathBuf {
    std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .expect("HOME is set for the test host")
                .join(".cargo")
        })
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
/// under `--locked --offline` (the dependency edge included).
fn check_fixture(tag: &str, answer_text: &str, with_dependency: bool) -> CheckFixture {
    let tree = TempTree::new("confined-check", tag);
    let root = tree.path.clone();
    std::fs::create_dir_all(root.join("src")).expect("src");
    std::fs::create_dir_all(root.join("tests")).expect("tests");
    let (dep_name, dep_version, dep_checksum) = cfg_if_lock_entry();
    let dep_block = if with_dependency {
        format!("\n[dependencies]\n{dep_name} = \"={dep_version}\"\n")
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
            // injection; LD_LIBRARY_PATH is the loader path the
            // toolchain cargo exports for the test binary; PWD is
            // exported by the /bin/sh that runs the fixed namespace
            // script; SSL_CERT_DIR is injected by the rustup proxy that
            // resolves the confined cargo on rustup-shim hosts.
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
/// stable facts digest, so every harness run of a task pins the same
/// revision. The facts are a local, approved-contract change covering
/// every criterion, which the shared gate rule opens without any plan
/// revision: the dispatch claim's transactional `Open` check admits it
/// for real, never through a skipped gate.
fn record_plan_selection(
    world: &mut support::World,
    session: &SessionId,
    task: &rivect::contracts::TaskId,
) -> u64 {
    let config = rivect::config::Config::parse_validated(&support::base_config())
        .expect("harness config parses");
    let criteria: Vec<_> = world
        .runtime
        .store()
        .snapshot(task)
        .expect("the task snapshot")
        .criteria
        .items
        .into_iter()
        .map(|criterion| criterion.id)
        .collect();
    let request = rivect::actions::PlanRequest {
        task_id: task.clone(),
        kind: rivect::actions::RequestKind::Change,
        surfaces: rivect::actions::SurfaceScan::Known([rivect::actions::Surface::Local].into()),
        contract: rivect::actions::ContractBasis::Approved,
        parts: vec![rivect::actions::WorkPart {
            id: "check".to_string(),
            criteria,
            depends_on: Vec::new(),
            proof: "cargo test --test check".to_string(),
        }],
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
    assert_eq!(
        world
            .runtime
            .store()
            .plan_gate(task)
            .expect("the gate reads"),
        rivect::state::PlanGate::Open,
        "the harness selection opens the shared gate for real"
    );
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
    // The sanctioned DEC-048 path: the executor mints the opaque
    // issuer-bound admission; the issuer derives the pair's roots from
    // the admission binding.
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

fn check_error_site(result: &Result<CheckRun, ExecutorError>) -> &'static str {
    match result {
        Err(ExecutorError::Check(error)) => error.site(),
        other => panic!("expected a typed check failure, got {other:?}"),
    }
}

/// Harness-side disposal of one retained attempt root: the product's
/// strict cleanup (DEC-056) refuses the destructive emptying, so the
/// test unseals and removes its own debris.
fn drop_sealed_attempt_root(root: &Path) {
    fn unseal_all(dir: &Path) {
        use std::os::unix::fs::PermissionsExt as _;
        drop(std::fs::set_permissions(
            dir,
            std::fs::Permissions::from_mode(0o700),
        ));
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.filter_map(Result::ok) {
                let path = entry.path();
                if path.is_dir() && !path.is_symlink() {
                    unseal_all(&path);
                }
            }
        }
    }
    if root.is_dir() {
        unseal_all(root);
    }
    drop(std::fs::remove_dir_all(root));
}

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

/// EVID-478, DEC-047 recovery: the Runtime-open reconcile settles an
/// unresolved attempt exactly once and re-decides the cleanup for every
/// surviving root. Three crash windows (journey disposition, pre-return
/// finalisation, recovery row), restart idempotency, no replay, and no
/// fabricated `admit.claim_commit` — every durable row is preserved
/// byte-for-byte, and strict cleanup (DEC-056) refuses each present
/// root before any destructive effect: the debris survives, no
/// `cleanup.root` row lands, and the obligation stays pending. The
/// macOS twin carries the same proof under Seatbelt.
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
        // recovery row, root gone.
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
    drop(world);
    drop_sealed_attempt_root(&unresolved_root);
    drop_sealed_attempt_root(&journey_root);
    drop_sealed_attempt_root(&finalised_root);
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

/// Populates a private cargo home with the cfg-if archive, its nested
/// sparse-index entry, and the registry root descriptor — all copied
/// from the canonical host cache (the bytes keep their lock checksums).
fn populate_fake_registry(cargo_home: &Path, name: &str, version: &str, _checksum: &str) {
    let (archive, _, _, _) = cfg_if_identity();
    let (registry_dir, _, index_root) = registry_layout();
    let cache_dir = cargo_home.join("registry/cache").join(&registry_dir);
    std::fs::create_dir_all(&cache_dir).expect("fake cache dir");
    std::fs::copy(&archive, cache_dir.join(format!("{name}-{version}.crate")))
        .expect("copy archive");

    let index_dir = index_root.join(&registry_dir);
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
    let fake_index_root = cargo_home.join("registry/index").join(&registry_dir);
    let mut dest = fake_index_root.join(".cache");
    for shard in &shards {
        dest = dest.join(shard);
    }
    std::fs::create_dir_all(&dest).expect("fake index dir");
    std::fs::copy(&source, dest.join(name)).expect("copy index entry");
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

/// One fresh control-proof layout: canonical `src`/`rw` roots and the
/// control probe's own executable directory under a private temp tree,
/// with the landlock `CheckRules` for them. The control DATA directory
/// (secret, write target) keeps no read allowance.
fn control_layout(tag: &str) -> (TempTree, linux::CheckRules, PathBuf) {
    let tree = TempTree::new("sandbox-linux", tag);
    let src = tree.path.join("src");
    let rw = tree.path.join("rw");
    let control_bin = tree.path.join("control").join("bin");
    std::fs::create_dir_all(&src).expect("src");
    std::fs::create_dir_all(&rw).expect("rw");
    std::fs::create_dir_all(&control_bin).expect("control bin");
    let rules = linux::CheckRules {
        toolchain: toolchain_cargo()
            .parent()
            .expect("toolchain dir")
            .to_path_buf(),
        snapshot: src.canonicalize().expect("canonical src"),
        rw: rw.canonicalize().expect("canonical rw"),
        test_binaries: false,
    };
    (tree, rules, control_bin)
}

/// The compiled loopback connect probe the network control runs — a real
/// `socket`+`connect` pair `/bin/sh` cannot express.
fn compile_netprobe(dir: &Path, owner: &mut TempTree) -> PathBuf {
    compile_c_probe(
        dir,
        "netprobe",
        r#"
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "usage: netprobe port\n"); return 2; }
    int port = atoi(argv[1]);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return 3; }
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons((short)port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
        perror("connect");
        return 4;
    }
    close(fd);
    return 0;
}
"#,
        owner,
    )
}

/// Runs one deny-first control leg under the real check confinement
/// chain — the same exec allowances the product control set grants — and
/// returns its captured output.
fn run_control_leg(
    rules: &linux::CheckRules,
    control_bin: &Path,
    program: &str,
    args: &[&str],
    owner: &mut TempTree,
) -> rivect::executor::OwnedOutput {
    let args: Vec<std::ffi::OsString> = args.iter().map(std::ffi::OsString::from).collect();
    let exec_paths = [
        PathBuf::from("/bin/cat"),
        PathBuf::from("/bin/sh"),
        control_bin.to_path_buf(),
    ];
    let mut command = linux::check_control_command(rules, Path::new(program), &args, &exec_paths)
        .expect("control command");
    command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let cancel = AtomicBool::new(false);
    let outcome = command.run_check(&cancel);
    if outcome.is_err() {
        owner.retain();
    }
    outcome.expect("the control leg runs")
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
    assert!(
        red.summary.as_deref().unwrap_or("").contains("FAILED"),
        "the bounded cargo summary is captured: {:?}",
        red.summary
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
    assert_eq!(
        green.cleanup,
        CleanupClaim::DescendantsStopped,
        "the PID namespace bounds the group stop"
    );
    assert!(
        green.attempt_root.is_some(),
        "transport success keeps the attempt root in place: the executor never decides the verdict or removes the root (DEC-047), and strict cleanup (DEC-056) refuses the destructive emptying"
    );
    assert!(
        green.vendor_digest.is_none(),
        "a dependency-free run vendors nothing"
    );
    assert_ne!(green.check_digest_v1, green.check_digest_v2);
    drop_sealed_attempt_root(green.attempt_root.as_deref().expect("retained root"));
    drop_sealed_attempt_root(red.attempt_root.as_deref().expect("retained root"));
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
    // The fixture's own panic (a leaked key) travels in the bounded
    // stderr capture — surface it so the failing key is visible.
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
    // made inexpressible): the allocation ended, so the reconsult at
    // the first cache byte refuses before staging or spawn.
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
    // The child-side invisibility proof targets a REGULAR file — the
    // real cfg-if archive from the host cache — because a directory
    // target made /bin/cat fail EISDIR whether or not the boundary
    // denied (the macOS twin's mutant survived exactly that confound).
    ensure_helper();
    let (mut tree, rules, control_bin) = control_layout("registry-invisible");
    let (archive, _, _, _) = cfg_if_identity();
    let archive_arg = archive.to_string_lossy().into_owned();
    let expected = std::fs::read(&archive).expect("unconfined archive bytes");
    let positive = std::process::Command::new("/bin/cat")
        .arg(&archive)
        .env_clear()
        .output()
        .expect("unconfined read");
    assert!(positive.status.success(), "{positive:?}");
    assert_eq!(positive.stdout, expected);
    let denied = run_control_leg(&rules, &control_bin, "/bin/cat", &[&archive_arg], &mut tree);
    let stderr = String::from_utf8_lossy(&denied.stderr);
    assert!(
        !denied.status.success(),
        "the host registry's real archive is invisible to the confined child: {denied:?}"
    );
    assert!(
        stderr.contains("Operation not permitted") || stderr.contains("Permission denied"),
        "the denial carries the OS permission cause, not a kind error: {denied:?}"
    );
    assert!(
        stderr.contains("cat"),
        "the denial names the probe's own operation: {denied:?}"
    );
    assert!(
        !stderr.contains("Is a directory"),
        "a regular-file target cannot fail with EISDIR: {denied:?}"
    );
    drop(tree);
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
    // The nested sparse-index layout opened through pinned fds on a
    // private cargo home: the positive proves the fd anchor reads
    // exactly the authorized nested inode.
    ensure_helper();
    let (_, dep_name, dep_version, dep_checksum) = cfg_if_identity();
    // A tag distinct from the fixture's: TempTree paths key on pid
    // alone, so a shared tag would let the fixture erase the fake home.
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
    // run proves the vendored dependency was really staged and compiled,
    // and the RED→GREEN pair runs with FRESH grants on each side. The
    // Linux staging path (parent-side staged-cargo-home copied into the
    // namespace tmpfs) must deliver the same verified bytes.
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
    drop_sealed_attempt_root(red.attempt_root.as_deref().expect("retained root"));
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
    drop_sealed_attempt_root(green.attempt_root.as_deref().expect("retained root"));
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
fn confined_check_stage_fault_retains_its_site_and_restart_never_respawns() {
    // T4 staging-time fault: a missing archive refuses at dep.cache_missing,
    // the terminal row for that seam survives the attempt-root cleanup,
    // and RE-RUNNING the same admission never reaches staging again —
    // the consumed pair refuses the restart typed at admit.dep.
    ensure_helper();
    let (_, dep_name, dep_version, dep_checksum) = cfg_if_identity();
    let (registry_dir, _, _) = registry_layout();
    // A tag distinct from the fixture's: TempTree paths key on pid
    // alone, so a shared tag would let the fixture erase the populated
    // fake home.
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
    drop_sealed_attempt_root(&rivect::executor::attempt_root_of(&attempt_id));
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
    drop_sealed_attempt_root(&rivect::executor::attempt_root_of(&attempt_id));
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
    // terminal row, rejects the attempt, and decides the root cleanup —
    // the preservation claim below describes the early-return branch
    // where the terminal retention itself collides and the root is
    // deliberately left in place. The second seed makes this test's own
    // root survive deterministically.
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
    // attempt's root with no sibling race, and no phase ever ran (the
    // Linux parent-visible vendor-out never appears).
    let preserved_root = std::env::temp_dir().join(format!("rivect-check-{attempt_id}"));
    assert!(
        std::fs::read_to_string(preserved_root.join("src/answer.txt"))
            .is_ok_and(|text| text == "ok"),
        "the preserved root holds the copied fixture"
    );
    assert!(
        !preserved_root.join("vendor-out").exists(),
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
    drop_sealed_attempt_root(&preserved_root);
}

/// Admits and runs one dependency-free confined check on a freshly
/// recorded selection, through the sanctioned issuer path.
fn run_selector_check(
    world: &mut support::World,
    session: &SessionId,
    task: &rivect::contracts::TaskId,
    fixture: &CheckFixture,
    cargo: PathBuf,
    target: CheckTarget,
    harness_threads: u32,
) -> Result<CheckRun, ExecutorError> {
    let revision = record_plan_selection(world, session, task);
    let project_grant_id = world
        .runtime
        .policy_writer()
        .grant_read(fixture.root().to_path_buf());
    let expected = workspace_digest(fixture.root()).expect("workspace digest");
    let check = ConfinedCheck {
        project_grant_id,
        target,
        harness_threads,
        ..base_check(task, fixture, cargo.clone(), expected, revision)
    };
    let exec_grant = world.runtime.policy_writer().grant_classes(
        check.cargo.parent().expect("toolchain").to_path_buf(),
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
            .expect("admission")
    };
    let mut executor = world.runtime.executor();
    executor.execute_check(&mut admission, &check, &AtomicBool::new(false))
}

#[test]
fn confined_check_selects_the_private_library_target_not_an_integration_substitute() {
    // The typed Library selector reaches the crate's own private
    // `#[cfg(test)]` unit tests through `--lib` under a bounded harness
    // thread count, while the identical bytes under the Integration
    // selector stay RED: the private half expects the live answer and
    // the integration half keeps expecting "ok", so an integration
    // substitute cannot pass the library leg (cause 11 inventory).
    ensure_helper();
    let fixture = check_fixture("lib-selector", "private-marker", false);
    std::fs::write(
        fixture.root().join("src/lib.rs"),
        concat!(
            "pub fn answer() -> &'static str {\n",
            "    include_str!(\"../answer.txt\")\n",
            "}\n",
            "#[test]\n",
            "fn green_passes() {\n",
            "    assert_eq!(crate::answer(), \"private-marker\", \"the private half\");\n",
            "}\n",
        ),
    )
    .expect("lib-selector lib.rs");
    let cargo = toolchain_cargo();
    let mut world = support::open_world("confined-check-lib-selector", None);
    let session = world.open_session("confined-check-lib-selector");
    let task = world.create_task(&session, "lib-selector");
    let lib_run = run_selector_check(
        &mut world,
        &session,
        &task,
        &fixture,
        cargo.clone(),
        CheckTarget::Library,
        2,
    )
    .expect("the library leg completes");
    assert_eq!(
        lib_run.exit_code,
        Some(0),
        "the private library half passes under two harness threads"
    );
    drop_sealed_attempt_root(lib_run.attempt_root.as_deref().expect("retained root"));

    // The same bytes through the Integration selector run the
    // integration half, which still expects "ok" — RED, proving the
    // selector actually switched the executed test binary.
    let mut world = support::open_world("confined-check-int-selector", None);
    let session = world.open_session("confined-check-int-selector");
    let task = world.create_task(&session, "int-selector");
    let int_run = run_selector_check(
        &mut world,
        &session,
        &task,
        &fixture,
        cargo,
        CheckTarget::Integration("check".to_string()),
        2,
    )
    .expect("the integration leg completes");
    assert_ne!(
        int_run.exit_code,
        Some(0),
        "the integration half stays RED on the same bytes — the selector discriminates"
    );
    drop_sealed_attempt_root(int_run.attempt_root.as_deref().expect("retained root"));
}

#[test]
fn confined_check_harness_thread_bound_refuses_out_of_range_before_any_root() {
    // The bounded harness thread count is part of the admission
    // contract: zero and above CHECK_MAX_HARNESS_THREADS refuse typed
    // at admission — before any claim, root, or spawn.
    ensure_helper();
    let fixture = check_fixture("thread-bound", "ok", false);
    let mut world = support::open_world("confined-check-thread-bound", None);
    let session = world.open_session("confined-check-thread-bound");
    let task = world.create_task(&session, "thread-bound");
    let revision = record_plan_selection(&mut world, &session, &task);
    let cargo = toolchain_cargo();
    let expected = workspace_digest(fixture.root()).expect("digest");
    for bound in [0, rivect::executor::CHECK_MAX_HARNESS_THREADS + 1] {
        let check = ConfinedCheck {
            harness_threads: bound,
            ..base_check(&task, &fixture, cargo.clone(), expected.clone(), revision)
        };
        let exec_grant = world.runtime.policy_writer().grant_classes(
            check.cargo.parent().expect("toolchain").to_path_buf(),
            vec![EffectClass::Exec],
        );
        let program = check.cargo.clone();
        let handoff = world.runtime.check_handoff(&task);
        let mut executor = world.runtime.executor();
        let refusal = executor.admit_check(
            &task,
            EffectRequest::Exec {
                grant_id: exec_grant,
                program,
            },
            PermissionMode::Yolo,
            &check,
            &handoff,
        );
        match refusal {
            Err(ExecutorError::Check(CheckError::TargetLayout { detail })) => assert!(
                detail.contains("harness thread bound"),
                "the refusal names the bound: {detail}"
            ),
            other => unreachable!("bound {bound} must refuse typed, got {other:?}"),
        }
    }
}

#[test]
fn confined_check_enrolled_deny_outranks_active_grants_before_the_claim() {
    // The deny-first reconsult (DEC-054): an enrolled deny on the
    // project root outranks the active Read grant and the Yolo mode at
    // the pre-claim re-verification — the check refuses before any
    // claim, root, copied byte, or spawn, and the legitimate attempt
    // stays planned.
    ensure_helper();
    let fixture = check_fixture("deny-first", "ok", false);
    let mut world = support::open_world("confined-check-deny-first", None);
    let session = world.open_session("confined-check-deny-first");
    let task = world.create_task(&session, "deny-first");
    let revision = record_plan_selection(&mut world, &session, &task);
    let cargo = toolchain_cargo();
    let expected = workspace_digest(fixture.root()).expect("digest");
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
            .expect("the check admits before the deny lands")
    };
    world
        .runtime
        .policy_writer()
        .enroll_deny(
            fixture
                .root()
                .canonicalize()
                .expect("canonical fixture root"),
        )
        .expect("enroll the project-root deny");
    let attempt_id = admitted.bound_attempt_id().to_string();
    let mut executor = world.runtime.executor();
    let refusal = executor.execute_check(&mut admitted, &check, &AtomicBool::new(false));
    match refusal {
        Err(ExecutorError::Check(CheckError::ProjectReadGrant { detail })) => assert!(
            detail.contains("denied the check project read"),
            "the refusal names the denied project read: {detail}"
        ),
        other => unreachable!("an enrolled deny must refuse the check, got {other:?}"),
    }
    assert!(
        !rivect::executor::attempt_root_of(&attempt_id).exists(),
        "the denied check never created an attempt root"
    );
    assert_eq!(
        world
            .runtime
            .store()
            .attempt_state(&attempt_id)
            .expect("attempt state"),
        Some("planned".to_string()),
        "the legitimate attempt stays planned"
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

    // A special file refuses the same way: a FIFO.
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
    // handshake is copied → swap-applied → release (the macOS B4 shape):
    // the watcher flags the snapshot copy, the swapper applies one
    // VERIFIED swap cycle and holds the replacement through the phases,
    // and only the observed swap-applied acknowledgment releases the
    // post-run assertions — a run whose window never opened is a vacuous
    // pass, and a swapper without its own deadline could wait forever on
    // a watcher that missed (T6).
    let marker = format!(
        "zz-aba-marker-{}-{}.txt",
        std::process::id(),
        rivect::contracts::TaskId::generate().0
    );
    std::fs::write(fixture.root().join(&marker), b"bound").expect("write marker");
    let expected = workspace_digest(fixture.root()).expect("digest with marker");
    // The watcher scans for any check root; the unique snapshot marker
    // inside `src` identifies OUR root — the root name is the
    // server-owned attempt id (uuid), no longer pid-prefixed.
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
    // the replacement, VERIFIES it is the live bytes, HOLDS it while the
    // phases consume, then restores. The thread carries its own deadline,
    // so a watcher timeout can never leave it waiting forever.
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
fn confined_check_denies_project_writes_network_and_outside_reads() {
    ensure_helper();
    let (mut tree, rules, control_bin) = control_layout("denied-controls");
    let src = rules.snapshot.clone();
    let control = control_bin.parent().expect("control root").to_path_buf();
    // The read control targets a REGULAR secret beside the probe's own
    // executable directory — the old directory target made /bin/cat fail
    // EISDIR whether or not the boundary denied.
    let secret = control.join("secret");
    std::fs::write(&secret, b"host-cache-secret").expect("secret");
    let deny = control.join("deny");
    let probe = compile_netprobe(&control_bin, &mut tree);
    let probe_arg = probe.to_string_lossy().into_owned();

    // Sealed snapshot write target stays intact through the write leg.
    let sealed = src.join("sealed.txt");
    std::fs::write(&sealed, b"sealed").expect("sealed file");

    // Both probes prove themselves UNCONFINED first: a broken probe would
    // make every confined leg "succeed at failing".
    let read_ok = std::process::Command::new("/bin/cat").arg(&secret).output();
    if read_ok.is_err() {
        tree.retain();
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
        tree.retain();
    }
    let connected = connected.expect("unconfined network probe");
    assert!(
        connected.status.success(),
        "the compiled network probe connects unconfined: {}",
        String::from_utf8_lossy(&connected.stderr)
    );

    // Write outside rw denied with its own cause and target.
    let denied = run_control_leg(
        &rules,
        &control_bin,
        "/bin/sh",
        &["-c", &format!("echo x > {}", deny.display())],
        &mut tree,
    );
    let stderr = String::from_utf8_lossy(&denied.stderr);
    assert!(
        !denied.status.success(),
        "a write outside rw is denied: {denied:?}"
    );
    assert!(
        stderr.contains("Operation not permitted") || stderr.contains("Permission denied"),
        "the write denial is the OS boundary's: {denied:?}"
    );
    assert!(!deny.exists(), "the denied write target was never created");
    assert_eq!(
        std::fs::read(&sealed).expect("sealed file intact"),
        b"sealed"
    );

    // A write INTO the sealed snapshot itself is denied the same way:
    // the snapshot keeps a read-only allowance, so even its own path
    // cannot mutate the sealed candidate (T8 — the write leg used to
    // target only paths outside every root).
    let sealed_target = sealed.to_string_lossy().into_owned();
    let denied = run_control_leg(
        &rules,
        &control_bin,
        "/bin/sh",
        &["-c", &format!("echo x > {}", sealed_target)],
        &mut tree,
    );
    let stderr = String::from_utf8_lossy(&denied.stderr);
    assert!(
        !denied.status.success(),
        "a write into the sealed snapshot is denied: {denied:?}"
    );
    assert!(
        stderr.contains("Operation not permitted") || stderr.contains("Permission denied"),
        "the snapshot write denial is the OS boundary's: {denied:?}"
    );
    assert_eq!(
        std::fs::read(&sealed).expect("sealed bytes unchanged"),
        b"sealed",
        "the sealed snapshot's bytes are unchanged — its digest cannot have moved"
    );

    // Network denied: the compiled socket+connect pair a shell cannot
    // express, refused by the netns/seccomp chain with the probe's own
    // operation.
    let denied = run_control_leg(
        &rules,
        &control_bin,
        &probe_arg,
        &[&port.to_string()],
        &mut tree,
    );
    let stderr = String::from_utf8_lossy(&denied.stderr);
    assert!(
        !denied.status.success(),
        "a network connect is denied: {denied:?}"
    );
    assert!(
        stderr.contains("Operation not permitted") || stderr.contains("Permission denied"),
        "the network denial is the OS boundary's: {denied:?}"
    );
    assert!(
        stderr.contains("socket") || stderr.contains("connect"),
        "the network denial names its own operation: {denied:?}"
    );

    // Read outside the roots denied: the regular secret under the control
    // DATA directory, which keeps no read allowance.
    let secret_arg = secret.to_string_lossy().into_owned();
    let denied = run_control_leg(&rules, &control_bin, "/bin/cat", &[&secret_arg], &mut tree);
    let stderr = String::from_utf8_lossy(&denied.stderr);
    assert!(
        !denied.status.success(),
        "an outside read is denied: {denied:?}"
    );
    assert!(
        stderr.contains("Operation not permitted") || stderr.contains("Permission denied"),
        "the read denial is the OS boundary's: {denied:?}"
    );
    drop(tree);
}

#[test]
fn non_enforcing_mechanism_fails_the_denied_controls_first() {
    // `/bin/true` in the launcher position never confines: it exits 0
    // without running the chain, so the denied-write control leg ADMITS
    // — the discriminator `run_check_controls` fails closed on.
    ensure_helper();
    let fixture = TempTree::new("sandbox-linux", "non-enforcing-check");
    std::fs::create_dir_all(fixture.path.join("rw")).expect("rw");
    let non_enforcing = SandboxLauncher {
        unshare: PathBuf::from("/bin/true"),
        setpriv: PathBuf::from(SETPRIV),
    };
    let confinement = linux::write_confinement(&fixture.path).expect("write confinement");
    let outside = fixture.path.join("outside-deny");
    let script = format!("echo x > {}", outside.display());
    let args = [std::ffi::OsStr::new("-c"), std::ffi::OsStr::new(&script)];
    let admitted = linux::run_confined(&non_enforcing, &confinement, Path::new("/bin/sh"), &args)
        .expect("the non-enforcing control run itself");
    assert!(
        admitted.exit_ok,
        "a non-enforcing mechanism admits the denied control: {admitted:?}"
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
    // Leak the tree: the proxy layout must outlive this block.
    #[expect(
        clippy::mem_forget,
        reason = "the proxy-layout fixture must outlive the block; its TempTree drop would delete it mid-test"
    )]
    std::mem::forget(holder);
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
    let (mut tree, rules, control_bin) = control_layout("linker-exec");
    // An unrelated system binary (outside the toolchain, the linker set,
    // /lib and /usr/lib) is denied execution.
    let denied = run_control_leg(&rules, &control_bin, "/usr/bin/true", &[], &mut tree);
    assert!(
        !denied.status.success(),
        "an unrelated system binary is denied execution: {denied:?}"
    );
    // The production linker executes: the resolved canonical compiler
    // driver is inside the admitted linker set.
    let allowed = run_control_leg(
        &rules,
        &control_bin,
        "/usr/bin/cc",
        &["--version"],
        &mut tree,
    );
    assert!(
        allowed.status.success(),
        "the canonical linker is executable inside the check boundary: {allowed:?}"
    );
    drop(tree);
}

#[test]
fn linux_check_quota_and_descendant_escape_are_bounded() {
    ensure_helper();
    let mut holder = TempTree::new("sandbox-linux", "quota-escape");
    let attempt = holder.path.join("attempt");
    let src = attempt.join("src");
    let rw = attempt.join("rw");
    let probes = holder.path.join("probes");
    std::fs::create_dir_all(&src).expect("src");
    std::fs::create_dir_all(&rw).expect("rw");
    std::fs::create_dir_all(&probes).expect("probes");
    // Quota oracle: many individually sub-cap files (64 MiB each, far
    // under the 512 MiB per-file FSIZE cap) must refuse on the AGGREGATE
    // tmpfs quota with ENOSPC exactly — errno 28, never the EFBIG a
    // per-file FSIZE breach produces — and a total that stays inside
    // the pinned 512 MiB capacity (a single big-file loop could not
    // distinguish the two limits).
    let quota_probe = compile_c_probe(
        &probes,
        "quota_probe",
        r#"
    #define _GNU_SOURCE
    #include <errno.h>
    #include <fcntl.h>
    #include <stdio.h>
    #include <string.h>
    #include <unistd.h>
    #define CHUNK (1 << 20)
    #define FILE_BYTES (64LL << 20)
    #define CAP 536870912LL
    /* The tmpfs pin is 512 MiB +- one block; the slab covers the quota's
     * own metadata accounting without letting a runaway total pass. */
    #define SLACK 65536LL
    static char buf[CHUNK];
    int main(int argc, char **argv) {
        if (argc < 3) { dprintf(2, "usage: quota_probe <dir> <confined|control>\n"); return 2; }
        int control = strcmp(argv[2], "control") == 0;
        long long total = 0;
        int files = 0;
        for (;;) {
    char path[4096];
    snprintf(path, sizeof path, "%s/q%d", argv[1], files);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) { dprintf(2, "OPEN_ERRNO=%d\n", errno); return 3; }
    long long wrote = 0;
    int refusal = 0;
    while (wrote < FILE_BYTES) {
        ssize_t n = write(fd, buf, CHUNK);
        if (n < 0) { refusal = errno; break; }
        wrote += n;
        total += n;
    }
    close(fd);
    if (refusal) {
        if (control) { dprintf(2, "CONTROL_REFUSED errno=%d\n", refusal); return 4; }
        dprintf(1, "QUOTA errno=%d total=%lld files=%d\n", refusal, total, files);
        return (refusal == ENOSPC && files >= 2 && total > 0 && total <= CAP + SLACK) ? 0 : 5;
    }
    files++;
    if (control && files >= 9) {
        /* 9 * 64 MiB passes the confined capacity with no
         * refusal — the non-enforcing control's whole point. */
        dprintf(1, "CONTROL total=%lld files=%d\n", total, files);
        return 0;
    }
        }
    }
    "#,
        &mut holder,
    );
    // Escape oracle: a forked descendant's setsid(2) must fail with
    // EPERM exactly (the seccomp denial, not a missing binary's 127),
    // and a lingering descendant cannot outlive the phase.
    let escape_probe = compile_c_probe(
        &probes,
        "escape_probe",
        r#"
    #define _GNU_SOURCE
    #include <errno.h>
    #include <stdio.h>
    #include <sys/wait.h>
    #include <unistd.h>
    int main(void) {
        pid_t escapee = fork();
        if (escapee < 0) return 2;
        if (escapee == 0) {
    int refused = setsid() < 0;
    dprintf(1, "SETSID_ERRNO=%d\n", refused ? errno : 0);
    _exit(refused ? errno : 0);
        }
        int status = 0;
        if (waitpid(escapee, &status, 0) < 0) return 3;
        int errno_witness = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        pid_t lingerer = fork();
        if (lingerer < 0) return 4;
        if (lingerer == 0) {
    /* pause forever: only the stop machinery may end it — a
     * natural exit would fake the descendant-gone witness. */
    for (;;) pause();
        }
        dprintf(1, "LINGER_PID=%d\n", lingerer);
        return errno_witness == EPERM ? 0 : 5;
    }
    "#,
        &mut holder,
    );
    let rules = linux::CheckRules {
        // The probes directory is this leg's "toolchain": the phase
        // chain must exec the compiled probe through the production
        // namespace/landlock/seccomp chain; every other rule stays
        // production-shaped (the canonical-cargo legs cover the real
        // toolchain case).
        toolchain: probes.canonicalize().expect("canonical probes"),
        snapshot: src.canonicalize().expect("canonical src"),
        rw: rw.canonicalize().expect("canonical rw"),
        test_binaries: false,
    };
    let attempt_canonical = attempt.canonicalize().expect("canonical attempt");
    let rw_canonical = rw.canonicalize().expect("canonical rw");
    let run_probe = |program: &Path, args: &[std::ffi::OsString]| {
        let mut command =
            linux::check_phase_command(&rules, &attempt_canonical, None, program, args)
                .expect("phase command");
        command
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let cancel = AtomicBool::new(false);
        command.run_check(&cancel)
    };

    // Confined: the aggregate quota refuses with ENOSPC exactly.
    let quota_args: Vec<std::ffi::OsString> =
        vec![rw_canonical.as_os_str().to_os_string(), "confined".into()];
    let quota = run_probe(&quota_probe, &quota_args);
    if quota.is_err() {
        holder.retain();
    }
    let quota = quota.expect("the confined probe phase runs");
    let quota_out = String::from_utf8_lossy(&quota.stdout);
    assert!(
        quota.status.success(),
        "the bounded tmpfs stops the runaway writer: {quota:?}\n{quota_out}"
    );
    assert!(
        quota_out.contains("QUOTA errno=28 "),
        "the aggregate refusal is ENOSPC (28), not FSIZE's EFBIG: {quota_out}"
    );
    let refused_total: i64 = quota_out
        .lines()
        .find_map(|line| {
            line.strip_prefix("QUOTA errno=").and_then(|rest| {
                rest.split(' ').find_map(|part| {
                    part.strip_prefix("total=")
                        .and_then(|value| value.parse().ok())
                })
            })
        })
        .unwrap_or(-1);
    assert!(
        refused_total > 0 && refused_total <= 536_870_912 + 65_536,
        "the refused total stays inside the pinned 512 MiB capacity: {quota_out}"
    );

    // Non-enforcing control: the same writer on a plain directory
    // passes the confined capacity with no refusal at all.
    let control_dir = holder.path.join("control-files");
    std::fs::create_dir_all(&control_dir).expect("control dir");
    let control = std::process::Command::new(&quota_probe)
        .arg(&control_dir)
        .arg("control")
        .stdin(std::process::Stdio::null())
        .output();
    if control.is_err() {
        holder.retain();
    }
    let control = control.expect("the control probe runs");
    let control_out = String::from_utf8_lossy(&control.stdout);
    assert!(
        control.status.success(),
        "unconfined, the same writer passes the capacity: {control:?}\n{control_out}"
    );
    assert!(
        control_out.contains("files=9"),
        "the control wrote 9 sub-cap files past 512 MiB aggregate: {control_out}"
    );

    // Confined escape witness: setsid refuses with EPERM exactly.
    let escape = run_probe(&escape_probe, &[]);
    if escape.is_err() {
        holder.retain();
    }
    let escape = escape.expect("the confined probe phase runs");
    let escape_out = String::from_utf8_lossy(&escape.stdout);
    assert!(
        escape.status.success(),
        "the descendant's session escape is denied with EPERM: {escape:?}\n{escape_out}"
    );
    assert!(
        escape_out.contains("SETSID_ERRNO=1\n"),
        "the escape errno witness is EPERM (1), not any nonzero: {escape_out}"
    );
    // Descendant-gone: after the phase chain ends, no live escape_probe
    // process remains. The lingerer paused forever, so only the stop
    // machinery could have ended it — the PID-namespace teardown here,
    // the same totality the executor's killpg stop provides in
    // production. (Linux has no observer RSS leg by design, DEC-040:
    // the aggregate bound is this tmpfs quota plus the check profile
    // rlimits; the sampled group-RSS stop is macOS-only, whose
    // survivor residual DEC-041 records honestly.)
    let mut gone = !any_live_probe("escape_probe");
    for _ in 0..50 {
        if gone {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
        gone = !any_live_probe("escape_probe");
    }
    assert!(
        gone,
        "the lingering descendant must not outlive the phase: {escape_out}"
    );
    drop(holder);
}

/// Whether any live (non-zombie) process with `comm` is running — the
/// host-side witness for descendants of a finished confined phase.
fn any_live_probe(comm: &str) -> bool {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return false;
    };
    for entry in entries.flatten() {
        let Ok(stat) = std::fs::read_to_string(entry.path().join("stat")) else {
            continue;
        };
        // comm sits in parens before the state field; a zombie holds no
        // bytes and no cpu, so only a live state counts as an escape.
        let Some((_, tail)) = stat.split_once('(') else {
            continue;
        };
        let Some((name, rest)) = tail.rsplit_once(')') else {
            continue;
        };
        if name == comm
            && rest
                .trim_start()
                .chars()
                .next()
                .is_some_and(|state| state != 'Z')
        {
            return true;
        }
    }
    false
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

/// Mints one dependency-free check admission through the sanctioned
/// issuer path and returns it with the exact check it binds, so one test
/// can present the same opaque admission to more than one executor.
fn admit_confined_check(
    world: &mut support::World,
    session: &SessionId,
    task: &rivect::contracts::TaskId,
    fixture: &CheckFixture,
) -> (rivect::executor::CheckAdmission, ConfinedCheck) {
    let revision = record_plan_selection(world, session, task);
    let cargo = toolchain_cargo();
    let expected = workspace_digest(fixture.root()).expect("workspace digest");
    let check = ConfinedCheck {
        project_grant_id: world
            .runtime
            .policy_writer()
            .grant_read(fixture.root().to_path_buf()),
        ..base_check(task, fixture, cargo.clone(), expected, revision)
    };
    let exec_grant = world.runtime.policy_writer().grant_classes(
        check.cargo.parent().expect("toolchain dir").to_path_buf(),
        vec![EffectClass::Exec],
    );
    let handoff = world.runtime.check_handoff(task);
    let admission = {
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
            .expect("the sanctioned issuer mints the admission")
    };
    (admission, check)
}

/// The zero-claim, zero-root state a pre-claim refusal must leave its own
/// attempt in: planned, no attempt root, and no attempt-keyed effect,
/// settlement, or cleanup row. The `admit.claim`/`admit.claim_commit`
/// evidence rows stay the caller's to assert — one test seeds them as a
/// prior dispatch's durable residue.
fn assert_attempt_stays_planned(world: &support::World, attempt_id: &str) {
    let store = world.runtime.store();
    assert_eq!(
        store
            .attempt_state(attempt_id)
            .expect("attempt state lookup")
            .as_deref(),
        Some("planned"),
        "a pre-claim refusal never runs or settles the attempt"
    );
    assert!(
        !rivect::executor::attempt_root_of(attempt_id).exists(),
        "a pre-claim refusal never allocates the attempt root"
    );
    for site in ["pre.effect", "close.confirmed", "cleanup.root"] {
        assert!(
            !store
                .has_retained(&check_boundary_id(attempt_id, site))
                .expect("retained lookup"),
            "no attempt-keyed {site} row exists"
        );
    }
}

/// The fixed zero-wait refusal boundary one claim refusal writes: a
/// distinct invocation-scoped row whose suffix is the refusing site.
fn assert_claim_refusal_row(added: &[(String, serde_json::Value)], attempt_id: &str, site: &str) {
    assert_eq!(
        added.len(),
        1,
        "one claim refusal writes exactly one claim-seam row: {added:?}"
    );
    let (boundary, record) = &added[0];
    assert!(
        boundary.ends_with(&format!(":{site}")),
        "the refusal row names its own site: {boundary}"
    );
    assert_eq!(record["site"], site);
    assert_eq!(record["cause"], "claim refused");
    assert!(
        !boundary.contains(attempt_id),
        "the claim-seam row stays invocation-scoped, never attempt-keyed: {boundary}"
    );
    assert_eq!(
        record.as_object().map(serde_json::Map::len),
        Some(3),
        "the row holds only the fixed site, cause, and binding: {record}"
    );
}

/// The attempt rows of this world's store, read through a separate
/// read-only connection so the owner's writer is never touched.
fn attempt_rows(world: &support::World) -> i64 {
    let db = world.runtime.owner().runtime_dir().join("rivect.db");
    let conn =
        rusqlite::Connection::open_with_flags(&db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("read-only store connection");
    conn.query_row("SELECT COUNT(*) FROM attempts", [], |row| row.get(0))
        .expect("count attempt rows")
}

#[cfg(target_os = "linux")]
#[test]
fn confined_check_issuer_authority_cannot_be_spoofed_or_rebound() {
    ensure_helper();
    let fixture = check_fixture("issuer-authority", "ok", false);
    let mut world = support::open_world("confined-check-issuer-authority", None);
    let session = world.open_session("confined-check-issuer-authority");
    let task = world.create_task(&session, "issuer-authority");

    // The positive: the genuine issuer path admits, claims, and really
    // dispatches. The refusals below refuse a live authority, not a
    // broken fixture.
    let admitted = run_confined_check(
        &mut world,
        &session,
        &task,
        fixture.root(),
        false,
        "green_passes",
    )
    .expect("the legitimate issuer path dispatches");
    assert_eq!(
        admitted.exit_code,
        Some(0),
        "the admitted candidate is GREEN"
    );
    assert_eq!(admitted.signal, None);
    let attempts_after_positive = attempt_rows(&world);
    let admitted_root = admitted
        .attempt_root
        .expect("the admitted transport retains its root");

    // The Runtime handoff is not portable: another Runtime's handoff and
    // a handoff issued for another task refuse at the mint, before any
    // attempt row, grant use, or effect on this runtime.
    let cargo = toolchain_cargo();
    let mut peer = support::open_world("confined-check-issuer-authority-peer", None);
    let peer_session = peer.open_session("confined-check-issuer-authority-peer");
    let peer_task = peer.create_task(&peer_session, "issuer-authority-peer");
    let peer_handoff = peer.runtime.check_handoff(&peer_task);
    let other_task = world.create_task(&session, "issuer-authority-other");
    let other_handoff = world.runtime.check_handoff(&other_task);
    let unbound = base_check(
        &task,
        &fixture,
        cargo.clone(),
        "unused before the handoff gate".to_string(),
        0,
    );
    let spoof_grant = world.runtime.policy_writer().grant_classes(
        cargo.parent().expect("toolchain dir").to_path_buf(),
        vec![EffectClass::Exec],
    );
    for (handoff, what) in [
        (&peer_handoff, "another runtime's"),
        (&other_handoff, "another task's"),
    ] {
        let error = {
            let mut executor = world.runtime.executor();
            executor
                .admit_check(
                    &task,
                    EffectRequest::Exec {
                        grant_id: spoof_grant.clone(),
                        program: cargo.clone(),
                    },
                    PermissionMode::Yolo,
                    &unbound,
                    handoff,
                )
                .expect_err("a spoofed handoff never mints")
        };
        assert!(
            matches!(
                &error,
                ExecutorError::Check(CheckError::SelectionMismatch { .. })
            ),
            "{what} handoff must refuse typed, got {error:?}"
        );
        assert_eq!(
            check_error_site(&Err(error)),
            "admit.selection",
            "the spoofed handoff keeps its own mint boundary"
        );
    }
    assert_eq!(
        attempt_rows(&world),
        attempts_after_positive,
        "a spoofed handoff never plans an attempt, grant use, or effect"
    );

    // The genuine admission the next legs try to forge, rebind, and
    // revive. Minting allocates nothing durable yet.
    let (mut admission, check) = admit_confined_check(&mut world, &session, &task, &fixture);
    let attempt_id = admission.bound_attempt_id().to_string();
    assert_attempt_stays_planned(&world, &attempt_id);
    for site in ["admit.claim", "admit.claim_commit"] {
        assert!(
            !world
                .runtime
                .store()
                .has_retained(&check_boundary_id(&attempt_id, site))
                .expect("retained lookup"),
            "the mint writes no {site} evidence"
        );
    }
    let before = rejection_rows(&world);

    // A foreign admission: the same opaque admission presented through
    // another Runtime's executor refuses at the issuer gate before any
    // claim, root, byte, or spawn — and disposes nothing of its own
    // allocation, so the issuing pair stays live for the rebind below.
    let foreign = {
        let mut executor = peer.runtime.executor();
        executor.execute_check(&mut admission, &check, &AtomicBool::new(false))
    };
    assert!(
        matches!(
            &foreign,
            Err(ExecutorError::Check(CheckError::Claim {
                site: "admit.issuer",
                ..
            }))
        ),
        "a foreign Runtime's executor must refuse the admission, got {foreign:?}"
    );
    assert_eq!(check_error_site(&foreign), "admit.issuer");
    assert_eq!(
        admission.phase(),
        rivect::executor::CheckPhase::Pending,
        "a foreign presentation never spends the holder's admission"
    );
    assert_eq!(
        rejection_rows(&world),
        before,
        "the foreign refusal records nothing on the issuing store"
    );
    assert!(
        rejection_rows(&peer).is_empty(),
        "the foreign refusal records nothing on the presenting store"
    );
    assert_attempt_stays_planned(&world, &attempt_id);

    // A rebound admission: the same legitimate admission presented with a
    // check rebound to another candidate refuses at the binding gate and
    // records its own invocation-scoped boundary.
    let rebound = ConfinedCheck {
        expected_candidate_digest: "another candidate".to_string(),
        ..check.clone()
    };
    let rebound_error = {
        let mut executor = world.runtime.executor();
        executor.execute_check(&mut admission, &rebound, &AtomicBool::new(false))
    };
    assert_eq!(
        check_error_site(&rebound_error),
        "admit.binding",
        "a rebound candidate refuses at its own binding boundary"
    );
    assert_eq!(
        admission.phase(),
        rivect::executor::CheckPhase::Spent,
        "the refusal spends only the presentation's own allocation"
    );
    assert_preclaim_denial(&world, &admission, &before, "admit.binding");
    assert_attempt_stays_planned(&world, &attempt_id);

    // A spent admission can never be revived: every later presentation
    // names the issuer gate and adds no second row.
    let after_binding = rejection_rows(&world);
    let spent = {
        let mut executor = world.runtime.executor();
        executor.execute_check(&mut admission, &check, &AtomicBool::new(false))
    };
    assert_eq!(
        check_error_site(&spent),
        "admit.issuer",
        "a spent admission refuses at the issuer gate, never a claim"
    );
    assert_eq!(
        admission.phase(),
        rivect::executor::CheckPhase::Spent,
        "the spent gate never re-opens the allocation"
    );
    assert_eq!(
        rejection_rows(&world),
        after_binding,
        "the spent gate adds no second boundary row"
    );
    assert_attempt_stays_planned(&world, &attempt_id);
    assert!(
        !rivect::executor::attempt_root_of(&attempt_id).exists(),
        "no refused presentation ever allocated the attempt root"
    );
    drop_sealed_attempt_root(&admitted_root);
}

#[cfg(target_os = "linux")]
#[test]
fn confined_check_issuer_claim_is_atomic_and_prevents_all_replay() {
    ensure_helper();
    let fixture = check_fixture("issuer-claim", "ok", false);
    let mut world = support::open_world("confined-check-issuer-claim", None);
    let session = world.open_session("confined-check-issuer-claim");
    let task = world.create_task(&session, "issuer-claim");
    let (mut admission, check) = admit_confined_check(&mut world, &session, &task, &fixture);
    let attempt_id = admission.bound_attempt_id().to_string();
    let marker = check_boundary_id(&attempt_id, "admit.claim");
    assert!(
        !world
            .runtime
            .store()
            .has_retained(&marker)
            .expect("retained lookup"),
        "the planned attempt carries no claim marker before its dispatch"
    );

    // One admitted dispatch: the first-only claim commits, the attempt
    // moves planned→running once, and the candidate really runs.
    let run = {
        let mut executor = world.runtime.executor();
        executor
            .execute_check(&mut admission, &check, &AtomicBool::new(false))
            .expect("the one admitted dispatch succeeds")
    };
    assert_eq!(run.exit_code, Some(0), "the admitted candidate is GREEN");
    assert_eq!(
        admission.phase(),
        rivect::executor::CheckPhase::Claimed,
        "the owning dispatch holds the claimed phase"
    );
    assert_eq!(
        world
            .runtime
            .store()
            .attempt_state(&attempt_id)
            .expect("attempt state lookup")
            .as_deref(),
        Some("running"),
        "the claim performed exactly one planned→running transition"
    );
    let committed_marker = world
        .runtime
        .store()
        .retained(&marker)
        .expect("marker lookup")
        .expect("the first-only claim marker is durable");
    let marker_record: serde_json::Value =
        serde_json::from_str(&committed_marker).expect("the marker record decodes");
    assert_eq!(marker_record["site"], "admit.claim");
    assert_eq!(marker_record["attempt"], attempt_id);
    assert!(
        !world
            .runtime
            .store()
            .has_retained(&check_boundary_id(&attempt_id, "admit.claim_commit"))
            .expect("retained lookup"),
        "a committed claim leaves no ambiguous-commit evidence"
    );
    let root = run
        .attempt_root
        .expect("the admitted transport retains its root");
    assert!(root.is_dir(), "the admitted dispatch allocated its root");

    // Harness-side disposal of the admitted attempt's own root debris: the
    // replay below must not recreate it.
    drop_sealed_attempt_root(&root);

    // A second dispatch of the same admission never spawns and never
    // claims twice: the claimed phase refuses typed, writes nothing, and
    // leaves the single durable marker byte-identical.
    let before_replay = rejection_rows(&world);
    let replay = {
        let mut executor = world.runtime.executor();
        executor.execute_check(&mut admission, &check, &AtomicBool::new(false))
    };
    assert_eq!(
        check_error_site(&replay),
        "admit.replay",
        "the same admission never dispatches twice"
    );
    assert_eq!(
        admission.phase(),
        rivect::executor::CheckPhase::Claimed,
        "a replayed presentation keeps the owning phase"
    );
    assert_eq!(
        world
            .runtime
            .store()
            .attempt_state(&attempt_id)
            .expect("attempt state lookup")
            .as_deref(),
        Some("running"),
        "the replay never claims or settles the attempt"
    );
    assert_eq!(
        world
            .runtime
            .store()
            .retained(&marker)
            .expect("marker lookup"),
        Some(committed_marker),
        "the one committed claim marker survives byte-identical"
    );
    assert_eq!(
        rejection_rows(&world),
        before_replay,
        "the claimed-phase replay writes no new boundary row"
    );
    assert!(
        !root.exists(),
        "the replay never reallocates the attempt root"
    );
    assert!(
        !rivect::executor::attempt_root_of(&attempt_id).exists(),
        "no attempt root exists after the replay"
    );

    // A durable first-only marker from a crashed prior dispatch: a fresh
    // presentation bound to that attempt is refused by the store's own
    // marker read, before any root or spawn, and writes its own claim
    // refusal row.
    let (mut restarted, restarted_check) =
        admit_confined_check(&mut world, &session, &task, &fixture);
    let restarted_attempt = restarted.bound_attempt_id().to_string();
    let replayed_marker = check_boundary_id(&restarted_attempt, "admit.claim");
    world
        .runtime
        .store_writer()
        .retain_attempt(&rivect::verification::RetainedAttempt {
            attempt_id: restarted_attempt.clone(),
            boundary_id: replayed_marker.clone(),
            stage: rivect::verification::RetainedStage::Terminal,
            cause: "the prior dispatch committed its first-only claim".to_string(),
            digest: rivect::verification::record_digest(&restarted_attempt, "prior claim"),
            build_attempt: restarted_attempt.clone(),
            admitted_attempt_id: Some(restarted_attempt.clone()),
        })
        .expect("seed the prior dispatch's durable claim marker");
    let seeded_marker = world
        .runtime
        .store()
        .retained(&replayed_marker)
        .expect("marker lookup")
        .expect("the seeded marker is durable");
    let before_claim_refusal = rejection_rows(&world);
    let refused = {
        let mut executor = world.runtime.executor();
        executor.execute_check(&mut restarted, &restarted_check, &AtomicBool::new(false))
    };
    assert_eq!(
        check_error_site(&refused),
        "admit.replay",
        "the durable claim marker refuses the replay at the store's claim"
    );
    assert_eq!(
        restarted.phase(),
        rivect::executor::CheckPhase::Spent,
        "a claim refusal releases only its own allocation"
    );
    assert_attempt_stays_planned(&world, &restarted_attempt);
    assert!(
        !world
            .runtime
            .store()
            .has_retained(&check_boundary_id(&restarted_attempt, "admit.claim_commit"))
            .expect("retained lookup"),
        "the store refused before any ambiguous-commit path"
    );
    let added: Vec<_> = rejection_rows(&world)
        .into_iter()
        .filter(|row| !before_claim_refusal.contains(row))
        .collect();
    assert_claim_refusal_row(&added, &restarted_attempt, "admit.replay");
    assert_eq!(
        world
            .runtime
            .store()
            .retained(&replayed_marker)
            .expect("marker lookup"),
        Some(seeded_marker.clone()),
        "the durable marker survives the refusal byte-identical"
    );

    // The spent admission cannot be revived: the issuer gate names itself
    // and adds no second boundary.
    let before_spent = rejection_rows(&world);
    let spent = {
        let mut executor = world.runtime.executor();
        executor.execute_check(&mut restarted, &restarted_check, &AtomicBool::new(false))
    };
    assert_eq!(
        check_error_site(&spent),
        "admit.issuer",
        "a spent admission refuses at the issuer gate after the claim replay"
    );
    assert_eq!(
        rejection_rows(&world),
        before_spent,
        "the spent gate adds no second boundary row"
    );
    assert_attempt_stays_planned(&world, &restarted_attempt);
    assert_eq!(
        world
            .runtime
            .store()
            .retained(&replayed_marker)
            .expect("marker lookup"),
        Some(seeded_marker),
        "the replayed marker stays byte-identical through the spent gate"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn confined_check_issuer_fault_sites_survive_cleanup_without_collision() {
    ensure_helper();
    let fixture = check_fixture("issuer-sites", "ok", false);
    let mut world = support::open_world("confined-check-issuer-sites", None);
    let session = world.open_session("confined-check-issuer-sites");
    let task = world.create_task(&session, "issuer-sites");

    // Fault 1 (issue authority): a foreign presentation refuses at
    // admit.issuer before any claim or root and records nothing; the same
    // admission with a rebound binding then refuses at its own
    // admit.binding boundary. Both are distinct typed sites on the same
    // attempt, never one aliased boundary.
    let mut peer = support::open_world("confined-check-issuer-sites-peer", None);
    let (mut authority, authority_check) =
        admit_confined_check(&mut world, &session, &task, &fixture);
    let authority_attempt = authority.bound_attempt_id().to_string();
    let before = rejection_rows(&world);
    let foreign = {
        let mut executor = peer.runtime.executor();
        executor.execute_check(&mut authority, &authority_check, &AtomicBool::new(false))
    };
    assert!(
        matches!(
            &foreign,
            Err(ExecutorError::Check(CheckError::Claim {
                site: "admit.issuer",
                ..
            }))
        ),
        "the issue-authority refusal keeps its own typed boundary, got {foreign:?}"
    );
    assert_eq!(check_error_site(&foreign), "admit.issuer");
    assert_eq!(
        authority.phase(),
        rivect::executor::CheckPhase::Pending,
        "the foreign presentation disposes no issuing allocation"
    );
    assert_eq!(
        rejection_rows(&world),
        before,
        "the issue-authority refusal records nothing on the issuing store"
    );
    assert!(
        rejection_rows(&peer).is_empty(),
        "the issue-authority refusal records nothing on the presenting store"
    );
    assert_attempt_stays_planned(&world, &authority_attempt);

    let rebound = ConfinedCheck {
        expected_candidate_digest: "another candidate".to_string(),
        ..authority_check.clone()
    };
    let binding_error = {
        let mut executor = world.runtime.executor();
        executor.execute_check(&mut authority, &rebound, &AtomicBool::new(false))
    };
    assert_eq!(
        check_error_site(&binding_error),
        "admit.binding",
        "the rebound binding keeps its own typed boundary"
    );
    assert_preclaim_denial(&world, &authority, &before, "admit.binding");
    assert_attempt_stays_planned(&world, &authority_attempt);

    // Fault 2 (claim): a durable ambiguous-COMMIT row from a crashed prior
    // dispatch makes the first-only claim refuse the replay at the store
    // seam. Its own invocation-scoped row lands and the prior evidence
    // stays byte-identical — the refusal deletes nothing it did not write.
    let (mut claimed, claimed_check) = admit_confined_check(&mut world, &session, &task, &fixture);
    let claimed_attempt = claimed.bound_attempt_id().to_string();
    let evidence_boundary = check_boundary_id(&claimed_attempt, "admit.claim_commit");
    world
        .runtime
        .store_writer()
        .retain_attempt(&rivect::verification::RetainedAttempt {
            attempt_id: claimed_attempt.clone(),
            boundary_id: evidence_boundary.clone(),
            stage: rivect::verification::RetainedStage::Terminal,
            cause: "admit.claim_commit: transaction_ended=true primary=5".to_string(),
            digest: rivect::verification::record_digest(&claimed_attempt, "ambiguous commit"),
            build_attempt: claimed_attempt.clone(),
            admitted_attempt_id: Some(claimed_attempt.clone()),
        })
        .expect("seed the prior ambiguous-COMMIT evidence");
    let evidence = world
        .runtime
        .store()
        .retained(&evidence_boundary)
        .expect("evidence lookup")
        .expect("the seeded evidence is durable");
    let before_claim = rejection_rows(&world);
    let claim_error = {
        let mut executor = world.runtime.executor();
        executor.execute_check(&mut claimed, &claimed_check, &AtomicBool::new(false))
    };
    assert_eq!(
        check_error_site(&claim_error),
        "admit.replay",
        "the durable ambiguous-COMMIT evidence refuses the claim replay"
    );
    assert_eq!(
        claimed.phase(),
        rivect::executor::CheckPhase::Spent,
        "the claim refusal releases only its own allocation"
    );
    assert_attempt_stays_planned(&world, &claimed_attempt);
    assert!(
        !world
            .runtime
            .store()
            .has_retained(&check_boundary_id(&claimed_attempt, "admit.claim"))
            .expect("retained lookup"),
        "the refused claim writes no marker of its own"
    );
    assert_eq!(
        world
            .runtime
            .store()
            .retained(&evidence_boundary)
            .expect("evidence lookup"),
        Some(evidence.clone()),
        "the prior ambiguous-COMMIT evidence survives the refusal byte-identical"
    );
    let claim_added: Vec<_> = rejection_rows(&world)
        .into_iter()
        .filter(|row| !before_claim.contains(row))
        .collect();
    assert_claim_refusal_row(&claim_added, &claimed_attempt, "admit.replay");

    // The two seams never alias: one invocation-scoped row per refusal,
    // each naming only its own site, with distinct identities — and the
    // seeded evidence is still its own separate, untouched row.
    let added: Vec<_> = rejection_rows(&world)
        .into_iter()
        .filter(|row| !before.contains(row))
        .collect();
    assert_eq!(
        added.len(),
        2,
        "two refused seams wrote two distinct rows: {added:?}"
    );
    let binding_row = added
        .iter()
        .find(|(_, record)| record["site"] == "admit.binding")
        .expect("the binding refusal row");
    let claim_row = added
        .iter()
        .find(|(_, record)| record["site"] == "admit.replay")
        .expect("the claim refusal row");
    assert_ne!(
        binding_row.0, claim_row.0,
        "two seams never share one rejection boundary"
    );
    assert!(
        binding_row.0.ends_with(":admit.binding"),
        "the binding row names its own boundary: {}",
        binding_row.0
    );
    assert!(
        claim_row.0.ends_with(":admit.replay"),
        "the claim row names its own boundary: {}",
        claim_row.0
    );
    assert_eq!(binding_row.1["cause"], "pre-claim refusal");
    assert_eq!(claim_row.1["cause"], "claim refused");
    for (boundary, record) in &added {
        let site = record["site"].as_str().expect("the row names its site");
        for other in ["admit.issuer", "admit.binding", "admit.replay"] {
            if other != site {
                assert!(
                    !boundary.ends_with(&format!(":{other}")),
                    "the {site} row never aliases {other}: {boundary}"
                );
            }
        }
    }
    assert!(
        !added
            .iter()
            .any(|(boundary, _)| boundary.contains(&authority_attempt)
                || boundary.contains(&claimed_attempt)),
        "no refusal row forges an attempt-keyed boundary: {added:?}"
    );

    // Cleanup and re-presentation: both refusals stay typed at the issuer
    // gate, the rows and the seeded evidence survive unchanged, and the
    // attempts keep zero claim, zero root, and zero settlement.
    let after = rejection_rows(&world);
    for (admission, check) in [
        (&mut authority, &authority_check),
        (&mut claimed, &claimed_check),
    ] {
        let spent = {
            let mut executor = world.runtime.executor();
            executor.execute_check(admission, check, &AtomicBool::new(false))
        };
        assert_eq!(
            check_error_site(&spent),
            "admit.issuer",
            "a spent admission still names the issuer gate"
        );
        assert_eq!(
            admission.phase(),
            rivect::executor::CheckPhase::Spent,
            "the spent gate never revives the allocation"
        );
    }
    assert_eq!(
        rejection_rows(&world),
        after,
        "the spent retries add no second boundary row"
    );
    assert_eq!(
        world
            .runtime
            .store()
            .retained(&evidence_boundary)
            .expect("evidence lookup"),
        Some(evidence),
        "the seeded evidence survives every later refusal byte-identical"
    );
    assert_attempt_stays_planned(&world, &authority_attempt);
    assert_attempt_stays_planned(&world, &claimed_attempt);
    for attempt_id in [&authority_attempt, &claimed_attempt] {
        drop_sealed_attempt_root(&rivect::executor::attempt_root_of(attempt_id));
    }
    for attempt_id in [&authority_attempt, &claimed_attempt] {
        assert!(
            !rivect::executor::attempt_root_of(attempt_id).exists(),
            "no refused presentation allocated an attempt root"
        );
    }
}

#[test]
fn confined_check_cancellation_refuses_typed_and_retains_the_site() {
    ensure_helper();
    let fixture = check_fixture("cancel", "ok", false);
    let mut world = support::open_world("confined-check-cancel", None);
    let session = world.open_session("confined-check-cancel");
    let task = world.create_task(&session, "cancel");
    let cargo = toolchain_cargo();
    let expected = workspace_digest(fixture.root()).expect("digest");
    let revision = record_plan_selection(&mut world, &session, &task);
    let mut check = base_check(&task, &fixture, cargo.clone(), expected, revision);
    check.project_grant_id = world
        .runtime
        .policy_writer()
        .grant_read(fixture.root().to_path_buf());
    let exec_grant = world.runtime.policy_writer().grant_classes(
        cargo.parent().expect("toolchain").to_path_buf(),
        vec![EffectClass::Exec],
    );
    let before = rejection_rows(&world);
    let (error, admitted) = {
        let handoff = world.runtime.check_handoff(&task);
        let mut executor = world.runtime.executor();
        let mut admitted = executor
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
            .expect("admit");
        // Cancellation is raised before the run: the check refuses
        // typed before the claim, never starts a phase, and records
        // only the invocation-scoped denial — the planned attempt is
        // neither claimed nor settled.
        let error = executor.execute_check(&mut admitted, &check, &AtomicBool::new(true));
        (error, admitted)
    };
    assert!(
        matches!(
            &error,
            Err(ExecutorError::Check(CheckError::VendorCancel { .. }))
        ),
        "the cancelled check refuses typed before the snapshot: {error:?}"
    );
    assert_preclaim_denial(&world, &admitted, &before, "vendor.cancel");
}

#[test]
fn owned_launch_check_cold_cargo_preserves_spawn_handshake() {
    ensure_helper();
    let fixture = check_fixture("owned-cold-spawn", "ok", false);
    assert!(!fixture.root().join("target").exists());
    let manifest = std::fs::read_to_string(fixture.root().join("Cargo.toml"))
        .expect("read the dependency-free cold fixture");
    assert!(!manifest.contains("[dependencies]"));
    let mut world = support::open_world("owned-cold-spawn", None);
    let session = world.open_session("owned-cold-spawn");
    let task = world.create_task(&session, "owned-cold-spawn");
    let run = run_confined_check(
        &mut world,
        &session,
        &task,
        fixture.root(),
        false,
        "green_passes",
    )
    .expect("cold cargo must compile and execute through the owned check chain");
    assert_eq!(run.exit_code, Some(0));
    assert_eq!(run.signal, None);
    let stdout = String::from_utf8_lossy(&run.stdout.head);
    let stderr = String::from_utf8_lossy(&run.stderr.head);
    assert!(stderr.contains("Compiling fixture v0.1.0"), "{stderr}");
    assert!(stdout.contains("test green_passes ... ok"), "{stdout}");
    assert!(
        run.summary.as_deref().is_some_and(|summary| summary.starts_with(
            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out; finished in "
        ))
    );
    let root = run
        .attempt_root
        .as_deref()
        .expect("the check owner retains its sealed attempt root");
    assert!(root.is_dir());
    assert_eq!(run.cleanup, CleanupClaim::DescendantsStopped);
    let identity = std::fs::metadata(root).expect("observe the retained check identity");
    println!(
        "owned cold cargo root={root:?} dev={} ino={}\nstdout={stdout}\nstderr={stderr}",
        identity.dev(),
        identity.ino()
    );
    drop_sealed_attempt_root(root);
}
