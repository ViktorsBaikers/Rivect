//! Linux effect backend for the execution world. Exactly one scoped
//! existing-file read or checked-fd managed write per admitted effect;
//! everything else is denied before any byte is touched. Every effect
//! crosses a Landlock/seccomp/netns boundary in a fixed order: a one-time
//! conformance probe proves the boundary denies as well as admits (the
//! denied legs run first and touch only system or worker-owned probe
//! files, so a non-enforcing mechanism is detected before any leg touches
//! the user's target), then a confined OS leg proves the kernel admits
//! this operation inside the scope, and only then does the checked
//! in-process leg move bytes — no ambient path.
//!
//! The confinement launcher composes three kernel mechanisms without any
//! `unsafe` in this crate: `unshare(1)` isolates the network namespace,
//! `setpriv(1)` applies a Landlock ruleset (handled filesystem accesses
//! with per-path allowances, deny-by-default) and the seccomp net-deny
//! filter on every leg that runs a program — pathname AF_UNIX sockets
//! cross the network namespace, so the namespace alone never carries the
//! egress boundary — and `--nnp` pins `no_new_privs` so the filter
//! cannot be escaped through privilege grants.

use super::macos::{FileIdentity, ReadObservation, ReadWorker, WorkerError};
use super::{
    denied_write_candidate, drain_retaining_cap, inspect_regular_target, same_regular_file,
    set_private_mode,
};
use sha2::Digest;
use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs::{File, Metadata};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Mutex, PoisonError};

/// The Landlock/netns launcher, the injected seam the conformance probes
/// key on. Tests substitute shims to prove fail-closed behavior.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SandboxLauncher {
    pub unshare: PathBuf,
    pub setpriv: PathBuf,
}

impl Default for SandboxLauncher {
    fn default() -> Self {
        Self {
            unshare: PathBuf::from(UNSHARE),
            setpriv: PathBuf::from(SETPRIV),
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct LinuxWorker;

impl ReadWorker for LinuxWorker {
    fn read_once(
        &mut self,
        scope_root: &Path,
        target: &Path,
    ) -> Result<ReadObservation, WorkerError> {
        // Confinement is intrinsic to the free functions: the probe and
        // gate run inside them, so every caller crosses the boundary.
        // There is no unconfined variant to call by mistake.
        read_once(scope_root, target)
    }

    fn write_once(
        &mut self,
        scope_root: &Path,
        target: &Path,
        expected: FileIdentity,
        bytes: &[u8],
    ) -> Result<(), WorkerError> {
        write_once(scope_root, target, expected, bytes)
    }

    fn exec_once(&mut self, scope_root: &Path, program: &Path) -> Result<(), WorkerError> {
        exec_once(scope_root, program)
    }

    fn egress_once(&mut self, url: &str) -> Result<(), WorkerError> {
        egress_once(url)
    }
}

/// Canonical denied-control target for the exec leg: a system binary no
/// sane grant scope covers, so a confined execution of it must be denied
/// before the admitted program is touched. A grant scope that already
/// covers this path is not confinable and fails the leg closed.
const DENIED_PROBE_EXEC: &str = "/usr/sbin/agetty";

/// The egress control leg's program (bash): its `/dev/tcp` redirection
/// performs a real connect whose exit status discriminates a held
/// listener (exit 0 on the backlog) from a denied socket syscall.
const BASH: &str = "/usr/bin/bash";

/// One confined process execution inside the granted scope. The denied
/// control leg runs first — the boundary must refuse a known out-of-scope
/// binary before the admitted program is touched — then the confined run
/// of the program is the effect itself: there is no in-process exec leg,
/// so a program the boundary admits is exactly the effect that happened.
/// A bare program's own nonzero exit is indistinguishable from a boundary
/// denial here and denies the effect (the request carries no arguments,
/// so a well-formed probe program exits zero).
///
/// # Errors
/// Returns [`WorkerError::SandboxUnavailable`] when the boundary admits
/// the denied control (it does not enforce) or the confinement cannot be
/// built, [`WorkerError::SandboxSpawnFailed`] when a launcher leg cannot
/// start, and [`WorkerError::SandboxDenied`] when the boundary rejects
/// the program.
pub fn exec_once(scope_root: &Path, program: &Path) -> Result<(), WorkerError> {
    let launcher = SandboxLauncher::default();
    let confinement = exec_confinement(scope_root)?;
    let control = run_confined(&launcher, &confinement, Path::new(DENIED_PROBE_EXEC), &[])?;
    if control.exit_ok {
        return Err(WorkerError::SandboxUnavailable {
            reason: format!(
                "landlock exec boundary admitted the denied control {DENIED_PROBE_EXEC}"
            ),
        });
    }
    let outcome = run_confined(&launcher, &confinement, program, &[])?;
    expect_admitted(outcome, program)
}

/// One egress attempt against the netns/seccomp boundary. This backend
/// grants no egress allowance anywhere, so the confined leg exists to
/// prove the denial is the OS boundary's, never a stub: the denied
/// control leg must fail to reach a listener this worker holds itself
/// (a passthrough mechanism would connect and is a capability failure,
/// caught before any externally visible connect). The control target is
/// worker-owned loopback state, so the requested URL never enters any
/// child argument list; the seccomp filter denies the socket syscall
/// itself for every destination alike.
///
/// # Errors
/// Returns [`WorkerError::SandboxUnavailable`] when the control listener
/// cannot be held or the boundary admits a denied connect, and
/// [`WorkerError::SandboxDenied`] naming the requested URL — the typed
/// form of the OS denial every egress effect meets here.
pub fn egress_once(url: &str) -> Result<(), WorkerError> {
    let listener = bind_control_listener()?;
    let port = listener
        .local_addr()
        .map_err(control_listener_unavailable)?
        .port();
    // `sh -c` justification (standards §10): the command string is built
    // only from the worker's own loopback literal and the numeric port of
    // its own listener — no user input reaches this leg.
    let control_connect = format!("exec 3<>/dev/tcp/127.0.0.1/{port}");
    let control = run_confined(
        &SandboxLauncher::default(),
        &egress_confinement(),
        Path::new(BASH),
        &[OsStr::new("-c"), OsStr::new(&control_connect)],
    )?;
    if control.exit_ok {
        return Err(WorkerError::SandboxUnavailable {
            reason: "netns/seccomp egress boundary admitted the denied control connect".to_string(),
        });
    }
    Err(WorkerError::SandboxDenied {
        target: PathBuf::from(url),
    })
}

/// Binds the egress control listener on loopback.
fn bind_control_listener() -> Result<std::net::TcpListener, WorkerError> {
    std::net::TcpListener::bind(("127.0.0.1", 0)).map_err(control_listener_unavailable)
}

fn control_listener_unavailable(source: std::io::Error) -> WorkerError {
    WorkerError::SandboxUnavailable {
        reason: format!("egress control listener unavailable: {source}"),
    }
}

pub const BACKEND: &str = "linux";

pub const READ_MAX_BYTES: usize = 1 << 20;
pub const WRITE_MAX_BYTES: usize = READ_MAX_BYTES;

/// util-linux `unshare(1)` — the only netns launcher this backend uses.
pub const UNSHARE: &str = "/usr/bin/unshare";

/// util-linux `setpriv(1)` 2.41+ — applies Landlock rulesets, seccomp
/// filters, and `no_new_privs` before executing the confined program.
pub const SETPRIV: &str = "/usr/bin/setpriv";

/// The read leg's confined program (coreutils `cat`).
const CAT: &str = "/usr/bin/cat";

/// The write leg's confined program (coreutils `tee`): it opens its
/// target with `O_WRONLY|O_CREAT|O_TRUNC`, so the write boundary is
/// proven by a real open-for-write — `touch(1)` only calls `utimensat`,
/// which Landlock does not govern and which would prove nothing.
const TEE: &str = "/usr/bin/tee";

/// Canonical probe target for the read boundary's denied leg: world
/// readable, so a denied confined read names enforcement, never
/// filesystem permission. A grant scope that already covers this path is
/// not confinable and fails the probe.
pub const DENIED_PROBE_TARGET: &str = "/etc/hosts";

/// Linux `O_NONBLOCK` (0o4000; no libc dependency here). Opening a FIFO
/// read-only with this flag returns immediately even when no writer holds
/// the other end, so a target swapped to a FIFO between the metadata
/// check and `open(2)` cannot block this worker forever.
const O_NONBLOCK: i32 = 0o4000;

/// Linux `O_NOFOLLOW` (0o400000): the write probe's in-process
/// writability fallback must never open through a symlink planted on the
/// artifact path — a tampered artifact stays a typed denial instead of an
/// ambient write outside the scope.
const O_NOFOLLOW: i32 = 0o400000;

/// One bounded read of an existing regular file inside the canonical scope
/// root. Symlinks that escape the scope are denied via canonicalisation; the
/// opened handle is re-checked as a regular file and for dev/ino identity
/// (fail-closed on swaps), and the FIFO-before-open window is bounded by an
/// `O_NONBLOCK` open. Confinement is intrinsic: the conformance probe runs
/// first, then the confined read gate, and only then does the checked
/// in-process leg open anything.
///
/// # Errors
/// Returns the worker's typed effect denials for targets this process
/// cannot observe, and [`WorkerError::SandboxUnavailable`] /
/// [`WorkerError::SandboxSpawnFailed`] when the confinement mechanism
/// itself cannot start or does not enforce.
pub fn read_once(scope_root: &Path, target: &Path) -> Result<ReadObservation, WorkerError> {
    let (canonical_target, canonical_meta) = inspect_regular_target(scope_root, target)?;
    if canonical_meta.len() > READ_MAX_BYTES as u64 {
        return Err(WorkerError::TooLarge);
    }
    let launcher = SandboxLauncher::default();
    probe_read_conformance(&launcher, scope_root, &canonical_target)?;
    confined_read_gate(&launcher, scope_root, &canonical_target)?;
    // The open re-walks the original path without O_NOFOLLOW: a swap to a
    // different regular file is caught by the dev/ino identity check below
    // (fail-closed), and a swap to a FIFO cannot hang this bounded open
    // (O_NONBLOCK) before the fd-level regular-file check denies it.
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(O_NONBLOCK)
        .open(target)
        .map_err(|source| WorkerError::ReadFailed { source })?;
    let opened_meta = file
        .metadata()
        .map_err(|source| WorkerError::MetadataUnavailable { source })?;
    if !opened_meta.is_file() {
        return Err(WorkerError::NotRegularFile {
            target: target.to_path_buf(),
        });
    }
    // Hardlinks inside the granted scope share dev+inode and remain allowed.
    if !same_regular_file(&canonical_meta, &opened_meta) {
        return Err(WorkerError::TargetChanged {
            target: target.to_path_buf(),
        });
    }
    if opened_meta.len() > READ_MAX_BYTES as u64 {
        return Err(WorkerError::TooLarge);
    }
    let mut bounded = Vec::with_capacity(opened_meta.len() as usize);
    file.take((READ_MAX_BYTES as u64) + 1)
        .read_to_end(&mut bounded)
        .map_err(|source| WorkerError::ReadFailed { source })?;
    if bounded.len() > READ_MAX_BYTES {
        return Err(WorkerError::TooLarge);
    }
    let digest = crate::config::hex(&sha2::Sha256::digest(&bounded));
    Ok(ReadObservation {
        bytes: bounded,
        digest,
    })
}

/// One checked-fd managed write of an existing regular file inside the
/// canonical scope root: the write fd is the checked fd — after the open,
/// the occupant is re-checked for both the canonical-path identity and the
/// admitted identity before any mutation can land on the handle.
/// Confinement is intrinsic to this path — probe, then gate, then the
/// checked in-process leg — there is no unconfined variant.
///
/// # Errors
/// Returns [`WorkerError::WriteTooLarge`] for oversized payloads, the
/// worker's typed denials for targets this process cannot observe or that
/// changed between the check and the open, and
/// [`WorkerError::SandboxUnavailable`] / [`WorkerError::SandboxSpawnFailed`]
/// when the confinement mechanism itself cannot start or does not enforce.
pub fn write_once(
    scope_root: &Path,
    target: &Path,
    expected: FileIdentity,
    bytes: &[u8],
) -> Result<(), WorkerError> {
    if bytes.len() > WRITE_MAX_BYTES {
        return Err(WorkerError::WriteTooLarge);
    }
    let (_, canonical_meta) = inspect_regular_target(scope_root, target)?;
    let launcher = SandboxLauncher::default();
    probe_write_conformance(&launcher, scope_root)?;
    confined_write_gate(&launcher, scope_root, target)?;
    // The open re-walks the original path. Both the admitted identity and
    // the canonical-path identity must match the opened handle before any
    // fd mutation can happen.
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .custom_flags(O_NONBLOCK)
        .open(target)
        .map_err(|source| WorkerError::WriteFailed { source })?;
    write_opened_file(target, &canonical_meta, &mut file, expected, bytes)
}

/// Post-open occupant re-check plus the checked-fd mutation: the handle's
/// current metadata must still be the canonical regular file and still
/// carry the admitted identity, or the write denies without a byte moved.
fn write_opened_file(
    target: &Path,
    canonical_meta: &Metadata,
    file: &mut File,
    expected: FileIdentity,
    bytes: &[u8],
) -> Result<(), WorkerError> {
    let opened_meta = file
        .metadata()
        .map_err(|source| WorkerError::MetadataUnavailable { source })?;
    if !same_regular_file(canonical_meta, &opened_meta)
        || FileIdentity::from_metadata(&opened_meta) != expected
    {
        return Err(WorkerError::TargetChanged {
            target: target.to_path_buf(),
        });
    }
    let length =
        u64::try_from(bytes.len()).map_err(|source| WorkerError::WriteLengthOverflow { source })?;
    file.set_len(length)
        .map_err(|source| WorkerError::WriteMutationFailed { source })?;
    file.write_all(bytes)
        .map_err(|source| WorkerError::WriteMutationFailed { source })
}

// ---------------------------------------------------------------------------
// Landlock/seccomp/netns confinement: every admitted effect crosses the
// OS boundary before the checked in-process leg can move a byte.
// ---------------------------------------------------------------------------

/// Landlock read allowances every confined program needs: the program
/// itself and the dynamic linker trees. `/bin` and `/lib` are symlinks
/// Landlock resolves at rule-add time, so one rule covers both spellings
/// of the system trees. These trees never include user data, and
/// `/etc` deliberately stays unreadable — glibc falls back to the default
/// linker search path when `ld.so.cache` is denied, which the conformance
/// probes prove for every leg.
const SYSTEM_READ_RULES: &[&str] = &[
    "path-beneath:read-file,read-dir:/usr",
    "path-beneath:read-file,read-dir:/lib",
];

/// Landlock execute allowances for the read and write legs' programs
/// (`cat`, `tee`). The exec leg grants none of these — process execution
/// is allowed only inside the granted scope there.
const SYSTEM_EXECUTE_RULES: &[&str] = &["path-beneath:execute:/usr", "path-beneath:execute:/bin"];

/// The confinement one confined leg runs under — the profile equivalent:
/// a Landlock ruleset that handles every filesystem access right
/// (deny-by-default) plus allowances for the system trees and exactly one
/// granted operation inside the scope; the launcher always adds the
/// network namespace, and the egress and exec legs add the seccomp
/// net-deny — a program that runs inside the scope owns no connect
/// primitive, because pathname unix sockets cross the netns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Confinement {
    /// Reads of the system trees plus reads of files inside the scope.
    Read { scope: PathBuf },
    /// Writes (open-for-write, create, truncate) inside the scope only.
    Write { scope: PathBuf },
    /// Process execution inside the scope only. The seccomp net-deny is
    /// loaded for this leg: pathname AF_UNIX sockets cross the network
    /// namespace, so a scoped program must not reach unix services
    /// outside the scope through it.
    Exec { scope: PathBuf },
    /// No filesystem rules; the netns plus the seccomp net-deny filter
    /// carry the egress boundary.
    Egress,
}

/// Canonicalizes one scope root for a Landlock rule: rules anchor at
/// resolved directories, so a symlinked spelling would deny the very
/// scope the grant admits.
fn canonical_scope(scope_root: &Path) -> Result<PathBuf, WorkerError> {
    let canonical = scope_root
        .canonicalize()
        .map_err(|source| WorkerError::ScopeRootUnavailable { source })?;
    if canonical.to_str().is_none() {
        return Err(WorkerError::SandboxUnavailable {
            reason: "linux landlock: scope root is not valid unicode".to_string(),
        });
    }
    Ok(canonical)
}

fn scope_rule(rights: &str, scope: &Path) -> String {
    format!("path-beneath:{rights}:{}", scope.display())
}

/// Confinement for the read legs: system reads plus `read-file` beneath
/// the granted scope.
///
/// # Errors
/// Returns [`WorkerError::ScopeRootUnavailable`] when the scope root
/// cannot be canonicalized.
pub fn read_confinement(scope_root: &Path) -> Result<Confinement, WorkerError> {
    Ok(Confinement::Read {
        scope: canonical_scope(scope_root)?,
    })
}

/// Confinement for the managed-write legs: system reads and executes plus
/// open-for-write, create, and truncate beneath the granted scope.
///
/// # Errors
/// Returns [`WorkerError::ScopeRootUnavailable`] when the scope root
/// cannot be canonicalized.
pub fn write_confinement(scope_root: &Path) -> Result<Confinement, WorkerError> {
    Ok(Confinement::Write {
        scope: canonical_scope(scope_root)?,
    })
}

/// Confinement for the exec boundary: system reads (the dynamic linker
/// trees) and process execution only inside the granted scope.
///
/// # Errors
/// Returns [`WorkerError::ScopeRootUnavailable`] when the scope root
/// cannot be canonicalized.
pub fn exec_confinement(scope_root: &Path) -> Result<Confinement, WorkerError> {
    Ok(Confinement::Exec {
        scope: canonical_scope(scope_root)?,
    })
}

/// Confinement for the egress boundary: no filesystem rules; the netns
/// plus the seccomp net-deny filter deny the egress.
#[must_use = "the confinement is a pure builder; an unused one proves nothing"]
pub fn egress_confinement() -> Confinement {
    Confinement::Egress
}

fn landlock_rules(confinement: &Confinement) -> Vec<String> {
    match confinement {
        Confinement::Read { scope } => {
            let mut rules = SYSTEM_EXECUTE_RULES.iter().map(|r| (*r).to_string());
            let mut all: Vec<String> = SYSTEM_READ_RULES.iter().map(|r| (*r).to_string()).collect();
            all.extend(&mut rules);
            all.push(scope_rule("read-file", scope));
            all
        }
        Confinement::Write { scope } => {
            let mut all: Vec<String> = SYSTEM_EXECUTE_RULES
                .iter()
                .chain(SYSTEM_READ_RULES)
                .map(|r| (*r).to_string())
                .collect();
            all.push(scope_rule("write-file,make-reg,truncate", scope));
            all
        }
        Confinement::Exec { scope } => {
            let mut rules: Vec<String> = SYSTEM_READ_RULES
                .iter()
                .map(|rule| (*rule).to_string())
                .collect();
            rules.extend(loader_rules("read-file"));
            rules.extend(loader_rules("execute"));
            rules.push(scope_rule("execute", scope));
            rules
        }
        Confinement::Egress => Vec::new(),
    }
}

/// The ELF interpreter candidates glibc layouts use across
/// architectures. The exec confinement grants the loader's own tree the
/// execute (and read) allowance the kernel requires beside the binary —
/// without it every dynamically linked program is denied at the
/// interpreter step, while process execution everywhere else stays
/// denied.
const LOADER_CANDIDATES: &[&str] = &[
    "/lib/ld-linux-aarch64.so.1",
    "/lib64/ld-linux-x86-64.so.2",
    "/lib/ld-linux-x86-64.so.2",
];

/// Landlock rules anchoring at the resolved parent directory of every
/// loader that exists on this host, so one rule set covers arm64 and
/// amd64 layouts without anchoring at nonexistent paths (which
/// `setpriv` rejects).
fn loader_rules(rights: &str) -> Vec<String> {
    LOADER_CANDIDATES
        .iter()
        .filter_map(|candidate| Path::new(candidate).canonicalize().ok())
        .filter_map(|loader| loader.parent().map(|parent| scope_rule(rights, parent)))
        .collect()
}

// ----- seccomp net-deny filter -------------------------------------------

/// `AUDIT_ARCH_AARCH64` — the `seccomp_data` architecture word on 64-bit
/// arm, verified against the proof container's kernel.
const AUDIT_ARCH_AARCH64: u32 = 0xC000_00B7;

/// `AUDIT_ARCH_X86_64` for the same guard on amd64 hosts.
const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;

/// `SECCOMP_RET_ERRNO | EPERM` — a denied network syscall surfaces as
/// `EPERM` from the confined program, never as a signal.
const SECCOMP_RET_ERRNO_EPERM: u32 = 0x0005_0001;

/// `SECCOMP_RET_ALLOW` — every syscall outside the deny list runs.
const SECCOMP_RET_ALLOW: u32 = 0x7FFF_0000;

/// Classic-BPF opcodes for the hand-assembled deny-list filter. The
/// filter loads the architecture word and jumps straight to a deny
/// verdict for any other architecture (an unjudged architecture fails
/// closed), loads the syscall number, masks the x32/ILP32 compat band
/// bit, and returns `ERRNO|EPERM` for exactly the denied numbers,
/// `ALLOW` for everything else — so the launcher's own `execve` of the
/// confined program is never blocked, and neither are the Landlock
/// syscalls `setpriv` itself already applied.
const BPF_LD_W_ABS: u16 = 0x20;
const BPF_ALU_AND_K: u16 = 0x54;
const BPF_JEQ_K: u16 = 0x15;
const BPF_RET_K: u16 = 0x06;
const SECCOMP_DATA_NR_OFFSET: u32 = 0;
const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;

/// `!0x4000_0000` — the syscall-number word with the x32/ILP32 compat
/// band bit cleared: a compat-band number (`nr | 0x4000_0000`) carries
/// the native audit architecture, so it must be judged by its masked
/// native number instead of missing every native-equality deny entry.
const SECCOMP_COMPAT_BAND_MASK: u32 = 0xBFFF_FFFF;

/// The network syscalls the egress boundary denies, per native
/// architecture. `None` on any other architecture is an honest
/// capability failure, never an unfiltered leg.
fn native_net_syscalls() -> Option<(u32, &'static [u32])> {
    match std::env::consts::ARCH {
        "aarch64" => Some((
            AUDIT_ARCH_AARCH64,
            &[198, 199, 203, 206, 211], // socket socketpair connect sendto sendmsg
        )),
        "x86_64" => Some((
            AUDIT_ARCH_X86_64,
            &[41, 53, 42, 44, 46], // socket socketpair connect sendto sendmsg
        )),
        _ => None,
    }
}

/// Renders the net-deny filter as raw `struct sock_filter` instructions —
/// the exact file format `setpriv --seccomp-filter` loads.
fn net_deny_filter() -> Result<Vec<u8>, WorkerError> {
    let Some((arch, denied)) = native_net_syscalls() else {
        return Err(WorkerError::SandboxUnavailable {
            reason: format!(
                "linux seccomp: no net-deny syscall table for architecture {}",
                std::env::consts::ARCH
            ),
        });
    };
    let mut program: Vec<(u16, u8, u8, u32)> = vec![
        (BPF_LD_W_ABS, 0, 0, SECCOMP_DATA_ARCH_OFFSET),
        // Any other architecture lands on a deny verdict: an unjudged
        // architecture fails closed. The constant offset reaches the
        // first deny pair's ERRNO return from the guard.
        (BPF_JEQ_K, 0, 3, arch),
        (BPF_LD_W_ABS, 0, 0, SECCOMP_DATA_NR_OFFSET),
        // Compat band before every comparison: a `nr | 0x4000_0000`
        // call is judged by its native number.
        (BPF_ALU_AND_K, 0, 0, SECCOMP_COMPAT_BAND_MASK),
    ];
    for &nr in denied {
        program.push((BPF_JEQ_K, 0, 1, nr));
        program.push((BPF_RET_K, 0, 0, SECCOMP_RET_ERRNO_EPERM));
    }
    program.push((BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW));
    let mut bytes = Vec::with_capacity(program.len() * 8);
    for (code, jt, jf, k) in program {
        bytes.extend_from_slice(&code.to_le_bytes());
        bytes.push(jt);
        bytes.push(jf);
        bytes.extend_from_slice(&k.to_le_bytes());
    }
    Ok(bytes)
}

/// The loaded net-deny filter file for this process, written once under a
/// private unpredictable directory the same probe discipline uses for its
/// artifacts.
static SECCOMP_FILTER_FILE: Mutex<Option<PathBuf>> = Mutex::new(None);

/// Returns the path of this process's seccomp net-deny filter file,
/// writing it on first use.
///
/// # Errors
/// Returns [`WorkerError::SandboxUnavailable`] when the filter cannot be
/// rendered for this architecture or its private directory cannot be
/// created, and [`WorkerError::WriteFailed`] when the filter file itself
/// cannot be written.
pub fn net_deny_filter_file() -> Result<PathBuf, WorkerError> {
    let cached = SECCOMP_FILTER_FILE
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    if let Some(path) = cached {
        return Ok(path);
    }
    let filter = net_deny_filter()?;
    let dir = std::env::temp_dir().join(format!(
        "rivect-seccomp-filter-{}-{}",
        std::process::id(),
        crate::contracts::TaskId::generate().0
    ));
    std::fs::create_dir(&dir).map_err(|source| WorkerError::WriteFailed { source })?;
    if !set_private_mode(&dir) {
        return Err(WorkerError::SandboxUnavailable {
            reason: "linux seccomp: the filter directory cannot be secured private".to_string(),
        });
    }
    let path = dir.join("net-deny.bpf");
    std::fs::write(&path, &filter).map_err(|source| WorkerError::WriteFailed { source })?;
    SECCOMP_FILTER_FILE
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .replace(path.clone());
    Ok(path)
}

// ----- the confined run ---------------------------------------------------

/// Outcome of one confined run. The child's stdout is never captured —
/// gates and probes decide on the exit status alone — so no run can
/// buffer an unbounded child stream in this process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfinedOutcome {
    pub exit_ok: bool,
    pub stderr: String,
}

/// Runs one program under the confinement: `unshare --net` composes the
/// network namespace, `setpriv --nnp --landlock-access fs` applies the
/// ruleset (deny-by-default) with the confinement's allowances, and the
/// exec and egress legs additionally load the seccomp net-deny filter.
/// Arguments are passed separately, the child inherits no environment,
/// and only the exit status decides success. The child's stdout goes to
/// `/dev/null`; stderr is drained to EOF but only its first 64 KiB are
/// retained.
///
/// # Errors
/// Returns [`WorkerError::SandboxSpawnFailed`] when the launcher itself
/// cannot be started or observed — an init failure, never an effect
/// denial.
pub fn run_confined(
    launcher: &SandboxLauncher,
    confinement: &Confinement,
    program: &Path,
    args: &[&OsStr],
) -> Result<ConfinedOutcome, WorkerError> {
    let mut command = Command::new(&launcher.unshare);
    command
        .arg("--net")
        .arg("--")
        .arg(&launcher.setpriv)
        .arg("--nnp");
    // `--landlock-access fs` with no allowances denies every filesystem
    // access including the launcher's own exec, so it is applied only
    // with a rule set; the egress confinement carries no filesystem
    // rules — its boundary is the netns plus the seccomp net-deny.
    let rules = landlock_rules(confinement);
    if !rules.is_empty() {
        command.arg("--landlock-access").arg("fs");
        for rule in rules {
            command.arg("--landlock-rule").arg(&rule);
        }
    }
    // A program that runs inside the scope is untrusted, and pathname
    // AF_UNIX sockets cross the network namespace: the seccomp net-deny
    // is loaded wherever a confined program executes — the exec leg and
    // the egress boundary — so the netns is never the egress carrier
    // alone.
    if matches!(confinement, Confinement::Egress | Confinement::Exec { .. }) {
        command.arg("--seccomp-filter").arg(net_deny_filter_file()?);
    }
    command.arg(program).args(args);
    let mut child = command
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|source| WorkerError::SandboxSpawnFailed { source })?;
    // Drain stderr to EOF before waiting: a child holding a full stderr
    // pipe could otherwise block forever against a wait()ing parent.
    let raw = match child.stderr.take() {
        Some(pipe) => drain_retaining_cap(pipe)
            .map_err(|source| WorkerError::SandboxSpawnFailed { source })?,
        None => Vec::new(),
    };
    let status = child
        .wait()
        .map_err(|source| WorkerError::SandboxSpawnFailed { source })?;
    Ok(ConfinedOutcome {
        exit_ok: status.success(),
        stderr: String::from_utf8_lossy(&raw).into_owned(),
    })
}

/// One bounded first line of confined stderr for a capability reason: the
/// launcher names its failed mechanism (`setpriv: … Landlock …`,
/// `unshare: …`), so the excerpt keeps that name while staying small.
fn stderr_excerpt(stderr: &str) -> String {
    stderr
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or_default()
        .chars()
        .take(160)
        .collect()
}

/// Verdict of one confined gate or effect leg: an admitted run is `Ok`;
/// a denied run is the typed OS denial naming the target.
fn expect_admitted(outcome: ConfinedOutcome, target: &Path) -> Result<(), WorkerError> {
    if outcome.exit_ok {
        Ok(())
    } else {
        Err(WorkerError::SandboxDenied {
            target: target.to_path_buf(),
        })
    }
}

/// Verdict of one denied probe leg: a run the boundary admitted is a
/// capability failure; the expected denial is plain `Ok`.
fn expect_denied(outcome: ConfinedOutcome, reason: &str) -> Result<(), WorkerError> {
    if outcome.exit_ok {
        Err(WorkerError::SandboxUnavailable {
            reason: reason.to_string(),
        })
    } else {
        Ok(())
    }
}

// ----- conformance probes and gates --------------------------------------

/// Read conformance verdicts already proven this process holds, keyed by
/// the launcher pair and the canonical scope: the kernel's enforcement
/// does not change per effect, but a degenerate scope must not poison a
/// healthy one. Failed probes are not cached — a broken boundary
/// re-probes on every effect and stays at zero effects.
static CONFORMANT_READ_SCOPES: Mutex<BTreeSet<(SandboxLauncher, PathBuf)>> =
    Mutex::new(BTreeSet::new());

/// Write conformance verdicts already proven this process holds, under
/// the same caching rules as the read set: the verdict is all a later
/// gate needs, because every confined write leg runs on its own fresh
/// probe artifact — nothing reusable (and nothing an alias could
/// pre-exist at) is ever opened twice.
static CONFORMANT_WRITE_SCOPES: Mutex<BTreeSet<(SandboxLauncher, PathBuf)>> =
    Mutex::new(BTreeSet::new());

/// One unpredictable in-scope probe artifact name: `tee` opens its
/// target with `O_WRONLY|O_CREAT|O_TRUNC`, so the write legs address
/// only names no other process could have pre-planted or aliased (a
/// hardlink or symlink at the name cannot exist yet) — a probe leg can
/// never truncate or follow an existing file.
fn fresh_probe_artifact(scope: &Path) -> PathBuf {
    scope.join(format!(
        ".rivect-write-probe-{}-{}",
        std::process::id(),
        crate::contracts::TaskId::generate().0
    ))
}

/// OS-boundary gate for one read effect: the kernel itself must admit a
/// read of exactly this target before the checked in-process leg runs.
fn confined_read_gate(
    launcher: &SandboxLauncher,
    scope_root: &Path,
    canonical_target: &Path,
) -> Result<(), WorkerError> {
    let outcome = run_confined(
        launcher,
        &read_confinement(scope_root)?,
        Path::new(CAT),
        &[canonical_target.as_os_str()],
    )?;
    expect_admitted(outcome, canonical_target)
}

/// OS-boundary gate for one managed write. The confined leg proves the
/// write allowance on a fresh unpredictable artifact this gate creates
/// inside the scope and removes afterwards — never the user's target and
/// never a name an alias (hardlink or symlink) could pre-exist at, so
/// the gate cannot truncate, follow, or recreate anything but its own
/// probe file.
fn confined_write_gate(
    launcher: &SandboxLauncher,
    scope_root: &Path,
    target: &Path,
) -> Result<(), WorkerError> {
    probe_write_conformance(launcher, scope_root)?;
    let confinement = write_confinement(scope_root)?;
    let Confinement::Write { scope } = &confinement else {
        unreachable!("internal error: the write confinement always carries a scope");
    };
    let artifact = fresh_probe_artifact(scope);
    let outcome = run_confined(
        launcher,
        &confinement,
        Path::new(TEE),
        &[artifact.as_os_str()],
    )?;
    drop(std::fs::remove_file(&artifact));
    expect_admitted(outcome, target)
}

/// Proves the Landlock read boundary enforces before the first read
/// effect in a scope (PROH-001, EDGE-009): the kernel must deny a
/// confined read of the denied probe target and admit a confined read of
/// this target. The denied leg runs first, so a non-enforcing mechanism
/// is caught before any leg touches the user's target. Both legs
/// discriminate enforcement from filesystem permission — an unreadable
/// probe target proves nothing, and a target this process cannot read is
/// a typed effect denial, never a capability failure.
///
/// # Errors
/// Returns [`WorkerError::SandboxSpawnFailed`] when the launcher cannot
/// start, [`WorkerError::SandboxUnavailable`] when the boundary does not
/// enforce or the scope is not confinable (the reason names the failed
/// mechanism when the launcher reports one), and the worker's typed
/// effect denials for targets this process cannot observe.
pub fn probe_read_conformance(
    launcher: &SandboxLauncher,
    scope_root: &Path,
    target: &Path,
) -> Result<(), WorkerError> {
    let key = (launcher.clone(), canonical_scope(scope_root)?);
    if CONFORMANT_READ_SCOPES
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .contains(&key)
    {
        return Ok(());
    }
    let canonical_target = target
        .canonicalize()
        .map_err(|_source| WorkerError::TargetMissing {
            target: target.to_path_buf(),
        })?;
    let confinement = read_confinement(scope_root)?;
    // Denied leg first: on a non-enforcing mechanism this read succeeds
    // and the probe fails before any leg touches the user's target. The
    // verdict discriminates only while this process could read the probe
    // target without the boundary at all.
    let denied = run_confined(
        launcher,
        &confinement,
        Path::new(CAT),
        &[Path::new(DENIED_PROBE_TARGET).as_os_str()],
    )?;
    expect_denied(
        denied,
        "linux landlock conformance probe: the boundary admitted the denied read leg",
    )?;
    if File::open(DENIED_PROBE_TARGET).is_err() {
        return Err(WorkerError::SandboxUnavailable {
            reason: "linux landlock conformance probe: the denied read target is unreadable, so enforcement cannot be proven"
                .to_string(),
        });
    }
    // Admitted leg on the user's canonical target: a failure distinguishes
    // a target this process cannot read (a typed effect denial) from a
    // boundary that wrongly denies in-scope reads — a capability failure
    // whose reason carries the launcher's own mechanism name.
    match run_confined(
        launcher,
        &confinement,
        Path::new(CAT),
        &[canonical_target.as_os_str()],
    ) {
        Ok(outcome) if outcome.exit_ok => {}
        Ok(outcome) => {
            File::open(&canonical_target).map_err(|source| WorkerError::ReadFailed { source })?;
            return Err(WorkerError::SandboxUnavailable {
                reason: format!(
                    "linux landlock conformance probe: the boundary denied the in-scope read leg: {}",
                    stderr_excerpt(&outcome.stderr)
                ),
            });
        }
        Err(error) => return Err(error),
    }
    CONFORMANT_READ_SCOPES
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(key);
    Ok(())
}

/// Proves the Landlock write boundary enforces before the first managed
/// write in a scope: the kernel must deny a confined write to a file
/// this process owns outside the scope and admit one to a fresh
/// artifact inside the scope. The denied leg runs first, so a
/// non-enforcing mechanism is caught before any in-scope ambient I/O,
/// both legs run under `tee`'s create-only discipline on fresh
/// unpredictable names, and the artifact is removed after the probe —
/// conformance leaves no debris and can never truncate or follow a
/// pre-planted file. A scope this process cannot write is a typed
/// effect denial, never a capability failure.
///
/// # Errors
/// Returns [`WorkerError::SandboxSpawnFailed`] when the launcher cannot
/// start, [`WorkerError::SandboxUnavailable`] when the boundary does not
/// enforce or the scope is not confinable (the reason names the failed
/// mechanism when the launcher reports one), and
/// [`WorkerError::WriteFailed`] when the scope is not writable by this
/// process.
pub fn probe_write_conformance(
    launcher: &SandboxLauncher,
    scope_root: &Path,
) -> Result<(), WorkerError> {
    let key = (launcher.clone(), canonical_scope(scope_root)?);
    if CONFORMANT_WRITE_SCOPES
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .contains(&key)
    {
        return Ok(());
    }
    let confinement = write_confinement(scope_root)?;
    // Denied leg first: the candidate lives in a private directory this
    // process just created outside the scope, so only the boundary can
    // deny the write — and a confined write that succeeds means it never
    // denied anything. The stray a passthrough tee created and its
    // directory are removed either way.
    let candidate = denied_write_candidate(
        &key.1,
        "linux landlock conformance probe: no securable write-denial probe root outside the scope, so it is not confinable",
    )?;
    let denied = run_confined(
        launcher,
        &confinement,
        Path::new(TEE),
        &[candidate.as_os_str()],
    );
    drop(std::fs::remove_file(&candidate));
    if let Some(parent) = candidate.parent() {
        drop(std::fs::remove_dir(parent));
    }
    expect_denied(
        denied?,
        "linux landlock conformance probe: the boundary admitted the denied write leg",
    )?;
    // Admitted leg on a fresh artifact this worker owns inside the
    // scope, so no confined leg ever touches the user's write target.
    // A failure distinguishes a scope this process cannot write (an
    // effect denial) from a boundary that wrongly denies in-scope
    // writes (a capability failure naming the mechanism).
    let artifact = fresh_probe_artifact(&key.1);
    let verdict = match run_confined(
        launcher,
        &confinement,
        Path::new(TEE),
        &[artifact.as_os_str()],
    ) {
        Ok(outcome) if outcome.exit_ok => Ok(()),
        Ok(outcome) => {
            // `O_NOFOLLOW` keeps this writability check from ever opening
            // through a symlink planted on the artifact path — a tampered
            // artifact surfaces as the same typed write denial as a scope
            // this process cannot write.
            match std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .custom_flags(O_NOFOLLOW)
                .open(&artifact)
            {
                Ok(_) => Err(WorkerError::SandboxUnavailable {
                    reason: format!(
                        "linux landlock conformance probe: the boundary denied the in-scope write leg: {}",
                        stderr_excerpt(&outcome.stderr)
                    ),
                }),
                Err(source) => Err(WorkerError::WriteFailed { source }),
            }
        }
        Err(error) => Err(error),
    };
    // No debris either way: the artifact existed only between the
    // confined leg and this removal, whatever the verdict was.
    drop(std::fs::remove_file(&artifact));
    verdict?;
    CONFORMANT_WRITE_SCOPES
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(key);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        Confinement, SYSTEM_EXECUTE_RULES, landlock_rules, native_net_syscalls, net_deny_filter,
    };
    use crate::executor::{STDERR_RETAIN_BYTES, drain_retaining_cap, same_regular_file};
    use std::io::Read as _;
    use std::path::Path;

    #[test]
    fn target_identity_requires_same_regular_file() -> Result<(), Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "rivect-linux-worker-{}",
            crate::contracts::TaskId::generate().0
        ));
        std::fs::create_dir_all(&root)?;
        let first = root.join("first");
        let second = root.join("second");
        std::fs::write(&first, b"first")?;
        std::fs::write(&second, b"second")?;
        let first_meta = std::fs::metadata(&first)?;
        let second_meta = std::fs::metadata(&second)?;
        let directory_meta = std::fs::metadata(&root)?;
        assert!(same_regular_file(&first_meta, &first_meta));
        assert!(!same_regular_file(&first_meta, &second_meta));
        assert!(!same_regular_file(&first_meta, &directory_meta));
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn drain_retains_only_the_cap_and_drains_to_eof() {
        let oversized = STDERR_RETAIN_BYTES + 4096;
        let mut stream = std::io::Cursor::new(vec![b'e'; oversized]);
        let retained = drain_retaining_cap(&mut stream).expect("drain oversized stderr");
        assert_eq!(
            retained.len(),
            STDERR_RETAIN_BYTES,
            "a spamming child retains exactly the cap"
        );
        assert!(retained.iter().all(|&byte| byte == b'e'));
        // EOF was reached, not merely the cap: a second read yields nothing.
        let mut tail = Vec::new();
        stream
            .read_to_end(&mut tail)
            .expect("stream already at eof");
        assert!(tail.is_empty());

        let mut small = std::io::Cursor::new(b"operation not permitted".to_vec());
        let retained = drain_retaining_cap(&mut small).expect("drain bounded stderr");
        assert_eq!(retained, b"operation not permitted");
    }

    #[test]
    fn net_deny_filter_masks_the_compat_band_and_fails_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let (arch, denied) =
            native_net_syscalls().ok_or("no syscall table on this architecture")?;
        let filter = net_deny_filter()?;
        // arch load, arch guard, nr load, compat mask, two insns per
        // denied nr, allow tail.
        assert_eq!(filter.len(), (4 + 2 * denied.len() + 1) * 8);
        let insn = |index: usize| {
            let base = index * 8;
            let code = u16::from_le_bytes([
                *filter.get(base).ok_or("missing code byte")?,
                *filter.get(base + 1).ok_or("missing code byte")?,
            ]);
            let jt = *filter.get(base + 2).ok_or("missing jt byte")?;
            let jf = *filter.get(base + 3).ok_or("missing jf byte")?;
            let k = u32::from_le_bytes([
                *filter.get(base + 4).ok_or("missing k byte")?,
                *filter.get(base + 5).ok_or("missing k byte")?,
                *filter.get(base + 6).ok_or("missing k byte")?,
                *filter.get(base + 7).ok_or("missing k byte")?,
            ]);
            Ok::<(u16, u8, u8, u32), Box<dyn std::error::Error>>((code, jt, jf, k))
        };
        assert_eq!(
            insn(0)?,
            (0x20, 0, 0, 4),
            "the first load reads the arch word"
        );
        assert_eq!(
            insn(1)?,
            (0x15, 0, 3, arch),
            "the guard pins the native arch: jt falls through, jf fails closed"
        );
        assert_eq!(
            insn(5)?,
            (0x06, 0, 0, 0x0005_0001),
            "the guard's miss jump lands on a deny verdict, not the allow tail"
        );
        assert_eq!(
            insn(2)?,
            (0x20, 0, 0, 0),
            "the second load reads the nr word"
        );
        assert_eq!(
            insn(3)?,
            (0x54, 0, 0, 0xBFFF_FFFF),
            "the compat band bit is masked before every deny comparison"
        );
        for (position, &nr) in denied.iter().enumerate() {
            assert_eq!(insn(4 + position * 2)?, (0x15, 0, 1, nr));
            assert_eq!(
                insn(5 + position * 2)?,
                (0x06, 0, 0, 0x0005_0001),
                "each denied nr returns ERRNO|EPERM"
            );
        }
        assert_eq!(
            insn(4 + denied.len() * 2)?,
            (0x06, 0, 0, 0x7FFF_0000),
            "the tail allows every other syscall"
        );

        // Semantics, not just shape: run the assembled program.
        let verdict = |arch_word: u32, nr: u32| -> u32 {
            let mut acc = 0u32;
            let mut index = 0usize;
            loop {
                let (code, jt, jf, k) = insn(index).expect("decoded instruction");
                match code {
                    0x20 => {
                        acc = if k == 4 { arch_word } else { nr };
                        index += 1;
                    }
                    0x15 => index += 1 + usize::from(if acc == k { jt } else { jf }),
                    0x54 => {
                        acc &= k;
                        index += 1;
                    }
                    0x06 => return k,
                    // An unknown opcode denies: the interpreter must not
                    // invent an allowance the kernel would not grant.
                    _ => return 0x0005_0001,
                }
            }
        };
        assert_eq!(
            verdict(arch, denied[0]),
            0x0005_0001,
            "a denied nr returns ERRNO|EPERM"
        );
        assert_eq!(
            verdict(arch, denied[0] | 0x4000_0000),
            0x0005_0001,
            "a compat-band nr is masked into the deny list"
        );
        let bystander = (0u32..)
            .find(|candidate| !denied.contains(candidate))
            .expect("a bystander nr exists");
        assert_eq!(
            verdict(arch, bystander),
            0x7FFF_0000,
            "every other nr is allowed"
        );
        assert_eq!(
            verdict(arch ^ 1, denied[0]),
            0x0005_0001,
            "a foreign architecture fails closed"
        );
        Ok(())
    }

    #[test]
    fn confinement_rules_grant_exactly_the_admitted_operation() {
        let read = landlock_rules(&Confinement::Read {
            scope: Path::new("/scope").to_path_buf(),
        });
        assert_eq!(
            read.last().map(String::as_str),
            Some("path-beneath:read-file:/scope")
        );
        let write = landlock_rules(&Confinement::Write {
            scope: Path::new("/scope").to_path_buf(),
        });
        assert_eq!(
            write.last().map(String::as_str),
            Some("path-beneath:write-file,make-reg,truncate:/scope")
        );
        let exec = landlock_rules(&Confinement::Exec {
            scope: Path::new("/scope").to_path_buf(),
        });
        assert_eq!(
            exec.last().map(String::as_str),
            Some("path-beneath:execute:/scope")
        );
        // The exec confinement grants no system-wide execute allowance:
        // only the scope and the loader trees may execute.
        assert!(!exec.iter().any(|rule| {
            SYSTEM_EXECUTE_RULES.contains(&rule.as_str()) || rule.contains("execute:/usr/bin")
        }));
        assert!(landlock_rules(&Confinement::Egress).is_empty());
    }
}
