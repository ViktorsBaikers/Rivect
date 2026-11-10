//! Sessionless, read-only diagnostics: `rivect doctor` answers before any
//! `Runtime::open`. Nothing here opens the store, takes the owner election or
//! writes a file — the checks are the exe-side manifest, `config.toml`, the
//! `runtime/` stat, a non-creating `runtime/owner.lock` shared-lock probe and
//! [`rivect::state::inspect_read_only`], so asking for diagnostics can never
//! mutate, lock or elect.

use rivect::config;
use rivect::contracts::{RELEASE_MANIFEST_NAME, SCHEMA_VERSION};
use rivect::owner::OWNER_LOCK;
use rivect::state::inspect_read_only;
use serde_json::{Value, json};
use std::io;
use std::path::{Path, PathBuf};

/// How one check ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckState {
    /// The surface is present and healthy.
    Ready,
    /// Present but not ready: the detail names what is wrong.
    Degraded,
    /// Another process holds the writer election.
    Held,
    /// Not created yet: a fresh data root, which is not a failure.
    Missing,
}

impl CheckState {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Degraded => "degraded",
            Self::Held => "held",
            Self::Missing => "missing",
        }
    }
}

/// One named check with its verdict and the detail an operator reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorCheck {
    pub name: &'static str,
    pub state: CheckState,
    pub detail: String,
}

/// The whole report. `ready` is derived from the checks, never asserted
/// beside them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorResult {
    pub data_root: PathBuf,
    pub project: Option<PathBuf>,
    pub checks: Vec<DoctorCheck>,
}

impl DoctorResult {
    /// Whether every check answered ready. A missing database is not ready —
    /// a fresh root has nothing to serve yet — and its own check says so.
    #[must_use]
    pub fn ready(&self) -> bool {
        self.checks
            .iter()
            .all(|check| check.state == CheckState::Ready)
    }

    /// The report as the one JSON object the command prints.
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({
            "schema_version": SCHEMA_VERSION,
            "kind": "doctor",
            "data_root": self.data_root.to_string_lossy(),
            "project": self.project.as_ref().map(|path| path.to_string_lossy().into_owned()),
            "ready": self.ready(),
            "checks": self
                .checks
                .iter()
                .map(|check| json!({
                    "name": check.name,
                    "state": check.state.as_str(),
                    "detail": check.detail,
                }))
                .collect::<Vec<_>>(),
        })
    }
}

/// One machine frame the headless loop must answer before it opens anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DoctorFrame {
    /// A frame this module does not serve.
    Other,
    /// A `command.execute` frame under the `doctor` kind.
    Doctor { id: Value, project: Option<PathBuf> },
}

/// Classifies one headless request frame. Only the exact
/// `command.execute`/`doctor` shape is doctor's: every other frame belongs to
/// the dispatcher, which needs the runtime this command exists to avoid.
#[must_use]
pub fn classify_frame(frame: &str) -> DoctorFrame {
    let Ok(parsed) = serde_json::from_str::<Value>(frame) else {
        return DoctorFrame::Other;
    };
    if parsed.get("method").and_then(Value::as_str) != Some("command.execute") {
        return DoctorFrame::Other;
    }
    if parsed
        .pointer("/params/command/kind")
        .and_then(Value::as_str)
        != Some("doctor")
    {
        return DoctorFrame::Other;
    }
    let id = parsed.get("id").cloned().unwrap_or(Value::Null);
    let project = parsed
        .pointer("/params/project")
        .and_then(Value::as_str)
        .map(PathBuf::from);
    DoctorFrame::Doctor { id, project }
}

/// The one response a doctor frame receives: the same report the CLI prints,
/// under the JSON-RPC envelope.
#[must_use]
pub fn answer_frame(id: Value, result: &DoctorResult) -> String {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result.to_json(),
    })
    .to_string()
}

/// Runs every check against `data_root` and the project root the caller
/// named. No call here opens a connection, creates a path or takes the writer
/// election. `own_lock` says this process holds the writer election itself —
/// true only for the headless loop's in-process answer — so the shared probe
/// does not read its own exclusive lock as another process's.
#[must_use]
pub fn inspect(data_root: &Path, project: Option<&Path>, own_lock: bool) -> DoctorResult {
    let runtime_dir = data_root.join("runtime");
    let checks = vec![
        exe_check(),
        release_check(),
        config_check(data_root),
        runtime_dir_check(&runtime_dir),
        owner_lock_check(data_root, own_lock),
        store_check(&runtime_dir),
    ];
    DoctorResult {
        data_root: data_root.to_path_buf(),
        project: project.map(Path::to_path_buf),
        checks,
    }
}

/// The exe-side manifest: the running binary and the build identity it
/// reports. A binary that cannot name itself is not one this build shipped.
fn exe_check() -> DoctorCheck {
    match std::env::current_exe() {
        Ok(exe) => match std::fs::metadata(&exe) {
            Ok(metadata) if metadata.is_file() => DoctorCheck {
                name: "exe",
                state: CheckState::Ready,
                detail: format!(
                    "{} ({}, {} bytes)",
                    exe.to_string_lossy(),
                    rivect::BUILD_ATTEMPT_ID,
                    metadata.len()
                ),
            },
            Ok(_) => DoctorCheck {
                name: "exe",
                state: CheckState::Degraded,
                detail: "the running executable is not a regular file".to_string(),
            },
            Err(error) => DoctorCheck {
                name: "exe",
                state: CheckState::Degraded,
                detail: format!("the running executable cannot be stat-ed: {error}"),
            },
        },
        Err(error) => DoctorCheck {
            name: "exe",
            state: CheckState::Degraded,
            detail: format!("the running executable cannot be named: {error}"),
        },
    }
}

/// The packaged release identity beside the running executable. A build that
/// ships no manifest is a checkout binary, not an installed release; one that
/// does ship a manifest must pass the same exact-inventory and digest check
/// activation uses, so a broken bundle answers degraded instead of ready.
fn release_check() -> DoctorCheck {
    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(error) => {
            return DoctorCheck {
                name: "release",
                state: CheckState::Degraded,
                detail: format!("the running executable cannot be named: {error}"),
            };
        }
    };
    let Some(directory) = exe.parent() else {
        return DoctorCheck {
            name: "release",
            state: CheckState::Degraded,
            detail: "the running executable has no directory".to_string(),
        };
    };
    match std::fs::symlink_metadata(directory.join(RELEASE_MANIFEST_NAME)) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => DoctorCheck {
            name: "release",
            state: CheckState::Ready,
            detail: "no release manifest beside the executable; this is not a packaged install"
                .to_string(),
        },
        Err(error) => DoctorCheck {
            name: "release",
            state: CheckState::Degraded,
            detail: format!("the release manifest cannot be stat-ed: {error}"),
        },
        Ok(_) => match rivect::executor::verify_release_bundle(directory) {
            Ok(activation) => DoctorCheck {
                name: "release",
                state: CheckState::Ready,
                detail: format!(
                    "packaged release {} (manifest sha256 {})",
                    activation.build,
                    activation
                        .manifest_sha256
                        .get(..12)
                        .unwrap_or(&activation.manifest_sha256)
                ),
            },
            Err(error) => DoctorCheck {
                name: "release",
                state: CheckState::Degraded,
                detail: format!("the packaged release is refused: {error}"),
            },
        },
    }
}

/// `config.toml` read through the owner's one bounded ingress and resolved by
/// the schema the boot uses. An absent document is the shipped base alone and
/// is ready; a document the schema rejects is degraded with its first refusal.
fn config_check(data_root: &Path) -> DoctorCheck {
    let path = data_root.join("config.toml");
    // The ceiling is the contracts request bound the runtime's own config
    // ingress applies, so the doctor refuses a document the boot would refuse.
    match rivect::owner::read_user_config(&path, rivect::contracts::REQUEST_MAX_BYTES) {
        Ok(None) => DoctorCheck {
            name: "config",
            state: CheckState::Ready,
            detail: "no config.toml; the shipped base serves alone".to_string(),
        },
        Ok(Some(document)) => match config::resolve_effective(Some(&document)) {
            Ok(effective) => DoctorCheck {
                name: "config",
                state: CheckState::Ready,
                detail: format!(
                    "config.toml is valid over base {} ({})",
                    effective.base_version(),
                    &effective.sources_digest[..12.min(effective.sources_digest.len())]
                ),
            },
            Err(error) => DoctorCheck {
                name: "config",
                state: CheckState::Degraded,
                detail: format!("config.toml is rejected: {error}"),
            },
        },
        Err(error) => DoctorCheck {
            name: "config",
            state: CheckState::Degraded,
            detail: format!("config.toml cannot be read: {error}"),
        },
    }
}

/// The `runtime/` directory: the owner's private root. A missing one is a
/// fresh data root, not a failure; one another account can read is degraded.
fn runtime_dir_check(runtime_dir: &Path) -> DoctorCheck {
    match std::fs::metadata(runtime_dir) {
        Ok(metadata) if metadata.is_dir() => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                let mode = metadata.permissions().mode() & 0o777;
                if mode & 0o077 != 0 {
                    return DoctorCheck {
                        name: "runtime_dir",
                        state: CheckState::Degraded,
                        detail: format!("{runtime_dir:?} is mode {mode:o}, not 0700"),
                    };
                }
            }
            DoctorCheck {
                name: "runtime_dir",
                state: CheckState::Ready,
                detail: format!("{runtime_dir:?} is a private directory"),
            }
        }
        Ok(_) => DoctorCheck {
            name: "runtime_dir",
            state: CheckState::Degraded,
            detail: format!("{runtime_dir:?} is not a directory"),
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => DoctorCheck {
            name: "runtime_dir",
            state: CheckState::Missing,
            detail: "no runtime directory yet; the first open creates it".to_string(),
        },
        Err(error) => DoctorCheck {
            name: "runtime_dir",
            state: CheckState::Degraded,
            detail: format!("{runtime_dir:?} cannot be stat-ed: {error}"),
        },
    }
}

/// The writer election, probed with one non-blocking SHARED lock on the
/// existing `owner.lock` (TD-05). The open is non-creating and the probe lock
/// is released at drop: a probe finds a writer by failing to take the shared
/// lock, never by becoming one, and a root nobody owns is left exactly as it
/// was. A shared holder — another doctor — is not a writer, so it does not
/// read as `held`.
fn owner_lock_check(data_root: &Path, own_lock: bool) -> DoctorCheck {
    let path = data_root.join(OWNER_LOCK);
    let runtime_dir = data_root.join("runtime");
    // This process holds the exclusive election: the shared probe would collide
    // with its own lock and report a writer that does not exist. The check is
    // about another process, so the owned fact is the ready answer.
    if own_lock {
        return DoctorCheck {
            name: "owner_lock",
            state: CheckState::Ready,
            detail: "this process holds the writer election".to_string(),
        };
    }
    let file = match std::fs::OpenOptions::new().read(true).open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            // A released election may leave no lock file behind: a root that
            // already has a database is quiescent, and one without is fresh.
            let recorded = runtime_dir.join("rivect.db").exists();
            return DoctorCheck {
                name: "owner_lock",
                state: if recorded {
                    CheckState::Ready
                } else {
                    CheckState::Missing
                },
                detail: if recorded {
                    "no election is recorded; the root is quiescent".to_string()
                } else {
                    "no owner lock yet; no runtime holds this root".to_string()
                },
            };
        }
        Err(error) => {
            return DoctorCheck {
                name: "owner_lock",
                state: CheckState::Degraded,
                detail: format!("{path:?} cannot be opened: {error}"),
            };
        }
    };
    match file.try_lock_shared() {
        Ok(()) => DoctorCheck {
            name: "owner_lock",
            state: CheckState::Ready,
            detail: "no writer holds the election".to_string(),
        },
        Err(std::fs::TryLockError::WouldBlock) => DoctorCheck {
            name: "owner_lock",
            state: CheckState::Held,
            detail: "another process holds the writer election".to_string(),
        },
        Err(std::fs::TryLockError::Error(error)) => DoctorCheck {
            name: "owner_lock",
            state: CheckState::Degraded,
            detail: format!("the election probe failed: {error}"),
        },
    }
}

/// The database file's own bytes: presence, size, header magic and the two
/// sidecars. Deciding this without a connection is the point — an open would
/// take a descriptor on the file the owner holds.
fn store_check(runtime_dir: &Path) -> DoctorCheck {
    let db = runtime_dir.join("rivect.db");
    match inspect_read_only(&db) {
        Ok(inspection) if !inspection.present => DoctorCheck {
            name: "state_db",
            state: CheckState::Missing,
            detail: "no database yet; the first open creates it".to_string(),
        },
        Ok(inspection) if !inspection.header_ok => DoctorCheck {
            name: "state_db",
            state: CheckState::Degraded,
            detail: format!(
                "{db:?} is {} bytes and does not start with the SQLite header",
                inspection.bytes
            ),
        },
        Ok(inspection) => DoctorCheck {
            name: "state_db",
            state: CheckState::Ready,
            detail: format!(
                "{db:?} is {} bytes (sidecars: {:?})",
                inspection.bytes, inspection.sidecars
            ),
        },
        Err(error) => DoctorCheck {
            name: "state_db",
            state: CheckState::Degraded,
            detail: format!("{db:?} cannot be inspected: {error}"),
        },
    }
}
