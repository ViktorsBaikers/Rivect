//! macOS read backend for the effect worker (architecture «Shell/PTY»
//! confinement for this slice's read-only surface). Exactly one scoped
//! existing-file read per admitted effect; everything else is denied before
//! any byte is touched. SLICE-003 extends this same backend.

use sha2::Digest;
use std::path::Path;
/// The one injected backend seam: everything the executor reads goes
pub trait ReadWorker: Send {
    fn read_once(
        &mut self,
        scope_root: &Path,
        target: &Path,
    ) -> Result<ReadObservation, WorkerError>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct MacosReadWorker;

impl ReadWorker for MacosReadWorker {
    fn read_once(
        &mut self,
        scope_root: &Path,
        target: &Path,
    ) -> Result<ReadObservation, WorkerError> {
        read_once(scope_root, target)
    }
}

pub const BACKEND: &str = "macos";

pub const READ_MAX_BYTES: usize = 1 << 20;

#[derive(Debug, Clone, PartialEq)]
pub struct ReadObservation {
    pub bytes: Vec<u8>,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum WorkerError {
    Denied(String),
    NotFound(String),
}

impl std::fmt::Display for WorkerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Denied(why) => write!(f, "denied: {why}"),
            Self::NotFound(what) => write!(f, "not found: {what}"),
        }
    }
}

/// One bounded read of an existing regular file inside the canonical scope
/// root. Symlinks that escape the scope are denied via canonicalisation.
pub fn read_once(scope_root: &Path, target: &Path) -> Result<ReadObservation, WorkerError> {
    let scope = scope_root
        .canonicalize()
        .map_err(|err| WorkerError::Denied(format!("scope root unavailable: {err}")))?;
    let file = target.canonicalize().map_err(|_| {
        WorkerError::NotFound(format!("target does not exist: {}", target.display()))
    })?;
    if !file.starts_with(&scope) {
        return Err(WorkerError::Denied(format!(
            "target {} is outside the admitted scope",
            target.display()
        )));
    }
    let meta = std::fs::metadata(&file)
        .map_err(|err| WorkerError::Denied(format!("target metadata unavailable: {err}")))?;
    if !meta.is_file() {
        return Err(WorkerError::Denied(format!(
            "target {} is not a regular file",
            target.display()
        )));
    }
    let bounded =
        std::fs::read(&file).map_err(|err| WorkerError::Denied(format!("read failed: {err}")))?;
    if bounded.len() > READ_MAX_BYTES {
        return Err(WorkerError::Denied(format!(
            "target exceeds the {READ_MAX_BYTES} byte read limit"
        )));
    }
    let digest = crate::config::hex(&sha2::Sha256::digest(&bounded));
    Ok(ReadObservation {
        bytes: bounded,
        digest,
    })
}
