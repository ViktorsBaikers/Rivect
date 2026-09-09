//! macOS read backend for the effect worker (architecture «Shell/PTY»
//! confinement for this slice's read-only surface). Exactly one scoped
//! existing-file read per admitted effect; everything else is denied before
//! any byte is touched. SLICE-003 extends this same backend.

use sha2::Digest;
use std::path::{Path, PathBuf};
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

#[derive(Debug, thiserror::Error)]
pub enum WorkerError {
    #[error("denied: scope root unavailable: {source}")]
    ScopeRootUnavailable { source: std::io::Error },
    #[error("not found: target does not exist: {}", target.display())]
    TargetMissing { target: PathBuf },
    #[error("denied: target {} is outside the admitted scope", target.display())]
    OutsideScope { target: PathBuf },
    #[error("denied: target metadata unavailable: {source}")]
    MetadataUnavailable { source: std::io::Error },
    #[error("denied: target {} is not a regular file", target.display())]
    NotRegularFile { target: PathBuf },
    #[error("denied: read failed: {source}")]
    ReadFailed { source: std::io::Error },
    #[error("denied: target exceeds the {READ_MAX_BYTES} byte read limit")]
    TooLarge,
}

/// One bounded read of an existing regular file inside the canonical scope
/// root. Symlinks that escape the scope are denied via canonicalisation.
pub fn read_once(scope_root: &Path, target: &Path) -> Result<ReadObservation, WorkerError> {
    let scope = scope_root
        .canonicalize()
        .map_err(|source| WorkerError::ScopeRootUnavailable { source })?;
    let file = target
        .canonicalize()
        .map_err(|_| WorkerError::TargetMissing {
            target: target.to_path_buf(),
        })?;
    if !file.starts_with(&scope) {
        return Err(WorkerError::OutsideScope {
            target: target.to_path_buf(),
        });
    }
    let meta =
        std::fs::metadata(&file).map_err(|source| WorkerError::MetadataUnavailable { source })?;
    if !meta.is_file() {
        return Err(WorkerError::NotRegularFile {
            target: target.to_path_buf(),
        });
    }
    let bounded = std::fs::read(&file).map_err(|source| WorkerError::ReadFailed { source })?;
    if bounded.len() > READ_MAX_BYTES {
        return Err(WorkerError::TooLarge);
    }
    let digest = crate::config::hex(&sha2::Sha256::digest(&bounded));
    Ok(ReadObservation {
        bytes: bounded,
        digest,
    })
}
