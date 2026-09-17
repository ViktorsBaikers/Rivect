//! macOS read backend for the effect worker (architecture «Shell/PTY»
//! confinement for this slice's read-only surface). Exactly one scoped
//! existing-file read per admitted effect; everything else is denied before
//! any byte is touched. SLICE-003 extends this same backend.

use sha2::Digest;
use std::fs::{File, Metadata};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
/// The one injected backend seam: everything the executor reads goes
pub trait ReadWorker: Send {
    fn read_once(
        &mut self,
        scope_root: &Path,
        target: &Path,
    ) -> Result<ReadObservation, WorkerError>;

    fn write_once(
        &mut self,
        _scope_root: &Path,
        _target: &Path,
        _expected: FileIdentity,
        _bytes: &[u8],
    ) -> Result<(), WorkerError> {
        Err(WorkerError::WriteUnavailable)
    }
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

    fn write_once(
        &mut self,
        scope_root: &Path,
        target: &Path,
        expected: FileIdentity,
        bytes: &[u8],
    ) -> Result<(), WorkerError> {
        write_once(scope_root, target, expected, bytes)
    }
}

pub const BACKEND: &str = "macos";

pub const READ_MAX_BYTES: usize = 1 << 20;
pub const WRITE_MAX_BYTES: usize = READ_MAX_BYTES;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileIdentity {
    pub dev: u64,
    pub ino: u64,
}

impl FileIdentity {
    fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
        }
    }
}

/// macOS `O_NONBLOCK` (Darwin fcntl.h: 0x0004; no libc dependency here).
/// Opening a FIFO read-only with this flag returns immediately even when no
/// writer holds the other end, so a target swapped to a FIFO between the
/// metadata check and `open(2)` cannot block this worker forever. Regular
/// files ignore the flag, so the read path below is unaffected.
const O_NONBLOCK: i32 = 0x0004;

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
    #[error("denied: target changed while opening: {}", target.display())]
    TargetChanged { target: PathBuf },
    #[error("denied: read failed: {source}")]
    ReadFailed { source: std::io::Error },
    #[error("denied: write failed: {source}")]
    WriteFailed { source: std::io::Error },
    #[error("denied: managed write failed after mutation: {source}")]
    WriteMutationFailed { source: std::io::Error },
    #[error("denied: managed write backend unavailable")]
    WriteUnavailable,
    #[error("denied: managed write exceeds the {WRITE_MAX_BYTES} byte limit")]
    WriteTooLarge,
    #[error("denied: managed write length conversion failed: {source}")]
    WriteLengthOverflow { source: std::num::TryFromIntError },
    #[error("denied: target exceeds the {READ_MAX_BYTES} byte read limit")]
    TooLarge,
}

fn same_regular_file(expected: &Metadata, opened: &Metadata) -> bool {
    expected.is_file()
        && opened.is_file()
        && expected.dev() == opened.dev()
        && expected.ino() == opened.ino()
}

fn inspect_regular_target(
    scope_root: &Path,
    target: &Path,
) -> Result<(PathBuf, Metadata), WorkerError> {
    let scope = scope_root
        .canonicalize()
        .map_err(|source| WorkerError::ScopeRootUnavailable { source })?;
    let canonical_target = target
        .canonicalize()
        // Every canonicalize failure — missing, permission, symlink loop —
        // denies the effect the same way: the target is unavailable.
        .map_err(|_source| WorkerError::TargetMissing {
            target: target.to_path_buf(),
        })?;
    if !canonical_target.starts_with(&scope) {
        return Err(WorkerError::OutsideScope {
            target: target.to_path_buf(),
        });
    }
    let canonical_meta = std::fs::metadata(&canonical_target)
        .map_err(|source| WorkerError::MetadataUnavailable { source })?;
    if !canonical_meta.is_file() {
        return Err(WorkerError::NotRegularFile {
            target: target.to_path_buf(),
        });
    }
    Ok((canonical_target, canonical_meta))
}

pub(crate) fn target_identity(
    scope_root: &Path,
    target: &Path,
) -> Result<FileIdentity, WorkerError> {
    let (_, metadata) = inspect_regular_target(scope_root, target)?;
    Ok(FileIdentity::from_metadata(&metadata))
}

/// One bounded read of an existing regular file inside the canonical scope
/// root. Symlinks that escape the scope are denied via canonicalisation; the
/// opened handle is re-checked as a regular file and for dev/ino identity
/// (fail-closed on swaps), and the FIFO-before-open window is bounded by an
/// `O_NONBLOCK` open instead of a potentially unbounded blocking `open(2)`.
pub fn read_once(scope_root: &Path, target: &Path) -> Result<ReadObservation, WorkerError> {
    let (_, canonical_meta) = inspect_regular_target(scope_root, target)?;
    if canonical_meta.len() > READ_MAX_BYTES as u64 {
        return Err(WorkerError::TooLarge);
    }
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
    // The open re-walks the original path. Both the admitted identity and the
    // canonical-path identity must match the opened handle before any fd
    // mutation can happen.
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .custom_flags(O_NONBLOCK)
        .open(target)
        .map_err(|source| WorkerError::WriteFailed { source })?;
    write_opened_file(target, &canonical_meta, &mut file, expected, bytes)
}

/// Writes through an already-opened file after checking its current identity.
pub fn write_once_on_opened_file(
    scope_root: &Path,
    target: &Path,
    file: &mut File,
    expected: FileIdentity,
    bytes: &[u8],
) -> Result<(), WorkerError> {
    if bytes.len() > WRITE_MAX_BYTES {
        return Err(WorkerError::WriteTooLarge);
    }
    let (_, canonical_meta) = inspect_regular_target(scope_root, target)?;
    write_opened_file(target, &canonical_meta, file, expected, bytes)
}

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

#[cfg(test)]
mod tests {
    use super::same_regular_file;

    #[test]
    fn target_identity_requires_same_regular_file() -> Result<(), Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "rivect-worker-{}",
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
}
