//! On-demand owner: OS advisory lock election over the private runtime
//! directory before any database writer is opened. The loser attaches; a
//! second writer is never created.

use crate::config::ConfigError;
use crate::state::{StoreError, TaskStore};
use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum OwnerError {
    #[error("another owner already holds this data root")]
    AlreadyOwned,
    #[error("owner I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("owner storage failed: {0}")]
    Store(#[from] StoreError),
    #[error("owner configuration failed: {0}")]
    Config(#[from] ConfigError),
}

pub struct Owner {
    _lock: File,
    pub store: TaskStore,
    pub generation: u64,
    runtime_dir: PathBuf,
}

impl Owner {
    /// Elects the single writer for `data_root` or fails closed. The lock is
    /// advisory and held for the owner's whole lifetime; dropping the owner
    /// releases it.
    pub fn elect(data_root: &Path) -> Result<Self, OwnerError> {
        let runtime_dir = data_root.join("runtime");
        std::fs::create_dir_all(&runtime_dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&runtime_dir, std::fs::Permissions::from_mode(0o700))?;
        }
        let lock_path = runtime_dir.join("owner.lock");
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)?;
        match lock.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => return Err(OwnerError::AlreadyOwned),
            Err(err) => return Err(OwnerError::Io(io::Error::other(err))),
        }
        let store = TaskStore::open(&runtime_dir.join("rivect.db"))?;
        Ok(Self {
            _lock: lock,
            store,
            generation: 1,
            runtime_dir,
        })
    }

    pub fn runtime_dir(&self) -> &Path {
        &self.runtime_dir
    }

    pub fn reopen_store(&mut self) -> Result<(), StoreError> {
        self.store = TaskStore::open(&self.runtime_dir.join("rivect.db"))?;
        Ok(())
    }
}
