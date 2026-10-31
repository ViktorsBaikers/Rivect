//! On-demand owner: OS advisory lock election over the private runtime
//! directory before any database writer is opened. The loser attaches; a
//! second writer is never created.

use crate::config::ConfigError;
use crate::state::{ReleasedLock, StoreError, TaskStore, unlock_or_hand_off};
use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

/// A failed election or config read. Every variant that holds a cause
/// shows only its own context and keeps the cause as its `source()`; the
/// operator-facing join of context and cause is `ui::failure_report`.
#[derive(Debug, thiserror::Error)]
pub enum OwnerError {
    #[error("another owner already holds this data root")]
    AlreadyOwned,
    #[error("owner i/o failed")]
    Io(#[from] io::Error),
    #[error("owner storage failed")]
    Store(#[from] StoreError),
    #[error("owner configuration failed: {path}")]
    Config {
        path: PathBuf,
        #[source]
        source: ConfigError,
    },
    #[error("owner configuration exceeds {limit} bytes: {path}")]
    ConfigTooLarge { path: PathBuf, limit: usize },
    #[error("owner configuration failed: {path}: read failed")]
    ConfigRead {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("supervisor construction failed")]
    SupervisorPolicy(#[from] crate::supervisor::SupervisorError),
}

/// The elected owner. Its store and generation are read through accessors
/// and never rebound from outside the crate.
///
/// ```compile_fail
/// use rivect::{owner::Owner, state::TaskStore};
/// fn f(owner: &mut Owner) { let _s: &mut TaskStore = &mut owner.store; }
/// ```
///
/// ```
/// use rivect::{owner::Owner, state::TaskStore};
/// fn f(owner: &mut Owner) { let _s: &TaskStore = owner.store(); }
/// ```
///
/// ```compile_fail
/// use rivect::owner::Owner;
/// fn f(owner: &mut Owner) { owner.generation = 2; }
/// ```
///
/// ```
/// use rivect::owner::Owner;
/// fn f(owner: &mut Owner) { let _g: u64 = owner.generation(); }
/// ```
pub struct Owner {
    pub(crate) store: TaskStore,
    pub(crate) generation: u64,
    runtime_dir: PathBuf,
    /// Declared last and `Owner` has no `Drop`, so the store (connection
    /// close, then entry destruction) is released before the election.
    _election: Election,
}

/// The held `owner.lock`. Release is owner-managed, never left to the
/// last close: a descriptor a concurrently forked child inherited
/// shares the open file description until its `exec`, so the explicit
/// unlock is what lets the next election win. A failed unlock is handed
/// off (see [`unlock_or_hand_off`]) and the file still closes.
struct Election(File);

/// The lock file an election over a data root holds, relative to that root. The
/// boot, the deferred startup and an update refusal all name this one path, so
/// an operator is pointed at the exact file another process owns.
pub const OWNER_LOCK: &str = "runtime/owner.lock";

impl Drop for Election {
    fn drop(&mut self) {
        unlock_or_hand_off(ReleasedLock::Owner, || self.0.unlock());
    }
}

/// Takes the one election over `data_root`: the private runtime directory, the
/// advisory lock on [`OWNER_LOCK`], and the held descriptor the caller wraps.
/// Both entries share it, so the directory shape and the refusal are stated
/// once.
fn elect_lock(data_root: &Path) -> Result<(PathBuf, Election), OwnerError> {
    let runtime_dir = data_root.join("runtime");
    std::fs::create_dir_all(&runtime_dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&runtime_dir, std::fs::Permissions::from_mode(0o700))?;
    }
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(data_root.join(OWNER_LOCK))?;
    match lock.try_lock() {
        Ok(()) => {}
        Err(std::fs::TryLockError::WouldBlock) => return Err(OwnerError::AlreadyOwned),
        Err(err) => return Err(OwnerError::Io(io::Error::other(err))),
    }
    Ok((runtime_dir, Election(lock)))
}

impl Owner {
    /// Elects the single writer for `data_root` or fails closed. The lock is
    /// advisory and held for the owner's whole lifetime; dropping the owner
    /// releases it after its store, and a failed election releases the same
    /// way. An unlock failure is handed to the surface that dropped the
    /// owner, which drains it after the drop (`Runtime::release`).
    ///
    /// # Errors
    /// [`OwnerError::AlreadyOwned`] when another process holds the lock,
    /// [`OwnerError::Io`] when the lock file cannot be opened, and the store
    /// admission refusals [`TaskStore::open`] reports.
    pub fn elect(data_root: &Path) -> Result<Self, OwnerError> {
        let (runtime_dir, election) = elect_lock(data_root)?;
        let store = TaskStore::open(&runtime_dir.join("rivect.db"))?;
        Ok(Self {
            store,
            generation: 1,
            runtime_dir,
            _election: election,
        })
    }

    /// Elects the owner for the production startup: the lock is taken exactly as
    /// [`Owner::elect`] takes it, but the store arrives admitted and *not yet
    /// bootstrapped*. The caller publishes the schema it needs together with the
    /// base and the policy it validated in one transaction
    /// ([`TaskStore::publish_generation`]), so no generation is visible before all
    /// of it is; a failure drops this owner and its election with it, which is
    /// what a refused startup owes the data root.
    ///
    /// # Errors
    /// The same election, data-root and admission refusals as [`Owner::elect`].
    pub(crate) fn elect_deferred(data_root: &Path) -> Result<Self, OwnerError> {
        let (runtime_dir, election) = elect_lock(data_root)?;
        let store = TaskStore::open_deferred(&runtime_dir.join("rivect.db"))?;
        Ok(Self {
            store,
            generation: 1,
            runtime_dir,
            _election: election,
        })
    }

    pub fn runtime_dir(&self) -> &Path {
        &self.runtime_dir
    }

    /// The owner's task store, read-only: writes go through
    /// `Runtime::store_writer`.
    #[must_use]
    pub fn store(&self) -> &TaskStore {
        &self.store
    }

    /// The owner's current generation.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn reopen_store(&mut self) -> Result<(), StoreError> {
        self.store.reopen(&self.runtime_dir.join("rivect.db"))
    }

    /// DEC-051: closes the store through the typed close (healthy
    /// optimize/checkpoint path included); the owner lock stays held.
    pub fn close_store(&mut self) -> Result<(), StoreError> {
        self.store.close()
    }
}

/// Reads the user's config document through the owner's one bounded
/// ingress (DEC-054): a missing file is `Ok(None)`, an oversize, a
/// non-UTF-8, or an unreadable file is the typed owner error. Boot and
/// the Runtime's config reload share it, so no second reader exists.
/// The ingress is one checked open — `O_NOFOLLOW|O_NONBLOCK` with the
/// opened fd's own metadata naming a regular file (DEC-056) — so a
/// symlink or FIFO swapped onto the path can neither redirect nor hang
/// the read, and the caller's previous view survives every typed
/// failure.
///
/// # Errors
/// Returns [`OwnerError::ConfigRead`] or [`OwnerError::ConfigTooLarge`].
/// The `source()` of a read failure is the original `io::Error` the open,
/// the metadata call or the bounded read returned, with its errno and
/// payload untouched.
pub fn read_user_config(path: &Path, limit: usize) -> Result<Option<String>, OwnerError> {
    use std::io::Read as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let read_failed = |source: io::Error| OwnerError::ConfigRead {
        path: path.to_path_buf(),
        source,
    };
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(
            rivect_sandbox_helper::ANCHOR_O_NOFOLLOW | rivect_sandbox_helper::OPEN_NONBLOCK,
        )
        .open(path)
    {
        Ok(file) => file,
        // Only a missing file reads as absence; a permission failure,
        // a swapped-on symlink (ELOOP), and any other open refusal are
        // typed read failures.
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(read_failed(source)),
    };
    let meta = match proof::config_metadata_fault() {
        Some(error) => Err(error),
        None => file.metadata(),
    }
    .map_err(read_failed)?;
    if !meta.is_file() {
        return Err(read_failed(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the user config path is not a regular file",
        )));
    }
    if meta.len() > limit as u64 {
        return Err(OwnerError::ConfigTooLarge {
            path: path.to_path_buf(),
            limit,
        });
    }
    // The take-bounded read catches growth between the fstat and the
    // read instead of allocating past the ceiling.
    let mut bytes = Vec::new();
    let read = match proof::config_read_fault() {
        Some(error) => Err(error),
        None => file.take(limit as u64 + 1).read_to_end(&mut bytes),
    };
    read.map_err(read_failed)?;
    if bytes.len() > limit {
        return Err(OwnerError::ConfigTooLarge {
            path: path.to_path_buf(),
            limit,
        });
    }
    let text = String::from_utf8(bytes)
        .map_err(|source| read_failed(io::Error::new(io::ErrorKind::InvalidData, source)))?;
    Ok(Some(text))
}

/// Production proof seam of the config ingress: the unarmed build is
/// production-equivalent and no flag or environment variable arms it.
#[cfg(not(test))]
mod proof {
    pub(super) fn config_metadata_fault() -> Option<std::io::Error> {
        None
    }
    pub(super) fn config_read_fault() -> Option<std::io::Error> {
        None
    }
}

/// The test twin: one armed fault per call site, taken on use, so a
/// mapping proof sees the object its boundary call returned.
#[cfg(test)]
pub(crate) mod proof {
    use std::cell::Cell;
    use std::io;

    thread_local! {
        static METADATA: Cell<Option<io::Error>> = const { Cell::new(None) };
        static READ: Cell<Option<io::Error>> = const { Cell::new(None) };
    }

    /// Arms `error` as the result of this thread's next config `metadata` call.
    pub fn arm_config_metadata_fault(error: io::Error) {
        METADATA.with(|slot| slot.set(Some(error)));
    }

    /// Arms `error` as the result of this thread's next bounded config read.
    pub fn arm_config_read_fault(error: io::Error) {
        READ.with(|slot| slot.set(Some(error)));
    }

    pub(super) fn config_metadata_fault() -> Option<io::Error> {
        METADATA.with(Cell::take)
    }

    pub(super) fn config_read_fault() -> Option<io::Error> {
        READ.with(Cell::take)
    }
}

#[cfg(test)]
mod tests {
    use super::{Owner, OwnerError, proof, read_user_config};
    use crate::state::{proof as proof_state, take_release_lines};
    use std::path::PathBuf;

    type Ingress = Result<(), Box<dyn std::error::Error>>;

    fn scratch(name: &str) -> Result<tempfile::TempDir, Box<dyn std::error::Error>> {
        Ok(tempfile::TempDir::with_prefix(format!(
            "rivect-owner-ingress-{name}-"
        ))?)
    }

    #[test]
    fn an_absent_config_is_the_only_absent_answer() -> Ingress {
        let root = scratch("absent")?;
        assert!(
            matches!(
                read_user_config(&root.path().join("missing.toml"), 64),
                Ok(None)
            ),
            "a missing file is absence"
        );
        Ok(())
    }

    #[test]
    fn a_regular_config_reads_bounded() -> Ingress {
        let root = scratch("regular")?;
        let path = root.path().join("config.toml");
        std::fs::write(&path, "[workflow]\nenabled = false\n")?;
        assert_eq!(
            read_user_config(&path, 64)?,
            Some("[workflow]\nenabled = false\n".to_string())
        );
        Ok(())
    }

    #[test]
    fn an_oversize_config_is_the_typed_ceiling() -> Ingress {
        let root = scratch("oversize")?;
        let path = root.path().join("config.toml");
        std::fs::write(&path, "x".repeat(65))?;
        match read_user_config(&path, 64) {
            Err(OwnerError::ConfigTooLarge { limit, .. }) => assert_eq!(limit, 64),
            other => unreachable!("an oversize config is the typed ceiling, got {other:?}"),
        }
        Ok(())
    }

    #[test]
    fn a_non_utf8_config_is_a_typed_read_failure() -> Ingress {
        let root = scratch("utf8")?;
        let path = root.path().join("config.toml");
        std::fs::write(&path, [0xff, 0xfe, 0x0a])?;
        assert!(
            matches!(
                read_user_config(&path, 64),
                Err(OwnerError::ConfigRead { source, .. })
                    if source.kind() == std::io::ErrorKind::InvalidData
            ),
            "corrupt bytes are a typed read failure"
        );
        Ok(())
    }

    #[test]
    fn a_config_symlink_refuses_typed() -> Ingress {
        let root = scratch("symlink")?;
        let target = root.path().join("real.toml");
        std::fs::write(&target, "[workflow]\n")?;
        let link = root.path().join("config.toml");
        std::os::unix::fs::symlink(&target, &link)?;
        assert!(
            matches!(
                read_user_config(&link, 64),
                Err(OwnerError::ConfigRead { .. })
            ),
            "a swapped-on symlink never redirects the read"
        );
        Ok(())
    }

    #[test]
    fn a_config_socket_refuses_typed_without_blocking() -> Ingress {
        let root = scratch("socket")?;
        let path = root.path().join("config.toml");
        let _listener = std::os::unix::net::UnixListener::bind(&path)?;
        assert!(
            matches!(
                read_user_config(&path, 64),
                Err(OwnerError::ConfigRead { .. })
            ),
            "a special file at the config path is a typed read failure"
        );
        Ok(())
    }

    #[test]
    fn a_config_directory_refuses_typed() -> Ingress {
        let root = scratch("dir")?;
        let path: PathBuf = root.path().join("config.toml");
        std::fs::create_dir_all(&path)?;
        assert!(
            matches!(
                read_user_config(&path, 64),
                Err(OwnerError::ConfigRead { source, .. })
                    if source.kind() == std::io::ErrorKind::InvalidInput
            ),
            "a directory is the typed not-regular refusal"
        );
        Ok(())
    }

    #[derive(Debug, thiserror::Error)]
    #[error("staged config fault")]
    struct Staged {
        nonce: u64,
    }

    fn assert_no_release_lines() {
        assert_eq!(
            take_release_lines(),
            Vec::<String>::new(),
            "no release fault is pending"
        );
    }

    #[test]
    fn config_metadata_and_read_failures_keep_the_original_io_error() -> Ingress {
        let root = scratch("original")?;
        let path = root.path().join("config.toml");
        std::fs::write(&path, "[workflow]\n")?;

        proof::arm_config_metadata_fault(std::io::Error::from_raw_os_error(5));
        match read_user_config(&path, 64) {
            Err(error @ OwnerError::ConfigRead { .. }) => {
                assert_eq!(
                    error.to_string(),
                    format!(
                        "owner configuration failed: {}: read failed",
                        path.display()
                    ),
                    "the stage is named, the cause is not repeated"
                );
                let original = std::error::Error::source(&error)
                    .and_then(|source| source.downcast_ref::<std::io::Error>())
                    .ok_or("the metadata failure is the source")?;
                assert_eq!(original.raw_os_error(), Some(5));
                assert!(original.get_ref().is_none(), "no payload was added");
            }
            other => unreachable!("a metadata failure is the typed read failure, got {other:?}"),
        }

        proof::arm_config_read_fault(std::io::Error::other(Staged { nonce: 7 }));
        match read_user_config(&path, 64) {
            Err(OwnerError::ConfigRead { source, .. }) => {
                let staged = source
                    .get_ref()
                    .and_then(|payload| payload.downcast_ref::<Staged>())
                    .ok_or("the read failure keeps its payload")?;
                assert_eq!(staged.nonce, 7);
            }
            other => unreachable!("a read failure is the typed read failure, got {other:?}"),
        }
        // Each fault is taken by its one call: the next read is healthy.
        assert_eq!(
            read_user_config(&path, 64)?,
            Some("[workflow]\n".to_string())
        );
        Ok(())
    }

    #[test]
    fn election_releases_while_a_duplicate_lives() -> Ingress {
        proof_state::run_isolated_release_test(
            "owner::tests::election_releases_while_a_duplicate_lives",
            || {
                assert_no_release_lines();
                let root = scratch("election-duplicate")?;
                let owner = Owner::elect(root.path())?;
                let duplicate = owner._election.0.try_clone()?;
                assert!(
                    matches!(Owner::elect(root.path()), Err(OwnerError::AlreadyOwned)),
                    "a second election while the owner lives is refused"
                );
                drop(owner);
                // The duplicate keeps the election description alive: only the
                // explicit unlock lets the next election win.
                let again = Owner::elect(root.path())?;
                drop(again);
                drop(duplicate);
                assert_no_release_lines();
                Ok(())
            },
        )
    }

    #[test]
    fn owner_release_failures_close_in_order_and_hand_off_once() -> Ingress {
        proof_state::run_isolated_release_test(
            "owner::tests::owner_release_failures_close_in_order_and_hand_off_once",
            || {
                const LINES: [&str; 2] = [
                    "database writer lock release failed: other error",
                    "owner lock release failed: other error",
                ];
                assert_no_release_lines();
                let root = scratch("release-faults")?;
                let owner = Owner::elect(root.path())?;
                let duplicate = owner._election.0.try_clone()?;
                proof_state::arm_unlock_faults(2);
                drop(owner);
                assert_eq!(take_release_lines(), LINES, "the store releases first");
                assert_no_release_lines();
                // The failed unlock still closed the descriptor: the duplicate
                // keeps the election, and only until it closes.
                assert!(
                    matches!(Owner::elect(root.path()), Err(OwnerError::AlreadyOwned)),
                    "the duplicate keeps refusing"
                );
                drop(duplicate);
                drop(Owner::elect(root.path())?);

                // A failed election releases through the same two drops.
                proof_state::arm_bootstrap_fault();
                proof_state::arm_unlock_faults(2);
                let failed = Owner::elect(root.path());
                assert!(
                    matches!(failed, Err(OwnerError::Store(_))),
                    "the bootstrap fault is the storage failure"
                );
                assert_eq!(take_release_lines(), LINES, "store first, election last");
                assert_no_release_lines();
                drop(Owner::elect(root.path())?);
                assert_no_release_lines();
                Ok(())
            },
        )
    }
}

/// The in-crate twins of the closed-surface doctests: the same
/// expressions over `crate::` paths must compile, so each doctest's
/// failure is attributable to visibility only.
#[cfg(test)]
mod closed_surface_twins {
    use super::Owner;
    use crate::state::TaskStore;

    fn store_borrow(owner: &mut Owner) {
        let _s: &mut TaskStore = &mut owner.store;
    }

    fn generation_write(owner: &mut Owner) {
        owner.generation = 2;
    }

    #[test]
    fn the_closed_owner_items_are_reachable_inside_the_crate() {
        let _: fn(&mut Owner) = store_borrow;
        let _: fn(&mut Owner) = generation_write;
    }
}
