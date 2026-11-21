//! Local credential persistence.
//!
//! Rivect keeps provider material in one owner-only JSON document beside the
//! runtime database, like the reference CLIs' `auth.json`/`agent.db` rather
//! than an OS keychain. The file holds scoped entries as byte arrays; the
//! scope key is the same `service/account/.../profile` token config carries,
//! so a reference names its location and never its material. Writes replace
//! the document atomically and the temporary file inherits the owner-only
//! mode; reads never mutate.

use super::{CredentialStore, ProviderError, SecretRef, StoreKind};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};

/// Schema of the owner's credential document.
const SCHEMA_VERSION: u32 = 1;
/// Bounds one read: every admitted key is ≤ 8 KiB and the document holds a
/// handful of scopes, so a larger file is not one this build wrote.
const MAX_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Document {
    version: u32,
    entries: BTreeMap<String, Vec<u8>>,
}

/// `CredentialStore` over the owner's credential document.
pub(super) struct FileBackend {
    path: PathBuf,
    namespace: String,
}

impl FileBackend {
    pub(super) fn new(path: PathBuf, namespace: &str) -> Self {
        Self {
            path,
            namespace: namespace.to_string(),
        }
    }

    /// Serializes read-modify-write cycles across every backend instance:
    /// the login seam and the provider seam open separate instances over the
    /// same document. The owner process is the only writer; shortcut:
    /// cross-process writers need a file lock, add one when a second writer
    /// can enroll against a live runtime.
    fn guard() -> MutexGuard<'static, ()> {
        static LOCK: Mutex<()> = Mutex::new(());
        LOCK.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn in_namespace(&self, service: &str) -> bool {
        service == self.namespace
            || service
                .strip_prefix(&self.namespace)
                .is_some_and(|rest| rest.starts_with('.'))
    }

    fn admit(&self, credential: &SecretRef) -> Result<(), ProviderError> {
        if self.in_namespace(credential.service()) {
            Ok(())
        } else {
            Err(ProviderError::CredentialOutsideNamespace {
                store: StoreKind::File,
                scope: credential.scope().to_string(),
            })
        }
    }

    fn read(&self) -> Result<BTreeMap<String, Vec<u8>>, ProviderError> {
        let file = match File::open(&self.path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(BTreeMap::new());
            }
            Err(error) => return Err(unavailable(error)),
        };
        let mut bytes = Vec::new();
        file.take(MAX_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(unavailable)?;
        if bytes.len() as u64 > MAX_BYTES {
            return Err(unavailable("the credential file exceeds the size bound"));
        }
        let Ok(document) = serde_json::from_slice::<Document>(&bytes) else {
            return Err(unavailable("the credential file is invalid"));
        };
        if document.version != SCHEMA_VERSION {
            return Err(unavailable(
                "the credential file has an unsupported schema version",
            ));
        }
        Ok(document.entries)
    }

    fn write(&self, entries: BTreeMap<String, Vec<u8>>) -> Result<(), ProviderError> {
        let Some(parent) = self.path.parent() else {
            return Err(unavailable("the credential path has no parent"));
        };
        fs::create_dir_all(parent).map_err(unavailable)?;
        let document = Document {
            version: SCHEMA_VERSION,
            entries,
        };
        let mut bytes = serde_json::to_vec(&document).map_err(unavailable)?;
        bytes.push(b'\n');
        let mut temp = tempfile::NamedTempFile::new_in(parent).map_err(unavailable)?;
        temp.write_all(&bytes).map_err(unavailable)?;
        temp.as_file().sync_all().map_err(unavailable)?;
        temp.persist(&self.path)
            .map(|_| ())
            .map_err(|error| unavailable(error.error))?;
        Ok(())
    }

    /// The scopes the owner's document records under `service` — the census
    /// feeds the precheck journal, never a credential read.
    fn accounts(&self, service: &str) -> Result<Vec<String>, ProviderError> {
        if !self.in_namespace(service) {
            return Err(ProviderError::CredentialOutsideNamespace {
                store: StoreKind::File,
                scope: service.to_string(),
            });
        }
        let mut accounts = self
            .read()?
            .into_keys()
            .filter(|scope| scope_service(scope) == service)
            .collect::<Vec<_>>();
        accounts.sort();
        accounts.dedup();
        Ok(accounts)
    }
}

fn scope_service(scope: &str) -> &str {
    &scope[..scope.find('/').unwrap_or(scope.len())]
}

fn unavailable(reason: impl std::fmt::Display) -> ProviderError {
    ProviderError::StoreUnavailable {
        store: StoreKind::File,
        reason: reason.to_string(),
    }
}

impl CredentialStore for FileBackend {
    fn kind(&self) -> StoreKind {
        StoreKind::File
    }

    fn occupied(&self, credential: &SecretRef) -> Result<bool, ProviderError> {
        self.admit(credential)?;
        Ok(self.read()?.contains_key(credential.scope()))
    }

    fn entry_accounts(&self, service: &str) -> Result<Vec<String>, ProviderError> {
        self.accounts(service)
    }

    fn login(&self, credential: &SecretRef, secret: &[u8]) -> Result<(), ProviderError> {
        self.admit(credential)?;
        let _guard = Self::guard();
        let mut entries = self.read()?;
        if entries.contains_key(credential.scope()) {
            return Err(ProviderError::CredentialOccupied {
                scope: credential.scope().to_string(),
            });
        }
        entries.insert(credential.scope().to_string(), secret.to_vec());
        self.write(entries)
    }

    fn resolve(&self, credential: &SecretRef) -> Result<Vec<u8>, ProviderError> {
        self.admit(credential)?;
        self.read()?
            .remove(credential.scope())
            .ok_or_else(|| ProviderError::CredentialAbsent {
                scope: credential.scope().to_string(),
            })
    }

    fn refresh(&self, credential: &SecretRef, secret: &[u8]) -> Result<(), ProviderError> {
        self.admit(credential)?;
        let _guard = Self::guard();
        let mut entries = self.read()?;
        entries.insert(credential.scope().to_string(), secret.to_vec());
        self.write(entries)
    }

    fn revoke(&self, credential: &SecretRef) -> Result<(), ProviderError> {
        self.admit(credential)?;
        let _guard = Self::guard();
        let mut entries = self.read()?;
        if entries.remove(credential.scope()).is_none() {
            return Err(ProviderError::CredentialAbsent {
                scope: credential.scope().to_string(),
            });
        }
        self.write(entries)
    }

    fn logout(&self, credential: &SecretRef) -> Result<(), ProviderError> {
        self.revoke(credential)
    }
}

/// The owner's credential document under a data root. The path is fixed so a
/// restart, the login seam and the provider seam all address one document.
#[must_use]
pub(super) fn path(root: &Path) -> PathBuf {
    root.join("runtime").join("credentials.json")
}
