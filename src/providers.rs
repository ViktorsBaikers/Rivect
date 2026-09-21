//! Provider adapters. The loopback provider is the owner-brokered local
//! fixture for offline first-task proof; live dialects arrive in later
//! slices. Workers never hold a provider handle, only the broker does.
//!
//! The scoped credential-profile seam (SRC-010) also lives here:
//! [`SecretRef`] is the only token that crosses into config, adapters,
//! diagnostics and manifests, and [`CredentialStore`] is the only path
//! between a native secret store and an adapter — secret bytes never
//! leave the store boundary (INV-001).

use crate::config::{Config, ConnKind, Connection, ModelAssign, Profile};
use crate::model::RequestManifest;
use crate::resources::UsageDelta;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};

pub mod gemini;
pub mod local;
pub mod openai;
pub mod sse;

#[derive(Debug, Clone, PartialEq)]
pub struct ToolCall {
    pub tool: String,
    pub path: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProviderReply {
    pub text: String,
    pub tool_calls: Vec<ToolCall>,
    /// The physical usage report of this one send (INV-022/INV-024):
    /// it travels inside the reply, so one physical send produces one
    /// accounting record — `Unknown` when the provider reported none,
    /// never an estimate and never a zero the retained bound could
    /// release as.
    pub usage: UsageDelta,
}

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum ProviderError {
    #[error("provider capability unavailable: model references unknown connection")]
    UnknownConnection,
    #[error("provider capability unavailable: {kind} connection requires a separate live grant")]
    LiveGrantRequired { kind: ConnKind },
    /// DEC-014: the named store class cannot serve the call — absent,
    /// locked or denied. `reason` is the platform's own Display text
    /// verbatim — expected to name the condition; the seam cannot detect
    /// material a platform embeds in it. No plaintext fallback exists
    /// (INV-006).
    #[error("credential store {store} is unavailable: {reason}")]
    StoreUnavailable { store: StoreKind, reason: String },
    /// DEC-014: the store answered with more than one credential for the
    /// scope — resolution is denied rather than picking one silently.
    #[error("credential store {store} answered ambiguously for the scope")]
    StoreAmbiguous { store: StoreKind },
    /// DEC-014: the connection's resolved binding names no usable scoped
    /// reference. `scope` is the config key path that failed, not a value;
    /// `cause` carries the parse verdict when the bound ref was malformed
    /// and is `None` when the binding named no ref at all.
    #[error("credential for connection {connection} is unresolved at {scope}")]
    CredentialUnresolved {
        connection: String,
        scope: String,
        #[source]
        cause: Option<SecretRefError>,
    },
    /// DEC-014: a profile-bound ref whose trailing scope segment is not the
    /// bound profile's name — scope and binding cannot diverge.
    #[error(
        "connection {connection} binds profile {profile} but the credential scope names another profile"
    )]
    CredentialProfileMismatch { connection: String, profile: String },
    /// The ref targets a different store class or a service prefix outside
    /// this backend's admitted namespace — refused before any store call.
    #[error("credential scope {scope} is outside the {store} store's admitted namespace")]
    CredentialOutsideNamespace { store: StoreKind, scope: String },
    /// Enrollment is create-only: an occupied scope is a collision the
    /// caller must reconcile, never an implicit overwrite.
    #[error("credential scope {scope} already holds material")]
    CredentialOccupied { scope: String },
    /// No material exists at the scope — distinct from an empty secret.
    #[error("no credential material at scope {scope}")]
    CredentialAbsent { scope: String },
    /// The resolved credential material cannot serve this dialect —
    /// non-UTF-8 bytes where the contract needs a bearer token. The
    /// material itself never appears in the error.
    #[error("credential material for connection {connection} is not usable by this dialect")]
    CredentialMalformed { connection: String },
    /// DEC-007: the manifest's pin names a connection whose recorded
    /// source class is not this adapter's dialect — dialect selection
    /// keys on the literal connection id, never an auth label.
    #[error("connection {connection} does not speak this adapter's dialect")]
    DialectMismatch { connection: String },
    /// The manifest carries no pinned model id for the wire request —
    /// an auto assignment resolves its model at catalogue time, which
    /// this adapter does not hold.
    #[error("connection {connection} requires a fixed model pin on the wire request")]
    UnpinnedModel { connection: String },
    /// DEC-014: the connection's configured region names an endpoint
    /// outside this dialect's recorded contract — a configured region
    /// is never silently ignored.
    #[error("connection {connection} region {region} is outside the dialect's endpoint contract")]
    RegionMismatch { connection: String, region: String },
    /// The transport failed before a usable reply — connect, TLS,
    /// status or read failure. `reason` carries the client's own text;
    /// it never contains secret material.
    #[error("connection {connection} transport failed: {reason}")]
    Transport { connection: String, reason: String },
    /// The provider's own terminal event reported a failed or
    /// incomplete response — a peer verdict, not a parse error.
    #[error("connection {connection} reported failure: {reason}")]
    ProviderFailed { connection: String, reason: String },
    /// The stream ended without a terminal event the dialect can
    /// classify, or a terminal carried an outcome it cannot — unknown
    /// is never success.
    #[error("connection {connection} ended without a classifiable terminal event")]
    UnknownTerminal { connection: String },
    /// A wire event or item was malformed — bad JSON, a missing
    /// mandatory field, a truncated item or an over-limit line.
    #[error("connection {connection} stream violated the dialect contract: {reason}")]
    StreamViolation { connection: String, reason: String },
    /// A well-formed output item the dialect cannot honour — an
    /// unbounded server-side tool kind or a tool shape the frozen
    /// request never declared.
    #[error("connection {connection} produced an incompatible output: {reason}")]
    IncompatibleOutput { connection: String, reason: String },
    /// DEC-012: a reasoning artifact outside this manifest's
    /// session/epoch lineage — absent or foreign `encrypted_content`
    /// is a provenance failure, never silently dropped or replayed.
    #[error("connection {connection} returned a reasoning artifact outside the lineage: {reason}")]
    ReasoningProvenance { connection: String, reason: String },
}

/// The native secret-store class a credential reference resolves to
/// (SRC-010). `keyring:` in a config ref binds the platform's native class;
/// `keychain:`/`secret-service:` pin a class explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreKind {
    /// macOS Keychain (`apple-native-keyring-store`, keychain feature).
    Keychain,
    /// Linux Secret Service over D-Bus (`zbus-secret-service-keyring-store`).
    SecretService,
}

impl std::fmt::Display for StoreKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            StoreKind::Keychain => "keychain",
            StoreKind::SecretService => "secret-service",
        })
    }
}

/// Why a raw string is not a usable [`SecretRef`]. Fields carry the
/// rejected token — a reference shape, never stored material.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SecretRefError {
    /// Not the `store:scope` shape — missing separator, empty scope,
    /// whitespace, or empty `/` segments.
    #[error("credential reference is not a scoped store:scope reference")]
    NotScoped,
    /// Well-formed, but the store label names no admitted class.
    #[error("credential reference names an unsupported credential store: {store}")]
    UnsupportedStore { store: String },
}

/// A scoped credential reference — the only token that may cross from a
/// store into config, adapters, diagnostics or a manifest (INV-001). The
/// grammar is `store:account[/origin/]profile`, the same `store:scope`
/// shape `scoped_secret_ref` validates at config ingress and re-validated
/// here on the trust boundary. A `SecretRef` names where material lives;
/// it never contains material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretRef {
    store: StoreKind,
    raw: String,
    scope: String,
}

impl SecretRef {
    /// Parses `store:scope`. `keyring` resolves to this platform's native
    /// store class; `keychain`/`secret-service` pin a class. Anything else
    /// — including `env:`, `file:` or a bare token — is refused, so an
    /// adapter can never be handed a plaintext-or-env indirection (INV-006).
    ///
    /// # Errors
    /// [`SecretRefError::NotScoped`] for shape violations;
    /// [`SecretRefError::UnsupportedStore`] for an unadmitted store label.
    pub fn parse(raw: &str) -> Result<Self, SecretRefError> {
        let Some((store, scope)) = raw.split_once(':') else {
            return Err(SecretRefError::NotScoped);
        };
        let store_ok = !store.is_empty()
            && store
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic())
            && store
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'));
        let scope_ok = !scope.is_empty()
            && !scope.chars().any(char::is_whitespace)
            && scope.split('/').all(|segment| !segment.is_empty());
        if !store_ok || !scope_ok {
            return Err(SecretRefError::NotScoped);
        }
        let store = match store {
            "keyring" => native_store_kind(),
            "keychain" => StoreKind::Keychain,
            "secret-service" | "secret_service" => StoreKind::SecretService,
            _ => {
                return Err(SecretRefError::UnsupportedStore {
                    store: store.to_string(),
                });
            }
        };
        Ok(Self {
            store,
            raw: raw.to_string(),
            scope: scope.to_string(),
        })
    }

    /// The resolved store class.
    #[must_use]
    pub fn store(&self) -> StoreKind {
        self.store
    }

    /// The scope path — `account[/origin/]profile`.
    #[must_use]
    pub fn scope(&self) -> &str {
        &self.scope
    }

    /// The verbatim `store:scope` token — safe for diagnostics and journals
    /// (a reference is config data, not material).
    #[must_use]
    pub fn raw(&self) -> &str {
        &self.raw
    }

    /// The leading scope segment — the account namespace the backend uses
    /// as its service bucket and the namespace prefix guards match on.
    #[must_use]
    pub fn service(&self) -> &str {
        &self.scope[..self.scope.find('/').unwrap_or(self.scope.len())]
    }

    /// The trailing scope segment — the credential profile. A
    /// `profiles.<name>` binding must agree with it (DEC-014 mismatch).
    #[must_use]
    pub fn profile(&self) -> &str {
        &self.scope[self.scope.rfind('/').map_or(0, |i| i + 1)..]
    }
}

impl std::fmt::Display for SecretRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.raw)
    }
}

/// `keyring:` binds this platform's native store class. On platforms
/// without an admitted native store the class still resolves — the backend
/// constructor then answers `StoreUnavailable` (INV-006).
#[cfg(target_os = "macos")]
const fn native_store_kind() -> StoreKind {
    StoreKind::Keychain
}

/// Linux: `keyring:` binds Secret Service.
#[cfg(target_os = "linux")]
const fn native_store_kind() -> StoreKind {
    StoreKind::SecretService
}

/// Other platforms have no admitted native store; resolving to a class
/// keeps parsing total while [`native_store`] reports it unavailable.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
const fn native_store_kind() -> StoreKind {
    StoreKind::Keychain
}

/// The credential-store seam (SRC-010): the only path between a native
/// secret store and an adapter. Secret bytes cross this boundary only as
/// `&[u8]` arguments and `Vec<u8>` returns — every other surface sees the
/// scoped [`SecretRef`] (INV-001). Implementations fail closed with typed
/// errors; none may substitute plaintext or env storage (INV-006).
///
/// Lifecycle: `login` enrolls and refuses an occupied scope
/// (`CredentialOccupied` — enrollment never overwrites); `refresh` replaces
/// material at the scope; `revoke` and `logout` delete it; `resolve`
/// returns the bytes or `CredentialAbsent`.
pub trait CredentialStore: Send + Sync {
    /// The store class this backend serves.
    fn kind(&self) -> StoreKind;
    /// Whether material exists at the scope.
    ///
    /// # Errors
    /// [`ProviderError::CredentialOutsideNamespace`] for a foreign scope;
    /// [`ProviderError::StoreUnavailable`]/`StoreAmbiguous` on a failed or
    /// ambiguous store answer.
    fn occupied(&self, credential: &SecretRef) -> Result<bool, ProviderError>;
    /// User ids of entries under `service` — the namespace census the
    /// precheck journals before any write (DEC-002). An entry's `user`
    /// specifier is the full scope path, so the census returns scope
    /// paths, never material.
    ///
    /// # Errors
    /// [`ProviderError::CredentialOutsideNamespace`] for a foreign service;
    /// [`ProviderError::StoreUnavailable`] on a failed search.
    fn entry_accounts(&self, service: &str) -> Result<Vec<String>, ProviderError>;
    /// Enrolls `secret` at the scope.
    ///
    /// # Errors
    /// [`ProviderError::CredentialOccupied`] when the scope holds material —
    /// checked before the write; [`ProviderError::CredentialOutsideNamespace`],
    /// `StoreUnavailable`/`StoreAmbiguous` on store conditions.
    fn login(&self, credential: &SecretRef, secret: &[u8]) -> Result<(), ProviderError>;
    /// Reads the material at the scope.
    ///
    /// # Errors
    /// [`ProviderError::CredentialAbsent`] when the scope is empty;
    /// `CredentialOutsideNamespace`/`StoreUnavailable`/`StoreAmbiguous` on
    /// store conditions.
    fn resolve(&self, credential: &SecretRef) -> Result<Vec<u8>, ProviderError>;
    /// Replaces the material at the scope.
    ///
    /// # Errors
    /// `CredentialOutsideNamespace`/`StoreUnavailable`/`StoreAmbiguous` on
    /// store conditions.
    fn refresh(&self, credential: &SecretRef, secret: &[u8]) -> Result<(), ProviderError>;
    /// Deletes the entry at the scope (credential revocation).
    ///
    /// # Errors
    /// `CredentialOutsideNamespace`/`StoreUnavailable`/`StoreAmbiguous` on
    /// store conditions.
    fn revoke(&self, credential: &SecretRef) -> Result<(), ProviderError>;
    /// Deletes the entry at the scope (profile teardown).
    ///
    /// # Errors
    /// `CredentialOutsideNamespace`/`StoreUnavailable`/`StoreAmbiguous` on
    /// store conditions.
    fn logout(&self, credential: &SecretRef) -> Result<(), ProviderError>;
}

/// `CredentialStore` over a keyring-core backend (SRC-010 explicit stores).
/// Entry identity is `(service, user)` = (the scope's leading namespace
/// segment, the full scope path) — the scope encodes account/origin/profile
/// so writes stay scoped. `namespace` is the admitted service prefix: a ref
/// outside it — or aimed at another store class — is refused as
/// [`ProviderError::CredentialOutsideNamespace`] before any store call.
pub struct KeyringBackend {
    store: Arc<keyring_core::CredentialStore>,
    kind: StoreKind,
    namespace: String,
    /// Per-scope enrollment serialization: `login`'s create-only
    /// check-then-act has no atomic create-if-absent in the keyring API,
    /// so same-scope enrollments queue on a per-scope mutex and a queued
    /// caller's `occupied` check observes the earlier write. Entries are
    /// retained — removing a slot between a holder's release and a parked
    /// waiter's acquire would reopen the race — and the map stays bounded
    /// by the distinct scopes this backend serves. The guarantee is
    /// login-vs-login on this one instance: `refresh`/`revoke` skip these
    /// locks entirely, a second `KeyringBackend` holds a disjoint map, and
    /// a writer outside this instance — another backend or process —
    /// silently overwrites the entry, since both admitted backends upsert
    /// (`security-framework` answers `errSecDuplicateItem` with
    /// `SecItemUpdate`; the secret-service store creates items with
    /// `replace = true`). No store error surfaces that race.
    login_locks: Mutex<BTreeMap<String, Arc<Mutex<()>>>>,
}

impl std::fmt::Debug for KeyringBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The store trait object has no Debug; the class and namespace
        // identify the backend for diagnostics.
        f.debug_struct("KeyringBackend")
            .field("kind", &self.kind)
            .field("namespace", &self.namespace)
            .finish_non_exhaustive()
    }
}

impl KeyringBackend {
    /// Wraps an opened keyring-core store. `namespace` is the service
    /// prefix the backend admits — `rivect` in production, `rivect-test`
    /// under the harness (DEC-002).
    pub fn new(
        store: Arc<keyring_core::CredentialStore>,
        kind: StoreKind,
        namespace: &str,
    ) -> Self {
        Self {
            store,
            kind,
            namespace: namespace.to_string(),
            login_locks: Mutex::new(BTreeMap::new()),
        }
    }

    /// `service` is inside the namespace when it equals it or extends it by
    /// a `.`-separated component (`rivect-test.work`).
    fn in_namespace(&self, service: &str) -> bool {
        service == self.namespace
            || service
                .strip_prefix(&self.namespace)
                .is_some_and(|rest| rest.starts_with('.'))
    }

    /// Builds the native entry specifier — a pure value construction with
    /// no store effect — after the namespace guard. Every op goes through
    /// here, so a foreign ref is refused before any store call.
    fn entry(&self, credential: &SecretRef) -> Result<keyring_core::Entry, ProviderError> {
        if credential.store() != self.kind || !self.in_namespace(credential.service()) {
            return Err(ProviderError::CredentialOutsideNamespace {
                store: self.kind,
                scope: credential.scope().to_string(),
            });
        }
        self.store
            .build(credential.service(), credential.scope(), None)
            .map_err(|err| self.map_error(credential, err))
    }

    /// One occupancy read on an already-built entry: `NoEntry` is an empty
    /// slot; every other condition maps to the typed vocabulary.
    fn entry_occupied(
        &self,
        credential: &SecretRef,
        entry: &keyring_core::Entry,
    ) -> Result<bool, ProviderError> {
        match entry.get_secret() {
            Ok(_) => Ok(true),
            Err(err) => match self.map_error(credential, err) {
                ProviderError::CredentialAbsent { .. } => Ok(false),
                other => Err(other),
            },
        }
    }

    /// Maps keyring-core conditions onto the typed vocabulary (DEC-014).
    /// `NoEntry` is `CredentialAbsent`; `Ambiguous` is `StoreAmbiguous`;
    /// every other condition — denied access, platform failure, a store
    /// refusing oversized material — is `StoreUnavailable` carrying the
    /// platform's own reason text verbatim — expected to name the
    /// condition; the seam cannot detect material a platform embeds.
    fn map_error(&self, credential: &SecretRef, err: keyring_core::Error) -> ProviderError {
        match err {
            keyring_core::Error::NoEntry => ProviderError::CredentialAbsent {
                scope: credential.scope().to_string(),
            },
            keyring_core::Error::Ambiguous(_) => ProviderError::StoreAmbiguous { store: self.kind },
            other => ProviderError::StoreUnavailable {
                store: self.kind,
                reason: other.to_string(),
            },
        }
    }
}

impl CredentialStore for KeyringBackend {
    fn kind(&self) -> StoreKind {
        self.kind
    }

    fn occupied(&self, credential: &SecretRef) -> Result<bool, ProviderError> {
        let entry = self.entry(credential)?;
        self.entry_occupied(credential, &entry)
    }

    fn entry_accounts(&self, service: &str) -> Result<Vec<String>, ProviderError> {
        if !self.in_namespace(service) {
            return Err(ProviderError::CredentialOutsideNamespace {
                store: self.kind,
                scope: service.to_string(),
            });
        }
        let spec = HashMap::from([("service", service)]);
        let entries = self
            .store
            .search(&spec)
            .map_err(|err| ProviderError::StoreUnavailable {
                store: self.kind,
                reason: err.to_string(),
            })?;
        let mut accounts = entries
            .iter()
            .filter_map(|entry| entry.get_specifiers())
            .filter_map(|(entry_service, user)| (entry_service == service).then_some(user))
            .collect::<Vec<_>>();
        accounts.sort();
        accounts.dedup();
        Ok(accounts)
    }

    fn login(&self, credential: &SecretRef, secret: &[u8]) -> Result<(), ProviderError> {
        // Enrollment is create-only: the occupancy check runs under the
        // per-scope mutex after the namespace/kind guard, so two same-scope
        // enrollments cannot both observe the slot empty (DEC-002). Poison
        // recovery is sound — the guard serializes, it protects no state.
        let entry = self.entry(credential)?;
        let scope_lock = {
            let mut locks = self.login_locks.lock().unwrap_or_else(|e| e.into_inner());
            Arc::clone(
                locks
                    .entry(credential.scope().to_string())
                    .or_insert_with(|| Arc::new(Mutex::new(()))),
            )
        };
        let _guard = scope_lock.lock().unwrap_or_else(|e| e.into_inner());
        if self.entry_occupied(credential, &entry)? {
            return Err(ProviderError::CredentialOccupied {
                scope: credential.scope().to_string(),
            });
        }
        entry
            .set_secret(secret)
            .map_err(|err| self.map_error(credential, err))
    }

    fn resolve(&self, credential: &SecretRef) -> Result<Vec<u8>, ProviderError> {
        self.entry(credential)?
            .get_secret()
            .map_err(|err| self.map_error(credential, err))
    }

    fn refresh(&self, credential: &SecretRef, secret: &[u8]) -> Result<(), ProviderError> {
        self.entry(credential)?
            .set_secret(secret)
            .map_err(|err| self.map_error(credential, err))
    }

    fn revoke(&self, credential: &SecretRef) -> Result<(), ProviderError> {
        self.entry(credential)?
            .delete_credential()
            .map_err(|err| self.map_error(credential, err))
    }

    fn logout(&self, credential: &SecretRef) -> Result<(), ProviderError> {
        self.revoke(credential)
    }
}

/// The shared outcome one in-flight refresh publishes to its joiners.
struct RefreshFlight {
    outcome: Mutex<Option<Result<(), ProviderError>>>,
    ready: Condvar,
}

/// Per-profile refresh single-flight (INV-009): while a refresh for one
/// credential scope is in flight, concurrent refreshes for the same scope
/// join it — the leader's inner op is the only store write and its outcome
/// stands for every waiter. Different scopes hold independent flights; all
/// other ops pass through untouched.
pub struct FlightedStore {
    inner: Box<dyn CredentialStore>,
    flights: Mutex<BTreeMap<String, Arc<RefreshFlight>>>,
    waiters: AtomicU64,
}

impl FlightedStore {
    /// Wraps any backend with the refresh flight serializer — the one
    /// constructor [`native_store`] uses, and the one tests use to pin the
    /// coalescing behavior deterministically.
    pub fn new(inner: Box<dyn CredentialStore>) -> Self {
        Self {
            inner,
            flights: Mutex::new(BTreeMap::new()),
            waiters: AtomicU64::new(0),
        }
    }

    /// Refresh callers currently joined on an in-flight op — the
    /// observability surface for the INV-009 guarantee.
    #[must_use]
    pub fn refresh_waiters(&self) -> u64 {
        self.waiters.load(Ordering::SeqCst)
    }

    fn flights(&self) -> MutexGuard<'_, BTreeMap<String, Arc<RefreshFlight>>> {
        // Poison recovery is sound here: the map only ever gains or loses
        // whole flight entries, so a panicking holder leaves it valid.
        self.flights.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Parks on the flight until the leader publishes its outcome, then
    /// returns that outcome — the joiner never runs a second store op.
    fn join(&self, flight: &Arc<RefreshFlight>) -> Result<(), ProviderError> {
        // Same poison argument as `flights`: the slot holds at most one
        // completed outcome write.
        let mut outcome = flight.outcome.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            if let Some(result) = outcome.clone() {
                self.waiters.fetch_sub(1, Ordering::SeqCst);
                return result;
            }
            outcome = flight
                .ready
                .wait(outcome)
                .unwrap_or_else(|e| e.into_inner());
        }
    }
}

impl std::fmt::Debug for FlightedStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The inner store is a trait object; the class and the live
        // waiter count are the observability surface (INV-009).
        f.debug_struct("FlightedStore")
            .field("kind", &self.inner.kind())
            .field("refresh_waiters", &self.refresh_waiters())
            .finish_non_exhaustive()
    }
}

/// The leader half of one in-flight refresh. On drop — normal return or
/// unwind — the map entry is removed BEFORE the outcome is published, so
/// a refresh arriving mid-publish becomes the next leader instead of
/// joining a spent flight and taking `Ok` for bytes it never wrote. A
/// leader that unwound past `inner.refresh` publishes `StoreUnavailable`,
/// so parked joiners wake with a typed error and the scope is free for
/// the next leader instead of wedging on an outcome that never comes.
struct FlightLeader<'a> {
    store: &'a FlightedStore,
    key: String,
    flight: Arc<RefreshFlight>,
    outcome: Option<Result<(), ProviderError>>,
}

impl Drop for FlightLeader<'_> {
    fn drop(&mut self) {
        self.store.flights().remove(&self.key);
        let mut outcome = self
            .flight
            .outcome
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *outcome = Some(self.outcome.take().unwrap_or_else(|| {
            Err(ProviderError::StoreUnavailable {
                store: self.store.inner.kind(),
                reason: "refresh leader panicked".to_string(),
            })
        }));
        drop(outcome);
        self.flight.ready.notify_all();
    }
}

impl CredentialStore for FlightedStore {
    fn kind(&self) -> StoreKind {
        self.inner.kind()
    }

    fn occupied(&self, credential: &SecretRef) -> Result<bool, ProviderError> {
        self.inner.occupied(credential)
    }

    fn entry_accounts(&self, service: &str) -> Result<Vec<String>, ProviderError> {
        self.inner.entry_accounts(service)
    }

    fn login(&self, credential: &SecretRef, secret: &[u8]) -> Result<(), ProviderError> {
        self.inner.login(credential, secret)
    }

    fn resolve(&self, credential: &SecretRef) -> Result<Vec<u8>, ProviderError> {
        self.inner.resolve(credential)
    }

    fn refresh(&self, credential: &SecretRef, secret: &[u8]) -> Result<(), ProviderError> {
        // The flights map keys on the scope alone, so a foreign-class ref
        // must be refused before slot selection — otherwise it joins a
        // flight the backend admitted and takes `Ok` for an op that never
        // ran. A same-kind ref needs no separate namespace check here:
        // equal scopes imply equal namespace verdicts, and a foreign-scope
        // leader's flight only ever carries that refusal.
        if credential.store() != self.inner.kind() {
            return Err(ProviderError::CredentialOutsideNamespace {
                store: self.inner.kind(),
                scope: credential.scope().to_string(),
            });
        }
        // The flights-map guard must drop before `join` parks on the
        // condvar — joining while still holding it would serialize every
        // other caller on the map lock instead of the flight.
        enum Slot {
            Lead(Arc<RefreshFlight>),
            Join(Arc<RefreshFlight>),
        }
        let slot = {
            let mut flights = self.flights();
            match flights.entry(credential.scope().to_string()) {
                std::collections::btree_map::Entry::Occupied(entry) => {
                    self.waiters.fetch_add(1, Ordering::SeqCst);
                    Slot::Join(Arc::clone(entry.get()))
                }
                std::collections::btree_map::Entry::Vacant(slot) => {
                    Slot::Lead(Arc::clone(slot.insert(Arc::new(RefreshFlight {
                        outcome: Mutex::new(None),
                        ready: Condvar::new(),
                    }))))
                }
            }
        };
        let flight = match slot {
            Slot::Lead(flight) => flight,
            Slot::Join(flight) => return self.join(&flight),
        };
        // `FlightLeader` owns the remove → publish → notify sequence on
        // drop, so an unwinding leader cannot leave a flightless outcome
        // or a parked crowd behind.
        let mut leader = FlightLeader {
            store: self,
            key: credential.scope().to_string(),
            flight,
            outcome: None,
        };
        let result = self.inner.refresh(credential, secret);
        leader.outcome = Some(result.clone());
        result
    }

    fn revoke(&self, credential: &SecretRef) -> Result<(), ProviderError> {
        self.inner.revoke(credential)
    }

    fn logout(&self, credential: &SecretRef) -> Result<(), ProviderError> {
        self.inner.logout(credential)
    }
}

/// Opens the platform backend for `kind` under `namespace` and returns it
/// with per-profile refresh serialization installed (INV-009). This is the
/// only constructor adapters use — SRC-010 explicit stores, never a
/// plaintext or env-substituted store.
///
/// # Errors
/// [`ProviderError::StoreUnavailable`] when the class has no usable store
/// on this platform — a locked or absent backend surfaces its platform
/// reason; there is no fallback (INV-006).
pub fn native_store(kind: StoreKind, namespace: &str) -> Result<FlightedStore, ProviderError> {
    let backend = match kind {
        StoreKind::Keychain => keychain_backend()?,
        StoreKind::SecretService => secret_service_backend()?,
    };
    Ok(FlightedStore::new(Box::new(KeyringBackend::new(
        backend, kind, namespace,
    ))))
}

/// macOS: the login-Keychain backend (SRC-010; `keychain` feature — the
/// file-backed store, not the data-protection one). The seam does not
/// suppress prompts — a locked keychain can still park an op on an
/// unlock dialog, and bounding that wait is the caller's concern.
#[cfg(target_os = "macos")]
fn keychain_backend() -> Result<Arc<keyring_core::CredentialStore>, ProviderError> {
    apple_native_keyring_store::keychain::Store::new()
        .map(|store| -> Arc<keyring_core::CredentialStore> { store })
        .map_err(|err| ProviderError::StoreUnavailable {
            store: StoreKind::Keychain,
            reason: err.to_string(),
        })
}

/// Non-macOS platforms have no Keychain class.
#[cfg(not(target_os = "macos"))]
fn keychain_backend() -> Result<Arc<keyring_core::CredentialStore>, ProviderError> {
    Err(ProviderError::StoreUnavailable {
        store: StoreKind::Keychain,
        reason: "the keychain store class exists only on macOS".to_string(),
    })
}

/// Linux: the Secret Service backend over the session D-Bus. A headless
/// host with no session bus answers `StoreUnavailable` at construction;
/// where a store does answer, a locked collection can still park an op on
/// an unlock prompt — the seam bounds nothing, the caller does.
#[cfg(target_os = "linux")]
fn secret_service_backend() -> Result<Arc<keyring_core::CredentialStore>, ProviderError> {
    zbus_secret_service_keyring_store::Store::new()
        .map(|store| -> Arc<keyring_core::CredentialStore> { store })
        .map_err(|err| ProviderError::StoreUnavailable {
            store: StoreKind::SecretService,
            reason: err.to_string(),
        })
}

/// Non-Linux platforms have no Secret Service class.
#[cfg(not(target_os = "linux"))]
fn secret_service_backend() -> Result<Arc<keyring_core::CredentialStore>, ProviderError> {
    Err(ProviderError::StoreUnavailable {
        store: StoreKind::SecretService,
        reason: "the secret service store class exists only on linux".to_string(),
    })
}

/// DEC-013 credential resolution: `connections.<id>.profile` binds
/// `profiles.<name>.credential_ref` first; without a profile binding the
/// connection's own `credential_ref` applies. Catalogue presence is never
/// entitlement — the returned [`SecretRef`] only scopes a store lookup —
/// and every failure is a typed denial, never a plaintext fallback
/// (INV-006).
///
/// A profile-bound ref's trailing scope segment must equal the profile
/// name — the scope's profile leg IS the binding, so a divergent scope is
/// [`ProviderError::CredentialProfileMismatch`].
///
/// # Errors
/// [`ProviderError::UnknownConnection`] for an undeclared id;
/// [`ProviderError::CredentialUnresolved`] when the bound profile, its
/// ref, or the connection's own ref is absent or malformed;
/// [`ProviderError::CredentialProfileMismatch`] as documented above.
pub fn resolve_credential(config: &Config, connection: &str) -> Result<SecretRef, ProviderError> {
    resolve_credential_in(&config.connections, &config.profiles, connection)
}

/// The catalogue-level half of [`resolve_credential`] (DEC-011): the
/// broker's dispatch-time re-check and [`offline_usable`] run the same
/// profile-precedence resolution without owning a `Config` — a
/// connection whose binding cannot resolve keeps the typed denial.
pub(crate) fn resolve_credential_in(
    connections: &BTreeMap<String, Connection>,
    profiles: &BTreeMap<String, Profile>,
    connection: &str,
) -> Result<SecretRef, ProviderError> {
    let Some(conn) = connections.get(connection) else {
        return Err(ProviderError::UnknownConnection);
    };
    if let Some(profile) = &conn.profile {
        let key = format!("profiles.{profile}.credential_ref");
        let raw = profiles
            .get(profile)
            .and_then(|profile| profile.credential_ref.clone())
            .ok_or_else(|| ProviderError::CredentialUnresolved {
                connection: connection.to_string(),
                scope: key.clone(),
                cause: None,
            })?;
        let credential =
            SecretRef::parse(&raw).map_err(|parse| ProviderError::CredentialUnresolved {
                connection: connection.to_string(),
                scope: key.clone(),
                cause: Some(parse),
            })?;
        if credential.profile() != profile {
            return Err(ProviderError::CredentialProfileMismatch {
                connection: connection.to_string(),
                profile: profile.clone(),
            });
        }
        return Ok(credential);
    }
    let key = format!("connections.{connection}.credential_ref");
    let raw = conn
        .credential_ref
        .clone()
        .ok_or_else(|| ProviderError::CredentialUnresolved {
            connection: connection.to_string(),
            scope: key.clone(),
            cause: None,
        })?;
    SecretRef::parse(&raw).map_err(|parse| ProviderError::CredentialUnresolved {
        connection: connection.to_string(),
        scope: key,
        cause: Some(parse),
    })
}

const ADMITTED_READ: &str = "performing the admitted read";
const WAITING_FOR_DECISION: &str = "no permitted action; waiting for a decision";

/// The recorded wire dialect of a connection id (DEC-007/DEC-025):
/// keyed by the literal id's source class — `openai` speaks the
/// OpenAI Responses API, `google` speaks the Gemini
/// `streamGenerateContent` dialect, `custom-chat-completions` speaks
/// the OpenAI-compatible Chat Completions dialect — never inferred
/// from an auth label or a catalogue answer. `openai-codex`,
/// `google-vertex`, `google-antigravity` and `google-gemini-cli` are
/// distinct literal ids and stay unrouted until their own dialects
/// land.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dialect {
    /// The OpenAI Responses API (`POST {endpoint}/responses`, SSE).
    Responses,
    /// The Google Gemini generate-content API
    /// (`POST {endpoint}/models/{id}:streamGenerateContent?alt=sse`, SSE).
    Gemini,
    /// The OpenAI-compatible Chat Completions API
    /// (`POST {endpoint}/chat/completions`, SSE) — the dialect every
    /// compatible host wired under the literal `custom-chat-completions`
    /// id shares (HZN-008 class S).
    ChatCompletions,
}

/// The recorded dialect for a literal connection id; `None` for ids
/// whose source class has no wired dialect in this build.
#[must_use]
pub fn dialect_for(connection: &str) -> Option<Dialect> {
    match connection {
        "openai" => Some(Dialect::Responses),
        "google" => Some(Dialect::Gemini),
        "custom-chat-completions" => Some(Dialect::ChatCompletions),
        _ => None,
    }
}

pub trait Provider: Send {
    fn name(&self) -> &'static str;
    /// Whether this adapter's dialect serves `connection` — the send
    /// seam's fail-closed gate (AC-046): eligibility says a connection
    /// is theoretically usable; only the injected provider can say it
    /// speaks its dialect, and a manifest it cannot honour is a typed
    /// denial, never a fabricated reply. Every implementor — test
    /// doubles included — declares the rule; a scripted double that
    /// answers anything returns `true`.
    fn serves(&self, connection: &str, entry: &Connection) -> bool;
    fn send(&mut self, manifest: &RequestManifest) -> Result<ProviderReply, ProviderError>;
}

/// Offline loopback: answers from local fixtures only, zero network. The
/// fixture decision reads a `read <path>` instruction out of the manifest
/// inputs and returns it as a tool call for the executor boundary.
pub struct LoopbackProvider {
    calls: u64,
}

impl LoopbackProvider {
    pub fn new() -> Self {
        Self { calls: 0 }
    }

    pub fn calls(&self) -> u64 {
        self.calls
    }
}

impl Default for LoopbackProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl Provider for LoopbackProvider {
    fn name(&self) -> &'static str {
        "loopback"
    }

    /// The offline fixture answers local connections only — a pin to
    /// a credentialled or subscribed class is a dialect it does not
    /// speak, so the seam denies it rather than fabricating a reply.
    /// An id [`dialect_for`] reserves is a live dialect's connection
    /// even when it declares `local` kind: reserved ids are never
    /// fixture-served.
    fn serves(&self, connection: &str, entry: &Connection) -> bool {
        entry.kind == ConnKind::Local && dialect_for(connection).is_none()
    }

    fn send(&mut self, manifest: &RequestManifest) -> Result<ProviderReply, ProviderError> {
        self.calls += 1;
        let path = manifest
            .inputs
            .lines()
            .rev()
            .find_map(|line| line.strip_prefix("read ").map(str::to_string));
        match path {
            Some(path) => Ok(ProviderReply {
                text: ADMITTED_READ.to_string(),
                tool_calls: vec![ToolCall {
                    tool: "read_file".to_string(),
                    path: Some(path),
                }],
                usage: UsageDelta::Unknown,
            }),
            None => Ok(ProviderReply {
                text: WAITING_FOR_DECISION.to_string(),
                tool_calls: Vec::new(),
                usage: UsageDelta::Unknown,
            }),
        }
    }
}

/// Whether the connection's recorded auth class resolves a scoped
/// [`SecretRef`] under DEC-013 precedence (DEC-011): the offline
/// dispatch precondition for `api_key` connections. Resolution is
/// binding-level — the store is read at send time — so a missing,
/// malformed or mismatched binding is the unresolved case.
fn credential_resolves(
    connections: &BTreeMap<String, Connection>,
    profiles: &BTreeMap<String, Profile>,
    connection: &str,
) -> bool {
    resolve_credential_in(connections, profiles, connection).is_ok()
}

/// Connection eligibility for offline dispatch (DEC-011): local
/// connections are always usable; an `api_key` connection is usable
/// exactly when its recorded auth class resolves a scoped
/// [`SecretRef`] — catalogue presence is never entitlement, and an
/// unresolved binding keeps the typed live-grant denial.
///
/// # Errors
/// [`ProviderError::UnknownConnection`] for a fixed pin on an
/// undeclared connection; [`ProviderError::LiveGrantRequired`] for a
/// non-local pin whose credential does not resolve.
pub fn offline_eligible(
    model: &ModelAssign,
    connections: &BTreeMap<String, Connection>,
    profiles: &BTreeMap<String, Profile>,
) -> Result<(), ProviderError> {
    let ModelAssign::Fixed(fixed) = model else {
        return Ok(());
    };
    match connections.get(&fixed.connection) {
        None => Err(ProviderError::UnknownConnection),
        Some(_) if offline_usable(connections, profiles, &fixed.connection) => Ok(()),
        Some(entry) => Err(ProviderError::LiveGrantRequired { kind: entry.kind }),
    }
}

/// Offline eligibility as a ranking predicate (AC-044/DEC-011): a
/// candidate usable without a separate live grant — a local
/// connection always; an `api_key` one exactly when its credential
/// resolves. A `subscription` names a live grant no scoped reference
/// confers — it stays grant-gated until the subscription machinery
/// lands. Ranking filters candidates with this; [`offline_eligible`]
/// keeps the typed rejection vocabulary for the single-candidate
/// fixed path.
#[must_use]
pub fn offline_usable(
    connections: &BTreeMap<String, Connection>,
    profiles: &BTreeMap<String, Profile>,
    connection: &str,
) -> bool {
    match connections.get(connection) {
        None => false,
        Some(entry) => match entry.kind {
            ConnKind::Local => true,
            ConnKind::ApiKey => credential_resolves(connections, profiles, connection),
            ConnKind::Subscription => false,
        },
    }
}
