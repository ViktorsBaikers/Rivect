//! Shared corpus (architecture TP-PUBLIC + TP-ADMISSION-PACKET): the
//! canonical request line set, the question fixture, the eight config
//! examples with their negative mutations and group controls, and the
//! PTY harness for real-terminal TUI cases. One corpus, both ingresses.

#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::let_underscore_must_use,
    let_underscore_drop,
    clippy::redundant_clone,
    reason = "shared test corpus: helpers are not all used by every target; test code keeps unwrap/expect/discard conveniences (standards §14)"
)]

use rivect::commands::{Ingress, Runtime};
use rivect::config::Config;
use rivect::contracts::{AnswerSelection, Event, Question, SessionId, TaskId};
use rivect::model::{Broker, RequestManifest};
use rivect::providers::{
    CredentialStore, Provider, ProviderError, ProviderReply, SecretRef, StoreKind,
};
use serde_json::{Value, json};
use sha2::Digest;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

pub const CONNECTION_ID: &str = "test-conn-1";

// ----- config corpus (research/config-examples.md, verbatim) -----

pub fn base_config() -> String {
    "config_version = 1\n\
     [connections.primary]\n\
     kind = \"api_key\"\n\
     endpoint = \"https://api.openai.com/v1\"\n\
     credential_ref = \"keyring:primary\"\n\
     [models.defaults]\n\
     model = { mode = \"auto\" }\n\
     effort = { mode = \"auto\" }\n\
     fallback = { mode = \"auto\" }\n"
        .to_string()
}

pub fn config_all_roles_auto() -> String {
    base_config()
}

pub fn config_pinned_planner() -> String {
    format!(
        "{}\n[models.purposes.planner]\nmodel = {{ mode = \"fixed\", connection = \"primary\", model_id = \"fixture-model\" }}\neffort = {{ mode = \"fixed\", value = \"high\" }}\n",
        base_config()
    )
}

pub fn config_distinct_pools() -> String {
    format!(
        "{}\n\
         [connections.local]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:11434\"\n\
         [models.groups.backend]\nmodel = {{ mode = \"auto\", pool = [\"local\"] }}\n\
         [models.groups.frontend]\nmodel = {{ mode = \"auto\", pool = [\"primary\"] }}\n\
         [models.purposes.backend_task]\ngroup = \"backend\"\n\
         [models.purposes.frontend_task]\ngroup = \"frontend\"\n\
         [models.purposes.vision]\nmodel = {{ mode = \"auto\", pool = [\"primary\"] }}\n",
        base_config()
    )
}

pub fn config_fixed_model_auto_effort() -> String {
    format!(
        "{}\n[models.purposes.main]\nmodel = {{ mode = \"fixed\", connection = \"primary\", model_id = \"fixture-model\" }}\neffort = {{ mode = \"auto\" }}\n",
        base_config()
    )
}

pub fn config_explicit_chain() -> String {
    format!(
        "{}\n[models.purposes.planner]\nmodel = {{ mode = \"fixed\", connection = \"primary\", model_id = \"fixture-model\" }}\nfallback = {{ mode = \"auto\", chain = [{{ mode = \"fixed\", connection = \"primary\", model_id = \"fixture-reserve\" }}] }}\n",
        base_config()
    )
}

const MANUAL_SUBSCRIPTION_TAIL: &str = "\n\
         [connections.subscription]\nkind = \"subscription\"\nendpoint = \"https://subscription.fixture.invalid\"\ncredential_ref = \"keyring:subscription-fixture\"\n\
         [models.purposes.main]\nmodel = { mode = \"fixed\", connection = \"subscription\", model_id = \"fixture-model\" }\nfallback = { mode = \"manual\" }\n";

pub fn config_manual_subscription() -> String {
    format!("{}{MANUAL_SUBSCRIPTION_TAIL}", base_config())
}

pub fn config_distinct_pools_with_manual_subscription() -> String {
    format!("{}{MANUAL_SUBSCRIPTION_TAIL}", config_distinct_pools())
}

pub fn config_one_provider() -> String {
    format!(
        "{}\n[models.purposes.reviewer]\nmodel = {{ mode = \"inherit\" }}\neffort = {{ mode = \"inherit\" }}\n",
        base_config()
    )
}

pub fn config_learned_role() -> String {
    format!(
        "{}\n[models.purposes.\"personal:api-review\"]\nmodel = {{ mode = \"inherit\" }}\neffort = {{ mode = \"inherit\" }}\n",
        base_config()
    )
}

pub const SECRET_CANARY: &str = "sk-live-canary-0123456789abcdef";

/// Offline credential-store double (SRC-010 test seam): resolves
/// exactly the scoped refs it was seeded with and answers the same
/// typed denial vocabulary the native seam returns — no platform
/// store is touched and no plaintext fallback exists. Material is
/// keyed by the ref's scope, the same identity the real backends use.
pub struct MapStore {
    kind: StoreKind,
    secrets: std::sync::Mutex<std::collections::BTreeMap<String, Vec<u8>>>,
}

impl MapStore {
    /// An empty store of the given class; `enroll` seeds scopes.
    pub fn new(kind: StoreKind) -> Self {
        Self {
            kind,
            secrets: std::sync::Mutex::new(std::collections::BTreeMap::new()),
        }
    }

    /// A store pre-seeded with `(store:scope, material)` pairs.
    pub fn seeded(kind: StoreKind, entries: &[(&str, &str)]) -> Self {
        let store = Self::new(kind);
        for (raw, secret) in entries {
            store.enroll(raw, secret.as_bytes());
        }
        store
    }

    /// Enrolls material at a `store:scope` ref — the enrollment path
    /// tests use to place a credential without a platform store.
    pub fn enroll(&self, raw: &str, secret: &[u8]) {
        let credential = SecretRef::parse(raw).expect("seed ref is a scoped store:scope");
        self.secrets
            .lock()
            .expect("store lock")
            .insert(credential.scope().to_string(), secret.to_vec());
    }
}

impl CredentialStore for MapStore {
    fn kind(&self) -> StoreKind {
        self.kind
    }

    fn occupied(&self, credential: &SecretRef) -> Result<bool, ProviderError> {
        Ok(self
            .secrets
            .lock()
            .expect("store lock")
            .contains_key(credential.scope()))
    }

    fn entry_accounts(&self, service: &str) -> Result<Vec<String>, ProviderError> {
        Ok(self
            .secrets
            .lock()
            .expect("store lock")
            .keys()
            .filter(|scope| scope.as_str() == service || scope.starts_with(&format!("{service}/")))
            .cloned()
            .collect())
    }

    fn login(&self, credential: &SecretRef, secret: &[u8]) -> Result<(), ProviderError> {
        let mut secrets = self.secrets.lock().expect("store lock");
        if secrets.contains_key(credential.scope()) {
            return Err(ProviderError::CredentialOccupied {
                scope: credential.scope().to_string(),
            });
        }
        secrets.insert(credential.scope().to_string(), secret.to_vec());
        drop(secrets);
        Ok(())
    }

    fn resolve(&self, credential: &SecretRef) -> Result<Vec<u8>, ProviderError> {
        self.secrets
            .lock()
            .expect("store lock")
            .get(credential.scope())
            .cloned()
            .ok_or_else(|| ProviderError::CredentialAbsent {
                scope: credential.scope().to_string(),
            })
    }

    fn refresh(&self, credential: &SecretRef, secret: &[u8]) -> Result<(), ProviderError> {
        self.secrets
            .lock()
            .expect("store lock")
            .insert(credential.scope().to_string(), secret.to_vec());
        Ok(())
    }

    fn revoke(&self, credential: &SecretRef) -> Result<(), ProviderError> {
        self.secrets
            .lock()
            .expect("store lock")
            .remove(credential.scope())
            .map(|_| ())
            .ok_or_else(|| ProviderError::CredentialAbsent {
                scope: credential.scope().to_string(),
            })
    }

    fn logout(&self, credential: &SecretRef) -> Result<(), ProviderError> {
        self.revoke(credential)
    }
}

/// A store double whose `resolve` parks for a fixed delay before
/// delegating — the seam a credential leg that consumes the send's
/// whole budget is proved through (DEC-014).
pub struct SlowStore {
    pub inner: MapStore,
    pub delay: Duration,
}

impl CredentialStore for SlowStore {
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
        std::thread::sleep(self.delay);
        self.inner.resolve(credential)
    }

    fn refresh(&self, credential: &SecretRef, secret: &[u8]) -> Result<(), ProviderError> {
        self.inner.refresh(credential, secret)
    }

    fn revoke(&self, credential: &SecretRef) -> Result<(), ProviderError> {
        self.inner.revoke(credential)
    }

    fn logout(&self, credential: &SecretRef) -> Result<(), ProviderError> {
        self.inner.logout(credential)
    }
}

pub fn negative_configs() -> Vec<(&'static str, String)> {
    vec![
        (
            "N-model-id",
            config_pinned_planner().replace(", model_id = \"fixture-model\" }", " }"),
        ),
        (
            "N-effort-value",
            config_pinned_planner().replace(", value = \"high\" }", " }"),
        ),
        (
            "N-key",
            config_all_roles_auto().replace(
                "[models.defaults]\n",
                "[models.defaults]\nunknown_field = true\n",
            ),
        ),
        (
            "N-fallback",
            config_all_roles_auto().replace(
                "fallback = { mode = \"auto\" }",
                "fallback = { mode = \"sometimes\" }",
            ),
        ),
        (
            "N-secret",
            config_all_roles_auto().replace(
                "credential_ref = \"keyring:primary\"",
                &format!("api_key = \"{SECRET_CANARY}\""),
            ),
        ),
        (
            "N-duplicate",
            config_all_roles_auto().replacen(
                "config_version = 1\n",
                "config_version = 1\nconfig_version = 1\n",
                1,
            ),
        ),
    ]
}

// ----- TP-PUBLIC request corpus -----

pub fn corpus_open(bootstrap: &str) -> String {
    json!({
        "jsonrpc": "2.0", "id": 1, "method": "session.open",
        "params": { "schema_version": 1, "bootstrap_id": bootstrap }
    })
    .to_string()
}

pub fn corpus_status(session: &SessionId) -> String {
    json!({
        "jsonrpc": "2.0", "id": 2, "method": "runtime.status",
        "params": { "schema_version": 1, "session_id": session.0, "page": { "page_size": 20 } }
    })
    .to_string()
}

pub fn corpus_config_read(session: &SessionId) -> String {
    json!({
        "jsonrpc": "2.0", "id": 3, "method": "config.read",
        "params": { "schema_version": 1, "session_id": session.0, "keys": ["workflow.enabled"], "page": { "page_size": 20 } }
    })
    .to_string()
}

pub fn corpus_create(session: &SessionId, command_id: &str) -> String {
    json!({
        "jsonrpc": "2.0", "id": 4, "method": "task.submit",
        "params": {
            "schema_version": 1, "command_id": command_id, "session_id": session.0,
            "kind": "create",
            "goal": "Объяснить тему в выбранной форме.",
            "contract": {
                "criteria": ["Дать объяснение в выбранной форме."],
                "constraints": ["Не изменять файлы."]
            },
            "attachments": []
        }
    })
    .to_string()
}

pub fn corpus_question_current(session: &SessionId, task: &TaskId, id: Value) -> String {
    json!({
        "jsonrpc": "2.0", "id": id, "method": "question.current",
        "params": { "schema_version": 1, "session_id": session.0, "task_id": task.0 }
    })
    .to_string()
}

pub fn corpus_answer_option(
    session: &SessionId,
    command_id: &str,
    task: &TaskId,
    question: &Question,
    option_id: &str,
    id: Value,
) -> String {
    json!({
        "jsonrpc": "2.0", "id": id, "method": "task.submit",
        "params": {
            "schema_version": 1, "command_id": command_id, "session_id": session.0,
            "kind": "answer", "task_id": task.0,
            "expected_intent_revision": question.intent_revision,
            "question_id": question.question_id.0, "question_revision": question.question_revision,
            "selection": { "kind": "option", "option_id": option_id }
        }
    })
    .to_string()
}

pub fn corpus_answer_custom(
    session: &SessionId,
    command_id: &str,
    task: &TaskId,
    question: &Question,
    text: &str,
    id: Value,
) -> String {
    json!({
        "jsonrpc": "2.0", "id": id, "method": "task.submit",
        "params": {
            "schema_version": 1, "command_id": command_id, "session_id": session.0,
            "kind": "answer", "task_id": task.0,
            "expected_intent_revision": question.intent_revision,
            "question_id": question.question_id.0, "question_revision": question.question_revision,
            "selection": { "kind": "custom", "text": text }
        }
    })
    .to_string()
}

pub fn corpus_steer(
    session: &SessionId,
    command_id: &str,
    task: &TaskId,
    intent_revision: u64,
    task_revision: u64,
    id: Value,
) -> String {
    json!({
        "jsonrpc": "2.0", "id": id, "method": "task.submit",
        "params": {
            "schema_version": 1, "command_id": command_id, "session_id": session.0,
            "kind": "steer", "task_id": task.0,
            "expected_intent_revision": intent_revision, "expected_task_revision": task_revision,
            "instruction": "Сохранить краткую форму.", "attachments": []
        }
    })
    .to_string()
}

// ----- world helpers -----

pub struct CountingProvider {
    inner: rivect::providers::LoopbackProvider,
    calls: Arc<AtomicU64>,
    last_manifest: Arc<std::sync::Mutex<Option<RequestManifest>>>,
}

impl CountingProvider {
    pub fn new() -> (
        Self,
        Arc<AtomicU64>,
        Arc<std::sync::Mutex<Option<RequestManifest>>>,
    ) {
        let calls = Arc::new(AtomicU64::new(0));
        let last_manifest = Arc::new(std::sync::Mutex::new(None));
        (
            Self {
                inner: rivect::providers::LoopbackProvider::new(),
                calls: calls.clone(),
                last_manifest: last_manifest.clone(),
            },
            calls,
            last_manifest,
        )
    }
}

impl Provider for CountingProvider {
    fn name(&self) -> &'static str {
        self.inner.name()
    }

    /// The double's serving rule is its wrapped provider's — the
    /// count observes sends, not the dialect claim.
    fn serves(&self, connection: &str, entry: &rivect::config::Connection) -> bool {
        self.inner.serves(connection, entry)
    }

    fn send(&mut self, manifest: &RequestManifest) -> Result<ProviderReply, ProviderError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        *self.last_manifest.lock().expect("manifest lock") = Some(manifest.clone());
        self.inner.send(manifest)
    }
}

pub struct World {
    pub root: PathBuf,
    pub runtime: Runtime,
    pub provider_calls: Arc<AtomicU64>,
    pub worker_reads: Arc<AtomicU64>,
    pub last_read_digest: Arc<std::sync::Mutex<Option<String>>>,
    last_manifest: Arc<std::sync::Mutex<Option<RequestManifest>>>,
    directory: Option<tempfile::TempDir>,
}

#[cfg(target_os = "linux")]
pub type PlatformWorker = rivect::executor::linux::LinuxWorker;
#[cfg(not(target_os = "linux"))]
pub type PlatformWorker = rivect::executor::macos::MacosReadWorker;

#[cfg(target_os = "linux")]
pub const PLATFORM_READ_MAX_BYTES: usize = rivect::executor::linux::READ_MAX_BYTES;
#[cfg(not(target_os = "linux"))]
pub const PLATFORM_READ_MAX_BYTES: usize = rivect::executor::macos::READ_MAX_BYTES;

#[cfg(target_os = "linux")]
pub fn platform_read_once(
    scope_root: &Path,
    target: &Path,
) -> Result<rivect::executor::ReadObservation, rivect::executor::WorkerError> {
    rivect::executor::linux::read_once(scope_root, target)
}
#[cfg(not(target_os = "linux"))]
pub fn platform_read_once(
    scope_root: &Path,
    target: &Path,
) -> Result<rivect::executor::ReadObservation, rivect::executor::WorkerError> {
    rivect::executor::macos::read_once(scope_root, target)
}

/// Injectable read-worker oracle: delegates to the real platform worker and
/// counts only successful reads (plus their digest), no global state.
pub struct CountingReadWorker {
    inner: PlatformWorker,
    reads: Arc<AtomicU64>,
    last_digest: Arc<std::sync::Mutex<Option<String>>>,
}

impl rivect::executor::ReadWorker for CountingReadWorker {
    fn read_once(
        &mut self,
        scope_root: &Path,
        target: &Path,
    ) -> Result<rivect::executor::ReadObservation, rivect::executor::WorkerError> {
        let observation = self.inner.read_once(scope_root, target)?;
        self.reads.fetch_add(1, Ordering::SeqCst);
        *self.last_digest.lock().expect("digest lock") = Some(observation.digest.clone());
        Ok(observation)
    }
}

impl World {
    /// The exact manifest the provider received on its latest dispatch.
    pub fn last_manifest(&self) -> Option<RequestManifest> {
        self.last_manifest.lock().expect("manifest lock").clone()
    }

    pub fn worker_reads(&self) -> u64 {
        self.worker_reads.load(Ordering::SeqCst)
    }

    pub fn last_read_digest(&self) -> Option<String> {
        self.last_read_digest.lock().expect("digest lock").clone()
    }
}

impl World {
    /// Failure-only retention of the world's root (see [`TempTree::retain`]).
    /// Only a world from `open_world`/`open_world_with` owns its root; the
    /// owner of an `open_world_at` root is the caller's `TempDir`.
    pub fn retain(&mut self) {
        retain_root(
            self.directory
                .as_mut()
                .expect("retain needs a world that owns its root"),
        );
    }
}

/// One native fixture directory; its private `TempDir` is the only remover.
pub struct TempTree {
    pub path: PathBuf,
    directory: tempfile::TempDir,
}

impl TempTree {
    pub fn new(prefix: &str, name: &str) -> Self {
        let directory = tempfile::Builder::new()
            .prefix(&format!("rivect-{prefix}-{name}-"))
            .tempdir()
            .expect("create private fixture");
        Self::from(directory)
    }
}

impl From<tempfile::TempDir> for TempTree {
    fn from(directory: tempfile::TempDir) -> Self {
        let path = directory.path().to_path_buf();
        Self { path, directory }
    }
}

/// Reports one retained root on stderr through the locked handle; a
/// failed write is handed to `black_box`, never a panic.
fn report_retained(path: &Path) {
    use std::io::Write as _;
    let line = format!("retained root {}: child reap unproven\n", path.display());
    if let Err(error) = std::io::stderr().lock().write_all(line.as_bytes()) {
        std::hint::black_box(error);
    }
}

/// Failure-only retention for a std child whose reap is unproven: the
/// `TempDir` stays owned by the caller but its `Drop` removes nothing.
/// The retained path is reported; nothing claims cleanup.
pub fn retain_root(root: &mut tempfile::TempDir) {
    root.disable_cleanup(true);
    report_retained(root.path());
}

impl TempTree {
    /// Failure-only retention of this tree's root (see [`retain_root`]).
    pub fn retain(&mut self) {
        retain_root(&mut self.directory);
    }

    #[cfg(target_os = "linux")]
    fn close(self) -> std::io::Result<()> {
        self.directory.close()
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BorrowedRemoval {
    PartialRemovalUnknown,
}

#[cfg(target_os = "linux")]
#[derive(Debug, thiserror::Error)]
#[error("borrowed root identity unavailable at {}", locator.display())]
pub struct BorrowedIdentityFailure {
    pub locator: PathBuf,
    pub expected: Option<rivect::executor::FileIdentity>,
    pub primary: Option<rivect::executor::WorkerError>,
    pub observed: Option<rivect::executor::FileIdentity>,
    pub observed_directory: Option<bool>,
    #[source]
    pub source: Option<std::io::Error>,
}

#[cfg(target_os = "linux")]
#[derive(Debug, thiserror::Error)]
#[error("borrowed root close failed at {}: {source}", locator.display())]
pub struct BorrowedCloseFailure {
    pub locator: PathBuf,
    pub expected: Option<rivect::executor::FileIdentity>,
    pub primary: Option<rivect::executor::WorkerError>,
    pub disposition: BorrowedRemoval,
    #[source]
    pub source: std::io::Error,
}

#[cfg(target_os = "linux")]
#[derive(Debug, thiserror::Error)]
pub enum BorrowedFinalizeError {
    #[error("borrowed root arm identity unavailable at {}", .0.locator.display())]
    ArmIdentity(#[source] Box<BorrowedIdentityFailure>),
    #[error("borrowed root result does not prove release at {}", locator.display())]
    UnexpectedResult {
        locator: PathBuf,
        expected: Option<rivect::executor::FileIdentity>,
        primary: Option<rivect::executor::WorkerError>,
    },
    #[error("borrowed root identity unavailable at {}", .0.locator.display())]
    Identity(#[source] Box<BorrowedIdentityFailure>),
    #[error(transparent)]
    Close(Box<BorrowedCloseFailure>),
}

/// Keeps a borrowed native fixture until its release and identity are verified.
#[cfg(target_os = "linux")]
pub struct BorrowedNativeRoot {
    tree: Option<TempTree>,
    locator: PathBuf,
    expected: rivect::executor::FileIdentity,
}

#[cfg(target_os = "linux")]
impl BorrowedNativeRoot {
    pub fn arm(mut tree: TempTree) -> Result<Self, BorrowedFinalizeError> {
        use rivect::executor::FileIdentity;
        tree.directory.disable_cleanup(true);
        let locator = tree.path.clone();
        let metadata = std::fs::symlink_metadata(&locator);
        match metadata {
            Ok(metadata) if metadata.is_dir() => Ok(Self {
                tree: Some(tree),
                locator,
                expected: FileIdentity::from_metadata(&metadata),
            }),
            observation => {
                let (expected, observed_directory, source) = match observation {
                    Ok(metadata) => (
                        Some(FileIdentity::from_metadata(&metadata)),
                        Some(metadata.is_dir()),
                        None,
                    ),
                    Err(source) => (None, None, Some(source)),
                };
                report_retained(&locator);
                Err(BorrowedFinalizeError::ArmIdentity(Box::new(
                    BorrowedIdentityFailure {
                        locator,
                        expected,
                        primary: None,
                        observed: expected,
                        observed_directory,
                        source,
                    },
                )))
            }
        }
    }

    pub fn path(&self) -> &Path {
        &self.locator
    }

    pub fn finalize(
        mut self,
        primary: rivect::executor::WorkerError,
    ) -> Result<rivect::executor::WorkerError, BorrowedFinalizeError> {
        use rivect::executor::{FileIdentity, WorkerError};
        let locator = self.locator.clone();
        let expected = Some(self.expected);
        if !matches!(primary, WorkerError::ConfinedRunTimedOut) {
            return Err(BorrowedFinalizeError::UnexpectedResult {
                locator,
                expected,
                primary: Some(primary),
            });
        }
        let observation = std::fs::symlink_metadata(&locator);
        match observation {
            Ok(metadata)
                if metadata.is_dir() && FileIdentity::from_metadata(&metadata) == self.expected => {
            }
            observation => {
                let (observed, observed_directory, source) = match observation {
                    Ok(metadata) => (
                        Some(FileIdentity::from_metadata(&metadata)),
                        Some(metadata.is_dir()),
                        None,
                    ),
                    Err(source) => (None, None, Some(source)),
                };
                return Err(BorrowedFinalizeError::Identity(Box::new(
                    BorrowedIdentityFailure {
                        locator,
                        expected,
                        primary: Some(primary),
                        observed,
                        observed_directory,
                        source,
                    },
                )));
            }
        }
        // Taking the sole owner prevents a second removal after a partial close failure.
        let tree = self.tree.take().expect("armed guard owns the fixture");
        match tree.close() {
            Ok(()) => Ok(primary),
            Err(source) => Err(BorrowedFinalizeError::Close(Box::new(
                BorrowedCloseFailure {
                    locator,
                    expected,
                    primary: Some(primary),
                    disposition: BorrowedRemoval::PartialRemovalUnknown,
                    source,
                },
            ))),
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for BorrowedNativeRoot {
    fn drop(&mut self) {
        if self.tree.is_some() {
            report_retained(&self.locator);
        }
    }
}

impl AsRef<Path> for TempTree {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}
impl AsRef<std::ffi::OsStr> for TempTree {
    fn as_ref(&self) -> &std::ffi::OsStr {
        self.path.as_os_str()
    }
}
impl std::ops::Deref for TempTree {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.path
    }
}

/// The DEC-014 matrix verdicts the policy pins for one decision context.
pub fn matrix_verdict(
    mode: rivect::policy::PermissionMode,
    class: rivect::contracts::EffectClass,
) -> rivect::policy::ModeDecision {
    let policy = rivect::policy::Policy::default();
    let ctx = rivect::policy::AdmissionContext {
        mode,
        in_grant_scope: true,
        budget_remaining: true,
        in_trusted_scope: true,
        has_checkpoint: true,
        previously_approved: true,
        within_declared_bounds: true,
        dry_run: false,
    };
    policy.decide(Path::new("/scope/target"), class, &ctx)
}

/// A world that owns its root: the root is removed when the world drops.
pub fn open_world(tag: &str, config_toml: Option<&str>) -> World {
    let directory =
        tempfile::TempDir::with_prefix(format!("rivect-{tag}-")).expect("create private fixture");
    let mut world = open_world_at(directory.path(), config_toml);
    world.directory = Some(directory);
    world
}

/// A world over a caller-owned root: the caller's `TempDir` stays the only
/// remover, so the root outlives the world and may be reopened.
pub fn open_world_at(root: &Path, config_toml: Option<&str>) -> World {
    let root = root.to_path_buf();
    if let Some(text) = config_toml {
        std::fs::write(root.join("config.toml"), text).expect("config write");
    }
    let (provider, calls, last_manifest) = CountingProvider::new();
    let worker_reads = Arc::new(AtomicU64::new(0));
    let last_read_digest = Arc::new(std::sync::Mutex::new(None));
    let worker = CountingReadWorker {
        inner: PlatformWorker::default(),
        reads: worker_reads.clone(),
        last_digest: last_read_digest.clone(),
    };
    let runtime = Runtime::open_with_worker(&root, Box::new(provider), Box::new(worker))
        .expect("owner elected");
    World {
        root,
        runtime,
        directory: None,
        provider_calls: calls,
        worker_reads,
        last_read_digest,
        last_manifest,
    }
}

/// World with injected provider and read worker: the supervisor
/// outcome/error feed cases stub one seam at a time while every other
/// subsystem stays production. Counters stay zero — counting belongs to
/// [`open_world`].
pub fn open_world_with(
    tag: &str,
    config_toml: Option<&str>,
    provider: Box<dyn Provider>,
    worker: Box<dyn rivect::executor::ReadWorker>,
) -> World {
    let directory =
        tempfile::TempDir::with_prefix(format!("rivect-{tag}-")).expect("create private fixture");
    let root = directory.path().to_path_buf();
    if let Some(text) = config_toml {
        std::fs::write(root.join("config.toml"), text).expect("config write");
    }
    let runtime = Runtime::open_with_worker(&root, provider, worker).expect("owner elected");
    World {
        root,
        runtime,
        directory: Some(directory),
        provider_calls: Arc::new(AtomicU64::new(0)),
        worker_reads: Arc::new(AtomicU64::new(0)),
        last_read_digest: Arc::new(std::sync::Mutex::new(None)),
        last_manifest: Arc::new(std::sync::Mutex::new(None)),
    }
}
pub trait IntoRequest {
    fn into_request(self) -> String;
}

impl IntoRequest for &str {
    fn into_request(self) -> String {
        self.to_string()
    }
}

impl IntoRequest for &String {
    fn into_request(self) -> String {
        self.clone()
    }
}

impl IntoRequest for &Value {
    fn into_request(self) -> String {
        self.to_string()
    }
}

impl World {
    pub fn dispatch(&mut self, request: impl IntoRequest) -> Value {
        let response = rivect::commands::dispatch_runtime_request(
            &mut self.runtime,
            Ingress::TrustedHuman,
            CONNECTION_ID,
            &request.into_request(),
        );
        serde_json::from_str(&response).expect("response is valid JSON")
    }

    pub fn dispatch_machine(&mut self, request: impl IntoRequest) -> Value {
        let response = rivect::commands::dispatch_runtime_request(
            &mut self.runtime,
            Ingress::Machine,
            CONNECTION_ID,
            &request.into_request(),
        );
        serde_json::from_str(&response).expect("response is valid JSON")
    }

    pub fn open_session(&mut self, bootstrap: &str) -> SessionId {
        let response = self.dispatch(&corpus_open(bootstrap));
        SessionId(
            response["result"]["session_id"]
                .as_str()
                .expect("session id")
                .to_string(),
        )
    }

    pub fn create_task(&mut self, session: &SessionId, command_id: &str) -> TaskId {
        let response = self.dispatch(&corpus_create(session, command_id));
        let result = response.get("result").cloned().unwrap_or(Value::Null);
        assert!(
            result.get("task_id").and_then(Value::as_str).is_some(),
            "create failed: {response}"
        );
        TaskId(result["task_id"].as_str().expect("task id").to_string())
    }

    pub fn publish(&mut self, session: &SessionId, task: &TaskId) -> Question {
        let question = Question::fixture(task, 1);
        self.runtime
            .store_writer()
            .publish_question(session, &question)
            .expect("publish_question commits");
        question
    }
    pub fn reopen(&mut self) {
        // The read-count and digest Arcs survive the restart: the fresh
        // runtime injects a new counting wrapper over the same counters.
        let staging_provider = CountingProvider::new().0;
        let staging_worker = CountingReadWorker {
            inner: PlatformWorker::default(),
            reads: Arc::new(AtomicU64::new(0)),
            last_digest: Arc::new(std::sync::Mutex::new(None)),
        };
        let staging = self.root.join(".reopen-staging");
        let placeholder = Runtime::open_with_worker(
            &staging,
            Box::new(staging_provider),
            Box::new(staging_worker),
        )
        .expect("staging owner");
        let old = std::mem::replace(&mut self.runtime, placeholder);
        drop(old);
        let (provider, calls, last_manifest) = CountingProvider::new();
        let worker = CountingReadWorker {
            inner: PlatformWorker::default(),
            reads: self.worker_reads.clone(),
            last_digest: self.last_read_digest.clone(),
        };
        self.runtime = Runtime::open_with_worker(&self.root, Box::new(provider), Box::new(worker))
            .expect("re-elected owner");
        self.provider_calls = calls;
        self.last_manifest = last_manifest;
    }
}

pub fn answer_custom(text: &str) -> AnswerSelection {
    AnswerSelection::Custom {
        text: text.to_string(),
    }
}

pub fn event_for_test(cursor: u64, aggregate_revision: u64) -> Event {
    Event {
        schema_version: 1,
        event_id: rivect::contracts::EventId::generate(),
        aggregate_id: "aggregate-1".to_string(),
        aggregate_revision,
        cursor,
        session_id: SessionId("11111111-1111-4111-8111-111111111111".to_string()),
        task_id: None,
        event_type: "test.event".to_string(),
        delta: serde_json::json!({}),
        origin: "system".to_string(),
    }
}

// ----- PTY harness (real terminal, real binary) -----

mod pty;

pub use pty::*;

/// A real PTY child over `program` with a fresh session-owned root that is
/// both the data and the env root.
pub fn spawn_pty(program: &str, rows: u16, cols: u16) -> PtySession {
    let root = tempfile::TempDir::with_prefix("rivect-pty-data-").expect("pty data root");
    let data_root = root.path().to_path_buf();
    spawn_pty_with_args(program, rows, cols, root, &data_root, &data_root, &[])
}

/// `spawn_pty` over a caller-owned root; both paths lie at or under it.
pub fn spawn_pty_with_args(
    program: &str,
    rows: u16,
    cols: u16,
    root: tempfile::TempDir,
    data_root: &Path,
    env_root: &Path,
    args: &[&str],
) -> PtySession {
    let mut command = pty_command(program);
    command.env("RIVECT_DATA_ROOT", env_root);
    for arg in args {
        command.arg(arg);
    }
    PtySession::spawn(command, rows, cols, root, data_root.to_path_buf()).expect("pty spawn")
}

pub fn rivect_binary() -> String {
    env!("CARGO_BIN_EXE_rivect").to_string()
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    rivect::config::hex(&sha2::Sha256::digest(bytes))
}

pub fn path_str(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

mod helper;

pub use helper::ensure_helper;

/// Marker appended by the T9 shim after copying fd0→stdout. A host-side
/// read of the target never produces this line.
pub const HELPER_IO_WITNESS: &str = "RIVECT-HELPER-IO-WITNESS";

/// Test helper that performs confined I/O itself: `confined read` copies
/// stdin to stdout and appends [`HELPER_IO_WITNESS`]; `confined write`
/// tees the payload to the inherited target fd and records its length at
/// `write_witness`. `launch` execs the remainder so probes still hit the
/// real OS boundary. `probe-write` execs the real helper so write gates
/// still open(O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW).
pub fn install_helper_io_shim(dir: &Path, write_witness: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let real_helper = rivect_sandbox_helper::helper_binary().expect("real helper for probe-write");
    let shim = dir.join("rivect-shim-helper");
    let payload = dir.join("shim-write-payload");
    let script = format!(
        "#!/bin/sh\n\
         if [ \"$1\" = \"launch\" ]; then\n\
         shift\n\
         [ \"$1\" = \"--\" ] && shift\n\
         exec \"$@\"\n\
         fi\n\
         if [ \"$1\" = \"confined\" ] && [ \"$3\" = \"read\" ]; then\n\
         /bin/cat\n\
         printf '%s\\n' '{HELPER_IO_WITNESS}'\n\
         exit 0\n\
         fi\n\
         if [ \"$1\" = \"confined\" ] && [ \"$3\" = \"write\" ]; then\n\
         /usr/bin/tee '{payload}' >/dev/stdout\n\
         /usr/bin/wc -c < '{payload}' | /usr/bin/tr -d '[:space:]' > '{witness}'\n\
         exit 0\n\
         fi\n\
         if [ \"$1\" = \"probe-write\" ]; then\n\
         exec '{real}' \"$@\"\n\
         fi\n\
         exit 30\n",
        payload = payload.display(),
        witness = write_witness.display(),
        real = real_helper.display(),
    );
    std::fs::write(&shim, script).expect("write helper I/O shim");
    std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755))
        .expect("chmod helper I/O shim");
    shim
}

/// World fixture mirroring the effect-boundary one: a scoped read grant
/// and the supplied worker behind the executor. The marker is the
/// platform-specific scoped-file contents.
pub fn sandbox_world(
    tag: &str,
    marker: &[u8],
    worker: impl rivect::executor::ReadWorker + 'static,
) -> (World, TaskId, PathBuf, String) {
    ensure_helper();
    let mut world = open_world(tag, None);
    let session = world.open_session(&format!("{tag}-session"));
    let task = world.create_task(&session, &format!("{tag}-task"));
    let scope = world.root.join("scope");
    std::fs::create_dir_all(&scope).expect("create sandbox scope");
    let file = scope.join("target.txt");
    std::fs::write(&file, marker).expect("create sandbox target");
    let grant = world.runtime.set_read_scope(scope, file.clone());
    world.runtime.read_worker = Box::new(worker);
    (world, task, file, grant)
}

// ----- provider wire harness ----------------------------------------

/// reqwest's blocking client owns an internal runtime that must never
/// be dropped inside any tokio context — even the blocking pool — so
/// every broker/provider drop goes to a plain OS thread.
pub fn drop_blocking<T: Send + 'static>(value: T) {
    std::thread::spawn(move || drop(value))
        .join()
        .expect("the drop thread joins");
}

/// A bare `provider.send` must not run inside any tokio context for
/// the same reason — sends go to a plain OS thread and the provider
/// comes back.
pub fn send_on_thread<P: Provider + 'static>(
    mut provider: P,
    manifest: RequestManifest,
) -> (P, Result<ProviderReply, ProviderError>) {
    std::thread::spawn(move || {
        let outcome = provider.send(&manifest);
        (provider, outcome)
    })
    .join()
    .expect("the send thread joins")
}

/// A prepared manifest plus the broker that admitted it — the real
/// admission path for the caller's provider pin. The store half of
/// the `*_provider` builders is the credential seam the provider
/// already holds; the caller's clone is done.
pub fn prepared_with<P: Provider + 'static>(
    (provider, _store): (P, Arc<MapStore>),
    config: &Config,
    world: &str,
    inputs: &str,
) -> (Broker, RequestManifest) {
    let mut broker = Broker::new(Box::new(provider));
    let manifest = broker
        .prepare("main", config, world, inputs)
        .expect("the pin passes DEC-011 eligibility");
    (broker, manifest)
}

/// One SSE block on the wire.
pub fn sse_block(event: &str, data: &Value) -> String {
    format!("event: {event}\ndata: {data}\n\n")
}

/// A completed Responses stream: an in-progress message item, a text
/// delta, the done item, any extra output items, then the mandatory
/// `response.completed` terminal carrying the full output set and
/// usage.
pub fn responses_completed_stream(
    text: &str,
    extra_items: Vec<Value>,
    usage: Option<Value>,
) -> String {
    let message = json!({
        "id": "msg_1",
        "type": "message",
        "status": "completed",
        "role": "assistant",
        "content": [{ "type": "output_text", "text": text }],
    });
    let mut output = extra_items;
    output.push(message.clone());
    let mut response = json!({
        "id": "resp_1",
        "status": "completed",
        "output": output,
    });
    if let Some(usage) = usage {
        response["usage"] = usage;
    }
    format!(
        "{}{}{}{}",
        sse_block(
            "response.output_item.added",
            &json!({"item": {"id": "msg_1", "type": "message", "status": "in_progress", "role": "assistant", "content": []}, "output_index": 0}),
        ),
        sse_block(
            "response.output_text.delta",
            &json!({"delta": text, "item_id": "msg_1", "output_index": 0, "content_index": 0}),
        ),
        sse_block(
            "response.output_item.done",
            &json!({"item": message, "output_index": 0}),
        ),
        sse_block("response.completed", &json!({"response": response})),
    )
}

pub async fn mount_responses(server: &MockServer, body: String) {
    Mock::given(method("POST"))
        .and(path("/v1/responses"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(body),
        )
        .mount(server)
        .await;
}

/// The request bodies the fixture peer received, parsed as JSON.
pub async fn received_bodies(server: &MockServer) -> Vec<Value> {
    server
        .received_requests()
        .await
        .expect("the mock recorded requests")
        .iter()
        .map(|request: &Request| {
            serde_json::from_slice(&request.body).expect("the wire body is json")
        })
        .collect()
}

// ----- decision fork fixtures (tests/decisions.rs) -----

/// The five-position material fork the decision tests start from:
/// `stage` is the recommended position, `drop` stays visible disabled
/// with its reason — the card must not substitute it and the answer seam
/// must refuse it. `delegation`/`author` default to absent so every test
/// opts into machine resolution explicitly.
pub fn decision_input(task: &TaskId) -> rivect::actions::ResolveDecisionInput {
    use rivect::contracts::{Availability, OptionId, QuestionOption};
    let option =
        |id: &str, label: &str, consequences: &str, availability: Availability| QuestionOption {
            option_id: OptionId(id.to_string()),
            label: label.to_string(),
            consequences: consequences.to_string(),
            availability,
        };
    rivect::actions::ResolveDecisionInput {
        task_id: task.clone(),
        prompt: "The staged migration is ready; pick the rollout.".to_string(),
        options: vec![
            option(
                "ship",
                "Ship now",
                "Every tenant moves at once.",
                Availability::Enabled,
            ),
            option(
                "stage",
                "Staged rollout",
                "Five percent, then widen.",
                Availability::Enabled,
            ),
            option(
                "hold",
                "Hold for the window",
                "Wait for the change freeze.",
                Availability::Enabled,
            ),
            option(
                "rollback",
                "Roll back",
                "Return to the prior release.",
                Availability::Enabled,
            ),
            option(
                "drop",
                "Drop the change",
                "Discards the prepared migration.",
                Availability::Disabled {
                    reason: "the migration is already staged".to_string(),
                },
            ),
        ],
        recommended_option_id: OptionId("stage".to_string()),
        recommendation_basis: "a staged rollout keeps the rollback window open".to_string(),
        delegation: None,
        author: None,
    }
}

/// `decisions.control` on the `command.execute` carrier: `status` takes
/// neither mutation field, `ask`/`auto`/`inherit` require both.
pub fn corpus_decisions_control(
    session: &SessionId,
    op: &str,
    command_id: Option<&str>,
    expected_source_digest: Option<&str>,
    id: Value,
) -> String {
    let mut params = json!({
        "schema_version": 1, "session_id": session.0,
        "command": { "kind": "decisions.control" }, "op": op
    });
    if let Some(command_id) = command_id {
        params["command_id"] = json!(command_id);
    }
    if let Some(expected) = expected_source_digest {
        params["expected_source_digest"] = json!(expected);
    }
    json!({ "jsonrpc": "2.0", "id": id, "method": "command.execute", "params": params }).to_string()
}

// ----- source-search fixture corpus (EDGE-004) -----

/// `command.execute` for one named local kind — the carrier every
/// command kind rides; `project.init` and the future `search.*`/
/// `code.*`/`source.*` interface names are asserted through it.
pub fn corpus_command_execute(session: &SessionId, kind: &str, id: Value) -> String {
    json!({
        "jsonrpc": "2.0", "id": id, "method": "command.execute",
        "params": { "schema_version": 1, "session_id": session.0, "command": { "kind": kind } }
    })
    .to_string()
}

/// The search fixture tree: a `.git` marker so `.gitignore` rules bind,
/// ignore rules excluding `build/` and `secret.txt`, a hidden directory,
/// UTF-8 and single-byte (windows-1251) sources, a doc outside the
/// `*.rs` scope, and a repeated-marker file the truncation leg bounds.
/// `shared_marker` lives in five places so each filter is discriminating:
/// hidden, ignored, scoped-in, scope-excluded, and ignored-non-scope.
pub fn search_corpus(name: &str) -> TempTree {
    let tree = TempTree::new("search", name);
    let root = &tree.path;
    std::fs::create_dir_all(root.join(".git")).expect("git marker");
    std::fs::write(root.join(".gitignore"), "build/\nsecret.txt\n").expect("gitignore");
    std::fs::create_dir_all(root.join(".hidden")).expect("hidden dir");
    std::fs::write(root.join(".hidden/note.rs"), "fn shared_marker() {}\n").expect("hidden file");
    std::fs::create_dir_all(root.join("build")).expect("build dir");
    std::fs::write(root.join("build/generated.rs"), "fn shared_marker() {}\n")
        .expect("ignored file");
    std::fs::create_dir_all(root.join("src")).expect("src dir");
    std::fs::write(
        root.join("src/lib.rs"),
        "fn shared_marker() {}\nfn only_in_lib() {}\n",
    )
    .expect("lib");
    std::fs::write(
        root.join("src/unicode.rs"),
        "const LABEL: &str = \"こんにちは世界\";\nlet glyph = \"\u{1F469}\u{1F3FD}\u{200D}\u{1F4BB}\";\n",
    )
    .expect("unicode");
    // windows-1251 bytes on purpose: a single-byte corpus the UTF-8
    // needle must never match — encoding-honest, not lossy-decoded.
    std::fs::write(
        root.join("src/cp1251.rs"),
        b"let msg = \"\xCF\xF0\xE8\xE2\xE5\xF2\";\nfn single_byte_marker() {}\n",
    )
    .expect("cp1251");
    let repeated = (1..=8).fold(String::new(), |mut body, n| {
        body.push_str(&format!("fn repeated_marker_{n}() {{}}\n"));
        body
    });
    std::fs::write(root.join("src/many.rs"), repeated).expect("many");
    std::fs::create_dir_all(root.join("docs")).expect("docs dir");
    std::fs::write(root.join("docs/notes.md"), "shared_marker in prose\n").expect("docs");
    std::fs::write(root.join("secret.txt"), "shared_marker secret\n").expect("secret");
    tree
}

/// The project-index fixture: a Cargo package root so module paths
/// resolve from the package, a nested workspace member so a
/// query-root-relative derivation would answer differently, an imported
/// Rust module, a TypeScript module reached two ways, a test target, an
/// unsupported language, and a lockfile.
pub fn project_corpus(name: &str) -> TempTree {
    let tree = TempTree::new("project", name);
    let root = &tree.path;
    std::fs::create_dir_all(root.join(".git")).expect("git marker");
    std::fs::write(root.join("Cargo.toml"), "[package]\nname = \"fixture\"\n").expect("manifest");
    std::fs::write(root.join("Cargo.lock"), "version = 3\n").expect("lockfile");
    write_file(root, "src/lib.rs", "pub mod helper;\npub fn root_fn() {}\n");
    write_file(root, "src/helper.rs", "pub fn helper_fn() {}\n");
    write_file(
        root,
        "src/uses.rs",
        "use crate::helper::helper_fn;\n\
         pub fn call_it() {\n    helper_fn();\n    crate::helper::helper_fn();\n}\n\
         pub fn external() {}\n",
    );
    write_file(
        root,
        "app/main.ts",
        "import { helper } from \"./helper\";\nexport function run() { helper(); }\n",
    );
    write_file(root, "app/helper.ts", "export function helper() {}\n");
    write_file(
        root,
        "tests/case.rs",
        "use crate::helper::helper_fn;\nfn case() { helper_fn(); }\n",
    );
    tree
}

/// Writes one fixture file, creating its directory.
pub fn write_file(root: &Path, relative: &str, body: &str) {
    let target = root.join(relative);
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent).expect("fixture dir");
    }
    std::fs::write(target, body).expect("fixture file");
}

/// One `Query` over the fixture: `Respect` filters, no scope glob,
/// bound 64 — each leg overrides exactly the field under test.
pub fn search_query(
    kind: rivect::context::QueryKind,
    root: &Path,
    pattern: &str,
) -> rivect::context::Query {
    rivect::context::Query {
        kind,
        root: root.to_path_buf(),
        pattern: pattern.to_string(),
        scope_glob: None,
        ignore: rivect::context::IgnorePolicy::Respect,
        limit: 64,
        symbol_op: None,
        document: None,
    }
}

/// One `Symbol` query carrying its operation — the symbol leg refuses an
/// op-less request, so every symbol test names the op it proves.
pub fn symbol_query(
    root: &Path,
    pattern: &str,
    op: rivect::lsp::SymbolOp,
) -> rivect::context::Query {
    let mut request = search_query(rivect::context::QueryKind::Symbol, root, pattern);
    request.symbol_op = Some(op);
    request
}

/// A fixture tree holding exactly `files` under a `.git` marker — each
/// symbol leg pins its own small corpus so line numbers stay exact.
pub fn tree_of(name: &str, files: &[(&str, &str)]) -> TempTree {
    let tree = TempTree::new("symbol", name);
    std::fs::create_dir_all(tree.path.join(".git")).expect("git marker");
    for (relative, body) in files {
        let target = tree.path.join(relative);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).expect("fixture dir");
        }
        std::fs::write(target, body).expect("fixture file");
    }
    tree
}

/// The structural-search fixture tree: a `.git` marker, one ignored
/// Rust file, and per-language sources — Rust, TypeScript and TSX carry
/// known structural shapes; a Python file carries a language no
/// admitted grammar claims. Per-test legs add damaged or locked files
/// themselves so the base corpus stays predictable.
pub fn ast_corpus(name: &str) -> TempTree {
    let tree = TempTree::new("ast", name);
    let root = &tree.path;
    std::fs::create_dir_all(root.join(".git")).expect("git marker");
    std::fs::write(root.join(".gitignore"), "build/\n").expect("gitignore");
    std::fs::create_dir_all(root.join("src")).expect("src dir");
    std::fs::write(
        root.join("src/lib.rs"),
        "fn greet(name: &str) -> String {\n    format!(\"hello {name}\")\n}\n\nfn marker_target() {}\n\nfn other_target() {}\n",
    )
    .expect("rust fixture");
    std::fs::write(
        root.join("src/app.ts"),
        "function greet(name) {\n    return \"hello \" + name;\n}\n\nconst ANSWER: number = 42;\n",
    )
    .expect("ts fixture");
    std::fs::write(
        root.join("src/widget.tsx"),
        "export function Widget(props) {\n    return <div>{props.title}</div>;\n}\n",
    )
    .expect("tsx fixture");
    std::fs::write(
        root.join("src/notes.py"),
        "def greet(name):\n    return \"hello \" + name\n",
    )
    .expect("unsupported fixture");
    std::fs::create_dir_all(root.join("build")).expect("build dir");
    std::fs::write(root.join("build/generated.rs"), "fn generated() {}\n").expect("ignored rust");
    tree
}

/// The typed-symbol-index fixture tree: same-name `helper` definitions
/// across scopes — `mod a` (returning `Token`) and `mod b` in Rust,
/// plus a top-level TypeScript `helper` — an undefined `zap()` use for
/// the unknown-edge leg, one ignored Rust file, and a Python file no
/// admitted grammar claims so the fallback and coverage legs bind.
/// `lib.rs` is exactly nine lines; the tests pin line numbers. `mod a`
/// names the root `Token` through `crate::` — a bare name does not
/// cross a module boundary.
pub fn symbol_corpus(name: &str) -> TempTree {
    let tree = TempTree::new("symbol", name);
    let root = &tree.path;
    std::fs::create_dir_all(root.join(".git")).expect("git marker");
    std::fs::write(root.join(".gitignore"), "build/\n").expect("gitignore");
    std::fs::create_dir_all(root.join("src")).expect("src dir");
    std::fs::write(
        root.join("src/lib.rs"),
        "mod a {\n\
         \x20   pub fn helper() -> crate::Token { crate::Token }\n\
         \x20   pub fn summon() { helper(); }\n\
         }\n\
         mod b {\n\
         \x20   pub fn helper() {}\n\
         }\n\
         pub struct Token;\n\
         pub fn caller() { a::helper(); b::helper(); zap(); }\n",
    )
    .expect("rust fixture");
    std::fs::write(
        root.join("src/app.ts"),
        "function helper() { return 1; }\n\
         export class Widget {\n\
         \x20   build() { return this; }\n\
         }\n\
         const runner: Widget = new Widget();\n",
    )
    .expect("ts fixture");
    std::fs::write(root.join("src/notes.py"), "def helper():\n    return 1\n").expect("py fixture");
    std::fs::create_dir_all(root.join("build")).expect("build dir");
    std::fs::write(root.join("build/generated.rs"), "fn generated() {}\n").expect("ignored rust");
    tree
}
