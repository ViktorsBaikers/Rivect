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
use rivect::contracts::{AnswerSelection, Event, Question, SessionId, TaskId};
use rivect::model::RequestManifest;
use rivect::providers::{
    CredentialStore, Provider, ProviderError, ProviderReply, SecretRef, StoreKind,
};
use serde_json::{Value, json};
use sha2::Digest;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Once};
use std::time::Duration;

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

pub fn config_manual_subscription() -> String {
    format!(
        "{}\n\
         [connections.subscription]\nkind = \"subscription\"\nendpoint = \"https://subscription.fixture.invalid\"\ncredential_ref = \"keyring:subscription-fixture\"\n\
         [models.purposes.main]\nmodel = {{ mode = \"fixed\", connection = \"subscription\", model_id = \"fixture-model\" }}\nfallback = {{ mode = \"manual\" }}\n",
        base_config()
    )
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
}

/// Injectable read-worker oracle: delegates to the REAL macOS worker and
/// counts only successful reads (plus their digest), no global state.
pub struct CountingReadWorker {
    inner: rivect::executor::macos::MacosReadWorker,
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

pub fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "rivect-{}-{}-{}",
        tag,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

/// Fixture directory removed on drop; `prefix` keeps each suite's trees
/// distinct while the name pins the case.
pub struct TempTree {
    pub path: PathBuf,
}

impl TempTree {
    pub fn new(prefix: &str, name: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("rivect-{prefix}-{name}-{}", std::process::id()));
        if path.exists() {
            std::fs::remove_dir_all(&path).expect("remove stale fixture");
        }
        std::fs::create_dir_all(&path).expect("create fixture");
        Self { path }
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        if self.path.exists() {
            drop(std::fs::remove_dir_all(&self.path));
        }
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

pub fn open_world(tag: &str, config_toml: Option<&str>) -> World {
    open_world_at(temp_dir(tag), config_toml)
}

pub fn open_world_at(root: PathBuf, config_toml: Option<&str>) -> World {
    if let Some(text) = config_toml {
        std::fs::write(root.join("config.toml"), text).expect("config write");
    }
    let (provider, calls, last_manifest) = CountingProvider::new();
    let worker_reads = Arc::new(AtomicU64::new(0));
    let last_read_digest = Arc::new(std::sync::Mutex::new(None));
    let worker = CountingReadWorker {
        inner: rivect::executor::macos::MacosReadWorker,
        reads: worker_reads.clone(),
        last_digest: last_read_digest.clone(),
    };
    let runtime = Runtime::open_with_worker(&root, Box::new(provider), Box::new(worker))
        .expect("owner elected");
    World {
        root,
        runtime,
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
    let root = temp_dir(tag);
    if let Some(text) = config_toml {
        std::fs::write(root.join("config.toml"), text).expect("config write");
    }
    let runtime = Runtime::open_with_worker(&root, provider, worker).expect("owner elected");
    World {
        root,
        runtime,
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
            .owner
            .store
            .publish_question(session, &question)
            .expect("publish_question commits");
        question
    }
    pub fn reopen(&mut self) {
        // The read-count and digest Arcs survive the restart: the fresh
        // runtime injects a new counting wrapper over the same counters.
        let staging_provider = CountingProvider::new().0;
        let staging_worker = CountingReadWorker {
            inner: rivect::executor::macos::MacosReadWorker,
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
            inner: rivect::executor::macos::MacosReadWorker,
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

pub struct PtySession {
    master: Box<dyn std::io::Write + Send>,
    child: Box<dyn portable_pty::Child + Send>,
    stream: Arc<std::sync::Mutex<Vec<u8>>>,
    data_root: PathBuf,
}

pub fn spawn_pty(program: &str, rows: u16, cols: u16) -> PtySession {
    let data_root = temp_dir("pty-data");
    spawn_pty_with_args(program, rows, cols, &data_root, &data_root, &[])
}

pub fn spawn_pty_with_args(
    program: &str,
    rows: u16,
    cols: u16,
    data_root: &Path,
    env_root: &Path,
    args: &[&str],
) -> PtySession {
    use portable_pty::{CommandBuilder, NativePtySystem, PtySize, PtySystem};
    let pty_system = NativePtySystem::default();
    let pair = pty_system
        .openpty(PtySize {
            rows,
            cols,
            pixel_width: 0,
            pixel_height: 0,
        })
        .expect("openpty");
    let mut command = CommandBuilder::new(program);
    command.env("RIVECT_DATA_ROOT", env_root);
    for arg in args {
        command.arg(arg);
    }
    let child = pair.slave.spawn_command(command).expect("spawn");
    let writer = pair.master.take_writer().expect("writer");
    let mut reader = pair.master.try_clone_reader().expect("reader");
    let stream = Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = stream.clone();
    // A continuous drain keeps the child's render loop from filling the pty
    // buffer while the test is between reads.
    std::thread::spawn(move || {
        let mut chunk = [0u8; 4096];
        loop {
            match reader.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => sink
                    .lock()
                    .expect("pty lock")
                    .extend_from_slice(&chunk[..n]),
            }
        }
    });
    PtySession {
        master: writer,
        child,
        stream,
        data_root: data_root.to_path_buf(),
    }
}

impl PtySession {
    pub fn data_root(&self) -> PathBuf {
        self.data_root.clone()
    }

    /// Waits until `needle` appears in the collected stream or the deadline
    /// passes; returns whether the needle was seen.
    pub fn wait_for(&mut self, needle: &[u8], timeout: Duration) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        while std::time::Instant::now() < deadline {
            let found = {
                let stream = self.stream.lock().expect("pty lock");
                find_subsequence(&stream, needle).is_some()
            };
            if found {
                return true;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        let stream = self.stream.lock().expect("pty lock");
        find_subsequence(&stream, needle).is_some()
    }

    pub fn send(&mut self, bytes: &[u8]) {
        use std::io::Write;
        self.master.write_all(bytes).expect("pty write");
        self.master.flush().expect("pty flush");
    }

    pub fn collected(&self) -> Vec<u8> {
        self.stream.lock().expect("pty lock").clone()
    }

    pub fn wait_exit(&mut self, timeout: Duration) -> Option<u32> {
        let deadline = std::time::Instant::now() + timeout;
        while std::time::Instant::now() < deadline {
            if let Ok(Some(status)) = self.child.try_wait() {
                return Some(status.exit_code());
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = self.child.kill();
        None
    }
}

pub fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
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

pub fn ensure_helper() {
    static BUILD: Once = Once::new();
    BUILD.call_once(|| {
        let status = std::process::Command::new(env!("CARGO"))
            .args(["build", "-p", "rivect-sandbox-helper"])
            .status()
            .expect("spawn helper build");
        assert!(status.success(), "helper build failed: {status}");
    });
}

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
