//! Shared corpus (architecture TP-PUBLIC + TP-ADMISSION-PACKET): the
//! canonical request line set, the question fixture, the eight config
//! examples with their negative mutations and group controls, and the
//! PTY harness for real-terminal TUI cases. One corpus, both ingresses.

#![allow(dead_code)]

use rivect::commands::{Ingress, Runtime};
use rivect::contracts::{AnswerSelection, Event, Question, SessionId, TaskId};
use rivect::model::RequestManifest;
use rivect::providers::{Provider, ProviderReply};
use serde_json::{Value, json};
use sha2::Digest;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
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

    fn send(
        &mut self,
        manifest: &RequestManifest,
    ) -> Result<ProviderReply, rivect::providers::ProviderError> {
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
    master: std::boxed::Box<dyn std::io::Write + Send>,
    child: std::boxed::Box<dyn portable_pty::Child + Send>,
    stream: Arc<std::sync::Mutex<Vec<u8>>>,
}

pub fn spawn_pty(program: &str, rows: u16, cols: u16) -> PtySession {
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
    command.env("RIVECT_DATA_ROOT", temp_dir("pty-data"));
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
    }
}

impl PtySession {
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
