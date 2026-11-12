//! AC-078 typed vision path (TD-20): one answer image crosses the scoped
//! executor, is sniffed/bounded/digested on the frozen manifest, and rides
//! the same single provider send the text path uses. Every unsupported
//! shape — declared/detected media mismatch, oversize, outside scope, a
//! symlink escape, an incapable provider, a machine answer — denies typed
//! with zero sends. The packaged TUI composer is the shipped ordinary entry:
//! `/image <path>` attaches one file to the next answer and the local
//! loopback model completes with one settlement. Live external vision stays
//! NOT_RUN.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::let_underscore_must_use,
    let_underscore_drop,
    clippy::redundant_clone,
    reason = "test assertions fail loudly with the observed payload; src/ stays strict (standards §14)"
)]

mod support;

use rivect::config::Connection;
use rivect::contracts::{Question, SessionId, TaskId};
use rivect::model::RequestManifest;
use rivect::providers::{LoopbackProvider, Provider, ProviderError, ProviderReply};
use rivect::state::SettlementTotals;
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use support::{World, corpus_create};

/// A deterministic 1×1 PNG: the local fixture every positive carries.
const PNG: &[u8] = &[
    0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, b'I', b'H', b'D', b'R',
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4,
    0x89, 0x00, 0x00, 0x00, 0x0a, b'I', b'D', b'A', b'T', 0x78, 0x9c, 0x63, 0x00, 0x01, 0x00, 0x00,
    0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, b'I', b'E', b'N', b'D', 0xae, 0x42, 0x60, 0x82,
];

const JPEG_MAGIC: &[u8] = &[
    0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, b'J', b'F', b'I', b'F', 0x00,
];

fn vision_config() -> String {
    "config_version = 1\n\
     [connections.fixture-local]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:11434\"\n\
     [models.defaults]\n\
     model = { mode = \"fixed\", connection = \"fixture-local\", model_id = \"fixture-model\" }\n\
     effort = { mode = \"auto\" }\nfallback = { mode = \"off\" }\n"
        .to_string()
}

/// One counting provider over the offline loopback whose recorded capability
/// answers the fixture model. A text-only world uses `capable = false` to
/// prove the eligibility denial.
struct VisionPeer {
    inner: LoopbackProvider,
    calls: Arc<AtomicU64>,
    manifest: Arc<std::sync::Mutex<Option<RequestManifest>>>,
    capable: bool,
}

impl VisionPeer {
    fn new(
        capable: bool,
    ) -> (
        Self,
        Arc<AtomicU64>,
        Arc<std::sync::Mutex<Option<RequestManifest>>>,
    ) {
        let calls = Arc::new(AtomicU64::new(0));
        let manifest = Arc::new(std::sync::Mutex::new(None));
        (
            Self {
                inner: LoopbackProvider::new(),
                calls: calls.clone(),
                manifest: manifest.clone(),
                capable,
            },
            calls,
            manifest,
        )
    }
}

impl Provider for VisionPeer {
    fn name(&self) -> &'static str {
        "vision-fixture"
    }

    fn serves(&self, connection: &str, entry: &Connection) -> bool {
        self.inner.serves(connection, entry)
    }

    fn image_input(&self, connection: &str, model: &str) -> bool {
        self.capable && connection == "fixture-local" && model == "fixture-model"
    }

    fn send(&mut self, manifest: &RequestManifest) -> Result<ProviderReply, ProviderError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        *self.manifest.lock().expect("manifest lock") = Some(manifest.clone());
        self.inner.send(manifest)
    }
}

struct VisionWorld {
    world: World,
    scope: PathBuf,
    image: PathBuf,
    calls: Arc<AtomicU64>,
    manifest: Arc<std::sync::Mutex<Option<RequestManifest>>>,
}

fn vision_world(tag: &str, capable: bool) -> VisionWorld {
    support::ensure_helper();
    let (provider, calls, manifest) = VisionPeer::new(capable);
    let mut world = support::open_world_with(
        tag,
        Some(&vision_config()),
        Box::new(provider),
        Box::new(support::PlatformWorker::default()),
    );
    let scope = world.root.join("scope");
    std::fs::create_dir_all(&scope).expect("scope dir");
    let image = scope.join("image.png");
    std::fs::write(&image, PNG).expect("image fixture");
    let file = scope.join("allowed.txt");
    std::fs::write(&file, "vision fixture file\n").expect("scoped file");
    world.runtime.purpose = "backend_task".to_string();
    world.runtime.set_read_scope(scope.clone(), file);
    VisionWorld {
        world,
        scope,
        image,
        calls,
        manifest,
    }
}

fn create_running_task(
    world: &mut World,
    session: &SessionId,
    question: &mut Option<Question>,
) -> TaskId {
    let response = world.dispatch(&corpus_create(session, "vision-create"));
    let task = TaskId(
        response["result"]["task_id"]
            .as_str()
            .expect("task id")
            .to_string(),
    );
    *question = Some(world.publish(session, &task));
    task
}

fn answer_frame(
    session: &SessionId,
    task: &TaskId,
    question: &Question,
    text: &str,
    image: Option<Value>,
) -> String {
    let mut params = json!({
        "schema_version": 1, "command_id": "vision-answer", "session_id": session.0,
        "kind": "answer", "task_id": task.0,
        "expected_intent_revision": question.intent_revision,
        "question_id": question.question_id.0,
        "question_revision": question.question_revision,
        "selection": { "kind": "custom", "text": text },
    });
    if let Some(image) = image {
        params["image"] = image;
    }
    json!({"jsonrpc": "2.0", "id": 41, "method": "task.submit", "params": params}).to_string()
}

fn totals(world: &World) -> SettlementTotals {
    world.runtime.store().settlement_totals().expect("totals")
}

#[test]
fn tui_answer_carries_one_bounded_digested_image_and_one_settlement() {
    let mut fixture = vision_world("vision-positive", true);
    let session = fixture.world.open_session("vision-session");
    let mut question = None;
    let task = create_running_task(&mut fixture.world, &session, &mut question);
    let question = question.expect("question");
    let image_path = fixture.image.display().to_string();
    let answer = fixture.world.dispatch(&answer_frame(
        &session,
        &task,
        &question,
        "describe the image",
        Some(json!({"path": image_path, "media_type": "png"})),
    ));
    assert!(answer["error"].is_null(), "{answer}");
    assert_eq!(answer["result"]["status"], "applied", "{answer}");
    assert_eq!(
        answer["result"]["snapshot"]["lifecycle"], "completed",
        "the answer drains the ordinary step to completion"
    );
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1, "one physical send");
    assert_eq!(totals(&fixture.world).settled_count, 1, "one settlement");

    let manifest = fixture
        .manifest
        .lock()
        .expect("manifest lock")
        .clone()
        .expect("the provider received the manifest");
    let image = manifest
        .image
        .as_ref()
        .expect("the manifest carries the image");
    assert_eq!(image.media(), rivect::model::ImageMedia::Png);
    assert_eq!(image.byte_len(), PNG.len());
    assert_eq!(image.digest(), support::sha256_hex(PNG));
    assert_eq!(image.bytes(), PNG);
    assert_eq!(image.dimensions(), Some((1, 1)));
    assert!(
        !manifest.wire_bytes().contains("data:image/"),
        "wire_bytes stays the text composition the adapter never relies on"
    );
    for rendered in [format!("{manifest:?}"), format!("{image:?}")] {
        assert!(
            !rendered.contains("iVBORw0KGgo") && !rendered.contains("data:image/"),
            "no image bytes or data URL in Debug: {rendered}"
        );
        assert!(
            rendered.contains(&support::sha256_hex(PNG)),
            "the digest is named"
        );
    }
}

#[test]
fn declared_media_mismatch_denies_before_any_send() {
    let mut fixture = vision_world("vision-mismatch", true);
    let session = fixture.world.open_session("vision-mismatch-session");
    let mut question = None;
    let task = create_running_task(&mut fixture.world, &session, &mut question);
    let question = question.expect("question");
    let mismatched = fixture.scope.join("declared-png.jpg");
    std::fs::write(&mismatched, JPEG_MAGIC).expect("jpeg fixture");
    let answer = fixture.world.dispatch(&answer_frame(
        &session,
        &task,
        &question,
        "describe",
        Some(json!({"path": mismatched.display().to_string(), "media_type": "png"})),
    ));
    assert_eq!(answer["error"]["data"]["code"], "invalid_input", "{answer}");
    assert!(
        answer["error"]["data"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("declared png, detected jpeg")),
        "the denial names both media: {answer}"
    );
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0, "zero sends");
    assert_eq!(totals(&fixture.world).settled_count, 0, "zero settlements");
}

#[test]
fn oversize_image_names_the_raw_bound_and_scope_with_zero_sends() {
    let mut fixture = vision_world("vision-oversize", true);
    let session = fixture.world.open_session("vision-oversize-session");
    let mut question = None;
    let task = create_running_task(&mut fixture.world, &session, &mut question);
    let question = question.expect("question");
    let oversize = fixture.scope.join("oversize.png");
    let mut bytes = PNG.to_vec();
    bytes.resize(rivect::contracts::IMAGE_MAX_BYTES + 1, 0);
    std::fs::write(&oversize, &bytes).expect("oversize fixture");
    let answer = fixture.world.dispatch(&answer_frame(
        &session,
        &task,
        &question,
        "describe",
        Some(json!({"path": oversize.display().to_string(), "media_type": "png"})),
    ));
    let message = answer["error"]["data"]["message"]
        .as_str()
        .expect("typed message");
    assert!(
        message.contains("raw_limit=524288") && message.contains("wire_limit=1048576"),
        "the denial names both bounds: {answer}"
    );
    assert!(
        message.contains(&fixture.scope.display().to_string()),
        "the denial names the resolved scope root: {answer}"
    );
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0, "zero sends");
    assert_eq!(totals(&fixture.world).settled_count, 0, "zero settlements");
}

#[test]
fn unsupported_media_denies_before_any_send() {
    let mut fixture = vision_world("vision-media", true);
    let session = fixture.world.open_session("vision-media-session");
    let mut question = None;
    let task = create_running_task(&mut fixture.world, &session, &mut question);
    let question = question.expect("question");
    let gif = fixture.scope.join("animation.png");
    std::fs::write(&gif, b"GIF89a-not-an-image").expect("gif fixture");
    let answer = fixture.world.dispatch(&answer_frame(
        &session,
        &task,
        &question,
        "describe",
        Some(json!({"path": gif.display().to_string(), "media_type": "png"})),
    ));
    assert!(
        answer["error"]["data"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("unsupported image media")),
        "{answer}"
    );
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
    assert_eq!(totals(&fixture.world).settled_count, 0);
}

#[test]
fn outside_scope_and_symlink_escape_deny_through_the_executor() {
    let mut fixture = vision_world("vision-scope", true);
    let session = fixture.world.open_session("vision-scope-session");
    let mut question = None;
    let task = create_running_task(&mut fixture.world, &session, &mut question);
    let question = question.expect("question");
    let outside = fixture.world.root.join("outside.png");
    std::fs::write(&outside, PNG).expect("outside fixture");
    let outside_answer = fixture.world.dispatch(&answer_frame(
        &session,
        &task,
        &question,
        "describe",
        Some(json!({"path": outside.display().to_string(), "media_type": "png"})),
    ));
    assert_eq!(
        outside_answer["error"]["data"]["code"], "denied",
        "{outside_answer}"
    );
    assert!(
        outside_answer["error"]["data"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("outside the admitted scope")),
        "{outside_answer}"
    );

    let escape = fixture.scope.join("escape.png");
    std::os::unix::fs::symlink(&outside, &escape).expect("symlink fixture");
    let symlink_answer = fixture.world.dispatch(&answer_frame(
        &session,
        &task,
        &question,
        "describe",
        Some(json!({"path": escape.display().to_string(), "media_type": "png"})),
    ));
    assert_eq!(
        symlink_answer["error"]["data"]["code"], "denied",
        "{symlink_answer}"
    );
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0, "zero sends");
    assert_eq!(totals(&fixture.world).settled_count, 0, "zero settlements");
}

#[test]
fn incapable_provider_denies_typed_with_zero_sends() {
    let mut fixture = vision_world("vision-incapable", false);
    let session = fixture.world.open_session("vision-incapable-session");
    let mut question = None;
    let task = create_running_task(&mut fixture.world, &session, &mut question);
    let question = question.expect("question");
    let answer = fixture.world.dispatch(&answer_frame(
        &session,
        &task,
        &question,
        "describe",
        Some(json!({"path": fixture.image.display().to_string(), "media_type": "png"})),
    ));
    assert_eq!(
        answer["error"]["data"]["code"], "capability_unavailable",
        "{answer}"
    );
    assert!(
        answer["error"]["data"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("image input is not supported")),
        "{answer}"
    );
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0, "zero sends");
    assert_eq!(totals(&fixture.world).settled_count, 0, "zero settlements");
}

#[test]
fn machine_vision_answer_is_denied_and_names_the_tui_recovery() {
    let mut fixture = vision_world("vision-machine", true);
    let session = fixture.world.open_session("vision-machine-session");
    let mut question = None;
    let task = create_running_task(&mut fixture.world, &session, &mut question);
    let question = question.expect("question");
    let answer = fixture.world.dispatch_machine(&answer_frame(
        &session,
        &task,
        &question,
        "describe",
        Some(json!({"path": fixture.image.display().to_string(), "media_type": "png"})),
    ));
    assert_eq!(answer["error"]["data"]["code"], "denied", "{answer}");
    assert!(
        answer["error"]["data"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("/image <path>")),
        "the denial names the TUI composer recovery: {answer}"
    );
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0, "zero sends");
}

// ----- packaged TUI composer positive -----

/// One local `ollama` loopback peer: the served catalogue and native
/// descriptor state a vision model so the recorded capability probe
/// answers, and one Responses POST carries the answer's read call. Only
/// `/v1/responses` POSTs are counted as sends.
struct OllamaPeer {
    endpoint: String,
    address: std::net::SocketAddr,
    posts: Arc<AtomicU64>,
    stop: Arc<std::sync::atomic::AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl OllamaPeer {
    fn start(read_path: &'static str) -> Self {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind peer");
        let address = listener.local_addr().expect("peer address");
        let posts = Arc::new(AtomicU64::new(0));
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let thread_posts = posts.clone();
        let thread_stop = stop.clone();
        let handle = std::thread::spawn(move || {
            loop {
                let Ok((mut stream, _)) = listener.accept() else {
                    return;
                };
                if thread_stop.load(Ordering::SeqCst) {
                    return;
                }
                let Some((method, target, _)) = read_http(&mut stream) else {
                    continue;
                };
                // The Responses adapter's legs: the model send is the one
                // counted POST, while the capability gate and the catalogue
                // read state the served descriptor — `/api/tags` and
                // `/api/show` are the native surface, never sends.
                let (status, body) = if method == "POST" && target.ends_with("/v1/responses") {
                    thread_posts.fetch_add(1, Ordering::SeqCst);
                    ("200 OK", responses_stream(read_path))
                } else if target.ends_with("/api/show") {
                    (
                        "200 OK",
                        json!({
                            "capabilities": ["thinking", "vision"],
                            "model_info": {"fixture.context_length": 4096},
                        })
                        .to_string(),
                    )
                } else if target.ends_with("/api/tags") {
                    (
                        "200 OK",
                        json!({"models": [{"name": "fixture-vision"}]}).to_string(),
                    )
                } else if target.ends_with("/models") {
                    (
                        "200 OK",
                        json!({"object": "list", "data": [{"id": "fixture-vision"}]}).to_string(),
                    )
                } else {
                    ("200 OK", json!({"object": "list", "data": []}).to_string())
                };
                let is_stream = method == "POST" && target.ends_with("/v1/responses");
                let content_type = if is_stream {
                    "text/event-stream"
                } else {
                    "application/json"
                };
                let head = format!(
                    "HTTP/1.1 {status}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    body.len()
                );
                let written = stream
                    .write_all(head.as_bytes())
                    .and_then(|()| stream.write_all(body.as_bytes()))
                    .and_then(|()| stream.flush());
                drop(written);
            }
        });
        Self {
            endpoint: format!("http://{address}/v1"),
            address,
            posts,
            stop,
            handle: Some(handle),
        }
    }

    fn posts(&self) -> u64 {
        self.posts.load(Ordering::SeqCst)
    }
}

impl Drop for OllamaPeer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Ok(stream) = std::net::TcpStream::connect(self.address) {
            drop(stream);
        }
        if let Some(handle) = self.handle.take() {
            let joined = handle.join();
            drop(joined);
        }
    }
}

fn read_http(stream: &mut std::net::TcpStream) -> Option<(String, String, Vec<u8>)> {
    let reader = stream.try_clone().ok()?;
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();
    let mut content_length = 0usize;
    loop {
        let mut header = String::new();
        reader.read_line(&mut header).ok()?;
        if header.trim_end().is_empty() {
            break;
        }
        if let Some((name, value)) = header.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            content_length = value.trim().parse().ok()?;
        }
    }
    let mut body = vec![0u8; content_length];
    reader.read_exact(&mut body).ok()?;
    Some((method, target, body))
}

/// One completed Responses stream carrying a single `read_file` call:
/// the answer step executes it once with no second model send.
fn responses_stream(read_path: &str) -> String {
    let arguments = serde_json::to_string(&json!({"path": read_path})).expect("arguments");
    let call = json!({
        "id": "fc_1", "type": "function_call", "status": "completed",
        "call_id": "call-vision", "name": "read_file", "arguments": arguments,
    });
    let added = support::sse_block(
        "response.output_item.added",
        &json!({
            "item": {"id": "fc_1", "type": "function_call", "status": "in_progress", "name": "read_file", "arguments": ""},
            "output_index": 0,
        }),
    );
    let done = support::sse_block(
        "response.output_item.done",
        &json!({"item": call, "output_index": 0}),
    );
    let completed = support::sse_block(
        "response.completed",
        &json!({"response": {
            "id": "resp_1",
            "status": "completed",
            "output": [call],
            "usage": {"input_tokens": 3, "output_tokens": 1, "total_tokens": 4},
        }}),
    );
    format!("{added}{done}{completed}")
}

fn installed_vision_config(endpoint: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.ollama]\nkind = \"local\"\nendpoint = \"{endpoint}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"ollama\", model_id = \"fixture-vision\" }}\n\
         effort = {{ mode = \"auto\" }}\nfallback = {{ mode = \"off\" }}\n"
    )
}

#[test]
fn packaged_tui_slash_image_attaches_a_png_and_completes_with_one_settlement() {
    let peer = OllamaPeer::start("AGENTS.md");
    let root = tempfile::TempDir::with_prefix("rivect-vision-tui-").expect("fixture root");
    let bundle = support::release::baseline_bundle();
    assert!(
        !bundle.starts_with(env!("CARGO_MANIFEST_DIR")),
        "the positive runs on the packaged bundle outside the checkout: {}",
        bundle.display()
    );
    let data = root.path().join("data root");
    let cwd = root.path().join("nested").join("юникод");
    std::fs::create_dir_all(&data).expect("data root");
    std::fs::create_dir_all(&cwd).expect("cwd");
    std::fs::write(cwd.join("AGENTS.md"), "vision instructions\n").expect("instructions");
    std::fs::write(cwd.join("image.png"), PNG).expect("image fixture");
    std::fs::write(
        data.join("config.toml"),
        installed_vision_config(&peer.endpoint),
    )
    .expect("config");

    let mut command = support::pty_command(bundle.join("rivect"));
    command.arg("--data-root");
    command.arg(&data);
    command.cwd(&cwd);
    let mut pty = support::PtySession::spawn(command, 24, 80, root, data.clone())
        .expect("spawn the packaged TUI");
    assert!(
        pty.wait_for(b"\x1b[?1049h", Duration::from_secs(10))
            .expect("pty read"),
        "the packaged TUI enters the alternate screen"
    );
    pty.send(b"/image image.png\r").expect("pty send");
    let attached = support::wait_for_screen_text(
        &pty,
        24,
        80,
        &format!("image png {} bytes", PNG.len()),
        Duration::from_secs(10),
    )
    .expect("attachment line");
    assert!(
        attached.contains(&format!("image png {} bytes", PNG.len())),
        "the composer names the attached media and size: {attached}"
    );
    pty.send(b"/image\r").expect("pty send bare image");
    let cleared =
        support::wait_for_screen_text(&pty, 24, 80, "image detached", Duration::from_secs(10))
            .expect("clear line");
    assert!(
        cleared.contains("image detached"),
        "bare /image clears the attachment: {cleared}"
    );
    pty.send(b"/image image.png\r").expect("pty send again");

    pty.send("run the vision task\r".as_bytes())
        .expect("pty send");
    let card =
        support::wait_for_screen_text(&pty, 24, 80, "awaiting decision", Duration::from_secs(10))
            .expect("start card");
    assert!(card.contains("awaiting decision"), "the start card opens");
    std::thread::sleep(Duration::from_millis(300));
    pty.send(b"\r").expect("pty send enter");
    let answered = support::wait_for_screen_text(
        &pty,
        24,
        80,
        "decision answer recorded; task resumed",
        Duration::from_secs(10),
    )
    .expect("answer note");
    assert!(
        answered.contains("decision answer recorded; task resumed"),
        "the answer resumes the task: {answered}"
    );
    let completed =
        support::wait_for_screen_text(&pty, 24, 80, "completed", Duration::from_secs(10))
            .expect("completed dock");
    assert!(completed.contains("completed"), "the task completes");
    pty.send(b"\x1b").expect("pty send exit");
    assert_eq!(
        pty.wait_exit(Duration::from_secs(10)).expect("pty wait"),
        Some(0)
    );
    let db = data.join("runtime").join("rivect.db");
    let conn = rusqlite::Connection::open(&db).expect("open store");
    let settlements: i64 = conn
        .query_row("SELECT COUNT(*) FROM usage_settlements", [], |row| {
            row.get(0)
        })
        .expect("count settlements");
    assert_eq!(settlements, 1, "one settlement");
    assert_eq!(peer.posts(), 1, "one configured-model send");
    pty.finish().expect("pty teardown");
}

/// The interface docs name the shipped entry, so the test reads it as a
/// contract: a catalog row for `/image` would make it a second registry.
#[test]
fn image_stays_a_ui_local_verb_and_the_catalog_keeps_36_rows() {
    assert_eq!(
        rivect::tools::CATALOG.len(),
        36,
        "the catalog stays 36 rows"
    );
    assert!(
        !rivect::tools::CATALOG
            .iter()
            .any(|row| row.canonical_id.contains("image")),
        "`/image` is not a catalog row"
    );
}
