//! Loopback DWS peer: one plain TCP listener that serves the recorded
//! REST setup paths and the workflow WebSocket upgrade, so the adapter
//! proof runs the real socket stack — the blocking client on one side,
//! `tungstenite::accept_hdr` on the other. No production host, no live
//! account, no recorded frame from a real workflow.

use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tungstenite::handshake::server::{Request, Response};
use tungstenite::{Message, accept_hdr};

/// The workflow token the direct-access leg answers.
pub const WORKFLOW_TOKEN: &str = "fixture-workflow-token-not-real";

/// The numeric project id the path lookup answers.
pub const PROJECT_ID: &str = "77";

/// The first workflow id a create answers; every create increments it.
pub const FIRST_WORKFLOW_ID: u64 = 4242;

/// The client PAT the stored workspace profile carries.
pub const PROFILE_TOKEN: &str = "fixture-profile-token-not-real";

/// How long a served socket may stay silent before the peer gives up, so
/// a broken client can never wedge the test thread.
const READ_WINDOW: Duration = Duration::from_secs(10);

/// One request the peer received — a REST leg or the socket upgrade.
#[derive(Debug, Clone)]
pub struct PeerRequest {
    pub method: String,
    pub target: String,
    pub headers: BTreeMap<String, String>,
    pub body: String,
}

impl PeerRequest {
    /// The request path without its query.
    #[must_use]
    pub fn path(&self) -> &str {
        self.target.split('?').next().unwrap_or_default()
    }
}

/// What one socket does after the client's start envelope.
#[derive(Debug, Clone, Default)]
pub struct SocketScript {
    /// Frames written to the client, in order.
    pub frames: Vec<String>,
    /// Whether the peer closes the socket after the frames.
    pub close: bool,
}

/// The whole peer's script: one entry per accepted socket, the last one
/// repeating for a further socket.
#[derive(Debug, Clone, Default)]
pub struct PeerScript {
    pub sockets: Vec<SocketScript>,
    /// Accept the TCP connection and never answer the upgrade.
    pub silent: bool,
    /// Answer a workflow `stop` (`PATCH …/workflows/{id}`) with 500.
    pub refuse_stop: bool,
    /// Answer the numeric project-id lookup (`GET /api/v4/projects/…`)
    /// with 404.
    pub fail_project_lookup: bool,
}

#[derive(Default)]
struct Shared {
    requests: Mutex<Vec<PeerRequest>>,
    start_frames: Mutex<Vec<Value>>,
    sockets: AtomicU64,
    creates: AtomicU64,
    shutdown: AtomicBool,
}

/// One running loopback peer; its drop stops the listener thread.
pub struct WsPeer {
    base: String,
    address: SocketAddr,
    shared: Arc<Shared>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl WsPeer {
    /// Starts the peer on an ephemeral loopback port.
    #[must_use]
    pub fn start(script: PeerScript) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind the loopback DWS peer");
        let address = listener
            .local_addr()
            .expect("the loopback peer has an address");
        let base = format!("http://{address}");
        let shared = Arc::new(Shared::default());
        let thread_shared = Arc::clone(&shared);
        let handle = std::thread::spawn(move || serve_loop(&listener, &script, &thread_shared));
        Self {
            base,
            address,
            shared,
            handle: Some(handle),
        }
    }

    /// The `http://` base the connection's endpoint names.
    #[must_use]
    pub fn base(&self) -> &str {
        &self.base
    }

    /// Every request the peer received, in arrival order.
    #[must_use]
    pub fn requests(&self) -> Vec<PeerRequest> {
        self.shared
            .requests
            .lock()
            .expect("peer request log")
            .clone()
    }

    /// The `startRequest` envelopes the sockets carried.
    #[must_use]
    pub fn start_frames(&self) -> Vec<Value> {
        self.shared
            .start_frames
            .lock()
            .expect("peer start-frame log")
            .clone()
    }

    /// How many sockets the peer upgraded.
    #[must_use]
    pub fn sockets(&self) -> u64 {
        self.shared.sockets.load(Ordering::SeqCst)
    }

    /// How many workflows the create leg made.
    #[must_use]
    pub fn creates(&self) -> u64 {
        self.shared.creates.load(Ordering::SeqCst)
    }
}

impl Drop for WsPeer {
    fn drop(&mut self) {
        self.shared.shutdown.store(true, Ordering::SeqCst);
        // Wake the blocking accept so the thread observes the flag.
        if let Ok(stream) = TcpStream::connect(self.address) {
            drop(stream);
        }
        if let Some(handle) = self.handle.take() {
            let joined = handle.join();
            drop(joined);
        }
    }
}

fn serve_loop(listener: &TcpListener, script: &PeerScript, shared: &Shared) {
    loop {
        let Ok((stream, _address)) = listener.accept() else {
            return;
        };
        if shared.shutdown.load(Ordering::SeqCst) {
            return;
        }
        serve(stream, script, shared);
    }
}

fn serve(stream: TcpStream, script: &PeerScript, shared: &Shared) {
    if stream.set_read_timeout(Some(READ_WINDOW)).is_err() {
        return;
    }
    let mut probe = [0_u8; 4096];
    let Ok(size) = stream.peek(&mut probe) else {
        return;
    };
    if size == 0 {
        return;
    }
    let head = String::from_utf8_lossy(&probe[..size]).to_string();
    if head.starts_with("GET ") && head.contains("/duo_workflows/ws") {
        if script.silent {
            hold_unanswered(stream);
        } else {
            serve_socket(stream, script, shared);
        }
        return;
    }
    serve_rest(stream, script, shared);
}

/// Holds an accepted connection that never answers the upgrade — the
/// silent-handshake case.
fn hold_unanswered(mut stream: TcpStream) {
    let mut sink = [0_u8; 1];
    loop {
        match stream.read(&mut sink) {
            Ok(0) => return,
            Err(_closed) => return,
            Ok(_more) => continue,
        }
    }
}

fn serve_rest(mut stream: TcpStream, script: &PeerScript, shared: &Shared) {
    let Some(request) = read_request(&mut stream) else {
        return;
    };
    let (status, payload) = route(&request, script, shared);
    shared
        .requests
        .lock()
        .expect("peer request log")
        .push(request);
    let body = payload.to_string();
    let reason = if (200..300).contains(&status) {
        "OK"
    } else {
        "Error"
    };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    );
    if stream.write_all(head.as_bytes()).is_err() {
        return;
    }
    if stream.write_all(body.as_bytes()).is_err() {
        return;
    }
    let flushed = stream.flush();
    drop(flushed);
}

fn route(request: &PeerRequest, script: &PeerScript, shared: &Shared) -> (u16, Value) {
    match (request.method.as_str(), request.path()) {
        ("POST", "/api/v4/ai/duo_workflows/direct_access") => {
            (200, json!({ "gitlab_rails": { "token": WORKFLOW_TOKEN } }))
        }
        ("POST", "/api/v4/ai/duo_workflows/workflows") => {
            let id = FIRST_WORKFLOW_ID + shared.creates.fetch_add(1, Ordering::SeqCst);
            (200, json!({ "id": id.to_string() }))
        }
        ("PATCH", path)
            if path.starts_with("/api/v4/ai/duo_workflows/workflows/") && script.refuse_stop =>
        {
            (
                500,
                json!({ "message": "the workflow could not be stopped" }),
            )
        }
        ("PATCH", path) if path.starts_with("/api/v4/ai/duo_workflows/workflows/") => {
            (200, json!({ "status": "STOPPED" }))
        }
        ("GET", path) if path.starts_with("/api/v4/projects/") && script.fail_project_lookup => {
            (404, json!({ "message": "404 project not found" }))
        }
        ("GET", path) if path.starts_with("/api/v4/projects/") => {
            (200, json!({ "id": PROJECT_ID }))
        }
        _ => (200, json!({})),
    }
}

fn read_request(stream: &mut TcpStream) -> Option<PeerRequest> {
    let reader = stream.try_clone().ok()?;
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();
    let mut headers = BTreeMap::new();
    loop {
        let mut header = String::new();
        reader.read_line(&mut header).ok()?;
        let header = header.trim_end();
        if header.is_empty() {
            break;
        }
        if let Some((name, value)) = header.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }
    let length = headers
        .get("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = vec![0_u8; length];
    if length > 0 {
        reader.read_exact(&mut body).ok()?;
    }
    Some(PeerRequest {
        method,
        target,
        headers,
        body: String::from_utf8_lossy(&body).to_string(),
    })
}

#[allow(
    clippy::result_large_err,
    reason = "tungstenite's own handshake callback signature carries the large error type"
)]
fn serve_socket(stream: TcpStream, script: &PeerScript, shared: &Shared) {
    let mut socket = match accept_hdr(stream, |request: &Request, response: Response| {
        record_upgrade(shared, request);
        Ok(response)
    }) {
        Ok(socket) => socket,
        Err(_handshake) => return,
    };
    let index = shared.sockets.fetch_add(1, Ordering::SeqCst) as usize;
    match socket.read() {
        Ok(Message::Text(text)) => {
            if let Ok(parsed) = serde_json::from_str::<Value>(&text) {
                shared
                    .start_frames
                    .lock()
                    .expect("peer start-frame log")
                    .push(parsed);
            }
        }
        Ok(_other) => {
            return;
        }
        Err(_closed) => return,
    }
    if let Some(scripted) = script.sockets.get(index).or_else(|| script.sockets.last()) {
        for frame in &scripted.frames {
            if socket.send(Message::Text(frame.clone().into())).is_err() {
                return;
            }
        }
        if scripted.close {
            if socket.close(None).is_err() {
                return;
            }
            return;
        }
    }
    // Hold the socket until the client drops it, so a silent socket and a
    // client-side idle window are both real.
    loop {
        match socket.read() {
            Ok(_message) => continue,
            Err(_closed) => return,
        }
    }
}

fn record_upgrade(shared: &Shared, request: &Request) {
    let headers = request
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_ascii_lowercase(), value.to_string()))
        })
        .collect();
    shared
        .requests
        .lock()
        .expect("peer request log")
        .push(PeerRequest {
            method: request.method().as_str().to_string(),
            target: request.uri().to_string(),
            headers,
            body: String::new(),
        });
}
