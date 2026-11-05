//! Scoped local sharing proof (AC-083b): a listener exists only with an
//! explicit grant, the token is served once and only its SHA-256 digest is
//! stored, and an observer over the socket may read the four allowed
//! projections and nothing else. Revoke and expiry are terminal and refuse
//! the next request before any method body runs; every frame is bound to the
//! grant's session and task.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::let_underscore_must_use,
    let_underscore_drop,
    clippy::redundant_clone,
    reason = "test code keeps unwrap/expect/panic/discard conveniences; src/ stays strict (standards §14)"
)]

mod support;

use rivect::commands::{DispatchStep, Ingress};
use rivect::contracts::{SessionId, TaskId};
use rivect::model::{SendContext, SendOutcome};
use rivect::resources::UsageDelta;
use rivect::state::{ConflictCause, SharingGrantState, StoreError};
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use support::World;

const OPEN: u64 = 1_000;

/// The one local connection a ledger-seeding send resolves through.
fn local_config() -> String {
    "config_version = 1\n\
     [connections.local]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:11434\"\n\
     [models.defaults]\n\
     model = { mode = \"fixed\", connection = \"local\", model_id = \"fixture-model\" }\n\
     effort = { mode = \"fixed\", value = \"high\" }\n\
     fallback = { mode = \"off\" }\n"
        .to_string()
}

/// One world with a live clock, one session and one task: the grant's scope.
struct Fixture {
    world: World,
    session: SessionId,
    task: TaskId,
    now: Arc<AtomicU64>,
}

impl Fixture {
    fn new(tag: &str) -> Self {
        Self::with_config(tag, None)
    }

    fn with_config(tag: &str, config: Option<&str>) -> Self {
        let mut world = support::open_world(tag, config);
        let now = Arc::new(AtomicU64::new(OPEN));
        let handle = Arc::clone(&now);
        world.runtime.work_clock = Box::new(move || handle.load(Ordering::SeqCst));
        let session = world.open_session(&format!("{tag}-boot"));
        let task = world.create_task(&session, &format!("{tag}-task"));
        Self {
            world,
            session,
            task,
            now,
        }
    }

    /// Opens a grant through the product path and returns its wire answer.
    fn open(&mut self, ttl_seconds: Option<u64>) -> Value {
        let mut params = json!({
            "schema_version": 1,
            "session_id": self.session.0,
            "task_id": self.task.0,
        });
        if let Some(ttl) = ttl_seconds {
            params["ttl_seconds"] = json!(ttl);
        }
        self.open_params(params)
    }

    fn open_params(&mut self, params: Value) -> Value {
        let response = self.world.dispatch(&rpc("sharing.grant.open", params));
        assert!(
            response.get("error").is_none(),
            "grant open refused: {response}"
        );
        response["result"].clone()
    }

    fn revoke(&mut self, grant_id: &str) -> Value {
        let response = self.world.dispatch(&rpc(
            "sharing.grant.revoke",
            json!({
                "schema_version": 1,
                "session_id": self.session.0,
                "grant_id": grant_id,
            }),
        ));
        assert!(
            response.get("error").is_none(),
            "grant revoke refused: {response}"
        );
        response["result"].clone()
    }

    fn status(&mut self) -> Value {
        self.world.dispatch(&status_request(&self.session))
    }
}

fn rpc(method: &str, params: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": 73, "method": method, "params": params})
}

fn status_request(session: &SessionId) -> Value {
    rpc(
        "runtime.status",
        json!({"schema_version": 1, "session_id": session.0}),
    )
}

fn snapshot_request(session: &SessionId, task: &TaskId) -> Value {
    rpc(
        "task.snapshot",
        json!({
            "schema_version": 1,
            "session_id": session.0,
            "task_id": task.0,
        }),
    )
}

fn collection_request(session: &SessionId, task: &TaskId) -> Value {
    rpc(
        "task.collection",
        json!({
            "schema_version": 1,
            "session_id": session.0,
            "task_id": task.0,
            "collection": "criteria",
        }),
    )
}

/// One observer over the grant's socket: one request per write, one framed
/// answer per read.
struct Observer {
    writer: UnixStream,
    reader: BufReader<UnixStream>,
}

impl Observer {
    fn connect(socket: &str) -> Self {
        let writer = UnixStream::connect(socket).expect("the share socket accepts");
        writer
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("observer read timeout");
        let reader = BufReader::new(writer.try_clone().expect("observer client clone"));
        Self { writer, reader }
    }

    fn write(&mut self, request: &Value) {
        writeln!(self.writer, "{request}").expect("observer frame write");
        self.writer.flush().expect("observer frame flush");
    }

    fn read(&mut self) -> Value {
        let mut line = String::new();
        let read = self.reader.read_line(&mut line).expect("observer answer");
        assert!(read > 0, "the share surface closed without an answer");
        serde_json::from_str(&line).expect("observer answer is JSON")
    }

    fn send(&mut self, world: &mut World, request: &Value) -> Value {
        self.write(request);
        pump(world);
        self.read()
    }

    fn expect_closed(&mut self) {
        let mut line = String::new();
        let read = self
            .reader
            .read_line(&mut line)
            .expect("a closed peer is readable");
        assert_eq!(read, 0, "the share surface must close the connection");
    }
}

/// Attaches over the grant's socket and returns the live observer. The
/// attach answer is the read-only contract: mode, the grant's session and
/// task, and the exact method allowlist.
fn attach_over_socket(fixture: &mut Fixture, opened: &Value) -> Observer {
    let mut observer = Observer::connect(&socket_of(opened));
    let attached = observer.send(
        &mut fixture.world,
        &rpc(
            "sharing.attach",
            json!({"schema_version": 1, "token": token_of(opened)}),
        ),
    );
    assert!(attached.get("error").is_none(), "attach failed: {attached}");
    let result = &attached["result"];
    assert_eq!(result["mode"], "read_only");
    assert_eq!(result["session_id"], fixture.session.0);
    assert_eq!(result["task_id"], fixture.task.0);
    assert_eq!(
        result["methods"],
        json!([
            "runtime.status",
            "task.snapshot",
            "task.collection",
            "command.describe"
        ])
    );
    observer
}

/// One serving turn on the runtime's own thread. A frame written before the
/// turn is already in the socket buffer, so one turn answers it.
fn pump(world: &mut World) {
    for _ in 0..100 {
        if world.runtime.serve_sharing() > 0 {
            return;
        }
        std::thread::yield_now();
    }
    panic!("the share surface answered no frame");
}

fn token_of(opened: &Value) -> String {
    opened["token"]
        .as_str()
        .expect("the open answer carries the token")
        .to_string()
}

fn grant_id_of(opened: &Value) -> String {
    opened["grant_id"]
        .as_str()
        .expect("the open answer carries the grant id")
        .to_string()
}

fn socket_of(opened: &Value) -> String {
    opened["socket_path"]
        .as_str()
        .expect("the open answer carries the socket path")
        .to_string()
}

fn sha256_hex(text: &str) -> String {
    use sha2::Digest;
    rivect::config::hex(&sha2::Sha256::digest(text.as_bytes()))
}

fn database(root: &Path) -> rusqlite::Connection {
    rusqlite::Connection::open(root.join("runtime").join("rivect.db"))
        .expect("the store opens for the proof")
}

/// One grant row as the store holds it: `(task, digest, expiry, state)`.
fn grant_row(root: &Path, grant_id: &str) -> (String, String, i64, String) {
    database(root)
        .query_row(
            "SELECT task_id, token_digest, expires_at, state FROM sharing_grants WHERE grant_id = ?1",
            [grant_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .expect("the grant row is recorded")
}

fn grant_state(root: &Path, grant_id: &str) -> String {
    grant_row(root, grant_id).3
}

fn count(root: &Path, statement: &str) -> u64 {
    let count: i64 = database(root)
        .query_row(statement, [], |row| row.get(0))
        .expect("the count reads");
    u64::try_from(count).expect("a row count is non-negative")
}

/// Every byte the store keeps: the database and both WAL sidecars.
fn store_bytes(root: &Path) -> Vec<u8> {
    let runtime = root.join("runtime");
    let mut bytes = std::fs::read(runtime.join("rivect.db")).expect("store bytes");
    for sidecar in ["rivect.db-wal", "rivect.db-shm"] {
        if let Ok(extra) = std::fs::read(runtime.join(sidecar)) {
            bytes.extend_from_slice(&extra);
        }
    }
    bytes
}

fn socket_paths(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(directory) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path
                .extension()
                .is_some_and(|extension| extension == "sock")
            {
                found.push(path);
            }
        }
    }
    found
}

fn error_code(response: &Value) -> &str {
    response["error"]["data"]["code"]
        .as_str()
        .expect("the refusal carries its typed code")
}

fn error_text(response: &Value) -> String {
    response["error"]["data"]["message"]
        .as_str()
        .expect("the refusal carries its message")
        .to_string()
}

#[test]
fn sharing_grant_open_returns_plaintext_once_and_stores_only_the_digest() {
    let mut fixture = Fixture::new("sd");
    let opened = fixture.open(None);
    let token = token_of(&opened);
    let grant_id = grant_id_of(&opened);

    assert_eq!(token.len(), 64, "the token is 256 bits rendered as hex");
    assert!(token.bytes().all(|byte| byte.is_ascii_hexdigit()));

    let socket = socket_of(&opened);
    assert!(
        Path::new(&socket).starts_with(&fixture.world.root),
        "the listener lives under the user data root"
    );
    let mode = std::fs::metadata(&socket)
        .expect("the socket exists")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600, "the socket is owner-only");

    let (task_id, digest, expires_at, state) = grant_row(&fixture.world.root, &grant_id);
    assert_eq!(task_id, fixture.task.0);
    assert_eq!(digest, sha256_hex(&token), "only the digest is stored");
    assert_ne!(digest, token);
    assert!(expires_at > 0);
    assert_eq!(state, "open");
    assert!(
        !store_bytes(&fixture.world.root)
            .windows(token.len())
            .any(|window| window == token.as_bytes()),
        "the plaintext token never reaches the store"
    );

    // A second open mints a different grant; the first token is never
    // served again by any method.
    let second = fixture.open(None);
    assert_ne!(token_of(&second), token);
    let attached = fixture.world.dispatch(&rpc(
        "sharing.attach",
        json!({"schema_version": 1, "token": token}),
    ));
    assert!(
        attached.get("error").is_none(),
        "the token attaches: {attached}"
    );
    assert!(
        attached["result"].get("token").is_none(),
        "the attach answer never carries the plaintext"
    );
    assert!(fixture.status().to_string().find(&token).is_none());
}

#[test]
fn no_socket_exists_without_a_grant() {
    let mut fixture = Fixture::new("ns");
    assert!(
        socket_paths(&fixture.world.root).is_empty(),
        "a world without a grant binds no socket"
    );
    assert!(
        UnixStream::connect(fixture.world.root.join("sharing/probe.sock")).is_err(),
        "no listener answers before the opt-in"
    );

    let opened = fixture.open(None);
    let socket = socket_of(&opened);
    assert_eq!(socket_paths(&fixture.world.root).len(), 1);

    let revoked = fixture.revoke(&grant_id_of(&opened));
    assert_eq!(revoked["state"], "revoked");
    assert!(
        !Path::new(&socket).exists(),
        "revoke removes the listener path"
    );
    assert!(socket_paths(&fixture.world.root).is_empty());
    assert!(
        UnixStream::connect(&socket).is_err(),
        "a revoked grant accepts no connection"
    );
}

#[test]
fn observer_attach_without_a_grant_is_denied() {
    let mut world = support::open_world("na", None);
    let token = "ab".repeat(32);
    let response = world.dispatch(&rpc(
        "sharing.attach",
        json!({"schema_version": 1, "token": token}),
    ));
    assert_eq!(error_code(&response), "denied");
    assert_eq!(
        count(&world.root, "SELECT COUNT(*) FROM sharing_grants"),
        0,
        "no grant row was invented by the attempt"
    );
    assert_eq!(
        count(&world.root, "SELECT COUNT(*) FROM attachments"),
        0,
        "no observer attachment row exists"
    );
    assert!(
        socket_paths(&world.root).is_empty(),
        "no admission is possible without a grant"
    );
}

#[test]
fn observer_unknown_token_is_denied() {
    let mut fixture = Fixture::new("nu");
    let opened = fixture.open(None);
    let socket = socket_of(&opened);
    let mut observer = Observer::connect(&socket);
    let response = observer.send(
        &mut fixture.world,
        &rpc(
            "sharing.attach",
            json!({"schema_version": 1, "token": "cd".repeat(32)}),
        ),
    );
    assert_eq!(error_code(&response), "denied");
    observer.expect_closed();
    assert!(
        Path::new(&socket).exists(),
        "a wrong token does not close the grant"
    );
    assert_eq!(
        count(&fixture.world.root, "SELECT COUNT(*) FROM sharing_grants"),
        1
    );

    // The real token still attaches: the failed attempt consumed nothing.
    let mut observer = Observer::connect(&socket);
    let attached = observer.send(
        &mut fixture.world,
        &rpc(
            "sharing.attach",
            json!({"schema_version": 1, "token": token_of(&opened)}),
        ),
    );
    assert!(attached.get("error").is_none(), "attach failed: {attached}");
}

#[test]
fn observer_attach_reads_only_allowlisted_methods() {
    let mut fixture = Fixture::new("ra");
    let opened = fixture.open(None);
    let mut observer = attach_over_socket(&mut fixture, &opened);
    let requests = [
        status_request(&fixture.session),
        snapshot_request(&fixture.session, &fixture.task),
        collection_request(&fixture.session, &fixture.task),
        rpc("command.describe", json!({"schema_version": 1})),
    ];
    for request in requests {
        let method = request["method"].as_str().unwrap();
        let response = observer.send(&mut fixture.world, &request);
        assert!(
            response.get("error").is_none(),
            "allowed read {method} refused: {response}"
        );
        match method {
            "runtime.status" => {
                assert_eq!(response["result"]["session_id"], fixture.session.0);
            }
            "task.snapshot" => {
                assert_eq!(response["result"]["task_id"], fixture.task.0);
            }
            "task.collection" => {
                assert!(response["result"]["items"].is_array());
                assert!(response["result"]["snapshot_generation"].is_u64());
            }
            _ => {
                assert!(response["result"]["items"].is_array());
            }
        }
    }
}

#[test]
fn socket_reattach_replaces_the_attachment_and_still_reads() {
    let mut fixture = Fixture::new("re");
    let opened = fixture.open(None);
    let mut observer = attach_over_socket(&mut fixture, &opened);
    let first = observer.send(
        &mut fixture.world,
        &rpc(
            "sharing.attach",
            json!({"schema_version": 1, "token": token_of(&opened)}),
        ),
    );
    assert!(
        first.get("error").is_none(),
        "second attach failed: {first}"
    );
    let second = observer.send(
        &mut fixture.world,
        &rpc(
            "sharing.attach",
            json!({"schema_version": 1, "token": token_of(&opened)}),
        ),
    );
    // The connection holds one live attachment: the newest id, still the
    // grant's own read-only contract.
    assert_ne!(
        first["result"]["attachment_id"],
        second["result"]["attachment_id"]
    );
    assert_eq!(second["result"]["mode"], "read_only");
    assert_eq!(second["result"]["session_id"], fixture.session.0);
    assert_eq!(second["result"]["task_id"], fixture.task.0);

    let status = observer.send(&mut fixture.world, &status_request(&fixture.session));
    assert!(
        status.get("error").is_none(),
        "the replaced attachment still reads: {status}"
    );
    assert_eq!(status["result"]["session_id"], fixture.session.0);
}

#[test]
fn observer_cannot_steer_approve_execute_or_publish() {
    let mut fixture = Fixture::new("st");
    let opened = fixture.open(None);
    let mut observer = attach_over_socket(&mut fixture, &opened);

    let tasks_before = count(&fixture.world.root, "SELECT COUNT(*) FROM tasks");
    let config_path = fixture.world.root.join("config.toml");
    let denials = [
        rpc(
            "session.open",
            json!({"schema_version": 1, "bootstrap_id": "observer-boot"}),
        ),
        rpc(
            "session.attach",
            json!({"schema_version": 1, "bootstrap_id": "observer-boot"}),
        ),
        rpc(
            "session.close",
            json!({"schema_version": 1, "session_id": fixture.session.0}),
        ),
        rpc(
            "task.submit",
            json!({
                "schema_version": 1,
                "session_id": fixture.session.0,
                "command_id": "observer-submit",
                "kind": "steer",
                "task_id": fixture.task.0,
                "text": "observer steer",
            }),
        ),
        rpc(
            "command.execute",
            json!({
                "schema_version": 1,
                "session_id": fixture.session.0,
                "command": {"kind": "config.set"},
                "key": "workflow",
                "value": "off",
            }),
        ),
    ];
    for request in denials {
        let method = request["method"].as_str().unwrap();
        let response = observer.send(&mut fixture.world, &request);
        assert_eq!(error_code(&response), "denied", "{method} must be denied");
        assert!(
            response.get("result").is_none(),
            "{method} produced a result"
        );
    }

    assert_eq!(
        count(&fixture.world.root, "SELECT COUNT(*) FROM tasks"),
        tasks_before,
        "an observer cannot publish or start a task"
    );
    assert!(
        !config_path.exists(),
        "an observer cannot execute a config edit"
    );
    assert_eq!(
        count(
            &fixture.world.root,
            "SELECT COUNT(*) FROM usage_settlements"
        ),
        0,
        "no steer or execute reached the ledger"
    );

    // The attachment stays a reader: the deny gate ran before the method
    // body, not by tearing the connection down.
    let status = observer.send(&mut fixture.world, &status_request(&fixture.session));
    assert!(status.get("error").is_none());
}

#[test]
fn observer_cannot_export_events_or_artifacts() {
    let mut fixture = Fixture::new("ex");
    let opened = fixture.open(None);
    let mut observer = attach_over_socket(&mut fixture, &opened);

    let denials = [
        rpc(
            "events.read",
            json!({
                "schema_version": 1,
                "session_id": fixture.session.0,
                "task_id": fixture.task.0,
            }),
        ),
        rpc(
            "artifact.read",
            json!({"schema_version": 1, "artifact_id": "any"}),
        ),
        rpc(
            "config.read",
            json!({"schema_version": 1, "session_id": fixture.session.0, "keys": ["workflow"]}),
        ),
    ];
    for request in denials {
        let method = request["method"].as_str().unwrap();
        let response = observer.send(&mut fixture.world, &request);
        assert_eq!(error_code(&response), "denied", "{method} must be denied");
        assert!(
            response.get("result").is_none(),
            "{method} exported a transcript or config"
        );
    }
}

#[test]
fn observer_frames_are_bound_to_the_grant_scope() {
    let mut fixture = Fixture::new("sc");
    let other_session = fixture.world.open_session("sc-other-boot");
    let other_task = fixture.world.create_task(&other_session, "sc-other-task");
    let opened = fixture.open(None);
    let mut observer = attach_over_socket(&mut fixture, &opened);

    let foreign_session = observer.send(&mut fixture.world, &status_request(&other_session));
    assert_eq!(error_code(&foreign_session), "denied");
    assert!(foreign_session.get("result").is_none());

    let foreign_task = observer.send(
        &mut fixture.world,
        &snapshot_request(&fixture.session, &other_task),
    );
    assert_eq!(error_code(&foreign_task), "denied");
    assert!(foreign_task.get("result").is_none());

    // A frame with no ids is served inside the grant's own scope.
    let bound = observer.send(
        &mut fixture.world,
        &rpc("task.snapshot", json!({"schema_version": 1})),
    );
    assert_eq!(bound["result"]["task_id"], fixture.task.0);
    let bound_status = observer.send(
        &mut fixture.world,
        &rpc("runtime.status", json!({"schema_version": 1})),
    );
    assert_eq!(bound_status["result"]["session_id"], fixture.session.0);
}

#[test]
fn observer_request_before_attach_is_denied() {
    let mut fixture = Fixture::new("pa");
    let opened = fixture.open(None);
    let mut observer = Observer::connect(&socket_of(&opened));
    let response = observer.send(&mut fixture.world, &status_request(&fixture.session));
    assert_eq!(error_code(&response), "denied");
    assert!(response.get("result").is_none());
    observer.expect_closed();
}

#[test]
fn observer_invalid_frame_is_refused() {
    let mut fixture = Fixture::new("if");
    let opened = fixture.open(None);
    let mut observer = attach_over_socket(&mut fixture, &opened);
    writeln!(observer.writer, "{{\"jsonrpc\":\"2.0\"").expect("invalid frame write");
    observer.writer.flush().expect("invalid frame flush");
    pump(&mut fixture.world);
    let response = observer.read();
    assert_eq!(error_code(&response), "invalid_input");
    assert!(response.get("result").is_none());
    observer.expect_closed();
}

#[test]
fn observer_oversize_frame_is_refused() {
    let mut fixture = Fixture::new("ov");
    let opened = fixture.open(None);
    let mut observer = attach_over_socket(&mut fixture, &opened);
    let mut writer = observer.writer.try_clone().expect("oversize client clone");
    let payload = vec![b'x'; rivect::contracts::REQUEST_MAX_BYTES + 1];
    let sender = std::thread::spawn(move || {
        // The peer is closed once the cap is seen; a refused write is the
        // expected end of this fixture, not a failure.
        if let Err(error) = writer.write_all(&payload) {
            drop(error);
        }
    });
    while !sender.is_finished() {
        fixture.world.runtime.serve_sharing();
        std::thread::yield_now();
    }
    sender.join().expect("oversize writer joins");
    fixture.world.runtime.serve_sharing();
    let response = observer.read();
    assert_eq!(error_code(&response), "invalid_input");
    assert!(response.get("result").is_none());
    observer.expect_closed();
}

#[test]
fn expired_grant_stops_access_without_renewal() {
    let mut fixture = Fixture::new("xp");
    let opened = fixture.open(Some(10));
    let expires_at = opened["expires_at"].as_i64().expect("expiry is served");
    assert_eq!(expires_at, 1_010);
    let token = token_of(&opened);
    let mut observer = attach_over_socket(&mut fixture, &opened);

    fixture.now.store(1_009, Ordering::SeqCst);
    let before = observer.send(&mut fixture.world, &status_request(&fixture.session));
    assert!(before.get("error").is_none(), "a live grant still reads");

    // A status refresh never extends the recorded deadline.
    assert_eq!(
        grant_row(&fixture.world.root, &grant_id_of(&opened)).2,
        expires_at
    );

    fixture.now.store(1_010, Ordering::SeqCst);
    let refused = observer.send(&mut fixture.world, &status_request(&fixture.session));
    assert_eq!(error_code(&refused), "denied");
    observer.expect_closed();
    let (_, _, stored_expiry, state) = grant_row(&fixture.world.root, &grant_id_of(&opened));
    assert_eq!(state, "expired", "expiry is terminal in the store");
    assert_eq!(stored_expiry, expires_at);
    assert!(
        !Path::new(&socket_of(&opened)).exists(),
        "expiry closes the listener"
    );

    // No renewal: later attempts stay refused and the row never reopens.
    fixture.now.store(9_999, Ordering::SeqCst);
    let retry = fixture.world.dispatch(&rpc(
        "sharing.attach",
        json!({"schema_version": 1, "token": token}),
    ));
    assert_eq!(error_code(&retry), "denied");
    assert_eq!(
        grant_row(&fixture.world.root, &grant_id_of(&opened)).3,
        "expired"
    );
    assert_eq!(
        grant_row(&fixture.world.root, &grant_id_of(&opened)).2,
        expires_at,
        "the deadline is never extended"
    );
}

#[test]
fn per_frame_clock_refuses_the_frame_after_expiry() {
    let mut fixture = Fixture::new("pf");
    let opened = fixture.open(Some(10));
    let mut observer = attach_over_socket(&mut fixture, &opened);

    // Both frames are buffered before the turn: the first is answered under
    // a pre-deadline clock, the second under a post-deadline one.
    observer.write(&status_request(&fixture.session));
    observer.write(&status_request(&fixture.session));
    let advancing = Arc::new(AtomicU64::new(1_009));
    let handle = Arc::clone(&advancing);
    fixture.world.runtime.work_clock = Box::new(move || handle.fetch_add(1, Ordering::SeqCst));

    pump(&mut fixture.world);
    let first = observer.read();
    assert!(first.get("error").is_none(), "pre-deadline frame: {first}");
    let second = observer.read();
    assert_eq!(error_code(&second), "denied");
    observer.expect_closed();
    assert_eq!(
        grant_state(&fixture.world.root, &grant_id_of(&opened)),
        "expired",
        "the mid-turn expiry is recorded"
    );
}

#[test]
fn revoked_grant_stops_access_and_closes_the_socket() {
    let mut fixture = Fixture::new("rv");
    let opened = fixture.open(None);
    let grant_id = grant_id_of(&opened);
    let socket = socket_of(&opened);
    let mut observer = attach_over_socket(&mut fixture, &opened);

    let revoked = fixture.revoke(&grant_id);
    assert_eq!(revoked["grant_id"], grant_id);
    assert_eq!(revoked["state"], "revoked");
    assert_eq!(
        grant_row(&fixture.world.root, &grant_id).3,
        "revoked",
        "the revoke is recorded once and terminally"
    );
    assert!(!Path::new(&socket).exists());
    assert!(UnixStream::connect(&socket).is_err());

    // A request that was already attached is refused before the method
    // body, then the connection closes.
    let refused = observer.send(&mut fixture.world, &status_request(&fixture.session));
    assert_eq!(error_code(&refused), "denied");
    observer.expect_closed();

    // The token is dead too, and a second revoke changes nothing.
    let retry = fixture.world.dispatch(&rpc(
        "sharing.attach",
        json!({"schema_version": 1, "token": token_of(&opened)}),
    ));
    assert_eq!(error_code(&retry), "denied");
    assert_eq!(fixture.revoke(&grant_id)["state"], "revoked");
}

#[test]
fn bounded_turn_lets_a_queued_revoke_land_behind_buffered_frames() {
    let mut fixture = Fixture::new("bq");
    let opened = fixture.open(None);
    let grant_id = grant_id_of(&opened);
    let mut observer = attach_over_socket(&mut fixture, &opened);

    // More frames than one serving turn may answer are already buffered when
    // the revoke is dispatched; the bounded turn returns, the revoke lands.
    for _ in 0..4 {
        observer.write(&status_request(&fixture.session));
    }
    let revoked = fixture.revoke(&grant_id);
    assert_eq!(revoked["state"], "revoked");
    assert_eq!(grant_state(&fixture.world.root, &grant_id), "revoked");
    assert!(!Path::new(&socket_of(&opened)).exists());

    // Whatever the pre-revoke turn served is already queued; the next frame
    // is refused. Read until the first denial instead of pinning the frame
    // budget the turn happened to spend.
    pump(&mut fixture.world);
    for _ in 0..6 {
        let response = observer.read();
        if response.get("error").is_some() {
            assert_eq!(error_code(&response), "denied");
            observer.expect_closed();
            return;
        }
    }
    panic!("the queued revoke never refused a buffered frame");
}

#[test]
fn refresh_does_not_extend_the_grant() {
    let mut fixture = Fixture::new("rf");
    let opened = fixture.open(Some(10));
    let grant_id = grant_id_of(&opened);
    let expires_at = opened["expires_at"].as_i64().expect("expiry is served");
    let mut observer = attach_over_socket(&mut fixture, &opened);

    for now in [1_001, 1_005, 1_009] {
        fixture.now.store(now, Ordering::SeqCst);
        let response = observer.send(&mut fixture.world, &status_request(&fixture.session));
        assert!(response.get("error").is_none(), "status at {now}");
        assert_eq!(
            grant_row(&fixture.world.root, &grant_id).2,
            expires_at,
            "a refresh at {now} extended the grant"
        );
    }

    fixture.now.store(
        u64::try_from(expires_at).expect("a positive expiry fits the clock"),
        Ordering::SeqCst,
    );
    let refused = observer.send(&mut fixture.world, &status_request(&fixture.session));
    assert_eq!(error_code(&refused), "denied");
}

#[test]
fn share_token_never_reaches_status_logs_or_errors() {
    let mut fixture = Fixture::new("tk");
    let opened = fixture.open(None);
    let token = token_of(&opened);

    let status = fixture.status();
    assert!(
        !status.to_string().contains(&token),
        "runtime.status leaked the token"
    );
    assert!(
        fixture
            .world
            .runtime
            .boot_diagnostics
            .iter()
            .all(|line| !line.contains(&token)),
        "a boot diagnostic leaked the token"
    );
    assert!(
        !socket_of(&opened).contains(&token),
        "the socket path carries data, never the token"
    );

    // A refusal frame on the socket never carries the token either.
    let mut observer = Observer::connect(&socket_of(&opened));
    let pre_attach = observer.send(&mut fixture.world, &status_request(&fixture.session));
    assert_eq!(error_code(&pre_attach), "denied");
    assert!(!pre_attach.to_string().contains(&token));

    let unknown = fixture.world.dispatch(&rpc(
        "sharing.attach",
        json!({"schema_version": 1, "token": "ef".repeat(32)}),
    ));
    assert_eq!(error_code(&unknown), "denied");
    assert!(
        !error_text(&unknown).contains(&token),
        "an attach refusal leaked the token"
    );
    assert!(
        !fixture.revoke(&grant_id_of(&opened))["state"]
            .as_str()
            .unwrap()
            .contains(&token)
    );
    let closed = fixture.world.dispatch(&rpc(
        "sharing.attach",
        json!({"schema_version": 1, "token": token}),
    ));
    assert_eq!(error_code(&closed), "denied");
    assert!(!error_text(&closed).contains(&token));
    assert!(
        !store_bytes(&fixture.world.root)
            .windows(token.len())
            .any(|window| window == token.as_bytes()),
        "the token is never at rest"
    );
}

/// One settled send with exact bins, so the shared ledger has a non-empty
/// projection before the observer reads it.
fn seed_settlement(fixture: &mut Fixture) {
    let config = fixture.world.runtime.config_for_broker();
    let manifest = fixture
        .world
        .runtime
        .broker
        .prepare(
            "backend_task",
            &config,
            "/world/sharing-ledger",
            "goal: observer ledger projection",
        )
        .expect("the ledger manifest prepares");
    fixture
        .world
        .runtime
        .store_writer()
        .open_budget(&fixture.task.0, 100)
        .expect("the ledger scope opens");
    let context = SendContext {
        purpose: "backend_task".to_string(),
        connection: "local".to_string(),
        parent_attempt_id: None,
        ranking_basis: None,
    };
    let ticket = fixture
        .world
        .runtime
        .store_writer()
        .begin_send(&[fixture.task.0.as_str()], &context, &manifest)
        .expect("the send opens its dispatched row");
    fixture
        .world
        .runtime
        .store_writer()
        .finish_send(
            &ticket,
            &SendOutcome::Settled {
                usage: UsageDelta::Exact {
                    prompt_tokens: 7,
                    completion_tokens: 3,
                    total_tokens: 10,
                },
                wire_retries: 0,
            },
        )
        .expect("the send settles");
    fixture
        .world
        .runtime
        .refresh_economy(None)
        .expect("the economy projection refreshes");
}

#[test]
fn observer_session_uses_the_shared_ledger() {
    let mut fixture = Fixture::with_config("ld", Some(&local_config()));
    seed_settlement(&mut fixture);
    let sessions_before = count(&fixture.world.root, "SELECT COUNT(*) FROM sessions");
    let attachments_before = count(&fixture.world.root, "SELECT COUNT(*) FROM attachments");
    let scopes_before = count(&fixture.world.root, "SELECT COUNT(*) FROM budget_scopes");
    let settlements_before = count(
        &fixture.world.root,
        "SELECT COUNT(*) FROM usage_settlements",
    );
    let spent_before = count(
        &fixture.world.root,
        "SELECT COALESCE(SUM(charged_units), 0) FROM usage_settlements WHERE state = 'settled'",
    );
    assert_eq!(
        settlements_before, 1,
        "the seeded send recorded one settlement"
    );
    assert!(
        spent_before > 0,
        "the seeded send charged the shared ledger"
    );

    let opened = fixture.open(None);
    let mut observer = attach_over_socket(&mut fixture, &opened);
    let observer_status = observer.send(&mut fixture.world, &status_request(&fixture.session));
    assert!(observer_status.get("error").is_none());
    let local_status = fixture.status();
    let observed = &observer_status["result"]["economy"];
    assert_eq!(
        observed["settled_tokens"],
        json!(10),
        "the observer reads the settled token total, not an empty projection"
    );
    assert!(
        observed["charged_units"].as_u64().is_some(),
        "the observer reads the charged units, not an empty projection"
    );
    assert_eq!(
        observed, &local_status["result"]["economy"],
        "the observer reads the one shared ledger projection"
    );

    let snapshot = observer.send(
        &mut fixture.world,
        &snapshot_request(&fixture.session, &fixture.task),
    );
    assert!(snapshot.get("error").is_none());
    let collection = observer.send(
        &mut fixture.world,
        &collection_request(&fixture.session, &fixture.task),
    );
    assert!(collection.get("error").is_none());

    assert_eq!(observer_status["result"]["session_id"], fixture.session.0);
    assert_eq!(
        count(&fixture.world.root, "SELECT COUNT(*) FROM sessions"),
        sessions_before,
        "the observer opened no session"
    );
    assert_eq!(
        count(&fixture.world.root, "SELECT COUNT(*) FROM attachments"),
        attachments_before,
        "the observer writes no attachment row"
    );
    assert_eq!(
        count(&fixture.world.root, "SELECT COUNT(*) FROM budget_scopes"),
        scopes_before,
        "the observer created no ledger scope"
    );
    assert_eq!(
        count(
            &fixture.world.root,
            "SELECT COUNT(*) FROM usage_settlements"
        ),
        settlements_before,
        "the observer wrote no settlement"
    );
    assert_eq!(
        count(&fixture.world.root, "SELECT COUNT(*) FROM sharing_grants"),
        1,
        "the grant is the only row the surface writes"
    );
}

#[test]
fn grant_open_refuses_a_task_from_another_session() {
    let mut fixture = Fixture::new("gs");
    let other_session = fixture.world.open_session("gs-other-boot");
    let other_task = fixture.world.create_task(&other_session, "gs-other-task");
    let response = fixture.world.dispatch(&rpc(
        "sharing.grant.open",
        json!({
            "schema_version": 1,
            "session_id": fixture.session.0,
            "task_id": other_task.0,
        }),
    ));
    assert_eq!(error_code(&response), "not_found");
    assert_eq!(
        count(&fixture.world.root, "SELECT COUNT(*) FROM sharing_grants"),
        0,
        "a cross-session grant records no row"
    );
    assert!(
        socket_paths(&fixture.world.root).is_empty(),
        "no listener is left behind by the refused open"
    );
}

#[test]
fn grant_open_accepts_the_max_ttl_and_refuses_out_of_range() {
    let mut fixture = Fixture::new("tt");
    for ttl in [0, 86_401, 1_000_000] {
        let response = fixture.world.dispatch(&rpc(
            "sharing.grant.open",
            json!({
                "schema_version": 1,
                "session_id": fixture.session.0,
                "task_id": fixture.task.0,
                "ttl_seconds": ttl,
            }),
        ));
        assert_eq!(error_code(&response), "invalid_input", "ttl {ttl}");
    }
    assert_eq!(
        count(&fixture.world.root, "SELECT COUNT(*) FROM sharing_grants"),
        0
    );
    assert!(socket_paths(&fixture.world.root).is_empty());

    // The documented maximum is accepted and recorded verbatim.
    let opened = fixture.open(Some(rivect::commands::sharing::MAX_GRANT_SECONDS));
    assert_eq!(
        opened["expires_at"],
        json!(OPEN + rivect::commands::sharing::MAX_GRANT_SECONDS)
    );
    assert_eq!(
        count(&fixture.world.root, "SELECT COUNT(*) FROM sharing_grants"),
        1
    );
    assert_eq!(socket_paths(&fixture.world.root).len(), 1);
}

#[test]
fn attach_refuses_a_missing_or_unshaped_token() {
    let mut fixture = Fixture::new("ut");
    let opened = fixture.open(None);
    let missing = fixture
        .world
        .dispatch(&rpc("sharing.attach", json!({"schema_version": 1})));
    assert_eq!(error_code(&missing), "invalid_input");

    for token in ["zz".to_string(), "ab".repeat(31), "gh".repeat(32)] {
        let response = fixture.world.dispatch(&rpc(
            "sharing.attach",
            json!({"schema_version": 1, "token": token}),
        ));
        assert_eq!(error_code(&response), "denied", "token {token}");
    }
    assert_eq!(
        count(&fixture.world.root, "SELECT COUNT(*) FROM sharing_grants"),
        1,
        "the refusals consumed no grant"
    );
    assert!(Path::new(&socket_of(&opened)).exists());
}

#[test]
fn revoke_refuses_an_unknown_grant_and_corrupt_state() {
    let mut fixture = Fixture::new("ug");
    let unknown = fixture.world.dispatch(&rpc(
        "sharing.grant.revoke",
        json!({"schema_version": 1, "session_id": fixture.session.0, "grant_id": "absent"}),
    ));
    assert_eq!(error_code(&unknown), "not_found");

    let opened = fixture.open(None);
    let grant_id = grant_id_of(&opened);
    database(&fixture.world.root)
        .execute(
            "UPDATE sharing_grants SET state = 'bogus' WHERE grant_id = ?1",
            [&grant_id],
        )
        .expect("the corrupt row writes");
    let corrupt = fixture.world.dispatch(&rpc(
        "sharing.grant.revoke",
        json!({"schema_version": 1, "session_id": fixture.session.0, "grant_id": grant_id}),
    ));
    assert_eq!(error_code(&corrupt), "storage_unavailable");
}

#[test]
fn grant_open_and_revoke_allow_machine_and_deny_observer() {
    let mut fixture = Fixture::new("in");
    // The stdio CLI's machine ingress is the same local user over the same
    // data root, so it may manage a grant.
    let machine_open = fixture.world.dispatch_machine(&rpc(
        "sharing.grant.open",
        json!({
            "schema_version": 1,
            "session_id": fixture.session.0,
            "task_id": fixture.task.0,
        }),
    ));
    assert!(
        machine_open.get("error").is_none(),
        "machine open refused: {machine_open}"
    );
    let grant_id = machine_open["result"]["grant_id"]
        .as_str()
        .expect("machine open returns the grant")
        .to_string();
    assert_eq!(
        count(&fixture.world.root, "SELECT COUNT(*) FROM sharing_grants"),
        1
    );
    assert_eq!(socket_paths(&fixture.world.root).len(), 1);

    let machine_revoke = fixture.world.dispatch_machine(&rpc(
        "sharing.grant.revoke",
        json!({
            "schema_version": 1,
            "session_id": fixture.session.0,
            "grant_id": grant_id,
        }),
    ));
    assert!(
        machine_revoke.get("error").is_none(),
        "machine revoke refused: {machine_revoke}"
    );
    assert_eq!(machine_revoke["result"]["state"], "revoked");
    assert!(socket_paths(&fixture.world.root).is_empty());

    // The socket observer is the untrusted read boundary and may never manage
    // a grant, on either method.
    let observer_requests = [
        (
            "sharing.grant.open",
            json!({
                "schema_version": 1,
                "session_id": fixture.session.0,
                "task_id": fixture.task.0,
            }),
        ),
        (
            "sharing.grant.revoke",
            json!({
                "schema_version": 1,
                "session_id": fixture.session.0,
                "grant_id": grant_id,
            }),
        ),
    ];
    for (method, params) in observer_requests {
        let response = rivect::commands::dispatch_runtime_request(
            &mut fixture.world.runtime,
            Ingress::Observer,
            "observer-direct",
            &rpc(method, params).to_string(),
        );
        let response: Value = serde_json::from_str(&response).expect("the refusal is JSON");
        assert_eq!(error_code(&response), "denied", "{method}");
        assert!(
            error_text(&response).contains("not available to an observer"),
            "{method} names the observer boundary: {response}"
        );
        assert!(response.get("result").is_none());
    }
}

#[test]
fn dispatch_turns_pump_the_share_surface() {
    let mut fixture = Fixture::new("dp");
    let opened = fixture.open(None);
    let mut observer = Observer::connect(&socket_of(&opened));

    // No explicit serve call: the local dispatch pumps the attach frame.
    observer.write(&rpc(
        "sharing.attach",
        json!({"schema_version": 1, "token": token_of(&opened)}),
    ));
    let local = fixture.status();
    assert!(local.get("error").is_none());
    let attached = observer.read();
    assert!(attached.get("error").is_none(), "attach failed: {attached}");

    // `dispatch_step` pumps the same surface for a loop turn.
    observer.write(&status_request(&fixture.session));
    let local_request = status_request(&fixture.session).to_string();
    let step = rivect::commands::dispatch_step(
        &mut fixture.world.runtime,
        Ingress::TrustedHuman,
        "test-loop",
        &local_request,
    );
    assert!(matches!(step, DispatchStep::Ready(_)));
    let served = observer.read();
    assert_eq!(served["result"]["session_id"], fixture.session.0);
}

#[test]
fn observer_ingress_denies_answer_and_steer_at_the_dispatch_gate() {
    let mut fixture = Fixture::new("ob");
    let question = fixture.world.publish(&fixture.session, &fixture.task);
    let requests = [
        rpc(
            "task.submit",
            json!({
                "schema_version": 1,
                "session_id": fixture.session.0,
                "command_id": "observer-answer",
                "kind": "answer",
                "task_id": fixture.task.0,
                "question_id": question.question_id.0,
                "question_revision": question.question_revision,
                "selection": {"kind": "custom", "text": "observer answer"},
            }),
        ),
        rpc(
            "task.submit",
            json!({
                "schema_version": 1,
                "session_id": fixture.session.0,
                "command_id": "observer-steer",
                "kind": "steer",
                "task_id": fixture.task.0,
                "text": "observer steer",
            }),
        ),
    ];
    for request in requests {
        let response = rivect::commands::dispatch_runtime_request(
            &mut fixture.world.runtime,
            Ingress::Observer,
            "observer-direct",
            &request.to_string(),
        );
        let response: Value = serde_json::from_str(&response).expect("the refusal is JSON");
        assert_eq!(error_code(&response), "denied");
        assert!(
            error_text(&response).contains("not available to an observer"),
            "the dispatcher gate names the observer boundary: {response}"
        );
        assert!(response.get("result").is_none());
    }
    // The gate runs before any handler: neither attempt moved a row.
    assert_eq!(
        count(
            &fixture.world.root,
            "SELECT COUNT(*) FROM answer_attempts WHERE outcome = 'denied'"
        ),
        0,
        "the gate refused before the answer handler could journal"
    );
    assert_eq!(
        count(&fixture.world.root, "SELECT COUNT(*) FROM tasks"),
        1,
        "no task was created or steered"
    );
}

#[test]
fn sharing_terminal_transitions_are_idempotent_or_conflicting() {
    let mut fixture = Fixture::new("ts");
    let expired_open = fixture.open(Some(10));
    let expired_id = grant_id_of(&expired_open);
    let expires_at = u64::try_from(
        expired_open["expires_at"]
            .as_i64()
            .expect("expiry is served"),
    )
    .expect("a positive expiry fits the clock");
    let expired = fixture
        .world
        .runtime
        .store_writer()
        .expire_sharing_grant(&expired_id, expires_at)
        .expect("the first expiry transitions");
    assert_eq!(expired.state, SharingGrantState::Expired);
    match fixture
        .world
        .runtime
        .store_writer()
        .expire_sharing_grant(&expired_id, expires_at)
    {
        Err(StoreError::Conflict(ConflictCause::SharingGrantClosed { state, .. })) => {
            assert_eq!(state, "expired", "the conflict names the terminal state");
        }
        other => panic!("a second expiry must conflict, got {other:?}"),
    }

    let failed_open = fixture.open(None);
    let failed_id = grant_id_of(&failed_open);
    let failed = fixture
        .world
        .runtime
        .store_writer()
        .fail_sharing_grant(&failed_id)
        .expect("the accept-fault transition records failed");
    assert_eq!(failed.state, SharingGrantState::Failed);
    let again = fixture
        .world
        .runtime
        .store_writer()
        .fail_sharing_grant(&failed_id)
        .expect("a terminal row is returned unchanged");
    assert_eq!(again.state, SharingGrantState::Failed);
    assert_eq!(grant_state(&fixture.world.root, &failed_id), "failed");
}

#[test]
fn connection_cap_closes_the_surplus_peer() {
    let mut fixture = Fixture::new("cp");
    let opened = fixture.open(None);
    let socket = socket_of(&opened);
    let mut peers: Vec<Observer> = (0..=rivect::commands::sharing::MAX_CONNECTIONS)
        .map(|_| Observer::connect(&socket))
        .collect();
    // One turn accepts up to the cap, closes the surplus and returns.
    fixture.world.runtime.serve_sharing();
    peers[rivect::commands::sharing::MAX_CONNECTIONS].expect_closed();
    // An admitted peer is live and can attach.
    let attached = peers[0].send(
        &mut fixture.world,
        &rpc(
            "sharing.attach",
            json!({"schema_version": 1, "token": token_of(&opened)}),
        ),
    );
    assert!(attached.get("error").is_none(), "attach failed: {attached}");
}

#[test]
fn leftover_open_grants_are_failed_on_reopen() {
    let mut fixture = Fixture::new("ro");
    let opened = fixture.open(None);
    let grant_id = grant_id_of(&opened);
    assert_eq!(grant_state(&fixture.world.root, &grant_id), "open");

    fixture.world.reopen();
    assert_eq!(
        grant_state(&fixture.world.root, &grant_id),
        "failed",
        "a row left open beside a dead listener reads failed after reopen"
    );
    assert!(
        socket_paths(&fixture.world.root).is_empty(),
        "no listener survived the process"
    );
}

#[test]
fn revoke_refuses_another_sessions_grant() {
    let mut fixture = Fixture::new("xs");
    let other_session = fixture.world.open_session("xs-other-boot");
    let opened = fixture.open(None);
    let grant_id = grant_id_of(&opened);
    let foreign = fixture.world.dispatch(&rpc(
        "sharing.grant.revoke",
        json!({
            "schema_version": 1,
            "session_id": other_session.0,
            "grant_id": grant_id,
        }),
    ));
    assert_eq!(error_code(&foreign), "not_found");
    assert_eq!(
        grant_state(&fixture.world.root, &grant_id),
        "open",
        "another session cannot revoke the grant"
    );
    assert_eq!(fixture.revoke(&grant_id)["state"], "revoked");
}

#[test]
fn socket_attach_refuses_a_foreign_schema_version() {
    let mut fixture = Fixture::new("sv");
    let opened = fixture.open(None);
    let socket = socket_of(&opened);
    for params in [
        json!({"schema_version": 2, "token": token_of(&opened)}),
        json!({"token": token_of(&opened)}),
    ] {
        let mut observer = Observer::connect(&socket);
        let response = observer.send(&mut fixture.world, &rpc("sharing.attach", params));
        assert_eq!(error_code(&response), "invalid_input");
        assert!(response.get("result").is_none());
        observer.expect_closed();
    }
    // The refusals consumed nothing: the grant still attaches under schema 1.
    let _observer = attach_over_socket(&mut fixture, &opened);
}
