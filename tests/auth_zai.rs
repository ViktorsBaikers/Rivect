//! Z.AI coding-plan sign-in proof (AC-008): state, the manual callback, the
//! short-lived token exchange, business login, customer info, the default
//! organization/project selection, find-or-create of the `rivect` key, the
//! copied secret, the canonical `zai` profile and its reader — against
//! loopback contract peers only. Every negative pins its request counter, so
//! a cancellation, stale callback, indeterminate issuance, failed create-only
//! write, foreign key or PAYG attempt cannot mint a second key, touch another
//! profile's bytes or substitute the wrong endpoint.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::let_underscore_must_use,
    let_underscore_drop,
    clippy::redundant_clone,
    reason = "test code keeps unwrap/expect/panic/discard conveniences; src/ stays strict (standards §14)"
)]

mod support;

use rivect::config::{Config, ConnKind};
use rivect::providers::zai_login::{self, LoginError as ZaiError, ZaiEndpoints};
use rivect::providers::{CredentialStore, ProviderError, SecretRef, StoreKind};
use serde_json::{Value, json};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

const ZAI_CONNECTION: &str = "zai-coding-plan";
const ZAI_SCOPE: &str = "keychain:rivect-test/zai";
const OTHER_SCOPE: &str = "keychain:rivect-test/kimi-code";
const PRIOR_PROFILE: &str = r#"{"api_key":"prior","secret_key":"prior-secret"}"#;
const OTHER_PROFILE: &str = r#"{"api_key":"other","secret_key":"other-secret"}"#;

/// One request a contract peer received.
#[derive(Clone)]
struct Seen {
    line: String,
    head: String,
    body: String,
}

/// A scripted loopback peer: one JSON answer per request. A plain `std`
/// listener keeps the blocking producer off a Tokio context.
struct Peer {
    base: String,
    seen: Arc<Mutex<Vec<Seen>>>,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Peer {
    fn start(answer: impl Fn(&Seen) -> (u16, String) + Send + Sync + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback peer");
        listener
            .set_nonblocking(true)
            .expect("nonblocking loopback peer");
        let base = format!("http://{}", listener.local_addr().expect("peer address"));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&seen);
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let handle = std::thread::spawn(move || {
            while !flag.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _address)) => {
                        // Darwin inherits the listener's nonblocking flag on accept.
                        stream.set_nonblocking(false).expect("peer blocking mode");
                        stream
                            .set_read_timeout(Some(Duration::from_secs(5)))
                            .expect("peer read timeout");
                        let Some(request) = read_request(&mut stream) else {
                            continue;
                        };
                        recorded.lock().expect("seen lock").push(request.clone());
                        let (status, payload) = answer(&request);
                        let reason = if status == 200 { "OK" } else { "Error" };
                        let response = format!(
                            "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\n\
                             Content-Length: {}\r\nConnection: close\r\n\r\n{payload}",
                            payload.len()
                        );
                        stream
                            .write_all(response.as_bytes())
                            .expect("peer writes its answer");
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::park_timeout(Duration::from_millis(5));
                    }
                    Err(_error) => break,
                }
            }
        });
        Self {
            base,
            seen,
            stop,
            handle: Some(handle),
        }
    }

    fn requests(&self) -> Vec<Seen> {
        self.seen.lock().expect("seen lock").clone()
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn read_request(stream: &mut std::net::TcpStream) -> Option<Seen> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        let read = stream.read(&mut chunk).ok()?;
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            break position;
        }
    };
    let head = String::from_utf8_lossy(&buffer[..head_end]).to_string();
    let length = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    let body_start = head_end + 4;
    while buffer.len() < body_start + length {
        let read = stream.read(&mut chunk).ok()?;
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
    Some(Seen {
        line: head.lines().next()?.to_string(),
        head,
        body: String::from_utf8_lossy(&buffer[body_start..buffer.len()]).to_string(),
    })
}

/// One response per recorded leg, routed by request line.
struct Script {
    token: (u16, String),
    login: (u16, String),
    customer: (u16, String),
    keys: (u16, String),
    create: (u16, String),
    copy: (u16, String),
}

impl Script {
    fn success() -> Self {
        Self {
            token: token_envelope(json!({
                "zai": { "access_token": "oauth-access-token" },
                "user": { "email": "user@example.com", "id": "user-42" }
            })),
            login: biz_envelope(json!({ "access_token": "biz-token", "expires_in": 3600 })),
            customer: biz_envelope(json!({
                "organizations": [{
                    "organizationId": "org-1",
                    "isDefault": true,
                    "projects": [{ "projectId": "proj-1", "isDefault": true }]
                }]
            })),
            keys: biz_envelope(json!([])),
            create: biz_envelope(json!({
                "name": "rivect",
                "apiKey": "created-key",
                "secretKey": "inline-ignored"
            })),
            copy: biz_envelope(json!({ "apiKey": "created-key", "secretKey": "real-secret" })),
        }
    }

    fn answer(&self, seen: &Seen) -> (u16, String) {
        let line = seen.line.as_str();
        if line.starts_with("POST /api/v1/oauth/token ") {
            return self.token.clone();
        }
        if line.starts_with("POST /api/auth/z/login ") {
            return self.login.clone();
        }
        if line.starts_with("GET /api/biz/customer/getCustomerInfo ") {
            return self.customer.clone();
        }
        if line.contains("/api_keys/copy/") {
            return self.copy.clone();
        }
        if line.starts_with("POST ") && line.contains("/api_keys ") {
            return self.create.clone();
        }
        if line.starts_with("GET ") && line.contains("/api_keys ") {
            return self.keys.clone();
        }
        (404, "{}".to_string())
    }
}

fn token_envelope(data: Value) -> (u16, String) {
    (
        200,
        json!({ "code": 0, "msg": "ok", "data": data }).to_string(),
    )
}

fn biz_envelope(data: Value) -> (u16, String) {
    (
        200,
        json!({ "code": 200, "msg": "Operation successful", "success": true, "data": data })
            .to_string(),
    )
}

fn scripted_peer(script: Script) -> Peer {
    Peer::start(move |seen| script.answer(seen))
}

fn zai_config(kind: &str, profile: &str) -> Config {
    Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.zai-coding-plan]\n\
         kind = \"{kind}\"\n\
         endpoint = \"https://api.z.ai\"\n\
         credential_ref = \"keychain:rivect-test/{profile}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"auto\" }}\n\
         effort = {{ mode = \"auto\" }}\n\
         fallback = {{ mode = \"auto\" }}\n"
    ))
    .expect("the zai config parses")
}

fn endpoints(peer: &Peer) -> ZaiEndpoints {
    ZaiEndpoints::new(
        &format!("{}/api/oauth/authorize", peer.base),
        &format!("{}/api/v1/oauth/token", peer.base),
        &peer.base,
    )
}

fn begin(peer: &Peer) -> zai_login::LoginSession {
    zai_login::begin_login(&endpoints(peer)).expect("the login begins")
}

fn callback(session: &zai_login::LoginSession) -> String {
    format!(
        "{}?code=auth-code&state={}",
        zai_login::CALLBACK_URL,
        session.state()
    )
}

fn reference(scope: &str) -> SecretRef {
    SecretRef::parse(scope).expect("the fixture reference parses")
}

fn assert_nothing_published(store: &support::MapStore, scope: &str) {
    let error = store
        .resolve(&reference(scope))
        .expect_err("nothing is published at the scope");
    assert!(
        matches!(error, ProviderError::CredentialAbsent { .. }),
        "{error}"
    );
}

fn stored(store: &support::MapStore, scope: &str) -> Vec<u8> {
    store
        .resolve(&reference(scope))
        .expect("the scope holds material")
}

/// The mutating requests a scripted peer received.
fn mutations(requests: &[Seen]) -> Vec<&str> {
    requests
        .iter()
        .filter(|request| {
            request.line.starts_with("POST ")
                || request.line.starts_with("PUT ")
                || request.line.starts_with("DELETE ")
        })
        .map(|request| request.line.as_str())
        .collect()
}

/// How long a peer or a test waits for its handshake partner before the
/// test fails instead of hanging.
const HOLD_LIMIT: Duration = Duration::from_secs(30);

#[derive(Default)]
struct HoldState {
    reached: bool,
    released: bool,
}

/// A peer/worker handshake: the peer announces a leg and parks until the
/// test releases it, so cancellation lands at a named point instead of on a
/// timer.
struct Hold {
    state: Mutex<HoldState>,
    changed: Condvar,
}

impl Hold {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(HoldState::default()),
            changed: Condvar::new(),
        })
    }

    /// Peer side: announce the leg and wait for the test's release.
    fn park(&self) {
        let mut state = self.state.lock().expect("hold lock");
        state.reached = true;
        self.changed.notify_all();
        while !state.released {
            let (next, timeout) = self
                .changed
                .wait_timeout(state, HOLD_LIMIT)
                .expect("hold wait");
            state = next;
            if timeout.timed_out() {
                drop(state);
                return;
            }
        }
        drop(state);
    }

    /// Test side: wait until the peer has reached its park point.
    fn reached(&self) {
        let mut state = self.state.lock().expect("hold lock");
        let deadline = Instant::now() + HOLD_LIMIT;
        while !state.reached {
            let left = deadline.saturating_duration_since(Instant::now());
            assert!(!left.is_zero(), "the peer never reached the hold point");
            let (next, _timeout) = self.changed.wait_timeout(state, left).expect("hold wait");
            state = next;
        }
        drop(state);
    }

    /// Test side: let the peer answer.
    fn release(&self) {
        let mut state = self.state.lock().expect("hold lock");
        state.released = true;
        self.changed.notify_all();
        drop(state);
    }
}

/// The recorded authorize leg, no PKCE, and the bounded fetch budget.
#[test]
fn zai_begin_advertises_the_recorded_non_pkce_authorize() {
    assert_eq!(
        zai_login::FETCH_TIMEOUT,
        Duration::from_secs(30),
        "each fetch keeps the recorded 30 s bound"
    );
    let first = zai_login::begin_login(&ZaiEndpoints::recorded()).expect("the login begins");
    let second = zai_login::begin_login(&ZaiEndpoints::recorded()).expect("the login begins");

    let url = reqwest::Url::parse(first.authorize_url()).expect("the authorize url parses");
    assert_eq!(
        url.as_str().split('?').next(),
        Some(zai_login::AUTHORIZE_URL)
    );
    let query: Vec<(String, String)> = url
        .query_pairs()
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect();
    assert!(query.contains(&("client_id".into(), zai_login::CLIENT_ID.into())));
    assert!(query.contains(&("response_type".into(), "code".into())));
    assert!(query.contains(&("redirect_uri".into(), zai_login::CALLBACK_URL.into())));
    assert!(query.contains(&("state".into(), first.state().into())));
    assert!(!query.iter().any(|(name, _)| name == "code_challenge"));
    assert_ne!(first.state(), second.state());
}

/// The full create walk: token, business login, customer, empty key list,
/// create, copy — then the canonical profile and its reader.
#[test]
fn zai_alias_publishes_the_canonical_profile() {
    let peer = scripted_peer(Script::success());
    let session = begin(&peer);
    let store = support::MapStore::new(StoreKind::Keychain);

    let profile = zai_login::complete_login(
        &zai_config("api_key", "zai"),
        ZAI_CONNECTION,
        &session,
        &callback(&session),
        &store,
    )
    .expect("the sign-in finishes");

    assert_eq!(profile, "zai");
    let bytes = stored(&store, ZAI_SCOPE);
    let read = zai_login::read_zai(&bytes).expect("the producer bytes parse");
    assert_eq!(read.token(), "created-key.real-secret");
    let stored_text = String::from_utf8_lossy(&bytes);
    assert!(!stored_text.contains("oauth-access-token"), "{stored_text}");
    assert!(!stored_text.contains("biz-token"), "{stored_text}");
    let debug = format!("{read:?}");
    assert!(!debug.contains("created-key"), "{debug}");
    assert!(!debug.contains("real-secret"), "{debug}");

    let requests = peer.requests();
    let lines: Vec<&str> = requests
        .iter()
        .map(|request| request.line.as_str())
        .collect();
    assert_eq!(
        lines,
        vec![
            "POST /api/v1/oauth/token HTTP/1.1",
            "POST /api/auth/z/login HTTP/1.1",
            "GET /api/biz/customer/getCustomerInfo HTTP/1.1",
            "GET /api/biz/v1/organization/org-1/projects/proj-1/api_keys HTTP/1.1",
            "POST /api/biz/v1/organization/org-1/projects/proj-1/api_keys HTTP/1.1",
            "GET /api/biz/v1/organization/org-1/projects/proj-1/api_keys/copy/created-key HTTP/1.1",
        ]
    );

    let token_body: Value = serde_json::from_str(&requests[0].body).expect("a json body");
    assert_eq!(
        token_body,
        json!({
            "provider": "zai",
            "code": "auth-code",
            "redirect_uri": zai_login::CALLBACK_URL,
            "state": session.state(),
        })
    );
    assert!(
        !requests[0]
            .head
            .to_ascii_lowercase()
            .contains("authorization:")
    );

    let login_body: Value = serde_json::from_str(&requests[1].body).expect("a json body");
    assert_eq!(login_body, json!({ "token": "oauth-access-token" }));
    for biz in &requests[2..] {
        assert!(
            biz.head
                .lines()
                .any(|line| line.eq_ignore_ascii_case("authorization: Bearer biz-token")),
            "every business leg carries the business token"
        );
    }

    let create_body: Value = serde_json::from_str(&requests[4].body).expect("a json body");
    assert_eq!(create_body, json!({ "name": "rivect" }));
}

/// A pre-existing `rivect` key is reused: no create, the secret comes from
/// the copy leg, and foreign entries are neither selected nor mutated.
#[test]
fn zai_reuses_the_existing_rivect_key_and_copies_its_secret() {
    let mut script = Script::success();
    script.keys = biz_envelope(json!([
        { "name": "zcode-api-key", "apiKey": "zcode-key", "secretKey": "*****aaaa" },
        { "name": "rivect", "apiKey": "existing-key", "secretKey": "*****pz5Y" }
    ]));
    script.copy = biz_envelope(json!({ "apiKey": "existing-key", "secretKey": "real-secret" }));
    let peer = scripted_peer(script);
    let session = begin(&peer);
    let store = support::MapStore::new(StoreKind::Keychain);

    zai_login::complete_login(
        &zai_config("api_key", "zai"),
        ZAI_CONNECTION,
        &session,
        &callback(&session),
        &store,
    )
    .expect("the existing key is reused");

    let requests = peer.requests();
    assert_eq!(
        requests
            .iter()
            .filter(
                |request| request.line.starts_with("POST ") && request.line.contains("/api_keys ")
            )
            .count(),
        0,
        "an existing key is never re-created"
    );
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.line.contains("/copy/"))
            .count(),
        1
    );
    assert!(
        requests
            .last()
            .is_some_and(|request| request.line.contains("/copy/existing-key ")),
        "the copy leg targets the rivect key"
    );
    let bytes = stored(&store, ZAI_SCOPE);
    let read = zai_login::read_zai(&bytes).expect("the producer bytes parse");
    assert_eq!(read.token(), "existing-key.real-secret");
}

/// The default organization and project are selected from the nested
/// customer response, in order.
#[test]
fn zai_selects_the_default_organization_and_project() {
    let mut script = Script::success();
    script.customer = biz_envelope(json!({
        "organizations": [
            {
                "organizationId": "org-other",
                "isDefault": false,
                "projects": [{ "projectId": "proj-x", "isDefault": true }]
            },
            {
                "organizationId": "org-default",
                "isDefault": true,
                "projects": [
                    { "projectId": "proj-a", "isDefault": false },
                    { "projectId": "proj-default", "isDefault": true }
                ]
            }
        ]
    }));
    let peer = scripted_peer(script);
    let session = begin(&peer);
    let store = support::MapStore::new(StoreKind::Keychain);

    zai_login::complete_login(
        &zai_config("api_key", "zai"),
        ZAI_CONNECTION,
        &session,
        &callback(&session),
        &store,
    )
    .expect("the default organization and project bind");

    let requests = peer.requests();
    assert!(
        requests.iter().any(|request| request.line.starts_with(
            "GET /api/biz/v1/organization/org-default/projects/proj-default/api_keys "
        )),
        "the default organization/project bind the key leg"
    );
    assert!(
        requests
            .iter()
            .all(|request| !request.line.contains("/organization/org-other/")),
        "a non-default organization is never used"
    );
}

/// Cancelling before the first leg, and between the token and business
/// legs, publishes nothing and sends no create request.
#[test]
fn zai_a_cancelled_login_publishes_nothing() {
    let peer = scripted_peer(Script::success());
    let session = begin(&peer);
    session.cancel();
    let store = support::MapStore::seeded(StoreKind::Keychain, &[(ZAI_SCOPE, PRIOR_PROFILE)]);
    let error = zai_login::complete_login(
        &zai_config("api_key", "zai"),
        ZAI_CONNECTION,
        &session,
        &callback(&session),
        &store,
    )
    .expect_err("a cancelled login publishes nothing");
    assert!(matches!(error, ZaiError::Cancelled), "{error}");
    assert!(peer.requests().is_empty());
    assert_eq!(stored(&store, ZAI_SCOPE), PRIOR_PROFILE.as_bytes());

    let hold = Hold::new();
    let script = Script::success();
    let peer = {
        let hold = Arc::clone(&hold);
        Peer::start(move |seen| {
            if seen.line.starts_with("POST /api/v1/oauth/token ") {
                hold.park();
            }
            script.answer(seen)
        })
    };
    let session = Arc::new(begin(&peer));
    let store = Arc::new(support::MapStore::new(StoreKind::Keychain));
    let config = zai_config("api_key", "zai");
    let redirect = callback(&session);
    let worker = {
        let session = Arc::clone(&session);
        let store = Arc::clone(&store);
        std::thread::spawn(move || {
            zai_login::complete_login(&config, ZAI_CONNECTION, &session, &redirect, store.as_ref())
        })
    };
    hold.reached();
    session.cancel();
    hold.release();
    let error = worker
        .join()
        .expect("the worker joins")
        .expect_err("the cancelled login stops after the token leg");
    assert!(matches!(error, ZaiError::Cancelled), "{error}");
    assert_eq!(
        peer.requests().len(),
        1,
        "no leg after the cancellation point runs"
    );
    assert_nothing_published(&store, ZAI_SCOPE);
}

/// Cancelling after the create leg completes stops before the copy and the
/// store write: exactly one key is issued and the prior bytes survive.
#[test]
fn zai_a_cancel_after_the_key_is_issued_publishes_nothing() {
    let hold = Hold::new();
    let script = Script::success();
    let peer = {
        let hold = Arc::clone(&hold);
        Peer::start(move |seen| {
            if seen.line.starts_with("POST ") && seen.line.contains("/api_keys ") {
                hold.park();
            }
            script.answer(seen)
        })
    };
    let session = Arc::new(begin(&peer));
    let store = Arc::new(support::MapStore::seeded(
        StoreKind::Keychain,
        &[(ZAI_SCOPE, PRIOR_PROFILE)],
    ));
    let config = zai_config("api_key", "zai");
    let redirect = callback(&session);
    let worker = {
        let session = Arc::clone(&session);
        let store = Arc::clone(&store);
        std::thread::spawn(move || {
            zai_login::complete_login(&config, ZAI_CONNECTION, &session, &redirect, store.as_ref())
        })
    };
    hold.reached();
    session.cancel();
    hold.release();
    let error = worker
        .join()
        .expect("the worker joins")
        .expect_err("a cancel after the create stops before the copy");
    assert!(matches!(error, ZaiError::Cancelled), "{error}");
    let requests = peer.requests();
    assert_eq!(
        mutations(&requests),
        vec![
            "POST /api/v1/oauth/token HTTP/1.1",
            "POST /api/auth/z/login HTTP/1.1",
            "POST /api/biz/v1/organization/org-1/projects/proj-1/api_keys HTTP/1.1",
        ],
        "exactly one key is created, and no mutation follows it"
    );
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.line.contains("/copy/"))
            .count(),
        0,
        "a cancelled login never copies the secret"
    );
    assert_eq!(
        requests.len(),
        5,
        "token, login, customer, key list and create only"
    );
    assert_eq!(
        stored(&store, ZAI_SCOPE),
        PRIOR_PROFILE.as_bytes(),
        "no store write lands"
    );
}

/// A stale state and a foreign callback origin deny before any request.
#[test]
fn zai_stale_and_foreign_callbacks_deny_before_a_request() {
    let peer = scripted_peer(Script::success());
    let session = begin(&peer);
    let store = support::MapStore::seeded(StoreKind::Keychain, &[(ZAI_SCOPE, PRIOR_PROFILE)]);

    let stale = format!(
        "{}?code=auth-code&state=stale-state",
        zai_login::CALLBACK_URL
    );
    let error = zai_login::complete_login(
        &zai_config("api_key", "zai"),
        ZAI_CONNECTION,
        &session,
        &stale,
        &store,
    )
    .expect_err("a stale state denies");
    assert!(matches!(error, ZaiError::StateMismatch), "{error}");
    assert!(peer.requests().is_empty());
    assert_eq!(stored(&store, ZAI_SCOPE), PRIOR_PROFILE.as_bytes());

    let foreign = format!(
        "https://zai-auth.example/callback?code=auth-code&state={}",
        session.state()
    );
    let error = zai_login::complete_login(
        &zai_config("api_key", "zai"),
        ZAI_CONNECTION,
        &session,
        &foreign,
        &store,
    )
    .expect_err("a foreign callback origin denies");
    assert!(
        matches!(error, ZaiError::CallbackNotRecorded { .. }),
        "{error}"
    );
    assert!(peer.requests().is_empty());
}

/// The pinned upstream's manual `code#state` form exchanges the pasted code
/// with the login's state echoed in the token body.
#[test]
fn zai_accepts_the_manual_code_state_callback() {
    let peer = scripted_peer(Script::success());
    let session = begin(&peer);
    let store = support::MapStore::new(StoreKind::Keychain);
    let manual = format!("auth-code#{}", session.state());
    zai_login::complete_login(
        &zai_config("api_key", "zai"),
        ZAI_CONNECTION,
        &session,
        &manual,
        &store,
    )
    .expect("the manual code#state form finishes");
    let requests = peer.requests();
    let token_body: Value = serde_json::from_str(&requests[0].body).expect("a json body");
    assert_eq!(token_body["code"], json!("auth-code"));
    assert_eq!(token_body["state"], json!(session.state()));
    let bytes = stored(&store, ZAI_SCOPE);
    assert_eq!(
        zai_login::read_zai(&bytes)
            .expect("the producer bytes parse")
            .token(),
        "created-key.real-secret"
    );
}

/// An OAuth error callback cancels before any request and leaves the prior
/// bytes untouched.
#[test]
fn zai_an_error_callback_cancels_before_a_request() {
    let peer = scripted_peer(Script::success());
    let session = begin(&peer);
    let store = support::MapStore::seeded(StoreKind::Keychain, &[(ZAI_SCOPE, PRIOR_PROFILE)]);
    let denied = format!(
        "{}?error=access_denied&state={}",
        zai_login::CALLBACK_URL,
        session.state()
    );
    let error = zai_login::complete_login(
        &zai_config("api_key", "zai"),
        ZAI_CONNECTION,
        &session,
        &denied,
        &store,
    )
    .expect_err("an error callback cancels");
    assert!(matches!(error, ZaiError::Cancelled), "{error}");
    assert!(peer.requests().is_empty());
    assert_eq!(stored(&store, ZAI_SCOPE), PRIOR_PROFILE.as_bytes());
}

/// An indeterminate create denies typed after exactly one create request:
/// no copy, no store write, no second mint.
#[test]
fn zai_indeterminate_issuance_denies_without_retry() {
    let mut script = Script::success();
    script.create = (500, "{}".to_string());
    let peer = scripted_peer(script);
    let session = begin(&peer);
    let store = support::MapStore::seeded(StoreKind::Keychain, &[(ZAI_SCOPE, PRIOR_PROFILE)]);
    let error = zai_login::complete_login(
        &zai_config("api_key", "zai"),
        ZAI_CONNECTION,
        &session,
        &callback(&session),
        &store,
    )
    .expect_err("an indeterminate create denies");
    assert!(
        matches!(error, ZaiError::KeyIssuanceIndeterminate { .. }),
        "{error}"
    );

    let requests = peer.requests();
    assert_eq!(
        requests
            .iter()
            .filter(
                |request| request.line.starts_with("POST ") && request.line.contains("/api_keys ")
            )
            .count(),
        1,
        "the create leg is never retried"
    );
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.line.contains("/copy/"))
            .count(),
        0
    );
    assert!(
        requests
            .iter()
            .all(|request| !request.line.contains("/paas/")),
        "no PAYG endpoint is substituted"
    );
    assert_eq!(stored(&store, ZAI_SCOPE), PRIOR_PROFILE.as_bytes());
}

/// A failed create-only write leaves the prior profile byte-identical and
/// does not repeat the key issuance.
#[test]
fn zai_failed_create_only_write_leaves_prior_bytes() {
    let peer = scripted_peer(Script::success());
    let session = begin(&peer);
    let store = support::MapStore::seeded(StoreKind::Keychain, &[(ZAI_SCOPE, PRIOR_PROFILE)]);

    let error = zai_login::complete_login(
        &zai_config("api_key", "zai"),
        ZAI_CONNECTION,
        &session,
        &callback(&session),
        &store,
    )
    .expect_err("an occupied scope denies");
    assert!(
        matches!(
            error,
            ZaiError::Provider(ProviderError::CredentialOccupied { .. })
        ),
        "{error}"
    );

    assert_eq!(stored(&store, ZAI_SCOPE), PRIOR_PROFILE.as_bytes());
    assert_eq!(
        peer.requests()
            .iter()
            .filter(
                |request| request.line.starts_with("POST ") && request.line.contains("/api_keys ")
            )
            .count(),
        1,
        "a failed store write never mints a second key"
    );
}

/// A peer naming another client's key in the create or copy reply denies
/// typed, and nothing is copied or stored.
#[test]
fn zai_foreign_key_material_denies() {
    let mut foreign_create = Script::success();
    foreign_create.create = biz_envelope(json!({
        "name": "zcode-api-key",
        "apiKey": "foreign-key",
        "secretKey": "foreign-secret"
    }));
    let peer = scripted_peer(foreign_create);
    let session = begin(&peer);
    let store = support::MapStore::seeded(StoreKind::Keychain, &[(ZAI_SCOPE, PRIOR_PROFILE)]);
    let error = zai_login::complete_login(
        &zai_config("api_key", "zai"),
        ZAI_CONNECTION,
        &session,
        &callback(&session),
        &store,
    )
    .expect_err("a foreign key name denies");
    assert!(matches!(error, ZaiError::ForeignKeyRefused), "{error}");
    let requests = peer.requests();
    assert_eq!(
        mutations(&requests),
        vec![
            "POST /api/v1/oauth/token HTTP/1.1",
            "POST /api/auth/z/login HTTP/1.1",
            "POST /api/biz/v1/organization/org-1/projects/proj-1/api_keys HTTP/1.1",
        ],
        "exactly one create request, and no mutation after the refusal"
    );
    assert_eq!(requests.len(), 5, "the walk stops at the refused create");
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.line.contains("/copy/"))
            .count(),
        0,
        "another client's key is never copied"
    );
    let create = requests.last().expect("the create leg was reached");
    assert_eq!(
        serde_json::from_str::<Value>(&create.body).expect("a json body"),
        json!({ "name": "rivect" }),
        "the create request names only Rivect's key"
    );
    assert_eq!(stored(&store, ZAI_SCOPE), PRIOR_PROFILE.as_bytes());

    let mut foreign_copy = Script::success();
    foreign_copy.copy =
        biz_envelope(json!({ "apiKey": "zcode-key", "secretKey": "foreign-secret" }));
    let peer = scripted_peer(foreign_copy);
    let session = begin(&peer);
    let error = zai_login::complete_login(
        &zai_config("api_key", "zai"),
        ZAI_CONNECTION,
        &session,
        &callback(&session),
        &store,
    )
    .expect_err("a copy reply naming another key denies");
    assert!(matches!(error, ZaiError::ForeignKeyRefused), "{error}");
    let requests = peer.requests();
    assert_eq!(
        mutations(&requests),
        vec![
            "POST /api/v1/oauth/token HTTP/1.1",
            "POST /api/auth/z/login HTTP/1.1",
            "POST /api/biz/v1/organization/org-1/projects/proj-1/api_keys HTTP/1.1",
        ],
        "exactly one create request, and no mutation after the refusal"
    );
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.line.contains("/copy/"))
            .count(),
        1,
        "exactly one copy request, never retried"
    );
    let copy = requests.last().expect("the copy leg was reached");
    assert!(
        copy.line.starts_with(
            "GET /api/biz/v1/organization/org-1/projects/proj-1/api_keys/copy/created-key "
        ),
        "the copy targets rivect's key"
    );
    assert_eq!(requests.len(), 6, "no request follows the refused copy");
    assert_eq!(stored(&store, ZAI_SCOPE), PRIOR_PROFILE.as_bytes());
}

/// A refusing copy leg denies after one create and one copy, and stores
/// nothing: the prior profile bytes survive.
#[test]
fn zai_a_copy_refusal_denies_without_storing() {
    let mut script = Script::success();
    script.copy = (500, "{}".to_string());
    let peer = scripted_peer(script);
    let session = begin(&peer);
    let store = support::MapStore::seeded(StoreKind::Keychain, &[(ZAI_SCOPE, PRIOR_PROFILE)]);
    let error = zai_login::complete_login(
        &zai_config("api_key", "zai"),
        ZAI_CONNECTION,
        &session,
        &callback(&session),
        &store,
    )
    .expect_err("a refused copy denies");
    assert!(
        matches!(error, ZaiError::KeyCopyRefused { status: 500 }),
        "{error}"
    );
    let requests = peer.requests();
    assert_eq!(
        mutations(&requests),
        vec![
            "POST /api/v1/oauth/token HTTP/1.1",
            "POST /api/auth/z/login HTTP/1.1",
            "POST /api/biz/v1/organization/org-1/projects/proj-1/api_keys HTTP/1.1",
        ],
        "exactly one create request, never retried or re-minted"
    );
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.line.contains("/copy/"))
            .count(),
        1,
        "exactly one copy request, never retried"
    );
    assert_eq!(requests.len(), 6, "no request follows the refused copy");
    assert_eq!(stored(&store, ZAI_SCOPE), PRIOR_PROFILE.as_bytes());
}

/// A PAYG base is never admitted, and the recorded business root is the
/// coding-plan one.
#[test]
fn zai_payg_substitution_is_refused() {
    assert_eq!(zai_login::BIZ_BASE, "https://api.z.ai");
    let payg = ZaiEndpoints::new(
        zai_login::AUTHORIZE_URL,
        zai_login::TOKEN_URL,
        "https://api.z.ai/api/coding/paas/v4",
    );
    let error = zai_login::begin_login(&payg).expect_err("a PAYG base is outside the contract");
    assert!(
        matches!(error, ZaiError::EndpointNotRecorded { .. }),
        "{error}"
    );

    let payg_token = ZaiEndpoints::new(
        zai_login::AUTHORIZE_URL,
        "https://api.z.ai/api/coding/paas/v4",
        zai_login::BIZ_BASE,
    );
    let error = zai_login::begin_login(&payg_token).expect_err("a PAYG token leg is refused");
    assert!(
        matches!(error, ZaiError::EndpointNotRecorded { .. }),
        "{error}"
    );

    zai_login::begin_login(&ZaiEndpoints::new(
        zai_login::AUTHORIZE_URL,
        zai_login::TOKEN_URL,
        "https://api.z.ai/",
    ))
    .expect("the recorded root admits its trailing-slash form");
}

/// The binding must name the canonical `zai` profile: another profile's
/// bytes are never touched and no request is sent.
#[test]
fn zai_a_non_canonical_profile_denies() {
    let peer = scripted_peer(Script::success());
    let session = begin(&peer);
    let store = support::MapStore::seeded(
        StoreKind::Keychain,
        &[(ZAI_SCOPE, PRIOR_PROFILE), (OTHER_SCOPE, OTHER_PROFILE)],
    );

    let error = zai_login::complete_login(
        &zai_config("api_key", "kimi-code"),
        ZAI_CONNECTION,
        &session,
        &callback(&session),
        &store,
    )
    .expect_err("a non-canonical profile is refused");
    assert!(
        matches!(&error, ZaiError::ProfileNotCanonical { profile } if profile == "kimi-code"),
        "{error}"
    );
    assert!(peer.requests().is_empty());
    assert_eq!(stored(&store, ZAI_SCOPE), PRIOR_PROFILE.as_bytes());
    assert_eq!(stored(&store, OTHER_SCOPE), OTHER_PROFILE.as_bytes());
}

/// The login path writes only an `api_key` row.
#[test]
fn zai_a_non_api_key_binding_denies() {
    let peer = scripted_peer(Script::success());
    let session = begin(&peer);
    let store = support::MapStore::new(StoreKind::Keychain);

    let error = zai_login::complete_login(
        &zai_config("subscription", "zai"),
        ZAI_CONNECTION,
        &session,
        &callback(&session),
        &store,
    )
    .expect_err("the login path writes only an api key row");
    assert!(
        matches!(
            error,
            ZaiError::NotApiKey {
                kind: ConnKind::Subscription,
                ..
            }
        ),
        "{error}"
    );
    assert!(peer.requests().is_empty());
}

/// The named reader denies material that is not a canonical `zai` profile.
#[test]
fn zai_reader_denies_foreign_material() {
    assert_eq!(
        zai_login::read_zai(br#"{"api_key":"a","secret_key":"b"}"#)
            .expect("canonical material parses")
            .token(),
        "a.b"
    );
    for foreign in [
        br#"{"api_key":"a","secret_key":"b","extra":1}"#.as_slice(),
        br#"{"api_key":"","secret_key":"b"}"#.as_slice(),
        br#"{"api_key":" a","secret_key":"b"}"#.as_slice(),
        br#"{"api_key":"a"}"#.as_slice(),
        b"not json".as_slice(),
    ] {
        let error = zai_login::read_zai(foreign).expect_err("foreign material denies");
        assert!(
            matches!(error, ZaiError::StoredCredentialMalformed { .. }),
            "{error}"
        );
    }
}
