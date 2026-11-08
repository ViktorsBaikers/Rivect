//! Cursor PKCE/poll, Devin CLI and Copilot device login proof (AC-008): the
//! recorded login legs, their status and transport denials, the create-only
//! canonical profiles, the enterprise normalization and the redacted token
//! surfaces are proved against loopback contract peers only.

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
use rivect::providers::anthropic_login;
use rivect::providers::copilot_login::{
    self, Advance as CopilotAdvance, DeviceEndpoints as CopilotEndpoints,
    LoginError as CopilotLoginError, StoredCredential as CopilotStoredCredential,
};
use rivect::providers::cursor_login::{
    self, Advance, CursorEndpoints, LoginError, POLL_MAX_ATTEMPTS, StoredCredential,
};
use rivect::providers::devin_login::{
    self, CALLBACK_URL, DevinEndpoints, LoginError as DevinLoginError,
};
use rivect::providers::gitlab_agent_login::{
    self, CALLBACK_URL as GITLAB_CALLBACK_URL, CLIENT_ID as GITLAB_CLIENT_ID,
    CredentialKind as GitlabCredentialKind, GitlabEndpoints, LoginError as GitlabLoginError,
    WorkspaceScope,
};
use rivect::providers::openai_login::{self, LoginError as OpenaiLoginError};
use rivect::providers::{CredentialStore, ProviderError, SecretRef, StoreKind, resolve_credential};
use serde_json::{Value, json};
use sha2::Digest as _;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const CURSOR_REF: &str = "keychain:rivect-test/cursor";
const CURSOR_REFRESH: &str = "fixture-cursor-refresh";
const CURSOR_REFRESH_ROTATED: &str = "fixture-cursor-refresh-rotated";
const TOKEN_EXPIRY: u64 = 4_102_444_800;
/// The recorded five-minute skew the stored expiry subtracts.
const EXPIRY_SKEW: u64 = 300;

/// A scripted loopback peer: one JSON answer per request line, judged by the
/// test's own closure. Status `0` accepts the connection and closes it
/// without an answer, which is the deterministic transport-failure shim. It
/// is a plain `std` listener because the login calls run on the test thread
/// and `reqwest::blocking` must never run inside a Tokio context.
struct TestPeer {
    base: String,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl TestPeer {
    fn start(handler: impl Fn(&str, &str, &str) -> (u16, String) + Send + Sync + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback peer");
        listener
            .set_nonblocking(true)
            .expect("nonblocking loopback peer");
        let base = format!("http://{}", listener.local_addr().expect("peer address"));
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let handler = Arc::new(handler);
        let handle = std::thread::spawn(move || {
            while !flag.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _address)) => {
                        // Darwin inherits the listener's nonblocking flag on accept.
                        stream.set_nonblocking(false).expect("peer blocking mode");
                        stream
                            .set_read_timeout(Some(Duration::from_secs(5)))
                            .expect("peer read timeout");
                        if let Some((line, head, body)) = read_request(&mut stream) {
                            let (status, payload) = handler(&line, &head, &body);
                            if status == 0 {
                                continue;
                            }
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
            stop,
            handle: Some(handle),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }
}

impl Drop for TestPeer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Reads one HTTP request: the full request line, the headers, and the body
/// under its `Content-Length`.
fn read_request(stream: &mut TcpStream) -> Option<(String, String, String)> {
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
    let line = head.lines().next()?.to_string();
    let body = String::from_utf8_lossy(&buffer[body_start..buffer.len()]).to_string();
    Some((line, head, body))
}

fn cursor_config() -> Config {
    Config::parse_validated(
        "config_version = 1\n\
         [connections.cursor]\n\
         kind = \"api_key\"\n\
         endpoint = \"https://api2.cursor.sh\"\n\
         credential_ref = \"keychain:rivect-test/cursor\"\n\
         [models.defaults]\n\
         model = { mode = \"auto\" }\n\
         effort = { mode = \"auto\" }\n\
         fallback = { mode = \"auto\" }\n",
    )
    .expect("the cursor config parses")
}

fn config_without_cursor() -> Config {
    Config::parse_validated(
        "config_version = 1\n\
         [connections.other]\n\
         kind = \"api_key\"\n\
         endpoint = \"https://api.example.invalid/v1\"\n\
         credential_ref = \"keychain:rivect-test/other\"\n\
         [models.defaults]\n\
         model = { mode = \"auto\" }\n\
         effort = { mode = \"auto\" }\n\
         fallback = { mode = \"auto\" }\n",
    )
    .expect("the config without cursor parses")
}

fn subscription_cursor_config() -> Config {
    Config::parse_validated(
        "config_version = 1\n\
         [connections.cursor]\n\
         kind = \"subscription\"\n\
         endpoint = \"https://api2.cursor.sh\"\n\
         credential_ref = \"keychain:rivect-test/cursor\"\n\
         [models.defaults]\n\
         model = { mode = \"auto\" }\n\
         effort = { mode = \"auto\" }\n\
         fallback = { mode = \"auto\" }\n",
    )
    .expect("the subscription cursor config parses")
}

fn endpoints(peer: &TestPeer) -> CursorEndpoints {
    CursorEndpoints {
        login: peer.url("/loginDeepControl"),
        poll: peer.url("/auth/poll"),
        refresh: peer.url("/auth/exchange_user_api_key"),
    }
}

fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(chunk.get(1).copied().unwrap_or(0));
        let b2 = u32::from(chunk.get(2).copied().unwrap_or(0));
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(char::from(ALPHABET[((triple >> 18) & 0x3f) as usize]));
        out.push(char::from(ALPHABET[((triple >> 12) & 0x3f) as usize]));
        if chunk.len() > 1 {
            out.push(char::from(ALPHABET[((triple >> 6) & 0x3f) as usize]));
        }
        if chunk.len() > 2 {
            out.push(char::from(ALPHABET[(triple & 0x3f) as usize]));
        }
    }
    out
}

fn jwt_token(claims: &Value) -> String {
    let header = base64url(br#"{"alg":"none","typ":"JWT"}"#);
    let payload = serde_json::to_vec(claims).expect("the fixture payload serializes");
    format!("{header}.{}.c2lnbmF0dXJl", base64url(&payload))
}

fn cursor_token(sub: &str, exp: u64) -> String {
    jwt_token(&json!({ "sub": sub, "exp": exp }))
}

/// The raw value of one query member of `url`.
fn query_value(url: &str, name: &str) -> Option<String> {
    let query = url.split_once('?')?.1;
    query.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        (key == name).then(|| value.to_string())
    })
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the clock is after the epoch")
        .as_secs()
}

fn s256(verifier: &str) -> String {
    base64url(&sha2::Sha256::digest(verifier.as_bytes()))
}

fn token_reply(access_token: &str, refresh_token: &str) -> String {
    json!({
        "accessToken": access_token,
        "refreshToken": refresh_token,
    })
    .to_string()
}

const DEVIN_REF: &str = "keychain:rivect-test/devin";

fn devin_config() -> Config {
    Config::parse_validated(
        "config_version = 1\n\
         [connections.devin]\n\
         kind = \"api_key\"\n\
         endpoint = \"https://api.devin.ai\"\n\
         credential_ref = \"keychain:rivect-test/devin\"\n\
         [models.defaults]\n\
         model = { mode = \"auto\" }\n\
         effort = { mode = \"auto\" }\n\
         fallback = { mode = \"auto\" }\n",
    )
    .expect("the devin config parses")
}

fn subscription_devin_config() -> Config {
    Config::parse_validated(
        "config_version = 1\n\
         [connections.devin]\n\
         kind = \"subscription\"\n\
         endpoint = \"https://api.devin.ai\"\n\
         credential_ref = \"keychain:rivect-test/devin\"\n\
         [models.defaults]\n\
         model = { mode = \"auto\" }\n\
         effort = { mode = \"auto\" }\n\
         fallback = { mode = \"auto\" }\n",
    )
    .expect("the subscription devin config parses")
}

fn devin_endpoints(peer: &TestPeer) -> DevinEndpoints {
    DevinEndpoints {
        authorize: peer.url("/auth/cli/continue"),
        token: peer.url("/auth/cli/token"),
    }
}

fn devin_reply(token: &str) -> String {
    json!({ "token": token }).to_string()
}

fn devin_callback(query: &str) -> String {
    format!("{CALLBACK_URL}?{query}")
}

const COPILOT_REF: &str = "keychain:rivect-test/copilot";
const COPILOT_TOKEN: &str = "fixture-copilot-token";
const COPILOT_DEVICE_CODE: &str = "fixture-device-code";
const COPILOT_USER_CODE: &str = "ABCD-1234";

fn copilot_config() -> Config {
    Config::parse_validated(
        "config_version = 1\n\
         [connections.github-copilot]\n\
         kind = \"api_key\"\n\
         endpoint = \"https://api.githubcopilot.com\"\n\
         credential_ref = \"keychain:rivect-test/copilot\"\n\
         [models.defaults]\n\
         model = { mode = \"auto\" }\n\
         effort = { mode = \"auto\" }\n\
         fallback = { mode = \"auto\" }\n",
    )
    .expect("the copilot config parses")
}

fn copilot_endpoints(peer: &TestPeer) -> CopilotEndpoints {
    CopilotEndpoints {
        device_code: peer.url("/login/device/code"),
        access_token: peer.url("/login/oauth/access_token"),
    }
}

fn copilot_device_reply(interval: u64, expires_in: u64) -> String {
    copilot_device_reply_with_uri("https://github.com/login/device", interval, expires_in)
}

fn copilot_device_reply_with_uri(uri: &str, interval: u64, expires_in: u64) -> String {
    json!({
        "device_code": COPILOT_DEVICE_CODE,
        "user_code": COPILOT_USER_CODE,
        "verification_uri": uri,
        "interval": interval,
        "expires_in": expires_in,
    })
    .to_string()
}

fn copilot_token_reply(token: &str) -> String {
    json!({
        "access_token": token,
        "token_type": "bearer",
        "scope": "read:user",
    })
    .to_string()
}

fn copilot_error_reply(error: &str) -> String {
    json!({ "error": error }).to_string()
}

/// The value of one request header, matched case-insensitively.
fn request_header(head: &str, name: &str) -> Option<String> {
    head.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.eq_ignore_ascii_case(name)
            .then(|| value.trim().to_string())
    })
}

/// Both device legs carry the recorded Copilot CLI identity and the JSON
/// accept plus form content type the shared bounded POST sets.
fn assert_copilot_identity(head: &str) {
    assert_eq!(
        request_header(head, "accept").as_deref(),
        Some("application/json")
    );
    assert_eq!(
        request_header(head, "content-type").as_deref(),
        Some("application/x-www-form-urlencoded")
    );
    assert_eq!(
        request_header(head, "user-agent").as_deref(),
        Some("copilot/1.0.82")
    );
    assert_eq!(
        request_header(head, "copilot-integration-id").as_deref(),
        Some("copilot-developer-cli")
    );
    assert_eq!(
        request_header(head, "copilot-harness-id").as_deref(),
        Some("copilot-sdk")
    );
}

#[test]
fn cursor_login_polls_until_the_browser_completes() {
    let polls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&polls);
    let requests = Arc::new(Mutex::new(Vec::<String>::new()));
    let recorded = Arc::clone(&requests);
    let access = cursor_token("auth0|user-fixture", TOKEN_EXPIRY);
    let reply = token_reply(&access, CURSOR_REFRESH);
    let peer = TestPeer::start(move |line, _head, _body| {
        let poll = counter.fetch_add(1, Ordering::SeqCst);
        recorded.lock().expect("record lock").push(line.to_string());
        if poll < 2 {
            (404, String::new())
        } else {
            (200, reply.clone())
        }
    });
    let config = cursor_config();
    let store = support::MapStore::new(StoreKind::Keychain);
    let mut session = cursor_login::begin_login(&endpoints(&peer)).expect("entropy");
    let uuid = uuid::Uuid::parse_str(session.uuid()).expect("the state is a uuid");
    assert_eq!(uuid.get_version_num(), 4);
    assert!(
        session
            .login_url()
            .starts_with(&format!("{}/loginDeepControl?challenge=", peer.base))
    );
    assert!(
        session
            .login_url()
            .contains(&format!("uuid={}", session.uuid()))
    );
    assert!(session.login_url().contains("mode=login"));
    assert!(session.login_url().contains("redirectTarget=cli"));
    assert_eq!(session.code_verifier().len(), 43);
    let challenge =
        query_value(session.login_url(), "challenge").expect("the login URL carries the challenge");
    assert_eq!(
        challenge,
        s256(session.code_verifier()),
        "the login URL publishes the S256 of the verifier"
    );
    assert_eq!(
        query_value(session.login_url(), "uuid").as_deref(),
        Some(session.uuid())
    );

    match cursor_login::advance(&config, "cursor", &mut session, &store).expect("first poll") {
        Advance::Pending { next_poll_at } => {
            assert!(next_poll_at > Instant::now(), "the next poll is scheduled");
        }
        Advance::Complete(_) => panic!("the first 404 stays pending"),
    }
    assert!(matches!(
        cursor_login::advance(&config, "cursor", &mut session, &store).expect("second poll"),
        Advance::Pending { .. }
    ));
    let profile =
        match cursor_login::advance(&config, "cursor", &mut session, &store).expect("third poll") {
            Advance::Complete(profile) => profile,
            Advance::Pending { .. } => panic!("the browser completed"),
        };
    assert_eq!(profile, "cursor");

    let reference = resolve_credential(&config, "cursor").expect("the canonical ref");
    let credential = cursor_login::read_credential(&store, &reference).expect("stored profile");
    assert_eq!(credential.access_token(), access);
    assert_eq!(credential.refresh_token(), CURSOR_REFRESH);
    assert_eq!(credential.expires_at(), TOKEN_EXPIRY - EXPIRY_SKEW);
    assert_eq!(credential.user_id(), "user-fixture");

    let raw: Value = serde_json::from_slice(&store.resolve(&reference).expect("stored bytes"))
        .expect("profile json");
    let mut keys = raw
        .as_object()
        .expect("the stored profile is an object")
        .keys()
        .cloned()
        .collect::<Vec<String>>();
    keys.sort();
    assert_eq!(
        keys,
        ["access_token", "expires_at", "refresh_token", "user_id"]
    );

    // The public completion path writes the same closed profile from one
    // 2xx reply without a poll leg.
    let direct_store = support::MapStore::new(StoreKind::Keychain);
    let direct_reply = json!({
        "accessToken": access,
        "refreshToken": CURSOR_REFRESH,
    });
    assert_eq!(
        cursor_login::complete(&config, "cursor", &direct_reply, &direct_store)
            .expect("the public completion writes the profile"),
        "cursor"
    );
    let direct_reference = resolve_credential(&config, "cursor").expect("the canonical ref");
    let direct = cursor_login::read_credential(&direct_store, &direct_reference)
        .expect("the direct profile reads back");
    assert_eq!(direct.user_id(), "user-fixture");
    assert_eq!(direct.expires_at(), TOKEN_EXPIRY - EXPIRY_SKEW);

    let expected = format!(
        "GET /auth/poll?uuid={}&verifier={} HTTP/1.1",
        session.uuid(),
        session.code_verifier()
    );
    let observed = requests.lock().expect("record lock");
    assert_eq!(observed.len(), 3);
    for (attempt, line) in observed.iter().enumerate() {
        assert_eq!(
            line,
            &expected,
            "poll attempt {} carries the recorded method, state and verifier",
            attempt + 1
        );
    }
}

#[test]
fn cursor_login_pending_404_is_bounded_and_retried() {
    let polls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&polls);
    let peer = TestPeer::start(move |_path, _head, _body| {
        counter.fetch_add(1, Ordering::SeqCst);
        (404, String::new())
    });
    let config = cursor_config();
    let store = support::MapStore::new(StoreKind::Keychain);
    let mut session = cursor_login::begin_login(&endpoints(&peer)).expect("entropy");
    for _ in 0..POLL_MAX_ATTEMPTS {
        match cursor_login::advance(&config, "cursor", &mut session, &store).expect("pending poll")
        {
            Advance::Pending { next_poll_at } => {
                assert!(
                    next_poll_at.saturating_duration_since(Instant::now())
                        <= Duration::from_secs(10),
                    "the recorded backoff ceiling"
                );
            }
            Advance::Complete(_) => panic!("a 404 never completes"),
        }
    }
    let error = cursor_login::advance(&config, "cursor", &mut session, &store)
        .expect_err("the recorded poll window is bounded");
    assert!(matches!(error, LoginError::Expired), "{error}");
    assert_eq!(
        polls.load(Ordering::SeqCst),
        usize::try_from(POLL_MAX_ATTEMPTS).expect("the attempt count fits")
    );
    let reference = resolve_credential(&config, "cursor").expect("the canonical ref");
    assert!(matches!(
        store.resolve(&reference),
        Err(ProviderError::CredentialAbsent { .. })
    ));
}

#[test]
fn cursor_login_status_rejections_do_not_activate() {
    let answers = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&answers);
    let peer = TestPeer::start(move |_line, _head, _body| {
        let answer = counter.fetch_add(1, Ordering::SeqCst);
        if answer == 0 {
            (403, json!({ "error": "rejected" }).to_string())
        } else {
            (401, json!({ "error": "bad verifier" }).to_string())
        }
    });
    let config = cursor_config();
    let store = support::MapStore::new(StoreKind::Keychain);

    let mut rejected = cursor_login::begin_login(&endpoints(&peer)).expect("entropy");
    let verifier = rejected.code_verifier().to_string();
    let error = cursor_login::advance(&config, "cursor", &mut rejected, &store)
        .expect_err("the peer rejected the poll");
    assert!(
        matches!(error, LoginError::TokenRejected { status: 403 }),
        "{error}"
    );
    assert!(!format!("{error} {error:?}").contains(&verifier));

    let mut refused = cursor_login::begin_login(&endpoints(&peer)).expect("entropy");
    let error = cursor_login::advance(&config, "cursor", &mut refused, &store)
        .expect_err("the peer refused the verifier");
    assert!(
        matches!(error, LoginError::TokenRejected { status: 401 }),
        "{error}"
    );

    let reference = resolve_credential(&config, "cursor").expect("the canonical ref");
    assert!(matches!(
        store.resolve(&reference),
        Err(ProviderError::CredentialAbsent { .. })
    ));
}

#[test]
fn cursor_occupied_scope_keeps_the_prior_profile() {
    let prior = b"prior-cursor-material";
    let peer = TestPeer::start(move |_path, _head, _body| {
        (
            200,
            token_reply(
                &cursor_token("auth0|user-fixture", TOKEN_EXPIRY),
                CURSOR_REFRESH,
            ),
        )
    });
    let config = cursor_config();
    let store = support::MapStore::seeded(
        StoreKind::Keychain,
        &[(CURSOR_REF, "prior-cursor-material")],
    );
    let mut session = cursor_login::begin_login(&endpoints(&peer)).expect("entropy");
    let error = cursor_login::advance(&config, "cursor", &mut session, &store)
        .expect_err("create-only enrollment refuses an occupied scope");
    assert!(
        matches!(
            error,
            LoginError::Provider(ProviderError::CredentialOccupied { .. })
        ),
        "{error}"
    );
    let reference = resolve_credential(&config, "cursor").expect("the canonical ref");
    assert_eq!(store.resolve(&reference).expect("prior bytes"), prior);
}

/// A store whose enrollment always refuses: the canonical scope already holds
/// prior material and the write is denied, so the bytes stay identical.
struct RefusingLoginStore {
    inner: support::MapStore,
}

impl CredentialStore for RefusingLoginStore {
    fn kind(&self) -> StoreKind {
        self.inner.kind()
    }

    fn occupied(&self, credential: &SecretRef) -> Result<bool, ProviderError> {
        self.inner.occupied(credential)
    }

    fn entry_accounts(&self, service: &str) -> Result<Vec<String>, ProviderError> {
        self.inner.entry_accounts(service)
    }

    fn login(&self, _credential: &SecretRef, _secret: &[u8]) -> Result<(), ProviderError> {
        Err(ProviderError::StoreUnavailable {
            store: self.inner.kind(),
            reason: "fixture refusal".to_string(),
        })
    }

    fn resolve(&self, credential: &SecretRef) -> Result<Vec<u8>, ProviderError> {
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

/// A store whose in-place refresh always refuses while reads still succeed.
struct RefusingRefreshStore {
    inner: support::MapStore,
}

impl CredentialStore for RefusingRefreshStore {
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

    fn refresh(&self, _credential: &SecretRef, _secret: &[u8]) -> Result<(), ProviderError> {
        Err(ProviderError::StoreUnavailable {
            store: self.inner.kind(),
            reason: "fixture refusal".to_string(),
        })
    }

    fn revoke(&self, credential: &SecretRef) -> Result<(), ProviderError> {
        self.inner.revoke(credential)
    }

    fn logout(&self, credential: &SecretRef) -> Result<(), ProviderError> {
        self.inner.logout(credential)
    }
}

#[test]
fn cursor_failed_store_write_keeps_the_prior_profile() {
    let prior = b"prior-cursor-material";
    let peer = TestPeer::start(move |_path, _head, _body| {
        (
            200,
            token_reply(
                &cursor_token("auth0|user-fixture", TOKEN_EXPIRY),
                CURSOR_REFRESH,
            ),
        )
    });
    let config = cursor_config();
    let inner = support::MapStore::seeded(
        StoreKind::Keychain,
        &[(CURSOR_REF, "prior-cursor-material")],
    );
    let store = RefusingLoginStore { inner };
    let mut session = cursor_login::begin_login(&endpoints(&peer)).expect("entropy");
    let error = cursor_login::advance(&config, "cursor", &mut session, &store)
        .expect_err("a refused store write denies");
    assert!(
        matches!(
            error,
            LoginError::Provider(ProviderError::StoreUnavailable { .. })
        ),
        "{error}"
    );
    let reference = resolve_credential(&config, "cursor").expect("the canonical ref");
    assert_eq!(store.resolve(&reference).expect("prior bytes"), prior);
}

#[test]
fn cursor_refresh_preserves_the_user_id() {
    let prior_access = cursor_token("auth0|user-fixture", TOKEN_EXPIRY);
    let rotated_expiry = TOKEN_EXPIRY + 3_600;
    let rotated_access = cursor_token("auth0|other-user", rotated_expiry);
    let observed = Arc::new(Mutex::new(Vec::<(String, String, String)>::new()));
    let recorded = Arc::clone(&observed);
    let reply = token_reply(&rotated_access, CURSOR_REFRESH_ROTATED);
    let peer = TestPeer::start(move |line, head, body| {
        recorded.lock().expect("record lock").push((
            line.to_string(),
            head.to_string(),
            body.to_string(),
        ));
        (200, reply.clone())
    });
    let config = cursor_config();
    let prior = json!({
        "access_token": prior_access,
        "refresh_token": CURSOR_REFRESH,
        "expires_at": TOKEN_EXPIRY - EXPIRY_SKEW,
        "user_id": "user-fixture",
    })
    .to_string();
    let store = support::MapStore::seeded(StoreKind::Keychain, &[(CURSOR_REF, &prior)]);

    let profile = cursor_login::refresh(
        &config,
        "cursor",
        &peer.url("/auth/exchange_user_api_key"),
        &store,
    )
    .expect("the refresh exchange completes");
    assert_eq!(profile, "cursor");

    let reference = resolve_credential(&config, "cursor").expect("the canonical ref");
    let credential: StoredCredential =
        cursor_login::read_credential(&store, &reference).expect("stored profile");
    assert_eq!(credential.access_token(), rotated_access);
    assert_eq!(credential.refresh_token(), CURSOR_REFRESH_ROTATED);
    assert_eq!(credential.expires_at(), rotated_expiry - EXPIRY_SKEW);
    assert_eq!(
        credential.user_id(),
        "user-fixture",
        "a refresh never rebinds the profile to the token's sub"
    );

    let requests = observed.lock().expect("record lock");
    assert_eq!(requests.len(), 1);
    let (line, head, body) = &requests[0];
    assert_eq!(line, "POST /auth/exchange_user_api_key HTTP/1.1");
    let lower = head.to_ascii_lowercase();
    assert!(
        lower.contains(&format!(
            "authorization: bearer {}",
            CURSOR_REFRESH.to_ascii_lowercase()
        )),
        "{head}"
    );
    assert!(lower.contains("content-type: application/json"), "{head}");
    assert_eq!(body, "{}");
    drop(requests);
}

#[test]
fn cursor_login_pins_the_recorded_contract_literals() {
    assert_eq!(POLL_MAX_ATTEMPTS, 150);
    assert_eq!(
        cursor_login::LOGIN_URL,
        "https://cursor.com/loginDeepControl"
    );
    assert_eq!(cursor_login::POLL_URL, "https://api2.cursor.sh/auth/poll");
    assert_eq!(
        cursor_login::REFRESH_URL,
        "https://api2.cursor.sh/auth/exchange_user_api_key"
    );
    let recorded = CursorEndpoints::recorded();
    assert_eq!(recorded.login, "https://cursor.com/loginDeepControl");
    assert_eq!(recorded.poll, "https://api2.cursor.sh/auth/poll");
    assert_eq!(
        recorded.refresh,
        "https://api2.cursor.sh/auth/exchange_user_api_key"
    );
}

#[test]
fn cursor_login_backoff_widens_by_a_fifth_to_the_cap() {
    let peer = TestPeer::start(|_line, _head, _body| (404, String::new()));
    let config = cursor_config();
    let store = support::MapStore::new(StoreKind::Keychain);
    let mut session = cursor_login::begin_login(&endpoints(&peer)).expect("entropy");
    // The first 404 widens before it schedules, so the first wait is 1.2s.
    let mut expected = Duration::from_millis(1_200);
    let mut widened = false;
    for _ in 0..18 {
        let before = Instant::now();
        let next_poll_at = match cursor_login::advance(&config, "cursor", &mut session, &store)
            .expect("a 404 stays pending")
        {
            Advance::Pending { next_poll_at } => next_poll_at,
            Advance::Complete(_) => panic!("a 404 never completes"),
        };
        let observed = next_poll_at.saturating_duration_since(before);
        assert!(
            observed + Duration::from_millis(1) >= expected,
            "the scheduled delay {observed:?} is at least {expected:?}"
        );
        assert!(
            observed <= expected + Duration::from_secs(1),
            "the scheduled delay {observed:?} is about {expected:?}"
        );
        if expected > Duration::from_secs(1) && expected < Duration::from_secs(10) {
            widened = true;
        }
        expected = expected.mul_f64(1.2).min(Duration::from_secs(10));
    }
    assert!(widened, "the delay widens before it saturates");
    assert_eq!(
        expected,
        Duration::from_secs(10),
        "the widened delay saturates at the recorded cap"
    );
}

#[test]
fn cursor_login_transport_errors_reset_on_a_pending_poll() {
    let requests = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&requests);
    let peer = TestPeer::start(move |_line, _head, _body| {
        let attempt = counter.fetch_add(1, Ordering::SeqCst);
        match attempt {
            0 | 2 | 4 | 5 | 6 => (0, String::new()),
            _ => (404, String::new()),
        }
    });
    let config = cursor_config();
    let store = support::MapStore::new(StoreKind::Keychain);
    let mut session = cursor_login::begin_login(&endpoints(&peer)).expect("entropy");
    let verifier = session.code_verifier().to_string();
    for attempt in 1..=6 {
        assert!(
            matches!(
                cursor_login::advance(&config, "cursor", &mut session, &store)
                    .expect("the poll stays pending"),
                Advance::Pending { .. }
            ),
            "attempt {attempt} stays pending: each 404 resets the transport-error counter"
        );
    }
    let error = cursor_login::advance(&config, "cursor", &mut session, &store)
        .expect_err("the third consecutive transport error denies");
    assert!(matches!(error, LoginError::PollingFailed { .. }), "{error}");
    assert!(!format!("{error} {error:?}").contains(&verifier));
    assert_eq!(requests.load(Ordering::SeqCst), 7);
}

#[test]
fn cursor_login_rejects_foreign_and_userinfo_endpoints() {
    let requests = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&requests);
    let peer = TestPeer::start(move |_line, _head, _body| {
        counter.fetch_add(1, Ordering::SeqCst);
        (200, String::new())
    });
    let config = cursor_config();
    let prior = json!({
        "access_token": cursor_token("auth0|user-fixture", TOKEN_EXPIRY),
        "refresh_token": CURSOR_REFRESH,
        "expires_at": TOKEN_EXPIRY - EXPIRY_SKEW,
        "user_id": "user-fixture",
    })
    .to_string();
    let store = support::MapStore::seeded(StoreKind::Keychain, &[(CURSOR_REF, &prior)]);
    let recorded = CursorEndpoints::recorded();
    let userinfo_origin = format!(
        "https://user:pass@{}",
        peer.base.trim_start_matches("http://")
    );

    for endpoints in [
        CursorEndpoints {
            login: "https://evil.example/loginDeepControl".to_string(),
            ..recorded.clone()
        },
        CursorEndpoints {
            poll: format!("{userinfo_origin}/auth/poll"),
            ..recorded.clone()
        },
    ] {
        let error = cursor_login::begin_login(&endpoints).expect_err("a foreign endpoint denies");
        assert!(
            matches!(error, LoginError::EndpointNotRecorded { .. }),
            "{error}"
        );
    }
    assert_eq!(requests.load(Ordering::SeqCst), 0);

    let reference = resolve_credential(&config, "cursor").expect("the canonical ref");
    for endpoint in [
        "https://evil.example/auth/exchange_user_api_key".to_string(),
        format!("{userinfo_origin}/auth/exchange_user_api_key"),
    ] {
        let error = cursor_login::refresh(&config, "cursor", &endpoint, &store)
            .expect_err("a foreign refresh endpoint denies before the store");
        assert!(
            matches!(error, LoginError::EndpointNotRecorded { .. }),
            "{error}"
        );
        assert_eq!(
            store.resolve(&reference).expect("prior bytes"),
            prior.as_bytes()
        );
    }
    assert_eq!(requests.load(Ordering::SeqCst), 0);
}

#[test]
fn cursor_producer_reply_negatives_write_nothing() {
    let config = cursor_config();
    let access = cursor_token("auth0|user-fixture", TOKEN_EXPIRY);
    let cases = [
        (json!({ "refreshToken": CURSOR_REFRESH }), "accessToken"),
        (json!({ "accessToken": access.clone() }), "refreshToken"),
    ];
    for (reply, field) in cases {
        let store = support::MapStore::new(StoreKind::Keychain);
        let error = cursor_login::complete(&config, "cursor", &reply, &store)
            .expect_err("an incomplete reply denies");
        assert!(
            matches!(error, LoginError::MissingField { field: observed } if observed == field),
            "{error}"
        );
        let reference = resolve_credential(&config, "cursor").expect("the canonical ref");
        assert!(matches!(
            store.resolve(&reference),
            Err(ProviderError::CredentialAbsent { .. })
        ));
    }

    let incomplete = TestPeer::start(|_line, _head, _body| {
        (200, json!({ "refreshToken": CURSOR_REFRESH }).to_string())
    });
    let store = support::MapStore::new(StoreKind::Keychain);
    let mut session = cursor_login::begin_login(&endpoints(&incomplete)).expect("entropy");
    let error = cursor_login::advance(&config, "cursor", &mut session, &store)
        .expect_err("a 2xx without accessToken denies");
    assert!(
        matches!(
            error,
            LoginError::MissingField {
                field: "accessToken"
            }
        ),
        "{error}"
    );
    let reference = resolve_credential(&config, "cursor").expect("the canonical ref");
    assert!(matches!(
        store.resolve(&reference),
        Err(ProviderError::CredentialAbsent { .. })
    ));

    let no_sub = jwt_token(&json!({ "exp": TOKEN_EXPIRY }));
    let reply = json!({ "accessToken": no_sub, "refreshToken": CURSOR_REFRESH });
    let store = support::MapStore::new(StoreKind::Keychain);
    let error = cursor_login::complete(&config, "cursor", &reply, &store)
        .expect_err("a token without sub denies");
    assert!(matches!(error, LoginError::MissingUserId), "{error}");
    let reference = resolve_credential(&config, "cursor").expect("the canonical ref");
    assert!(matches!(
        store.resolve(&reference),
        Err(ProviderError::CredentialAbsent { .. })
    ));

    let peer = TestPeer::start(|_line, _head, _body| (200, "not-json".to_string()));
    let store = support::MapStore::new(StoreKind::Keychain);
    let mut session = cursor_login::begin_login(&endpoints(&peer)).expect("entropy");
    let error = cursor_login::advance(&config, "cursor", &mut session, &store)
        .expect_err("malformed json denies");
    assert!(
        matches!(error, LoginError::MalformedResponse { .. }),
        "{error}"
    );
    assert!(matches!(
        store.resolve(&reference),
        Err(ProviderError::CredentialAbsent { .. })
    ));

    let exp_less = jwt_token(&json!({ "sub": "auth0|user-fixture" }));
    let reply = json!({ "accessToken": exp_less, "refreshToken": CURSOR_REFRESH });
    let store = support::MapStore::new(StoreKind::Keychain);
    let before = now_seconds();
    assert_eq!(
        cursor_login::complete(&config, "cursor", &reply, &store)
            .expect("the public completion writes the profile"),
        "cursor"
    );
    let after = now_seconds();
    let credential = cursor_login::read_credential(&store, &reference).expect("stored profile");
    assert!(credential.expires_at() >= before + 3_600);
    assert!(credential.expires_at() <= after + 3_600);
}

#[test]
fn cursor_refresh_failure_paths_keep_the_prior_profile() {
    let config = cursor_config();
    let prior = json!({
        "access_token": cursor_token("auth0|user-fixture", TOKEN_EXPIRY),
        "refresh_token": CURSOR_REFRESH,
        "expires_at": TOKEN_EXPIRY - EXPIRY_SKEW,
        "user_id": "user-fixture",
    })
    .to_string();
    let reference = resolve_credential(&config, "cursor").expect("the canonical ref");

    let refused = TestPeer::start(|_line, _head, _body| (401, "{}".to_string()));
    let store = support::MapStore::seeded(StoreKind::Keychain, &[(CURSOR_REF, &prior)]);
    let error = cursor_login::refresh(
        &config,
        "cursor",
        &refused.url("/auth/exchange_user_api_key"),
        &store,
    )
    .expect_err("a refusing peer denies");
    assert!(
        matches!(error, LoginError::TokenRejected { status: 401 }),
        "{error}"
    );
    assert_eq!(
        store.resolve(&reference).expect("prior bytes"),
        prior.as_bytes()
    );

    let malformed = TestPeer::start(|_line, _head, _body| {
        (
            200,
            token_reply(
                &cursor_token("auth0|user-fixture", TOKEN_EXPIRY),
                CURSOR_REFRESH_ROTATED,
            ),
        )
    });
    let store =
        support::MapStore::seeded(StoreKind::Keychain, &[(CURSOR_REF, "not-a-cursor-profile")]);
    let error = cursor_login::refresh(
        &config,
        "cursor",
        &malformed.url("/auth/exchange_user_api_key"),
        &store,
    )
    .expect_err("malformed stored material denies");
    assert!(
        matches!(error, LoginError::StoredCredentialMalformed { .. }),
        "{error}"
    );
    assert_eq!(
        store.resolve(&reference).expect("prior bytes"),
        b"not-a-cursor-profile"
    );

    let peer = TestPeer::start(|_line, _head, _body| {
        (
            200,
            token_reply(
                &cursor_token("auth0|user-fixture", TOKEN_EXPIRY),
                CURSOR_REFRESH_ROTATED,
            ),
        )
    });
    let store = RefusingRefreshStore {
        inner: support::MapStore::seeded(StoreKind::Keychain, &[(CURSOR_REF, &prior)]),
    };
    let error = cursor_login::refresh(
        &config,
        "cursor",
        &peer.url("/auth/exchange_user_api_key"),
        &store,
    )
    .expect_err("a refused refresh write denies");
    assert!(
        matches!(
            error,
            LoginError::Provider(ProviderError::StoreUnavailable { .. })
        ),
        "{error}"
    );
    assert_eq!(
        store.resolve(&reference).expect("prior bytes"),
        prior.as_bytes()
    );
}

#[test]
fn cursor_config_negatives_deny_with_zero_requests() {
    let requests = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&requests);
    let peer = TestPeer::start(move |_line, _head, _body| {
        counter.fetch_add(1, Ordering::SeqCst);
        (
            200,
            token_reply(
                &cursor_token("auth0|user-fixture", TOKEN_EXPIRY),
                CURSOR_REFRESH,
            ),
        )
    });
    let empty = support::MapStore::new(StoreKind::Keychain);
    let reply = json!({
        "accessToken": cursor_token("auth0|user-fixture", TOKEN_EXPIRY),
        "refreshToken": CURSOR_REFRESH,
    });

    let undeclared = config_without_cursor();
    let mut session = cursor_login::begin_login(&endpoints(&peer)).expect("entropy");
    let error = cursor_login::advance(&undeclared, "cursor", &mut session, &empty)
        .expect_err("an undeclared connection denies");
    assert!(
        matches!(error, LoginError::ConnectionMissing { .. }),
        "{error}"
    );
    let error = cursor_login::complete(&undeclared, "cursor", &reply, &empty)
        .expect_err("an undeclared connection denies");
    assert!(
        matches!(error, LoginError::ConnectionMissing { .. }),
        "{error}"
    );

    let subscription = subscription_cursor_config();
    let error = cursor_login::advance(&subscription, "cursor", &mut session, &empty)
        .expect_err("a non-api-key connection denies");
    assert!(
        matches!(
            error,
            LoginError::NotApiKey {
                kind: ConnKind::Subscription,
                ..
            }
        ),
        "{error}"
    );
    let error = cursor_login::complete(&subscription, "cursor", &reply, &empty)
        .expect_err("a non-api-key connection denies");
    assert!(
        matches!(
            error,
            LoginError::NotApiKey {
                kind: ConnKind::Subscription,
                ..
            }
        ),
        "{error}"
    );

    assert_eq!(requests.load(Ordering::SeqCst), 0);
    let reference = resolve_credential(&cursor_config(), "cursor").expect("the canonical ref");
    assert!(matches!(
        empty.resolve(&reference),
        Err(ProviderError::CredentialAbsent { .. })
    ));
}

#[test]
fn cursor_profile_never_prints_secrets() {
    let access = cursor_token("auth0|user-fixture", TOKEN_EXPIRY);
    let reply = token_reply(&access, CURSOR_REFRESH);
    let peer = TestPeer::start(move |_line, _head, _body| (200, reply.clone()));
    let config = cursor_config();
    let store = support::MapStore::new(StoreKind::Keychain);
    let mut session = cursor_login::begin_login(&endpoints(&peer)).expect("entropy");
    let verifier = session.code_verifier().to_string();
    let _profile = match cursor_login::advance(&config, "cursor", &mut session, &store) {
        Ok(Advance::Complete(profile)) => profile,
        Ok(Advance::Pending { .. }) => panic!("the peer answered immediately"),
        Err(error) => panic!("the poll completes: {error}"),
    };
    let reference = resolve_credential(&config, "cursor").expect("the canonical ref");
    let credential = cursor_login::read_credential(&store, &reference).expect("stored profile");

    let session_debug = format!("{session:?}");
    assert!(session_debug.contains("<redacted>"));
    assert!(!session_debug.contains(&verifier), "{session_debug}");
    let credential_debug = format!("{credential:?}");
    assert!(credential_debug.contains("<redacted>"));
    assert!(!credential_debug.contains(&access), "{credential_debug}");
    assert!(
        !credential_debug.contains(CURSOR_REFRESH),
        "{credential_debug}"
    );

    let malformed_json =
        serde_json::from_slice::<Value>(b"not-json").expect_err("the fixture is not an object");
    let serialization = serde_json::from_slice::<Value>(b"{").expect_err("the fixture is not json");
    let clock = UNIX_EPOCH
        .duration_since(SystemTime::now())
        .expect_err("the wall clock is after the unix epoch");
    let mut errors = vec![
        LoginError::TokenRejected { status: 403 },
        LoginError::MissingField {
            field: "accessToken",
        },
        LoginError::MissingUserId,
        LoginError::InvalidExpiry,
        LoginError::Expired,
        LoginError::ResponseTooLarge,
        LoginError::MalformedResponse {
            cause: malformed_json,
        },
        LoginError::StoredCredentialMalformed {
            reason: "a value outside the profile shape",
        },
        LoginError::Serialization {
            cause: serialization,
        },
        LoginError::Clock { cause: clock },
        LoginError::EndpointNotRecorded {
            origin: "https://evil.example".to_string(),
        },
        LoginError::ConnectionMissing {
            connection: "cursor".to_string(),
        },
        LoginError::NotApiKey {
            connection: "cursor".to_string(),
            kind: ConnKind::Local,
        },
        LoginError::Provider(ProviderError::StoreUnavailable {
            store: StoreKind::Keychain,
            reason: "fixture refusal".to_string(),
        }),
    ];

    let refusal = TestPeer::start(|_line, _head, _body| (0, String::new()));
    let dead_endpoints = CursorEndpoints {
        login: refusal.url("/loginDeepControl"),
        poll: refusal.url("/auth/poll"),
        refresh: refusal.url("/auth/exchange_user_api_key"),
    };
    let mut dead = cursor_login::begin_login(&dead_endpoints).expect("entropy");
    for _ in 0..2 {
        assert!(matches!(
            cursor_login::advance(&config, "cursor", &mut dead, &store)
                .expect("pending transport failure"),
            Advance::Pending { .. }
        ));
    }
    let polling = cursor_login::advance(&config, "cursor", &mut dead, &store)
        .expect_err("the third consecutive transport error denies");
    assert!(matches!(polling, LoginError::PollingFailed { .. }));
    errors.push(polling);

    for error in &errors {
        let rendered = format!("{error} {error:?}");
        assert!(!rendered.contains(&access), "{rendered}");
        assert!(!rendered.contains(CURSOR_REFRESH), "{rendered}");
        assert!(!rendered.contains(&verifier), "{rendered}");
    }
}

#[test]
fn devin_exchange_uses_pkce_and_json_body() {
    let observed = Arc::new(Mutex::new(Vec::<(String, String, String)>::new()));
    let recorded = Arc::clone(&observed);
    let token = jwt_token(&json!({ "sub": "devin-user", "exp": TOKEN_EXPIRY }));
    let reply = devin_reply(&token);
    let peer = TestPeer::start(move |line, head, body| {
        recorded.lock().expect("record lock").push((
            line.to_string(),
            head.to_string(),
            body.to_string(),
        ));
        (200, reply.clone())
    });
    let config = devin_config();
    let store = support::MapStore::new(StoreKind::Keychain);
    let session = devin_login::begin_login(&devin_endpoints(&peer)).expect("entropy");

    let recorded = DevinEndpoints::recorded();
    assert_eq!(recorded.authorize, "https://app.devin.ai/auth/cli/continue");
    assert_eq!(recorded.token, "https://api.devin.ai/auth/cli/token");
    assert_eq!(CALLBACK_URL, "http://127.0.0.1:59653/callback");

    let state = uuid::Uuid::parse_str(session.state()).expect("the state is a uuid");
    assert_eq!(state.get_version_num(), 4);
    assert!(
        session
            .login_url()
            .starts_with(&format!("{}/auth/cli/continue?", peer.base))
    );
    let login = reqwest::Url::parse(session.login_url()).expect("the login url parses");
    let query = |name: &str| {
        login
            .query_pairs()
            .find_map(|(key, value)| (key.as_ref() == name).then(|| value.into_owned()))
    };
    assert_eq!(query("response_type").as_deref(), Some("code"));
    assert_eq!(query("redirect_uri").as_deref(), Some(CALLBACK_URL));
    assert_eq!(query("code_challenge_method").as_deref(), Some("S256"));
    assert_eq!(query("state").as_deref(), Some(session.state()));
    assert_eq!(query("prompt").as_deref(), Some("select_account"));
    assert_eq!(session.code_verifier().len(), 43);
    assert_eq!(
        query("code_challenge").as_deref(),
        Some(s256(session.code_verifier()).as_str()),
        "the login URL publishes the S256 of the verifier"
    );

    let callback = devin_callback(&format!("code=callback-code&state={}", session.state()));
    assert_eq!(
        devin_login::complete(&config, "devin", &session, &callback, &store)
            .expect("the exchange completes"),
        "devin"
    );

    let reference = resolve_credential(&config, "devin").expect("the canonical ref");
    let raw: Value =
        serde_json::from_slice(&store.resolve(&reference).expect("stored bytes")).expect("json");
    let mut keys = raw
        .as_object()
        .expect("the stored profile is an object")
        .keys()
        .cloned()
        .collect::<Vec<String>>();
    keys.sort();
    assert_eq!(keys, ["access_token", "expires_at", "refresh_token"]);
    assert_eq!(raw["access_token"], json!(token));
    assert_eq!(raw["refresh_token"], json!(token));
    assert_eq!(raw["expires_at"], json!(TOKEN_EXPIRY));

    let credential = devin_login::read_credential(&store, &reference).expect("stored profile");
    assert_eq!(credential.access_token(), token);
    assert_eq!(credential.refresh_token(), token);
    assert_eq!(credential.expires_at(), TOKEN_EXPIRY);

    let (line, head, body) = {
        let requests = observed.lock().expect("record lock");
        assert_eq!(requests.len(), 1);
        requests[0].clone()
    };
    assert_eq!(line, "POST /auth/cli/token HTTP/1.1");
    let lower = head.to_ascii_lowercase();
    assert!(lower.contains("accept: application/json"), "{head}");
    assert!(lower.contains("content-type: application/json"), "{head}");
    assert!(
        !lower.contains("application/x-www-form-urlencoded"),
        "the recorded body is json, not a form: {head}"
    );
    let parsed: Value = serde_json::from_str(&body).expect("the token body is json");
    assert_eq!(
        parsed,
        json!({ "code": "callback-code", "code_verifier": session.code_verifier() })
    );
}

#[test]
fn devin_expired_jwt_and_no_refresh_deny_typed() {
    const YEAR: u64 = 365 * 24 * 60 * 60;
    let expired_at = now_seconds().saturating_sub(60);
    let expired = jwt_token(&json!({ "sub": "devin-user", "exp": expired_at }));
    let reply = devin_reply(&expired);
    let peer = TestPeer::start(move |_line, _head, _body| (200, reply.clone()));

    let config = devin_config();
    let store = support::MapStore::new(StoreKind::Keychain);
    let session = devin_login::begin_login(&devin_endpoints(&peer)).expect("entropy");
    let callback = devin_callback(&format!("code=callback-code&state={}", session.state()));
    assert_eq!(
        devin_login::complete(&config, "devin", &session, &callback, &store)
            .expect("the expired profile is recorded, not silently renewed"),
        "devin"
    );

    let reference = resolve_credential(&config, "devin").expect("the canonical ref");
    let raw: Value =
        serde_json::from_slice(&store.resolve(&reference).expect("stored bytes")).expect("json");
    assert_eq!(raw["expires_at"], json!(expired_at));
    let error = devin_login::read_credential(&store, &reference)
        .expect_err("an expired profile denies: the recorded class offers no refresh");
    assert!(matches!(&error, DevinLoginError::Expired), "{error}");
    let rendered = format!("{error} {error:?}");
    assert!(rendered.contains("no refresh"), "{rendered}");
    assert!(!rendered.contains(&expired), "{rendered}");

    let exp_less = jwt_token(&json!({ "sub": "devin-user" }));
    let reply = devin_reply(&exp_less);
    let peer = TestPeer::start(move |_line, _head, _body| (200, reply.clone()));
    let store = support::MapStore::new(StoreKind::Keychain);
    let session = devin_login::begin_login(&devin_endpoints(&peer)).expect("entropy");
    let callback = devin_callback(&format!("code=callback-code&state={}", session.state()));
    let before = now_seconds();
    assert_eq!(
        devin_login::complete(&config, "devin", &session, &callback, &store)
            .expect("the fallback profile is recorded"),
        "devin"
    );
    let after = now_seconds();
    let reference = resolve_credential(&config, "devin").expect("the canonical ref");
    let credential =
        devin_login::read_credential(&store, &reference).expect("the fallback profile reads");
    assert!(credential.expires_at() >= before + YEAR);
    assert!(
        credential.expires_at() <= after + YEAR,
        "the recorded fallback is 365 days, not cursor's one hour"
    );

    let opaque = devin_reply("opaque-token");
    let peer = TestPeer::start(move |_line, _head, _body| (200, opaque.clone()));
    let store = support::MapStore::new(StoreKind::Keychain);
    let session = devin_login::begin_login(&devin_endpoints(&peer)).expect("entropy");
    let callback = devin_callback(&format!("code=callback-code&state={}", session.state()));
    let before = now_seconds();
    assert_eq!(
        devin_login::complete(&config, "devin", &session, &callback, &store)
            .expect("the opaque profile is recorded"),
        "devin"
    );
    let after = now_seconds();
    let credential =
        devin_login::read_credential(&store, &reference).expect("the opaque profile reads");
    assert_eq!(credential.access_token(), "opaque-token");
    assert!(credential.expires_at() >= before + YEAR);
    assert!(credential.expires_at() <= after + YEAR);
}

#[test]
fn devin_cancelled_or_wrong_state_does_not_activate() {
    let requests = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&requests);
    let token = jwt_token(&json!({ "sub": "devin-user", "exp": TOKEN_EXPIRY }));
    let peer = TestPeer::start(move |_line, _head, _body| {
        counter.fetch_add(1, Ordering::SeqCst);
        (200, devin_reply(&token))
    });
    let config = devin_config();
    let store = support::MapStore::new(StoreKind::Keychain);
    let session = devin_login::begin_login(&devin_endpoints(&peer)).expect("entropy");
    let state = session.state();
    let reference = resolve_credential(&config, "devin").expect("the canonical ref");

    let error = devin_login::complete(
        &config,
        "devin",
        &session,
        &format!("http://127.0.0.1:59654/callback?code=callback-code&state={state}"),
        &store,
    )
    .expect_err("a foreign callback port denies");
    assert!(
        matches!(&error, DevinLoginError::CallbackNotRecorded { .. }),
        "{error}"
    );
    let error = devin_login::complete(
        &config,
        "devin",
        &session,
        &format!("https://evil.example/callback?code=callback-code&state={state}"),
        &store,
    )
    .expect_err("a foreign callback origin denies");
    assert!(
        matches!(&error, DevinLoginError::CallbackNotRecorded { .. }),
        "{error}"
    );
    let callback_code = "callback-code";
    for callback in [
        format!("https://127.0.0.1:59653/callback?code={callback_code}&state={state}"),
        format!("http://127.0.0.1:59653/cb?code={callback_code}&state={state}"),
        format!("http://user:pass@127.0.0.1:59653/callback?code={callback_code}&state={state}"),
    ] {
        let error = devin_login::complete(&config, "devin", &session, &callback, &store)
            .expect_err("a foreign callback scheme, userinfo or path denies");
        assert!(
            matches!(&error, DevinLoginError::CallbackNotRecorded { .. }),
            "{error}"
        );
        let rendered = format!("{error} {error:?}");
        assert!(!rendered.contains(callback_code), "{rendered}");
        assert!(!rendered.contains(state), "{rendered}");
    }
    let error = devin_login::complete(
        &config,
        "devin",
        &session,
        &devin_callback("code=callback-code&state=not-the-minted-state"),
        &store,
    )
    .expect_err("a wrong state denies");
    assert!(matches!(&error, DevinLoginError::StateMismatch), "{error}");
    let error = devin_login::complete(
        &config,
        "devin",
        &session,
        &devin_callback(&format!("error=access_denied&state={state}")),
        &store,
    )
    .expect_err("a cancelled callback denies");
    assert!(matches!(&error, DevinLoginError::Cancelled), "{error}");
    let error = devin_login::complete(
        &config,
        "devin",
        &session,
        &devin_callback(&format!("state={state}")),
        &store,
    )
    .expect_err("a callback without a code denies");
    assert!(
        matches!(&error, DevinLoginError::MissingField { field: "code" }),
        "{error}"
    );

    assert_eq!(requests.load(Ordering::SeqCst), 0);
    assert!(matches!(
        store.resolve(&reference),
        Err(ProviderError::CredentialAbsent { .. })
    ));

    let prior = b"prior-devin-material";
    let prior_store =
        support::MapStore::seeded(StoreKind::Keychain, &[(DEVIN_REF, "prior-devin-material")]);
    let error = devin_login::complete(
        &config,
        "devin",
        &session,
        &devin_callback(&format!("error=access_denied&state={state}")),
        &prior_store,
    )
    .expect_err("a cancellation leaves the prior profile untouched");
    assert!(matches!(&error, DevinLoginError::Cancelled), "{error}");
    assert_eq!(prior_store.resolve(&reference).expect("prior bytes"), prior);
    assert_eq!(requests.load(Ordering::SeqCst), 0);

    let refused =
        TestPeer::start(|_line, _head, _body| (401, json!({ "error": "rejected" }).to_string()));
    let store =
        support::MapStore::seeded(StoreKind::Keychain, &[(DEVIN_REF, "prior-devin-material")]);
    let session = devin_login::begin_login(&devin_endpoints(&refused)).expect("entropy");
    let callback = devin_callback(&format!("code=callback-code&state={}", session.state()));
    let error = devin_login::complete(&config, "devin", &session, &callback, &store)
        .expect_err("the peer rejected the exchange");
    assert!(
        matches!(&error, DevinLoginError::TokenRejected { status: 401 }),
        "{error}"
    );
    assert_eq!(store.resolve(&reference).expect("prior bytes"), prior);
}

#[test]
fn devin_malformed_token_reply_keeps_the_prior_profile() {
    let config = devin_config();
    let reference = resolve_credential(&config, "devin").expect("the canonical ref");
    let prior = b"prior-devin-material";

    for (payload, expected_field) in [
        ("not-json".to_string(), None),
        ("{}".to_string(), Some("token")),
        (json!({ "token": 123 }).to_string(), Some("token")),
    ] {
        let requests = Arc::new(Mutex::new(Vec::<String>::new()));
        let recorded = Arc::clone(&requests);
        let peer = TestPeer::start(move |line, _head, _body| {
            recorded.lock().expect("record lock").push(line.to_string());
            (200, payload.clone())
        });
        let store =
            support::MapStore::seeded(StoreKind::Keychain, &[(DEVIN_REF, "prior-devin-material")]);
        let session = devin_login::begin_login(&devin_endpoints(&peer)).expect("entropy");
        let callback = devin_callback(&format!("code=callback-code&state={}", session.state()));
        let error = devin_login::complete(&config, "devin", &session, &callback, &store)
            .expect_err("a malformed token reply denies");
        match expected_field {
            Some(field) => assert!(
                matches!(error, DevinLoginError::MissingField { field: observed } if observed == field),
                "{error}"
            ),
            None => assert!(
                matches!(error, DevinLoginError::MalformedResponse { .. }),
                "{error}"
            ),
        }
        assert_eq!(store.resolve(&reference).expect("prior bytes"), prior);
        let requests = requests.lock().expect("record lock");
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0], "POST /auth/cli/token HTTP/1.1");
    }
}

#[test]
fn devin_foreign_endpoints_deny_before_any_request() {
    let requests = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&requests);
    let peer = TestPeer::start(move |_line, _head, _body| {
        counter.fetch_add(1, Ordering::SeqCst);
        (200, String::new())
    });
    let recorded = DevinEndpoints::recorded();
    let userinfo_origin = format!(
        "https://user:pass@{}",
        peer.base.trim_start_matches("http://")
    );

    for endpoints in [
        DevinEndpoints {
            authorize: "https://evil.example/auth/cli/continue".to_string(),
            ..recorded.clone()
        },
        DevinEndpoints {
            token: "https://evil.example/auth/cli/token".to_string(),
            ..recorded.clone()
        },
        DevinEndpoints {
            authorize: format!("{userinfo_origin}/auth/cli/continue"),
            ..recorded.clone()
        },
    ] {
        let error = devin_login::begin_login(&endpoints).expect_err("a foreign endpoint denies");
        assert!(
            matches!(error, DevinLoginError::EndpointNotRecorded { .. }),
            "{error}"
        );
    }
    assert_eq!(requests.load(Ordering::SeqCst), 0);
}

#[test]
fn devin_read_and_config_negatives_deny_with_zero_requests() {
    let config = devin_config();
    let reference = resolve_credential(&config, "devin").expect("the canonical ref");

    let malformed = support::MapStore::seeded(StoreKind::Keychain, &[(DEVIN_REF, "not-a-profile")]);
    let error = devin_login::read_credential(&malformed, &reference)
        .expect_err("foreign stored material denies");
    assert!(
        matches!(error, DevinLoginError::StoredCredentialMalformed { .. }),
        "{error}"
    );

    let requests = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&requests);
    let peer = TestPeer::start(move |_line, _head, _body| {
        counter.fetch_add(1, Ordering::SeqCst);
        (200, String::new())
    });
    let prior = b"prior-devin-material";
    let store =
        support::MapStore::seeded(StoreKind::Keychain, &[(DEVIN_REF, "prior-devin-material")]);
    let session = devin_login::begin_login(&devin_endpoints(&peer)).expect("entropy");
    let callback = devin_callback(&format!("code=callback-code&state={}", session.state()));

    let undeclared = config_without_cursor();
    let error = devin_login::complete(&undeclared, "devin", &session, &callback, &store)
        .expect_err("an undeclared connection denies");
    assert!(
        matches!(error, DevinLoginError::ConnectionMissing { .. }),
        "{error}"
    );

    let subscription = subscription_devin_config();
    let error = devin_login::complete(&subscription, "devin", &session, &callback, &store)
        .expect_err("a subscription connection denies");
    assert!(
        matches!(
            error,
            DevinLoginError::NotApiKey {
                kind: ConnKind::Subscription,
                ..
            }
        ),
        "{error}"
    );

    assert_eq!(requests.load(Ordering::SeqCst), 0);
    assert_eq!(store.resolve(&reference).expect("prior bytes"), prior);
}

#[test]
fn devin_occupied_scope_keeps_the_prior_profile() {
    let prior = b"prior-devin-material";
    let token = jwt_token(&json!({ "sub": "devin-user", "exp": TOKEN_EXPIRY }));
    let reply = devin_reply(&token);
    let peer = TestPeer::start(move |_line, _head, _body| (200, reply.clone()));
    let config = devin_config();
    let store =
        support::MapStore::seeded(StoreKind::Keychain, &[(DEVIN_REF, "prior-devin-material")]);
    let session = devin_login::begin_login(&devin_endpoints(&peer)).expect("entropy");
    let callback = devin_callback(&format!("code=callback-code&state={}", session.state()));
    let error = devin_login::complete(&config, "devin", &session, &callback, &store)
        .expect_err("create-only enrollment refuses an occupied scope");
    assert!(
        matches!(
            &error,
            DevinLoginError::Provider(ProviderError::CredentialOccupied { .. })
        ),
        "{error}"
    );
    let reference = resolve_credential(&config, "devin").expect("the canonical ref");
    assert_eq!(store.resolve(&reference).expect("prior bytes"), prior);
}

#[test]
fn devin_failed_store_write_keeps_the_prior_profile() {
    let prior = b"prior-devin-material";
    let token = jwt_token(&json!({ "sub": "devin-user", "exp": TOKEN_EXPIRY }));
    let reply = devin_reply(&token);
    let peer = TestPeer::start(move |_line, _head, _body| (200, reply.clone()));
    let config = devin_config();
    let store = RefusingLoginStore {
        inner: support::MapStore::seeded(
            StoreKind::Keychain,
            &[(DEVIN_REF, "prior-devin-material")],
        ),
    };
    let session = devin_login::begin_login(&devin_endpoints(&peer)).expect("entropy");
    let callback = devin_callback(&format!("code=callback-code&state={}", session.state()));
    let error = devin_login::complete(&config, "devin", &session, &callback, &store)
        .expect_err("a refused store write denies");
    assert!(
        matches!(
            &error,
            DevinLoginError::Provider(ProviderError::StoreUnavailable { .. })
        ),
        "{error}"
    );
    let reference = resolve_credential(&config, "devin").expect("the canonical ref");
    assert_eq!(store.resolve(&reference).expect("prior bytes"), prior);
}

#[test]
fn devin_profile_never_prints_secrets() {
    let token = jwt_token(&json!({ "sub": "devin-user", "exp": TOKEN_EXPIRY }));
    let reply = devin_reply(&token);
    let peer = TestPeer::start(move |_line, _head, _body| (200, reply.clone()));
    let config = devin_config();
    let store = support::MapStore::new(StoreKind::Keychain);
    let session = devin_login::begin_login(&devin_endpoints(&peer)).expect("entropy");
    let verifier = session.code_verifier().to_string();
    let callback = devin_callback(&format!("code=callback-code&state={}", session.state()));
    let profile = devin_login::complete(&config, "devin", &session, &callback, &store)
        .expect("the exchange completes");
    assert_eq!(profile, "devin");

    let reference = resolve_credential(&config, "devin").expect("the canonical ref");
    let credential = devin_login::read_credential(&store, &reference).expect("stored profile");
    let session_debug = format!("{session:?}");
    assert!(session_debug.contains("<redacted>"));
    assert!(!session_debug.contains(&verifier), "{session_debug}");
    let credential_debug = format!("{credential:?}");
    assert!(credential_debug.contains("<redacted>"));
    assert!(!credential_debug.contains(&token), "{credential_debug}");

    let malformed_json =
        serde_json::from_slice::<Value>(b"not-json").expect_err("the fixture is not an object");
    let serialization = serde_json::from_slice::<Value>(b"{").expect_err("the fixture is not json");
    let clock = UNIX_EPOCH
        .duration_since(SystemTime::now())
        .expect_err("the wall clock is after the unix epoch");
    let errors = vec![
        DevinLoginError::TokenRejected { status: 403 },
        DevinLoginError::MissingField { field: "code" },
        DevinLoginError::Expired,
        DevinLoginError::ResponseTooLarge,
        DevinLoginError::MalformedResponse {
            cause: malformed_json,
        },
        DevinLoginError::StoredCredentialMalformed {
            reason: "a value outside the profile shape",
        },
        DevinLoginError::Serialization {
            cause: serialization,
        },
        DevinLoginError::Clock { cause: clock },
        DevinLoginError::EndpointNotRecorded {
            origin: "https://evil.example".to_string(),
        },
        DevinLoginError::CallbackNotRecorded {
            origin: "https://evil.example".to_string(),
        },
        DevinLoginError::StateMismatch,
        DevinLoginError::Cancelled,
        DevinLoginError::ConnectionMissing {
            connection: "devin".to_string(),
        },
        DevinLoginError::NotApiKey {
            connection: "devin".to_string(),
            kind: ConnKind::Local,
        },
        DevinLoginError::Provider(ProviderError::StoreUnavailable {
            store: StoreKind::Keychain,
            reason: "fixture refusal".to_string(),
        }),
    ];
    for error in &errors {
        let rendered = format!("{error} {error:?}");
        assert!(!rendered.contains(&token), "{rendered}");
        assert!(!rendered.contains(&verifier), "{rendered}");
    }
}

#[test]
fn copilot_device_flow_pending_slow_down_denial_and_expiry_are_bounded() {
    let observed = Arc::new(Mutex::new(Vec::<(String, String, String)>::new()));
    let token_polls = Arc::new(AtomicUsize::new(0));
    let recorded = Arc::clone(&observed);
    let counter = Arc::clone(&token_polls);
    let peer = TestPeer::start(move |line, head, body| {
        recorded.lock().expect("record lock").push((
            line.to_string(),
            head.to_string(),
            body.to_string(),
        ));
        if line.contains("/login/device/code") {
            (200, copilot_device_reply(5, 900))
        } else {
            match counter.fetch_add(1, Ordering::SeqCst) {
                0 => (200, copilot_error_reply("authorization_pending")),
                1 => (200, copilot_error_reply("slow_down")),
                _ => (200, copilot_error_reply("access_denied")),
            }
        }
    });
    let config = copilot_config();
    let prior = b"prior-copilot-material";
    let store = support::MapStore::seeded(
        StoreKind::Keychain,
        &[(COPILOT_REF, "prior-copilot-material")],
    );
    let started = Instant::now();
    let mut session =
        copilot_login::begin_device("", copilot_endpoints(&peer)).expect("device code");
    let begun = Instant::now();
    assert_eq!(session.domain(), "github.com");
    assert_eq!(session.enterprise_url(), None);
    assert_eq!(session.api_endpoint(), None);
    assert_eq!(
        session.verification_uri(),
        "https://github.com/login/device"
    );
    assert_eq!(session.user_code(), COPILOT_USER_CODE);
    assert_eq!(session.interval(), Duration::from_secs(5));
    assert_eq!(session.expires_in(), 900);
    assert!(session.next_poll_at() >= started + Duration::from_secs(5));
    assert!(session.next_poll_at() <= begun + Duration::from_secs(5));

    assert!(matches!(
        copilot_login::advance(&config, "github-copilot", &mut session, &store).expect("pending"),
        CopilotAdvance::Pending
    ));
    assert!(matches!(
        copilot_login::advance(&config, "github-copilot", &mut session, &store).expect("slow down"),
        CopilotAdvance::SlowDown
    ));
    assert_eq!(session.interval(), Duration::from_secs(10));
    let error = copilot_login::advance(&config, "github-copilot", &mut session, &store)
        .expect_err("an operator denial stops the leg");
    assert!(matches!(error, CopilotLoginError::DeviceDenied), "{error}");
    assert_eq!(token_polls.load(Ordering::SeqCst), 3);

    let reference = resolve_credential(&config, "github-copilot").expect("the canonical ref");
    assert_eq!(store.resolve(&reference).expect("prior bytes"), prior);

    {
        let observed = observed.lock().expect("record lock");
        let device = observed
            .iter()
            .find(|(line, ..)| line.contains("/login/device/code"))
            .expect("the device-code request was recorded");
        assert_copilot_identity(&device.1);
        assert!(device.2.contains("client_id=Ov23ctDVkRmgkPke0Mmm"));
        assert!(device.2.contains("scope=read%3Auser"));
        let polls: Vec<_> = observed
            .iter()
            .filter(|(line, ..)| line.contains("/login/oauth/access_token"))
            .collect();
        assert_eq!(polls.len(), 3);
        for (_, head, body) in polls {
            assert_copilot_identity(head);
            assert!(body.contains("device_code=fixture-device-code"));
            assert!(
                body.contains("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code")
            );
        }
        drop(observed);
    }

    let expired_peer = TestPeer::start(|line, _head, _body| {
        if line.contains("/login/device/code") {
            (200, copilot_device_reply(5, 900))
        } else {
            (200, copilot_error_reply("expired_token"))
        }
    });
    let mut expired =
        copilot_login::begin_device("", copilot_endpoints(&expired_peer)).expect("device code");
    let error = copilot_login::advance(&config, "github-copilot", &mut expired, &store)
        .expect_err("the peer expiry stops the leg");
    assert!(matches!(error, CopilotLoginError::DeviceExpired), "{error}");

    let deadline_requests = Arc::new(AtomicUsize::new(0));
    let deadline_count = Arc::clone(&deadline_requests);
    let deadline_peer = TestPeer::start(move |line, _head, _body| {
        if line.contains("/login/device/code") {
            (200, copilot_device_reply(5, 0))
        } else {
            deadline_count.fetch_add(1, Ordering::SeqCst);
            (200, copilot_token_reply(COPILOT_TOKEN))
        }
    });
    let mut deadline =
        copilot_login::begin_device("", copilot_endpoints(&deadline_peer)).expect("device code");
    let error = copilot_login::advance(&config, "github-copilot", &mut deadline, &store)
        .expect_err("an elapsed device window stops the leg");
    assert!(matches!(error, CopilotLoginError::DeviceExpired), "{error}");
    assert_eq!(deadline_requests.load(Ordering::SeqCst), 0);

    let cancelled_peer = TestPeer::start(|line, _head, _body| {
        if line.contains("/login/device/code") {
            (200, copilot_device_reply(5, 900))
        } else {
            (0, String::new())
        }
    });
    let mut cancelled =
        copilot_login::begin_device("", copilot_endpoints(&cancelled_peer)).expect("device code");
    let error = copilot_login::advance(&config, "github-copilot", &mut cancelled, &store)
        .expect_err("a closed poll is a typed transport denial");
    assert!(
        matches!(
            error,
            CopilotLoginError::Provider(ProviderError::Transport { .. })
        ),
        "{error}"
    );
    assert_eq!(store.resolve(&reference).expect("prior bytes"), prior);
}

#[test]
fn copilot_unknown_peer_error_text_is_never_echoed() {
    let peer = TestPeer::start(|line, _head, _body| {
        if line.contains("/login/device/code") {
            (200, copilot_device_reply(5, 900))
        } else {
            (200, copilot_error_reply(COPILOT_DEVICE_CODE))
        }
    });
    let config = copilot_config();
    let store = support::MapStore::new(StoreKind::Keychain);
    let reference = resolve_credential(&config, "github-copilot").expect("the canonical ref");
    let mut session =
        copilot_login::begin_device("", copilot_endpoints(&peer)).expect("device code");
    let error = copilot_login::advance(&config, "github-copilot", &mut session, &store)
        .expect_err("an unknown peer error denies");
    assert!(
        matches!(&error, CopilotLoginError::Denied { code } if code == "unknown device error"),
        "{error}"
    );
    let rendered = format!("{error} {error:?}");
    assert!(!rendered.contains(COPILOT_DEVICE_CODE), "{rendered}");
    assert!(
        matches!(
            store.resolve(&reference),
            Err(ProviderError::CredentialAbsent { .. })
        ),
        "an unknown peer error must not enroll"
    );
}

#[test]
fn copilot_success_after_the_device_window_denies_without_storing() {
    let peer = TestPeer::start(|line, _head, _body| {
        if line.contains("/login/device/code") {
            (200, copilot_device_reply(5, 1))
        } else {
            std::thread::sleep(Duration::from_millis(1_100));
            (200, copilot_token_reply(COPILOT_TOKEN))
        }
    });
    let config = copilot_config();
    let store = support::MapStore::new(StoreKind::Keychain);
    let reference = resolve_credential(&config, "github-copilot").expect("the canonical ref");
    let mut session =
        copilot_login::begin_device("", copilot_endpoints(&peer)).expect("device code");
    let error = copilot_login::advance(&config, "github-copilot", &mut session, &store)
        .expect_err("a success past the device window denies");
    assert!(matches!(error, CopilotLoginError::DeviceExpired), "{error}");
    assert!(
        matches!(
            store.resolve(&reference),
            Err(ProviderError::CredentialAbsent { .. })
        ),
        "a late success must not enroll"
    );
}

#[test]
fn copilot_reply_negatives_deny_without_activation() {
    let config = copilot_config();
    let store = support::MapStore::new(StoreKind::Keychain);
    let reference = resolve_credential(&config, "github-copilot").expect("the canonical ref");

    let refused = TestPeer::start(|_line, _head, _body| (403, String::new()));
    let error = copilot_login::begin_device("", copilot_endpoints(&refused))
        .expect_err("a non-success device reply denies");
    assert!(
        matches!(error, CopilotLoginError::TokenRejected { status: 403 }),
        "{error}"
    );

    let garbage = TestPeer::start(|_line, _head, _body| (200, "not-json".to_string()));
    let error = copilot_login::begin_device("", copilot_endpoints(&garbage))
        .expect_err("a malformed device reply denies");
    assert!(
        matches!(error, CopilotLoginError::MalformedResponse { .. }),
        "{error}"
    );

    let refusing = TestPeer::start(|line, _head, _body| {
        if line.contains("/login/device/code") {
            (200, copilot_device_reply(5, 900))
        } else {
            (500, "{}".to_string())
        }
    });
    let mut session =
        copilot_login::begin_device("", copilot_endpoints(&refusing)).expect("device code");
    let error = copilot_login::advance(&config, "github-copilot", &mut session, &store)
        .expect_err("a non-success poll without an error member denies");
    assert!(
        matches!(error, CopilotLoginError::TokenRejected { status: 500 }),
        "{error}"
    );

    assert!(
        matches!(
            store.resolve(&reference),
            Err(ProviderError::CredentialAbsent { .. })
        ),
        "no negative path may enroll"
    );
}

#[test]
fn copilot_enterprise_domain_normalizes_and_wrong_ghe_origin_denies() {
    let requests = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&requests);
    let peer = TestPeer::start(move |line, _head, _body| {
        counter.fetch_add(1, Ordering::SeqCst);
        if line.contains("/login/oauth/access_token") {
            (200, copilot_token_reply(COPILOT_TOKEN))
        } else {
            (200, copilot_device_reply(5, 900))
        }
    });
    for input in [
        "",
        "github.com",
        "https://api.github.com/ignored",
        "www.github.com",
    ] {
        let session = copilot_login::begin_device(input, copilot_endpoints(&peer))
            .expect("a public input uses github.com");
        assert_eq!(session.domain(), "github.com", "{input}");
        assert_eq!(session.enterprise_url(), None, "{input}");
        assert_eq!(session.api_endpoint(), None, "{input}");
    }

    let enterprise_peer = TestPeer::start(|line, _head, _body| {
        if line.contains("/login/oauth/access_token") {
            (200, copilot_token_reply(COPILOT_TOKEN))
        } else {
            (
                200,
                copilot_device_reply_with_uri("https://company.ghe.com/login/device", 5, 900),
            )
        }
    });
    let config = copilot_config();
    let store = support::MapStore::new(StoreKind::Keychain);
    let mut enterprise = copilot_login::begin_device(
        "  https://company.ghe.com/some/path  ",
        copilot_endpoints(&enterprise_peer),
    )
    .expect("the enterprise host normalizes");
    assert_eq!(enterprise.domain(), "company.ghe.com");
    assert_eq!(enterprise.enterprise_url(), Some("company.ghe.com"));
    assert_eq!(
        enterprise.api_endpoint(),
        Some("https://copilot-api.company.ghe.com")
    );
    assert!(matches!(
        copilot_login::advance(&config, "github-copilot", &mut enterprise, &store)
            .expect("the device grant completes"),
        CopilotAdvance::Complete(_)
    ));
    let reference = resolve_credential(&config, "github-copilot").expect("the canonical ref");
    let stored = copilot_login::read_credential(&store, &reference).expect("stored profile");
    assert_eq!(stored.token(), COPILOT_TOKEN);
    assert_eq!(stored.enterprise_url(), Some("company.ghe.com"));
    assert_eq!(
        stored.api_endpoint(),
        Some("https://copilot-api.company.ghe.com")
    );
    let now = now_seconds();
    let ten_years = 10 * 365 * 24 * 60 * 60;
    assert!(stored.expires_at() >= now + ten_years);
    assert!(stored.expires_at() <= now + 315_576_000 + 120);
    let prior = store.resolve(&reference).expect("stored bytes");
    let raw: Value = serde_json::from_slice(&prior).expect("stored json");
    assert_eq!(
        raw.get("enterprise_url").and_then(Value::as_str),
        Some("company.ghe.com")
    );
    assert_eq!(
        raw.get("api_endpoint").and_then(Value::as_str),
        Some("https://copilot-api.company.ghe.com")
    );

    let copilot_api_peer = TestPeer::start(|line, _head, _body| {
        if line.contains("/login/oauth/access_token") {
            (200, copilot_token_reply(COPILOT_TOKEN))
        } else {
            (
                200,
                copilot_device_reply_with_uri(
                    "https://copilot-api.company.ghe.com/login/device",
                    5,
                    900,
                ),
            )
        }
    });
    let copilot_api = copilot_login::begin_device(
        "copilot-api.company.ghe.com",
        copilot_endpoints(&copilot_api_peer),
    )
    .expect("the recorded copilot-api prefix is not doubled");
    assert_eq!(copilot_api.domain(), "copilot-api.company.ghe.com");
    assert_eq!(
        copilot_api.enterprise_url(),
        Some("copilot-api.company.ghe.com")
    );
    assert_eq!(
        copilot_api.api_endpoint(),
        Some("https://copilot-api.company.ghe.com")
    );

    let before = requests.load(Ordering::SeqCst);
    for input in ["https://", "not a host"] {
        let error = copilot_login::begin_device(input, copilot_endpoints(&peer))
            .expect_err("an unusable enterprise origin denies");
        assert!(matches!(error, CopilotLoginError::InvalidDomain), "{error}");
    }
    let foreign = CopilotEndpoints {
        device_code: "https://evil.example/login/device/code".to_string(),
        access_token: peer.url("/login/oauth/access_token"),
    };
    let error = copilot_login::begin_device("company.ghe.com", foreign)
        .expect_err("a foreign device origin denies before any request");
    assert!(
        matches!(error, CopilotLoginError::EndpointNotRecorded { .. }),
        "{error}"
    );
    let userinfo = CopilotEndpoints {
        device_code: format!("http://user:pass@{}", &peer.base["http://".len()..]),
        access_token: peer.url("/login/oauth/access_token"),
    };
    let error = copilot_login::begin_device("company.ghe.com", userinfo)
        .expect_err("userinfo never impersonates the loopback host");
    assert!(
        matches!(error, CopilotLoginError::EndpointNotRecorded { .. }),
        "{error}"
    );
    let rendered = format!("{error} {error:?}");
    assert!(!rendered.contains("user:pass"), "{rendered}");
    assert!(!rendered.contains("pass@"), "{rendered}");
    let foreign_token = CopilotEndpoints {
        device_code: peer.url("/login/device/code"),
        access_token: "https://evil.example/login/oauth/access_token".to_string(),
    };
    let error = copilot_login::begin_device("company.ghe.com", foreign_token)
        .expect_err("a foreign access-token origin denies before any request");
    assert!(
        matches!(error, CopilotLoginError::EndpointNotRecorded { .. }),
        "{error}"
    );
    let token_userinfo = CopilotEndpoints {
        device_code: peer.url("/login/device/code"),
        access_token: format!(
            "http://user:pass@{}/login/oauth/access_token",
            &peer.base["http://".len()..]
        ),
    };
    let error = copilot_login::begin_device("company.ghe.com", token_userinfo)
        .expect_err("access-token userinfo never impersonates the loopback host");
    assert!(
        matches!(error, CopilotLoginError::EndpointNotRecorded { .. }),
        "{error}"
    );
    let rendered = format!("{error} {error:?}");
    assert!(!rendered.contains("user:pass"), "{rendered}");
    assert!(!rendered.contains("pass@"), "{rendered}");
    assert_eq!(requests.load(Ordering::SeqCst), before);
    assert_eq!(store.resolve(&reference).expect("stored bytes"), prior);
}

#[test]
fn copilot_login_never_posts_model_policy() {
    let observed = Arc::new(Mutex::new(Vec::<(String, String, String)>::new()));
    let recorded = Arc::clone(&observed);
    let peer = TestPeer::start(move |line, head, body| {
        recorded.lock().expect("record lock").push((
            line.to_string(),
            head.to_string(),
            body.to_string(),
        ));
        if line.contains("/login/oauth/access_token") {
            (200, copilot_token_reply(COPILOT_TOKEN))
        } else {
            (200, copilot_device_reply(5, 900))
        }
    });
    let config = copilot_config();
    let store = support::MapStore::new(StoreKind::Keychain);
    let mut session =
        copilot_login::begin_device("", copilot_endpoints(&peer)).expect("device code");
    assert!(matches!(
        copilot_login::advance(&config, "github-copilot", &mut session, &store)
            .expect("the device grant completes"),
        CopilotAdvance::Complete(_)
    ));

    let observed = observed.lock().expect("record lock");
    assert_eq!(observed.len(), 2, "{observed:?}");
    for (line, _head, body) in observed.iter() {
        let lower = line.to_ascii_lowercase();
        assert!(line.starts_with("POST "), "{line}");
        assert!(!lower.contains("/models/"), "{line}");
        assert!(!lower.contains("policy"), "{line}");
        if line.contains("/login/oauth/access_token") {
            assert!(body.contains("device_code=fixture-device-code"));
            assert!(
                body.contains("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code")
            );
        }
    }
    drop(observed);

    let endpoints = CopilotEndpoints::recorded("company.ghe.com");
    assert_eq!(
        endpoints.device_code,
        "https://company.ghe.com/login/device/code"
    );
    assert_eq!(
        endpoints.access_token,
        "https://company.ghe.com/login/oauth/access_token"
    );
    let reference = resolve_credential(&config, "github-copilot").expect("the canonical ref");
    let stored = copilot_login::read_credential(&store, &reference).expect("stored profile");
    assert_eq!(stored.token(), COPILOT_TOKEN);
    assert_eq!(stored.enterprise_url(), None);
    assert_eq!(stored.api_endpoint(), None);
    let raw: Value =
        serde_json::from_slice(&store.resolve(&reference).expect("stored bytes")).expect("json");
    assert_eq!(
        raw.get("token").and_then(Value::as_str),
        Some(COPILOT_TOKEN)
    );
    assert!(raw.get("enterprise_url").is_none(), "{raw}");
    assert!(raw.get("api_endpoint").is_none(), "{raw}");
    assert!(raw.get("expires_at").and_then(Value::as_u64).is_some());
}

#[test]
fn copilot_occupied_scope_keeps_the_prior_profile() {
    let prior = b"prior-copilot-material";
    let peer = TestPeer::start(|line, _head, _body| {
        if line.contains("/login/oauth/access_token") {
            (200, copilot_token_reply(COPILOT_TOKEN))
        } else {
            (200, copilot_device_reply(5, 900))
        }
    });
    let config = copilot_config();
    let store = support::MapStore::seeded(
        StoreKind::Keychain,
        &[(COPILOT_REF, "prior-copilot-material")],
    );
    let mut session =
        copilot_login::begin_device("", copilot_endpoints(&peer)).expect("device code");
    let error = copilot_login::advance(&config, "github-copilot", &mut session, &store)
        .expect_err("create-only enrollment refuses an occupied scope");
    assert!(
        matches!(
            &error,
            CopilotLoginError::Provider(ProviderError::CredentialOccupied { .. })
        ),
        "{error}"
    );
    let reference = resolve_credential(&config, "github-copilot").expect("the canonical ref");
    assert_eq!(store.resolve(&reference).expect("prior bytes"), prior);
}

#[test]
fn copilot_failed_store_write_keeps_the_prior_profile() {
    let prior = b"prior-copilot-material";
    let peer = TestPeer::start(|line, _head, _body| {
        if line.contains("/login/oauth/access_token") {
            (200, copilot_token_reply(COPILOT_TOKEN))
        } else {
            (200, copilot_device_reply(5, 900))
        }
    });
    let config = copilot_config();
    let store = RefusingLoginStore {
        inner: support::MapStore::seeded(
            StoreKind::Keychain,
            &[(COPILOT_REF, "prior-copilot-material")],
        ),
    };
    let mut session =
        copilot_login::begin_device("", copilot_endpoints(&peer)).expect("device code");
    let error = copilot_login::advance(&config, "github-copilot", &mut session, &store)
        .expect_err("a refused store write denies");
    assert!(
        matches!(
            &error,
            CopilotLoginError::Provider(ProviderError::StoreUnavailable { .. })
        ),
        "{error}"
    );
    let reference = resolve_credential(&config, "github-copilot").expect("the canonical ref");
    assert_eq!(store.resolve(&reference).expect("prior bytes"), prior);
}

#[test]
fn copilot_profile_never_prints_secrets() {
    let peer = TestPeer::start(|line, _head, _body| {
        if line.contains("/login/oauth/access_token") {
            (200, copilot_token_reply(COPILOT_TOKEN))
        } else {
            (200, copilot_device_reply(5, 900))
        }
    });
    let config = copilot_config();
    let store = support::MapStore::new(StoreKind::Keychain);
    let mut session =
        copilot_login::begin_device("", copilot_endpoints(&peer)).expect("device code");
    let session_debug = format!("{session:?}");
    assert!(session_debug.contains("<redacted>"));
    assert!(
        !session_debug.contains(COPILOT_DEVICE_CODE),
        "{session_debug}"
    );
    copilot_login::advance(&config, "github-copilot", &mut session, &store)
        .expect("the device grant completes");

    let reference = resolve_credential(&config, "github-copilot").expect("the canonical ref");
    let credential: CopilotStoredCredential =
        copilot_login::read_credential(&store, &reference).expect("stored profile");
    let credential_debug = format!("{credential:?}");
    assert!(credential_debug.contains("<redacted>"));
    assert!(
        !credential_debug.contains(COPILOT_TOKEN),
        "{credential_debug}"
    );

    // Stored endpoints render origin-only: path, query and userinfo never
    // reach `Debug`, and the token stays redacted.
    let enterprise = json!({
        "token": COPILOT_TOKEN,
        "enterprise_url": "company.ghe.com",
        "api_endpoint": "https://api.company.ghe.com/private/path?token=fixture-query-secret",
        "expires_at": 4_102_444_800_u64,
    })
    .to_string();
    let seeded = support::MapStore::seeded(StoreKind::Keychain, &[(COPILOT_REF, &enterprise)]);
    let stored = copilot_login::read_credential(&seeded, &reference).expect("stored profile");
    let stored_debug = format!("{stored:?}");
    assert!(
        stored_debug.contains("https://company.ghe.com"),
        "{stored_debug}"
    );
    assert!(
        stored_debug.contains("https://api.company.ghe.com"),
        "{stored_debug}"
    );
    assert!(!stored_debug.contains("private/path"), "{stored_debug}");
    assert!(
        !stored_debug.contains("fixture-query-secret"),
        "{stored_debug}"
    );
    assert!(!stored_debug.contains(COPILOT_TOKEN), "{stored_debug}");

    let malformed_stored = json!({
        "token": COPILOT_TOKEN,
        "expires_at": COPILOT_DEVICE_CODE,
    })
    .to_string();
    let seeded = support::MapStore::seeded(
        StoreKind::Keychain,
        &[(COPILOT_REF, malformed_stored.as_str())],
    );
    let error = copilot_login::read_credential(&seeded, &reference)
        .expect_err("the stored shape is malformed");
    assert!(
        matches!(error, CopilotLoginError::StoredCredentialMalformed { .. }),
        "{error}"
    );
    let rendered = format!("{error} {error:?}");
    assert!(!rendered.contains(COPILOT_TOKEN), "{rendered}");
    assert!(!rendered.contains(COPILOT_DEVICE_CODE), "{rendered}");

    let malformed_json =
        serde_json::from_slice::<Value>(b"not-json").expect_err("the fixture is not an object");
    let closed = serde_json::from_slice::<CopilotStoredCredential>(
        br#"{"token":"x","expires_at":1,"extra":true}"#,
    )
    .expect_err("the stored shape is closed");
    assert!(closed.to_string().contains("unknown field"), "{closed}");
    let serialization = serde_json::from_slice::<Value>(b"{").expect_err("the fixture is not json");
    let clock = UNIX_EPOCH
        .duration_since(SystemTime::now())
        .expect_err("the wall clock is after the unix epoch");
    let errors = vec![
        CopilotLoginError::InvalidDomain,
        CopilotLoginError::EndpointNotRecorded {
            origin: "https://evil.example".to_string(),
        },
        CopilotLoginError::TokenRejected { status: 403 },
        CopilotLoginError::MissingField {
            field: "access_token",
        },
        CopilotLoginError::MalformedField { field: "interval" },
        CopilotLoginError::DeviceExpiryOutOfRange { seconds: 86_401 },
        CopilotLoginError::DeviceIntervalOutOfRange { seconds: 3_601 },
        CopilotLoginError::DeviceDenied,
        CopilotLoginError::DeviceExpired,
        CopilotLoginError::Denied {
            code: "device_flow_disabled".to_string(),
        },
        CopilotLoginError::ResponseTooLarge,
        CopilotLoginError::MalformedResponse {
            cause: malformed_json,
        },
        CopilotLoginError::StoredCredentialMalformed {
            reason: "invalid json",
        },
        CopilotLoginError::Serialization {
            cause: serialization,
        },
        CopilotLoginError::Clock { cause: clock },
        CopilotLoginError::ConnectionMissing {
            connection: "github-copilot".to_string(),
        },
        CopilotLoginError::NotApiKey {
            connection: "github-copilot".to_string(),
            kind: ConnKind::Local,
        },
        CopilotLoginError::Provider(ProviderError::StoreUnavailable {
            store: StoreKind::Keychain,
            reason: "fixture refusal".to_string(),
        }),
    ];
    for error in &errors {
        let rendered = format!("{error} {error:?}");
        assert!(!rendered.contains(COPILOT_TOKEN), "{rendered}");
        assert!(!rendered.contains(COPILOT_DEVICE_CODE), "{rendered}");
    }
}

const GITLAB_REF: &str = "keychain:rivect-test/gitlab-duo-agent";
const GITLAB_ACCESS: &str = "fixture-gitlab-access";
const GITLAB_REFRESH: &str = "fixture-gitlab-refresh";
const GITLAB_ACCESS_ROTATED: &str = "fixture-gitlab-access-rotated";
const GITLAB_REFRESH_ROTATED: &str = "fixture-gitlab-refresh-rotated";
const GITLAB_PAT: &str = "fixture-gitlab-pat";
const GITLAB_CREATED_AT: u64 = 1_700_000_000;
const GITLAB_NAMESPACE: &str = "group/subgroup";
const GITLAB_PROJECT: &str = "group/subgroup/project";

fn gitlab_config() -> Config {
    Config::parse_validated(
        "config_version = 1\n\
         [connections.gitlab-duo-agent]\n\
         kind = \"api_key\"\n\
         endpoint = \"https://gitlab.com\"\n\
         credential_ref = \"keychain:rivect-test/gitlab-duo-agent\"\n\
         [models.defaults]\n\
         model = { mode = \"auto\" }\n\
         effort = { mode = \"auto\" }\n\
         fallback = { mode = \"auto\" }\n",
    )
    .expect("the gitlab config parses")
}

fn gitlab_scope() -> WorkspaceScope {
    WorkspaceScope::new(
        gitlab_agent_login::ORIGIN,
        GITLAB_NAMESPACE,
        Some(GITLAB_PROJECT),
    )
}

fn gitlab_endpoints(peer: &TestPeer) -> GitlabEndpoints {
    GitlabEndpoints::new(&peer.url("/oauth/authorize"), &peer.url("/oauth/token"))
}

fn gitlab_reply(access: &str, refresh: &str, expires_in: u64, created_at: u64) -> String {
    json!({
        "access_token": access,
        "refresh_token": refresh,
        "expires_in": expires_in,
        "created_at": created_at,
    })
    .to_string()
}

fn gitlab_oauth_profile(access: &str, refresh: &str, expires_at: u64) -> String {
    json!({
        "kind": "oauth",
        "access_token": access,
        "refresh_token": refresh,
        "expires_at": expires_at,
        "origin": gitlab_agent_login::ORIGIN,
        "namespace": GITLAB_NAMESPACE,
        "project": GITLAB_PROJECT,
    })
    .to_string()
}

fn gitlab_pat_profile(token: &str) -> String {
    json!({
        "kind": "pat",
        "access_token": token,
        "origin": gitlab_agent_login::ORIGIN,
        "namespace": GITLAB_NAMESPACE,
        "project": GITLAB_PROJECT,
    })
    .to_string()
}

fn gitlab_callback(code: &str, state: &str) -> String {
    format!("{GITLAB_CALLBACK_URL}?code={code}&state={state}")
}

/// The decoded value of one form member the login POST sent.
fn form_value(body: &str, name: &str) -> Option<String> {
    let url =
        reqwest::Url::parse(&format!("http://form.invalid/?{body}")).expect("the form body parses");
    url.query_pairs()
        .find_map(|(key, value)| (key.as_ref() == name).then(|| value.into_owned()))
}

/// The raw stored bytes at the canonical scope.
fn gitlab_stored(store: &support::MapStore, config: &Config) -> Vec<u8> {
    let reference = resolve_credential(config, "gitlab-duo-agent").expect("the canonical ref");
    store.resolve(&reference).expect("stored bytes")
}

#[test]
fn gitlab_agent_manual_callback_and_pkce_exchange() {
    let observed = Arc::new(Mutex::new(Vec::<(String, String, String)>::new()));
    let recorded = Arc::clone(&observed);
    let reply = gitlab_reply(GITLAB_ACCESS, GITLAB_REFRESH, 7200, GITLAB_CREATED_AT);
    let peer = TestPeer::start(move |line, head, body| {
        recorded.lock().expect("record lock").push((
            line.to_string(),
            head.to_string(),
            body.to_string(),
        ));
        (200, reply.clone())
    });
    let config = gitlab_config();
    let store = support::MapStore::new(StoreKind::Keychain);
    let scope = gitlab_scope();
    let session = gitlab_agent_login::begin_login(&scope, &gitlab_endpoints(&peer))
        .expect("the loopback endpoints mint a session");

    assert_eq!(
        gitlab_agent_login::AUTHORIZE_URL,
        "https://gitlab.com/oauth/authorize"
    );
    assert_eq!(
        gitlab_agent_login::TOKEN_URL,
        "https://gitlab.com/oauth/token"
    );
    assert_eq!(gitlab_agent_login::ORIGIN, "https://gitlab.com");
    assert_eq!(gitlab_agent_login::OAUTH_SCOPE, "api");
    assert_eq!(
        GITLAB_CALLBACK_URL,
        "vscode://gitlab.gitlab-workflow/authentication"
    );
    assert_eq!(
        GITLAB_CLIENT_ID,
        "36f2a70cddeb5a0889d4fd8295c241b7e9848e89cf9e599d0eed2d8e5350fbf5"
    );
    let state = uuid::Uuid::parse_str(session.state()).expect("the state is a uuid");
    assert_eq!(state.get_version_num(), 4);
    let login = reqwest::Url::parse(session.login_url()).expect("the login url parses");
    let query = |name: &str| {
        login
            .query_pairs()
            .find_map(|(key, value)| (key.as_ref() == name).then(|| value.into_owned()))
    };
    assert_eq!(query("client_id").as_deref(), Some(GITLAB_CLIENT_ID));
    assert_eq!(query("response_type").as_deref(), Some("code"));
    assert_eq!(query("redirect_uri").as_deref(), Some(GITLAB_CALLBACK_URL));
    assert_eq!(query("scope").as_deref(), Some("api"));
    assert_eq!(query("code_challenge_method").as_deref(), Some("S256"));
    assert_eq!(query("state").as_deref(), Some(session.state()));
    assert_eq!(session.code_verifier().len(), 43);
    assert_eq!(
        query("code_challenge").as_deref(),
        Some(s256(session.code_verifier()).as_str()),
        "the login URL publishes the S256 of the verifier"
    );

    let callback = gitlab_callback("callback-code", session.state());
    assert_eq!(
        gitlab_agent_login::complete(&config, "gitlab-duo-agent", &session, &callback, &store)
            .expect("the form exchange completes"),
        "gitlab-duo-agent"
    );

    let reference = resolve_credential(&config, "gitlab-duo-agent").expect("the canonical ref");
    let raw: Value =
        serde_json::from_slice(&store.resolve(&reference).expect("stored bytes")).expect("json");
    let mut keys = raw
        .as_object()
        .expect("the stored profile is an object")
        .keys()
        .cloned()
        .collect::<Vec<String>>();
    keys.sort();
    assert_eq!(
        keys,
        [
            "access_token",
            "expires_at",
            "kind",
            "namespace",
            "origin",
            "project",
            "refresh_token",
        ]
    );
    assert_eq!(raw["kind"], json!("oauth"));
    assert_eq!(raw["access_token"], json!(GITLAB_ACCESS));
    assert_eq!(raw["refresh_token"], json!(GITLAB_REFRESH));
    assert_eq!(
        raw["expires_at"],
        json!(GITLAB_CREATED_AT + 7200 - EXPIRY_SKEW)
    );
    assert_eq!(raw["origin"], json!(gitlab_agent_login::ORIGIN));
    assert_eq!(raw["namespace"], json!(GITLAB_NAMESPACE));
    assert_eq!(raw["project"], json!(GITLAB_PROJECT));

    let credential = gitlab_agent_login::read_credential(&store, &reference)
        .expect("the stored workspace profile");
    assert_eq!(credential.kind(), GitlabCredentialKind::Oauth);
    assert_eq!(credential.access_token(), GITLAB_ACCESS);
    assert_eq!(credential.refresh_token(), Some(GITLAB_REFRESH));
    assert_eq!(
        credential.expires_at(),
        Some(GITLAB_CREATED_AT + 7200 - EXPIRY_SKEW)
    );
    assert_eq!(credential.origin(), gitlab_agent_login::ORIGIN);
    assert_eq!(credential.namespace(), GITLAB_NAMESPACE);
    assert_eq!(credential.project(), Some(GITLAB_PROJECT));

    let (line, head, body) = {
        let requests = observed.lock().expect("record lock");
        assert_eq!(
            requests.len(),
            1,
            "no settings PUT and no non-recorded request"
        );
        requests[0].clone()
    };
    assert_eq!(line, "POST /oauth/token HTTP/1.1");
    assert!(
        head.to_ascii_lowercase()
            .contains("content-type: application/x-www-form-urlencoded"),
        "{head}"
    );
    assert_eq!(
        form_value(&body, "client_id").as_deref(),
        Some(GITLAB_CLIENT_ID)
    );
    assert_eq!(
        form_value(&body, "grant_type").as_deref(),
        Some("authorization_code")
    );
    assert_eq!(form_value(&body, "code").as_deref(), Some("callback-code"));
    assert_eq!(
        form_value(&body, "redirect_uri").as_deref(),
        Some(GITLAB_CALLBACK_URL)
    );
    assert_eq!(
        form_value(&body, "code_verifier").as_deref(),
        Some(session.code_verifier())
    );
}

#[test]
fn gitlab_agent_pat_enrollment_stores_the_workspace_scope() {
    let config = gitlab_config();
    let store = support::MapStore::new(StoreKind::Keychain);
    let scope = gitlab_scope();
    assert_eq!(
        gitlab_agent_login::enroll_pat(
            &config,
            "gitlab-duo-agent",
            &format!(" {GITLAB_PAT} "),
            &scope,
            &store
        )
        .expect("the PAT enrolls"),
        "gitlab-duo-agent"
    );

    let blank_store = support::MapStore::new(StoreKind::Keychain);
    let error =
        gitlab_agent_login::enroll_pat(&config, "gitlab-duo-agent", "   ", &scope, &blank_store)
            .expect_err("a whitespace-only token is absent, not a PAT");
    assert!(
        matches!(error, GitlabLoginError::MissingField { field: "token" }),
        "{error}"
    );

    let reference = resolve_credential(&config, "gitlab-duo-agent").expect("the canonical ref");
    assert!(
        matches!(
            blank_store.resolve(&reference),
            Err(ProviderError::CredentialAbsent { .. })
        ),
        "a blank token writes no partial profile"
    );

    let raw: Value =
        serde_json::from_slice(&store.resolve(&reference).expect("stored bytes")).expect("json");
    let mut keys = raw
        .as_object()
        .expect("the stored profile is an object")
        .keys()
        .cloned()
        .collect::<Vec<String>>();
    keys.sort();
    assert_eq!(
        keys,
        ["access_token", "kind", "namespace", "origin", "project",],
        "the PAT form omits refresh and expiry"
    );
    assert_eq!(raw["kind"], json!("pat"));
    assert_eq!(raw["access_token"], json!(GITLAB_PAT));
    assert_eq!(raw["origin"], json!(gitlab_agent_login::ORIGIN));
    assert_eq!(raw["namespace"], json!(GITLAB_NAMESPACE));
    assert_eq!(raw["project"], json!(GITLAB_PROJECT));

    let credential = gitlab_agent_login::read_credential(&store, &reference)
        .expect("the stored workspace profile");
    assert_eq!(credential.kind(), GitlabCredentialKind::Pat);
    assert_eq!(credential.access_token(), GITLAB_PAT);
    assert_eq!(credential.refresh_token(), None);
    assert_eq!(credential.expires_at(), None);
    assert_eq!(credential.origin(), gitlab_agent_login::ORIGIN);
    assert_eq!(credential.namespace(), GITLAB_NAMESPACE);
    assert_eq!(credential.project(), Some(GITLAB_PROJECT));

    let closed = serde_json::from_slice::<gitlab_agent_login::WorkspaceCredential>(
        br#"{"kind":"pat","access_token":"x","origin":"https://gitlab.com","namespace":"group","extra":true}"#,
    )
    .expect_err("the stored shape is closed");
    assert!(closed.to_string().contains("unknown field"), "{closed}");
}

#[test]
fn gitlab_agent_refresh_preserves_origin_namespace_and_project() {
    let observed = Arc::new(Mutex::new(Vec::<(String, String, String)>::new()));
    let recorded = Arc::clone(&observed);
    let reply = gitlab_reply(
        GITLAB_ACCESS_ROTATED,
        GITLAB_REFRESH_ROTATED,
        3600,
        GITLAB_CREATED_AT + 100_000,
    );
    let peer = TestPeer::start(move |line, head, body| {
        recorded.lock().expect("record lock").push((
            line.to_string(),
            head.to_string(),
            body.to_string(),
        ));
        (200, reply.clone())
    });
    let config = gitlab_config();
    let prior = gitlab_oauth_profile(GITLAB_ACCESS, GITLAB_REFRESH, GITLAB_CREATED_AT);
    let store = support::MapStore::seeded(StoreKind::Keychain, &[(GITLAB_REF, &prior)]);

    assert_eq!(
        gitlab_agent_login::refresh(
            &config,
            "gitlab-duo-agent",
            &peer.url("/oauth/token"),
            &store
        )
        .expect("the refresh exchange completes"),
        "gitlab-duo-agent"
    );

    let reference = resolve_credential(&config, "gitlab-duo-agent").expect("the canonical ref");
    let raw: Value =
        serde_json::from_slice(&store.resolve(&reference).expect("stored bytes")).expect("json");
    assert_eq!(raw["kind"], json!("oauth"));
    assert_eq!(raw["access_token"], json!(GITLAB_ACCESS_ROTATED));
    assert_eq!(raw["refresh_token"], json!(GITLAB_REFRESH_ROTATED));
    assert_eq!(
        raw["expires_at"],
        json!(GITLAB_CREATED_AT + 100_000 + 3600 - EXPIRY_SKEW)
    );
    assert_eq!(
        raw["origin"],
        json!(gitlab_agent_login::ORIGIN),
        "the refresh preserves the operator origin"
    );
    assert_eq!(raw["namespace"], json!(GITLAB_NAMESPACE));
    assert_eq!(raw["project"], json!(GITLAB_PROJECT));

    let (line, head, body) = {
        let requests = observed.lock().expect("record lock");
        assert_eq!(requests.len(), 1);
        requests[0].clone()
    };
    assert_eq!(line, "POST /oauth/token HTTP/1.1");
    assert!(
        head.to_ascii_lowercase()
            .contains("content-type: application/x-www-form-urlencoded"),
        "{head}"
    );
    assert_eq!(
        form_value(&body, "grant_type").as_deref(),
        Some("refresh_token")
    );
    assert_eq!(
        form_value(&body, "client_id").as_deref(),
        Some(GITLAB_CLIENT_ID)
    );
    assert_eq!(
        form_value(&body, "refresh_token").as_deref(),
        Some(GITLAB_REFRESH)
    );
    assert_eq!(
        form_value(&body, "redirect_uri").as_deref(),
        Some(GITLAB_CALLBACK_URL)
    );
    assert_eq!(
        form_value(&body, "code_verifier"),
        None,
        "a refresh carries no PKCE verifier"
    );

    let pat = gitlab_pat_profile(GITLAB_PAT);
    let pat_store = support::MapStore::seeded(StoreKind::Keychain, &[(GITLAB_REF, &pat)]);
    let before = gitlab_stored(&pat_store, &config);
    let error = gitlab_agent_login::refresh(
        &config,
        "gitlab-duo-agent",
        &peer.url("/oauth/token"),
        &pat_store,
    )
    .expect_err("a PAT has no refresh leg");
    assert!(
        matches!(error, GitlabLoginError::RefreshUnavailable),
        "{error}"
    );
    assert_eq!(
        pat_store
            .resolve(&resolve_credential(&config, "gitlab-duo-agent").expect("canonical"))
            .expect("prior bytes"),
        before,
        "a refused refresh leaves the PAT byte-identical"
    );
    assert_eq!(
        observed.lock().expect("record lock").len(),
        1,
        "the PAT denial never reaches the wire"
    );
}

#[test]
fn gitlab_agent_other_scope_profile_is_absent() {
    let config = gitlab_config();
    let other = gitlab_oauth_profile(GITLAB_ACCESS, GITLAB_REFRESH, GITLAB_CREATED_AT);
    let store = support::MapStore::seeded(
        StoreKind::Keychain,
        &[("keychain:rivect-test/gitlab-agent-other", &other)],
    );
    let reference = resolve_credential(&config, "gitlab-duo-agent").expect("the canonical ref");
    let error = gitlab_agent_login::read_credential(&store, &reference)
        .expect_err("another scope is never the canonical profile");
    assert!(
        matches!(
            &error,
            GitlabLoginError::Provider(ProviderError::CredentialAbsent { scope })
                if scope == "rivect-test/gitlab-duo-agent"
        ),
        "{error}"
    );
}

#[test]
fn gitlab_agent_wrong_callback_or_origin_denies() {
    let requests = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&requests);
    let peer = TestPeer::start(move |_line, _head, _body| {
        counter.fetch_add(1, Ordering::SeqCst);
        (
            200,
            gitlab_reply(GITLAB_ACCESS, GITLAB_REFRESH, 7200, GITLAB_CREATED_AT),
        )
    });
    let config = gitlab_config();
    let prior = gitlab_oauth_profile(GITLAB_ACCESS, GITLAB_REFRESH, GITLAB_CREATED_AT);
    let store = support::MapStore::seeded(StoreKind::Keychain, &[(GITLAB_REF, &prior)]);
    let reference = resolve_credential(&config, "gitlab-duo-agent").expect("the canonical ref");
    let session = gitlab_agent_login::begin_login(&gitlab_scope(), &gitlab_endpoints(&peer))
        .expect("the loopback endpoints mint a session");

    let wrong_origin = format!(
        "https://evil.example/authentication?code=callback-code&state={}",
        session.state()
    );
    let wrong_path = format!(
        "vscode://gitlab.gitlab-workflow/other?code=callback-code&state={}",
        session.state()
    );
    let wrong_state = gitlab_callback("callback-code", "wrong-state");
    let empty_code = format!("{GITLAB_CALLBACK_URL}?code=&state={}", session.state());
    let cancelled = format!(
        "{GITLAB_CALLBACK_URL}?error=access_denied&state={}",
        session.state()
    );

    for (callback, expected) in [
        (&wrong_origin, "callback origin"),
        (&wrong_path, "callback path"),
        (&wrong_state, "state"),
        (&empty_code, "code"),
        (&cancelled, "cancelled"),
    ] {
        let error =
            gitlab_agent_login::complete(&config, "gitlab-duo-agent", &session, callback, &store)
                .expect_err(expected);
        match expected {
            "callback origin" | "callback path" => assert!(
                matches!(error, GitlabLoginError::CallbackNotRecorded { .. }),
                "{error}"
            ),
            "state" => assert!(matches!(error, GitlabLoginError::StateMismatch), "{error}"),
            "code" => assert!(
                matches!(error, GitlabLoginError::MissingField { field: "code" }),
                "{error}"
            ),
            _ => assert!(matches!(error, GitlabLoginError::Cancelled), "{error}"),
        }
        assert_eq!(
            store.resolve(&reference).expect("prior bytes"),
            prior.as_bytes(),
            "a denied callback writes nothing"
        );
    }

    let foreign_scope = WorkspaceScope::new("https://gitlab.example.com", "group", None);
    let error = gitlab_agent_login::begin_login(&foreign_scope, &gitlab_endpoints(&peer))
        .expect_err("only gitlab.com is admitted");
    assert!(
        matches!(error, GitlabLoginError::OriginNotRecorded { .. }),
        "{error}"
    );
    let error = gitlab_agent_login::enroll_pat(
        &config,
        "gitlab-duo-agent",
        GITLAB_PAT,
        &foreign_scope,
        &store,
    )
    .expect_err("only gitlab.com is admitted");
    assert!(
        matches!(error, GitlabLoginError::OriginNotRecorded { .. }),
        "{error}"
    );

    for endpoints in [
        GitlabEndpoints::new(
            "https://evil.example/oauth/authorize",
            &peer.url("/oauth/token"),
        ),
        GitlabEndpoints::new(
            &peer.url("/oauth/authorize"),
            "https://evil.example/oauth/token",
        ),
        GitlabEndpoints::new(
            "https://user:pass@gitlab.com/oauth/authorize",
            &peer.url("/oauth/token"),
        ),
    ] {
        let error = gitlab_agent_login::begin_login(&gitlab_scope(), &endpoints)
            .expect_err("a foreign endpoint denies");
        assert!(
            matches!(error, GitlabLoginError::EndpointNotRecorded { .. }),
            "{error}"
        );
    }

    assert_eq!(
        store.resolve(&reference).expect("prior bytes"),
        prior.as_bytes(),
        "every denied transition leaves the prior profile byte-identical"
    );
    assert_eq!(
        requests.load(Ordering::SeqCst),
        0,
        "a denied callback or origin sends no request"
    );
}

#[test]
fn gitlab_agent_occupied_scope_keeps_the_prior_profile() {
    let observed = Arc::new(Mutex::new(Vec::<String>::new()));
    let recorded = Arc::clone(&observed);
    let reply = gitlab_reply(GITLAB_ACCESS, GITLAB_REFRESH, 7200, GITLAB_CREATED_AT);
    let peer = TestPeer::start(move |line, _head, _body| {
        recorded.lock().expect("record lock").push(line.to_string());
        (200, reply.clone())
    });
    let config = gitlab_config();
    let prior = gitlab_oauth_profile(GITLAB_ACCESS, GITLAB_REFRESH, GITLAB_CREATED_AT);
    let store = support::MapStore::seeded(StoreKind::Keychain, &[(GITLAB_REF, &prior)]);
    let reference = resolve_credential(&config, "gitlab-duo-agent").expect("the canonical ref");
    let session = gitlab_agent_login::begin_login(&gitlab_scope(), &gitlab_endpoints(&peer))
        .expect("the loopback endpoints mint a session");
    let callback = gitlab_callback("callback-code", session.state());

    let error =
        gitlab_agent_login::complete(&config, "gitlab-duo-agent", &session, &callback, &store)
            .expect_err("create-only enrollment refuses an occupied scope");
    assert!(
        matches!(
            error,
            GitlabLoginError::Provider(ProviderError::CredentialOccupied { .. })
        ),
        "{error}"
    );
    assert_eq!(
        store.resolve(&reference).expect("prior bytes"),
        prior.as_bytes()
    );

    let error = gitlab_agent_login::enroll_pat(
        &config,
        "gitlab-duo-agent",
        GITLAB_PAT,
        &gitlab_scope(),
        &store,
    )
    .expect_err("PAT enrollment is create-only too");
    assert!(
        matches!(
            error,
            GitlabLoginError::Provider(ProviderError::CredentialOccupied { .. })
        ),
        "{error}"
    );
    assert_eq!(
        store.resolve(&reference).expect("prior bytes"),
        prior.as_bytes()
    );
    let requests = observed.lock().expect("record lock");
    assert_eq!(requests.len(), 1, "one exchange, no settings PUT");
    assert_eq!(requests[0], "POST /oauth/token HTTP/1.1");
}

#[test]
fn gitlab_agent_failed_store_write_keeps_the_prior_profile() {
    let observed = Arc::new(Mutex::new(Vec::<String>::new()));
    let recorded = Arc::clone(&observed);
    let reply = gitlab_reply(GITLAB_ACCESS, GITLAB_REFRESH, 7200, GITLAB_CREATED_AT);
    let peer = TestPeer::start(move |line, _head, _body| {
        recorded.lock().expect("record lock").push(line.to_string());
        (200, reply.clone())
    });
    let config = gitlab_config();
    let prior = gitlab_oauth_profile(GITLAB_ACCESS, GITLAB_REFRESH, GITLAB_CREATED_AT);
    let inner = support::MapStore::seeded(StoreKind::Keychain, &[(GITLAB_REF, &prior)]);
    let store = RefusingLoginStore { inner };
    let reference = resolve_credential(&config, "gitlab-duo-agent").expect("the canonical ref");
    let session = gitlab_agent_login::begin_login(&gitlab_scope(), &gitlab_endpoints(&peer))
        .expect("the loopback endpoints mint a session");
    let callback = gitlab_callback("callback-code", session.state());

    let error =
        gitlab_agent_login::complete(&config, "gitlab-duo-agent", &session, &callback, &store)
            .expect_err("a refused store write denies");
    assert!(
        matches!(
            error,
            GitlabLoginError::Provider(ProviderError::StoreUnavailable { .. })
        ),
        "{error}"
    );
    assert_eq!(
        store.resolve(&reference).expect("prior bytes"),
        prior.as_bytes()
    );

    let error = gitlab_agent_login::enroll_pat(
        &config,
        "gitlab-duo-agent",
        GITLAB_PAT,
        &gitlab_scope(),
        &store,
    )
    .expect_err("a refused store write denies the PAT too");
    assert!(
        matches!(
            error,
            GitlabLoginError::Provider(ProviderError::StoreUnavailable { .. })
        ),
        "{error}"
    );
    assert_eq!(
        store.resolve(&reference).expect("prior bytes"),
        prior.as_bytes()
    );
    let requests = observed.lock().expect("record lock");
    assert_eq!(requests.len(), 1, "one exchange, no settings PUT");
    assert_eq!(requests[0], "POST /oauth/token HTTP/1.1");
}

#[test]
fn gitlab_agent_profile_never_prints_secrets() {
    let reply = gitlab_reply(GITLAB_ACCESS, GITLAB_REFRESH, 7200, GITLAB_CREATED_AT);
    let peer = TestPeer::start(move |_line, _head, _body| (200, reply.clone()));
    let config = gitlab_config();
    let store = support::MapStore::new(StoreKind::Keychain);
    let session = gitlab_agent_login::begin_login(&gitlab_scope(), &gitlab_endpoints(&peer))
        .expect("the loopback endpoints mint a session");
    let verifier = session.code_verifier().to_string();
    let callback = gitlab_callback("callback-code", session.state());
    let _profile =
        gitlab_agent_login::complete(&config, "gitlab-duo-agent", &session, &callback, &store)
            .expect("the form exchange completes");
    let reference = resolve_credential(&config, "gitlab-duo-agent").expect("the canonical ref");
    let credential = gitlab_agent_login::read_credential(&store, &reference)
        .expect("the stored workspace profile");

    let session_debug = format!("{session:?}");
    assert!(session_debug.contains("<redacted>"));
    assert!(!session_debug.contains(&verifier), "{session_debug}");
    let credential_debug = format!("{credential:?}");
    assert!(credential_debug.contains("<redacted>"));
    assert!(
        !credential_debug.contains(GITLAB_ACCESS),
        "{credential_debug}"
    );
    assert!(
        !credential_debug.contains(GITLAB_REFRESH),
        "{credential_debug}"
    );
    // The workspace scope identifiers are non-secret and render verbatim.
    assert!(credential_debug.contains(gitlab_agent_login::ORIGIN));
    assert!(credential_debug.contains(GITLAB_NAMESPACE));
    assert!(credential_debug.contains(GITLAB_PROJECT));

    let malformed_json =
        serde_json::from_slice::<Value>(b"not-json").expect_err("the fixture is not an object");
    let serialization = serde_json::from_slice::<Value>(b"{").expect_err("the fixture is not json");
    let clock = UNIX_EPOCH
        .duration_since(SystemTime::now())
        .expect_err("the wall clock is after the unix epoch");
    let callback_error = gitlab_agent_login::complete(
        &config,
        "gitlab-duo-agent",
        &session,
        &format!(
            "https://evil.example/authentication?code=fixture-secret-code&state={}",
            session.state()
        ),
        &store,
    )
    .expect_err("a foreign callback denies");
    let errors = vec![
        GitlabLoginError::OriginNotRecorded {
            origin: "https://gitlab.example.com".to_string(),
        },
        GitlabLoginError::EndpointNotRecorded {
            origin: "https://evil.example".to_string(),
        },
        callback_error,
        GitlabLoginError::StateMismatch,
        GitlabLoginError::Cancelled,
        GitlabLoginError::ConnectionMissing {
            connection: "gitlab-duo-agent".to_string(),
        },
        GitlabLoginError::NotApiKey {
            connection: "gitlab-duo-agent".to_string(),
            kind: ConnKind::Local,
        },
        GitlabLoginError::TokenRejected { status: 403 },
        GitlabLoginError::MissingField {
            field: "access_token",
        },
        GitlabLoginError::InvalidExpiry,
        GitlabLoginError::RefreshUnavailable,
        GitlabLoginError::ResponseTooLarge,
        GitlabLoginError::MalformedResponse {
            cause: malformed_json,
        },
        GitlabLoginError::StoredCredentialMalformed {
            reason: "a value outside the profile shape",
        },
        GitlabLoginError::Serialization {
            cause: serialization,
        },
        GitlabLoginError::Clock { cause: clock },
        GitlabLoginError::Provider(ProviderError::StoreUnavailable {
            store: StoreKind::Keychain,
            reason: "fixture refusal".to_string(),
        }),
    ];
    for error in &errors {
        let display = error.to_string();
        assert!(
            display
                .chars()
                .next()
                .is_some_and(|first| first.is_ascii_lowercase()),
            "the display starts lowercase: {display}"
        );
        let rendered = format!("{display} {error:?}");
        assert!(!rendered.contains(GITLAB_ACCESS), "{rendered}");
        assert!(!rendered.contains(GITLAB_REFRESH), "{rendered}");
        assert!(!rendered.contains(&verifier), "{rendered}");
        assert!(!rendered.contains("fixture-secret-code"), "{rendered}");
    }
}

/// A stored-profile parse failure keeps only serde's class: a token
/// planted in a numeric field never reaches the `Display` or `Debug`
/// surface, and neither does the stored JSON.
#[test]
fn stored_profile_parse_errors_never_render_the_stored_bytes() {
    fn assert_clean(rendered: &str, secret: &str) {
        assert!(
            rendered.contains("a value outside the profile shape"),
            "{rendered}"
        );
        assert!(!rendered.contains(secret), "{rendered}");
        assert!(!rendered.contains("access_token"), "{rendered}");
        assert!(!rendered.contains("refresh_token"), "{rendered}");
        assert!(!rendered.contains("expires_at"), "{rendered}");
    }

    let cursor = "cursor-secret-in-numeric-field";
    let cursor_ref = SecretRef::parse("keychain:rivect-test/cursor").expect("cursor ref");
    let stored = format!(
        r#"{{"access_token":"{cursor}","refresh_token":"{cursor}-refresh","expires_at":"{cursor}","user_id":"u"}}"#
    );
    let store = support::MapStore::seeded(
        StoreKind::Keychain,
        &[("keychain:rivect-test/cursor", &stored)],
    );
    let error = cursor_login::read_credential(&store, &cursor_ref).expect_err("wrong type");
    assert_clean(&format!("{error} {error:?}"), cursor);

    let devin = "devin-secret-in-numeric-field";
    let devin_ref = SecretRef::parse("keychain:rivect-test/devin").expect("devin ref");
    let stored = format!(
        r#"{{"access_token":"{devin}","refresh_token":"{devin}-refresh","expires_at":"{devin}"}}"#
    );
    let store = support::MapStore::seeded(
        StoreKind::Keychain,
        &[("keychain:rivect-test/devin", &stored)],
    );
    let error = devin_login::read_credential(&store, &devin_ref).expect_err("wrong type");
    assert_clean(&format!("{error} {error:?}"), devin);

    let gitlab = "gitlab-secret-in-numeric-field";
    let gitlab_ref = SecretRef::parse("keychain:rivect-test/gitlab").expect("gitlab ref");
    let stored = format!(
        r#"{{"kind":"pat","access_token":"{gitlab}","origin":"https://gitlab.com","namespace":"g","expires_at":"{gitlab}"}}"#
    );
    let store = support::MapStore::seeded(
        StoreKind::Keychain,
        &[("keychain:rivect-test/gitlab", &stored)],
    );
    let error = gitlab_agent_login::read_credential(&store, &gitlab_ref).expect_err("wrong type");
    assert_clean(&format!("{error} {error:?}"), gitlab);

    let anthropic = "anthropic-secret-in-numeric-field";
    let anthropic_ref = SecretRef::parse("keychain:rivect-test/anthropic").expect("anthropic ref");
    let stored = format!(
        r#"{{"access_token":"{anthropic}","refresh_token":"{anthropic}-refresh","expires_at":"{anthropic}","organization_id":"o"}}"#
    );
    let store = support::MapStore::seeded(
        StoreKind::Keychain,
        &[("keychain:rivect-test/anthropic", &stored)],
    );
    let error = anthropic_login::read_subscription(&store, &anthropic_ref).expect_err("wrong type");
    assert_clean(&format!("{error} {error:?}"), anthropic);

    let codex = "codex-secret-in-numeric-field";
    let codex_ref = SecretRef::parse("keychain:rivect-test/codex").expect("codex ref");
    let stored = format!(
        r#"{{"access_token":"{codex}","refresh_token":"{codex}-refresh","expires_at":"{codex}"}}"#
    );
    let store = support::MapStore::seeded(
        StoreKind::Keychain,
        &[("keychain:rivect-test/codex", &stored)],
    );
    let error = openai_login::read_credential(&store, &codex_ref).expect_err("wrong type");
    let rendered = format!("{error} {error:?}");
    assert!(matches!(
        error,
        OpenaiLoginError::StoredCredentialMalformed { .. }
    ));
    assert_clean(&rendered, codex);
}

/// The device page is exposed only as `https` on the session's own
/// domain; a script, file or foreign-host URI is a typed denial that
/// never renders the raw value.
#[test]
fn copilot_verification_uri_must_be_https_on_the_session_domain() {
    for (domain, uri) in [
        ("", "javascript:alert(1)"),
        ("", "file:///etc/passwd"),
        ("", "https://evil.example/login/device"),
        ("company.ghe.com", "https://github.com/login/device"),
    ] {
        let uri_owned = uri.to_string();
        let peer = TestPeer::start(move |line, _head, _body| {
            if line.contains("/login/device/code") {
                (
                    200,
                    json!({
                        "device_code": COPILOT_DEVICE_CODE,
                        "user_code": COPILOT_USER_CODE,
                        "verification_uri": uri_owned,
                        "interval": 5,
                        "expires_in": 900,
                    })
                    .to_string(),
                )
            } else {
                (200, copilot_token_reply(COPILOT_TOKEN))
            }
        });
        let error = copilot_login::begin_device(domain, copilot_endpoints(&peer))
            .expect_err("the verification page is outside the session domain");
        assert!(
            matches!(error, CopilotLoginError::EndpointNotRecorded { .. }),
            "{uri}: {error:?}"
        );
        let rendered = format!("{error} {error:?}");
        assert!(!rendered.contains("/etc/passwd"), "{rendered}");
        assert!(!rendered.contains("alert(1)"), "{rendered}");
        assert!(!rendered.contains("evil.example/login"), "{rendered}");
    }
}

/// A manually seeded workspace profile naming another instance origin
/// denies before any consumer reads it, and the prior bytes are untouched.
#[test]
fn gitlab_agent_foreign_stored_origin_denies_read() {
    let config = gitlab_config();
    let reference = resolve_credential(&config, "gitlab-duo-agent").expect("the canonical ref");
    let profile = json!({
        "kind": "oauth",
        "access_token": GITLAB_ACCESS,
        "refresh_token": GITLAB_REFRESH,
        "expires_at": 4_102_444_800_u64,
        "origin": "https://gitlab.example.com",
        "namespace": GITLAB_NAMESPACE,
        "project": GITLAB_PROJECT,
    })
    .to_string();
    let store = support::MapStore::seeded(StoreKind::Keychain, &[(GITLAB_REF, &profile)]);

    let error = gitlab_agent_login::read_credential(&store, &reference)
        .expect_err("a foreign instance origin is not this class");
    assert!(
        matches!(
            &error,
            GitlabLoginError::Provider(ProviderError::CredentialMalformed { .. })
        ),
        "{error:?}"
    );
    assert_eq!(
        store.resolve(&reference).expect("prior bytes"),
        profile.as_bytes(),
        "the denied read leaves the stored bytes untouched"
    );
    let rendered = format!("{error} {error:?}");
    assert!(!rendered.contains("gitlab.example.com"), "{rendered}");
    assert!(!rendered.contains(GITLAB_ACCESS), "{rendered}");

    let renamed = SecretRef::parse("keychain:rivect-test/renamed-profile").expect("the scoped ref");
    let renamed_store = support::MapStore::seeded(
        StoreKind::Keychain,
        &[("keychain:rivect-test/renamed-profile", &profile)],
    );
    let error = gitlab_agent_login::read_credential(&renamed_store, &renamed)
        .expect_err("a foreign instance origin is not this class");
    let rendered = format!("{error} {error:?}");
    assert!(rendered.contains("gitlab-duo-agent"), "{rendered}");
    assert!(!rendered.contains("renamed-profile"), "{rendered}");
}
