//! Codex login ingress proof (DEC-020, AC-040j): `auth.login.begin` and
//! `auth.login.complete` are the product entrypoints, the TUI `/login`
//! command calls the same methods, and the device alias, its bounded
//! pending/slow_down/denial/expiry states and the canonical profile are
//! proved against loopback contract peers only.

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

use rivect::commands::{Ingress, dispatch_runtime_request};
use rivect::config::Config;
use rivect::providers::openai_login::{
    self, CANONICAL_PROFILE, DeviceAdvance, DeviceEndpoints, DeviceLoginSession,
    LoginError as CodexLoginError, canonical_reference, read_credential,
};
use rivect::providers::{CredentialStore, ProviderError, SecretRef, StoreKind, resolve_credential};
use rivect::ui::login_command;
use serde_json::{Value, json};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;
use support::{CODEX_EMAIL, CODEX_REF, CODEX_WORKSPACE};

const CODEX_REFRESH_FIXTURE: &str = "fixture-codex-refresh-not-real";
/// The device interval the loop admits; the recorded fallback is five
/// seconds, and the contract peers answer one so the proof stays bounded.
const TEST_INTERVAL: &str = "1";

/// A scripted loopback peer: one JSON answer per request path, judged by the
/// test's own closure. It is a plain `std` listener because the login RPC
/// dispatches on the test thread and `reqwest::blocking` must never run
/// inside a Tokio context.
struct TestPeer {
    base: String,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl TestPeer {
    fn start(handler: impl Fn(&str, &str) -> (u16, String) + Send + Sync + 'static) -> Self {
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
                        if let Some((path, body)) = read_request(&mut stream) {
                            let (status, payload) = handler(&path, &body);
                            let reason = if status == 200 { "OK" } else { "Error" };
                            let response = format!(
                                "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\n\
                                 Content-Length: {}\r\nConnection: close\r\n\r\n{payload}",
                                payload.len()
                            );
                            let _ = stream.write_all(response.as_bytes());
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

/// Reads one HTTP request: the path and the body under its `Content-Length`.
fn read_request(stream: &mut TcpStream) -> Option<(String, String)> {
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
    let path = head.lines().next()?.split_whitespace().nth(1)?.to_string();
    let body = String::from_utf8_lossy(&buffer[body_start..buffer.len()]).to_string();
    Some((path, body))
}

fn codex_config() -> Config {
    Config::parse_validated(&support::codex_login_config()).expect("the codex config parses")
}

fn token_reply(workspace: &str, email: &str) -> String {
    json!({
        "access_token": support::codex_access_token(workspace, email, "plus"),
        "refresh_token": CODEX_REFRESH_FIXTURE,
        "id_token": support::codex_access_token(workspace, email, "plus"),
        "expires_in": 28_800u64,
    })
    .to_string()
}

/// Dispatches one request and answers the parsed envelope.
fn rpc(world: &mut support::World, method: &str, params: Value) -> Value {
    let request = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    });
    let response = dispatch_runtime_request(
        &mut world.runtime,
        Ingress::TrustedHuman,
        "codex-login-test",
        &request.to_string(),
    );
    serde_json::from_str(&response).expect("the dispatcher answers json")
}

fn rpc_ok(world: &mut support::World, method: &str, params: Value) -> Value {
    let response = rpc(world, method, params);
    assert!(
        response.get("error").is_none(),
        "{method} answered an error: {response}"
    );
    response["result"].clone()
}

/// The typed wire body of a refusal.
fn rpc_refusal(world: &mut support::World, method: &str, params: Value) -> Value {
    let response = rpc(world, method, params);
    assert!(
        response.get("error").is_some(),
        "{method} unexpectedly succeeded: {response}"
    );
    response["error"]["data"].clone()
}

/// Asserts the refusal's wire code and message, then answers the message.
fn assert_refusal(
    world: &mut support::World,
    method: &str,
    params: Value,
    code: &str,
    message: &str,
) -> String {
    let body = rpc_refusal(world, method, params);
    assert_eq!(body["code"], code, "{body}");
    let text = body["message"]
        .as_str()
        .expect("the wire error carries a message");
    assert!(text.contains(message), "{text}");
    text.to_string()
}

fn callback(state: &str, code: &str) -> String {
    format!("http://localhost:1455/auth/callback?code={code}&state={state}")
}

fn session(world: &mut support::World) -> String {
    rpc_ok(
        world,
        "session.open",
        json!({ "schema_version": 1, "bootstrap_id": "codex-login-test" }),
    )["session_id"]
        .as_str()
        .expect("session.open answers a session")
        .to_string()
}

/// One scripted device peer; the poll counter is the bounded-loop
/// observation. Modes cover pending, `authorization_pending`, slow_down,
/// denial, expiry and a slow success delivered after the expiry.
fn device_peer(mode: &'static str, expires_in: u64) -> (TestPeer, Arc<AtomicUsize>) {
    let polls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&polls);
    let peer = TestPeer::start(move |path, _body| match path {
        "/deviceauth/usercode" => (
            200,
            json!({
                "device_auth_id": "device-handle-fixture",
                "user_code": "USER-CODE",
                "interval": TEST_INTERVAL,
                "expires_in": expires_in,
            })
            .to_string(),
        ),
        "/deviceauth/token" => {
            let poll = counter.fetch_add(1, Ordering::SeqCst) + 1;
            let code = json!({
                "authorization_code": "device-code",
                "code_verifier": "device-verifier-fixture",
            })
            .to_string();
            match mode {
                "pending" if poll == 1 => (403, String::new()),
                "authorization_pending" if poll == 1 => {
                    (200, json!({ "error": "authorization_pending" }).to_string())
                }
                "slow_down" => (200, json!({ "error": "slow_down" }).to_string()),
                "denied" => (200, json!({ "error": "access_denied" }).to_string()),
                "expired" => (403, String::new()),
                "slow_success" => {
                    std::thread::park_timeout(Duration::from_millis(2_200));
                    (200, code)
                }
                _ => (200, code),
            }
        }
        "/oauth/token" => (200, token_reply(CODEX_WORKSPACE, CODEX_EMAIL)),
        _ => (404, "{}".to_string()),
    });
    (peer, polls)
}

fn endpoints(peer: &TestPeer) -> DeviceEndpoints {
    DeviceEndpoints {
        usercode: peer.url("/deviceauth/usercode"),
        token: peer.url("/deviceauth/token"),
        exchange: peer.url("/oauth/token"),
    }
}

fn begin_device(config: &Config, peer: &TestPeer) -> DeviceLoginSession {
    openai_login::begin_device_login(config, "openai-codex-device", endpoints(peer))
        .expect("the device alias starts")
}

fn variant(error: &CodexLoginError) -> &'static str {
    match error {
        CodexLoginError::Entropy { .. } => "Entropy",
        CodexLoginError::NotARedirect => "NotARedirect",
        CodexLoginError::OriginMismatch => "OriginMismatch",
        CodexLoginError::StateMismatch => "StateMismatch",
        CodexLoginError::Cancelled => "Cancelled",
        CodexLoginError::Denied { .. } => "Denied",
        CodexLoginError::MissingCode => "MissingCode",
        CodexLoginError::EndpointNotRecorded { .. } => "EndpointNotRecorded",
        CodexLoginError::TokenRejected { .. } => "TokenRejected",
        CodexLoginError::MissingField { .. } => "MissingField",
        CodexLoginError::MissingIdentity => "MissingIdentity",
        CodexLoginError::ResponseTooLarge => "ResponseTooLarge",
        CodexLoginError::MalformedResponse { .. } => "MalformedResponse",
        CodexLoginError::NotApiKey { .. } => "NotApiKey",
        CodexLoginError::NotCanonicalProfile { .. } => "NotCanonicalProfile",
        CodexLoginError::WorkspaceMismatch => "WorkspaceMismatch",
        CodexLoginError::AccountMismatch => "AccountMismatch",
        CodexLoginError::StoredCredentialMalformed { .. } => "StoredCredentialMalformed",
        CodexLoginError::Serialization { .. } => "Serialization",
        CodexLoginError::Clock { .. } => "Clock",
        CodexLoginError::DeviceDenied => "DeviceDenied",
        CodexLoginError::DeviceExpired => "DeviceExpired",
        CodexLoginError::DeviceExpiryOutOfRange { .. } => "DeviceExpiryOutOfRange",
        CodexLoginError::TokenExpiryOutOfRange { .. } => "TokenExpiryOutOfRange",
        CodexLoginError::DeviceIntervalOutOfRange { .. } => "DeviceIntervalOutOfRange",
        CodexLoginError::MalformedField { .. } => "MalformedField",
        CodexLoginError::ConnectionMissing { .. } => "ConnectionMissing",
        CodexLoginError::Provider(_) => "Provider",
    }
}

/// The device alias stores the one canonical `openai-codex` profile the
/// browser leg writes.
#[test]
fn codex_device_alias_creates_the_same_canonical_profile() {
    let (peer, polls) = device_peer("pending", 10);
    let mut device = begin_device(&codex_config(), &peer);
    assert_eq!(device.connection(), CANONICAL_PROFILE);
    assert_eq!(
        device.verification_url(),
        "https://auth.openai.com/codex/device"
    );
    assert_eq!(device.user_code(), "USER-CODE");
    assert_eq!(device.expires_in(), 10);

    let config = codex_config();
    let store = support::MapStore::new(StoreKind::Keychain);
    let profile =
        openai_login::complete_device_login(&config, "openai-codex-device", &mut device, &store)
            .expect("the alias completes the canonical login");
    assert_eq!(profile, CANONICAL_PROFILE);
    assert_eq!(polls.load(Ordering::SeqCst), 2, "one pending then the code");

    let canonical = resolve_credential(&config, CANONICAL_PROFILE).expect("canonical ref");
    let by_alias = canonical_reference(&config, "openai-codex-device").expect("alias ref");
    assert_eq!(by_alias.scope(), canonical.scope());
    assert_eq!(by_alias.profile(), CANONICAL_PROFILE);
    let credential = read_credential(&store, &canonical).expect("the profile reads back");
    assert_eq!(credential.account_id(), Some(CODEX_WORKSPACE));
    assert_eq!(credential.email(), Some(CODEX_EMAIL));
}

/// Pending answers keep polling, `authorization_pending` continues, a
/// `slow_down` widens the wait, a denial stops at once, the peer's expiry —
/// and a success delivered after it — end the leg. Every poll count is
/// exact, and a failure leaves no profile behind.
#[test]
fn codex_device_pending_slow_down_denial_and_expiry_are_bounded() {
    let config = codex_config();
    let reference = canonical_reference(&config, "openai-codex").expect("canonical ref");

    for (mode, expires_in, expected_polls) in [("pending", 10, 2), ("authorization_pending", 10, 2)]
    {
        let (peer, polls) = device_peer(mode, expires_in);
        let mut device = begin_device(&config, &peer);
        let store = support::MapStore::new(StoreKind::Keychain);
        let profile =
            openai_login::complete_device_login(&config, "openai-codex", &mut device, &store)
                .expect("the pending leg completes once the code arrives");
        assert_eq!(profile, CANONICAL_PROFILE, "{mode}");
        assert_eq!(polls.load(Ordering::SeqCst), expected_polls, "{mode}");
    }

    for (mode, expires_in, expected, expected_polls) in [
        ("slow_down", 3, "DeviceExpired", 1),
        ("denied", 10, "DeviceDenied", 1),
        ("expired", 1, "DeviceExpired", 1),
        ("slow_success", 2, "DeviceExpired", 1),
    ] {
        let (peer, polls) = device_peer(mode, expires_in);
        let mut device = begin_device(&config, &peer);
        let store = support::MapStore::new(StoreKind::Keychain);
        let error =
            openai_login::complete_device_login(&config, "openai-codex", &mut device, &store)
                .expect_err("the bounded leg denies");
        assert_eq!(variant(&error), expected, "{mode}: {error}");
        assert_eq!(polls.load(Ordering::SeqCst), expected_polls, "{mode}");
        assert!(
            !store.occupied(&reference).expect("the store answers"),
            "{mode}: no profile is activated"
        );
    }

    // An unbounded peer lifetime is a typed denial, never a panicking
    // `Instant + Duration`.
    let (peer, _polls) = device_peer("expired", u64::MAX);
    let error = openai_login::begin_device_login(&config, "openai-codex-device", endpoints(&peer))
        .expect_err("the unbounded lifetime denies");
    assert_eq!(variant(&error), "DeviceExpiryOutOfRange", "{error}");

    // An unbounded or malformed poll interval is a typed denial too: the
    // schedule is never built from a numeric or string peer value.
    for (usercode, expected) in [
        (
            json!({
                "device_auth_id": "handle",
                "user_code": "CODE",
                "interval": u64::MAX,
            }),
            "DeviceIntervalOutOfRange",
        ),
        (
            json!({
                "device_auth_id": "handle",
                "user_code": "CODE",
                "interval": "999999999999999999999999",
            }),
            "MalformedField",
        ),
        (
            json!({
                "device_auth_id": "handle",
                "user_code": "CODE",
                "interval": 1.5,
            }),
            "MalformedField",
        ),
    ] {
        let peer = TestPeer::start(move |path, _body| match path {
            "/deviceauth/usercode" => (200, usercode.to_string()),
            "/oauth/token" => (200, token_reply(CODEX_WORKSPACE, CODEX_EMAIL)),
            _ => (404, "{}".to_string()),
        });
        let error =
            openai_login::begin_device_login(&config, "openai-codex-device", endpoints(&peer))
                .expect_err("the interval denial is typed");
        assert_eq!(variant(&error), expected, "{error}");
    }

    // A present but unparseable lifetime denies; a numeric string parses.
    for expires_in in [json!("soon"), json!(1.5)] {
        let usercode = json!({
            "device_auth_id": "handle",
            "user_code": "CODE",
            "interval": TEST_INTERVAL,
            "expires_in": expires_in,
        });
        let peer = TestPeer::start(move |path, _body| match path {
            "/deviceauth/usercode" => (200, usercode.to_string()),
            "/oauth/token" => (200, token_reply(CODEX_WORKSPACE, CODEX_EMAIL)),
            _ => (404, "{}".to_string()),
        });
        let error =
            openai_login::begin_device_login(&config, "openai-codex-device", endpoints(&peer))
                .expect_err("the malformed lifetime denies");
        assert_eq!(variant(&error), "MalformedField", "{error}");
    }
    let numeric = json!({
        "device_auth_id": "handle",
        "user_code": "CODE",
        "interval": TEST_INTERVAL,
        "expires_in": "60",
    });
    let peer = TestPeer::start(move |path, _body| match path {
        "/deviceauth/usercode" => (200, numeric.to_string()),
        "/oauth/token" => (200, token_reply(CODEX_WORKSPACE, CODEX_EMAIL)),
        _ => (404, "{}".to_string()),
    });
    let device = begin_device(&config, &peer);
    assert_eq!(device.expires_in(), 60, "a numeric string parses");

    // The single-step form reports the same pending state without sleeping.
    let (peer, polls) = device_peer("pending", 10);
    let mut device = begin_device(&config, &peer);
    let store = support::MapStore::new(StoreKind::Keychain);
    assert_eq!(
        openai_login::advance_device_login(&config, "openai-codex", &mut device, &store)
            .expect("the first poll is pending"),
        DeviceAdvance::Pending
    );
    assert_eq!(polls.load(Ordering::SeqCst), 1);
    assert_eq!(
        openai_login::advance_device_login(&config, "openai-codex", &mut device, &store)
            .expect("the interval has not elapsed"),
        DeviceAdvance::Pending,
        "a repeated call inside the interval performs no second poll"
    );
    assert_eq!(polls.load(Ordering::SeqCst), 1);
}

/// `auth.login.begin` answers the pending state and the recorded
/// verification URL, and a mismatched state is a denial.
#[test]
fn auth_login_begin_reports_pending_and_verification_url() {
    let peer = TestPeer::start(|path, _body| match path {
        "/oauth/token" => (200, token_reply(CODEX_WORKSPACE, CODEX_EMAIL)),
        _ => (404, "{}".to_string()),
    });
    let config = support::codex_login_config();
    let mut world = support::open_world("codex-login-begin", Some(&config));
    let store = Arc::new(support::MapStore::new(StoreKind::Keychain));
    world.runtime.login_credentials = Some(store.clone());

    let result = rpc_ok(
        &mut world,
        "auth.login.begin",
        json!({
            "schema_version": 1,
            "connection": "openai-codex",
            "mode": "browser",
            "token_endpoint": peer.url("/oauth/token"),
        }),
    );
    let state = result["state"]
        .as_str()
        .expect("begin reports a pending state");
    assert!(!state.is_empty());
    let url = result["verification_url"]
        .as_str()
        .expect("begin reports the verification url");
    assert!(url.starts_with("https://auth.openai.com/oauth/authorize?"));
    assert!(url.contains("redirect_uri=http%3A%2F%2Flocalhost%3A1455%2Fauth%2Fcallback"));
    assert!(
        !url.contains("code_verifier"),
        "the authorize URL carries the challenge, never the verifier"
    );
    assert!(result["user_code"].is_null());
    assert!(result["expires_in"].is_null());

    assert_refusal(
        &mut world,
        "auth.login.complete",
        json!({
            "schema_version": 1,
            "state": "foreign-state",
            "redirect": callback(state, "good-code"),
        }),
        "denied",
        "state does not match",
    );
    let reference = resolve_credential(&codex_config(), "openai-codex").expect("canonical ref");
    assert!(
        !store.occupied(&reference).expect("the store answers"),
        "a wrong state activates no profile"
    );
}

/// `auth.login.complete` creates the canonical profile. Each refusal keeps
/// its own label and wire code, the response body and `config.read` carry no
/// token, and every failure leaves the prior profile untouched.
#[test]
fn auth_login_complete_creates_the_profile() {
    let peer = TestPeer::start(|path, _body| match path {
        "/oauth/token" => (200, token_reply(CODEX_WORKSPACE, CODEX_EMAIL)),
        _ => (404, "{}".to_string()),
    });
    let config = support::codex_login_config();
    let mut world = support::open_world("codex-login-complete", Some(&config));
    let store = Arc::new(support::MapStore::new(StoreKind::Keychain));
    world.runtime.login_credentials = Some(store.clone());
    let session_id = session(&mut world);
    let reference = resolve_credential(&codex_config(), "openai-codex").expect("canonical ref");

    let begin = rpc_ok(
        &mut world,
        "auth.login.begin",
        json!({
            "schema_version": 1,
            "mode": "browser",
            "token_endpoint": peer.url("/oauth/token"),
        }),
    );
    let state = begin["state"].as_str().expect("pending state").to_string();

    assert_refusal(
        &mut world,
        "auth.login.complete",
        json!({
            "schema_version": 1,
            "redirect": "http://localhost:1455/auth/callback?code=good-code&state=foreign",
        }),
        "denied",
        "state does not match",
    );
    assert!(
        !store.occupied(&reference).expect("the store answers"),
        "wrong state: no profile"
    );

    assert_refusal(
        &mut world,
        "auth.login.complete",
        json!({
            "schema_version": 1,
            "redirect": callback(&state, "good-code").replace("localhost", "127.0.0.1"),
        }),
        "denied",
        "outside the recorded callback",
    );
    assert!(
        !store.occupied(&reference).expect("the store answers"),
        "wrong origin: no profile"
    );

    assert_refusal(
        &mut world,
        "auth.login.complete",
        json!({
            "schema_version": 1,
            "redirect": format!(
                "http://localhost:1455/auth/callback?error=access_denied&state={state}"
            ),
        }),
        "denied",
        "cancelled",
    );
    assert!(
        !store.occupied(&reference).expect("the store answers"),
        "cancel: no profile"
    );

    assert_refusal(
        &mut world,
        "auth.login.complete",
        json!({ "schema_version": 1 }),
        "invalid_input",
        "redirect is required",
    );

    let result = rpc_ok(
        &mut world,
        "auth.login.complete",
        json!({ "schema_version": 1, "redirect": callback(&state, "good-code") }),
    );
    assert_eq!(result["profile"], CANONICAL_PROFILE);
    let credential = read_credential(store.as_ref(), &reference).expect("the profile reads back");
    assert_eq!(credential.account_id(), Some(CODEX_WORKSPACE));
    let rendered = result.to_string();
    let access = support::codex_access_token(CODEX_WORKSPACE, CODEX_EMAIL, "plus");
    assert!(!rendered.contains(CODEX_REFRESH_FIXTURE));
    assert!(!rendered.contains(&access));

    let read = rpc_ok(
        &mut world,
        "config.read",
        json!({
            "schema_version": 1,
            "session_id": session_id,
            "keys": [
                "profiles.openai-codex.credential_ref",
                "connections.openai-codex.profile",
            ],
        }),
    );
    let exported = read.to_string();
    assert!(exported.contains("openai-codex"));
    assert!(
        !exported.contains(&access),
        "config export carries no token"
    );
    assert!(!exported.contains(CODEX_REFRESH_FIXTURE));
}

/// The device RPC leg: `begin` reports the user code and lifetime, the first
/// `complete` is a bounded pending poll, the second creates the canonical
/// profile, and `config.read` exports no token.
#[test]
fn auth_login_device_rpc_creates_the_profile() {
    let (peer, polls) = device_peer("pending", 10);
    let config = support::codex_login_config();
    let mut world = support::open_world("codex-login-device", Some(&config));
    let store = Arc::new(support::MapStore::new(StoreKind::Keychain));
    world.runtime.login_credentials = Some(store.clone());
    let session_id = session(&mut world);

    let begin = rpc_ok(
        &mut world,
        "auth.login.begin",
        json!({
            "schema_version": 1,
            "connection": "openai-codex-device",
            "mode": "device",
            "usercode_endpoint": peer.url("/deviceauth/usercode"),
            "device_token_endpoint": peer.url("/deviceauth/token"),
            "token_endpoint": peer.url("/oauth/token"),
        }),
    );
    assert_eq!(begin["user_code"], "USER-CODE");
    assert_eq!(begin["expires_in"], 10);
    assert_eq!(
        begin["verification_url"],
        "https://auth.openai.com/codex/device"
    );

    let pending = rpc_ok(
        &mut world,
        "auth.login.complete",
        json!({ "schema_version": 1 }),
    );
    assert_eq!(pending["state"], "pending");
    assert_eq!(polls.load(Ordering::SeqCst), 1, "one bounded poll");

    std::thread::park_timeout(Duration::from_secs(1));
    let completed = rpc_ok(
        &mut world,
        "auth.login.complete",
        json!({ "schema_version": 1 }),
    );
    assert_eq!(completed["profile"], CANONICAL_PROFILE);
    assert_eq!(polls.load(Ordering::SeqCst), 2);

    let reference = resolve_credential(&codex_config(), "openai-codex").expect("canonical ref");
    assert!(store.occupied(&reference).expect("the store answers"));
    let credential = read_credential(store.as_ref(), &reference).expect("the profile reads back");
    assert_eq!(credential.account_id(), Some(CODEX_WORKSPACE));

    // A slow_down answer is one pending state, not a completion.
    let (slow_peer, _slow_polls) = device_peer("slow_down", 10);
    let slow_begin = rpc_ok(
        &mut world,
        "auth.login.begin",
        json!({
            "schema_version": 1,
            "mode": "device",
            "usercode_endpoint": slow_peer.url("/deviceauth/usercode"),
            "device_token_endpoint": slow_peer.url("/deviceauth/token"),
            "token_endpoint": slow_peer.url("/oauth/token"),
        }),
    );
    assert_eq!(slow_begin["user_code"], "USER-CODE");
    let slowed = rpc_ok(
        &mut world,
        "auth.login.complete",
        json!({ "schema_version": 1 }),
    );
    assert_eq!(slowed["state"], "slow_down");
    let read = rpc_ok(
        &mut world,
        "config.read",
        json!({
            "schema_version": 1,
            "session_id": session_id,
            "keys": ["profiles.openai-codex.credential_ref"],
        }),
    );
    let exported = read.to_string();
    assert!(!exported.contains(CODEX_REFRESH_FIXTURE));
    assert!(!exported.contains(&support::codex_access_token(
        CODEX_WORKSPACE,
        CODEX_EMAIL,
        "plus"
    )));
}

/// A store whose write always fails: the login refusal is
/// `storage_unavailable`, and no profile is produced.
struct FailingStore;

impl CredentialStore for FailingStore {
    fn kind(&self) -> StoreKind {
        StoreKind::Keychain
    }

    fn occupied(&self, _credential: &SecretRef) -> Result<bool, ProviderError> {
        Ok(false)
    }

    fn entry_accounts(&self, _service: &str) -> Result<Vec<String>, ProviderError> {
        Ok(Vec::new())
    }

    fn login(&self, _credential: &SecretRef, _secret: &[u8]) -> Result<(), ProviderError> {
        Err(ProviderError::StoreUnavailable {
            store: StoreKind::Keychain,
            reason: "scripted store denial".to_string(),
        })
    }

    fn resolve(&self, credential: &SecretRef) -> Result<Vec<u8>, ProviderError> {
        Err(ProviderError::CredentialAbsent {
            scope: credential.scope().to_string(),
        })
    }

    fn refresh(&self, _credential: &SecretRef, _secret: &[u8]) -> Result<(), ProviderError> {
        Ok(())
    }

    fn revoke(&self, _credential: &SecretRef) -> Result<(), ProviderError> {
        Ok(())
    }

    fn logout(&self, credential: &SecretRef) -> Result<(), ProviderError> {
        self.revoke(credential)
    }
}

/// Every untested wire branch answers its own class: no pending login, an
/// unknown mode, an unknown or mistyped parameter, a 401 exchange, a
/// transport fault, an occupied scope (conflict, prior bytes kept) and a
/// failed store write (storage_unavailable).
#[test]
fn auth_login_wire_codes_and_untested_branches() {
    let config = support::codex_login_config();

    // No pending login; an empty cancel reports none, a begin then cancel
    // drops the leg, and the next complete is the no-pending conflict.
    let mut world = support::open_world("codex-login-no-pending", Some(&config));
    world.runtime.login_credentials = Some(Arc::new(support::MapStore::new(StoreKind::Keychain)));
    let empty = rpc_ok(
        &mut world,
        "auth.login.cancel",
        json!({ "schema_version": 1 }),
    );
    assert_eq!(empty["state"], "none");
    let begun = rpc_ok(
        &mut world,
        "auth.login.begin",
        json!({ "schema_version": 1 }),
    );
    assert!(begun["state"].is_string());
    let cancelled = rpc_ok(
        &mut world,
        "auth.login.cancel",
        json!({ "schema_version": 1 }),
    );
    assert_eq!(cancelled["state"], "cancelled");
    assert_refusal(
        &mut world,
        "auth.login.complete",
        json!({ "schema_version": 1 }),
        "conflict",
        "no login is pending",
    );

    // Unknown mode, unknown parameter, mistyped parameter.
    let mut world = support::open_world("codex-login-bad-params", Some(&config));
    world.runtime.login_credentials = Some(Arc::new(support::MapStore::new(StoreKind::Keychain)));
    assert_refusal(
        &mut world,
        "auth.login.begin",
        json!({ "schema_version": 1, "mode": "bogus" }),
        "invalid_input",
        "unknown login mode",
    );
    assert_refusal(
        &mut world,
        "auth.login.begin",
        json!({ "schema_version": 1, "bogus": true }),
        "invalid_input",
        "unknown parameter",
    );
    assert_refusal(
        &mut world,
        "auth.login.begin",
        json!({ "schema_version": 1, "mode": 5 }),
        "invalid_input",
        "mode",
    );

    // A config without the canonical row names the missing connection.
    let missing = "config_version = 1\n\
        [connections.neighbor]\n\
        kind = \"api_key\"\n\
        endpoint = \"https://api.example.invalid/v1\"\n\
        credential_ref = \"keychain:rivect-test/codex-neighbor\"\n\
        [models.defaults]\n\
        model = { mode = \"auto\" }\n\
        effort = { mode = \"auto\" }\n\
        fallback = { mode = \"auto\" }\n";
    let mut world = support::open_world("codex-login-missing-connection", Some(missing));
    world.runtime.login_credentials = Some(Arc::new(support::MapStore::new(StoreKind::Keychain)));
    let message = assert_refusal(
        &mut world,
        "auth.login.begin",
        json!({ "schema_version": 1 }),
        "invalid_input",
        "openai-codex",
    );
    assert!(
        message.contains("[connections.openai-codex]"),
        "the refusal names the connection row: {message}"
    );
    assert!(
        message.contains("[profiles.openai-codex]"),
        "the refusal names the profile row: {message}"
    );

    // A 401 exchange is a denial; its body never reaches the diagnostic.
    let rejecting = TestPeer::start(|path, _body| match path {
        "/oauth/token" => (
            401,
            json!({ "error": "invalid_grant", "echo": "canary-code-value" }).to_string(),
        ),
        _ => (404, "{}".to_string()),
    });
    let mut world = support::open_world("codex-login-401", Some(&config));
    world.runtime.login_credentials = Some(Arc::new(support::MapStore::new(StoreKind::Keychain)));
    let begin = rpc_ok(
        &mut world,
        "auth.login.begin",
        json!({ "schema_version": 1, "token_endpoint": rejecting.url("/oauth/token") }),
    );
    let state = begin["state"].as_str().expect("pending state").to_string();
    let message = assert_refusal(
        &mut world,
        "auth.login.complete",
        json!({ "schema_version": 1, "redirect": callback(&state, "canary-code-value") }),
        "denied",
        "http status 401",
    );
    assert!(!message.contains("canary-code-value"));

    // A dead loopback endpoint is a transport fault, not invalid input.
    let mut world = support::open_world("codex-login-transport", Some(&config));
    world.runtime.login_credentials = Some(Arc::new(support::MapStore::new(StoreKind::Keychain)));
    let begin = rpc_ok(
        &mut world,
        "auth.login.begin",
        json!({
            "schema_version": 1,
            "token_endpoint": "http://127.0.0.1:1/oauth/token",
        }),
    );
    let state = begin["state"].as_str().expect("pending state").to_string();
    assert_refusal(
        &mut world,
        "auth.login.complete",
        json!({ "schema_version": 1, "redirect": callback(&state, "good-code") }),
        "outcome_unknown",
        "transport failed",
    );

    // A create-only scope is a conflict and its bytes stay identical.
    let accepting = TestPeer::start(|path, _body| match path {
        "/oauth/token" => (200, token_reply(CODEX_WORKSPACE, CODEX_EMAIL)),
        _ => (404, "{}".to_string()),
    });
    let mut world = support::open_world("codex-login-occupied", Some(&config));
    let store = Arc::new(support::MapStore::new(StoreKind::Keychain));
    world.runtime.login_credentials = Some(store.clone());
    let first = rpc_ok(
        &mut world,
        "auth.login.begin",
        json!({ "schema_version": 1, "token_endpoint": accepting.url("/oauth/token") }),
    );
    let first_state = first["state"].as_str().expect("pending state").to_string();
    rpc_ok(
        &mut world,
        "auth.login.complete",
        json!({ "schema_version": 1, "redirect": callback(&first_state, "good-code") }),
    );
    let reference = resolve_credential(&codex_config(), "openai-codex").expect("canonical ref");
    let prior = store.resolve(&reference).expect("prior material");
    let second = rpc_ok(
        &mut world,
        "auth.login.begin",
        json!({ "schema_version": 1, "token_endpoint": accepting.url("/oauth/token") }),
    );
    let second_state = second["state"].as_str().expect("pending state").to_string();
    assert_refusal(
        &mut world,
        "auth.login.complete",
        json!({ "schema_version": 1, "redirect": callback(&second_state, "good-code") }),
        "conflict",
        "already holds material",
    );
    assert_eq!(
        store.resolve(&reference).expect("prior material"),
        prior,
        "the active profile is byte-identical"
    );

    // A failed store write is a storage failure.
    let mut world = support::open_world("codex-login-store-failure", Some(&config));
    world.runtime.login_credentials = Some(Arc::new(FailingStore));
    let begin = rpc_ok(
        &mut world,
        "auth.login.begin",
        json!({ "schema_version": 1, "token_endpoint": accepting.url("/oauth/token") }),
    );
    let state = begin["state"].as_str().expect("pending state").to_string();
    assert_refusal(
        &mut world,
        "auth.login.complete",
        json!({ "schema_version": 1, "redirect": callback(&state, "good-code") }),
        "storage_unavailable",
        "unavailable",
    );

    // A store holding foreign material at the canonical scope denies
    // `storage_unavailable` instead of parsing it as a credential.
    let mut world = support::open_world("codex-login-stored-malformed", Some(&config));
    world.runtime.login_credentials = Some(Arc::new(support::MapStore::seeded(
        StoreKind::Keychain,
        &[(CODEX_REF, "not-a-codex-credential")],
    )));
    let begin = rpc_ok(
        &mut world,
        "auth.login.begin",
        json!({ "schema_version": 1, "token_endpoint": accepting.url("/oauth/token") }),
    );
    let state = begin["state"].as_str().expect("pending state").to_string();
    assert_refusal(
        &mut world,
        "auth.login.complete",
        json!({ "schema_version": 1, "redirect": callback(&state, "good-code") }),
        "storage_unavailable",
        "not a codex credential",
    );
}

/// The TUI `/login` command runs the same begin/complete methods and paints
/// the pending URL and the canonical profile.
#[test]
fn tui_login_command_uses_the_same_methods() {
    let peer = TestPeer::start(|path, _body| match path {
        "/oauth/token" => (200, token_reply(CODEX_WORKSPACE, CODEX_EMAIL)),
        _ => (404, "{}".to_string()),
    });
    let config = support::codex_login_config();
    let parsed = Config::parse_validated(&config).expect("the codex config parses");
    let mut world = support::open_world("codex-login-tui", Some(&config));
    let store = Arc::new(support::MapStore::new(StoreKind::Keychain));
    world.runtime.login_credentials = Some(store.clone());
    let reference = resolve_credential(&parsed, "openai-codex").expect("canonical ref");

    // The `/login` command begins the browser leg and paints the recorded
    // verification URL.
    let pending = login_command(&mut world.runtime, None).expect("the TUI begins a login");
    assert_eq!(pending.len(), 1);
    assert!(pending[0].contains("https://auth.openai.com/oauth/authorize?"));

    // The same pending leg is completed through `/login <callback>`; the
    // begin above uses the recorded endpoint, so the contract peer is chosen
    // through the same `auth.login.begin` method for the exchange itself.
    let begin = rpc_ok(
        &mut world,
        "auth.login.begin",
        json!({ "schema_version": 1, "token_endpoint": peer.url("/oauth/token") }),
    );
    let state = begin["state"].as_str().expect("pending state").to_string();
    let completed = login_command(&mut world.runtime, Some(&callback(&state, "good-code")))
        .expect("the TUI completes the login");
    assert_eq!(
        completed,
        vec![format!("Login complete: {CANONICAL_PROFILE}")]
    );
    assert!(store.occupied(&reference).expect("the store answers"));
}
