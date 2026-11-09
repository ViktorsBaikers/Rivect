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
use rivect::model::{Broker, NullLedger};
use rivect::providers::kimi::{self, KimiProvider};
use rivect::providers::openai_login::{
    self, CANONICAL_PROFILE, DeviceAdvance, DeviceEndpoints, DeviceLoginSession,
    LoginError as CodexLoginError, canonical_reference, read_credential,
};
use rivect::providers::{CredentialStore, ProviderError, SecretRef, StoreKind, resolve_credential};
use rivect::ui::login_command;
use serde_json::{Value, json};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
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

// ----- Kimi Code device login (SLICE-005) ---------------------------------

/// The Kimi Code row: one api-key declaration whose scope holds either the
/// device profile or the pasted key, and the fixed pin the state proof
/// never sends.
fn kimi_config() -> String {
    "config_version = 1\n\
     [connections.kimi-code]\n\
     kind = \"api_key\"\n\
     endpoint = \"https://api.kimi.com/coding/v1\"\n\
     credential_ref = \"keyring:rivect-test/kimi-device\"\n\
     profile = \"kimi-device\"\n\
     [profiles.kimi-device]\n\
     credential_ref = \"keyring:rivect-test/kimi-device\"\n\
     [models.defaults]\n\
     model = { mode = \"fixed\", connection = \"kimi-code\", model_id = \"kimi-k3\" }\n\
     effort = { mode = \"auto\" }\n\
     fallback = { mode = \"auto\" }\n"
        .to_string()
}

const KIMI_REF: &str = "keyring:rivect-test/kimi-device";
const KIMI_ACCESS: &str = "kimi-access-fixture-not-real";
const KIMI_REFRESH: &str = "kimi-refresh-fixture-not-real";

fn kimi_endpoints(peer: &TestPeer) -> kimi::Endpoints {
    kimi::Endpoints {
        device_authorization: peer.url("/device_authorization"),
        token: peer.url("/token"),
    }
}

const KIMI_API_REF: &str = "keyring:rivect-test/kimi-api";
const KIMI_API_KEY: &str = "sk-kimi-api-fixture-not-real";

/// One Kimi Code declaration bound at `reference`, pointed at `base` so a
/// real send reaches the contract peer.
fn kimi_config_at(base: &str, reference: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.kimi-code]\n\
         kind = \"api_key\"\n\
         endpoint = \"{base}/v1\"\n\
         credential_ref = \"{reference}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"kimi-code\", model_id = \"kimi-k3\" }}\n\
         effort = {{ mode = \"auto\" }}\n\
         fallback = {{ mode = \"auto\" }}\n"
    )
}

/// The stored device profile the lifecycle cases start from.
fn kimi_device_material(access: &str, refresh: &str) -> String {
    json!({
        "access_token": access,
        "refresh_token": refresh,
        "expires_at": 1_900_000_000u64,
        "account_id": "user-kimi-1",
    })
    .to_string()
}

/// One Messages answer the inference leg accepts whole.
fn kimi_answer_stream(text: &str) -> String {
    format!(
        "event: message_start\n\
         data: {}\n\n\
         event: content_block_start\n\
         data: {}\n\n\
         event: content_block_delta\n\
         data: {}\n\n\
         event: content_block_stop\n\
         data: {}\n\n\
         event: message_delta\n\
         data: {}\n\n\
         event: message_stop\n\
         data: {}\n\n",
        json!({"type": "message_start", "message": {"usage": {"input_tokens": 3}}}),
        json!({"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}),
        json!({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": text}}),
        json!({"type": "content_block_stop", "index": 0}),
        json!({"type": "message_delta", "delta": {"stop_reason": "end_turn"}, "usage": {"output_tokens": 1}}),
        json!({"type": "message_stop"}),
    )
}

/// One profile's real inference send through the shared Broker, on a plain
/// OS thread because the blocking client cannot build inside a runtime.
fn kimi_neighbor_send(
    config: &Config,
    store: Arc<support::MapStore>,
    prompt: &str,
) -> (String, usize) {
    let config = config.clone();
    let prompt = prompt.to_string();
    std::thread::spawn(move || {
        let provider = KimiProvider::new(&config, "kimi-code", store).expect("the adapter builds");
        let mut broker = Broker::new(Box::new(provider));
        let manifest = broker
            .prepare("main", &config, "/world/kimi", &prompt)
            .expect("the kimi pin prepares");
        let reply = broker
            .dispatch(&mut NullLedger, "/world/kimi", &manifest)
            .expect("the neighbour profile sends");
        (reply.text, broker.accounted_requests())
    })
    .join()
    .expect("the send thread joins")
}

/// One scripted Kimi peer: the usercode mint and the device poll. Modes
/// cover pending, slow_down, denial, expiry, an out-of-range lifetime, a
/// missing account claim and another account's token.
fn kimi_peer(mode: &'static str) -> (TestPeer, Arc<AtomicUsize>) {
    let polls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&polls);
    let lifetime = if matches!(mode, "short_life" | "http_404_expired") {
        1
    } else {
        10
    };
    let peer = TestPeer::start(move |path, _body| match path {
        "/device_authorization" => (
            200,
            json!({
                "device_code": "kimi-device-handle-fixture",
                "user_code": "KIMI-CODE",
                "verification_uri": "https://www.kimi.com/code/authorize",
                "verification_uri_complete": "https://www.kimi.com/code/authorize?code=KIMI-CODE",
                "interval": TEST_INTERVAL,
                "expires_in": lifetime,
            })
            .to_string(),
        ),
        "/token" => {
            let poll = counter.fetch_add(1, Ordering::SeqCst) + 1;
            let token = json!({
                "access_token": KIMI_ACCESS,
                "refresh_token": KIMI_REFRESH,
                "expires_in": 3600u64,
                "user_id": "user-kimi-1",
            })
            .to_string();
            match mode {
                "pending" if poll == 1 => {
                    (200, json!({ "error": "authorization_pending" }).to_string())
                }
                "slow_down" => (200, json!({ "error": "slow_down" }).to_string()),
                "denied" => (200, json!({ "error": "access_denied" }).to_string()),
                "expired" => (200, json!({ "error": "expired_token" }).to_string()),
                "token_expiry" => (
                    200,
                    json!({
                        "access_token": KIMI_ACCESS,
                        "expires_in": u64::MAX,
                        "user_id": "user-kimi-1",
                    })
                    .to_string(),
                ),
                "no_identity" => (
                    200,
                    json!({ "access_token": KIMI_ACCESS, "expires_in": 3600u64 }).to_string(),
                ),
                "account_b" => (
                    200,
                    json!({
                        "access_token": KIMI_ACCESS,
                        "refresh_token": KIMI_REFRESH,
                        "expires_in": 3600u64,
                        "user_id": "user-kimi-2",
                    })
                    .to_string(),
                ),
                "http_403" | "http_404" | "http_404_expired" => {
                    (if mode == "http_403" { 403 } else { 404 }, "{}".to_string())
                }
                _ => (200, token),
            }
        }
        _ => (404, "{}".to_string()),
    });
    (peer, polls)
}

/// The device leg writes one scoped profile: the account the token named,
/// the tokens never printable, and the poll count exact.
#[test]
fn kimi_device_login_writes_the_scoped_profile() {
    let (peer, polls) = kimi_peer("pending");
    let config = Config::parse_validated(&kimi_config()).expect("the kimi config parses");
    let mut device = kimi::begin_device_login(&config, "kimi-code", kimi_endpoints(&peer))
        .expect("the device leg begins");
    assert_eq!(device.connection(), "kimi-code");
    assert_eq!(device.profile(), "kimi-device");
    assert_eq!(device.user_code(), "KIMI-CODE");
    assert_eq!(
        device.verification_url(),
        "https://www.kimi.com/code/authorize"
    );
    assert_eq!(
        device.verification_uri_complete(),
        Some("https://www.kimi.com/code/authorize?code=KIMI-CODE")
    );
    assert_eq!(device.expires_in(), 10);
    assert!(!format!("{device:?}").contains("kimi-device-handle-fixture"));

    let store = support::MapStore::new(StoreKind::Keychain);
    let profile = {
        let mut profile = None;
        for _ in 0..8 {
            match kimi::advance_device_login(&config, "kimi-code", &mut device, &store)
                .expect("the poll answers")
            {
                kimi::DeviceAdvance::Complete(name) => {
                    profile = Some(name);
                    break;
                }
                kimi::DeviceAdvance::Pending | kimi::DeviceAdvance::SlowDown => {
                    std::thread::park_timeout(Duration::from_millis(1_100));
                }
            }
        }
        profile.expect("the pending leg completes")
    };
    assert_eq!(profile, "kimi-device");
    assert_eq!(
        polls.load(Ordering::SeqCst),
        2,
        "one pending then the token"
    );

    let reference = kimi::credential_reference(&config, "kimi-code").expect("the scoped ref");
    assert_eq!(reference.raw(), KIMI_REF);
    let credential = kimi::read_credential(&store, &reference).expect("the profile reads back");
    assert_eq!(credential.account_id(), "user-kimi-1");
    assert_eq!(credential.access_token(), KIMI_ACCESS);
    assert!(credential.expires_at() > 0);
    let rendered = format!("{credential:?}");
    assert!(!rendered.contains(KIMI_ACCESS));
    assert!(!rendered.contains(KIMI_REFRESH));
}

/// Pending keeps polling at the peer's interval, slow_down widens it, a
/// denial and the lifetime end the leg, and the peer's ceilings are typed.
#[test]
fn kimi_device_pending_slow_down_denial_and_expiry_are_bounded() {
    let config = Config::parse_validated(&kimi_config()).expect("the kimi config parses");
    let store = support::MapStore::new(StoreKind::Keychain);

    // Pending schedules the next poll; a call inside the interval performs
    // no second request.
    let (peer, polls) = kimi_peer("pending");
    let mut device = kimi::begin_device_login(&config, "kimi-code", kimi_endpoints(&peer))
        .expect("the leg begins");
    assert_eq!(
        kimi::advance_device_login(&config, "kimi-code", &mut device, &store)
            .expect("the first poll is pending"),
        kimi::DeviceAdvance::Pending
    );
    assert_eq!(polls.load(Ordering::SeqCst), 1);
    assert_eq!(
        kimi::advance_device_login(&config, "kimi-code", &mut device, &store)
            .expect("the interval has not elapsed"),
        kimi::DeviceAdvance::Pending
    );
    assert_eq!(polls.load(Ordering::SeqCst), 1, "no early poll");

    // slow_down answers its own state and widens the interval.
    let (peer, polls) = kimi_peer("slow_down");
    let mut device = kimi::begin_device_login(&config, "kimi-code", kimi_endpoints(&peer))
        .expect("the leg begins");
    assert_eq!(
        kimi::advance_device_login(&config, "kimi-code", &mut device, &store)
            .expect("the slow_down answer is classified"),
        kimi::DeviceAdvance::SlowDown
    );
    assert_eq!(polls.load(Ordering::SeqCst), 1);

    // A denial and an expired device code are their own classes.
    for (mode, expected) in [("denied", "DeviceDenied"), ("expired", "DeviceExpired")] {
        let (peer, polls) = kimi_peer(mode);
        let mut device = kimi::begin_device_login(&config, "kimi-code", kimi_endpoints(&peer))
            .expect("the leg begins");
        let error = kimi::advance_device_login(&config, "kimi-code", &mut device, &store)
            .expect_err("the poll denies");
        assert_eq!(kimi_variant(&error), expected, "{mode}: {error}");
        assert_eq!(polls.load(Ordering::SeqCst), 1, "{mode}");
    }

    // The lifetime is checked before a poll: an expired leg sends nothing.
    let (peer, polls) = kimi_peer("short_life");
    let mut device = kimi::begin_device_login(&config, "kimi-code", kimi_endpoints(&peer))
        .expect("the leg begins");
    assert_eq!(device.expires_in(), 1);
    std::thread::park_timeout(Duration::from_millis(1_100));
    let error = kimi::advance_device_login(&config, "kimi-code", &mut device, &store)
        .expect_err("the lifetime ended");
    assert_eq!(kimi_variant(&error), "DeviceExpired");
    assert_eq!(polls.load(Ordering::SeqCst), 0, "no poll past the window");

    // A status-only 403/404 from the token endpoint is ambiguous — the peer
    // states no RFC 8628 error member — so it stays pending until the
    // recorded lifetime ends the leg: never a success, never an early
    // re-enrol.
    for mode in ["http_403", "http_404"] {
        let (peer, polls) = kimi_peer(mode);
        let mut device = kimi::begin_device_login(&config, "kimi-code", kimi_endpoints(&peer))
            .expect("the leg begins");
        assert_eq!(
            kimi::advance_device_login(&config, "kimi-code", &mut device, &store)
                .expect("the ambiguous status is pending"),
            kimi::DeviceAdvance::Pending,
            "{mode}"
        );
        assert_eq!(polls.load(Ordering::SeqCst), 1, "{mode}");
    }
    let (peer, polls) = kimi_peer("http_404_expired");
    let mut device = kimi::begin_device_login(&config, "kimi-code", kimi_endpoints(&peer))
        .expect("the leg begins");
    assert_eq!(
        kimi::advance_device_login(&config, "kimi-code", &mut device, &store)
            .expect("the ambiguous status is pending"),
        kimi::DeviceAdvance::Pending
    );
    std::thread::park_timeout(Duration::from_millis(1_100));
    let error = kimi::advance_device_login(&config, "kimi-code", &mut device, &store)
        .expect_err("the ambiguous status never outlives the lifetime");
    assert_eq!(kimi_variant(&error), "DeviceExpired");
    assert_eq!(
        polls.load(Ordering::SeqCst),
        1,
        "no poll past the recorded window"
    );

    // Out-of-contract peer values are typed, never unbounded deadlines.
    let unbounded = TestPeer::start(|path, _body| match path {
        "/device_authorization" => (
            200,
            json!({
                "device_code": "handle",
                "user_code": "CODE",
                "verification_uri": "https://www.kimi.com/code/authorize",
                "interval": TEST_INTERVAL,
                "expires_in": u64::MAX,
            })
            .to_string(),
        ),
        _ => (404, "{}".to_string()),
    });
    let error = kimi::begin_device_login(&config, "kimi-code", kimi_endpoints(&unbounded))
        .expect_err("the lifetime ceiling denies");
    assert_eq!(kimi_variant(&error), "DeviceExpiryOutOfRange", "{error}");
    for (interval, expected) in [
        (json!(u64::MAX), "DeviceIntervalOutOfRange"),
        (json!("999999999999999999999999"), "MalformedField"),
        (json!(1.5), "MalformedField"),
    ] {
        let peer = TestPeer::start(move |path, _body| match path {
            "/device_authorization" => (
                200,
                json!({
                    "device_code": "handle",
                    "user_code": "CODE",
                    "verification_uri": "https://www.kimi.com/code/authorize",
                    "interval": interval,
                })
                .to_string(),
            ),
            _ => (404, "{}".to_string()),
        });
        let error = kimi::begin_device_login(&config, "kimi-code", kimi_endpoints(&peer))
            .expect_err("the interval ceiling denies");
        assert_eq!(kimi_variant(&error), expected, "{error}");
    }

    // A token lifetime beyond the ceiling and a token with no account claim
    // both deny without writing.
    for (mode, expected) in [
        ("token_expiry", "TokenExpiryOutOfRange"),
        ("no_identity", "MissingIdentity"),
    ] {
        let (peer, _polls) = kimi_peer(mode);
        let mut device = kimi::begin_device_login(&config, "kimi-code", kimi_endpoints(&peer))
            .expect("the leg begins");
        let error = kimi::advance_device_login(&config, "kimi-code", &mut device, &store)
            .expect_err("the token reply denies");
        assert_eq!(kimi_variant(&error), expected, "{mode}: {error}");
        assert!(
            !store
                .occupied(&kimi::credential_reference(&config, "kimi-code").expect("ref"))
                .expect("the store answers")
        );
    }
}

/// The account-device binding: a token for another account than the
/// enrolled profile denies and leaves the stored bytes untouched.
#[test]
fn kimi_device_binds_the_account_and_keeps_prior_bytes() {
    let config = Config::parse_validated(&kimi_config()).expect("the kimi config parses");
    let reference = kimi::credential_reference(&config, "kimi-code").expect("the scoped ref");
    let prior = json!({
        "access_token": "prior-access-fixture",
        "refresh_token": "prior-refresh-fixture",
        "expires_at": 1_900_000_000u64,
        "account_id": "user-kimi-1",
    })
    .to_string();
    let store = support::MapStore::seeded(StoreKind::Keychain, &[(KIMI_REF, prior.as_str())]);
    let (peer, polls) = kimi_peer("account_b");
    let mut device = kimi::begin_device_login(&config, "kimi-code", kimi_endpoints(&peer))
        .expect("the leg begins");
    let error = kimi::advance_device_login(&config, "kimi-code", &mut device, &store)
        .expect_err("another account is not bound");
    assert_eq!(kimi_variant(&error), "AccountMismatch", "{error}");
    assert_eq!(polls.load(Ordering::SeqCst), 1);
    let kept = store.resolve(&reference).expect("the prior profile");
    assert_eq!(
        String::from_utf8(kept).expect("utf-8 material"),
        prior,
        "the enrolled profile is byte-identical"
    );
}

/// The RPC leg: `begin` answers the recorded device fields, each
/// `complete` is one bounded poll, and a mismatched state, a foreign
/// origin, a cancel and a browser mode never reach the peer.
#[test]
fn kimi_device_rpc_reports_pending_and_creates_the_profile() {
    let (peer, polls) = kimi_peer("pending");
    let mut world = support::open_world("kimi-login-rpc", Some(&kimi_config()));
    let store = Arc::new(support::MapStore::new(StoreKind::Keychain));
    world.runtime.login_credentials = Some(store.clone());
    let session_id = session(&mut world);

    let begin = rpc_ok(
        &mut world,
        "auth.login.begin",
        json!({
            "schema_version": 1,
            "connection": "kimi-code",
            "mode": "device",
            "usercode_endpoint": peer.url("/device_authorization"),
            "device_token_endpoint": peer.url("/token"),
        }),
    );
    assert_eq!(begin["user_code"], "KIMI-CODE");
    assert_eq!(begin["expires_in"], 10);
    assert_eq!(
        begin["verification_url"],
        "https://www.kimi.com/code/authorize"
    );
    assert!(begin["state"].is_string(), "begin reports a pending state");

    assert_refusal(
        &mut world,
        "auth.login.complete",
        json!({ "schema_version": 1, "state": "foreign-state" }),
        "denied",
        "state does not match",
    );
    let pending = rpc_ok(
        &mut world,
        "auth.login.complete",
        json!({ "schema_version": 1 }),
    );
    assert_eq!(pending["state"], "pending");
    assert_eq!(polls.load(Ordering::SeqCst), 1);
    std::thread::park_timeout(Duration::from_secs(1));
    let completed = rpc_ok(
        &mut world,
        "auth.login.complete",
        json!({ "schema_version": 1 }),
    );
    assert_eq!(completed["profile"], "kimi-device");
    assert_eq!(polls.load(Ordering::SeqCst), 2);

    let parsed = Config::parse_validated(&kimi_config()).expect("parses");
    let reference = kimi::credential_reference(&parsed, "kimi-code").expect("the scoped ref");
    let credential = kimi::read_credential(store.as_ref(), &reference).expect("the profile");
    assert_eq!(credential.account_id(), "user-kimi-1");

    let read = rpc_ok(
        &mut world,
        "config.read",
        json!({
            "schema_version": 1,
            "session_id": session_id,
            "keys": ["profiles.kimi-device.credential_ref"],
        }),
    );
    let exported = read.to_string();
    assert!(!exported.contains(KIMI_ACCESS));
    assert!(!exported.contains(KIMI_REFRESH));

    // A cancel drops the leg and leaves no profile behind.
    let (fresh_peer, fresh_polls) = kimi_peer("pending");
    let fresh_begin = rpc_ok(
        &mut world,
        "auth.login.begin",
        json!({
            "schema_version": 1,
            "connection": "kimi-code",
            "mode": "device",
            "usercode_endpoint": fresh_peer.url("/device_authorization"),
            "device_token_endpoint": fresh_peer.url("/token"),
        }),
    );
    assert!(fresh_begin["state"].is_string());
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
    assert_eq!(
        fresh_polls.load(Ordering::SeqCst),
        0,
        "a cancel polls nothing"
    );

    // A foreign origin is refused before any request; a browser mode on the
    // device-only row is its own typed refusal. Both fixed endpoints are
    // proved: a counting peer sits on the admitted leg with the foreign host
    // on the other, so a probe that contacts the admitted peer is visible and
    // the typed refusal must land before either request is sent.
    let (counting, counted) = kimi_peer("pending");
    assert_refusal(
        &mut world,
        "auth.login.begin",
        json!({
            "schema_version": 1,
            "connection": "kimi-code",
            "mode": "device",
            "usercode_endpoint": counting.url("/device_authorization"),
            "device_token_endpoint": "https://evil.example/token",
        }),
        "invalid_input",
        "outside the recorded contract",
    );
    assert_eq!(counted.load(Ordering::SeqCst), 0, "zero requests");
    let (counting, counted) = kimi_peer("pending");
    assert_refusal(
        &mut world,
        "auth.login.begin",
        json!({
            "schema_version": 1,
            "connection": "kimi-code",
            "mode": "device",
            "usercode_endpoint": "https://evil.example/device_authorization",
            "device_token_endpoint": counting.url("/token"),
        }),
        "invalid_input",
        "outside the recorded contract",
    );
    assert_eq!(counted.load(Ordering::SeqCst), 0, "zero requests");
    assert_refusal(
        &mut world,
        "auth.login.begin",
        json!({
            "schema_version": 1,
            "connection": "kimi-code",
            "mode": "browser",
        }),
        "capability_unavailable",
        "device-code login only",
    );
}

/// Every recorded request body one scripted Kimi peer kept: `(path, body)`.
type KimiPeerLog = Arc<Mutex<Vec<(String, String)>>>;

/// One recording Kimi peer: the mint and the first poll answer, and every
/// request's body is kept for the assertions the state proof never made.
fn kimi_recording_peer() -> (TestPeer, KimiPeerLog) {
    let log = Arc::new(Mutex::new(Vec::new()));
    let entries = Arc::clone(&log);
    let peer = TestPeer::start(move |path, body| {
        entries
            .lock()
            .expect("peer log")
            .push((path.to_string(), body.to_string()));
        match path {
            "/device_authorization" => (
                200,
                json!({
                    "device_code": "kimi-device-handle-fixture",
                    "user_code": "KIMI-CODE",
                    "verification_uri": "https://www.kimi.com/code/authorize",
                    "interval": TEST_INTERVAL,
                    "expires_in": 10,
                })
                .to_string(),
            ),
            "/token" => (
                200,
                json!({
                    "access_token": KIMI_ACCESS,
                    "refresh_token": KIMI_REFRESH,
                    "expires_in": 3600u64,
                    "user_id": "user-kimi-1",
                })
                .to_string(),
            ),
            _ => (404, "{}".to_string()),
        }
    });
    (peer, log)
}

/// The mint posts exactly the recorded `client_id` JSON and the poll posts
/// the recorded form triple `grant_type`, `device_code` and `client_id`;
/// pairs are compared by name, so their order is not part of the contract.
#[test]
fn kimi_device_requests_carry_the_recorded_bodies() {
    let (peer, log) = kimi_recording_peer();
    let config = Config::parse_validated(&kimi_config()).expect("the kimi config parses");
    let mut device = kimi::begin_device_login(&config, "kimi-code", kimi_endpoints(&peer))
        .expect("the device leg begins");
    let store = support::MapStore::new(StoreKind::Keychain);
    assert_eq!(
        kimi::advance_device_login(&config, "kimi-code", &mut device, &store)
            .expect("the first poll completes"),
        kimi::DeviceAdvance::Complete("kimi-device".to_string())
    );

    let entries = log.lock().expect("peer log").clone();
    assert_eq!(entries.len(), 2, "one mint and one poll");
    assert_eq!(entries[0].0, "/device_authorization");
    let mint: Value = serde_json::from_str(&entries[0].1).expect("the mint body is json");
    assert_eq!(mint, json!({ "client_id": kimi::CLIENT_ID }));
    assert_eq!(entries[1].0, "/token");
    let form: Vec<(&str, &str)> = entries[1]
        .1
        .split('&')
        .map(|pair| pair.split_once('=').expect("a form pair"))
        .collect();
    let field = |name: &str| {
        form.iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| *value)
    };
    assert_eq!(form.len(), 3, "the poll body is the recorded grant triple");
    assert_eq!(
        field("grant_type"),
        Some("urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code"),
        "the recorded device grant"
    );
    assert_eq!(field("device_code"), Some("kimi-device-handle-fixture"));
    assert_eq!(field("client_id"), Some(kimi::CLIENT_ID));
}

/// One refresh peer: the first reply rotates the refresh token, the second
/// omits it, and both inference legs answer.
fn kimi_lifecycle_peer() -> (TestPeer, Arc<AtomicUsize>, KimiPeerLog) {
    let refreshes = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&refreshes);
    let log = Arc::new(Mutex::new(Vec::new()));
    let entries = Arc::clone(&log);
    let peer = TestPeer::start(move |path, body| {
        entries
            .lock()
            .expect("peer log")
            .push((path.to_string(), body.to_string()));
        match path {
            "/token" => {
                let refresh = counter.fetch_add(1, Ordering::SeqCst) + 1;
                let reply = if refresh == 1 {
                    json!({
                        "access_token": "fresh-access-1",
                        "refresh_token": "rotated-refresh-fixture",
                        "expires_in": 3600u64,
                        "user_id": "user-kimi-1",
                    })
                } else {
                    json!({
                        "access_token": "fresh-access-2",
                        "expires_in": 3600u64,
                        "user_id": "user-kimi-1",
                    })
                };
                (200, reply.to_string())
            }
            "/v1/models" => (200, json!({"data": [{"id": "kimi-k3"}]}).to_string()),
            "/v1/messages" => (200, kimi_answer_stream("neighbor answer")),
            _ => (404, "{}".to_string()),
        }
    });
    (peer, refreshes, log)
}

/// `auth.refresh`, `auth.logout` and `auth.revoke` are the product surface:
/// a refresh rotates the stored token and presents it on the next refresh,
/// and after every lifecycle op the neighbour profile still completes a
/// real send through the shared Broker.
#[test]
fn kimi_refresh_logout_and_revoke_stay_on_the_command_surface() {
    let (peer, refreshes, log) = kimi_lifecycle_peer();
    let device_config = Config::parse_validated(&kimi_config_at(&peer.base, KIMI_REF))
        .expect("the device binding parses");
    let api_config = Config::parse_validated(&kimi_config_at(&peer.base, KIMI_API_REF))
        .expect("the api binding parses");
    let device_ref = kimi::credential_reference(&device_config, "kimi-code").expect("device ref");
    let api_ref = SecretRef::parse(KIMI_API_REF).expect("the api ref");
    let prior = kimi_device_material("prior-access-fixture", "prior-refresh-fixture");
    let store = Arc::new(support::MapStore::seeded(
        StoreKind::Keychain,
        &[(KIMI_REF, prior.as_str()), (KIMI_API_REF, KIMI_API_KEY)],
    ));

    let mut device_world = support::open_world(
        "kimi-lifecycle-device",
        Some(&kimi_config_at(&peer.base, KIMI_REF)),
    );
    device_world.runtime.login_credentials = Some(store.clone());
    let mut api_world = support::open_world(
        "kimi-lifecycle-api",
        Some(&kimi_config_at(&peer.base, KIMI_API_REF)),
    );
    api_world.runtime.login_credentials = Some(store.clone());

    // Two refreshes: the first reply rotates the token, the second reply
    // omits it, and each request presents the token stored before it.
    for _turn in 0..2 {
        let refreshed = rpc_ok(
            &mut device_world,
            "auth.refresh",
            json!({
                "schema_version": 1,
                "connection": "kimi-code",
                "device_token_endpoint": peer.url("/token"),
            }),
        );
        assert_eq!(refreshed["profile"], "kimi-device");
    }
    assert_eq!(refreshes.load(Ordering::SeqCst), 2);
    let device = kimi::read_credential(store.as_ref(), &device_ref)
        .expect("the refreshed device profile reads back");
    assert_eq!(device.access_token(), "fresh-access-2");
    let bodies: Vec<String> = log
        .lock()
        .expect("peer log")
        .iter()
        .filter(|(path, _body)| path == "/token")
        .map(|(_path, body)| body.clone())
        .collect();
    assert!(
        bodies[0].contains("grant_type=refresh_token")
            && bodies[0].contains("refresh_token=prior-refresh-fixture"),
        "the first refresh presents the stored token: {}",
        bodies[0]
    );
    assert!(
        bodies[1].contains("refresh_token=rotated-refresh-fixture"),
        "the second refresh presents the rotated token: {}",
        bodies[1]
    );
    assert_eq!(
        store.resolve(&api_ref).expect("the neighbour scope"),
        KIMI_API_KEY.as_bytes(),
        "the neighbour profile is byte-identical after the refresh"
    );

    // The neighbour API-key profile completes a real send after the
    // refresh.
    let (text, accounted) =
        kimi_neighbor_send(&api_config, Arc::clone(&store), "goal: after refresh");
    assert_eq!(text, "neighbor answer");
    assert_eq!(accounted, 1);

    // Local logout of the API profile removes that scope only: the device
    // profile still completes a real send.
    let logged = rpc_ok(
        &mut api_world,
        "auth.logout",
        json!({ "schema_version": 1, "connection": "kimi-code" }),
    );
    assert_eq!(logged["profile"], "kimi-api");
    assert!(!store.occupied(&api_ref).expect("the store answers"));
    let (text, accounted) =
        kimi_neighbor_send(&device_config, Arc::clone(&store), "goal: after logout");
    assert_eq!(text, "neighbor answer");
    assert_eq!(accounted, 1);

    // A re-enrolled key revoked locally leaves the device profile usable.
    store
        .login(&api_ref, KIMI_API_KEY.as_bytes())
        .expect("the key scope is free after logout");
    let revoked = rpc_ok(
        &mut api_world,
        "auth.revoke",
        json!({ "schema_version": 1, "connection": "kimi-code" }),
    );
    assert_eq!(revoked["profile"], "kimi-api");
    assert!(!store.occupied(&api_ref).expect("the store answers"));
    let (text, accounted) =
        kimi_neighbor_send(&device_config, Arc::clone(&store), "goal: after revoke");
    assert_eq!(text, "neighbor answer");
    assert_eq!(accounted, 1);
}

/// A refresh reply bound to another account denies and leaves the stored
/// profile byte-identical: the rotate leg never re-keys a scope it cannot
/// prove.
#[test]
fn kimi_refresh_cross_account_denies_and_keeps_prior_bytes() {
    let (peer, polls) = kimi_peer("account_b");
    let mut world = support::open_world("kimi-refresh-account", Some(&kimi_config()));
    let prior = kimi_device_material("prior-access-fixture", "prior-refresh-fixture");
    let store = Arc::new(support::MapStore::seeded(
        StoreKind::Keychain,
        &[(KIMI_REF, prior.as_str())],
    ));
    world.runtime.login_credentials = Some(store.clone());
    assert_refusal(
        &mut world,
        "auth.refresh",
        json!({
            "schema_version": 1,
            "connection": "kimi-code",
            "device_token_endpoint": peer.url("/token"),
        }),
        "denied",
        "different account",
    );
    assert_eq!(polls.load(Ordering::SeqCst), 1, "one refresh leg crossed");
    let reference = SecretRef::parse(KIMI_REF).expect("the device ref");
    assert_eq!(
        String::from_utf8(store.resolve(&reference).expect("the prior profile"))
            .expect("utf-8 material"),
        prior,
        "the stored profile is byte-identical"
    );
}

/// A store that reports the scope occupied and then fails the read: the
/// account-binding check must surface the storage failure instead of
/// treating it as the intended other-shape case.
struct OccupiedBrokenStore;

impl CredentialStore for OccupiedBrokenStore {
    fn kind(&self) -> StoreKind {
        StoreKind::Keychain
    }

    fn occupied(&self, _credential: &SecretRef) -> Result<bool, ProviderError> {
        Ok(true)
    }

    fn entry_accounts(&self, _service: &str) -> Result<Vec<String>, ProviderError> {
        Ok(Vec::new())
    }

    fn login(&self, _credential: &SecretRef, _secret: &[u8]) -> Result<(), ProviderError> {
        Ok(())
    }

    fn resolve(&self, _credential: &SecretRef) -> Result<Vec<u8>, ProviderError> {
        Err(ProviderError::StoreUnavailable {
            store: StoreKind::Keychain,
            reason: "locked".to_string(),
        })
    }

    fn refresh(&self, _credential: &SecretRef, _secret: &[u8]) -> Result<(), ProviderError> {
        Ok(())
    }

    fn revoke(&self, _credential: &SecretRef) -> Result<(), ProviderError> {
        Ok(())
    }

    fn logout(&self, _credential: &SecretRef) -> Result<(), ProviderError> {
        Ok(())
    }
}

/// The account-device binding propagates a storage failure: only the
/// intended other-shape case is treated as the store's create-only denial,
/// and nothing is enrolled.
#[test]
fn kimi_device_account_binding_surfaces_a_storage_failure() {
    let (peer, polls) = kimi_peer("ok");
    let config = Config::parse_validated(&kimi_config()).expect("the kimi config parses");
    let mut device = kimi::begin_device_login(&config, "kimi-code", kimi_endpoints(&peer))
        .expect("the leg begins");
    let error = kimi::advance_device_login(&config, "kimi-code", &mut device, &OccupiedBrokenStore)
        .expect_err("the storage failure is not swallowed");
    assert!(
        matches!(
            error,
            kimi::KimiLoginError::Provider(ProviderError::StoreUnavailable { .. })
        ),
        "{error:?}"
    );
    assert_eq!(polls.load(Ordering::SeqCst), 1);
}

fn kimi_variant(error: &kimi::KimiLoginError) -> &'static str {
    match error {
        kimi::KimiLoginError::Entropy { .. } => "Entropy",
        kimi::KimiLoginError::ConnectionMissing { .. } => "ConnectionMissing",
        kimi::KimiLoginError::NotApiKey { .. } => "NotApiKey",
        kimi::KimiLoginError::Provider(_) => "Provider",
        kimi::KimiLoginError::EndpointNotRecorded { .. } => "EndpointNotRecorded",
        kimi::KimiLoginError::TokenRejected { .. } => "TokenRejected",
        kimi::KimiLoginError::MissingField { .. } => "MissingField",
        kimi::KimiLoginError::MalformedField { .. } => "MalformedField",
        kimi::KimiLoginError::MalformedResponse { .. } => "MalformedResponse",
        kimi::KimiLoginError::ResponseTooLarge => "ResponseTooLarge",
        kimi::KimiLoginError::Clock { .. } => "Clock",
        kimi::KimiLoginError::Serialization { .. } => "Serialization",
        kimi::KimiLoginError::DeviceDenied => "DeviceDenied",
        kimi::KimiLoginError::DeviceExpired => "DeviceExpired",
        kimi::KimiLoginError::Denied { .. } => "Denied",
        kimi::KimiLoginError::DeviceExpiryOutOfRange { .. } => "DeviceExpiryOutOfRange",
        kimi::KimiLoginError::DeviceIntervalOutOfRange { .. } => "DeviceIntervalOutOfRange",
        kimi::KimiLoginError::TokenExpiryOutOfRange { .. } => "TokenExpiryOutOfRange",
        kimi::KimiLoginError::MissingIdentity => "MissingIdentity",
        kimi::KimiLoginError::AccountMismatch => "AccountMismatch",
        kimi::KimiLoginError::StoredCredentialMalformed { .. } => "StoredCredentialMalformed",
        kimi::KimiLoginError::NotRefreshable { .. } => "NotRefreshable",
    }
}
