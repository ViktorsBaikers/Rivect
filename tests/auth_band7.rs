//! Vertex ADC resolution, Antigravity and Gemini CLI Code Assist project
//! provisioning proof (AC-005, AC-006, AC-007): the recorded source order,
//! the three file-type exchanges, the metadata leg, the refresh skew, the
//! create-only profile write, the bounded onboarding LROs, the
//! personal/Workspace project rule and the VPC-SC denial — against loopback
//! contract peers only. No test touches the real token, metadata, IAM or
//! Code Assist hosts.

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
use rivect::providers::antigravity_login::{
    self, AntigravityEndpoints, CODE_ASSIST_ORIGIN, CODE_ASSIST_SANDBOX_ORIGIN, Leg,
    LoginError as AntigravityError, ProvisioningBudget,
};
use rivect::providers::gemini_cli_login::{
    self, CodeAssistEndpoints, LoginError as CodeAssistError, OnboardingBudget, ProjectSource,
};
use rivect::providers::muse_login::{self, LoginError as MuseError};
use rivect::providers::vertex_login::{
    self, AdcEndpoints, AdcSources, CredentialSource, EndpointClass, LoginError, METADATA_URL,
    TOKEN_URL,
};
use rivect::providers::{CredentialStore, ProviderError, SecretRef, StoreKind};
use serde_json::{Value, json};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tempfile::TempDir;

/// A 2048-bit PKCS#8 RSA fixture (test-only, openssl generated).
const FIXTURE_KEY: &str = concat!(
    "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDNnqxT6Ut6ZKZj4pcF+NXyp+LB5qM51NS4bl2aLwYnm91ZtM8fmSWtQX81N1hrBs7xDtWgwxYxi175XCf23eo/XjvlSMrEQyKvcVV+r05w/Ckl0Ha0OhT3MKgDS3zkeYDpC+WMVsx5wgo/rs/f/Xi2m9gcpvIIzFcO0VFVCyW8Fma7lzBEpiYzUtpZa5QZ+AGrTENN/FKHQRw5o96/cmT8iR59X4UTFKm5NX0F/OEh5/E/8XGq2rxONB03UiQT95rD+mCMUYv6QWzi0LcY+JwoG5/NuOU1czcoD4FA66kgKYJYFB1yeolVH4Ccl1/d86j2lNW6axGXLUE7GUF45cu/AgMBAAECggEATGjknSIa3Fa+xmuTt7JqvwvIZknw6jK/AfJxcjR7UwjGzukz9wgQSjwGq53vi4YyLL5YgK8+dhbWqk+mwkRhIj9Afsn4H8ra/ttc7AD1Y2MxX04CbqMO23UHWoIY3UaRswiquuYegjirWlL6CMDGtQVg3/TiCIb26xi54qKL2ULG92Oc+aMi2eT1NgDegk+vHqlteH/mTOywgBFutItPHQrf5nJCwoRBdLn8OVZ3E9gm2UaiqkhYl5tUEimj8gwLvFISvvO373b9fFplnUdTlDE9PisStmqxCO0NxHFqIyj5wkvLvzqYX7R+Zpwsna0P+0wWtw5wMIDIHuA4f5oo0QKBgQD0qfI/mLZ+Oql14zeKOGXZbR+z9SwsvkCkLAH6zoZbZZKcSQxlBOXVJ/pfSJad6p6TXQoCnfk0M0WsFAi6HJWVbLNbZ2Ec8xq/HYXixXrL2AUN8sKfKuacejfKg8tqG14x3BTtEnwFdWa5FtRc5WoF16hstf835AmmMAIIlR5ptQKBgQDXJZw7kHUmCXCzwFSTwpoGn4GDctNQTnfNi/uWo45ssIb9zqIztDa8QQ3dOgSa8VRQBFuA89TolNMy/50FsFMN+kXKHww89Yt/CvxO1PwXYF9hEQ0t/vjA50GUXv4TyfWf4DLCLnBW0WVWR5xry1dPp52oM3rulkOTT3RnX774IwKBgFFs2d2Ggn3CIjHEu/A5UtQouBtZJimB69t3dfU1lIuIY2G2AfUAy0jEdFQPwWiu87WRikpSruRLiA174WenKbVAJvTtk+lhku418iAFnxeGPjBlMZZtXbCIEFdKw4D9uLyZRTGdLD9Y0iYZTfXYuA9XtYrwiw7bysZPRe37StLdAoGAekrCl4jxTgGnskTszmCbNJCOCa3HN6qipo+fHm0xk85zrOk7gbA6PJ+txcYov/nVNvaDHLV8nAecVSy+kHE9hIByEwW66xuXg0s3R4gBEziQfpg2qaJ4uw24VSH5wj3WBF5n+8Bx0qeLtpNV8l/O7VQVZXp9sghvuNg9DlV6M4kCgYBj7Pyfz3AFR51TcU4GQvZuvKN9tltMACcWr+Glr5OuGT11MoEec9j9wWryRf4Ae5XltbVFSiuXsdob+NNFIPFA/PNSz0B6PPna8Bse6dIkqi1MGrGx2k/ySMrAS6Pjpoq7yieByakpqLWYyZvB9FJXsyLUmIabMpF1u+/wr/7dGg==",
    "\n",
);

/// A 2030-01-01T00:00:00Z expiry the impersonation peer reports.
const IMPERSONATION_EXPIRY: &str = "2030-01-01T00:00:00Z";
const IMPERSONATION_EXPIRY_SECONDS: u64 = 1_893_456_000;

/// One request a contract peer received.
#[derive(Clone)]
struct Seen {
    line: String,
    head: String,
    body: String,
}

/// A scripted loopback peer: one JSON answer per request, judged by the
/// test's own closure. It is a plain `std` listener because the resolver
/// runs on the test thread (`reqwest::blocking` must not run inside a
/// Tokio context).
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
                        // A client that already gave up closes before the
                        // answer lands; the request stays recorded.
                        if stream.write_all(response.as_bytes()).is_err() {
                            continue;
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
            seen,
            stop,
            handle: Some(handle),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
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

/// Reads one HTTP request: the request line, the headers and the body under
/// its `Content-Length`.
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

/// Writes one ADC file into the test's own temporary directory.
fn adc_file(directory: &Path, name: &str, value: &Value) -> PathBuf {
    let path = directory.join(name);
    std::fs::write(
        &path,
        serde_json::to_vec(value).expect("the fixture serializes"),
    )
    .expect("the fixture writes");
    path
}

fn authorized_user(refresh_token: &str) -> Value {
    json!({
        "type": "authorized_user",
        "client_id": "fixture-client-id",
        "client_secret": "fixture-client-secret",
        "refresh_token": refresh_token,
    })
}

/// The PEM armor the fixture key needs; spelled from its label so the test
/// file carries no pasted key header.
fn fixture_pem() -> String {
    let label = "PRIVATE KEY";
    format!("-----BEGIN {label}-----\n{FIXTURE_KEY}-----END {label}-----\n")
}

fn service_account() -> Value {
    json!({
        "type": "service_account",
        "client_email": "fixture@example.iam.gserviceaccount.com",
        "private_key": fixture_pem(),
        "private_key_id": "fixture-key-id",
    })
}

/// A token answer whose access token names the granted refresh token, so a
/// test can prove which source's grant reached the peer.
fn token_answer(expires_in: u64) -> impl Fn(&Seen) -> (u16, String) {
    move |seen| {
        let refresh = form_value(&seen.body, "refresh_token").unwrap_or_else(|| "assertion".into());
        (
            200,
            json!({
                "access_token": format!("token-{refresh}"),
                "expires_in": expires_in,
            })
            .to_string(),
        )
    }
}

fn metadata_answer(seen: &Seen) -> (u16, String) {
    let flavor = seen
        .head
        .lines()
        .any(|line| line.eq_ignore_ascii_case("metadata-flavor: Google"));
    if !flavor {
        return (403, "{}".to_string());
    }
    (
        200,
        json!({ "access_token": "token-metadata", "expires_in": 3600 }).to_string(),
    )
}

fn impersonation_answer(seen: &Seen) -> (u16, String) {
    if seen.line.contains(":generateAccessToken") {
        return (
            200,
            json!({
                "accessToken": "token-impersonated",
                "expireTime": IMPERSONATION_EXPIRY,
            })
            .to_string(),
        );
    }
    token_answer(3600)(seen)
}

/// The value of one form member, percent-decoded.
fn form_value(body: &str, name: &str) -> Option<String> {
    body.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        (percent_decode(key).as_deref() == Some(name)).then(|| percent_decode(value))?
    })
}

fn percent_decode(raw: &str) -> Option<String> {
    let mut bytes = Vec::with_capacity(raw.len());
    let mut chars = raw.bytes();
    while let Some(byte) = chars.next() {
        if byte == b'%' {
            let high = hex(chars.next()?)?;
            let low = hex(chars.next()?)?;
            bytes.push(high << 4 | low);
        } else if byte == b'+' {
            bytes.push(b' ');
        } else {
            bytes.push(byte);
        }
    }
    String::from_utf8(bytes).ok()
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn base64url_decode(raw: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(raw.len() * 3 / 4);
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    for byte in raw.bytes() {
        let value = match byte {
            b'A'..=b'Z' => u32::from(byte - b'A'),
            b'a'..=b'z' => u32::from(byte - b'a') + 26,
            b'0'..=b'9' => u32::from(byte - b'0') + 52,
            b'-' | b'+' => 62,
            b'_' | b'/' => 63,
            b'=' => break,
            _ => return None,
        };
        buffer = (buffer << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the clock is after the epoch")
        .as_secs()
}

fn vertex_config() -> Config {
    Config::parse_validated(
        "config_version = 1\n\
         [connections.vertex]\n\
         kind = \"api_key\"\n\
         endpoint = \"https://us-central1-aiplatform.googleapis.com\"\n\
         credential_ref = \"keychain:rivect-test/vertex\"\n\
         [models.defaults]\n\
         model = { mode = \"auto\" }\n\
         effort = { mode = \"auto\" }\n\
         fallback = { mode = \"auto\" }\n",
    )
    .expect("the vertex config parses")
}

const VERTEX_SCOPE: &str = "keychain:rivect-test/vertex";

/// A live loopback peer plus the ADC inputs that point at it.
struct Harness {
    peer: Peer,
    root: TempDir,
    sources: AdcSources,
    metadata: Peer,
}

impl Harness {
    fn new(answer: impl Fn(&Seen) -> (u16, String) + Send + Sync + 'static) -> Self {
        let peer = Peer::start(answer);
        let metadata = Peer::start(metadata_answer);
        let root = tempfile::tempdir().expect("a temporary directory");
        let mut harness = Self {
            peer,
            root,
            sources: AdcSources {
                gac_file: None,
                user_adc_file: None,
                project: None,
                location: None,
                raw_env_token: false,
                endpoints: AdcEndpoints::recorded(),
            },
            metadata,
        };
        harness.sources = harness.inputs(Some("fixture-project"), Some("us-central1"));
        harness
    }

    fn file(&self, name: &str, value: &Value) -> PathBuf {
        adc_file(self.root.path(), name, value)
    }

    fn inputs(&self, project: Option<&str>, location: Option<&str>) -> AdcSources {
        AdcSources {
            gac_file: None,
            user_adc_file: None,
            project: project.map(str::to_string),
            location: location.map(str::to_string),
            raw_env_token: false,
            endpoints: AdcEndpoints {
                token: self.peer.url("/token"),
                metadata: self.metadata.url("/metadata"),
                iam: self.peer.url("/iam"),
            },
        }
    }
}

#[test]
fn vertex_adc_source_order() {
    let mut harness = Harness::new(token_answer(3600));
    harness.sources.gac_file = Some(harness.file("gac.json", &authorized_user("gac-refresh")));
    harness.sources.user_adc_file =
        Some(harness.file("user.json", &authorized_user("user-refresh")));
    let peer = &harness.peer;
    let metadata = &harness.metadata;

    let credential = vertex_login::resolve("vertex", &harness.sources).expect("the chain resolves");

    assert_eq!(credential.source(), CredentialSource::GacFile);
    assert_eq!(credential.access_token(), "token-gac-refresh");
    assert_eq!(credential.project(), "fixture-project");
    assert_eq!(credential.location(), "us-central1");
    let requests = peer.requests();
    assert_eq!(requests.len(), 1, "exactly one token exchange");
    assert_eq!(requests[0].line, "POST /token HTTP/1.1");
    assert!(
        metadata.requests().is_empty(),
        "the metadata leg is never reached once a file answers"
    );
}

#[test]
fn a_missing_application_credentials_file_denies_without_fallback() {
    let mut harness = Harness::new(token_answer(3600));
    harness.sources.gac_file = Some(harness.root.path().join("absent.json"));
    harness.sources.user_adc_file =
        Some(harness.file("user.json", &authorized_user("user-refresh")));

    let error = vertex_login::resolve("vertex", &harness.sources).expect_err("the named file wins");

    assert!(matches!(error, LoginError::GacFileMissing), "{error}");
    assert!(
        harness.peer.requests().is_empty(),
        "no exchange is attempted"
    );
    assert!(harness.metadata.requests().is_empty());
}

#[test]
fn a_raw_environment_token_is_refused() {
    let mut harness = Harness::new(token_answer(3600));
    harness.sources.gac_file = Some(harness.file("gac.json", &authorized_user("gac-refresh")));
    harness.sources.raw_env_token = true;

    let error =
        vertex_login::resolve("vertex", &harness.sources).expect_err("the token is no source");

    assert!(matches!(error, LoginError::RawTokenRefused), "{error}");
    assert!(harness.peer.requests().is_empty());
}

#[test]
fn the_user_adc_file_serves_when_the_named_file_is_absent() {
    let mut harness = Harness::new(token_answer(3600));
    harness.sources.user_adc_file =
        Some(harness.file("user.json", &authorized_user("user-refresh")));

    let credential =
        vertex_login::resolve("vertex", &harness.sources).expect("the user file answers");

    assert_eq!(credential.source(), CredentialSource::UserAdcFile);
    assert_eq!(credential.access_token(), "token-user-refresh");
    assert_eq!(harness.peer.requests().len(), 1);
}

#[test]
fn the_metadata_leg_carries_the_flavor_header() {
    let harness = Harness::new(token_answer(3600));

    let credential = vertex_login::resolve("vertex", &harness.sources).expect("metadata answers");

    assert_eq!(credential.source(), CredentialSource::Metadata);
    assert_eq!(credential.access_token(), "token-metadata");
    let requests = harness.metadata.requests();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].line.starts_with("GET /metadata "));
    assert!(
        requests[0]
            .head
            .lines()
            .any(|line| line.eq_ignore_ascii_case("metadata-flavor: Google")),
        "{}",
        requests[0].head
    );
    assert!(harness.peer.requests().is_empty());
}

#[test]
fn an_exhausted_source_chain_denies() {
    let peer = Peer::start(|_seen| (500u16, "{}".to_string()));
    let root = tempfile::tempdir().expect("a temporary directory");
    let mut inputs = AdcSources {
        gac_file: None,
        user_adc_file: Some(root.path().join("absent.json")),
        project: Some("fixture-project".to_string()),
        location: Some("us-central1".to_string()),
        raw_env_token: false,
        endpoints: AdcEndpoints::recorded(),
    };
    inputs.endpoints.token = peer.url("/token");
    inputs.endpoints.metadata = peer.url("/metadata");

    let error = vertex_login::resolve("vertex", &inputs).expect_err("no source answers");

    assert!(matches!(error, LoginError::CredentialsMissing), "{error}");
    assert_eq!(peer.requests().len(), 1, "only the metadata probe ran");
}

#[test]
fn a_service_account_file_signs_the_recorded_assertion() {
    let mut harness = Harness::new(token_answer(3600));
    harness.sources.gac_file = Some(harness.file("gac.json", &service_account()));

    let credential =
        vertex_login::resolve("vertex", &harness.sources).expect("the assertion is accepted");

    assert_eq!(credential.access_token(), "token-assertion");
    let requests = harness.peer.requests();
    assert_eq!(requests.len(), 1);
    let body = &requests[0].body;
    assert_eq!(
        form_value(body, "grant_type").as_deref(),
        Some("urn:ietf:params:oauth:grant-type:jwt-bearer")
    );
    let assertion = form_value(body, "assertion").expect("the form carries the assertion");
    let mut segments = assertion.split('.');
    let header = segments.next().expect("the jwt header");
    let payload = segments.next().expect("the jwt payload");
    let signature = segments.next().expect("the jwt signature");
    assert!(segments.next().is_none());
    assert_eq!(
        base64url_decode(header).map(|bytes| String::from_utf8_lossy(&bytes).to_string()),
        Some(r#"{"alg":"RS256","kid":"fixture-key-id","typ":"JWT"}"#.to_string())
    );
    let claims: Value =
        serde_json::from_slice(&base64url_decode(payload).expect("the payload decodes"))
            .expect("the payload is json");
    assert_eq!(
        claims.get("iss").and_then(Value::as_str),
        Some("fixture@example.iam.gserviceaccount.com")
    );
    assert_eq!(
        claims.get("aud").and_then(Value::as_str),
        Some(harness.sources.endpoints.token.as_str())
    );
    assert_eq!(
        claims.get("scope").and_then(Value::as_str),
        Some("https://www.googleapis.com/auth/cloud-platform")
    );
    let issued = claims.get("iat").and_then(Value::as_u64).expect("iat");
    let expires = claims.get("exp").and_then(Value::as_u64).expect("exp");
    assert_eq!(expires - issued, 3600);
    assert_eq!(signature.len(), 342, "a 2048-bit RS256 signature");
}

#[test]
fn an_authorized_user_file_posts_the_refresh_grant() {
    let mut harness = Harness::new(token_answer(3600));
    harness.sources.gac_file = Some(harness.file("gac.json", &authorized_user("fixture-refresh")));

    let credential = vertex_login::resolve("vertex", &harness.sources).expect("the refresh lands");

    assert_eq!(credential.access_token(), "token-fixture-refresh");
    let requests = harness.peer.requests();
    let body = &requests[0].body;
    assert_eq!(
        form_value(body, "grant_type").as_deref(),
        Some("refresh_token")
    );
    assert_eq!(
        form_value(body, "client_id").as_deref(),
        Some("fixture-client-id")
    );
    assert_eq!(
        form_value(body, "client_secret").as_deref(),
        Some("fixture-client-secret")
    );
    assert_eq!(
        form_value(body, "refresh_token").as_deref(),
        Some("fixture-refresh")
    );
}

#[test]
fn impersonation_targets_the_recorded_iam_path() {
    let file_host = Peer::start(|_seen| (500u16, "{}".to_string()));
    let mut harness = Harness::new(impersonation_answer);
    let impersonation_url = format!(
        "{}/v1/projects/-/serviceAccounts/target@example.iam.gserviceaccount.com:generateAccessToken",
        file_host.base
    );
    let file = json!({
        "type": "impersonated_service_account",
        "service_account_impersonation_url": impersonation_url,
        "source_credentials": authorized_user("source-refresh"),
        "delegates": ["delegate@example.iam.gserviceaccount.com"],
    });
    harness.sources.gac_file = Some(harness.file("gac.json", &file));

    let credential =
        vertex_login::resolve("vertex", &harness.sources).expect("the exchange resolves");

    assert_eq!(credential.access_token(), "token-impersonated");
    assert_eq!(
        credential.expires_at(),
        IMPERSONATION_EXPIRY_SECONDS - 60,
        "the skew is subtracted from the reply's own expiry"
    );
    let requests = harness.peer.requests();
    assert_eq!(requests.len(), 2, "source token, then the IAM exchange");
    assert_eq!(requests[0].line, "POST /token HTTP/1.1");
    assert_eq!(
        requests[1].line,
        "POST /iam/projects/-/serviceAccounts/target@example.iam.gserviceaccount.com:generateAccessToken HTTP/1.1"
    );
    assert!(
        requests[1]
            .head
            .lines()
            .any(|line| line.eq_ignore_ascii_case("authorization: Bearer token-source-refresh")),
        "{}",
        requests[1].head
    );
    let payload: Value = serde_json::from_str(&requests[1].body).expect("a json body");
    assert_eq!(
        payload.get("lifetime").and_then(Value::as_str),
        Some("3600s")
    );
    assert_eq!(
        payload.get("scope"),
        Some(&json!(["https://www.googleapis.com/auth/cloud-platform"]))
    );
    assert_eq!(
        payload.get("delegates"),
        Some(&json!(["delegate@example.iam.gserviceaccount.com"]))
    );
    assert!(
        file_host.requests().is_empty(),
        "the file's own URL host never receives the exchange"
    );
}

#[test]
fn a_service_account_source_completes_the_impersonation_chain() {
    let mut harness = Harness::new(impersonation_answer);
    let impersonation_url = format!(
        "{}/v1/projects/-/serviceAccounts/target@example.iam.gserviceaccount.com:generateAccessToken",
        harness.peer.base
    );
    let file = json!({
        "type": "impersonated_service_account",
        "service_account_impersonation_url": impersonation_url,
        "source_credentials": service_account(),
    });
    harness.sources.gac_file = Some(harness.file("gac.json", &file));

    let credential = vertex_login::resolve("vertex", &harness.sources).expect("the chain resolves");

    assert_eq!(credential.access_token(), "token-impersonated");
    let requests = harness.peer.requests();
    assert_eq!(requests.len(), 2, "source assertion, then the IAM exchange");
    assert_eq!(requests[0].line, "POST /token HTTP/1.1");
    let assertion =
        form_value(&requests[0].body, "assertion").expect("the form carries the assertion");
    let mut segments = assertion.split('.');
    let payload = segments.nth(1).expect("the jwt payload");
    let signature = segments.next().expect("the jwt signature");
    assert!(segments.next().is_none());
    let claims: Value =
        serde_json::from_slice(&base64url_decode(payload).expect("the payload decodes"))
            .expect("the payload is json");
    assert_eq!(
        claims.get("iss").and_then(Value::as_str),
        Some("fixture@example.iam.gserviceaccount.com")
    );
    assert_eq!(
        claims.get("aud").and_then(Value::as_str),
        Some(harness.sources.endpoints.token.as_str())
    );
    let issued = claims.get("iat").and_then(Value::as_u64).expect("iat");
    let expires = claims.get("exp").and_then(Value::as_u64).expect("exp");
    assert_eq!(expires - issued, 3600);
    assert_eq!(signature.len(), 342, "a 2048-bit RS256 signature");
    assert_eq!(
        requests[1].line,
        "POST /iam/projects/-/serviceAccounts/target@example.iam.gserviceaccount.com:generateAccessToken HTTP/1.1"
    );
    assert!(
        requests[1]
            .head
            .lines()
            .any(|line| line.eq_ignore_ascii_case("authorization: Bearer token-assertion")),
        "{}",
        requests[1].head
    );
    vertex_login::resolve("vertex", &harness.sources).expect("the cached token serves");
    assert_eq!(
        harness.peer.requests().len(),
        2,
        "the impersonated token is cached"
    );
}

#[test]
fn an_unrecorded_file_type_denies() {
    let mut harness = Harness::new(token_answer(3600));
    harness.sources.gac_file = Some(harness.file(
        "gac.json",
        &json!({ "type": "external_account", "audience": "fixture" }),
    ));

    let error = vertex_login::resolve("vertex", &harness.sources).expect_err("the type is refused");

    assert!(
        matches!(
            error,
            LoginError::UnsupportedCredentialType {
                class: CredentialSource::GacFile
            }
        ),
        "{error}"
    );
    assert!(harness.peer.requests().is_empty());
}

#[test]
fn an_endpoint_outside_the_contract_denies_before_a_request() {
    let harness = Harness::new(token_answer(3600));
    let mut inputs = harness.inputs(Some("fixture-project"), Some("us-central1"));
    inputs.gac_file = Some(adc_file(
        harness.root.path(),
        "gac.json",
        &authorized_user("fixture-refresh"),
    ));
    inputs.endpoints.token = "https://evil.example/token".to_string();

    let error = vertex_login::resolve("vertex", &inputs).expect_err("a foreign origin is refused");

    assert!(
        matches!(error, LoginError::EndpointNotAdmitted { .. }),
        "{error}"
    );
    assert!(harness.peer.requests().is_empty());
    assert_eq!(TOKEN_URL, "https://oauth2.googleapis.com/token");
    assert_eq!(
        METADATA_URL,
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
    );
}

#[test]
fn a_missing_project_or_location_denies() {
    let harness = Harness::new(token_answer(3600));
    let mut inputs = harness.inputs(None, Some("us-central1"));
    let error = vertex_login::resolve("vertex", &inputs).expect_err("the project is required");
    assert!(matches!(error, LoginError::MissingProject), "{error}");

    inputs = harness.inputs(Some("fixture-project"), Some("  "));
    let error = vertex_login::resolve("vertex", &inputs).expect_err("the location is required");
    assert!(matches!(error, LoginError::MissingLocation), "{error}");
    assert!(harness.peer.requests().is_empty());
}

#[test]
fn the_skew_reissues_an_expired_cached_token() {
    let mut harness = Harness::new(token_answer(30));
    harness.sources.gac_file = Some(harness.file("gac.json", &authorized_user("fixture-refresh")));

    let first = vertex_login::resolve("vertex", &harness.sources).expect("the first resolution");
    let second = vertex_login::resolve("vertex", &harness.sources).expect("the second resolution");

    assert!(
        first.expires_at() < now_seconds(),
        "a 30 s lifetime is already inside the 60 s skew"
    );
    assert_eq!(
        harness.peer.requests().len(),
        2,
        "the second call re-exchanges"
    );
    assert_eq!(second.source(), CredentialSource::GacFile);
    assert_eq!(second.project(), "fixture-project");
    assert_eq!(second.location(), "us-central1");
}

#[test]
fn a_live_cached_token_serves_the_second_resolution() {
    let mut harness = Harness::new(token_answer(3600));
    harness.sources.gac_file = Some(harness.file("gac.json", &authorized_user("fixture-refresh")));

    let first = vertex_login::resolve("vertex", &harness.sources).expect("the first resolution");
    let second = vertex_login::resolve("vertex", &harness.sources).expect("the second resolution");

    assert_eq!(
        harness.peer.requests().len(),
        1,
        "the cache serves the second call"
    );
    assert_eq!(first.access_token(), second.access_token());
    assert_eq!(first.expires_at(), second.expires_at());
}

#[test]
fn vertex_profile_publishes_the_canonical_credential_bytes() {
    let mut harness = Harness::new(token_answer(3600));
    harness.sources.gac_file = Some(harness.file("gac.json", &authorized_user("fixture-refresh")));
    let config = vertex_config();
    let store = support::MapStore::new(StoreKind::Keychain);
    let reference = SecretRef::parse(VERTEX_SCOPE).expect("the fixture reference parses");

    let profile = vertex_login::login(&config, "vertex", &harness.sources, &store)
        .expect("the profile is published");

    assert_eq!(profile, "vertex");
    let bytes = store.resolve(&reference).expect("the profile is stored");
    let credential =
        vertex_login::read(&store, &reference).expect("the profile reads back through its struct");
    let expected = format!(
        "{{\"source\":\"gac_file\",\"project\":\"fixture-project\",\"location\":\"us-central1\",\"access_token\":\"token-fixture-refresh\",\"expires_at\":{}}}",
        credential.expires_at()
    );
    assert_eq!(
        String::from_utf8(bytes.clone()).expect("utf-8 bytes"),
        expected
    );
    assert_eq!(credential.source(), CredentialSource::GacFile);
    assert_eq!(credential.project(), "fixture-project");
    assert_eq!(credential.location(), "us-central1");
    let rendered = format!("{credential:?}");
    assert!(rendered.contains("<redacted>"), "{rendered}");
    assert!(!rendered.contains("token-fixture-refresh"), "{rendered}");

    let occupied = vertex_login::login(&config, "vertex", &harness.sources, &store)
        .expect_err("enrollment is create-only");
    assert!(
        matches!(
            occupied,
            LoginError::Provider(ProviderError::CredentialOccupied { .. })
        ),
        "{occupied}"
    );
    assert_eq!(
        store.resolve(&reference).expect("the profile is untouched"),
        bytes,
        "a refused write leaves the prior bytes byte-identical"
    );
}

/// A stored Vertex profile whose binding a refresh must keep.
const STORED_VERTEX: &str = "{\"source\":\"gac_file\",\"project\":\"fixture-project\",\"location\":\"us-central1\",\"access_token\":\"stale-token\",\"expires_at\":1}";

fn stored_vertex_store() -> support::MapStore {
    support::MapStore::seeded(StoreKind::Keychain, &[(VERTEX_SCOPE, STORED_VERTEX)])
}

#[test]
fn vertex_refresh_preserves_the_stored_binding() {
    let mut harness = Harness::new(token_answer(3600));
    harness.sources.gac_file = Some(harness.file("gac.json", &authorized_user("refreshed")));
    let store = stored_vertex_store();
    let reference = SecretRef::parse(VERTEX_SCOPE).expect("the fixture reference parses");
    // A caller naming another binding must not rewrite the stored one.
    let mut sources = harness.inputs(Some("other-project"), Some("europe-west4"));
    sources.gac_file = harness.sources.gac_file.clone();

    let before = now_seconds();
    let profile = vertex_login::refresh(&store, &reference, &sources).expect("the refresh lands");
    let after = now_seconds();

    assert_eq!(profile, "vertex");
    let refreshed = vertex_login::read(&store, &reference).expect("the profile reads back");
    assert_eq!(refreshed.source(), CredentialSource::GacFile);
    assert_eq!(refreshed.project(), "fixture-project");
    assert_eq!(refreshed.location(), "us-central1");
    assert_eq!(refreshed.access_token(), "token-refreshed");
    // The reply's 3600 s under the recorded 60 s skew, bracketed by the
    // clock readings taken around the call.
    assert!(
        (before + 3540..=after + 3540).contains(&refreshed.expires_at()),
        "the expiry is now + expires_in - 60 s, got {}",
        refreshed.expires_at()
    );
    assert_eq!(harness.peer.requests().len(), 1, "one exchange");
}

#[test]
fn vertex_refresh_records_the_source_it_actually_used() {
    let mut harness = Harness::new(token_answer(3600));
    // The stored binding names the GAC file, but only the user ADC file is
    // configured now, so the fresh token comes from a different source.
    harness.sources.user_adc_file =
        Some(harness.file("user.json", &authorized_user("user-refresh")));
    let store = stored_vertex_store();
    let reference = SecretRef::parse(VERTEX_SCOPE).expect("the fixture reference parses");

    vertex_login::refresh(&store, &reference, &harness.sources).expect("the refresh lands");

    let refreshed = vertex_login::read(&store, &reference).expect("the profile reads back");
    assert_eq!(
        refreshed.source(),
        CredentialSource::UserAdcFile,
        "the stored source names the artifact the refresh obtained"
    );
    assert_eq!(refreshed.access_token(), "token-user-refresh");
    assert_eq!(refreshed.project(), "fixture-project");
    assert_eq!(refreshed.location(), "us-central1");
}

#[test]
fn vertex_refresh_of_a_failed_exchange_leaves_the_bytes_identical() {
    let mut harness = Harness::new(|_seen| (500u16, "{}".to_string()));
    harness.sources.gac_file = Some(harness.file("gac.json", &authorized_user("fixture-refresh")));
    let store = stored_vertex_store();
    let reference = SecretRef::parse(VERTEX_SCOPE).expect("the fixture reference parses");

    let error =
        vertex_login::refresh(&store, &reference, &harness.sources).expect_err("the peer rejects");

    assert!(
        matches!(
            error,
            LoginError::ExchangeRejected {
                class: EndpointClass::Token,
                status: 500
            }
        ),
        "{error}"
    );
    assert_eq!(
        store.resolve(&reference).expect("the profile is untouched"),
        STORED_VERTEX.as_bytes()
    );
}

#[test]
fn vertex_refresh_refuses_a_raw_environment_token() {
    let harness = Harness::new(token_answer(3600));
    let store = stored_vertex_store();
    let reference = SecretRef::parse(VERTEX_SCOPE).expect("the fixture reference parses");
    let mut sources = harness.inputs(Some("fixture-project"), Some("us-central1"));
    sources.raw_env_token = true;

    let error =
        vertex_login::refresh(&store, &reference, &sources).expect_err("the token is no source");

    assert!(matches!(error, LoginError::RawTokenRefused), "{error}");
    assert_eq!(
        store.resolve(&reference).expect("the profile is untouched"),
        STORED_VERTEX.as_bytes()
    );
    assert!(harness.peer.requests().is_empty());
}

#[test]
fn a_failed_login_exchange_publishes_no_profile() {
    let mut harness = Harness::new(|_seen| (500u16, "hostile-peer-body".to_string()));
    harness.sources.gac_file = Some(harness.file("gac.json", &authorized_user("fixture-refresh")));
    let config = vertex_config();
    let store = support::MapStore::new(StoreKind::Keychain);
    let reference = SecretRef::parse(VERTEX_SCOPE).expect("the fixture reference parses");

    // The typed class itself is proven by `a_failed_token_exchange_denies_typed`;
    // this case owns the store predicate.
    let _error = vertex_login::login(&config, "vertex", &harness.sources, &store)
        .expect_err("the peer rejects");

    assert!(
        matches!(
            store.resolve(&reference),
            Err(ProviderError::CredentialAbsent { .. })
        ),
        "a failed exchange writes nothing"
    );
}

#[test]
fn a_service_account_file_without_an_email_denies_before_the_exchange() {
    let mut harness = Harness::new(token_answer(3600));
    harness.sources.gac_file = Some(harness.file(
        "gac.json",
        &json!({
            "type": "service_account",
            "client_email": "",
            "private_key": fixture_pem(),
        }),
    ));

    let error =
        vertex_login::resolve("vertex", &harness.sources).expect_err("the account has no email");

    assert!(
        matches!(
            error,
            LoginError::MissingField {
                field: "client_email"
            }
        ),
        "{error}"
    );
    assert!(
        harness.peer.requests().is_empty(),
        "the account is checked before any exchange"
    );
    assert!(harness.metadata.requests().is_empty());
}

#[test]
fn a_service_account_file_without_a_usable_key_denies_before_the_exchange() {
    let mut harness = Harness::new(token_answer(3600));
    harness.sources.gac_file = Some(harness.file(
        "gac.json",
        &json!({
            "type": "service_account",
            "client_email": "fixture@example.iam.gserviceaccount.com",
            "private_key": "not a pkcs8 key",
        }),
    ));

    let error = vertex_login::resolve("vertex", &harness.sources).expect_err("the key is unusable");

    assert!(matches!(error, LoginError::PrivateKeyUnusable), "{error}");
    assert!(
        harness.peer.requests().is_empty(),
        "the assertion is signed before any exchange"
    );
}

#[test]
fn foreign_vertex_material_is_refused_and_refresh_writes_nothing() {
    const FOREIGN: &str = "{\"token\":\"x\"}";
    let harness = Harness::new(token_answer(3600));
    let store = support::MapStore::seeded(StoreKind::Keychain, &[(VERTEX_SCOPE, FOREIGN)]);
    let reference = SecretRef::parse(VERTEX_SCOPE).expect("the fixture reference parses");

    let error = vertex_login::read(&store, &reference).expect_err("foreign material");
    assert!(
        matches!(error, LoginError::StoredCredentialMalformed { .. }),
        "{error}"
    );
    let error = vertex_login::refresh(&store, &reference, &harness.sources)
        .expect_err("the stored profile is refused");
    assert!(
        matches!(error, LoginError::StoredCredentialMalformed { .. }),
        "{error}"
    );
    assert_eq!(
        store
            .resolve(&reference)
            .expect("the material is untouched"),
        FOREIGN.as_bytes()
    );
    assert!(harness.peer.requests().is_empty());
}

#[test]
fn an_impersonation_url_without_a_target_denies() {
    let mut harness = Harness::new(impersonation_answer);
    let file = json!({
        "type": "impersonated_service_account",
        "service_account_impersonation_url":
            "http://127.0.0.1:9/v1/projects/-/serviceAccounts/",
        "source_credentials": authorized_user("source-refresh"),
    });
    harness.sources.gac_file = Some(harness.file("gac.json", &file));

    let error = vertex_login::resolve("vertex", &harness.sources).expect_err("no target");
    assert!(
        matches!(error, LoginError::ImpersonatedTargetMissing),
        "{error}"
    );

    let file = json!({
        "type": "impersonated_service_account",
        "service_account_impersonation_url":
            "http://127.0.0.1:9/v1/projects/-/serviceAccounts/target%2Fextra:generateAccessToken",
        "source_credentials": authorized_user("source-refresh"),
    });
    harness.sources.gac_file = Some(harness.file("gac.json", &file));

    let error = vertex_login::resolve("vertex", &harness.sources).expect_err("a rewritten path");
    assert!(
        matches!(error, LoginError::ImpersonatedTargetMalformed),
        "{error}"
    );
    assert!(
        harness.peer.requests().is_empty(),
        "the target is parsed before any exchange runs"
    );
}

#[test]
fn a_failed_token_exchange_denies_typed() {
    let peer = Peer::start(|_seen| (500u16, "hostile-peer-body".to_string()));
    let root = tempfile::tempdir().expect("a temporary directory");
    let mut inputs = AdcSources {
        gac_file: Some(adc_file(
            root.path(),
            "gac.json",
            &authorized_user("fixture-refresh"),
        )),
        user_adc_file: None,
        project: Some("fixture-project".to_string()),
        location: Some("us-central1".to_string()),
        raw_env_token: false,
        endpoints: AdcEndpoints::recorded(),
    };
    inputs.endpoints.token = peer.url("/token");
    inputs.endpoints.metadata = peer.url("/metadata");

    let error = vertex_login::resolve("vertex", &inputs).expect_err("the peer rejects");

    assert!(
        matches!(
            error,
            LoginError::ExchangeRejected {
                class: EndpointClass::Token,
                status: 500
            }
        ),
        "{error}"
    );
    let rendered = error.to_string();
    assert!(!rendered.contains("hostile-peer-body"), "{rendered}");
    assert!(!rendered.contains("fixture-refresh"), "{rendered}");
    assert_eq!(peer.requests().len(), 1);
}

#[test]
fn one_resolution_serves_concurrent_callers() {
    let slow = |seen: &Seen| {
        std::thread::sleep(Duration::from_millis(150));
        token_answer(3600)(seen)
    };
    let mut harness = Harness::new(slow);
    harness.sources.gac_file =
        Some(harness.file("gac.json", &authorized_user("concurrent-refresh")));
    let sources = Arc::new(harness.sources);

    let (first, second) = std::thread::scope(|scope| {
        let one = scope.spawn(|| vertex_login::resolve("vertex", &sources));
        let two = scope.spawn(|| vertex_login::resolve("vertex", &sources));
        (
            one.join().expect("the first caller joins"),
            two.join().expect("the second caller joins"),
        )
    });

    let first = first.expect("the first caller resolves");
    let second = second.expect("the second caller resolves");
    assert_eq!(harness.peer.requests().len(), 1, "one shared exchange");
    assert_eq!(first.access_token(), second.access_token());
    assert_eq!(first.expires_at(), second.expires_at());
}

#[test]
fn distinct_credential_files_do_not_share_a_cached_token() {
    let mut harness = Harness::new(token_answer(3600));
    harness.sources.gac_file = Some(harness.file("first.json", &authorized_user("first-refresh")));

    let first = vertex_login::resolve("vertex", &harness.sources).expect("the first file resolves");
    harness.sources.gac_file =
        Some(harness.file("second.json", &authorized_user("second-refresh")));
    let second =
        vertex_login::resolve("vertex", &harness.sources).expect("the second file resolves");

    assert_eq!(
        harness.peer.requests().len(),
        2,
        "each file is its own cached source"
    );
    assert_eq!(first.access_token(), "token-first-refresh");
    assert_eq!(second.access_token(), "token-second-refresh");
}

/// The Antigravity connection the producer binds.
const ANTIGRAVITY_SCOPE: &str = "keychain:rivect-test/antigravity";

fn antigravity_config(kind: &str) -> Config {
    Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.antigravity]\n\
         kind = \"{kind}\"\n\
         endpoint = \"https://daily-cloudcode-pa.googleapis.com\"\n\
         credential_ref = \"keychain:rivect-test/antigravity\"\n\
         [models.defaults]\n\
         model = {{ mode = \"auto\" }}\n\
         effort = {{ mode = \"auto\" }}\n\
         fallback = {{ mode = \"auto\" }}\n"
    ))
    .expect("the antigravity config parses")
}

fn antigravity_endpoints(peer: &Peer) -> AntigravityEndpoints {
    AntigravityEndpoints {
        code_assist: peer.base.clone(),
    }
}

fn antigravity_reference() -> SecretRef {
    SecretRef::parse(ANTIGRAVITY_SCOPE).expect("the fixture reference parses")
}

fn assert_nothing_published(store: &support::MapStore, reference: &SecretRef) {
    let error = store
        .resolve(reference)
        .expect_err("nothing is published at the scope");
    assert!(
        matches!(error, ProviderError::CredentialAbsent { .. }),
        "{error}"
    );
}

/// Waits until `predicate` holds under a bounded deadline, so a not-yet-run
/// leg fails loud instead of passing a cancellation test vacuously.
fn wait_until(what: &str, predicate: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if predicate() {
            return;
        }
        std::thread::park_timeout(Duration::from_millis(2));
    }
    panic!("timed out waiting for {what}");
}

/// A guard: the identity, project repeat, onboarding and poll legs at the
/// recorded bound — 30 s total, 1 s polls — the exact source bodies, the
/// mandatory final reload, the real `fetchAvailableModels` map and the
/// canonical project-bound profile.
#[test]
fn antigravity_lro_bounds() {
    assert_eq!(
        ProvisioningBudget::recorded(),
        ProvisioningBudget {
            deadline: Duration::from_secs(30),
            poll_interval: Duration::from_secs(1),
        }
    );
    assert_eq!(
        ProvisioningBudget::default(),
        ProvisioningBudget::recorded()
    );

    let loads = Arc::new(AtomicUsize::new(0));
    let load_count = Arc::clone(&loads);
    let peer = Peer::start(move |seen| {
        if seen.line.contains(":loadCodeAssist") {
            return match load_count.fetch_add(1, Ordering::SeqCst) {
                0 => (
                    200,
                    json!({ "allowedTiers": [{ "id": "free-tier" }] }).to_string(),
                ),
                1 => (
                    200,
                    json!({ "cloudaicompanionProject": "fixture-project" }).to_string(),
                ),
                _ => (
                    200,
                    json!({
                        "paidTier": { "id": "paid-tier" },
                        "cloudaicompanionProject": "fixture-project"
                    })
                    .to_string(),
                ),
            };
        }
        if seen.line.contains(":fetchAvailableModels") {
            return (200, antigravity_models().to_string());
        }
        if seen.line.contains(":onboardUser") {
            return (
                200,
                json!({ "name": "operations/onboard-1", "done": false }).to_string(),
            );
        }
        (
            200,
            json!({
                "name": "operations/onboard-1",
                "done": true,
                "error": null,
                "response": { "cloudaicompanionProject": "ignored-project" }
            })
            .to_string(),
        )
    });
    let endpoints = antigravity_endpoints(&peer);
    let session =
        antigravity_login::begin_login("fixture-token", &endpoints).expect("the login begins");
    assert_eq!(session.budget(), ProvisioningBudget::recorded());
    let store = support::MapStore::new(StoreKind::Keychain);
    let reference = antigravity_reference();

    let profile = antigravity_login::complete_login(
        &antigravity_config("api_key"),
        "antigravity",
        &session,
        &store,
    )
    .expect("the onboarding finishes");

    assert_eq!(profile, "antigravity");
    let requests = peer.requests();
    assert_eq!(
        requests.len(),
        6,
        "identity, onboarding, poll, the final reload, its project repeat and \
         discovery: {}",
        requests.len()
    );
    assert_eq!(requests[0].line, "POST /v1internal:loadCodeAssist HTTP/1.1");
    assert_eq!(requests[1].line, "POST /v1internal:onboardUser HTTP/1.1");
    assert_eq!(
        requests[2].line,
        "GET /v1internal/operations/onboard-1 HTTP/1.1"
    );
    assert_eq!(requests[3].line, "POST /v1internal:loadCodeAssist HTTP/1.1");
    assert_eq!(requests[4].line, "POST /v1internal:loadCodeAssist HTTP/1.1");
    assert_eq!(
        requests[5].line,
        "POST /v1internal:fetchAvailableModels HTTP/1.1"
    );
    for request in &requests {
        assert!(
            request
                .head
                .lines()
                .any(|line| line.eq_ignore_ascii_case("authorization: Bearer fixture-token")),
            "{}",
            request.head
        );
    }
    let identity_body: Value = serde_json::from_str(&requests[0].body).expect("a json body");
    assert_eq!(
        identity_body,
        json!({ "metadata": { "ideType": "ANTIGRAVITY" } })
    );
    let onboard_body: Value = serde_json::from_str(&requests[1].body).expect("a json body");
    assert_eq!(
        onboard_body,
        json!({
            "tierId": "free-tier",
            "metadata": { "ideType": "ANTIGRAVITY" }
        })
    );
    let reload_body: Value = serde_json::from_str(&requests[3].body).expect("a json body");
    assert_eq!(reload_body, identity_body);
    let bound_reload: Value = serde_json::from_str(&requests[4].body).expect("a json body");
    assert_eq!(
        bound_reload,
        json!({
            "cloudaicompanionProject": "fixture-project",
            "metadata": { "ideType": "ANTIGRAVITY" }
        })
    );
    let discovery_body: Value = serde_json::from_str(&requests[5].body).expect("a json body");
    assert_eq!(discovery_body, json!({}));

    let bytes = store.resolve(&reference).expect("the profile is stored");
    assert_eq!(
        String::from_utf8(bytes.clone()).expect("utf-8 bytes"),
        "{\"access_token\":\"fixture-token\",\"project\":\"fixture-project\",\
         \"classes\":{\"claude-sonnet-4-5\":\"anthropic\",\"gemini-2.5-flash\":\"gemini\",\
         \"gpt-oss-120b\":\"gpt-oss\",\"gpt-oss-120b-medium\":\"gpt-oss\"}}"
    );
    let stored = antigravity_login::read_profile(&store, &reference).expect("the profile reads");
    assert_eq!(stored.access_token(), "fixture-token");
    assert_eq!(stored.project(), "fixture-project");
    assert_eq!(
        stored
            .classes()
            .get("claude-sonnet-4-5")
            .map(String::as_str),
        Some("anthropic")
    );
    assert_eq!(
        stored.classes().get("gemini-2.5-flash").map(String::as_str),
        Some("gemini")
    );
    assert_eq!(
        stored.classes().get("gpt-oss-120b").map(String::as_str),
        Some("gpt-oss")
    );
    let rendered = format!("{stored:?}");
    assert!(rendered.contains("<redacted>"), "{rendered}");
    assert!(!rendered.contains("fixture-token"), "{rendered}");
    let session_rendered = format!("{session:?}");
    assert!(
        !session_rendered.contains("fixture-token"),
        "{session_rendered}"
    );
}

/// The recorded discovery answer: the three pinned classes plus the gpt-oss
/// entry's declared alternate id.
fn antigravity_models() -> Value {
    json!({
        "models": {
            "gemini-2.5-flash": {},
            "claude-sonnet-4-5": {},
            "gpt-oss-120b": {},
            "gpt-oss-120b-medium": {}
        }
    })
}

/// A load reply binding the fixture project under a paid tier, so the
/// discovery is not repeated.
fn paid_load_reply() -> Value {
    json!({
        "currentTier": { "id": "free-tier" },
        "paidTier": { "id": "paid-tier" },
        "cloudaicompanionProject": "fixture-project"
    })
}

#[test]
fn antigravity_a_current_tier_still_reloads_the_bound_project() {
    let loads = Arc::new(AtomicUsize::new(0));
    let load_count = Arc::clone(&loads);
    let peer = Peer::start(move |seen| {
        if seen.line.contains(":loadCodeAssist") {
            load_count.fetch_add(1, Ordering::SeqCst);
            // The initial reply names a stale project; only the final reload
            // may publish the binding.
            return (
                200,
                json!({
                    "currentTier": { "id": "free-tier" },
                    "paidTier": { "id": "paid-tier" },
                    "cloudaicompanionProject": if load_count.load(Ordering::SeqCst) == 1 {
                        "stale-project"
                    } else {
                        "fixture-project"
                    }
                })
                .to_string(),
            );
        }
        if seen.line.contains(":fetchAvailableModels") {
            return (200, antigravity_models().to_string());
        }
        (500u16, "{}".to_string())
    });
    let endpoints = antigravity_endpoints(&peer);
    let session =
        antigravity_login::begin_login("fixture-token", &endpoints).expect("the login begins");
    let store = support::MapStore::new(StoreKind::Keychain);
    let reference = antigravity_reference();

    antigravity_login::complete_login(
        &antigravity_config("api_key"),
        "antigravity",
        &session,
        &store,
    )
    .expect("the profile publishes");

    let requests = peer.requests();
    assert_eq!(
        requests.len(),
        3,
        "a current tier never onboards again: {}",
        requests.len()
    );
    assert_eq!(requests[0].line, "POST /v1internal:loadCodeAssist HTTP/1.1");
    assert_eq!(requests[1].line, "POST /v1internal:loadCodeAssist HTTP/1.1");
    assert_eq!(
        requests[2].line,
        "POST /v1internal:fetchAvailableModels HTTP/1.1"
    );
    let stored = antigravity_login::read_profile(&store, &reference).expect("the profile reads");
    assert_eq!(
        stored.project(),
        "fixture-project",
        "only the final reload binds the project"
    );
}

#[test]
fn antigravity_a_project_reload_repeats_the_metadata_with_the_project() {
    let loads = Arc::new(AtomicUsize::new(0));
    let load_count = Arc::clone(&loads);
    let peer = Peer::start(move |seen| {
        if seen.line.contains(":loadCodeAssist") {
            return match load_count.fetch_add(1, Ordering::SeqCst) {
                0 => (
                    200,
                    json!({ "cloudaicompanionProject": "fixture-project" }).to_string(),
                ),
                1 => (
                    200,
                    json!({
                        "currentTier": { "id": "free-tier" },
                        "paidTier": { "id": "paid-tier" },
                        "cloudaicompanionProject": "fixture-project"
                    })
                    .to_string(),
                ),
                _ => (200, paid_load_reply().to_string()),
            };
        }
        if seen.line.contains(":fetchAvailableModels") {
            return (200, antigravity_models().to_string());
        }
        (500u16, "{}".to_string())
    });
    let endpoints = antigravity_endpoints(&peer);
    let session =
        antigravity_login::begin_login("fixture-token", &endpoints).expect("the login begins");
    let store = support::MapStore::new(StoreKind::Keychain);

    antigravity_login::complete_login(
        &antigravity_config("api_key"),
        "antigravity",
        &session,
        &store,
    )
    .expect("the profile publishes");

    let requests = peer.requests();
    assert_eq!(
        requests.len(),
        4,
        "initial load, its project repeat, the final reload and discovery: {}",
        requests.len()
    );
    let repeat: Value = serde_json::from_str(&requests[1].body).expect("a json body");
    assert_eq!(
        repeat,
        json!({
            "cloudaicompanionProject": "fixture-project",
            "metadata": { "ideType": "ANTIGRAVITY" }
        })
    );
    assert!(
        requests
            .iter()
            .all(|request| !request.line.contains(":onboardUser")),
        "a paid tier never onboards"
    );
}

#[test]
fn antigravity_an_ineligible_free_tier_denies_before_onboarding() {
    let peer = Peer::start(|_seen| {
        (
            200u16,
            json!({
                "ineligibleTiers": [
                    { "tierId": "free-tier", "reasonMessage": "hostile-peer-body" }
                ]
            })
            .to_string(),
        )
    });
    let endpoints = antigravity_endpoints(&peer);
    let session =
        antigravity_login::begin_login("fixture-token", &endpoints).expect("the login begins");
    let store = support::MapStore::new(StoreKind::Keychain);
    let reference = antigravity_reference();

    let error = antigravity_login::complete_login(
        &antigravity_config("api_key"),
        "antigravity",
        &session,
        &store,
    )
    .expect_err("the source eligibility check refuses the account");

    assert!(
        matches!(error, AntigravityError::FreeTierIneligible),
        "{error}"
    );
    assert!(!error.to_string().contains("hostile-peer-body"));
    assert_nothing_published(&store, &reference);
    assert_eq!(
        peer.requests().len(),
        1,
        "no onboarding or discovery leg runs"
    );
}

#[test]
fn antigravity_a_rejected_identity_publishes_nothing() {
    let peer = Peer::start(|_seen| (403u16, "hostile-peer-body".to_string()));
    let endpoints = antigravity_endpoints(&peer);
    let session =
        antigravity_login::begin_login("fixture-token", &endpoints).expect("the login begins");
    let store = support::MapStore::new(StoreKind::Keychain);
    let reference = antigravity_reference();

    let error = antigravity_login::complete_login(
        &antigravity_config("api_key"),
        "antigravity",
        &session,
        &store,
    )
    .expect_err("the identity leg refuses the token");

    assert!(
        matches!(
            error,
            AntigravityError::Rejected {
                leg: Leg::Identity,
                status: 403
            }
        ),
        "{error}"
    );
    let rendered = error.to_string();
    assert!(!rendered.contains("fixture-token"), "{rendered}");
    assert!(!rendered.contains("hostile-peer-body"), "{rendered}");
    assert_nothing_published(&store, &reference);
    assert_eq!(peer.requests().len(), 1, "no onboarding leg runs");
}

#[test]
fn antigravity_a_projectless_tier_denies_without_onboarding() {
    let peer = Peer::start(|_seen| {
        (
            200u16,
            json!({
                "currentTier": { "id": "free-tier" },
                "paidTier": { "id": "paid-tier" }
            })
            .to_string(),
        )
    });
    let endpoints = antigravity_endpoints(&peer);
    let session =
        antigravity_login::begin_login("fixture-token", &endpoints).expect("the login begins");
    let store = support::MapStore::new(StoreKind::Keychain);
    let reference = antigravity_reference();

    let error = antigravity_login::complete_login(
        &antigravity_config("api_key"),
        "antigravity",
        &session,
        &store,
    )
    .expect_err("a bound project is required");

    assert!(matches!(error, AntigravityError::ProjectUnbound), "{error}");
    assert_nothing_published(&store, &reference);
    assert_eq!(
        peer.requests().len(),
        2,
        "the initial and final reloads run; onboarding never does"
    );
}

#[test]
fn antigravity_a_finished_operation_with_an_error_denies() {
    let peer = Peer::start(|seen| {
        if seen.line.contains(":loadCodeAssist") {
            return (200u16, "{}".to_string());
        }
        (
            200u16,
            json!({
                "name": "operations/denied",
                "done": true,
                "error": { "code": 9, "message": "hostile-peer-body" }
            })
            .to_string(),
        )
    });
    let endpoints = antigravity_endpoints(&peer);
    let session =
        antigravity_login::begin_login("fixture-token", &endpoints).expect("the login begins");
    let store = support::MapStore::new(StoreKind::Keychain);
    let reference = antigravity_reference();

    let error = antigravity_login::complete_login(
        &antigravity_config("api_key"),
        "antigravity",
        &session,
        &store,
    )
    .expect_err("a done operation with an error denies");

    assert!(
        matches!(error, AntigravityError::ProvisioningDenied),
        "{error}"
    );
    assert!(!error.to_string().contains("hostile-peer-body"));
    assert_nothing_published(&store, &reference);
    assert_eq!(peer.requests().len(), 2, "no poll runs");
}

#[test]
fn antigravity_a_finished_operation_without_a_response_denies() {
    let peer = Peer::start(|seen| {
        if seen.line.contains(":loadCodeAssist") {
            return (200u16, "{}".to_string());
        }
        (
            200u16,
            json!({ "done": true, "error": null, "response": null }).to_string(),
        )
    });
    let endpoints = antigravity_endpoints(&peer);
    let session =
        antigravity_login::begin_login("fixture-token", &endpoints).expect("the login begins");
    let store = support::MapStore::new(StoreKind::Keychain);
    let reference = antigravity_reference();

    let error = antigravity_login::complete_login(
        &antigravity_config("api_key"),
        "antigravity",
        &session,
        &store,
    )
    .expect_err("a null response denies");

    assert!(
        matches!(error, AntigravityError::ProvisioningResponseMissing),
        "{error}"
    );
    assert_nothing_published(&store, &reference);
}

#[test]
fn antigravity_a_pending_operation_without_a_name_denies() {
    let peer = Peer::start(|seen| {
        if seen.line.contains(":loadCodeAssist") {
            return (200u16, "{}".to_string());
        }
        (200u16, json!({ "done": false }).to_string())
    });
    let endpoints = antigravity_endpoints(&peer);
    let session =
        antigravity_login::begin_login("fixture-token", &endpoints).expect("the login begins");
    let store = support::MapStore::new(StoreKind::Keychain);
    let reference = antigravity_reference();

    let error = antigravity_login::complete_login(
        &antigravity_config("api_key"),
        "antigravity",
        &session,
        &store,
    )
    .expect_err("an unnamed operation can never be polled");

    assert!(
        matches!(error, AntigravityError::OperationNameMissing),
        "{error}"
    );
    assert_nothing_published(&store, &reference);
    assert_eq!(peer.requests().len(), 2);
}

#[test]
fn antigravity_an_operation_name_cannot_rewrite_the_poll_path() {
    let peer = Peer::start(|seen| {
        if seen.line.contains(":loadCodeAssist") {
            return (200u16, "{}".to_string());
        }
        (
            200u16,
            json!({ "name": "../accessTokens/steal", "done": false }).to_string(),
        )
    });
    let endpoints = antigravity_endpoints(&peer);
    let session =
        antigravity_login::begin_login("fixture-token", &endpoints).expect("the login begins");
    let store = support::MapStore::new(StoreKind::Keychain);
    let reference = antigravity_reference();

    let error = antigravity_login::complete_login(
        &antigravity_config("api_key"),
        "antigravity",
        &session,
        &store,
    )
    .expect_err("a rewritten operation path is refused");

    assert!(
        matches!(error, AntigravityError::OperationNameMalformed),
        "{error}"
    );
    assert_nothing_published(&store, &reference);
    assert_eq!(peer.requests().len(), 2, "no poll is sent");
}

#[test]
fn antigravity_a_rejected_poll_denies() {
    let peer = Peer::start(|seen| {
        if seen.line.contains(":loadCodeAssist") {
            return (200u16, "{}".to_string());
        }
        if seen.line.contains(":onboardUser") {
            return (
                200u16,
                json!({ "name": "operations/pending", "done": false }).to_string(),
            );
        }
        (500u16, "{}".to_string())
    });
    let endpoints = antigravity_endpoints(&peer);
    let session =
        antigravity_login::begin_login("fixture-token", &endpoints).expect("the login begins");
    let store = support::MapStore::new(StoreKind::Keychain);
    let reference = antigravity_reference();

    let error = antigravity_login::complete_login(
        &antigravity_config("api_key"),
        "antigravity",
        &session,
        &store,
    )
    .expect_err("a non-ok poll denies");

    assert!(
        matches!(
            error,
            AntigravityError::Rejected {
                leg: Leg::Operation,
                status: 500
            }
        ),
        "{error}"
    );
    assert_nothing_published(&store, &reference);
    assert_eq!(peer.requests().len(), 3);
}

/// A guard: the one budget — not a per-request window — ends the wait. The
/// poll interval equals the deadline, so the wait parks until the budget is
/// spent and the typed expiry lands before any poll request; scheduler load
/// can consume part of the budget inside a leg but never turns the denial
/// into an opaque transport error.
#[test]
fn antigravity_the_deadline_stops_the_wait() {
    let peer = Peer::start(|seen| {
        if seen.line.contains(":loadCodeAssist") {
            return (200u16, "{}".to_string());
        }
        (
            200u16,
            json!({ "name": "operations/never", "done": false }).to_string(),
        )
    });
    let endpoints = antigravity_endpoints(&peer);
    let session = antigravity_login::begin_login_with(
        "fixture-token",
        &endpoints,
        ProvisioningBudget {
            deadline: Duration::from_secs(2),
            poll_interval: Duration::from_secs(2),
        },
    )
    .expect("the login begins");
    let store = support::MapStore::new(StoreKind::Keychain);
    let reference = antigravity_reference();

    let error = antigravity_login::complete_login(
        &antigravity_config("api_key"),
        "antigravity",
        &session,
        &store,
    )
    .expect_err("the operation never finishes");

    assert!(
        matches!(error, AntigravityError::ProvisioningTimedOut),
        "{error}"
    );
    assert_nothing_published(&store, &reference);
    let requests = peer.requests();
    assert!(
        requests
            .iter()
            .any(|request| request.line.contains(":onboardUser")),
        "the onboarding leg was reached: {} requests",
        requests.len()
    );
    assert!(
        requests
            .iter()
            .all(|request| !request.line.starts_with("GET ")),
        "the deadline ends the wait before a poll: {} requests",
        requests.len()
    );
}

#[test]
fn antigravity_the_one_deadline_spans_the_final_reload() {
    let loads = Arc::new(AtomicUsize::new(0));
    let load_count = Arc::clone(&loads);
    let peer = Peer::start(move |seen| {
        if seen.line.contains(":loadCodeAssist") {
            if load_count.fetch_add(1, Ordering::SeqCst) == 0 {
                return (200u16, "{}".to_string());
            }
            std::thread::sleep(Duration::from_millis(700));
            return (
                200u16,
                json!({ "cloudaicompanionProject": "fixture-project" }).to_string(),
            );
        }
        (
            200u16,
            json!({ "done": true, "error": null, "response": {} }).to_string(),
        )
    });
    let endpoints = antigravity_endpoints(&peer);
    let session = antigravity_login::begin_login_with(
        "fixture-token",
        &endpoints,
        ProvisioningBudget {
            deadline: Duration::from_millis(400),
            poll_interval: Duration::from_millis(20),
        },
    )
    .expect("the login begins");
    let store = support::MapStore::new(StoreKind::Keychain);
    let reference = antigravity_reference();

    let error = antigravity_login::complete_login(
        &antigravity_config("api_key"),
        "antigravity",
        &session,
        &store,
    )
    .expect_err("the final reload shares the spent budget");

    assert!(
        matches!(error, AntigravityError::ProvisioningTimedOut),
        "{error}"
    );
    assert_nothing_published(&store, &reference);
    let requests = peer.requests();
    assert_eq!(
        requests.len(),
        3,
        "the spent budget denies the final reload, not a fresh window: {}",
        requests.len()
    );
    assert_eq!(requests[2].line, "POST /v1internal:loadCodeAssist HTTP/1.1");
}

#[test]
fn antigravity_the_one_deadline_spans_the_discovery() {
    let peer = Peer::start(|seen| {
        if seen.line.contains(":loadCodeAssist") {
            return (200u16, paid_load_reply().to_string());
        }
        std::thread::sleep(Duration::from_millis(700));
        (200u16, antigravity_models().to_string())
    });
    let endpoints = antigravity_endpoints(&peer);
    let session = antigravity_login::begin_login_with(
        "fixture-token",
        &endpoints,
        ProvisioningBudget {
            deadline: Duration::from_millis(400),
            poll_interval: Duration::from_millis(20),
        },
    )
    .expect("the login begins");
    let store = support::MapStore::new(StoreKind::Keychain);
    let reference = antigravity_reference();

    let error = antigravity_login::complete_login(
        &antigravity_config("api_key"),
        "antigravity",
        &session,
        &store,
    )
    .expect_err("the discovery leg shares the spent budget");

    assert!(
        matches!(error, AntigravityError::ProvisioningTimedOut),
        "{error}"
    );
    assert_nothing_published(&store, &reference);
    let requests = peer.requests();
    assert_eq!(
        requests.len(),
        3,
        "initial load, final reload and the denied discovery: {}",
        requests.len()
    );
    assert_eq!(
        requests[2].line,
        "POST /v1internal:fetchAvailableModels HTTP/1.1"
    );
}

/// A reset per added leg would pass the earlier final-reload case only
/// because its earlier legs cost nothing: here the initial load spends most
/// of the budget, so the final reload's own delay fits a fresh window but
/// not the shared one.
#[test]
fn antigravity_the_spent_budget_denies_a_late_final_reload() {
    let loads = Arc::new(AtomicUsize::new(0));
    let load_count = Arc::clone(&loads);
    let peer = Peer::start(move |seen| {
        if seen.line.contains(":loadCodeAssist") {
            if load_count.fetch_add(1, Ordering::SeqCst) == 0 {
                std::thread::sleep(Duration::from_millis(1_200));
            } else {
                std::thread::sleep(Duration::from_millis(1_000));
            }
            return (200u16, paid_load_reply().to_string());
        }
        (200u16, antigravity_models().to_string())
    });
    let endpoints = antigravity_endpoints(&peer);
    let session = antigravity_login::begin_login_with(
        "fixture-token",
        &endpoints,
        ProvisioningBudget {
            deadline: Duration::from_millis(2_000),
            poll_interval: Duration::from_millis(20),
        },
    )
    .expect("the login begins");
    let store = support::MapStore::new(StoreKind::Keychain);
    let reference = antigravity_reference();

    let error = antigravity_login::complete_login(
        &antigravity_config("api_key"),
        "antigravity",
        &session,
        &store,
    )
    .expect_err("the final reload shares the budget the initial load spent");

    assert!(
        matches!(error, AntigravityError::ProvisioningTimedOut),
        "{error}"
    );
    assert_nothing_published(&store, &reference);
    let requests = peer.requests();
    assert_eq!(
        requests.len(),
        2,
        "the initial load and the denied final reload: {}",
        requests.len()
    );
    assert_eq!(requests[1].line, "POST /v1internal:loadCodeAssist HTTP/1.1");
}

/// The optional project repeat — issued only when no paid tier is present —
/// shares the same budget: its own delay exceeds what remains.
#[test]
fn antigravity_the_one_deadline_spans_the_project_repeat() {
    let loads = Arc::new(AtomicUsize::new(0));
    let load_count = Arc::clone(&loads);
    let peer = Peer::start(move |seen| {
        if seen.line.contains(":loadCodeAssist") {
            if load_count.fetch_add(1, Ordering::SeqCst) == 0 {
                return (
                    200u16,
                    json!({ "cloudaicompanionProject": "fixture-project" }).to_string(),
                );
            }
            std::thread::sleep(Duration::from_millis(700));
            return (200u16, paid_load_reply().to_string());
        }
        (200u16, antigravity_models().to_string())
    });
    let endpoints = antigravity_endpoints(&peer);
    let session = antigravity_login::begin_login_with(
        "fixture-token",
        &endpoints,
        ProvisioningBudget {
            deadline: Duration::from_millis(400),
            poll_interval: Duration::from_millis(20),
        },
    )
    .expect("the login begins");
    let store = support::MapStore::new(StoreKind::Keychain);
    let reference = antigravity_reference();

    let error = antigravity_login::complete_login(
        &antigravity_config("api_key"),
        "antigravity",
        &session,
        &store,
    )
    .expect_err("the project repeat shares the spent budget");

    assert!(
        matches!(error, AntigravityError::ProvisioningTimedOut),
        "{error}"
    );
    assert_nothing_published(&store, &reference);
    let requests = peer.requests();
    assert_eq!(
        requests.len(),
        2,
        "the initial load and the denied project repeat: {}",
        requests.len()
    );
    let repeat_body: Value = serde_json::from_str(&requests[1].body).expect("a json body");
    assert_eq!(
        repeat_body,
        json!({
            "cloudaicompanionProject": "fixture-project",
            "metadata": { "ideType": "ANTIGRAVITY" }
        }),
        "the repeat carries the project"
    );
}

#[test]
fn antigravity_an_unknown_model_class_denies_before_publication() {
    let peer = Peer::start(|seen| {
        if seen.line.contains(":loadCodeAssist") {
            return (200u16, paid_load_reply().to_string());
        }
        (
            200u16,
            json!({ "models": { "gemini-9-experimental": {} } }).to_string(),
        )
    });
    let endpoints = antigravity_endpoints(&peer);
    let session =
        antigravity_login::begin_login("fixture-token", &endpoints).expect("the login begins");
    let store = support::MapStore::new(StoreKind::Keychain);
    let reference = antigravity_reference();

    let error = antigravity_login::complete_login(
        &antigravity_config("api_key"),
        "antigravity",
        &session,
        &store,
    )
    .expect_err("no class is inferred from a model-name prefix");

    assert!(
        matches!(
            error,
            AntigravityError::ModelClassUnknown { ref model } if model == "gemini-9-experimental"
        ),
        "{error}"
    );
    assert!(!error.to_string().contains("gemini-9-experimental"));
    assert_nothing_published(&store, &reference);
    assert_eq!(peer.requests().len(), 3);
}

#[test]
fn antigravity_a_cancelled_login_publishes_nothing() {
    let peer = Peer::start(|_seen| (200u16, "unreachable".to_string()));
    let endpoints = antigravity_endpoints(&peer);
    let store = support::MapStore::new(StoreKind::Keychain);
    let reference = antigravity_reference();
    let config = antigravity_config("api_key");

    let cancelled =
        antigravity_login::begin_login("fixture-token", &endpoints).expect("the login begins");
    cancelled.cancel();
    let error = antigravity_login::complete_login(&config, "antigravity", &cancelled, &store)
        .expect_err("a cancelled session publishes nothing");
    assert!(matches!(error, AntigravityError::Cancelled), "{error}");
    assert_nothing_published(&store, &reference);
    assert_eq!(
        peer.requests().len(),
        0,
        "no leg runs for a cancelled login"
    );

    let slow = Peer::start(|seen| {
        if seen.line.contains(":loadCodeAssist") {
            return (200u16, "{}".to_string());
        }
        (
            200u16,
            json!({ "name": "operations/pending", "done": false }).to_string(),
        )
    });
    let slow_endpoints = antigravity_endpoints(&slow);
    let session = antigravity_login::begin_login_with(
        "fixture-token",
        &slow_endpoints,
        ProvisioningBudget {
            deadline: Duration::from_secs(5),
            poll_interval: Duration::from_millis(20),
        },
    )
    .expect("the login begins");

    let outcome = std::thread::scope(|scope| {
        let login = scope
            .spawn(|| antigravity_login::complete_login(&config, "antigravity", &session, &store));
        // The peer must have answered the identity and onboarding legs and
        // seen a poll before the cancel, so a thread that never started
        // cannot pass this case vacuously.
        wait_until("the peer to answer the onboarding legs", || {
            slow.requests().len() >= 2
        });
        wait_until("the first operation poll", || {
            slow.requests()
                .iter()
                .any(|request| request.line.starts_with("GET "))
        });
        session.cancel();
        login.join().expect("the login thread joins")
    });

    let error = outcome.expect_err("the mid-wait cancellation publishes nothing");
    assert!(matches!(error, AntigravityError::Cancelled), "{error}");
    assert_nothing_published(&store, &reference);
    let requests = slow.requests();
    assert!(
        requests.len() >= 3
            && requests
                .iter()
                .any(|request| request.line.starts_with("GET ")),
        "the cancel lands after the onboarding leg and a poll: {}",
        requests.len()
    );
}

/// A cancellation observed after the last leg and before the write denies at
/// the pre-write guard: the peer answers discovery only once the test has
/// cancelled, so the guard cannot miss the flag.
#[test]
fn antigravity_a_cancel_before_the_write_publishes_nothing() {
    let gate = Arc::new(AtomicBool::new(false));
    let peer_gate = Arc::clone(&gate);
    let peer = Peer::start(move |seen| {
        if seen.line.contains(":loadCodeAssist") {
            return (200u16, paid_load_reply().to_string());
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        while !peer_gate.load(Ordering::SeqCst) && Instant::now() < deadline {
            std::thread::park_timeout(Duration::from_millis(2));
        }
        (200u16, antigravity_models().to_string())
    });
    let endpoints = antigravity_endpoints(&peer);
    let session =
        antigravity_login::begin_login("fixture-token", &endpoints).expect("the login begins");
    let store = support::MapStore::new(StoreKind::Keychain);
    let reference = antigravity_reference();
    let config = antigravity_config("api_key");

    let outcome = std::thread::scope(|scope| {
        let login = scope
            .spawn(|| antigravity_login::complete_login(&config, "antigravity", &session, &store));
        wait_until("the discovery request", || {
            peer.requests()
                .iter()
                .any(|request| request.line.contains(":fetchAvailableModels"))
        });
        session.cancel();
        gate.store(true, Ordering::SeqCst);
        login.join().expect("the login thread joins")
    });

    let error = outcome.expect_err("a cancellation before the write publishes nothing");
    assert!(matches!(error, AntigravityError::Cancelled), "{error}");
    assert_nothing_published(&store, &reference);
}

#[test]
fn antigravity_a_late_callback_publishes_nothing() {
    let peer = Peer::start(|seen| {
        if seen.line.contains(":loadCodeAssist") {
            return (200u16, paid_load_reply().to_string());
        }
        if seen.line.contains(":fetchAvailableModels") {
            return (200u16, antigravity_models().to_string());
        }
        (500u16, "{}".to_string())
    });
    let endpoints = antigravity_endpoints(&peer);
    let store = support::MapStore::new(StoreKind::Keychain);
    let reference = antigravity_reference();
    let config = antigravity_config("api_key");

    let first =
        antigravity_login::begin_login("fixture-token", &endpoints).expect("the login begins");
    antigravity_login::complete_login(&config, "antigravity", &first, &store)
        .expect("the first profile publishes");
    let published = store.resolve(&reference).expect("the profile is stored");

    let late =
        antigravity_login::begin_login("fixture-token", &endpoints).expect("the login begins");
    late.cancel();
    let error = antigravity_login::complete_login(&config, "antigravity", &late, &store)
        .expect_err("a late completion publishes nothing");
    assert!(matches!(error, AntigravityError::Cancelled), "{error}");
    assert_eq!(
        store.resolve(&reference).expect("the profile is untouched"),
        published,
        "a cancelled completion leaves the prior bytes byte-identical"
    );

    let second =
        antigravity_login::begin_login("fixture-token", &endpoints).expect("the login begins");
    let error = antigravity_login::complete_login(&config, "antigravity", &second, &store)
        .expect_err("enrollment is create-only");
    assert!(
        matches!(
            error,
            AntigravityError::Provider(ProviderError::CredentialOccupied { .. })
        ),
        "{error}"
    );
    assert_eq!(
        store.resolve(&reference).expect("the profile is untouched"),
        published,
        "a refused write leaves the prior bytes byte-identical"
    );
}

/// A store whose enrollment always refuses while reads still succeed.
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

#[test]
fn antigravity_a_refused_write_publishes_nothing() {
    let peer = Peer::start(|seen| {
        if seen.line.contains(":loadCodeAssist") {
            return (200u16, paid_load_reply().to_string());
        }
        (200u16, antigravity_models().to_string())
    });
    let endpoints = antigravity_endpoints(&peer);
    let session =
        antigravity_login::begin_login("fixture-token", &endpoints).expect("the login begins");
    let store = RefusingLoginStore {
        inner: support::MapStore::new(StoreKind::Keychain),
    };
    let reference = antigravity_reference();

    let error = antigravity_login::complete_login(
        &antigravity_config("api_key"),
        "antigravity",
        &session,
        &store,
    )
    .expect_err("the store refuses the enrollment");

    assert!(
        matches!(
            error,
            AntigravityError::Provider(ProviderError::StoreUnavailable { .. })
        ),
        "{error}"
    );
    assert_nothing_published(&store.inner, &reference);
}

/// A stored profile whose binding a refresh must keep.
const STORED_ANTIGRAVITY: &str = "{\"access_token\":\"stale-token\",\"project\":\"fixture-project\",\"classes\":{\"gemini-2.5-flash\":\"gemini\",\"gpt-oss-120b\":\"gpt-oss\"}}";

#[test]
fn antigravity_refresh_preserves_the_project_and_classes() {
    let store = support::MapStore::seeded(
        StoreKind::Keychain,
        &[(ANTIGRAVITY_SCOPE, STORED_ANTIGRAVITY)],
    );
    let reference = antigravity_reference();

    let profile = antigravity_login::refresh_profile(&store, &reference, "fresh-token")
        .expect("the explicit refresh writes");

    assert_eq!(profile, "antigravity");
    assert_eq!(
        String::from_utf8(store.resolve(&reference).expect("the profile is stored"))
            .expect("utf-8 bytes"),
        "{\"access_token\":\"fresh-token\",\"project\":\"fixture-project\",\
         \"classes\":{\"gemini-2.5-flash\":\"gemini\",\"gpt-oss-120b\":\"gpt-oss\"}}",
        "refresh changes the token only, with no provisioning or discovery"
    );
    let stored = antigravity_login::read_profile(&store, &reference).expect("the profile reads");
    assert_eq!(stored.access_token(), "fresh-token");
    assert_eq!(stored.project(), "fixture-project");
    assert_eq!(
        stored.classes().get("gpt-oss-120b").map(String::as_str),
        Some("gpt-oss")
    );

    let error = antigravity_login::refresh_profile(&store, &reference, "  ")
        .expect_err("a blank token never enters the profile");
    assert!(
        matches!(
            error,
            AntigravityError::MissingField {
                field: "access_token"
            }
        ),
        "{error}"
    );
    assert_eq!(
        String::from_utf8(store.resolve(&reference).expect("the profile is stored"))
            .expect("utf-8 bytes"),
        "{\"access_token\":\"fresh-token\",\"project\":\"fixture-project\",\
         \"classes\":{\"gemini-2.5-flash\":\"gemini\",\"gpt-oss-120b\":\"gpt-oss\"}}",
        "a refused refresh leaves the prior bytes byte-identical"
    );
}

/// A store whose refresh always refuses while reads still succeed.
struct RefusingAntigravityRefreshStore {
    inner: support::MapStore,
}

impl CredentialStore for RefusingAntigravityRefreshStore {
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
fn antigravity_refresh_denies_foreign_stored_material() {
    let store = support::MapStore::seeded(
        StoreKind::Keychain,
        &[(ANTIGRAVITY_SCOPE, "not-an-antigravity-profile")],
    );
    let reference = antigravity_reference();

    let error = antigravity_login::refresh_profile(&store, &reference, "fresh-token")
        .expect_err("foreign stored material is a typed denial");

    assert!(
        matches!(error, AntigravityError::StoredCredentialMalformed { .. }),
        "{error}"
    );
    assert_eq!(
        String::from_utf8(store.resolve(&reference).expect("the profile is stored"))
            .expect("utf-8 bytes"),
        "not-an-antigravity-profile",
        "a denied refresh leaves the prior bytes byte-identical"
    );
}

#[test]
fn antigravity_refresh_of_a_refused_store_leaves_the_bytes_identical() {
    let store = RefusingAntigravityRefreshStore {
        inner: support::MapStore::seeded(
            StoreKind::Keychain,
            &[(ANTIGRAVITY_SCOPE, STORED_ANTIGRAVITY)],
        ),
    };
    let reference = antigravity_reference();

    let error = antigravity_login::refresh_profile(&store, &reference, "fresh-token")
        .expect_err("the store refuses the refresh");

    assert!(
        matches!(
            error,
            AntigravityError::Provider(ProviderError::StoreUnavailable { .. })
        ),
        "{error}"
    );
    assert_eq!(
        String::from_utf8(store.resolve(&reference).expect("the profile is stored"))
            .expect("utf-8 bytes"),
        STORED_ANTIGRAVITY,
        "a refused refresh leaves the prior bytes byte-identical"
    );
}

#[test]
fn antigravity_an_unrecorded_origin_denies_before_a_request() {
    assert_eq!(
        CODE_ASSIST_ORIGIN,
        "https://daily-cloudcode-pa.googleapis.com"
    );
    assert_eq!(
        CODE_ASSIST_SANDBOX_ORIGIN,
        "https://daily-cloudcode-pa.sandbox.googleapis.com"
    );
    let error = antigravity_login::begin_login(
        "fixture-token",
        &AntigravityEndpoints {
            code_assist: "https://evil.example".to_string(),
        },
    )
    .expect_err("a foreign origin is refused");
    assert!(
        matches!(
            error,
            AntigravityError::EndpointNotAdmitted { ref origin }
                if origin == "https://evil.example"
        ),
        "{error}"
    );
    antigravity_login::begin_login(
        "fixture-token",
        &AntigravityEndpoints {
            code_assist: CODE_ASSIST_SANDBOX_ORIGIN.to_string(),
        },
    )
    .expect("the recorded sandbox fallback is admitted");
    assert_eq!(
        AntigravityEndpoints::recorded().code_assist,
        CODE_ASSIST_ORIGIN
    );
}

#[test]
fn antigravity_a_blank_token_denies() {
    let error = antigravity_login::begin_login("  ", &AntigravityEndpoints::recorded())
        .expect_err("the login needs a token");
    assert!(
        matches!(
            error,
            AntigravityError::MissingField {
                field: "access_token"
            }
        ),
        "{error}"
    );
}

#[test]
fn antigravity_a_non_api_key_binding_denies() {
    let peer = Peer::start(|_seen| (200u16, "{}".to_string()));
    let endpoints = antigravity_endpoints(&peer);
    let session =
        antigravity_login::begin_login("fixture-token", &endpoints).expect("the login begins");
    let store = support::MapStore::new(StoreKind::Keychain);

    let error = antigravity_login::complete_login(
        &antigravity_config("subscription"),
        "antigravity",
        &session,
        &store,
    )
    .expect_err("the login path writes only an api key row");

    assert!(
        matches!(
            error,
            AntigravityError::NotApiKey {
                kind: ConnKind::Subscription,
                ..
            }
        ),
        "{error}"
    );
    assert_eq!(peer.requests().len(), 0);
}

#[test]
fn antigravity_read_profile_rejects_foreign_material() {
    let reference = antigravity_reference();
    let store = support::MapStore::seeded(
        StoreKind::Keychain,
        &[(
            ANTIGRAVITY_SCOPE,
            r#"{"access_token":"fixture-token","project":"fixture-project","classes":{},"extra":1}"#,
        )],
    );

    let error = antigravity_login::read_profile(&store, &reference)
        .expect_err("an unknown field is refused");

    assert!(
        matches!(error, AntigravityError::StoredCredentialMalformed { .. }),
        "{error}"
    );
}

/// The Gemini CLI Code Assist connection the producer binds.
const CODE_ASSIST_SCOPE: &str = "keychain:rivect-test/code-assist";

fn code_assist_config(kind: &str) -> Config {
    Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.code-assist]\n\
         kind = \"{kind}\"\n\
         endpoint = \"https://cloudcode-pa.googleapis.com\"\n\
         credential_ref = \"keychain:rivect-test/code-assist\"\n\
         [models.defaults]\n\
         model = {{ mode = \"auto\" }}\n\
         effort = {{ mode = \"auto\" }}\n\
         fallback = {{ mode = \"auto\" }}\n"
    ))
    .expect("the code assist config parses")
}

fn code_assist_endpoints(peer: &Peer) -> CodeAssistEndpoints {
    CodeAssistEndpoints {
        code_assist: peer.base.clone(),
    }
}

fn code_assist_reference() -> SecretRef {
    SecretRef::parse(CODE_ASSIST_SCOPE).expect("the fixture reference parses")
}

fn code_assist_session(
    peer: &Peer,
    budget: OnboardingBudget,
    project: Option<&str>,
) -> gemini_cli_login::LoginSession {
    gemini_cli_login::begin_login_with(
        "fixture-token",
        &code_assist_endpoints(peer),
        budget,
        &ProjectSource {
            project: project.map(str::to_string),
        },
    )
    .expect("the code assist login begins")
}

/// The recorded discovery metadata every Code Assist leg carries.
fn gemini_metadata() -> Value {
    json!({
        "ideType": "IDE_UNSPECIFIED",
        "platform": "PLATFORM_UNSPECIFIED",
        "pluginType": "GEMINI",
    })
}

/// A guard: the recorded onboarding bound — 24 polls at 5 s — the
/// free-tier onboarding sequence, the poll cadence and the canonical
/// tier/project profile.
#[test]
fn code_assist_lro_bounds() {
    assert_eq!(
        OnboardingBudget::recorded(),
        OnboardingBudget {
            max_attempts: 24,
            poll_interval: Duration::from_secs(5),
        }
    );
    assert_eq!(
        gemini_cli_login::begin_login("fixture-token", &CodeAssistEndpoints::recorded())
            .expect("the public login begins")
            .budget(),
        OnboardingBudget::recorded()
    );

    let polls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&polls);
    let peer = Peer::start(move |seen| {
        if seen.line.contains(":loadCodeAssist") {
            return (
                200,
                json!({ "allowedTiers": [{ "id": "free-tier", "isDefault": true }] }).to_string(),
            );
        }
        if seen.line.contains(":onboardUser") {
            return (
                200,
                json!({ "name": "operations/onboard-1", "done": false }).to_string(),
            );
        }
        if counter.fetch_add(1, Ordering::SeqCst) == 0 {
            return (
                200,
                json!({ "name": "operations/onboard-1", "done": false }).to_string(),
            );
        }
        (
            200,
            json!({
                "name": "operations/onboard-1",
                "done": true,
                "response": { "cloudaicompanionProject": { "id": "fixture-project" } }
            })
            .to_string(),
        )
    });
    let session = code_assist_session(&peer, OnboardingBudget::recorded(), None);
    assert_eq!(session.budget(), OnboardingBudget::recorded());
    let store = support::MapStore::new(StoreKind::Keychain);
    let reference = code_assist_reference();

    let profile = gemini_cli_login::complete_login(
        &code_assist_config("api_key"),
        "code-assist",
        &session,
        &store,
    )
    .expect("the onboarding finishes");

    assert_eq!(profile, "code-assist");
    let requests = peer.requests();
    assert_eq!(
        requests.len(),
        4,
        "identity, onboarding and two polls: {}",
        requests.len()
    );
    assert_eq!(requests[0].line, "POST /v1internal:loadCodeAssist HTTP/1.1");
    assert_eq!(requests[1].line, "POST /v1internal:onboardUser HTTP/1.1");
    assert_eq!(
        requests[2].line,
        "GET /v1internal/operations/onboard-1 HTTP/1.1"
    );
    assert_eq!(
        requests[3].line,
        "GET /v1internal/operations/onboard-1 HTTP/1.1"
    );
    for request in &requests {
        assert!(
            request
                .head
                .lines()
                .any(|line| line.eq_ignore_ascii_case("authorization: Bearer fixture-token")),
            "{}",
            request.head
        );
    }
    let load_body: Value = serde_json::from_str(&requests[0].body).expect("a json body");
    assert_eq!(load_body, json!({ "metadata": gemini_metadata() }));
    let onboard_body: Value = serde_json::from_str(&requests[1].body).expect("a json body");
    assert_eq!(
        onboard_body,
        json!({ "tierId": "free-tier", "metadata": gemini_metadata() })
    );

    let bytes = store.resolve(&reference).expect("the profile is stored");
    assert_eq!(
        String::from_utf8(bytes.clone()).expect("utf-8 bytes"),
        "{\"access_token\":\"fixture-token\",\"project\":\"fixture-project\",\"tier\":\"free-tier\"}"
    );
    let stored = gemini_cli_login::read_profile(&store, &reference).expect("the profile reads");
    assert_eq!(stored.access_token(), "fixture-token");
    assert_eq!(stored.project(), "fixture-project");
    assert_eq!(stored.tier(), "free-tier");
    let rendered = format!("{stored:?}");
    assert!(rendered.contains("<redacted>"), "{rendered}");
    assert!(!rendered.contains("fixture-token"), "{rendered}");
    let session_rendered = format!("{session:?}");
    assert!(
        !session_rendered.contains("fixture-token"),
        "{session_rendered}"
    );
}

#[test]
fn code_assist_a_current_tier_binds_the_project_without_onboarding() {
    let peer = Peer::start(|seen| {
        if seen.line.contains(":loadCodeAssist") {
            return (
                200,
                json!({
                    "currentTier": { "id": "standard-tier" },
                    "cloudaicompanionProject": "fixture-project"
                })
                .to_string(),
            );
        }
        (500u16, "{}".to_string())
    });
    let session = code_assist_session(&peer, OnboardingBudget::recorded(), None);
    let store = support::MapStore::new(StoreKind::Keychain);
    let reference = code_assist_reference();

    gemini_cli_login::complete_login(
        &code_assist_config("api_key"),
        "code-assist",
        &session,
        &store,
    )
    .expect("the profile publishes");

    assert_eq!(
        peer.requests().len(),
        1,
        "a current tier never onboards again"
    );
    let stored = gemini_cli_login::read_profile(&store, &reference).expect("the profile reads");
    assert_eq!(stored.project(), "fixture-project");
    assert_eq!(stored.tier(), "standard-tier");
}

#[test]
fn code_assist_a_workspace_tier_requires_an_explicit_project() {
    let peer = Peer::start(|_seen| {
        (
            200u16,
            json!({ "currentTier": { "id": "standard-tier" } }).to_string(),
        )
    });
    let store = support::MapStore::new(StoreKind::Keychain);
    let reference = code_assist_reference();
    let config = code_assist_config("api_key");

    let session = code_assist_session(&peer, OnboardingBudget::recorded(), None);
    let error = gemini_cli_login::complete_login(&config, "code-assist", &session, &store)
        .expect_err("a Workspace tier needs an explicit project");
    assert!(matches!(error, CodeAssistError::ProjectRequired), "{error}");
    assert_nothing_published(&store, &reference);
    assert_eq!(peer.requests().len(), 1);

    let explicit = code_assist_session(&peer, OnboardingBudget::recorded(), Some("env-project"));
    gemini_cli_login::complete_login(&config, "code-assist", &explicit, &store)
        .expect("the explicit project binds the profile");
    let stored = gemini_cli_login::read_profile(&store, &reference).expect("the profile reads");
    assert_eq!(stored.project(), "env-project");
    assert_eq!(stored.tier(), "standard-tier");
    assert_eq!(peer.requests().len(), 2, "no onboarding leg runs");
}

#[test]
fn code_assist_a_non_free_default_tier_requires_an_explicit_project() {
    let peer = Peer::start(|seen| {
        if seen.line.contains(":loadCodeAssist") {
            return (
                200,
                json!({ "allowedTiers": [{ "id": "standard-tier", "isDefault": true }] })
                    .to_string(),
            );
        }
        (
            200u16,
            json!({
                "done": true,
                "response": { "cloudaicompanionProject": { "id": "fixture-project" } }
            })
            .to_string(),
        )
    });
    let store = support::MapStore::new(StoreKind::Keychain);
    let reference = code_assist_reference();
    let config = code_assist_config("api_key");

    let session = code_assist_session(&peer, OnboardingBudget::recorded(), None);
    let error = gemini_cli_login::complete_login(&config, "code-assist", &session, &store)
        .expect_err("a non-free tier needs an explicit project");
    assert!(matches!(error, CodeAssistError::ProjectRequired), "{error}");
    assert_nothing_published(&store, &reference);
    assert_eq!(peer.requests().len(), 1, "no onboarding leg runs");

    let explicit = code_assist_session(&peer, OnboardingBudget::recorded(), Some("env-project"));
    gemini_cli_login::complete_login(&config, "code-assist", &explicit, &store)
        .expect("the non-free tier onboards the explicit project");
    let requests = peer.requests();
    assert_eq!(requests.len(), 3);
    let onboard_body: Value = serde_json::from_str(&requests[2].body).expect("a json body");
    assert_eq!(
        onboard_body,
        json!({
            "tierId": "standard-tier",
            "cloudaicompanionProject": "env-project",
            "metadata": {
                "ideType": "IDE_UNSPECIFIED",
                "platform": "PLATFORM_UNSPECIFIED",
                "pluginType": "GEMINI",
                "duetProject": "env-project",
            }
        })
    );
    let stored = gemini_cli_login::read_profile(&store, &reference).expect("the profile reads");
    assert_eq!(stored.project(), "fixture-project");
    assert_eq!(stored.tier(), "standard-tier");
}

#[test]
fn code_assist_a_current_tier_without_an_id_binds_the_project() {
    let unbound = Peer::start(|_seen| (200u16, json!({ "currentTier": {} }).to_string()));
    let store = support::MapStore::new(StoreKind::Keychain);
    let reference = code_assist_reference();
    let config = code_assist_config("api_key");

    let error = gemini_cli_login::complete_login(
        &config,
        "code-assist",
        &code_assist_session(&unbound, OnboardingBudget::recorded(), None),
        &store,
    )
    .expect_err("a current tier without an id still needs a project");
    assert!(matches!(error, CodeAssistError::ProjectRequired), "{error}");
    assert_nothing_published(&store, &reference);

    let bound = Peer::start(|_seen| {
        (
            200u16,
            json!({
                "currentTier": {},
                "cloudaicompanionProject": "fixture-project"
            })
            .to_string(),
        )
    });
    gemini_cli_login::complete_login(
        &config,
        "code-assist",
        &code_assist_session(&bound, OnboardingBudget::recorded(), None),
        &store,
    )
    .expect("a bound current tier without an id still publishes");
    assert_eq!(bound.requests().len(), 1, "a current tier never onboards");
    let stored = gemini_cli_login::read_profile(&store, &reference).expect("the profile reads");
    assert_eq!(stored.project(), "fixture-project");
    assert_eq!(stored.tier(), "", "an absent upstream id is not a tier");
    assert_eq!(
        String::from_utf8(store.resolve(&reference).expect("the profile is stored"))
            .expect("utf-8 bytes"),
        "{\"access_token\":\"fixture-token\",\"project\":\"fixture-project\",\"tier\":\"\"}"
    );

    let supplied = Peer::start(|_seen| (200u16, json!({ "currentTier": {} }).to_string()));
    let explicit_store = support::MapStore::new(StoreKind::Keychain);
    gemini_cli_login::complete_login(
        &config,
        "code-assist",
        &code_assist_session(&supplied, OnboardingBudget::recorded(), Some("env-project")),
        &explicit_store,
    )
    .expect("the supplied project binds a current tier without an id");
    let stored =
        gemini_cli_login::read_profile(&explicit_store, &reference).expect("the profile reads");
    assert_eq!(stored.project(), "env-project");
    assert_eq!(stored.tier(), "");
}

#[test]
fn code_assist_a_default_tier_without_an_id_selects_the_free_tier() {
    let peer = Peer::start(|seen| {
        if seen.line.contains(":loadCodeAssist") {
            return (
                200u16,
                json!({ "allowedTiers": [{ "isDefault": true }] }).to_string(),
            );
        }
        (
            200u16,
            json!({
                "done": true,
                "response": { "cloudaicompanionProject": { "id": "fixture-project" } }
            })
            .to_string(),
        )
    });
    let store = support::MapStore::new(StoreKind::Keychain);
    let reference = code_assist_reference();

    gemini_cli_login::complete_login(
        &code_assist_config("api_key"),
        "code-assist",
        &code_assist_session(&peer, OnboardingBudget::recorded(), None),
        &store,
    )
    .expect("a default entry without an id onboards free-tier");

    let requests = peer.requests();
    assert_eq!(requests.len(), 2, "identity then onboarding");
    let onboard_body: Value = serde_json::from_str(&requests[1].body).expect("a json body");
    assert_eq!(
        onboard_body,
        json!({ "tierId": "free-tier", "metadata": gemini_metadata() })
    );
    let stored = gemini_cli_login::read_profile(&store, &reference).expect("the profile reads");
    assert_eq!(stored.project(), "fixture-project");
    assert_eq!(stored.tier(), "free-tier");
}

#[test]
fn code_assist_an_absent_default_onboards_the_legacy_tier() {
    let peer = Peer::start(|seen| {
        if seen.line.contains(":loadCodeAssist") {
            return (200u16, json!({ "allowedTiers": [] }).to_string());
        }
        (
            200u16,
            json!({
                "done": true,
                "response": { "cloudaicompanionProject": { "id": "fixture-project" } }
            })
            .to_string(),
        )
    });
    let store = support::MapStore::new(StoreKind::Keychain);
    let reference = code_assist_reference();
    let config = code_assist_config("api_key");

    let error = gemini_cli_login::complete_login(
        &config,
        "code-assist",
        &code_assist_session(&peer, OnboardingBudget::recorded(), None),
        &store,
    )
    .expect_err("the legacy tier needs an explicit project");
    assert!(matches!(error, CodeAssistError::ProjectRequired), "{error}");
    assert_nothing_published(&store, &reference);
    assert_eq!(peer.requests().len(), 1, "no onboarding leg runs");

    gemini_cli_login::complete_login(
        &config,
        "code-assist",
        &code_assist_session(&peer, OnboardingBudget::recorded(), Some("env-project")),
        &store,
    )
    .expect("the legacy tier onboards the explicit project");
    let requests = peer.requests();
    let onboard_body: Value = serde_json::from_str(&requests[2].body).expect("a json body");
    assert_eq!(onboard_body["tierId"], json!("legacy-tier"));
    assert_eq!(
        onboard_body["cloudaicompanionProject"],
        json!("env-project")
    );
    let stored = gemini_cli_login::read_profile(&store, &reference).expect("the profile reads");
    assert_eq!(stored.project(), "fixture-project");
    assert_eq!(stored.tier(), "legacy-tier");
}

#[test]
fn code_assist_an_unknown_default_tier_is_not_an_entitlement() {
    let peer = Peer::start(|seen| {
        if seen.line.contains(":loadCodeAssist") {
            return (
                200u16,
                json!({ "allowedTiers": [{ "id": "custom-tier", "isDefault": true }] }).to_string(),
            );
        }
        (
            200u16,
            json!({
                "done": true,
                "response": { "cloudaicompanionProject": { "id": "fixture-project" } }
            })
            .to_string(),
        )
    });
    let store = support::MapStore::new(StoreKind::Keychain);
    let reference = code_assist_reference();
    let config = code_assist_config("api_key");

    let error = gemini_cli_login::complete_login(
        &config,
        "code-assist",
        &code_assist_session(&peer, OnboardingBudget::recorded(), None),
        &store,
    )
    .expect_err("an unknown tier grants no project-free path");
    assert!(matches!(error, CodeAssistError::ProjectRequired), "{error}");
    assert_nothing_published(&store, &reference);

    gemini_cli_login::complete_login(
        &config,
        "code-assist",
        &code_assist_session(&peer, OnboardingBudget::recorded(), Some("env-project")),
        &store,
    )
    .expect("the known string value onboards verbatim");
    let requests = peer.requests();
    let onboard_body: Value = serde_json::from_str(&requests[2].body).expect("a json body");
    assert_eq!(
        onboard_body,
        json!({
            "tierId": "custom-tier",
            "cloudaicompanionProject": "env-project",
            "metadata": {
                "ideType": "IDE_UNSPECIFIED",
                "platform": "PLATFORM_UNSPECIFIED",
                "pluginType": "GEMINI",
                "duetProject": "env-project",
            }
        })
    );
    let stored = gemini_cli_login::read_profile(&store, &reference).expect("the profile reads");
    assert_eq!(stored.tier(), "custom-tier");
}

/// A VPC-SC load answer is a typed denial with and without an explicit
/// project: no tier is synthesized and nothing onboards or publishes.
#[test]
fn code_assist_vpc_sc_denies_with_and_without_an_explicit_project() {
    let peer = Peer::start(|_seen| {
        (
            403u16,
            json!({ "error": { "details": [{ "reason": "SECURITY_POLICY_VIOLATED" }] } })
                .to_string(),
        )
    });
    let store = support::MapStore::new(StoreKind::Keychain);
    let reference = code_assist_reference();
    let config = code_assist_config("api_key");

    let error = gemini_cli_login::complete_login(
        &config,
        "code-assist",
        &code_assist_session(&peer, OnboardingBudget::recorded(), None),
        &store,
    )
    .expect_err("a VPC-SC refusal denies without an explicit project");
    assert!(matches!(error, CodeAssistError::VpcScDenied), "{error}");
    assert_nothing_published(&store, &reference);

    let error = gemini_cli_login::complete_login(
        &config,
        "code-assist",
        &code_assist_session(&peer, OnboardingBudget::recorded(), Some("vpc-project")),
        &store,
    )
    .expect_err("a VPC-SC refusal denies with an explicit project");
    assert!(matches!(error, CodeAssistError::VpcScDenied), "{error}");
    assert_nothing_published(&store, &reference);

    let requests = peer.requests();
    assert_eq!(requests.len(), 2, "one load per attempt");
    assert!(
        requests
            .iter()
            .all(|request| !request.line.contains(":onboardUser")),
        "no onboarding leg runs"
    );
}

#[test]
fn code_assist_a_rejected_identity_publishes_nothing() {
    let peer = Peer::start(|_seen| {
        (
            403u16,
            json!({
                "error": {
                    "message": "hostile-peer-body",
                    "details": [{ "reason": "OTHER" }]
                }
            })
            .to_string(),
        )
    });
    let session = code_assist_session(&peer, OnboardingBudget::recorded(), None);
    let store = support::MapStore::new(StoreKind::Keychain);
    let reference = code_assist_reference();

    let error = gemini_cli_login::complete_login(
        &code_assist_config("api_key"),
        "code-assist",
        &session,
        &store,
    )
    .expect_err("a non-VPC refusal is a typed denial");

    assert!(
        matches!(
            error,
            CodeAssistError::Rejected {
                leg: gemini_cli_login::Leg::Identity,
                status: 403
            }
        ),
        "{error}"
    );
    let rendered = error.to_string();
    assert!(!rendered.contains("fixture-token"), "{rendered}");
    assert!(!rendered.contains("hostile-peer-body"), "{rendered}");
    assert_nothing_published(&store, &reference);
    assert_eq!(peer.requests().len(), 1);
}

#[test]
fn code_assist_a_rejected_poll_denies() {
    let peer = Peer::start(|seen| {
        if seen.line.contains(":loadCodeAssist") {
            return (
                200u16,
                json!({ "allowedTiers": [{ "id": "free-tier", "isDefault": true }] }).to_string(),
            );
        }
        if seen.line.contains(":onboardUser") {
            return (
                200u16,
                json!({ "name": "operations/pending", "done": false }).to_string(),
            );
        }
        (500u16, "{}".to_string())
    });
    let session = code_assist_session(&peer, OnboardingBudget::recorded(), None);
    let store = support::MapStore::new(StoreKind::Keychain);
    let reference = code_assist_reference();

    let error = gemini_cli_login::complete_login(
        &code_assist_config("api_key"),
        "code-assist",
        &session,
        &store,
    )
    .expect_err("a non-ok poll denies");

    assert!(
        matches!(
            error,
            CodeAssistError::Rejected {
                leg: gemini_cli_login::Leg::Operation,
                status: 500
            }
        ),
        "{error}"
    );
    assert_nothing_published(&store, &reference);
    assert_eq!(peer.requests().len(), 3);
}

#[test]
fn code_assist_the_poll_cap_denies() {
    let peer = Peer::start(|seen| {
        if seen.line.contains(":loadCodeAssist") {
            return (
                200u16,
                json!({ "allowedTiers": [{ "id": "free-tier", "isDefault": true }] }).to_string(),
            );
        }
        (
            200u16,
            json!({ "name": "operations/never", "done": false }).to_string(),
        )
    });
    let session = code_assist_session(
        &peer,
        OnboardingBudget {
            max_attempts: 3,
            poll_interval: Duration::from_millis(5),
        },
        None,
    );
    let store = support::MapStore::new(StoreKind::Keychain);
    let reference = code_assist_reference();

    let error = gemini_cli_login::complete_login(
        &code_assist_config("api_key"),
        "code-assist",
        &session,
        &store,
    )
    .expect_err("the operation never finishes");

    assert!(
        matches!(error, CodeAssistError::ProvisioningTimedOut),
        "{error}"
    );
    assert_nothing_published(&store, &reference);
    let requests = peer.requests();
    let polls = requests
        .iter()
        .filter(|request| request.line.starts_with("GET "))
        .count();
    assert_eq!(polls, 3, "the recorded attempt cap ends the wait");
}

#[test]
fn code_assist_a_done_operation_without_a_project_falls_back_to_the_explicit_project() {
    let peer = Peer::start(|seen| {
        if seen.line.contains(":loadCodeAssist") {
            return (
                200u16,
                json!({ "allowedTiers": [{ "id": "free-tier", "isDefault": true }] }).to_string(),
            );
        }
        (
            200u16,
            json!({ "done": true, "response": null }).to_string(),
        )
    });
    let store = support::MapStore::new(StoreKind::Keychain);
    let reference = code_assist_reference();
    let config = code_assist_config("api_key");

    let session = code_assist_session(&peer, OnboardingBudget::recorded(), None);
    let error = gemini_cli_login::complete_login(&config, "code-assist", &session, &store)
        .expect_err("no project and no explicit project denies");
    assert!(matches!(error, CodeAssistError::ProjectUnbound), "{error}");
    assert_nothing_published(&store, &reference);

    let explicit = code_assist_session(&peer, OnboardingBudget::recorded(), Some("env-project"));
    gemini_cli_login::complete_login(&config, "code-assist", &explicit, &store)
        .expect("the explicit project is the recorded fallback");
    let stored = gemini_cli_login::read_profile(&store, &reference).expect("the profile reads");
    assert_eq!(stored.project(), "env-project");
    assert_eq!(stored.tier(), "free-tier");
}

#[test]
fn code_assist_refresh_preserves_project_and_tier() {
    let peer = Peer::start(|_seen| {
        (
            200u16,
            json!({
                "currentTier": { "id": "standard-tier" },
                "cloudaicompanionProject": "fixture-project"
            })
            .to_string(),
        )
    });
    let session = code_assist_session(&peer, OnboardingBudget::recorded(), None);
    let store = support::MapStore::new(StoreKind::Keychain);
    let reference = code_assist_reference();
    let config = code_assist_config("api_key");

    gemini_cli_login::complete_login(&config, "code-assist", &session, &store)
        .expect("the profile publishes");

    let profile = gemini_cli_login::refresh_profile(&store, &reference, "rotated-token")
        .expect("the refresh replaces the token");
    assert_eq!(profile, "code-assist");
    let stored = gemini_cli_login::read_profile(&store, &reference).expect("the profile reads");
    assert_eq!(stored.access_token(), "rotated-token");
    assert_eq!(stored.project(), "fixture-project");
    assert_eq!(stored.tier(), "standard-tier");

    let published = store.resolve(&reference).expect("the profile is stored");
    let blank = gemini_cli_login::refresh_profile(&store, &reference, "  ")
        .expect_err("a refresh needs a token");
    assert!(
        matches!(
            blank,
            CodeAssistError::MissingField {
                field: "access_token"
            }
        ),
        "{blank}"
    );
    assert_eq!(
        store.resolve(&reference).expect("the profile is untouched"),
        published,
        "a refused refresh leaves the prior bytes byte-identical"
    );
}

#[test]
fn code_assist_a_stored_string_profile_stays_readable() {
    let reference = code_assist_reference();
    let store = support::MapStore::seeded(
        StoreKind::Keychain,
        &[(
            CODE_ASSIST_SCOPE,
            r#"{"access_token":"stale-token","project":"fixture-project","tier":"standard-tier"}"#,
        )],
    );

    let stored = gemini_cli_login::read_profile(&store, &reference).expect("the profile reads");

    assert_eq!(stored.access_token(), "stale-token");
    assert_eq!(stored.project(), "fixture-project");
    assert_eq!(stored.tier(), "standard-tier");
}

#[test]
fn code_assist_refresh_preserves_an_absent_tier_id() {
    let reference = code_assist_reference();
    let store = support::MapStore::seeded(
        StoreKind::Keychain,
        &[(
            CODE_ASSIST_SCOPE,
            r#"{"access_token":"stale-token","project":"fixture-project","tier":""}"#,
        )],
    );

    gemini_cli_login::refresh_profile(&store, &reference, "rotated-token")
        .expect("the refresh replaces the token");

    assert_eq!(
        String::from_utf8(store.resolve(&reference).expect("the profile is stored"))
            .expect("utf-8 bytes"),
        "{\"access_token\":\"rotated-token\",\"project\":\"fixture-project\",\"tier\":\"\"}"
    );
    let stored = gemini_cli_login::read_profile(&store, &reference).expect("the profile reads");
    assert_eq!(stored.tier(), "", "the absent id stays absent");
    assert_eq!(stored.project(), "fixture-project");
}

#[test]
fn code_assist_a_cancelled_or_late_login_publishes_nothing() {
    let peer = Peer::start(|_seen| (200u16, "{}".to_string()));
    let store = support::MapStore::new(StoreKind::Keychain);
    let reference = code_assist_reference();
    let config = code_assist_config("api_key");

    let cancelled = code_assist_session(&peer, OnboardingBudget::recorded(), None);
    cancelled.cancel();
    let error = gemini_cli_login::complete_login(&config, "code-assist", &cancelled, &store)
        .expect_err("a cancelled session publishes nothing");
    assert!(matches!(error, CodeAssistError::Cancelled), "{error}");
    assert_nothing_published(&store, &reference);
    assert_eq!(
        peer.requests().len(),
        0,
        "no leg runs for a cancelled login"
    );

    let binding = Peer::start(|_seen| {
        (
            200u16,
            json!({
                "currentTier": { "id": "free-tier" },
                "cloudaicompanionProject": "fixture-project"
            })
            .to_string(),
        )
    });
    let first = code_assist_session(&binding, OnboardingBudget::recorded(), None);
    gemini_cli_login::complete_login(&config, "code-assist", &first, &store)
        .expect("the first profile publishes");
    let published = store.resolve(&reference).expect("the profile is stored");

    let late = code_assist_session(&binding, OnboardingBudget::recorded(), None);
    late.cancel();
    let error = gemini_cli_login::complete_login(&config, "code-assist", &late, &store)
        .expect_err("a late completion publishes nothing");
    assert!(matches!(error, CodeAssistError::Cancelled), "{error}");
    assert_eq!(
        store.resolve(&reference).expect("the profile is untouched"),
        published,
        "a cancelled completion leaves the prior bytes byte-identical"
    );

    let second = code_assist_session(&binding, OnboardingBudget::recorded(), None);
    let error = gemini_cli_login::complete_login(&config, "code-assist", &second, &store)
        .expect_err("enrollment is create-only");
    assert!(
        matches!(
            error,
            CodeAssistError::Provider(ProviderError::CredentialOccupied { .. })
        ),
        "{error}"
    );
    assert_eq!(
        store.resolve(&reference).expect("the profile is untouched"),
        published,
        "a refused write leaves the prior bytes byte-identical"
    );
}

/// A mid-flight cancel reaches the guards a pre-cancel cannot: the peer
/// shares the session and cancels once it has served discovery, and again
/// while the first poll is pending. Neither publishes, and the poll loop
/// stops before another request or a write.
#[test]
fn code_assist_a_mid_flight_cancel_publishes_nothing() {
    let shared: Arc<OnceLock<Arc<gemini_cli_login::LoginSession>>> = Arc::new(OnceLock::new());
    let peer_slot = Arc::clone(&shared);
    let peer = Peer::start(move |seen| {
        if seen.line.contains(":loadCodeAssist") {
            peer_slot
                .get()
                .expect("the session is shared before the first leg")
                .cancel();
            return (
                200u16,
                json!({
                    "currentTier": { "id": "free-tier" },
                    "cloudaicompanionProject": "fixture-project"
                })
                .to_string(),
            );
        }
        (500u16, "{}".to_string())
    });
    let session = Arc::new(code_assist_session(
        &peer,
        OnboardingBudget::recorded(),
        None,
    ));
    shared.set(Arc::clone(&session)).expect("the slot is empty");
    let store = support::MapStore::new(StoreKind::Keychain);
    let reference = code_assist_reference();

    let error = gemini_cli_login::complete_login(
        &code_assist_config("api_key"),
        "code-assist",
        &session,
        &store,
    )
    .expect_err("a cancel after discovery publishes nothing");
    assert!(matches!(error, CodeAssistError::Cancelled), "{error}");
    assert_nothing_published(&store, &reference);
    let requests = peer.requests();
    assert_eq!(requests.len(), 1, "only the discovery leg runs");
    assert!(!requests[0].line.contains(":onboardUser"));

    let shared: Arc<OnceLock<Arc<gemini_cli_login::LoginSession>>> = Arc::new(OnceLock::new());
    let peer_slot = Arc::clone(&shared);
    let peer = Peer::start(move |seen| {
        if seen.line.contains(":loadCodeAssist") {
            return (
                200u16,
                json!({ "allowedTiers": [{ "id": "free-tier", "isDefault": true }] }).to_string(),
            );
        }
        if seen.line.contains(":onboardUser") {
            return (
                200u16,
                json!({ "name": "operations/pending", "done": false }).to_string(),
            );
        }
        peer_slot
            .get()
            .expect("the session is shared before the first poll")
            .cancel();
        (
            200u16,
            json!({ "name": "operations/pending", "done": false }).to_string(),
        )
    });
    let session = Arc::new(code_assist_session(
        &peer,
        OnboardingBudget {
            max_attempts: 3,
            poll_interval: Duration::from_millis(10),
        },
        None,
    ));
    shared.set(Arc::clone(&session)).expect("the slot is empty");

    let error = gemini_cli_login::complete_login(
        &code_assist_config("api_key"),
        "code-assist",
        &session,
        &store,
    )
    .expect_err("a cancel during the first poll publishes nothing");
    assert!(matches!(error, CodeAssistError::Cancelled), "{error}");
    assert_nothing_published(&store, &reference);
    let requests = peer.requests();
    assert_eq!(
        requests.len(),
        3,
        "the cancelled poll ends the wait before another request"
    );
    assert!(requests[2].line.starts_with("GET "));
}

/// The poll loop spends the budget's interval between attempts: the recorded
/// budget's 5 s value is asserted separately, and this measures the wait the
/// loop actually applies.
#[test]
fn code_assist_polls_wait_the_budget_interval() {
    let peer = Peer::start(|seen| {
        if seen.line.contains(":loadCodeAssist") {
            return (
                200u16,
                json!({ "allowedTiers": [{ "id": "free-tier", "isDefault": true }] }).to_string(),
            );
        }
        (
            200u16,
            json!({ "name": "operations/never", "done": false }).to_string(),
        )
    });
    let interval = Duration::from_millis(50);
    let session = code_assist_session(
        &peer,
        OnboardingBudget {
            max_attempts: 3,
            poll_interval: interval,
        },
        None,
    );
    let store = support::MapStore::new(StoreKind::Keychain);
    let reference = code_assist_reference();

    let started = Instant::now();
    let error = gemini_cli_login::complete_login(
        &code_assist_config("api_key"),
        "code-assist",
        &session,
        &store,
    )
    .expect_err("the operation never finishes");
    let elapsed = started.elapsed();

    assert!(
        matches!(error, CodeAssistError::ProvisioningTimedOut),
        "{error}"
    );
    assert_nothing_published(&store, &reference);
    assert!(
        elapsed >= interval * 2,
        "two retried polls wait the budget interval: {elapsed:?}"
    );
    let polls = peer
        .requests()
        .iter()
        .filter(|request| request.line.starts_with("GET "))
        .count();
    assert_eq!(polls, 3, "the recorded attempt cap ends the wait");
}

#[test]
fn code_assist_a_refused_write_publishes_nothing() {
    let peer = Peer::start(|seen| {
        if seen.line.contains(":loadCodeAssist") {
            return (
                200u16,
                json!({ "allowedTiers": [{ "id": "free-tier", "isDefault": true }] }).to_string(),
            );
        }
        (
            200u16,
            json!({
                "done": true,
                "response": { "cloudaicompanionProject": { "id": "fixture-project" } }
            })
            .to_string(),
        )
    });
    let store = RefusingLoginStore {
        inner: support::MapStore::new(StoreKind::Keychain),
    };
    let reference = code_assist_reference();

    let error = gemini_cli_login::complete_login(
        &code_assist_config("api_key"),
        "code-assist",
        &code_assist_session(&peer, OnboardingBudget::recorded(), None),
        &store,
    )
    .expect_err("the store refuses the enrollment");

    assert!(
        matches!(
            error,
            CodeAssistError::Provider(ProviderError::StoreUnavailable { .. })
        ),
        "{error}"
    );
    assert_nothing_published(&store.inner, &reference);
}

#[test]
fn code_assist_an_unrecorded_origin_denies_before_a_request() {
    assert_eq!(
        gemini_cli_login::CODE_ASSIST_ORIGIN,
        "https://cloudcode-pa.googleapis.com"
    );
    let error = gemini_cli_login::begin_login(
        "fixture-token",
        &CodeAssistEndpoints {
            code_assist: "https://evil.example".to_string(),
        },
    )
    .expect_err("a foreign origin is refused");
    assert!(
        matches!(
            error,
            CodeAssistError::EndpointNotAdmitted { ref origin }
                if origin == "https://evil.example"
        ),
        "{error}"
    );
    let antigravity = gemini_cli_login::begin_login(
        "fixture-token",
        &CodeAssistEndpoints {
            code_assist: "https://daily-cloudcode-pa.googleapis.com".to_string(),
        },
    )
    .expect_err("the antigravity origin is not a Code Assist origin");
    assert!(
        matches!(antigravity, CodeAssistError::EndpointNotAdmitted { .. }),
        "{antigravity}"
    );
    gemini_cli_login::begin_login("fixture-token", &CodeAssistEndpoints::recorded())
        .expect("the recorded origin is admitted");
}

#[test]
fn code_assist_a_blank_token_denies() {
    let error = gemini_cli_login::begin_login("  ", &CodeAssistEndpoints::recorded())
        .expect_err("the login needs a token");
    assert!(
        matches!(
            error,
            CodeAssistError::MissingField {
                field: "access_token"
            }
        ),
        "{error}"
    );
}

#[test]
fn code_assist_a_non_api_key_binding_denies() {
    let peer = Peer::start(|_seen| (200u16, "{}".to_string()));
    let session = code_assist_session(&peer, OnboardingBudget::recorded(), None);
    let store = support::MapStore::new(StoreKind::Keychain);

    let error = gemini_cli_login::complete_login(
        &code_assist_config("subscription"),
        "code-assist",
        &session,
        &store,
    )
    .expect_err("the login path writes only an api key row");

    assert!(
        matches!(
            error,
            CodeAssistError::NotApiKey {
                kind: ConnKind::Subscription,
                ..
            }
        ),
        "{error}"
    );
    assert_eq!(peer.requests().len(), 0);
}

#[test]
fn code_assist_read_profile_rejects_foreign_material() {
    let reference = code_assist_reference();
    let store = support::MapStore::seeded(
        StoreKind::Keychain,
        &[(
            CODE_ASSIST_SCOPE,
            r#"{"access_token":"fixture-token","project":"fixture-project","tier":"free-tier","extra":1}"#,
        )],
    );

    let error = gemini_cli_login::read_profile(&store, &reference)
        .expect_err("an unknown field is refused");

    assert!(
        matches!(error, CodeAssistError::StoredCredentialMalformed { .. }),
        "{error}"
    );
}

/// The scoped material the blocked Muse producer must leave untouched.
const MUSE_SCOPE: &str = "keychain:rivect-test/muse-subscription";

/// The prior profile bytes a denial must preserve.
const MUSE_PRIOR: &str = r#"{"api_key":"fixture-prior-key","region":"fixture-region"}"#;

/// The recorded external block class the producer denial and the future
/// `muse-code` send gate both carry.
const MUSE_CLASS: &str = "BLOCKED_EXTERNAL";

#[test]
fn muse_profile_denied() {
    let peer = Peer::start(|_seen| (200u16, "{}".to_string()));
    let store = support::MapStore::seeded(StoreKind::Keychain, &[(MUSE_SCOPE, MUSE_PRIOR)]);
    let reference = SecretRef::parse(MUSE_SCOPE).expect("the fixture scope parses");
    let before = store.resolve(&reference).expect("the prior material reads");

    let error = muse_login::begin_login()
        .expect_err("the subscription-key producer never mints or activates a profile");

    assert_eq!(
        muse_login::EXTERNAL_CLASS,
        MUSE_CLASS,
        "the constant names the recorded external class"
    );
    assert!(
        matches!(
            &error,
            MuseError::ExternalBlocked { class } if *class == muse_login::EXTERNAL_CLASS
        ),
        "the denial carries the one constant the send gate will read: {error}"
    );
    assert_eq!(
        error.to_string(),
        format!(
            "the muse subscription-key profile is externally blocked ({MUSE_CLASS}); no documented compatible route exists"
        ),
        "the display is lowercase and names the class"
    );
    assert_eq!(
        store
            .resolve(&reference)
            .expect("the prior material still reads"),
        before,
        "a denial leaves the seeded bytes byte-identical"
    );
    assert!(
        store.occupied(&reference).expect("the scope answers"),
        "the prior profile is never removed"
    );
    assert_eq!(
        store
            .entry_accounts("rivect-test")
            .expect("the store answers")
            .len(),
        1,
        "no second profile or PAYG key is minted"
    );
    assert_eq!(peer.requests().len(), 0, "the producer has no live leg");

    let again = muse_login::begin_login().expect_err("no fallback route exists");
    assert!(
        matches!(
            &again,
            MuseError::ExternalBlocked { class } if *class == muse_login::EXTERNAL_CLASS
        ),
        "a repeated invocation denies identically instead of substituting PAYG: {again}"
    );
    assert_eq!(
        store
            .resolve(&reference)
            .expect("the prior material still reads"),
        before,
        "the repeated denial still writes nothing"
    );
    assert_eq!(
        peer.requests().len(),
        0,
        "no live leg exists after a retry either"
    );
}
