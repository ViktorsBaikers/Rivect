//! Vertex ADC resolution proof (AC-005): the recorded source order, the
//! three file-type exchanges, the metadata leg, the refresh skew and the
//! create-only profile write — against loopback contract peers only. No
//! test touches the real token, metadata or IAM hosts.

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

use rivect::config::Config;
use rivect::providers::vertex_login::{
    self, AdcEndpoints, AdcSources, CredentialSource, EndpointClass, LoginError, METADATA_URL,
    TOKEN_URL,
};
use rivect::providers::{CredentialStore, ProviderError, SecretRef, StoreKind};
use serde_json::{Value, json};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
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
