//! Offline Bedrock proof: the Converse wire for the literal
//! `amazon-bedrock` connection and the Responses wire for
//! `bedrock-mantle` — the recorded regional bases, credentials, closed
//! tables, discovery policy and terminals. One loopback raw-TCP peer per
//! leg; no live AWS account or request.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::let_underscore_must_use,
    let_underscore_drop,
    clippy::redundant_clone,
    reason = "test code keeps unwrap/expect/panic/discard conveniences and block-wise fixture assembly; src/ stays strict (standards §14)"
)]

use rivect::config::{Config, ModelAssign};
use rivect::model::{Broker, NullLedger, RequestManifest};
use rivect::providers::aws;
use rivect::providers::bedrock::BedrockProvider;
use rivect::providers::openai::OpenAiProvider;
use rivect::providers::{
    CredentialStore, Dialect, LoopbackProvider, Provider, ProviderError, StoreKind, ToolCall,
    dialect_for,
};
use rivect::resources::UsageDelta;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

mod support;

use support::{MapStore, prepared_with, responses_completed_stream};

const CONNECTION: &str = "amazon-bedrock";
const REF: &str = "keyring:rivect-test/amazon-bedrock";
const BEARER: &str = "fixture-bearer-token-not-real";
const SECRET: &str = "fixture-secret-key-not-real";
const SESSION: &str = "SESSIONTOKEN";
const STATIC_MATERIAL: &str = r#"{"access_key_id":"AKIDEXAMPLE","secret_access_key":"fixture-secret-key-not-real","session_token":"SESSIONTOKEN"}"#;
const STATIC_REGION_MATERIAL: &str = r#"{"access_key_id":"AKIDEXAMPLE","secret_access_key":"fixture-secret-key-not-real","session_token":"SESSIONTOKEN","region":"us-east-1"}"#;
const MODEL: &str = "anthropic.claude-3-5-haiku-20241022-v1:0";
const MODEL_ENCODED: &str = "anthropic.claude-3-5-haiku-20241022-v1%3A0";
const MODEL_MAX_TOKENS: u64 = 8192;
const WORLD: &str = "/world/bedrock";
const SIGNING_TIMESTAMP: &str = "20150830T123600Z";
const SIGNED_HEADERS: &str =
    "content-type;host;x-amz-content-sha256;x-amz-date;x-amz-security-token";
const SIGNING_REGION: &str = "us-east-1";
const MANTLE_CONNECTION: &str = "bedrock-mantle";
const MANTLE_REF: &str = "keyring:rivect-test/bedrock-mantle";
const MANTLE_MODEL: &str = "openai.gpt-5.6-sol";
const MANTLE_WORLD: &str = "/world/bedrock-mantle";
const MANTLE_SEED: [&str; 5] = [
    "openai.gpt-5.4",
    "openai.gpt-5.5",
    "openai.gpt-5.6-luna",
    "openai.gpt-5.6-sol",
    "openai.gpt-5.6-terra",
];

fn fixture_config(model: &str, region: Option<&str>, effort: &str) -> Config {
    let region = region.map_or_else(String::new, |region| format!("region = \"{region}\"\n"));
    let document = format!(
        "config_version = 1\n\
         [connections.{CONNECTION}]\n\
         kind = \"api_key\"\n\
         endpoint = \"https://bedrock-runtime.us-east-1.amazonaws.com\"\n\
         credential_ref = \"{REF}\"\n\
         {region}\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"{CONNECTION}\", model_id = \"{model}\" }}\n\
         {effort}\n\
         fallback = {{ mode = \"off\" }}\n"
    );
    Config::parse_validated(&document).expect("the fixture config validates")
}

fn standard_config(model: &str) -> Config {
    fixture_config(model, None, "effort = { mode = \"auto\" }")
}

fn effort_config() -> Config {
    fixture_config(
        MODEL,
        None,
        "effort = { mode = \"fixed\", value = \"high\" }",
    )
}

/// A `local` declaration for the Converse id, optionally carrying the
/// contradictory profile member the build gate names first.
fn local_config(profile: Option<&str>) -> Config {
    let binding = match profile {
        Some(name) => {
            format!("profile = \"{name}\"\n[profiles.{name}]\ncredential_ref = \"{REF}\"\n")
        }
        None => String::new(),
    };
    let document = format!(
        "config_version = 1\n\
         [connections.{CONNECTION}]\n\
         kind = \"local\"\n\
         endpoint = \"\"\n\
         {binding}\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"{CONNECTION}\", model_id = \"{MODEL}\" }}\n\
         effort = {{ mode = \"auto\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    );
    Config::parse_validated(&document).expect("the local-declaration fixture config validates")
}

fn fixture_store(material: &str) -> Arc<MapStore> {
    Arc::new(MapStore::seeded(StoreKind::Keychain, &[(REF, material)]))
}

fn empty_store() -> Arc<MapStore> {
    Arc::new(MapStore::seeded(StoreKind::Keychain, &[]))
}

fn fixture_provider(config: &Config, store: Arc<MapStore>, base: &str) -> BedrockProvider {
    BedrockProvider::with_base_override(
        config,
        CONNECTION,
        store,
        Duration::from_secs(5),
        Some(base.to_owned()),
    )
    .expect("the Converse adapter builds")
}

fn mantle_config(model: &str, region: Option<&str>) -> Config {
    let region = region.map_or_else(String::new, |region| format!("region = \"{region}\"\n"));
    let document = format!(
        "config_version = 1\n\
         [connections.{MANTLE_CONNECTION}]\n\
         kind = \"api_key\"\n\
         endpoint = \"\"\n\
         credential_ref = \"{MANTLE_REF}\"\n\
         {region}\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"{MANTLE_CONNECTION}\", model_id = \"{model}\" }}\n\
         effort = {{ mode = \"auto\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    );
    Config::parse_validated(&document).expect("the mantle fixture config validates")
}

fn mantle_store(material: &str) -> Arc<MapStore> {
    Arc::new(MapStore::seeded(
        StoreKind::Keychain,
        &[(MANTLE_REF, material)],
    ))
}

fn mantle_provider(config: &Config, store: Arc<MapStore>, base: &str) -> OpenAiProvider {
    OpenAiProvider::with_mantle_base_override(
        config,
        MANTLE_CONNECTION,
        store,
        Duration::from_secs(5),
        Some(format!("{base}/openai/v1")),
    )
    .expect("the mantle adapter builds")
}

fn mantle_manifest(config: &Config, inputs: &str) -> RequestManifest {
    let mut broker = Broker::new(Box::new(LoopbackProvider::new()));
    broker
        .prepare("main", config, MANTLE_WORLD, inputs)
        .expect("the mantle pin prepares")
}

fn mantle_peer(content_type: &'static str, status: &'static str, body: Vec<u8>) -> Peer {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the mantle peer");
    let base = format!(
        "http://{}",
        listener.local_addr().expect("the peer address")
    );
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept one mantle request");
        let captured = read_request(&mut stream);
        let head = format!(
            "HTTP/1.1 {status}\r\n\
             Content-Type: {content_type}\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\r\n",
            body.len()
        );
        stream
            .write_all(head.as_bytes())
            .expect("write the mantle response head");
        stream
            .write_all(&body)
            .expect("write the mantle response body");
        stream.flush().expect("flush the mantle response");
        captured
    });
    Peer { base, handle }
}

struct SequencePeer {
    base: String,
    handle: JoinHandle<SequenceCaptured>,
}

struct SequenceCaptured {
    requests: Vec<Captured>,
    extra: bool,
}

/// A loopback peer that answers one scripted response per request and
/// then reports whether any further request reached it.
fn mantle_sequence_peer(responses: Vec<(&'static str, &'static str, Vec<u8>)>) -> SequencePeer {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the sequence peer");
    let base = format!(
        "http://{}",
        listener.local_addr().expect("the peer address")
    );
    let handle = std::thread::spawn(move || {
        let mut requests = Vec::new();
        for (content_type, status, body) in responses {
            let (mut stream, _) = listener.accept().expect("accept one scripted request");
            requests.push(read_request(&mut stream));
            let head = format!(
                "HTTP/1.1 {status}\r\n\
                 Content-Type: {content_type}\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\r\n",
                body.len()
            );
            stream
                .write_all(head.as_bytes())
                .expect("write the scripted response head");
            stream
                .write_all(&body)
                .expect("write the scripted response body");
            stream.flush().expect("flush the scripted response");
        }
        listener
            .set_nonblocking(true)
            .expect("the sequence peer is nonblocking");
        // A denied send that leaked its wire leg would connect here.
        std::thread::sleep(Duration::from_millis(100));
        let extra = listener.accept().is_ok();
        SequenceCaptured { requests, extra }
    });
    SequencePeer { base, handle }
}

fn manifest(config: &Config, inputs: &str) -> RequestManifest {
    let mut broker = Broker::new(Box::new(LoopbackProvider::new()));
    broker
        .prepare("main", config, WORLD, inputs)
        .expect("the pin prepares")
}

struct Captured {
    line: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

impl Captured {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }

    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).expect("the request body is json")
    }
}

struct Peer {
    base: String,
    handle: JoinHandle<Captured>,
}

impl Peer {
    fn finish(self) -> Captured {
        self.handle.join().expect("the peer thread joins")
    }
}

fn read_request(stream: &mut TcpStream) -> Captured {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 1024];
    let head_end = loop {
        let read = stream.read(&mut chunk).expect("read the request head");
        assert!(read > 0, "the peer closed before the request head");
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
    };
    let head = String::from_utf8_lossy(&buffer[..head_end]);
    let mut lines = head.split("\r\n");
    let line = lines.next().unwrap_or_default().to_owned();
    let mut headers = BTreeMap::new();
    for header in lines {
        if let Some((name, value)) = header.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
        }
    }
    let content_length = headers
        .get("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = buffer[head_end..].to_vec();
    while body.len() < content_length {
        let read = stream.read(&mut chunk).expect("read the request body");
        if read == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..read]);
    }
    body.truncate(content_length);
    Captured {
        line,
        headers,
        body,
    }
}

fn write_head(stream: &mut TcpStream, length: usize) {
    let head = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: application/vnd.amazon.eventstream\r\n\
         Content-Length: {length}\r\n\
         Connection: close\r\n\r\n"
    );
    stream
        .write_all(head.as_bytes())
        .expect("write the response head");
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut block = [0u8; 64];
    if key.len() > block.len() {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0x36u8; 64];
    let mut outer_pad = [0x5cu8; 64];
    for (index, byte) in block.iter().enumerate() {
        inner_pad[index] ^= byte;
        outer_pad[index] ^= byte;
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(data);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner);
    let digest = outer.finalize();
    let mut signature = [0u8; 32];
    signature.copy_from_slice(&digest);
    signature
}

/// The AWS canonical URI, implemented independently of the signer under
/// test: `/` and the unreserved set stay literal, every other byte —
/// including an already-encoded `%` — is re-encoded once more.
fn expected_canonical_uri(path: &str) -> String {
    let mut canonical = String::new();
    for byte in path.bytes() {
        if byte == b'/' || byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~')
        {
            canonical.push(char::from(byte));
        } else {
            canonical.push_str(&format!("%{byte:02X}"));
        }
    }
    canonical
}

/// Recomputes the whole SigV4 authorization from the captured request bytes,
/// independently of the signer under test.
fn expected_sigv4_authorization(captured: &Captured, region: &str) -> String {
    let path = captured
        .line
        .split_whitespace()
        .nth(1)
        .expect("the captured request line carries a target");
    let path = expected_canonical_uri(path);
    let host = captured.header("host").expect("the request carries host");
    let content_type = captured
        .header("content-type")
        .expect("the request carries content-type");
    let date = captured
        .header("x-amz-date")
        .expect("the request carries x-amz-date");
    let token = captured
        .header("x-amz-security-token")
        .expect("the request carries x-amz-security-token");
    let payload_hash = rivect::config::hex(&Sha256::digest(&captured.body));
    let canonical_headers = format!(
        "content-type:{content_type}\n\
         host:{host}\n\
         x-amz-content-sha256:{payload_hash}\n\
         x-amz-date:{date}\n\
         x-amz-security-token:{token}\n"
    );
    let canonical =
        format!("POST\n{path}\n\n{canonical_headers}\n{SIGNED_HEADERS}\n{payload_hash}");
    let scope = format!("{}/{region}/bedrock/aws4_request", &date[..8]);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{date}\n{scope}\n{}",
        rivect::config::hex(&Sha256::digest(canonical.as_bytes()))
    );
    let mut key = hmac_sha256(format!("AWS4{SECRET}").as_bytes(), &date.as_bytes()[..8]);
    for part in [region, "bedrock", "aws4_request"] {
        key = hmac_sha256(&key, part.as_bytes());
    }
    let signature = rivect::config::hex(&hmac_sha256(&key, string_to_sign.as_bytes()));
    format!(
        "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/{scope}, SignedHeaders={SIGNED_HEADERS}, Signature={signature}"
    )
}

fn scripted_peer(body: Vec<u8>) -> Peer {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the loopback peer");
    let base = format!(
        "http://{}",
        listener.local_addr().expect("the peer address")
    );
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept one request");
        let captured = read_request(&mut stream);
        write_head(&mut stream, body.len());
        stream.write_all(&body).expect("write the response body");
        stream.flush().expect("flush the response");
        captured
    });
    Peer { base, handle }
}

fn split_peer(body: Vec<u8>, split: usize) -> Peer {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the loopback peer");
    let base = format!(
        "http://{}",
        listener.local_addr().expect("the peer address")
    );
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept one request");
        let captured = read_request(&mut stream);
        write_head(&mut stream, body.len());
        let (first, second) = body.split_at(split);
        stream
            .write_all(first)
            .expect("write the first response half");
        stream.flush().expect("flush the first response half");
        std::thread::sleep(Duration::from_millis(25));
        stream
            .write_all(second)
            .expect("write the second response half");
        stream.flush().expect("flush the response");
        captured
    });
    Peer { base, handle }
}

struct SilentPeer {
    listener: TcpListener,
    base: String,
}

impl SilentPeer {
    fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind the silent peer");
        listener
            .set_nonblocking(true)
            .expect("the silent peer is nonblocking");
        let base = format!(
            "http://{}",
            listener.local_addr().expect("the peer address")
        );
        Self { listener, base }
    }

    fn assert_no_request(&self) {
        match self.listener.accept() {
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Ok((_stream, _)) => panic!("the denied send reached the peer"),
            Err(error) => panic!("the silent peer failed to check: {error}"),
        }
    }
}

fn string_header(name: &str, value: &str) -> Vec<u8> {
    let mut header = Vec::new();
    header.push(u8::try_from(name.len()).expect("the header name fits"));
    header.extend_from_slice(name.as_bytes());
    header.push(7);
    header.extend_from_slice(
        &u16::try_from(value.len())
            .expect("the header value fits")
            .to_be_bytes(),
    );
    header.extend_from_slice(value.as_bytes());
    header
}

fn frame_with_headers(headers: &[u8], payload: &[u8]) -> Vec<u8> {
    let total = 12 + headers.len() + payload.len() + 4;
    let mut message = Vec::with_capacity(total);
    message.extend_from_slice(&u32::try_from(total).expect("the frame fits").to_be_bytes());
    message.extend_from_slice(
        &u32::try_from(headers.len())
            .expect("the header block fits")
            .to_be_bytes(),
    );
    message.extend_from_slice(&0u32.to_be_bytes());
    message.extend_from_slice(headers);
    message.extend_from_slice(payload);
    message.extend_from_slice(&0u32.to_be_bytes());
    message
}

fn frame(message_type: &str, event_type: &str, payload: &Value) -> Vec<u8> {
    let mut headers = string_header(":message-type", message_type);
    headers.extend(string_header(":event-type", event_type));
    let payload = serde_json::to_vec(payload).expect("the payload is json");
    frame_with_headers(&headers, &payload)
}

fn exception_frame(exception_type: &str, message: &str) -> Vec<u8> {
    let mut headers = string_header(":message-type", "exception");
    headers.extend(string_header(":exception-type", exception_type));
    let payload = serde_json::to_vec(&json!({"message": message})).expect("the payload is json");
    frame_with_headers(&headers, &payload)
}

fn frame_prelude(total: u32, headers_length: u32) -> Vec<u8> {
    let mut prelude = Vec::new();
    prelude.extend_from_slice(&total.to_be_bytes());
    prelude.extend_from_slice(&headers_length.to_be_bytes());
    prelude.extend_from_slice(&0u32.to_be_bytes());
    prelude
}

fn valid_stream(text: &str, input_tokens: u64, output_tokens: u64) -> Vec<u8> {
    let total = input_tokens
        .checked_add(output_tokens)
        .expect("the fixture total fits");
    let mut stream = Vec::new();
    stream.extend(frame(
        "event",
        "messageStart",
        &json!({"role": "assistant"}),
    ));
    stream.extend(frame(
        "event",
        "contentBlockStart",
        &json!({"contentBlockIndex": 0, "start": {}}),
    ));
    stream.extend(frame(
        "event",
        "contentBlockDelta",
        &json!({"contentBlockIndex": 0, "delta": {"text": text}}),
    ));
    stream.extend(frame(
        "event",
        "contentBlockStop",
        &json!({"contentBlockIndex": 0}),
    ));
    stream.extend(frame(
        "event",
        "messageStop",
        &json!({"stopReason": "end_turn"}),
    ));
    stream.extend(frame(
        "event",
        "metadata",
        &json!({"usage": {
            "inputTokens": input_tokens,
            "outputTokens": output_tokens,
            "totalTokens": total,
        }}),
    ));
    stream
}

fn tool_stream(name: &str, input: &str, stop_reason: &str) -> Vec<u8> {
    let mut stream = Vec::new();
    stream.extend(frame(
        "event",
        "messageStart",
        &json!({"role": "assistant"}),
    ));
    stream.extend(frame(
        "event",
        "contentBlockStart",
        &json!({
            "contentBlockIndex": 0,
            "start": {"toolUse": {"toolUseId": "tool-1", "name": name}},
        }),
    ));
    stream.extend(frame(
        "event",
        "contentBlockDelta",
        &json!({"contentBlockIndex": 0, "delta": {"toolUse": {"input": input}}}),
    ));
    stream.extend(frame(
        "event",
        "contentBlockStop",
        &json!({"contentBlockIndex": 0}),
    ));
    stream.extend(frame(
        "event",
        "messageStop",
        &json!({"stopReason": stop_reason}),
    ));
    stream.extend(frame(
        "event",
        "metadata",
        &json!({"usage": {
            "inputTokens": 1,
            "outputTokens": 1,
            "totalTokens": 2,
        }}),
    ));
    stream
}

#[test]
fn bedrock_valid_control_bearer_yields_one_outcome_and_one_physical_usage() {
    let peer = scripted_peer(valid_stream("verified outcome text", 11, 7));
    let config = standard_config(MODEL);
    let store = fixture_store(BEARER);
    let provider = fixture_provider(&config, store.clone(), &peer.base);
    let (mut broker, prepared) = prepared_with(
        (provider, store),
        &config,
        WORLD,
        "goal: prove the Converse wire",
    );

    let reply = broker
        .dispatch(&mut NullLedger, WORLD, &prepared)
        .expect("the verified outcome dispatches");
    assert_eq!(reply.text, "verified outcome text");
    assert!(reply.tool_calls.is_empty());
    assert_eq!(
        reply.usage,
        UsageDelta::Exact {
            prompt_tokens: 11,
            completion_tokens: 7,
            total_tokens: 18,
        }
    );
    assert_eq!(broker.accounted_requests(), 1);
    let record = broker
        .accounting_record(&prepared.attempt_id)
        .expect("the send is accounted");
    assert_eq!(record.connection, CONNECTION);
    assert_eq!(record.usage, reply.usage);

    let captured = peer.finish();
    assert_eq!(
        captured.line,
        format!("POST /model/{MODEL_ENCODED}/converse-stream HTTP/1.1")
    );
    let expected_auth = format!("Bearer {BEARER}");
    assert_eq!(
        captured.header("authorization"),
        Some(expected_auth.as_str())
    );
    assert_eq!(captured.header("content-type"), Some("application/json"));
    assert_eq!(
        captured.header("accept"),
        Some("application/vnd.amazon.eventstream")
    );
    let body = captured.json();
    assert_eq!(body["messages"][0]["role"], json!("user"));
    assert_eq!(
        body["messages"][0]["content"][0]["text"],
        json!(prepared.inputs)
    );
    assert_eq!(body["system"][0]["text"], json!(prepared.instructions));
    assert_eq!(
        body["inferenceConfig"]["maxTokens"],
        json!(MODEL_MAX_TOKENS)
    );
    assert_eq!(
        body["toolConfig"]["tools"][0]["toolSpec"]["name"],
        json!("read_file")
    );
    assert_eq!(
        body["toolConfig"]["tools"][0]["toolSpec"]["inputSchema"]["json"]["type"],
        json!("object")
    );
    assert!(body.get("model").is_none());
    assert!(!String::from_utf8_lossy(&captured.body).contains(BEARER));
}

#[test]
fn bedrock_valid_control_static_key_sigv4_signs_the_converse_request() {
    let peer = scripted_peer(valid_stream("signed outcome", 3, 4));
    let config = standard_config(MODEL);
    let store = fixture_store(STATIC_REGION_MATERIAL);
    let provider = fixture_provider(&config, store.clone(), &peer.base)
        .with_signing_timestamp(SIGNING_TIMESTAMP);
    let (mut broker, prepared) = prepared_with(
        (provider, store),
        &config,
        WORLD,
        "goal: sign the Converse request",
    );

    let reply = broker
        .dispatch(&mut NullLedger, WORLD, &prepared)
        .expect("the signed Converse send dispatches");
    assert_eq!(reply.text, "signed outcome");
    assert_eq!(
        reply.usage,
        UsageDelta::Exact {
            prompt_tokens: 3,
            completion_tokens: 4,
            total_tokens: 7,
        }
    );
    assert_eq!(broker.accounted_requests(), 1);
    let record = broker
        .accounting_record(&prepared.attempt_id)
        .expect("the send is accounted");
    assert_eq!(record.connection, CONNECTION);
    assert_eq!(record.usage, reply.usage);

    let captured = peer.finish();
    assert_eq!(
        captured.line,
        format!("POST /model/{MODEL_ENCODED}/converse-stream HTTP/1.1")
    );
    let authorization = captured
        .header("authorization")
        .expect("the static key signs the request");
    assert!(
        authorization.contains(&format!("SignedHeaders={SIGNED_HEADERS},")),
        "the signed set binds the payload hash: {authorization}"
    );
    assert_eq!(
        authorization,
        expected_sigv4_authorization(&captured, SIGNING_REGION)
    );
    assert_eq!(captured.header("x-amz-date"), Some(SIGNING_TIMESTAMP));
    assert_eq!(captured.header("x-amz-security-token"), Some(SESSION));
    let expected_hash = rivect::config::hex(&Sha256::digest(&captured.body));
    assert_eq!(
        captured.header("x-amz-content-sha256"),
        Some(expected_hash.as_str())
    );
    assert_eq!(captured.header("content-type"), Some("application/json"));
    assert_eq!(
        captured.header("accept"),
        Some("application/vnd.amazon.eventstream")
    );
    assert!(!String::from_utf8_lossy(&captured.body).contains(SECRET));
}

#[test]
fn bedrock_catalog_is_the_recorded_static_table() {
    let config = standard_config(MODEL);
    let provider = BedrockProvider::new(&config, CONNECTION, empty_store(), Duration::from_secs(5))
        .expect("the Converse adapter builds");
    let models = provider.catalog_models();
    assert_eq!(models.len(), 149, "the recorded 149-id table");
    let haiku = models
        .iter()
        .find(|model| model.id == MODEL)
        .expect("the recorded haiku row");
    assert_eq!(haiku.context_window, Some(200000));
    assert_eq!(haiku.max_output_tokens, Some(8192));
    let glm = models
        .iter()
        .find(|model| model.id == "zai.glm-5")
        .expect("the recorded zai row");
    assert_eq!(glm.context_window, Some(202752));
    assert_eq!(glm.max_output_tokens, Some(101376));
    let mut rows: Vec<String> = models
        .iter()
        .map(|model| {
            format!(
                "{}\t{}\t{}\n",
                model.id,
                model
                    .context_window
                    .expect("every row carries a context window"),
                model
                    .max_output_tokens
                    .expect("every row carries an output bound"),
            )
        })
        .collect();
    rows.sort();
    let digest = rivect::config::hex(&Sha256::digest(rows.concat().as_bytes()));
    assert_eq!(
        digest,
        "2c5b3094c9b4cc5a8ba4c24f8b72c101dedd78aa9d6dcded4f2e792c46b4e0e9"
    );
    let unique: BTreeSet<&str> = models.iter().map(|model| model.id.as_str()).collect();
    assert_eq!(unique.len(), models.len(), "the table carries unique ids");
    assert_eq!(dialect_for(CONNECTION), Some(Dialect::Converse));
}

#[test]
fn bedrock_recorded_base_resolves_per_region() {
    assert_eq!(
        aws::bedrock_base("eu-central-1"),
        "https://bedrock-runtime.eu-central-1.amazonaws.com"
    );
    let config = standard_config(MODEL);
    let provider = BedrockProvider::new(&config, CONNECTION, empty_store(), Duration::from_secs(5))
        .expect("the Converse adapter builds")
        .with_signing_timestamp(SIGNING_TIMESTAMP);
    assert_eq!(
        provider.resolved_base("eu-central-1"),
        "https://bedrock-runtime.eu-central-1.amazonaws.com"
    );
    assert_eq!(
        provider.resolved_base("us-east-1"),
        "https://bedrock-runtime.us-east-1.amazonaws.com"
    );
}

#[test]
fn bedrock_base_override_denies_non_loopback_and_ambiguous_urls() {
    let config = standard_config(MODEL);
    let store: Arc<dyn CredentialStore> = fixture_store(BEARER);
    for base in [
        "https://example.com",
        "http://user:pass@127.0.0.1:9",
        "http://127.0.0.1:9/?query=1",
        "http://127.0.0.1:9/#fragment",
    ] {
        let error = BedrockProvider::with_base_override(
            &config,
            CONNECTION,
            Arc::clone(&store),
            Duration::from_secs(5),
            Some(base.to_owned()),
        )
        .expect_err("the override is not an admitted loopback endpoint");
        assert!(
            matches!(error, ProviderError::UnsendableRequest { .. }),
            "{base}: {error:?}"
        );
    }
}

#[test]
fn bedrock_trailing_slash_base_keeps_one_slash() {
    let peer = scripted_peer(valid_stream("normalized base", 1, 1));
    let base = format!("{}/", peer.base);
    let config = standard_config(MODEL);
    let store = fixture_store(BEARER);
    let provider = fixture_provider(&config, store.clone(), &base);
    let (mut broker, prepared) = prepared_with(
        (provider, store),
        &config,
        WORLD,
        "goal: normalize the base",
    );

    let reply = broker
        .dispatch(&mut NullLedger, WORLD, &prepared)
        .expect("the trailing-slash base sends");
    assert_eq!(reply.text, "normalized base");
    assert_eq!(broker.accounted_requests(), 1);
    let captured = peer.finish();
    assert_eq!(
        captured.line,
        format!("POST /model/{MODEL_ENCODED}/converse-stream HTTP/1.1")
    );
}

#[test]
fn bedrock_request_uses_the_recorded_max_tokens() {
    let peer = scripted_peer(valid_stream("tokens", 1, 1));
    let config = standard_config("zai.glm-5");
    let store = fixture_store(BEARER);
    let provider = fixture_provider(&config, store.clone(), &peer.base);
    let (mut broker, prepared) = prepared_with(
        (provider, store),
        &config,
        WORLD,
        "goal: use the recorded output bound",
    );

    let reply = broker
        .dispatch(&mut NullLedger, WORLD, &prepared)
        .expect("the recorded output bound sends");
    assert_eq!(reply.text, "tokens");
    assert_eq!(
        reply.usage,
        UsageDelta::Exact {
            prompt_tokens: 1,
            completion_tokens: 1,
            total_tokens: 2,
        }
    );
    assert_eq!(broker.accounted_requests(), 1);
    let record = broker
        .accounting_record(&prepared.attempt_id)
        .expect("the send is accounted");
    assert_eq!(record.usage, reply.usage);
    let captured = peer.finish();
    let body = captured.json();
    assert_eq!(body["inferenceConfig"]["maxTokens"], json!(101376));
    assert_ne!(
        u64::try_from(prepared.output_reserve).expect("the reserve fits"),
        101376,
        "the body must not use the byte reserve as a token bound"
    );
}

#[test]
fn bedrock_arn_model_uses_its_embedded_region_and_table_id() {
    let arn =
        "arn:aws:bedrock:eu-central-1:123456789012:foundation-model/anthropic.claude-opus-4-6-v1";
    let encoded = "arn%3Aaws%3Abedrock%3Aeu-central-1%3A123456789012%3Afoundation-model%2Fanthropic.claude-opus-4-6-v1";
    let peer = scripted_peer(valid_stream("arn outcome", 2, 3));
    let config = standard_config(arn);
    let store = fixture_store(STATIC_MATERIAL);
    let provider = fixture_provider(&config, store.clone(), &peer.base);
    let (mut broker, prepared) =
        prepared_with((provider, store), &config, WORLD, "goal: use the ARN model");

    let reply = broker
        .dispatch(&mut NullLedger, WORLD, &prepared)
        .expect("the recorded ARN model sends");
    assert_eq!(reply.text, "arn outcome");
    assert_eq!(
        reply.usage,
        UsageDelta::Exact {
            prompt_tokens: 2,
            completion_tokens: 3,
            total_tokens: 5,
        }
    );
    assert_eq!(broker.accounted_requests(), 1);
    let record = broker
        .accounting_record(&prepared.attempt_id)
        .expect("the send is accounted");
    assert_eq!(record.usage, reply.usage);
    let captured = peer.finish();
    assert_eq!(
        captured.line,
        format!("POST /model/{encoded}/converse-stream HTTP/1.1")
    );
    assert!(
        captured.line.contains("%3A"),
        "the wire path carries the encoded ARN separator"
    );
    let authorization = captured
        .header("authorization")
        .expect("the ARN send is signed");
    assert!(
        authorization.contains("/eu-central-1/bedrock/aws4_request"),
        "the ARN's embedded region signs the request: {authorization}"
    );
    assert_eq!(
        authorization,
        expected_sigv4_authorization(&captured, "eu-central-1"),
        "the signature recomputes from the captured bytes with the doubly-encoded canonical path"
    );
}

#[test]
fn bedrock_arn_with_an_unrecorded_id_denies() {
    let arn = "arn:aws:bedrock:eu-central-1:123456789012:foundation-model/not-a-recorded-model";
    let silent = SilentPeer::new();
    let config = standard_config(arn);
    let mut provider = fixture_provider(&config, empty_store(), &silent.base);
    let prepared = manifest(&config, "goal: deny the unrecorded ARN");

    match provider.send(&prepared) {
        Err(ProviderError::UnsupportedParameter {
            connection,
            parameter,
            model,
        }) => {
            assert_eq!(connection, CONNECTION);
            assert_eq!(parameter, "model");
            assert_eq!(model, arn);
        }
        other => panic!("expected the model denial, got {other:?}"),
    }
    silent.assert_no_request();
}

#[test]
fn bedrock_model_outside_the_table_denies_before_wire() {
    let silent = SilentPeer::new();
    let config = standard_config("not-a-recorded-model");
    let mut provider = fixture_provider(&config, empty_store(), &silent.base);
    let prepared = manifest(&config, "goal: deny the unrecorded model");

    match provider.send(&prepared) {
        Err(ProviderError::UnsupportedParameter {
            connection,
            parameter,
            model,
        }) => {
            assert_eq!(connection, CONNECTION);
            assert_eq!(parameter, "model");
            assert_eq!(model, "not-a-recorded-model");
        }
        other => panic!("expected the model denial, got {other:?}"),
    }
    silent.assert_no_request();
}

#[test]
fn bedrock_pinned_effort_denies() {
    let silent = SilentPeer::new();
    let config = effort_config();
    let mut provider = fixture_provider(&config, empty_store(), &silent.base);
    let prepared = manifest(&config, "goal: deny the pinned effort");

    match provider.send(&prepared) {
        Err(ProviderError::UnsupportedParameter {
            connection,
            parameter,
            model,
        }) => {
            assert_eq!(connection, CONNECTION);
            assert_eq!(parameter, "effort");
            assert_eq!(model, MODEL);
        }
        other => panic!("expected the effort denial, got {other:?}"),
    }
    silent.assert_no_request();
}

#[test]
fn bedrock_wrong_credential_or_region_denies_without_secrets() {
    let material = r#"{"sso_start_url":"https://example.invalid/start"}"#;
    let silent = SilentPeer::new();
    let config = standard_config(MODEL);
    let mut provider = fixture_provider(&config, fixture_store(material), &silent.base);
    let prepared = manifest(&config, "goal: deny the blocked material");
    let error = provider
        .send(&prepared)
        .expect_err("the SSO descriptor is a blocked class");
    let message = error.to_string();
    match error {
        ProviderError::UnsupportedCredentialClass { connection, class } => {
            assert_eq!(connection, CONNECTION);
            assert_eq!(class, "sso");
        }
        other => panic!("expected the blocked credential class, got {other:?}"),
    }
    assert!(!message.contains(SECRET));
    assert!(!message.contains(BEARER));
    silent.assert_no_request();

    let model = "us.anthropic.claude-opus-4-6-v1";
    let silent = SilentPeer::new();
    let config = fixture_config(model, Some("eu-west-1"), "effort = { mode = \"auto\" }");
    let mut provider = fixture_provider(&config, fixture_store(BEARER), &silent.base);
    let prepared = manifest(&config, "goal: deny the wrong region");
    match provider.send(&prepared) {
        Err(ProviderError::RegionMismatch { connection, region }) => {
            assert_eq!(connection, CONNECTION);
            assert_eq!(region, "eu-west-1");
        }
        other => panic!("expected the region denial, got {other:?}"),
    }
    silent.assert_no_request();
}

/// Every region source is admitted by the strict grammar before a base
/// builder sees it: a hostile configured, material, ARN or ambient value
/// is a typed denial with no peer request and no echoed value.
#[test]
fn bedrock_hostile_region_sources_deny_before_the_wire() {
    let hostile_material = r#"{"access_key_id":"AKIDEXAMPLE","secret_access_key":"fixture-secret-key-not-real","region":"x.y"}"#;
    let arn = "arn:aws:bedrock:x.y:123456789012:foundation-model/anthropic.claude-opus-4-6-v1";

    let configured = fixture_config(MODEL, Some("eu-evil.com/"), "effort = { mode = \"auto\" }");
    let empty = fixture_config(MODEL, Some(""), "effort = { mode = \"auto\" }");
    let cases = [
        (configured, BEARER.to_owned(), None),
        (empty, BEARER.to_owned(), None),
        (standard_config(MODEL), hostile_material.to_owned(), None),
        (standard_config(arn), BEARER.to_owned(), None),
        (
            standard_config(MODEL),
            BEARER.to_owned(),
            Some("eu-evil.com/"),
        ),
    ];
    for (config, material, ambient) in cases {
        let silent = SilentPeer::new();
        let mut provider = fixture_provider(&config, fixture_store(&material), &silent.base);
        if let Some(ambient) = ambient {
            provider = provider.with_ambient_region(ambient);
        }
        let prepared = manifest(&config, "goal: deny the hostile region");
        let error = provider.send(&prepared).expect_err("the region is not AWS");
        let rendered = format!("{error} {error:?}");
        match error {
            ProviderError::UnsendableRequest { connection, reason } => {
                assert_eq!(connection, CONNECTION);
                assert_eq!(reason, "region is not a valid AWS region");
            }
            other => panic!("expected the region denial, got {other:?}"),
        }
        assert!(!rendered.contains("eu-evil.com"), "{rendered}");
        assert!(!rendered.contains("x.y"), "{rendered}");
        silent.assert_no_request();
    }
}

/// The owner gates run before the credential seam: a reverse id is another
/// dialect, and a `local` declaration (with or without a contradictory
/// profile) never resolves a scoped credential.
#[test]
fn bedrock_owner_gates_deny_before_credential_or_wire() {
    let config = standard_config(MODEL);
    for reverse in ["bedrock-mantle", "github-copilot"] {
        let error = BedrockProvider::new(&config, reverse, empty_store(), Duration::from_secs(5))
            .expect_err("a reverse id is another dialect");
        assert!(
            matches!(error, ProviderError::DialectMismatch { .. }),
            "{reverse}: {error:?}"
        );
    }

    let error = BedrockProvider::new(
        &local_config(Some("fixture-profile")),
        CONNECTION,
        empty_store(),
        Duration::from_secs(5),
    )
    .expect_err("a local declaration with a profile denies");
    assert!(
        matches!(error, ProviderError::LocalProfileDeclared { .. }),
        "{error:?}"
    );

    let error = BedrockProvider::new(
        &local_config(None),
        CONNECTION,
        empty_store(),
        Duration::from_secs(5),
    )
    .expect_err("a local declaration is not a credentialled class");
    match error {
        ProviderError::CredentialUnresolved {
            connection,
            scope,
            cause,
        } => {
            assert_eq!(connection, CONNECTION);
            assert_eq!(scope, format!("connections.{CONNECTION}.kind"));
            assert!(cause.is_none());
        }
        other => panic!("expected the unresolved credential, got {other:?}"),
    }
}

/// A one-member auto pool naming the Converse connection resolves the
/// closed table's sorted-first id and still yields one outcome and one
/// physical usage.
#[test]
fn bedrock_auto_picks_the_sorted_first_table_model() {
    let peer = scripted_peer(valid_stream("auto outcome", 4, 2));
    let config = standard_config(MODEL);
    let store = fixture_store(BEARER);
    let mut provider = fixture_provider(&config, store, &peer.base);
    let mut prepared = manifest(&config, "goal: resolve the auto pin");
    prepared.model = ModelAssign::Auto {
        pool: Some(vec![CONNECTION.to_string()]),
    };

    let reply = provider.send(&prepared).expect("the auto pin sends");
    assert_eq!(reply.text, "auto outcome");
    assert_eq!(
        reply.usage,
        UsageDelta::Exact {
            prompt_tokens: 4,
            completion_tokens: 2,
            total_tokens: 6,
        }
    );
    let captured = peer.finish();
    assert_eq!(
        captured.line,
        "POST /model/anthropic.claude-3-5-haiku-20241022-v1%3A0/converse-stream HTTP/1.1"
    );
    assert_eq!(captured.json()["inferenceConfig"]["maxTokens"], json!(8192));
}

#[test]
fn bedrock_absent_material_denies_with_no_request() {
    let silent = SilentPeer::new();
    let config = standard_config(MODEL);
    let mut provider = fixture_provider(&config, empty_store(), &silent.base);
    let prepared = manifest(&config, "goal: deny the absent material");

    match provider.send(&prepared) {
        Err(ProviderError::CredentialAbsent { scope }) => {
            assert!(!scope.is_empty());
        }
        other => panic!("expected the absent credential denial, got {other:?}"),
    }
    silent.assert_no_request();
}

#[test]
fn bedrock_partial_tool_block_and_unknown_terminal_deny() {
    let peer = scripted_peer(tool_stream("read_file", r#"{"path":"#, "tool_use"));
    let config = standard_config(MODEL);
    let mut provider = fixture_provider(&config, fixture_store(BEARER), &peer.base);
    let prepared = manifest(&config, "goal: deny the partial tool block");
    let error = provider
        .send(&prepared)
        .expect_err("the partial tool input is not complete at contentBlockStop");
    match error {
        ProviderError::StreamViolation { connection, reason } => {
            assert_eq!(connection, CONNECTION);
            assert!(
                reason.contains("tool block carries an incomplete json input"),
                "{reason}"
            );
        }
        other => panic!("expected the partial tool denial, got {other:?}"),
    }
    let _captured = peer.finish();

    let peer = scripted_peer(tool_stream("read_file", "{}", "not-a-recorded-stop"));
    let mut provider = fixture_provider(&config, fixture_store(BEARER), &peer.base);
    let prepared = manifest(&config, "goal: deny the unknown terminal");
    let error = provider
        .send(&prepared)
        .expect_err("the unknown stop reason is no success");
    assert!(
        matches!(error, ProviderError::UnknownTerminal { .. }),
        "expected the unknown terminal, got {error:?}"
    );
    let _captured = peer.finish();
}

#[test]
fn bedrock_missing_message_stop_denies() {
    let mut stream = Vec::new();
    stream.extend(frame(
        "event",
        "messageStart",
        &json!({"role": "assistant"}),
    ));
    stream.extend(frame(
        "event",
        "contentBlockStart",
        &json!({"contentBlockIndex": 0, "start": {}}),
    ));
    stream.extend(frame(
        "event",
        "contentBlockDelta",
        &json!({"contentBlockIndex": 0, "delta": {"text": "no terminal"}}),
    ));
    stream.extend(frame(
        "event",
        "contentBlockStop",
        &json!({"contentBlockIndex": 0}),
    ));
    let peer = scripted_peer(stream);
    let config = standard_config(MODEL);
    let mut provider = fixture_provider(&config, fixture_store(BEARER), &peer.base);
    let prepared = manifest(&config, "goal: deny the missing terminal");

    let error = provider
        .send(&prepared)
        .expect_err("a clean EOF without messageStop is no success");
    match error {
        ProviderError::UnknownTerminal { connection } => assert_eq!(connection, CONNECTION),
        other => panic!("expected the missing-terminal denial, got {other:?}"),
    }
    let _captured = peer.finish();
}

#[test]
fn bedrock_event_after_message_stop_denies() {
    let mut stream = Vec::new();
    stream.extend(frame(
        "event",
        "messageStart",
        &json!({"role": "assistant"}),
    ));
    stream.extend(frame(
        "event",
        "contentBlockStart",
        &json!({"contentBlockIndex": 0, "start": {}}),
    ));
    stream.extend(frame(
        "event",
        "contentBlockStop",
        &json!({"contentBlockIndex": 0}),
    ));
    stream.extend(frame(
        "event",
        "messageStop",
        &json!({"stopReason": "end_turn"}),
    ));
    stream.extend(frame(
        "event",
        "contentBlockStart",
        &json!({"contentBlockIndex": 1, "start": {}}),
    ));
    let peer = scripted_peer(stream);
    let config = standard_config(MODEL);
    let mut provider = fixture_provider(&config, fixture_store(BEARER), &peer.base);
    let prepared = manifest(&config, "goal: deny the event after the terminal");

    let error = provider
        .send(&prepared)
        .expect_err("a frame after messageStop is no success");
    match error {
        ProviderError::StreamViolation { connection, reason } => {
            assert_eq!(connection, CONNECTION);
            assert!(reason.contains("after messageStop"), "{reason}");
        }
        other => panic!("expected the post-terminal denial, got {other:?}"),
    }
    let _captured = peer.finish();
}

#[test]
fn bedrock_complete_tool_use_yields_a_tool_call() {
    let peer = scripted_peer(tool_stream(
        "read_file",
        r#"{"path":"src/main.rs"}"#,
        "tool_use",
    ));
    let config = standard_config(MODEL);
    let store = fixture_store(BEARER);
    let provider = fixture_provider(&config, store.clone(), &peer.base);
    let (mut broker, prepared) = prepared_with(
        (provider, store),
        &config,
        WORLD,
        "goal: surface the complete tool call",
    );

    let reply = broker
        .dispatch(&mut NullLedger, WORLD, &prepared)
        .expect("the complete tool block dispatches");
    assert!(reply.text.is_empty());
    assert_eq!(
        reply.tool_calls,
        vec![ToolCall {
            tool: "read_file".to_owned(),
            path: Some("src/main.rs".to_owned()),
        }]
    );
    assert_eq!(
        reply.usage,
        UsageDelta::Exact {
            prompt_tokens: 1,
            completion_tokens: 1,
            total_tokens: 2,
        }
    );
    assert_eq!(broker.accounted_requests(), 1);
    let record = broker
        .accounting_record(&prepared.attempt_id)
        .expect("the send is accounted");
    assert_eq!(record.connection, CONNECTION);
    assert_eq!(record.usage, reply.usage);
    let _captured = peer.finish();
}

#[test]
fn bedrock_undeclared_tool_denies() {
    let peer = scripted_peer(tool_stream(
        "write_file",
        r#"{"path":"src/main.rs"}"#,
        "tool_use",
    ));
    let config = standard_config(MODEL);
    let mut provider = fixture_provider(&config, fixture_store(BEARER), &peer.base);
    let prepared = manifest(&config, "goal: deny the undeclared tool");

    let error = provider
        .send(&prepared)
        .expect_err("a tool outside the declared set is no success");
    match error {
        ProviderError::IncompatibleOutput { connection, reason } => {
            assert_eq!(connection, CONNECTION);
            assert!(reason.contains("undeclared tool write_file"), "{reason}");
        }
        other => panic!("expected the undeclared-tool denial, got {other:?}"),
    }
    let _captured = peer.finish();
}

#[test]
fn bedrock_truncated_frame_denies() {
    let mut stream = valid_stream("truncated", 1, 1);
    stream.truncate(20);
    let peer = scripted_peer(stream);
    let config = standard_config(MODEL);
    let mut provider = fixture_provider(&config, fixture_store(BEARER), &peer.base);
    let prepared = manifest(&config, "goal: deny the truncated frame");

    let error = provider
        .send(&prepared)
        .expect_err("the truncated frame is no success");
    assert!(
        matches!(error, ProviderError::StreamViolation { .. }),
        "expected the truncation denial, got {error:?}"
    );
    let _captured = peer.finish();
}

#[test]
fn bedrock_oversized_frame_denies() {
    let oversized = u32::try_from(1024 * 1024 + 1).expect("the fixture length fits");
    let peer = scripted_peer(frame_prelude(oversized, 0));
    let config = standard_config(MODEL);
    let mut provider = fixture_provider(&config, fixture_store(BEARER), &peer.base);
    let prepared = manifest(&config, "goal: deny the oversized frame");

    let error = provider
        .send(&prepared)
        .expect_err("the oversized frame is no success");
    assert!(
        matches!(error, ProviderError::StreamViolation { .. }),
        "expected the oversized-frame denial, got {error:?}"
    );
    let _captured = peer.finish();
}

#[test]
fn bedrock_stream_split_inside_a_frame_is_sealed() {
    let stream = valid_stream("sealed across reads", 5, 6);
    let peer = split_peer(stream, 15);
    let config = standard_config(MODEL);
    let store = fixture_store(BEARER);
    let provider = fixture_provider(&config, store.clone(), &peer.base);
    let (mut broker, prepared) = prepared_with(
        (provider, store),
        &config,
        WORLD,
        "goal: seal the split frame",
    );

    let reply = broker
        .dispatch(&mut NullLedger, WORLD, &prepared)
        .expect("the split frame is buffered and sealed");
    assert_eq!(reply.text, "sealed across reads");
    assert_eq!(
        reply.usage,
        UsageDelta::Exact {
            prompt_tokens: 5,
            completion_tokens: 6,
            total_tokens: 11,
        }
    );
    assert_eq!(broker.accounted_requests(), 1);
    let record = broker
        .accounting_record(&prepared.attempt_id)
        .expect("the send is accounted");
    assert_eq!(record.connection, CONNECTION);
    assert_eq!(record.usage, reply.usage);
    let captured = peer.finish();
    assert!(!captured.body.is_empty());
}

#[test]
fn bedrock_exception_frame_is_a_peer_failure() {
    let mut stream = Vec::new();
    stream.extend(frame(
        "event",
        "messageStart",
        &json!({"role": "assistant"}),
    ));
    stream.extend(exception_frame(
        "validationException",
        "the peer rejected the request",
    ));
    let peer = scripted_peer(stream);
    let config = standard_config(MODEL);
    let mut provider = fixture_provider(&config, fixture_store(BEARER), &peer.base);
    let prepared = manifest(&config, "goal: deny the exception frame");

    let error = provider
        .send(&prepared)
        .expect_err("the exception frame is a peer failure");
    match error {
        ProviderError::ProviderFailed { connection, reason } => {
            assert_eq!(connection, CONNECTION);
            assert!(reason.contains("the peer rejected the request"), "{reason}");
        }
        other => panic!("expected the peer failure, got {other:?}"),
    }
    let _captured = peer.finish();
}

/// A peer exception message carrying terminal control bytes reaches the
/// diagnostic only as visible escapes, never as raw ESC.
#[test]
fn bedrock_exception_message_escapes_control_characters() {
    let mut stream = Vec::new();
    stream.extend(frame(
        "event",
        "messageStart",
        &json!({"role": "assistant"}),
    ));
    stream.extend(exception_frame(
        "validationException",
        "\u{1b}[31mhostile\u{7f}\u{9b}",
    ));
    let peer = scripted_peer(stream);
    let config = standard_config(MODEL);
    let mut provider = fixture_provider(&config, fixture_store(BEARER), &peer.base);
    let prepared = manifest(&config, "goal: escape the exception text");

    let error = provider
        .send(&prepared)
        .expect_err("the exception frame is a peer failure");
    let rendered = format!("{error} {error:?}");
    assert!(!rendered.contains('\u{1b}'), "{rendered}");
    assert!(
        rendered.contains("\\u{1b}[31mhostile\\u{7f}\\u{9b}"),
        "{rendered}"
    );
    let _captured = peer.finish();
}

#[test]
fn mantle_valid_control_yields_one_outcome_and_one_physical_usage() {
    let stream = responses_completed_stream(
        "mantle outcome",
        Vec::new(),
        Some(json!({"input_tokens": 11, "output_tokens": 7, "total_tokens": 18})),
    );
    let peer = mantle_peer("text/event-stream", "200 OK", stream.into_bytes());
    let config = mantle_config(MANTLE_MODEL, None);
    let store = mantle_store(BEARER);
    let provider = mantle_provider(&config, store.clone(), &peer.base);
    let (mut broker, prepared) = prepared_with(
        (provider, store),
        &config,
        MANTLE_WORLD,
        "goal: prove the mantle Responses wire",
    );

    let reply = broker
        .dispatch(&mut NullLedger, MANTLE_WORLD, &prepared)
        .expect("the verified mantle outcome dispatches");
    assert_eq!(reply.text, "mantle outcome");
    assert!(reply.tool_calls.is_empty());
    assert_eq!(
        reply.usage,
        UsageDelta::Exact {
            prompt_tokens: 11,
            completion_tokens: 7,
            total_tokens: 18,
        }
    );
    assert_eq!(broker.accounted_requests(), 1);
    let record = broker
        .accounting_record(&prepared.attempt_id)
        .expect("the send is accounted");
    assert_eq!(record.connection, MANTLE_CONNECTION);
    assert_eq!(record.usage, reply.usage);

    let captured = peer.finish();
    assert_eq!(captured.line, "POST /openai/v1/responses HTTP/1.1");
    let expected_auth = format!("Bearer {BEARER}");
    assert_eq!(
        captured.header("authorization"),
        Some(expected_auth.as_str())
    );
    let body = captured.json();
    assert_eq!(body["model"], json!(MANTLE_MODEL));
    assert_eq!(body["store"], json!(false));
    assert_eq!(body["stream"], json!(true));
    assert_eq!(body["include"], json!(["reasoning.encrypted_content"]));
    assert!(!String::from_utf8_lossy(&captured.body).contains(BEARER));
}

#[test]
fn mantle_base_builder_substitutes_the_resolved_region() {
    let config = mantle_config(MANTLE_MODEL, Some("eu-west-1"));
    let provider = OpenAiProvider::new(&config, MANTLE_CONNECTION, empty_store())
        .expect("the mantle adapter builds");
    assert_eq!(
        provider.resolved_base(),
        "https://bedrock-mantle.eu-west-1.api.aws/openai/v1"
    );
    assert_eq!(provider.resolved_base(), aws::mantle_base("eu-west-1"));
    assert_eq!(
        aws::mantle_base("eu-west-1"),
        "https://bedrock-mantle.eu-west-1.api.aws/openai/v1"
    );
    assert_eq!(
        aws::mantle_discovery_base("eu-west-1"),
        "https://bedrock-mantle.eu-west-1.api.aws/v1/models"
    );
    // Configured region wins over the material's and the ambient one;
    // the material region outranks ambient; with neither, the recorded
    // us-east-1 fallback stands.
    assert_eq!(
        aws::resolve_region(
            MANTLE_CONNECTION,
            MANTLE_MODEL,
            Some("eu-west-1"),
            Some("ap-south-1"),
            Some("us-east-1"),
        )
        .expect("the configured region answers"),
        "eu-west-1"
    );
    assert_eq!(
        aws::resolve_region(
            MANTLE_CONNECTION,
            MANTLE_MODEL,
            None,
            Some("ap-south-1"),
            Some("us-east-1"),
        )
        .expect("the material region answers"),
        "ap-south-1"
    );
    assert_eq!(
        aws::resolve_region(MANTLE_CONNECTION, MANTLE_MODEL, None, None, None)
            .expect("the recorded fallback answers"),
        "us-east-1"
    );
}

#[test]
fn mantle_pinned_geo_resolves_the_send_base() {
    // The geo pin is discovered under a loopback override; the send base
    // must follow that pin's own region, not the region assembly picked
    // for the non-geo seed.
    let model = "eu.openai.gpt-5.6-sol";
    let body = br#"{"data":[{"id":"eu.openai.gpt-5.6-sol"}]}"#;
    let peer = mantle_peer("application/json", "200 OK", body.to_vec());
    let config = mantle_config(model, None);
    let provider = mantle_provider(&config, mantle_store(BEARER), &peer.base);
    let listed = provider.catalog().expect("the listing answers");
    assert_eq!(listed, ["eu.openai.gpt-5.6-sol"]);
    let captured = peer.finish();
    assert_eq!(captured.line, "GET /v1/models HTTP/1.1");

    // No configured region and no base override: the pinned geo beats the
    // ambient us-east-1 that assembly used for the seed id.
    let provider = OpenAiProvider::new(&config, MANTLE_CONNECTION, empty_store())
        .expect("the mantle adapter builds")
        .with_mantle_ambient_region("us-east-1");
    assert_eq!(
        provider
            .mantle_send_base(model)
            .expect("the geo pin resolves"),
        "https://bedrock-mantle.eu-west-1.api.aws/openai/v1"
    );
    assert_ne!(
        provider
            .mantle_send_base(model)
            .expect("the geo pin resolves"),
        aws::mantle_base("us-east-1")
    );
    // The valid control: a non-geo pin under the same ambient posts to
    // the forced-ambient base.
    assert_eq!(
        provider
            .mantle_send_base("openai.gpt-5.6-sol")
            .expect("the control pin resolves"),
        "https://bedrock-mantle.us-east-1.api.aws/openai/v1"
    );
}

/// A geo-pinned mantle offer sends end-to-end: the captured host and
/// `/openai/v1/responses` path show the send reached the peer. The base the
/// pin resolves to is proven by `mantle_pinned_geo_resolves_the_send_base`.
#[test]
fn mantle_geo_pin_send_posts_to_its_resolved_base() {
    let model = "eu.openai.gpt-5.6-sol";
    let listing = br#"{"data":[{"id":"eu.openai.gpt-5.6-sol"}]}"#;
    let stream = responses_completed_stream(
        "geo mantle outcome",
        Vec::new(),
        Some(json!({"input_tokens": 2, "output_tokens": 1, "total_tokens": 3})),
    );
    let peer = mantle_sequence_peer(vec![
        ("application/json", "200 OK", listing.to_vec()),
        ("text/event-stream", "200 OK", stream.into_bytes()),
    ]);
    let config = mantle_config(model, None);
    let mut provider = mantle_provider(&config, mantle_store(BEARER), &peer.base);
    assert_eq!(
        provider.catalog().expect("the listing answers"),
        [model.to_string()]
    );

    let prepared = mantle_manifest(&config, "goal: send the geo-pinned offer");
    let reply = provider.send(&prepared).expect("the geo pin sends");
    assert_eq!(reply.text, "geo mantle outcome");
    assert_eq!(
        reply.usage,
        UsageDelta::Exact {
            prompt_tokens: 2,
            completion_tokens: 1,
            total_tokens: 3,
        }
    );

    let authority = peer
        .base
        .strip_prefix("http://")
        .expect("the loopback base is http")
        .to_string();
    let captured = peer.handle.join().expect("the sequence peer joins");
    assert_eq!(captured.requests.len(), 2);
    assert_eq!(captured.requests[0].line, "GET /v1/models HTTP/1.1");
    assert_eq!(
        captured.requests[1].line,
        "POST /openai/v1/responses HTTP/1.1"
    );
    assert_eq!(
        captured.requests[1].header("host"),
        Some(authority.as_str())
    );
    assert_eq!(captured.requests[1].json()["model"], json!(model));
    assert!(!captured.extra, "the geo send put bytes on the wrong leg");
}

#[test]
fn mantle_arm_declares_the_seed_and_discovery_policy() {
    assert_eq!(dialect_for(MANTLE_CONNECTION), Some(Dialect::Responses));
    let config = mantle_config(MANTLE_MODEL, None);
    let adapter = OpenAiProvider::new(&config, MANTLE_CONNECTION, empty_store())
        .expect("the mantle arm builds without a configured endpoint");
    assert!(!adapter.requires_configured_endpoint());
    assert!(adapter.declares_reasoning_artifact());

    // A failed listing keeps the recorded five-id seed without error.
    let peer = mantle_peer(
        "application/json",
        "500 Internal Server Error",
        b"{\"error\":\"listing unavailable\"}".to_vec(),
    );
    let provider = mantle_provider(&config, mantle_store(BEARER), &peer.base);
    let listed = provider.catalog().expect("a failed listing is non-fatal");
    assert_eq!(listed, MANTLE_SEED);
    let captured = peer.finish();
    assert_eq!(captured.line, "GET /v1/models HTTP/1.1");
}

#[test]
fn mantle_contract_declares_the_reasoning_artifact_and_no_configured_endpoint() {
    let config = mantle_config(MANTLE_MODEL, None);
    let provider = OpenAiProvider::new(&config, MANTLE_CONNECTION, empty_store())
        .expect("the mantle arm builds without a configured endpoint");
    assert!(provider.declares_reasoning_artifact());
    assert!(!provider.requires_configured_endpoint());
}

#[test]
fn mantle_discovery_replaces_the_seed_on_success() {
    let body = br#"{"data":[{"id":"openai.gpt-9-preview"},{"id":"openai.gpt-5.6-sol"},{"id":""}]}"#;
    let peer = mantle_peer("application/json", "200 OK", body.to_vec());
    let config = mantle_config(MANTLE_MODEL, None);
    let provider = mantle_provider(&config, mantle_store(BEARER), &peer.base);

    let listed = provider.catalog().expect("the listing answers");
    assert_eq!(listed, ["openai.gpt-5.6-sol", "openai.gpt-9-preview"]);
    assert!(!listed.contains(&"openai.gpt-5.4".to_string()));

    let captured = peer.finish();
    assert_eq!(captured.line, "GET /v1/models HTTP/1.1");
    let expected_auth = format!("Bearer {BEARER}");
    assert_eq!(
        captured.header("authorization"),
        Some(expected_auth.as_str())
    );
}

#[test]
fn mantle_empty_listing_is_authoritative() {
    // A 200 whose `data` is an array is a successful listing even when it
    // names no offer: entries without an id contribute nothing, and `[]`
    // means the peer serves no model — never the recorded seed.
    for body in [
        br#"{"data":[]}"#.as_slice(),
        br#"{"data":[{"object":"model"}]}"#.as_slice(),
    ] {
        let peer = mantle_sequence_peer(vec![("application/json", "200 OK", body.to_vec())]);
        let config = mantle_config(MANTLE_MODEL, None);
        let mut provider = mantle_provider(&config, mantle_store(BEARER), &peer.base);

        let listed = provider
            .catalog()
            .expect("an empty listing is not an error");
        assert!(listed.is_empty(), "{listed:?}");

        // Every pin is now outside the authoritative offer set, so the
        // seed id denies before any wire leg.
        let prepared = mantle_manifest(&config, "goal: deny a pin the empty listing omitted");
        match provider.send(&prepared) {
            Err(ProviderError::UnsupportedParameter {
                connection,
                parameter,
                model,
            }) => {
                assert_eq!(connection, MANTLE_CONNECTION);
                assert_eq!(parameter, "model");
                assert_eq!(model, MANTLE_MODEL);
            }
            other => panic!("expected the empty-listing denial, got {other:?}"),
        }

        let captured = peer.handle.join().expect("the sequence peer joins");
        assert_eq!(captured.requests.len(), 1);
        assert_eq!(captured.requests[0].line, "GET /v1/models HTTP/1.1");
        assert!(!captured.extra, "the denied pin put bytes on the wire");
    }
}

#[test]
fn mantle_listed_offer_gates_send() {
    let listing = br#"{"data":[{"id":"openai.gpt-9-preview"}]}"#;
    let stream = responses_completed_stream(
        "listed mantle outcome",
        Vec::new(),
        Some(json!({"input_tokens": 3, "output_tokens": 2, "total_tokens": 5})),
    );
    let peer = mantle_sequence_peer(vec![
        ("application/json", "200 OK", listing.to_vec()),
        ("text/event-stream", "200 OK", stream.into_bytes()),
    ]);
    let config = mantle_config(MANTLE_MODEL, None);
    let mut provider = mantle_provider(&config, mantle_store(BEARER), &peer.base);

    let listed = provider.catalog().expect("the listing answers");
    assert_eq!(listed, ["openai.gpt-9-preview"]);

    // The retained listing replaces the seed: the omitted seed id denies
    // before any wire leg.
    let omitted = "openai.gpt-5.4";
    let denied = mantle_manifest(
        &mantle_config(omitted, None),
        "goal: deny the id the successful listing omitted",
    );
    match provider.send(&denied) {
        Err(ProviderError::UnsupportedParameter {
            connection,
            parameter,
            model,
        }) => {
            assert_eq!(connection, MANTLE_CONNECTION);
            assert_eq!(parameter, "model");
            assert_eq!(model, omitted);
        }
        other => panic!("expected the retained-listing denial, got {other:?}"),
    }

    // The listed id is inside the retained offer and sends normally.
    let offered = mantle_manifest(
        &mantle_config("openai.gpt-9-preview", None),
        "goal: send the listed mantle offer",
    );
    let reply = provider.send(&offered).expect("the listed offer sends");
    assert_eq!(reply.text, "listed mantle outcome");
    assert_eq!(
        reply.usage,
        UsageDelta::Exact {
            prompt_tokens: 3,
            completion_tokens: 2,
            total_tokens: 5,
        }
    );

    let captured = peer.handle.join().expect("the sequence peer joins");
    assert_eq!(captured.requests.len(), 2);
    assert_eq!(captured.requests[0].line, "GET /v1/models HTTP/1.1");
    assert_eq!(
        captured.requests[1].line,
        "POST /openai/v1/responses HTTP/1.1"
    );
    assert_eq!(
        captured.requests[1].json()["model"],
        json!("openai.gpt-9-preview")
    );
    assert!(!captured.extra, "the denied pin put bytes on the wire");
}

#[test]
fn mantle_failed_discovery_keeps_the_seed() {
    let cases: [(&str, &[u8]); 3] = [
        ("500 Internal Server Error", b"{\"error\":\"down\"}"),
        ("200 OK", b"not json"),
        // A payload without the `data` array is not a listing; only a
        // missing/non-array carrier keeps the seed (the authoritative
        // empty-array case is its own test).
        ("200 OK", b"{\"object\":\"list\"}"),
    ];
    for (status, body) in cases {
        let peer = mantle_peer("application/json", status, body.to_vec());
        let config = mantle_config(MANTLE_MODEL, None);
        let provider = mantle_provider(&config, mantle_store(BEARER), &peer.base);
        let listed = provider.catalog().expect("a failed listing is non-fatal");
        assert_eq!(listed, MANTLE_SEED, "{status}");
        let captured = peer.finish();
        assert_eq!(captured.line, "GET /v1/models HTTP/1.1");
    }
}

#[test]
fn mantle_discovery_transport_failure_keeps_the_seed() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the closing mantle peer");
    let base = format!(
        "http://{}",
        listener.local_addr().expect("the peer address")
    );
    let handle = std::thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept one mantle request");
        // Closing without a response is a transport failure, not a listing.
        drop(stream);
    });
    let config = mantle_config(MANTLE_MODEL, None);
    let provider = mantle_provider(&config, mantle_store(BEARER), &base);

    let listed = provider.catalog().expect("a closed listing is non-fatal");
    assert_eq!(listed, MANTLE_SEED);
    handle.join().expect("the closing peer joins");
}

#[test]
fn mantle_oversized_discovery_listing_keeps_the_seed() {
    // A valid head followed by a body past the catalogue byte bound is a
    // failed discovery read: the listing never parses, so the seed stands.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the oversized mantle peer");
    let base = format!(
        "http://{}",
        listener.local_addr().expect("the peer address")
    );
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept one mantle request");
        let captured = read_request(&mut stream);
        // One byte past the 1 MiB catalogue bound.
        let body = vec![b' '; 1024 * 1024 + 1];
        let head = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\r\n",
            body.len()
        );
        // The client aborts at the bound and drops the socket, so the
        // trailing write may fail; the request is already captured.
        let _ = stream.write_all(head.as_bytes());
        let _ = stream.write_all(&body);
        let _ = stream.flush();
        captured
    });
    let config = mantle_config(MANTLE_MODEL, None);
    let provider = mantle_provider(&config, mantle_store(BEARER), &base);

    let listed = provider
        .catalog()
        .expect("an oversized listing is non-fatal");
    assert_eq!(listed, MANTLE_SEED);
    let captured = handle.join().expect("the oversized peer joins");
    assert_eq!(captured.line, "GET /v1/models HTTP/1.1");
}

#[test]
fn mantle_model_outside_the_offered_set_denies() {
    let silent = SilentPeer::new();
    let model = "openai.gpt-4.1";
    let config = mantle_config(model, None);
    let mut provider = mantle_provider(&config, mantle_store(BEARER), &silent.base);
    let prepared = mantle_manifest(&config, "goal: deny the unoffered mantle model");

    match provider.send(&prepared) {
        Err(ProviderError::UnsupportedParameter {
            connection,
            parameter,
            model: denied,
        }) => {
            assert_eq!(connection, MANTLE_CONNECTION);
            assert_eq!(parameter, "model");
            assert_eq!(denied, model);
        }
        other => panic!("expected the offer-set denial, got {other:?}"),
    }
    silent.assert_no_request();
}

#[test]
fn mantle_static_key_material_denies_as_blocked_class() {
    for material in [STATIC_MATERIAL, r#"{"access_key_id":"AKIDEXAMPLE"}"#] {
        let silent = SilentPeer::new();
        let config = mantle_config(MANTLE_MODEL, None);
        let mut provider = mantle_provider(&config, mantle_store(material), &silent.base);
        let prepared = mantle_manifest(&config, "goal: deny the mantle static key");

        let error = provider
            .send(&prepared)
            .expect_err("static-key SigV4 is blocked for mantle");
        let message = error.to_string();
        match error {
            ProviderError::UnsupportedCredentialClass { connection, class } => {
                assert_eq!(connection, MANTLE_CONNECTION);
                assert_eq!(class, "sigv4");
            }
            other => panic!("expected the blocked-class denial, got {other:?}"),
        }
        assert!(!message.contains(SECRET));
        silent.assert_no_request();
    }
}

#[test]
fn mantle_base_override_denies_non_loopback_and_ambiguous_urls() {
    let config = mantle_config(MANTLE_MODEL, None);
    let store: Arc<dyn CredentialStore> = mantle_store(BEARER);
    for base in [
        "https://api.aws/openai/v1",
        "http://user:pass@127.0.0.1:9/openai/v1",
        "http://127.0.0.1:9/openai/v1?query=1",
        "http://127.0.0.1:9/openai/v1#fragment",
        "not a url",
        "",
    ] {
        let error = OpenAiProvider::with_mantle_base_override(
            &config,
            MANTLE_CONNECTION,
            Arc::clone(&store),
            Duration::from_secs(5),
            Some(base.to_owned()),
        )
        .expect_err("the mantle override is not an admitted loopback endpoint");
        assert!(
            matches!(error, ProviderError::UnsendableRequest { .. }),
            "{base}: {error:?}"
        );
    }
}

#[test]
fn mantle_wrong_region_denies_without_secrets() {
    let silent = SilentPeer::new();
    // A geo-prefixed pin under a configured region outside its geo takes
    // the shared resolver's region gate before the offer gate.
    let model = "eu.openai.gpt-5.6-sol";
    let config = mantle_config(model, Some("us-east-1"));
    let mut provider = mantle_provider(&config, mantle_store(BEARER), &silent.base);
    let prepared = mantle_manifest(&config, "goal: deny the wrong mantle region");

    let error = provider
        .send(&prepared)
        .expect_err("the configured region cannot serve the pin's geo");
    let message = error.to_string();
    match error {
        ProviderError::RegionMismatch { connection, region } => {
            assert_eq!(connection, MANTLE_CONNECTION);
            assert_eq!(region, "us-east-1");
        }
        other => panic!("expected the region denial, got {other:?}"),
    }
    assert!(!message.contains(BEARER));
    silent.assert_no_request();
}
