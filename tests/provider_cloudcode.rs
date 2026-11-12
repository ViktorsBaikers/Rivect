//! CloudCode proof: the Antigravity envelope (AC-002, T2) and the Gemini
//! CLI projection (AC-003, T3). Each configured literal id — the
//! `google-antigravity` connection and the `google-gemini-cli` one —
//! returns one verified outcome through the standard Broker.
//!
//! Antigravity's wire class comes from the profile's pinned `classes` map
//! joined to the manifest model — never from the model name. The recorded
//! envelope posts to the profile origin's
//! `/v1internal:streamGenerateContent?alt=sse` with the bearer, the
//! `project`/`model`/`request`/`requestId`/`userAgent`/`requestType` top
//! level, the Antigravity role-tagged `systemInstruction`, the derived
//! `sessionId` and the recorded labels; the Gemini request builder supplies
//! the nested `contents`/`tools`/`generationConfig`.
//!
//! The Gemini CLI projection posts the same path to the recorded
//! `cloudcode-pa` origin only, with the recorded `GeminiCLI` user agent and
//! plugin metadata, the exact `project`/`model`/`request` top level, no
//! Antigravity-only field and the thinking config inside the nested
//! request. Its tier/project gate denies an unclassified tier or a blank
//! project before the post, and an Antigravity-shaped frame is a violation
//! for the id — a 403 stays a transport verdict, never a quota conclusion.
//!
//! The response contract is the shared Gemini codec's CloudCode leg: a
//! frame without `response` is skipped, content-only chunks accumulate
//! ahead of the terminal and usage, and a missing terminal, an in-band
//! error, a partial tool or an unknown finish reason is never success.
//! A wrong origin or profile denies typed with zero physical requests, one
//! failed settlement row and no accounting row; a positive send records
//! exactly one.
//!
//! TP-PROVIDER-INSTALLED::google-antigravity and ::google-gemini-cli stay
//! NOT_RUN: every leg here is a loopback peer, never a live call.

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

use rivect::config::Config;
use rivect::model::{Broker, ModelError, RequestManifest};
use rivect::providers::antigravity_login::{
    self, AntigravityEndpoints, CODE_ASSIST_ORIGIN, CODE_ASSIST_SANDBOX_ORIGIN,
};
use rivect::providers::cloudcode::{CloudCodeProvider, GeminiCliProvider};
use rivect::providers::gemini_cli_login::{
    self as code_assist, CODE_ASSIST_ORIGIN as GEMINI_CLI_ORIGIN, CodeAssistEndpoints,
};
use rivect::providers::{
    CredentialStore, Dialect, Provider, ProviderError, ProviderReply, SecretRef, StoreKind,
    TransportCause, TransportClass, dialect_for,
};
use rivect::resources::{Exactness, UsageDelta};
use rivect::state::{SettlementState, StoreLedger, TaskStore};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

mod support;

/// Print one offline receipt marker for a provider trial.
fn emit_provider_row(trial: &str, provider: &str) {
    println!(
        "ROW {} ok",
        rivect::verification::provider_case(trial, provider)
    );
}

use support::{CountingLedger, MapStore, SlowStore, prepared_with, received_bodies};

/// The literal connection id this adapter serves.
const ANTIGRAVITY: &str = "google-antigravity";
/// The credential profile the connection binds.
const PROFILE: &str = "google-antigravity";
/// The scoped credential ref the profile binds.
const CREDENTIAL_REF: &str = "keyring:rivect-test/google-antigravity";
/// Fixture material, never a real credential, only ever sent to localhost.
const TOKEN: &str = "fixture-antigravity-token-not-real";
const PROJECT: &str = "rvct-antigravity-project";
const STORE_KIND: StoreKind = StoreKind::Keychain;
const WORLD: &str = "/world/antigravity";
const INPUTS: &str = "goal: prove the antigravity wire";
/// The recorded signed-decimal session id `INPUTS` derives.
const INPUTS_SESSION_ID: &str = "-883841849234536203";
const SECOND_INPUTS: &str = "goal: continue the antigravity session";
const THIRD_INPUTS: &str = "goal: close the antigravity session";

/// The literal Gemini CLI connection id, its profile binding, scoped
/// credential ref and fixture material — never a real credential, only
/// ever sent to localhost.
const GEMINI_CLI: &str = "google-gemini-cli";
const GEMINI_CLI_PROFILE: &str = "google-gemini-cli";
const GEMINI_CLI_REF: &str = "keyring:rivect-test/google-gemini-cli";
const GEMINI_CLI_TOKEN: &str = "fixture-gemini-cli-token-not-real";
const GEMINI_CLI_PROJECT: &str = "rvct-gemini-cli-project";
const GEMINI_CLI_MODEL: &str = "gemini-2.5-pro";
const GEMINI_CLI_INPUTS: &str = "goal: prove the gemini cli wire";

/// The recorded Gemini CLI plugin identity every request states.
const CLIENT_METADATA: &str =
    "ideType=IDE_UNSPECIFIED,platform=PLATFORM_UNSPECIFIED,pluginType=GEMINI";

/// The three recorded classes, one pinned model each, plus the gpt-oss
/// entry's declared alternate id.
const GEMINI_MODEL: &str = "gemini-2.5-flash";
const ANTHROPIC_MODEL: &str = "claude-sonnet-4-5";
const GPT_OSS_MODEL: &str = "gpt-oss-120b";
const GPT_OSS_ALT_MODEL: &str = "gpt-oss-120b-medium";

/// The recorded request path the CloudCode stream rides.
const STREAM_PATH: &str = "/v1internal:streamGenerateContent";

/// One configured `google-antigravity` connection pointing at the fixture
/// peer: the profile binding resolves the scoped `SecretRef` (DEC-013) and
/// the dialect comes from the literal connection id.
fn antigravity_config(endpoint: &str, model: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.{ANTIGRAVITY}]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\ncredential_ref = \"{CREDENTIAL_REF}\"\nprofile = \"{PROFILE}\"\n\
         [profiles.{PROFILE}]\ncredential_ref = \"{CREDENTIAL_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"{ANTIGRAVITY}\", model_id = \"{model}\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    )
}

/// The stored account/project profile the login producer writes: the
/// token, the bound project and the pinned model-class map.
fn profile_json(classes: &[(&str, &str)]) -> String {
    let classes: serde_json::Map<String, Value> = classes
        .iter()
        .map(|(model, class)| ((*model).to_string(), json!(class)))
        .collect();
    json!({
        "access_token": TOKEN,
        "project": PROJECT,
        "classes": classes,
    })
    .to_string()
}

/// The corrected producer's artifact: all three recorded classes plus the
/// gpt-oss entry's declared alternate id.
fn pinned_profile() -> String {
    profile_json(&[
        (GEMINI_MODEL, "gemini"),
        (ANTHROPIC_MODEL, "anthropic"),
        (GPT_OSS_MODEL, "gpt-oss"),
        (GPT_OSS_ALT_MODEL, "gpt-oss"),
    ])
}

/// One request the loopback peer received.
#[derive(Clone)]
struct Seen {
    line: String,
    body: String,
}

/// A scripted loopback peer: one JSON answer per request, judged by the
/// test's own closure. It is a plain `std` listener because the login
/// producer runs `reqwest::blocking` on the test thread.
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
        body: String::from_utf8_lossy(&buffer[body_start..buffer.len()]).to_string(),
    })
}

/// reqwest's blocking client builds and drops a shell runtime inside
/// `wait::enter` — panicking in any tokio context (debug builds) — so
/// every adapter construction happens on a plain OS thread.
fn provider_result(
    config: Config,
    store: Arc<MapStore>,
) -> Result<CloudCodeProvider, ProviderError> {
    std::thread::spawn(move || CloudCodeProvider::new(&config, ANTIGRAVITY, store))
        .join()
        .expect("the provider thread joins")
}

fn provider_with_deadline(
    config: &Config,
    profile: &str,
    deadline: Duration,
) -> (CloudCodeProvider, Arc<MapStore>) {
    let store = Arc::new(MapStore::seeded(STORE_KIND, &[(CREDENTIAL_REF, profile)]));
    let handle = Arc::clone(&store);
    let config = config.clone();
    let provider = std::thread::spawn(move || {
        CloudCodeProvider::with_deadline(&config, ANTIGRAVITY, handle, deadline)
    })
    .join()
    .expect("the provider thread joins")
    .expect("the adapter builds for the literal id");
    (provider, store)
}

fn antigravity_provider(config: &Config, profile: &str) -> (CloudCodeProvider, Arc<MapStore>) {
    let store = Arc::new(MapStore::seeded(STORE_KIND, &[(CREDENTIAL_REF, profile)]));
    let provider = provider_result(config.clone(), Arc::clone(&store))
        .expect("the antigravity adapter builds for the literal id");
    (provider, store)
}

/// One configured `google-gemini-cli` connection pointing at the fixture
/// peer: the profile binding resolves the scoped `SecretRef` and the
/// dialect comes from the literal connection id.
fn gemini_cli_config(endpoint: &str, model: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.{GEMINI_CLI}]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\ncredential_ref = \"{GEMINI_CLI_REF}\"\nprofile = \"{GEMINI_CLI_PROFILE}\"\n\
         [profiles.{GEMINI_CLI_PROFILE}]\ncredential_ref = \"{GEMINI_CLI_REF}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"{GEMINI_CLI}\", model_id = \"{model}\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    )
}

/// The stored tier/project profile the Code Assist login producer writes.
fn gemini_cli_profile(project: &str, tier: &str) -> String {
    json!({
        "access_token": GEMINI_CLI_TOKEN,
        "project": project,
        "tier": tier,
    })
    .to_string()
}

fn gemini_cli_provider(config: &Config, profile: &str) -> (GeminiCliProvider, Arc<MapStore>) {
    let store = Arc::new(MapStore::seeded(STORE_KIND, &[(GEMINI_CLI_REF, profile)]));
    let handle = Arc::clone(&store);
    let config = config.clone();
    let provider = std::thread::spawn(move || GeminiCliProvider::new(&config, GEMINI_CLI, handle))
        .join()
        .expect("the provider thread joins")
        .expect("the gemini cli adapter builds for the literal id");
    (provider, store)
}

fn gemini_cli_provider_with_deadline(
    config: &Config,
    profile: &str,
    deadline: Duration,
) -> (GeminiCliProvider, Arc<MapStore>) {
    let store = Arc::new(MapStore::seeded(STORE_KIND, &[(GEMINI_CLI_REF, profile)]));
    let handle = Arc::clone(&store);
    let config = config.clone();
    let provider = std::thread::spawn(move || {
        GeminiCliProvider::with_deadline(&config, GEMINI_CLI, handle, deadline)
    })
    .join()
    .expect("the provider thread joins")
    .expect("the gemini cli adapter builds for the literal id");
    (provider, store)
}

/// The recorded Gemini CLI user agent in the client's Node platform and
/// architecture spellings.
fn expected_gemini_cli_user_agent(model: &str) -> String {
    let platform = match std::env::consts::OS {
        "macos" => "darwin",
        "windows" => "win32",
        platform => platform,
    };
    let arch = match std::env::consts::ARCH {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        arch => arch,
    };
    format!("GeminiCLI/0.46.0/{model} ({platform}; {arch}; terminal)")
}

/// One blocking dispatch on a plain OS thread: the provider's blocking
/// client must not run inside the fixture peer's tokio context.
fn dispatch(
    mut broker: Broker,
    mut ledger: CountingLedger,
    manifest: RequestManifest,
) -> (Broker, CountingLedger, Result<ProviderReply, ModelError>) {
    std::thread::spawn(move || {
        let outcome = broker.dispatch(&mut ledger, WORLD, &manifest);
        (broker, ledger, outcome)
    })
    .join()
    .expect("the dispatch thread joins")
}

/// One SSE response on the recorded resource path.
async fn mount_stream(server: &MockServer, body: String) {
    Mock::given(method("POST"))
        .and(path(STREAM_PATH))
        .and(query_param("alt", "sse"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(body),
        )
        .mount(server)
        .await;
}

/// The recorded CloudCode stream: a frame without `response` (skipped), a
/// content-only chunk carrying the response id, then the terminal chunk
/// with the finish reason and the usage report.
fn cloudcode_stream(
    text: &str,
    response_id: &str,
    prompt: u64,
    candidates: u64,
    cached: u64,
    thoughts: u64,
) -> String {
    format!(
        "data: {}\n\ndata: {}\n\ndata: {}\n\n",
        json!({"traceId": "trace-1"}),
        json!({"response": {
            "candidates": [{
                "content": {"role": "model", "parts": [{"text": text}]},
                "index": 0,
            }],
            "responseId": response_id,
        }}),
        json!({"response": {
            "candidates": [{
                "content": {"role": "model", "parts": []},
                "finishReason": "STOP",
                "index": 0,
            }],
            "usageMetadata": {
                "promptTokenCount": prompt,
                "candidatesTokenCount": candidates,
                "totalTokenCount": prompt + candidates + thoughts,
                "cachedContentTokenCount": cached,
                "thoughtsTokenCount": thoughts,
            },
        }}),
    )
}

fn header<'a>(request: &'a Request, name: &str) -> Option<&'a str> {
    request
        .headers
        .get(name)
        .and_then(|value| value.to_str().ok())
}

/// The request id is `agent/<uuid>/<millis>/<uuid>/<step>`; the label
/// trajectory is the third segment.
fn request_id_segments(body: &Value) -> Vec<&str> {
    body["requestId"]
        .as_str()
        .expect("the envelope names a request id")
        .split('/')
        .collect()
}

/// The `request` keys the Antigravity envelope records — no other member
/// rides the projection.
const REQUEST_KEYS: &[&str] = &[
    "contents",
    "generationConfig",
    "labels",
    "sessionId",
    "systemInstruction",
    "tools",
];

/// The full Antigravity envelope: the exact request line, the recorded
/// headers, the top-level fields, the Antigravity-only system role,
/// session id and labels, the nested Gemini request surface, and one
/// verified outcome with one accounting record.
#[tokio::test]
async fn antigravity_envelope_is_recorded() {
    emit_provider_row("WIRE", "google-antigravity");
    assert_eq!(dialect_for(ANTIGRAVITY), Some(Dialect::CloudCode));
    assert_eq!(Dialect::CloudCode.to_string(), "cloudcode");

    let server = MockServer::start().await;
    mount_stream(
        &server,
        cloudcode_stream("the recorded answer", "resp-1", 11, 7, 3, 2),
    )
    .await;
    let config =
        Config::parse_validated(&antigravity_config(&server.uri(), GEMINI_MODEL)).expect("valid");
    let (provider, store) = antigravity_provider(&config, &pinned_profile());
    let rendered = format!("{provider:?}");
    for secret in [TOKEN, PROJECT] {
        assert!(
            !rendered.contains(secret),
            "the adapter Debug never carries credential material"
        );
    }
    let (broker, manifest) = prepared_with((provider, store), &config, WORLD, INPUTS);
    let instructions = manifest.instructions.clone();
    let attempt_id = manifest.attempt_id.clone();
    let (broker, ledger, outcome) = dispatch(broker, CountingLedger::new(), manifest);
    let reply = outcome.expect("the recorded CloudCode send succeeds");
    assert_eq!(reply.text, "the recorded answer");
    assert_eq!(
        reply.usage,
        UsageDelta::from_reported(8, 9, 20, Some(2), Some(3), Some(0)),
        "the CloudCode usage legs are the recorded ones"
    );
    assert_eq!(ledger.begun, 1, "the send opened one settlement row");
    assert_eq!(ledger.finished, 1);
    assert_eq!(ledger.failed, 0);
    assert_eq!(
        broker.accounted_requests(),
        1,
        "one completed send records exactly one accounting row"
    );
    let record = broker
        .accounting_record(&attempt_id)
        .expect("the accounting row names the attempt");
    assert_eq!(record.usage, reply.usage);
    assert_eq!(
        record.connection, ANTIGRAVITY,
        "the accounting row names the send's connection"
    );

    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1, "one physical request per entered send");
    let request = &requests[0];
    assert_eq!(request.method.as_str(), "POST");
    assert_eq!(request.url.path(), STREAM_PATH);
    assert_eq!(request.url.query(), Some("alt=sse"));
    assert_eq!(
        header(request, "authorization"),
        Some(format!("Bearer {TOKEN}").as_str())
    );
    assert_eq!(header(request, "content-type"), Some("application/json"));
    assert_eq!(header(request, "accept"), Some("text/event-stream"));
    assert_eq!(header(request, "x-goog-api-key"), None);
    assert_eq!(
        header(request, "user-agent"),
        None,
        "no recorded Antigravity version exists to send, so the leg sends none"
    );

    let bodies = received_bodies(&server).await;
    let body = &bodies[0];
    let mut top: Vec<&str> = body
        .as_object()
        .expect("the envelope is an object")
        .keys()
        .map(String::as_str)
        .collect();
    top.sort_unstable();
    assert_eq!(
        top,
        [
            "model",
            "project",
            "request",
            "requestId",
            "requestType",
            "userAgent"
        ],
        "the top level is exactly the recorded envelope"
    );
    assert_eq!(body["project"], json!(PROJECT));
    assert_eq!(body["model"], json!(GEMINI_MODEL));
    assert_eq!(body["userAgent"], json!("antigravity"));
    assert_eq!(body["requestType"], json!("agent"));

    let request_body = &body["request"];
    let mut keys: Vec<&str> = request_body
        .as_object()
        .expect("the request is an object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys, REQUEST_KEYS,
        "the nested request carries the recorded keys"
    );
    assert_eq!(
        request_body["contents"],
        json!([{ "role": "user", "parts": [{ "text": INPUTS }] }]),
        "the Gemini builder's contents ride the nested request"
    );
    assert_eq!(
        request_body["systemInstruction"],
        json!({"parts": [{ "text": instructions }], "role": "user"}),
        "Antigravity tags the system instruction with role user"
    );
    assert_eq!(
        request_body["generationConfig"]["thinkingConfig"]["thinkingLevel"],
        json!("MEDIUM"),
        "the pinned effort stays inside the builder's generationConfig"
    );
    assert_eq!(
        request_body["tools"][0]["functionDeclarations"][0]["name"],
        json!("read_file"),
        "the declared tool surface rides functionDeclarations"
    );
    assert_eq!(
        request_body["sessionId"],
        json!(INPUTS_SESSION_ID),
        "the session id is the pinned signed decimal of the first user text"
    );

    let segments = request_id_segments(body);
    assert_eq!(segments.len(), 5);
    assert_eq!(segments[0], "agent");
    assert!(uuid::Uuid::parse_str(segments[1]).is_ok());
    assert!(segments[2].parse::<u64>().is_ok());
    assert!(uuid::Uuid::parse_str(segments[3]).is_ok());
    assert_eq!(segments[4], "2", "the first request is step 2");
    assert_eq!(
        request_body["labels"],
        json!({
            "last_step_index": "1",
            "trajectory_id": segments[3],
            "used_claude": "false",
            "used_claude_conservative": "false",
        }),
        "the first request carries exactly the recorded labels"
    );

    support::drop_blocking(broker);
}

/// Each recorded class reaches its own wire profile: the model rides the
/// envelope verbatim, the gpt-oss alternate id resolves through the same
/// pinned entry, and only the Anthropic class labels the request
/// `used_claude`.
#[tokio::test]
async fn three_classes_reach_their_recorded_wire_profiles() {
    for (model, used_claude) in [
        (GEMINI_MODEL, "false"),
        (ANTHROPIC_MODEL, "true"),
        (GPT_OSS_MODEL, "false"),
        (GPT_OSS_ALT_MODEL, "false"),
    ] {
        let server = MockServer::start().await;
        mount_stream(
            &server,
            cloudcode_stream("class answer", "resp-1", 4, 3, 0, 0),
        )
        .await;
        let config =
            Config::parse_validated(&antigravity_config(&server.uri(), model)).expect("valid");
        let (broker, manifest) = prepared_with(
            antigravity_provider(&config, &pinned_profile()),
            &config,
            WORLD,
            INPUTS,
        );
        let (broker, ledger, outcome) = dispatch(broker, CountingLedger::new(), manifest);
        let reply = outcome.expect("each recorded class sends");
        assert_eq!(reply.text, "class answer");
        assert_eq!(ledger.failed, 0);
        assert_eq!(broker.accounted_requests(), 1);

        let bodies = received_bodies(&server).await;
        assert_eq!(bodies.len(), 1, "{model} sends one physical request");
        assert_eq!(bodies[0]["model"], json!(model));
        let segments = request_id_segments(&bodies[0]);
        assert_eq!(
            bodies[0]["request"]["labels"],
            json!({
                "last_step_index": "1",
                "trajectory_id": segments[3],
                "used_claude": used_claude,
                "used_claude_conservative": used_claude,
            }),
            "{model} carries exactly the recorded labels"
        );
        support::drop_blocking(broker);
    }
}

/// The profile's class map decides, not the model name: a gemini-named id
/// mapped to `anthropic` labels the request `used_claude`, so a name
/// heuristic cannot pass.
#[tokio::test]
async fn the_pinned_map_not_the_model_name_decides_the_class() {
    let server = MockServer::start().await;
    mount_stream(
        &server,
        cloudcode_stream("map answer", "resp-1", 3, 2, 0, 0),
    )
    .await;
    let config =
        Config::parse_validated(&antigravity_config(&server.uri(), GEMINI_MODEL)).expect("valid");
    let contradicted = profile_json(&[
        (GEMINI_MODEL, "anthropic"),
        (ANTHROPIC_MODEL, "gemini"),
        (GPT_OSS_MODEL, "gpt-oss"),
    ]);
    let (broker, manifest) = prepared_with(
        antigravity_provider(&config, &contradicted),
        &config,
        WORLD,
        INPUTS,
    );
    let (broker, ledger, outcome) = dispatch(broker, CountingLedger::new(), manifest);
    let reply = outcome.expect("the contradictory map still sends");
    assert_eq!(reply.text, "map answer");
    assert_eq!(ledger.failed, 0);
    assert_eq!(broker.accounted_requests(), 1);

    let bodies = received_bodies(&server).await;
    assert_eq!(bodies.len(), 1);
    assert_eq!(bodies[0]["model"], json!(GEMINI_MODEL));
    let segments = request_id_segments(&bodies[0]);
    assert_eq!(
        bodies[0]["request"]["labels"],
        json!({
            "last_step_index": "1",
            "trajectory_id": segments[3],
            "used_claude": "true",
            "used_claude_conservative": "true",
        }),
        "the gemini-named id mapped to anthropic carries the anthropic labels"
    );
    support::drop_blocking(broker);
}

/// A model outside the pinned map — absent, or mapped to a class the
/// dialect never recorded — denies `ModelClassUnresolved` before the post:
/// zero requests, one failed settlement row and no accounting.
#[tokio::test]
async fn a_model_outside_the_pinned_class_map_denies_before_the_post() {
    let server = MockServer::start().await;
    for (model, profile) in [
        (ANTHROPIC_MODEL, profile_json(&[(GEMINI_MODEL, "gemini")])),
        (
            GEMINI_MODEL,
            profile_json(&[(GEMINI_MODEL, "unrecorded-class")]),
        ),
    ] {
        let config =
            Config::parse_validated(&antigravity_config(&server.uri(), model)).expect("valid");
        let (broker, manifest) = prepared_with(
            antigravity_provider(&config, &profile),
            &config,
            WORLD,
            INPUTS,
        );
        let (broker, ledger, outcome) = dispatch(broker, CountingLedger::new(), manifest);
        match outcome {
            Err(ModelError::Provider(ProviderError::ModelClassUnresolved {
                connection,
                model: denied,
            })) => {
                assert_eq!(connection, ANTIGRAVITY);
                assert_eq!(denied, model);
            }
            other => panic!("the unpinned class denies typed before the post: {other:?}"),
        }
        assert_eq!(ledger.begun, 1);
        assert_eq!(ledger.finished, 1);
        assert_eq!(ledger.failed, 1, "the entered send closes one failed row");
        assert_eq!(broker.accounted_requests(), 0);
        support::drop_blocking(broker);
    }
    assert_eq!(
        server.received_requests().await.expect("recorded").len(),
        0,
        "a class denial puts no request on the wire"
    );
}

/// Both ids refuse a configured region: the recorded class names none, so
/// construction denies `RegionMismatch` before any post and the fixture
/// peer never sees a request.
#[test]
fn a_configured_region_denies_both_ids_before_any_post() {
    let peer = Peer::start(|_seen| (200_u16, "{}".to_string()));
    let regioned = |raw: String| {
        Config::parse_validated(&raw.replace(
            "kind = \"api_key\"",
            "kind = \"api_key\"\nregion = \"us-central1\"",
        ))
        .expect("the regioned config parses")
    };
    let antigravity = regioned(antigravity_config(&peer.base, GEMINI_MODEL));
    let gemini_cli = regioned(gemini_cli_config(&peer.base, GEMINI_CLI_MODEL));

    let denied = CloudCodeProvider::new(
        &antigravity,
        ANTIGRAVITY,
        Arc::new(MapStore::seeded(
            STORE_KIND,
            &[(CREDENTIAL_REF, &pinned_profile())],
        )),
    )
    .expect_err("the antigravity id records no region");
    let ProviderError::RegionMismatch { connection, region } = &denied else {
        panic!("a configured region is the typed mismatch: {denied:?}");
    };
    assert_eq!(connection, ANTIGRAVITY);
    assert_eq!(region, "us-central1");

    let denied = GeminiCliProvider::new(
        &gemini_cli,
        GEMINI_CLI,
        Arc::new(MapStore::seeded(
            STORE_KIND,
            &[(
                GEMINI_CLI_REF,
                &gemini_cli_profile(GEMINI_CLI_PROJECT, "free-tier"),
            )],
        )),
    )
    .expect_err("the gemini cli id records no region");
    let ProviderError::RegionMismatch { connection, region } = &denied else {
        panic!("a configured region is the typed mismatch: {denied:?}");
    };
    assert_eq!(connection, GEMINI_CLI);
    assert_eq!(region, "us-central1");

    assert!(
        peer.requests().is_empty(),
        "a region denial puts no request on the wire"
    );
}

/// Each adapter serves only its literal id: the sibling id is a
/// `DialectMismatch`, an undeclared id on the recorded dialect is
/// `UnknownConnection`, `with_fallback` refuses a target outside the
/// recorded endpoint set, and `serves` answers only the adapter's own id.
#[test]
fn each_adapter_denies_the_sibling_identity() {
    let antigravity =
        Config::parse_validated(&antigravity_config("http://127.0.0.1:9", GEMINI_MODEL))
            .expect("valid");
    let gemini_cli =
        Config::parse_validated(&gemini_cli_config("http://127.0.0.1:9", GEMINI_CLI_MODEL))
            .expect("valid");
    let antigravity_store: Arc<dyn CredentialStore> = Arc::new(MapStore::seeded(
        STORE_KIND,
        &[(CREDENTIAL_REF, &pinned_profile())],
    ));
    let gemini_cli_store: Arc<dyn CredentialStore> = Arc::new(MapStore::seeded(
        STORE_KIND,
        &[(
            GEMINI_CLI_REF,
            &gemini_cli_profile(GEMINI_CLI_PROJECT, "free-tier"),
        )],
    ));

    let denied = CloudCodeProvider::new(&gemini_cli, GEMINI_CLI, Arc::clone(&antigravity_store))
        .expect_err("the gemini cli id is not this envelope's");
    assert!(
        matches!(
            denied,
            ProviderError::DialectMismatch { ref connection } if connection == GEMINI_CLI
        ),
        "the sibling id is a dialect mismatch: {denied:?}"
    );
    let denied = GeminiCliProvider::new(&antigravity, ANTIGRAVITY, Arc::clone(&gemini_cli_store))
        .expect_err("the antigravity id is not this projection's");
    assert!(
        matches!(
            denied,
            ProviderError::DialectMismatch { ref connection } if connection == ANTIGRAVITY
        ),
        "the sibling id is a dialect mismatch: {denied:?}"
    );

    // The literal id records the dialect but this config never declared
    // it: the denial is the undeclared connection, not the dialect.
    let denied = CloudCodeProvider::new(&gemini_cli, ANTIGRAVITY, Arc::clone(&antigravity_store))
        .expect_err("an undeclared connection never builds");
    assert!(
        matches!(
            denied,
            ProviderError::UnknownConnection { ref connection } if connection == ANTIGRAVITY
        ),
        "an undeclared id denies typed: {denied:?}"
    );
    let denied = GeminiCliProvider::new(&antigravity, GEMINI_CLI, Arc::clone(&gemini_cli_store))
        .expect_err("an undeclared connection never builds");
    assert!(
        matches!(
            denied,
            ProviderError::UnknownConnection { ref connection } if connection == GEMINI_CLI
        ),
        "an undeclared id denies typed: {denied:?}"
    );

    let provider =
        CloudCodeProvider::new(&antigravity, ANTIGRAVITY, Arc::clone(&antigravity_store))
            .expect("the antigravity adapter builds");
    let sibling_entry = gemini_cli
        .connections
        .get(GEMINI_CLI)
        .expect("the sibling connection is declared");
    assert!(!provider.serves(GEMINI_CLI, sibling_entry));
    assert!(
        provider.serves(
            ANTIGRAVITY,
            antigravity
                .connections
                .get(ANTIGRAVITY)
                .expect("the own connection is declared")
        )
    );
    let denied = provider
        .with_fallback("https://foreign.example.invalid")
        .expect_err("a foreign failover target never enters");
    assert!(
        matches!(denied, ProviderError::CredentialBaseMismatch { .. }),
        "a foreign target is outside the recorded endpoint set: {denied:?}"
    );
    let provider =
        CloudCodeProvider::new(&antigravity, ANTIGRAVITY, Arc::clone(&antigravity_store))
            .expect("the antigravity adapter builds")
            .with_fallback(CODE_ASSIST_SANDBOX_ORIGIN)
            .expect("the recorded sandbox target admits");

    let provider_cli = GeminiCliProvider::new(&gemini_cli, GEMINI_CLI, gemini_cli_store)
        .expect("the gemini cli adapter builds");
    let sibling_entry = antigravity
        .connections
        .get(ANTIGRAVITY)
        .expect("the sibling connection is declared");
    assert!(!provider_cli.serves(ANTIGRAVITY, sibling_entry));
    assert!(
        provider_cli.serves(
            GEMINI_CLI,
            gemini_cli
                .connections
                .get(GEMINI_CLI)
                .expect("the own connection is declared")
        )
    );

    support::drop_blocking(provider);
    support::drop_blocking(provider_cli);
}

/// Both recorded origins pass admission: an expired budget proves the
/// endpoint set without a live call, because an out-of-set origin denies
/// `CredentialBaseMismatch` before the budget check while an admitted one
/// reaches it with zero requests.
#[tokio::test]
async fn recorded_daily_and_sandbox_origins_are_admitted() {
    for origin in [CODE_ASSIST_ORIGIN, CODE_ASSIST_SANDBOX_ORIGIN] {
        // An expired budget proves admission: an out-of-set origin would
        // deny CredentialBaseMismatch before the budget check, while an
        // admitted one reaches the deadline with zero requests.
        let config =
            Config::parse_validated(&antigravity_config(origin, GEMINI_MODEL)).expect("valid");
        let (provider, store) = provider_with_deadline(&config, &pinned_profile(), Duration::ZERO);
        let (broker, manifest) = prepared_with((provider, store), &config, WORLD, INPUTS);
        let (broker, ledger, outcome) = dispatch(broker, CountingLedger::new(), manifest);
        match outcome {
            Err(ModelError::Provider(ProviderError::Transport { cause, .. })) => {
                assert_eq!(
                    cause.class(),
                    TransportClass::DeadlineExpired,
                    "{origin} passed origin admission and stopped at the budget"
                );
            }
            other => panic!("{origin} must reach the budget check, not the wire: {other:?}"),
        }
        assert_eq!(broker.accounted_requests(), 0);
        assert_eq!(ledger.failed, 1);
        support::drop_blocking(broker);
    }
}

/// The recorded failover: a transient first-attempt failure retries the
/// sandbox origin exactly once, and the successful send still records
/// exactly one accounting row for the connection.
#[tokio::test]
async fn a_transient_first_failure_falls_back_to_the_sandbox_origin_once() {
    emit_provider_row("RECOVERY", "google-antigravity");
    let daily = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(STREAM_PATH))
        .respond_with(ResponseTemplate::new(503))
        .mount(&daily)
        .await;
    let sandbox = MockServer::start().await;
    mount_stream(
        &sandbox,
        cloudcode_stream("sandbox answer", "resp-s", 6, 4, 1, 1),
    )
    .await;
    let config =
        Config::parse_validated(&antigravity_config(&daily.uri(), GEMINI_MODEL)).expect("valid");
    let (provider, store) = antigravity_provider(&config, &pinned_profile());
    let provider = provider
        .with_fallback(&sandbox.uri())
        .expect("the proof fallback admits");
    let (broker, manifest) = prepared_with((provider, store), &config, WORLD, INPUTS);
    let attempt_id = manifest.attempt_id.clone();
    let (broker, ledger, outcome) = dispatch(broker, CountingLedger::new(), manifest);
    let reply = outcome.expect("the fallback attempt answers");
    assert_eq!(reply.text, "sandbox answer");
    assert_eq!(reply.wire_retries, 1, "the fallback is the one retry");
    assert_eq!(
        reply.usage,
        UsageDelta::from_reported(5, 5, 11, Some(1), Some(1), Some(0))
    );
    assert_eq!(ledger.begun, 1, "one entered send opens one settlement row");
    assert_eq!(ledger.finished, 1);
    assert_eq!(ledger.failed, 0);
    assert_eq!(
        broker.accounted_requests(),
        1,
        "the successful fallback attempt yields exactly one accounting row"
    );
    let record = broker
        .accounting_record(&attempt_id)
        .expect("the accounting row names the attempt");
    assert_eq!(record.connection, ANTIGRAVITY);
    assert_eq!(record.usage, reply.usage);
    assert_eq!(
        daily.received_requests().await.expect("recorded").len(),
        1,
        "the daily origin is the first attempt"
    );
    assert_eq!(
        sandbox.received_requests().await.expect("recorded").len(),
        1,
        "the sandbox origin is the single fallback"
    );
    support::drop_blocking(broker);
}

/// The other recorded transient triggers: a refused daily connection
/// falls over before any stream starts, and a 429 first failure is the
/// rate-limit arm. Each success records exactly one accounting row.
#[tokio::test]
async fn a_refused_connection_and_a_429_fall_back_to_the_sandbox_origin_once() {
    // A loopback port bound then released: the first attempt is refused
    // rather than answered, which is the transport-failure arm.
    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
    let closed = format!(
        "http://{}",
        listener.local_addr().expect("the loopback address")
    );
    drop(listener);
    let sandbox = MockServer::start().await;
    mount_stream(
        &sandbox,
        cloudcode_stream("refused fallback", "resp-r", 6, 4, 1, 1),
    )
    .await;
    let config =
        Config::parse_validated(&antigravity_config(&closed, GEMINI_MODEL)).expect("valid");
    let (provider, store) = antigravity_provider(&config, &pinned_profile());
    let provider = provider
        .with_fallback(&sandbox.uri())
        .expect("the proof fallback admits");
    let (broker, manifest) = prepared_with((provider, store), &config, WORLD, INPUTS);
    let attempt_id = manifest.attempt_id.clone();
    let (broker, ledger, outcome) = dispatch(broker, CountingLedger::new(), manifest);
    let reply = outcome.expect("the sandbox attempt answers a refused daily connection");
    assert_eq!(reply.text, "refused fallback");
    assert_eq!(reply.wire_retries, 1, "the fallback is the one retry");
    assert_eq!(ledger.failed, 0);
    assert_eq!(
        broker.accounted_requests(),
        1,
        "the successful fallback attempt yields exactly one accounting row"
    );
    assert_eq!(
        broker
            .accounting_record(&attempt_id)
            .expect("the accounting row names the attempt")
            .connection,
        ANTIGRAVITY
    );
    assert_eq!(
        sandbox.received_requests().await.expect("recorded").len(),
        1,
        "the sandbox origin is the single fallback"
    );
    support::drop_blocking(broker);

    // A 429 first failure is the recorded rate-limit arm.
    let daily = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(STREAM_PATH))
        .respond_with(ResponseTemplate::new(429))
        .mount(&daily)
        .await;
    let sandbox = MockServer::start().await;
    mount_stream(
        &sandbox,
        cloudcode_stream("rate limit fallback", "resp-l", 2, 1, 0, 0),
    )
    .await;
    let config =
        Config::parse_validated(&antigravity_config(&daily.uri(), GEMINI_MODEL)).expect("valid");
    let (provider, store) = antigravity_provider(&config, &pinned_profile());
    let provider = provider
        .with_fallback(&sandbox.uri())
        .expect("the proof fallback admits");
    let (broker, manifest) = prepared_with((provider, store), &config, WORLD, INPUTS);
    let attempt_id = manifest.attempt_id.clone();
    let (broker, ledger, outcome) = dispatch(broker, CountingLedger::new(), manifest);
    let reply = outcome.expect("the sandbox attempt answers the 429");
    assert_eq!(reply.text, "rate limit fallback");
    assert_eq!(reply.wire_retries, 1, "one retry, never a second");
    assert_eq!(ledger.failed, 0);
    assert_eq!(
        broker.accounted_requests(),
        1,
        "the successful fallback attempt yields exactly one accounting row"
    );
    assert_eq!(
        broker
            .accounting_record(&attempt_id)
            .expect("the accounting row names the attempt")
            .connection,
        ANTIGRAVITY
    );
    assert_eq!(
        daily.received_requests().await.expect("recorded").len(),
        1,
        "the 429 is the first attempt"
    );
    assert_eq!(
        sandbox.received_requests().await.expect("recorded").len(),
        1,
        "the sandbox origin is the single fallback"
    );
    support::drop_blocking(broker);
}

/// Two transient failures are one typed error with no accounting: the
/// fallback is attempted once and never again.
#[tokio::test]
async fn a_double_transient_failure_is_one_error_with_no_accounting() {
    let daily = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(STREAM_PATH))
        .respond_with(ResponseTemplate::new(503))
        .mount(&daily)
        .await;
    let sandbox = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(STREAM_PATH))
        .respond_with(ResponseTemplate::new(502))
        .mount(&sandbox)
        .await;
    let config =
        Config::parse_validated(&antigravity_config(&daily.uri(), GEMINI_MODEL)).expect("valid");
    let (provider, store) = antigravity_provider(&config, &pinned_profile());
    let provider = provider
        .with_fallback(&sandbox.uri())
        .expect("the proof fallback admits");
    let (broker, manifest) = prepared_with((provider, store), &config, WORLD, INPUTS);
    let (broker, ledger, outcome) = dispatch(broker, CountingLedger::new(), manifest);
    match outcome {
        Err(ModelError::Provider(ProviderError::Transport { cause, .. })) => assert_eq!(
            cause.class(),
            TransportClass::HttpStatus { code: 502 },
            "the retry's own failure class is the one error"
        ),
        other => panic!("the double failure is one typed error: {other:?}"),
    }
    assert_eq!(ledger.begun, 1);
    assert_eq!(ledger.finished, 1);
    assert_eq!(ledger.failed, 1);
    assert_eq!(broker.accounted_requests(), 0);
    assert_eq!(daily.received_requests().await.expect("recorded").len(), 1);
    assert_eq!(
        sandbox.received_requests().await.expect("recorded").len(),
        1
    );
    support::drop_blocking(broker);
}

/// The fallback is narrower than any retry: a non-transient status never
/// fails over, and a failure after content was observed never fails over.
#[tokio::test]
async fn a_non_transient_or_after_content_failure_never_falls_back() {
    let daily = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(STREAM_PATH))
        .respond_with(ResponseTemplate::new(403))
        .mount(&daily)
        .await;
    let sandbox = MockServer::start().await;
    mount_stream(
        &sandbox,
        cloudcode_stream("never sent", "resp-x", 1, 1, 0, 0),
    )
    .await;
    let config =
        Config::parse_validated(&antigravity_config(&daily.uri(), GEMINI_MODEL)).expect("valid");
    let (provider, store) = antigravity_provider(&config, &pinned_profile());
    let provider = provider
        .with_fallback(&sandbox.uri())
        .expect("the proof fallback admits");
    let (broker, manifest) = prepared_with((provider, store), &config, WORLD, INPUTS);
    let (broker, ledger, outcome) = dispatch(broker, CountingLedger::new(), manifest);
    match outcome {
        Err(ModelError::Provider(ProviderError::Transport { cause, .. })) => assert_eq!(
            cause.class(),
            TransportClass::HttpStatus { code: 403 },
            "the peer's non-transient verdict is returned unchanged"
        ),
        other => panic!("a 403 never falls back: {other:?}"),
    }
    assert_eq!(ledger.failed, 1);
    assert_eq!(broker.accounted_requests(), 0);
    assert_eq!(daily.received_requests().await.expect("recorded").len(), 1);
    assert_eq!(
        sandbox.received_requests().await.expect("recorded").len(),
        0,
        "the sandbox origin is never attempted after a non-transient status"
    );
    support::drop_blocking(broker);

    // A stream that starts and carries content before failing is past the
    // failover point: the sandbox origin is never attempted.
    let daily = MockServer::start().await;
    let content_then_end = format!(
        "data: {}\n\n",
        json!({"response": {
            "candidates": [{
                "content": {"role": "model", "parts": [{"text": "observed"}]},
                "index": 0,
            }],
        }}),
    );
    mount_stream(&daily, content_then_end).await;
    let sandbox = MockServer::start().await;
    mount_stream(
        &sandbox,
        cloudcode_stream("never sent", "resp-x", 1, 1, 0, 0),
    )
    .await;
    let config =
        Config::parse_validated(&antigravity_config(&daily.uri(), GEMINI_MODEL)).expect("valid");
    let (provider, store) = antigravity_provider(&config, &pinned_profile());
    let provider = provider
        .with_fallback(&sandbox.uri())
        .expect("the proof fallback admits");
    let (broker, manifest) = prepared_with((provider, store), &config, WORLD, INPUTS);
    let (broker, ledger, outcome) = dispatch(broker, CountingLedger::new(), manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::UnknownTerminal { .. }))
        ),
        "content without a terminal is a stream verdict: {outcome:?}"
    );
    assert_eq!(ledger.failed, 1);
    assert_eq!(broker.accounted_requests(), 0);
    assert_eq!(daily.received_requests().await.expect("recorded").len(), 1);
    assert_eq!(
        sandbox.received_requests().await.expect("recorded").len(),
        0,
        "the sandbox origin is never attempted after content"
    );
    support::drop_blocking(broker);
}

/// A loopback peer that reads one request's line and aborts the
/// connection without answering: the client handed the request off, and
/// the peer sent no response bytes. The read line proves the hand-off.
fn abort_after_the_request_line() -> (String, std::thread::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback peer");
    let address = listener.local_addr().expect("the peer address");
    let handle = std::thread::spawn(move || {
        let (stream, _) = listener.accept().expect("the daily peer accepts");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("the peer read timeout");
        let mut line = String::new();
        BufReader::new(stream.try_clone().expect("the peer reads"))
            .read_line(&mut line)
            .expect("the request line crosses before the abort");
        // The abortive close reaches the client as a mid-request death:
        // the request bytes are gone, the response never starts.
        stream
            .shutdown(std::net::Shutdown::Both)
            .expect("the peer aborts");
        line
    });
    (format!("http://{address}"), handle)
}

/// The narrowed failover: a daily POST that was handed off and then
/// aborted may have reached the daily origin, so it never re-POSTs the
/// body to the sandbox. The entered send settles unknown with no crossed
/// retry.
#[tokio::test]
async fn a_request_aborted_after_hand_off_never_falls_back() {
    let (daily, peer) = abort_after_the_request_line();
    let sandbox = MockServer::start().await;
    mount_stream(
        &sandbox,
        cloudcode_stream("never sent", "resp-x", 1, 1, 0, 0),
    )
    .await;
    let config = Config::parse_validated(&antigravity_config(&daily, GEMINI_MODEL)).expect("valid");
    let (provider, store) = antigravity_provider(&config, &pinned_profile());
    let provider = provider
        .with_fallback(&sandbox.uri())
        .expect("the proof fallback admits");
    let (broker, manifest) = prepared_with((provider, store), &config, WORLD, INPUTS);
    let attempt_id = manifest.attempt_id.clone();
    let root = tempfile::TempDir::with_prefix("rivect-cloudcode-abort-").expect("fixture root");
    let db = root.path().join("state.db");
    let (store, outcome) = std::thread::spawn(move || {
        let mut store = TaskStore::open(&db).expect("store opens");
        let mut ledger = StoreLedger::new(&mut store, Vec::new());
        let mut broker = broker;
        let outcome = broker.dispatch(&mut ledger, WORLD, &manifest);
        (store, outcome)
    })
    .join()
    .expect("the dispatch thread joins");
    match outcome {
        Err(ModelError::Provider(ProviderError::Transport { cause, .. })) => {
            assert_eq!(
                cause.class(),
                TransportClass::RequestFailure,
                "an aborted send is a request failure, not a timeout"
            );
            let TransportCause::Request { source } = &cause else {
                panic!("the abort keeps its request cause: {cause:?}");
            };
            assert!(
                !source.is_connect() && !source.is_builder(),
                "the handed-off failure is no safe pre-stream class"
            );
        }
        other => panic!("the abort is one typed transport failure: {other:?}"),
    }
    assert_eq!(
        sandbox.received_requests().await.expect("recorded").len(),
        0,
        "the sandbox origin is never attempted when the daily leg may have applied"
    );
    let line = peer.join().expect("the daily peer joins");
    assert!(
        line.starts_with("POST /v1internal:streamGenerateContent"),
        "the daily POST crossed before the abort: {line:?}"
    );
    let row = store
        .settlement(&attempt_id)
        .expect("the entered failure settles");
    assert_eq!(row.state, SettlementState::Settled);
    assert_eq!(
        row.wire_retries, 0,
        "a non-failover failure crossed exactly one leg"
    );
    assert_eq!(row.exactness, Exactness::Unknown);
    assert_eq!(row.unknown_reason.as_deref(), Some("send failed"));
    assert_eq!(
        row.bins.total_tokens, None,
        "a failed send reports no usage, never zero"
    );
}

/// A loopback peer that accepts one request and never answers it: the
/// attempt is handed off and then times out. The thread ends when the
/// client closes the timed-out connection.
fn never_answer() -> (String, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback peer");
    let address = listener.local_addr().expect("the peer address");
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("the daily peer accepts");
        let mut sink = [0_u8; 4096];
        while let Ok(read) = stream.read(&mut sink) {
            if read == 0 {
                return;
            }
        }
    });
    (format!("http://{address}"), handle)
}

/// A loopback peer that answers headers and one content frame, then
/// stalls its body until the client's timeout closes the connection.
fn stall_after_one_event() -> (String, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback peer");
    let address = listener.local_addr().expect("the peer address");
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("the daily peer accepts");
        let mut head = Vec::new();
        let mut chunk = [0_u8; 4096];
        while head
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .is_none()
        {
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => return,
                Ok(read) => head.extend_from_slice(&chunk[..read]),
            }
        }
        let frame = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\nconnection: close\r\n\r\ndata: {}\n\n",
            json!({"response": {
                "candidates": [{
                    "content": {"role": "model", "parts": [{"text": "partial"}]},
                    "index": 0,
                }],
            }}),
        );
        if stream.write_all(frame.as_bytes()).is_err() {
            return;
        }
        let mut sink = [0_u8; 4096];
        while let Ok(read) = stream.read(&mut sink) {
            if read == 0 {
                return;
            }
        }
    });
    (format!("http://{address}"), handle)
}

/// A loopback peer that answers headers and one content frame at once,
/// then one terminal frame after `terminal_after`: a stream that would
/// complete inside a whole deadline but past one attempt's share.
fn slow_completing_stream(terminal_after: Duration) -> (String, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback peer");
    let address = listener.local_addr().expect("the peer address");
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("the daily peer accepts");
        let mut head = Vec::new();
        let mut chunk = [0_u8; 4096];
        while head
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .is_none()
        {
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => return,
                Ok(read) => head.extend_from_slice(&chunk[..read]),
            }
        }
        let opened = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\nconnection: close\r\n\r\ndata: {}\n\n",
            json!({"response": {
                "candidates": [{
                    "content": {"role": "model", "parts": [{"text": "slow"}]},
                    "index": 0,
                }],
            }}),
        );
        if stream.write_all(opened.as_bytes()).is_err() {
            return;
        }
        std::thread::sleep(terminal_after);
        let terminal = format!(
            "data: {}\n\n",
            json!({"response": {
                "candidates": [{
                    "content": {"role": "model", "parts": []},
                    "finishReason": "STOP",
                    "index": 0,
                }],
                "usageMetadata": {
                    "promptTokenCount": 1,
                    "candidatesTokenCount": 1,
                    "totalTokenCount": 2,
                },
            }}),
        );
        // The client may already have timed out; the thread ends either way.
        let _written = stream.write_all(terminal.as_bytes());
    });
    (format!("http://{address}"), handle)
}

/// A loopback peer that keeps one valid stream breathing: a content frame
/// at once, then one every `drip`, and the terminal at `terminal_after`.
/// Every gap stays under one attempt's share, so a per-read window never
/// fires and only a total attempt timeout can cut the stream.
fn live_drip_stream(
    drip: Duration,
    terminal_after: Duration,
) -> (String, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback peer");
    let address = listener.local_addr().expect("the peer address");
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("the daily peer accepts");
        let mut head = Vec::new();
        let mut chunk = [0_u8; 4096];
        while head
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .is_none()
        {
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => return,
                Ok(read) => head.extend_from_slice(&chunk[..read]),
            }
        }
        let frame = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\nconnection: close\r\n\r\ndata: {}\n\n",
            json!({"response": {
                "candidates": [{
                    "content": {"role": "model", "parts": [{"text": "live"}]},
                    "index": 0,
                }],
            }}),
        );
        if stream.write_all(frame.as_bytes()).is_err() {
            return;
        }
        let mut written = Duration::ZERO;
        while written + drip <= terminal_after {
            std::thread::sleep(drip);
            written += drip;
            if stream.write_all(frame.as_bytes()).is_err() {
                return;
            }
        }
        if terminal_after > written {
            std::thread::sleep(terminal_after - written);
        }
        let terminal = format!(
            "data: {}\n\n",
            json!({"response": {
                "candidates": [{
                    "content": {"role": "model", "parts": []},
                    "finishReason": "STOP",
                    "index": 0,
                }],
                "usageMetadata": {
                    "promptTokenCount": 1,
                    "candidatesTokenCount": 1,
                    "totalTokenCount": 2,
                },
            }}),
        );
        // The client may already have timed out; the thread ends either way.
        let _written = stream.write_all(terminal.as_bytes());
    });
    (format!("http://{address}"), handle)
}

/// The recorded failover inside one deadline: a daily origin that accepts
/// the request and never answers spends exactly its share of the budget,
/// then the one retry answers and the whole send stays inside the
/// deadline. The single-attempt share is the price of that reachability.
#[tokio::test]
async fn a_stalled_origin_times_out_once_and_fails_over_inside_the_deadline() {
    let deadline = Duration::from_secs(4);
    let (daily, peer) = never_answer();
    let sandbox = MockServer::start().await;
    mount_stream(
        &sandbox,
        cloudcode_stream("sandbox answer", "resp-s", 6, 4, 1, 1),
    )
    .await;
    let config = Config::parse_validated(&antigravity_config(&daily, GEMINI_MODEL)).expect("valid");
    let (provider, store) = provider_with_deadline(&config, &pinned_profile(), deadline);
    let provider = provider
        .with_fallback(&sandbox.uri())
        .expect("the proof fallback admits");
    let (broker, manifest) = prepared_with((provider, store), &config, WORLD, INPUTS);
    let started = Instant::now();
    let (broker, ledger, outcome) = dispatch(broker, CountingLedger::new(), manifest);
    let elapsed = started.elapsed();
    let reply = outcome.expect("the sandbox attempt answers the stalled daily origin");
    assert_eq!(reply.text, "sandbox answer");
    assert_eq!(reply.wire_retries, 1, "one retry, never a second");
    assert!(
        elapsed >= deadline / 2,
        "the stalled attempt spent its whole share: {elapsed:?}"
    );
    assert!(
        elapsed < deadline,
        "the timed-out attempt and its retry stay inside one deadline: {elapsed:?}"
    );
    assert_eq!(ledger.begun, 1, "one entered send opens one settlement row");
    assert_eq!(ledger.finished, 1);
    assert_eq!(ledger.failed, 0);
    assert_eq!(
        broker.accounted_requests(),
        1,
        "the answering retry yields exactly one accounting row"
    );
    assert_eq!(
        sandbox.received_requests().await.expect("recorded").len(),
        1,
        "the sandbox origin is the single retry"
    );
    peer.join().expect("the daily peer joins");
    support::drop_blocking(broker);
}

/// A stream that stalls after its first frame is a read-stage failure, not
/// a transient hand-off: it never fails over, and the half-budget attempt
/// bound cuts it there instead of letting it consume the whole deadline.
#[tokio::test]
async fn a_read_stage_timeout_never_fails_over() {
    let deadline = Duration::from_secs(4);
    let (daily, peer) = stall_after_one_event();
    let sandbox = MockServer::start().await;
    mount_stream(
        &sandbox,
        cloudcode_stream("never sent", "resp-x", 1, 1, 0, 0),
    )
    .await;
    let config = Config::parse_validated(&antigravity_config(&daily, GEMINI_MODEL)).expect("valid");
    let (provider, store) = provider_with_deadline(&config, &pinned_profile(), deadline);
    let provider = provider
        .with_fallback(&sandbox.uri())
        .expect("the proof fallback admits");
    let (broker, manifest) = prepared_with((provider, store), &config, WORLD, INPUTS);
    let attempt_id = manifest.attempt_id.clone();
    let root =
        tempfile::TempDir::with_prefix("rivect-cloudcode-read-stall-").expect("fixture root");
    let db = root.path().join("state.db");
    let started = Instant::now();
    let (store, outcome) = std::thread::spawn(move || {
        let mut store = TaskStore::open(&db).expect("store opens");
        let mut ledger = StoreLedger::new(&mut store, Vec::new());
        let mut broker = broker;
        let outcome = broker.dispatch(&mut ledger, WORLD, &manifest);
        (store, outcome)
    })
    .join()
    .expect("the dispatch thread joins");
    let elapsed = started.elapsed();
    match outcome {
        Err(ModelError::Provider(ProviderError::Transport { cause, .. })) => {
            assert_eq!(
                cause.class(),
                TransportClass::Timeout,
                "the stalled body keeps the timeout class"
            );
            assert!(
                matches!(cause, TransportCause::Read { .. }),
                "the failure is a body read, not a hand-off: {cause:?}"
            );
        }
        other => panic!("the stalled stream is one typed transport failure: {other:?}"),
    }
    assert_eq!(
        sandbox.received_requests().await.expect("recorded").len(),
        0,
        "a read-stage failure never re-POSTs the body"
    );
    let row = store
        .settlement(&attempt_id)
        .expect("the entered failure settles");
    assert_eq!(row.state, SettlementState::Settled);
    assert_eq!(
        row.wire_retries, 0,
        "the stream crossed one leg and no retry followed"
    );
    assert!(
        elapsed >= deadline / 2 && elapsed < deadline,
        "the half-share attempt bound cuts the stall: {elapsed:?}"
    );
    peer.join().expect("the daily peer joins");
}

/// The split's cost, pinned: a reply that would finish inside the whole
/// deadline but past one attempt's share is cut at the request timeout, and
/// no retry follows because a read-stage failure never fails over. The
/// former whole-deadline client admitted this stream.
#[tokio::test]
async fn a_stream_past_the_attempt_share_is_cut_inside_the_deadline() {
    let deadline = Duration::from_secs(4);
    let (daily, peer) = slow_completing_stream(Duration::from_millis(3000));
    let sandbox = MockServer::start().await;
    mount_stream(
        &sandbox,
        cloudcode_stream("never sent", "resp-x", 1, 1, 0, 0),
    )
    .await;
    let config = Config::parse_validated(&antigravity_config(&daily, GEMINI_MODEL)).expect("valid");
    let (provider, store) = provider_with_deadline(&config, &pinned_profile(), deadline);
    let provider = provider
        .with_fallback(&sandbox.uri())
        .expect("the proof fallback admits");
    let (broker, manifest) = prepared_with((provider, store), &config, WORLD, INPUTS);
    let attempt_id = manifest.attempt_id.clone();
    let root = tempfile::TempDir::with_prefix("rivect-cloudcode-share-cut-").expect("fixture root");
    let db = root.path().join("state.db");
    let started = Instant::now();
    let (store, outcome) = std::thread::spawn(move || {
        let mut store = TaskStore::open(&db).expect("store opens");
        let mut ledger = StoreLedger::new(&mut store, Vec::new());
        let mut broker = broker;
        let outcome = broker.dispatch(&mut ledger, WORLD, &manifest);
        (store, outcome)
    })
    .join()
    .expect("the dispatch thread joins");
    let elapsed = started.elapsed();
    match outcome {
        Err(ModelError::Provider(ProviderError::Transport { cause, .. })) => {
            assert_eq!(
                cause.class(),
                TransportClass::Timeout,
                "the share cut is the timeout class"
            );
            assert!(
                matches!(cause, TransportCause::Read { .. }),
                "the cut lands mid-stream: {cause:?}"
            );
        }
        other => panic!("the share cut is one typed transport failure: {other:?}"),
    }
    assert!(
        elapsed >= deadline / 2 && elapsed < deadline,
        "the attempt is cut at its share, inside the deadline: {elapsed:?}"
    );
    assert_eq!(
        sandbox.received_requests().await.expect("recorded").len(),
        0,
        "a read-stage failure never re-POSTs the body"
    );
    let row = store
        .settlement(&attempt_id)
        .expect("the entered failure settles");
    assert_eq!(
        row.wire_retries, 0,
        "the stream crossed one leg and no retry followed"
    );
    peer.join().expect("the slow peer joins");
}

/// A valid stream that keeps breathing past one attempt's share: frames
/// arrive well under the share, so a per-read window never fires, and the
/// terminal lands past the share but inside the deadline. Only the
/// request-level total cuts the send, with no retry after the read started.
#[tokio::test]
async fn a_live_drip_past_the_attempt_share_is_cut_by_the_total_timeout() {
    let deadline = Duration::from_secs(4);
    let (daily, peer) = live_drip_stream(Duration::from_millis(400), Duration::from_millis(2600));
    let sandbox = MockServer::start().await;
    mount_stream(
        &sandbox,
        cloudcode_stream("never sent", "resp-x", 1, 1, 0, 0),
    )
    .await;
    let config = Config::parse_validated(&antigravity_config(&daily, GEMINI_MODEL)).expect("valid");
    let (provider, store) = provider_with_deadline(&config, &pinned_profile(), deadline);
    let provider = provider
        .with_fallback(&sandbox.uri())
        .expect("the proof fallback admits");
    let (broker, manifest) = prepared_with((provider, store), &config, WORLD, INPUTS);
    let attempt_id = manifest.attempt_id.clone();
    let root = tempfile::TempDir::with_prefix("rivect-cloudcode-live-drip-").expect("fixture root");
    let db = root.path().join("state.db");
    let started = Instant::now();
    let (store, outcome) = std::thread::spawn(move || {
        let mut store = TaskStore::open(&db).expect("store opens");
        let mut ledger = StoreLedger::new(&mut store, Vec::new());
        let mut broker = broker;
        let outcome = broker.dispatch(&mut ledger, WORLD, &manifest);
        (store, outcome)
    })
    .join()
    .expect("the dispatch thread joins");
    let elapsed = started.elapsed();
    match outcome {
        Err(ModelError::Provider(ProviderError::Transport { cause, .. })) => {
            assert_eq!(
                cause.class(),
                TransportClass::Timeout,
                "the total attempt bound is the timeout class"
            );
            assert!(
                matches!(cause, TransportCause::Read { .. }),
                "the cut lands mid-stream: {cause:?}"
            );
        }
        other => panic!("the live drip is one typed transport failure: {other:?}"),
    }
    assert!(
        elapsed >= deadline / 2 && elapsed < deadline,
        "each read stayed inside the share; the total cuts the send: {elapsed:?}"
    );
    assert_eq!(
        sandbox.received_requests().await.expect("recorded").len(),
        0,
        "a read-stage failure never re-POSTs the body"
    );
    let row = store
        .settlement(&attempt_id)
        .expect("the entered failure settles");
    assert_eq!(
        row.wire_retries, 0,
        "the stream crossed one leg and no retry followed"
    );
    peer.join().expect("the live peer joins");
}

/// A retry that provably never left the client — a refused connect — is
/// not a crossed leg: the first failure stays the reported one, with its
/// class, and the settlement records no retry.
#[tokio::test]
async fn a_retry_that_never_crossed_the_wire_keeps_the_first_failure() {
    let deadline = Duration::from_secs(4);
    let (daily, peer) = never_answer();
    // A loopback port bound then released: the retry's connect is refused
    // before a byte of it exists.
    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
    let closed = format!(
        "http://{}",
        listener.local_addr().expect("the loopback address")
    );
    drop(listener);
    let config = Config::parse_validated(&antigravity_config(&daily, GEMINI_MODEL)).expect("valid");
    let (provider, store) = provider_with_deadline(&config, &pinned_profile(), deadline);
    let provider = provider
        .with_fallback(&closed)
        .expect("the proof fallback admits");
    let (broker, manifest) = prepared_with((provider, store), &config, WORLD, INPUTS);
    let attempt_id = manifest.attempt_id.clone();
    let root =
        tempfile::TempDir::with_prefix("rivect-cloudcode-refused-retry-").expect("fixture root");
    let db = root.path().join("state.db");
    let started = Instant::now();
    let (store, outcome) = std::thread::spawn(move || {
        let mut store = TaskStore::open(&db).expect("store opens");
        let mut ledger = StoreLedger::new(&mut store, Vec::new());
        let mut broker = broker;
        let outcome = broker.dispatch(&mut ledger, WORLD, &manifest);
        (store, outcome)
    })
    .join()
    .expect("the dispatch thread joins");
    let elapsed = started.elapsed();
    match outcome {
        Err(ModelError::Provider(ProviderError::Transport { cause, .. })) => {
            assert_eq!(
                cause.class(),
                TransportClass::Timeout,
                "the first attempt's class is the one reported"
            );
        }
        other => panic!("the refused retry keeps the first failure: {other:?}"),
    }
    let row = store
        .settlement(&attempt_id)
        .expect("the entered failure settles");
    assert_eq!(row.state, SettlementState::Settled);
    assert_eq!(
        row.wire_retries, 0,
        "a retry that never left the client is not a crossed leg"
    );
    assert!(
        elapsed < deadline,
        "the timed-out attempt and the refused retry stay inside one deadline: {elapsed:?}"
    );
    peer.join().expect("the daily peer joins");
}

/// A client-level construction failure never reaches a socket on either
/// leg: the stored bearer carries a newline, so both POSTs fail in
/// reqwest's builder. The first failure stays the reported one with its
/// class, and the settlement records no crossed leg.
#[tokio::test]
async fn a_builder_failure_on_both_legs_keeps_the_first_error() {
    let daily = MockServer::start().await;
    mount_stream(&daily, cloudcode_stream("never sent", "resp-x", 1, 1, 0, 0)).await;
    let sandbox = MockServer::start().await;
    mount_stream(
        &sandbox,
        cloudcode_stream("never sent", "resp-x", 1, 1, 0, 0),
    )
    .await;
    let config =
        Config::parse_validated(&antigravity_config(&daily.uri(), GEMINI_MODEL)).expect("valid");
    // The escaped newline parses into the stored token; a newline is not a
    // header value, so reqwest rejects the request while building it.
    let profile = profile_json(&[(GEMINI_MODEL, "gemini")]).replace(TOKEN, "fixture\\nbad");
    let (provider, store) = provider_with_deadline(&config, &profile, Duration::from_secs(4));
    let provider = provider
        .with_fallback(&sandbox.uri())
        .expect("the proof fallback admits");
    let (broker, manifest) = prepared_with((provider, store), &config, WORLD, INPUTS);
    let attempt_id = manifest.attempt_id.clone();
    let root = tempfile::TempDir::with_prefix("rivect-cloudcode-builder-").expect("fixture root");
    let db = root.path().join("state.db");
    let (store, outcome) = std::thread::spawn(move || {
        let mut store = TaskStore::open(&db).expect("store opens");
        let mut ledger = StoreLedger::new(&mut store, Vec::new());
        let mut broker = broker;
        let outcome = broker.dispatch(&mut ledger, WORLD, &manifest);
        (store, outcome)
    })
    .join()
    .expect("the dispatch thread joins");
    match outcome {
        Err(ModelError::Provider(ProviderError::Transport { cause, .. })) => {
            let TransportCause::Request { source } = &cause else {
                panic!("the builder failure keeps its request cause: {cause:?}");
            };
            assert!(
                source.is_builder(),
                "the failure provably never left the client: {source}"
            );
            assert_eq!(
                cause.class(),
                TransportClass::RequestFailure,
                "a builder failure is the request class"
            );
        }
        other => panic!("the builder failure is one typed transport error: {other:?}"),
    }
    assert_eq!(
        daily.received_requests().await.expect("recorded").len(),
        0,
        "the first POST never reached a socket"
    );
    assert_eq!(
        sandbox.received_requests().await.expect("recorded").len(),
        0,
        "the retry never reached a socket"
    );
    let row = store
        .settlement(&attempt_id)
        .expect("the entered failure settles");
    assert_eq!(row.state, SettlementState::Settled);
    assert_eq!(
        row.wire_retries, 0,
        "a retry that never left the client is not a crossed leg"
    );
}

/// The remaining-budget clamp, not a fixed share: a credential resolve
/// that spends two of the three seconds leaves the first attempt one
/// second, so the send ends at the deadline instead of deadline + share.
/// The fallback is never reached.
#[tokio::test]
async fn a_slow_credential_resolve_cannot_push_the_send_past_the_deadline() {
    let deadline = Duration::from_secs(3);
    let (daily, peer) = never_answer();
    let sandbox = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(STREAM_PATH))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(600)))
        .mount(&sandbox)
        .await;
    let config = Config::parse_validated(&antigravity_config(&daily, GEMINI_MODEL)).expect("valid");
    let profile = pinned_profile();
    let store: Arc<dyn CredentialStore> = Arc::new(SlowStore {
        inner: MapStore::seeded(STORE_KIND, &[(CREDENTIAL_REF, profile.as_str())]),
        delay: Duration::from_secs(2),
    });
    let handle = Arc::clone(&store);
    let config_for_provider = config.clone();
    let provider = std::thread::spawn(move || {
        CloudCodeProvider::with_deadline(&config_for_provider, ANTIGRAVITY, handle, deadline)
    })
    .join()
    .expect("the provider thread joins")
    .expect("the adapter builds for the literal id");
    let provider = provider
        .with_fallback(&sandbox.uri())
        .expect("the proof fallback admits");
    let mut broker = Broker::new(Box::new(provider));
    let manifest = broker
        .prepare("main", &config, WORLD, INPUTS)
        .expect("the pin prepares");
    let started = Instant::now();
    let (broker, ledger, outcome) = dispatch(broker, CountingLedger::new(), manifest);
    let elapsed = started.elapsed();
    match outcome {
        Err(ModelError::Provider(ProviderError::Transport { cause, .. })) => assert_eq!(
            cause.class(),
            TransportClass::DeadlineExpired,
            "the retry is refused once the resolve has spent the deadline"
        ),
        other => panic!("both origins never answer; the budget is the verdict: {other:?}"),
    }
    assert!(
        elapsed < deadline + Duration::from_millis(250),
        "the resolve spends the same budget; no attempt adds a share: {elapsed:?}"
    );
    assert_eq!(ledger.begun, 1, "one entered send opens one settlement row");
    assert_eq!(ledger.finished, 1);
    assert_eq!(ledger.failed, 1);
    assert_eq!(broker.accounted_requests(), 0);
    assert_eq!(
        sandbox.received_requests().await.expect("recorded").len(),
        0,
        "the retry never reaches the sandbox after the deadline"
    );
    peer.join().expect("the daily peer joins");
    support::drop_blocking(broker);
}

/// A retried leg that answers 200 and then fails while its body streams is
/// still the second crossed leg: the failure keeps the `Retried` marker
/// and the settlement records the count.
#[tokio::test]
async fn a_retried_stream_failure_keeps_the_crossed_leg_count() {
    let daily = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(STREAM_PATH))
        .respond_with(ResponseTemplate::new(503))
        .mount(&daily)
        .await;
    let sandbox = MockServer::start().await;
    let content_only = format!(
        "data: {}\n\n",
        json!({"response": {
            "candidates": [{
                "content": {"role": "model", "parts": [{"text": "observed"}]},
                "index": 0,
            }],
        }}),
    );
    mount_stream(&sandbox, content_only).await;
    let config =
        Config::parse_validated(&antigravity_config(&daily.uri(), GEMINI_MODEL)).expect("valid");
    let (provider, store) = antigravity_provider(&config, &pinned_profile());
    let provider = provider
        .with_fallback(&sandbox.uri())
        .expect("the proof fallback admits");
    let (broker, manifest) = prepared_with((provider, store), &config, WORLD, INPUTS);
    let attempt_id = manifest.attempt_id.clone();
    let root = tempfile::TempDir::with_prefix("rivect-cloudcode-retried-").expect("fixture root");
    let db = root.path().join("state.db");
    let (store, outcome) = std::thread::spawn(move || {
        let mut store = TaskStore::open(&db).expect("store opens");
        let mut ledger = StoreLedger::new(&mut store, Vec::new());
        let mut broker = broker;
        let outcome = broker.dispatch(&mut ledger, WORLD, &manifest);
        (store, outcome)
    })
    .join()
    .expect("the dispatch thread joins");
    match outcome {
        // The broker unwraps the adapter's retry marker at the send
        // boundary, so the caller meets the stream verdict while the
        // crossed-leg count stays on the settlement row below.
        Err(ModelError::Provider(ProviderError::UnknownTerminal { connection })) => {
            assert_eq!(connection, ANTIGRAVITY);
        }
        other => panic!("a failed retried stream keeps its class: {other:?}"),
    }
    let row = store
        .settlement(&attempt_id)
        .expect("the failed retried stream settles");
    assert_eq!(row.state, SettlementState::Settled);
    assert_eq!(row.wire_retries, 1, "both physical legs crossed the wire");
    assert_eq!(row.exactness, Exactness::Unknown);
    assert_eq!(row.unknown_reason.as_deref(), Some("send failed"));
    assert_eq!(
        row.bins.total_tokens, None,
        "a failed retried stream reports no usage, never zero"
    );
    assert_eq!(daily.received_requests().await.expect("recorded").len(), 1);
    assert_eq!(
        sandbox.received_requests().await.expect("recorded").len(),
        1
    );
}

/// A wrong origin and an unusable profile both deny typed before any
/// request: zero physical requests, one failed settlement row and no
/// accounting row.
#[tokio::test]
async fn wrong_origin_and_profile_deny_without_a_request() {
    emit_provider_row("AUTH", "google-antigravity");
    // The foreign origin is config-valid https but outside the recorded
    // set. The zero budget makes a guard regression stop at the deadline
    // instead of reaching the foreign host.
    let server = MockServer::start().await;
    let config = Config::parse_validated(&antigravity_config(
        "https://foreign.example.invalid",
        GEMINI_MODEL,
    ))
    .expect("valid");
    let (provider, store) = provider_with_deadline(&config, &pinned_profile(), Duration::ZERO);
    let (broker, manifest) = prepared_with((provider, store), &config, WORLD, INPUTS);
    let (broker, ledger, outcome) = dispatch(broker, CountingLedger::new(), manifest);
    match outcome {
        Err(ModelError::Provider(ProviderError::CredentialBaseMismatch { connection, .. })) => {
            assert_eq!(connection, ANTIGRAVITY)
        }
        other => panic!("the foreign origin denies typed: {other:?}"),
    }
    assert_eq!(ledger.begun, 1);
    assert_eq!(ledger.finished, 1);
    assert_eq!(ledger.failed, 1, "the entered send closes one failed row");
    assert_eq!(broker.accounted_requests(), 0);
    assert_eq!(
        server.received_requests().await.expect("recorded").len(),
        0,
        "a refused origin puts no request on the wire"
    );
    support::drop_blocking(broker);

    // Stored material that is not the producer's profile denies typed.
    let config =
        Config::parse_validated(&antigravity_config(&server.uri(), GEMINI_MODEL)).expect("valid");
    let (broker, manifest) = prepared_with(
        antigravity_provider(&config, "not-an-antigravity-profile"),
        &config,
        WORLD,
        INPUTS,
    );
    let (broker, ledger, outcome) = dispatch(broker, CountingLedger::new(), manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(
                ProviderError::CredentialMalformed { .. }
            ))
        ),
        "the malformed profile denies typed: {outcome:?}"
    );
    assert_eq!(ledger.failed, 1);
    assert_eq!(broker.accounted_requests(), 0);
    assert_eq!(
        server.received_requests().await.expect("recorded").len(),
        0,
        "a refused profile puts no request on the wire"
    );
    support::drop_blocking(broker);

    // A scope with no material keeps the store's own typed denial.
    let empty = Arc::new(MapStore::new(STORE_KIND));
    let provider = provider_result(config.clone(), Arc::clone(&empty)).expect("the adapter builds");
    let (broker, manifest) = prepared_with((provider, empty), &config, WORLD, INPUTS);
    let (broker, ledger, outcome) = dispatch(broker, CountingLedger::new(), manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(ProviderError::CredentialAbsent { .. }))
        ),
        "an absent profile scope denies typed: {outcome:?}"
    );
    assert_eq!(ledger.failed, 1);
    assert_eq!(broker.accounted_requests(), 0);
    assert_eq!(
        server.received_requests().await.expect("recorded").len(),
        0,
        "an absent profile puts no request on the wire"
    );
    support::drop_blocking(broker);
}

/// The conversation state the recorded envelope names: the second turn
/// keeps the first text's session id, advances the request step, echoes
/// the completed response id as `last_execution_id`, and replays the
/// committed model turn through the shared Gemini builder.
#[tokio::test]
async fn second_turn_echoes_the_response_id_and_keeps_the_session() {
    let server = MockServer::start().await;
    mount_stream(
        &server,
        cloudcode_stream("first answer", "resp-1", 5, 2, 0, 0),
    )
    .await;
    let config =
        Config::parse_validated(&antigravity_config(&server.uri(), GEMINI_MODEL)).expect("valid");
    let (mut broker, first) = prepared_with(
        antigravity_provider(&config, &pinned_profile()),
        &config,
        WORLD,
        INPUTS,
    );
    let second = broker
        .prepare("main", &config, WORLD, SECOND_INPUTS)
        .expect("the second turn prepares");
    let (broker, ledger, outcomes) = std::thread::spawn(move || {
        let mut ledger = CountingLedger::new();
        let first_outcome = broker.dispatch(&mut ledger, WORLD, &first);
        let second_outcome = broker.dispatch(&mut ledger, WORLD, &second);
        (broker, ledger, (first_outcome, second_outcome))
    })
    .join()
    .expect("the dispatch thread joins");
    assert!(outcomes.0.is_ok(), "{:?}", outcomes.0);
    assert!(outcomes.1.is_ok(), "{:?}", outcomes.1);
    assert_eq!(ledger.begun, 2);
    assert_eq!(ledger.failed, 0);
    assert_eq!(broker.accounted_requests(), 2);

    let bodies = received_bodies(&server).await;
    assert_eq!(bodies.len(), 2);
    let first_body = &bodies[0];
    let second_body = &bodies[1];
    assert_eq!(request_id_segments(second_body)[4], "3");
    assert_eq!(
        second_body["request"]["labels"]["last_step_index"],
        json!("2")
    );
    assert_eq!(
        second_body["request"]["labels"]["last_execution_id"],
        json!("resp-1"),
        "the completed response id is echoed as last_execution_id"
    );
    assert_eq!(
        second_body["request"]["sessionId"], first_body["request"]["sessionId"],
        "the session id is stable across the conversation's turns"
    );
    assert_eq!(
        second_body["request"]["sessionId"],
        json!(INPUTS_SESSION_ID),
        "the session id is the pinned decimal of the first user text, not the second"
    );
    assert_eq!(
        second_body["request"]["contents"],
        json!([
            { "role": "model", "parts": [{ "text": "first answer" }] },
            { "role": "user", "parts": [{ "text": SECOND_INPUTS }] },
        ]),
        "the shared builder replays the committed model turn ahead of the new user content"
    );
    support::drop_blocking(broker);
}

/// A completed stream without a `responseId` clears the echoed id, as the
/// recorded source assigns on every stream: the third turn carries no
/// `last_execution_id` after the second turn answered without one, while
/// the session id and step keep advancing.
#[test]
fn a_completed_stream_without_a_response_id_clears_last_execution_id() {
    let turns = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&turns);
    let peer = Peer::start(move |seen| {
        if !seen.line.contains(":streamGenerateContent") {
            return (500_u16, "{}".to_string());
        }
        match counter.fetch_add(1, Ordering::SeqCst) {
            0 => (200, cloudcode_stream("first answer", "resp-1", 5, 2, 0, 0)),
            1 => (
                200,
                format!(
                    "data: {}\n\ndata: {}\n\n",
                    json!({"response": {
                        "candidates": [{
                            "content": {"role": "model", "parts": [{"text": "second answer"}]},
                            "index": 0,
                        }],
                    }}),
                    json!({"response": {
                        "candidates": [{
                            "content": {"role": "model", "parts": []},
                            "finishReason": "STOP",
                            "index": 0,
                        }],
                    }}),
                ),
            ),
            _ => (200, cloudcode_stream("third answer", "resp-3", 5, 2, 0, 0)),
        }
    });
    let config =
        Config::parse_validated(&antigravity_config(&peer.base, GEMINI_MODEL)).expect("valid");
    let (mut broker, first) = prepared_with(
        antigravity_provider(&config, &pinned_profile()),
        &config,
        WORLD,
        INPUTS,
    );
    let second = broker
        .prepare("main", &config, WORLD, SECOND_INPUTS)
        .expect("the second turn prepares");
    let config_thread = config.clone();
    let (broker, ledger, outcomes) = std::thread::spawn(move || {
        let mut ledger = CountingLedger::new();
        let first_outcome = broker.dispatch(&mut ledger, WORLD, &first);
        let second_outcome = broker.dispatch(&mut ledger, WORLD, &second);
        let third = broker
            .prepare("main", &config_thread, WORLD, THIRD_INPUTS)
            .expect("the third turn prepares");
        let third_outcome = broker.dispatch(&mut ledger, WORLD, &third);
        (
            broker,
            ledger,
            [first_outcome, second_outcome, third_outcome],
        )
    })
    .join()
    .expect("the dispatch thread joins");
    for outcome in &outcomes {
        assert!(outcome.is_ok(), "{outcome:?}");
    }
    assert_eq!(ledger.begun, 3);
    assert_eq!(ledger.finished, 3);
    assert_eq!(ledger.failed, 0);
    assert_eq!(broker.accounted_requests(), 3);

    let bodies: Vec<Value> = peer
        .requests()
        .iter()
        .map(|request| serde_json::from_str(&request.body).expect("the envelope is json"))
        .collect();
    assert_eq!(bodies.len(), 3);
    assert_eq!(request_id_segments(&bodies[0])[4], "2");
    assert_eq!(
        bodies[1]["request"]["labels"]["last_execution_id"],
        json!("resp-1"),
        "the first completed stream's id is echoed by the second turn"
    );
    assert_eq!(request_id_segments(&bodies[1])[4], "3");
    assert!(
        bodies[2]["request"]["labels"]
            .get("last_execution_id")
            .is_none(),
        "the second turn's id-less stream clears the slot, so no stale id rides"
    );
    assert_eq!(request_id_segments(&bodies[2])[4], "4");
    assert_eq!(
        bodies[2]["request"]["labels"]["last_step_index"],
        json!("3")
    );
    for body in &bodies {
        assert_eq!(
            body["request"]["sessionId"],
            json!(INPUTS_SESSION_ID),
            "the session id stays the first text's across the turns"
        );
    }
    support::drop_blocking(broker);
}

/// The Antigravity project rule denies before the post: a blank stored
/// project closes one failed settlement row, records no accounting row
/// and puts no request on the wire.
#[tokio::test]
async fn antigravity_blank_project_denies_before_the_post() {
    let server = MockServer::start().await;
    let config =
        Config::parse_validated(&antigravity_config(&server.uri(), GEMINI_MODEL)).expect("valid");
    let mut classes = serde_json::Map::new();
    classes.insert(GEMINI_MODEL.to_string(), json!("gemini"));
    let profile = json!({
        "access_token": TOKEN,
        "project": "   ",
        "classes": classes,
    })
    .to_string();
    let (broker, manifest) = prepared_with(
        antigravity_provider(&config, &profile),
        &config,
        WORLD,
        INPUTS,
    );
    let (broker, ledger, outcome) = dispatch(broker, CountingLedger::new(), manifest);
    match outcome {
        Err(ModelError::Provider(ProviderError::UnsendableRequest { connection, reason })) => {
            assert_eq!(connection, ANTIGRAVITY);
            assert_eq!(reason, "the profile project is empty");
        }
        other => panic!("the blank project denies typed: {other:?}"),
    }
    assert_eq!(ledger.begun, 1);
    assert_eq!(ledger.finished, 1);
    assert_eq!(ledger.failed, 1);
    assert_eq!(broker.accounted_requests(), 0);
    assert_eq!(
        server.received_requests().await.expect("recorded").len(),
        0,
        "a blank project puts no request on the wire"
    );
    support::drop_blocking(broker);
}

/// Usage reports reach the reply verbatim: an inconsistent
/// `totalTokenCount` is charged as reported rather than re-summed from
/// the legs, and a non-object `usageMetadata` is a wire violation.
#[tokio::test]
async fn usage_reports_reach_the_reply_verbatim() {
    let inconsistent = format!(
        "data: {}\n\n",
        json!({"response": {
            "candidates": [{
                "content": {"role": "model", "parts": []},
                "finishReason": "STOP",
                "index": 0,
            }],
            "usageMetadata": {
                "promptTokenCount": 10,
                "candidatesTokenCount": 4,
                "totalTokenCount": 99,
            },
        }}),
    );
    let (reply, broker, _) = positive_stream(inconsistent).await;
    assert_eq!(
        reply.usage,
        UsageDelta::from_reported(10, 4, 99, None, Some(0), Some(0))
    );
    assert_eq!(
        reply.usage.confirmed_total(),
        Some(99),
        "the reported total is charged verbatim, never re-summed from the legs"
    );
    support::drop_blocking(broker);

    let non_object = format!(
        "data: {}\n\n",
        json!({"response": {
            "candidates": [{
                "content": {"role": "model", "parts": []},
                "finishReason": "STOP",
                "index": 0,
            }],
            "usageMetadata": [],
        }}),
    );
    let (error, broker, _) = negative_stream(non_object).await;
    match error {
        ProviderError::StreamViolation { connection, reason } => {
            assert_eq!(connection, ANTIGRAVITY);
            assert_eq!(reason, "usageMetadata is not an object");
        }
        other => panic!("a non-object usage report is a wire violation: {other:?}"),
    }
    support::drop_blocking(broker);
}

/// One positive stream through a real Broker: the reply, the settled row and
/// the one accounting row.
async fn positive_stream(body: String) -> (ProviderReply, Broker, CountingLedger) {
    let server = MockServer::start().await;
    mount_stream(&server, body).await;
    let config =
        Config::parse_validated(&antigravity_config(&server.uri(), GEMINI_MODEL)).expect("valid");
    let (broker, manifest) = prepared_with(
        antigravity_provider(&config, &pinned_profile()),
        &config,
        WORLD,
        INPUTS,
    );
    let (broker, ledger, outcome) = dispatch(broker, CountingLedger::new(), manifest);
    let reply = outcome.expect("the positive stream answers");
    assert_eq!(ledger.begun, 1);
    assert_eq!(ledger.finished, 1);
    assert_eq!(ledger.failed, 0);
    assert_eq!(broker.accounted_requests(), 1);
    (reply, broker, ledger)
}

/// One negative stream through a real Broker: the typed provider error, the
/// settled row and the zero accounting row.
async fn negative_stream(body: String) -> (ProviderError, Broker, CountingLedger) {
    let server = MockServer::start().await;
    mount_stream(&server, body).await;
    let config =
        Config::parse_validated(&antigravity_config(&server.uri(), GEMINI_MODEL)).expect("valid");
    let (broker, manifest) = prepared_with(
        antigravity_provider(&config, &pinned_profile()),
        &config,
        WORLD,
        INPUTS,
    );
    let (broker, ledger, outcome) = dispatch(broker, CountingLedger::new(), manifest);
    let error = match outcome {
        Err(ModelError::Provider(error)) => error,
        other => panic!("the negative stream must fail typed: {other:?}"),
    };
    assert_eq!(ledger.begun, 1);
    assert_eq!(ledger.finished, 1);
    assert_eq!(ledger.failed, 1);
    assert_eq!(broker.accounted_requests(), 0);
    (error, broker, ledger)
}

/// The whole-stream terminal rules: a completed stream without a terminal,
/// an unknown finish reason and a partial tool are never success.
#[tokio::test]
async fn terminal_removed_and_unknown_reasons_are_never_success() {
    let content_only = format!(
        "data: {}\n\n",
        json!({"response": {
            "candidates": [{
                "content": {"role": "model", "parts": [{"text": "half"}]},
                "index": 0,
            }],
        }}),
    );
    let (error, broker, _) = negative_stream(content_only).await;
    assert!(
        matches!(error, ProviderError::UnknownTerminal { .. }),
        "a stream without a terminal is unknown: {error:?}"
    );
    support::drop_blocking(broker);

    let unknown_reason = format!(
        "data: {}\n\n",
        json!({"response": {
            "candidates": [{
                "content": {"role": "model", "parts": []},
                "finishReason": "SOMETHING_NEW",
                "index": 0,
            }],
        }}),
    );
    let (error, broker, _) = negative_stream(unknown_reason).await;
    assert!(
        matches!(error, ProviderError::UnknownTerminal { .. }),
        "an unrecorded finish reason is unclassifiable: {error:?}"
    );
    support::drop_blocking(broker);

    let partial_tool = format!(
        "data: {}\n\n",
        json!({"response": {
            "candidates": [{
                "content": {
                    "role": "model",
                    "parts": [{"functionCall": {"name": "read_file", "args": {"path": "/x"}}}],
                },
                "index": 0,
            }],
        }}),
    );
    let (error, broker, _) = negative_stream(partial_tool).await;
    assert!(
        matches!(error, ProviderError::UnknownTerminal { .. }),
        "a partial tool without a terminal is never success: {error:?}"
    );
    support::drop_blocking(broker);
}

/// An in-band error and a malformed partial tool are typed failures.
#[tokio::test]
async fn in_band_error_and_malformed_tool_are_typed_failures() {
    let in_band = format!(
        "data: {}\n\n",
        json!({"error": {"code": 500, "message": "boom", "status": "INTERNAL"}}),
    );
    let (error, broker, _) = negative_stream(in_band).await;
    match error {
        ProviderError::ProviderFailed { reason, .. } => assert_eq!(reason, "boom"),
        other => panic!("the in-band error is the peer's failure verdict: {other:?}"),
    }
    support::drop_blocking(broker);

    let malformed_tool = format!(
        "data: {}\n\n",
        json!({"response": {
            "candidates": [{
                "content": {
                    "role": "model",
                    "parts": [{"functionCall": {"args": {"path": "/x"}}}],
                },
                "index": 0,
            }],
        }}),
    );
    let (error, broker, _) = negative_stream(malformed_tool).await;
    assert!(
        matches!(error, ProviderError::StreamViolation { .. }),
        "a nameless functionCall is a wire violation: {error:?}"
    );
    support::drop_blocking(broker);
}

/// The CloudCode `promptFeedback` rule has two recorded branches: a
/// `blockReason` with no candidate is the peer's typed failure, while the
/// same reason beside a candidate that finishes still carries the answer.
#[tokio::test]
async fn prompt_feedback_blocks_only_without_a_candidate() {
    let blocked = format!(
        "data: {}\n\n",
        json!({"response": {"promptFeedback": {"blockReason": "SAFETY"}}}),
    );
    let (error, broker, _) = negative_stream(blocked).await;
    match error {
        ProviderError::ProviderFailed { reason, .. } => {
            assert_eq!(reason, "request blocked by google: SAFETY");
        }
        other => panic!("a blockReason without a candidate is typed: {other:?}"),
    }
    support::drop_blocking(broker);

    // An explicit empty candidate list is the same "no candidate" shape.
    let empty_list = format!(
        "data: {}\n\n",
        json!({"response": {"promptFeedback": {"blockReason": "SAFETY"}, "candidates": []}}),
    );
    let (error, broker, _) = negative_stream(empty_list).await;
    match error {
        ProviderError::ProviderFailed { reason, .. } => {
            assert_eq!(reason, "request blocked by google: SAFETY");
        }
        other => panic!("a blockReason with an empty candidate list is typed: {other:?}"),
    }
    support::drop_blocking(broker);

    let answered = format!(
        "data: {}\n\n",
        json!({"response": {
            "promptFeedback": {"blockReason": "SAFETY"},
            "candidates": [{
                "content": {"role": "model", "parts": [{"text": "still answered"}]},
                "finishReason": "STOP",
                "index": 0,
            }],
        }}),
    );
    let (reply, broker, _) = positive_stream(answered).await;
    assert_eq!(reply.text, "still answered");
    assert_eq!(
        reply.usage,
        UsageDelta::Unknown,
        "an absent usage report stays unknown"
    );
    support::drop_blocking(broker);
}

/// The recorded CloudCode usage shape: absent cache and thought counters are
/// the reported zero (proto3 elides zero fields), the reasoning leg stays
/// `None`, and a present non-counter is a wire violation.
#[tokio::test]
async fn cloudcode_usage_treats_absent_counters_as_reported_zero() {
    let absent = format!(
        "data: {}\n\n",
        json!({"response": {
            "candidates": [{
                "content": {"role": "model", "parts": []},
                "finishReason": "STOP",
                "index": 0,
            }],
            "usageMetadata": {
                "promptTokenCount": 11,
                "candidatesTokenCount": 7,
                "totalTokenCount": 18,
            },
        }}),
    );
    let (reply, broker, _) = positive_stream(absent).await;
    assert_eq!(
        reply.usage,
        UsageDelta::from_reported(11, 7, 18, None, Some(0), Some(0)),
        "the absent cache and thought counters are the reported zero"
    );
    support::drop_blocking(broker);

    let non_counter = format!(
        "data: {}\n\n",
        json!({"response": {
            "candidates": [{
                "content": {"role": "model", "parts": []},
                "finishReason": "STOP",
                "index": 0,
            }],
            "usageMetadata": {
                "promptTokenCount": "eleven",
                "candidatesTokenCount": 7,
                "totalTokenCount": 18,
            },
        }}),
    );
    let (error, broker, _) = negative_stream(non_counter).await;
    assert!(
        matches!(error, ProviderError::StreamViolation { .. }),
        "a present non-counter is a wire violation: {error:?}"
    );
    support::drop_blocking(broker);
}

/// A usage-only tail after the terminal is the recorded shape, and the last
/// report the stream carried is authoritative.
#[tokio::test]
async fn the_last_usage_report_after_the_terminal_wins() {
    let tail = format!(
        "data: {}\n\n",
        json!({"response": {"usageMetadata": {
            "promptTokenCount": 20,
            "candidatesTokenCount": 10,
            "totalTokenCount": 35,
            "cachedContentTokenCount": 5,
            "thoughtsTokenCount": 5,
        }}})
    );
    let body = format!(
        "{}{}",
        cloudcode_stream("tail answer", "resp-1", 11, 7, 3, 2),
        tail
    );
    let (reply, broker, _) = positive_stream(body).await;
    assert_eq!(reply.text, "tail answer");
    assert_eq!(
        reply.usage,
        UsageDelta::from_reported(15, 15, 35, Some(5), Some(5), Some(0)),
        "the tail report replaces the terminal's usage"
    );
    support::drop_blocking(broker);
}

/// AC-002's artifact link: the real SLICE-163 producer publishes the profile
/// through the credential store's login path, `read_profile` reads those
/// bytes, and the adapter dispatches all three recorded classes from that
/// artifact.
#[test]
fn antigravity_adapter_consumes_the_producer_artifact() {
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
                    json!({ "cloudaicompanionProject": PROJECT }).to_string(),
                ),
                _ => (
                    200,
                    json!({
                        "paidTier": { "id": "paid-tier" },
                        "cloudaicompanionProject": PROJECT
                    })
                    .to_string(),
                ),
            };
        }
        if seen.line.contains(":fetchAvailableModels") {
            let models: Value = [
                GEMINI_MODEL,
                ANTHROPIC_MODEL,
                GPT_OSS_MODEL,
                GPT_OSS_ALT_MODEL,
            ]
            .into_iter()
            .map(|model| (model.to_string(), json!({})))
            .collect();
            return (200, json!({ "models": models }).to_string());
        }
        if seen.line.contains(":onboardUser") {
            return (
                200,
                json!({ "name": "operations/onboard-1", "done": false }).to_string(),
            );
        }
        if seen.line.contains("/v1internal/operations/") {
            return (
                200,
                json!({
                    "name": "operations/onboard-1",
                    "done": true,
                    "error": null,
                    "response": { "cloudaicompanionProject": "ignored-project" }
                })
                .to_string(),
            );
        }
        if seen.line.contains(":streamGenerateContent") {
            return (
                200,
                cloudcode_stream("produced answer", "resp-1", 5, 2, 0, 0),
            );
        }
        (500_u16, "{}".to_string())
    });

    let store = Arc::new(MapStore::new(STORE_KIND));
    let producer_config =
        Config::parse_validated(&antigravity_config(&peer.base, GEMINI_MODEL)).expect("valid");
    let session = antigravity_login::begin_login(
        TOKEN,
        &AntigravityEndpoints {
            code_assist: peer.base.clone(),
        },
    )
    .expect("the login begins");
    let profile =
        antigravity_login::complete_login(&producer_config, ANTIGRAVITY, &session, store.as_ref())
            .expect("the producer publishes the profile");
    assert_eq!(profile, PROFILE);

    let reference = SecretRef::parse(CREDENTIAL_REF).expect("the credential ref parses");
    let artifact =
        antigravity_login::read_profile(store.as_ref(), &reference).expect("the profile reads");
    assert_eq!(artifact.access_token(), TOKEN);
    assert_eq!(artifact.project(), PROJECT);
    let expected: BTreeMap<String, String> = [
        (GEMINI_MODEL, "gemini"),
        (ANTHROPIC_MODEL, "anthropic"),
        (GPT_OSS_MODEL, "gpt-oss"),
        (GPT_OSS_ALT_MODEL, "gpt-oss"),
    ]
    .into_iter()
    .map(|(model, class)| (model.to_string(), class.to_string()))
    .collect();
    assert_eq!(
        artifact.classes(),
        &expected,
        "the producer's discovery map is the artifact the adapter consumes"
    );

    for model in [GEMINI_MODEL, ANTHROPIC_MODEL, GPT_OSS_MODEL] {
        let config =
            Config::parse_validated(&antigravity_config(&peer.base, model)).expect("valid");
        let provider = provider_result(config.clone(), Arc::clone(&store))
            .expect("the adapter builds from the produced artifact");
        let (broker, manifest) =
            prepared_with((provider, Arc::clone(&store)), &config, WORLD, INPUTS);
        let attempt_id = manifest.attempt_id.clone();
        let (broker, ledger, outcome) = dispatch(broker, CountingLedger::new(), manifest);
        let reply = outcome.expect("the produced profile's class sends");
        assert_eq!(reply.text, "produced answer");
        assert_eq!(ledger.failed, 0);
        assert_eq!(broker.accounted_requests(), 1);
        assert_eq!(
            broker
                .accounting_record(&attempt_id)
                .expect("the accounting row names the attempt")
                .connection,
            ANTIGRAVITY
        );
        support::drop_blocking(broker);
    }

    let requests = peer.requests();
    let streams: Vec<_> = requests
        .iter()
        .filter(|request| request.line.contains(":streamGenerateContent"))
        .collect();
    assert_eq!(streams.len(), 3, "one send per recorded class");
    for (request, (model, used_claude)) in streams.iter().zip([
        (GEMINI_MODEL, "false"),
        (ANTHROPIC_MODEL, "true"),
        (GPT_OSS_MODEL, "false"),
    ]) {
        let body: Value = serde_json::from_str(&request.body).expect("the envelope is json");
        assert_eq!(body["model"], json!(model));
        let segments = request_id_segments(&body);
        assert_eq!(
            body["request"]["labels"],
            json!({
                "last_step_index": "1",
                "trajectory_id": segments[3],
                "used_claude": used_claude,
                "used_claude_conservative": used_claude,
            }),
            "{model} carries exactly the recorded labels"
        );
    }
}

/// The Gemini CLI projection: the recorded `cloudcode-pa` stream line, the
/// Gemini CLI user agent and plugin metadata plus the shared Bearer/JSON/SSE
/// headers, the exact `project`/`model`/`request` top level with the thinking
/// config inside the nested request, none of the Antigravity envelope
/// members, and one verified outcome with one accounting record.
#[tokio::test]
async fn gemini_cli_envelope_is_recorded() {
    emit_provider_row("WIRE", "google-gemini-cli");
    assert_eq!(dialect_for(GEMINI_CLI), Some(Dialect::CloudCode));

    let server = MockServer::start().await;
    mount_stream(
        &server,
        cloudcode_stream("the gemini cli answer", "resp-1", 11, 7, 3, 2),
    )
    .await;
    let config = Config::parse_validated(&gemini_cli_config(&server.uri(), GEMINI_CLI_MODEL))
        .expect("valid");
    let (provider, store) = gemini_cli_provider(
        &config,
        &gemini_cli_profile(GEMINI_CLI_PROJECT, "standard-tier"),
    );
    let rendered = format!("{provider:?}");
    for secret in [GEMINI_CLI_TOKEN, GEMINI_CLI_PROJECT] {
        assert!(
            !rendered.contains(secret),
            "the adapter Debug never carries credential material"
        );
    }
    let (broker, manifest) = prepared_with((provider, store), &config, WORLD, GEMINI_CLI_INPUTS);
    let instructions = manifest.instructions.clone();
    let attempt_id = manifest.attempt_id.clone();
    let (broker, ledger, outcome) = dispatch(broker, CountingLedger::new(), manifest);
    let reply = outcome.expect("the recorded Gemini CLI send succeeds");
    assert_eq!(reply.text, "the gemini cli answer");
    assert_eq!(
        reply.usage,
        UsageDelta::from_reported(8, 9, 20, Some(2), Some(3), Some(0)),
        "the Gemini CLI stream maps the shared CloudCode usage legs"
    );
    assert_eq!(ledger.begun, 1);
    assert_eq!(ledger.finished, 1);
    assert_eq!(ledger.failed, 0);
    assert_eq!(
        broker.accounted_requests(),
        1,
        "one completed send records exactly one accounting row"
    );
    let record = broker
        .accounting_record(&attempt_id)
        .expect("the accounting row names the attempt");
    assert_eq!(record.usage, reply.usage);
    assert_eq!(
        record.connection, GEMINI_CLI,
        "the accounting row names the Gemini CLI connection"
    );

    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1, "one physical request per entered send");
    let request = &requests[0];
    assert_eq!(request.method.as_str(), "POST");
    assert_eq!(request.url.path(), STREAM_PATH);
    assert_eq!(request.url.query(), Some("alt=sse"));
    assert_eq!(
        header(request, "authorization"),
        Some(format!("Bearer {GEMINI_CLI_TOKEN}").as_str())
    );
    assert_eq!(header(request, "content-type"), Some("application/json"));
    assert_eq!(header(request, "accept"), Some("text/event-stream"));
    assert_eq!(
        header(request, "user-agent"),
        Some(expected_gemini_cli_user_agent(GEMINI_CLI_MODEL).as_str()),
        "the recorded Gemini CLI user agent names the pinned model"
    );
    assert_eq!(header(request, "client-metadata"), Some(CLIENT_METADATA));
    assert_eq!(header(request, "x-goog-api-key"), None);

    let bodies = received_bodies(&server).await;
    let body = &bodies[0];
    let mut top: Vec<&str> = body
        .as_object()
        .expect("the envelope is an object")
        .keys()
        .map(String::as_str)
        .collect();
    top.sort_unstable();
    assert_eq!(
        top,
        ["model", "project", "request"],
        "the top level is exactly the Gemini CLI projection"
    );
    assert_eq!(body["project"], json!(GEMINI_CLI_PROJECT));
    assert_eq!(body["model"], json!(GEMINI_CLI_MODEL));
    for antigravity_member in [
        "requestId",
        "userAgent",
        "requestType",
        "labels",
        "sessionId",
    ] {
        assert!(
            body.get(antigravity_member).is_none(),
            "the Gemini CLI top level never carries {antigravity_member}"
        );
    }
    assert!(
        body.get("generationConfig").is_none(),
        "the thinking config stays inside the nested request"
    );

    let request_body = &body["request"];
    let mut keys: Vec<&str> = request_body
        .as_object()
        .expect("the request is an object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        ["contents", "generationConfig", "systemInstruction", "tools"],
        "the nested request carries the Gemini request surface"
    );
    assert_eq!(
        request_body["contents"],
        json!([{ "role": "user", "parts": [{ "text": GEMINI_CLI_INPUTS }] }])
    );
    assert_eq!(
        request_body["systemInstruction"],
        json!({ "parts": [{ "text": instructions }] }),
        "the Gemini CLI projection states no system role"
    );
    assert!(
        request_body["systemInstruction"].get("role").is_none(),
        "an Antigravity role never leaks into this projection"
    );
    assert_eq!(
        request_body["generationConfig"]["thinkingConfig"]["thinkingLevel"],
        json!("MEDIUM"),
        "the pinned effort stays inside request.generationConfig.thinkingConfig"
    );
    assert_eq!(
        request_body["tools"][0]["functionDeclarations"][0]["name"],
        json!("read_file")
    );
    for antigravity_member in ["sessionId", "labels"] {
        assert!(
            request_body.get(antigravity_member).is_none(),
            "the Gemini CLI request never carries {antigravity_member}"
        );
    }

    support::drop_blocking(broker);
}

/// The Gemini CLI request timeout is the budget left at the post, not the
/// whole deadline: a credential resolve that spends most of a short budget
/// leaves the never-answering attempt only the remainder, so the send ends
/// inside the deadline. A fixed full-deadline request timeout would end
/// past it by the resolve delay.
#[tokio::test]
async fn a_slow_resolve_cannot_push_the_gemini_cli_send_past_the_deadline() {
    emit_provider_row("RECOVERY", "google-gemini-cli");
    let deadline = Duration::from_millis(1600);
    let (origin, peer) = never_answer();
    let config =
        Config::parse_validated(&gemini_cli_config(&origin, GEMINI_CLI_MODEL)).expect("valid");
    let profile = gemini_cli_profile(GEMINI_CLI_PROJECT, "");
    let store: Arc<dyn CredentialStore> = Arc::new(SlowStore {
        inner: MapStore::seeded(STORE_KIND, &[(GEMINI_CLI_REF, profile.as_str())]),
        delay: Duration::from_millis(1000),
    });
    let provider = {
        let config = config.clone();
        std::thread::spawn(move || {
            GeminiCliProvider::with_deadline(&config, GEMINI_CLI, store, deadline)
        })
        .join()
        .expect("the provider thread joins")
        .expect("the adapter builds for the literal id")
    };
    let (broker, manifest) = prepared_with(
        (
            provider,
            Arc::new(MapStore::seeded(
                STORE_KIND,
                &[(GEMINI_CLI_REF, profile.as_str())],
            )),
        ),
        &config,
        WORLD,
        GEMINI_CLI_INPUTS,
    );
    let started = Instant::now();
    let (broker, ledger, outcome) = dispatch(broker, CountingLedger::new(), manifest);
    let elapsed = started.elapsed();
    match outcome {
        Err(ModelError::Provider(ProviderError::Transport { cause, .. })) => {
            assert_eq!(
                cause.class(),
                TransportClass::Timeout,
                "the remaining-budget timeout is the timeout class"
            );
        }
        other => panic!("the never-answering origin is one typed transport failure: {other:?}"),
    }
    assert!(
        elapsed >= deadline,
        "the post waits out the remaining budget: {elapsed:?}"
    );
    assert!(
        elapsed < deadline + Duration::from_millis(300),
        "the resolve spends the same budget; the post adds only its remainder: {elapsed:?}"
    );
    assert_eq!(ledger.begun, 1, "one entered send opens one settlement row");
    assert_eq!(ledger.finished, 1);
    assert_eq!(ledger.failed, 1);
    assert_eq!(
        broker.accounted_requests(),
        0,
        "a send with no reply opens no accounting record"
    );
    peer.join().expect("the unanswered peer joins");
    support::drop_blocking(broker);
}

/// AC-003's artifact link: the real Code Assist producer publishes a
/// known-id and an absent-id tier profile through the credential store's
/// login path, the same reader returns those strings verbatim, and the
/// adapter dispatches from each artifact with one accounting row.
#[test]
fn gemini_cli_consumes_the_producer_artifact_for_known_and_absent_tier_ids() {
    for tier in ["standard-tier", ""] {
        let answer = tier.to_string();
        let peer = Peer::start(move |seen| {
            if seen.line.contains(":loadCodeAssist") {
                let current = if answer.is_empty() {
                    json!({})
                } else {
                    json!({ "id": answer })
                };
                return (
                    200,
                    json!({
                        "currentTier": current,
                        "cloudaicompanionProject": GEMINI_CLI_PROJECT,
                    })
                    .to_string(),
                );
            }
            if seen.line.contains(":streamGenerateContent") {
                return (
                    200,
                    cloudcode_stream("produced gemini answer", "resp-1", 5, 2, 0, 0),
                );
            }
            (500, "{}".to_string())
        });
        let store = Arc::new(MapStore::new(STORE_KIND));
        let config = Config::parse_validated(&gemini_cli_config(&peer.base, GEMINI_CLI_MODEL))
            .expect("valid");
        let session = code_assist::begin_login(
            GEMINI_CLI_TOKEN,
            &CodeAssistEndpoints {
                code_assist: peer.base.clone(),
            },
        )
        .expect("the code assist login begins");
        let profile = code_assist::complete_login(&config, GEMINI_CLI, &session, store.as_ref())
            .expect("the producer publishes the profile");
        assert_eq!(profile, GEMINI_CLI_PROFILE);

        let reference = SecretRef::parse(GEMINI_CLI_REF).expect("the credential ref parses");
        let artifact =
            code_assist::read_profile(store.as_ref(), &reference).expect("the profile reads");
        assert_eq!(artifact.access_token(), GEMINI_CLI_TOKEN);
        assert_eq!(artifact.project(), GEMINI_CLI_PROJECT);
        assert_eq!(
            artifact.tier(),
            tier,
            "the producer-created tier string reads verbatim"
        );

        let provider = {
            let config = config.clone();
            let handle = Arc::clone(&store);
            std::thread::spawn(move || GeminiCliProvider::new(&config, GEMINI_CLI, handle))
                .join()
                .expect("the provider thread joins")
                .expect("the adapter builds from the produced artifact")
        };
        let (broker, manifest) = prepared_with(
            (provider, Arc::clone(&store)),
            &config,
            WORLD,
            GEMINI_CLI_INPUTS,
        );
        let attempt_id = manifest.attempt_id.clone();
        let (broker, ledger, outcome) = dispatch(broker, CountingLedger::new(), manifest);
        let reply = outcome.expect("the produced profile sends");
        assert_eq!(reply.text, "produced gemini answer");
        assert_eq!(ledger.failed, 0);
        assert_eq!(broker.accounted_requests(), 1);
        assert_eq!(
            broker
                .accounting_record(&attempt_id)
                .expect("the accounting row names the attempt")
                .connection,
            GEMINI_CLI
        );

        let requests = peer.requests();
        let streams: Vec<_> = requests
            .iter()
            .filter(|request| request.line.contains(":streamGenerateContent"))
            .collect();
        assert_eq!(streams.len(), 1, "the produced profile sends once");
        let body: Value = serde_json::from_str(&streams[0].body).expect("the projection is json");
        assert_eq!(body["project"], json!(GEMINI_CLI_PROJECT));
        assert_eq!(body["model"], json!(GEMINI_CLI_MODEL));
        assert_eq!(
            body.as_object().expect("an object").keys().count(),
            3,
            "the top level is exactly project, model and request"
        );
        support::drop_blocking(broker);
    }
}

/// The four recorded tier states with a bound project send: the
/// free/default class, the default fallback, the Workspace/Standard class
/// and the absent upstream current-tier id all pass the recorded rule.
#[tokio::test]
async fn gemini_cli_recorded_tier_states_send_with_a_bound_project() {
    for tier in ["free-tier", "legacy-tier", "standard-tier", ""] {
        let server = MockServer::start().await;
        mount_stream(
            &server,
            cloudcode_stream("tier answer", "resp-1", 4, 3, 0, 0),
        )
        .await;
        let config = Config::parse_validated(&gemini_cli_config(&server.uri(), GEMINI_CLI_MODEL))
            .expect("valid");
        let (broker, manifest) = prepared_with(
            gemini_cli_provider(&config, &gemini_cli_profile(GEMINI_CLI_PROJECT, tier)),
            &config,
            WORLD,
            GEMINI_CLI_INPUTS,
        );
        let (broker, ledger, outcome) = dispatch(broker, CountingLedger::new(), manifest);
        let reply = outcome.expect("each recorded tier state sends");
        assert_eq!(reply.text, "tier answer");
        assert_eq!(ledger.failed, 0);
        assert_eq!(
            broker.accounted_requests(),
            1,
            "{tier} records exactly one accounting row"
        );
        support::drop_blocking(broker);
    }
}

/// The recorded tier/project rule denies before the post: a tier outside
/// the default/free and Workspace/Standard classes, a blank project and an
/// Antigravity-shaped stored profile each close one failed settlement row
/// with zero requests and no accounting row.
#[tokio::test]
async fn gemini_cli_tier_and_project_gate_denies_before_the_post() {
    emit_provider_row("AUTH", "google-gemini-cli");
    let server = MockServer::start().await;
    let config = Config::parse_validated(&gemini_cli_config(&server.uri(), GEMINI_CLI_MODEL))
        .expect("valid");

    let (broker, manifest) = prepared_with(
        gemini_cli_provider(
            &config,
            &gemini_cli_profile(GEMINI_CLI_PROJECT, "paid-tier"),
        ),
        &config,
        WORLD,
        GEMINI_CLI_INPUTS,
    );
    let (broker, ledger, outcome) = dispatch(broker, CountingLedger::new(), manifest);
    match outcome {
        Err(ModelError::Provider(ProviderError::UnsendableRequest { connection, reason })) => {
            assert_eq!(connection, GEMINI_CLI);
            assert_eq!(reason, "the stored tier is outside the recorded tier rule");
        }
        other => panic!("the unclassified tier denies typed: {other:?}"),
    }
    assert_eq!(ledger.begun, 1);
    assert_eq!(ledger.finished, 1);
    assert_eq!(ledger.failed, 1);
    assert_eq!(broker.accounted_requests(), 0);
    support::drop_blocking(broker);

    let (broker, manifest) = prepared_with(
        gemini_cli_provider(&config, &gemini_cli_profile("   ", "free-tier")),
        &config,
        WORLD,
        GEMINI_CLI_INPUTS,
    );
    let (broker, ledger, outcome) = dispatch(broker, CountingLedger::new(), manifest);
    match outcome {
        Err(ModelError::Provider(ProviderError::UnsendableRequest { connection, reason })) => {
            assert_eq!(connection, GEMINI_CLI);
            assert_eq!(reason, "the profile project is empty");
        }
        other => panic!("the blank project denies typed: {other:?}"),
    }
    assert_eq!(ledger.failed, 1);
    assert_eq!(broker.accounted_requests(), 0);
    support::drop_blocking(broker);

    // The Antigravity producer's artifact is not this id's profile: the
    // strict reader refuses the foreign envelope before any request.
    let (broker, manifest) = prepared_with(
        gemini_cli_provider(&config, &profile_json(&[(GEMINI_MODEL, "gemini")])),
        &config,
        WORLD,
        GEMINI_CLI_INPUTS,
    );
    let (broker, ledger, outcome) = dispatch(broker, CountingLedger::new(), manifest);
    assert!(
        matches!(
            outcome,
            Err(ModelError::Provider(
                ProviderError::CredentialMalformed { .. }
            ))
        ),
        "the Antigravity-shaped profile is unusable by this id: {outcome:?}"
    );
    assert_eq!(ledger.failed, 1);
    assert_eq!(broker.accounted_requests(), 0);
    assert_eq!(
        server.received_requests().await.expect("recorded").len(),
        0,
        "a denied send puts no request on the wire"
    );
    support::drop_blocking(broker);
}

/// The Gemini CLI id admits the recorded `cloudcode-pa` origin only: the
/// Antigravity daily and sandbox origins and foreign hosts deny typed with
/// zero requests, while the recorded origin reaches the budget check.
#[tokio::test]
async fn gemini_cli_origin_admission_excludes_the_antigravity_origins() {
    for origin in [
        CODE_ASSIST_ORIGIN,
        CODE_ASSIST_SANDBOX_ORIGIN,
        "https://foreign.example.invalid",
    ] {
        let config =
            Config::parse_validated(&gemini_cli_config(origin, GEMINI_CLI_MODEL)).expect("valid");
        // The zero budget makes a guard regression stop at the deadline
        // instead of reaching a foreign host.
        let (provider, store) = gemini_cli_provider_with_deadline(
            &config,
            &gemini_cli_profile(GEMINI_CLI_PROJECT, "standard-tier"),
            Duration::ZERO,
        );
        let (broker, manifest) =
            prepared_with((provider, store), &config, WORLD, GEMINI_CLI_INPUTS);
        let (broker, ledger, outcome) = dispatch(broker, CountingLedger::new(), manifest);
        match outcome {
            Err(ModelError::Provider(ProviderError::CredentialBaseMismatch {
                connection, ..
            })) => assert_eq!(connection, GEMINI_CLI),
            other => panic!("{origin} is outside the Gemini CLI origin set: {other:?}"),
        }
        assert_eq!(ledger.failed, 1);
        assert_eq!(broker.accounted_requests(), 0);
        support::drop_blocking(broker);
    }

    // The recorded production origin is the admitted host: an expired
    // budget proves admission without a live call.
    let config = Config::parse_validated(&gemini_cli_config(GEMINI_CLI_ORIGIN, GEMINI_CLI_MODEL))
        .expect("valid");
    let (provider, store) = gemini_cli_provider_with_deadline(
        &config,
        &gemini_cli_profile(GEMINI_CLI_PROJECT, "free-tier"),
        Duration::ZERO,
    );
    let (broker, manifest) = prepared_with((provider, store), &config, WORLD, GEMINI_CLI_INPUTS);
    let (broker, ledger, outcome) = dispatch(broker, CountingLedger::new(), manifest);
    match outcome {
        Err(ModelError::Provider(ProviderError::Transport { cause, .. })) => assert_eq!(
            cause.class(),
            TransportClass::DeadlineExpired,
            "the recorded origin passed admission and stopped at the budget"
        ),
        other => panic!("the recorded origin must reach the budget check: {other:?}"),
    }
    assert_eq!(ledger.failed, 1);
    assert_eq!(broker.accounted_requests(), 0);
    support::drop_blocking(broker);
}

/// The Antigravity envelope mutant: a frame carrying `requestId`,
/// `userAgent`, `requestType`, `sessionId` or `labels` is a wire violation
/// for this id even beside a valid terminal, so it can never be read as a
/// completed answer or a quota verdict.
#[tokio::test]
async fn gemini_cli_rejects_the_antigravity_envelope_mutant() {
    for member in [
        "requestId",
        "userAgent",
        "requestType",
        "sessionId",
        "labels",
    ] {
        let server = MockServer::start().await;
        let mut chunk = json!({
            "response": {
                "candidates": [{
                    "content": {"role": "model", "parts": []},
                    "finishReason": "STOP",
                    "index": 0,
                }],
                "usageMetadata": {
                    "promptTokenCount": 4,
                    "candidatesTokenCount": 2,
                    "totalTokenCount": 6,
                },
            },
        });
        chunk[member] = if member == "labels" {
            json!({ "trajectory_id": "trajectory-1" })
        } else {
            json!("antigravity")
        };
        let body = format!("data: {}\n\n", chunk);
        mount_stream(&server, body).await;
        let config = Config::parse_validated(&gemini_cli_config(&server.uri(), GEMINI_CLI_MODEL))
            .expect("valid");
        let (broker, manifest) = prepared_with(
            gemini_cli_provider(
                &config,
                &gemini_cli_profile(GEMINI_CLI_PROJECT, "standard-tier"),
            ),
            &config,
            WORLD,
            GEMINI_CLI_INPUTS,
        );
        let (broker, ledger, outcome) = dispatch(broker, CountingLedger::new(), manifest);
        match outcome {
            Err(ModelError::Provider(ProviderError::StreamViolation { connection, reason })) => {
                assert_eq!(connection, GEMINI_CLI);
                assert_eq!(reason, "cloudcode frame carries the antigravity envelope");
            }
            other => panic!("the {member} mutant is never a success: {other:?}"),
        }
        assert_eq!(ledger.failed, 1);
        assert_eq!(broker.accounted_requests(), 0);
        assert_eq!(
            server.received_requests().await.expect("recorded").len(),
            1,
            "the projection is refused on the stream, not by a retry"
        );
        support::drop_blocking(broker);
    }
}

/// A 403 is a transport verdict for this id, never Code Assist quota
/// evidence: one request, no quota probe, zero accounting rows.
#[tokio::test]
async fn an_antigravity_403_never_reads_as_no_quota() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(STREAM_PATH))
        .respond_with(
            ResponseTemplate::new(403).set_body_string(
                json!({"error": {"code": 403, "message": "forbidden"}}).to_string(),
            ),
        )
        .mount(&server)
        .await;
    let config = Config::parse_validated(&gemini_cli_config(&server.uri(), GEMINI_CLI_MODEL))
        .expect("valid");
    let (broker, manifest) = prepared_with(
        gemini_cli_provider(
            &config,
            &gemini_cli_profile(GEMINI_CLI_PROJECT, "standard-tier"),
        ),
        &config,
        WORLD,
        GEMINI_CLI_INPUTS,
    );
    let attempt_id = manifest.attempt_id.clone();
    let (broker, ledger, outcome) = dispatch(broker, CountingLedger::new(), manifest);
    match outcome {
        Err(ModelError::Provider(ProviderError::Transport { cause, .. })) => assert_eq!(
            cause.class(),
            TransportClass::HttpStatus { code: 403 },
            "the peer's 403 stays a transport verdict"
        ),
        other => panic!("a 403 is never a no-quota result: {other:?}"),
    }
    assert_eq!(ledger.begun, 1);
    assert_eq!(ledger.finished, 1);
    assert_eq!(ledger.failed, 1);
    assert_eq!(broker.accounted_requests(), 0);
    assert!(
        broker.accounting_record(&attempt_id).is_none(),
        "a failed 403 send records no accounting row"
    );
    let requests = server.received_requests().await.expect("recorded");
    assert_eq!(requests.len(), 1, "the 403 never triggers a second leg");
    assert_eq!(requests[0].url.path(), STREAM_PATH);
    assert!(
        requests
            .iter()
            .all(|request| !request.url.path().contains("retrieveUserQuota")),
        "this id makes no quota call"
    );
    support::drop_blocking(broker);
}
