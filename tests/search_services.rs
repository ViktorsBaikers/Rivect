//! Five recorded search services (TD-19): every service answers AUTH, RESULT
//! and RECOVERY through the typed `docs.search` entry against loopback peers,
//! with one physical attempt per request. A wrong origin/profile, a missing
//! connection/key and an unknown selector refuse before any transport; a
//! query-key credential is redacted from plans, errors, results and Debug.
//! `docs.status` stays a pure read and is asserted separately in `tests/docs.rs`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::let_underscore_must_use,
    let_underscore_drop,
    reason = "test assertions fail loudly with the observed payload; src/ stays strict (standards §14)"
)]

mod support;

use rivect::config::Config;
use rivect::contracts::SessionId;
use rivect::docs::{
    SEARCH_MAX_LIMIT, SEARCH_PROFILES, SEARCH_REDACTED, SEARCH_RESPONSE_MAX_BYTES, SearchAuth,
    SearchError, SearchRequest, search, search_plan, search_profile,
};
use rivect::providers::{CredentialStore, ProviderError, SecretRef, StoreKind};
use rivect::tools::LocalKind;
use rivect::verification::SEARCH_SERVICES;
use serde_json::{Value, json};
use sha2::Digest;
use std::collections::{BTreeMap, VecDeque};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// An offline credential store that counts every resolve, so a refusal before
/// the credential read is observable as zero.
struct CountingStore {
    kind: StoreKind,
    secrets: Mutex<BTreeMap<String, Vec<u8>>>,
    resolves: AtomicU64,
}

impl CountingStore {
    fn seeded(entries: &[(&str, &str)]) -> Self {
        let secrets = entries
            .iter()
            .map(|(raw, secret)| {
                let credential = SecretRef::parse(raw).expect("seed is a scoped ref");
                (credential.scope().to_string(), secret.as_bytes().to_vec())
            })
            .collect();
        Self {
            kind: StoreKind::Keychain,
            secrets: Mutex::new(secrets),
            resolves: AtomicU64::new(0),
        }
    }

    fn resolves(&self) -> u64 {
        self.resolves.load(Ordering::SeqCst)
    }
}

impl CredentialStore for CountingStore {
    fn kind(&self) -> StoreKind {
        self.kind
    }

    fn occupied(&self, credential: &SecretRef) -> Result<bool, ProviderError> {
        Ok(self
            .secrets
            .lock()
            .expect("store lock")
            .contains_key(credential.scope()))
    }

    fn entry_accounts(&self, service: &str) -> Result<Vec<String>, ProviderError> {
        Ok(self
            .secrets
            .lock()
            .expect("store lock")
            .keys()
            .filter(|scope| scope.as_str() == service || scope.starts_with(&format!("{service}/")))
            .cloned()
            .collect())
    }

    fn login(&self, credential: &SecretRef, secret: &[u8]) -> Result<(), ProviderError> {
        self.secrets
            .lock()
            .expect("store lock")
            .insert(credential.scope().to_string(), secret.to_vec());
        Ok(())
    }

    fn resolve(&self, credential: &SecretRef) -> Result<Vec<u8>, ProviderError> {
        self.resolves.fetch_add(1, Ordering::SeqCst);
        self.secrets
            .lock()
            .expect("store lock")
            .get(credential.scope())
            .cloned()
            .ok_or_else(|| ProviderError::CredentialAbsent {
                scope: credential.scope().to_string(),
            })
    }

    fn refresh(&self, credential: &SecretRef, secret: &[u8]) -> Result<(), ProviderError> {
        self.secrets
            .lock()
            .expect("store lock")
            .insert(credential.scope().to_string(), secret.to_vec());
        Ok(())
    }

    fn revoke(&self, credential: &SecretRef) -> Result<(), ProviderError> {
        self.secrets
            .lock()
            .expect("store lock")
            .remove(credential.scope())
            .map(|_| ())
            .ok_or_else(|| ProviderError::CredentialAbsent {
                scope: credential.scope().to_string(),
            })
    }

    fn logout(&self, credential: &SecretRef) -> Result<(), ProviderError> {
        self.revoke(credential)
    }
}

/// One scripted HTTP reply.
struct Reply {
    status: u16,
    headers: Vec<(&'static str, String)>,
    body: String,
}

impl Reply {
    fn json(value: &Value) -> Self {
        Self {
            status: 200,
            headers: vec![("content-type", "application/json".to_string())],
            body: value.to_string(),
        }
    }

    fn status(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: String::new(),
        }
    }

    fn redirect() -> Self {
        Self {
            status: 302,
            headers: vec![("location", "http://127.0.0.1:1/elsewhere".to_string())],
            body: String::new(),
        }
    }
}

/// One request a loopback peer observed.
#[derive(Debug, Clone)]
struct Recorded {
    method: String,
    target: String,
    headers: BTreeMap<String, String>,
    body: String,
}

impl Recorded {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }
}

/// A loopback peer that answers one scripted reply per accepted connection.
struct Peer {
    address: SocketAddr,
    endpoint: String,
    requests: Arc<Mutex<Vec<Recorded>>>,
    attempts: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Peer {
    fn start(replies: Vec<Reply>) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind the search peer");
        let address = listener.local_addr().expect("peer address");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let attempts = Arc::new(AtomicU64::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_requests = Arc::clone(&requests);
        let thread_attempts = Arc::clone(&attempts);
        let thread_stop = Arc::clone(&stop);
        let handle = std::thread::spawn(move || {
            let mut replies: VecDeque<Reply> = replies.into();
            loop {
                let Ok((mut stream, _)) = listener.accept() else {
                    return;
                };
                if thread_stop.load(Ordering::SeqCst) {
                    return;
                }
                thread_attempts.fetch_add(1, Ordering::SeqCst);
                let Some(recorded) = read_http(&mut stream) else {
                    continue;
                };
                thread_requests.lock().expect("request lock").push(recorded);
                let reply = replies.pop_front().unwrap_or_else(|| Reply::status(500));
                write_reply(&mut stream, &reply);
            }
        });
        Self {
            address,
            endpoint: format!("http://{address}"),
            requests,
            attempts,
            stop,
            handle: Some(handle),
        }
    }

    fn attempts(&self) -> u64 {
        self.attempts.load(Ordering::SeqCst)
    }

    fn requests(&self) -> Vec<Recorded> {
        self.requests.lock().expect("request lock").clone()
    }

    fn only_request(&self) -> Recorded {
        let requests = self.requests();
        assert_eq!(requests.len(), 1, "one physical request: {requests:?}");
        requests.into_iter().next().expect("one request")
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Ok(stream) = TcpStream::connect(self.address) {
            drop(stream);
        }
        if let Some(handle) = self.handle.take() {
            let joined = handle.join();
            drop(joined);
        }
    }
}

/// A bound loopback listener with no accept loop: a connection attempt would
/// sit in the backlog, so a nonblocking accept proves whether one happened.
struct SilentPeer {
    listener: TcpListener,
    endpoint: String,
}

impl SilentPeer {
    fn start() -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind the silent peer");
        let endpoint = format!(
            "http://{}",
            listener.local_addr().expect("silent peer address")
        );
        Self { listener, endpoint }
    }

    fn assert_no_connection(&self) {
        self.listener
            .set_nonblocking(true)
            .expect("nonblocking accept");
        match self.listener.accept() {
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Ok(_) => panic!("a refused request still opened a connection"),
            Err(error) => panic!("silent peer accept failed: {error}"),
        }
    }
}

/// A peer that accepts the request, records it, and then stalls past the
/// whole deadline without writing an answer.
struct StallingPeer {
    address: SocketAddr,
    endpoint: String,
    attempts: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl StallingPeer {
    fn start() -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind the stalling peer");
        let address = listener.local_addr().expect("stalling peer address");
        let attempts = Arc::new(AtomicU64::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_attempts = Arc::clone(&attempts);
        let thread_stop = Arc::clone(&stop);
        let handle = std::thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            thread_attempts.fetch_add(1, Ordering::SeqCst);
            let _ = read_http(&mut stream);
            for _ in 0..70 {
                if thread_stop.load(Ordering::SeqCst) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        });
        Self {
            address,
            endpoint: format!("http://{address}"),
            attempts,
            stop,
            handle: Some(handle),
        }
    }

    fn attempts(&self) -> u64 {
        self.attempts.load(Ordering::SeqCst)
    }
}

impl Drop for StallingPeer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Ok(stream) = TcpStream::connect(self.address) {
            drop(stream);
        }
        if let Some(handle) = self.handle.take() {
            let joined = handle.join();
            drop(joined);
        }
    }
}

fn read_http(stream: &mut TcpStream) -> Option<Recorded> {
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .ok()?;
    let mut reader = BufReader::new(stream.try_clone().ok()?);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();
    let mut headers = BTreeMap::new();
    let mut content_length = 0usize;
    loop {
        let mut header = String::new();
        reader.read_line(&mut header).ok()?;
        if header.trim_end().is_empty() {
            break;
        }
        if let Some((name, value)) = header.split_once(':') {
            let name = name.trim().to_ascii_lowercase();
            let value = value.trim().to_string();
            if name == "content-length" {
                content_length = value.parse().ok()?;
            }
            headers.insert(name, value);
        }
    }
    let mut body = vec![0u8; content_length];
    reader.read_exact(&mut body).ok()?;
    Some(Recorded {
        method,
        target,
        headers,
        body: String::from_utf8_lossy(&body).into_owned(),
    })
}

fn write_reply(stream: &mut TcpStream, reply: &Reply) {
    let body = reply.body.as_bytes();
    let mut head = format!(
        "HTTP/1.1 {} Rivect\r\ncontent-length: {}\r\nconnection: close\r\n",
        reply.status,
        body.len()
    );
    for (name, value) in &reply.headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    let _ = stream
        .write_all(head.as_bytes())
        .and_then(|()| stream.write_all(body))
        .and_then(|()| stream.flush());
}

fn connection_row(
    service: &str,
    endpoint: &str,
    credential_ref: Option<&str>,
    profile: Option<&str>,
) -> String {
    let mut row = format!(
        "[connections.\"search.{service}\"]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\n"
    );
    if let Some(reference) = credential_ref {
        row.push_str(&format!("credential_ref = \"{reference}\"\n"));
    }
    if let Some(profile) = profile {
        row.push_str(&format!("profile = \"{profile}\"\n"));
    }
    row
}

fn config_with(rows: &[String]) -> Config {
    let document = format!("{}\n{}", support::base_config(), rows.concat());
    rivect::config::resolve_effective(Some(&document))
        .expect("the search fixture config validates")
        .composed()
}

fn request(service: &str, query: &str, limit: usize) -> SearchRequest {
    SearchRequest {
        schema_version: 1,
        session_id: "search-session".to_string(),
        service: service.to_string(),
        query: query.to_string(),
        limit,
    }
}

fn hit(profile_id: &str, index: usize, echoed_key: Option<&str>) -> Value {
    let profile = search_profile(profile_id).expect("recorded profile");
    let suffix = match echoed_key {
        Some(key) => format!("{key}/{index}"),
        None => index.to_string(),
    };
    json!({
        "title": format!("{profile_id} source {suffix}"),
        "url": format!("https://{profile_id}.example/{suffix}"),
        profile.snippet_field: format!("{profile_id} snippet {suffix}"),
    })
}

fn results_reply(profile_id: &str, hits: &[Value]) -> Reply {
    let profile = search_profile(profile_id).expect("recorded profile");
    let mut body = serde_json::Map::new();
    body.insert(
        profile.results_field.to_string(),
        Value::Array(hits.to_vec()),
    );
    Reply::json(&Value::Object(body))
}

#[test]
fn recorded_profiles_match_the_conformance_roster() {
    assert_eq!(
        SEARCH_PROFILES
            .iter()
            .map(|profile| profile.id)
            .collect::<Vec<_>>(),
        SEARCH_SERVICES,
        "the owner's table and the counted roster are one list"
    );
    for profile in &SEARCH_PROFILES {
        assert!(
            profile.endpoint.starts_with("https://"),
            "{profile:?} is an https endpoint"
        );
        assert!(
            matches!(profile.method, "GET" | "POST"),
            "{profile:?} records its method"
        );
        assert!(
            matches!(
                profile.auth,
                SearchAuth::Bearer | SearchAuth::XApiKey | SearchAuth::QueryKey
            ),
            "{profile:?} records one admitted auth shape"
        );
    }
    assert_eq!(search_profile("bing"), None);
}

#[test]
fn search_services_authenticate_five_recorded_profiles() {
    for service in SEARCH_SERVICES {
        let profile = search_profile(service).expect("recorded profile");
        let peer = Peer::start(vec![results_reply(service, &[hit(service, 0, None)])]);
        let reference = format!("keyring:search/{service}");
        let config = config_with(&[connection_row(
            service,
            &peer.endpoint,
            Some(&reference),
            None,
        )]);
        let store = CountingStore::seeded(&[(&reference, &format!("key-{service}"))]);
        let answer = search(
            &request(service, &format!("auth {service}"), 1),
            &config,
            &store,
        )
        .expect("the loopback AUTH leg answers");
        assert_eq!(answer.kind, "docs.search", "{answer:?}");
        assert_eq!(answer.service, service);
        assert_eq!(answer.attempts, 1);
        assert_eq!(store.resolves(), 1, "one scoped resolve per attempt");
        assert_eq!(peer.attempts(), 1, "one physical request for {service}");
        let recorded = peer.only_request();
        assert_eq!(recorded.method, profile.method);
        if profile.method == "POST" {
            assert!(
                recorded.body.contains(&format!("auth {service}")),
                "the POST body carries the query: {}",
                recorded.body
            );
        }
        match profile.auth {
            SearchAuth::Bearer => {
                assert_eq!(
                    recorded.header("authorization"),
                    Some(format!("Bearer key-{service}").as_str())
                );
            }
            SearchAuth::XApiKey => {
                assert_eq!(
                    recorded.header("x-api-key"),
                    Some(format!("key-{service}").as_str())
                );
            }
            SearchAuth::QueryKey => {
                assert!(
                    recorded.target.contains(&format!("api_key=key-{service}")),
                    "the query key rides the request: {}",
                    recorded.target
                );
                assert_eq!(recorded.header("authorization"), None);
            }
        }
        let wire = serde_json::to_value(&answer).expect("the answer encodes");
        assert!(
            !wire.to_string().contains(&format!("key-{service}")),
            "the credential never enters the result: {wire}"
        );
        println!("ROW TP-SEARCH-{service}-AUTH ok");
    }
}

#[test]
fn search_services_return_bounded_cited_results() {
    for service in SEARCH_SERVICES {
        let hits = [
            hit(service, 0, None),
            hit(service, 1, None),
            hit(service, 2, None),
        ];
        let peer = Peer::start(vec![results_reply(service, &hits)]);
        let reference = format!("keyring:search/{service}");
        let config = config_with(&[connection_row(
            service,
            &peer.endpoint,
            Some(&reference),
            None,
        )]);
        let store = CountingStore::seeded(&[(&reference, "result-key")]);
        let query = format!("result {service}");
        let answer = search(&request(service, &query, 2), &config, &store)
            .expect("the loopback RESULT leg answers");
        assert_eq!(answer.attempts, 1, "one physical attempt");
        assert_eq!(peer.attempts(), 1, "one request reached the peer");
        assert_eq!(answer.results.len(), 2, "the requested bound is kept");
        assert!(
            answer.truncated,
            "a third upstream hit is declared truncated"
        );
        assert_eq!(
            answer.query_sha256,
            rivect::config::hex(&sha2::Sha256::digest(query.as_bytes())),
            "the query digest is the caller's bytes"
        );
        for result in &answer.results {
            assert!(result.url.starts_with("https://"), "{result:?}");
            assert!(!result.title.is_empty(), "{result:?}");
            assert!(!result.snippet.is_empty(), "{result:?}");
        }
        let wire = serde_json::to_value(&answer).expect("the answer encodes");
        assert_eq!(wire["kind"], "docs.search", "{wire}");
        assert_eq!(wire["service"], service, "{wire}");
        for key in ["package", "version", "body", "status"] {
            assert!(
                wire.get(key).is_none(),
                "a search result is never a SourceDoc: {wire}"
            );
        }
        let profile_answer = &wire["results"][0];
        assert_eq!(profile_answer["title"], hits[0]["title"], "{wire}");
        assert_eq!(profile_answer["url"], hits[0]["url"], "{wire}");
        let keys: std::collections::BTreeSet<&str> = profile_answer
            .as_object()
            .expect("a hit object")
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            ["snippet", "title", "url"].into_iter().collect(),
            "a hit is normalized to title/url/snippet: {wire}"
        );
        assert!(profile_answer["snippet"].as_str().is_some(), "{wire}");
        println!("ROW TP-SEARCH-{service}-RESULT ok");
    }
    assert_eq!(SEARCH_MAX_LIMIT, 20);
}

#[test]
fn search_services_recover_with_typed_bounded_errors() {
    for service in SEARCH_SERVICES {
        let replies = vec![
            Reply::status(401),
            Reply::status(429),
            Reply::status(503),
            Reply::redirect(),
            Reply {
                status: 200,
                headers: vec![("content-type", "application/json".to_string())],
                body: r#"{"results":"not an array"}"#.to_string(),
            },
            Reply {
                status: 200,
                headers: vec![("content-type", "application/json".to_string())],
                body: "x".repeat(SEARCH_RESPONSE_MAX_BYTES + 1),
            },
        ];
        let peer = Peer::start(replies);
        let reference = format!("keyring:search/{service}");
        let config = config_with(&[connection_row(
            service,
            &peer.endpoint,
            Some(&reference),
            None,
        )]);
        let store = CountingStore::seeded(&[(&reference, "recovery-key")]);
        let failures = [
            SearchError::Denied { status: 401 },
            SearchError::QuotaExhausted,
            SearchError::Upstream { status: 503 },
            SearchError::RedirectRefused {
                service: service.to_string(),
            },
            SearchError::Malformed,
            SearchError::TooLarge {
                limit: SEARCH_RESPONSE_MAX_BYTES,
            },
        ];
        for expected in &failures {
            let error = search(
                &request(service, &format!("recovery {service}"), 1),
                &config,
                &store,
            )
            .expect_err("the RECOVERY leg is non-success");
            assert_eq!(&error, expected, "{service} answered {error}");
            assert_eq!(error.code(), expected.code());
        }
        assert_eq!(
            peer.attempts(),
            failures.len() as u64,
            "each typed failure is one physical attempt, and a redirect is never followed"
        );
        println!("ROW TP-SEARCH-{service}-RECOVERY ok");
    }
}

#[test]
fn wrong_origin_and_profile_refuse_before_any_attempt() {
    // The endpoint is outside the recorded profile origin: refused before the
    // credential is even resolved.
    let reference = "keyring:search/exa";
    let config = config_with(&[connection_row(
        "exa",
        "https://search.other.example/v1",
        Some(reference),
        None,
    )]);
    let store = CountingStore::seeded(&[(reference, "origin-key")]);
    let error = search(&request("exa", "wrong origin", 1), &config, &store)
        .expect_err("an unrecorded origin denies");
    assert_eq!(
        error,
        SearchError::WrongOrigin {
            service: "exa".to_string()
        }
    );
    assert_eq!(store.resolves(), 0, "no credential read before the refusal");

    // The credential's own origin leg names another host than the loopback
    // endpoint: no physical request is made.
    let silent = SilentPeer::start();
    let reference = "keyring:search/other.example/exa";
    let config = config_with(&[connection_row(
        "exa",
        &silent.endpoint,
        Some(reference),
        None,
    )]);
    let store = CountingStore::seeded(&[(reference, "origin-key")]);
    let error = search(&request("exa", "wrong origin", 1), &config, &store)
        .expect_err("a mismatched credential origin denies");
    assert_eq!(
        error,
        SearchError::WrongOrigin {
            service: "exa".to_string()
        }
    );
    silent.assert_no_connection();

    // A profile-bound ref whose trailing scope names another profile is the
    // same typed refusal before the store is read.
    let silent = SilentPeer::start();
    let reference = "keyring:search/exa";
    let config = config_with(&[
        connection_row("exa", &silent.endpoint, Some(reference), Some("search-exa")),
        format!("[profiles.search-exa]\ncredential_ref = \"{reference}\"\n"),
    ]);
    let store = CountingStore::seeded(&[(reference, "origin-key")]);
    let error = search(&request("exa", "wrong profile", 1), &config, &store)
        .expect_err("a profile mismatch denies");
    assert_eq!(
        error,
        SearchError::WrongOrigin {
            service: "exa".to_string()
        }
    );
    assert_eq!(store.resolves(), 0, "no store read for a profile mismatch");
    silent.assert_no_connection();
}

#[test]
fn missing_connection_and_key_are_missing_credential() {
    let silent = SilentPeer::start();
    let store = CountingStore::seeded(&[]);
    let error = search(
        &request("exa", "missing connection", 1),
        &config_with(&[]),
        &store,
    )
    .expect_err("an undeclared connection is missing");
    assert_eq!(
        error,
        SearchError::MissingCredential {
            service: "exa".to_string()
        }
    );
    assert_eq!(store.resolves(), 0);
    silent.assert_no_connection();

    let reference = "keyring:search/exa";
    let config = config_with(&[connection_row(
        "exa",
        &silent.endpoint,
        Some(reference),
        None,
    )]);
    let error = search(&request("exa", "absent material", 1), &config, &store)
        .expect_err("an empty store scope is missing");
    assert_eq!(
        error,
        SearchError::MissingCredential {
            service: "exa".to_string()
        }
    );
    assert_eq!(store.resolves(), 1, "the store was asked exactly once");
    silent.assert_no_connection();

    // The direct-source baseline never depends on a search connection.
    assert_eq!(
        rivect::docs::status(),
        rivect::docs::status_for(&rivect::docs::Cache::default())
    );
}

#[test]
fn query_key_auth_redacts_the_key_everywhere() {
    let service = "kagi";
    let profile = search_profile(service).expect("recorded profile");
    let key = "kagi-secret-query-key";
    let peer = Peer::start(vec![results_reply(service, &[hit(service, 0, Some(key))])]);
    let reference = format!("keyring:search/{service}");
    let config = config_with(&[connection_row(
        service,
        &peer.endpoint,
        Some(&reference),
        None,
    )]);
    let store = CountingStore::seeded(&[(&reference, key)]);
    let request = request(service, "redaction", 1);
    let plan = search_plan(profile, &peer.endpoint, &request).expect("the plan builds");
    assert!(
        plan.url().contains(&format!("api_key={SEARCH_REDACTED}")),
        "the plan renders the redacted key: {}",
        plan.url()
    );
    let debug = format!("{plan:?}");
    assert!(!debug.contains(key), "Debug never carries the key: {debug}");
    assert!(debug.contains(SEARCH_REDACTED), "{debug}");

    let answer = search(&request, &config, &store).expect("the loopback answer serves");
    let wire = serde_json::to_value(&answer).expect("the answer encodes");
    assert!(
        !wire.to_string().contains(key),
        "results never echo the key: {wire}"
    );
    assert!(
        wire.to_string().contains(SEARCH_REDACTED),
        "an echoed key is replaced: {wire}"
    );
    let recorded = peer.only_request();
    assert!(
        recorded.target.contains(key),
        "the request itself carries the key: {}",
        recorded.target
    );

    // A typed upstream failure is equally key-free.
    let peer = Peer::start(vec![Reply::status(403)]);
    let config = config_with(&[connection_row(
        service,
        &peer.endpoint,
        Some(&reference),
        None,
    )]);
    let error = search(&request, &config, &store).expect_err("403 denies");
    assert_eq!(error, SearchError::Denied { status: 403 });
    assert!(!error.to_string().contains(key), "{error}");
    assert!(!format!("{error:?}").contains(key), "{error:?}");
}

#[test]
fn timeout_is_typed_and_bounded_by_the_recorded_deadline() {
    let service = "perplexity";
    let peer = StallingPeer::start();
    let reference = format!("keyring:search/{service}");
    let config = config_with(&[connection_row(
        service,
        &peer.endpoint,
        Some(&reference),
        None,
    )]);
    let store = CountingStore::seeded(&[(&reference, "timeout-key")]);
    let started = Instant::now();
    let error = search(&request(service, "timeout", 1), &config, &store)
        .expect_err("a stalled peer times out");
    let elapsed = started.elapsed();
    assert_eq!(error, SearchError::Timeout);
    assert_eq!(
        error.code(),
        rivect::contracts::ErrorCode::DependencyBlocked
    );
    assert_eq!(peer.attempts(), 1, "one physical attempt");
    assert!(
        elapsed >= Duration::from_secs(4),
        "the whole-call deadline was applied: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(8),
        "the deadline is bounded, not open: {elapsed:?}"
    );
}

#[test]
fn invalid_requests_are_typed_before_any_read() {
    let store = CountingStore::seeded(&[]);
    let config = config_with(&[]);
    let cases = [
        (
            SearchRequest {
                schema_version: 2,
                ..request("exa", "x", 1)
            },
            SearchError::InvalidRequest {
                field: "schema_version",
            },
        ),
        (
            SearchRequest {
                session_id: String::new(),
                ..request("exa", "x", 1)
            },
            SearchError::InvalidRequest {
                field: "session_id",
            },
        ),
        (
            request("exa", "   ", 1),
            SearchError::InvalidRequest { field: "query" },
        ),
        (
            request("exa", "x", 0),
            SearchError::InvalidRequest { field: "limit" },
        ),
        (
            request("exa", "x", SEARCH_MAX_LIMIT + 1),
            SearchError::InvalidRequest { field: "limit" },
        ),
    ];
    for (request, expected) in cases {
        let error = search(&request, &config, &store).expect_err("the invalid request is refused");
        assert_eq!(error, expected);
    }
    let long = "x".repeat(4097);
    let error = search(&request("exa", &long, 1), &config, &store)
        .expect_err("an oversized query is refused");
    assert_eq!(
        error,
        SearchError::TooLarge {
            limit: rivect::docs::SEARCH_QUERY_MAX_BYTES
        }
    );
    assert_eq!(store.resolves(), 0, "no credential read for a bad request");
}

fn search_frame(id: u64, session: &SessionId, extra: Value) -> Value {
    let mut params = json!({"schema_version": 1, "session_id": session});
    if let Some(fields) = extra.as_object() {
        for (key, value) in fields {
            params[key] = value.clone();
        }
    }
    json!({"jsonrpc": "2.0", "id": id, "method": "docs.search", "params": params})
}

#[test]
fn docs_search_rpc_serves_one_recorded_service_and_adds_no_catalog_row() {
    let peer = Peer::start(vec![results_reply("tavily", &[hit("tavily", 0, None)])]);
    let reference = "keyring:search/tavily";
    let document = format!(
        "{}\n{}",
        support::base_config(),
        connection_row("tavily", &peer.endpoint, Some(reference), None)
    );
    let mut world = support::open_world("search-rpc", Some(&document));
    let store = Arc::new(CountingStore::seeded(&[(reference, "rpc-key")]));
    world.runtime.search_credentials = Some(store.clone());
    let session = world.open_session("search-rpc-session");
    let response = world.dispatch(&search_frame(
        1,
        &session,
        json!({"service": "tavily", "query": "rpc result", "limit": 1}),
    ));
    assert!(response.get("error").is_none(), "{response}");
    assert_eq!(response["result"]["kind"], "docs.search", "{response}");
    assert_eq!(response["result"]["service"], "tavily", "{response}");
    assert_eq!(response["result"]["attempts"], 1, "{response}");
    assert_eq!(store.resolves(), 1);
    assert_eq!(peer.attempts(), 1);
    assert_eq!(
        rivect::tools::local_command_kind("docs.search"),
        LocalKind::Unknown,
        "docs.search is a JSON-RPC method, never a catalog row"
    );
    assert!(
        !rivect::tools::CATALOG
            .iter()
            .any(|row| row.canonical_id == "docs.search"),
        "the catalog keeps its 36 rows"
    );

    let unknown = world.dispatch(&search_frame(
        2,
        &session,
        json!({"service": "bing", "query": "x", "limit": 1}),
    ));
    assert_eq!(
        unknown["error"]["data"]["code"], "invalid_input",
        "{unknown}"
    );
    assert_eq!(
        store.resolves(),
        1,
        "an unknown service reads no credential"
    );
    assert_eq!(peer.attempts(), 1, "an unknown service sends nothing");

    let absent = world.dispatch(&search_frame(3, &session, json!({"query": "x"})));
    assert_eq!(absent["error"]["data"]["code"], "invalid_input", "{absent}");
    assert_eq!(store.resolves(), 1, "an absent service reads no credential");
    assert_eq!(peer.attempts(), 1, "an absent service sends nothing");

    let bespoke = world.dispatch(&search_frame(
        4,
        &session,
        json!({"service": "tavily", "query": "x", "limit": 0}),
    ));
    assert_eq!(
        bespoke["error"]["data"]["code"], "invalid_input",
        "{bespoke}"
    );
    assert_eq!(store.resolves(), 1);
    assert_eq!(peer.attempts(), 1);
}
