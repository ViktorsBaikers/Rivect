//! Cancellation must interrupt the POST, not discard a reply after the peer sends it.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use rivect::config::Config;
use rivect::model::{
    Broker, Ledger, LedgerError, ModelError, NullLedger, RequestManifest, SendContext, SendOutcome,
    SendTicket,
};
use rivect::providers::{CredentialStore, ProviderError, StoreKind, configured_provider};

mod support;

#[derive(Default)]
struct ObservedLedger {
    entries: usize,
    finishes: Vec<SendOutcome>,
}

impl Ledger for ObservedLedger {
    fn begin_send(
        &mut self,
        context: &SendContext,
        manifest: &RequestManifest,
    ) -> Result<SendTicket, LedgerError> {
        self.entries += 1;
        NullLedger.begin_send(context, manifest)
    }

    fn finish_send(
        &mut self,
        _ticket: &SendTicket,
        outcome: &SendOutcome,
    ) -> Result<(), LedgerError> {
        self.finishes.push(*outcome);
        Ok(())
    }

    fn record_reasoning_drop(
        &mut self,
        ticket: &SendTicket,
        count: u64,
    ) -> Result<(), LedgerError> {
        NullLedger.record_reasoning_drop(ticket, count)
    }
}

fn receive_post(stream: &mut TcpStream) -> io::Result<()> {
    let mut request = BufReader::new(stream);
    let mut line = String::new();
    request.read_line(&mut line)?;
    assert_eq!(line, "POST /v1/messages HTTP/1.1\r\n");
    let mut length = None;
    loop {
        line.clear();
        if request.read_line(&mut line)? == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        if line == "\r\n" {
            break;
        }
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            length = Some(value.trim().parse::<u64>().map_err(io::Error::other)?);
        }
    }
    let length = length.ok_or_else(|| io::Error::other("missing POST length"))?;
    assert!(length > 0);
    assert_eq!(
        io::copy(&mut request.take(length), &mut io::sink())?,
        length
    );
    Ok(())
}

#[test]
fn cancel_closes_post_before_response_and_spends_admission()
-> Result<(), Box<dyn std::error::Error>> {
    interrupted(false)
}

#[test]
fn cancel_closes_unfinished_sse_body() -> Result<(), Box<dyn std::error::Error>> {
    interrupted(true)
}

fn interrupted(send_headers: bool) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let port = listener.local_addr()?.port();
    let config = Config::parse_validated(&format!(
        r#"config_version = 1
[connections.anthropic]
kind = "api_key"
endpoint = "http://127.0.0.1:{port}/v1"
credential_ref = "keyring:rivect-test/anthropic"
[models.defaults]
model = {{ mode = "fixed", connection = "anthropic", model_id = "claude-opus-4-8" }}
effort = {{ mode = "auto" }}
fallback = {{ mode = "manual" }}
"#
    ))?;
    let store: Arc<dyn CredentialStore> = Arc::new(support::MapStore::seeded(
        StoreKind::Keychain,
        &[("keyring:rivect-test/anthropic", "fixture-only")],
    ));
    let mut broker = Broker::new(configured_provider(&config, &store)?.provider);
    let world = "/world/cancel";
    let manifest = broker.prepare("main", &config, world, "fixture")?;
    let cancel = AtomicBool::new(false);
    let mut ledger = ObservedLedger::default();
    listener.set_nonblocking(true)?;
    let (result, closed) = std::thread::scope(|scope| -> io::Result<_> {
        let peer = scope.spawn(|| -> io::Result<bool> {
            let end = Instant::now() + Duration::from_secs(5);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock && Instant::now() < end => std::thread::sleep(Duration::from_millis(2)),
                    Err(err) => return Err(err),
                }
            };
            stream.set_nonblocking(false)?;
            stream.set_read_timeout(Some(Duration::from_secs(2)))?;
            receive_post(&mut stream)?;
            if send_headers {
                stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n: keep-alive\n\n")?;
            }
            cancel.store(true, Ordering::Release);
            match stream.read(&mut [0]) {
                Ok(0) => Ok(true),
                Err(err) if err.kind() == io::ErrorKind::ConnectionReset => Ok(true),
                Err(err) if matches!(err.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {
                    if !send_headers {
                        stream.write_all(b"HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")?;
                    }
                    Ok(false)
                }
                Ok(_) => Err(io::Error::other("unexpected bytes after POST")),
                Err(err) => Err(err),
            }
        });
        let result = broker.dispatch_with_cancel(&mut ledger, world, &manifest, Some(&cancel));
        Ok((
            result,
            peer.join()
                .map_err(|_panic| io::Error::other("peer panicked"))??,
        ))
    })?;
    assert!(closed, "client kept cancelled POST open until response");
    assert!(matches!(
        result,
        Err(ModelError::Provider(ProviderError::Interrupted { .. }))
    ));
    assert_eq!(ledger.entries, 1);
    assert_eq!(ledger.finishes, [SendOutcome::Failed { wire_retries: 0 }]);
    assert_eq!(broker.accounted_requests(), 0);
    assert!(matches!(
        broker.dispatch(&mut NullLedger, world, &manifest),
        Err(ModelError::AttemptCancelled { .. })
    ));
    let next = broker.prepare("main", &config, world, "cancel before reservation")?;
    assert!(matches!(
        broker.dispatch_with_cancel(&mut ledger, world, &next, Some(&cancel)),
        Err(ModelError::AttemptCancelled { .. })
    ));
    assert_eq!(ledger.entries, 1);
    assert!(matches!(listener.accept(), Err(err) if err.kind() == io::ErrorKind::WouldBlock));
    Ok(())
}

/// Regression for the silent-stream hang (v0.1.24): the async client
/// request timeout ends at the headers, so a peer that answers `200`
/// and then never sends a byte parked the foreground dispatch forever
/// — the user-visible "streaming" that never completes. Each body read
/// must carry the remaining send budget itself.
#[test]
fn a_silent_sse_body_trips_the_send_deadline() -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let port = listener.local_addr()?.port();
    let config = Config::parse_validated(&format!(
        r#"config_version = 1
[connections.anthropic]
kind = "api_key"
endpoint = "http://127.0.0.1:{port}/v1"
credential_ref = "keyring:rivect-test/anthropic"
[models.defaults]
model = {{ mode = "fixed", connection = "anthropic", model_id = "claude-opus-4-8" }}
effort = {{ mode = "auto" }}
fallback = {{ mode = "off" }}
"#
    ))?;
    let store: Arc<dyn CredentialStore> = Arc::new(support::MapStore::seeded(
        StoreKind::Keychain,
        &[("keyring:rivect-test/anthropic", "fixture-only")],
    ));
    let provider = rivect::providers::anthropic::MessagesProvider::with_deadline(
        &config,
        "anthropic",
        store,
        Duration::from_secs(2),
    )?;
    let mut broker = Broker::new(Box::new(provider));
    let world = "/world/stall";
    let manifest = broker.prepare("main", &config, world, "fixture")?;
    let cancel = Arc::new(AtomicBool::new(false));
    // The detached worker lets the test prove the dispatch returned:
    // without the bound this call never yields, and a scoped join would
    // hang the suite instead of failing it.
    let worker_cancel = Arc::clone(&cancel);
    let (report, outcome) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("stalled-stream-dispatch".to_string())
        .spawn(move || {
            let mut ledger = NullLedger;
            let result = broker.dispatch_with_cancel(
                &mut ledger,
                world,
                &manifest,
                Some(worker_cancel.as_ref()),
            );
            let _dropped = report.send(result);
        })?;
    let (mut stream, _) = listener.accept()?;
    stream.set_read_timeout(Some(Duration::from_secs(15)))?;
    receive_post(&mut stream)?;
    stream.write_all(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n: keep-alive\n\n",
    )?;
    let reply = outcome.recv_timeout(Duration::from_secs(30))?;
    assert!(
        matches!(
            reply,
            Err(ModelError::Provider(ProviderError::Transport { .. }))
        ),
        "the stalled stream must end on the send deadline, got {reply:?}"
    );
    Ok(())
}
