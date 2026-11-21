//! The loopback redirect capture a browser sign-in uses instead of asking the
//! operator to paste the callback URL.
//!
//! One listener is started per pending browser leg, bound to the recorded
//! callback host and port. It accepts exactly one request on the recorded
//! path, answers a static page, and retains the redirect URL for the pending
//! `auth.login.complete`. The leg's own state check runs later: a forged or
//! late callback is refused there, never here.
//!
//! The listener is opt-in and bounded: a bind failure leaves the leg on the
//! paste fallback, every connection has a read deadline, the accepted request
//! is size-capped, and the whole wait ends with the pending leg. No request
//! bytes are echoed to the page, so the response carries no reflected input.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, sync_channel};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use super::login_catalog::Callback;

/// How long a browser leg waits for its redirect before the capture stops.
/// The pending login itself stays usable through the paste fallback.
const WAIT: Duration = Duration::from_secs(600);
/// The per-connection read deadline.
const READ_DEADLINE: Duration = Duration::from_secs(3);
/// The request size cap: a redirect line is far shorter.
const REQUEST_LIMIT: usize = 8192;
/// How often the accept loop checks its stop channel.
const TICK: Duration = Duration::from_millis(25);

/// The static page a completed browser redirect lands on.
const PAGE: &str = "<!doctype html><meta charset=\"utf-8\"><title>Rivect</title>\
<body style=\"font:16px system-ui;margin:4rem\"><h1>Rivect</h1>\
<p>Sign-in received. Return to the terminal.</p></body>";

/// One pending redirect capture.
pub struct CallbackListener {
    origin: String,
    captured: Arc<Mutex<Option<String>>>,
    stop: Option<SyncSender<()>>,
    worker: Option<JoinHandle<()>>,
}

impl CallbackListener {
    /// Binds the recorded loopback origin and starts the capture thread.
    /// `None` when the port is taken or the origin is not a loopback literal:
    /// the leg then keeps the paste fallback and no socket exists.
    ///
    /// `bind_port` is the debug/test seam: it moves the socket only, while
    /// the captured redirect keeps the recorded origin. A release caller
    /// passes `None`.
    #[must_use]
    pub fn start(origin: &str, callback: Callback, bind_port: Option<u16>) -> Option<Self> {
        let expected = format!("http://{}:{}", callback.host, callback.port);
        if origin != expected {
            return None;
        }
        let listener = if let Some(port) = bind_port {
            TcpListener::bind(("127.0.0.1", port))
        } else {
            TcpListener::bind((callback.host, callback.port))
        }
        .ok()?;
        listener.set_nonblocking(true).ok()?;
        let (stop, stopped) = sync_channel(1);
        let captured = Arc::new(Mutex::new(None));
        let worker = {
            let captured = Arc::clone(&captured);
            let path = callback.path;
            thread::Builder::new()
                .name("rivect-login-callback".to_string())
                .spawn(move || accept(&listener, path, &stopped, &captured))
                .ok()?
        };
        Some(Self {
            origin: origin.to_string(),
            captured,
            stop: Some(stop),
            worker: Some(worker),
        })
    }

    /// The redirect URL one browser request carried, once.
    ///
    /// The value is the recorded origin joined with the accepted request
    /// target; the pending leg still verifies its origin, state and code.
    #[must_use]
    pub fn take(&self) -> Option<String> {
        let target = self.captured.lock().ok()?.take()?;
        Some(format!("{}{target}", self.origin))
    }
}

impl Drop for CallbackListener {
    fn drop(&mut self) {
        drop(self.stop.take());
        if let Some(worker) = self.worker.take() {
            // The worker owns no fallible state; a panicking thread has already
            // ended, and its result is not the caller's outcome.
            drop(worker.join());
        }
    }
}

fn accept(
    listener: &TcpListener,
    path: &str,
    stopped: &Receiver<()>,
    captured: &Mutex<Option<String>>,
) {
    let deadline = Instant::now() + WAIT;
    while Instant::now() < deadline {
        match listener.accept() {
            Ok((mut stream, _)) => {
                // A stray request is answered and the leg keeps waiting; only
                // the captured redirect ends the capture.
                if capture(&mut stream, path, captured) {
                    return;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => return,
        }
        match stopped.recv_timeout(TICK) {
            Err(RecvTimeoutError::Timeout) => {}
            Ok(()) | Err(RecvTimeoutError::Disconnected) => return,
        }
    }
}

fn capture(stream: &mut TcpStream, path: &str, captured: &Mutex<Option<String>>) -> bool {
    if stream.set_read_timeout(Some(READ_DEADLINE)).is_err()
        || stream.set_write_timeout(Some(READ_DEADLINE)).is_err()
    {
        return false;
    }
    let mut request = Vec::new();
    let mut chunk = [0_u8; 1024];
    while request.len() < REQUEST_LIMIT {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => {
                request.extend_from_slice(&chunk[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            Err(_) => return false,
        }
    }
    let Some(line) = request.split(|byte| *byte == b'\n').next() else {
        return false;
    };
    let line = String::from_utf8_lossy(line);
    let mut parts = line.split(' ');
    let (Some("GET"), Some(target), Some(_version)) = (parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    let admitted = target
        .strip_prefix(path)
        .is_some_and(|rest| rest.starts_with('?') && !rest.contains('#'));
    if !admitted {
        respond(stream, "404 Not Found");
        return false;
    }
    let stored = captured
        .lock()
        .map(|mut slot| slot.replace(target.to_string()).is_none())
        .unwrap_or(false);
    if !stored {
        respond(stream, "409 Conflict");
        return false;
    }
    respond(stream, "200 OK");
    true
}

fn respond(stream: &mut TcpStream, status: &str) {
    let body = if status == "200 OK" { PAGE } else { "" };
    let reply = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n{body}",
        body.len()
    );
    if stream.write_all(reply.as_bytes()).is_err() {
        return;
    }
    if stream.flush().is_err() {
        return;
    }
    // A graceful write shutdown sends FIN after the bytes; dropping a socket
    // the peer is still reading can answer RST on some platforms. A failed
    // shutdown means the peer already closed; there is nothing left to send.
    drop(stream.shutdown(std::net::Shutdown::Write));
    // Read until the peer closes so the socket is not dropped with unread
    // request bytes; that close sequence is what keeps FIN from becoming RST.
    let mut sink = [0_u8; 128];
    while matches!(stream.read(&mut sink), Ok(read) if read > 0) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    fn callback(port: u16) -> Callback {
        Callback {
            host: "127.0.0.1",
            port,
            path: "/callback",
        }
    }

    fn free_port() -> u16 {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("probe port");
        listener.local_addr().expect("probe address").port()
    }

    fn listener_on(port: u16) -> CallbackListener {
        CallbackListener::start(&format!("http://127.0.0.1:{port}"), callback(port), None)
            .expect("loopback capture starts")
    }

    fn get(port: u16, target: &str) -> String {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("read deadline");
        stream
            .write_all(format!("GET {target} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes())
            .expect("request");
        let mut reply = String::new();
        stream.read_to_string(&mut reply).expect("reply");
        reply
    }

    #[test]
    fn captures_one_redirect_and_ignores_the_rest() {
        let port = free_port();
        let listener = listener_on(port);
        let reply = get(port, "/callback?code=one&state=two");
        assert!(reply.starts_with("HTTP/1.1 200 OK"), "{reply}");
        assert_eq!(
            listener.take(),
            Some(format!(
                "http://127.0.0.1:{port}/callback?code=one&state=two"
            ))
        );
        assert_eq!(listener.take(), None, "the capture is one-shot");
    }

    #[test]
    fn refuses_another_path_and_traversal() {
        let port = free_port();
        let listener = listener_on(port);
        let reply = get(port, "/callback/../secret?code=one");
        assert!(reply.starts_with("HTTP/1.1 404"), "{reply}");
        assert_eq!(listener.take(), None);
    }

    #[test]
    fn binds_only_the_recorded_origin() {
        let port = free_port();
        assert!(
            CallbackListener::start("http://evil.example:1", callback(port), None).is_none(),
            "a foreign origin never binds"
        );
    }
}
