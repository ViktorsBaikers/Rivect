//! Scoped local sharing (AC-083b, DEC-016): an opt-in Unix-domain listener
//! that exposes four read-only projections to one granted observer and
//! nothing else. The plaintext token is returned once; the store keeps only
//! its SHA-256 digest. Revoke and expiry are terminal and refuse a request
//! before any method body runs. Remote or multi-user sharing is out of scope.

use crate::commands::Runtime;
use crate::contracts::{SCHEMA_VERSION, SessionId, TaskId};
use crate::state::{ConflictCause, SharingGrantState, StoreError};
use serde::Serialize;
use sha2::Digest;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// The grant lifetime used when the request names none.
pub const DEFAULT_GRANT_SECONDS: u64 = 900;

/// The longest grant this build opens: a day.
pub const MAX_GRANT_SECONDS: u64 = 24 * 60 * 60;

/// 256 bits of OS entropy, rendered as hex.
const TOKEN_BYTES: usize = 32;
const TOKEN_HEX_LEN: usize = TOKEN_BYTES * 2;

/// The grant's row identity: a random name, never the credential, kept
/// short enough that its socket path stays inside `sun_path`.
const GRANT_ID_BYTES: usize = 12;

/// The directory under the user data root that holds the sockets.
const SHARING_DIR: &str = "sharing";

/// The accepted-connection bound per grant: a peer past it is closed rather
/// than queued, so a local client cannot grow the service without bound.
pub const MAX_CONNECTIONS: usize = 8;

/// The frames one serving turn may answer across the whole surface, and the
/// wall-clock budget of that turn: a peer that keeps feeding frames cannot
/// hold the dispatch thread and starve a queued revoke.
const MAX_FRAMES_PER_TURN: usize = 3;
const MAX_SERVE_TURN: Duration = Duration::from_millis(250);

const READ_CHUNK: usize = 4096;

/// One grant as the opening call serves it: the only answer that ever
/// carries the plaintext token, and its `Debug` redacts it.
#[derive(Serialize)]
pub struct OpenedGrant {
    pub grant_id: String,
    pub token: String,
    pub task_id: String,
    pub socket_path: String,
    pub expires_at: u64,
}

impl std::fmt::Debug for OpenedGrant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenedGrant")
            .field("grant_id", &self.grant_id)
            .field("token", &"<redacted>")
            .field("task_id", &self.task_id)
            .field("socket_path", &self.socket_path)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// One observer attachment as the attach exchange serves it: read-only
/// projections and the grant's own deadline, never the token.
#[derive(Debug, Serialize)]
pub struct SharingAttachment {
    pub schema_version: u32,
    pub attachment_id: String,
    pub grant_id: String,
    pub task_id: String,
    pub session_id: String,
    pub mode: &'static str,
    pub methods: Vec<&'static str>,
    pub expires_at: u64,
}

/// One terminal revoke answer.
#[derive(Debug, Serialize)]
pub struct RevokedGrant {
    pub grant_id: String,
    pub state: String,
}

/// One sharing-boundary failure. Display text is English and lowercase and
/// never carries the token.
#[derive(Debug, thiserror::Error)]
pub enum SharingError {
    #[error("entropy source is unavailable: {cause}")]
    Entropy { cause: getrandom::Error },
    #[error("share socket {path}: {source}")]
    Socket {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("share token does not match a live grant")]
    UnknownToken,
    #[error("sharing grant {grant_id} is {state}")]
    Closed { grant_id: String, state: String },
    #[error("sharing attachment is not live on this grant")]
    UnknownAttachment,
    #[error("share request exceeds the 1 MiB cap")]
    Oversize,
    #[error("share frame is not valid JSON")]
    InvalidFrame,
    #[error("share frame schema_version must be 1")]
    InvalidSchema,
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl SharingError {
    /// The wire class one refusal reports.
    #[must_use]
    pub fn code(&self) -> crate::contracts::ErrorCode {
        use crate::contracts::ErrorCode;
        match self {
            Self::Entropy { .. } | Self::Socket { .. } => ErrorCode::InternalError,
            Self::UnknownToken | Self::Closed { .. } | Self::UnknownAttachment => ErrorCode::Denied,
            Self::Oversize | Self::InvalidFrame | Self::InvalidSchema => ErrorCode::InvalidInput,
            Self::Store(source) => source.code(),
        }
    }
}

/// The live sharing surface: one listener per open grant, the attachment ids
/// each grant minted, and the pending observer connections. Nothing here
/// outlives the process, and nothing here holds a token.
#[derive(Default)]
pub struct SharingService {
    grants: BTreeMap<String, LiveGrant>,
}

/// One serving turn's budget: a fixed frame count and a wall-clock deadline,
/// so a peer that keeps feeding frames cannot hold the dispatch thread.
struct ServeTurn {
    deadline: Instant,
    frames_left: usize,
}

impl ServeTurn {
    fn start() -> Self {
        Self {
            deadline: Instant::now() + MAX_SERVE_TURN,
            frames_left: MAX_FRAMES_PER_TURN,
        }
    }

    fn available(&self) -> bool {
        self.frames_left > 0 && Instant::now() < self.deadline
    }

    /// Spends one frame of the turn; `false` when the budget just ran out.
    fn spend(&mut self) -> bool {
        if !self.available() {
            return false;
        }
        self.frames_left -= 1;
        true
    }

    /// What is left of the turn's wall clock. A write is bounded by it, so a
    /// peer that stops reading cannot stretch the turn past its budget.
    fn remaining(&self) -> Duration {
        self.deadline.saturating_duration_since(Instant::now())
    }
}

impl SharingService {
    /// Records one grant's live surface. The task row and the socket open in
    /// one call from [`Runtime`], so a grant's row and its listener exist
    /// together or not at all.
    fn insert(&mut self, grant: LiveGrant) {
        self.grants.insert(grant.grant_id.clone(), grant);
    }

    /// Exchanges one token for an attachment on the grant it belongs to.
    /// An expired grant is marked terminal and its listener closed before
    /// the refusal, so no later request reaches a method body.
    ///
    /// # Errors
    /// [`SharingError::UnknownToken`] for a token no live grant holds,
    /// [`SharingError::Closed`] for a revoked or expired grant, the storage
    /// refusal of the terminal expiry write, and entropy failure.
    pub fn attach(
        &mut self,
        rt: &mut Runtime,
        token: &str,
    ) -> Result<SharingAttachment, SharingError> {
        let now = (rt.work_clock)();
        if !is_token_shaped(token) {
            return Err(SharingError::UnknownToken);
        }
        let digest = token_digest(token);
        let Some(grant) = self
            .grants
            .values_mut()
            .find(|grant| grant.token_digest == digest)
        else {
            return Err(SharingError::UnknownToken);
        };
        grant.ensure_live(rt, now)?;
        let attachment_id = random_hex(16)?;
        // A local-wire attachment is a receipt, not a connection: no socket
        // owns it, so it never enters the grant's connection-owned set. The
        // socket exchange is the path that mints a verifiable attachment, and
        // its set stays bounded by live connections.
        Ok(grant.attachment_view(attachment_id))
    }

    /// Serves pending observer frames for one bounded turn. A listener or
    /// connection fault closes that connection; the grant state stays the
    /// record, so a failed socket never weakens a grant. The turn always
    /// returns: a frame budget and a deadline stop a peer that keeps feeding
    /// frames from starving the local request queued behind the pump.
    pub fn serve(&mut self, rt: &mut Runtime) -> usize {
        if self.grants.is_empty() {
            return 0;
        }
        let grant_ids: Vec<String> = self.grants.keys().cloned().collect();
        let mut turn = ServeTurn::start();
        let mut served = 0;
        for grant_id in grant_ids {
            if !turn.available() {
                break;
            }
            if let Some(grant) = self.grants.get_mut(&grant_id) {
                served += grant.serve(rt, &mut turn);
            }
        }
        served
    }
}

/// One open grant's live surface.
struct LiveGrant {
    grant_id: String,
    session_id: String,
    task_id: String,
    token_digest: String,
    expires_at: u64,
    state: SharingGrantState,
    listener: Option<UnixListener>,
    socket_path: PathBuf,
    attachments: BTreeSet<String>,
    connections: Vec<ShareConnection>,
}

impl LiveGrant {
    fn attachment_view(&self, attachment_id: String) -> SharingAttachment {
        SharingAttachment {
            schema_version: SCHEMA_VERSION,
            attachment_id,
            grant_id: self.grant_id.clone(),
            task_id: self.task_id.clone(),
            session_id: self.session_id.clone(),
            mode: "read_only",
            methods: crate::commands::observer_methods().to_vec(),
            expires_at: self.expires_at,
        }
    }

    /// Refuses once the grant is no longer live. Expiry writes its terminal
    /// row and closes the listener before returning the refusal; a row another
    /// transition already closed is adopted as this surface's state instead of
    /// being reported as an expiry that never wrote.
    fn ensure_live(&mut self, rt: &mut Runtime, now: u64) -> Result<(), SharingError> {
        match self.state {
            SharingGrantState::Open if now < self.expires_at => Ok(()),
            SharingGrantState::Open => {
                let expired = rt.owner.store.expire_sharing_grant(&self.grant_id, now);
                self.state = SharingGrantState::Expired;
                self.close_listener();
                match expired {
                    Ok(_grant) => Err(self.closed()),
                    Err(StoreError::Conflict(ConflictCause::SharingGrantClosed {
                        state, ..
                    })) => {
                        self.state = SharingGrantState::from_db(&state)?;
                        Err(self.closed())
                    }
                    // The surface is already closed; the failed record write
                    // reaches the observer instead of being dropped.
                    Err(source) => Err(SharingError::Store(source)),
                }
            }
            _ => Err(self.closed()),
        }
    }

    fn closed(&self) -> SharingError {
        SharingError::Closed {
            grant_id: self.grant_id.clone(),
            state: self.state.as_str().to_string(),
        }
    }

    /// Closes the listener for good. Pending connections stay open to carry
    /// the refusal for their next frame; no new one is accepted.
    fn close_listener(&mut self) {
        self.listener = None;
        unlink_socket(&self.socket_path);
    }

    /// One serving turn: accept pending peers, then answer frames within the
    /// turn's budget. A listener that cannot accept closes terminally and
    /// records why, so the row never reads `open` beside a dead surface.
    fn serve(&mut self, rt: &mut Runtime, turn: &mut ServeTurn) -> usize {
        if self.state == SharingGrantState::Open
            && let Some(listener) = self.listener.as_ref()
        {
            loop {
                match listener.accept() {
                    Ok((stream, _address)) => {
                        if self.connections.len() >= MAX_CONNECTIONS {
                            // The bound is the refusal: the surplus peer is
                            // closed and the loop stops, so the turn returns
                            // to the dispatcher instead of draining a backlog.
                            drop(stream);
                            break;
                        }
                        match stream.set_nonblocking(true) {
                            Ok(()) => self.connections.push(ShareConnection {
                                stream,
                                pending: Vec::new(),
                                ready: VecDeque::new(),
                                attachment: None,
                            }),
                            // A descriptor that cannot be polled is closed;
                            // it holds no grant state to weaken.
                            Err(_source) => drop(stream),
                        }
                    }
                    Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                    // No offline fixture can raise a signal-interrupted
                    // accept; the retry is construction-only.
                    Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                    Err(_source) => {
                        // A listener accept fault is construction-only
                        // offline: the row records the terminal state so the
                        // store and the live surface never disagree.
                        self.state = SharingGrantState::Failed;
                        self.close_listener();
                        // The row must agree with the closed surface; a failed
                        // record write is a fallback the closed listener
                        // already makes safe.
                        if let Err(source) = rt.owner.store.fail_sharing_grant(&self.grant_id) {
                            drop(source);
                        }
                        break;
                    }
                }
            }
        }
        let connections = std::mem::take(&mut self.connections);
        let mut kept = Vec::with_capacity(connections.len());
        let mut served = 0;
        for mut connection in connections {
            let (keep, answered) = self.pump(rt, &mut connection, turn);
            served += answered;
            if keep {
                kept.push(connection);
            }
        }
        self.connections = kept;
        served
    }

    /// Answers the connection's ready frames within the turn's budget, then
    /// releases its attachment id when the peer is done. The clock is read per
    /// frame, so a grant that expires mid-turn refuses the next frame.
    /// Returns whether the connection stays and the count served.
    fn pump(
        &mut self,
        rt: &mut Runtime,
        connection: &mut ShareConnection,
        turn: &mut ServeTurn,
    ) -> (bool, usize) {
        let (keep, served) = self.pump_frames(rt, connection, turn);
        if !keep && let Some(attachment) = connection.attachment.take() {
            // The set is bounded by live connections: an id leaves with the
            // connection it was minted for.
            self.attachments.remove(&attachment);
        }
        (keep, served)
    }

    fn pump_frames(
        &mut self,
        rt: &mut Runtime,
        connection: &mut ShareConnection,
        turn: &mut ServeTurn,
    ) -> (bool, usize) {
        let mut served = 0;
        loop {
            if !turn.available() {
                return (true, served);
            }
            let frame = match connection.next_frame() {
                Ok(FrameRead::Frame(frame)) => frame,
                Ok(FrameRead::Idle) => return (true, served),
                Ok(FrameRead::Closed) => return (false, served),
                Ok(FrameRead::Oversize) => {
                    let refusal = crate::commands::share_refusal(
                        &serde_json::Value::Null,
                        &SharingError::Oversize,
                    );
                    // The oversize peer closes either way; a refused write
                    // is a peer already gone, not a second fault to report.
                    if let Err(source) = connection.write_frame(&refusal, turn.remaining()) {
                        drop(source);
                    }
                    return (false, served);
                }
                Err(_source) => return (false, served),
            };
            if !turn.spend() {
                // The deadline passed between the budget check and the read;
                // the frame stays queued for the next turn, never dropped.
                connection.requeue(frame);
                return (true, served);
            }
            served += 1;
            let now = (rt.work_clock)();
            let (response, keep) = self.answer(rt, connection, &frame, now);
            if connection.write_frame(&response, turn.remaining()).is_err() {
                return (false, served);
            }
            if !keep {
                return (false, served);
            }
        }
    }

    /// The gate before any method body: attach is the only pre-attachment
    /// exchange, every other frame needs a live grant and a live attachment,
    /// and the method allowlist is checked by the dispatcher.
    fn answer(
        &mut self,
        rt: &mut Runtime,
        connection: &mut ShareConnection,
        frame: &[u8],
        now: u64,
    ) -> (String, bool) {
        let Ok(parsed) = serde_json::from_slice::<serde_json::Value>(frame) else {
            return (
                crate::commands::share_refusal(
                    &serde_json::Value::Null,
                    &SharingError::InvalidFrame,
                ),
                false,
            );
        };
        let id = parsed.get("id").cloned().unwrap_or(serde_json::Value::Null);
        let method = parsed.get("method").and_then(serde_json::Value::as_str);
        if method == Some(crate::commands::SHARING_ATTACH_METHOD) {
            // The one method a connection may call before it holds an
            // attachment carries the same schema_version as the local wire.
            if parsed
                .get("params")
                .and_then(|params| params.get("schema_version"))
                .and_then(serde_json::Value::as_u64)
                != Some(u64::from(SCHEMA_VERSION))
            {
                return (
                    crate::commands::share_refusal(&id, &SharingError::InvalidSchema),
                    false,
                );
            }
            let token = parsed
                .get("params")
                .and_then(|params| params.get("token"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            return match self.exchange_token(rt, token, now) {
                Ok(attachment) => {
                    if let Some(previous) = connection
                        .attachment
                        .replace(attachment.attachment_id.clone())
                    {
                        // One live attachment per connection: the replaced id
                        // leaves with it, so the set is bounded by peers.
                        self.attachments.remove(&previous);
                    }
                    (ok_response(&id, &attachment), true)
                }
                Err(error) => (crate::commands::share_refusal(&id, &error), false),
            };
        }
        let Some(attachment) = connection.attachment.as_deref() else {
            return (
                crate::commands::share_refusal(&id, &SharingError::UnknownAttachment),
                false,
            );
        };
        match self.verify_attachment(rt, attachment, now) {
            Ok(()) => match std::str::from_utf8(frame) {
                Ok(request) => (
                    crate::commands::dispatch_observer_request(
                        rt,
                        attachment,
                        &self.session_id,
                        &self.task_id,
                        request,
                    ),
                    true,
                ),
                Err(_source) => (
                    crate::commands::share_refusal(&id, &SharingError::InvalidFrame),
                    false,
                ),
            },
            Err(error) => (crate::commands::share_refusal(&id, &error), false),
        }
    }

    fn exchange_token(
        &mut self,
        rt: &mut Runtime,
        token: &str,
        now: u64,
    ) -> Result<SharingAttachment, SharingError> {
        if !is_token_shaped(token) || self.token_digest != token_digest(token) {
            return Err(SharingError::UnknownToken);
        }
        self.ensure_live(rt, now)?;
        let attachment_id = random_hex(16)?;
        self.attachments.insert(attachment_id.clone());
        Ok(self.attachment_view(attachment_id))
    }

    fn verify_attachment(
        &mut self,
        rt: &mut Runtime,
        attachment_id: &str,
        now: u64,
    ) -> Result<(), SharingError> {
        self.ensure_live(rt, now)?;
        if self.attachments.contains(attachment_id) {
            Ok(())
        } else {
            Err(SharingError::UnknownAttachment)
        }
    }
}

impl Drop for LiveGrant {
    fn drop(&mut self) {
        self.listener = None;
        unlink_socket(&self.socket_path);
    }
}

/// One accepted observer peer: unframed bytes are kept until their newline
/// arrives, so a frame split across reads is still one frame. A frame read
/// after the turn's budget ran out is queued in `ready`, never dropped.
struct ShareConnection {
    stream: UnixStream,
    pending: Vec<u8>,
    ready: VecDeque<Vec<u8>>,
    attachment: Option<String>,
}

enum FrameRead {
    Frame(Vec<u8>),
    Idle,
    Closed,
    Oversize,
}

impl ShareConnection {
    fn next_frame(&mut self) -> std::io::Result<FrameRead> {
        if let Some(frame) = self.ready.pop_front() {
            return Ok(FrameRead::Frame(frame));
        }
        loop {
            if let Some(frame) = self.take_frame() {
                return Ok(FrameRead::Frame(frame));
            }
            if self.pending.len() > crate::contracts::REQUEST_MAX_BYTES {
                return Ok(FrameRead::Oversize);
            }
            let mut chunk = [0u8; READ_CHUNK];
            match self.stream.read(&mut chunk) {
                Ok(0) => return Ok(FrameRead::Closed),
                Ok(read) => self.pending.extend_from_slice(&chunk[..read]),
                Err(error) if error.kind() == ErrorKind::WouldBlock => return Ok(FrameRead::Idle),
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
    }

    fn requeue(&mut self, frame: Vec<u8>) {
        self.ready.push_front(frame);
    }

    fn take_frame(&mut self) -> Option<Vec<u8>> {
        let end = self.pending.iter().position(|byte| *byte == b'\n')?;
        let mut frame: Vec<u8> = self.pending.drain(..=end).collect();
        frame.pop();
        if frame.last() == Some(&b'\r') {
            frame.pop();
        }
        Some(frame)
    }

    /// Writes one response under the turn's remaining budget, then returns
    /// the stream to non-blocking reads.
    fn write_frame(&mut self, response: &str, timeout: Duration) -> std::io::Result<()> {
        self.stream.set_nonblocking(false)?;
        let written = self.write_blocking(response, timeout);
        let restored = self.stream.set_nonblocking(true);
        match (written, restored) {
            (Err(error), _) | (Ok(()), Err(error)) => Err(error),
            (Ok(()), Ok(())) => Ok(()),
        }
    }

    fn write_blocking(&mut self, response: &str, timeout: Duration) -> std::io::Result<()> {
        // A zero timeout is meaningless to the socket layer; the floor keeps
        // an exhausted turn from blocking forever.
        //
        // X5 construction-only: an offline fixture cannot hold a live writer
        // and a non-reading reader on one thread without deadlocking the
        // producer, so a stalled-peer write timeout is not induced here; the
        // timeout is the turn's remaining budget, and the slice inventory
        // records this branch as construction-only.
        self.stream
            .set_write_timeout(Some(timeout.max(Duration::from_millis(1))))?;
        self.stream.write_all(response.as_bytes())?;
        self.stream.write_all(b"\n")?;
        self.stream.flush()
    }
}

impl Runtime {
    /// Opens one scoped observer grant (AC-083b): a 256-bit token whose
    /// SHA-256 digest is the only stored form, a private socket under the
    /// data root, and the plaintext token returned exactly once.
    ///
    /// # Errors
    /// The store refusal of the grant row, the socket bind failure, and
    /// entropy failure. A socket that cannot be bound records no grant.
    pub fn open_sharing_grant(
        &mut self,
        session_id: &SessionId,
        task_id: &TaskId,
        ttl_seconds: u64,
    ) -> Result<OpenedGrant, SharingError> {
        let grant_id = random_hex(GRANT_ID_BYTES)?;
        let token = random_hex(TOKEN_BYTES)?;
        let digest = token_digest(&token);
        // The public entry clips the request to the recorded grant window
        // itself, so a direct caller cannot mint an expiry the row or wire
        // cannot represent.
        let ttl_seconds = ttl_seconds.clamp(1, MAX_GRANT_SECONDS);
        let expires_at = (self.work_clock)().saturating_add(ttl_seconds);
        let socket_path = self
            .data_root
            .join(SHARING_DIR)
            .join(format!("{grant_id}.sock"));
        let listener = bind_private(&socket_path)?;
        match self
            .owner
            .store
            .open_sharing_grant(&grant_id, session_id, task_id, &digest, expires_at)
        {
            Ok(_grant) => {
                {
                    let service = Arc::clone(&self.sharing);
                    let mut service = lock_sharing(&service);
                    service.insert(LiveGrant {
                        grant_id: grant_id.clone(),
                        session_id: session_id.0.clone(),
                        task_id: task_id.0.clone(),
                        token_digest: digest,
                        expires_at,
                        state: SharingGrantState::Open,
                        listener: Some(listener),
                        socket_path: socket_path.clone(),
                        attachments: BTreeSet::new(),
                        connections: Vec::new(),
                    });
                }
                Ok(OpenedGrant {
                    grant_id,
                    token,
                    task_id: task_id.0.clone(),
                    socket_path: socket_path.display().to_string(),
                    expires_at,
                })
            }
            Err(source) => {
                // No row exists, so the just-bound path must not survive it.
                drop(listener);
                unlink_socket(&socket_path);
                Err(SharingError::Store(source))
            }
        }
    }

    /// Exchanges one grant token for a read-only attachment.
    ///
    /// # Errors
    /// The refusals [`SharingService::attach`] documents.
    pub fn attach_sharing(&mut self, token: &str) -> Result<SharingAttachment, SharingError> {
        let service = Arc::clone(&self.sharing);
        let mut service = lock_sharing(&service);
        service.attach(self, token)
    }

    /// Revokes one grant terminally and closes its listener, provided the
    /// named session owns the grant's task. A second revoke reports the
    /// recorded state and changes nothing.
    ///
    /// # Errors
    /// [`StoreError::NotFound`] for an id this store does not hold or one that
    /// belongs to another session, and the storage failure of the write.
    pub fn revoke_sharing_grant(
        &mut self,
        session_id: &SessionId,
        grant_id: &str,
    ) -> Result<RevokedGrant, SharingError> {
        let grant = self
            .owner
            .store
            .revoke_sharing_grant(grant_id, session_id)?;
        {
            let service = Arc::clone(&self.sharing);
            let mut service = lock_sharing(&service);
            if let Some(live) = service.grants.get_mut(grant_id) {
                live.state = grant.state;
                live.close_listener();
            }
        }
        Ok(RevokedGrant {
            grant_id: grant.grant_id,
            state: grant.state.as_str().to_string(),
        })
    }

    /// Serves the pending observer frames once, on the runtime's own thread
    /// so the one store connection stays the only one. Every dispatch turn
    /// pumps it, so a live grant's socket is answered while the owner keeps
    /// serving local requests.
    ///
    /// Returns the number of frames answered.
    pub fn serve_sharing(&mut self) -> usize {
        let service = Arc::clone(&self.sharing);
        let mut service = lock_sharing(&service);
        service.serve(self)
    }
}

/// The one mutex policy for the share surface: a poisoned lock is recovered
/// because the service keeps no half-updated invariant — it fails closed on
/// its own — and an optional surface must not disable the runtime.
fn lock_sharing(service: &Arc<Mutex<SharingService>>) -> MutexGuard<'_, SharingService> {
    match service.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// One successful observer answer. The only failure is serialization of a
/// result the boundary just built; that answers as the internal-error frame.
fn ok_response(id: &serde_json::Value, result: &impl Serialize) -> String {
    serde_json::to_string(&serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result,
    }))
    .unwrap_or_else(|_error| {
        "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32000,\"message\":\"internal_error\"}}"
            .to_string()
    })
}

/// Whether the presented token has the exact shape this build mints; any
/// other input is the same denial as a wrong token, never a hashing oracle.
fn is_token_shaped(token: &str) -> bool {
    token.len() == TOKEN_HEX_LEN && token.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// The stored form of a token: its SHA-256 hex.
fn token_digest(token: &str) -> String {
    crate::config::hex(&sha2::Sha256::digest(token.as_bytes()))
}

fn random_hex(bytes: usize) -> Result<String, SharingError> {
    let mut material = vec![0u8; bytes];
    getrandom::fill(&mut material).map_err(|cause| SharingError::Entropy { cause })?;
    Ok(crate::config::hex(&material))
}

/// Creates the private directory and binds the socket at 0600. A socket that
/// cannot be made private is closed and removed rather than served.
fn bind_private(socket_path: &Path) -> Result<UnixListener, SharingError> {
    if let Some(directory) = socket_path.parent() {
        std::fs::create_dir_all(directory).map_err(|source| socket_error(socket_path, source))?;
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))
            .map_err(|source| socket_error(socket_path, source))?;
    }
    let listener =
        UnixListener::bind(socket_path).map_err(|source| socket_error(socket_path, source))?;
    let private = (|| -> std::io::Result<()> {
        std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)
    })();
    match private {
        Ok(()) => Ok(listener),
        Err(source) => {
            drop(listener);
            unlink_socket(socket_path);
            Err(socket_error(socket_path, source))
        }
    }
}

fn socket_error(path: &Path, source: std::io::Error) -> SharingError {
    SharingError::Socket {
        path: path.display().to_string(),
        source,
    }
}

/// Removes one socket path. A path already gone needs nothing, and a failed
/// unlink leaves a dead path — never a live listener — while the next grant
/// uses a fresh name.
fn unlink_socket(path: &Path) {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => drop(error),
    }
}

#[cfg(test)]
mod tests {
    use super::{OpenedGrant, token_digest};

    #[test]
    fn token_digest_is_sha256_hex() {
        assert_eq!(
            token_digest("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn opened_grant_debug_redacts_the_token() {
        let token = "ab".repeat(32);
        let opened = OpenedGrant {
            grant_id: "grant".to_string(),
            token: token.clone(),
            task_id: "task".to_string(),
            socket_path: "/data/sharing/grant.sock".to_string(),
            expires_at: 1,
        };
        let debug = format!("{opened:?}");
        assert!(!debug.contains(&token), "Debug leaked the plaintext token");
        assert!(debug.contains("<redacted>"));
    }
}
