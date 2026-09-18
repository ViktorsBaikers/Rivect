//! Resource holders, the bounded notification queue, and the safe
//! external-data flow. Overflow never drops obligations silently: the
//! backlog is replaced by one resync marker.

use crate::contracts::Event;
use crate::executor::{FileIdentity, ReadObservation};
use crate::policy::PermissionMode;
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceHolderStatus {
    Active,
    TerminationUnknown,
    Terminated,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ResourceHolder {
    pub resource_scope: String,
    pub executor_id: String,
    pub owner_generation: u64,
    pub status: ResourceHolderStatus,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Delivery {
    Event(Event),
    ResyncMarker,
}

pub struct NotificationQueue {
    capacity: usize,
    pending: VecDeque<Event>,
    overflowed: bool,
}

impl NotificationQueue {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            pending: VecDeque::new(),
            overflowed: false,
        }
    }

    pub fn push(&mut self, event: Event) {
        if self.pending.len() >= self.capacity {
            self.pending.clear();
            self.overflowed = true;
        }
        self.pending.push_back(event);
    }

    /// Drains at most `limit` deliveries; a pending overflow is reported
    /// first as a single resync marker.
    pub fn drain(&mut self, limit: usize) -> Vec<Delivery> {
        let mut out = Vec::new();
        if self.overflowed {
            self.overflowed = false;
            out.push(Delivery::ResyncMarker);
        }
        while out.len() < limit {
            let Some(event) = self.pending.pop_front() else {
                break;
            };
            out.push(Delivery::Event(event));
        }
        out
    }

    pub fn len(&self) -> usize {
        self.pending.len()
    }

    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
}

/// The merge identity of one permitted read (INV-023). The operation
/// kind is the registry itself: only reads enter it, so effects can
/// never merge. The remaining components are the significant input
/// (the target as admitted), the file snapshot binding observed at
/// admit (the same dev/ino binding the checked-fd write path pins), the
/// access scope (the grant's scope root), and the rights the read was
/// permitted under: the grant identity and the caller's permission
/// mode. Policy generations are projected through those components —
/// a fresh grant is a fresh id, and any deny or revocation that
/// changes this read's verdict rejects the next admit instead of
/// merging with the open flight.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReadFlightKey {
    pub target: PathBuf,
    pub snapshot: SnapshotBinding,
    pub scope_root: PathBuf,
    pub rights: ReadRights,
}

/// The file snapshot binding of one admitted read — the same dev/ino
/// pair the checked-fd write path pins — in the hashable shape the
/// flight key needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotBinding(pub FileIdentity);

impl std::hash::Hash for SnapshotBinding {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        state.write_u64(self.0.dev);
        state.write_u64(self.0.ino);
    }
}

/// The rights half of a [`ReadFlightKey`]: grant identity plus the
/// permission mode id the verdict was consulted under.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReadRights {
    pub grant_id: String,
    pub mode: &'static str,
}

impl ReadRights {
    #[must_use]
    pub fn new(grant_id: &str, mode: PermissionMode) -> Self {
        Self {
            grant_id: grant_id.to_string(),
            mode: mode.id(),
        }
    }
}

/// One in-flight read: the attempts admitted while the physical read
/// was still due, and — once the first of them executed — the single
/// physical observation every remaining member shares.
#[derive(Debug, Clone, PartialEq)]
struct Flight {
    members: Vec<String>,
    observation: Option<ReadObservation>,
}

/// Where one admitted read sits in its flight: the first-admitted
/// member leads; every identical permitted admit that joins the open
/// flight follows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlightRole {
    Leader,
    Follower,
}

/// Single-flight registry for identical permitted reads (INV-023,
/// EDGE-008): identical reads merge into one physical charge, and the
/// merge key covers target, snapshot, access scope, and rights, so
/// differing reads never share a flight. A member that never executes
/// keeps its seat — the registry grows one entry per admitted-but-
/// unsettled read, never per byte.
// ponytail: members are pruned only when they execute or leave; if an
// abandoned-open-flight leak ever matters, retire on task settle.
#[derive(Debug, Default)]
pub struct ReadFlights {
    flights: HashMap<ReadFlightKey, Vec<Flight>>,
    by_attempt: HashMap<String, ReadFlightKey>,
}

impl ReadFlights {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers one admitted read. An identical open flight — still
    /// waiting for its physical read — takes the attempt as a follower;
    /// anything else opens a fresh flight with the attempt as leader.
    pub fn subscribe(&mut self, key: ReadFlightKey, attempt_id: &str) -> FlightRole {
        let joins_open = self
            .flights
            .get(&key)
            .is_some_and(|flights| flights.last().is_some_and(|f| f.observation.is_none()));
        let role = if joins_open {
            if let Some(flight) = self.flights.get_mut(&key).and_then(|fs| fs.last_mut()) {
                flight.members.push(attempt_id.to_string());
            }
            FlightRole::Follower
        } else {
            self.flights.entry(key.clone()).or_default().push(Flight {
                members: vec![attempt_id.to_string()],
                observation: None,
            });
            FlightRole::Leader
        };
        self.by_attempt.insert(attempt_id.to_string(), key);
        role
    }

    /// The admission-order seat of one attempt, when it still holds
    /// flight membership: the first remaining member leads.
    pub fn role(&self, attempt_id: &str) -> Option<FlightRole> {
        let key = self.by_attempt.get(attempt_id)?;
        let flight = self
            .flights
            .get(key)?
            .iter()
            .find(|flight| flight.members.iter().any(|member| member == attempt_id))?;
        if flight
            .members
            .first()
            .is_some_and(|leader| leader == attempt_id)
        {
            Some(FlightRole::Leader)
        } else {
            Some(FlightRole::Follower)
        }
    }

    /// Takes the shared observation for one member — the flight's one
    /// physical read, once it exists — and consumes the membership with
    /// it. `None` leaves the membership untouched: the flight is still
    /// open, or the attempt never joined one.
    pub fn take_shared(&mut self, attempt_id: &str) -> Option<ReadObservation> {
        let key = self.by_attempt.get(attempt_id)?.clone();
        let flights = self.flights.get_mut(&key)?;
        let index = flights
            .iter()
            .position(|flight| flight.members.iter().any(|member| member == attempt_id))?;
        let observation = flights[index].observation.clone()?;
        flights[index].members.retain(|member| member != attempt_id);
        if flights[index].members.is_empty() {
            flights.remove(index);
        }
        self.by_attempt.remove(attempt_id);
        Some(observation)
    }

    /// Records the one physical observation on the member's flight and
    /// retires the reader's own membership: the observation now belongs
    /// to the remaining waiters, and an empty flight is gone.
    pub fn settle(&mut self, attempt_id: &str, observation: ReadObservation) {
        let Some(key) = self.by_attempt.get(attempt_id).cloned() else {
            return;
        };
        let Some(flights) = self.flights.get_mut(&key) else {
            return;
        };
        let Some(index) = flights
            .iter()
            .position(|flight| flight.members.iter().any(|member| member == attempt_id))
        else {
            return;
        };
        flights[index].members.retain(|member| member != attempt_id);
        flights[index].observation = Some(observation);
        if flights[index].members.is_empty() {
            flights.remove(index);
        }
        self.by_attempt.remove(attempt_id);
    }

    /// Drops one member without an observation: a cancelled or denied
    /// member leaves the flight, and the remaining members keep their
    /// own claim on the physical read. A flight with no members left
    /// is gone — cancel-all stops the work.
    pub fn drop_member(&mut self, attempt_id: &str) {
        let Some(key) = self.by_attempt.get(attempt_id).cloned() else {
            return;
        };
        let Some(flights) = self.flights.get_mut(&key) else {
            return;
        };
        for flight in flights.iter_mut() {
            flight.members.retain(|member| member != attempt_id);
        }
        flights.retain(|flight| !flight.members.is_empty());
        self.by_attempt.remove(attempt_id);
    }
}

/// Display state of one external output stream. `Streaming` is the only
/// non-terminal state: a settled stream ignores later producer chunks,
/// so partial or failed output can never be extended into looking
/// complete.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum OutputStatus {
    #[default]
    Streaming,
    Complete,
    Partial {
        cause: String,
    },
    Failed {
        cause: String,
    },
}

/// How one producer run settles its external output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutputSettlement {
    Complete,
    Partial { cause: String },
    Failed { cause: String },
}

/// Upper bound on retained display text per stream: plenty for reading
/// long tool output, while an endless producer can never grow the view
/// without limit. The retained head is marked, never silently whole.
pub const OUTPUT_RETAIN_BYTES: usize = 64 * 1024;

/// Streaming presentation projection of external (worker) output: the
/// untrusted source meets sanitization here, before any display string
/// exists. Control sequences are neutralized per character — the
/// introducer byte itself never survives, so a sequence split across
/// chunk boundaries is exactly as inert as an unsplit one and nothing
/// depends on reassembling it. UTF-8 sequences split across chunks are
/// held pending and decoded once complete; invalid bytes become
/// replacement characters. Safety never depends on hiding output: the
/// escaped text stays visible as data (design-brief §5).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct OutputStream {
    pending: Vec<u8>,
    text: String,
    truncated: bool,
    status: OutputStatus,
}

impl OutputStream {
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends one chunk of external bytes. A settled or truncated
    /// stream ignores the chunk: terminal states are final and the
    /// retained head is the whole display.
    pub fn push_chunk(&mut self, bytes: &[u8]) {
        if self.truncated || !matches!(self.status, OutputStatus::Streaming) {
            return;
        }
        self.pending.extend_from_slice(bytes);
        self.decode_pending(false);
    }

    /// Settles the stream: an incomplete UTF-8 tail flushes as one
    /// replacement character, then the typed state is final.
    pub fn settle(&mut self, settlement: OutputSettlement) {
        self.decode_pending(true);
        self.status = match settlement {
            OutputSettlement::Complete => OutputStatus::Complete,
            OutputSettlement::Partial { cause } => OutputStatus::Partial { cause },
            OutputSettlement::Failed { cause } => OutputStatus::Failed { cause },
        };
    }

    /// Sanitized display text; contains no control character but `\n`.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The stream's typed display state.
    #[must_use]
    pub fn status(&self) -> &OutputStatus {
        &self.status
    }

    /// Whether any display surface must show this stream: it holds
    /// text, or it settled without producing any.
    #[must_use]
    pub fn is_active(&self) -> bool {
        !self.text.is_empty() || !matches!(self.status, OutputStatus::Streaming)
    }

    /// Whether retention capacity truncated the display text.
    #[must_use]
    pub fn head_truncated(&self) -> bool {
        self.truncated
    }

    /// Decodes as much of the pending bytes as forms complete UTF-8,
    /// sanitizing each decoded run into the bounded display text. With
    /// `flush`, an unterminated tail becomes one replacement character;
    /// otherwise it stays pending for the next chunk.
    fn decode_pending(&mut self, flush: bool) {
        let mut pending = std::mem::take(&mut self.pending);
        let mut consumed = 0usize;
        while consumed < pending.len() && !self.truncated {
            match std::str::from_utf8(&pending[consumed..]) {
                Ok(valid) => {
                    self.append_decoded(valid);
                    consumed = pending.len();
                }
                Err(error) => {
                    let up_to = error.valid_up_to();
                    let valid = String::from_utf8_lossy(&pending[consumed..consumed + up_to]);
                    self.append_decoded(&valid);
                    match error.error_len() {
                        Some(invalid) => {
                            self.append_decoded("\u{fffd}");
                            consumed += up_to + invalid;
                        }
                        None => {
                            if flush {
                                self.append_decoded("\u{fffd}");
                                consumed = pending.len();
                            } else {
                                // Incomplete UTF-8 tail: keep it pending.
                                consumed += up_to;
                                break;
                            }
                        }
                    }
                }
            }
        }
        self.pending = pending.split_off(consumed);
        if self.truncated {
            self.pending.clear();
        }
    }

    /// Appends sanitized characters and stops at the retention cap.
    /// Only `\n` survives as a control: every other control character
    /// is escaped (C0 caret notation, keeping the data visible) or
    /// replaced (DEL, C1), so no control byte ever reaches a terminal.
    fn append_decoded(&mut self, decoded: &str) {
        for ch in decoded.chars() {
            if self.text.len() >= OUTPUT_RETAIN_BYTES {
                self.truncated = true;
                break;
            }
            if is_stripped_format(ch) {
                continue;
            }
            if ch == '\n' || !ch.is_control() {
                self.text.push(ch);
            } else if u32::from(ch) < 0x20 {
                self.text.push('^');
                self.text
                    .push(char::from_u32(u32::from(ch) + 0x40).unwrap_or('\u{fffd}'));
            } else {
                self.text.push('\u{fffd}');
            }
        }
    }
}

/// Strips known spoofing-relevant Unicode format controls that reverse
/// or hide status copy, then maps remaining controls to caret or U+FFFD.
pub fn sanitize_status_cause(cause: &str) -> String {
    let mut out = String::with_capacity(cause.len());
    for ch in cause.chars() {
        if is_stripped_format(ch) {
            continue;
        }
        if ch == '\n' || !ch.is_control() {
            out.push(ch);
        } else if u32::from(ch) < 0x20 {
            out.push('^');
            out.push(char::from_u32(u32::from(ch) + 0x40).unwrap_or('\u{fffd}'));
        } else {
            out.push('\u{fffd}');
        }
    }
    out
}

/// Known spoofing-relevant Unicode format controls (Cf). This list is
/// not exhaustive Cf coverage.
fn is_stripped_format(ch: char) -> bool {
    matches!(
        ch,
        '\u{00AD}'
            | '\u{0600}'..='\u{0605}'
            | '\u{061C}'
            | '\u{06DD}'
            | '\u{070F}'
            | '\u{0890}'..='\u{0891}'
            | '\u{08E2}'
            | '\u{17B4}'..='\u{17B5}'
            | '\u{180B}'..='\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{206F}'
            | '\u{110BD}'
            | '\u{1D173}'..='\u{1D17A}'
            | '\u{FEFF}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{E0000}'..='\u{E007F}'
    )
}
