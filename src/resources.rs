//! Resource holders, the bounded notification queue, and the safe
//! external-data flow. Overflow never drops obligations silently: the
//! backlog is replaced by one resync marker.

use crate::contracts::Event;
use std::collections::VecDeque;

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
