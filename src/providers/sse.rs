//! The one bounded incremental SSE parser every streaming dialect
//! shares (SRC-004): WHATWG HTML §9.2.5–9.2.6 semantics over arbitrary
//! byte chunks. Line splitting runs on raw bytes — CR and LF are ASCII
//! and can never appear inside a multibyte UTF-8 sequence — so a code
//! point split across chunks is held in the byte buffer until its line
//! completes, and each complete line decodes exactly once. One leading
//! BOM is removed; CR, LF and CRLF all terminate a line, including a
//! CR+LF pair split across a chunk boundary; comment lines and unknown
//! fields are ignored; exactly one space after the field colon is
//! stripped; a field without a colon carries an empty value; `data`
//! lines join and lose the final LF; a block without `data` never
//! dispatches (the `id` it carried still applies); an `id` containing
//! U+0000 and a non-ASCII-digit `retry` are ignored; and an incomplete
//! block at EOF is discarded — the caller's unknown terminal, never an
//! implicit success.
//!
//! Bounds are the fail-closed contract: one physical line and one
//! event's accumulated `data` each carry a hard cap, and an overrun is
//! a typed [`SseError`], never a truncation. Every byte is scanned at
//! most twice — the parser keeps a cursor past the terminator-free
//! prefix, so hostile chunk-by-chunk delivery stays linear in the
//! input size.

/// The byte cap on one physical line — a longer line fails closed
/// instead of buffering unbounded.
const MAX_LINE_BYTES: usize = 256 * 1024;

/// The byte cap on one event's accumulated `data` buffer.
const MAX_DATA_BYTES: usize = 4 * 1024 * 1024;

/// The UTF-8 BOM — removed once, only as the stream's leading bytes.
const BOM: &[u8] = &[0xEF, 0xBB, 0xBF];

/// One dispatched event block (§9.2.6): the accumulated `data` buffer
/// with its final LF removed, the event-type buffer verbatim (empty
/// when the block carried no `event` field — the caller maps that to
/// the default message type), the last event id the stream set, and
/// the last ASCII-digit `retry` it set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseEvent {
    pub event: String,
    pub data: String,
    pub id: Option<String>,
    pub retry: Option<u64>,
}

/// The parser's fail-closed diagnostics — every refusal names the
/// bound crossed or the decode that failed; nothing is silently
/// dropped.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SseError {
    /// A held byte bound was crossed: one over-long physical line or
    /// one event's accumulated `data`.
    #[error("sse input exceeded the {what} bound of {limit} bytes")]
    Overrun { what: &'static str, limit: usize },
    /// A complete line was not valid UTF-8.
    #[error("sse line is not valid utf-8")]
    InvalidUtf8,
}

/// The pending block's field buffers plus the stream-level `id`/`retry`
/// values — kept apart from the byte buffer so a complete line can be
/// processed while the byte tail is still borrowed.
#[derive(Default)]
struct Block {
    /// The pending block's `event` buffer.
    event_type: String,
    /// The pending block's `data` buffer — one LF per `data` field.
    data: String,
    /// The stream's last event id — applied at dispatch even when the
    /// intervening blocks carried no `data`.
    last_id: Option<String>,
    /// The stream's last `retry` field value.
    retry: Option<u64>,
}

impl Block {
    /// §9.2.6 line processing: a blank line dispatches the block; a
    /// line starting with a colon is a comment; a line without one is
    /// a field name with an empty value; a colon consumes exactly one
    /// following space.
    fn line(&mut self, raw: &[u8], events: &mut Vec<SseEvent>) -> Result<(), SseError> {
        if raw.len() > MAX_LINE_BYTES {
            return Err(SseError::Overrun {
                what: "line",
                limit: MAX_LINE_BYTES,
            });
        }
        let text = std::str::from_utf8(raw).map_err(|_utf8| SseError::InvalidUtf8)?;
        if text.is_empty() {
            self.dispatch(events);
            return Ok(());
        }
        if text.starts_with(':') {
            return Ok(());
        }
        let (field, value) = match text.split_once(':') {
            Some((field, value)) => (field, value.strip_prefix(' ').unwrap_or(value)),
            None => (text, ""),
        };
        match field {
            "event" => {
                self.event_type.clear();
                self.event_type.push_str(value);
            }
            "data" => {
                let next = self.data.len() + value.len() + 1;
                if next > MAX_DATA_BYTES {
                    return Err(SseError::Overrun {
                        what: "event data",
                        limit: MAX_DATA_BYTES,
                    });
                }
                self.data.push_str(value);
                self.data.push('\n');
            }
            // An id containing U+0000 is ignored outright; any other
            // value becomes the stream's last event id.
            "id" => {
                if !value.contains('\0') {
                    self.last_id = Some(value.to_string());
                }
            }
            // Only a pure ASCII-digit retry applies.
            "retry" => {
                if !value.is_empty()
                    && value.bytes().all(|b| b.is_ascii_digit())
                    && let Ok(ms) = value.parse::<u64>()
                {
                    self.retry = Some(ms);
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// A block dispatches only when its `data` buffer is non-empty —
    /// the final LF each `data` field appended is removed — and the
    /// field buffers reset either way while `id`/`retry` persist.
    fn dispatch(&mut self, events: &mut Vec<SseEvent>) {
        if !self.data.is_empty() {
            let mut data = std::mem::take(&mut self.data);
            data.pop();
            events.push(SseEvent {
                event: std::mem::take(&mut self.event_type),
                data,
                id: self.last_id.clone(),
                retry: self.retry,
            });
        }
        self.event_type.clear();
    }
}

/// Incremental parser state: the unprocessed byte tail, the scan
/// cursor into it, and the pending block's field buffers.
pub struct SseParser {
    /// Bytes not yet consumed into a line — a partial line tail and at
    /// most one held CR whose pair byte has not arrived.
    buf: Vec<u8>,
    /// `buf[..scanned]` is known to hold no terminator; the next feed
    /// resumes the terminator scan there, keeping per-byte work O(1).
    scanned: usize,
    /// The stream-leading BOM decision is still open — a split BOM
    /// prefix holds the bytes until the third byte or EOF.
    bom_pending: bool,
    block: Block,
}

impl SseParser {
    #[must_use]
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            scanned: 0,
            bom_pending: true,
            block: Block::default(),
        }
    }

    /// Feeds one chunk; returns every event block the new bytes
    /// completed. A chunk boundary inside a code point, a line ending
    /// or a BOM is held, never mishandled.
    ///
    /// # Errors
    /// [`SseError::Overrun`] when a line or an event's data crosses its
    /// bound; [`SseError::InvalidUtf8`] when a complete line does not
    /// decode.
    pub fn feed(&mut self, chunk: &[u8]) -> Result<Vec<SseEvent>, SseError> {
        if chunk.is_empty() {
            return Ok(Vec::new());
        }
        // The completed line will be the terminator-free prefix the
        // buffer already holds plus this chunk's share up to its first
        // terminator — bound that sum before copying, so one hostile
        // chunk can never grow the held tail past the cap first. A
        // held CR at the tail pairs inside the pump, whose post-scan
        // invariant bounds the new tail instead.
        if self.buf.last() != Some(&b'\r') {
            let held = if self.bom_pending {
                self.buf.len()
            } else {
                self.scanned
            };
            let pending = held
                + chunk
                    .iter()
                    .position(|b| matches!(b, b'\r' | b'\n'))
                    .unwrap_or(chunk.len());
            if pending > MAX_LINE_BYTES {
                return Err(SseError::Overrun {
                    what: "line",
                    limit: MAX_LINE_BYTES,
                });
            }
        }
        self.buf.extend_from_slice(chunk);
        self.pump(false)
    }

    /// EOF: a trailing CR terminates its line and trailing complete
    /// lines flush; then the unterminated byte tail and the pending
    /// block are discarded (§9.2.5 — an event incomplete at end of
    /// stream is never dispatched).
    ///
    /// # Errors
    /// [`SseError::InvalidUtf8`] when a line completed by the final
    /// bytes does not decode; the partial tail itself is discarded
    /// without decoding.
    pub fn finish(&mut self) -> Result<Vec<SseEvent>, SseError> {
        let events = self.pump(true)?;
        self.buf.clear();
        // The scan cursor is buffer state: it dies with the bytes or a
        // later feed scans past the end of a shorter tail.
        self.scanned = 0;
        self.block.event_type.clear();
        self.block.data.clear();
        Ok(events)
    }

    /// Drives the line loop over the buffered bytes. `at_eof` decides a
    /// trailing CR: mid-stream it is held for a possible LF pair, at
    /// EOF it terminates its line.
    fn pump(&mut self, at_eof: bool) -> Result<Vec<SseEvent>, SseError> {
        let mut events = Vec::new();
        if self.bom_pending {
            let held = self.buf.as_slice();
            // A strict BOM prefix shorter than the BOM waits for the
            // missing bytes; anything else decides immediately.
            if !held.is_empty() && held.len() < BOM.len() && BOM.starts_with(held) && !at_eof {
                return Ok(events);
            }
            if held.starts_with(BOM) {
                self.buf.drain(..BOM.len());
            }
            self.bom_pending = false;
            self.scanned = 0;
        }
        let mut consumed = 0usize;
        loop {
            let scan_from = consumed.max(self.scanned);
            let Some(off) = self.buf[scan_from..]
                .iter()
                .position(|b| matches!(b, b'\r' | b'\n'))
            else {
                self.scanned = self.buf.len();
                break;
            };
            let at = scan_from + off;
            match self.buf[at] {
                b'\r' => {
                    if at + 1 == self.buf.len() && !at_eof {
                        // The CR may pair with an LF that has not
                        // arrived — hold the whole unterminated line.
                        self.scanned = at;
                        break;
                    }
                    let width = if at + 1 < self.buf.len() && self.buf[at + 1] == b'\n' {
                        2
                    } else {
                        1
                    };
                    self.block.line(&self.buf[consumed..at], &mut events)?;
                    consumed = at + width;
                    self.scanned = consumed;
                }
                _ => {
                    self.block.line(&self.buf[consumed..at], &mut events)?;
                    consumed = at + 1;
                    self.scanned = consumed;
                }
            }
        }
        self.buf.drain(..consumed);
        self.scanned -= consumed;
        // The held line is the terminator-free prefix — a CR held for
        // its LF pair is not a byte of it, so the cap applies to the
        // scanned prefix, not the raw buffer length.
        if self.scanned > MAX_LINE_BYTES {
            return Err(SseError::Overrun {
                what: "line",
                limit: MAX_LINE_BYTES,
            });
        }
        Ok(events)
    }
}

impl std::fmt::Debug for SseParser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The buffer holds raw peer bytes — parser state shape is the
        // diagnostic surface, never the unvalidated wire data itself.
        f.debug_struct("SseParser")
            .field("buffered", &self.buf.len())
            .field("scanned", &self.scanned)
            .field("bom_pending", &self.bom_pending)
            .finish_non_exhaustive()
    }
}

impl Default for SseParser {
    fn default() -> Self {
        Self::new()
    }
}
