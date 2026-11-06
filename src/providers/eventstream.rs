//! Bounded AWS event-stream framing for the Bedrock Converse response.
//!
//! A message is `total-length | headers-length | prelude-crc` (12 bytes),
//! the header block, the payload, and a 4-byte message CRC. This decoder
//! owns the length framing only: a split read is buffered until the
//! declared message arrives, a frame past the per-frame bound or a stream
//! past the total bound denies, and a partial trailing message is a typed
//! truncation rather than a silent end of stream. The Bedrock reducer
//! classifies the decoded headers and payload; this module never treats a
//! frame as a terminal event.

use std::collections::BTreeMap;

/// The largest single event-stream message this build admits.
pub const MAX_EVENTSTREAM_FRAME_BYTES: usize = 1024 * 1024;

/// The largest whole Converse response stream this build admits.
pub const MAX_EVENTSTREAM_BYTES: usize = 8 * 1024 * 1024;

/// Why an event-stream byte sequence cannot be framed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EventStreamError {
    #[error("event-stream frame of {length} bytes exceeds the {limit}-byte bound")]
    FrameTooLarge { length: usize, limit: usize },
    #[error("event-stream exceeds the {limit}-byte stream bound")]
    StreamTooLarge { limit: usize },
    #[error("event-stream frame truncated: declared {declared}, remaining {remaining}")]
    TruncatedFrame { declared: usize, remaining: usize },
    #[error("event-stream frame length is malformed")]
    MalformedFrame,
    #[error("event-stream header is malformed")]
    MalformedHeader,
}

/// One decoded message: the headers the Bedrock reducer reads, and the
/// exact payload bytes it parses as JSON.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub message_type: Option<String>,
    pub event_type: Option<String>,
    pub exception_type: Option<String>,
    pub payload: Vec<u8>,
}

/// A streaming frame decoder that retains bytes across read boundaries.
#[derive(Debug, Default)]
pub struct EventStreamDecoder {
    buffer: Vec<u8>,
    consumed: usize,
}

impl EventStreamDecoder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends one read and yields every complete frame it now contains.
    ///
    /// # Errors
    /// [`EventStreamError::StreamTooLarge`] when the total input exceeds
    /// [`MAX_EVENTSTREAM_BYTES`]; [`EventStreamError::FrameTooLarge`] for
    /// a message past [`MAX_EVENTSTREAM_FRAME_BYTES`]; and the frame or
    /// header denials for a malformed length or header block.
    pub fn feed(&mut self, bytes: &[u8]) -> Result<Vec<Frame>, EventStreamError> {
        let consumed = self.consumed.saturating_add(bytes.len());
        if consumed > MAX_EVENTSTREAM_BYTES {
            return Err(EventStreamError::StreamTooLarge {
                limit: MAX_EVENTSTREAM_BYTES,
            });
        }
        self.consumed = consumed;
        self.buffer.extend_from_slice(bytes);
        let mut frames = Vec::new();
        while let Some(frame) = self.next_frame()? {
            frames.push(frame);
        }
        Ok(frames)
    }

    /// Confirms the stream ended on a message boundary.
    ///
    /// # Errors
    /// [`EventStreamError::TruncatedFrame`] when bytes remain after the
    /// last complete message.
    pub fn finish(&self) -> Result<(), EventStreamError> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        let declared = self
            .buffer
            .get(..4)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u32::from_be_bytes)
            .map(|length| usize::try_from(length).unwrap_or(usize::MAX))
            .unwrap_or(0);
        Err(EventStreamError::TruncatedFrame {
            declared,
            remaining: self.buffer.len(),
        })
    }

    fn next_frame(&mut self) -> Result<Option<Frame>, EventStreamError> {
        let Some(prelude) = self.buffer.get(..12) else {
            return Ok(None);
        };
        let total = read_u32(prelude, 0)?;
        let headers_length = read_u32(prelude, 4)?;
        if total < 16 || headers_length > total - 16 {
            return Err(EventStreamError::MalformedFrame);
        }
        if total > MAX_EVENTSTREAM_FRAME_BYTES {
            return Err(EventStreamError::FrameTooLarge {
                length: total,
                limit: MAX_EVENTSTREAM_FRAME_BYTES,
            });
        }
        if self.buffer.len() < total {
            return Ok(None);
        }
        let frame = self
            .buffer
            .get(..total)
            .ok_or(EventStreamError::MalformedFrame)?;
        let headers_end = 12usize
            .checked_add(headers_length)
            .ok_or(EventStreamError::MalformedFrame)?;
        let payload_end = total
            .checked_sub(4)
            .ok_or(EventStreamError::MalformedFrame)?;
        let header_bytes = frame
            .get(12..headers_end)
            .ok_or(EventStreamError::MalformedFrame)?;
        let payload = frame
            .get(headers_end..payload_end)
            .ok_or(EventStreamError::MalformedFrame)?
            .to_vec();
        let mut headers = parse_headers(header_bytes)?;
        let message_type = headers.remove(":message-type");
        let event_type = headers.remove(":event-type");
        let exception_type = headers.remove(":exception-type");
        self.buffer.drain(..total);
        Ok(Some(Frame {
            message_type,
            event_type,
            exception_type,
            payload,
        }))
    }
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<usize, EventStreamError> {
    let chunk = bytes
        .get(offset..offset.saturating_add(4))
        .ok_or(EventStreamError::MalformedFrame)?;
    let number = u32::from_be_bytes(
        chunk
            .try_into()
            .map_err(|_array| EventStreamError::MalformedFrame)?,
    );
    Ok(usize::try_from(number).unwrap_or(usize::MAX))
}

fn parse_headers(mut bytes: &[u8]) -> Result<BTreeMap<String, String>, EventStreamError> {
    let mut headers = BTreeMap::new();
    while !bytes.is_empty() {
        let (name_length, rest) = bytes
            .split_first()
            .ok_or(EventStreamError::MalformedHeader)?;
        let name_length = usize::from(*name_length);
        let (name, rest) = split(rest, name_length)?;
        let name = std::str::from_utf8(name).map_err(|_utf8| EventStreamError::MalformedHeader)?;
        let (value_type, rest) = rest
            .split_first()
            .ok_or(EventStreamError::MalformedHeader)?;
        let (value, rest) = header_value(*value_type, rest)?;
        if let Some(value) = value {
            headers.insert(name.to_owned(), value);
        }
        bytes = rest;
    }
    Ok(headers)
}

fn header_value(value_type: u8, bytes: &[u8]) -> Result<(Option<String>, &[u8]), EventStreamError> {
    let (length, rest) = match value_type {
        0 | 1 => return Ok((None, bytes)),
        2 => (1, bytes),
        3 => (2, bytes),
        4 => (4, bytes),
        5 | 8 => (8, bytes),
        6 | 7 => {
            let (length, rest) = split(bytes, 2)?;
            let length = u16::from_be_bytes(
                length
                    .try_into()
                    .map_err(|_array| EventStreamError::MalformedHeader)?,
            );
            (usize::from(length), rest)
        }
        9 => (16, bytes),
        _ => return Err(EventStreamError::MalformedHeader),
    };
    let (value, rest) = split(rest, length)?;
    if value_type == 7 {
        let value =
            std::str::from_utf8(value).map_err(|_utf8| EventStreamError::MalformedHeader)?;
        return Ok((Some(value.to_owned()), rest));
    }
    Ok((None, rest))
}

fn split(bytes: &[u8], length: usize) -> Result<(&[u8], &[u8]), EventStreamError> {
    if bytes.len() < length {
        return Err(EventStreamError::MalformedHeader);
    }
    Ok(bytes.split_at(length))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn string_header(name: &str, value: &str) -> Vec<u8> {
        let mut header = Vec::new();
        header.push(u8::try_from(name.len()).expect("header name fits"));
        header.extend_from_slice(name.as_bytes());
        header.push(7);
        header.extend_from_slice(
            &u16::try_from(value.len())
                .expect("header value fits")
                .to_be_bytes(),
        );
        header.extend_from_slice(value.as_bytes());
        header
    }

    fn frame(event_type: &str, payload: &[u8]) -> Vec<u8> {
        let mut headers = string_header(":message-type", "event");
        headers.extend(string_header(":event-type", event_type));
        framed(&headers, payload)
    }

    fn framed(headers: &[u8], payload: &[u8]) -> Vec<u8> {
        let total = 12 + headers.len() + payload.len() + 4;
        let mut message = Vec::with_capacity(total);
        message.extend_from_slice(
            &u32::try_from(total)
                .expect("frame fits a u32")
                .to_be_bytes(),
        );
        message.extend_from_slice(
            &u32::try_from(headers.len())
                .expect("header block fits a u32")
                .to_be_bytes(),
        );
        message.extend_from_slice(&0u32.to_be_bytes());
        message.extend_from_slice(headers);
        message.extend_from_slice(payload);
        message.extend_from_slice(&0u32.to_be_bytes());
        message
    }

    #[test]
    fn eventstream_frames_survive_split_feeds() {
        let message = frame("contentBlockDelta", br#"{"delta":{"text":"hi"}}"#);
        let mut decoder = EventStreamDecoder::new();
        let mut frames = Vec::new();
        for byte in message {
            frames.extend(decoder.feed(&[byte]).expect("partial feed"));
        }
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].message_type.as_deref(), Some("event"));
        assert_eq!(frames[0].event_type.as_deref(), Some("contentBlockDelta"));
        assert_eq!(frames[0].payload, br#"{"delta":{"text":"hi"}}"#.to_vec());
        decoder.finish().expect("complete stream");
    }

    #[test]
    fn eventstream_rejects_an_oversized_frame() {
        let mut prelude = Vec::new();
        prelude.extend_from_slice(
            &u32::try_from(MAX_EVENTSTREAM_FRAME_BYTES + 1)
                .unwrap()
                .to_be_bytes(),
        );
        prelude.extend_from_slice(&0u32.to_be_bytes());
        prelude.extend_from_slice(&0u32.to_be_bytes());
        let error = EventStreamDecoder::new()
            .feed(&prelude)
            .expect_err("oversized frame");
        assert!(matches!(error, EventStreamError::FrameTooLarge { .. }));
    }

    #[test]
    fn eventstream_rejects_a_stream_over_the_total_bound() {
        let bytes = vec![0u8; MAX_EVENTSTREAM_BYTES + 1];
        let error = EventStreamDecoder::new()
            .feed(&bytes)
            .expect_err("oversized stream");
        assert!(matches!(error, EventStreamError::StreamTooLarge { .. }));
    }

    #[test]
    fn eventstream_rejects_a_partial_trailing_frame() {
        let message = frame("messageStop", br#"{"stopReason":"end_turn"}"#);
        let mut decoder = EventStreamDecoder::new();
        decoder
            .feed(&message[..message.len() - 3])
            .expect("partial frame buffers");
        let error = decoder.finish().expect_err("truncated frame");
        assert!(matches!(error, EventStreamError::TruncatedFrame { .. }));
    }

    #[test]
    fn eventstream_rejects_malformed_headers() {
        let headers = [2u8, b':', b'x', 99];
        let message = framed(&headers, b"{}");
        let error = EventStreamDecoder::new()
            .feed(&message)
            .expect_err("unknown header value type");
        assert_eq!(error, EventStreamError::MalformedHeader);
    }
}
