//! The confined-effect protocol the rivect executor and this helper share:
//! exit verdicts, the binary-resolution rule, the `launch` memory-budget
//! option, and the safe wrappers the host and a capped child need (fd
//! flags, process-group kill, memory limit, map size, pipe readiness). The
//! owner errors use `thiserror`; FFI calls stay behind checked safe
//! wrappers, and the effect syscall surface lives in the binary.

use std::cell::RefCell;
use std::io;
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, FromRawFd as _};
use std::path::PathBuf;
use std::time::Duration;

/// The original bounded observation at an owned-launch failure boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnedFaultCause {
    Io {
        operation: u8,
        field: u8,
        errno: i32,
    },
    Readback {
        field: u8,
        actual: i64,
    },
    WriteCount {
        requested: u64,
        returned: u64,
    },
    Missing {
        field: u8,
    },
    Duplicate {
        field: u8,
        count: u64,
    },
    Malformed {
        field: u8,
        offset: u64,
    },
    NumericOverflow {
        field: u8,
        offset: u64,
    },
    Trailing {
        field: u8,
        offset: u64,
    },
    Limit {
        field: u8,
        limit: u64,
        observed: u64,
    },
    EarlyEof {
        field: u8,
        expected: u64,
        observed: u64,
    },
    MapMismatch {
        inside_pair: u64,
        outside_pair: u64,
        count_pair: u64,
    },
    ExtraMap {
        ordinal_count: u64,
        inside: u32,
        outside: u32,
    },
    Mismatch {
        field: u8,
        expected: u64,
        observed: u64,
    },
    SetgroupsAllow,
    Changed {
        field: u8,
    },
    Unverifiable {
        field: u8,
    },
    LiveDisappearance {
        tid: u32,
    },
    Deadline,
    Cancelled,
    HardLimitMismatch {
        field: u8,
        expected: u64,
        observed: u64,
    },
    GidMapMismatch {
        inside_pair: u64,
        outside_pair: u64,
        count_pair: u64,
    },
    ExtraGidMap {
        ordinal_count: u64,
        inside: u32,
        outside: u32,
    },
}

/// The fixed execution profile carried by an authenticated entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnedProfile {
    Worker,
    Index,
    Check,
}

impl OwnedProfile {
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::Worker => "worker",
            Self::Index => "index",
            Self::Check => "check",
        }
    }
}

/// The bounded control records shared by the native helper and executor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnedRecord {
    Entry {
        profile: OwnedProfile,
        baseline: u32,
        nproc: u32,
        verified: u8,
    },
    Exit(u8),
    Signal(u8),
    Stop(OwnedStop),
    Fault(OwnedFault),
}

/// A fixed stop reason; it never carries payload output or an arbitrary token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnedStop {
    Cancelled,
    Deadline,
    Observation,
    ControlLost,
}

impl OwnedStop {
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::Cancelled => "cancelled",
            Self::Deadline => "deadline",
            Self::Observation => "observation",
            Self::ControlLost => "control_lost",
        }
    }
}

impl OwnedRecord {
    /// Encodes one canonical bounded record.
    ///
    /// # Errors
    /// Returns a grammar refusal for an invalid signal or unverified entry.
    pub fn encode(self) -> Result<String, OwnedProtocolError> {
        let frame = match self {
            Self::Entry {
                profile,
                baseline,
                nproc,
                verified,
            } if verified == 63 && baseline > 0 && nproc > 0 => format!(
                "owned-launch-v1 entry {} {baseline} {nproc} {verified}\n",
                profile.token()
            ),
            Self::Exit(code) => format!("owned-launch-v1 terminal exit {code}\n"),
            Self::Signal(signal) if (1..=64).contains(&signal) => {
                format!("owned-launch-v1 terminal signal {signal}\n")
            }
            Self::Stop(reason) => format!("owned-launch-v1 terminal stop {}\n", reason.token()),
            Self::Fault(fault) => return fault.encode(),
            _ => return Err(OwnedProtocolError::Malformed),
        };
        if frame.len() > 128 {
            return Err(OwnedProtocolError::Oversize);
        }
        Ok(frame)
    }
}

/// Tests the only legal ordered pair of pre-entry fault observations.
/// Both records remain immutable; later protocol loss cannot replace either.
#[must_use]
pub fn owned_fault_pair(primary: OwnedFault, secondary: OwnedFault) -> bool {
    fn rank(fault: OwnedFault) -> Option<u8> {
        if fault.boundary() != "owned.child.spawn" {
            return None;
        }
        match fault.cause() {
            OwnedFaultCause::Io {
                operation: 5 | 22,
                field: 24,
                ..
            }
            | OwnedFaultCause::Missing { field: 24 }
            | OwnedFaultCause::Duplicate { field: 24, .. }
            | OwnedFaultCause::Malformed { field: 24, .. }
            | OwnedFaultCause::NumericOverflow { field: 24, .. }
            | OwnedFaultCause::Trailing { field: 24, .. }
            | OwnedFaultCause::Limit { field: 24, .. }
            | OwnedFaultCause::EarlyEof { field: 24, .. } => Some(0),
            OwnedFaultCause::Io {
                operation: 7,
                field: 20,
                ..
            } => Some(1),
            OwnedFaultCause::Io {
                operation: 14,
                field: 0,
                ..
            } => Some(2),
            _ => None,
        }
    }
    match (rank(primary), rank(secondary)) {
        (None, Some(_)) => true,
        (Some(first), Some(next)) => first < next,
        _ => false,
    }
}

/// Owns the bounded external record grammar and retains complete fault facts
/// when a later record is malformed, duplicated, or lost.
#[derive(Debug, Default)]
pub struct OwnedSequence {
    entry: Option<OwnedRecord>,
    terminal: Option<OwnedRecord>,
    primary: Option<OwnedFault>,
    secondary: Option<OwnedFault>,
    failed: bool,
}

impl OwnedSequence {
    /// Admits one complete record in the external language.
    ///
    /// # Errors
    /// Refuses a third frame, a reversed fault pair, or any other sequence.
    pub fn push(&mut self, record: OwnedRecord) -> Result<(), OwnedProtocolError> {
        if let Err(error) = record.encode() {
            self.failed = true;
            return Err(error);
        }
        let valid = if self.failed {
            false
        } else {
            match record {
                OwnedRecord::Entry { .. } => {
                    if self.entry.is_none() && self.primary.is_none() && self.terminal.is_none() {
                        self.entry = Some(record);
                        true
                    } else {
                        false
                    }
                }
                OwnedRecord::Fault(fault) => {
                    if self.entry.is_some() {
                        if self.terminal.is_none() {
                            self.terminal = Some(record);
                            self.primary = Some(fault);
                            true
                        } else {
                            false
                        }
                    } else if let Some(primary) = self.primary {
                        if self.secondary.is_none() && owned_fault_pair(primary, fault) {
                            self.secondary = Some(fault);
                            true
                        } else {
                            false
                        }
                    } else {
                        self.primary = Some(fault);
                        true
                    }
                }
                _ => {
                    if self.entry.is_some() && self.terminal.is_none() {
                        self.terminal = Some(record);
                        true
                    } else {
                        false
                    }
                }
            }
        };
        if valid {
            Ok(())
        } else {
            self.failed = true;
            Err(OwnedProtocolError::Malformed)
        }
    }

    /// Marks transport loss without discarding already authenticated facts.
    pub fn lost(&mut self) {
        self.failed = true;
    }

    #[must_use]
    pub fn entry(&self) -> Option<OwnedRecord> {
        self.entry
    }
    #[must_use]
    pub fn terminal(&self) -> Option<OwnedRecord> {
        self.terminal
    }
    #[must_use]
    pub fn primary(&self) -> Option<OwnedFault> {
        self.primary
    }
    #[must_use]
    pub fn secondary(&self) -> Option<OwnedFault> {
        self.secondary
    }
    /// Only a complete entry/terminal transcript and normal trusted waiter
    /// completion can establish release. EOF and actual wait are caller facts.
    #[must_use]
    pub fn released(&self, eof: bool, waiter_success: bool) -> bool {
        !self.failed
            && eof
            && waiter_success
            && self.entry.is_some()
            && matches!(
                self.terminal,
                Some(OwnedRecord::Exit(_) | OwnedRecord::Signal(_) | OwnedRecord::Stop(_))
            )
    }
}

/// Parses one complete frame into a record or the exact field-24 refusal.
///
/// Offsets are zero-based indexes into the whole frame, including the prefix.
/// A frame longer than 128 bytes is `Limit` before the body is examined.
///
/// # Errors
/// Returns the closed cause for a frame that is not one canonical record.
pub fn parse_owned_record_observed(bytes: &[u8]) -> Result<OwnedRecord, OwnedFaultCause> {
    if bytes.len() > 128 {
        return Err(OwnedFaultCause::Limit {
            field: 24,
            limit: 128,
            observed: bytes.len() as u64,
        });
    }
    if bytes.last() != Some(&b'\n') {
        let observed = bytes.len() as u64;
        return Err(OwnedFaultCause::EarlyEof {
            field: 24,
            expected: observed + 1,
            observed,
        });
    }
    let body_len = bytes.len() - 1;
    for (index, byte) in bytes[..body_len].iter().enumerate() {
        if !byte.is_ascii_graphic() && *byte != b' ' {
            return Err(malformed_at(index));
        }
    }
    let tokens = split_frame_tokens(bytes, body_len)?;
    let record = decode_owned_record(bytes, &tokens)?;
    if record.encode().ok().as_deref().map(str::as_bytes) != Some(bytes) {
        return Err(malformed_at(
            tokens.first().map(|token| token.start).unwrap_or(0),
        ));
    }
    Ok(record)
}

/// Parses one complete authenticated control record without admitting raw output.
///
/// # Errors
/// Returns a typed grammar refusal before constructing invalid values.
pub fn parse_owned_record(bytes: &[u8]) -> Result<OwnedRecord, OwnedProtocolError> {
    match parse_owned_record_observed(bytes) {
        Ok(record) => Ok(record),
        Err(_) if bytes.len() > 128 => Err(OwnedProtocolError::Oversize),
        Err(_) => Err(OwnedProtocolError::Malformed),
    }
}

/// An authenticated failure record with a closed boundary and cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnedFault {
    boundary: &'static str,
    cause: OwnedFaultCause,
}

/// A refusal to interpret an owned-launch control frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum OwnedProtocolError {
    #[error("invalid owned launch frame")]
    Malformed,
    #[error("owned launch frame exceeds the byte limit")]
    Oversize,
}

/// Parses one bounded canonical fault frame.
///
/// # Errors
/// Returns a typed refusal for an unknown, incomplete, or invalid frame.
pub fn parse_owned_fault(bytes: &[u8]) -> Result<OwnedFault, OwnedProtocolError> {
    match parse_owned_record_observed(bytes) {
        Ok(OwnedRecord::Fault(fault)) => Ok(fault),
        Ok(_) => Err(OwnedProtocolError::Malformed),
        Err(_) if bytes.len() > 128 => Err(OwnedProtocolError::Oversize),
        Err(_) => Err(OwnedProtocolError::Malformed),
    }
}

fn malformed_at(offset: usize) -> OwnedFaultCause {
    OwnedFaultCause::Malformed {
        field: 24,
        offset: offset as u64,
    }
}

fn overflow_at(offset: usize) -> OwnedFaultCause {
    OwnedFaultCause::NumericOverflow {
        field: 24,
        offset: offset as u64,
    }
}

#[derive(Clone, Copy)]
struct FrameToken {
    start: usize,
    end: usize,
}

fn split_frame_tokens(bytes: &[u8], body_len: usize) -> Result<Vec<FrameToken>, OwnedFaultCause> {
    if body_len == 0 {
        return Err(OwnedFaultCause::Missing { field: 24 });
    }
    let mut tokens = Vec::new();
    let mut index = 0;
    while index < body_len {
        if bytes[index] == b' ' {
            return Err(malformed_at(index));
        }
        let start = index;
        while index < body_len && bytes[index] != b' ' {
            index += 1;
        }
        tokens.push(FrameToken { start, end: index });
        if index < body_len {
            let separator = index;
            index += 1;
            if index == body_len || bytes[index] == b' ' {
                let offend = if index == body_len { separator } else { index };
                return Err(malformed_at(offend));
            }
        }
    }
    Ok(tokens)
}

fn frame_token(tokens: &[FrameToken], index: usize) -> Result<FrameToken, OwnedFaultCause> {
    tokens
        .get(index)
        .copied()
        .ok_or(OwnedFaultCause::Missing { field: 24 })
}

fn token_bytes(bytes: &[u8], token: FrameToken) -> &[u8] {
    &bytes[token.start..token.end]
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn hex_text(bytes: &[u8], token: FrameToken, width: usize) -> Result<(), OwnedFaultCause> {
    let length = token.end - token.start;
    let present = length.min(width);
    for index in 0..present {
        if hex_digit(bytes[token.start + index]).is_none() {
            return Err(malformed_at(token.start + index));
        }
    }
    if length < width {
        return Err(malformed_at(token.end));
    }
    if length > width {
        return Err(malformed_at(token.start + width));
    }
    Ok(())
}

fn parse_hex_bounded(
    bytes: &[u8],
    token: FrameToken,
    width: usize,
    max: u64,
) -> Result<u64, OwnedFaultCause> {
    hex_text(bytes, token, width)?;
    let mut value: u128 = 0;
    for (index, byte) in token_bytes(bytes, token).iter().enumerate() {
        let Some(digit) = hex_digit(*byte) else {
            return Err(malformed_at(token.start + index));
        };
        if value > u128::from(max) / 16 {
            return Err(overflow_at(token.start + index));
        }
        let next = value * 16 + u128::from(digit);
        if next > u128::from(max) {
            return Err(overflow_at(token.start + index));
        }
        value = next;
    }
    Ok(value as u64)
}

fn parse_decimal(bytes: &[u8], token: FrameToken, max: u64) -> Result<u64, OwnedFaultCause> {
    let text = token_bytes(bytes, token);
    if text.is_empty() {
        return Err(OwnedFaultCause::Missing { field: 24 });
    }
    if text.len() > 1 && text[0] == b'0' {
        return Err(malformed_at(token.start + 1));
    }
    let mut value: u128 = 0;
    for (index, byte) in text.iter().enumerate() {
        if !byte.is_ascii_digit() {
            return Err(malformed_at(token.start + index));
        }
        let digit = u128::from(byte - b'0');
        if value > u128::from(max) / 10 {
            return Err(overflow_at(token.start + index));
        }
        let next = value * 10 + digit;
        if next > u128::from(max) {
            return Err(overflow_at(token.start + index));
        }
        value = next;
    }
    Ok(value as u64)
}

fn fault_arity(tag: u64) -> Option<usize> {
    match tag {
        1 | 9 | 10 | 11 | 12 | 13 | 20 | 21 | 22 => Some(3),
        2 | 3 | 5 | 6 | 7 | 8 => Some(2),
        4 | 15 | 16 | 17 => Some(1),
        14 | 18 | 19 => Some(0),
        _ => None,
    }
}

fn decode_owned_record(
    bytes: &[u8],
    tokens: &[FrameToken],
) -> Result<OwnedRecord, OwnedFaultCause> {
    let head = frame_token(tokens, 0)?;
    if token_bytes(bytes, head) != b"owned-launch-v1" {
        return Err(malformed_at(head.start));
    }
    let kind = frame_token(tokens, 1)?;
    match token_bytes(bytes, kind) {
        b"entry" => decode_entry(bytes, tokens),
        b"terminal" => decode_terminal(bytes, tokens),
        _ => Err(malformed_at(kind.start)),
    }
}

fn finish_record(
    tokens: &[FrameToken],
    width: usize,
    record: OwnedRecord,
) -> Result<OwnedRecord, OwnedFaultCause> {
    if tokens.len() > width {
        return Err(OwnedFaultCause::Trailing {
            field: 24,
            offset: tokens[width].start as u64,
        });
    }
    Ok(record)
}

fn decode_entry(bytes: &[u8], tokens: &[FrameToken]) -> Result<OwnedRecord, OwnedFaultCause> {
    let profile_token = frame_token(tokens, 2)?;
    let profile = match token_bytes(bytes, profile_token) {
        b"worker" => OwnedProfile::Worker,
        b"index" => OwnedProfile::Index,
        b"check" => OwnedProfile::Check,
        _ => return Err(malformed_at(profile_token.start)),
    };
    let baseline_token = frame_token(tokens, 3)?;
    let baseline = parse_decimal(bytes, baseline_token, u64::from(u32::MAX))?;
    if baseline == 0 {
        return Err(malformed_at(baseline_token.start));
    }
    let nproc_token = frame_token(tokens, 4)?;
    let nproc = parse_decimal(bytes, nproc_token, u64::from(u32::MAX))?;
    if nproc == 0 {
        return Err(malformed_at(nproc_token.start));
    }
    let verified_token = frame_token(tokens, 5)?;
    let verified = parse_decimal(bytes, verified_token, u64::from(u8::MAX))?;
    if verified != 63 {
        return Err(malformed_at(verified_token.start));
    }
    finish_record(
        tokens,
        6,
        OwnedRecord::Entry {
            profile,
            baseline: baseline as u32,
            nproc: nproc as u32,
            verified: verified as u8,
        },
    )
}

fn decode_terminal(bytes: &[u8], tokens: &[FrameToken]) -> Result<OwnedRecord, OwnedFaultCause> {
    let verb = frame_token(tokens, 2)?;
    match token_bytes(bytes, verb) {
        b"exit" => {
            let code_token = frame_token(tokens, 3)?;
            let code = parse_decimal(bytes, code_token, u64::from(u8::MAX))?;
            finish_record(tokens, 4, OwnedRecord::Exit(code as u8))
        }
        b"signal" => {
            let signal_token = frame_token(tokens, 3)?;
            let signal = parse_decimal(bytes, signal_token, u64::from(u8::MAX))?;
            if !(1..=64).contains(&signal) {
                return Err(malformed_at(signal_token.start));
            }
            finish_record(tokens, 4, OwnedRecord::Signal(signal as u8))
        }
        b"stop" => {
            let reason_token = frame_token(tokens, 3)?;
            let reason = match token_bytes(bytes, reason_token) {
                b"cancelled" => OwnedStop::Cancelled,
                b"deadline" => OwnedStop::Deadline,
                b"observation" => OwnedStop::Observation,
                b"control_lost" => OwnedStop::ControlLost,
                _ => return Err(malformed_at(reason_token.start)),
            };
            finish_record(tokens, 4, OwnedRecord::Stop(reason))
        }
        b"fault" => decode_fault(bytes, tokens),
        _ => Err(malformed_at(verb.start)),
    }
}

fn decode_fault(bytes: &[u8], tokens: &[FrameToken]) -> Result<OwnedRecord, OwnedFaultCause> {
    let boundary_token = frame_token(tokens, 3)?;
    let tag_token = frame_token(tokens, 4)?;
    let boundary_name = std::str::from_utf8(token_bytes(bytes, boundary_token))
        .map_err(|_malformed| malformed_at(boundary_token.start))?;
    let boundary =
        child_fault_boundary(boundary_name).ok_or_else(|| malformed_at(boundary_token.start))?;
    let tag = parse_hex_bounded(bytes, tag_token, 4, u64::from(u16::MAX))?;
    let operands = &tokens[5..];
    let Some(arity) = fault_arity(tag) else {
        for token in operands {
            hex_text(bytes, *token, 16)?;
        }
        return Err(malformed_at(tag_token.start));
    };
    let mut words = [0_u64; 3];
    let present = operands.len().min(arity);
    for (index, token) in operands.iter().take(present).enumerate() {
        let max = fault_operand_max(tag, index);
        words[index] = parse_hex_bounded(bytes, *token, 16, max)?;
    }
    if operands.len() > arity {
        return Err(OwnedFaultCause::Trailing {
            field: 24,
            offset: operands[arity].start as u64,
        });
    }
    if operands.len() < arity {
        return Err(OwnedFaultCause::Missing { field: 24 });
    }
    let cause = fault_cause(tag, words)?;
    match OwnedFault::new(boundary, cause) {
        Ok(fault) => Ok(OwnedRecord::Fault(fault)),
        Err(OwnedProtocolError::Malformed | OwnedProtocolError::Oversize) => {
            Err(malformed_at(tag_token.start))
        }
    }
}

fn fault_operand_max(tag: u64, index: usize) -> u64 {
    match (tag, index) {
        (1, 0 | 1)
        | (2, 0)
        | (4, 0)
        | (5, 0)
        | (6, 0)
        | (7, 0)
        | (8, 0)
        | (9, 0)
        | (10, 0)
        | (13, 0)
        | (15, 0)
        | (16, 0)
        | (20, 0) => u64::from(u8::MAX),
        (1, 2) => i32::MAX as u64,
        (12, 1 | 2) | (17, 0) | (22, 1 | 2) => u64::from(u32::MAX),
        _ => u64::MAX,
    }
}

fn fault_cause(tag: u64, words: [u64; 3]) -> Result<OwnedFaultCause, OwnedFaultCause> {
    let [a, b, c] = words;
    let narrow = |value: u64| -> u8 { value as u8 };
    Ok(match tag {
        1 => OwnedFaultCause::Io {
            operation: narrow(a),
            field: narrow(b),
            errno: c as i32,
        },
        2 => OwnedFaultCause::Readback {
            field: narrow(a),
            actual: i64::from_ne_bytes(b.to_ne_bytes()),
        },
        3 => OwnedFaultCause::WriteCount {
            requested: a,
            returned: b,
        },
        4 => OwnedFaultCause::Missing { field: narrow(a) },
        5 => OwnedFaultCause::Duplicate {
            field: narrow(a),
            count: b,
        },
        6 => OwnedFaultCause::Malformed {
            field: narrow(a),
            offset: b,
        },
        7 => OwnedFaultCause::NumericOverflow {
            field: narrow(a),
            offset: b,
        },
        8 => OwnedFaultCause::Trailing {
            field: narrow(a),
            offset: b,
        },
        9 => OwnedFaultCause::Limit {
            field: narrow(a),
            limit: b,
            observed: c,
        },
        10 => OwnedFaultCause::EarlyEof {
            field: narrow(a),
            expected: b,
            observed: c,
        },
        11 => OwnedFaultCause::MapMismatch {
            inside_pair: a,
            outside_pair: b,
            count_pair: c,
        },
        12 => OwnedFaultCause::ExtraMap {
            ordinal_count: a,
            inside: b as u32,
            outside: c as u32,
        },
        13 => OwnedFaultCause::Mismatch {
            field: narrow(a),
            expected: b,
            observed: c,
        },
        14 => OwnedFaultCause::SetgroupsAllow,
        15 => OwnedFaultCause::Changed { field: narrow(a) },
        16 => OwnedFaultCause::Unverifiable { field: narrow(a) },
        17 => OwnedFaultCause::LiveDisappearance { tid: a as u32 },
        18 => OwnedFaultCause::Deadline,
        19 => OwnedFaultCause::Cancelled,
        20 => OwnedFaultCause::HardLimitMismatch {
            field: narrow(a),
            expected: b,
            observed: c,
        },
        21 => OwnedFaultCause::GidMapMismatch {
            inside_pair: a,
            outside_pair: b,
            count_pair: c,
        },
        22 => OwnedFaultCause::ExtraGidMap {
            ordinal_count: a,
            inside: b as u32,
            outside: c as u32,
        },
        _ => return Err(malformed_at(0)),
    })
}

fn child_fault_boundary(name: &str) -> Option<&'static str> {
    match name {
        "owned.waiter.initial_dumpable" => Some("owned.waiter.initial_dumpable"),
        "owned.waiter.dumpable" => Some("owned.waiter.dumpable"),
        "owned.init.dumpable" => Some("owned.init.dumpable"),
        "owned.waiter.initial_tracer" => Some("owned.waiter.initial_tracer"),
        "owned.waiter.tracer" => Some("owned.waiter.tracer"),
        "owned.waiter.overflow_uid" => Some("owned.waiter.overflow_uid"),
        "owned.waiter.overflow_gid" => Some("owned.waiter.overflow_gid"),
        "owned.namespace.user" => Some("owned.namespace.user"),
        "owned.namespace.mount" => Some("owned.namespace.mount"),
        "owned.namespace.pid" => Some("owned.namespace.pid"),
        "owned.namespace.setgroups.open" => Some("owned.namespace.setgroups.open"),
        "owned.namespace.uid_map.open" => Some("owned.namespace.uid_map.open"),
        "owned.namespace.gid_map.open" => Some("owned.namespace.gid_map.open"),
        "owned.namespace.setgroups" => Some("owned.namespace.setgroups"),
        "owned.namespace.uid_map" => Some("owned.namespace.uid_map"),
        "owned.namespace.gid_map" => Some("owned.namespace.gid_map"),
        "owned.namespace.setgroups.readback" => Some("owned.namespace.setgroups.readback"),
        "owned.namespace.uid_map.readback" => Some("owned.namespace.uid_map.readback"),
        "owned.namespace.gid_map.readback" => Some("owned.namespace.gid_map.readback"),
        "owned.namespace.setgroups.close" => Some("owned.namespace.setgroups.close"),
        "owned.namespace.uid_map.close" => Some("owned.namespace.uid_map.close"),
        "owned.namespace.gid_map.close" => Some("owned.namespace.gid_map.close"),
        "owned.waiter.parent_death" => Some("owned.waiter.parent_death"),
        "owned.init.parent_death" => Some("owned.init.parent_death"),
        "owned.init.fork" => Some("owned.init.fork"),
        "owned.init.proc" => Some("owned.init.proc"),
        "owned.resource.census" => Some("owned.resource.census"),
        "owned.resource.limit" => Some("owned.resource.limit"),
        "owned.child.capabilities" => Some("owned.child.capabilities"),
        "owned.child.fence" => Some("owned.child.fence"),
        "owned.child.control_close" => Some("owned.child.control_close"),
        "owned.child.spawn" => Some("owned.child.spawn"),
        "owned.protocol.entry" => Some("owned.protocol.entry"),
        "owned.protocol.terminal" => Some("owned.protocol.terminal"),
        "owned.protocol.write" => Some("owned.protocol.write"),
        "owned.protocol.read" => Some("owned.protocol.read"),
        "owned.protocol.grammar" => Some("owned.protocol.grammar"),
        _ => None,
    }
}

fn fault_reader_cap(field: u8) -> Option<u64> {
    match field {
        12 | 13 => Some(32),
        24 => Some(128),
        2 | 3 | 4 | 5 | 6 | 8 | 9 | 14 | 15 | 16 | 31 => Some(65_536),
        _ => None,
    }
}

fn field_value_fits(field: u8, value: u64) -> bool {
    match field {
        3 | 4 | 5 | 12 | 13 | 17 | 18 | 22 | 31 | 33 => u32::try_from(value).is_ok(),
        6..=8 => value <= 4096,
        9 => value <= 65_537,
        10 => value <= 5,
        11 => value <= 250,
        14..=16 => value <= 65_537,
        19 | 20 | 32 => i32::try_from(value).is_ok(),
        21 => u8::try_from(value).is_ok(),
        24 => value <= 129,
        25..=29 | 34..=40 => true,
        30 => (1..=64).contains(&value),
        41 => value <= 1,
        _ => false,
    }
}

impl OwnedFault {
    /// Validates a child fault against the closed boundary/cause inventory.
    ///
    /// # Errors
    /// Returns a typed refusal for an illegal pair or operand; owner-local
    /// observations cannot be serialized as child faults.
    pub fn new(boundary: &str, cause: OwnedFaultCause) -> Result<Self, OwnedProtocolError> {
        let boundary = child_fault_boundary(boundary).ok_or(OwnedProtocolError::Malformed)?;
        if !cause_valid_at(boundary, cause) {
            return Err(OwnedProtocolError::Malformed);
        }
        Ok(Self { boundary, cause })
    }

    /// Returns the exact validated boundary.
    pub fn boundary(&self) -> &'static str {
        self.boundary
    }

    /// Returns the original typed observation, including every operand.
    pub fn cause(&self) -> OwnedFaultCause {
        self.cause
    }

    /// Formats the bounded canonical control frame.
    ///
    /// # Errors
    /// Returns a typed refusal if the observation is not a legal child fault.
    pub fn encode(&self) -> Result<String, OwnedProtocolError> {
        Self::new(self.boundary, self.cause)?;
        let (tag, operands, count) = self.cause.words();
        use std::fmt::Write as _;
        let mut frame = format!("owned-launch-v1 terminal fault {} {tag:04x}", self.boundary);
        for word in &operands[..count] {
            write!(frame, " {word:016x}").map_err(|_malformed| OwnedProtocolError::Malformed)?;
        }
        frame.push('\n');
        if frame.len() > 128 {
            return Err(OwnedProtocolError::Oversize);
        }
        Ok(frame)
    }
}

impl OwnedFaultCause {
    fn words(self) -> (u16, [u64; 3], usize) {
        match self {
            Self::Io {
                operation,
                field,
                errno,
            } => (
                1,
                [
                    u64::from(operation),
                    u64::from(field),
                    u64::from_ne_bytes(i64::from(errno).to_ne_bytes()),
                ],
                3,
            ),
            Self::Readback { field, actual } => (
                2,
                [
                    u64::from(field),
                    u64::from_ne_bytes(actual.to_ne_bytes()),
                    0,
                ],
                2,
            ),
            Self::WriteCount {
                requested,
                returned,
            } => (3, [requested, returned, 0], 2),
            Self::Missing { field } => (4, [u64::from(field), 0, 0], 1),
            Self::Duplicate { field, count } => (5, [u64::from(field), count, 0], 2),
            Self::Malformed { field, offset } => (6, [u64::from(field), offset, 0], 2),
            Self::NumericOverflow { field, offset } => (7, [u64::from(field), offset, 0], 2),
            Self::Trailing { field, offset } => (8, [u64::from(field), offset, 0], 2),
            Self::Limit {
                field,
                limit,
                observed,
            } => (9, [u64::from(field), limit, observed], 3),
            Self::EarlyEof {
                field,
                expected,
                observed,
            } => (10, [u64::from(field), expected, observed], 3),
            Self::MapMismatch {
                inside_pair,
                outside_pair,
                count_pair,
            } => (11, [inside_pair, outside_pair, count_pair], 3),
            Self::ExtraMap {
                ordinal_count,
                inside,
                outside,
            } => (
                12,
                [ordinal_count, u64::from(inside), u64::from(outside)],
                3,
            ),
            Self::Mismatch {
                field,
                expected,
                observed,
            } => (13, [u64::from(field), expected, observed], 3),
            Self::SetgroupsAllow => (14, [0; 3], 0),
            Self::Changed { field } => (15, [u64::from(field), 0, 0], 1),
            Self::Unverifiable { field } => (16, [u64::from(field), 0, 0], 1),
            Self::LiveDisappearance { tid } => (17, [u64::from(tid), 0, 0], 1),
            Self::Deadline => (18, [0; 3], 0),
            Self::Cancelled => (19, [0; 3], 0),
            Self::HardLimitMismatch {
                field,
                expected,
                observed,
            } => (20, [u64::from(field), expected, observed], 3),
            Self::GidMapMismatch {
                inside_pair,
                outside_pair,
                count_pair,
            } => (21, [inside_pair, outside_pair, count_pair], 3),
            Self::ExtraGidMap {
                ordinal_count,
                inside,
                outside,
            } => (
                22,
                [ordinal_count, u64::from(inside), u64::from(outside)],
                3,
            ),
        }
    }
}

fn cause_valid_at(boundary: &str, cause: OwnedFaultCause) -> bool {
    use OwnedFaultCause as C;
    let parent_death = matches!(
        boundary,
        "owned.waiter.parent_death" | "owned.init.parent_death"
    );
    let map_readback = matches!(
        boundary,
        "owned.namespace.setgroups.readback"
            | "owned.namespace.uid_map.readback"
            | "owned.namespace.gid_map.readback"
    );
    let map_open = matches!(
        boundary,
        "owned.namespace.setgroups.open"
            | "owned.namespace.uid_map.open"
            | "owned.namespace.gid_map.open"
    );
    let semantic_field = |field| match boundary {
        "owned.resource.census" => matches!(field, 7 | 8 | 22),
        "owned.resource.limit" => (35..=40).contains(&field),
        "owned.child.capabilities" => matches!(field, 25..=29 | 41),
        "owned.waiter.parent_death" | "owned.init.parent_death" => matches!(field, 3 | 31),
        "owned.protocol.read" | "owned.protocol.grammar" => field == 24,
        "owned.child.spawn" => matches!(field, 20 | 21 | 22 | 32 | 39),
        _ if map_open => matches!(field, 19 | 32..=34),
        _ if map_readback => matches!(field, 17 | 18),
        _ => false,
    };
    let shape_field = |field| match boundary {
        "owned.waiter.initial_tracer" | "owned.waiter.tracer" => field == 2,
        "owned.waiter.overflow_uid" => field == 12,
        "owned.waiter.overflow_gid" => field == 13,
        "owned.resource.census" => matches!(field, 3 | 4 | 5 | 6 | 8 | 9),
        "owned.protocol.read" | "owned.protocol.grammar" | "owned.child.spawn" => field == 24,
        "owned.waiter.parent_death" | "owned.init.parent_death" => matches!(field, 3 | 31),
        _ if map_readback => matches!(field, 2 | 14..=16),
        _ => false,
    };
    match cause {
        C::Io {
            operation,
            field,
            errno,
        } => {
            errno > 0
                && match boundary {
                    "owned.waiter.initial_dumpable" => (operation, field) == (2, 1),
                    "owned.waiter.dumpable" | "owned.init.dumpable" => {
                        matches!((operation, field), (1 | 2, 1))
                    }
                    "owned.waiter.initial_tracer" | "owned.waiter.tracer" => {
                        matches!((operation, field), (4 | 5 | 8, 2))
                    }
                    "owned.waiter.overflow_uid" => matches!((operation, field), (4 | 5, 12)),
                    "owned.waiter.overflow_gid" => matches!((operation, field), (4 | 5, 13)),
                    "owned.namespace.user" | "owned.namespace.mount" | "owned.namespace.pid" => {
                        (operation, field) == (3, 0)
                    }
                    "owned.namespace.setgroups"
                    | "owned.namespace.uid_map"
                    | "owned.namespace.gid_map" => (operation, field) == (6, 0),
                    "owned.namespace.setgroups.close"
                    | "owned.namespace.uid_map.close"
                    | "owned.namespace.gid_map.close" => (operation, field) == (7, 0),
                    "owned.waiter.parent_death" | "owned.init.parent_death" => {
                        matches!((operation, field), (12, 30) | (4 | 5 | 7, 3 | 31))
                    }
                    "owned.init.fork" => (operation, field) == (13, 0),
                    "owned.init.proc" => (operation, field) == (15, 0),
                    "owned.resource.census" => matches!(
                        (operation, field),
                        (4 | 10, 8) | (4 | 5 | 8, 6) | (5, 3..=5)
                    ),
                    "owned.resource.limit" => {
                        matches!(operation, 26 | 27) && (35..=40).contains(&field)
                    }
                    "owned.child.capabilities" => matches!(
                        (operation, field),
                        (16 | 17, 0) | (28 | 29, 29) | (30 | 31, 28) | (32 | 33, 41)
                    ),
                    "owned.child.fence" => (operation, field) == (18, 0),
                    "owned.child.control_close" => (operation, field) == (7, 20),
                    "owned.child.spawn" => matches!(
                        (operation, field),
                        (23, 20)
                            | (19, 20 | 32)
                            | (7, 0 | 20)
                            | (13 | 14 | 24 | 25, 0)
                            | (5 | 6 | 22, 24)
                    ),
                    "owned.protocol.entry" | "owned.protocol.terminal" | "owned.protocol.write" => {
                        (operation, field) == (6, 24)
                    }
                    "owned.protocol.read" => matches!((operation, field), (5 | 22, 24)),
                    _ if map_open => matches!((operation, field), (4, 0) | (11, 19) | (19, 32)),
                    _ if map_readback => {
                        matches!((operation, field), (4 | 5 | 8, 14..=16 | 2) | (2, 1))
                    }
                    _ => false,
                }
        }
        C::Readback { field: 1, actual } => {
            i32::try_from(actual).is_ok()
                && actual != -1
                && match boundary {
                    "owned.waiter.initial_dumpable" => actual != 0 && actual != 1,
                    "owned.waiter.dumpable" | "owned.init.dumpable" => actual != 0,
                    _ => map_readback && actual != 0,
                }
        }
        C::Readback { field: 2, actual } => {
            u32::try_from(actual).is_ok()
                && actual > 0
                && (map_readback
                    || matches!(
                        boundary,
                        "owned.waiter.initial_tracer" | "owned.waiter.tracer"
                    ))
        }
        C::Readback { .. } | C::LiveDisappearance { .. } => false,
        C::WriteCount {
            requested,
            returned,
        } => {
            requested > 0
                && returned < requested
                && (boundary != "owned.child.spawn" || requested <= 128)
                && matches!(
                    boundary,
                    "owned.namespace.setgroups"
                        | "owned.namespace.uid_map"
                        | "owned.namespace.gid_map"
                        | "owned.protocol.entry"
                        | "owned.protocol.terminal"
                        | "owned.protocol.write"
                        | "owned.child.spawn"
                )
        }
        C::Missing { field } => shape_field(field),
        C::Duplicate { field, count } => shape_field(field) && count >= 2,
        C::Malformed { field, offset }
        | C::NumericOverflow { field, offset }
        | C::Trailing { field, offset } => {
            shape_field(field) && fault_reader_cap(field).is_some_and(|cap| offset <= cap + 1)
        }
        C::Limit {
            field,
            limit,
            observed,
        } => {
            shape_field(field)
                && observed > limit
                && field_value_fits(field, limit)
                && field_value_fits(field, observed)
                && (!parent_death || (limit == 65_536 && observed == 65_537))
        }
        C::EarlyEof {
            field,
            expected,
            observed,
        } => {
            shape_field(field)
                && observed < expected
                && field_value_fits(field, expected)
                && field_value_fits(field, observed)
                && (!parent_death || (expected == observed + 1 && expected <= 65_537))
        }
        C::MapMismatch {
            inside_pair,
            outside_pair,
            count_pair,
        }
        | C::GidMapMismatch {
            inside_pair,
            outside_pair,
            count_pair,
        } => {
            map_readback
                && [inside_pair, outside_pair, count_pair]
                    .iter()
                    .any(|pair| pair >> 32 != pair & u64::from(u32::MAX))
        }
        C::ExtraMap { ordinal_count, .. } | C::ExtraGidMap { ordinal_count, .. } => {
            let ordinal = ordinal_count >> 32;
            let count = ordinal_count & u64::from(u32::MAX);
            let written = match cause {
                C::ExtraMap { .. } => boundary != "owned.namespace.setgroups.readback",
                _ => boundary == "owned.namespace.gid_map.readback",
            };
            map_readback && ordinal < count && (!written || ordinal >= 1)
        }
        C::Mismatch {
            field,
            expected,
            observed,
        } => {
            semantic_field(field)
                && expected != observed
                && field_value_fits(field, expected)
                && field_value_fits(field, observed)
                && (!parent_death
                    || (expected > 0
                        && i32::try_from(expected).is_ok()
                        && i32::try_from(observed).is_ok()))
                && (boundary != "owned.child.spawn"
                    || match field {
                        20 => expected == 3 && observed < 3,
                        21 => expected == 63,
                        22 | 39 => {
                            expected > 0
                                && u32::try_from(expected).is_ok()
                                && u32::try_from(observed).is_ok()
                        }
                        32 => expected == 1 && observed & 1 == 0,
                        _ => false,
                    })
        }
        C::HardLimitMismatch {
            field,
            expected,
            observed,
        } => {
            boundary == "owned.resource.limit" && (35..=40).contains(&field) && expected != observed
        }
        C::SetgroupsAllow => map_readback,
        C::Changed { field } => {
            boundary != "owned.protocol.grammar"
                && boundary != "owned.child.spawn"
                && semantic_field(field)
                && boundary != "owned.resource.limit"
                && boundary != "owned.child.capabilities"
                && !map_readback
                && (!parent_death || field == 31)
        }
        C::Unverifiable { field } => {
            (if parent_death {
                field == 31 || (field == 3 && boundary == "owned.waiter.parent_death")
            } else if boundary == "owned.child.spawn" {
                field == 24
            } else {
                semantic_field(field)
            }) && boundary != "owned.resource.limit"
                && boundary != "owned.child.capabilities"
                && !map_readback
        }
        C::Deadline | C::Cancelled => true,
    }
}

#[derive(Debug, thiserror::Error)]
#[error("seccomp syscall table is unavailable for this architecture")]
pub enum SeccompCompileError {
    Architecture,
}

/// The two fixed points at which the native launch installs its fence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeccompStage {
    PreInjection,
    Final,
}

/// `AUDIT_ARCH_AARCH64` — the `seccomp_data` architecture word on 64-bit
/// arm, verified against the proof container's kernel.
const AUDIT_ARCH_AARCH64: u32 = 0xC000_00B7;

/// `AUDIT_ARCH_X86_64` for the same guard on amd64 hosts.
const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;

/// `SECCOMP_RET_ERRNO | EPERM` — a denied network syscall surfaces as
/// `EPERM` from the confined program, never as a signal.
const SECCOMP_RET_ERRNO_EPERM: u32 = 0x0005_0001;

/// `SECCOMP_RET_ERRNO | ENOSYS` — glibc tries `clone3` first and falls
/// back to `clone` only on ENOSYS. EPERM would break fork in confined
/// exec; the deny targets confused-deputy (`clone3` as a helper), not spawn.
const SECCOMP_RET_ERRNO_ENOSYS: u32 = 0x0005_0026;

/// `clone3` — same number on x86_64 and aarch64.
const SYS_CLONE3: u32 = 435;

/// `clone` — architecture-specific; judged by flags, not denied by number,
/// so glibc `fork` (SIGCHLD) still works after `clone3` returns ENOSYS.
fn sys_clone() -> Option<u32> {
    native_net_syscalls().map(|table| table.4)
}

/// Namespace bits `clone` must not be allowed to set: a NEWPID/NEWUSER
/// child leaves the host's process group and survives `killpg`. SIGCHLD
/// and thread flags stay allowed so ordinary `fork` works.
const CLONE_NEWTIME: u32 = 0x0000_0080;
const CLONE_NEWNS: u32 = 0x0002_0000;
const CLONE_NEWCGROUP: u32 = 0x0200_0000;
const CLONE_NEWUTS: u32 = 0x0400_0000;
const CLONE_NEWIPC: u32 = 0x0800_0000;
const CLONE_NEWUSER: u32 = 0x1000_0000;
const CLONE_NEWPID: u32 = 0x2000_0000;
const CLONE_NEWNET: u32 = 0x4000_0000;
const CLONE_NEW_NAMESPACE_FLAGS: u32 = CLONE_NEWTIME
    | CLONE_NEWNS
    | CLONE_NEWCGROUP
    | CLONE_NEWUTS
    | CLONE_NEWIPC
    | CLONE_NEWUSER
    | CLONE_NEWPID
    | CLONE_NEWNET;

/// Offset of `seccomp_data.args[0]` (low 32 bits of the first syscall arg).
const SECCOMP_DATA_ARGS0_OFFSET: u32 = 16;

/// `SECCOMP_RET_ALLOW` — every syscall outside the deny list runs.
const SECCOMP_RET_ALLOW: u32 = 0x7FFF_0000;

/// Classic-BPF opcodes for the hand-assembled deny-list filter. The
/// filter loads the architecture word and jumps straight to a deny
/// verdict for any other architecture (an unjudged architecture fails
/// closed), loads the syscall number, masks the x32/ILP32 compat band
/// bit, and returns `ERRNO|EPERM` for the denied numbers except `clone3`
/// (which returns `ERRNO|ENOSYS` so glibc fork falls back to `clone`),
/// `ALLOW` for everything else — so the launcher's own `execve` of the
/// confined program is never blocked, and neither are the Landlock
/// syscalls `setpriv` itself already applied.
const BPF_LD_W_ABS: u16 = 0x20;
const BPF_ALU_AND_K: u16 = 0x54;
const BPF_JEQ_K: u16 = 0x15;
const BPF_RET_K: u16 = 0x06;
const SECCOMP_DATA_NR_OFFSET: u32 = 0;
const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;

/// `!0x4000_0000` — the syscall-number word with the x32/ILP32 compat
/// band bit cleared: a compat-band number (`nr | 0x4000_0000`) carries
/// the native audit architecture, so it must be judged by its masked
/// native number instead of missing every native-equality deny entry.
const SECCOMP_COMPAT_BAND_MASK: u32 = 0xBFFF_FFFF;

/// The network syscalls the egress boundary denies, per native
/// architecture. `None` on any other architecture is an honest
/// capability failure, never an unfiltered leg.
pub fn seccomp_denied_syscalls() -> Option<&'static [u32]> {
    native_net_syscalls().map(|table| table.1)
}

type NativeSyscallTable = (u32, &'static [u32], &'static [u32], u32, u32);

fn native_net_syscalls() -> Option<NativeSyscallTable> {
    match std::env::consts::ARCH {
        "aarch64" => {
            const SYS_BIND: u32 = 200;
            const SYS_LISTEN: u32 = 201;
            const SYS_RECVMSG: u32 = 212;
            const SYS_SETPGID: u32 = 154;
            const SYS_SETSID: u32 = 157;
            Some((
                AUDIT_ARCH_AARCH64,
                &[
                    198,
                    // `socketpair` (199) and `recvfrom` (207) stay
                    // allowed: the kernel only supports socketpair for
                    // AF_UNIX, and with `socket` (198) denied the only
                    // socket a child can create is such a pair, whose
                    // peer is the spawning process itself — no egress
                    // path exists (`connect`/`bind`/`listen` stay
                    // denied). Rust std's fork-path `Command::spawn`
                    // bootstrap needs the pair plus a `recvfrom` on it
                    // for the exec-result handshake, so denying either
                    // breaks every Rust child (cargo→rustc included).
                    SYS_BIND,
                    SYS_LISTEN,
                    202,
                    203,
                    206,
                    211,
                    SYS_RECVMSG,
                    242, // socket bind listen accept connect sendto sendmsg recvmsg accept4
                    243,
                    269, // recvmmsg sendmmsg
                    97,
                    117,
                    SYS_SETPGID,
                    SYS_SETSID,
                    268,
                    270,
                    271,
                    280, // unshare ptrace setpgid setsid setns process_vm_* bpf
                    425,
                    426,
                    427,
                    434,
                    438,        // io_uring_* pidfd_open pidfd_getfd
                    SYS_CLONE3, // clone3 → ENOSYS so glibc fork falls back to clone
                ],
                &[198, 211, 269, 117, 270, 271, 438, 425, 426, 427],
                199,
                220,
            ))
        }
        "x86_64" => {
            const SYS_BIND: u32 = 49;
            const SYS_LISTEN: u32 = 50;
            const SYS_RECVMSG: u32 = 47;
            const SYS_SETPGID: u32 = 109;
            const SYS_SETSID: u32 = 112;
            Some((
                AUDIT_ARCH_X86_64,
                &[
                    41,
                    42,
                    43,
                    44,
                    // 45 (`recvfrom`) and 53 (`socketpair`) stay allowed:
                    // the std spawn handshake needs both; see the aarch64
                    // arm for the full rationale.
                    46,
                    SYS_RECVMSG,
                    SYS_BIND,
                    SYS_LISTEN,
                    288, // socket connect accept sendto sendmsg recvmsg bind listen accept4
                    299,
                    307, // recvmmsg sendmmsg
                    101,
                    SYS_SETPGID,
                    SYS_SETSID,
                    272,
                    308,
                    310,
                    311,
                    321, // ptrace setpgid setsid unshare setns process_vm_* bpf
                    425,
                    426,
                    427,
                    434,
                    438,        // io_uring_* pidfd_open pidfd_getfd
                    SYS_CLONE3, // clone3 → ENOSYS so glibc fork falls back to clone
                ],
                &[41, 46, 307, 101, 310, 311, 438, 425, 426, 427],
                53,
                56,
            ))
        }
        _ => None,
    }
}

/// Renders the net-deny filter as raw `struct sock_filter` instructions —
/// the exact file format `setpriv --seccomp-filter` loads.
pub fn compile_seccomp(stage: SeccompStage) -> Result<Vec<u8>, SeccompCompileError> {
    let Some((arch, final_denied, early_denied, socketpair, _)) = native_net_syscalls() else {
        return Err(SeccompCompileError::Architecture);
    };
    let denied = match stage {
        SeccompStage::Final => final_denied,
        SeccompStage::PreInjection => early_denied,
    };
    let mut program: Vec<(u16, u8, u8, u32)> = if stage == SeccompStage::Final {
        vec![
            (BPF_LD_W_ABS, 0, 0, SECCOMP_DATA_ARCH_OFFSET),
            // Any other architecture lands on a deny verdict: an unjudged
            // architecture fails closed. The constant offset reaches the
            // first deny pair's ERRNO return from the guard.
            (BPF_JEQ_K, 0, 3, arch),
            (BPF_LD_W_ABS, 0, 0, SECCOMP_DATA_NR_OFFSET),
            // Compat band before every comparison: a `nr | 0x4000_0000`
            // call is judged by its native number.
            (BPF_ALU_AND_K, 0, 0, SECCOMP_COMPAT_BAND_MASK),
        ]
    } else {
        let mut prefix = vec![
            (BPF_LD_W_ABS, 0, 0, SECCOMP_DATA_ARCH_OFFSET),
            (BPF_JEQ_K, 1, 0, arch),
            (BPF_RET_K, 0, 0, SECCOMP_RET_ERRNO_EPERM),
            (BPF_LD_W_ABS, 0, 0, SECCOMP_DATA_NR_OFFSET),
        ];
        if arch == AUDIT_ARCH_X86_64 {
            // Judge the raw ABI bit before any native-number normalization.
            prefix.push((0x45, 0, 1, 0x4000_0000));
            prefix.push((BPF_RET_K, 0, 0, SECCOMP_RET_ERRNO_EPERM));
        }
        prefix.push((BPF_JEQ_K, 0, 19, socketpair));
        for (offset, expected) in [(16, 1), (24, 524293), (32, 0)] {
            prefix.extend_from_slice(&[
                (BPF_LD_W_ABS, 0, 0, offset),
                (BPF_JEQ_K, 1, 0, expected),
                (BPF_RET_K, 0, 0, SECCOMP_RET_ERRNO_EPERM),
                (BPF_LD_W_ABS, 0, 0, offset + 4),
                (BPF_JEQ_K, 1, 0, 0),
                (BPF_RET_K, 0, 0, SECCOMP_RET_ERRNO_EPERM),
            ]);
        }
        prefix.push((BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW));
        // Argument loads cannot replace the nr accumulator on the deny path.
        prefix.push((BPF_LD_W_ABS, 0, 0, SECCOMP_DATA_NR_OFFSET));
        prefix
    };
    for &nr in denied {
        program.push((BPF_JEQ_K, 0, 1, nr));
        let ret = if nr == SYS_CLONE3 {
            SECCOMP_RET_ERRNO_ENOSYS
        } else {
            SECCOMP_RET_ERRNO_EPERM
        };
        program.push((BPF_RET_K, 0, 0, ret));
    }
    if stage == SeccompStage::Final {
        // SYS_clone stays allowed by number so glibc fork (SIGCHLD) works.
        // args[0] carrying any CLONE_NEW* namespace bit is EPERM: that child
        // would leave the process group and survive killpg.
        let sys_clone = sys_clone().ok_or(SeccompCompileError::Architecture)?;
        program.push((BPF_JEQ_K, 0, 4, sys_clone));
        program.push((BPF_LD_W_ABS, 0, 0, SECCOMP_DATA_ARGS0_OFFSET));
        program.push((BPF_ALU_AND_K, 0, 0, CLONE_NEW_NAMESPACE_FLAGS));
        program.push((BPF_JEQ_K, 1, 0, 0));
        program.push((BPF_RET_K, 0, 0, SECCOMP_RET_ERRNO_EPERM));
    }
    program.push((BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW));
    let mut bytes = Vec::with_capacity(program.len() * 8);
    for (code, jt, jf, k) in program {
        bytes.extend_from_slice(&code.to_le_bytes());
        bytes.push(jt);
        bytes.push(jf);
        bytes.extend_from_slice(&k.to_le_bytes());
    }
    Ok(bytes)
}

/// A source observation made by the parent before an owned exposure.
#[derive(Debug, thiserror::Error)]
pub enum OwnedParentError {
    #[error(transparent)]
    Observation(OwnedParentObservation),
}

/// Opaque facts frozen by the parent observer. Callers cannot create or
/// mutate original-request-stop provenance or acquired-descriptor custody.
///
/// ```compile_fail,E0616
/// use rivect_sandbox_helper::{OwnedParentObservation, OwnedStop};
/// fn forge(mut observation: OwnedParentObservation) {
///     observation.request_stop = Some(OwnedStop::Cancelled);
/// }
/// ```
///
/// ```compile_fail,E0451
/// use rivect_sandbox_helper::{OwnedFaultCause, OwnedParentObservation};
/// let observation = OwnedParentObservation {
///     boundary: "owned.parent.task_budget",
///     cause: OwnedFaultCause::Deadline,
///     source: None,
///     secondary: None,
///     status: None,
///     request_stop: None,
/// };
/// ```
#[derive(Debug, thiserror::Error)]
#[error("owned parent protection failed at {boundary}: {cause:?}")]
pub struct OwnedParentObservation {
    boundary: &'static str,
    cause: OwnedFaultCause,
    #[source]
    source: Option<io::Error>,
    secondary: Option<Box<OwnedParentError>>,
    status: Option<std::fs::File>,
    request_stop: Option<OwnedStop>,
}

/// Protects the caller before creating or exposing an owned artifact.
///
/// # Errors
/// Returns the original typed observation if every live task cannot be
/// verified untraced within the private bounds. Dumpability remains zero
/// after refusal; callers must not restore it or replay an exposed effect.
#[cfg(target_os = "linux")]
pub fn ensure_owned_parent_protected() -> Result<(), OwnedParentError> {
    ensure_parent_with_request(None)
}

/// Protects an owning request using its original deadline and live predicate.
/// The predicate is borrowed only by this root-stack observation.
///
/// # Errors
/// Returns the first actual observation, including original request-stop provenance.
#[cfg(target_os = "linux")]
pub fn protect_owned_request(
    deadline: std::time::Instant,
    cancel: &dyn Fn() -> bool,
) -> Result<(), OwnedParentError> {
    ensure_parent_with_request(Some(ParentRequest {
        deadline,
        cancel: Some(cancel),
    }))
}

/// Protects a direct owner whose shipped interface has no cancellation facility.
///
/// # Errors
/// Returns the first actual observation under the original direct deadline.
#[cfg(target_os = "linux")]
pub fn protect_owned_direct(deadline: std::time::Instant) -> Result<(), OwnedParentError> {
    ensure_parent_with_request(Some(ParentRequest {
        deadline,
        cancel: None,
    }))
}

#[cfg(target_os = "linux")]
fn ensure_parent_with_request(request: Option<ParentRequest<'_>>) -> Result<(), OwnedParentError> {
    ensure_parent_observing(request, &mut |_, _, _| {})
}

#[cfg(target_os = "linux")]
fn ensure_parent_observing(
    request: Option<ParentRequest<'_>>,
    observe: &mut impl FnMut(u32, std::os::fd::RawFd, u8),
) -> Result<(), OwnedParentError> {
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs::{File, OpenOptions};
    use std::os::unix::fs::OpenOptionsExt as _;
    use std::time::Instant;

    let deadline = Instant::now() + Duration::from_millis(2000);
    let pid = std::process::id();
    parent_budget(deadline, request)?;
    // SAFETY: PR_SET_DUMPABLE takes one integer and no pointer operands.
    if unsafe { prctl(4, 0, 0, 0, 0) } == -1 {
        return Err(parent_io(
            "owned.parent.protect",
            1,
            1,
            io::Error::last_os_error(),
        ));
    }
    // The dumpable bit is already cleared. Read it back even if the
    // deadline elapsed during the set; a positive value stays a readback.
    parent_dumpable(deadline, request)?;
    let mut pinned: BTreeMap<u32, File> = BTreeMap::new();
    let mut outcome = (|| -> Result<(), OwnedParentError> {
        for _sweep in 0..64 {
            parent_budget(deadline, request)?;
            parent_dumpable(deadline, request)?;
            let task_dir = OpenOptions::new()
                .read(true)
                .custom_flags(O_DIRECTORY | O_CLOEXEC | ANCHOR_O_NOFOLLOW)
                .open("/proc/self/task")
                .map_err(|source| parent_io("owned.parent.task_dir", 4, 8, source))?;
            observe(0, task_dir.as_raw_fd(), 5);
            let mut seen = BTreeSet::new();
            let observation = (|| -> Result<bool, OwnedParentError> {
                parent_budget(deadline, request)?;
                parent_task_names(task_dir.as_fd(), deadline, request, &mut |entry| {
                    // Names in this chunk are already read. A deadline here
                    // must not drop them; the next getdents is gated above.
                    let Some(bytes) = entry else {
                        return Ok(());
                    };
                    parent_task_entry(
                        &mut pinned,
                        &mut seen,
                        bytes,
                        (task_dir.as_fd(), pid),
                        deadline,
                        request,
                        observe,
                    )
                })?;
                // Pin and cold-read during traversal, so births before its final EOF
                // can join this acquisition. Every initial read still precedes the
                // count, and closure preserves all surviving held identities.
                loop {
                    // The leader status is already pinned. Reading it after
                    // the deadline keeps the thread count; the next sweep
                    // still stops before opening a new descriptor.
                    let leader = pinned.get_mut(&pid).ok_or_else(|| {
                        parent_fault(
                            "owned.parent.task_count",
                            OwnedFaultCause::Missing { field: 3 },
                        )
                    })?;
                    observe(pid, leader.as_raw_fd(), 1);
                    let count = parent_status(leader, pid, pid, deadline, request)?.threads;
                    if count == 0 || count > 4096 {
                        return Err(parent_fault(
                            "owned.parent.task_count",
                            OwnedFaultCause::Unverifiable { field: 5 },
                        ));
                    }
                    // A removal invalidates the entire old count. Since each repeated
                    // attempt removes a pinned nonleader, the finite cohort bounds it.
                    if parent_read_cohort(&mut pinned, pid, deadline, request, 2, observe)? {
                        continue;
                    }
                    if usize::try_from(count).ok() != Some(pinned.len()) {
                        return Ok(false);
                    }
                    break;
                }
                parent_dumpable(deadline, request)?;
                // The cut already matches. A deadline during that readback
                // must not discard the closed census.
                Ok(true)
            })();
            let mut observation = observation;
            retire_parent_result(task_dir, 8, deadline, request, &mut observation, 0, observe);
            if observation? {
                return Ok(());
            }
        }
        Err(parent_fault(
            "owned.parent.task_churn",
            OwnedFaultCause::Limit {
                field: 10,
                limit: 64,
                observed: 65,
            },
        ))
    })();
    for (tid, status) in pinned {
        retire_parent_result(status, 6, deadline, request, &mut outcome, tid, observe);
    }
    outcome
}

// The new-status open refusal this thread's tests armed: the traversal's
// own fault seam, so the refusal does not depend on the kernel permission
// checks a privileged container's CAP_DAC_OVERRIDE satisfies.
#[cfg(target_os = "linux")]
#[cfg(test)]
thread_local! {
    static NEW_STATUS_OPEN_FAULT: std::cell::Cell<Option<io::Error>> =
        const { std::cell::Cell::new(None) };
}

/// Arms `error` as the result of this thread's next new-status open.
#[cfg(target_os = "linux")]
#[cfg(test)]
fn arm_new_status_open_fault(error: io::Error) {
    NEW_STATUS_OPEN_FAULT.with(|slot| slot.set(Some(error)));
}

/// The refusal this thread armed, taken on use so one traversal sees it once.
#[cfg(target_os = "linux")]
#[cfg(test)]
fn new_status_open_fault() -> Option<io::Error> {
    NEW_STATUS_OPEN_FAULT.with(std::cell::Cell::take)
}

#[cfg(target_os = "linux")]
fn parent_task_entry(
    pinned: &mut std::collections::BTreeMap<u32, std::fs::File>,
    seen: &mut std::collections::BTreeSet<u32>,
    bytes: &[u8],
    scope: (BorrowedFd<'_>, u32),
    deadline: std::time::Instant,
    request: Option<ParentRequest<'_>>,
    observe: &mut impl FnMut(u32, std::os::fd::RawFd, u8),
) -> Result<(), OwnedParentError> {
    use std::fs::File;
    let (task_dir, pid) = scope;
    if bytes.is_empty() || bytes[0] == b'0' || !bytes.iter().all(u8::is_ascii_digit) {
        return Err(parent_fault(
            "owned.parent.task_census",
            OwnedFaultCause::Malformed {
                field: 6,
                offset: 0,
            },
        ));
    }
    let tid = std::str::from_utf8(bytes)
        .ok()
        .and_then(|text| text.parse::<u32>().ok())
        .filter(|tid| *tid > 0 && i32::try_from(*tid).is_ok())
        .ok_or_else(|| {
            parent_fault(
                "owned.parent.task_identity",
                OwnedFaultCause::NumericOverflow {
                    field: 3,
                    offset: 0,
                },
            )
        })?;
    if !seen.insert(tid) {
        return Err(parent_fault(
            "owned.parent.task_identity",
            OwnedFaultCause::Duplicate { field: 7, count: 2 },
        ));
    }
    if pinned.contains_key(&tid) && parent_read_task(pinned, tid, pid, deadline, request, observe)?
    {
        return Ok(());
    }
    parent_task_capacity(pinned.len(), || {
        parent_read_cohort(pinned, pid, deadline, request, 3, observe)?;
        Ok(pinned.len())
    })?;
    let relative = std::ffi::CString::new(format!("{tid}/status")).map_err(|_nul| {
        parent_fault(
            "owned.parent.task_open",
            OwnedFaultCause::Malformed {
                field: 6,
                offset: 0,
            },
        )
    })?;
    parent_budget(deadline, request)?;
    #[cfg(test)]
    {
        // An armed refusal stands in for the open, so this boundary keeps its
        // own typed cause where the kernel's permission checks are satisfied.
        if let Some(source) = new_status_open_fault() {
            return Err(parent_io("owned.parent.task_open", 4, 6, source));
        }
    }
    // SAFETY: the held directory and NUL-terminated relative path live
    // through openat; a successful fd is adopted exactly once below.
    let fd = unsafe {
        openat(
            task_dir.as_raw_fd(),
            relative.as_ptr(),
            O_CLOEXEC | ANCHOR_O_NOFOLLOW,
        )
    };
    let opened = if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: openat returned a fresh uniquely owned descriptor.
        Ok(unsafe { File::from_raw_fd(fd) })
    };
    let status = match opened {
        Ok(status) => status,
        Err(source) if tid != pid && matches!(source.raw_os_error(), Some(2 | 3)) => {
            let tgid = i32::try_from(pid).map_err(|_range| {
                parent_fault(
                    "owned.parent.task_identity",
                    OwnedFaultCause::Unverifiable { field: 4 },
                )
            })?;
            let tid_arg = i32::try_from(tid).map_err(|_range| {
                parent_fault(
                    "owned.parent.task_identity",
                    OwnedFaultCause::Unverifiable { field: 3 },
                )
            })?;
            // SAFETY: signal zero only observes existence in this TGID.
            let result = unsafe { tgkill(tgid, tid_arg, 0) };
            let probe_error = if result == -1 {
                Some(io::Error::last_os_error())
            } else {
                None
            };
            match probe_error {
                Some(error) if error.raw_os_error() == Some(3) => {
                    // The task is already gone. A deadline during that probe
                    // must not turn the disappearance into a fault.
                    return Ok(());
                }
                Some(error) => {
                    return Err(parent_io("owned.parent.task_lifecycle", 9, 3, error));
                }
                None => {
                    return Err(OwnedParentError::Observation(OwnedParentObservation {
                        boundary: "owned.parent.task_lifecycle",
                        cause: OwnedFaultCause::LiveDisappearance { tid },
                        source: Some(source),
                        secondary: None,
                        status: None,
                        request_stop: None,
                    }));
                }
            }
        }
        Err(source) => return Err(parent_io("owned.parent.task_open", 4, 6, source)),
    };
    pinned.insert(tid, status);
    observe(tid, pinned[&tid].as_raw_fd(), 0);
    parent_read_task(pinned, tid, pid, deadline, request, observe).map(|_| ())
}

#[cfg(target_os = "linux")]
fn parent_task_capacity(
    held: usize,
    refresh: impl FnOnce() -> Result<usize, OwnedParentError>,
) -> Result<(), OwnedParentError> {
    if held == 4096 && refresh()? == 4096 {
        return Err(parent_fault(
            "owned.parent.task_limit",
            OwnedFaultCause::Limit {
                field: 7,
                limit: 4096,
                observed: 4097,
            },
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn parent_read_task(
    pinned: &mut std::collections::BTreeMap<u32, std::fs::File>,
    tid: u32,
    pid: u32,
    deadline: std::time::Instant,
    request: Option<ParentRequest<'_>>,
    observe: &mut impl FnMut(u32, std::os::fd::RawFd, u8),
) -> Result<bool, OwnedParentError> {
    // The descriptor is already pinned. A deadline here must not hide
    // the identity those bytes name.
    let status = pinned.get_mut(&tid).ok_or_else(|| {
        parent_fault(
            "owned.parent.task_identity",
            OwnedFaultCause::Missing { field: 7 },
        )
    })?;
    observe(tid, status.as_raw_fd(), 3);
    match parent_status(status, tid, pid, deadline, request) {
        Ok(_) => Ok(true),
        Err(error)
            if tid != pid
                && matches!(
                    error.cause(),
                    OwnedFaultCause::Io {
                        operation: 5,
                        errno: 3,
                        ..
                    }
                ) =>
        {
            let mut outcome = Ok(());
            if let Some(status) = pinned.remove(&tid) {
                retire_parent_result(status, 6, deadline, request, &mut outcome, tid, observe);
            }
            outcome.map(|()| false)
        }
        Err(error) => Err(error),
    }
}

#[cfg(target_os = "linux")]
fn parent_read_cohort(
    pinned: &mut std::collections::BTreeMap<u32, std::fs::File>,
    pid: u32,
    deadline: std::time::Instant,
    request: Option<ParentRequest<'_>>,
    phase: u8,
    observe: &mut impl FnMut(u32, std::os::fd::RawFd, u8),
) -> Result<bool, OwnedParentError> {
    let mut retired = Vec::new();
    for (&tid, status) in pinned.iter_mut() {
        // Each status is already pinned. Read it before any deadline check
        // so a finished identity is not replaced by Cause::Deadline.
        observe(tid, status.as_raw_fd(), phase);
        match parent_status(status, tid, pid, deadline, request) {
            Ok(_) => {}
            Err(error)
                if tid != pid
                    && matches!(
                        error.cause(),
                        OwnedFaultCause::Io {
                            operation: 5,
                            errno: 3,
                            ..
                        }
                    ) =>
            {
                // The task is already gone. A deadline here must not turn
                // that disappearance into a fault before its descriptor is retired.
                retired.push(tid);
            }
            Err(error) => return Err(error),
        }
    }
    let removed = !retired.is_empty();
    let mut outcome = Ok(());
    for tid in retired {
        if let Some(status) = pinned.remove(&tid) {
            retire_parent_result(status, 6, deadline, request, &mut outcome, tid, observe);
        }
    }
    outcome?;
    Ok(removed)
}

#[cfg(target_os = "linux")]
fn retire_parent_result<T>(
    file: std::fs::File,
    field: u8,
    deadline: std::time::Instant,
    request: Option<ParentRequest<'_>>,
    outcome: &mut Result<T, OwnedParentError>,
    tid: u32,
    observe: &mut impl FnMut(u32, std::os::fd::RawFd, u8),
) {
    use std::os::fd::IntoRawFd as _;
    let _ = (deadline, request);
    let fd = file.into_raw_fd();
    observe(tid, fd, 4);
    // SAFETY: this consumes the unique acquired descriptor exactly once.
    if unsafe { close(fd) } == -1 {
        let error = parent_io(
            "owned.parent.task_census",
            7,
            field,
            io::Error::last_os_error(),
        );
        match outcome {
            Err(primary) => primary.set_secondary(error),
            Ok(_) => *outcome = Err(error),
        }
    }
    // The descriptor is already closed. A deadline during that close must
    // not replace a retirement that succeeded.
}

#[cfg(target_os = "linux")]
fn parent_task_names(
    directory: BorrowedFd<'_>,
    deadline: std::time::Instant,
    request: Option<ParentRequest<'_>>,
    visit: &mut impl FnMut(Option<&[u8]>) -> Result<(), OwnedParentError>,
) -> Result<(), OwnedParentError> {
    #[cfg(target_arch = "x86_64")]
    const GETDENTS64: std::ffi::c_long = 217;
    #[cfg(target_arch = "aarch64")]
    const GETDENTS64: std::ffi::c_long = 61;
    let mut names = 0_u64;
    let mut bytes = [0_u8; 32_768];
    loop {
        parent_budget(deadline, request)?;
        if names > 0 {
            visit(None)?;
        }
        // SAFETY: getdents64 writes at most the supplied live buffer length to
        // an acquired directory. No pointer or descriptor escapes the call.
        let count = unsafe {
            syscall(
                GETDENTS64,
                directory.as_raw_fd(),
                bytes.as_mut_ptr(),
                bytes.len(),
            )
        };
        if count == -1 {
            return Err(parent_io(
                "owned.parent.task_census",
                10,
                8,
                io::Error::last_os_error(),
            ));
        }
        if count == 0 {
            // The directory is already finished. A deadline during getdents
            // must not turn that EOF into a fault.
            return Ok(());
        }
        let count = usize::try_from(count).map_err(|_range| {
            parent_fault(
                "owned.parent.task_census",
                OwnedFaultCause::Unverifiable { field: 8 },
            )
        })?;
        let mut offset = 0;
        // This chunk is already in hand. A deadline while its names are
        // visited must not drop the directory the kernel returned.
        while offset < count {
            let rest = &bytes[offset..count];
            if rest.len() < 20 {
                return Err(parent_fault(
                    "owned.parent.task_census",
                    OwnedFaultCause::Malformed {
                        field: 6,
                        offset: offset as u64,
                    },
                ));
            }
            let length = usize::from(u16::from_ne_bytes([rest[16], rest[17]]));
            if length < 20 || length > rest.len() {
                return Err(parent_fault(
                    "owned.parent.task_census",
                    OwnedFaultCause::Malformed {
                        field: 6,
                        offset: offset as u64,
                    },
                ));
            }
            let name = &rest[19..length];
            let end = name.iter().position(|byte| *byte == 0).ok_or_else(|| {
                parent_fault(
                    "owned.parent.task_census",
                    OwnedFaultCause::Malformed {
                        field: 6,
                        offset: (offset + 19) as u64,
                    },
                )
            })?;
            let name = &name[..end];
            if name != b"." && name != b".." {
                if names == 4096 {
                    return Err(parent_fault(
                        "owned.parent.task_limit",
                        OwnedFaultCause::Limit {
                            field: 6,
                            limit: 4096,
                            observed: 4097,
                        },
                    ));
                }
                names += 1;
                visit(Some(name))?;
            }
            offset += length;
        }
    }
}

#[cfg(target_os = "linux")]
fn parent_fault(boundary: &'static str, cause: OwnedFaultCause) -> OwnedParentError {
    OwnedParentError::Observation(OwnedParentObservation {
        boundary,
        cause,
        source: None,
        secondary: None,
        status: None,
        request_stop: None,
    })
}

#[cfg(target_os = "linux")]
fn parent_io(
    boundary: &'static str,
    operation: u8,
    field: u8,
    source: io::Error,
) -> OwnedParentError {
    let cause = match source.raw_os_error() {
        Some(errno) => OwnedFaultCause::Io {
            operation,
            field,
            errno,
        },
        None => OwnedFaultCause::Unverifiable { field },
    };
    OwnedParentError::Observation(OwnedParentObservation {
        boundary,
        cause,
        source: Some(source),
        secondary: None,
        status: None,
        request_stop: None,
    })
}

#[cfg(target_os = "linux")]
fn parent_budget(
    deadline: std::time::Instant,
    request: Option<ParentRequest<'_>>,
) -> Result<(), OwnedParentError> {
    request_budget("owned.parent.task_budget", request)?;
    if std::time::Instant::now() >= deadline {
        Err(parent_fault(
            "owned.parent.task_budget",
            OwnedFaultCause::Deadline,
        ))
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn parent_dumpable(
    deadline: std::time::Instant,
    request: Option<ParentRequest<'_>>,
) -> Result<(), OwnedParentError> {
    let _ = (deadline, request);
    // SAFETY: PR_GET_DUMPABLE has no pointer operands.
    let actual = unsafe { prctl(3, 0, 0, 0, 0) };
    let result = if actual == -1 {
        Err(parent_io(
            "owned.parent.dumpable",
            2,
            1,
            io::Error::last_os_error(),
        ))
    } else if actual != 0 {
        Err(parent_fault(
            "owned.parent.dumpable",
            OwnedFaultCause::Readback {
                field: 1,
                actual: i64::from(actual),
            },
        ))
    } else {
        Ok(())
    };
    // A matching readback is the result. A deadline that elapses during
    // the get must not replace it.
    result
}

#[cfg(target_os = "linux")]
struct ParentStatus {
    threads: u32,
}

#[cfg(target_os = "linux")]
fn parent_status(
    file: &mut std::fs::File,
    tid: u32,
    pid: u32,
    deadline: std::time::Instant,
    request: Option<ParentRequest<'_>>,
) -> Result<ParentStatus, OwnedParentError> {
    use std::io::{Read as _, Seek as _, SeekFrom};
    // The caller already decided to read this status. An elapsed deadline
    // must not hide the identity those bytes name.
    file.seek(SeekFrom::Start(0))
        .map_err(|source| parent_io("owned.parent.task_status", 8, 9, source))?;
    let mut bytes = Vec::with_capacity(4096);
    let mut chunk = [0_u8; 4096];
    loop {
        let remaining = 65_537_usize.saturating_sub(bytes.len());
        let width = remaining.min(chunk.len());
        let read = file
            .read(&mut chunk[..width])
            .map_err(|source| parent_io("owned.parent.task_status", 5, 9, source))?;
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..read]);
        if bytes.len() > 65_536 {
            return Err(parent_fault(
                "owned.parent.task_limit",
                OwnedFaultCause::Limit {
                    field: 9,
                    limit: 65_536,
                    observed: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
                },
            ));
        }
        // Bytes already landed. A deadline must not drop a file whose next
        // read is EOF. One probe decides that.
        if parent_budget(deadline, request).is_err() {
            let remaining = 65_537_usize.saturating_sub(bytes.len());
            let width = remaining.min(chunk.len());
            let extra = file
                .read(&mut chunk[..width])
                .map_err(|source| parent_io("owned.parent.task_status", 5, 9, source))?;
            if extra == 0 {
                break;
            }
            bytes.extend_from_slice(&chunk[..extra]);
            if bytes.len() > 65_536 {
                return Err(parent_fault(
                    "owned.parent.task_limit",
                    OwnedFaultCause::Limit {
                        field: 9,
                        limit: 65_536,
                        observed: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
                    },
                ));
            }
            parent_budget(deadline, request)?;
        }
    }
    let mut fields: [Option<u32>; 4] = [None; 4];
    let mut offset = 0;
    // The status bytes are already bounded. A deadline during the scan
    // must not replace the identity those bytes already name.
    for line in bytes.split_inclusive(|byte| *byte == b'\n') {
        let line_offset = offset;
        offset += line.len();
        let (index, field, key, value): (_, _, &[u8], _) =
            if let Some(value) = line.strip_prefix(b"Pid:") {
                (0, 3, b"Pid:", value)
            } else if let Some(value) = line.strip_prefix(b"Tgid:") {
                (1, 4, b"Tgid:", value)
            } else if let Some(value) = line.strip_prefix(b"TracerPid:") {
                (2, 2, b"TracerPid:", value)
            } else if let Some(value) = line.strip_prefix(b"Threads:") {
                (3, 5, b"Threads:", value)
            } else {
                continue;
            };
        if fields[index].is_some() {
            let count = bytes
                .split_inclusive(|byte| *byte == b'\n')
                .filter(|line| line.starts_with(key))
                .count();
            return Err(parent_fault(
                "owned.parent.task_status",
                OwnedFaultCause::Duplicate {
                    field,
                    count: count as u64,
                },
            ));
        }
        let value = parent_decimal(value, line_offset + key.len(), field)
            .map_err(|cause| parent_fault("owned.parent.task_status", cause))?;
        // Positive tracing is irreversible evidence for this invocation, even
        // if the task retires before a later line or read can be observed.
        if index == 2 && value != 0 {
            return Err(parent_fault(
                "owned.parent.tracer",
                OwnedFaultCause::Readback {
                    field: 2,
                    actual: i64::from(value),
                },
            ));
        }
        fields[index] = Some(value);
    }
    if !bytes.is_empty() && bytes.last() != Some(&b'\n') {
        let observed = bytes.len() as u64;
        return Err(parent_fault(
            "owned.parent.task_status",
            OwnedFaultCause::EarlyEof {
                field: 9,
                expected: observed + 1,
                observed,
            },
        ));
    }
    for (index, field) in [3, 4, 2, 5].into_iter().enumerate() {
        if fields[index].is_none() {
            return Err(parent_fault(
                "owned.parent.task_status",
                OwnedFaultCause::Missing { field },
            ));
        }
    }
    if fields[0] != Some(tid) || fields[1] != Some(pid) {
        return Err(parent_fault(
            "owned.parent.task_identity",
            OwnedFaultCause::Unverifiable { field: 7 },
        ));
    }
    fields[3]
        .map(|threads| ParentStatus { threads })
        .ok_or_else(|| {
            parent_fault(
                "owned.parent.task_status",
                OwnedFaultCause::Missing { field: 5 },
            )
        })
}

#[cfg(target_os = "linux")]
fn parent_identity(bytes: &[u8], field: u8) -> Result<u32, OwnedFaultCause> {
    if bytes.len() > 65_536 {
        return Err(OwnedFaultCause::Limit {
            field,
            limit: 65_536,
            observed: 65_537,
        });
    }
    if !bytes.is_empty() && bytes.last() != Some(&b'\n') {
        let observed = bytes.len() as u64;
        return Err(OwnedFaultCause::EarlyEof {
            field,
            expected: observed + 1,
            observed,
        });
    }
    let key: &[u8] = if field == 3 { b"Pid:" } else { b"PPid:" };
    let mut selected = None;
    let mut count = 0_u64;
    let mut offset = 0;
    for line in bytes.split_inclusive(|byte| *byte == b'\n') {
        if let Some(value) = line.strip_prefix(key) {
            count += 1;
            selected = Some((value, offset + key.len()));
        }
        offset += line.len();
    }
    if count >= 2 {
        return Err(OwnedFaultCause::Duplicate { field, count });
    }
    let (value, offset) = selected.ok_or(OwnedFaultCause::Missing { field })?;
    parent_decimal(value, offset, field)
}

#[cfg(target_os = "linux")]
fn parent_decimal(value: &[u8], offset: usize, field: u8) -> Result<u32, OwnedFaultCause> {
    let mut cursor = 0;
    while matches!(value.get(cursor), Some(b' ' | b'\t')) {
        cursor += 1;
    }
    if cursor == 0 || !value.get(cursor).is_some_and(u8::is_ascii_digit) {
        return Err(OwnedFaultCause::Malformed {
            field,
            offset: (offset + cursor) as u64,
        });
    }
    let first = cursor;
    let mut identity = 0_u32;
    while let Some(byte) = value.get(cursor).filter(|byte| byte.is_ascii_digit()) {
        if cursor > first && value[first] == b'0' {
            return Err(OwnedFaultCause::Malformed {
                field,
                offset: (offset + cursor) as u64,
            });
        }
        identity = identity
            .checked_mul(10)
            .and_then(|number| number.checked_add(u32::from(*byte - b'0')))
            .filter(|number| i32::try_from(*number).is_ok())
            .ok_or(OwnedFaultCause::NumericOverflow {
                field,
                offset: (offset + cursor) as u64,
            })?;
        cursor += 1;
    }
    if cursor == value.len() {
        let observed = (offset + cursor) as u64;
        return Err(OwnedFaultCause::EarlyEof {
            field,
            expected: observed + 1,
            observed,
        });
    }
    if value.get(cursor..) != Some(b"\n") {
        return Err(OwnedFaultCause::Trailing {
            field,
            offset: (offset + cursor) as u64,
        });
    }
    Ok(identity)
}

#[cfg(target_os = "linux")]
fn parent_identity_with_context(
    bytes: &[u8],
    field: u8,
    boundary: &'static str,
    _deadline: std::time::Instant,
    _request: Option<ParentRequest<'_>>,
) -> Result<u32, OwnedParentError> {
    // The status bytes are already bounded. Their identity is the result;
    // a deadline or cancel while they are scanned must not replace it.
    // Callers enforce the stop before the next side effect.
    parent_identity(bytes, field).map_err(|cause| parent_fault(boundary, cause))
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
struct ParentRequest<'a> {
    deadline: std::time::Instant,
    cancel: Option<&'a dyn Fn() -> bool>,
}

#[cfg(target_os = "linux")]
fn request_budget(
    boundary: &'static str,
    request: Option<ParentRequest<'_>>,
) -> Result<(), OwnedParentError> {
    let Some(request) = request else {
        return Ok(());
    };
    let stop = if request.cancel.is_some_and(|cancel| cancel()) {
        Some(OwnedStop::Cancelled)
    } else if std::time::Instant::now() >= request.deadline {
        Some(OwnedStop::Deadline)
    } else {
        None
    };
    if let Some(stop) = stop {
        let mut error = parent_fault(
            boundary,
            match stop {
                OwnedStop::Cancelled => OwnedFaultCause::Cancelled,
                _ => OwnedFaultCause::Deadline,
            },
        );
        let OwnedParentError::Observation(OwnedParentObservation { request_stop, .. }) = &mut error;
        *request_stop = Some(stop);
        Err(error)
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn identity_budget(
    boundary: &'static str,
    deadline: std::time::Instant,
) -> Result<(), OwnedParentError> {
    if std::time::Instant::now() >= deadline {
        Err(parent_fault(boundary, OwnedFaultCause::Deadline))
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
/// An already-armed parent-death signal is read back even after the deadline.
/// A fresh observation still stops when that deadline has already elapsed.
#[cfg(test)]
fn identity_read_proceeds(already_armed: bool, elapsed: bool) -> bool {
    already_armed || !elapsed
}

fn self_status_identity(
    boundary: &'static str,
    field: u8,
    expected: u32,
    deadline: std::time::Instant,
    request: Option<ParentRequest<'_>>,
    already_armed: bool,
) -> Result<u32, OwnedParentError> {
    use std::fs::File;
    use std::io::Read as _;
    use std::os::fd::IntoRawFd as _;

    // Fresh observations stop before opening. An armed signal is already
    // the side effect, so its status is read even after the deadline.
    if !already_armed {
        request_budget(boundary, request)?;
        identity_budget(boundary, deadline)?;
    }
    // SAFETY: AT_FDCWD and the fixed trusted proc path are valid for openat;
    // no creation mode is required, and EINTR is returned without retry.
    let fd = unsafe { openat(-100, c"/proc/self/status".as_ptr(), O_CLOEXEC | O_NONBLOCK) };
    if fd == -1 {
        return Err(parent_io(boundary, 4, field, io::Error::last_os_error()));
    }
    // SAFETY: openat returned a fresh uniquely owned status descriptor.
    let mut status = unsafe { File::from_raw_fd(fd) };
    let observation = (|| {
        // The descriptor is already open. An armed readback must not stop
        // before the first status byte; a fresh observation still does.
        if !already_armed {
            request_budget(boundary, request)?;
            identity_budget(boundary, deadline)?;
        }
        let mut bytes = [0_u8; 65_537];
        let mut length = 0;
        loop {
            let count = status
                .read(&mut bytes[length..])
                .map_err(|source| parent_io(boundary, 5, field, source))?;
            if count == 0 {
                break;
            }
            length += count;
            if length == bytes.len() {
                return Err(parent_fault(
                    boundary,
                    OwnedFaultCause::Limit {
                        field,
                        limit: 65_536,
                        observed: 65_537,
                    },
                ));
            }
            // Bytes already landed. A deadline must not drop a status file
            // whose next read is EOF. One probe decides that.
            if request_budget(boundary, request).is_err()
                || identity_budget(boundary, deadline).is_err()
            {
                let extra = status
                    .read(&mut bytes[length..])
                    .map_err(|source| parent_io(boundary, 5, field, source))?;
                if extra == 0 {
                    break;
                }
                length += extra;
                if length == bytes.len() {
                    return Err(parent_fault(
                        boundary,
                        OwnedFaultCause::Limit {
                            field,
                            limit: 65_536,
                            observed: 65_537,
                        },
                    ));
                }
                request_budget(boundary, request)?;
                identity_budget(boundary, deadline)?;
            }
        }
        let actual =
            parent_identity_with_context(&bytes[..length], field, boundary, deadline, request)?;
        if actual != expected {
            return Err(parent_fault(
                boundary,
                OwnedFaultCause::Mismatch {
                    field,
                    expected: u64::from(expected),
                    observed: u64::from(actual),
                },
            ));
        }
        Ok(actual)
    })();
    match observation {
        Err(mut error) => {
            // The fatal helper path holds this capability until process exit.
            // The live root retires it once before returning a local refusal.
            let OwnedParentError::Observation(OwnedParentObservation { status: held, .. }) =
                &mut error;
            *held = Some(status);
            Err(error)
        }
        Ok(actual) => {
            let fd = status.into_raw_fd();
            // SAFETY: into_raw_fd transfers the unique live status descriptor;
            // close is attempted once. The identity is already proven, so a
            // deadline that elapses during this close must not replace it.
            if unsafe { close(fd) } == -1 {
                return Err(parent_io(boundary, 7, field, io::Error::last_os_error()));
            }
            Ok(actual)
        }
    }
}

/// Freezes the actual outer process identity before the native init fork.
///
/// # Errors
/// Returns the original same-view status observation. A fatal helper must
/// retain the error until its bounded fault attempt and process exit.
#[cfg(target_os = "linux")]
pub fn owned_init_parent_identity(deadline: std::time::Instant) -> Result<u32, OwnedParentError> {
    self_status_identity(
        "owned.init.parent_death",
        3,
        std::process::id(),
        deadline,
        None,
        false,
    )
}

/// Arms parent death and verifies the original process in the outer proc view.
///
/// # Errors
/// Returns the original setter, status, shape, identity, or close failure.
/// This operation is valid only before the init's local proc remount. A fatal
/// helper retains the error through reporting and exits without dropping it.
#[cfg(target_os = "linux")]
pub fn arm_owned_parent(
    init: bool,
    expected: u32,
    deadline: std::time::Instant,
) -> Result<(), OwnedParentError> {
    let boundary = if init {
        "owned.init.parent_death"
    } else {
        "owned.waiter.parent_death"
    };
    identity_budget(boundary, deadline)?;
    // SAFETY: PR_SET_PDEATHSIG takes a signal integer and no pointer operands.
    if unsafe { prctl(1, 9, 0, 0, 0) } == -1 {
        return Err(parent_io(boundary, 12, 30, io::Error::last_os_error()));
    }
    // The death signal is already armed. Verify the identity even if the
    // deadline elapses during the setter; a matching status stays success.
    self_status_identity(boundary, 31, expected, deadline, None, true).map(|_| ())
}

impl OwnedParentError {
    /// Returns the original request stop observed before any earlier failure.
    #[must_use]
    pub fn request_stop(&self) -> Option<OwnedStop> {
        let Self::Observation(OwnedParentObservation { request_stop, .. }) = self;
        *request_stop
    }

    #[must_use]
    pub fn boundary(&self) -> &'static str {
        let Self::Observation(OwnedParentObservation { boundary, .. }) = self;
        boundary
    }

    #[must_use]
    pub fn cause(&self) -> OwnedFaultCause {
        let Self::Observation(OwnedParentObservation { cause, .. }) = self;
        *cause
    }

    #[must_use]
    pub fn io_source(&self) -> Option<&io::Error> {
        let Self::Observation(OwnedParentObservation { source, .. }) = self;
        source.as_ref()
    }

    #[must_use]
    pub fn secondary(&self) -> Option<&Self> {
        let Self::Observation(OwnedParentObservation { secondary, .. }) = self;
        secondary.as_deref()
    }

    fn set_secondary(&mut self, error: Self) {
        let Self::Observation(OwnedParentObservation { secondary, .. }) = self;
        if secondary.is_none() {
            *secondary = Some(Box::new(error));
        }
    }

    #[cfg(target_os = "linux")]
    fn retire_status(&mut self, field: u8) {
        use std::os::fd::IntoRawFd as _;
        let Self::Observation(OwnedParentObservation { status, .. }) = self;
        if let Some(status) = status.take() {
            let fd = status.into_raw_fd();
            // SAFETY: the unique acquired status descriptor is consumed here;
            // its number is never reused for another close attempt.
            if unsafe { close(fd) } == -1 {
                self.set_secondary(parent_io(
                    self.boundary(),
                    7,
                    field,
                    io::Error::last_os_error(),
                ));
            }
        }
    }
}

#[cfg(target_os = "linux")]
unsafe extern "C" {
    fn prctl(option: i32, ...) -> i32;
    fn tgkill(tgid: i32, tid: i32, signal: i32) -> i32;
    fn close(fd: i32) -> i32;
    fn syscall(number: std::ffi::c_long, ...) -> std::ffi::c_long;
}

thread_local! {
    static HELPER_BINARY_OVERRIDE: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
}

/// Overrides helper resolution for this thread. Tests use this instead of
/// `env::set_var` (unsafe in edition 2024). Pass `None` to restore.
pub fn override_helper_binary(path: Option<PathBuf>) {
    HELPER_BINARY_OVERRIDE.with(|slot| {
        *slot.borrow_mut() = path;
    });
}

/// The confined run succeeded.
pub const EXIT_OK: i32 = 0;
/// The confined child could not apply its sandbox (sandbox_init / Landlock):
/// a mechanism-init failure, never an effect denial.
pub const EXIT_SANDBOX_INIT: i32 = 10;
/// The data-plane fd I/O failed inside the confined child.
pub const EXIT_DATA_IO: i32 = 20;
/// The confined write failed after the target was already truncated: the
/// bytes on disk are neither the old nor the intended content, so the
/// host must classify the attempt unknown, never rejected.
pub const EXIT_DATA_MUTATED: i32 = 21;
/// The helper was invoked with an invalid mode/argument contract.
pub const EXIT_PROTOCOL: i32 = 30;
/// `launch` could not execute the target program for a reason other than a
/// missing binary.
pub const EXIT_LAUNCH_EXEC: i32 = 126;
/// `launch` could not find the target program to execute.
pub const EXIT_LAUNCH_NOT_FOUND: i32 = 127;

/// Resolves the confined helper binary that performs admitted fd I/O.
/// Cargo sets `CARGO_BIN_EXE_rivect_sandbox_helper` for this crate's binary
/// in test builds; a `RIVECT_SANDBOX_HELPER` override pins an explicit
/// install; and the production layout expects the helper installed beside
/// the rivect executable (or one level up from a `deps/` test harness).
///
/// # Errors
/// Returns an `io::Error` naming the resolution rule when no candidate
/// exists — the executor surfaces that as the mechanism being unavailable,
/// never as an ambient in-process fallback.
pub fn helper_binary() -> io::Result<PathBuf> {
    if let Some(path) =
        HELPER_BINARY_OVERRIDE.with(|slot| slot.try_borrow().ok().and_then(|guard| guard.clone()))
    {
        return Ok(path);
    }
    if let Some(path) = std::env::var_os("RIVECT_SANDBOX_HELPER") {
        return Ok(PathBuf::from(path));
    }
    owned_helper_binary()
}

/// Resolves the installed native owner independently of payload helper overrides.
///
/// # Errors
/// Returns the original resolution failure when the installed helper is absent.
pub fn owned_helper_binary() -> io::Result<PathBuf> {
    let exe = std::env::current_exe()?;
    let dir = exe.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "cannot resolve the current executable directory",
        )
    })?;
    let beside = dir.join("rivect-sandbox-helper");
    if beside.is_file() {
        return Ok(beside);
    }
    // A `target/debug/deps/rivect-<hash>` test harness keeps the helper at
    // `target/debug/rivect-sandbox-helper`; one level up from `deps/`.
    let up = dir.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "cannot resolve the parent of the current executable directory",
        )
    })?;
    let deps_beside = up.join("rivect-sandbox-helper");
    if deps_beside.is_file() {
        return Ok(deps_beside);
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "rivect-sandbox-helper binary not found beside the rivect executable (or one level up from a deps/ test harness); install it beside the binary",
    ))
}

/// Makes only the held child control endpoint survive the trusted helper exec.
///
/// # Errors
/// Returns the actual spawn error; the endpoint remains borrowed until spawn.
#[cfg(target_os = "linux")]
pub fn spawn_owned_control(
    mut command: std::process::Command,
    endpoint: &std::os::unix::net::UnixStream,
    deadline: std::time::Instant,
    cancel: Option<&dyn Fn() -> bool>,
) -> io::Result<std::process::Child> {
    use std::os::unix::process::CommandExt as _;
    let request = Some(ParentRequest { deadline, cancel });
    request_budget("owned.waiter.parent_death", request).map_err(io::Error::other)?;
    ensure_parent_with_request(request).map_err(io::Error::other)?;
    request_budget("owned.waiter.parent_death", request).map_err(io::Error::other)?;
    let pid = std::process::id();
    let expected = self_status_identity(
        "owned.waiter.parent_death",
        3,
        pid,
        deadline,
        request,
        false,
    )
    .map_err(|mut error| {
        error.retire_status(3);
        io::Error::other(error)
    })?;
    command.env("RIVECT_OWNED_PARENT_PID", expected.to_string());
    let fd = endpoint.as_raw_fd();
    // SAFETY: the endpoint remains alive through spawn. The child callback
    // performs only Linux syscalls and fcntl and reads no shared state.
    // CLOEXEC preserves std's private spawn-error pipe until exec; closing
    // it here could falsely acknowledge a later failed trusted exec.
    unsafe {
        command.pre_exec(move || {
            if parent_syscall(436, 3_u32, u32::MAX, 4_u32) == -1 {
                return Err(io::Error::last_os_error());
            }
            if fcntl(fd, 2, 0) == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    request_budget("owned.waiter.parent_death", request).map_err(io::Error::other)?;
    command.spawn()
}

/// Opens a stable capability while the trusted waiter is still unreaped.
///
/// # Errors
/// Returns the actual pidfd_open failure without a numeric-signal fallback.
#[cfg(target_os = "linux")]
pub fn owned_waiter_pidfd(pid: u32) -> io::Result<std::os::fd::OwnedFd> {
    // SAFETY: pidfd_open accepts a numeric pid and zero flags and returns a
    // fresh descriptor. The caller holds the child unreaped during this call.
    let fd = unsafe { parent_syscall(434, pid, 0_u32) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let raw =
        i32::try_from(fd).map_err(|source| io::Error::new(io::ErrorKind::InvalidData, source))?;
    // SAFETY: this successful syscall returned a fresh owned descriptor.
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) })
}

/// Sends SIGKILL through a held waiter capability, including after exit.
///
/// # Errors
/// Returns the native error; ESRCH is a completed teardown.
#[cfg(target_os = "linux")]
pub fn kill_owned_waiter(fd: BorrowedFd<'_>) -> io::Result<()> {
    // SAFETY: the borrowed pidfd remains live throughout the syscall; the
    // null siginfo and zero flags request the ordinary SIGKILL operation.
    if unsafe { parent_syscall(424, fd.as_raw_fd(), 9_i32, std::ptr::null::<u8>(), 0_u32) } == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(3) {
        Ok(())
    } else {
        Err(error)
    }
}

/// Reads the kernel monotonic clock used by the owned execution deadline.
///
/// # Errors
/// Returns the native clock error or a bounded integer conversion failure.
#[cfg(target_os = "linux")]
pub fn owned_monotonic_ns() -> io::Result<u64> {
    #[repr(C)]
    struct Timespec {
        seconds: i64,
        nanoseconds: i64,
    }
    unsafe extern "C" {
        fn clock_gettime(clock: i32, value: *mut Timespec) -> i32;
    }
    let mut value = Timespec {
        seconds: 0,
        nanoseconds: 0,
    };
    // SAFETY: CLOCK_MONOTONIC writes exactly the initialized repr(C) object.
    if unsafe { clock_gettime(1, &mut value) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let seconds = u64::try_from(value.seconds)
        .map_err(|source| io::Error::new(io::ErrorKind::InvalidData, source))?;
    let nanos = u64::try_from(value.nanoseconds)
        .map_err(|source| io::Error::new(io::ErrorKind::InvalidData, source))?;
    if nanos >= 1_000_000_000 {
        return Err(io::Error::other("invalid monotonic nanoseconds"));
    }
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|base| base.checked_add(nanos))
        .ok_or_else(|| io::Error::other("monotonic clock exceeds range"))
}

/// Marks a pipe fd non-blocking so the host can drain a confined child
/// without `thread::sleep`.
///
/// # Errors
/// Returns the OS error when `fcntl` cannot read or set the flags.
pub fn set_nonblocking(fd: impl std::os::fd::AsFd) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let raw = fd.as_fd().as_raw_fd();
    // SAFETY: `raw` is a live fd borrowed from `AsFd`; F_GETFL/F_SETFL
    // only read and write the fd flags word and never alias memory.
    let flags = unsafe { fcntl(raw, F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: same fd; the flags word is the F_GETFL result plus O_NONBLOCK.
    let rc = unsafe { fcntl(raw, F_SETFL, flags | O_NONBLOCK) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The failure of one open-file-description write-lock attempt. The
/// helper owns the only errno classification of that lock.
#[derive(Debug, thiserror::Error)]
pub enum OfdLockError {
    /// Another open file description holds a conflicting lock.
    #[error("another open file description holds the byte-range lock")]
    Held,
    /// The platform or filesystem has no open-file-description locks.
    #[error("open-file-description locks are not supported here")]
    Unsupported,
    /// Any other failure of the lock call.
    #[error("open-file-description lock call failed")]
    Io(#[source] io::Error),
}

/// `struct flock` as the pinned targets lay it out (`l_pid` stays 0 for
/// the OFD commands).
#[cfg(target_os = "linux")]
#[repr(C)]
struct Flock {
    l_type: i16,
    l_whence: i16,
    l_start: i64,
    l_len: i64,
    l_pid: i32,
}
#[cfg(target_os = "macos")]
#[repr(C)]
struct Flock {
    l_start: i64,
    l_len: i64,
    l_pid: i32,
    l_type: i16,
    l_whence: i16,
}

#[cfg(target_os = "linux")]
const F_OFD_SETLK: i32 = 37;
#[cfg(target_os = "macos")]
const F_OFD_SETLK: i32 = 90;
#[cfg(target_os = "linux")]
const F_SETLK: i32 = 6;
#[cfg(target_os = "macos")]
const F_SETLK: i32 = 8;
#[cfg(target_os = "linux")]
const F_WRLCK: i16 = 1;
#[cfg(target_os = "macos")]
const F_WRLCK: i16 = 3;
#[cfg(target_os = "linux")]
const F_RDLCK: i16 = 0;
#[cfg(target_os = "macos")]
const F_RDLCK: i16 = 1;
const F_UNLCK: i16 = 2;
const SEEK_SET: i16 = 0;
#[cfg(target_os = "linux")]
const EAGAIN: i32 = 11;
#[cfg(target_os = "macos")]
const EAGAIN: i32 = 35;
const EACCES: i32 = 13;
/// Errnos the pinned targets' headers give for "no OFD locks here":
/// `EINVAL` (command unknown), `ENOLCK` (no lock manager), `ENOSYS`,
/// `EOPNOTSUPP` (Linux 95) / `ENOTSUP` (Darwin 45).
#[cfg(target_os = "linux")]
const OFD_UNSUPPORTED: [i32; 4] = [22, 37, 38, 95];
#[cfg(target_os = "macos")]
const OFD_UNSUPPORTED: [i32; 4] = [22, 77, 78, 45];

/// Issues one non-blocking `lock_type` request for `[offset, offset +
/// len)` with `command`.
fn try_lock(
    file: impl std::os::fd::AsFd,
    command: i32,
    lock_type: i16,
    offset: i64,
    len: i64,
) -> Result<(), io::Error> {
    let mut request = Flock {
        l_type: lock_type,
        l_whence: SEEK_SET,
        l_start: offset,
        l_len: len,
        l_pid: 0,
    };
    // SAFETY: the fd is live (borrowed from `file`) and `request` is a
    // valid, exclusively borrowed `struct flock` of the target layout
    // that outlives the call.
    let rc = unsafe { fcntl(file.as_fd().as_raw_fd(), command, &raw mut request) };
    if rc == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The one errno classification of an open-file-description lock attempt:
/// a conflict, a platform without such locks, or any other failure.
fn classify_ofd_lock(error: io::Error) -> OfdLockError {
    match error.raw_os_error() {
        Some(EAGAIN | EACCES) => OfdLockError::Held,
        Some(code) if OFD_UNSUPPORTED.contains(&code) => OfdLockError::Unsupported,
        _ => OfdLockError::Io(error),
    }
}

/// The errno classification of a POSIX lock attempt: a conflict or any
/// other failure.
fn classify_posix_lock(error: io::Error) -> OfdLockError {
    match error.raw_os_error() {
        Some(EAGAIN | EACCES) => OfdLockError::Held,
        _ => OfdLockError::Io(error),
    }
}

/// Takes a non-blocking exclusive open-file-description lock on the one
/// byte at `offset`. The lock is released only by the last close of the
/// open file description behind `file`.
///
/// # Errors
/// `Held` on a conflict (`EAGAIN`/`EACCES`), `Unsupported` when the
/// platform has no OFD locks, `Io` for every other errno.
pub fn ofd_try_write_lock(file: &std::fs::File, offset: i64) -> Result<(), OfdLockError> {
    try_lock(file, F_OFD_SETLK, F_WRLCK, offset, 1).map_err(classify_ofd_lock)
}

/// Releases the open-file-description lock on the one byte at `offset`
/// through `fd`, whichever descriptor of the description that is. It
/// never waits and classifies nothing: when to unlock belongs to the
/// caller, and the last close of the description releases it anyway.
///
/// # Errors
/// The OS error of the `F_UNLCK` request, unclassified.
pub fn ofd_unlock(fd: impl std::os::fd::AsFd, offset: i64) -> io::Result<()> {
    try_lock(fd, F_OFD_SETLK, F_UNLCK, offset, 1)
}

/// Takes a non-blocking exclusive POSIX (process-owned) lock on
/// `[offset, offset + len)` with `F_SETLK`, the lock family SQLite's
/// own file locking uses. It is released when the process closes any fd
/// of the file or exits.
///
/// # Errors
/// `Held` on a conflict (`EAGAIN`/`EACCES`), `Io` for every other errno.
pub fn posix_try_write_range(
    file: &std::fs::File,
    offset: i64,
    len: i64,
) -> Result<(), OfdLockError> {
    try_lock(file, F_SETLK, F_WRLCK, offset, len).map_err(classify_posix_lock)
}

/// Takes a non-blocking shared POSIX (process-owned) lock on `[offset,
/// offset + len)` with `F_SETLK`; `file` must be open for reading. It is
/// released when the process closes any fd of the file or exits.
///
/// # Errors
/// `Held` on a conflict with another process's exclusive lock
/// (`EAGAIN`/`EACCES`), `Io` for every other errno.
pub fn posix_try_read_range(
    file: &std::fs::File,
    offset: i64,
    len: i64,
) -> Result<(), OfdLockError> {
    try_lock(file, F_SETLK, F_RDLCK, offset, len).map_err(classify_posix_lock)
}

/// Longest reuse token: the platform tag byte, the four-byte Linux handle
/// type and `MAX_HANDLE_SZ` (128) handle bytes.
pub const REUSE_TOKEN_MAX: usize = 133;

/// Linux `O_PATH` (uapi asm-generic fcntl.h, the same bit on x86_64 and
/// aarch64): an identity-only open that neither reads nor writes.
#[cfg(target_os = "linux")]
pub const OPEN_PATH: i32 = 0o10_000_000;

/// The platform tag of a Linux file-handle token.
const REUSE_TAG_LINUX: u8 = 1;
/// The platform tag of a Darwin volume-UUID token.
const REUSE_TAG_DARWIN: u8 = 2;
/// Bytes of the Linux handle type a Linux token carries after its tag.
const LINUX_HANDLE_TYPE_LEN: usize = 4;
/// `MAX_HANDLE_SZ` (linux/fcntl.h).
const LINUX_MAX_HANDLE_SZ: usize = 128;
/// Bytes of the Darwin volume UUID a Darwin token carries after its tag.
const DARWIN_UUID_LEN: usize = 16;

/// The discriminator that tells a reused `(dev, ino)` from the file it
/// was taken from: a Linux file handle or a Darwin volume UUID, tagged
/// by platform. Bytes past the length stay zero, so the derived equality
/// compares exactly the token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReuseToken {
    len: u8,
    bytes: [u8; REUSE_TOKEN_MAX],
}

impl ReuseToken {
    /// The tagged token bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }

    /// Decodes tagged token bytes, validating the platform shape: a Linux
    /// token carries four handle-type bytes and a nonempty handle whose
    /// length is a multiple of four, a Darwin token exactly sixteen UUID
    /// bytes. `None` for an unknown tag, an invalid platform length, an
    /// empty payload or more than [`REUSE_TOKEN_MAX`] bytes.
    #[must_use]
    pub fn from_bytes(raw: &[u8]) -> Option<Self> {
        let (&tag, payload) = raw.split_first()?;
        let shaped = match tag {
            REUSE_TAG_LINUX => payload
                .len()
                .checked_sub(LINUX_HANDLE_TYPE_LEN)
                .is_some_and(|handle| {
                    handle > 0 && handle.is_multiple_of(4) && handle <= LINUX_MAX_HANDLE_SZ
                }),
            REUSE_TAG_DARWIN => payload.len() == DARWIN_UUID_LEN,
            _ => false,
        };
        if !shaped || raw.len() > REUSE_TOKEN_MAX {
            return None;
        }
        let mut bytes = [0; REUSE_TOKEN_MAX];
        bytes[..raw.len()].copy_from_slice(raw);
        Some(Self {
            len: u8::try_from(raw.len()).ok()?,
            bytes,
        })
    }
}

/// Why no reuse token could be taken for a file.
#[derive(Debug, thiserror::Error)]
pub enum ReuseTokenError {
    /// The filesystem offers no reuse discriminator for this file.
    #[error("the filesystem reports no reuse discriminator")]
    Unsupported,
    /// The query failed or returned a malformed answer.
    #[error("reuse discriminator query failed")]
    Io(#[source] io::Error),
}

fn malformed_reuse_answer(what: &'static str) -> ReuseTokenError {
    ReuseTokenError::Io(io::Error::new(io::ErrorKind::InvalidData, what))
}

/// `struct file_handle` with its `MAX_HANDLE_SZ` payload inline.
#[cfg(target_os = "linux")]
#[repr(C)]
struct LinuxFileHandle {
    handle_bytes: u32,
    handle_type: i32,
    f_handle: [u8; LINUX_MAX_HANDLE_SZ],
}

/// `AT_EMPTY_PATH` (linux/fcntl.h): the handle names the fd itself.
#[cfg(target_os = "linux")]
const AT_EMPTY_PATH: i32 = 0x1000;
/// `FILEID_INVALID` (linux/exportfs.h).
#[cfg(target_os = "linux")]
const LINUX_FILEID_INVALID: i32 = 0xff;
/// `EOPNOTSUPP`, `EOVERFLOW` and `ENOSYS`: no exportable handle here.
#[cfg(target_os = "linux")]
const REUSE_UNSUPPORTED: [i32; 3] = [95, 75, 38];

#[cfg(target_os = "linux")]
unsafe extern "C" {
    fn name_to_handle_at(
        dirfd: i32,
        pathname: *const std::os::raw::c_char,
        handle: *mut LinuxFileHandle,
        mount_id: *mut i32,
        flags: i32,
    ) -> i32;
}

/// Takes the reuse token of the file behind `file`: on Linux its
/// exportable file handle, which names the inode generation a recycled
/// inode number does not share. Every call queries the kernel.
///
/// # Errors
/// [`ReuseTokenError::Unsupported`] when the filesystem exports no handle
/// (`EOPNOTSUPP`, `EOVERFLOW`, `ENOSYS`); [`ReuseTokenError::Io`] for
/// every other errno and for a malformed handle.
#[cfg(target_os = "linux")]
pub fn reuse_token(file: &std::fs::File) -> Result<ReuseToken, ReuseTokenError> {
    let mut handle = LinuxFileHandle {
        handle_bytes: LINUX_MAX_HANDLE_SZ as u32,
        handle_type: 0,
        f_handle: [0; LINUX_MAX_HANDLE_SZ],
    };
    let mut mount_id = 0_i32;
    // SAFETY: the fd is live (borrowed from `file`), the empty path is a
    // NUL-terminated literal, and `handle`/`mount_id` are exclusively
    // borrowed buffers of the kernel layout whose `handle_bytes` names the
    // inline payload capacity; the kernel writes only within them.
    let rc = unsafe {
        name_to_handle_at(
            file.as_raw_fd(),
            c"".as_ptr(),
            &raw mut handle,
            &raw mut mount_id,
            AT_EMPTY_PATH,
        )
    };
    if rc == -1 {
        let error = io::Error::last_os_error();
        return Err(match error.raw_os_error() {
            Some(code) if REUSE_UNSUPPORTED.contains(&code) => ReuseTokenError::Unsupported,
            _ => ReuseTokenError::Io(error),
        });
    }
    let handle_len = usize::try_from(handle.handle_bytes)
        .map_err(|_overflow| malformed_reuse_answer("file handle length exceeds usize"))?;
    if handle_len > LINUX_MAX_HANDLE_SZ {
        return Err(malformed_reuse_answer("file handle exceeds MAX_HANDLE_SZ"));
    }
    if handle_len == 0 || !handle_len.is_multiple_of(4) {
        return Err(malformed_reuse_answer(
            "file handle length is not word aligned",
        ));
    }
    if handle.handle_type <= 0 || handle.handle_type == LINUX_FILEID_INVALID {
        return Err(malformed_reuse_answer("file handle type is invalid"));
    }
    let mut raw = Vec::with_capacity(1 + LINUX_HANDLE_TYPE_LEN + handle_len);
    raw.push(REUSE_TAG_LINUX);
    raw.extend_from_slice(&handle.handle_type.to_le_bytes());
    raw.extend_from_slice(&handle.f_handle[..handle_len]);
    ReuseToken::from_bytes(&raw).ok_or_else(|| malformed_reuse_answer("file handle token"))
}

/// `struct attrlist` (sys/attr.h).
#[cfg(target_os = "macos")]
#[repr(C)]
struct DarwinAttrList {
    bitmapcount: u16,
    reserved: u16,
    commonattr: u32,
    volattr: u32,
    dirattr: u32,
    fileattr: u32,
    forkattr: u32,
}

/// `attribute_set_t` (sys/attr.h).
#[cfg(target_os = "macos")]
#[repr(C)]
struct DarwinAttributeSet {
    commonattr: u32,
    volattr: u32,
    dirattr: u32,
    fileattr: u32,
    forkattr: u32,
}

/// `vol_capabilities_attr_t` (sys/attr.h).
#[cfg(target_os = "macos")]
#[repr(C)]
struct DarwinVolCapabilities {
    capabilities: [u32; 4],
    valid: [u32; 4],
}

/// The packed answer in attribute bit order: returned set, `ATTR_CMN_DEVID`,
/// then `ATTR_VOL_CAPABILITIES` and `ATTR_VOL_UUID`.
#[cfg(target_os = "macos")]
#[repr(C)]
struct DarwinVolumeAnswer {
    length: u32,
    returned: DarwinAttributeSet,
    devid: i32,
    capabilities: DarwinVolCapabilities,
    uuid: [u8; DARWIN_UUID_LEN],
}

#[cfg(target_os = "macos")]
const DARWIN_VOLUME_ANSWER_LEN: usize = 76;
#[cfg(target_os = "macos")]
const _: () = assert!(std::mem::size_of::<DarwinVolumeAnswer>() == DARWIN_VOLUME_ANSWER_LEN);

#[cfg(target_os = "macos")]
const ATTR_BIT_MAP_COUNT: u16 = 5;
#[cfg(target_os = "macos")]
const ATTR_CMN_RETURNED_ATTRS: u32 = 0x8000_0000;
#[cfg(target_os = "macos")]
const ATTR_CMN_DEVID: u32 = 0x0000_0002;
#[cfg(target_os = "macos")]
const ATTR_VOL_INFO: u32 = 0x8000_0000;
#[cfg(target_os = "macos")]
const ATTR_VOL_CAPABILITIES: u32 = 0x0002_0000;
#[cfg(target_os = "macos")]
const ATTR_VOL_UUID: u32 = 0x0004_0000;
#[cfg(target_os = "macos")]
const FSOPT_NOFOLLOW: u32 = 0x0000_0001;
#[cfg(target_os = "macos")]
const FSOPT_PACK_INVAL_ATTRS: u32 = 0x0000_0008;
/// `VOL_CAPABILITIES_FORMAT` index and `VOL_CAP_FMT_PATH_FROM_ID`: the
/// volume resolves a file id back to its path, so ids are persistent.
#[cfg(target_os = "macos")]
const VOL_CAPABILITIES_FORMAT: usize = 0;
#[cfg(target_os = "macos")]
const VOL_CAP_FMT_PATH_FROM_ID: u32 = 0x0000_4000;
/// `ENOTSUP` and `EINVAL`: the volume answers no such attributes.
#[cfg(target_os = "macos")]
const REUSE_UNSUPPORTED: [i32; 2] = [45, 22];

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn getattrlist(
        path: *const std::os::raw::c_char,
        attr_list: *mut DarwinAttrList,
        attr_buf: *mut DarwinVolumeAnswer,
        attr_buf_size: usize,
        options: u32,
    ) -> i32;
    fn fgetattrlist(
        fd: i32,
        attr_list: *mut DarwinAttrList,
        attr_buf: *mut DarwinVolumeAnswer,
        attr_buf_size: usize,
        options: u32,
    ) -> i32;
}

#[cfg(target_os = "macos")]
fn darwin_volume_request() -> (DarwinAttrList, DarwinVolumeAnswer) {
    (
        DarwinAttrList {
            bitmapcount: ATTR_BIT_MAP_COUNT,
            reserved: 0,
            commonattr: ATTR_CMN_RETURNED_ATTRS | ATTR_CMN_DEVID,
            volattr: ATTR_VOL_INFO | ATTR_VOL_CAPABILITIES | ATTR_VOL_UUID,
            dirattr: 0,
            fileattr: 0,
            forkattr: 0,
        },
        DarwinVolumeAnswer {
            length: 0,
            returned: DarwinAttributeSet {
                commonattr: 0,
                volattr: 0,
                dirattr: 0,
                fileattr: 0,
                forkattr: 0,
            },
            devid: 0,
            capabilities: DarwinVolCapabilities {
                capabilities: [0; 4],
                valid: [0; 4],
            },
            uuid: [0; DARWIN_UUID_LEN],
        },
    )
}

/// Validates one `getattrlist` answer against the device the caller
/// observed and turns its volume UUID into a Darwin token.
#[cfg(target_os = "macos")]
fn darwin_volume_token(
    rc: i32,
    answer: &DarwinVolumeAnswer,
    dev: u64,
) -> Result<ReuseToken, ReuseTokenError> {
    if rc == -1 {
        let error = io::Error::last_os_error();
        return Err(match error.raw_os_error() {
            Some(code) if REUSE_UNSUPPORTED.contains(&code) => ReuseTokenError::Unsupported,
            _ => ReuseTokenError::Io(error),
        });
    }
    if usize::try_from(answer.length).ok() != Some(DARWIN_VOLUME_ANSWER_LEN) {
        return Err(malformed_reuse_answer("volume attribute answer length"));
    }
    let returned_all = answer.returned.commonattr & ATTR_CMN_DEVID != 0
        && answer.returned.volattr & ATTR_VOL_CAPABILITIES != 0
        && answer.returned.volattr & ATTR_VOL_UUID != 0;
    let persistent_ids = answer.capabilities.valid[VOL_CAPABILITIES_FORMAT]
        & answer.capabilities.capabilities[VOL_CAPABILITIES_FORMAT]
        & VOL_CAP_FMT_PATH_FROM_ID
        != 0;
    if !returned_all || !persistent_ids {
        return Err(ReuseTokenError::Unsupported);
    }
    // std widens Darwin's signed `st_dev` the same way.
    if answer.devid as u64 != dev {
        return Err(malformed_reuse_answer(
            "volume device differs from the file",
        ));
    }
    if answer.uuid == [0; DARWIN_UUID_LEN] {
        return Err(ReuseTokenError::Unsupported);
    }
    let mut raw = [0; 1 + DARWIN_UUID_LEN];
    raw[0] = REUSE_TAG_DARWIN;
    raw[1..].copy_from_slice(&answer.uuid);
    ReuseToken::from_bytes(&raw).ok_or_else(|| malformed_reuse_answer("volume uuid token"))
}

/// Takes the reuse token of the file behind `file`: on Darwin the UUID of
/// a volume whose file ids persist, checked against the fd's own device.
/// Every call queries the kernel.
///
/// # Errors
/// [`ReuseTokenError::Unsupported`] when the volume does not return its
/// device, capabilities or UUID, lacks persistent file ids, has an
/// all-zero UUID, or answers `ENOTSUP`/`EINVAL`; [`ReuseTokenError::Io`]
/// for every other failure, a malformed answer or a device mismatch.
#[cfg(target_os = "macos")]
pub fn reuse_token(file: &std::fs::File) -> Result<ReuseToken, ReuseTokenError> {
    use std::os::unix::fs::MetadataExt as _;
    let dev = file.metadata().map_err(ReuseTokenError::Io)?.dev();
    let (mut request, mut answer) = darwin_volume_request();
    // SAFETY: the fd is live (borrowed from `file`); `request` and
    // `answer` are exclusively borrowed repr(C) buffers of the sys/attr.h
    // layout, and the size passed is exactly `answer`'s size.
    let rc = unsafe {
        fgetattrlist(
            file.as_raw_fd(),
            &raw mut request,
            &raw mut answer,
            DARWIN_VOLUME_ANSWER_LEN,
            FSOPT_PACK_INVAL_ATTRS,
        )
    };
    darwin_volume_token(rc, &answer, dev)
}

/// [`reuse_token`] for a path without following a final symlink, checked
/// against the device `dev` the caller observed for that path.
///
/// # Errors
/// As [`reuse_token`]; a path with an interior NUL is
/// [`ReuseTokenError::Io`].
#[cfg(target_os = "macos")]
pub fn reuse_token_at(path: &std::path::Path, dev: u64) -> Result<ReuseToken, ReuseTokenError> {
    use std::os::unix::ffi::OsStrExt as _;
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|source| {
        ReuseTokenError::Io(io::Error::new(io::ErrorKind::InvalidInput, source))
    })?;
    let (mut request, mut answer) = darwin_volume_request();
    // SAFETY: `c_path` is a live NUL-terminated string; `request` and
    // `answer` are exclusively borrowed repr(C) buffers of the sys/attr.h
    // layout, and the size passed is exactly `answer`'s size.
    let rc = unsafe {
        getattrlist(
            c_path.as_ptr(),
            &raw mut request,
            &raw mut answer,
            DARWIN_VOLUME_ANSWER_LEN,
            FSOPT_NOFOLLOW | FSOPT_PACK_INVAL_ATTRS,
        )
    };
    darwin_volume_token(rc, &answer, dev)
}

const F_GETFL: i32 = 3;
const F_SETFL: i32 = 4;
const SIGKILL: i32 = 9;

#[cfg(target_os = "macos")]
const O_NONBLOCK: i32 = 0x0004;
#[cfg(target_os = "linux")]
const O_NONBLOCK: i32 = 0o4000;

/// Sends `SIGKILL` to the confined child's process group. The host sets
/// the child as a group leader at spawn (`process_group(0)`), so this
/// reaps grandchildren that inherited the group — `Child::kill` cannot.
///
/// # Errors
/// Returns the OS error when the pid does not fit `pid_t` or `kill(2)`
/// fails.
pub fn kill_process_group(pid: u32) -> io::Result<()> {
    let pgid = i32::try_from(pid).map_err(|_overflow| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "confined child pid does not fit pid_t",
        )
    })?;
    // SAFETY: `pid` is the confined child's process-group leader; a
    // negative pid is the POSIX process-group form of `kill(2)`.
    let rc = unsafe { kill(-pgid, SIGKILL) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

// ---------------------------------------------------------------------------
// fd-anchored dependency traversal (DEC-042/D-122): the only sanctioned
// `unsafe` surface for `openat` — no std API opens a path relative to a
// directory fd. Everything the executor stages from the Cargo cache walks
// component by component from a pinned root fd with
// O_DIRECTORY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC, so a symlinked or swapped
// ancestor is a typed refusal, never a followed link.
// ---------------------------------------------------------------------------

/// Why an fd-anchored `openat` refused. Each cause keeps its own variant
/// so the executor retains a distinct seam per offline correction (D-124:
/// hardlink, kind, and size are separable corrections).
#[derive(Debug)]
pub enum FdOpenError {
    /// The flag/syscall combination is unsupported on this OS (EINVAL or
    /// ENOSYS): a setup refusal, never a weaker fallback.
    UnsupportedCapability { source: io::Error },
    /// A path component (or the leaf) is a symlink; O_NOFOLLOW refused it.
    SymlinkComponent,
    /// The component does not exist (ENOENT).
    Missing,
    /// The opened inode is the wrong kind for the requested open.
    WrongKind,
    /// The leaf carries more than one hard link.
    MultipleLinks,
    /// The leaf exceeds the caller's byte bound.
    Oversize,
    /// Any other OS failure, carried for `source()`.
    Io { source: io::Error },
}

impl std::fmt::Display for FdOpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedCapability { source } => {
                write!(f, "fd-anchored open capability unsupported: {source}")
            }
            Self::SymlinkComponent => write!(f, "a path component is a symlink"),
            Self::Missing => write!(f, "a path component is missing"),
            Self::WrongKind => write!(f, "the opened inode has the wrong kind"),
            Self::MultipleLinks => write!(f, "the leaf carries multiple hard links"),
            Self::Oversize => write!(f, "the leaf exceeds the declared byte bound"),
            Self::Io { source } => write!(f, "fd-anchored open failed: {source}"),
        }
    }
}

impl std::error::Error for FdOpenError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::UnsupportedCapability { source } | Self::Io { source } => Some(source),
            _ => None,
        }
    }
}

// `openat(2)` — present on macOS and Linux with the same ABI; the mode
// argument is unused without O_CREAT and stays out of the declaration.
#[allow(
    unsafe_code,
    reason = "the crate's sanctioned syscall surface (DEC-009)"
)]
unsafe extern "C" {
    unsafe fn openat(dirfd: i32, pathname: *const std::os::raw::c_char, oflag: i32) -> i32;
    unsafe fn fstatat(
        dirfd: i32,
        pathname: *const std::os::raw::c_char,
        buf: *mut StatProbe,
        flag: i32,
    ) -> i32;
}

/// `O_DIRECTORY` per platform (Darwin fcntl.h: 0x100000; Linux x86_64
/// 0o200000; the asm-generic layout every other Linux arch uses, arm64
/// included, 0o40000 — a mismatched bit names another flag and lets a
/// non-directory open through).
#[cfg(target_os = "macos")]
const O_DIRECTORY: i32 = 0x100000;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const O_DIRECTORY: i32 = 0o200_000;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const O_DIRECTORY: i32 = 0o40_000;

/// `O_CLOEXEC` per platform (Darwin: 0x01000000; Linux: 0o2000000).
#[cfg(target_os = "macos")]
const O_CLOEXEC: i32 = 0x0100_0000;
#[cfg(target_os = "linux")]
const O_CLOEXEC: i32 = 0o2000000;

/// `O_NOFOLLOW` mirrors the per-architecture values the binary pins in
/// `main.rs` (Darwin 0x0100; Linux x86_64 0o400000, asm-generic/aarch64
/// 0o100000) — a mismatched bit names another flag and follows links.
/// Exposed `pub` so the executor's checked opens share the one verified
/// ABI constant instead of a second copy.
#[cfg(target_os = "macos")]
pub const ANCHOR_O_NOFOLLOW: i32 = 0x0100;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub const ANCHOR_O_NOFOLLOW: i32 = 0o400_000;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub const ANCHOR_O_NOFOLLOW: i32 = 0o100_000;
/// `O_NONBLOCK` for the executor's checked regular-file opens: a FIFO
/// swapped onto a path between metadata and open returns immediately
/// instead of blocking the caller forever. Regular files ignore it.
#[cfg(target_os = "macos")]
pub const OPEN_NONBLOCK: i32 = 0x0004;
#[cfg(target_os = "linux")]
pub const OPEN_NONBLOCK: i32 = 0o4000;

/// Any other Linux architecture fails the build rather than guessing an
/// ABI bit (an `O_NOFOLLOW` mismatch names another flag's bit and silently
/// follows links).
#[cfg(all(
    target_os = "linux",
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
))]
const ANCHOR_O_NOFOLLOW: i32 =
    compile_error!("unsupported linux architecture for fd-anchored opens") as i32;

/// `O_RDONLY` is 0 on both platforms.
const O_RDONLY: i32 = 0;

/// Darwin errno values the typed mapping needs (ELOOP differs from Linux).
#[cfg(target_os = "macos")]
const ELOOP: i32 = 62;
#[cfg(target_os = "linux")]
const ELOOP: i32 = 40;
/// errno values Darwin and Linux agree on.
const ENOENT: i32 = 2;
const ENOTDIR: i32 = 20;
const EISDIR: i32 = 21;
const EINVAL: i32 = 22;
const ENOSYS: i32 = 38;

/// `AT_SYMLINK_NOFOLLOW` for the refusal classifier (fcntl.h: Linux
/// 0x100, Darwin 0x0020).
#[cfg(target_os = "linux")]
const AT_SYMLINK_NOFOLLOW: i32 = 0x100;
#[cfg(target_os = "macos")]
const AT_SYMLINK_NOFOLLOW: i32 = 0x0020;

/// `st_mode` file-type mask and symlink value (stat.h, common to both
/// platforms).
const S_IFMT: u32 = 0o170_000;
const S_IFLNK: u32 = 0o120_000;

/// `fstatat` probe: a byte buffer larger than every `struct stat` ABI
/// the supported targets define (Linux x86_64 144, aarch64 128, Darwin
/// 144), 8-aligned so every ABI field lands aligned.
#[repr(C, align(8))]
struct StatProbe([u8; 256]);

/// Byte offset of `st_mode` in `struct stat`: Linux x86_64 after
/// st_dev/st_ino/st_nlink, aarch64 (asm-generic) after st_dev/st_ino,
/// Darwin after st_dev (mode_t precedes ino_t there). The whole mode
/// fits 16 bits and the supported targets are little-endian, so the
/// first two bytes carry it.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const ST_MODE_OFFSET: usize = 24;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const ST_MODE_OFFSET: usize = 16;
#[cfg(target_os = "macos")]
const ST_MODE_OFFSET: usize = 4;
/// Identity of one opened inode, read through the fd itself (`fstat` via
/// std): the executor compares a fresh walk's lineage against the pinned
/// one before every dependency byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FdIdentity {
    pub dev: u64,
    pub ino: u64,
    pub nlink: u64,
    /// True for a directory inode.
    pub directory: bool,
    /// True for a regular-file inode.
    pub regular: bool,
    pub size: u64,
}

/// A directory fd pinned by the anchored walk. The fd is close-on-exec and
/// nonblocking; the identity is the snapshot taken at open time.
#[derive(Debug)]
pub struct AnchoredDir {
    pub fd: std::os::fd::OwnedFd,
    pub identity: FdIdentity,
}

/// A regular leaf fd opened relative to a pinned directory with
/// `O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC`, single-link and within the byte
/// bound at open time.
#[derive(Debug)]
pub struct AnchoredLeaf {
    pub file: std::fs::File,
    pub identity: FdIdentity,
}

fn fd_identity_of(file: &std::fs::File) -> Result<FdIdentity, FdOpenError> {
    use std::os::unix::fs::MetadataExt as _;
    let meta = file
        .metadata()
        .map_err(|source| FdOpenError::Io { source })?;
    Ok(FdIdentity {
        dev: meta.dev(),
        ino: meta.ino(),
        nlink: meta.nlink(),
        directory: meta.is_dir(),
        regular: meta.is_file(),
        size: meta.len(),
    })
}

impl FdIdentity {
    /// Whether two pinned identities name the same directory inode. A
    /// directory's `nlink` and `size` move with benign host activity
    /// (sibling temp trees appearing under a shared parent), and
    /// directories cannot be hardlinked, so the lineage comparison keys
    /// on the device/inode pair and the directory kind alone. Leaf
    /// identities keep the full field set — `nlink` is the hardlink
    /// discriminator there.
    #[must_use]
    pub fn same_directory_inode(&self, other: &Self) -> bool {
        self.dev == other.dev && self.ino == other.ino && self.directory
    }
}

/// Maps one `openat` failure to its typed cause: ELOOP names the symlink
/// O_NOFOLLOW refused, ENOENT the missing component, ENOTDIR/EISDIR a kind
/// mismatch, and EINVAL/ENOSYS an unsupported flag combination.
fn fd_open_error(error: io::Error) -> FdOpenError {
    match error.raw_os_error() {
        Some(ELOOP) => FdOpenError::SymlinkComponent,
        Some(ENOENT) => FdOpenError::Missing,
        Some(ENOTDIR) | Some(EISDIR) => FdOpenError::WrongKind,
        Some(EINVAL) | Some(ENOSYS) => FdOpenError::UnsupportedCapability { source: error },
        _ => FdOpenError::Io { source: error },
    }
}

/// Classifies a refused `openat(O_DIRECTORY|O_NOFOLLOW)` component open.
/// errno alone is not portable: Linux overlayfs answers ENOTDIR — not
/// ELOOP — when O_NOFOLLOW refuses a symlinked component, so the
/// ambiguous ENOTDIR refusal is settled by stat'ing the component with
/// `AT_SYMLINK_NOFOLLOW`: a symlink names the symlink seam, anything
/// else keeps the errno mapping.
fn classify_directory_refusal(
    parent: &AnchoredDir,
    component: &std::ffi::CString,
    error: io::Error,
) -> FdOpenError {
    if error.raw_os_error() == Some(ENOTDIR) {
        let mut probe = StatProbe([0_u8; 256]);
        // SAFETY: `component` is a NUL-terminated borrowed buffer; the
        // parent fd is a borrowed live directory fd; `probe` is a valid
        // 8-aligned 256-byte buffer larger than every supported
        // `struct stat` ABI, so the kernel write stays in bounds.
        let stated = unsafe {
            fstatat(
                parent.fd.as_raw_fd(),
                component.as_ptr(),
                &mut probe,
                AT_SYMLINK_NOFOLLOW,
            )
        };
        if stated == 0 {
            let mode =
                u32::from(probe.0[ST_MODE_OFFSET]) | u32::from(probe.0[ST_MODE_OFFSET + 1]) << 8;
            if mode & S_IFMT == S_IFLNK {
                return FdOpenError::SymlinkComponent;
            }
        }
    }
    fd_open_error(error)
}

/// `AT_FDCWD` — the root open addresses an absolute path.
const AT_FDCWD: i32 = -100;

/// Opens the filesystem root (`/`) as the anchor of every dependency walk:
/// after this open the walk never resolves a dependency path by pathname.
///
/// # Errors
/// Returns [`FdOpenError::UnsupportedCapability`] when the platform
/// refuses the flag set, and the typed OS causes otherwise.
pub fn open_filesystem_root() -> Result<AnchoredDir, FdOpenError> {
    let path = std::ffi::CString::new("/").map_err(|_interior| FdOpenError::WrongKind)?;
    // SAFETY: `path` is a NUL-terminated owned buffer valid for the call;
    // openat with AT_FDCWD resolves the absolute path and either returns a
    // fresh descriptor or -1 with errno set.
    let opened = unsafe {
        openat(
            AT_FDCWD,
            path.as_ptr(),
            O_RDONLY | O_DIRECTORY | ANCHOR_O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC,
        )
    };
    anchored_dir_from(opened)
}

/// Opens one directory component relative to a pinned parent fd, refusing
/// `.`/`..`/empty components lexically before any syscall.
///
/// # Errors
/// Returns [`FdOpenError::SymlinkComponent`] for a symlinked component,
/// [`FdOpenError::Missing`], [`FdOpenError::WrongKind`], the capability
/// refusal, or the OS failure.
pub fn openat_directory(
    parent: &AnchoredDir,
    component: &[u8],
) -> Result<AnchoredDir, FdOpenError> {
    if component.is_empty() || component == b"." || component == b".." {
        return Err(FdOpenError::WrongKind);
    }
    // A `/` byte turns the component into a pathname `openat` would
    // resolve relative to the parent fd — `a/../b` walks out of the
    // anchored directory. Components are single names, never paths.
    if component.contains(&b'/') {
        return Err(FdOpenError::WrongKind);
    }
    let path = std::ffi::CString::new(component).map_err(|_interior| FdOpenError::WrongKind)?;
    // SAFETY: `path` is a NUL-terminated owned buffer; the parent fd is a
    // borrowed live directory fd. openat returns a fresh descriptor or -1.
    let opened = unsafe {
        openat(
            parent.fd.as_raw_fd(),
            path.as_ptr(),
            O_RDONLY | O_DIRECTORY | ANCHOR_O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC,
        )
    };
    if opened < 0 {
        return Err(classify_directory_refusal(
            parent,
            &path,
            io::Error::last_os_error(),
        ));
    }
    anchored_dir_from(opened)
}

fn anchored_dir_from(opened: i32) -> Result<AnchoredDir, FdOpenError> {
    if opened < 0 {
        return Err(fd_open_error(io::Error::last_os_error()));
    }
    // SAFETY: `opened` is a fresh descriptor this call just returned and
    // no other owner exists for it.
    let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(opened) };
    let probe = std::fs::File::from(
        fd.try_clone()
            .map_err(|source| FdOpenError::Io { source })?,
    );
    let identity = fd_identity_of(&probe)?;
    drop(probe);
    if !identity.directory {
        return Err(FdOpenError::WrongKind);
    }
    Ok(AnchoredDir { fd, identity })
}

/// Opens one regular leaf relative to a pinned directory fd with
/// `O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC`, requiring a single-link inode within
/// `max_bytes`. The bound checks run on the opened fd itself.
///
/// # Errors
/// Returns the typed causes of [`FdOpenError`]; `MultipleLinks` and
/// `Oversize` are leaf-only refusals with distinct corrections (D-124).
pub fn openat_leaf(
    parent: &AnchoredDir,
    name: &[u8],
    max_bytes: u64,
) -> Result<AnchoredLeaf, FdOpenError> {
    if name.is_empty() || name == b"." || name == b".." {
        return Err(FdOpenError::WrongKind);
    }
    // Same lexical path refusal as the directory walk: a leaf name with
    // a `/` byte (e.g. `a/../b` from a hostile lockfile) would address
    // an inode outside the anchored parent.
    if name.contains(&b'/') {
        return Err(FdOpenError::WrongKind);
    }
    let path = std::ffi::CString::new(name).map_err(|_interior| FdOpenError::WrongKind)?;
    // SAFETY: `path` is a NUL-terminated owned buffer; the parent fd is a
    // borrowed live directory fd. openat returns a fresh descriptor or -1.
    let opened = unsafe {
        openat(
            parent.fd.as_raw_fd(),
            path.as_ptr(),
            O_RDONLY | ANCHOR_O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC,
        )
    };
    if opened < 0 {
        return Err(fd_open_error(io::Error::last_os_error()));
    }
    // SAFETY: `opened` is a fresh descriptor this call just returned and
    // no other owner exists for it.
    let file = std::fs::File::from(unsafe { std::os::fd::OwnedFd::from_raw_fd(opened) });
    let identity = fd_identity_of(&file)?;
    if !identity.regular {
        return Err(FdOpenError::WrongKind);
    }
    if identity.nlink > 1 {
        return Err(FdOpenError::MultipleLinks);
    }
    if identity.size > max_bytes {
        return Err(FdOpenError::Oversize);
    }
    Ok(AnchoredLeaf { file, identity })
}

/// The only `launch` option accepted before `--`: caps the launched
/// program's memory at a byte budget (`launch --memory-budget <bytes> -- …`).
pub const MEMORY_BUDGET_FLAG: &str = "--memory-budget";

/// The largest `--memory-budget` value `launch` accepts, in bytes (DEC-032).
pub const INDEX_WORKER_MEMORY_BUDGET: u64 = 512 * 1024 * 1024;

/// The `launch` option that selects the check resource profile (DEC-040):
/// finite per-process limits sized to host one isolated Cargo check.
/// Mutually exclusive with [`MEMORY_PROFILE_FLAG`][MEMORY_BUDGET_FLAG]; a
/// launch may carry at most one of the two.
pub const RESOURCE_PROFILE_FLAG: &str = "--resource-profile";

/// The only `--resource-profile` value: the isolated-check ceilings.
pub const RESOURCE_PROFILE_CHECK: &str = "check";

// The check-profile constants (DEC-040): each is the measured peak of the
// benign offline Cargo fixture times four, held inside its approved
// ceiling — CPU 300 s, FSIZE 512 MiB per file, NOFILE 4096, NPROC headroom
// 256, sampled group RSS 4 GiB, Linux AS 8 GiB per process. A benign
// fixture that outgrows one of these is a human decision, never a quiet
// constant bump.

/// Check-profile hard CPU seconds per process (ceiling 300).
pub const CHECK_CPU_SECONDS: u64 = 120;
/// Check-profile hard per-file byte cap (ceiling 512 MiB).
pub const CHECK_FSIZE_BYTES: u64 = 512 * 1024 * 1024;
/// Check-profile hard fd cap per process (ceiling 4096).
pub const CHECK_NOFILE: u64 = 4096;
/// Headroom the check profile adds to the measured same-uid process count
/// for its NPROC (ceiling 256) — fixed 64 would count a busy host's own
/// processes against Cargo.
pub const CHECK_NPROC_HEADROOM: u64 = 256;
/// The sampled group-RSS ceiling the parent enforces while a check runs
/// (4 GiB). Advisory observation, never a hard per-process limit: on
/// macOS a `setsid` child escapes group accounting (DEC-041).
pub const CHECK_GROUP_RSS_BYTES: u64 = 4 * 1024 * 1024 * 1024;
/// Check-profile hard address-space bytes per process (ceiling 8 GiB).
/// Linux only: Darwin rejects an absolute cap below its baseline map.
#[cfg(target_os = "linux")]
pub const CHECK_AS_BYTES: u64 = 8 * 1024 * 1024 * 1024;

/// The platform `struct rlimit`: two `u64` words on every supported target.
/// Shared with the helper binary's `setrlimit` so the layout has one home.
#[doc(hidden)]
#[repr(C)]
pub struct Rlimit {
    pub rlim_cur: u64,
    pub rlim_max: u64,
}

/// `RLIMIT_DATA`: the same id on macOS and Linux.
#[doc(hidden)]
pub const RLIMIT_DATA: i32 = 2;
/// `RLIMIT_AS`: the platform resource id.
#[doc(hidden)]
#[cfg(target_os = "macos")]
pub const RLIMIT_AS: i32 = 5;
#[cfg(target_os = "macos")]
const RLIM_INFINITY: u64 = (1 << 63) - 1;
/// `RLIMIT_AS`: the platform resource id.
#[doc(hidden)]
#[cfg(target_os = "linux")]
pub const RLIMIT_AS: i32 = 9;
#[cfg(target_os = "linux")]
const RLIM_INFINITY: u64 = u64::MAX;

/// The smaller finite soft limit of `RLIMIT_AS` and `RLIMIT_DATA`, in bytes;
/// `None` when both are unlimited. A capped launch sets both on macOS and
/// only the address space on Linux, so the minimum is the binding cap.
///
/// # Errors
/// Returns the OS error when `getrlimit` fails.
pub fn memory_limit() -> io::Result<Option<u64>> {
    let address_space = soft_limit(RLIMIT_AS)?;
    let data = soft_limit(RLIMIT_DATA)?;
    Ok(address_space.into_iter().chain(data).min())
}

fn soft_limit(resource: i32) -> io::Result<Option<u64>> {
    let mut limit = Rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is a live, writable repr(C) `struct rlimit` and
    // `resource` is a documented platform RLIMIT id; getrlimit only writes
    // those two words.
    if unsafe { getrlimit(resource, &mut limit) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((limit.rlim_cur < RLIM_INFINITY).then_some(limit.rlim_cur))
}

/// SDK `<mach/task_info.h>` `struct mach_task_basic_info`, declared under
/// `#pragma pack(4)`: three `mach_vm_size_t`, two `time_value_t`
/// (`integer_t` seconds + microseconds), `policy_t`, `integer_t`.
#[cfg(target_os = "macos")]
#[repr(C, packed(4))]
struct MachTaskBasicInfo {
    virtual_size: u64,
    _resident_size: u64,
    _resident_size_max: u64,
    _user_time: [i32; 2],
    _system_time: [i32; 2],
    _policy: i32,
    _suspend_count: i32,
}

#[cfg(target_os = "macos")]
const _: () = assert!(size_of::<MachTaskBasicInfo>() == 48);

#[cfg(target_os = "macos")]
const MACH_TASK_BASIC_INFO: u32 = 20;
/// `MACH_TASK_BASIC_INFO_COUNT`: the struct size in `natural_t` words.
#[cfg(target_os = "macos")]
const MACH_TASK_BASIC_INFO_COUNT: u32 = 12;
#[cfg(target_os = "macos")]
const KERN_SUCCESS: i32 = 0;

/// This process's current virtual map size in bytes (`task_info`
/// `MACH_TASK_BASIC_INFO` `virtual_size`). Darwin rejects an absolute
/// `RLIMIT_AS`/`RLIMIT_DATA` below its multi-hundred-GiB baseline map, so a
/// macOS memory cap is only expressible relative to this measurement.
///
/// # Errors
/// Returns an error naming the `kern_return_t` when `task_info` fails or
/// answers with a short structure.
#[cfg(target_os = "macos")]
pub fn current_map_size() -> io::Result<u64> {
    let mut info = MachTaskBasicInfo {
        virtual_size: 0,
        _resident_size: 0,
        _resident_size_max: 0,
        _user_time: [0; 2],
        _system_time: [0; 2],
        _policy: 0,
        _suspend_count: 0,
    };
    let mut count = MACH_TASK_BASIC_INFO_COUNT;
    // SAFETY: `mach_task_self_` is libSystem's process-constant task port,
    // initialised before `main`; `info` is a live 48-byte buffer matching
    // the SDK layout, and `count` tells the kernel its size in words, so
    // task_info writes at most that many words.
    let status = unsafe {
        task_info(
            mach_task_self_,
            MACH_TASK_BASIC_INFO,
            (&raw mut info).cast::<i32>(),
            &mut count,
        )
    };
    if status != KERN_SUCCESS {
        return Err(io::Error::other(format!(
            "task_info failed with kern_return {status}"
        )));
    }
    if count != MACH_TASK_BASIC_INFO_COUNT {
        return Err(io::Error::other(format!(
            "task_info returned {count} words instead of {MACH_TASK_BASIC_INFO_COUNT}"
        )));
    }
    Ok(info.virtual_size)
}

/// SDK `<sys/resource.h>` `struct rusage_info_v4`, natural alignment (no
/// `#pragma pack`): a 16-byte uuid, then 35 `uint64_t` counters of which
/// `ri_resident_size` is the seventh and `ri_phys_footprint` the eighth.
#[cfg(target_os = "macos")]
#[repr(C)]
struct RusageInfoV4 {
    _uuid: [u8; 16],
    /// `ri_user_time` through `ri_wired_size`.
    _leading: [u64; 6],
    resident_size: u64,
    phys_footprint: u64,
    /// `ri_proc_start_abstime` through `ri_runnable_time`.
    _trailing: [u64; 27],
}

#[cfg(target_os = "macos")]
const _: () = assert!(size_of::<RusageInfoV4>() == 296);
#[cfg(target_os = "macos")]
const _: () = assert!(std::mem::offset_of!(RusageInfoV4, resident_size) == 64);
#[cfg(target_os = "macos")]
const _: () = assert!(std::mem::offset_of!(RusageInfoV4, phys_footprint) == 72);

#[cfg(target_os = "macos")]
const RUSAGE_INFO_V4: i32 = 4;

/// Reads process `pid`'s `rusage_info_v4` through `proc_pid_rusage`.
///
/// # Errors
/// Returns `InvalidInput` when `pid` does not fit `pid_t`, and the OS
/// error (`ESRCH`, `EPERM`) when `proc_pid_rusage` fails — a reaped pid
/// fails, since it may already name another process.
#[cfg(target_os = "macos")]
fn proc_rusage_v4(pid: u32) -> io::Result<RusageInfoV4> {
    let pid = i32::try_from(pid).map_err(|_overflow| {
        io::Error::new(io::ErrorKind::InvalidInput, "pid does not fit pid_t")
    })?;
    let mut info = RusageInfoV4 {
        _uuid: [0; 16],
        _leading: [0; 6],
        resident_size: 0,
        phys_footprint: 0,
        _trailing: [0; 27],
    };
    // SAFETY: `info` is a live, writable 296-byte buffer with the SDK
    // `rusage_info_v4` layout (size and counter offsets asserted above).
    // The header types the argument `rusage_info_t *` (`void **`), yet the
    // call writes the flavor's struct at that address, so the buffer
    // itself is passed; RUSAGE_INFO_V4 bounds the write to that struct.
    if unsafe { proc_pid_rusage(pid, RUSAGE_INFO_V4, &raw mut info) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(info)
}

/// Process `pid`'s physical footprint in bytes (`proc_pid_rusage`
/// `RUSAGE_INFO_V4` `ri_phys_footprint`) — it counts the small heap
/// allocations a relative `RLIMIT_AS`/`RLIMIT_DATA` cap lets through. A
/// live child reads its footprint and an exited, unreaped one reads zero;
/// a reaped pid fails, since it may already name another process.
///
/// # Errors
/// Returns `InvalidInput` when `pid` does not fit `pid_t`, and the OS
/// error (`ESRCH`, `EPERM`) when `proc_pid_rusage` fails.
#[cfg(target_os = "macos")]
pub fn phys_footprint(pid: u32) -> io::Result<u64> {
    Ok(proc_rusage_v4(pid)?.phys_footprint)
}

/// Process `pid`'s resident set in bytes (`ri_resident_size` on macOS,
/// `/proc/<pid>/statm` resident pages on Linux) — the parent samples this
/// across a confined group as an advisory aggregate, never a hard bound.
/// A live child reads its residency, an exited unreaped one reads zero,
/// and a reaped pid fails, since it may already name another process.
///
/// # Errors
/// Returns [`ProcessReadError::ReadFailed`] naming `pid` when the read
/// fails — on macOS when the pid does not fit `pid_t` or
/// `proc_pid_rusage` answers an OS error, on Linux when the statm read
/// fails — and [`ProcessReadError::MalformedRecord`] when the record is
/// missing or does not parse into a byte count.
#[cfg(target_os = "macos")]
pub fn resident_bytes(pid: u32) -> Result<u64, ProcessReadError> {
    proc_rusage_v4(pid)
        .map(|rusage| rusage.resident_size)
        .map_err(|source| ProcessReadError::ReadFailed { pid, source })
}

/// Process `pid`'s resident set in bytes, from `/proc/<pid>/statm`'s
/// resident field. Sampling this across a confined group is advisory,
/// never a hard bound; a reaped pid has no `/proc` entry and fails.
///
/// # Errors
/// Returns [`ProcessReadError::ReadFailed`] when the statm read fails
/// and [`ProcessReadError::MalformedRecord`] when the record is missing,
/// its resident field is not decimal, or its byte count overflows.
#[cfg(target_os = "linux")]
pub fn resident_bytes(pid: u32) -> Result<u64, ProcessReadError> {
    let statm = std::fs::read_to_string(proc_root().join(pid.to_string()).join("statm"))
        .map_err(|error| ProcessReadError::ReadFailed { pid, source: error })?;
    // statm: size resident shared text lib data dt, all in pages.
    let Some(resident_pages) = statm.split_whitespace().nth(1) else {
        return Err(ProcessReadError::MalformedRecord { pid });
    };
    let resident_pages: u64 = resident_pages
        .parse()
        .map_err(|_parse| ProcessReadError::MalformedRecord { pid })?;
    // SAFETY: getpagesize takes no arguments and returns the page size.
    let page = u64::try_from(unsafe { getpagesize() })
        .map_err(|_negative| ProcessReadError::MalformedRecord { pid })?;
    resident_pages
        .checked_mul(page)
        .ok_or(ProcessReadError::MalformedRecord { pid })
}

/// The owner enum of the process-read surface — `uid_process_count`,
/// `process_group_members`, `resident_bytes`: callers and tests branch
/// on variant identity, never on prose (P-001).
#[derive(Debug)]
pub enum ProcessReadError {
    /// The host holds more processes than the bounded scan admits: the
    /// counts feed hard NPROC decisions, so an unmeasurable host is a
    /// typed refusal, never a truncated guess.
    ScanCapExceeded,
    /// Process `pid`'s record exists but does not parse.
    MalformedRecord { pid: u32 },
    /// The record read of process `pid` failed with an OS error; the
    /// pid stays typed on the refusal so a caller deciding whether a
    /// live process was omitted never mistakes it for an enumeration
    /// failure that belongs to no pid in particular.
    ReadFailed { pid: u32, source: io::Error },
    /// An enumeration-level I/O failure no single pid owns — including
    /// the enumeration call itself failing, on Darwin a nonpositive
    /// `proc_listallpids` return (Seatbelt's process-info denial
    /// answers zero with EPERM set), and on Linux a `/proc` walk that
    /// lists no process at all (an empty or unusable mount: the caller
    /// itself is a process, so a live host's table is never empty).
    Io(io::Error),
}

impl std::fmt::Display for ProcessReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ScanCapExceeded => {
                write!(f, "process enumeration exceeded the scan cap")
            }
            Self::MalformedRecord { pid } => write!(f, "process record {pid} is malformed"),
            Self::ReadFailed { pid, .. } => write!(f, "reading process record {pid} failed"),
            // Owner text only: the OS prose lives in `source()`, never in
            // a Display a caller might surface verbatim.
            Self::Io(_) => write!(f, "process enumeration io failed"),
        }
    }
}

impl std::error::Error for ProcessReadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ReadFailed { source, .. } => Some(source),
            Self::Io(source) => Some(source),
            Self::ScanCapExceeded | Self::MalformedRecord { .. } => None,
        }
    }
}

impl From<io::Error> for ProcessReadError {
    fn from(source: io::Error) -> Self {
        Self::Io(source)
    }
}

/// The current NPROC charge under this process's real uid: Linux counts
/// tasks because RLIMIT_NPROC charges every thread; macOS counts processes.
/// This is the measured base the check profile adds its NPROC headroom to;
/// a fixed value would count a busy host's own tasks against Cargo.
/// The count is bounded: a host past the scan cap reads as unmeasurable
/// instead of looping a fork bomb.
///
/// # Errors
/// Returns [`ProcessReadError::ScanCapExceeded`] when the host outgrows
/// the bounded scan, [`ProcessReadError::Io`] when the enumeration call
/// itself fails or enumerates no process at all, and a pid-carrying
/// variant when a live process's record cannot be read or parsed.
pub fn uid_process_count() -> Result<u64, ProcessReadError> {
    uid_count_platform()
}

/// The pids currently in process group `pgid` — the parent's kill and
/// sampled-aggregate surface for a confined chain whose leader was
/// spawned with `process_group(0)`. A descendant that calls `setsid`
/// escapes the listing on macOS and Linux alike (DEC-041): group
/// membership is current, not ancestral, so the group kill — and any
/// RSS aggregate sampled over this listing — stays advisory against a
/// session-escaping descendant. The listing is bounded like the uid
/// count.
///
/// # Errors
/// Returns [`ProcessReadError::ScanCapExceeded`] when the host outgrows
/// the bounded scan, [`ProcessReadError::Io`] when the enumeration call
/// itself fails or enumerates no process at all, and a pid-carrying
/// variant when a live process's record cannot be read or parsed.
pub fn process_group_members(pgid: u32) -> Result<Vec<u32>, ProcessReadError> {
    group_members_platform(pgid)
}

/// Enumeration refuses hosts past this many live processes: the reads
/// feed hard NPROC decisions, so an unmeasurable host is a typed refusal,
/// never a truncated guess.
#[cfg(target_os = "macos")]
const PROCESS_SCAN_CAP: i32 = 1 << 16;
#[cfg(target_os = "linux")]
const PROCESS_SCAN_CAP: usize = 1 << 16;

// The fixture `/proc` root and scan cap this thread's tests planted:
// the consumer-level seam — unit tests drive the PUBLIC count, listing,
// and resident surfaces over controlled records instead of asserting
// on private helpers.
#[cfg(target_os = "linux")]
#[cfg(test)]
thread_local! {
    static PROC_ROOT_OVERRIDE: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
    static SCAN_CAP_OVERRIDE: std::cell::Cell<usize> = const {
        std::cell::Cell::new(PROCESS_SCAN_CAP)
    };
}

/// The process-table root this thread reads: the real `/proc`, or the
/// fixture root a test planted.
#[cfg(target_os = "linux")]
fn proc_root() -> PathBuf {
    #[cfg(test)]
    {
        PROC_ROOT_OVERRIDE.with(|root| {
            root.borrow()
                .clone()
                .unwrap_or_else(|| PathBuf::from("/proc"))
        })
    }
    // The production root is fixed; only a test thread can override it.
    #[cfg(not(test))]
    {
        PathBuf::from("/proc")
    }
}

/// The scan bound this thread honors: the fixed cap, or the smaller cap
/// a test planted.
#[cfg(target_os = "linux")]
fn scan_cap() -> usize {
    #[cfg(test)]
    let cap = SCAN_CAP_OVERRIDE.with(|cap| cap.get());
    #[cfg(not(test))]
    let cap: usize = PROCESS_SCAN_CAP;
    cap
}

// The scripted listing and fallback-record answers this thread's tests
// planted: the consumer-level seam — Darwin unit tests drive the PUBLIC
// count and listing surfaces through controlled listing/kinfo outcomes
// instead of asserting on private helpers or the host's live process
// table (the Linux twin plants a fixture proc root for the same
// purpose).
#[cfg(target_os = "macos")]
#[cfg(test)]
type ScriptedListing = Box<dyn Fn(&mut [i32]) -> i32>;

/// The scripted fallback-record answer the same seam plants.
#[cfg(target_os = "macos")]
#[cfg(test)]
type ScriptedKinfo = Box<dyn Fn(&mut usize) -> i32>;

#[cfg(target_os = "macos")]
#[cfg(test)]
thread_local! {
    static SCRIPTED_LISTING: RefCell<Option<ScriptedListing>> =
        const { RefCell::new(None) };
    static SCRIPTED_KINFO: RefCell<Option<ScriptedKinfo>> =
        const { RefCell::new(None) };
}

/// Sets this thread's errno so the captured `source()` answers a
/// scripted failure verbatim.
#[cfg(target_os = "macos")]
#[cfg(test)]
fn set_errno(errno: i32) {
    // SAFETY: `__error` names this thread's errno slot; one i32 store,
    // the same slot a failed libc call writes.
    unsafe {
        *__error() = errno;
    }
}

#[cfg(target_os = "macos")]
#[cfg(test)]
unsafe extern "C" {
    fn __error() -> *mut i32;
}

/// SDK `<sys/proc_info.h>` `struct proc_bsdinfo`, natural alignment: the
/// `pbi_*` uint32 prefix (uid_t/gid_t are uint32_t), `pbi_comm[16]` and
/// `pbi_name[32]`, the uint32 tail, then two uint64 timestamps.
#[cfg(target_os = "macos")]
#[repr(C)]
struct ProcBsdInfo {
    _flags: u32,
    _status: u32,
    _xstatus: u32,
    _pid: u32,
    _ppid: u32,
    _uid: u32,
    _gid: u32,
    ruid: u32,
    _rgid: u32,
    _svuid: u32,
    _svgid: u32,
    _reserved: u32,
    _comm: [u8; 16],
    _name: [u8; 32],
    _nfiles: u32,
    pgid: u32,
    _pjobc: u32,
    _e_tdev: u32,
    _e_tpgid: u32,
    _nice: i32,
    _start_tvsec: u64,
    _start_tvusec: u64,
}

#[cfg(target_os = "macos")]
const _: () = assert!(size_of::<ProcBsdInfo>() == 136);
#[cfg(target_os = "macos")]
const _: () = assert!(std::mem::offset_of!(ProcBsdInfo, ruid) == 28);
#[cfg(target_os = "macos")]
const _: () = assert!(std::mem::offset_of!(ProcBsdInfo, pgid) == 100);

/// `proc_pidinfo` flavor `PROC_PIDTBSDINFO`.
#[cfg(target_os = "macos")]
const PROC_PIDTBSDINFO: i32 = 3;

/// SDK `<sys/sysctl.h>` `struct kinfo_proc`: the userland ABI `ps`
/// reads through `sysctl(KERN_PROC_PID)`, which answers for every host
/// pid without the privilege `proc_pidinfo` demands for other owners'
/// processes. Only the two fields the enumeration fallback consumes are
/// named; the gaps are padding, and the size and offsets are asserted
/// to the ABI layout so a drift fails to compile.
#[cfg(target_os = "macos")]
#[repr(C)]
struct KinfoProc {
    /// `kp_proc` through `kp_eproc.e_pcred.p_svuid`.
    _head: [u8; 392],
    /// `kp_eproc.e_pcred.p_ruid` — NPROC is charged per real uid.
    ruid: u32,
    /// `p_rgid` through `kp_eproc.e_ppid`.
    _mid: [u8; 168],
    /// `kp_eproc.e_pgid`.
    pgid: u32,
    _tail: [u8; 80],
}

/// `size_of::<KinfoProc>()`, usable as a `match` pattern arm.
#[cfg(target_os = "macos")]
const KINFO_PROC_SIZE: usize = size_of::<KinfoProc>();
#[cfg(target_os = "macos")]
const _: () = assert!(KINFO_PROC_SIZE == 648);
#[cfg(target_os = "macos")]
const _: () = assert!(std::mem::offset_of!(KinfoProc, ruid) == 392);
#[cfg(target_os = "macos")]
const _: () = assert!(std::mem::offset_of!(KinfoProc, pgid) == 564);

/// `sysctl` mib: `CTL_KERN`, `KERN_PROC`, `KERN_PROC_PID`.
#[cfg(target_os = "macos")]
const CTL_KERN: i32 = 1;
#[cfg(target_os = "macos")]
const KERN_PROC: i32 = 14;
#[cfg(target_os = "macos")]
const KERN_PROC_PID: i32 = 1;

/// One enumerated process: its pid, owning real uid, and process group.
#[cfg(target_os = "macos")]
#[derive(Debug, PartialEq)]
struct ProcessEntry {
    pid: u32,
    uid: u32,
    pgid: u32,
}

/// `proc_listallpids` behind this thread's test seam: the real listing,
/// or the scripted answer a unit test planted so the public count and
/// listing surfaces can be driven through controlled listing outcomes.
#[cfg(target_os = "macos")]
fn list_all_pids(pids: &mut [i32]) -> i32 {
    #[cfg(test)]
    {
        let scripted = SCRIPTED_LISTING.with(|slot| slot.borrow().as_ref().map(|f| f(pids)));
        if let Some(answer) = scripted {
            return answer;
        }
    }
    // SAFETY: `pids` is a live, writable buffer of `pids.len()` pid_t
    // entries; the byte-size argument bounds the kernel's write to
    // exactly that span, and the return is the pid count that fit.
    unsafe { proc_listallpids(pids.as_mut_ptr(), pid_buffer_bytes(pids.len() as i32)) }
}

/// Enumerates every process with its real uid and pgid through
/// `proc_listallpids` and `PROC_PIDTBSDINFO`. The listing's `buffersize`
/// argument is a BYTE capacity, while the return is a pid COUNT: a
/// buffer reported exactly full may be truncated, so the loop grows it
/// (bounded by the scan cap) and re-lists rather than returning a
/// partial host. A pid whose info read fails falls back to its kinfo
/// record: a pid that exited between the list and its read holds no
/// record, so it contributes nothing, while a live pid the read cannot
/// see — PID 1 under SIP answers zero with EPERM — is read through
/// `sysctl`, the same userland ABI `ps` uses; every remaining failure
/// is a typed refusal, never an incomplete count that passes. A
/// positive count whose table holds no usable pid — every row a
/// nonpositive pid — is refused the same way as a zero return: a
/// live host always holds the caller's own pid, never an empty Ok.
#[cfg(target_os = "macos")]
fn enumerate_processes() -> Result<Vec<ProcessEntry>, ProcessReadError> {
    let mut capacity = 4096_i32;
    loop {
        let mut pids = vec![0_i32; capacity as usize];
        // A nonpositive return is the enumeration call itself failing:
        // -1 is the documented failure, and zero is not an answer a
        // live host can give — the caller itself is a process — while
        // Seatbelt's process-info denial answers zero with EPERM set,
        // an errno a stale read cannot reliably discriminate, so every
        // nonpositive return is the pid-less typed refusal captured
        // immediately, never an empty-host Ok that silently omits the
        // whole table.
        let filled = list_all_pids(&mut pids);
        if filled <= 0 {
            return Err(ProcessReadError::Io(io::Error::last_os_error()));
        }
        if filled < capacity {
            let mut entries = Vec::with_capacity(filled as usize);
            let mut visited = 0_usize;
            for pid in &pids[..filled as usize] {
                if *pid <= 0 {
                    continue;
                }
                visited += 1;
                let mut info = zeroed_proc_bsd_info();
                // SAFETY: `info` is a live, writable buffer with the SDK
                // `proc_bsdinfo` layout (size and field offsets asserted
                // above); the flavor bounds the kernel's write to that
                // struct.
                let written = unsafe {
                    proc_pidinfo(
                        *pid,
                        PROC_PIDTBSDINFO,
                        0,
                        (&raw mut info).cast(),
                        size_of::<ProcBsdInfo>() as i32,
                    )
                };
                if written as usize == size_of::<ProcBsdInfo>() {
                    entries.push(bsd_entry(*pid, &info));
                } else {
                    // Any other answer — zero, negative, or short — is a
                    // failed read, and zero is ambiguous on Darwin: a
                    // pid that vanished between the listing and this
                    // read answers zero, and so does a live pid the
                    // caller may not read (PID 1 under SIP answers zero
                    // with EPERM), while errno is stale after a zero
                    // return and cannot discriminate. The kinfo record
                    // can: no record means the pid is gone and holds no
                    // process slot, while a record is read through the
                    // same userland ABI `ps` uses — a live pid is
                    // counted or the enumeration refuses typed, never
                    // silently omitted from a passing count.
                    // No record: the pid no longer exists, so it holds
                    // no process slot and contributes nothing.
                    if let Some(entry) = kinfo_entry(*pid)? {
                        entries.push(entry);
                    }
                }
            }
            // A positive count whose every row was a nonpositive pid is
            // the zero-return refusal's sibling: not a table a live host
            // can give — the caller itself holds a pid slot — so the
            // answer is the pid-less typed refusal with owner text,
            // never an empty Ok that silently reports a host with no
            // processes.
            if visited == 0 {
                return Err(ProcessReadError::Io(io::Error::other(
                    "no usable pids in the process listing",
                )));
            }
            return Ok(entries);
        }
        capacity = next_scan_capacity(capacity).ok_or(ProcessReadError::ScanCapExceeded)?;
    }
}

/// Maps a complete `proc_bsdinfo` answer to an entry. NPROC is charged
/// per credential, and a setuid process still holds its real uid's
/// slots: the entry reads `pbi_ruid`, never the effective `pbi_uid`.
#[cfg(target_os = "macos")]
fn bsd_entry(pid: i32, info: &ProcBsdInfo) -> ProcessEntry {
    ProcessEntry {
        pid: pid as u32,
        uid: info.ruid,
        pgid: info.pgid,
    }
}

/// The next listing capacity after a buffer that reported exactly full:
/// fourfold growth bounded by the scan cap. `None` once the cap is
/// reached — the host is unmeasurable and the caller refuses typed
/// instead of looping a fork bomb's listing.
#[cfg(target_os = "macos")]
fn next_scan_capacity(capacity: i32) -> Option<i32> {
    (capacity < PROCESS_SCAN_CAP).then_some((capacity * 4).min(PROCESS_SCAN_CAP))
}

/// `sysctl(KERN_PROC_PID)` behind this thread's test seam: the real
/// record read, or the scripted answer a unit test planted so the
/// public count and listing surfaces can be driven through a
/// controlled fallback outcome.
#[cfg(target_os = "macos")]
fn kern_proc_pid(pid: i32, info: *mut std::os::raw::c_void, len: &mut usize) -> i32 {
    #[cfg(test)]
    {
        let scripted = SCRIPTED_KINFO.with(|slot| slot.borrow().as_ref().map(|f| f(len)));
        if let Some(answer) = scripted {
            return answer;
        }
    }
    let mib = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid];
    // SAFETY: `mib` names KERN_PROC_PID; `info` is a live writable
    // buffer of `*len` bytes with the SDK `kinfo_proc` layout (size and
    // field offsets asserted above), and sysctl writes at most `*len`
    // bytes into it.
    unsafe { sysctl(mib.as_ptr(), 4, info, len, std::ptr::null(), 0) }
}

/// The fallback read for a pid whose `proc_pidinfo` answer was not a
/// complete `proc_bsdinfo`: `sysctl(KERN_PROC_PID)` serves the same
/// userland ABI `ps` reads, for every host pid, without the privilege
/// `proc_pidinfo` demands for other owners' processes.
///
/// # Errors
/// Returns [`ProcessReadError::ReadFailed`] when `sysctl` itself fails —
/// the pid's state is then ambiguous and the caller refuses typed — and
/// [`ProcessReadError::MalformedRecord`] when the record is neither
/// absent nor the full ABI struct.
#[cfg(target_os = "macos")]
fn kinfo_entry(pid: i32) -> Result<Option<ProcessEntry>, ProcessReadError> {
    let mut info = zeroed_kinfo_proc();
    let mut len = KINFO_PROC_SIZE;
    if kern_proc_pid(pid, (&raw mut info).cast(), &mut len) != 0 {
        let os = io::Error::last_os_error();
        // The refusal names the pid it read: a caller deciding whether a
        // live pid was omitted must never mistake an enumeration-level
        // error, whose errno belongs to no pid in particular, for a
        // typed answer.
        return Err(ProcessReadError::ReadFailed {
            pid: pid as u32,
            source: os,
        });
    }
    kinfo_record(pid, len, &info)
}

/// Maps a `sysctl(KERN_PROC_PID)` answer to an entry: no record means
/// the pid is gone and holds no process slot, the full ABI struct is an
/// entry reading the REAL uid (`p_ruid` — NPROC is charged per
/// credential, and a setuid process still holds its real uid's slots),
/// and any other length is a malformed record, never a partial entry.
#[cfg(target_os = "macos")]
fn kinfo_record(
    pid: i32,
    len: usize,
    info: &KinfoProc,
) -> Result<Option<ProcessEntry>, ProcessReadError> {
    match len {
        0 => Ok(None),
        KINFO_PROC_SIZE => Ok(Some(ProcessEntry {
            pid: pid as u32,
            uid: info.ruid,
            pgid: info.pgid,
        })),
        _short => Err(ProcessReadError::MalformedRecord { pid: pid as u32 }),
    }
}

/// An all-zero `kinfo_proc` buffer for `sysctl` to fill.
#[cfg(target_os = "macos")]
fn zeroed_kinfo_proc() -> KinfoProc {
    KinfoProc {
        _head: [0; 392],
        ruid: 0,
        _mid: [0; 168],
        pgid: 0,
        _tail: [0; 80],
    }
}

/// An all-zero `proc_bsdinfo` buffer for `proc_pidinfo` to fill.
#[cfg(target_os = "macos")]
fn zeroed_proc_bsd_info() -> ProcBsdInfo {
    ProcBsdInfo {
        _flags: 0,
        _status: 0,
        _xstatus: 0,
        _pid: 0,
        _ppid: 0,
        _uid: 0,
        _gid: 0,
        ruid: 0,
        _rgid: 0,
        _svuid: 0,
        _svgid: 0,
        _reserved: 0,
        _comm: [0; 16],
        _name: [0; 32],
        _nfiles: 0,
        pgid: 0,
        _pjobc: 0,
        _e_tdev: 0,
        _e_tpgid: 0,
        _nice: 0,
        _start_tvsec: 0,
        _start_tvusec: 0,
    }
}

#[cfg(target_os = "macos")]
fn uid_count_platform() -> Result<u64, ProcessReadError> {
    // SAFETY: getuid takes no arguments and returns the real uid — the
    // credential RLIMIT_NPROC is charged against.
    let uid = unsafe { getuid() };
    let mut count = 0_u64;
    for entry in enumerate_processes()? {
        if entry.uid == uid {
            count += 1;
        }
    }
    Ok(count)
}

#[cfg(target_os = "macos")]
fn group_members_platform(pgid: u32) -> Result<Vec<u32>, ProcessReadError> {
    Ok(enumerate_processes()?
        .into_iter()
        .filter(|entry| entry.pgid == pgid)
        .map(|entry| entry.pid)
        .collect())
}

/// The `proc_listallpids` byte-capacity argument for a `capacity`-pid
/// buffer: four bytes per pid_t slot. The argument is a BYTE size while
/// the syscall's return is a pid COUNT, so passing the count itself
/// shrinks the buffer fourfold and silently truncates a busy host's
/// listing at a quarter of its intended entries — the F3 regression the
/// boundary unit test pins.
#[cfg(target_os = "macos")]
fn pid_buffer_bytes(capacity: i32) -> i32 {
    capacity * size_of::<i32>() as i32
}

/// Visits every `/proc/<pid>` entry once, bounded by [`PROCESS_SCAN_CAP`]:
/// a host past the cap is unmeasurable and the walk fails typed instead
/// of looping a fork bomb. Non-numeric `/proc` entries are kernel files,
/// not processes; a pid that vanishes mid-walk is mapped to a skip by the
/// visitor's own record read (which proves the exit), and every other
/// error propagates. A walk that visits no pid at all read an unusable
/// table, not a live host with zero processes, and refuses typed with
/// the pid-less [`ProcessReadError::Io`].
#[cfg(target_os = "linux")]
fn visit_proc_pids(
    visit: &mut dyn FnMut(u32) -> Result<(), ProcessReadError>,
) -> Result<(), ProcessReadError> {
    let root = proc_root();
    let cap = scan_cap();
    let dir = std::fs::read_dir(&root).map_err(|error| {
        ProcessReadError::Io(io::Error::new(
            error.kind(),
            format!("open {}: {error}", root.display()),
        ))
    })?;
    let mut scanned = 0_usize;
    let mut visited = 0_usize;
    for entry in dir {
        let entry = entry.map_err(|error| {
            ProcessReadError::Io(io::Error::new(
                error.kind(),
                format!("walk {}: {error}", root.display()),
            ))
        })?;
        scanned += 1;
        if scanned > cap {
            return Err(ProcessReadError::ScanCapExceeded);
        }
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        visited += 1;
        visit(pid)?;
    }
    // A table that listed no process entry is an empty or unusable
    // `/proc` — an empty bind mount over it reads exactly like this —
    // never a live host with zero processes (the caller itself is one),
    // so the walk refuses typed instead of handing Ok(0)/Ok(vec![]) to
    // a hard-NPROC decision as a measured baseline. An absent process
    // group stays a legitimate empty answer: it follows a walk that
    // enumerated the table and simply found no member.
    if visited == 0 {
        return Err(ProcessReadError::Io(io::Error::other(format!(
            "no process entries under {}",
            root.display()
        ))));
    }
    Ok(())
}

/// The real uid and task count of process `pid` from one status record.
/// The real uid is the first field of `/proc/<pid>/status`'s
/// `Uid:` line (real, effective, saved, fs) — the credential NPROC is
/// charged against. `/proc/<pid>`'s directory owner tracks the EFFECTIVE
/// uid, so a privilege-dropped process (`setpriv --ruid=n --euid=0`)
/// would silently vanish from its real uid's count if the owner were
/// trusted. The read is bounded by procfs's own record size.
#[cfg(target_os = "linux")]
fn stat_real_uid(pid: u32) -> Result<Option<(u32, u64)>, ProcessReadError> {
    let status = match std::fs::read_to_string(proc_root().join(pid.to_string()).join("status")) {
        Ok(status) => status,
        // The process exited between readdir and this read: it holds no
        // process slot anymore, so it contributes no count.
        Err(error) if error.raw_os_error() == Some(ESRCH) || proc_entry_gone(pid) => {
            return Ok(None);
        }
        Err(error) => return Err(ProcessReadError::ReadFailed { pid, source: error }),
    };
    parse_real_uid_status(pid, &status)
}

#[cfg(target_os = "linux")]
fn parse_real_uid_status(pid: u32, status: &str) -> Result<Option<(u32, u64)>, ProcessReadError> {
    // A record whose Uid: line is missing, or whose real-uid field is not
    // decimal, is malformed naming the pid — mapped here at the parse
    // site, never silently skipped.
    let uid = status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|fields| fields.split_whitespace().next())
        .ok_or(ProcessReadError::MalformedRecord { pid })?;
    let uid = uid
        .parse::<u32>()
        .map_err(|_parse| ProcessReadError::MalformedRecord { pid })?;
    let threads = status
        .lines()
        .find_map(|line| line.strip_prefix("Threads:"))
        .map(str::trim)
        .filter(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
        .ok_or(ProcessReadError::MalformedRecord { pid })?
        .parse::<u64>()
        .map_err(|_parse| ProcessReadError::MalformedRecord { pid })?;
    if threads == 0 {
        if proc_entry_gone(pid) {
            return Ok(None);
        }
        return Err(ProcessReadError::MalformedRecord { pid });
    }
    Ok(Some((uid, threads)))
}

#[cfg(target_os = "linux")]
fn uid_count_platform() -> Result<u64, ProcessReadError> {
    // SAFETY: getuid takes no arguments and returns the real uid — the
    // credential RLIMIT_NPROC is charged against.
    let uid = unsafe { getuid() };
    let mut count = 0_u64;
    visit_proc_pids(&mut |pid| {
        match stat_real_uid(pid)? {
            Some((real, threads)) if real == uid => {
                count = count
                    .checked_add(threads)
                    .ok_or(ProcessReadError::MalformedRecord { pid })?;
            }
            Some(_) | None => {}
        }
        Ok(())
    })?;
    Ok(count)
}

/// `ESRCH` (raw 3): the errno the kernel answers for a task it already
/// released. std maps neither it nor a vanished `/proc/<pid>` entry to a
/// distinct `ErrorKind`, so the scan discriminates on the raw code.
#[cfg(target_os = "linux")]
const ESRCH: i32 = 3;

/// The `/proc/<pid>` entry is gone on recheck: the pid was reaped between
/// the directory scan and its stat read, so it demonstrably holds no
/// process slot anymore.
#[cfg(target_os = "linux")]
fn proc_entry_gone(pid: u32) -> bool {
    matches!(
        std::fs::metadata(proc_root().join(pid.to_string())),
        Err(error) if error.kind() == io::ErrorKind::NotFound
    )
}

/// Reads `/proc/<pid>/stat`, mapping the demonstrably-vanished failures
/// — the kernel answers raw `ESRCH` for a task it already released, and a
/// reaped pid's entry is gone on recheck — to `Ok(None)`, the same skip
/// the macOS scan makes. Every other read failure (EACCES, EIO) stays
/// the typed refusal.
#[cfg(target_os = "linux")]
fn read_stat(pid: u32) -> Result<Option<String>, ProcessReadError> {
    match std::fs::read_to_string(proc_root().join(pid.to_string()).join("stat")) {
        Ok(stat) => Ok(Some(stat)),
        Err(error) if error.raw_os_error() == Some(ESRCH) || proc_entry_gone(pid) => Ok(None),
        Err(error) => Err(ProcessReadError::ReadFailed { pid, source: error }),
    }
}

/// The pgrp field of a `/proc/<pid>/stat` read. comm is parenthesised and
/// may contain spaces and parens itself, so the fields after the LAST ')'
/// are the stable ones: state, ppid, pgrp.
#[cfg(target_os = "linux")]
fn stat_pgrp(stat: &str) -> Option<u32> {
    stat.rsplit_once(')')
        .and_then(|(_, tail)| tail.split_whitespace().nth(2))
        // A non-decimal pgrp field feeds the caller's bounded re-read;
        // its second failure is the MalformedRecord refusal.
        .and_then(|field| field.parse::<u32>().ok())
}

#[cfg(target_os = "linux")]
fn group_members_platform(pgid: u32) -> Result<Vec<u32>, ProcessReadError> {
    let mut members = Vec::new();
    visit_proc_pids(&mut |pid| {
        // A task caught mid-exit can serve an empty or truncated stat;
        // its state settles within one re-read — a zombie's stat parses
        // again, a reaped pid's entry is gone — so the second read
        // separates that transient (skip) from a live pid whose stat
        // genuinely will not parse (typed refusal).
        for _ in 0..2 {
            match read_stat(pid)? {
                None => return Ok(()),
                Some(stat) => {
                    if let Some(pgrp) = stat_pgrp(&stat) {
                        if pgrp == pgid {
                            members.push(pid);
                        }
                        return Ok(());
                    }
                }
            }
        }
        Err(ProcessReadError::MalformedRecord { pid })
    })?;
    Ok(members)
}

/// `struct pollfd`: identical layout on macOS and Linux.
#[repr(C)]
struct PollFd {
    fd: i32,
    events: i16,
    revents: i16,
}

const POLLIN: i16 = 0x1;
const POLLOUT: i16 = 0x4;

#[cfg(target_os = "macos")]
type NfdsT = u32;
#[cfg(target_os = "linux")]
type NfdsT = std::os::raw::c_ulong;

/// Blocks until any `readable` fd can be read, any `writable` fd can be
/// written, or `timeout` passes — the host's idle wait on a confined
/// child's pipes, instead of a spin. It reports no readiness: the caller
/// retries its non-blocking I/O. Empty sets simply wait the timeout.
///
/// A hung-up, errored or invalid fd (`POLLHUP`/`POLLERR`/`POLLNVAL`) is
/// always ready, so a caller must drop an fd from its sets once it reads
/// EOF or an error there; otherwise every later wait returns at once.
///
/// # Errors
/// Returns the OS error when `poll(2)` fails; an interrupted wait (EINTR)
/// is a normal early return.
pub fn wait_ready(
    readable: &[BorrowedFd<'_>],
    writable: &[BorrowedFd<'_>],
    timeout: Duration,
) -> io::Result<()> {
    let mut fds: Vec<PollFd> = readable
        .iter()
        .map(|fd| (fd, POLLIN))
        .chain(writable.iter().map(|fd| (fd, POLLOUT)))
        .map(|(fd, events)| PollFd {
            fd: fd.as_raw_fd(),
            events,
            revents: 0,
        })
        .collect();
    let count = NfdsT::try_from(fds.len()).map_err(|_overflow| {
        io::Error::new(io::ErrorKind::InvalidInput, "too many fds to wait on")
    })?;
    // Round up so a sub-millisecond timeout still waits instead of spinning;
    // saturate at poll's `int` range (about 24 days).
    let millis = i32::try_from(timeout.as_nanos().div_ceil(1_000_000)).unwrap_or(i32::MAX);
    // SAFETY: `fds` is a live, writable array of `count` repr(C) pollfd
    // entries whose fds are borrowed for this call; poll only writes their
    // `revents`.
    if unsafe { poll(fds.as_mut_ptr(), count, millis) } >= 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::Interrupted {
        Ok(())
    } else {
        Err(error)
    }
}

unsafe extern "C" {
    fn fcntl(fd: i32, cmd: i32, ...) -> i32;
    fn kill(pid: i32, sig: i32) -> i32;
    fn getrlimit(resource: i32, rlim: *mut Rlimit) -> i32;
    fn poll(fds: *mut PollFd, nfds: NfdsT, timeout: i32) -> i32;
    fn getuid() -> u32;
}

#[cfg(target_os = "linux")]
unsafe extern "C" {
    #[link_name = "syscall"]
    fn parent_syscall(number: std::os::raw::c_long, ...) -> std::os::raw::c_long;
    fn getpagesize() -> i32;
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    static mach_task_self_: u32;
    fn task_info(
        target_task: u32,
        flavor: u32,
        task_info_out: *mut i32,
        task_info_out_count: *mut u32,
    ) -> i32;
    fn proc_pid_rusage(pid: i32, flavor: i32, buffer: *mut RusageInfoV4) -> i32;
    fn proc_listallpids(buffer: *mut i32, buffersize: i32) -> i32;
    fn proc_pidinfo(
        pid: i32,
        flavor: i32,
        arg: u64,
        buffer: *mut std::os::raw::c_void,
        buffersize: i32,
    ) -> i32;
    fn sysctl(
        name: *const i32,
        namelen: u32,
        oldp: *mut std::os::raw::c_void,
        oldlenp: *mut usize,
        newp: *const std::os::raw::c_void,
        newlen: usize,
    ) -> i32;
}

#[cfg(target_os = "macos")]
#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "lib unit tests assert boundary outcomes directly (standards §14)"
)]
mod tests {
    use super::*;

    #[test]
    fn pid_buffer_bytes_is_a_byte_capacity_not_an_entry_count() {
        // The F3 truncation boundary: a 1024-entry buffer must ask for
        // 4096 BYTES — the entry count itself would admit only 256 pids
        // — and the scan cap's full range stays a positive byte size.
        assert_eq!(pid_buffer_bytes(1024), 4096);
        assert_eq!(pid_buffer_bytes(PROCESS_SCAN_CAP), PROCESS_SCAN_CAP * 4);
    }

    #[test]
    fn primary_record_selects_the_real_uid_not_the_effective() {
        let mut info = zeroed_proc_bsd_info();
        // A setuid-root process: effective uid 0, real uid 1001 — the
        // entry must charge NPROC to the real uid. A LIVE mismatched-
        // credential leg needs root to set up, so the record mapping is
        // proven in-crate over both record paths instead.
        info.ruid = 1001;
        info._uid = 0;
        let entry = bsd_entry(42, &info);
        assert_eq!(entry.uid, 1001, "the primary record reads pbi_ruid");
        assert_eq!(entry.pid, 42);
    }

    #[test]
    fn fallback_record_selects_the_real_uid_and_maps_lengths() {
        let mut info = zeroed_kinfo_proc();
        info.ruid = 1001;
        // The full ABI struct maps to an entry reading the REAL uid.
        let entry = kinfo_record(42, KINFO_PROC_SIZE, &info)
            .expect("a full record maps")
            .expect("an entry");
        assert_eq!(entry.uid, 1001, "the fallback record reads p_ruid");
        assert_eq!(entry.pid, 42);
        // No record: the pid is gone, never a malformed refusal.
        assert!(matches!(kinfo_record(42, 0, &info), Ok(None)));
        // A short answer is a malformed record naming the pid — never a
        // partial entry that would pass a truncated count.
        assert!(matches!(
            kinfo_record(42, 1, &info),
            Err(ProcessReadError::MalformedRecord { pid: 42 })
        ));
    }

    #[test]
    fn kinfo_fallback_reads_no_record_for_a_vanished_pid() {
        // kern.maxproc tops out far below 4,000,000, so this pid cannot
        // exist: the sysctl answer must be "no record" — the skip that
        // keeps a reaped pid from failing the enumeration — and not a
        // short-read refusal.
        assert!(matches!(kinfo_entry(4_000_000), Ok(None)));
    }

    #[test]
    fn scan_capacity_growth_refuses_typed_at_the_cap() {
        // A buffer reported exactly full grows fourfold, bounded by the
        // scan cap; at the cap the answer is None — the caller's
        // ScanCapExceeded refusal, never an unbounded loop.
        assert_eq!(next_scan_capacity(4096), Some(16_384));
        assert_eq!(
            next_scan_capacity(PROCESS_SCAN_CAP / 2),
            Some(PROCESS_SCAN_CAP)
        );
        assert_eq!(next_scan_capacity(PROCESS_SCAN_CAP), None);
    }

    #[test]
    fn io_display_is_owner_text_and_keeps_the_os_prose_in_source() {
        use std::error::Error as _;
        // EPERM's OS prose ("Operation not permitted (os error 1)") must
        // stay in source(); the Display is stable owner text callers may
        // surface verbatim.
        let error = ProcessReadError::Io(io::Error::from_raw_os_error(1));
        assert_eq!(error.to_string(), "process enumeration io failed");
        assert!(error.source().is_some(), "the OS error stays in source()");
    }
    /// Plants scripted listing/kinfo answers for this thread's public
    /// enumeration surfaces; the real FFI answers again once the body
    /// returns.
    fn with_scripted_enumeration<L, K>(listing: L, kinfo: Option<K>, body: impl FnOnce())
    where
        L: Fn(&mut [i32]) -> i32 + 'static,
        K: Fn(&mut usize) -> i32 + 'static,
    {
        SCRIPTED_LISTING.with(|slot| {
            let scripted: ScriptedListing = Box::new(listing);
            *slot.borrow_mut() = Some(scripted);
        });
        SCRIPTED_KINFO.with(|slot| {
            let scripted: Option<ScriptedKinfo> = kinfo.map(|answer| {
                let boxed: ScriptedKinfo = Box::new(answer);
                boxed
            });
            *slot.borrow_mut() = scripted;
        });
        body();
        SCRIPTED_LISTING.with(|slot| *slot.borrow_mut() = None);
        SCRIPTED_KINFO.with(|slot| *slot.borrow_mut() = None);
    }

    #[test]
    fn zero_listing_refuses_typed_through_public_count_and_listing() {
        // Seatbelt's process-info denial answers zero with EPERM set:
        // both public surfaces must refuse with the pid-less Io variant
        // carrying the OS error in source(), never Ok(0)/Ok(vec![])
        // silently reporting an empty host.
        with_scripted_enumeration(
            |_| {
                set_errno(1);
                0
            },
            None::<fn(&mut usize) -> i32>,
            || {
                for refusal in [
                    uid_process_count().map(|_| ()),
                    process_group_members(7).map(|_| ()),
                ] {
                    match refusal {
                        Err(ProcessReadError::Io(source)) => assert_eq!(
                            source.raw_os_error(),
                            Some(1),
                            "the Seatbelt EPERM stays in source()"
                        ),
                        other => panic!(
                            "a zero listing must refuse typed through the public surface, got {other:?}"
                        ),
                    }
                }
            },
        );
    }

    #[test]
    fn negative_listing_return_refuses_typed_through_public_surfaces() {
        // `proc_listallpids` documents -1 as the failing return: both
        // public surfaces must refuse with the pid-less Io variant
        // carrying the errno in source(), never a count or listing
        // built off a failed enumeration.
        with_scripted_enumeration(
            |_| {
                set_errno(1);
                -1
            },
            None::<fn(&mut usize) -> i32>,
            || {
                for refusal in [
                    uid_process_count().map(|_| ()),
                    process_group_members(7).map(|_| ()),
                ] {
                    match refusal {
                        Err(ProcessReadError::Io(source)) => assert_eq!(
                            source.raw_os_error(),
                            Some(1),
                            "the failed listing's errno stays in source()"
                        ),
                        other => panic!(
                            "a negative listing must refuse typed through the public surface, got {other:?}"
                        ),
                    }
                }
            },
        );
    }

    #[test]
    fn positive_but_unusable_listing_refuses_typed_through_public_surfaces() {
        // A positive count over a table whose every row is a nonpositive
        // pid is the same refusal class as a zero return: not a table a
        // live host can give — the caller itself is a process — so both
        // public surfaces refuse with the pid-less Io variant carrying
        // owner text, never Ok(0)/Ok(vec![]) silently reporting an
        // empty host.
        with_scripted_enumeration(
            |pids| {
                pids[0] = 0;
                1
            },
            None::<fn(&mut usize) -> i32>,
            || {
                for refusal in [
                    uid_process_count().map(|_| ()),
                    process_group_members(7).map(|_| ()),
                ] {
                    match refusal {
                        Err(ProcessReadError::Io(source)) => assert_eq!(
                            source.to_string(),
                            "no usable pids in the process listing",
                            "the refusal carries owner text in source()"
                        ),
                        other => panic!(
                            "a positive-but-unusable listing must refuse typed through the public surface, got {other:?}"
                        ),
                    }
                }
            },
        );
    }

    #[test]
    fn exactly_full_listing_refuses_scan_cap_through_public_surface() {
        // A listing that always reports the buffer exactly full drives
        // the growth loop into the scan cap: both public surfaces
        // refuse ScanCapExceeded, never a truncated count or listing.
        with_scripted_enumeration(
            |pids| pids.len() as i32,
            None::<fn(&mut usize) -> i32>,
            || {
                assert!(matches!(
                    uid_process_count(),
                    Err(ProcessReadError::ScanCapExceeded)
                ));
                assert!(matches!(
                    process_group_members(7),
                    Err(ProcessReadError::ScanCapExceeded)
                ));
            },
        );
    }

    #[test]
    fn fallback_records_refuse_malformed_and_readfailed_through_public_surface() {
        // 4,000,000 sits past kern.maxproc, so the real primary read
        // answers the natural incomplete zero and the scripted fallback
        // record — the mapping under test — decides.
        const GHOST: i32 = 4_000_000;
        // A persistently short record: MalformedRecord naming the pid.
        with_scripted_enumeration(
            |pids| {
                pids[0] = GHOST;
                1
            },
            Some(|len: &mut usize| {
                *len = 8;
                0
            }),
            || {
                assert!(matches!(
                    uid_process_count(),
                    Err(ProcessReadError::MalformedRecord { pid }) if pid == GHOST as u32
                ));
                assert!(matches!(
                    process_group_members(7),
                    Err(ProcessReadError::MalformedRecord { pid }) if pid == GHOST as u32
                ));
            },
        );
        // A failing fallback read: ReadFailed naming the pid with the
        // OS error retained in source().
        with_scripted_enumeration(
            |pids| {
                pids[0] = GHOST;
                1
            },
            Some(|_: &mut usize| {
                set_errno(1);
                -1
            }),
            || {
                for refusal in [
                    uid_process_count().map(|_| ()),
                    process_group_members(7).map(|_| ()),
                ] {
                    match refusal {
                        Err(ProcessReadError::ReadFailed { pid, source }) => {
                            assert_eq!(pid, GHOST as u32);
                            assert_eq!(
                                source.raw_os_error(),
                                Some(1),
                                "the failed read retains its OS error in source()"
                            );
                        }
                        other => panic!(
                            "a failed fallback read must refuse ReadFailed naming the pid, got {other:?}"
                        ),
                    }
                }
            },
        );
    }

    #[test]
    fn enotdir_refusals_are_settled_by_the_component_stat() {
        // Overlayfs answers ENOTDIR when O_NOFOLLOW refuses a symlink,
        // so the ambiguous errno must be settled by stat'ing the
        // component itself: a symlink names the symlink seam, a real
        // file keeps the wrong-kind refusal.
        let owner = tempfile::TempDir::with_prefix("rivect-classify-").unwrap();
        std::os::unix::fs::symlink("target", owner.path().join("link")).unwrap();
        std::fs::write(owner.path().join("file"), b"k").unwrap();
        let root = owner.path().canonicalize().unwrap();
        let mut parent = open_filesystem_root().unwrap();
        for component in root.components().skip(1) {
            parent = openat_directory(&parent, component.as_os_str().as_encoded_bytes()).unwrap();
        }
        let link = std::ffi::CString::new("link").unwrap();
        match classify_directory_refusal(&parent, &link, io::Error::from_raw_os_error(ENOTDIR)) {
            FdOpenError::SymlinkComponent => {}
            other => panic!(
                "a symlink behind an ENOTDIR refusal must name the symlink seam, got {other:?}"
            ),
        }
        let file = std::ffi::CString::new("file").unwrap();
        match classify_directory_refusal(&parent, &file, io::Error::from_raw_os_error(ENOTDIR)) {
            FdOpenError::WrongKind => {}
            other => panic!(
                "a regular file behind an ENOTDIR refusal keeps the kind refusal, got {other:?}"
            ),
        }
    }
}

#[cfg(target_os = "linux")]
#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "lib unit tests assert boundary outcomes directly (standards §14)"
)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn owned_launch_private_mapping_bootstrap_is_protected() {
        {
            use std::os::fd::AsRawFd as _;
            use std::os::unix::fs::MetadataExt as _;
            let file = tempfile::tempfile().expect("retirement control");
            let fd = file.as_raw_fd();
            let fd_path = format!("/proc/self/fd/{fd}");
            // The pin keeps the inode alive after the close, so a recycled inode
            // number cannot make a closed fd number look like the retired file.
            let pin = file.try_clone().expect("retirement control inode pin");
            let retired_identity = {
                let metadata = file.metadata().expect("retirement control identity");
                (metadata.dev(), metadata.ino())
            };
            let before = std::fs::metadata(&fd_path).expect("retirement control fd path");
            assert_eq!(
                (before.dev(), before.ino()),
                retired_identity,
                "the fd path must name the retirement control before retirement"
            );
            let mut outcome: Result<(), OwnedParentError> = Ok(());
            let mut phases = Vec::new();
            retire_parent_result(
                file,
                6,
                Instant::now(),
                None,
                &mut outcome,
                1,
                &mut |tid, raw, phase| phases.push((tid, raw, phase)),
            );
            assert!(
                outcome.is_ok(),
                "a closed retirement stays success after the deadline, got {outcome:?}"
            );
            assert_eq!(phases, vec![(1, fd, 4)]);
            match std::fs::metadata(&fd_path) {
                Err(error) => assert_eq!(
                    error.kind(),
                    io::ErrorKind::NotFound,
                    "a retired fd number must be absent or reused, got {error:?}"
                ),
                Ok(reused) => assert_ne!(
                    (reused.dev(), reused.ino()),
                    retired_identity,
                    "the retired file must stay unreachable through its old fd number"
                ),
            }
            drop(pin);
        }
        match parent_dumpable(Instant::now(), None) {
            Ok(()) => {}
            Err(error) => {
                assert_ne!(
                    error.cause(),
                    OwnedFaultCause::Deadline,
                    "an elapsed deadline must not hide the dumpable readback"
                );
                assert!(
                    matches!(error.cause(), OwnedFaultCause::Readback { field: 1, .. }),
                    "dumpable readback stays the observation, got {error:?}"
                );
            }
        }
        {
            let mut status = tempfile::tempfile().expect("finished status fixture");
            io::Write::write_all(
                &mut status,
                b"Pid:\t7\nTgid:\t8\nTracerPid:\t0\nThreads:\t1\n",
            )
            .expect("write finished status");
            let parsed = parent_status(&mut status, 7, 8, Instant::now(), None)
                .expect("a finished status keeps its identity after the deadline");
            assert_eq!(parsed.threads, 1);
            let mut pinned = std::collections::BTreeMap::new();
            pinned.insert(7, status);
            let alive =
                parent_read_task(&mut pinned, 7, 8, Instant::now(), None, &mut |_, _, _| {})
                    .expect("a pinned status is read after the deadline");
            assert!(alive);
            let removed =
                parent_read_cohort(&mut pinned, 8, Instant::now(), None, 2, &mut |_, _, _| {})
                    .expect("a pinned cohort is read after the deadline");
            assert!(!removed);
        }
        assert!(identity_read_proceeds(true, true));
        assert!(identity_read_proceeds(true, false));
        assert!(identity_read_proceeds(false, false));
        assert!(!identity_read_proceeds(false, true));
        let pid = std::process::id();
        let armed = self_status_identity(
            "owned.waiter.parent_death",
            3,
            pid,
            Instant::now(),
            None,
            true,
        )
        .expect("an armed identity is read after the deadline");
        assert_eq!(armed, pid);
        let fresh = self_status_identity(
            "owned.waiter.parent_death",
            3,
            pid,
            Instant::now(),
            None,
            false,
        );
        match fresh {
            Err(error) => assert_eq!(
                error.cause(),
                OwnedFaultCause::Deadline,
                "a fresh identity stops before opening once the deadline has elapsed"
            ),
            Ok(value) => panic!("a fresh identity must not open after the deadline, got {value}"),
        }
        assert_eq!(
            parse_owned_record_observed(b"owned-launch-v1 terminal fault owned.child.spawn 0g\n"),
            Err(OwnedFaultCause::Malformed {
                field: 24,
                offset: 50
            })
        );
        assert_eq!(
            parse_owned_record(b"owned-launch-v1 terminal fault owned.child.spawn 0g\n"),
            Err(OwnedProtocolError::Malformed)
        );
        assert_eq!(
            parse_owned_fault(b"owned-launch-v1 terminal fault owned.child.spawn 0g\n"),
            Err(OwnedProtocolError::Malformed)
        );
        assert_eq!(
            parse_owned_record_observed(b"owned-launch-v1 entry worker 1 x 63\n"),
            Err(OwnedFaultCause::Malformed {
                field: 24,
                offset: 31
            })
        );
        assert_eq!(
            parse_owned_record_observed(b"owned-launch-v1 entry worker 4294967296 64 63\n"),
            Err(OwnedFaultCause::NumericOverflow {
                field: 24,
                offset: 38
            })
        );
        assert_eq!(
            parse_owned_record_observed(b"owned-launch-v1 terminal exit 256\n"),
            Err(OwnedFaultCause::NumericOverflow {
                field: 24,
                offset: 32
            })
        );
        assert_eq!(
            parse_owned_record_observed(b"owned-launch-v1 terminal exit 00\n"),
            Err(OwnedFaultCause::Malformed {
                field: 24,
                offset: 31
            })
        );
        assert_eq!(
            parse_owned_record_observed(b"owned-launch-v1 terminal exit 0 x\n"),
            Err(OwnedFaultCause::Trailing {
                field: 24,
                offset: 32
            })
        );
        assert_eq!(
            parse_owned_record_observed(b"owned-launch-v1 entry worker 1\n"),
            Err(OwnedFaultCause::Missing { field: 24 })
        );
        assert_eq!(
            parse_owned_record_observed(b"owned-launch-v1 terminal exit 0"),
            Err(OwnedFaultCause::EarlyEof {
                field: 24,
                expected: 32,
                observed: 31
            })
        );
        assert_eq!(
            parse_owned_record_observed(b""),
            Err(OwnedFaultCause::EarlyEof {
                field: 24,
                expected: 1,
                observed: 0
            })
        );
        assert_eq!(
            parse_owned_record_observed(b"x\n"),
            Err(OwnedFaultCause::Malformed {
                field: 24,
                offset: 0
            })
        );
        let mut at_limit = vec![b'a'; 128];
        assert_eq!(
            parse_owned_record_observed(&at_limit),
            Err(OwnedFaultCause::EarlyEof {
                field: 24,
                expected: 129,
                observed: 128
            })
        );
        at_limit.push(b'a');
        assert_eq!(
            parse_owned_record_observed(&at_limit),
            Err(OwnedFaultCause::Limit {
                field: 24,
                limit: 128,
                observed: 129
            })
        );
        assert_eq!(
            parse_owned_record(&at_limit),
            Err(OwnedProtocolError::Oversize)
        );
        assert_eq!(
            parse_owned_record_observed(&vec![b'a'; 256]),
            Err(OwnedFaultCause::Limit {
                field: 24,
                limit: 128,
                observed: 256
            })
        );
        assert_eq!(
            parse_owned_record(&vec![b'a'; 256]),
            Err(OwnedProtocolError::Oversize)
        );
        use std::cell::Cell;
        use std::time::Instant;

        fn traced_task_control() -> bool {
            use std::io::{BufRead as _, Write as _};
            use std::os::fd::AsFd as _;
            use std::process::{Command, Stdio};
            let child_args = [
                "--exact",
                "tests::owned_launch_private_mapping_bootstrap_is_protected",
                "--nocapture",
                "--test-threads=1",
            ];
            if std::env::args().skip(1).eq(child_args) {
                let (ready, received) = std::sync::mpsc::sync_channel(1);
                let (release, released) = std::sync::mpsc::sync_channel(1);
                let sibling = std::thread::spawn(move || {
                    let identity = std::fs::read_link("/proc/thread-self")
                        .expect("native traced task identity");
                    ready
                        .send(identity.file_name().expect("traced tid").to_os_string())
                        .expect("publish native task identity");
                    released
                        .recv_timeout(Duration::from_secs(5))
                        .expect("bounded traced task release");
                });
                let tid = received
                    .recv_timeout(Duration::from_secs(5))
                    .expect("task parked");
                println!(
                    "owned traced task {} {}",
                    std::process::id(),
                    tid.to_string_lossy()
                );
                io::stdout()
                    .flush()
                    .expect("publish traced task before attachment");
                let mut line = String::new();
                io::stdin()
                    .read_line(&mut line)
                    .expect("wait for native attachment");
                let tracer = line.trim().parse::<i64>().expect("independent tracer tid");
                let error = ensure_parent_observing(None, &mut |_, _, _| {})
                    .expect_err("a traced nonleader must refuse before exposure");
                assert_eq!(error.boundary(), "owned.parent.tracer");
                assert_eq!(
                    error.cause(),
                    OwnedFaultCause::Readback {
                        field: 2,
                        actual: tracer
                    }
                );
                assert!(error.request_stop().is_none());
                assert!(error.io_source().is_none());
                assert!(error.secondary().is_none());
                println!("owned traced refusal tracer={tracer} no_next_effect=true");
                io::stdout()
                    .flush()
                    .expect("publish original traced refusal");
                line.clear();
                io::stdin()
                    .read_line(&mut line)
                    .expect("wait for native detach");
                assert_eq!(line, "released\n");
                release.send(()).expect("release detached task");
                sibling.join().expect("join detached task");
                return true;
            }
            fn native_line(stdout: &mut io::BufReader<std::process::ChildStdout>) -> String {
                let deadline = Instant::now() + Duration::from_secs(5);
                let mut line = String::new();
                while !line.ends_with('\n') {
                    assert!(Instant::now() < deadline, "bounded native publication");
                    match stdout.read_line(&mut line) {
                        Ok(0) => panic!("native fixture closed before publication"),
                        Ok(_) => assert!(line.len() <= 4096),
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            wait_ready(
                                &[stdout.get_ref().as_fd()],
                                &[],
                                deadline.saturating_duration_since(Instant::now()),
                            )
                            .expect("wait for native publication");
                        }
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                        Err(error) => panic!("native publication failed: {error}"),
                    }
                }
                line
            }
            struct FixtureChild(std::process::Child, Option<u32>);
            impl Drop for FixtureChild {
                fn drop(&mut self) {
                    if self
                        .0
                        .try_wait()
                        .expect("observe own traced fixture")
                        .is_none()
                    {
                        self.0.kill().expect("stop only the owned traced fixture");
                        if let Some(tid) = self.1 {
                            let mut status = 0;
                            // SAFETY: SIGKILL was sent only to our unreaped
                            // direct child; this retires its held traced task.
                            let _observed =
                                unsafe { waitpid(tid as i32, &raw mut status, 0x40000000) };
                        }
                        self.0.wait().expect("reap the owned traced fixture");
                    }
                }
            }
            let mut child = FixtureChild(
                Command::new(std::env::current_exe().expect("native provider test executable"))
                    .args(child_args)
                    .env_clear()
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::inherit())
                    .spawn()
                    .expect("spawn the owned native traced fixture"),
                None,
            );
            let stdout = child
                .0
                .stdout
                .take()
                .expect("own traced fixture publication");
            set_nonblocking(stdout.as_fd()).expect("make native publication nonblocking");
            let mut stdout = io::BufReader::new(stdout);
            let mut publication = None;
            for _ in 0..8 {
                let line = native_line(&mut stdout);
                if let Some((_, line)) = line.split_once("owned traced task ") {
                    assert!(line.len() <= 128);
                    let mut identities = line.split_whitespace();
                    let pid = identities
                        .next()
                        .expect("published child pid")
                        .parse::<u32>()
                        .expect("native child pid");
                    let tid = identities
                        .next()
                        .expect("published task tid")
                        .parse::<u32>()
                        .expect("native child tid");
                    assert!(identities.next().is_none());
                    publication = Some((pid, tid));
                    break;
                }
            }
            let (pid, tid) = publication.expect("actual traced task was published");
            assert_eq!(pid, child.0.id());
            assert_ne!(pid, tid);
            unsafe extern "C" {
                fn ptrace(request: i32, pid: i32, address: usize, data: usize) -> isize;
                fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
            }
            // SAFETY: the target is a published live task of our unreaped direct
            // child, parked on a private barrier; SEIZE does not stop or signal it.
            assert_eq!(unsafe { ptrace(0x4206, tid as i32, 0, 0x00100000) }, 0);
            child.1 = Some(tid);
            let tracer = std::fs::read_link("/proc/thread-self").expect("actual tracing thread");
            let tracer = tracer
                .file_name()
                .expect("actual tracer tid")
                .to_string_lossy()
                .parse::<u32>()
                .expect("numeric tracer tid");
            let leader = std::fs::read_to_string(format!("/proc/{pid}/status"))
                .expect("independently read untraced leader");
            let task = std::fs::read_to_string(format!("/proc/{pid}/task/{tid}/status"))
                .expect("independently read attached task");
            assert!(leader.lines().any(|line| line == "TracerPid:\t0"));
            assert!(
                task.lines()
                    .any(|line| line == format!("TracerPid:\t{tracer}"))
            );
            println!("owned traced attached pid={pid} tid={tid} tracer={tracer} leader_tracer=0");
            writeln!(
                child.0.stdin.as_mut().expect("own fixture gate"),
                "{tracer}"
            )
            .expect("permit guard only after independent native attribution");
            let result = native_line(&mut stdout);
            assert_eq!(
                result,
                format!("owned traced refusal tracer={tracer} no_next_effect=true\n")
            );
            // SAFETY: this remains the same held traced child task; INTERRUPT
            // obtains the ptrace stop required for a native checked detach.
            assert_eq!(unsafe { ptrace(0x4207, tid as i32, 0, 0) }, 0);
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                let mut status = 0;
                // SAFETY: status is writable; __WALL|WNOHANG observes only the
                // exact published traced child task without waiting on strangers.
                let observed = unsafe { waitpid(tid as i32, &raw mut status, 0x40000001) };
                assert!(observed >= 0);
                if observed == tid as i32 {
                    assert_eq!(status & 0xff, 0x7f);
                    break;
                }
                assert!(Instant::now() < deadline, "bounded traced-task stop");
                std::thread::yield_now();
            }
            // SAFETY: the exact held task is now in the observed ptrace stop;
            // DETACH resumes it without injecting a signal.
            assert_eq!(unsafe { ptrace(17, tid as i32, 0, 0) }, 0);
            child.1 = None;
            writeln!(
                child.0.stdin.as_mut().expect("own fixture gate"),
                "released"
            )
            .expect("release only after native detach");
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                if let Some(status) = child.0.try_wait().expect("observe traced fixture exit") {
                    assert!(status.success());
                    break;
                }
                assert!(Instant::now() < deadline, "bounded traced fixture reap");
                std::thread::yield_now();
            }
            println!(
                "owned traced nonleader pid={pid} tid={tid} tracer={tracer} leader_tracer=0 refused=true detached=true reaped=true"
            );
            false
        }
        fn protocol_controls() {
            for (field, key) in [(3, "Pid"), (31, "PPid")] {
                let status = format!("Name:\thelper\n{key}:\t7\nThreads:\t1\n");
                assert_eq!(parent_identity(status.as_bytes(), field), Ok(7));
                let zero = format!("{key}:\t0\n");
                assert_eq!(parent_identity(zero.as_bytes(), field), Ok(0));
                assert_eq!(
                    parent_identity(b"Name:\thelper\n", field),
                    Err(OwnedFaultCause::Missing { field })
                );
                let duplicate = format!("{key}:\t7\n{key}:\t7\n{key}:\t7\n");
                assert_eq!(
                    parent_identity(duplicate.as_bytes(), field),
                    Err(OwnedFaultCause::Duplicate { field, count: 3 })
                );
                let incomplete = format!("{key}:\t7");
                let length = incomplete.len() as u64;
                assert_eq!(
                    parent_identity(incomplete.as_bytes(), field),
                    Err(OwnedFaultCause::EarlyEof {
                        field,
                        expected: length + 1,
                        observed: length
                    })
                );
                let bad = format!("{key}:\t07\n");
                assert_eq!(
                    parent_identity(bad.as_bytes(), field),
                    Err(OwnedFaultCause::Malformed {
                        field,
                        offset: (key.len() + 3) as u64
                    })
                );
                let trailing = format!("{key}:\t7 \n");
                assert_eq!(
                    parent_identity(trailing.as_bytes(), field),
                    Err(OwnedFaultCause::Trailing {
                        field,
                        offset: (key.len() + 3) as u64
                    })
                );
                let overflow = format!("{key}:\t2147483648\n");
                assert_eq!(
                    parent_identity(overflow.as_bytes(), field),
                    Err(OwnedFaultCause::NumericOverflow {
                        field,
                        offset: (key.len() + 11) as u64
                    })
                );
            }
            for boundary in ["owned.waiter.parent_death", "owned.init.parent_death"] {
                for (operation, field) in
                    [(4, 3), (5, 3), (7, 3), (4, 31), (5, 31), (7, 31), (12, 30)]
                {
                    let literal = format!(
                        "owned-launch-v1 terminal fault {boundary} 0001 {operation:016x} {field:016x} 0000000000000005\n"
                    );
                    assert_eq!(
                        parse_owned_fault(literal.as_bytes()),
                        Ok(OwnedFault {
                            boundary,
                            cause: OwnedFaultCause::Io {
                                operation,
                                field,
                                errno: 5
                            }
                        }),
                        "parent-process observations must preserve the actual syscall and selected status field"
                    );
                }
                for field in [3, 31] {
                    let literal = format!(
                        "owned-launch-v1 terminal fault {boundary} 000d {field:016x} 0000000000000007 0000000000000000\n"
                    );
                    assert_eq!(
                        parse_owned_fault(literal.as_bytes()),
                        Ok(OwnedFault {
                            boundary,
                            cause: OwnedFaultCause::Mismatch {
                                field,
                                expected: 7,
                                observed: 0
                            },
                        })
                    );
                }
            }
            let get_eio = b"owned-launch-v1 terminal fault owned.waiter.initial_dumpable 0001 0000000000000002 0000000000000001 0000000000000005\n";
            let invalid_dumpable = b"owned-launch-v1 terminal fault owned.waiter.initial_dumpable 0002 0000000000000001 0000000000000002\n";
            assert_eq!(
                parse_owned_fault(get_eio),
                Ok(OwnedFault {
                    boundary: "owned.waiter.initial_dumpable",
                    cause: OwnedFaultCause::Io {
                        operation: 2,
                        field: 1,
                        errno: 5
                    },
                }),
                "the original GET_DUMPABLE errno must cross the canonical control parser"
            );
            assert_eq!(
                parse_owned_fault(invalid_dumpable),
                Ok(OwnedFault {
                    boundary: "owned.waiter.initial_dumpable",
                    cause: OwnedFaultCause::Readback {
                        field: 1,
                        actual: 2
                    },
                }),
                "a successful GET with an invalid value is distinct from a failed syscall"
            );

            // The private transport operations keep their actual syscall and field.
            for (operation, field) in [
                (23, 20),
                (19, 20),
                (19, 32),
                (7, 0),
                (13, 0),
                (6, 24),
                (5, 24),
                (22, 24),
                (7, 20),
                (14, 0),
                (25, 0),
            ] {
                let literal = format!(
                    "owned-launch-v1 terminal fault owned.child.spawn 0001 {operation:016x} {field:016x} 0000000000000005\n"
                );
                assert_eq!(
                    parse_owned_fault(literal.as_bytes()),
                    Ok(OwnedFault {
                        boundary: "owned.child.spawn",
                        cause: OwnedFaultCause::Io {
                            operation,
                            field,
                            errno: 5
                        },
                    }),
                    "each private transport syscall must retain its exact operation and field"
                );
            }

            for cause in [
                OwnedFaultCause::Mismatch {
                    field: 20,
                    expected: 4,
                    observed: 0,
                },
                OwnedFaultCause::Mismatch {
                    field: 20,
                    expected: 3,
                    observed: 4,
                },
                OwnedFaultCause::Mismatch {
                    field: 32,
                    expected: 0,
                    observed: 2,
                },
                OwnedFaultCause::Mismatch {
                    field: 32,
                    expected: 1,
                    observed: 3,
                },
                OwnedFaultCause::Mismatch {
                    field: 21,
                    expected: 62,
                    observed: 63,
                },
                OwnedFaultCause::Mismatch {
                    field: 22,
                    expected: 0,
                    observed: 1,
                },
                OwnedFaultCause::Mismatch {
                    field: 39,
                    expected: 0,
                    observed: 1,
                },
                OwnedFaultCause::Mismatch {
                    field: 24,
                    expected: 0,
                    observed: 1,
                },
                OwnedFaultCause::Changed { field: 20 },
                OwnedFaultCause::Unverifiable { field: 20 },
                OwnedFaultCause::WriteCount {
                    requested: 129,
                    returned: 0,
                },
            ] {
                assert_eq!(
                    OwnedFault {
                        boundary: "owned.child.spawn",
                        cause
                    }
                    .encode(),
                    Err(OwnedProtocolError::Malformed),
                    "private causes must identify an actual failed predicate within its bounds"
                );
            }

            use proptest::prelude::*;
            use proptest::test_runner::{
                Config, RngAlgorithm, RngSeed, TestRng, TestRunner, noop_result_cache,
            };
            use std::cell::Cell;
            use std::time::Instant;
            let config = || Config {
                cases: 256,
                max_local_rejects: 0,
                max_global_rejects: 0,
                max_flat_map_regens: 0,
                max_shrink_iters: 128,
                max_shrink_time: 100,
                max_default_size_range: 256,
                failure_persistence: None,
                source_file: None,
                test_name: None,
                result_cache: noop_result_cache,
                verbose: 0,
                rng_algorithm: RngAlgorithm::ChaCha,
                rng_seed: RngSeed::Fixed(0),
                _non_exhaustive: (),
            };
            let seed =
                std::array::from_fn::<_, 32, _>(|index| u8::try_from(index).expect("seed index"));
            let mut arbitrary =
                TestRunner::new_with_rng(config(), TestRng::from_seed(RngAlgorithm::ChaCha, &seed));
            let bytes_count = Cell::new(0_u32);
            let bytes_deadline = Instant::now() + Duration::from_secs(5);
            arbitrary
                .run(&proptest::collection::vec(any::<u8>(), 0..=256), |bytes| {
                    prop_assert!(Instant::now() < bytes_deadline);
                    prop_assert!(std::panic::catch_unwind(|| parse_owned_fault(&bytes)).is_ok());
                    prop_assert!(
                        std::panic::catch_unwind(|| parse_owned_record_observed(&bytes)).is_ok()
                    );
                    match parse_owned_record_observed(&bytes) {
                        Ok(record) => {
                            prop_assert_eq!(parse_owned_record(&bytes), Ok(record));
                        }
                        Err(_) => {
                            prop_assert!(parse_owned_record(&bytes).is_err());
                            prop_assert!(parse_owned_fault(&bytes).is_err());
                        }
                    }
                    prop_assert!(Instant::now() < bytes_deadline);
                    bytes_count.set(bytes_count.get() + 1);
                    Ok(())
                })
                .expect("arbitrary control bytes must not panic");
            assert_eq!(bytes_count.get(), 256);

            // Expected records are chosen independently from the implementation's
            // legality predicates. No filter or retry can hide a refused record.
            let legal_record = |(variant, value): (u8, u64)| {
                let low = u32::try_from(value & u64::from(u32::MAX)).expect("bounded lower word");
                let cause = match variant {
                    0 => OwnedFaultCause::Io {
                        operation: if value == u64::MAX {
                            17
                        } else if value & 1 == 1 {
                            16
                        } else {
                            2
                        },
                        field: if value == u64::MAX || value & 1 == 1 {
                            0
                        } else {
                            1
                        },
                        errno: i32::try_from(value % 2_147_483_647 + 1).expect("positive errno"),
                    },
                    1 => OwnedFaultCause::Readback {
                        field: 1,
                        actual: i64::from(low % 2_147_483_646 + 2),
                    },
                    2 => OwnedFaultCause::WriteCount {
                        requested: 1 + value % u64::MAX,
                        returned: 0,
                    },
                    3 => OwnedFaultCause::Missing { field: 2 },
                    4 => OwnedFaultCause::Duplicate {
                        field: 2,
                        count: value.saturating_add(2),
                    },
                    5 => OwnedFaultCause::Malformed {
                        field: 24,
                        offset: value % 130,
                    },
                    6 => OwnedFaultCause::NumericOverflow {
                        field: 24,
                        offset: value % 130,
                    },
                    7 => OwnedFaultCause::Trailing {
                        field: 24,
                        offset: value % 130,
                    },
                    8 => OwnedFaultCause::Limit {
                        field: 24,
                        limit: value % 129,
                        observed: value % 129 + 1,
                    },
                    9 => OwnedFaultCause::EarlyEof {
                        field: 24,
                        expected: value % 129 + 1,
                        observed: value % 129,
                    },
                    10 => OwnedFaultCause::MapMismatch {
                        inside_pair: u64::from(low) << 32 | u64::from(low.wrapping_add(1)),
                        outside_pair: 0,
                        count_pair: 0x1_00000001,
                    },
                    11 => OwnedFaultCause::ExtraMap {
                        ordinal_count: 0x1_00000002,
                        inside: low,
                        outside: low,
                    },
                    12 => OwnedFaultCause::Mismatch {
                        field: 39,
                        expected: 64,
                        observed: if value == 64 { 65 } else { value },
                    },
                    13 => OwnedFaultCause::SetgroupsAllow,
                    14 => OwnedFaultCause::Changed { field: 22 },
                    15 => OwnedFaultCause::Unverifiable { field: 24 },
                    16 => OwnedFaultCause::Deadline,
                    17 => OwnedFaultCause::Cancelled,
                    18 => OwnedFaultCause::HardLimitMismatch {
                        field: 39,
                        expected: 64,
                        observed: if value == 64 { 65 } else { value },
                    },
                    19 => OwnedFaultCause::GidMapMismatch {
                        inside_pair: u64::from(low) << 32 | u64::from(low.wrapping_add(1)),
                        outside_pair: 0,
                        count_pair: 0x1_00000001,
                    },
                    _ => OwnedFaultCause::ExtraGidMap {
                        ordinal_count: 0x1_00000002,
                        inside: low,
                        outside: low,
                    },
                };
                let boundary = match variant {
                    0 if value == u64::MAX || value & 1 == 1 => "owned.child.capabilities",
                    0 | 1 => "owned.waiter.initial_dumpable",
                    2 => "owned.namespace.uid_map",
                    3 | 4 => "owned.waiter.tracer",
                    5..=9 | 15..=17 => "owned.child.spawn",
                    10 | 11 | 13 | 19 | 20 => "owned.namespace.gid_map.readback",
                    12 | 18 => "owned.resource.limit",
                    _ => "owned.resource.census",
                };
                OwnedFault { boundary, cause }
            };
            for variant in 0..21 {
                for value in [0, 1, 63, 64, u64::from(u32::MAX), u64::MAX] {
                    let expected = legal_record((variant, value));
                    let frame = expected.encode().expect("independent family endpoint");
                    assert_eq!(parse_owned_fault(frame.as_bytes()), Ok(expected));
                }
            }
            let legal = (0_u8..21, any::<u64>()).prop_map(legal_record);
            for tid in [1, u32::MAX] {
                let local_only = OwnedFault {
                    boundary: "owned.child.spawn",
                    cause: OwnedFaultCause::LiveDisappearance { tid },
                };
                assert_eq!(local_only.encode(), Err(OwnedProtocolError::Malformed));
                let literal =
                    format!("owned-launch-v1 terminal fault owned.child.spawn 0011 {tid:016x}\n");
                assert_eq!(
                    parse_owned_fault(literal.as_bytes()),
                    Err(OwnedProtocolError::Malformed)
                );
            }

            let mut roundtrip =
                TestRunner::new_with_rng(config(), TestRng::from_seed(RngAlgorithm::ChaCha, &seed));
            let legal_count = Cell::new(0_u32);
            let legal_deadline = Instant::now() + Duration::from_secs(5);
            roundtrip
                .run(&legal, |expected| {
                    prop_assert!(Instant::now() < legal_deadline);
                    let frame = expected
                        .encode()
                        .map_err(|error| TestCaseError::fail(error.to_string()))?;
                    prop_assert_eq!(parse_owned_fault(frame.as_bytes()), Ok(expected));
                    prop_assert_eq!(
                        parse_owned_record_observed(frame.as_bytes()),
                        Ok(OwnedRecord::Fault(expected))
                    );
                    prop_assert_eq!(
                        parse_owned_record(frame.as_bytes()),
                        Ok(OwnedRecord::Fault(expected))
                    );
                    prop_assert!(Instant::now() < legal_deadline);
                    legal_count.set(legal_count.get() + 1);
                    Ok(())
                })
                .expect("all independently generated legal records must round trip");
            assert_eq!(legal_count.get(), 256);
            println!(
                "owned launch properties: arbitrary={} legal={} successful=512 child_families=21 family_endpoints=126 parent_only_rejections=4",
                bytes_count.get(),
                legal_count.get()
            );
            let primary = parse_owned_fault(b"owned-launch-v1 terminal fault owned.child.capabilities 0001 0000000000000010 0000000000000000 0000000000000005\n")
            .expect("independent capset literal");
            let observation = parse_owned_fault(b"owned-launch-v1 terminal fault owned.child.spawn 0001 0000000000000005 0000000000000018 0000000000000005\n")
            .expect("independent private read literal");
            let close = parse_owned_fault(b"owned-launch-v1 terminal fault owned.child.spawn 0001 0000000000000007 0000000000000014 0000000000000005\n")
            .expect("independent receiver close literal");
            let wait = parse_owned_fault(b"owned-launch-v1 terminal fault owned.child.spawn 0001 000000000000000e 0000000000000000 0000000000000005\n")
            .expect("independent init wait literal");
            for (first, second) in [
                (primary, observation),
                (primary, close),
                (primary, wait),
                (observation, close),
                (observation, wait),
                (close, wait),
            ] {
                let mut sequence = OwnedSequence::default();
                assert_eq!(sequence.push(OwnedRecord::Fault(first)), Ok(()));
                assert_eq!(sequence.push(OwnedRecord::Fault(second)), Ok(()));
                assert_eq!(sequence.primary(), Some(first));
                assert_eq!(sequence.secondary(), Some(second));
                assert!(!sequence.released(true, true));
                assert!(sequence.push(OwnedRecord::Fault(wait)).is_err());
                assert_eq!(sequence.primary(), Some(first));
                assert_eq!(sequence.secondary(), Some(second));
                sequence.lost();
                assert_eq!(sequence.primary(), Some(first));
                assert_eq!(sequence.secondary(), Some(second));
            }
            for (first, second) in [
                (primary, primary),
                (observation, observation),
                (close, close),
                (wait, wait),
                (wait, close),
                (close, observation),
                (wait, observation),
                (close, primary),
            ] {
                let mut sequence = OwnedSequence::default();
                assert_eq!(sequence.push(OwnedRecord::Fault(first)), Ok(()));
                assert!(sequence.push(OwnedRecord::Fault(second)).is_err());
                assert_eq!(sequence.primary(), Some(first));
                assert_eq!(sequence.secondary(), None);
            }
            for terminal in [
                OwnedRecord::Exit(0),
                OwnedRecord::Exit(23),
                OwnedRecord::Signal(15),
            ] {
                let mut sequence = OwnedSequence::default();
                sequence
                    .push(OwnedRecord::Entry {
                        profile: OwnedProfile::Worker,
                        baseline: 2,
                        nproc: 64,
                        verified: 63,
                    })
                    .expect("entry");
                assert!(!sequence.released(true, true));
                sequence.push(terminal).expect("terminal");
                assert!(!sequence.released(false, true));
                assert!(!sequence.released(true, false));
                assert!(sequence.released(true, true));
                assert!(sequence.push(OwnedRecord::Fault(primary)).is_err());
                assert!(!sequence.released(true, true));
            }
        }

        fn parent_status_shape_controls() {
            for (field, key) in [
                (3, "Pid:"),
                (4, "Tgid:"),
                (2, "TracerPid:"),
                (5, "Threads:"),
            ] {
                let mut prefix = String::from("Name:\tfixture\n");
                for (other, value) in [
                    ("Pid:", 7),
                    ("Tgid:", 8),
                    ("TracerPid:", 0),
                    ("Threads:", 1),
                ] {
                    if other != key {
                        prefix.push_str(&format!("{other}\t{value}\n"));
                    }
                }
                let offset = (prefix.len() + key.len()) as u64;
                let malformed = format!("{prefix}{key}\t07\n");
                let trailing = format!("{prefix}{key}\t7 \n");
                let overflow = format!("{prefix}{key}\t2147483648\n");
                let incomplete = format!("{prefix}{key}\t7");
                let incomplete_length = incomplete.len() as u64;
                let duplicate = format!("{prefix}{key}\t0\n{key}\t0\n{key}\t0\n");
                for (bytes, expected) in [
                    (
                        malformed,
                        OwnedFaultCause::Malformed {
                            field,
                            offset: offset + 2,
                        },
                    ),
                    (
                        trailing,
                        OwnedFaultCause::Trailing {
                            field,
                            offset: offset + 2,
                        },
                    ),
                    (
                        overflow,
                        OwnedFaultCause::NumericOverflow {
                            field,
                            offset: offset + 10,
                        },
                    ),
                    (
                        incomplete,
                        OwnedFaultCause::EarlyEof {
                            field,
                            expected: incomplete_length + 1,
                            observed: incomplete_length,
                        },
                    ),
                    (duplicate, OwnedFaultCause::Duplicate { field, count: 3 }),
                ] {
                    let mut file = tempfile::tempfile().expect("own bounded status-reader input");
                    io::Write::write_all(&mut file, bytes.as_bytes())
                        .expect("write independent status bytes");
                    let error = parent_status(
                        &mut file,
                        7,
                        8,
                        Instant::now() + Duration::from_millis(250),
                        None,
                    )
                    .err()
                    .expect("malformed task status cannot authorize exposure");
                    assert_eq!(error.boundary(), "owned.parent.task_status");
                    assert_eq!(
                        error.cause(),
                        expected,
                        "literal reader field={field} bytes={bytes:?}"
                    );
                    assert!(error.io_source().is_none());
                    assert!(error.request_stop().is_none());
                    assert!(error.secondary().is_none());
                }
            }
        }
        protocol_controls();
        if traced_task_control() {
            return;
        }
        parent_status_shape_controls();

        fn finite_task_controls() {
            // Each held task is released while the cohort reread of its own
            // pinned identity follows the fresh count, so every retiree crosses
            // its own barrier inside the census that pins it. Five waves must
            // contract one cohort without spending acquisition slots.
            let mut retiring = std::collections::BTreeMap::new();
            for _ in 0..5 {
                let (release, released) = std::sync::mpsc::sync_channel(1);
                let (ready, received) = std::sync::mpsc::sync_channel(1);
                let (done, completed) = std::sync::mpsc::sync_channel(1);
                let task = std::thread::spawn(move || {
                    let link =
                        std::fs::read_link("/proc/thread-self").expect("native thread identity");
                    let tid = link
                        .file_name()
                        .expect("thread id")
                        .to_str()
                        .expect("decimal tid")
                        .parse::<u32>()
                        .expect("positive tid");
                    ready.send(tid).expect("publish held task");
                    released
                        .recv_timeout(Duration::from_secs(5))
                        .expect("bounded retirement barrier");
                    done.send(()).expect("publish retirement completion");
                });
                let tid = received
                    .recv_timeout(Duration::from_secs(5))
                    .expect("bounded held task readiness");
                retiring.insert(tid, (release, completed, task));
            }
            let mut waves = 0;
            let mut acquisitions = 0;
            let pid = std::process::id();
            let result = ensure_parent_observing(None, &mut |tid, _, phase| {
                if tid == pid && phase == 0 {
                    acquisitions += 1;
                }
                if phase == 2
                    && let Some((release, completed, task)) = retiring.remove(&tid)
                {
                    release.send(()).expect("release held task");
                    completed
                        .recv_timeout(Duration::from_secs(5))
                        .expect("bounded task completion");
                    task.join().expect("retiring task joined");
                    waves += 1;
                }
            });
            for (_, (release, completed, task)) in retiring {
                release.send(()).expect("release remaining task");
                completed
                    .recv_timeout(Duration::from_secs(5))
                    .expect("bounded remaining completion");
                task.join().expect("remaining held task joined");
            }
            assert!(
                result.is_ok(),
                "five grounded retirement waves must close one surviving cohort: {result:?}"
            );
            assert_eq!(waves, 5, "all five native retirement barriers must execute");
            assert_eq!(
                acquisitions, 1,
                "grounded retirement must preserve the original pinned cohort"
            );
            println!("owned parent census: retirement_waves={waves} acquisitions={acquisitions}");
            let mut births = Vec::new();
            let mut birth_acquisitions = 0;
            let mut reread_births = std::collections::BTreeSet::new();
            let birth_result = ensure_parent_observing(None, &mut |tid, _, phase| {
                if tid == pid && phase == 0 {
                    birth_acquisitions += 1;
                    if births.len() < 4 {
                        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
                        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
                        let handle = std::thread::spawn(move || {
                            let own_tid = std::fs::read_link("/proc/thread-self")
                                .expect("read the born thread identity")
                                .file_name()
                                .expect("born thread identity component")
                                .to_str()
                                .expect("numeric born thread identity")
                                .parse::<u32>()
                                .expect("parse born thread identity");
                            ready_tx
                                .send(own_tid)
                                .expect("publish born thread identity");
                            release_rx
                                .recv_timeout(Duration::from_secs(5))
                                .expect("release the born thread");
                        });
                        let born_tid = ready_rx
                            .recv_timeout(Duration::from_secs(5))
                            .expect("born thread is parked before the first observation");
                        births.push((born_tid, release_tx, handle));
                    }
                }
                if phase == 2 && births.iter().any(|(born_tid, _, _)| *born_tid == tid) {
                    reread_births.insert(tid);
                }
            });
            let born_count = births.len();
            for (_, release, handle) in births {
                release.send(()).expect("release each parked born thread");
                handle.join().expect("reap each born thread");
            }
            assert!(
                birth_result.is_ok(),
                "a finite birth during initial acquisition must join the same closed cut: {birth_result:?}"
            );
            assert_eq!(birth_acquisitions, 1);
            assert_eq!(born_count, 1);
            assert_eq!(
                reread_births.len(),
                1,
                "the born task must be pinned and cold reread after the count"
            );
            println!(
                "owned parent census: births={born_count} acquisitions={birth_acquisitions} cold_rereads={}",
                reread_births.len()
            );
        }
        finite_task_controls();
        fn late_birth_control() {
            // A birth after EOF cannot join that acquisition's fixed cohort.
            // Keep every new task parked, so no retirement or TID reuse can explain
            // the fresh count's strict excess over the held identities.
            let mut late_births = Vec::new();
            let mut late_pins = std::collections::BTreeSet::new();
            let mut late_cuts = Vec::new();
            let mut late_acquisitions = 0;
            let mut late_retirements = 0;
            let late_result = ensure_parent_observing(None, &mut |tid, _, phase| {
                if phase == 5 {
                    late_acquisitions += 1;
                }
                if phase == 0 {
                    late_pins.insert(tid);
                }
                if phase == 4 && tid != 0 {
                    late_pins.remove(&tid);
                    if late_cuts.len() < 64 {
                        late_retirements += 1;
                    }
                }
                if phase == 1 {
                    let held = late_pins.len();
                    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
                    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
                    let handle = std::thread::spawn(move || {
                        let own_tid = std::fs::read_link("/proc/thread-self")
                            .expect("late birth native identity")
                            .file_name()
                            .expect("late birth identity component")
                            .to_str()
                            .expect("late birth decimal identity")
                            .parse::<u32>()
                            .expect("late birth numeric identity");
                        ready_tx.send(own_tid).expect("publish late born identity");
                        release_rx
                            .recv_timeout(Duration::from_secs(5))
                            .expect("bounded late born task custody");
                    });
                    let born_tid = ready_rx
                        .recv_timeout(Duration::from_secs(5))
                        .expect("late born task is parked before count");
                    assert!(!late_pins.contains(&born_tid));
                    let status = std::fs::read("/proc/self/status")
                        .expect("independent native thread count");
                    assert!(status.len() <= 65536);
                    let count = status
                        .split(|byte| *byte == b'\n')
                        .find_map(|line| line.strip_prefix(b"Threads:"))
                        .map(|value| {
                            std::str::from_utf8(value)
                                .expect("native count decimal")
                                .trim()
                                .parse::<usize>()
                                .expect("native thread count value")
                        })
                        .expect("native Threads record");
                    late_cuts.push((held, count, born_tid));
                    late_births.push((release_tx, handle));
                }
            });
            for (release, handle) in late_births {
                release
                    .send(())
                    .expect("release late born task after guard return");
                handle.join().expect("join every late born task");
            }
            assert_eq!(late_acquisitions, 64);
            assert_eq!(late_cuts.len(), 64);
            assert_eq!(late_retirements, 0);
            for (held, count, _) in &late_cuts {
                assert_eq!(*count, held + 1, "one independently parked post-EOF birth");
            }
            assert!(matches!(
                late_result.as_ref().map_err(OwnedParentError::cause),
                Err(OwnedFaultCause::Limit {
                    field: 10,
                    limit: 64,
                    observed: 65
                })
            ));
            println!(
                "owned parent late births: acquisitions={late_acquisitions} retirements={late_retirements} cuts={late_cuts:?} result={late_result:?}"
            );
        }
        late_birth_control();
        fn lifecycle_controls() {
            let pid = std::process::id();
            let (old_ready, old_received) = std::sync::mpsc::sync_channel(1);
            let (old_release, old_released) = std::sync::mpsc::sync_channel(1);
            let old_task = std::thread::spawn(move || {
                let tid = std::fs::read_link("/proc/thread-self")
                    .expect("old task identity")
                    .file_name()
                    .expect("old task component")
                    .to_str()
                    .expect("decimal old tid")
                    .parse::<u32>()
                    .expect("old numeric tid");
                old_ready.send(tid).expect("publish old task");
                old_released
                    .recv_timeout(Duration::from_secs(5))
                    .expect("bounded old task gate");
            });
            let old_tid = old_received
                .recv_timeout(Duration::from_secs(5))
                .expect("old task parked");
            let mut old_status = std::fs::File::open(format!("/proc/self/task/{old_tid}/status"))
                .expect("pin old native identity");
            old_release.send(()).expect("release old native identity");
            old_task.join().expect("join old native identity");
            // join() returns before the kernel task entry necessarily
            // disappears; the held FD must observe retirement once it is
            // gone, so give the entry a bounded settle before reading.
            let settle = Instant::now() + Duration::from_millis(50);
            while Path::new(&format!("/proc/self/task/{old_tid}")).exists()
                && Instant::now() < settle
            {
                std::thread::yield_now();
            }
            let deadline = Instant::now() + Duration::from_millis(250);
            let death = parent_status(&mut old_status, old_tid, pid, deadline, None)
                .err()
                .expect("held native old status must observe retirement");
            assert!(matches!(
                death.cause(),
                OwnedFaultCause::Io {
                    operation: 5,
                    field: 9,
                    errno: 3
                }
            ));
            let dead_template = old_status
                .try_clone()
                .expect("retain independent native death witness");
            let current = tempfile::tempdir().expect("semantic current directory");
            std::fs::create_dir(current.path().join(old_tid.to_string()))
                .expect("semantic new occupant directory");
            std::fs::write(
                current.path().join(format!("{old_tid}/status")),
                format!("Pid:\t{old_tid}\nTgid:\t{pid}\nTracerPid:\t0\nThreads:\t1\n"),
            )
            .expect("independent new matching whole status");
            let directory = std::fs::File::open(current.path()).expect("held semantic directory");
            let mut pinned = std::collections::BTreeMap::from([(old_tid, old_status)]);
            let mut seen = std::collections::BTreeSet::new();
            let mut trace = Vec::new();
            let replacement = parent_task_entry(
                &mut pinned,
                &mut seen,
                old_tid.to_string().as_bytes(),
                (directory.as_fd(), pid),
                deadline,
                None,
                &mut |_, _, phase| trace.push(phase),
            );
            let new_pinned = pinned.contains_key(&old_tid);
            let mut cleanup = Ok(());
            for (tid, status) in pinned {
                retire_parent_result(
                    status,
                    6,
                    deadline,
                    None,
                    &mut cleanup,
                    tid,
                    &mut |_, _, _| {},
                );
            }
            cleanup.expect("checked semantic terminal cleanup");
            replacement.expect(
                "one current entry may acquire a separately validated new pin after old death",
            );
            assert!(
                new_pinned,
                "old held read ESRCH is not evidence for the current new occupant"
            );
            assert_eq!(
                trace,
                [3, 4, 0, 3],
                "old cold read, checked old retirement, one new open and fresh new validation"
            );
            assert!(
                seen.contains(&old_tid),
                "retirement cannot erase the traversal occurrence"
            );
            println!("owned parent reuse: native_old_esrch=1 new_opens=1 new_validations=1");
            unsafe extern "C" {
                #[link_name = "dup2"]
                fn fixture_dup2(old: i32, new: i32) -> i32;
            }
            let status_path = current.path().join(format!("{old_tid}/status"));
            let valid = format!("Pid:\t{old_tid}\nTgid:\t{pid}\nTracerPid:\t0\nThreads:\t1\n");
            let (unseekable, _peer) = UnixStream::pair().expect("unseekable new-read control");
            for scenario in [
                "valid",
                "new_esrch",
                "new_seek",
                "new_read",
                "new_parse",
                "new_tracer",
                "new_identity",
                "new_open",
                "old_close",
                "stop",
                "primary_secondary",
            ] {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(&status_path, std::fs::Permissions::from_mode(0o600))
                    .expect("restore fixture permissions");
                if scenario == "new_read" {
                    std::fs::remove_file(&status_path)
                        .expect("replace only the owned semantic status");
                    std::fs::create_dir(&status_path).expect("directory read-error control");
                } else {
                    let bytes = match scenario {
                        "new_parse" => "Pid:\tx\n".to_string(),
                        "new_tracer" | "primary_secondary" => {
                            format!("Pid:\t{old_tid}\nTgid:\t{pid}\nTracerPid:\t9\nThreads:\t1\n")
                        }
                        "new_identity" => {
                            format!("Pid:\t1\nTgid:\t{pid}\nTracerPid:\t0\nThreads:\t1\n")
                        }
                        _ => valid.clone(),
                    };
                    std::fs::write(&status_path, bytes).expect("independent current-entry status");
                }
                if scenario == "new_open" {
                    arm_new_status_open_fault(io::Error::from_raw_os_error(EACCES));
                }
                let mut pinned = std::collections::BTreeMap::from([(
                    old_tid,
                    dead_template.try_clone().expect("old held identity"),
                )]);
                let mut seen = std::collections::BTreeSet::new();
                let cancelled = Cell::new(false);
                let cancel = || cancelled.get();
                let deadline = Instant::now() + Duration::from_millis(250);
                let request = Some(ParentRequest {
                    deadline,
                    cancel: Some(&cancel),
                });
                let mut phases = Vec::new();
                let mut closes = 0;
                let mut result = parent_task_entry(
                    &mut pinned,
                    &mut seen,
                    old_tid.to_string().as_bytes(),
                    (directory.as_fd(), pid),
                    deadline,
                    request,
                    &mut |_, fd, phase| {
                        phases.push(phase);
                        if phase == 4 {
                            closes += 1;
                            if scenario == "stop" {
                                cancelled.set(true);
                            }
                            if scenario == "old_close" {
                                // SAFETY: the fixture consumes its own descriptor before the checked-close fault probe.
                                assert_eq!(unsafe { close(fd) }, 0);
                            }
                        }
                        if phase == 0 && matches!(scenario, "new_esrch" | "new_seek") {
                            let source = if scenario == "new_esrch" {
                                dead_template.as_raw_fd()
                            } else {
                                unseekable.as_raw_fd()
                            };
                            // SAFETY: both fixture descriptors are live; only this guard-owned destination is replaced.
                            assert_eq!(unsafe { fixture_dup2(source, fd) }, fd);
                        }
                    },
                );
                let observations = phases.len();
                let duplicate = parent_task_entry(
                    &mut pinned,
                    &mut seen,
                    old_tid.to_string().as_bytes(),
                    (directory.as_fd(), pid),
                    deadline,
                    request,
                    &mut |_, _, phase| phases.push(phase),
                )
                .expect_err("same traversal occurrence cannot observe or open again");
                assert_eq!(
                    duplicate.cause(),
                    OwnedFaultCause::Duplicate { field: 7, count: 2 }
                );
                assert_eq!(
                    phases.len(),
                    observations,
                    "duplicate after old or new retirement must refuse before additional observation"
                );
                let new_opens = phases.iter().filter(|phase| **phase == 0).count();
                assert_eq!(
                    new_opens,
                    usize::from(!matches!(scenario, "new_open" | "old_close" | "stop")),
                    "at most one new open per first occurrence"
                );
                let expected = match scenario {
                    "valid" | "new_esrch" => None,
                    "new_seek" => Some(OwnedFaultCause::Io {
                        operation: 8,
                        field: 9,
                        errno: 29,
                    }),
                    "new_read" => Some(OwnedFaultCause::Io {
                        operation: 5,
                        field: 9,
                        errno: 21,
                    }),
                    "new_parse" => Some(OwnedFaultCause::Malformed {
                        field: 3,
                        offset: 5,
                    }),
                    "new_tracer" | "primary_secondary" => Some(OwnedFaultCause::Readback {
                        field: 2,
                        actual: 9,
                    }),
                    "new_identity" => Some(OwnedFaultCause::Unverifiable { field: 7 }),
                    "new_open" => Some(OwnedFaultCause::Io {
                        operation: 4,
                        field: 6,
                        errno: 13,
                    }),
                    "old_close" => Some(OwnedFaultCause::Io {
                        operation: 7,
                        field: 6,
                        errno: 9,
                    }),
                    "stop" => Some(OwnedFaultCause::Cancelled),
                    _ => unreachable!("enumerated semantic scenario"),
                };
                assert_eq!(
                    result.as_ref().err().map(OwnedParentError::cause),
                    expected,
                    "exact original typed cause for {scenario}"
                );
                if let Some(OwnedFaultCause::Io { errno, .. }) = expected {
                    assert_eq!(
                        result
                            .as_ref()
                            .err()
                            .and_then(OwnedParentError::io_source)
                            .and_then(io::Error::raw_os_error),
                        Some(errno)
                    );
                }
                for (tid, status) in pinned {
                    retire_parent_result(
                        status,
                        6,
                        deadline,
                        request,
                        &mut result,
                        tid,
                        &mut |_, fd, phase| {
                            assert_eq!(
                                phase, 4,
                                "only mandatory consuming closes may follow failure"
                            );
                            closes += 1;
                            if scenario == "primary_secondary" {
                                cancelled.set(true);
                                // SAFETY: the fixture consumes its own fd to produce a real checked-close failure.
                                assert_eq!(unsafe { close(fd) }, 0);
                            }
                        },
                    );
                }
                assert_eq!(
                    closes,
                    1 + new_opens,
                    "each old/new owned lifetime closes exactly once for {scenario}"
                );
                if scenario == "primary_secondary" {
                    let mut cleanup = result;
                    let extra = tempfile::tempfile()
                        .expect("independent directory-close secondary control");
                    retire_parent_result(
                        extra,
                        8,
                        deadline,
                        request,
                        &mut cleanup,
                        0,
                        &mut |_, fd, _| {
                            // SAFETY: only the fixture-owned extra descriptor is consumed for the second close fault.
                            assert_eq!(unsafe { close(fd) }, 0);
                        },
                    );
                    let original = cleanup.expect_err(
                        "tracer primary survives late stop and multiple checked-close failures",
                    );
                    assert_eq!(original.cause(), expected.expect("tracer cause"));
                    assert_eq!(
                        original.secondary().map(OwnedParentError::cause),
                        Some(OwnedFaultCause::Io {
                            operation: 7,
                            field: 6,
                            errno: 9
                        })
                    );
                    assert_eq!(
                        original
                            .secondary()
                            .and_then(OwnedParentError::io_source)
                            .and_then(io::Error::raw_os_error),
                        Some(9)
                    );
                }
                if scenario == "new_read" {
                    std::fs::remove_dir(&status_path)
                        .expect("remove owned directory read-error control");
                    std::fs::write(&status_path, &valid).expect("restore semantic status file");
                }
            }
            println!(
                "owned parent occurrence controls: scenarios=11 duplicate_refusals=11 once_close=11"
            );
            // The semantic 4096-member cap script shares the production decision;
            // a small native cohort separately supplies cold-read/retirement evidence.
            let mut members: std::collections::BTreeSet<_> =
                (1_000_000_000..1_000_004_095).collect();
            members.insert(old_tid);
            assert_eq!(members.len(), 4096);
            let mut cohort = std::collections::BTreeMap::from([(
                pid,
                std::fs::File::open("/proc/self/status").expect("native live cap-refresh member"),
            )]);
            let mut refreshes = 0;
            let mut reads = 0;
            let mut opens = 0;
            let deadline = Instant::now() + Duration::from_millis(250);
            let mut at_cap = parent_task_capacity(members.len(), || {
                refreshes += 1;
                assert!(
                    !parent_read_cohort(
                        &mut cohort,
                        pid,
                        deadline,
                        None,
                        3,
                        &mut |_, _, phase| {
                            assert_eq!(phase, 3);
                            reads += 1;
                        }
                    )?,
                    "a live native member does not retire"
                );
                Ok(members.len())
            });
            if at_cap.is_ok() {
                at_cap = parent_task_entry(
                    &mut cohort,
                    &mut std::collections::BTreeSet::new(),
                    old_tid.to_string().as_bytes(),
                    (directory.as_fd(), pid),
                    deadline,
                    None,
                    &mut |_, _, phase| {
                        if phase == 0 {
                            opens += 1;
                        }
                    },
                );
            }
            assert_eq!(
                at_cap
                    .expect_err(
                        "full retained cohort cannot open an extra status without retirement"
                    )
                    .cause(),
                OwnedFaultCause::Limit {
                    field: 7,
                    limit: 4096,
                    observed: 4097
                }
            );
            assert_eq!(
                refreshes, 1,
                "one bounded refresh precedes aggregate-cap refusal"
            );
            assert_eq!(reads, 1, "the separate native live cohort is cold read");
            assert_eq!(opens, 0, "aggregate cap is checked before the new open");
            cohort.insert(
                old_tid,
                dead_template
                    .try_clone()
                    .expect("native retired cap member"),
            );
            let target = 1_000_004_097_u32;
            std::fs::create_dir(current.path().join(target.to_string()))
                .expect("new capped current entry");
            std::fs::write(
                current.path().join(format!("{target}/status")),
                format!("Pid:\t{target}\nTgid:\t{pid}\nTracerPid:\t0\nThreads:\t4096\n"),
            )
            .expect("independent new capped identity");
            refreshes = 0;
            reads = 0;
            let mut retired = 0;
            let deadline = Instant::now() + Duration::from_millis(250);
            parent_task_capacity(members.len(), || {
                refreshes += 1;
                assert!(
                    parent_read_cohort(
                        &mut cohort,
                        pid,
                        deadline,
                        None,
                        3,
                        &mut |tid, _, phase| {
                            if phase == 3 {
                                reads += 1;
                            }
                            if phase == 4 {
                                assert_eq!(tid, old_tid);
                                retired += 1;
                            }
                        }
                    )?,
                    "the held native old identity actually retires"
                );
                assert!(!cohort.contains_key(&old_tid));
                assert!(members.remove(&old_tid));
                Ok(members.len())
            })
            .expect("one actual removal permits the next status acquisition");
            let mut new_validation = Vec::new();
            parent_task_entry(
                &mut cohort,
                &mut std::collections::BTreeSet::new(),
                target.to_string().as_bytes(),
                (directory.as_fd(), pid),
                deadline,
                None,
                &mut |tid, _, phase| {
                    assert_eq!(tid, target);
                    new_validation.push(phase);
                    if phase == 0 {
                        opens += 1;
                    }
                },
            )
            .expect("one separately validated new open after cap refresh");
            assert_eq!(
                new_validation,
                [0, 3],
                "cap refresh cannot replace fresh NEW validation"
            );
            assert!(members.insert(target));
            assert_eq!(
                (refreshes, reads, opens, retired, members.len()),
                (1, 2, 1, 1, 4096)
            );
            let mut cleanup = Ok(());
            let mut closed = 0;
            for (tid, status) in cohort {
                retire_parent_result(
                    status,
                    6,
                    deadline,
                    None,
                    &mut cleanup,
                    tid,
                    &mut |_, _, phase| {
                        assert_eq!(phase, 4);
                        closed += 1;
                    },
                );
            }
            cleanup.expect("checked once-only native cap-witness cleanup");
            assert_eq!(closed, 2);
            println!(
                "owned parent cap controls: semantic_members=4096 refusals=1 refreshes_per_branch=1 native_retirement=1 new_opens=1 native_closed=2"
            );
            for retire_after_count in [false, true] {
                let (stable_ready, stable_received) = std::sync::mpsc::sync_channel(1);
                let (stable_release, stable_released) = std::sync::mpsc::sync_channel(1);
                let stable_task = std::thread::spawn(move || {
                    let tid = std::fs::read_link("/proc/thread-self")
                        .expect("stable task identity")
                        .file_name()
                        .expect("stable task component")
                        .to_str()
                        .expect("decimal stable tid")
                        .parse::<u32>()
                        .expect("stable numeric tid");
                    stable_ready.send(tid).expect("publish stable task");
                    stable_released
                        .recv_timeout(Duration::from_secs(5))
                        .expect("bounded stable task gate");
                });
                let stable_tid = stable_received
                    .recv_timeout(Duration::from_secs(5))
                    .expect("stable survivor parked before traversal");
                let own_tid = std::fs::read_link("/proc/thread-self")
                    .expect("fixture task identity")
                    .file_name()
                    .expect("fixture task component")
                    .to_str()
                    .expect("decimal fixture tid")
                    .parse::<u32>()
                    .expect("fixture numeric tid");
                let controlled = std::collections::BTreeSet::from([pid, own_tid, stable_tid]);
                let mut occurrence_reads = std::collections::BTreeMap::new();
                let mut before_count = true;
                let mut traversal_reads = Vec::new();
                let mut parked = Vec::new();
                let mut retired_tid = None;
                if retire_after_count {
                    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
                    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
                    let handle = std::thread::spawn(move || {
                        let tid = std::fs::read_link("/proc/thread-self")
                            .expect("retiring task identity")
                            .file_name()
                            .expect("retiring task component")
                            .to_str()
                            .expect("decimal tid")
                            .parse::<u32>()
                            .expect("retiring numeric tid");
                        ready_tx.send(tid).expect("publish retiring task");
                        release_rx
                            .recv_timeout(Duration::from_secs(5))
                            .expect("bounded retiring task gate");
                    });
                    let tid = ready_rx
                        .recv_timeout(Duration::from_secs(5))
                        .expect("retiring task parked");
                    retired_tid = Some(tid);
                    parked.push((tid, release_tx, handle));
                }
                let mut live = std::collections::BTreeMap::new();
                let mut original = std::collections::BTreeMap::new();
                let mut token = 0_u64;
                let mut directories = 0;
                let mut count_cuts = 0;
                let mut born = None;
                let mut lifetime_preserved = true;
                let mut closes = 0;
                let mut post_count = std::collections::BTreeSet::new();
                let late_result = ensure_parent_observing(None, &mut |tid, fd, phase| {
                    match phase {
                        0 => {
                            token += 1;
                            assert!(
                                live.insert(tid, (token, fd)).is_none(),
                                "every actual open starts a distinct lifetime"
                            );
                        }
                        4 if tid != 0 => {
                            assert_eq!(
                                live.remove(&tid).map(|(_, held)| held),
                                Some(fd),
                                "every consuming close ends one actual lifetime"
                            );
                            closes += 1;
                        }
                        5 => {
                            directories += 1;
                            before_count = true;
                            occurrence_reads.clear();
                        }
                        3 if before_count && controlled.contains(&tid) => {
                            *occurrence_reads.entry(tid).or_insert(0_u32) += 1;
                        }
                        1 if tid == pid => {
                            if before_count {
                                traversal_reads.push(occurrence_reads.clone());
                                before_count = false;
                            }
                            count_cuts += 1;
                            if original.is_empty() {
                                original = live
                                    .iter()
                                    .filter(|(tid, _)| controlled.contains(tid))
                                    .map(|(tid, lifetime)| (*tid, *lifetime))
                                    .collect();
                            }
                            for (old_tid, lifetime) in &original {
                                if Some(*old_tid) != retired_tid {
                                    lifetime_preserved &= live.get(old_tid) == Some(lifetime);
                                }
                            }
                        }
                        2 => {
                            post_count.insert(tid);
                        }
                        _ => {}
                    }
                    let birth_phase = if retire_after_count { 2 } else { 1 };
                    if tid == pid && phase == birth_phase && born.is_none() {
                        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
                        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
                        let handle = std::thread::spawn(move || {
                            let tid = std::fs::read_link("/proc/thread-self")
                                .expect("late task identity")
                                .file_name()
                                .expect("late task component")
                                .to_str()
                                .expect("decimal late tid")
                                .parse::<u32>()
                                .expect("late numeric tid");
                            ready_tx.send(tid).expect("publish late task");
                            release_rx
                                .recv_timeout(Duration::from_secs(5))
                                .expect("bounded late task gate");
                        });
                        let tid = ready_rx
                            .recv_timeout(Duration::from_secs(5))
                            .expect("late task parked");
                        born = Some(tid);
                        parked.push((tid, release_tx, handle));
                        if retire_after_count {
                            let (_, release, handle) = parked.remove(0);
                            release
                                .send(())
                                .expect("retire the old pinned task after count");
                            handle.join().expect("old pinned task joined");
                        }
                    }
                });
                for (_, release, handle) in parked {
                    release.send(()).expect("release each late parked task");
                    handle.join().expect("join each late parked task");
                }
                stable_release
                    .send(())
                    .expect("release the controlled survivor after terminal cleanup");
                stable_task.join().expect("join the controlled survivor");
                assert!(
                    late_result.is_ok(),
                    "finite late birth must reach a closed cut: {late_result:?}"
                );
                for reads in &traversal_reads {
                    for tid in &controlled {
                        assert_eq!(
                            reads.get(tid),
                            Some(&1),
                            "one occurrence cold read per controlled survivor before count, without batch or EOF refresh"
                        );
                    }
                }
                assert_eq!(
                    original.len(),
                    controlled.len(),
                    "every controlled survivor needs its old open-lifetime token"
                );
                assert!(
                    lifetime_preserved,
                    "surviving old status lifetimes must remain open across the late-birth traversal"
                );
                assert_eq!(
                    directories, 2,
                    "one finite late birth requires exactly one fresh traversal"
                );
                assert!(count_cuts >= 2);
                assert!(
                    born.is_some_and(|tid| post_count.contains(&tid)),
                    "the independently born task must be cold read after count"
                );
                assert!(
                    live.is_empty(),
                    "every acquired status must receive a consuming checked close"
                );
                assert_eq!(token, closes);
                println!(
                    "owned parent late birth: after_count={retire_after_count} acquisitions={directories} opens={token} checked_closes={closes} preserved={lifetime_preserved}"
                );
            }
        }
        lifecycle_controls();
        let pid = std::process::id();
        ensure_owned_parent_protected()
            .expect("an ordinary untraced test process must be protected");
        // SAFETY: PR_GET_DUMPABLE has no pointer operands or effects.
        assert_eq!(
            // SAFETY: PR_GET_DUMPABLE observes this thread without pointer operands.
            unsafe { prctl(3, 0, 0, 0, 0) },
            0,
            "the parent must be permanently non-dumpable before allocation"
        );
        use std::io::Read as _;
        use std::os::unix::net::UnixStream;
        use std::process::{Command, Stdio};
        struct HeldHelper(std::process::Child);
        impl Drop for HeldHelper {
            fn drop(&mut self) {
                if !matches!(self.0.try_wait(), Ok(Some(_))) {
                    drop(self.0.kill());
                    drop(self.0.wait());
                }
            }
        }
        let (mut parent_control, child_control) = UnixStream::pair().expect("private control pair");
        parent_control
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("bounded control read");
        let mut command = Command::new(helper_binary().expect("actual native helper"));
        command
            .args([
                "owned",
                "worker",
                &child_control.as_raw_fd().to_string(),
                &(owned_monotonic_ns().expect("native monotonic clock") + 3_000_000_000)
                    .to_string(),
                "--",
                "/bin/sh",
                "-c",
                "exit 23",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .env_clear();
        let mut held = HeldHelper(
            spawn_owned_control(
                command,
                &child_control,
                Instant::now() + Duration::from_secs(3),
                None,
            )
            .expect("spawn native owned prefix"),
        );
        drop(child_control);
        let mut bytes = Vec::new();
        parent_control
            .by_ref()
            .take(257)
            .read_to_end(&mut bytes)
            .expect("bounded native control records");
        assert!(
            bytes.starts_with(b"owned-launch-v1 entry worker "),
            "the native prefix must emit authenticated entry before the payload terminal: {bytes:?}"
        );
        assert!(
            bytes.ends_with(b"owned-launch-v1 terminal exit 23\n"),
            "the native prefix must preserve payload exit23 separately from waiter0: {bytes:?}"
        );
        assert!(
            held.0
                .wait()
                .expect("normal trusted waiter completion")
                .success()
        );

        fn creator_thread_death_control() {
            use std::io::Read as _;
            use std::os::fd::AsFd as _;
            let root_pid = std::process::id();
            let (published, publication) = std::sync::mpsc::sync_channel(1);
            let (release, released) = std::sync::mpsc::sync_channel(1);
            let creator = std::thread::spawn(move || {
                let identity =
                    std::fs::read_link("/proc/thread-self").expect("actual creator task identity");
                let tid = identity
                    .file_name()
                    .expect("creator TID")
                    .to_str()
                    .expect("decimal creator TID")
                    .parse::<u32>()
                    .expect("native creator TID");
                assert_ne!(root_pid, tid);
                let (parent_control, child_control) =
                    UnixStream::pair().expect("creator private control pair");
                let mut command =
                    Command::new(owned_helper_binary().expect("actual creator native helper"));
                command
                    .args([
                        "owned",
                        "worker",
                        &child_control.as_raw_fd().to_string(),
                        &(owned_monotonic_ns().expect("creator native clock") + 3_000_000_000)
                            .to_string(),
                        "--",
                        "/bin/sh",
                        "-c",
                        "printf ready; read ignored",
                    ])
                    .env_clear()
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped());
                let held = HeldHelper(
                    spawn_owned_control(
                        command,
                        &child_control,
                        Instant::now() + Duration::from_secs(3),
                        None,
                    )
                    .expect("creator launches with original process PID"),
                );
                drop(child_control);
                published
                    .send((held, parent_control, tid))
                    .expect("publish held native waiter before creator exit");
                released
                    .recv_timeout(Duration::from_secs(5))
                    .expect("bounded creator release gate");
            });
            let (mut held, mut control, tid) = publication
                .recv_timeout(Duration::from_secs(5))
                .expect("published creator waiter custody");
            let waiter_pid = held.0.id();
            let _pidfd =
                owned_waiter_pidfd(waiter_pid).expect("hold unreaped creator waiter identity");
            control
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("bounded creator entry read");
            let mut entry = Vec::new();
            loop {
                let mut byte = [0];
                control
                    .read_exact(&mut byte)
                    .expect("read native creator entry");
                entry.push(byte[0]);
                assert!(entry.len() <= 128);
                if byte[0] == b'\n' {
                    break;
                }
            }
            assert!(matches!(
                parse_owned_record(&entry).expect("actual creator entry"),
                OwnedRecord::Entry {
                    profile: OwnedProfile::Worker,
                    verified: 63,
                    ..
                }
            ));
            let stdout = held
                .0
                .stdout
                .as_mut()
                .expect("owned creator payload stdout");
            wait_ready(&[stdout.as_fd()], &[], Duration::from_secs(3))
                .expect("bounded actual payload readiness");
            let mut ready = [0; 5];
            stdout
                .read_exact(&mut ready)
                .expect("actual payload is parked before creator death");
            assert_eq!(&ready, b"ready");
            println!(
                "owned creator thread before exit root_pid={root_pid} creator_tid={tid} waiter_pid={waiter_pid} entry={:?} payload_ready=true root_alive=true",
                String::from_utf8_lossy(&entry)
            );
            release
                .send(())
                .expect("release only the owned creator task");
            creator.join().expect("actual creator thread exited");
            let deadline = Instant::now() + Duration::from_secs(5);
            let status = loop {
                if let Some(status) = held.0.try_wait().expect("observe owned creator waiter") {
                    break status;
                }
                assert!(
                    Instant::now() < deadline,
                    "creator death must deliver bounded kernel SIGKILL"
                );
                std::thread::sleep(Duration::from_millis(10));
            };
            use std::os::unix::process::ExitStatusExt as _;
            println!(
                "owned creator thread actual wait root_pid={root_pid} creator_tid={tid} waiter_pid={waiter_pid} status={status:?}"
            );
            assert_eq!(status.signal(), Some(9));
            assert_eq!(std::process::id(), root_pid);
            assert!(!Path::new(&format!("/proc/{root_pid}/task/{tid}")).exists());
            println!(
                "owned creator thread after exit root_pid={root_pid} creator_tid={tid} waiter_pid={waiter_pid} actual_waiter={status:?} root_alive=true creator_gone=true waiter_reaped=true"
            );
        }
        creator_thread_death_control();
        std::thread::spawn(|| {
            #[repr(C)]
            struct Filter { code: u16, jt: u8, jf: u8, value: u32 }
            #[repr(C)]
            struct Program { length: u16, filter: *const Filter }
            #[cfg(target_arch = "x86_64")]
            const CAPSET: std::os::raw::c_long = 126;
            #[cfg(target_arch = "aarch64")]
            const CAPSET: std::os::raw::c_long = 91;
            let filters = [
                Filter { code: 0x20, jt: 0, jf: 0, value: 0 },
                Filter { code: 0x15, jt: 0, jf: 1, value: CAPSET as u32 },
                Filter { code: 0x06, jt: 0, jf: 0, value: 0x00050005 },
                Filter { code: 0x06, jt: 0, jf: 0, value: 0x7fff0000 },
            ];
            let program = Program { length: 4, filter: filters.as_ptr() };
            // SAFETY: these fixed options restrict only this owned fixture thread;
            // the kernel copies its aligned immutable filter before returning.
            assert_eq!(unsafe { prctl(38, 1, 0, 0, 0) }, 0);
            // SAFETY: the live aligned program contains four bounded instructions.
            assert_eq!(unsafe { prctl(22, 2, &program, 0, 0) }, 0);
            // SAFETY: the admitted filter returns before dereferencing capset operands.
            assert_eq!(unsafe { parent_syscall(CAPSET, std::ptr::null::<u8>(), std::ptr::null::<u8>()) }, -1);
            assert_eq!(io::Error::last_os_error().raw_os_error(), Some(5));
            println!("owned native child capset independent return=-1 errno=5");
            let (mut parent_control, child_control) = UnixStream::pair().expect("owned capset control pair");
            parent_control.set_read_timeout(Some(Duration::from_secs(5))).expect("bounded capset control read");
            let mut command = Command::new(owned_helper_binary().expect("actual installed native helper"));
            command.args([
                "owned", "worker", &child_control.as_raw_fd().to_string(),
                &(owned_monotonic_ns().expect("native clock") + 3_000_000_000).to_string(),
                "--", "/bin/true",
            ]).env_clear().stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped());
            let mut held = HeldHelper(spawn_owned_control(command, &child_control, Instant::now() + Duration::from_secs(3), None).expect("spawn actual capset fault leg"));
            drop(child_control);
            let mut bytes = Vec::new();
            parent_control.by_ref().take(257).read_to_end(&mut bytes).expect("read actual bounded capset fault");
            println!("owned native child capset actual delivered={:?}", String::from_utf8_lossy(&bytes));
            assert_eq!(bytes, b"owned-launch-v1 terminal fault owned.child.capabilities 0001 0000000000000010 0000000000000000 0000000000000005\n");
            let fault = parse_owned_record(&bytes).expect("parse actual delivered capset fault");
            assert!(matches!(fault, OwnedRecord::Fault(fault) if fault.boundary() == "owned.child.capabilities" && fault.cause() == OwnedFaultCause::Io { operation: 16, field: 0, errno: 5 }));
            let mut sequence = OwnedSequence::default();
            sequence.push(fault).expect("actual singleton child fault");
            assert!(!sequence.released(true, false));
            let status = held.0.wait().expect("reap actual capset waiter");
            println!("owned native child capset actual waiter={status:?}");
            assert_eq!(status.code(), Some(10));
        }).join().expect("join the owned native capset fixture");

        {
            #[repr(C)]
            struct Filter {
                code: u16,
                jt: u8,
                jf: u8,
                value: u32,
            }
            #[repr(C)]
            struct Program {
                length: u16,
                filter: *const Filter,
            }
            unsafe extern "C" {
                fn unshare(flags: i32) -> i32;
            }
            #[cfg(target_arch = "x86_64")]
            let (arch, number) = (0xc000_003e_u32, 272_u32);
            #[cfg(target_arch = "aarch64")]
            let (arch, number) = (0xc000_00b7_u32, 97_u32);
            let instructions = [
                (0x20_u16, 0_u8, 0_u8, 4_u32),
                (0x15, 0, 3, arch),
                (0x20, 0, 0, 0),
                (0x15, 0, 1, number),
                (0x06, 0, 0, 0x0005_0001),
                (0x06, 0, 0, 0x7fff_0000),
            ];
            let mut bytes = Vec::new();
            let filters: Vec<_> = instructions
                .into_iter()
                .map(|(code, jt, jf, value)| {
                    bytes.extend_from_slice(&code.to_le_bytes());
                    bytes.extend_from_slice(&[jt, jf]);
                    bytes.extend_from_slice(&value.to_le_bytes());
                    Filter {
                        code,
                        jt,
                        jf,
                        value,
                    }
                })
                .collect();
            let program = Program {
                length: 6,
                filter: filters.as_ptr(),
            };
            // SAFETY: the aligned immutable BPF is copied by the kernel and
            // restricts only this disposable thread after all namespace positives.
            assert_eq!(unsafe { prctl(38, 1, 0, 0, 0) }, 0);
            // SAFETY: the live aligned program is copied by the kernel for this thread.
            assert_eq!(unsafe { prctl(22, 2, &program, 0, 0) }, 0);
            // SAFETY: this denied native unshare has no pointer operands and
            // cannot create a child; errno is captured before another syscall.
            let returned = unsafe { unshare(0x1000_0000) };
            let native = io::Error::last_os_error();
            assert_eq!(returned, -1);
            assert_eq!(native.raw_os_error(), Some(1));
            println!(
                "owned namespace independent native witness: arch={arch} syscall={number} flags=268435456 filter={bytes:?} returned={returned} errno=1 nochild=true"
            );
        }

        fn install_guard_eio(calls: &[(u32, u32)]) {
            #[repr(C)]
            struct Filter {
                code: u16,
                jt: u8,
                jf: u8,
                value: u32,
            }
            #[repr(C)]
            struct Program {
                length: u16,
                filter: *const Filter,
            }
            #[cfg(target_arch = "x86_64")]
            const ARCH: u32 = 0xc000_003e;
            #[cfg(target_arch = "aarch64")]
            const ARCH: u32 = 0xc000_00b7;
            let mut words = vec![
                (0x20, 0, 0, 4),
                (0x15, 1, 0, ARCH),
                (0x06, 0, 0, 0x7fff_0000),
            ];
            for &(number, argument) in calls {
                words.extend([
                    (0x20, 0, 0, 0),
                    (0x15, 0, 3, number),
                    (0x20, 0, 0, 16),
                    (0x15, 0, 1, argument),
                    (0x06, 0, 0, 0x0005_0005),
                ]);
            }
            words.push((0x06, 0, 0, 0x7fff_0000));
            let filters: Vec<_> = words
                .into_iter()
                .map(|(code, jt, jf, value)| Filter {
                    code,
                    jt,
                    jf,
                    value,
                })
                .collect();
            let program = Program {
                length: u16::try_from(filters.len()).expect("bounded native fault filter"),
                filter: filters.as_ptr(),
            };
            // SAFETY: these options restrict only the current disposable test
            // thread; aligned instructions remain alive throughout the kernel copy.
            assert_eq!(unsafe { prctl(38, 1, 0, 0, 0) }, 0);
            // SAFETY: the live aligned program is copied by the kernel for this thread.
            assert_eq!(unsafe { prctl(22, 2, &program, 0, 0) }, 0);
        }
        #[cfg(target_arch = "x86_64")]
        let (read_number, close_number, prctl_number) = (0, 3, 157);
        #[cfg(target_arch = "aarch64")]
        let (read_number, close_number, prctl_number) = (63, 57, 167);
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
        let retiring = std::thread::spawn(move || {
            let tid = std::fs::read_link("/proc/thread-self")
                .expect("native EIO task identity")
                .file_name()
                .expect("native EIO identity component")
                .to_str()
                .expect("native EIO decimal identity")
                .parse::<u32>()
                .expect("native EIO numeric identity");
            ready_tx.send(tid).expect("publish native EIO task");
            release_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("bounded EIO retirement gate");
        });
        let retiring_tid = ready_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("native EIO task parked");
        let mut retiring = Some((release_tx, retiring));
        let mut pending = Vec::new();
        let mut old_close_attempts = 0;
        let old_close = ensure_parent_observing(None, &mut |tid, fd, phase| {
            if tid == pid
                && phase == 2
                && let Some((release, handle)) = retiring.take()
            {
                release.send(()).expect("retire EIO task after count");
                handle.join().expect("join native EIO retired task");
            }
            if tid == retiring_tid && phase == 4 {
                old_close_attempts += 1;
                pending.push((tid, fd));
                install_guard_eio(&[(close_number, u32::try_from(fd).expect("native status fd"))]);
            }
        })
        .expect_err("actual old status close EIO must abort contraction");
        if let Some((release, handle)) = retiring {
            release
                .send(())
                .expect("release native task after earlier failure");
            handle
                .join()
                .expect("join native task after earlier failure");
        }
        assert_eq!(old_close_attempts, 1);
        assert_eq!(
            old_close.cause(),
            OwnedFaultCause::Io {
                operation: 7,
                field: 6,
                errno: 5
            }
        );
        assert_eq!(
            old_close.io_source().and_then(io::Error::raw_os_error),
            Some(5)
        );
        assert!(old_close.secondary().is_none());
        assert!(old_close.request_stop().is_none());

        for read_failure in [false, true] {
            let cancelled = Cell::new(false);
            let cancel = || cancelled.get();
            let request = Some(ParentRequest {
                deadline: Instant::now() + Duration::from_secs(5),
                cancel: Some(&cancel),
            });
            let mut selected = None;
            let mut closes = 0;
            let error = ensure_parent_observing(request, &mut |tid, fd, phase| {
                if tid == pid && phase == 0 && read_failure {
                    selected = Some(fd);
                    install_guard_eio(&[
                        (read_number, u32::try_from(fd).expect("native read fd")),
                        (close_number, u32::try_from(fd).expect("native close fd")),
                    ]);
                }
                if tid == pid && phase == 4 {
                    closes += 1;
                    if !read_failure {
                        selected = Some(fd);
                        install_guard_eio(&[(
                            close_number,
                            u32::try_from(fd).expect("native final close fd"),
                        )]);
                    }
                    cancelled.set(true);
                }
            })
            .expect_err("actual read or final close EIO must survive late cancellation");
            assert_eq!(closes, 1);
            assert_eq!(
                error.cause(),
                OwnedFaultCause::Io {
                    operation: if read_failure { 5 } else { 7 },
                    field: if read_failure { 9 } else { 6 },
                    errno: 5
                }
            );
            assert_eq!(error.io_source().and_then(io::Error::raw_os_error), Some(5));
            assert!(error.request_stop().is_none());
            let secondary = error.secondary();
            assert_eq!(
                secondary.map(OwnedParentError::cause),
                read_failure.then_some(OwnedFaultCause::Io {
                    operation: 7,
                    field: 6,
                    errno: 5
                })
            );
            assert_eq!(
                secondary
                    .and_then(OwnedParentError::io_source)
                    .and_then(io::Error::raw_os_error),
                read_failure.then_some(5)
            );
            pending.push((pid, selected.expect("actual selected status fd")));
        }
        assert_eq!(pending.len(), 3);
        assert_eq!(
            pending
                .iter()
                .map(|(_, fd)| *fd)
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            3
        );
        for (tid, fd) in &pending {
            let path = std::fs::read_link(format!("/proc/self/fd/{fd}"))
                .expect("seccomp EIO retains an uncertain native fd");
            assert_eq!(
                path,
                PathBuf::from(format!("/proc/{pid}/task/{tid}/status"))
            );
        }
        println!(
            "owned parent native EIO: old_close=1 final_close=1 read_close_pair=1 pending_status_fds={pending:?} cleanup=kernel_process_exit_only"
        );
        // The last filter forbids GET_DUMPABLE on this test thread. No further
        // guard, spawn or product effect follows; the disposable target exits.
        install_guard_eio(&[(prctl_number, 3)]);
        let get = ensure_parent_observing(None, &mut |_, _, _| {
            panic!("GET failure must precede FD acquisition")
        })
        .expect_err("native GET_DUMPABLE EIO must refuse before allocation");
        assert_eq!(
            get.cause(),
            OwnedFaultCause::Io {
                operation: 2,
                field: 1,
                errno: 5
            }
        );
        assert_eq!(get.io_source().and_then(io::Error::raw_os_error), Some(5));
        assert!(get.secondary().is_none());
        assert!(get.request_stop().is_none());
        println!("owned parent native GET: errno=5 operation=2 field=1 acquisitions=0");
    }

    #[test]
    fn stat_pgrp_refuses_malformed_stat_lines() {
        // The stable fields sit after the LAST ')': a parse failure
        // (None) is the MalformedRecord refusal in group_members_platform,
        // never a silently skipped pid.
        assert_eq!(stat_pgrp("1 (sh) R 2 3 4"), Some(3));
        assert_eq!(stat_pgrp("no closing paren R 2 3"), None);
        assert_eq!(stat_pgrp("1 (sh) R x y z"), None);
    }

    #[test]
    fn resident_bytes_names_the_pid_on_a_failed_read() {
        // pid u32::MAX cannot exist: the statm read fails and the
        // refusal carries the pid — never a pid-less Io.
        match resident_bytes(u32::MAX) {
            Err(ProcessReadError::ReadFailed { pid, .. }) if pid == u32::MAX => {}
            other => panic!("a vanished pid must refuse typed naming the pid, got {other:?}"),
        }
    }

    /// Plants a fixture process table under a fresh temp root and points
    /// this thread's proc-root seam at it; whatever the leg left at the
    /// root — a planted table, an empty dir, a plain file, nothing — is
    /// removed when the body returns.
    fn with_proc_fixture(body: impl FnOnce(&Path)) {
        let owner = tempfile::TempDir::with_prefix("rivect-proc-fixture-").unwrap();
        let root = owner.path().join("proc");
        PROC_ROOT_OVERRIDE.with(|slot| *slot.borrow_mut() = Some(root.clone()));
        body(&root);
        PROC_ROOT_OVERRIDE.with(|slot| *slot.borrow_mut() = None);
    }

    /// Plants one fixture `/proc/<pid>` record; `None` fields are left out.
    fn plant_pid(
        root: &Path,
        pid: u32,
        status: Option<&str>,
        stat: Option<&str>,
        statm: Option<&str>,
    ) {
        let dir = root.join(pid.to_string());
        std::fs::create_dir_all(&dir).expect("create the fixture pid dir");
        if let Some(status) = status {
            std::fs::write(dir.join("status"), status).expect("write the fixture status");
        }
        if let Some(stat) = stat {
            std::fs::write(dir.join("stat"), stat).expect("write the fixture stat");
        }
        if let Some(statm) = statm {
            std::fs::write(dir.join("statm"), statm).expect("write the fixture statm");
        }
    }

    #[test]
    fn uid_process_count_charges_every_task_of_the_real_uid() {
        // SAFETY: getuid takes no arguments and returns the real uid.
        let uid = unsafe { getuid() };
        with_proc_fixture(|root| {
            for (pid, real_uid, threads) in
                [(60, uid, 3), (61, uid, 1), (62, uid.wrapping_add(1), 5)]
            {
                plant_pid(
                    root,
                    pid,
                    Some(&format!("Uid:\t{real_uid}\t0\t0\t0\nThreads:\t{threads}\n")),
                    None,
                    None,
                );
            }
            assert_eq!(uid_process_count().expect("count the fixture tasks"), 4);
        });
        with_proc_fixture(|root| {
            plant_pid(
                root,
                63,
                Some(&format!("Uid:\t{uid}\t0\t0\t0\n")),
                None,
                None,
            );
            assert!(matches!(
                uid_process_count(),
                Err(ProcessReadError::MalformedRecord { pid: 63 })
            ));
        });
        with_proc_fixture(|root| {
            plant_pid(
                root,
                64,
                Some(&format!("Uid:\t{uid}\t0\t0\t0\nThreads:\t\n")),
                None,
                None,
            );
            assert!(matches!(
                uid_process_count(),
                Err(ProcessReadError::MalformedRecord { pid: 64 })
            ));
        });
        with_proc_fixture(|root| {
            plant_pid(
                root,
                65,
                Some(&format!("Uid:\t{uid}\t0\t0\t0\nThreads:\tabc\n")),
                None,
                None,
            );
            assert!(matches!(
                uid_process_count(),
                Err(ProcessReadError::MalformedRecord { pid: 65 })
            ));
        });
        with_proc_fixture(|root| {
            plant_pid(
                root,
                66,
                Some(&format!("Uid:\t{uid}\t0\t0\t0\nThreads:\t0\n")),
                None,
                None,
            );
            assert!(matches!(
                uid_process_count(),
                Err(ProcessReadError::MalformedRecord { pid: 66 })
            ));
        });
        with_proc_fixture(|root| {
            plant_pid(
                root,
                67,
                Some(&format!(
                    "Uid:\t{uid}\t0\t0\t0\nThreads:\t18446744073709551616\n"
                )),
                None,
                None,
            );
            assert!(matches!(
                uid_process_count(),
                Err(ProcessReadError::MalformedRecord { pid: 67 })
            ));
        });
        with_proc_fixture(|root| {
            plant_pid(
                root,
                68,
                Some(&format!(
                    "Uid:\t{uid}\t0\t0\t0\nThreads:\t18446744073709551615\n"
                )),
                None,
                None,
            );
            assert_eq!(uid_process_count().expect("count u64::MAX tasks"), u64::MAX);
        });
        with_proc_fixture(|root| {
            let status = format!("Uid:\t{uid}\t0\t0\t0\nThreads:\t18446744073709551615\n");
            plant_pid(root, 69, Some(&status), None, None);
            plant_pid(root, 70, Some(&status), None, None);
            assert!(matches!(
                uid_process_count(),
                Err(ProcessReadError::MalformedRecord { pid: 69 | 70 })
            ));
        });
        with_proc_fixture(|root| {
            plant_pid(
                root,
                71,
                Some(&format!("Uid:\t{uid}\t0\t0\t0\nThreads:\t0\n")),
                None,
                None,
            );
            let dir = root.join("71");
            let status = std::fs::read_to_string(dir.join("status"))
                .expect("read the fixture status before replacing its pid directory");
            std::fs::remove_dir_all(&dir).expect("remove the fixture pid directory");
            std::os::unix::fs::symlink("71", &dir).expect("plant the self-loop pid symlink");
            assert!(matches!(
                parse_real_uid_status(71, &status),
                Err(ProcessReadError::MalformedRecord { pid: 71 })
            ));
        });
        with_proc_fixture(|root| {
            plant_pid(
                root,
                72,
                Some(&format!("Uid:\t{uid}\t0\t0\t0\nThreads:\t0\n")),
                None,
                None,
            );
            let dir = root.join("72");
            let status = std::fs::read_to_string(dir.join("status"))
                .expect("read the fixture status before removing its pid directory");
            std::fs::remove_dir_all(&dir).expect("remove the fixture pid directory");
            let outcome = parse_real_uid_status(72, &status);
            assert!(
                matches!(&outcome, Ok(None)),
                "a vanished pid with zero tasks must be skipped, got {outcome:?}"
            );
        });
    }

    #[test]
    fn scan_cap_refusal_surfaces_through_the_public_count_and_listing() {
        // SAFETY: getuid takes no arguments and returns the real uid.
        let uid = unsafe { getuid() };
        with_proc_fixture(|root| {
            for pid in [10_u32, 11, 12] {
                plant_pid(
                    root,
                    pid,
                    Some(&format!("Uid:\t{uid}\t0\t0\t0\nThreads:\t1\n")),
                    Some(&format!("{pid} (sleep) S 1 0 1\n")),
                    None,
                );
            }
            // Under the planted cap the public count surfaces every fixture
            // process of this real uid.
            SCAN_CAP_OVERRIDE.with(|cap| cap.set(3));
            assert_eq!(
                uid_process_count().expect("count the fixture under the cap"),
                3
            );
            // One process past the cap is the typed ScanCapExceeded refusal
            // through the public surface — never a truncated count.
            SCAN_CAP_OVERRIDE.with(|cap| cap.set(2));
            assert!(matches!(
                uid_process_count(),
                Err(ProcessReadError::ScanCapExceeded)
            ));
            assert!(matches!(
                process_group_members(7),
                Err(ProcessReadError::ScanCapExceeded)
            ));
        });
        SCAN_CAP_OVERRIDE.with(|cap| cap.set(PROCESS_SCAN_CAP));
    }

    #[test]
    fn malformed_status_surfaces_as_a_pid_named_refusal() {
        with_proc_fixture(|root| {
            // A status record with no Uid: line at all.
            plant_pid(
                root,
                30,
                Some("Name:\tbroken\nVmRSS:\t1 kB\nThreads:\t1\n"),
                None,
                None,
            );
            assert!(matches!(
                uid_process_count(),
                Err(ProcessReadError::MalformedRecord { pid: 30 })
            ));
        });
        with_proc_fixture(|root| {
            // A Uid: line whose real-uid field is not decimal.
            plant_pid(
                root,
                31,
                Some("Uid:\tabc\t0\t0\t0\nThreads:\t1\n"),
                None,
                None,
            );
            assert!(matches!(
                uid_process_count(),
                Err(ProcessReadError::MalformedRecord { pid: 31 })
            ));
        });
    }

    #[test]
    fn malformed_group_stat_surfaces_after_the_bounded_reread() {
        with_proc_fixture(|root| {
            plant_pid(root, 20, None, Some("20 (sleep) S 1 7 1\n"), None);
            // A live pid whose stat never reaches a pgrp field: the bounded
            // re-read settles on the typed refusal naming the pid.
            plant_pid(root, 21, None, Some("21 (broken) S\n"), None);
            assert!(matches!(
                process_group_members(7),
                Err(ProcessReadError::MalformedRecord { pid: 21 })
            ));
        });
    }

    #[test]
    fn resident_bytes_maps_missing_nondecimal_and_overflowing_statm() {
        with_proc_fixture(|root| {
            // A statm with no resident field at all.
            plant_pid(root, 40, None, None, Some("4096\n"));
            assert!(matches!(
                resident_bytes(40),
                Err(ProcessReadError::MalformedRecord { pid: 40 })
            ));
        });
        with_proc_fixture(|root| {
            // A non-decimal resident field.
            plant_pid(root, 41, None, None, Some("4096 33x\n"));
            assert!(matches!(
                resident_bytes(41),
                Err(ProcessReadError::MalformedRecord { pid: 41 })
            ));
        });
        with_proc_fixture(|root| {
            // A resident page count whose byte total overflows u64.
            plant_pid(
                root,
                42,
                None,
                None,
                Some("18446744073709551615 18446744073709551615\n"),
            );
            assert!(matches!(
                resident_bytes(42),
                Err(ProcessReadError::MalformedRecord { pid: 42 })
            ));
        });
        // The positive mapping: resident pages times the live page size.
        with_proc_fixture(|root| {
            plant_pid(root, 43, None, None, Some("16 3 0 1 0 0 0\n"));
            // SAFETY: getpagesize takes no arguments and returns the page size.
            let page = u64::try_from(unsafe { getpagesize() }).expect("positive page size");
            assert_eq!(
                resident_bytes(43).expect("map a well-formed statm"),
                3 * page
            );
        });
    }
    #[test]
    fn missing_records_refuse_readfailed_through_public_count_and_listing() {
        with_proc_fixture(|root| {
            // The pid directory is present — the fixture just planted it
            // — but its status/stat records are absent: a read of a
            // demonstrably present pid fails ENOENT, which is neither
            // the vanished-pid ESRCH nor a gone entry, so both public
            // surfaces must refuse ReadFailed naming the pid with the
            // OS error retained, never a skipped record.
            plant_pid(root, 50, None, None, None);
            for refusal in [
                uid_process_count().map(|_| ()),
                process_group_members(7).map(|_| ()),
            ] {
                match refusal {
                    Err(ProcessReadError::ReadFailed { pid: 50, source }) => assert_eq!(
                        source.raw_os_error(),
                        Some(2),
                        "the ENOENT read failure stays in source()"
                    ),
                    other => panic!(
                        "a present pid with an absent record must refuse ReadFailed, got {other:?}"
                    ),
                }
            }
        });
    }

    #[test]
    fn unusable_proc_roots_refuse_io_through_public_count_and_listing() {
        // An empty table: the walk succeeds but visits no pid. The
        // caller itself is a process, so this is an unusable `/proc` —
        // an empty bind mount over it reads exactly like this — never a
        // host with zero processes: both public surfaces must refuse
        // with the pid-less Io, never Ok(0)/Ok(vec![]) that a
        // hard-NPROC check would take as a measured baseline.
        with_proc_fixture(|root| {
            std::fs::create_dir(root).expect("plant the empty fixture proc root");
            for refusal in [
                uid_process_count().map(|_| ()),
                process_group_members(7).map(|_| ()),
            ] {
                match refusal {
                    Err(ProcessReadError::Io(_)) => {}
                    other => panic!(
                        "an empty proc root must refuse Io through the public surface, got {other:?}"
                    ),
                }
            }
        });
        // A missing root: the enumeration-level open itself fails typed.
        with_proc_fixture(|_root| {
            for refusal in [
                uid_process_count().map(|_| ()),
                process_group_members(7).map(|_| ()),
            ] {
                match refusal {
                    Err(ProcessReadError::Io(_)) => {}
                    other => panic!(
                        "a missing proc root must refuse Io through the public surface, got {other:?}"
                    ),
                }
            }
        });
        // A non-directory root: the walk fails typed at the open.
        with_proc_fixture(|root| {
            std::fs::write(root, b"not a directory").expect("plant the non-directory root");
            for refusal in [
                uid_process_count().map(|_| ()),
                process_group_members(7).map(|_| ()),
            ] {
                match refusal {
                    Err(ProcessReadError::Io(_)) => {}
                    other => panic!(
                        "a non-directory proc root must refuse Io through the public surface, got {other:?}"
                    ),
                }
            }
        });
    }

    #[test]
    fn anchored_walk_opens_real_trees_and_refuses_symlink_components() {
        let owner = tempfile::TempDir::with_prefix("rivect-anchor-").unwrap();
        std::fs::create_dir_all(owner.path().join("a/b/c")).unwrap();
        // The fd walk refuses symlink components, so the walk target must
        // be the canonical spelling (a host temp dir under /var is a
        // symlink on macOS).
        let root = owner.path().canonicalize().unwrap();
        let nested = root.join("a/b/c");
        std::fs::write(nested.join("leaf"), b"anchor-bytes").unwrap();
        let components: Vec<std::ffi::OsString> = nested
            .components()
            .skip(1)
            .map(|component| component.as_os_str().to_owned())
            .collect();

        // Positive: root fd → component walk → leaf open.
        let mut current = open_filesystem_root().unwrap();
        for component in &components {
            current = openat_directory(&current, component.as_encoded_bytes()).unwrap();
        }
        let leaf = openat_leaf(&current, b"leaf", 1024).unwrap();
        let mut leaf = leaf;
        use std::io::Read as _;
        let mut bytes = Vec::new();
        leaf.file.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"anchor-bytes");
        assert_eq!(
            leaf.identity.nlink, 1,
            "a freshly written leaf has one link"
        );

        // A symlinked component refuses: the link still exists with its
        // leaf reachable by canonical path, but the fd walk never follows.
        let swapped = nested.join("swapped");
        std::fs::create_dir_all(&swapped).unwrap();
        let link = swapped.join("through");
        std::os::unix::fs::symlink(&nested, &link).unwrap();
        let through = openat_directory(&current, b"swapped").unwrap();
        match openat_directory(&through, b"through") {
            Err(FdOpenError::SymlinkComponent) => {}
            other => panic!("a symlinked component must refuse, got {other:?}"),
        }
        // `..` and empty components refuse lexically.
        match openat_directory(&through, b"..") {
            Err(FdOpenError::WrongKind) => {}
            other => panic!("a `..` component must refuse, got {other:?}"),
        }
        // A `/` inside a component or leaf name is a pathname escape
        // attempt, refused lexically before any syscall: `a/../b` and
        // `x/y` must never resolve, and a NUL byte is not a name.
        for hostile_dir in [b"a/../b".as_slice(), b"x/y".as_slice()] {
            match openat_directory(&current, hostile_dir) {
                Err(FdOpenError::WrongKind) => {}
                other => panic!("a path-bearing component must refuse, got {other:?}"),
            }
        }
        for hostile_leaf in [
            b"a/../b".as_slice(),
            b"x/y".as_slice(),
            b"nul\0name".as_slice(),
        ] {
            match openat_leaf(&current, hostile_leaf, 1024) {
                Err(FdOpenError::WrongKind) => {}
                other => panic!("a path-bearing leaf name must refuse, got {other:?}"),
            }
        }
        // A missing leaf names Missing; an oversize leaf names Oversize.
        match openat_leaf(&current, b"absent", 8) {
            Err(FdOpenError::Missing) => {}
            other => panic!("a missing leaf must refuse Missing, got {other:?}"),
        }
        std::fs::write(nested.join("big"), vec![b'b'; 32]).unwrap();
        match openat_leaf(&current, b"big", 8) {
            Err(FdOpenError::Oversize) => {}
            other => panic!("an oversize leaf must refuse Oversize, got {other:?}"),
        }
        // A hard-linked leaf names MultipleLinks, distinct from kind and
        // size (D-124 separable corrections).
        std::fs::hard_link(nested.join("big"), nested.join("big-link")).unwrap();
        match openat_leaf(&current, b"big", 1024) {
            Err(FdOpenError::MultipleLinks) => {}
            other => panic!("a multi-link leaf must refuse MultipleLinks, got {other:?}"),
        }
        // A symlinked leaf itself names the leaf seam.
        std::os::unix::fs::symlink("leaf", nested.join("leaf-link")).unwrap();
        match openat_leaf(&current, b"leaf-link", 1024) {
            Err(FdOpenError::SymlinkComponent) => {}
            other => panic!("a symlinked leaf must refuse, got {other:?}"),
        }
    }

    #[test]
    fn enotdir_refusals_are_settled_by_the_component_stat() {
        // Overlayfs answers ENOTDIR when O_NOFOLLOW refuses a symlink,
        // so the ambiguous errno must be settled by stat'ing the
        // component itself: a symlink names the symlink seam, a real
        // file keeps the wrong-kind refusal.
        let owner = tempfile::TempDir::with_prefix("rivect-classify-").unwrap();
        std::os::unix::fs::symlink("target", owner.path().join("link")).unwrap();
        std::fs::write(owner.path().join("file"), b"k").unwrap();
        let root = owner.path().canonicalize().unwrap();
        let mut parent = open_filesystem_root().unwrap();
        for component in root.components().skip(1) {
            parent = openat_directory(&parent, component.as_os_str().as_encoded_bytes()).unwrap();
        }
        let link = std::ffi::CString::new("link").unwrap();
        match classify_directory_refusal(&parent, &link, io::Error::from_raw_os_error(ENOTDIR)) {
            FdOpenError::SymlinkComponent => {}
            other => panic!(
                "a symlink behind an ENOTDIR refusal must name the symlink seam, got {other:?}"
            ),
        }
        let file = std::ffi::CString::new("file").unwrap();
        match classify_directory_refusal(&parent, &file, io::Error::from_raw_os_error(ENOTDIR)) {
            FdOpenError::WrongKind => {}
            other => panic!(
                "a regular file behind an ENOTDIR refusal keeps the kind refusal, got {other:?}"
            ),
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "lib unit tests assert boundary outcomes directly (standards §14)"
)]
mod anchored_exec {
    use super::*;

    /// Every descriptor of the anchored walk closes on exec. The child
    /// probes the actual descriptor numbers the parent holds (`-ef`
    /// compares inodes through `/dev/fd/<n>`), and a duplicate whose
    /// `FD_CLOEXEC` this test clears is the positive control: the same
    /// probe must observe exactly that one descriptor.
    #[test]
    fn anchored_fds_are_not_inherited_across_exec() {
        use std::os::fd::AsRawFd as _;
        let mut root = tempfile::TempDir::with_prefix("rivect-anchor-exec-").unwrap();
        let dir = root.path().canonicalize().unwrap();
        std::fs::write(dir.join("leaf"), b"anchored bytes").unwrap();
        let anchor_root = open_filesystem_root().unwrap();
        let mut pinned = open_filesystem_root().unwrap();
        for component in dir.components().skip(1) {
            use std::os::unix::ffi::OsStrExt as _;
            pinned = openat_directory(&pinned, component.as_os_str().as_bytes()).unwrap();
        }
        let leaf = openat_leaf(&pinned, b"leaf", 1024).unwrap();
        let control = leaf.file.try_clone().unwrap();
        // SAFETY: `control` is a live fd owned by this test; F_SETFD only
        // rewrites its descriptor flags (0 clears FD_CLOEXEC).
        assert_eq!(unsafe { fcntl(control.as_raw_fd(), 2, 0) }, 0);
        let leaf_path = dir.join("leaf");
        let probes = [
            ("anchored-root", anchor_root.fd.as_raw_fd(), "/".to_string()),
            (
                "anchored-dir",
                pinned.fd.as_raw_fd(),
                dir.display().to_string(),
            ),
            (
                "anchored-leaf",
                leaf.file.as_raw_fd(),
                leaf_path.display().to_string(),
            ),
            (
                "control",
                control.as_raw_fd(),
                leaf_path.display().to_string(),
            ),
        ];
        // The probe script is constant: every label, descriptor number and
        // path reaches it as a positional argument, never interpolated, and
        // the child sees only the PATH its shell may need.
        let output = std::process::Command::new("/bin/sh")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .args([
                "-c",
                "while [ \"$#\" -gt 0 ]; do [ \"/dev/fd/$2\" -ef \"$3\" ] && echo \"$1:$2\"; shift 3; done; true",
                "sh",
            ])
            .args(probes.iter().flat_map(|(label, fd, target)| {
                [(*label).to_owned(), fd.to_string(), target.clone()]
            }))
            .output();
        let output = match output {
            Ok(output) => output,
            Err(error) => {
                root.disable_cleanup(true);
                panic!(
                    "retained root {}: child reap unproven: {error}",
                    root.path().display()
                );
            }
        };
        assert!(output.status.success(), "{:?}", output.status);
        let observed = String::from_utf8_lossy(&output.stdout);
        assert_eq!(
            observed.trim_end(),
            format!("control:{}", control.as_raw_fd()),
            "only the control descriptor crosses exec; probes {probes:?}"
        );
        // The parent still holds every anchored descriptor, so an absent
        // line is not a vanished fd.
        assert!(leaf.identity.regular && pinned.identity.directory);
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    reason = "lib unit tests assert boundary outcomes directly (standards §14)"
)]
mod ofd_lock {
    use super::*;
    use std::io::Write as _;

    /// The one marker variable of the probe child: the lock target the
    /// parent made, so a child started any other way refuses.
    const PROBE_FILE: &str = "RIVECT_HELPER_LOCK_FILE";
    const PROBE_ENTRY: &str = "ofd_lock::lock_probe_child";

    /// One private root holding the lock target, beside two separate open
    /// file descriptions of it. The root is first, so it drops last.
    fn two_descriptions() -> (tempfile::TempDir, PathBuf, std::fs::File, std::fs::File) {
        let root = tempfile::TempDir::with_prefix("rivect-ofd-lock-").unwrap();
        let path = root.path().join("target");
        let open = || {
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(&path)
                .unwrap()
        };
        let (first, second) = (open(), open());
        (root, path, first, second)
    }

    /// One foreign probe: a child of this test binary takes `request`
    /// (`ofd <offset>` or `posix <offset> <len>`) on `target` and reports
    /// `held` or `acquired`. A step that fails leaves the child's reap
    /// unproven, so the root is retained before the panic.
    fn foreign_probe(
        owner: &mut tempfile::TempDir,
        target: &std::path::Path,
        request: &str,
    ) -> String {
        use std::process::{Command, Stdio};
        let steps = std::env::current_exe()
            .and_then(|exe| {
                Command::new(exe)
                    .args([PROBE_ENTRY, "--exact", "--ignored", "--nocapture"])
                    .env_clear()
                    .env(PROBE_FILE, target)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
            })
            .map(|mut child| {
                let wrote = child
                    .stdin
                    .take()
                    .map(|mut pipe| writeln!(pipe, "{request}"));
                (wrote, child.wait_with_output())
            });
        let output = match steps {
            Ok((Some(Ok(())), Ok(output))) => output,
            Ok((Some(Err(error)), _) | (_, Err(error))) | Err(error) => {
                owner.disable_cleanup(true);
                panic!(
                    "retained root {}: child reap unproven: {error}",
                    owner.path().display()
                );
            }
            Ok((None, _)) => {
                owner.disable_cleanup(true);
                panic!(
                    "retained root {}: child reap unproven: the child stdin pipe was missing",
                    owner.path().display()
                );
            }
        };
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("test result: ok. 1 passed;"),
            "the probe child failed ({}):\n{stdout}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        stdout
            .lines()
            .find_map(|line| {
                line.split_once("lock-probe: ")
                    .map(|(_, rest)| rest.to_owned())
            })
            .expect("the probe child printed its report")
    }

    /// Child entry: one foreign lock request on the target the marker
    /// names.
    #[test]
    #[ignore = "child entry started only by the ofd_lock probes"]
    fn lock_probe_child() {
        let target =
            std::env::var_os(PROBE_FILE).expect("the child entry runs only under its parent");
        assert_eq!(
            std::env::vars_os().count(),
            1,
            "the child environment holds only the marker"
        );
        let mut request = String::new();
        io::stdin().read_line(&mut request).unwrap();
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(target)
            .unwrap();
        let fields: Vec<&str> = request.split_whitespace().collect();
        let probed = match fields.as_slice() {
            ["ofd", offset] => ofd_try_write_lock(&file, offset.parse().unwrap()),
            ["posix", offset, len] => {
                posix_try_write_range(&file, offset.parse().unwrap(), len.parse().unwrap())
            }
            other => panic!("unknown probe request {other:?}"),
        };
        let outcome = match probed {
            Ok(()) => "acquired",
            Err(OfdLockError::Held) => "held",
            Err(error) => panic!("the probe failed: {error:?}"),
        };
        writeln!(io::stdout(), "lock-probe: {outcome}").unwrap();
    }

    #[test]
    fn ofd_write_lock_conflicts_across_descriptions_and_maps_errors() {
        let (mut root, path, first, second) = two_descriptions();
        ofd_try_write_lock(&first, 5).unwrap();
        assert!(matches!(
            ofd_try_write_lock(&second, 5),
            Err(OfdLockError::Held)
        ));
        assert_eq!(
            foreign_probe(&mut root, &path, "ofd 5"),
            "held",
            "another process's description conflicts too"
        );
        // A read-only description cannot take a write lock: EBADF is
        // neither a conflict nor an unsupported mechanism.
        let read_only = std::fs::File::open(&path).unwrap();
        assert!(matches!(
            ofd_try_write_lock(&read_only, 9),
            Err(OfdLockError::Io(_))
        ));
        // Independent platform literals, not the classifier's table, so a
        // dropped errno there fails. Linux headers: EINVAL 22
        // (asm-generic/errno-base.h), ENOLCK 37, ENOSYS 38, EOPNOTSUPP 95
        // (asm-generic/errno.h). Darwin libc: EINVAL 22, ENOTSUP 45, ENOLCK
        // 77, ENOSYS 78.
        #[cfg(target_os = "linux")]
        let unsupported = [
            ("EINVAL", 22),
            ("ENOLCK", 37),
            ("ENOSYS", 38),
            ("EOPNOTSUPP", 95),
        ];
        #[cfg(target_os = "macos")]
        let unsupported = [
            ("EINVAL", 22),
            ("ENOTSUP", 45),
            ("ENOLCK", 77),
            ("ENOSYS", 78),
        ];
        for (name, code) in unsupported {
            assert!(
                matches!(
                    classify_ofd_lock(io::Error::from_raw_os_error(code)),
                    OfdLockError::Unsupported
                ),
                "{name} ({code}) is the declared unsupported mechanism"
            );
        }
        for code in [EAGAIN, EACCES] {
            assert!(
                matches!(
                    classify_ofd_lock(io::Error::from_raw_os_error(code)),
                    OfdLockError::Held
                ),
                "errno {code} is a conflict"
            );
        }
        // ENOENT is declared in neither table.
        assert!(matches!(
            classify_ofd_lock(io::Error::from_raw_os_error(2)),
            OfdLockError::Io(_)
        ));
    }

    #[test]
    fn ofd_write_lock_lives_until_the_last_close_of_its_description() {
        use std::process::Command;
        const CHILD_ARGS: [&str; 3] = [
            "--exact",
            "ofd_lock::ofd_write_lock_lives_until_the_last_close_of_its_description",
            "--nocapture",
        ];
        const RESULT: &str = "test result: ok. 1 passed; 0 failed; 0 ignored;";
        // A sibling test's spawn holds a CLOEXEC copy of these descriptions
        // until its exec, so the last close is only observable in a process
        // that runs this test alone; the parent holds no fixture descriptor.
        if !std::env::args_os().skip(1).eq(CHILD_ARGS) {
            let output = std::env::current_exe()
                .and_then(|exe| {
                    let mut child = Command::new(exe);
                    child.args(CHILD_ARGS).env_clear();
                    if let Some(tmpdir) = std::env::var_os("TMPDIR") {
                        child.env("TMPDIR", tmpdir);
                    }
                    child.output()
                })
                .unwrap_or_else(|error| panic!("ofd last-close child reap unproven: {error}"));
            let stdout = String::from_utf8_lossy(&output.stdout);
            let named = format!("test {} ... ok", CHILD_ARGS[1]);
            let running = stdout
                .lines()
                .filter(|line| *line == "running 1 test")
                .count();
            let results = stdout
                .lines()
                .filter(|line| line.starts_with(RESULT))
                .count();
            let proved = output.status.success()
                && running == 1
                && results == 1
                && stdout.lines().any(|line| line == named);
            assert!(
                proved,
                "ofd last-close child failed: {}\n{stdout}\n{}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        let (_root, path, first, second) = two_descriptions();
        let duplicate = first.try_clone().unwrap();
        ofd_try_write_lock(&first, 7).unwrap();
        drop(first);
        assert!(matches!(
            ofd_try_write_lock(&second, 7),
            Err(OfdLockError::Held)
        ));
        // Opening and closing another description of the inode is not a
        // release: a POSIX lock would be dropped by that close.
        drop(std::fs::File::open(&path).unwrap());
        assert!(matches!(
            ofd_try_write_lock(&second, 7),
            Err(OfdLockError::Held)
        ));
        drop(duplicate);
        ofd_try_write_lock(&second, 7).unwrap();
    }

    #[test]
    fn ofd_write_lock_is_byte_exact() {
        let (mut root, path, first, second) = two_descriptions();
        // The byte after the locked one stays addressable on every target.
        let sentinel = i64::MAX - 2;
        ofd_try_write_lock(&first, sentinel).unwrap();
        // Another process's POSIX lock over exactly one byte conflicts at
        // the locked byte and is granted before and after it.
        for (offset, outcome) in [
            (sentinel - 1, "acquired"),
            (sentinel, "held"),
            (sentinel + 1, "acquired"),
        ] {
            assert_eq!(
                foreign_probe(&mut root, &path, &format!("posix {offset} 1")),
                outcome,
                "byte {offset}"
            );
        }
        ofd_try_write_lock(&second, sentinel - 1).unwrap();
        assert!(matches!(
            ofd_try_write_lock(&second, sentinel),
            Err(OfdLockError::Held)
        ));
    }

    #[test]
    fn ofd_unlock_releases_the_lock_while_a_duplicate_lives() {
        let (_root, _path, first, second) = two_descriptions();
        let duplicate = first.try_clone().unwrap();
        ofd_try_write_lock(&first, 11).unwrap();
        drop(first);
        // The duplicate keeps the description, and so the lock, alive.
        assert!(matches!(
            ofd_try_write_lock(&second, 11),
            Err(OfdLockError::Held)
        ));
        // An explicit unlock through any descriptor of the description
        // releases it while that duplicate is still open.
        ofd_unlock(&duplicate, 11).unwrap();
        ofd_try_write_lock(&second, 11).unwrap();
        // Unlocking a byte nobody locked is not an error.
        ofd_unlock(&duplicate, 13).unwrap();
        drop(duplicate);
    }
}
