//! Shared login-producer primitives: PKCE minting, bounded HTTP legs, form
//! and JSON exchange, JWT claim extraction, expiry arithmetic, the api-key
//! config binding gate and the redacted `Debug` token.
//!
//! Every primitive keeps its owner-local error vocabulary: the shared
//! [`CommonError`] is mapped into each producer's `LoginError`, so the
//! shipped login modules answer exactly the variants and Display text they
//! did before this extraction. Secret material — the PKCE verifier and every
//! token — never enters `Debug`, an error or a diagnostic.

use super::{
    CATALOG_MAX_BYTES, ProviderError, STREAM_CHUNK_BYTES, SecretRef, is_loopback_url, read_chunk,
    resolve_credential, transport,
};
use crate::config::{Config, ConnKind};
use serde_json::Value;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// The PKCE verifier's entropy: 32 bytes render a 43-character verifier,
/// the recorded minimum (RFC 7636 §4.1).
pub(super) const VERIFIER_BYTES: usize = 32;

/// One shared primitive failure. Each producer maps it into its own error
/// enum, so the login modules keep their owner-local variants and text.
#[derive(Debug, thiserror::Error)]
pub(super) enum CommonError {
    /// The platform entropy source could not fill a verifier or state.
    #[error("entropy source is unavailable: {cause}")]
    Entropy { cause: getrandom::Error },
    /// A bounded reply exceeded the shared byte bound.
    #[error("the response exceeds the byte bound")]
    ResponseTooLarge,
    /// A reply was not the JSON object the contract records.
    #[error("the endpoint answered malformed json")]
    MalformedResponse {
        #[source]
        cause: serde_json::Error,
    },
    /// The system clock is before the Unix epoch, so no expiry applies.
    #[error("system clock is before the unix epoch: {cause}")]
    Clock {
        #[source]
        cause: std::time::SystemTimeError,
    },
    /// A bounded read failed or its whole-leg deadline expired.
    #[error(transparent)]
    Transport(#[from] ProviderError),
}

/// One shared config-binding denial: a login path may write only a declared
/// `api_key` row. Each producer maps it into its own error enum, exactly as
/// it maps [`CommonError`].
#[derive(Debug, thiserror::Error)]
pub(super) enum BindingError {
    /// The connection a login path must bind is not declared in the config.
    #[error("connection {connection} is not declared")]
    ConnectionMissing { connection: String },
    /// The connection is declared with a kind the login path must not write.
    #[error("connection {connection} is {kind}, not an api key")]
    NotApiKey { connection: String, kind: ConnKind },
    /// The shipped resolution refused the binding.
    #[error(transparent)]
    Provider(#[from] ProviderError),
}

/// The `Debug` value a stored token renders as: `<redacted>`.
#[must_use]
pub(super) fn redacted(_secret: &str) -> &'static str {
    "<redacted>"
}

/// The printable class of a stored-profile parse failure. serde's own
/// message is dropped because it can quote the stored bytes.
pub(super) fn malformed_reason(cause: &serde_json::Error) -> &'static str {
    match cause.classify() {
        serde_json::error::Category::Io => "an io failure",
        serde_json::error::Category::Syntax => "invalid json",
        serde_json::error::Category::Data => "a value outside the profile shape",
        serde_json::error::Category::Eof => "truncated json",
    }
}

/// 32 bytes of OS entropy rendered base64url — the verifier and state share
/// this one draw helper.
pub(super) fn random_urlsafe() -> Result<String, CommonError> {
    let mut bytes = [0u8; VERIFIER_BYTES];
    getrandom::fill(&mut bytes).map_err(|cause| CommonError::Entropy { cause })?;
    Ok(base64url(&bytes))
}

/// 16 bytes of OS entropy rendered as a canonical UUID v4, the recorded
/// state shape. The version and variant bits are set in place so the
/// entropy draw stays fallible instead of a panicking constructor.
pub(super) fn random_uuid() -> Result<String, CommonError> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|cause| CommonError::Entropy { cause })?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(uuid::Uuid::from_bytes(bytes).to_string())
}

/// The S256 PKCE challenge of a verifier: SHA-256 over the verifier's
/// bytes, base64url without padding (RFC 7636 §4.2).
#[must_use]
pub(super) fn challenge_for(code_verifier: &str) -> String {
    use sha2::Digest as _;
    base64url(&sha2::Sha256::digest(code_verifier.as_bytes()))
}

/// Base64url without padding, hand-rolled so no codec dependency is added.
#[must_use]
pub(super) fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(chunk.get(1).copied().unwrap_or(0));
        let b2 = u32::from(chunk.get(2).copied().unwrap_or(0));
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(char::from(ALPHABET[((triple >> 18) & 0x3f) as usize]));
        out.push(char::from(ALPHABET[((triple >> 12) & 0x3f) as usize]));
        if chunk.len() > 1 {
            out.push(char::from(ALPHABET[((triple >> 6) & 0x3f) as usize]));
        }
        if chunk.len() > 2 {
            out.push(char::from(ALPHABET[(triple & 0x3f) as usize]));
        }
    }
    out
}

/// Base64url decoding for a token payload; both the URL alphabet and the
/// standard alphabet a peer may emit are accepted, padding optional.
#[must_use]
pub(super) fn base64url_decode(raw: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(raw.len() * 3 / 4);
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    for byte in raw.bytes() {
        let value = match byte {
            b'A'..=b'Z' => u32::from(byte - b'A'),
            b'a'..=b'z' => u32::from(byte - b'a') + 26,
            b'0'..=b'9' => u32::from(byte - b'0') + 52,
            b'-' | b'+' => 62,
            b'_' | b'/' => 63,
            b'=' => break,
            _ => return None,
        };
        buffer = (buffer << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

/// The JSON payload of a JWT with exactly three dot segments; a malformed
/// token answers `None` rather than a parse diagnostic that could quote token
/// bytes.
#[must_use]
#[expect(
    clippy::manual_ok_err,
    reason = "the parse refusal is the declared no-claims fallback, not a discarded error"
)]
pub(super) fn jwt_claims(token: &str) -> Option<Value> {
    let mut segments = token.split('.');
    segments.next()?;
    let payload = segments.next()?;
    segments.next()?;
    if segments.next().is_some() {
        return None;
    }
    let bytes = base64url_decode(payload)?;
    match serde_json::from_slice(&bytes) {
        Ok(claims) => Some(claims),
        // A malformed payload is the recorded no-claims fallback; the parse
        // error could quote token bytes, so it is never rendered.
        Err(_cause) => None,
    }
}

/// Seconds since the Unix epoch, or the clock denial.
pub(super) fn clock_seconds() -> Result<u64, CommonError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|cause| CommonError::Clock { cause })?
        .as_secs())
}

/// The stored expiry for a peer `expires_in` count with `skew` subtracted.
pub(super) fn expires_at(expires_in: u64, skew: Duration) -> Result<u64, CommonError> {
    Ok(clock_seconds()?
        .saturating_add(expires_in)
        .saturating_sub(skew.as_secs()))
}

/// The config binding a login path may write: a declared `api_key` row,
/// resolved to its scoped reference. Each producer maps the typed denial
/// into its own `LoginError`.
pub(super) fn api_key_reference(
    config: &Config,
    connection: &str,
) -> Result<SecretRef, BindingError> {
    let entry =
        config
            .connections
            .get(connection)
            .ok_or_else(|| BindingError::ConnectionMissing {
                connection: connection.to_string(),
            })?;
    if entry.kind != ConnKind::ApiKey {
        return Err(BindingError::NotApiKey {
            connection: connection.to_string(),
            kind: entry.kind,
        });
    }
    Ok(resolve_credential(config, connection)?)
}

/// One HTTP client under a whole-leg budget with redirects off.
pub(super) fn client(
    connection: &str,
    timeout: Duration,
) -> Result<reqwest::blocking::Client, ProviderError> {
    reqwest::blocking::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|err| transport(connection, err))
}

/// One bounded POST: the caller names the body form and any extra headers,
/// so a producer keeps its recorded headers without owning client setup.
pub(super) fn post(
    connection: &str,
    endpoint: &str,
    timeout: Duration,
    body: Body<'_>,
    headers: &[(&str, &str)],
) -> Result<(reqwest::blocking::Response, Instant), ProviderError> {
    let started = Instant::now();
    let client = client(connection, timeout)?;
    let mut request = client.post(endpoint);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let request = match body {
        Body::Json(value) => request.json(value),
        Body::Form(fields) => request
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(form_body(fields)),
    };
    let response = request.send().map_err(|err| transport(connection, err))?;
    Ok((response, started))
}

/// The body of one POST.
pub(super) enum Body<'a> {
    /// A JSON object.
    Json(&'a Value),
    /// Form fields, percent-encoded in order.
    Form(&'a [(&'a str, &'a str)]),
}

/// The reply under the leg's budget and byte bound — a dribbling or
/// oversized body is denied, never buffered unbounded.
pub(super) fn read_body(
    connection: &str,
    response: &mut reqwest::blocking::Response,
    deadline: Duration,
    started: Instant,
) -> Result<Vec<u8>, CommonError> {
    let mut body = Vec::new();
    let mut chunk = vec![0u8; STREAM_CHUNK_BYTES];
    loop {
        let read = read_chunk(connection, deadline, response, &mut chunk, started)?;
        if read == 0 {
            break;
        }
        if body.len() + read > CATALOG_MAX_BYTES {
            return Err(CommonError::ResponseTooLarge);
        }
        body.extend_from_slice(&chunk[..read]);
    }
    Ok(body)
}

/// A bounded reply parsed as the JSON object the contract records.
pub(super) fn parse_json(body: &[u8]) -> Result<Value, CommonError> {
    serde_json::from_slice(body).map_err(|cause| CommonError::MalformedResponse { cause })
}

/// A non-empty string member of a reply's top level.
#[must_use]
pub(super) fn text_field(reply: &Value, field: &str) -> Option<String> {
    reply
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

/// The recorded endpoint or a loopback contract peer; anything else would
/// carry secret material to a foreign host. The URL is parsed, so userinfo
/// never impersonates the host it precedes.
#[must_use]
pub(super) fn admitted_endpoint(endpoint: &str, recorded: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(endpoint) else {
        return false;
    };
    if !url.username().is_empty() || url.password().is_some() {
        return false;
    }
    if endpoint == recorded {
        return true;
    }
    url.scheme() == "http" && is_loopback_url(&url)
}

/// The canonical scheme/host class a rejected endpoint names — never the raw
/// URL, which may carry a code, userinfo or a verifier.
#[must_use]
pub(super) fn endpoint_origin(endpoint: &str) -> String {
    match reqwest::Url::parse(endpoint) {
        Ok(url) => match url.host_str() {
            Some(host) => format!("{}://{host}", url.scheme()),
            None => format!("{} url", url.scheme()),
        },
        Err(_parse) => "an unparseable url".to_string(),
    }
}

/// Percent-encodes everything outside the RFC 3986 unreserved set.
#[must_use]
pub(super) fn encode_component(raw: &str) -> String {
    super::percent_encode_component(raw)
}

/// The UTF-8 value of a percent-encoded query member; a malformed escape or
/// a non-UTF-8 value answers `None`, never a lossy guess.
#[must_use]
#[expect(
    clippy::manual_ok_err,
    reason = "a non-UTF-8 query member is the declared malformed-redirect answer"
)]
pub(super) fn percent_decode(raw: &str) -> Option<String> {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let high = bytes.get(index + 1).and_then(|b| hex_value(*b));
            let low = bytes.get(index + 2).and_then(|b| hex_value(*b));
            let (Some(high), Some(low)) = (high, low) else {
                return None;
            };
            out.push(high << 4 | low);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    match String::from_utf8(out) {
        Ok(value) => Some(value),
        // A non-UTF-8 query member is the recorded malformed-redirect answer.
        Err(_cause) => None,
    }
}

fn form_body(fields: &[(&str, &str)]) -> String {
    fields
        .iter()
        .map(|(name, value)| format!("{}={}", encode_component(name), encode_component(value)))
        .collect::<Vec<String>>()
        .join("&")
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn base64url_renders_the_recorded_client_id_bytes() {
        // The recorded client id is stored base64 in the source; the
        // hand-rolled codec is proven against those exact bytes.
        assert_eq!(
            base64url(&[
                0x9d, 0x1c, 0x25, 0x0a, 0xe6, 0x1b, 0x44, 0xd9, 0x88, 0xed, 0x59, 0x44, 0xd1, 0x96,
                0x2f, 0x5e
            ]),
            "nRwlCuYbRNmI7VlE0ZYvXg"
        );
    }

    /// RFC 7636 Appendix B: the recorded verifier's S256 challenge.
    #[test]
    fn challenge_matches_the_rfc7636_appendix_b_vector() {
        assert_eq!(
            challenge_for("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn jwt_claims_requires_exactly_three_dot_segments() {
        let payload = base64url(br#"{"sub":"auth0|user-fixture"}"#);
        assert_eq!(
            jwt_claims(&format!("header.{payload}.signature"))
                .and_then(|claims| claims.get("sub").cloned()),
            Some(json!("auth0|user-fixture"))
        );
        assert_eq!(jwt_claims(&format!("header.{payload}")), None);
        assert_eq!(jwt_claims(&payload), None);
        assert_eq!(
            jwt_claims(&format!("header.{payload}.signature.extra")),
            None
        );
        assert_eq!(jwt_claims("not-a-jwt"), None);
    }

    #[test]
    fn the_binding_gate_admits_only_a_declared_api_key_row() {
        let config = Config::parse_validated(
            "config_version = 1\n\
             [connections.devin]\n\
             kind = \"api_key\"\n\
             endpoint = \"https://api.devin.ai\"\n\
             credential_ref = \"keychain:rivect-test/devin\"\n\
             [connections.subscription]\n\
             kind = \"subscription\"\n\
             endpoint = \"https://example.invalid\"\n\
             credential_ref = \"keychain:rivect-test/subscription\"\n\
             [models.defaults]\n\
             model = { mode = \"auto\" }\n\
             effort = { mode = \"auto\" }\n\
             fallback = { mode = \"auto\" }\n",
        )
        .expect("the binding fixture parses");

        let reference = api_key_reference(&config, "devin").expect("the api-key row binds");
        assert_eq!(reference.raw(), "keychain:rivect-test/devin");

        let missing =
            api_key_reference(&config, "missing").expect_err("an undeclared connection denies");
        assert!(
            matches!(missing, BindingError::ConnectionMissing { .. }),
            "{missing}"
        );

        let subscription =
            api_key_reference(&config, "subscription").expect_err("a subscription row denies");
        assert!(
            matches!(
                subscription,
                BindingError::NotApiKey {
                    kind: ConnKind::Subscription,
                    ..
                }
            ),
            "{subscription}"
        );
    }
}
