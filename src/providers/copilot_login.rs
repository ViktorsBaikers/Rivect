//! GitHub Copilot device login lifecycle: the recorded device-code and
//! access-token legs, the enterprise-origin normalization and the canonical
//! scoped profile. Library-level — no CLI verb is added.
//!
//! The recorded contract is OMP's `registry/oauth/github-copilot.ts` and the
//! catalogue wire facts (`0133f7ff`): the Copilot CLI app client id
//! `Ov23ctDVkRmgkPke0Mmm`, `scope=read:user` and the CLI identity headers on
//! both device legs. A blank domain means `github.com`; a public GitHub host
//! folds onto it; every other host is the normalized enterprise origin whose
//! API base is `https://copilot-api.{domain}`. GitHub OAuth tokens are
//! long-lived, so the stored expiry is the recorded far-future ten-year value
//! and no refresh leg exists — the same token would serve one.
//!
//! Enrollment is create-only through [`CredentialStore::login`]: an occupied
//! scope or a refused store operation denies and leaves the prior bytes
//! untouched. The device code is one-time login state and never enters
//! `Debug`, an error or a diagnostic; the stored token is redacted in the
//! profile's `Debug`. Login posts no model-policy request — accepting model
//! policies is not part of the recorded login transition.

use super::login_common::{self, BindingError, Body, CommonError};
use super::{CredentialStore, ProviderError, SecretRef};
use crate::config::{Config, ConnKind};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;
use std::time::{Duration, Instant};

/// The recorded public Copilot CLI app id.
const CLIENT_ID: &str = "Ov23ctDVkRmgkPke0Mmm";
/// The recorded scope the device request asks for.
const SCOPE: &str = "read:user";
/// The recorded CLI identity the GitHub device legs carry.
const USER_AGENT: &str = "copilot/1.0.82";
const INTEGRATION_ID: &str = "copilot-developer-cli";
const HARNESS_ID: &str = "copilot-sdk";
/// The identity headers both device legs send; the form content type is set
/// by the shared bounded POST.
const OAUTH_HEADERS: [(&str, &str); 4] = [
    ("Accept", "application/json"),
    ("User-Agent", USER_AGENT),
    ("Copilot-Integration-Id", INTEGRATION_ID),
    ("Copilot-Harness-Id", HARNESS_ID),
];
/// The recorded device grant type.
const GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";
/// The connection a device-leg transport failure names before a caller has
/// bound one.
const CONNECTION: &str = "github-copilot";
/// The two recorded GitHub device paths.
const DEVICE_CODE_PATH: &str = "/login/device/code";
const ACCESS_TOKEN_PATH: &str = "/login/oauth/access_token";
/// The public device host a blank or public input folds onto.
const PUBLIC_DOMAIN: &str = "github.com";
/// The public hosts the recorded normalization folds onto `github.com`.
const PUBLIC_HOSTS: [&str; 3] = ["api.github.com", "github.com", "www.github.com"];

/// One device leg's whole budget, shared by connect, request and read.
const LOGIN_TIMEOUT: Duration = Duration::from_secs(30);

/// The recorded poll fallback and the RFC 8628 `slow_down` increment.
const DEFAULT_INTERVAL_SECONDS: u64 = 5;
const SLOW_DOWN_STEP: Duration = Duration::from_secs(5);

/// The recorded device-code lifetime when the peer omits one.
const DEFAULT_EXPIRY_SECONDS: u64 = 900;
/// The widest device lifetime this build admits. A peer value above it is a
/// contract violation, never an unbounded deadline.
const MAX_EXPIRY_SECONDS: u64 = 24 * 60 * 60;
/// The widest poll interval this build admits, so no peer value schedules a
/// poll far outside the device window.
const MAX_INTERVAL_SECONDS: u64 = 60 * 60;

/// The recorded far-future expiry: ten years (10 × 365.25 days) in seconds.
const FAR_FUTURE_SECONDS: u64 = 315_576_000;

/// The GitHub OAuth endpoints. Production callers pass
/// [`DeviceEndpoints::recorded`]; tests pass loopback peers. The override is
/// not a config surface.
#[derive(Debug, Clone)]
pub struct DeviceEndpoints {
    /// The recorded `POST https://{domain}/login/device/code` leg.
    pub device_code: String,
    /// The recorded `POST https://{domain}/login/oauth/access_token` leg.
    pub access_token: String,
}

impl DeviceEndpoints {
    /// The recorded endpoints for the normalized device domain.
    #[must_use]
    pub fn recorded(domain: &str) -> Self {
        Self {
            device_code: format!("https://{domain}{DEVICE_CODE_PATH}"),
            access_token: format!("https://{domain}{ACCESS_TOKEN_PATH}"),
        }
    }
}

/// One in-flight device-code leg: the normalized domain and its enterprise
/// facts, the peer-issued verification output, the one-time device handle
/// and the caller-driven schedule. `Debug` redacts the device handle — the
/// user code and verification URL are the only printable device output.
pub struct DeviceLoginSession {
    domain: String,
    enterprise_url: Option<String>,
    api_endpoint: Option<String>,
    verification_uri: String,
    user_code: String,
    device_code: String,
    interval: Duration,
    expires_in: u64,
    deadline: Instant,
    next_poll_at: Instant,
    endpoints: DeviceEndpoints,
}

impl fmt::Debug for DeviceLoginSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceLoginSession")
            .field("domain", &self.domain)
            .field("enterprise_url", &self.enterprise_url)
            .field("api_endpoint", &self.api_endpoint)
            .field("verification_uri", &self.verification_uri)
            .field("user_code", &self.user_code)
            .field("device_code", &login_common::redacted(&self.device_code))
            .field("interval", &self.interval)
            .field("expires_in", &self.expires_in)
            .finish()
    }
}

impl DeviceLoginSession {
    /// The normalized device host: `github.com` or the enterprise host.
    #[must_use]
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// The normalized non-public enterprise origin, absent on public GitHub.
    #[must_use]
    pub fn enterprise_url(&self) -> Option<&str> {
        self.enterprise_url.as_deref()
    }

    /// The recorded enterprise API base, absent on public GitHub.
    #[must_use]
    pub fn api_endpoint(&self) -> Option<&str> {
        self.api_endpoint.as_deref()
    }

    /// The peer-issued page the operator opens.
    #[must_use]
    pub fn verification_uri(&self) -> &str {
        &self.verification_uri
    }

    /// The peer-issued code the operator enters.
    #[must_use]
    pub fn user_code(&self) -> &str {
        &self.user_code
    }

    /// The current poll interval, widened by each `slow_down` answer.
    #[must_use]
    pub fn interval(&self) -> Duration {
        self.interval
    }

    /// The peer-issued device-code lifetime in seconds.
    #[must_use]
    pub fn expires_in(&self) -> u64 {
        self.expires_in
    }

    /// The instant the caller should make its next [`advance`] call.
    #[must_use]
    pub fn next_poll_at(&self) -> Instant {
        self.next_poll_at
    }
}

/// The one-step result of advancing a device login.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Advance {
    /// The peer has not seen the operator finish; poll again at
    /// [`DeviceLoginSession::next_poll_at`].
    Pending,
    /// The peer asked for a slower cadence; the session interval was widened
    /// and the next poll is scheduled at the new interval.
    SlowDown,
    /// The peer answered the access token and the canonical profile holds
    /// the profile name.
    Complete(String),
}

/// Normalizes the operator's domain and starts one recorded device-code leg.
/// A blank or public GitHub input uses `github.com`; every other host is the
/// normalized enterprise origin. The request carries the recorded client id,
/// `scope=read:user` and the CLI identity headers.
///
/// # Errors
/// [`LoginError::InvalidDomain`] when a non-blank input is not a usable
/// host; [`LoginError::EndpointNotRecorded`] for an endpoint outside its
/// recorded class or a verification page that is not `https` on the
/// session's own domain; [`LoginError::TokenRejected`] for a non-success
/// status;
/// the response denials [`LoginError::MissingField`],
/// [`LoginError::MalformedField`], [`LoginError::DeviceExpiryOutOfRange`]
/// and [`LoginError::DeviceIntervalOutOfRange`]; and the bounded transport
/// and body failures.
pub fn begin_device(
    domain: &str,
    endpoints: DeviceEndpoints,
) -> Result<DeviceLoginSession, LoginError> {
    let origin = device_origin(domain)?;
    let recorded = DeviceEndpoints::recorded(&origin.domain);
    for (endpoint, expected) in [
        (
            endpoints.device_code.as_str(),
            recorded.device_code.as_str(),
        ),
        (
            endpoints.access_token.as_str(),
            recorded.access_token.as_str(),
        ),
    ] {
        if !login_common::admitted_endpoint(endpoint, expected) {
            return Err(LoginError::EndpointNotRecorded {
                origin: login_common::endpoint_origin(endpoint),
            });
        }
    }
    let (mut response, started) = login_common::post(
        CONNECTION,
        &endpoints.device_code,
        LOGIN_TIMEOUT,
        Body::Form(&[("client_id", CLIENT_ID), ("scope", SCOPE)]),
        &OAUTH_HEADERS,
    )?;
    if !response.status().is_success() {
        return Err(LoginError::TokenRejected {
            status: response.status().as_u16(),
        });
    }
    let body = login_common::read_body(CONNECTION, &mut response, LOGIN_TIMEOUT, started)?;
    let reply = login_common::parse_json(&body)?;
    let device_code = text_field(&reply, "device_code")?;
    let user_code = text_field(&reply, "user_code")?;
    let verification_uri =
        admitted_verification_uri(&origin.domain, &text_field(&reply, "verification_uri")?)?;
    let interval = device_interval(&reply)?;
    let expires_in = device_expiry(&reply)?;
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(expires_in))
        .ok_or(LoginError::DeviceExpiryOutOfRange {
            seconds: expires_in,
        })?;
    let next_poll_at =
        Instant::now()
            .checked_add(interval)
            .ok_or(LoginError::DeviceIntervalOutOfRange {
                seconds: interval.as_secs(),
            })?;
    Ok(DeviceLoginSession {
        domain: origin.domain,
        enterprise_url: origin.enterprise_url,
        api_endpoint: origin.api_endpoint,
        verification_uri,
        user_code,
        device_code,
        interval,
        expires_in,
        deadline,
        next_poll_at,
        endpoints,
    })
}

/// Performs exactly one bounded access-token poll and writes the canonical
/// profile when the peer answers. The step never sleeps: pending and
/// `slow_down` answers schedule the next poll, a denial stops immediately
/// and the peer's expiry ends the leg. A success is re-checked against the
/// deadline before the create-only store write, so a slow peer cannot enroll
/// past the window.
///
/// # Errors
/// [`LoginError::DeviceExpired`] when the device window has passed before
/// the poll, when the peer answers `expired_token`, or when a success
/// arrives after the window; [`LoginError::DeviceDenied`] on
/// `access_denied`; [`LoginError::Denied`] for any error code outside the
/// recorded set (a fixed label, never the peer's text);
/// [`LoginError::TokenRejected`] for a non-success status without an error
/// member; [`LoginError::MissingField`] for an answer without
/// `access_token`; [`LoginError::MalformedResponse`] for a success reply
/// that is not JSON; [`LoginError::ResponseTooLarge`] when the reply
/// exceeds the byte bound; [`LoginError::DeviceIntervalOutOfRange`] when
/// the next poll instant is not representable; [`LoginError::Clock`] when
/// the wall clock is before the Unix epoch; [`LoginError::Serialization`]
/// when the profile cannot be encoded; the config-binding denials
/// [`LoginError::ConnectionMissing`] and [`LoginError::NotApiKey`]; and the
/// transport and store denials behind [`LoginError::Provider`] — including
/// [`ProviderError::CredentialOccupied`].
pub fn advance(
    config: &Config,
    connection: &str,
    session: &mut DeviceLoginSession,
    store: &dyn CredentialStore,
) -> Result<Advance, LoginError> {
    let reference = login_common::api_key_reference(config, connection)?;
    if Instant::now() >= session.deadline {
        return Err(LoginError::DeviceExpired);
    }
    let (mut response, started) = login_common::post(
        connection,
        &session.endpoints.access_token,
        LOGIN_TIMEOUT,
        Body::Form(&[
            ("client_id", CLIENT_ID),
            ("device_code", &session.device_code),
            ("grant_type", GRANT_TYPE),
        ]),
        &OAUTH_HEADERS,
    )?;
    let status = response.status();
    let body = login_common::read_body(connection, &mut response, LOGIN_TIMEOUT, started)?;
    let parsed = serde_json::from_slice::<Value>(&body);
    if let Ok(reply) = &parsed
        && let Some(error) = reply.get("error").and_then(Value::as_str)
    {
        return advance_error(session, error);
    }
    if !status.is_success() {
        return Err(LoginError::TokenRejected {
            status: status.as_u16(),
        });
    }
    let reply = parsed.map_err(|cause| LoginError::MalformedResponse { cause })?;
    let token = text_field(&reply, "access_token")?;
    if Instant::now() >= session.deadline {
        return Err(LoginError::DeviceExpired);
    }
    let material = StoredCredential {
        token,
        enterprise_url: session.enterprise_url.clone(),
        api_endpoint: session.api_endpoint.clone(),
        expires_at: far_future_expiry()?,
    };
    let bytes =
        serde_json::to_vec(&material).map_err(|cause| LoginError::Serialization { cause })?;
    store.login(&reference, &bytes)?;
    Ok(Advance::Complete(reference.profile().to_string()))
}

/// Reads the Copilot profile at a scoped reference. Parsing is strict:
/// foreign material is a typed denial, never a guess.
///
/// # Errors
/// The [`LoginError::Provider`] store denial, and
/// [`LoginError::StoredCredentialMalformed`] when the material is not a
/// Copilot profile.
pub fn read_credential(
    store: &dyn CredentialStore,
    reference: &SecretRef,
) -> Result<StoredCredential, LoginError> {
    let bytes = store.resolve(reference)?;
    serde_json::from_slice(&bytes).map_err(|cause| LoginError::StoredCredentialMalformed {
        reason: login_common::malformed_reason(&cause),
    })
}

/// A stored profile endpoint rendered for `Debug`: scheme and host only,
/// never its path, query, fragment or userinfo. A bare enterprise host is
/// read as an https origin.
fn stored_origin(raw: &str) -> String {
    let parsed =
        reqwest::Url::parse(raw).or_else(|_parse| reqwest::Url::parse(&format!("https://{raw}")));
    parsed.map_or_else(
        |_parse| "<unparsed origin>".to_string(),
        |url| login_common::endpoint_origin(url.as_str()),
    )
}

/// The canonical scoped profile written at login. The token never appears in
/// `Debug`; the enterprise origin and API base are config-class facts.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredCredential {
    token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    enterprise_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    api_endpoint: Option<String>,
    expires_at: u64,
}

impl fmt::Debug for StoredCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredCredential")
            .field("token", &login_common::redacted(&self.token))
            .field(
                "enterprise_url",
                &self.enterprise_url.as_deref().map(stored_origin),
            )
            .field(
                "api_endpoint",
                &self.api_endpoint.as_deref().map(stored_origin),
            )
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl StoredCredential {
    /// The GitHub OAuth token a Copilot adapter would send.
    #[must_use]
    pub fn token(&self) -> &str {
        &self.token
    }

    /// The normalized enterprise origin, absent on public GitHub.
    #[must_use]
    pub fn enterprise_url(&self) -> Option<&str> {
        self.enterprise_url.as_deref()
    }

    /// The recorded enterprise API base, absent on public GitHub.
    #[must_use]
    pub fn api_endpoint(&self) -> Option<&str> {
        self.api_endpoint.as_deref()
    }

    /// The far-future expiry in seconds since the Unix epoch.
    #[must_use]
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }
}

/// One login lifecycle failure. Display text is English and lowercase, and
/// never carries the device handle, a token or an endpoint query.
#[derive(Debug, thiserror::Error)]
pub enum LoginError {
    /// The platform entropy source could not fill a login secret.
    #[error("entropy source is unavailable: {cause}")]
    Entropy { cause: getrandom::Error },
    /// The non-blank domain input is not a usable host.
    #[error("the github enterprise domain is not a valid host")]
    InvalidDomain,
    /// The endpoint is neither its recorded URL nor a loopback peer.
    /// `origin` is the canonical scheme/host class — never the raw URL.
    #[error("github copilot endpoint origin {origin} is outside the recorded contract")]
    EndpointNotRecorded { origin: String },
    /// The system clock is before the Unix epoch, so no expiry applies.
    #[error("system clock is before the unix epoch: {cause}")]
    Clock { cause: std::time::SystemTimeError },
    /// The canonical connection the operator must declare is absent.
    #[error("connection {connection} is not declared")]
    ConnectionMissing { connection: String },
    /// The login path writes only an `api_key` binding.
    #[error("connection {connection} is {kind}, not an api key")]
    NotApiKey { connection: String, kind: ConnKind },
    /// The endpoint answered a non-success status without an error member.
    #[error("the github copilot endpoint answered with http status {status}")]
    TokenRejected { status: u16 },
    /// A reply omitted a recorded member.
    #[error("the github copilot response carries no {field}")]
    MissingField { field: &'static str },
    /// A present device member is not the recorded numeric shape.
    #[error("the github copilot response carries a malformed {field}")]
    MalformedField { field: &'static str },
    /// The peer-issued device lifetime exceeds the admitted ceiling.
    #[error("device expiry {seconds} seconds is outside the admitted ceiling")]
    DeviceExpiryOutOfRange { seconds: u64 },
    /// The peer-issued poll interval exceeds the admitted ceiling.
    #[error("device poll interval {seconds} seconds is outside the admitted ceiling")]
    DeviceIntervalOutOfRange { seconds: u64 },
    /// The device peer reported an operator denial.
    #[error("device authorization was denied")]
    DeviceDenied,
    /// The device code expired before it was redeemed.
    #[error("device authorization expired")]
    DeviceExpired,
    /// The device peer reported an error code outside the recorded set.
    /// `code` is a fixed label, never the peer's text.
    #[error("device authorization failed: {code}")]
    Denied { code: String },
    /// A reply exceeded the bounded response size.
    #[error("the response exceeds the byte bound")]
    ResponseTooLarge,
    /// A reply was not the JSON object the contract records.
    #[error("the endpoint answered malformed json")]
    MalformedResponse {
        #[source]
        cause: serde_json::Error,
    },
    /// The material at the scope is not a Copilot profile. serde's own
    /// diagnostic can quote the stored bytes, so only its class is kept.
    #[error("the stored credential is not a github copilot credential: {reason}")]
    StoredCredentialMalformed { reason: &'static str },
    /// The in-memory profile could not be encoded for the store.
    #[error("the github copilot credential could not be serialized")]
    Serialization {
        #[source]
        cause: serde_json::Error,
    },
    /// The credential seam's typed denial — unavailable/ambiguous store, an
    /// occupied scope, or a scope outside the backend's namespace.
    #[error(transparent)]
    Provider(#[from] ProviderError),
}

impl From<CommonError> for LoginError {
    fn from(error: CommonError) -> Self {
        match error {
            CommonError::Entropy { cause } => Self::Entropy { cause },
            CommonError::ResponseTooLarge => Self::ResponseTooLarge,
            CommonError::MalformedResponse { cause } => Self::MalformedResponse { cause },
            CommonError::Clock { cause } => Self::Clock { cause },
            CommonError::Transport(cause) => Self::Provider(cause),
        }
    }
}

impl From<BindingError> for LoginError {
    fn from(error: BindingError) -> Self {
        match error {
            BindingError::ConnectionMissing { connection } => {
                Self::ConnectionMissing { connection }
            }
            BindingError::NotApiKey { connection, kind } => Self::NotApiKey { connection, kind },
            BindingError::Provider(cause) => Self::Provider(cause),
        }
    }
}

/// The normalized device origin: the folded public host or the enterprise
/// host with its recorded API base.
struct Origin {
    domain: String,
    enterprise_url: Option<String>,
    api_endpoint: Option<String>,
}

/// Normalizes the operator's input the way the recorded producer does: a
/// blank input is public, a public host folds onto `github.com`, and any
/// other parsed host keeps its name as the enterprise origin.
fn device_origin(raw: &str) -> Result<Origin, LoginError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(public_origin());
    }
    let host = parse_host(trimmed).ok_or(LoginError::InvalidDomain)?;
    if PUBLIC_HOSTS.contains(&host.as_str()) {
        return Ok(public_origin());
    }
    let api_host = if host.starts_with("copilot-api.") {
        host.clone()
    } else {
        format!("copilot-api.{host}")
    };
    Ok(Origin {
        domain: host.clone(),
        enterprise_url: Some(host),
        api_endpoint: Some(format!("https://{api_host}")),
    })
}

fn public_origin() -> Origin {
    Origin {
        domain: PUBLIC_DOMAIN.to_string(),
        enterprise_url: None,
        api_endpoint: None,
    }
}

/// The host of `raw`: a bare host is read as https, and a URL input keeps
/// only its hostname. Anything the URL parser rejects is not a domain.
fn parse_host(raw: &str) -> Option<String> {
    let parsed = if raw.contains("://") {
        reqwest::Url::parse(raw).ok()?
    } else {
        reqwest::Url::parse(&format!("https://{raw}")).ok()?
    };
    let host = parsed.host_str()?;
    (!host.is_empty()).then(|| host.to_lowercase())
}

/// The peer's device page, admitted only as `https` on the session's own
/// domain: a `javascript:`, `file:` or foreign-host URI is a typed denial
/// that names the canonical scheme/host class, never the raw URL.
fn admitted_verification_uri(domain: &str, raw: &str) -> Result<String, LoginError> {
    let denied = || LoginError::EndpointNotRecorded {
        origin: login_common::endpoint_origin(raw),
    };
    let url = reqwest::Url::parse(raw).map_err(|_parse| denied())?;
    if url.scheme() != "https"
        || url.host_str() != Some(domain)
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(denied());
    }
    Ok(raw.to_string())
}

fn text_field(reply: &Value, field: &'static str) -> Result<String, LoginError> {
    login_common::text_field(reply, field).ok_or(LoginError::MissingField { field })
}

/// The peer-issued poll interval in seconds. A missing value keeps the
/// recorded fallback, a zero interval is raised to one second so the loop
/// never busy-polls, and an unparseable or above-ceiling value denies.
fn device_interval(reply: &Value) -> Result<Duration, LoginError> {
    let seconds = numeric_field(reply, "interval")?.unwrap_or(DEFAULT_INTERVAL_SECONDS);
    if seconds > MAX_INTERVAL_SECONDS {
        return Err(LoginError::DeviceIntervalOutOfRange { seconds });
    }
    Ok(Duration::from_secs(seconds.max(1)))
}

/// The peer-issued device lifetime in seconds; a missing value keeps the
/// recorded fallback, and an unparseable or above-ceiling value denies.
fn device_expiry(reply: &Value) -> Result<u64, LoginError> {
    let seconds = numeric_field(reply, "expires_in")?.unwrap_or(DEFAULT_EXPIRY_SECONDS);
    if seconds > MAX_EXPIRY_SECONDS {
        return Err(LoginError::DeviceExpiryOutOfRange { seconds });
    }
    Ok(seconds)
}

/// A whole-second numeric member; absent answers `None`, a non-integer or
/// non-numeric shape is a peer contract violation.
fn numeric_field(reply: &Value, field: &'static str) -> Result<Option<u64>, LoginError> {
    match reply.get(field) {
        None => Ok(None),
        Some(Value::Number(number)) => number
            .as_u64()
            .map(Some)
            .ok_or(LoginError::MalformedField { field }),
        Some(Value::String(text)) => text
            .trim()
            .parse::<u64>()
            .map(Some)
            .map_err(|_parse| LoginError::MalformedField { field }),
        Some(_) => Err(LoginError::MalformedField { field }),
    }
}

/// Applies one error member from the token reply. Pending and slow-down
/// schedule the next poll; denial and expiry stop the leg; any other code
/// maps to a fixed denial label that never echoes the peer's text.
fn advance_error(session: &mut DeviceLoginSession, error: &str) -> Result<Advance, LoginError> {
    match error {
        "authorization_pending" => {
            schedule(session)?;
            Ok(Advance::Pending)
        }
        "slow_down" => {
            session.interval = session
                .interval
                .saturating_add(SLOW_DOWN_STEP)
                .min(Duration::from_secs(MAX_INTERVAL_SECONDS));
            schedule(session)?;
            Ok(Advance::SlowDown)
        }
        "access_denied" => Err(LoginError::DeviceDenied),
        "expired_token" => Err(LoginError::DeviceExpired),
        _ => Err(LoginError::Denied {
            code: "unknown device error".to_string(),
        }),
    }
}

/// The next poll instant under the current interval; an unrepresentable
/// instant is a typed denial rather than a panicking `Instant + Duration`.
fn schedule(session: &mut DeviceLoginSession) -> Result<(), LoginError> {
    session.next_poll_at = Instant::now().checked_add(session.interval).ok_or(
        LoginError::DeviceIntervalOutOfRange {
            seconds: session.interval.as_secs(),
        },
    )?;
    Ok(())
}

fn far_future_expiry() -> Result<u64, LoginError> {
    Ok(login_common::clock_seconds()?.saturating_add(FAR_FUTURE_SECONDS))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn device_session() -> DeviceLoginSession {
        DeviceLoginSession {
            domain: PUBLIC_DOMAIN.to_string(),
            enterprise_url: None,
            api_endpoint: None,
            verification_uri: "https://github.com/login/device".to_string(),
            user_code: "ABCD-1234".to_string(),
            device_code: "fixture-device-code".to_string(),
            interval: Duration::from_secs(DEFAULT_INTERVAL_SECONDS),
            expires_in: DEFAULT_EXPIRY_SECONDS,
            deadline: Instant::now() + Duration::from_secs(DEFAULT_EXPIRY_SECONDS),
            next_poll_at: Instant::now(),
            endpoints: DeviceEndpoints::recorded(PUBLIC_DOMAIN),
        }
    }

    #[test]
    fn text_field_requires_a_non_empty_string_member() {
        let reply = json!({ "device_code": "abc", "empty": "", "number": 7 });
        assert_eq!(
            text_field(&reply, "device_code").expect("the member is a string"),
            "abc"
        );
        for field in ["missing", "empty", "number"] {
            assert!(
                matches!(text_field(&reply, field), Err(LoginError::MissingField { field: named }) if named == field),
                "{field}"
            );
        }
    }

    #[test]
    fn numeric_field_admits_whole_seconds_and_denies_other_shapes() {
        let reply = json!({
            "number": 7,
            "text": " 7 ",
            "negative": -1,
            "float": 1.5,
            "junk": "soon",
            "object": {},
        });
        assert_eq!(
            numeric_field(&reply, "missing").expect("an absent member is admitted"),
            None
        );
        assert_eq!(
            numeric_field(&reply, "number").expect("a whole number is admitted"),
            Some(7)
        );
        assert_eq!(
            numeric_field(&reply, "text").expect("a decimal string is admitted"),
            Some(7)
        );
        for field in ["negative", "float", "junk", "object"] {
            assert!(
                matches!(numeric_field(&reply, field), Err(LoginError::MalformedField { field: named }) if named == field),
                "{field}"
            );
        }
    }

    #[test]
    fn device_interval_defaults_and_raises_a_zero_to_one_second() {
        assert_eq!(
            device_interval(&json!({})).expect("the recorded fallback applies"),
            Duration::from_secs(5)
        );
        assert_eq!(
            device_interval(&json!({ "interval": 0 })).expect("a zero interval is raised"),
            Duration::from_secs(1)
        );
        assert_eq!(
            device_interval(&json!({ "interval": 3600 })).expect("the ceiling is admitted"),
            Duration::from_secs(3600)
        );
        assert_eq!(
            device_interval(&json!({ "interval": "10" })).expect("a decimal string is admitted"),
            Duration::from_secs(10)
        );
        let error = device_interval(&json!({ "interval": 3601 })).expect_err("above the ceiling");
        assert!(
            matches!(
                error,
                LoginError::DeviceIntervalOutOfRange { seconds: 3601 }
            ),
            "{error}"
        );
        let error = device_interval(&json!({ "interval": "soon" })).expect_err("not a number");
        assert!(
            matches!(error, LoginError::MalformedField { field: "interval" }),
            "{error}"
        );
    }

    #[test]
    fn device_expiry_defaults_and_denies_above_the_ceiling() {
        assert_eq!(
            device_expiry(&json!({})).expect("the recorded fallback applies"),
            900
        );
        assert_eq!(
            device_expiry(&json!({ "expires_in": 0 })).expect("a zero lifetime is admitted"),
            0
        );
        assert_eq!(
            device_expiry(&json!({ "expires_in": 86_400 })).expect("the ceiling is admitted"),
            86_400
        );
        assert_eq!(
            device_expiry(&json!({ "expires_in": "900" })).expect("a decimal string is admitted"),
            900
        );
        let error = device_expiry(&json!({ "expires_in": 86_401 })).expect_err("above the ceiling");
        assert!(
            matches!(
                error,
                LoginError::DeviceExpiryOutOfRange { seconds: 86_401 }
            ),
            "{error}"
        );
        let error = device_expiry(&json!({ "expires_in": 1.5 })).expect_err("not a whole number");
        assert!(
            matches!(
                error,
                LoginError::MalformedField {
                    field: "expires_in"
                }
            ),
            "{error}"
        );
    }

    #[test]
    fn advance_error_maps_recorded_codes_and_sanitizes_unknown_text() {
        let mut session = device_session();

        let started = Instant::now();
        assert_eq!(
            advance_error(&mut session, "authorization_pending").expect("a pending answer"),
            Advance::Pending
        );
        assert!(session.next_poll_at() >= started + Duration::from_secs(5));

        assert_eq!(
            advance_error(&mut session, "slow_down").expect("a slow-down answer"),
            Advance::SlowDown
        );
        assert_eq!(session.interval(), Duration::from_secs(10));

        let error = advance_error(&mut session, "access_denied").expect_err("a denial");
        assert!(matches!(error, LoginError::DeviceDenied), "{error}");
        let error = advance_error(&mut session, "expired_token").expect_err("an expiry");
        assert!(matches!(error, LoginError::DeviceExpired), "{error}");

        let error = advance_error(&mut session, "fixture-device-code").expect_err("unknown");
        assert!(
            matches!(&error, LoginError::Denied { code } if code == "unknown device error"),
            "{error}"
        );
        let rendered = format!("{error} {error:?}");
        assert!(!rendered.contains("fixture-device-code"), "{rendered}");
    }
}
