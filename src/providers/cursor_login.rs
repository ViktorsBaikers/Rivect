//! Cursor PKCE/poll login lifecycle: the recorded `loginDeepControl` leg,
//! the caller-driven poll, the access-token identity, the canonical scoped
//! profile and the refresh that never rebinds the user. Library-level — no
//! CLI verb is added.
//!
//! The recorded contract is OMP's `packages/ai/src/registry/oauth/cursor.ts`
//! (`0133f7ff`): the login URL `https://cursor.com/loginDeepControl` carrying
//! the S256 challenge, a UUID v4 and `mode=login&redirectTarget=cli`; the
//! poll `GET https://api2.cursor.sh/auth/poll?uuid&verifier` where `404` is
//! pending, a `2xx` answers `{accessToken, refreshToken}`, and up to 150
//! attempts bound the wait; the refresh
//! `POST https://api2.cursor.sh/auth/exchange_user_api_key` with the stored
//! refresh token as its bearer. Identity comes from the access token's `sub`
//! (the id after an auth0-style `|`); expiry is the token's own `exp` minus
//! five minutes, or one hour when no `exp` is readable.
//!
//! Enrollment is create-only through [`CredentialStore::login`]: an occupied
//! scope or a refused store operation denies and leaves the prior bytes
//! untouched. The PKCE verifier is one-time and never enters `Debug`, an
//! error or a diagnostic; both tokens are redacted in the stored profile's
//! `Debug`.

use super::login_common::{self, BindingError, Body, CommonError};
use super::{CredentialStore, ProviderError, SecretRef};
use crate::config::{Config, ConnKind};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fmt;
use std::time::{Duration, Instant};

/// The recorded login leg the operator opens.
pub const LOGIN_URL: &str = "https://cursor.com/loginDeepControl";

/// The recorded poll leg. A caller passes it explicitly so an offline
/// contract peer can stand in; the login path admits only this URL or a
/// loopback origin.
pub const POLL_URL: &str = "https://api2.cursor.sh/auth/poll";

/// The recorded refresh leg; the same loopback admission applies.
pub const REFRESH_URL: &str = "https://api2.cursor.sh/auth/exchange_user_api_key";

/// The recorded poll ceiling: 150 attempts, after which the wait expires.
pub const POLL_MAX_ATTEMPTS: u32 = 150;

/// One poll leg's whole budget, shared by connect, request and read.
const LOGIN_TIMEOUT: Duration = Duration::from_secs(30);

/// The recorded first poll delay and its widening ceiling.
const POLL_BASE_DELAY: Duration = Duration::from_secs(1);
const POLL_MAX_DELAY: Duration = Duration::from_secs(10);

/// The recorded consecutive transport-error ceiling.
const TRANSPORT_ERROR_LIMIT: u32 = 3;

/// The recorded expiry skew subtracted from the access token's own `exp`.
const JWT_EXPIRY_SKEW: Duration = Duration::from_secs(300);

/// The lifetime an access token without a readable `exp` is given.
const JWT_FALLBACK_LIFETIME: Duration = Duration::from_secs(60 * 60);

/// The three recorded endpoints. Production callers pass
/// [`CursorEndpoints::recorded`]; tests pass loopback peers. The override is
/// not a config surface.
#[derive(Debug, Clone)]
pub struct CursorEndpoints {
    /// The page the operator opens.
    pub login: String,
    /// The poll the caller advances one step at a time.
    pub poll: String,
    /// The refresh exchange.
    pub refresh: String,
}

impl CursorEndpoints {
    /// The recorded production endpoints.
    #[must_use]
    pub fn recorded() -> Self {
        Self {
            login: LOGIN_URL.to_string(),
            poll: POLL_URL.to_string(),
            refresh: REFRESH_URL.to_string(),
        }
    }
}

/// One in-flight poll leg: the URL the operator opens, the UUID the peer
/// matches, the one-time PKCE pair and the caller-driven schedule. `Debug`
/// redacts the verifier — only the wire's public half is printable.
pub struct LoginSession {
    login_url: String,
    uuid: String,
    code_verifier: String,
    code_challenge: String,
    endpoints: CursorEndpoints,
    attempts: u32,
    consecutive_errors: u32,
    delay: Duration,
    next_poll_at: Instant,
}

impl fmt::Debug for LoginSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoginSession")
            .field("login_url", &self.login_url)
            .field("uuid", &self.uuid)
            .field(
                "code_verifier",
                &login_common::redacted(&self.code_verifier),
            )
            .field("code_challenge", &self.code_challenge)
            .field("next_poll_at", &self.next_poll_at)
            .finish()
    }
}

impl LoginSession {
    /// The recorded login URL to open.
    #[must_use]
    pub fn login_url(&self) -> &str {
        &self.login_url
    }

    /// The UUID the poll and the browser leg share.
    #[must_use]
    pub fn uuid(&self) -> &str {
        &self.uuid
    }

    /// The PKCE verifier the poll presents. One-time secret: never printed,
    /// logged or stored by this module.
    #[must_use]
    pub fn code_verifier(&self) -> &str {
        &self.code_verifier
    }

    /// The S256 challenge the login leg published.
    #[must_use]
    pub fn code_challenge(&self) -> &str {
        &self.code_challenge
    }

    /// The instant the caller should make its next [`advance`] call.
    #[must_use]
    pub fn next_poll_at(&self) -> Instant {
        self.next_poll_at
    }
}

/// The one-step result of advancing the poll.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Advance {
    /// The browser has not completed yet; poll again at this instant.
    Pending { next_poll_at: Instant },
    /// The peer answered the token pair and the canonical profile now holds
    /// the profile name.
    Complete(String),
}

/// Builds one poll leg from OS entropy: a 32-byte verifier rendered
/// base64url, its S256 challenge, and a UUID v4 state.
///
/// # Errors
/// [`LoginError::Entropy`] when the platform entropy source fails;
/// [`LoginError::EndpointNotRecorded`] for a foreign endpoint;
/// [`LoginError::Expired`] when the first poll instant is unrepresentable.
pub fn begin_login(endpoints: &CursorEndpoints) -> Result<LoginSession, LoginError> {
    for (endpoint, recorded) in [
        (endpoints.login.as_str(), LOGIN_URL),
        (endpoints.poll.as_str(), POLL_URL),
        (endpoints.refresh.as_str(), REFRESH_URL),
    ] {
        if !login_common::admitted_endpoint(endpoint, recorded) {
            return Err(LoginError::EndpointNotRecorded {
                origin: login_common::endpoint_origin(endpoint),
            });
        }
    }
    let code_verifier = login_common::random_urlsafe()?;
    let code_challenge = login_common::challenge_for(&code_verifier);
    let uuid = login_common::random_uuid()?;
    let login_url = format!(
        "{}?challenge={}&uuid={uuid}&mode=login&redirectTarget=cli",
        endpoints.login,
        login_common::encode_component(&code_challenge),
    );
    let next_poll_at = Instant::now()
        .checked_add(POLL_BASE_DELAY)
        .ok_or(LoginError::Expired)?;
    Ok(LoginSession {
        login_url,
        uuid,
        code_verifier,
        code_challenge,
        endpoints: endpoints.clone(),
        attempts: 0,
        consecutive_errors: 0,
        delay: POLL_BASE_DELAY,
        next_poll_at,
    })
}

/// Performs exactly one bounded `GET` poll attempt. `404` is pending and
/// schedules the next poll; a `2xx` completes the login and writes the
/// canonical profile; any other status denies immediately. Three
/// consecutive transport failures deny, and the recorded 150-attempt window
/// expires the leg. The step never sleeps — scheduling belongs to the
/// caller.
///
/// # Errors
/// [`LoginError::TokenRejected`] for a non-404, non-2xx status;
/// [`LoginError::PollingFailed`] after three consecutive transport
/// failures; [`LoginError::Expired`] at the recorded attempt ceiling; the
/// config, response and store denials [`complete`] documents.
pub fn advance(
    config: &Config,
    connection: &str,
    session: &mut LoginSession,
    store: &dyn CredentialStore,
) -> Result<Advance, LoginError> {
    let reference = login_common::api_key_reference(config, connection)?;
    if session.attempts >= POLL_MAX_ATTEMPTS {
        return Err(LoginError::Expired);
    }
    let poll_url = format!(
        "{}?uuid={}&verifier={}",
        session.endpoints.poll,
        login_common::encode_component(&session.uuid),
        login_common::encode_component(&session.code_verifier),
    );
    session.attempts = session.attempts.saturating_add(1);
    let (mut response, started) = match get(connection, &poll_url, LOGIN_TIMEOUT) {
        Ok(leg) => leg,
        Err(cause) => {
            session.consecutive_errors = session.consecutive_errors.saturating_add(1);
            if session.consecutive_errors >= TRANSPORT_ERROR_LIMIT {
                return Err(LoginError::PollingFailed { cause });
            }
            return pending(session);
        }
    };
    let status = response.status();
    if status.as_u16() == 404 {
        session.consecutive_errors = 0;
        session.delay = session
            .delay
            .saturating_mul(6)
            .div_f64(5.0)
            .min(POLL_MAX_DELAY);
        return pending(session);
    }
    if !status.is_success() {
        return Err(LoginError::TokenRejected {
            status: status.as_u16(),
        });
    }
    let body = login_common::read_body(connection, &mut response, LOGIN_TIMEOUT, started)?;
    let reply = login_common::parse_json(&body)?;
    enroll(&reference, &reply, store).map(Advance::Complete)
}

/// Writes the canonical scoped profile from one successful poll reply. The
/// user id comes from the JWT `sub`; the expiry is the token's `exp` minus
/// five minutes, or one hour when absent. Enrollment is create-only, so an
/// occupied scope denies and its prior bytes stay byte-identical.
///
/// # Errors
/// [`LoginError::ConnectionMissing`]/[`LoginError::NotApiKey`] for the
/// config binding; [`LoginError::MissingField`] for a reply without both
/// tokens; [`LoginError::MissingUserId`] for a token without `sub`;
/// [`LoginError::InvalidExpiry`] when the token's `exp` is not a positive
/// whole second; [`LoginError::Provider`] for the store denial — including
/// [`ProviderError::CredentialOccupied`] on an already enrolled scope.
pub fn complete(
    config: &Config,
    connection: &str,
    reply: &Value,
    store: &dyn CredentialStore,
) -> Result<String, LoginError> {
    let reference = login_common::api_key_reference(config, connection)?;
    enroll(&reference, reply, store)
}

/// Replaces the stored profile's token and expiry from the recorded refresh
/// exchange. The stored `user_id` is carried forward unchanged: a refresh
/// never rebinds the profile to another user.
///
/// # Errors
/// [`LoginError::EndpointNotRecorded`] for a foreign refresh endpoint;
/// [`LoginError::StoredCredentialMalformed`] when the scope does not hold a
/// Cursor profile; [`LoginError::TokenRejected`] for a refusing peer; the
/// reply and store denials [`complete`] documents.
pub fn refresh(
    config: &Config,
    connection: &str,
    refresh_endpoint: &str,
    store: &dyn CredentialStore,
) -> Result<String, LoginError> {
    if !login_common::admitted_endpoint(refresh_endpoint, REFRESH_URL) {
        return Err(LoginError::EndpointNotRecorded {
            origin: login_common::endpoint_origin(refresh_endpoint),
        });
    }
    let reference = login_common::api_key_reference(config, connection)?;
    let stored = read_credential(store, &reference)?;
    let bearer = format!("Bearer {}", stored.refresh_token);
    let body = json!({});
    let (mut response, started) = login_common::post(
        connection,
        refresh_endpoint,
        LOGIN_TIMEOUT,
        Body::Json(&body),
        &[("authorization", bearer.as_str())],
    )?;
    if !response.status().is_success() {
        return Err(LoginError::TokenRejected {
            status: response.status().as_u16(),
        });
    }
    let body = login_common::read_body(connection, &mut response, LOGIN_TIMEOUT, started)?;
    let reply = login_common::parse_json(&body)?;
    let access_token = text_field(&reply, "accessToken")?;
    let refresh_token =
        login_common::text_field(&reply, "refreshToken").unwrap_or(stored.refresh_token);
    let expires_at = jwt_expires_at(&access_token)?;
    let updated = StoredCredential {
        access_token,
        refresh_token,
        expires_at,
        user_id: stored.user_id,
    };
    store.refresh(&reference, &serialize(&updated)?)?;
    Ok(reference.profile().to_string())
}

/// Reads the Cursor profile at a scoped reference. Parsing is strict:
/// foreign material is a typed denial, never a guess.
///
/// # Errors
/// The [`LoginError::Provider`] store denial, and
/// [`LoginError::StoredCredentialMalformed`] when the material is not a
/// Cursor profile.
pub fn read_credential(
    store: &dyn CredentialStore,
    reference: &SecretRef,
) -> Result<StoredCredential, LoginError> {
    let bytes = store.resolve(reference)?;
    serde_json::from_slice(&bytes).map_err(|cause| LoginError::StoredCredentialMalformed {
        reason: login_common::malformed_reason(&cause),
    })
}

/// The canonical scoped profile written at login. The tokens never appear in
/// `Debug`; the user id is the config-class identity the refresh preserves.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredCredential {
    access_token: String,
    refresh_token: String,
    expires_at: u64,
    user_id: String,
}

impl fmt::Debug for StoredCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredCredential")
            .field("access_token", &login_common::redacted(&self.access_token))
            .field(
                "refresh_token",
                &login_common::redacted(&self.refresh_token),
            )
            .field("expires_at", &self.expires_at)
            .field("user_id", &self.user_id)
            .finish()
    }
}

impl StoredCredential {
    /// The access token a Cursor adapter would send.
    #[must_use]
    pub fn access_token(&self) -> &str {
        &self.access_token
    }

    /// The refresh token the recorded exchange presents.
    #[must_use]
    pub fn refresh_token(&self) -> &str {
        &self.refresh_token
    }

    /// The access token's expiry in seconds since the Unix epoch, with the
    /// recorded skew already subtracted.
    #[must_use]
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// The user id the JWT `sub` reported at login.
    #[must_use]
    pub fn user_id(&self) -> &str {
        &self.user_id
    }
}

/// One login lifecycle failure. Display text is English and lowercase, and
/// never carries the verifier, a token or the poll URL.
#[derive(Debug, thiserror::Error)]
pub enum LoginError {
    /// The platform entropy source could not fill the verifier or state.
    #[error("entropy source is unavailable: {cause}")]
    Entropy { cause: getrandom::Error },
    /// The system clock is before the Unix epoch, so no expiry applies.
    #[error("system clock is before the unix epoch: {cause}")]
    Clock { cause: std::time::SystemTimeError },
    /// The endpoint is neither its recorded URL nor a loopback peer.
    /// `origin` is the canonical scheme/host class — never the raw URL,
    /// which may carry a verifier.
    #[error("cursor endpoint origin {origin} is outside the recorded contract")]
    EndpointNotRecorded { origin: String },
    /// The canonical connection the operator must declare is absent.
    #[error("connection {connection} is not declared")]
    ConnectionMissing { connection: String },
    /// The login path writes only an `api_key` binding.
    #[error("connection {connection} is {kind}, not an api key")]
    NotApiKey { connection: String, kind: ConnKind },
    /// The poll answered a non-404, non-2xx status.
    #[error("the cursor poll answered with http status {status}")]
    TokenRejected { status: u16 },
    /// A reply omitted a recorded member.
    #[error("the cursor response carries no {field}")]
    MissingField { field: &'static str },
    /// The access token carries no user id, so no profile can be scoped.
    #[error("the cursor access token carries no user id")]
    MissingUserId,
    /// The access token's own `exp` is not a positive whole-second instant.
    #[error("the cursor access token expiry is not a positive instant")]
    InvalidExpiry,
    /// The bounded poll window expired.
    #[error("cursor authentication polling expired")]
    Expired,
    /// Three consecutive transport failures ended the poll.
    #[error("cursor authentication polling failed after three consecutive transport errors")]
    PollingFailed {
        #[source]
        cause: ProviderError,
    },
    /// A reply exceeded the bounded response size.
    #[error("the cursor response exceeds the byte bound")]
    ResponseTooLarge,
    /// A reply was not the JSON object the contract records.
    #[error("the cursor endpoint answered malformed json")]
    MalformedResponse {
        #[source]
        cause: serde_json::Error,
    },
    /// The material at the scope is not a Cursor profile. serde's own
    /// diagnostic can quote the stored bytes, so only its class is kept.
    #[error("the stored credential is not a cursor credential: {reason}")]
    StoredCredentialMalformed { reason: &'static str },
    /// The in-memory profile could not be encoded for the store.
    #[error("the cursor credential could not be serialized")]
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

fn enroll(
    reference: &SecretRef,
    reply: &Value,
    store: &dyn CredentialStore,
) -> Result<String, LoginError> {
    let access_token = text_field(reply, "accessToken")?;
    let refresh_token = text_field(reply, "refreshToken")?;
    let user_id = jwt_subject(&access_token).ok_or(LoginError::MissingUserId)?;
    let expires_at = jwt_expires_at(&access_token)?;
    let credential = StoredCredential {
        access_token,
        refresh_token,
        expires_at,
        user_id,
    };
    store.login(reference, &serialize(&credential)?)?;
    Ok(reference.profile().to_string())
}

fn text_field(reply: &Value, field: &'static str) -> Result<String, LoginError> {
    login_common::text_field(reply, field).ok_or(LoginError::MissingField { field })
}

fn serialize(material: &StoredCredential) -> Result<Vec<u8>, LoginError> {
    serde_json::to_vec(material).map_err(|cause| LoginError::Serialization { cause })
}

/// One bounded GET with redirects off.
fn get(
    connection: &str,
    endpoint: &str,
    timeout: Duration,
) -> Result<(reqwest::blocking::Response, Instant), ProviderError> {
    let started = Instant::now();
    let client = login_common::client(connection, timeout)?;
    let response = client
        .get(endpoint)
        .send()
        .map_err(|cause| super::transport(connection, cause))?;
    Ok((response, started))
}

/// The recorded user id in the access token's `sub`: an auth0-style
/// `provider|id` subject keeps the id after the separator, exactly as the
/// recorded producer reads it. No signature verification: the claim is an
/// index into the peer's own answer, never an authentication decision.
fn jwt_subject(token: &str) -> Option<String> {
    let subject = login_common::jwt_claims(token)?
        .get("sub")?
        .as_str()?
        .trim()
        .to_string();
    let user = subject
        .split('|')
        .nth(1)
        .unwrap_or(subject.as_str())
        .trim()
        .to_string();
    (!user.is_empty()).then_some(user)
}

/// The recorded access-token expiry: the JWT's own `exp` minus five minutes,
/// or one hour from now when the token carries no readable `exp`. The
/// recorded producer is JavaScript, so an integral JSON float is the same
/// whole-second instant as the integer form; a numeric `exp` that is not a
/// positive whole second denies instead of borrowing the fallback.
fn jwt_expires_at(token: &str) -> Result<u64, LoginError> {
    let Some(exp) = login_common::jwt_claims(token).and_then(|claims| claims.get("exp").cloned())
    else {
        return fallback_expiry();
    };
    match exp {
        Value::Number(_) => Ok(recorded_seconds(&exp)?.saturating_sub(JWT_EXPIRY_SKEW.as_secs())),
        _ => fallback_expiry(),
    }
}

fn fallback_expiry() -> Result<u64, LoginError> {
    Ok(login_common::clock_seconds()?.saturating_add(JWT_FALLBACK_LIFETIME.as_secs()))
}

fn recorded_seconds(value: &Value) -> Result<u64, LoginError> {
    if let Some(seconds) = value.as_u64() {
        return (seconds > 0)
            .then_some(seconds)
            .ok_or(LoginError::InvalidExpiry);
    }
    let seconds = value.as_f64().filter(|seconds| {
        seconds.is_finite()
            && seconds.fract() == 0.0
            && *seconds > 0.0
            && *seconds < u64::MAX as f64
    });
    seconds
        .map(|seconds| seconds as u64)
        .ok_or(LoginError::InvalidExpiry)
}

fn pending(session: &mut LoginSession) -> Result<Advance, LoginError> {
    let next = Instant::now()
        .checked_add(session.delay)
        .ok_or(LoginError::Expired)?;
    session.next_poll_at = next;
    Ok(Advance::Pending { next_poll_at: next })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token_with_claims(claims: &Value) -> String {
        let payload = serde_json::to_vec(claims).expect("payload");
        format!("header.{}.signature", login_common::base64url(&payload))
    }

    #[test]
    fn jwt_subject_reads_the_recorded_user_id_and_denies_an_empty_one() {
        assert_eq!(
            jwt_subject(&token_with_claims(&json!({ "sub": "auth0|user-fixture" }))).as_deref(),
            Some("user-fixture")
        );
        assert_eq!(
            jwt_subject(&token_with_claims(&json!({ "sub": "plain-subject" }))).as_deref(),
            Some("plain-subject")
        );
        assert_eq!(
            jwt_subject(&token_with_claims(&json!({ "sub": "auth0|  " }))),
            None
        );
        assert_eq!(jwt_subject("not-a-jwt"), None);
    }

    #[test]
    fn jwt_expiry_accepts_an_integral_float_and_denies_a_non_positive_number() {
        let token = token_with_claims(&json!({ "exp": 4_102_444_800.0 }));
        assert_eq!(
            jwt_expires_at(&token).expect("the recorded expiry"),
            4_102_444_800 - JWT_EXPIRY_SKEW.as_secs()
        );
        for exp in [json!(-1), json!(-1.5), json!(0), json!(0.0), json!(1.5)] {
            let error = jwt_expires_at(&token_with_claims(&json!({ "exp": exp })))
                .expect_err("a non-positive or fractional exp denies");
            assert!(matches!(error, LoginError::InvalidExpiry), "{error}");
        }
    }

    #[test]
    fn jwt_expiry_falls_back_to_one_hour_without_a_readable_exp() {
        let before = login_common::clock_seconds().expect("clock");
        let fallback = jwt_expires_at(&token_with_claims(&json!({ "sub": "auth0|user" })))
            .expect("the one-hour fallback");
        let after = login_common::clock_seconds().expect("clock");
        assert!(fallback >= before + JWT_FALLBACK_LIFETIME.as_secs());
        assert!(fallback <= after + JWT_FALLBACK_LIFETIME.as_secs());
    }

    #[test]
    fn the_recorded_endpoints_admit_their_own_urls() {
        let endpoints = CursorEndpoints::recorded();
        assert!(login_common::admitted_endpoint(&endpoints.login, LOGIN_URL));
        assert!(login_common::admitted_endpoint(&endpoints.poll, POLL_URL));
        assert!(login_common::admitted_endpoint(
            &endpoints.refresh,
            REFRESH_URL
        ));
    }
}
