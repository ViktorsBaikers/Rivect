//! Devin CLI OAuth profile: the recorded `oauth-code` login leg, its JSON
//! token exchange and the canonical scoped profile. Library-level — no CLI
//! verb is added.
//!
//! The recorded contract is OMP's `rules/auth/devin.kdl` (`0133f7ff`): the
//! authorize URL `https://app.devin.ai/auth/cli/continue` with a UUID state,
//! S256 PKCE and `prompt=select_account`; the fixed loopback callback
//! `http://127.0.0.1:59653/callback`; and the token exchange
//! `POST https://api.devin.ai/auth/cli/token` with the JSON body
//! `{code, code_verifier}` and `Accept: application/json`. The response's
//! `token` is the access token; expiry is that JWT's own `exp`, or the
//! recorded 365-day fallback when no readable `exp` is present. The
//! recorded class declares `refresh none`, so no refresh leg exists and an
//! expired profile denies instead of borrowing another grant.
//!
//! Enrollment is create-only through [`CredentialStore::login`]: an occupied
//! scope or a refused store operation denies and leaves the prior bytes
//! untouched. The PKCE verifier is single-exchange and never enters `Debug`, an
//! error or a diagnostic; both tokens are redacted in the stored profile's
//! `Debug`.

use super::login_common::{self, BindingError, Body, CommonError};
use super::{CredentialStore, ProviderError, SecretRef};
use crate::config::{Config, ConnKind};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fmt;
use std::time::Duration;

/// The recorded authorize leg the operator opens.
pub const AUTHORIZE_URL: &str = "https://app.devin.ai/auth/cli/continue";

/// The recorded JSON token exchange.
pub const TOKEN_URL: &str = "https://api.devin.ai/auth/cli/token";

/// The recorded fixed loopback callback.
pub const CALLBACK_URL: &str = "http://127.0.0.1:59653/callback";

/// One exchange leg's whole budget, shared by connect, request and read.
const LOGIN_TIMEOUT: Duration = Duration::from_secs(30);

/// The recorded lifetime when the access token carries no readable `exp`:
/// 365 days, not Cursor's one hour.
const JWT_FALLBACK_LIFETIME: Duration = Duration::from_secs(365 * 24 * 60 * 60);

/// The two recorded endpoints. Production callers pass
/// [`DevinEndpoints::recorded`]; tests pass loopback peers. The override is
/// not a config surface. The callback is fixed by the recorded contract.
#[derive(Debug, Clone)]
pub struct DevinEndpoints {
    /// The page the operator opens.
    pub authorize: String,
    /// The JSON token exchange.
    pub token: String,
}

impl DevinEndpoints {
    /// The recorded production endpoints.
    #[must_use]
    pub fn recorded() -> Self {
        Self {
            authorize: AUTHORIZE_URL.to_string(),
            token: TOKEN_URL.to_string(),
        }
    }
}

/// One in-flight login leg: the URL the operator opens, the UUID state the
/// callback must echo, the single-exchange PKCE pair and the endpoints.
/// `Debug` redacts the verifier — only the wire's public half is printable.
pub struct LoginSession {
    login_url: String,
    state: String,
    code_verifier: String,
    code_challenge: String,
    endpoints: DevinEndpoints,
}

impl fmt::Debug for LoginSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoginSession")
            .field("login_url", &self.login_url)
            .field("state", &self.state)
            .field(
                "code_verifier",
                &login_common::redacted(&self.code_verifier),
            )
            .field("code_challenge", &self.code_challenge)
            .finish()
    }
}

impl LoginSession {
    /// The recorded login URL to open.
    #[must_use]
    pub fn login_url(&self) -> &str {
        &self.login_url
    }

    /// The UUID state the callback must echo.
    #[must_use]
    pub fn state(&self) -> &str {
        &self.state
    }

    /// The PKCE verifier the exchange presents. Single-exchange secret:
    /// never printed, logged or stored by this module.
    #[must_use]
    pub fn code_verifier(&self) -> &str {
        &self.code_verifier
    }

    /// The S256 challenge the login leg published.
    #[must_use]
    pub fn code_challenge(&self) -> &str {
        &self.code_challenge
    }
}

/// Builds one login leg from OS entropy: a 32-byte verifier rendered
/// base64url, its S256 challenge, and a UUID v4 state. The authorize URL
/// carries the recorded standard parameters, the fixed loopback callback
/// and `prompt=select_account`.
///
/// # Errors
/// [`LoginError::Entropy`] when the platform entropy source fails;
/// [`LoginError::EndpointNotRecorded`] for a foreign endpoint.
pub fn begin_login(endpoints: &DevinEndpoints) -> Result<LoginSession, LoginError> {
    for (endpoint, recorded) in [
        (endpoints.authorize.as_str(), AUTHORIZE_URL),
        (endpoints.token.as_str(), TOKEN_URL),
    ] {
        if !login_common::admitted_endpoint(endpoint, recorded) {
            return Err(LoginError::EndpointNotRecorded {
                origin: login_common::endpoint_origin(endpoint),
            });
        }
    }
    let code_verifier = login_common::random_urlsafe()?;
    let code_challenge = login_common::challenge_for(&code_verifier);
    let state = login_common::random_uuid()?;
    let login_url = format!(
        "{}?response_type=code&redirect_uri={}&code_challenge={}&code_challenge_method=S256&state={}&prompt=select_account",
        endpoints.authorize,
        login_common::encode_component(CALLBACK_URL),
        login_common::encode_component(&code_challenge),
        login_common::encode_component(&state),
    );
    Ok(LoginSession {
        login_url,
        state,
        code_verifier,
        code_challenge,
        endpoints: endpoints.clone(),
    })
}

/// Verifies one browser callback and performs the recorded exchange. The
/// callback origin must be the fixed loopback callback and its `state` must
/// equal the session's; a cancellation (`error`) or missing code denies
/// before any request. A successful reply's `token` is stored in both the
/// access and refresh fields — the recorded class maps both credential
/// slots to that one field and declares no refresh leg. Enrollment is
/// create-only, so an occupied scope denies and its prior bytes stay
/// byte-identical.
///
/// # Errors
/// [`LoginError::CallbackNotRecorded`] for a foreign origin or path;
/// [`LoginError::StateMismatch`]/[`LoginError::Cancelled`] for the
/// callback negatives; [`LoginError::MissingField`] for a callback without
/// `code` or a reply without `token`;
/// [`LoginError::ConnectionMissing`]/[`LoginError::NotApiKey`] for the
/// config binding; [`LoginError::TokenRejected`] for a refusing peer; the
/// response, clock, serialization and store denials this module documents.
pub fn complete(
    config: &Config,
    connection: &str,
    session: &LoginSession,
    callback: &str,
    store: &dyn CredentialStore,
) -> Result<String, LoginError> {
    let reference = login_common::api_key_reference(config, connection)?;
    let code = verify_callback(callback, session)?;
    let body = json!({ "code": code, "code_verifier": session.code_verifier });
    let (mut response, started) = login_common::post(
        connection,
        &session.endpoints.token,
        LOGIN_TIMEOUT,
        Body::Json(&body),
        &[("accept", "application/json")],
    )?;
    if !response.status().is_success() {
        return Err(LoginError::TokenRejected {
            status: response.status().as_u16(),
        });
    }
    let body = login_common::read_body(connection, &mut response, LOGIN_TIMEOUT, started)?;
    let reply = login_common::parse_json(&body)?;
    let token = text_field(&reply, "token")?;
    let expires_at = jwt_expires_at(&token)?;
    let credential = StoredCredential {
        access_token: token.clone(),
        refresh_token: token,
        expires_at,
    };
    store.login(&reference, &serialize(&credential)?)?;
    Ok(reference.profile().to_string())
}

/// Reads the Devin profile at a scoped reference. Parsing is strict:
/// foreign material is a typed denial, never a guess. The recorded class
/// has no refresh leg, so a profile whose `expires_at` has passed denies
/// [`LoginError::Expired`] rather than being handed to a caller.
///
/// # Errors
/// The [`LoginError::Provider`] store denial,
/// [`LoginError::StoredCredentialMalformed`] when the material is not a
/// Devin profile, [`LoginError::Clock`] when the wall clock is before the
/// Unix epoch, and [`LoginError::Expired`] for a passed expiry.
pub fn read_credential(
    store: &dyn CredentialStore,
    reference: &SecretRef,
) -> Result<StoredCredential, LoginError> {
    let bytes = store.resolve(reference)?;
    let credential: StoredCredential =
        serde_json::from_slice(&bytes).map_err(|cause| LoginError::StoredCredentialMalformed {
            reason: login_common::malformed_reason(&cause),
        })?;
    if credential.expires_at <= login_common::clock_seconds()? {
        return Err(LoginError::Expired);
    }
    Ok(credential)
}

/// The canonical scoped profile written at login. The tokens never appear
/// in `Debug`; `expires_at` is the access token's own `exp` in seconds
/// since the Unix epoch.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredCredential {
    access_token: String,
    refresh_token: String,
    expires_at: u64,
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
            .finish()
    }
}

impl StoredCredential {
    /// The access token a Devin adapter would send.
    #[must_use]
    pub fn access_token(&self) -> &str {
        &self.access_token
    }

    /// The recorded refresh slot. The class declares `refresh none`, so no
    /// code path exchanges it.
    #[must_use]
    pub fn refresh_token(&self) -> &str {
        &self.refresh_token
    }

    /// The access token's expiry in seconds since the Unix epoch.
    #[must_use]
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }
}

/// One login lifecycle failure. Display text is English and lowercase, and
/// never carries the verifier, a token, a code or the callback query.
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
    /// which may carry a code or a verifier.
    #[error("devin endpoint origin {origin} is outside the recorded contract")]
    EndpointNotRecorded { origin: String },
    /// The callback is not the recorded fixed loopback origin and path.
    /// `origin` never carries the callback's query.
    #[error("devin callback {origin} is outside the recorded loopback contract")]
    CallbackNotRecorded { origin: String },
    /// The callback state is not the one this login leg minted.
    #[error("the devin callback state does not match this login")]
    StateMismatch,
    /// The browser answered a cancellation instead of a code.
    #[error("the devin login was cancelled at the callback")]
    Cancelled,
    /// The canonical connection the operator must declare is absent.
    #[error("connection {connection} is not declared")]
    ConnectionMissing { connection: String },
    /// The login path writes only an `api_key` binding.
    #[error("connection {connection} is {kind}, not an api key")]
    NotApiKey { connection: String, kind: ConnKind },
    /// The token endpoint answered a non-2xx status.
    #[error("the devin token endpoint answered with http status {status}")]
    TokenRejected { status: u16 },
    /// A callback or reply omitted a recorded member.
    #[error("the devin response carries no {field}")]
    MissingField { field: &'static str },
    /// The stored profile's expiry has passed and the recorded class offers
    /// no refresh leg.
    #[error("the devin profile expired and the recorded provider offers no refresh")]
    Expired,
    /// A reply exceeded the bounded response size.
    #[error("the devin response exceeds the byte bound")]
    ResponseTooLarge,
    /// A reply was not the JSON object the contract records.
    #[error("the devin endpoint answered malformed json")]
    MalformedResponse {
        #[source]
        cause: serde_json::Error,
    },
    /// The material at the scope is not a Devin profile. serde's own
    /// diagnostic can quote the stored bytes, so only its class is kept.
    #[error("the stored credential is not a devin credential: {reason}")]
    StoredCredentialMalformed { reason: &'static str },
    /// The in-memory profile could not be encoded for the store.
    #[error("the devin credential could not be serialized")]
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

/// The callback's one-time code after the fixed origin/path and state
/// checks. Duplicate query members keep the first, like the recorded
/// producer's `URLSearchParams.get`.
fn verify_callback(callback: &str, session: &LoginSession) -> Result<String, LoginError> {
    let url = reqwest::Url::parse(callback).map_err(|_parse| LoginError::CallbackNotRecorded {
        origin: login_common::endpoint_origin(callback),
    })?;
    if url.scheme() != "http"
        || url.host_str() != Some("127.0.0.1")
        || url.port() != Some(59653)
        || url.path() != "/callback"
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(LoginError::CallbackNotRecorded {
            origin: login_common::endpoint_origin(callback),
        });
    }
    let mut code = None;
    let mut state = None;
    let mut cancelled = false;
    for (name, value) in url.query_pairs() {
        match name.as_ref() {
            "code" if code.is_none() => code = Some(value.into_owned()),
            "state" if state.is_none() => state = Some(value.into_owned()),
            "error" => cancelled = true,
            _ => {}
        }
    }
    if state.as_deref() != Some(session.state.as_str()) {
        return Err(LoginError::StateMismatch);
    }
    if cancelled {
        return Err(LoginError::Cancelled);
    }
    code.filter(|value| !value.is_empty())
        .ok_or(LoginError::MissingField { field: "code" })
}

fn text_field(reply: &Value, field: &'static str) -> Result<String, LoginError> {
    login_common::text_field(reply, field).ok_or(LoginError::MissingField { field })
}

fn serialize(material: &StoredCredential) -> Result<Vec<u8>, LoginError> {
    serde_json::to_vec(material).map_err(|cause| LoginError::Serialization { cause })
}

/// The recorded access-token expiry: the JWT's own `exp` as a whole-second
/// instant, or 365 days from now when the token carries no readable `exp`.
/// The recorded producer is JavaScript, so any finite numeric `exp` counts;
/// a non-positive one stays in the past, which makes the stored profile
/// deny at read instead of borrowing a refresh that does not exist.
fn jwt_expires_at(token: &str) -> Result<u64, LoginError> {
    let Some(exp) = login_common::jwt_claims(token).and_then(|claims| claims.get("exp").cloned())
    else {
        return fallback_expiry();
    };
    match exp.as_f64() {
        Some(seconds) if seconds.is_finite() => Ok(if seconds > 0.0 { seconds as u64 } else { 0 }),
        _ => fallback_expiry(),
    }
}

fn fallback_expiry() -> Result<u64, LoginError> {
    Ok(login_common::clock_seconds()?.saturating_add(JWT_FALLBACK_LIFETIME.as_secs()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token_with_claims(claims: &Value) -> String {
        let payload = serde_json::to_vec(claims).expect("payload");
        format!("header.{}.signature", login_common::base64url(&payload))
    }

    #[test]
    fn jwt_expiry_reads_the_recorded_instant_and_falls_back_by_365_days() {
        let token = token_with_claims(&json!({ "exp": 4_102_444_800_u64 }));
        assert_eq!(
            jwt_expires_at(&token).expect("the recorded expiry"),
            4_102_444_800
        );

        let before = login_common::clock_seconds().expect("clock");
        let fallback = jwt_expires_at(&token_with_claims(&json!({ "sub": "devin-user" })))
            .expect("the 365-day fallback");
        let after = login_common::clock_seconds().expect("clock");
        assert!(fallback >= before + JWT_FALLBACK_LIFETIME.as_secs());
        assert!(fallback <= after + JWT_FALLBACK_LIFETIME.as_secs());

        let expired = token_with_claims(&json!({ "exp": 1 }));
        assert_eq!(jwt_expires_at(&expired).expect("the past expiry"), 1);
        let negative = token_with_claims(&json!({ "exp": -1 }));
        assert_eq!(jwt_expires_at(&negative).expect("the past expiry"), 0);

        for token in [
            "opaque-token".to_string(),
            token_with_claims(&json!({ "exp": "4102444800" })),
        ] {
            let before = login_common::clock_seconds().expect("clock");
            let fallback = jwt_expires_at(&token).expect("the 365-day fallback");
            let after = login_common::clock_seconds().expect("clock");
            assert!(
                fallback >= before + JWT_FALLBACK_LIFETIME.as_secs(),
                "{token}"
            );
            assert!(
                fallback <= after + JWT_FALLBACK_LIFETIME.as_secs(),
                "{token}"
            );
        }
    }

    #[test]
    fn foreign_endpoints_deny_before_minting_a_session() {
        for endpoints in [
            DevinEndpoints {
                authorize: "https://evil.example/auth/cli/continue".to_string(),
                ..DevinEndpoints::recorded()
            },
            DevinEndpoints {
                token: "https://evil.example/auth/cli/token".to_string(),
                ..DevinEndpoints::recorded()
            },
            DevinEndpoints {
                token: "https://user:pass@app.devin.ai/auth/cli/token".to_string(),
                ..DevinEndpoints::recorded()
            },
        ] {
            let error = begin_login(&endpoints).expect_err("a foreign endpoint denies");
            assert!(
                matches!(error, LoginError::EndpointNotRecorded { .. }),
                "{error}"
            );
        }
        begin_login(&DevinEndpoints::recorded()).expect("the recorded endpoints mint a session");
    }
}
