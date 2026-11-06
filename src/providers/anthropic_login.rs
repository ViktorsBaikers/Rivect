//! Anthropic Pro/Max login lifecycle (DEC-009/DEC-012/DEC-017): the
//! source-bound code+PKCE authorize leg, the org-bound exchange, the
//! refresh that never rebinds the organization, and the scoped
//! subscription credential written through the shipped
//! [`CredentialStore`] seam. Library-level — no CLI verb is added.
//!
//! The recorded contract is OMP's `rules/auth/anthropic.kdl` (`0133f7ff`):
//! authorize `https://claude.ai/oauth/authorize`, the recorded public
//! client id `9d1c250a-e61b-44d9-88ed-5944d1962f5e`, the six recorded
//! scopes, PKCE `S256`, callback `127.0.0.1:54545/callback`, and both the
//! code exchange and refresh posting JSON to
//! `https://api.anthropic.com/v1/oauth/token`. The token response maps
//! `access_token`, `refresh_token`, `expires_in`, `account.*` and
//! `organization.*`; the organization is captured once at login and
//! never rewritten by a refresh. Secret material — the PKCE verifier and
//! both tokens — never enters `Debug`, `Display` or a diagnostic.
//!
//! `ConnKind::Subscription` stays inference-ineligible at the Broker's
//! offline gate; the returned scoped [`SecretRef`] is what the Messages
//! adapter consumes at its own seam.
//!
//! Enrollment is create-only (`CredentialStore::login` refuses an occupied
//! scope with [`ProviderError::CredentialOccupied`]), so the recorded
//! re-login sequence is revoke → login: [`clear_subscription`] deletes the
//! scope through the store's `logout`, then a fresh [`begin_login`] and
//! [`complete_login`] enroll the new credential. A refresh is the
//! in-place rotation path; it never needs the scope cleared.

use super::login_common::{self, Body, CommonError};
use super::{CredentialStore, ProviderError, SecretRef, bounded_reason, resolve_credential};
use crate::config::{Config, ConnKind};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fmt;
use std::time::Duration;

/// The recorded token endpoint the code exchange and refresh share
/// (`anthropic.kdl:19,41`). A caller passes it explicitly so an offline
/// contract peer can stand in; the login path admits only this URL or a
/// loopback origin.
pub const TOKEN_ENDPOINT: &str = "https://api.anthropic.com/v1/oauth/token";

/// The recorded authorize endpoint (`anthropic.kdl:7`).
const AUTHORIZE_URL: &str = "https://claude.ai/oauth/authorize";
/// The recorded public OAuth client id, base64-decoded (`anthropic.kdl:9`).
const CLIENT_ID: &str = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";
/// The recorded scopes (`anthropic.kdl:12-13`), space-delimited on the URL.
const SCOPES: &str = "org:create_api_key user:profile user:inference \
                      user:sessions:claude_code user:mcp_servers user:file_upload";
/// The recorded loopback callback (`anthropic.kdl:17`).
const CALLBACK_ORIGIN: &str = "http://127.0.0.1:54545";
const CALLBACK_PATH: &str = "/callback";
const REDIRECT_URI: &str = "http://127.0.0.1:54545/callback";
/// The refresh-only beta the recorded contract sends (`anthropic.kdl:36`).
const REFRESH_BETA: &str = "oauth-2025-04-20";
/// The recorded refresh user agent, pinned to the recorded Claude Code
/// SDK version (`claude_code_sdk_version` = `2.1.257`).
const REFRESH_AGENT: &str = "anthropic-sdk-typescript/2.1.257 userOAuthProvider";
/// One login leg's whole budget, shared by connect, request and read.
const LOGIN_TIMEOUT: Duration = Duration::from_secs(30);

/// The recorded skew subtracted from the peer's `expires_in` lifetime.
const EXPIRY_SKEW: Duration = Duration::from_secs(300);

/// One in-flight authorize leg: the URL the operator opens, the CSRF
/// state that must come back, and the PKCE pair it carries. `Debug`
/// redacts the verifier — only the wire's public half is printable.
pub struct LoginSession {
    authorize_url: String,
    state: String,
    code_verifier: String,
    code_challenge: String,
}

impl fmt::Debug for LoginSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoginSession")
            .field("authorize_url", &self.authorize_url)
            .field("state", &self.state)
            .field("code_verifier", &"<redacted>")
            .field("code_challenge", &self.code_challenge)
            .finish()
    }
}

impl LoginSession {
    /// The recorded authorize URL to open — the query carries the state,
    /// the challenge and the recorded scopes.
    #[must_use]
    pub fn authorize_url(&self) -> &str {
        &self.authorize_url
    }

    /// The CSRF state this session requires on the redirect.
    #[must_use]
    pub fn state(&self) -> &str {
        &self.state
    }

    /// The PKCE verifier the exchange presents. One-time secret: never
    /// printed, logged or stored by this module.
    #[must_use]
    pub fn code_verifier(&self) -> &str {
        &self.code_verifier
    }

    /// The S256 challenge the authorize leg published.
    #[must_use]
    pub fn code_challenge(&self) -> &str {
        &self.code_challenge
    }
}

/// The S256 PKCE challenge of a verifier: SHA-256 over the verifier's
/// bytes, base64url without padding (RFC 7636 §4.2).
#[must_use]
pub fn challenge_for(code_verifier: &str) -> String {
    login_common::challenge_for(code_verifier)
}

/// Builds one authorize leg from OS entropy. The verifier and state are
/// independent 32-byte draws rendered base64url.
///
/// # Errors
/// [`LoginError::Entropy`] when the platform entropy source fails.
pub fn begin_login() -> Result<LoginSession, LoginError> {
    let state = login_common::random_urlsafe()?;
    let code_verifier = login_common::random_urlsafe()?;
    let code_challenge = challenge_for(&code_verifier);
    let authorize_url = format!(
        "{AUTHORIZE_URL}?code=true&client_id={CLIENT_ID}&redirect_uri={}&response_type=code&scope={}&state={state}&code_challenge={code_challenge}&code_challenge_method=S256",
        login_common::encode_component(REDIRECT_URI),
        login_common::encode_component(SCOPES),
    );
    Ok(LoginSession {
        authorize_url,
        state,
        code_verifier,
        code_challenge,
    })
}

/// Completes one login: verifies the callback's origin and CSRF state,
/// exchanges the code against the token endpoint, binds the organization
/// the response reports, writes the scoped subscription credential, and
/// answers the profile name the credential scope carries.
///
/// The connection must be declared `subscription`, so an API-key
/// connection's scope is never written by this path. A rejected or
/// interrupted write leaves the previous material untouched. Enrollment
/// is create-only: a scope that already holds material denies
/// [`ProviderError::CredentialOccupied`], so a second login first clears
/// the scope through [`clear_subscription`].
///
/// # Errors
/// [`LoginError::NotARedirect`]/[`LoginError::OriginMismatch`]/
/// [`LoginError::StateMismatch`] before any wire leg;
/// [`LoginError::Cancelled`]/[`LoginError::Denied`] for a refused
/// authorize leg; [`LoginError::EndpointNotRecorded`],
/// [`LoginError::TokenRejected`] and [`LoginError::MissingField`] for a
/// rejecting or incomplete peer; [`LoginError::NotSubscription`] and
/// [`LoginError::Provider`] for the config binding and store seam —
/// including [`ProviderError::CredentialOccupied`] on an already
/// enrolled scope.
pub fn complete_login(
    config: &Config,
    connection: &str,
    session: &LoginSession,
    redirect: &str,
    token_endpoint: &str,
    store: &dyn CredentialStore,
) -> Result<String, LoginError> {
    let reference = subscription_reference(config, connection)?;
    let callback = parse_callback(redirect)?;
    if callback.state.as_deref() != Some(session.state.as_str()) {
        return Err(LoginError::StateMismatch);
    }
    if let Some(error) = callback.error {
        return Err(if error == "access_denied" {
            LoginError::Cancelled
        } else {
            LoginError::Denied {
                code: bounded_reason(error),
            }
        });
    }
    let code = callback.code.ok_or(LoginError::MissingCode)?;
    let reply = exchange(
        connection,
        token_endpoint,
        &json!({
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": CLIENT_ID,
            "code_verifier": session.code_verifier,
            "state": session.state,
        }),
        false,
    )?;
    let material = SubscriptionCredential::from_login(&reply)?;
    store.login(&reference, &serialize(&material)?)?;
    Ok(reference.profile().to_string())
}

/// Refreshes the subscription credential at the connection's declared
/// scope. Only `access_token`, `refresh_token` and `expires_in` are read
/// from the reply: the organization and account identity captured at
/// login are carried forward, never rebound.
///
/// # Errors
/// [`LoginError::NotSubscription`] for a non-subscription binding;
/// [`LoginError::StoredCredentialMalformed`] when the stored material is
/// not a subscription credential; [`LoginError::TokenRejected`] for an
/// expired or revoked grant; the [`LoginError::Provider`] store denial;
/// the exchange denials [`complete_login`] documents.
pub fn refresh_login(
    config: &Config,
    connection: &str,
    token_endpoint: &str,
    store: &dyn CredentialStore,
) -> Result<String, LoginError> {
    let reference = subscription_reference(config, connection)?;
    let stored = read_subscription(store, &reference)?;
    let reply = exchange(
        connection,
        token_endpoint,
        &json!({
            "grant_type": "refresh_token",
            "refresh_token": stored.refresh_token,
            "client_id": CLIENT_ID,
        }),
        true,
    )?;
    let refreshed = stored.refreshed(&reply)?;
    store.refresh(&reference, &serialize(&refreshed)?)?;
    Ok(reference.profile().to_string())
}

/// Reads the subscription credential at a scoped reference — the seam
/// the Messages adapter consumes an access token through. Parsing is
/// strict: foreign material is a typed denial, never a guess.
///
/// # Errors
/// The [`LoginError::Provider`] store denial, and
/// [`LoginError::StoredCredentialMalformed`] when the material is not a
/// subscription credential.
pub fn read_subscription(
    store: &dyn CredentialStore,
    reference: &SecretRef,
) -> Result<SubscriptionCredential, LoginError> {
    let bytes = store.resolve(reference)?;
    serde_json::from_slice(&bytes).map_err(|cause| LoginError::StoredCredentialMalformed {
        reason: login_common::malformed_reason(&cause),
    })
}

/// Deletes the subscription credential at `credential` through the store's
/// `logout`, opening the scope for the next [`complete_login`]. This is
/// the revoke half of the recorded revoke → login sequence; a refresh is
/// the in-place rotation path and never needs it.
///
/// # Errors
/// [`LoginError::Provider`] with [`ProviderError::CredentialAbsent`] when
/// the scope holds no material, and the store's other typed denials.
pub fn clear_subscription(
    store: &dyn CredentialStore,
    credential: &SecretRef,
) -> Result<(), LoginError> {
    store.logout(credential)?;
    Ok(())
}

/// The scoped subscription credential written at login. Tokens are the
/// stored material and never appear in `Debug`.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubscriptionCredential {
    access_token: String,
    refresh_token: String,
    expires_at: u64,
    account_id: Option<String>,
    email: Option<String>,
    organization_id: String,
    organization_name: Option<String>,
}

impl fmt::Debug for SubscriptionCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SubscriptionCredential")
            .field("access_token", &login_common::redacted(&self.access_token))
            .field(
                "refresh_token",
                &login_common::redacted(&self.refresh_token),
            )
            .field("expires_at", &self.expires_at)
            .field("account_id", &self.account_id)
            .field("email", &self.email.as_ref().map(|_address| "<redacted>"))
            .field("organization_id", &self.organization_id)
            .field("organization_name", &self.organization_name)
            .finish()
    }
}

impl SubscriptionCredential {
    /// The access token a Messages adapter sends as its bearer.
    #[must_use]
    pub fn access_token(&self) -> &str {
        &self.access_token
    }

    /// The organization the credential was bound to at login.
    #[must_use]
    pub fn organization_id(&self) -> &str {
        &self.organization_id
    }

    /// The organization's recorded name, when the response carried one.
    #[must_use]
    pub fn organization_name(&self) -> Option<&str> {
        self.organization_name.as_deref()
    }

    /// The access token's expiry, in seconds since the Unix epoch, with
    /// the recorded skew already subtracted.
    #[must_use]
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    fn from_login(reply: &Value) -> Result<Self, LoginError> {
        Ok(Self {
            access_token: token_field(reply, "access_token")?,
            refresh_token: token_field(reply, "refresh_token")?,
            expires_at: expires_at(expires_in(reply)?)?,
            account_id: nested_optional(reply, "account", "uuid"),
            email: nested_optional(reply, "account", "email_address"),
            organization_id: nested_field(reply, "organization", "uuid")?,
            organization_name: nested_optional(reply, "organization", "name"),
        })
    }

    fn refreshed(&self, reply: &Value) -> Result<Self, LoginError> {
        Ok(Self {
            access_token: token_field(reply, "access_token")?,
            refresh_token: token_field(reply, "refresh_token")?,
            expires_at: expires_at(expires_in(reply)?)?,
            // The recorded refresh deliberately does not remap identity:
            // the org fixed at login is the one the credential stays in.
            account_id: self.account_id.clone(),
            email: self.email.clone(),
            organization_id: self.organization_id.clone(),
            organization_name: self.organization_name.clone(),
        })
    }
}

/// One login lifecycle failure. Display text is English and lowercase,
/// and never carries the code, the verifier or a token.
#[derive(Debug, thiserror::Error)]
pub enum LoginError {
    /// The platform entropy source could not fill the verifier/state.
    #[error("entropy source is unavailable: {cause}")]
    Entropy { cause: getrandom::Error },
    /// The redirect is not a URL this callback route can parse.
    #[error("redirect is not the recorded callback url")]
    NotARedirect,
    /// The redirect's origin or route is not the recorded callback.
    #[error("redirect origin is outside the recorded callback")]
    OriginMismatch,
    /// The redirect's `state` is not this session's CSRF state.
    #[error("redirect state does not match this login")]
    StateMismatch,
    /// The operator cancelled the authorize leg.
    #[error("authorization was cancelled")]
    Cancelled,
    /// The authorize leg refused the request with a peer error code.
    #[error("authorization was denied: {code}")]
    Denied { code: String },
    /// A successful redirect carried no authorization code.
    #[error("redirect carries no authorization code")]
    MissingCode,
    /// The token endpoint is neither the recorded URL nor a loopback peer.
    /// `origin` is the canonical scheme/host class — never the raw URL,
    /// which may carry userinfo.
    #[error("token endpoint origin {origin} is outside the recorded contract")]
    EndpointNotRecorded { origin: String },
    /// The token endpoint answered a non-success status — an expired or
    /// revoked grant lands here, and the body is never read.
    #[error("the token endpoint answered with http status {status}")]
    TokenRejected { status: u16 },
    /// A 2xx reply omitted a recorded field.
    #[error("the token response carries no {field}")]
    MissingField { field: &'static str },
    /// A 2xx reply exceeded the bounded response size.
    #[error("the token response exceeds the byte bound")]
    ResponseTooLarge,
    /// A 2xx reply was not the JSON object the contract records.
    #[error("the token endpoint answered malformed json")]
    MalformedResponse {
        #[source]
        cause: serde_json::Error,
    },
    /// The connection is declared with another kind, so login must not
    /// write its scope.
    #[error("connection {connection} is {kind}, not a subscription")]
    NotSubscription { connection: String, kind: ConnKind },
    /// The material at the scope is not a subscription credential.
    /// serde's own diagnostic can quote the stored bytes, so only its
    /// class is kept.
    #[error("the stored credential is not a subscription credential: {reason}")]
    StoredCredentialMalformed { reason: &'static str },
    /// The in-memory credential could not be encoded for the store.
    #[error("the subscription credential could not be serialized")]
    Serialization {
        #[source]
        cause: serde_json::Error,
    },
    /// The system clock is before the Unix epoch, so no expiry applies.
    #[error("system clock is before the unix epoch: {cause}")]
    Clock { cause: std::time::SystemTimeError },
    /// The credential seam's typed denial — unavailable/ambiguous store,
    /// an occupied scope, or a scope outside the backend's namespace.
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

/// The redirect's recorded members; unknown query keys are ignored, a
/// duplicated recorded key is a malformed redirect.
struct Callback {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

/// Parses the loopback callback URL. Origin and route are compared as
/// exact strings, so a look-alike host never matches.
fn parse_callback(redirect: &str) -> Result<Callback, LoginError> {
    let rest = redirect
        .strip_prefix("http://")
        .ok_or(LoginError::NotARedirect)?;
    let (authority, target) = rest.split_once('/').ok_or(LoginError::NotARedirect)?;
    if format!("http://{authority}") != CALLBACK_ORIGIN {
        return Err(LoginError::OriginMismatch);
    }
    let target = format!("/{target}");
    let (path, query) = target.split_once('?').unwrap_or((&target, ""));
    if path != CALLBACK_PATH {
        return Err(LoginError::OriginMismatch);
    }
    let mut callback = Callback {
        code: None,
        state: None,
        error: None,
    };
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = pair.split_once('=').ok_or(LoginError::NotARedirect)?;
        let value = percent_decode(value)?;
        match key {
            "code" => callback.code = Some(unique(callback.code, value)?),
            "state" => callback.state = Some(unique(callback.state, value)?),
            "error" => callback.error = Some(unique(callback.error, value)?),
            _ => {}
        }
    }
    Ok(callback)
}

/// A recorded query key may appear once; a duplicate is a malformed
/// redirect rather than a last-one-wins guess.
fn unique(slot: Option<String>, value: String) -> Result<String, LoginError> {
    if slot.is_some() {
        return Err(LoginError::NotARedirect);
    }
    Ok(value)
}

/// The config binding's scoped reference. Only a `subscription` row may
/// be written by the login path, so an API-key profile can never be
/// overwritten through it.
fn subscription_reference(config: &Config, connection: &str) -> Result<SecretRef, LoginError> {
    let entry =
        config
            .connections
            .get(connection)
            .ok_or_else(|| ProviderError::UnknownConnection {
                connection: connection.to_string(),
            })?;
    if entry.kind != ConnKind::Subscription {
        return Err(LoginError::NotSubscription {
            connection: connection.to_string(),
            kind: entry.kind,
        });
    }
    Ok(resolve_credential(config, connection)?)
}

/// Posts one token request and returns the parsed JSON object. The code
/// and the verifier ride a JSON body — the recorded form — and the
/// refresh adds the recorded beta and user agent only.
fn exchange(
    connection: &str,
    token_endpoint: &str,
    body: &Value,
    refresh: bool,
) -> Result<Value, LoginError> {
    if !admitted_endpoint(token_endpoint) {
        return Err(LoginError::EndpointNotRecorded {
            origin: endpoint_origin(token_endpoint),
        });
    }
    let headers: &[(&str, &str)] = if refresh {
        &[
            ("anthropic-beta", REFRESH_BETA),
            ("user-agent", REFRESH_AGENT),
        ]
    } else {
        &[]
    };
    let (mut response, started) = login_common::post(
        connection,
        token_endpoint,
        LOGIN_TIMEOUT,
        Body::Json(body),
        headers,
    )?;
    if !response.status().is_success() {
        return Err(LoginError::TokenRejected {
            status: response.status().as_u16(),
        });
    }
    let reply = read_token_body(connection, &mut response, started)?;
    Ok(login_common::parse_json(&reply)?)
}

/// The token endpoint is the recorded URL or a loopback contract peer;
/// anything else would carry the code and verifier to a foreign host. The
/// URL is parsed, so userinfo never impersonates the host it precedes.
fn admitted_endpoint(endpoint: &str) -> bool {
    login_common::admitted_endpoint(endpoint, TOKEN_ENDPOINT)
}

/// The canonical scheme/host class a rejected endpoint names — never the
/// raw URL, which may carry the code or userinfo.
fn endpoint_origin(endpoint: &str) -> String {
    login_common::endpoint_origin(endpoint)
}

/// The token reply under the login leg's budget and byte bound — a
/// dribbling or oversized body is denied, never buffered unbounded. The
/// bound is the shared catalogue bound, but the denial stays this
/// module's [`LoginError::ResponseTooLarge`]; the oversize login case
/// pins that fork.
fn read_token_body(
    connection: &str,
    response: &mut reqwest::blocking::Response,
    started: std::time::Instant,
) -> Result<Vec<u8>, LoginError> {
    Ok(login_common::read_body(
        connection,
        response,
        LOGIN_TIMEOUT,
        started,
    )?)
}

/// A non-empty string member of the token reply's top level.
fn token_field(reply: &Value, field: &'static str) -> Result<String, LoginError> {
    login_common::text_field(reply, field).ok_or(LoginError::MissingField { field })
}

/// A non-empty string member of a recorded identity section.
fn nested_field(reply: &Value, section: &str, field: &'static str) -> Result<String, LoginError> {
    nested_optional(reply, section, field).ok_or(LoginError::MissingField { field })
}

fn nested_optional(reply: &Value, section: &str, field: &str) -> Option<String> {
    reply
        .get(section)
        .and_then(|value| value.get(field))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

/// The recorded `expires_in` is an integer seconds count; a string or a
/// float is a peer contract violation, never coerced.
fn expires_in(reply: &Value) -> Result<u64, LoginError> {
    reply
        .get("expires_in")
        .and_then(Value::as_u64)
        .ok_or(LoginError::MissingField {
            field: "expires_in",
        })
}

/// The stored expiry with the recorded skew already subtracted.
fn expires_at(expires_in: u64) -> Result<u64, LoginError> {
    Ok(login_common::expires_at(expires_in, EXPIRY_SKEW)?)
}

fn serialize(material: &SubscriptionCredential) -> Result<Vec<u8>, LoginError> {
    serde_json::to_vec(material).map_err(|cause| LoginError::Serialization { cause })
}

fn percent_decode(raw: &str) -> Result<String, LoginError> {
    login_common::percent_decode(raw).ok_or(LoginError::NotARedirect)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_renders_the_recorded_client_id_bytes() {
        // The recorded client id is stored base64 in the source; the
        // hand-rolled codec is proven against those exact bytes.
        assert_eq!(
            login_common::base64url(&[
                0x9d, 0x1c, 0x25, 0x0a, 0xe6, 0x1b, 0x44, 0xd9, 0x88, 0xed, 0x59, 0x44, 0xd1, 0x96,
                0x2f, 0x5e
            ]),
            "nRwlCuYbRNmI7VlE0ZYvXg"
        );
    }

    #[test]
    fn percent_decode_reads_utf8_and_rejects_malformed_escapes() {
        assert_eq!(percent_decode("a%2Bb%20c").expect("decode"), "a+b c");
        assert!(matches!(
            percent_decode("a%zz"),
            Err(LoginError::NotARedirect)
        ));
        assert!(matches!(
            percent_decode("%ff"),
            Err(LoginError::NotARedirect)
        ));
    }
}
