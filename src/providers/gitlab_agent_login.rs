//! GitLab Duo Agent workspace login: the recorded manual-callback OAuth leg,
//! its form exchange, the PAT enrollment and the canonical scoped workspace
//! profile. Library-level — no CLI verb is added.
//!
//! The recorded contract is OMP's `rules/auth/gitlab-duo-agent.kdl`
//! (`0133f7ff`): the authorize URL `https://gitlab.com/oauth/authorize` with
//! the official VS Code OAuth client id, scope `api`, S256 PKCE and the manual
//! callback `vscode://gitlab.gitlab-workflow/authentication`; the form token
//! exchange at `https://gitlab.com/oauth/token`; and the form refresh carrying
//! the fixed `redirect_uri`. Expiry is the response's `expires_in` counted
//! from `created_at`, less the recorded five-minute skew. The stored form is
//! closed: `kind = "oauth"` keeps the refresh/expiry fields,
//! `kind = "pat"` keeps neither, and both carry the operator's `origin`,
//! `namespace` and optional `project`.
//!
//! Enrollment is create-only through [`CredentialStore::login`]: an occupied
//! scope or a refused store operation denies and leaves the prior bytes
//! untouched. The PKCE verifier is single-exchange and never enters `Debug`,
//! an error or a diagnostic; every token is redacted in the stored profile's
//! `Debug`.

use super::login_common::{self, BindingError, Body, CommonError};
use super::{CredentialStore, ProviderError, SecretRef};
use crate::config::{Config, ConnKind};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;
use std::time::Duration;

/// The only instance origin this build admits.
pub const ORIGIN: &str = "https://gitlab.com";

/// The recorded authorize leg the operator opens.
pub const AUTHORIZE_URL: &str = "https://gitlab.com/oauth/authorize";

/// The recorded form token and refresh exchange.
pub const TOKEN_URL: &str = "https://gitlab.com/oauth/token";

/// The recorded official VS Code OAuth application.
pub const CLIENT_ID: &str = "36f2a70cddeb5a0889d4fd8295c241b7e9848e89cf9e599d0eed2d8e5350fbf5";

/// The recorded manual callback the operator pastes back.
pub const CALLBACK_URL: &str = "vscode://gitlab.gitlab-workflow/authentication";

/// The recorded OAuth scope.
pub const OAUTH_SCOPE: &str = "api";

/// One exchange leg's whole budget, shared by connect, request and read.
const LOGIN_TIMEOUT: Duration = Duration::from_secs(30);

/// The recorded skew subtracted from `created_at + expires_in`.
const EXPIRY_SKEW: Duration = Duration::from_secs(300);

/// The two recorded endpoints. Production callers pass
/// [`GitlabEndpoints::recorded`]; tests pass loopback peers. The override is
/// not a config surface.
#[derive(Debug, Clone)]
pub struct GitlabEndpoints {
    authorize: String,
    token: String,
}

impl GitlabEndpoints {
    /// One endpoint pair for the recorded contract or a loopback peer.
    #[must_use]
    pub fn new(authorize: &str, token: &str) -> Self {
        Self {
            authorize: authorize.to_string(),
            token: token.to_string(),
        }
    }

    /// The recorded production endpoints.
    #[must_use]
    pub fn recorded() -> Self {
        Self::new(AUTHORIZE_URL, TOKEN_URL)
    }
}

/// The operator-supplied workspace scope the profile records. `origin` is the
/// instance origin, `namespace` the GitLab namespace path and `project` the
/// optional project path; none of them comes from the OAuth response.
#[derive(Debug, Clone)]
pub struct WorkspaceScope {
    origin: String,
    namespace: String,
    project: Option<String>,
}

impl WorkspaceScope {
    /// One workspace scope from its operator inputs.
    #[must_use]
    pub fn new(origin: &str, namespace: &str, project: Option<&str>) -> Self {
        Self {
            origin: origin.to_string(),
            namespace: namespace.to_string(),
            project: project.map(str::to_string),
        }
    }
}

/// One in-flight login leg: the URL the operator opens, the UUID state the
/// pasted callback must echo, the single-exchange PKCE pair, the endpoints and
/// the operator scope. `Debug` redacts the verifier — only the wire's public
/// half is printable.
pub struct LoginSession {
    login_url: String,
    state: String,
    code_verifier: String,
    code_challenge: String,
    endpoints: GitlabEndpoints,
    scope: WorkspaceScope,
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

    /// The UUID state the pasted callback must echo.
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
/// base64url, its S256 challenge, and a UUID v4 state. Only
/// [`ORIGIN`] and the recorded or loopback endpoints are admitted.
///
/// # Errors
/// [`LoginError::OriginNotRecorded`] for another instance origin;
/// [`LoginError::EndpointNotRecorded`] for a foreign endpoint;
/// [`LoginError::Entropy`] when the platform entropy source fails.
pub fn begin_login(
    scope: &WorkspaceScope,
    endpoints: &GitlabEndpoints,
) -> Result<LoginSession, LoginError> {
    admit_origin(scope)?;
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
        "{}?client_id={}&response_type=code&redirect_uri={}&scope={}&code_challenge={}&code_challenge_method=S256&state={}",
        endpoints.authorize,
        login_common::encode_component(CLIENT_ID),
        login_common::encode_component(CALLBACK_URL),
        login_common::encode_component(OAUTH_SCOPE),
        login_common::encode_component(&code_challenge),
        login_common::encode_component(&state),
    );
    Ok(LoginSession {
        login_url,
        state,
        code_verifier,
        code_challenge,
        endpoints: endpoints.clone(),
        scope: scope.clone(),
    })
}

/// Verifies one pasted manual callback and performs the recorded form
/// exchange. The callback must be the fixed [`CALLBACK_URL`] origin and path
/// and its `state` must equal the session's; a cancellation (`error`) or
/// missing code denies before any request. A successful reply is stored with
/// `kind = "oauth"`, the session's operator scope and the expiry from
/// `created_at + expires_in - 300 s`. Enrollment is create-only, so an
/// occupied scope denies and its prior bytes stay byte-identical.
///
/// # Errors
/// [`LoginError::CallbackNotRecorded`] for a foreign origin or path;
/// [`LoginError::StateMismatch`]/[`LoginError::Cancelled`] for the callback
/// negatives; [`LoginError::MissingField`] for a callback without `code` or a
/// reply without a recorded member;
/// [`LoginError::ConnectionMissing`]/[`LoginError::NotApiKey`] for the config
/// binding; [`LoginError::TokenRejected`] for a refusing peer; the response,
/// clock, serialization and store denials this module documents.
pub fn complete(
    config: &Config,
    connection: &str,
    session: &LoginSession,
    callback: &str,
    store: &dyn CredentialStore,
) -> Result<String, LoginError> {
    let reference = login_common::api_key_reference(config, connection)?;
    let code = verify_callback(callback, session)?;
    let fields = [
        ("grant_type", "authorization_code"),
        ("client_id", CLIENT_ID),
        ("code", code.as_str()),
        ("redirect_uri", CALLBACK_URL),
        ("code_verifier", session.code_verifier.as_str()),
    ];
    let (mut response, started) = login_common::post(
        connection,
        &session.endpoints.token,
        LOGIN_TIMEOUT,
        Body::Form(&fields),
        &[],
    )?;
    if !response.status().is_success() {
        return Err(LoginError::TokenRejected {
            status: response.status().as_u16(),
        });
    }
    let body = login_common::read_body(connection, &mut response, LOGIN_TIMEOUT, started)?;
    let reply = login_common::parse_json(&body)?;
    enroll_oauth(&reference, &reply, &session.scope, store)
}

/// Stores the recorded personal-access-token form at the canonical scope:
/// `kind = "pat"`, the token, the operator scope and no refresh or expiry
/// field. Enrollment is create-only, so an occupied scope denies and its
/// prior bytes stay byte-identical.
///
/// # Errors
/// [`LoginError::OriginNotRecorded`] for another instance origin;
/// [`LoginError::MissingField`] for an empty or whitespace-only token;
/// [`LoginError::ConnectionMissing`]/[`LoginError::NotApiKey`] for the config
/// binding; the serialization and store denials this module documents.
pub fn enroll_pat(
    config: &Config,
    connection: &str,
    token: &str,
    scope: &WorkspaceScope,
    store: &dyn CredentialStore,
) -> Result<String, LoginError> {
    let reference = login_common::api_key_reference(config, connection)?;
    let credential = pat_credential(token, scope)?;
    store.login(&reference, &serialize(&credential)?)?;
    Ok(reference.profile().to_string())
}

/// Replaces the stored OAuth profile's token and expiry from the recorded form
/// refresh, carrying the fixed `redirect_uri`. `origin`, `namespace` and
/// `project` are preserved: a refresh never rebinds the workspace. A PAT has
/// no refresh leg and denies [`LoginError::RefreshUnavailable`].
///
/// # Errors
/// [`LoginError::EndpointNotRecorded`] for a foreign token endpoint;
/// [`LoginError::StoredCredentialMalformed`] when the scope does not hold a
/// GitLab workspace profile; [`LoginError::RefreshUnavailable`] for a PAT;
/// [`LoginError::TokenRejected`] for a refusing peer; the reply and store
/// denials [`complete`] documents.
pub fn refresh(
    config: &Config,
    connection: &str,
    token_endpoint: &str,
    store: &dyn CredentialStore,
) -> Result<String, LoginError> {
    if !login_common::admitted_endpoint(token_endpoint, TOKEN_URL) {
        return Err(LoginError::EndpointNotRecorded {
            origin: login_common::endpoint_origin(token_endpoint),
        });
    }
    let reference = login_common::api_key_reference(config, connection)?;
    let stored = read_credential(store, &reference)?;
    let prior_refresh = match stored.kind {
        CredentialKind::Pat => return Err(LoginError::RefreshUnavailable),
        CredentialKind::Oauth => stored
            .refresh_token
            .clone()
            .ok_or(LoginError::MissingField {
                field: "refresh_token",
            })?,
    };
    let fields = [
        ("grant_type", "refresh_token"),
        ("client_id", CLIENT_ID),
        ("refresh_token", prior_refresh.as_str()),
        ("redirect_uri", CALLBACK_URL),
    ];
    let (mut response, started) = login_common::post(
        connection,
        token_endpoint,
        LOGIN_TIMEOUT,
        Body::Form(&fields),
        &[],
    )?;
    if !response.status().is_success() {
        return Err(LoginError::TokenRejected {
            status: response.status().as_u16(),
        });
    }
    let body = login_common::read_body(connection, &mut response, LOGIN_TIMEOUT, started)?;
    let reply = login_common::parse_json(&body)?;
    let access_token = text_field(&reply, "access_token")?;
    let refresh_token = login_common::text_field(&reply, "refresh_token").unwrap_or(prior_refresh);
    let expires_at = token_expiry(&reply)?;
    let updated = WorkspaceCredential {
        kind: CredentialKind::Oauth,
        access_token,
        refresh_token: Some(refresh_token),
        expires_at: Some(expires_at),
        origin: stored.origin,
        namespace: stored.namespace,
        project: stored.project,
    };
    store.refresh(&reference, &serialize(&updated)?)?;
    Ok(reference.profile().to_string())
}

/// Reads the GitLab workspace profile at a scoped reference. Parsing is
/// strict: foreign material is a typed denial, never a guess.
///
/// # Errors
/// The [`LoginError::Provider`] store denial — including
/// [`ProviderError::CredentialAbsent`] for another scope — and
/// [`LoginError::StoredCredentialMalformed`] when the material is not a
/// GitLab workspace profile. A profile whose recorded origin is not
/// [`ORIGIN`] denies [`ProviderError::CredentialMalformed`] naming the
/// connection after parsing, so a manually seeded foreign instance can
/// never be read as this class.
pub fn read_credential(
    store: &dyn CredentialStore,
    reference: &SecretRef,
) -> Result<WorkspaceCredential, LoginError> {
    let bytes = store.resolve(reference)?;
    let credential: WorkspaceCredential =
        serde_json::from_slice(&bytes).map_err(|cause| LoginError::StoredCredentialMalformed {
            reason: login_common::malformed_reason(&cause),
        })?;
    if credential.origin != ORIGIN {
        return Err(LoginError::Provider(ProviderError::CredentialMalformed {
            connection: "gitlab-duo-agent".to_string(),
        }));
    }
    Ok(credential)
}

/// The stored credential form: `oauth` or `pat`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CredentialKind {
    /// The OAuth form with a refresh token and an expiry.
    Oauth,
    /// The personal-access-token form with neither.
    Pat,
}

/// The canonical scoped workspace profile. `oauth` carries the refresh token
/// and expiry; `pat` omits both on the wire. Every token is redacted in
/// `Debug`; `origin`, `namespace` and `project` are non-secret scope
/// identifiers and render verbatim, and unknown fields deny.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceCredential {
    kind: CredentialKind,
    access_token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expires_at: Option<u64>,
    origin: String,
    namespace: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    project: Option<String>,
}

impl fmt::Debug for WorkspaceCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WorkspaceCredential")
            .field("kind", &self.kind)
            .field("access_token", &login_common::redacted(&self.access_token))
            .field(
                "refresh_token",
                &self.refresh_token.as_deref().map(login_common::redacted),
            )
            .field("expires_at", &self.expires_at)
            .field("origin", &self.origin)
            .field("namespace", &self.namespace)
            .field("project", &self.project)
            .finish()
    }
}

impl WorkspaceCredential {
    /// The stored form.
    #[must_use]
    pub fn kind(&self) -> CredentialKind {
        self.kind
    }

    /// The access token a GitLab workspace consumer would send.
    #[must_use]
    pub fn access_token(&self) -> &str {
        &self.access_token
    }

    /// The refresh token the recorded OAuth exchange presents, or `None` for
    /// a PAT.
    #[must_use]
    pub fn refresh_token(&self) -> Option<&str> {
        self.refresh_token.as_deref()
    }

    /// The access token's expiry in seconds since the Unix epoch with the
    /// recorded skew already subtracted, or `None` for a PAT.
    #[must_use]
    pub fn expires_at(&self) -> Option<u64> {
        self.expires_at
    }

    /// The instance origin the operator declared.
    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// The GitLab namespace the workspace resolves under.
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// The optional GitLab project path.
    #[must_use]
    pub fn project(&self) -> Option<&str> {
        self.project.as_deref()
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
    /// The instance origin is not the one this build records.
    #[error("gitlab workspace origin {origin} is outside the recorded contract")]
    OriginNotRecorded { origin: String },
    /// The endpoint is neither its recorded URL nor a loopback peer.
    /// `origin` is the canonical scheme/host class — never the raw URL,
    /// which may carry a code or a verifier.
    #[error("gitlab endpoint origin {origin} is outside the recorded contract")]
    EndpointNotRecorded { origin: String },
    /// The pasted callback is not the recorded manual callback origin and
    /// path. `origin` never carries the callback's query.
    #[error("gitlab callback {origin} is outside the recorded manual callback")]
    CallbackNotRecorded { origin: String },
    /// The callback state is not the one this login leg minted.
    #[error("the gitlab callback state does not match this login")]
    StateMismatch,
    /// The browser answered a cancellation instead of a code.
    #[error("the gitlab login was cancelled at the callback")]
    Cancelled,
    /// The canonical connection the operator must declare is absent.
    #[error("connection {connection} is not declared")]
    ConnectionMissing { connection: String },
    /// The login path writes only an `api_key` binding.
    #[error("connection {connection} is {kind}, not an api key")]
    NotApiKey { connection: String, kind: ConnKind },
    /// The token endpoint answered a non-2xx status.
    #[error("the gitlab token endpoint answered with http status {status}")]
    TokenRejected { status: u16 },
    /// A callback or reply omitted a recorded member.
    #[error("the gitlab response carries no {field}")]
    MissingField { field: &'static str },
    /// The token expiry is not a non-negative whole-second instant.
    #[error("the gitlab token expiry is not a non-negative whole second")]
    InvalidExpiry,
    /// The stored profile is a PAT, whose recorded class has no refresh leg.
    #[error("the gitlab workspace profile is a personal access token and has no refresh")]
    RefreshUnavailable,
    /// A reply exceeded the bounded response size.
    #[error("the gitlab response exceeds the byte bound")]
    ResponseTooLarge,
    /// A reply was not the JSON object the contract records.
    #[error("the gitlab endpoint answered malformed json")]
    MalformedResponse {
        #[source]
        cause: serde_json::Error,
    },
    /// The material at the scope is not a GitLab workspace profile.
    /// serde's own diagnostic can quote the stored bytes, so only its
    /// class is kept.
    #[error("the stored credential is not a gitlab workspace credential: {reason}")]
    StoredCredentialMalformed { reason: &'static str },
    /// The in-memory profile could not be encoded for the store.
    #[error("the gitlab workspace credential could not be serialized")]
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

fn admit_origin(scope: &WorkspaceScope) -> Result<(), LoginError> {
    if scope.origin == ORIGIN {
        return Ok(());
    }
    Err(LoginError::OriginNotRecorded {
        origin: login_common::endpoint_origin(&scope.origin),
    })
}

fn enroll_oauth(
    reference: &SecretRef,
    reply: &Value,
    scope: &WorkspaceScope,
    store: &dyn CredentialStore,
) -> Result<String, LoginError> {
    let access_token = text_field(reply, "access_token")?;
    let refresh_token = text_field(reply, "refresh_token")?;
    let expires_at = token_expiry(reply)?;
    let credential = WorkspaceCredential {
        kind: CredentialKind::Oauth,
        access_token,
        refresh_token: Some(refresh_token),
        expires_at: Some(expires_at),
        origin: scope.origin.clone(),
        namespace: scope.namespace.clone(),
        project: scope.project.clone(),
    };
    store.login(reference, &serialize(&credential)?)?;
    Ok(reference.profile().to_string())
}

fn pat_credential(token: &str, scope: &WorkspaceScope) -> Result<WorkspaceCredential, LoginError> {
    admit_origin(scope)?;
    let token = token.trim();
    if token.is_empty() {
        return Err(LoginError::MissingField { field: "token" });
    }
    Ok(WorkspaceCredential {
        kind: CredentialKind::Pat,
        access_token: token.to_string(),
        refresh_token: None,
        expires_at: None,
        origin: scope.origin.clone(),
        namespace: scope.namespace.clone(),
        project: scope.project.clone(),
    })
}

fn text_field(reply: &Value, field: &'static str) -> Result<String, LoginError> {
    login_common::text_field(reply, field).ok_or(LoginError::MissingField { field })
}

fn serialize(material: &WorkspaceCredential) -> Result<Vec<u8>, LoginError> {
    serde_json::to_vec(material).map_err(|cause| LoginError::Serialization { cause })
}

/// The recorded expiry: `created_at` plus `expires_in`, less five minutes.
/// A reply without `created_at` counts from the wall clock, as the recorded
/// producer does.
fn token_expiry(reply: &Value) -> Result<u64, LoginError> {
    let expires_in =
        recorded_seconds(reply.get("expires_in").ok_or(LoginError::MissingField {
            field: "expires_in",
        })?)?;
    let created_at = match reply.get("created_at") {
        Some(value) => recorded_seconds(value)?,
        None => login_common::clock_seconds()?,
    };
    Ok(created_at
        .saturating_add(expires_in)
        .saturating_sub(EXPIRY_SKEW.as_secs()))
}

fn recorded_seconds(value: &Value) -> Result<u64, LoginError> {
    if let Some(seconds) = value.as_u64() {
        return Ok(seconds);
    }
    let seconds = value.as_f64().filter(|seconds| {
        seconds.is_finite()
            && seconds.fract() == 0.0
            && *seconds >= 0.0
            && *seconds < u64::MAX as f64
    });
    seconds
        .map(|seconds| seconds as u64)
        .ok_or(LoginError::InvalidExpiry)
}

/// The pasted callback's one-time code after the fixed origin/path and state
/// checks. Duplicate query members keep the first, like the recorded
/// producer's `URLSearchParams.get`.
fn verify_callback(callback: &str, session: &LoginSession) -> Result<String, LoginError> {
    let url = reqwest::Url::parse(callback).map_err(|_parse| LoginError::CallbackNotRecorded {
        origin: login_common::endpoint_origin(callback),
    })?;
    if url.scheme() != "vscode"
        || url.host_str() != Some("gitlab.gitlab-workflow")
        || url.path() != "/authentication"
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_recorded_endpoints_and_scope_are_pinned() {
        let endpoints = GitlabEndpoints::recorded();
        assert_eq!(endpoints.authorize, AUTHORIZE_URL);
        assert_eq!(endpoints.token, TOKEN_URL);
        assert_eq!(ORIGIN, "https://gitlab.com");
        assert_eq!(OAUTH_SCOPE, "api");
        assert_eq!(
            CLIENT_ID,
            "36f2a70cddeb5a0889d4fd8295c241b7e9848e89cf9e599d0eed2d8e5350fbf5"
        );
        assert_eq!(
            CALLBACK_URL,
            "vscode://gitlab.gitlab-workflow/authentication"
        );
    }

    #[test]
    fn the_expiry_counts_from_created_at_with_the_recorded_skew() {
        let reply = serde_json::json!({ "expires_in": 7200, "created_at": 1_000 });
        assert_eq!(token_expiry(&reply).expect("the recorded expiry"), 7_900);
        let fractional = serde_json::json!({ "expires_in": 7200.0, "created_at": 1_000.0 });
        assert_eq!(
            token_expiry(&fractional).expect("an integral float expiry"),
            7_900
        );
        for reply in [
            serde_json::json!({ "created_at": 1_000 }),
            serde_json::json!({ "expires_in": -1, "created_at": 1_000 }),
            serde_json::json!({ "expires_in": 1.5, "created_at": 1_000 }),
            serde_json::json!({ "expires_in": 7200, "created_at": "yesterday" }),
        ] {
            let error = token_expiry(&reply).expect_err("a malformed expiry denies");
            assert!(
                matches!(
                    error,
                    LoginError::MissingField { .. } | LoginError::InvalidExpiry
                ),
                "{error}"
            );
        }
    }
}
