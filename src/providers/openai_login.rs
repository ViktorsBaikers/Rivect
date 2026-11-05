//! OpenAI Codex login lifecycle (DEC-020): the browser code+PKCE leg, the
//! device-code alias, the account/workspace binding, and the canonical
//! `openai-codex` credential written through the shipped
//! [`CredentialStore`] seam.
//!
//! The recorded contract is OMP's `rules/auth/openai-codex.kdl` and
//! `rules/auth/openai-codex-device.kdl` (`0133f7ff`): authorize
//! `https://auth.openai.com/oauth/authorize`, the recorded public client id
//! `app_EMoamEEZ73f0CkXaXp7hrann`, the six recorded scopes, PKCE `S256`,
//! the recorded callback `http://localhost:1455/auth/callback` (no port
//! fallback), the form-encoded exchange at
//! `https://auth.openai.com/oauth/token`, and the device pair
//! `/api/accounts/deviceauth/usercode` plus `/api/accounts/deviceauth/token`
//! behind `https://auth.openai.com/codex/device`. The device alias stores as
//! `openai-codex`, so both entrypoints write the one canonical profile.
//!
//! The ChatGPT workspace (`chatgpt_account_id`) and the account email come
//! from the access/id token claims. A login that answers another workspace
//! or account than the active profile denies typed; it never borrows the
//! stored token. A rejected exchange, an interrupted store write or an
//! expired device poll leaves the previous material untouched.
//!
//! The canonical connection is `kind = "api_key"` with the scoped OAuth
//! bearer at the credential ref (DEC-020), so the Broker's offline gate
//! admits it; a `subscription` declaration is refused here and keeps its
//! separate live-grant rule. Token material — the PKCE verifier, the device
//! handle and every token — never enters `Debug`, `Display` or a diagnostic.

use super::{
    CATALOG_MAX_BYTES, CredentialStore, ProviderError, STREAM_CHUNK_BYTES, SecretRef,
    bounded_reason, is_loopback_host, read_chunk, resolve_credential, transport,
};
use crate::config::{Config, ConnKind};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// The canonical profile both entrypoints write (DEC-020).
pub const CANONICAL_PROFILE: &str = "openai-codex";

/// The recorded token endpoint the exchange shares with the refresh
/// contract. A caller passes it explicitly so an offline contract peer can
/// stand in; the login path admits only this URL or a loopback origin.
pub const TOKEN_ENDPOINT: &str = "https://auth.openai.com/oauth/token";

/// The recorded authorize endpoint (`openai-codex.kdl`).
const AUTHORIZE_URL: &str = "https://auth.openai.com/oauth/authorize";
/// The recorded public OAuth client id.
const CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
/// The recorded scopes, space-delimited on the URL.
const SCOPES: &str = "openid profile email offline_access api.connectors.read \
                      api.connectors.invoke";
/// The recorded callback — OpenAI allowlists this exact URI, so a busy port
/// fails instead of falling back.
const CALLBACK_ORIGIN: &str = "http://localhost:1455";
const CALLBACK_PATH: &str = "/auth/callback";
const REDIRECT_URI: &str = "http://localhost:1455/auth/callback";
/// The recorded originator the authorize leg carries.
const ORIGINATOR: &str = "omp";
/// The recorded device endpoints and the page the operator opens.
pub const DEVICE_USERCODE_ENDPOINT: &str =
    "https://auth.openai.com/api/accounts/deviceauth/usercode";
pub const DEVICE_TOKEN_ENDPOINT: &str = "https://auth.openai.com/api/accounts/deviceauth/token";
pub const DEVICE_AUTH_URL: &str = "https://auth.openai.com/codex/device";
const DEVICE_REDIRECT_URI: &str = "https://auth.openai.com/deviceauth/callback";
/// The recorded expiry skew is `skew-ms=0`; the token's own `expires_in`
/// stands unadjusted.
const EXPIRY_SKEW: Duration = Duration::ZERO;
/// One login leg's whole budget, shared by connect, request and read. The
/// recorded token leg allows 15 seconds.
const LOGIN_TIMEOUT: Duration = Duration::from_secs(15);

// The test-only whole-leg budget: a case can shrink the ceiling without
// changing the recorded product value, so a dribbling peer proves the send
// and the body read share one deadline.
#[cfg(test)]
thread_local! {
    static TEST_LEG_TIMEOUT: std::cell::Cell<Option<Duration>> =
        const { std::cell::Cell::new(None) };
}

/// The budget the current leg runs under: the recorded value, or a test's
/// explicit override.
fn leg_timeout() -> Duration {
    #[cfg(test)]
    {
        TEST_LEG_TIMEOUT.with(|slot| slot.get().unwrap_or(LOGIN_TIMEOUT))
    }
    #[cfg(not(test))]
    {
        LOGIN_TIMEOUT
    }
}

/// Sets the current thread's whole-leg budget for one test; `None` restores
/// the recorded value.
#[cfg(test)]
fn set_test_leg_timeout(timeout: Option<Duration>) {
    TEST_LEG_TIMEOUT.with(|slot| slot.set(timeout));
}
/// The PKCE verifier's entropy: 32 bytes render a 43-character verifier.
const VERIFIER_BYTES: usize = 32;
/// The recorded polling fallback and the RFC 8628 increment, in seconds.
const DEVICE_INTERVAL_SECONDS: u64 = 5;
const DEVICE_SLOW_DOWN_SECONDS: u64 = 5;
/// The recorded poll ceiling (OMP's `DEVICE_MAX_POLLS` is 120 five-second
/// polls); it bounds a device handle whose reply carried no `expires_in`.
const DEVICE_DEFAULT_EXPIRY_SECONDS: u64 = 600;
/// The widest device lifetime this build admits: the recorded 120-poll
/// window (120 × (5 + 3) seconds). A peer value above it is a contract
/// violation, never an unbounded deadline.
const DEVICE_MAX_EXPIRY_SECONDS: u64 = 960;
/// The widest poll interval this build admits: the recorded lifetime ceiling,
/// so no peer value can schedule a poll past the device window.
const DEVICE_MAX_INTERVAL_SECONDS: u64 = DEVICE_MAX_EXPIRY_SECONDS;
/// The widest access-token lifetime this build admits: 30 days. A peer
/// `expires_in` above it would write a never-expiring credential, so the
/// exchange denies that contract violation instead.
const TOKEN_MAX_EXPIRY_SECONDS: u64 = 30 * 24 * 60 * 60;
/// The ChatGPT claim namespaces the identity slice reads.
const AUTH_CLAIM: &str = "https://api.openai.com/auth";
const PROFILE_CLAIM: &str = "https://api.openai.com/profile";

/// The recorded device endpoints; a caller may substitute loopback contract
/// peers, but every URL is admitted against its own recorded class.
#[derive(Debug, Clone)]
pub struct DeviceEndpoints {
    pub usercode: String,
    pub token: String,
    pub exchange: String,
}

impl DeviceEndpoints {
    #[must_use]
    pub fn recorded() -> Self {
        Self {
            usercode: DEVICE_USERCODE_ENDPOINT.to_string(),
            token: DEVICE_TOKEN_ENDPOINT.to_string(),
            exchange: TOKEN_ENDPOINT.to_string(),
        }
    }
}

/// One in-flight browser authorize leg: the URL the operator opens, the CSRF
/// state that must come back, the PKCE pair it carries, and the token
/// endpoint admitted at begin. `Debug` redacts the verifier — only the
/// wire's public half is printable.
pub struct LoginSession {
    connection: String,
    authorize_url: String,
    state: String,
    code_verifier: String,
    code_challenge: String,
    token_endpoint: String,
}

impl fmt::Debug for LoginSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoginSession")
            .field("connection", &self.connection)
            .field("authorize_url", &self.authorize_url)
            .field("state", &self.state)
            .field("code_verifier", &"<redacted>")
            .field("code_challenge", &self.code_challenge)
            .finish()
    }
}

impl LoginSession {
    /// The canonical connection the session was minted for.
    #[must_use]
    pub fn connection(&self) -> &str {
        &self.connection
    }

    /// The recorded authorize URL to open.
    #[must_use]
    pub fn authorize_url(&self) -> &str {
        &self.authorize_url
    }

    /// The CSRF state this session requires on the redirect.
    #[must_use]
    pub fn state(&self) -> &str {
        &self.state
    }

    /// The PKCE verifier the exchange presents. One-time secret.
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

/// One in-flight device-code leg. The device handle is the login state
/// `complete` polls with; `Debug` redacts it and the PKCE material, while
/// the verification URL and user code stay printable — they are the only
/// device output.
pub struct DeviceLoginSession {
    connection: String,
    state: String,
    verification_url: String,
    user_code: String,
    interval: Duration,
    expires_in: u64,
    deadline: Instant,
    next_poll_at: Instant,
    endpoints: DeviceEndpoints,
}

impl fmt::Debug for DeviceLoginSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceLoginSession")
            .field("connection", &self.connection)
            .field("state", &"<redacted>")
            .field("verification_url", &self.verification_url)
            .field("user_code", &self.user_code)
            .field("interval", &self.interval)
            .field("expires_in", &self.expires_in)
            .finish()
    }
}

impl DeviceLoginSession {
    /// The canonical connection the session was minted for.
    #[must_use]
    pub fn connection(&self) -> &str {
        &self.connection
    }

    /// The opaque device handle the poll presents.
    #[must_use]
    pub fn state(&self) -> &str {
        &self.state
    }

    /// The recorded page the operator opens.
    #[must_use]
    pub fn verification_url(&self) -> &str {
        &self.verification_url
    }

    /// The recorded user code the operator enters.
    #[must_use]
    pub fn user_code(&self) -> &str {
        &self.user_code
    }

    /// The peer-issued device-code lifetime in seconds.
    #[must_use]
    pub fn expires_in(&self) -> u64 {
        self.expires_in
    }
}

/// The one-step result of advancing a device login: the peer is still
/// pending, asked for a slower cadence, or answered the code that completed
/// the canonical profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceAdvance {
    Pending,
    SlowDown,
    Complete(String),
}

/// The S256 PKCE challenge of a verifier: SHA-256 over the verifier's bytes,
/// base64url without padding (RFC 7636 §4.2).
#[must_use]
pub fn challenge_for(code_verifier: &str) -> String {
    use sha2::Digest as _;
    base64url(&sha2::Sha256::digest(code_verifier.as_bytes()))
}

/// The recorded connection a login entrypoint writes: the device alias
/// stores as the canonical id, so both entrypoints share one profile.
#[must_use]
pub(crate) fn canonical_connection(connection: &str) -> &str {
    match connection {
        "openai-codex-device" => CANONICAL_PROFILE,
        other => other,
    }
}

/// Builds one browser authorize leg from OS entropy. The connection must
/// resolve to the canonical `openai-codex` api-key profile, and the token
/// endpoint must be the recorded URL or a loopback contract peer.
///
/// # Errors
/// [`LoginError::Entropy`] when the platform entropy source fails; the
/// config-binding denials [`canonical_reference`] documents; and
/// [`LoginError::EndpointNotRecorded`] for a foreign token endpoint.
pub fn begin_login(
    config: &Config,
    connection: &str,
    token_endpoint: &str,
) -> Result<LoginSession, LoginError> {
    let reference = canonical_reference(config, connection)?;
    if !admitted_endpoint(token_endpoint, TOKEN_ENDPOINT) {
        return Err(LoginError::EndpointNotRecorded {
            origin: endpoint_origin(token_endpoint),
        });
    }
    let state = random_urlsafe()?;
    let code_verifier = random_urlsafe()?;
    let code_challenge = challenge_for(&code_verifier);
    let authorize_url = format!(
        "{AUTHORIZE_URL}?response_type=code&client_id={CLIENT_ID}&redirect_uri={}&scope={}\
         &code_challenge={code_challenge}&code_challenge_method=S256&state={state}\
         &id_token_add_organizations=true&codex_cli_simplified_flow=true\
         &originator={ORIGINATOR}",
        encode_component(REDIRECT_URI),
        encode_component(SCOPES),
    );
    Ok(LoginSession {
        connection: reference.profile().to_string(),
        authorize_url,
        state,
        code_verifier,
        code_challenge,
        token_endpoint: token_endpoint.to_string(),
    })
}

/// Completes one browser login: verifies the recorded callback origin and
/// the CSRF state, exchanges the code, binds the reported identity and
/// writes the canonical credential. A rejected exchange or an interrupted
/// write leaves the previous material untouched.
///
/// # Errors
/// [`LoginError::NotARedirect`]/[`LoginError::OriginMismatch`]/
/// [`LoginError::StateMismatch`] before any wire leg;
/// [`LoginError::Cancelled`]/[`LoginError::Denied`] for a refused authorize
/// leg; [`LoginError::MissingCode`] for a bare redirect;
/// [`LoginError::TokenRejected`], [`LoginError::MalformedResponse`] and
/// [`LoginError::MissingField`] for a rejecting or incomplete peer;
/// [`LoginError::WorkspaceMismatch`]/[`LoginError::AccountMismatch`] when the
/// reply belongs to another identity; and the store's typed denials —
/// including [`ProviderError::CredentialOccupied`] on an already enrolled
/// canonical scope.
pub fn complete_login(
    config: &Config,
    connection: &str,
    session: &LoginSession,
    redirect: &str,
    store: &dyn CredentialStore,
) -> Result<String, LoginError> {
    let reference = canonical_reference(config, connection)?;
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
        &session.connection,
        &session.token_endpoint,
        &[
            ("grant_type", "authorization_code"),
            ("client_id", CLIENT_ID),
            ("code", &code),
            ("code_verifier", &session.code_verifier),
            ("redirect_uri", REDIRECT_URI),
        ],
    )?;
    enroll(&reference, &reply, store)
}

/// Starts the recorded device-code alias: one usercode request against the
/// peer, then a bounded polling session. The alias resolves and writes the
/// canonical `openai-codex` profile.
///
/// # Errors
/// The config-binding denials [`canonical_reference`] documents;
/// [`LoginError::EndpointNotRecorded`] for a foreign endpoint;
/// [`LoginError::TokenRejected`]/[`LoginError::MalformedResponse`]/
/// [`LoginError::MissingField`] for a rejecting or incomplete peer.
pub fn begin_device_login(
    config: &Config,
    connection: &str,
    endpoints: DeviceEndpoints,
) -> Result<DeviceLoginSession, LoginError> {
    let reference = canonical_reference(config, connection)?;
    for (endpoint, recorded) in [
        (endpoints.usercode.as_str(), DEVICE_USERCODE_ENDPOINT),
        (endpoints.token.as_str(), DEVICE_TOKEN_ENDPOINT),
        (endpoints.exchange.as_str(), TOKEN_ENDPOINT),
    ] {
        if !admitted_endpoint(endpoint, recorded) {
            return Err(LoginError::EndpointNotRecorded {
                origin: endpoint_origin(endpoint),
            });
        }
    }
    let reply = post_json(
        reference.profile(),
        &endpoints.usercode,
        &serde_json::json!({ "client_id": CLIENT_ID }),
    )?;
    let state = token_field(&reply, "device_auth_id")?;
    let user_code = token_field(&reply, "user_code")?;
    let interval = device_interval(&reply)?;
    let expires_in = device_expiry(&reply)?;
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(expires_in))
        .ok_or(LoginError::DeviceExpiryOutOfRange {
            seconds: expires_in,
        })?;
    Ok(DeviceLoginSession {
        connection: reference.profile().to_string(),
        state,
        verification_url: DEVICE_AUTH_URL.to_string(),
        user_code,
        interval,
        expires_in,
        deadline,
        next_poll_at: Instant::now(),
        endpoints,
    })
}

/// Advances one device login by exactly one bounded poll and writes the
/// canonical credential when the peer answers the code. The step never
/// sleeps: a pending answer schedules the next poll at the peer's interval,
/// `slow_down` widens that interval, a denial stops immediately and the
/// peer's expiry ends the leg. The one HTTP request is the whole blocking
/// work, so a TUI command can poll once without parking its event loop.
///
/// # Errors
/// [`LoginError::DeviceDenied`] for an operator denial,
/// [`LoginError::DeviceExpired`] at the expiry — checked before the poll and
/// again after a successful reply, so a slow peer cannot enroll past the
/// deadline — and the exchange and store denials [`complete_login`]
/// documents.
pub fn advance_device_login(
    config: &Config,
    connection: &str,
    device: &mut DeviceLoginSession,
    store: &dyn CredentialStore,
) -> Result<DeviceAdvance, LoginError> {
    let reference = canonical_reference(config, connection)?;
    if Instant::now() >= device.deadline {
        return Err(LoginError::DeviceExpired);
    }
    if Instant::now() < device.next_poll_at {
        return Ok(DeviceAdvance::Pending);
    }
    let (mut response, started) = post_json_response(
        &device.connection,
        &device.endpoints.token,
        &serde_json::json!({
            "device_auth_id": device.state,
            "user_code": device.user_code,
        }),
    )?;
    let status = response.status();
    let body = read_login_body(&device.connection, &mut response, started)?;
    let parsed = serde_json::from_slice::<Value>(&body);
    if let Some(error) = parsed
        .as_ref()
        .ok()
        .and_then(|reply| reply.get("error"))
        .and_then(Value::as_str)
    {
        match error {
            "authorization_pending" => {
                device.next_poll_at = next_poll_at(device)?;
                return Ok(DeviceAdvance::Pending);
            }
            "slow_down" => {
                device.interval = device
                    .interval
                    .saturating_add(Duration::from_secs(DEVICE_SLOW_DOWN_SECONDS))
                    .min(Duration::from_secs(DEVICE_MAX_INTERVAL_SECONDS));
                device.next_poll_at = next_poll_at(device)?;
                return Ok(DeviceAdvance::SlowDown);
            }
            "expired_token" | "authorization_expired" => {
                return Err(LoginError::DeviceExpired);
            }
            "access_denied" => return Err(LoginError::DeviceDenied),
            other => {
                return Err(LoginError::Denied {
                    code: bounded_reason(other),
                });
            }
        }
    }
    if matches!(status.as_u16(), 403 | 404) {
        device.next_poll_at = next_poll_at(device)?;
        return Ok(DeviceAdvance::Pending);
    }
    if !status.is_success() {
        return Err(LoginError::TokenRejected {
            status: status.as_u16(),
        });
    }
    let reply = parsed.map_err(|cause| LoginError::MalformedResponse { cause })?;
    let code = token_field(&reply, "authorization_code")?;
    let verifier = token_field(&reply, "code_verifier")?;
    // A slow peer may deliver the authorization after the expiry: the
    // deadline is re-checked here, before the exchange, so a late code
    // never enrolls a credential the window already closed.
    if Instant::now() >= device.deadline {
        return Err(LoginError::DeviceExpired);
    }
    let reply = exchange(
        &device.connection,
        &device.endpoints.exchange,
        &[
            ("grant_type", "authorization_code"),
            ("client_id", CLIENT_ID),
            ("code", &code),
            ("code_verifier", &verifier),
            ("redirect_uri", DEVICE_REDIRECT_URI),
        ],
    )?;
    enroll(&reference, &reply, store).map(DeviceAdvance::Complete)
}

/// Polls the device leg to its terminal state and writes the canonical
/// credential on success. Polling is bounded by the peer's expiry:
/// authorization-pending answers keep polling, `slow_down` widens the
/// interval by the recorded step, a denial stops immediately and the
/// deadline ends the wait. Each wait is one bounded `park_timeout` slice,
/// never an unbounded sleep; the one step it drives does the wire work.
///
/// # Errors
/// The [`advance_device_login`] denials.
pub fn complete_device_login(
    config: &Config,
    connection: &str,
    device: &mut DeviceLoginSession,
    store: &dyn CredentialStore,
) -> Result<String, LoginError> {
    loop {
        let remaining = device.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(LoginError::DeviceExpired);
        }
        let wait = device
            .next_poll_at
            .saturating_duration_since(Instant::now());
        wait_rung(wait.min(remaining));
        match advance_device_login(config, connection, device, store)? {
            DeviceAdvance::Complete(profile) => return Ok(profile),
            DeviceAdvance::Pending | DeviceAdvance::SlowDown => {}
        }
    }
}

/// The canonical `openai-codex` reference both entrypoints write: the
/// connection must be declared `api_key`, and its resolved scope's profile
/// leg must be the canonical name — so a login can never write a subscription
/// or a differently named profile.
///
/// # Errors
/// [`LoginError::ConnectionMissing`] for an undeclared connection;
/// [`ProviderError::CredentialUnresolved`]/`CredentialProfileMismatch` from
/// the shipped resolution; [`LoginError::NotApiKey`] for a non-api-key
/// declaration; [`LoginError::NotCanonicalProfile`] for another profile leg.
pub fn canonical_reference(config: &Config, connection: &str) -> Result<SecretRef, LoginError> {
    let connection = canonical_connection(connection);
    let entry =
        config
            .connections
            .get(connection)
            .ok_or_else(|| LoginError::ConnectionMissing {
                connection: connection.to_string(),
            })?;
    if entry.kind != ConnKind::ApiKey {
        return Err(LoginError::NotApiKey {
            connection: connection.to_string(),
            kind: entry.kind,
        });
    }
    let reference = resolve_credential(config, connection)?;
    if reference.profile() != CANONICAL_PROFILE {
        return Err(LoginError::NotCanonicalProfile {
            connection: connection.to_string(),
            profile: reference.profile().to_string(),
        });
    }
    Ok(reference)
}

/// Reads the canonical credential at a scoped reference — the seam a
/// Responses adapter consumes the OAuth bearer through. Parsing is strict:
/// foreign material is a typed denial, never a guess.
///
/// # Errors
/// The [`LoginError::Provider`] store denial, and
/// [`LoginError::StoredCredentialMalformed`] when the material is not a Codex
/// credential.
pub fn read_credential(
    store: &dyn CredentialStore,
    reference: &SecretRef,
) -> Result<CodexCredential, LoginError> {
    let bytes = store.resolve(reference)?;
    serde_json::from_slice(&bytes).map_err(|cause| LoginError::StoredCredentialMalformed { cause })
}

/// The scoped Codex credential written at login. Tokens never appear in
/// `Debug`; the workspace id and plan are config-class identity, while the
/// email stays redacted as PII.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodexCredential {
    access_token: String,
    refresh_token: String,
    id_token: Option<String>,
    expires_at: u64,
    account_id: Option<String>,
    email: Option<String>,
    plan_type: Option<String>,
}

impl fmt::Debug for CodexCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CodexCredential")
            .field("access_token", &"<redacted>")
            .field("refresh_token", &"<redacted>")
            .field(
                "id_token",
                &self.id_token.as_ref().map(|_token| "<redacted>"),
            )
            .field("expires_at", &self.expires_at)
            .field("account_id", &self.account_id)
            .field("email", &self.email.as_ref().map(|_address| "<redacted>"))
            .field("plan_type", &self.plan_type)
            .finish()
    }
}

impl CodexCredential {
    /// The OAuth bearer a Responses adapter sends.
    #[must_use]
    pub fn access_token(&self) -> &str {
        &self.access_token
    }

    /// The ChatGPT workspace the credential is bound to.
    #[must_use]
    pub fn account_id(&self) -> Option<&str> {
        self.account_id.as_deref()
    }

    /// The account email the token reported.
    #[must_use]
    pub fn email(&self) -> Option<&str> {
        self.email.as_deref()
    }

    /// The recorded plan type, when the claims carried one.
    #[must_use]
    pub fn plan_type(&self) -> Option<&str> {
        self.plan_type.as_deref()
    }

    /// The access token's expiry in seconds since the Unix epoch.
    #[must_use]
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }
}

/// One login lifecycle failure. Display text is English and lowercase, and
/// never carries the code, the verifier, the device handle or a token.
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
    /// The authorize leg or device poll refused the request.
    #[error("authorization was denied: {code}")]
    Denied { code: String },
    /// A successful redirect carried no authorization code.
    #[error("redirect carries no authorization code")]
    MissingCode,
    /// The endpoint is neither its recorded URL nor a loopback peer.
    /// `origin` is the canonical scheme/host class — never the raw URL,
    /// which may carry userinfo.
    #[error("endpoint origin {origin} is outside the recorded contract")]
    EndpointNotRecorded { origin: String },
    /// The endpoint answered a non-success status — an expired or revoked
    /// grant lands here, and the body is never read.
    #[error("the token endpoint answered with http status {status}")]
    TokenRejected { status: u16 },
    /// A 2xx reply omitted a recorded field.
    #[error("the response carries no {field}")]
    MissingField { field: &'static str },
    /// The token claims named neither a workspace nor an account.
    #[error("the token carries no account identity")]
    MissingIdentity,
    /// A 2xx reply exceeded the bounded response size.
    #[error("the response exceeds the byte bound")]
    ResponseTooLarge,
    /// A 2xx reply was not the JSON object the contract records.
    #[error("the endpoint answered malformed json")]
    MalformedResponse {
        #[source]
        cause: serde_json::Error,
    },
    /// The connection is declared with another kind, so login must not write
    /// its scope.
    #[error("connection {connection} is {kind}, not an api key")]
    NotApiKey { connection: String, kind: ConnKind },
    /// The resolved scope is not the canonical `openai-codex` profile.
    #[error(
        "connection {connection} resolves profile {profile}, not the canonical openai-codex profile"
    )]
    NotCanonicalProfile { connection: String, profile: String },
    /// The exchange answered another workspace than the active profile.
    #[error("the token belongs to a different workspace than the active profile")]
    WorkspaceMismatch,
    /// The exchange answered another account than the active profile.
    #[error("the token belongs to a different account than the active profile")]
    AccountMismatch,
    /// The material at the scope is not a Codex credential.
    #[error("the stored credential is not a codex credential")]
    StoredCredentialMalformed {
        #[source]
        cause: serde_json::Error,
    },
    /// The in-memory credential could not be encoded for the store.
    #[error("the codex credential could not be serialized")]
    Serialization {
        #[source]
        cause: serde_json::Error,
    },
    /// The system clock is before the Unix epoch, so no expiry applies.
    #[error("system clock is before the unix epoch: {cause}")]
    Clock { cause: std::time::SystemTimeError },
    /// The device peer reported an operator denial.
    #[error("device authorization was denied")]
    DeviceDenied,
    /// The device code expired before it was redeemed.
    #[error("device authorization expired")]
    DeviceExpired,
    /// The peer-issued device lifetime exceeds the recorded ceiling.
    #[error("device expiry {seconds} seconds is outside the recorded ceiling")]
    DeviceExpiryOutOfRange { seconds: u64 },
    /// The exchanged access-token lifetime exceeds the recorded ceiling.
    #[error("token expiry {seconds} seconds is outside the recorded ceiling")]
    TokenExpiryOutOfRange { seconds: u64 },
    /// The peer-issued poll interval exceeds the recorded ceiling.
    #[error("device poll interval {seconds} seconds is outside the recorded ceiling")]
    DeviceIntervalOutOfRange { seconds: u64 },
    /// A present device member is not the recorded type or numeric shape.
    #[error("the response carries a malformed {field}")]
    MalformedField { field: &'static str },
    /// The canonical connection the operator must declare is absent.
    #[error(
        "connection {connection} is not declared; add the [connections.{connection}] and [profiles.{connection}] rows"
    )]
    ConnectionMissing { connection: String },
    /// The credential seam's typed denial — unavailable/ambiguous store, an
    /// occupied scope, or a scope outside the backend's namespace.
    #[error(transparent)]
    Provider(#[from] ProviderError),
}

/// The redirect's recorded members; unknown query keys are ignored, a
/// duplicated recorded key is a malformed redirect.
struct Callback {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

/// Parses the recorded callback URL. Origin and route are compared as exact
/// strings, so a look-alike host never matches.
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

/// A recorded query key may appear once; a duplicate is a malformed redirect
/// rather than a last-one-wins guess.
fn unique(slot: Option<String>, value: String) -> Result<String, LoginError> {
    if slot.is_some() {
        return Err(LoginError::NotARedirect);
    }
    Ok(value)
}

/// One token request that returns its parsed JSON object. The code, the
/// verifier and the refresh ride the recorded form body, never the URL.
fn exchange(
    connection: &str,
    token_endpoint: &str,
    fields: &[(&str, &str)],
) -> Result<Value, LoginError> {
    if !admitted_endpoint(token_endpoint, TOKEN_ENDPOINT) {
        return Err(LoginError::EndpointNotRecorded {
            origin: endpoint_origin(token_endpoint),
        });
    }
    let body = fields
        .iter()
        .map(|(name, value)| format!("{}={}", encode_component(name), encode_component(value)))
        .collect::<Vec<String>>()
        .join("&");
    let started = Instant::now();
    let client = reqwest::blocking::Client::builder()
        .timeout(client_timeout())
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|err| transport(connection, err))?;
    let mut response = client
        .post(token_endpoint)
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .body(body)
        .send()
        .map_err(|err| transport(connection, err))?;
    if !response.status().is_success() {
        return Err(LoginError::TokenRejected {
            status: response.status().as_u16(),
        });
    }
    let reply = read_login_body(connection, &mut response, started)?;
    serde_json::from_slice(&reply).map_err(|cause| LoginError::MalformedResponse { cause })
}

/// One JSON request that returns its parsed object — the device usercode leg.
fn post_json(connection: &str, endpoint: &str, body: &Value) -> Result<Value, LoginError> {
    let (mut response, started) = post_json_response(connection, endpoint, body)?;
    if !response.status().is_success() {
        return Err(LoginError::TokenRejected {
            status: response.status().as_u16(),
        });
    }
    let reply = read_login_body(connection, &mut response, started)?;
    serde_json::from_slice(&reply).map_err(|cause| LoginError::MalformedResponse { cause })
}

/// The unread response of one JSON request and the instant its budget
/// started; the caller classifies the status and reads a bounded body under
/// the same whole-leg deadline.
fn post_json_response(
    connection: &str,
    endpoint: &str,
    body: &Value,
) -> Result<(reqwest::blocking::Response, Instant), LoginError> {
    let started = Instant::now();
    let client = reqwest::blocking::Client::builder()
        .timeout(client_timeout())
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|err| transport(connection, err))?;
    let response = client
        .post(endpoint)
        .json(body)
        .send()
        .map_err(|err| LoginError::Provider(transport(connection, err)))?;
    Ok((response, started))
}

/// The transport's own backstop: in production the recorded 15-second leg
/// bound; under a test, twice the injected whole-leg budget so the shared
/// read deadline is the authoritative denial and a client timeout can never
/// mask it.
fn client_timeout() -> Duration {
    #[cfg(test)]
    {
        leg_timeout().saturating_mul(2)
    }
    #[cfg(not(test))]
    {
        LOGIN_TIMEOUT
    }
}

/// The recorded endpoint or a loopback contract peer; anything else would
/// carry the code, the verifier or the device handle to a foreign host. The
/// URL is parsed, so userinfo never impersonates the host it precedes.
fn admitted_endpoint(endpoint: &str, recorded: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(endpoint) else {
        return false;
    };
    if !url.username().is_empty() || url.password().is_some() {
        return false;
    }
    if endpoint == recorded {
        return true;
    }
    url.scheme() == "http" && is_loopback_host(url.host_str())
}

/// The canonical scheme/host class a rejected endpoint names — never the raw
/// URL, which may carry the code or userinfo.
fn endpoint_origin(endpoint: &str) -> String {
    match reqwest::Url::parse(endpoint) {
        Ok(url) => match url.host_str() {
            Some(host) => format!("{}://{host}", url.scheme()),
            None => format!("{} url", url.scheme()),
        },
        Err(_parse) => "an unparseable url".to_string(),
    }
}

/// The reply under the login leg's budget and byte bound — a dribbling or
/// oversized body is denied, never buffered unbounded.
fn read_login_body(
    connection: &str,
    response: &mut reqwest::blocking::Response,
    started: Instant,
) -> Result<Vec<u8>, LoginError> {
    let mut body = Vec::new();
    let mut chunk = vec![0u8; STREAM_CHUNK_BYTES];
    loop {
        let read = read_chunk(connection, leg_timeout(), response, &mut chunk, started)?;
        if read == 0 {
            break;
        }
        if body.len() + read > CATALOG_MAX_BYTES {
            return Err(LoginError::ResponseTooLarge);
        }
        body.extend_from_slice(&chunk[..read]);
    }
    Ok(body)
}

/// A non-empty string member of the reply's top level.
fn token_field(reply: &Value, field: &'static str) -> Result<String, LoginError> {
    reply
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or(LoginError::MissingField { field })
}

/// The peer-issued poll interval, in seconds; a missing value keeps the
/// recorded fallback, a zero interval is raised to one second so the loop
/// never busy-polls, and an unparseable or above-ceiling value is a typed
/// denial — the schedule is never built from an unbounded peer figure.
fn device_interval(reply: &Value) -> Result<Duration, LoginError> {
    let seconds = match reply.get("interval") {
        None => DEVICE_INTERVAL_SECONDS,
        Some(Value::Number(number)) => number
            .as_u64()
            .ok_or(LoginError::MalformedField { field: "interval" })?,
        Some(Value::String(text)) => text
            .trim()
            .parse::<u64>()
            .map_err(|_parse| LoginError::MalformedField { field: "interval" })?,
        Some(_) => return Err(LoginError::MalformedField { field: "interval" }),
    };
    if seconds > DEVICE_MAX_INTERVAL_SECONDS {
        return Err(LoginError::DeviceIntervalOutOfRange { seconds });
    }
    Ok(Duration::from_secs(seconds.max(1)))
}

/// The next poll instant under the recorded interval ceiling; an
/// unrepresentable instant is a typed denial rather than a panicking
/// `Instant + Duration`.
fn next_poll_at(device: &DeviceLoginSession) -> Result<Instant, LoginError> {
    Instant::now()
        .checked_add(device.interval)
        .ok_or(LoginError::DeviceIntervalOutOfRange {
            seconds: device.interval.as_secs(),
        })
}

/// The peer-issued device-code lifetime; a reply without one keeps the
/// recorded poll ceiling, a numeric string is parsed, and an unparseable or
/// above-ceiling value is a typed denial — the deadline is never built from
/// an unbounded or silently defaulted peer figure.
fn device_expiry(reply: &Value) -> Result<u64, LoginError> {
    let seconds = match reply.get("expires_in") {
        None => DEVICE_DEFAULT_EXPIRY_SECONDS,
        Some(Value::Number(number)) => number.as_u64().ok_or(LoginError::MalformedField {
            field: "expires_in",
        })?,
        Some(Value::String(text)) => {
            text.trim()
                .parse::<u64>()
                .map_err(|_parse| LoginError::MalformedField {
                    field: "expires_in",
                })?
        }
        Some(_) => {
            return Err(LoginError::MalformedField {
                field: "expires_in",
            });
        }
    };
    if seconds > DEVICE_MAX_EXPIRY_SECONDS {
        return Err(LoginError::DeviceExpiryOutOfRange { seconds });
    }
    Ok(seconds)
}

/// The recorded `expires_in` is an integer seconds count; a string or a float
/// is a peer contract violation, never coerced.
fn expires_in(reply: &Value) -> Result<u64, LoginError> {
    reply
        .get("expires_in")
        .and_then(Value::as_u64)
        .ok_or(LoginError::MissingField {
            field: "expires_in",
        })
}

/// The stored expiry with the recorded skew (zero) applied.
fn expires_at(expires_in: u64) -> Result<u64, LoginError> {
    if expires_in > TOKEN_MAX_EXPIRY_SECONDS {
        return Err(LoginError::TokenExpiryOutOfRange {
            seconds: expires_in,
        });
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|cause| LoginError::Clock { cause })?
        .as_secs();
    Ok(now
        .saturating_add(expires_in)
        .saturating_sub(EXPIRY_SKEW.as_secs()))
}

/// The identity slice the Codex claims carry: the ChatGPT workspace, the
/// account email and the plan type.
struct Identity {
    workspace: Option<String>,
    email: Option<String>,
    plan_type: Option<String>,
}

/// Reads the identity from the access token, falling back to the id token.
/// A token that carries neither a workspace nor an email is a login denial,
/// never an anonymous credential.
fn identity(reply: &Value) -> Result<Identity, LoginError> {
    let access = token_field(reply, "access_token")?;
    let id_token = reply
        .get("id_token")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty());
    let access_claims = jwt_claims(&access);
    let id_claims = id_token.and_then(jwt_claims);
    let workspace = claim(access_claims.as_ref(), AUTH_CLAIM, "chatgpt_account_id")
        .or_else(|| claim(id_claims.as_ref(), AUTH_CLAIM, "chatgpt_account_id"));
    let email = claim(access_claims.as_ref(), PROFILE_CLAIM, "email")
        .or_else(|| claim(id_claims.as_ref(), PROFILE_CLAIM, "email"))
        .map(|address| address.trim().to_lowercase())
        .filter(|address| !address.is_empty());
    let plan_type = claim(access_claims.as_ref(), AUTH_CLAIM, "chatgpt_plan_type")
        .or_else(|| claim(id_claims.as_ref(), AUTH_CLAIM, "chatgpt_plan_type"))
        .map(|plan| plan.trim().to_lowercase())
        .filter(|plan| !plan.is_empty());
    if workspace.is_none() && email.is_none() {
        return Err(LoginError::MissingIdentity);
    }
    Ok(Identity {
        workspace,
        email,
        plan_type,
    })
}

/// One non-empty string claim inside a namespaced section.
fn claim(claims: Option<&Value>, section: &str, name: &str) -> Option<String> {
    claims?
        .get(section)?
        .get(name)?
        .as_str()
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

/// The JSON payload of a JWT; a malformed token answers `None` rather than a
/// parse diagnostic that could quote token bytes.
fn jwt_claims(token: &str) -> Option<Value> {
    let payload = token.split('.').nth(1)?;
    let bytes = base64url_decode(payload)?;
    serde_json::from_slice(&bytes).ok()
}

/// Enrolls the exchanged tokens at the canonical scope. An active profile at
/// the scope is compared first: another workspace or account denies before
/// any write and never borrows the stored token. Enrollment itself is
/// create-only, so an occupied scope stays the store's typed denial.
fn enroll(
    reference: &SecretRef,
    reply: &Value,
    store: &dyn CredentialStore,
) -> Result<String, LoginError> {
    let identity = identity(reply)?;
    let access_token = token_field(reply, "access_token")?;
    let refresh_token = token_field(reply, "refresh_token")?;
    let id_token = reply
        .get("id_token")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let expires_at = expires_at(expires_in(reply)?)?;
    match store.resolve(reference) {
        Ok(bytes) => {
            let active: CodexCredential = serde_json::from_slice(&bytes)
                .map_err(|cause| LoginError::StoredCredentialMalformed { cause })?;
            if active.account_id.is_some()
                && identity.workspace.is_some()
                && active.account_id != identity.workspace
            {
                return Err(LoginError::WorkspaceMismatch);
            }
            if active.email.is_some() && identity.email.is_some() && active.email != identity.email
            {
                return Err(LoginError::AccountMismatch);
            }
        }
        Err(ProviderError::CredentialAbsent { .. }) => {}
        Err(error) => return Err(LoginError::Provider(error)),
    }
    let credential = CodexCredential {
        access_token,
        refresh_token,
        id_token,
        expires_at,
        account_id: identity.workspace,
        email: identity.email,
        plan_type: identity.plan_type,
    };
    let material =
        serde_json::to_vec(&credential).map_err(|cause| LoginError::Serialization { cause })?;
    store.login(reference, &material)?;
    Ok(reference.profile().to_string())
}

/// 32 bytes of OS entropy rendered base64url — the verifier and state share
/// this one draw helper.
fn random_urlsafe() -> Result<String, LoginError> {
    let mut bytes = [0u8; VERIFIER_BYTES];
    getrandom::fill(&mut bytes).map_err(|cause| LoginError::Entropy { cause })?;
    Ok(base64url(&bytes))
}

/// One bounded wait that survives a spurious wake without shortening the
/// interval: no poll loop and no spawned timer runs beside it.
fn wait_rung(rung: Duration) {
    let started = Instant::now();
    while let Some(left) = rung
        .checked_sub(started.elapsed())
        .filter(|left| !left.is_zero())
    {
        std::thread::park_timeout(left);
    }
}

/// base64url without padding, hand-rolled so no new codec dependency is
/// admitted for two call sites.
fn base64url(bytes: &[u8]) -> String {
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

/// Base64url decoding for the token payload; both the URL alphabet and the
/// standard alphabet a peer may emit are accepted, padding optional.
fn base64url_decode(raw: &str) -> Option<Vec<u8>> {
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

/// Percent-encodes everything outside the RFC 3986 unreserved set — the
/// authorize URL carries the redirect URI and the scope list.
fn encode_component(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for byte in raw.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push(char::from(HEX[(byte >> 4) as usize]));
            out.push(char::from(HEX[(byte & 0xf) as usize]));
        }
    }
    out
}

fn percent_decode(raw: &str) -> Result<String, LoginError> {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let high = bytes.get(index + 1).and_then(|b| hex_value(*b));
            let low = bytes.get(index + 2).and_then(|b| hex_value(*b));
            let (Some(high), Some(low)) = (high, low) else {
                return Err(LoginError::NotARedirect);
            };
            out.push(high << 4 | low);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(out).map_err(|_cause| LoginError::NotARedirect)
}

const HEX: &[u8; 16] = b"0123456789ABCDEF";

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

    #[test]
    fn base64url_roundtrips_the_payload_bytes() {
        let payload = br#"{"https://api.openai.com/auth":{"chatgpt_account_id":"ws"}}"#;
        let encoded = base64url(payload);
        assert_eq!(
            base64url_decode(&encoded).expect("the recorded alphabet decodes"),
            payload
        );
        assert!(base64url_decode("a%b").is_none());
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
    fn a_peer_expiry_above_the_recorded_ceiling_denies_typed() {
        let error = device_expiry(&serde_json::json!({ "expires_in": u64::MAX }))
            .expect_err("the unbounded peer lifetime denies");
        assert!(matches!(
            error,
            LoginError::DeviceExpiryOutOfRange { seconds } if seconds == u64::MAX
        ));
        assert_eq!(
            device_expiry(&serde_json::json!({ "expires_in": 960u64 }))
                .expect("the recorded ceiling is admitted"),
            960
        );
    }

    #[test]
    fn a_peer_interval_above_the_recorded_ceiling_denies_typed() {
        let error = device_interval(&serde_json::json!({ "interval": u64::MAX }))
            .expect_err("the unbounded poll interval denies");
        assert!(matches!(
            error,
            LoginError::DeviceIntervalOutOfRange { seconds } if seconds == u64::MAX
        ));
        assert_eq!(
            device_interval(&serde_json::json!({})).expect("the recorded fallback"),
            Duration::from_secs(DEVICE_INTERVAL_SECONDS)
        );
        assert_eq!(
            device_interval(&serde_json::json!({ "interval": "3" })).expect("a numeric string"),
            Duration::from_secs(3)
        );
        for malformed in [
            serde_json::json!({ "interval": "not-a-number" }),
            serde_json::json!({ "interval": 1.5 }),
            serde_json::json!({ "interval": true }),
        ] {
            assert!(matches!(
                device_interval(&malformed),
                Err(LoginError::MalformedField { field: "interval" })
            ));
        }
    }

    #[test]
    fn a_present_malformed_expires_in_denies_while_a_missing_one_keeps_the_fallback() {
        for malformed in [
            serde_json::json!({ "expires_in": "soon" }),
            serde_json::json!({ "expires_in": 1.5 }),
            serde_json::json!({ "expires_in": true }),
        ] {
            assert!(matches!(
                device_expiry(&malformed),
                Err(LoginError::MalformedField {
                    field: "expires_in"
                })
            ));
        }
        assert_eq!(
            device_expiry(&serde_json::json!({ "expires_in": "60" }))
                .expect("a numeric string parses"),
            60
        );
        assert_eq!(
            device_expiry(&serde_json::json!({})).expect("the recorded fallback"),
            DEVICE_DEFAULT_EXPIRY_SECONDS
        );
    }

    #[test]
    fn an_exchange_expiry_above_the_recorded_ceiling_denies_typed() {
        let error = expires_at(u64::MAX).expect_err("the unbounded token lifetime denies");
        assert!(matches!(
            error,
            LoginError::TokenExpiryOutOfRange { seconds } if seconds == u64::MAX
        ));
        assert!(
            expires_at(TOKEN_MAX_EXPIRY_SECONDS).is_ok(),
            "the recorded ceiling is admitted"
        );
    }

    #[test]
    fn a_dribbling_peer_is_denied_by_the_shared_leg_deadline() {
        use std::io::{Read as _, Write as _};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let base = format!("http://{}", listener.local_addr().expect("peer address"));
        let config = Config::parse_validated(
            "config_version = 1\n\
             [connections.openai-codex]\n\
             kind = \"api_key\"\n\
             endpoint = \"https://chatgpt.com/backend-api/codex\"\n\
             credential_ref = \"keychain:rivect-test/openai-codex\"\n\
             profile = \"openai-codex\"\n\
             [profiles.openai-codex]\n\
             credential_ref = \"keychain:rivect-test/openai-codex\"\n\
             [models.defaults]\n\
             model = { mode = \"auto\" }\n\
             effort = { mode = \"auto\" }\n\
             fallback = { mode = \"auto\" }\n",
        )
        .expect("the canonical config parses");
        let endpoints = DeviceEndpoints {
            usercode: format!("{base}/usercode"),
            token: format!("{base}/token"),
            exchange: format!("{base}/exchange"),
        };
        // The peer answers headers only after 250 ms and dribbles the body at
        // 1 ms per byte; a fresh body-read budget would finish, the shared
        // send-to-read budget expires first.
        set_test_leg_timeout(Some(Duration::from_millis(300)));
        let outcome = std::thread::scope(|scope| {
            let _server = scope.spawn(move || {
                let (mut stream, _address) = listener.accept().expect("one connection");
                let mut request = [0u8; 4096];
                let _read = stream.read(&mut request);
                std::thread::park_timeout(Duration::from_millis(250));
                let body = serde_json::json!({
                    "device_auth_id": "handle",
                    "user_code": "CODE",
                    "interval": "1",
                    "expires_in": 60,
                })
                .to_string();
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _written = stream.write_all(head.as_bytes());
                for byte in body.as_bytes() {
                    std::thread::park_timeout(Duration::from_millis(1));
                    if stream.write_all(&[*byte]).is_err() {
                        break;
                    }
                }
            });
            begin_device_login(&config, "openai-codex-device", endpoints)
        });
        set_test_leg_timeout(None);
        let error = outcome.expect_err("the whole-leg deadline denies a dribbling peer");
        let transport = match &error {
            LoginError::Provider(ProviderError::Transport { cause, .. }) => Some(cause),
            _ => None,
        };
        assert!(
            transport.is_some(),
            "expected a transport denial, got {error}"
        );
        if let Some(cause) = transport {
            assert_eq!(
                cause.class(),
                crate::providers::TransportClass::DeadlineExpired,
                "{error}"
            );
        }
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
