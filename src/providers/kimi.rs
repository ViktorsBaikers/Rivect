//! Kimi Code lifecycle and inference (AC-040/AC-046): the recorded
//! device-code login at `auth.kimi.com`, the create-only scoped profile it
//! writes, the explicit refresh and local logout, and the one adapter that
//! sends the resolved model on the protocol its catalogue listing declares.
//! The Messages leg is the shared `super::anthropic::MessagesCodec`: its
//! thinking lineage, drop policy and stream reduction are reused, never
//! copied, so the two adapters cannot drift.
//!
//! The recorded contract is OMP's `rules/auth/kimi-code.kdl` and
//! `providers/kimi.ts` (`0133f7ff`): the device grant posts `client_id` to
//! `/api/oauth/device_authorization` and redeems its `device_code` at
//! `/api/oauth/token`; the coding base is `https://api.kimi.com/coding/v1`,
//! whose `/models` rows may name a `protocol` — `messages` (the recorded
//! default for rows without one) or `chat` — and the send therefore appends
//! `/messages` or `/chat/completions` to the same base. The identity the
//! request carries is Rivect's own: the crate version and the recorded
//! `X-Msh-*` platform/version/device-model header class, never another
//! client's name, version or install id.
//!
//! An undeclared, region-mismatched or unresolved binding denies typed
//! before any wire leg; a profile or origin outside the recorded contract
//! never reaches the peer. Token material — the device code, the access and
//! refresh tokens — never enters `Debug`, `Display` or a diagnostic.

use super::anthropic::{ANTHROPIC_VERSION, MessagesCodec, RefusedMessages, THINKING_BINDING_BETA};
use super::login_common::{self, BindingError, CommonError};
use super::sse::{MAX_STREAM_BYTES, SseEvent, SseParser};
use super::{
    CredentialStore, Dialect, Provider, ProviderError, ProviderReply, STREAM_CHUNK_BYTES,
    SecretRef, ToolCall, WireAuth, bounded_reason, check_deadline, read_chunk,
    resolve_admitted_credential_in, retain_lineage_epoch, retire_displaced_epochs, sse, transport,
    transport_status, violation, wire_body,
};
use crate::config::{Config, ConnKind, Connection, FixedModel, ModelAssign};
use crate::model::RequestManifest;
use crate::resources::UsageDelta;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The literal connection id this module owns.
pub const CONNECTION: &str = "kimi-code";

/// The recorded coding base: both protocols append their path to it.
pub const DEFAULT_BASE: &str = "https://api.kimi.com/coding/v1";
/// The recorded device-authorization base.
pub const AUTH_BASE: &str = "https://auth.kimi.com";
/// The recorded public device client id.
pub const CLIENT_ID: &str = "17e5f671-d194-4dfb-9706-5516cb48c098";
pub const DEVICE_AUTHORIZATION_PATH: &str = "/api/oauth/device_authorization";
pub const TOKEN_PATH: &str = "/api/oauth/token";
const DEVICE_CODE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// One login leg's whole budget, shared by connect, request and read.
const LOGIN_TIMEOUT: Duration = Duration::from_secs(15);
/// The whole-send budget: catalogue resolution, credential resolution,
/// connect, request and every stream read count against it.
const REQUEST_DEADLINE: Duration = Duration::from_secs(120);

/// The recorded polling fallback and the RFC 8628 `slow_down` increment.
const DEFAULT_INTERVAL_SECONDS: u64 = 5;
const SLOW_DOWN_SECONDS: u64 = 5;
/// The recorded poll ceiling when a reply carries no lifetime.
const DEFAULT_EXPIRY_SECONDS: u64 = 600;
/// The widest device lifetime and poll interval this build admits.
const MAX_EXPIRY_SECONDS: u64 = 960;
/// The widest access-token lifetime this build admits: 30 days.
const MAX_TOKEN_EXPIRY_SECONDS: u64 = 30 * 24 * 60 * 60;

/// The bound on distinct tool calls one stream may open.
const MAX_TOOL_CALLS: usize = 32;
/// The bound on one tool call's accumulated argument bytes.
const MAX_TOOL_ARGS_BYTES: usize = 1024 * 1024;

/// The protocol one catalogue row resolves. Rows without a recorded
/// `protocol` keep the dialect's recorded Anthropic-compatible default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    ChatCompletions,
    Messages,
}

impl Protocol {
    /// The shared dialect this protocol rides.
    #[must_use]
    pub fn dialect(self) -> Dialect {
        match self {
            Self::ChatCompletions => Dialect::ChatCompletions,
            Self::Messages => Dialect::Messages,
        }
    }
}

/// One catalogue row as the listing declared it: the id and the raw
/// `protocol` member, which only the selected row classifies.
struct ListedRow {
    id: String,
    protocol: Option<Value>,
}

/// The recorded device endpoints; a caller may substitute loopback
/// contract peers, but every URL is admitted against its recorded host.
#[derive(Debug, Clone)]
pub struct Endpoints {
    pub device_authorization: String,
    pub token: String,
}

impl Endpoints {
    #[must_use]
    pub fn recorded() -> Self {
        Self {
            device_authorization: format!("{AUTH_BASE}{DEVICE_AUTHORIZATION_PATH}"),
            token: format!("{AUTH_BASE}{TOKEN_PATH}"),
        }
    }
}

/// One in-flight device leg. The device code is the login state the caller
/// verifies and the poll presents; `Debug` redacts it.
pub struct DeviceLoginSession {
    connection: String,
    profile: String,
    device_code: String,
    user_code: String,
    verification_url: String,
    verification_uri_complete: Option<String>,
    interval: Duration,
    expires_in: u64,
    deadline: Instant,
    next_poll_at: Instant,
    endpoints: Endpoints,
}

impl fmt::Debug for DeviceLoginSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceLoginSession")
            .field("connection", &self.connection)
            .field("profile", &self.profile)
            .field("device_code", &"<redacted>")
            .field("user_code", &self.user_code)
            .field("verification_url", &self.verification_url)
            .field("interval", &self.interval)
            .field("expires_in", &self.expires_in)
            .finish_non_exhaustive()
    }
}

impl DeviceLoginSession {
    /// The literal connection whose scoped profile the leg writes.
    #[must_use]
    pub fn connection(&self) -> &str {
        &self.connection
    }

    /// The profile leg the credential scope carries.
    #[must_use]
    pub fn profile(&self) -> &str {
        &self.profile
    }

    /// The opaque device code, the handle the caller verifies.
    #[must_use]
    pub fn state(&self) -> &str {
        &self.device_code
    }

    #[must_use]
    pub fn user_code(&self) -> &str {
        &self.user_code
    }

    #[must_use]
    pub fn verification_url(&self) -> &str {
        &self.verification_url
    }

    /// The complete verification URL, when the peer issued one.
    #[must_use]
    pub fn verification_uri_complete(&self) -> Option<&str> {
        self.verification_uri_complete.as_deref()
    }

    #[must_use]
    pub fn expires_in(&self) -> u64 {
        self.expires_in
    }
}

/// One bounded device poll's classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceAdvance {
    Pending,
    SlowDown,
    Complete(String),
}

/// The scoped credential a completed device login writes. Tokens never
/// appear in `Debug`; the account id is config-class identity.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KimiCredential {
    access_token: String,
    refresh_token: Option<String>,
    expires_at: u64,
    account_id: String,
}

impl fmt::Debug for KimiCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KimiCredential")
            .field("access_token", &login_common::redacted(&self.access_token))
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_token| "<redacted>"),
            )
            .field("expires_at", &self.expires_at)
            .field("account_id", &self.account_id)
            .finish()
    }
}

impl KimiCredential {
    /// The bearer the wire leg presents.
    #[must_use]
    pub fn access_token(&self) -> &str {
        &self.access_token
    }

    /// The account the device binding enrolled.
    #[must_use]
    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    #[must_use]
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }
}

/// One login failure. Display text is English, lowercase and never carries
/// a device code, a verifier or a token.
#[derive(Debug, thiserror::Error)]
pub enum KimiLoginError {
    #[error("entropy source is unavailable: {cause}")]
    Entropy { cause: getrandom::Error },
    #[error(
        "connection {connection} is not declared; add the [connections.{connection}] row with its credential_ref"
    )]
    ConnectionMissing { connection: String },
    #[error("connection {connection} is {kind}, not an api key")]
    NotApiKey { connection: String, kind: ConnKind },
    #[error(transparent)]
    Provider(#[from] ProviderError),
    #[error("endpoint origin {origin} is outside the recorded contract")]
    EndpointNotRecorded { origin: String },
    #[error("the token endpoint answered with http status {status}")]
    TokenRejected { status: u16 },
    #[error("the response carries no {field}")]
    MissingField { field: &'static str },
    #[error("the response carries a malformed {field}")]
    MalformedField { field: &'static str },
    #[error("the endpoint answered malformed json")]
    MalformedResponse {
        #[source]
        cause: serde_json::Error,
    },
    #[error("the response exceeds the byte bound")]
    ResponseTooLarge,
    #[error("the system clock is before the unix epoch: {cause}")]
    Clock { cause: std::time::SystemTimeError },
    #[error("the kimi credential could not be serialized")]
    Serialization {
        #[source]
        cause: serde_json::Error,
    },
    #[error("device authorization was denied")]
    DeviceDenied,
    #[error("device authorization expired")]
    DeviceExpired,
    #[error("device authorization was refused: {code}")]
    Denied { code: String },
    #[error("device expiry {seconds} seconds is outside the recorded ceiling")]
    DeviceExpiryOutOfRange { seconds: u64 },
    #[error("device poll interval {seconds} seconds is outside the recorded ceiling")]
    DeviceIntervalOutOfRange { seconds: u64 },
    #[error("token expiry {seconds} seconds is outside the recorded ceiling")]
    TokenExpiryOutOfRange { seconds: u64 },
    #[error("the token carries no account identity")]
    MissingIdentity,
    #[error("the token belongs to a different account than the active profile")]
    AccountMismatch,
    #[error("the stored credential is not a kimi profile: {reason}")]
    StoredCredentialMalformed { reason: &'static str },
    #[error("the credential at scope {scope} is not a refreshable kimi profile")]
    NotRefreshable { scope: String },
}

impl From<CommonError> for KimiLoginError {
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

impl From<BindingError> for KimiLoginError {
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

/// The recorded header identity: Rivect's own crate and platform facts.
/// The recorded client's name, version and persisted device id are never
/// copied, and no hostname or user value leaves the client.
fn identity_headers() -> [(&'static str, String); 4] {
    let version = env!("CARGO_PKG_VERSION");
    [
        ("user-agent", format!("rivect/{version}")),
        ("x-msh-platform", "rivect".to_string()),
        ("x-msh-version", version.to_string()),
        (
            "x-msh-device-model",
            format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
        ),
    ]
}

fn identity_request(
    request: reqwest::blocking::RequestBuilder,
) -> reqwest::blocking::RequestBuilder {
    identity_headers()
        .into_iter()
        .fold(request, |request, (name, value)| {
            request.header(name, value)
        })
}

/// The canonical scheme/host class a rejected endpoint names.
fn endpoint_origin(endpoint: &str) -> String {
    match reqwest::Url::parse(endpoint) {
        Ok(url) => match url.host_str() {
            Some(host) => format!("{}://{host}", url.scheme()),
            None => format!("{} url", url.scheme()),
        },
        Err(_parse) => "an unparseable url".to_string(),
    }
}

/// The scoped reference a login writes: the declared `api_key` row's own
/// binding. A `kimi-code` declaration may bind any profile name; the two
/// enrolled profiles stay separate scopes, so neither ever overwrites the
/// other.
///
/// # Errors
/// The typed config-binding denials.
pub fn credential_reference(
    config: &Config,
    connection: &str,
) -> Result<SecretRef, KimiLoginError> {
    Ok(login_common::api_key_reference(config, connection)?)
}

/// The credential seam a login writes through: the injected store, or the
/// platform backend the bound scope's class and namespace name.
///
/// # Errors
/// The config-binding denials and the store's own typed refusal.
pub fn login_store(
    config: &Config,
    connection: &str,
    injected: Option<&Arc<dyn CredentialStore>>,
) -> Result<Arc<dyn CredentialStore>, KimiLoginError> {
    let reference = credential_reference(config, connection)?;
    if let Some(store) = injected {
        return Ok(Arc::clone(store));
    }
    Ok(Arc::new(super::native_store(
        reference.store(),
        reference.service(),
    )?))
}

/// Starts one recorded device leg: the usercode request mints the device
/// code, the user code and the verification URL the operator opens.
///
/// # Errors
/// The config-binding denials; [`KimiLoginError::EndpointNotRecorded`] for
/// a foreign endpoint; [`KimiLoginError::TokenRejected`],
/// [`KimiLoginError::MalformedResponse`], [`KimiLoginError::MissingField`]
/// and the lifetime/interval ceilings for a rejecting or out-of-contract
/// peer.
pub fn begin_device_login(
    config: &Config,
    connection: &str,
    endpoints: Endpoints,
) -> Result<DeviceLoginSession, KimiLoginError> {
    let reference = credential_reference(config, connection)?;
    let recorded = Endpoints::recorded();
    for (endpoint, expected) in [
        (
            endpoints.device_authorization.as_str(),
            recorded.device_authorization.as_str(),
        ),
        (endpoints.token.as_str(), recorded.token.as_str()),
    ] {
        if !login_common::admitted_endpoint(endpoint, expected) {
            return Err(KimiLoginError::EndpointNotRecorded {
                origin: endpoint_origin(endpoint),
            });
        }
    }
    let client = login_common::client(reference.profile(), LOGIN_TIMEOUT)?;
    let request = identity_request(client.post(&endpoints.device_authorization))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header(reqwest::header::ACCEPT, "application/json")
        .body(wire_body(
            &reference.to_string(),
            &json!({ "client_id": CLIENT_ID }),
        )?);
    let started = Instant::now();
    let mut response = request
        .send()
        .map_err(|err| transport(reference.profile(), err))?;
    let reply = reply_object(&mut response, started)?;
    let device_code = text_field(&reply, "device_code")?;
    let user_code = text_field(&reply, "user_code")?;
    let verification_url = text_field(&reply, "verification_uri")?;
    let verification_uri_complete = optional_text(&reply, "verification_uri_complete")?;
    let interval = interval_of(&reply)?;
    let expires_in = lifetime_of(&reply, "expires_in", DEFAULT_EXPIRY_SECONDS)?;
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(expires_in))
        .ok_or(KimiLoginError::DeviceExpiryOutOfRange {
            seconds: expires_in,
        })?;
    Ok(DeviceLoginSession {
        connection: connection.to_string(),
        profile: reference.profile().to_string(),
        device_code,
        user_code,
        verification_url,
        verification_uri_complete,
        interval,
        expires_in,
        deadline,
        next_poll_at: Instant::now(),
        endpoints,
    })
}

/// Advances one device leg by exactly one bounded poll. The step never
/// sleeps: a pending answer schedules the next poll at the peer's interval,
/// `slow_down` widens it, a denial stops at once and the lifetime ends the
/// leg.
///
/// # Errors
/// [`KimiLoginError::DeviceDenied`] for an operator denial,
/// [`KimiLoginError::DeviceExpired`] at the lifetime — checked before the
/// poll and again after a success, so a slow peer cannot enroll past the
/// window — and the store and reply denials.
pub fn advance_device_login(
    config: &Config,
    connection: &str,
    device: &mut DeviceLoginSession,
    store: &dyn CredentialStore,
) -> Result<DeviceAdvance, KimiLoginError> {
    let reference = credential_reference(config, connection)?;
    if Instant::now() >= device.deadline {
        return Err(KimiLoginError::DeviceExpired);
    }
    if Instant::now() < device.next_poll_at {
        return Ok(DeviceAdvance::Pending);
    }
    let client = login_common::client(reference.profile(), LOGIN_TIMEOUT)?;
    let request = identity_request(client.post(&device.endpoints.token))
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .header(reqwest::header::ACCEPT, "application/json")
        .body(form_body(&[
            ("grant_type", DEVICE_CODE_GRANT),
            ("device_code", &device.device_code),
            ("client_id", CLIENT_ID),
        ]));
    let started = Instant::now();
    let mut response = request
        .send()
        .map_err(|err| transport(reference.profile(), err))?;
    let status = response.status();
    let body = login_common::read_body(reference.profile(), &mut response, LOGIN_TIMEOUT, started)?;
    let parsed = serde_json::from_slice::<Value>(&body);
    if let Some(error) = parsed
        .as_ref()
        .ok()
        .and_then(|reply| reply.get("error"))
        .and_then(Value::as_str)
    {
        return match error {
            "authorization_pending" => {
                device.next_poll_at = next_poll(device)?;
                Ok(DeviceAdvance::Pending)
            }
            "slow_down" => {
                device.interval = device
                    .interval
                    .saturating_add(Duration::from_secs(SLOW_DOWN_SECONDS))
                    .min(Duration::from_secs(MAX_EXPIRY_SECONDS));
                device.next_poll_at = next_poll(device)?;
                Ok(DeviceAdvance::SlowDown)
            }
            "expired_token" | "authorization_expired" => Err(KimiLoginError::DeviceExpired),
            "access_denied" => Err(KimiLoginError::DeviceDenied),
            other => Err(KimiLoginError::Denied {
                code: bounded_reason(other),
            }),
        };
    }
    // RFC 8628 states denials as `error` members; a status-only refusal
    // here is ambiguous (the peer never says whether the code is bad or
    // just not authorized yet), so it stays pending until the recorded
    // lifetime ends the leg — never success, never an early re-enrol.
    if matches!(status.as_u16(), 403 | 404) {
        device.next_poll_at = next_poll(device)?;
        return Ok(DeviceAdvance::Pending);
    }
    if !status.is_success() {
        return Err(KimiLoginError::TokenRejected {
            status: status.as_u16(),
        });
    }
    let reply = parsed.map_err(|cause| KimiLoginError::MalformedResponse { cause })?;
    if Instant::now() >= device.deadline {
        return Err(KimiLoginError::DeviceExpired);
    }
    let credential = credential_from(&reply)?;
    bind_account(&reference, &credential, store)?;
    let material =
        serde_json::to_vec(&credential).map_err(|cause| KimiLoginError::Serialization { cause })?;
    store.login(&reference, &material)?;
    Ok(DeviceAdvance::Complete(reference.profile().to_string()))
}

/// Reads the stored device profile at a scoped reference. Parsing is
/// strict: a bare API key is not this profile.
///
/// # Errors
/// The store's typed denial and
/// [`KimiLoginError::StoredCredentialMalformed`].
pub fn read_credential(
    store: &dyn CredentialStore,
    reference: &SecretRef,
) -> Result<KimiCredential, KimiLoginError> {
    let bytes = store.resolve(reference)?;
    serde_json::from_slice(&bytes).map_err(|cause| KimiLoginError::StoredCredentialMalformed {
        reason: login_common::malformed_reason(&cause),
    })
}

/// Refreshes the stored device profile from its refresh token. The new
/// material replaces the same scope only, so the other profile stays
/// byte-identical; a reply bound to another account denies instead of
/// re-keying the profile.
///
/// # Errors
/// [`KimiLoginError::NotRefreshable`] for a bare-key or tokenless profile,
/// the typed reply denials, and the store's own refusal.
pub fn refresh_credential(
    store: &dyn CredentialStore,
    reference: &SecretRef,
    endpoints: &Endpoints,
) -> Result<(), KimiLoginError> {
    let material = store.resolve(reference)?;
    let text = std::str::from_utf8(&material).map_err(|_utf8| {
        KimiLoginError::StoredCredentialMalformed {
            reason: "the stored bytes are not utf-8",
        }
    })?;
    if !text.trim_start().starts_with('{') {
        return Err(KimiLoginError::NotRefreshable {
            scope: reference.scope().to_string(),
        });
    }
    let mut credential: KimiCredential = serde_json::from_slice(&material).map_err(|cause| {
        KimiLoginError::StoredCredentialMalformed {
            reason: login_common::malformed_reason(&cause),
        }
    })?;
    let Some(refresh_token) = credential.refresh_token.clone() else {
        return Err(KimiLoginError::NotRefreshable {
            scope: reference.scope().to_string(),
        });
    };
    let recorded = Endpoints::recorded();
    if !login_common::admitted_endpoint(&endpoints.token, &recorded.token) {
        return Err(KimiLoginError::EndpointNotRecorded {
            origin: endpoint_origin(&endpoints.token),
        });
    }
    let client = login_common::client(reference.profile(), LOGIN_TIMEOUT)?;
    let request = identity_request(client.post(&endpoints.token))
        .header(
            reqwest::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .header(reqwest::header::ACCEPT, "application/json")
        .body(form_body(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", &refresh_token),
            ("client_id", CLIENT_ID),
        ]));
    let started = Instant::now();
    let mut response = request
        .send()
        .map_err(|err| transport(reference.profile(), err))?;
    let reply = reply_object(&mut response, started)?;
    let fresh = credential_from(&reply)?;
    if fresh.account_id != credential.account_id {
        return Err(KimiLoginError::AccountMismatch);
    }
    // A refresh reply may omit the new refresh token; the recorded form
    // then keeps the previous one rather than dropping the leg.
    if fresh.refresh_token.is_none() {
        credential.refresh_token = Some(refresh_token);
    }
    credential.access_token = fresh.access_token;
    credential.expires_at = fresh.expires_at;
    if let Some(refresh) = fresh.refresh_token {
        credential.refresh_token = Some(refresh);
    }
    let material =
        serde_json::to_vec(&credential).map_err(|cause| KimiLoginError::Serialization { cause })?;
    store.refresh(reference, &material)?;
    Ok(())
}

/// Deletes the profile at this scope. This is a local logout only — a
/// server-side revocation is a live action this build does not claim, and
/// the other profile's scope is untouched.
///
/// # Errors
/// The store's typed refusal.
pub fn logout_local(
    store: &dyn CredentialStore,
    reference: &SecretRef,
) -> Result<(), KimiLoginError> {
    store.logout(reference)?;
    Ok(())
}

/// Deletes the profile at this scope through the store's revocation
/// channel. Like [`logout_local`] this is local entry deletion: whether a
/// provider-side grant was revoked is a live question this build does not
/// claim, and the other profile's scope is untouched.
///
/// # Errors
/// The store's typed refusal.
pub fn revoke_local(
    store: &dyn CredentialStore,
    reference: &SecretRef,
) -> Result<(), KimiLoginError> {
    store.revoke(reference)?;
    Ok(())
}

/// The persisted material one send presents: a bare API-key profile is the
/// key itself; a device profile is the stored credential JSON.
fn bearer_material(
    store: &dyn CredentialStore,
    reference: &SecretRef,
) -> Result<String, ProviderError> {
    let material = store.resolve(reference)?;
    let text = String::from_utf8(material).map_err(|_utf8| ProviderError::CredentialMalformed {
        connection: CONNECTION.to_string(),
    })?;
    let trimmed = text.trim();
    if trimmed.starts_with('{') {
        let credential: KimiCredential =
            serde_json::from_str(trimmed).map_err(|_parse| ProviderError::CredentialMalformed {
                connection: CONNECTION.to_string(),
            })?;
        return Ok(credential.access_token);
    }
    if trimmed.is_empty() {
        return Err(ProviderError::CredentialMalformed {
            connection: CONNECTION.to_string(),
        });
    }
    Ok(trimmed.to_string())
}

/// Refuses a completed device token bound to another account than the one
/// already enrolled at the scope. The check reads only a stored profile;
/// an occupied scope of any other shape stays the store's own create-only
/// denial.
fn bind_account(
    reference: &SecretRef,
    credential: &KimiCredential,
    store: &dyn CredentialStore,
) -> Result<(), KimiLoginError> {
    if !store.occupied(reference)? {
        return Ok(());
    }
    match read_credential(store, reference) {
        Ok(existing) if existing.account_id != credential.account_id => {
            Err(KimiLoginError::AccountMismatch)
        }
        Ok(_same_account) => Ok(()),
        // Occupied material of another shape is the store's own
        // create-only denial to report; every other read failure is this
        // seam's error and must not be swallowed.
        Err(KimiLoginError::StoredCredentialMalformed { .. }) => Ok(()),
        Err(error) => Err(error),
    }
}

/// Bounded body read for the login legs, parsed as a JSON object.
fn reply_object(
    response: &mut reqwest::blocking::Response,
    started: Instant,
) -> Result<Value, KimiLoginError> {
    if !response.status().is_success() {
        return Err(KimiLoginError::TokenRejected {
            status: response.status().as_u16(),
        });
    }
    let body = login_common::read_body(CONNECTION, response, LOGIN_TIMEOUT, started)?;
    let reply = login_common::parse_json(&body)?;
    reply
        .as_object()
        .cloned()
        .map(Value::Object)
        .ok_or(KimiLoginError::MalformedResponse {
            cause: serde_json::Error::io(std::io::Error::other("reply is not an object")),
        })
}

fn text_field(reply: &Value, field: &'static str) -> Result<String, KimiLoginError> {
    login_common::text_field(reply, field).ok_or(KimiLoginError::MissingField { field })
}

fn optional_text(reply: &Value, field: &'static str) -> Result<Option<String>, KimiLoginError> {
    match reply.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if !value.is_empty() => Ok(Some(value.clone())),
        Some(_) => Err(KimiLoginError::MalformedField { field }),
    }
}

/// A positive whole count: a JSON number or a numeric string, never a
/// fraction or an unbounded value.
fn count_field(reply: &Value, field: &'static str) -> Result<Option<u64>, KimiLoginError> {
    match reply.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => {
            let count = value
                .as_u64()
                .or_else(|| value.as_str().and_then(|text| text.parse::<u64>().ok()))
                .ok_or(KimiLoginError::MalformedField { field })?;
            Ok(Some(count))
        }
    }
}

fn lifetime_of(reply: &Value, field: &'static str, fallback: u64) -> Result<u64, KimiLoginError> {
    let seconds = count_field(reply, field)?.unwrap_or(fallback);
    if seconds == 0 {
        return Err(KimiLoginError::MalformedField { field });
    }
    if seconds > MAX_EXPIRY_SECONDS {
        return Err(KimiLoginError::DeviceExpiryOutOfRange { seconds });
    }
    Ok(seconds)
}

fn interval_of(reply: &Value) -> Result<Duration, KimiLoginError> {
    let seconds = match count_field(reply, "interval")? {
        None => DEFAULT_INTERVAL_SECONDS,
        Some(0) => return Err(KimiLoginError::MalformedField { field: "interval" }),
        Some(seconds) => seconds,
    };
    if seconds > MAX_EXPIRY_SECONDS {
        return Err(KimiLoginError::DeviceIntervalOutOfRange { seconds });
    }
    Ok(Duration::from_secs(seconds))
}

fn next_poll(device: &DeviceLoginSession) -> Result<Instant, KimiLoginError> {
    Instant::now()
        .checked_add(device.interval)
        .ok_or(KimiLoginError::DeviceIntervalOutOfRange {
            seconds: device.interval.as_secs(),
        })
}

/// The recorded `user_id|sub` account claim of a completed token: the reply
/// fields first, then the id token's claims, then the access token's.
fn account_claim(reply: &Value) -> Option<String> {
    let from_claims = |claims: &Value| {
        ["user_id", "sub"].into_iter().find_map(|field| {
            claims
                .get(field)
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
        })
    };
    if let Some(account) = from_claims(reply) {
        return Some(account);
    }
    if let Some(id_token) = reply.get("id_token").and_then(Value::as_str)
        && let Some(claims) = login_common::jwt_claims(id_token)
        && let Some(account) = from_claims(&claims)
    {
        return Some(account);
    }
    let access_token = reply.get("access_token").and_then(Value::as_str)?;
    from_claims(&login_common::jwt_claims(access_token)?)
}

fn credential_from(reply: &Value) -> Result<KimiCredential, KimiLoginError> {
    let access_token = text_field(reply, "access_token")?;
    let account_id = account_claim(reply).ok_or(KimiLoginError::MissingIdentity)?;
    let expires_in = count_field(reply, "expires_in")?.ok_or(KimiLoginError::MissingField {
        field: "expires_in",
    })?;
    if expires_in == 0 {
        return Err(KimiLoginError::MalformedField {
            field: "expires_in",
        });
    }
    if expires_in > MAX_TOKEN_EXPIRY_SECONDS {
        return Err(KimiLoginError::TokenExpiryOutOfRange {
            seconds: expires_in,
        });
    }
    let expires_at = login_common::expires_at(expires_in, Duration::ZERO)?;
    Ok(KimiCredential {
        access_token,
        refresh_token: optional_text(reply, "refresh_token")?,
        expires_at,
        account_id,
    })
}

fn form_body(fields: &[(&str, &str)]) -> String {
    fields
        .iter()
        .map(|(name, value)| {
            format!(
                "{}={}",
                login_common::encode_component(name),
                login_common::encode_component(value)
            )
        })
        .collect::<Vec<String>>()
        .join("&")
}

/// The protocol a catalogue row declares. A row without `protocol` keeps
/// the recorded Messages default; a value outside the closed set is never
/// guessed.
fn protocol_of(declared: Option<&Value>, model: &str) -> Result<Protocol, ProviderError> {
    match declared {
        None | Some(Value::Null) => Ok(Protocol::Messages),
        Some(Value::String(value)) => match value.as_str() {
            "messages" | "anthropic" => Ok(Protocol::Messages),
            "chat" | "chat-completions" | "completions" | "openai" => Ok(Protocol::ChatCompletions),
            _ => Err(ProviderError::ModelClassUnresolved {
                connection: CONNECTION.to_string(),
                model: model.to_string(),
            }),
        },
        Some(_) => Err(ProviderError::ModelClassUnresolved {
            connection: CONNECTION.to_string(),
            model: model.to_string(),
        }),
    }
}

/// The terminal classification one finished Chat Completions stream
/// reduces to.
enum ChatTerminal {
    Completed,
    Failed(String),
    Unclassifiable,
}

/// The reasoning member names the recorded Chat contract returns as-is on
/// a multi-turn replay; the one the stream used is the one replayed.
const CHAT_REASONING_KEYS: [&str; 3] = ["reasoning_content", "reasoning", "reasoning_text"];

/// One in-flight streamed Chat tool call: `index` and `id` are the recorded
/// correlation keys — `id` is set once like `name`, and unique across
/// blocks — and `args` is the arguments text still concatenating.
#[derive(Default)]
struct ChatBlock {
    id: Option<String>,
    name: Option<String>,
    args: String,
}

#[derive(Default)]
struct ChatStream {
    text: String,
    /// The reasoning the peer streamed, in the member it named.
    reasoning: [String; CHAT_REASONING_KEYS.len()],
    blocks: Vec<ChatBlock>,
    block_by_index: HashMap<u64, usize>,
    terminal: Option<ChatTerminal>,
    done: bool,
    usage: Option<Value>,
}

/// The assistant turn one Chat epoch replays: the reasoning the peer sent
/// returns as-is beside the answer it accompanied.
struct ChatLineage {
    model: String,
    message: Value,
}

/// The frozen execution world, purpose and epoch a Chat replay belongs to.
type ChatLineageKey = (String, String, String);

fn chat_lineage_key(manifest: &RequestManifest) -> ChatLineageKey {
    (
        manifest.world.clone(),
        manifest.purpose.clone(),
        manifest.epoch_id.clone(),
    )
}

/// The Kimi Code adapter: one literal connection, the resolved protocol of
/// each send's model, and exactly one reply and one physical usage report
/// per send.
pub struct KimiProvider {
    connection: String,
    endpoint: String,
    auth: WireAuth,
    store: Arc<dyn CredentialStore>,
    client: reqwest::blocking::Client,
    deadline: Duration,
    /// The shared Messages reduction: thinking lineage, drop policy and
    /// stream accounting for the Anthropic-compatible leg.
    codec: MessagesCodec,
    /// Chat reasoning turns, one per lineage, replayed inside their epoch.
    chat_lineages: BTreeMap<ChatLineageKey, ChatLineage>,
}

impl fmt::Debug for KimiProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KimiProvider")
            .field("connection", &self.connection)
            .field("endpoint", &self.endpoint)
            .field("auth", &self.auth)
            .field("deadline", &self.deadline)
            .finish_non_exhaustive()
    }
}

impl KimiProvider {
    /// Builds the adapter for the literal `kimi-code` row: the connection
    /// must be declared, carry no region, and resolve its scoped binding.
    ///
    /// # Errors
    /// [`ProviderError::DialectMismatch`] for another literal id;
    /// [`ProviderError::UnknownConnection`] for an undeclared one;
    /// [`ProviderError::RegionMismatch`] for a configured region;
    /// [`ProviderError::LocalProfileDeclared`] for a local declaration
    /// binding a profile; [`ProviderError::CredentialUnresolved`] for an
    /// unresolved binding; and [`ProviderError::Transport`] when the HTTP
    /// client cannot build.
    pub fn new(
        config: &Config,
        connection: &str,
        store: Arc<dyn CredentialStore>,
    ) -> Result<Self, ProviderError> {
        Self::build(config, connection, store, REQUEST_DEADLINE)
    }

    /// How many replayed thinking blocks the peer reported dropping.
    #[must_use]
    pub fn dropped_reasoning(&self) -> u64 {
        self.codec.dropped_reasoning()
    }

    fn build(
        config: &Config,
        connection: &str,
        store: Arc<dyn CredentialStore>,
        deadline: Duration,
    ) -> Result<Self, ProviderError> {
        if connection != CONNECTION {
            return Err(ProviderError::DialectMismatch {
                connection: connection.to_string(),
            });
        }
        let entry =
            config
                .connections
                .get(connection)
                .ok_or_else(|| ProviderError::UnknownConnection {
                    connection: connection.to_string(),
                })?;
        if let Some(region) = &entry.region {
            return Err(ProviderError::RegionMismatch {
                connection: connection.to_string(),
                region: region.clone(),
            });
        }
        if entry.kind == ConnKind::Local && entry.profile.is_some() {
            return Err(ProviderError::LocalProfileDeclared {
                connection: connection.to_string(),
            });
        }
        // The recorded Kimi Code class is the api-key row (the device
        // profile it may hold is stored in that row's scope); a local or
        // subscription declaration records semantics this adapter has
        // none for, so it denies before any wire leg instead of sending
        // under an invented one.
        match entry.kind {
            ConnKind::ApiKey => {}
            ConnKind::Local => {
                return Err(ProviderError::CredentialUnresolved {
                    connection: connection.to_string(),
                    scope: format!("connections.{connection}.kind"),
                    cause: None,
                });
            }
            ConnKind::Subscription => {
                return Err(ProviderError::LiveGrantRequired {
                    kind: ConnKind::Subscription,
                });
            }
        }
        let configured = entry.endpoint.trim().trim_end_matches('/');
        let endpoint = if configured.is_empty() {
            DEFAULT_BASE.to_string()
        } else {
            configured.to_string()
        };
        let credential =
            resolve_admitted_credential_in(&config.connections, &config.profiles, connection)?
                .ok_or_else(|| ProviderError::CredentialUnresolved {
                    connection: connection.to_string(),
                    scope: format!("connections.{connection}.credential_ref"),
                    cause: None,
                })?;
        let client = reqwest::blocking::Client::builder()
            .timeout(deadline.saturating_mul(2))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|err| transport(connection, err))?;
        Ok(Self {
            connection: connection.to_string(),
            endpoint,
            auth: WireAuth::Store(Some(credential)),
            store,
            client,
            deadline,
            codec: MessagesCodec::new(connection),
            chat_lineages: BTreeMap::new(),
        })
    }

    /// The one catalogue read a send performs: the rows in deterministic
    /// id order, each keeping its raw `protocol` member. Only the selected
    /// row is classified, so a forward-compatible value on a sibling row
    /// never denies this send; a duplicate id is a listing violation.
    ///
    /// # Errors
    /// [`ProviderError::Transport`] for a failed call, non-success status
    /// or expired budget, and [`ProviderError::StreamViolation`] when the
    /// listing is not the recorded shape.
    fn listing(&self, bearer: &str, started: Instant) -> Result<Vec<ListedRow>, ProviderError> {
        check_deadline(&self.connection, self.deadline, started)?;
        let mut response = identity_request(
            self.client
                .get(format!("{}/models", self.endpoint))
                .header(reqwest::header::ACCEPT, "application/json")
                .bearer_auth(bearer),
        )
        .send()
        .map_err(|err| transport(&self.connection, err))?;
        if !response.status().is_success() {
            return Err(transport_status(&self.connection, response.status()));
        }
        let body =
            super::read_catalog_body(&self.connection, self.deadline, &mut response, started)?;
        let payload: Value = serde_json::from_slice(&body)
            .map_err(|_parse| violation(&self.connection, "model listing is not json"))?;
        let rows = payload
            .get("data")
            .and_then(Value::as_array)
            .ok_or_else(|| violation(&self.connection, "model listing carries no data array"))?;
        let mut listed = Vec::with_capacity(rows.len());
        for row in rows {
            let Some(id) = row.get("id").and_then(Value::as_str) else {
                return Err(violation(&self.connection, "a model row carries no id"));
            };
            listed.push(ListedRow {
                id: id.to_string(),
                protocol: row.get("protocol").cloned(),
            });
        }
        listed.sort_by(|a, b| a.id.cmp(&b.id));
        if listed.windows(2).any(|pair| pair[0].id == pair[1].id) {
            return Err(violation(
                &self.connection,
                "model listing carries a duplicate id",
            ));
        }
        Ok(listed)
    }

    /// The bearer one send presents, resolved exactly once per send.
    fn bearer(&self) -> Result<String, ProviderError> {
        let WireAuth::Store(Some(reference)) = &self.auth else {
            return Err(ProviderError::CredentialUnresolved {
                connection: self.connection.clone(),
                scope: format!("connections.{}.credential_ref", self.connection),
                cause: None,
            });
        };
        bearer_material(self.store.as_ref(), reference)
    }

    /// The pinned or auto-resolved model and its declared protocol, both
    /// from this send's one catalogue read. The protocol comes from the
    /// selected row, never from the id family or the credential form.
    fn resolve_model(
        &self,
        manifest: &RequestManifest,
        bearer: &str,
        started: Instant,
    ) -> Result<(String, Protocol), ProviderError> {
        let listed = self.listing(bearer, started)?;
        let model = match &manifest.model {
            ModelAssign::Fixed(fixed) => {
                if fixed.connection != self.connection {
                    return Err(ProviderError::DialectMismatch {
                        connection: fixed.connection.clone(),
                    });
                }
                fixed.model_id.clone()
            }
            ModelAssign::Auto { pool: Some(pool) }
                if pool.len() == 1 && pool[0] == self.connection =>
            {
                listed.first().map(|row| row.id.clone()).ok_or_else(|| {
                    ProviderError::UnpinnedModel {
                        connection: self.connection.clone(),
                    }
                })?
            }
            _ => {
                return Err(ProviderError::UnpinnedModel {
                    connection: self.connection.clone(),
                });
            }
        };
        let row = listed.iter().find(|row| row.id == model).ok_or_else(|| {
            ProviderError::UnsupportedParameter {
                connection: self.connection.clone(),
                parameter: "model",
                model: model.clone(),
            }
        })?;
        Ok((model, protocol_of(row.protocol.as_ref(), &row.id)?))
    }

    /// The frozen manifest as the Chat Completions wire body. The prior
    /// assistant turn of this epoch replays its reasoning beside the answer
    /// it accompanied; a prefix mutation replays nothing and retires the
    /// conversation's displaced epochs before the wire leg.
    fn chat_body(
        &mut self,
        manifest: &RequestManifest,
        model: &str,
    ) -> Result<Value, ProviderError> {
        if manifest.mutation_reason.is_some() {
            retire_displaced_epochs(&mut self.chat_lineages, &chat_lineage_key(manifest));
        }
        let mut messages = Vec::with_capacity(3);
        if !manifest.instructions.is_empty() {
            messages.push(json!({ "role": "system", "content": manifest.instructions }));
        }
        if manifest.mutation_reason.is_none()
            && let Some(prior) = self.chat_lineages.get(&chat_lineage_key(manifest))
            && prior.model == model
        {
            messages.push(prior.message.clone());
        }
        messages.push(json!({ "role": "user", "content": manifest.inputs }));
        let mut body = json!({
            "model": model,
            "messages": messages,
            "stream": true,
            "stream_options": { "include_usage": true },
        });
        if let crate::config::EffortAssign::Fixed { value } = &manifest.effort {
            // The recorded Kimi ladder is low/high with `max` as the
            // provider default; every other pinned level denies typed
            // rather than riding a value the contract never states.
            if !matches!(
                value,
                crate::config::EffortLevel::Low | crate::config::EffortLevel::High
            ) {
                return Err(ProviderError::UnsupportedParameter {
                    connection: self.connection.clone(),
                    parameter: "reasoning_effort",
                    model: model.to_string(),
                });
            }
            body["reasoning_effort"] = json!(value.name());
        }
        if !manifest.tools.is_empty() {
            body["tools"] = Value::Array(
                manifest
                    .tools
                    .iter()
                    .map(|name| {
                        json!({
                            "type": "function",
                            "function": {
                                "name": name,
                                "description": "",
                                "parameters": { "type": "object" },
                            },
                        })
                    })
                    .collect(),
            );
        }
        Ok(body)
    }

    /// A pinned Messages effort has no recorded dial: the denial lands
    /// before the body, never as a silently dropped field.
    fn check_messages_effort(
        &self,
        manifest: &RequestManifest,
        model: &str,
    ) -> Result<(), ProviderError> {
        if let crate::config::EffortAssign::Fixed { .. } = &manifest.effort {
            return Err(ProviderError::UnsupportedParameter {
                connection: self.connection.clone(),
                parameter: "reasoning_effort",
                model: model.to_string(),
            });
        }
        Ok(())
    }
}

impl Provider for KimiProvider {
    fn name(&self) -> &'static str {
        "kimi-code"
    }

    fn serves(&self, connection: &str, _entry: &Connection) -> bool {
        connection == self.connection
    }

    /// Sends the frozen manifest as one physical request on its model's
    /// resolved protocol.
    ///
    /// # Errors
    /// [`ProviderError::UnpinnedModel`]/[`ProviderError::DialectMismatch`]
    /// for an assignment this adapter cannot pin, the credential seam's
    /// typed denials, [`ProviderError::CredentialMalformed`] for foreign
    /// stored material, [`ProviderError::UnsupportedParameter`] for a row
    /// outside the listing or a rejected pinned parameter,
    /// [`ProviderError::ModelClassUnresolved`] for an undeclared protocol,
    /// [`ProviderError::Transport`], [`ProviderError::ProviderFailed`],
    /// [`ProviderError::UnknownTerminal`], [`ProviderError::StreamViolation`]
    /// and [`ProviderError::IncompatibleOutput`] as the reducers document.
    fn send(&mut self, manifest: &RequestManifest) -> Result<ProviderReply, ProviderError> {
        let started = Instant::now();
        check_deadline(&self.connection, self.deadline, started)?;
        let bearer = self.bearer()?;
        let (model, protocol) = self.resolve_model(manifest, &bearer, started)?;
        match protocol {
            Protocol::ChatCompletions => {
                let body = self.chat_body(manifest, &model)?;
                let bytes = wire_body(&self.connection, &body)?;
                check_deadline(&self.connection, self.deadline, started)?;
                let response = identity_request(
                    self.client
                        .post(format!("{}/chat/completions", self.endpoint))
                        .header(reqwest::header::CONTENT_TYPE, "application/json")
                        .header(reqwest::header::ACCEPT, "text/event-stream")
                        .bearer_auth(&bearer)
                        .body(bytes),
                )
                .send()
                .map_err(|err| transport(&self.connection, err))?;
                if !response.status().is_success() {
                    return Err(transport_status(&self.connection, response.status()));
                }
                self.read_chat(manifest, &model, response, started)
            }
            Protocol::Messages => {
                self.check_messages_effort(manifest, &model)?;
                let fixed = FixedModel {
                    connection: self.connection.clone(),
                    model_id: model.clone(),
                };
                let binding = self.codec.binding(manifest, &model);
                let body = self.codec.request_body(manifest, &fixed, &binding);
                let bytes = wire_body(&self.connection, &body)?;
                check_deadline(&self.connection, self.deadline, started)?;
                let deadline = self.deadline;
                let client = &self.client;
                let endpoint = self.endpoint.as_str();
                let connection = self.connection.as_str();
                let post = |bytes: Vec<u8>, drop_block: bool| {
                    let mut request = identity_request(
                        client
                            .post(format!("{endpoint}/messages"))
                            .header(reqwest::header::CONTENT_TYPE, "application/json")
                            .header(reqwest::header::ACCEPT, "text/event-stream")
                            .header("anthropic-version", ANTHROPIC_VERSION)
                            .bearer_auth(&bearer)
                            .body(bytes),
                    );
                    if drop_block {
                        request = request.header("anthropic-beta", THINKING_BINDING_BETA);
                    }
                    request.send().map_err(|err| transport(connection, err))
                };
                let response = post(bytes, binding.drop_block)?;
                let codec = &mut self.codec;
                if response.status().is_success() {
                    return codec.read_stream(manifest, &model, response, deadline, started);
                }
                codec.retry_invalid_signature(
                    RefusedMessages {
                        manifest,
                        fixed: &fixed,
                        binding: &binding,
                        response,
                    },
                    deadline,
                    started,
                    post,
                )
            }
        }
    }
}

impl KimiProvider {
    /// Reads one Chat Completions SSE body through the shared bounded
    /// parser. `[DONE]` alone is the recorded server-agreed close; EOF
    /// with neither a classifiable `finish_reason` nor the sentinel is
    /// the unknown terminal.
    fn read_chat(
        &mut self,
        manifest: &RequestManifest,
        model: &str,
        mut response: reqwest::blocking::Response,
        started: Instant,
    ) -> Result<ProviderReply, ProviderError> {
        let mut parser = SseParser::new();
        let mut state = ChatStream::default();
        let mut chunk = vec![0u8; STREAM_CHUNK_BYTES];
        let mut total = 0usize;
        loop {
            let read = read_chunk(
                &self.connection,
                self.deadline,
                &mut response,
                &mut chunk,
                started,
            )?;
            if read == 0 {
                break;
            }
            total = total.saturating_add(read);
            if total > MAX_STREAM_BYTES {
                return Err(violation(&self.connection, "stream exceeds the byte bound"));
            }
            for event in parser
                .feed(&chunk[..read])
                .map_err(|err| sse(&self.connection, err))?
            {
                self.on_chat_event(&mut state, event)?;
            }
        }
        check_deadline(&self.connection, self.deadline, started)?;
        for event in parser.finish().map_err(|err| sse(&self.connection, err))? {
            self.on_chat_event(&mut state, event)?;
        }
        match state.terminal.take() {
            Some(ChatTerminal::Completed) => self.finish_chat(manifest, model, state),
            Some(ChatTerminal::Failed(reason)) => Err(ProviderError::ProviderFailed {
                connection: self.connection.clone(),
                reason: bounded_reason(reason),
            }),
            Some(ChatTerminal::Unclassifiable) => Err(ProviderError::UnknownTerminal {
                connection: self.connection.clone(),
            }),
            None if state.done => self.finish_chat(manifest, model, state),
            None => Err(ProviderError::UnknownTerminal {
                connection: self.connection.clone(),
            }),
        }
    }

    /// Finalizes a completed Chat stream and commits its replayable
    /// assistant turn: a stream that never declared reasoning commits
    /// nothing, so an unchanged epoch without reasoning replays nothing.
    fn finish_chat(
        &mut self,
        manifest: &RequestManifest,
        model: &str,
        mut state: ChatStream,
    ) -> Result<ProviderReply, ProviderError> {
        let usage = chat_usage(state.usage.as_ref())?;
        let mut tool_calls = Vec::with_capacity(state.blocks.len());
        for block in std::mem::take(&mut state.blocks) {
            let Some(name) = block.name.filter(|name| !name.is_empty()) else {
                return Err(violation(
                    &self.connection,
                    "a tool_call block never carried a function name",
                ));
            };
            if !manifest.tools.iter().any(|declared| declared == &name) {
                return Err(ProviderError::IncompatibleOutput {
                    connection: self.connection.clone(),
                    reason: bounded_reason(format!("tool_call names undeclared tool {name}")),
                });
            }
            let path = if block.args.is_empty() {
                None
            } else {
                let args: Value = serde_json::from_str(&block.args).map_err(|_parse| {
                    violation(&self.connection, "a tool_call's arguments did not parse")
                })?;
                let Some(args) = args.as_object() else {
                    return Err(violation(
                        &self.connection,
                        "a tool_call's arguments are not an object",
                    ));
                };
                args.get("path").and_then(Value::as_str).map(str::to_string)
            };
            tool_calls.push(ToolCall { tool: name, path });
        }
        self.commit_chat(manifest, model, &state);
        Ok(ProviderReply {
            text: state.text,
            tool_calls,
            usage,
            wire_retries: 0,
            dropped_reasoning: 0,
        })
    }

    /// Commits the assistant turn one Chat epoch replays — the answer and
    /// every reasoning member the peer named, byte-identical. A mutation or
    /// a reasoning-less turn clears the conversation's replay state instead,
    /// so a displaced epoch never answers a later send.
    fn commit_chat(&mut self, manifest: &RequestManifest, model: &str, state: &ChatStream) {
        let key = chat_lineage_key(manifest);
        if manifest.mutation_reason.is_some() || state.reasoning.iter().all(String::is_empty) {
            retire_displaced_epochs(&mut self.chat_lineages, &key);
            return;
        }
        let mut message = serde_json::Map::new();
        message.insert("role".to_string(), json!("assistant"));
        message.insert("content".to_string(), json!(state.text));
        for (name, piece) in CHAT_REASONING_KEYS.iter().zip(&state.reasoning) {
            if !piece.is_empty() {
                message.insert((*name).to_string(), json!(piece));
            }
        }
        retain_lineage_epoch(
            &mut self.chat_lineages,
            key,
            ChatLineage {
                model: model.to_string(),
                message: Value::Object(message),
            },
        );
    }

    fn on_chat_event(&self, state: &mut ChatStream, event: SseEvent) -> Result<(), ProviderError> {
        if event.data == "[DONE]" {
            if state.done {
                return Err(violation(
                    &self.connection,
                    "stream carried a duplicate [DONE] sentinel",
                ));
            }
            state.done = true;
            return Ok(());
        }
        if state.done {
            return Err(violation(
                &self.connection,
                "stream carried content after the [DONE] sentinel",
            ));
        }
        let chunk: Value = serde_json::from_str(&event.data)
            .map_err(|_parse| violation(&self.connection, "stream chunk is not json"))?;
        if !chunk.is_object() {
            return Err(violation(&self.connection, "stream chunk is not an object"));
        }
        if let Some(error) = chunk.get("error").filter(|error| !is_falsy(error)) {
            let reason = match error {
                Value::String(reason) => reason.clone(),
                Value::Object(_) => super::payload_reason(error),
                _ => {
                    return Err(violation(
                        &self.connection,
                        "stream chunk error is not an object or string",
                    ));
                }
            };
            return self.set_chat_terminal(state, ChatTerminal::Failed(reason));
        }
        if let Some(message) = chunk.get("message").filter(|message| !is_falsy(message)) {
            let Some(reason) = message.as_str() else {
                return Err(violation(
                    &self.connection,
                    "stream chunk message is not a string",
                ));
            };
            return self.set_chat_terminal(state, ChatTerminal::Failed(reason.to_string()));
        }
        let choice = match chunk.get("choices") {
            None => None,
            Some(choices) => {
                let Some(list) = choices.as_array() else {
                    return Err(violation(
                        &self.connection,
                        "stream chunk choices is not an array",
                    ));
                };
                if list.len() > 1 {
                    return Err(violation(
                        &self.connection,
                        "stream chunk carried more than one choice",
                    ));
                }
                match list.first() {
                    None => None,
                    Some(choice) => {
                        if !choice.is_object() {
                            return Err(violation(
                                &self.connection,
                                "stream chunk choice is not an object",
                            ));
                        }
                        if state.terminal.is_some() {
                            return Err(violation(
                                &self.connection,
                                "stream carried a choice after its terminal",
                            ));
                        }
                        if let Some(index) = choice.get("index")
                            && index.as_u64() != Some(0)
                        {
                            return Err(violation(
                                &self.connection,
                                "stream chunk choice carries a nonzero index",
                            ));
                        }
                        Some(choice)
                    }
                }
            }
        };
        if let Some(choice) = choice {
            self.on_chat_delta(state, choice)?;
            if let Some(reason) = choice.get("finish_reason") {
                let terminal = match reason {
                    Value::Null => None,
                    Value::String(reason) => Some(match reason.to_ascii_lowercase().as_str() {
                        "stop" | "end" | "length" | "max_tokens" | "function_call"
                        | "tool_calls" => ChatTerminal::Completed,
                        "content_filter"
                        | "network_error"
                        | "error"
                        | "insufficient_system_resource" => ChatTerminal::Failed(format!(
                            "generation failed with finish reason {reason}"
                        )),
                        _ => ChatTerminal::Unclassifiable,
                    }),
                    _ => {
                        return Err(violation(
                            &self.connection,
                            "choice finish_reason is not a string",
                        ));
                    }
                };
                if let Some(terminal) = terminal {
                    self.set_chat_terminal(state, terminal)?;
                }
            }
        }
        if let Some(usage) = chunk
            .get("usage")
            .or_else(|| choice.and_then(|choice| choice.get("usage")))
            .filter(|usage| !usage.is_null())
        {
            state.usage = Some(usage.clone());
        }
        Ok(())
    }

    fn on_chat_delta(&self, state: &mut ChatStream, choice: &Value) -> Result<(), ProviderError> {
        let Some(delta) = choice.get("delta").filter(|delta| !delta.is_null()) else {
            return Ok(());
        };
        let Some(delta) = delta.as_object() else {
            return Err(violation(&self.connection, "choice delta is not an object"));
        };
        if let Some(content) = delta.get("content") {
            match content {
                Value::String(text) => state.text.push_str(text),
                Value::Null => {}
                _ => return Err(violation(&self.connection, "delta content is not a string")),
            }
        }
        for (slot, key) in state.reasoning.iter_mut().zip(CHAT_REASONING_KEYS) {
            if let Some(reasoning) = delta.get(key) {
                match reasoning {
                    Value::String(piece) => slot.push_str(piece),
                    Value::Null => {}
                    _ => {
                        return Err(violation(
                            &self.connection,
                            "delta reasoning is not a string",
                        ));
                    }
                }
            }
        }
        if let Some(calls) = delta.get("tool_calls") {
            let Some(calls) = calls.as_array() else {
                return Err(violation(
                    &self.connection,
                    "delta tool_calls is not an array",
                ));
            };
            for entry in calls {
                self.on_chat_tool_call(state, entry, calls.len() > 1)?;
            }
        }
        Ok(())
    }

    /// Routes one `tool_calls` entry to its block: the stream `index` wins,
    /// then a block's declared `id`, and only a single-entry delta may
    /// continue the last-opened block — an unkeyed entry inside a
    /// multi-call batch cannot be attributed to a sibling. A block's `id`
    /// and function `name` are each set once; a second, different value or
    /// an id a sibling already holds is a malformed stream, never a silent
    /// re-key. Argument fragments concatenate under the byte bound.
    fn on_chat_tool_call(
        &self,
        state: &mut ChatStream,
        entry: &Value,
        batched: bool,
    ) -> Result<(), ProviderError> {
        let Some(entry) = entry.as_object() else {
            return Err(violation(
                &self.connection,
                "tool_calls entry is not an object",
            ));
        };
        let index = match entry.get("index") {
            None => None,
            Some(index) => match index.as_u64() {
                Some(index) => Some(index),
                None => {
                    return Err(violation(
                        &self.connection,
                        "tool_calls entry index is not an integer",
                    ));
                }
            },
        };
        let id = match entry.get("id") {
            None | Some(Value::Null) => None,
            // An empty id is no correlation key — the contract treats a
            // falsy id as absent.
            Some(Value::String(id)) if !id.is_empty() => Some(id.clone()),
            Some(Value::String(_)) => None,
            Some(_) => {
                return Err(violation(
                    &self.connection,
                    "tool_calls entry id is not a string",
                ));
            }
        };
        let position = if let Some(index) = index {
            match state.block_by_index.get(&index) {
                Some(&position) => position,
                None => {
                    let position = state.blocks.len();
                    state.blocks.push(ChatBlock::default());
                    state.block_by_index.insert(index, position);
                    position
                }
            }
        } else if let Some(id) = &id {
            match state
                .blocks
                .iter()
                .rposition(|block| block.id.as_deref() == Some(id.as_str()))
            {
                Some(position) => position,
                None => {
                    state.blocks.push(ChatBlock {
                        id: Some(id.clone()),
                        ..ChatBlock::default()
                    });
                    state.blocks.len() - 1
                }
            }
        } else if batched {
            return Err(violation(
                &self.connection,
                "a tool_calls entry without index or id cannot be routed",
            ));
        } else if state.blocks.is_empty() {
            state.blocks.push(ChatBlock::default());
            0
        } else {
            state.blocks.len() - 1
        };
        if state.blocks.len() > MAX_TOOL_CALLS {
            return Err(violation(
                &self.connection,
                "stream carried more tool calls than the bound",
            ));
        }
        if let Some(kind) = entry.get("type") {
            match kind {
                Value::Null => {}
                Value::String(kind) if kind == "function" => {}
                Value::String(_) => {
                    return Err(ProviderError::IncompatibleOutput {
                        connection: self.connection.clone(),
                        reason: bounded_reason("a streamed tool call is not a function call"),
                    });
                }
                _ => {
                    return Err(violation(
                        &self.connection,
                        "tool_calls entry type is not a string",
                    ));
                }
            }
        }
        // `id` is set once like `name`; an id a sibling block already holds
        // would make an id-only continuation ambiguous.
        if let Some(id) = id {
            match &state.blocks[position].id {
                Some(existing) if existing != &id => {
                    return Err(violation(
                        &self.connection,
                        "a tool_call block's id changed mid-stream",
                    ));
                }
                Some(_) => {}
                None => {
                    if state.blocks.iter().enumerate().any(|(at, block)| {
                        at != position && block.id.as_deref() == Some(id.as_str())
                    }) {
                        return Err(violation(
                            &self.connection,
                            "two tool_call blocks carry the same id",
                        ));
                    }
                    state.blocks[position].id = Some(id);
                }
            }
        }
        if let Some(function) = entry.get("function") {
            let Some(function) = function.as_object() else {
                return Err(violation(
                    &self.connection,
                    "tool_calls entry function is not an object",
                ));
            };
            if let Some(name) = function.get("name") {
                match name {
                    Value::String(name) if !name.is_empty() => match &state.blocks[position].name {
                        Some(existing) if existing != name => {
                            return Err(violation(
                                &self.connection,
                                "a tool_call block's function name changed mid-stream",
                            ));
                        }
                        Some(_) => {}
                        None => state.blocks[position].name = Some(name.clone()),
                    },
                    Value::String(_) | Value::Null => {}
                    _ => {
                        return Err(violation(
                            &self.connection,
                            "tool_call function name is not a string",
                        ));
                    }
                }
            }
            if let Some(arguments) = function.get("arguments") {
                match arguments {
                    Value::String(piece) => {
                        let block = &mut state.blocks[position];
                        if block.args.len() + piece.len() > MAX_TOOL_ARGS_BYTES {
                            return Err(violation(
                                &self.connection,
                                "a tool_call's arguments exceed the byte bound",
                            ));
                        }
                        block.args.push_str(piece);
                    }
                    Value::Null => {}
                    _ => {
                        return Err(violation(
                            &self.connection,
                            "a tool_call's arguments are not a streamed string",
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    fn set_chat_terminal(
        &self,
        state: &mut ChatStream,
        terminal: ChatTerminal,
    ) -> Result<(), ProviderError> {
        if state.terminal.is_some() {
            return Err(violation(
                &self.connection,
                "stream carried a duplicate terminal",
            ));
        }
        state.terminal = Some(terminal);
        Ok(())
    }
}

/// The physical usage a Chat Completions stream reported: absent stays
/// unknown, a present-but-unreadable shape is a wire violation.
fn chat_usage(usage: Option<&Value>) -> Result<UsageDelta, ProviderError> {
    let Some(usage) = usage else {
        return Ok(UsageDelta::Unknown);
    };
    let prompt = usage.get("prompt_tokens").and_then(Value::as_u64);
    let completion = usage.get("completion_tokens").and_then(Value::as_u64);
    let total = usage.get("total_tokens").and_then(Value::as_u64);
    let cache_read = usage
        .get("prompt_tokens_details")
        .and_then(|details| details.get("cached_tokens"))
        .and_then(Value::as_u64);
    let reasoning = usage
        .get("completion_tokens_details")
        .and_then(|details| details.get("reasoning_tokens"))
        .and_then(Value::as_u64);
    match (prompt, completion, total) {
        (Some(prompt_tokens), Some(completion_tokens), Some(total_tokens)) => {
            // Cached prompt tokens are a subset of `prompt_tokens` in this
            // dialect, so the prompt leg is uncached input only.
            // shortcut: dialect semantics normalized at the adapter; revisit if a provider changes the inclusion rule
            let uncached = prompt_tokens.saturating_sub(cache_read.unwrap_or(0));
            Ok(UsageDelta::from_reported(
                uncached,
                completion_tokens,
                total_tokens,
                reasoning,
                cache_read,
                None,
            ))
        }
        _ => Err(violation(CONNECTION, "usage is not a readable token shape")),
    }
}

/// JavaScript truthiness for the recorded `if (data.error)` guards.
fn is_falsy(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Bool(flag) => !flag,
        Value::Number(number) => number.as_f64() == Some(0.0),
        Value::String(text) => text.is_empty(),
        Value::Array(_) | Value::Object(_) => false,
    }
}

/// Keeps the recorded dialect gate visible to reviewers: this module rides
/// both protocol dialects in the provider registry.
#[must_use]
pub fn dialects() -> &'static [Dialect] {
    const DIALECTS: &[Dialect] = &[Dialect::Messages, Dialect::ChatCompletions];
    DIALECTS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recorded_identity_carries_no_foreign_client_name() {
        let headers = identity_headers();
        let rendered = format!("{headers:?}");
        assert!(rendered.contains("rivect/"));
        assert!(!rendered.contains("KimiCLI"));
    }

    #[test]
    fn a_row_without_protocol_keeps_the_messages_default() {
        assert_eq!(
            protocol_of(None, "kimi-k3").expect("default"),
            Protocol::Messages
        );
        assert_eq!(
            protocol_of(Some(&json!("chat")), "x").expect("chat"),
            Protocol::ChatCompletions
        );
        assert!(matches!(
            protocol_of(Some(&json!("grpc")), "x"),
            Err(ProviderError::ModelClassUnresolved { .. })
        ));
    }

    #[test]
    fn device_lifetime_and_interval_ceilings_are_typed() {
        assert!(matches!(
            lifetime_of(&json!({ "expires_in": u64::MAX }), "expires_in", 600),
            Err(KimiLoginError::DeviceExpiryOutOfRange { .. })
        ));
        assert!(matches!(
            interval_of(&json!({ "interval": "999999999999999999999999" })),
            Err(KimiLoginError::MalformedField { field: "interval" })
        ));
        assert!(matches!(
            interval_of(&json!({ "interval": 1.5 })),
            Err(KimiLoginError::MalformedField { field: "interval" })
        ));
    }
}
