//! Z.AI (GLM Coding Plan · Sign in) profile producer: the recorded
//! non-PKCE authorization-code leg, the JSON token exchange, the business
//! API sequence that provisions the durable `rivect` key, and the canonical
//! `zai` scoped profile. Library-level — no CLI verb is added.
//!
//! The recorded contract is OMP's `rules/auth/zai-coding-plan.kdl`
//! (`0133f7ff`) with its key-minting hook
//! (`registry/oauth/zai.ts`): authorize
//! `https://chat.z.ai/api/oauth/authorize` with the ZCode-registered client
//! id and the manual callback `zcode://zai-auth/callback`, the non-RFC JSON
//! token exchange at `https://zcode.z.ai/api/v1/oauth/token`, then
//! business-login (`https://api.z.ai/api/auth/z/login`), customer info
//! (`/api/biz/customer/getCustomerInfo`), the default organization/project
//! selection, find-or-create of the key named [`KEY_NAME`], and the copy
//! leg that returns its secret. The stored bytes are a [`ZaiProfile`] whose
//! `token()` is `${apiKey}.${secretKey}`; the OAuth token is never the
//! model key.
//!
//! Every fetch is one bounded 30 s leg with no polling. An indeterminate
//! create/copy denies typed without a second mint, and enrollment is
//! create-only through [`CredentialStore::login`], so prior profile bytes
//! stay byte-identical on every denial. The PAYG origin is never admitted
//! or substituted.

use super::login_common::{self, BindingError, Body, CommonError};
use super::{CredentialStore, ProviderError, is_loopback_url, transport};
use crate::config::{Config, ConnKind};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// The recorded authorize leg the operator opens.
pub const AUTHORIZE_URL: &str = "https://chat.z.ai/api/oauth/authorize";

/// The recorded JSON token exchange.
pub const TOKEN_URL: &str = "https://zcode.z.ai/api/v1/oauth/token";

/// The recorded business API root — the coding-plan surface, never the PAYG
/// root.
pub const BIZ_BASE: &str = "https://api.z.ai";

/// The recorded manual callback. No local listener is bound.
pub const CALLBACK_URL: &str = "zcode://zai-auth/callback";

/// The recorded ZCode-registered OAuth client.
pub const CLIENT_ID: &str = "client_P8X5CMWmlaRO9gyO-KSqtg";

/// Rivect's own key name: sign-in never mutates another client's key.
pub const KEY_NAME: &str = "rivect";

/// The canonical profile name the alias stores under.
pub const PROFILE: &str = "zai";

/// One fetch's whole budget, shared by connect, request and read.
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(30);

// The test-only whole-leg budget: a case can shrink the ceiling without
// changing the recorded product value, so a stalled peer proves each leg
// applies its own bound.
#[cfg(test)]
thread_local! {
    static TEST_FETCH_TIMEOUT: std::cell::Cell<Option<Duration>> =
        const { std::cell::Cell::new(None) };
    static APPLIED_LEG_BUDGET: std::cell::Cell<Option<Duration>> =
        const { std::cell::Cell::new(None) };
}

/// The budget every leg actually passes to the client and the body reader.
fn leg_timeout() -> Duration {
    #[cfg(test)]
    {
        TEST_FETCH_TIMEOUT.with(|slot| slot.get().unwrap_or(FETCH_TIMEOUT))
    }
    #[cfg(not(test))]
    {
        FETCH_TIMEOUT
    }
}

#[cfg(test)]
fn set_test_fetch_timeout(timeout: Option<Duration>) {
    TEST_FETCH_TIMEOUT.with(|slot| slot.set(timeout));
}

/// Records the budget handed to the transport seam, so a case observes the
/// applied value and not only its effect.
fn applied_budget(timeout: Duration) -> Duration {
    #[cfg(test)]
    APPLIED_LEG_BUDGET.with(|slot| slot.set(Some(timeout)));
    timeout
}

/// The recorded endpoints. Production callers pass [`ZaiEndpoints::recorded`];
/// tests pass a loopback peer. The override is not a config surface, and a
/// non-loopback endpoint is admitted only when it is the recorded URL.
#[derive(Debug, Clone)]
pub struct ZaiEndpoints {
    authorize: String,
    token: String,
    biz_base: String,
}

impl ZaiEndpoints {
    /// One endpoint set for the recorded contract or a loopback peer.
    #[must_use]
    pub fn new(authorize: &str, token: &str, biz_base: &str) -> Self {
        Self {
            authorize: authorize.to_string(),
            token: token.to_string(),
            biz_base: biz_base.to_string(),
        }
    }

    /// The recorded production endpoints.
    #[must_use]
    pub fn recorded() -> Self {
        Self::new(AUTHORIZE_URL, TOKEN_URL, BIZ_BASE)
    }
}

/// One in-flight sign-in: the URL the operator opens, the UUID state the
/// callback must echo, the endpoints and the cancellation flag. No secret is
/// minted before the exchange, so `Debug` carries only the public leg.
pub struct LoginSession {
    authorize_url: String,
    state: String,
    endpoints: ZaiEndpoints,
    cancelled: AtomicBool,
}

impl fmt::Debug for LoginSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoginSession")
            .field("authorize_url", &self.authorize_url)
            .field("state", &self.state)
            .finish()
    }
}

impl LoginSession {
    /// The recorded authorize URL to open.
    #[must_use]
    pub fn authorize_url(&self) -> &str {
        &self.authorize_url
    }

    /// The UUID state the callback must echo.
    #[must_use]
    pub fn state(&self) -> &str {
        &self.state
    }

    /// Stops the login before its next leg. A leg already in flight finishes
    /// under its own 30 s bound; no later leg runs and nothing is stored.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    /// Whether [`Self::cancel`] has stopped this login.
    #[must_use]
    pub fn cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

/// Builds one sign-in leg from OS entropy: a UUID v4 state and the recorded
/// authorize URL with no PKCE, matching the recorded non-PKCE request.
///
/// # Errors
/// [`LoginError::EndpointNotRecorded`] for a foreign endpoint or a business
/// base outside the recorded root; [`LoginError::Entropy`] when the platform
/// entropy source fails.
pub fn begin_login(endpoints: &ZaiEndpoints) -> Result<LoginSession, LoginError> {
    admit_endpoints(endpoints)?;
    let state = login_common::random_uuid()?;
    let authorize_url = format!(
        "{}?client_id={}&response_type=code&redirect_uri={}&state={}",
        endpoints.authorize,
        login_common::encode_component(CLIENT_ID),
        login_common::encode_component(CALLBACK_URL),
        login_common::encode_component(&state),
    );
    Ok(LoginSession {
        authorize_url,
        state,
        endpoints: endpoints.clone(),
        cancelled: AtomicBool::new(false),
    })
}

/// Completes one sign-in: verifies the callback's origin and state, exchanges
/// the code, resolves the default organization/project, finds or creates the
/// [`KEY_NAME`] key, copies its secret and publishes a [`ZaiProfile`] whose
/// `token()` is `${apiKey}.${secretKey}` at the connection's declared scope.
///
/// The connection must be a declared `api_key` row whose reference names the
/// canonical [`PROFILE`]; any other profile is refused before a request, so
/// another profile's bytes are never touched. Enrollment is create-only: an
/// occupied scope denies and leaves its prior bytes byte-identical. The
/// sequence is one ordered walk — token, business login, customer, key list,
/// create when absent, copy — with 30 s per fetch and no polling.
///
/// # Errors
/// [`LoginError::NotApiKey`]/[`LoginError::ProfileNotCanonical`] before any
/// request; [`LoginError::Cancelled`]/[`LoginError::CallbackNotRecorded`]/
/// [`LoginError::StateMismatch`] for the callback negatives;
/// [`LoginError::ExchangeRefused`]/[`LoginError::ProviderRefused`] for a
/// refusing peer; [`LoginError::KeyIssuanceIndeterminate`] after a create
/// whose outcome is unknown (never retried); [`LoginError::ForeignKeyRefused`]
/// for material naming another client's key; [`LoginError::KeyListingRefused`]/
/// [`LoginError::KeyCopyRefused`] for those legs; and the response, store and
/// serialization denials this module documents.
pub fn complete_login(
    config: &Config,
    connection: &str,
    session: &LoginSession,
    callback: &str,
    store: &dyn CredentialStore,
) -> Result<String, LoginError> {
    let reference = login_common::api_key_reference(config, connection)?;
    if reference.profile() != PROFILE {
        return Err(LoginError::ProfileNotCanonical {
            profile: reference.profile().to_string(),
        });
    }
    check_cancelled(session)?;
    let code = verify_callback(callback, session)?;
    check_cancelled(session)?;
    let oauth_token = exchange(connection, session, &code)?;
    check_cancelled(session)?;
    let biz_token = business_login(connection, session, &oauth_token)?;
    check_cancelled(session)?;
    let (organization, project) = customer_project(connection, session, &biz_token)?;
    let keys_url = format!(
        "{}/api/biz/v1/organization/{}/projects/{}/api_keys",
        session.endpoints.biz_base.trim_end_matches('/'),
        login_common::encode_component(&organization),
        login_common::encode_component(&project),
    );
    check_cancelled(session)?;
    let listed = list_keys(connection, &keys_url, &biz_token)?;
    check_cancelled(session)?;
    let api_key = match find_existing_key(&listed)? {
        Some(api_key) => api_key,
        None => create_key(connection, &keys_url, &biz_token)?,
    };
    check_cancelled(session)?;
    let secret_key = copy_secret(connection, &keys_url, &biz_token, &api_key)?;
    check_cancelled(session)?;
    let profile = ZaiProfile {
        api_key,
        secret_key,
    };
    store.login(&reference, &serialize(&profile)?)?;
    Ok(reference.profile().to_string())
}

/// Reads the canonical `zai` profile from the bytes the producer stored.
/// Parsing is strict: an unknown field, a malformed document or a credential
/// half outside the recorded form is a typed denial, never a guess.
///
/// # Errors
/// [`LoginError::StoredCredentialMalformed`] when the bytes are not a
/// canonical `zai` profile.
pub fn read_zai(bytes: &[u8]) -> Result<ZaiProfile, LoginError> {
    let profile: ZaiProfile =
        serde_json::from_slice(bytes).map_err(|cause| LoginError::StoredCredentialMalformed {
            reason: login_common::malformed_reason(&cause),
        })?;
    if !admitted_half(&profile.api_key) || !admitted_half(&profile.secret_key) {
        return Err(LoginError::StoredCredentialMalformed {
            reason: "a credential half outside the recorded form",
        });
    }
    Ok(profile)
}

/// The canonical scoped Z.AI profile: the durable key id and secret. Both
/// halves are redacted in `Debug`, and unknown fields deny.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZaiProfile {
    api_key: String,
    secret_key: String,
}

impl fmt::Debug for ZaiProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ZaiProfile")
            .field("api_key", &login_common::redacted(&self.api_key))
            .field("secret_key", &login_common::redacted(&self.secret_key))
            .finish()
    }
}

impl ZaiProfile {
    /// The canonical `${apiKey}.${secretKey}` bearer the consumer sends.
    /// The OAuth token is never this value.
    #[must_use]
    pub fn token(&self) -> String {
        format!("{}.{}", self.api_key, self.secret_key)
    }
}

/// One sign-in lifecycle failure. Display text is English and lowercase, and
/// never carries a token, a secret, a provider message or the callback query.
#[derive(Debug, thiserror::Error)]
pub enum LoginError {
    /// The platform entropy source could not fill the state.
    #[error("entropy source is unavailable: {cause}")]
    Entropy { cause: getrandom::Error },
    /// The system clock is before the Unix epoch.
    #[error("system clock is before the unix epoch: {cause}")]
    Clock { cause: std::time::SystemTimeError },
    /// The endpoint is neither its recorded URL nor an admitted loopback
    /// peer. `origin` is the canonical scheme/host class — never the raw URL.
    #[error("z.ai endpoint origin {origin} is outside the recorded contract")]
    EndpointNotRecorded { origin: String },
    /// The pasted callback is not the recorded callback origin and path.
    #[error("z.ai callback {origin} is outside the recorded callback")]
    CallbackNotRecorded { origin: String },
    /// The callback state is not the one this login leg minted.
    #[error("the z.ai callback state does not match this login")]
    StateMismatch,
    /// The browser answered a cancellation instead of a code.
    #[error("the z.ai login was cancelled at the callback")]
    Cancelled,
    /// The canonical connection the operator must declare is absent.
    #[error("connection {connection} is not declared")]
    ConnectionMissing { connection: String },
    /// The login path writes only an `api_key` binding.
    #[error("connection {connection} is {kind}, not an api key")]
    NotApiKey { connection: String, kind: ConnKind },
    /// The binding names a profile other than the canonical `zai`.
    #[error("the login is bound to profile {profile}, not the canonical zai profile")]
    ProfileNotCanonical { profile: String },
    /// The token endpoint answered a non-2xx status.
    #[error("the z.ai token endpoint answered with http status {status}")]
    ExchangeRefused { status: u16 },
    /// A business endpoint answered a non-2xx status.
    #[error("the z.ai business api answered with http status {status}")]
    ProviderRefused { status: u16 },
    /// The key list answered a non-2xx status.
    #[error("the z.ai key list answered with http status {status}")]
    KeyListingRefused { status: u16 },
    /// The key copy answered a non-2xx status.
    #[error("the z.ai key copy answered with http status {status}")]
    KeyCopyRefused { status: u16 },
    /// A reply omitted a recorded member.
    #[error("the z.ai response carries no {field}")]
    MissingField { field: &'static str },
    /// The recorded reply envelope reported a failure.
    #[error("the z.ai {operation} was refused")]
    EnvelopeDenied { operation: &'static str },
    /// The create request's outcome is unknown: it is never retried, so a
    /// second key is never minted.
    #[error("the z.ai key issuance outcome is indeterminate; the login does not retry")]
    KeyIssuanceIndeterminate {
        #[source]
        cause: Box<dyn std::error::Error + Send + Sync>,
    },
    /// The peer named or copied a key other than Rivect's own.
    #[error("the z.ai key response names a key rivect does not own")]
    ForeignKeyRefused,
    /// A reply exceeded the bounded response size.
    #[error("the z.ai response exceeds the byte bound")]
    ResponseTooLarge,
    /// A reply was not the JSON object the contract records.
    #[error("the z.ai endpoint answered malformed json")]
    MalformedResponse {
        #[source]
        cause: serde_json::Error,
    },
    /// The material is not a canonical `zai` profile. serde's own diagnostic
    /// can quote the stored bytes, so only its class is kept.
    #[error("the stored credential is not a z.ai profile: {reason}")]
    StoredCredentialMalformed { reason: &'static str },
    /// The in-memory profile could not be encoded for the store.
    #[error("the z.ai profile could not be serialized")]
    Serialization {
        #[source]
        cause: serde_json::Error,
    },
    /// The credential seam's typed denial — an occupied scope or a store
    /// condition.
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

/// One bounded reply: a refusal carries only its status, so a peer's error
/// body is never parsed or rendered.
enum Reply {
    Refused(u16),
    Json(Value),
}

fn admit_endpoints(endpoints: &ZaiEndpoints) -> Result<(), LoginError> {
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
    if !admitted_base(&endpoints.biz_base) {
        return Err(LoginError::EndpointNotRecorded {
            origin: login_common::endpoint_origin(&endpoints.biz_base),
        });
    }
    Ok(())
}

/// The recorded business root or a loopback base with no path: a PAYG base
/// carries `/coding/paas` and never passes.
fn admitted_base(endpoint: &str) -> bool {
    if endpoint.trim_end_matches('/') == BIZ_BASE {
        return true;
    }
    let Ok(url) = reqwest::Url::parse(endpoint) else {
        return false;
    };
    url.scheme() == "http"
        && is_loopback_url(&url)
        && url.username().is_empty()
        && url.password().is_none()
        && (url.path() == "/" || url.path().is_empty())
        && url.query().is_none()
        && url.fragment().is_none()
}

fn check_cancelled(session: &LoginSession) -> Result<(), LoginError> {
    if session.cancelled() {
        return Err(LoginError::Cancelled);
    }
    Ok(())
}

fn exchange(connection: &str, session: &LoginSession, code: &str) -> Result<String, LoginError> {
    let body = json!({
        "provider": "zai",
        "code": code,
        "redirect_uri": CALLBACK_URL,
        "state": session.state,
    });
    let reply = match post_json(connection, &session.endpoints.token, &body, None)? {
        Reply::Json(reply) => reply,
        Reply::Refused(status) => return Err(LoginError::ExchangeRefused { status }),
    };
    let data = unwrapped(&reply, "token exchange")?;
    data.get("zai")
        .and_then(|zai| zai.get("access_token"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(str::to_string)
        .ok_or(LoginError::MissingField {
            field: "access_token",
        })
}

fn business_login(
    connection: &str,
    session: &LoginSession,
    oauth_token: &str,
) -> Result<String, LoginError> {
    let endpoint = format!(
        "{}/api/auth/z/login",
        session.endpoints.biz_base.trim_end_matches('/')
    );
    let reply = match post_json(
        connection,
        &endpoint,
        &json!({ "token": oauth_token }),
        None,
    )? {
        Reply::Json(reply) => reply,
        Reply::Refused(status) => return Err(LoginError::ProviderRefused { status }),
    };
    let data = unwrapped(&reply, "business login")?;
    ["access_token", "accessToken"]
        .iter()
        .find_map(|field| value_member(&data, field))
        .ok_or(LoginError::MissingField {
            field: "access_token",
        })
}

fn customer_project(
    connection: &str,
    session: &LoginSession,
    biz_token: &str,
) -> Result<(String, String), LoginError> {
    let endpoint = format!(
        "{}/api/biz/customer/getCustomerInfo",
        session.endpoints.biz_base.trim_end_matches('/')
    );
    let reply = match fetch_json(connection, &endpoint, biz_token)? {
        Reply::Json(reply) => reply,
        Reply::Refused(status) => return Err(LoginError::ProviderRefused { status }),
    };
    let data = unwrapped(&reply, "customer lookup")?;
    let organizations: &[Value] = data
        .get("organizations")
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice);
    let organization = default_entry(organizations).ok_or(LoginError::MissingField {
        field: "organizationId",
    })?;
    let organization_id =
        value_member(organization, "organizationId").ok_or(LoginError::MissingField {
            field: "organizationId",
        })?;
    let projects: &[Value] = organization
        .get("projects")
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice);
    let project = default_entry(projects).ok_or(LoginError::MissingField { field: "projectId" })?;
    let project_id = value_member(project, "projectId")
        .ok_or(LoginError::MissingField { field: "projectId" })?;
    Ok((organization_id, project_id))
}

fn list_keys(connection: &str, keys_url: &str, biz_token: &str) -> Result<Value, LoginError> {
    match fetch_json(connection, keys_url, biz_token)? {
        Reply::Json(reply) => Ok(reply),
        Reply::Refused(status) => Err(LoginError::KeyListingRefused { status }),
    }
}

/// The key named [`KEY_NAME`], or `None` so the caller creates it. Foreign
/// entries are never selected, copied or mutated.
fn find_existing_key(reply: &Value) -> Result<Option<String>, LoginError> {
    let data = unwrapped(reply, "api key list")?;
    let rows = key_rows(&data);
    let Some(row) = rows
        .iter()
        .find(|row| row.get("name").and_then(Value::as_str) == Some(KEY_NAME))
    else {
        return Ok(None);
    };
    value_member(row, "apiKey")
        .map(Some)
        .ok_or(LoginError::MissingField { field: "apiKey" })
}

fn create_key(connection: &str, keys_url: &str, biz_token: &str) -> Result<String, LoginError> {
    let reply = match post_json(
        connection,
        keys_url,
        &json!({ "name": KEY_NAME }),
        Some(biz_token),
    )
    .map_err(indeterminate_leg)?
    {
        Reply::Json(reply) => reply,
        Reply::Refused(status) => return Err(indeterminate_status(status)),
    };
    let data = unwrapped(&reply, "api key create").map_err(indeterminate)?;
    match data.get("name").and_then(Value::as_str) {
        Some(KEY_NAME) => {}
        Some(_other) => return Err(LoginError::ForeignKeyRefused),
        None => return Err(indeterminate_message("the create reply names no key")),
    }
    value_member(&data, "apiKey")
        .ok_or_else(|| indeterminate_message("the create reply carries no apiKey"))
}

fn copy_secret(
    connection: &str,
    keys_url: &str,
    biz_token: &str,
    api_key: &str,
) -> Result<String, LoginError> {
    let endpoint = format!(
        "{keys_url}/copy/{}",
        login_common::encode_component(api_key)
    );
    let reply = match fetch_json(connection, &endpoint, biz_token)? {
        Reply::Json(reply) => reply,
        Reply::Refused(status) => return Err(LoginError::KeyCopyRefused { status }),
    };
    let data = unwrapped(&reply, "api key copy")?;
    if let Some(copied) = data.get("apiKey").and_then(Value::as_str)
        && copied != api_key
    {
        return Err(LoginError::ForeignKeyRefused);
    }
    value_member(&data, "secretKey").ok_or(LoginError::MissingField { field: "secretKey" })
}

/// One bounded POST. The reply's status is decided before its body is read,
/// so a refusal never parses provider text.
fn post_json(
    connection: &str,
    endpoint: &str,
    body: &Value,
    bearer: Option<&str>,
) -> Result<Reply, CommonError> {
    let authorization = bearer.map(|token| format!("Bearer {token}"));
    let mut headers: Vec<(&str, &str)> = Vec::new();
    if let Some(value) = authorization.as_deref() {
        headers.push(("Authorization", value));
    }
    let timeout = applied_budget(leg_timeout());
    let (mut response, started) =
        login_common::post(connection, endpoint, timeout, Body::Json(body), &headers)?;
    if !response.status().is_success() {
        return Ok(Reply::Refused(response.status().as_u16()));
    }
    let body = login_common::read_body(connection, &mut response, timeout, started)?;
    Ok(Reply::Json(login_common::parse_json(&body)?))
}

/// One bounded GET under the same rule.
fn fetch_json(connection: &str, endpoint: &str, bearer: &str) -> Result<Reply, CommonError> {
    let timeout = applied_budget(leg_timeout());
    let started = Instant::now();
    let client = login_common::client(connection, timeout)?;
    let mut response = client
        .get(endpoint)
        .header("Authorization", format!("Bearer {bearer}"))
        .send()
        .map_err(|cause| CommonError::Transport(transport(connection, cause)))?;
    if !response.status().is_success() {
        return Ok(Reply::Refused(response.status().as_u16()));
    }
    let body = login_common::read_body(connection, &mut response, timeout, started)?;
    Ok(Reply::Json(login_common::parse_json(&body)?))
}

/// The `{ code, msg, data, success }` envelope: `code` 0/200 and no
/// `success: false` admits `data`; anything else denies without rendering
/// the peer's message.
fn unwrapped(reply: &Value, operation: &'static str) -> Result<Value, LoginError> {
    let Some(object) = reply.as_object() else {
        return Ok(reply.clone());
    };
    if !object.contains_key("code") && !object.contains_key("success") {
        return Ok(reply.clone());
    }
    let refused = object.get("success").and_then(Value::as_bool) == Some(false)
        || object.get("code").is_some_and(|code| !admitted_code(code));
    if refused {
        return Err(LoginError::EnvelopeDenied { operation });
    }
    Ok(object.get("data").cloned().unwrap_or_else(|| reply.clone()))
}

fn admitted_code(code: &Value) -> bool {
    match code {
        Value::Null => true,
        Value::Number(number) => number
            .as_u64()
            .is_some_and(|value| value == 0 || value == 200),
        Value::String(text) => text == "0" || text == "200",
        _ => false,
    }
}

fn default_entry(entries: &[Value]) -> Option<&Value> {
    entries
        .iter()
        .find(|entry| entry.get("isDefault").and_then(Value::as_bool) == Some(true))
        .or_else(|| entries.first())
}

fn key_rows(reply: &Value) -> &[Value] {
    if let Some(rows) = reply.as_array() {
        return rows;
    }
    for field in ["list", "keys", "apiKeys", "records"] {
        if let Some(rows) = reply.get(field).and_then(Value::as_array) {
            return rows;
        }
    }
    &[]
}

fn value_member(value: &Value, field: &str) -> Option<String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|member| !member.is_empty())
        .map(str::to_string)
}

fn admitted_half(value: &str) -> bool {
    !value.is_empty() && value.trim() == value && !value.chars().any(char::is_control)
}

fn serialize(profile: &ZaiProfile) -> Result<Vec<u8>, LoginError> {
    serde_json::to_vec(profile).map_err(|cause| LoginError::Serialization { cause })
}

fn indeterminate(cause: LoginError) -> LoginError {
    LoginError::KeyIssuanceIndeterminate {
        cause: Box::new(cause),
    }
}

fn indeterminate_leg(cause: CommonError) -> LoginError {
    indeterminate(LoginError::from(cause))
}

fn indeterminate_status(status: u16) -> LoginError {
    LoginError::KeyIssuanceIndeterminate {
        cause: Box::new(std::io::Error::other(format!(
            "the create request answered http status {status}"
        ))),
    }
}

fn indeterminate_message(message: &'static str) -> LoginError {
    LoginError::KeyIssuanceIndeterminate {
        cause: Box::new(std::io::Error::other(message)),
    }
}

/// The pasted callback: the recorded `zcode://zai-auth/callback` URL, or the
/// `code#state` form the manual input offers. Duplicate members keep the
/// first, like the recorded producer.
fn verify_callback(callback: &str, session: &LoginSession) -> Result<String, LoginError> {
    let (code, state, cancelled) = if callback.contains("://") {
        let url =
            reqwest::Url::parse(callback).map_err(|_parse| LoginError::CallbackNotRecorded {
                origin: login_common::endpoint_origin(callback),
            })?;
        if url.scheme() != "zcode"
            || url.host_str() != Some("zai-auth")
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
        (code, state, cancelled)
    } else {
        let (code, state) = callback.split_once('#').ok_or(LoginError::StateMismatch)?;
        (Some(code.to_string()), Some(state.to_string()), false)
    };
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
    fn the_recorded_endpoints_and_key_name_are_pinned() {
        assert_eq!(AUTHORIZE_URL, "https://chat.z.ai/api/oauth/authorize");
        assert_eq!(TOKEN_URL, "https://zcode.z.ai/api/v1/oauth/token");
        assert_eq!(BIZ_BASE, "https://api.z.ai");
        assert_eq!(CALLBACK_URL, "zcode://zai-auth/callback");
        assert_eq!(KEY_NAME, "rivect");
        assert_eq!(PROFILE, "zai");
    }

    #[test]
    fn the_envelope_admits_both_recorded_success_codes() {
        assert!(unwrapped(&json!({"code": 0, "data": 1}), "leg").is_ok());
        assert!(unwrapped(&json!({"code": 200, "success": true}), "leg").is_ok());
        assert!(unwrapped(&json!({"code": "200"}), "leg").is_ok());
        assert!(unwrapped(&json!({"code": 1}), "leg").is_err());
        assert!(unwrapped(&json!({"success": false}), "leg").is_err());
        assert_eq!(
            unwrapped(&json!({"value": 1}), "leg").expect("a bare body"),
            json!({"value": 1})
        );
    }

    #[test]
    fn the_default_entry_prefers_the_flagged_element() {
        let entries = [
            json!({"id": "first"}),
            json!({"id": "default", "isDefault": true}),
        ];
        assert_eq!(
            default_entry(&entries).and_then(|entry| entry.get("id")),
            Some(&json!("default"))
        );
        assert_eq!(
            default_entry(&[json!({"id": "only"})]).and_then(|entry| entry.get("id")),
            Some(&json!("only"))
        );
        assert!(default_entry(&[]).is_none());
    }

    #[test]
    fn the_reader_denies_foreign_material() {
        assert!(read_zai(br#"{"api_key":"a","secret_key":"b"}"#).is_ok());
        for foreign in [
            br#"{"api_key":"a","secret_key":"b","extra":1}"#.as_slice(),
            br#"{"api_key":"","secret_key":"b"}"#.as_slice(),
            br#"{"api_key":" a","secret_key":"b"}"#.as_slice(),
            br#"{"api_key":"a"}"#.as_slice(),
            b"not json".as_slice(),
        ] {
            let error = read_zai(foreign).expect_err("foreign material denies");
            assert!(
                matches!(error, LoginError::StoredCredentialMalformed { .. }),
                "{error}"
            );
        }
    }

    /// The first request line a stalled peer accepted, and the leg's denial.
    fn stalled_leg(
        drive: fn(&LoginSession, &str) -> Result<(), LoginError>,
    ) -> (Vec<String>, LoginError) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind a stalled peer");
        listener.set_nonblocking(true).expect("nonblocking peer");
        let base = format!("http://{}", listener.local_addr().expect("peer address"));
        let stop = AtomicBool::new(false);
        std::thread::scope(|scope| {
            let server = scope.spawn(|| {
                let mut held = Vec::new();
                let mut lines = Vec::new();
                while !stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((mut stream, _address)) => {
                            stream
                                .set_read_timeout(Some(Duration::from_secs(5)))
                                .expect("peer read timeout");
                            if let Some(line) = request_line(&mut stream) {
                                lines.push(line);
                            }
                            held.push(stream);
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::park_timeout(Duration::from_millis(5));
                        }
                        Err(_error) => break,
                    }
                }
                drop(held);
                lines
            });
            let endpoints = ZaiEndpoints::new(
                &format!("{base}/api/oauth/authorize"),
                &format!("{base}/api/v1/oauth/token"),
                &base,
            );
            let session = begin_login(&endpoints).expect("the login begins");
            let keys_url = format!("{base}/api/biz/v1/organization/org-1/projects/proj-1/api_keys");
            let error = drive(&session, &keys_url).expect_err("the stalled leg denies");
            stop.store(true, Ordering::SeqCst);
            let lines = server.join().expect("the stalled peer joins");
            (lines, error)
        })
    }

    fn request_line(stream: &mut std::net::TcpStream) -> Option<String> {
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            let read = std::io::Read::read(stream, &mut chunk).ok()?;
            if read == 0 {
                return None;
            }
            buffer.extend_from_slice(&chunk[..read]);
            if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
                return String::from_utf8_lossy(&buffer[..position])
                    .lines()
                    .next()
                    .map(str::to_string);
            }
        }
    }

    /// Shrinks the per-fetch budget for one case and restores the recorded
    /// product value on drop, so a failing case cannot leak the override.
    struct FetchBudget;

    impl FetchBudget {
        fn set(timeout: Duration) -> Self {
            set_test_fetch_timeout(Some(timeout));
            Self
        }
    }

    impl Drop for FetchBudget {
        fn drop(&mut self) {
            set_test_fetch_timeout(None);
        }
    }

    fn assert_timed_out(error: &LoginError) {
        let error = match error {
            LoginError::KeyIssuanceIndeterminate { cause } => cause
                .downcast_ref::<LoginError>()
                .expect("the create keeps its typed cause"),
            other => other,
        };
        assert!(
            matches!(
                error,
                LoginError::Provider(ProviderError::Transport { cause, .. })
                    if cause.class() == crate::providers::TransportClass::Timeout
            ),
            "expected a bounded transport timeout, got {error}"
        );
    }

    #[test]
    fn every_fetch_leg_applies_its_own_budget() {
        assert_eq!(FETCH_TIMEOUT, Duration::from_secs(30));
        assert_eq!(leg_timeout(), FETCH_TIMEOUT);
        // Wide enough that a starved peer thread still accepts before the leg
        // times out; the applied-budget assertion, not the clock, discriminates.
        let budget = Duration::from_secs(1);
        let _budget = FetchBudget::set(budget);

        type Leg = fn(&LoginSession, &str) -> Result<(), LoginError>;
        let legs: [(&str, Leg); 6] = [
            ("POST /api/v1/oauth/token HTTP/1.1", |session, _keys| {
                exchange("zai", session, "auth-code").map(|_token| ())
            }),
            ("POST /api/auth/z/login HTTP/1.1", |session, _keys| {
                business_login("zai", session, "oauth-access-token").map(|_token| ())
            }),
            (
                "GET /api/biz/customer/getCustomerInfo HTTP/1.1",
                |session, _keys| customer_project("zai", session, "biz-token").map(|_selection| ()),
            ),
            (
                "GET /api/biz/v1/organization/org-1/projects/proj-1/api_keys HTTP/1.1",
                |_session, keys| list_keys("zai", keys, "biz-token").map(|_reply| ()),
            ),
            (
                "POST /api/biz/v1/organization/org-1/projects/proj-1/api_keys HTTP/1.1",
                |_session, keys| create_key("zai", keys, "biz-token").map(|_key| ()),
            ),
            (
                "GET /api/biz/v1/organization/org-1/projects/proj-1/api_keys/copy/created-key HTTP/1.1",
                |_session, keys| {
                    copy_secret("zai", keys, "biz-token", "created-key").map(|_secret| ())
                },
            ),
        ];
        for (expected, drive) in legs {
            APPLIED_LEG_BUDGET.with(|slot| slot.set(None));
            let (lines, error) = stalled_leg(drive);
            assert_eq!(
                APPLIED_LEG_BUDGET.with(|slot| slot.get()),
                Some(budget),
                "the leg hands the injected budget to the transport"
            );
            assert_timed_out(&error);
            assert_eq!(
                lines,
                vec![expected.to_string()],
                "the stalled request is the bounded leg"
            );
        }
    }
}
