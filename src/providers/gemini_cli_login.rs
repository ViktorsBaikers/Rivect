//! Gemini CLI Code Assist project-profile producer: the explicit login leg,
//! the recorded discovery/onboarding calls and the canonical tier/profile.
//! Library-level — no CLI verb is added.
//!
//! The recorded contract is the project discovery the Gemini CLI makes after
//! sign-in: `POST {origin}/v1internal:loadCodeAssist` carries the bearer and
//! the optional explicit project and answers the current tier, the bound
//! project and the allowed tiers; when no current tier exists,
//! `POST {origin}/v1internal:onboardUser` answers a long-running operation
//! and `GET {origin}/v1internal/{name}` polls it. The poll is bounded by
//! [`OnboardingBudget::recorded`] — 24 attempts at 5 s (DEC-009) — and a
//! truthy `done` terminates it; a non-OK poll or leg denies typed.
//!
//! A current tier returns its bound project; a personal account without one
//! falls back to [`ProjectSource`], and a Workspace/Standard tier requires
//! that explicit project. A `SECURITY_POLICY_VIOLATED` (VPC-SC) load answer
//! denies typed with or without an explicit project — no tier is inferred.
//! A tier entry may carry no id: a default entry without one selects the
//! free tier, an absent default selects the legacy tier, and a bound current
//! tier without an id stores the empty tier string, which documents only
//! that upstream id's absence and is never an entitlement. The source
//! operation schema carries no `error` field, so a finished operation without
//! a project is a project-bound denial rather than a retry.
//!
//! Enrollment is create-only through [`CredentialStore::login`]: an occupied
//! scope or a refused store operation denies and leaves the prior bytes
//! untouched. The profile is written only after the project is bound, and a
//! login cancelled before the write — including one cancelled while the
//! bounded operation runs — publishes nothing. [`refresh_profile`] replaces
//! the token only, preserving the project and tier. The access token is
//! redacted in the session's and the profile's `Debug` and never enters an
//! error or a diagnostic.

use super::login_common::{self, BindingError, Body, CommonError};
use super::{CredentialStore, ProviderError, SecretRef};
use crate::config::{Config, ConnKind};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// The recorded Gemini CLI Code Assist origin.
pub const CODE_ASSIST_ORIGIN: &str = "https://cloudcode-pa.googleapis.com";

/// The recorded project-discovery poll cap (DEC-009).
pub const POLL_MAX_ATTEMPTS: u32 = 24;

/// The recorded pause between two project-discovery polls (DEC-009).
pub const POLL_INTERVAL: Duration = Duration::from_secs(5);

/// The recorded `v1internal` surface the onboarding calls ride.
const API_PATH: &str = "v1internal";

/// The recorded plugin identity every discovery and onboarding body carries.
const PLUGIN_TYPE: &str = "GEMINI";

const IDE_TYPE: &str = "IDE_UNSPECIFIED";
const PLATFORM: &str = "PLATFORM_UNSPECIFIED";

/// The recorded tier ids the project rule reads.
const FREE_TIER: &str = "free-tier";
const LEGACY_TIER: &str = "legacy-tier";

/// The per-fetch bound of the post-callback provisioning calls.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// The recorded project-discovery poll bounds: 24 attempts at 5 s.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OnboardingBudget {
    /// The number of operation polls before the wait is denied.
    pub max_attempts: u32,
    /// The pause before a retried poll.
    pub poll_interval: Duration,
}

impl OnboardingBudget {
    /// The recorded budget: 24 attempts at 5 s.
    #[must_use]
    pub const fn recorded() -> Self {
        Self {
            max_attempts: POLL_MAX_ATTEMPTS,
            poll_interval: POLL_INTERVAL,
        }
    }
}

impl Default for OnboardingBudget {
    fn default() -> Self {
        Self::recorded()
    }
}

/// The explicit project source: `GOOGLE_CLOUD_PROJECT` then
/// `GOOGLE_CLOUD_PROJECT_ID`. Production callers pass
/// [`ProjectSource::from_environment`]; tests name the project directly. The
/// override is not a config surface.
#[derive(Debug, Clone, Default)]
pub struct ProjectSource {
    /// The explicit project id, when the operator environment names one.
    pub project: Option<String>,
}

impl ProjectSource {
    /// The operator environment: the two recorded variable names, first
    /// present value wins.
    #[must_use]
    pub fn from_environment() -> Self {
        Self {
            project: project_from(
                &["GOOGLE_CLOUD_PROJECT", "GOOGLE_CLOUD_PROJECT_ID"],
                |name| std::env::var(name).ok(),
            ),
        }
    }
}

/// The recorded origin the onboarding calls reach. Production callers pass
/// [`CodeAssistEndpoints::recorded`]; tests pass a loopback peer. The
/// override is not a config surface.
#[derive(Debug, Clone)]
pub struct CodeAssistEndpoints {
    /// The Code Assist origin, without the `v1internal` path.
    pub code_assist: String,
}

impl CodeAssistEndpoints {
    /// The recorded production origin.
    #[must_use]
    pub fn recorded() -> Self {
        Self {
            code_assist: CODE_ASSIST_ORIGIN.to_string(),
        }
    }
}

/// One in-flight login: the operator's explicit access token, the endpoints,
/// the recorded wait and the explicit project source. `Debug` redacts the
/// token.
///
/// A session is single-use: [`complete_login`] takes it by reference, and
/// [`LoginSession::cancel`] makes every later completion publish nothing.
pub struct LoginSession {
    access_token: String,
    endpoints: CodeAssistEndpoints,
    budget: OnboardingBudget,
    project: Option<String>,
    cancelled: AtomicBool,
}

impl fmt::Debug for LoginSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoginSession")
            .field("access_token", &login_common::redacted(&self.access_token))
            .field("code_assist", &self.endpoints.code_assist)
            .field("budget", &self.budget)
            .field("project", &self.project)
            .field("cancelled", &self.is_cancelled())
            .finish()
    }
}

impl LoginSession {
    /// The recorded wait this session runs under.
    #[must_use]
    pub fn budget(&self) -> OnboardingBudget {
        self.budget
    }

    /// Cancels the login. A completion that has not written yet publishes
    /// nothing, and one that already wrote is untouched.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    /// Whether this session has been cancelled.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

/// Builds one login session from the operator environment under the recorded
/// poll budget.
///
/// # Errors
/// [`LoginError::MissingField`] for an empty or whitespace-only token;
/// [`LoginError::EndpointNotAdmitted`] for an origin outside the recorded
/// set and outside loopback.
pub fn begin_login(
    access_token: &str,
    endpoints: &CodeAssistEndpoints,
) -> Result<LoginSession, LoginError> {
    begin_login_with(
        access_token,
        endpoints,
        OnboardingBudget::recorded(),
        &ProjectSource::from_environment(),
    )
}

/// Builds one login session under an explicit budget and project source — the
/// offline proof's seam.
///
/// # Errors
/// [`begin_login`]'s contract.
pub fn begin_login_with(
    access_token: &str,
    endpoints: &CodeAssistEndpoints,
    budget: OnboardingBudget,
    project: &ProjectSource,
) -> Result<LoginSession, LoginError> {
    let access_token = non_blank(Some(access_token)).ok_or(LoginError::MissingField {
        field: "access_token",
    })?;
    admit_origin(&endpoints.code_assist)?;
    Ok(LoginSession {
        access_token: access_token.to_string(),
        endpoints: endpoints.clone(),
        budget,
        project: non_blank(project.project.as_deref()).map(str::to_string),
        cancelled: AtomicBool::new(false),
    })
}

/// Runs the recorded discovery/onboarding sequence and writes the
/// tier/project-bound profile at the connection's scoped reference through
/// [`CredentialStore::login`], which refuses an occupied scope.
///
/// # Errors
/// [`LoginError::ConnectionMissing`]/[`LoginError::NotApiKey`] for the
/// config binding; [`LoginError::Cancelled`] for a cancelled session;
/// [`LoginError::Rejected`] for a refusing leg;
/// [`LoginError::VpcScDenied`] for the recorded VPC-SC load answer;
/// [`LoginError::ProjectRequired`] when the tier needs an explicit project;
/// [`LoginError::ProjectUnbound`]/[`LoginError::ProvisioningTimedOut`] for
/// the operation's terminal checks; the reply, serialization and store
/// denials this module documents.
pub fn complete_login(
    config: &Config,
    connection: &str,
    session: &LoginSession,
    store: &dyn CredentialStore,
) -> Result<String, LoginError> {
    let reference = login_common::api_key_reference(config, connection)?;
    if session.is_cancelled() {
        return Err(LoginError::Cancelled);
    }
    let discovered = discover(connection, session)?;
    if session.is_cancelled() {
        return Err(LoginError::Cancelled);
    }
    let profile = CodeAssistProfile {
        access_token: session.access_token.clone(),
        project: discovered.project,
        tier: discovered.tier,
    };
    store.login(&reference, &serialize(&profile)?)?;
    Ok(reference.profile().to_string())
}

/// Replaces the stored profile's access token, preserving the project and
/// tier the login bound. A blank token or a foreign scope publishes nothing.
///
/// # Errors
/// [`LoginError::MissingField`] for an empty or whitespace-only token;
/// [`LoginError::StoredCredentialMalformed`] when the scope does not hold a
/// Code Assist profile; the [`LoginError::Provider`] store denial.
pub fn refresh_profile(
    store: &dyn CredentialStore,
    reference: &SecretRef,
    access_token: &str,
) -> Result<String, LoginError> {
    let access_token = non_blank(Some(access_token)).ok_or(LoginError::MissingField {
        field: "access_token",
    })?;
    let stored = read_profile(store, reference)?;
    let updated = CodeAssistProfile {
        access_token: access_token.to_string(),
        project: stored.project,
        tier: stored.tier,
    };
    store.refresh(reference, &serialize(&updated)?)?;
    Ok(reference.profile().to_string())
}

/// Reads the Code Assist profile at a scoped reference — the seam the
/// CloudCode adapter consumes the producer artifact through. Parsing is
/// strict: foreign material is a typed denial, never a guess.
///
/// # Errors
/// The [`LoginError::Provider`] store denial, and
/// [`LoginError::StoredCredentialMalformed`] when the material is not a Code
/// Assist profile.
pub fn read_profile(
    store: &dyn CredentialStore,
    reference: &SecretRef,
) -> Result<CodeAssistProfile, LoginError> {
    let bytes = store.resolve(reference)?;
    serde_json::from_slice(&bytes).map_err(|cause| LoginError::StoredCredentialMalformed {
        reason: login_common::malformed_reason(&cause),
    })
}

/// The canonical scoped Code Assist profile: the bearer, the bound project
/// and the discovered tier. The token is redacted in `Debug`; the project and
/// tier are scope identifiers and render verbatim, and unknown fields deny.
/// An empty tier means the upstream current tier carried no id: it confers
/// no tier entitlement.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodeAssistProfile {
    access_token: String,
    project: String,
    tier: String,
}

impl fmt::Debug for CodeAssistProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CodeAssistProfile")
            .field("access_token", &login_common::redacted(&self.access_token))
            .field("project", &self.project)
            .field("tier", &self.tier)
            .finish()
    }
}

impl CodeAssistProfile {
    /// The bearer the CloudCode adapter sends.
    #[must_use]
    pub fn access_token(&self) -> &str {
        &self.access_token
    }

    /// The project the account is bound to.
    #[must_use]
    pub fn project(&self) -> &str {
        &self.project
    }

    /// The discovered tier the adapter applies its project rule to. An empty
    /// string means the upstream current tier carried no id; it confers no
    /// tier entitlement and selects no tier rule.
    #[must_use]
    pub fn tier(&self) -> &str {
        &self.tier
    }
}

/// The onboarding call a denial names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Leg {
    /// The `loadCodeAssist` discovery call.
    Identity,
    /// The `onboardUser` call.
    Onboarding,
    /// The operation poll.
    Operation,
}

impl fmt::Display for Leg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Identity => "identity",
            Self::Onboarding => "onboarding",
            Self::Operation => "operation",
        })
    }
}

/// One login failure. Display text is English and lowercase, and never
/// carries the access token, a peer body or stored bytes.
#[derive(Debug, thiserror::Error)]
pub enum LoginError {
    /// The platform entropy source could not fill a session draw.
    #[error("entropy source is unavailable: {cause}")]
    Entropy {
        /// The platform entropy failure.
        cause: getrandom::Error,
    },
    /// The system clock is before the Unix epoch.
    #[error("system clock is before the unix epoch: {cause}")]
    Clock {
        /// The platform's clock failure.
        cause: std::time::SystemTimeError,
    },
    /// The Code Assist origin is neither recorded nor a loopback peer.
    /// `origin` is the canonical scheme/host class — never the raw URL.
    #[error("the code assist origin {origin} is outside the recorded contract")]
    EndpointNotAdmitted {
        /// The canonical origin class that was refused.
        origin: String,
    },
    /// The login was cancelled before it published.
    #[error("the code assist login was cancelled")]
    Cancelled,
    /// The connection the login path must bind is not declared.
    #[error("connection {connection} is not declared")]
    ConnectionMissing {
        /// The requested connection id.
        connection: String,
    },
    /// The login path writes only an `api_key` binding.
    #[error("connection {connection} is {kind}, not an api key")]
    NotApiKey {
        /// The requested connection id.
        connection: String,
        /// Its declared kind.
        kind: ConnKind,
    },
    /// The explicit login supplied no token.
    #[error("the code assist login carries no {field}")]
    MissingField {
        /// The missing member.
        field: &'static str,
    },
    /// A leg answered a non-success status; the body is never rendered.
    #[error("the code assist {leg} leg answered http status {status}")]
    Rejected {
        /// The call that was refused.
        leg: Leg,
        /// The peer's status code.
        status: u16,
    },
    /// The load leg answered the recorded VPC-SC `SECURITY_POLICY_VIOLATED`
    /// refusal; no tier is inferred from it.
    #[error("the code assist identity leg answers a security policy violation")]
    VpcScDenied,
    /// The tier needs an explicit project and the environment names none.
    #[error(
        "the code assist account requires an explicit project: set \
         GOOGLE_CLOUD_PROJECT or GOOGLE_CLOUD_PROJECT_ID"
    )]
    ProjectRequired,
    /// The onboarding finished without binding a project.
    #[error("the code assist account reports no bound project")]
    ProjectUnbound,
    /// The operation name is not a plain path segment sequence.
    #[error("the code assist onboarding operation name is not a plain path")]
    OperationNameMalformed,
    /// The recorded poll cap expired before the operation finished.
    #[error("the code assist project provisioning did not finish within the recorded poll cap")]
    ProvisioningTimedOut,
    /// A reply exceeded the shared byte bound.
    #[error("the code assist response exceeds the byte bound")]
    ResponseTooLarge,
    /// A reply was not the JSON object the contract records.
    #[error("the code assist endpoint answered malformed json")]
    MalformedResponse {
        /// The parse failure; serde's message could quote bytes.
        #[source]
        cause: serde_json::Error,
    },
    /// The material at the scope is not a Code Assist profile.
    #[error("the stored credential is not a code assist profile: {reason}")]
    StoredCredentialMalformed {
        /// The parse failure's class — serde's message could quote bytes.
        reason: &'static str,
    },
    /// The in-memory profile could not be encoded for the store.
    #[error("the code assist profile could not be serialized")]
    Serialization {
        /// The encoder failure.
        #[source]
        cause: serde_json::Error,
    },
    /// The credential seam's typed denial.
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

/// One provisioning outcome: the bound project and the selected tier.
struct Discovered {
    project: String,
    tier: String,
}

/// The discovery reply's recorded half.
#[derive(Deserialize)]
struct LoadCodeAssistPayload {
    #[serde(rename = "cloudaicompanionProject", default)]
    project: Option<String>,
    #[serde(rename = "currentTier", default)]
    current_tier: Option<Tier>,
    #[serde(rename = "allowedTiers", default)]
    allowed_tiers: Vec<Tier>,
}

/// One tier the account holds or may onboard. The id is optional in the
/// discovery DTO: an entry may be identified only by its `isDefault` flag.
#[derive(Deserialize)]
struct Tier {
    id: Option<String>,
    #[serde(rename = "isDefault", default)]
    is_default: bool,
}

/// Runs the recorded discovery/onboarding sequence.
fn discover(connection: &str, session: &LoginSession) -> Result<Discovered, LoginError> {
    let base = format!(
        "{}/{API_PATH}",
        session.endpoints.code_assist.trim_end_matches('/')
    );
    let authorization = format!("Bearer {}", session.access_token);
    let headers = [("authorization", authorization.as_str())];
    let project = session.project.as_deref();

    if session.is_cancelled() {
        return Err(LoginError::Cancelled);
    }
    let (status, payload) = post_json(
        connection,
        &format!("{base}:loadCodeAssist"),
        &load_body(project),
        &headers,
    )?;
    // The binding type is load-bearing: field access does not drive inference.
    let data: LoadCodeAssistPayload = if is_success(status) {
        serde_json::from_value(payload).map_err(|cause| LoginError::MalformedResponse { cause })?
    } else if is_vpc_sc(&payload) {
        return Err(LoginError::VpcScDenied);
    } else {
        return Err(LoginError::Rejected {
            leg: Leg::Identity,
            status,
        });
    };

    if let Some(tier) = data.current_tier {
        let bound = non_blank(data.project.as_deref())
            .or(project)
            .ok_or(LoginError::ProjectRequired)?;
        return Ok(Discovered {
            project: bound.to_string(),
            tier: non_blank(tier.id.as_deref())
                .unwrap_or_default()
                .to_string(),
        });
    }

    let tier = default_tier(&data.allowed_tiers);
    if tier.as_str() != FREE_TIER && project.is_none() {
        return Err(LoginError::ProjectRequired);
    }
    if session.is_cancelled() {
        return Err(LoginError::Cancelled);
    }
    let (status, mut operation) = post_json(
        connection,
        &format!("{base}:onboardUser"),
        &onboard_body(&tier, project),
        &headers,
    )?;
    if !is_success(status) {
        return Err(LoginError::Rejected {
            leg: Leg::Onboarding,
            status,
        });
    }
    if !operation.get("done").is_some_and(truthy)
        && let Some(name) = operation
            .get("name")
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty())
    {
        let path = operation_path(name)?;
        operation = poll_operation(
            connection,
            session,
            &format!("{base}/{path}"),
            &headers,
            session.budget,
        )?;
    }
    let bound = operation_project(&operation)
        .or_else(|| project.map(str::to_string))
        .ok_or(LoginError::ProjectUnbound)?;
    Ok(Discovered {
        project: bound,
        tier,
    })
}

/// Polls one pending operation up to the recorded cap; a truthy `done`
/// terminates it and a non-OK poll denies.
fn poll_operation(
    connection: &str,
    session: &LoginSession,
    endpoint: &str,
    headers: &[(&str, &str)],
    budget: OnboardingBudget,
) -> Result<Value, LoginError> {
    for attempt in 0..budget.max_attempts {
        if attempt > 0 {
            if session.is_cancelled() {
                return Err(LoginError::Cancelled);
            }
            pause(budget.poll_interval);
        }
        if session.is_cancelled() {
            return Err(LoginError::Cancelled);
        }
        let operation = get_leg(connection, endpoint, headers)?;
        if operation.get("done").is_some_and(truthy) {
            return Ok(operation);
        }
    }
    Err(LoginError::ProvisioningTimedOut)
}

/// One bounded wait that survives a spurious wake without shortening the poll
/// interval: no sleep loop and no spawned timer runs beside it.
fn pause(interval: Duration) {
    let started = Instant::now();
    while let Some(left) = interval
        .checked_sub(started.elapsed())
        .filter(|left| !left.is_zero())
    {
        std::thread::park_timeout(left);
    }
}

/// One bounded JSON POST; a success body must parse, a refusal body is kept
/// only so the recorded VPC-SC answer can be read.
fn post_json(
    connection: &str,
    endpoint: &str,
    body: &Value,
    headers: &[(&str, &str)],
) -> Result<(u16, Value), LoginError> {
    let (mut response, started) = login_common::post(
        connection,
        endpoint,
        REQUEST_TIMEOUT,
        Body::Json(body),
        headers,
    )?;
    let status = response.status().as_u16();
    let bytes = login_common::read_body(connection, &mut response, REQUEST_TIMEOUT, started)?;
    if is_success(status) {
        let payload = serde_json::from_slice(&bytes)
            .map_err(|cause| LoginError::MalformedResponse { cause })?;
        return Ok((status, payload));
    }
    // A refusal body that is not the recorded error shape is simply not the
    // VPC-SC answer; the status still denies with its own typed variant.
    Ok((
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    ))
}

/// One bounded GET under the recorded request deadline.
fn get_leg(
    connection: &str,
    endpoint: &str,
    headers: &[(&str, &str)],
) -> Result<Value, LoginError> {
    let started = Instant::now();
    let client = login_common::client(connection, REQUEST_TIMEOUT)?;
    let mut request = client.get(endpoint);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let mut response = request
        .send()
        .map_err(|error| super::transport(connection, error))?;
    let status = response.status().as_u16();
    if !is_success(status) {
        return Err(LoginError::Rejected {
            leg: Leg::Operation,
            status,
        });
    }
    let bytes = login_common::read_body(connection, &mut response, REQUEST_TIMEOUT, started)?;
    serde_json::from_slice(&bytes).map_err(|cause| LoginError::MalformedResponse { cause })
}

fn is_success(status: u16) -> bool {
    (200..300).contains(&status)
}

/// The recorded discovery body: the optional explicit project and the
/// plugin identity, never the token.
fn load_body(project: Option<&str>) -> Value {
    let mut body = serde_json::Map::new();
    if let Some(project) = project {
        body.insert("cloudaicompanionProject".to_string(), json!(project));
    }
    body.insert("metadata".to_string(), metadata(project));
    Value::Object(body)
}

/// The recorded onboarding body: the selected tier, and the explicit project
/// only for a non-free tier.
fn onboard_body(tier: &str, project: Option<&str>) -> Value {
    let mut body = serde_json::Map::new();
    body.insert("tierId".to_string(), json!(tier));
    if tier != FREE_TIER
        && let Some(project) = project
    {
        body.insert("cloudaicompanionProject".to_string(), json!(project));
        body.insert("metadata".to_string(), metadata(Some(project)));
        return Value::Object(body);
    }
    body.insert("metadata".to_string(), metadata(None));
    Value::Object(body)
}

/// The recorded plugin metadata; a free-tier onboarding carries no
/// `duetProject`.
fn metadata(duet_project: Option<&str>) -> Value {
    let mut metadata = serde_json::Map::new();
    metadata.insert("ideType".to_string(), json!(IDE_TYPE));
    metadata.insert("platform".to_string(), json!(PLATFORM));
    metadata.insert("pluginType".to_string(), json!(PLUGIN_TYPE));
    if let Some(project) = duet_project {
        metadata.insert("duetProject".to_string(), json!(project));
    }
    Value::Object(metadata)
}

/// The recorded VPC-SC answer: a non-OK load whose error details carry the
/// `SECURITY_POLICY_VIOLATED` reason.
fn is_vpc_sc(payload: &Value) -> bool {
    payload
        .get("error")
        .and_then(|error| error.get("details"))
        .and_then(Value::as_array)
        .is_some_and(|details| {
            details.iter().any(|detail| {
                detail.get("reason").and_then(Value::as_str) == Some("SECURITY_POLICY_VIOLATED")
            })
        })
}

/// The default tier the source derives from the allowed tiers: the id of the
/// entry flagged `isDefault` — the free tier when that entry carries none —
/// else the legacy tier.
fn default_tier(allowed: &[Tier]) -> String {
    // A present-but-blank id counts as absent: only a non-blank id names a tier.
    allowed.iter().find(|tier| tier.is_default).map_or_else(
        || LEGACY_TIER.to_string(),
        |tier| non_blank(tier.id.as_deref()).map_or_else(|| FREE_TIER.to_string(), str::to_string),
    )
}

/// The project an operation response binds: the recorded object's `id`.
fn operation_project(operation: &Value) -> Option<String> {
    let project = operation
        .get("response")?
        .get("cloudaicompanionProject")?
        .get("id")?
        .as_str()?;
    non_blank(Some(project)).map(str::to_string)
}

/// The source's truthiness check: `done` terminates on any truthy value.
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64().is_some_and(|number| number != 0.0),
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(map) => !map.is_empty(),
    }
}

/// A pending operation's name as a plain relative path, so it can never
/// rewrite the polled URL's path.
fn operation_path(name: &str) -> Result<&str, LoginError> {
    let plain = !name.is_empty()
        && name.split('/').all(|segment| {
            !segment.is_empty()
                && segment != "."
                && segment != ".."
                && segment.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~')
                })
        });
    if !plain {
        return Err(LoginError::OperationNameMalformed);
    }
    Ok(name)
}

/// Admits the Code Assist origin before any call: the recorded origin or a
/// loopback contract peer.
fn admit_origin(origin: &str) -> Result<(), LoginError> {
    if login_common::admitted_endpoint(origin, CODE_ASSIST_ORIGIN) {
        return Ok(());
    }
    Err(LoginError::EndpointNotAdmitted {
        origin: login_common::endpoint_origin(origin),
    })
}

/// The explicit project the environment names, first present value wins.
fn project_from(names: &[&str], lookup: impl Fn(&str) -> Option<String>) -> Option<String> {
    for name in names {
        let Some(value) = lookup(name) else {
            continue;
        };
        let value = value.trim();
        if !value.is_empty() {
            return Some(value.to_string());
        }
    }
    None
}

fn serialize(profile: &CodeAssistProfile) -> Result<Vec<u8>, LoginError> {
    serde_json::to_vec(profile).map_err(|cause| LoginError::Serialization { cause })
}

fn non_blank(value: Option<&str>) -> Option<&str> {
    value.filter(|value| !value.trim().is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_recorded_budget_is_the_source_cap() {
        assert_eq!(OnboardingBudget::recorded().max_attempts, 24);
        assert_eq!(
            OnboardingBudget::recorded().poll_interval,
            Duration::from_secs(5)
        );
        assert_eq!(OnboardingBudget::default(), OnboardingBudget::recorded());
    }

    #[test]
    fn any_truthy_done_terminates_the_poll() {
        assert!(truthy(&json!(true)));
        assert!(!truthy(&json!(false)));
        assert!(!truthy(&Value::Null));
        assert!(truthy(&json!(1)));
        assert!(!truthy(&json!(0)));
        assert!(!truthy(&json!("")));
        assert!(truthy(&json!("done")));
        assert!(!truthy(&json!({})));
        assert!(truthy(&json!({ "id": "value" })));
    }

    #[test]
    fn the_vpc_sc_reason_is_detected_in_the_error_details() {
        assert!(is_vpc_sc(&json!({
            "error": { "details": [{ "reason": "SECURITY_POLICY_VIOLATED" }] }
        })));
        assert!(!is_vpc_sc(&json!({
            "error": { "details": [{ "reason": "OTHER" }] }
        })));
        assert!(!is_vpc_sc(&json!({})));
        assert!(!is_vpc_sc(&json!({ "error": { "details": "not-a-list" } })));
    }

    #[test]
    fn the_default_tier_falls_back_to_the_legacy_tier() {
        let free = Tier {
            id: Some(FREE_TIER.to_string()),
            is_default: true,
        };
        let standard = Tier {
            id: Some("standard-tier".to_string()),
            is_default: false,
        };
        assert_eq!(default_tier(&[standard, free]), FREE_TIER);
        assert_eq!(default_tier(&[]), LEGACY_TIER);
        assert_eq!(
            default_tier(&[Tier {
                id: Some("standard-tier".to_string()),
                is_default: false,
            }]),
            LEGACY_TIER
        );
    }

    #[test]
    fn a_default_tier_without_an_id_selects_the_free_tier() {
        assert_eq!(
            default_tier(&[Tier {
                id: None,
                is_default: true,
            }]),
            FREE_TIER
        );
        assert_eq!(
            default_tier(&[Tier {
                id: Some("  ".to_string()),
                is_default: true,
            }]),
            FREE_TIER
        );
        assert_eq!(
            default_tier(&[Tier {
                id: Some("custom-tier".to_string()),
                is_default: true,
            }]),
            "custom-tier"
        );
    }

    #[test]
    fn an_operation_project_is_the_recorded_object_id() {
        assert_eq!(
            operation_project(&json!({
                "response": { "cloudaicompanionProject": { "id": "fixture-project" } }
            })),
            Some("fixture-project".to_string())
        );
        assert_eq!(
            operation_project(&json!({ "response": { "cloudaicompanionProject": "plain" } })),
            None
        );
        assert_eq!(operation_project(&json!({ "response": null })), None);
    }

    #[test]
    fn an_operation_name_is_a_plain_relative_path() {
        assert_eq!(
            operation_path("operations/onboard-1").ok(),
            Some("operations/onboard-1")
        );
        assert!(matches!(
            operation_path(""),
            Err(LoginError::OperationNameMalformed)
        ));
        assert!(matches!(
            operation_path("../accessTokens/steal"),
            Err(LoginError::OperationNameMalformed)
        ));
        assert!(matches!(
            operation_path("/operations/onboard-1"),
            Err(LoginError::OperationNameMalformed)
        ));
    }

    #[test]
    fn the_explicit_project_prefers_the_first_present_name() {
        let lookup = |name: &str| match name {
            "GOOGLE_CLOUD_PROJECT" => Some("  ".to_string()),
            "GOOGLE_CLOUD_PROJECT_ID" => Some("fixture-project".to_string()),
            _ => None,
        };
        assert_eq!(
            project_from(&["GOOGLE_CLOUD_PROJECT", "GOOGLE_CLOUD_PROJECT_ID"], lookup),
            Some("fixture-project".to_string())
        );
        assert_eq!(project_from(&["absent"], |_name| None), None);
    }

    #[test]
    fn the_metadata_body_carries_the_recorded_plugin() {
        assert_eq!(
            metadata(None),
            json!({
                "ideType": "IDE_UNSPECIFIED",
                "platform": "PLATFORM_UNSPECIFIED",
                "pluginType": "GEMINI",
            })
        );
        assert_eq!(
            metadata(Some("fixture-project")),
            json!({
                "ideType": "IDE_UNSPECIFIED",
                "platform": "PLATFORM_UNSPECIFIED",
                "pluginType": "GEMINI",
                "duetProject": "fixture-project",
            })
        );
    }
}
