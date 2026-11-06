//! Antigravity project-profile producer: the explicit login leg, the three
//! recorded onboarding calls and the canonical scoped profile.
//! Library-level — no CLI verb is added.
//!
//! The recorded contract is the account/project discovery the Antigravity
//! editor makes after sign-in: `POST {origin}/v1internal:loadCodeAssist`
//! carries the bearer and answers the current tier and the bound project;
//! when no current tier exists, `POST {origin}/v1internal:onboardUser`
//! answers a long-running operation, and `GET {origin}/v1internal/{name}`
//! polls it. The wait is bounded by [`ProvisioningBudget::recorded`] — 30 s
//! total with 1 s polls (DEC-009) — a `done` operation with a non-null
//! `error` is a denial, a `done` operation with a null `response` is a
//! denial, and a pending operation without a name is a denial, so onboarding
//! is never re-run blindly. The admitted origins are the recorded
//! [`CODE_ASSIST_ORIGIN`], its recorded sandbox fallback and a loopback
//! contract peer.
//!
//! Enrollment is create-only through [`CredentialStore::login`]: an occupied
//! scope or a refused store operation denies and leaves the prior bytes
//! untouched. The profile is written only after the project is bound, and a
//! login cancelled before the write — including one cancelled while the
//! bounded operation runs — publishes nothing. The access token is redacted
//! in the session's and the profile's `Debug` and never enters an error or a
//! diagnostic.

use super::login_common::{self, BindingError, Body, CommonError};
use super::{CredentialStore, ProviderError, SecretRef, TransportClass};
use crate::config::{Config, ConnKind};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// The recorded Antigravity Code Assist origin.
pub const CODE_ASSIST_ORIGIN: &str = "https://daily-cloudcode-pa.googleapis.com";

/// The recorded sandbox fallback origin; admitted inside the recorded set
/// only.
pub const CODE_ASSIST_SANDBOX_ORIGIN: &str = "https://daily-cloudcode-pa.sandbox.googleapis.com";

/// The recorded `v1internal` surface the three onboarding calls ride.
const API_PATH: &str = "v1internal";

/// The recorded plugin identity the discovery and onboarding bodies carry.
const PLUGIN_TYPE: &str = "ANTIGRAVITY";

/// The recorded onboarding LRO bounds: 30 s total, 1 s polls (DEC-009).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProvisioningBudget {
    /// The whole onboarding wait, across all three calls.
    pub deadline: Duration,
    /// The pause between two operation polls.
    pub poll_interval: Duration,
}

impl ProvisioningBudget {
    /// The recorded budget: 30 s total, 1 s polls.
    #[must_use]
    pub const fn recorded() -> Self {
        Self {
            deadline: Duration::from_secs(30),
            poll_interval: Duration::from_secs(1),
        }
    }
}

impl Default for ProvisioningBudget {
    fn default() -> Self {
        Self::recorded()
    }
}

/// The recorded origin the three onboarding calls reach. Production callers
/// pass [`AntigravityEndpoints::recorded`]; tests pass a loopback peer. The
/// override is not a config surface.
#[derive(Debug, Clone)]
pub struct AntigravityEndpoints {
    /// The Code Assist origin, without the `v1internal` path.
    pub code_assist: String,
}

impl AntigravityEndpoints {
    /// The recorded production origin.
    #[must_use]
    pub fn recorded() -> Self {
        Self {
            code_assist: CODE_ASSIST_ORIGIN.to_string(),
        }
    }
}

/// One in-flight login: the operator's explicit access token, the endpoints
/// and the recorded wait. `Debug` redacts the token.
///
/// A session is single-use: [`complete_login`] takes it by reference, and
/// [`LoginSession::cancel`] makes every later completion publish nothing.
pub struct LoginSession {
    access_token: String,
    endpoints: AntigravityEndpoints,
    budget: ProvisioningBudget,
    cancelled: AtomicBool,
}

impl fmt::Debug for LoginSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoginSession")
            .field("access_token", &login_common::redacted(&self.access_token))
            .field("code_assist", &self.endpoints.code_assist)
            .field("budget", &self.budget)
            .field("cancelled", &self.is_cancelled())
            .finish()
    }
}

impl LoginSession {
    /// The recorded wait this session runs under.
    #[must_use]
    pub fn budget(&self) -> ProvisioningBudget {
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

/// Builds one login session under the recorded LRO budget.
///
/// # Errors
/// [`LoginError::MissingField`] for an empty or whitespace-only token;
/// [`LoginError::EndpointNotAdmitted`] for an origin outside the recorded
/// set and outside loopback.
pub fn begin_login(
    access_token: &str,
    endpoints: &AntigravityEndpoints,
) -> Result<LoginSession, LoginError> {
    begin_login_with(access_token, endpoints, ProvisioningBudget::recorded())
}

/// Builds one login session under an explicit budget — the offline proof's
/// seam for a short wait.
///
/// # Errors
/// [`begin_login`]'s contract.
pub fn begin_login_with(
    access_token: &str,
    endpoints: &AntigravityEndpoints,
    budget: ProvisioningBudget,
) -> Result<LoginSession, LoginError> {
    let access_token = non_blank(Some(access_token)).ok_or(LoginError::MissingField {
        field: "access_token",
    })?;
    admit_origin(&endpoints.code_assist)?;
    Ok(LoginSession {
        access_token: access_token.to_string(),
        endpoints: endpoints.clone(),
        budget,
        cancelled: AtomicBool::new(false),
    })
}

/// Runs the recorded onboarding sequence and writes the project-bound
/// profile at the connection's scoped reference through
/// [`CredentialStore::login`], which refuses an occupied scope.
///
/// The discovery call is the identity leg: a token it rejects, a reply
/// naming no project and every pending-operation denial publish nothing. A
/// cancellation observed before the write publishes nothing either.
///
/// # Errors
/// [`LoginError::ConnectionMissing`]/[`LoginError::NotApiKey`] for the
/// config binding; [`LoginError::Cancelled`] for a cancelled session;
/// [`LoginError::Rejected`] for a refusing leg;
/// [`LoginError::ProjectUnbound`]/[`LoginError::ProvisioningDenied`]/
/// [`LoginError::ProvisioningResponseMissing`]/
/// [`LoginError::OperationNameMissing`]/
/// [`LoginError::OperationNameMalformed`] for the operation's terminal
/// checks; [`LoginError::ProvisioningTimedOut`] when the budget expires; the
/// reply, serialization and store denials this module documents.
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
    let binding = provision(connection, session)?;
    if session.is_cancelled() {
        return Err(LoginError::Cancelled);
    }
    let profile = AntigravityProfile {
        access_token: session.access_token.clone(),
        project: binding.project,
        classes: binding.classes,
    };
    store.login(&reference, &serialize(&profile)?)?;
    Ok(reference.profile().to_string())
}

/// Reads the Antigravity profile at a scoped reference — the seam the
/// CloudCode adapter consumes the producer artifact through. Parsing is
/// strict: foreign material is a typed denial, never a guess.
///
/// # Errors
/// The [`LoginError::Provider`] store denial, and
/// [`LoginError::StoredCredentialMalformed`] when the material is not an
/// Antigravity profile.
pub fn read_profile(
    store: &dyn CredentialStore,
    reference: &SecretRef,
) -> Result<AntigravityProfile, LoginError> {
    let bytes = store.resolve(reference)?;
    serde_json::from_slice(&bytes).map_err(|cause| LoginError::StoredCredentialMalformed {
        reason: login_common::malformed_reason(&cause),
    })
}

/// The canonical scoped Antigravity profile: the bearer, the bound project
/// and the discovery's model table. The token is redacted in `Debug`; the
/// project and the table are scope identifiers and render verbatim, and
/// unknown fields deny.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AntigravityProfile {
    access_token: String,
    project: String,
    classes: BTreeMap<String, String>,
}

impl fmt::Debug for AntigravityProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AntigravityProfile")
            .field("access_token", &login_common::redacted(&self.access_token))
            .field("project", &self.project)
            .field("classes", &self.classes)
            .finish()
    }
}

impl AntigravityProfile {
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

    /// The discovery's model-to-class table.
    #[must_use]
    pub fn classes(&self) -> &BTreeMap<String, String> {
        &self.classes
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
    /// The system clock is before the Unix epoch, so no delay applies.
    #[error("system clock is before the unix epoch: {cause}")]
    Clock {
        /// The platform's clock failure.
        cause: std::time::SystemTimeError,
    },
    /// The Code Assist origin is neither recorded nor a loopback peer.
    /// `origin` is the canonical scheme/host class — never the raw URL.
    #[error("the antigravity code assist origin {origin} is outside the recorded contract")]
    EndpointNotAdmitted {
        /// The canonical origin class that was refused.
        origin: String,
    },
    /// The login was cancelled before it published.
    #[error("the antigravity login was cancelled")]
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
    #[error("the antigravity login carries no {field}")]
    MissingField {
        /// The missing member.
        field: &'static str,
    },
    /// An onboarding call answered a non-success status; the body is never
    /// read.
    #[error("the antigravity {leg} leg answered http status {status}")]
    Rejected {
        /// The call that was refused.
        leg: Leg,
        /// The peer's status code.
        status: u16,
    },
    /// The discovery reply binds no project.
    #[error("the antigravity account reports no bound project")]
    ProjectUnbound,
    /// The finished operation carries a non-null error.
    #[error("the antigravity onboarding operation carries an error")]
    ProvisioningDenied,
    /// The finished operation carries a null response.
    #[error("the antigravity onboarding operation finished without a response")]
    ProvisioningResponseMissing,
    /// A pending operation carries no name, so it could never be polled.
    #[error("the antigravity onboarding operation carries no name")]
    OperationNameMissing,
    /// The operation name is not a plain path segment sequence.
    #[error("the antigravity onboarding operation name is not a plain path")]
    OperationNameMalformed,
    /// The recorded deadline expired before the operation finished.
    #[error("the antigravity onboarding operation did not finish within the deadline")]
    ProvisioningTimedOut,
    /// A reply exceeded the shared byte bound.
    #[error("the antigravity response exceeds the byte bound")]
    ResponseTooLarge,
    /// A reply was not the JSON object the contract records.
    #[error("the antigravity endpoint answered malformed json")]
    MalformedResponse {
        /// The parse failure; serde's message could quote bytes.
        #[source]
        cause: serde_json::Error,
    },
    /// The material at the scope is not an Antigravity profile.
    #[error("the stored credential is not an antigravity profile: {reason}")]
    StoredCredentialMalformed {
        /// The parse failure's class — serde's message could quote bytes.
        reason: &'static str,
    },
    /// The in-memory profile could not be encoded for the store.
    #[error("the antigravity profile could not be serialized")]
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

/// One provisioning outcome: the bound project and the discovery's table.
struct Binding {
    project: String,
    classes: BTreeMap<String, String>,
}

/// The discovery reply's recorded half.
#[derive(Deserialize)]
struct Discovery {
    #[serde(rename = "currentTier", default)]
    current_tier: Option<Value>,
    #[serde(rename = "cloudaicompanionProject", default)]
    project: Option<Value>,
    #[serde(rename = "availableModels", default)]
    available_models: Vec<AvailableModel>,
}

/// One model the discovery payload entitles, with its class.
#[derive(Deserialize)]
struct AvailableModel {
    name: String,
    class: String,
}

/// Runs the three onboarding calls under the session's budget.
fn provision(connection: &str, session: &LoginSession) -> Result<Binding, LoginError> {
    let deadline = Instant::now()
        .checked_add(session.budget.deadline)
        .ok_or(LoginError::ProvisioningTimedOut)?;
    let base = format!(
        "{}/{API_PATH}",
        session.endpoints.code_assist.trim_end_matches('/')
    );
    let authorization = format!("Bearer {}", session.access_token);
    let headers = [("authorization", authorization.as_str())];
    let identity = post_leg(
        connection,
        &format!("{base}:loadCodeAssist"),
        deadline,
        &metadata_body(),
        &headers,
        Leg::Identity,
    )?;
    let Discovery {
        current_tier,
        project,
        available_models,
    } = serde_json::from_value(identity)
        .map_err(|cause| LoginError::MalformedResponse { cause })?;
    let classes = available_models
        .into_iter()
        .map(|model| (model.name, model.class))
        .collect();
    if !has_current_tier(current_tier.as_ref()) {
        // shortcut: the onboardUser body carries no tierId; the tier
        // vocabulary lands with the consumer's class-resolution table.
        let operation = post_leg(
            connection,
            &format!("{base}:onboardUser"),
            deadline,
            &metadata_body(),
            &headers,
            Leg::Onboarding,
        )?;
        let project = settle(connection, session, &base, deadline, &headers, operation)?;
        return Ok(Binding { project, classes });
    }
    // A current tier without a bound project is no usable profile, and
    // onboarding never re-runs for it.
    let project = project
        .as_ref()
        .and_then(project_value)
        .ok_or(LoginError::ProjectUnbound)?;
    Ok(Binding { project, classes })
}

/// Settles one operation: a finished one answers the project or denies, a
/// pending one is polled every budget interval until the deadline.
fn settle(
    connection: &str,
    session: &LoginSession,
    base: &str,
    deadline: Instant,
    headers: &[(&str, &str)],
    mut operation: Value,
) -> Result<String, LoginError> {
    loop {
        if session.is_cancelled() {
            return Err(LoginError::Cancelled);
        }
        if operation.get("done").and_then(Value::as_bool) == Some(true) {
            if operation.get("error").is_some_and(|error| !error.is_null()) {
                return Err(LoginError::ProvisioningDenied);
            }
            let response = operation
                .get("response")
                .filter(|response| !response.is_null())
                .ok_or(LoginError::ProvisioningResponseMissing)?;
            return project_id(response).ok_or(LoginError::ProjectUnbound);
        }
        let name =
            login_common::text_field(&operation, "name").ok_or(LoginError::OperationNameMissing)?;
        let path = operation_path(&name)?;
        let wait = remaining(deadline)?.min(session.budget.poll_interval);
        pause(wait);
        if session.is_cancelled() {
            return Err(LoginError::Cancelled);
        }
        operation = get_leg(
            connection,
            &format!("{base}/{path}"),
            deadline,
            headers,
            Leg::Operation,
        )?;
    }
}

/// One bounded wait that survives a spurious wake without shortening the
/// poll interval: no sleep loop and no spawned timer runs beside it.
fn pause(interval: Duration) {
    let started = Instant::now();
    while let Some(left) = interval
        .checked_sub(started.elapsed())
        .filter(|left| !left.is_zero())
    {
        std::thread::park_timeout(left);
    }
}

/// One bounded JSON POST under the remaining budget.
fn post_leg(
    connection: &str,
    endpoint: &str,
    deadline: Instant,
    body: &Value,
    headers: &[(&str, &str)],
    leg: Leg,
) -> Result<Value, LoginError> {
    let left = remaining(deadline)?;
    let (mut response, started) =
        login_common::post(connection, endpoint, left, Body::Json(body), headers)
            .map_err(|error| leg_failure(deadline, error))?;
    if !response.status().is_success() {
        return Err(LoginError::Rejected {
            leg,
            status: response.status().as_u16(),
        });
    }
    let bytes = login_common::read_body(connection, &mut response, left, started)
        .map_err(|error| leg_common_failure(deadline, error))?;
    serde_json::from_slice(&bytes).map_err(|cause| LoginError::MalformedResponse { cause })
}

/// One bounded GET under the remaining budget.
fn get_leg(
    connection: &str,
    endpoint: &str,
    deadline: Instant,
    headers: &[(&str, &str)],
    leg: Leg,
) -> Result<Value, LoginError> {
    let left = remaining(deadline)?;
    let started = Instant::now();
    let client = login_common::client(connection, left)?;
    let mut request = client.get(endpoint);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let mut response = request
        .send()
        .map_err(|error| leg_failure(deadline, super::transport(connection, error)))?;
    if !response.status().is_success() {
        return Err(LoginError::Rejected {
            leg,
            status: response.status().as_u16(),
        });
    }
    let bytes = login_common::read_body(connection, &mut response, left, started)
        .map_err(|error| leg_common_failure(deadline, error))?;
    serde_json::from_slice(&bytes).map_err(|cause| LoginError::MalformedResponse { cause })
}

/// A leg failure observed after the one budget is spent is the recorded
/// expiry, not an opaque transport timeout: the client's per-request window
/// is derived from the same deadline, so load can consume it inside a leg.
/// A failure of any other class keeps its own typed denial.
fn leg_failure(deadline: Instant, error: ProviderError) -> LoginError {
    let timed_out = matches!(
        &error,
        ProviderError::Transport { cause, .. }
            if matches!(
                cause.class(),
                TransportClass::Timeout | TransportClass::DeadlineExpired
            )
    );
    if timed_out && Instant::now() >= deadline {
        return LoginError::ProvisioningTimedOut;
    }
    LoginError::Provider(error)
}

/// The shared primitive's failure under the same rule.
fn leg_common_failure(deadline: Instant, error: CommonError) -> LoginError {
    match error {
        CommonError::Transport(cause) => leg_failure(deadline, cause),
        other => LoginError::from(other),
    }
}

/// The time left before the recorded deadline, or the typed expiry.
fn remaining(deadline: Instant) -> Result<Duration, LoginError> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err(LoginError::ProvisioningTimedOut);
    }
    Ok(left)
}

/// The recorded discovery body: the plugin identity, never the token.
fn metadata_body() -> Value {
    json!({ "metadata": { "pluginType": PLUGIN_TYPE } })
}

/// The project id a discovery or operation reply names: the recorded field
/// is either the id itself or an object with an `id`.
fn project_id(container: &Value) -> Option<String> {
    project_value(container.get("cloudaicompanionProject")?)
}

/// The id one project field carries: the id string, or an object's `id`.
fn project_value(field: &Value) -> Option<String> {
    let id = field
        .as_str()
        .or_else(|| field.get("id").and_then(Value::as_str))?;
    non_blank(Some(id)).map(str::to_string)
}

/// Whether the discovery reply names a current tier; an explicit null is no
/// tier, so the onboarding leg is the only path that binds a project.
fn has_current_tier(tier: Option<&Value>) -> bool {
    tier.is_some_and(|tier| !tier.is_null())
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

/// Admits the Code Assist origin before any call: a recorded origin or a
/// loopback contract peer.
fn admit_origin(origin: &str) -> Result<(), LoginError> {
    if login_common::admitted_endpoint(origin, CODE_ASSIST_ORIGIN)
        || login_common::admitted_endpoint(origin, CODE_ASSIST_SANDBOX_ORIGIN)
    {
        return Ok(());
    }
    Err(LoginError::EndpointNotAdmitted {
        origin: login_common::endpoint_origin(origin),
    })
}

fn serialize(profile: &AntigravityProfile) -> Result<Vec<u8>, LoginError> {
    serde_json::to_vec(profile).map_err(|cause| LoginError::Serialization { cause })
}

fn non_blank(value: Option<&str>) -> Option<&str> {
    value.filter(|value| !value.trim().is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::TransportCause;

    #[test]
    fn a_spent_budget_maps_a_timeout_but_not_a_plain_failure() {
        let deadline = Instant::now() - Duration::from_millis(1);
        let expired = ProviderError::Transport {
            connection: "antigravity".to_string(),
            cause: TransportCause::Deadline {
                budget: Duration::from_millis(1),
            },
        };
        assert!(matches!(
            leg_failure(deadline, expired),
            LoginError::ProvisioningTimedOut
        ));

        let reset = ProviderError::Transport {
            connection: "antigravity".to_string(),
            cause: TransportCause::Read {
                source: std::sync::Arc::new(std::io::Error::other("peer reset")),
            },
        };
        assert!(matches!(
            leg_failure(deadline, reset),
            LoginError::Provider(ProviderError::Transport { .. })
        ));
    }

    #[test]
    fn a_project_field_names_its_id_or_an_object_id() {
        assert_eq!(
            project_id(&json!({ "cloudaicompanionProject": "fixture-project" })),
            Some("fixture-project".to_string())
        );
        assert_eq!(
            project_id(&json!({ "cloudaicompanionProject": { "id": "fixture-project" } })),
            Some("fixture-project".to_string())
        );
        assert_eq!(
            project_id(&json!({ "cloudaicompanionProject": "  " })),
            None
        );
        assert_eq!(
            project_id(&json!({ "currentTier": { "id": "free-tier" } })),
            None
        );
    }

    #[test]
    fn the_discovery_reply_reads_its_recorded_half() {
        let discovery: Discovery = serde_json::from_value(json!({
            "currentTier": { "id": "free-tier" },
            "cloudaicompanionProject": { "id": "fixture-project" },
            "availableModels": [{ "name": "claude-sonnet-4-5", "class": "pro" }]
        }))
        .expect("the discovery reply parses");

        assert!(discovery.current_tier.is_some());
        assert_eq!(
            discovery.project.as_ref().and_then(project_value),
            Some("fixture-project".to_string())
        );
        assert_eq!(discovery.available_models.len(), 1);
    }

    #[test]
    fn a_null_current_tier_is_no_tier() {
        let absent: Discovery = serde_json::from_value(json!({})).expect("an empty reply parses");
        let null: Discovery =
            serde_json::from_value(json!({ "currentTier": null })).expect("a null tier parses");
        let present: Discovery =
            serde_json::from_value(json!({ "currentTier": { "id": "free-tier" } }))
                .expect("a tier parses");

        assert!(!has_current_tier(absent.current_tier.as_ref()));
        assert!(!has_current_tier(null.current_tier.as_ref()));
        assert!(has_current_tier(present.current_tier.as_ref()));
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
}
