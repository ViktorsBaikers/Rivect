//! Antigravity project-profile producer: the explicit login leg, the
//! recorded provisioning sequence and the canonical scoped profile.
//! Library-level — no CLI verb is added.
//!
//! The recorded contract is the account/project discovery the Antigravity
//! editor makes after sign-in: `POST {origin}/v1internal:loadCodeAssist`
//! carries the bearer and the `ideType: ANTIGRAVITY` metadata, answers the
//! current/paid tier and the bound project, and is repeated with that project
//! when no paid tier is present. The source free-tier eligibility check runs
//! before onboarding; when no current tier exists,
//! `POST {origin}/v1internal:onboardUser` carries `tierId: free-tier` with the
//! same metadata and answers a long-running operation, and
//! `GET {origin}/v1internal/{name}` polls it. After onboarding or an existing
//! current tier the project is reloaded once more: the operation response is
//! never the binding. `POST {origin}/v1internal:fetchAvailableModels` then
//! answers the `models` map, whose ids are joined to the pinned catalog's
//! explicit classes. The wait is bounded by
//! [`ProvisioningBudget::recorded`] — 30 s total with 1 s polls (DEC-009) —
//! shared by every leg and the publication admission; a `done` operation with
//! a non-null `error` is a denial, a `done` operation with a null `response`
//! is a denial, and a pending operation without a name is a denial, so
//! onboarding is never re-run blindly. The admitted origins are the recorded
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

/// The recorded `v1internal` surface the provisioning calls ride.
const API_PATH: &str = "v1internal";

/// The recorded IDE identity every discovery and onboarding body carries.
const IDE_TYPE: &str = "ANTIGRAVITY";

/// The recorded tier id the onboarding body carries.
const FREE_TIER: &str = "free-tier";

/// One pinned catalog row for the discovered models map: the source
/// `identity.class` and the explicit alternate ids the same entry declares
/// (`requestModelId` and aliases).
struct PinnedModel {
    class: &'static str,
    alternate_ids: &'static [&'static str],
}

/// The pinned Antigravity catalog. A discovered id outside these rows has no
/// recorded class and denies; no class is inferred from a model-name prefix.
const PINNED_MODELS: &[(&str, PinnedModel)] = &[
    (
        "gemini-2.5-flash",
        PinnedModel {
            class: "gemini",
            alternate_ids: &[],
        },
    ),
    (
        "claude-sonnet-4-5",
        PinnedModel {
            class: "anthropic",
            alternate_ids: &[],
        },
    ),
    (
        "gpt-oss-120b",
        PinnedModel {
            class: "gpt-oss",
            alternate_ids: &["gpt-oss-120b-medium"],
        },
    ),
];

/// The recorded onboarding LRO bounds: 30 s total, 1 s polls (DEC-009).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProvisioningBudget {
    /// The one shared wait: the initial load, its project repeat, onboarding,
    /// the operation polls, the final reload, discovery and the publication
    /// admission all read this budget; no leg resets it.
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

/// The recorded origin the provisioning calls reach. Production callers
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
    /// The clock the shared deadline reads. Production reads the system
    /// clock; the offline proof steps it so the publication admission is
    /// reached already spent without racing the last leg.
    #[cfg(test)]
    clock: std::sync::Arc<dyn Fn() -> Instant + Send + Sync>,
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

    /// The clock the shared deadline reads.
    #[cfg(not(test))]
    fn now(&self) -> Instant {
        Instant::now()
    }

    /// The injected clock the offline proof advances.
    #[cfg(test)]
    fn now(&self) -> Instant {
        (self.clock)()
    }

    /// The time left before the recorded deadline, or the typed expiry.
    fn remaining(&self, deadline: Instant) -> Result<Duration, LoginError> {
        let left = deadline.saturating_duration_since(self.now());
        if left.is_zero() {
            return Err(LoginError::ProvisioningTimedOut);
        }
        Ok(left)
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
/// seam for a short wait. A zero poll interval is clamped to one millisecond
/// so a library caller cannot turn the operation poll into a tight loop.
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
        budget: ProvisioningBudget {
            poll_interval: budget.poll_interval.max(Duration::from_millis(1)),
            ..budget
        },
        cancelled: AtomicBool::new(false),
        #[cfg(test)]
        clock: std::sync::Arc::new(Instant::now),
    })
}

/// Runs the recorded discovery, onboarding and final binding sequence and
/// writes the project-bound profile at the connection's scoped reference
/// through [`CredentialStore::login`], which refuses an occupied scope.
///
/// The `loadCodeAssist` calls are the identity legs: a token they reject, a
/// reply naming no project, an ineligible free tier and every
/// pending-operation denial publish nothing. Only the final reload binds the
/// project, and a cancellation or a spent budget observed before the write
/// publishes nothing either.
///
/// # Errors
/// [`LoginError::ConnectionMissing`]/[`LoginError::NotApiKey`] for the
/// config binding; [`LoginError::Cancelled`] for a cancelled session;
/// [`LoginError::Rejected`] for a refusing leg;
/// [`LoginError::FreeTierIneligible`] for the source eligibility denial;
/// [`LoginError::ProjectUnbound`]/[`LoginError::ProvisioningDenied`]/
/// [`LoginError::ProvisioningResponseMissing`]/
/// [`LoginError::OperationNameMissing`]/
/// [`LoginError::OperationNameMalformed`] for the binding and operation's
/// terminal checks; [`LoginError::ModelClassUnknown`] for a discovered model
/// outside the pinned catalog; [`LoginError::ProvisioningTimedOut`] when the
/// shared budget expires; the reply, serialization and store denials this
/// module documents.
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
    let deadline = session
        .now()
        .checked_add(session.budget.deadline)
        .ok_or(LoginError::ProvisioningTimedOut)?;
    let binding = provision(connection, session, deadline)?;
    // The publication admission rides the same deadline as every leg: a
    // budget spent after the last reply denies and writes nothing.
    session.remaining(deadline)?;
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

/// Replaces the stored profile's token only, preserving the project and the
/// class table. Refresh is explicit: it runs no provisioning or discovery
/// call and grants no hidden external effect.
///
/// # Errors
/// [`LoginError::MissingField`] for an empty or whitespace-only token;
/// [`LoginError::StoredCredentialMalformed`] when the stored material is not
/// an Antigravity profile; the [`LoginError::Provider`] store denial.
pub fn refresh_profile(
    store: &dyn CredentialStore,
    reference: &SecretRef,
    access_token: &str,
) -> Result<String, LoginError> {
    let access_token = non_blank(Some(access_token)).ok_or(LoginError::MissingField {
        field: "access_token",
    })?;
    let stored = read_profile(store, reference)?;
    let updated = AntigravityProfile {
        access_token: access_token.to_string(),
        project: stored.project,
        classes: stored.classes,
    };
    store.refresh(reference, &serialize(&updated)?)?;
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
    /// The `fetchAvailableModels` call.
    Discovery,
}

impl fmt::Display for Leg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Identity => "identity",
            Self::Onboarding => "onboarding",
            Self::Operation => "operation",
            Self::Discovery => "discovery",
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
    /// The account declares the free tier ineligible with a recorded reason.
    #[error("the antigravity account is not eligible for the free tier")]
    FreeTierIneligible,
    /// A discovered model id has no recorded class in the pinned catalog.
    /// The id is retained for programmatic inspection only; peer text never
    /// enters the diagnostic.
    #[error("the antigravity account entitles a model outside the pinned catalog")]
    ModelClassUnknown {
        /// The discovered id outside the pinned catalog.
        model: String,
    },
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

/// The `loadCodeAssist` reply's recorded half.
#[derive(Deserialize)]
struct LoadReply {
    #[serde(rename = "currentTier", default)]
    current_tier: Option<Value>,
    #[serde(rename = "paidTier", default)]
    paid_tier: Option<Value>,
    #[serde(rename = "allowedTiers", default)]
    allowed_tiers: Vec<Tier>,
    #[serde(rename = "ineligibleTiers", default)]
    ineligible_tiers: Vec<IneligibleTier>,
    #[serde(rename = "cloudaicompanionProject", default)]
    project: Option<String>,
}

/// One tier the account may select.
#[derive(Deserialize)]
struct Tier {
    #[serde(default)]
    id: Option<String>,
}

/// One tier the account is refused. Only the recorded reason's presence is
/// read; the peer text never enters an error.
#[derive(Deserialize)]
struct IneligibleTier {
    #[serde(rename = "tierId", default)]
    tier_id: Option<String>,
    #[serde(rename = "reasonMessage", default)]
    reason_message: Option<String>,
}

/// The `fetchAvailableModels` reply: the account's models map.
#[derive(Deserialize)]
struct ModelsReply {
    models: BTreeMap<String, Value>,
}

/// Runs discovery, onboarding and the final binding under one deadline.
fn provision(
    connection: &str,
    session: &LoginSession,
    deadline: Instant,
) -> Result<Binding, LoginError> {
    let base = format!(
        "{}/{API_PATH}",
        session.endpoints.code_assist.trim_end_matches('/')
    );
    let authorization = format!("Bearer {}", session.access_token);
    let headers = [("authorization", authorization.as_str())];
    let initial = load_code_assist(connection, session, &base, deadline, &headers)?;
    assert_free_tier_eligible(&initial)?;
    if !has_tier(initial.current_tier.as_ref()) {
        let operation = post_leg(
            connection,
            session,
            &format!("{base}:onboardUser"),
            deadline,
            &onboard_body(),
            &headers,
            Leg::Onboarding,
        )?;
        settle(connection, session, &base, deadline, &headers, operation)?;
    }
    // The operation response never substitutes for the final binding check:
    // only the reloaded project is published.
    let refreshed = load_code_assist(connection, session, &base, deadline, &headers)?;
    let project = refreshed
        .project
        .filter(|project| !project.is_empty())
        .ok_or(LoginError::ProjectUnbound)?;
    let classes = discover_classes(connection, session, &base, deadline, &headers)?;
    Ok(Binding { project, classes })
}

/// Runs the source `loadCodeAssist` sequence: the metadata call, then the
/// project-carrying repeat when no paid tier is present.
fn load_code_assist(
    connection: &str,
    session: &LoginSession,
    base: &str,
    deadline: Instant,
    headers: &[(&str, &str)],
) -> Result<LoadReply, LoginError> {
    let reply = load_reply(
        connection,
        session,
        base,
        deadline,
        &metadata_body(),
        headers,
    )?;
    if has_tier(reply.paid_tier.as_ref()) {
        return Ok(reply);
    }
    let Some(project) = reply
        .project
        .as_deref()
        .filter(|project| !project.is_empty())
    else {
        return Ok(reply);
    };
    load_reply(
        connection,
        session,
        base,
        deadline,
        &load_body(project),
        headers,
    )
}

/// One `loadCodeAssist` POST parsed into the recorded reply.
fn load_reply(
    connection: &str,
    session: &LoginSession,
    base: &str,
    deadline: Instant,
    body: &Value,
    headers: &[(&str, &str)],
) -> Result<LoadReply, LoginError> {
    let reply = post_leg(
        connection,
        session,
        &format!("{base}:loadCodeAssist"),
        deadline,
        body,
        headers,
        Leg::Identity,
    )?;
    serde_json::from_value(reply).map_err(|cause| LoginError::MalformedResponse { cause })
}

/// The source's free-tier eligibility: an allowed `free-tier` row passes, an
/// explicit ineligible row with a recorded reason denies, and an account that
/// declares neither passes as the source does.
fn assert_free_tier_eligible(reply: &LoadReply) -> Result<(), LoginError> {
    if reply
        .allowed_tiers
        .iter()
        .any(|tier| tier.id.as_deref() == Some(FREE_TIER))
    {
        return Ok(());
    }
    let denied = reply.ineligible_tiers.iter().any(|tier| {
        tier.tier_id.as_deref() == Some(FREE_TIER)
            && tier
                .reason_message
                .as_deref()
                .is_some_and(|reason| !reason.trim().is_empty())
    });
    if denied {
        return Err(LoginError::FreeTierIneligible);
    }
    Ok(())
}

/// Runs the source discovery: the bearer `{}` POST whose `models` map keys
/// are joined to the pinned catalog.
fn discover_classes(
    connection: &str,
    session: &LoginSession,
    base: &str,
    deadline: Instant,
    headers: &[(&str, &str)],
) -> Result<BTreeMap<String, String>, LoginError> {
    let reply = post_leg(
        connection,
        session,
        &format!("{base}:fetchAvailableModels"),
        deadline,
        &json!({}),
        headers,
        Leg::Discovery,
    )?;
    let ModelsReply { models } =
        serde_json::from_value(reply).map_err(|cause| LoginError::MalformedResponse { cause })?;
    models
        .into_keys()
        .map(|model| {
            let class = pinned_class(&model).ok_or_else(|| LoginError::ModelClassUnknown {
                model: model.clone(),
            })?;
            Ok((model, class.to_string()))
        })
        .collect()
}

/// The pinned class of a discovered id, matched by canonical id or by the
/// entry's declared alternate ids.
fn pinned_class(model: &str) -> Option<&'static str> {
    PINNED_MODELS.iter().find_map(|(canonical, entry)| {
        (*canonical == model || entry.alternate_ids.contains(&model)).then_some(entry.class)
    })
}

/// Settles one operation: a finished one passes its terminal checks, a
/// pending one is polled every budget interval until the deadline. The
/// response is never read as the binding.
fn settle(
    connection: &str,
    session: &LoginSession,
    base: &str,
    deadline: Instant,
    headers: &[(&str, &str)],
    mut operation: Value,
) -> Result<(), LoginError> {
    loop {
        if session.is_cancelled() {
            return Err(LoginError::Cancelled);
        }
        if operation.get("done").and_then(Value::as_bool) == Some(true) {
            if operation.get("error").is_some_and(|error| !error.is_null()) {
                return Err(LoginError::ProvisioningDenied);
            }
            if operation.get("response").is_none_or(Value::is_null) {
                return Err(LoginError::ProvisioningResponseMissing);
            }
            return Ok(());
        }
        let name =
            login_common::text_field(&operation, "name").ok_or(LoginError::OperationNameMissing)?;
        let path = operation_path(&name)?;
        let wait = session
            .remaining(deadline)?
            .min(session.budget.poll_interval);
        pause(wait);
        if session.is_cancelled() {
            return Err(LoginError::Cancelled);
        }
        operation = get_leg(
            connection,
            session,
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
    session: &LoginSession,
    endpoint: &str,
    deadline: Instant,
    body: &Value,
    headers: &[(&str, &str)],
    leg: Leg,
) -> Result<Value, LoginError> {
    let left = session.remaining(deadline)?;
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
    session: &LoginSession,
    endpoint: &str,
    deadline: Instant,
    headers: &[(&str, &str)],
    leg: Leg,
) -> Result<Value, LoginError> {
    let left = session.remaining(deadline)?;
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

/// The recorded discovery body: the IDE identity, never the token.
fn metadata_body() -> Value {
    json!({ "metadata": { "ideType": IDE_TYPE } })
}

/// The source onboarding body: the free tier with the same metadata.
fn onboard_body() -> Value {
    json!({ "tierId": FREE_TIER, "metadata": { "ideType": IDE_TYPE } })
}

/// The project-carrying repeat of the discovery body.
fn load_body(project: &str) -> Value {
    json!({ "cloudaicompanionProject": project, "metadata": { "ideType": IDE_TYPE } })
}

/// Whether a recorded tier field carries a tier; an explicit null is no tier,
/// exactly as the source's `!== undefined && !== null` check reads it.
fn has_tier(tier: Option<&Value>) -> bool {
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
    fn the_load_reply_reads_its_source_halves() {
        let reply: LoadReply = serde_json::from_value(json!({
            "currentTier": { "id": "free-tier" },
            "paidTier": null,
            "allowedTiers": [{ "id": "free-tier" }],
            "ineligibleTiers": [{ "tierId": "legacy-tier", "reasonMessage": "peer text" }],
            "cloudaicompanionProject": "fixture-project"
        }))
        .expect("the load reply parses");

        assert!(has_tier(reply.current_tier.as_ref()));
        assert!(!has_tier(reply.paid_tier.as_ref()));
        assert_eq!(reply.allowed_tiers.len(), 1);
        assert_eq!(reply.ineligible_tiers.len(), 1);
        assert_eq!(reply.project.as_deref(), Some("fixture-project"));
    }

    #[test]
    fn a_null_tier_is_no_tier() {
        let absent: LoadReply = serde_json::from_value(json!({})).expect("an empty reply parses");
        let null: LoadReply =
            serde_json::from_value(json!({ "currentTier": null })).expect("a null tier parses");
        let present: LoadReply =
            serde_json::from_value(json!({ "currentTier": { "id": "free-tier" } }))
                .expect("a tier parses");

        assert!(!has_tier(absent.current_tier.as_ref()));
        assert!(!has_tier(null.current_tier.as_ref()));
        assert!(has_tier(present.current_tier.as_ref()));
    }

    #[test]
    fn the_pinned_catalog_classifies_only_recorded_identities() {
        assert_eq!(pinned_class("gemini-2.5-flash"), Some("gemini"));
        assert_eq!(pinned_class("claude-sonnet-4-5"), Some("anthropic"));
        assert_eq!(pinned_class("gpt-oss-120b"), Some("gpt-oss"));
        assert_eq!(pinned_class("gpt-oss-120b-medium"), Some("gpt-oss"));
        assert_eq!(pinned_class("gemini-9-experimental"), None);
        assert_eq!(pinned_class("claude-sonnet-4-5-pro"), None);
        assert_eq!(pinned_class(""), None);
    }

    #[test]
    fn the_eligibility_check_reads_allowed_and_ineligible_tiers() {
        let allowed: LoadReply = serde_json::from_value(json!({
            "allowedTiers": [{ "id": "free-tier" }],
            "ineligibleTiers": [{ "tierId": "free-tier", "reasonMessage": "peer text" }]
        }))
        .expect("an allowed reply parses");
        assert!(assert_free_tier_eligible(&allowed).is_ok());

        let refused: LoadReply = serde_json::from_value(json!({
            "ineligibleTiers": [{ "tierId": "free-tier", "reasonMessage": "peer text" }]
        }))
        .expect("an ineligible reply parses");
        assert!(matches!(
            assert_free_tier_eligible(&refused),
            Err(LoginError::FreeTierIneligible)
        ));

        let unnamed: LoadReply = serde_json::from_value(json!({
            "ineligibleTiers": [{ "tierId": "free-tier" }]
        }))
        .expect("a reasonless reply parses");
        assert!(assert_free_tier_eligible(&unnamed).is_ok());

        let silent: LoadReply = serde_json::from_value(json!({})).expect("an empty reply parses");
        assert!(assert_free_tier_eligible(&silent).is_ok());
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
    fn a_zero_poll_interval_is_clamped() {
        let session = begin_login_with(
            "fixture-token",
            &AntigravityEndpoints::recorded(),
            ProvisioningBudget {
                deadline: Duration::from_secs(1),
                poll_interval: Duration::ZERO,
            },
        )
        .expect("the login begins");

        assert_eq!(session.budget().poll_interval, Duration::from_millis(1));
    }

    const ADMISSION_SCOPE: &str = "rivect-test/antigravity";
    const STORED_AT_ADMISSION: &str = "{\"access_token\":\"prior-token\",\"project\":\"prior-project\",\"classes\":{\"gemini-2.5-flash\":\"gemini\"}}";

    fn antigravity_config() -> Config {
        Config::parse_validated(
            "config_version = 1\n\
             [connections.antigravity]\n\
             kind = \"api_key\"\n\
             endpoint = \"https://daily-cloudcode-pa.googleapis.com\"\n\
             credential_ref = \"keychain:rivect-test/antigravity\"\n\
             [models.defaults]\n\
             model = { mode = \"auto\" }\n\
             effort = { mode = \"auto\" }\n\
             fallback = { mode = \"auto\" }\n",
        )
        .expect("the antigravity config parses")
    }

    /// One loopback contract peer that records each request line and answers
    /// it; the accept loop stops on drop.
    struct TestPeer {
        base: String,
        seen: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
        stop: std::sync::Arc<AtomicBool>,
        handle: Option<std::thread::JoinHandle<()>>,
    }

    impl TestPeer {
        fn start(answer: impl Fn(&str) -> String + Send + Sync + 'static) -> Self {
            use std::io::Write as _;

            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback peer");
            listener
                .set_nonblocking(true)
                .expect("nonblocking loopback peer");
            let base = format!("http://{}", listener.local_addr().expect("peer address"));
            let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let recorded = std::sync::Arc::clone(&seen);
            let stop = std::sync::Arc::new(AtomicBool::new(false));
            let flag = std::sync::Arc::clone(&stop);
            let handle = std::thread::Builder::new()
                .spawn(move || {
                    while !flag.load(Ordering::SeqCst) {
                        match listener.accept() {
                            Ok((mut stream, _address)) => {
                                let Some(line) = read_request_line(&mut stream) else {
                                    continue;
                                };
                                recorded.lock().expect("seen lock").push(line.clone());
                                let payload = answer(&line);
                                let response = format!(
                                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                                     Content-Length: {}\r\nConnection: close\r\n\r\n{payload}",
                                    payload.len()
                                );
                                if stream.write_all(response.as_bytes()).is_err() {
                                    continue;
                                }
                            }
                            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                                std::thread::park_timeout(Duration::from_millis(1));
                            }
                            Err(_error) => break,
                        }
                    }
                })
                .expect("the peer thread starts");
            Self {
                base,
                seen,
                stop,
                handle: Some(handle),
            }
        }

        fn requests(&self) -> Vec<String> {
            self.seen.lock().expect("seen lock").clone()
        }
    }

    impl Drop for TestPeer {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(handle) = self.handle.take() {
                handle.join().expect("the peer thread joins");
            }
        }
    }

    /// Reads one request's head and body and answers its request line.
    fn read_request_line(stream: &mut std::net::TcpStream) -> Option<String> {
        use std::io::Read as _;

        stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 4096];
        let head_end = loop {
            let read = stream.read(&mut chunk).ok()?;
            if read == 0 {
                return None;
            }
            buffer.extend_from_slice(&chunk[..read]);
            if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
                break position;
            }
        };
        let head = String::from_utf8_lossy(&buffer[..head_end]).to_string();
        let length = head
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
            .unwrap_or(0);
        let body_start = head_end + 4;
        while buffer.len() < body_start + length {
            let read = stream.read(&mut chunk).ok()?;
            if read == 0 {
                break;
            }
            buffer.extend_from_slice(&chunk[..read]);
        }
        head.lines().next().map(str::to_string)
    }

    /// A create-only in-memory store: the admission proof reads its prior
    /// bytes back.
    struct TestStore {
        entries: std::sync::Mutex<BTreeMap<String, Vec<u8>>>,
    }

    impl TestStore {
        fn with(scope: &str, secret: &[u8]) -> Self {
            let mut entries = BTreeMap::new();
            entries.insert(scope.to_string(), secret.to_vec());
            Self {
                entries: std::sync::Mutex::new(entries),
            }
        }

        fn bytes(&self, scope: &str) -> Option<Vec<u8>> {
            self.entries.lock().expect("store lock").get(scope).cloned()
        }
    }

    impl CredentialStore for TestStore {
        fn kind(&self) -> crate::providers::StoreKind {
            crate::providers::StoreKind::Keychain
        }

        fn occupied(&self, credential: &SecretRef) -> Result<bool, ProviderError> {
            Ok(self
                .entries
                .lock()
                .expect("store lock")
                .contains_key(credential.scope()))
        }

        fn entry_accounts(&self, _service: &str) -> Result<Vec<String>, ProviderError> {
            Ok(Vec::new())
        }

        fn login(&self, credential: &SecretRef, secret: &[u8]) -> Result<(), ProviderError> {
            let mut entries = self.entries.lock().expect("store lock");
            if entries.contains_key(credential.scope()) {
                return Err(ProviderError::CredentialOccupied {
                    scope: credential.scope().to_string(),
                });
            }
            entries.insert(credential.scope().to_string(), secret.to_vec());
            drop(entries);
            Ok(())
        }

        fn resolve(&self, credential: &SecretRef) -> Result<Vec<u8>, ProviderError> {
            self.bytes(credential.scope())
                .ok_or_else(|| ProviderError::CredentialAbsent {
                    scope: credential.scope().to_string(),
                })
        }

        fn refresh(&self, credential: &SecretRef, secret: &[u8]) -> Result<(), ProviderError> {
            self.entries
                .lock()
                .expect("store lock")
                .insert(credential.scope().to_string(), secret.to_vec());
            Ok(())
        }

        fn revoke(&self, credential: &SecretRef) -> Result<(), ProviderError> {
            self.entries
                .lock()
                .expect("store lock")
                .remove(credential.scope())
                .map(|_| ())
                .ok_or_else(|| ProviderError::CredentialAbsent {
                    scope: credential.scope().to_string(),
                })
        }

        fn logout(&self, credential: &SecretRef) -> Result<(), ProviderError> {
            self.revoke(credential)
        }
    }

    /// The reading sequence is the deadline, one per leg (initial load, final
    /// reload, discovery) and then the publication admission: the last
    /// reading is the first past the deadline. A removed admission would
    /// reach the create-only write instead of the typed expiry.
    #[test]
    fn a_budget_spent_at_the_publication_admission_writes_nothing() {
        let peer = TestPeer::start(|line| {
            if line.contains(":loadCodeAssist") {
                return json!({
                    "currentTier": { "id": "free-tier" },
                    "paidTier": { "id": "paid-tier" },
                    "cloudaicompanionProject": "fixture-project"
                })
                .to_string();
            }
            json!({ "models": { "gemini-2.5-flash": {} } }).to_string()
        });
        let base = Instant::now();
        let readings = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let mut session = begin_login_with(
            "fixture-token",
            &AntigravityEndpoints {
                code_assist: peer.base.clone(),
            },
            ProvisioningBudget {
                deadline: Duration::from_millis(400),
                poll_interval: Duration::from_millis(20),
            },
        )
        .expect("the login begins");
        let stepped = std::sync::Arc::clone(&readings);
        session.clock = std::sync::Arc::new(move || {
            base + Duration::from_millis(100) * stepped.fetch_add(1, Ordering::SeqCst)
        });
        let store = TestStore::with(ADMISSION_SCOPE, STORED_AT_ADMISSION.as_bytes());

        let error = complete_login(&antigravity_config(), "antigravity", &session, &store)
            .expect_err("the publication admission is spent");

        assert!(matches!(error, LoginError::ProvisioningTimedOut), "{error}");
        assert_eq!(
            store.bytes(ADMISSION_SCOPE),
            Some(STORED_AT_ADMISSION.as_bytes().to_vec()),
            "the prior bytes are untouched"
        );
        assert_eq!(
            peer.requests().len(),
            3,
            "every leg answered before the admission"
        );
    }
}
