//! The two recorded CloudCode `v1internal` projections: the
//! `google-antigravity` envelope (AC-002) and the `google-gemini-cli`
//! projection on the same dialect (AC-003). Dialect selection keys on the
//! literal connection id; each id owns its recorded envelope and origin
//! set and neither projection is reused for the other.
//!
//! The Antigravity wire contract is the pinned envelope: `POST
//! {origin}/v1internal:streamGenerateContent?alt=sse` to the recorded
//! daily origin, or the recorded sandbox origin when the connection names
//! it. The bearer comes from the account/project profile, and the body's
//! top level carries `project`, `model`, `request`, `requestId`,
//! `userAgent` and `requestType`, with the Gemini request builder's
//! `contents`/`tools`/`generationConfig` nested under `request` beside the
//! Antigravity `sessionId`, `labels` and role-tagged `systemInstruction`.
//! The model class is the profile's pinned `classes` entry for the
//! manifest model — `gemini`, `anthropic` or `gpt-oss` — never inferred
//! from the model name; the `anthropic` class is the one that labels the
//! request `used_claude`. A model outside the map denies
//! [`ProviderError::ModelClassUnresolved`] before any request. The
//! recorded failover is narrow: a daily-origin attempt that fails before
//! its stream starts — a transport timeout/connect failure or a transient
//! status — retries the sandbox origin exactly once. A non-transient
//! status such as 403 is the peer's verdict, and a failure after content
//! was observed never fails over.
//!
//! The Gemini CLI wire contract posts the same stream path to the recorded
//! `cloudcode-pa` origin only — no failover list — with the recorded
//! `GeminiCLI` user agent and plugin metadata. Its top level is exactly
//! `project`, `model` and `request`: no `requestId`, `userAgent`,
//! `requestType`, `labels` or `sessionId` rides it, and the system
//! instruction carries no role. The tier/project rule is applied to the
//! stored profile before the post: a blank project never sends, and a
//! tier the recorded default/free and Workspace/Standard classes do not
//! classify denies rather than sending under a guessed entitlement. An
//! Antigravity-shaped frame — the request envelope or a request-only
//! field — is a violation for this id, so no Antigravity failure or
//! envelope can be read as a Code Assist quota verdict; this module makes
//! no quota call at all.
//!
//! Both projections share the extracted Gemini codec's response leg: each
//! SSE frame is parsed once, a frame without `response` is skipped, an
//! in-band `error` is a typed failure, and a completed stream requires one
//! `finishReason` — a missing or unknown terminal is never success.
//!
//! Secret material crosses only from [`CredentialStore`] into the
//! `Authorization` header per send — never into config, manifests,
//! diagnostics or these types' `Debug` (INV-001/INV-006).

use super::antigravity_login::{
    AntigravityProfile, CODE_ASSIST_ORIGIN, CODE_ASSIST_SANDBOX_ORIGIN, LoginError, read_profile,
};
use super::gemini::{GeminiCodec, StreamOutcome};
use super::gemini_cli_login::{
    self as gemini_cli, CODE_ASSIST_ORIGIN as GEMINI_CLI_ORIGIN, CodeAssistProfile, FREE_TIER,
    LEGACY_TIER,
};
use super::login_common;
use super::{
    CredentialStore, Dialect, Provider, ProviderError, ProviderReply, TransportCause,
    TransportClass, WireAuth, check_deadline, dialect_for, forwarded_header_map,
    resolve_credential, transport, transport_status, wire_body,
};
use crate::config::{Config, Connection, FixedModel, ModelAssign};
use crate::model::RequestManifest;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// The whole-request budget every CloudCode send shares.
const REQUEST_DEADLINE: Duration = Duration::from_secs(120);

/// One physical attempt's share of the budget: half, as a *cap*. The real
/// bound is the budget still remaining when the POST starts, which the
/// share caps but cannot exceed — a slow credential resolve spends from
/// the same deadline, so no attempt may assume a full share is left. The
/// recorded failover retries once inside the same deadline, so a retry
/// starts with whatever the first attempt left, never a fresh share. A
/// single successful attempt is bounded the same way: a reply that would
/// stream past the smaller bound is cut there, which is the price of
/// fitting the recorded retry inside one deadline. The client's
/// `timeout(deadline)` stays the outer backstop.
const ATTEMPT_SHARE: u32 = 2;

/// The recorded request path and query the CloudCode stream rides.
const STREAM_PATH: &str = "v1internal:streamGenerateContent?alt=sse";

/// The recorded user agent the body states.
const USER_AGENT: &str = "antigravity";

/// The recorded request class the body states.
const REQUEST_TYPE: &str = "agent";

/// The literal Antigravity connection id this module's envelope serves.
const ANTIGRAVITY_ID: &str = "google-antigravity";

/// The literal Gemini CLI connection id this module's projection serves.
const GEMINI_CLI_ID: &str = "google-gemini-cli";

/// The recorded Gemini CLI client version the user agent states. The
/// source reads an environment override; this adapter exposes no
/// environment or configuration surface, so the recorded default is the
/// wire value.
const GEMINI_CLI_VERSION: &str = "0.46.0";

/// The recorded plugin identity every Gemini CLI request states.
const GEMINI_CLI_METADATA: &str =
    "ideType=IDE_UNSPECIFIED,platform=PLATFORM_UNSPECIFIED,pluginType=GEMINI";

/// The documented absent upstream tier id: an empty tier selects no
/// rule. The free/default and legacy ids come from the producer that
/// writes them, and the Workspace/Standard id is the consumer's own
/// classification of a stored profile.
const STANDARD_TIER: &str = "standard-tier";

/// The three recorded Antigravity model classes the profile's pinned map
/// may name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ModelClass {
    Gemini,
    Anthropic,
    GptOss,
}

impl ModelClass {
    fn recorded(value: &str) -> Option<Self> {
        match value {
            "gemini" => Some(Self::Gemini),
            "anthropic" => Some(Self::Anthropic),
            "gpt-oss" => Some(Self::GptOss),
            _ => None,
        }
    }

    /// The recorded `used_claude` label value: the Anthropic class is the
    /// one the source labels `true`.
    fn used_claude(self) -> &'static str {
        match self {
            Self::Anthropic => "true",
            Self::Gemini | Self::GptOss => "false",
        }
    }
}

/// The `google-antigravity` adapter. Constructed per connection; the
/// Broker owns the handle.
pub struct CloudCodeProvider {
    /// The literal connection id this adapter serves.
    connection: String,
    /// The configured origin, trimmed; empty resolves the recorded daily
    /// origin.
    endpoint: String,
    /// The recorded failover target: the sandbox origin for a daily
    /// configuration, `None` for the sandbox origin itself and for a proof
    /// loopback peer. Set for proof legs by [`Self::with_fallback`].
    fallback: Option<String>,
    /// The scoped credential binding resolved under DEC-013 precedence.
    auth: WireAuth,
    store: Arc<dyn CredentialStore>,
    client: reqwest::blocking::Client,
    /// The one budget credential resolution and the stream share.
    deadline: Duration,
    /// The extracted Gemini request and stream codec, read through its
    /// CloudCode leg.
    codec: GeminiCodec,
    /// The per-conversation identity the recorded `requestId` names.
    agent_id: String,
    trajectory_id: String,
    /// The first user text's signed-decimal session id, fixed on the
    /// first send and stable across the conversation's turns.
    session_id: Option<String>,
    /// The next request's step: the recorded client starts at 2.
    step: u64,
    /// The last completed response id the next request echoes as
    /// `last_execution_id`.
    last_execution_id: Option<String>,
}

impl CloudCodeProvider {
    /// Builds the Antigravity adapter for its one literal id
    /// `google-antigravity`: any other id — the sibling CloudCode
    /// projection included — is a dialect mismatch. The connection must
    /// be declared, carry no configured region — the recorded class has
    /// none — and resolve a scoped credential under DEC-013 precedence.
    /// The configured endpoint admits exactly the recorded daily and
    /// sandbox origins, the empty default (the daily origin), and an
    /// admitted loopback http contract peer; every other origin denies
    /// before a request. A send shares one whole-request budget: a single
    /// request attempt is capped at half the deadline, and the recorded
    /// failover retry is bounded by the budget still remaining when it
    /// starts — never a second full share.
    ///
    /// # Errors
    /// [`ProviderError::DialectMismatch`] for any id but the literal
    /// `google-antigravity`; [`ProviderError::UnknownConnection`] for an
    /// undeclared id; [`ProviderError::RegionMismatch`] for a configured
    /// region; [`resolve_credential`]'s typed denials for a missing,
    /// malformed or mismatched binding; [`ProviderError::Transport`] when
    /// the HTTP client cannot be built.
    pub fn new(
        config: &Config,
        connection: &str,
        store: Arc<dyn CredentialStore>,
    ) -> Result<Self, ProviderError> {
        Self::build(config, connection, store, REQUEST_DEADLINE)
    }

    /// The same literal id and admitted endpoint set as [`Self::new`],
    /// under an explicit whole-request deadline — the bound is adapter
    /// policy; proof legs pin a short one so the budget is exercised
    /// deterministically. The same half-deadline attempt cap and
    /// remaining-budget retry bound apply.
    ///
    /// # Errors
    /// [`Self::new`]'s contract.
    pub fn with_deadline(
        config: &Config,
        connection: &str,
        store: Arc<dyn CredentialStore>,
        deadline: Duration,
    ) -> Result<Self, ProviderError> {
        Self::build(config, connection, store, deadline)
    }

    /// The same adapter with an explicit failover target — the proof seam
    /// for the recorded daily-to-sandbox rule; production construction
    /// derives the target from the configured origin. The target is
    /// admitted under the same recorded endpoint set [`Self::new`] admits
    /// — the daily and sandbox origins, the empty default and a loopback
    /// http contract peer — so a foreign origin can never enter.
    ///
    /// # Errors
    /// [`ProviderError::CredentialBaseMismatch`] for a target outside the
    /// recorded endpoint set.
    pub fn with_fallback(mut self, fallback: &str) -> Result<Self, ProviderError> {
        self.fallback = Some(recorded_origin(&self.connection, fallback)?);
        Ok(self)
    }

    fn build(
        config: &Config,
        connection: &str,
        store: Arc<dyn CredentialStore>,
        deadline: Duration,
    ) -> Result<Self, ProviderError> {
        if connection != ANTIGRAVITY_ID || dialect_for(connection) != Some(Dialect::CloudCode) {
            return Err(ProviderError::DialectMismatch {
                connection: connection.to_string(),
            });
        }
        let conn =
            config
                .connections
                .get(connection)
                .ok_or_else(|| ProviderError::UnknownConnection {
                    connection: connection.to_string(),
                })?;
        if let Some(region) = &conn.region {
            return Err(ProviderError::RegionMismatch {
                connection: connection.to_string(),
                region: region.clone(),
            });
        }
        let auth = WireAuth::Store(Some(resolve_credential(config, connection)?));
        let client = reqwest::blocking::Client::builder()
            .timeout(deadline)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|err| transport(connection, err))?;
        let endpoint = conn.endpoint.trim().trim_end_matches('/').to_string();
        Ok(Self {
            connection: connection.to_string(),
            fallback: recorded_fallback(&endpoint),
            endpoint,
            auth,
            store,
            client,
            deadline,
            codec: GeminiCodec::new(connection),
            agent_id: uuid::Uuid::new_v4().to_string(),
            trajectory_id: uuid::Uuid::new_v4().to_string(),
            session_id: None,
            step: 1,
            last_execution_id: None,
        })
    }

    /// The recorded origin this profile path reaches: the configured daily
    /// or sandbox origin, the recorded daily default for an absent
    /// endpoint, or an admitted loopback contract peer. Any other origin
    /// would carry the bearer to a foreign host, so it denies before the
    /// post.
    fn origin(&self) -> Result<String, ProviderError> {
        recorded_origin(&self.connection, &self.endpoint)
    }

    /// The stored account/project profile this send authenticates with —
    /// the only place secret bytes cross the store boundary. A malformed
    /// artifact or a blank token is a typed denial, never a credential
    /// guess.
    fn profile(&self) -> Result<AntigravityProfile, ProviderError> {
        let WireAuth::Store(Some(reference)) = &self.auth else {
            return Err(ProviderError::CredentialUnresolved {
                connection: self.connection.clone(),
                scope: format!("connections.{}.credential_ref", self.connection),
                cause: None,
            });
        };
        match read_profile(self.store.as_ref(), reference) {
            Ok(profile) if profile.access_token().trim().is_empty() => {
                Err(ProviderError::CredentialMalformed {
                    connection: self.connection.clone(),
                })
            }
            Ok(profile) => Ok(profile),
            Err(LoginError::Provider(error)) => Err(error),
            Err(_malformed) => Err(ProviderError::CredentialMalformed {
                connection: self.connection.clone(),
            }),
        }
    }

    /// The model's recorded class from the profile's pinned map; a model
    /// outside the three recorded classes denies before any request.
    fn class_for(
        &self,
        profile: &AntigravityProfile,
        model: &str,
    ) -> Result<ModelClass, ProviderError> {
        profile
            .classes()
            .get(model)
            .and_then(|class| ModelClass::recorded(class))
            .ok_or_else(|| ProviderError::ModelClassUnresolved {
                connection: self.connection.clone(),
                model: model.to_string(),
            })
    }

    /// The session's signed-decimal id, derived from the first user text
    /// on the first send and stable across the conversation's turns.
    fn session_id(&mut self, inputs: &str) -> String {
        self.session_id
            .get_or_insert_with(|| derive_session_id(inputs))
            .clone()
    }

    /// The frozen manifest as the recorded Antigravity envelope: the
    /// Gemini builder's request nested under `request` with the
    /// Antigravity role-tagged system instruction, the session id and the
    /// recorded labels; the top level carries the project, model,
    /// request id, user agent and request type.
    fn envelope(
        &mut self,
        manifest: &RequestManifest,
        project: &str,
        model: &str,
        class: ModelClass,
    ) -> Result<Value, ProviderError> {
        let mut request = self.codec.request_body(manifest)?;
        // A system instruction that is not an object keeps its shape: the
        // recorded envelope adds the role only where the field exists and
        // is addressable, never overwriting a non-object value.
        if let Some(instruction) = request
            .get_mut("systemInstruction")
            .and_then(Value::as_object_mut)
        {
            instruction.insert("role".to_string(), json!("user"));
        }
        let session_id = self.session_id(&manifest.inputs);
        self.step = self.step.saturating_add(1);
        let step = self.step;
        let mut labels = serde_json::Map::new();
        if let Some(last) = &self.last_execution_id {
            labels.insert("last_execution_id".to_string(), json!(last));
        }
        labels.insert(
            "last_step_index".to_string(),
            json!(step.saturating_sub(1).to_string()),
        );
        labels.insert(
            "trajectory_id".to_string(),
            json!(self.trajectory_id.clone()),
        );
        labels.insert("used_claude".to_string(), json!(class.used_claude()));
        labels.insert(
            "used_claude_conservative".to_string(),
            json!(class.used_claude()),
        );
        request["labels"] = Value::Object(labels);
        request["sessionId"] = json!(session_id);
        Ok(json!({
            "project": project,
            "model": model,
            "request": request,
            "requestId": format!(
                "agent/{}/{}/{}/{}",
                self.agent_id,
                unix_millis(),
                self.trajectory_id,
                step
            ),
            "userAgent": USER_AGENT,
            "requestType": REQUEST_TYPE,
        }))
    }

    /// Sends the frozen manifest as one physical CloudCode request. The
    /// origin, credential, project and class all resolve before the post,
    /// so a wrong profile or origin never puts a byte on the wire.
    ///
    /// # Errors
    /// [`ProviderError::UnpinnedModel`], [`ProviderError::DialectMismatch`],
    /// [`ProviderError::CredentialBaseMismatch`] for an origin outside the
    /// recorded set, [`ProviderError::CredentialMalformed`] or the store's
    /// typed denial for unusable material,
    /// [`ProviderError::UnsendableRequest`] for an empty project or a body
    /// over the wire bound, [`ProviderError::ModelClassUnresolved`] for a
    /// model outside the profile's pinned classes, [`ProviderError::Transport`],
    /// [`ProviderError::ProviderFailed`], [`ProviderError::UnknownTerminal`],
    /// [`ProviderError::StreamViolation`],
    /// [`ProviderError::IncompatibleOutput`] and
    /// [`ProviderError::ReasoningProvenance`] as the stream legs document.
    fn send_manifest(
        &mut self,
        manifest: &RequestManifest,
    ) -> Result<ProviderReply, ProviderError> {
        let started = Instant::now();
        // The origin is config-class and pure: resolving it first lets an
        // out-of-set endpoint deny typed even under an expired budget,
        // while an admitted origin still reaches the budget check before
        // any store or wire leg.
        let origin = self.origin()?;
        check_deadline(&self.connection, self.deadline, started)?;
        let fixed = fixed_model(&self.connection, manifest)?;
        let profile = self.profile()?;
        if profile.project().trim().is_empty() {
            return Err(ProviderError::UnsendableRequest {
                connection: self.connection.clone(),
                reason: "the profile project is empty".to_string(),
            });
        }
        let class = self.class_for(&profile, &fixed.model_id)?;
        let body = self.envelope(manifest, profile.project(), &fixed.model_id, class)?;
        let body_bytes = wire_body(&self.connection, &body)?;
        // The wire leg is the last budget check: a resolve that spent the
        // clock fails the send typed here — an expired budget never puts a
        // byte on the wire.
        check_deadline(&self.connection, self.deadline, started)?;
        // Failover is safe only before the stream starts: a transport
        // failure or an unsuccessful status means no content was observed.
        // A failure after content was read below never reaches this match.
        let (response, retried) =
            match self.post(&origin, profile.access_token(), body_bytes, started) {
                Ok(response) if response.status().is_success() => (response, false),
                Ok(response) => {
                    let status = response.status();
                    let error = transport_status(&self.connection, status);
                    if !transient_status(status) {
                        return Err(error);
                    }
                    self.retry_once(&body, profile.access_token(), started, error)?
                }
                Err(error) => {
                    if !transient_transport(&error) {
                        return Err(error);
                    }
                    self.retry_once(&body, profile.access_token(), started, error)?
                }
            };
        let StreamOutcome {
            mut reply,
            response_id,
        } = match self
            .codec
            .read_cloudcode_stream(manifest, response, self.deadline, started)
        {
            Ok(outcome) => outcome,
            // The retried leg crossed the wire, so its stream failure is
            // that second leg's too: the count rides the failure beside
            // its class, as the settlement records it.
            Err(source) if retried => {
                return Err(ProviderError::Retried {
                    wire_retries: 1,
                    source: Box::new(source),
                });
            }
            Err(source) => return Err(source),
        };
        if retried {
            reply.wire_retries = reply.wire_retries.saturating_add(1);
        }
        // The recorded source assigns on every completed stream, so a
        // stream without an id clears the slot: a stale id never rides
        // the next request's `last_execution_id`.
        self.last_execution_id = response_id;
        Ok(reply)
    }

    /// The one physical POST: the body crosses as the bytes the bound
    /// checked, and the shared budget is re-read immediately before it.
    /// The request timeout bounds this attempt — connect, send and its
    /// stream — by the smaller of [`ATTEMPT_SHARE`]'s cap and the budget
    /// still remaining at the post, so a slow credential resolve cannot
    /// push the attempt past the whole-request deadline. The recorded
    /// failover needs two whole requests inside one deadline: a timed-out
    /// first leg hands the retry nothing it could reuse, so the retry must
    /// start its own connect and stream, and only a reserved share keeps
    /// both inside the budget. The deliberate cost is that a *single*
    /// successful attempt is bounded the same way: a reply whose stream
    /// would run past its share is cut at the request timeout even though
    /// the whole deadline could have admitted it. The client's own
    /// `timeout(deadline)` stays the outer backstop.
    fn post(
        &self,
        origin: &str,
        token: &str,
        body: Vec<u8>,
        started: Instant,
    ) -> Result<reqwest::blocking::Response, ProviderError> {
        check_deadline(&self.connection, self.deadline, started)?;
        let remaining = self
            .deadline
            .saturating_sub(started.elapsed())
            .min(self.deadline / ATTEMPT_SHARE);
        self.client
            .post(format!("{origin}/{STREAM_PATH}"))
            .timeout(remaining)
            .bearer_auth(token)
            // The recorded source derives its Antigravity `User-Agent` from
            // a live update manifest; no recorded version exists in this
            // slice, so the leg sends none rather than inventing one. The
            // envelope's `userAgent` member is the recorded body field
            // AC-002 names; capability headers are HZN-108.
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::ACCEPT, "text/event-stream")
            .headers(forwarded_header_map(self.auth.forwarded()))
            .body(body)
            .send()
            .map_err(|err| transport(&self.connection, err))
    }

    /// One retry against the recorded failover target. No target or a
    /// non-transient first failure returns the first error unchanged. A
    /// spent budget returns the fresh expiry rather than a retry. A retry
    /// that provably never left the client — a connect or builder
    /// failure — returns the first error and is not counted as a crossed
    /// leg; one that crossed the wire and failed is a single typed
    /// failure carrying that one-leg count.
    fn retry_once(
        &self,
        body: &Value,
        token: &str,
        started: Instant,
        first_error: ProviderError,
    ) -> Result<(reqwest::blocking::Response, bool), ProviderError> {
        let Some(fallback) = &self.fallback else {
            return Err(first_error);
        };
        check_deadline(&self.connection, self.deadline, started)?;
        let retry_body = wire_body(&self.connection, body)?;
        let retry = match self.post(fallback, token, retry_body, started) {
            Ok(response) if response.status().is_success() => return Ok((response, true)),
            Ok(response) => transport_status(&self.connection, response.status()),
            Err(source) => source,
        };
        // A retry the budget refused before the POST never crossed the
        // wire, so it is not counted as a leg.
        if matches!(
            &retry,
            ProviderError::Transport { cause, .. }
                if cause.class() == TransportClass::DeadlineExpired
        ) {
            return Err(retry);
        }
        // A connect or builder failure provably never left the client:
        // the first failure remains the reported one and no leg is
        // counted.
        if never_left_the_client(&retry) {
            return Err(first_error);
        }
        Err(ProviderError::Retried {
            wire_retries: 1,
            source: Box::new(retry),
        })
    }
}

/// The pinned model both CloudCode projections require. An auto
/// assignment is refused typed: the wire model must be named rather than
/// resolved from a catalogue neither projection holds, and a pin naming
/// another connection is a dialect mismatch.
fn fixed_model(connection: &str, manifest: &RequestManifest) -> Result<FixedModel, ProviderError> {
    let fixed = match &manifest.model {
        ModelAssign::Fixed(fixed) => fixed.clone(),
        _ => {
            return Err(ProviderError::UnpinnedModel {
                connection: connection.to_string(),
            });
        }
    };
    if fixed.connection != connection {
        return Err(ProviderError::DialectMismatch {
            connection: fixed.connection,
        });
    }
    Ok(fixed)
}

/// The recorded origin a configured endpoint resolves: empty is the
/// recorded daily origin, the two recorded constants are themselves, and a
/// loopback http contract peer is admitted for proof legs. Every other
/// value — including an https loopback or a foreign host — denies typed
/// before any request.
fn recorded_origin(connection: &str, endpoint: &str) -> Result<String, ProviderError> {
    if endpoint.is_empty() {
        return Ok(CODE_ASSIST_ORIGIN.to_string());
    }
    if endpoint == CODE_ASSIST_SANDBOX_ORIGIN
        || login_common::admitted_endpoint(endpoint, CODE_ASSIST_ORIGIN)
    {
        return Ok(endpoint.to_string());
    }
    Err(ProviderError::CredentialBaseMismatch {
        connection: connection.to_string(),
        enrolled: login_common::endpoint_origin(endpoint),
    })
}

/// The recorded failover target of a configured origin: the daily origin —
/// explicit or the empty default — fails over to the sandbox origin; the
/// sandbox origin is terminal, and a proof loopback peer never fails over
/// unless the proof sets the target explicitly.
fn recorded_fallback(endpoint: &str) -> Option<String> {
    (endpoint.is_empty() || endpoint == CODE_ASSIST_ORIGIN)
        .then(|| CODE_ASSIST_SANDBOX_ORIGIN.to_string())
}

/// The recorded transient status a first attempt may fail over on: the
/// client-timeout, rate-limit and server-error classes. Every other status,
/// including 403, is the peer's verdict and never fails over.
fn transient_status(status: reqwest::StatusCode) -> bool {
    status == reqwest::StatusCode::REQUEST_TIMEOUT
        || status == reqwest::StatusCode::TOO_MANY_REQUESTS
        || status.is_server_error()
}

/// Whether a transport failure provably never left the client: a connect
/// or builder failure. A timeout can happen after hand-off, so it is not
/// this class.
fn never_left_the_client(error: &ProviderError) -> bool {
    matches!(
        error,
        ProviderError::Transport {
            cause: TransportCause::Request { source },
            ..
        } if source.is_connect() || source.is_builder()
    )
}

/// Whether a first-attempt failure is the recorded transient transport
/// class: a request timeout, or a connect/build failure whose request
/// provably never left the client. A read failure belongs to an
/// already-started stream, an expired budget is the whole-request
/// verdict, and reqwest's other request failures include send and
/// hand-off errors that may already have crossed the wire — none fails
/// over.
fn transient_transport(error: &ProviderError) -> bool {
    let ProviderError::Transport { cause, .. } = error else {
        return false;
    };
    match cause {
        TransportCause::Request { source } => {
            source.is_timeout() || source.is_connect() || source.is_builder()
        }
        TransportCause::Read { .. } | TransportCause::Deadline { .. } => false,
        TransportCause::Status { .. } => false,
    }
}

/// The recorded signed-decimal session id: the first eight bytes of the
/// SHA-256 over the session's first user text, masked to int63 and
/// rendered with a leading minus.
fn derive_session_id(text: &str) -> String {
    let digest = Sha256::digest(text.as_bytes());
    let mut value: u64 = 0;
    for byte in digest.iter().take(8) {
        value = (value << 8) | u64::from(*byte);
    }
    format!("-{}", value & ((1 << 63) - 1))
}

/// The epoch millisecond the recorded `requestId` names.
fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

/// The recorded origin a Gemini CLI endpoint resolves: empty is the
/// recorded `cloudcode-pa` origin, the constant is itself, and a loopback
/// http contract peer is admitted for proof legs. Every other value —
/// including the Antigravity daily and sandbox origins — denies typed
/// before any request.
fn gemini_cli_origin(connection: &str, endpoint: &str) -> Result<String, ProviderError> {
    if endpoint.is_empty() {
        return Ok(GEMINI_CLI_ORIGIN.to_string());
    }
    if endpoint == GEMINI_CLI_ORIGIN || login_common::admitted_endpoint(endpoint, GEMINI_CLI_ORIGIN)
    {
        return Ok(endpoint.to_string());
    }
    Err(ProviderError::CredentialBaseMismatch {
        connection: connection.to_string(),
        enrolled: login_common::endpoint_origin(endpoint),
    })
}

/// The Gemini CLI top level: exactly the bound project, the pinned model
/// and the Gemini request — no Antigravity envelope member rides it. The
/// request must carry none of the Antigravity request-only members; one
/// that does is refused here, so the shared builder can never leak the
/// other projection's fields onto this wire.
fn gemini_cli_envelope(
    connection: &str,
    project: &str,
    model: &str,
    request: Value,
) -> Result<Value, ProviderError> {
    let antigravity_only = request.get("sessionId").is_some()
        || request.get("labels").is_some()
        || request
            .get("systemInstruction")
            .and_then(|instruction| instruction.get("role"))
            .is_some();
    if antigravity_only {
        return Err(ProviderError::UnsendableRequest {
            connection: connection.to_string(),
            reason: "the request carries an antigravity-only field".to_string(),
        });
    }
    Ok(json!({
        "project": project,
        "model": model,
        "request": request,
    }))
}

/// The recorded Gemini CLI user agent:
/// `GeminiCLI/<version>/<model> (<platform>; <arch>; terminal)`, in the
/// platform and architecture spellings the recorded client reports.
fn gemini_cli_user_agent(model: &str) -> String {
    format!(
        "GeminiCLI/{GEMINI_CLI_VERSION}/{model} ({}; {}; terminal)",
        node_platform(),
        node_arch()
    )
}

/// The recorded client's platform name: the Node spellings, not the
/// Rust target triple's.
fn node_platform() -> &'static str {
    match std::env::consts::OS {
        "macos" => "darwin",
        "windows" => "win32",
        platform => platform,
    }
}

/// The recorded client's architecture name: the Node spellings, not the
/// Rust target triple's.
fn node_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        arch => arch,
    }
}

impl std::fmt::Debug for CloudCodeProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The scoped ref is the visible token — the store and its
        // material never enter diagnostics (INV-001).
        f.debug_struct("CloudCodeProvider")
            .field("connection", &self.connection)
            .field("endpoint", &self.endpoint)
            .field("auth", &self.auth)
            .field("deadline", &self.deadline)
            .finish_non_exhaustive()
    }
}

impl Provider for CloudCodeProvider {
    fn name(&self) -> &'static str {
        ANTIGRAVITY_ID
    }

    /// The adapter serves only the literal connection id its dialect was
    /// constructed for (DEC-007).
    fn serves(&self, connection: &str, _entry: &Connection) -> bool {
        connection == self.connection
    }

    fn send(&mut self, manifest: &RequestManifest) -> Result<ProviderReply, ProviderError> {
        self.send_manifest(manifest)
    }
}

/// The `google-gemini-cli` adapter: the Gemini CLI projection of the
/// CloudCode `v1internal` dialect. Constructed per connection; the Broker
/// owns the handle.
pub struct GeminiCliProvider {
    /// The literal connection id this adapter serves.
    connection: String,
    /// The configured origin, trimmed; empty resolves the recorded
    /// `cloudcode-pa` origin.
    endpoint: String,
    /// The scoped credential binding resolved under DEC-013 precedence.
    auth: WireAuth,
    store: Arc<dyn CredentialStore>,
    client: reqwest::blocking::Client,
    /// The one budget credential resolution and the stream share.
    deadline: Duration,
    /// The extracted Gemini request and stream codec, read through its
    /// Gemini CLI leg.
    codec: GeminiCodec,
}

impl GeminiCliProvider {
    /// Builds the adapter for its literal connection id: the id must record
    /// the CloudCode dialect and be `google-gemini-cli`, the connection must
    /// be declared, carry no configured region — the recorded class has
    /// none — and resolve a scoped credential under DEC-013 precedence.
    /// The configured endpoint admits exactly the recorded `cloudcode-pa`
    /// origin, the empty default (that same origin), and an admitted
    /// loopback http contract peer; every other origin denies before a
    /// request.
    ///
    /// # Errors
    /// [`ProviderError::DialectMismatch`] for any other connection id;
    /// [`ProviderError::UnknownConnection`] for an undeclared id;
    /// [`ProviderError::RegionMismatch`] for a configured region;
    /// [`resolve_credential`]'s typed denials for a missing, malformed or
    /// mismatched binding; [`ProviderError::Transport`] when the HTTP
    /// client cannot be built.
    pub fn new(
        config: &Config,
        connection: &str,
        store: Arc<dyn CredentialStore>,
    ) -> Result<Self, ProviderError> {
        Self::build(config, connection, store, REQUEST_DEADLINE)
    }

    /// The same adapter under an explicit whole-request deadline — the
    /// bound is adapter policy; proof legs pin a short one so the budget
    /// is exercised deterministically.
    ///
    /// # Errors
    /// [`Self::new`]'s contract.
    pub fn with_deadline(
        config: &Config,
        connection: &str,
        store: Arc<dyn CredentialStore>,
        deadline: Duration,
    ) -> Result<Self, ProviderError> {
        Self::build(config, connection, store, deadline)
    }

    fn build(
        config: &Config,
        connection: &str,
        store: Arc<dyn CredentialStore>,
        deadline: Duration,
    ) -> Result<Self, ProviderError> {
        if connection != GEMINI_CLI_ID || dialect_for(connection) != Some(Dialect::CloudCode) {
            return Err(ProviderError::DialectMismatch {
                connection: connection.to_string(),
            });
        }
        let conn =
            config
                .connections
                .get(connection)
                .ok_or_else(|| ProviderError::UnknownConnection {
                    connection: connection.to_string(),
                })?;
        if let Some(region) = &conn.region {
            return Err(ProviderError::RegionMismatch {
                connection: connection.to_string(),
                region: region.clone(),
            });
        }
        let auth = WireAuth::Store(Some(resolve_credential(config, connection)?));
        let client = reqwest::blocking::Client::builder()
            .timeout(deadline)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|err| transport(connection, err))?;
        Ok(Self {
            connection: connection.to_string(),
            endpoint: conn.endpoint.trim().trim_end_matches('/').to_string(),
            auth,
            store,
            client,
            deadline,
            codec: GeminiCodec::new(connection),
        })
    }

    /// The recorded origin this send reaches: the configured
    /// `cloudcode-pa` origin, the recorded default for an absent endpoint,
    /// or an admitted loopback contract peer. Any other host would carry
    /// the bearer elsewhere, so it denies before the post.
    fn origin(&self) -> Result<String, ProviderError> {
        gemini_cli_origin(&self.connection, &self.endpoint)
    }

    /// The stored tier/project profile this send authenticates with — the
    /// only place secret bytes cross the store boundary. A malformed
    /// artifact or a blank token is a typed denial, never a credential
    /// guess.
    fn profile(&self) -> Result<CodeAssistProfile, ProviderError> {
        let WireAuth::Store(Some(reference)) = &self.auth else {
            return Err(ProviderError::CredentialUnresolved {
                connection: self.connection.clone(),
                scope: format!("connections.{}.credential_ref", self.connection),
                cause: None,
            });
        };
        match gemini_cli::read_profile(self.store.as_ref(), reference) {
            Ok(profile) if profile.access_token().trim().is_empty() => {
                Err(ProviderError::CredentialMalformed {
                    connection: self.connection.clone(),
                })
            }
            Ok(profile) => Ok(profile),
            Err(gemini_cli::LoginError::Provider(error)) => Err(error),
            Err(_malformed) => Err(ProviderError::CredentialMalformed {
                connection: self.connection.clone(),
            }),
        }
    }

    /// The recorded tier/project rule, applied before the post: the
    /// producer binds a project, so a blank one is never sendable, and the
    /// stored tier must be one the rule classifies — the free/default
    /// class, the default fallback, the Workspace/Standard class, or the
    /// empty string that documents an absent upstream current-tier id and
    /// selects no rule. A tier outside that set is denied rather than sent
    /// under a guessed entitlement.
    fn gate(&self, profile: &CodeAssistProfile) -> Result<(), ProviderError> {
        if profile.project().trim().is_empty() {
            return Err(ProviderError::UnsendableRequest {
                connection: self.connection.clone(),
                reason: "the profile project is empty".to_string(),
            });
        }
        match profile.tier() {
            "" | FREE_TIER | LEGACY_TIER | STANDARD_TIER => Ok(()),
            _ => Err(ProviderError::UnsendableRequest {
                connection: self.connection.clone(),
                reason: "the stored tier is outside the recorded tier rule".to_string(),
            }),
        }
    }

    /// Sends the frozen manifest as one physical Gemini CLI request. The
    /// origin, credential, tier and project all resolve before the post,
    /// so a wrong profile or origin never puts a byte on the wire.
    ///
    /// # Errors
    /// [`ProviderError::UnpinnedModel`], [`ProviderError::DialectMismatch`],
    /// [`ProviderError::CredentialBaseMismatch`] for an origin outside the
    /// recorded set, [`ProviderError::CredentialMalformed`] or the store's
    /// typed denial for unusable material, [`ProviderError::UnsendableRequest`]
    /// for a blank project, an unclassified tier or a body over the wire
    /// bound, and the codec's typed transport, provider and stream
    /// denials.
    fn send_manifest(
        &mut self,
        manifest: &RequestManifest,
    ) -> Result<ProviderReply, ProviderError> {
        let started = Instant::now();
        // The origin is config-class and pure: resolving it first lets an
        // out-of-set endpoint deny typed even under an expired budget.
        let origin = self.origin()?;
        check_deadline(&self.connection, self.deadline, started)?;
        let fixed = fixed_model(&self.connection, manifest)?;
        let profile = self.profile()?;
        self.gate(&profile)?;
        let body = gemini_cli_envelope(
            &self.connection,
            profile.project(),
            &fixed.model_id,
            self.codec.request_body(manifest)?,
        )?;
        let body_bytes = wire_body(&self.connection, &body)?;
        // The wire leg is the last budget check: an expired budget never
        // puts a byte on the wire.
        check_deadline(&self.connection, self.deadline, started)?;
        let response = self.post(
            &origin,
            profile.access_token(),
            &fixed.model_id,
            body_bytes,
            started,
        )?;
        if !response.status().is_success() {
            return Err(transport_status(&self.connection, response.status()));
        }
        // The Gemini CLI projection keeps no response-id state: the shared
        // reader's id is not a wire field this projection echoes.
        let StreamOutcome { reply, .. } =
            self.codec
                .read_gemini_cli_stream(manifest, response, self.deadline, started)?;
        Ok(reply)
    }

    /// The one physical POST: the recorded bearer, JSON and SSE headers
    /// plus the Gemini CLI user agent and plugin metadata; the body crosses
    /// as the bytes the bound checked. This projection sends one attempt
    /// with no retry to share the budget, so its request timeout is the
    /// budget still remaining at the post — never more than the whole
    /// deadline — and stalling anywhere inside the attempt, including a
    /// slow credential resolve before it, cannot outlive the deadline.
    fn post(
        &self,
        origin: &str,
        token: &str,
        model: &str,
        body: Vec<u8>,
        started: Instant,
    ) -> Result<reqwest::blocking::Response, ProviderError> {
        check_deadline(&self.connection, self.deadline, started)?;
        let remaining = self.deadline.saturating_sub(started.elapsed());
        self.client
            .post(format!("{origin}/{STREAM_PATH}"))
            .timeout(remaining)
            .bearer_auth(token)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::ACCEPT, "text/event-stream")
            .header(reqwest::header::USER_AGENT, gemini_cli_user_agent(model))
            .header("Client-Metadata", GEMINI_CLI_METADATA)
            .headers(forwarded_header_map(self.auth.forwarded()))
            .body(body)
            .send()
            .map_err(|err| transport(&self.connection, err))
    }
}

impl std::fmt::Debug for GeminiCliProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The scoped ref is the visible token — the store and its
        // material never enter diagnostics (INV-001).
        f.debug_struct("GeminiCliProvider")
            .field("connection", &self.connection)
            .field("endpoint", &self.endpoint)
            .field("auth", &self.auth)
            .field("deadline", &self.deadline)
            .finish_non_exhaustive()
    }
}

impl Provider for GeminiCliProvider {
    fn name(&self) -> &'static str {
        GEMINI_CLI_ID
    }

    /// The adapter serves only its literal connection id (DEC-007).
    fn serves(&self, connection: &str, _entry: &Connection) -> bool {
        connection == self.connection
    }

    fn send(&mut self, manifest: &RequestManifest) -> Result<ProviderReply, ProviderError> {
        self.send_manifest(manifest)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ANTIGRAVITY_ID, CODE_ASSIST_ORIGIN, CODE_ASSIST_SANDBOX_ORIGIN, CloudCodeProvider,
        GEMINI_CLI_ID, GEMINI_CLI_ORIGIN, derive_session_id, gemini_cli_envelope,
        gemini_cli_origin, recorded_fallback, recorded_origin,
    };
    use crate::config::Config;
    use crate::providers::{CredentialStore, ProviderError, SecretRef, StoreKind};
    use serde_json::json;
    use std::sync::Arc;

    /// The recorded endpoint set is exactly the two constants plus a
    /// loopback http peer: an absent endpoint resolves daily, the sandbox
    /// constant is itself, and every foreign origin — including an https
    /// loopback — denies typed before any request.
    #[test]
    fn recorded_origins_are_the_only_admitted_endpoints() {
        assert_eq!(
            recorded_origin("google-antigravity", "").unwrap(),
            CODE_ASSIST_ORIGIN
        );
        assert_eq!(
            recorded_origin("google-antigravity", CODE_ASSIST_ORIGIN).unwrap(),
            CODE_ASSIST_ORIGIN
        );
        assert_eq!(
            recorded_origin("google-antigravity", CODE_ASSIST_SANDBOX_ORIGIN).unwrap(),
            CODE_ASSIST_SANDBOX_ORIGIN
        );
        assert_eq!(
            recorded_origin("google-antigravity", "http://127.0.0.1:9").unwrap(),
            "http://127.0.0.1:9"
        );
        for foreign in [
            "https://cloudcode-pa.googleapis.com",
            "https://foreign.example.invalid",
            "https://127.0.0.1:9",
            "http://10.0.0.1",
        ] {
            assert!(
                matches!(
                    recorded_origin("google-antigravity", foreign),
                    Err(ProviderError::CredentialBaseMismatch { .. })
                ),
                "{foreign} is outside the recorded endpoint set"
            );
        }
    }

    /// The recorded failover target: only the daily origin (explicit or the
    /// empty default) falls over to the sandbox origin; the sandbox origin
    /// and a proof loopback are terminal.
    #[test]
    fn only_the_daily_origin_records_the_sandbox_fallback() {
        assert_eq!(
            recorded_fallback(""),
            Some(CODE_ASSIST_SANDBOX_ORIGIN.to_string())
        );
        assert_eq!(
            recorded_fallback(CODE_ASSIST_ORIGIN),
            Some(CODE_ASSIST_SANDBOX_ORIGIN.to_string())
        );
        assert_eq!(recorded_fallback(CODE_ASSIST_SANDBOX_ORIGIN), None);
        assert_eq!(recorded_fallback("http://127.0.0.1:9"), None);
    }

    /// The recorded session id is the SHA-256 prefix masked to int63 and
    /// rendered with a leading minus: the pinned vectors cover a digest
    /// whose top bit is clear and one whose top bit the mask clears.
    #[test]
    fn session_ids_are_masked_signed_decimals() {
        assert_eq!(derive_session_id("hello"), "-3238736544897475342");
        assert_eq!(derive_session_id("a"), "-5374906597990186442");
        assert_ne!(derive_session_id("a"), derive_session_id("b"));
    }

    /// The Gemini CLI endpoint set is exactly the recorded `cloudcode-pa`
    /// constant plus a loopback http peer: the Antigravity daily and
    /// sandbox origins are refused, so a 403 from either is unreachable
    /// from this id.
    #[test]
    fn gemini_cli_origins_exclude_the_antigravity_hosts() {
        assert_eq!(
            gemini_cli_origin(GEMINI_CLI_ID, "").unwrap(),
            GEMINI_CLI_ORIGIN
        );
        assert_eq!(
            gemini_cli_origin(GEMINI_CLI_ID, "http://127.0.0.1:9").unwrap(),
            "http://127.0.0.1:9"
        );
        for foreign in [
            CODE_ASSIST_ORIGIN,
            CODE_ASSIST_SANDBOX_ORIGIN,
            "https://foreign.example.invalid",
            "https://127.0.0.1:9",
            "http://10.0.0.1",
        ] {
            assert!(
                matches!(
                    gemini_cli_origin(GEMINI_CLI_ID, foreign),
                    Err(ProviderError::CredentialBaseMismatch { .. })
                ),
                "{foreign} is outside the Gemini CLI endpoint set"
            );
        }
    }

    /// The Gemini CLI projection refuses the Antigravity request shape: a
    /// body carrying the Antigravity session id, labels or system role is
    /// never wrapped, while the plain Gemini request rides through.
    #[test]
    fn gemini_cli_refuses_the_antigravity_request_shape() {
        let antigravity_shaped = json!({
            "contents": [{ "role": "user", "parts": [{ "text": "goal" }] }],
            "systemInstruction": {
                "role": "user",
                "parts": [{ "text": "rules" }],
            },
            "sessionId": "-1",
            "labels": { "trajectory_id": "trajectory-1" },
        });
        assert!(matches!(
            gemini_cli_envelope(GEMINI_CLI_ID, "project", "model", antigravity_shaped),
            Err(ProviderError::UnsendableRequest { .. })
        ));
        for member in ["sessionId", "labels"] {
            let mut request = json!({
                "contents": [{ "role": "user", "parts": [{ "text": "goal" }] }],
            });
            request[member] = json!("antigravity");
            assert!(
                matches!(
                    gemini_cli_envelope(GEMINI_CLI_ID, "project", "model", request),
                    Err(ProviderError::UnsendableRequest { .. })
                ),
                "{member} is refused on its own"
            );
        }
        let role_only = json!({
            "systemInstruction": {
                "role": "user",
                "parts": [{ "text": "rules" }],
            },
        });
        assert!(matches!(
            gemini_cli_envelope(GEMINI_CLI_ID, "project", "model", role_only),
            Err(ProviderError::UnsendableRequest { .. })
        ));

        let plain = json!({
            "contents": [{ "role": "user", "parts": [{ "text": "goal" }] }],
            "systemInstruction": { "parts": [{ "text": "rules" }] },
        });
        let envelope =
            gemini_cli_envelope(GEMINI_CLI_ID, "project", "model", plain.clone()).unwrap();
        assert_eq!(
            envelope,
            json!({
                "project": "project",
                "model": "model",
                "request": plain,
            })
        );
    }

    /// The build leg derives the failover target from the configured
    /// origin itself, so the wire legs are not its only proof: an absent
    /// or daily endpoint records the sandbox origin, while the sandbox
    /// origin and a proof loopback peer are terminal.
    #[test]
    fn the_built_adapter_derives_the_recorded_fallback() {
        for (endpoint, expected) in [
            ("", Some(CODE_ASSIST_SANDBOX_ORIGIN)),
            (CODE_ASSIST_ORIGIN, Some(CODE_ASSIST_SANDBOX_ORIGIN)),
            (CODE_ASSIST_SANDBOX_ORIGIN, None),
            ("http://127.0.0.1:9", None),
        ] {
            let provider =
                CloudCodeProvider::new(&config(endpoint), ANTIGRAVITY_ID, Arc::new(EmptyStore))
                    .expect("the recorded endpoint set builds");
            assert_eq!(provider.fallback.as_deref(), expected, "{endpoint:?}");
        }
    }

    /// The recorded config shape one CloudCode connection declares; the
    /// build leg resolves the binding without reading the store.
    fn config(endpoint: &str) -> Config {
        Config::parse_validated(&format!(
            "config_version = 1\n\
             [connections.{ANTIGRAVITY_ID}]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\ncredential_ref = \"keyring:rivect-test/{ANTIGRAVITY_ID}\"\nprofile = \"{ANTIGRAVITY_ID}\"\n\
             [profiles.{ANTIGRAVITY_ID}]\ncredential_ref = \"keyring:rivect-test/{ANTIGRAVITY_ID}\"\n\
             [models.defaults]\nmodel = {{ mode = \"fixed\", connection = \"{ANTIGRAVITY_ID}\", model_id = \"gemini-2.5-flash\" }}\neffort = {{ mode = \"fixed\", value = \"medium\" }}\nfallback = {{ mode = \"off\" }}\n"
        ))
        .expect("the fixture config parses")
    }

    /// The build leg never reads the store, so an empty scope still
    /// builds the adapter.
    struct EmptyStore;

    impl CredentialStore for EmptyStore {
        fn kind(&self) -> StoreKind {
            StoreKind::Keychain
        }

        fn occupied(&self, _credential: &SecretRef) -> Result<bool, ProviderError> {
            Ok(false)
        }

        fn entry_accounts(&self, _service: &str) -> Result<Vec<String>, ProviderError> {
            Ok(Vec::new())
        }

        fn login(&self, _credential: &SecretRef, _secret: &[u8]) -> Result<(), ProviderError> {
            Ok(())
        }

        fn resolve(&self, credential: &SecretRef) -> Result<Vec<u8>, ProviderError> {
            Err(ProviderError::CredentialAbsent {
                scope: credential.scope().to_string(),
            })
        }

        fn refresh(&self, _credential: &SecretRef, _secret: &[u8]) -> Result<(), ProviderError> {
            Ok(())
        }

        fn revoke(&self, credential: &SecretRef) -> Result<(), ProviderError> {
            Err(ProviderError::CredentialAbsent {
                scope: credential.scope().to_string(),
            })
        }

        fn logout(&self, credential: &SecretRef) -> Result<(), ProviderError> {
            self.revoke(credential)
        }
    }
}
