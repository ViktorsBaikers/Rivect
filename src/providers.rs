//! Provider adapters. The loopback provider is the owner-brokered local
//! fixture for offline proof; a production entrypoint builds the configured
//! adapter set through [`configured_provider`]. Workers never hold a
//! provider handle, only the broker does.
//!
//! The scoped credential-profile seam (SRC-010) also lives here:
//! [`SecretRef`] is the only token that crosses into config, adapters,
//! diagnostics and manifests, and [`CredentialStore`] is the only path
//! between a native secret store and an adapter — secret bytes never
//! leave the store boundary (INV-001).
//!
//! # Recorded connection contract (band 4)
//!
//! Each row is the literal id's recorded source class (HZN-008): the
//! dialect, default base, credential class and region fact its arm
//! binds. The required `endpoint` field's empty string is the sentinel
//! for the row's recorded default base, never "no host"; none of the
//! ten records a `region` field, so a configured `region` denies typed.
//! An id whose arm has not landed has no dialect and denies
//! `DialectMismatch` — a row is the recorded target, not a built-state
//! claim.
//!
//! | id | dialect | recorded default base | credential class | region |
//! | --- | --- | --- | --- | --- |
//! | `venice` | Chat Completions | `https://api.venice.ai/api/v1` | `api_key` bearer — its public listing is wire-keyless, not config-keyless | none |
//! | `vllm` | Chat Completions | `http://127.0.0.1:8000/v1` | open proxy — absent binding or server key; `kind = "local"` is the shipped headerless form | none |
//! | `wafer-serverless` | Chat Completions | `https://pass.wafer.ai/v1` | `api_key` bearer | none |
//! | `xai` | Responses | `https://api.x.ai/v1` | `api_key` bearer | none |
//! | `xai-oauth` | Responses | `https://api.x.ai/v1` | `api_key` bearer (device-code token; live login stays deferred) | none |
//! | `xiaomi` | Chat Completions | `https://api.xiaomimimo.com/v1` | `api_key` bearer (PAYG literal) | none |
//! | `xiaomi-token-plan-ams` | Chat Completions | `https://token-plan-ams.xiaomimimo.com/v1` | `api_key` bearer (token-plan literal) | none |
//! | `xiaomi-token-plan-cn` | Chat Completions | `https://token-plan-cn.xiaomimimo.com/v1` | `api_key` bearer (token-plan literal) | none |
//! | `xiaomi-token-plan-sgp` | Chat Completions | `https://token-plan-sgp.xiaomimimo.com/v1` | `api_key` bearer (token-plan literal) | none |
//! | `yolo-auto` | Chat Completions | `https://yolo-auto.com/v1` | `api_key` bearer | none |
//!
//! # Recorded routed contract (band 5)
//!
//! A routed id owns no single dialect: [`dialect_for`] stays its literal
//! default, and [`routes_for`]/[`route_for`] name the codec each model
//! rides. `gitlab-duo` is Chat Completions by default with a closed alias
//! table (Messages aliases and Responses codex aliases). Both OpenCode
//! gateways record `openai-completions` as their default resolution:
//! `opencode-go` sends `claude-*`/`qwen*`/`minimax-m2.5*` on Messages
//! (except the five CC exacts) and the GPT/Grok/Muse families plus
//! `deepseek-v4-flash` on Responses; `opencode-zen` sends
//! `claude-*`/`qwen-*` on Messages, the GPT/Grok/Muse families on
//! Responses and `gemini-*` on the Gemini dialect. A model outside a
//! closed alias table denies; every other routed id falls back to its
//! recorded default.
//!
//! `zenmux` records the platform's two fixed bases: the authoritative
//! `/api/v1` metadata listing drives the catalogue, and each model's
//! recorded class decides the route — an `anthropic/` id (the
//! metadata's owning provider) takes Messages on `/api/anthropic`,
//! everything else rides the recorded Chat Completions default. An
//! unrecorded class or id rides that default too: the class is never
//! inferred from auth, a family name or the configured default model.
//!
//! `anthropic` also carries the recorded subscription form: a
//! `kind = "subscription"` declaration stores the login module's
//! [`anthropic_login::SubscriptionCredential`] JSON at its scoped ref, and
//! the Messages adapter sends that credential's `access_token` as
//! `Authorization: Bearer` — never the stored JSON and never `x-api-key`.
//! The login lifecycle itself ([`anthropic_login`]) is library-level; no
//! CLI verb is added.
//!
//! `vercel-ai-gateway` records the gateway's Messages surface on the
//! `https://ai-gateway.vercel.sh` root: the gateway key rides
//! `Authorization: Bearer`, and the keyed `/v1/models` listing's
//! `tool-use` tag is the closed table — a row without the tag is never
//! offered, and a pin outside the tagged set denies before the body.
//!
//! `custom-messages` records the operator-configured Messages origin:
//! no default base exists, so an empty endpoint denies before the
//! wire. The origin's own `/v1/models` listing is the discovery source
//! and a manual model id sends without it, because the id records no
//! closed alias table to fall outside. Its credential is the recorded
//! custom-origin form — optional, so an unbound declaration sends
//! headerless rather than inventing a key.
//!
//! `openai-codex` records the Codex OAuth form (DEC-020): the browser
//! code+PKCE leg and its device alias both write one canonical
//! `kind = "api_key"` profile through [`openai_login`], so the Broker's
//! offline gate admits it; the subscription rule above stays untouched.
//!
//! `github-copilot` records three routes over the closed 44-id catalogue
//! table (DEC-004): every `claude-*` row rides Messages, the recorded
//! `gpt-5*`/`grok-4.5`/`grok-4.6`/`mai-*` rows ride Responses, and every
//! other row rides the Chat Completions default. A model outside the
//! table has no route at all; [`copilot`] is the only owner that builds
//! its codec, because the API base and the CAPI identity come from the
//! stored credential rather than a fixed proxy.
//!
//! `kimi-code` records the Kimi Code device/API-key form (the
//! `research/provider-coverage.md` device-code row, OMP
//! `rules/auth/kimi-code.kdl` and `providers/kimi.ts`; DEC-031 re-pinned
//! only this roster): the Messages default covers rows whose listing names
//! no `protocol`, a `chat` row rides Chat Completions, and [`kimi`] owns
//! both legs because the protocol is resolved from the model's catalogue
//! row — never from the credential class. Its Messages leg is the shared
//! `anthropic::MessagesCodec`, so the reasoning lineage is the one
//! adapter's.
//!
//! `zai` records the Z.AI GLM Coding Plan row and `zai-coding-plan` its
//! sign-in alias (the alias stores the canonical `zai` profile rather than
//! a second backend). [`zai`] serves both literals over the bundled
//! catalogue's two coding-plan transports — Messages on
//! `https://api.z.ai/api/anthropic` and native Chat Completions on
//! `https://api.z.ai/api/coding/paas/v4` — selected by the model's recorded
//! row and bound by the configured endpoint; the PAYG base is never
//! admitted, a configured region denies, and the shared Messages codec
//! carries the reasoning lineage and one-strip signature retry.

use crate::config::{Config, ConnKind, Connection, EffortLevel, ModelAssign, Profile};
use crate::model::RequestManifest;
use crate::resources::UsageDelta;
use serde_json::Value;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::io::Read;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

pub mod anthropic;
pub mod anthropic_login;
pub mod antigravity_login;
#[doc(hidden)]
pub mod aws;
pub mod bedrock;
pub mod cloudcode;
pub mod copilot;
pub mod copilot_login;
pub mod cursor_login;
pub mod devin_login;
mod eventstream;
pub mod gemini;
pub mod gemini_cli_login;
pub mod gitlab_agent_login;
pub mod gitlab_workflow;
pub mod kimi;
pub mod local;
pub(crate) mod login_common;
pub mod muse_login;
pub mod ollama_cloud;
pub mod openai;
pub mod openai_login;
pub mod routed;
pub mod sse;
pub mod vertex;
pub mod vertex_login;
pub mod zai;
pub mod zai_login;

/// The one catalogue record both dialect owners share (DEC-007):
/// defined once in the local adapter, re-exported here so the
/// Responses surface offers the same vocabulary.
pub use local::{CatalogModel, ModelPrice};

/// A stated positive whole count; absent, zero or unreadable stays `None`.
pub(crate) fn positive_count(value: Option<&Value>) -> Option<u64> {
    value
        .and_then(|value| {
            value
                .as_u64()
                .or_else(|| value.as_str().and_then(|text| text.parse::<u64>().ok()))
        })
        .filter(|count| *count > 0)
}

/// The recorded reasoning level on our effort vocabulary: a level the
/// enum cannot name never lands.
pub(crate) fn wire_effort(value: &str) -> Option<EffortLevel> {
    match value {
        "minimal" => Some(EffortLevel::Minimal),
        "low" => Some(EffortLevel::Low),
        "medium" => Some(EffortLevel::Medium),
        "high" => Some(EffortLevel::High),
        "xhigh" => Some(EffortLevel::Xhigh),
        _ => None,
    }
}

/// A URL whose host is a loopback address: any literal the standard
/// library calls loopback — `127.0.0.0/8` and `::1` — or the reserved
/// `localhost` name and its `*.localhost` children. The parsed host is
/// compared, never the raw input.
pub(crate) fn is_loopback_url(url: &reqwest::Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return ip.is_loopback();
    }
    host.eq_ignore_ascii_case("localhost")
        || matches!(
            host.rsplit_once('.'),
            Some((prefix, label)) if !prefix.is_empty() && label.eq_ignore_ascii_case("localhost")
        )
}

/// Percent-encodes everything outside the RFC 3986 unreserved set; the one
/// encoder the login forms and the Bedrock path share.
#[must_use]
pub(crate) fn percent_encode_component(raw: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
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

/// The loopback base override one adapter's wire proof may take: the
/// value is trimmed of surrounding whitespace and trailing slashes, and
/// only a loopback host over http(s) without credentials, query
/// or fragment is admitted. Every other URL — including a production
/// host and an ambiguous loopback form — is refused before any send.
pub(crate) fn loopback_base(connection: &str, raw: &str) -> Result<String, ProviderError> {
    let base = raw.trim().trim_end_matches('/');
    let url = reqwest::Url::parse(base).map_err(|_url| ProviderError::UnsendableRequest {
        connection: connection.to_string(),
        reason: "the base override is not a URL".to_string(),
    })?;
    if !is_loopback_url(&url)
        || !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(ProviderError::UnsendableRequest {
            connection: connection.to_string(),
            reason: "the base override is not a loopback endpoint".to_string(),
        });
    }
    Ok(base.to_owned())
}

#[derive(Debug, Clone, PartialEq)]
pub struct ToolCall {
    pub tool: String,
    pub path: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProviderReply {
    pub text: String,
    pub tool_calls: Vec<ToolCall>,
    /// The physical usage report of this one send (INV-022/INV-024):
    /// it travels inside the reply, so one physical send produces one
    /// accounting record — `Unknown` when the provider reported none,
    /// never an estimate and never a zero the retained bound could
    /// release as.
    pub usage: UsageDelta,
    /// How many adapter-internal corrections this physical child attempt
    /// sent before the answering one (AC-057). A retry is the same child —
    /// its first leg's usage is unknown, never zero — so the settlement
    /// carries the count instead of opening a second attempt.
    pub wire_retries: u32,
    /// How many replayed thinking blocks this physical send's peer reported
    /// dropping (AC-046): the Messages codec's per-send delta, never the
    /// cumulative counter and never provider text. The broker records it as
    /// durable evidence; the send itself succeeded.
    pub dropped_reasoning: u64,
}

/// A transport failure's programmatic class, independent of diagnostic text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportClass {
    /// The adapter observed its whole-request budget expire between calls.
    DeadlineExpired,
    /// The HTTP client or response reader timed out inside a call.
    Timeout,
    /// The HTTP client failed without a timeout.
    RequestFailure,
    /// Reading the response failed without a timeout.
    ReadFailure,
    /// The peer returned an unsuccessful HTTP status.
    HttpStatus { code: u16 },
}

/// Retained transport provenance with diagnostics that never render external source text.
///
/// Inspect sources programmatically; a timeout does not authorize retrying an unknown effect.
///
/// # Examples
///
/// ```
/// use rivect::providers::{ProviderError, TransportCause, TransportClass};
/// use std::error::Error;
/// use std::time::Duration;
///
/// fn inspect(error: &ProviderError) {
///     if let ProviderError::Transport { cause, .. } = error {
///         match cause.class() {
///             TransportClass::Timeout => { /* reconcile the external outcome before retrying */ }
///             TransportClass::DeadlineExpired => {}
///             TransportClass::RequestFailure | TransportClass::ReadFailure => {}
///             TransportClass::HttpStatus { code } => assert!((100..1000).contains(&code)),
///         }
///         let request = cause.source().and_then(|source| source.downcast_ref::<reqwest::Error>());
///         if let Some(request) = request {
///             assert_eq!(cause.class() == TransportClass::Timeout, request.is_timeout());
///         }
///         let _safe_diagnostics = (format!("{error}"), format!("{error:?}"));
///     }
/// }
/// let error = ProviderError::Transport {
///     connection: "local".into(),
///     cause: TransportCause::Deadline { budget: Duration::from_secs(1) },
/// };
/// inspect(&error);
/// ```
#[derive(Clone)]
pub enum TransportCause {
    /// The adapter's complete request budget, shared by all of its legs.
    Deadline { budget: Duration },
    /// The original HTTP client error; adapters remove its outer URL before retaining it.
    Request { source: Arc<reqwest::Error> },
    /// The original response read error, including its kind, OS code and inner source.
    Read { source: Arc<std::io::Error> },
    /// The unsuccessful response status, without the uncontrolled response body.
    Status { status: reqwest::StatusCode },
}

impl TransportCause {
    /// Classifies the retained source without parsing its diagnostic text.
    pub fn class(&self) -> TransportClass {
        match self {
            Self::Deadline { .. } => TransportClass::DeadlineExpired,
            Self::Request { source } if source.is_timeout() => TransportClass::Timeout,
            Self::Request { .. } => TransportClass::RequestFailure,
            Self::Read { source }
                if source.kind() == std::io::ErrorKind::TimedOut
                    || source
                        .get_ref()
                        .and_then(|inner| inner.downcast_ref::<reqwest::Error>())
                        .is_some_and(reqwest::Error::is_timeout) =>
            {
                TransportClass::Timeout
            }
            Self::Read { .. } => TransportClass::ReadFailure,
            Self::Status { status } => TransportClass::HttpStatus {
                code: status.as_u16(),
            },
        }
    }
}

impl std::fmt::Display for TransportCause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Deadline { budget } => write!(f, "request exceeded the {budget:?} send deadline"),
            Self::Request { source } => format_request_kind(source, f),
            Self::Read { source } => {
                if let Some(request) = source
                    .get_ref()
                    .and_then(|inner| inner.downcast_ref::<reqwest::Error>())
                {
                    return format_request_kind(request, f);
                }
                write!(f, "response read failed: {}", source.kind())?;
                if let Some(code) = source.raw_os_error() {
                    write!(f, " (os code {code})")?;
                }
                Ok(())
            }
            Self::Status { status } => write!(f, "http status {}", status.as_u16()),
        }
    }
}

fn format_request_kind(
    error: &reqwest::Error,
    f: &mut std::fmt::Formatter<'_>,
) -> std::fmt::Result {
    let context = if error.is_builder() {
        "http builder error"
    } else if error.is_request() {
        "http request error"
    } else if error.is_body() {
        "http body error"
    } else if error.is_decode() {
        "http decode error"
    } else if error.is_redirect() {
        "http redirect error"
    } else if error.is_upgrade() {
        "http upgrade error"
    } else if error.is_status() {
        return match error.status() {
            Some(status) => write!(f, "http status {}", status.as_u16()),
            None => f.write_str("http status error"),
        };
    } else {
        "http transport error"
    };
    f.write_str(context)
}

impl std::fmt::Debug for TransportCause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

impl std::error::Error for TransportCause {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Request { source } => Some(source.as_ref()),
            Self::Read { source } => Some(source.as_ref()),
            Self::Deadline { .. } | Self::Status { .. } => None,
        }
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum ProviderError {
    /// DEC-014: the model names a connection id the catalogue does not
    /// declare — the denial names the id, like every sibling.
    #[error("provider capability unavailable: model references unknown connection {connection}")]
    UnknownConnection { connection: String },
    #[error("provider capability unavailable: {kind} connection requires a separate live grant")]
    LiveGrantRequired { kind: ConnKind },
    /// DEC-014: the named store class cannot serve the call — absent,
    /// locked or denied. `reason` is the platform's own Display text
    /// verbatim — expected to name the condition; the seam cannot detect
    /// material a platform embeds in it. No plaintext fallback exists
    /// (INV-006).
    #[error("credential store {store} is unavailable: {reason}")]
    StoreUnavailable { store: StoreKind, reason: String },
    /// DEC-014: the store answered with more than one credential for the
    /// scope — resolution is denied rather than picking one silently.
    #[error("credential store {store} answered ambiguously for the scope")]
    StoreAmbiguous { store: StoreKind },
    /// DEC-014: the connection's resolved binding names no usable scoped
    /// reference. `scope` is the config key path that failed, not a value;
    /// `cause` carries the parse verdict when the bound ref was malformed
    /// and is `None` when the binding named no ref at all.
    #[error("credential for connection {connection} is unresolved at {scope}")]
    CredentialUnresolved {
        connection: String,
        scope: String,
        #[source]
        cause: Option<SecretRefError>,
    },
    /// A `local` declaration names a locally served endpoint; a `profile`
    /// binding is the contradictory half — the message names it so the
    /// operator fixes the right member (DEC-023).
    #[error("connection {connection} is local and must not carry a profile")]
    LocalProfileDeclared { connection: String },
    /// DEC-014: a profile-bound ref whose trailing scope segment is not the
    /// bound profile's name — scope and binding cannot diverge.
    #[error(
        "connection {connection} binds profile {profile} but the credential scope names another profile"
    )]
    CredentialProfileMismatch { connection: String, profile: String },
    /// The ref targets a different store class or a service prefix outside
    /// this backend's admitted namespace — refused before any store call.
    #[error("credential scope {scope} is outside the {store} store's admitted namespace")]
    CredentialOutsideNamespace { store: StoreKind, scope: String },
    /// Enrollment is create-only: an occupied scope is a collision the
    /// caller must reconcile, never an implicit overwrite.
    #[error("credential scope {scope} already holds material")]
    CredentialOccupied { scope: String },
    /// No material exists at the scope — distinct from an empty secret.
    #[error("no credential material at scope {scope}")]
    CredentialAbsent { scope: String },
    /// The resolved credential material cannot serve this dialect —
    /// non-UTF-8 bytes where the contract needs a bearer token, a
    /// token outside the dialect's recorded credential grammar (a
    /// PAYG `sk-…` key where the contract binds plan `sk-sp-…`
    /// keys), or — on the codex ids — stored material that is not the
    /// login module's credential JSON or whose access token is blank.
    /// The material itself never appears in the error.
    #[error("credential material for connection {connection} is not usable by this dialect")]
    CredentialMalformed { connection: String },
    /// The store material names a credential class this build cannot
    /// read — web identity, SSO, ECS/EC2 metadata or a credential
    /// process. `class` is the recorded descriptor name; no path,
    /// process or environment value reaches the message.
    #[error("connection {connection} credential class {class} is blocked in this build")]
    UnsupportedCredentialClass {
        connection: String,
        class: &'static str,
    },
    /// The credential's enrolled endpoint base does not match the
    /// connection's configured endpoint (HZN-008 class P), or — on a
    /// credential-derived base such as `github-copilot` — is not an
    /// admitted https origin: a key enrolled for one recorded base —
    /// international, China or a custom origin — can never serve
    /// another, and the denial lands before any wire leg reaches the
    /// wrong host. `enrolled` is the credential's recorded base rendered
    /// for diagnostics: the canonical egress form
    /// (`canonical_egress_target`) for a base compared against a
    /// configured endpoint, and on a credential-derived base only the
    /// scheme, host and port — or a fixed marker when the value is not a
    /// URL. Path, query, fragment and userinfo in stored material never
    /// reach diagnostics, so the field stays config-class data, never
    /// secret material.
    #[error(
        "credential for connection {connection} is enrolled for a different endpoint base: {enrolled}"
    )]
    CredentialBaseMismatch {
        connection: String,
        enrolled: String,
    },
    /// DEC-007: the manifest's pin names a connection whose recorded
    /// source class is not this adapter's dialect — dialect selection
    /// keys on the literal connection id, never an auth label.
    #[error("connection {connection} does not speak this adapter's dialect")]
    DialectMismatch { connection: String },
    /// The id [`dialect_for`] reserves failed the send gate: no
    /// installed adapter serves its recorded dialect in this build —
    /// the honest build truth, distinct from an adapter declining an
    /// id it was offered.
    #[error(
        "connection {connection} is reserved for dialect {dialect}; no installed adapter serves it in this build"
    )]
    DialectUnserved {
        connection: String,
        dialect: Dialect,
    },
    /// The connection's recorded source class is externally blocked
    /// (AC-009): the denial lands before any adapter's dialect claim and
    /// before the ledger reserves the send, so no installed adapter, key
    /// or PAYG substitute can change it. `class` names the recorded
    /// block, never a second literal, and the variant carries no
    /// credential material.
    #[error("connection {connection} is externally blocked ({class})")]
    ExternalBlocked {
        connection: String,
        class: &'static str,
    },
    /// The pinned model has no native class in a dual-class adapter: its
    /// recorded catalogue `api` owner is neither of the classes this
    /// adapter serves, so the request can never be projected onto a wire
    /// resource. The class is never inferred from the model-name family
    /// or the credential form, and the denial lands before any request.
    #[error("connection {connection} resolves no native model class for {model}")]
    ModelClassUnresolved { connection: String, model: String },
    /// The manifest carries no pinned model id for the wire request —
    /// an auto assignment resolves its model at catalogue time, which
    /// this adapter does not hold.
    #[error("connection {connection} requires a fixed model pin on the wire request")]
    UnpinnedModel { connection: String },
    /// DEC-014: the connection's configured region names an endpoint
    /// outside this dialect's recorded contract — a configured region
    /// is never silently ignored.
    #[error("connection {connection} region {region} is outside the dialect's endpoint contract")]
    RegionMismatch { connection: String, region: String },
    /// DEC-005: the arm's base is operator data (Cloudflare
    /// account/gateway), so no default host exists — an empty
    /// configured endpoint names no recorded base to send to.
    #[error("connection {connection} requires a configured endpoint")]
    EndpointRequired { connection: String },
    /// The transport failed before a usable reply — connect, TLS,
    /// status or read failure. The source is retained for programmatic inspection.
    #[error("connection {connection} transport failed: {cause}")]
    Transport {
        connection: String,
        #[source]
        cause: TransportCause,
    },
    /// The provider's own terminal event reported a failed or
    /// incomplete response — a peer verdict, not a parse error.
    #[error("connection {connection} reported failure: {reason}")]
    ProviderFailed { connection: String, reason: String },
    /// The stream ended without a terminal event the dialect can
    /// classify, or a terminal carried an outcome it cannot — unknown
    /// is never success.
    #[error("connection {connection} ended without a classifiable terminal event")]
    UnknownTerminal { connection: String },
    /// A wire event or item was malformed — bad JSON, a missing
    /// mandatory field, a truncated item or an over-limit line.
    #[error("connection {connection} stream violated the dialect contract: {reason}")]
    StreamViolation { connection: String, reason: String },
    /// A well-formed output item the dialect cannot honour — an
    /// unbounded server-side tool kind or a tool shape the frozen
    /// request never declared.
    #[error("connection {connection} produced an incompatible output: {reason}")]
    IncompatibleOutput { connection: String, reason: String },
    /// The frozen request carries a parameter the connection's recorded
    /// contract rejects for the pinned model — a rejected parameter is
    /// a typed denial before the chat leg (an auto pick resolved its
    /// model from the catalogue leg first), never silently dropped from
    /// the body.
    #[error("connection {connection} rejects request parameter {parameter} for model {model}")]
    UnsupportedParameter {
        connection: String,
        parameter: &'static str,
        model: String,
    },
    /// The frozen request cannot be shaped into a sendable wire request:
    /// its body does not serialize, its bytes exceed the wire bound, or a
    /// value the dialect must transmit is unusable. The denial lands
    /// before any byte crossed, so it is definitive — a substitute cannot
    /// repeat an effect that never left the client.
    #[error("connection {connection} request cannot be sent: {reason}")]
    UnsendableRequest { connection: String, reason: String },
    /// DEC-012: a reasoning artifact outside this manifest's
    /// session/epoch lineage — absent or foreign `encrypted_content`
    /// is a provenance failure, never silently dropped or replayed.
    #[error("connection {connection} returned a reasoning artifact outside the lineage: {reason}")]
    ReasoningProvenance { connection: String, reason: String },
    /// One failed send after the adapter's own corrected retry: the count
    /// travels beside the failure so the entered settle records how many
    /// legs crossed the wire. The broker unwraps the marker at the send
    /// boundary, so callers meet only the failure's own class.
    #[error("send failed after {wire_retries} wire retries: {source}")]
    Retried {
        wire_retries: u32,
        #[source]
        source: Box<ProviderError>,
    },
}

impl ProviderError {
    /// Splits the adapter's retry marker off this failure: the wire-retry
    /// count and the class the caller sees. A failure without a marker
    /// crossed no retried leg.
    pub(crate) fn settle(self) -> (u32, Self) {
        match self {
            Self::Retried {
                wire_retries,
                source,
            } => (wire_retries, *source),
            class => (0, class),
        }
    }
}

/// The native secret-store class a credential reference resolves to
/// (SRC-010). `keyring:` in a config ref binds the platform's native class;
/// `keychain:`/`secret-service:` pin a class explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum StoreKind {
    /// macOS Keychain (`apple-native-keyring-store`, keychain feature).
    Keychain,
    /// Linux Secret Service over D-Bus (`zbus-secret-service-keyring-store`).
    SecretService,
}

impl std::fmt::Display for StoreKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            StoreKind::Keychain => "keychain",
            StoreKind::SecretService => "secret-service",
        })
    }
}

/// Why a raw string is not a usable [`SecretRef`]. Fields carry the
/// rejected token — a reference shape, never stored material.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SecretRefError {
    /// Not the `store:scope` shape — missing separator, empty scope,
    /// whitespace, or empty `/` segments.
    #[error("credential reference is not a scoped store:scope reference")]
    NotScoped,
    /// Well-formed, but the store label names no admitted class.
    #[error("credential reference names an unsupported credential store: {store}")]
    UnsupportedStore { store: String },
}

/// A scoped credential reference — the only token that may cross from a
/// store into config, adapters, diagnostics or a manifest (INV-001). The
/// grammar is `store:account[/origin/]profile` — the one shape config
/// ingress validates through this same [`SecretRef::parse`], so no
/// admitted-at-ingress ref can fail the trust boundary's re-check. A
/// `SecretRef` names where material lives; it never contains material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretRef {
    store: StoreKind,
    raw: String,
    scope: String,
}

impl SecretRef {
    /// Parses `store:scope`. `keyring` resolves to this platform's native
    /// store class; `keychain`/`secret-service` pin a class. Anything else
    /// — including `env:`, `file:` or a bare token — is refused, so an
    /// adapter can never be handed a plaintext-or-env indirection (INV-006).
    ///
    /// # Errors
    /// [`SecretRefError::NotScoped`] for shape violations;
    /// [`SecretRefError::UnsupportedStore`] for an unadmitted store label.
    pub fn parse(raw: &str) -> Result<Self, SecretRefError> {
        let Some((store, scope)) = raw.split_once(':') else {
            return Err(SecretRefError::NotScoped);
        };
        let store_ok = !store.is_empty()
            && store
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic())
            && store
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'));
        let scope_ok = !scope.is_empty()
            && !scope.chars().any(char::is_whitespace)
            && scope.split('/').all(|segment| !segment.is_empty());
        if !store_ok || !scope_ok {
            return Err(SecretRefError::NotScoped);
        }
        let store = match store {
            "keyring" => native_store_kind(),
            "keychain" => StoreKind::Keychain,
            "secret-service" | "secret_service" => StoreKind::SecretService,
            _ => {
                return Err(SecretRefError::UnsupportedStore {
                    store: store.to_string(),
                });
            }
        };
        Ok(Self {
            store,
            raw: raw.to_string(),
            scope: scope.to_string(),
        })
    }

    /// The resolved store class.
    #[must_use]
    pub fn store(&self) -> StoreKind {
        self.store
    }

    /// The scope path — `account[/origin/]profile`.
    #[must_use]
    pub fn scope(&self) -> &str {
        &self.scope
    }

    /// The verbatim `store:scope` token — safe for diagnostics and journals
    /// (a reference is config data, not material).
    #[must_use]
    pub fn raw(&self) -> &str {
        &self.raw
    }

    /// The leading scope segment — the account namespace the backend uses
    /// as its service bucket and the namespace prefix guards match on.
    #[must_use]
    pub fn service(&self) -> &str {
        &self.scope[..self.scope.find('/').unwrap_or(self.scope.len())]
    }

    /// The trailing scope segment — the credential profile. A
    /// `profiles.<name>` binding must agree with it (DEC-014 mismatch).
    #[must_use]
    pub fn profile(&self) -> &str {
        &self.scope[self.scope.rfind('/').map_or(0, |i| i + 1)..]
    }
}

impl std::fmt::Display for SecretRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.raw)
    }
}

/// The credential material a wire request authenticates with: a scoped
/// reference the adapter resolves per send, or material an exchange
/// already resolved for one send. The `Resolved` form exists for the
/// two-leg proxies; no diagnostic may render either half.
#[derive(Clone)]
pub enum WireAuth {
    /// The scoped store reference — the adapter reads material through
    /// [`CredentialStore`] once per send; `None` is the recorded
    /// absent-binding form.
    Store(Option<SecretRef>),
    /// Material a preflight exchange resolved for this send: the token
    /// plus the returned headers the proxy leg may forward.
    Resolved {
        token: String,
        headers: BTreeMap<String, String>,
    },
}

/// The header map a store-bound credential forwards: none. A resolved
/// exchange is the only source of proxy headers, and the exchange itself
/// admits only the recorded `x-gitlab-*` names.
static NO_FORWARDED_HEADERS: BTreeMap<String, String> = BTreeMap::new();

impl WireAuth {
    /// The headers the proxy leg may forward — empty for a store-bound
    /// credential, never an exchange's token-bearing names.
    pub(crate) fn forwarded(&self) -> &BTreeMap<String, String> {
        match self {
            Self::Store(_) => &NO_FORWARDED_HEADERS,
            Self::Resolved { headers, .. } => headers,
        }
    }
}

impl std::fmt::Debug for WireAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Store(credential) => f.debug_tuple("Store").field(credential).finish(),
            Self::Resolved { headers, .. } => {
                let headers = format!("<{} redacted>", headers.len());
                f.debug_struct("Resolved")
                    .field("token", &"<redacted>")
                    .field("headers", &headers)
                    .finish()
            }
        }
    }
}

/// `keyring:` binds this platform's native store class. On platforms
/// without an admitted native store the class still resolves — the backend
/// constructor then answers `StoreUnavailable` (INV-006).
#[cfg(target_os = "macos")]
const fn native_store_kind() -> StoreKind {
    StoreKind::Keychain
}

/// Linux: `keyring:` binds Secret Service.
#[cfg(target_os = "linux")]
const fn native_store_kind() -> StoreKind {
    StoreKind::SecretService
}

/// Other platforms have no admitted native store; resolving to a class
/// keeps parsing total while [`native_store`] reports it unavailable.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
const fn native_store_kind() -> StoreKind {
    StoreKind::Keychain
}

/// The credential-store seam (SRC-010): the only path between a native
/// secret store and an adapter. Secret bytes cross this boundary only as
/// `&[u8]` arguments and `Vec<u8>` returns — every other surface sees the
/// scoped [`SecretRef`] (INV-001). Implementations fail closed with typed
/// errors; none may substitute plaintext or env storage (INV-006).
///
/// Lifecycle: `login` enrolls and refuses an occupied scope
/// (`CredentialOccupied` — enrollment never overwrites); `refresh` replaces
/// material at the scope; `revoke` and `logout` delete it; `resolve`
/// returns the bytes or `CredentialAbsent`.
pub trait CredentialStore: Send + Sync {
    /// The store class this backend serves.
    fn kind(&self) -> StoreKind;
    /// Whether material exists at the scope.
    ///
    /// # Errors
    /// [`ProviderError::CredentialOutsideNamespace`] for a foreign scope;
    /// [`ProviderError::StoreUnavailable`]/`StoreAmbiguous` on a failed or
    /// ambiguous store answer.
    fn occupied(&self, credential: &SecretRef) -> Result<bool, ProviderError>;
    /// User ids of entries under `service` — the namespace census the
    /// precheck journals before any write (DEC-002). An entry's `user`
    /// specifier is the full scope path, so the census returns scope
    /// paths, never material.
    ///
    /// # Errors
    /// [`ProviderError::CredentialOutsideNamespace`] for a foreign service;
    /// [`ProviderError::StoreUnavailable`] on a failed search.
    fn entry_accounts(&self, service: &str) -> Result<Vec<String>, ProviderError>;
    /// Enrolls `secret` at the scope.
    ///
    /// # Errors
    /// [`ProviderError::CredentialOccupied`] when the scope holds material —
    /// checked before the write; [`ProviderError::CredentialOutsideNamespace`],
    /// `StoreUnavailable`/`StoreAmbiguous` on store conditions.
    fn login(&self, credential: &SecretRef, secret: &[u8]) -> Result<(), ProviderError>;
    /// Reads the material at the scope.
    ///
    /// The call is synchronous and cannot be cancelled once running:
    /// a native backend may block past the caller's request deadline —
    /// no safe mechanism interrupts a blocking store op in flight, and
    /// a detached watchdog thread is not one. Callers bound the seam by
    /// checking their deadline *before* the call and again before the
    /// resolved material is used; only test/probe harnesses may hold a
    /// real wall-clock bound around it.
    ///
    /// # Errors
    /// [`ProviderError::CredentialAbsent`] when the scope is empty;
    /// `CredentialOutsideNamespace`/`StoreUnavailable`/`StoreAmbiguous` on
    /// store conditions.
    fn resolve(&self, credential: &SecretRef) -> Result<Vec<u8>, ProviderError>;
    /// Replaces the material at the scope.
    ///
    /// # Errors
    /// `CredentialOutsideNamespace`/`StoreUnavailable`/`StoreAmbiguous` on
    /// store conditions.
    fn refresh(&self, credential: &SecretRef, secret: &[u8]) -> Result<(), ProviderError>;
    /// Deletes the entry at the scope (credential revocation).
    ///
    /// # Errors
    /// `CredentialOutsideNamespace`/`StoreUnavailable`/`StoreAmbiguous` on
    /// store conditions.
    fn revoke(&self, credential: &SecretRef) -> Result<(), ProviderError>;
    /// Deletes the entry at the scope (profile teardown).
    ///
    /// # Errors
    /// `CredentialOutsideNamespace`/`StoreUnavailable`/`StoreAmbiguous` on
    /// store conditions.
    fn logout(&self, credential: &SecretRef) -> Result<(), ProviderError>;
}

/// `CredentialStore` over a keyring-core backend (SRC-010 explicit stores).
/// Entry identity is `(service, user)` = (the scope's leading namespace
/// segment, the full scope path) — the scope encodes account/origin/profile
/// so writes stay scoped. `namespace` is the admitted service prefix: a ref
/// outside it — or aimed at another store class — is refused as
/// [`ProviderError::CredentialOutsideNamespace`] before any store call.
pub struct KeyringBackend {
    store: Arc<keyring_core::CredentialStore>,
    kind: StoreKind,
    namespace: String,
    /// Per-scope enrollment serialization: `login`'s create-only
    /// check-then-act has no atomic create-if-absent in the keyring API,
    /// so same-scope enrollments queue on a per-scope mutex and a queued
    /// caller's `occupied` check observes the earlier write. Entries are
    /// retained — removing a slot between a holder's release and a parked
    /// waiter's acquire would reopen the race — and the map stays bounded
    /// by the distinct scopes this backend serves. The guarantee is
    /// login-vs-login on this one instance: `refresh`/`revoke` skip these
    /// locks entirely, a second `KeyringBackend` holds a disjoint map, and
    /// a writer outside this instance — another backend or process —
    /// silently overwrites the entry, since both admitted backends upsert
    /// (`security-framework` answers `errSecDuplicateItem` with
    /// `SecItemUpdate`; the secret-service store creates items with
    /// `replace = true`). No store error surfaces that race.
    login_locks: Mutex<BTreeMap<String, Arc<Mutex<()>>>>,
}

impl std::fmt::Debug for KeyringBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The store trait object has no Debug; the class and namespace
        // identify the backend for diagnostics.
        f.debug_struct("KeyringBackend")
            .field("kind", &self.kind)
            .field("namespace", &self.namespace)
            .finish_non_exhaustive()
    }
}

impl KeyringBackend {
    /// Wraps an opened keyring-core store. `namespace` is the service
    /// prefix the backend admits — `rivect` in production, `rivect-test`
    /// under the harness (DEC-002).
    pub fn new(
        store: Arc<keyring_core::CredentialStore>,
        kind: StoreKind,
        namespace: &str,
    ) -> Self {
        Self {
            store,
            kind,
            namespace: namespace.to_string(),
            login_locks: Mutex::new(BTreeMap::new()),
        }
    }

    /// `service` is inside the namespace when it equals it or extends it by
    /// a `.`-separated component (`rivect-test.work`).
    fn in_namespace(&self, service: &str) -> bool {
        service == self.namespace
            || service
                .strip_prefix(&self.namespace)
                .is_some_and(|rest| rest.starts_with('.'))
    }

    /// Builds the native entry specifier — a pure value construction with
    /// no store effect — after the namespace guard. Every op goes through
    /// here, so a foreign ref is refused before any store call.
    fn entry(&self, credential: &SecretRef) -> Result<keyring_core::Entry, ProviderError> {
        if credential.store() != self.kind || !self.in_namespace(credential.service()) {
            return Err(ProviderError::CredentialOutsideNamespace {
                store: self.kind,
                scope: credential.scope().to_string(),
            });
        }
        self.store
            .build(credential.service(), credential.scope(), None)
            .map_err(|err| self.map_error(credential, err))
    }

    /// One occupancy read on an already-built entry: `NoEntry` is an empty
    /// slot; every other condition maps to the typed vocabulary.
    fn entry_occupied(
        &self,
        credential: &SecretRef,
        entry: &keyring_core::Entry,
    ) -> Result<bool, ProviderError> {
        match entry.get_secret() {
            Ok(_) => Ok(true),
            Err(err) => match self.map_error(credential, err) {
                ProviderError::CredentialAbsent { .. } => Ok(false),
                other => Err(other),
            },
        }
    }

    /// Maps keyring-core conditions onto the typed vocabulary (DEC-014).
    /// `NoEntry` is `CredentialAbsent`; `Ambiguous` is `StoreAmbiguous`;
    /// every other condition — denied access, platform failure, a store
    /// refusing oversized material — is `StoreUnavailable` carrying the
    /// platform's own reason text verbatim — expected to name the
    /// condition; the seam cannot detect material a platform embeds.
    fn map_error(&self, credential: &SecretRef, err: keyring_core::Error) -> ProviderError {
        match err {
            keyring_core::Error::NoEntry => ProviderError::CredentialAbsent {
                scope: credential.scope().to_string(),
            },
            keyring_core::Error::Ambiguous(_) => ProviderError::StoreAmbiguous { store: self.kind },
            other => ProviderError::StoreUnavailable {
                store: self.kind,
                reason: other.to_string(),
            },
        }
    }
}

impl CredentialStore for KeyringBackend {
    fn kind(&self) -> StoreKind {
        self.kind
    }

    fn occupied(&self, credential: &SecretRef) -> Result<bool, ProviderError> {
        let entry = self.entry(credential)?;
        self.entry_occupied(credential, &entry)
    }

    fn entry_accounts(&self, service: &str) -> Result<Vec<String>, ProviderError> {
        if !self.in_namespace(service) {
            return Err(ProviderError::CredentialOutsideNamespace {
                store: self.kind,
                scope: service.to_string(),
            });
        }
        let spec = HashMap::from([("service", service)]);
        let entries = self
            .store
            .search(&spec)
            .map_err(|err| ProviderError::StoreUnavailable {
                store: self.kind,
                reason: err.to_string(),
            })?;
        let mut accounts = entries
            .iter()
            .filter_map(|entry| entry.get_specifiers())
            .filter_map(|(entry_service, user)| (entry_service == service).then_some(user))
            .collect::<Vec<_>>();
        accounts.sort();
        accounts.dedup();
        Ok(accounts)
    }

    fn login(&self, credential: &SecretRef, secret: &[u8]) -> Result<(), ProviderError> {
        // Enrollment is create-only: the occupancy check runs under the
        // per-scope mutex after the namespace/kind guard, so two same-scope
        // enrollments cannot both observe the slot empty (DEC-002). Poison
        // recovery is sound — the guard serializes, it protects no state.
        let entry = self.entry(credential)?;
        let scope_lock = {
            let mut locks = self.login_locks.lock().unwrap_or_else(|e| e.into_inner());
            Arc::clone(
                locks
                    .entry(credential.scope().to_string())
                    .or_insert_with(|| Arc::new(Mutex::new(()))),
            )
        };
        let _guard = scope_lock.lock().unwrap_or_else(|e| e.into_inner());
        if self.entry_occupied(credential, &entry)? {
            return Err(ProviderError::CredentialOccupied {
                scope: credential.scope().to_string(),
            });
        }
        entry
            .set_secret(secret)
            .map_err(|err| self.map_error(credential, err))
    }

    fn resolve(&self, credential: &SecretRef) -> Result<Vec<u8>, ProviderError> {
        self.entry(credential)?
            .get_secret()
            .map_err(|err| self.map_error(credential, err))
    }

    fn refresh(&self, credential: &SecretRef, secret: &[u8]) -> Result<(), ProviderError> {
        self.entry(credential)?
            .set_secret(secret)
            .map_err(|err| self.map_error(credential, err))
    }

    fn revoke(&self, credential: &SecretRef) -> Result<(), ProviderError> {
        self.entry(credential)?
            .delete_credential()
            .map_err(|err| self.map_error(credential, err))
    }

    fn logout(&self, credential: &SecretRef) -> Result<(), ProviderError> {
        self.revoke(credential)
    }
}

/// The shared outcome one in-flight refresh publishes to its joiners.
struct RefreshFlight {
    outcome: Mutex<Option<Result<(), ProviderError>>>,
    ready: Condvar,
}

/// The default bound a refresh joiner parks under — the whole-request
/// deadline the seam's callers run on. An outcome arriving after the
/// caller's budget is spent is no use to it, so a longer park could
/// only ever wedge the thread.
const JOIN_BOUND: Duration = Duration::from_secs(120);

/// Per-profile refresh single-flight (INV-009): while a refresh for one
/// credential scope is in flight, concurrent refreshes for the same scope
/// join it — the leader's inner op is the only store write and its outcome
/// stands for every waiter. Different scopes hold independent flights; all
/// other ops pass through untouched.
pub struct FlightedStore {
    inner: Box<dyn CredentialStore>,
    flights: Mutex<BTreeMap<String, Arc<RefreshFlight>>>,
    waiters: AtomicU64,
    join_bound: Duration,
}

impl FlightedStore {
    /// Wraps any backend with the refresh flight serializer — the one
    /// constructor [`native_store`] uses, and the one tests use to pin the
    /// coalescing behavior deterministically. Joiners park under
    /// `JOIN_BOUND`.
    pub fn new(inner: Box<dyn CredentialStore>) -> Self {
        Self::with_join_bound(inner, JOIN_BOUND)
    }

    /// The same seam under an explicit join bound — the constructor a
    /// test uses to prove a wedged leader denies its joiners instead of
    /// parking them past the bound.
    pub fn with_join_bound(inner: Box<dyn CredentialStore>, join_bound: Duration) -> Self {
        Self {
            inner,
            flights: Mutex::new(BTreeMap::new()),
            waiters: AtomicU64::new(0),
            join_bound,
        }
    }

    /// Refresh callers currently joined on an in-flight op — the
    /// observability surface for the INV-009 guarantee.
    #[must_use]
    pub fn refresh_waiters(&self) -> u64 {
        self.waiters.load(Ordering::SeqCst)
    }

    fn flights(&self) -> MutexGuard<'_, BTreeMap<String, Arc<RefreshFlight>>> {
        // Poison recovery is sound here: the map only ever gains or loses
        // whole flight entries, so a panicking holder leaves it valid.
        self.flights.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Parks on the flight until the leader publishes its outcome or the
    /// join bound lapses, then returns that outcome or a typed denial —
    /// the joiner never runs a second store op and never parks forever.
    /// The bound cannot reach into the leader's synchronous store op: a
    /// call already running completes or wedges on its own thread, and
    /// no safe mechanism cancels it — the joiner is released while the
    /// flight stays the leader's to finish.
    fn join(&self, flight: &Arc<RefreshFlight>) -> Result<(), ProviderError> {
        let started = Instant::now();
        let result = {
            // Same poison argument as `flights`: the slot holds at most
            // one completed outcome write — the guard drops with the
            // block, never held past the verdict.
            let mut outcome = flight.outcome.lock().unwrap_or_else(|e| e.into_inner());
            loop {
                if let Some(result) = outcome.clone() {
                    break result;
                }
                let elapsed = started.elapsed();
                if elapsed >= self.join_bound {
                    break Err(ProviderError::StoreUnavailable {
                        store: self.inner.kind(),
                        reason: "refresh join exceeded its bound".to_string(),
                    });
                }
                let (guard, _wait) = flight
                    .ready
                    .wait_timeout(outcome, self.join_bound - elapsed)
                    .unwrap_or_else(|e| e.into_inner());
                outcome = guard;
            }
        };
        self.waiters.fetch_sub(1, Ordering::SeqCst);
        result
    }
}

impl std::fmt::Debug for FlightedStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The inner store is a trait object; the class and the live
        // waiter count are the observability surface (INV-009).
        f.debug_struct("FlightedStore")
            .field("kind", &self.inner.kind())
            .field("refresh_waiters", &self.refresh_waiters())
            .finish_non_exhaustive()
    }
}

/// The leader half of one in-flight refresh. On drop — normal return or
/// unwind — the map entry is removed BEFORE the outcome is published, so
/// a refresh arriving mid-publish becomes the next leader instead of
/// joining a spent flight and taking `Ok` for bytes it never wrote. A
/// leader that unwound past `inner.refresh` publishes `StoreUnavailable`,
/// so parked joiners wake with a typed error and the scope is free for
/// the next leader instead of wedging on an outcome that never comes.
struct FlightLeader<'a> {
    store: &'a FlightedStore,
    key: String,
    flight: Arc<RefreshFlight>,
    outcome: Option<Result<(), ProviderError>>,
}

impl Drop for FlightLeader<'_> {
    fn drop(&mut self) {
        self.store.flights().remove(&self.key);
        let mut outcome = self
            .flight
            .outcome
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *outcome = Some(self.outcome.take().unwrap_or_else(|| {
            Err(ProviderError::StoreUnavailable {
                store: self.store.inner.kind(),
                reason: "refresh leader panicked".to_string(),
            })
        }));
        drop(outcome);
        self.flight.ready.notify_all();
    }
}

impl CredentialStore for FlightedStore {
    fn kind(&self) -> StoreKind {
        self.inner.kind()
    }

    fn occupied(&self, credential: &SecretRef) -> Result<bool, ProviderError> {
        self.inner.occupied(credential)
    }

    fn entry_accounts(&self, service: &str) -> Result<Vec<String>, ProviderError> {
        self.inner.entry_accounts(service)
    }

    fn login(&self, credential: &SecretRef, secret: &[u8]) -> Result<(), ProviderError> {
        self.inner.login(credential, secret)
    }

    fn resolve(&self, credential: &SecretRef) -> Result<Vec<u8>, ProviderError> {
        self.inner.resolve(credential)
    }

    fn refresh(&self, credential: &SecretRef, secret: &[u8]) -> Result<(), ProviderError> {
        // The flights map keys on the scope alone, so a foreign-class ref
        // must be refused before slot selection — otherwise it joins a
        // flight the backend admitted and takes `Ok` for an op that never
        // ran. A same-kind ref needs no separate namespace check here:
        // equal scopes imply equal namespace verdicts, and a foreign-scope
        // leader's flight only ever carries that refusal.
        if credential.store() != self.inner.kind() {
            return Err(ProviderError::CredentialOutsideNamespace {
                store: self.inner.kind(),
                scope: credential.scope().to_string(),
            });
        }
        // The flights-map guard must drop before `join` parks on the
        // condvar — joining while still holding it would serialize every
        // other caller on the map lock instead of the flight.
        enum Slot {
            Lead(Arc<RefreshFlight>),
            Join(Arc<RefreshFlight>),
        }
        let slot = {
            let mut flights = self.flights();
            match flights.entry(credential.scope().to_string()) {
                std::collections::btree_map::Entry::Occupied(entry) => {
                    self.waiters.fetch_add(1, Ordering::SeqCst);
                    Slot::Join(Arc::clone(entry.get()))
                }
                std::collections::btree_map::Entry::Vacant(slot) => {
                    Slot::Lead(Arc::clone(slot.insert(Arc::new(RefreshFlight {
                        outcome: Mutex::new(None),
                        ready: Condvar::new(),
                    }))))
                }
            }
        };
        let flight = match slot {
            Slot::Lead(flight) => flight,
            Slot::Join(flight) => return self.join(&flight),
        };
        // `FlightLeader` owns the remove → publish → notify sequence on
        // drop, so an unwinding leader cannot leave a flightless outcome
        // or a parked crowd behind.
        let mut leader = FlightLeader {
            store: self,
            key: credential.scope().to_string(),
            flight,
            outcome: None,
        };
        let result = self.inner.refresh(credential, secret);
        leader.outcome = Some(result.clone());
        result
    }

    fn revoke(&self, credential: &SecretRef) -> Result<(), ProviderError> {
        self.inner.revoke(credential)
    }

    fn logout(&self, credential: &SecretRef) -> Result<(), ProviderError> {
        self.inner.logout(credential)
    }
}

/// Opens the platform backend for `kind` under `namespace` and returns it
/// with per-profile refresh serialization installed (INV-009). This is the
/// only constructor adapters use — SRC-010 explicit stores, never a
/// plaintext or env-substituted store.
///
/// # Errors
/// [`ProviderError::StoreUnavailable`] when the class has no usable store
/// on this platform — a locked or absent backend surfaces its platform
/// reason; there is no fallback (INV-006).
pub fn native_store(kind: StoreKind, namespace: &str) -> Result<FlightedStore, ProviderError> {
    let backend = match kind {
        StoreKind::Keychain => keychain_backend()?,
        StoreKind::SecretService => secret_service_backend()?,
    };
    Ok(FlightedStore::new(Box::new(KeyringBackend::new(
        backend, kind, namespace,
    ))))
}

/// macOS: the login-Keychain backend (SRC-010; `keychain` feature — the
/// file-backed store, not the data-protection one). The seam does not
/// suppress prompts — a locked keychain can still park an op on an
/// unlock dialog, and bounding that wait is the caller's concern.
#[cfg(target_os = "macos")]
fn keychain_backend() -> Result<Arc<keyring_core::CredentialStore>, ProviderError> {
    apple_native_keyring_store::keychain::Store::new()
        .map(|store| -> Arc<keyring_core::CredentialStore> { store })
        .map_err(|err| ProviderError::StoreUnavailable {
            store: StoreKind::Keychain,
            reason: err.to_string(),
        })
}

/// Non-macOS platforms have no Keychain class.
#[cfg(not(target_os = "macos"))]
fn keychain_backend() -> Result<Arc<keyring_core::CredentialStore>, ProviderError> {
    Err(ProviderError::StoreUnavailable {
        store: StoreKind::Keychain,
        reason: "the keychain store class exists only on macOS".to_string(),
    })
}

/// Linux: the Secret Service backend over the session D-Bus. A headless
/// host with no session bus answers `StoreUnavailable` at construction;
/// where a store does answer, a locked collection can still park an op on
/// an unlock prompt — the seam bounds nothing, the caller does.
#[cfg(target_os = "linux")]
fn secret_service_backend() -> Result<Arc<keyring_core::CredentialStore>, ProviderError> {
    zbus_secret_service_keyring_store::Store::new()
        .map(|store| -> Arc<keyring_core::CredentialStore> { store })
        .map_err(|err| ProviderError::StoreUnavailable {
            store: StoreKind::SecretService,
            reason: err.to_string(),
        })
}

/// Non-Linux platforms have no Secret Service class.
#[cfg(not(target_os = "linux"))]
fn secret_service_backend() -> Result<Arc<keyring_core::CredentialStore>, ProviderError> {
    Err(ProviderError::StoreUnavailable {
        store: StoreKind::SecretService,
        reason: "the secret service store class exists only on linux".to_string(),
    })
}

/// DEC-013 credential resolution: `connections.<id>.profile` binds
/// `profiles.<name>.credential_ref` first; without a profile binding the
/// connection's own `credential_ref` applies. Catalogue presence is never
/// entitlement — the returned [`SecretRef`] only scopes a store lookup —
/// and every failure is a typed denial, never a plaintext fallback
/// (INV-006).
///
/// A profile-bound ref's trailing scope segment must equal the profile
/// name — the scope's profile leg IS the binding, so a divergent scope is
/// [`ProviderError::CredentialProfileMismatch`].
///
/// # Errors
/// [`ProviderError::UnknownConnection`] for an undeclared id;
/// [`ProviderError::CredentialUnresolved`] when the bound profile, its
/// ref, or the connection's own ref is absent or malformed;
/// [`ProviderError::CredentialProfileMismatch`] as documented above.
pub fn resolve_credential(config: &Config, connection: &str) -> Result<SecretRef, ProviderError> {
    resolve_credential_in(&config.connections, &config.profiles, connection)
}

/// The catalogue-level half of [`resolve_credential`] (DEC-011): the
/// broker's dispatch-time re-check and [`offline_usable`] run the same
/// profile-precedence resolution without owning a `Config` — a
/// connection whose binding cannot resolve keeps the typed denial.
pub(crate) fn resolve_credential_in(
    connections: &BTreeMap<String, Connection>,
    profiles: &BTreeMap<String, Profile>,
    connection: &str,
) -> Result<SecretRef, ProviderError> {
    let Some(conn) = connections.get(connection) else {
        return Err(ProviderError::UnknownConnection {
            connection: connection.to_string(),
        });
    };
    if let Some(profile) = &conn.profile {
        let key = format!("profiles.{profile}.credential_ref");
        let raw = profiles
            .get(profile)
            .and_then(|profile| profile.credential_ref.clone())
            .ok_or_else(|| ProviderError::CredentialUnresolved {
                connection: connection.to_string(),
                scope: key.clone(),
                cause: None,
            })?;
        let credential = parse_scoped(connection, &key, &raw)?;
        if credential.profile() != profile {
            return Err(ProviderError::CredentialProfileMismatch {
                connection: connection.to_string(),
                profile: profile.clone(),
            });
        }
        return Ok(credential);
    }
    let key = format!("connections.{connection}.credential_ref");
    let raw = conn
        .credential_ref
        .clone()
        .ok_or_else(|| ProviderError::CredentialUnresolved {
            connection: connection.to_string(),
            scope: key.clone(),
            cause: None,
        })?;
    parse_scoped(connection, &key, &raw)
}

/// The `SecretRef::parse` leg both credential bindings share: a
/// malformed bound ref is [`ProviderError::CredentialUnresolved`]
/// under the failed key path, the parse verdict as its cause.
fn parse_scoped(connection: &str, key: &str, raw: &str) -> Result<SecretRef, ProviderError> {
    SecretRef::parse(raw).map_err(|parse| ProviderError::CredentialUnresolved {
        connection: connection.to_string(),
        scope: key.to_string(),
        cause: Some(parse),
    })
}

const ADMITTED_READ: &str = "performing the admitted read";
const WAITING_FOR_DECISION: &str = "no permitted action; waiting for a decision";

/// The recorded dialect of a connection id (DEC-007/DEC-025):
/// keyed by the literal id's source class — `openai` speaks the
/// OpenAI Responses API, `abliteration` is its recorded class-A
/// exception speaking the same dialect, `meta` its recorded
/// class-B plug on `api.meta.ai/v1` (HZN-008), `ollama` its
/// recorded local Responses plug with the optional credential
/// (DEC-009), `openrouter` its catalogue-only-keyless Responses
/// plug behind the recorded paste-key form (DEC-003), `sakana` its
/// key-gated authoritative Responses plug (DEC-004), `custom-responses`
/// its operator-configured custom-origin Responses plug (DEC-015), and
/// `xai`/
/// `xai-oauth` their authoritative-listing Responses plugs — the latter
/// carrying the device-code-produced token at the scoped seam — and
/// `openai-codex`/`openai-codex-device` the ChatGPT account-scoped
/// Responses plug whose device alias shares the one contract; and
/// `bedrock-mantle` the recorded regional Responses plug whose
/// successful listing replaces its five-id seed; `google` speaks
/// the Gemini `streamGenerateContent` dialect,
/// `ollama-cloud` its recorded native `ollama-chat` JSONL dialect
/// (DEC-001), `custom-chat-completions` speaks the OpenAI-compatible
/// Chat Completions dialect and `aiand`/`aimlapi`/`alibaba-coding-plan`/
/// `alibaba-token-plan`/`coreweave`/`deepinfra`/`deepseek`/`firepass`/`fireworks`/`gmi-cloud`/`groq`/`huggingface`/`kilo`
/// are its recorded class-A/class-P plugs speaking the same dialect,
/// with `litellm` the recorded class-B configured-proxy plug,
/// `llama.cpp`/`lm-studio`/`vllm` the recorded class-B local-endpoint
/// plugs,
/// `mistral` the recorded class-B env-chain plug,
/// `moonshot`, `nanogpt`, `novita`, `nvidia`, `qianfan`,
/// `qwen-portal`, `siliconflow`, `siliconflow-cn`, `synthetic`,
/// `together`, `venice`, `xiaomi`, `xiaomi-token-plan-ams`,
/// `xiaomi-token-plan-cn`, `xiaomi-token-plan-sgp` and `yolo-auto` the
/// recorded class-B api-key plugs — `venice` over its host's public
/// catalogue, `xiaomi` on its recorded PAYG literal,
/// `xiaomi-token-plan-ams` on the pinned AMS token-plan literal,
/// `xiaomi-token-plan-cn` on the pinned CN token-plan literal,
/// `xiaomi-token-plan-sgp` on the pinned SG token-plan literal, never
/// another cluster, and `yolo-auto` on the flat-rate
/// `https://yolo-auto.com/v1` base — and
/// `minimax-code`/`minimax-code-cn` the recorded class-P plan-key plugs
/// on that same dialect (HZN-008) — never inferred from an
/// auth label or a catalogue answer. `zenmux` records Chat Completions
/// as its default and a Messages route for its metadata's Anthropic
/// class, and `github-copilot` records Chat Completions as the default
/// over its closed three-route table. `google-vertex` records its own
/// dual-class dialect, and `google-antigravity` and `google-gemini-cli`
/// the CloudCode `v1internal` dialect — one variant, two literal ids
/// with their own recorded projections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Dialect {
    /// The OpenAI Responses API (`POST {endpoint}/responses`, SSE).
    Responses,
    /// The Google Gemini generate-content API
    /// (`POST {endpoint}/models/{id}:streamGenerateContent?alt=sse`, SSE).
    Gemini,
    /// The OpenAI-compatible Chat Completions API
    /// (`POST {endpoint}/chat/completions`, SSE) — the dialect every
    /// compatible host wired under the literal `custom-chat-completions`
    /// id shares (HZN-008 class S).
    ChatCompletions,
    /// The Anthropic Messages API (`POST {endpoint}/v1/messages`, SSE):
    /// the recorded dialect of `anthropic`, `minimax`, `umans`,
    /// `cloudflare-ai-gateway`, `vercel-ai-gateway` and the
    /// operator-configured `custom-messages` origin, never inferred
    /// from an auth label.
    Messages,
    /// The native Ollama Cloud chat API (`POST {endpoint}/api/chat`,
    /// newline-delimited JSON) — the recorded dialect of the literal
    /// `ollama-cloud` id (DEC-001), never SSE and never shared.
    OllamaChat,
    /// The Amazon Bedrock Converse event-stream API
    /// (`POST {base}/model/{id}/converse-stream`) — the recorded
    /// dialect of the literal `amazon-bedrock` id.
    Converse,
    /// The Cursor agent backend — the recorded class of the literal
    /// `cursor` id. No installed adapter serves it in this build, so a
    /// send denies [`ProviderError::DialectUnserved`]: the marker names
    /// the recorded transport, it is not a wire claim.
    CursorAgent,
    /// The Devin agent backend — the recorded class of the literal
    /// `devin` id. No installed adapter serves it in this build, so a
    /// send denies [`ProviderError::DialectUnserved`]: the marker names
    /// the recorded transport, it is not a wire claim.
    DevinAgent,
    /// The GitLab Duo Agent workflow transport — the recorded class of
    /// the literal `gitlab-duo-agent` id, served by
    /// [`gitlab_workflow::GitlabWorkflowProvider`]: the REST setup chain
    /// plus the WebSocket workflow stream.
    GitlabWorkflow,
    /// The Vertex AI dual-class dialect — the recorded class of the
    /// literal `google-vertex` id, served by [`vertex::VertexProvider`]:
    /// a model whose catalogue `api` owner is `google-vertex` rides the
    /// publisher `streamGenerateContent` projection, and one owned by
    /// `anthropic-messages` rides the regional `streamRawPredict`
    /// resource. The class is resolved from the recorded catalogue row,
    /// never from the model-name family.
    Vertex,
    /// The CloudCode `v1internal` dialect — the recorded class of the
    /// literal `google-antigravity` and `google-gemini-cli` ids.
    /// [`cloudcode::CloudCodeProvider`] serves the Antigravity envelope
    /// over the recorded daily or sandbox origin, and
    /// [`cloudcode::GeminiCliProvider`] the Gemini CLI projection over
    /// the recorded `cloudcode-pa` origin; both nest the Gemini request
    /// builder's body under `request`, each with its own top level.
    CloudCode,
}

impl std::fmt::Display for Dialect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Responses => "responses",
            Self::Gemini => "gemini",
            Self::ChatCompletions => "chat-completions",
            Self::Messages => "messages",
            Self::OllamaChat => "ollama-chat",
            Self::Converse => "converse",
            Self::CursorAgent => "cursor-agent",
            Self::DevinAgent => "devin-agent",
            Self::GitlabWorkflow => "gitlab-workflow",
            Self::Vertex => "vertex",
            Self::CloudCode => "cloudcode",
        })
    }
}

/// The recorded external block class for `connection`, if any (AC-009):
/// `muse-code` denies on its recorded premise before any adapter's
/// dialect claim and before the ledger reserves the send, so no installed
/// adapter can change the outcome. [`muse_login::EXTERNAL_CLASS`] is the
/// class's single source, and the id declares no [`dialect_for`] arm.
#[must_use]
pub fn externally_blocked(connection: &str) -> Option<&'static str> {
    match connection {
        "muse-code" => Some(muse_login::EXTERNAL_CLASS),
        _ => None,
    }
}

/// The recorded dialect for a literal connection id; `None` for ids
/// whose source class has no wired dialect in this build.
#[must_use]
pub fn dialect_for(connection: &str) -> Option<Dialect> {
    match connection {
        "openai" => Some(Dialect::Responses),
        "azure" => Some(Dialect::Responses),
        "abliteration" => Some(Dialect::Responses),
        "meta" => Some(Dialect::Responses),
        "ollama" => Some(Dialect::Responses),
        "custom-responses" => Some(Dialect::Responses),
        "openrouter" => Some(Dialect::Responses),
        "sakana" => Some(Dialect::Responses),
        "xai" => Some(Dialect::Responses),
        "xai-oauth" => Some(Dialect::Responses),
        "openai-codex" => Some(Dialect::Responses),
        "openai-codex-device" => Some(Dialect::Responses),
        "amazon-bedrock" => Some(Dialect::Converse),
        "bedrock-mantle" => Some(Dialect::Responses),
        "cursor" => Some(Dialect::CursorAgent),
        "devin" => Some(Dialect::DevinAgent),
        "gitlab-duo-agent" => Some(Dialect::GitlabWorkflow),
        "ollama-cloud" => Some(Dialect::OllamaChat),
        "google" => Some(Dialect::Gemini),
        "google-vertex" => Some(Dialect::Vertex),
        "google-antigravity" => Some(Dialect::CloudCode),
        "google-gemini-cli" => Some(Dialect::CloudCode),
        "anthropic" => Some(Dialect::Messages),
        "minimax" => Some(Dialect::Messages),
        "umans" => Some(Dialect::Messages),
        "cloudflare-ai-gateway" => Some(Dialect::Messages),
        "custom-messages" => Some(Dialect::Messages),
        "vercel-ai-gateway" => Some(Dialect::Messages),
        // The recorded Messages default: a catalogue row that names no
        // `protocol` keeps the Anthropic-compatible leg, and the row's
        // declared protocol decides the actual send.
        "kimi-code" => Some(Dialect::Messages),
        "gitlab-duo" => Some(Dialect::ChatCompletions),
        "github-copilot" => Some(Dialect::ChatCompletions),
        "opencode-go" => Some(Dialect::ChatCompletions),
        "opencode-zen" => Some(Dialect::ChatCompletions),
        "custom-chat-completions" => Some(Dialect::ChatCompletions),
        "aiand" => Some(Dialect::ChatCompletions),
        "aimlapi" => Some(Dialect::ChatCompletions),
        "alibaba-coding-plan" => Some(Dialect::ChatCompletions),
        "alibaba-token-plan" => Some(Dialect::ChatCompletions),
        "baseten" => Some(Dialect::ChatCompletions),
        "cerebras" => Some(Dialect::ChatCompletions),
        "cline-pass" => Some(Dialect::ChatCompletions),
        "coreweave" => Some(Dialect::ChatCompletions),
        "deepinfra" => Some(Dialect::ChatCompletions),
        "deepseek" => Some(Dialect::ChatCompletions),
        "firepass" => Some(Dialect::ChatCompletions),
        "fireworks" => Some(Dialect::ChatCompletions),
        "gmi-cloud" => Some(Dialect::ChatCompletions),
        "groq" => Some(Dialect::ChatCompletions),
        "huggingface" => Some(Dialect::ChatCompletions),
        "kilo" => Some(Dialect::ChatCompletions),
        "litellm" => Some(Dialect::ChatCompletions),
        "llama.cpp" => Some(Dialect::ChatCompletions),
        "lm-studio" => Some(Dialect::ChatCompletions),
        "minimax-code" => Some(Dialect::ChatCompletions),
        "minimax-code-cn" => Some(Dialect::ChatCompletions),
        "mistral" => Some(Dialect::ChatCompletions),
        "moonshot" => Some(Dialect::ChatCompletions),
        "nanogpt" => Some(Dialect::ChatCompletions),
        "novita" => Some(Dialect::ChatCompletions),
        "nvidia" => Some(Dialect::ChatCompletions),
        "qianfan" => Some(Dialect::ChatCompletions),
        "qwen-portal" => Some(Dialect::ChatCompletions),
        "siliconflow" => Some(Dialect::ChatCompletions),
        "siliconflow-cn" => Some(Dialect::ChatCompletions),
        "synthetic" => Some(Dialect::ChatCompletions),
        "together" => Some(Dialect::ChatCompletions),
        "venice" => Some(Dialect::ChatCompletions),
        "vllm" => Some(Dialect::ChatCompletions),
        "wafer-serverless" => Some(Dialect::ChatCompletions),
        "xiaomi" => Some(Dialect::ChatCompletions),
        "xiaomi-token-plan-ams" => Some(Dialect::ChatCompletions),
        "xiaomi-token-plan-cn" => Some(Dialect::ChatCompletions),
        "xiaomi-token-plan-sgp" => Some(Dialect::ChatCompletions),
        "yolo-auto" => Some(Dialect::ChatCompletions),
        "zenmux" => Some(Dialect::ChatCompletions),
        // The canonical `zai` row and its `zai-coding-plan` sign-in alias
        // are one backend: the recorded Messages default, while the model's
        // bundled row selects the coding-plan transport per send.
        "zai" | "zai-coding-plan" => Some(Dialect::Messages),
        "zhipu-coding-plan" => Some(Dialect::ChatCompletions),
        _ => None,
    }
}

/// The recorded dialects a routed id can serve (DEC-017). Only the ids
/// with a route table in this build are listed; a single-dialect id
/// answers an empty slice and keeps [`dialect_for`] as its sole gate, and
/// a further routed id appends its own table here.
#[must_use]
pub fn routes_for(connection: &str) -> &'static [Dialect] {
    match connection {
        "gitlab-duo" => GITLAB_DUO_ROUTES,
        "github-copilot" => COPILOT_ROUTES,
        "opencode-go" => OPENCODE_GO_ROUTES,
        "opencode-zen" => OPENCODE_ZEN_ROUTES,
        "zenmux" => ZENMUX_ROUTES,
        "kimi-code" => kimi::dialects(),
        "zai" | "zai-coding-plan" => zai::dialects(),
        _ => &[],
    }
}

/// Whether a failed entered send on `from` must not be re-dispatched onto
/// `to`: both literals resolve to one recorded contract whose arm forbids
/// a blind same-backend retry (PROH-020). The routing owner consults this
/// before minting a fallback substitute.
#[must_use]
pub(crate) fn blind_retry_refused(from: &str, to: &str) -> bool {
    openai::refuses_blind_retry(from) && openai::same_recorded_contract(from, to)
}

/// The recorded dialect a routed id serves for `model` (REQ-038); `None`
/// for an unrouted id or a model outside a closed recorded set.
#[must_use]
pub fn route_for(connection: &str, model: &str) -> Option<Dialect> {
    routed_wire_model(connection, model).map(|(_, dialect)| dialect)
}

/// The GitLab alias table (DEC-013): the public alias is deployment
/// identity, and its `upstreamModelId` is the wire model. The table is
/// closed — an alias outside it has no recorded route.
const GITLAB_DUO_MODELS: &[(&str, &str, Dialect)] = &[
    ("duo-chat-opus-4-6", "claude-opus-4-6", Dialect::Messages),
    (
        "duo-chat-sonnet-4-6",
        "claude-sonnet-4-6",
        Dialect::Messages,
    ),
    (
        "duo-chat-opus-4-5",
        "claude-opus-4-5-20251101",
        Dialect::Messages,
    ),
    (
        "duo-chat-sonnet-4-5",
        "claude-sonnet-4-5-20250929",
        Dialect::Messages,
    ),
    (
        "duo-chat-haiku-4-5",
        "claude-haiku-4-5-20251001",
        Dialect::Messages,
    ),
    (
        "duo-chat-gpt-5-1",
        "gpt-5.1-2025-11-13",
        Dialect::ChatCompletions,
    ),
    (
        "duo-chat-gpt-5-2",
        "gpt-5.2-2025-12-11",
        Dialect::ChatCompletions,
    ),
    (
        "duo-chat-gpt-5-mini",
        "gpt-5-mini-2025-08-07",
        Dialect::ChatCompletions,
    ),
    ("duo-chat-gpt-5-codex", "gpt-5-codex", Dialect::Responses),
    (
        "duo-chat-gpt-5-2-codex",
        "gpt-5.2-codex",
        Dialect::Responses,
    ),
];

const GITLAB_DUO_ROUTES: &[Dialect] = &[
    Dialect::Messages,
    Dialect::Responses,
    Dialect::ChatCompletions,
];

/// The recorded `github-copilot` route table: Messages for the Claude
/// families, Responses for the recorded GPT/Grok/Mai rows, and the Chat
/// Completions default for everything else.
const COPILOT_ROUTES: &[Dialect] = &[
    Dialect::Messages,
    Dialect::ChatCompletions,
    Dialect::Responses,
];

/// The closed 44-id `github-copilot` catalogue table with each row's
/// recorded `api` column. A model outside this table has no route, even
/// when its name matches a recorded family prefix or glob.
const COPILOT_MODELS: &[(&str, &str)] = &[
    ("claude-fable-5", "anthropic-messages"),
    ("claude-haiku-4.5", "anthropic-messages"),
    ("claude-opus-4.5", "anthropic-messages"),
    ("claude-opus-4.6", "anthropic-messages"),
    ("claude-opus-4.7", "anthropic-messages"),
    ("claude-opus-4.8", "anthropic-messages"),
    ("claude-opus-5", "anthropic-messages"),
    ("claude-sonnet-4", "anthropic-messages"),
    ("claude-sonnet-4.5", "anthropic-messages"),
    ("claude-sonnet-4.6", "anthropic-messages"),
    ("claude-sonnet-5", "anthropic-messages"),
    ("gemini-2.5-pro", "openai-completions"),
    ("gemini-3-flash-preview", "openai-completions"),
    ("gemini-3-pro-preview", "openai-completions"),
    ("gemini-3.1-pro-preview", "openai-completions"),
    ("gemini-3.5-flash", "openai-completions"),
    ("gemini-3.6-flash", "openai-completions"),
    ("gemini-3.7-flash", "openai-completions"),
    ("gpt-4.1", "openai-completions"),
    ("gpt-4o", "openai-completions"),
    ("gpt-5", "openai-responses"),
    ("gpt-5-mini", "openai-responses"),
    ("gpt-5.1", "openai-responses"),
    ("gpt-5.1-codex", "openai-responses"),
    ("gpt-5.1-codex-max", "openai-responses"),
    ("gpt-5.1-codex-mini", "openai-responses"),
    ("gpt-5.2", "openai-responses"),
    ("gpt-5.2-codex", "openai-responses"),
    ("gpt-5.3-codex", "openai-responses"),
    ("gpt-5.4", "openai-responses"),
    ("gpt-5.4-mini", "openai-responses"),
    ("gpt-5.4-nano", "openai-responses"),
    ("gpt-5.5", "openai-responses"),
    ("gpt-5.6-luna", "openai-responses"),
    ("gpt-5.6-sol", "openai-responses"),
    ("gpt-5.6-terra", "openai-responses"),
    ("grok-4.5", "openai-responses"),
    ("grok-4.6", "openai-responses"),
    ("grok-code-fast-1", "openai-completions"),
    ("kimi-k2.7-code", "openai-completions"),
    ("kimi-k3", "openai-completions"),
    ("mai-code-1-flash-picker", "openai-responses"),
    ("mai-code-1.1-flash", "openai-responses"),
    ("raptor-mini", "openai-completions"),
];

/// The recorded `github-copilot` route for one table row: its `api`
/// column decides the codec, and only the three recorded columns have a
/// route — an id outside the closed table answers `None`.
fn copilot_route(model: &str) -> Option<Dialect> {
    let (_, api) = COPILOT_MODELS.iter().find(|(id, _)| *id == model)?;
    match *api {
        "anthropic-messages" => Some(Dialect::Messages),
        "openai-completions" => Some(Dialect::ChatCompletions),
        "openai-responses" => Some(Dialect::Responses),
        _ => None,
    }
}

/// The sorted-first id of the closed `github-copilot` route table: the
/// deterministic auto pick over the connection's recorded catalogue.
fn copilot_first_model() -> Option<&'static str> {
    COPILOT_MODELS.iter().map(|(id, _)| *id).min()
}

/// The `opencode-go` route table (DEC-014): Chat Completions is the
/// recorded `defaultResolution`; the GPT/Grok/Muse families and
/// `deepseek-v4-flash` ride Responses; the MiniMax M2.5, Qwen and
/// Claude families ride Messages except where the recorded CC exacts
/// override them.
const OPENCODE_GO_ROUTES: &[Dialect] = &[
    Dialect::ChatCompletions,
    Dialect::Messages,
    Dialect::Responses,
];

/// The recorded `opencode-go` route for one model (DEC-014): the
/// Responses classes first, then the recorded CC exacts, then the
/// Messages families, and finally the recorded Chat Completions
/// default.
fn opencode_go_route(model: &str) -> Dialect {
    if model.starts_with("gpt-")
        || model.starts_with("grok-")
        || model.starts_with("muse-")
        || model == "deepseek-v4-flash"
    {
        Dialect::Responses
    } else if matches!(
        model,
        "minimax-m2.7" | "minimax-m3" | "minimax-m3-free" | "qwen3.5-plus" | "qwen3.6-plus"
    ) {
        Dialect::ChatCompletions
    } else if model.starts_with("claude-")
        || model.starts_with("qwen")
        || model.starts_with("minimax-m2.5")
    {
        Dialect::Messages
    } else {
        Dialect::ChatCompletions
    }
}

/// The `opencode-zen` route table (DEC-014/DEC-018): Chat Completions
/// is the recorded `defaultResolution`, and the overrides route Claude/
/// `qwen-` to Messages, GPT/Grok/Muse to Responses and Gemini to its
/// own dialect.
const OPENCODE_ZEN_ROUTES: &[Dialect] = &[
    Dialect::ChatCompletions,
    Dialect::Messages,
    Dialect::Responses,
    Dialect::Gemini,
];

/// The recorded `opencode-zen` route for one model: the family
/// overrides first, then the recorded Chat Completions default —
/// an id matching no override rides that default (DEC-018).
fn opencode_zen_route(model: &str) -> Dialect {
    if model.starts_with("gpt-") || model.starts_with("grok-") || model.starts_with("muse-") {
        Dialect::Responses
    } else if model.starts_with("claude-") || model.starts_with("qwen-") {
        Dialect::Messages
    } else if model.starts_with("gemini-") {
        Dialect::Gemini
    } else {
        Dialect::ChatCompletions
    }
}

/// The `zenmux` route table: the recorded Chat Completions default and
/// the Messages route its authoritative metadata's Anthropic class
/// takes — never a further dialect, and never a fallback between them.
const ZENMUX_ROUTES: &[Dialect] = &[Dialect::ChatCompletions, Dialect::Messages];

/// The recorded `zenmux` OpenAI-compatible API root.
const ZENMUX_OPENAI_BASE: &str = "https://zenmux.ai/api/v1";

/// The recorded `zenmux` Anthropic Messages root.
const ZENMUX_ANTHROPIC_BASE: &str = "https://zenmux.ai/api/anthropic";

/// The recorded `zenmux` Chat Completions base resolution
/// (`normalizeZenMuxOpenAiBaseUrl`): an empty configured base resolves
/// the recorded root, one trailing slash is dropped, and a base naming
/// the Messages root folds onto the Chat Completions root — the two
/// bases are one fixed pair, never two unrelated origins.
pub(crate) fn zenmux_openai_base(configured: &str) -> String {
    let trimmed = configured.trim();
    if trimmed.is_empty() {
        return ZENMUX_OPENAI_BASE.to_string();
    }
    let normalized = trimmed.strip_suffix('/').unwrap_or(trimmed);
    match normalized.strip_suffix("/api/anthropic") {
        Some(origin) => format!("{origin}/api/v1"),
        None => normalized.to_string(),
    }
}

/// The recorded `zenmux` Messages base (`toZenMuxAnthropicBaseUrl`):
/// derived from the Chat Completions base's origin, replacing its
/// `/api/v1` suffix with `/api/anthropic` and keeping any custom
/// origin. The recorded fixed pair is the fallback for a base that is
/// not a URL.
pub(crate) fn zenmux_anthropic_base(configured: &str) -> String {
    let openai = zenmux_openai_base(configured);
    let Ok(mut url) = reqwest::Url::parse(&openai) else {
        return ZENMUX_ANTHROPIC_BASE.to_string();
    };
    let path = url.path().trim_end_matches('/');
    let mirror = match path.strip_suffix("/api/v1") {
        Some(origin) => format!("{origin}/api/anthropic"),
        None => "/api/anthropic".to_string(),
    };
    url.set_path(&mirror);
    url.to_string()
}

/// The recorded `zenmux` Anthropic class (HZN-16-01): the authoritative
/// metadata's owning provider, which its `<provider>/<model>` slug
/// carries, is the routed class mark. The listing's `owned_by` is the
/// catalogue authority and the slug is the same owner identity the wire
/// names, so the two agree by construction; when a record disagreed, the
/// slug still decides the route because it is the wire identity the
/// metadata row offers, and the row is never rewritten. Every other id —
/// including an id outside the metadata — is the recorded Chat
/// Completions default, so no family name or auth label ever infers the
/// Messages route.
pub(crate) fn zenmux_is_anthropic(model: &str) -> bool {
    model
        .split_once('/')
        .is_some_and(|(owner, _)| owner.eq_ignore_ascii_case("anthropic"))
}

/// The recorded `zenmux` route for one model: the metadata's Anthropic
/// class takes Messages; everything else rides the Chat Completions
/// default (never a cross-route fallback).
fn zenmux_route(model: &str) -> Dialect {
    if zenmux_is_anthropic(model) {
        Dialect::Messages
    } else {
        Dialect::ChatCompletions
    }
}

/// The wire model and route of a routed id's model: the GitLab alias
/// table's `upstreamModelId`, the `github-copilot` closed 44-id table's
/// recorded `api` column (a model outside that table has no route), or
/// the `opencode-go`/`opencode-zen`/`zenmux` class route over the
/// verbatim model id. `None` is the closed-set denial.
pub(crate) fn routed_wire_model(connection: &str, model: &str) -> Option<(String, Dialect)> {
    match connection {
        "gitlab-duo" => GITLAB_DUO_MODELS
            .iter()
            .find(|(alias, ..)| *alias == model)
            .map(|(_, upstream, dialect)| ((*upstream).to_string(), *dialect)),
        "github-copilot" => copilot_route(model).map(|dialect| (model.to_string(), dialect)),
        "opencode-go" => Some((model.to_string(), opencode_go_route(model))),
        "opencode-zen" => Some((model.to_string(), opencode_zen_route(model))),
        "zenmux" => Some((model.to_string(), zenmux_route(model))),
        _ => None,
    }
}

/// The aliases a routed id offers as its catalogue: GitLab's static
/// alias table, or `None` where the catalogue is the one keyed gateway
/// listing its route table filters.
pub(crate) fn routed_catalog(connection: &str) -> Option<Vec<CatalogModel>> {
    match connection {
        "gitlab-duo" => Some(
            GITLAB_DUO_MODELS
                .iter()
                .map(|(alias, ..)| CatalogModel {
                    id: (*alias).to_string(),
                    ..CatalogModel::default()
                })
                .collect(),
        ),
        _ => None,
    }
}

/// The catalogue rows this build records for one connection (DEC-013,
/// AC-096): the alias table a routed id ships, else the recorded allowlist or
/// recorded seed rows of its Chat Completions class. An empty answer is the
/// unknown fact — the ranker never invents a row for a connection that records
/// none, and no live read happens here.
#[must_use]
pub(crate) fn recorded_models(connection: &str) -> Vec<CatalogModel> {
    match routed_catalog(connection) {
        Some(rows) => rows,
        None => local::recorded_catalog(connection),
    }
}

pub trait Provider: Send {
    fn name(&self) -> &'static str;
    /// Whether this adapter's dialect serves `connection` — the send
    /// seam's fail-closed gate (AC-046): eligibility says a connection
    /// is theoretically usable; only the injected provider can say it
    /// speaks its dialect, and a manifest it cannot honour is a typed
    /// denial, never a fabricated reply. Every implementor — test
    /// doubles included — declares the rule; a scripted double that
    /// answers anything returns `true`.
    fn serves(&self, connection: &str, entry: &Connection) -> bool;
    /// Whether this adapter's recorded model surface answers image input
    /// (TD-20): the typed vision path admits a request only when the pinned
    /// connection serves it and this capability holds, so an adapter that
    /// cannot honour an image denies it typed instead of dropping it. The
    /// default is `false`; an adapter whose recorded catalogue states the
    /// mark overrides it.
    fn image_input(&self, connection: &str, model: &str) -> bool {
        let _ = (connection, model);
        false
    }
    fn send(&mut self, manifest: &RequestManifest) -> Result<ProviderReply, ProviderError>;
}

/// Offline loopback: answers from local fixtures only, zero network. The
/// fixture decision reads a `read <path>` instruction out of the manifest
/// inputs and returns it as a tool call for the executor boundary.
pub struct LoopbackProvider {
    calls: u64,
}

impl LoopbackProvider {
    pub fn new() -> Self {
        Self { calls: 0 }
    }

    pub fn calls(&self) -> u64 {
        self.calls
    }
}

impl Default for LoopbackProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl Provider for LoopbackProvider {
    fn name(&self) -> &'static str {
        "loopback"
    }

    /// The offline fixture answers local connections only — a pin to
    /// a credentialled or subscribed class is a dialect it does not
    /// speak, so the seam denies it rather than fabricating a reply.
    /// An id [`dialect_for`] reserves is a live dialect's connection
    /// even when it declares `local` kind: reserved ids are never
    /// fixture-served.
    fn serves(&self, connection: &str, entry: &Connection) -> bool {
        entry.kind == ConnKind::Local && dialect_for(connection).is_none()
    }

    fn send(&mut self, manifest: &RequestManifest) -> Result<ProviderReply, ProviderError> {
        self.calls += 1;
        let path = manifest
            .inputs
            .lines()
            .rev()
            .find_map(|line| line.strip_prefix("read ").map(str::to_string));
        match path {
            Some(path) => Ok(ProviderReply {
                text: ADMITTED_READ.to_string(),
                tool_calls: vec![ToolCall {
                    tool: "read_file".to_string(),
                    path: Some(path),
                }],
                usage: UsageDelta::Unknown,
                wire_retries: 0,
                dropped_reasoning: 0,
            }),
            None => Ok(ProviderReply {
                text: WAITING_FOR_DECISION.to_string(),
                tool_calls: Vec::new(),
                usage: UsageDelta::Unknown,
                wire_retries: 0,
                dropped_reasoning: 0,
            }),
        }
    }
}

/// The credential seam the production provider factory receives. The
/// platform backend opens on the first scope a send resolves, so an open —
/// and a runtime whose config declares no credentialled connection — never
/// touches a keyring. Backends are kept per `(class, account)` so the
/// per-profile refresh serialization holds across sends; the map is bounded
/// by the distinct scopes config can reference.
struct PlatformStore {
    opened: Mutex<BTreeMap<(StoreKind, String), Arc<FlightedStore>>>,
}

impl PlatformStore {
    fn store_for(&self, credential: &SecretRef) -> Result<Arc<FlightedStore>, ProviderError> {
        let key = (credential.store(), credential.service().to_string());
        // The map is a plain cache: a poisoning writer left no torn entry,
        // so recovering the guard cannot expose a half-built backend.
        let mut opened = self
            .opened
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(store) = opened.get(&key) {
            return Ok(Arc::clone(store));
        }
        let store = Arc::new(native_store(key.0, &key.1)?);
        opened.insert(key, Arc::clone(&store));
        drop(opened);
        Ok(store)
    }
}

impl CredentialStore for PlatformStore {
    fn kind(&self) -> StoreKind {
        native_store_kind()
    }

    fn occupied(&self, credential: &SecretRef) -> Result<bool, ProviderError> {
        self.store_for(credential)?.occupied(credential)
    }

    fn entry_accounts(&self, service: &str) -> Result<Vec<String>, ProviderError> {
        native_store(native_store_kind(), service)?.entry_accounts(service)
    }

    fn login(&self, credential: &SecretRef, secret: &[u8]) -> Result<(), ProviderError> {
        self.store_for(credential)?.login(credential, secret)
    }

    fn resolve(&self, credential: &SecretRef) -> Result<Vec<u8>, ProviderError> {
        self.store_for(credential)?.resolve(credential)
    }

    fn refresh(&self, credential: &SecretRef, secret: &[u8]) -> Result<(), ProviderError> {
        self.store_for(credential)?.refresh(credential, secret)
    }

    fn revoke(&self, credential: &SecretRef) -> Result<(), ProviderError> {
        self.store_for(credential)?.revoke(credential)
    }

    fn logout(&self, credential: &SecretRef) -> Result<(), ProviderError> {
        self.store_for(credential)?.logout(credential)
    }
}

/// The platform credential seam a configured runtime hands its provider
/// factory: both native classes open lazily, one backend per
/// `(class, account)` scope the config references.
#[must_use]
pub fn platform_credential_store() -> Arc<dyn CredentialStore> {
    Arc::new(PlatformStore {
        opened: Mutex::new(BTreeMap::new()),
    })
}

/// The recorded dialect this build has an installed adapter for. `None`
/// means the Broker's own send gate names the denial: an id with no
/// recorded wire is a dialect mismatch, and the two agent backends without
/// an adapter are the recorded unserved class.
fn installed_dialect(connection: &str) -> Option<Dialect> {
    match dialect_for(connection)? {
        Dialect::CursorAgent | Dialect::DevinAgent => None,
        dialect => Some(dialect),
    }
}

/// The whole-send budget the adapters' own constructors default to; the
/// Bedrock constructor takes it explicitly, so the configured set passes the
/// same figure instead of inventing a second one.
const PROVIDER_SEND_DEADLINE: Duration = Duration::from_secs(120);

/// One declared connection the provider build refused: the typed cause,
/// named by the row that produced it. The connection stays uninstalled, so
/// the broker's send gate denies it typed before any request, and the
/// runtime reports this cause instead of swallowing it.
#[derive(Debug)]
pub struct ProviderRefusal {
    pub connection: String,
    pub error: ProviderError,
}

/// One provider a factory built, beside every declared connection the build
/// refused. A whole-build refusal is the factory's own `Err`; a refused row
/// never fails the build, so one unbuildable declaration cannot brick the
/// open around it.
pub struct ProviderBuild {
    pub provider: Box<dyn Provider>,
    pub refusals: Vec<ProviderRefusal>,
}

impl std::fmt::Debug for ProviderBuild {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderBuild")
            .field("provider", &self.provider.name())
            .field("refusals", &self.refusals)
            .finish()
    }
}

/// The production adapter set (TD-01): one [`Provider`] over the shipped
/// codecs, built from the admitted config. Each declared connection whose
/// recorded class has an installed adapter is constructed once here — the
/// only production provider construction site — so a config reload builds a
/// new set from the new config. Every adapter records the connection entry
/// it was built from: [`Provider::serves`] answers only for that entry, so
/// an adapter whose config diverged from the served view refuses the send
/// instead of crossing it under bytes nobody admitted.
/// Connections without an installed adapter are not built: the Broker's
/// dialect claim denies them typed before any send.
pub struct ConfiguredProvider {
    adapters: BTreeMap<String, (Connection, Box<dyn Provider>)>,
}

impl std::fmt::Debug for ConfiguredProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConfiguredProvider")
            .field("connections", &self.adapters.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl ConfiguredProvider {
    /// The adapter one connection's recorded dialect names.
    fn adapter_for(
        config: &Config,
        connection: &str,
        dialect: Dialect,
        store: &Arc<dyn CredentialStore>,
    ) -> Result<Box<dyn Provider>, ProviderError> {
        let store = Arc::clone(store);
        // The Kimi owner builds its own literal adapter: its two protocols
        // are resolved per model from the catalogue listing, so it is not
        // one of the single-dialect codec arms below.
        if connection == kimi::CONNECTION {
            return Ok(Box::new(kimi::KimiProvider::new(
                config, connection, store,
            )?));
        }
        // Z.AI's two literals resolve the bundled row's transport per model,
        // so the literal owner builds this adapter, never a single-dialect
        // codec arm.
        if zai::serves_literal(connection) {
            return Ok(Box::new(zai::ZaiProvider::new(config, connection, store)?));
        }
        match dialect {
            Dialect::Responses => Ok(Box::new(openai::OpenAiProvider::new(
                config, connection, store,
            )?)),
            Dialect::Messages => Ok(Box::new(anthropic::MessagesProvider::new(
                config, connection, store,
            )?)),
            Dialect::ChatCompletions => match connection {
                "github-copilot" => Ok(Box::new(copilot::CopilotProvider::new(
                    config, connection, store,
                )?)),
                "gitlab-duo" | "opencode-go" | "opencode-zen" | "zenmux" => Ok(Box::new(
                    routed::RoutedProvider::new(config, connection, store)?,
                )),
                _ => Ok(Box::new(local::ChatCompletionsProvider::new(
                    config, connection, store,
                )?)),
            },
            Dialect::Gemini => Ok(Box::new(gemini::GeminiProvider::new(
                config, connection, store,
            )?)),
            Dialect::OllamaChat => Ok(Box::new(ollama_cloud::OllamaCloudProvider::new(
                config, connection, store,
            )?)),
            Dialect::Converse => Ok(Box::new(bedrock::BedrockProvider::new(
                config,
                connection,
                store,
                PROVIDER_SEND_DEADLINE,
            )?)),
            Dialect::GitlabWorkflow => Ok(Box::new(gitlab_workflow::GitlabWorkflowProvider::new(
                config, connection, store,
            )?)),
            Dialect::Vertex => Ok(Box::new(vertex::VertexProvider::new(
                config, connection, store,
            )?)),
            Dialect::CloudCode => match connection {
                "google-antigravity" => Ok(Box::new(cloudcode::CloudCodeProvider::new(
                    config, connection, store,
                )?)),
                "google-gemini-cli" => Ok(Box::new(cloudcode::GeminiCliProvider::new(
                    config, connection, store,
                )?)),
                _ => Err(ProviderError::DialectUnserved {
                    connection: connection.to_string(),
                    dialect,
                }),
            },
            Dialect::CursorAgent | Dialect::DevinAgent => Err(ProviderError::DialectUnserved {
                connection: connection.to_string(),
                dialect,
            }),
        }
    }
}

impl Provider for ConfiguredProvider {
    fn name(&self) -> &'static str {
        "configured"
    }

    /// The entry this connection's adapter was built from is the only one it
    /// serves: a served view that moved without a rebuild refuses the send
    /// here, before the adapter or the ledger sees the request. The dispatch
    /// re-check already denies a moved entry as `ConnectionChanged`; this is
    /// the adapter's own half of the same guarantee, so no divergence between
    /// the installed set and the served view can silently cross the wire.
    fn serves(&self, connection: &str, entry: &Connection) -> bool {
        self.adapters
            .get(connection)
            .is_some_and(|(built, _)| built == entry)
    }

    /// The installed adapter's own recorded capability — a connection the
    /// set did not build answers `false` rather than borrowing a sibling's.
    fn image_input(&self, connection: &str, model: &str) -> bool {
        self.adapters
            .get(connection)
            .is_some_and(|(_, adapter)| adapter.image_input(connection, model))
    }

    fn send(&mut self, manifest: &RequestManifest) -> Result<ProviderReply, ProviderError> {
        // The Broker narrows every send to one connection before this seam;
        // a manifest that still names a pool is a caller error, never a
        // reason to pick one.
        let connection = match &manifest.model {
            ModelAssign::Fixed(fixed) => fixed.connection.as_str(),
            ModelAssign::Auto { pool: Some(pool) } if pool.len() == 1 => pool[0].as_str(),
            _ => {
                return Err(ProviderError::UnsendableRequest {
                    connection: "manifest".to_string(),
                    reason: "the model assignment names no single connection".to_string(),
                });
            }
        };
        let Some((_, adapter)) = self.adapters.get_mut(connection) else {
            return Err(ProviderError::DialectMismatch {
                connection: connection.to_string(),
            });
        };
        // A typed image rides only the adapter that records its mark
        // (TD-21): a substitute minted from a failed attempt keeps the
        // image, so a retry whose dialect cannot honour it denies typed
        // here instead of letting that codec drop the image.
        if manifest.image.is_some() {
            let ModelAssign::Fixed(fixed) = &manifest.model else {
                return Err(ProviderError::UnsendableRequest {
                    connection: connection.to_string(),
                    reason: "an image request names no single model".to_string(),
                });
            };
            if !adapter.image_input(connection, &fixed.model_id) {
                return Err(ProviderError::UnsupportedParameter {
                    connection: connection.to_string(),
                    parameter: "image",
                    model: fixed.model_id.clone(),
                });
            }
        }
        adapter.send(manifest)
    }
}

/// Builds the production provider for the admitted config (TD-01): the one
/// construction site both entrypoints pass to `Runtime::open_configured`,
/// and the one a config reload re-runs.
///
/// A declared connection whose recorded class refuses to build — an unknown
/// or region-mismatched declaration, a local row binding a profile, an
/// unresolvable credential binding — is left uninstalled and its typed cause
/// is recorded in [`ProviderBuild::refusals`], so one unbuildable row never
/// refuses the whole set and the runtime reports the cause. A connection with
/// no installed adapter is not a refusal either: the Broker denies it before
/// any send.
///
/// # Errors
/// Nothing today: the set is total, and every refusal is per connection. The
/// seam keeps the whole-build refusal so a factory that cannot build any
/// provider fails the open and the rebuild closed instead of installing
/// nothing.
pub fn configured_provider(
    config: &Config,
    store: &Arc<dyn CredentialStore>,
) -> Result<ProviderBuild, ProviderError> {
    let mut adapters: BTreeMap<String, (Connection, Box<dyn Provider>)> = BTreeMap::new();
    let mut refusals = Vec::new();
    for (connection, entry) in &config.connections {
        let Some(dialect) = installed_dialect(connection) else {
            continue;
        };
        match ConfiguredProvider::adapter_for(config, connection, dialect, store) {
            Ok(adapter) => {
                adapters.insert(connection.clone(), (entry.clone(), adapter));
            }
            Err(error) => refusals.push(ProviderRefusal {
                connection: connection.clone(),
                error,
            }),
        }
    }
    Ok(ProviderBuild {
        provider: Box::new(ConfiguredProvider { adapters }),
        refusals,
    })
}

/// Whether a literal connection id records the credential-optional
/// absent-binding form: the open proxy (`litellm`) — a configured proxy
/// that serves with or without a key — the local-endpoint class
/// (`llama.cpp`, `lm-studio`, `ollama`, `vllm`) — a local server whose
/// recorded auth is optional beside its server-key mode — and the
/// custom-origin class (`custom-responses`, `custom-messages`) — an
/// operator-configured origin whose recorded auth is optional
/// (DEC-015). Each admits a declaration that omits `credential_ref`, an
/// absent binding sends no credential header — never a dummy key — and
/// the pin stays offline-usable. The catalogue-only `openrouter` is the
/// exception this predicate excludes: [`admit_absent_binding`] admits
/// its unbound declaration at ingress for the keyless `GET /models`,
/// while this send/eligibility answer stays false. Every other
/// `api_key` id requires its scoped binding at ingress and at
/// eligibility.
///
/// Its contract-side twin for the CC local-endpoint ids (`litellm`,
/// `llama.cpp`, `lm-studio`, `vllm`) is `CredentialRule::OpenProxy` in
/// the local adapter's per-id table, the arm that carries the class's
/// wire form; `ollama`'s contract side is the Responses adapter's
/// `Option<SecretRef>` arm, and `custom-responses`' is its own
/// Responses `SourceContract` arm.
#[must_use]
pub(crate) fn open_proxy_connection(connection: &str) -> bool {
    matches!(
        connection,
        "litellm"
            | "llama.cpp"
            | "lm-studio"
            | "ollama"
            | "vllm"
            | "custom-responses"
            | "custom-messages"
    )
}

/// Whether a literal connection id records the absent-binding form at
/// ingress (DEC-009/DEC-010): the credential-optional classes
/// [`open_proxy_connection`] names, plus `openrouter` — whose keyless
/// `GET /models` is reachable only when the declaration may omit its
/// `credential_ref`. This is the ingress predicate alone:
/// [`open_proxy_connection`] stays the send/eligibility answer, so an
/// unbound `openrouter` row is admitted here and still not
/// send-eligible.
#[must_use]
pub(crate) fn admit_absent_binding(connection: &str) -> bool {
    open_proxy_connection(connection) || connection == "openrouter"
}

/// The [`resolve_credential_in`] leg the two absent-binding classes
/// share: a declaration `absent` names that binds no credential at all
/// resolves `None`, while every other binding resolves the scoped
/// [`SecretRef`] unchanged. A bound-but-malformed or
/// profile-mismatched reference keeps its typed denial — the absent
/// binding is the only admitted form.
///
/// # Errors
/// [`resolve_credential_in`]'s typed denials for every binding the
/// declaration does carry.
fn resolve_absent_binding_in(
    connections: &BTreeMap<String, Connection>,
    profiles: &BTreeMap<String, Profile>,
    connection: &str,
    absent: fn(&str) -> bool,
) -> Result<Option<SecretRef>, ProviderError> {
    let unbound = connections
        .get(connection)
        .is_some_and(|conn| conn.profile.is_none() && conn.credential_ref.is_none());
    if unbound && absent(connection) {
        return Ok(None);
    }
    resolve_credential_in(connections, profiles, connection).map(Some)
}

/// [`resolve_absent_binding_in`] under the send/eligibility predicate:
/// a connection of that class whose declaration binds no credential at
/// all resolves `None`; an unbound `openrouter` connection does not —
/// it lists keylessly and never sends.
///
/// # Errors
/// [`resolve_credential_in`]'s typed denials for every binding the
/// declaration does carry.
pub(crate) fn resolve_optional_credential_in(
    connections: &BTreeMap<String, Connection>,
    profiles: &BTreeMap<String, Profile>,
    connection: &str,
) -> Result<Option<SecretRef>, ProviderError> {
    resolve_absent_binding_in(connections, profiles, connection, open_proxy_connection)
}

/// [`resolve_absent_binding_in`] under the config-ingress admission
/// (DEC-010): a declaration the ingress predicate
/// [`admit_absent_binding`] names resolves `None` when it binds no
/// credential at all, so the keyless catalogue leg builds. Eligibility
/// keeps the narrower [`open_proxy_connection`] answer — an unbound
/// `openrouter` connection lists here and never sends.
///
/// # Errors
/// [`ProviderError::DialectMismatch`] for `github-copilot`, whose
/// dedicated owner builds its own credential-derived codec, and
/// [`resolve_credential_in`]'s typed denials for every binding the
/// declaration does carry.
pub(crate) fn resolve_admitted_credential_in(
    connections: &BTreeMap<String, Connection>,
    profiles: &BTreeMap<String, Profile>,
    connection: &str,
) -> Result<Option<SecretRef>, ProviderError> {
    if connection == "github-copilot" {
        // DEC-016: the shared builders stop here; only
        // [`copilot::CopilotProvider`] may construct this id, because its
        // base and CAPI identity come from the stored credential.
        return Err(ProviderError::DialectMismatch {
            connection: connection.to_string(),
        });
    }
    resolve_absent_binding_in(connections, profiles, connection, admit_absent_binding)
}

/// Connection eligibility for offline dispatch (DEC-011): local
/// connections are always usable; an `api_key` connection is usable
/// exactly when its recorded auth class resolves a scoped
/// [`SecretRef`] — or, on the recorded absent-binding class, when its
/// declaration binds none — catalogue presence is never entitlement,
/// and an unresolved binding keeps the typed live-grant denial.
///
/// # Errors
/// [`ProviderError::UnknownConnection`] for a fixed pin on an
/// undeclared connection; [`ProviderError::LiveGrantRequired`] for a
/// non-local pin whose credential does not resolve.
pub fn offline_eligible(
    model: &ModelAssign,
    connections: &BTreeMap<String, Connection>,
    profiles: &BTreeMap<String, Profile>,
) -> Result<(), ProviderError> {
    let ModelAssign::Fixed(fixed) = model else {
        return Ok(());
    };
    match connections.get(&fixed.connection) {
        None => Err(ProviderError::UnknownConnection {
            connection: fixed.connection.clone(),
        }),
        Some(_) if offline_usable(connections, profiles, &fixed.connection) => Ok(()),
        Some(entry) => Err(ProviderError::LiveGrantRequired { kind: entry.kind }),
    }
}

/// Offline eligibility as a ranking predicate (AC-044/DEC-011): a
/// candidate usable without a separate live grant — a local
/// connection always; an `api_key` one exactly when its credential
/// resolves, or binds none on the recorded absent-binding class. A
/// `subscription` names a live grant no scoped reference
/// confers — it stays grant-gated until the subscription machinery
/// lands. Ranking filters candidates with this; [`offline_eligible`]
/// keeps the typed rejection vocabulary for the single-candidate
/// fixed path. A `local` declaration of a dialect-reserved id ranks
/// here and its dispatch still denies typed — ranking says the pin is
/// usable without a live grant, never that the send succeeds.
#[must_use]
pub fn offline_usable(
    connections: &BTreeMap<String, Connection>,
    profiles: &BTreeMap<String, Profile>,
    connection: &str,
) -> bool {
    match connections.get(connection) {
        None => false,
        Some(entry) => match entry.kind {
            ConnKind::Local => true,
            ConnKind::ApiKey => {
                resolve_optional_credential_in(connections, profiles, connection).is_ok()
            }
            ConnKind::Subscription => false,
        },
    }
}

/// Bytes read from a response stream per pass — the chunking is an
/// implementation detail the SSE parser is indifferent to.
pub(crate) const STREAM_CHUNK_BYTES: usize = 8 * 1024;

/// The bound on one catalogue payload — a listing never needs more,
/// and an unbounded or dribbling body is denied under the same budget
/// as a streamed response.
pub(crate) const CATALOG_MAX_BYTES: usize = 1024 * 1024;

/// The whole-request budget check (DEC-014): evaluated before the
/// post, before every stream read and before the final pass, so
/// connect, request send, reads and finalization share one deadline —
/// a peer dribbling a byte inside each per-read window parks the
/// stream only until the total budget is spent.
pub(crate) fn check_deadline(
    connection: &str,
    deadline: Duration,
    started: Instant,
) -> Result<(), ProviderError> {
    if started.elapsed() >= deadline {
        return Err(ProviderError::Transport {
            connection: connection.to_string(),
            cause: TransportCause::Deadline { budget: deadline },
        });
    }
    Ok(())
}

/// One bounded read under the shared deadline: the check runs before
/// the call, `Interrupted` retries in place, and any other read
/// failure is the typed transport error. Returns the bytes read — `0`
/// is the stream's end.
pub(crate) fn read_chunk(
    connection: &str,
    deadline: Duration,
    response: &mut reqwest::blocking::Response,
    chunk: &mut [u8],
    started: Instant,
) -> Result<usize, ProviderError> {
    loop {
        check_deadline(connection, deadline, started)?;
        match response.read(chunk) {
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(transport_io(connection, err)),
            Ok(read) => return Ok(read),
        }
    }
}

/// The catalogue body read under the shared deadline and byte bound —
/// a dribbling or oversized payload is denied, never parked or
/// buffered unbounded.
pub(crate) fn read_catalog_body(
    connection: &str,
    deadline: Duration,
    response: &mut reqwest::blocking::Response,
    started: Instant,
) -> Result<Vec<u8>, ProviderError> {
    let mut body = Vec::new();
    let mut chunk = vec![0u8; STREAM_CHUNK_BYTES];
    loop {
        let read = read_chunk(connection, deadline, response, &mut chunk, started)?;
        if read == 0 {
            break;
        }
        if body.len() + read > CATALOG_MAX_BYTES {
            return Err(violation(
                connection,
                "models payload exceeds the byte bound",
            ));
        }
        body.extend_from_slice(&chunk[..read]);
    }
    Ok(body)
}

/// The forwarded proxy headers as a request map: a name or value the
/// HTTP grammar rejects is never constructed — the exchange's untrusted
/// header object cannot smuggle framing through this seam.
pub(crate) fn forwarded_header_map(
    headers: &BTreeMap<String, String>,
) -> reqwest::header::HeaderMap {
    let mut map = reqwest::header::HeaderMap::new();
    for (name, value) in headers {
        let Ok(name) = reqwest::header::HeaderName::from_bytes(name.as_bytes()) else {
            continue;
        };
        let Ok(value) = reqwest::header::HeaderValue::from_str(value) else {
            continue;
        };
        map.insert(name, value);
    }
    map
}

/// The serialized body is what crosses the wire: it carries the
/// replayed lineage set, so the same byte bound the manifest's
/// accounted size promised is enforced on the actual bytes —
/// oversized, never truncated (AC-013). A body that cannot serialize
/// or overruns the bound is [`ProviderError::UnsendableRequest`]: the
/// refusal lands before the post, so it is definitive.
pub(crate) fn wire_body(connection: &str, body: &Value) -> Result<Vec<u8>, ProviderError> {
    let body_bytes = serde_json::to_vec(body).map_err(|_ser| ProviderError::UnsendableRequest {
        connection: connection.to_string(),
        reason: "request body could not serialize".to_string(),
    })?;
    if body_bytes.len() > crate::contracts::MODEL_WIRE_MAX_BYTES {
        return Err(ProviderError::UnsendableRequest {
            connection: connection.to_string(),
            reason: format!(
                "request body of {} bytes exceeds the {} byte wire bound",
                body_bytes.len(),
                crate::contracts::MODEL_WIRE_MAX_BYTES
            ),
        });
    }
    Ok(body_bytes)
}

/// How many conversation lineages one adapter retains across distinct
/// worlds and purposes: replay state is disposable, so a long-lived process
/// never accumulates every displaced epoch it ever saw.
pub(crate) const LINEAGE_EPOCH_LIMIT: usize = 16;

/// Retires every epoch of one conversation except `key`: a conversation
/// replays only the state its current epoch committed, so a displaced epoch
/// must not answer a later send.
pub(crate) fn retire_displaced_epochs<V>(
    epochs: &mut BTreeMap<(String, String, String), V>,
    key: &(String, String, String),
) {
    epochs.retain(|held, _| held.0 != key.0 || held.1 != key.1);
}

/// Records one committed epoch's replay state: the conversation's older
/// epochs are displaced and the lowest-keyed conversation is dropped past
/// the cap. An evicted epoch replays nothing — a miss, never stale bytes.
pub(crate) fn retain_lineage_epoch<V>(
    epochs: &mut BTreeMap<(String, String, String), V>,
    key: (String, String, String),
    value: V,
) {
    retire_displaced_epochs(epochs, &key);
    epochs.insert(key, value);
    while epochs.len() > LINEAGE_EPOCH_LIMIT && epochs.pop_first().is_some() {}
}

pub(crate) fn transport(connection: &str, err: reqwest::Error) -> ProviderError {
    ProviderError::Transport {
        connection: connection.to_string(),
        cause: TransportCause::Request {
            source: Arc::new(err.without_url()),
        },
    }
}

fn transport_io(connection: &str, err: std::io::Error) -> ProviderError {
    ProviderError::Transport {
        connection: connection.to_string(),
        cause: TransportCause::Read {
            source: Arc::new(err),
        },
    }
}

/// A non-success status is reported by code alone — the response
/// body is uncontrolled peer text and never enters diagnostics.
pub(crate) fn transport_status(connection: &str, status: reqwest::StatusCode) -> ProviderError {
    ProviderError::Transport {
        connection: connection.to_string(),
        cause: TransportCause::Status { status },
    }
}

pub(crate) fn sse(connection: &str, err: sse::SseError) -> ProviderError {
    ProviderError::StreamViolation {
        connection: connection.to_string(),
        reason: err.to_string(),
    }
}

pub(crate) fn violation(connection: &str, reason: impl Into<String>) -> ProviderError {
    ProviderError::StreamViolation {
        connection: connection.to_string(),
        reason: reason.into(),
    }
}

/// The byte bound on a peer-provided failure reason — enough for a real
/// verdict, far short of a payload a hostile peer could park in the
/// diagnostic surface.
pub(crate) const REASON_MAX_BYTES: usize = 1024;

/// Renders every C0/C1 control character and DEL as its visible
/// `\u{..}` escape, so peer text can never carry terminal control
/// sequences into a diagnostic.
fn escaped_controls(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for ch in text.chars() {
        if matches!(ch, '\u{0}'..='\u{1f}' | '\u{7f}'..='\u{9f}') {
            escaped.push_str(&format!("\\u{{{:x}}}", u32::from(ch)));
        } else {
            escaped.push(ch);
        }
    }
    escaped
}

/// Bounds a peer-provided failure reason to [`REASON_MAX_BYTES`] on a
/// UTF-8 char boundary — the reason stays valid text, never a
/// mid-sequence cut.
pub(crate) fn bounded_reason(reason: impl Into<String>) -> String {
    let reason = escaped_controls(&reason.into());
    if reason.len() <= REASON_MAX_BYTES {
        return reason;
    }
    let mut end = REASON_MAX_BYTES;
    while !reason.is_char_boundary(end) {
        end -= 1;
    }
    reason[..end].to_string()
}

/// The reason a failed verdict carries — the peer's own `message`,
/// `status` or `code` field, whichever it populated. Strings render with
/// control characters escaped and scalar numbers/booleans still read; a
/// nested object or array is structure, not prose, and is never
/// serialized into the reason.
pub(crate) fn payload_reason(payload: &Value) -> String {
    for field in ["message", "status", "code"] {
        match payload.get(field) {
            Some(Value::String(text)) => return escaped_controls(text),
            Some(scalar @ (Value::Number(_) | Value::Bool(_))) => return scalar.to_string(),
            _ => {}
        }
    }
    "unclassified".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    /// The recorded `github-copilot` table is closed: its 44 `api`
    /// columns are the only routes, and a family-shaped id that is not a
    /// row (or a prefix the rules name without a row) has no route.
    #[test]
    fn copilot_route_table_matches_the_recorded_rows() {
        assert_eq!(COPILOT_MODELS.len(), 44);
        for (id, api) in COPILOT_MODELS {
            let expected = match *api {
                "anthropic-messages" => Some(Dialect::Messages),
                "openai-completions" => Some(Dialect::ChatCompletions),
                "openai-responses" => Some(Dialect::Responses),
                _ => None,
            };
            assert!(expected.is_some(), "unrecorded copilot api column {api}");
            assert_eq!(copilot_route(id), expected, "{id}");
        }
        assert_eq!(
            route_for("github-copilot", "claude-opus-4.6"),
            Some(Dialect::Messages)
        );
        assert_eq!(
            route_for("github-copilot", "gpt-4o"),
            Some(Dialect::ChatCompletions)
        );
        assert_eq!(
            route_for("github-copilot", "gpt-5.2"),
            Some(Dialect::Responses)
        );
        assert_eq!(route_for("github-copilot", "gpt-6"), None);
        assert_eq!(route_for("github-copilot", "claude-mythos-9"), None);
        assert_eq!(
            routed_wire_model("github-copilot", "grok-4.5"),
            Some(("grok-4.5".to_string(), Dialect::Responses))
        );
    }

    /// The recorded 44-row table is pinned by content: the sorted
    /// `(id, api)` pairs hash to one digest, so a renamed row, a moved
    /// `api` column or a silently swapped id reds even when the count
    /// still reads 44.
    #[test]
    fn copilot_route_table_is_pinned_by_content() {
        use sha2::{Digest, Sha256};

        let mut rows: Vec<String> = COPILOT_MODELS
            .iter()
            .map(|(id, api)| format!("{id}\t{api}"))
            .collect();
        rows.sort();
        assert_eq!(COPILOT_MODELS.len(), 44);
        assert_eq!(
            crate::model::hex(&Sha256::digest(rows.join("\n").as_bytes())),
            "6975cd5bde657fa75e3d8b860848be2e7cb46d261fa9c790ee24ae37a72e227b"
        );
    }

    fn request_error() -> Result<reqwest::Error, Box<dyn Error>> {
        let client = reqwest::blocking::Client::builder().no_proxy().build()?;
        match client
            .get("ftp://fixture-user:fixture-secret@127.0.0.1/private-path?token=fixture-query#fixture-fragment")
            .send()
        {
            Err(error) => Ok(error),
            Ok(_) => Err(std::io::Error::other("unsupported scheme unexpectedly succeeded").into()),
        }
    }

    #[test]
    fn transport_source_clone_preserves_concrete_leaf() -> Result<(), Box<dyn Error>> {
        let original = transport("local", request_error()?);
        let cloned = original.clone();
        drop(original);
        let cause = cloned
            .source()
            .and_then(|source| source.downcast_ref::<TransportCause>())
            .ok_or_else(|| std::io::Error::other("transport cause missing"))?;
        assert_eq!(cause.class(), TransportClass::RequestFailure);
        let leaf = cause
            .source()
            .and_then(|source| source.downcast_ref::<reqwest::Error>())
            .ok_or_else(|| std::io::Error::other("concrete request source missing"))?;
        assert!(!leaf.is_timeout());
        assert!(leaf.url().is_none());

        let directory = tempfile::tempdir()?;
        let Err(error) = std::fs::File::open(directory.path().join("absent")) else {
            return Err(std::io::Error::other("missing file unexpectedly opened").into());
        };
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
        assert!(error.raw_os_error().is_some());
        let os_code = error.raw_os_error();
        let original = transport_io("local", error);
        let cloned = original.clone();
        drop(original);
        let cause = cloned
            .source()
            .and_then(|source| source.downcast_ref::<TransportCause>())
            .ok_or_else(|| std::io::Error::other("read cause missing"))?;
        assert_eq!(cause.class(), TransportClass::ReadFailure);
        let leaf = cause
            .source()
            .and_then(|source| source.downcast_ref::<std::io::Error>())
            .ok_or_else(|| std::io::Error::other("concrete read source missing"))?;
        assert_eq!(leaf.kind(), std::io::ErrorKind::NotFound);
        assert_eq!(leaf.raw_os_error(), os_code);
        assert!(leaf.get_ref().is_none());

        let original = transport_io("local", std::io::Error::other(request_error()?));
        let cloned = original.clone();
        drop(original);
        let cause = cloned
            .source()
            .ok_or_else(|| std::io::Error::other("cause missing"))?;
        let leaf = cause
            .source()
            .and_then(|source| source.downcast_ref::<std::io::Error>())
            .ok_or_else(|| std::io::Error::other("wrapped read source missing"))?;
        assert_eq!(leaf.kind(), std::io::ErrorKind::Other);
        assert!(leaf.raw_os_error().is_none());
        assert!(
            leaf.get_ref()
                .is_some_and(|inner| inner.is::<reqwest::Error>())
        );

        let timeout = TransportCause::Read {
            source: Arc::new(std::io::Error::from(std::io::ErrorKind::TimedOut)),
        };
        assert_eq!(timeout.class(), TransportClass::Timeout);
        let budget = Duration::from_millis(500);
        let deadline = check_deadline("local", budget, Instant::now() - budget);
        assert!(matches!(deadline, Err(ProviderError::Transport {
            cause: TransportCause::Deadline { budget: observed }, ..
        }) if observed == budget));
        let deadline = TransportCause::Deadline { budget };
        assert_eq!(deadline.class(), TransportClass::DeadlineExpired);
        assert!(deadline.source().is_none());
        for status in [401, 429, 503] {
            let error = transport_status("local", reqwest::StatusCode::from_u16(status)?);
            let cause = error
                .source()
                .and_then(|source| source.downcast_ref::<TransportCause>())
                .ok_or_else(|| std::io::Error::other("status cause missing"))?;
            assert_eq!(cause.class(), TransportClass::HttpStatus { code: status });
            assert!(cause.source().is_none());
        }
        Ok(())
    }

    #[test]
    fn transport_diagnostics_are_safe() -> Result<(), Box<dyn Error>> {
        let request = request_error()?;
        assert!(
            request
                .url()
                .is_some_and(|url| url.query() == Some("token=fixture-query"))
        );
        let read = std::io::Error::other(request_error()?);
        let nested = read
            .get_ref()
            .and_then(|source| source.downcast_ref::<reqwest::Error>())
            .ok_or_else(|| std::io::Error::other("nested request source missing"))?;
        assert!(
            nested
                .url()
                .is_some_and(|url| url.query() == Some("token=fixture-query"))
        );
        let sentinels = [
            "fixture-user",
            "fixture-secret",
            "private-path",
            "fixture-query",
            "fixture-fragment",
            "hostile-peer-body",
        ];
        let causes: [(TransportCause, &[&str]); 7] = [
            (
                TransportCause::Request {
                    source: Arc::new(request),
                },
                &["builder"],
            ),
            (
                TransportCause::Read {
                    source: Arc::new(std::io::Error::other(sentinels.join(" "))),
                },
                &["read"],
            ),
            (
                TransportCause::Read {
                    source: Arc::new(read),
                },
                &["builder"],
            ),
            (
                TransportCause::Deadline {
                    budget: Duration::from_millis(500),
                },
                &["deadline", "500ms"],
            ),
            (
                TransportCause::Status {
                    status: reqwest::StatusCode::UNAUTHORIZED,
                },
                &["status", "401"],
            ),
            (
                TransportCause::Status {
                    status: reqwest::StatusCode::TOO_MANY_REQUESTS,
                },
                &["status", "429"],
            ),
            (
                TransportCause::Status {
                    status: reqwest::StatusCode::SERVICE_UNAVAILABLE,
                },
                &["status", "503"],
            ),
        ];
        for (cause, context) in causes {
            let diagnostics = [format!("{cause}"), format!("{cause:?}")];
            let owner = ProviderError::Transport {
                connection: "local".to_string(),
                cause,
            };
            let owner_diagnostics = [format!("{owner}"), format!("{owner:?}")];
            let model = crate::model::ModelError::Provider(owner);
            let model_diagnostics = [format!("{model}"), format!("{model:?}")];
            let controller = crate::controller::ControllerError::Model(model);
            for diagnostic in diagnostics
                .into_iter()
                .chain(owner_diagnostics)
                .chain(model_diagnostics)
                .chain([format!("{controller}"), format!("{controller:?}")])
            {
                assert!(
                    !diagnostic.is_empty(),
                    "transport diagnostics must retain safe context"
                );
                for required in context {
                    assert!(
                        diagnostic.contains(required),
                        "transport diagnostics lost typed context"
                    );
                }
                for sentinel in sentinels {
                    assert!(
                        !diagnostic.contains(sentinel),
                        "transport diagnostics exposed source material"
                    );
                }
            }
        }
        Ok(())
    }

    /// The `zenmux` base pair is the recorded transform itself: the
    /// configured Chat Completions root, a folded Messages root, and the
    /// derived mirror — asserted directly so neither half can be removed
    /// behind the adapter's `Debug` surface.
    #[test]
    fn zenmux_bases_resolve_as_the_recorded_pair() {
        assert_eq!(zenmux_openai_base(""), "https://zenmux.ai/api/v1");
        assert_eq!(
            zenmux_openai_base("https://zenmux.ai/api/anthropic/"),
            "https://zenmux.ai/api/v1"
        );
        assert_eq!(
            zenmux_openai_base("https://gateway.example.test/zenmux/api/v1/"),
            "https://gateway.example.test/zenmux/api/v1"
        );
        assert_eq!(zenmux_anthropic_base(""), "https://zenmux.ai/api/anthropic");
        assert_eq!(
            zenmux_anthropic_base("https://zenmux.ai/api/v1"),
            "https://zenmux.ai/api/anthropic"
        );
        assert_eq!(
            zenmux_anthropic_base("https://zenmux.ai/api/anthropic"),
            "https://zenmux.ai/api/anthropic"
        );
        assert_eq!(
            zenmux_anthropic_base("https://gateway.example.test/zenmux/api/v1"),
            "https://gateway.example.test/zenmux/api/anthropic"
        );
    }

    /// The routing class is the id's owner prefix, case-insensitive: the
    /// listing's `owned_by`/metadata is catalogue authority, and the id
    /// slug is the same owner identity on the wire. A bare family name or
    /// an id whose slug names no owner rides the Chat Completions default.
    #[test]
    fn zenmux_class_is_the_owner_prefix_not_the_family_name() {
        assert!(zenmux_is_anthropic("anthropic/claude-opus-4.8"));
        assert!(zenmux_is_anthropic("Anthropic/claude-opus-4.8"));
        assert!(!zenmux_is_anthropic("claude-opus-4.8"));
        assert!(!zenmux_is_anthropic("google/gemini-3-pro-preview"));
        assert!(!zenmux_is_anthropic("fixture/unknown-model"));
        assert!(!zenmux_is_anthropic("anthropic"));
    }

    /// Peer text reaches a diagnostic only with every control character
    /// escaped: an ANSI sequence renders as visible text, never bytes a
    /// terminal would execute.
    #[test]
    fn peer_reasons_escape_control_characters() {
        let escaped = bounded_reason("failure \u{1b}[31mred\u{7f}\u{9b}");
        assert_eq!(escaped, "failure \\u{1b}[31mred\\u{7f}\\u{9b}");
        assert!(!escaped.chars().any(char::is_control));

        let payload = serde_json::json!({"message": "\u{1b}[2Jpayload"});
        assert_eq!(payload_reason(&payload), "\\u{1b}[2Jpayload");
        let scalar = serde_json::json!({"code": 7});
        assert_eq!(payload_reason(&scalar), "7");
        assert_eq!(payload_reason(&serde_json::json!({})), "unclassified");
    }

    #[test]
    fn one_encoder_serves_the_login_forms_and_the_model_path() {
        assert_eq!(percent_encode_component("a:b/c d~"), "a%3Ab%2Fc%20d~");
        assert_eq!(percent_encode_component("v1:0"), "v1%3A0");
        assert_eq!(percent_encode_component("unreserved-._~"), "unreserved-._~");
    }
}
