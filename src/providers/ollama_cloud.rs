//! The native Ollama Cloud dialect adapter (DEC-001/DEC-018) — the
//! literal `ollama-cloud` connection records this dialect and no
//! sibling: `POST {base}/api/chat` streams newline-delimited JSON,
//! never SSE, and the catalogue is the key-gated `GET {base}/api/tags`
//! listing enriched by a bounded `POST {base}/api/show` overlay
//! (DEC-012/DEC-013). The adapter reuses the transport, deadline,
//! credential and accounting seams of the shared owners; it authors no
//! second SSE codec and holds its own scoped [`SecretRef`] — the
//! credential is required, so no keyless path exists (PROH-010). The
//! request carries one system turn and one user turn, no history, and
//! declared tools ride `tool_choice: "auto"` (DEC-015); secret material
//! crosses only from the [`CredentialStore`] into the `Authorization`
//! header and never enters diagnostics (INV-001).

use crate::config::{
    Config, ConnKind, Connection, EffortAssign, EffortLevel, FixedModel, ModelAssign,
};
use crate::model::RequestManifest;
use crate::providers::{
    CatalogModel, CredentialStore, Dialect, Provider, ProviderError, ProviderReply,
    STREAM_CHUNK_BYTES, SecretRef, ToolCall, TransportCause, bounded_reason, check_deadline,
    dialect_for, payload_reason, read_catalog_body, read_chunk, resolve_credential_in, transport,
    transport_status, violation, wire_body,
};
use crate::resources::UsageDelta;
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The whole-request deadline one physical send may take: the budget
/// covers credential resolution, the auto-pool catalogue leg, connect,
/// the post, every JSONL read and finalization — checked before each
/// blocking call so no leg runs unbounded while the caller believes
/// the adapter answered promptly. The check bounds the work between
/// calls; a call already in flight answers to the client's per-call
/// backstop instead.
const REQUEST_DEADLINE: Duration = Duration::from_secs(120);

/// The recorded cloud base (DEC-011): an empty configured endpoint
/// resolves here, and the configured value otherwise wins after this
/// adapter's trim — surrounding whitespace, every trailing slash and
/// one trailing `/api` stripped.
const OLLAMA_CLOUD_DEFAULT_ENDPOINT: &str = "https://ollama.com";

/// The recorded `/api/tags` retry ladder (DEC-013): a retryable
/// status waits one rung and asks again; the ladder is listing-only —
/// no send is ever retried.
const TAGS_RETRY_LADDER: [Duration; 3] = [
    Duration::from_secs(2),
    Duration::from_secs(5),
    Duration::from_secs(10),
];

/// The most listed ids one advisory `/api/show` phase probes (DEC-012).
const DISCOVERY_MAX_IDS: usize = 32;

/// The one advisory budget the `/api/show` overlay shares (DEC-012):
/// an expired phase leaves the remaining listing-only entries rather
/// than extending the catalogue leg.
const DISCOVERY_PHASE_BUDGET: Duration = Duration::from_millis(250);

/// The per-entry context default when the metadata carries no positive
/// context key (DEC-012).
const DEFAULT_CONTEXT_WINDOW: u64 = 128_000;

/// The per-entry max-output default: `min(context, 8192)` (DEC-012).
const DEFAULT_MAX_OUTPUT_TOKENS: u64 = 8_192;

/// The recorded 65536 max-output cap the `deepseek-v4-flash` and
/// `deepseek-v4-pro` entries carry (AC-040e).
const DEEPSEEK_MAX_OUTPUT_TOKENS: u64 = 65_536;

/// The bound on one JSONL frame — a frame never needs more, and an
/// unterminated or dribbling line is denied under the same budget as
/// the stream itself.
const MAX_FRAME_BYTES: usize = 1024 * 1024;

/// The bound on the tool calls one stream may carry — the shared
/// codec's bound, so a hostile peer cannot grow the reply unbounded.
const MAX_TOOL_CALLS: usize = 32;

/// The connection's API base (DEC-011): the configured endpoint is
/// trimmed of surrounding whitespace and of every trailing slash, then
/// one trailing `/api` is stripped — the recorded native base the
/// resource paths hang off. The empty result resolves the recorded
/// cloud default; no other suffix is ever inferred.
fn endpoint_for(configured: &str) -> String {
    let trimmed = configured.trim().trim_end_matches('/');
    let base = trimmed
        .strip_suffix("/api")
        .unwrap_or(trimmed)
        .trim_end_matches('/');
    if base.is_empty() {
        OLLAMA_CLOUD_DEFAULT_ENDPOINT.to_string()
    } else {
        base.to_string()
    }
}

/// The terminal classification one completed stream reduces to: the
/// recorded `done` verdict, the peer's own failure, or a reason the
/// dialect cannot classify.
enum Terminal {
    Completed,
    Failed { reason: String },
    Unclassifiable,
}

/// Per-stream accounting: the visible answer text, the tool calls the
/// frames carried, the `done` chunk's physical usage report and the
/// terminal the stream declared. The terminal is the single source of
/// truth: the reader stops at the first one, so no frame is processed
/// after it.
struct StreamState {
    text: String,
    tool_calls: Vec<ToolCall>,
    usage: UsageDelta,
    terminal: Option<Terminal>,
}

impl Default for StreamState {
    fn default() -> Self {
        Self {
            text: String::new(),
            tool_calls: Vec::new(),
            usage: UsageDelta::Unknown,
            terminal: None,
        }
    }
}

/// The native Ollama Cloud adapter. Constructed per connection from the
/// validated config; the broker owns the handle — workers never hold
/// one.
pub struct OllamaCloudProvider {
    /// The literal connection id this adapter serves — the dialect
    /// key, not a label.
    connection: String,
    /// The configured endpoint base under DEC-011 — trimmed, one
    /// trailing `/api` stripped, and the recorded cloud default when
    /// that leaves nothing.
    endpoint: String,
    /// The scoped credential binding: required, so every wire leg
    /// bears the bearer. Material is read from the store per send so a
    /// rotation is honoured without rebuilding the adapter.
    credential: SecretRef,
    store: Arc<dyn CredentialStore>,
    client: reqwest::blocking::Client,
    /// The one budget the whole send — credential resolution, the
    /// auto-pool catalogue leg, connect, the post, every stream read
    /// and finalization — shares. The reqwest client's per-call timeout
    /// sits at twice it, the backstop bounding a blocking call the
    /// clock cannot interrupt.
    deadline: Duration,
}

/// What the advisory phase has left (DEC-012): `None` once the budget
/// is spent, so every native request is clipped to the phase's total
/// clock instead of opening a fresh one per request.
fn phase_remaining(budget: Duration, phase: Instant) -> Option<Duration> {
    budget
        .checked_sub(phase.elapsed())
        .filter(|left| !left.is_zero())
}

/// The first positive context key the recorded class maps, in its
/// stated order: a `model_info.*.context_length` member (sorted for
/// determinism), then `num_ctx`, then `context_window`.
fn native_context_window(payload: &Value) -> Option<u64> {
    if let Some(info) = payload.get("model_info").and_then(Value::as_object) {
        let mut keys: Vec<&String> = info
            .keys()
            .filter(|key| key.ends_with(".context_length"))
            .collect();
        keys.sort();
        for key in keys {
            if let Some(tokens) = info.get(key).and_then(positive_tokens) {
                return Some(tokens);
            }
        }
    }
    ["num_ctx", "context_window"]
        .iter()
        .find_map(|key| payload.get(*key).and_then(positive_tokens))
}

fn positive_tokens(value: &Value) -> Option<u64> {
    value.as_u64().filter(|tokens| *tokens > 0)
}

/// The max-output figure one enriched entry carries (AC-040e): the two
/// recorded DeepSeek ids keep their 65536 cap, every other id takes
/// `min(context, 8192)`.
fn max_output_tokens(id: &str, context_window: u64) -> u64 {
    if matches!(id, "deepseek-v4-flash" | "deepseek-v4-pro") {
        DEEPSEEK_MAX_OUTPUT_TOKENS
    } else {
        context_window.min(DEFAULT_MAX_OUTPUT_TOKENS)
    }
}

/// Whether a thinking model records the GLM ≥5.2 single-high ladder
/// (AC-040e): the `glm-` version, wherever the namespace prefix sits,
/// reads 5.2 or later.
fn is_glm_at_least_5_2(id: &str) -> bool {
    let lowered = id.to_ascii_lowercase();
    let Some(at) = lowered.find("glm-") else {
        return false;
    };
    let version: String = lowered[at + "glm-".len()..]
        .chars()
        .take_while(|ch| ch.is_ascii_digit() || *ch == '.')
        .collect();
    let mut parts = version.split('.').filter(|part| !part.is_empty());
    let Some(major) = parts.next().and_then(|part| part.parse::<u64>().ok()) else {
        return false;
    };
    let minor = parts
        .next()
        .and_then(|part| part.parse::<u64>().ok())
        .unwrap_or(0);
    (major, minor) >= (5, 2)
}

/// The reasoning-effort ladder one enriched entry carries (AC-040e):
/// a non-thinking model records none, a GLM ≥5.2 thinking model
/// records the single `high` level, and every other thinking model
/// records `minimal…high`. The recorded `max`/`none` values have no
/// landing level and are never coerced onto a lower one (D10).
fn effort_ladder(id: &str, reasoning: bool) -> Vec<EffortLevel> {
    if !reasoning {
        return Vec::new();
    }
    if is_glm_at_least_5_2(id) {
        vec![EffortLevel::High]
    } else {
        vec![
            EffortLevel::Minimal,
            EffortLevel::Low,
            EffortLevel::Medium,
            EffortLevel::High,
        ]
    }
}

/// Folds one successful `/api/show` answer into a listing entry: the
/// `capabilities` marks, the first positive context key with the
/// recorded default, the per-id max-output figure and the reasoning
/// ladder. A listing-only entry never reaches this fold, so its
/// metadata stays unstated rather than defaulted.
fn apply_metadata(model: &mut CatalogModel, payload: &Value) {
    let capabilities = payload.get("capabilities").and_then(Value::as_array);
    let declares = |name: &str| {
        capabilities.is_some_and(|values| values.iter().any(|value| value.as_str() == Some(name)))
    };
    let reasoning = declares("thinking");
    let context_window = native_context_window(payload).unwrap_or(DEFAULT_CONTEXT_WINDOW);
    model.reasoning = reasoning;
    model.vision = declares("vision");
    model.context_window = Some(context_window);
    model.max_output_tokens = Some(max_output_tokens(&model.id, context_window));
    model.efforts = effort_ladder(&model.id, reasoning);
}

/// The listed entries one native discovery phase probes (DEC-012): the
/// leading [`DISCOVERY_MAX_IDS`] offers, never the whole listing.
fn probe_targets(models: &mut [CatalogModel]) -> &mut [CatalogModel] {
    let probed = models.len().min(DISCOVERY_MAX_IDS);
    &mut models[..probed]
}

/// The listing ids one `/api/tags` answer offers: the recorded
/// `models[].name` (the entry's `model` member as its documented
/// alias), non-empty after trimming, in deterministic sorted order and
/// deduplicated. No chat-capability filter runs — the listing is the
/// offer set.
fn tags_ids(connection: &str, body: &[u8]) -> Result<Vec<String>, ProviderError> {
    let payload: Value = serde_json::from_slice(body)
        .map_err(|_parse| violation(connection, "tags payload is not json"))?;
    let Some(models) = payload.get("models").and_then(Value::as_array) else {
        return Err(violation(
            connection,
            "tags payload carries no models array",
        ));
    };
    let mut ids: Vec<String> = models
        .iter()
        .filter_map(|entry| {
            entry
                .get("name")
                .and_then(Value::as_str)
                .or_else(|| entry.get("model").and_then(Value::as_str))
                .map(str::trim)
                .filter(|id| !id.is_empty())
                .map(str::to_string)
        })
        .collect();
    ids.sort();
    ids.dedup();
    Ok(ids)
}

/// Whether a status is the recorded retryable class (DEC-013).
fn retryable_status(status: reqwest::StatusCode) -> bool {
    matches!(
        status,
        reqwest::StatusCode::SERVICE_UNAVAILABLE | reqwest::StatusCode::TOO_MANY_REQUESTS
    )
}

/// One recorded ladder rung: parks until the whole interval elapsed, so
/// a spurious wake or a stray token never shortens the retry — and no
/// poll loop or spawned timer runs.
fn wait_rung(rung: Duration) {
    let started = Instant::now();
    while let Some(left) = rung
        .checked_sub(started.elapsed())
        .filter(|left| !left.is_zero())
    {
        std::thread::park_timeout(left);
    }
}

/// The physical usage one `done` chunk reported: both counters present
/// charge the sum as the total, while a frame withholding either half
/// stays [`UsageDelta::Unknown`] — never an estimate.
fn frame_usage(connection: &str, frame: &Value) -> Result<UsageDelta, ProviderError> {
    let prompt = frame.get("prompt_eval_count").and_then(Value::as_u64);
    let completion = frame.get("eval_count").and_then(Value::as_u64);
    match (prompt, completion) {
        (Some(prompt_tokens), Some(completion_tokens)) => {
            let total_tokens = prompt_tokens
                .checked_add(completion_tokens)
                .ok_or_else(|| violation(connection, "done counters overflow"))?;
            Ok(UsageDelta::Exact {
                prompt_tokens,
                completion_tokens,
                total_tokens,
            })
        }
        _ => Ok(UsageDelta::Unknown),
    }
}

/// JavaScript-truthiness for the recorded `if (frame.error)` guard:
/// `null`, `false`, `0` and `""` carry no verdict.
fn carries_no_verdict(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Bool(flag) => !flag,
        Value::Number(number) => number.as_f64() == Some(0.0),
        Value::String(text) => text.is_empty(),
        Value::Array(_) | Value::Object(_) => false,
    }
}

impl OllamaCloudProvider {
    /// Builds the adapter for one connection id: the id must record
    /// the native `ollama-chat` dialect (DEC-001), the connection must
    /// be declared, carry no configured region the dialect's endpoint
    /// contract cannot honour, and resolve a scoped credential — the
    /// class has no keyless path (PROH-010).
    ///
    /// # Errors
    /// [`ProviderError::DialectMismatch`] for a connection id without
    /// the native dialect; [`ProviderError::UnknownConnection`] for an
    /// undeclared id; [`ProviderError::RegionMismatch`] for a
    /// configured region; [`ProviderError::LocalProfileDeclared`] for a
    /// `local` declaration that binds a `profile`;
    /// [`ProviderError::CredentialUnresolved`] for a `local`
    /// declaration — the class requires its binding, so the kind is
    /// denied before any credential resolves —
    /// `resolve_credential_in`'s typed denials for
    /// a missing, malformed or mismatched binding;
    /// [`ProviderError::Transport`] when the HTTP client cannot be
    /// built.
    pub fn new(
        config: &Config,
        connection: &str,
        store: Arc<dyn CredentialStore>,
    ) -> Result<Self, ProviderError> {
        Self::build(config, connection, store, REQUEST_DEADLINE)
    }

    /// The same adapter under an explicit whole-request deadline — the
    /// bound is adapter policy; proof legs pin a short one so the
    /// budget is exercised deterministically.
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
        if dialect_for(connection) != Some(Dialect::OllamaChat) {
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
        // The class requires its binding: an unbound declaration and a
        // `local` declaration that names a locally served endpoint are
        // both the typed unresolved denial at build, before any wire
        // leg exists — the profile member must not turn the row into a
        // credentialled sender (DEC-009/DEC-010). A `local` row that
        // binds a `profile` is the contradictory half and is named as
        // such first (DEC-023).
        if conn.kind == ConnKind::Local && conn.profile.is_some() {
            return Err(ProviderError::LocalProfileDeclared {
                connection: connection.to_string(),
            });
        }
        if conn.kind == ConnKind::Local {
            return Err(ProviderError::CredentialUnresolved {
                connection: connection.to_string(),
                scope: format!("connections.{connection}.kind"),
                cause: None,
            });
        }
        let credential = resolve_credential_in(&config.connections, &config.profiles, connection)?;
        // The transport backstop sits strictly above the adapter's own
        // deadline: an expiry races out through `check_deadline` and
        // names itself the send's deadline, while reqwest's timer only
        // fires on a stall the budget check cannot reach.
        let client = reqwest::blocking::Client::builder()
            .timeout(deadline.saturating_mul(2))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|err| transport(connection, err))?;
        Ok(Self {
            connection: connection.to_string(),
            endpoint: endpoint_for(&conn.endpoint),
            credential,
            store,
            client,
            deadline,
        })
    }

    /// The rich catalogue: the key-gated `/api/tags` listing is the
    /// offer set, enriched by the bounded `/api/show` overlay — each id
    /// carrying the shared [`CatalogModel`], returned in deterministic
    /// sorted order.
    ///
    /// # Errors
    /// The credential seam's typed denials, [`ProviderError::Transport`]
    /// on a failed call, a non-success status after the retry ladder or
    /// an expired whole-call budget, and
    /// [`ProviderError::StreamViolation`] when a payload does not carry
    /// the shape the contract requires.
    pub fn catalog(&self) -> Result<Vec<CatalogModel>, ProviderError> {
        // A standalone lookup opens its own whole-call budget — the
        // credential resolution, the listing ladder and the overlay
        // share it, the same bound a send's catalogue leg rides.
        let started = Instant::now();
        check_deadline(&self.connection, self.deadline, started)?;
        let token = self.secret()?;
        let mut models: Vec<CatalogModel> = self
            .listing_within(&token, started)?
            .into_iter()
            .map(|id| CatalogModel {
                id,
                ..CatalogModel::default()
            })
            .collect();
        // The overlay is advisory: it enriches the listing's own offers
        // and never extends or replaces them (DEC-012) — and it spends
        // the caller's clock like every other leg, so a peer answering
        // past the whole-call budget is the typed deadline, never a
        // late catalogue.
        self.enrich(&mut models, &token, started);
        check_deadline(&self.connection, self.deadline, started)?;
        Ok(models)
    }

    /// The `/api/tags` listing leg under the caller's clock and
    /// credential — a send passes its own `started` so the lookup
    /// spends the same whole-request budget instead of opening a
    /// second, unaccounted one. The recorded ladder retries a
    /// retryable status (DEC-013); a rung that cannot finish inside
    /// the caller's budget is the typed deadline denial, never a late
    /// retry, and an exhausted ladder denies with the peer's own code.
    fn listing_within(&self, token: &str, started: Instant) -> Result<Vec<String>, ProviderError> {
        let mut ladder = TAGS_RETRY_LADDER.iter();
        loop {
            check_deadline(&self.connection, self.deadline, started)?;
            let mut response = self
                .client
                .get(format!("{}/api/tags", self.endpoint))
                .bearer_auth(token)
                .send()
                .map_err(|err| transport(&self.connection, err))?;
            if response.status().is_success() {
                let body =
                    read_catalog_body(&self.connection, self.deadline, &mut response, started)?;
                return tags_ids(&self.connection, &body);
            }
            let status = response.status();
            if !retryable_status(status) {
                return Err(transport_status(&self.connection, status));
            }
            let Some(rung) = ladder.next().copied() else {
                return Err(transport_status(&self.connection, status));
            };
            if started.elapsed() + rung >= self.deadline {
                return Err(ProviderError::Transport {
                    connection: self.connection.clone(),
                    cause: TransportCause::Deadline {
                        budget: self.deadline,
                    },
                });
            }
            wait_rung(rung);
        }
    }

    /// Reads the credential material for this call — the only place
    /// secret bytes cross the store boundary. A non-UTF-8 secret cannot
    /// be a bearer token: typed denial, never a mangled header.
    fn secret(&self) -> Result<String, ProviderError> {
        let material = self.store.resolve(&self.credential)?;
        String::from_utf8(material).map_err(|_utf8| ProviderError::CredentialMalformed {
            connection: self.connection.clone(),
        })
    }

    /// The bounded `/api/show` overlay (DEC-012): the listing's leading
    /// ids under one advisory phase — at most [`DISCOVERY_MAX_IDS`] and
    /// the smaller of the recorded 250 ms and the whole call's
    /// remainder. Each request is clipped to what the phase has left,
    /// so the phase is a total bound rather than a per-request one.
    /// Every failure is non-fatal — the entry keeps its listing-only
    /// surface — while the phase's own spend stays inside the caller's
    /// clock, so a peer answering past it is the typed deadline rather
    /// than a late catalogue.
    fn enrich(&self, models: &mut [CatalogModel], token: &str, started: Instant) {
        let Some(budget) = self
            .deadline
            .checked_sub(started.elapsed())
            .map(|left| left.min(DISCOVERY_PHASE_BUDGET))
            .filter(|left| !left.is_zero())
        else {
            return;
        };
        let phase = Instant::now();
        for model in probe_targets(models) {
            if phase_remaining(budget, phase).is_none() {
                break;
            }
            if let Some(payload) = self.show(token, &model.id, budget, phase) {
                apply_metadata(model, &payload);
            }
        }
    }

    /// One `/api/show` probe for a listed id, bounded by the advisory
    /// phase. Any failure leaves the id listing-only.
    fn show(&self, token: &str, id: &str, budget: Duration, phase: Instant) -> Option<Value> {
        let remaining = phase_remaining(budget, phase)?;
        let started = Instant::now();
        let body = match serde_json::to_vec(&json!({ "model": id })) {
            Ok(body) => body,
            Err(_err) => return None,
        };
        let mut response = match self
            .client
            .post(format!("{}/api/show", self.endpoint))
            .timeout(remaining)
            .bearer_auth(token)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
        {
            Ok(response) => response,
            Err(_err) => return None,
        };
        if !response.status().is_success() {
            return None;
        }
        let body = match read_catalog_body(&self.connection, remaining, &mut response, started) {
            Ok(body) => body,
            Err(_err) => return None,
        };
        let payload: Value = match serde_json::from_slice(&body) {
            Ok(payload) => payload,
            Err(_err) => return None,
        };
        if payload.is_object() {
            Some(payload)
        } else {
            None
        }
    }

    /// The frozen manifest as the native chat request (DEC-015): the
    /// model pin, one `system` turn when the instructions carry text,
    /// one `user` turn, `stream: true`, and the declared tool surface
    /// with `tool_choice: "auto"` when tools are pinned. A pinned
    /// effort rides the recorded native `think` member under the pinned
    /// level's own name — `minimal`/`xhigh` included, never coerced onto
    /// a lower level, so a peer that rejects the level is a typed
    /// denial; an auto or inherited assignment omits the member. The
    /// manifest carries no history and no request-side max-token field,
    /// so neither is ever invented.
    fn request_body(&self, manifest: &RequestManifest, model_id: &str) -> Value {
        let mut messages = Vec::with_capacity(2);
        if !manifest.instructions.is_empty() {
            messages.push(json!({ "role": "system", "content": manifest.instructions }));
        }
        messages.push(json!({ "role": "user", "content": manifest.inputs }));
        let mut body = json!({
            "model": model_id,
            "messages": messages,
            "stream": true,
        });
        if let EffortAssign::Fixed { value } = &manifest.effort {
            body["think"] = json!(value.name());
        }
        if !manifest.tools.is_empty() {
            body["tools"] = Value::Array(
                manifest
                    .tools
                    .iter()
                    .map(|name| json!({ "type": "function", "function": { "name": name } }))
                    .collect(),
            );
            body["tool_choice"] = json!("auto");
        }
        body
    }

    /// Reads the JSONL body and reduces it to the one terminal the
    /// dialect can classify. Each frame is one newline-terminated JSON
    /// object; the first terminal frame closes the stream — a `done`
    /// verdict or the peer's own error — and a stream that ends mid
    /// frame is a wire violation while a clean end before the terminal
    /// is the unknown terminal; neither is ever success.
    fn read_stream(
        &self,
        manifest: &RequestManifest,
        mut response: reqwest::blocking::Response,
        started: Instant,
    ) -> Result<ProviderReply, ProviderError> {
        let mut state = StreamState::default();
        let mut pending: Vec<u8> = Vec::new();
        let mut chunk = vec![0u8; STREAM_CHUNK_BYTES];
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
            pending.extend_from_slice(&chunk[..read]);
            let mut consumed = 0;
            let mut closed = false;
            while let Some(offset) = pending[consumed..].iter().position(|byte| *byte == b'\n') {
                let end = consumed + offset;
                self.on_frame(&mut state, &pending[consumed..end])?;
                consumed = end + 1;
                if state.terminal.is_some() {
                    closed = true;
                    break;
                }
            }
            pending.drain(..consumed);
            if closed {
                break;
            }
            if pending.len() > MAX_FRAME_BYTES {
                return Err(violation(
                    &self.connection,
                    "jsonl frame exceeds the byte bound",
                ));
            }
        }
        // Finalization shares the budget — the stream's total cost is
        // bounded even when its last byte lands just inside it.
        check_deadline(&self.connection, self.deadline, started)?;
        if state.terminal.is_none() {
            if !pending.is_empty() {
                return Err(violation(&self.connection, "stream ended mid jsonl frame"));
            }
            return Err(ProviderError::UnknownTerminal {
                connection: self.connection.clone(),
            });
        }
        match state.terminal {
            Some(Terminal::Completed) => self.complete(manifest, state),
            Some(Terminal::Failed { reason }) => Err(ProviderError::ProviderFailed {
                connection: self.connection.clone(),
                reason: bounded_reason(reason),
            }),
            Some(Terminal::Unclassifiable) | None => Err(ProviderError::UnknownTerminal {
                connection: self.connection.clone(),
            }),
        }
    }

    /// Classifies one JSONL frame. A blank line is framing, not a
    /// verdict; an `error` member is the peer's own failure; a `done`
    /// frame maps its recorded `done_reason` — `length`, `tool_calls`
    /// and the absent reason complete, `load` is a provider failure,
    /// and any other reason is unclassifiable. A malformed frame or a
    /// non-string `done_reason` is a wire violation.
    fn on_frame(&self, state: &mut StreamState, frame: &[u8]) -> Result<(), ProviderError> {
        if frame.len() > MAX_FRAME_BYTES {
            return Err(violation(
                &self.connection,
                "jsonl frame exceeds the byte bound",
            ));
        }
        let frame = std::str::from_utf8(frame)
            .map_err(|_utf8| violation(&self.connection, "jsonl frame is not utf-8"))?;
        let frame = frame.trim();
        if frame.is_empty() {
            return Ok(());
        }
        let frame: Value = serde_json::from_str(frame)
            .map_err(|_parse| violation(&self.connection, "jsonl frame is not json"))?;
        if !frame.is_object() {
            return Err(violation(&self.connection, "jsonl frame is not an object"));
        }
        if let Some(error) = frame
            .get("error")
            .filter(|error| !carries_no_verdict(error))
        {
            let reason = match error {
                Value::String(reason) => reason.clone(),
                Value::Object(_) => payload_reason(error),
                _ => {
                    return Err(violation(
                        &self.connection,
                        "frame error is not an object or string",
                    ));
                }
            };
            state.terminal = Some(Terminal::Failed { reason });
            return Ok(());
        }
        if let Some(message) = frame.get("message").filter(|message| !message.is_null()) {
            self.on_message(state, message)?;
        }
        let done = match frame.get("done") {
            None => false,
            Some(Value::Bool(done)) => *done,
            Some(_) => return Err(violation(&self.connection, "frame done is not a boolean")),
        };
        if !done {
            return Ok(());
        }
        let terminal = match frame.get("done_reason") {
            None | Some(Value::Null) => Terminal::Completed,
            Some(Value::String(reason)) => match reason.as_str() {
                "stop" | "length" | "tool_calls" => Terminal::Completed,
                "load" => Terminal::Failed {
                    reason: format!("generation failed with done reason {reason}"),
                },
                _ => Terminal::Unclassifiable,
            },
            Some(_) => {
                return Err(violation(&self.connection, "done_reason is not a string"));
            }
        };
        state.usage = frame_usage(&self.connection, &frame)?;
        state.terminal = Some(terminal);
        Ok(())
    }

    /// Folds one frame's `message` into the stream: `content` fragments
    /// join the visible answer, `tool_calls` entries join the typed
    /// calls, and every other progress member — `thinking` included —
    /// is observed, never part of the answer.
    fn on_message(&self, state: &mut StreamState, message: &Value) -> Result<(), ProviderError> {
        let Some(message) = message.as_object() else {
            return Err(violation(&self.connection, "message is not an object"));
        };
        if let Some(content) = message.get("content") {
            match content {
                Value::String(text) => state.text.push_str(text),
                Value::Null => {}
                _ => {
                    return Err(violation(
                        &self.connection,
                        "message content is not a string",
                    ));
                }
            }
        }
        if let Some(calls) = message.get("tool_calls") {
            let Some(calls) = calls.as_array() else {
                return Err(violation(
                    &self.connection,
                    "message tool_calls is not an array",
                ));
            };
            for entry in calls {
                state.tool_calls.push(self.tool_call(entry)?);
                if state.tool_calls.len() > MAX_TOOL_CALLS {
                    return Err(violation(
                        &self.connection,
                        "stream carried more tool calls than the bound",
                    ));
                }
            }
        }
        Ok(())
    }

    /// One native tool call: the `function.name` and the `path` member
    /// of its arguments object. A call without a name or with arguments
    /// outside the recorded object shape is a wire violation.
    fn tool_call(&self, entry: &Value) -> Result<ToolCall, ProviderError> {
        let Some(entry) = entry.as_object() else {
            return Err(violation(&self.connection, "tool call is not an object"));
        };
        let Some(function) = entry.get("function").and_then(Value::as_object) else {
            return Err(violation(
                &self.connection,
                "tool call carries no function object",
            ));
        };
        let Some(name) = function
            .get("name")
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty())
        else {
            return Err(violation(
                &self.connection,
                "tool call carries no function name",
            ));
        };
        let path = match function.get("arguments") {
            None | Some(Value::Null) => None,
            Some(Value::Object(args)) => {
                args.get("path").and_then(Value::as_str).map(str::to_string)
            }
            Some(_) => {
                return Err(violation(
                    &self.connection,
                    "tool call arguments are not an object",
                ));
            }
        };
        Ok(ToolCall {
            tool: name.to_string(),
            path,
        })
    }

    /// Finalizes a completed stream: a tool call the frozen request
    /// never declared is a typed rejection, never executed — and the
    /// `done` chunk's report becomes the physical charge.
    fn complete(
        &self,
        manifest: &RequestManifest,
        state: StreamState,
    ) -> Result<ProviderReply, ProviderError> {
        for call in &state.tool_calls {
            if !manifest.tools.iter().any(|declared| declared == &call.tool) {
                return Err(ProviderError::IncompatibleOutput {
                    connection: self.connection.clone(),
                    reason: bounded_reason(format!(
                        "tool call names undeclared tool {}",
                        call.tool
                    )),
                });
            }
        }
        Ok(ProviderReply {
            text: state.text,
            tool_calls: state.tool_calls,
            usage: state.usage,
        })
    }
}

impl std::fmt::Debug for OllamaCloudProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The scoped ref is the visible token — the store and its
        // material never enter diagnostics (INV-001).
        f.debug_struct("OllamaCloudProvider")
            .field("connection", &self.connection)
            .field("endpoint", &self.endpoint)
            .field("credential", &self.credential)
            .field("deadline", &self.deadline)
            .finish_non_exhaustive()
    }
}

impl Provider for OllamaCloudProvider {
    fn name(&self) -> &'static str {
        "ollama-chat"
    }

    /// The adapter serves only the literal connection id its dialect
    /// was constructed for (DEC-001) — a pin to any other id is a
    /// dialect it does not speak.
    fn serves(&self, connection: &str, _entry: &Connection) -> bool {
        connection == self.connection
    }

    /// Sends the frozen manifest as one physical native chat request.
    ///
    /// # Errors
    /// [`ProviderError::UnpinnedModel`] when the manifest carries no
    /// fixed model id and no single-member auto pool naming this
    /// connection, [`ProviderError::DialectMismatch`] when the pin
    /// names a different connection, the credential seam's typed
    /// denials, [`ProviderError::Transport`],
    /// [`ProviderError::ProviderFailed`],
    /// [`ProviderError::UnknownTerminal`],
    /// [`ProviderError::StreamViolation`] — including a serialized
    /// request body over the wire bound — and
    /// [`ProviderError::IncompatibleOutput`] as the stream legs
    /// document.
    fn send(&mut self, manifest: &RequestManifest) -> Result<ProviderReply, ProviderError> {
        // The whole call spends one budget: credential resolution, the
        // auto-pool catalogue leg and the streamed response all count
        // against the same clock — no leg starts past the deadline the
        // caller was promised; an in-flight credential-store call runs
        // to completion (uninterruptible).
        let started = Instant::now();
        // The credential resolves once per send — the catalogue leg and
        // the post both bear the same material, so a rotation mid-send
        // can never split one request across two secrets.
        check_deadline(&self.connection, self.deadline, started)?;
        let token = self.secret()?;
        // A fixed pin names connection and model verbatim. A
        // single-member auto pool naming this connection is an
        // explicit pick of it — the pick pins the connection, and the
        // listing names the model: the deterministic sorted-first id.
        // Any other assignment is a model this adapter cannot pin.
        let fixed = match &manifest.model {
            ModelAssign::Fixed(fixed) => fixed.clone(),
            ModelAssign::Auto { pool: Some(pool) }
                if pool.len() == 1 && pool[0] == self.connection =>
            {
                let model_id = self
                    .listing_within(&token, started)?
                    .into_iter()
                    .next()
                    .ok_or_else(|| ProviderError::UnpinnedModel {
                        connection: self.connection.clone(),
                    })?;
                FixedModel {
                    connection: self.connection.clone(),
                    model_id,
                }
            }
            _ => {
                return Err(ProviderError::UnpinnedModel {
                    connection: self.connection.clone(),
                });
            }
        };
        if fixed.connection != self.connection {
            return Err(ProviderError::DialectMismatch {
                connection: fixed.connection,
            });
        }
        let body = self.request_body(manifest, &fixed.model_id);
        let body_bytes = wire_body(&self.connection, &body)?;
        // The wire leg is the last budget check: a resolve or catalogue
        // leg that spent the clock fails the send typed here — an
        // expired budget never puts a byte on the wire.
        check_deadline(&self.connection, self.deadline, started)?;
        let request = self
            .client
            .post(format!("{}/api/chat", self.endpoint))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .bearer_auth(&token)
            .body(body_bytes);
        let response = request
            .send()
            .map_err(|err| transport(&self.connection, err))?;
        if !response.status().is_success() {
            return Err(transport_status(&self.connection, response.status()));
        }
        self.read_stream(manifest, response, started)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// DEC-011's base rule: the configured value is trimmed of
    /// surrounding whitespace and trailing slashes, exactly one
    /// trailing `/api` is stripped, and the empty result resolves the
    /// recorded cloud default — no other suffix is inferred.
    #[test]
    fn endpoint_rule_trims_and_strips_one_api_suffix() {
        assert_eq!(endpoint_for("   "), OLLAMA_CLOUD_DEFAULT_ENDPOINT);
        assert_eq!(endpoint_for(""), OLLAMA_CLOUD_DEFAULT_ENDPOINT);
        assert_eq!(endpoint_for(" / "), OLLAMA_CLOUD_DEFAULT_ENDPOINT);
        assert_eq!(
            endpoint_for("  https://ollama.com/api/  "),
            "https://ollama.com"
        );
        assert_eq!(
            endpoint_for("https://ollama.com///api"),
            "https://ollama.com"
        );
        assert_eq!(
            endpoint_for("https://example.invalid/ollama"),
            "https://example.invalid/ollama"
        );
        assert_eq!(
            endpoint_for("https://example.invalid/ollama/api/api"),
            "https://example.invalid/ollama/api",
            "only one /api suffix is stripped"
        );
    }

    /// AC-040e's GLM threshold: the version reads through a namespace
    /// prefix, a missing minor counts as zero, and a non-GLM id never
    /// matches.
    #[test]
    fn glm_threshold_reads_the_recorded_version() {
        assert!(is_glm_at_least_5_2("glm-5.2"));
        assert!(is_glm_at_least_5_2("zai-org/GLM-5.2"));
        assert!(is_glm_at_least_5_2("glm-5.2-fast"));
        assert!(is_glm_at_least_5_2("glm-6"));
        assert!(!is_glm_at_least_5_2("glm-5.1"));
        assert!(!is_glm_at_least_5_2("glm-5"));
        assert!(!is_glm_at_least_5_2("deepseek-v4-pro"));
        assert!(!is_glm_at_least_5_2("glm"));
    }

    /// DEC-012's fanout bound: a phase probes the listing's leading 32
    /// entries, never more — and never probes past a shorter listing.
    #[test]
    fn probe_targets_stop_at_the_discovery_maximum() {
        let mut models: Vec<CatalogModel> = (0..40)
            .map(|index| CatalogModel {
                id: format!("model-{index:02}"),
                ..CatalogModel::default()
            })
            .collect();
        let probed = probe_targets(&mut models);
        assert_eq!(probed.len(), DISCOVERY_MAX_IDS, "40 listed ids probe 32");
        assert_eq!(probed[0].id, "model-00");
        assert_eq!(probed[31].id, "model-31");
        let mut short = models[..7].to_vec();
        assert_eq!(probe_targets(&mut short).len(), 7);
        assert!(probe_targets(&mut []).is_empty());
    }
}
