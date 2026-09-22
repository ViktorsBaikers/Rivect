//! The `google` connection's adapter — the Gemini `streamGenerateContent`
//! dialect (DEC-007/DEC-025, HZN-008 class C). Dialect selection keys on
//! the literal connection id, never an auth label or a catalogue answer;
//! `google-vertex`, `google-antigravity` and `google-gemini-cli` are
//! distinct literal ids with their own recorded classes. The adapter
//! authors no async code — [`Provider::send`] is a blocking single-shot
//! seam and Tokio appears only inside reqwest's blocking client plus the
//! dev-dependency test harness.
//!
//! The recorded contract (google-shared.ts buildGoogleGenerateContentParams
//! / consumeGoogleStream): `POST {endpoint}/models/{id}:streamGenerateContent
//! ?alt=sse` under `x-goog-api-key`, the body carrying `contents`, an
//! optional `systemInstruction`, `tools` as `functionDeclarations`, and a
//! `generationConfig.thinkingConfig.thinkingLevel` for the pinned effort —
//! the manifest's frozen effort is the explicit capability surface, never
//! inferred from the model name. Each SSE `data:` block is one
//! `GenerateContentResponse` chunk; `candidates[0]` carries `content.parts`
//! and the mandatory `finishReason`; `usageMetadata` reports the physical
//! charge verbatim.
//!
//! `thoughtSignature` is the provider-bound opaque artifact (DEC-012
//! analogue): it may ride any part type, signature-bearing parts replay
//! verbatim inside the lineage's model turns, and a signature a different
//! session lineage minted is a provenance failure — never silently dropped
//! or blindly replayed.
//!
//! Secret material crosses only from [`CredentialStore`] into the
//! `x-goog-api-key` header per send — never into config, manifests,
//! diagnostics or this type's `Debug` (INV-001/INV-006).

use crate::config::{Config, Connection, EffortAssign, EffortLevel, FixedModel, ModelAssign};
use crate::model::RequestManifest;
use crate::providers::sse::{SseEvent, SseParser};
use crate::providers::{
    CredentialStore, Dialect, Provider, ProviderError, ProviderReply, STREAM_CHUNK_BYTES,
    SecretRef, ToolCall, bounded_reason, check_deadline, dialect_for, payload_reason,
    read_catalog_body, read_chunk, resolve_credential, sse, transport, transport_status, violation,
    wire_body,
};
use crate::resources::UsageDelta;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The whole-request deadline one physical send may take (DEC-014):
/// the budget covers the whole send — credential resolution, the
/// auto-pool catalogue leg, connect, request send, every stream read
/// and finalization — checked before each blocking call so no leg
/// runs unbounded while the caller believes the adapter answered
/// promptly. The check bounds the work between calls; a call already
/// in flight answers to the client's per-call backstop instead, so
/// the worst case is the deadline plus one backstop-bounded call.
const REQUEST_DEADLINE: Duration = Duration::from_secs(120);

/// The recorded static catalogue the `models.list` answer merges with
/// (HZN-008): the bundled sample the source ships — `gemini-3.1-pro-preview`
/// is the recorded default — so the offered set is never gated on the
/// listing's tail pages or cadence.
const GEMINI_MODELS: &[&str] = &[
    "gemini-3.1-pro",
    "gemini-3.1-pro-preview",
    "gemini-3.7-flash",
];

/// The recorded key-type predicate for the `google` source class
/// (HZN-008 docs): the API keys this dialect authenticates with are
/// the project-billed "standard" keys — distinct from the
/// service-account-bound "authorization" keys new AI Studio issues.
/// The type is a property of the account's key, never detectable from
/// its material.
pub const GOOGLE_PROJECT_BILLED_KEY_TYPE: &str = "standard";

/// The recorded sunset predicate (HZN-008 docs): upstream rejects
/// every standard key from September 2026 — unrestricted ones are
/// already refused. A documented breaking change the account owner
/// must observe; the adapter cannot detect the account's key type.
pub const GOOGLE_STANDARD_KEY_SUNSET: &str = "2026-09";

/// The manifest-bound session/epoch a replay set belongs to
/// (DEC-012): keyed by the frozen execution world, purpose and epoch
/// — a different world is a different lineage, and distinct epochs
/// keep distinct sets so a commit under a stale or interleaved epoch
/// mutates only its own.
type LineageKey = (String, String, String);

/// A signature's provenance claim: the session key plus the epoch
/// that minted it. The epoch leg keeps a retired epoch's artifacts
/// claimed — replaying one under a new epoch is a provenance failure,
/// never a silent adoption.
type SignatureClaim = (String, String, String);

/// The terminal classification one finished stream reduces to: a
/// `STOP`/`MAX_TOKENS` finish, a provider-reported failure verdict,
/// or a `finishReason` the dialect cannot classify.
enum Terminal {
    Completed,
    Failed { reason: String },
    Unclassifiable,
}

/// Per-stream accounting: the assembled model turn's verbatim parts
/// (the lineage replay item), the visible answer text, validated tool
/// calls, collected thought signatures, the last usage report the
/// stream carried, and the terminal it declared. Parts without a
/// finish reason are partial content — a partial tool call is never
/// a usable one.
#[derive(Default)]
struct StreamState {
    parts: Vec<Value>,
    text: String,
    tool_calls: Vec<ToolCall>,
    signatures: Vec<String>,
    usage: Option<Value>,
    terminal: Option<Terminal>,
}

/// The `google` Gemini adapter. Constructed per connection from the
/// validated config; the broker owns the handle — workers never hold
/// one.
pub struct GeminiProvider {
    /// The literal connection id this adapter serves — the dialect
    /// key, not a label.
    connection: String,
    /// The configured endpoint base, trailing slashes trimmed — the
    /// API root including its version segment (`/v1beta`).
    endpoint: String,
    /// The scoped credential binding resolved under DEC-013
    /// precedence — material is read from the store per send so a
    /// rotation is honoured without rebuilding the adapter.
    credential: SecretRef,
    store: Arc<dyn CredentialStore>,
    client: reqwest::blocking::Client,
    /// The one budget the whole send — credential resolution, the
    /// auto-pool catalogue leg, connect, request send, every stream
    /// read and finalization — shares (DEC-014). The reqwest client's
    /// per-call timeout sits at twice it, the backstop bounding a
    /// blocking call the clock cannot interrupt: an expiry observed
    /// between calls surfaces as this adapter's named deadline, while
    /// a stall inside one call surfaces the backstop's own text.
    deadline: Duration,
    /// Manifest-bound replay sets, one per epoch (DEC-012): the
    /// assembled `{role: "model", parts}` turn of every completed
    /// send, replayed verbatim ahead of the next user content —
    /// signature-bearing parts preserved as-is, never merged or moved
    /// across parts. Per-epoch keys mean a commit under a stale epoch
    /// can never wipe the live epoch's set; a retired set is simply
    /// never looked up again.
    lineages: BTreeMap<LineageKey, Vec<Value>>,
    signature_owner: BTreeMap<String, SignatureClaim>,
}

impl GeminiProvider {
    /// Builds the adapter for one connection id: the id must record
    /// the Gemini dialect (DEC-007), the connection must be declared,
    /// carry no configured region — the recorded class has none — and
    /// resolve a scoped credential under DEC-013 precedence.
    ///
    /// # Errors
    /// [`ProviderError::DialectMismatch`] for a connection id without
    /// the Gemini source class; [`ProviderError::UnknownConnection`]
    /// for an undeclared id; [`ProviderError::RegionMismatch`] for a
    /// configured region; [`resolve_credential`]'s typed denials for a
    /// missing, malformed or mismatched binding;
    /// [`ProviderError::Transport`] when the HTTP client cannot be
    /// built.
    pub fn new(
        config: &Config,
        connection: &str,
        store: Arc<dyn CredentialStore>,
    ) -> Result<Self, ProviderError> {
        Self::build(config, connection, store, REQUEST_DEADLINE)
    }

    /// The same adapter under an explicit whole-request deadline —
    /// the bound is adapter policy; proof legs pin a short one so the
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
        if dialect_for(connection) != Some(Dialect::Gemini) {
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
        let credential = resolve_credential(config, connection)?;
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
            endpoint: conn.endpoint.trim_end_matches('/').to_string(),
            credential,
            store,
            client,
            deadline,
            lineages: BTreeMap::new(),
            signature_owner: BTreeMap::new(),
        })
    }

    /// The model catalogue for this connection (HZN-008): the
    /// `models.list` answer merged with the recorded static catalogue.
    /// Only entries whose `supportedGenerationMethods` admit
    /// `generateContent` join — a capability the listing does not
    /// state is never inferred from the model name — returned in
    /// deterministic sorted order.
    ///
    /// # Errors
    /// The credential seam's typed denials, [`ProviderError::Transport`]
    /// on a failed call or non-success status or an expired whole-call
    /// budget, and [`ProviderError::StreamViolation`] when the payload
    /// does not carry the `models` array the contract requires.
    pub fn catalog(&self) -> Result<Vec<String>, ProviderError> {
        // A standalone lookup opens its own whole-call budget — the
        // credential resolution and the wire leg share it, the same
        // bound a send's catalogue leg rides.
        let started = Instant::now();
        // The store call itself cannot be interrupted once running —
        // the check before it is the only point an expired budget
        // still denies the resolve without touching the seam.
        check_deadline(&self.connection, self.deadline, started)?;
        let token = self.secret()?;
        self.catalog_within(&token, started)
    }

    /// The catalogue leg under the caller's clock and credential —
    /// a send passes its own `started` so the lookup spends the same
    /// whole-request budget instead of opening a second, unaccounted
    /// one.
    fn catalog_within(&self, token: &str, started: Instant) -> Result<Vec<String>, ProviderError> {
        check_deadline(&self.connection, self.deadline, started)?;
        let mut response = self
            .client
            .get(format!("{}/models", self.endpoint))
            .header("x-goog-api-key", token)
            .send()
            .map_err(|err| transport(&self.connection, err))?;
        if !response.status().is_success() {
            return Err(transport_status(&self.connection, response.status()));
        }
        // A `nextPageToken` tail is not chased: the static catalogue
        // still applies, so a long listing only narrows the dynamic
        // share, never invents an id.
        let body = read_catalog_body(&self.connection, self.deadline, &mut response, started)?;
        let body: Value = serde_json::from_slice(&body)
            .map_err(|_parse| violation(&self.connection, "models payload is not json"))?;
        let Some(models) = body.get("models").and_then(Value::as_array) else {
            return Err(violation(
                &self.connection,
                "models payload carries no models array",
            ));
        };
        let mut ids: Vec<String> = models
            .iter()
            .filter_map(|entry| {
                let serves = entry
                    .get("supportedGenerationMethods")
                    .and_then(Value::as_array)
                    .is_some_and(|methods| {
                        methods
                            .iter()
                            .any(|method| method.as_str() == Some("generateContent"))
                    });
                if !serves {
                    return None;
                }
                entry
                    .get("name")
                    .and_then(Value::as_str)
                    .and_then(|name| name.strip_prefix("models/"))
                    // A listed name is peer-supplied path material:
                    // only the recorded id charset is offered, so a
                    // hostile or empty entry can never poison the
                    // sorted-first auto pick.
                    .filter(|id| valid_model_id(id))
                    .map(str::to_string)
            })
            .collect();
        for &id in GEMINI_MODELS {
            ids.push(id.to_string());
        }
        ids.sort();
        ids.dedup();
        Ok(ids)
    }

    /// Reads the credential material for this send — the only place
    /// secret bytes cross the store boundary. A non-UTF-8 secret
    /// cannot be an API-key header: typed denial, never a mangled
    /// header.
    fn secret(&self) -> Result<String, ProviderError> {
        let material = self.store.resolve(&self.credential)?;
        String::from_utf8(material).map_err(|_utf8| ProviderError::CredentialMalformed {
            connection: self.connection.clone(),
        })
    }

    /// The frozen manifest as the Gemini wire request: the lineage's
    /// recorded model turns replayed ahead of the new user content —
    /// the stateless replay the signed-part contract requires — the
    /// instructions as `systemInstruction` when they carry text, the
    /// declared tool surface as `functionDeclarations`, and the pinned
    /// effort as `thinkingConfig.thinkingLevel`. The manifest's frozen
    /// effort is the only capability surface: a level the recorded
    /// `ThinkingLevel` enum does not carry is a typed refusal to build
    /// the request, never a silent drop or clamp.
    ///
    /// The replay set is bound by `MODEL_WIRE_MAX_BYTES`: once a
    /// lineage's committed turns serialize past it, every send under
    /// that epoch fails `StreamViolation` — turns are never evicted,
    /// dropping them would break the stateless replay.
    fn request_body(&self, manifest: &RequestManifest) -> Result<Value, ProviderError> {
        let key = (
            manifest.world.clone(),
            manifest.purpose.clone(),
            manifest.epoch_id.clone(),
        );
        let mut contents = self
            .lineages
            .get(&key)
            .map_or_else(Vec::new, |turns| turns.clone());
        contents.push(json!({
            "role": "user",
            "parts": [{ "text": manifest.inputs }],
        }));
        let mut body = json!({ "contents": contents });
        if !manifest.instructions.is_empty() {
            body["systemInstruction"] = json!({
                "parts": [{ "text": manifest.instructions }],
            });
        }
        if let EffortAssign::Fixed { value } = &manifest.effort {
            let level = match value {
                EffortLevel::Minimal => "MINIMAL",
                EffortLevel::Low => "LOW",
                EffortLevel::Medium => "MEDIUM",
                EffortLevel::High => "HIGH",
                // The recorded ThinkingLevel enum tops out at HIGH —
                // transmitting an invented spelling or silently
                // clamping to HIGH would send an effort nobody pinned.
                EffortLevel::Xhigh => {
                    return Err(ProviderError::StreamViolation {
                        connection: self.connection.clone(),
                        reason: format!(
                            "effort {} has no recorded thinking level in this dialect",
                            value.name()
                        ),
                    });
                }
            };
            body["generationConfig"] = json!({
                "thinkingConfig": { "thinkingLevel": level },
            });
        }
        if !manifest.tools.is_empty() {
            body["tools"] = json!([{
                "functionDeclarations": manifest
                    .tools
                    .iter()
                    .map(|name| json!({ "name": name, "description": "" }))
                    .collect::<Vec<_>>(),
            }]);
        }
        Ok(body)
    }

    /// Reads the SSE body through the shared bounded parser and
    /// reduces it to the one terminal the dialect can classify. A
    /// stream that ends without a `finishReason`, or with one the
    /// dialect cannot classify, is never success — the recorded
    /// contract throws on the missing finish reason the same way.
    fn read_stream(
        &mut self,
        manifest: &RequestManifest,
        mut response: reqwest::blocking::Response,
        started: Instant,
    ) -> Result<ProviderReply, ProviderError> {
        let mut parser = SseParser::new();
        let mut state = StreamState::default();
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
            for event in parser
                .feed(&chunk[..read])
                .map_err(|err| sse(&self.connection, err))?
            {
                self.on_chunk(&mut state, manifest, event)?;
            }
        }
        // Finalization shares the budget — the stream's total cost is
        // bounded even when its last byte lands just inside it.
        check_deadline(&self.connection, self.deadline, started)?;
        for event in parser.finish().map_err(|err| sse(&self.connection, err))? {
            self.on_chunk(&mut state, manifest, event)?;
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

    /// Classifies one dispatched SSE event as a `GenerateContentResponse`
    /// chunk. `error` and `promptFeedback.blockReason` are peer verdicts;
    /// `candidates[0]` carries the streamed parts and the mandatory
    /// `finishReason` — `STOP`/`MAX_TOKENS` complete, every other
    /// recorded reason is the peer's own failure verdict, and a reason
    /// the dialect never recorded is unclassifiable, never success. A
    /// second terminal of any kind is a malformed stream.
    fn on_chunk(
        &self,
        state: &mut StreamState,
        manifest: &RequestManifest,
        event: SseEvent,
    ) -> Result<(), ProviderError> {
        let chunk: Value = serde_json::from_str(&event.data)
            .map_err(|_parse| violation(&self.connection, "stream chunk is not json"))?;
        if !chunk.is_object() {
            return Err(violation(&self.connection, "stream chunk is not an object"));
        }
        if let Some(error) = chunk.get("error") {
            return self.set_terminal(
                state,
                Terminal::Failed {
                    reason: payload_reason(error),
                },
            );
        }
        if let Some(feedback) = chunk.get("promptFeedback") {
            if !feedback.is_object() {
                return Err(violation(
                    &self.connection,
                    "promptFeedback is not an object",
                ));
            }
            if let Some(reason) = feedback.get("blockReason") {
                let Some(reason) = reason.as_str() else {
                    return Err(violation(
                        &self.connection,
                        "promptFeedback blockReason is not a string",
                    ));
                };
                return self.set_terminal(
                    state,
                    Terminal::Failed {
                        reason: format!("request blocked by google: {reason}"),
                    },
                );
            }
        }
        if let Some(candidates) = chunk.get("candidates") {
            let Some(list) = candidates.as_array() else {
                return Err(violation(
                    &self.connection,
                    "stream chunk candidates is not an array",
                ));
            };
            // The request never declares `candidateCount`, so a second
            // candidate is off-contract input — never a silent
            // first-pick of divergent content.
            if list.len() > 1 {
                return Err(violation(
                    &self.connection,
                    "stream chunk carried more than one candidate",
                ));
            }
            if let Some(candidate) = list.first() {
                if !candidate.is_object() {
                    return Err(violation(
                        &self.connection,
                        "stream chunk candidate is not an object",
                    ));
                }
                // A candidate after the declared terminal adopts
                // nothing: the verdict closed the turn, and only the
                // recorded usageMetadata-only tail may follow it.
                if state.terminal.is_some() {
                    return Err(violation(
                        &self.connection,
                        "stream carried a candidate after its terminal",
                    ));
                }
                if let Some(index) = candidate.get("index") {
                    // proto3 elides the zero index, so a present index
                    // other than 0 belongs to a candidate slot the
                    // request never asked for.
                    if index.as_u64() != Some(0) {
                        return Err(violation(
                            &self.connection,
                            "stream chunk candidate carries a nonzero index",
                        ));
                    }
                }
                if let Some(content) = candidate.get("content") {
                    if !content.is_object() {
                        return Err(violation(
                            &self.connection,
                            "candidate content is not an object",
                        ));
                    }
                    // proto3 elides an empty `repeated parts`: upstream
                    // reads `candidate?.content?.parts`, so a role-only
                    // content folds zero parts rather than violating.
                    if let Some(parts) = content.get("parts") {
                        let Some(parts) = parts.as_array() else {
                            return Err(violation(
                                &self.connection,
                                "candidate content parts is not an array",
                            ));
                        };
                        for part in parts {
                            self.on_part(state, manifest, part)?;
                        }
                    }
                }
                if let Some(reason) = candidate.get("finishReason") {
                    let Some(reason) = reason.as_str() else {
                        return Err(violation(
                            &self.connection,
                            "candidate finishReason is not a string",
                        ));
                    };
                    let terminal = match reason {
                        "STOP" | "MAX_TOKENS" => Terminal::Completed,
                        // The recorded error-class reasons — the peer's own
                        // verdict, never success even when earlier chunks
                        // carried valid tool calls.
                        "BLOCKLIST"
                        | "PROHIBITED_CONTENT"
                        | "SPII"
                        | "SAFETY"
                        | "IMAGE_SAFETY"
                        | "IMAGE_PROHIBITED_CONTENT"
                        | "IMAGE_RECITATION"
                        | "IMAGE_OTHER"
                        | "RECITATION"
                        | "FINISH_REASON_UNSPECIFIED"
                        | "OTHER"
                        | "LANGUAGE"
                        | "MALFORMED_FUNCTION_CALL"
                        | "UNEXPECTED_TOOL_CALL"
                        | "NO_IMAGE" => Terminal::Failed {
                            reason: format!("generation failed with finish reason {reason}"),
                        },
                        _ => Terminal::Unclassifiable,
                    };
                    self.set_terminal(state, terminal)?;
                }
            }
        }
        if let Some(usage) = chunk.get("usageMetadata") {
            // Usage reports are cumulative — the last one the stream
            // carried is authoritative.
            state.usage = Some(usage.clone());
        }
        Ok(())
    }

    /// Validates one streamed part and folds it into the assembled
    /// turn. `text` joins the visible answer unless the part is
    /// marked `thought` — thought text is model-internal, never
    /// answer text, while its signature still enters the lineage.
    /// `thoughtSignature` on any part type is collected for the
    /// provenance claim. `functionCall` must name a tool the frozen
    /// request declared — an undeclared name is output the dialect
    /// cannot honour, never executed. A part kind outside the recorded
    /// text/thought/function surface is the same typed rejection.
    fn on_part(
        &self,
        state: &mut StreamState,
        manifest: &RequestManifest,
        part: &Value,
    ) -> Result<(), ProviderError> {
        let Some(object) = part.as_object() else {
            return Err(violation(&self.connection, "stream part is not an object"));
        };
        for key in object.keys() {
            if !matches!(
                key.as_str(),
                "text" | "thought" | "thoughtSignature" | "functionCall"
            ) {
                return Err(ProviderError::IncompatibleOutput {
                    connection: self.connection.clone(),
                    reason: bounded_reason(format!("unsupported part kind {key}")),
                });
            }
        }
        if let Some(thought) = object.get("thought")
            && !thought.is_boolean()
        {
            return Err(violation(
                &self.connection,
                "part thought marker is not a boolean",
            ));
        }
        if let Some(signature) = object.get("thoughtSignature") {
            let Some(signature) = signature.as_str() else {
                return Err(violation(
                    &self.connection,
                    "part thoughtSignature is not a string",
                ));
            };
            if !signature.is_empty() {
                state.signatures.push(signature.to_string());
            }
        }
        if let Some(text) = object.get("text") {
            let Some(text) = text.as_str() else {
                return Err(violation(&self.connection, "part text is not a string"));
            };
            if object.get("thought").and_then(Value::as_bool) != Some(true) {
                state.text.push_str(text);
            }
        }
        if let Some(call) = object.get("functionCall") {
            let Some(call) = call.as_object() else {
                return Err(violation(
                    &self.connection,
                    "functionCall part is not an object",
                ));
            };
            let Some(name) = call.get("name").and_then(Value::as_str) else {
                return Err(violation(
                    &self.connection,
                    "functionCall part carries no name",
                ));
            };
            // The call must name a tool the frozen request declared —
            // an undeclared name is output the dialect cannot honour,
            // never executed.
            if !manifest.tools.iter().any(|declared| declared == name) {
                return Err(ProviderError::IncompatibleOutput {
                    connection: self.connection.clone(),
                    reason: bounded_reason(format!("functionCall names undeclared tool {name}")),
                });
            }
            let path = match call.get("args") {
                None => None,
                Some(args) => {
                    let Some(args) = args.as_object() else {
                        return Err(violation(
                            &self.connection,
                            "functionCall args are not an object",
                        ));
                    };
                    args.get("path").and_then(Value::as_str).map(str::to_string)
                }
            };
            state.tool_calls.push(ToolCall {
                tool: name.to_string(),
                path,
            });
        }
        state.parts.push(part.clone());
        Ok(())
    }

    /// The terminal slot — a second verdict of any kind is a malformed
    /// stream, never a saturating overwrite.
    fn set_terminal(
        &self,
        state: &mut StreamState,
        terminal: Terminal,
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

    /// Checks every collected signature against this manifest's
    /// lineage, extracts the physical usage, and only then commits
    /// the assembled turn — a rejected reply mutates nothing.
    fn complete(
        &mut self,
        manifest: &RequestManifest,
        state: StreamState,
    ) -> Result<ProviderReply, ProviderError> {
        // Provenance (DEC-012): a claim keys on the epoch that minted
        // the signature, so a signature a retired epoch produced is
        // foreign to the live one — retirement never frees a claim for
        // silent re-mint. A signature the live lineage owns is a replay
        // of ours; an unclaimed one is minted by this response and
        // claimed below; a signature owned elsewhere is foreign —
        // rejected, never replayed.
        let claim = (
            manifest.world.clone(),
            manifest.purpose.clone(),
            manifest.epoch_id.clone(),
        );
        for signature in &state.signatures {
            match self.signature_owner.get(signature) {
                Some(owner) if *owner == claim => {}
                Some(_) => {
                    return Err(ProviderError::ReasoningProvenance {
                        connection: self.connection.clone(),
                        reason: "the artifact belongs to a different session lineage".to_string(),
                    });
                }
                None => {}
            }
        }
        let usage = self.usage_of(&state)?;
        // Commit: the validated assembled turn joins this epoch's own
        // replay set — never the session's last-committed one — and its
        // signatures join the lineage's provenance set. Artifact claims
        // persist as tombstones across a retired epoch's set.
        if !state.parts.is_empty() {
            let key = (
                manifest.world.clone(),
                manifest.purpose.clone(),
                manifest.epoch_id.clone(),
            );
            self.lineages.entry(key).or_default().push(json!({
                "role": "model",
                "parts": state.parts,
            }));
        }
        for signature in state.signatures {
            self.signature_owner.insert(signature, claim.clone());
        }
        Ok(ProviderReply {
            text: state.text,
            tool_calls: state.tool_calls,
            usage,
        })
    }

    /// The physical usage the terminal reported: absent `usageMetadata`
    /// stays [`UsageDelta::Unknown`] — never an estimate, never a zero
    /// the accounting could release; a present-but-unreadable shape is
    /// a wire violation.
    fn usage_of(&self, state: &StreamState) -> Result<UsageDelta, ProviderError> {
        let Some(usage) = &state.usage else {
            return Ok(UsageDelta::Unknown);
        };
        let prompt = usage.get("promptTokenCount").and_then(Value::as_u64);
        // proto3 JSON omits zero-valued fields, so an absent
        // `candidatesTokenCount` is the reported zero — not a withheld
        // counter and not an estimate. A present counter that does not
        // read is still malformed.
        let completion = match usage.get("candidatesTokenCount") {
            None => Some(0),
            Some(count) => count.as_u64(),
        };
        let total = usage.get("totalTokenCount").and_then(Value::as_u64);
        match (prompt, completion, total) {
            // The reported total is charged verbatim — never re-summed
            // — and a usage object that withholds it is a wire
            // violation, not an estimate the peer never charged.
            (Some(prompt_tokens), Some(completion_tokens), Some(total_tokens)) => {
                Ok(UsageDelta::Exact {
                    prompt_tokens,
                    completion_tokens,
                    total_tokens,
                })
            }
            _ => Err(violation(
                &self.connection,
                "usageMetadata is not a readable token shape",
            )),
        }
    }
}

/// A model id is exactly one URL path segment — non-empty and inside
/// the recorded `[A-Za-z0-9._-]` id charset. Dots are admitted — the
/// pinned `:streamGenerateContent` suffix means the id can never form
/// a bare `.`/`..` segment — while `/`, `?` or `%` are denied: they
/// would split the path, open the query early or percent-rewrite the
/// request.
fn valid_model_id(id: &str) -> bool {
    !id.is_empty()
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

impl std::fmt::Debug for GeminiProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The scoped ref is the visible token — the store and its
        // material never enter diagnostics (INV-001).
        f.debug_struct("GeminiProvider")
            .field("connection", &self.connection)
            .field("endpoint", &self.endpoint)
            .field("credential", &self.credential)
            .field("deadline", &self.deadline)
            .finish_non_exhaustive()
    }
}

impl Provider for GeminiProvider {
    fn name(&self) -> &'static str {
        "google-gemini"
    }

    /// The adapter serves only the literal connection id its dialect
    /// was constructed for (DEC-007) — a pin to any other id is a
    /// dialect it does not speak.
    fn serves(&self, connection: &str, _entry: &Connection) -> bool {
        connection == self.connection
    }

    /// Sends the frozen manifest as one physical Gemini request.
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
    /// request body over the wire bound, a pinned effort the recorded
    /// `ThinkingLevel` enum cannot carry, or a resolved model id
    /// outside the URL path-segment charset —
    /// [`ProviderError::IncompatibleOutput`] and
    /// [`ProviderError::ReasoningProvenance`] as the stream legs
    /// document.
    fn send(&mut self, manifest: &RequestManifest) -> Result<ProviderReply, ProviderError> {
        // The whole call spends one budget: credential resolution, the
        // auto-pool catalogue leg, and the streamed response all count
        // against the same clock — no leg starts past the deadline the
        // caller was promised; an in-flight credential-store call runs
        // to completion (uninterruptible).
        let started = Instant::now();
        // The credential resolves once per send — the catalogue leg and
        // the post both bear the same material, so a rotation mid-send
        // can never split one request across two secrets. The store call
        // cannot be interrupted once running, so an already-spent budget
        // must deny it here rather than on the far side.
        check_deadline(&self.connection, self.deadline, started)?;
        let token = self.secret()?;
        // A fixed pin names connection and model verbatim. A
        // single-member auto pool naming this connection is an
        // explicit pick of it — the pick pins the connection, and the
        // catalogue names the model: the deterministic sorted-first id
        // of the listing merged with the static catalogue, the
        // recorded auto semantic of resolving the model at catalogue
        // time. Any other assignment is a model this adapter cannot pin.
        let fixed = match &manifest.model {
            ModelAssign::Fixed(fixed) => fixed.clone(),
            ModelAssign::Auto { pool: Some(pool) }
                if pool.len() == 1 && pool[0] == self.connection =>
            {
                let model_id = self
                    .catalog_within(&token, started)?
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
        // The resolved id is verbatim URL path material: re-validated
        // at the adapter boundary whichever leg produced it, so a
        // hostile or malformed pin is denied before any post — `..`,
        // `?` or `%` in an id would traverse the `/models/` collection
        // or rewrite the method suffix.
        if !valid_model_id(&fixed.model_id) {
            return Err(ProviderError::StreamViolation {
                connection: self.connection.clone(),
                reason: bounded_reason(format!(
                    "model id {:?} is not a usable request path segment",
                    fixed.model_id
                )),
            });
        }
        let body = self.request_body(manifest)?;
        let body_bytes = wire_body(&self.connection, &body)?;
        // The wire leg is the last budget check: a resolve or
        // catalogue leg that spent the clock fails the send typed
        // here — an expired budget never puts a byte on the wire.
        check_deadline(&self.connection, self.deadline, started)?;
        let response = self
            .client
            .post(format!(
                "{}/models/{}:streamGenerateContent?alt=sse",
                self.endpoint, fixed.model_id
            ))
            .header("x-goog-api-key", &token)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::ACCEPT, "text/event-stream")
            .body(body_bytes)
            .send()
            .map_err(|err| transport(&self.connection, err))?;
        if !response.status().is_success() {
            return Err(transport_status(&self.connection, response.status()));
        }
        self.read_stream(manifest, response, started)
    }
}
