//! The OpenAI Responses dialect adapter (DEC-007/DEC-025, HZN-008) —
//! the literal connection ids `openai` and `abliteration` record this
//! dialect. Dialect selection keys on the literal connection id,
//! never an auth label or a catalogue answer, and `openai-codex` is
//! a distinct literal id with its own recorded class. The adapter
//! authors no async code — [`Provider::send`] is
//! a blocking single-shot seam and Tokio appears only inside reqwest's
//! blocking client plus the dev-dependency test harness — and
//! `store: false` is sent verbatim on
//! every request: an explicit wire field, not a zero-retention claim.
//! Because the provider keeps no server-side state, cross-turn
//! context replays through the lineage the adapter holds (DEC-012),
//! and `include = ["reasoning.encrypted_content"]` rides the same body
//! where the recorded peer returns reasoning items with the artifact
//! the replay contract needs (SRC-019/D-006) — a connection whose
//! recorded compat says the peer never returns them never asks.
//! Secret material crosses only from [`CredentialStore`] into the
//! `Authorization` header per send — never into config, manifests,
//! diagnostics or this type's `Debug` (INV-001/INV-006).

use crate::config::{Config, Connection, EffortAssign, FixedModel, ModelAssign};
use crate::model::RequestManifest;
use crate::providers::sse::{SseEvent, SseParser};
use crate::providers::{
    CredentialStore, Dialect, Provider, ProviderError, ProviderReply, STREAM_CHUNK_BYTES,
    SecretRef, ToolCall, bounded_reason, check_deadline, dialect_for, read_catalog_body,
    read_chunk, resolve_credential, sse, transport, transport_status, violation, wire_body,
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

/// The recorded source sample of Responses-capable model ids the
/// `openai` connection's catalogue surface filters `/models` to
/// (HZN-008): the static sample the offline contract pins — live
/// discovery is a later leg.
const RESPONSES_MODELS: &[&str] = &["gpt-5.2", "gpt-5.2-codex", "gpt-5.1", "o4-mini", "o3"];

/// The recorded static seed of `abliteration` model ids (HZN-008,
/// `ABLITERATION_STATIC_MODELS`): the merge floor the catalogue
/// unions over the authoritative `/models` listing — a seeded id
/// offers even when the listing omits it. The recorded source seeded
/// them so generation and first boot could offer models with no live
/// key; that rationale stays upstream's — this adapter resolves a
/// credential before any catalogue call, so the seed's role here is
/// the floor, never a keyless offer path.
const ABLITERATION_MODELS: &[&str] = &[
    "abliterated-model",
    "abliterated-model-large",
    "abliterated-model-large-v2",
];

/// The predicates the recorded source class binds to a literal
/// Responses id (HZN-008): the dialect is shared across connection
/// ids — the catalogue rule and the reasoning-artifact surface are
/// not. The `abliteration` compat's recorded `stream-idle-timeout-ms
/// 0` maps to construction rather than a field: the stream read loop
/// runs no per-read idle watchdog, so a peer idling between chunks
/// mid reasoning turn is bounded only by the whole-call `deadline` —
/// the predicate holds by the loop's shape for every id.
struct SourceContract {
    /// The static source-sample model ids the connection offers.
    seed: &'static [&'static str],
    /// `true` — `/models` is authoritative and `seed` merges on top
    /// of the listing as the offer floor (`abliteration`: the
    /// recorded model manager marks the listing authoritative while
    /// the recorded seed's ids stay offered even when the listing
    /// omits them); `false` — the listing filters to `seed`
    /// (`openai`: the recorded sample is the offer set).
    authoritative_models: bool,
    /// `true` — the request asks for the `reasoning.encrypted_content`
    /// artifact the replay contract carries (SRC-019/D-006); `false`
    /// — the recorded peer compat marks the gateway as never
    /// returning encrypted reasoning items, so the include is never
    /// requested (`abliteration`: every model reasons intrinsically —
    /// `reasoning: true` forced in the recorded mapper — and none
    /// returns a replayable artifact).
    reasoning_artifact: bool,
}

/// The recorded per-connection contract for a Responses id
/// (DEC-007/DEC-025): `build` denies every id without the recorded
/// Responses class before this lookup runs, and an id the dialect map
/// admits but this table does not name resolves `None` — denied the
/// same way. A further Responses id records its own predicates as a
/// named arm here, never inherits another's.
fn contract_for(connection: &str) -> Option<SourceContract> {
    match connection {
        "openai" => Some(SourceContract {
            seed: RESPONSES_MODELS,
            authoritative_models: false,
            reasoning_artifact: true,
        }),
        "abliteration" => Some(SourceContract {
            seed: ABLITERATION_MODELS,
            authoritative_models: true,
            reasoning_artifact: false,
        }),
        _ => None,
    }
}

/// The manifest-bound session/epoch a replay set belongs to
/// (DEC-012): keyed by the frozen execution world, purpose and epoch
/// — a different world is a different lineage, and distinct epochs
/// keep distinct sets so a commit under a stale or interleaved epoch
/// mutates only its own.
type LineageKey = (String, String, String);

/// A blob's provenance claim (DEC-012): the session key plus the
/// epoch that minted it. The epoch leg keeps a retired epoch's
/// artifacts claimed — replaying one under a new epoch is a
/// provenance failure, never a silent adoption.
type BlobClaim = (String, String, String);

/// The terminal classification one completed stream reduces to: the
/// `response.completed` payload, a provider-reported failure, or a
/// provider-reported incomplete/cancelled verdict.
enum Terminal {
    Completed { response: Value },
    Failed { reason: String },
    Incomplete { reason: String },
}

/// Per-stream accounting: open output items (a nonzero count at EOF
/// means the stream truncated mid item — a partial tool call is never
/// a usable one) and the terminal the stream declared.
#[derive(Default)]
struct StreamState {
    open_items: u64,
    terminal: Option<Terminal>,
}

/// The shared Responses adapter. Constructed per connection from the
/// validated config; the broker owns the handle — workers never hold
/// one.
pub struct OpenAiProvider {
    /// The literal connection id this adapter serves — the dialect
    /// key, not a label.
    connection: String,
    /// The recorded per-connection predicates (HZN-008): resolved
    /// from the literal id at build and never re-keyed — the dialect
    /// is shared, the contract is not.
    contract: SourceContract,
    /// The configured endpoint base, trailing slashes trimmed.
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
    /// Manifest-bound replay sets, one per epoch (DEC-012): every
    /// output item the epoch's completed turns returned, replayed
    /// verbatim ahead of the next input because `store: false` keeps
    /// no server-side state — plus the blob→lineage ownership map that
    /// makes a foreign artifact detectable. Per-epoch keys mean a
    /// commit under a stale epoch can never wipe the live epoch's set;
    /// a retired set is simply never looked up again.
    lineages: BTreeMap<LineageKey, Vec<Value>>,
    blob_owner: BTreeMap<String, BlobClaim>,
}

impl OpenAiProvider {
    /// Builds the adapter for one connection id: the id must record
    /// the Responses dialect (DEC-007), the connection must be
    /// declared, carry no configured region the dialect's endpoint
    /// contract cannot honour, and resolve a scoped credential under
    /// DEC-013 precedence.
    ///
    /// # Errors
    /// [`ProviderError::DialectMismatch`] for a connection id without
    /// the Responses source class; [`ProviderError::UnknownConnection`]
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
        if dialect_for(connection) != Some(Dialect::Responses) {
            return Err(ProviderError::DialectMismatch {
                connection: connection.to_string(),
            });
        }
        // A Responses-classed id without its own recorded contract arm
        // is denied the same way — the predicates are recorded per
        // literal id, never inherited silently.
        let contract = contract_for(connection).ok_or(ProviderError::DialectMismatch {
            connection: connection.to_string(),
        })?;
        let conn = config
            .connections
            .get(connection)
            .ok_or(ProviderError::UnknownConnection)?;
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
            contract,
            endpoint: conn.endpoint.trim_end_matches('/').to_string(),
            credential,
            store,
            client,
            deadline,
            lineages: BTreeMap::new(),
            blob_owner: BTreeMap::new(),
        })
    }

    /// The model catalogue for this connection (HZN-008): `GET
    /// /models` under the literal id's recorded rule — `openai`
    /// filters the listing to the recorded Responses-capable sample,
    /// `abliteration` treats the listing as authoritative and merges
    /// its static source seed on top — returned in deterministic
    /// sorted order.
    ///
    /// # Errors
    /// The credential seam's typed denials, [`ProviderError::Transport`]
    /// on a failed call or non-success status or an expired whole-call
    /// budget, and [`ProviderError::StreamViolation`] when the payload
    /// does not carry the `data` array the contract requires.
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
            .bearer_auth(token)
            .send()
            .map_err(|err| transport(&self.connection, err))?;
        if !response.status().is_success() {
            return Err(transport_status(&self.connection, response.status()));
        }
        let body = read_catalog_body(&self.connection, self.deadline, &mut response, started)?;
        let body: Value = serde_json::from_slice(&body)
            .map_err(|_parse| violation(&self.connection, "models payload is not json"))?;
        let Some(data) = body.get("data").and_then(Value::as_array) else {
            return Err(violation(
                &self.connection,
                "models payload carries no data array",
            ));
        };
        // The catalogue rule is the literal id's recorded contract
        // (HZN-008): `openai` filters the listing to the recorded
        // sample — ids the dialect does not serve are never offered —
        // while `abliteration` treats the listing as authoritative:
        // every non-empty id offers, and the recorded seed merges on
        // top as the offer floor.
        let mut ids: Vec<String> = data
            .iter()
            .filter_map(|entry| entry.get("id").and_then(Value::as_str))
            .filter(|id| {
                if self.contract.authoritative_models {
                    !id.is_empty()
                } else {
                    self.contract.seed.contains(id)
                }
            })
            .map(str::to_string)
            .collect();
        if self.contract.authoritative_models {
            ids.extend(self.contract.seed.iter().map(|id| (*id).to_string()));
            ids.sort();
            ids.dedup();
        } else {
            ids.sort();
        }
        Ok(ids)
    }

    /// Reads the credential material for this send — the only place
    /// secret bytes cross the store boundary. A non-UTF-8 secret
    /// cannot be a bearer token: typed denial, never a mangled header.
    fn secret(&self) -> Result<String, ProviderError> {
        let material = self.store.resolve(&self.credential)?;
        String::from_utf8(material).map_err(|_utf8| ProviderError::CredentialMalformed {
            connection: self.connection.clone(),
        })
    }

    /// The frozen manifest as the Responses wire request (AC-013):
    /// model pin, instructions and the declared tool surface verbatim,
    /// `store: false` and `stream: true` always,
    /// `include = ["reasoning.encrypted_content"]` where the recorded
    /// peer returns the reasoning artifact the replay contract carries
    /// (SRC-019/D-006), the pinned effort on the reasoning surface,
    /// and the epoch's recorded output items replayed ahead of the new
    /// input — the stateless replay the `store: false` contract
    /// requires.
    ///
    /// The replay set is bound by `MODEL_WIRE_MAX_BYTES`: once a
    /// lineage's committed items serialize past it, every send under
    /// that epoch fails `StreamViolation` — items are never evicted,
    /// dropping them would break the stateless replay. The wedge's
    /// recorded escape is a prefix mutation opening a new epoch with
    /// an empty set (F15).
    fn request_body(&self, manifest: &RequestManifest, fixed: &FixedModel) -> Value {
        let key = (
            manifest.world.clone(),
            manifest.purpose.clone(),
            manifest.epoch_id.clone(),
        );
        let prior = self
            .lineages
            .get(&key)
            .map_or_else(Vec::new, |items| items.clone());
        let mut input = prior;
        input.push(json!({
            "role": "user",
            "content": [{ "type": "input_text", "text": manifest.inputs }],
        }));
        let mut body = json!({
            "model": fixed.model_id,
            "instructions": manifest.instructions,
            "input": input,
            "store": false,
            "stream": true,
        });
        // The replay-artifact include rides only where the recorded
        // peer returns encrypted reasoning items (SRC-019/D-006): the
        // `abliteration` gateway never does — its recorded compat
        // marks `include-encrypted-reasoning #false` and every model
        // reasons intrinsically — so its request never asks.
        if self.contract.reasoning_artifact {
            body["include"] = json!(["reasoning.encrypted_content"]);
        }
        if let EffortAssign::Fixed { value } = &manifest.effort {
            body["reasoning"] = json!({ "effort": value.name() });
        }
        if !manifest.tools.is_empty() {
            body["tools"] = Value::Array(
                manifest
                    .tools
                    .iter()
                    .map(|name| json!({ "type": "function", "name": name }))
                    .collect(),
            );
        }
        body
    }

    /// Reads the SSE body through the shared bounded parser and
    /// reduces it to the one terminal the dialect can classify. A
    /// stream that ends mid item, without a terminal, or with an
    /// unclassifiable one is never success.
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
                self.on_event(&mut state, event)?;
            }
        }
        // Finalization shares the budget — the stream's total cost is
        // bounded even when its last byte lands just inside it.
        check_deadline(&self.connection, self.deadline, started)?;
        for event in parser.finish().map_err(|err| sse(&self.connection, err))? {
            self.on_event(&mut state, event)?;
        }
        if state.open_items > 0 {
            return Err(violation(&self.connection, "stream ended mid output item"));
        }
        match state.terminal {
            Some(Terminal::Completed { response }) => self.complete(manifest, &response),
            Some(Terminal::Failed { reason }) | Some(Terminal::Incomplete { reason }) => {
                Err(ProviderError::ProviderFailed {
                    connection: self.connection.clone(),
                    reason: bounded_reason(reason),
                })
            }
            None => Err(ProviderError::UnknownTerminal {
                connection: self.connection.clone(),
            }),
        }
    }

    /// Classifies one dispatched SSE event. Lifecycle and delta events
    /// are forward-compatible surface — observed, never a terminal
    /// substitute; only the mandatory terminal events produce the
    /// outcome. A known terminal event with a malformed payload is a
    /// wire violation, and a `response.completed` whose status the
    /// dialect cannot classify is an unknown terminal.
    fn on_event(&self, state: &mut StreamState, event: SseEvent) -> Result<(), ProviderError> {
        let terminal = match event.event.as_str() {
            "response.output_item.added" => {
                state.open_items += 1;
                None
            }
            "response.output_item.done" => {
                // The lifecycle contract pairs every done with its
                // added (REQ-036): an orphan close is a malformed
                // stream, never a saturating no-op that hides it.
                if state.open_items == 0 {
                    return Err(violation(
                        &self.connection,
                        "output item done event without its added",
                    ));
                }
                state.open_items -= 1;
                None
            }
            "response.completed" => {
                let response = self.response_payload(&event, "response.completed")?;
                match response.get("status").and_then(Value::as_str) {
                    Some("completed") => Some(Terminal::Completed { response }),
                    Some("failed") => Some(Terminal::Failed {
                        reason: payload_reason(&response),
                    }),
                    Some("incomplete") | Some("cancelled") => Some(Terminal::Incomplete {
                        reason: payload_reason(&response),
                    }),
                    _ => {
                        return Err(ProviderError::UnknownTerminal {
                            connection: self.connection.clone(),
                        });
                    }
                }
            }
            "response.failed" => Some(Terminal::Failed {
                reason: payload_reason(&self.response_payload(&event, "response.failed")?),
            }),
            "response.incomplete" => Some(Terminal::Incomplete {
                reason: payload_reason(&self.response_payload(&event, "response.incomplete")?),
            }),
            "error" => {
                let payload: Value = serde_json::from_str(&event.data).map_err(|_parse| {
                    violation(&self.connection, "error event payload is not json")
                })?;
                Some(Terminal::Failed {
                    reason: payload_reason(&payload),
                })
            }
            _ => None,
        };
        if let Some(terminal) = terminal {
            if state.terminal.is_some() {
                return Err(violation(
                    &self.connection,
                    "stream carried a duplicate terminal event",
                ));
            }
            state.terminal = Some(terminal);
        }
        Ok(())
    }

    /// The `response` object one terminal event's payload must carry.
    fn response_payload(
        &self,
        event: &SseEvent,
        name: &'static str,
    ) -> Result<Value, ProviderError> {
        let payload: Value = serde_json::from_str(&event.data)
            .map_err(|_parse| violation(&self.connection, "terminal event payload is not json"))?;
        let response = payload.get("response").cloned().unwrap_or(payload);
        if !response.is_object() {
            return Err(violation(&self.connection, name));
        }
        Ok(response)
    }

    /// Validates the completed response's output items, checks every
    /// reasoning artifact against this manifest's lineage, extracts
    /// the physical usage, and only then commits the lineage — a
    /// rejected reply mutates nothing.
    fn complete(
        &mut self,
        manifest: &RequestManifest,
        response: &Value,
    ) -> Result<ProviderReply, ProviderError> {
        let Some(output) = response.get("output").and_then(Value::as_array) else {
            return Err(violation(
                &self.connection,
                "response.completed carries no output array",
            ));
        };
        let mut text = String::new();
        let mut tool_calls = Vec::new();
        let mut blobs = Vec::new();
        for item in output {
            let Some(item_type) = item.get("type").and_then(Value::as_str) else {
                return Err(violation(&self.connection, "output item without a type"));
            };
            // A completed terminal may only carry finished items: an
            // unfinished or unlabelled message/function_call is
            // truncated content — never returned, never executed. A
            // reasoning item is exempt from the lifecycle check: its
            // gate is the `encrypted_content` provenance below, and
            // the artifact replays verbatim whatever label it carried
            // (D-006) — the recorded contract requires the blob, not
            // the status.
            if matches!(item_type, "message" | "function_call")
                && item.get("status").and_then(Value::as_str) != Some("completed")
            {
                return Err(ProviderError::StreamViolation {
                    connection: self.connection.clone(),
                    reason: bounded_reason(format!(
                        "{item_type} item in a completed response is not completed"
                    )),
                });
            }
            match item_type {
                "message" => {
                    let Some(content) = item.get("content").and_then(Value::as_array) else {
                        return Err(violation(
                            &self.connection,
                            "message item carries no content array",
                        ));
                    };
                    for part in content {
                        match part.get("type").and_then(Value::as_str) {
                            Some("output_text") => {
                                let Some(part_text) = part.get("text").and_then(Value::as_str)
                                else {
                                    return Err(violation(
                                        &self.connection,
                                        "output_text part carries no text",
                                    ));
                                };
                                text.push_str(part_text);
                            }
                            Some("refusal") => {
                                if let Some(refusal) = part.get("refusal").and_then(Value::as_str) {
                                    text.push_str(refusal);
                                }
                            }
                            // Other content parts are forward-compatible
                            // surface — observed, not consumed.
                            Some(_) => {}
                            None => {
                                return Err(violation(
                                    &self.connection,
                                    "message content part without a type",
                                ));
                            }
                        }
                    }
                }
                "function_call" => {
                    let Some(name) = item.get("name").and_then(Value::as_str) else {
                        return Err(violation(
                            &self.connection,
                            "function_call item carries no name",
                        ));
                    };
                    // The call must name a tool the frozen request
                    // declared — an undeclared name is output the
                    // dialect cannot honour, never executed.
                    if !manifest.tools.iter().any(|declared| declared == name) {
                        return Err(ProviderError::IncompatibleOutput {
                            connection: self.connection.clone(),
                            reason: bounded_reason(format!(
                                "function_call names undeclared tool {name}"
                            )),
                        });
                    }
                    let Some(arguments) = item.get("arguments").and_then(Value::as_str) else {
                        return Err(violation(
                            &self.connection,
                            "function_call item carries no arguments",
                        ));
                    };
                    let parsed: Value = serde_json::from_str(arguments).map_err(|_parse| {
                        violation(&self.connection, "function_call arguments are not json")
                    })?;
                    let args = parsed.as_object().ok_or_else(|| {
                        violation(
                            &self.connection,
                            "function_call arguments are not an object",
                        )
                    })?;
                    tool_calls.push(ToolCall {
                        tool: name.to_string(),
                        path: args.get("path").and_then(Value::as_str).map(str::to_string),
                    });
                }
                // DEC-012: where the recorded peer returns the replay
                // artifact, a reasoning item must carry the opaque
                // `encrypted_content` the lineage contract needs —
                // absent content is a provenance failure, never a
                // silent drop. Where the recorded peer never returns
                // it, a blobless item is the peer's normal shape —
                // observed, then excluded from the lineage below since
                // there is no artifact to replay under — while any
                // `encrypted_content` member it does carry is
                // off-contract foreign material, the same denial.
                "reasoning" => {
                    if self.contract.reasoning_artifact {
                        let Some(blob) = item.get("encrypted_content").and_then(Value::as_str)
                        else {
                            return Err(ProviderError::ReasoningProvenance {
                                connection: self.connection.clone(),
                                reason: "a reasoning item carried no encrypted_content".to_string(),
                            });
                        };
                        blobs.push(blob.to_string());
                    } else if item.get("encrypted_content").is_some() {
                        return Err(ProviderError::ReasoningProvenance {
                            connection: self.connection.clone(),
                            reason: "a reasoning item carried an artifact the recorded peer never returns".to_string(),
                        });
                    }
                }
                // A well-formed item the dialect cannot honour —
                // server-side tool kinds the request never declared.
                other => {
                    return Err(ProviderError::IncompatibleOutput {
                        connection: self.connection.clone(),
                        reason: bounded_reason(format!("unsupported output item type {other}")),
                    });
                }
            }
        }
        // Provenance (DEC-012): a claim keys on the epoch that minted
        // the artifact, so a blob a retired epoch produced is foreign
        // to the live one — retirement never frees a claim for silent
        // re-mint. A blob the live lineage owns is a replay of ours;
        // an unclaimed blob is minted by this response and claimed
        // below; a blob owned elsewhere is foreign — rejected, never
        // replayed.
        let claim = (
            manifest.world.clone(),
            manifest.purpose.clone(),
            manifest.epoch_id.clone(),
        );
        for blob in &blobs {
            match self.blob_owner.get(blob) {
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
        let usage = self.usage_of(response)?;
        // Commit: the validated output set joins this epoch's own
        // replay set — never the session's last-committed one, so a
        // stale or interleaved send cannot wipe the live epoch's
        // context — and its artifacts join the lineage's provenance
        // set. A retired epoch's set is never looked up again, while
        // artifact claims persist as tombstones: replaying a retired
        // blob under the new epoch is the provenance failure above.
        let key = (
            manifest.world.clone(),
            manifest.purpose.clone(),
            manifest.epoch_id.clone(),
        );
        // Under the no-artifact contract a reasoning item carries
        // nothing the stateless replay can adopt — it never joins the
        // lineage (a blobbed one was already refused above).
        self.lineages.entry(key).or_default().extend(
            output
                .iter()
                .filter(|item| {
                    self.contract.reasoning_artifact
                        || item.get("type").and_then(Value::as_str) != Some("reasoning")
                })
                .cloned(),
        );
        for blob in blobs {
            self.blob_owner.insert(blob, claim.clone());
        }
        Ok(ProviderReply {
            text,
            tool_calls,
            usage,
        })
    }

    /// The physical usage the terminal reported: absent usage stays
    /// [`UsageDelta::Unknown`] — never an estimate, never a zero the
    /// accounting could release; a present-but-unreadable shape is a
    /// wire violation.
    fn usage_of(&self, response: &Value) -> Result<UsageDelta, ProviderError> {
        let Some(usage) = response.get("usage") else {
            return Ok(UsageDelta::Unknown);
        };
        let input = usage.get("input_tokens").and_then(Value::as_u64);
        let output = usage.get("output_tokens").and_then(Value::as_u64);
        let total = usage.get("total_tokens").and_then(Value::as_u64);
        match (input, output, total) {
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
                "response.usage is not a readable token shape",
            )),
        }
    }
}

/// The reason a failed/incomplete verdict carries — the peer's own
/// `code`, `message` or `reason` field, whichever it populated.
fn payload_reason(response: &Value) -> String {
    for field in ["code", "message", "reason"] {
        if let Some(value) = response.get(field).and_then(Value::as_str) {
            return value.to_string();
        }
    }
    if let Some(details) = response.get("incomplete_details")
        && let Some(reason) = details.get("reason").and_then(Value::as_str)
    {
        return reason.to_string();
    }
    if let Some(error) = response.get("error") {
        for field in ["code", "message"] {
            if let Some(value) = error.get(field).and_then(Value::as_str) {
                return value.to_string();
            }
        }
    }
    "unclassified".to_string()
}

impl std::fmt::Debug for OpenAiProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The scoped ref is the visible token — the store and its
        // material never enter diagnostics (INV-001).
        f.debug_struct("OpenAiProvider")
            .field("connection", &self.connection)
            .field("endpoint", &self.endpoint)
            .field("credential", &self.credential)
            .field("deadline", &self.deadline)
            .finish_non_exhaustive()
    }
}

impl Provider for OpenAiProvider {
    fn name(&self) -> &'static str {
        "openai-responses"
    }

    /// The adapter serves only the literal connection id its dialect
    /// was constructed for (DEC-007) — a pin to any other id is a
    /// dialect it does not speak.
    fn serves(&self, connection: &str, _entry: &Connection) -> bool {
        connection == self.connection
    }

    /// Sends the frozen manifest as one physical Responses request.
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
    /// request body over the wire bound —
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
        // live catalogue names the model: the deterministic
        // sorted-first id it answers under the connection's recorded
        // catalogue rule, the recorded
        // auto semantic of resolving the model at catalogue time. Any
        // other assignment is a model this adapter cannot pin.
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
        let body = self.request_body(manifest, &fixed);
        let body_bytes = wire_body(&self.connection, &body)?;
        // The wire leg is the last budget check: a resolve or
        // catalogue leg that spent the clock fails the send typed
        // here — an expired budget never puts a byte on the wire.
        check_deadline(&self.connection, self.deadline, started)?;
        let response = self
            .client
            .post(format!("{}/responses", self.endpoint))
            .bearer_auth(&token)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body_bytes)
            .send()
            .map_err(|err| transport(&self.connection, err))?;
        if !response.status().is_success() {
            return Err(transport_status(&self.connection, response.status()));
        }
        self.read_stream(manifest, response, started)
    }
}
