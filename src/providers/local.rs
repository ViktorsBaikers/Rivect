//! The `custom-chat-completions` and `aiand` connections' adapter —
//! the OpenAI-compatible Chat Completions dialect (DEC-007/DEC-025,
//! HZN-008 class S and class A). Dialect selection keys on the
//! literal connection id, never an auth label, an endpoint shape or
//! a catalogue answer: every compatible host a deployment wires
//! under `custom-chat-completions` shares the one recorded generic
//! contract, while `aiand` carries its own recorded predicates —
//! the `/v1` base normalization and the org-scoped catalogue
//! transform — resolved per literal id by the contract table, never
//! inherited across ids. The adapter authors no
//! async code — [`Provider::send`] is a blocking single-shot seam and
//! Tokio appears only inside reqwest's blocking client plus the
//! dev-dependency test harness.
//!
//! The recorded contract (omp openai-completions.ts /
//! openai-shared.ts): `POST {endpoint}/chat/completions` under a
//! `Bearer` authorization, the body carrying `model`, `messages`
//! (`system` for the instructions, `user` for the inputs), `stream`
//! with `stream_options.include_usage`, the declared tool surface as
//! `{"type": "function", "function": {…}}` entries and the pinned
//! effort as `reasoning_effort` verbatim — the manifest's frozen
//! effort is the explicit capability surface, never inferred from the
//! model name. Each SSE `data:` block is one `chat.completion.chunk`;
//! `choices[0].delta` carries the streamed content, reasoning and
//! `tool_calls` fragments; `finish_reason` declares the terminal; the
//! trailing `choices:[]` usage chunk reports the physical charge;
//! `[DONE]` is the server-agreed close.
//!
//! Secret material crosses only from [`CredentialStore`] into the
//! `Authorization` header per send — never into config, manifests,
//! diagnostics or this type's `Debug` (INV-001/INV-006).

use crate::config::{Config, Connection, EffortAssign, EffortLevel, FixedModel, ModelAssign};
use crate::model::RequestManifest;
use crate::providers::sse::{SseError, SseEvent, SseParser};
use crate::providers::{
    CredentialStore, Dialect, Provider, ProviderError, ProviderReply, SecretRef, ToolCall,
    dialect_for, resolve_credential,
};
use crate::resources::UsageDelta;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::io::Read;
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

/// Bytes read from the response stream per pass — the chunking is an
/// implementation detail the SSE parser is indifferent to.
const STREAM_CHUNK_BYTES: usize = 8 * 1024;

/// The bound on one `models` catalogue payload — a listing never
/// needs more, and an unbounded or dribbling body is denied under
/// the same budget as a streamed response.
const CATALOG_MAX_BYTES: usize = 1024 * 1024;

/// The bound on distinct tool-call blocks one stream may open — a
/// streamed response to a request declaring a handful of tools never
/// legitimately carries more, and an unbounded count is denied rather
/// than accumulated.
const MAX_TOOL_CALLS: usize = 32;

/// The bound on one tool call's accumulated `arguments` text — the
/// fragments concatenate into a JSON object the wire bound already
/// sized, so a dribbling argument stream is denied, never buffered
/// unbounded.
const MAX_TOOL_ARGS_BYTES: usize = 1024 * 1024;

/// The recorded static seed of `aiand` model ids (HZN-008,
/// `AIAND_STATIC_MODELS`): the merge floor the catalogue unions over
/// the authoritative org-scoped `/models` listing — a seeded id
/// offers even when the listing omits it. The recorded source seeded
/// them so generation and first boot could offer models with no live
/// key; that rationale stays upstream's — this adapter resolves a
/// credential before any catalogue call, so the seed's role here is
/// the offer floor, never a keyless offer path, and it carries ids
/// only: the listing alone states a model's metadata.
const AIAND_MODELS: &[&str] = &[
    "qwen/qwen3.6-27b",
    "deepseek-ai/deepseek-v4-flash",
    "google/gemma-4-31b-it",
    "openai/gpt-oss-120b",
    "deepseek-ai/deepseek-v4-pro",
    "moonshotai/kimi-k2.7-code",
    "moonshotai/kimi-k2.6",
    "zai-org/glm-5.2",
    "zai-org/glm-5.1",
];

/// The recorded default API root of an `aiand` connection
/// (`AIAND_DEFAULT_BASE_URL`): the host an absent or empty configured
/// endpoint resolves to under the recorded base normalization.
const AIAND_DEFAULT_BASE_URL: &str = "https://api.aiand.com/v1";

/// The recorded per-entry transform a `data[]` listing runs
/// (HZN-008): the generic class carries model ids only, while
/// `aiand`'s org-scoped listing applies the recorded
/// capability/effort/currency map (`mapAiandModel`).
enum EntryRule {
    /// Every non-empty `id` verbatim — the generic class records no
    /// per-model metadata surface.
    IdsOnly,
    /// The org-scoped `aiand` transform: `capabilities` names the
    /// reasoning and image-input surface, `reasoning_efforts` maps
    /// onto the effort ladder, and the org's billing currency decides
    /// whether the stated per-1M-token price lands.
    Aiand,
}

/// The predicates the recorded source class binds to a literal Chat
/// Completions id (HZN-008): the dialect is shared across connection
/// ids — the endpoint rule, the catalogue seed and the per-entry
/// transform are not.
struct SourceContract {
    /// The recorded static-seed model ids merging into the listing as
    /// the offer floor — empty where the class records no seed.
    seed: &'static [&'static str],
    /// `true` — the configured endpoint normalizes onto the recorded
    /// `/v1` API root (`aiand`'s `normalizeAiandBaseUrl`: a bare
    /// configured base gains the `/v1` tail, an empty one resolves to
    /// the recorded default host); `false` — the configured origin is
    /// the API base verbatim, trailing slashes trimmed
    /// (`custom-chat-completions` binds egress to the configured
    /// origin and records no fixed host).
    normalized_v1_root: bool,
    /// The recorded per-entry transform over `data[]` entries.
    entries: EntryRule,
}

/// The recorded per-connection contract for a Chat Completions id
/// (DEC-007/DEC-025): `build` denies every id without the recorded
/// Chat Completions class before this lookup runs, and an id the
/// dialect map admits but this table does not name resolves `None` —
/// denied the same way. A further Chat Completions id records its own
/// predicates as a named arm here, never inherits another's.
fn contract_for(connection: &str) -> Option<SourceContract> {
    match connection {
        "custom-chat-completions" => Some(SourceContract {
            seed: &[],
            normalized_v1_root: false,
            entries: EntryRule::IdsOnly,
        }),
        "aiand" => Some(SourceContract {
            seed: AIAND_MODELS,
            normalized_v1_root: true,
            entries: EntryRule::Aiand,
        }),
        _ => None,
    }
}

impl SourceContract {
    /// The connection's API root under the recorded endpoint rule:
    /// egress stays bound to the configured endpoint — the `aiand`
    /// normalization only supplies the `/v1` tail a configured base
    /// lacks, and the recorded default host for an empty one.
    fn endpoint(&self, configured: &str) -> String {
        if !self.normalized_v1_root {
            return configured.trim_end_matches('/').to_string();
        }
        let trimmed = configured.trim();
        if trimmed.is_empty() {
            return AIAND_DEFAULT_BASE_URL.to_string();
        }
        let base = trimmed.trim_end_matches('/');
        if base.ends_with("/v1") {
            base.to_string()
        } else {
            format!("{base}/v1")
        }
    }
}

/// The stated price a catalogued model carries (HZN-008): the literal
/// id's recorded currency rule decides — `Unknown` is a carried
/// state, never a coerced zero and never a silent USD default.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum ModelPrice {
    /// The listing named an unrecognized or no billing currency — the
    /// price stays unknown rather than releasing as a zero.
    #[default]
    Unknown,
    /// The entry's stated USD figures per 1M tokens — a stated zero
    /// is a real figure (a free model), never the unknown state.
    Usd {
        /// The stated input-token price per 1M.
        input_per_1m: f64,
        /// The stated output-token price per 1M.
        output_per_1m: f64,
    },
}

/// One catalogued model a Chat Completions connection offers
/// (HZN-008): `id` is the wire name — the request body's `model`,
/// never URL material. The remaining fields carry the literal id's
/// recorded per-entry transform; a class recording none keeps every
/// one at its empty or unknown surface.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct CatalogModel {
    /// The model id the wire request names.
    pub id: String,
    /// The listing's declared reasoning capability; `false` where the
    /// class records no capability surface.
    pub reasoning: bool,
    /// The listing's declared image-input capability.
    pub vision: bool,
    /// The reasoning-effort levels the listing declared, in wire
    /// order — wire values our effort enum cannot name never land.
    pub efforts: Vec<EffortLevel>,
    /// The listing's declared default effort — carried only when it
    /// is itself a declared level.
    pub effort_default: Option<EffortLevel>,
    /// The listing's declared context window in tokens.
    pub context_window: Option<u64>,
    /// The listing's stated per-1M-token price under the recorded
    /// currency rule.
    pub price: ModelPrice,
}

/// The terminal classification one finished stream reduces to: a
/// recorded completion `finish_reason`, the peer's own failure
/// verdict, or a reason the dialect cannot classify.
enum Terminal {
    Completed,
    Failed { reason: String },
    Unclassifiable,
}

/// One in-flight streamed tool call: fragments of a single
/// `choices[].delta.tool_calls[]` entry accumulate here until the
/// stream's terminal. `id` and `index` are the recorded correlation
/// keys — `id` is set once like `name`, and additionally unique
/// across blocks — and `args` is the arguments text still being
/// concatenated.
#[derive(Default)]
struct ToolBlock {
    id: Option<String>,
    name: Option<String>,
    args: String,
}

/// Per-stream accounting: the visible answer text, the in-flight
/// tool-call blocks with their stream-index routing table, the last
/// usage report the stream carried, the declared terminal, and the
/// `[DONE]` sentinel — a stream that ends without a finish_reason
/// but closed on `[DONE]` is the recorded server-agreed stop; one
/// that ends with neither is the unknown terminal.
#[derive(Default)]
struct StreamState {
    text: String,
    blocks: Vec<ToolBlock>,
    block_by_index: HashMap<u64, usize>,
    usage: Option<Value>,
    terminal: Option<Terminal>,
    done: bool,
}

/// The shared Chat Completions adapter — `custom-chat-completions`
/// and `aiand` alike (DEC-007). Constructed per connection from the
/// validated config; the broker owns the handle — workers never hold
/// one.
pub struct ChatCompletionsProvider {
    /// The literal connection id this adapter serves — the dialect
    /// key, not a label.
    connection: String,
    /// The recorded per-connection predicates (HZN-008): resolved
    /// from the literal id at build and never re-keyed — the dialect
    /// is shared, the contract is not.
    contract: SourceContract,
    /// The configured endpoint base under the literal id's recorded
    /// endpoint rule — the API root including its version segment
    /// (`/v1`).
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
}

impl ChatCompletionsProvider {
    /// Builds the adapter for one connection id: the id must record
    /// the Chat Completions dialect (DEC-007) and name a recorded
    /// per-connection contract (HZN-008), the connection must be
    /// declared, carry no configured region — neither recorded class
    /// has one — and resolve a scoped credential under DEC-013
    /// precedence.
    ///
    /// # Errors
    /// [`ProviderError::DialectMismatch`] for a connection id without
    /// the Chat Completions source class or its own contract arm;
    /// [`ProviderError::UnknownConnection`] for an undeclared id;
    /// [`ProviderError::RegionMismatch`] for a configured region;
    /// [`resolve_credential`]'s typed denials for a missing, malformed
    /// or mismatched binding; [`ProviderError::Transport`] when the
    /// HTTP client cannot be built.
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
        if dialect_for(connection) != Some(Dialect::ChatCompletions) {
            return Err(ProviderError::DialectMismatch {
                connection: connection.to_string(),
            });
        }
        // A Chat-Completions-classed id without its own recorded
        // contract arm is denied the same way — the predicates are
        // recorded per literal id, never inherited silently.
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
            .map_err(|err| ProviderError::Transport {
                connection: connection.to_string(),
                reason: err.without_url().to_string(),
            })?;
        Ok(Self {
            connection: connection.to_string(),
            endpoint: contract.endpoint(&conn.endpoint),
            contract,
            credential,
            store,
            client,
            deadline,
        })
    }

    /// The model catalogue for this connection (HZN-008): the
    /// configured endpoint's own `models` listing under the literal
    /// id's recorded contract — every non-empty `data[].id` is an
    /// offered model under its per-entry transform, the recorded
    /// static seed merges on top as the offer floor, and the union
    /// returns in deterministic sorted order. The generic class
    /// admits the listing verbatim: gateway-style ids carry path
    /// characters legitimately, since a model id is never URL
    /// material in this dialect — it rides the request body.
    ///
    /// # Errors
    /// The credential seam's typed denials, [`ProviderError::Transport`]
    /// on a failed call or non-success status or an expired whole-call
    /// budget, and [`ProviderError::StreamViolation`] when the payload
    /// does not carry the `data` array the contract requires.
    pub fn catalog(&self) -> Result<Vec<CatalogModel>, ProviderError> {
        // A standalone lookup opens its own whole-call budget — the
        // credential resolution and the wire leg share it, the same
        // bound a send's catalogue leg rides.
        let started = Instant::now();
        let token = self.secret()?;
        self.catalog_within(&token, started)
    }

    /// The catalogue leg under the caller's clock and credential —
    /// a send passes its own `started` so the lookup spends the same
    /// whole-request budget instead of opening a second, unaccounted
    /// one.
    fn catalog_within(
        &self,
        token: &str,
        started: Instant,
    ) -> Result<Vec<CatalogModel>, ProviderError> {
        self.check_deadline(started)?;
        let mut response = self
            .client
            .get(format!("{}/models", self.endpoint))
            .bearer_auth(token)
            .send()
            .map_err(|err| self.transport(err))?;
        if !response.status().is_success() {
            return Err(self.transport_status(response.status()));
        }
        // The listing reads under the same whole-request budget and a
        // byte bound — a dribbling or oversized payload is denied,
        // never parked or buffered unbounded.
        let mut body = Vec::new();
        let mut chunk = vec![0u8; STREAM_CHUNK_BYTES];
        loop {
            let read = self.read_chunk(&mut response, &mut chunk, started)?;
            if read == 0 {
                break;
            }
            if body.len() + read > CATALOG_MAX_BYTES {
                return Err(self.violation("models payload exceeds the byte bound"));
            }
            body.extend_from_slice(&chunk[..read]);
        }
        let body: Value = serde_json::from_slice(&body)
            .map_err(|_parse| self.violation("models payload is not json"))?;
        let Some(data) = body.get("data").and_then(Value::as_array) else {
            return Err(self.violation("models payload carries no data array"));
        };
        // Every listed `id` is an offer under the literal id's
        // recorded per-entry transform — an empty or absent one can
        // never name a model.
        let mut models: Vec<CatalogModel> = data
            .iter()
            .filter_map(|entry| self.catalog_entry(entry))
            .collect();
        // The recorded seed unions on top as the offer floor — a
        // seeded id the listing omitted still offers, carrying the
        // empty transform surface: the seed never states metadata the
        // listing did not. Listed entries precede the stubs, so the
        // stable sort keeps a listing entry's transform over its
        // seed stub on a collision.
        models.extend(self.contract.seed.iter().map(|id| CatalogModel {
            id: (*id).to_string(),
            ..CatalogModel::default()
        }));
        models.sort_by(|a, b| a.id.cmp(&b.id));
        models.dedup_by(|a, b| a.id == b.id);
        Ok(models)
    }

    /// One `data[]` entry under the literal id's recorded transform —
    /// `None` when the entry names no usable id: an empty or absent
    /// id can never name a model.
    fn catalog_entry(&self, entry: &Value) -> Option<CatalogModel> {
        let id = entry
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())?;
        Some(match self.contract.entries {
            EntryRule::IdsOnly => CatalogModel {
                id: id.to_string(),
                ..CatalogModel::default()
            },
            EntryRule::Aiand => aiand_entry(id, entry),
        })
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

    /// The frozen manifest as the Chat Completions wire request:
    /// `model`, `messages` — the instructions as the `system` message
    /// when they carry text, the inputs as `user` — `stream` with the
    /// recorded `stream_options.include_usage`, the declared tool
    /// surface as function tools, and the pinned effort as
    /// `reasoning_effort` verbatim. The manifest's frozen effort is
    /// the only capability surface: nothing else — no sampling
    /// knobs, no provider options — is invented.
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
            "stream_options": { "include_usage": true },
        });
        if let EffortAssign::Fixed { value } = &manifest.effort {
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
        body
    }

    /// The whole-request budget check (DEC-014): evaluated before
    /// the post, before every stream read and before the final pass,
    /// so connect, request send, reads and finalization share one
    /// deadline — a peer dribbling a byte inside each per-read window
    /// parks the stream only until the total budget is spent.
    fn check_deadline(&self, started: Instant) -> Result<(), ProviderError> {
        if started.elapsed() >= self.deadline {
            return Err(ProviderError::Transport {
                connection: self.connection.clone(),
                reason: format!("request exceeded the {:?} send deadline", self.deadline),
            });
        }
        Ok(())
    }

    /// One bounded read under the shared deadline: the check runs
    /// before the call, `Interrupted` retries in place, and any other
    /// read failure is the typed transport error. Returns the bytes
    /// read — `0` is the stream's end.
    fn read_chunk(
        &self,
        response: &mut reqwest::blocking::Response,
        chunk: &mut [u8],
        started: Instant,
    ) -> Result<usize, ProviderError> {
        loop {
            self.check_deadline(started)?;
            match response.read(chunk) {
                Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(err) => return Err(self.transport_io(err)),
                Ok(read) => return Ok(read),
            }
        }
    }

    /// Reads the SSE body through the shared bounded parser and
    /// reduces it to the one terminal the dialect can classify. A
    /// stream that ends on `[DONE]` alone is the recorded
    /// server-agreed stop; one that ends with neither a finish_reason
    /// nor the sentinel, or with a reason the dialect cannot
    /// classify, is never success.
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
            let read = self.read_chunk(&mut response, &mut chunk, started)?;
            if read == 0 {
                break;
            }
            for event in parser.feed(&chunk[..read]).map_err(|err| self.sse(err))? {
                self.on_chunk(&mut state, event)?;
            }
        }
        // Finalization shares the budget — the stream's total cost is
        // bounded even when its last byte lands just inside it.
        self.check_deadline(started)?;
        for event in parser.finish().map_err(|err| self.sse(err))? {
            self.on_chunk(&mut state, event)?;
        }
        match state.terminal {
            Some(Terminal::Completed) => self.complete(manifest, state),
            Some(Terminal::Failed { reason }) => Err(ProviderError::ProviderFailed {
                connection: self.connection.clone(),
                reason,
            }),
            Some(Terminal::Unclassifiable) => Err(ProviderError::UnknownTerminal {
                connection: self.connection.clone(),
            }),
            // The recorded contract treats `[DONE]` alone as the
            // server-agreed close — compatible hosts that never send a
            // finish_reason rely on it. EOF with neither stays unknown.
            None if state.done => self.complete(manifest, state),
            None => Err(ProviderError::UnknownTerminal {
                connection: self.connection.clone(),
            }),
        }
    }

    /// Classifies one dispatched SSE event as a `chat.completion.chunk`.
    /// The `[DONE]` sentinel is the server-agreed close — exactly one
    /// may arrive, and nothing may follow it. An `error` member or the
    /// flat `{"message": "…"}` shape some hosts send is the peer's own
    /// failure verdict. `choices[0]` carries the delta and the
    /// `finish_reason`; the request never asks for more than one
    /// candidate, so a second choice or a nonzero index is off-contract.
    /// A choice after the declared terminal adopts nothing — only the
    /// recorded `choices:[]` usage tail may follow it.
    fn on_chunk(&self, state: &mut StreamState, event: SseEvent) -> Result<(), ProviderError> {
        if event.data == "[DONE]" {
            if state.done {
                return Err(self.violation("stream carried a duplicate [DONE] sentinel"));
            }
            state.done = true;
            return Ok(());
        }
        if state.done {
            return Err(self.violation("stream carried content after the [DONE] sentinel"));
        }
        let chunk: Value = serde_json::from_str(&event.data)
            .map_err(|_parse| self.violation("stream chunk is not json"))?;
        if !chunk.is_object() {
            return Err(self.violation("stream chunk is not an object"));
        }
        if let Some(error) = chunk.get("error").filter(|error| !is_falsy(error)) {
            let reason = match error {
                Value::String(reason) => reason.clone(),
                Value::Object(_) => payload_reason(error),
                _ => return Err(self.violation("stream chunk error is not an object or string")),
            };
            return self.set_terminal(state, Terminal::Failed { reason });
        }
        if let Some(message) = chunk.get("message").filter(|message| !is_falsy(message)) {
            let Some(reason) = message.as_str() else {
                return Err(self.violation("stream chunk message is not a string"));
            };
            return self.set_terminal(
                state,
                Terminal::Failed {
                    reason: reason.to_string(),
                },
            );
        }
        let choice =
            match chunk.get("choices") {
                None => None,
                Some(choices) => {
                    let Some(list) = choices.as_array() else {
                        return Err(self.violation("stream chunk choices is not an array"));
                    };
                    // The request never asks for more than one candidate,
                    // so a second choice is off-contract input — never a
                    // silent first-pick of divergent content.
                    if list.len() > 1 {
                        return Err(self.violation("stream chunk carried more than one choice"));
                    }
                    match list.first() {
                        None => None,
                        Some(choice) => {
                            if !choice.is_object() {
                                return Err(self.violation("stream chunk choice is not an object"));
                            }
                            // A choice after the declared terminal adopts
                            // nothing: the verdict closed the turn, and
                            // only the usage tail and `[DONE]` may follow.
                            if state.terminal.is_some() {
                                return Err(
                                    self.violation("stream carried a choice after its terminal")
                                );
                            }
                            if let Some(index) = choice.get("index") {
                                // The single requested slot is index 0;
                                // any other belongs to a candidate the
                                // request never asked for.
                                if index.as_u64() != Some(0) {
                                    return Err(self
                                        .violation("stream chunk choice carries a nonzero index"));
                                }
                            }
                            if choice
                                .get("message")
                                .is_some_and(|message| !message.is_null())
                            {
                                // A `message` member is the non-streamed
                                // response shape — this stream carries
                                // deltas only.
                                return Err(self
                                    .violation("stream chunk choice carries a non-delta message"));
                            }
                            Some(choice)
                        }
                    }
                }
            };
        if let Some(choice) = choice {
            self.on_delta(state, choice)?;
            if let Some(reason) = choice.get("finish_reason") {
                let terminal = match reason {
                    // A null reason is a non-terminal chunk — the
                    // field exists on every streamed choice.
                    Value::Null => None,
                    Value::String(reason) => {
                        Some(match reason.to_ascii_lowercase().as_str() {
                            "stop" | "end" | "length" | "max_tokens" | "function_call"
                            | "tool_calls" => Terminal::Completed,
                            // The recorded failure reasons — the peer's
                            // own verdict, never success even when
                            // earlier chunks carried valid tool calls.
                            "content_filter"
                            | "network_error"
                            | "error"
                            | "insufficient_system_resource" => Terminal::Failed {
                                reason: format!("generation failed with finish reason {reason}"),
                            },
                            _ => Terminal::Unclassifiable,
                        })
                    }
                    _ => return Err(self.violation("choice finish_reason is not a string")),
                };
                if let Some(terminal) = terminal {
                    self.set_terminal(state, terminal)?;
                }
            }
        }
        // `stream_options.include_usage` lands the physical report on
        // the trailing `choices:[]` chunk; a choice-level `usage`
        // member is the same surface on hosts that report per choice.
        // The last report the stream carried is authoritative.
        if let Some(usage) = chunk
            .get("usage")
            .or_else(|| choice.and_then(|choice| choice.get("usage")))
            .filter(|usage| !usage.is_null())
        {
            state.usage = Some(usage.clone());
        }
        Ok(())
    }

    /// Validates one choice's `delta` and folds it into the stream's
    /// state. `content` fragments join the visible answer;
    /// `reasoning_content`/`reasoning`/`reasoning_text` and `refusal`
    /// are consumed as progress but never join it; `reasoning_details`
    /// is the recorded opaque artifact member this dialect has no
    /// replay contract for — observed, never adopted. `tool_calls`
    /// entries accumulate into their routed block.
    fn on_delta(&self, state: &mut StreamState, choice: &Value) -> Result<(), ProviderError> {
        let Some(delta) = choice.get("delta").filter(|delta| !delta.is_null()) else {
            return Ok(());
        };
        let Some(delta) = delta.as_object() else {
            return Err(self.violation("choice delta is not an object"));
        };
        if let Some(role) = delta.get("role") {
            match role {
                Value::String(_) | Value::Null => {}
                _ => return Err(self.violation("delta role is not a string")),
            }
        }
        if let Some(content) = delta.get("content") {
            match content {
                Value::String(text) => state.text.push_str(text),
                Value::Null => {}
                _ => return Err(self.violation("delta content is not a string")),
            }
        }
        if let Some(refusal) = delta.get("refusal") {
            match refusal {
                Value::String(_) | Value::Null => {}
                _ => return Err(self.violation("delta refusal is not a string")),
            }
        }
        for key in ["reasoning_content", "reasoning", "reasoning_text"] {
            if let Some(reasoning) = delta.get(key) {
                match reasoning {
                    Value::String(_) | Value::Null => {}
                    _ => return Err(self.violation("delta reasoning is not a string")),
                }
            }
        }
        if let Some(details) = delta.get("reasoning_details")
            && !details.is_array()
            && !details.is_null()
        {
            return Err(self.violation("delta reasoning_details is not an array"));
        }
        if let Some(calls) = delta.get("tool_calls") {
            let Some(calls) = calls.as_array() else {
                return Err(self.violation("delta tool_calls is not an array"));
            };
            for entry in calls {
                self.on_tool_call_entry(state, entry, calls.len() > 1)?;
            }
        }
        Ok(())
    }

    /// Routes one `tool_calls` entry to its block — the stream `index`
    /// wins, then a pending block's `id`, and only a single-entry
    /// delta may continue the last-opened block: an unkeyed entry
    /// inside a multi-call batch cannot be attributed to a sibling.
    /// The block's `id` and function `name` are each set once — a
    /// second, different value on the same block, or an id a sibling
    /// block already holds, is a malformed stream — and `arguments`
    /// fragments concatenate under the byte bound.
    fn on_tool_call_entry(
        &self,
        state: &mut StreamState,
        entry: &Value,
        batched: bool,
    ) -> Result<(), ProviderError> {
        let Some(entry) = entry.as_object() else {
            return Err(self.violation("tool_calls entry is not an object"));
        };
        let index = match entry.get("index") {
            None => None,
            Some(index) => match index.as_u64() {
                Some(index) => Some(index),
                None => return Err(self.violation("tool_calls entry index is not an integer")),
            },
        };
        let id = match entry.get("id") {
            None | Some(Value::Null) => None,
            // An empty id is no correlation key — the recorded
            // contract treats a falsy id as absent.
            Some(Value::String(id)) if !id.is_empty() => Some(id.clone()),
            Some(Value::String(_)) => None,
            Some(_) => return Err(self.violation("tool_calls entry id is not a string")),
        };
        let position = if let Some(index) = index {
            match state.block_by_index.get(&index) {
                Some(&position) => position,
                None => {
                    let position = state.blocks.len();
                    state.blocks.push(ToolBlock::default());
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
                    state.blocks.push(ToolBlock {
                        id: Some(id.clone()),
                        ..ToolBlock::default()
                    });
                    state.blocks.len() - 1
                }
            }
        } else if batched {
            return Err(self.violation("a tool_calls entry without index or id cannot be routed"));
        } else if state.blocks.is_empty() {
            state.blocks.push(ToolBlock::default());
            0
        } else {
            state.blocks.len() - 1
        };
        if state.blocks.len() > MAX_TOOL_CALLS {
            return Err(self.violation("stream carried more tool calls than the bound"));
        }
        match entry.get("type") {
            None | Some(Value::Null) => {}
            Some(Value::String(kind)) if kind == "function" => {}
            // A tool call kind outside the recorded `function` shape is
            // output the dialect cannot honour, never executed.
            Some(Value::String(_)) => {
                return Err(ProviderError::IncompatibleOutput {
                    connection: self.connection.clone(),
                    reason: "a streamed tool call is not a function call".to_string(),
                });
            }
            Some(_) => return Err(self.violation("tool_calls entry type is not a string")),
        }
        // The block's id is set once like its name — a second,
        // different id re-keys a routed block, and an id a sibling
        // block already holds would make an id-only continuation's
        // routing ambiguous: both are malformed, never silently
        // re-keyed.
        if let Some(id) = id {
            match &state.blocks[position].id {
                Some(existing) if existing != &id => {
                    return Err(self.violation("a tool_call block's id changed mid-stream"));
                }
                Some(_) => {}
                None => {
                    if state.blocks.iter().enumerate().any(|(at, block)| {
                        at != position && block.id.as_deref() == Some(id.as_str())
                    }) {
                        return Err(self.violation("two tool_call blocks carry the same id"));
                    }
                    state.blocks[position].id = Some(id);
                }
            }
        }
        if let Some(function) = entry.get("function") {
            let Some(function) = function.as_object() else {
                return Err(self.violation("tool_calls entry function is not an object"));
            };
            if let Some(name) = function.get("name") {
                match name {
                    Value::String(name) if !name.is_empty() => match &state.blocks[position].name {
                        Some(existing) if existing != name => {
                            return Err(self.violation(
                                "a tool_call block's function name changed mid-stream",
                            ));
                        }
                        Some(_) => {}
                        None => state.blocks[position].name = Some(name.clone()),
                    },
                    Value::String(_) | Value::Null => {}
                    _ => return Err(self.violation("tool_call function name is not a string")),
                }
            }
            if let Some(arguments) = function.get("arguments") {
                match arguments {
                    Value::String(piece) => {
                        let block = &mut state.blocks[position];
                        if block.args.len() + piece.len() > MAX_TOOL_ARGS_BYTES {
                            return Err(
                                self.violation("a tool_call's arguments exceed the byte bound")
                            );
                        }
                        block.args.push_str(piece);
                    }
                    Value::Null => {}
                    _ => {
                        return Err(
                            self.violation("a tool_call's arguments are not a streamed string")
                        );
                    }
                }
            }
        }
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
            return Err(self.violation("stream carried a duplicate terminal"));
        }
        state.terminal = Some(terminal);
        Ok(())
    }

    /// Finalizes a completed stream: the accumulated arguments parse
    /// into the typed calls — a block that never carried a name, a
    /// name the frozen request never declared, or arguments that never
    /// parse into an object are all typed rejections, never executed
    /// — and the last usage report becomes the physical charge.
    fn complete(
        &self,
        manifest: &RequestManifest,
        state: StreamState,
    ) -> Result<ProviderReply, ProviderError> {
        let usage = self.usage_of(&state)?;
        let mut tool_calls = Vec::with_capacity(state.blocks.len());
        for block in state.blocks {
            let Some(name) = block.name.filter(|name| !name.is_empty()) else {
                return Err(self.violation("a tool_call block never carried a function name"));
            };
            if !manifest.tools.iter().any(|declared| declared == &name) {
                return Err(ProviderError::IncompatibleOutput {
                    connection: self.connection.clone(),
                    reason: format!("tool_call names undeclared tool {name}"),
                });
            }
            let path = if block.args.is_empty() {
                None
            } else {
                let args: Value = serde_json::from_str(&block.args)
                    .map_err(|_parse| self.violation("a tool_call's arguments did not parse"))?;
                let Some(args) = args.as_object() else {
                    return Err(self.violation("a tool_call's arguments are not an object"));
                };
                args.get("path").and_then(Value::as_str).map(str::to_string)
            };
            tool_calls.push(ToolCall { tool: name, path });
        }
        Ok(ProviderReply {
            text: state.text,
            tool_calls,
            usage,
        })
    }

    /// The physical usage the stream reported: an absent `usage`
    /// stays [`UsageDelta::Unknown`] — never an estimate, never a zero
    /// the accounting could release; a present-but-unreadable shape is
    /// a wire violation.
    fn usage_of(&self, state: &StreamState) -> Result<UsageDelta, ProviderError> {
        let Some(usage) = &state.usage else {
            return Ok(UsageDelta::Unknown);
        };
        let prompt = usage.get("prompt_tokens").and_then(Value::as_u64);
        let completion = usage.get("completion_tokens").and_then(Value::as_u64);
        let total = usage.get("total_tokens").and_then(Value::as_u64);
        match (prompt, completion, total) {
            // The reported total is charged verbatim — never re-summed
            // — and a usage object that withholds a counter is a wire
            // violation, not an estimate the peer never charged.
            (Some(prompt_tokens), Some(completion_tokens), Some(total_tokens)) => {
                Ok(UsageDelta::Exact {
                    prompt_tokens,
                    completion_tokens,
                    total_tokens,
                })
            }
            _ => Err(self.violation("usage is not a readable token shape")),
        }
    }

    fn transport(&self, err: reqwest::Error) -> ProviderError {
        ProviderError::Transport {
            connection: self.connection.clone(),
            reason: err.without_url().to_string(),
        }
    }

    fn transport_io(&self, err: std::io::Error) -> ProviderError {
        ProviderError::Transport {
            connection: self.connection.clone(),
            reason: err.to_string(),
        }
    }

    /// A non-success status is reported by code alone — the response
    /// body is uncontrolled peer text and never enters diagnostics.
    fn transport_status(&self, status: reqwest::StatusCode) -> ProviderError {
        ProviderError::Transport {
            connection: self.connection.clone(),
            reason: format!("status {}", status.as_u16()),
        }
    }

    fn sse(&self, err: SseError) -> ProviderError {
        ProviderError::StreamViolation {
            connection: self.connection.clone(),
            reason: err.to_string(),
        }
    }

    fn violation(&self, reason: impl Into<String>) -> ProviderError {
        ProviderError::StreamViolation {
            connection: self.connection.clone(),
            reason: reason.into(),
        }
    }
}

/// JavaScript-truthiness for the recorded `if (data.error)` /
/// `if (data.message)` guards: `null`, `false`, `0` and `""` carry no
/// verdict.
fn is_falsy(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Bool(b) => !b,
        Value::Number(n) => n.as_f64() == Some(0.0),
        Value::String(s) => s.is_empty(),
        Value::Array(_) | Value::Object(_) => false,
    }
}

/// The reason a failed verdict carries — the peer's own `message`,
/// `status` or `code` field, whichever it populated. Strings render
/// verbatim and scalar numbers/booleans still read; a nested object or
/// array is structure, not prose, and is never serialized into the
/// reason.
fn payload_reason(payload: &Value) -> String {
    for field in ["message", "status", "code"] {
        match payload.get(field) {
            Some(Value::String(text)) => return text.clone(),
            Some(scalar @ (Value::Number(_) | Value::Bool(_))) => return scalar.to_string(),
            _ => {}
        }
    }
    "unclassified".to_string()
}

/// The recorded `aiand` effort wire value
/// (`AIAND_EFFORT_BY_WIRE_VALUE`), restricted to the levels our
/// effort enum names — the recorded `max` has no landing level and
/// never maps onto a lower one.
fn aiand_effort(value: &str) -> Option<EffortLevel> {
    match value {
        "minimal" => Some(EffortLevel::Minimal),
        "low" => Some(EffortLevel::Low),
        "medium" => Some(EffortLevel::Medium),
        "high" => Some(EffortLevel::High),
        "xhigh" => Some(EffortLevel::Xhigh),
        _ => None,
    }
}

/// `toPositiveNumber(_, null)`: a positive whole count or its decimal
/// string reads; anything else — a stated zero included — is absent.
fn positive_count(value: Option<&Value>) -> Option<u64> {
    value
        .and_then(|value| {
            value
                .as_u64()
                .or_else(|| value.as_str().and_then(|text| text.parse::<u64>().ok()))
        })
        .filter(|count| *count > 0)
}

/// `toPositiveNumber(_, 0)` inside a `usd` entry: a finite
/// non-negative number or its decimal string is the stated figure —
/// a stated zero is a real figure, a free model's price — anything
/// else reads as the recorded zero fallback.
fn stated_price(value: Option<&Value>) -> f64 {
    value
        .and_then(|value| {
            value
                .as_f64()
                .or_else(|| value.as_str().and_then(|text| text.parse::<f64>().ok()))
        })
        .filter(|number| number.is_finite() && *number >= 0.0)
        .unwrap_or(0.0)
}

/// The recorded `aiand` currency rule (`mapAiandCost`): the org's
/// billing currency decides whether a stated price lands — only a
/// `usd` entry's figures carry onto the surface, while every other
/// currency, a missing member or an unreadable shape stays
/// [`ModelPrice::Unknown`]: never coerced to a zero the accounting
/// could release, never defaulted to USD.
fn aiand_price(entry: &Value) -> ModelPrice {
    if entry.get("currency").and_then(Value::as_str) != Some("usd") {
        return ModelPrice::Unknown;
    }
    ModelPrice::Usd {
        input_per_1m: stated_price(entry.get("input_per_1m")),
        output_per_1m: stated_price(entry.get("output_per_1m")),
    }
}

/// The recorded `aiand` entry transform (`mapAiandModel` /
/// `mapAiandThinking`): `capabilities` names the reasoning and
/// image-input surface; only a reasoning entry's `reasoning_efforts`
/// maps onto the effort ladder, unmappable wire values dropped, the
/// declared default landing only as a declared level; the currency
/// rule decides the price.
fn aiand_entry(id: &str, entry: &Value) -> CatalogModel {
    let capabilities = entry.get("capabilities").and_then(Value::as_array);
    let capability = |name: &str| {
        capabilities.is_some_and(|list| list.iter().any(|member| member.as_str() == Some(name)))
    };
    let reasoning = capability("reasoning");
    let efforts: Vec<EffortLevel> = if reasoning {
        entry
            .get("reasoning_efforts")
            .and_then(Value::as_array)
            .map(|list| {
                list.iter()
                    .filter_map(Value::as_str)
                    .filter_map(aiand_effort)
                    .collect()
            })
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    let effort_default = entry
        .get("reasoning_effort_default")
        .and_then(Value::as_str)
        .and_then(aiand_effort)
        .filter(|default| reasoning && efforts.contains(default));
    CatalogModel {
        id: id.to_string(),
        reasoning,
        vision: capability("vision"),
        efforts,
        effort_default,
        context_window: positive_count(entry.get("context_window")),
        price: aiand_price(entry),
    }
}

impl std::fmt::Debug for ChatCompletionsProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The scoped ref is the visible token — the store and its
        // material never enter diagnostics (INV-001).
        f.debug_struct("ChatCompletionsProvider")
            .field("connection", &self.connection)
            .field("endpoint", &self.endpoint)
            .field("credential", &self.credential)
            .field("deadline", &self.deadline)
            .finish_non_exhaustive()
    }
}

impl Provider for ChatCompletionsProvider {
    fn name(&self) -> &'static str {
        "openai-chat-completions"
    }

    /// The adapter serves only the literal connection id its dialect
    /// was constructed for (DEC-007) — a pin to any other id is a
    /// dialect it does not speak.
    fn serves(&self, connection: &str, _entry: &Connection) -> bool {
        connection == self.connection
    }

    /// Sends the frozen manifest as one physical Chat Completions
    /// request.
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
        // auto-pool catalogue leg, and the streamed response all count
        // against the same clock — no leg runs past the deadline the
        // caller was promised.
        let started = Instant::now();
        // The credential resolves once per send — the catalogue leg and
        // the post both bear the same material, so a rotation mid-send
        // can never split one request across two secrets.
        let token = self.secret()?;
        // A fixed pin names connection and model verbatim. A
        // single-member auto pool naming this connection is an
        // explicit pick of it — the pick pins the connection, and the
        // catalogue names the model: the deterministic sorted-first id
        // of the listing, the recorded auto semantic of resolving the
        // model at catalogue time. Any other assignment is a model
        // this adapter cannot pin.
        let fixed = match &manifest.model {
            ModelAssign::Fixed(fixed) => fixed.clone(),
            ModelAssign::Auto { pool: Some(pool) }
                if pool.len() == 1 && pool[0] == self.connection =>
            {
                let model_id = self
                    .catalog_within(&token, started)?
                    .into_iter()
                    .next()
                    .map(|model| model.id)
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
        // The serialized body is what crosses the wire: the same byte
        // bound the manifest's accounted size promised is enforced on
        // the actual bytes — oversized, never truncated (AC-013).
        let body_bytes = serde_json::to_vec(&body)
            .map_err(|_ser| self.violation("request body could not serialize"))?;
        if body_bytes.len() > crate::contracts::MODEL_WIRE_MAX_BYTES {
            return Err(ProviderError::StreamViolation {
                connection: self.connection.clone(),
                reason: format!(
                    "request body of {} bytes exceeds the {} byte wire bound",
                    body_bytes.len(),
                    crate::contracts::MODEL_WIRE_MAX_BYTES
                ),
            });
        }
        // The wire leg is the last budget check: a resolve or
        // catalogue leg that spent the clock fails the send typed
        // here — an expired budget never puts a byte on the wire.
        self.check_deadline(started)?;
        let response = self
            .client
            .post(format!("{}/chat/completions", self.endpoint))
            .bearer_auth(&token)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::ACCEPT, "text/event-stream")
            .body(body_bytes)
            .send()
            .map_err(|err| self.transport(err))?;
        if !response.status().is_success() {
            return Err(self.transport_status(response.status()));
        }
        self.read_stream(manifest, response, started)
    }
}
