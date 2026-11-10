//! Z.AI GLM Coding Plan inference (AC-040/AC-046): one literal adapter for
//! the `zai` provider row and its `zai-coding-plan` sign-in alias, over the
//! canonical `zai` profile [`super::zai_login`] produces.
//!
//! The recorded contract is OMP's bundled `zai` catalogue (`models.json`,
//! `0133f7ff`): most rows ride the Anthropic-compatible Messages transport on
//! `https://api.z.ai/api/anthropic`, and `glm-5.3-flash` rides the native
//! OpenAI-completions transport on
//! `https://api.z.ai/api/coding/paas/v4`. The configured endpoint binds the
//! connection to one of those recorded bases (or to the recorded origin,
//! which selects the base by model) and a loopback base is the offline proof
//! override; the PAYG base `https://api.z.ai/api/paas/v4` is never admitted
//! or substituted. A configured region denies typed: the record states none.
//!
//! The Messages leg is the shared `MessagesCodec`: its thinking lineage,
//! one-strip `Invalid signature` retry and stream reduction are reused, never
//! copied. The Chat leg reads the shared bounded SSE parser and carries the
//! recorded `reasoning_content` member as-is into the next turn of the same
//! epoch. Every send resolves the canonical profile once, presents
//! `${apiKey}.${secretKey}` as the one bearer, and returns exactly one reply
//! and one physical usage report; a partial tool call or an unknown terminal
//! is never success.

use super::anthropic::{ANTHROPIC_VERSION, MessagesCodec, RefusedMessages, THINKING_BINDING_BETA};
use super::sse::{MAX_STREAM_BYTES, SseEvent, SseParser};
use super::{
    CredentialStore, Dialect, Provider, ProviderError, ProviderReply, STREAM_CHUNK_BYTES, ToolCall,
    WireAuth, bounded_reason, check_deadline, loopback_base, read_chunk,
    resolve_admitted_credential_in, sse, transport, transport_status, violation, wire_body,
};
use crate::config::{Config, ConnKind, Connection, EffortAssign, FixedModel, ModelAssign};
use crate::model::RequestManifest;
use crate::resources::UsageDelta;
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The provider row the canonical profile serves.
pub const CONNECTION: &str = "zai";

/// The sign-in alias that stores the same canonical profile.
pub const ALIAS_CONNECTION: &str = "zai-coding-plan";

/// The recorded Z.AI origin. A configured endpoint naming it binds the
/// connection to the recorded coding-plan bases, never to PAYG.
pub const ORIGIN: &str = "https://api.z.ai";

/// The recorded Messages coding-plan base.
pub const MESSAGES_BASE: &str = "https://api.z.ai/api/anthropic";

/// The recorded native Chat coding-plan base.
pub const CHAT_BASE: &str = "https://api.z.ai/api/coding/paas/v4";

/// The whole-send budget: credential resolution, connect, request and every
/// stream read count against it.
const REQUEST_DEADLINE: Duration = Duration::from_secs(120);

/// The bound on distinct tool calls one stream may open.
const MAX_TOOL_CALLS: usize = 32;

/// The bound on one tool call's accumulated argument bytes.
const MAX_TOOL_ARGS_BYTES: usize = 1024 * 1024;

/// The reasoning member names the recorded Chat contract returns as-is on a
/// multi-turn replay; the one the stream used is the one replayed.
const CHAT_REASONING_KEYS: [&str; 3] = ["reasoning_content", "reasoning", "reasoning_text"];

/// The closed recorded `zai` model table: the id and the transport its
/// bundled catalogue row names. The table is the recorded route — never
/// inferred from the model family, the credential form or an HTTP 200.
const MODELS: &[(&str, Dialect)] = &[
    ("glm-4.5", Dialect::Messages),
    ("glm-4.5-air", Dialect::Messages),
    ("glm-4.5-flash", Dialect::Messages),
    ("glm-4.5v", Dialect::Messages),
    ("glm-4.6", Dialect::Messages),
    ("glm-4.6v", Dialect::Messages),
    ("glm-4.7", Dialect::Messages),
    ("glm-4.7-flash", Dialect::Messages),
    ("glm-4.7-flashx", Dialect::Messages),
    ("glm-5", Dialect::Messages),
    ("glm-5-turbo", Dialect::Messages),
    ("glm-5.1", Dialect::Messages),
    ("glm-5.2", Dialect::Messages),
    ("glm-5.3", Dialect::Messages),
    ("glm-5.3-flash", Dialect::ChatCompletions),
    ("glm-5v-turbo", Dialect::Messages),
];

/// Whether `connection` is one of the two literals this adapter serves: the
/// canonical provider row and its sign-in alias are one backend, never a
/// second one.
#[must_use]
pub fn serves_literal(connection: &str) -> bool {
    connection == CONNECTION || connection == ALIAS_CONNECTION
}

/// The recorded transports both literals resolve: a model's recorded row
/// selects one, and the credential class never does.
#[must_use]
pub fn dialects() -> &'static [Dialect] {
    const DIALECTS: &[Dialect] = &[Dialect::Messages, Dialect::ChatCompletions];
    DIALECTS
}

/// The recorded transport one pinned model rides; `None` for a model outside
/// the bundled catalogue.
#[must_use]
pub fn route_for(model: &str) -> Option<Dialect> {
    MODELS
        .iter()
        .find(|(id, _)| *id == model)
        .map(|(_, dialect)| *dialect)
}

/// The endpoint binding one connection declaration carries: the recorded
/// base selection or the loopback proof override. A production base outside
/// the recorded coding-plan surface never becomes this value.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Endpoint {
    /// Empty or the recorded origin: the model's route selects the base.
    Origin,
    /// One recorded base: the model's route must agree with it.
    Base(&'static str),
    /// A loopback contract peer: the route appends its own path.
    Loopback(String),
}

impl Endpoint {
    fn bind(connection: &str, raw: &str) -> Result<Self, ProviderError> {
        let trimmed = raw.trim().trim_end_matches('/');
        if trimmed.is_empty() || trimmed == ORIGIN {
            return Ok(Self::Origin);
        }
        if trimmed == MESSAGES_BASE {
            return Ok(Self::Base(MESSAGES_BASE));
        }
        if trimmed == CHAT_BASE {
            return Ok(Self::Base(CHAT_BASE));
        }
        match loopback_base(connection, trimmed) {
            Ok(base) => Ok(Self::Loopback(base)),
            Err(_refused) => Err(ProviderError::UnsendableRequest {
                connection: connection.to_string(),
                reason: "the endpoint is outside the recorded z.ai coding-plan bases".to_string(),
            }),
        }
    }

    /// The base the selected route sends under: the recorded base, the
    /// configured recorded base when it names the same transport, or the
    /// loopback peer. A configured base bound to the other transport is a
    /// typed refusal before any request.
    fn for_route(&self, connection: &str, dialect: Dialect) -> Result<&str, ProviderError> {
        let recorded = match dialect {
            Dialect::ChatCompletions => CHAT_BASE,
            _ => MESSAGES_BASE,
        };
        match self {
            Self::Origin => Ok(recorded),
            Self::Base(base) if *base == recorded => Ok(base),
            Self::Base(_) => Err(ProviderError::UnsendableRequest {
                connection: connection.to_string(),
                reason: "the configured endpoint binds the other coding-plan transport".to_string(),
            }),
            Self::Loopback(base) => Ok(base),
        }
    }
}

/// The terminal classification one finished Chat Completions stream reduces
/// to.
enum ChatTerminal {
    Completed,
    Failed(String),
    Unclassifiable,
}

/// One in-flight streamed Chat tool call: `index` and `id` are the recorded
/// correlation keys — `id` is set once like `name` — and `args` is the
/// arguments text still concatenating.
#[derive(Default)]
struct ChatBlock {
    id: Option<String>,
    name: Option<String>,
    args: String,
}

#[derive(Default)]
struct ChatStream {
    text: String,
    /// The reasoning the peer streamed, in the member it named.
    reasoning: [String; CHAT_REASONING_KEYS.len()],
    blocks: Vec<ChatBlock>,
    block_by_index: HashMap<u64, usize>,
    terminal: Option<ChatTerminal>,
    done: bool,
    usage: Option<Value>,
}

/// The assistant turn one Chat epoch replays: the reasoning the peer sent
/// returns as-is beside the answer it accompanied.
struct ChatLineage {
    model: String,
    message: Value,
}

/// The frozen execution world, purpose and epoch a Chat replay belongs to.
type ChatLineageKey = (String, String, String);

fn chat_lineage_key(manifest: &RequestManifest) -> ChatLineageKey {
    (
        manifest.world.clone(),
        manifest.purpose.clone(),
        manifest.epoch_id.clone(),
    )
}

/// The Z.AI adapter: one literal connection, the recorded transport of each
/// send's model, and exactly one reply and one physical usage report per
/// send.
pub struct ZaiProvider {
    connection: String,
    endpoint: Endpoint,
    auth: WireAuth,
    store: Arc<dyn CredentialStore>,
    client: reqwest::blocking::Client,
    deadline: Duration,
    /// The shared Messages reduction: thinking lineage, drop policy,
    /// one-strip signature retry and stream accounting.
    codec: MessagesCodec,
    /// Chat reasoning turns, one per lineage, replayed inside their epoch.
    chat_lineages: BTreeMap<ChatLineageKey, ChatLineage>,
}

impl fmt::Debug for ZaiProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ZaiProvider")
            .field("connection", &self.connection)
            .field("endpoint", &self.endpoint)
            .field("auth", &self.auth)
            .field("deadline", &self.deadline)
            .finish_non_exhaustive()
    }
}

impl ZaiProvider {
    /// Builds the adapter for one of the two literals: the connection must
    /// be an `api_key` row bound to the canonical `zai` profile, carry no
    /// configured region, and name a recorded coding-plan endpoint or a
    /// loopback contract peer.
    ///
    /// # Errors
    /// [`ProviderError::DialectMismatch`] for another literal id;
    /// [`ProviderError::UnknownConnection`] for an undeclared one;
    /// [`ProviderError::RegionMismatch`] for a configured region;
    /// [`ProviderError::LocalProfileDeclared`] for a local declaration
    /// binding a profile; [`ProviderError::CredentialUnresolved`] for a
    /// local declaration or an unresolved binding;
    /// [`ProviderError::LiveGrantRequired`] for a subscription declaration;
    /// [`ProviderError::CredentialMalformed`] for a scope that does not name
    /// the canonical profile; [`ProviderError::UnsendableRequest`] for a
    /// foreign endpoint; and [`ProviderError::Transport`] when the HTTP
    /// client cannot build.
    pub fn new(
        config: &Config,
        connection: &str,
        store: Arc<dyn CredentialStore>,
    ) -> Result<Self, ProviderError> {
        Self::build(config, connection, store)
    }

    fn build(
        config: &Config,
        connection: &str,
        store: Arc<dyn CredentialStore>,
    ) -> Result<Self, ProviderError> {
        let deadline = REQUEST_DEADLINE;
        if !serves_literal(connection) {
            return Err(ProviderError::DialectMismatch {
                connection: connection.to_string(),
            });
        }
        let entry =
            config
                .connections
                .get(connection)
                .ok_or_else(|| ProviderError::UnknownConnection {
                    connection: connection.to_string(),
                })?;
        if let Some(region) = &entry.region {
            return Err(ProviderError::RegionMismatch {
                connection: connection.to_string(),
                region: region.clone(),
            });
        }
        if entry.kind == ConnKind::Local && entry.profile.is_some() {
            return Err(ProviderError::LocalProfileDeclared {
                connection: connection.to_string(),
            });
        }
        match entry.kind {
            ConnKind::ApiKey => {}
            ConnKind::Local => {
                return Err(ProviderError::CredentialUnresolved {
                    connection: connection.to_string(),
                    scope: format!("connections.{connection}.kind"),
                    cause: None,
                });
            }
            ConnKind::Subscription => {
                return Err(ProviderError::LiveGrantRequired {
                    kind: ConnKind::Subscription,
                });
            }
        }
        let endpoint = Endpoint::bind(connection, &entry.endpoint)?;
        let credential =
            resolve_admitted_credential_in(&config.connections, &config.profiles, connection)?
                .ok_or_else(|| ProviderError::CredentialUnresolved {
                    connection: connection.to_string(),
                    scope: format!("connections.{connection}.credential_ref"),
                    cause: None,
                })?;
        // The canonical profile is the only binding this adapter reads: a
        // scope naming another profile or material is refused before any
        // wire leg, so another class's bytes are never sent under z.ai.
        if credential.profile() != super::zai_login::PROFILE {
            return Err(ProviderError::CredentialMalformed {
                connection: connection.to_string(),
            });
        }
        let client = reqwest::blocking::Client::builder()
            .timeout(deadline.saturating_mul(2))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|err| transport(connection, err))?;
        Ok(Self {
            connection: connection.to_string(),
            endpoint,
            auth: WireAuth::Store(Some(credential)),
            store,
            client,
            deadline,
            codec: MessagesCodec::new(connection),
            chat_lineages: BTreeMap::new(),
        })
    }

    /// How many replayed thinking blocks the peer reported dropping.
    #[must_use]
    pub fn dropped_reasoning(&self) -> u64 {
        self.codec.dropped_reasoning()
    }

    /// The `${apiKey}.${secretKey}` bearer the canonical profile carries.
    /// Material that is not that profile denies typed; it never rides a
    /// request and never falls back to a PAYG key form.
    fn bearer(&self) -> Result<String, ProviderError> {
        let WireAuth::Store(Some(reference)) = &self.auth else {
            return Err(ProviderError::CredentialUnresolved {
                connection: self.connection.clone(),
                scope: format!("connections.{}.credential_ref", self.connection),
                cause: None,
            });
        };
        let material = self.store.resolve(reference)?;
        let profile = super::zai_login::read_zai(&material).map_err(|_denied| {
            ProviderError::CredentialMalformed {
                connection: self.connection.clone(),
            }
        })?;
        Ok(profile.token())
    }

    /// The frozen manifest as the Chat Completions wire body. The prior
    /// assistant turn of this epoch replays its reasoning beside the answer
    /// it accompanied; a prefix mutation replays nothing, and no developer
    /// role is ever constructed.
    fn chat_body(&self, manifest: &RequestManifest, model: &str) -> Result<Value, ProviderError> {
        if let EffortAssign::Fixed { .. } = &manifest.effort {
            // The recorded Chat row names an effort ladder this build's
            // vocabulary cannot transmit without inventing a wire value.
            return Err(ProviderError::UnsupportedParameter {
                connection: self.connection.clone(),
                parameter: "reasoning_effort",
                model: model.to_string(),
            });
        }
        let mut messages = Vec::with_capacity(3);
        if !manifest.instructions.is_empty() {
            messages.push(json!({ "role": "system", "content": manifest.instructions }));
        }
        if manifest.mutation_reason.is_none()
            && let Some(prior) = self.chat_lineages.get(&chat_lineage_key(manifest))
            && prior.model == model
        {
            messages.push(prior.message.clone());
        }
        messages.push(json!({ "role": "user", "content": manifest.inputs }));
        let mut body = json!({
            "model": model,
            "messages": messages,
            "stream": true,
            "stream_options": { "include_usage": true },
        });
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
        Ok(body)
    }

    /// A pinned Messages effort has no recorded dial this codec constructs:
    /// the denial lands before the body, never as a silently dropped field.
    fn check_messages_effort(
        &self,
        manifest: &RequestManifest,
        model: &str,
    ) -> Result<(), ProviderError> {
        if let EffortAssign::Fixed { .. } = &manifest.effort {
            return Err(ProviderError::UnsupportedParameter {
                connection: self.connection.clone(),
                parameter: "reasoning_effort",
                model: model.to_string(),
            });
        }
        Ok(())
    }

    fn send_messages(
        &mut self,
        manifest: &RequestManifest,
        model: &str,
        base: &str,
        bearer: &str,
        started: Instant,
    ) -> Result<ProviderReply, ProviderError> {
        self.check_messages_effort(manifest, model)?;
        let fixed = FixedModel {
            connection: self.connection.clone(),
            model_id: model.to_string(),
        };
        let binding = self.codec.binding(manifest, model);
        let body = self.codec.request_body(manifest, &fixed, &binding);
        let bytes = wire_body(&self.connection, &body)?;
        check_deadline(&self.connection, self.deadline, started)?;
        let deadline = self.deadline;
        let client = &self.client;
        let connection = self.connection.as_str();
        let post = |bytes: Vec<u8>, drop_block: bool| {
            let mut request = client
                .post(format!("{base}/v1/messages"))
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .header(reqwest::header::ACCEPT, "text/event-stream")
                .header("anthropic-version", ANTHROPIC_VERSION)
                .bearer_auth(bearer)
                .body(bytes);
            if drop_block {
                request = request.header("anthropic-beta", THINKING_BINDING_BETA);
            }
            request.send().map_err(|err| transport(connection, err))
        };
        let response = post(bytes, binding.drop_block)?;
        let codec = &mut self.codec;
        if response.status().is_success() {
            return codec.read_stream(manifest, model, response, deadline, started);
        }
        codec.retry_invalid_signature(
            RefusedMessages {
                manifest,
                fixed: &fixed,
                binding: &binding,
                response,
            },
            deadline,
            started,
            post,
        )
    }

    fn send_chat(
        &mut self,
        manifest: &RequestManifest,
        model: &str,
        base: &str,
        bearer: &str,
        started: Instant,
    ) -> Result<ProviderReply, ProviderError> {
        let body = self.chat_body(manifest, model)?;
        let bytes = wire_body(&self.connection, &body)?;
        check_deadline(&self.connection, self.deadline, started)?;
        let response = self
            .client
            .post(format!("{base}/chat/completions"))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::ACCEPT, "text/event-stream")
            .bearer_auth(bearer)
            .body(bytes)
            .send()
            .map_err(|err| transport(&self.connection, err))?;
        if !response.status().is_success() {
            return Err(transport_status(&self.connection, response.status()));
        }
        self.read_chat(manifest, model, response, started)
    }

    /// Reads one Chat Completions SSE body through the shared bounded
    /// parser. `[DONE]` alone is the recorded server-agreed close; EOF with
    /// neither a classifiable `finish_reason` nor the sentinel is the
    /// unknown terminal.
    fn read_chat(
        &mut self,
        manifest: &RequestManifest,
        model: &str,
        mut response: reqwest::blocking::Response,
        started: Instant,
    ) -> Result<ProviderReply, ProviderError> {
        let mut parser = SseParser::new();
        let mut state = ChatStream::default();
        let mut chunk = vec![0u8; STREAM_CHUNK_BYTES];
        let mut total = 0usize;
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
            total = total.saturating_add(read);
            if total > MAX_STREAM_BYTES {
                return Err(violation(&self.connection, "stream exceeds the byte bound"));
            }
            for event in parser
                .feed(&chunk[..read])
                .map_err(|err| sse(&self.connection, err))?
            {
                self.on_chat_event(&mut state, event)?;
            }
        }
        check_deadline(&self.connection, self.deadline, started)?;
        for event in parser.finish().map_err(|err| sse(&self.connection, err))? {
            self.on_chat_event(&mut state, event)?;
        }
        match state.terminal.take() {
            Some(ChatTerminal::Completed) => self.finish_chat(manifest, model, state),
            Some(ChatTerminal::Failed(reason)) => Err(ProviderError::ProviderFailed {
                connection: self.connection.clone(),
                reason: bounded_reason(reason),
            }),
            Some(ChatTerminal::Unclassifiable) => Err(ProviderError::UnknownTerminal {
                connection: self.connection.clone(),
            }),
            None if state.done => self.finish_chat(manifest, model, state),
            None => Err(ProviderError::UnknownTerminal {
                connection: self.connection.clone(),
            }),
        }
    }

    /// Finalizes a completed Chat stream and commits its replayable
    /// assistant turn: a stream that never declared reasoning commits
    /// nothing, so an unchanged epoch without reasoning replays nothing.
    fn finish_chat(
        &mut self,
        manifest: &RequestManifest,
        model: &str,
        mut state: ChatStream,
    ) -> Result<ProviderReply, ProviderError> {
        let usage = chat_usage(&self.connection, state.usage.as_ref())?;
        let mut tool_calls = Vec::with_capacity(state.blocks.len());
        for block in std::mem::take(&mut state.blocks) {
            let Some(name) = block.name.filter(|name| !name.is_empty()) else {
                return Err(violation(
                    &self.connection,
                    "a tool_call block never carried a function name",
                ));
            };
            if !manifest.tools.iter().any(|declared| declared == &name) {
                return Err(ProviderError::IncompatibleOutput {
                    connection: self.connection.clone(),
                    reason: bounded_reason(format!("tool_call names undeclared tool {name}")),
                });
            }
            let path = if block.args.is_empty() {
                None
            } else {
                let args: Value = serde_json::from_str(&block.args).map_err(|_parse| {
                    violation(&self.connection, "a tool_call's arguments did not parse")
                })?;
                let Some(args) = args.as_object() else {
                    return Err(violation(
                        &self.connection,
                        "a tool_call's arguments are not an object",
                    ));
                };
                args.get("path").and_then(Value::as_str).map(str::to_string)
            };
            tool_calls.push(ToolCall { tool: name, path });
        }
        self.commit_chat(manifest, model, &state);
        Ok(ProviderReply {
            text: state.text,
            tool_calls,
            usage,
            wire_retries: 0,
        })
    }

    /// Commits the assistant turn one Chat epoch replays — the answer and
    /// every reasoning member the peer named, byte-identical. A mutation
    /// or a reasoning-less turn clears the epoch's set instead.
    fn commit_chat(&mut self, manifest: &RequestManifest, model: &str, state: &ChatStream) {
        let key = chat_lineage_key(manifest);
        if manifest.mutation_reason.is_some() || state.reasoning.iter().all(String::is_empty) {
            self.chat_lineages.remove(&key);
            return;
        }
        let mut message = serde_json::Map::new();
        message.insert("role".to_string(), json!("assistant"));
        message.insert("content".to_string(), json!(state.text));
        for (name, piece) in CHAT_REASONING_KEYS.iter().zip(&state.reasoning) {
            if !piece.is_empty() {
                message.insert((*name).to_string(), json!(piece));
            }
        }
        self.chat_lineages.insert(
            key,
            ChatLineage {
                model: model.to_string(),
                message: Value::Object(message),
            },
        );
    }

    fn on_chat_event(&self, state: &mut ChatStream, event: SseEvent) -> Result<(), ProviderError> {
        if event.data == "[DONE]" {
            if state.done {
                return Err(violation(
                    &self.connection,
                    "stream carried a duplicate [DONE] sentinel",
                ));
            }
            state.done = true;
            return Ok(());
        }
        if state.done {
            return Err(violation(
                &self.connection,
                "stream carried content after the [DONE] sentinel",
            ));
        }
        let chunk: Value = serde_json::from_str(&event.data)
            .map_err(|_parse| violation(&self.connection, "stream chunk is not json"))?;
        if !chunk.is_object() {
            return Err(violation(&self.connection, "stream chunk is not an object"));
        }
        if let Some(error) = chunk.get("error").filter(|error| !is_falsy(error)) {
            let reason = match error {
                Value::String(reason) => reason.clone(),
                Value::Object(_) => super::payload_reason(error),
                _ => {
                    return Err(violation(
                        &self.connection,
                        "stream chunk error is not an object or string",
                    ));
                }
            };
            return self.set_chat_terminal(state, ChatTerminal::Failed(reason));
        }
        if let Some(message) = chunk.get("message").filter(|message| !is_falsy(message)) {
            let Some(reason) = message.as_str() else {
                return Err(violation(
                    &self.connection,
                    "stream chunk message is not a string",
                ));
            };
            return self.set_chat_terminal(state, ChatTerminal::Failed(reason.to_string()));
        }
        let choice = match chunk.get("choices") {
            None => None,
            Some(choices) => {
                let Some(list) = choices.as_array() else {
                    return Err(violation(
                        &self.connection,
                        "stream chunk choices is not an array",
                    ));
                };
                if list.len() > 1 {
                    return Err(violation(
                        &self.connection,
                        "stream chunk carried more than one choice",
                    ));
                }
                match list.first() {
                    None => None,
                    Some(choice) => {
                        if !choice.is_object() {
                            return Err(violation(
                                &self.connection,
                                "stream chunk choice is not an object",
                            ));
                        }
                        if state.terminal.is_some() {
                            return Err(violation(
                                &self.connection,
                                "stream carried a choice after its terminal",
                            ));
                        }
                        if let Some(index) = choice.get("index")
                            && index.as_u64() != Some(0)
                        {
                            return Err(violation(
                                &self.connection,
                                "stream chunk choice carries a nonzero index",
                            ));
                        }
                        Some(choice)
                    }
                }
            }
        };
        if let Some(choice) = choice {
            self.on_chat_delta(state, choice)?;
            if let Some(reason) = choice.get("finish_reason") {
                let terminal = match reason {
                    Value::Null => None,
                    Value::String(reason) => Some(match reason.to_ascii_lowercase().as_str() {
                        "stop" | "end" | "length" | "max_tokens" | "function_call"
                        | "tool_calls" => ChatTerminal::Completed,
                        "content_filter"
                        | "network_error"
                        | "error"
                        | "insufficient_system_resource" => ChatTerminal::Failed(format!(
                            "generation failed with finish reason {reason}"
                        )),
                        _ => ChatTerminal::Unclassifiable,
                    }),
                    _ => {
                        return Err(violation(
                            &self.connection,
                            "choice finish_reason is not a string",
                        ));
                    }
                };
                if let Some(terminal) = terminal {
                    self.set_chat_terminal(state, terminal)?;
                }
            }
        }
        if let Some(usage) = chunk
            .get("usage")
            .or_else(|| choice.and_then(|choice| choice.get("usage")))
            .filter(|usage| !usage.is_null())
        {
            state.usage = Some(usage.clone());
        }
        Ok(())
    }

    fn on_chat_delta(&self, state: &mut ChatStream, choice: &Value) -> Result<(), ProviderError> {
        let Some(delta) = choice.get("delta").filter(|delta| !delta.is_null()) else {
            return Ok(());
        };
        let Some(delta) = delta.as_object() else {
            return Err(violation(&self.connection, "choice delta is not an object"));
        };
        if let Some(content) = delta.get("content") {
            match content {
                Value::String(text) => state.text.push_str(text),
                Value::Null => {}
                _ => {
                    return Err(violation(&self.connection, "delta content is not a string"));
                }
            }
        }
        for (slot, key) in state.reasoning.iter_mut().zip(CHAT_REASONING_KEYS) {
            if let Some(reasoning) = delta.get(key) {
                match reasoning {
                    Value::String(piece) => slot.push_str(piece),
                    Value::Null => {}
                    _ => {
                        return Err(violation(
                            &self.connection,
                            "delta reasoning is not a string",
                        ));
                    }
                }
            }
        }
        if let Some(calls) = delta.get("tool_calls") {
            let Some(calls) = calls.as_array() else {
                return Err(violation(
                    &self.connection,
                    "delta tool_calls is not an array",
                ));
            };
            for entry in calls {
                self.on_chat_tool_call(state, entry, calls.len() > 1)?;
            }
        }
        Ok(())
    }

    /// Routes one `tool_calls` entry to its block: the stream `index` wins,
    /// then a block's declared `id`, and only a single-entry delta may
    /// continue the last-opened block. A block's `id` and function `name`
    /// are each set once; a second, different value or an id a sibling
    /// already holds is a malformed stream. Argument fragments concatenate
    /// under the byte bound.
    fn on_chat_tool_call(
        &self,
        state: &mut ChatStream,
        entry: &Value,
        batched: bool,
    ) -> Result<(), ProviderError> {
        let Some(entry) = entry.as_object() else {
            return Err(violation(
                &self.connection,
                "tool_calls entry is not an object",
            ));
        };
        let index = match entry.get("index") {
            None => None,
            Some(index) => match index.as_u64() {
                Some(index) => Some(index),
                None => {
                    return Err(violation(
                        &self.connection,
                        "tool_calls entry index is not an integer",
                    ));
                }
            },
        };
        let id = match entry.get("id") {
            None | Some(Value::Null) => None,
            Some(Value::String(id)) if !id.is_empty() => Some(id.clone()),
            Some(Value::String(_)) => None,
            Some(_) => {
                return Err(violation(
                    &self.connection,
                    "tool_calls entry id is not a string",
                ));
            }
        };
        let position = if let Some(index) = index {
            match state.block_by_index.get(&index) {
                Some(&position) => position,
                None => {
                    let position = state.blocks.len();
                    state.blocks.push(ChatBlock::default());
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
                    state.blocks.push(ChatBlock {
                        id: Some(id.clone()),
                        ..ChatBlock::default()
                    });
                    state.blocks.len() - 1
                }
            }
        } else if batched {
            return Err(violation(
                &self.connection,
                "a tool_calls entry without index or id cannot be routed",
            ));
        } else if state.blocks.is_empty() {
            state.blocks.push(ChatBlock::default());
            0
        } else {
            state.blocks.len() - 1
        };
        if state.blocks.len() > MAX_TOOL_CALLS {
            return Err(violation(
                &self.connection,
                "stream carried more tool calls than the bound",
            ));
        }
        if let Some(kind) = entry.get("type") {
            match kind {
                Value::Null => {}
                Value::String(kind) if kind == "function" => {}
                Value::String(_) => {
                    return Err(ProviderError::IncompatibleOutput {
                        connection: self.connection.clone(),
                        reason: bounded_reason("a streamed tool call is not a function call"),
                    });
                }
                _ => {
                    return Err(violation(
                        &self.connection,
                        "tool_calls entry type is not a string",
                    ));
                }
            }
        }
        if let Some(id) = id {
            match &state.blocks[position].id {
                Some(existing) if existing != &id => {
                    return Err(violation(
                        &self.connection,
                        "a tool_call block's id changed mid-stream",
                    ));
                }
                Some(_) => {}
                None => {
                    if state.blocks.iter().enumerate().any(|(at, block)| {
                        at != position && block.id.as_deref() == Some(id.as_str())
                    }) {
                        return Err(violation(
                            &self.connection,
                            "two tool_call blocks carry the same id",
                        ));
                    }
                    state.blocks[position].id = Some(id);
                }
            }
        }
        if let Some(function) = entry.get("function") {
            let Some(function) = function.as_object() else {
                return Err(violation(
                    &self.connection,
                    "tool_calls entry function is not an object",
                ));
            };
            if let Some(name) = function.get("name") {
                match name {
                    Value::String(name) if !name.is_empty() => match &state.blocks[position].name {
                        Some(existing) if existing != name => {
                            return Err(violation(
                                &self.connection,
                                "a tool_call block's function name changed mid-stream",
                            ));
                        }
                        Some(_) => {}
                        None => state.blocks[position].name = Some(name.clone()),
                    },
                    Value::String(_) | Value::Null => {}
                    _ => {
                        return Err(violation(
                            &self.connection,
                            "tool_call function name is not a string",
                        ));
                    }
                }
            }
            if let Some(arguments) = function.get("arguments") {
                match arguments {
                    Value::String(piece) => {
                        let block = &mut state.blocks[position];
                        if block.args.len() + piece.len() > MAX_TOOL_ARGS_BYTES {
                            return Err(violation(
                                &self.connection,
                                "a tool_call's arguments exceed the byte bound",
                            ));
                        }
                        block.args.push_str(piece);
                    }
                    Value::Null => {}
                    _ => {
                        return Err(violation(
                            &self.connection,
                            "a tool_call's arguments are not a streamed string",
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    fn set_chat_terminal(
        &self,
        state: &mut ChatStream,
        terminal: ChatTerminal,
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
}

impl Provider for ZaiProvider {
    fn name(&self) -> &'static str {
        "zai"
    }

    fn serves(&self, connection: &str, _entry: &Connection) -> bool {
        connection == self.connection
    }

    /// Sends the frozen manifest as one physical request on its model's
    /// recorded transport.
    ///
    /// # Errors
    /// [`ProviderError::UnpinnedModel`]/[`ProviderError::DialectMismatch`]
    /// for an assignment this adapter cannot pin, the credential seam's
    /// typed denials, [`ProviderError::CredentialMalformed`] for material
    /// outside the canonical profile, [`ProviderError::UnsupportedParameter`]
    /// for a row outside the recorded table or a rejected pinned parameter,
    /// [`ProviderError::UnsendableRequest`] for an endpoint bound to the
    /// other transport, and the codecs' transport, terminal and wire
    /// denials.
    fn send(&mut self, manifest: &RequestManifest) -> Result<ProviderReply, ProviderError> {
        let started = Instant::now();
        check_deadline(&self.connection, self.deadline, started)?;
        let model = match &manifest.model {
            ModelAssign::Fixed(fixed) => {
                if fixed.connection != self.connection {
                    return Err(ProviderError::DialectMismatch {
                        connection: fixed.connection.clone(),
                    });
                }
                fixed.model_id.clone()
            }
            _ => {
                return Err(ProviderError::UnpinnedModel {
                    connection: self.connection.clone(),
                });
            }
        };
        let dialect = route_for(&model).ok_or_else(|| ProviderError::UnsupportedParameter {
            connection: self.connection.clone(),
            parameter: "model",
            model: model.clone(),
        })?;
        let bearer = self.bearer()?;
        let base = self
            .endpoint
            .for_route(&self.connection, dialect)?
            .to_string();
        match dialect {
            Dialect::ChatCompletions => self.send_chat(manifest, &model, &base, &bearer, started),
            _ => self.send_messages(manifest, &model, &base, &bearer, started),
        }
    }
}

/// The physical usage a Chat Completions stream reported: absent stays
/// unknown, a present-but-unreadable shape is a wire violation.
fn chat_usage(connection: &str, usage: Option<&Value>) -> Result<UsageDelta, ProviderError> {
    let Some(usage) = usage else {
        return Ok(UsageDelta::Unknown);
    };
    let prompt = usage.get("prompt_tokens").and_then(Value::as_u64);
    let completion = usage.get("completion_tokens").and_then(Value::as_u64);
    let total = usage.get("total_tokens").and_then(Value::as_u64);
    let cache_read = usage
        .get("prompt_tokens_details")
        .and_then(|details| details.get("cached_tokens"))
        .and_then(Value::as_u64);
    let reasoning = usage
        .get("completion_tokens_details")
        .and_then(|details| details.get("reasoning_tokens"))
        .and_then(Value::as_u64);
    match (prompt, completion, total) {
        (Some(prompt_tokens), Some(completion_tokens), Some(total_tokens)) => {
            Ok(UsageDelta::from_reported(
                prompt_tokens,
                completion_tokens,
                total_tokens,
                reasoning,
                cache_read,
                None,
            ))
        }
        _ => Err(violation(connection, "usage is not a readable token shape")),
    }
}

/// JavaScript truthiness for the recorded `if (data.error)` guards.
fn is_falsy(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Bool(flag) => !flag,
        Value::Number(number) => number.as_f64() == Some(0.0),
        Value::String(text) => text.is_empty(),
        Value::Array(_) | Value::Object(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_recorded_table_selects_each_transport_by_model() {
        assert_eq!(route_for("glm-5.2"), Some(Dialect::Messages));
        assert_eq!(route_for("glm-4.6"), Some(Dialect::Messages));
        assert_eq!(route_for("glm-5.3-flash"), Some(Dialect::ChatCompletions));
        assert_eq!(route_for("glm-5.2[1m]"), None);
        assert_eq!(route_for("sk-payg-key"), None);
        assert_eq!(MODELS.len(), 16, "the bundled zai rows, none invented");
    }

    #[test]
    fn aliases_are_one_backend() {
        assert!(serves_literal("zai"));
        assert!(serves_literal("zai-coding-plan"));
        assert!(!serves_literal("zhipu-coding-plan"));
        assert_eq!(
            dialects(),
            &[Dialect::Messages, Dialect::ChatCompletions][..]
        );
        assert_eq!(CONNECTION, "zai");
        assert_eq!(ALIAS_CONNECTION, "zai-coding-plan");
    }

    #[test]
    fn endpoint_binding_admits_only_the_recorded_surface() {
        assert_eq!(Endpoint::bind("zai", "").expect("empty"), Endpoint::Origin);
        assert_eq!(
            Endpoint::bind("zai", "https://api.z.ai/").expect("origin"),
            Endpoint::Origin
        );
        assert_eq!(
            Endpoint::bind("zai", MESSAGES_BASE).expect("messages"),
            Endpoint::Base(MESSAGES_BASE)
        );
        assert_eq!(
            Endpoint::bind("zai", CHAT_BASE).expect("chat"),
            Endpoint::Base(CHAT_BASE)
        );
        let loopback = Endpoint::bind("zai", "http://127.0.0.1:9").expect("loopback");
        assert!(matches!(loopback, Endpoint::Loopback(_)));
        assert!(matches!(
            Endpoint::bind("zai", "https://api.z.ai/api/paas/v4"),
            Err(ProviderError::UnsendableRequest { .. })
        ));
        assert!(matches!(
            Endpoint::bind("zai", "https://open.bigmodel.cn/api/coding/paas/v4"),
            Err(ProviderError::UnsendableRequest { .. })
        ));
    }

    #[test]
    fn a_configured_base_binds_its_own_transport_only() {
        let endpoint = Endpoint::Base(MESSAGES_BASE);
        assert_eq!(
            endpoint
                .for_route("zai", Dialect::Messages)
                .expect("the bound transport"),
            MESSAGES_BASE
        );
        assert!(matches!(
            endpoint.for_route("zai", Dialect::ChatCompletions),
            Err(ProviderError::UnsendableRequest { .. })
        ));
        let origin = Endpoint::Origin;
        assert_eq!(
            origin
                .for_route("zai", Dialect::ChatCompletions)
                .expect("chat"),
            CHAT_BASE
        );
        assert_eq!(
            origin
                .for_route("zai", Dialect::Messages)
                .expect("messages"),
            MESSAGES_BASE
        );
    }
}
