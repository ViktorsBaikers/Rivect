//! The Anthropic Messages dialect owner (DEC-002): one adapter for the
//! literal ids whose recorded source class speaks `POST /v1/messages`.
//! The catalogue, credential form and stream reducer are per-id contract
//! rows — an id the table does not name is denied the same way as an id
//! outside the dialect, never served by another row's predicates.
//!
//! The reducer is fail-closed: `message_stop` is the only terminal (no
//! `[DONE]`), EOF without it is an unknown terminal, an open content
//! block at the terminal is a partial frame, and usage stays unknown
//! unless both the start input count and the delta output count arrived.
//!
//! Preserved thinking follows the recorded epoch contract (REQ-039):
//! assistant thinking/signature blocks are replayed bytewise inside the
//! same `(world, purpose, epoch)` lineage; a mutation (or a model switch)
//! sends the beta header plus `drop_block`, never replays the stale set,
//! and records the peer's `input_transformations` as dropped reasoning.
//! A `400` naming `Invalid signature` is permanent: the adapter strips
//! the replayed thinking blocks for exactly one retry, never twice.
//!
//! An `anthropic` declaration of `kind = "subscription"` stores the login
//! module's `SubscriptionCredential` JSON at its scoped ref; this adapter
//! parses it back and sends only its `access_token`, as
//! `Authorization: Bearer` beside `anthropic-version` — the stored JSON
//! and its refresh token never reach the wire or an `x-api-key` header.
//!
//! `vercel-ai-gateway` records the gateway's Messages surface on
//! `https://ai-gateway.vercel.sh`: the gateway key rides
//! `Authorization: Bearer`, and the keyed `/v1/models` listing's
//! `tool-use` tag is the closed table — a row without the tag is never
//! offered, and a pin outside the tagged set denies before the body.

use super::anthropic_login::{LoginError, read_subscription};
use super::sse::{SseEvent, SseParser};
use super::{
    CatalogModel, CredentialStore, Dialect, Provider, ProviderError, ProviderReply, ToolCall,
    WireAuth, bounded_reason, check_deadline, dialect_for, forwarded_header_map,
    open_proxy_connection, payload_reason, positive_count, read_catalog_body, read_chunk,
    resolve_admitted_credential_in, route_for, routes_for, sse, transport, transport_status,
    violation, wire_body, wire_effort,
};
use crate::config::{Config, ConnKind, EffortAssign, FixedModel, ModelAssign};
use crate::model::RequestManifest;
use crate::resources::UsageDelta;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The whole-request budget every Messages send shares.
const REQUEST_DEADLINE: Duration = Duration::from_secs(120);

/// The recorded adapter output budget (ASM-005): the manifest's
/// `output_reserve` is bytes, so the Messages `max_tokens` never derives
/// from it.
pub const MESSAGES_MAX_TOKENS: u64 = 8192;

/// The protocol version every Messages request must carry.
const ANTHROPIC_VERSION: &str = "2023-06-01";

/// The recorded beta surface for the preserved-thinking drop policy.
const THINKING_BINDING_BETA: &str = "thinking-binding-controls-2026-08-01";

/// The recorded default base of the `anthropic` arm.
const ANTHROPIC_DEFAULT_BASE: &str = "https://api.anthropic.com";

/// The recorded default base of the `umans` arm.
const UMANS_DEFAULT_BASE: &str = "https://api.code.umans.ai";

/// The recorded default base of the `minimax` arm; the configured base
/// wins verbatim and inference appends `/v1/messages`.
const MINIMAX_DEFAULT_BASE: &str = "https://api.minimax.io/anthropic";

/// The recorded default base of the `vercel-ai-gateway` arm: the
/// Messages-compatible gateway root, so inference appends `/v1/messages`.
const VERCEL_DEFAULT_BASE: &str = "https://ai-gateway.vercel.sh";

/// The recorded `/v1/models` capability tag that admits a model to this
/// arm: a row without it is neither offered nor sent.
const VERCEL_TOOL_USE_TAG: &str = "tool-use";

/// The recorded static seed of the `cloudflare-ai-gateway` arm: no
/// gateway listing exists, so this is the whole catalogue.
const CLOUDFLARE_SEED: &[&str] = &["anthropic/claude-opus-4-8"];

/// The upstream-provider prefix the `cloudflare-ai-gateway` arm's
/// closed route set is keyed by (DEC-005): the gateway serves the
/// Anthropic route only, and the wire model keeps its prefix.
const CLOUDFLARE_MODEL_PREFIX: &str = "anthropic/";

/// The recorded GitLab Duo proxy base and the Messages aliases'
/// `upstreamModelId` table (DEC-013): the routed owner translates the
/// alias before the wire, so these are the only models this arm sends.
const GITLAB_MESSAGES_PROXY: &str = "https://cloud.gitlab.com/ai/v1/proxy/anthropic";
const GITLAB_MESSAGES_MODELS: &[&str] = &[
    "claude-opus-4-6",
    "claude-sonnet-4-6",
    "claude-opus-4-5-20251101",
    "claude-sonnet-4-5-20250929",
    "claude-haiku-4-5-20251001",
];

/// The recorded `opencode-zen` base path (DEC-014): the routed owner
/// appends `/v1` per route, and the configured endpoint's trailing
/// `/v1` is stripped before that append.
const OPENCODE_ZEN_BASE: &str = "https://opencode.ai/zen";

/// The recorded `opencode-go` base path (DEC-014): the routed owner
/// appends `/v1` per route, and the configured endpoint's trailing
/// `/v1` is stripped before that append.
const OPENCODE_GO_BASE: &str = "https://opencode.ai/zen/go";

/// The recorded `minimax` M-series offer set. The arm has no listing
/// leg: these ids are the whole catalogue, and an id outside the set is
/// never offered or sent.
const MINIMAX_MODELS: &[&str] = &[
    "MiniMax-M3",
    "MiniMax-M2.7",
    "MiniMax-M2.7-highspeed",
    "MiniMax-M2.5",
    "MiniMax-M2.5-highspeed",
    "MiniMax-M2.1",
    "MiniMax-M2.1-highspeed",
    "MiniMax-M2",
];

/// The recorded `/v1/models` snapshot families the catalogue never offers.
const ANTHROPIC_EXCLUDED_PREFIXES: &[&str] = &["claude-3-5-haiku", "claude-3-7-sonnet"];
const ANTHROPIC_EXCLUDED_IDS: &[&str] = &["claude-3-opus-20240229", "claude-3-sonnet-20240229"];

/// The per-id catalogue rule: `KeyedListing` offers the keyed listing's
/// ids minus the frozen snapshot families; `ModelsInfo` reads the
/// object-keyed `/models/info` payload whose keys are the model ids.
#[derive(Clone, Copy)]
enum CatalogRule {
    KeyedListing {
        excluded_prefixes: &'static [&'static str],
        excluded_ids: &'static [&'static str],
    },
    /// The `opencode-go` keyed `/v1/models` listing filtered by the
    /// recorded route table to the ids whose route is Messages
    /// (DEC-014): catalogue and send guard share one family set, so a
    /// CC/Responses-family id is neither offered nor sent here.
    KeyedRouteListing,
    /// The `vercel-ai-gateway` keyed `/v1/models` listing filtered by
    /// the recorded `tags` marker: only a `tool-use` row is offered, and
    /// a pin outside the tagged set has no route here — HTTP 200 is not
    /// entitlement.
    ToolUseListing,
    /// The `umans` object-keyed listing: keys are wire model ids, values
    /// carry the stated capability surface. No seed floor — a retired
    /// cached id is never fabricated.
    ModelsInfo,
    /// The arm's recorded static offer set: no listing leg exists, and
    /// an id outside the set is neither offered nor sent.
    Allowlist(&'static [&'static str]),
    /// The arm's recorded static seed beside its upstream-provider
    /// route family (DEC-005): no listing leg exists, the seed is the
    /// whole catalogue, and a wire model outside `prefix` has no
    /// recorded route.
    SeedAndPrefix {
        seed: &'static [&'static str],
        prefix: &'static str,
    },
}

/// The per-id credential form the wire legs bind.
#[derive(Clone, Copy)]
enum CredentialRule {
    /// `x-api-key` plus the mandatory `anthropic-version` header.
    ApiKey,
    /// The Cloudflare Run-permission token in `cf-aig-authorization:
    /// Bearer <token>` only, plus the mandatory `anthropic-version`
    /// header — never `x-api-key` or a second `Authorization`
    /// (DEC-005).
    CloudflareGateway,
    /// A bearer token under `Authorization`, plus the mandatory
    /// `anthropic-version` — the GitLab proxy leg's short-lived
    /// exchanged token (DEC-013).
    Bearer,
}

/// One literal id's recorded Messages predicates (HZN-008/DEC-002): base
/// rule, catalogue rule and credential form. A further Messages id
/// appends its own arm; none inherits a sibling's.
#[derive(Clone, Copy)]
struct MessagesContract {
    /// The recorded default base; a configured endpoint wins verbatim
    /// after trimming.
    default_base: &'static str,
    /// Whether a configured base carries a trailing `/v1` that the
    /// recorded arm strips before its own paths are appended.
    strip_v1: bool,
    /// The per-id catalogue entry rule.
    catalog: CatalogRule,
    /// The per-id credential form.
    credential: CredentialRule,
}

fn contract_for(connection: &str) -> Option<MessagesContract> {
    match connection {
        "anthropic" => Some(MessagesContract {
            default_base: ANTHROPIC_DEFAULT_BASE,
            strip_v1: false,
            catalog: CatalogRule::KeyedListing {
                excluded_prefixes: ANTHROPIC_EXCLUDED_PREFIXES,
                excluded_ids: ANTHROPIC_EXCLUDED_IDS,
            },
            credential: CredentialRule::ApiKey,
        }),
        "umans" => Some(MessagesContract {
            default_base: UMANS_DEFAULT_BASE,
            strip_v1: true,
            catalog: CatalogRule::ModelsInfo,
            credential: CredentialRule::ApiKey,
        }),
        "minimax" => Some(MessagesContract {
            default_base: MINIMAX_DEFAULT_BASE,
            strip_v1: false,
            catalog: CatalogRule::Allowlist(MINIMAX_MODELS),
            credential: CredentialRule::ApiKey,
        }),
        "cloudflare-ai-gateway" => Some(MessagesContract {
            // DEC-005: account/gateway are operator data, so no default
            // base is invented; the configured endpoint is the complete
            // native proxy base.
            default_base: "",
            strip_v1: false,
            catalog: CatalogRule::SeedAndPrefix {
                seed: CLOUDFLARE_SEED,
                prefix: CLOUDFLARE_MODEL_PREFIX,
            },
            credential: CredentialRule::CloudflareGateway,
        }),
        // The gateway root is the recorded Messages base, so inference
        // appends `/v1/messages`; the gateway key rides `Authorization:
        // Bearer`, and the catalogue is the keyed `/v1/models` listing's
        // `tool-use` rows.
        "vercel-ai-gateway" => Some(MessagesContract {
            default_base: VERCEL_DEFAULT_BASE,
            strip_v1: false,
            catalog: CatalogRule::ToolUseListing,
            credential: CredentialRule::Bearer,
        }),
        // DEC-013: the proxy base is recorded and the routed owner
        // passes it as the codec's configured endpoint; the wire model
        // is the alias's upstream id, and the short-lived exchange token
        // rides `Authorization: Bearer`.
        "gitlab-duo" => Some(MessagesContract {
            default_base: GITLAB_MESSAGES_PROXY,
            strip_v1: false,
            catalog: CatalogRule::Allowlist(GITLAB_MESSAGES_MODELS),
            credential: CredentialRule::Bearer,
        }),
        // DEC-014: the routed owner passes `{base}/v1` as the
        // configured endpoint; the arm strips it and appends its own
        // `/v1/...` paths, so the gateway key rides `Authorization:
        // Bearer` beside the recorded Anthropic version header. The
        // keyed listing is filtered to the Messages route family.
        "opencode-go" => Some(MessagesContract {
            default_base: OPENCODE_GO_BASE,
            strip_v1: true,
            catalog: CatalogRule::KeyedRouteListing,
            credential: CredentialRule::Bearer,
        }),
        // DEC-014: the routed owner passes `{base}/v1` as the
        // configured endpoint; the arm strips it and appends its own
        // `/v1/...` paths, so the gateway key rides `Authorization:
        // Bearer` beside the recorded Anthropic version header.
        "opencode-zen" => Some(MessagesContract {
            default_base: OPENCODE_ZEN_BASE,
            strip_v1: true,
            catalog: CatalogRule::KeyedListing {
                excluded_prefixes: &[],
                excluded_ids: &[],
            },
            credential: CredentialRule::Bearer,
        }),
        _ => None,
    }
}

/// The conversation lineage a replayed thinking set belongs to: a
/// different world, purpose or epoch is a different conversation.
type LineageKey = (String, String, String);

/// The assistant blocks captured under one lineage, bound to the model
/// that minted them — the one-way model binding never replays a block
/// against another model.
struct ThinkingLineage {
    model: String,
    blocks: Vec<Value>,
}

/// One request's replay decision: the captured blocks to replay and
/// whether the recorded drop policy rides the request.
struct RequestBinding {
    replay: Vec<Value>,
    drop_block: bool,
}

/// The replay block state of one content block while it streams.
#[derive(Clone, Copy, PartialEq, Eq)]
enum BlockKind {
    Text,
    Tool,
    Thinking,
    RedactedThinking,
}

struct Block {
    kind: BlockKind,
    text: String,
    name: String,
    args: String,
    thinking: String,
    signature: String,
    redacted: Option<Value>,
}

impl Block {
    fn new(kind: BlockKind) -> Self {
        Self {
            kind,
            text: String::new(),
            name: String::new(),
            args: String::new(),
            thinking: String::new(),
            signature: String::new(),
            redacted: None,
        }
    }
}

/// Per-stream accounting: open content blocks (a nonzero count at the
/// terminal is a partial frame), the cumulative usage pair, the terminal
/// declaration, and the replayable assistant blocks the reply minted.
#[derive(Default)]
struct StreamState {
    started: bool,
    terminal: bool,
    text: String,
    tool_calls: Vec<ToolCall>,
    blocks: BTreeMap<u64, Block>,
    input_tokens: Option<u64>,
    output_tokens: Option<u64>,
    /// Cache legs the peer reported on `message_start`; absent stays unknown.
    cache_read_tokens: Option<u64>,
    cache_write_tokens: Option<u64>,
    stop_reason: Option<String>,
    thinking: Vec<Value>,
    transformations: u64,
}

/// The recorded terminal reasons the dialect can classify as success.
/// Any other reason is an unknown terminal, never an outcome.
const CLASSIFIED_STOP_REASONS: &[&str] = &[
    "end_turn",
    "max_tokens",
    "stop_sequence",
    "tool_use",
    "refusal",
];

/// The shared Messages adapter. Constructed per connection; the Broker
/// owns the handle.
pub struct MessagesProvider {
    /// The literal connection id this adapter serves.
    connection: String,
    /// The recorded per-id predicates.
    contract: MessagesContract,
    /// The configured or default base, trimmed of trailing slashes.
    endpoint: String,
    /// The credential seam: a scoped reference resolved per send, or a
    /// preflight-resolved token the caller supplied.
    auth: WireAuth,
    /// Whether the declaration is the recorded subscription form: the
    /// stored material is a [`super::anthropic_login::SubscriptionCredential`]
    /// and only its access token crosses the wire, as a bearer.
    subscription: bool,
    store: Arc<dyn CredentialStore>,
    client: reqwest::blocking::Client,
    /// The one budget credential resolution, catalogue and stream share.
    deadline: Duration,
    /// Assistant thinking sets, one per lineage.
    lineages: BTreeMap<LineageKey, ThinkingLineage>,
    /// How many replayed blocks the peer reported it dropped.
    dropped_reasoning: u64,
}

impl MessagesProvider {
    /// Builds the adapter for one literal id: the id must record the
    /// Messages dialect and a contract arm, the connection must carry no
    /// configured region, an arm with no default base must carry a
    /// configured endpoint, and the scoped credential must resolve.
    ///
    /// # Errors
    /// [`ProviderError::DialectMismatch`] for an id outside the dialect
    /// or without its own contract arm, [`ProviderError::UnknownConnection`]
    /// for an undeclared id, [`ProviderError::RegionMismatch`] for a
    /// configured region, [`ProviderError::LocalProfileDeclared`] for a
    /// local declaration binding a profile,
    /// [`ProviderError::EndpointRequired`] for an empty endpoint on an
    /// arm that records no default base,
    /// [`ProviderError::CredentialUnresolved`] for a reserved local
    /// declaration or an unresolved binding, and
    /// [`ProviderError::Transport`] when the HTTP client cannot build.
    pub fn new(
        config: &Config,
        connection: &str,
        store: Arc<dyn CredentialStore>,
    ) -> Result<Self, ProviderError> {
        Self::build(config, connection, store, REQUEST_DEADLINE, None)
    }

    /// The same adapter under an explicit whole-request deadline; proof
    /// legs pin a short one so the budget is exercised deterministically.
    ///
    /// # Errors
    /// [`Self::new`]'s contract.
    pub fn with_deadline(
        config: &Config,
        connection: &str,
        store: Arc<dyn CredentialStore>,
        deadline: Duration,
    ) -> Result<Self, ProviderError> {
        Self::build(config, connection, store, deadline, None)
    }

    /// Builds the adapter for a route-scoped construction. The routed
    /// owner is the caller: the gate is the id's recorded route table,
    /// and a preflight-resolved [`WireAuth`] skips the store resolve.
    ///
    /// # Errors
    /// [`Self::new`]'s contract, and
    /// [`ProviderError::DialectMismatch`] when the id's recorded routes
    /// do not include Messages.
    pub fn with_route(
        config: &Config,
        connection: &str,
        store: Arc<dyn CredentialStore>,
        deadline: Duration,
        auth: WireAuth,
    ) -> Result<Self, ProviderError> {
        if !routes_for(connection).contains(&Dialect::Messages) {
            return Err(ProviderError::DialectMismatch {
                connection: connection.to_string(),
            });
        }
        Self::assemble(config, connection, store, deadline, Some(auth))
    }

    fn build(
        config: &Config,
        connection: &str,
        store: Arc<dyn CredentialStore>,
        deadline: Duration,
        auth: Option<WireAuth>,
    ) -> Result<Self, ProviderError> {
        if dialect_for(connection) != Some(Dialect::Messages) {
            return Err(ProviderError::DialectMismatch {
                connection: connection.to_string(),
            });
        }
        Self::assemble(config, connection, store, deadline, auth)
    }

    fn assemble(
        config: &Config,
        connection: &str,
        store: Arc<dyn CredentialStore>,
        deadline: Duration,
        auth: Option<WireAuth>,
    ) -> Result<Self, ProviderError> {
        let contract = contract_for(connection).ok_or(ProviderError::DialectMismatch {
            connection: connection.to_string(),
        })?;
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
        if conn.kind == ConnKind::Local && conn.profile.is_some() {
            return Err(ProviderError::LocalProfileDeclared {
                connection: connection.to_string(),
            });
        }
        if conn.kind == ConnKind::Local && !open_proxy_connection(connection) {
            return Err(ProviderError::CredentialUnresolved {
                connection: connection.to_string(),
                scope: format!("connections.{connection}.kind"),
                cause: None,
            });
        }
        // DEC-005: an arm recording no default base has no host unless
        // the operator supplied one — deny before the credential seam
        // or any wire leg.
        let endpoint = endpoint_for(&contract, &conn.endpoint);
        if endpoint.is_empty() {
            return Err(ProviderError::EndpointRequired {
                connection: connection.to_string(),
            });
        }
        let auth = match auth {
            Some(auth) => auth,
            None => WireAuth::Store(resolve_admitted_credential_in(
                &config.connections,
                &config.profiles,
                connection,
            )?),
        };
        let client = reqwest::blocking::Client::builder()
            .timeout(deadline.saturating_mul(2))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|err| transport(connection, err))?;
        Ok(Self {
            connection: connection.to_string(),
            contract,
            endpoint,
            auth,
            subscription: conn.kind == ConnKind::Subscription,
            store,
            client,
            deadline,
            lineages: BTreeMap::new(),
            dropped_reasoning: 0,
        })
    }

    /// The model catalogue ids in deterministic sorted order.
    ///
    /// # Errors
    /// [`Self::catalog_models`]'s typed denials.
    pub fn catalog(&self) -> Result<Vec<String>, ProviderError> {
        Ok(self
            .catalog_models()?
            .into_iter()
            .map(|model| model.id)
            .collect())
    }

    /// The rich catalogue: the literal id's recorded listing rule under
    /// the shared whole-call budget. A static offer set answers before the
    /// credential seam is touched; only a wire listing resolves a token.
    ///
    /// # Errors
    /// The credential seam's typed denials; [`ProviderError::Transport`]
    /// for a failed call, non-success status or expired budget;
    /// [`ProviderError::StreamViolation`] when the listing payload is not
    /// the recorded shape.
    pub fn catalog_models(&self) -> Result<Vec<CatalogModel>, ProviderError> {
        let started = Instant::now();
        check_deadline(&self.connection, self.deadline, started)?;
        if let Some(models) = self.static_catalog() {
            return Ok(models);
        }
        let token = self
            .token()?
            .ok_or_else(|| ProviderError::CredentialUnresolved {
                connection: self.connection.clone(),
                scope: format!("connections.{}.credential_ref", self.connection),
                cause: None,
            })?;
        self.catalog_within(&token, started)
    }

    /// How many replayed thinking blocks the peer reported dropping.
    #[must_use]
    pub fn dropped_reasoning(&self) -> u64 {
        self.dropped_reasoning
    }

    fn catalog_within(
        &self,
        token: &str,
        started: Instant,
    ) -> Result<Vec<CatalogModel>, ProviderError> {
        check_deadline(&self.connection, self.deadline, started)?;
        if let Some(models) = self.static_catalog() {
            return Ok(models);
        }
        let url = self
            .catalog_url()
            .ok_or_else(|| violation(&self.connection, "catalogue rule has no wire path"))?;
        let request = self
            .client
            .get(url)
            .header(reqwest::header::ACCEPT, "application/json");
        let mut response = self
            .authenticated(request, token)
            .send()
            .map_err(|err| transport(&self.connection, err))?;
        if !response.status().is_success() {
            return Err(transport_status(&self.connection, response.status()));
        }
        let body = read_catalog_body(&self.connection, self.deadline, &mut response, started)?;
        let body: Value = serde_json::from_slice(&body)
            .map_err(|_parse| violation(&self.connection, "models payload is not json"))?;
        let mut models = self.listed_models(&body)?;
        models.sort_by(|a, b| a.id.cmp(&b.id));
        models.dedup_by(|a, b| a.id == b.id);
        Ok(models)
    }

    /// The literal id's recorded catalogue path: the keyed `/v1/models`
    /// listing, the `umans` `/models/info` listing on the base whose
    /// trailing `/v1` was already stripped, or no path for an arm whose
    /// offer set is static.
    fn catalog_url(&self) -> Option<String> {
        match self.contract.catalog {
            CatalogRule::KeyedListing { .. }
            | CatalogRule::KeyedRouteListing
            | CatalogRule::ToolUseListing => Some(models_url(&self.endpoint)),
            CatalogRule::ModelsInfo => Some(models_info_url(&self.endpoint)),
            CatalogRule::Allowlist(_) | CatalogRule::SeedAndPrefix { .. } => None,
        }
    }

    /// The static offer set of a static arm; `None` where the arm
    /// discovers its catalogue over the wire.
    fn static_catalog(&self) -> Option<Vec<CatalogModel>> {
        match self.contract.catalog {
            CatalogRule::Allowlist(ids) | CatalogRule::SeedAndPrefix { seed: ids, .. } => {
                Some(allowlisted_models(ids))
            }
            CatalogRule::KeyedListing { .. }
            | CatalogRule::KeyedRouteListing
            | CatalogRule::ToolUseListing
            | CatalogRule::ModelsInfo => None,
        }
    }

    /// The listing payload under the literal id's recorded shape.
    fn listed_models(&self, body: &Value) -> Result<Vec<CatalogModel>, ProviderError> {
        match self.contract.catalog {
            CatalogRule::KeyedListing { .. }
            | CatalogRule::KeyedRouteListing
            | CatalogRule::ToolUseListing => {
                let Some(data) = body.get("data").and_then(Value::as_array) else {
                    return Err(violation(
                        &self.connection,
                        "models payload carries no data array",
                    ));
                };
                Ok(data
                    .iter()
                    .filter_map(|entry| self.catalog_entry(entry))
                    .collect())
            }
            CatalogRule::ModelsInfo => {
                let Some(listing) = body.as_object() else {
                    return Err(violation(
                        &self.connection,
                        "models payload is not an object keyed by model id",
                    ));
                };
                Ok(listing
                    .iter()
                    .filter_map(|(id, entry)| models_info_entry(id, entry))
                    .collect())
            }
            CatalogRule::Allowlist(ids) | CatalogRule::SeedAndPrefix { seed: ids, .. } => {
                Ok(allowlisted_models(ids))
            }
        }
    }

    /// One listed entry under the literal id's recorded rule. An entry
    /// without an id offers nothing; the frozen snapshot families are
    /// excluded rather than remapped, the OpenCode gateway keeps only the
    /// ids its recorded route table sends on Messages, and the Vercel
    /// gateway keeps only the rows carrying the recorded `tool-use` tag.
    fn catalog_entry(&self, entry: &Value) -> Option<CatalogModel> {
        let id = entry
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())?;
        match self.contract.catalog {
            CatalogRule::KeyedListing {
                excluded_prefixes,
                excluded_ids,
            } => {
                if excluded_prefixes
                    .iter()
                    .any(|prefix| id.starts_with(prefix))
                    || excluded_ids.contains(&id)
                {
                    return None;
                }
            }
            CatalogRule::KeyedRouteListing => {
                if route_for(&self.connection, id) != Some(Dialect::Messages) {
                    return None;
                }
            }
            CatalogRule::ToolUseListing => {
                let tagged = entry
                    .get("tags")
                    .and_then(Value::as_array)
                    .is_some_and(|tags| {
                        tags.iter()
                            .any(|tag| tag.as_str() == Some(VERCEL_TOOL_USE_TAG))
                    });
                if !tagged {
                    return None;
                }
                return Some(CatalogModel {
                    id: id.to_string(),
                    tools: true,
                    ..CatalogModel::default()
                });
            }
            CatalogRule::ModelsInfo
            | CatalogRule::Allowlist(_)
            | CatalogRule::SeedAndPrefix { .. } => return None,
        }
        Some(CatalogModel {
            id: id.to_string(),
            ..CatalogModel::default()
        })
    }

    /// The material this send authenticates with. The store call cannot
    /// be interrupted once running, so the budget is checked before it.
    /// A subscription declaration stores the login module's credential
    /// JSON; only its access token crosses the wire.
    fn token(&self) -> Result<Option<String>, ProviderError> {
        match &self.auth {
            WireAuth::Store(Some(credential)) if self.subscription => {
                match read_subscription(self.store.as_ref(), credential) {
                    Ok(material) => Ok(Some(material.access_token().to_string())),
                    Err(LoginError::Provider(error)) => Err(error),
                    Err(_malformed) => Err(ProviderError::CredentialMalformed {
                        connection: self.connection.clone(),
                    }),
                }
            }
            WireAuth::Store(Some(credential)) => {
                let material = self.store.resolve(credential)?;
                let token = String::from_utf8(material).map_err(|_utf8| {
                    ProviderError::CredentialMalformed {
                        connection: self.connection.clone(),
                    }
                })?;
                Ok(Some(token))
            }
            WireAuth::Store(None) => Ok(None),
            WireAuth::Resolved { token, .. } => Ok(Some(token.clone())),
        }
    }

    fn authenticated(
        &self,
        request: reqwest::blocking::RequestBuilder,
        token: &str,
    ) -> reqwest::blocking::RequestBuilder {
        let rule = if self.subscription {
            // A subscription token is an OAuth access token: it rides
            // `Authorization: Bearer`, never `x-api-key`.
            CredentialRule::Bearer
        } else {
            self.contract.credential
        };
        match rule {
            CredentialRule::ApiKey => request
                .header("x-api-key", token)
                .header("anthropic-version", ANTHROPIC_VERSION),
            CredentialRule::CloudflareGateway => request
                .header("cf-aig-authorization", format!("Bearer {token}"))
                .header("anthropic-version", ANTHROPIC_VERSION),
            CredentialRule::Bearer => request
                .bearer_auth(token)
                .header("anthropic-version", ANTHROPIC_VERSION),
        }
        .headers(forwarded_header_map(self.auth.forwarded()))
    }

    /// The frozen manifest as the Messages wire request: `system`
    /// top-level, the mandatory `max_tokens`, the declared client tools
    /// with `input_schema`, and any replayed assistant thinking set.
    fn request_body(
        &self,
        manifest: &RequestManifest,
        fixed: &FixedModel,
        binding: &RequestBinding,
    ) -> Value {
        let mut messages = Vec::with_capacity(2);
        if !binding.replay.is_empty() {
            messages.push(json!({
                "role": "assistant",
                "content": binding.replay.clone(),
            }));
        }
        messages.push(json!({ "role": "user", "content": manifest.inputs }));
        let mut body = json!({
            "model": fixed.model_id,
            "max_tokens": MESSAGES_MAX_TOKENS,
            "stream": true,
            "system": manifest.instructions,
            "messages": messages,
        });
        if !manifest.tools.is_empty() {
            body["tools"] = Value::Array(
                manifest
                    .tools
                    .iter()
                    .map(|name| {
                        json!({
                            "name": name,
                            "description": "",
                            "input_schema": { "type": "object" },
                        })
                    })
                    .collect(),
            );
        }
        if binding.drop_block {
            body["thinking"] =
                json!({ "block_binding": { "prefix_mismatch_behavior": "drop_block" } });
        }
        body
    }

    /// The replay decision for this manifest: an unchanged lineage and
    /// model replays its captured blocks; a mutation or model switch
    /// drops the set and requests the recorded drop policy.
    fn binding(&mut self, manifest: &RequestManifest, model: &str) -> RequestBinding {
        let key = lineage_key(manifest);
        if manifest.mutation_reason.is_some() {
            self.lineages.remove(&key);
            return RequestBinding {
                replay: Vec::new(),
                drop_block: true,
            };
        }
        if let Some(lineage) = self.lineages.get(&key)
            && lineage.model == model
        {
            return RequestBinding {
                replay: lineage.blocks.clone(),
                drop_block: false,
            };
        }
        if self.lineages.remove(&key).is_some() {
            return RequestBinding {
                replay: Vec::new(),
                drop_block: true,
            };
        }
        RequestBinding {
            replay: Vec::new(),
            drop_block: false,
        }
    }

    /// An `Allowlist` arm records its whole serve set, a
    /// `SeedAndPrefix` arm its upstream-provider route family, the
    /// gateway's `KeyedRouteListing` its Messages family from the same
    /// route table the routed owner dispatches on, and the Vercel
    /// gateway's `ToolUseListing` the rows the keyed `/v1/models` listing
    /// tags `tool-use`: an id outside the recorded set has no route here,
    /// so the denial lands before the body, never as a wire request to a
    /// sibling id's model. The marker set travels in from
    /// [`Self::admitted_listing`], whose typed read failures surface
    /// before this check.
    fn check_model(
        &self,
        model: &str,
        offered: Option<&[CatalogModel]>,
    ) -> Result<(), ProviderError> {
        let admitted = match self.contract.catalog {
            CatalogRule::Allowlist(ids) => ids.contains(&model),
            CatalogRule::SeedAndPrefix { prefix, .. } => model.starts_with(prefix),
            CatalogRule::KeyedRouteListing => {
                route_for(&self.connection, model) == Some(Dialect::Messages)
            }
            CatalogRule::ToolUseListing => {
                offered.is_some_and(|models| models.iter().any(|entry| entry.id == model))
            }
            CatalogRule::KeyedListing { .. } | CatalogRule::ModelsInfo => true,
        };
        if admitted {
            return Ok(());
        }
        Err(ProviderError::UnsupportedParameter {
            connection: self.connection.clone(),
            parameter: "model",
            model: model.to_string(),
        })
    }

    /// A pinned effort has no recorded Messages dial: the denial lands
    /// before the marker listing is read and before the body exists, never
    /// as a silently dropped field. `model` names the frozen pin's id, or
    /// `auto` while an unpinned request has not resolved one yet.
    fn check_effort(&self, manifest: &RequestManifest, model: &str) -> Result<(), ProviderError> {
        if matches!(manifest.effort, EffortAssign::Fixed { .. }) {
            return Err(ProviderError::UnsupportedParameter {
                connection: self.connection.clone(),
                parameter: "effort",
                model: model.to_string(),
            });
        }
        Ok(())
    }

    /// The Messages tool name grammar: 1–128 ASCII alphanumerics, `_` or
    /// `-`. A pin outside it has no constructible client tool and denies
    /// before the marker listing and the wire.
    fn check_tools(&self, manifest: &RequestManifest, model: &str) -> Result<(), ProviderError> {
        for name in &manifest.tools {
            if !valid_tool_name(name) {
                return Err(ProviderError::UnsupportedParameter {
                    connection: self.connection.clone(),
                    parameter: "tools",
                    model: model.to_string(),
                });
            }
        }
        Ok(())
    }

    /// The auto pool's wire model: the one connection this broker routed
    /// to is the guard, and the first offered model (already sorted by
    /// [`Self::admitted_listing`]) is the pick. An assignment outside that
    /// narrow form is [`ProviderError::UnpinnedModel`].
    ///
    /// # Errors
    /// [`ProviderError::UnpinnedModel`] for a manifest whose model is not a
    /// one-connection auto pool on this adapter; the catalogue read's
    /// [`ProviderError::Transport`]/[`ProviderError::StreamViolation`]
    /// denials when no offered set travels in.
    fn auto_model(
        &self,
        manifest: &RequestManifest,
        token: &str,
        started: Instant,
        offered: Option<&[CatalogModel]>,
    ) -> Result<FixedModel, ProviderError> {
        let ModelAssign::Auto { pool: Some(pool) } = &manifest.model else {
            return Err(ProviderError::UnpinnedModel {
                connection: self.connection.clone(),
            });
        };
        if pool.len() != 1 || pool[0] != self.connection {
            return Err(ProviderError::UnpinnedModel {
                connection: self.connection.clone(),
            });
        }
        let model_id = match offered {
            Some(models) => models.first().map(|model| model.id.clone()),
            None => self
                .catalog_within(token, started)?
                .into_iter()
                .next()
                .map(|model| model.id),
        }
        .ok_or_else(|| ProviderError::UnpinnedModel {
            connection: self.connection.clone(),
        })?;
        Ok(FixedModel {
            connection: self.connection.clone(),
            model_id,
        })
    }

    /// The marker-filtered offer set a send admits against, read once: the
    /// `ToolUseListing` arm answers the keyed listing, every other arm
    /// answers `None` because its admission needs no wire read. Every
    /// assignment reaches the local request-shape denials before this read;
    /// an auto pin learns its model id from it.
    ///
    /// # Errors
    /// [`ProviderError::Transport`] for a failed call, non-success status
    /// or expired budget; [`ProviderError::StreamViolation`] when the
    /// listing payload is not the recorded shape.
    fn admitted_listing(
        &self,
        token: &str,
        started: Instant,
    ) -> Result<Option<Vec<CatalogModel>>, ProviderError> {
        match self.contract.catalog {
            CatalogRule::ToolUseListing => Ok(Some(self.catalog_within(token, started)?)),
            CatalogRule::KeyedListing { .. }
            | CatalogRule::KeyedRouteListing
            | CatalogRule::ModelsInfo
            | CatalogRule::Allowlist(_)
            | CatalogRule::SeedAndPrefix { .. } => Ok(None),
        }
    }

    fn post(
        &self,
        token: &str,
        body: Vec<u8>,
        drop_block: bool,
    ) -> Result<reqwest::blocking::Response, ProviderError> {
        let mut request = self
            .client
            .post(messages_url(&self.endpoint))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::ACCEPT, "text/event-stream")
            .body(body);
        if drop_block {
            request = request.header("anthropic-beta", THINKING_BINDING_BETA);
        }
        self.authenticated(request, token)
            .send()
            .map_err(|err| transport(&self.connection, err))
    }

    /// Sends the frozen manifest as one physical Messages request.
    ///
    /// # Errors
    /// [`ProviderError::UnpinnedModel`], [`ProviderError::DialectMismatch`],
    /// the credential seam's typed denials,
    /// [`ProviderError::UnsupportedParameter`] for a pinned effort, a
    /// tool name the dialect cannot construct, or a model outside an
    /// allowlist arm's recorded offer set, the marker listing's
    /// [`ProviderError::Transport`]/[`ProviderError::StreamViolation`]
    /// denials for a marker arm, [`ProviderError::Transport`] for a
    /// failed or non-success send leg, [`ProviderError::ProviderFailed`],
    /// [`ProviderError::UnknownTerminal`],
    /// [`ProviderError::StreamViolation`] and
    /// [`ProviderError::IncompatibleOutput`] as the reducer documents.
    fn send_manifest(
        &mut self,
        manifest: &RequestManifest,
    ) -> Result<ProviderReply, ProviderError> {
        let started = Instant::now();
        check_deadline(&self.connection, self.deadline, started)?;
        let token = self
            .token()?
            .ok_or_else(|| ProviderError::CredentialUnresolved {
                connection: self.connection.clone(),
                scope: format!("connections.{}.credential_ref", self.connection),
                cause: None,
            })?;
        // The request-shape denials are local: a pinned effort, an
        // unconstructible tool name, or a pin naming another adapter never
        // reads the marker listing or crosses the wire. An unresolved auto
        // model admits under its assignment spelling, so every assignment
        // reaches these checks before the listing read.
        let pinned = match &manifest.model {
            ModelAssign::Fixed(fixed) => {
                if fixed.connection != self.connection {
                    return Err(ProviderError::DialectMismatch {
                        connection: fixed.connection.clone(),
                    });
                }
                Some(fixed.clone())
            }
            _ => None,
        };
        let admission_model = match &manifest.model {
            ModelAssign::Fixed(fixed) => fixed.model_id.as_str(),
            _ => "auto",
        };
        self.check_effort(manifest, admission_model)?;
        self.check_tools(manifest, admission_model)?;
        let offered = self.admitted_listing(&token, started)?;
        let fixed = match pinned {
            Some(fixed) => fixed,
            None => self.auto_model(manifest, &token, started, offered.as_deref())?,
        };
        self.check_model(&fixed.model_id, offered.as_deref())?;
        let binding = self.binding(manifest, &fixed.model_id);
        let body = self.request_body(manifest, &fixed, &binding);
        let body_bytes = wire_body(&self.connection, &body)?;
        check_deadline(&self.connection, self.deadline, started)?;
        let mut response = self.post(&token, body_bytes, binding.drop_block)?;
        let status = response.status();
        if status.is_success() {
            return self.read_stream(manifest, &fixed.model_id, response, started);
        }
        if status == reqwest::StatusCode::BAD_REQUEST && !binding.replay.is_empty() {
            let failed =
                read_catalog_body(&self.connection, self.deadline, &mut response, started)?;
            if names_invalid_signature(&failed) {
                // The body is permanently invalid; never replay its blocks
                // on a later send even when the stripped retry also fails.
                self.lineages.remove(&lineage_key(manifest));
                let stripped = RequestBinding {
                    replay: Vec::new(),
                    drop_block: binding.drop_block,
                };
                let retry_body = self.request_body(manifest, &fixed, &stripped);
                // Defensive: the HTTP seam cannot reach these two checks — the
                // first leg's refusable body read already enforces the shared
                // clock — so neither failure may ever be counted as a retry.
                let retry_bytes = wire_body(&self.connection, &retry_body)?;
                check_deadline(&self.connection, self.deadline, started)?;
                let retry = match self.post(&token, retry_bytes, stripped.drop_block) {
                    Ok(retry) => retry,
                    Err(source) => {
                        // The corrected leg's POST is the second crossed
                        // leg even when it fails before a response: the
                        // count rides the failure beside its class.
                        return Err(ProviderError::Retried {
                            wire_retries: 1,
                            source: Box::new(source),
                        });
                    }
                };
                let retry_status = retry.status();
                if !retry_status.is_success() {
                    // The corrected leg crossed the wire and was refused:
                    // the settlement keeps the count beside the class.
                    return Err(ProviderError::Retried {
                        wire_retries: 1,
                        source: Box::new(transport_status(&self.connection, retry_status)),
                    });
                }
                // The correction is this child's own second leg, not a
                // second attempt: the reply carries the count and the
                // first leg's usage stays unknown. A retried leg that
                // fails while its body streams crossed too.
                let mut reply = match self.read_stream(manifest, &fixed.model_id, retry, started) {
                    Ok(reply) => reply,
                    Err(source) => {
                        return Err(ProviderError::Retried {
                            wire_retries: 1,
                            source: Box::new(source),
                        });
                    }
                };
                reply.wire_retries = reply.wire_retries.saturating_add(1);
                return Ok(reply);
            }
        }
        Err(transport_status(&self.connection, status))
    }

    /// Reads the SSE body through the shared bounded parser and reduces
    /// it to the one terminal the dialect can classify.
    fn read_stream(
        &mut self,
        manifest: &RequestManifest,
        model: &str,
        mut response: reqwest::blocking::Response,
        started: Instant,
    ) -> Result<ProviderReply, ProviderError> {
        let mut parser = SseParser::new();
        let mut state = StreamState::default();
        let mut chunk = vec![0u8; super::STREAM_CHUNK_BYTES];
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
                self.on_event(manifest, &mut state, event)?;
            }
        }
        check_deadline(&self.connection, self.deadline, started)?;
        for event in parser.finish().map_err(|err| sse(&self.connection, err))? {
            self.on_event(manifest, &mut state, event)?;
        }
        if !state.blocks.is_empty() {
            return Err(violation(
                &self.connection,
                "stream ended mid content block",
            ));
        }
        if !state.terminal {
            return Err(ProviderError::UnknownTerminal {
                connection: self.connection.clone(),
            });
        }
        let stop_reason = state.stop_reason.as_deref().unwrap_or_default();
        if !CLASSIFIED_STOP_REASONS.contains(&stop_reason) {
            return Err(ProviderError::UnknownTerminal {
                connection: self.connection.clone(),
            });
        }
        if stop_reason == "tool_use" && state.tool_calls.is_empty() {
            return Err(violation(
                &self.connection,
                "tool_use terminal carried no tool call",
            ));
        }
        let usage = match (state.input_tokens, state.output_tokens) {
            (Some(prompt_tokens), Some(completion_tokens)) => {
                let total_tokens =
                    prompt_tokens
                        .checked_add(completion_tokens)
                        .ok_or_else(|| {
                            violation(&self.connection, "usage token counts overflow the total")
                        })?;
                // A reported cache leg makes the report a leg set: the pair
                // keeps its folded shape and the cache counters ride as
                // their own legs. A peer reporting none stays exact.
                UsageDelta::from_reported(
                    prompt_tokens,
                    completion_tokens,
                    total_tokens,
                    None,
                    state.cache_read_tokens,
                    state.cache_write_tokens,
                )
            }
            _ => UsageDelta::Unknown,
        };
        self.dropped_reasoning = self.dropped_reasoning.saturating_add(state.transformations);
        self.commit(manifest, model, state.thinking);
        Ok(ProviderReply {
            text: state.text,
            tool_calls: state.tool_calls,
            usage,
            wire_retries: 0,
        })
    }

    /// Classifies one dispatched SSE event. Only `message_stop` is a
    /// terminal; an event after it is a duplicate-terminal violation.
    fn on_event(
        &self,
        manifest: &RequestManifest,
        state: &mut StreamState,
        event: SseEvent,
    ) -> Result<(), ProviderError> {
        if state.terminal {
            return Err(violation(
                &self.connection,
                "stream carried an event after message_stop",
            ));
        }
        let payload: Value = serde_json::from_str(&event.data)
            .map_err(|_parse| violation(&self.connection, "event payload is not json"))?;
        let name = if event.event.is_empty() {
            payload
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        } else {
            event.event
        };
        match name.as_str() {
            "message_start" => self.on_message_start(state, &payload),
            "content_block_start" => self.on_content_block_start(state, &payload),
            "content_block_delta" => self.on_content_block_delta(state, &payload),
            "content_block_stop" => self.on_content_block_stop(manifest, state, &payload),
            "message_delta" => self.on_message_delta(state, &payload),
            "message_stop" => {
                if !state.blocks.is_empty() {
                    return Err(violation(
                        &self.connection,
                        "message_stop before every content block closed",
                    ));
                }
                state.terminal = true;
                Ok(())
            }
            "error" => Err(ProviderError::ProviderFailed {
                connection: self.connection.clone(),
                reason: bounded_reason(
                    payload
                        .get("error")
                        .map_or_else(|| payload_reason(&payload), payload_reason),
                ),
            }),
            // Pings and forward-compatible surface are observed, never a
            // terminal substitute.
            _ => Ok(()),
        }
    }

    fn on_message_start(
        &self,
        state: &mut StreamState,
        payload: &Value,
    ) -> Result<(), ProviderError> {
        if state.started {
            return Err(violation(
                &self.connection,
                "stream carried a duplicate message_start",
            ));
        }
        state.started = true;
        let Some(message) = payload.get("message").filter(|value| value.is_object()) else {
            return Err(violation(
                &self.connection,
                "message_start carries no message object",
            ));
        };
        if let Some(usage) = message.get("usage")
            && let Some(input) = usage.get("input_tokens")
        {
            state.input_tokens = Some(input.as_u64().ok_or_else(|| {
                violation(
                    &self.connection,
                    "message_start input_tokens is not a token count",
                )
            })?);
            state.cache_read_tokens = usage.get("cache_read_input_tokens").and_then(Value::as_u64);
            state.cache_write_tokens = usage
                .get("cache_creation_input_tokens")
                .and_then(Value::as_u64);
        }
        state.transformations = transformations_in(&self.connection, message)?
            .saturating_add(transformations_in(&self.connection, payload)?);
        Ok(())
    }

    fn on_content_block_start(
        &self,
        state: &mut StreamState,
        payload: &Value,
    ) -> Result<(), ProviderError> {
        if !state.started {
            return Err(violation(
                &self.connection,
                "content block started before message_start",
            ));
        }
        let index = payload
            .get("index")
            .and_then(Value::as_u64)
            .ok_or_else(|| violation(&self.connection, "content block carries no index"))?;
        let block = payload
            .get("content_block")
            .filter(|value| value.is_object())
            .ok_or_else(|| violation(&self.connection, "content block start carries no block"))?;
        if state.blocks.contains_key(&index) {
            return Err(violation(
                &self.connection,
                "content block index started twice",
            ));
        }
        let kind = block
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(|| violation(&self.connection, "content block carries no type"))?;
        let mut entry = match kind {
            "text" => Block::new(BlockKind::Text),
            "tool_use" => {
                let mut entry = Block::new(BlockKind::Tool);
                entry.name = block
                    .get("name")
                    .and_then(Value::as_str)
                    .ok_or_else(|| violation(&self.connection, "tool_use block carries no name"))?
                    .to_string();
                entry
            }
            "thinking" => {
                let mut entry = Block::new(BlockKind::Thinking);
                if let Some(thinking) = block.get("thinking").and_then(Value::as_str) {
                    entry.thinking.push_str(thinking);
                }
                if let Some(signature) = block.get("signature").and_then(Value::as_str) {
                    entry.signature.push_str(signature);
                }
                entry
            }
            "redacted_thinking" => {
                let mut entry = Block::new(BlockKind::RedactedThinking);
                entry.redacted = Some(block.clone());
                entry
            }
            other => {
                return Err(ProviderError::IncompatibleOutput {
                    connection: self.connection.clone(),
                    reason: bounded_reason(format!("unsupported content block type {other}")),
                });
            }
        };
        if kind == "text"
            && let Some(text) = block.get("text").and_then(Value::as_str)
        {
            entry.text.push_str(text);
        }
        state.blocks.insert(index, entry);
        Ok(())
    }

    fn on_content_block_delta(
        &self,
        state: &mut StreamState,
        payload: &Value,
    ) -> Result<(), ProviderError> {
        let index = payload
            .get("index")
            .and_then(Value::as_u64)
            .ok_or_else(|| violation(&self.connection, "content delta carries no index"))?;
        let delta = payload
            .get("delta")
            .filter(|value| value.is_object())
            .ok_or_else(|| violation(&self.connection, "content delta carries no delta object"))?;
        let delta_type = delta
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(|| violation(&self.connection, "content delta carries no type"))?;
        let block = state
            .blocks
            .get_mut(&index)
            .ok_or_else(|| violation(&self.connection, "content block delta without its start"))?;
        match (block.kind, delta_type) {
            (BlockKind::Text, "text_delta") => {
                let text = delta
                    .get("text")
                    .and_then(Value::as_str)
                    .ok_or_else(|| violation(&self.connection, "text delta carries no text"))?;
                block.text.push_str(text);
            }
            (BlockKind::Tool, "input_json_delta") => {
                let partial = delta
                    .get("partial_json")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        violation(&self.connection, "tool delta carries no partial_json")
                    })?;
                block.args.push_str(partial);
            }
            (BlockKind::Thinking, "thinking_delta") => {
                let thinking = delta
                    .get("thinking")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        violation(&self.connection, "thinking delta carries no thinking")
                    })?;
                block.thinking.push_str(thinking);
            }
            (BlockKind::Thinking, "signature_delta") => {
                let signature =
                    delta
                        .get("signature")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            violation(&self.connection, "signature delta carries no signature")
                        })?;
                block.signature.push_str(signature);
            }
            (BlockKind::RedactedThinking, _) => {}
            _ => {
                return Err(violation(
                    &self.connection,
                    "content block delta does not match its block",
                ));
            }
        }
        Ok(())
    }

    fn on_content_block_stop(
        &self,
        manifest: &RequestManifest,
        state: &mut StreamState,
        payload: &Value,
    ) -> Result<(), ProviderError> {
        let index = payload
            .get("index")
            .and_then(Value::as_u64)
            .ok_or_else(|| violation(&self.connection, "content block stop carries no index"))?;
        let block = state
            .blocks
            .remove(&index)
            .ok_or_else(|| violation(&self.connection, "content block stop without its start"))?;
        match block.kind {
            BlockKind::Text => state.text.push_str(&block.text),
            BlockKind::Tool => {
                let raw = block.args.trim();
                let parsed: Value = if raw.is_empty() {
                    json!({})
                } else {
                    serde_json::from_str(raw).map_err(|_parse| {
                        violation(&self.connection, "a tool_use input did not parse")
                    })?
                };
                let args = parsed.as_object().ok_or_else(|| {
                    violation(&self.connection, "a tool_use input is not an object")
                })?;
                if !manifest
                    .tools
                    .iter()
                    .any(|declared| declared == &block.name)
                {
                    return Err(ProviderError::IncompatibleOutput {
                        connection: self.connection.clone(),
                        reason: bounded_reason(format!(
                            "tool_use names undeclared tool {}",
                            block.name
                        )),
                    });
                }
                state.tool_calls.push(ToolCall {
                    tool: block.name,
                    path: args.get("path").and_then(Value::as_str).map(str::to_string),
                });
            }
            BlockKind::Thinking => {
                if block.signature.is_empty() {
                    return Err(violation(
                        &self.connection,
                        "a thinking block carried no signature",
                    ));
                }
                state.thinking.push(json!({
                    "type": "thinking",
                    "thinking": block.thinking,
                    "signature": block.signature,
                }));
            }
            BlockKind::RedactedThinking => {
                let Some(value) = block.redacted else {
                    return Err(violation(
                        &self.connection,
                        "a redacted_thinking block carried no data",
                    ));
                };
                state.thinking.push(value);
            }
        }
        Ok(())
    }

    fn on_message_delta(
        &self,
        state: &mut StreamState,
        payload: &Value,
    ) -> Result<(), ProviderError> {
        if let Some(reason) = payload
            .pointer("/delta/stop_reason")
            .and_then(Value::as_str)
        {
            state.stop_reason = Some(reason.to_string());
        }
        if let Some(usage) = payload.get("usage") {
            let usage = usage.as_object().ok_or_else(|| {
                violation(&self.connection, "message_delta usage is not an object")
            })?;
            if let Some(output) = usage.get("output_tokens") {
                state.output_tokens = Some(output.as_u64().ok_or_else(|| {
                    violation(
                        &self.connection,
                        "message_delta output_tokens is not a token count",
                    )
                })?);
            }
        }
        Ok(())
    }

    /// Commits this reply's assistant thinking set under its own lineage:
    /// a set is replayed only by the same world, purpose, epoch and model.
    fn commit(&mut self, manifest: &RequestManifest, model: &str, blocks: Vec<Value>) {
        let key = lineage_key(manifest);
        if blocks.is_empty() {
            self.lineages.remove(&key);
        } else {
            self.lineages.insert(
                key,
                ThinkingLineage {
                    model: model.to_string(),
                    blocks,
                },
            );
        }
    }
}

impl std::fmt::Debug for MessagesProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MessagesProvider")
            .field("connection", &self.connection)
            .field("endpoint", &self.endpoint)
            .field("auth", &self.auth)
            .field("deadline", &self.deadline)
            .finish_non_exhaustive()
    }
}

impl Provider for MessagesProvider {
    fn name(&self) -> &'static str {
        "anthropic-messages"
    }

    fn serves(&self, connection: &str, _entry: &crate::config::Connection) -> bool {
        connection == self.connection
    }

    fn send(&mut self, manifest: &RequestManifest) -> Result<ProviderReply, ProviderError> {
        Self::send_manifest(self, manifest)
    }
}

/// The Messages tool name grammar (1–128 ASCII alphanumerics, `_` or
/// `-`): a name outside it has no constructible client tool.
fn valid_tool_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    (1..=128).contains(&bytes.len())
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

/// The connection's recorded base: the configured endpoint wins after
/// trimming, and an empty value resolves the literal arm's default. An
/// arm recording the trailing `/v1` strip loses that segment before its
/// own paths are appended.
fn endpoint_for(contract: &MessagesContract, configured: &str) -> String {
    let configured = configured.trim().trim_end_matches('/');
    let base = if configured.is_empty() {
        contract.default_base
    } else {
        configured
    };
    if contract.strip_v1 {
        base.strip_suffix("/v1").unwrap_or(base).to_string()
    } else {
        base.to_string()
    }
}

/// `{base}/v1/models`, or `{base}/models` when the configured base
/// already carries the version segment.
fn models_url(base: &str) -> String {
    if base.ends_with("/v1") {
        format!("{base}/models")
    } else {
        format!("{base}/v1/models")
    }
}

/// `{base}/models/info`: the `umans` object-keyed listing, on the base
/// whose trailing `/v1` has already been stripped.
fn models_info_url(base: &str) -> String {
    format!("{base}/models/info")
}

/// A static offer set as catalogue entries in deterministic id order;
/// each id carries no claimed capability surface the arm did not record.
fn allowlisted_models(ids: &[&str]) -> Vec<CatalogModel> {
    let mut models: Vec<CatalogModel> = ids
        .iter()
        .map(|id| CatalogModel {
            id: (*id).to_string(),
            ..CatalogModel::default()
        })
        .collect();
    models.sort_by(|a, b| a.id.cmp(&b.id));
    models
}

/// One `umans` `/models/info` entry: the object key is the wire model id,
/// and only the stated capability surface maps. A `via-handoff` sentinel
/// is not `true`, so it never marks vision; `name` and `display_name`
/// have no carrier in [`CatalogModel`].
fn models_info_entry(id: &str, entry: &Value) -> Option<CatalogModel> {
    if id.is_empty() {
        return None;
    }
    let reasoning = entry
        .pointer("/capabilities/reasoning/supported")
        .and_then(Value::as_bool)
        == Some(true);
    let efforts = if reasoning {
        entry
            .pointer("/capabilities/reasoning/levels")
            .and_then(Value::as_array)
            .map(|levels| {
                levels
                    .iter()
                    .filter_map(|level| level.as_str().and_then(wire_effort))
                    .collect()
            })
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    Some(CatalogModel {
        id: id.to_string(),
        reasoning,
        vision: entry
            .pointer("/capabilities/supports_vision")
            .and_then(Value::as_bool)
            == Some(true),
        tools: entry
            .pointer("/capabilities/supports_tools")
            .and_then(Value::as_bool)
            == Some(true),
        efforts,
        context_window: positive_count(entry.get("context_window")),
        max_output_tokens: positive_count(entry.get("max_completion_tokens")),
        ..CatalogModel::default()
    })
}

/// `{base}/v1/messages`, or `{base}/messages` when the configured base
/// already carries the version segment.
fn messages_url(base: &str) -> String {
    if base.ends_with("/v1") {
        format!("{base}/messages")
    } else {
        format!("{base}/v1/messages")
    }
}

fn lineage_key(manifest: &RequestManifest) -> LineageKey {
    (
        manifest.world.clone(),
        manifest.purpose.clone(),
        manifest.epoch_id.clone(),
    )
}

/// The recorded transformation types that mean the peer dropped a
/// replayed thinking block. Unknown transformation kinds are observed,
/// not counted as dropped reasoning.
fn transformations_in(connection: &str, payload: &Value) -> Result<u64, ProviderError> {
    let Some(value) = payload.get("input_transformations") else {
        return Ok(0);
    };
    let Some(entries) = value.as_array() else {
        return Err(violation(
            connection,
            "input_transformations is not an array",
        ));
    };
    Ok(entries
        .iter()
        .filter(|entry| {
            let kind = entry.as_str().or_else(|| {
                entry
                    .get("type")
                    .or_else(|| entry.get("name"))
                    .and_then(Value::as_str)
            });
            matches!(
                kind,
                Some("prefix_binding_mismatch" | "model_binding_mismatch")
            )
        })
        .count() as u64)
}

/// The permanent semantic error marker: a `400` whose body names an
/// invalid thinking signature. The body is bounded and never enters
/// diagnostics.
fn names_invalid_signature(body: &[u8]) -> bool {
    body.windows(b"Invalid signature".len())
        .any(|window| window == b"Invalid signature".as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_append_v1_only_when_the_base_lacks_it() {
        let contract = contract_for("anthropic").expect("the anthropic arm records");
        assert_eq!(endpoint_for(&contract, "  "), ANTHROPIC_DEFAULT_BASE);
        assert_eq!(
            endpoint_for(&contract, " https://api.anthropic.com/v1/ "),
            "https://api.anthropic.com/v1"
        );
        assert_eq!(
            models_url("https://api.anthropic.com"),
            "https://api.anthropic.com/v1/models"
        );
        assert_eq!(
            models_url("https://api.anthropic.com/v1"),
            "https://api.anthropic.com/v1/models"
        );
        assert_eq!(
            messages_url("https://api.anthropic.com"),
            "https://api.anthropic.com/v1/messages"
        );
        assert_eq!(
            messages_url("https://api.anthropic.com/v1"),
            "https://api.anthropic.com/v1/messages"
        );
    }

    #[test]
    fn umans_strips_the_version_segment_and_reads_models_info() {
        let contract = contract_for("umans").expect("the umans arm records");
        assert_eq!(endpoint_for(&contract, "  "), UMANS_DEFAULT_BASE);
        assert_eq!(
            endpoint_for(&contract, " https://api.code.umans.ai/v1/ "),
            "https://api.code.umans.ai"
        );
        assert_eq!(
            models_info_url("https://api.code.umans.ai"),
            "https://api.code.umans.ai/models/info"
        );
        assert_eq!(
            messages_url("https://api.code.umans.ai"),
            "https://api.code.umans.ai/v1/messages"
        );
    }

    #[test]
    fn minimax_keeps_its_base_verbatim() {
        let contract = contract_for("minimax").expect("the minimax arm records");
        assert_eq!(endpoint_for(&contract, "  "), MINIMAX_DEFAULT_BASE);
        assert_eq!(
            endpoint_for(&contract, " https://api.minimax.io/anthropic/v1/ "),
            "https://api.minimax.io/anthropic/v1",
            "the arm records no trailing /v1 strip"
        );
        assert_eq!(
            messages_url("https://api.minimax.io/anthropic"),
            "https://api.minimax.io/anthropic/v1/messages"
        );
    }

    #[test]
    fn tool_names_outside_the_messages_grammar_are_refused() {
        assert!(valid_tool_name("read_file"));
        assert!(valid_tool_name("read-file_2"));
        assert!(!valid_tool_name(""));
        assert!(!valid_tool_name("read file"));
        assert!(!valid_tool_name(&"x".repeat(129)));
    }

    #[test]
    fn cloudflare_keeps_the_configured_base_and_appends_the_messages_path() {
        let contract = contract_for("cloudflare-ai-gateway").expect("the cloudflare arm records");
        assert_eq!(
            endpoint_for(&contract, "  "),
            "",
            "no default gateway base is invented"
        );
        assert_eq!(
            endpoint_for(
                &contract,
                " https://gateway.ai.cloudflare.com/v1/account/gateway/anthropic/ "
            ),
            "https://gateway.ai.cloudflare.com/v1/account/gateway/anthropic"
        );
        assert_eq!(
            messages_url("https://gateway.ai.cloudflare.com/v1/account/gateway/anthropic"),
            "https://gateway.ai.cloudflare.com/v1/account/gateway/anthropic/v1/messages"
        );
    }

    #[test]
    fn vercel_resolves_the_recorded_base_and_the_gateway_paths() {
        let contract = contract_for("vercel-ai-gateway").expect("the gateway arm records");
        assert_eq!(
            endpoint_for(&contract, "  "),
            "https://ai-gateway.vercel.sh",
            "the empty sentinel resolves the recorded gateway base"
        );
        assert_eq!(
            models_url(&endpoint_for(&contract, "  ")),
            "https://ai-gateway.vercel.sh/v1/models"
        );
        assert_eq!(
            messages_url(&endpoint_for(&contract, "  ")),
            "https://ai-gateway.vercel.sh/v1/messages"
        );
        assert_eq!(
            endpoint_for(&contract, " https://gateway.example/v1/ "),
            "https://gateway.example/v1",
            "the configured base wins verbatim"
        );
        assert_eq!(
            models_url("https://gateway.example/v1"),
            "https://gateway.example/v1/models"
        );
        assert_eq!(
            messages_url("https://gateway.example/v1"),
            "https://gateway.example/v1/messages"
        );
    }
}
