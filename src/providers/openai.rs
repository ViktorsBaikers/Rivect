//! The OpenAI Responses dialect adapter (DEC-007/DEC-025, HZN-008) —
//! the literal connection ids `openai`, `abliteration`, `meta`,
//! `ollama`, `custom-responses`, `openrouter`, `sakana`, `xai`,
//! `xai-oauth`, `openai-codex` and `openai-codex-device` record this
//! dialect. `ollama`
//! is the local endpoint whose credential is optional (DEC-009) and
//! whose catalogue carries a bounded native discovery overlay
//! (DEC-012); `openrouter` rides the recorded paste-key form behind a
//! catalogue-only keyless listing (DEC-003/DEC-010); `sakana` rides a
//! key-gated authoritative listing whose in-source Fugu entries are
//! mapping references, never offers (DEC-004); `custom-responses` rides
//! an operator-configured origin with no default base — its listing is
//! the model source and an absent binding is the headerless custom-open
//! form (DEC-015); `xai` and `xai-oauth`
//! ride the authoritative xAI listing — the latter with the
//! device-code-produced token resolved at the scoped credential seam,
//! the former rejecting the listing's recorded negative effort residue.
//! Dialect selection keys
//! on the literal connection id, never an auth label or a catalogue
//! answer, and `openai-codex`/`openai-codex-device` are distinct literal
//! ids sharing one recorded ChatGPT Responses contract: the login
//! module's credential JSON is the bearer, its workspace scopes the
//! account discovery, and the closed route table bounds the wire.
//! `bedrock-mantle` rides the same Responses wire at the recorded
//! regional base, with a replace-on-success listing policy over its
//! five-id seed and the blocked static-key class named as such.
//! The adapter authors no async code — [`Provider::send`] is
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

use crate::config::{
    Config, ConnKind, Connection, EffortAssign, EffortLevel, FixedModel, ModelAssign,
};
use crate::model::{ImageInput, RequestManifest};
use crate::providers::aws;
use crate::providers::openai_login::{CodexCredential, LoginError as CodexLoginError};
use crate::providers::sse::{SseEvent, SseParser};
use crate::providers::{
    CatalogModel, CredentialStore, Dialect, ModelPrice, Provider, ProviderError, ProviderReply,
    STREAM_CHUNK_BYTES, ToolCall, WireAuth, bounded_reason, check_deadline, dialect_for,
    forwarded_header_map, loopback_base, open_proxy_connection, read_catalog_body, read_chunk,
    resolve_admitted_credential_in, route_for, routes_for, sse, transport, transport_status,
    violation, wire_body,
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

/// The recorded local `ollama` base (DEC-011): an empty configured
/// endpoint resolves here, and the configured value otherwise wins
/// after this adapter's trim — every trailing slash and surrounding
/// whitespace stripped.
const OLLAMA_DEFAULT_ENDPOINT: &str = "http://127.0.0.1:11434/v1";

/// The recorded `openrouter` base (DEC-003): an empty configured
/// endpoint resolves here, and a configured value otherwise wins after
/// this adapter's trim.
const OPENROUTER_DEFAULT_ENDPOINT: &str = "https://openrouter.ai/api/v1";

/// The recorded `sakana` base (DEC-004): an empty configured endpoint
/// resolves here, and a configured value otherwise wins after this
/// adapter's trim.
const SAKANA_DEFAULT_ENDPOINT: &str = "https://api.sakana.ai/v1";

/// The recorded `xai` base: an empty configured endpoint resolves here,
/// and a configured value otherwise wins after this adapter's trim.
const XAI_DEFAULT_ENDPOINT: &str = "https://api.x.ai/v1";

/// The recorded `xai-oauth` base: an empty configured endpoint resolves
/// here, and a configured value otherwise wins after this adapter's
/// trim. The device-code token is the credential, not a host selector.
const XAI_OAUTH_DEFAULT_ENDPOINT: &str = "https://api.x.ai/v1";

/// The recorded GitLab Duo OpenAI proxy base (DEC-013); the routed owner
/// supplies it as the codec's configured endpoint.
const GITLAB_RESPONSES_PROXY: &str = "https://cloud.gitlab.com/ai/v1/proxy/openai/v1";

/// The recorded `opencode-zen` Responses base: the routed owner passes
/// `{base}/v1` as the configured endpoint, and an empty endpoint
/// resolves this recorded API root.
const OPENCODE_ZEN_RESPONSES_BASE: &str = "https://opencode.ai/zen/v1";

/// The recorded `opencode-go` Responses base: the routed owner passes
/// `{base}/v1` as the configured endpoint, and an empty endpoint
/// resolves this recorded API root.
const OPENCODE_GO_RESPONSES_BASE: &str = "https://opencode.ai/zen/go/v1";

/// The Responses aliases' `upstreamModelId` table (DEC-013): the routed
/// owner translates the public alias before the wire.
const GITLAB_RESPONSES_MODELS: &[&str] = &["gpt-5-codex", "gpt-5.2-codex"];

/// The closed Codex route table (AC-040i): the account-scoped ChatGPT
/// listing may name other ids, but only these recorded Responses ids
/// ride the wire, and a pinned id outside the table denies before any
/// request. The device alias shares the one table.
const CODEX_MODELS: &[&str] = &["gpt-5-codex", "gpt-5.2-codex"];

/// The account-scope header the ChatGPT Codex backend binds a request
/// to (HZN-16-03): the workspace recorded on the scoped credential,
/// sent only when the credential carries one.
const CODEX_ACCOUNT_HEADER: &str = "chatgpt-account-id";

/// Whether a literal id records the Codex credential contract: the
/// canonical connection and its device alias share one backend and one
/// credential profile.
fn is_codex_connection(connection: &str) -> bool {
    matches!(connection, "openai-codex" | "openai-codex-device")
}

/// Whether one literal id's recorded contract forbids re-dispatching a
/// failed entered send onto a sibling literal of the same contract
/// (PROH-020). The routing owner consults this before minting a
/// fallback substitute; an id with no contract arm answers `false`.
pub(crate) fn refuses_blind_retry(connection: &str) -> bool {
    contract_for(connection).is_some_and(|contract| contract.blind_retry == BlindRetry::Refused)
}

/// Whether two literal ids resolve to the same recorded Codex contract
/// — the canonical id and its device alias — so a failure on one is a
/// failure of the one backend, never a fresh substitute target.
pub(crate) fn same_recorded_contract(left: &str, right: &str) -> bool {
    is_codex_connection(left) && is_codex_connection(right)
}

/// The recorded `openrouter` paste-key prefix (DEC-003): the bare
/// `sk-or-…` key the paste form stores at the scoped credential seam.
const OPENROUTER_KEY_PREFIX: &str = "sk-or-";

/// The most listed ids one native discovery phase probes (DEC-012).
const NATIVE_DISCOVERY_MAX_IDS: usize = 32;

/// The one advisory budget the native `/api/tags` + `/api/show`
/// overlay shares (DEC-012): an expired phase leaves the remaining
/// listing-only entries rather than extending the catalogue leg.
const NATIVE_DISCOVERY_BUDGET: Duration = Duration::from_millis(250);

/// The per-entry defaults when the native metadata carries no positive
/// context key (DEC-012).
const OLLAMA_DEFAULT_CONTEXT_WINDOW: u64 = 128_000;

/// The per-entry max output default (DEC-012).
const OLLAMA_DEFAULT_MAX_OUTPUT_TOKENS: u64 = 8_192;

/// The recorded source sample of Responses-capable model ids the
/// `openai` connection's catalogue surface filters `/models` to
/// (HZN-008): the static sample the offline contract pins — live
/// discovery is a later leg.
const RESPONSES_MODELS: &[&str] = &["gpt-5.2", "gpt-5.2-codex", "gpt-5.1", "o4-mini", "o3"];

/// The recorded closed seed of `bedrock-mantle` model ids (DEC-012):
/// the offer set a failed or unparseable listing keeps, replaced by a
/// successful authoritative listing — which may name no ids at all.
const MANTLE_MODELS: &[&str] = &[
    "openai.gpt-5.4",
    "openai.gpt-5.5",
    "openai.gpt-5.6-luna",
    "openai.gpt-5.6-sol",
    "openai.gpt-5.6-terra",
];

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

/// The recorded static Muse roster of `meta` model ids (HZN-008,
/// `META_MUSE_STATIC_MODELS`): the merge floor the catalogue unions
/// over the authoritative `/models` listing — a rostered id offers
/// even when the listing omits it. The recorded tiers ride verbatim:
/// `muse-spark-1.1` ships as the standard SKU only, while
/// `muse-spark-1.2` and `muse-spark-1.3` each carry both the
/// standard and the `-contributor` training-eligible variant, and
/// the Standard-or-Contributor payment predicate is stated by the
/// id itself, never chosen silently by omitting either half. The
/// record names an excluded-id filter but never its contents, so no
/// exclusion is applied here.
const META_MUSE_MODELS: &[&str] = &[
    "muse-spark-1.1",
    "muse-spark-1.2",
    "muse-spark-1.2-contributor",
    "muse-spark-1.3",
    "muse-spark-1.3-contributor",
];

/// How one listed `/models` entry becomes an offered
/// [`CatalogModel`]: the id alone under the contract's filter, the
/// entry's own tool-capable surfaces (`openrouter`, DEC-010), the
/// recorded `sakana` listing rule (DEC-004), the id-only `xai` listing
/// whose recorded negative effort residue bounds a pinned effort, or
/// the id-only `xai-oauth` listing whose selected-list floor is a
/// residual — no vendored ids are retained, so the listing alone offers
/// minus the recorded non-chat families.
#[derive(Clone, Copy)]
enum EntryRule {
    IdsOnly,
    OpenRouterTools,
    Sakana,
    Xai,
    XaiOAuth,
}

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
    /// omits them; `meta`: the same dynamic-plus-static rule over the
    /// recorded Muse roster); `false` — the listing filters to `seed`
    /// (`openai`: the recorded sample is the offer set).
    authoritative_models: bool,
    /// The per-id catalogue entry rule: `IdsOnly` offers the entry's
    /// id under `authoritative_models`/`seed`; `OpenRouterTools` offers
    /// only a tool-capable entry with its declared surfaces mapped;
    /// `Xai` shares that id-only offer under its recorded effort
    /// suppression, and `XaiOAuth` under its selected-list residual.
    entry: EntryRule,
    /// `true` — the request asks for the `reasoning.encrypted_content`
    /// artifact the replay contract carries (SRC-019/D-006); `false`
    /// — the recorded peer compat marks the gateway as never
    /// returning encrypted reasoning items, so the include is never
    /// requested (`abliteration`: every model reasons intrinsically —
    /// `reasoning: true` forced in the recorded mapper — and none
    /// returns a replayable artifact; `meta`: the record states no
    /// encrypted reasoning artifact for the id, so none is asked for).
    reasoning_artifact: bool,
    /// `true` — the origin is operator data and no default base exists
    /// (`custom-responses`, DEC-015): an empty configured endpoint
    /// denies [`crate::providers::ProviderError::EndpointRequired`]
    /// before the wire. `false` — [`endpoint_for`] resolves the arm's
    /// recorded default or keeps the shipped verbatim value.
    requires_configured_endpoint: bool,
    /// Whether a failed entered send may be re-dispatched onto a sibling
    /// literal of the same contract: `Refused` on the codex contract —
    /// an unknown remote outcome is final, never a blind same-backend
    /// retry (PROH-020) — and `Allowed` elsewhere. The routing owner
    /// consults this before minting a fallback substitute.
    blind_retry: BlindRetry,
}

/// Whether a failed entered send may be re-dispatched onto a sibling
/// literal of the same recorded contract (PROH-020). The routing owner
/// reads this through the contract arm before minting a substitute.
#[derive(Clone, Copy, PartialEq, Eq)]
enum BlindRetry {
    Allowed,
    Refused,
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
            entry: EntryRule::IdsOnly,
            reasoning_artifact: true,
            requires_configured_endpoint: false,
            blind_retry: BlindRetry::Allowed,
        }),
        // DEC-012: the recorded 5-id seed is kept when a listing fails
        // or is unparseable, and replaced by an authoritative listing;
        // the Responses wire and the encrypted reasoning artifact are
        // shared with `openai`.
        "bedrock-mantle" => Some(SourceContract {
            seed: MANTLE_MODELS,
            authoritative_models: false,
            entry: EntryRule::IdsOnly,
            reasoning_artifact: true,
            requires_configured_endpoint: false,
            blind_retry: BlindRetry::Allowed,
        }),
        "abliteration" => Some(SourceContract {
            seed: ABLITERATION_MODELS,
            authoritative_models: true,
            entry: EntryRule::IdsOnly,
            reasoning_artifact: false,
            requires_configured_endpoint: false,
            blind_retry: BlindRetry::Allowed,
        }),
        "meta" => Some(SourceContract {
            seed: META_MUSE_MODELS,
            authoritative_models: true,
            entry: EntryRule::IdsOnly,
            reasoning_artifact: false,
            requires_configured_endpoint: false,
            blind_retry: BlindRetry::Allowed,
        }),
        "ollama" => Some(SourceContract {
            seed: &[],
            authoritative_models: true,
            entry: EntryRule::IdsOnly,
            reasoning_artifact: false,
            requires_configured_endpoint: false,
            blind_retry: BlindRetry::Allowed,
        }),
        // The listing is authoritative and carries its own entry rule
        // (DEC-010): the keyless `/models` answer offers only what the
        // adapter can honour, and the record states no replay artifact
        // for the id.
        "openrouter" => Some(SourceContract {
            seed: &[],
            authoritative_models: true,
            entry: EntryRule::OpenRouterTools,
            reasoning_artifact: false,
            requires_configured_endpoint: false,
            blind_retry: BlindRetry::Allowed,
        }),
        // The listing is authoritative and carries its own entry rule
        // (DEC-004): the recorded in-source Fugu entries are mapping
        // references, so no seed merges an offer, and the record states
        // no replay artifact for the id.
        "sakana" => Some(SourceContract {
            seed: &[],
            authoritative_models: true,
            entry: EntryRule::Sakana,
            reasoning_artifact: false,
            requires_configured_endpoint: false,
            blind_retry: BlindRetry::Allowed,
        }),
        // The xAI listing is authoritative and carries no vendored
        // floor; its recorded negative effort residue bounds a pinned
        // effort, and the contract states no replay artifact for the id.
        "xai" => Some(SourceContract {
            seed: &[],
            authoritative_models: true,
            entry: EntryRule::Xai,
            reasoning_artifact: false,
            requires_configured_endpoint: false,
            blind_retry: BlindRetry::Allowed,
        }),
        // The xAI OAuth listing is authoritative and no vendored
        // selected list is retained, so the listing alone offers — minus
        // the recorded non-chat image/STT/voice families the chat picker
        // never shows — and the recorded compat asks for the encrypted
        // reasoning artifact the replay contract carries.
        "xai-oauth" => Some(SourceContract {
            seed: &[],
            authoritative_models: true,
            entry: EntryRule::XaiOAuth,
            reasoning_artifact: true,
            requires_configured_endpoint: false,
            blind_retry: BlindRetry::Allowed,
        }),
        // DEC-013: the routed owner translates the alias and passes the
        // fixed proxy base as the configured endpoint; the listing is
        // not a source — the alias table is.
        "gitlab-duo" => Some(SourceContract {
            seed: GITLAB_RESPONSES_MODELS,
            authoritative_models: true,
            entry: EntryRule::IdsOnly,
            reasoning_artifact: false,
            requires_configured_endpoint: false,
            blind_retry: BlindRetry::Allowed,
        }),
        // DEC-014/DEC-020: the routed owner passes `{base}/v1` as the
        // configured endpoint for the Muse Spark and deepseek-v4-flash
        // overrides; the gateway listing is the whole catalogue and
        // states no replay artifact for the id.
        "opencode-go" => Some(SourceContract {
            seed: &[],
            authoritative_models: true,
            entry: EntryRule::IdsOnly,
            reasoning_artifact: false,
            requires_configured_endpoint: false,
            blind_retry: BlindRetry::Allowed,
        }),
        // DEC-014: the routed owner passes `{base}/v1` as the
        // configured endpoint for the Muse Spark overrides; the
        // gateway listing is the whole catalogue and states no replay
        // artifact for the id.
        "opencode-zen" => Some(SourceContract {
            seed: &[],
            authoritative_models: true,
            entry: EntryRule::IdsOnly,
            reasoning_artifact: false,
            requires_configured_endpoint: false,
            blind_retry: BlindRetry::Allowed,
        }),
        // DEC-020/HZN-16-03: the ChatGPT account-scoped listing is the
        // discovery source, and the closed Codex route table is the
        // offer set — an HTTP 200 listing never releases an id outside
        // it. The device alias records the same contract: one backend,
        // one credential profile. The arm has no recorded default base,
        // so an empty endpoint denies before the wire.
        "openai-codex" | "openai-codex-device" => Some(SourceContract {
            seed: CODEX_MODELS,
            authoritative_models: false,
            entry: EntryRule::IdsOnly,
            reasoning_artifact: true,
            requires_configured_endpoint: true,
            blind_retry: BlindRetry::Refused,
        }),
        // DEC-004: the routed owner derives the CAPI base from the
        // stored credential and passes it as the configured endpoint, so
        // the arm requires one. The closed route table is the send gate,
        // and the record states the replay artifact the Responses wire
        // carries.
        "github-copilot" => Some(SourceContract {
            seed: &[],
            authoritative_models: false,
            entry: EntryRule::IdsOnly,
            reasoning_artifact: true,
            requires_configured_endpoint: true,
            blind_retry: BlindRetry::Allowed,
        }),
        // DEC-015: the origin is operator-configured, so no default base
        // is invented and an empty endpoint denies before the wire. The
        // listing is the model source (a pinned manual id sends without
        // it), an absent binding is the recorded custom-open headerless
        // form, and the record states no replay artifact for the id.
        "custom-responses" => Some(SourceContract {
            seed: &[],
            authoritative_models: true,
            entry: EntryRule::IdsOnly,
            reasoning_artifact: false,
            requires_configured_endpoint: true,
            blind_retry: BlindRetry::Allowed,
        }),
        _ => None,
    }
}

/// Whether one pinned Responses id carries the recorded image-input mark
/// (TD-21): the captured descriptor rows state `input: ["text", "image"]`
/// for the `bedrock-mantle` frontier seeds — the one Responses seed table
/// this build records with the mark — so a pin outside that table answers
/// `false` and the vision path denies typed instead of sending an image
/// the record never admitted.
fn recorded_image_input(connection: &str, model: &str) -> bool {
    match connection {
        "bedrock-mantle" => MANTLE_MODELS.contains(&model),
        _ => false,
    }
}

/// The connection's API base (DEC-011): the configured endpoint is
/// trimmed of surrounding whitespace and of every trailing slash —
/// this adapter's own normalization, not a rule the other adapters
/// share — and the empty result resolves the recorded base on `ollama`,
/// `openrouter`, `sakana`, `xai`, `xai-oauth`, `gitlab-duo`,
/// `opencode-go` and `opencode-zen` alone. Every other id
/// keeps the trimmed value verbatim; no id's base is ever inferred, and
/// an arm recording no default (`custom-responses`) denies the empty
/// result at assembly. `bedrock-mantle` bypasses this rule: its
/// configured region substitutes the recorded regional template at
/// assembly.
fn endpoint_for(connection: &str, configured: &str) -> String {
    let configured = configured.trim().trim_end_matches('/');
    if configured.is_empty() {
        match connection {
            "ollama" => OLLAMA_DEFAULT_ENDPOINT.to_string(),
            "openrouter" => OPENROUTER_DEFAULT_ENDPOINT.to_string(),
            "sakana" => SAKANA_DEFAULT_ENDPOINT.to_string(),
            "xai" => XAI_DEFAULT_ENDPOINT.to_string(),
            "xai-oauth" => XAI_OAUTH_DEFAULT_ENDPOINT.to_string(),
            "gitlab-duo" => GITLAB_RESPONSES_PROXY.to_string(),
            "opencode-go" => OPENCODE_GO_RESPONSES_BASE.to_string(),
            "opencode-zen" => OPENCODE_ZEN_RESPONSES_BASE.to_string(),
            _ => configured.to_string(),
        }
    } else {
        configured.to_string()
    }
}

/// The mantle base under one resolved region (DEC-012): the admitted
/// loopback override when present, else the recorded regional template.
/// Assembly and send share it so a pin's region and the seed id's
/// region reach the same host rewrite.
fn mantle_base_for(base_override: Option<&str>, region: &str) -> String {
    match base_override {
        Some(base) => base.to_owned(),
        None => aws::mantle_base(region),
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

/// The material one send authenticates with: the bearer token plus the
/// ChatGPT workspace the credential is bound to. Only the codex ids
/// record an account scope; every other arm carries `None` and sends no
/// account header.
struct WireMaterial {
    token: String,
    account: Option<String>,
}

/// Applies the scoped material to one outgoing request: the bearer and,
/// where the credential recorded a workspace, the account-scope header.
/// Both the catalogue and the inference leg use this one seam, so an
/// absent binding stays headerless on either leg and a recorded account
/// rides both.
fn authenticate(
    request: reqwest::blocking::RequestBuilder,
    material: Option<&WireMaterial>,
) -> reqwest::blocking::RequestBuilder {
    let Some(material) = material else {
        return request;
    };
    let request = request.bearer_auth(&material.token);
    match &material.account {
        Some(account) => request.header(CODEX_ACCOUNT_HEADER, account),
        None => request,
    }
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
    /// The configured endpoint base under DEC-011 — trimmed, every
    /// trailing slash stripped, and the recorded local default on
    /// `ollama` when that leaves nothing. On `bedrock-mantle` this is
    /// the regional base the resolved region substituted.
    endpoint: String,
    /// The configured region the mantle base resolves through; `None`
    /// for every Responses id whose endpoint contract admits no region.
    configured_region: Option<String>,
    /// The admitted loopback override for offline proof, when the caller
    /// supplied one. Kept beside the assembled endpoint so a send can
    /// rebuild the base under the pinned model's own region; `None`
    /// resolves the recorded regional template.
    mantle_base_override: Option<String>,
    /// The ambient region mantle resolution reads. Production leaves it
    /// `None` and follows the process environment; proof pins one so a
    /// developer's ambient region cannot move the resolved base.
    mantle_ambient_region: Option<String>,
    /// The most recent successful mantle listing; `None` before the
    /// first attempt and after a failed one, when the send gate falls
    /// back to the recorded seed instead of re-listing.
    mantle_offer: std::sync::Mutex<Option<Vec<String>>>,
    /// The credential seam: a scoped reference resolved per send — a
    /// rotation is honoured without rebuilding the adapter — or a
    /// preflight-resolved token the routed owner supplied. `Store(None)`
    /// is the recorded absent-binding form: no header rides either leg.
    auth: WireAuth,
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

/// The listed entries one native discovery phase probes (DEC-012): the
/// leading [`NATIVE_DISCOVERY_MAX_IDS`] offers, never the whole
/// listing.
fn probe_targets_mut(models: &mut [CatalogModel]) -> &mut [CatalogModel] {
    let probed = models.len().min(NATIVE_DISCOVERY_MAX_IDS);
    &mut models[..probed]
}

/// What the advisory phase has left (DEC-012): `None` once the budget
/// is spent, so every native request is clipped to the phase's total
/// clock instead of opening a fresh one per request.
fn phase_remaining(budget: Duration, phase: Instant) -> Option<Duration> {
    budget
        .checked_sub(phase.elapsed())
        .filter(|left| !left.is_zero())
}

impl OpenAiProvider {
    /// Builds the adapter for one connection id: the id must record
    /// the Responses dialect (DEC-007), the connection must be
    /// declared, carry no configured region the dialect's endpoint
    /// contract cannot honour (`bedrock-mantle` admits its region and
    /// substitutes it into the regional base), and resolve a scoped
    /// credential under DEC-013 precedence.
    ///
    /// # Errors
    /// [`ProviderError::DialectMismatch`] for a connection id without
    /// the Responses source class; [`ProviderError::UnknownConnection`]
    /// for an undeclared id; [`ProviderError::RegionMismatch`] for a
    /// configured region on an id whose endpoint contract admits none;
    /// [`ProviderError::EndpointRequired`] when the
    /// arm records no default base and the configured endpoint is
    /// empty; [`ProviderError::LocalProfileDeclared`] for a
    /// `local` declaration that binds a `profile`;
    /// [`ProviderError::CredentialUnresolved`] for a `local`
    /// declaration of a reserved id that is not an open proxy — denied
    /// by declaration kind before any credential resolves —
    /// `resolve_admitted_credential_in`'s typed
    /// denials for a malformed or mismatched binding on a required id
    /// (the admitted absent-binding class resolves `None`);
    /// [`ProviderError::Transport`] when the HTTP client cannot be
    /// built.
    pub fn new(
        config: &Config,
        connection: &str,
        store: Arc<dyn CredentialStore>,
    ) -> Result<Self, ProviderError> {
        Self::build(config, connection, store, REQUEST_DEADLINE, None, None)
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
        Self::build(config, connection, store, deadline, None, None)
    }

    /// Builds the adapter for a route-scoped construction. The routed
    /// owner is the caller: the gate is the id's recorded route table,
    /// and a preflight-resolved [`WireAuth`] skips the store resolve.
    ///
    /// # Errors
    /// [`Self::new`]'s contract, and
    /// [`ProviderError::DialectMismatch`] when the id's recorded routes
    /// do not include Responses.
    pub fn with_route(
        config: &Config,
        connection: &str,
        store: Arc<dyn CredentialStore>,
        deadline: Duration,
        auth: WireAuth,
    ) -> Result<Self, ProviderError> {
        if !routes_for(connection).contains(&Dialect::Responses) {
            return Err(ProviderError::DialectMismatch {
                connection: connection.to_string(),
            });
        }
        Self::assemble(config, connection, store, deadline, Some(auth), None)
    }

    /// Builds the `bedrock-mantle` adapter with a loopback base override
    /// for offline proof.
    ///
    /// The override is admitted only for a literal loopback host; a
    /// non-loopback value is refused before any send. No other id may
    /// take this seam.
    ///
    /// # Errors
    /// [`Self::new`]'s contract, [`ProviderError::DialectMismatch`] when
    /// `connection` is not `bedrock-mantle`, and
    /// [`ProviderError::UnsendableRequest`] when the override is not a
    /// loopback URL.
    pub fn with_mantle_base_override(
        config: &Config,
        connection: &str,
        store: Arc<dyn CredentialStore>,
        deadline: Duration,
        base_override: Option<String>,
    ) -> Result<Self, ProviderError> {
        if connection != "bedrock-mantle" {
            return Err(ProviderError::DialectMismatch {
                connection: connection.to_string(),
            });
        }
        Self::build(config, connection, store, deadline, None, base_override)
    }

    /// Fixes the ambient region mantle resolution reads. Production
    /// follows the process environment; proof pins one region so a
    /// developer's ambient value cannot move the resolved base.
    #[doc(hidden)]
    #[must_use]
    pub fn with_mantle_ambient_region(mut self, region: &str) -> Self {
        self.mantle_ambient_region = Some(region.to_owned());
        self
    }

    fn build(
        config: &Config,
        connection: &str,
        store: Arc<dyn CredentialStore>,
        deadline: Duration,
        auth: Option<WireAuth>,
        base_override: Option<String>,
    ) -> Result<Self, ProviderError> {
        if dialect_for(connection) != Some(Dialect::Responses) {
            return Err(ProviderError::DialectMismatch {
                connection: connection.to_string(),
            });
        }
        Self::assemble(config, connection, store, deadline, auth, base_override)
    }

    fn assemble(
        config: &Config,
        connection: &str,
        store: Arc<dyn CredentialStore>,
        deadline: Duration,
        auth: Option<WireAuth>,
        base_override: Option<String>,
    ) -> Result<Self, ProviderError> {
        // A Responses-classed id without its own recorded contract arm
        // is denied the same way — the predicates are recorded per
        // literal id, never inherited silently.
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
        // `bedrock-mantle` is the one Responses id whose recorded base is
        // region-scoped: its configured `region` is admitted and
        // substituted at assembly, because the recorded ids carry no geo
        // prefix to resolve later. Every other id keeps the shipped
        // blanket denial.
        if connection != "bedrock-mantle"
            && let Some(region) = &conn.region
        {
            return Err(ProviderError::RegionMismatch {
                connection: connection.to_string(),
                region: region.clone(),
            });
        }
        // A `local` declaration names a locally served endpoint that
        // binds no credential; a `profile` member is the contradictory
        // half of the declaration — it must not turn the row into a
        // credentialled sender (DEC-009/DEC-010, DEC-023). The profile
        // half is named first so the operator fixes the right member;
        // the reserved Responses ids still deny the kind itself before
        // any credential resolution, and an open-proxy `ollama` that
        // binds no profile stays admitted.
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
        // DEC-015: an arm recording no default base has no host unless
        // the operator supplied one — deny before the credential seam
        // or any wire leg. `bedrock-mantle` records a regional template
        // instead: the configured region, else the ambient region, else
        // us-east-1, substituted at assembly. The admitted Bearer
        // material carries no region and the only form that does is the
        // blocked static-key class, so no material rank contributes here
        // (DEC-017).
        let base_override = match base_override {
            Some(raw) => Some(loopback_base(connection, &raw)?),
            None => None,
        };
        let (endpoint, configured_region, mantle_base_override) = if connection == "bedrock-mantle"
        {
            let ambient = aws::ambient_region();
            let region = aws::resolve_region(
                connection,
                MANTLE_MODELS[0],
                conn.region.as_deref(),
                None,
                ambient.as_deref(),
            )?;
            let endpoint = mantle_base_for(base_override.as_deref(), &region);
            (endpoint, conn.region.clone(), base_override)
        } else {
            (endpoint_for(connection, &conn.endpoint), None, None)
        };
        if contract.requires_configured_endpoint && endpoint.is_empty() {
            return Err(ProviderError::EndpointRequired {
                connection: connection.to_string(),
            });
        }
        // The admitted absent-binding classes — the open proxy, the
        // local endpoint, the custom-origin id and the catalogue-only
        // `openrouter` — resolve `None` for a declaration that binds
        // nothing; every required Responses id resolves through the
        // same precedence and keeps its typed denial when nothing binds
        // (DEC-009/DEC-010/DEC-015).
        let auth = match auth {
            Some(auth) => auth,
            None => WireAuth::Store(resolve_admitted_credential_in(
                &config.connections,
                &config.profiles,
                connection,
            )?),
        };
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
            endpoint,
            configured_region,
            mantle_base_override,
            mantle_ambient_region: None,
            mantle_offer: std::sync::Mutex::new(None),
            auth,
            store,
            client,
            deadline,
            lineages: BTreeMap::new(),
            blob_owner: BTreeMap::new(),
        })
    }

    /// The base assembly resolved: the admitted loopback override or the
    /// recorded regional template under the assembled region. A
    /// `bedrock-mantle` send rebuilds it for the pinned model through
    /// [`Self::mantle_send_base`], because the pin's geo can name a
    /// different region than the seed id assembly resolved.
    #[doc(hidden)]
    #[must_use]
    pub fn resolved_base(&self) -> &str {
        &self.endpoint
    }

    /// The base a mantle send builds for `model`: the admitted loopback
    /// override, else the regional template of the region resolved for
    /// that pin — the send's own region gate, run without a wire.
    ///
    /// # Errors
    /// [`ProviderError::RegionMismatch`] when the configured region
    /// cannot serve the model's geo.
    #[doc(hidden)]
    pub fn mantle_send_base(&self, model: &str) -> Result<String, ProviderError> {
        let region = aws::resolve_region(
            &self.connection,
            model,
            self.configured_region.as_deref(),
            None,
            self.ambient_region().as_deref(),
        )?;
        Ok(mantle_base_for(
            self.mantle_base_override.as_deref(),
            &region,
        ))
    }

    /// The ambient region mantle resolution reads: the proof-pinned one,
    /// else the process environment.
    fn ambient_region(&self) -> Option<String> {
        self.mantle_ambient_region
            .clone()
            .or_else(aws::ambient_region)
    }

    /// Whether the literal id's recorded contract asks the peer for the
    /// encrypted reasoning artifact the replay contract needs.
    #[doc(hidden)]
    #[must_use]
    pub fn declares_reasoning_artifact(&self) -> bool {
        self.contract.reasoning_artifact
    }

    /// Whether the literal id's recorded contract requires a configured
    /// endpoint before assembly.
    #[doc(hidden)]
    #[must_use]
    pub fn requires_configured_endpoint(&self) -> bool {
        self.contract.requires_configured_endpoint
    }

    /// The model catalogue for this connection (HZN-008): the ids of
    /// [`catalog_models`](Self::catalog_models) in the same
    /// deterministic sorted order, carrying the literal id's recorded
    /// rule and any bounded discovery overlay.
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

    /// The rich catalogue (DEC-007): `GET /models` under the literal
    /// id's recorded rule — `openai` filters the listing to the
    /// recorded Responses-capable sample, `abliteration` and `meta`
    /// treat the listing as authoritative and merge their static
    /// source seeds on top, `ollama` enriches the listing's own
    /// offers from the bounded native discovery overlay (DEC-012), and
    /// `bedrock-mantle` offers the most recent attempt's regional
    /// listing — authoritative even when it names no offer — else its
    /// recorded five-id seed, with a failed attempt reverting to that
    /// seed for a missing/non-array `data` or an
    /// HTTP/transport/parse failure, never an error — `openrouter`
    /// offers only the listing's tool-capable
    /// entries with their recorded surfaces mapped (DEC-010), `sakana`
    /// offers the authoritative listing's entries with the recorded Fugu
    /// mapping (DEC-004), `custom-responses` offers the authoritative listing
    /// alone (DEC-015), and `xai` offers the authoritative xAI listing as
    /// id-only entries with no vendored selected-list floor while
    /// `xai-oauth` offers the same listing minus its recorded non-chat
    /// image/STT/voice families — and `openai-codex`/`openai-codex-device`
    /// offer the account-scoped ChatGPT listing filtered to the closed
    /// recorded route table — each id carrying the shared
    /// [`CatalogModel`], returned in deterministic sorted order.
    ///
    /// # Errors
    /// The credential seam's typed denials, [`ProviderError::Transport`]
    /// on a failed call or non-success status or an expired whole-call
    /// budget, and [`ProviderError::StreamViolation`] when the payload
    /// does not carry the `data` array the contract requires. A
    /// `bedrock-mantle` discovery failure is the recorded exception: it
    /// answers the retained seed instead of an error.
    pub fn catalog_models(&self) -> Result<Vec<CatalogModel>, ProviderError> {
        // A standalone lookup opens its own whole-call budget — the
        // credential resolution and the wire leg share it, the same
        // bound a send's catalogue leg rides.
        let started = Instant::now();
        // The store call itself cannot be interrupted once running —
        // the check before it is the only point an expired budget
        // still denies the resolve without touching the seam.
        check_deadline(&self.connection, self.deadline, started)?;
        let token = self.secret()?;
        let mut models = self.catalog_within(token.as_ref(), started)?;
        // The overlay is advisory: it enriches the listing's own
        // offers and never extends or replaces them (DEC-012) — and it
        // spends the caller's clock like every other leg, so a peer
        // answering past the whole-call budget is the typed deadline,
        // never a late catalogue.
        if self.connection == "ollama" {
            self.enrich_native(&mut models, started);
            check_deadline(&self.connection, self.deadline, started)?;
        }
        Ok(models)
    }

    /// The catalogue leg under the caller's clock and credential —
    /// a send passes its own `started` so the lookup spends the same
    /// whole-request budget instead of opening a second, unaccounted
    /// one. An absent token on the recorded optional class sends no
    /// `Authorization` header, and the codex account header rides only
    /// where the scoped credential recorded a workspace.
    fn catalog_within(
        &self,
        token: Option<&WireMaterial>,
        started: Instant,
    ) -> Result<Vec<CatalogModel>, ProviderError> {
        // Mantle discovery is its own policy (DEC-012): a successful
        // listing replaces the seed and a failed or unparseable one
        // keeps it with no error. The branch sits before the shared
        // deadline denial so a listing that spends the clock is the
        // recorded fallback, not a catalogue error.
        if self.connection == "bedrock-mantle" {
            return Ok(self.mantle_catalog(token, started));
        }
        check_deadline(&self.connection, self.deadline, started)?;
        let mut request = self.client.get(format!("{}/models", self.endpoint));
        request = authenticate(request, token);
        request = request.headers(forwarded_header_map(self.auth.forwarded()));
        let mut response = request
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
        // while `abliteration`, `meta`, `ollama`, `openrouter`,
        // `sakana`, `xai` and `xai-oauth` treat the listing as
        // authoritative: every offered entry answers, and a seed the
        // arm carries merges on top as the offer floor.
        let mut models: Vec<CatalogModel> = data
            .iter()
            .filter_map(|entry| self.catalog_entry(entry))
            .collect();
        if self.contract.authoritative_models {
            models.extend(self.contract.seed.iter().map(|id| CatalogModel {
                id: (*id).to_string(),
                ..CatalogModel::default()
            }));
            models.sort_by(|a, b| a.id.cmp(&b.id));
            models.dedup_by(|a, b| a.id == b.id);
        } else {
            models.sort_by(|a, b| a.id.cmp(&b.id));
        }
        Ok(models)
    }

    /// The mantle catalogue policy (DEC-012): a successful parseable
    /// listing is authoritative and replaces the recorded seed; any
    /// failed, unparseable or truncated listing keeps the seed, with no
    /// error. The successful ids are retained so the send gate reflects
    /// the same offer set the catalogue just answered.
    fn mantle_catalog(&self, token: Option<&WireMaterial>, started: Instant) -> Vec<CatalogModel> {
        let listing = self.mantle_listing(token, started);
        let offer = listing
            .as_ref()
            .map(|models| models.iter().map(|model| model.id.clone()).collect());
        match self.mantle_offer.lock() {
            Ok(mut retained) => *retained = offer,
            Err(poisoned) => *poisoned.into_inner() = offer,
        }
        match listing {
            Some(models) => models,
            None => self.mantle_seed(),
        }
    }

    /// The recorded 5-id seed, offered when discovery fails.
    fn mantle_seed(&self) -> Vec<CatalogModel> {
        MANTLE_MODELS
            .iter()
            .map(|id| CatalogModel {
                id: (*id).to_string(),
                ..CatalogModel::default()
            })
            .collect()
    }

    /// Whether `model_id` is inside the current mantle offer set: the
    /// most recent attempt's listing, with a failed attempt reverting to
    /// the recorded seed. A poisoned lock recovers the retained set —
    /// the ids are always valid.
    fn mantle_offered(&self, model_id: &str) -> bool {
        let retained = match self.mantle_offer.lock() {
            Ok(offer) => offer,
            Err(poisoned) => poisoned.into_inner(),
        };
        match retained.as_ref() {
            Some(offer) => offer.iter().any(|id| id == model_id),
            None => MANTLE_MODELS.contains(&model_id),
        }
    }

    /// One mantle listing attempt: `GET {base-without-/openai/v1}/v1/models`
    /// under the resolved bearer. Every failure — transport, non-success,
    /// a missing or non-array `data`, or an unreadable/unparseable
    /// payload — answers `None`, and the caller keeps the seed, because
    /// the record marks a failed discovery non-fatal. A 200 whose `data`
    /// is an array is a successful listing even when it names no id:
    /// zero offers is authoritative, not a failure.
    fn mantle_listing(
        &self,
        token: Option<&WireMaterial>,
        started: Instant,
    ) -> Option<Vec<CatalogModel>> {
        if check_deadline(&self.connection, self.deadline, started).is_err() {
            return None;
        }
        let mut request = self.client.get(self.mantle_discovery_url());
        request = authenticate(request, token);
        request = request.headers(forwarded_header_map(self.auth.forwarded()));
        let Ok(mut response) = request.send() else {
            return None;
        };
        if !response.status().is_success() {
            return None;
        }
        let Ok(body) = read_catalog_body(&self.connection, self.deadline, &mut response, started)
        else {
            return None;
        };
        let Ok(payload) = serde_json::from_slice::<Value>(&body) else {
            return None;
        };
        let entries = payload.get("data").and_then(Value::as_array)?;
        let mut models: Vec<CatalogModel> = entries
            .iter()
            .filter_map(|entry| {
                let id = entry.get("id").and_then(Value::as_str)?;
                (!id.is_empty()).then(|| CatalogModel {
                    id: id.to_string(),
                    ..CatalogModel::default()
                })
            })
            .collect();
        models.sort_by(|a, b| a.id.cmp(&b.id));
        models.dedup_by(|a, b| a.id == b.id);
        // A 200 whose `data` is an array is a successful authoritative
        // listing, `[]` included: entries without an id contribute no
        // offer, and zero offers is a real answer, never the seed.
        Some(models)
    }

    /// The recorded discovery rewrite (DEC-012): the model base's
    /// `/openai/v1` segment becomes `/v1`, then `/models` — at the same
    /// regional host. A loopback override takes the same rewrite, so the
    /// wire proof exercises the recorded path.
    fn mantle_discovery_url(&self) -> String {
        if let Some(region) = &self.configured_region
            && self.endpoint == aws::mantle_base(region)
        {
            return aws::mantle_discovery_base(region);
        }
        let root = self
            .endpoint
            .strip_suffix("/openai/v1")
            .unwrap_or(&self.endpoint);
        format!("{root}/v1/models")
    }

    /// One listed entry under the literal id's recorded entry rule:
    /// `EntryRule::OpenRouterTools` offers only an entry whose
    /// `supported_parameters` declares `tools` and maps that entry's own
    /// surfaces (DEC-010); `EntryRule::Sakana` maps the recorded listing
    /// rule (DEC-004); `EntryRule::IdsOnly` offers the id alone under the
    /// contract's filter; `EntryRule::Xai` shares that id-only offer under
    /// its authoritative listing, since no vendored selected list is
    /// retained; `EntryRule::XaiOAuth` offers the same id-only listing
    /// minus its recorded non-chat image/STT/voice families.
    fn catalog_entry(&self, entry: &Value) -> Option<CatalogModel> {
        match self.contract.entry {
            EntryRule::OpenRouterTools => openrouter_model(entry),
            EntryRule::Sakana => sakana_model(entry),
            EntryRule::XaiOAuth => {
                let id = entry.get("id").and_then(Value::as_str)?;
                (!id.is_empty() && !xai_oauth_excludes(id)).then(|| CatalogModel {
                    id: id.to_string(),
                    ..CatalogModel::default()
                })
            }
            EntryRule::IdsOnly | EntryRule::Xai => {
                let id = entry.get("id").and_then(Value::as_str)?;
                let offered = if self.contract.authoritative_models {
                    !id.is_empty()
                } else {
                    self.contract.seed.contains(&id)
                };
                offered.then(|| CatalogModel {
                    id: id.to_string(),
                    ..CatalogModel::default()
                })
            }
        }
    }

    /// Reads the credential material for this send — the only place
    /// secret bytes cross the store boundary. The absent binding
    /// resolves `None` and sends no header (DEC-009); a non-UTF-8
    /// secret cannot be a bearer token: typed denial, never a mangled
    /// header. `openrouter` admits the recorded paste-key grammar only
    /// (DEC-003): material outside `sk-or-…` denies typed here, before
    /// any wire leg. The codex ids store the login module's credential
    /// JSON, read back through that module's own parser: the access
    /// token is the bearer and the recorded workspace is the account
    /// scope, so foreign material (unparseable JSON, or a blank access
    /// token) denies `CredentialMalformed` instead of crossing the wire
    /// as JSON.
    fn secret(&self) -> Result<Option<WireMaterial>, ProviderError> {
        if is_codex_connection(&self.connection) {
            return self.codex_material();
        }
        if self.connection == "bedrock-mantle" {
            return self.mantle_material();
        }
        let material = match &self.auth {
            WireAuth::Store(None) => return Ok(None),
            WireAuth::Store(Some(credential)) => self.store.resolve(credential)?,
            WireAuth::Resolved { token, .. } => token.clone().into_bytes(),
        };
        let token =
            String::from_utf8(material).map_err(|_utf8| ProviderError::CredentialMalformed {
                connection: self.connection.clone(),
            })?;
        if self.connection != "openrouter" {
            return Ok(Some(WireMaterial {
                token,
                account: None,
            }));
        }
        let token = token.trim();
        if !is_openrouter_paste_key(token) {
            return Err(ProviderError::CredentialMalformed {
                connection: self.connection.clone(),
            });
        }
        Ok(Some(WireMaterial {
            token: token.to_string(),
            account: None,
        }))
    }

    /// The codex credential arm: the login module reads the stored JSON
    /// (its store denial keeps its typed class), and material that is not
    /// the recorded credential shape — or whose access token is blank
    /// after trim — is `CredentialMalformed` before any wire leg. A
    /// pre-resolved token is refused typed: the routed constructor never
    /// supplies one for a codex id, and a bare bearer cannot prove it is
    /// the stored credential the workspace scope is recorded on.
    fn codex_material(&self) -> Result<Option<WireMaterial>, ProviderError> {
        let credential: CodexCredential = match &self.auth {
            WireAuth::Store(None) => return Ok(None),
            WireAuth::Store(Some(reference)) => {
                match crate::providers::openai_login::read_credential(
                    self.store.as_ref(),
                    reference,
                ) {
                    Ok(credential) => credential,
                    Err(CodexLoginError::Provider(error)) => return Err(error),
                    Err(_malformed) => {
                        return Err(ProviderError::CredentialMalformed {
                            connection: self.connection.clone(),
                        });
                    }
                }
            }
            WireAuth::Resolved { .. } => {
                return Err(ProviderError::CredentialMalformed {
                    connection: self.connection.clone(),
                });
            }
        };
        let token = credential.access_token().trim();
        if token.is_empty() {
            return Err(ProviderError::CredentialMalformed {
                connection: self.connection.clone(),
            });
        }
        Ok(Some(WireMaterial {
            token: token.to_string(),
            account: credential.account_id().map(str::to_string),
        }))
    }

    /// The mantle credential arm: the recorded Bearer forms — a raw
    /// token or `{bearer_token}` — are the only admitted material. The
    /// static-key form (and any object naming either static-key member)
    /// is the recorded SigV4 class this build blocks, denied typed
    /// before any request; every other shape keeps the shared parser's
    /// malformed/blocked denial.
    fn mantle_material(&self) -> Result<Option<WireMaterial>, ProviderError> {
        let material = match &self.auth {
            WireAuth::Store(None) => return Ok(None),
            WireAuth::Store(Some(credential)) => self.store.resolve(credential)?,
            WireAuth::Resolved { token, .. } => token.clone().into_bytes(),
        };
        // A partial static-key object is not a closed Bearer form, but
        // its class is still SigV4 — classify it before the parser's
        // generic object denial.
        if let Ok(Value::Object(object)) = serde_json::from_slice::<Value>(&material)
            && (object.contains_key("access_key_id") || object.contains_key("secret_access_key"))
        {
            return Err(ProviderError::UnsupportedCredentialClass {
                connection: self.connection.clone(),
                class: "sigv4",
            });
        }
        match aws::parse_material(&self.connection, &material)? {
            aws::AwsMaterial::Bearer(token) => Ok(Some(WireMaterial {
                token,
                account: None,
            })),
            aws::AwsMaterial::StaticKeys { .. } => Err(ProviderError::UnsupportedCredentialClass {
                connection: self.connection.clone(),
                class: "sigv4",
            }),
        }
    }

    /// The recorded xAI negative effort suppression (HZN-008): the
    /// listing's residue ids reject the `reasoning.effort` dial, so a
    /// pinned effort on one denies typed before the body exists. The
    /// suppression bounds both xAI listings — the paid key and the OAuth
    /// device-code surface — and the positive effort ladder is a
    /// residual, so an id outside the residue keeps the pin.
    fn check_effort(
        &self,
        manifest: &RequestManifest,
        model_id: &str,
    ) -> Result<(), ProviderError> {
        if !matches!(self.contract.entry, EntryRule::Xai | EntryRule::XaiOAuth)
            || !matches!(&manifest.effort, EffortAssign::Fixed { .. })
            || !xai_suppresses_effort(model_id)
        {
            return Ok(());
        }
        Err(ProviderError::UnsupportedParameter {
            connection: self.connection.clone(),
            parameter: "reasoning_effort",
            model: model_id.to_string(),
        })
    }

    /// The bounded native discovery overlay (DEC-012): the configured
    /// base minus one trailing `/v1` answers `/api/tags`, then
    /// `/api/show` per listed id under one advisory phase — at most 32
    /// ids and the smaller of the recorded 250 ms and the whole
    /// call's remainder. Each request is clipped to what the phase has
    /// left, so the phase is a total bound rather than a per-request
    /// one. Every failure is non-fatal — the entry keeps its
    /// listing-only surface — while the phase's own spend stays
    /// inside the caller's clock, so a peer answering past it is the
    /// typed deadline rather than a late catalogue.
    fn enrich_native(&self, models: &mut [CatalogModel], started: Instant) {
        let Some(budget) = self
            .deadline
            .checked_sub(started.elapsed())
            .map(|left| left.min(NATIVE_DISCOVERY_BUDGET))
            .filter(|left| !left.is_zero())
        else {
            return;
        };
        let native_base = self.endpoint.strip_suffix("/v1").unwrap_or(&self.endpoint);
        let phase = Instant::now();
        if !self.native_tags(native_base, budget, phase) {
            return;
        }
        for model in probe_targets_mut(models) {
            if phase_remaining(budget, phase).is_none() {
                break;
            }
            if let Some(metadata) = self.native_show(native_base, &model.id, budget, phase) {
                model.reasoning = metadata.reasoning;
                model.vision = metadata.vision;
                model.context_window = Some(metadata.context_window);
                model.max_output_tokens = Some(metadata.max_output_tokens);
            }
        }
    }

    /// The native liveness probe: unauthenticated, part of the same
    /// advisory phase. A non-success or unreadable answer skips the
    /// show fanout.
    fn native_tags(&self, native_base: &str, budget: Duration, phase: Instant) -> bool {
        let Some(remaining) = phase_remaining(budget, phase) else {
            return false;
        };
        let started = Instant::now();
        let mut response = match self
            .client
            .get(format!("{native_base}/api/tags"))
            .timeout(remaining)
            .send()
        {
            Ok(response) => response,
            Err(_err) => return false,
        };
        if !response.status().is_success() {
            return false;
        }
        read_catalog_body(&self.connection, remaining, &mut response, started).is_ok()
    }

    /// One unauthenticated `/api/show` probe for a listed id, bounded
    /// by the advisory phase. Any failure leaves the id listing-only.
    fn native_show(
        &self,
        native_base: &str,
        id: &str,
        budget: Duration,
        phase: Instant,
    ) -> Option<NativeMetadata> {
        let remaining = phase_remaining(budget, phase)?;
        let started = Instant::now();
        let body = match serde_json::to_vec(&json!({ "model": id })) {
            Ok(body) => body,
            Err(_err) => return None,
        };
        let mut response = match self
            .client
            .post(format!("{native_base}/api/show"))
            .timeout(remaining)
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
            Some(NativeMetadata::from_show(&payload))
        } else {
            None
        }
    }

    /// The RFC 4648 §4 base64 alphabet the Responses `data:` URL uses.
    const BASE64_ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    /// Encodes `bytes` as padded base64: every three bytes become four
    /// symbols and a trailing one or two bytes are `=`-padded. The one
    /// alphabet the wire contract names is in-repo — a dependency would
    /// add a format surface this adapter never sends.
    fn base64_encode(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
        for chunk in bytes.chunks(3) {
            let mut block = [0u8; 3];
            block[..chunk.len()].copy_from_slice(chunk);
            let bits = u32::from(block[0]) << 16 | u32::from(block[1]) << 8 | u32::from(block[2]);
            let symbol =
                |shift: u32| Self::BASE64_ALPHABET[((bits >> shift) & 0x3f) as usize] as char;
            out.push(symbol(18));
            out.push(symbol(12));
            out.push(if chunk.len() > 1 { symbol(6) } else { '=' });
            out.push(if chunk.len() > 2 { symbol(0) } else { '=' });
        }
        out
    }

    /// The `data:` URL one typed image occupies on the Responses wire
    /// (TD-21): the sniffed media type, the base64 alphabet and the raw
    /// bytes' padded encoding — the exact bytes the frozen manifest
    /// accounted as [`ImageInput::encoded_len`].
    fn image_data_url(image: &ImageInput) -> String {
        format!(
            "data:{};base64,{}",
            image.media().wire_media(),
            Self::base64_encode(image.bytes())
        )
    }

    /// The frozen manifest as the Responses wire request (AC-013):
    /// model pin, instructions and the declared tool surface verbatim,
    /// `store: false` and `stream: true` always,
    /// `include = ["reasoning.encrypted_content"]` where the recorded
    /// peer returns the reasoning artifact the replay contract carries
    /// (SRC-019/D-006), the pinned effort on the reasoning surface,
    /// the frozen image as one `input_image` part in the same user
    /// message as its text, and the epoch's recorded output items
    /// replayed ahead of the new input — the stateless replay the
    /// `store: false` contract requires.
    ///
    /// The replay set is bound by `MODEL_WIRE_MAX_BYTES`: once a
    /// lineage's committed items serialize past it, every send under
    /// that epoch fails `UnsendableRequest` — items are never evicted,
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
        let mut content = vec![json!({ "type": "input_text", "text": manifest.inputs })];
        if let Some(image) = &manifest.image {
            content.push(json!({
                "type": "input_image",
                "image_url": Self::image_data_url(image),
            }));
        }
        input.push(json!({ "role": "user", "content": content }));
        let mut body = json!({
            "model": fixed.model_id,
            "instructions": manifest.instructions,
            "input": input,
            "store": false,
            "stream": true,
        });
        // The replay-artifact include rides only where the recorded
        // peer returns encrypted reasoning items (SRC-019/D-006):
        // `abliteration` never does — its recorded compat marks
        // `include-encrypted-reasoning #false` — and `meta`'s record
        // states no artifact either, so neither request ever asks.
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
            wire_retries: 0,
            dropped_reasoning: 0,
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
        // The recorded detail objects: a cached prompt share and a reasoning
        // share already folded into the completion count. Absent stays
        // unknown and the report stays exact.
        let cache_read = usage
            .get("input_tokens_details")
            .and_then(|details| details.get("cached_tokens"))
            .and_then(Value::as_u64);
        let reasoning = usage
            .get("output_tokens_details")
            .and_then(|details| details.get("reasoning_tokens"))
            .and_then(Value::as_u64);
        match (input, output, total) {
            // The reported total is charged verbatim — never re-summed
            // — and a usage object that withholds it is a wire
            // violation, not an estimate the peer never charged.
            (Some(prompt_tokens), Some(completion_tokens), Some(total_tokens)) => {
                // Cached input tokens are a subset of `input_tokens` in
                // this dialect, so the input leg is uncached input only.
                // shortcut: dialect semantics normalized at the adapter; revisit if a provider changes the inclusion rule
                let uncached = prompt_tokens.saturating_sub(cache_read.unwrap_or(0));
                Ok(UsageDelta::from_reported(
                    uncached,
                    completion_tokens,
                    total_tokens,
                    reasoning,
                    cache_read,
                    None,
                ))
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

/// The recorded per-entry surface one successful `/api/show` probe
/// contributes (DEC-012): capability marks plus the first positive
/// context key, with the recorded defaults when the metadata carries
/// none.
struct NativeMetadata {
    reasoning: bool,
    vision: bool,
    context_window: u64,
    max_output_tokens: u64,
}

impl NativeMetadata {
    fn from_show(payload: &Value) -> Self {
        let capabilities = payload.get("capabilities").and_then(Value::as_array);
        let declares = |name: &str| {
            capabilities
                .is_some_and(|values| values.iter().any(|value| value.as_str() == Some(name)))
        };
        Self {
            reasoning: declares("thinking"),
            vision: declares("vision"),
            context_window: native_context_window(payload).unwrap_or(OLLAMA_DEFAULT_CONTEXT_WINDOW),
            max_output_tokens: OLLAMA_DEFAULT_MAX_OUTPUT_TOKENS,
        }
    }
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

/// The recorded xAI OAuth non-chat prefixes (HZN-008): `/models` also
/// lists image, speech-to-text and voice entries whose dedicated tool
/// surfaces carry their own model strings, so the chat picker never
/// offers them. The paid `xai` record states no such filter.
fn xai_oauth_excludes(model_id: &str) -> bool {
    ["grok-imagine-", "grok-stt-", "grok-voice-"]
        .iter()
        .any(|prefix| model_id.starts_with(prefix))
}

/// The recorded xAI effort residue (HZN-008): the listing's
/// `*reasoning`, `grok-build*`, `grok-code-fast*` and `*composer*` ids
/// reject the `reasoning.effort` dial. Every other id keeps the pin —
/// the recorded positive ladder is a residual, never an allowlist.
fn xai_suppresses_effort(model_id: &str) -> bool {
    model_id.ends_with("reasoning")
        || model_id.starts_with("grok-build")
        || model_id.starts_with("grok-code-fast")
        || model_id.contains("composer")
}

/// The recorded `openrouter` paste-key grammar (DEC-003): `sk-or-`,
/// then one or more base characters. Another product's `sk-…` token, a
/// JSON blob or empty material is not the recorded paste form.
fn is_openrouter_paste_key(token: &str) -> bool {
    let Some(rest) = token.strip_prefix(OPENROUTER_KEY_PREFIX) else {
        return false;
    };
    !rest.is_empty()
        && rest.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'~' | b'+' | b'/' | b'-')
        })
}

/// One `openrouter` listing entry under the recorded catalogue rule
/// (DEC-010): only an entry whose `supported_parameters` declares
/// `tools` is offered — the surface this adapter's request can honour
/// — and the entry's declared capabilities map onto the shared record.
/// An absent or invalid field stays empty or unknown; the listing never
/// supplies a default figure.
fn openrouter_model(entry: &Value) -> Option<CatalogModel> {
    let id = entry
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())?;
    let declares = |name: &str| {
        entry
            .get("supported_parameters")
            .and_then(Value::as_array)
            .is_some_and(|values| values.iter().any(|value| value.as_str() == Some(name)))
    };
    if !declares("tools") {
        return None;
    }
    Some(CatalogModel {
        id: id.to_string(),
        reasoning: declares("reasoning"),
        vision: entry
            .pointer("/architecture/input_modalities")
            .and_then(Value::as_array)
            .is_some_and(|modalities| {
                modalities
                    .iter()
                    .any(|modality| modality.as_str() == Some("image"))
            }),
        context_window: entry.get("context_length").and_then(positive_tokens),
        max_output_tokens: entry
            .pointer("/top_provider/max_completion_tokens")
            .and_then(positive_tokens),
        price: openrouter_price(entry),
        ..CatalogModel::default()
    })
}

/// One `sakana` listing entry under the recorded catalogue rule
/// (DEC-004): the listing alone names offers, with no chat filter and
/// no seeded roster — the recorded in-source Fugu entries are mapping
/// references, so an id only offers when the listing names it. A
/// `fugu*` id maps the recorded reasoning ladder to its one
/// representable level (`high`; `max` is outside the shared
/// vocabulary, DEC-008); vision comes from the entry's declared
/// capabilities, and the stated limits land only when positive.
/// Unknown stays `None`; the recorded request-side clamp is upstream
/// behaviour this adapter never carries (D3).
fn sakana_model(entry: &Value) -> Option<CatalogModel> {
    let id = entry
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())?;
    let capabilities = entry.get("capabilities").and_then(Value::as_array);
    let vision = capabilities
        .is_some_and(|values| values.iter().any(|value| value.as_str() == Some("vision")));
    let fugu = id.starts_with("fugu");
    Some(CatalogModel {
        id: id.to_string(),
        reasoning: fugu,
        vision,
        efforts: if fugu {
            vec![EffortLevel::High]
        } else {
            Vec::new()
        },
        context_window: entry.get("context_length").and_then(positive_tokens),
        max_output_tokens: entry.get("max_completion_tokens").and_then(positive_tokens),
        ..CatalogModel::default()
    })
}

/// The entry's stated per-token USD figures, scaled to the shared
/// per-1M record. Both members must carry a readable non-negative
/// number — a partial or invalid pair is not a figure, so the price
/// stays [`ModelPrice::Unknown`] rather than releasing a default.
fn openrouter_price(entry: &Value) -> ModelPrice {
    let Some(pricing) = entry.get("pricing") else {
        return ModelPrice::Unknown;
    };
    let (Some(prompt), Some(completion)) = (
        pricing.get("prompt").and_then(price_per_token),
        pricing.get("completion").and_then(price_per_token),
    ) else {
        return ModelPrice::Unknown;
    };
    let input_per_1m = prompt * 1_000_000.0;
    let output_per_1m = completion * 1_000_000.0;
    // A finite per-token figure can still overflow the 1M scale; a
    // non-finite product is not a price either.
    if !input_per_1m.is_finite() || !output_per_1m.is_finite() {
        return ModelPrice::Unknown;
    }
    ModelPrice::Usd {
        input_per_1m,
        output_per_1m,
    }
}

/// One per-token price member: the listing states a decimal string (a
/// JSON number is admitted too). A non-numeric, negative or non-finite
/// member is not a price.
fn price_per_token(value: &Value) -> Option<f64> {
    let price = match value {
        Value::String(text) => text.trim().parse::<f64>().ok()?,
        Value::Number(number) => number.as_f64()?,
        _ => return None,
    };
    (price.is_finite() && price >= 0.0).then_some(price)
}

impl std::fmt::Debug for OpenAiProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The scoped ref is the visible token — the store and its
        // material never enter diagnostics (INV-001).
        f.debug_struct("OpenAiProvider")
            .field("connection", &self.connection)
            .field("endpoint", &self.endpoint)
            .field("credential", &self.auth)
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

    /// The recorded image mark for one pinned model (TD-21): the recorded
    /// descriptor rows answer from the table alone, while the local
    /// endpoint class states its capability only in the served native
    /// descriptor, so the same bounded discovery the catalogue leg reads
    /// answers here. A failed or unreadable discovery is no capability —
    /// the request then denies typed instead of sending an image the peer
    /// never admitted.
    fn image_input(&self, connection: &str, model: &str) -> bool {
        if connection != self.connection {
            return false;
        }
        if recorded_image_input(connection, model) {
            return true;
        }
        self.connection == "ollama"
            && self
                .catalog_models()
                .is_ok_and(|rows| rows.iter().any(|row| row.id == model && row.vision))
    }

    /// Sends the frozen manifest as one physical Responses request.
    ///
    /// # Errors
    /// [`ProviderError::UnpinnedModel`] when the manifest carries no
    /// fixed model id and no single-member auto pool naming this
    /// connection, [`ProviderError::DialectMismatch`] when the pin
    /// names a different connection, the credential seam's typed
    /// denials, [`ProviderError::UnsupportedParameter`] for a pinned
    /// effort the xAI residue suppresses or a `bedrock-mantle` pin
    /// outside the current offer set (the last successful listing, else
    /// the recorded seed), [`ProviderError::RegionMismatch`] for a
    /// mantle pin whose geo the configured region cannot serve,
    /// [`ProviderError::Transport`],
    /// [`ProviderError::ProviderFailed`],
    /// [`ProviderError::UnknownTerminal`],
    /// [`ProviderError::UnsendableRequest`] for a serialized request
    /// body over the wire bound, [`ProviderError::StreamViolation`],
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
        // The catalogue-only absence (DEC-010): a declaration the
        // ingress admitted without a binding — the unbound `api_key`
        // form — lists keylessly, but a send needs a bound credential.
        // The denial lands here — before the auto-pool catalogue leg
        // and the post — so an unbound `openrouter` connection issues
        // no wire request and no fabricated header.
        if token.is_none() && !open_proxy_connection(&self.connection) {
            return Err(ProviderError::CredentialUnresolved {
                connection: self.connection.clone(),
                scope: format!("connections.{}.credential_ref", self.connection),
                cause: None,
            });
        }
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
                    .catalog_within(token.as_ref(), started)?
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
        // `bedrock-mantle` is region-scoped: `mantle_send_base` runs the
        // shared geo gate and owns the base for this pin, so a geo pin
        // never posts to the region assembly picked for the non-geo
        // seed. The offer gate follows: a pin outside the current offer
        // set — the most recent attempt's listing, else the recorded
        // seed — denies here, before the body exists.
        let mantle_base = if self.connection == "bedrock-mantle" {
            let base = self.mantle_send_base(&fixed.model_id)?;
            if !self.mantle_offered(&fixed.model_id) {
                return Err(ProviderError::UnsupportedParameter {
                    connection: self.connection.clone(),
                    parameter: "model",
                    model: fixed.model_id,
                });
            }
            Some(base)
        } else {
            None
        };
        let url = match &mantle_base {
            Some(base) => format!("{base}/responses"),
            None => format!("{}/responses", self.endpoint),
        };
        // The closed Codex route (AC-040i): the account-scoped listing
        // may name ids this contract does not serve, so a pin outside
        // the recorded table denies typed before the body exists —
        // never a silently dropped or forwarded model.
        if is_codex_connection(&self.connection) && !CODEX_MODELS.contains(&fixed.model_id.as_str())
        {
            return Err(ProviderError::UnsupportedParameter {
                connection: self.connection.clone(),
                parameter: "model",
                model: fixed.model_id,
            });
        }
        // The closed `github-copilot` table is this arm's route gate: a
        // pin whose recorded route is another codec — or no row at all —
        // never posts a Responses body.
        if self.connection == "github-copilot"
            && route_for(&self.connection, &fixed.model_id) != Some(Dialect::Responses)
        {
            return Err(ProviderError::UnsupportedParameter {
                connection: self.connection.clone(),
                parameter: "model",
                model: fixed.model_id,
            });
        }
        // The recorded xAI residue rejects the effort dial: the denial
        // lands before the body exists, never a silently dropped pin.
        self.check_effort(manifest, &fixed.model_id)?;
        let body = self.request_body(manifest, &fixed);
        let body_bytes = wire_body(&self.connection, &body)?;
        // The wire leg is the last budget check: a resolve or
        // catalogue leg that spent the clock fails the send typed
        // here — an expired budget never puts a byte on the wire.
        check_deadline(&self.connection, self.deadline, started)?;
        let request = self
            .client
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body_bytes);
        // The absent binding sends no header; a bound one sends the
        // same material the catalogue leg carried (DEC-009).
        let request = authenticate(request, token.as_ref());
        let request = request.headers(forwarded_header_map(self.auth.forwarded()));
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

    /// DEC-011's endpoint rule: the configured base is trimmed and
    /// loses every trailing slash, and the empty result resolves the
    /// recorded base on `ollama`, `openrouter`, `sakana`, `xai`,
    /// `xai-oauth`, `gitlab-duo`, `opencode-go` and `opencode-zen`
    /// alone — a sibling id keeps its own (absent) value and never
    /// borrows another's host. The `ollama`, `sakana`, `xai`,
    /// `xai-oauth`, `gitlab-duo`, `opencode-go` and `opencode-zen`
    /// defaults are pinned as literals, not only through the consts
    /// they resolve.
    #[test]
    fn endpoint_rule_trims_before_resolving_the_recorded_defaults() {
        assert_eq!(endpoint_for("ollama", "   "), "http://127.0.0.1:11434/v1");
        assert_eq!(endpoint_for("ollama", ""), OLLAMA_DEFAULT_ENDPOINT);
        assert_eq!(endpoint_for("ollama", " / "), OLLAMA_DEFAULT_ENDPOINT);
        assert_eq!(
            endpoint_for("ollama", "  http://127.0.0.1:9/v1/  "),
            "http://127.0.0.1:9/v1"
        );
        assert_eq!(endpoint_for("openrouter", ""), OPENROUTER_DEFAULT_ENDPOINT);
        assert_eq!(
            endpoint_for("openrouter", "  "),
            OPENROUTER_DEFAULT_ENDPOINT
        );
        assert_eq!(endpoint_for("sakana", ""), "https://api.sakana.ai/v1");
        assert_eq!(endpoint_for("sakana", " / "), SAKANA_DEFAULT_ENDPOINT);
        assert_eq!(
            endpoint_for("sakana", " https://api.sakana.ai/v1/ "),
            "https://api.sakana.ai/v1"
        );
        assert_eq!(endpoint_for("xai", ""), "https://api.x.ai/v1");
        assert_eq!(endpoint_for("xai", " / "), XAI_DEFAULT_ENDPOINT);
        assert_eq!(
            endpoint_for("xai", " https://api.x.ai/v1/// "),
            "https://api.x.ai/v1"
        );
        assert_eq!(endpoint_for("xai-oauth", ""), "https://api.x.ai/v1");
        assert_eq!(endpoint_for("xai-oauth", " / "), XAI_OAUTH_DEFAULT_ENDPOINT);
        assert_eq!(
            endpoint_for("xai-oauth", " https://api.x.ai/v1/// "),
            "https://api.x.ai/v1"
        );
        assert_eq!(
            endpoint_for("gitlab-duo", ""),
            "https://cloud.gitlab.com/ai/v1/proxy/openai/v1"
        );
        assert_eq!(
            endpoint_for("opencode-go", ""),
            "https://opencode.ai/zen/go/v1"
        );
        assert_eq!(
            endpoint_for("opencode-zen", ""),
            "https://opencode.ai/zen/v1"
        );
        assert_eq!(
            endpoint_for("openrouter", " https://openrouter.ai/api/v1/ "),
            "https://openrouter.ai/api/v1"
        );
        assert_eq!(
            endpoint_for("openrouter", " https://openrouter.ai/api/v1/// "),
            "https://openrouter.ai/api/v1"
        );
        assert_eq!(
            endpoint_for("openai", " https://api.openai.com/v1/// "),
            "https://api.openai.com/v1"
        );
        assert_eq!(endpoint_for("openai", "   "), "");
        assert_eq!(
            endpoint_for("openai", " https://api.openai.com/v1/ "),
            "https://api.openai.com/v1"
        );
    }

    /// The xAI effort residue is the recorded negative list alone: the
    /// suffix/prefix/contains classes suppress, and an id outside them
    /// keeps the pin — the positive ladder stays a residual.
    #[test]
    fn xai_effort_suppression_is_the_recorded_negative_residue() {
        for suppressed in [
            "grok-4.20-0309-reasoning",
            "grok-build-0.1",
            "grok-code-fast-1",
            "grok-composer-2.5-fast",
        ] {
            assert!(
                xai_suppresses_effort(suppressed),
                "{suppressed} is in the suppression residue"
            );
        }
        for admitted in [
            "grok-4.3",
            "grok-4.6",
            "grok-3-mini",
            "grok-4.20-multi-agent-0309",
        ] {
            assert!(
                !xai_suppresses_effort(admitted),
                "{admitted} is outside the suppression residue"
            );
        }
    }

    /// DEC-012's fanout bound: a phase probes the listing's leading 32
    /// entries, never more — and never probes past a shorter listing.
    #[test]
    fn probe_targets_stop_at_the_recorded_maximum() {
        let mut models: Vec<CatalogModel> = (0..40)
            .map(|index| CatalogModel {
                id: format!("model-{index:02}"),
                ..CatalogModel::default()
            })
            .collect();
        let probed = probe_targets_mut(&mut models);
        assert_eq!(probed.len(), 32, "40 listed ids probe the leading 32");
        assert_eq!(probed[0].id, "model-00");
        assert_eq!(probed[31].id, "model-31");
        let mut short = models[..7].to_vec();
        assert_eq!(probe_targets_mut(&mut short).len(), 7);
    }

    /// The in-repo encoder against RFC 4648 §10's vectors plus the
    /// padding and full-alphabet edges the `data:` URL depends on.
    #[test]
    fn base64_matches_the_rfc_4648_vectors() {
        for (raw, encoded) in [
            ("", ""),
            ("f", "Zg=="),
            ("f\u{6f}", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(
                OpenAiProvider::base64_encode(raw.as_bytes()),
                encoded,
                "{raw:?} encodes as the RFC vector"
            );
        }
        assert_eq!(OpenAiProvider::base64_encode(&[0x00]), "AA==");
        assert_eq!(OpenAiProvider::base64_encode(&[0xff, 0xff, 0xff]), "////");
        assert_eq!(
            OpenAiProvider::base64_encode(&[0xfb, 0xff, 0xbf]),
            "+/+/",
            "the last two alphabet symbols are `+` and `/`"
        );
    }

    /// The recorded image mark is the mantle seed alone: the same id on
    /// another connection, or another id on the mantle connection, is
    /// text-only — the pin then denies typed rather than sending an
    /// image the record never admitted.
    #[test]
    fn recorded_image_input_is_the_mantle_seed_only() {
        for id in MANTLE_MODELS {
            assert!(
                recorded_image_input("bedrock-mantle", id),
                "{id} carries the recorded image mark"
            );
            assert!(
                !recorded_image_input("openai", id),
                "{id} is not recorded on openai"
            );
        }
        for id in RESPONSES_MODELS {
            assert!(
                !recorded_image_input("openai", id),
                "{id} records no image mark"
            );
            assert!(!recorded_image_input("bedrock-mantle", id));
        }
    }
}
