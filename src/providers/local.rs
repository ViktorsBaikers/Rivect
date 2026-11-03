//! The `custom-chat-completions`, `aiand`, `aimlapi`,
//! `alibaba-coding-plan`, `alibaba-token-plan`, `coreweave`,
//! `deepinfra`, `deepseek`, `firepass`, `fireworks`, `gmi-cloud`,
//! `groq`, `huggingface`, `kilo`, `litellm`, `llama.cpp`, `lm-studio`,
//! `minimax-code`/`minimax-code-cn`, `mistral`, `moonshot`, `nanogpt`,
//! `novita`, `nvidia`, `qianfan`, `qwen-portal`, `siliconflow`,
//! `siliconflow-cn`, `synthetic`, `together`, `venice` and `vllm`
//! connections' adapter —
//! the OpenAI-compatible Chat Completions dialect
//! (DEC-007/DEC-025, HZN-008 class S, class A, class P and class B).
//! Dialect selection keys on the literal connection id, never an auth
//! label, an endpoint shape or a catalogue answer: every compatible
//! host a deployment wires under `custom-chat-completions` shares the
//! one recorded generic contract, while `aiand`, `aimlapi`,
//! `alibaba-coding-plan`, `alibaba-token-plan`, `coreweave`,
//! `deepinfra`, `deepseek`, `firepass`, `fireworks`, `gmi-cloud`,
//! `groq`, `huggingface` and `kilo` carry their own recorded predicates — the
//! `/v1` base normalization and the org-scoped catalogue transform
//! on `aiand`, the default-host endpoint rule and the chat-id
//! catalogue filter on `aimlapi`, the region-choice endpoint, the
//! static allowed-model catalogue and the enrolled-base credential
//! binding on `alibaba-coding-plan`, the region-choice endpoint,
//! the region-bound authoritative `/models` catalogue with its
//! chat-id prefix filter and the enrolled-base credential binding —
//! the optional quota `cookie` member admitted for shape and dropped —
//! on `alibaba-token-plan`, the configured-or-default host, the
//! authoritative `/models` listing and the scoped `key` with its
//! `OpenAI-Project` member — the recorded login is `api-key`, whose
//! `OpenAI-Project` header hook resolves from the environment, a
//! channel the transport has none of, so Rivect's store form
//! materializes that scope as the scoped JSON; the bare paste key is
//! login input the credential substrate resolves (D4), never store
//! material — on `coreweave`, the configured-or-default host, the
//! authoritative chat-model `/models` listing — the public metadata
//! catalogue never an authentication surface — and the plain bearer
//! credential on `deepinfra`, the configured-or-default host,
//! the authoritative `/models` listing gated by the recorded
//! built-in roster — built-in ids offered, benchmark ids never —
//! the plain bearer credential and the recorded native reasoning
//! rules on `deepseek` — catalogue reasoning marks, the verbatim
//! reasoning-effort pin and reasoning-content progress, while the
//! recorded `thinking` body toggle is unsent (D5) — the shared
//! `api.fireworks.ai/inference/v1`
//! host under the recorded static router catalogue — the `fpk_…` key
//! authorizes no `/models` lookup, so no discovery leg exists — the
//! dedicated `fpk_` key grammar and the router wire-model-id dispatch
//! on `firepass`, and the configured-or-default
//! `api.fireworks.ai/inference/v1` host, the request-model
//! `/models` listing — the `/v1/accounts/fireworks/models`
//! management API never a model source — the serverless/fast
//! chat-model predicates with the recorded wire-model-id dispatch,
//! the recorded Fast seed and the plain bearer credential on
//! `fireworks`, and the configured-or-default
//! `api.gmi-serving.com/v1` host, the authoritative `/models`
//! listing whose bare-id rows are offered verbatim and the plain
//! bearer credential on `gmi-cloud`, and the configured-or-default
//! `api.groq.com/openai/v1` host, the recorded static and benchmark
//! floor merged over the provider's non-authoritative `/models` list —
//! a listed foreign id is offered while a 200 listing confers no
//! entitlement — the per-model effort predicate (a pinned level the
//! model does not record denies typed: before any wire leg for a fixed
//! pin, and before the chat request leg for an auto pick that resolved
//! its model from the listing first) and the
//! plain bearer credential on `groq`, and the configured-or-default
//! `router.huggingface.co/v1` host, the recorded T1 static bundled
//! rows as the offer floor with the key-gated `/models` listing as
//! their non-authoritative supplement, the ids riding the catalogue
//! and the wire verbatim — the `provider/model` routing suffix is
//! never stripped, folded or re-prefixed — and the
//! fine-grained model-request token, whose `hf_…` grammar is the
//! account/org billing form: material of another credential class
//! denies typed before any wire leg rather than billing implicitly on
//! `huggingface`, and the configured-or-default
//! `api.kilo.ai/api/gateway` host with the recorded keyless
//! `/models` discovery — its offers merge over the recorded default
//! row as the floor, the `Authorization` header rides only when the
//! store resolves material, and no catalogue answer confers paid
//! entitlement — and the recorded custom device/key profile class,
//! whose enrolled device login or key supplies the opaque gateway
//! bearer a send requires (material naming no token denies typed
//! before any wire leg), with no subscription SKU or price invented
//! on `kilo`, and the user-configured `litellm` proxy base verbatim —
//! the recorded default (`LITELLM_BASE_URL ?? http://localhost:4000/v1`)
//! is never substituted because the base must be configured, so no
//! localhost catalogue exists — whose discovery is the proxy's own
//! management metadata first (four recorded paths under one bounded
//! phase) with the recorded fall-through to `/models`, and whose
//! recorded credential arm is the open proxy: an undeclared binding
//! rides headerless on every leg, a declared binding that cannot
//! resolve denies typed, and a scoped key sends the bearer — neither
//! form invents a catalogue — and the configured `llama.cpp` local base
//! verbatim, or the recorded `http://127.0.0.1:8080` default when the
//! field is empty, whose recorded contract opens no `/models` leg: the
//! catalogue is empty and the recorded manual model path is the only
//! served route, with no base-URL merging (DEC-008/PROH-009/D7), while
//! its recorded optional auth shares the same absent-binding form, and
//! the configured `lm-studio` local base under the same local-endpoint
//! shape with its own recorded default `http://127.0.0.1:1234/v1` —
//! neither local class borrows the other's base (EDGE-006) — and the
//! configured-or-recorded `api.minimax.io/v1` international base of
//! `minimax-code`, whose plan
//! key rides as the plain bearer — a plan-scoped key is a billing fact
//! of the connection, never a connection kind and never a PAYG
//! substitute (DEC-007/DEC-010) — and `minimax-code-cn`'s own recorded
//! `api.minimaxi.com/v1` CN base under the same shape — the CN plan's
//! fixed window vs the international plan's rolling window stays a
//! billing fact of each enrolled key, and the `minimax.cn` Anthropic
//! URL is a recorded divergence, never substituted (EDGE-007) —
//! neither class records a discovery leg: no `/models` call and no
//! vendored roster, so the catalogue opens no wire leg and the
//! manual model path is the only served route — and the
//! configured-or-recorded `api.mistral.ai/v1` base of `mistral`,
//! whose recorded `requireApiKey` `/models` listing is the whole
//! catalogue — no vendored roster exists (D4), so an empty or failed
//! answer has no floor to fall back to — and whose recorded
//! env/credential-chain class resolves through the scoped `SecretRef`
//! seam the same way `groq`'s does: an `env:`/`file:`/plaintext ref
//! is refused at ingress, traversal stays substrate debt (DEC-006) —
//! and the configured-or-recorded `api.moonshot.ai/v1` base of
//! `moonshot`, whose `requireApiKey` `/models` listing and the send
//! leg alike follow the configured base — never the recorded default
//! when one is configured — and whose recorded K3 top-level
//! `reasoning_effort` ladder (`low`/`high`) is a distinct predicate
//! from the K2.x `thinking` surface this adapter never constructs:
//! `low`/`high` ride the body verbatim, an out-of-ladder pin denies
//! typed, and the recorded `max` has no carrier in the shared effort
//! vocabulary, so no `max` request is ever constructed (DEC-014) — a
//! fallback key name proves neither region nor payment — and the
//! configured-or-recorded `nano-gpt.com/api/v1` base of `nanogpt`,
//! whose recorded api-key class makes its `/models` listing the whole
//! catalogue only when the scoped material resolves — a keyless
//! lookup opens no wire leg — while its `:thinking` suffix variants
//! collapse into the single base offer they alias and the
//! subscription base is a separate configured payment class, never a
//! hidden fallback (DEC-010) — and the configured-or-recorded
//! `api.novita.ai/openai/v1` base of `novita`, whose recorded
//! `dynamicModelsAuthoritative` keyless `/models` discovery is the
//! whole catalogue — an absent scope rides the anonymous listing
//! with no `Authorization` header, while the same absent scope
//! denies a send typed — and whose listing answer passes the
//! recorded entry
//! filter: a numeric `status` other than `1`, an `ai_infer_test`
//! test id, an entry whose `endpoints` omit `chat/completions`, and
//! a non-positive `max_output_tokens` are each dropped, so an
//! unfiltered or public listing row never reaches the offer set.
//! The recorded login validates against inference, never payment
//! administration — a limited-role key that cannot read billing is
//! verified by a model request — and no price or billing fact is
//! borrowed from another id: this class carries no vendored price
//! row (D6), so an admitted offer keeps [`ModelPrice::Unknown`] —
//! resolved per literal
//! id by the contract table, never inherited
//! across ids. The configured-or-recorded
//! `integrate.api.nvidia.com/v1` base of `nvidia` follows the same
//! shape: its recorded `createSimpleOpenAICompletionsOptions`
//! discovery is the plain keyed `/models` listing as the whole
//! catalogue — no vendored floor and no entry filter beyond the
//! recorded simple answer, so every listed `vendor/model` id rides
//! the catalogue and the wire verbatim — and its recorded login
//! validation is optional (`optional=#true`): a `401`/`403` from the
//! validation/model request is the typed hard denial, while any other
//! non-success proves neither access nor denial and is never reported
//! as success or as entitlement. The configured-or-recorded
//! `https://qianfan.baidubce.com/v2` base of `qianfan` carries the
//! recorded api-key class: its key-gated `/models` listing is the
//! whole catalogue, each `data[]` row mapping the id plus
//! `context_length` and `max_completion_tokens` when stated, and the
//! recorded `deepseek-v3.2` default is a catalogue hint — never a
//! seeded offer or a ranking the sorted-first auto pick follows
//! (DEC-014/D11). The configured-or-recorded
//! `https://portal.qwen.ai/v1` base of `qwen-portal` carries the same
//! api-key class: its key-gated `/models` listing is the whole
//! catalogue, each `data[]` row mapping the id plus `context_length`
//! and `max_completion_tokens` when stated, and the recorded
//! `coder-model` default is a hint — never a seeded offer or a
//! ranking. The paste api-key alternative resolves at the scoped
//! `SecretRef` seam, while the recorded Qwen OAuth free-tier lifecycle
//! (refresh, quota, revocation) is a bounded residual (D6/DEC-002)
//! this adapter never constructs. The configured-or-recorded
//! `https://api.siliconflow.com/v1` base of `siliconflow` carries the
//! same api-key class under its own authoritative listing: the recorded
//! exclusion list drops the embedding, reranker and image/audio/video
//! generator ids, each admitted `data[]` row maps the id plus
//! `context_length` and `max_completion_tokens` when stated under the
//! recorded `min(maxTokens, context)` clamp, and the recorded
//! models.dev hydration is a runtime residual (D2) this adapter never
//! claims. The configured-or-recorded `https://api.siliconflow.cn/v1`
//! base of `siliconflow-cn` carries the same transform under its own
//! host and credential: the id-keyed region split (EDGE-007) never
//! substitutes either host for the other, and the distinct recorded
//! `SILICONFLOW_CN_API_KEY` env name is class metadata, not a second
//! ingress. The configured-or-recorded
//! `https://api.synthetic.new/openai/v1` base of `synthetic` carries
//! the pinned code's `/openai/v1` root — never the docs' `/v1` — over
//! the class's own nonstandard listing surface: capabilities arrive in
//! `supported_features`, modalities in `input_modalities`, the output
//! cap in `max_output_length` (then `max_tokens`, then the recorded
//! 8192 fallback, as this adapter carries no bundled reference), the
//! accepted effort vocabulary in `reasoning_parameters.efforts`
//! (representable levels only: `none` is the thinking-off router state
//! and `max` names no level our vocabulary transmits, DEC-008), and
//! per-token USD prices in `pricing` as `$`-prefixed decimals scaled
//! to per-1M figures. A partial or unreadable price stays
//! [`ModelPrice::Unknown`], never a default figure; absent keys stay at
//! their empty surface. The configured-or-recorded
//! `https://api.together.xyz/v1` base of `together` carries the same
//! api-key class: the pinned `.xyz` host binds, while the documentation's
//! `.ai` alias and the US endpoint alias are never substituted
//! (DEC-005), and the key-gated `/models` listing is the whole catalogue
//! with no entry filter — every parseable id is an offer, each `data[]`
//! row mapping the id plus `context_length` and `max_completion_tokens`
//! when stated (DEC-020) — with no seed floor. The configured-or-recorded
//! `https://api.venice.ai/api/v1` base of `venice` carries the recorded
//! public catalogue: its `/models` listing rides headerless whenever the
//! store resolves no material — the discovery tolerance alone, never a
//! send, so the same absent material denies `CredentialAbsent` — and a
//! listing answer is never authentication; each row maps the id plus the
//! generic `context_length`/`max_completion_tokens` limits when stated,
//! the plain bearer carries the model-request key (a class distinct from
//! the administrative key, though `SecretRef` material states no class —
//! a residual), and the recorded request names no
//! `stream_options.include_usage` member, so its body never asks for a
//! usage report and the charged usage may stay unknown. The configured-or-recorded
//! `http://127.0.0.1:8000/v1` base of `vllm` is its own recorded local
//! host — never `llama.cpp`'s `:8080` or `lm-studio`'s `:1234`
//! (EDGE-006) — whose `/models` listing maps vLLM's `max_model_len` as
//! the context window and carries the display-only Qwen reasoning mark;
//! its recorded auth is optional beside the server-key mode, so the
//! same absent-binding form rides headerless, a scoped key rides as the
//! bearer, and the listing states no effort ladder: a pinned
//! `reasoning_effort` denies typed rather than being dropped. The
//! adapter authors no
//! async code — [`Provider::send`] is a blocking single-shot seam and
//! Tokio appears only inside reqwest's blocking client plus the
//! dev-dependency test harness.
//!
//! The recorded contract (omp openai-completions.ts /
//! openai-shared.ts): `POST {endpoint}/chat/completions` under a
//! `Bearer` authorization, the body carrying `model`, `messages`
//! (`system` for the instructions, `user` for the inputs), `stream`
//! with `stream_options.include_usage` — every arm but `venice`, whose
//! recorded request names no usage-report member — the declared tool surface as
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

use crate::config::{
    Config, ConnKind, Connection, EffortAssign, EffortLevel, FixedModel, ModelAssign,
};
use crate::model::RequestManifest;
use crate::policy::canonical_egress_target;
use crate::providers::sse::{SseEvent, SseParser};
use crate::providers::{
    CredentialStore, Dialect, Provider, ProviderError, ProviderReply, STREAM_CHUNK_BYTES,
    SecretRef, ToolCall, TransportCause, bounded_reason, check_deadline, dialect_for,
    payload_reason, read_catalog_body, read_chunk, resolve_credential,
    resolve_optional_credential_in, sse, transport, transport_status, violation, wire_body,
};
use crate::resources::UsageDelta;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, HashMap};
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

/// The recorded default API root of an `aimlapi` connection
/// (`aimlApiModelManagerOptions`'s `defaultBaseUrl`): the host the
/// recorded `config?.baseUrl ?? defaultBaseUrl` fallback resolves.
/// Our schema's `endpoint` field is required, so its empty string is
/// the upstream absent-override case.
const AIMLAPI_DEFAULT_BASE_URL: &str = "https://api.aimlapi.com/v1";

/// The recorded `alibaba-coding-plan` international endpoint —
/// `alibabaCodingPlanModelManagerOptions`'s `defaultBaseUrl`: the
/// host the required `endpoint` field's empty string resolves under
/// the recorded `config?.baseUrl ?? defaultBaseUrl` fallback. The
/// region choice the upstream login prompt enumerates —
/// international, China (`coding.dashscope.aliyuncs.com/v1`) or a
/// custom origin — rides the configured `endpoint` itself, so the
/// adapter's `region` field stays denied.
const ALIBABA_PLAN_INTL_BASE_URL: &str = "https://coding-intl.dashscope.aliyuncs.com/v1";

/// The recorded `alibaba-coding-plan` allowed-model list (HZN-008
/// class P — `mapWithBundledReference` over the bundled descriptors):
/// the plan's whole model surface. No `/models` discovery leg exists
/// for this class, so the catalogue is this list alone. Each entry
/// carries the bundled descriptor's image-input mark and nothing
/// else — the allowlist states ids and that mark, never reasoning,
/// effort, window or price data the class does not record.
const ALIBABA_PLAN_MODELS: &[(&str, bool)] = &[
    ("qwen3.7-plus", true),
    ("qwen3.6-plus", true),
    ("kimi-k2.5", true),
    ("glm-5", false),
    ("MiniMax-M2.5", false),
    ("qwen3.5-plus", false),
    ("qwen3-max-2026-01-23", false),
    ("qwen3-coder-next", false),
    ("qwen3-coder-plus", false),
    ("glm-4.7", false),
];

/// The recorded `alibaba-coding-plan` key grammar (`sk-sp-…`): the
/// Coding Plan subscription key class. PAYG keys carry the ordinary
/// `sk-…` grammar and are a different product the plan's bases never
/// serve — a bearer outside the grammar denies before any wire leg.
const PLAN_KEY_PREFIX: &str = "sk-sp-";

/// The recorded `alibaba-token-plan` international endpoint —
/// `ALIBABA_TOKEN_PLAN_BASE_URL`, `alibabaTokenPlanModelManagerOptions`'s
/// `defaultBaseUrl`: the host the required `endpoint` field's empty
/// string resolves under the recorded
/// `credential?.baseUrl ?? config?.baseUrl ?? ALIBABA_TOKEN_PLAN_BASE_URL`
/// fallback. The region choice the upstream login prompt enumerates —
/// international, China
/// (`token-plan.cn-beijing.maas.aliyuncs.com/compatible-mode/v1`) or a
/// custom origin — rides the configured `endpoint` itself, so the
/// adapter's `region` field stays denied.
const ALIBABA_TOKEN_PLAN_INTL_BASE_URL: &str =
    "https://token-plan.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1";

/// The recorded `alibaba-token-plan` `exclude-models` prefix roster
/// (`runtime/behavior.kdl`: "Alibaba Token Plan serves ASR/image/
/// embedding SKUs the chat picker cannot route") — `isExcludedModel`'s
/// `prefix` arm, `startsWith` on the normalized id.
const ALIBABA_TOKEN_PLAN_EXCLUDED_PREFIXES: &[&str] = &[
    "fun-asr",
    "happyhorse-",
    "qwen-audio-",
    "qwen-image-",
    "text-embedding-",
    "wan2.7-",
];

/// The recorded default API root of a `coreweave` connection
/// (`api.inference.wandb.ai/v1`): the host an absent or empty
/// configured endpoint resolves to under the recorded
/// `… ?? defaultBaseUrl` absent-override case — the same rule the
/// plan classes bind.
const COREWEAVE_DEFAULT_BASE_URL: &str = "https://api.inference.wandb.ai/v1";

/// The scope header CoreWeave Serverless Inference requires on every
/// scoped request (`OpenAI-Project`, wire/coreweave.ts): the recorded
/// `<team>/<project>` member of the stored scoped credential — spend
/// lands against that project, and a scoped request without it is
/// denied upstream the same way the recorded pre-validation check
/// denies an unset `COREWEAVE_PROJECT` before any fetch. The stored
/// material always names it: the recorded `api-key` login's
/// `OpenAI-Project` header hook resolves from the environment, and
/// Rivect's translated store form materializes that scope, while the
/// bare pasted key is input to that login, never material this
/// class's store slot holds.
const OPENAI_PROJECT_HEADER: &str = "OpenAI-Project";

/// The recorded default API root of a `deepinfra` connection
/// (`DEEPINFRA_BASE_URL` — `api.deepinfra.com/v1/openai`,
/// `deepinfraModelManagerOptions`'s `defaultBaseUrl`): the host the
/// required `endpoint` field's empty string resolves under the
/// recorded `config?.baseUrl ?? DEEPINFRA_BASE_URL` fallback — the
/// same absent-override rule the plan classes bind.
const DEEPINFRA_DEFAULT_BASE_URL: &str = "https://api.deepinfra.com/v1/openai";

/// The recorded default API root of a `deepseek` connection
/// (`api.deepseek.com`, `deepseekModelManagerOptions`'s
/// `defaultBaseUrl`): the host the required `endpoint` field's
/// empty string resolves under the recorded
/// `config?.baseUrl ?? defaultBaseUrl` fallback — the same
/// absent-override rule the plan classes bind.
const DEEPSEEK_BASE_URL: &str = "https://api.deepseek.com";

/// The recorded `deepseek` built-in roster (HZN-008 class A,
/// `deepseekModelManagerOptions`'s `builtInModelManager`):
/// `deepseek-v4-flash`, `deepseek-v4-flash-vision-exp` and
/// `deepseek-v4-pro` carry the recorded surface — the native
/// reasoning mark with its `low`/`high`/`max` ladder (the recorded
/// `max` has no landing level in our enum and never maps onto a
/// lower one), the million-token window and the per-model USD
/// prices [`DEEPSEEK_PRICES`] states — while the prepaid balance
/// and off-peak rules stay account facts we never synthesize. A
/// listed or seeded id outside the roster is a benchmark or legacy
/// id and is never offered as a model.
const DEEPSEEK_BUILTIN_MODELS: &[&str] = &[
    "deepseek-v4-flash",
    "deepseek-v4-flash-vision-exp",
    "deepseek-v4-pro",
];

/// The recorded per-model USD prices the `deepseek` roster rows
/// state (`models.json` `cost.input`/`cost.output` per 1M tokens):
/// the flash builds bill 0.14/0.28, the pro build 0.435/0.87. The
/// recorded cache-read/cache-write figures have no carrier —
/// [`ModelPrice`] states input/output alone — so they stay
/// uncarried rather than flattened into the carried legs.
const DEEPSEEK_PRICES: &[(&str, f64, f64)] = &[
    ("deepseek-v4-flash", 0.14, 0.28),
    ("deepseek-v4-flash-vision-exp", 0.14, 0.28),
    ("deepseek-v4-pro", 0.435, 0.87),
];

/// The recorded vision mark a `deepseek` built-in carries: the
/// `vision-exp` build alone admits image input.
const DEEPSEEK_VISION_MODEL: &str = "deepseek-v4-flash-vision-exp";

/// The recorded `firepass` static router catalogue (HZN-008 class P —
/// `auth/firepass.kdl`, `firepassModelManagerOptions`): the manager
/// returns a bare provider id with the bundled catalogue canonical,
/// and the dedicated `fpk_…` keys do not authorize `/models`, so this
/// connection opens no discovery leg at all and a `/models` answer
/// never proves access. The two recorded router identities stay
/// distinct entries, never one reconciled id: the pinned source's
/// `kimi-k2.6-turbo` (Kimi K2.6 Turbo, wired as
/// `accounts/fireworks/routers/kimi-k2p6-turbo`) and the id the
/// official Fire Pass page documents at the same pin, `kimi-k3-fast`.
/// The class records no vision mark and no per-model price for either,
/// so those surfaces stay off and unknown.
const FIREPASS_MODELS: &[(&str, bool)] = &[("kimi-k2.6-turbo", false), ("kimi-k3-fast", false)];

/// The recorded `fpk_` prefix a Fire Pass key carries
/// (`auth/firepass.kdl`, prompt `fpk_...`): the pass key is enrolled
/// for this connection alone, so a Fireworks account key on the shared
/// `api.fireworks.ai` host never satisfies the grammar.
const FIREPASS_KEY_PREFIX: &str = "fpk_";

/// The recorded default API root of a `fireworks` connection
/// (`api.fireworks.ai/inference/v1`, `fireworksModelManagerOptions`'
/// `config?.baseUrl ?? defaultBaseUrl` fallback): the host the
/// required `endpoint` field's empty string resolves under — the
/// same absent-override rule the plan classes bind. The connection
/// shares the host with `firepass`, never a contract: egress and
/// credential grammar bind per literal connection id.
const FIREWORKS_BASE_URL: &str = "https://api.fireworks.ai/inference/v1";

/// The recorded `accounts/fireworks/models/` wire prefix the
/// inference listing returns on its ids — the catalogue offers the
/// public form (`toFireworksPublicModelId`), the request body
/// carries the wire form (`toFireworksWireModelId`). The
/// `accounts/fireworks/routers/` prefix is the Fast/`firepass`
/// serving path — the recorded `exclude-models
/// prefix="accounts/fireworks/"` runtime rule drops any id still
/// carrying a reserved prefix after the public-form strip, so a
/// listed router id is never offered.
const FIREWORKS_WIRE_PREFIX: &str = "accounts/fireworks/models/";
const FIREWORKS_ROUTER_PREFIX: &str = "accounts/fireworks/routers/";

/// The recorded public-id suffix a Fireworks Fast serving-path
/// variant carries (`FIREWORKS_FAST_SUFFIX` —
/// `fireworks-model-id.ts`): Fast routers never appear in the
/// serverless list, so the recorded surface seeds the named variants
/// as the offer floor (`buildFireworksFastSeed` /
/// `FIREWORKS_FAST_VARIANT_SPECS`), and the recorded
/// `wire-model-id-mode "firepass"` dispatch on a `*-fast` id sends
/// the router wire form `accounts/fireworks/routers/<id>` with the
/// recorded `p` version separator. The seed ids are the public
/// catalogue ids the recorded variant specs name — a fast id the
/// listing itself returns is offered through the same transform, so
/// the offer set is a union, never a rekey.
const FIREWORKS_FAST_IDS: &[&str] = &[
    "glm-5.1-fast",
    "glm-5.2-fast",
    "kimi-k2.6-fast",
    "kimi-k2.7-code-fast",
];

/// The recorded per-model USD prices the pinned `fireworks` rows of
/// `models.json` state (`cost.input`/`cost.output` per 1M tokens),
/// plus the recorded Fast variant prices
/// (`FIREWORKS_FAST_VARIANT_SPECS`): a stated zero is a real figure
/// — a free or bundled-only SKU — never the unknown state. The
/// recorded `cacheRead`/`cacheWrite` figures have no carrier —
/// [`ModelPrice`] states input/output alone — so they stay
/// uncarried rather than flattened into the carried legs, and an
/// id the pinned rows do not name keeps `ModelPrice::Unknown`.
const FIREWORKS_PRICES: &[(&str, f64, f64)] = &[
    ("deepseek-v4-flash", 0.14, 0.28),
    ("deepseek-v4-flash-0731", 0.175, 0.35),
    ("deepseek-v4-flash-vision-exp", 0.14, 0.28),
    ("deepseek-v4-pro", 0.435, 0.87),
    ("deepseek-v4-pro-0813", 1.65, 4.95),
    ("flux-1-schnell-fp8", 0.0, 0.0),
    ("glm-5", 1.0, 3.2),
    ("glm-5.1", 1.4, 4.4),
    ("glm-5.1-fast", 2.8, 8.8),
    ("glm-5.2", 0.966, 3.036),
    ("glm-5.2-fast", 2.1, 6.6),
    ("glm-5.3", 1.4, 4.4),
    ("glm-5.3-flash", 0.075, 0.25),
    ("gpt-oss-120b", 0.35, 0.75),
    ("gpt-oss-20b", 0.0, 0.0),
    ("inkling", 1.25, 5.0625),
    ("kimi-k2.5", 0.6, 3.0),
    ("kimi-k2.6", 0.95, 4.0),
    ("kimi-k2.6-fast", 2.0, 8.0),
    ("kimi-k2.7-code", 0.67, 3.4),
    ("kimi-k2.7-code-fast", 1.9, 8.0),
    ("kimi-k3", 3.0, 15.0),
    ("minimax-m2.5", 0.3, 1.2),
    ("minimax-m2.7", 0.3, 1.2),
    ("minimax-m3", 0.3, 1.2),
    ("muse-glimmer-30b", 0.0, 0.0),
    ("nemotron-3-ultra-nvfp4", 0.0, 0.0),
    ("nemotron-lightning-3.5-30b-a3b", 0.0, 0.0),
    ("qwen3-embedding-8b", 0.0, 0.0),
    ("qwen3-reranker-8b", 0.0, 0.0),
    ("qwen3.6-plus", 0.0, 0.0),
    ("qwen3.7-plus", 0.32, 1.28),
    ("qwen3.8-2.4t-a95b", 0.0, 0.0),
    ("qwen3.8-max", 2.0, 6.0),
];

/// The recorded default API root of a `gmi-cloud` connection
/// (`api.gmi-serving.com/v1`, DEC-025 row `Rivect/key →
/// api.gmi-serving.com/v1`): the host the required `endpoint` field's
/// empty string resolves under — the same absent-override rule the
/// plan classes bind. The class records no per-model price, so an
/// offered id keeps [`ModelPrice::Unknown`]: a figure is never
/// borrowed from another connection's table.
const GMI_BASE_URL: &str = "https://api.gmi-serving.com/v1";

/// The recorded default API root of a `groq` connection
/// (`api.groq.com/openai/v1`, DEC-025 row `Rivect/key →
/// api.groq.com/openai/v1`): the host the required `endpoint` field's
/// empty string resolves under — the same absent-override rule the
/// plan classes bind.
const GROQ_BASE_URL: &str = "https://api.groq.com/openai/v1";

/// The recorded `groq` static and benchmark model floor (HZN-008 class
/// A, `groqModelManagerOptions` → `createSimpleOpenAICompletionsOptions`
/// over the pinned `models.json` rows): the ids the contract merges
/// over the provider's non-authoritative `/models` list. The listing
/// contributes ids — a foreign listed id is offered — while these
/// seeded ids keep their recorded reference surface; neither list
/// proves entitlement.
const GROQ_SEED: &[&str] = &[
    "deepseek-r1-distill-llama-70b",
    "gemma2-9b-it",
    "groq/compound",
    "groq/compound-mini",
    "llama-3.1-8b-instant",
    "llama-3.3-70b-versatile",
    "llama3-70b-8192",
    "llama3-8b-8192",
    "meta-llama/llama-4-maverick-17b-128e-instruct",
    "meta-llama/llama-4-scout-17b-16e-instruct",
    "mistral-saba-24b",
    "moonshotai/kimi-k2-instruct",
    "moonshotai/kimi-k2-instruct-0905",
    "openai/gpt-oss-120b",
    "openai/gpt-oss-20b",
    "openai/gpt-oss-safeguard-20b",
    "qwen-qwq-32b",
    "qwen/qwen3-32b",
    "qwen/qwen3.6-27b",
    "qwen/qwen3.8-27b",
];

/// The recorded `groq` image-input builds (`input: ["text", "image"]`
/// in the pinned rows): every other build is text-only.
const GROQ_VISION_MODELS: &[&str] = &[
    "meta-llama/llama-4-maverick-17b-128e-instruct",
    "meta-llama/llama-4-scout-17b-16e-instruct",
    "qwen/qwen3.6-27b",
    "qwen/qwen3.8-27b",
];

/// The recorded ladder the `groq/compound` systems carry.
const GROQ_EFFORT_FULL: &[EffortLevel] = &[
    EffortLevel::Minimal,
    EffortLevel::Low,
    EffortLevel::Medium,
    EffortLevel::High,
    EffortLevel::Xhigh,
];

/// The recorded ladder the `gpt-oss` builds carry.
const GROQ_EFFORT_OSS: &[EffortLevel] = &[EffortLevel::Low, EffortLevel::Medium, EffortLevel::High];

/// The recorded ladder the Qwen builds carry.
const GROQ_EFFORT_QWEN: &[EffortLevel] = &[
    EffortLevel::Minimal,
    EffortLevel::Low,
    EffortLevel::Medium,
    EffortLevel::High,
];

/// The recorded per-model effort ladder the pinned `groq` rows state
/// (`thinking.efforts`, `thinking-mode "effort"`): a level a model
/// does not name is a parameter its wire contract rejects, so a pin
/// carrying it denies typed rather than dropping `reasoning_effort`
/// from the body. A model absent here records no effort surface, so
/// every pinned level denies for it. The recorded `max` level has no
/// landing in our enum and never maps onto a lower one — the R1
/// distill row therefore carries `high` alone.
const GROQ_EFFORTS: &[(&str, &[EffortLevel])] = &[
    ("deepseek-r1-distill-llama-70b", &[EffortLevel::High]),
    ("groq/compound", GROQ_EFFORT_FULL),
    ("groq/compound-mini", GROQ_EFFORT_FULL),
    ("openai/gpt-oss-120b", GROQ_EFFORT_OSS),
    ("openai/gpt-oss-20b", GROQ_EFFORT_OSS),
    ("openai/gpt-oss-safeguard-20b", GROQ_EFFORT_OSS),
    ("qwen-qwq-32b", GROQ_EFFORT_QWEN),
    ("qwen/qwen3.6-27b", GROQ_EFFORT_QWEN),
    ("qwen/qwen3.8-27b", GROQ_EFFORT_QWEN),
];

/// The recorded per-model USD prices the pinned `groq` rows state
/// (`cost.input`/`cost.output` per 1M tokens): a stated zero is a
/// real figure — a bundled or free SKU. The recorded `cacheRead`
/// figures have no carrier — [`ModelPrice`] states input/output
/// alone — so they stay uncarried.
const GROQ_PRICES: &[(&str, f64, f64)] = &[
    ("deepseek-r1-distill-llama-70b", 0.75, 0.99),
    ("gemma2-9b-it", 0.2, 0.2),
    ("groq/compound", 0.0, 0.0),
    ("groq/compound-mini", 0.0, 0.0),
    ("llama-3.1-8b-instant", 0.05, 0.08),
    ("llama-3.3-70b-versatile", 0.59, 0.79),
    ("llama3-70b-8192", 0.59, 0.79),
    ("llama3-8b-8192", 0.05, 0.08),
    ("meta-llama/llama-4-maverick-17b-128e-instruct", 0.2, 0.6),
    ("meta-llama/llama-4-scout-17b-16e-instruct", 0.11, 0.34),
    ("mistral-saba-24b", 0.79, 0.79),
    ("moonshotai/kimi-k2-instruct", 1.0, 3.0),
    ("moonshotai/kimi-k2-instruct-0905", 1.0, 3.0),
    ("openai/gpt-oss-120b", 0.15, 0.6),
    ("openai/gpt-oss-20b", 0.075, 0.3),
    ("openai/gpt-oss-safeguard-20b", 0.075, 0.3),
    ("qwen-qwq-32b", 0.29, 0.39),
    ("qwen/qwen3-32b", 0.29, 0.59),
    ("qwen/qwen3.6-27b", 0.6, 3.0),
    ("qwen/qwen3.8-27b", 0.8, 4.0),
];

/// The recorded default API root of a `huggingface` connection
/// (`router.huggingface.co/v1`, DEC-025 row: a fine-grained
/// model-request token → that host): the host the required `endpoint`
/// field's empty string resolves under — the same absent-override rule
/// the plan classes bind.
const HUGGINGFACE_BASE_URL: &str = "https://router.huggingface.co/v1";

/// The recorded `huggingface` token grammar (`auth/huggingface.kdl`:
/// the API-key login pastes a fine-grained `hf_…` model-request
/// token): prefix plus a non-empty body. That token is the recorded
/// account/org billing form — material outside the grammar names
/// another class and never rides this contract.
const HUGGINGFACE_TOKEN_PREFIX: &str = "hf_";

/// The recorded `huggingface` static bundled rows (HZN-008 DEC-025 T1
/// static-bearer-chat cell; the pinned `models.json` `huggingface`
/// rows at OMP 18.1.14 @ `0133f7ff`): the class records these bundled
/// ids as the model universe, so they form the offer floor the
/// key-gated `/models` answer merges over without conferring
/// entitlement. The floor carries ids only — the bundled reference
/// descriptors (cost, image-input, context window, reasoning/effort)
/// stay uncarried, so a floor offer keeps [`ModelPrice::Unknown`] and
/// an empty capability surface.
const HUGGINGFACE_SEED: &[&str] = &[
    "MiniMaxAI/MiniMax-M2",
    "MiniMaxAI/MiniMax-M2.1",
    "MiniMaxAI/MiniMax-M2.5",
    "MiniMaxAI/MiniMax-M2.7",
    "MiniMaxAI/MiniMax-M3",
    "Qwen/Qwen2.5-Coder-32B-Instruct",
    "Qwen/Qwen3-235B-A22B",
    "Qwen/Qwen3-235B-A22B-Instruct-2507",
    "Qwen/Qwen3-235B-A22B-Thinking-2507",
    "Qwen/Qwen3-30B-A3B",
    "Qwen/Qwen3-32B",
    "Qwen/Qwen3-Coder-30B-A3B-Instruct",
    "Qwen/Qwen3-Coder-480B-A35B-Instruct",
    "Qwen/Qwen3-Coder-Next",
    "Qwen/Qwen3-Next-80B-A3B-Instruct",
    "Qwen/Qwen3-Next-80B-A3B-Thinking",
    "Qwen/Qwen3-VL-235B-A22B-Instruct",
    "Qwen/Qwen3-VL-235B-A22B-Thinking",
    "Qwen/Qwen3.5-122B-A10B",
    "Qwen/Qwen3.5-27B",
    "Qwen/Qwen3.5-35B-A3B",
    "Qwen/Qwen3.5-397B-A17B",
    "Qwen/Qwen3.5-9B",
    "Qwen/Qwen3.6-27B",
    "Qwen/Qwen3.6-35B-A3B",
    "Qwen/Qwen3.8-2.4T-A95B",
    "Qwen/Qwen3.8-27B",
    "XiaomiMiMo/MiMo-V2-Flash",
    "XiaomiMiMo/MiMo-V2.5",
    "XiaomiMiMo/MiMo-V2.5-Pro",
    "deepseek-ai/DeepSeek-R1",
    "deepseek-ai/DeepSeek-R1-0528",
    "deepseek-ai/DeepSeek-V3",
    "deepseek-ai/DeepSeek-V3-0324",
    "deepseek-ai/DeepSeek-V3.1",
    "deepseek-ai/DeepSeek-V3.2",
    "deepseek-ai/DeepSeek-V4-Flash",
    "deepseek-ai/DeepSeek-V4-Flash-0731",
    "deepseek-ai/DeepSeek-V4-Flash-Vision-Exp",
    "deepseek-ai/DeepSeek-V4-Pro",
    "deepseek-ai/DeepSeek-V4-Pro-0813",
    "google/gemma-4-26B-A4B-it",
    "google/gemma-4-31B-it",
    "meta-llama/Llama-3.1-8B-Instruct",
    "meta-llama/Llama-3.3-70B-Instruct",
    "meta-llama/Llama-3.3-70B-Instruct-Turbo",
    "moonshotai/Kimi-K2-Instruct",
    "moonshotai/Kimi-K2-Instruct-0905",
    "moonshotai/Kimi-K2-Thinking",
    "moonshotai/Kimi-K2.5",
    "moonshotai/Kimi-K2.6",
    "moonshotai/Kimi-K2.7-Code",
    "moonshotai/Kimi-K3",
    "openai/gpt-oss-120b",
    "openai/gpt-oss-20b",
    "stepfun-ai/Step-3.5-Flash",
    "stepfun-ai/Step-3.7-Flash",
    "tencent/Hy3",
    "thinkingmachines/Inkling",
    "thinkingmachines/Inkling-Small",
    "zai-org/GLM-4.5",
    "zai-org/GLM-4.5-Air",
    "zai-org/GLM-4.5V",
    "zai-org/GLM-4.6",
    "zai-org/GLM-4.6V-Flash",
    "zai-org/GLM-4.7",
    "zai-org/GLM-4.7-Flash",
    "zai-org/GLM-5",
    "zai-org/GLM-5.1",
    "zai-org/GLM-5.2",
    "zai-org/GLM-5.3",
    "zai-org/GLM-5.3-Flash",
];

/// The recorded default API root of a `kilo` connection
/// (`auth/kilo.kdl`, `kiloModelManagerOptions`'s
/// `config?.baseUrl ?? "https://api.kilo.ai/api/gateway"`): the host
/// the required `endpoint` field's empty string resolves under — the
/// same absent-override rule the plan classes bind.
const KILO_BASE_URL: &str = "https://api.kilo.ai/api/gateway";

/// The recorded `kilo` catalogue floor (HZN-008 class P — the pinned
/// descriptor's `defaultModel` at OMP 18.1.14 @ `0133f7ff`): the
/// recorded keyless discovery merges its `/models` offers over this
/// row, and an empty answer leaves it standing. The pinned roster
/// (`models.json`) is not vendored in this slice, so the per-row
/// descriptors it records for the id — cost, reasoning, effort — are
/// not carried: the offer keeps [`ModelPrice::Unknown`] and an empty
/// capability surface rather than a transcribed figure, and no
/// subscription SKU is invented either.
const KILO_MODELS: &[(&str, bool)] = &[("anthropic/claude-opus-4.8", false)];

/// The recorded `litellm` management-metadata paths, in the pinned
/// fetcher's order (`LITELLM_RICH_ENDPOINTS` in
/// `packages/catalog/src/provider-models/openai-compat.ts` at commit
/// `0133f7ff52d3859944b4fd4ccf3852df7fbf1b54`): the proxy's model-group
/// metadata first, then the v2 and v1 `model/info` forms. The paths are
/// appended to the management base — the configured base minus its
/// `/v1` segment.
const LITELLM_METADATA_PATHS: &[&str] = &[
    "/model_group/info",
    "/v2/model/info",
    "/model/info",
    "/v1/model/info",
];

/// The recorded bound on the whole management-metadata phase — the
/// pinned `litellmModelManagerOptions`' `timeoutMs: 10_000` around
/// `fetchLiteLLMRichModels`. Each probe spends at most the bound's
/// remainder ([`litellm_probe_budget`]); once it is spent the walk ends
/// with whatever it served.
const LITELLM_METADATA_BUDGET: Duration = Duration::from_secs(10);

/// The recorded `litellm` placeholder model groups
/// (`LITELLM_UNUSABLE_SENTINEL_IDS`): a row naming one of these and
/// carrying no metadata is the proxy's placeholder answer, never a
/// model it serves.
const LITELLM_SENTINEL_IDS: &[&str] = &["all-team-models", "all-proxy-models", "no-default-models"];

/// The recorded scale of the rich metadata's per-token USD prices
/// (`getLiteLLMPerMillionCost`): `input_cost_per_token` and
/// `output_cost_per_token` are per token, [`ModelPrice::Usd`] per 1M.
const LITELLM_PRICE_SCALE: f64 = 1_000_000.0;

/// The recorded default base of a `llama.cpp` connection
/// (`auth/llama.cpp.kdl`'s login instructions: "default base URL:
/// http://127.0.0.1:8080; set LLAMA_CPP_BASE_URL to customize") — the
/// host the required `endpoint` field's empty string resolves under. The
/// recorded default carries no `/v1` segment, so the dialect's own
/// `/chat/completions` path is appended to it verbatim.
const LLAMA_CPP_BASE_URL: &str = "http://127.0.0.1:8080";

/// The recorded default base of an `lm-studio` connection (the
/// traceability per-ID row's `127.0.0.1:1234/v1`) — the API root the
/// required `endpoint` field's empty string resolves under. Unlike
/// `llama.cpp`'s recorded base this one carries its `/v1` segment, so
/// the dialect's resource paths append directly; each local class keeps
/// its own recorded default and neither borrows the other's (EDGE-006).
const LM_STUDIO_BASE_URL: &str = "http://127.0.0.1:1234/v1";

/// The recorded bound on the `lm-studio` native metadata probe
/// (`LM_STUDIO_NATIVE_METADATA_TIMEOUT_MS = 250` at commit
/// `0133f7ff52d3859944b4fd4ccf3852df7fbf1b54`): the probe runs beside
/// the `/models` listing under this bound clipped to the whole call's
/// remainder, and a spent bound leaves the listing's offers untouched.
const LM_STUDIO_NATIVE_METADATA_BUDGET: Duration = Duration::from_millis(250);

/// The recorded `minimax-code` international endpoint — the
/// `api.minimax.io/v1` host the DEC-025 row's `ключ подписки →
/// api.minimax.io/v1` binding names: the API root the required
/// `endpoint` field's empty string resolves under, under the same
/// absent-override rule the plan classes bind. The plan window and
/// credits stay account facts of the enrolled key — the record names
/// no `/models` discovery and no vendored roster, so this constant
/// carries the base alone and the `minimax-code-cn` host on
/// `api.minimaxi.com` is a different connection's arm (EDGE-007).
const MINIMAX_CODE_INTL_BASE_URL: &str = "https://api.minimax.io/v1";

/// The recorded `minimax-code-cn` CN endpoint — the
/// `api.minimaxi.com/v1` host the DEC-025 row's `ключ подписки →
/// api.minimaxi.com/v1` binding names: the API root the required
/// `endpoint` field's empty string resolves under, under the same
/// absent-override rule the plan classes bind. The CN plan's fixed
/// window and credits stay account facts of the enrolled key — the
/// record names no `/models` discovery and no vendored roster, so this
/// constant carries the base alone; the international sibling's
/// `api.minimax.io` host and the `minimax.cn` Anthropic URL are a
/// recorded divergence, never substituted (EDGE-007/DEC-007).
const MINIMAX_CODE_CN_BASE_URL: &str = "https://api.minimaxi.com/v1";

/// The recorded `mistral` endpoint — the `api.mistral.ai/v1` host the
/// DEC-025 row's `Rivect/key → api.mistral.ai/v1` binding names: the
/// API root the required `endpoint` field's empty string resolves
/// under, under the same absent-override rule the plan classes bind.
/// The env/credential-chain login's env traversal stays credential-
/// substrate debt (DEC-006/D4): the band carries the scoped `SecretRef`
/// seam alone and this constant carries the base alone.
const MISTRAL_BASE_URL: &str = "https://api.mistral.ai/v1";

/// The recorded `moonshot` endpoint — the `api.moonshot.ai/v1` host
/// the DEC-025 row's `Rivect/key → configured MOONSHOT base, default
/// api.moonshot.ai/v1` binding names: the API root the required
/// `endpoint` field's empty string resolves under, under the same
/// absent-override rule the plan classes bind. The configured base
/// redirects discovery and streaming alike, and the recorded
/// `KIMI_API_KEY` fallback key name proves neither region nor
/// payment — no region or billing class is ever inferred from the
/// material's name.
const MOONSHOT_BASE_URL: &str = "https://api.moonshot.ai/v1";

/// The recorded `nanogpt` endpoint — the `nano-gpt.com/api/v1` host
/// the DEC-025 row's `Rivect/key → nano-gpt.com/api/v1` binding names:
/// the API root the required `endpoint` field's empty string resolves
/// under, under the same absent-override rule the plan classes bind.
/// The recorded explicit routing and price settings are catalogue
/// metadata with no vendored carrier (D6): this constant carries the
/// base alone, and the recorded subscription base is a separate
/// configured payment class — never a kind or fallback this adapter
/// constructs (DEC-010).
const NANOGPT_BASE_URL: &str = "https://nano-gpt.com/api/v1";

/// The recorded `novita` endpoint — the `api.novita.ai/openai/v1` host
/// the DEC-025 row's `Rivect/key → api.novita.ai/openai/v1` binding
/// names: the API root the required `endpoint` field's empty string
/// resolves under, under the same absent-override rule the plan
/// classes bind. The recorded login validates against inference on
/// this base rather than the payment administration API, because a
/// limited team role holds no billing scope while its inference key
/// is valid; this adapter constructs no payment leg at all. The
/// recorded entry prices are listing facts in the class's own
/// 1/10,000-USD units, which this class carries no vendored row for
/// (D6): no price is borrowed from another connection.
const NOVITA_BASE_URL: &str = "https://api.novita.ai/openai/v1";

/// The recorded `nvidia` endpoint — the `integrate.api.nvidia.com/v1`
/// host the pinned `nvidiaModelManagerOptions` hands to
/// `createSimpleOpenAICompletionsOptions`: the API root the required
/// `endpoint` field's empty string resolves under, under the same
/// absent-override rule the plan classes bind. The recorded login
/// validates the key against inference optionally (`optional=#true`):
/// a `401`/`403` is the hard auth rejection, any other failure proves
/// neither access nor denial.
const NVIDIA_BASE_URL: &str = "https://integrate.api.nvidia.com/v1";

/// The recorded default API root of a `qianfan` connection
/// (`https://qianfan.baidubce.com/v2`): the host the required
/// `endpoint` field's empty string resolves under, under the same
/// absent-override rule the plan classes bind. The class records no
/// region selector — the base itself carries the API version — and no
/// per-model price or roster row, so an offered id keeps
/// [`ModelPrice::Unknown`] and an unlisted id is never seeded.
const QIANFAN_BASE_URL: &str = "https://qianfan.baidubce.com/v2";

/// The recorded default API root of a `qwen-portal` connection
/// (`https://portal.qwen.ai/v1`): the host the required `endpoint`
/// field's empty string resolves under, under the same
/// absent-override rule the plan classes bind. The paste api-key
/// alternative (`QWEN_OAUTH_TOKEN`/`QWEN_PORTAL_API_KEY` names) is
/// live-ingress metadata, never an environment read this adapter
/// constructs (DEC-011); the recorded Qwen OAuth free-tier lifecycle
/// (token refresh, quota, revocation) is a bounded residual owned by
/// position 19 (D6/DEC-002), so this class records no lifecycle leg
/// and claims no entitlement. The recorded `coder-model` default is a
/// catalogue hint, never a seeded offer or ranking (DEC-014/D11).
const QWEN_PORTAL_BASE_URL: &str = "https://portal.qwen.ai/v1";

/// The recorded default API root of a `siliconflow` connection
/// (`https://api.siliconflow.com/v1`): the host the required
/// `endpoint` field's empty string resolves under, under the same
/// absent-override rule the plan classes bind. The recorded
/// `SILICONFLOW_API_KEY` env name is live-ingress metadata, never an
/// environment read this adapter constructs (DEC-011), and the class
/// records no region selector — the base itself carries the region.
/// The recorded `zai-org/GLM-5.1` default is a catalogue hint, never a
/// seeded offer or ranking (DEC-014/D11), and the recorded models.dev
/// metadata hydration is a runtime residual (D2) this adapter does not
/// carry.
const SILICONFLOW_BASE_URL: &str = "https://api.siliconflow.com/v1";

/// The recorded default API root of a `siliconflow-cn` connection
/// (`https://api.siliconflow.cn/v1`): the distinct CN host the required
/// `endpoint` field's empty string resolves under, under the same
/// absent-override rule `siliconflow` binds. The id-keyed region split
/// (EDGE-007) keeps the hosts, the recorded `SILICONFLOW_CN_API_KEY`
/// env name and the credential scopes per id: neither host is ever
/// substituted for the other, and the env name is live-ingress
/// metadata, never an environment read this adapter constructs
/// (DEC-011). The class records no region selector — the base itself
/// carries the region — and the shared exclusion list and
/// `min(maxTokens, context)` clamp apply unchanged, with the recorded
/// models.dev hydration a runtime residual (D2).
const SILICONFLOW_CN_BASE_URL: &str = "https://api.siliconflow.cn/v1";

/// The recorded default API root of a `synthetic` connection
/// (`https://api.synthetic.new/openai/v1`): the pinned code's
/// `openai/v1` root the required `endpoint` field's empty string
/// resolves under, under the same absent-override rule the plan
/// classes bind — never the documentation's bare `/v1`, because the
/// pinned code binds. The recorded `SYNTHETIC_API_KEY` env name is
/// live-ingress metadata, never an environment read this adapter
/// constructs (DEC-011), and the class records no region selector —
/// the base itself carries the API version. The recorded
/// `hf:zai-org/GLM-5.2` default is a catalogue hint, never a seeded
/// offer or ranking (DEC-014/D11), and the recorded Anthropic-format
/// sibling (`/anthropic/v1/messages`) is a different connection class
/// this arm never constructs (D7).
const SYNTHETIC_BASE_URL: &str = "https://api.synthetic.new/openai/v1";

/// The recorded output-cap fallback a `synthetic` route advertises no
/// `max_output_length` or `max_tokens` for (`SYNTHETIC_FALLBACK_MAX_TOKENS`):
/// a cap low enough that verbose models stop on `length`, which is
/// exactly the recorded placeholder's stated trade-off. This adapter
/// carries no bundled reference, so the chain ends here.
const SYNTHETIC_FALLBACK_MAX_TOKENS: u64 = 8192;

/// The recorded default API root of a `together` connection
/// (`https://api.together.xyz/v1`): the pinned `.xyz` host the required
/// `endpoint` field's empty string resolves under, under the same
/// absent-override rule the plan classes bind. The documentation's
/// `.ai` alias and the US endpoint alias are never substituted
/// (DEC-005), and the class records no region selector — the base
/// itself carries the API version. The class records no per-model
/// price or roster row (D2), so an offered id keeps
/// [`ModelPrice::Unknown`].
const TOGETHER_BASE_URL: &str = "https://api.together.xyz/v1";

/// The recorded default API root of a `venice` connection
/// (`https://api.venice.ai/api/v1` in the traceability per-ID row): the
/// host the required `endpoint` field's empty string resolves under,
/// under the same absent-override rule the plan classes bind. The host's
/// `/models` listing is public and rides keyless, which is never
/// authentication; the class records no region selector, so a configured
/// `region` denies typed.
const VENICE_BASE_URL: &str = "https://api.venice.ai/api/v1";

/// The recorded default API root of a `vllm` connection
/// (`127.0.0.1:8000/v1` in the traceability per-ID row): the host the
/// required `endpoint` field's empty string resolves under, under the
/// same absent-override rule the local-endpoint class binds. It is its
/// own recorded host — never `llama.cpp`'s `http://127.0.0.1:8080` or
/// `lm-studio`'s `http://127.0.0.1:1234/v1` (EDGE-006) — and carries
/// no region selector, so a configured `region` denies typed.
const VLLM_BASE_URL: &str = "http://127.0.0.1:8000/v1";

/// The recorded per-model K3 effort ladder the pinned `moonshot`
/// rows state (`reasoning_effort` `low`/`high`): a level a model
/// does not name is a parameter its wire contract rejects, so a pin
/// carrying it denies typed rather than dropping `reasoning_effort`
/// from the body. A model absent here records no effort surface, so
/// every pinned level denies for it. The recorded `max` level has no
/// landing in our enum and never maps onto a lower one, so no `max`
/// request is ever constructed (DEC-014).
const MOONSHOT_EFFORTS: &[(&str, &[EffortLevel])] =
    &[("kimi-k3", &[EffortLevel::Low, EffortLevel::High])];

/// The recorded endpoint rule a literal id binds (HZN-008): the
/// dialect is shared across connection ids — how a configured
/// endpoint becomes the API root is not.
enum EndpointRule {
    /// The configured origin is the API base verbatim, trailing
    /// slashes trimmed (`custom-chat-completions` binds egress to the
    /// configured origin and records no fixed host).
    Verbatim,
    /// `aiand`'s `normalizeAiandBaseUrl`: a bare configured base gains
    /// the `/v1` tail, an empty one resolves the recorded default
    /// host.
    NormalizedV1Root,
    /// `aimlapi`'s `config?.baseUrl ?? defaultBaseUrl` under the
    /// discovery client's `normalizeBaseUrl` — the configured base
    /// trimmed, a single trailing slash stripped — with the required
    /// field's empty string standing for the absent override the
    /// `??` fallback covers: the recorded default host.
    ConfiguredElseDefault,
    /// The configured-or-recorded base resolution the plan providers
    /// (`alibaba-coding-plan`, `alibaba-token-plan`) and the
    /// local-endpoint class (`llama.cpp`, `lm-studio`, `vllm`) share: the configured origin
    /// verbatim under the recorded ingress normalization —
    /// trimmed, all trailing slashes stripped, as the login hook's
    /// custom-origin input is normalized — with the required field's
    /// empty string standing for the absent override: the carried
    /// recorded class endpoint. The region choice —
    /// international, China or a custom origin — is this configured
    /// base itself; neither recorded contract names a `region` field.
    PlanBaseOrDefault(&'static str),
}

/// The recorded catalogue source a literal id binds (HZN-008): the
/// dialect shares the response shape — where the offered ids come
/// from is per-connection contract.
enum CatalogRule {
    /// The configured endpoint's own `GET {endpoint}/models` listing
    /// under the per-entry transform, with the recorded static seed
    /// merged on top as the offer floor.
    Listing,
    /// The recorded fixed allowed-model list alone — the lookup opens
    /// no wire leg and resolves no credential, so a `/models` answer
    /// (keyless or keyed) can never add an offer. Each tuple is the
    /// model id and its bundled-descriptor vision mark. An auto pick
    /// resolves the sorted-first id — the adapter's one uniform auto
    /// semantic; a descriptor's recorded `defaultModel` is a
    /// catalogue hint, not a product ranking this contract performs.
    Allowlist(&'static [(&'static str, bool)]),
    /// The recorded credential-optional *discovery* (`kilo`'s and
    /// `novita`'s `catalogDiscovery.allowUnauthenticated` and the
    /// `fetchOpenAICompatibleModels` call with `apiKey` optional): the
    /// configured endpoint's own `/models` answer contributes its
    /// offers under the per-entry transform, the recorded rows below
    /// merge on top as the offer floor — an empty answer leaves the
    /// floor standing — and the `Authorization` header rides only
    /// when the store resolves material. This variant's tolerance is
    /// the catalogue's alone, over an absent *scope* on a class that
    /// still binds a credential ([`CredentialRule::Kilo`],
    /// [`CredentialRule::Bearer`]): the
    /// recorded keyless catalogue answers, while the same absent
    /// material denies a send. An undeclared *binding* is a different
    /// recorded fact with its own arm ([`CredentialRule::OpenProxy`]),
    /// so neither policy is inferred from the other. A
    /// resolved-but-unusable credential still denies typed rather than
    /// silently dropping to the keyless form, and no answer confers
    /// entitlement: a paid send resolves its credential before any
    /// leg. Each floor tuple is the model id and its image-input mark
    /// — the bundled descriptor's recorded mark where the class
    /// records one, `false` otherwise.
    UnauthenticatedListing(&'static [(&'static str, bool)]),
}

/// The recorded credential grammar a literal id binds (HZN-008):
/// what the resolved store material may be before it bears a wire
/// leg is per-connection contract, enforced inside the credential
/// seam — before any request.
enum CredentialRule {
    /// The material is the bearer token verbatim — any UTF-8 string
    /// the store resolves.
    Bearer,
    /// `alibaba-coding-plan`'s recorded `api-key-format "structured"`
    /// credential: a JSON object whose `token` is the bearer and whose
    /// `enterpriseUrl` is the base the key was enrolled and validated
    /// against — required to equal the connection's configured base,
    /// so a key enrolled for one base class can never serve another.
    /// It is the only shape the recorded login writes: a bare key or
    /// a token-only blob is unbound material — attributable to no
    /// base — and denies as malformed. The bearer must carry the
    /// recorded plan-key grammar.
    AlibabaPlan,
    /// `alibaba-token-plan`'s recorded credential
    /// (`parseAlibabaTokenPlanCredential`): a bare `sk-…` token, or a
    /// JSON object whose `token` is the bearer, whose optional
    /// `baseUrl` is the region base the key was enrolled and validated
    /// against — absent meaning the recorded international endpoint —
    /// required to equal the connection's configured base, and whose
    /// optional `cookie` is the separately admitted quota credential:
    /// shape-checked and dropped — the recorded login pastes it by
    /// hand for a usage API this adapter has no leg for, so no wire
    /// leg, diagnostic or surface ever reads it. The bearer must carry
    /// the recorded `TOKEN_PATTERN` grammar.
    AlibabaTokenPlan,
    /// `firepass`'s recorded credential (`auth/firepass.kdl`): a
    /// dedicated `fpk_…` Fire Pass key bound to its own enrollment.
    /// The connection shares `api.fireworks.ai` with `fireworks` but
    /// never a key class — a Fireworks account key is unbound
    /// material here and denies as malformed before any wire leg.
    Firepass,
    /// `coreweave`'s recorded credential (`Rivect/key +
    /// OpenAI-Project`, wire/coreweave.ts): the recorded login is
    /// `api-key`, whose `OpenAI-Project` header hook resolves from the
    /// environment — a channel the transport has none of — so the
    /// store slot holds Rivect's translated scoped JSON: `key` is the
    /// bearer and `OpenAI-Project` is the `<team>/<project>` scope the
    /// request carries, resolved before any fetch and failed closed
    /// without. The bare pasted key is login input the credential
    /// substrate resolves into that stored form (D4), never store
    /// material: a bare key, a key-only blob, an empty member or
    /// material outside the scoped shape denies as malformed before
    /// any wire leg.
    CoreWeave,
    /// `huggingface`'s recorded credential (`auth/huggingface.kdl`):
    /// the fine-grained model-request token the API-key login pastes
    /// — the `hf_…` grammar — and the one billing form the row
    /// records: the router charges the request to the token's user or
    /// org. Material of another class — a provider-signed key that
    /// would bill at the provider (BYOK), a structured blob the login
    /// never writes — denies as malformed before any wire leg rather
    /// than being forwarded under an inferred billing mode (INV-005).
    HuggingFace,
    /// `kilo`'s recorded credential (`auth/kilo.kdl` `login "custom"`,
    /// `registry/oauth/kilo.ts`, descriptor env `KILO_API_KEY`): the
    /// explicit device login's opaque gateway token, or the recorded
    /// key, is a bare bearer with no prefix and no structured shape.
    /// The class records no subscription SKU, so material naming no
    /// token — empty or whitespace only — is unenrolled material and
    /// denies as malformed before any wire leg rather than reaching
    /// the gateway as an empty bearer.
    Kilo,
    /// `litellm`'s recorded credential-optional auth class (HZN-008
    /// class B, `auth/litellm.kdl` `login "api-key"` against a
    /// user-configured proxy) and `llama.cpp`'s recorded optional auth
    /// beside its server-key mode (`auth/llama.cpp.kdl`),
    /// `lm-studio`'s recorded optional auth over its local base
    /// (`auth/lm-studio.kdl`) and `vllm`'s configured local mode with
    /// or without a server key: the recorded
    /// absent-binding form. A declaration that binds nothing is admitted
    /// and rides headerless on *every* leg — the host's own
    /// unauthenticated path, never a dummy key — while a declaration that
    /// does bind resolves the plain bearer and a bound scope that cannot
    /// resolve denies typed on every leg. The admission fact lives here,
    /// not in the catalogue: [`CatalogRule::UnauthenticatedListing`] is
    /// `kilo`'s separate discovery tolerance over an absent scope.
    OpenProxy,
}

/// The recorded per-entry transform a `data[]` listing runs
/// (HZN-008): the generic class carries model ids only,
/// `aiand`'s org-scoped listing applies the recorded
/// capability/effort/currency map (`mapAiandModel`), and `aimlapi`'s
/// applies the recorded chat-id filter to a defaults-only surface.
enum EntryRule {
    /// Every id with a non-whitespace body verbatim — the generic
    /// class records no per-model metadata surface.
    IdsOnly,
    /// The recorded generic listing surface some classes state beside
    /// the id: `data[].id` with `context_length` and
    /// `max_completion_tokens` mapped when the entry carries a
    /// positive value (DEC-020). An absent or unreadable value stays
    /// `None` — no default figure, no borrowed sibling field — and no
    /// class using this rule records a seed floor.
    GenericMetadata,
    /// The org-scoped `aiand` transform: `capabilities` names the
    /// reasoning and image-input surface, `reasoning_efforts` maps
    /// onto the effort ladder, and the org's billing currency decides
    /// whether the stated per-1M-token price lands.
    Aiand,
    /// The `aimlapi` transform: the id must pass the recorded chat-id
    /// filter (`isLikelyAimlApiChatModelId` — the provider's
    /// `exclude-models` roster drops the media and embedding SKUs the
    /// chat surface cannot serve); an admitted id lands the defaults
    /// surface alone — `mapWithBundledReference` hydrates a listing
    /// entry only through a bundled reference index this adapter does
    /// not carry, so the listing states the id alone.
    Aimlapi,
    /// The `alibaba-token-plan` transform: the id must pass the
    /// recorded chat-id filter (`isAlibabaTokenPlanChatModelId` — the
    /// provider's `exclude-models` prefix roster drops the
    /// ASR/image/embedding SKUs the chat picker cannot route); an
    /// admitted id lands the defaults surface alone — the recorded
    /// `mapModel` reference/limits hydration is the enrichment layer
    /// this adapter does not carry, the same boundary `aimlapi`
    /// applies.
    AlibabaTokenPlan,
    /// The `deepseek` transform: the id must name a recorded built-in
    /// (`DEEPSEEK_BUILTIN_MODELS` — the offered universe the roster
    /// bounds); an admitted id lands the recorded surface — the
    /// native reasoning mark with the mappable effort levels, the
    /// `vision-exp` build's image-input mark, the million-token
    /// window and the recorded per-model USD prices — while the
    /// prepaid balance stays an account fact. A benchmark or legacy
    /// id the listing carries is never offered.
    DeepSeek,
    /// The `fireworks` transform — the recorded serverless/fast
    /// chat-model predicates (DEC-025): the listed id is normalized
    /// to its public form (`toFireworksPublicModelId` — the
    /// `accounts/fireworks/models/` prefix stripped, the `p` version
    /// separator folded back to `.`), and an id still carrying the
    /// reserved `accounts/fireworks/` prefix is dropped under the
    /// recorded `exclude-models` runtime rule — a router id is a
    /// serving path, never a model this connection offers. The
    /// admitted id carries the per-model USD price the pinned
    /// `models.json` row states (`FIREWORKS_PRICES` — a stated zero
    /// is a real figure); the listing row names nothing else, and
    /// the class records no other entry surface this transform maps.
    Fireworks,
    /// The `firepass` arm: the class binds the recorded static router
    /// allowlist, so no listing entry is ever transformed — a listed
    /// id proves no access this class records and offers nothing —
    /// while the arm's live duty is the wire dispatch: every offered
    /// router id sends under the `accounts/fireworks/routers/` form.
    /// Unreached under [`CatalogRule::Allowlist`]: no listing exists
    /// to transform.
    Firepass,
    /// The `groq` arm: the recorded static and benchmark floor merges
    /// over the provider's non-authoritative `/models` listing, so a
    /// listed foreign id is offered as served — no recorded price,
    /// effort or vision surface — while a seeded recorded id keeps the
    /// reference surface [`groq_entry`] states. The per-model effort
    /// predicate does not live here: [`ChatCompletionsProvider::check_parameters`]
    /// owns the typed denial of a pinned `reasoning_effort` the model's
    /// recorded ladder does not carry — never a silently dropped body
    /// field. The class's other recorded-rejected parameters (logprobs,
    /// logit_bias, top_logprobs, `messages[].name`, `n`, temperature)
    /// are never constructed by this adapter, so none can be dropped.
    Groq,
    /// The `huggingface` arm: the recorded `provider/model` routing
    /// rule is why the class carries its own arm, and that rule's
    /// transform is identity — not a rewrite a reader should expect.
    /// A listed namespaced id (`org/model`) and a listed id carrying the
    /// `:provider` serving suffix ride the catalogue and the wire
    /// exactly as served; nothing is stripped, folded or re-prefixed.
    /// The router selects the serving provider from that suffix, so a
    /// rewrite would silently reroute a pinned model.
    HuggingFace,
    /// The `litellm` arm: the recorded discovery is the proxy's
    /// management metadata first — [`LITELLM_METADATA_PATHS`] probed in
    /// order under one bounded phase budget, with the recorded
    /// fall-through to `/models` — and this arm carries both halves of
    /// that shape. A metadata entry maps through the rich transform
    /// ([`litellm_metadata_model`]): the id from `model_group` /
    /// `model_name` / `id` / `litellm_params.model`, the capability
    /// marks, the input window and the per-token→per-1M price from the
    /// entry or its `model_info` object. A row the `/models`
    /// fall-through yields is the OpenAI-compatible listing form, so it
    /// carries its id alone — the metadata leg is the rich source.
    LiteLlm,
    /// The `lm-studio` arm: the listed id is the OpenAI-compatible
    /// listing form offered id-only, and the class records one extra
    /// catalogue source beside that listing — its native loaded-context
    /// probe (`GET {native base}/api/v0/models`, the configured base
    /// without its `/v1` segment) —
    /// [`ChatCompletionsProvider::lm_studio_catalog`] starts in
    /// parallel and overlays on the ids the listing already offers.
    /// The listing stays authoritative: a row the probe alone names
    /// adds nothing.
    LmStudio,
    /// The `moonshot` arm: the `requireApiKey` `/models` listing's
    /// rows are offered id-only — the recorded price/roster metadata
    /// has no vendored carrier (D6) — while the arm's live duty is
    /// the recorded K3 effort ladder [`MOONSHOT_EFFORTS`] states:
    /// [`ChatCompletionsProvider::check_parameters`] owns the typed
    /// denial of a pinned `reasoning_effort` the pin's model does
    /// not record, never a silently dropped body field.
    Moonshot,
    /// The `nanogpt` arm: the api-key-gated `/models` listing's rows
    /// pass the recorded chat-id filter — a `:thinking`-suffixed alias
    /// (`NANO_GPT_THINKING_SUFFIX_RE`, `:thinking` with or without a
    /// `:<level>` tail) is never offered; it only marks the base id it
    /// collapses into, which [`ChatCompletionsProvider::catalog_within`]
    /// applies after the per-entry pass. The record's explicit routing
    /// and price settings have no vendored carrier (D6), and the
    /// subscription base is a separate configured payment class — never
    /// a fallback this arm constructs (DEC-010).
    NanoGpt,
    /// The `novita` arm: the recorded keyless `/models` discovery
    /// (`catalogDiscovery.allowUnauthenticated`, no `requireApiKey`)
    /// is authoritative (`dynamicModelsAuthoritative`); an absent
    /// scope rides this listing anonymously, while the send leg still
    /// denies `CredentialAbsent`, and each `data[]` entry passes the
    /// recorded conjunction — a numeric
    /// `status` other than `1` is inactive, an `ai_infer_test` id is
    /// a test SKU, `endpoints` must carry `chat/completions` as an
    /// array member, and `max_output_tokens` must read positive —
    /// so an unfiltered or public listing row can never widen the
    /// offer set. No vendored roster or price row exists (D6), and a
    /// limited-role key is verified by a model request, never by
    /// payment administration.
    Novita,
    /// The `siliconflow`/`siliconflow-cn` arm: the key-gated
    /// authoritative `/models` listing drops the recorded non-chat
    /// families ([`SILICONFLOW_EXCLUDED_SUBSTRINGS`]) and maps a
    /// listed `context_length`/`max_completion_tokens` under the
    /// recorded `min(maxTokens, context)` clamp. The recorded
    /// models.dev hydration is a runtime-only enrichment this offline
    /// adapter does not carry (D2), so an admitted id keeps the limits
    /// the listing states and no borrowed price. Both region ids share
    /// this transform; their hosts and credentials stay per-id.
    SiliconFlow,
    /// The `synthetic` arm: the key-gated authoritative `/models`
    /// listing's nonstandard record shape — capabilities arrive in
    /// `supported_features` (only `reasoning` has a carrier; `tools`
    /// stays a capability this record surface does not carry),
    /// modalities in `input_modalities` (`image` marks vision), the
    /// output cap in `max_output_length`, then the generic
    /// `max_tokens`, then the recorded 8192 fallback because this
    /// adapter carries no bundled reference, and the accepted effort
    /// vocabulary in `reasoning_parameters.efforts`. Only levels our
    /// effort enum names land: `none` is the thinking-off router
    /// state, never a user effort, and `max` names no representable
    /// level (DEC-008), so neither is coerced onto a neighbour. Per-token
    /// USD prices in `pricing.prompt`/`pricing.completion` are
    /// `$`-prefixed decimals scaled to per-1M figures; a partial or
    /// unreadable price stays [`ModelPrice::Unknown`], never a
    /// default figure. Unknown keys are ignored and absent values
    /// stay at their empty surface.
    Synthetic,
    /// The `vllm` transform: the listing's own `max_model_len` is the
    /// served context window (vLLM's field, never the shared
    /// `context_length`), and a Qwen `major.minor` at or above 3.8 in
    /// the offered id carries the display-only reasoning mark the
    /// recorded Qwen chat template uses. The listing states no effort
    /// ladder, so the mark is display-only: a pinned
    /// `reasoning_effort` is denied typed at the send seam rather than
    /// silently dropped.
    Vllm,
}

/// The predicates the recorded source class binds to a literal Chat
/// Completions id (HZN-008): the dialect is shared across connection
/// ids — the endpoint rule, the catalogue source, the credential
/// grammar, the catalogue seed and the per-entry transform are not.
struct SourceContract {
    /// The recorded static-seed model ids merging into the listing as
    /// the offer floor — empty where the class records no seed.
    /// Unreached under [`CatalogRule::Allowlist`]: a static catalogue
    /// carries its whole surface in the allowlist itself.
    seed: &'static [&'static str],
    /// The recorded endpoint rule the configured `endpoint` resolves
    /// under.
    endpoint: EndpointRule,
    /// The recorded catalogue source the lookup resolves under.
    catalog: CatalogRule,
    /// The recorded credential grammar the resolved material must
    /// satisfy before it bears a wire leg.
    credential: CredentialRule,
    /// The recorded per-entry transform over `data[]` entries.
    /// Unreached under [`CatalogRule::Allowlist`]: no listing exists
    /// to transform.
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
            endpoint: EndpointRule::Verbatim,
            catalog: CatalogRule::Listing,
            credential: CredentialRule::Bearer,
            entries: EntryRule::IdsOnly,
        }),
        "aiand" => Some(SourceContract {
            seed: AIAND_MODELS,
            endpoint: EndpointRule::NormalizedV1Root,
            catalog: CatalogRule::Listing,
            credential: CredentialRule::Bearer,
            entries: EntryRule::Aiand,
        }),
        // `aimlApiModelManagerOptions`: no static seed, the
        // configured-or-default host rule and the chat-id listing
        // filter — the account's shared balance is an account-level
        // fact the recorded contract gives no wire surface.
        "aimlapi" => Some(SourceContract {
            seed: &[],
            endpoint: EndpointRule::ConfiguredElseDefault,
            catalog: CatalogRule::Listing,
            credential: CredentialRule::Bearer,
            entries: EntryRule::Aimlapi,
        }),
        // `alibabaCodingPlanModelManagerOptions`: the configured-or-
        // recorded-international base carrying the region choice, the
        // recorded allowed-model list alone — the class records no
        // `/models` discovery — and the `api-key-format "structured"`
        // credential binding a key to the base it was enrolled for.
        "alibaba-coding-plan" => Some(SourceContract {
            seed: &[],
            endpoint: EndpointRule::PlanBaseOrDefault(ALIBABA_PLAN_INTL_BASE_URL),
            catalog: CatalogRule::Allowlist(ALIBABA_PLAN_MODELS),
            credential: CredentialRule::AlibabaPlan,
            entries: EntryRule::IdsOnly,
        }),
        // `alibabaTokenPlanModelManagerOptions`: the configured-or-
        // recorded-international base carrying the region choice, the
        // configured base's own authoritative `/models` listing under
        // the recorded chat-id filter (`dynamicModelsAuthoritative` —
        // the discovered set alone; the recorded static fallback list
        // rides the upstream client cache layer, never a seed union
        // here), and the structured `{token, cookie?, baseUrl?}`
        // credential binding a key to the region base it was enrolled
        // for.
        "alibaba-token-plan" => Some(SourceContract {
            seed: &[],
            endpoint: EndpointRule::PlanBaseOrDefault(ALIBABA_TOKEN_PLAN_INTL_BASE_URL),
            catalog: CatalogRule::Listing,
            credential: CredentialRule::AlibabaTokenPlan,
            entries: EntryRule::AlibabaTokenPlan,
        }),
        // `coreweave` (HZN-008 class A): the configured-or-recorded
        // `api.inference.wandb.ai/v1` base, the authoritative
        // `/models` listing admitted id-only — team/project spend and
        // geography stay recorded-separate data, never synthesized
        // surface — and the scoped `{key, OpenAI-Project}` JSON as
        // Rivect's translated store form of the recorded `api-key`
        // login, whose `OpenAI-Project` hook the environment resolves
        // — a channel the transport has none of. The bare pasted key
        // is login input the credential substrate resolves (D4),
        // never store material, so material outside the scoped shape
        // denies before any leg.
        "coreweave" => Some(SourceContract {
            seed: &[],
            endpoint: EndpointRule::PlanBaseOrDefault(COREWEAVE_DEFAULT_BASE_URL),
            catalog: CatalogRule::Listing,
            credential: CredentialRule::CoreWeave,
            entries: EntryRule::IdsOnly,
        }),
        // `deepinfra` (HZN-008 class A): the configured-or-recorded
        // `api.deepinfra.com/v1/openai` base, the authoritative
        // chat-model `/models` listing — the public metadata
        // catalogue never an authentication surface — and the plain
        // bearer credential: ids-only offers keep service-tier and
        // flex surcharges as recorded-separated metadata, never a
        // synthesized price.
        "deepinfra" => Some(SourceContract {
            seed: &[],
            endpoint: EndpointRule::PlanBaseOrDefault(DEEPINFRA_DEFAULT_BASE_URL),
            catalog: CatalogRule::Listing,
            credential: CredentialRule::Bearer,
            entries: EntryRule::IdsOnly,
        }),
        // `deepseek` (HZN-008 class A): the configured-or-recorded
        // `api.deepseek.com` base, the authoritative `/models`
        // listing gated by the recorded built-in roster — built-in
        // ids offered with their native reasoning surface, benchmark
        // ids never — the roster merged on top as the offer floor,
        // and the plain bearer credential: the recorded per-model
        // USD prices carry; the prepaid balance stays an account fact.
        "deepseek" => Some(SourceContract {
            seed: DEEPSEEK_BUILTIN_MODELS,
            endpoint: EndpointRule::PlanBaseOrDefault(DEEPSEEK_BASE_URL),
            catalog: CatalogRule::Listing,
            credential: CredentialRule::Bearer,
            entries: EntryRule::DeepSeek,
        }),
        // `firepass` (HZN-008 class P): the same
        // `api.fireworks.ai/inference/v1` base `fireworks` serves under
        // its own connection id, the recorded static router catalogue
        // alone — the `fpk_…` key authorizes no `/models` lookup, so a
        // listing answer never proves access and no discovery leg
        // exists — the dedicated `fpk_` key grammar, and the class
        // rule carrying the router wire dispatch: admission and egress
        // discriminate by connection id, never by host.
        "firepass" => Some(SourceContract {
            seed: &[],
            endpoint: EndpointRule::PlanBaseOrDefault(FIREWORKS_BASE_URL),
            catalog: CatalogRule::Allowlist(FIREPASS_MODELS),
            credential: CredentialRule::Firepass,
            entries: EntryRule::Firepass,
        }),
        // `fireworks` (HZN-008 class A): the configured-or-recorded
        // `api.fireworks.ai/inference/v1` base — the host `firepass`
        // shares under a distinct connection id and credential
        // grammar — the configured base's own request-model
        // `/models` listing (the `/v1/accounts/fireworks/models`
        // management API is never a model source, and a `/models`
        // HTTP 200 is never entitlement), the recorded Fast seed as
        // the offer floor for the router variants the listing never
        // surfaces, and the plain bearer credential: the
        // serverless/fast predicates gate admission, the recorded
        // per-model USD prices carry.
        "fireworks" => Some(SourceContract {
            seed: FIREWORKS_FAST_IDS,
            endpoint: EndpointRule::PlanBaseOrDefault(FIREWORKS_BASE_URL),
            catalog: CatalogRule::Listing,
            credential: CredentialRule::Bearer,
            entries: EntryRule::Fireworks,
        }),
        // `gmi-cloud` (HZN-008 class A): the configured-or-recorded
        // `api.gmi-serving.com/v1` base, the authoritative `/models`
        // listing under ids-only offers — a listing row's bare id is
        // offered exactly as served, never namespaced or otherwise
        // rewritten — and the plain bearer credential. The class
        // records no per-model price: an unrecorded id keeps
        // [`ModelPrice::Unknown`], never a figure borrowed from
        // another connection's table.
        "gmi-cloud" => Some(SourceContract {
            seed: &[],
            endpoint: EndpointRule::PlanBaseOrDefault(GMI_BASE_URL),
            catalog: CatalogRule::Listing,
            credential: CredentialRule::Bearer,
            entries: EntryRule::IdsOnly,
        }),
        // `groq` (HZN-008 class A): the configured-or-recorded
        // `api.groq.com/openai/v1` base, the recorded static and
        // benchmark floor merged over the provider's non-authoritative
        // `/models` list — a listed foreign id is offered, and a 200
        // listing never proves entitlement — the plain bearer
        // credential, and the recorded per-model effort predicate: a
        // pinned `reasoning_effort` the pin's model does not record is
        // a rejected parameter that denies typed — before any wire leg
        // for a fixed pin, and before the chat request leg for an auto
        // pick that resolved its model from the listing first — never
        // silently dropped.
        "groq" => Some(SourceContract {
            seed: GROQ_SEED,
            endpoint: EndpointRule::PlanBaseOrDefault(GROQ_BASE_URL),
            catalog: CatalogRule::Listing,
            credential: CredentialRule::Bearer,
            entries: EntryRule::Groq,
        }),
        // `huggingface` (HZN-008 class A): the configured-or-recorded
        // `router.huggingface.co/v1` base, the recorded T1 static
        // bundled rows as the offer floor with the key-gated `/models`
        // listing as their non-authoritative supplement, the ids riding
        // verbatim — the recorded `provider/model` routing suffix
        // included — and the recorded fine-grained model-request token:
        // its `hf_…` grammar is the account/org billing form, so
        // material of another class denies before any wire leg and the
        // billing mode is never inferred (INV-005).
        "huggingface" => Some(SourceContract {
            seed: HUGGINGFACE_SEED,
            endpoint: EndpointRule::PlanBaseOrDefault(HUGGINGFACE_BASE_URL),
            catalog: CatalogRule::Listing,
            credential: CredentialRule::HuggingFace,
            entries: EntryRule::HuggingFace,
        }),
        // `kilo` (HZN-008 class P): the configured-or-recorded
        // `api.kilo.ai/api/gateway` base, the recorded keyless
        // discovery — its `/models` offers merge over the recorded
        // default row as the floor, the header rides only when
        // material resolves, and a keyless or free answer proves no
        // paid entitlement — the recorded custom device/key profile
        // credential, and no invented subscription SKU: an offer the
        // class records no vendored price row for keeps
        // [`ModelPrice::Unknown`].
        "kilo" => Some(SourceContract {
            seed: &[],
            endpoint: EndpointRule::PlanBaseOrDefault(KILO_BASE_URL),
            catalog: CatalogRule::UnauthenticatedListing(KILO_MODELS),
            credential: CredentialRule::Kilo,
            entries: EntryRule::IdsOnly,
        }),
        // `litellm` (HZN-008 class B — the configured-proxy cell): the
        // user-configured proxy base verbatim — the recorded default is
        // `LITELLM_BASE_URL ?? http://localhost:4000/v1`, but our
        // required `endpoint` field means a base must be configured, so
        // the default is never substituted and no localhost catalogue
        // is invented: an empty configured base stays empty — the
        // recorded listing whose discovery is the proxy's own management
        // metadata first ([`LITELLM_METADATA_PATHS`] under one bounded
        // phase budget) with the recorded fall-through to `/models`,
        // no seed (the class records no built-in roster), the recorded
        // open-proxy credential arm (an absent binding rides headerless
        // on every leg, a declared binding that cannot resolve denies
        // typed — never a dummy key), and ids riding the catalogue and
        // the wire verbatim.
        "litellm" => Some(SourceContract {
            seed: &[],
            endpoint: EndpointRule::Verbatim,
            catalog: CatalogRule::Listing,
            credential: CredentialRule::OpenProxy,
            entries: EntryRule::LiteLlm,
        }),
        // `llama.cpp` (HZN-008 class B — the local-endpoint cell): the
        // configured local base verbatim, or the recorded default
        // `http://127.0.0.1:8080` when the required `endpoint` field is
        // empty. The recorded contract names no discovery leg — no
        // `/models` call and no vendored roster — so the catalogue is
        // the recorded fixed list alone, which this class leaves
        // unrecorded: the lookup opens no wire leg and resolves no
        // credential, and the recorded manual model path is the only
        // served route, with no base-URL merging (DEC-008/PROH-009/D7).
        // The recorded auth is optional beside the server-key mode, so
        // the credential arm is the absent-binding form: an unbound
        // declaration rides headerless, a declared binding that cannot
        // resolve denies typed, and a scoped key rides as the bearer.
        "llama.cpp" => Some(SourceContract {
            seed: &[],
            endpoint: EndpointRule::PlanBaseOrDefault(LLAMA_CPP_BASE_URL),
            catalog: CatalogRule::Allowlist(&[]),
            credential: CredentialRule::OpenProxy,
            entries: EntryRule::IdsOnly,
        }),
        // `lm-studio` (HZN-008 class B — the local-endpoint cell): the
        // configured local base verbatim, or the recorded default
        // `http://127.0.0.1:1234/v1` when the required `endpoint` field
        // is empty — its own base, never `llama.cpp`'s `:8080`
        // (EDGE-006). The catalogue is that base's own `/models`
        // listing under ids-only offers, so a listing answer proves no
        // paid access; the recorded loaded-context metadata rides the
        // native `/api/v0/models` probe started beside that listing —
        // an advisory overlay that marks vision and fills the window
        // for ids the listing already offers, never a catalogue a probe
        // can deny or widen (D9) — and no discovery or base-URL merging
        // is built beyond the listing leg (D8: the recorded extra
        // `/v1/responses` path is a different connection class and
        // stays unbuilt). The local class records no account
        // or org predicate — no shared external account exists — so
        // none is asserted. The recorded auth is optional beside the
        // server-key mode, so the credential arm is the absent-binding
        // form: an unbound declaration rides headerless, a declared
        // binding that cannot resolve denies typed, and a scoped key
        // rides as the bearer.
        "lm-studio" => Some(SourceContract {
            seed: &[],
            endpoint: EndpointRule::PlanBaseOrDefault(LM_STUDIO_BASE_URL),
            catalog: CatalogRule::Listing,
            credential: CredentialRule::OpenProxy,
            entries: EntryRule::LmStudio,
        }),
        // `minimax-code` (HZN-008 class P — the plan-key cell): the
        // configured-or-recorded `api.minimax.io/v1` international base,
        // and the recorded contract names no discovery leg — no
        // `/models` call and no vendored roster — so the catalogue is
        // the recorded fixed list alone, which this class leaves
        // unrecorded: the lookup opens no wire leg and resolves no
        // credential, a listing answer never adds an offer, and the
        // manual model path is the only served route. The recorded
        // subscription key is a plan-scoped `api_key` (DEC-010), never
        // `ConnKind::Subscription`, and the international plan vs PAYG
        // split stays a billing fact of the enrolled key — the plain
        // bearer arm carries no grammar, so the recovery ladder's PAYG
        // mention is never implemented as a substitute (DEC-007).
        "minimax-code" => Some(SourceContract {
            seed: &[],
            endpoint: EndpointRule::PlanBaseOrDefault(MINIMAX_CODE_INTL_BASE_URL),
            catalog: CatalogRule::Allowlist(&[]),
            credential: CredentialRule::Bearer,
            entries: EntryRule::IdsOnly,
        }),
        // `minimax-code-cn` (HZN-008 class P — the CN plan-key cell):
        // the configured-or-recorded `api.minimaxi.com/v1` CN base —
        // never the international sibling's `api.minimax.io` host and
        // never the `minimax.cn` Anthropic URL, a recorded divergence
        // that stays a divergence (EDGE-007/DEC-007) — and the recorded
        // contract names no discovery leg — no `/models` call and no
        // vendored roster — so the catalogue is the recorded fixed
        // list alone, which this class leaves unrecorded: the lookup
        // opens no wire leg and resolves no credential, a listing
        // answer never adds an offer, and the manual model path is the
        // only served route. The recorded subscription key is a
        // plan-scoped `api_key` (DEC-010), never
        // `ConnKind::Subscription`, and the CN plan's fixed window vs
        // the international plan's rolling window stays a billing fact
        // of the enrolled key — the plain bearer arm carries no
        // grammar, so no window or host is ever substituted.
        "minimax-code-cn" => Some(SourceContract {
            seed: &[],
            endpoint: EndpointRule::PlanBaseOrDefault(MINIMAX_CODE_CN_BASE_URL),
            catalog: CatalogRule::Allowlist(&[]),
            credential: CredentialRule::Bearer,
            entries: EntryRule::IdsOnly,
        }),
        // `mistral` (HZN-008 class B — the env/credential-chain cell,
        // DEC-006): the configured-or-recorded `api.mistral.ai/v1`
        // base, and the recorded `requireApiKey` `/models` listing is
        // the whole catalogue — built-in ids are discovered there, and
        // no vendored roster exists (D4), so an empty or failed answer
        // has no floor to fall back to and keeps the leg's typed
        // denial. The recorded env class resolves at the scoped
        // `SecretRef` seam the same way `groq`'s does — the plain
        // bearer arm carries the stored material, an
        // `env:`/`file:`/plaintext ref is refused at ingress, and the
        // traversal itself stays credential-substrate debt (D4). The
        // recorded parameter-naming notes (`random_seed`,
        // `prediction`, `prompt_cache_key`, `safe_prompt`,
        // `prompt_mode`) are contract notes, not adapter fields — no
        // leg builds or asserts them. Authorization and payment
        // failures surface as the typed transport denial.
        "mistral" => Some(SourceContract {
            seed: &[],
            endpoint: EndpointRule::PlanBaseOrDefault(MISTRAL_BASE_URL),
            catalog: CatalogRule::Listing,
            credential: CredentialRule::Bearer,
            entries: EntryRule::IdsOnly,
        }),
        // `moonshot` (HZN-008 class B — the api-key cell, DEC-025 row
        // `Rivect/key → configured MOONSHOT base, default
        // api.moonshot.ai/v1`): the configured-or-recorded base
        // redirects discovery and streaming alike, and the recorded
        // `requireApiKey` `/models` listing is the whole catalogue —
        // ids ride verbatim, no vendored roster or price surface is
        // carried (D4/D6), so an empty or failed answer has no floor
        // to fall back to. The plain bearer arm carries the stored
        // material — the recorded `KIMI_API_KEY` fallback key name
        // proves neither region nor payment, and a configured `region`
        // denies as always. The recorded K3 effort ladder is a
        // distinct predicate from the K2.x `thinking` surface the
        // adapter never constructs: `low`/`high` ride
        // `reasoning_effort` verbatim, an out-of-ladder pin denies
        // typed, and the recorded `max` has no carrier — no `max`
        // request is ever constructed (DEC-014).
        "moonshot" => Some(SourceContract {
            seed: &[],
            endpoint: EndpointRule::PlanBaseOrDefault(MOONSHOT_BASE_URL),
            catalog: CatalogRule::Listing,
            credential: CredentialRule::Bearer,
            entries: EntryRule::Moonshot,
        }),
        // `nanogpt` (HZN-008 class B — the api-key cell, DEC-025 row
        // `Rivect/key → nano-gpt.com/api/v1`): the configured-or-recorded
        // base redirects discovery and streaming alike, and the recorded
        // api-key class gates the `/models` listing on resolved material
        // — the conditional `fetchDynamicModels` spread exists only when
        // the key does, so a keyless lookup opens no wire leg and denies
        // typed. The listing is the whole catalogue: no vendored roster
        // or price/routing carrier exists (D6), so an empty or failed
        // answer has no floor to fall back to, and the recorded
        // `:thinking` aliases collapse into the single base offer under
        // the recorded chat-id filter. The plain bearer arm carries the
        // stored material — the recorded subscription base is a separate
        // configured payment class, never a hidden fallback path this
        // arm constructs (DEC-010).
        "nanogpt" => Some(SourceContract {
            seed: &[],
            endpoint: EndpointRule::PlanBaseOrDefault(NANOGPT_BASE_URL),
            catalog: CatalogRule::Listing,
            credential: CredentialRule::Bearer,
            entries: EntryRule::NanoGpt,
        }),
        // `novita` (HZN-008 class B — the api-key cell, DEC-025 row
        // `Rivect/key → api.novita.ai/openai/v1`): the
        // configured-or-recorded base redirects discovery and
        // streaming alike, and the recorded descriptor's
        // `catalogDiscovery.allowUnauthenticated` — no
        // `requireApiKey` — makes `/models` a keyless discovery: an
        // absent scope rides the anonymous listing with no
        // `Authorization` header, while the same absent scope denies
        // a send `CredentialAbsent`. The listing is authoritative
        // (`dynamicModelsAuthoritative`): no vendored roster or price
        // row exists (D6), so an empty or failed answer has no floor
        // to fall back to, and every entry must pass the recorded
        // conjunction (active status, non-test id, `chat/completions`
        // endpoint, positive `max_output_tokens`) before it offers.
        // The plain bearer arm carries the stored material — the
        // recorded login validates against inference, never payment
        // administration, and no billing or price fact is borrowed
        // from another id.
        "novita" => Some(SourceContract {
            seed: &[],
            endpoint: EndpointRule::PlanBaseOrDefault(NOVITA_BASE_URL),
            catalog: CatalogRule::UnauthenticatedListing(&[]),
            credential: CredentialRule::Bearer,
            entries: EntryRule::Novita,
        }),
        // `nvidia` (HZN-008 class B — the api-key cell): the
        // configured-or-recorded base redirects discovery and
        // streaming alike, and the recorded
        // `createSimpleOpenAICompletionsOptions` discovery is the
        // plain keyed `/models` listing — no `filterModel` and no
        // vendored floor, so every listed id is an offer and a
        // `vendor/model` namespace rides the catalogue and the wire
        // verbatim, while an empty or failed answer has no floor to
        // fall back to. The plain bearer arm carries the stored
        // material. The recorded login's validation is optional
        // (`optional=#true`): this adapter constructs no login probe,
        // so a `401`/`403` from a validation/model request is the
        // typed hard denial, while any other non-success proves
        // neither access nor denial — never a success or an
        // entitlement claim.
        "nvidia" => Some(SourceContract {
            seed: &[],
            endpoint: EndpointRule::PlanBaseOrDefault(NVIDIA_BASE_URL),
            catalog: CatalogRule::Listing,
            credential: CredentialRule::Bearer,
            entries: EntryRule::IdsOnly,
        }),
        // `qianfan` (HZN-008 class B — the api-key cell): the
        // configured-or-recorded `https://qianfan.baidubce.com/v2` base
        // redirects discovery and streaming alike, and the recorded
        // api-key class gates the `/models` listing on resolved material
        // — a keyless lookup opens no wire leg and denies typed. The
        // listing is the whole catalogue: `data[]` rows carry the id
        // plus `context_length` and `max_completion_tokens` when
        // present (DEC-020), and the class records no vendored roster or
        // seed, so an empty or failed answer has no floor to fall back
        // to. The recorded `deepseek-v3.2` default is a catalogue hint,
        // never a seeded offer and never a ranking — the auto pick stays
        // the adapter's uniform sorted-first listed id (DEC-014/D11).
        // The plain bearer arm carries the stored material, and a
        // configured `region` denies: the contract names none.
        "qianfan" => Some(SourceContract {
            seed: &[],
            endpoint: EndpointRule::PlanBaseOrDefault(QIANFAN_BASE_URL),
            catalog: CatalogRule::Listing,
            credential: CredentialRule::Bearer,
            entries: EntryRule::GenericMetadata,
        }),
        // `qwen-portal` (HZN-008 class B — the api-key cell): the
        // configured-or-recorded `https://portal.qwen.ai/v1` base
        // redirects discovery and streaming alike, and the recorded
        // api-key class gates the `/models` listing on resolved material
        // — a keyless lookup opens no wire leg and denies typed. The
        // listing is the whole catalogue: `data[]` rows carry the id
        // plus `context_length` and `max_completion_tokens` when
        // present (DEC-020), and the class records no vendored roster or
        // seed, so an empty or failed answer has no floor to fall back
        // to. The recorded `coder-model` default is a catalogue hint,
        // never a seeded offer and never a ranking — the auto pick stays
        // the adapter's uniform sorted-first listed id (DEC-014/D11).
        // The plain bearer arm carries the pasted key; the recorded
        // Qwen OAuth free-tier lifecycle (refresh, quota, revocation)
        // is a bounded residual (D6/DEC-002), never constructed here,
        // and a configured `region` denies: the contract names none.
        "qwen-portal" => Some(SourceContract {
            seed: &[],
            endpoint: EndpointRule::PlanBaseOrDefault(QWEN_PORTAL_BASE_URL),
            catalog: CatalogRule::Listing,
            credential: CredentialRule::Bearer,
            entries: EntryRule::GenericMetadata,
        }),
        // `siliconflow` (HZN-008 class B — the api-key cell): the
        // configured-or-recorded `https://api.siliconflow.com/v1` base
        // redirects discovery and streaming alike, and the recorded
        // api-key class gates the `/models` listing on resolved material
        // — a keyless lookup opens no wire leg and denies typed. The
        // listing is authoritative (`dynamicModelsAuthoritative`): the
        // recorded exclusion list drops embeddings, rerankers and
        // image/audio/video generators, and an admitted `data[]` row
        // maps the id plus `context_length` and `max_completion_tokens`
        // when present under the recorded `min(maxTokens, context)`
        // clamp (DEC-020). The class records no vendored roster, seed or
        // price row (D2), so an empty or failed answer has no floor to
        // fall back to. The recorded `zai-org/GLM-5.1` default is a
        // catalogue hint, never a seeded offer and never a ranking — the
        // auto pick stays the sorted-first listed id (DEC-014/D11) — and
        // a configured `region` denies: the contract names none.
        "siliconflow" => Some(SourceContract {
            seed: &[],
            endpoint: EndpointRule::PlanBaseOrDefault(SILICONFLOW_BASE_URL),
            catalog: CatalogRule::Listing,
            credential: CredentialRule::Bearer,
            entries: EntryRule::SiliconFlow,
        }),
        // `siliconflow-cn` (HZN-008 class B — the api-key cell): the
        // configured-or-recorded `https://api.siliconflow.cn/v1` CN host
        // redirects discovery and streaming alike. The split from
        // `siliconflow` is id-keyed (EDGE-007): distinct host, distinct
        // recorded `SILICONFLOW_CN_API_KEY` env name behind the same
        // scoped seam, and never a substitution of either host or
        // credential for the other. The recorded api-key class gates the
        // authoritative `/models` listing on resolved material — a
        // keyless lookup opens no wire leg and denies typed — and the
        // shared exclusion transform ([`EntryRule::SiliconFlow`]) drops
        // the recorded non-chat families and maps the stated limits
        // under the recorded clamp. The class records no vendored
        // roster, seed or price row (D2), so an empty or failed answer
        // has no floor to fall back to. A configured `region` denies:
        // the contract names none.
        "siliconflow-cn" => Some(SourceContract {
            seed: &[],
            endpoint: EndpointRule::PlanBaseOrDefault(SILICONFLOW_CN_BASE_URL),
            catalog: CatalogRule::Listing,
            credential: CredentialRule::Bearer,
            entries: EntryRule::SiliconFlow,
        }),
        // `synthetic` (HZN-008 class B — the api-key cell): the
        // configured-or-recorded `https://api.synthetic.new/openai/v1`
        // base — the pinned code's `openai/v1` root, never the docs'
        // bare `/v1` — redirects discovery and streaming alike, and
        // the recorded api-key class gates the authoritative `/models`
        // listing on resolved material: a keyless lookup opens no wire
        // leg and denies typed. The class's nonstandard entry surface
        // ([`EntryRule::Synthetic`]) maps capabilities, modalities,
        // the output-cap chain, the representable effort vocabulary
        // and per-token USD prices; an empty or failed answer has no
        // seed or vendored price floor to fall back to. A configured
        // `region` denies: the contract names none, and the recorded
        // Anthropic-format sibling is outside this arm (D7).
        "synthetic" => Some(SourceContract {
            seed: &[],
            endpoint: EndpointRule::PlanBaseOrDefault(SYNTHETIC_BASE_URL),
            catalog: CatalogRule::Listing,
            credential: CredentialRule::Bearer,
            entries: EntryRule::Synthetic,
        }),
        // `together` (HZN-008 class B — the api-key cell): the
        // configured-or-recorded `https://api.together.xyz/v1` base —
        // the pinned `.xyz` host, never the documentation's `.ai`
        // alias or the US endpoint alias (DEC-005) — redirects
        // discovery and streaming alike, and the recorded api-key
        // class gates the `/models` listing on resolved material: a
        // keyless lookup opens no wire leg and denies typed. The
        // listing is the whole catalogue under no entry filter — every
        // parseable `data[]` id is an offer, each row mapping the id
        // plus `context_length` and `max_completion_tokens` when
        // present (DEC-020) — and the class records no vendored
        // roster or seed, so an empty or failed answer has no floor to
        // fall back to. The plain bearer arm carries the stored
        // material, and a configured `region` denies: the contract
        // names none. The recorded models-endpoint validation stays
        // the live probe; this adapter constructs no chat probe.
        "together" => Some(SourceContract {
            seed: &[],
            endpoint: EndpointRule::PlanBaseOrDefault(TOGETHER_BASE_URL),
            catalog: CatalogRule::Listing,
            credential: CredentialRule::Bearer,
            entries: EntryRule::GenericMetadata,
        }),
        // `venice` (HZN-008 class B — the public-catalogue cell): the
        // configured-or-recorded `https://api.venice.ai/api/v1` base,
        // the host's public `/models` listing under the recorded
        // generic entry transform — `context_length` and
        // `max_completion_tokens` mapped when stated — and the plain
        // bearer model-request key. The listing rides keyless when the
        // store resolves no material, and that tolerance is the
        // catalogue's alone: the same absent material denies a send
        // `CredentialAbsent`, since a public catalogue is not
        // authentication and a listing answer confers no entitlement.
        // The class records neither a seed nor a vendored price row, so
        // an empty or failed answer has no floor to fall back to. The
        // model-request key is a class distinct from the administrative
        // key, but `SecretRef` material states no class — that
        // discrimination is a residual. A configured `region` denies:
        // the contract names none.
        "venice" => Some(SourceContract {
            seed: &[],
            endpoint: EndpointRule::PlanBaseOrDefault(VENICE_BASE_URL),
            catalog: CatalogRule::UnauthenticatedListing(&[]),
            credential: CredentialRule::Bearer,
            entries: EntryRule::GenericMetadata,
        }),
        // `vllm` (HZN-008 class B — the local-server cell): the
        // configured local base verbatim, or the recorded default
        // `http://127.0.0.1:8000/v1` when the required `endpoint` field
        // is empty — its own host, never `llama.cpp`'s `:8080` or
        // `lm-studio`'s `:1234` (EDGE-006). The configured base's own
        // `/models` listing is the catalogue, each row mapping vLLM's
        // `max_model_len` as the context window and carrying the
        // display-only Qwen reasoning mark; the recorded auth is
        // optional beside the server-key mode, so the credential arm is
        // the absent-binding form: an unbound declaration rides
        // headerless, a declared binding that cannot resolve denies
        // typed, and a scoped key rides as the bearer. The listing
        // states no effort ladder, so a pinned effort denies at the
        // send seam rather than being dropped.
        "vllm" => Some(SourceContract {
            seed: &[],
            endpoint: EndpointRule::PlanBaseOrDefault(VLLM_BASE_URL),
            catalog: CatalogRule::Listing,
            credential: CredentialRule::OpenProxy,
            entries: EntryRule::Vllm,
        }),
        _ => None,
    }
}

impl SourceContract {
    /// Whether the recorded credential arm admits a declaration that
    /// binds no credential at all — the absent-binding form shared by
    /// the open proxy and the local-endpoint class. An exhaustive
    /// decision over the credential rule, so a further arm must state
    /// its admission here rather than inheriting the required-binding
    /// path by default.
    fn binds_optional_credential(&self) -> bool {
        match self.credential {
            CredentialRule::OpenProxy => true,
            CredentialRule::Bearer
            | CredentialRule::AlibabaPlan
            | CredentialRule::AlibabaTokenPlan
            | CredentialRule::Firepass
            | CredentialRule::CoreWeave
            | CredentialRule::HuggingFace
            | CredentialRule::Kilo => false,
        }
    }

    /// Whether the recorded catalogue tolerates an absent scope on the
    /// classification leg — the keyless discovery form. An exhaustive
    /// decision over the catalogue rule; this is the discovery fact
    /// alone, separate from [`Self::binds_optional_credential`], so
    /// neither policy is inferred from the other.
    fn keyless_discovery(&self) -> bool {
        match self.catalog {
            CatalogRule::Listing | CatalogRule::Allowlist(_) => false,
            CatalogRule::UnauthenticatedListing(_) => true,
        }
    }

    /// The connection's API root under the recorded endpoint rule:
    /// egress stays bound to the configured endpoint — the `aiand`
    /// normalization only supplies the `/v1` tail a configured base
    /// lacks, and each recorded default host covers an empty one.
    fn endpoint(&self, configured: &str) -> String {
        match self.endpoint {
            EndpointRule::Verbatim => configured.trim_end_matches('/').to_string(),
            EndpointRule::NormalizedV1Root => {
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
            EndpointRule::ConfiguredElseDefault => {
                // `normalizeBaseUrl`: the configured base trimmed, one
                // trailing slash stripped — never a `/v1` append; the
                // empty string is the upstream absent-override case
                // the recorded `?? defaultBaseUrl` covers.
                let trimmed = configured.trim();
                if trimmed.is_empty() {
                    return AIMLAPI_DEFAULT_BASE_URL.to_string();
                }
                trimmed.strip_suffix('/').unwrap_or(trimmed).to_string()
            }
            EndpointRule::PlanBaseOrDefault(default) => {
                // The login hook's custom-origin ingress normalization
                // — trim, all trailing slashes stripped — applied to
                // whichever base the connection configures; the empty
                // string is the absent-override case the recorded
                // `… ?? defaultBaseUrl` covers with the class's
                // recorded endpoint.
                let trimmed = configured.trim();
                if trimmed.is_empty() {
                    return default.to_string();
                }
                trimmed.trim_end_matches('/').to_string()
            }
        }
    }
}

/// The wire leg that reads the credential — the one seam both legs share.
/// A send (and its auto-pick catalogue leg) requires the material a bound
/// scope names, while a standalone catalogue read is the recorded keyless
/// discovery's leg, which admits an absent scope as the headerless form.
#[derive(Clone, Copy)]
enum CredentialLeg {
    Send,
    Discovery,
}

/// The recorded `litellm` management-metadata phase's outcome
/// (`fetchLiteLLMRichModels`): either the proxy served its metadata, or
/// the class takes the recorded fall-through to `/models`. Every cause
/// of the fall-through is recorded as non-terminal — an absent form
/// (404 from a proxy that does not expose it), a refused or failed
/// status, an unreadable or empty body, a transport failure, or a spent
/// phase budget — because `/models` is the class's remaining recorded
/// source, never a failure the catalogue may surface.
enum MetadataPhase {
    /// The proxy served management metadata for at least one model.
    Served(Vec<CatalogModel>),
    /// The recorded fall-through to the `/models` listing.
    FallThrough,
}

/// One `lm-studio` native row's loaded-context surface: whether the
/// row is image-capable — a `vlm` type or a `vision`/`image`
/// capability — and the positive context window the runtime reports
/// for the id.
struct LmStudioNativeModel {
    vision: bool,
    context_window: Option<u64>,
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
    /// The maximum output tokens this adapter carries from the
    /// listing — populated only by a per-id adapter that maps it.
    /// `None` means this adapter does not carry the listing's value,
    /// which may include a source field the recorded class does not
    /// map.
    pub max_output_tokens: Option<u64>,
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

/// The recorded allowlist as catalogue entries — deterministic sorted
/// order, each id carrying its bundled-descriptor vision mark and
/// nothing else.
fn allowlist_models(list: &[(&str, bool)]) -> Vec<CatalogModel> {
    let mut models: Vec<CatalogModel> = list
        .iter()
        .map(|(id, vision)| CatalogModel {
            id: (*id).to_string(),
            vision: *vision,
            ..CatalogModel::default()
        })
        .collect();
    models.sort_by(|a, b| a.id.cmp(&b.id));
    models
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

/// The wire material one resolved credential carries — the bearer
/// token, plus the `OpenAI-Project` scope a scoped `coreweave`
/// credential names. Never rendered: both members are secret-store
/// material.
struct WireSecret {
    /// The `Authorization: Bearer` token.
    bearer: String,
    /// The `OpenAI-Project` header value — `Some` only for the
    /// `coreweave` scoped store material, whose `<team>/<project>` is
    /// the recorded login's env-resolved hook materialized in the
    /// store; every leg of that class carries it.
    project: Option<String>,
}

impl WireSecret {
    /// A bare-bearer credential — every arm without a scope member.
    fn bearer(token: String) -> Self {
        Self {
            bearer: token,
            project: None,
        }
    }

    /// The material's headers on one leg: `Authorization` first, the
    /// `OpenAI-Project` scope next when the arm carries one — and no
    /// header at all when the declaration binds nothing.
    fn attach(
        request: reqwest::blocking::RequestBuilder,
        secret: Option<&WireSecret>,
    ) -> reqwest::blocking::RequestBuilder {
        let Some(secret) = secret else {
            return request;
        };
        let request = request.bearer_auth(&secret.bearer);
        if let Some(project) = &secret.project {
            request.header(OPENAI_PROJECT_HEADER, project)
        } else {
            request
        }
    }
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
    /// rotation is honoured without rebuilding the adapter — or `None`
    /// on a recorded credential-optional class whose declaration binds
    /// nothing: the recorded absent-binding form sends no
    /// `Authorization` header and never a dummy key.
    credential: Option<SecretRef>,
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
    /// declared, carry no configured region — no recorded class
    /// has one — and resolve a scoped credential under DEC-013
    /// precedence, except on the recorded credential-optional classes
    /// whose declaration binds none: that is the absent-binding form,
    /// and the adapter then bears no material at all.
    ///
    /// # Errors
    /// [`ProviderError::DialectMismatch`] for a connection id without
    /// the Chat Completions source class or its own contract arm;
    /// [`ProviderError::UnknownConnection`] for an undeclared id;
    /// [`ProviderError::RegionMismatch`] for a configured region;
    /// [`ProviderError::LocalProfileDeclared`] for a `local`
    /// declaration that binds a `profile` on such a contract;
    /// [`ProviderError::CredentialUnresolved`] for a `local`
    /// declaration on a contract that requires its binding — denied by
    /// declaration kind before any credential resolves —
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
        // A `local` declaration names a locally served endpoint that
        // binds no credential; a contract that requires its binding
        // cannot honour that kind, and a `profile` member is the
        // contradictory half that must not turn the row into a
        // credentialled sender (DEC-009/DEC-010, DEC-023). The profile
        // half is named first so the operator fixes the right member;
        // the kind itself is denied before any credential resolution,
        // and an optional-binding contract keeps its profile form.
        if conn.kind == ConnKind::Local
            && !contract.binds_optional_credential()
            && conn.profile.is_some()
        {
            return Err(ProviderError::LocalProfileDeclared {
                connection: connection.to_string(),
            });
        }
        if conn.kind == ConnKind::Local && !contract.binds_optional_credential() {
            return Err(ProviderError::CredentialUnresolved {
                connection: connection.to_string(),
                scope: format!("connections.{connection}.kind"),
                cause: None,
            });
        }
        let credential = if contract.binds_optional_credential() {
            resolve_optional_credential_in(&config.connections, &config.profiles, connection)?
        } else {
            Some(resolve_credential(config, connection)?)
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
    /// id's recorded contract — every `data[]` id with a non-whitespace
    /// body is an offered model under its per-entry transform, the
    /// recorded
    /// static seed merges on top as the offer floor, and the union
    /// returns in deterministic sorted order. A class whose recorded
    /// catalogue is a fixed allowlist answers it alone: no listing
    /// leg exists, so no credential is resolved and no byte crosses
    /// wire. A class whose recorded discovery allows an
    /// unauthenticated catalogue sends no `Authorization` header when
    /// no credential resolves, and still merges its recorded rows as
    /// the offer floor; a class whose credential arm admits an
    /// undeclared binding — the absent-binding form — sends the same
    /// headerless lookup over its configured base alone. A class whose
    /// recorded discovery is its proxy's management metadata
    /// (`litellm`) probes that metadata first and takes the recorded
    /// `/models` fall-through only when the metadata yields nothing.
    /// The generic class
    /// admits the listing verbatim: gateway-style ids carry path
    /// characters legitimately, since a model id is never URL
    /// material in this dialect — it rides the request body.
    ///
    /// # Errors
    /// The credential seam's typed denials, [`ProviderError::Transport`]
    /// on a failed call or non-success status or an expired whole-call
    /// budget, and [`ProviderError::StreamViolation`] when the payload
    /// does not carry the `data` array the contract requires. A
    /// *seeded* class answers its recorded seed floor instead of denying
    /// on a failed or unparseable listing — that seed is the offer floor
    /// the listing only supplements, and a keyless class's recorded
    /// discovery rows are that floor too — while a seedless class has no
    /// floor and keeps the typed denial. A spent whole-call budget is
    /// never a failed answer: its deadline denial stands.
    pub fn catalog(&self) -> Result<Vec<CatalogModel>, ProviderError> {
        // The recorded allowlist is the whole catalogue — no wire
        // leg, no credential resolution.
        if let CatalogRule::Allowlist(list) = self.contract.catalog {
            return Ok(allowlist_models(list));
        }
        // A standalone lookup opens its own whole-call budget — the
        // credential resolution and the wire leg share it, the same
        // bound a send's catalogue leg rides.
        let started = Instant::now();
        // The store call itself cannot be interrupted once running —
        // the check before it is the only point an expired budget
        // still denies the resolve without touching the seam.
        check_deadline(&self.connection, self.deadline, started)?;
        // The discovery leg answers the material this class bears:
        // `None` when the declaration binds none (the absent-binding
        // form) or the recorded keyless discovery tolerates an empty
        // store, so the leg rides without the header instead of failing.
        let secret = self.leg_secret(CredentialLeg::Discovery)?;
        self.catalog_within(secret.as_ref(), started)
    }

    /// The catalogue leg under the caller's clock and resolved
    /// credential — a send passes its own `started` so the lookup
    /// spends the same whole-request budget instead of opening a
    /// second, unaccounted one, and the recorded keyless discovery
    /// passes `None` when no material resolves. `lm-studio`'s leg also
    /// runs the class's native loaded-context probe beside the listing
    /// ([`Self::lm_studio_catalog`]); every other class answers the
    /// listing alone.
    fn catalog_within(
        &self,
        secret: Option<&WireSecret>,
        started: Instant,
    ) -> Result<Vec<CatalogModel>, ProviderError> {
        check_deadline(&self.connection, self.deadline, started)?;
        // The recorded allowlist answers in place — a send's
        // auto-pick never opens a `/models` leg.
        if let CatalogRule::Allowlist(list) = self.contract.catalog {
            return Ok(allowlist_models(list));
        }
        // The recorded metadata-first discovery answers alone when the
        // proxy serves it; otherwise the listing below is the class's
        // remaining recorded source.
        if matches!(self.contract.entries, EntryRule::LiteLlm)
            && let MetadataPhase::Served(models) = self.litellm_metadata(secret, started)?
        {
            return Ok(models);
        }
        // The fall-through leg is a request too: a budget the metadata
        // phase spent is the typed deadline, never a post on an expired
        // clock.
        check_deadline(&self.connection, self.deadline, started)?;
        // `lm-studio` records one extra catalogue source beside the
        // listing — its native loaded-context probe — so its leg runs
        // on the class's own path; every other class answers the
        // listing alone.
        if matches!(self.contract.entries, EntryRule::LmStudio) {
            return self.lm_studio_catalog(secret, started);
        }
        self.listing_catalog(secret, started)
    }

    /// The `lm-studio` catalogue leg: the configured base's `/models`
    /// listing with the class's native loaded-context probe
    /// (`GET {native base}/api/v0/models`, the configured base without
    /// its `/v1` segment) started in parallel, and the probe's
    /// marks overlaid on the ids the listing already offers. The probe
    /// spends at most [`LM_STUDIO_NATIVE_METADATA_BUDGET`], clipped to
    /// the whole call's remainder, and it is advisory: a refused,
    /// unreadable, failed or timed-out answer leaves the listing's
    /// offers untouched, so it never denies a listing it could not read
    /// and never invents an offer. The listing stays authoritative — an
    /// id only the probe names gets nothing.
    fn lm_studio_catalog(
        &self,
        secret: Option<&WireSecret>,
        started: Instant,
    ) -> Result<Vec<CatalogModel>, ProviderError> {
        let budget = self
            .deadline
            .checked_sub(started.elapsed())
            .map(|left| left.min(LM_STUDIO_NATIVE_METADATA_BUDGET))
            .filter(|left| !left.is_zero());
        let (listed, native) = std::thread::scope(|scope| {
            // The probe overlaps the listing instead of serializing
            // behind it, so the class pays one round trip, not two.
            let probe = budget
                .map(|budget| scope.spawn(move || self.lm_studio_native_metadata(secret, budget)));
            let listed = self.listing_catalog(secret, started);
            // A probe thread that panicked is the same advisory miss as
            // a failed answer — never a catalogue failure.
            let native = probe.and_then(|handle| handle.join().unwrap_or_default());
            (listed, native)
        });
        let mut models = listed?;
        if let Some(native) = native {
            for model in &mut models {
                let Some(metadata) = native.get(&model.id) else {
                    continue;
                };
                model.vision |= metadata.vision;
                if let Some(window) = metadata.context_window {
                    model.context_window = Some(window);
                }
            }
        }
        // The probe runs inside the same clock as every other leg: an
        // answer that completes past the whole-call budget is the typed
        // deadline, never a late catalogue.
        check_deadline(&self.connection, self.deadline, started)?;
        Ok(models)
    }

    /// The class's recorded native loaded-context probe
    /// (`fetchLmStudioNativeModelMetadata`): `GET {native
    /// base}/api/v0/models` — the configured base trimmed of its `/v1`
    /// segment — under [`LM_STUDIO_NATIVE_METADATA_BUDGET`], keyed by
    /// the model id it names. Every miss answers `None` — this is the
    /// declared advisory fallback over the listing, so a non-2xx
    /// status, a transport failure, a spent bound or a payload outside
    /// the recorded shape contributes no mark and never a catalogue
    /// denial. The bearer rides only when the connection resolved
    /// material; the keyless local mode probes headerless.
    fn lm_studio_native_metadata(
        &self,
        secret: Option<&WireSecret>,
        budget: Duration,
    ) -> Option<HashMap<String, LmStudioNativeModel>> {
        let started = Instant::now();
        let mut request = self
            .client
            .get(format!(
                "{}/api/v0/models",
                lm_studio_native_base(&self.endpoint)
            ))
            .timeout(budget)
            .header(reqwest::header::ACCEPT, "application/json");
        if let Some(secret) = secret {
            request = request.bearer_auth(&secret.bearer);
        }
        let Ok(mut response) = request.send() else {
            return None;
        };
        if !response.status().is_success() {
            return None;
        }
        let Ok(body) = read_catalog_body(&self.connection, budget, &mut response, started) else {
            return None;
        };
        let Ok(payload) = serde_json::from_slice::<Value>(&body) else {
            return None;
        };
        lm_studio_native_models(&payload)
    }

    /// The `/models` listing leg under the literal id's recorded
    /// contract: every `data[]` id with a non-whitespace body under its
    /// per-entry transform, the recorded floor unioned on top as the
    /// offer floor, and the union in deterministic sorted order. As in
    /// [`Self::catalog_within`], a seeded or keyless-floor class answers
    /// its floor instead of denying on a failed or unparseable listing,
    /// a seedless class keeps the typed denial, and a spent whole-call
    /// budget is never converted into the floor ([`Self::floor_or`]).
    fn listing_catalog(
        &self,
        secret: Option<&WireSecret>,
        started: Instant,
    ) -> Result<Vec<CatalogModel>, ProviderError> {
        let request =
            WireSecret::attach(self.client.get(format!("{}/models", self.endpoint)), secret);
        let mut response = match request.send() {
            Ok(response) => response,
            Err(err) => return self.floor_or(transport(&self.connection, err)),
        };
        // The wait spent the budget: a status that lands after it is no
        // answer at all, so the deadline denial stands before the status
        // branch — a status inside the budget keeps its recorded floor
        // handling below.
        check_deadline(&self.connection, self.deadline, started)?;
        if !response.status().is_success() {
            return self.floor_or(transport_status(&self.connection, response.status()));
        }
        let body = match read_catalog_body(&self.connection, self.deadline, &mut response, started)
        {
            Ok(body) => body,
            Err(err) => return self.floor_or(err),
        };
        let body: Value = match serde_json::from_slice(&body) {
            Ok(body) => body,
            Err(_parse) => {
                return self.floor_or(violation(&self.connection, "models payload is not json"));
            }
        };
        let Some(data) = body.get("data").and_then(Value::as_array) else {
            return self.floor_or(violation(
                &self.connection,
                "models payload carries no data array",
            ));
        };
        // Every listed `id` is an offer under the literal id's
        // recorded per-entry transform — an empty, absent or
        // whitespace-only one can never name a model.
        let mut models: Vec<CatalogModel> = data
            .iter()
            .filter_map(|entry| self.catalog_entry(entry))
            .collect();
        // `nanogpt`'s recorded collapse: the alias rows the entry
        // filter dropped mark their base offers reasoning-capable —
        // the record states the mark on the kept model alone, so a
        // base whose alias was filtered gains `reasoning` and a base
        // the listing never carried stays absent.
        if matches!(self.contract.entries, EntryRule::NanoGpt) {
            mark_nanogpt_thinking_bases(data, &mut models);
        }
        // The recorded floor unions on top as the offer floor — a
        // seeded or keyless-floor id the listing omitted still offers,
        // carrying the recorded transform surface the listing arm
        // lands. Listed entries precede the floor, so the stable sort
        // keeps a listing entry's transform over its floor stub on a
        // collision.
        models.extend(self.floor_models());
        models.sort_by(|a, b| a.id.cmp(&b.id));
        models.dedup_by(|a, b| a.id == b.id);
        Ok(models)
    }

    /// The recorded seed ids under the literal id's per-entry
    /// transform — the offer floor a listing only supplements.
    fn seed_models(&self) -> Vec<CatalogModel> {
        self.contract
            .seed
            .iter()
            .filter_map(|id| match self.contract.entries {
                EntryRule::DeepSeek => deepseek_entry(id),
                EntryRule::Fireworks => fireworks_entry(id),
                EntryRule::Groq => Some(groq_entry(id)),
                EntryRule::IdsOnly
                | EntryRule::GenericMetadata
                | EntryRule::Aiand
                | EntryRule::Aimlapi
                | EntryRule::AlibabaTokenPlan
                | EntryRule::Firepass
                | EntryRule::HuggingFace
                | EntryRule::LiteLlm
                | EntryRule::LmStudio
                | EntryRule::Moonshot
                | EntryRule::NanoGpt
                | EntryRule::Novita
                | EntryRule::SiliconFlow
                | EntryRule::Synthetic
                | EntryRule::Vllm => Some(CatalogModel {
                    id: (*id).to_string(),
                    ..CatalogModel::default()
                }),
            })
            .collect()
    }

    /// The recorded offer floor — the seed ids under the literal id's
    /// per-entry transform plus the keyless discovery's recorded rows —
    /// in the union's sorted, deduplicated order. A listing only
    /// supplements it.
    fn floor_models(&self) -> Vec<CatalogModel> {
        let mut models = self.seed_models();
        if let CatalogRule::UnauthenticatedListing(floor) = self.contract.catalog {
            models.extend(allowlist_models(floor));
        }
        models.sort_by(|a, b| a.id.cmp(&b.id));
        models.dedup_by(|a, b| a.id == b.id);
        models
    }

    /// The recorded floor alone as a catalogue answer: the seed and the
    /// keyless discovery's recorded rows in the union's sorted,
    /// deduplicated order, or `None` for a class that records no floor
    /// and so has nothing to fall back to.
    fn seed_floor(&self) -> Option<Vec<CatalogModel>> {
        let models = self.floor_models();
        if models.is_empty() {
            return None;
        }
        Some(models)
    }

    /// A listing leg that answered nothing usable still answers a
    /// seeded class's recorded floor — that seed is the offer floor the
    /// listing only supplements, so a failed or unparseable answer
    /// contributes no offer and takes none away — while a seedless
    /// class keeps the leg's typed denial. A spent whole-call budget is
    /// no answer: its deadline denial is re-raised unchanged, never
    /// converted into the floor.
    fn floor_or(&self, err: ProviderError) -> Result<Vec<CatalogModel>, ProviderError> {
        if matches!(
            &err,
            ProviderError::Transport {
                cause: TransportCause::Deadline { .. },
                ..
            }
        ) {
            return Err(err);
        }
        match self.seed_floor() {
            Some(floor) => Ok(floor),
            None => Err(err),
        }
    }

    /// The recorded `litellm` management-metadata phase
    /// (`fetchLiteLLMRichModels` at commit
    /// `0133f7ff52d3859944b4fd4ccf3852df7fbf1b54`): the management base
    /// — the configured base minus a trailing `/v1` — probed in
    /// [`LITELLM_METADATA_PATHS`] order, every probe carrying
    /// `Accept: application/json` and the resolved material when there
    /// is any. Each probe is bounded by [`litellm_probe_budget`] — the
    /// recorded phase bound's remainder against the whole call's — so no
    /// request starts, and no read runs, after either budget is spent.
    /// The first answering endpoint owns the offered id set; later
    /// endpoints only enrich those ids, and a set whose window and price
    /// are both stated ends the phase early. Each entry maps through the
    /// rich transform ([`litellm_metadata_model`]).
    ///
    /// A later form's failure ends the walk with the set already served:
    /// offers are never discarded for a form the phase had outgrown, and
    /// only a walk that offered nothing is
    /// [`MetadataPhase::FallThrough`]. An absent form (404) is skipped
    /// in order; a refused or failed status, an unreadable body, a
    /// transport failure and a spent phase bound all end the walk, and
    /// the record's next source for an empty walk is `/models`, so none
    /// of them is a catalogue error.
    ///
    /// # Errors
    /// [`ProviderError::Transport`] when the whole-call budget expires —
    /// [`check_deadline`]'s typed denial, re-raised before every probe
    /// so an expired call is never converted into the recorded
    /// fall-through.
    fn litellm_metadata(
        &self,
        secret: Option<&WireSecret>,
        started: Instant,
    ) -> Result<MetadataPhase, ProviderError> {
        let management_base = litellm_management_base(&self.endpoint);
        if management_base.is_empty() {
            return Ok(MetadataPhase::FallThrough);
        }
        let phase_started = Instant::now();
        let mut offered: BTreeMap<String, CatalogModel> = BTreeMap::new();
        for path in LITELLM_METADATA_PATHS {
            check_deadline(&self.connection, self.deadline, started)?;
            let Some(budget) = litellm_probe_budget(phase_started, started, self.deadline) else {
                // The recorded phase bound is spent: the walk ends with
                // whatever it served.
                break;
            };
            let probe_started = Instant::now();
            let mut request = self
                .client
                .get(format!("{management_base}{path}"))
                .timeout(budget)
                .header(reqwest::header::ACCEPT, "application/json");
            if let Some(secret) = secret {
                request = request.bearer_auth(&secret.bearer);
            }
            let mut response = match request.send() {
                Ok(response) => response,
                // A transport failure ends the walk; a served set stays.
                Err(_transport) => break,
            };
            let status = response.status();
            if status == reqwest::StatusCode::NOT_FOUND {
                // The proxy does not expose this metadata form: the
                // recorded walk continues with the next path.
                continue;
            }
            if !status.is_success() {
                // A refused or failed form ends the walk; a served set
                // stays served.
                break;
            }
            let body =
                match read_catalog_body(&self.connection, budget, &mut response, probe_started) {
                    Ok(body) => body,
                    // An unreadable body — the probe's remaining bound
                    // included — ends the walk; a served set stays.
                    Err(_unreadable) => break,
                };
            let Ok(payload) = serde_json::from_slice::<Value>(&body) else {
                // A body outside the recorded shape ends the walk.
                break;
            };
            let Some(entries) =
                litellm_metadata_entries(&payload).filter(|entries| !entries.is_empty())
            else {
                // A body naming no entry list, or a list carrying no
                // object row, serves nothing here: the walk continues
                // with the next path.
                continue;
            };
            if offered.is_empty() {
                for entry in entries {
                    if let Some(model) = litellm_metadata_model(entry) {
                        offered.insert(model.id.clone(), model);
                    }
                }
            } else {
                for entry in entries {
                    if let Some(model) = litellm_metadata_model(entry)
                        && let Some(existing) = offered.get_mut(&model.id)
                    {
                        // A later endpoint only enriches an id the first
                        // answering form owns; it never adds one.
                        litellm_metadata_fill(existing, &model);
                    }
                }
            }
            // A form whose rows were all placeholders served nothing, so
            // it cannot read as complete: the walk keeps going for a form
            // that carries real offers.
            if !offered.is_empty() && !litellm_metadata_incomplete(&offered) {
                break;
            }
        }
        if offered.is_empty() {
            return Ok(MetadataPhase::FallThrough);
        }
        Ok(MetadataPhase::Served(offered.into_values().collect()))
    }

    /// One `data[]` entry under the literal id's recorded transform —
    /// `None` when the entry names no usable id: an empty, absent or
    /// whitespace-only id can never name a model, and an `aimlapi` id
    /// the recorded `exclude-models` roster names is filtered before
    /// offer.
    fn catalog_entry(&self, entry: &Value) -> Option<CatalogModel> {
        let id = entry
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| !id.trim().is_empty())?;
        match self.contract.entries {
            EntryRule::IdsOnly => Some(CatalogModel {
                id: id.to_string(),
                ..CatalogModel::default()
            }),
            EntryRule::GenericMetadata => Some(generic_metadata_entry(id, entry)),
            EntryRule::Aiand => Some(aiand_entry(id, entry)),
            // `filterModel` runs on the mapped model's id — verbatim
            // `entry.id` here, the mapped id `mapWithBundledReference`
            // keeps — so the recorded filter applies to the listed id.
            EntryRule::Aimlapi => is_likely_aimlapi_chat_id(id).then(|| CatalogModel {
                id: id.to_string(),
                ..CatalogModel::default()
            }),
            EntryRule::AlibabaTokenPlan => {
                is_alibaba_token_plan_chat_id(id).then(|| CatalogModel {
                    id: id.to_string(),
                    ..CatalogModel::default()
                })
            }
            EntryRule::DeepSeek => deepseek_entry(id),
            EntryRule::Fireworks => fireworks_entry(id),
            // A listed id is offered under the recorded entry surface:
            // a foreign id carries no recorded price, effort or vision
            // mark, while a recorded id carries its full surface.
            EntryRule::Groq => Some(groq_entry(id)),
            // The recorded routing form — `org/model` and a
            // `:provider` suffix included — rides the listing unchanged.
            EntryRule::HuggingFace => Some(CatalogModel {
                id: id.to_string(),
                ..CatalogModel::default()
            }),
            // This class's rich source is its management metadata; a
            // `/models` row the recorded fall-through yields is the
            // OpenAI-compatible listing form and names its id alone.
            EntryRule::LiteLlm => Some(CatalogModel {
                id: id.to_string(),
                ..CatalogModel::default()
            }),
            // This class's richer source is its native metadata probe,
            // run beside this fall-through listing; a listed id is
            // still offered exactly as served.
            EntryRule::LmStudio => Some(CatalogModel {
                id: id.to_string(),
                ..CatalogModel::default()
            }),
            // The `requireApiKey` listing's rows carry the id alone —
            // the recorded price/roster metadata has no vendored
            // carrier (D6).
            EntryRule::Moonshot => Some(CatalogModel {
                id: id.to_string(),
                ..CatalogModel::default()
            }),
            // The recorded chat-id filter: a `:thinking`-suffixed alias
            // is never an offer — it only marks the base id it aliases,
            // the mark `catalog_within` applies after this pass. The
            // record's `exclude-models` consult carries no vendored
            // roster for this class, so every other non-empty id is
            // offered.
            EntryRule::NanoGpt => is_likely_nanogpt_text_id(id).then(|| CatalogModel {
                id: id.to_string(),
                ..CatalogModel::default()
            }),
            // The recorded authority conjunction
            // (`novitaModelManagerOptions`'s `filterModel`): the
            // listing is authoritative, so an entry failing any clause
            // never reaches the offer set, and an admitted id keeps no
            // surface the class records no vendored row for (D6).
            EntryRule::Novita => is_likely_novita_chat_entry(id, entry).then(|| CatalogModel {
                id: id.to_string(),
                ..CatalogModel::default()
            }),
            // The recorded SiliconFlow filter and mapping: the
            // authoritative listing drops the non-chat families, and
            // an admitted row carries its stated limits under the
            // recorded clamp.
            EntryRule::SiliconFlow => siliconflow_entry(id, entry),
            // The recorded Synthetic transform: the class's nonstandard
            // capability, modality, output-cap, effort and per-token
            // pricing fields, with invalid or partial prices staying
            // unknown.
            EntryRule::Synthetic => Some(synthetic_entry(id, entry)),
            // The recorded vLLM listing surface: `max_model_len` is the
            // window carrier and a Qwen ≥3.8 id carries the
            // display-only reasoning mark.
            EntryRule::Vllm => Some(vllm_entry(id, entry)),
            // Unreached: this class binds the static allowlist, so no
            // listing leg runs. A listed id would prove no access the
            // class records, so the transform admits nothing.
            EntryRule::Firepass => None,
        }
    }

    /// Reads the credential material behind the wire leg `leg` names —
    /// the one store read this adapter performs — and answers the wire
    /// material the literal id's recorded credential grammar binds.
    /// A declaration that binds no credential at all resolves `None` on
    /// every leg: that is the recorded absent-binding form, which sends
    /// the unauthenticated request, never a dummy key. An absent scope
    /// on a class the declaration does bind resolves `None` on the
    /// discovery leg alone (the recorded keyless catalogue); a send still
    /// denies `CredentialAbsent`, so a keyless or free catalogue never
    /// pays for a request. Material the store does hold still passes the
    /// class grammar — resolved-but-unusable material denies typed rather
    /// than silently dropping to the keyless form — and a non-UTF-8
    /// secret can never be a bearer token: typed denial, never a
    /// mangled header. Every grammar, scope or base denial lands here,
    /// before any wire leg.
    fn leg_secret(&self, leg: CredentialLeg) -> Result<Option<WireSecret>, ProviderError> {
        let Some(credential) = &self.credential else {
            return Ok(None);
        };
        match self.store.resolve(credential) {
            Ok(material) => self.wire_secret(material).map(Some),
            Err(ProviderError::CredentialAbsent { .. })
                if matches!(leg, CredentialLeg::Discovery) && self.contract.keyless_discovery() =>
            {
                Ok(None)
            }
            Err(err) => Err(err),
        }
    }

    /// The wire material one resolved store answer binds under the
    /// literal id's recorded credential grammar — the grammar half
    /// both store reads share.
    fn wire_secret(&self, material: Vec<u8>) -> Result<WireSecret, ProviderError> {
        let text =
            String::from_utf8(material).map_err(|_utf8| ProviderError::CredentialMalformed {
                connection: self.connection.clone(),
            })?;
        match self.contract.credential {
            CredentialRule::Bearer => Ok(WireSecret::bearer(text)),
            CredentialRule::AlibabaPlan => self.plan_bearer(&text).map(WireSecret::bearer),
            CredentialRule::AlibabaTokenPlan => {
                self.token_plan_bearer(&text).map(WireSecret::bearer)
            }
            CredentialRule::CoreWeave => self.coreweave_secret(&text),
            CredentialRule::Firepass => self
                .prefixed_bearer(&text, FIREPASS_KEY_PREFIX)
                .map(WireSecret::bearer),
            CredentialRule::HuggingFace => self
                .prefixed_bearer(&text, HUGGINGFACE_TOKEN_PREFIX)
                .map(WireSecret::bearer),
            CredentialRule::Kilo => self.opaque_bearer(&text).map(WireSecret::bearer),
            // The absent-binding class's declared form is the host's own
            // key — a proxy master/virtual key, or a local server key —
            // carried as the plain bearer the recorded `api-key` login
            // pastes; material naming no key denies typed rather than
            // sending an empty bearer.
            CredentialRule::OpenProxy => self.opaque_bearer(&text).map(WireSecret::bearer),
        }
    }

    /// The wire material a `coreweave` credential resolves
    /// (`Rivect/key + OpenAI-Project`, wire/coreweave.ts): the recorded
    /// login is `api-key`, whose `OpenAI-Project` header hook resolves
    /// from the environment — a channel the transport has none of — so
    /// the store slot holds Rivect's translated scoped JSON: `key` is
    /// the bearer and `OpenAI-Project` is the `<team>/<project>` scope
    /// the header carries, which the recorded surface resolves before
    /// any fetch and fails closed without. The bare pasted key is
    /// login input the credential substrate resolves into that stored
    /// form (D4), never store material here: only a JSON object naming
    /// both members as non-empty strings is store material, and
    /// anything else — a bare key, a key-only or empty-scope blob,
    /// empty or whitespace-only material, a quoted string, an array,
    /// JSON that does not parse — denies as malformed before any wire
    /// leg.
    fn coreweave_secret(&self, material: &str) -> Result<WireSecret, ProviderError> {
        let malformed = || ProviderError::CredentialMalformed {
            connection: self.connection.clone(),
        };
        let trimmed = material.trim();
        if trimmed.is_empty() {
            return Err(malformed());
        }
        let parsed: Value = serde_json::from_str(trimmed).map_err(|_parse| malformed())?;
        let bearer = parsed
            .get("key")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|key| !key.is_empty())
            .ok_or_else(&malformed)?;
        let project = parsed
            .get(OPENAI_PROJECT_HEADER)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|scope| !scope.is_empty())
            .ok_or_else(&malformed)?;
        Ok(WireSecret {
            bearer: bearer.to_string(),
            project: Some(project.to_string()),
        })
    }

    /// The bearer a prefix-keyed credential grammar resolves
    /// (`firepass`'s dedicated `fpk_…` pass key and `huggingface`'s
    /// fine-grained `hf_…` model-request token): the trimmed material
    /// must carry that class's recorded prefix plus a non-empty body,
    /// and the trimmed material is then the bearer verbatim. Material
    /// outside the grammar — a key of another enrollment or billing
    /// class included — denies as malformed before any wire leg.
    fn prefixed_bearer(&self, material: &str, prefix: &str) -> Result<String, ProviderError> {
        let token = material.trim();
        token
            .strip_prefix(prefix)
            .filter(|body| !body.is_empty())
            .ok_or_else(|| ProviderError::CredentialMalformed {
                connection: self.connection.clone(),
            })?;
        Ok(token.to_string())
    }

    /// The bearer an opaque-key credential resolves — `kilo`'s recorded
    /// device login token or key (`auth/kilo.kdl` `login "custom"`,
    /// `registry/oauth/kilo.ts`), `litellm`'s proxy master or virtual
    /// key, and `llama.cpp`/`lm-studio`'s optional server key: no class
    /// prefix, no structured body, so the grammar is the trimmed
    /// material verbatim.
    /// Material naming no key denies as malformed before any wire leg —
    /// none of these classes records a subscription SKU or a login an
    /// empty bearer could name.
    fn opaque_bearer(&self, material: &str) -> Result<String, ProviderError> {
        let token = material.trim();
        if token.is_empty() {
            return Err(ProviderError::CredentialMalformed {
                connection: self.connection.clone(),
            });
        }
        Ok(token.to_string())
    }

    /// The bearer an `alibaba-coding-plan` credential resolves
    /// (`alibabaCodingPlanAuth`, `api-key-format "structured"`): the
    /// only shape the recorded login writes is a JSON object whose
    /// `token` is the bearer and whose `enterpriseUrl` is the base the
    /// key was enrolled and validated against — required to equal the
    /// connection's configured base, so a key enrolled for one
    /// recorded base class can never serve another. Anything else is
    /// unbound material the recorded flow never produces — a bare
    /// key, a token-only blob, a missing or unusable field — and
    /// denies as malformed rather than borrowing the slot's
    /// configured base. The recorded `apiEndpoint` steering field is
    /// never read — the configured endpoint alone decides egress.
    /// The bearer must carry the recorded plan-key grammar: a PAYG
    /// `sk-…` is a different product on every plan base. Every denial
    /// is typed and lands before any wire leg.
    fn plan_bearer(&self, material: &str) -> Result<String, ProviderError> {
        let malformed = || ProviderError::CredentialMalformed {
            connection: self.connection.clone(),
        };
        let parsed: Value = serde_json::from_str(material.trim()).map_err(|_parse| malformed())?;
        let token = parsed
            .get("token")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|token| token.starts_with(PLAN_KEY_PREFIX))
            .ok_or_else(&malformed)?;
        // The recorded ingress normalization applied to the enrolled
        // base — the same rule the configured endpoint resolved under
        // at build, so the comparison is over the normalized bases.
        let enrolled = parsed
            .get("enterpriseUrl")
            .and_then(Value::as_str)
            .ok_or_else(&malformed)?
            .trim()
            .trim_end_matches('/');
        if enrolled.is_empty() {
            return Err(malformed());
        }
        if enrolled != self.endpoint {
            return Err(ProviderError::CredentialBaseMismatch {
                connection: self.connection.clone(),
                // The canonical egress rendering — userinfo, query and
                // fragment inside store content never reach the
                // diagnostic.
                enrolled: canonical_egress_target(enrolled),
            });
        }
        Ok(token.to_string())
    }

    /// The bearer an `alibaba-token-plan` credential resolves
    /// (`parseAlibabaTokenPlanCredential`): a bare `sk-…` token, or a
    /// JSON object whose `token` is the bearer, whose optional
    /// `baseUrl` is the region base the key was enrolled and validated
    /// against — absent meaning the recorded international endpoint,
    /// the base the recorded login leaves unwritten — required to
    /// equal the connection's configured base, so a key enrolled for
    /// one region can never serve another (#6682), and whose optional
    /// `cookie` is the separately admitted quota credential: checked
    /// for its recorded string shape and dropped — the usage API it
    /// reports to is a client side-channel this adapter has no leg
    /// for, so the member is never read into a header, a request part
    /// or a diagnostic. Upstream lets the credential's `baseUrl` steer
    /// discovery (`credential?.baseUrl ?? config?.baseUrl ?? …`);
    /// the adapter instead keeps egress bound to the configured
    /// endpoint alone and treats the enrolled base as the region
    /// evidence it must match — the same bound `plan_bearer` applies
    /// to `enterpriseUrl`. Anything else is material the recorded
    /// parse never produces — a non-`sk-…` token, a non-string member
    /// — and denies as malformed. Every denial is typed and lands
    /// before any wire leg.
    fn token_plan_bearer(&self, material: &str) -> Result<String, ProviderError> {
        let malformed = || ProviderError::CredentialMalformed {
            connection: self.connection.clone(),
        };
        let trimmed = material.trim();
        if trimmed.is_empty() {
            return Err(malformed());
        }
        let (token, enrolled) = if trimmed.starts_with('{') {
            let parsed: Value = serde_json::from_str(trimmed).map_err(|_parse| malformed())?;
            let token = parsed
                .get("token")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|token| is_token_plan_key(token))
                .ok_or_else(&malformed)?;
            // The recorded optional members: non-string shapes are
            // material the parse never produces — denied; the cookie
            // is then dropped unread, the baseUrl binds the region.
            match parsed.get("cookie") {
                None | Some(Value::String(_)) => {}
                Some(_) => return Err(malformed()),
            }
            let enrolled = match parsed.get("baseUrl") {
                None => None,
                // The recorded ingress normalization applied to the
                // enrolled base — the same rule the configured
                // endpoint resolved under at build, so the comparison
                // is over the normalized bases; the empty string is
                // the absent case the recorded parse leaves unset.
                Some(Value::String(base)) => {
                    let base = base.trim().trim_end_matches('/');
                    if base.is_empty() {
                        None
                    } else {
                        Some(base.to_string())
                    }
                }
                Some(_) => return Err(malformed()),
            };
            (token.to_string(), enrolled)
        } else {
            // A bare `sk-…` token: the recorded serialize writes this
            // shape only when the enrolled base is the international
            // default, so absent `baseUrl` is the intl class.
            if !is_token_plan_key(trimmed) {
                return Err(malformed());
            }
            (trimmed.to_string(), None)
        };
        let enrolled = enrolled.unwrap_or_else(|| ALIBABA_TOKEN_PLAN_INTL_BASE_URL.to_string());
        if enrolled != self.endpoint {
            return Err(ProviderError::CredentialBaseMismatch {
                connection: self.connection.clone(),
                // The canonical egress rendering — userinfo, query and
                // fragment inside store content never reach the
                // diagnostic.
                enrolled: canonical_egress_target(&enrolled),
            });
        }
        Ok(token)
    }

    /// The wire form the `model` member carries under the literal
    /// id's recorded wire-model-id dispatch (`wire-model-id-mode`,
    /// `fireworks.kdl`): `fireworks` sends
    /// `accounts/fireworks/models/<id>` — `accounts/fireworks/
    /// routers/<id>` for a `*-fast` serving-path id — with the
    /// recorded `p` version separator (`toFireworksWireModelId`);
    /// `firepass` sends `accounts/fireworks/routers/<id>` for every
    /// pinned router id (`toFirepassWireModelId`); every verbatim
    /// transform — `IdsOnly`, `GenericMetadata`, `Aiand`, `Aimlapi`,
    /// `AlibabaTokenPlan`, `DeepSeek`, `Groq`, `HuggingFace`,
    /// `LiteLlm`, `Moonshot`, `NanoGpt`, `Novita`, `SiliconFlow`,
    /// `Synthetic` and `Vllm` —
    /// sends the offered id unchanged. Each variant is listed so a
    /// future transform cannot ship verbatim ids silently.
    fn wire_model_id(&self, model_id: &str) -> String {
        match self.contract.entries {
            EntryRule::Firepass => firepass_wire_model_id(model_id),
            EntryRule::Fireworks => fireworks_wire_model_id(model_id),
            EntryRule::IdsOnly
            | EntryRule::GenericMetadata
            | EntryRule::Aiand
            | EntryRule::Aimlapi
            | EntryRule::AlibabaTokenPlan
            | EntryRule::DeepSeek
            | EntryRule::Groq
            | EntryRule::HuggingFace
            | EntryRule::LiteLlm
            | EntryRule::LmStudio
            | EntryRule::Moonshot
            | EntryRule::NanoGpt
            | EntryRule::Novita
            | EntryRule::SiliconFlow
            | EntryRule::Synthetic
            | EntryRule::Vllm => model_id.to_string(),
        }
    }

    /// Whether this class asks the peer for the recorded
    /// `stream_options.include_usage` usage report. Every arm does except
    /// `venice`: its recorded request names no `stream_options` member,
    /// so a body carrying one would send a parameter the class does not
    /// request — and its reported usage may legitimately stay
    /// [`UsageDelta::Unknown`].
    fn requests_usage_report(&self) -> bool {
        self.connection != "venice"
    }

    /// The frozen manifest as the Chat Completions wire request:
    /// `model`, `messages` — the instructions as the `system` message
    /// when they carry text, the inputs as `user` — `stream` with the
    /// recorded `stream_options.include_usage`, the declared tool
    /// surface as function tools, and the pinned effort as
    /// `reasoning_effort` verbatim. The manifest's frozen effort is
    /// the only capability surface: nothing else — no sampling
    /// knobs, no provider options — is invented. The recorded usage
    /// request rides every arm but `venice`
    /// ([`Self::requests_usage_report`]), whose body names no
    /// `stream_options` member at all.
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
        if self.requests_usage_report() {
            body["stream_options"] = json!({ "include_usage": true });
        }
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

    /// The recorded parameter predicate (HZN-008): a pinned
    /// `reasoning_effort` rides the body only where the pin's model
    /// records that level — every other level, and every model with no
    /// recorded effort surface, is a parameter that class rejects. The
    /// predicate is per-arm, not per-connection: every arm whose
    /// contract records an effort ladder — `groq`'s per-model table
    /// and `moonshot`'s K3 ladder (DEC-014) — denies the unrecorded
    /// pin typed, while an arm that records no ladder applies no
    /// effort predicate at all. The denial lands before the request
    /// body exists: a fixed pin denies before any wire leg, while an
    /// auto pin — whose model the listing resolved first — denies
    /// before the chat request leg. The value is never dropped from
    /// the body behind the caller's back. The classes' other
    /// recorded-rejected parameters (`groq`'s logprobs, logit_bias,
    /// top_logprobs, `messages[].name`, `n`, temperature) are never
    /// constructed by this adapter, so none can be dropped. `vllm`
    /// records no effort ladder either: the listing that could state
    /// the chat-template surface is not visible at the send seam, so
    /// every pinned level denies typed.
    fn check_parameters(
        &self,
        manifest: &RequestManifest,
        model_id: &str,
    ) -> Result<(), ProviderError> {
        let ladder = match self.contract.entries {
            EntryRule::Groq => GROQ_EFFORTS,
            EntryRule::Moonshot => MOONSHOT_EFFORTS,
            // The listing that could state the effort surface is not
            // visible at the send seam, so no level is recorded: every
            // pinned effort denies typed rather than being dropped.
            EntryRule::Vllm => &[],
            EntryRule::IdsOnly
            | EntryRule::GenericMetadata
            | EntryRule::Aiand
            | EntryRule::Aimlapi
            | EntryRule::AlibabaTokenPlan
            | EntryRule::DeepSeek
            | EntryRule::Firepass
            | EntryRule::Fireworks
            | EntryRule::HuggingFace
            | EntryRule::LiteLlm
            | EntryRule::LmStudio
            | EntryRule::NanoGpt
            | EntryRule::Novita
            | EntryRule::SiliconFlow
            | EntryRule::Synthetic => return Ok(()),
        };
        let EffortAssign::Fixed { value } = &manifest.effort else {
            return Ok(());
        };
        let recorded = ladder
            .iter()
            .any(|(model, levels)| *model == model_id && levels.contains(value));
        if recorded {
            return Ok(());
        }
        Err(ProviderError::UnsupportedParameter {
            connection: self.connection.clone(),
            parameter: "reasoning_effort",
            model: model_id.to_string(),
        })
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
                self.on_chunk(&mut state, event)?;
            }
        }
        // Finalization shares the budget — the stream's total cost is
        // bounded even when its last byte lands just inside it.
        check_deadline(&self.connection, self.deadline, started)?;
        for event in parser.finish().map_err(|err| sse(&self.connection, err))? {
            self.on_chunk(&mut state, event)?;
        }
        match state.terminal {
            Some(Terminal::Completed) => self.complete(manifest, state),
            Some(Terminal::Failed { reason }) => Err(ProviderError::ProviderFailed {
                connection: self.connection.clone(),
                reason: bounded_reason(reason),
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
                Value::Object(_) => payload_reason(error),
                _ => {
                    return Err(violation(
                        &self.connection,
                        "stream chunk error is not an object or string",
                    ));
                }
            };
            return self.set_terminal(state, Terminal::Failed { reason });
        }
        if let Some(message) = chunk.get("message").filter(|message| !is_falsy(message)) {
            let Some(reason) = message.as_str() else {
                return Err(violation(
                    &self.connection,
                    "stream chunk message is not a string",
                ));
            };
            return self.set_terminal(
                state,
                Terminal::Failed {
                    reason: reason.to_string(),
                },
            );
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
                // The request never asks for more than one candidate,
                // so a second choice is off-contract input — never a
                // silent first-pick of divergent content.
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
                        // A choice after the declared terminal adopts
                        // nothing: the verdict closed the turn, and
                        // only the usage tail and `[DONE]` may follow.
                        if state.terminal.is_some() {
                            return Err(violation(
                                &self.connection,
                                "stream carried a choice after its terminal",
                            ));
                        }
                        if let Some(index) = choice.get("index") {
                            // The single requested slot is index 0;
                            // any other belongs to a candidate the
                            // request never asked for.
                            if index.as_u64() != Some(0) {
                                return Err(violation(
                                    &self.connection,
                                    "stream chunk choice carries a nonzero index",
                                ));
                            }
                        }
                        if choice
                            .get("message")
                            .is_some_and(|message| !message.is_null())
                        {
                            // A `message` member is the non-streamed
                            // response shape — this stream carries
                            // deltas only.
                            return Err(violation(
                                &self.connection,
                                "stream chunk choice carries a non-delta message",
                            ));
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
                    _ => {
                        return Err(violation(
                            &self.connection,
                            "choice finish_reason is not a string",
                        ));
                    }
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
            return Err(violation(&self.connection, "choice delta is not an object"));
        };
        if let Some(role) = delta.get("role") {
            match role {
                Value::String(_) | Value::Null => {}
                _ => return Err(violation(&self.connection, "delta role is not a string")),
            }
        }
        if let Some(content) = delta.get("content") {
            match content {
                Value::String(text) => state.text.push_str(text),
                Value::Null => {}
                _ => return Err(violation(&self.connection, "delta content is not a string")),
            }
        }
        if let Some(refusal) = delta.get("refusal") {
            match refusal {
                Value::String(_) | Value::Null => {}
                _ => return Err(violation(&self.connection, "delta refusal is not a string")),
            }
        }
        for key in ["reasoning_content", "reasoning", "reasoning_text"] {
            if let Some(reasoning) = delta.get(key) {
                match reasoning {
                    Value::String(_) | Value::Null => {}
                    _ => {
                        return Err(violation(
                            &self.connection,
                            "delta reasoning is not a string",
                        ));
                    }
                }
            }
        }
        if let Some(details) = delta.get("reasoning_details")
            && !details.is_array()
            && !details.is_null()
        {
            return Err(violation(
                &self.connection,
                "delta reasoning_details is not an array",
            ));
        }
        if let Some(calls) = delta.get("tool_calls") {
            let Some(calls) = calls.as_array() else {
                return Err(violation(
                    &self.connection,
                    "delta tool_calls is not an array",
                ));
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
            // An empty id is no correlation key — the recorded
            // contract treats a falsy id as absent.
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
            return Err(violation(
                &self.connection,
                "a tool_calls entry without index or id cannot be routed",
            ));
        } else if state.blocks.is_empty() {
            state.blocks.push(ToolBlock::default());
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
            Some(_) => {
                return Err(violation(
                    &self.connection,
                    "tool_calls entry type is not a string",
                ));
            }
        }
        // The block's id is set once like its name — a second,
        // different id re-keys a routed block, and an id a sibling
        // block already holds would make an id-only continuation's
        // routing ambiguous: both are malformed, never silently
        // re-keyed.
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
            _ => Err(violation(
                &self.connection,
                "usage is not a readable token shape",
            )),
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

/// The recorded generic listing transform (DEC-020): the id plus the two
/// limits a row can state — `context_length` on the window carrier and
/// `max_completion_tokens` on the maximum-output carrier — each read as a
/// positive whole count. An absent, zero or unreadable value stays
/// `None`: the class records no default figure, and neither carrier is
/// ever borrowed from the other.
fn generic_metadata_entry(id: &str, entry: &Value) -> CatalogModel {
    CatalogModel {
        id: id.to_string(),
        context_window: positive_count(entry.get("context_length")),
        max_output_tokens: positive_count(entry.get("max_completion_tokens")),
        ..CatalogModel::default()
    }
}

/// The recorded `vllm` listing transform: vLLM's own `max_model_len`
/// is the served context window — the compatible listing states no
/// `context_length` — and a Qwen `major.minor` at or above 3.8 in the
/// offered id carries the display-only reasoning mark the recorded
/// Qwen chat template implies. The listing states no effort ladder, so
/// the mark is display-only; [`ChatCompletionsProvider::check_parameters`]
/// denies a pinned level instead of dropping it.
fn vllm_entry(id: &str, entry: &Value) -> CatalogModel {
    CatalogModel {
        id: id.to_string(),
        reasoning: vllm_qwen_reasoning(id),
        context_window: positive_count(entry.get("max_model_len")),
        ..CatalogModel::default()
    }
}

/// Whether a listed id names a Qwen version at or above 3.8 (HZN-14-03):
/// every case-insensitive `qwen` occurrence is followed by a
/// `major.minor` pair, and only a pair that high marks reasoning. A
/// bare major (`Qwen3-…`) states no 3.8 surface and marks nothing.
fn vllm_qwen_reasoning(id: &str) -> bool {
    let lowered = id.to_ascii_lowercase();
    let mut rest = lowered.as_str();
    while let Some(found) = rest.find("qwen") {
        let version = &rest[found + "qwen".len()..];
        let major_len = version
            .find(|ch: char| !ch.is_ascii_digit())
            .unwrap_or(version.len());
        if let Some(minor_text) = version[major_len..].strip_prefix('.') {
            let minor_len = minor_text
                .find(|ch: char| !ch.is_ascii_digit())
                .unwrap_or(minor_text.len());
            if let (Ok(major), Ok(minor)) = (
                version[..major_len].parse::<u64>(),
                minor_text[..minor_len].parse::<u64>(),
            ) && (major, minor) >= (3, 8)
            {
                return true;
            }
        }
        rest = version;
    }
    false
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
        max_output_tokens: None,
        price: aiand_price(entry),
    }
}

/// The recorded `litellm` management base
/// (`normalizeLiteLLMManagementBaseUrl`): the configured base trimmed
/// of trailing slashes with a trailing `/v1` segment removed, so the
/// recorded paths append to the proxy's own root. An absent base stays
/// empty, and the phase then opens no request at all — never a
/// substituted host.
fn litellm_management_base(base: &str) -> String {
    let base = base.trim().trim_end_matches('/');
    base.strip_suffix("/v1")
        .unwrap_or(base)
        .trim_end_matches('/')
        .to_string()
}

/// The budget one `litellm` metadata probe may spend: the shorter of the
/// recorded phase bound's remainder and the whole call's remainder, or
/// `None` when either is spent — a spent phase ends the walk, and a spent
/// call is [`check_deadline`]'s typed denial to raise.
fn litellm_probe_budget(
    phase_started: Instant,
    call_started: Instant,
    call_deadline: Duration,
) -> Option<Duration> {
    let phase_left = LITELLM_METADATA_BUDGET.checked_sub(phase_started.elapsed())?;
    let call_left = call_deadline.checked_sub(call_started.elapsed())?;
    Some(phase_left.min(call_left)).filter(|left| !left.is_zero())
}

/// The recorded `litellm` metadata payload's entries
/// (`extractLiteLLMRichEntries`): a JSON array of records, or the first
/// of the recorded wrappers — `data`, `models`, `result`, `items` —
/// that holds one. A payload carrying none of them has no entries.
fn litellm_metadata_entries(payload: &Value) -> Option<Vec<&Value>> {
    match payload {
        Value::Array(items) => Some(items.iter().filter(|item| item.is_object()).collect()),
        Value::Object(map) => ["data", "models", "result", "items"]
            .iter()
            .find_map(|key| map.get(*key).and_then(litellm_metadata_entries)),
        _ => None,
    }
}

/// One rich `litellm` metadata field (`getLiteLLMMetadataValue`): the
/// entry's own member, else the same member of its `model_info` object.
fn litellm_metadata_value<'a>(entry: &'a Value, key: &str) -> Option<&'a Value> {
    entry
        .get(key)
        .or_else(|| entry.get("model_info").and_then(|info| info.get(key)))
}

/// The model id a rich `litellm` entry names
/// (`getLiteLLMRichModelId`): `model_group`, then `model_name`, then
/// `id`, then the backend `litellm_params.model` — each as a non-empty
/// trimmed string.
fn litellm_model_id(entry: &Value) -> Option<String> {
    let text = |key: &str| {
        entry
            .get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
    };
    text("model_group")
        .or_else(|| text("model_name"))
        .or_else(|| text("id"))
        .or_else(|| {
            entry
                .get("litellm_params")
                .and_then(|params| params.get("model"))
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
        })
}

/// Whether a rich `litellm` entry is the proxy's placeholder row
/// (`isLiteLLMUnusableSentinelPlaceholder`): it names a recorded
/// sentinel id and carries no metadata at all — no window, no stated
/// capability, no supported parameters, no provider list. Such a row is
/// never offered as a model.
fn is_litellm_sentinel_placeholder(entry: &Value) -> bool {
    let names_sentinel = ["model_group", "id", "model_name"].iter().any(|key| {
        litellm_metadata_value(entry, key)
            .and_then(Value::as_str)
            .is_some_and(|value| LITELLM_SENTINEL_IDS.contains(&value.trim()))
    }) || entry
        .get("litellm_params")
        .and_then(|params| params.get("model"))
        .and_then(Value::as_str)
        .is_some_and(|value| LITELLM_SENTINEL_IDS.contains(&value.trim()));
    if !names_sentinel {
        return false;
    }
    let providers = entry.get("providers");
    if providers.is_some_and(|list| !list.as_array().is_some_and(Vec::is_empty)) {
        return false;
    }
    let carries_window = ["max_input_tokens", "max_output_tokens"]
        .iter()
        .any(|key| positive_count(litellm_metadata_value(entry, key)).is_some());
    let carries_capability = [
        "supports_vision",
        "supports_reasoning",
        "supports_function_calling",
        "supports_tools",
    ]
    .iter()
    .any(|key| litellm_metadata_value(entry, key).and_then(Value::as_bool) == Some(true));
    let carries_params = litellm_metadata_value(entry, "supported_openai_params")
        .and_then(Value::as_array)
        .is_some_and(|params| !params.is_empty());
    !(carries_window || carries_capability || carries_params)
}

/// The recorded USD price a rich `litellm` entry states
/// (`getLiteLLMReportedCost` / `getLiteLLMCost`): the per-token
/// `input_cost_per_token` and `output_cost_per_token` figures, each
/// scaled to [`ModelPrice::Usd`]'s per-1M basis. Both legs are needed —
/// a row stating one alone keeps [`ModelPrice::Unknown`], never a zero
/// the accounting could release.
fn litellm_metadata_price(entry: &Value) -> ModelPrice {
    let per_million = |key: &str| {
        litellm_metadata_value(entry, key)
            .and_then(Value::as_f64)
            .filter(|value| *value > 0.0)
            .map(|value| value * LITELLM_PRICE_SCALE)
    };
    match (
        per_million("input_cost_per_token"),
        per_million("output_cost_per_token"),
    ) {
        (Some(input_per_1m), Some(output_per_1m)) => ModelPrice::Usd {
            input_per_1m,
            output_per_1m,
        },
        _ => ModelPrice::Unknown,
    }
}

/// One rich `litellm` metadata entry as an offer (`mapLiteLLMRichEntry`,
/// reduced to the surface [`CatalogModel`] carries): the id, the stated
/// capability marks, the input window and the per-1M price. The
/// recorded effort ladder and API route have no landing here — this
/// adapter's effort surface is per-pin, not per-model — and an absent
/// window stays absent rather than adopting the reference default the
/// upstream mapper fills.
fn litellm_metadata_model(entry: &Value) -> Option<CatalogModel> {
    if is_litellm_sentinel_placeholder(entry) {
        return None;
    }
    let id = litellm_model_id(entry)?;
    Some(CatalogModel {
        id,
        reasoning: litellm_metadata_value(entry, "supports_reasoning").and_then(Value::as_bool)
            == Some(true),
        vision: litellm_metadata_value(entry, "supports_vision").and_then(Value::as_bool)
            == Some(true),
        efforts: Vec::new(),
        effort_default: None,
        context_window: positive_count(litellm_metadata_value(entry, "max_input_tokens")),
        max_output_tokens: None,
        price: litellm_metadata_price(entry),
    })
}

/// Fills the gaps a later `litellm` metadata form covers
/// (`mergeLiteLLMRichEndpointModels`): the first answering endpoint owns
/// the id set, and a later one may only add capability marks, a window
/// or a price the first left unstated.
fn litellm_metadata_fill(existing: &mut CatalogModel, next: &CatalogModel) {
    existing.reasoning |= next.reasoning;
    existing.vision |= next.vision;
    if existing.context_window.is_none() {
        existing.context_window = next.context_window;
    }
    if existing.price == ModelPrice::Unknown {
        existing.price = next.price;
    }
}

/// Whether the metadata phase has more to learn
/// (`needsMoreMetadata`): an offer still missing its input window or its
/// price keeps the recorded walk alive. The upstream predicate also
/// watches a vision mark that no answer stated; [`CatalogModel`] carries
/// that mark as a bool whose absence is `false`, so this reduction
/// watches the two surfaces the model actually carries.
fn litellm_metadata_incomplete(offered: &BTreeMap<String, CatalogModel>) -> bool {
    offered
        .values()
        .any(|model| model.context_window.is_none() || model.price == ModelPrice::Unknown)
}

/// The recorded per-model USD price a pinned row table states for
/// an id (`cost.input`/`cost.output` per 1M tokens): a stated zero
/// is a real figure — a free or bundled-only SKU — and an id the
/// rows do not name keeps [`ModelPrice::Unknown`], never a borrowed
/// or coerced figure.
fn pinned_price(rows: &[(&str, f64, f64)], id: &str) -> ModelPrice {
    rows.iter()
        .find(|(model, ..)| *model == id)
        .map(|(_, input_per_1m, output_per_1m)| ModelPrice::Usd {
            input_per_1m: *input_per_1m,
            output_per_1m: *output_per_1m,
        })
        .unwrap_or_default()
}

/// The recorded `groq` entry transform (pinned `models.json`): a
/// listed or seeded id is offered as served. A recorded row carries its
/// reasoning mark, effort ladder, image-input mark and USD price; an id
/// the pinned rows do not name is a foreign listing id — offered with
/// no reasoning, effort, vision or price surface, so no figure is
/// borrowed and no entitlement is implied.
fn groq_entry(id: &str) -> CatalogModel {
    let efforts = GROQ_EFFORTS
        .iter()
        .find(|(model, _)| *model == id)
        .map(|(_, levels)| (*levels).to_vec())
        .unwrap_or_default();
    CatalogModel {
        id: id.to_string(),
        reasoning: !efforts.is_empty(),
        vision: GROQ_VISION_MODELS.contains(&id),
        efforts,
        price: pinned_price(GROQ_PRICES, id),
        ..CatalogModel::default()
    }
}

/// The recorded `deepseek` entry transform: only a built-in id the
/// roster names offers — a benchmark or legacy id the listing
/// carries never does. The admitted entry carries the recorded
/// surface: the native reasoning mark with the `low`/`high`/`max`
/// ladder's mappable levels (the recorded `max` names no level our
/// enum carries and never maps onto a lower one), the `vision-exp`
/// build's image-input mark, the million-token window and the
/// per-model USD prices [`DEEPSEEK_PRICES`] states; the prepaid
/// balance and off-peak rules stay account facts we never
/// synthesize, and the recorded cache figures stay uncarried —
/// [`ModelPrice`] holds input/output alone.
fn deepseek_entry(id: &str) -> Option<CatalogModel> {
    DEEPSEEK_BUILTIN_MODELS.contains(&id).then(|| CatalogModel {
        id: id.to_string(),
        reasoning: true,
        vision: id == DEEPSEEK_VISION_MODEL,
        efforts: vec![EffortLevel::Low, EffortLevel::High],
        context_window: Some(1_000_000),
        price: pinned_price(DEEPSEEK_PRICES, id),
        ..CatalogModel::default()
    })
}

/// The recorded version-separator fold the Fireworks-family ids share:
/// every `from` sitting between two digits becomes `to` — the `p`↔`.`
/// pair the public and wire forms disagree on. Any other character,
/// including a separator at an edge or beside a non-digit, rides
/// verbatim.
fn fold_version_separator(text: &str, from: char, to: char) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut folded = String::with_capacity(text.len());
    for (at, &ch) in chars.iter().enumerate() {
        if ch == from
            && at > 0
            && chars[at - 1].is_ascii_digit()
            && chars.get(at + 1).is_some_and(char::is_ascii_digit)
        {
            folded.push(to);
        } else {
            folded.push(ch);
        }
    }
    folded
}

/// The recorded `fireworks` public id
/// (`toFireworksPublicModelId`): the `accounts/fireworks/models/`
/// wire prefix stripped, then the `p` version separator between
/// digits folded back to `.` (`kimi-k2p7-code` → `kimi-k2.7-code`).
fn fireworks_public_id(id: &str) -> String {
    fold_version_separator(
        id.strip_prefix(FIREWORKS_WIRE_PREFIX).unwrap_or(id),
        'p',
        '.',
    )
}

/// The recorded Fireworks-family wire-id body
/// (`toFireworksWireModelId`/`toFirepassWireModelId`): whichever
/// recorded wire prefix the id carries is stripped, then every `.`
/// between digits folds to the `p` version separator.
fn fireworks_wire_body(id: &str) -> String {
    let stripped = id
        .strip_prefix(FIREWORKS_WIRE_PREFIX)
        .or_else(|| id.strip_prefix(FIREWORKS_ROUTER_PREFIX))
        .unwrap_or(id);
    fold_version_separator(stripped, '.', 'p')
}

/// The recorded `fireworks` wire id (`toFireworksWireModelId`): the
/// shared body fold, then the serving-path prefix — `routers/`
/// exactly when the body ends `-fast`, `models/` otherwise. A pin
/// already carrying a wire prefix is therefore re-served under the
/// path its id names, never echoed verbatim when the prefix
/// disagrees with the id.
fn fireworks_wire_model_id(id: &str) -> String {
    let wire = fireworks_wire_body(id);
    if wire.ends_with("-fast") {
        format!("{FIREWORKS_ROUTER_PREFIX}{wire}")
    } else {
        format!("{FIREWORKS_WIRE_PREFIX}{wire}")
    }
}

/// The recorded `firepass` wire id (`toFirepassWireModelId` under the
/// recorded `wire-model-id-mode "firepass"`): the shared body fold,
/// then the `accounts/fireworks/routers/` prefix unconditionally —
/// the recorded login validate sends its router id in that form
/// (`auth/firepass.kdl`), and the pass key is scoped to a router, so
/// `kimi-k2.6-turbo` wires as
/// `accounts/fireworks/routers/kimi-k2p6-turbo` while the documented
/// `kimi-k3-fast` keeps its own router form instead of folding onto
/// the pinned id.
fn firepass_wire_model_id(id: &str) -> String {
    format!("{FIREWORKS_ROUTER_PREFIX}{}", fireworks_wire_body(id))
}

/// The recorded `fireworks` entry transform — the admission surface
/// of the DEC-025 row: any unreserved request-model id is admitted,
/// carrying its public form after the `accounts/fireworks/models/`
/// wire prefix is stripped, and an id still carrying the reserved
/// `accounts/fireworks/` prefix is dropped under the recorded
/// `exclude-models prefix="accounts/fireworks/"` runtime rule — a
/// router id is a serving path, never a model this connection
/// offers. The row records no per-id chat predicate beyond that
/// reserved-prefix exclusion, so none is applied. The admitted id
/// carries the per-model USD price [`FIREWORKS_PRICES`] states — a
/// stated zero is a real figure — with [`ModelPrice::Unknown`] for
/// an id the pinned rows do not name; the request-model listing
/// names no other recorded surface, so every other field stays at
/// its empty surface.
fn fireworks_entry(id: &str) -> Option<CatalogModel> {
    let public = fireworks_public_id(id);
    if public.is_empty() || public.starts_with("accounts/fireworks/") {
        return None;
    }
    Some(CatalogModel {
        id: public.clone(),
        price: pinned_price(FIREWORKS_PRICES, &public),
        ..CatalogModel::default()
    })
}

/// The recorded `aimlapi` exclusion tokens (`rules/runtime/
/// behavior.kdl`, `exclude-models provider="aimlapi"`): an id whose
/// lowercase alphanumeric runs name one is a media/embedding SKU the
/// chat surface cannot serve. The match runs on bounded `[^a-z0-9]+`
/// segments, not plain substrings — a `...-video-...` segment drops
/// while `video` inside `videoservice` survives.
const AIMLAPI_EXCLUDED_TOKENS: &[&str] = &[
    "audio",
    "embed",
    "embedding",
    "embeddings",
    "i2i",
    "i2v",
    "image",
    "speech",
    "t2i",
    "t2v",
    "tts",
    "video",
];

/// The recorded `aimlapi` exclusion substrings (same rule): media
/// family names matched inside the lowercase id.
const AIMLAPI_EXCLUDED_SUBSTRINGS: &[&str] = &[
    "dall-e", "dalle", "flux", "imagen", "sora", "veo", "whisper",
];

/// The recorded `aimlapi` chat-id filter
/// (`isLikelyAimlApiChatModelId` → `isExcludedModel`, openai-compat.ts
/// §6.4): the id is trimmed and lowered, then dropped when the
/// `exclude-models` rule matches — a substring hit, or a `token` hit
/// against the id's alphanumeric runs (`matchesList` splits
/// `[^a-z0-9]+`). Every other non-empty listed id is offered.
fn is_likely_aimlapi_chat_id(id: &str) -> bool {
    let normalized = id.trim().to_lowercase();
    if normalized.is_empty() {
        return false;
    }
    if AIMLAPI_EXCLUDED_SUBSTRINGS
        .iter()
        .any(|sub| normalized.contains(sub))
    {
        return false;
    }
    !normalized
        .split(|c: char| !c.is_ascii_alphanumeric())
        .any(|part| AIMLAPI_EXCLUDED_TOKENS.contains(&part))
}

/// The recorded `alibaba-token-plan` key grammar (`TOKEN_PATTERN` —
/// `^sk-[A-Za-z0-9._~+/-]+={0,2}$`): `sk-`, then one or more base
/// characters, then at most two trailing `=` pad characters. A key
/// outside the grammar is a different product on every plan base.
fn is_token_plan_key(token: &str) -> bool {
    let Some(rest) = token.strip_prefix("sk-") else {
        return false;
    };
    let core = rest.trim_end_matches('=');
    if rest.len() - core.len() > 2 || core.is_empty() {
        return false;
    }
    core.bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'+' | b'/' | b'-'))
}

/// The recorded `alibaba-token-plan` chat-id filter
/// (`isAlibabaTokenPlanChatModelId` → `isExcludedModel`'s `prefix`
/// arm, openai-compat.ts §11): the id is trimmed and lowered, then
/// dropped when the `exclude-models` prefix roster matches — the
/// ASR/image/embedding SKUs the chat picker cannot route. Every
/// other non-empty listed id is offered.
fn is_alibaba_token_plan_chat_id(id: &str) -> bool {
    let normalized = id.trim().to_lowercase();
    if normalized.is_empty() {
        return false;
    }
    !ALIBABA_TOKEN_PLAN_EXCLUDED_PREFIXES
        .iter()
        .any(|prefix| normalized.starts_with(prefix))
}

/// The recorded `siliconflow`/`siliconflow-cn` exclusion list
/// (`exclude-models provider="siliconflow"`, runtime/behavior.kdl):
/// the provider's `/v1/models` roster interleaves embeddings,
/// rerankers and image/audio/video generators with no per-model type
/// field, so the text-chat transport can tell them apart only by name.
/// Both region ids record the same list. A dropped id is never an
/// offer; a chat id outside these recorded families survives.
const SILICONFLOW_EXCLUDED_SUBSTRINGS: &[&str] = &[
    "embedding",
    "reranker",
    "bge-",
    "bce-",
    "stable-diffusion",
    "image",
    "flux",
    "kolors",
    "sensevoice",
    "cosyvoice",
    "fish-speech",
    "indextts",
    "sovits",
    "whisper",
    "hunyuanvideo",
    "wan2",
    "ltx-video",
    "speech",
    "moderator",
    "tts",
];

/// The recorded SiliconFlow chat-id filter
/// (`isLikelySiliconFlowChatModelId` → `isExcludedModel`,
/// openai-compat.ts §6.6): the id is trimmed and lowered, then dropped
/// when the recorded exclusion list names one of its lowercase
/// substrings. Every other non-empty listed id is offered.
fn is_likely_siliconflow_chat_id(id: &str) -> bool {
    let normalized = id.trim().to_lowercase();
    if normalized.is_empty() {
        return false;
    }
    !SILICONFLOW_EXCLUDED_SUBSTRINGS
        .iter()
        .any(|family| normalized.contains(family))
}

/// The recorded SiliconFlow listing transform: the id must pass the
/// recorded chat-id filter, then [`generic_metadata_entry`] maps the two
/// stated limits, and the recorded `min(maxTokens, context)` clamp caps
/// the maximum output at the window where both exist. An absent, zero
/// or unreadable value stays `None` — no default figure and no borrowed
/// sibling field — and no vendored roster or price row exists (D2),
/// so an admitted offer keeps [`ModelPrice::Unknown`].
fn siliconflow_entry(id: &str, entry: &Value) -> Option<CatalogModel> {
    if !is_likely_siliconflow_chat_id(id) {
        return None;
    }
    let mut model = generic_metadata_entry(id, entry);
    if let (Some(max_output_tokens), Some(context_window)) =
        (model.max_output_tokens, model.context_window)
    {
        model.max_output_tokens = Some(max_output_tokens.min(context_window));
    }
    Some(model)
}

/// The recorded Synthetic string-list read (`toSyntheticStringList`):
/// an array contributes its string members in wire order; any other
/// shape, or an absent key, reads as no members.
fn synthetic_string_list(value: Option<&Value>) -> Vec<&str> {
    value
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

/// The recorded Synthetic per-token→per-1M conversion
/// (`toSyntheticCostPerMillion`): a JSON number or a string whose
/// trimmed form may carry one leading `$`, finite and non-negative,
/// scaled to per-1M tokens. The scale settles on a millionth of a
/// dollar per million tokens, so decimal scaling never drifts
/// (`4.5e-7` scales to `0.45`, not `0.44999999999999996`). Any other
/// shape — absent, unreadable, infinite, negative, or a finite figure
/// whose per-1M scale overflows — is no figure.
fn synthetic_cost_per_million(value: Option<&Value>) -> Option<f64> {
    let parsed = value
        .and_then(|value| {
            value.as_f64().or_else(|| {
                value.as_str().and_then(|text| {
                    let text = text.trim();
                    text.strip_prefix('$').unwrap_or(text).parse().ok()
                })
            })
        })
        .filter(|number| number.is_finite() && *number >= 0.0)?;
    let scaled = (parsed * 1e12).round() / 1e6;
    scaled.is_finite().then_some(scaled)
}

/// The recorded Synthetic price rule (`resolveSyntheticCost`): both
/// `pricing.prompt` and `pricing.completion` must state a usable
/// per-token figure — a partial answer keeps [`ModelPrice::Unknown`]
/// rather than borrowing a bundled reference or defaulting to zero.
/// A stated zero is a real figure, so a free route prices as USD zero,
/// never as unknown.
fn synthetic_price(entry: &Value) -> ModelPrice {
    let Some(pricing) = entry.get("pricing") else {
        return ModelPrice::Unknown;
    };
    let (Some(input_per_1m), Some(output_per_1m)) = (
        synthetic_cost_per_million(pricing.get("prompt")),
        synthetic_cost_per_million(pricing.get("completion")),
    ) else {
        return ModelPrice::Unknown;
    };
    ModelPrice::Usd {
        input_per_1m,
        output_per_1m,
    }
}

/// The recorded Synthetic listing transform (`syntheticModelManagerOptions`
/// at the pinned commit): `supported_features` names the reasoning
/// capability, `input_modalities` names image input, the output cap
/// falls from `max_output_length` through `max_tokens` to the recorded
/// 8192 placeholder (no bundled reference exists here), and
/// `reasoning_parameters.efforts` maps only levels our vocabulary
/// carries — `none` is the thinking-off router state and `max` has no
/// carrier, so neither lands (DEC-008). Reasoning is the wire's own
/// answer: a stated effort vocabulary decides it — a `none`-only
/// vocabulary is the off-switch, never a dial the feature mark would
/// claim — and only a wire stating no vocabulary falls back to
/// `supported_features` naming `reasoning`. The recorded source never
/// re-adds a dial from a reference this adapter does not carry.
/// `tools` is an ignored feature: the shared catalogue record
/// carries no tool field. `context_length` maps the input window when
/// stated; a `max_output_length`/`max_tokens` fallback never borrows
/// the window. Unknown keys — including the generic
/// `supports_reasoning`, `supports_vision`, `cost` and `price`
/// fields — are ignored.
fn synthetic_entry(id: &str, entry: &Value) -> CatalogModel {
    let features = synthetic_string_list(entry.get("supported_features"));
    let modalities = synthetic_string_list(entry.get("input_modalities"));
    let wire_efforts = entry
        .get("reasoning_parameters")
        .filter(|parameters| parameters.is_object())
        .map(|parameters| synthetic_string_list(parameters.get("efforts")))
        .unwrap_or_default();
    let efforts: Vec<EffortLevel> = wire_efforts
        .iter()
        .filter_map(|effort| aiand_effort(effort))
        .collect();
    // A route with at least one representable tier exposes a real
    // reasoning dial; a vocabulary naming only `none`/unrecognized
    // values is the off-switch, never a dial with one stop, and a
    // stated vocabulary overrides the `supported_features` mark rather
    // than resurrecting a dial the wire states none for. Only a wire
    // stating no vocabulary at all leaves `supported_features` as the
    // answer. `tools` lands nowhere — no shared field carries a tool
    // surface, so the feature neither offers one nor implies reasoning.
    let reasoning = if wire_efforts.is_empty() {
        features.contains(&"reasoning")
    } else {
        !efforts.is_empty()
    };
    CatalogModel {
        id: id.to_string(),
        reasoning,
        vision: modalities.contains(&"image"),
        efforts,
        effort_default: None,
        context_window: positive_count(entry.get("context_length")),
        max_output_tokens: Some(
            positive_count(entry.get("max_output_length"))
                .or_else(|| positive_count(entry.get("max_tokens")))
                .unwrap_or(SYNTHETIC_FALLBACK_MAX_TOKENS),
        ),
        price: synthetic_price(entry),
    }
}

/// The recorded `nanogpt` `:thinking` suffix
/// (`NANO_GPT_THINKING_SUFFIX_RE` — `:thinking` with or without a
/// `:<level>` tail, `:<tail>` carrying no further `:`): the base id an
/// alias row collapses into, or `None` when the id is no alias —
/// `:thinking:a:b` fails the recorded tail the same way the regex's
/// single `:[^:]+` group does.
fn nanogpt_thinking_base(id: &str) -> Option<&str> {
    // The recorded regex matches leftmost: the first `:thinking`
    // whose tail is empty or one colon-free `:level` — `exec`'s
    // `match.index` names it. A tail that is neither (`x:thinkingx`)
    // fails there and the scan advances exactly like the regex's.
    for (index, _) in id.match_indices(":thinking") {
        let tail = &id[index + ":thinking".len()..];
        if tail.is_empty() {
            return Some(&id[..index]);
        }
        if let Some(level) = tail.strip_prefix(':')
            && !level.is_empty()
            && !level.contains(':')
        {
            return Some(&id[..index]);
        }
    }
    None
}

/// The recorded `nanogpt` chat-id filter
/// (`isLikelyNanoGptTextModelId`, openai-compat.ts §23): the id is
/// trimmed and lowered, an empty one is dropped, and a
/// `:thinking`-suffixed alias is never an offer — it only marks the
/// base id it collapses into, the mark
/// [`mark_nanogpt_thinking_bases`] applies on the raw listing. The
/// record's `exclude-models` consult carries no vendored roster for
/// this class, so every other non-empty listed id is offered.
fn is_likely_nanogpt_text_id(id: &str) -> bool {
    let normalized = id.trim().to_lowercase();
    if normalized.is_empty() {
        return false;
    }
    nanogpt_thinking_base(&normalized).is_none()
}

/// The recorded `nanogpt` alias collapse (openai-compat.ts §23,
/// `thinkingBaseIds`): a `:thinking` alias row is dropped by the
/// entry filter, and the kept base offer it names is marked
/// reasoning-capable — the record states the mark on the served model
/// alone, so a base the listing omitted stays absent and one already
/// marked keeps its own declaration.
fn mark_nanogpt_thinking_bases(data: &[Value], models: &mut [CatalogModel]) {
    let mut bases = BTreeSet::new();
    for entry in data {
        if let Some(id) = entry.get("id").and_then(Value::as_str)
            && let Some(base) = nanogpt_thinking_base(id)
        {
            bases.insert(base);
        }
    }
    for model in models.iter_mut() {
        if bases.contains(model.id.as_str()) {
            model.reasoning = true;
        }
    }
}

/// The recorded `lm-studio` native base
/// (`toLmStudioNativeBaseUrl`): the configured base trimmed of
/// surrounding whitespace, one trailing `/`, then a trailing `/v1` —
/// the runtime's native API root the probe appends its own
/// `/api/v0/models` path to.
fn lm_studio_native_base(base: &str) -> String {
    let trimmed = base.trim();
    let normalized = trimmed.strip_suffix('/').unwrap_or(trimmed);
    normalized
        .strip_suffix("/v1")
        .unwrap_or(normalized)
        .to_string()
}

/// The recorded `lm-studio` native payload (`/api/v0/models`) keyed by
/// model id: a `vlm` type or a `vision`/`image` capability marks the
/// row image-capable, and the window is the loaded length of a loaded
/// model, else the max, train or model-len length in the recorded
/// order. A row naming no id is skipped; a payload without a `data`
/// array is outside the recorded shape and contributes no mark.
fn lm_studio_native_models(payload: &Value) -> Option<HashMap<String, LmStudioNativeModel>> {
    let entries = payload.get("data")?.as_array()?;
    let mut models = HashMap::new();
    for entry in entries {
        let Some(id) = entry.get("id").and_then(Value::as_str) else {
            continue;
        };
        if id.is_empty() {
            continue;
        }
        let model_type = entry
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_lowercase();
        let vision = model_type == "vlm"
            || entry
                .get("capabilities")
                .and_then(Value::as_array)
                .is_some_and(|capabilities| {
                    capabilities.iter().any(|capability| {
                        capability.as_str().is_some_and(|capability| {
                            matches!(capability.to_lowercase().as_str(), "vision" | "image")
                        })
                    })
                });
        let loaded = if entry.get("state").and_then(Value::as_str) == Some("loaded") {
            positive_count(entry.get("loaded_context_length"))
        } else {
            None
        };
        let context_window = loaded
            .or_else(|| positive_count(entry.get("max_context_length")))
            .or_else(|| positive_count(entry.get("context_length")))
            .or_else(|| positive_count(entry.get("max_model_len")));
        models.insert(
            id.to_string(),
            LmStudioNativeModel {
                vision,
                context_window,
            },
        );
    }
    Some(models)
}

/// The recorded `novita` entry filter (`novitaModelManagerOptions`'s
/// `filterModel`, openai-compat.ts §5.5): the recorded roster is
/// authoritative (`dynamicModelsAuthoritative`), so an entry reaches
/// the offer set only when upstream's whole conjunction holds —
/// `status` is absent, non-numeric or exactly the active `1` (every
/// other numeric status is inactive), the id is not an
/// `ai_infer_test` test SKU, `endpoints` carries `chat/completions`
/// as an array member, and `max_output_tokens` reads positive under
/// the shared token-count read. Dropping a clause would admit rows
/// the recorded source never offers.
fn is_likely_novita_chat_entry(id: &str, entry: &Value) -> bool {
    let active = entry
        .get("status")
        .and_then(Value::as_f64)
        .is_none_or(|status| status == 1.0);
    active
        && !id.to_lowercase().starts_with("ai_infer_test")
        && entry
            .get("endpoints")
            .and_then(Value::as_array)
            .is_some_and(|endpoints| {
                endpoints
                    .iter()
                    .any(|endpoint| endpoint.as_str() == Some("chat/completions"))
            })
        && positive_count(entry.get("max_output_tokens")).is_some()
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
    /// request body over the wire bound — [`ProviderError::IncompatibleOutput`]
    /// as the stream legs document, and
    /// [`ProviderError::UnsupportedParameter`] when the frozen request
    /// pins a parameter the connection's recorded contract rejects for
    /// the pinned model.
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
        // The send leg requires the material a bound scope names; only a
        // declaration binding nothing rides headerless.
        let secret = self.leg_secret(CredentialLeg::Send)?;
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
                    .catalog_within(secret.as_ref(), started)?
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
        // The literal id's recorded wire-model-id dispatch decides
        // the body's `model` — `fireworks` translates the public id
        // into the `accounts/fireworks/…` wire form (routers for the
        // `*-fast` serving path, models otherwise), `firepass` always
        // the routers serving path; every other contract names the id
        // verbatim.
        let wire_model_id = self.wire_model_id(&fixed.model_id);
        // A parameter the literal id's recorded contract rejects for
        // this model is a typed denial before the body exists — never
        // a value silently omitted from the request.
        self.check_parameters(manifest, &fixed.model_id)?;
        let body = self.request_body(manifest, &wire_model_id);
        let body_bytes = wire_body(&self.connection, &body)?;
        // The wire leg is the last budget check: a resolve or
        // catalogue leg that spent the clock fails the send typed
        // here — an expired budget never puts a byte on the wire.
        check_deadline(&self.connection, self.deadline, started)?;
        // The absent-binding form bears no material: the request carries
        // no `Authorization` header at all, never an empty or dummy bearer.
        let request = WireSecret::attach(
            self.client
                .post(format!("{}/chat/completions", self.endpoint))
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .header(reqwest::header::ACCEPT, "text/event-stream")
                .body(body_bytes),
            secret.as_ref(),
        );
        let response = request
            .send()
            .map_err(|err| transport(&self.connection, err))?;
        if !response.status().is_success() {
            return Err(transport_status(&self.connection, response.status()));
        }
        self.read_stream(manifest, response, started)
    }
}
