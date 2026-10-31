//! The `custom-chat-completions`, `aiand`, `aimlapi`,
//! `alibaba-coding-plan`, `alibaba-token-plan`, `coreweave`,
//! `deepinfra`, `deepseek`, `firepass`, `fireworks`, `gmi-cloud` and
//! `groq` connections' adapter — the OpenAI-compatible Chat Completions dialect
//! (DEC-007/DEC-025, HZN-008 class S, class A and class P).
//! Dialect selection keys on the literal connection id, never an auth
//! label, an endpoint shape or a catalogue answer: every compatible
//! host a deployment wires under `custom-chat-completions` shares the
//! one recorded generic contract, while `aiand`, `aimlapi`,
//! `alibaba-coding-plan`, `alibaba-token-plan`, `coreweave`,
//! `deepinfra`, `deepseek`, `firepass`, `fireworks`, `gmi-cloud` and
//! `groq` carry their own recorded predicates — the
//! `/v1` base normalization and the org-scoped catalogue transform
//! on `aiand`, the default-host endpoint rule and the chat-id
//! catalogue filter on `aimlapi`, the region-choice endpoint, the
//! static allowed-model catalogue and the enrolled-base credential
//! binding on `alibaba-coding-plan`, the region-choice endpoint,
//! the region-bound authoritative `/models` catalogue with its
//! chat-id prefix filter and the enrolled-base credential binding —
//! the optional quota `cookie` member admitted for shape and dropped —
//! on `alibaba-token-plan`, the configured-or-default host, the
//! authoritative `/models` listing and the scoped bearer credential —
//! the `OpenAI-Project` member required before any leg — on
//! `coreweave`, the configured-or-default host, the
//! authoritative chat-model `/models` listing — the public metadata
//! catalogue never an authentication surface — and the plain bearer
//! credential on `deepinfra`, the configured-or-default host,
//! the authoritative `/models` listing gated by the recorded
//! built-in roster — built-in ids offered, benchmark ids never —
//! the plain bearer credential and the recorded native reasoning
//! rules on `deepseek`, the shared `api.fireworks.ai/inference/v1`
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
//! plain bearer credential on `groq` — resolved per literal id by the
//! contract table, never inherited across ids. The adapter authors no
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
use crate::policy::canonical_egress_target;
use crate::providers::sse::{SseEvent, SseParser};
use crate::providers::{
    CredentialStore, Dialect, Provider, ProviderError, ProviderReply, STREAM_CHUNK_BYTES,
    SecretRef, ToolCall, bounded_reason, check_deadline, dialect_for, payload_reason,
    read_catalog_body, read_chunk, resolve_credential, sse, transport, transport_status, violation,
    wire_body,
};
use crate::resources::UsageDelta;
use serde_json::{Value, json};
use std::collections::HashMap;
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
/// request (`OpenAI-Project`, wire/coreweave.ts): the recorded
/// `<team>/<project>` member of the scoped credential — spend lands
/// against that project, and a request without it is denied upstream
/// the same way the recorded pre-validation check denies an unset
/// `COREWEAVE_PROJECT` before any fetch.
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
    /// The plan providers' shared base resolution
    /// (`alibaba-coding-plan`, `alibaba-token-plan`): the configured
    /// origin verbatim under the recorded ingress normalization —
    /// trimmed, all trailing slashes stripped, as the login hook's
    /// custom-origin input is normalized — with the required field's
    /// empty string standing for the absent override: the carried
    /// recorded international endpoint. The region choice —
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
    /// The recorded fixed allowed-model list alone — the class
    /// records no dynamic `/models` discovery, so the lookup opens
    /// no wire leg and resolves no credential. Each tuple is the
    /// model id and its bundled-descriptor vision mark. An auto pick
    /// resolves the sorted-first id — the adapter's one uniform auto
    /// semantic; a descriptor's recorded `defaultModel` is a
    /// catalogue hint, not a product ranking this contract performs.
    Allowlist(&'static [(&'static str, bool)]),
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
    /// `coreweave`'s recorded scoped credential (`Rivect/key +
    /// OpenAI-Project`, wire/coreweave.ts): a JSON object whose `key`
    /// is the bearer and whose `OpenAI-Project` is the
    /// `<team>/<project>` scope every request must carry — the
    /// recorded surface resolves the scope before any fetch and
    /// fails closed without it, so material lacking the member — a
    /// bare key, a key-only blob, an empty scope — is unscoped
    /// material that denies before any wire leg.
    CoreWeave,
}

/// The recorded per-entry transform a `data[]` listing runs
/// (HZN-008): the generic class carries model ids only,
/// `aiand`'s org-scoped listing applies the recorded
/// capability/effort/currency map (`mapAiandModel`), and `aimlapi`'s
/// applies the recorded chat-id filter to a defaults-only surface.
enum EntryRule {
    /// Every non-empty `id` verbatim — the generic class records no
    /// per-model metadata surface.
    IdsOnly,
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
        // surface — and the scoped `key`/`OpenAI-Project` credential:
        // unscoped material denies before any leg.
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
        _ => None,
    }
}

impl SourceContract {
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
                // international endpoint.
                let trimmed = configured.trim();
                if trimmed.is_empty() {
                    return default.to_string();
                }
                trimmed.trim_end_matches('/').to_string()
            }
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
/// token, plus the `OpenAI-Project` scope the `coreweave` arm requires
/// on every leg. Never rendered: both members are secret-store
/// material.
struct WireSecret {
    /// The `Authorization: Bearer` token.
    bearer: String,
    /// The `OpenAI-Project` header value — `Some` only under
    /// [`CredentialRule::CoreWeave`], where the grammar demands it.
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
    /// declared, carry no configured region — no recorded class
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
    /// returns in deterministic sorted order. A class whose recorded
    /// catalogue is a fixed allowlist answers it alone: no listing
    /// leg exists, so no credential is resolved and no byte crosses
    /// the wire. The generic class
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
        let secret = self.secret()?;
        self.catalog_within(&secret, started)
    }

    /// The catalogue leg under the caller's clock and credential —
    /// a send passes its own `started` so the lookup spends the same
    /// whole-request budget instead of opening a second, unaccounted
    /// one.
    fn catalog_within(
        &self,
        secret: &WireSecret,
        started: Instant,
    ) -> Result<Vec<CatalogModel>, ProviderError> {
        check_deadline(&self.connection, self.deadline, started)?;
        // The recorded allowlist answers in place — a send's
        // auto-pick never opens a `/models` leg.
        if let CatalogRule::Allowlist(list) = self.contract.catalog {
            return Ok(allowlist_models(list));
        }
        let mut request = self
            .client
            .get(format!("{}/models", self.endpoint))
            .bearer_auth(&secret.bearer);
        if let Some(project) = &secret.project {
            request = request.header(OPENAI_PROJECT_HEADER, project);
        }
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
        // Every listed `id` is an offer under the literal id's
        // recorded per-entry transform — an empty or absent one can
        // never name a model.
        let mut models: Vec<CatalogModel> = data
            .iter()
            .filter_map(|entry| self.catalog_entry(entry))
            .collect();
        // The recorded seed unions on top as the offer floor — a
        // seeded id the listing omitted still offers, carrying the
        // id-only surface a generic seed states. `deepseek`'s seed is
        // the built-in roster itself, so its stubs carry the same
        // recorded transform surface the listing arm lands. Listed
        // entries precede the stubs, so the stable sort keeps a
        // listing entry's transform over its seed stub on a
        // collision.
        models.extend(
            self.contract
                .seed
                .iter()
                .filter_map(|id| match self.contract.entries {
                    EntryRule::DeepSeek => deepseek_entry(id),
                    EntryRule::Fireworks => fireworks_entry(id),
                    EntryRule::Groq => Some(groq_entry(id)),
                    EntryRule::IdsOnly
                    | EntryRule::Aiand
                    | EntryRule::Aimlapi
                    | EntryRule::AlibabaTokenPlan
                    | EntryRule::Firepass => Some(CatalogModel {
                        id: (*id).to_string(),
                        ..CatalogModel::default()
                    }),
                }),
        );
        models.sort_by(|a, b| a.id.cmp(&b.id));
        models.dedup_by(|a, b| a.id == b.id);
        Ok(models)
    }

    /// One `data[]` entry under the literal id's recorded transform —
    /// `None` when the entry names no usable id: an empty or absent
    /// id can never name a model, and an `aimlapi` id the recorded
    /// `exclude-models` roster names is filtered before offer.
    fn catalog_entry(&self, entry: &Value) -> Option<CatalogModel> {
        let id = entry
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())?;
        match self.contract.entries {
            EntryRule::IdsOnly => Some(CatalogModel {
                id: id.to_string(),
                ..CatalogModel::default()
            }),
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
            // Unreached: this class binds the static allowlist, so no
            // listing leg runs. A listed id would prove no access the
            // class records, so the transform admits nothing.
            EntryRule::Firepass => None,
        }
    }

    /// Reads the credential material for this send — the only place
    /// secret bytes cross the store boundary — and answers the wire
    /// material the literal id's recorded credential grammar binds. A
    /// non-UTF-8 secret cannot be a bearer token: typed denial, never
    /// a mangled header. Every grammar, scope or base denial lands
    /// here — before any wire leg.
    fn secret(&self) -> Result<WireSecret, ProviderError> {
        let material = self.store.resolve(&self.credential)?;
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
            CredentialRule::Firepass => self.firepass_bearer(&text).map(WireSecret::bearer),
        }
    }

    /// The bearer and `OpenAI-Project` scope a `coreweave` credential
    /// resolves (`Rivect/key + OpenAI-Project`, wire/coreweave.ts):
    /// the stored material is a JSON object whose `key` is the bearer
    /// and whose `OpenAI-Project` is the `<team>/<project>` scope the
    /// header carries — the recorded surface resolves the scope
    /// before any fetch and fails closed without it, so a bare key,
    /// a key-only blob or an empty member is unscoped material and
    /// denies as malformed before any wire leg. Anything the
    /// recorded shape does not name — a non-string member, a
    /// non-object body — is material the recorded credential never
    /// produces and denies the same way.
    fn coreweave_secret(&self, material: &str) -> Result<WireSecret, ProviderError> {
        let malformed = || ProviderError::CredentialMalformed {
            connection: self.connection.clone(),
        };
        let parsed: Value = serde_json::from_str(material.trim()).map_err(|_parse| malformed())?;
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

    /// The bearer a `firepass` credential resolves (`auth/firepass.kdl`):
    /// the recorded pass key is the dedicated `fpk_…` class, prefix
    /// plus a non-empty body. The key is bound to this connection's
    /// own enrollment, so material outside the grammar — notably a
    /// Fireworks account key for the shared `api.fireworks.ai` host —
    /// denies as malformed before any wire leg, never as a bearer the
    /// pass product would bill differently. Every denial is typed and
    /// lands before any leg.
    fn firepass_bearer(&self, material: &str) -> Result<String, ProviderError> {
        let token = material.trim();
        token
            .strip_prefix(FIREPASS_KEY_PREFIX)
            .filter(|body| !body.is_empty())
            .ok_or_else(|| ProviderError::CredentialMalformed {
                connection: self.connection.clone(),
            })?;
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
    /// transform — `IdsOnly`, `Aiand`, `Aimlapi`, `AlibabaTokenPlan`,
    /// `DeepSeek` and `Groq` — sends the offered id unchanged. Each
    /// variant is listed so a future transform cannot ship verbatim
    /// ids silently.
    fn wire_model_id(&self, model_id: &str) -> String {
        match self.contract.entries {
            EntryRule::Firepass => firepass_wire_model_id(model_id),
            EntryRule::Fireworks => fireworks_wire_model_id(model_id),
            EntryRule::IdsOnly
            | EntryRule::Aiand
            | EntryRule::Aimlapi
            | EntryRule::AlibabaTokenPlan
            | EntryRule::DeepSeek
            | EntryRule::Groq => model_id.to_string(),
        }
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

    /// The recorded parameter predicate (HZN-008 `groq` row): a pinned
    /// `reasoning_effort` rides the body only where the pin's model
    /// records that level — every other level, and every model with no
    /// recorded effort surface, is a parameter this class rejects. The
    /// denial is typed and lands before the request body exists: a
    /// fixed pin denies before any wire leg, while an auto pin — whose
    /// model the non-authoritative listing resolved first — denies
    /// before the chat request leg. The value is never dropped from the
    /// body behind the caller's back. The class's other recorded-rejected
    /// parameters (logprobs, logit_bias, top_logprobs, `messages[].name`,
    /// `n`, temperature) are never constructed by this adapter, so none
    /// can be dropped.
    fn check_parameters(
        &self,
        manifest: &RequestManifest,
        model_id: &str,
    ) -> Result<(), ProviderError> {
        if !matches!(self.contract.entries, EntryRule::Groq) {
            return Ok(());
        }
        let EffortAssign::Fixed { value } = &manifest.effort else {
            return Ok(());
        };
        let recorded = GROQ_EFFORTS
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

/// The recorded `fireworks` public id
/// (`toFireworksPublicModelId`): the `accounts/fireworks/models/`
/// wire prefix stripped, then the `p` version separator between
/// digits folded back to `.` (`kimi-k2p7-code` → `kimi-k2.7-code`).
fn fireworks_public_id(id: &str) -> String {
    let stripped = id.strip_prefix(FIREWORKS_WIRE_PREFIX).unwrap_or(id);
    let chars: Vec<char> = stripped.chars().collect();
    let mut public = String::with_capacity(stripped.len());
    for (at, &ch) in chars.iter().enumerate() {
        if ch == 'p'
            && at > 0
            && chars[at - 1].is_ascii_digit()
            && chars.get(at + 1).is_some_and(char::is_ascii_digit)
        {
            public.push('.');
        } else {
            public.push(ch);
        }
    }
    public
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
    let chars: Vec<char> = stripped.chars().collect();
    let mut wire = String::with_capacity(stripped.len());
    for (at, &ch) in chars.iter().enumerate() {
        if ch == '.'
            && at > 0
            && chars[at - 1].is_ascii_digit()
            && chars.get(at + 1).is_some_and(char::is_ascii_digit)
        {
            wire.push('p');
        } else {
            wire.push(ch);
        }
    }
    wire
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
        let secret = self.secret()?;
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
                    .catalog_within(&secret, started)?
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
        let mut request = self
            .client
            .post(format!("{}/chat/completions", self.endpoint))
            .bearer_auth(&secret.bearer)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::ACCEPT, "text/event-stream")
            .body(body_bytes);
        if let Some(project) = &secret.project {
            request = request.header(OPENAI_PROJECT_HEADER, project);
        }
        let response = request
            .send()
            .map_err(|err| transport(&self.connection, err))?;
        if !response.status().is_success() {
            return Err(transport_status(&self.connection, response.status()));
        }
        self.read_stream(manifest, response, started)
    }
}
