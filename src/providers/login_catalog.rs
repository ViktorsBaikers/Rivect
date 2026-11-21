//! The sign-in catalogue `/login` serves: one row per provider this build can
//! authenticate against, and the methods each row admits.
//!
//! The catalogue is the single owner of a provider's display name, its
//! connection row (kind, endpoint, profile) and the callback origin a browser
//! leg may listen on. Selecting a row shows every method it names; a browser
//! method without a loopback callback is still selectable, and its redirect
//! must then be pasted by the operator. Nothing here reads a credential or
//! opens a socket.

use crate::config::ConnKind;

/// A loopback callback a browser sign-in may capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Callback {
    /// The literal host the redirect names (`localhost` or `127.0.0.1`).
    pub host: &'static str,
    /// The recorded port; the provider's registered redirect carries it.
    pub port: u16,
    /// The recorded path the browser lands on.
    pub path: &'static str,
}

/// One sign-in method a provider admits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Method {
    /// The wire name `auth.login.begin` accepts as `mode`.
    pub id: &'static str,
    /// The operator-facing label.
    pub label: &'static str,
    /// The loopback callback this method captures; absent when the redirect
    /// uses a private scheme the terminal cannot receive.
    pub callback: Option<Callback>,
}

/// One provider row: everything a login needs before any secret exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Provider {
    /// The connection id, and the wire name the picker sends back.
    pub id: &'static str,
    /// The operator-facing name.
    pub name: &'static str,
    /// The connection kind the profile binding requires.
    pub kind: ConnKind,
    /// The adapter's base endpoint.
    pub endpoint: &'static str,
    /// The credential profile the login writes.
    pub profile: &'static str,
    /// Every sign-in method, in display order.
    pub methods: &'static [Method],
}

const BROWSER_OPENAI: Method = Method {
    id: "browser",
    label: "Browser sign-in",
    callback: Some(Callback {
        host: "localhost",
        port: 1455,
        path: "/auth/callback",
    }),
};
const BROWSER_ANTHROPIC: Method = Method {
    id: "browser",
    label: "Browser sign-in",
    callback: Some(Callback {
        host: "127.0.0.1",
        port: 54545,
        path: "/callback",
    }),
};
const BROWSER_PASTE: Method = Method {
    id: "browser",
    label: "Browser sign-in · paste redirect",
    callback: None,
};
const DEVICE: Method = Method {
    id: "device",
    label: "Device code",
    callback: None,
};
const API_KEY: Method = Method {
    id: "api_key",
    label: "API key",
    callback: None,
};

/// One stored-key row: the connection is declared as an `api_key` scope and
/// the operator's key is the whole credential the adapter sends.
macro_rules! api_key {
    ($id:literal, $name:literal, $endpoint:literal) => {
        Provider {
            id: $id,
            name: $name,
            kind: ConnKind::ApiKey,
            endpoint: $endpoint,
            profile: $id,
            methods: &[API_KEY],
        }
    };
}

/// The catalogue rows: the interactive legs first, then every served
/// stored-key provider this build routes, in display order.
pub const PROVIDERS: &[Provider] = &[
    Provider {
        id: "anthropic",
        name: "Anthropic (Claude)",
        kind: ConnKind::Subscription,
        endpoint: "https://api.anthropic.com",
        profile: "anthropic",
        methods: &[BROWSER_ANTHROPIC],
    },
    Provider {
        id: "github-copilot",
        name: "GitHub Copilot",
        kind: ConnKind::ApiKey,
        endpoint: "https://api.githubcopilot.com",
        profile: "github-copilot",
        methods: &[DEVICE],
    },
    Provider {
        id: "kimi-code",
        name: "Kimi Code",
        kind: ConnKind::ApiKey,
        endpoint: "https://api.kimi.com/coding/v1",
        profile: "kimi-code",
        methods: &[DEVICE],
    },
    Provider {
        id: "openai-codex",
        name: "OpenAI (ChatGPT)",
        kind: ConnKind::ApiKey,
        endpoint: "https://chatgpt.com/backend-api/codex",
        profile: "openai-codex",
        methods: &[BROWSER_OPENAI, DEVICE],
    },
    Provider {
        id: "zai",
        name: "Z.AI Coding Plan",
        kind: ConnKind::ApiKey,
        endpoint: "https://api.z.ai/api/anthropic",
        profile: "zai",
        methods: &[BROWSER_PASTE],
    },
    // Stored-key providers: the connection is the adapter's recorded default
    // base, and the key is the bearer the adapter's credential grammar reads.
    api_key!("aiand", "ai&", "https://api.aiand.com/v1"),
    api_key!("aimlapi", "AIML API", "https://api.aimlapi.com/v1"),
    api_key!(
        "alibaba-coding-plan",
        "Alibaba Coding Plan",
        "https://coding-intl.dashscope.aliyuncs.com/v1"
    ),
    api_key!(
        "alibaba-token-plan",
        "QwenCloud Token Plan",
        "https://token-plan.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1"
    ),
    api_key!("baseten", "Baseten", "https://inference.baseten.co/v1"),
    api_key!("cerebras", "Cerebras", "https://api.cerebras.ai/v1"),
    api_key!("cline-pass", "ClinePass", "https://api.cline.bot/api/v1"),
    api_key!(
        "coreweave",
        "CoreWeave Serverless Inference",
        "https://api.inference.wandb.ai/v1"
    ),
    api_key!(
        "deepinfra",
        "DeepInfra",
        "https://api.deepinfra.com/v1/openai"
    ),
    api_key!("deepseek", "DeepSeek", "https://api.deepseek.com"),
    api_key!(
        "firepass",
        "Fire Pass (Fireworks subscription)",
        "https://api.fireworks.ai/inference/v1"
    ),
    api_key!(
        "fireworks",
        "Fireworks",
        "https://api.fireworks.ai/inference/v1"
    ),
    api_key!("gmi-cloud", "GMI Cloud", "https://api.gmi-serving.com/v1"),
    api_key!("groq", "Groq", "https://api.groq.com/openai/v1"),
    api_key!(
        "huggingface",
        "Hugging Face Inference",
        "https://router.huggingface.co/v1"
    ),
    api_key!("kilo", "Kilo Gateway", "https://api.kilo.ai/api/gateway"),
    api_key!("minimax", "MiniMax", "https://api.minimax.io/anthropic"),
    api_key!(
        "minimax-code",
        "MiniMax Token Plan (International)",
        "https://api.minimax.io/v1"
    ),
    api_key!(
        "minimax-code-cn",
        "MiniMax Token Plan (China)",
        "https://api.minimaxi.com/v1"
    ),
    api_key!("mistral", "Mistral", "https://api.mistral.ai/v1"),
    api_key!(
        "moonshot",
        "Moonshot (Kimi API)",
        "https://api.moonshot.ai/v1"
    ),
    api_key!("nanogpt", "NanoGPT", "https://nano-gpt.com/api/v1"),
    api_key!("novita", "Novita", "https://api.novita.ai/openai/v1"),
    api_key!("nvidia", "NVIDIA", "https://integrate.api.nvidia.com/v1"),
    api_key!("ollama-cloud", "Ollama Cloud", "https://ollama.com"),
    api_key!("openai", "OpenAI", "https://api.openai.com/v1"),
    api_key!(
        "opencode-go",
        "OpenCode Go",
        "https://opencode.ai/zen/go/v1"
    ),
    api_key!("opencode-zen", "OpenCode Zen", "https://opencode.ai/zen/v1"),
    api_key!("openrouter", "OpenRouter", "https://openrouter.ai/api/v1"),
    api_key!("qianfan", "Qianfan", "https://qianfan.baidubce.com/v2"),
    api_key!("qwen-portal", "Qwen Portal", "https://portal.qwen.ai/v1"),
    api_key!("sakana", "Sakana AI", "https://api.sakana.ai/v1"),
    api_key!(
        "siliconflow",
        "SiliconFlow",
        "https://api.siliconflow.com/v1"
    ),
    api_key!(
        "siliconflow-cn",
        "SiliconFlow (China)",
        "https://api.siliconflow.cn/v1"
    ),
    api_key!(
        "synthetic",
        "Synthetic",
        "https://api.synthetic.new/openai/v1"
    ),
    api_key!("together", "Together", "https://api.together.xyz/v1"),
    api_key!("umans", "Umans AI Coding Plan", "https://api.code.umans.ai"),
    api_key!("venice", "Venice", "https://api.venice.ai/api/v1"),
    api_key!(
        "vercel-ai-gateway",
        "Vercel AI Gateway",
        "https://ai-gateway.vercel.sh"
    ),
    api_key!(
        "wafer-serverless",
        "Wafer Serverless (pay-as-you-go)",
        "https://pass.wafer.ai/v1"
    ),
    api_key!("xai", "xAI API", "https://api.x.ai/v1"),
    api_key!("xiaomi", "Xiaomi MiMo", "https://api.xiaomimimo.com/v1"),
    api_key!(
        "xiaomi-token-plan-ams",
        "Xiaomi Token Plan (Europe)",
        "https://token-plan-ams.xiaomimimo.com/v1"
    ),
    api_key!(
        "xiaomi-token-plan-cn",
        "Xiaomi Token Plan (China)",
        "https://token-plan-cn.xiaomimimo.com/v1"
    ),
    api_key!(
        "xiaomi-token-plan-sgp",
        "Xiaomi Token Plan (Singapore)",
        "https://token-plan-sgp.xiaomimimo.com/v1"
    ),
    api_key!("yolo-auto", "Yolo-Auto", "https://yolo-auto.com/v1"),
    api_key!(
        "zhipu-coding-plan",
        "Zhipu Coding Plan (智谱)",
        "https://open.bigmodel.cn/api/coding/paas/v4"
    ),
];

/// The catalogue row for a literal provider id.
#[must_use]
pub fn provider(id: &str) -> Option<&'static Provider> {
    PROVIDERS.iter().find(|row| row.id == id)
}

/// The method a provider names, or `None` when the id is not one of its own.
#[must_use]
pub fn method(provider: &Provider, id: &str) -> Option<&'static Method> {
    provider.methods.iter().find(|method| method.id == id)
}
