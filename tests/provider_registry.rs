//! The recorded dialect roster (AC-011): every literal id `dialect_for`
//! answers, pinned exactly. The roster is the 68 pre-band ids plus the
//! admitted vertex and two CloudCode arms, and only a recorded id may add
//! to it.

#![allow(
    clippy::expect_used,
    reason = "test code keeps expect conveniences; src/ stays strict (standards §14)"
)]

use rivect::providers::{Dialect, dialect_for};

#[test]
fn bedrock_ids_map_to_their_recorded_dialects() {
    assert_eq!(dialect_for("amazon-bedrock"), Some(Dialect::Converse));
    assert_eq!(dialect_for("bedrock-mantle"), Some(Dialect::Responses));
    for id in [
        "bedrock",
        "bedrock-converse",
        "mantle",
        "bedrock-runtime",
        "bedrock-anthropic",
        "google-vertex-anthropic",
        "microsoft-foundry",
    ] {
        assert_eq!(dialect_for(id), None, "{id}");
    }
}

/// The exact current roster `dialect_for` answers, in source order.
const RECORDED_ROSTER: [(&str, Dialect); 71] = [
    ("openai", Dialect::Responses),
    ("abliteration", Dialect::Responses),
    ("meta", Dialect::Responses),
    ("ollama", Dialect::Responses),
    ("custom-responses", Dialect::Responses),
    ("openrouter", Dialect::Responses),
    ("sakana", Dialect::Responses),
    ("xai", Dialect::Responses),
    ("xai-oauth", Dialect::Responses),
    ("openai-codex", Dialect::Responses),
    ("openai-codex-device", Dialect::Responses),
    ("amazon-bedrock", Dialect::Converse),
    ("bedrock-mantle", Dialect::Responses),
    ("cursor", Dialect::CursorAgent),
    ("devin", Dialect::DevinAgent),
    ("gitlab-duo-agent", Dialect::GitlabWorkflow),
    ("ollama-cloud", Dialect::OllamaChat),
    ("google", Dialect::Gemini),
    ("google-vertex", Dialect::Vertex),
    ("google-antigravity", Dialect::CloudCode),
    ("google-gemini-cli", Dialect::CloudCode),
    ("anthropic", Dialect::Messages),
    ("minimax", Dialect::Messages),
    ("umans", Dialect::Messages),
    ("cloudflare-ai-gateway", Dialect::Messages),
    ("custom-messages", Dialect::Messages),
    ("vercel-ai-gateway", Dialect::Messages),
    ("gitlab-duo", Dialect::ChatCompletions),
    ("github-copilot", Dialect::ChatCompletions),
    ("opencode-go", Dialect::ChatCompletions),
    ("opencode-zen", Dialect::ChatCompletions),
    ("custom-chat-completions", Dialect::ChatCompletions),
    ("aiand", Dialect::ChatCompletions),
    ("aimlapi", Dialect::ChatCompletions),
    ("alibaba-coding-plan", Dialect::ChatCompletions),
    ("alibaba-token-plan", Dialect::ChatCompletions),
    ("coreweave", Dialect::ChatCompletions),
    ("deepinfra", Dialect::ChatCompletions),
    ("deepseek", Dialect::ChatCompletions),
    ("firepass", Dialect::ChatCompletions),
    ("fireworks", Dialect::ChatCompletions),
    ("gmi-cloud", Dialect::ChatCompletions),
    ("groq", Dialect::ChatCompletions),
    ("huggingface", Dialect::ChatCompletions),
    ("kilo", Dialect::ChatCompletions),
    ("litellm", Dialect::ChatCompletions),
    ("llama.cpp", Dialect::ChatCompletions),
    ("lm-studio", Dialect::ChatCompletions),
    ("minimax-code", Dialect::ChatCompletions),
    ("minimax-code-cn", Dialect::ChatCompletions),
    ("mistral", Dialect::ChatCompletions),
    ("moonshot", Dialect::ChatCompletions),
    ("nanogpt", Dialect::ChatCompletions),
    ("novita", Dialect::ChatCompletions),
    ("nvidia", Dialect::ChatCompletions),
    ("qianfan", Dialect::ChatCompletions),
    ("qwen-portal", Dialect::ChatCompletions),
    ("siliconflow", Dialect::ChatCompletions),
    ("siliconflow-cn", Dialect::ChatCompletions),
    ("synthetic", Dialect::ChatCompletions),
    ("together", Dialect::ChatCompletions),
    ("venice", Dialect::ChatCompletions),
    ("vllm", Dialect::ChatCompletions),
    ("wafer-serverless", Dialect::ChatCompletions),
    ("xiaomi", Dialect::ChatCompletions),
    ("xiaomi-token-plan-ams", Dialect::ChatCompletions),
    ("xiaomi-token-plan-cn", Dialect::ChatCompletions),
    ("xiaomi-token-plan-sgp", Dialect::ChatCompletions),
    ("yolo-auto", Dialect::ChatCompletions),
    ("zenmux", Dialect::ChatCompletions),
    ("zhipu-coding-plan", Dialect::ChatCompletions),
];

#[test]
fn roster_matches_the_recorded_dialect_arms() {
    assert_eq!(
        RECORDED_ROSTER.len(),
        71,
        "the roster is the 68 pre-band ids plus the vertex and two CloudCode arms"
    );
    let mut ids: Vec<&str> = RECORDED_ROSTER.iter().map(|(id, _)| *id).collect();
    let recorded = ids.len();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(
        ids.len(),
        recorded,
        "a duplicated roster row cannot mask a missing one"
    );
    for (id, dialect) in RECORDED_ROSTER {
        assert_eq!(dialect_for(id), Some(dialect), "{id}");
    }
    assert_eq!(
        dialect_for("not-a-recorded-id"),
        None,
        "an id outside the roster has no recorded dialect"
    );
    assert_eq!(
        dialect_for("google-gemini-cli"),
        Some(Dialect::CloudCode),
        "the second CloudCode id reuses the one recorded variant"
    );
    assert_eq!(Dialect::CloudCode.to_string(), "cloudcode");
}
