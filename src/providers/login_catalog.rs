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

/// The catalogue rows, sorted by id for a stable picker.
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
