//! Typed tool surface: the `read_file` tool routed through executor
//! admission, the journaled `config.set`/`config.unset` carrier commands,
//! and the one canonical command catalog the page, the help text, the
//! completion scripts and the dispatcher all read. A row this build cannot
//! serve carries its exact typed reason; an alias resolves here, not only in
//! the listing.

use crate::commands::Runtime;
use crate::contracts::{CommandDescriptor, Page, TaskId};
use crate::executor::{EffectOutcome, EffectRequest, ExecutorError};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalKind {
    ConfigSet,
    ConfigUnset,
    ConfigList,
    ConfigSearch,
    ConfigGet,
    ConfigExplain,
    ConfigValidate,
    ConfigExport,
    DecisionsControl,
    ProjectInit,
    ReadFile,
    SessionNew,
    SessionList,
    SessionSearch,
    SessionFork,
    SessionExport,
    SessionRecap,
    SettingsOpen,
    ViewClear,
    ContextCompact,
    ContextView,
    CheckpointPreview,
    CheckpointApply,
    PermissionsView,
    ModelView,
    EffortView,
    UsageView,
    WorkflowControl,
    HarnessControl,
    McpCall,
    DocsStatus,
    PlannedUnimplemented,
    Unknown,
}

const BUSY_READ: &str = "READ";
const BUSY_WRITE: &str = "WRITE";
const BUSY_READ_CONFIG: &str = "READ/CONFIG";
const BUSY_READ_INDEX: &str = "READ/INDEX";
const BUSY_EGRESS: &str = "EGRESS";

/// How one catalog row is invoked. The carrier is the row's contract: a
/// caller reaches the row exactly this way and no surface advertises a row
/// its carrier cannot serve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Carrier {
    /// `command.execute` under this row's kind, or an alias of it.
    Local,
    /// One existing JSON-RPC method, which the dispatcher already serves.
    Rpc(&'static str),
    /// The executable's own grammar.
    Cli(&'static str),
}

/// One row of the canonical command catalog. A row this build serves carries
/// no reason; an unbuilt row carries its exact typed one.
#[derive(Debug, Clone, Copy)]
pub struct CatalogRow {
    pub canonical_id: &'static str,
    pub aliases: &'static [&'static str],
    pub description: &'static str,
    pub busy_policy: &'static str,
    pub carrier: Carrier,
    pub unavailable: Option<&'static str>,
}

impl CatalogRow {
    #[must_use]
    pub fn available(&self) -> bool {
        self.unavailable.is_none()
    }
}

/// The 36 canonical rows, in their published order. This table is the one
/// source the page, the help text, the completion scripts and the alias map
/// are built from.
pub const CATALOG: &[CatalogRow] = &[
    CatalogRow {
        canonical_id: "session.new",
        aliases: &["new", "clear"],
        description: "start an independent conversation on this connection; the previous session stays resumable",
        busy_policy: BUSY_WRITE,
        carrier: Carrier::Local,
        unavailable: None,
    },
    CatalogRow {
        canonical_id: "settings.open",
        aliases: &["settings", "config"],
        description: "open the settings surface: the served config entries with their sources",
        busy_policy: BUSY_READ_CONFIG,
        carrier: Carrier::Local,
        unavailable: None,
    },
    CatalogRow {
        canonical_id: "session.list",
        aliases: &["sessions"],
        description: "list the sessions this data root recorded, newest first",
        busy_policy: BUSY_READ,
        carrier: Carrier::Local,
        unavailable: None,
    },
    CatalogRow {
        canonical_id: "session.search",
        aliases: &[],
        description: "search sessions by a substring of their recorded goals",
        busy_policy: BUSY_READ,
        carrier: Carrier::Local,
        unavailable: None,
    },
    CatalogRow {
        canonical_id: "session.resume",
        aliases: &[],
        description: "resume an existing session by attaching a fresh attachment to it",
        busy_policy: BUSY_WRITE,
        carrier: Carrier::Rpc("session.attach"),
        unavailable: None,
    },
    CatalogRow {
        canonical_id: "session.fork",
        aliases: &[],
        description: "start a new session carrying the same goals with fresh progress",
        busy_policy: BUSY_WRITE,
        carrier: Carrier::Local,
        unavailable: None,
    },
    CatalogRow {
        canonical_id: "session.export",
        aliases: &[],
        description: "export one session's recorded events as a bounded page",
        busy_policy: BUSY_READ,
        carrier: Carrier::Local,
        unavailable: None,
    },
    CatalogRow {
        canonical_id: "context.compact",
        aliases: &[],
        description: "fold one task's episodic history into its continuation checkpoint",
        busy_policy: BUSY_WRITE,
        carrier: Carrier::Local,
        unavailable: None,
    },
    CatalogRow {
        canonical_id: "session.recap",
        aliases: &[],
        description: "summarize one session's durable state: tasks, lifecycles and spend",
        busy_policy: BUSY_READ,
        carrier: Carrier::Local,
        unavailable: None,
    },
    CatalogRow {
        canonical_id: "checkpoint.preview",
        aliases: &[],
        description: "read the continuation checkpoint a fold would replace and the bytes it would shrink",
        busy_policy: BUSY_READ,
        carrier: Carrier::Local,
        unavailable: None,
    },
    CatalogRow {
        canonical_id: "checkpoint.apply",
        aliases: &[],
        description: "fold one task's history into its continuation checkpoint now",
        busy_policy: BUSY_WRITE,
        carrier: Carrier::Local,
        unavailable: None,
    },
    CatalogRow {
        canonical_id: "permissions.view",
        aliases: &[],
        description: "report the admission mode, the scoped grant and the decision mode",
        busy_policy: BUSY_READ_CONFIG,
        carrier: Carrier::Local,
        unavailable: None,
    },
    CatalogRow {
        canonical_id: "model.view",
        aliases: &[],
        description: "report the model each configured purpose resolves to",
        busy_policy: BUSY_READ_CONFIG,
        carrier: Carrier::Local,
        unavailable: None,
    },
    CatalogRow {
        canonical_id: "effort.view",
        aliases: &[],
        description: "report the effort each configured purpose resolves to",
        busy_policy: BUSY_READ_CONFIG,
        carrier: Carrier::Local,
        unavailable: None,
    },
    CatalogRow {
        canonical_id: "runtime.status",
        aliases: &[],
        description: "report the runtime, task, todo, scheduler and update projections",
        busy_policy: BUSY_READ,
        carrier: Carrier::Rpc("runtime.status"),
        unavailable: None,
    },
    CatalogRow {
        canonical_id: "context.view",
        aliases: &[],
        description: "report the assembled context's component sizes for one task",
        busy_policy: BUSY_READ,
        carrier: Carrier::Local,
        unavailable: None,
    },
    CatalogRow {
        canonical_id: "usage.view",
        aliases: &[],
        description: "report the settled usage totals and the latest settlement",
        busy_policy: BUSY_READ,
        carrier: Carrier::Local,
        unavailable: None,
    },
    CatalogRow {
        canonical_id: "command.help",
        aliases: &[],
        description: "serve this catalog page",
        busy_policy: BUSY_READ,
        carrier: Carrier::Rpc("command.describe"),
        unavailable: None,
    },
    CatalogRow {
        canonical_id: "task.cancel",
        aliases: &[],
        description: "cancel one task through task.submit's cancel op",
        busy_policy: BUSY_WRITE,
        carrier: Carrier::Rpc("task.submit"),
        unavailable: None,
    },
    CatalogRow {
        canonical_id: "session.exit",
        aliases: &[],
        description: "close the session attachment",
        busy_policy: BUSY_WRITE,
        carrier: Carrier::Rpc("session.close"),
        unavailable: None,
    },
    CatalogRow {
        canonical_id: "workflow.control",
        aliases: &[],
        description: "inspect or switch the workflow gate through the journaled config publication",
        busy_policy: BUSY_READ_CONFIG,
        carrier: Carrier::Local,
        unavailable: None,
    },
    CatalogRow {
        canonical_id: "harness.control",
        aliases: &[],
        description: "report the background machinery: scheduler slots and the project index generation",
        busy_policy: BUSY_READ_CONFIG,
        carrier: Carrier::Local,
        unavailable: None,
    },
    CatalogRow {
        canonical_id: "decisions.control",
        aliases: &["decisions"],
        description: "inspect or switch the decision mode (ask, auto, inherit)",
        busy_policy: BUSY_READ_CONFIG,
        carrier: Carrier::Local,
        unavailable: None,
    },
    CatalogRow {
        canonical_id: "docs.status",
        aliases: &["docs"],
        description: "report the installed documentation owner's status",
        busy_policy: BUSY_READ,
        carrier: Carrier::Local,
        unavailable: None,
    },
    CatalogRow {
        canonical_id: "view.clear",
        aliases: &[],
        description: "clear the transcript and streamed output; the stored conversation is kept",
        busy_policy: BUSY_READ,
        carrier: Carrier::Local,
        unavailable: None,
    },
    CatalogRow {
        canonical_id: "config.list",
        aliases: &[],
        description: "list every declared config key with its effective value",
        busy_policy: BUSY_READ_CONFIG,
        carrier: Carrier::Local,
        unavailable: None,
    },
    CatalogRow {
        canonical_id: "config.search",
        aliases: &[],
        description: "list the declared config keys whose name or sample matches a query",
        busy_policy: BUSY_READ_CONFIG,
        carrier: Carrier::Local,
        unavailable: None,
    },
    CatalogRow {
        canonical_id: "config.get",
        aliases: &[],
        description: "serve one declared config key's effective value and source",
        busy_policy: BUSY_READ_CONFIG,
        carrier: Carrier::Local,
        unavailable: None,
    },
    CatalogRow {
        canonical_id: "config.explain",
        aliases: &[],
        description: "serve one config key's entry, effective value and sources digest",
        busy_policy: BUSY_READ_CONFIG,
        carrier: Carrier::Local,
        unavailable: None,
    },
    CatalogRow {
        canonical_id: "config.set",
        aliases: &[],
        description: "set one config key through the shared schema and journaled publication",
        busy_policy: BUSY_WRITE,
        carrier: Carrier::Local,
        unavailable: None,
    },
    CatalogRow {
        canonical_id: "config.unset",
        aliases: &[],
        description: "remove one config override through the shared schema and journaled publication",
        busy_policy: BUSY_WRITE,
        carrier: Carrier::Local,
        unavailable: None,
    },
    CatalogRow {
        canonical_id: "config.validate",
        aliases: &[],
        description: "validate the config file on disk through the shared schema",
        busy_policy: BUSY_READ_CONFIG,
        carrier: Carrier::Local,
        unavailable: None,
    },
    CatalogRow {
        canonical_id: "config.export",
        aliases: &[],
        description: "export the effective config: entries, sources digest and base version",
        busy_policy: BUSY_READ_CONFIG,
        carrier: Carrier::Local,
        unavailable: None,
    },
    CatalogRow {
        canonical_id: "project.init",
        aliases: &[],
        description: "build or repair the project index generation for the pinned project root",
        busy_policy: BUSY_READ_INDEX,
        carrier: Carrier::Local,
        unavailable: None,
    },
    CatalogRow {
        canonical_id: "doctor",
        aliases: &[],
        description: "report the data root's health without opening the runtime",
        busy_policy: BUSY_READ,
        carrier: Carrier::Cli("rivect doctor [--project PATH]"),
        unavailable: None,
    },
    CatalogRow {
        canonical_id: "ui.render",
        aliases: &[],
        description: "paint the terminal surface in fullscreen or inline mode",
        busy_policy: BUSY_READ,
        carrier: Carrier::Cli("rivect --tui fullscreen|inline"),
        unavailable: None,
    },
];

/// The tool carriers the page publishes beside the command catalog. A tool is
/// not a command row — it has no dispatcher kind to alias — but the same page
/// serves it, so no surface has to re-spell it.
const TOOL_ROWS: &[CatalogRow] = &[
    CatalogRow {
        canonical_id: "read_file",
        aliases: &["read"],
        description: "one admitted file read in the current scope",
        busy_policy: BUSY_READ,
        carrier: Carrier::Local,
        unavailable: None,
    },
    CatalogRow {
        canonical_id: "mcp.call",
        aliases: &[],
        description: "one admitted tools/call against a declared MCP server",
        busy_policy: BUSY_EGRESS,
        carrier: Carrier::Local,
        unavailable: None,
    },
];

/// One shell whose completion script the catalog renders.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shell {
    Bash,
    Zsh,
    Fish,
}

impl Shell {
    /// The shell one word names; `None` for anything else.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "bash" => Some(Self::Bash),
            "zsh" => Some(Self::Zsh),
            "fish" => Some(Self::Fish),
            _ => None,
        }
    }

    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Self::Bash => "bash",
            Self::Zsh => "zsh",
            Self::Fish => "fish",
        }
    }
}

/// The catalog row a kind spells, canonical or alias. The alias resolves
/// here, once, so every caller — the dispatcher, the page, the help text —
/// reads one map.
#[must_use]
pub fn catalog_row(kind: &str) -> Option<&'static CatalogRow> {
    CATALOG
        .iter()
        .chain(TOOL_ROWS)
        .find(|row| row.canonical_id == kind || row.aliases.contains(&kind))
}

/// The rows the catalog carries without a handler, derived from [`CATALOG`]
/// rather than stored beside it: promoting a row removes it here in the same
/// edit that gives it a handler.
#[must_use]
pub fn unavailable_rows() -> Vec<&'static CatalogRow> {
    CATALOG.iter().filter(|row| !row.available()).collect()
}

/// Why `command.execute` cannot run `kind`, when the catalog side says so: an
/// unbuilt row names its exact reason, and a row served by another carrier
/// names that entry instead of pretending the dispatcher refused an unknown
/// kind.
#[must_use]
pub fn local_refusal(kind: &str) -> Option<String> {
    let row = catalog_row(kind)?;
    if let Some(reason) = row.unavailable {
        return Some(reason.to_string());
    }
    match row.carrier {
        Carrier::Local => None,
        Carrier::Rpc(method) => Some(format!("this row is served by the {method} method")),
        Carrier::Cli(command) => Some(format!("this row is served by `{command}`")),
    }
}

/// The handler one canonical local row reaches. Aliases never appear here:
/// [`catalog_row`] resolves them to the row first, so the dispatcher's alias
/// map cannot drift from the page it advertises.
fn handler_kind(canonical_id: &str) -> LocalKind {
    match canonical_id {
        "session.new" => LocalKind::SessionNew,
        "settings.open" => LocalKind::SettingsOpen,
        "session.list" => LocalKind::SessionList,
        "session.search" => LocalKind::SessionSearch,
        "session.fork" => LocalKind::SessionFork,
        "session.export" => LocalKind::SessionExport,
        "session.recap" => LocalKind::SessionRecap,
        "context.compact" => LocalKind::ContextCompact,
        "checkpoint.preview" => LocalKind::CheckpointPreview,
        "checkpoint.apply" => LocalKind::CheckpointApply,
        "permissions.view" => LocalKind::PermissionsView,
        "model.view" => LocalKind::ModelView,
        "effort.view" => LocalKind::EffortView,
        "context.view" => LocalKind::ContextView,
        "usage.view" => LocalKind::UsageView,
        "workflow.control" => LocalKind::WorkflowControl,
        "harness.control" => LocalKind::HarnessControl,
        "decisions.control" => LocalKind::DecisionsControl,
        "view.clear" => LocalKind::ViewClear,
        "config.list" => LocalKind::ConfigList,
        "config.search" => LocalKind::ConfigSearch,
        "config.get" => LocalKind::ConfigGet,
        "config.explain" => LocalKind::ConfigExplain,
        "config.set" => LocalKind::ConfigSet,
        "config.unset" => LocalKind::ConfigUnset,
        "config.validate" => LocalKind::ConfigValidate,
        "config.export" => LocalKind::ConfigExport,
        "project.init" => LocalKind::ProjectInit,
        "read_file" => LocalKind::ReadFile,
        "mcp.call" => LocalKind::McpCall,
        "docs.status" => LocalKind::DocsStatus,
        _ => LocalKind::Unknown,
    }
}

/// The kind one word dispatches to, resolved through the catalog: an alias
/// reaches its row's handler, an unbuilt row is typed-unavailable, and a row
/// another carrier serves is typed-unavailable too — [`local_refusal`] then
/// names the carrier instead of the dispatcher claiming it never heard of a
/// row the page advertises.
pub fn local_command_kind(kind: &str) -> LocalKind {
    let Some(row) = catalog_row(kind) else {
        return LocalKind::Unknown;
    };
    if !row.available() {
        return LocalKind::PlannedUnimplemented;
    }
    match row.carrier {
        Carrier::Local => handler_kind(row.canonical_id),
        Carrier::Rpc(_) | Carrier::Cli(_) => LocalKind::PlannedUnimplemented,
    }
}

/// The permission mode the `read_file` boundary admits under (DEC-015): the
/// interim manual carrier, stated once beside the tool it governs.
pub const READ_FILE_MODE: crate::policy::PermissionMode = crate::policy::PermissionMode::Manual;

fn descriptor(row: &CatalogRow) -> CommandDescriptor {
    CommandDescriptor {
        canonical_id: row.canonical_id.to_string(),
        aliases: row.aliases.iter().map(|a| a.to_string()).collect(),
        description: row.description.to_string(),
        busy_policy: row.busy_policy.to_string(),
        available: row.available(),
        unavailability_reason: row.unavailable.map(str::to_string),
    }
}

/// The page every command surface serves: the 36 canonical rows in their
/// published order, then the tool carriers.
pub fn describe() -> Page<CommandDescriptor> {
    let items = CATALOG
        .iter()
        .chain(TOOL_ROWS)
        .map(descriptor)
        .collect::<Vec<_>>();
    Page::new(items, 0)
}

/// The page as help lines. Every word is the page's own, so a row the page
/// does not carry cannot appear in the text.
#[must_use]
pub fn help_lines(page: &Page<CommandDescriptor>) -> Vec<String> {
    page.items
        .iter()
        .map(|item| {
            let aliases = item.aliases.join(", ");
            match &item.unavailability_reason {
                Some(reason) => format!(
                    "  {:<20} {:<16} {} (unavailable: {reason})",
                    item.canonical_id, aliases, item.description
                ),
                None => format!(
                    "  {:<20} {:<16} {}",
                    item.canonical_id, aliases, item.description
                ),
            }
        })
        .collect()
}

/// The words a completion script offers: every row's canonical id and every
/// alias, in page order.
#[must_use]
pub fn completion_words(page: &Page<CommandDescriptor>) -> Vec<String> {
    let mut words = Vec::with_capacity(page.items.len());
    for item in &page.items {
        words.push(item.canonical_id.clone());
        words.extend(item.aliases.iter().cloned());
    }
    words
}

/// One completion script rendered from the page. The words are the page's
/// own, so a row the page drops is not completed either.
#[must_use]
pub fn completions(page: &Page<CommandDescriptor>, shell: Shell) -> String {
    let words = completion_words(page).join(" ");
    match shell {
        Shell::Bash => format!(
            "_rivect() {{\n    COMPREPLY=( $(compgen -W \"{words}\" -- \"${{COMP_WORDS[COMP_CWORD]}}\") )\n}}\ncomplete -F _rivect rivect\n"
        ),
        Shell::Zsh => format!(
            "#compdef rivect\n_rivect() {{\n    _arguments \"1: :(({words}))\"\n}}\n_rivect \"$@\"\n"
        ),
        Shell::Fish => words
            .split_whitespace()
            .fold(String::new(), |mut script, word| {
                script.push_str("complete -c rivect -f -a ");
                script.push_str(word);
                script.push('\n');
                script
            }),
    }
}

/// Typed tool invoke: everything routes through executor admission; there is
/// no direct filesystem access from the tool layer.
pub fn invoke_read(
    rt: &mut Runtime,
    task_id: &TaskId,
    grant_id: &str,
    path: PathBuf,
) -> Result<EffectOutcome, ExecutorError> {
    let request = EffectRequest::Read {
        grant_id: grant_id.to_string(),
        path,
    };
    let mut executor = rt.executor();
    let admitted = executor.admit(task_id, request, READ_FILE_MODE)?;
    executor.execute(&admitted)
}
