//! Minimal TUI (design brief D-005): fullscreen alternate screen by default,
//! mouse capture off, terminal restored on exit, cancel and panic. Also owns
//! the client-side event projection rules.

use crate::commands::{Ingress, Runtime, dispatch_runtime_request};
use crate::contracts::{CommandId, EffectClass, Event, TEXT_MAX_BYTES};
use crate::policy::{ModeDecision, preapproval_scope};
use crate::providers::LoopbackProvider;
use crate::resources::{OutputStatus, OutputStream, sanitize_status_cause};
use crate::state::TaskStore;
use crossterm::cursor::Show;
use crossterm::event::{
    Event as TermEvent, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, poll, read,
};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::{Backend, CrosstermBackend};
use ratatui::layout::Constraint;
use ratatui::widgets::Paragraph;
use serde_json::{Value, json};
use std::io::{self, Stdout, Write};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

fn report_cleanup_error(error: &io::Error) {
    let message = format!("terminal cleanup failed: {error}\n");
    let mut stderr = io::stderr().lock();
    if let Err(write_error) = stderr.write_all(message.as_bytes()) {
        std::hint::black_box(write_error);
    }
}

/// Terminal lifecycle guard. Mouse capture is deliberately never enabled
/// (D-005 default off so copy-on-select and tmux copy-mode keep working).
pub struct TerminalGuard {
    terminal: Terminal<CrosstermBackend<Stdout>>,
    previous_hook: Arc<dyn Fn(&std::panic::PanicHookInfo<'_>) + Sync + Send>,
    restored: bool,
}

impl TerminalGuard {
    pub fn enter() -> io::Result<Self> {
        enable_raw_mode()?;
        if let Err(error) = execute!(io::stdout(), EnterAlternateScreen) {
            if let Err(cleanup_error) = disable_raw_mode() {
                report_cleanup_error(&cleanup_error);
            }
            return Err(error);
        }
        let terminal = match Terminal::new(CrosstermBackend::new(io::stdout())) {
            Ok(terminal) => terminal,
            Err(error) => {
                let mut out = io::stdout();
                if let Err(cleanup_error) = execute!(out, LeaveAlternateScreen, Show) {
                    report_cleanup_error(&cleanup_error);
                }
                if let Err(cleanup_error) = disable_raw_mode() {
                    report_cleanup_error(&cleanup_error);
                }
                return Err(error);
            }
        };
        let original: Arc<dyn Fn(&std::panic::PanicHookInfo<'_>) + Sync + Send> =
            Arc::new(std::panic::take_hook());
        let chained = original.clone();
        // The hook cannot borrow the terminal, so it restores the shared tty
        // state directly; the guard's own restore stays idempotent.
        std::panic::set_hook(Box::new(move |info| {
            let mut out = io::stdout();
            if let Err(error) = execute!(out, LeaveAlternateScreen, Show) {
                report_cleanup_error(&error);
            }
            if let Err(error) = disable_raw_mode() {
                report_cleanup_error(&error);
            }
            chained(info);
        }));
        Ok(Self {
            terminal,
            previous_hook: original,
            restored: false,
        })
    }

    pub fn terminal_mut(&mut self) -> &mut Terminal<CrosstermBackend<Stdout>> {
        &mut self.terminal
    }

    fn restore_terminal(&mut self) -> io::Result<()> {
        if self.restored {
            return Ok(());
        }
        let clear_succeeded = match self.terminal.clear() {
            Ok(()) => true,
            Err(error) => {
                report_cleanup_error(&error);
                false
            }
        };
        let screen = execute!(io::stdout(), LeaveAlternateScreen, Show);
        let raw_mode = disable_raw_mode();
        let result = match (screen, raw_mode) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(screen_error), Ok(())) => Err(screen_error),
            (Ok(()), Err(raw_mode_error)) => Err(raw_mode_error),
            (Err(screen_error), Err(raw_mode_error)) => {
                report_cleanup_error(&raw_mode_error);
                Err(screen_error)
            }
        };
        if result.is_ok() && clear_succeeded {
            if !std::thread::panicking() {
                let original = std::mem::replace(&mut self.previous_hook, Arc::new(|_| {}));
                std::panic::set_hook(Box::new(move |info| original(info)));
            }
            self.restored = true;
        }
        result
    }

    pub fn restore(mut self) -> io::Result<()> {
        self.restore_terminal()
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        if let Err(error) = self.restore_terminal() {
            report_cleanup_error(&error);
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct LocalView {
    pub status: String,
    pub dock: Vec<String>,
    pub transcript: Vec<String>,
    pub composer: String,
    /// Streaming external (worker) output with its typed settlement
    /// state. Hostile or not, everything shown passed sanitization at
    /// the stream boundary; the step driver produces the chunks.
    pub output: OutputStream,
    /// Vertical scroll offset of the streaming output body; output
    /// updates never move it, so a reader scrolled into old output
    /// keeps their place while output updates in place.
    pub output_scroll: u16,
    /// Open permission panel (modal). The Ask-verdict producer arrives with
    /// the mode-selection carrier; while open, keys route to the panel.
    pub panel: Option<PermissionPanel>,
}

/// Human actions the permission panel offers (DEC-014 verdict-vs-action
/// split: the `{allow,ask,deny}` token is the mode verdict, these are the
/// choices a human makes about it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PanelAction {
    AllowOnce,
    LimitedGrant,
    Deny,
}

impl PanelAction {
    fn label(self) -> String {
        match self {
            Self::AllowOnce => "allow once".to_string(),
            // The label states the TTL the grant records: 600 s is
            // ten minutes of limited consent, kept inside the 60-column
            // acceptance geometry.
            Self::LimitedGrant => {
                format!(
                    "allow with limited grant ({} min)",
                    LIMIT_GRANT_TTL_SECONDS / 60
                )
            }
            Self::Deny => "deny".to_string(),
        }
    }

    fn all() -> [Self; 3] {
        [Self::AllowOnce, Self::LimitedGrant, Self::Deny]
    }
}

/// Title of the awaiting-permission state (design-brief §4).
pub const PANEL_TITLE: &str = "awaiting permission";
/// Transcript note when the panel resolves without a grant.
pub const PANEL_DENIED_NOTE: &str = "permission denied; no grant recorded";
/// Transcript note when the one-shot allow is chosen: it names the chosen
/// action and the next observable state — the request is consumed by the
/// choice and no grant outlives it (no consent carrier exists yet; the
/// consume seam arrives with the mode-selection carrier).
pub const PANEL_ALLOWED_NOTE: &str = "allowed once; no grant recorded; request consumed";
/// Transcript note when the limited grant is recorded in the store.
pub const PANEL_LIMITED_NOTE: &str = "limited grant recorded";
/// One pinned footer line naming the panel's three key affordances.
pub const PANEL_FOOTER_HINT: &str = "Tab/arrows move, Enter confirms, Esc denies";
/// Grantor identity the panel records limited grants under.
const PANEL_GRANTOR: &str = "human:tui-panel";
/// Limited grants stay short on purpose; renewing is one explicit action.
const LIMIT_GRANT_TTL_SECONDS: i64 = 600;

/// The permission panel: one pending effect asking for consent. Focus is
/// never consent (PRO-002) — the default focus is the non-destructive
/// action and Enter confirms only what is focused.
#[derive(Debug, Clone, PartialEq)]
pub struct PermissionPanel {
    pub verdict: ModeDecision,
    pub class: EffectClass,
    pub initiator: String,
    pub expiry: String,
    pub scope: String,
    focus: PanelAction,
    /// Vertical scroll offset of the scope body; the header and the
    /// actions footer never scroll.
    body_scroll: u16,
}

impl PermissionPanel {
    /// Assembles the panel for one pending effect; `class` is the asked
    /// effect's class and namespaces the limited-grant consent.
    pub fn new(
        verdict: ModeDecision,
        class: EffectClass,
        initiator: impl Into<String>,
        expiry: impl Into<String>,
        scope: impl Into<String>,
    ) -> Self {
        Self {
            verdict,
            class,
            initiator: initiator.into(),
            expiry: expiry.into(),
            scope: scope.into(),
            focus: PanelAction::Deny,
            body_scroll: 0,
        }
    }

    /// Cycles focus across the actions; wrapping is intentional so every
    /// action is reachable with either arrow key.
    pub fn shift_focus(&mut self, backward: bool) {
        let actions = PanelAction::all();
        let index = actions
            .iter()
            .position(|action| *action == self.focus)
            .unwrap_or(actions.len() - 1);
        let offset = if backward { actions.len() - 1 } else { 1 };
        self.focus = actions[(index + offset) % actions.len()];
    }

    /// The action a confirming Enter resolves to.
    pub fn confirm(&self) -> PanelAction {
        self.focus
    }

    /// Panel body; the focused action is bracketed so focus is readable
    /// without color (standards §7.3: never color alone).
    pub fn actions_line(&self) -> String {
        PanelAction::all()
            .iter()
            .map(|action| {
                if *action == self.focus {
                    format!("[{}]", action.label())
                } else {
                    action.label()
                }
            })
            .collect::<Vec<_>>()
            .join(" | ")
    }

    /// Returns focus to the non-destructive action: a failed recording
    /// must not leave the confirming action under Enter.
    pub fn focus_deny(&mut self) {
        self.focus = PanelAction::Deny;
    }

    /// Scrolls the scope body one line; the header and the actions footer
    /// stay pinned, so a body longer than its region never hides the
    /// actions behind the scope.
    pub fn scroll_body(&mut self, down: bool) {
        self.body_scroll = if down {
            self.body_scroll.saturating_add(1)
        } else {
            self.body_scroll.saturating_sub(1)
        };
    }

    /// Pinned header: the mandatory fields precede the scope so scarce
    /// rows never hide them (design-brief §4).
    fn header_text(&self) -> String {
        format!(
            "{PANEL_TITLE}\ndecision: {}\neffect: {}\ninitiator: {}\nexpiry: {}",
            self.verdict.token(),
            effect_class_label(self.class),
            self.initiator,
            self.expiry,
        )
    }

    /// Scrollable body: the scope, the only freely wrapping part (the
    /// request detail carrier arrives with the mode-selection carrier).
    fn body_text(&self) -> String {
        format!("scope: {}", self.scope)
    }

    /// Pinned footer: the actions line, then the one affordance hint.
    fn footer_text(&self) -> String {
        format!("{}\n{PANEL_FOOTER_HINT}", self.actions_line())
    }
}

/// The six effect classes, spelled for the panel's mandatory
/// `effect:` header line.
fn effect_class_label(class: EffectClass) -> &'static str {
    match class {
        EffectClass::Read => "read",
        EffectClass::Write => "write",
        EffectClass::Exec => "exec",
        EffectClass::Egress => "egress",
        EffectClass::Model => "model",
        EffectClass::Control => "control",
    }
}

/// Rows of the pinned panel header (`header_text`).
const PANEL_HEADER_ROWS: u16 = 5;
/// Rows of the pinned panel footer (`footer_text`).
const PANEL_FOOTER_ROWS: u16 = 2;

/// Start, no connection: input and help are available; login has not happened.
pub const STATUS_DISCONNECTED: &str = "Rivect · not connected · /help for help";
pub const DOCK_EMPTY: &str = "No tasks. Login is a separate explicit action.";
pub const TRANSCRIPT_INPUT: &str = "Input is available. Enter a task or a clarification.";
pub const TRANSCRIPT_NO_PROJECT: &str =
    "No project or index is selected; ordinary replies are not blocked.";
pub const HELP_TEXT: &str = concat!(
    "Commands: Enter submits a task; /help shows help; ",
    "Esc quits; Ctrl-C cancels.",
);

/// Status line while external output streams (design-brief §4).
pub const OUTPUT_STATUS_STREAMING: &str = "output · streaming";
/// Status line when a producer run completed the stream.
pub const OUTPUT_STATUS_COMPLETE: &str = "output · complete";
/// Status line prefix when the stream settled partial.
pub const OUTPUT_STATUS_PARTIAL: &str = "output · partial";
/// Status line prefix when the stream settled failed.
pub const OUTPUT_STATUS_ERROR: &str = "output · error";
/// Appended when retention capacity truncated the stream: the shown
/// text is the retained head, never the whole output.
pub const OUTPUT_TRUNCATED_NOTE: &str = "first 64 KiB retained";

pub fn initial_view() -> LocalView {
    LocalView {
        status: STATUS_DISCONNECTED.to_string(),
        dock: vec![DOCK_EMPTY.to_string()],
        transcript: vec![
            TRANSCRIPT_INPUT.to_string(),
            TRANSCRIPT_NO_PROJECT.to_string(),
        ],
        composer: String::new(),
        output: OutputStream::new(),
        output_scroll: 0,
        panel: None,
    }
}

pub fn render<B: Backend>(terminal: &mut Terminal<B>, view: &LocalView) -> Result<(), B::Error> {
    terminal.draw(|frame| {
        let area = frame.area();
        let output_active = view.output.is_active();
        let mut rows = Vec::with_capacity(6);
        rows.push(Constraint::Length(1));
        rows.push(Constraint::Min(1));
        if output_active {
            rows.push(Constraint::Length(1));
            rows.push(Constraint::Min(1));
        }
        rows.push(Constraint::Length(view.dock.len().clamp(1, 3) as u16));
        rows.push(Constraint::Length(1));
        let chunks = ratatui::layout::Layout::vertical(rows).split(area);
        frame.render_widget(Paragraph::new(view.status.clone()), chunks[0]);
        frame.render_widget(Paragraph::new(view.transcript.join("\n")), chunks[1]);
        let mut next = 2;
        if output_active {
            frame.render_widget(
                Paragraph::new(output_status_line(&view.output)),
                chunks[next],
            );
            next += 1;
            frame.render_widget(
                Paragraph::new(view.output.text())
                    .wrap(ratatui::widgets::Wrap { trim: false })
                    .scroll((view.output_scroll, 0)),
                chunks[next],
            );
            next += 1;
        }
        frame.render_widget(Paragraph::new(view.dock.join("\n")), chunks[next]);
        frame.render_widget(
            Paragraph::new(format!("> {}", view.composer)),
            chunks[next + 1],
        );
        if let Some(panel) = &view.panel {
            // Modal overlay: capped at the 60-column acceptance geometry,
            // clamped to the buffer, three regions — pinned header,
            // scrollable scope body (wrapping, never truncating),
            // pinned actions footer (design-brief §4).
            let width = area.width.min(60);
            let height = area.height.saturating_sub(4).max(6);
            let panel_area = ratatui::layout::Rect {
                x: area.width.saturating_sub(width) / 2,
                y: area.height.saturating_sub(height) / 2,
                width,
                height,
            };
            frame.render_widget(ratatui::widgets::Clear, panel_area);
            let block = ratatui::widgets::Block::bordered();
            let inner = block.inner(panel_area);
            frame.render_widget(block, panel_area);
            let regions = ratatui::layout::Layout::vertical([
                Constraint::Length(PANEL_HEADER_ROWS),
                Constraint::Min(1),
                Constraint::Length(PANEL_FOOTER_ROWS),
            ])
            .split(inner);
            frame.render_widget(Paragraph::new(panel.header_text()), regions[0]);
            frame.render_widget(
                Paragraph::new(panel.body_text())
                    .wrap(ratatui::widgets::Wrap { trim: false })
                    .scroll((panel.body_scroll, 0)),
                regions[1],
            );
            frame.render_widget(Paragraph::new(panel.footer_text()), regions[2]);
        }
    })?;
    Ok(())
}

/// One status line for the streaming output region: the typed state
/// and, when retention truncated the stream, the honest capacity note —
/// truncated output is never presented as the whole output.
fn output_status_line(output: &OutputStream) -> String {
    let base = match output.status() {
        OutputStatus::Streaming => OUTPUT_STATUS_STREAMING.to_string(),
        OutputStatus::Complete => OUTPUT_STATUS_COMPLETE.to_string(),
        OutputStatus::Partial { cause } => {
            format!("{OUTPUT_STATUS_PARTIAL}: {}", sanitize_status_cause(cause))
        }
        OutputStatus::Failed { cause } => {
            format!("{OUTPUT_STATUS_ERROR}: {}", sanitize_status_cause(cause))
        }
    };
    if output.head_truncated() {
        format!("{base} · {OUTPUT_TRUNCATED_NOTE}")
    } else {
        base
    }
}

const TUI_CONNECTION: &str = "tui";

fn dispatch_tui_request(runtime: &mut Runtime, request: Value) -> io::Result<Value> {
    let request = serde_json::to_string(&request)
        .map_err(|source| io::Error::other(format!("tui request encoding failed: {source}")))?;
    let response =
        dispatch_runtime_request(runtime, Ingress::TrustedHuman, TUI_CONNECTION, &request);
    let response: Value = serde_json::from_str(&response)
        .map_err(|source| io::Error::other(format!("tui response decoding failed: {source}")))?;
    if let Some(error) = response.get("error") {
        let message = error
            .get("data")
            .and_then(|data| data.get("message"))
            .and_then(Value::as_str)
            .or_else(|| error.get("message").and_then(Value::as_str))
            .unwrap_or("request rejected");
        return Err(io::Error::other(format!("tui request rejected: {message}")));
    }
    response
        .get("result")
        .cloned()
        .ok_or_else(|| io::Error::other("tui response omitted result"))
}

struct TuiDispatch {
    runtime: Runtime,
    session_id: String,
}

impl TuiDispatch {
    fn open(data_root: &Path) -> io::Result<Self> {
        let mut runtime = Runtime::open(data_root, Box::new(LoopbackProvider::new()))
            .map_err(|source| io::Error::other(format!("tui runtime open failed: {source}")))?;
        let result = dispatch_tui_request(
            &mut runtime,
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "session.open",
                "params": {
                    "schema_version": 1,
                    "bootstrap_id": format!("tui-{}", CommandId::generate()),
                }
            }),
        )?;
        let session_id = result
            .get("session_id")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| io::Error::other("tui session.open omitted session_id"))?;
        Ok(Self {
            runtime,
            session_id,
        })
    }

    fn submit(&mut self, goal: &str) -> io::Result<(String, String)> {
        let result = dispatch_tui_request(
            &mut self.runtime,
            json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "task.submit",
                "params": {
                    "schema_version": 1,
                    "command_id": CommandId::generate().0,
                    "session_id": self.session_id,
                    "kind": "create",
                    "goal": goal,
                    "contract": { "criteria": [], "constraints": [] },
                }
            }),
        )?;
        let status = result
            .get("status")
            .and_then(Value::as_str)
            .ok_or_else(|| io::Error::other("tui task submission omitted status"))?;
        if status != "accepted" {
            return Err(io::Error::other("tui task submission was not accepted"));
        }
        let task_id = result
            .get("task_id")
            .and_then(Value::as_str)
            .ok_or_else(|| io::Error::other("tui task submission omitted task_id"))?;
        Ok((status.to_owned(), task_id.to_owned()))
    }

    fn status(&mut self) -> io::Result<Value> {
        // Dock contract: request one PAGE_MAX response; it does not walk cursors.
        dispatch_tui_request(
            &mut self.runtime,
            json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "runtime.status",
                "params": {
                    "schema_version": 1,
                    "session_id": self.session_id,
                    "page": { "page_size": crate::contracts::PAGE_MAX },
                }
            }),
        )
    }
}

fn task_dock(status: &Value) -> Vec<String> {
    let Some(items) = status
        .get("todo")
        .and_then(|todo| todo.get("items"))
        .and_then(Value::as_array)
        .filter(|items| !items.is_empty())
    else {
        return vec![DOCK_EMPTY.to_string()];
    };
    items
        .iter()
        .filter_map(|item| {
            let task_id = item.get("task_id").and_then(Value::as_str)?;
            let lifecycle = item.get("lifecycle").and_then(Value::as_str)?;
            let reason = item
                .get("blockers")
                .and_then(Value::as_array)
                .and_then(|blockers| blockers.first())
                .and_then(|blocker| blocker.get("reason"))
                .and_then(Value::as_str);
            Some(match reason {
                Some(reason) => format!("task {task_id}: {lifecycle} ({reason})"),
                None => format!("task {task_id}: {lifecycle}"),
            })
        })
        .collect()
}

const COMPOSER_LIMIT_MESSAGE: &str = "Composer input exceeds the goal size limit.";

/// Handles one key event while the permission panel is open — the one
/// production handler, shared by the TUI loop and the panel harness, so
/// the limited-grant recording is exercised on the exact production path.
/// Returns false when the caller should exit with the cancel code
/// (Ctrl-C). Enter confirms only the focused action — an unsolicited
/// Enter resolves to the default deny focus, never a grant (PRO-002);
/// composer input is suspended while the modal owns the keys.
///
/// A limited-grant recording that fails resolves nothing: the panel
/// stays open, the typed store error is noted in the transcript, and
/// focus returns to the deny action, so the choice can be retried or
/// denied, never lost to the failure.
pub fn handle_panel_key(
    code: KeyCode,
    modifiers: KeyModifiers,
    view: &mut LocalView,
    store: &mut TaskStore,
) -> bool {
    if code == KeyCode::Char('c') && modifiers.contains(KeyModifiers::CONTROL) {
        return false;
    }
    match code {
        KeyCode::Left
        | KeyCode::BackTab
        | KeyCode::Right
        | KeyCode::Tab
        | KeyCode::Up
        | KeyCode::Down => {
            let backward = matches!(code, KeyCode::Left | KeyCode::BackTab | KeyCode::Up);
            if let Some(panel) = view.panel.as_mut() {
                panel.shift_focus(backward);
            }
        }
        KeyCode::PageUp | KeyCode::PageDown => {
            if let Some(panel) = view.panel.as_mut() {
                panel.scroll_body(code == KeyCode::PageDown);
            }
        }
        KeyCode::Enter => confirm_panel_action(view, store),
        // Esc cancels the prompt: stopped work stays visible, nothing is
        // granted (design-brief Pause/cancel state).
        KeyCode::Esc if view.panel.take().is_some() => {
            view.transcript.push(PANEL_DENIED_NOTE.to_string());
        }
        _ => {}
    }
    true
}

/// Resolves the Enter key. The panel resolves only after its chosen
/// action succeeded; a failed grant recording puts the panel back
/// un-resolved, notes the typed store error, and returns focus to the
/// deny action, so the choice can be retried or denied, never lost to
/// the failure.
fn confirm_panel_action(view: &mut LocalView, store: &mut TaskStore) {
    if let Some(mut panel) = view.panel.take() {
        match panel.confirm() {
            PanelAction::Deny => {
                view.transcript.push(PANEL_DENIED_NOTE.to_string());
            }
            PanelAction::AllowOnce => {
                view.transcript.push(PANEL_ALLOWED_NOTE.to_string());
            }
            PanelAction::LimitedGrant => {
                let scope = preapproval_scope(panel.class, &panel.scope);
                match store.record_preapproval(&scope, PANEL_GRANTOR, LIMIT_GRANT_TTL_SECONDS) {
                    Ok(()) => {
                        view.transcript.push(PANEL_LIMITED_NOTE.to_string());
                    }
                    Err(source) => {
                        panel.focus_deny();
                        view.panel = Some(panel);
                        view.transcript
                            .push(format!("limited grant recording failed: {source}"));
                    }
                }
            }
        }
    }
}

fn append_composer_char(view: &mut LocalView, ch: char) {
    // The typed goal must never exceed what create_task accepts; the wire
    // frame cap (REQUEST_MAX_BYTES) is far above this, so TEXT_MAX_BYTES is
    // the binding limit for composed goals.
    if view.composer.len().saturating_add(ch.len_utf8()) > TEXT_MAX_BYTES {
        if view.transcript.last().map(String::as_str) != Some(COMPOSER_LIMIT_MESSAGE) {
            view.transcript.push(COMPOSER_LIMIT_MESSAGE.to_string());
        }
        return;
    }
    view.composer.push(ch);
}

/// Runs the minimal fullscreen loop. Esc quits normally, Ctrl-C cancels
/// (exit 130). The guard guarantees terminal restoration on both paths and on
/// panic.
pub fn run_tui(data_root: &Path) -> io::Result<i32> {
    let mut guard = TerminalGuard::enter()?;
    let mut view = initial_view();
    let mut tui_dispatch: Option<TuiDispatch> = None;
    let mut exit = 0;
    loop {
        render(guard.terminal_mut(), &view)?;
        if poll(Duration::from_millis(250))?
            && let TermEvent::Key(KeyEvent {
                code,
                modifiers,
                kind: KeyEventKind::Press,
                ..
            }) = read()?
        {
            match (code, modifiers) {
                (KeyCode::Esc, _) if view.panel.is_none() => break,
                (KeyCode::Char('c'), m) if m.contains(KeyModifiers::CONTROL) => {
                    exit = 130;
                    break;
                }
                _ if view.panel.is_some() => {
                    // The modal owns the keys through the shared production
                    // handler; the limited-grant action records on the same
                    // store handle decide reads (DEC-016). Without an open
                    // dispatch there is no store to grant on, so the
                    // action fails honestly.
                    let dispatch = tui_dispatch
                        .as_mut()
                        .ok_or_else(|| io::Error::other("no open session to grant on"))?;
                    if !handle_panel_key(
                        code,
                        modifiers,
                        &mut view,
                        &mut dispatch.runtime.owner.store,
                    ) {
                        exit = 130;
                        break;
                    }
                }
                // Streaming output scroll: the reader keeps their place
                // while output updates in place (design-brief §3).
                (KeyCode::PageUp | KeyCode::PageDown, _) if view.output.is_active() => {
                    view.output_scroll = if code == KeyCode::PageDown {
                        view.output_scroll.saturating_add(1)
                    } else {
                        view.output_scroll.saturating_sub(1)
                    };
                }
                (KeyCode::Enter, _) if !view.composer.is_empty() => {
                    let input = view.composer.clone();
                    if input == "/help" {
                        view.transcript.push(HELP_TEXT.to_string());
                        view.composer.clear();
                    } else {
                        if tui_dispatch.is_none() {
                            tui_dispatch = Some(TuiDispatch::open(data_root)?);
                        }
                        let dispatch = tui_dispatch
                            .as_mut()
                            .ok_or_else(|| io::Error::other("tui dispatch unavailable"))?;
                        let (status, task_id) = dispatch.submit(&input)?;
                        view.dock = task_dock(&dispatch.status()?);
                        view.transcript
                            .push(format!("Submitted task: {input} ({status}: {task_id})"));
                        view.composer.clear();
                    }
                }
                (KeyCode::Enter, _) => {}
                (KeyCode::Char(ch), _) => append_composer_char(&mut view, ch),
                (KeyCode::Backspace, _) => {
                    view.composer.pop();
                }
                _ => {}
            }
        }
    }
    guard.restore()?;
    Ok(exit)
}

/// Client-side projection rules (architecture «Транспорт и размеры»): apply
/// only revision = last + 1; duplicates are ignored; a gap or a different
/// payload for the same revision forces a resync instead of skipping.
#[derive(Debug, Clone, PartialEq)]
pub enum ApplyVerdict {
    Applied,
    Duplicate,
    Resync,
}

#[derive(Debug, Default)]
pub struct Projection {
    pub last_revision: u64,
    last_delta: Option<Value>,
}

impl Projection {
    pub fn new(last_revision: u64) -> Self {
        Self {
            last_revision,
            last_delta: None,
        }
    }

    pub fn apply(&mut self, event: &Event) -> ApplyVerdict {
        if event.aggregate_revision <= self.last_revision {
            return if self.last_delta.as_ref() == Some(&event.delta) {
                ApplyVerdict::Duplicate
            } else {
                ApplyVerdict::Resync
            };
        }
        if event.aggregate_revision != self.last_revision + 1 {
            return ApplyVerdict::Resync;
        }
        self.last_revision = event.aggregate_revision;
        self.last_delta = Some(event.delta.clone());
        ApplyVerdict::Applied
    }
}

#[cfg(test)]
mod tests {
    use super::{TuiDispatch, append_composer_char, initial_view, task_dock};
    use crate::contracts::{PAGE_MAX, TEXT_MAX_BYTES};
    use serde_json::json;
    #[test]
    fn tui_status_requests_page_maximum() -> Result<(), Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "rivect-ui-page-max-{}",
            crate::contracts::CommandId::generate()
        ));
        std::fs::create_dir_all(&root)?;
        let mut dispatch = TuiDispatch::open(&root)?;
        for index in 0..PAGE_MAX {
            dispatch.submit(&format!("page-max-task-{index}"))?;
        }
        let status = dispatch.status()?;
        let task_count = status
            .get("tasks")
            .and_then(|tasks| tasks.get("items"))
            .and_then(serde_json::Value::as_array)
            .map(Vec::len);
        assert_eq!(task_count, Some(PAGE_MAX as usize));
        assert_eq!(task_dock(&status).len(), PAGE_MAX as usize);
        Ok(())
    }

    #[test]
    fn task_dock_renders_blocked_reason() {
        let dock = task_dock(&json!({
            "todo": {
                "items": [{
                    "task_id": "task-1",
                    "lifecycle": "blocked",
                    "blockers": [{ "reason": "outcome_unknown" }]
                }]
            }
        }));
        assert_eq!(dock, vec!["task task-1: blocked (outcome_unknown)"]);
    }

    #[test]
    fn composer_rejects_input_beyond_goal_limit() {
        let mut view = initial_view();
        view.composer = "x".repeat(TEXT_MAX_BYTES - 1);
        append_composer_char(&mut view, 'é');
        assert_eq!(view.composer.len(), TEXT_MAX_BYTES - 1);
        assert_eq!(
            view.transcript
                .iter()
                .filter(|line| line.as_str() == super::COMPOSER_LIMIT_MESSAGE)
                .count(),
            1
        );
        // Exactly TEXT_MAX_BYTES bytes is the submission boundary: accepted.
        append_composer_char(&mut view, 'x');
        assert_eq!(view.composer.len(), TEXT_MAX_BYTES);
        append_composer_char(&mut view, 'y');
        assert_eq!(view.composer.len(), TEXT_MAX_BYTES);
        assert_eq!(
            view.transcript
                .iter()
                .filter(|line| line.as_str() == super::COMPOSER_LIMIT_MESSAGE)
                .count(),
            1
        );
    }
}
