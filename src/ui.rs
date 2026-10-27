//! Minimal TUI (design brief D-005): fullscreen alternate screen by default,
//! mouse capture off, terminal restored on exit, cancel and panic. Also owns
//! the client-side event projection rules.

use crate::commands::{
    Ingress, ResumeAdmission, Runtime, dispatch_runtime_request, report_boot_diagnostics,
};
use crate::config::Config;
use crate::contracts::{
    AnswerSelection, Availability, CommandId, EffectClass, Event, Question, QuestionId, SessionId,
    TEXT_MAX_BYTES, TaskId,
};
use crate::owner::OwnerError;
use crate::policy::{
    ModeDecision, canonical_egress_target, grant_id_is_key_safe, preapproval_scope,
};
use crate::providers::LoopbackProvider;
use crate::resources::{OutputStatus, OutputStream, sanitize_status_cause};
use crate::state::StoreWriter;
use crossterm::cursor::Show;
use crossterm::event::{
    DisableBracketedPaste, EnableBracketedPaste, Event as TermEvent, KeyCode, KeyEvent,
    KeyEventKind, KeyModifiers, poll, read,
};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::{Backend, CrosstermBackend};
use ratatui::buffer::CellWidth as _;
use ratatui::layout::Constraint;
use ratatui::style::Style;
use ratatui::text::{Line, Text};
use ratatui::widgets::Paragraph;
use serde_json::{Value, json};
use std::cell::Cell;
use std::collections::VecDeque;
use std::fmt;
use std::io::{self, Stdout, Write};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

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
        if let Err(error) = execute!(io::stdout(), EnterAlternateScreen, EnableBracketedPaste) {
            // execute! applies the sequence left to right: the screen
            // may already be entered when the paste enable fails —
            // undo whichever prefixes landed, then drop raw mode.
            let mut out = io::stdout();
            if let Err(cleanup_error) =
                execute!(out, DisableBracketedPaste, LeaveAlternateScreen, Show)
            {
                report_cleanup_error(&cleanup_error);
            }
            if let Err(cleanup_error) = disable_raw_mode() {
                report_cleanup_error(&cleanup_error);
            }
            return Err(error);
        }
        let terminal = match Terminal::new(CrosstermBackend::new(io::stdout())) {
            Ok(terminal) => terminal,
            Err(error) => {
                let mut out = io::stdout();
                if let Err(cleanup_error) =
                    execute!(out, DisableBracketedPaste, LeaveAlternateScreen, Show)
                {
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
            if let Err(error) = execute!(out, DisableBracketedPaste, LeaveAlternateScreen, Show) {
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
        let screen = execute!(
            io::stdout(),
            DisableBracketedPaste,
            LeaveAlternateScreen,
            Show
        );
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

/// The near-full context warning as the dock projection paints it: the share
/// of the admission ceiling the measured context fills and the task its bytes
/// were measured from, so the continuation the row offers folds that very task
/// (AC-072, DEC-013). The row itself is written at paint time, where the width
/// it has to fit is known.
#[derive(Debug, Clone, PartialEq)]
pub struct ContextWarning {
    pub task_id: TaskId,
    pub percent: usize,
}

/// How long a dock projection may reuse its own measurement under an
/// unchanged key. The key is the subject task's revision, but the assembled
/// context also moves with records `runtime.status` does not carry — an
/// episode appended, a history folded — while the revision stays put, so the
/// key alone would serve a stale number until the task's next transition.
const CONTEXT_MEASURE_INTERVAL: Duration = Duration::from_secs(1);

/// The identity of one near-full measurement: whose context was measured, the
/// revision the status payload reported for it, and the setting the line is
/// gated on.
#[derive(Debug, Clone, PartialEq)]
struct ContextMeasureKey {
    task_id: TaskId,
    revision: Option<u64>,
    auto_compact: bool,
}

/// The dock projection's remembered measurement — the key it was taken under,
/// the line it produced, and the beat it was taken on.
#[derive(Debug)]
struct ContextMeasurement {
    key: ContextMeasureKey,
    warning: Option<ContextWarning>,
    taken: Instant,
}

impl ContextMeasurement {
    /// Whether this measurement still answers `key` at `now`: the key has not
    /// moved and the backstop interval has not passed.
    fn answers(&self, key: &ContextMeasureKey, now: Instant) -> bool {
        self.key == *key && now.saturating_duration_since(self.taken) < CONTEXT_MEASURE_INTERVAL
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct LocalView {
    pub status: String,
    pub dock: Vec<String>,
    /// The warning the dock projection paints while the assembled context is
    /// nearly full and auto-compaction is off. Recomputed on the projection's
    /// own beat from the store, so it never outlives the condition it names.
    pub context_warning: Option<ContextWarning>,
    /// The dock's own fault mark: the second consecutive failed projection
    /// read says so on the status band's own row, where a transcript past the
    /// panel cannot clip it. Cleared by the next read that succeeds.
    pub dock_stale: Option<String>,
    pub transcript: Vec<String>,
    pub composer: String,
    /// Streaming external (worker) output with its typed settlement
    /// state. Hostile or not, everything shown passed sanitization at
    /// the stream boundary; the step driver produces the chunks.
    pub output: OutputStream,
    /// Vertical scroll offset of the streaming output body; output
    /// updates never move it, so a reader scrolled into old output
    /// keeps their place while output updates in place. `render` clamps
    /// the stored offset to the wrapped bound each frame — it holds a
    /// shared borrow of the view, so the write-back goes through `Cell`
    /// — and a PageDown overshoot can never swallow the next PageUp.
    pub output_scroll: Cell<u16>,
    /// Open permission panel (modal). The Ask-verdict producer arrives with
    /// the mode-selection carrier; while open, keys route to the panel.
    pub panel: Option<PermissionPanel>,
    /// Open decision card (modal): one pending versioned question asking
    /// for a selection; while open, keys route to the card.
    pub decision: Option<DecisionPanel>,
    /// The question the operator last returned unanswered with Esc: it
    /// stays pending for the wire surface, but the poll must not reopen
    /// the same card in a loop. A different pending question clears it.
    pub decision_dismissed: Option<QuestionId>,
}

impl LocalView {
    /// Replaces the streaming output with a new stream: the new stream
    /// starts at its top, so the previous stream's scroll offset must
    /// not carry into content it never described.
    pub fn replace_output(&mut self, output: OutputStream) {
        self.output = output;
        self.output_scroll.set(0);
    }
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
/// One pinned footer line naming the panel's key affordances, sized to
/// fit the narrowest panel body (58 columns inside the border).
pub const PANEL_FOOTER_HINT: &str = "arrows move, PgUp/PgDn scroll, Enter confirms, Esc denies";
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
    pub grant_id: String,
    pub initiator: String,
    pub expiry: String,
    pub scope: String,
    focus: PanelAction,
    /// Vertical scroll offset of the scope body; the header and the
    /// actions footer never scroll. `render` clamps the stored offset
    /// to the wrapped bound each frame, through `Cell` like
    /// [`LocalView::output_scroll`].
    body_scroll: Cell<u16>,
}

impl PermissionPanel {
    /// Assembles the panel for one pending effect; `class` is the asked
    /// effect's class and namespaces the limited-grant consent.
    pub fn new(
        verdict: ModeDecision,
        class: EffectClass,
        grant_id: impl Into<String>,
        initiator: impl Into<String>,
        expiry: impl Into<String>,
        scope: impl Into<String>,
    ) -> Self {
        let scope = scope.into();
        let scope = if class == EffectClass::Egress {
            canonical_egress_target(&scope)
        } else {
            scope
        };
        Self {
            verdict,
            class,
            grant_id: grant_id.into(),
            initiator: initiator.into(),
            expiry: expiry.into(),
            scope,
            focus: PanelAction::Deny,
            body_scroll: Cell::new(0),
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
        self.body_scroll.update(|offset| {
            if down {
                offset.saturating_add(1)
            } else {
                offset.saturating_sub(1)
            }
        });
    }

    /// Pinned header: the mandatory fields precede the scope so scarce
    /// rows never hide them (design-brief §4).
    fn header_text(&self) -> String {
        format!(
            "{PANEL_TITLE}\ndecision: {}\neffect: {}\ninitiator: {}\nexpiry: {}\ngrant: {}",
            self.verdict.token(),
            effect_class_label(self.class),
            sanitize_status_cause(&self.initiator),
            sanitize_status_cause(&self.expiry),
            sanitize_status_cause(&self.grant_id),
        )
    }

    /// Scrollable body: the scope, the freely wrapping part (the request
    /// detail carrier arrives with the mode-selection carrier).
    fn body_text(&self) -> String {
        format!("scope: {}", sanitize_status_cause(&self.scope))
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
const PANEL_HEADER_ROWS: u16 = 6;
/// Rows of the pinned panel footer (`footer_text`).
const PANEL_FOOTER_ROWS: u16 = 2;

/// Title of the awaiting-decision state: one versioned question wants a
/// selection before the task resumes.
pub const DECISION_TITLE: &str = "awaiting decision";
/// Transcript note when an answer applied and the task's scheduler node
/// dispatched — the selection, the author it recorded under, and the
/// next observable state.
pub const DECISION_ANSWERED_NOTE: &str = "decision answer recorded; task resumed";
/// Transcript note when the answer committed but the task's tree was
/// already settled or cancelled: nothing will ever dispatch for it, so
/// the note names the settled tree — never "resumed" (INV-021 keeps the
/// durable answer either way).
pub const DECISION_SETTLED_NOTE: &str = "decision answer recorded; task tree already settled";
/// Transcript note when the card closes without an answer: nothing is
/// denied and nothing is applied — the question stays pending for the
/// wire surface, which owns the deferred answer; this card does not
/// reopen for that question this session.
pub const DECISION_LEFT_NOTE: &str =
    "decision left unanswered; question stays pending for the wire surface";
/// Transcript note when the custom draft hits the answer-size bound.
pub const DECISION_DRAFT_LIMIT_NOTE: &str = "custom answer exceeds the size limit";
/// One pinned footer line naming the card's key affordances.
pub const DECISION_FOOTER_HINT: &str = "arrows move, PgUp/PgDn scroll, Enter selects, Esc returns";
/// The footer hint while the custom row is in editing mode.
pub const DECISION_EDITING_HINT: &str = "type text; Enter newline, Esc finish";
/// Author the card records human answers under — the same local spelling
/// the wire surface uses for a human answer.
pub const DECISION_ANSWER_AUTHOR: &str = "human";
/// Transcript note when a paste arrives while the card owns input but
/// the draft is not open: the write is refused and named — the same
/// honesty every other refused append gets — never a silent drop.
pub const DECISION_PASTE_REFUSED_NOTE: &str = "paste refused while the decision card owns input";
/// Transcript note when the pinned question moves under an open card —
/// superseded or answered through another ingress: the card closes
/// honestly instead of keeping live affordances on a question that no
/// longer waits on it.
pub const DECISION_MOVED_NOTE: &str = "decision closed; the question is no longer pending";
/// The consent floor: Enter (commit) and Esc (dismiss) on the card are
/// refused until it has been painted this long. 200 ms sits below the
/// human reaction floor for an unexpected prompt (~200–250 ms), so a
/// refusal can only ever catch input produced unaimed — autorepeat on
/// a held Enter, bytes already in flight over SSH/mosh — never a real
/// answer to a question the operator saw.
pub const DECISION_CONSENT_DELAY: Duration = Duration::from_millis(200);

/// The decision card: one pending versioned question asking for a
/// selection. The card shows the question's five positions plus the
/// always-available multiline custom path; a disabled position stays
/// visible with its reason and can never be selected. Focus and the
/// recommended marker are display state — they never apply anything
/// (PRO-002); only an explicit Enter on a selectable position answers,
/// and the answer rides `TaskStore::answer_question` so stale revisions,
/// replays and stale intent deny through the same gates as the wire
/// surface — and journal the same attempt rows.
#[derive(Debug, Clone, PartialEq)]
pub struct DecisionPanel {
    pub question: Question,
    /// Index into `rows()`: `0..question.options.len()` are option rows,
    /// the last index is the custom-answer row.
    focus: usize,
    /// Vertical scroll offset of the option body; the header and the
    /// footer never scroll. `render` clamps it back each frame through
    /// `Cell` like [`PermissionPanel::body_scroll`].
    body_scroll: Cell<u16>,
    custom_draft: String,
    custom_editing: bool,
    /// Whether the operator scrolled the body away from the frame the
    /// reveal arms would pick. While set, the arms leave the window where
    /// the operator put it — an answer taller than the body is otherwise
    /// pinned to one of its rows on every frame and PgUp/PgDn move
    /// nothing. Moving focus clears it: the next item still has to be
    /// revealed.
    window_held: Cell<bool>,
    /// When this card's first frame flushed to the terminal — `render`
    /// stamps it through `Cell` like the scroll offsets, once. The
    /// consent keys (Enter commit, Esc dismiss) are refused until the
    /// card has been visible [`DECISION_CONSENT_DELAY`]: input produced
    /// before the operator could see the question must never settle or
    /// dismiss an unseen fork.
    first_painted_at: Cell<Option<Instant>>,
}

impl DecisionPanel {
    pub fn new(question: Question) -> Self {
        Self {
            question,
            focus: 0,
            body_scroll: Cell::new(0),
            custom_draft: String::new(),
            custom_editing: false,
            window_held: Cell::new(false),
            first_painted_at: Cell::new(None),
        }
    }

    /// The focused row index — display state only, never a selection.
    pub fn focus(&self) -> usize {
        self.focus
    }

    /// The custom row's index: the last of `rows()`, always reachable.
    pub fn custom_row(&self) -> usize {
        self.question.options.len()
    }

    /// Option rows plus the custom row.
    fn rows(&self) -> usize {
        self.question.options.len() + 1
    }

    /// Whether the custom row is in editing mode (draft input owns keys).
    pub fn custom_editing(&self) -> bool {
        self.custom_editing
    }

    /// The accumulated custom draft — display state until Enter submits it.
    pub fn custom_draft(&self) -> &str {
        &self.custom_draft
    }

    /// Cycles focus across every row including the custom row; wrapping
    /// is intentional so every position is reachable with either arrow.
    pub fn shift_focus(&mut self, backward: bool) {
        self.window_held.set(false);
        let rows = self.rows();
        let offset = if backward { rows - 1 } else { 1 };
        self.focus = (self.focus + offset) % rows;
    }

    /// Whether the operator has scrolled the body since focus last moved.
    fn window_held(&self) -> bool {
        self.window_held.get()
    }

    /// Scrolls the body one line; the header and footer stay pinned.
    pub fn scroll_body(&mut self, down: bool) {
        self.window_held.set(true);
        self.body_scroll.update(|offset| {
            if down {
                offset.saturating_add(1)
            } else {
                offset.saturating_sub(1)
            }
        });
    }

    /// Opens editing on the custom row (Enter on an empty draft) or stops
    /// it (Esc inside editing keeps the draft).
    fn set_custom_editing(&mut self, editing: bool) {
        // The draft grows at its end, so an editing session starts from the
        // window the reveal arms pick — a hold from before it would hide
        // every character the operator types.
        if editing {
            self.window_held.set(false);
        }
        self.custom_editing = editing;
    }

    /// Extends the custom draft with typed or pasted text, bounded by the
    /// same size limit a wire answer carries. Returns false when the
    /// bound rejected the append — the draft keeps what it already held.
    fn push_draft(&mut self, text: &str) -> bool {
        if self.custom_draft.len().saturating_add(text.len()) > TEXT_MAX_BYTES {
            return false;
        }
        self.custom_draft.push_str(text);
        true
    }

    /// Removes the draft's last extended grapheme cluster — a Backspace
    /// that dies mid-cluster would leave a combining mark orphaned. The
    /// segmentation is the render path's own (`styled_graphemes`), which
    /// drops clusters that contain a control char, so a trailing control
    /// (the pasted `\n` the draft deliberately keeps) peels off by its
    /// own bytes; a `\r\n` tail is one cluster and dies together.
    fn pop_grapheme(&mut self) {
        let remove = match self.custom_draft.chars().next_back() {
            None => 0,
            Some('\n') if self.custom_draft.chars().nth_back(1) == Some('\r') => 2,
            Some(ch) if ch.is_control() => ch.len_utf8(),
            Some(_) => Line::raw(self.custom_draft.as_str())
                .styled_graphemes(Style::default())
                .last()
                .map_or(0, |grapheme| grapheme.symbol.len()),
        };
        self.custom_draft.truncate(self.custom_draft.len() - remove);
    }

    /// Pinned header: title, task, and the pair the card's answer pins —
    /// `question_id`/`question_revision` are the fields a reader
    /// verifies. The intent pin rides the journal instead: at the
    /// card's 58-cell floor a third value on this row clipped past the
    /// border, so the header carries only what must stay whole.
    fn header_text(&self) -> String {
        format!(
            "{DECISION_TITLE}\ntask: {}\nquestion: {} rev {}",
            self.question.task_id.0, self.question.question_id.0, self.question.question_revision,
        )
    }

    /// The scrollable body's two parts: the prompt/recommendation
    /// preamble, then one item per row — five option rows plus the
    /// custom row. Item text is sanitized at build so the row-span math
    /// below counts the same graphemes the widget renders.
    fn body_parts(&self) -> (String, Vec<String>) {
        let preamble = format!(
            "question: {}\nrecommended: {} — {}\n",
            sanitize_status_cause(&self.question.prompt),
            sanitize_status_cause(&self.question.recommended_option_id.0),
            sanitize_status_cause(&self.question.recommendation_basis),
        );
        let mut items: Vec<String> = self
            .question
            .options
            .iter()
            .enumerate()
            .map(|(index, option)| {
                let mut row = format!(
                    "{}. {} — {}",
                    index + 1,
                    sanitize_status_cause(&option.label),
                    sanitize_status_cause(&option.consequences),
                );
                if option.option_id == self.question.recommended_option_id {
                    row.push_str(" (recommended)");
                }
                if let Availability::Disabled { reason } = &option.availability {
                    row.push_str(&format!(
                        " — unavailable: {}",
                        sanitize_status_cause(reason)
                    ));
                }
                row
            })
            .collect();
        items.push(self.custom_row_text());
        let items = items
            .iter()
            .enumerate()
            .map(|(index, row)| {
                if index == self.focus {
                    format!("> {row}")
                } else {
                    format!("  {row}")
                }
            })
            .collect();
        (preamble, items)
    }

    /// The custom row's text: the draft while it exists, the affordance
    /// otherwise, tagged while editing so the mode is visible without color.
    fn custom_row_text(&self) -> String {
        let index = self.question.options.len() + 1;
        let draft = if self.custom_draft.is_empty() {
            "type your own answer".to_string()
        } else {
            sanitize_status_cause(&self.custom_draft)
        };
        let editing = if self.custom_editing {
            " (editing)"
        } else {
            ""
        };
        format!("{index}. custom answer — {draft}{editing}")
    }

    /// Stamps the instant this card's first frame reached the terminal —
    /// the consent window starts at first paint, not at open, because
    /// only the paint makes the question visible. `inner_visible` is the
    /// card's painted interior clipped to the viewport: a frame that
    /// clipped it to nothing showed no question content, and an
    /// invisible paint starts no consent clock. Idempotent: later
    /// frames keep the first stamp.
    fn note_first_paint(&self, inner_visible: ratatui::layout::Rect) {
        if inner_visible.is_empty() {
            return;
        }
        if self.first_painted_at.get().is_none() {
            self.first_painted_at.set(Some(Instant::now()));
        }
    }

    /// Whether the card has been visible long enough for a keypress to
    /// have been aimed at it. Never painted fails closed: an unseen
    /// card cannot be consented to.
    fn consent_admitted(&self) -> bool {
        self.first_painted_at
            .get()
            .is_some_and(|painted| painted.elapsed() >= DECISION_CONSENT_DELAY)
    }

    /// Pinned footer: the focus counter with the hidden-row count, then
    /// the affordance hint for the card's current mode.
    fn footer_text(&self, hidden: usize) -> String {
        let focus = if hidden == 0 {
            format!("focus {}/{}", self.focus + 1, self.rows())
        } else {
            format!("focus {}/{} · {hidden} hidden", self.focus + 1, self.rows())
        };
        let hint = if self.custom_editing {
            DECISION_EDITING_HINT
        } else {
            DECISION_FOOTER_HINT
        };
        format!("{focus}\n{hint}")
    }
}

/// Rows of the pinned decision-card header (`DecisionPanel::header_text`).
const DECISION_HEADER_ROWS: u16 = 3;
/// Rows of the pinned decision-card footer (`DecisionPanel::footer_text`).
const DECISION_FOOTER_ROWS: u16 = 2;

/// Start, no connection: input and help are available; login has not happened.
pub const STATUS_DISCONNECTED: &str = "Rivect · not connected · /help for help";
pub const DOCK_EMPTY: &str = "No tasks. Login is a separate explicit action.";
pub const TRANSCRIPT_INPUT: &str = "Input is available. Enter a task or a clarification.";
pub const TRANSCRIPT_NO_PROJECT: &str =
    "No project or index is selected; ordinary replies are not blocked.";
pub const HELP_TEXT: &str = concat!(
    "Commands: Enter submits a task; Esc quits; Ctrl-C cancels.\n",
    "/help shows this list; /new starts an independent conversation;\n",
    "/clear clears the view; /compact folds the context.",
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
/// Scroll affordance on the output status line: PageUp/PageDown move
/// the output body while it is active.
pub const OUTPUT_SCROLL_HINT: &str = "PgUp/PgDn scroll";

pub fn initial_view() -> LocalView {
    LocalView {
        status: STATUS_DISCONNECTED.to_string(),
        dock: vec![DOCK_EMPTY.to_string()],
        context_warning: None,
        dock_stale: None,
        transcript: vec![
            TRANSCRIPT_INPUT.to_string(),
            TRANSCRIPT_NO_PROJECT.to_string(),
        ],
        composer: String::new(),
        output: OutputStream::new(),
        output_scroll: Cell::new(0),
        panel: None,
        decision: None,
        decision_dismissed: None,
    }
}

pub fn render<B: Backend>(terminal: &mut Terminal<B>, view: &LocalView) -> Result<(), B::Error> {
    let mut card_inner = None;
    terminal.draw(|frame| {
        let area = frame.area();
        let output_active = view.output.is_active();
        let mut rows = Vec::with_capacity(7);
        rows.push(Constraint::Length(1));
        rows.push(Constraint::Min(1));
        // The status band takes two rows while it has something to say: a
        // message chained after the transcript is painted below the panel the
        // moment the transcript outgrows it, and the long session AC-072
        // targets is that shape. Its rows are one message each — the warning
        // and the dock's fault mark — so a dead refresh never hides behind a
        // warning. An idle band takes no row, so the panels keep the geometry
        // they have without it.
        let band = status_band(view, usize::from(area.width));
        rows.push(Constraint::Length(if band.is_empty() { 0 } else { 2 }));
        if output_active {
            rows.push(Constraint::Length(1));
            rows.push(Constraint::Min(1));
        }
        rows.push(Constraint::Length(view.dock.len().clamp(1, 3) as u16));
        rows.push(Constraint::Length(1));
        let chunks = ratatui::layout::Layout::vertical(rows).split(area);
        frame.render_widget(
            Paragraph::new(sanitize_status_cause(&view.status)),
            chunks[0],
        );
        frame.render_widget(
            Paragraph::new(
                view.transcript
                    .iter()
                    .map(|line| sanitize_status_cause(line))
                    .collect::<Vec<_>>()
                    .join("\n"),
            ),
            chunks[1],
        );
        frame.render_widget(
            Paragraph::new(band).wrap(ratatui::widgets::Wrap { trim: true }),
            chunks[2],
        );
        let mut next = 3;
        if output_active {
            frame.render_widget(
                Paragraph::new(output_status_line(
                    &view.output,
                    view.panel.is_some() || view.decision.is_some(),
                )),
                chunks[next],
            );
            next += 1;
            // The measured text is the rendered text: clamping the raw
            // stream would count control characters the projection
            // escapes or drops, so the estimate disagrees with the
            // widget's own rows.
            let output_text = sanitize_status_cause(view.output.text());
            // The render owns the region's width and height, so it owns
            // the bound: the stored offset is clamped back each frame
            // and can never run past the content (the overshoot a
            // PageDown run would otherwise leave swallows the next
            // PageUp whole).
            let scroll = clamp_scroll(
                &output_text,
                chunks[next].width,
                chunks[next].height,
                view.output_scroll.get(),
            );
            view.output_scroll.set(scroll);
            frame.render_widget(
                Paragraph::new(output_text.as_str())
                    .wrap(ratatui::widgets::Wrap { trim: false })
                    .scroll((scroll, 0)),
                chunks[next],
            );
            next += 1;
        }
        frame.render_widget(
            Paragraph::new(
                view.dock
                    .iter()
                    .map(|line| sanitize_status_cause(line))
                    .collect::<Vec<_>>()
                    .join("\n"),
            ),
            chunks[next],
        );
        frame.render_widget(
            Paragraph::new(format!("> {}", sanitize_status_cause(&view.composer))),
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
            let body = panel.body_text();
            let body_scroll = clamp_scroll(
                &body,
                regions[1].width,
                regions[1].height,
                panel.body_scroll.get(),
            );
            panel.body_scroll.set(body_scroll);
            frame.render_widget(
                Paragraph::new(body.as_str())
                    .wrap(ratatui::widgets::Wrap { trim: false })
                    .scroll((body_scroll, 0)),
                regions[1],
            );
            frame.render_widget(Paragraph::new(panel.footer_text()), regions[2]);
        }
        if let Some(card) = &view.decision {
            // Modal overlay, same geometry and three-region discipline as
            // the permission panel: pinned header, scrollable position
            // body, pinned focus/hint footer.
            let width = area.width.min(60);
            let height = area.height.saturating_sub(4).max(6);
            let card_area = ratatui::layout::Rect {
                x: area.width.saturating_sub(width) / 2,
                y: area.height.saturating_sub(height) / 2,
                width,
                height,
            };
            frame.render_widget(ratatui::widgets::Clear, card_area);
            let block = ratatui::widgets::Block::bordered();
            let inner = block.inner(card_area);
            // The widgets clip to the buffer; the stamp does too. The
            // question content lives in `inner`, so its viewport
            // intersection is the part of this paint the operator could
            // actually see — empty means the frame showed nothing.
            card_inner = Some(inner.intersection(area));
            frame.render_widget(block, card_area);
            let regions = ratatui::layout::Layout::vertical([
                Constraint::Length(DECISION_HEADER_ROWS),
                Constraint::Min(1),
                Constraint::Length(DECISION_FOOTER_ROWS),
            ])
            .split(inner);
            frame.render_widget(Paragraph::new(card.header_text()), regions[0]);
            let (body, scroll, hidden) = decision_body(
                card,
                regions[1].width,
                regions[1].height,
                card.body_scroll.get(),
            );
            card.body_scroll.set(scroll);
            frame.render_widget(
                Paragraph::new(body.as_str())
                    .wrap(ratatui::widgets::Wrap { trim: false })
                    .scroll((scroll, 0)),
                regions[1],
            );
            frame.render_widget(Paragraph::new(card.footer_text(hidden)), regions[2]);
        }
    })?;
    // The frame just flushed: a card that painted for the first time
    // records the instant its consent window runs from — the earliest
    // moment input could have been aimed at it — but only when the
    // paint left a visible interior cell to aim at.
    if let (Some(card), Some(inner)) = (&view.decision, card_inner) {
        card.note_first_paint(inner);
    }
    Ok(())
}

/// One status line for the streaming output region: the fixed scroll
/// affordance leads, then the typed state and, when retention
/// truncated the stream, the honest capacity note — truncated output
/// is never presented as the whole output. The hint leads the variable
/// tail so a narrow width clips the cause, never the affordance; while
/// a modal — the grant panel or the decision card — owns PgUp/PgDn the
/// hint drops out entirely rather than lie about which keys move.
fn output_status_line(output: &OutputStream, modal_open: bool) -> String {
    let mut line = if modal_open {
        String::new()
    } else {
        format!("{OUTPUT_SCROLL_HINT} · ")
    };
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
    line.push_str(&base);
    if output.head_truncated() {
        line.push_str(&format!(" · {OUTPUT_TRUNCATED_NOTE}"));
    }
    line
}

/// Largest offset that can still render rows of `text` inside a
/// `width`×`height` region under `Paragraph`'s `Wrap { trim: false }`.
/// The row count is the widget's own word-wrap — same graphemes, cell
/// widths, and break decisions — so the clamp neither strands rows
/// (a short estimate) nor blanks the body (a tall one).
fn clamp_scroll(text: &str, width: u16, height: u16, offset: u16) -> u16 {
    // An unscrolled body needs no wrap pass: the clamp can only answer
    // zero, so skip the per-frame row count on the common path.
    if offset == 0 {
        return 0;
    }
    let rows = wrapped_row_count(text, width.max(1));
    let max = rows.saturating_sub(usize::from(height));
    offset.min(u16::try_from(max).unwrap_or(u16::MAX))
}

/// Rows `text` occupies under `Paragraph::wrap(Wrap { trim: false })`.
/// ratatui 0.30.2 keeps `WordWrapper` in a crate-private `reflow`
/// module, so the count ports that algorithm's decisions over the
/// public primitives the widget itself uses — `Text`'s `str::lines`
/// split, `Line::styled_graphemes` (the same grapheme segmentation and
/// the same control-grapheme filtering), `StyledGrapheme::is_whitespace`,
/// and `CellWidth` — instead of estimating by character count.
/// Cargo.lock pins ratatui to the vendored algorithm's version: on any
/// ratatui upgrade, re-diff this port against the new `WordWrapper`
/// source and re-run the PTY geometry matrix — a drifted port silently
/// mis-counts the panel's scroll clamp.
fn wrapped_row_count(text: &str, max_line_width: u16) -> usize {
    Text::from(text)
        .iter()
        .map(|line| wrapped_line_rows(line, max_line_width))
        .sum()
}

/// The wrapped rows one input `line` produces: a direct port of
/// `WordWrapper::process_input` with `trim == false` (the only mode
/// this file renders), tracking widths and symbol counts in place of
/// the grapheme buffers — the break decisions depend on nothing else.
fn wrapped_line_rows(line: &Line<'_>, max_line_width: u16) -> usize {
    let mut wrapped = 0usize;
    // The row under construction (upstream's `pending_line`).
    let mut line_width = 0u16;
    let mut line_symbols = 0usize;
    // The pending word (`pending_word`).
    let mut word_width = 0u16;
    let mut word_symbols = 0usize;
    // The pending whitespace (`pending_whitespace`): per-grapheme
    // widths, because the end-of-line drain consumes them front to back.
    let mut whitespace_width = 0u16;
    let mut whitespace: VecDeque<u16> = VecDeque::new();
    let mut non_whitespace_previous = false;

    for grapheme in line.styled_graphemes(Style::default()) {
        let is_whitespace = grapheme.is_whitespace();
        let symbol_width = grapheme.symbol.cell_width();
        // Symbols wider than the line limit are dropped entirely.
        if symbol_width > max_line_width {
            continue;
        }
        let word_found = non_whitespace_previous && is_whitespace;
        // With `trim == false` the pending word plus its whitespace
        // overflows an empty line exactly when their widths exceed it.
        let untrimmed_overflow =
            line_symbols == 0 && word_width + whitespace_width + symbol_width > max_line_width;
        if word_found || untrimmed_overflow {
            // `trim == false`: pending whitespace always lands on the
            // line, then the word joins it.
            line_symbols += whitespace.len() + word_symbols;
            line_width += whitespace_width + word_width;
            whitespace.clear();
            whitespace_width = 0;
            word_symbols = 0;
            word_width = 0;
        }
        // The pending line filled, or the pending word cannot join it.
        let line_full = line_width >= max_line_width;
        let pending_word_overflow =
            symbol_width > 0 && line_width + whitespace_width + word_width >= max_line_width;
        if line_full || pending_word_overflow {
            let mut remaining = max_line_width.saturating_sub(line_width);
            wrapped += 1;
            line_symbols = 0;
            line_width = 0;
            // Whitespace that still fits the ended row stays with it.
            while let Some(&width) = whitespace.front() {
                if width > remaining {
                    break;
                }
                whitespace_width -= width;
                remaining -= width;
                whitespace.pop_front();
            }
            // The separating whitespace ends with the row it broke.
            if is_whitespace && whitespace.is_empty() {
                continue;
            }
        }
        if is_whitespace {
            whitespace_width += symbol_width;
            whitespace.push_back(symbol_width);
        } else {
            word_width += symbol_width;
            word_symbols += 1;
        }
        non_whitespace_previous = !is_whitespace;
    }
    // Final flush, `trim == false`: pending whitespace always lands.
    line_symbols += whitespace.len() + word_symbols;
    if line_symbols > 0 {
        wrapped += 1;
    }
    // An empty input line still renders one row.
    wrapped.max(1)
}

const TUI_CONNECTION: &str = "tui";

/// A frame the runtime refused, carried as the dispatch error's payload:
/// the typed refusal a caller paints as one transcript line, kept apart
/// from a transport fault, which still leaves through the loop's error
/// path. Same carrier shape as [`TuiExitError`].
#[derive(Debug)]
struct RejectedRequest(String);

impl fmt::Display for RejectedRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for RejectedRequest {}

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
        return Err(io::Error::other(RejectedRequest(message.to_owned())));
    }
    response
        .get("result")
        .cloned()
        .ok_or_else(|| io::Error::other("tui response omitted result"))
}

/// A failed open still owes the operator the boot verdicts the dropped
/// runtime collected, followed by its lock release lines: they ride the
/// error so the caller surfaces them on a channel that is actually
/// visible — the transcript while the alternate screen owns the
/// terminal, the propagated error (through its typed carrier) after the
/// guard restores it.
struct TuiOpenError {
    error: io::Error,
    boot_diagnostics: Vec<String>,
}

/// The typed carrier that joins release lines to a propagated primary
/// error: the primary stays its `source()`, so its kind, errno, payload
/// and own chain are reachable, and its text is the carried lines only.
#[derive(Debug, thiserror::Error)]
enum TuiExitError {
    #[error(fmt = write_exit_lines)]
    Diagnostics {
        #[source]
        primary: io::Error,
        lines: Vec<String>,
    },
}

fn write_exit_lines(
    _primary: &io::Error,
    lines: &[String],
    formatter: &mut fmt::Formatter<'_>,
) -> fmt::Result {
    for (index, line) in lines.iter().enumerate() {
        if index > 0 {
            formatter.write_str("\n")?;
        }
        formatter.write_str(line)?;
    }
    Ok(())
}

/// The context of a runtime open failure inside the TUI: its cause is the
/// [`OwnerError`], held as the `source()`.
#[derive(Debug, thiserror::Error)]
#[error("tui runtime open failed")]
struct RuntimeOpenFailure(#[source] OwnerError);

impl TuiOpenError {
    /// The propagated error is the only channel left once the guard
    /// restores the screen, so the carried lines join it through the
    /// typed [`TuiExitError`] carrier — each already sanitized to a single
    /// line at the recovery boundary. With no lines the error comes back
    /// unchanged; a primary that already is the carrier gets the new lines
    /// appended, so the carrier never nests.
    fn into_io_error(self) -> io::Error {
        let Self {
            error,
            boot_diagnostics,
        } = self;
        if boot_diagnostics.is_empty() {
            return error;
        }
        let (primary, lines) = match error.downcast::<TuiExitError>() {
            Ok(TuiExitError::Diagnostics { primary, mut lines }) => {
                lines.extend(boot_diagnostics);
                (primary, lines)
            }
            Err(error) => (error, boot_diagnostics),
        };
        io::Error::new(primary.kind(), TuiExitError::Diagnostics { primary, lines })
    }
}

/// Delivers the owner's lock release failures once, after the loop's
/// guard and runtime dropped: an `Ok` reports them on the restored
/// screen, an `Err` carries them through [`TuiOpenError::into_io_error`]
/// (the identity on an empty carrier).
fn settle_released<T>(outcome: io::Result<T>) -> io::Result<T> {
    let lines = crate::state::take_release_lines();
    match outcome {
        Ok(value) => {
            report_boot_diagnostics(&lines);
            Ok(value)
        }
        Err(error) => Err(TuiOpenError {
            error,
            boot_diagnostics: lines,
        }
        .into_io_error()),
    }
}

/// Ends a runtime the open could not use: its boot verdicts, then its
/// release lines, are reported once and carried on the error.
fn discard_runtime(mut runtime: Runtime, error: io::Error) -> TuiOpenError {
    let mut boot_diagnostics = std::mem::take(&mut runtime.boot_diagnostics);
    boot_diagnostics.extend(runtime.release());
    report_boot_diagnostics(&boot_diagnostics);
    TuiOpenError {
        error,
        boot_diagnostics,
    }
}

/// The operator text of an error: the one place a context meets its
/// cause. An error carrying release lines is the report of its primary,
/// then `\n` and the lines. Otherwise it is the error's own text and,
/// while the error just written is context-only (an [`OwnerError`], or an
/// `io::Error` holding the runtime open context), `: ` and its source —
/// repeated for that source. The first other error is the original
/// failure: written once, its own chain not walked. At most three texts
/// per primary; any other error is written as its own text alone.
#[must_use]
pub fn failure_report<'a>(error: &'a (dyn std::error::Error + 'static)) -> impl fmt::Display + 'a {
    FailureReport(error)
}

struct FailureReport<'a>(&'a (dyn std::error::Error + 'static));

impl fmt::Display for FailureReport<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_report(self.0, formatter)
    }
}

fn write_report(
    error: &(dyn std::error::Error + 'static),
    formatter: &mut fmt::Formatter<'_>,
) -> fmt::Result {
    if let Some(carrier) = exit_carrier(error) {
        let TuiExitError::Diagnostics { primary, .. } = carrier;
        write_report(primary, formatter)?;
        formatter.write_str("\n")?;
        return fmt::Display::fmt(carrier, formatter);
    }
    write!(formatter, "{error}")?;
    let mut written = error;
    while is_context_only(written) {
        let Some(source) = written.source() else {
            break;
        };
        write!(formatter, ": {source}")?;
        written = source;
    }
    Ok(())
}

fn exit_carrier<'a>(error: &'a (dyn std::error::Error + 'static)) -> Option<&'a TuiExitError> {
    error
        .downcast_ref::<io::Error>()?
        .get_ref()?
        .downcast_ref::<TuiExitError>()
}

fn is_context_only(error: &(dyn std::error::Error + 'static)) -> bool {
    error.is::<OwnerError>()
        || error
            .downcast_ref::<io::Error>()
            .and_then(io::Error::get_ref)
            .is_some_and(|payload| payload.is::<RuntimeOpenFailure>())
}

/// The injected `runtime.status` failure the dock refresh's fault leg
/// reads, named so a test never matches on a bare `is_err`.
#[cfg(test)]
const STATUS_FAULT_REPORT: &str = "runtime.status unavailable";

struct TuiDispatch {
    runtime: Runtime,
    session_id: String,
    /// The dock projection's own measurement of the conversation it watches:
    /// measured once per key change, not once per beat, because assembling
    /// the context is the expensive half of the projection and its bytes only
    /// move when the task's state does.
    context_measurement: Option<ContextMeasurement>,
    /// Test-only fault seam: the next `status()` calls fail, so the dock
    /// refresh's failure path is reachable from the PTY harness. No
    /// production path ever arms it.
    #[cfg(test)]
    status_faults: usize,
}

impl TuiDispatch {
    fn open(data_root: &Path) -> Result<Self, TuiOpenError> {
        // `Runtime::open` already emitted the collected verdicts and the
        // release lines to stderr inside the failed open — emitting here
        // would double the channel — and also carries them on its error,
        // so this arm fills the same transcript/error channels the
        // sibling arms do for a discarded runtime. The cause stays an
        // object under its context; `failure_report` joins them.
        let mut runtime =
            Runtime::open(data_root, Box::new(LoopbackProvider::new())).map_err(|carrier| {
                let boot_diagnostics = carrier.diagnostics().to_vec();
                TuiOpenError {
                    error: io::Error::other(RuntimeOpenFailure(carrier.into_source())),
                    boot_diagnostics,
                }
            })?;
        let result = match dispatch_tui_request(
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
        ) {
            Ok(result) => result,
            // The runtime is discarded on this path: its verdicts and
            // release lines are reported best-effort and carried on the
            // error too — whether stderr is visible depends on the
            // alternate screen, which only the caller knows.
            Err(error) => return Err(discard_runtime(runtime, error)),
        };
        let Some(session_id) = result
            .get("session_id")
            .and_then(Value::as_str)
            .map(str::to_owned)
        else {
            // Same obligation as the dispatch arm: the dropped runtime
            // must not take its unresolved verdicts with it.
            return Err(discard_runtime(
                runtime,
                io::Error::other("tui session.open omitted session_id"),
            ));
        };
        Ok(Self {
            runtime,
            session_id,
            context_measurement: None,
            #[cfg(test)]
            status_faults: 0,
        })
    }

    /// Arms the injected `status()` failures the dock refresh has to
    /// survive: the counter is one-shot and consumed call by call.
    #[cfg(test)]
    fn fail_status(&mut self, count: usize) {
        self.status_faults = count;
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

    /// `view.clear`: the runtime answers that the kind is served; the
    /// rows it drops are the composer's own projection, so they are
    /// cleared by the caller and nothing durable is addressed.
    fn clear_view(&mut self) -> io::Result<()> {
        dispatch_tui_request(
            &mut self.runtime,
            json!({
                "jsonrpc": "2.0",
                "id": 4,
                "method": "command.execute",
                "params": {
                    "schema_version": 1,
                    "session_id": self.session_id,
                    "command": { "kind": "view.clear" },
                }
            }),
        )?;
        Ok(())
    }

    /// `session.new`: a fresh conversation on this connection. The
    /// dispatch follows the session the runtime minted, so every later
    /// request — status included — reads the new one, and the session it
    /// returns stays addressable for resume.
    fn new_session(&mut self) -> io::Result<String> {
        let previous = self.session_id.clone();
        let result = dispatch_tui_request(
            &mut self.runtime,
            json!({
                "jsonrpc": "2.0",
                "id": 5,
                "method": "command.execute",
                "params": {
                    "schema_version": 1,
                    "session_id": self.session_id,
                    "command": { "kind": "session.new" },
                }
            }),
        )?;
        let session_id = result
            .get("session_id")
            .and_then(Value::as_str)
            .ok_or_else(|| io::Error::other("tui session.new omitted session_id"))?;
        self.session_id = session_id.to_string();
        Ok(previous)
    }

    /// The dock's projection for one pass: the rows `runtime.status` carries
    /// plus the near-full warning the assembled context earns. Both reads are
    /// one projection, so a store that cannot answer one of them leaves the
    /// previous frame painted instead of half-updating it.
    fn dock_projection(
        &mut self,
        pending: Option<&TaskId>,
    ) -> io::Result<(Vec<String>, Option<ContextWarning>)> {
        let status = self.status()?;
        let warning = self.near_full_warning(&status, pending)?;
        Ok((task_dock(&status), warning))
    }

    /// The near-full warning for the conversation the operator is reading
    /// (AC-072, DEC-013): the task this view submitted while it is still
    /// pending, else the newest row the status page carries — never the
    /// oldest, which in a session with more than one task is a conversation
    /// that may have settled long ago. The measurement is the context's own
    /// assembled bytes, never a token estimate. `[context] auto_compact =
    /// true` silences the line, because nothing compacts automatically in
    /// this build — the key controls the guard and nothing else.
    ///
    /// Assembling a context is the expensive half of the beat, and the bytes
    /// only move when the task's state does, so the measurement is remembered
    /// under the subject's revision (with its id and the setting) and reused
    /// until that key moves or [`CONTEXT_MEASURE_INTERVAL`] passes.
    fn near_full_warning(
        &mut self,
        status: &Value,
        pending: Option<&TaskId>,
    ) -> io::Result<Option<ContextWarning>> {
        let auto_compact = self
            .runtime
            .effective()
            .parsed
            .as_ref()
            .is_some_and(Config::auto_compact);
        let items = status
            .get("todo")
            .and_then(|todo| todo.get("items"))
            .and_then(Value::as_array);
        let newest = items
            .and_then(|items| items.last())
            .and_then(|item| item.get("task_id"))
            .and_then(Value::as_str)
            .map(|task_id| TaskId(task_id.to_string()));
        let Some(task_id) = pending.cloned().or(newest) else {
            return Ok(None);
        };
        let revision = items
            .and_then(|items| {
                items.iter().find(|item| {
                    item.get("task_id").and_then(Value::as_str) == Some(task_id.0.as_str())
                })
            })
            .and_then(|item| item.get("task_revision"))
            .and_then(Value::as_u64);
        let key = ContextMeasureKey {
            task_id: task_id.clone(),
            revision,
            auto_compact,
        };
        let now = Instant::now();
        if let Some(measured) = &self.context_measurement
            && measured.answers(&key, now)
        {
            return Ok(measured.warning.clone());
        }
        // `[context] auto_compact = true` silences the line, and nothing
        // compacts automatically in this build — the key controls the guard
        // and nothing else, so a silenced projection assembles nothing.
        let warning = if auto_compact {
            None
        } else {
            let context = self
                .runtime
                .store()
                .assembled_context(&task_id)
                .map_err(|error| {
                    io::Error::other(format!("tui context measurement failed: {error}"))
                })?;
            nearly_full_warning(&task_id, context.text.len())
        };
        self.context_measurement = Some(ContextMeasurement {
            key,
            warning: warning.clone(),
            taken: now,
        });
        Ok(warning)
    }

    /// `context.compact`: the owner's forced compaction of one task's
    /// episodic history (AC-049) — the continuation the near-full warning
    /// names, reached from the composer. An accepted fold reports what it
    /// replaced and what it left; a fold the owner refuses stays the
    /// caller's to paint, never an exit.
    fn compact_context(&mut self, task: &TaskId) -> io::Result<(u64, u64, u64)> {
        let result = dispatch_tui_request(
            &mut self.runtime,
            json!({
                "jsonrpc": "2.0",
                "id": 6,
                "method": "command.execute",
                "params": {
                    "schema_version": 1,
                    "session_id": self.session_id,
                    "command": { "kind": "context.compact" },
                    "task_id": task.0,
                }
            }),
        )?;
        let read = |name: &str| -> io::Result<u64> {
            result
                .get(name)
                .and_then(Value::as_u64)
                .ok_or_else(|| io::Error::other(format!("tui context.compact omitted {name}")))
        };
        Ok((
            read("before_bytes")?,
            read("after_bytes")?,
            read("folded_records")?,
        ))
    }

    fn status(&mut self) -> io::Result<Value> {
        #[cfg(test)]
        if self.status_faults > 0 {
            self.status_faults -= 1;
            return Err(io::Error::other(STATUS_FAULT_REPORT));
        }
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

/// The dock rows a `runtime.status` result renders: one line per todo
/// item, then the profile pair. A line keeps its first blocker's reason;
/// a task the plan holds appends the first plan blocker's capability, so
/// a plan pause is never a bare "blocked". A line without a plan blocker
/// keeps its reason-only form.
pub fn task_dock(status: &Value) -> Vec<String> {
    let mut lines: Vec<String> = status
        .get("todo")
        .and_then(|todo| todo.get("items"))
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    let task_id = item.get("task_id").and_then(Value::as_str)?;
                    let lifecycle = item.get("lifecycle").and_then(Value::as_str)?;
                    let blockers = item.get("blockers").and_then(Value::as_array);
                    let reason = blockers
                        .and_then(|blockers| blockers.first())
                        .and_then(|blocker| blocker.get("reason"))
                        .and_then(Value::as_str);
                    let capability = blockers.and_then(|blockers| {
                        blockers
                            .iter()
                            .filter(|blocker| {
                                blocker.get("owner").and_then(Value::as_str)
                                    == Some(crate::state::PLAN_BLOCKER_OWNER)
                            })
                            .find_map(|blocker| {
                                blocker
                                    .get("condition")
                                    .and_then(|condition| condition.get("action_id"))
                                    .and_then(Value::as_str)
                            })
                    });
                    Some(match (reason, capability) {
                        (Some(reason), Some(capability)) => {
                            format!("task {task_id}: {lifecycle} ({reason}: {capability})")
                        }
                        (Some(reason), None) => format!("task {task_id}: {lifecycle} ({reason})"),
                        (None, _) => format!("task {task_id}: {lifecycle}"),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    // The pending/active profile pair rides the same status payload
    // (AC-047): a switch waiting for the next request shows beside the
    // active binding, a converged pair names the bound profile once.
    if let Some(profile) = status.get("profile") {
        let pending = profile.get("pending").and_then(Value::as_str);
        let active = profile.get("active").and_then(Value::as_str);
        match (pending, active) {
            (Some(pending), Some(active)) if pending != active => {
                lines.push(format!("profile: {active} active → {pending} pending"));
            }
            (Some(pending), Some(_)) => lines.push(format!("profile: {pending}")),
            // A pending profile with no active binding still shows —
            // tagged, so it never reads as the bound one.
            (Some(pending), None) => {
                lines.push(format!("profile: {pending} pending"));
            }
            (None, Some(active)) => lines.push(format!("profile: {active}")),
            (None, None) => {}
        }
    }
    if lines.is_empty() {
        return vec![DOCK_EMPTY.to_string()];
    }
    lines
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
    store: &mut StoreWriter<'_>,
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
fn confirm_panel_action(view: &mut LocalView, store: &mut StoreWriter<'_>) {
    if let Some(mut panel) = view.panel.take() {
        match panel.confirm() {
            PanelAction::Deny => {
                view.transcript.push(PANEL_DENIED_NOTE.to_string());
            }
            PanelAction::AllowOnce => {
                view.transcript.push(PANEL_ALLOWED_NOTE.to_string());
            }
            PanelAction::LimitedGrant => {
                if !grant_id_is_key_safe(&panel.grant_id) {
                    panel.focus_deny();
                    view.panel = Some(panel);
                    view.transcript
                        .push("limited grant recording failed: grant id is not valid".to_string());
                    return;
                }
                let Some(scope) = preapproval_scope(panel.class, &panel.grant_id, &panel.scope)
                else {
                    panel.focus_deny();
                    view.panel = Some(panel);
                    view.transcript.push(
                        "limited grant recording failed: scope is not valid unicode".to_string(),
                    );
                    return;
                };
                match store.record_preapproval(&scope, PANEL_GRANTOR, LIMIT_GRANT_TTL_SECONDS) {
                    Ok(()) => {
                        view.transcript.push(PANEL_LIMITED_NOTE.to_string());
                    }
                    Err(source) => {
                        panel.focus_deny();
                        view.panel = Some(panel);
                        view.transcript.push(format!(
                            "limited grant recording failed: {}",
                            sanitize_status_cause(&source.to_string())
                        ));
                    }
                }
            }
        }
    }
}

/// Handles one terminal event while the decision card is open — the one
/// production handler, shared by the TUI loop and the PTY harness.
/// Returns false when the caller should exit with the cancel code
/// (Ctrl-C). Enter applies only the focused position — an enabled
/// option, or the custom row's draft; a disabled row refuses with its
/// reason and an empty custom row opens editing instead of submitting
/// nothing. The answer rides `TaskStore::answer_question`: a store
/// denial is journaled there, noted here, and closes the card — the
/// question's state underneath has already moved, so a stale card must
/// not linger. Esc returns without answering; the question stays
/// pending and the transcript says so. Consent admission — refusing
/// Enter/Esc until the card has been visible [`DECISION_CONSENT_DELAY`]
/// — stays with the loop so this handler needs no clock to test.
pub fn handle_decision_event(
    event: &TermEvent,
    view: &mut LocalView,
    rt: &mut Runtime,
    session_id: &SessionId,
) -> bool {
    let (code, modifiers) = match event {
        // Only a discrete press is aimed input. A held key's autorepeat
        // carries no new decision — the operator pushed once — so
        // `Repeat` dies at the gate for every key: it cannot commit,
        // dismiss, or steer focus on a card nobody re-chose.
        TermEvent::Key(KeyEvent {
            code,
            modifiers,
            kind: KeyEventKind::Press,
            ..
        }) => (*code, *modifiers),
        // Bracketed paste is atomic: its bytes join the draft as text,
        // never as keys — a pasted newline must not submit.
        TermEvent::Paste(text) => {
            if let Some(card) = view.decision.as_mut() {
                if card.custom_editing {
                    if !card.push_draft(text) {
                        view.transcript.push(DECISION_DRAFT_LIMIT_NOTE.to_string());
                    }
                } else {
                    // A composer-aimed paste while the card owns input is
                    // a refused write — name it like every other refused
                    // append instead of dropping the text silently.
                    view.transcript
                        .push(DECISION_PASTE_REFUSED_NOTE.to_string());
                }
            }
            return true;
        }
        _ => return true,
    };
    if code == KeyCode::Char('c') && modifiers.contains(KeyModifiers::CONTROL) {
        return false;
    }
    let Some(card) = view.decision.as_mut() else {
        return true;
    };
    if card.custom_editing {
        match code {
            KeyCode::Esc => card.set_custom_editing(false),
            // The draft append is the guard: a rejected append — never a
            // silent truncate — lands the limit note instead.
            KeyCode::Enter if card.push_draft("\n") => {}
            KeyCode::Enter => {
                view.transcript.push(DECISION_DRAFT_LIMIT_NOTE.to_string());
            }
            KeyCode::Backspace => card.pop_grapheme(),
            KeyCode::Char(ch) if types_text(modifiers) && !card.push_draft(&ch.to_string()) => {
                view.transcript.push(DECISION_DRAFT_LIMIT_NOTE.to_string());
            }
            _ => {}
        }
        return true;
    }
    match code {
        KeyCode::Left
        | KeyCode::BackTab
        | KeyCode::Right
        | KeyCode::Tab
        | KeyCode::Up
        | KeyCode::Down => {
            let backward = matches!(code, KeyCode::Left | KeyCode::BackTab | KeyCode::Up);
            card.shift_focus(backward);
        }
        KeyCode::PageUp | KeyCode::PageDown => card.scroll_body(code == KeyCode::PageDown),
        KeyCode::Enter => apply_decision_choice(view, rt, session_id),
        // Esc returns the question untouched: the card closes, the fork
        // stays pending — never a denial and never an implied answer —
        // and the poll must not resurrect the same card an instant later.
        KeyCode::Esc => {
            if let Some(card) = view.decision.take() {
                view.decision_dismissed = Some(card.question.question_id);
                view.transcript.push(DECISION_LEFT_NOTE.to_string());
            }
        }
        _ => {}
    }
    true
}

/// Resolves Enter on the focused row: an enabled option applies its
/// selection; a disabled one refuses with its reason and the card stays
/// open; the custom row opens editing on an empty draft and submits the
/// draft otherwise.
fn apply_decision_choice(view: &mut LocalView, rt: &mut Runtime, session_id: &SessionId) {
    let Some(mut card) = view.decision.take() else {
        return;
    };
    if card.focus() == card.custom_row() {
        if card.custom_draft().trim().is_empty() {
            card.set_custom_editing(true);
            view.decision = Some(card);
            return;
        }
        let selection = AnswerSelection::Custom {
            text: card.custom_draft().to_string(),
        };
        answer_from_card(view, rt, session_id, &card, selection);
        return;
    }
    let Some(option) = card.question.options.get(card.focus()) else {
        view.decision = Some(card);
        return;
    };
    match &option.availability {
        Availability::Disabled { reason } => {
            view.transcript.push(format!(
                "decision position unavailable: {}",
                sanitize_status_cause(reason)
            ));
            view.decision = Some(card);
        }
        Availability::Enabled => {
            let selection = AnswerSelection::Option {
                option_id: option.option_id.clone(),
            };
            answer_from_card(view, rt, session_id, &card, selection);
        }
    }
}

/// Commits the card's pinned question id/revision through the shared
/// answer seam, then resumes the task through the same scheduler path
/// the wire answer takes — a committed answer that never submits its
/// runnable node leaves the task parked on a drained question. A denial
/// keeps the attempt journaled, lands on the transcript with the typed
/// reason, and closes the card — the stored question already moved past
/// the card's copy.
fn answer_from_card(
    view: &mut LocalView,
    rt: &mut Runtime,
    session_id: &SessionId,
    card: &DecisionPanel,
    selection: AnswerSelection,
) {
    match rt.owner.store.answer_question(
        session_id,
        &card.question.task_id,
        &card.question.question_id,
        card.question.question_revision,
        &selection,
        DECISION_ANSWER_AUTHOR,
    ) {
        Ok(_) => match rt.resume_answered(session_id, &card.question.task_id, selection) {
            Ok(ResumeAdmission::Drained) => {
                view.transcript.push(DECISION_ANSWERED_NOTE.to_string());
            }
            // The committed answer grew nothing runnable — a cancelled or
            // settled subtree never dispatches again, so the note says
            // "settled", never "resumed".
            Ok(ResumeAdmission::Tombstoned) => {
                view.transcript.push(DECISION_SETTLED_NOTE.to_string());
            }
            // The answer committed; only the resume failed — the note
            // names that exactly, never claims "resumed".
            Err(error) => view.transcript.push(format!(
                "decision answer recorded; resume failed: {}",
                sanitize_status_cause(&error.to_string())
            )),
        },
        Err(error) => view.transcript.push(format!(
            "decision answer denied: {}",
            sanitize_status_cause(&error.to_string())
        )),
    }
}

/// The decision body and its scroll math: `body_parts` is already the
/// rendered text, so per-item wrapped spans are exact; the focused
/// item's span is revealed when it falls out of the window unless the
/// operator has scrolled the body away, and the hidden count names only
/// the rows that stay fully outside.
fn decision_body(
    card: &DecisionPanel,
    width: u16,
    height: u16,
    offset: u16,
) -> (String, u16, usize) {
    let (preamble, items) = card.body_parts();
    let body_text = format!("{preamble}{}", items.join("\n"));
    let width = width.max(1);
    let mut spans = Vec::with_capacity(items.len());
    let mut cursor = wrapped_row_count(&preamble, width);
    for item in &items {
        let rows = wrapped_row_count(item, width);
        spans.push((cursor, cursor + rows));
        cursor += rows;
    }
    let focus_span = spans
        .get(card.focus().min(items.len().saturating_sub(1)))
        .copied()
        .unwrap_or((0, 0));
    let mut scroll = usize::from(clamp_scroll(&body_text, width, height, offset));
    let bottom = scroll + usize::from(height);
    // Reveal the focused item: scroll down only as far as needed, then
    // up if the item's end fell at or above the window. An item taller
    // than the body is never fully inside, so the up arm no longer drags
    // the window back to its first row every frame — while the operator
    // holds the window (`scroll_body`) neither arm fires at all, and the
    // answer scrolls like the rest of the body.
    if !card.window_held() {
        if focus_span.1 > bottom {
            scroll = focus_span.1.saturating_sub(usize::from(height));
        }
        if focus_span.1 <= scroll {
            scroll = focus_span.0;
        }
    }
    let scroll = usize::from(clamp_scroll(
        &body_text,
        width,
        height,
        u16::try_from(scroll).unwrap_or(u16::MAX),
    ));
    let bottom = scroll + usize::from(height);
    let hidden = spans
        .iter()
        .filter(|(start, end)| *end <= scroll || *start >= bottom)
        .count();
    (body_text, u16::try_from(scroll).unwrap_or(u16::MAX), hidden)
}

/// A `Char` is draft text only when its modifiers are empty or Shift —
/// plus, on Windows, the AltGr shapes `types_text_altgr` names. A bare
/// Ctrl or Alt chord is a command neither draft surface binds —
/// inserting its letter would type "w" for Ctrl+W. Off Windows the
/// CONTROL|ALT bits are exactly that: a real chord (unix AltGr is
/// ISO_Level3_Shift and never produces them), so the pair stays dead
/// there the way it was before the Windows AltGr admission.
fn types_text(modifiers: KeyModifiers) -> bool {
    modifiers.is_empty()
        || modifiers == KeyModifiers::SHIFT
        || (cfg!(windows) && types_text_altgr(modifiers))
}

/// The modifier sets crossterm 0.29 reports for AltGr on Windows:
/// CONTROL|ALT (`@ € { [ ] } \ ~`, `ąćęłńóśźż`) and, for the shifted
/// level, SHIFT|CONTROL|ALT (`Ą`) — crossterm keeps SHIFT_PRESSED on
/// the char, so the pair alone under-admits. Windows itself conflates
/// the pair with AltGr (L-Ctrl + R-Alt synthesizes it), so no real
/// chord is lost by treating these as text there. Kept separate from
/// the platform gate so every build can exercise the shape — only
/// `types_text` decides whether the host admits it.
fn types_text_altgr(modifiers: KeyModifiers) -> bool {
    modifiers == (KeyModifiers::CONTROL | KeyModifiers::ALT)
        || modifiers == (KeyModifiers::SHIFT | KeyModifiers::CONTROL | KeyModifiers::ALT)
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

/// One bracketed paste lands atomically in the composer. The composer
/// is a single line, so each line break joins with a space — a pasted
/// newline is draft text, never the early submit the pre-bracketed
/// byte stream produced. `append_composer_char` keeps the same size
/// bound typing does. On a terminal that does not honor bracketed
/// paste the raw byte stream still arrives: its `\r` submits this
/// composer — and while a decision card owns the keys it can answer
/// the card the same unaimed way.
fn append_composer_paste(view: &mut LocalView, text: &str) {
    for (index, line) in text
        .split(['\r', '\n'])
        .filter(|line| !line.is_empty())
        .enumerate()
    {
        if index > 0 {
            append_composer_char(view, ' ');
        }
        for ch in line.chars() {
            append_composer_char(view, ch);
        }
    }
}

/// Boot recovery diagnostics join the transcript where the human reads
/// them — a verdict that must be resolved cannot ride stderr inside the
/// alternate screen.
fn surface_boot_diagnostics(view: &mut LocalView, runtime: &Runtime) {
    view.transcript.extend_from_slice(&runtime.boot_diagnostics);
}

/// A failed open's carried verdicts join the transcript ahead of the
/// error line itself: the operator reads what must be resolved on the
/// same surface the TUI keeps painting.
fn note_open_failure(view: &mut LocalView, failure: &TuiOpenError) {
    view.transcript.extend_from_slice(&failure.boot_diagnostics);
    view.transcript.push(format!(
        "session open failed: {}",
        sanitize_status_cause(&failure_report(&failure.error).to_string())
    ));
}

/// Cap on the post-paint input drain below. The drain clears the queue
/// of unaimed input a card's first frame can race — a burst sent while
/// the paint was in flight — but it must not spin forever: under a
/// sustained byte flood an unbounded drain starves the loop, Ctrl-C
/// included. Leftovers degrade to dead navigation only, because the
/// consent floor — not the drain — is what refuses an unaimed Enter or
/// Esc. 64 events covers a realistic paste-tail burst by a wide margin.
const PRE_PAINT_DRAIN_CAP: usize = 64;

/// The continuation the near-full warning names — the same token the
/// composer parses, so the printed command and the accepted input cannot
/// diverge (DEC-014).
const COMPACT_TOKEN: &str = "/compact";
/// The share of the admission ceiling at which the assembled context counts
/// as nearly full (AC-072, DEC-013). The ceiling is
/// [`crate::contracts::MODEL_WIRE_MAX_BYTES`], the largest request the broker
/// admits; the context is measured in the bytes `assembled_context` serves,
/// because the tree has no token counter to measure it with.
const CONTEXT_NEARLY_FULL_PERCENT: usize = 80;

/// The warning a context of `bytes` bytes earns, or nothing while it still
/// has room. The task its continuation folds rides along: with more than one
/// conversation open, the bytes alone do not say whose.
fn nearly_full_warning(task: &TaskId, bytes: usize) -> Option<ContextWarning> {
    let percent = bytes.saturating_mul(100) / crate::contracts::MODEL_WIRE_MAX_BYTES;
    (percent >= CONTEXT_NEARLY_FULL_PERCENT).then(|| ContextWarning {
        task_id: task.clone(),
        percent,
    })
}

/// The warning's own row of the status band: the condition and the
/// continuation every width reads, and — only while the row has room for it —
/// the task that continuation folds. The band's rows are one message each, so
/// a name the row cannot hold is dropped rather than wrapped into the dock's
/// fault mark below it.
fn warning_row(warning: &ContextWarning, width: usize) -> String {
    let head = format!(
        "Context {}% full (auto-compact off): {COMPACT_TOKEN}",
        warning.percent
    );
    let named = format!("{head} folds task {}", warning.task_id.0);
    if named.chars().count() <= width {
        named
    } else {
        head
    }
}

/// The band between the transcript and the dock: the near-full warning first,
/// the dock's own fault mark second, one message per row so a dead refresh
/// stays visible while a warning is live too. Both sit here rather than after
/// the transcript, whose tail a long session pushes off the panel. Each
/// message is written to fit its row at the 60-column acceptance geometry;
/// the wrap is the backstop for a fault cause that outruns it.
fn status_band(view: &LocalView, width: usize) -> String {
    let mut rows: Vec<String> = Vec::new();
    if let Some(warning) = &view.context_warning {
        rows.push(sanitize_status_cause(&warning_row(warning, width)));
    }
    if let Some(stale) = &view.dock_stale {
        // The cause is foreign text: a newline in it would take the row the
        // message below owns, so the row keeps nothing but its own line.
        rows.push(sanitize_status_cause(stale).replace('\n', " "));
    }
    rows.join("\n")
}

/// The loop's input wait: one pass per interval.
const POLL_INTERVAL: Duration = Duration::from_millis(250);
/// The dock follows `runtime.status` on the loop's own beat, so a
/// lifecycle change paints on the next pass at the latest — and `render`
/// never reads the store for it.
const DOCK_REFRESH_INTERVAL: Duration = POLL_INTERVAL;

/// Runs the minimal fullscreen loop. Esc quits normally, Ctrl-C cancels
/// (exit 130). The guard guarantees terminal restoration on both paths and on
/// panic. Once the guard and the runtime are gone, the owner's lock release
/// failures are reported on the restored screen, or carried on the
/// returned error.
///
/// # Errors
/// An error carrying release lines keeps the primary's kind and exposes
/// the primary through `source()`; [`failure_report`] presents it. A
/// runtime open failure's chain runs from its context through the
/// `OwnerError` to the producer's original error.
pub fn run_tui(data_root: &Path) -> io::Result<i32> {
    drive_tui(data_root, |_, _| Ok(()))
}

/// The loop behind [`run_tui`], settled: after the loop's guard and
/// runtime dropped, [`settle_released`] delivers the release failures
/// once. `between_passes` runs at the top of every pass while a dispatch
/// is open; the in-crate card driver serves its control commands there,
/// and an `Err` leaves through the loop's own error path.
fn drive_tui<F>(data_root: &Path, between_passes: F) -> io::Result<i32>
where
    F: FnMut(&mut TuiDispatch, Option<&TaskId>) -> io::Result<()>,
{
    settle_released(tui_loop(data_root, between_passes))
}

/// Painted for a leading-slash input the vocabulary does not serve: the
/// operator gets the way back to the vocabulary, not a model call.
const COMPOSER_USAGE: &str = "Unknown command. /help lists the available commands.";

/// Painted when `/clear` drops the rows: what was read is gone from the
/// view, and what was stored behind it is not.
const VIEW_CLEARED_NOTE: &str = "View cleared; the stored conversation is unchanged.";

/// Painted when a `context.compact` is accepted: what the fold replaced and
/// what it left, so the operator sees the context actually shrank.
const CONTEXT_COMPACTED: &str = "Context compacted";

/// Painted when `/compact` runs with no conversation to fold: a plain line,
/// never the wire's own field name.
const NOTHING_TO_COMPACT: &str = "No conversation to compact yet; submit a task first.";

/// Drops what the operator was reading — transcript rows and streamed
/// output — and keeps the session and the stored conversation: `/clear` is
/// a view operation, never a delete.
fn reset_view_rows(view: &mut LocalView) {
    let fresh = initial_view();
    view.transcript = fresh.transcript;
    // The dock is a projection of `runtime.status`, refreshed by the loop,
    // so `/clear` does not blank it: live task state is not reading surface.
    view.output = fresh.output;
    view.output_scroll = fresh.output_scroll;
}

/// The runtime's own refusal message, when a dispatch fault is a rejected
/// frame rather than a transport failure.
fn rejection_message(error: &io::Error) -> Option<&str> {
    error
        .get_ref()?
        .downcast_ref::<RejectedRequest>()
        .map(|refusal| refusal.0.as_str())
}

/// A refused frame is a painted line, and only a transport fault is a
/// fault: the owner's refusal names the command on the transcript so the
/// loop keeps serving the session the operator is reading, while the fault
/// still leaves through the loop's error path.
fn refusal_or_fault(view: &mut LocalView, command: &str, error: io::Error) -> io::Result<()> {
    match rejection_message(&error) {
        Some(cause) => {
            view.transcript.push(format!("{command} refused: {cause}"));
            Ok(())
        }
        None => Err(error),
    }
}

/// The loop's dispatch, opened on the first command that needs it. A
/// failed open's carried verdicts fold into the propagated error: the
/// alternate screen owns the terminal, so stderr is a dead channel here.
fn ensure_dispatch<'a>(
    tui_dispatch: &'a mut Option<TuiDispatch>,
    view: &mut LocalView,
    data_root: &Path,
) -> io::Result<&'a mut TuiDispatch> {
    if tui_dispatch.is_none() {
        let dispatch = TuiDispatch::open(data_root).map_err(TuiOpenError::into_io_error)?;
        surface_boot_diagnostics(view, &dispatch.runtime);
        *tui_dispatch = Some(dispatch);
    }
    tui_dispatch
        .as_mut()
        .ok_or_else(|| io::Error::other("tui dispatch unavailable"))
}

/// Runs one Enter on a non-empty composer. A command the vocabulary
/// serves runs; a refusal paints its typed line and the loop keeps
/// serving, while a transport fault still leaves through the loop's error
/// path. The draft is consumed on every path: the operator asked once.
///
/// Only an exact match is a command: a document that mentions `/clear` on
/// one line, an argument and a near miss are never one, so none of them can
/// run, and none of them becomes a paid task either.
fn run_composer_command(
    input: &str,
    view: &mut LocalView,
    tui_dispatch: &mut Option<TuiDispatch>,
    data_root: &Path,
    pending_task: &mut Option<TaskId>,
) -> io::Result<()> {
    view.composer.clear();
    match input {
        "/help" => {
            view.transcript.push(HELP_TEXT.to_string());
            Ok(())
        }
        "/new" => {
            let dispatch = ensure_dispatch(tui_dispatch, view, data_root)?;
            match dispatch.new_session() {
                Ok(previous) => {
                    reset_view_rows(view);
                    // The card poll follows the conversation the operator
                    // is reading: a question the previous session left
                    // pending is not this conversation's to answer.
                    *pending_task = None;
                    // The warning measured the previous session's task, so
                    // the continuation it names is not this conversation's
                    // either: a `/compact` before the next projection beat
                    // would fold work this view no longer shows.
                    view.context_warning = None;
                    // The dock is a projection: the next beat paints it
                    // from the new session, so no read here can exit the
                    // TUI for a frame it is about to draw anyway.
                    view.transcript.push(format!(
                        "New conversation: {} (previous: {previous})",
                        dispatch.session_id
                    ));
                    Ok(())
                }
                Err(error) => refusal_or_fault(view, input, error),
            }
        }
        "/clear" => {
            let dispatch = ensure_dispatch(tui_dispatch, view, data_root)?;
            match dispatch.clear_view() {
                Ok(()) => {
                    reset_view_rows(view);
                    view.transcript.push(VIEW_CLEARED_NOTE.to_string());
                    Ok(())
                }
                Err(error) => refusal_or_fault(view, input, error),
            }
        }
        COMPACT_TOKEN => {
            // The task the painted warning measured is the one its
            // continuation folds; without a warning the composer folds the
            // task it last submitted. With neither there is no conversation
            // to fold, and a plain line says so instead of the wire's own
            // field name.
            let task = view
                .context_warning
                .as_ref()
                .map(|warning| warning.task_id.clone())
                .or_else(|| pending_task.clone());
            let Some(task) = task else {
                view.transcript.push(NOTHING_TO_COMPACT.to_string());
                return Ok(());
            };
            let dispatch = ensure_dispatch(tui_dispatch, view, data_root)?;
            match dispatch.compact_context(&task) {
                Ok((before, after, folded)) => {
                    view.transcript.push(format!(
                        "{CONTEXT_COMPACTED}: {before} → {after} bytes, {folded} records folded."
                    ));
                    Ok(())
                }
                Err(error) => refusal_or_fault(view, input, error),
            }
        }
        _ if input.starts_with('/') => {
            view.transcript.push(COMPOSER_USAGE.to_string());
            Ok(())
        }
        _ => {
            let dispatch = ensure_dispatch(tui_dispatch, view, data_root)?;
            let (status, task_id) = dispatch.submit(input)?;
            *pending_task = Some(TaskId(task_id.clone()));
            view.dock = task_dock(&dispatch.status()?);
            view.transcript
                .push(format!("Submitted task: {input} ({status}: {task_id})"));
            Ok(())
        }
    }
}

/// Re-projects the dock from `runtime.status`: the row an operator
/// watches is a live view of the store, not the value a submit cached. The
/// near-full warning rides the same projection, so the line that names the
/// condition is dropped by the beat that sees it gone (AC-072). A failed
/// read keeps the rows and the warning already painted — a dead refresh must
/// never blank a dock that was telling the truth a pass ago — and from the
/// second consecutive failure on, the status line marks itself, so a dead
/// refresh cannot pass for a healthy idle dock and a long transcript cannot
/// clip the mark. The mark holds for the whole run rather than one beat of
/// it: the fail it names is the run, so every later failing beat writes the
/// same line again (idempotent) and only a read that succeeds clears it. The
/// dock is already stale, and a line rewritten per interval would bury the
/// operator under one fault.
fn refresh_dock(
    view: &mut LocalView,
    dispatch: Option<&mut TuiDispatch>,
    pending: Option<&TaskId>,
    failures: &mut u32,
) {
    let Some(dispatch) = dispatch else {
        return;
    };
    match dispatch.dock_projection(pending) {
        Ok((rows, warning)) => {
            view.dock = rows;
            view.context_warning = warning;
            view.dock_stale = None;
            *failures = 0;
        }
        Err(error) => {
            *failures += 1;
            if *failures >= 2 {
                view.dock_stale = Some(format!(
                    "dock refresh failed: {}",
                    sanitize_status_cause(&error.to_string())
                ));
            }
        }
    }
}

/// The loop body: its terminal guard and runtime are dropped when it
/// returns, on every path.
fn tui_loop<F>(data_root: &Path, mut between_passes: F) -> io::Result<i32>
where
    F: FnMut(&mut TuiDispatch, Option<&TaskId>) -> io::Result<()>,
{
    let mut view = initial_view();
    // The eager open completes before the alternate screen: open does no
    // tty I/O, so a failed open's stderr verdicts stay on the primary
    // screen — and the transcript records them for the operator who
    // watches the degraded session that follows.
    let mut tui_dispatch = match TuiDispatch::open(data_root) {
        Ok(dispatch) => {
            surface_boot_diagnostics(&mut view, &dispatch.runtime);
            Some(dispatch)
        }
        Err(failure) => {
            note_open_failure(&mut view, &failure);
            None
        }
    };
    let mut guard = match TerminalGuard::enter() {
        Ok(guard) => guard,
        // The alternate screen never took the terminal, so stderr is
        // still the live channel here: a successfully opened runtime's
        // unresolved verdicts are emitted before the propagating error
        // drops it.
        Err(source) => {
            if let Some(dispatch) = &tui_dispatch {
                report_boot_diagnostics(&dispatch.runtime.boot_diagnostics);
            }
            return Err(source);
        }
    };
    let mut exit = 0;
    // The last submitted task — the one a material fork can still open a
    // decision card for while its question stays pending.
    let mut pending_task: Option<TaskId> = None;
    // The dock projection's own state: when it last read the store and
    // how many reads in a row have failed.
    let mut dock_refreshed: Option<Instant> = None;
    let mut dock_failures = 0;
    loop {
        if let Some(dispatch) = tui_dispatch.as_mut() {
            between_passes(dispatch, pending_task.as_ref())?;
        }
        // The dock is refreshed here, at the loop top: the pass that sees
        // a transition also paints it, and no `?` on this path can unwind
        // the alternate screen for a read that only re-paints a panel.
        if dock_refreshed.is_none_or(|last| last.elapsed() >= DOCK_REFRESH_INTERVAL) {
            dock_refreshed = Some(Instant::now());
            refresh_dock(
                &mut view,
                tui_dispatch.as_mut(),
                pending_task.as_ref(),
                &mut dock_failures,
            );
        }
        // A material fork surfaces through the same store seam: the
        // tracked task's pending question opens its card. While a card
        // owns the modal the same poll re-checks the pinned question, so
        // a fork that moved underneath — superseded by a steer, answered
        // over the wire — closes honestly instead of keeping live
        // controls a consent could still journal a denial against. The
        // poll runs before the draw so a card that just opened paints in
        // this same pass — the paint is the earliest moment input may
        // legitimately reach it.
        let mut card_opened = false;
        if let Some(card) = &view.decision {
            // The card pins one (id, revision); `current_question` is
            // the poll's own definition of "still waiting on a human" —
            // a different pending fork or none means this card's
            // question already moved.
            let moved = if let Some(dispatch) = tui_dispatch.as_mut() {
                dispatch
                    .runtime
                    .owner
                    .store
                    .current_question(&card.question.task_id)
                    .map_err(|source| {
                        io::Error::other(format!("tui question poll failed: {source}"))
                    })?
                    .is_none_or(|(question, _)| {
                        question.question_id != card.question.question_id
                            || question.question_revision != card.question.question_revision
                    })
            } else {
                false
            };
            if moved {
                view.decision = None;
                view.transcript.push(DECISION_MOVED_NOTE.to_string());
            }
        } else if let Some(task_id) = pending_task.clone()
            && let Some(dispatch) = tui_dispatch.as_mut()
            && let Some((question, _)) = dispatch
                .runtime
                .owner
                .store
                .current_question(&task_id)
                .map_err(|source| io::Error::other(format!("tui question poll failed: {source}")))?
        {
            // A card the operator returned stays dismissed for that
            // question; a different pending fork opens fresh.
            if view.decision_dismissed.as_ref() != Some(&question.question_id) {
                view.decision_dismissed = None;
                view.decision = Some(DecisionPanel::new(question));
                card_opened = true;
            }
        }
        render(guard.terminal_mut(), &view)?;
        if card_opened {
            // The card's first frame just painted, so anything still
            // queued was produced before the question was visible —
            // input that cannot have been aimed at the card must never
            // answer it (a blind Enter on focus 0) or dismiss it (a
            // blind Esc). Only input produced after the paint reaches
            // the card. The drain is blind to event kind: a Paste the
            // operator aimed at the composer dies here too — its text
            // is lost with the rest of the pre-paint queue. The bound
            // keeps a sustained byte flood from starving the loop; the
            // consent floor below, not this drain, is the invariant
            // that refuses unaimed Enter/Esc.
            for _ in 0..PRE_PAINT_DRAIN_CAP {
                if !poll(Duration::ZERO)? {
                    break;
                }
                read()?;
            }
        }
        if poll(POLL_INTERVAL)? {
            let event = read()?;
            if let Some(card) = &view.decision {
                // Until the card has been visible DECISION_CONSENT_DELAY,
                // a commit or dismiss keypress cannot have been aimed at
                // the question — autorepeat on a held Enter, bytes still
                // in flight over SSH/mosh — so the consent surfaces stay
                // refused while navigation and text keys stay live.
                let unaimed_consent = !card.consent_admitted()
                    && matches!(
                        event,
                        TermEvent::Key(KeyEvent {
                            code: KeyCode::Enter | KeyCode::Esc,
                            kind: KeyEventKind::Press | KeyEventKind::Repeat,
                            ..
                        })
                    );
                if unaimed_consent {
                    continue;
                }
                // The card owns the keys through the shared production
                // handler; the answer records on the same store handle
                // question.answer reads and resumes through the same
                // scheduler seam the wire answer takes.
                let dispatch = tui_dispatch
                    .as_mut()
                    .ok_or_else(|| io::Error::other("no open session to answer on"))?;
                if !handle_decision_event(
                    &event,
                    &mut view,
                    &mut dispatch.runtime,
                    &SessionId(dispatch.session_id.clone()),
                ) {
                    exit = 130;
                    break;
                }
                continue;
            }
            match event {
                TermEvent::Key(KeyEvent {
                    code,
                    modifiers,
                    kind: KeyEventKind::Press,
                    ..
                }) => match (code, modifiers) {
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
                            &mut dispatch.runtime.store_writer(),
                        ) {
                            exit = 130;
                            break;
                        }
                    }
                    // Streaming output scroll: the reader keeps their place
                    // while output updates in place (design-brief §3).
                    (KeyCode::PageUp | KeyCode::PageDown, _) if view.output.is_active() => {
                        view.output_scroll.update(|offset| {
                            if code == KeyCode::PageDown {
                                offset.saturating_add(1)
                            } else {
                                offset.saturating_sub(1)
                            }
                        });
                    }
                    (KeyCode::Enter, _) if !view.composer.is_empty() => {
                        let input = view.composer.clone();
                        run_composer_command(
                            &input,
                            &mut view,
                            &mut tui_dispatch,
                            data_root,
                            &mut pending_task,
                        )?;
                    }
                    (KeyCode::Enter, _) => {}
                    (KeyCode::Char(ch), m) if types_text(m) => append_composer_char(&mut view, ch),
                    (KeyCode::Backspace, _) => {
                        view.composer.pop();
                    }
                    _ => {}
                },
                // Bracketed paste is one atomic event: its text joins
                // the composer draft. While a modal owns input it drops
                // like the keys the modal swallows.
                TermEvent::Paste(text) if view.panel.is_none() => {
                    append_composer_paste(&mut view, &text);
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
    use super::{
        CONTEXT_MEASURE_INTERVAL, ContextMeasureKey, ContextMeasurement, DECISION_CONSENT_DELAY,
        DOCK_EMPTY, DecisionPanel, LoopbackProvider, OUTPUT_SCROLL_HINT, OutputStream, TuiDispatch,
        TuiOpenError, append_composer_char, append_composer_paste, initial_view, note_open_failure,
        output_status_line, render, surface_boot_diagnostics, task_dock, types_text,
        types_text_altgr, wrapped_row_count,
    };
    use crate::contracts::{PAGE_MAX, Question, TEXT_MAX_BYTES, TaskId};
    use crossterm::event::KeyModifiers;
    use serde_json::json;
    use std::time::{Duration, Instant};

    /// Mirrors `commands.rs::tests::BASE_CONFIG`: a publication needs a
    /// validating base plus one settable key to reach the journal.
    const BOOT_CONFIG: &str = "config_version = 1\n\
         [connections.primary]\n\
         kind = \"api_key\"\n\
         endpoint = \"https://api.openai.com/v1\"\n\
         credential_ref = \"keyring:primary\"\n\
         [models.defaults]\n\
         model = { mode = \"auto\" }\n\
         effort = { mode = \"auto\" }\n\
         fallback = { mode = \"auto\" }\n";

    /// The dock's remembered measurement answers one key only: a moved
    /// revision, a changed setting, a different task or an aged entry each
    /// re-measure, which is what keeps the near-full line following the
    /// context it names instead of the one it was taken from.
    #[test]
    fn a_context_measurement_answers_only_its_own_key() {
        let key = |task: &str, revision: Option<u64>, auto_compact: bool| ContextMeasureKey {
            task_id: TaskId(task.to_string()),
            revision,
            auto_compact,
        };
        let taken = Instant::now();
        let measurement = ContextMeasurement {
            key: key("task-1", Some(3), false),
            warning: None,
            taken,
        };
        assert!(measurement.answers(&key("task-1", Some(3), false), taken));
        assert!(measurement.answers(
            &key("task-1", Some(3), false),
            taken + CONTEXT_MEASURE_INTERVAL - Duration::from_millis(1)
        ));
        // The backstop: a state change the status payload does not carry is
        // re-measured once the interval has passed.
        assert!(!measurement.answers(
            &key("task-1", Some(3), false),
            taken + CONTEXT_MEASURE_INTERVAL
        ));
        assert!(!measurement.answers(&key("task-1", Some(4), false), taken));
        assert!(!measurement.answers(&key("task-1", None, false), taken));
        assert!(!measurement.answers(&key("task-1", Some(3), true), taken));
        assert!(!measurement.answers(&key("task-2", Some(3), false), taken));
    }

    /// Each expectation names the renderer's own break decisions, not a
    /// character-count guess: the cases below are exactly where a
    /// `chars()` estimate diverges from `Wrap { trim: false }`.
    #[test]
    fn wrap_count_measures_cells_not_characters() {
        // Ten double-width graphemes occupy twenty cells: the renderer
        // breaks the word at cell width, a character count under-reads.
        assert_eq!(wrapped_row_count("あいうえおかきくけこ", 8), 3);
        // A combining sequence is one grapheme of one cell, not two
        // characters: a character count over-reads.
        assert_eq!(wrapped_row_count("e\u{301}", 1), 1);
        assert_eq!(wrapped_row_count("e\u{301}".repeat(9).as_str(), 4), 3);
    }

    #[test]
    fn wrap_count_wraps_on_word_boundaries() {
        // A word that does not fit after its predecessor takes its own
        // row; the separating space ends the row it broke.
        assert_eq!(wrapped_row_count("aa bb", 4), 2);
        // A non-breaking space is part of the word — never a break —
        // so the five-cell word splits at cell width like any lone
        // word too wide for the row.
        assert_eq!(wrapped_row_count("ab\u{a0}cd", 4), 2);
        // A zero-width space IS a break: it ends the word but adds no
        // width, so both halves rejoin the same row.
        assert_eq!(wrapped_row_count("ab\u{200b}cd", 4), 1);
        // A whitespace run cannot break either: eight leading spaces
        // pack one over-wide row instead of wrapping per cell.
        assert_eq!(wrapped_row_count("        a", 4), 2);
        // A lone word longer than the width still breaks at cell width.
        assert_eq!(wrapped_row_count(&"a".repeat(65), 20), 4);
    }

    #[test]
    fn wrap_count_keeps_line_boundaries() {
        // `str::lines` semantics: a trailing newline adds no row and an
        // interior empty line renders one; `Text::raw("")` still yields
        // the one empty `Line` the renderer paints as a blank row.
        assert_eq!(wrapped_row_count("x\n", 8), 1);
        assert_eq!(wrapped_row_count("x\n\n", 8), 2);
        assert_eq!(wrapped_row_count("", 8), 1);
        assert_eq!(wrapped_row_count("aa bb\ncc", 4), 3);
    }

    #[test]
    fn tui_status_requests_page_maximum() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::TempDir::with_prefix("rivect-ui-page-max-")?;
        let mut dispatch = TuiDispatch::open(root.path()).map_err(TuiOpenError::into_io_error)?;
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
    fn task_dock_marks_a_pending_profile_switch_beside_the_active_binding() {
        let dock = task_dock(&json!({
            "todo": { "items": [] },
            "profile": { "pending": "p2", "active": "p1" }
        }));
        assert_eq!(dock, vec!["profile: p1 active → p2 pending"]);

        let converged = task_dock(&json!({
            "todo": { "items": [] },
            "profile": { "pending": "p1", "active": "p1" }
        }));
        assert_eq!(converged, vec!["profile: p1"]);

        // a pending profile with no active binding yet still shows —
        // tagged so it never reads as the bound one
        let pending_only = task_dock(&json!({
            "todo": { "items": [] },
            "profile": { "pending": "p2", "active": null }
        }));
        assert_eq!(pending_only, vec!["profile: p2 pending"]);

        let active_only = task_dock(&json!({
            "todo": { "items": [] },
            "profile": { "pending": null, "active": "p1" }
        }));
        assert_eq!(active_only, vec!["profile: p1"]);

        let silent = task_dock(&json!({
            "todo": { "items": [] },
            "profile": { "pending": null, "active": null }
        }));
        assert_eq!(silent, vec![DOCK_EMPTY]);
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

    #[test]
    fn composer_paste_joins_line_breaks_as_single_spaces() {
        let mut view = initial_view();
        append_composer_paste(&mut view, "first line\nsecond line");
        assert_eq!(view.composer, "first line second line");

        // `\r\n` is one break — not two spaces — and a bare `\r`
        // breaks the same way.
        view.composer.clear();
        append_composer_paste(&mut view, "a\r\nb\rc");
        assert_eq!(view.composer, "a b c");

        // Breaks at the edges and empty lines leave no stray spaces,
        // and pasted text abuts the existing draft — a paste is not a
        // word joiner.
        append_composer_paste(&mut view, "\n\ntail\n");
        assert_eq!(view.composer, "a b ctail");
    }

    #[test]
    fn text_chars_admit_shift_but_never_a_chord() {
        // The one modifier gate both draft surfaces share: bare and
        // Shift-ed chars are text on every platform. A bare Ctrl or
        // Alt chord is a command, not its letter — and off Windows the
        // CONTROL|ALT bits ARE such a chord, so the AltGr admission is
        // gated to the only platform that produces it.
        for modifiers in [KeyModifiers::NONE, KeyModifiers::SHIFT] {
            assert!(types_text(modifiers), "{modifiers:?} types text");
        }
        for modifiers in [
            KeyModifiers::CONTROL,
            KeyModifiers::ALT,
            KeyModifiers::CONTROL | KeyModifiers::SHIFT,
        ] {
            assert!(!types_text(modifiers), "{modifiers:?} is a chord, not text");
        }
        // The AltGr shapes are honest about the platform: the shape
        // predicate always recognizes them — every build can exercise
        // it — while the admission gate only says text on Windows.
        for modifiers in [
            KeyModifiers::CONTROL | KeyModifiers::ALT,
            KeyModifiers::SHIFT | KeyModifiers::CONTROL | KeyModifiers::ALT,
        ] {
            assert!(
                types_text_altgr(modifiers),
                "{modifiers:?} is the AltGr shape"
            );
            assert_eq!(
                types_text(modifiers),
                cfg!(windows),
                "{modifiers:?} is draft text only on the platform that reports AltGr"
            );
        }
    }

    /// A painted interior that reached cells — what the render passes
    /// when a real frame shows question content.
    const VISIBLE_INNER: ratatui::layout::Rect = ratatui::layout::Rect::new(1, 4, 58, 18);

    #[test]
    fn card_consent_is_refused_until_the_card_has_been_visible()
    -> Result<(), Box<dyn std::error::Error>> {
        let card = DecisionPanel::new(Question::fixture(&TaskId("task-1".to_string()), 1));
        // Never painted fails closed: an unseen card cannot be
        // consented to.
        assert!(!card.consent_admitted());
        // Painted just now is still inside the reaction floor.
        card.note_first_paint(VISIBLE_INNER);
        assert!(!card.consent_admitted());
        let stamped = card.first_painted_at.get().ok_or("the paint stamped")?;
        // A later frame keeps the first stamp — the window runs from
        // first visibility, not the latest paint.
        card.note_first_paint(VISIBLE_INNER);
        assert_eq!(card.first_painted_at.get(), Some(stamped));
        card.first_painted_at
            .set(Some(Instant::now() - DECISION_CONSENT_DELAY));
        assert!(
            card.consent_admitted(),
            "the floor elapsed — consent is admitted"
        );
        Ok(())
    }

    #[test]
    fn render_stamps_the_cards_first_paint() -> Result<(), Box<dyn std::error::Error>> {
        let mut view = initial_view();
        view.decision = Some(DecisionPanel::new(Question::fixture(
            &TaskId("task-1".to_string()),
            1,
        )));
        let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(60, 20))?;
        let card = view.decision.as_ref().ok_or("the card is open")?;
        assert!(
            card.first_painted_at.get().is_none(),
            "no stamp before the first frame"
        );
        render(&mut terminal, &view)?;
        let card = view.decision.as_ref().ok_or("the card is open")?;
        assert!(
            card.first_painted_at.get().is_some(),
            "the first painted frame starts the consent window"
        );
        Ok(())
    }

    #[test]
    fn render_never_stamps_a_card_that_painted_no_inner_cells()
    -> Result<(), Box<dyn std::error::Error>> {
        // A degenerate viewport clips the card to its border or less:
        // the frame flushed but no question content reached a cell, so
        // the paint starts no consent window on an invisible card.
        for (cols, rows) in [(1u16, 24u16), (80, 1)] {
            let mut view = initial_view();
            view.decision = Some(DecisionPanel::new(Question::fixture(
                &TaskId("task-1".to_string()),
                1,
            )));
            let mut terminal =
                ratatui::Terminal::new(ratatui::backend::TestBackend::new(cols, rows))?;
            render(&mut terminal, &view)?;
            let card = view.decision.as_ref().ok_or("the card is open")?;
            assert!(
                card.first_painted_at.get().is_none() && !card.consent_admitted(),
                "{cols}x{rows}: a paint with no visible inner cell admits no consent"
            );
        }
        Ok(())
    }

    #[test]
    fn status_line_leads_with_the_scroll_hint_and_yields_to_the_panel() {
        let mut output = OutputStream::new();
        output.settle(crate::resources::OutputSettlement::Partial {
            cause: "disk full".to_string(),
        });
        let line = output_status_line(&output, false);
        assert!(
            matches!(
                (line.find(OUTPUT_SCROLL_HINT), line.find("disk full")),
                (Some(hint), Some(cause)) if hint < cause
            ),
            "the fixed affordance leads the variable cause: {line}"
        );
        let panel_line = output_status_line(&output, true);
        assert!(
            !panel_line.contains(OUTPUT_SCROLL_HINT) && panel_line.contains("disk full"),
            "an open panel owns PgUp/PgDn — the hint drops, the cause stays: {panel_line}"
        );
    }

    /// Stages one pending publication row under a fresh temp root, then
    /// opens the runtime that must collect its unresolved verdict at
    /// boot. A pending journal row survives boot as an unresolved
    /// verdict, which the runtime must surface on whichever screen the
    /// human is watching; the owner store lives under `runtime/` — the
    /// path `Owner::elect` opens — so the staged row is visible to
    /// `Runtime::open`.
    fn staged_verdict_runtime(
        root: &std::path::Path,
    ) -> Result<crate::commands::Runtime, Box<dyn std::error::Error>> {
        let target = root.join("config.toml");
        std::fs::write(&target, BOOT_CONFIG)?;
        let runtime_dir = root.join("runtime");
        std::fs::create_dir_all(&runtime_dir)?;
        let mut store = crate::state::TaskStore::open(&runtime_dir.join("rivect.db"))?;
        let mut parsed = crate::config::Config::parse_validated(BOOT_CONFIG)?;
        let edit = parsed.set("workflow.enabled", crate::config::ConfigValue::Bool(false))?;
        crate::config::stage_publication(&mut store, "cli", &target, &edit)?;
        drop(store);
        Ok(crate::commands::Runtime::open(
            root,
            Box::new(LoopbackProvider::new()),
        )?)
    }

    #[test]
    fn boot_diagnostics_surface_in_the_transcript() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::TempDir::with_prefix("rivect-ui-boot-diag-")?;
        let runtime = staged_verdict_runtime(root.path())?;
        assert_eq!(
            runtime.boot_diagnostics.len(),
            1,
            "one unresolved verdict produces one diagnostic line"
        );
        let mut view = initial_view();
        surface_boot_diagnostics(&mut view, &runtime);
        assert!(
            view.transcript
                .iter()
                .any(|line| line.contains("publication recovery") && line.contains("resolution")),
            "the verdict and its resolution reach the transcript: {:?}",
            view.transcript
        );
        Ok(())
    }

    #[test]
    fn failed_open_drains_carried_verdicts_into_the_transcript()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::TempDir::with_prefix("rivect-ui-open-drain-")?;
        let mut runtime = staged_verdict_runtime(root.path())?;
        assert_eq!(runtime.boot_diagnostics.len(), 1);
        // The failed-open arm owes the operator the dropped runtime's
        // verdicts on the transcript surface, ahead of its own error
        // line. They are taken rather than moved: the runtime owns the
        // tracked index owner, so it cannot be destructured, and dropping
        // it has to run that owner's shutdown.
        let failure = TuiOpenError {
            error: std::io::Error::other("tui runtime open failed: staged"),
            boot_diagnostics: std::mem::take(&mut runtime.boot_diagnostics),
        };
        let mut view = initial_view();
        note_open_failure(&mut view, &failure);
        let verdict = view
            .transcript
            .iter()
            .position(|line| line.contains("publication recovery") && line.contains("resolution"));
        let error_line = view
            .transcript
            .iter()
            .position(|line| line.contains("session open failed"));
        assert!(
            matches!((verdict, error_line), (Some(v), Some(e)) if v < e),
            "the carried verdict lands ahead of the error line: {:?}",
            view.transcript
        );
        // And the propagated form keeps the lines for the post-restore
        // stderr print.
        let propagated = failure.into_io_error();
        let text = super::failure_report(&propagated).to_string();
        assert!(
            text.contains("publication recovery") && text.contains("tui runtime open failed"),
            "the propagated error still carries the verdict: {text}"
        );
        Ok(())
    }

    #[derive(Debug, thiserror::Error)]
    #[error("staged primary")]
    struct StagedPrimary {
        nonce: u64,
    }

    #[derive(Debug, thiserror::Error)]
    #[error("staged config fault")]
    struct StagedConfigFault {
        nonce: u64,
    }

    const WRITER_LINE: &str = "database writer lock release failed: other error";
    const OWNER_LINE: &str = "owner lock release failed: other error";

    type Check = Result<(), Box<dyn std::error::Error>>;

    fn assert_no_release_lines() {
        assert_eq!(
            crate::state::take_release_lines(),
            Vec::<String>::new(),
            "no release fault is pending"
        );
    }

    /// Opens a healthy runtime and drops it with `faults` unlocks armed, so
    /// the carrier holds that many lines for the surface to settle.
    fn carry_release_faults(faults: u8) -> Check {
        let root = tempfile::TempDir::with_prefix("rivect-ui-carry-")?;
        let runtime =
            crate::commands::Runtime::open(root.path(), Box::new(LoopbackProvider::new()))?;
        crate::state::proof::arm_unlock_faults(faults);
        drop(runtime);
        Ok(())
    }

    #[test]
    fn release_lines_ride_the_discard_and_loop_exit() -> Check {
        use super::{discard_runtime, failure_report, settle_released};
        use std::error::Error as _;
        use std::io;

        assert_no_release_lines();

        // A discarded runtime carries its two lines last.
        let root = tempfile::TempDir::with_prefix("rivect-ui-discard-")?;
        let runtime =
            crate::commands::Runtime::open(root.path(), Box::new(LoopbackProvider::new()))?;
        crate::state::proof::arm_unlock_faults(2);
        let failure = discard_runtime(runtime, io::Error::other("staged discard"));
        assert_eq!(failure.boot_diagnostics, [WRITER_LINE, OWNER_LINE]);
        assert_no_release_lines();

        // A carried line keeps the typed primary one `source()` hop away.
        carry_release_faults(1)?;
        let primary = io::Error::new(io::ErrorKind::PermissionDenied, StagedPrimary { nonce: 11 });
        let settled = settle_released::<()>(Err(primary))
            .err()
            .ok_or("the primary stays an error")?;
        assert_eq!(settled.kind(), io::ErrorKind::PermissionDenied);
        let mut reached = false;
        let mut hop = settled.source();
        while let Some(current) = hop {
            if let Some(inner) = current.downcast_ref::<io::Error>()
                && inner.kind() == io::ErrorKind::PermissionDenied
                && inner
                    .get_ref()
                    .and_then(|payload| payload.downcast_ref::<StagedPrimary>())
                    .is_some_and(|staged| staged.nonce == 11)
            {
                reached = true;
                break;
            }
            hop = current.source();
        }
        assert!(reached, "the source walk reaches the typed primary");
        assert_eq!(
            failure_report(&settled).to_string(),
            format!("staged primary\n{WRITER_LINE}")
        );
        assert_no_release_lines();

        // An empty carrier is the identity on the primary.
        let primary = io::Error::new(io::ErrorKind::PermissionDenied, StagedPrimary { nonce: 12 });
        let unchanged = settle_released::<()>(Err(primary))
            .err()
            .ok_or("the primary stays an error")?;
        assert_eq!(unchanged.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(
            unchanged
                .get_ref()
                .and_then(|payload| payload.downcast_ref::<StagedPrimary>())
                .map(|staged| staged.nonce),
            Some(12)
        );
        assert_eq!(failure_report(&unchanged).to_string(), "staged primary");
        assert_eq!(settle_released::<i32>(Ok(7))?, 7);

        // A raw OS error keeps its errno.
        carry_release_faults(1)?;
        let carried = settle_released::<()>(Err(io::Error::from_raw_os_error(5)))
            .err()
            .ok_or("the errno stays an error")?;
        assert_eq!(carried.kind(), io::Error::from_raw_os_error(5).kind());
        let inner = carried
            .source()
            .and_then(|hop| hop.downcast_ref::<io::Error>())
            .ok_or("the errno primary is one hop away")?;
        assert_eq!(inner.raw_os_error(), Some(5));
        assert!(inner.get_ref().is_none());
        assert_no_release_lines();
        let direct = settle_released::<()>(Err(io::Error::from_raw_os_error(5)))
            .err()
            .ok_or("the errno stays an error")?;
        assert_eq!(direct.raw_os_error(), Some(5));
        Ok(())
    }

    fn open_failure(root: &std::path::Path) -> Result<TuiOpenError, Box<dyn std::error::Error>> {
        match TuiDispatch::open(root) {
            Ok(_) => Err("the open must be refused".into()),
            Err(failure) => Ok(failure),
        }
    }

    /// The retry boundary's own two calls.
    fn retry_error(failure: TuiOpenError) -> Result<std::io::Error, Box<dyn std::error::Error>> {
        super::settle_released::<()>(Err(failure.into_io_error()))
            .err()
            .ok_or_else(|| "the retry boundary keeps the error".into())
    }

    fn chain(error: &std::io::Error) -> Vec<&(dyn std::error::Error + 'static)> {
        use std::error::Error as _;
        let mut hops = Vec::new();
        let mut next = error.source();
        while let Some(hop) = next {
            hops.push(hop);
            next = hop.source();
        }
        hops
    }

    fn config_root(mode: u32) -> Result<(tempfile::TempDir, std::path::PathBuf), std::io::Error> {
        use std::os::unix::fs::PermissionsExt as _;
        let root = tempfile::TempDir::with_prefix("rivect-ui-open-refusal-")?;
        let config = root.path().join("config.toml");
        std::fs::write(&config, "[workflow]\n")?;
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(mode))?;
        Ok((root, config))
    }

    /// The chain the retry boundary leaves for a `ConfigRead` refusal: the
    /// context, then (with carried lines) one more context hop, the
    /// `OwnerError`, and the original error, each shown once by the report.
    fn assert_config_read_chain(
        label: &str,
        error: &std::io::Error,
        carried: bool,
        config: &std::path::Path,
        original_ok: impl Fn(&std::io::Error) -> bool,
    ) -> Check {
        use crate::owner::OwnerError;
        assert_eq!(error.kind(), std::io::ErrorKind::Other, "{label}");
        assert_eq!(error.raw_os_error(), None, "{label}");
        let hops = chain(error);
        let owner_at = usize::from(carried);
        if carried {
            let context = hops
                .first()
                .and_then(|hop| hop.downcast_ref::<std::io::Error>())
                .ok_or("the carried primary is an io::Error")?;
            assert_eq!(context.kind(), std::io::ErrorKind::Other, "{label}");
            assert_eq!(context.raw_os_error(), None, "{label}");
        }
        let owner = hops.get(owner_at).ok_or("the OwnerError hop is missing")?;
        let Some(OwnerError::ConfigRead { path, .. }) = owner.downcast_ref::<OwnerError>() else {
            return Err(format!("{label}: the hop must be ConfigRead, found: {owner}").into());
        };
        assert_eq!(path, config, "{label}");
        let owner_text = format!(
            "owner configuration failed: {}: read failed",
            config.display()
        );
        assert_eq!(owner.to_string(), owner_text, "{label}");
        let original = hops
            .get(owner_at + 1)
            .ok_or("the original hop is missing")?;
        let Some(original_io) = original.downcast_ref::<std::io::Error>() else {
            return Err(format!("{label}: the original must be an io::Error: {original}").into());
        };
        assert!(original_ok(original_io), "{label}: {original_io:?}");
        assert_eq!(
            hops.len(),
            owner_at + 2,
            "{label}: nothing past the original"
        );
        let mut expected = format!("tui runtime open failed: {owner_text}: {original}");
        if carried {
            expected.push_str(&format!("\n{WRITER_LINE}\n{OWNER_LINE}"));
        }
        assert_eq!(
            super::failure_report(error).to_string(),
            expected,
            "{label}"
        );
        Ok(())
    }

    #[test]
    fn open_refusal_keeps_the_original_io_error_through_the_retry_error() -> Check {
        crate::state::proof::run_isolated_release_test(
            "ui::tests::open_refusal_keeps_the_original_io_error_through_the_retry_error",
            || {
                use crate::owner::{OwnerError, proof as owner_proof};
                use crate::state::proof;
                use std::io::Write as _;

                assert_no_release_lines();

                // A live owner: the chain ends at the `OwnerError`.
                let root = tempfile::TempDir::with_prefix("rivect-ui-open-owned-")?;
                let owner = crate::owner::Owner::elect(root.path())?;
                let error = retry_error(open_failure(root.path())?)?;
                assert_eq!(error.kind(), std::io::ErrorKind::Other);
                assert_eq!(error.raw_os_error(), None);
                let hops = chain(&error);
                assert_eq!(hops.len(), 1, "the chain ends at the OwnerError");
                assert!(matches!(
                    hops.first()
                        .and_then(|hop| hop.downcast_ref::<OwnerError>()),
                    Some(OwnerError::AlreadyOwned)
                ));
                assert_eq!(
                    super::failure_report(&error).to_string(),
                    "tui runtime open failed: another owner already holds this data root"
                );
                drop(owner);
                assert_no_release_lines();

                // The kernel's own refusal: EACCES from the config open.
                let (root, config) = config_root(0o000)?;
                match std::fs::File::open(&config) {
                    Ok(_) => {
                        std::io::stderr()
                            .write_all(b"NOT_RUN(open-eacces): root bypasses DAC\n")?;
                    }
                    Err(control) => {
                        assert_eq!(
                            control.kind(),
                            std::io::ErrorKind::PermissionDenied,
                            "fixture not established: the control open must be a permission refusal"
                        );
                        assert_eq!(
                            control.raw_os_error(),
                            Some(13),
                            "fixture not established: the control open must be EACCES"
                        );
                        for carried in [false, true] {
                            if carried {
                                proof::arm_unlock_faults(2);
                            }
                            let error = retry_error(open_failure(root.path())?)?;
                            assert_config_read_chain(
                                "eacces",
                                &error,
                                carried,
                                &config,
                                |original| {
                                    original.kind() == std::io::ErrorKind::PermissionDenied
                                        && original.raw_os_error() == Some(13)
                                        && original.get_ref().is_none()
                                        && original.to_string() == control.to_string()
                                },
                            )?;
                            assert_no_release_lines();
                        }
                    }
                }

                // Injected metadata failure: the mapping keeps the returned object.
                for carried in [false, true] {
                    let (root, config) = config_root(0o600)?;
                    owner_proof::arm_config_metadata_fault(std::io::Error::from_raw_os_error(5));
                    if carried {
                        proof::arm_unlock_faults(2);
                    }
                    let failure = open_failure(root.path())?;
                    if !carried {
                        let mut view = initial_view();
                        note_open_failure(&mut view, &failure);
                        let report = super::failure_report(&failure.error).to_string();
                        assert_eq!(
                            view.transcript.last(),
                            Some(&format!(
                                "session open failed: {}",
                                crate::resources::sanitize_status_cause(&report)
                            ))
                        );
                    }
                    let error = retry_error(failure)?;
                    assert_config_read_chain("metadata", &error, carried, &config, |original| {
                        original.raw_os_error() == Some(5) && original.get_ref().is_none()
                    })?;
                    assert_no_release_lines();
                }

                // Injected read failure: a typed payload survives every hop.
                for carried in [false, true] {
                    let (root, config) = config_root(0o600)?;
                    owner_proof::arm_config_read_fault(std::io::Error::other(StagedConfigFault {
                        nonce: 23,
                    }));
                    if carried {
                        proof::arm_unlock_faults(2);
                    }
                    let error = retry_error(open_failure(root.path())?)?;
                    assert_config_read_chain("read", &error, carried, &config, |original| {
                        original
                            .get_ref()
                            .and_then(|payload| payload.downcast_ref::<StagedConfigFault>())
                            .is_some_and(|staged| staged.nonce == 23)
                    })?;
                    assert_no_release_lines();
                }
                Ok(())
            },
        )
    }
}

#[cfg(test)]
#[path = "../tests/support/pty.rs"]
mod pty_support;

/// Result unwrapping for the PTY legs: a failed transport step fails the
/// leg with its fixed message and the typed cause.
#[cfg(test)]
mod leg {
    use std::fmt::Debug;

    pub(super) fn must<T, E: Debug>(result: Result<T, E>, what: &str) -> T {
        match result {
            Ok(value) => value,
            Err(error) => unreachable!("{what}: {error:?}"),
        }
    }
}

/// Provider legs of the shared PTY session: real `/bin/sh` children behind
/// the session's injectable doubles, one fixed test-authored script each
/// (no interpolated input).
#[cfg(test)]
mod pty_session {
    use super::leg::must;
    use super::pty_support::{
        PtyFaults, PtyIoError, PtySession, PtyTeardownError, PtyWaitError, pty_command,
        wait_for_screen_text,
    };
    use std::io::Write;
    use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::sync::atomic::Ordering;
    use std::time::Duration;
    use tempfile::TempDir;

    const SLEEPER: &str = "printf ready; exec sleep 30";
    const READER: &str = "printf ready; read line; exit 0";
    const INJECTED_READ: &str = "injected pty read fault";

    fn session_root() -> (TempDir, PathBuf) {
        let root = must(TempDir::with_prefix("rivect-pty-session-"), "session root");
        let path = root.path().to_path_buf();
        (root, path)
    }

    fn spawn(script: &str, root: TempDir, path: &Path, faults: &Arc<PtyFaults>) -> PtySession {
        let mut command = pty_command("/bin/sh");
        command.arg("-c");
        command.arg(script);
        must(
            PtySession::spawn_faulted(
                command,
                24,
                80,
                root,
                path.to_path_buf(),
                Arc::clone(faults),
            ),
            "session spawns",
        )
    }

    fn ready(script: &str) -> (PtySession, PathBuf, Arc<PtyFaults>) {
        let faults = Arc::new(PtyFaults::default());
        let (root, path) = session_root();
        let mut session = spawn(script, root, &path, &faults);
        assert!(
            must(
                session.wait_for(b"ready", Duration::from_secs(10)),
                "pty read"
            ),
            "the child printed its marker"
        );
        (session, path, faults)
    }

    fn parked(faults: &PtyFaults) -> Option<Box<dyn portable_pty::Child + Send + Sync>> {
        faults
            .parked_child
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }

    /// Out-of-band cleanup of a session that kept its root or panicked:
    /// the parked original child is reaped by the leg, and the root is
    /// removed only after that wait returned `Ok`.
    fn clean_up(faults: &PtyFaults, root: &Path) {
        let Some(mut child) = parked(faults) else {
            return;
        };
        if matches!(child.try_wait(), Ok(Some(_))) {
            drop(std::fs::remove_dir_all(root));
            return;
        }
        drop(child.kill());
        match child.wait() {
            Ok(_) => drop(std::fs::remove_dir_all(root)),
            Err(error) => {
                let note = format!(
                    "child wait failed ({error}); root kept at {}\n",
                    root.display()
                );
                drop(std::io::stderr().lock().write_all(note.as_bytes()));
            }
        }
    }

    #[test]
    fn try_wait_failure_keeps_the_root_and_sends_no_later_kill() {
        let faults_a = Arc::new(PtyFaults::default());
        faults_a.fail_try_wait.store(true, Ordering::SeqCst);
        let (root_a, path_a) = session_root();
        let mut session_a = spawn(SLEEPER, root_a, &path_a, &faults_a);
        let wait = session_a.wait_exit(Duration::from_secs(1));
        let finish_a = session_a.finish();
        let kills_a = faults_a.kills.load(Ordering::SeqCst);
        let exists_a = path_a.exists();

        let faults_b = Arc::new(PtyFaults::default());
        faults_b.fail_try_wait.store(true, Ordering::SeqCst);
        let (root_b, path_b) = session_root();
        let session_b = spawn(SLEEPER, root_b, &path_b, &faults_b);
        let finish_b = session_b.finish();
        let kills_b = faults_b.kills.load(Ordering::SeqCst);
        let exists_b = path_b.exists();

        clean_up(&faults_a, &path_a);
        clean_up(&faults_b, &path_b);
        assert!(matches!(wait, Err(PtyWaitError::Wait { .. })), "{wait:?}");
        assert!(
            matches!(&finish_a, Err(PtyTeardownError::ChildStateUnknown { root }) if *root == path_a),
            "{finish_a:?}"
        );
        assert!(
            matches!(&finish_b, Err(PtyTeardownError::ChildWait { root, .. }) if *root == path_b),
            "{finish_b:?}"
        );
        assert_eq!((kills_a, kills_b), (0, 0), "no kill after an unknown wait");
        assert!(exists_a && exists_b, "the kept roots exist");
    }

    #[test]
    fn stored_read_fault_rejects_stale_success_and_surfaces_at_finish() {
        // Stale success: `ready` is already in the stream.
        let (session, path, faults) = ready(SLEEPER);
        faults.fail_next_read.store(true, Ordering::SeqCst);
        let stale = wait_for_screen_text(&session, 24, 80, "ready", Duration::from_secs(1));
        let finished = session.finish();
        let gone = !path.exists();
        assert!(
            matches!(&stale, Err(PtyIoError::Read { source }) if source.to_string() == INJECTED_READ),
            "{stale:?}"
        );
        assert!(
            finished.is_ok(),
            "a taken fault is not reported twice: {finished:?}"
        );
        assert!(gone, "the root is removed after the reap");

        // Fault taken only at finish: step (2) precedes step (3).
        let (mut session, path, faults) = ready(READER);
        faults.fail_next_read.store(true, Ordering::SeqCst);
        must(session.send(b"\n"), "pty send");
        let exit = session.wait_exit(Duration::from_secs(10));
        let finished = session.finish();
        let gone = !path.exists();
        assert!(matches!(exit, Ok(Some(0))), "{exit:?}");
        assert!(
            matches!(&finished, Err(PtyTeardownError::Output { source }) if source.to_string() == INJECTED_READ),
            "{finished:?}"
        );
        assert!(gone, "the root is already removed when the fault surfaces");

        // `pump_for` returns the fault it took, never `Ok` at its deadline.
        let (mut session, path, faults) = ready(SLEEPER);
        faults.fail_next_read.store(true, Ordering::SeqCst);
        let pumped = session.pump_for(Duration::from_secs(1));
        let armed = faults.fail_next_read.load(Ordering::SeqCst);
        let finished = session.finish();
        let gone = !path.exists();
        assert!(
            matches!(&pumped, Err(PtyIoError::Read { source }) if source.to_string() == INJECTED_READ),
            "{pumped:?}"
        );
        assert!(!armed, "that pump's read took the armed fault");
        assert!(
            finished.is_ok(),
            "the returned fault is not reported again: {finished:?}"
        );
        assert!(gone);
    }

    #[test]
    fn wait_timeout_kills_then_reaps_before_the_root_is_removed() {
        let (mut session, path, faults) = ready(SLEEPER);
        let waited = session.wait_exit(Duration::from_millis(200));
        let kills = faults.kills.load(Ordering::SeqCst);
        let finished = session.finish();
        let at_reap = *faults
            .root_at_first_reap
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let gone = !path.exists();
        clean_up(&faults, &path);
        assert!(matches!(waited, Ok(None)), "{waited:?}");
        assert_eq!(kills, 1, "exactly one termination");
        assert!(finished.is_ok(), "{finished:?}");
        assert_eq!(at_reap, Some(true), "the root outlived the first reap");
        assert!(gone, "the root is gone afterwards");
    }

    #[test]
    fn panic_unwind_reaps_before_the_root_is_removed() {
        // (a) a ready session unwinds before any wait.
        let (session, path, faults) = ready(SLEEPER);
        let outcome = catch_unwind(AssertUnwindSafe(move || {
            let _held = session;
            resume_unwind(Box::new("unwind"));
        }));
        assert_unwound(&outcome, &faults, &path);

        // (b) installation unwind: the spawn itself runs inside the closure.
        let faults = Arc::new(PtyFaults::default());
        let (root, path) = session_root();
        let outcome = catch_unwind(AssertUnwindSafe({
            let (faults, path) = (Arc::clone(&faults), path.clone());
            move || {
                let _held = spawn(SLEEPER, root, &path, &faults);
                resume_unwind(Box::new("unwind"));
            }
        }));
        assert_unwound(&outcome, &faults, &path);
    }

    fn assert_unwound(
        outcome: &Result<(), Box<dyn std::any::Any + Send>>,
        faults: &Arc<PtyFaults>,
        path: &Path,
    ) {
        let kills = faults.kills.load(Ordering::SeqCst);
        let at_reap = *faults
            .root_at_first_reap
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let gone = !path.exists();
        let reaped = parked(faults).map(|mut child| child.try_wait());
        let kills_after = faults.kills.load(Ordering::SeqCst);
        assert!(outcome.is_err(), "the unwind reached catch_unwind");
        assert_eq!(kills, 1, "Drop terminated the child once");
        assert_eq!(at_reap, Some(true), "the root outlived the reap");
        assert!(gone, "the root is gone afterwards");
        assert!(
            matches!(reaped, Some(Ok(Some(_)))),
            "the session reaped the original child: {reaped:?}"
        );
        assert_eq!(kills_after, kills, "no further kill");
    }
}

#[cfg(test)]
mod h026_oracle_regressions {
    use super::card_pty::{CardDriverError, answer_request, normal_exit_succeeded};
    use crate::contracts::{CommandId, OptionId, Question, QuestionId, TaskId};
    use serde_json::json;

    #[test]
    fn answer_request_preserves_pending_recommendation() -> Result<(), Box<dyn std::error::Error>> {
        let task = TaskId("pending-task".to_string());
        let command = CommandId("answer-command".to_string());
        let mut question: Question = serde_json::from_value(json!({
            "question_id": "pending-question", "question_revision": 3,
            "task_id": "pending-task", "intent_revision": 7,
            "prompt": "Choose an answer format",
            "options": [
                {
                    "option_id": "brief", "label": "Brief", "consequences": "A brief answer",
                    "availability": { "kind": "enabled" }
                },
                {
                    "option_id": "steps", "label": "Steps", "consequences": "A list of steps",
                    "availability": { "kind": "enabled" }
                },
                {
                    "option_id": "worked", "label": "Worked", "consequences": "A worked example",
                    "availability": { "kind": "enabled" }
                }
            ],
            "recommended_option_id": "steps", "recommendation_basis": "The current request"
        }))?;
        let expected_steps = json!({
            "jsonrpc": "2.0", "id": 91, "method": "task.submit",
            "params": {
                "schema_version": 1, "command_id": "answer-command",
                "session_id": "answer-session", "kind": "answer", "task_id": "pending-task",
                "question_id": "pending-question", "question_revision": 3,
                "selection": { "kind": "option", "option_id": "steps" },
                "expected_intent_revision": 7, "expected_task_revision": 11
            }
        });
        assert_eq!(
            answer_request(&question, &task, "answer-session", &command, 7, 11),
            expected_steps
        );

        question.recommended_option_id = OptionId("brief".to_string());
        let mut expected_brief = expected_steps;
        expected_brief["params"]["selection"]["option_id"] = json!("brief");
        assert_eq!(
            answer_request(&question, &task, "answer-session", &command, 7, 11),
            expected_brief,
            "the current pending question recommends brief"
        );

        question.question_id = QuestionId("replacement-question".to_string());
        question.question_revision = 5;
        question.intent_revision = 13;
        question.recommended_option_id = OptionId("worked".to_string());
        let expected_worked = json!({
            "jsonrpc": "2.0", "id": 91, "method": "task.submit",
            "params": {
                "schema_version": 1, "command_id": "replacement-command",
                "session_id": "replacement-session", "kind": "answer", "task_id": "pending-task",
                "question_id": "replacement-question", "question_revision": 5,
                "selection": { "kind": "option", "option_id": "worked" },
                "expected_intent_revision": 13, "expected_task_revision": 17
            }
        });
        assert_eq!(
            answer_request(
                &question,
                &task,
                "replacement-session",
                &CommandId("replacement-command".to_string()),
                13,
                17,
            ),
            expected_worked,
            "the replacement pending question supplies its current identities and revisions"
        );
        Ok(())
    }

    #[test]
    fn normal_exit_requires_child_and_runtime_success() -> Result<(), Box<dyn std::error::Error>> {
        type NormalExitCase = (Option<u32>, Option<&'static [u8]>, bool);
        let cases: &[NormalExitCase] = &[
            (Some(0), Some(br#"{"exit":0}"#), true),
            (
                Some(0),
                Some(br#"{"error":"synthetic runtime failure"}"#),
                false,
            ),
            (Some(0), Some(br#"{"exit":1}"#), false),
            (Some(1), Some(br#"{"exit":0}"#), false),
            (None, Some(br#"{"exit":0}"#), false),
            (Some(0), None, false),
            (Some(0), Some(br#"{}"#), false),
            (Some(0), Some(br#"{"exit":null}"#), false),
            (Some(0), Some(br#"{"exit":"0"}"#), false),
            (
                Some(0),
                Some(br#"{"exit":0,"error":"synthetic runtime failure"}"#),
                false,
            ),
            (Some(0), Some(br#"{"exit":0,"extra":true}"#), false),
        ];
        for &(child, outcome, expected) in cases {
            assert_eq!(
                normal_exit_succeeded(child, outcome)?,
                expected,
                "child {child:?}, recorded runtime outcome {outcome:?}"
            );
        }
        let malformed = b"{";
        assert!(
            matches!(
                normal_exit_succeeded(Some(0), Some(malformed)),
                Err(CardDriverError::OutcomeDecode(_))
            ),
            "malformed recorded runtime outcome {malformed:?} is a decode error"
        );
        Ok(())
    }
}

/// The decision-card PTY legs. The TUI runs in a child of this test
/// binary (`card_driver_child`), so its one `Runtime` is the only store
/// writer while it lives; the parent drives it over files and reads the
/// store only after the child has exited.
#[cfg(test)]
mod card_pty {
    use super::leg::must;
    use super::pty_support::{
        PtyFaults, PtyIoError, PtySession, PtyTeardownError, find_subsequence, pty_command,
        reconstruct_screen, squashed, wait_for_screen_text,
    };
    use super::{
        COMPACT_TOKEN, CONTEXT_COMPACTED, CONTEXT_MEASURE_INTERVAL, CommandId,
        DECISION_CONSENT_DELAY, DECISION_MOVED_NOTE, DOCK_REFRESH_INTERVAL, NOTHING_TO_COMPACT,
        TuiDispatch, dispatch_tui_request, drive_tui, failure_report,
    };
    use crate::contracts::{AnswerAttemptOutcome, AnswerSelection, Question, SessionId, TaskId};
    use crate::state::TaskStore;
    use serde::Deserialize;
    use serde_json::{Value, json};
    use sha2::{Digest as _, Sha256};
    use std::io::{self, Write};
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::sync::atomic::Ordering;
    use std::time::{Duration, Instant};
    use tempfile::TempDir;

    const CARD_DRIVER_MARKER: &str = "RIVECT_CARD_DRIVER_ROOT";
    const DECISION_PTY_ROWS: usize = 20;
    const DECISION_PTY_COLS: usize = 60;
    /// The dock legs' viewport: wide enough for one
    /// `task <id>: <lifecycle> (<reason>)` row, so a frame is compared whole
    /// instead of as a wrap.
    const DOCK_PTY_ROWS: usize = 24;
    const DOCK_PTY_COLS: usize = 80;
    const COMMAND_DEADLINE: Duration = Duration::from_secs(10);
    const CHILD_LIFETIME: Duration = Duration::from_secs(60);
    /// The control command that makes the child panic, and the payload it
    /// panics with — the report the restored screen has to show.
    const PANIC_REQUEST: &str = "panic";
    const PANIC_REPORT: &str = "card driver panics on its parent's request";
    /// The pasted Cyrillic word, spelled by code point: source strings stay
    /// English (P-001).
    const PASTED_WORD: &str = "\u{434}\u{435}\u{440}\u{436}\u{438}";

    #[derive(Debug, thiserror::Error)]
    pub(super) enum CardDriverError {
        #[error("missing card-driver marker {marker}")]
        MissingMarker { marker: &'static str },
        #[error("card-driver i/o failed")]
        Io(#[from] io::Error),
        #[error("card-driver pty transport failed")]
        Transport(#[from] PtyIoError),
        #[error("card-driver pty teardown failed")]
        Teardown(#[from] PtyTeardownError),
        #[error("card-driver outcome decode failed")]
        OutcomeDecode(#[from] serde_json::Error),
    }

    fn write_atomic(path: &Path, text: &str) -> io::Result<()> {
        let mut staging = path.as_os_str().to_owned();
        staging.push(".tmp");
        let staging = PathBuf::from(staging);
        std::fs::write(&staging, text)?;
        std::fs::rename(&staging, path)
    }

    fn read_if_present(path: &Path) -> io::Result<Option<String>> {
        match std::fs::read_to_string(path) {
            Ok(text) => Ok(Some(text)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    // ----- child side -----

    /// Serves the parent's control files from inside the TUI loop.
    struct Control {
        dir: PathBuf,
        next: u32,
        started: Instant,
    }

    impl Control {
        fn serve(&mut self, dispatch: &mut TuiDispatch, task: Option<&TaskId>) -> io::Result<()> {
            if self.started.elapsed() > CHILD_LIFETIME {
                return Err(io::Error::other("card driver child outlived its lifetime"));
            }
            let Some(line) = read_if_present(&self.dir.join(format!("{}.cmd", self.next)))? else {
                return Ok(());
            };
            self.run(dispatch, task, line.trim())
        }

        fn run(
            &mut self,
            dispatch: &mut TuiDispatch,
            task: Option<&TaskId>,
            line: &str,
        ) -> io::Result<()> {
            let number = self.next;
            self.next += 1;
            let held = line == "hold";
            let ack = match execute(dispatch, task, line) {
                Ok(value) => json!({ "ok": value }),
                Err(message) => json!({ "error": message }),
            };
            write_atomic(&self.dir.join(format!("{number}.ack")), &ack.to_string())?;
            if !held {
                return Ok(());
            }
            let following = self.dir.join(format!("{}.cmd", self.next));
            let deadline = Instant::now() + COMMAND_DEADLINE;
            loop {
                if following.exists() && crossterm::event::poll(Duration::ZERO)? {
                    let line = std::fs::read_to_string(&following)?;
                    return self.run(dispatch, task, line.trim());
                }
                if Instant::now() >= deadline {
                    return Err(io::Error::other("hold never saw its queued input"));
                }
                // Waits on terminal input itself; no sleep.
                crossterm::event::poll(Duration::from_millis(5))?;
            }
        }
    }

    pub(super) fn answer_request(
        question: &Question,
        task: &TaskId,
        session_id: &str,
        command_id: &CommandId,
        intent_revision: u64,
        task_revision: u64,
    ) -> Value {
        json!({
            "jsonrpc": "2.0", "id": 91, "method": "task.submit",
            "params": {
                "schema_version": 1, "command_id": command_id.0,
                "session_id": session_id, "kind": "answer", "task_id": task.0,
                "question_id": question.question_id.0,
                "question_revision": question.question_revision,
                "selection": { "kind": "option", "option_id": question.recommended_option_id.0 },
                "expected_intent_revision": intent_revision,
                "expected_task_revision": task_revision,
            }
        })
    }

    pub(super) fn child_exited_cleanly(status: Option<u32>) -> bool {
        status == Some(0)
    }

    pub(super) fn normal_exit_succeeded(
        status: Option<u32>,
        outcome: Option<&[u8]>,
    ) -> Result<bool, CardDriverError> {
        let Some(outcome) = outcome else {
            return Ok(false);
        };
        let outcome: Value = serde_json::from_slice(outcome)?;
        Ok(child_exited_cleanly(status) && outcome == json!({ "exit": 0 }))
    }

    fn execute(
        dispatch: &mut TuiDispatch,
        task: Option<&TaskId>,
        line: &str,
    ) -> Result<Value, String> {
        let mut words = line.split_whitespace();
        let verb = words.next().unwrap_or_default();
        if verb == "hold" {
            return Ok(Value::Null);
        }
        if verb == "ping" {
            return Ok(Value::Null);
        }
        if verb == PANIC_REQUEST {
            // The panic leg's subject is the terminal guard's restore, so the
            // child has to die while the card owns the alternate screen: the
            // hook the guard installs and its `Drop` are then the only things
            // left that can give the terminal back.
            unreachable!("{PANIC_REPORT}");
        }
        if verb == "close-store" {
            return dispatch
                .runtime
                .owner
                .store
                .close()
                .map(|()| Value::Null)
                .map_err(|error| error.to_string());
        }
        if verb == "fail-status" {
            let count: usize = words
                .next()
                .ok_or("fail-status needs a count")?
                .parse()
                .map_err(|error: std::num::ParseIntError| error.to_string())?;
            dispatch.fail_status(count);
            return Ok(Value::Null);
        }
        // A durable task this view never submitted: the composer writes no
        // dock row for it, so only the projection can paint it.
        if verb == "seed" {
            let session_id = dispatch.session_id.clone();
            dispatch_tui_request(
                &mut dispatch.runtime,
                json!({
                    "jsonrpc": "2.0", "id": 93, "method": "task.submit",
                    "params": {
                        "schema_version": 1, "command_id": CommandId::generate().0,
                        "session_id": session_id, "kind": "create",
                        "goal": "recover the rollout",
                        "contract": { "criteria": [], "constraints": [] },
                    }
                }),
            )
            .map_err(|error| error.to_string())?;
            return dispatch.status().map_err(|error| error.to_string());
        }
        if verb == "recover" {
            // The restart path: the durable stream re-delivered with its own
            // duplicates and in reverse order, exactly as a resume may see
            // it. One consistent projection has to come back out.
            let task_id = TaskId(words.next().ok_or("recover needs a task id")?.to_string());
            let session = SessionId(dispatch.session_id.clone());
            let events = dispatch
                .runtime
                .store()
                .events_after(&session, Some(&task_id), 0, 100)
                .map_err(|error| error.to_string())?;
            let mut replayed = events.iter().rev().cloned().collect::<Vec<_>>();
            replayed.extend(events.iter().cloned());
            dispatch
                .runtime
                .store_writer()
                .recover_events(&session, &replayed)
                .map_err(|error| error.to_string())?;
            return dispatch.status().map_err(|error| error.to_string());
        }
        if verb == "new-context" {
            // The second conversation of the two-task legs, before anything
            // is recorded in it: a fresh task whose context is still small.
            let task_id = context_task(dispatch)?;
            return context_reply(dispatch, &task_id);
        }
        if verb == "fill-context" {
            // The near-full legs' fill. Without an argument the child mints
            // the context task; a named one is a conversation it already
            // opened. A handful of large observations — 18 records of
            // ~49 KiB — carries the assembled context past four fifths of
            // the admission ceiling while the record list a fold keeps stays
            // small.
            let task_id = match words.next() {
                Some(task_id) => TaskId(task_id.to_string()),
                None => context_task(dispatch)?,
            };
            {
                let mut writer = dispatch.runtime.store_writer();
                let scope = format!("task:{}", task_id.0);
                for index in 0..18_u8 {
                    let observation = format!(
                        "read the notes {}",
                        "a scoped line of the file ".repeat(1800)
                    );
                    writer
                        .insert_evidence(
                            &task_id,
                            0,
                            &scope,
                            &observation,
                            &format!("{index:02x}").repeat(32),
                        )
                        .map_err(|error| error.to_string())?;
                }
            }
            return context_reply(dispatch, &task_id);
        }
        if verb == "context-bytes" {
            let task_id = TaskId(
                words
                    .next()
                    .ok_or("context-bytes needs a task id")?
                    .to_string(),
            );
            return context_reply(dispatch, &task_id);
        }
        if verb == "auto-compact" {
            // The guard the warning is gated on, written through the owner's
            // own ingress: the document and the reload are the ones a user
            // edit takes, so the leg observes the production path.
            let enabled = match words.next() {
                Some("on") => true,
                Some("off") => false,
                _ => return Err("auto-compact needs on or off".to_string()),
            };
            let path = dispatch.runtime.config_path.clone();
            std::fs::write(
                &path,
                format!(
                    "config_version = 1\n[connections.primary]\nkind = \"api_key\"\nendpoint = \"https://api.openai.com/v1\"\ncredential_ref = \"keyring:primary\"\n[models.defaults]\nmodel = {{ mode = \"auto\" }}\neffort = {{ mode = \"auto\" }}\nfallback = {{ mode = \"auto\" }}\n[context]\nauto_compact = {enabled}\n"
                ),
            )
            .map_err(|error| error.to_string())?;
            // The owner's own reload, with its typed causes in the report: a
            // document it refuses says which key and why.
            dispatch.runtime.reload_config().map_err(|error| {
                match std::error::Error::source(&error) {
                    Some(cause) => format!("{error}: {cause}"),
                    None => error.to_string(),
                }
            })?;
            return dispatch.status().map_err(|error| error.to_string());
        }
        if verb == "complete" {
            // The task the composer tracked, or the one the leg names: a
            // conversation the parent opened through the fill seam belongs
            // to no composer submit.
            let subject = match words.next() {
                Some(task_id) => TaskId(task_id.to_string()),
                None => task.cloned().ok_or("complete needs a task id")?,
            };
            let session_id = SessionId(dispatch.session_id.clone());
            let snapshot = dispatch
                .runtime
                .store_writer()
                .complete_if_eligible(&session_id, &subject)
                .map_err(|error| error.to_string())?;
            return serde_json::to_value(snapshot.lifecycle).map_err(|error| error.to_string());
        }
        let task = task.ok_or("no tracked task")?;
        let pending = |dispatch: &TuiDispatch| {
            dispatch
                .runtime
                .store()
                .current_question(task)
                .map_err(|error| error.to_string())?
                .map(|(question, _)| question)
                .ok_or_else(|| "no pending question".to_string())
        };
        let session = SessionId("decision-pty".to_string());
        match verb {
            "block" => {
                // The owner's no-ready transition: a ready-set the plan cannot
                // serve, not a dispatch and not a model call.
                dispatch
                    .runtime
                    .store_writer()
                    .mark_no_ready(task)
                    .map(|()| Value::Null)
                    .map_err(|error| error.to_string())
            }
            "cancel" => {
                let snapshot = dispatch
                    .runtime
                    .store()
                    .snapshot(task)
                    .map_err(|error| error.to_string())?;
                let session_id = SessionId(dispatch.session_id.clone());
                dispatch
                    .runtime
                    .store_writer()
                    .cancel_task(
                        &session_id,
                        task,
                        snapshot.intent_revision,
                        Some("operator stop"),
                    )
                    .map(|result| json!({ "status": result.status }))
                    .map_err(|error| error.to_string())
            }
            "publish" => {
                let revision: u64 = words
                    .next()
                    .ok_or("publish needs an intent revision")?
                    .parse()
                    .map_err(|error: std::num::ParseIntError| error.to_string())?;
                let session = SessionId(
                    words
                        .next()
                        .ok_or("publish needs a session id")?
                        .to_string(),
                );
                let question = Question::fixture(task, revision);
                dispatch
                    .runtime
                    .store_writer()
                    .publish_question(&session, &question)
                    .map_err(|error| error.to_string())?;
                serde_json::to_value(&question).map_err(|error| error.to_string())
            }
            "steer" => {
                let snapshot = dispatch
                    .runtime
                    .store()
                    .snapshot(task)
                    .map_err(|error| error.to_string())?;
                let session_id = dispatch.session_id.clone();
                dispatch_tui_request(
                    &mut dispatch.runtime,
                    json!({
                        "jsonrpc": "2.0", "id": 90, "method": "task.submit",
                        "params": {
                            "schema_version": 1, "command_id": CommandId::generate().0,
                            "session_id": session_id, "kind": "steer", "task_id": task.0,
                            "expected_intent_revision": snapshot.intent_revision,
                            "expected_task_revision": snapshot.revision,
                            "instruction": "hold the rollout", "attachments": [],
                        }
                    }),
                )
                .map_err(|error| error.to_string())
            }
            "answer" => {
                let question = pending(dispatch)?;
                // The resumed task reads under the runtime's scope grant,
                // which a TUI runtime has none of until the driver sets one.
                let scope = dispatch.runtime.owner().runtime_dir().join("scope");
                let scoped_file = scope.join("allowed.txt");
                std::fs::create_dir_all(&scope).map_err(|error| error.to_string())?;
                std::fs::write(&scoped_file, b"card-driver-scope\n")
                    .map_err(|error| error.to_string())?;
                dispatch.runtime.purpose = "backend_task".to_string();
                dispatch.runtime.set_read_scope(scope, scoped_file);
                let snapshot = dispatch
                    .runtime
                    .store()
                    .snapshot(task)
                    .map_err(|error| error.to_string())?;
                let session_id = dispatch.session_id.clone();
                dispatch_tui_request(
                    &mut dispatch.runtime,
                    answer_request(
                        &question,
                        task,
                        &session_id,
                        &CommandId::generate(),
                        snapshot.intent_revision,
                        snapshot.revision,
                    ),
                )
                .map_err(|error| error.to_string())
            }
            "resolve" => {
                let question = pending(dispatch)?;
                let result = dispatch
                    .runtime
                    .store_writer()
                    .answer_question(
                        &session,
                        task,
                        &question.question_id,
                        question.question_revision,
                        &AnswerSelection::Option {
                            option_id: question.recommended_option_id.clone(),
                        },
                        "human",
                    )
                    .map_err(|error| error.to_string())?;
                Ok(json!({ "status": result.status }))
            }
            "report" => {
                let store = dispatch.runtime.store();
                let current = store
                    .current_question(task)
                    .map_err(|error| error.to_string())?
                    .map(|(question, _)| question);
                let attempts = store
                    .answer_attempts(task)
                    .map_err(|error| error.to_string())?
                    .iter()
                    .map(|attempt| {
                        json!({
                            "outcome": match attempt.outcome {
                                AnswerAttemptOutcome::Applied => "applied",
                                AnswerAttemptOutcome::Denied => "denied",
                            },
                            "author": attempt.author,
                        })
                    })
                    .collect::<Vec<_>>();
                Ok(json!({ "current": current, "attempts": attempts }))
            }
            other => Err(format!("unknown card-driver verb {other:?}")),
        }
    }

    /// One conversation for the near-full legs: a task with a criterion the
    /// parent can fill, its obligations already materialized so a record
    /// insert has an obligation to land on. The child mints it, because the
    /// session its runtime opened is the only one its store answers for.
    fn context_task(dispatch: &mut TuiDispatch) -> Result<TaskId, String> {
        let session_id = dispatch.session_id.clone();
        let created = dispatch_tui_request(
            &mut dispatch.runtime,
            json!({
                "jsonrpc": "2.0", "id": 94, "method": "task.submit",
                "params": {
                    "schema_version": 1, "command_id": CommandId::generate().0,
                    "session_id": session_id, "kind": "create",
                    "goal": "fold the rollout notes",
                    "contract": {
                        "criteria": ["read the rollout notes"],
                        "constraints": [],
                    },
                }
            }),
        )
        .map_err(|error| error.to_string())?;
        let task_id = TaskId(
            created
                .get("task_id")
                .and_then(Value::as_str)
                .ok_or("the context task.submit omitted task_id")?
                .to_string(),
        );
        dispatch
            .runtime
            .store_writer()
            .materialize_obligations(&task_id)
            .map_err(|error| error.to_string())?;
        Ok(task_id)
    }

    /// The bytes and digest of one task's assembled context as the child's
    /// own store serves them: the number the warning is measured against,
    /// and the bytes a paint must leave untouched.
    fn context_reply(dispatch: &TuiDispatch, task_id: &TaskId) -> Result<Value, String> {
        let context = dispatch
            .runtime
            .store()
            .assembled_context(task_id)
            .map_err(|error| error.to_string())?;
        Ok(json!({
            "task_id": task_id.0,
            "bytes": context.text.len(),
            "digest": crate::config::hex(&Sha256::digest(context.text.as_bytes())),
        }))
    }

    #[test]
    #[ignore = "card-driver child: its parent spawns it with the marker"]
    fn card_driver_child() -> Result<(), CardDriverError> {
        let root = match std::env::var_os(CARD_DRIVER_MARKER) {
            Some(value) if !value.is_empty() => PathBuf::from(value),
            _ => {
                return Err(CardDriverError::MissingMarker {
                    marker: CARD_DRIVER_MARKER,
                });
            }
        };
        let ctl = root.join("ctl");
        {
            // Clears libtest's banner from the reconstructed grid before the
            // alternate screen.
            let mut stdout = io::stdout().lock();
            stdout.write_all(b"\x1b[2J\x1b[H")?;
            stdout.flush()?;
        }
        if let Some(mode) = std::env::var_os(RELEASE_FAULT_MARKER) {
            // The release seam is armed on this thread, the one that opens
            // and drops the only `Runtime`.
            if mode == "retry" {
                std::fs::write(root.join("data").join("config.toml"), "[")?;
                crate::state::proof::arm_unlock_faults(4);
            } else if mode == "exit" {
                crate::state::proof::arm_unlock_faults(2);
                // The main screen keeps this row while the card owns the
                // alternate one: it is longer than the release line, so the
                // report must erase the row's tail, not only overwrite its
                // head. The cursor returns to column 0 where the leave
                // restores it.
                let mut stdout = io::stdout().lock();
                stdout.write_all(
                    b"stale main-screen row, longer than the release line that must replace it, \
                      never part of the verdict\r",
                )?;
                stdout.flush()?;
            } else {
                return Err(CardDriverError::Io(io::Error::from(
                    io::ErrorKind::InvalidInput,
                )));
            }
        }
        let mut control = Control {
            dir: ctl.clone(),
            next: 1,
            started: Instant::now(),
        };
        let result = drive_tui(&root.join("data"), |dispatch, task| {
            control.serve(dispatch, task)
        });
        let outcome = match &result {
            Ok(code) => json!({ "exit": code }),
            Err(error) => {
                let report = failure_report(error).to_string();
                let mut stderr = io::stderr().lock();
                if let Err(write_error) = stderr.write_all(format!("{report}\n").as_bytes()) {
                    std::hint::black_box(write_error);
                }
                json!({ "error": report })
            }
        };
        write_atomic(&ctl.join("outcome"), &outcome.to_string())?;
        Ok(())
    }

    // ----- parent side -----

    #[derive(Deserialize)]
    struct Report {
        current: Option<Question>,
        attempts: Vec<ReportedAttempt>,
    }

    #[derive(Deserialize)]
    struct ReportedAttempt {
        outcome: String,
        author: String,
    }

    struct CardDriver {
        pty: PtySession,
        ctl: PathBuf,
        next: u32,
    }

    impl CardDriver {
        fn spawn(rows: u16, cols: u16, env: &[(&str, &str)]) -> Result<Self, CardDriverError> {
            Self::spawn_with(rows, cols, env, None)
        }

        fn spawn_faulted(
            rows: u16,
            cols: u16,
            env: &[(&str, &str)],
            faults: Arc<PtyFaults>,
        ) -> Result<Self, CardDriverError> {
            Self::spawn_with(rows, cols, env, Some(faults))
        }

        fn spawn_with(
            rows: u16,
            cols: u16,
            env: &[(&str, &str)],
            faults: Option<Arc<PtyFaults>>,
        ) -> Result<Self, CardDriverError> {
            // The child's effects need the confined helper beside the test
            // binary, so build it before any card spawn, not on first denial.
            crate::executor::test_helper::ensure_helper();
            let root = TempDir::with_prefix("rivect-card-pty-")?;
            let data = root.path().join("data");
            let ctl = root.path().join("ctl");
            std::fs::create_dir_all(&data)?;
            std::fs::create_dir_all(&ctl)?;
            let mut command = pty_command(std::env::current_exe()?);
            command.env(CARD_DRIVER_MARKER, root.path());
            for (name, value) in env {
                command.env(name, value);
            }
            command.args([
                "ui::card_pty::card_driver_child",
                "--exact",
                "--ignored",
                "--test-threads=1",
                "--nocapture",
                "--color",
                "never",
            ]);
            let pty = match faults {
                Some(faults) => PtySession::spawn_faulted(command, rows, cols, root, data, faults),
                None => PtySession::spawn(command, rows, cols, root, data),
            }
            .map_err(io::Error::other)?;
            Ok(Self { pty, ctl, next: 0 })
        }

        /// One control command: written tmp-then-rename, answered by its
        /// ack. The wait pumps the PTY so the child never blocks on a full
        /// output buffer before its next pass.
        fn command(&mut self, line: &str) -> Result<Value, CardDriverError> {
            self.next += 1;
            let number = self.next;
            write_atomic(&self.ctl.join(format!("{number}.cmd")), line)?;
            let ack = self.ctl.join(format!("{number}.ack"));
            let deadline = Instant::now() + COMMAND_DEADLINE;
            loop {
                if let Some(text) = read_if_present(&ack)? {
                    let mut reply: Value = serde_json::from_str(&text).map_err(io::Error::other)?;
                    if let Some(message) = reply.get("error") {
                        return Err(io::Error::other(format!(
                            "card command {line:?} failed: {message}"
                        ))
                        .into());
                    }
                    return Ok(reply["ok"].take());
                }
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("card command {line:?} was never acknowledged"),
                    )
                    .into());
                }
                self.pty.pump_for(Duration::from_millis(25))?;
            }
        }

        /// Writes a control command without waiting for its ack: the child
        /// dies serving this one, so an ack would never come.
        fn enqueue(&mut self, line: &str) -> Result<(), CardDriverError> {
            self.next += 1;
            write_atomic(&self.ctl.join(format!("{}.cmd", self.next)), line)?;
            Ok(())
        }

        fn publish(&mut self, intent_revision: u64) -> Question {
            let reply = must(
                self.command(&format!("publish {intent_revision} decision-pty")),
                "the fork publishes",
            );
            must(
                serde_json::from_value(reply),
                "the publish reply is the question",
            )
        }

        fn report(&mut self) -> Report {
            let reply = must(self.command("report"), "the report answers");
            must(serde_json::from_value(reply), "the report decodes")
        }

        /// The child exited and recorded its outcome: the post-exit store
        /// read, made only after the child's `Runtime` is gone.
        fn exited(&self) -> (Value, TaskStore) {
            let text = must(
                std::fs::read_to_string(self.ctl.join("outcome")),
                "outcome file",
            );
            let store = must(
                TaskStore::open(&self.pty.data_root().join("runtime").join("rivect.db")),
                "post-exit store opens",
            );
            (must(serde_json::from_str(&text), "outcome decodes"), store)
        }

        fn finish(self) -> Result<(), CardDriverError> {
            Ok(self.pty.finish()?)
        }
    }

    fn secs(count: u64) -> Duration {
        Duration::from_secs(count)
    }

    fn screen(
        pty: &PtySession,
        rows: usize,
        cols: usize,
        needle: &str,
        timeout: Duration,
    ) -> String {
        must(
            wait_for_screen_text(pty, rows, cols, needle, timeout),
            "pty screen",
        )
    }

    fn press(pty: &mut PtySession, bytes: &[u8]) {
        must(pty.send(bytes), "pty send");
    }

    fn seen(pty: &mut PtySession, needle: &[u8], timeout: Duration) -> bool {
        must(pty.wait_for(needle, timeout), "pty read")
    }

    fn stream(pty: &PtySession) -> Vec<u8> {
        must(pty.collected(), "pty read")
    }

    fn pause(pty: &mut PtySession, duration: Duration) {
        must(pty.pump_for(duration), "pty pump");
    }

    /// Honest wait for the card's consent floor: the footer needle proves
    /// the frame painted — which is when `DECISION_CONSENT_DELAY` starts —
    /// but nothing on screen marks the window's end, so callers that send
    /// Enter or Esc right after first paint wait out the named contract
    /// duration, with the output pumped.
    fn wait_consent_window(pty: &mut PtySession) -> Result<(), PtyIoError> {
        pty.pump_for(DECISION_CONSENT_DELAY)
    }

    fn expect_exit(driver: &mut CardDriver, timeout: Duration) {
        assert!(
            child_exited_cleanly(must(driver.pty.wait_exit(timeout), "pty wait")),
            "the child test exits cleanly"
        );
    }

    fn expect_normal_outcome(driver: &CardDriver, status: Option<u32>) {
        let outcome = must(std::fs::read(driver.ctl.join("outcome")), "outcome file");
        assert!(
            must(
                normal_exit_succeeded(status, Some(&outcome)),
                "outcome decodes",
            ),
            "the child records runtime exit zero"
        );
    }

    fn expect_normal_exit(driver: &mut CardDriver, timeout: Duration) {
        let status = must(driver.pty.wait_exit(timeout), "pty wait");
        assert!(child_exited_cleanly(status), "the child test exits cleanly");
        expect_normal_outcome(driver, status);
    }

    fn teardown(driver: CardDriver) {
        must(driver.finish(), "card teardown");
    }

    /// The task id the dock row names (`task <id>: <lifecycle>`).
    fn dock_task_id(visible: &str) -> String {
        let Some(id) = visible
            .lines()
            .find_map(|line| line.strip_prefix("task "))
            .and_then(|rest| rest.split(':').next())
        else {
            unreachable!("the dock carries the task id: {visible}");
        };
        id.to_string()
    }

    struct Opened {
        driver: CardDriver,
        question: Question,
        screen: String,
    }

    /// Spawns the TUI at `(rows, cols)`, submits one task, publishes the
    /// fixture fork through the child's own runtime, and returns once the
    /// card is on screen. The screen reconstruction is ASCII-only —
    /// assertions needing non-ASCII bytes go to `seen`/`stream` instead.
    fn open_card_unwaited(rows: u16, cols: u16, env: &[(&str, &str)]) -> Opened {
        let mut driver = must(CardDriver::spawn(rows, cols, env), "card spawn");
        assert!(
            seen(&mut driver.pty, b"\x1b[?1049h", secs(10)),
            "alternate screen must be entered on start"
        );
        press(&mut driver.pty, b"pick a rollout lane\r");
        let visible = screen(
            &driver.pty,
            rows as usize,
            cols as usize,
            "Submitted task:",
            secs(10),
        );
        assert!(
            visible.contains("Submitted task:"),
            "the task receipt renders: {visible}"
        );
        let question = driver.publish(1);
        // `focus 1/6` sits in the pinned footer — the LAST text a card
        // frame emits. Waiting on it proves the whole frame landed.
        let screen_text = screen(
            &driver.pty,
            rows as usize,
            cols as usize,
            "focus 1/6",
            secs(10),
        );
        assert!(
            screen_text.contains("focus 1/6"),
            "the card opens on the pending question: {screen_text}"
        );
        Opened {
            driver,
            question,
            screen: screen_text,
        }
    }

    /// `open_card_unwaited` plus the consent-floor wait every leg that
    /// sends consent keys needs.
    fn open_card(rows: u16, cols: u16, env: &[(&str, &str)]) -> Opened {
        let mut opened = open_card_unwaited(rows, cols, env);
        must(wait_consent_window(&mut opened.driver.pty), "pty pump");
        opened
    }

    #[test]
    fn pty_decision_card_surfaces_and_commits_on_60x20() {
        let mut driver = must(
            CardDriver::spawn(DECISION_PTY_ROWS as u16, DECISION_PTY_COLS as u16, &[]),
            "card spawn",
        );
        assert!(
            seen(&mut driver.pty, b"\x1b[?1049h", secs(10)),
            "alternate screen must be entered on start"
        );

        press(&mut driver.pty, b"pick a rollout lane\r");
        let visible = screen(
            &driver.pty,
            DECISION_PTY_ROWS,
            DECISION_PTY_COLS,
            "Submitted task: pick a rollout lane (accepted: ",
            secs(10),
        );
        assert!(
            visible.contains("Submitted task: pick a rollout lane"),
            "the task receipt renders: {visible}"
        );
        // The dock row carries the full id; the transcript receipt clips
        // at 60 columns.
        let task_id = dock_task_id(&visible);

        // The material fork arrives through the child's own runtime; the
        // card picks it up on its next poll.
        let question = driver.publish(1);
        assert_eq!(question.task_id.0, task_id, "the fork pins the dock's task");

        // The footer needle waits out the whole frame: `decision` paints in
        // the header while the body and footer are still in flight, so the
        // hidden-row assert below would race the tail of the draw.
        let visible = screen(
            &driver.pty,
            DECISION_PTY_ROWS,
            DECISION_PTY_COLS,
            "focus 1/6",
            secs(10),
        );
        assert!(
            visible.contains("focus 1/6"),
            "the decision card opens on the pending question: {visible}"
        );
        assert!(
            visible.contains("recommended"),
            "positions and recommendation render: {visible}"
        );
        assert!(
            visible.contains("hidden") && visible.contains("PgUp/PgDn"),
            "the pinned footer reports hidden rows and the scroll hint: {visible}"
        );
        // The commit Enter below is consent: the card must have been
        // visible past the floor before it can be aimed.
        pause(&mut driver.pty, DECISION_CONSENT_DELAY);

        // PgDn scrolls the body under the pinned frame — focus never moves,
        // the window does. At the scroll floor nothing can hide below, so
        // the previously hidden custom row paints and the footer's
        // hidden-row count decrements; PgUp walks the same window back and
        // the count returns to the open frame's.
        for _ in 0..2 {
            press(&mut driver.pty, b"\x1b[B");
        }
        let visible = screen(
            &driver.pty,
            DECISION_PTY_ROWS,
            DECISION_PTY_COLS,
            "focus 3/6",
            secs(10),
        );
        let Some(before) = footer_hidden_count(&visible) else {
            unreachable!("the footer counts hidden rows: {visible}");
        };
        for _ in 0..5 {
            press(&mut driver.pty, b"\x1b[6~");
        }
        let visible = screen(
            &driver.pty,
            DECISION_PTY_ROWS,
            DECISION_PTY_COLS,
            "custom answer",
            secs(10),
        );
        assert!(
            visible.contains("custom answer"),
            "PgDn reveals the previously hidden custom row: {visible}"
        );
        assert!(
            squashed(&visible).contains("focus 3/6"),
            "scroll never moves focus: {visible}"
        );
        let dropped = must(
            wait_for_hidden_count(
                &mut driver.pty,
                DECISION_PTY_ROWS,
                DECISION_PTY_COLS,
                |count| count < before,
            ),
            "pty screen",
        );
        assert!(
            dropped < before,
            "scrolling to the floor leaves fewer rows hidden: {before} -> {dropped}"
        );
        for _ in 0..5 {
            press(&mut driver.pty, b"\x1b[5~");
        }
        let visible = screen(
            &driver.pty,
            DECISION_PTY_ROWS,
            DECISION_PTY_COLS,
            "1. Brief",
            secs(10),
        );
        assert!(
            visible.contains("1. Brief"),
            "PgUp scrolls the first row back into view: {visible}"
        );
        let restored = must(
            wait_for_hidden_count(
                &mut driver.pty,
                DECISION_PTY_ROWS,
                DECISION_PTY_COLS,
                |count| count == before,
            ),
            "pty screen",
        );
        assert_eq!(
            restored, before,
            "PgUp returns the window to its open position"
        );

        // Move one position and commit.
        press(&mut driver.pty, b"\x1b[A");
        press(&mut driver.pty, b"\r");
        let visible = screen(
            &driver.pty,
            DECISION_PTY_ROWS,
            DECISION_PTY_COLS,
            "decision answer recorded",
            secs(10),
        );
        assert!(
            visible.contains("decision answer recorded"),
            "Enter commits through the shared answer seam: {visible}"
        );

        press(&mut driver.pty, b"\x1b");
        expect_exit(&mut driver, secs(10));
        let (outcome, store) = driver.exited();
        assert_eq!(outcome, json!({ "exit": 0 }));
        let Some((answer_json, origin)) =
            must(store.answered_question(&TaskId(task_id)), "answered")
        else {
            unreachable!("the PTY answer is durable");
        };
        assert_eq!(origin, "human");
        assert!(answer_json.contains("\"steps\""), "{answer_json}");
        drop(store);
        teardown(driver);
    }

    /// One draft line's marker: the scroll leg's custom answer is fourteen
    /// numbered lines, so each row of the answer is nameable on the
    /// reconstructed screen — the window's head and its tail never share a
    /// marker.
    fn draft_line(line: usize) -> String {
        format!("answer line {line:02}")
    }

    /// Which of the draft's line markers the reconstructed frame paints.
    fn painted_draft_lines(flat: &str, lines: usize) -> Vec<usize> {
        (1..=lines)
            .filter(|line| flat.contains(&draft_line(*line)))
            .collect()
    }

    /// The focused custom answer is one span, so the body window's reveal
    /// arms decide what of it the operator can read. Pinning the window to
    /// the span's first row froze the answer: PgUp and PgDn moved nothing,
    /// and the rows past the body were unreachable. A focused answer taller
    /// than the body scrolls inside itself, both ways, without leaving
    /// focus — while its newest line stays painted as it is typed.
    #[test]
    fn pty_decision_card_scrolls_inside_a_custom_answer_taller_than_the_body() {
        // Fourteen short lines outgrow the 60x20 card's nine-row body: the
        // answer's tail sits outside the window while focus still holds it.
        const LINES: usize = 14;
        // From the tail the answer's first row enters the window five rows
        // up, and it stays inside it for eight more — one turn per row, so
        // this sweep lands inside the answer with rows to spare either way.
        const HEAD_TURNS: usize = 5;

        let Opened { mut driver, .. } =
            open_card(DECISION_PTY_ROWS as u16, DECISION_PTY_COLS as u16, &[]);
        for _ in 0..5 {
            press(&mut driver.pty, b"\x1b[B");
        }
        drop(screen(
            &driver.pty,
            DECISION_PTY_ROWS,
            DECISION_PTY_COLS,
            "focus 6/6",
            secs(10),
        ));

        // Scrolling before editing must not survive into the draft: the
        // answer grows at its end, so the window the operator scrolled to
        // still has to follow it. The `(editing)` wait below is the proof —
        // the row that scroll moved off screen only paints again once the
        // edit re-reveals it.
        press(&mut driver.pty, b"\x1b[5~");
        press(&mut driver.pty, b"\x1b[5~");

        // Enter opens editing on the empty draft; Enter inside editing adds
        // a draft newline, and the remaining lines land as one atomic paste
        // — the draft text typing produces, without a frame per keystroke.
        press(&mut driver.pty, b"\r");
        drop(screen(
            &driver.pty,
            DECISION_PTY_ROWS,
            DECISION_PTY_COLS,
            "(editing)",
            secs(10),
        ));
        press(&mut driver.pty, draft_line(1).as_bytes());
        press(&mut driver.pty, b"\r");
        let rest = (2..=LINES).map(draft_line).collect::<Vec<_>>().join("\n");
        press(
            &mut driver.pty,
            format!("\x1b[200~{rest}\x1b[201~").as_bytes(),
        );

        // Esc leaves editing with the draft intact — only then do PgUp/PgDn
        // reach the body, since editing mode owns every key. The footer hint
        // is the frame boundary: it is painted after the body.
        press(&mut driver.pty, b"\x1b");
        let typed = must(
            wait_for_squashed(
                &mut driver.pty,
                DECISION_PTY_ROWS,
                DECISION_PTY_COLS,
                "arrows move",
                secs(10),
            ),
            "pty screen",
        );
        let painted_typed = painted_draft_lines(&typed, LINES);

        // PgUp walks the window up through the answer: rows that were on
        // screen leave it, which is what a pinned window never does.
        for _ in 0..HEAD_TURNS {
            press(&mut driver.pty, b"\x1b[5~");
        }
        let head = must(
            wait_for_squashed(
                &mut driver.pty,
                DECISION_PTY_ROWS,
                DECISION_PTY_COLS,
                &draft_line(1),
                secs(10),
            ),
            "pty screen",
        );
        let painted_head = painted_draft_lines(&head, LINES);
        assert!(
            painted_head != painted_typed,
            "PgUp moves the window inside the focused answer: typed {painted_typed:?}, up {painted_head:?}"
        );
        assert!(
            !painted_head.contains(&LINES),
            "the answer's tail starts outside the window: {painted_head:?}"
        );

        // PgDn walks it back down; the turns outrun the body, so the sweep
        // parks on the answer's last row.
        for _ in 0..LINES + 2 {
            press(&mut driver.pty, b"\x1b[6~");
        }
        let after = must(
            wait_for_squashed(
                &mut driver.pty,
                DECISION_PTY_ROWS,
                DECISION_PTY_COLS,
                &draft_line(LINES),
                secs(10),
            ),
            "pty screen",
        );
        let painted_after = painted_draft_lines(&after, LINES);
        let revealed: Vec<usize> = painted_after
            .iter()
            .copied()
            .filter(|line| !painted_head.contains(line))
            .collect();
        assert!(
            painted_after.contains(&LINES),
            "PgDn paints the answer's hidden tail: before {painted_head:?}, after {painted_after:?}"
        );
        assert!(
            !revealed.is_empty(),
            "PgDn reveals rows that were hidden: before {painted_head:?}, after {painted_after:?}"
        );
        assert!(
            squashed(&after).contains("focus 6/6"),
            "scrolling inside the answer never moves focus: {painted_after:?}"
        );
        assert!(
            painted_typed.contains(&LINES),
            "the newest line stays painted as the answer grows: {painted_typed:?}"
        );

        // Leave without answering, then quit.
        press(&mut driver.pty, b"\x1b");
        drop(screen(
            &driver.pty,
            DECISION_PTY_ROWS,
            DECISION_PTY_COLS,
            "unanswered",
            secs(10),
        ));
        press(&mut driver.pty, b"\x1b");
        expect_exit(&mut driver, secs(10));
        teardown(driver);
    }

    #[test]
    fn pty_decision_card_esc_returns_without_answering() {
        let mut driver = must(
            CardDriver::spawn(DECISION_PTY_ROWS as u16, DECISION_PTY_COLS as u16, &[]),
            "card spawn",
        );
        assert!(
            seen(&mut driver.pty, b"\x1b[?1049h", secs(10)),
            "alternate screen"
        );
        press(&mut driver.pty, b"lane pick\r");
        let visible = screen(
            &driver.pty,
            DECISION_PTY_ROWS,
            DECISION_PTY_COLS,
            "Submitted task: lane pick (accepted: ",
            secs(10),
        );
        assert!(
            visible.contains("Submitted task: lane pick"),
            "the task receipt renders: {visible}"
        );
        let task_id = dock_task_id(&visible);

        let question = driver.publish(1);
        assert_eq!(question.task_id.0, task_id, "the fork pins the dock's task");
        let visible = screen(
            &driver.pty,
            DECISION_PTY_ROWS,
            DECISION_PTY_COLS,
            "focus 1/6",
            secs(10),
        );
        assert!(visible.contains("focus 1/6"), "{visible}");

        // Esc is consent too — it must be sent after the floor or the card
        // refuses it. First Esc closes the card; the second quits the TUI.
        pause(&mut driver.pty, DECISION_CONSENT_DELAY);
        press(&mut driver.pty, b"\x1b");
        let visible = screen(
            &driver.pty,
            DECISION_PTY_ROWS,
            DECISION_PTY_COLS,
            "decision left unanswered",
            secs(10),
        );
        assert!(
            visible.contains("decision left unanswered"),
            "Esc returns without answering: {visible}"
        );
        press(&mut driver.pty, b"\x1b");
        expect_exit(&mut driver, secs(10));
        let (outcome, store) = driver.exited();
        assert_eq!(outcome, json!({ "exit": 0 }));
        assert!(
            must(store.current_question(&TaskId(task_id)), "current").is_some(),
            "the question is still pending after Esc"
        );
        drop(store);
        teardown(driver);
    }

    /// `wait_for_screen_text` on the whitespace-normalized frame: the card
    /// wraps long text across rows, so a raw `contains` can never match a
    /// reason that wraps — and polling until the needle itself renders
    /// waits out the repaint burst instead of asserting a mid-frame capture.
    fn wait_for_squashed(
        pty: &mut PtySession,
        rows: usize,
        cols: usize,
        needle: &str,
        timeout: Duration,
    ) -> Result<String, PtyIoError> {
        let deadline = Instant::now() + timeout;
        let mut flat = String::new();
        while Instant::now() < deadline {
            flat = squashed(&reconstruct_screen(&pty.collected()?, rows, cols));
            if flat.contains(needle) {
                return Ok(flat);
            }
            pty.pump_for(Duration::from_millis(25))?;
        }
        Ok(flat)
    }

    /// The glyphs the card's frame is drawn from: a border column ends every
    /// card row, so it also falls between a row's last word and the next
    /// row's first.
    fn is_frame_glyph(ch: char) -> bool {
        ('\u{2500}'..='\u{257f}').contains(&ch)
    }

    /// The card's readable text at `(rows, cols)`: `replay_at`'s cells on the
    /// grid a terminal of that size shows, squashed with the frame glyphs
    /// dropped. The hand-written reconstruction in `tests/support/pty.rs`
    /// blanks every non-ASCII grapheme, so the border between two wrapped rows
    /// reads as a space there; cells keep it, and the 60-column card's disabled
    /// reason wraps exactly across that border. The cells stay the oracle:
    /// text a narrower or shorter grid clips or scrolls away is still absent.
    fn card_text(pty: &PtySession, rows: u16, cols: u16) -> Result<String, PtyIoError> {
        let cells = must(replay_at(&pty.collected()?, rows, cols), "pty screen")
            .settled
            .join("\n");
        Ok(squashed(&cells.replace(is_frame_glyph, " ")))
    }

    /// `card_text` polled until `needle` renders: `wait_for_squashed`'s wait
    /// shape, on cells instead of the reconstruction.
    fn wait_for_card_text(
        pty: &mut PtySession,
        rows: u16,
        cols: u16,
        needle: &str,
        timeout: Duration,
    ) -> Result<String, PtyIoError> {
        let deadline = Instant::now() + timeout;
        let mut flat = String::new();
        while Instant::now() < deadline {
            flat = card_text(pty, rows, cols)?;
            if flat.contains(needle) {
                return Ok(flat);
            }
            pty.pump_for(Duration::from_millis(25))?;
        }
        Ok(flat)
    }

    /// The `N hidden` count the pinned footer reports. The segment is
    /// absent entirely when nothing is hidden — a painted `focus` counter
    /// with no `hidden` tail IS a zero — while no `focus` at all means the
    /// card is not on screen.
    fn footer_hidden_count(screen: &str) -> Option<usize> {
        let flat = squashed(screen);
        if !flat.contains("focus") {
            return None;
        }
        match flat.find("hidden") {
            None => Some(0),
            Some(index) => flat[..index].split_whitespace().last()?.parse().ok(),
        }
    }

    /// Polls the footer's hidden-row count until `done` accepts it — the
    /// count is render output, so a scroll assertion must wait for the
    /// repaint rather than read the frame that may still be in flight.
    /// Returns the last count seen when the deadline expires.
    fn wait_for_hidden_count(
        pty: &mut PtySession,
        rows: usize,
        cols: usize,
        done: impl Fn(usize) -> bool,
    ) -> Result<usize, PtyIoError> {
        let deadline = Instant::now() + secs(10);
        let mut count = usize::MAX;
        while Instant::now() < deadline {
            let screen = reconstruct_screen(&pty.collected()?, rows, cols);
            if let Some(seen) = footer_hidden_count(&screen) {
                count = seen;
                if done(seen) {
                    return Ok(seen);
                }
            }
            pty.pump_for(Duration::from_millis(25))?;
        }
        Ok(count)
    }

    /// The column of the last `CSI row;col H` cursor address before `pos` —
    /// how a painted grapheme's cell stride is read off the raw stream.
    /// Returns `None` when no cursor address precedes the byte (plain
    /// back-to-back writes), which is exactly the one-cell-per-grapheme
    /// shape the width-2 assertion rejects.
    fn cursor_column_before(bytes: &[u8], pos: usize) -> Option<usize> {
        let mut index = pos;
        while index > 0 {
            index -= 1;
            if bytes[index] != b'H' {
                continue;
            }
            // The final byte is `H`; its parameters are digits and `;` —
            // anything else before them means this `H` was literal text.
            let mut start = index;
            while start > 0 && (bytes[start - 1].is_ascii_digit() || bytes[start - 1] == b';') {
                start -= 1;
            }
            if start >= 2 && bytes[start - 2] == 0x1b && bytes[start - 1] == b'[' {
                let params = std::str::from_utf8(&bytes[start..index]).ok()?;
                return params.split(';').nth(1)?.parse::<usize>().ok();
            }
        }
        None
    }

    /// The card clamps at 60 columns and only its height follows the
    /// viewport, so the same assertions hold across the matrix — that
    /// stability is itself the claim under test. The geometries are the
    /// ASM-002 set as `(rows, cols)`: 60x20, 80x24, 120x40, 160x50. Every
    /// frame here is read as cells: `card_text`/`wait_for_card_text` replay
    /// the stream through the same `vt100` model `replay` settles the exit
    /// legs on, sized to the viewport under test, so a screen claim at a
    /// geometry is a claim about the cells a terminal of that geometry holds.
    /// Text a grid this size clips or scrolls away is not in those cells, and
    /// the only thing dropped is the card's own frame: at 60 columns its
    /// reason wraps inside the row, and the border glyph that ends the row
    /// sits between the two halves of it.
    #[test]
    fn pty_decision_card_geometry_matrix() {
        for (rows, cols) in [(20u16, 60u16), (24, 80), (40, 120), (50, 160)] {
            let Opened { mut driver, .. } = open_card(rows, cols, &[]);
            let flat = must(card_text(&driver.pty, rows, cols), "pty screen");
            assert!(
                flat.contains("focus 1/6"),
                "{rows}x{cols}: the pinned footer opens on row one: {flat}"
            );
            assert!(
                flat.contains("recommended"),
                "{rows}x{cols}: the preamble renders: {flat}"
            );

            // Focus the disabled `diagram` row: the reason renders on the
            // row itself, wrapped but present, not only inside a denial.
            // "5/6" is the settle marker — it proves the four Downs landed;
            // at taller viewports the reason is visible without them.
            for _ in 0..4 {
                press(&mut driver.pty, b"\x1b[B");
            }
            drop(must(
                wait_for_card_text(&mut driver.pty, rows, cols, "5/6", secs(10)),
                "pty screen",
            ));
            let flat = must(
                wait_for_card_text(
                    &mut driver.pty,
                    rows,
                    cols,
                    "unavailable: no useful diagram for this topic",
                    secs(10),
                ),
                "pty screen",
            );
            assert!(
                flat.contains("focus 5/6"),
                "{rows}x{cols}: the last option row takes focus: {flat}"
            );
            assert!(
                flat.contains("unavailable: no useful diagram for this topic"),
                "{rows}x{cols}: the disabled row carries its reason: {flat}"
            );

            // The custom row is the last row and stays reachable.
            press(&mut driver.pty, b"\x1b[B");
            let flat = must(
                wait_for_card_text(&mut driver.pty, rows, cols, "focus 6/6", secs(10)),
                "pty screen",
            );
            assert!(
                flat.contains("focus 6/6") && flat.contains("6. custom answer"),
                "{rows}x{cols}: the custom row is reachable: {flat}"
            );

            // Leave without answering, then quit.
            press(&mut driver.pty, b"\x1b");
            drop(must(
                wait_for_card_text(&mut driver.pty, rows, cols, "unanswered", secs(10)),
                "pty screen",
            ));
            press(&mut driver.pty, b"\x1b");
            let status = must(driver.pty.wait_exit(secs(10)), "pty wait");
            assert!(child_exited_cleanly(status), "{rows}x{cols}: clean exit");
            expect_normal_outcome(&driver, status);
            teardown(driver);
        }
    }

    /// Whether the card paints its row-level focus marker on the body row
    /// naming `row`: `> ` leads the focused position's row and two spaces
    /// lead every other. `None` means the row is not on this frame at all
    /// — a different failure from a row that lost its marker.
    fn focus_marker(screen: &str, row: &str) -> Option<bool> {
        let line = screen.lines().find(|line| line.contains(row))?;
        Some(line.trim_start().starts_with("> "))
    }

    /// The footer counter is display state; the `> ` that leads the focused
    /// row is the indication a reader actually follows, and only the counter
    /// was asserted. The marker is asserted on the focused row, on its
    /// neighbour, and again after focus moves either way — at both ends of
    /// the geometry matrix, where the card's horizontal centring puts the
    /// marker in a different column.
    #[test]
    fn pty_decision_card_marks_only_the_focused_row() {
        for (rows, cols) in [(20u16, 60u16), (40, 120)] {
            let Opened {
                mut driver,
                screen: opened,
                ..
            } = open_card(rows, cols, &[]);
            assert_eq!(
                focus_marker(&opened, "1. Brief answer"),
                Some(true),
                "{rows}x{cols}: the focused row carries the marker: {opened}"
            );
            assert_eq!(
                focus_marker(&opened, "2. Step-by-step"),
                Some(false),
                "{rows}x{cols}: the neighbouring row does not: {opened}"
            );

            press(&mut driver.pty, b"\x1b[B");
            let moved = screen(
                &driver.pty,
                rows as usize,
                cols as usize,
                "focus 2/6",
                secs(10),
            );
            assert_eq!(
                focus_marker(&moved, "2. Step-by-step"),
                Some(true),
                "{rows}x{cols}: the marker moves with focus: {moved}"
            );
            assert_eq!(
                focus_marker(&moved, "1. Brief answer"),
                Some(false),
                "{rows}x{cols}: the row focus left is unmarked: {moved}"
            );

            press(&mut driver.pty, b"\x1b[A");
            let back = screen(
                &driver.pty,
                rows as usize,
                cols as usize,
                "focus 1/6",
                secs(10),
            );
            assert_eq!(
                focus_marker(&back, "1. Brief answer"),
                Some(true),
                "{rows}x{cols}: the marker returns with focus: {back}"
            );
            assert_eq!(
                focus_marker(&back, "2. Step-by-step"),
                Some(false),
                "{rows}x{cols}: nothing marks the row focus left: {back}"
            );

            // Leave without answering, then quit.
            press(&mut driver.pty, b"\x1b");
            drop(screen(
                &driver.pty,
                rows as usize,
                cols as usize,
                "unanswered",
                secs(10),
            ));
            press(&mut driver.pty, b"\x1b");
            expect_normal_exit(&mut driver, secs(10));
            teardown(driver);
        }
    }

    /// The design brief's verification geometries end in "+ live resize":
    /// the card clamps to 60 columns and takes its height from the viewport,
    /// so a terminal that grows must show more of the body on its next
    /// frame. The pty is resized under the live child — the kernel's winsize
    /// change, which is what a real window does — and the card has to repaint
    /// inside the new geometry: the option body and the pinned footer both
    /// readable there, with no row left hidden.
    #[test]
    fn pty_decision_card_repaints_inside_a_live_resize() {
        let Opened {
            mut driver,
            screen: opened,
            ..
        } = open_card(DECISION_PTY_ROWS as u16, DECISION_PTY_COLS as u16, &[]);
        // The 20-row card's body window is shorter than the body: the custom
        // row is one of the rows outside it, and those bytes never reached
        // the terminal.
        assert!(
            !opened.contains("6. custom answer"),
            "the 20-row card hides the custom row: {opened}"
        );

        must(driver.pty.resize(40, 120), "pty resize");
        // Only a frame painted in the taller geometry can carry the custom
        // row, so seeing it at 40x120 is the repaint itself.
        let flat = must(
            wait_for_squashed(&mut driver.pty, 40, 120, "6. custom answer", secs(10)),
            "pty screen",
        );
        assert!(
            flat.contains("1. Brief answer"),
            "the option body paints inside the new geometry: {flat}"
        );
        assert!(
            flat.contains("focus 1/6"),
            "the pinned footer paints inside the new geometry: {flat}"
        );
        assert_eq!(
            footer_hidden_count(&flat),
            Some(0),
            "the taller card hides no row: {flat}"
        );

        // Leave without answering, then quit — the same consent floor, and
        // the same geometry the card now owns.
        press(&mut driver.pty, b"\x1b");
        drop(screen(&driver.pty, 40, 120, "unanswered", secs(10)));
        press(&mut driver.pty, b"\x1b");
        expect_normal_exit(&mut driver, secs(10));
        teardown(driver);
    }

    #[test]
    fn pty_decision_card_custom_row_takes_multiline_paste_and_utf8() {
        let Opened {
            mut driver,
            question,
            ..
        } = open_card(24, 80, &[]);
        let task = question.task_id;
        for _ in 0..5 {
            press(&mut driver.pty, b"\x1b[B");
        }
        drop(screen(&driver.pty, 24, 80, "focus 6/6", secs(10)));

        // Enter opens editing; a second Enter adds a newline rather than
        // submitting; the bracketed paste lands atomically as one event.
        press(&mut driver.pty, b"\r");
        let visible = screen(&driver.pty, 24, 80, "(editing)", secs(10));
        assert!(visible.contains("(editing)"), "editing opens: {visible}");
        press(&mut driver.pty, b"hold the line");
        press(&mut driver.pty, b"\r");
        // The paste payload carries its own newline — bracketed paste is
        // one event, so the `\n` lands as draft text, never as Enter.
        press(
            &mut driver.pty,
            format!("\x1b[200~window\n{PASTED_WORD}\x1b[201~").as_bytes(),
        );

        // The pasted Cyrillic reached the card stream — the screen
        // reconstruction is ASCII-only, so the raw bytes are the evidence.
        assert!(
            seen(&mut driver.pty, PASTED_WORD.as_bytes(), secs(5)),
            "the pasted Cyrillic rendered"
        );

        // Width-2 graphemes take the same paste path: ratatui paints each
        // one cell-addressed with a two-column stride, so the graphemes are
        // never contiguous bytes — the evidence is the cursor advance.
        press(&mut driver.pty, "\x1b[200~ 窓は開く\x1b[201~".as_bytes());
        // `く` is the last grapheme the frame emits for this paste — waiting
        // on it closes the mid-flush window a `窓` wait would leave open,
        // where `は`/`開`/`く` can still be in flight at `collected()`.
        assert!(
            seen(&mut driver.pty, "く".as_bytes(), secs(5)),
            "the width-2 paste rendered"
        );
        let collected = stream(&driver.pty);
        // Last occurrence per grapheme — earlier repaints painted the draft
        // at other positions; the stride must come from one frame.
        let stride: Vec<usize> = ["窓", "は", "開", "く"]
            .iter()
            .filter_map(|grapheme| {
                collected
                    .windows(grapheme.len())
                    .rposition(|window| window == grapheme.as_bytes())
                    .and_then(|index| cursor_column_before(&collected, index))
            })
            .collect();
        assert_eq!(
            stride.len(),
            4,
            "every pasted grapheme painted at a cursor address"
        );
        assert!(
            stride.windows(2).all(|pair| pair[1] == pair[0] + 2),
            "each grapheme advances the cursor two cells: {stride:?}"
        );

        // Esc finishes editing with the draft intact — wait for the normal
        // footer hint to return before Enter: sent earlier, `\x1b`+`\r`
        // merge into one Alt+Enter event, and the card does not ignore it —
        // editing-mode Enter inserts a newline, so the draft would grow a
        // `\n` and never reach the commit arm.
        press(&mut driver.pty, b"\x1b");
        let visible = screen(&driver.pty, 24, 80, "arrows", secs(10));
        assert!(
            squashed(&visible).contains("arrows move"),
            "Esc leaves editing mode: {visible}"
        );
        press(&mut driver.pty, b"\r");
        let visible = screen(&driver.pty, 24, 80, "recorded", secs(10));
        assert!(
            squashed(&visible).contains("decision answer recorded"),
            "the custom answer commits: {visible}"
        );

        press(&mut driver.pty, b"\x1b");
        expect_exit(&mut driver, secs(10));
        let (outcome, store) = driver.exited();
        assert_eq!(outcome, json!({ "exit": 0 }));
        let Some((answer_json, origin)) = must(store.answered_question(&task), "answered") else {
            unreachable!("the custom answer is durable");
        };
        assert_eq!(origin, "human");
        assert!(
            answer_json.contains(&format!("hold the line\\nwindow\\n{PASTED_WORD}")),
            "the multiline draft is the custom answer: {answer_json}"
        );
        assert!(
            answer_json.contains(PASTED_WORD),
            "the Cyrillic paste survives to durable state: {answer_json}"
        );
        assert!(
            answer_json.contains("窓は開く"),
            "the width-2 paste survives to durable state: {answer_json}"
        );
        drop(store);
        teardown(driver);
    }

    /// The longest run of `─` box strokes in the raw stream — the card's
    /// bordered row is the only emitter, so the run measures its painted
    /// width one cell at a time.
    fn max_dash_run(bytes: &[u8]) -> usize {
        const DASH: &[u8] = "─".as_bytes();
        let mut best = 0usize;
        let mut run = 0usize;
        let mut index = 0usize;
        while index + DASH.len() <= bytes.len() {
            if bytes[index..index + DASH.len()] == *DASH {
                run += 1;
                index += DASH.len();
            } else {
                best = best.max(run);
                run = 0;
                index += 1;
            }
        }
        best.max(run)
    }

    /// The offset of the first SGR (`CSI … m`) sequence that is not a bare
    /// reset — the UI is monochrome, so resets are the only attribute
    /// escapes a NO_COLOR terminal should ever receive. Private-mode
    /// sequences (`?` params) are not SGR and never count.
    fn first_color_sgr(bytes: &[u8]) -> Option<usize> {
        let mut index = 0usize;
        while let Some(pos) = find_subsequence(&bytes[index..], b"\x1b[").map(|p| p + index) {
            let mut i = pos + 2;
            while i < bytes.len() && matches!(bytes[i], b'0'..=b'9' | b';' | b'?' | b' ') {
                i += 1;
            }
            if i < bytes.len() && bytes[i] == b'm' {
                let params = &bytes[pos + 2..i];
                // `ESC [ m` and `ESC [ 0 m` (and `0;0` chains) reset every
                // attribute — they set no color. Anything else would.
                let reset_only = params.is_empty()
                    || params
                        .split(|byte| *byte == b';')
                        .all(|code| !code.is_empty() && code.iter().all(|b| *b == b'0'));
                if params.first() != Some(&b'?') && !reset_only {
                    return Some(pos);
                }
            }
            index = pos + 2;
        }
        None
    }

    #[test]
    fn pty_decision_card_clamps_at_60_columns_on_a_wide_viewport() {
        // At 160 columns the card still paints its 60-column self: the
        // bordered row is 58 `─` strokes between the corners, and nothing
        // wider ever reaches the terminal.
        let Opened {
            mut driver,
            screen: opened_screen,
            ..
        } = open_card(50, 160, &[]);
        assert!(
            squashed(&opened_screen).contains("focus 1/6"),
            "the card is on screen: {opened_screen}"
        );
        assert_eq!(
            max_dash_run(&stream(&driver.pty)),
            58,
            "the border is 60 columns wide — 58 dashes between the corners"
        );
        // Esc leaves the card; the next Esc quits — spaced so each press is
        // its own read event.
        press(&mut driver.pty, b"\x1b");
        drop(screen(&driver.pty, 50, 160, "unanswered", secs(10)));
        press(&mut driver.pty, b"\x1b");
        expect_normal_exit(&mut driver, secs(10));
        teardown(driver);
    }

    #[test]
    fn pty_no_color_keeps_the_card_legible_and_emits_no_color() {
        // NO_COLOR is an env contract: the card must be fully legible
        // without a single SGR sequence — the UI paints text, never color.
        let Opened {
            mut driver,
            screen: opened_screen,
            ..
        } = open_card(24, 80, &[("NO_COLOR", "1")]);
        let flat = squashed(&opened_screen);
        assert!(
            flat.contains("awaiting decision") && flat.contains("focus 1/6"),
            "the card reads legible under NO_COLOR: {opened_screen}"
        );
        let bytes = stream(&driver.pty);
        assert_eq!(
            first_color_sgr(&bytes).map(|pos| {
                String::from_utf8_lossy(&bytes[pos..(pos + 16).min(bytes.len())]).into_owned()
            }),
            None,
            "no color SGR ever reaches the terminal"
        );
        // Esc leaves the card; the next Esc quits — spaced like the other
        // legs so each press is its own read event.
        press(&mut driver.pty, b"\x1b");
        drop(screen(&driver.pty, 24, 80, "unanswered", secs(10)));
        press(&mut driver.pty, b"\x1b");
        expect_normal_exit(&mut driver, secs(10));
        teardown(driver);
    }

    /// Marker the parent sets and `card_driver_child` reads to arm the
    /// release seam on its own thread: `retry` or `exit`.
    const RELEASE_FAULT_MARKER: &str = "RIVECT_CARD_RELEASE_FAULT";
    const RELEASE_W: &str = "database writer lock release failed: other error";
    const RELEASE_O: &str = "owner lock release failed: other error";
    const RETRY_FAILURE_ROW: &str = "tui runtime open failed: owner configuration failed";

    /// The screens one replayed PTY stream shows: the main screen at the
    /// moment the TUI took the alternate screen, and the final screen.
    struct Replay {
        entry: Vec<String>,
        settled: Vec<String>,
        settled_alternate: bool,
        /// Whether the settled screen still hides the cursor: a terminal
        /// restored after a crash shows it again.
        settled_cursor_hidden: bool,
    }

    fn screen_rows(parser: &vt100::Parser) -> Vec<String> {
        parser
            .screen()
            .contents()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    /// Replays `bytes` through the 120x40 terminal model (standards §12:
    /// screen state, never escape bytes). A row is one line of `contents()`,
    /// which reads only the active grid, so text written on the alternate
    /// screen or erased from the main screen is never a main-screen row.
    fn replay(bytes: &[u8]) -> Result<Replay, String> {
        replay_at(bytes, 40, 120)
    }

    /// `replay` on a terminal of `rows` x `cols`: the same model and the same
    /// rows, sized to the viewport a leg runs at, so a frame read at a
    /// geometry is what a terminal of that geometry really holds.
    fn replay_at(bytes: &[u8], rows: u16, cols: u16) -> Result<Replay, String> {
        let mut probe = vt100::Parser::new(rows, cols, 0);
        let entered = bytes
            .iter()
            .position(|byte| {
                probe.process(std::slice::from_ref(byte));
                probe.screen().alternate_screen()
            })
            .ok_or_else(|| "the stream never entered the alternate screen".to_owned())?;
        let mut before = vt100::Parser::new(rows, cols, 0);
        before.process(bytes.get(..entered).unwrap_or_default());
        let mut whole = vt100::Parser::new(rows, cols, 0);
        whole.process(bytes);
        Ok(Replay {
            entry: screen_rows(&before),
            settled: screen_rows(&whole),
            settled_alternate: whole.screen().alternate_screen(),
            settled_cursor_hidden: whole.screen().hide_cursor(),
        })
    }

    /// `(writer rows, owner rows, writer-then-owner pairs)` of one screen.
    fn release_rows(rows: &[String]) -> (usize, usize, usize) {
        let writer = rows.iter().filter(|row| row.as_str() == RELEASE_W).count();
        let owner = rows.iter().filter(|row| row.as_str() == RELEASE_O).count();
        let pairs = rows
            .windows(2)
            .filter(
                |pair| matches!(pair, [first, second] if first == RELEASE_W && second == RELEASE_O),
            )
            .count();
        (writer, owner, pairs)
    }

    /// A clean exit: nothing on the entry screen, exactly one release pair
    /// on the restored main screen.
    fn exit_verdict(bytes: &[u8]) -> Result<(), String> {
        let replay = replay(bytes)?;
        if replay.settled_alternate {
            return Err("the stream settled on the alternate screen".to_owned());
        }
        let entry = release_rows(&replay.entry);
        if entry != (0, 0, 0) {
            return Err(format!("the entry screen holds release rows {entry:?}"));
        }
        let settled = release_rows(&replay.settled);
        if settled != (1, 1, 1) {
            return Err(format!(
                "the settled screen holds {settled:?} (writer, owner, pair) rows, not one pair"
            ));
        }
        Ok(())
    }

    /// A failed lazy retry: the eager open's pair on the entry screen, and
    /// on the restored screen two pairs split by the child's printed error
    /// (the kept eager report above it, the printed report below it).
    fn retry_verdict(bytes: &[u8]) -> Result<(), String> {
        let replay = replay(bytes)?;
        if replay.settled_alternate {
            return Err("the stream settled on the alternate screen".to_owned());
        }
        let entry = release_rows(&replay.entry);
        if entry != (1, 1, 1) {
            return Err(format!("the entry screen holds {entry:?}, not one pair"));
        }
        let Some(split) = replay
            .settled
            .iter()
            .position(|row| row.starts_with(RETRY_FAILURE_ROW))
        else {
            return Err("the settled screen has no printed error row".to_owned());
        };
        let (above, rest) = replay.settled.split_at(split);
        let below = rest.split_first().map_or(rest, |(_, after)| after);
        for (label, rows) in [("above", above), ("below", below)] {
            let counted = release_rows(rows);
            if counted != (1, 1, 1) {
                return Err(format!(
                    "{label} the printed error: {counted:?}, not one pair"
                ));
            }
        }
        Ok(())
    }

    /// The oracle's own controls, run before the drivers.
    fn assert_release_oracle_controls() {
        let lines = format!("{RELEASE_W}\r\n{RELEASE_O}\r\n");
        let (enter, leave) = ("\x1b[?1049h", "\x1b[?1049l");
        let settled = format!("{enter}{leave}{lines}");
        assert_eq!(exit_verdict(settled.as_bytes()), Ok(()));
        let reentered = format!("{enter}{leave}{enter}{lines}");
        let reentered_screen = must(
            replay(reentered.as_bytes()),
            "the re-entered control replays",
        );
        assert!(
            reentered_screen.settled_alternate,
            "the re-entered control settles on the alternate screen"
        );
        assert!(
            exit_verdict(reentered.as_bytes()).is_err(),
            "a warning after re-entering the alternate screen is not on the restored screen"
        );
        let warned_inside = format!("{enter}{lines}{leave}");
        let warned_screen = must(
            replay(warned_inside.as_bytes()),
            "the warned control replays",
        );
        assert!(
            !warned_screen.settled_alternate,
            "the warned-inside control settles on the restored main screen"
        );
        assert_eq!(
            release_rows(&warned_screen.settled),
            (0, 0, 0),
            "the warning written on the alternate screen is gone after the leave"
        );
        assert!(
            exit_verdict(warned_inside.as_bytes()).is_err(),
            "a warning written on the alternate screen is gone after the leave"
        );
    }

    fn occurrences(bytes: &[u8], needle: &[u8]) -> usize {
        bytes
            .windows(needle.len())
            .filter(|window| *window == needle)
            .count()
    }

    fn outcome_of(driver: &CardDriver) -> Value {
        let text = must(
            std::fs::read_to_string(driver.ctl.join("outcome")),
            "outcome file",
        );
        must(serde_json::from_str(&text), "outcome decodes")
    }

    #[test]
    fn pty_poll_failure_degrades_to_a_named_error_and_restores() {
        // A poll failure must not strand the terminal: the question read
        // errors degrade the TUI to a named failure on stderr — after the
        // alternate screen and bracketed paste restore.
        let Opened { mut driver, .. } = open_card(24, 80, &[]);

        // Esc leaves the card so the next loop iteration polls
        // `current_question` again — then the store closes under the
        // runtime, turning that poll into a real backend error.
        press(&mut driver.pty, b"\x1b");
        drop(screen(&driver.pty, 24, 80, "unanswered", secs(10)));
        must(driver.command("close-store"), "the fault lands");

        assert_eq!(
            must(driver.pty.wait_exit(secs(10)), "pty wait"),
            Some(0),
            "the child reports the failure and exits"
        );
        let text = must(
            std::fs::read_to_string(driver.ctl.join("outcome")),
            "outcome file",
        );
        let outcome: Value = must(serde_json::from_str(&text), "outcome decodes");
        assert!(
            outcome["error"]
                .as_str()
                .is_some_and(|error| error.contains("tui question poll failed")),
            "the poll failure exits nonzero instead of spinning: {outcome}"
        );
        let bytes = stream(&driver.pty);
        assert!(
            find_subsequence(&bytes, b"\x1b[?1049l").is_some(),
            "the alternate screen restores on the error path"
        );
        assert!(
            find_subsequence(&bytes, b"\x1b[?2004l").is_some(),
            "bracketed paste restores on the error path"
        );
        assert!(
            find_subsequence(
                &bytes,
                b"tui question poll failed: task store is closed; reopen required"
            )
            .is_some(),
            "the failure is named on stderr: {}",
            String::from_utf8_lossy(&bytes[bytes.len().saturating_sub(2048)..])
        );
        teardown(driver);

        // Transport subcase: a read fault inside the ack wait comes back as
        // `Transport`, never dropped and never retried to a timeout.
        let faults = Arc::new(PtyFaults::default());
        let mut faulted = must(
            CardDriver::spawn_faulted(24, 80, &[], Arc::clone(&faults)),
            "faulted card spawn",
        );
        assert!(
            seen(&mut faulted.pty, b"\x1b[?1049h", secs(10)),
            "alternate screen must be entered on start"
        );
        press(&mut faulted.pty, b"transport probe\r");
        drop(screen(&faulted.pty, 24, 80, "Submitted task:", secs(10)));
        must(faulted.command("hold"), "the child holds its pass");
        faults.fail_next_read.store(true, Ordering::SeqCst);
        let held = faulted.command("report");
        let ack_absent = !faulted.ctl.join(format!("{}.ack", faulted.next)).exists();
        let armed = faults.fail_next_read.load(Ordering::SeqCst);
        let finished = faulted.finish();
        let parked = faults
            .parked_child
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(mut child) = parked
            && !matches!(child.try_wait(), Ok(Some(_)))
        {
            drop(child.kill());
            drop(child.wait());
        }
        assert!(
            matches!(&held, Err(CardDriverError::Transport(PtyIoError::Read { source }))
                if source.to_string() == "injected pty read fault"),
            "{held:?}"
        );
        assert!(
            ack_absent,
            "the held command had no ack when command returned"
        );
        assert!(!armed, "the ack wait's pump took the armed fault");
        assert!(
            finished.is_ok(),
            "the taken fault is not reported again: {finished:?}"
        );

        // Release subcases: the lock release failures reach the operator
        // exactly once, on the restored screen.
        assert_release_oracle_controls();

        // `retry`: the eager open and the lazy retry both fail and release.
        let mut retry = must(
            CardDriver::spawn(40, 120, &[(RELEASE_FAULT_MARKER, "retry")]),
            "retry card spawn",
        );
        assert!(
            seen(&mut retry.pty, b"\x1b[?1049h", secs(10)),
            "alternate screen must be entered on start"
        );
        drop(screen(&retry.pty, 40, 120, "session open failed", secs(10)));
        press(&mut retry.pty, b"x\r");
        expect_exit(&mut retry, secs(10));
        let outcome = outcome_of(&retry);
        let Some(error) = outcome["error"].as_str() else {
            unreachable!("the failed retry reports its error: {outcome}");
        };
        assert!(
            error.starts_with(RETRY_FAILURE_ROW),
            "the primary failure leads: {error}"
        );
        assert!(
            error.ends_with(&format!("\n{RELEASE_W}\n{RELEASE_O}")),
            "both release lines end the report: {error}"
        );
        assert_eq!(error.matches(RELEASE_W).count(), 1, "{error}");
        assert_eq!(error.matches(RELEASE_O).count(), 1, "{error}");
        must(
            retry_verdict(&stream(&retry.pty)),
            "the retry release rows on the restored screen",
        );
        teardown(retry);

        // `exit`: a clean exit reports both lines after the restore.
        let mut exit = must(
            CardDriver::spawn(40, 120, &[(RELEASE_FAULT_MARKER, "exit")]),
            "exit card spawn",
        );
        assert!(
            seen(&mut exit.pty, b"\x1b[?1049h", secs(10)),
            "alternate screen must be entered on start"
        );
        drop(screen(
            &exit.pty,
            40,
            120,
            "No project or index is selected",
            secs(10),
        ));
        press(&mut exit.pty, b"\x1b");
        expect_exit(&mut exit, secs(10));
        assert_eq!(outcome_of(&exit), json!({ "exit": 0 }));
        let bytes = stream(&exit.pty);
        must(
            exit_verdict(&bytes),
            "the exit release rows on the restored screen",
        );
        for line in [RELEASE_W, RELEASE_O] {
            assert_eq!(
                occurrences(&bytes, line.as_bytes()),
                1,
                "the raw stream holds {line} once"
            );
        }
        teardown(exit);
    }

    /// `tasks.md` and the design brief declare the terminal restored on exit,
    /// panic and cancel: the legs above cover exit and cancel, and the panic
    /// path had none. A panic runs both halves of the guard — the hook it
    /// installs and its `Drop` — while the card owns the alternate screen, and
    /// the terminal has to come back on the main screen with the cursor shown
    /// instead of stranding the operator on the alternate one.
    #[test]
    fn pty_card_panic_leaves_the_main_screen_and_the_cursor_restored() {
        // No consent key is ever sent: the card only has to be open.
        let Opened { mut driver, .. } = open_card_unwaited(24, 80, &[]);
        let card = must(replay(&stream(&driver.pty)), "the card stream replays");
        assert!(
            card.settled_alternate,
            "the card owns the alternate screen when the child dies"
        );
        assert!(
            card.settled_cursor_hidden,
            "the card's frames keep the cursor hidden"
        );

        must(driver.enqueue(PANIC_REQUEST), "the panic request lands");
        let status = must(driver.pty.wait_exit(secs(10)), "pty wait");
        assert!(
            status.is_some_and(|code| !child_exited_cleanly(Some(code))),
            "the panicking child ends the run itself: {status:?}"
        );
        // A panicking child never reaches its own outcome write, so this is
        // the panic path rather than the loop's exit path.
        assert!(
            !driver.ctl.join("outcome").exists(),
            "the run ended on the panic path"
        );

        let bytes = stream(&driver.pty);
        let restored = must(replay(&bytes), "the panic stream replays");
        let settled = restored.settled.join("\n");
        assert!(
            !restored.settled_alternate,
            "the panic leaves the alternate screen: {settled}"
        );
        assert!(
            !restored.settled_cursor_hidden,
            "the restored terminal shows the cursor again: {settled}"
        );
        // The crash report is only readable on the main grid if the leave
        // came before it: everything painted on the alternate screen dies
        // with it.
        assert!(
            settled.contains(PANIC_REPORT),
            "the panic reached the restored screen: {settled}"
        );
        teardown(driver);
    }

    #[test]
    fn pty_decision_card_never_commits_input_queued_before_its_first_paint() {
        let mut driver = must(
            CardDriver::spawn(DECISION_PTY_ROWS as u16, DECISION_PTY_COLS as u16, &[]),
            "card spawn",
        );
        assert!(
            seen(&mut driver.pty, b"\x1b[?1049h", secs(30)),
            "alternate screen must be entered on start"
        );
        // Patience only: the property is ordering (pre-paint input never commits), not the latency bound; a loaded suite may delay the paint.
        press(&mut driver.pty, b"pick a rollout lane\r");
        let visible = screen(
            &driver.pty,
            DECISION_PTY_ROWS,
            DECISION_PTY_COLS,
            "Submitted task:",
            secs(30),
        );
        assert!(
            visible.contains("Submitted task:"),
            "the task receipt renders: {visible}"
        );

        // The child holds its pass until the four keys are queued, so every
        // one of them is in the terminal queue before the card can paint:
        // two Enters and a Down-arrow+Enter pair in one write. Input
        // produced before the first painted frame must never reach the
        // card — a leaked arrow would move the focus of a card the operator
        // had not seen, a blind Enter would commit an unseen question.
        must(driver.command("hold"), "the child holds its pass");
        press(&mut driver.pty, b"\r\r\x1b[B\r");
        let question = driver.publish(1);

        let screen_text = screen(
            &driver.pty,
            DECISION_PTY_ROWS,
            DECISION_PTY_COLS,
            "focus 1/6",
            secs(30),
        );
        assert!(
            screen_text.contains("focus 1/6"),
            "the card paints over the blind input: {screen_text}"
        );
        let report = driver.report();
        assert!(
            report.current.is_some(),
            "a blind Enter never answered the unseen question"
        );
        assert!(report.attempts.is_empty(), "a blind Enter journals nothing");
        // The settled frame proves the arrow died too: a leaked Down would
        // have repainted the footer to `focus 2/6` inside a loop pass, and
        // several passes in the focus never moved.
        let settled = screen(
            &driver.pty,
            DECISION_PTY_ROWS,
            DECISION_PTY_COLS,
            "focus 2/6",
            DECISION_CONSENT_DELAY * 2,
        );
        assert!(
            !settled.contains("focus 2/6") && settled.contains("focus 1/6"),
            "the pre-paint arrow never moved focus: {settled}"
        );

        // Esc leaves the card; the next Esc quits. Esc is consent — it
        // waits out the floor like the aimed Enter would.
        pause(&mut driver.pty, DECISION_CONSENT_DELAY);
        press(&mut driver.pty, b"\x1b");
        drop(screen(
            &driver.pty,
            DECISION_PTY_ROWS,
            DECISION_PTY_COLS,
            "unanswered",
            secs(30),
        ));
        press(&mut driver.pty, b"\x1b");
        expect_exit(&mut driver, secs(30));
        let (outcome, store) = driver.exited();
        assert_eq!(outcome, json!({ "exit": 0 }));
        assert!(
            must(store.current_question(&question.task_id), "current").is_some(),
            "the question is still pending after Esc"
        );
        drop(store);
        teardown(driver);
    }

    #[test]
    fn pty_decision_card_refuses_consent_inside_the_visibility_floor() {
        // `open_card_unwaited`: both consent keys must land inside the
        // floor — they go out in the same breath as the first-paint proof,
        // before any wait lets the window elapse.
        let Opened { mut driver, .. } =
            open_card_unwaited(DECISION_PTY_ROWS as u16, DECISION_PTY_COLS as u16, &[]);

        // Bytes can still land inside the consent floor after the first
        // frame — autorepeat on a held Enter, data in flight over SSH —
        // and Enter plus Esc are exactly the keys such a burst settles or
        // dismisses with. Neither can have been aimed at the question, so
        // the floor refuses both. The absent-needle waits are the
        // discriminating proof: a commit or a dismissal would paint within
        // the wait, so a screen that never shows either is a real refusal,
        // not a race won.
        press(&mut driver.pty, b"\r");
        press(&mut driver.pty, b"\x1b");
        let visible = screen(
            &driver.pty,
            DECISION_PTY_ROWS,
            DECISION_PTY_COLS,
            "decision answer recorded",
            DECISION_CONSENT_DELAY * 2,
        );
        assert!(
            !visible.contains("decision answer recorded") && visible.contains("focus 1/6"),
            "an unaimed Enter never commits: {visible}"
        );
        let report = driver.report();
        assert!(
            report.current.is_some(),
            "an unaimed Enter never answers the question"
        );
        assert!(
            report.attempts.is_empty(),
            "a refused consent journals nothing"
        );
        let visible = screen(
            &driver.pty,
            DECISION_PTY_ROWS,
            DECISION_PTY_COLS,
            "unanswered",
            DECISION_CONSENT_DELAY * 2,
        );
        assert!(
            !visible.contains("unanswered") && visible.contains("focus 1/6"),
            "an unaimed Esc never dismisses the card: {visible}"
        );

        // The two refusal waits already outlasted the floor, so this Enter
        // is aimed at a question the operator has seen — consent again.
        press(&mut driver.pty, b"\r");
        let visible = screen(
            &driver.pty,
            DECISION_PTY_ROWS,
            DECISION_PTY_COLS,
            "decision answer recorded",
            secs(10),
        );
        assert!(
            visible.contains("decision answer recorded"),
            "the post-floor Enter commits: {visible}"
        );
        let report = driver.report();
        assert_eq!(report.attempts.len(), 1);
        assert_eq!(report.attempts[0].outcome, "applied");
        assert_eq!(report.attempts[0].author, "human");

        press(&mut driver.pty, b"\x1b");
        expect_normal_exit(&mut driver, secs(10));
        teardown(driver);
    }

    #[test]
    fn pty_decision_card_closes_when_its_question_moves() {
        let Opened {
            mut driver,
            question,
            ..
        } = open_card(24, 80, &[]);
        let task = question.task_id;

        // Steer supersedes the pinned question inside its own transaction:
        // the card's (id, revision) stops being the task's current
        // question while the modal is still open.
        let steered = must(driver.command("steer"), "the steer lands");
        let Some(intent_revision) = steered["intent_revision"].as_u64() else {
            unreachable!("the steer result carries the new intent revision: {steered}");
        };

        // The superseding fork opens its own card: the replacement
        // question's id on screen proves the stale card closed for real —
        // the view carries one card, so a painted second card means the
        // first one let go.
        let replacement = driver.publish(intent_revision);
        let reopened = screen(
            &driver.pty,
            24,
            80,
            replacement.question_id.0.as_str(),
            secs(10),
        );
        assert!(
            reopened.contains(replacement.question_id.0.as_str()),
            "the replacement fork opens a fresh card over the moved one: {reopened}"
        );

        // Answered over the wire while its card is open, the fork moves
        // again — the second card closes the same honest way instead of
        // keeping live controls that could only journal a denial.
        must(driver.command("answer"), "the wire answer lands");
        // With no card covering it, the transcript shows the close note
        // twice — once per moved fork.
        let deadline = Instant::now() + secs(10);
        let mut visible = String::new();
        while Instant::now() < deadline {
            visible = reconstruct_screen(&stream(&driver.pty), 24, 80);
            if visible.matches(DECISION_MOVED_NOTE).count() >= 2 {
                break;
            }
            pause(&mut driver.pty, Duration::from_millis(25));
        }
        assert!(
            visible.matches(DECISION_MOVED_NOTE).count() >= 2,
            "each moved fork closes its card with the move named: {visible}"
        );

        // With no live card, Esc is the TUI's own quit — proof no stale
        // modal lingered to eat it or journal a denied consent.
        press(&mut driver.pty, b"\x1b");
        expect_exit(&mut driver, secs(10));
        let (outcome, store) = driver.exited();
        assert_eq!(outcome, json!({ "exit": 0 }));
        assert!(
            must(store.current_question(&task), "current").is_none(),
            "the wire answer settled the last pending fork"
        );
        let attempts = must(store.answer_attempts(&task), "attempts");
        assert_eq!(
            attempts.len(),
            1,
            "only the wire answer journals — a stale card never wrote a denied attempt: {attempts:?}"
        );
        assert_eq!(attempts[0].outcome, AnswerAttemptOutcome::Applied);
        drop(store);
        teardown(driver);
    }

    #[test]
    fn pty_dismissed_card_stays_down_and_a_different_fork_reopens_it() {
        let Opened {
            mut driver,
            question: dismissed,
            screen: opened_screen,
        } = open_card(24, 80, &[]);
        assert!(
            opened_screen.contains(dismissed.question_id.0.as_str()),
            "the open card pins its question id: {opened_screen}"
        );

        // Esc after the floor returns the question unanswered. While THAT
        // question stays the task's current fork the poll must never
        // resurrect its card — the dismissal is the operator's choice, not
        // a transient close.
        press(&mut driver.pty, b"\x1b");
        let visible = screen(&driver.pty, 24, 80, "decision left unanswered", secs(10));
        assert!(
            visible.contains("decision left unanswered"),
            "Esc returns without answering: {visible}"
        );
        // Three poll intervals with the same question still pending: a poll
        // that ignored the dismissal would repaint the card inside one.
        let settled = screen(&driver.pty, 24, 80, "focus 1/6", Duration::from_millis(750));
        assert!(
            !settled.contains("focus 1/6") && !settled.contains(dismissed.question_id.0.as_str()),
            "the dismissed question's card never resurrected: {settled}"
        );

        // A different pending fork is a different question: the store
        // resolves the dismissed fork (the task runs again), then a fresh
        // fixture publishes on the same live intent. The dismissed marker
        // belongs to the old question id — it must not suppress the new
        // card, and a never-reopen arm would leave the screen cardless.
        must(
            driver.command("resolve"),
            "the answer settles the dismissed fork",
        );
        let replacement = driver.publish(dismissed.intent_revision);
        let reopened = screen(
            &driver.pty,
            24,
            80,
            replacement.question_id.0.as_str(),
            secs(10),
        );
        let flat = squashed(&reopened);
        assert!(
            flat.contains(replacement.question_id.0.as_str())
                && flat.contains("focus 1/6")
                && !flat.contains(dismissed.question_id.0.as_str()),
            "a different pending question reopens the card fresh: {reopened}"
        );

        // The reopened card carries its own consent floor; Esc after it
        // leaves the card, and the next Esc quits the TUI.
        pause(&mut driver.pty, DECISION_CONSENT_DELAY);
        press(&mut driver.pty, b"\x1b");
        drop(screen(&driver.pty, 24, 80, "unanswered", secs(10)));
        press(&mut driver.pty, b"\x1b");
        expect_normal_exit(&mut driver, secs(10));
        teardown(driver);
    }

    // ----- the dock as a projection of `runtime.status` -----

    /// Spawns the TUI, submits one task through the composer, and returns
    /// the driver with the task id its dock row names.
    fn submitted(goal: &str) -> (CardDriver, String) {
        let mut driver = must(
            CardDriver::spawn(DOCK_PTY_ROWS as u16, DOCK_PTY_COLS as u16, &[]),
            "card spawn",
        );
        assert!(
            seen(&mut driver.pty, b"\x1b[?1049h", secs(10)),
            "alternate screen must be entered on start"
        );
        press(&mut driver.pty, format!("{goal}\r").as_bytes());
        let visible = screen(
            &driver.pty,
            DOCK_PTY_ROWS,
            DOCK_PTY_COLS,
            "Submitted task:",
            secs(10),
        );
        assert!(
            visible.contains("Submitted task:"),
            "the task receipt renders: {visible}"
        );
        let task_id = dock_task_id(&visible);
        (driver, task_id)
    }

    /// The reconstructed frame once the dock row for `task_id` names
    /// `lifecycle`, whitespace-normalized.
    fn dock_row(driver: &mut CardDriver, task_id: &str, lifecycle: &str) -> String {
        let needle = format!("task {task_id}: {lifecycle}");
        let visible = screen(&driver.pty, DOCK_PTY_ROWS, DOCK_PTY_COLS, &needle, secs(10));
        squashed(&visible)
    }

    /// The dock rows a `runtime.status` result projects, spelled from the
    /// API's own fields rather than through the production renderer: the
    /// screen and the projection have to agree on their own.
    fn projected_rows(status: &Value) -> Vec<String> {
        let Some(items) = status["todo"]["items"].as_array() else {
            unreachable!("runtime.status carries its todo page: {status}");
        };
        items
            .iter()
            .map(
                |item| match (item["task_id"].as_str(), item["lifecycle"].as_str()) {
                    (Some(task_id), Some(lifecycle)) => format!("task {task_id}: {lifecycle}"),
                    _ => unreachable!("a todo item names its task and lifecycle: {item}"),
                },
            )
            .collect()
    }

    /// The frame the terminal has settled on, whitespace-normalized: a
    /// panel that is still painted reads here, one that was overwritten
    /// does not.
    fn settled_frame(driver: &CardDriver) -> String {
        must(
            card_text(&driver.pty, DOCK_PTY_ROWS as u16, DOCK_PTY_COLS as u16),
            "pty screen",
        )
    }

    /// The captured frame at `rows` x `cols` once it paints `needle`, one
    /// string per row: the terminal model's settled screen, so what a leg
    /// reads is the frame painted now rather than text an earlier frame left
    /// in the stream. Rows keep a message's own boundaries, which is what
    /// lets a leg prove a line fits the row it was written for.
    fn frame_rows(
        pty: &mut PtySession,
        rows: u16,
        cols: u16,
        needle: &str,
        timeout: Duration,
    ) -> Vec<String> {
        let deadline = Instant::now() + timeout;
        loop {
            let captured = must(
                replay_at(&must(pty.collected(), "pty read"), rows, cols),
                "pty screen",
            )
            .settled;
            if captured.iter().any(|row| row.contains(needle)) || Instant::now() >= deadline {
                return captured;
            }
            must(pty.pump_for(Duration::from_millis(25)), "pty pump");
        }
    }

    #[test]
    fn live_dock_follows_the_task_ac004_p1() {
        let (mut driver, task_id) = submitted("hold the rollout");
        let running = dock_row(&mut driver, &task_id, "running");
        assert!(
            running.contains(&format!("task {task_id}: running")),
            "the submit leaves its own lifecycle on the row: {running}"
        );

        // The owner's no-ready transition, driven through the store: the
        // composer is not asked again, so only a projection can repaint.
        must(driver.command("block"), "the owner blocks the task");
        let followed = dock_row(&mut driver, &task_id, "blocked");
        assert!(
            followed.contains(&format!("task {task_id}: blocked")),
            "the same row names the later lifecycle: {followed}"
        );
        assert_eq!(
            followed.matches("Submitted task:").count(),
            1,
            "the row moved because the store did, not because a second submit ran: {followed}"
        );
        assert_eq!(
            followed.matches(&format!("task {task_id}:")).count(),
            1,
            "one row per task: {followed}"
        );

        press(&mut driver.pty, b"\x1b");
        expect_normal_exit(&mut driver, secs(10));
        teardown(driver);
    }

    #[test]
    fn live_dock_follows_the_task_ac004_p2() {
        let (mut driver, task_id) = submitted("hold the rollout");
        dock_row(&mut driver, &task_id, "running");
        must(driver.command("block"), "the owner blocks the task");

        // The store's own no-ready blocker is the reason the frame carries; a
        // row without it would tell the operator only that something paused.
        let blocked = dock_row(&mut driver, &task_id, "blocked (dependency_blocked)");
        assert!(
            blocked.contains(&format!("task {task_id}: blocked (dependency_blocked)")),
            "the blocked frame carries its reason: {blocked}"
        );

        press(&mut driver.pty, b"\x1b");
        expect_normal_exit(&mut driver, secs(10));
        teardown(driver);
    }

    #[test]
    fn failed_dock_refresh_keeps_the_previous_rows_p3() {
        let (mut driver, task_id) = submitted("hold the rollout");
        dock_row(&mut driver, &task_id, "running");

        // (i) the refresh is what paints a transition.
        must(driver.command("block"), "the owner blocks the task");
        let followed = dock_row(&mut driver, &task_id, "blocked");
        assert!(
            followed.contains(&format!("task {task_id}: blocked")),
            "the refresh paints the transition: {followed}"
        );

        // (ii) one failed read is silent: the rows survive it and the dock is
        // not marked for a single miss.
        must(driver.command("fail-status 1"), "one status read fails");
        pause(&mut driver.pty, DOCK_REFRESH_INTERVAL * 2);
        let once = settled_frame(&driver);
        assert!(
            !once.contains("dock refresh failed"),
            "one failed read leaves the dock unmarked: {once}"
        );
        assert!(
            once.contains(&format!("task {task_id}: blocked")),
            "the rows a failed refresh cannot re-read stay painted: {once}"
        );

        // (iii) two consecutive failures mark the dock, and the mark holds
        // for the rest of the run: the armed failures outlast the beats the
        // frame is read across, so what is asserted here is the frame several
        // failures into the run, not the one beat the mark was first written
        // on — a dead refresh cannot pass for a healthy idle dock.
        must(driver.command("fail-status 24"), "the status seam arms");
        drop(frame_rows(
            &mut driver.pty,
            DOCK_PTY_ROWS as u16,
            DOCK_PTY_COLS as u16,
            "dock refresh failed:",
            secs(10),
        ));
        pause(&mut driver.pty, DOCK_REFRESH_INTERVAL * 2);
        let marked = settled_frame(&driver);
        assert!(
            marked.contains("dock refresh failed:"),
            "the second consecutive failure marks the dock, and the run keeps it marked: {marked}"
        );
        assert!(
            marked.contains(&format!("task {task_id}: blocked")),
            "the rows a dead refresh cannot re-read stay painted: {marked}"
        );

        press(&mut driver.pty, b"\x1b");
        expect_normal_exit(&mut driver, secs(10));
        teardown(driver);
    }

    #[test]
    fn live_dock_follows_the_task_ac005_p1() {
        let mut driver = must(
            CardDriver::spawn(DOCK_PTY_ROWS as u16, DOCK_PTY_COLS as u16, &[]),
            "card spawn",
        );
        assert!(
            seen(&mut driver.pty, b"\x1b[?1049h", secs(10)),
            "alternate screen must be entered on start"
        );
        let empty = screen(
            &driver.pty,
            DOCK_PTY_ROWS,
            DOCK_PTY_COLS,
            super::DOCK_EMPTY,
            secs(10),
        );
        assert!(
            squashed(&empty).contains(super::DOCK_EMPTY),
            "a fresh view starts on the empty dock: {empty}"
        );

        // The durable commit reaches the child's own session through the
        // runtime, never through this view's composer: nothing has cached a
        // dock row for it.
        let seeded = must(driver.command("seed"), "the durable task commits");
        let rows = projected_rows(&seeded);
        assert_eq!(rows.len(), 1, "one task is projected: {seeded}");
        let row = rows[0].clone();
        let painted = screen(&driver.pty, DOCK_PTY_ROWS, DOCK_PTY_COLS, &row, secs(10));
        assert!(
            painted.contains(&row),
            "the projection paints the recovered row: {painted}"
        );
        assert!(
            !painted.contains(super::DOCK_EMPTY),
            "the empty dock is replaced by what the API projects: {painted}"
        );

        // The resume path re-delivers the same stream with its duplicates and
        // in reverse order; the dock and the API must agree afterwards.
        let task_id = dock_task_id(&row);
        let recovered = must(
            driver.command(&format!("recover {task_id}")),
            "the owner replays its durable stream",
        );
        assert_eq!(
            projected_rows(&recovered),
            rows,
            "recovery returns one consistent projection: {recovered}"
        );
        pause(&mut driver.pty, DOCK_REFRESH_INTERVAL * 2);
        let settled = settled_frame(&driver);
        assert!(
            settled.contains(&row),
            "the recovered row survives the timer passes: {settled}"
        );
        assert_eq!(
            settled.matches(&row).count(),
            1,
            "the replayed stream duplicates no row: {settled}"
        );

        press(&mut driver.pty, b"\x1b");
        expect_normal_exit(&mut driver, secs(10));
        teardown(driver);
    }

    #[test]
    fn live_dock_follows_the_task_ac063_p1() {
        let (mut driver, task_id) = submitted("hold the rollout");
        dock_row(&mut driver, &task_id, "running");
        must(driver.command("complete"), "the owner completes the task");
        let completed = dock_row(&mut driver, &task_id, "completed");
        assert!(
            completed.contains(&format!("task {task_id}: completed")),
            "the completed lifecycle lands on the row: {completed}"
        );

        // The dock is a projection, so the timer passes after the completion
        // repaint the same row instead of dropping it.
        pause(&mut driver.pty, DOCK_REFRESH_INTERVAL * 3);
        let after = settled_frame(&driver);
        assert!(
            after.contains(&format!("task {task_id}: completed")),
            "the completed row stays painted after the UI timer: {after}"
        );

        press(&mut driver.pty, b"\x1b");
        expect_normal_exit(&mut driver, secs(10));
        teardown(driver);
    }

    #[test]
    fn live_dock_follows_the_task_ac064_p1() {
        let (mut driver, task_id) = submitted("hold the rollout");
        dock_row(&mut driver, &task_id, "running");
        must(driver.command("cancel"), "the owner cancels the task");

        let cancelled = dock_row(&mut driver, &task_id, "cancelled");
        assert!(
            cancelled.contains(&format!("task {task_id}: cancelled")),
            "a cancelled task renders as itself: {cancelled}"
        );
        assert!(
            !cancelled.contains(&format!("task {task_id}: completed")),
            "cancelled is never read as done: {cancelled}"
        );

        press(&mut driver.pty, b"\x1b");
        expect_normal_exit(&mut driver, secs(10));
        teardown(driver);
    }

    // ----- the near-full warning and the continuation it names -----

    /// The fragment every near-full warning carries: the condition and the
    /// key that silences it, so a leg can find the row and a cleared frame
    /// can be shown to lack it.
    const WARNING_NEEDLE: &str = "% full (auto-compact off)";

    /// What the fill left behind: the task its durable records belong to,
    /// the bytes its assembled context serves and the digest of those
    /// bytes.
    struct Filled {
        task_id: String,
        bytes: u64,
        digest: String,
    }

    fn filled_from(reply: &Value) -> Filled {
        let (Some(task_id), Some(bytes), Some(digest)) = (
            reply["task_id"].as_str(),
            reply["bytes"].as_u64(),
            reply["digest"].as_str(),
        ) else {
            unreachable!("the measurement names its task, bytes and digest: {reply}");
        };
        Filled {
            task_id: task_id.to_string(),
            bytes,
            digest: digest.to_string(),
        }
    }

    /// Fills one task's episodic history from inside the child: the runtime
    /// minted the session the records belong to, so a task the parent seeded
    /// would be invisible to it and a second runtime on its root would be a
    /// second writer.
    fn fill_history(driver: &mut CardDriver) -> Filled {
        let reply = must(
            driver.command("fill-context"),
            "the child fills the context",
        );
        filled_from(&reply)
    }

    /// The bytes and digest the child's own store serves for `task_id`.
    fn measured_context(driver: &mut CardDriver, task_id: &str) -> (u64, String) {
        let reply = must(
            driver.command(&format!("context-bytes {task_id}")),
            "the child measures its context",
        );
        let filled = filled_from(&reply);
        (filled.bytes, filled.digest)
    }

    /// The share of the model wire ceiling one assembled context fills, in
    /// whole percent — the measure the near-full threshold is stated in, so a
    /// leg can show which of two open conversations a line had to be about.
    fn wire_percent(bytes: u64) -> u64 {
        let ceiling = u64::try_from(crate::contracts::MODEL_WIRE_MAX_BYTES).unwrap_or(u64::MAX);
        bytes.saturating_mul(100) / ceiling
    }

    /// The painted near-full warning row, once it renders. The row is
    /// painted at the end of the transcript block, so the operator reads the
    /// condition and the command that answers it together.
    fn warning_row(driver: &mut CardDriver) -> String {
        let visible = screen(
            &driver.pty,
            DOCK_PTY_ROWS,
            DOCK_PTY_COLS,
            WARNING_NEEDLE,
            secs(10),
        );
        match visible.lines().find(|line| line.contains(WARNING_NEEDLE)) {
            Some(row) => row.to_string(),
            None => unreachable!("the warning is painted: {visible}"),
        }
    }

    #[test]
    fn auto_compact_off_warns_when_the_window_is_nearly_full_p1() {
        let mut driver = must(
            CardDriver::spawn(DOCK_PTY_ROWS as u16, DOCK_PTY_COLS as u16, &[]),
            "card spawn",
        );
        assert!(
            seen(&mut driver.pty, b"\x1b[?1049h", secs(10)),
            "alternate screen must be entered on start"
        );
        // A context this small earns nothing: the line speaks only once the
        // assembled bytes have crossed the threshold.
        pause(&mut driver.pty, DOCK_REFRESH_INTERVAL * 2);
        let quiet = settled_frame(&driver);
        assert!(
            !quiet.contains(WARNING_NEEDLE),
            "a small context paints no warning: {quiet}"
        );

        // The fill runs inside the child, so the records belong to the
        // session its own store answers for.
        fill_history(&mut driver);
        let painted = warning_row(&mut driver);
        assert!(
            painted.contains(WARNING_NEEDLE),
            "a nearly full context with auto-compaction off warns: {painted}"
        );

        // The key is what silences it in this build: the same full context
        // earns no line once `[context] auto_compact = true`.
        must(
            driver.command("auto-compact on"),
            "the child switches the key on",
        );
        pause(&mut driver.pty, DOCK_REFRESH_INTERVAL * 2);
        let silenced = settled_frame(&driver);
        assert!(
            !silenced.contains(WARNING_NEEDLE),
            "auto-compact on silences the warning: {silenced}"
        );
        must(
            driver.command("auto-compact off"),
            "the child switches the key off",
        );
        let returned = warning_row(&mut driver);
        assert!(
            returned.contains(WARNING_NEEDLE),
            "the line follows the key it is gated on: {returned}"
        );

        press(&mut driver.pty, b"\x1b");
        expect_normal_exit(&mut driver, secs(10));
        teardown(driver);
    }

    #[test]
    fn auto_compact_off_warns_when_the_window_is_nearly_full_p2() {
        let mut driver = must(
            CardDriver::spawn(DOCK_PTY_ROWS as u16, DOCK_PTY_COLS as u16, &[]),
            "card spawn",
        );
        assert!(
            seen(&mut driver.pty, b"\x1b[?1049h", secs(10)),
            "alternate screen must be entered on start"
        );
        fill_history(&mut driver);
        let row = warning_row(&mut driver);
        // The continuation is offered on the row itself, so the printed
        // spelling and the accepted input are one token.
        let token = match row.split_whitespace().find(|word| word.starts_with('/')) {
            Some(token) => token.to_string(),
            None => unreachable!("the warning names the continuation it offers: {row}"),
        };

        // Typed back exactly as printed: an accepted fold answers in the
        // transcript, which a token the composer does not serve could not do.
        press(&mut driver.pty, format!("{token}\r").as_bytes());
        let accepted = screen(
            &driver.pty,
            DOCK_PTY_ROWS,
            DOCK_PTY_COLS,
            CONTEXT_COMPACTED,
            secs(10),
        );
        let flat = squashed(&accepted);
        assert!(
            flat.contains(CONTEXT_COMPACTED),
            "the token the warning printed reaches the command: {flat}"
        );

        press(&mut driver.pty, b"\x1b");
        expect_normal_exit(&mut driver, secs(10));
        teardown(driver);
    }

    #[test]
    fn auto_compact_off_warns_when_the_window_is_nearly_full_p3() {
        let mut driver = must(
            CardDriver::spawn(DOCK_PTY_ROWS as u16, DOCK_PTY_COLS as u16, &[]),
            "card spawn",
        );
        assert!(
            seen(&mut driver.pty, b"\x1b[?1049h", secs(10)),
            "alternate screen must be entered on start"
        );
        let filled = fill_history(&mut driver);
        let painted = warning_row(&mut driver);
        assert!(
            painted.contains(WARNING_NEEDLE),
            "the warning is painted while the legs below measure: {painted}"
        );

        // The paint re-measures the context every beat and rewrites nothing:
        // the bytes the store serves after the line has painted (and after
        // further beats) are the very bytes the fill left.
        pause(&mut driver.pty, DOCK_REFRESH_INTERVAL * 2);
        let (bytes, digest) = measured_context(&mut driver, &filled.task_id);
        assert_eq!(
            digest, filled.digest,
            "the served context is the same bytes, not only the same length"
        );
        assert_eq!(
            bytes, filled.bytes,
            "the warning paints over the context without trimming it"
        );
        let still = settled_frame(&driver);
        assert!(
            still.contains(WARNING_NEEDLE),
            "the measured context is still the nearly full one: {still}"
        );

        press(&mut driver.pty, b"\x1b");
        expect_normal_exit(&mut driver, secs(10));
        teardown(driver);
    }

    /// The width the two-task legs paint at: the warning names the task its
    /// fold acts on by id, so the line runs past the 80-column acceptance
    /// geometry the legs above assert at.
    const WIDE_PTY_COLS: usize = 120;

    /// The painted copies of the help text: one per transcript row group, so
    /// the count is the transcript band the panel actually shows.
    fn help_rows(frame: &str) -> usize {
        frame.matches("Commands:").count()
    }

    /// Fills the transcript past the panel and proves it: the band of help
    /// text stops growing while more rows are still being added, so the
    /// rows — and anything chained after them — are painted off screen.
    fn overflowing_transcript(driver: &mut CardDriver) {
        press(&mut driver.pty, &b"/help\r".repeat(7));
        pause(&mut driver.pty, DOCK_REFRESH_INTERVAL * 4);
        let band = help_rows(&settled_frame(driver));
        assert!(
            band >= 4,
            "the transcript fills the panel before the fill: {band} row groups"
        );
        press(&mut driver.pty, &b"/help\r".repeat(6));
        pause(&mut driver.pty, DOCK_REFRESH_INTERVAL * 4);
        assert_eq!(
            help_rows(&settled_frame(driver)),
            band,
            "the transcript has outgrown the panel: the rows below it are off screen"
        );
    }

    #[test]
    fn auto_compact_off_warns_when_the_window_is_nearly_full_p9() {
        let mut driver = must(
            CardDriver::spawn(DOCK_PTY_ROWS as u16, DOCK_PTY_COLS as u16, &[]),
            "card spawn",
        );
        assert!(
            seen(&mut driver.pty, b"\x1b[?1049h", secs(10)),
            "alternate screen must be entered on start"
        );

        // The shape AC-072 targets is a session already long enough to fill
        // the panel: a line painted after the transcript is below it.
        overflowing_transcript(&mut driver);
        fill_history(&mut driver);
        let painted = warning_row(&mut driver);
        assert!(
            painted.contains(WARNING_NEEDLE),
            "the warning paints on its own row, not below the transcript: {painted}"
        );
        let overfull = help_rows(&settled_frame(&driver));

        // The dock's own fault mark holds the band's other row: with the
        // warning silenced it is what the band shows, and the overfull
        // transcript that used to clip it is unchanged.
        must(
            driver.command("auto-compact on"),
            "the child switches the key on",
        );
        pause(&mut driver.pty, DOCK_REFRESH_INTERVAL * 2);
        let silenced = settled_frame(&driver);
        assert!(
            !silenced.contains(WARNING_NEEDLE),
            "auto-compact on silences the line: {silenced}"
        );
        must(driver.command("fail-status 24"), "the status reads fail");
        drop(frame_rows(
            &mut driver.pty,
            DOCK_PTY_ROWS as u16,
            DOCK_PTY_COLS as u16,
            "dock refresh failed:",
            secs(10),
        ));
        pause(&mut driver.pty, DOCK_REFRESH_INTERVAL * 2);
        let marked = settled_frame(&driver);
        assert!(
            marked.contains("dock refresh failed:"),
            "the dock-stale mark paints where the transcript cannot clip it: {marked}"
        );
        assert_eq!(
            help_rows(&marked),
            overfull,
            "the mark paints on the same overfull session: {marked}"
        );

        press(&mut driver.pty, b"\x1b");
        expect_normal_exit(&mut driver, secs(10));
        teardown(driver);

        // Both messages at the 60-column acceptance geometry the card legs
        // paint at: a near-full conversation and a dead refresh hold at once,
        // each on its own row, and the warning's row is whole — its last word
        // included, so the continuation it names reads instead of clipping.
        let mut narrow = must(
            CardDriver::spawn(DECISION_PTY_ROWS as u16, DECISION_PTY_COLS as u16, &[]),
            "card spawn",
        );
        assert!(
            seen(&mut narrow.pty, b"\x1b[?1049h", secs(10)),
            "alternate screen must be entered on start"
        );
        fill_history(&mut narrow);
        let warned = frame_rows(
            &mut narrow.pty,
            DECISION_PTY_ROWS as u16,
            DECISION_PTY_COLS as u16,
            WARNING_NEEDLE,
            secs(10),
        );
        assert!(
            warned
                .iter()
                .any(|row| row.trim_end().ends_with(COMPACT_TOKEN)),
            "the warning fits its row at 60 columns, last word included: {warned:?}"
        );
        // The failures outlast the beats the frame is read across, so this is
        // one frame with the warning live: the armed run keeps the mark
        // painted under it instead of trading one message for the other.
        must(narrow.command("fail-status 24"), "the status reads fail");
        drop(frame_rows(
            &mut narrow.pty,
            DECISION_PTY_ROWS as u16,
            DECISION_PTY_COLS as u16,
            "dock refresh failed:",
            secs(10),
        ));
        pause(&mut narrow.pty, DOCK_REFRESH_INTERVAL * 2);
        let both = frame_rows(
            &mut narrow.pty,
            DECISION_PTY_ROWS as u16,
            DECISION_PTY_COLS as u16,
            "dock refresh failed:",
            secs(2),
        );
        let warning_at = both
            .iter()
            .position(|row| row.contains(WARNING_NEEDLE))
            .unwrap_or_else(|| unreachable!("the warning is painted: {both:?}"));
        let mark_at = both
            .iter()
            .position(|row| row.contains("dock refresh failed:"))
            .unwrap_or_else(|| unreachable!("the mark is painted: {both:?}"));
        assert!(
            both[warning_at].trim_end().ends_with(COMPACT_TOKEN),
            "the warning stays whole on its row while the mark is live: {both:?}"
        );
        assert_ne!(
            warning_at, mark_at,
            "the mark keeps its own row while the warning is live: {both:?}"
        );
        press(&mut narrow.pty, b"\x1b");
        expect_normal_exit(&mut narrow, secs(10));
        teardown(narrow);
    }

    #[test]
    fn auto_compact_off_warns_when_the_window_is_nearly_full_p10() {
        let mut driver = must(
            CardDriver::spawn(DOCK_PTY_ROWS as u16, WIDE_PTY_COLS as u16, &[]),
            "card spawn",
        );
        assert!(
            seen(&mut driver.pty, b"\x1b[?1049h", secs(10)),
            "alternate screen must be entered on start"
        );

        // The older conversation: nearly full and settled, the row a
        // first-of-the-page subject would warn about.
        let older = filled_from(&must(
            driver.command("fill-context"),
            "the older conversation fills",
        ));
        must(
            driver.command(&format!("complete {}", older.task_id)),
            "the older conversation settles",
        );
        // The conversation the operator is reading: newer and still small.
        let newer = filled_from(&must(
            driver.command("new-context"),
            "the newer conversation opens",
        ));
        pause(&mut driver.pty, DOCK_REFRESH_INTERVAL * 2);
        let quiet = must(
            card_text(&driver.pty, DOCK_PTY_ROWS as u16, WIDE_PTY_COLS as u16),
            "pty screen",
        );
        assert!(
            !quiet.contains(WARNING_NEEDLE),
            "a settled older conversation earns no line: {quiet}"
        );

        // Once the conversation being read fills, the line names it.
        let filled_newer = filled_from(&must(
            driver.command(&format!("fill-context {}", newer.task_id)),
            "the newer conversation fills",
        ));
        let wide = screen(
            &driver.pty,
            DOCK_PTY_ROWS,
            WIDE_PTY_COLS,
            WARNING_NEEDLE,
            secs(10),
        );
        let row = wide
            .lines()
            .find(|line| line.contains(WARNING_NEEDLE))
            .unwrap_or_else(|| unreachable!("the warning is painted: {wide}"));
        assert!(
            row.contains(&format!("task {}", newer.task_id)),
            "the line names the conversation the fold acts on: {row}"
        );
        assert!(
            !row.contains(&older.task_id),
            "and never the settled conversation behind it: {row}"
        );

        // `/compact` folds that conversation and leaves the other one as it
        // was.
        let (older_before, _) = measured_context(&mut driver, &older.task_id);
        press(&mut driver.pty, b"/compact\r");
        let accepted = screen(
            &driver.pty,
            DOCK_PTY_ROWS,
            WIDE_PTY_COLS,
            CONTEXT_COMPACTED,
            secs(10),
        );
        assert!(
            squashed(&accepted).contains(CONTEXT_COMPACTED),
            "the accepted fold answers in the transcript: {accepted}"
        );
        let (newer_after, _) = measured_context(&mut driver, &newer.task_id);
        let (older_after, _) = measured_context(&mut driver, &older.task_id);
        assert!(
            newer_after < filled_newer.bytes,
            "the fold shortened the conversation the line named: {} → {newer_after}",
            filled_newer.bytes
        );
        assert_eq!(
            older_after, older_before,
            "the settled conversation is untouched"
        );

        // The conversation the operator is reading is now the composer's own:
        // a submit is the one place the loop's pending task is set, and only
        // the pending arm can name it. The conversation behind it — the status
        // page's last row, opened and filled by the child — is one this view
        // never submitted and still nearly full, so a projection that measured
        // the last row would warn about that one instead.
        press(&mut driver.pty, b"ledger\r");
        let receipt = screen(
            &driver.pty,
            DOCK_PTY_ROWS,
            DOCK_PTY_COLS,
            "Submitted task: ledger",
            secs(10),
        );
        let Some(reading) = receipt
            .lines()
            .find_map(|line| line.split_once("(accepted: "))
            .map(|(_, tail)| {
                tail.chars()
                    .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '-')
                    .collect::<String>()
            })
            .filter(|task_id| !task_id.is_empty())
        else {
            unreachable!("the receipt names the submitted task: {receipt}");
        };
        // A composer submit carries no criteria, and an obligation is what a
        // record lands on, so this conversation is the one open task that
        // cannot be filled: what it has room for is the point here.
        let near_full = u64::try_from(super::CONTEXT_NEARLY_FULL_PERCENT).unwrap_or(u64::MAX);
        let reading_bytes = measured_context(&mut driver, &reading).0;
        assert!(
            wire_percent(reading_bytes) < near_full,
            "the conversation being read still has room: {reading_bytes} bytes"
        );
        let last_row = filled_from(&must(
            driver.command("new-context"),
            "the newer conversation opens",
        ));
        let filled_last_row = filled_from(&must(
            driver.command(&format!("fill-context {}", last_row.task_id)),
            "the newer conversation fills",
        ));
        assert!(
            wire_percent(filled_last_row.bytes) >= near_full,
            "the last row on its own would earn the line: {} bytes",
            filled_last_row.bytes
        );
        pause(
            &mut driver.pty,
            CONTEXT_MEASURE_INTERVAL + DOCK_REFRESH_INTERVAL * 2,
        );
        let quiet = settled_frame(&driver);
        assert!(
            !quiet.contains(WARNING_NEEDLE),
            "the line measures the conversation being read, never the last row: {quiet}"
        );

        // The continuation follows the same subject: with no line painted
        // `/compact` falls back to the pending conversation, whose empty
        // history the owner refuses to fold — the nearly full conversation
        // behind it keeps the bytes the fill left.
        press(&mut driver.pty, b"/compact\r");
        let refused = screen(
            &driver.pty,
            DOCK_PTY_ROWS,
            DOCK_PTY_COLS,
            "compaction would not shorten",
            secs(10),
        );
        assert!(
            squashed(&refused).contains("compaction would not shorten the history"),
            "the fold addresses the conversation being read: {refused}"
        );
        let (last_row_after, last_row_digest) = measured_context(&mut driver, &last_row.task_id);
        assert_eq!(
            last_row_after, filled_last_row.bytes,
            "the conversation the line never named is untouched"
        );
        assert_eq!(
            last_row_digest, filled_last_row.digest,
            "and its bytes are the ones the fill left"
        );

        press(&mut driver.pty, b"\x1b");
        expect_normal_exit(&mut driver, secs(10));
        teardown(driver);
    }

    #[test]
    fn refused_compaction_continuation_is_a_painted_line_p4() {
        let (mut driver, _task_id) = submitted("hold the rollout");
        // A task with no episodic history yet: the checkpoint line the fold
        // would leave is longer than the history it replaces, so the owner
        // refuses it as not shorter.
        press(&mut driver.pty, b"/compact\r");
        let visible = screen(
            &driver.pty,
            DOCK_PTY_ROWS,
            DOCK_PTY_COLS,
            "compaction would not shorten",
            secs(10),
        );
        let flat = squashed(&visible);
        assert!(
            flat.contains("compaction would not shorten the history"),
            "the refusal paints the owner's typed message: {flat}"
        );

        // A refusal is a line, not an exit: the loop still takes passes and
        // the next command is served.
        must(driver.command("ping"), "the loop keeps serving passes");
        press(&mut driver.pty, b"/help\r");
        let help = screen(
            &driver.pty,
            DOCK_PTY_ROWS,
            DOCK_PTY_COLS,
            "Commands: Enter submits a task",
            secs(10),
        );
        assert!(
            squashed(&help).contains("Commands: Enter submits a task"),
            "the loop keeps serving input after the refusal: {help}"
        );

        press(&mut driver.pty, b"\x1b");
        expect_normal_exit(&mut driver, secs(10));
        teardown(driver);
    }

    #[test]
    fn compacting_an_empty_session_paints_a_plain_note() {
        let mut driver = must(
            CardDriver::spawn(DOCK_PTY_ROWS as u16, DOCK_PTY_COLS as u16, &[]),
            "card spawn",
        );
        assert!(
            seen(&mut driver.pty, b"\x1b[?1049h", secs(10)),
            "alternate screen must be entered on start"
        );

        // No warning and no submitted task: there is no conversation to
        // fold, so nothing is dispatched and the operator reads a plain
        // line instead of the wire's own field name.
        press(&mut driver.pty, b"/compact\r");
        let visible = screen(
            &driver.pty,
            DOCK_PTY_ROWS,
            DOCK_PTY_COLS,
            NOTHING_TO_COMPACT,
            secs(10),
        );
        let flat = squashed(&visible);
        assert!(
            flat.contains(NOTHING_TO_COMPACT),
            "an empty session earns a plain note: {flat}"
        );
        assert!(
            !flat.contains("task_id"),
            "no wire field name reaches the operator: {flat}"
        );

        press(&mut driver.pty, b"\x1b");
        expect_normal_exit(&mut driver, secs(10));
        teardown(driver);
    }

    #[test]
    fn warning_clears_after_an_accepted_compaction_p8() {
        let mut driver = must(
            CardDriver::spawn(DOCK_PTY_ROWS as u16, DOCK_PTY_COLS as u16, &[]),
            "card spawn",
        );
        assert!(
            seen(&mut driver.pty, b"\x1b[?1049h", secs(10)),
            "alternate screen must be entered on start"
        );
        let filled = fill_history(&mut driver);
        let painted = warning_row(&mut driver);
        assert!(
            painted.contains(WARNING_NEEDLE),
            "the warning paints before the fold: {painted}"
        );

        press(&mut driver.pty, b"/compact\r");
        let accepted = screen(
            &driver.pty,
            DOCK_PTY_ROWS,
            DOCK_PTY_COLS,
            CONTEXT_COMPACTED,
            secs(10),
        );
        assert!(
            squashed(&accepted).contains(CONTEXT_COMPACTED),
            "the accepted fold answers in the transcript: {accepted}"
        );

        // The line tracks the condition it names: a fold leaves the task's
        // revision where it was, so the projection's cached measurement is
        // what holds the old line until the measurement backstop re-reads it.
        pause(
            &mut driver.pty,
            CONTEXT_MEASURE_INTERVAL + DOCK_REFRESH_INTERVAL * 2,
        );
        let settled = settled_frame(&driver);
        assert!(
            !settled.contains(WARNING_NEEDLE),
            "the warning does not outlive the condition it names: {settled}"
        );
        assert!(
            settled.contains(&format!("task {}:", filled.task_id)),
            "the task the fold kept stays on the dock: {settled}"
        );

        press(&mut driver.pty, b"\x1b");
        expect_normal_exit(&mut driver, secs(10));
        teardown(driver);
    }
}
