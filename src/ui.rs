//! Minimal TUI (design brief D-005): fullscreen alternate screen by default,
//! mouse capture off, terminal restored on exit, cancel and panic. Also owns
//! the client-side event projection rules.

use crate::contracts::Event;
use crossterm::cursor::Show;
use crossterm::event::{Event as TermEvent, KeyCode, KeyEvent, KeyModifiers, poll, read};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::Constraint;
use ratatui::widgets::Paragraph;
use std::io::{self, Stdout};
use std::sync::Arc;
use std::time::Duration;

/// Terminal lifecycle guard. Mouse capture is deliberately never enabled
/// (D-005 default off so copy-on-select and tmux copy-mode keep working).
pub struct TerminalGuard {
    terminal: Terminal<CrosstermBackend<Stdout>>,
    previous_hook: Arc<dyn Fn(&std::panic::PanicHookInfo<'_>) + Sync + Send>,
}

impl TerminalGuard {
    pub fn enter() -> io::Result<Self> {
        enable_raw_mode()?;
        execute!(io::stdout(), EnterAlternateScreen)?;
        let terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
        let original: Arc<dyn Fn(&std::panic::PanicHookInfo<'_>) + Sync + Send> =
            Arc::new(std::panic::take_hook());
        let chained = original.clone();
        // The hook cannot borrow the terminal, so it restores the shared tty
        // state directly; the guard's own restore stays idempotent.
        std::panic::set_hook(Box::new(move |info| {
            let mut out = io::stdout();
            let _ = execute!(out, LeaveAlternateScreen, Show);
            let _ = disable_raw_mode();
            chained(info);
        }));
        Ok(Self {
            terminal,
            previous_hook: original,
        })
    }

    pub fn terminal_mut(&mut self) -> &mut Terminal<CrosstermBackend<Stdout>> {
        &mut self.terminal
    }

    pub fn restore(mut self) -> io::Result<()> {
        let _ = self.terminal.clear();
        execute!(io::stdout(), LeaveAlternateScreen, Show)?;
        disable_raw_mode()?;
        let original = std::mem::replace(&mut self.previous_hook, Arc::new(|_| {}));
        std::panic::set_hook(Box::new(move |info| original(info)));
        Ok(())
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct LocalView {
    pub status: String,
    pub dock: Vec<String>,
    pub transcript: Vec<String>,
    pub composer: String,
}

/// «Начало, без подключения»: ввод и help доступны, логина нет.
pub fn initial_view() -> LocalView {
    LocalView {
        status: "Rivect · нет подключения · /help — справка".to_string(),
        dock: vec!["Задач нет. Login — отдельное явное действие.".to_string()],
        transcript: vec![
            "Ввод доступен. Укажите задачу или уточнение.".to_string(),
            "Проект и индекс не выбраны; обычный ответ не блокируется.".to_string(),
        ],
        composer: String::new(),
    }
}

pub fn render(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    view: &LocalView,
) -> io::Result<()> {
    terminal.draw(|frame| {
        let area = frame.area();
        let chunks = ratatui::layout::Layout::vertical([
            Constraint::Length(1),
            Constraint::Min(1),
            Constraint::Length(view.dock.len().clamp(1, 3) as u16),
            Constraint::Length(1),
        ])
        .split(area);
        frame.render_widget(Paragraph::new(view.status.clone()), chunks[0]);
        frame.render_widget(Paragraph::new(view.transcript.join("\n")), chunks[1]);
        frame.render_widget(Paragraph::new(view.dock.join("\n")), chunks[2]);
        frame.render_widget(Paragraph::new(format!("> {}", view.composer)), chunks[3]);
    })?;
    Ok(())
}

/// Runs the minimal fullscreen loop. `q`/Esc quits normally (exit 0),
/// Ctrl-C cancels (exit 130). The guard guarantees terminal restoration on
/// both paths and on panic.
pub fn run_tui() -> io::Result<i32> {
    let mut guard = TerminalGuard::enter()?;
    let mut view = initial_view();
    let mut exit = 0;
    loop {
        render(guard.terminal_mut(), &view)?;
        if poll(Duration::from_millis(250))?
            && let TermEvent::Key(KeyEvent {
                code, modifiers, ..
            }) = read()?
        {
            match (code, modifiers) {
                (KeyCode::Char('q'), _) | (KeyCode::Esc, _) => break,
                (KeyCode::Char('c'), m) if m.contains(KeyModifiers::CONTROL) => {
                    exit = 130;
                    break;
                }
                (KeyCode::Char(ch), _) => {
                    view.composer.push(ch);
                }
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
}

impl Projection {
    pub fn new(last_revision: u64) -> Self {
        Self { last_revision }
    }

    pub fn apply(&mut self, event: &Event) -> ApplyVerdict {
        if event.aggregate_revision <= self.last_revision {
            return ApplyVerdict::Duplicate;
        }
        if event.aggregate_revision != self.last_revision + 1 {
            return ApplyVerdict::Resync;
        }
        self.last_revision = event.aggregate_revision;
        ApplyVerdict::Applied
    }
}
