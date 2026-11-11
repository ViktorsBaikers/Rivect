//! AC-001 (TD-03): the exact packaged artifact from the release slice runs the
//! inherited 19 design-brief states across the four acceptance geometries plus
//! a live resize and the fourteen input modes. Each cell is exercised with a
//! pass/fail verdict — except the three theme inputs, whose distinct palettes
//! are declared NOT_RUN and whose cells carry that claim as their reason. The
//! state's own rendered observables at that geometry must appear, and the
//! input mode must reach the same artifact. Terminal
//! restore is checked after exit, cancel and panic; inline keeps the
//! transcript in the terminal's own scrollback with mouse capture off; and
//! focusing or inspecting a decision card or permission panel records no
//! answer, no preapproval and no provider call. Screenshot or file presence
//! is never used as interaction proof.
//!
//! The packaged artifact cannot be made to panic through any public input:
//! the panic leg therefore runs the same production `TerminalGuard` in this
//! test binary's ignored child and is reported as `test-child`, never as a
//! packaged PASS.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::let_underscore_must_use,
    let_underscore_drop,
    clippy::redundant_clone,
    reason = "installed PTY matrix: assertions fail loudly with the observed screen or verdict; src/ stays strict (standards §14)"
)]

mod support;

use crossterm::event::{Event as TermEvent, KeyCode, KeyEvent, KeyModifiers};
use rivect::contracts::{EffectClass, Question, TaskId};
use rivect::policy::{ModeDecision, preapproval_scope};
use rivect::resources::{OutputSettlement, OutputStream};
use rivect::ui::{
    DecisionPanel, LocalView, PermissionPanel, RenderMode, TerminalGuard, initial_view, task_dock,
};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

const STATES: usize = 19;
const GEOMETRIES: usize = 5;
const INPUTS: usize = 14;
const CELLS: usize = STATES * GEOMETRIES * INPUTS;

const WAIT: Duration = Duration::from_secs(10);

/// Env gate for the cursor-query trace: the harness prints when it sees
/// `ESC [ 6 n`, when it answers, and what the child reported on timeout.
/// Diagnostic only — unset, the trace is silent and no behaviour changes.
const CURSOR_TRACE_ENV: &str = "RIVECT_PTY_CURSOR_TRACE";

fn trace_enabled() -> bool {
    std::env::var_os(CURSOR_TRACE_ENV).is_some()
}

/// Microseconds since the harness's first traced call, so query, answer and
/// timeout orderings are readable in one run.
fn trace_at() -> Duration {
    static START: std::sync::LazyLock<Instant> = std::sync::LazyLock::new(Instant::now);
    START.elapsed()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Geometry {
    W60H20,
    W80H24,
    W120H40,
    W160H50,
    LiveResize,
}

impl Geometry {
    const ALL: [Self; GEOMETRIES] = [
        Self::W60H20,
        Self::W80H24,
        Self::W120H40,
        Self::W160H50,
        Self::LiveResize,
    ];

    fn size(self) -> (u16, u16) {
        match self {
            Self::W60H20 => (60, 20),
            Self::W80H24 | Self::LiveResize => (80, 24),
            Self::W120H40 => (120, 40),
            Self::W160H50 => (160, 50),
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::W60H20 => "60x20",
            Self::W80H24 => "80x24",
            Self::W120H40 => "120x40",
            Self::W160H50 => "160x50",
            Self::LiveResize => "live-resize",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum InputMode {
    Keyboard,
    Vim,
    Unicode,
    Paste,
    NoColor,
    Light,
    Dark,
    HighContrast,
    ReducedMotion,
    Plain,
    Fullscreen,
    Inline,
    Mouse,
    Tmux,
}

impl InputMode {
    const ALL: [Self; INPUTS] = [
        Self::Keyboard,
        Self::Vim,
        Self::Unicode,
        Self::Paste,
        Self::NoColor,
        Self::Light,
        Self::Dark,
        Self::HighContrast,
        Self::ReducedMotion,
        Self::Plain,
        Self::Fullscreen,
        Self::Inline,
        Self::Mouse,
        Self::Tmux,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::Keyboard => "keyboard-only",
            Self::Vim => "vim",
            Self::Unicode => "unicode",
            Self::Paste => "paste",
            Self::NoColor => "no-color",
            Self::Light => "light",
            Self::Dark => "dark",
            Self::HighContrast => "high-contrast",
            Self::ReducedMotion => "reduced-motion",
            Self::Plain => "plain",
            Self::Fullscreen => "fullscreen",
            Self::Inline => "inline",
            Self::Mouse => "mouse",
            Self::Tmux => "tmux",
        }
    }
}

struct StateFixture {
    name: &'static str,
    needles: Vec<&'static str>,
}

impl StateFixture {
    fn new(name: &'static str, view: LocalView, needles: &[&'static str]) -> Self {
        let reviewed = rivect::ui::review::ReviewState::view(name)
            .unwrap_or_else(|| panic!("review entry carries no state {name}"));
        assert_eq!(
            view.status, reviewed.status,
            "the PTY fixture and the packaged review view share a status: {name}"
        );
        assert_eq!(view.dock, reviewed.dock, "{name}: dock");
        assert_eq!(view.transcript, reviewed.transcript, "{name}: transcript");
        assert_eq!(view.composer, reviewed.composer, "{name}: composer");
        assert_eq!(
            view.decision.is_some(),
            reviewed.decision.is_some(),
            "{name}: decision presence"
        );
        assert_eq!(
            view.panel.is_some(),
            reviewed.panel.is_some(),
            "{name}: panel presence"
        );
        Self {
            name,
            needles: needles.to_vec(),
        }
    }
}

fn status_with_tasks(tasks: &[(&str, &str, Option<&str>)], economy: Value) -> Value {
    let items: Vec<Value> = tasks
        .iter()
        .map(|(task, lifecycle, reason)| {
            json!({
                "task_id": task,
                "lifecycle": lifecycle,
                "blockers": reason.map_or_else(Vec::new, |reason| vec![json!({"reason": reason})]),
            })
        })
        .collect();
    json!({ "todo": { "items": items }, "economy": economy })
}

fn state_fixture(state: usize) -> StateFixture {
    match state {
        // The two start states are the same production frame: the runtime
        // projects no project or index fact, so the seeded views and their
        // status/dock/transcript are identical. They stay distinct cells
        // because the design brief names both states, not because the
        // packaged artifact paints them differently.
        0 => StateFixture::new(
            "start-no-connection",
            initial_view(),
            &[
                "Rivect · not connected",
                "No tasks. Login is a separate explicit action.",
                "Input is available",
            ],
        ),
        1 => StateFixture::new(
            "no-project-index",
            initial_view(),
            &["No project or index is selected"],
        ),
        2 => {
            let mut view = initial_view();
            view.composer = "draft a change".to_string();
            StateFixture::new(
                "ready-for-input",
                view,
                &["> draft a change", "Input is available"],
            )
        }
        3 => {
            let mut view = initial_view();
            let mut output = OutputStream::new();
            output.push_chunk(b"streaming marker line\n");
            for _ in 0..120 {
                output.push_chunk(b"long tool output line\n");
            }
            view.replace_output(output);
            StateFixture::new(
                "streaming-long-output",
                view,
                &[
                    "output · streaming",
                    "streaming marker line",
                    "PgUp/PgDn scroll",
                ],
            )
        }
        4 => {
            let mut view = initial_view();
            view.dock = task_dock(&status_with_tasks(
                &[
                    ("task-1", "running", None),
                    ("task-2", "waiting", None),
                    ("task-3", "blocked", Some("plan gate")),
                    ("task-4", "completed", None),
                ],
                Value::Null,
            ));
            StateFixture::new(
                "parallel-work",
                view,
                &[
                    "task task-1: running",
                    "task task-2: waiting",
                    "+2 more",
                    "task task-4: completed",
                ],
            )
        }
        5 => {
            let mut view = initial_view();
            view.decision = Some(DecisionPanel::new(Question::fixture(
                &TaskId("task-1".to_string()),
                1,
            )));
            StateFixture::new(
                "awaiting-decision",
                view,
                &["awaiting decision", "focus 1/6", "recommended:"],
            )
        }
        6 => {
            let mut view = initial_view();
            let scope = format!(
                "{}/workflow-scope/deep/nested/directory-tree/permission-grant-boundary-with-a-deliberately-long-tail-suffix",
                "/tmp/installed-tui"
            );
            view.panel = Some(PermissionPanel::new(
                ModeDecision::Ask,
                EffectClass::Write,
                "grant-installed-tui",
                "task-170-fixture",
                "2036-01-01T00:00:00Z",
                scope,
            ));
            StateFixture::new(
                "awaiting-permission",
                view,
                &[
                    "awaiting permission",
                    "decision: ask",
                    "effect: write",
                    "[deny]",
                    "arrows move, PgUp/PgDn scroll, Enter confirms, Esc denies",
                ],
            )
        }
        7 => {
            let mut view = initial_view();
            view.transcript = vec![
                "tui: switched to inline".to_string(),
                "tui: switched to fullscreen".to_string(),
            ];
            view.composer = "draft survives".to_string();
            StateFixture::new(
                "fullscreen-inline",
                view,
                &[
                    "tui: switched to inline",
                    "tui: switched to fullscreen",
                    "> draft survives",
                ],
            )
        }
        8 => {
            let mut view = initial_view();
            view.dock = task_dock(&status_with_tasks(
                &[
                    ("task-1", "cancelled", Some("operator stop")),
                    ("task-2", "blocked", Some("unknown external effect")),
                ],
                Value::Null,
            ));
            StateFixture::new(
                "pause-cancel",
                view,
                &[
                    "task task-1: cancelled (operator stop)",
                    "task task-2: blocked (unknown external effect)",
                ],
            )
        }
        9 => {
            let mut view = initial_view();
            view.dock = task_dock(&status_with_tasks(
                &[(
                    "task-1",
                    "paused",
                    Some("quota exhausted; fallback unknown"),
                )],
                json!({
                    "project": "/tmp/installed-tui",
                    "cwd": "/tmp/installed-tui",
                    "settled_tokens": 10,
                    "settled_source": "exact",
                    "charged_units": 1,
                    "cost_source": "estimated",
                    "agents": 0,
                    "agents_source": "stale",
                    "reset_at": "2026-11-10T00:00:00Z",
                    "reset_source": "exact",
                    "quota_remaining": null,
                    "quota_source": "unknown: no quota endpoint reports remaining units",
                    "context_tokens": 5,
                    "context_source": "exact",
                    "cache_source": "stale",
                    "model": "fixture-model",
                    "source": "recorded",
                    "effort": "high",
                    "effort_source": "recorded",
                    "purpose": "main",
                    "connection": "primary",
                }),
            ));
            StateFixture::new(
                "quota-fallback",
                view,
                &["quota unknown", "fallback unknown", "estimated", "stale"],
            )
        }
        10 => {
            let mut view = initial_view();
            let mut output = OutputStream::new();
            output.push_chunk(b"partial body\n");
            output.settle(OutputSettlement::Partial {
                cause: "connection lost".to_string(),
            });
            view.replace_output(output);
            view.dock_stale = Some("dock refresh failed: offline".to_string());
            StateFixture::new(
                "error-offline-partial",
                view,
                &[
                    "output · partial: connection lost",
                    "dock refresh failed: offline",
                ],
            )
        }
        11 => {
            // Completion has no transcript line in production: it shows as
            // the dock lifecycle row the projection builds, so the seeded
            // frame carries that row and nothing it invented.
            let mut view = initial_view();
            view.dock = task_dock(&status_with_tasks(
                &[("task-1", "completed", None)],
                Value::Null,
            ));
            StateFixture::new("success", view, &["task task-1: completed"])
        }
        12 => {
            let mut view = initial_view();
            view.transcript = vec![
                "Settings:".to_string(),
                "model = auto (default)".to_string(),
                "effort = high (modified)".to_string(),
                "workflow.enabled = false (locked)".to_string(),
                "profile = next (pending)".to_string(),
            ];
            StateFixture::new(
                "settings-default-modified-locked-pending",
                view,
                &[
                    "model = auto (default)",
                    "effort = high (modified)",
                    "workflow.enabled = false (locked)",
                    "profile = next (pending)",
                ],
            )
        }
        13 => {
            let mut view = initial_view();
            view.transcript = vec![
                "config.set refused: conflict at models.defaults.model; the other writer's draft is kept"
                    .to_string(),
                "config.validate: invalid_input at context.auto_compact".to_string(),
            ];
            StateFixture::new(
                "settings-invalid-conflict",
                view,
                &[
                    "conflict at models.defaults.model",
                    "invalid_input at context.auto_compact",
                ],
            )
        }
        14 => {
            let mut view = initial_view();
            view.transcript = vec![
                "Resumed session: session-1".to_string(),
                "Context compacted: 4096 → 1024 bytes, 3 records folded".to_string(),
                "upgrade: active generation 1; pending generation 2".to_string(),
            ];
            view.dock = task_dock(&status_with_tasks(
                &[("task-1", "completed", None)],
                Value::Null,
            ));
            StateFixture::new(
                "resume-compaction-upgrade",
                view,
                &[
                    "Resumed session",
                    "Context compacted",
                    "upgrade: active generation 1",
                ],
            )
        }
        15 => {
            let mut view = initial_view();
            view.transcript = vec![
                "Rewind preview: task task-1, 4096 assembled bytes".to_string(),
                "no rollback applied; apply is a separate action".to_string(),
                "Checkpoint: cp-1 folded 3 records".to_string(),
                "checkpoint.apply refused: conflict: stale intent".to_string(),
            ];
            StateFixture::new(
                "rewind-preview-conflict-partial",
                view,
                &[
                    "Rewind preview",
                    "no rollback applied",
                    "checkpoint.apply refused: conflict",
                ],
            )
        }
        16 => {
            let mut view = initial_view();
            view.dock = task_dock(&status_with_tasks(
                &[
                    ("task-1", "running", None),
                    ("task-2", "waiting", None),
                    ("task-3", "blocked", Some("plan gate")),
                    ("task-4", "running", None),
                    ("task-5", "waiting", None),
                    ("task-6", "blocked", Some("plan gate")),
                    ("task-7", "running", None),
                    ("task-8", "completed", None),
                ],
                Value::Null,
            ));
            StateFixture::new(
                "big-list-narrow-window",
                view,
                &["+6 more", "task task-8: completed", "> "],
            )
        }
        17 => {
            let mut view = initial_view();
            view.transcript = vec!["workflow: off; custom task state".to_string()];
            view.dock = task_dock(&status_with_tasks(
                &[("task-1", "custom", Some("workflow off"))],
                Value::Null,
            ));
            StateFixture::new(
                "workflow-off",
                view,
                &["workflow: off", "task task-1: custom (workflow off)"],
            )
        }
        18 => {
            let mut view = initial_view();
            view.transcript =
                vec!["non-tty: structured events on stdout; diagnostics on stderr".to_string()];
            StateFixture::new("non-tty", view, &["non-tty: structured events on stdout"])
        }
        _ => panic!("state index out of range: {state}"),
    }
}

fn render_state(fixture: &StateFixture, geometry: Geometry) -> Result<(), String> {
    let mut tui = TuiPty::spawn_review(geometry, fixture.name, &[])?;
    for needle in &fixture.needles {
        tui.wait(needle, WAIT)?;
    }
    if geometry == Geometry::LiveResize {
        tui.resize(40, 120)?;
        tui.wait(fixture.needles[0], WAIT)?;
        tui.resize(20, 60)?;
        tui.wait(fixture.needles[0], WAIT)?;
    }
    tui.send(b"\x1b")?;
    let (bytes, code, data_root_opened) = tui.finish_review()?;
    if code != Some(0) {
        return Err(format!("review exit {code:?}"));
    }
    if data_root_opened {
        return Err("the review entry opened a data root".to_string());
    }
    require_fullscreen_restore(&bytes)
}

fn has_color_sgr(bytes: &[u8]) -> bool {
    let mut offset = 0usize;
    while let Some(found) = support::find_subsequence(&bytes[offset..], b"\x1b[") {
        let start = offset + found + 2;
        let mut end = start;
        // A CSI sequence ends at its final byte (0x40..=0x7e); only `m`
        // is an SGR selection, and only its own parameters count.
        while end < bytes.len() && !(0x40..=0x7e).contains(&bytes[end]) {
            end += 1;
        }
        if end < bytes.len() && bytes[end] == b'm' {
            for part in bytes[start..end].split(|byte| *byte == b';') {
                let Ok(text) = std::str::from_utf8(part) else {
                    continue;
                };
                let Ok(value) = text.parse::<u16>() else {
                    continue;
                };
                if matches!(
                    value,
                    30..=37 | 40..=47 | 90..=97 | 100..=107 | 38 | 48 | 58
                ) {
                    return true;
                }
            }
        }
        offset = start;
    }
    false
}

fn has_mouse_capture(bytes: &[u8]) -> bool {
    let needles: [&[u8]; 4] = [
        b"\x1b[?1000h",
        b"\x1b[?1002h",
        b"\x1b[?1003h",
        b"\x1b[?1006h",
    ];
    needles
        .iter()
        .any(|needle| support::find_subsequence(bytes, needle).is_some())
}

fn has_mouse_release(bytes: &[u8]) -> bool {
    let needles: [&[u8]; 4] = [
        b"\x1b[?1000l",
        b"\x1b[?1002l",
        b"\x1b[?1003l",
        b"\x1b[?1006l",
    ];
    needles
        .iter()
        .any(|needle| support::find_subsequence(bytes, needle).is_some())
}

fn has_forbidden_tmux_sequence(bytes: &[u8]) -> bool {
    let needles: [&[u8]; 4] = [b"\x1b[38;2;", b"\x1b[48;2;", b"\x1b]52;", b"\x1b[?2026h"];
    needles
        .iter()
        .any(|needle| support::find_subsequence(bytes, needle).is_some())
}

fn last_position(bytes: &[u8], needle: &[u8]) -> Option<usize> {
    bytes
        .windows(needle.len())
        .rposition(|window| window == needle)
}

fn mouse_capture_left_on(bytes: &[u8]) -> bool {
    let enables: [&[u8]; 4] = [
        b"\x1b[?1000h",
        b"\x1b[?1002h",
        b"\x1b[?1003h",
        b"\x1b[?1006h",
    ];
    let releases: [&[u8]; 4] = [
        b"\x1b[?1000l",
        b"\x1b[?1002l",
        b"\x1b[?1003l",
        b"\x1b[?1006l",
    ];
    let enabled = enables
        .iter()
        .filter_map(|needle| last_position(bytes, needle))
        .max();
    let released = releases
        .iter()
        .filter_map(|needle| last_position(bytes, needle))
        .max();
    match (enabled, released) {
        (Some(enabled), Some(released)) => enabled > released,
        (Some(_), None) => true,
        (None, _) => false,
    }
}

fn require_fullscreen_restore(bytes: &[u8]) -> Result<(), String> {
    if support::find_subsequence(bytes, b"\x1b[?1049h").is_none() {
        return Err("alternate screen was not entered".to_string());
    }
    if support::find_subsequence(bytes, b"\x1b[?1049l").is_none() {
        return Err("alternate screen was not left".to_string());
    }
    if support::find_subsequence(bytes, b"\x1b[?25h").is_none() {
        return Err("cursor was not shown on restore".to_string());
    }
    if mouse_capture_left_on(bytes) {
        return Err("mouse capture was left on".to_string());
    }
    Ok(())
}

fn require_inline_restore(bytes: &[u8]) -> Result<(), String> {
    // A deliberate `/tui` switch may pass through the alternate screen; the
    // final surface is inline only when every entry is followed by a leave.
    if let Some(enter) = support::find_subsequence(bytes, b"\x1b[?1049h")
        && support::find_subsequence(&bytes[enter..], b"\x1b[?1049l").is_none()
    {
        return Err("inline left the alternate screen entered by a switch".to_string());
    }
    if support::find_subsequence(bytes, b"\x1b[?2004h").is_none()
        || support::find_subsequence(bytes, b"\x1b[?2004l").is_none()
    {
        return Err("bracketed paste was not enabled and disabled".to_string());
    }
    if support::find_subsequence(bytes, b"\x1b[?25h").is_none() {
        return Err("cursor was not shown on restore".to_string());
    }
    if mouse_capture_left_on(bytes) {
        return Err("mouse capture was left on".to_string());
    }
    Ok(())
}

struct TuiPty {
    pty: support::PtySession,
    rows: u16,
    cols: u16,
    cursor_at: usize,
}

impl TuiPty {
    fn spawn(
        geometry: Geometry,
        mode: Option<RenderMode>,
        env: &[(&str, &str)],
    ) -> Result<Self, String> {
        let bundle = support::release::baseline_bundle();
        let root = tempfile::TempDir::with_prefix("rivect-installed-tui-")
            .map_err(|error| format!("tui root: {error}"))?;
        let data = root.path().join("data");
        std::fs::create_dir_all(&data).map_err(|error| format!("data root: {error}"))?;
        let (cols, rows) = geometry.size();
        let mut command = support::pty_command(bundle.join("rivect"));
        match mode {
            Some(RenderMode::Linear) => {
                // The accessibility surface has its own flag; `--tui`
                // accepts only the two viewport modes.
                command.arg("--linear");
            }
            Some(mode) => {
                command.arg("--tui");
                command.arg(mode.label());
            }
            None => {}
        }
        command.arg("--data-root");
        command.arg(&data);
        for (name, value) in env {
            command.env(name, value);
        }
        let pty = support::PtySession::spawn(command, rows, cols, root, data)
            .map_err(|error| format!("pty spawn: {error}"))?;
        Ok(Self {
            pty,
            rows,
            cols,
            cursor_at: 0,
        })
    }

    fn spawn_review(geometry: Geometry, state: &str, env: &[(&str, &str)]) -> Result<Self, String> {
        let bundle = support::release::baseline_bundle();
        let root = tempfile::TempDir::with_prefix("rivect-installed-review-")
            .map_err(|error| format!("review root: {error}"))?;
        let data = root.path().join("data");
        let (cols, rows) = geometry.size();
        let mut command = support::pty_command(bundle.join("rivect"));
        command.arg("--ui-review");
        command.arg(state);
        command.env("RIVECT_DATA_ROOT", &data);
        for (name, value) in env {
            command.env(name, value);
        }
        let pty = support::PtySession::spawn(command, rows, cols, root, data)
            .map_err(|error| format!("review pty: {error}"))?;
        Ok(Self {
            pty,
            rows,
            cols,
            cursor_at: 0,
        })
    }

    fn pump(&mut self, duration: Duration) -> Result<(), String> {
        self.pty
            .pump_for(duration)
            .map_err(|error| format!("pty pump: {error}"))
    }

    fn bytes(&self) -> Result<Vec<u8>, String> {
        self.pty
            .collected()
            .map_err(|error| format!("pty read: {error}"))
    }

    fn screen(&self, bytes: &[u8]) -> String {
        let mut parser = vt100::Parser::new(self.rows, self.cols, 200);
        parser.process(bytes);
        parser.screen().contents()
    }

    fn answer_cursor_query(&mut self) -> Result<(), String> {
        let bytes = self.bytes()?;
        if let Some(found) = support::find_subsequence(&bytes[self.cursor_at..], b"\x1b[6n") {
            if trace_enabled() {
                eprintln!(
                    "[cursor-trace {:?}] saw ESC[6n at byte {} (cursor_at {})",
                    trace_at(),
                    found,
                    self.cursor_at
                );
            }
            self.pty
                .send(b"\x1b[1;1R")
                .map_err(|error| format!("pty send: {error}"))?;
            if trace_enabled() {
                eprintln!("[cursor-trace {:?}] answered ESC[1;1R", trace_at());
            }
            self.cursor_at += found + 4;
        }
        Ok(())
    }

    fn wait(&mut self, needle: &str, timeout: Duration) -> Result<String, String> {
        let deadline = Instant::now() + timeout;
        loop {
            self.answer_cursor_query()?;
            let bytes = self.bytes()?;
            let screen = self.screen(&bytes);
            if support::squashed(&screen).contains(&support::squashed(needle)) {
                return Ok(screen);
            }
            if Instant::now() >= deadline {
                if trace_enabled() {
                    let text = String::from_utf8_lossy(&bytes);
                    eprintln!(
                        "[cursor-trace {:?}] timeout for {needle:?}; cleanup-report={} alt-in={} alt-out={} cursor_at={}",
                        trace_at(),
                        text.contains("terminal cleanup failed"),
                        text.contains("\u{1b}[?1049h"),
                        text.contains("\u{1b}[?1049l"),
                        self.cursor_at
                    );
                }
                return Err(format!(
                    "timeout waiting for {needle:?}; last screen:\n{screen}"
                ));
            }
            self.pty
                .pump_for(Duration::from_millis(25))
                .map_err(|error| format!("pty pump: {error}"))?;
        }
    }

    fn send(&mut self, bytes: &[u8]) -> Result<(), String> {
        if trace_enabled() {
            eprintln!(
                "[cursor-trace {:?}] send {:?}",
                trace_at(),
                String::from_utf8_lossy(bytes)
            );
        }
        self.pty
            .send(bytes)
            .map_err(|error| format!("pty send: {error}"))
    }

    fn resize(&mut self, rows: u16, cols: u16) -> Result<(), String> {
        self.pty
            .resize(rows, cols)
            .map_err(|error| format!("pty resize: {error}"))?;
        self.rows = rows;
        self.cols = cols;
        Ok(())
    }

    fn finish_review(mut self) -> Result<(Vec<u8>, Option<u32>, bool), String> {
        drop(self.pty.pump_for(Duration::from_millis(200)));
        let code = self
            .pty
            .wait_exit(Duration::from_secs(10))
            .map_err(|error| format!("pty wait: {error}"))?;
        let data_root_opened = self.pty.data_root().exists();
        let bytes = self.bytes()?;
        self.pty
            .finish()
            .map_err(|error| format!("pty teardown: {error}"))?;
        Ok((bytes, code, data_root_opened))
    }

    fn finish(mut self) -> Result<(Vec<u8>, Option<u32>), String> {
        drop(self.pty.pump_for(Duration::from_millis(200)));
        let code = self
            .pty
            .wait_exit(Duration::from_secs(10))
            .map_err(|error| format!("pty wait: {error}"))?;
        let bytes = self.bytes()?;
        self.pty
            .finish()
            .map_err(|error| format!("pty teardown: {error}"))?;
        Ok((bytes, code))
    }
}

fn exercise_resize(tui: &mut TuiPty, geometry: Geometry) -> Result<(), String> {
    if geometry != Geometry::LiveResize {
        return Ok(());
    }
    tui.resize(40, 120)?;
    tui.wait("Rivect · not connected", WAIT)?;
    tui.resize(20, 60)?;
    tui.wait("Rivect · not connected", WAIT)?;
    Ok(())
}

fn input_probe(input: InputMode, geometry: Geometry) -> Result<(), String> {
    match input {
        InputMode::Keyboard => {
            let mut tui = TuiPty::spawn(geometry, Some(RenderMode::Fullscreen), &[])?;
            tui.wait("Rivect · not connected", WAIT)?;
            exercise_resize(&mut tui, geometry)?;
            tui.send(b"/help\r")?;
            tui.wait("Commands: Enter submits", WAIT)?;
            tui.send(b"\x1b")?;
            let (bytes, code) = tui.finish()?;
            if code != Some(0) {
                return Err(format!("keyboard exit {code:?}"));
            }
            require_fullscreen_restore(&bytes)
        }
        InputMode::Vim => vim_probe(geometry),
        InputMode::Unicode => {
            let mut tui = TuiPty::spawn(geometry, Some(RenderMode::Fullscreen), &[])?;
            tui.wait("Rivect · not connected", WAIT)?;
            exercise_resize(&mut tui, geometry)?;
            tui.send("держ あ".as_bytes())?;
            tui.wait("> держ あ", WAIT)?;
            tui.send(b"\x1b")?;
            let (bytes, code) = tui.finish()?;
            if code != Some(0) {
                return Err(format!("unicode exit {code:?}"));
            }
            require_fullscreen_restore(&bytes)
        }
        InputMode::Paste => {
            let mut tui = TuiPty::spawn(geometry, Some(RenderMode::Fullscreen), &[])?;
            tui.wait("Rivect · not connected", WAIT)?;
            exercise_resize(&mut tui, geometry)?;
            tui.send(b"\x1b[200~alpha\nbeta\x1b[201~")?;
            tui.wait("> alpha beta", WAIT)?;
            tui.send(b"\x1b")?;
            let (bytes, code) = tui.finish()?;
            if code != Some(0) {
                return Err(format!("paste exit {code:?}"));
            }
            require_fullscreen_restore(&bytes)
        }
        InputMode::NoColor => color_probe(geometry, &[("NO_COLOR", "1")]),
        InputMode::Light => color_probe(geometry, &[("COLORFGBG", "15;0")]),
        InputMode::Dark => color_probe(geometry, &[("COLORFGBG", "0;15")]),
        InputMode::HighContrast => color_probe(
            geometry,
            &[("COLORFGBG", "0;15"), ("TERM", "xterm-256color")],
        ),
        InputMode::ReducedMotion => {
            let mut tui = TuiPty::spawn(
                geometry,
                Some(RenderMode::Fullscreen),
                &[("RIVECT_REDUCE_MOTION", "1")],
            )?;
            tui.wait("Rivect · not connected", WAIT)?;
            exercise_resize(&mut tui, geometry)?;
            tui.send(b"/help\r")?;
            tui.wait("Commands: Enter submits", WAIT)?;
            tui.send(b"\x1b")?;
            let (bytes, code) = tui.finish()?;
            if code != Some(0) {
                return Err(format!("reduced-motion exit {code:?}"));
            }
            const SPINNERS: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
            if SPINNERS
                .iter()
                .any(|glyph| support::find_subsequence(&bytes, glyph.as_bytes()).is_some())
            {
                return Err("reduced motion painted a spinner".to_string());
            }
            require_fullscreen_restore(&bytes)
        }
        InputMode::Plain => {
            let mut tui = TuiPty::spawn(geometry, Some(RenderMode::Inline), &[("TERM", "dumb")])?;
            tui.wait("Rivect · not connected", WAIT)?;
            exercise_resize(&mut tui, geometry)?;
            tui.send(b"/help\r")?;
            tui.wait("Commands: Enter submits", WAIT)?;
            tui.send(b"\x1b")?;
            let (bytes, code) = tui.finish()?;
            if code != Some(0) {
                return Err(format!("plain exit {code:?}"));
            }
            if has_color_sgr(&bytes) {
                return Err("plain emitted color".to_string());
            }
            require_inline_restore(&bytes)
        }
        InputMode::Fullscreen => {
            let mut tui = TuiPty::spawn(geometry, Some(RenderMode::Fullscreen), &[])?;
            tui.wait("Rivect · not connected", WAIT)?;
            exercise_resize(&mut tui, geometry)?;
            tui.send(b"/help\r")?;
            tui.wait("Commands: Enter submits", WAIT)?;
            tui.send(b"\x1b")?;
            let (bytes, code) = tui.finish()?;
            if code != Some(0) {
                return Err(format!("fullscreen exit {code:?}"));
            }
            require_fullscreen_restore(&bytes)
        }
        InputMode::Inline => inline_probe(geometry),
        InputMode::Mouse => {
            let mut tui = TuiPty::spawn(geometry, Some(RenderMode::Fullscreen), &[])?;
            tui.wait("Rivect · not connected", WAIT)?;
            exercise_resize(&mut tui, geometry)?;
            let before = tui.bytes()?;
            if has_mouse_capture(&before) {
                return Err("mouse capture was on by default".to_string());
            }
            tui.send(b"/tui mouse on\r")?;
            tui.wait("tui: mouse on", WAIT)?;
            let enabled = tui.bytes()?;
            if !has_mouse_capture(&enabled) {
                return Err("mouse capture did not enable".to_string());
            }
            tui.send(b"/tui mouse off\r")?;
            tui.wait("tui: mouse off", WAIT)?;
            tui.send(b"\x1b")?;
            let (bytes, code) = tui.finish()?;
            if code != Some(0) {
                return Err(format!("mouse exit {code:?}"));
            }
            if !has_mouse_release(&bytes) {
                return Err("mouse capture was not released".to_string());
            }
            require_fullscreen_restore(&bytes)
        }
        InputMode::Tmux => {
            let mut tui = TuiPty::spawn(
                geometry,
                Some(RenderMode::Fullscreen),
                &[("TERM", "tmux-256color")],
            )?;
            tui.wait("Rivect · not connected", WAIT)?;
            exercise_resize(&mut tui, geometry)?;
            tui.send(b"/help\r")?;
            tui.wait("Commands: Enter submits", WAIT)?;
            tui.send(b"\x1b")?;
            let (bytes, code) = tui.finish()?;
            if code != Some(0) {
                return Err(format!("tmux exit {code:?}"));
            }
            if has_forbidden_tmux_sequence(&bytes) {
                return Err("tmux received a truecolor/OSC sequence".to_string());
            }
            require_fullscreen_restore(&bytes)
        }
    }
}

fn color_probe(geometry: Geometry, env: &[(&str, &str)]) -> Result<(), String> {
    let (screen, bytes) = theme_run(geometry, env, "mode")?;
    let (control, control_bytes) = theme_run(geometry, &[], "control")?;
    if screen != control {
        return Err(format!(
            "theme mode changed the rendered screen: {screen:?} != {control:?}"
        ));
    }
    if has_color_sgr(&bytes) || has_color_sgr(&control_bytes) {
        return Err("theme mode emitted an SGR color".to_string());
    }
    require_fullscreen_restore(&bytes)
}

/// One theme-mode run: the screen it renders and the bytes it emitted. The
/// mode is only an environment input, so the differential against a control
/// run is its observable.
fn theme_run(
    geometry: Geometry,
    env: &[(&str, &str)],
    label: &str,
) -> Result<(String, Vec<u8>), String> {
    let mut tui = TuiPty::spawn(geometry, Some(RenderMode::Fullscreen), env)?;
    tui.wait("Rivect · not connected", WAIT)?;
    exercise_resize(&mut tui, geometry)?;
    tui.send(b"/help\r")?;
    tui.wait("Commands: Enter submits", WAIT)?;
    let screen = support::squashed(&tui.screen(&tui.bytes()?));
    let screen = screen
        .split("economy:")
        .next()
        .unwrap_or(screen.as_str())
        .to_string();
    tui.send(b"\x1b")?;
    let (bytes, code) = tui.finish()?;
    if code != Some(0) {
        return Err(format!("{label} theme exit {code:?}"));
    }
    Ok((screen, bytes))
}

fn inline_probe(geometry: Geometry) -> Result<(), String> {
    let mut tui = TuiPty::spawn(geometry, Some(RenderMode::Inline), &[])?;
    tui.wait("Rivect · not connected", WAIT)?;
    exercise_resize(&mut tui, geometry)?;
    tui.send(b"/help\r")?;
    tui.wait("Commands: Enter submits", WAIT)?;
    tui.send(b"draft text")?;
    tui.wait("> draft text", WAIT)?;
    // The draft survives a surface switch: the key is outside the composer.
    tui.send(b"\x14")?;
    // The fullscreen transcript follows its tail, so the switch's own row
    // is visible without a paging keypress.
    tui.wait("tui: switched to fullscreen", WAIT)?;
    tui.wait("> draft text", WAIT)?;
    tui.send(b"\x14")?;
    tui.wait("tui: switched to inline", WAIT)?;
    tui.wait("> draft text", WAIT)?;
    tui.send(b"\x1b")?;
    let rows = tui.rows;
    let cols = tui.cols;
    let (bytes, code) = tui.finish()?;
    if code != Some(0) {
        return Err(format!("inline exit {code:?}"));
    }
    require_inline_restore(&bytes)?;
    if !support::squashed(&String::from_utf8_lossy(&bytes)).contains("Commands: Enter submits") {
        return Err("inline transcript left no scrollback text".to_string());
    }
    let mut parser = vt100::Parser::new(rows, cols, 200);
    parser.process(&bytes);
    if !support::squashed(&parser.screen().contents()).contains("Commands: Enter submits") {
        return Err("inline transcript was not retained in scrollback".to_string());
    }
    Ok(())
}

fn vim_probe(geometry: Geometry) -> Result<(), String> {
    let mut tui = TuiPty::spawn(geometry, Some(RenderMode::Fullscreen), &[])?;
    tui.wait("Rivect · not connected", WAIT)?;
    exercise_resize(&mut tui, geometry)?;
    tui.send(b"vim card probe\r")?;
    tui.wait("awaiting decision", WAIT)?;
    tui.wait("focus 1/2", WAIT)?;
    std::thread::sleep(Duration::from_millis(300));
    tui.send(b"j")?;
    tui.wait("focus 2/2", WAIT)?;
    std::thread::sleep(Duration::from_millis(300));
    tui.send(b"\x1b")?;
    tui.wait("decision left unanswered", WAIT)?;
    tui.send(b"\x1b")?;
    let (bytes, code) = tui.finish()?;
    if code != Some(0) {
        return Err(format!("vim exit {code:?}"));
    }
    require_fullscreen_restore(&bytes)
}

fn zero_send_and_approval() -> Result<(), String> {
    let mut world = support::open_world("installed-tui-inspection", None);
    let session = world.open_session("inspection");
    let task = world.create_task(&session, "inspection");
    let mut view = initial_view();
    view.decision = Some(DecisionPanel::new(Question::fixture(&task, 1)));
    for code in [
        KeyCode::Right,
        KeyCode::Down,
        KeyCode::PageDown,
        KeyCode::Char('j'),
        KeyCode::Char('k'),
    ] {
        let event = TermEvent::Key(KeyEvent::new(code, KeyModifiers::NONE));
        rivect::ui::handle_decision_event(&event, &mut view, &mut world.runtime, &session);
    }
    if world.provider_calls.load(Ordering::SeqCst) != 0 {
        return Err("focusing the decision card called the provider".to_string());
    }
    if world
        .runtime
        .store()
        .answered_question(&task)
        .map_err(|error| error.to_string())?
        .is_some()
    {
        return Err("focusing the decision card recorded an answer".to_string());
    }
    if !world
        .runtime
        .store()
        .answer_attempts(&task)
        .map_err(|error| error.to_string())?
        .is_empty()
    {
        return Err("focusing the decision card recorded an attempt".to_string());
    }

    let scope = "/tmp/installed-tui-inspection-scope";
    let grant = "grant-inspection";
    view.panel = Some(PermissionPanel::new(
        ModeDecision::Ask,
        EffectClass::Write,
        grant,
        "task-170-fixture",
        "2036-01-01T00:00:00Z",
        scope,
    ));
    let key = preapproval_scope(EffectClass::Write, grant, scope)
        .ok_or_else(|| "inspection scope is not valid unicode".to_string())?;
    for code in [
        KeyCode::Right,
        KeyCode::Down,
        KeyCode::PageDown,
        KeyCode::Char('j'),
        KeyCode::Char('k'),
    ] {
        let mut writer = world.runtime.store_writer();
        rivect::ui::handle_panel_key(code, KeyModifiers::NONE, &mut view, &mut writer);
    }
    if world
        .runtime
        .store()
        .is_preapproved(&key)
        .map_err(|error| error.to_string())?
    {
        return Err("inspecting the permission panel recorded a preapproval".to_string());
    }
    let mut writer = world.runtime.store_writer();
    rivect::ui::handle_panel_key(KeyCode::Esc, KeyModifiers::NONE, &mut view, &mut writer);
    if view.panel.is_some() {
        return Err("Esc did not close the permission panel".to_string());
    }
    if world
        .runtime
        .store()
        .is_preapproved(&key)
        .map_err(|error| error.to_string())?
    {
        return Err("dismissing the permission panel recorded a preapproval".to_string());
    }
    Ok(())
}

fn headless_pipe_probe(geometry: Geometry, input: InputMode) -> Result<(), String> {
    let bundle = support::release::baseline_bundle();
    let root = tempfile::TempDir::with_prefix("rivect-installed-pipe-")
        .map_err(|error| format!("pipe root: {error}"))?;
    let data = root.path().join("data");
    std::fs::create_dir_all(&data).map_err(|error| format!("pipe data: {error}"))?;
    let mut command = std::process::Command::new(bundle.join("rivect"));
    command
        .arg("--headless")
        .arg("--data-root")
        .arg(&data)
        .current_dir(root.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|error| format!("pipe spawn: {error}"))?;
    {
        use std::io::Write as _;
        let stdin = child
            .stdin
            .as_mut()
            .ok_or_else(|| "pipe stdin unavailable".to_string())?;
        stdin
            .write_all(
                b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"command.describe\",\"params\":{\"schema_version\":1}}\n",
            )
            .map_err(|error| format!("pipe write: {error}"))?;
    }
    let output = child
        .wait_with_output()
        .map_err(|error| format!("pipe wait: {error}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() {
        return Err(format!(
            "non-TTY run exited {:?}: {stderr}",
            output.status.code()
        ));
    }
    if stdout.contains('\u{1b}') || stderr.contains('\u{1b}') {
        return Err("non-TTY channel emitted ANSI".to_string());
    }
    let mut answers = Vec::new();
    for line in stdout.lines() {
        answers.push(
            serde_json::from_str::<Value>(line)
                .map_err(|error| format!("non-TTY stdout is not JSON: {error}: {line}"))?,
        );
    }
    if answers.len() != 1 || answers[0]["id"] != json!(1) {
        return Err(format!(
            "the pipe must answer exactly id 1 once: {answers:?}"
        ));
    }
    // The pipe has no geometry or input mode: the cell is the same
    // structured-channel proof at every (G, I), and the report says so.
    let _ = (geometry, input);
    Ok(())
}

fn matrix_report_path() -> PathBuf {
    std::env::var_os("RIVECT_UI_MATRIX_REPORT")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("target")
                .join("installed-tui-matrix.json")
        })
}

const RESTORE_EXIT_CLAIM: &str =
    "NOT_RUN (owned by installed_terminal_restores_after_exit_cancel_and_panic)";
const RESTORE_CANCEL_CLAIM: &str =
    "NOT_RUN (owned by installed_terminal_restores_after_exit_cancel_and_panic)";
const RESTORE_PANIC_CLAIM: &str =
    "NOT_RUN (owned by installed_terminal_restores_after_exit_cancel_and_panic; test-child)";
const INLINE_SCROLLBACK_CLAIM: &str =
    "NOT_RUN (owned by installed_inline_clear_after_long_transcript_keeps_later_rows)";
const ZERO_SEND_CLAIM: &str = "NOT_RUN (unit-level proof: installed_focus_and_inspection_never_send_or_approve_unit_level; no packaged interaction claim)";
const THEME_LIGHT_CLAIM: &str = "theme-agnostic rendering; distinct light palette NOT_RUN";
const THEME_DARK_CLAIM: &str = "theme-agnostic rendering; distinct dark palette NOT_RUN";
const THEME_HIGH_CONTRAST_CLAIM: &str =
    "theme-agnostic rendering; distinct high-contrast palette NOT_RUN";

/// Cells whose distinct theme palette stays unproven: the three theme inputs
/// on every state and geometry. They are counted NOT_RUN with the claim as
/// the reason, never PASS.
const NOT_RUN_CELLS: usize = 3 * STATES * GEOMETRIES;

/// The theme inputs a cell cannot pass: their probes assert theme-agnostic
/// rendering only, so a passing probe earns the claim, not a cell verdict.
fn not_run_claim(input: InputMode) -> Option<&'static str> {
    match input {
        InputMode::Light => Some(THEME_LIGHT_CLAIM),
        InputMode::Dark => Some(THEME_DARK_CLAIM),
        InputMode::HighContrast => Some(THEME_HIGH_CONTRAST_CLAIM),
        _ => None,
    }
}

/// The permission panel's renderer-only claim: the frame proves the renderer
/// paints the seeded state, never an approval/decision path opening a panel.
const RENDERER_ONLY_CLAIM: &str = "renderer-only: no production approval/decision path opens the permission panel; the Ask verdict carries no class or target and the sole constructor is the passive `--ui-review` renderer in src/ui/review.rs (DEC-017)";

/// The streaming and failed-output fixtures' renderer-only claim: the step
/// driver that would feed `LocalView::output` in production is deferred, so
/// the frame proves the renderer paints the seeded stream, nothing more.
const RENDERER_ONLY_OUTPUT_CLAIM: &str = "renderer-only: no production producer feeds view.output (the step-driver feed is deferred); the frame proves the renderer paints the seeded stream";

/// The non-TTY state is not a TUI frame at all: a non-TTY entry routes to
/// the structured headless loop, so this cell proves the TUI renderer can
/// paint the seeded text, never that a terminal produces it.
const RENDERER_ONLY_NON_TTY_CLAIM: &str = "renderer-only: the non-TTY entry routes to the structured headless loop; the TUI cannot paint this state in production";

/// The states whose frame is a renderer fixture with no production producer.
fn renderer_only_claim(state: &str) -> Option<&'static str> {
    match state {
        "awaiting-permission" => Some(RENDERER_ONLY_CLAIM),
        "streaming-long-output" | "error-offline-partial" => Some(RENDERER_ONLY_OUTPUT_CLAIM),
        "non-tty" => Some(RENDERER_ONLY_NON_TTY_CLAIM),
        _ => None,
    }
}

/// What each seeded state can honestly claim: the two start states are one
/// production frame, completion has no transcript line, and the permission,
/// streaming, failed-output and non-TTY states are the renderer's alone.
fn state_claims() -> Value {
    json!({
        "start-no-connection": "production start frame; identical to no-project-index because the runtime projects no project or index fact",
        "no-project-index": "same production start frame as start-no-connection; no project or index projection exists",
        "awaiting-permission": RENDERER_ONLY_CLAIM,
        "streaming-long-output": RENDERER_ONLY_OUTPUT_CLAIM,
        "error-offline-partial": RENDERER_ONLY_OUTPUT_CLAIM,
        "non-tty": RENDERER_ONLY_NON_TTY_CLAIM,
        "success": "completion is the dock lifecycle row only; production has no completion transcript line",
    })
}

fn write_report(
    bundle: &Path,
    pass: usize,
    fail: usize,
    not_run: usize,
    cells: &[Value],
) -> Result<PathBuf, String> {
    let manifest = bundle.join("rivect.manifest.json");
    let digest = support::release::sha256_file(&manifest);
    let report = json!({
        "schema_version": 1,
        "candidate_manifest_sha256": digest,
        "states": STATES,
        "geometries": GEOMETRIES,
        "inputs": INPUTS,
        "cells": CELLS,
        "pass": pass,
        "fail": fail,
        "not_run": not_run,
        "cell_verdicts": cells,
        "restore": {
            "exit": RESTORE_EXIT_CLAIM,
            "cancel": RESTORE_CANCEL_CLAIM,
            "panic": RESTORE_PANIC_CLAIM,
            "inline_scrollback": INLINE_SCROLLBACK_CLAIM,
        },
        "zero_send_approval": ZERO_SEND_CLAIM,
        "state_claims": state_claims(),
        "input_mode_claims": {
            "no-color": "no SGR color emitted (asserted)",
            "light": THEME_LIGHT_CLAIM,
            "dark": THEME_DARK_CLAIM,
            "high-contrast": THEME_HIGH_CONTRAST_CLAIM,
            "reduced-motion": "no spinner glyphs emitted (asserted)",
        },
        "platform_terminals": "NOT_RUN (no platform terminal is available on this host)",
    });
    // The restore and zero-send fields are declarations, not executed
    // probes: this test owns neither leg. Assert their evidence class.
    for (label, claim) in [
        ("restore.exit", RESTORE_EXIT_CLAIM),
        ("restore.cancel", RESTORE_CANCEL_CLAIM),
        ("restore.panic", RESTORE_PANIC_CLAIM),
        ("restore.inline_scrollback", INLINE_SCROLLBACK_CLAIM),
        ("zero_send_approval", ZERO_SEND_CLAIM),
    ] {
        assert!(
            claim.starts_with("NOT_RUN"),
            "{label} declares its NOT_RUN owner instead of claiming execution: {claim}"
        );
    }
    for claim in [
        THEME_LIGHT_CLAIM,
        THEME_DARK_CLAIM,
        THEME_HIGH_CONTRAST_CLAIM,
    ] {
        assert!(
            claim.starts_with("theme-agnostic rendering"),
            "a theme cell declaration names the unproven palette: {claim}"
        );
    }
    // The renderer-only states must name their evidence class in the report,
    // and every passing cell of such a state must carry that same claim: a
    // reader can never take a seeded frame for production evidence.
    let claims = state_claims();
    for state in [
        "awaiting-permission",
        "streaming-long-output",
        "error-offline-partial",
        "non-tty",
    ] {
        assert!(
            claims[state]
                .as_str()
                .is_some_and(|claim| claim.starts_with("renderer-only: ")),
            "the renderer-only state {state} names its evidence class"
        );
    }
    for cell in cells {
        let state = cell["state"].as_str().unwrap_or_default();
        if cell["verdict"] == "PASS"
            && let Some(claim) = renderer_only_claim(state)
        {
            assert_eq!(
                cell["reason"], claim,
                "a passing renderer-only cell names its claim: {cell}"
            );
        }
    }
    let path = matrix_report_path();
    std::fs::write(
        &path,
        serde_json::to_string_pretty(&report)
            .map_err(|error| format!("matrix report encode: {error}"))?,
    )
    .map_err(|error| format!("matrix report write {}: {error}", path.display()))?;
    Ok(path)
}

#[test]
fn installed_19_state_matrix_runs_on_the_packaged_artifact() {
    let report_path = matrix_report_path();
    match std::fs::remove_file(&report_path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => panic!("invalidate matrix report: {error}"),
    }
    let bundle = support::release::baseline_bundle();
    assert!(
        !bundle.starts_with(env!("CARGO_MANIFEST_DIR")),
        "the matrix runs on the bundle outside the checkout: {}",
        bundle.display()
    );

    let mut input_verdicts = std::collections::HashMap::new();
    for geometry in Geometry::ALL {
        for input in InputMode::ALL {
            let verdict = input_probe(input, geometry);
            input_verdicts.insert((geometry, input), verdict);
        }
    }

    let mut pass = 0usize;
    let mut fail = 0usize;
    let mut not_run = 0usize;
    let mut cells = Vec::with_capacity(CELLS);
    for state in 0..STATES {
        let fixture = state_fixture(state);
        for geometry in Geometry::ALL {
            let state_verdict = render_state(&fixture, geometry);
            for input in InputMode::ALL {
                let input_verdict = input_verdicts
                    .get(&(geometry, input))
                    .cloned()
                    .unwrap_or_else(|| Err("input probe missing".to_string()));
                let (verdict, reason) =
                    match (not_run_claim(input), state_verdict.clone(), input_verdict) {
                        // The probe asserts theme-agnostic rendering only: the
                        // distinct palette stays NOT_RUN with its claim as the
                        // reason, never a PASS. A probe that fails is still a
                        // failure — the theme run broke, it did not go unproven.
                        (Some(claim), Ok(()), Ok(())) => {
                            not_run += 1;
                            ("NOT_RUN", claim.to_string())
                        }
                        (None, Ok(()), Ok(())) => {
                            pass += 1;
                            ("PASS", String::new())
                        }
                        (_, state, input) => {
                            fail += 1;
                            let mut reasons = Vec::new();
                            if let Err(reason) = state {
                                reasons.push(format!("state: {reason}"));
                            }
                            if let Err(reason) = input {
                                reasons.push(format!("input: {reason}"));
                            }
                            ("FAIL", reasons.join("; "))
                        }
                    };
                // A passing renderer-only frame names that fact, so no reader
                // takes it for a production one.
                let reason = match renderer_only_claim(fixture.name) {
                    Some(claim) if verdict == "PASS" => claim.to_string(),
                    _ => reason,
                };
                if verdict == "FAIL" {
                    println!(
                        "UI-CELL state={} geometry={} input={} verdict={verdict} reason={reason}",
                        fixture.name,
                        geometry.label(),
                        input.label()
                    );
                }
                cells.push(json!({
                    "state": fixture.name,
                    "geometry": geometry.label(),
                    "input": input.label(),
                    "verdict": verdict,
                    "reason": reason,
                }));
            }
        }
    }

    let path = write_report(bundle, pass, fail, not_run, &cells).expect("matrix report");
    println!(
        "UI-CELLS total={CELLS} pass={pass} fail={fail} not_run={not_run} report={}",
        path.display()
    );
    assert_eq!(pass + fail + not_run, CELLS, "every cell is accounted");
    assert_eq!(
        not_run, NOT_RUN_CELLS,
        "the three theme inputs are NOT_RUN on every state and geometry"
    );
    assert_eq!(pass, CELLS - NOT_RUN_CELLS, "every other cell passes");
    assert_eq!(
        fail, 0,
        "every installed UI cell passes or is a declared NOT_RUN"
    );
}

#[test]
fn installed_ui_review_entry_renders_all_19_states() {
    let bundle = support::release::baseline_bundle();
    assert!(
        !bundle.starts_with(env!("CARGO_MANIFEST_DIR")),
        "the review entry runs on the bundle outside the checkout: {}",
        bundle.display()
    );
    let mut rendered = 0usize;
    for state in 0..STATES {
        let fixture = state_fixture(state);
        render_state(&fixture, Geometry::W80H24)
            .unwrap_or_else(|error| panic!("review state {}: {error}", fixture.name));
        rendered += 1;
    }
    assert_eq!(rendered, STATES);
    println!("review states: {rendered}/{STATES} rendered on the packaged artifact");
}

#[test]
fn installed_ui_review_keys_stay_passive_and_ctrl_c_restores() {
    for (state, needle) in [
        ("awaiting-decision", "awaiting decision"),
        ("awaiting-permission", "awaiting permission"),
    ] {
        let mut tui = TuiPty::spawn_review(Geometry::W80H24, state, &[]).expect("review pty");
        tui.wait(needle, WAIT).expect("review state");
        let before = tui.screen(&tui.bytes().expect("review bytes"));
        for key in [b"\r".as_slice(), b"a", b"y", b"d"] {
            tui.send(key).expect("review key");
            tui.pump(Duration::from_millis(100)).expect("review pump");
        }
        let after = tui.screen(&tui.bytes().expect("review bytes"));
        assert_eq!(
            before, after,
            "{state}: Enter/a/y/d must not change the review screen"
        );
        tui.send(b"\x1b").expect("review exit");
        let (bytes, code, data_root_opened) = tui.finish_review().expect("review teardown");
        assert_eq!(code, Some(0), "{state}: Esc exits 0");
        assert!(!data_root_opened, "{state}: review created no rivect.db");
        require_fullscreen_restore(&bytes).expect("review restore");
    }

    let mut cancel =
        TuiPty::spawn_review(Geometry::W80H24, "start-no-connection", &[]).expect("review pty");
    cancel
        .wait("Rivect · not connected", WAIT)
        .expect("review state");
    cancel.send(b"\x03").expect("review ctrl-c");
    let (bytes, code, data_root_opened) = cancel.finish_review().expect("review teardown");
    assert_eq!(code, Some(130), "Ctrl-C exits 130");
    assert!(!data_root_opened, "Ctrl-C review created no rivect.db");
    require_fullscreen_restore(&bytes).expect("review restore");
}

#[test]
fn installed_inline_clear_after_long_transcript_keeps_later_rows() {
    let mut tui =
        TuiPty::spawn(Geometry::W80H24, Some(RenderMode::Inline), &[]).expect("inline pty");
    tui.wait("Input is available", WAIT).expect("inline screen");
    for _ in 0..8 {
        tui.send(b"/help\r").expect("help");
    }
    tui.wait("Commands: Enter submits", WAIT)
        .expect("help transcript");
    tui.send(b"/clear\r").expect("clear");
    tui.wait("New conversation:", WAIT)
        .expect("clear announcement");
    tui.send(b"/settings\r").expect("settings");
    tui.wait("Settings:", WAIT)
        .expect("rows after /clear reach inline scrollback");
    tui.send(b"\x1b").expect("exit");
    let (bytes, code) = tui.finish().expect("teardown");
    assert_eq!(code, Some(0), "inline /clear exits 0");
    require_inline_restore(&bytes).expect("inline restore");
}

/// The inline surface paints the decision card in its reserved region with
/// the question line and the focused row visible: the floor projection pins
/// both instead of scrolling the question away for a distant option. The
/// leg proves a key sent inside the consent floor is refused and the same
/// key after the floor dismisses the card.
#[test]
fn installed_inline_decision_card_paints_and_admits_after_the_consent_floor() {
    let mut tui =
        TuiPty::spawn(Geometry::W80H24, Some(RenderMode::Inline), &[]).expect("inline pty");
    tui.wait("Rivect · not connected", WAIT)
        .expect("inline screen");
    tui.send(b"inline card probe\r").expect("submit task");
    // The production first-question card: its prompt and focus counter are
    // both painted in the nine-row inline region, above the two-row footer.
    // The footer is the last row a card frame paints, so waiting on it
    // proves the whole frame — question line, focused row and footer —
    // landed, not just the first chunk of the diff.
    let opened = tui
        .wait("focus 1/2", WAIT)
        .expect("the inline pinned region paints the card footer");
    let screen = support::squashed(&opened);
    assert!(
        screen.contains("Begin the first step"),
        "the inline card paints the question prompt: {screen}"
    );
    assert!(
        screen.contains("> 1."),
        "the inline card paints the focused row: {screen}"
    );
    // The consent window runs from the first paint: a key sent inside it
    // cannot have been aimed at the card. The absent-needle wait outlasts
    // the floor, so a dismissal would have painted by the assertion.
    tui.send(b"\x1b").expect("pre-floor dismiss");
    tui.pump(Duration::from_millis(400))
        .expect("pump past the floor");
    let bytes = tui.bytes().expect("inline bytes");
    let refused = support::squashed(&tui.screen(&bytes));
    assert!(
        refused.contains("focus 1/2") && !refused.contains("decision left unanswered"),
        "an unaimed Esc inside the floor never dismisses the card: {refused}"
    );
    // The waits above already outlasted the floor, so this Esc is admitted
    // and the card leaves the question pending for the wire surface.
    tui.send(b"\x1b").expect("dismiss card");
    tui.wait("decision left unanswered", WAIT)
        .expect("the admitted Esc dismisses the card");
    tui.send(b"\x1b").expect("exit");
    let (bytes, code) = tui.finish().expect("teardown");
    assert_eq!(code, Some(0), "the inline card session exits 0");
    require_inline_restore(&bytes).expect("inline restore");
}

/// Every CSI sequence the linear surface emits must be a bracketed-paste
/// toggle; any other is cursor addressing or an alternate-screen entry and
/// breaks the append-only contract.
fn has_cursor_addressing(bytes: &[u8]) -> bool {
    let mut offset = 0usize;
    while let Some(found) = support::find_subsequence(&bytes[offset..], b"\x1b[") {
        let rest = &bytes[offset + found..];
        if !(rest.starts_with(b"\x1b[?2004h") || rest.starts_with(b"\x1b[?2004l")) {
            return true;
        }
        offset += found + 2;
    }
    false
}

/// One linear-surface selector under test: a label, the entry mode, and the
/// environment the child receives.
type LinearCase<'a> = (&'a str, Option<RenderMode>, &'a [(&'a str, &'a str)]);

/// The screen-reader surface is a linear append-only stream: no alternate
/// screen, no cursor addressing, and consecutive transcript rows arrive
/// intact. Both selectors — the flag and the environment — reach it on the
/// packaged artifact.
#[test]
fn installed_linear_mode_is_append_only_plain_text() {
    let cases: [LinearCase<'_>; 2] = [
        ("flag", Some(RenderMode::Linear), &[]),
        ("env", None, &[("RIVECT_LINEAR", "1")]),
    ];
    for (label, mode, env) in cases {
        let mut tui = TuiPty::spawn(Geometry::W80H24, mode, env)
            .unwrap_or_else(|error| panic!("{label} linear pty: {error}"));
        tui.wait("Input is available. Enter a task or a clarification.", WAIT)
            .unwrap_or_else(|error| panic!("{label} linear screen: {error}"));
        tui.send(b"/help\r").expect("help");
        tui.wait("Commands: Enter submits", WAIT)
            .unwrap_or_else(|error| panic!("{label} linear help: {error}"));
        tui.send(b"\x1b").expect("exit");
        let (bytes, code) = tui.finish().expect("teardown");
        assert_eq!(code, Some(0), "{label}: the linear session exits 0");
        assert!(
            support::find_subsequence(&bytes, b"\x1b[?1049").is_none(),
            "{label}: linear never enters the alternate screen"
        );
        assert!(
            !has_cursor_addressing(&bytes),
            "{label}: linear emitted cursor addressing: {}",
            String::from_utf8_lossy(&bytes)
        );
        let start = b"Input is available. Enter a task or a clarification.\r\n\
No project or index is selected; ordinary replies are not blocked.";
        assert!(
            support::find_subsequence(&bytes, start).is_some(),
            "{label}: consecutive transcript rows arrive intact: {}",
            String::from_utf8_lossy(&bytes)
        );
        assert!(
            support::find_subsequence(&bytes, b"Commands: Enter submits").is_some(),
            "{label}: the help row arrives in the stream"
        );
    }
}

#[test]
fn installed_terminal_restores_after_exit_cancel_and_panic() {
    // Exit and cancel run on the packaged artifact.
    let mut exit =
        TuiPty::spawn(Geometry::W80H24, Some(RenderMode::Fullscreen), &[]).expect("exit pty");
    exit.wait("Rivect · not connected", WAIT)
        .expect("exit screen");
    exit.send(b"\x1b").expect("exit key");
    let (bytes, code) = exit.finish().expect("exit teardown");
    assert_eq!(code, Some(0), "Esc exits cleanly");
    require_fullscreen_restore(&bytes).expect("exit restore");

    let mut cancel =
        TuiPty::spawn(Geometry::W60H20, Some(RenderMode::Fullscreen), &[]).expect("cancel pty");
    cancel
        .wait("Rivect · not connected", WAIT)
        .expect("cancel screen");
    cancel.send(b"\x03").expect("cancel key");
    let (bytes, code) = cancel.finish().expect("cancel teardown");
    assert_eq!(code, Some(130), "Ctrl-C cancels");
    require_fullscreen_restore(&bytes).expect("cancel restore");

    // The packaged artifact has no public panic trigger, so the panic leg
    // runs the same production guard in this test binary's child.
    panic_restore().expect("panic restore");
}

fn panic_restore() -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|error| format!("current exe: {error}"))?;
    let root = tempfile::TempDir::with_prefix("rivect-installed-panic-")
        .map_err(|error| format!("panic root: {error}"))?;
    let data = root.path().join("data");
    std::fs::create_dir_all(&data).map_err(|error| format!("panic data: {error}"))?;
    let mut command = support::pty_command(exe);
    command.env("RIVECT_INSTALLED_TUI_PANIC", "1");
    command.args([
        "--ignored",
        "--exact",
        "panic_child",
        "--test-threads=1",
        "--nocapture",
    ]);
    let mut pty = support::PtySession::spawn(command, 20, 80, root, data)
        .map_err(|error| format!("panic pty: {error}"))?;
    let entered = pty
        .wait_for(b"\x1b[?1049h", Duration::from_secs(10))
        .map_err(|error| format!("panic read: {error}"))?;
    if !entered {
        return Err("panic child never entered the alternate screen".to_string());
    }
    let code = pty
        .wait_exit(Duration::from_secs(10))
        .map_err(|error| format!("panic wait: {error}"))?;
    let bytes = pty
        .collected()
        .map_err(|error| format!("panic read: {error}"))?;
    pty.finish()
        .map_err(|error| format!("panic teardown: {error}"))?;
    if code == Some(0) {
        return Err("panic child exited successfully".to_string());
    }
    require_fullscreen_restore(&bytes)
}

#[test]
fn installed_focus_and_inspection_never_send_or_approve_unit_level() {
    zero_send_and_approval().expect("focus/inspection is passive");
}

#[test]
fn installed_non_tty_channels_stay_structured() {
    headless_pipe_probe(Geometry::W80H24, InputMode::Keyboard).expect("non-TTY channels");
}

/// A terminal stdin with a redirected stdout must answer the usage/help and
/// exit 2: with only one stream a terminal the run has no surface, and the
/// JSON-RPC loop would wait on the live terminal forever instead of printing.
#[test]
fn installed_mixed_streams_print_help_and_exit_instead_of_waiting() {
    let bundle = support::release::baseline_bundle();
    let root = tempfile::TempDir::with_prefix("rivect-installed-mixed-").expect("mixed root");
    let data = root.path().join("data");
    std::fs::create_dir_all(&data).expect("mixed data");
    let log = root.path().join("stream.log");
    let status = root.path().join("status");
    // The shell script is a fixed literal; the only substituted values are
    // this test's own paths, passed as environment entries rather than built
    // into the command string (standards §10). The brace group writes the
    // child's own exit class while `cat` keeps its stdout a real pipe.
    let mut command = support::pty_command("sh");
    command.arg("-c");
    command
        .arg("{ \"$RIVECT_BIN\" 2>&1; echo \"$?\" > \"$RIVECT_STATUS\"; } | cat > \"$RIVECT_LOG\"");
    command.env("RIVECT_BIN", bundle.join("rivect"));
    command.env("RIVECT_LOG", &log);
    command.env("RIVECT_STATUS", &status);
    command.env("RIVECT_DATA_ROOT", &data);
    let mut pty = support::PtySession::spawn(command, 24, 80, root, data).expect("mixed pty");
    let code = pty.wait_exit(WAIT).expect("mixed wait");
    let bytes = pty.collected().expect("mixed read");
    let log_text = std::fs::read_to_string(&log).unwrap_or_default();
    let status_text = std::fs::read_to_string(&status).unwrap_or_default();
    pty.finish().expect("mixed teardown");
    assert_eq!(
        code,
        Some(0),
        "the wrapper must finish after the child; a deadline kill here is the pre-fix hang: {}",
        String::from_utf8_lossy(&bytes)
    );
    assert_eq!(
        status_text.trim(),
        "2",
        "a mixed-stream run is a usage error, not a wait: {log_text}"
    );
    assert!(
        log_text.contains("usage:"),
        "the refusal prints the usage/help: {log_text}"
    );
    assert!(
        log_text.contains("stdout is not a terminal"),
        "the refusal names the non-terminal stream: {log_text}"
    );
    assert!(
        log_text.contains("--headless"),
        "the help names the machine entry: {log_text}"
    );
    assert!(
        !log_text.contains('\u{1b}'),
        "the refusal is plain text: {log_text}"
    );
}

#[test]
#[ignore = "panic child: its parent spawns it with RIVECT_INSTALLED_TUI_PANIC"]
fn panic_child() {
    if std::env::var_os("RIVECT_INSTALLED_TUI_PANIC").is_none() {
        return;
    }
    let _guard = TerminalGuard::enter().expect("terminal guard");
    panic!("installed tui panic restore probe");
}
