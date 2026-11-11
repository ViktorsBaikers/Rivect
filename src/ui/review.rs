//! Seed views for the packaged `--ui-review` entry (TD-14). The nineteen
//! inherited design-brief states are rendered through the production
//! renderer; this module owns only their view data, so the release entry and
//! the installed PTY matrix read one source. It opens no runtime, store or
//! provider and routes no decision or permission key.

use super::{
    DecisionPanel, LocalView, PermissionPanel, RenderMode, TerminalGuard, initial_view, render,
    task_dock,
};
use crate::contracts::{EffectClass, Question, TaskId};
use crate::policy::ModeDecision;
use crate::resources::{OutputSettlement, OutputStream};
use crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use serde_json::{Value, json};
use std::time::Duration;

/// The nineteen inherited states in design-brief order.
pub const STATES: [&str; 19] = [
    "start-no-connection",
    "no-project-index",
    "ready-for-input",
    "streaming-long-output",
    "parallel-work",
    "awaiting-decision",
    "awaiting-permission",
    "fullscreen-inline",
    "pause-cancel",
    "quota-fallback",
    "error-offline-partial",
    "success",
    "settings-default-modified-locked-pending",
    "settings-invalid-conflict",
    "resume-compaction-upgrade",
    "rewind-preview-conflict-partial",
    "big-list-narrow-window",
    "workflow-off",
    "non-tty",
];

/// The seeded views of the release review entry.
pub struct ReviewState;

impl ReviewState {
    /// The view one inherited state id names; an unknown id answers `None`.
    #[must_use]
    pub fn view(state: &str) -> Option<LocalView> {
        Some(match state {
            // Both start ids name the same production frame: the runtime
            // projects no project or index fact, so the design brief's two
            // states share one seeded view.
            "start-no-connection" => initial_view(),
            "no-project-index" => initial_view(),
            "ready-for-input" => {
                let mut view = initial_view();
                view.composer = "draft a change".to_string();
                view
            }
            "streaming-long-output" => {
                let mut view = initial_view();
                let mut output = OutputStream::new();
                output.push_chunk(b"streaming marker line\n");
                for _ in 0..120 {
                    output.push_chunk(b"long tool output line\n");
                }
                view.replace_output(output);
                view
            }
            "parallel-work" => {
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
                view
            }
            "awaiting-decision" => {
                let mut view = initial_view();
                view.decision = Some(DecisionPanel::new(Question::fixture(
                    &TaskId("task-1".to_string()),
                    1,
                )));
                view
            }
            "awaiting-permission" => {
                // Renderer-only: no production approval/decision path opens
                // the panel (the Ask verdict carries no class or target); the
                // sole constructor is the passive `--ui-review` renderer,
                // here — DEC-017. The frame proves the renderer paints the
                // state, never a production open.
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
                view
            }
            "fullscreen-inline" => {
                let mut view = initial_view();
                view.transcript = vec![
                    "tui: switched to inline".to_string(),
                    "tui: switched to fullscreen".to_string(),
                ];
                view.composer = "draft survives".to_string();
                view
            }
            "pause-cancel" => {
                let mut view = initial_view();
                view.dock = task_dock(&status_with_tasks(
                    &[
                        ("task-1", "cancelled", Some("operator stop")),
                        ("task-2", "blocked", Some("unknown external effect")),
                    ],
                    Value::Null,
                ));
                view
            }
            "quota-fallback" => {
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
                view
            }
            "error-offline-partial" => {
                let mut view = initial_view();
                let mut output = OutputStream::new();
                output.push_chunk(b"partial body\n");
                output.settle(OutputSettlement::Partial {
                    cause: "connection lost".to_string(),
                });
                view.replace_output(output);
                view.dock_stale = Some("dock refresh failed: offline".to_string());
                view
            }
            "success" => {
                // Completion shows as the dock lifecycle row only: the
                // production renderer has no completion transcript line.
                let mut view = initial_view();
                view.dock = task_dock(&status_with_tasks(
                    &[("task-1", "completed", None)],
                    Value::Null,
                ));
                view
            }
            "settings-default-modified-locked-pending" => {
                let mut view = initial_view();
                view.transcript = vec![
                    "Settings:".to_string(),
                    "model = auto (default)".to_string(),
                    "effort = high (modified)".to_string(),
                    "workflow.enabled = false (locked)".to_string(),
                    "profile = next (pending)".to_string(),
                ];
                view
            }
            "settings-invalid-conflict" => {
                let mut view = initial_view();
                view.transcript = vec![
                    "config.set refused: conflict at models.defaults.model; the other writer's draft is kept"
                        .to_string(),
                    "config.validate: invalid_input at context.auto_compact".to_string(),
                ];
                view
            }
            "resume-compaction-upgrade" => {
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
                view
            }
            "rewind-preview-conflict-partial" => {
                let mut view = initial_view();
                view.transcript = vec![
                    "Rewind preview: task task-1, 4096 assembled bytes".to_string(),
                    "no rollback applied; apply is a separate action".to_string(),
                    "Checkpoint: cp-1 folded 3 records".to_string(),
                    "checkpoint.apply refused: conflict: stale intent".to_string(),
                ];
                view
            }
            "big-list-narrow-window" => {
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
                view
            }
            "workflow-off" => {
                let mut view = initial_view();
                view.transcript = vec!["workflow: off; custom task state".to_string()];
                view.dock = task_dock(&status_with_tasks(
                    &[("task-1", "custom", Some("workflow off"))],
                    Value::Null,
                ));
                view
            }
            "non-tty" => {
                let mut view = initial_view();
                view.transcript =
                    vec!["non-tty: structured events on stdout; diagnostics on stderr".to_string()];
                view
            }
            _ => return None,
        })
    }

    /// Renders one state until Esc (0) or Ctrl-C (130). Unknown states are
    /// refused before a terminal is entered; the entry opens nothing else.
    ///
    /// # Errors
    /// The terminal guard, render or input failure.
    pub fn run(state: &str) -> std::io::Result<i32> {
        let Some(view) = Self::view(state) else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("unknown ui review state {state}"),
            ));
        };
        let mut guard = TerminalGuard::enter_mode(RenderMode::Fullscreen)?;
        render(guard.terminal_mut(), &view)?;
        loop {
            if !crossterm::event::poll(Duration::from_millis(250))? {
                continue;
            }
            match crossterm::event::read()? {
                Event::Key(KeyEvent {
                    code: KeyCode::Esc,
                    kind: KeyEventKind::Press,
                    ..
                }) => return Ok(0),
                Event::Key(KeyEvent {
                    code: KeyCode::Char('c'),
                    modifiers,
                    kind: KeyEventKind::Press,
                    ..
                }) if modifiers.contains(KeyModifiers::CONTROL) => return Ok(130),
                Event::Resize(_, _) => render(guard.terminal_mut(), &view)?,
                _ => {}
            }
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
