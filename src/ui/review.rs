//! Passive seed data for the packaged review surface. No terminal, store, or provider.

use super::{DOCK_EMPTY, STATUS_DISCONNECTED, TRANSCRIPT_INPUT, TRANSCRIPT_NO_PROJECT, task_dock};
use crate::contracts::{Availability, Question, TaskId};
use serde_json::{Value, json};

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

/// Projects a seeded review without opening a runtime, provider, or terminal.
#[must_use]
pub fn projection(state: &str) -> Option<Value> {
    let mut lines = vec![TRANSCRIPT_INPUT, TRANSCRIPT_NO_PROJECT];
    let mut dock = vec![DOCK_EMPTY.to_owned()];
    let mut composer = "";
    let mut panel = Vec::new();
    let stream;
    match state {
        "start-no-connection" | "no-project-index" => {}
        "ready-for-input" => composer = "draft a change",
        "streaming-long-output" => {
            stream = format!(
                "streaming marker line\n{}",
                "long tool output line\n".repeat(120)
            );
            lines.extend(["PgUp/PgDn scroll · output · streaming", &stream]);
        }
        "parallel-work" => {
            dock = rows(
                &[
                    ("task-1", "running", None),
                    ("task-2", "waiting", None),
                    ("task-3", "blocked", Some("plan gate")),
                    ("task-4", "completed", None),
                ],
                Value::Null,
            )
        }
        "awaiting-decision" => {
            composer = "[input paused: answer the decision card]";
            panel = decision_rows();
        }
        "awaiting-permission" => {
            composer = "[input paused: answer the permission panel]";
            panel = [
                "awaiting permission\ndecision: ask\neffect: write\ninitiator: task-170-fixture\nexpiry: 2036-01-01T00:00:00Z\ngrant: grant-installed-tui",
                "scope: /tmp/installed-tui/workflow-scope/deep/nested/directory-tree/permission-grant-boundary-with-a-deliberately-long-tail-suffix",
                "allow once | allow with limited grant (10 min) | [deny]\narrows move, PgUp/PgDn scroll, Enter confirms, Esc denies",
            ].map(str::to_owned).into();
        }
        "fullscreen-inline" => {
            lines = vec!["tui: switched to inline", "tui: switched to fullscreen"];
            composer = "draft survives";
        }
        "pause-cancel" => {
            dock = rows(
                &[
                    ("task-1", "cancelled", Some("operator stop")),
                    ("task-2", "blocked", Some("unknown external effect")),
                ],
                Value::Null,
            )
        }
        "quota-fallback" => {
            dock = rows(
                &[(
                    "task-1",
                    "paused",
                    Some("quota exhausted; fallback unknown"),
                )],
                json!({
                    "project":"/tmp/installed-tui", "cwd":"/tmp/installed-tui", "settled_tokens":10,
                    "settled_source":"exact", "charged_units":1, "cost_source":"estimated", "agents":0,
                    "agents_source":"stale", "reset_at":"2026-11-10T00:00:00Z", "reset_source":"exact",
                    "quota_remaining":null, "quota_source":"unknown: no quota endpoint reports remaining units",
                    "context_tokens":5, "context_source":"exact", "cache_source":"stale", "model":"fixture-model",
                    "source":"recorded", "effort":"high", "effort_source":"recorded", "purpose":"main", "connection":"primary"
                }),
            )
        }
        "error-offline-partial" => lines.extend([
            "PgUp/PgDn scroll · output · partial: connection lost",
            "partial body\n",
            "dock refresh failed: offline",
        ]),
        "success" | "resume-compaction-upgrade" => {
            dock = rows(&[("task-1", "completed", None)], Value::Null);
            if state == "resume-compaction-upgrade" {
                lines = vec![
                    "Resumed session: session-1",
                    "Context compacted: 4096 → 1024 bytes, 3 records folded",
                    "upgrade: active generation 1; pending generation 2",
                ];
            }
        }
        "settings-default-modified-locked-pending" => {
            lines = vec![
                "Settings:",
                "model = auto (default)",
                "effort = high (modified)",
                "workflow.enabled = false (locked)",
                "profile = next (pending)",
            ]
        }
        "settings-invalid-conflict" => {
            lines = vec![
                "config.set refused: conflict at models.defaults.model; the other writer's draft is kept",
                "config.validate: invalid_input at context.auto_compact",
            ]
        }
        "rewind-preview-conflict-partial" => {
            lines = vec![
                "Rewind preview: task task-1, 4096 assembled bytes",
                "no rollback applied; apply is a separate action",
                "Checkpoint: cp-1 folded 3 records",
                "checkpoint.apply refused: conflict: stale intent",
            ]
        }
        "big-list-narrow-window" => {
            dock = rows(
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
            )
        }
        "workflow-off" => {
            lines = vec!["workflow: off; custom task state"];
            dock = rows(&[("task-1", "custom", Some("workflow off"))], Value::Null);
        }
        "non-tty" => lines = vec!["non-tty: structured events on stdout; diagnostics on stderr"],
        _ => return None,
    }
    Some(
        json!({"state":state,"status":STATUS_DISCONNECTED,"dock":dock,"lines":lines,"composer":composer,"panel":panel}),
    )
}

fn decision_rows() -> Vec<String> {
    let q = Question::fixture(&TaskId("task-1".to_owned()), 1);
    let mut rows = vec![
        "awaiting decision\ntask: task-1\nquestion: 00000000-0000-4000-8000-000000000001 rev 1"
            .to_owned(),
        format!(
            "question: {}\nrecommended: {} — {}\n",
            q.prompt, q.recommended_option_id.0, q.recommendation_basis
        ),
    ];
    for (i, option) in q.options.iter().enumerate() {
        let prefix = if i == 0 { "> " } else { "  " };
        let mut row = format!(
            "{prefix}{}. {} — {}",
            i + 1,
            option.label,
            option.consequences
        );
        if option.option_id == q.recommended_option_id {
            row.push_str(" (recommended)");
        }
        if let Availability::Disabled { reason } = &option.availability {
            row.push_str(" — unavailable: ");
            row.push_str(reason);
        }
        rows.push(row);
    }
    let count = q.options.len() + 1;
    rows.push(format!("  {count}. custom answer — type your own answer"));
    rows.push(format!(
        "focus 1/{count}\narrows move, PgUp/PgDn scroll, Enter selects, Esc returns"
    ));
    rows
}

fn rows(tasks: &[(&str, &str, Option<&str>)], economy: Value) -> Vec<String> {
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
    let mut dock = task_dock(&json!({"todo":{"items":items},"economy":economy}));
    if tasks.len() > 3 {
        dock.insert(2, format!("+{} more", tasks.len() - 2));
    }
    dock
}
