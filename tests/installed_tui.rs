//! AC-001 (TD-03/TD-15): the exact packaged artifact from the release slice
//! runs the inherited 19 design-brief states across the four acceptance
//! geometries plus a live resize and the fourteen input modes. Every cell is
//! exercised with a pass/fail verdict. Every one of the 19 states is also
//! rendered under each of the three themes at every geometry (285
//! state×theme observations); each observation compares that state's
//! status/dock/composer/transcript/modal SGR fingerprint to the pinned palette
//! for its theme, with text identical to the default mono control. Mono
//! `NO_COLOR`/`TERM=dumb`/non-TTY emits no SGR color and every state's status
//! token plus dock/composer labels appear verbatim. The state's own rendered
//! observables at that geometry must appear, and the input mode must reach the
//! same artifact. Terminal restore is checked after exit, cancel and panic;
//! inline keeps the transcript in the terminal's own scrollback with mouse
//! capture off; and focusing or inspecting a decision card or permission panel
//! records no answer, no preapproval and no provider call. Screenshot or file
//! presence is never used as interaction proof.
//!

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

use rivect::contracts::{Lifecycle, MODEL_WIRE_MAX_BYTES, SessionId, TaskId};
use rivect::state::TaskStore;
use rivect::ui::{RenderMode, task_dock};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

const STATES: usize = 19;
const GEOMETRIES: usize = 5;
const INPUTS: usize = 14;
const CELLS: usize = STATES * GEOMETRIES * INPUTS;

/// One observation per state, geometry and theme.
const THEME_OBSERVATIONS: usize = STATES * GEOMETRIES * 3;
/// One mono label/SGR probe per state, geometry and selected theme.
const MONO_PROBES: usize = STATES * GEOMETRIES * 3;
/// One `TERM=dumb` label probe per state.
const DUMB_PROBES: usize = STATES;
/// The bounded worker set for independent packaged runs.
const MATRIX_WORKERS: usize = 4;
/// The recorded matrix gate: the run must stay below this wall time.
const MATRIX_BUDGET_SECONDS: f64 = 900.0;

/// The three inherited themes and the exact `RIVECT_THEME` value each names.
const THEMES: [&str; 3] = ["light", "dark", "high-contrast"];

/// Packaged probes run four-wide against a busy host: a generous deadline
/// keeps a load-slowed paint from reading as a defect, and still fails a hang.
const WAIT: Duration = Duration::from_secs(30);
/// The live-resize lane is separate from the four-worker pool: at most two
/// resized frames capture at once, and each waits for its own settled frame.
const LIVE_WORKERS: usize = 2;
/// A settled live-resize frame may take longer than an ordinary first paint,
/// and load stretches both; the deadline still fails a resize that never lands.
const LIVE_RESIZE_WAIT: Duration = Duration::from_secs(60);

const DECISION_UNANSWERED: &str = "Unanswered; question stays pending";

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

const STATUS: &str = "Rivect · not connected · /help for help";
const EMPTY_DOCK: &str = "No tasks. Login is a separate explicit action.";
const INPUT: &str = "Input is available. Enter a task or a clarification.";
const NO_PROJECT: &str = "No project or index is selected; ordinary replies are not blocked.";

struct ExpectedReview {
    dock: Vec<String>,
    transcript: Vec<String>,
    composer: String,
}

fn initial_view() -> ExpectedReview {
    ExpectedReview {
        dock: vec![EMPTY_DOCK.into()],
        transcript: vec![INPUT.into(), NO_PROJECT.into()],
        composer: String::new(),
    }
}

struct StateFixture {
    name: &'static str,
    needles: &'static [&'static str],
    dock_probe: String,
    transcript_probe: String,
    composer_label: String,
    modal: bool,
}

impl StateFixture {
    fn new(
        name: &'static str,
        mut expected: ExpectedReview,
        needles: &'static [&'static str],
    ) -> Self {
        let data = rivect::ui::review::projection(name).expect("known review state");
        let modal = matches!(name, "awaiting-permission" | "awaiting-decision");
        assert_eq!(data["status"], STATUS, "{name}: status");
        assert_eq!(data["composer"], expected.composer, "{name}: composer");
        let tasks = expected.dock.len().saturating_sub(1);
        if tasks > 3 {
            expected.dock.insert(2, format!("+{} more", tasks - 2));
        }
        assert_eq!(data["dock"], json!(expected.dock), "{name}: dock");
        assert_eq!(
            data["lines"],
            json!(expected.transcript),
            "{name}: transcript"
        );
        assert_eq!(
            !data["panel"].as_array().expect("panel rows").is_empty(),
            modal,
            "{name}: modal"
        );
        Self {
            name,
            needles,
            dock_probe: expected.dock.remove(0),
            transcript_probe: expected.transcript.remove(0),
            composer_label: format!("> {}", expected.composer).trim_end().to_owned(),
            modal,
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
        // Both review IDs intentionally start with the same disconnected facts.
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
            view.transcript
                .push("PgUp/PgDn scroll · output · streaming".into());
            view.transcript.push(format!(
                "streaming marker line\n{}",
                "long tool output line\n".repeat(120)
            ));
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
            view.composer = "[input paused: answer the decision card]".into();
            StateFixture::new(
                "awaiting-decision",
                view,
                &["awaiting decision", "focus 1/6", "recommended:"],
            )
        }
        6 => {
            let mut view = initial_view();
            view.composer = "[input paused: answer the permission panel]".into();
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
            view.transcript.extend([
                "PgUp/PgDn scroll · output · partial: connection lost".into(),
                "partial body\n".into(),
                "dock refresh failed: offline".into(),
            ]);
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
            // Completion is observed in the seeded lifecycle row.
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

/// The five palette carriers' SGR state, read from the final screen cells the
/// packaged renderer painted.
struct SurfaceFingerprints {
    status: String,
    dock: String,
    composer: String,
    modal: String,
    transcript: String,
}

impl SurfaceFingerprints {
    fn surface(&self, surface: &str) -> &str {
        match surface {
            "status" => &self.status,
            "dock" => &self.dock,
            "composer" => &self.composer,
            "modal" => &self.modal,
            "transcript" => &self.transcript,
            _ => panic!("unknown surface {surface}"),
        }
    }
}

/// Independently pinned xterm indexes and emphasis for the five visible surfaces.
fn expected_fingerprint(theme: &str, surface: &str) -> &'static str {
    match (theme, surface) {
        ("light", "status" | "modal") => "fg=Idx(4);bg=Default;bold=false",
        ("light", "composer") => "fg=Idx(5);bg=Default;bold=false",
        ("light", "dock" | "transcript") => "fg=Default;bg=Default;bold=false",
        ("dark", "status" | "modal") => "fg=Idx(6);bg=Default;bold=false",
        ("dark", "composer") => "fg=Idx(13);bg=Default;bold=false",
        ("dark", "dock" | "transcript") => "fg=Default;bg=Default;bold=false",
        ("high-contrast", "status") => "fg=Idx(11);bg=Default;bold=true",
        ("high-contrast", "composer") => "fg=Idx(14);bg=Default;bold=true",
        ("high-contrast", "modal") => "fg=Idx(15);bg=Default;bold=true",
        ("high-contrast", "dock" | "transcript") => "fg=Default;bg=Default;bold=true",
        _ => panic!("no expected fingerprint for {theme}/{surface}"),
    }
}

/// Captured review pages, actual surface cells, and raw terminal output.
struct ReviewFrame {
    text: String,
    fingerprints: SurfaceFingerprints,
    bytes: Vec<u8>,
}

/// One state×geometry×theme observation for the matrix report.
struct ThemeObservation {
    state: &'static str,
    geometry: &'static str,
    theme: &'static str,
    fingerprints: SurfaceFingerprints,
}

impl ThemeObservation {
    fn to_json(&self) -> Value {
        json!({
            "state": self.state,
            "geometry": self.geometry,
            "theme": self.theme,
            "status": self.fingerprints.status,
            "dock": self.fingerprints.dock,
            "composer": self.fingerprints.composer,
            "modal": self.fingerprints.modal,
            "transcript": self.fingerprints.transcript,
        })
    }
}

/// Runs independent jobs on a bounded worker set, preserving job order in the
/// result vector. Each job owns its fixture, so no view crosses a thread.
fn parallel_map<T: Copy + Send + Sync, R: Send>(
    jobs: &[T],
    workers: usize,
    work: impl Fn(T) -> R + Sync,
) -> Vec<R> {
    if jobs.is_empty() {
        return Vec::new();
    }
    let workers = workers.clamp(1, jobs.len());
    let chunk_size = jobs.len().div_ceil(workers);
    std::thread::scope(|scope| {
        let handles: Vec<_> = jobs
            .chunks(chunk_size)
            .map(|chunk| {
                let work = &work;
                scope.spawn(move || chunk.iter().map(|job| work(*job)).collect::<Vec<R>>())
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|handle| handle.join().expect("palette worker"))
            .collect()
    })
}

/// Runs the live-resize jobs in their own small lane after the ordinary jobs
/// have finished on the four-worker pool. Their resize settle never competes
/// with sibling redraws, and each capture waits for a still frame.
fn parallel_then_live<T: Copy + Send + Sync, R: Send>(
    jobs: &[T],
    workers: usize,
    live_workers: usize,
    live: impl Fn(T) -> bool + Sync,
    work: impl Fn(T) -> R + Sync,
) -> Vec<R> {
    let (live_jobs, parallel_jobs): (Vec<T>, Vec<T>) =
        jobs.iter().copied().partition(|job| live(*job));
    let mut results = parallel_map(&parallel_jobs, workers, &work);
    results.extend(parallel_map(&live_jobs, live_workers, work));
    results
}

/// Text from the captured grid, with each visible cell bound to its actual SGR.
/// Read the two responsive columns separately so wrapped body text is not interleaved.
struct PaintedRegion {
    text: String,
    positions: Vec<(u16, u16)>,
}

impl PaintedRegion {
    fn read(screen: &vt100::Screen, rows: u16, start: u16, end: u16) -> Self {
        let mut text = String::new();
        let mut positions = Vec::new();
        for row in 0..rows {
            let mut space = !text.is_empty();
            for col in start..end {
                let Some(cell) = screen.cell(row, col) else {
                    continue;
                };
                if cell.is_wide_continuation() {
                    continue;
                }
                let glyph = cell.contents();
                if glyph.trim().is_empty() {
                    space = !text.is_empty();
                    continue;
                }
                if space {
                    text.push(' ');
                    positions.push((row, col));
                    space = false;
                }
                text.push_str(glyph);
                positions.extend(std::iter::repeat_n((row, col), glyph.len()));
            }
        }
        Self { text, positions }
    }

    fn position(&self, label: &str) -> Option<(u16, u16)> {
        self.positions.get(self.text.find(label)?).copied()
    }

    fn fingerprint(&self, screen: &vt100::Screen, label: &str) -> Option<String> {
        let (row, col) = self.position(label)?;
        let cell = screen.cell(row, col)?;
        Some(format!(
            "fg={:?};bg={:?};bold={}",
            cell.fgcolor(),
            cell.bgcolor(),
            cell.bold()
        ))
    }
}

fn inspect_review(
    tui: &mut TuiPty,
    fixture: &StateFixture,
) -> Result<(String, SurfaceFingerprints), String> {
    let modal = if fixture.name == "awaiting-decision" {
        "awaiting decision"
    } else {
        "awaiting permission"
    };
    let mut surfaces: [Option<String>; 5] = Default::default();
    let mut text = String::new();
    for _ in 0..32 {
        let raw = tui.bytes()?;
        let mut parser = vt100::Parser::new(tui.rows, tui.cols, 0);
        parser.process(&raw);
        let screen = parser.screen();
        let full = PaintedRegion::read(screen, tui.rows, 0, tui.cols);
        // Review reserves one outer padding cell and one scrollbar cell. Its thumb is not a transcript glyph.
        let content_end = tui.cols.saturating_sub(2);
        let body_start = if tui.cols < 64 { 0 } else { 27 };
        let left_end = if body_start == 0 {
            content_end
        } else {
            body_start
        };
        let left = PaintedRegion::read(screen, tui.rows, 0, left_end);
        let body = PaintedRegion::read(screen, tui.rows, body_start, content_end);
        // The composer is pinned directly above the review help; a focused option can also start with '>'.
        let composer = format!("{} Review · Esc closes", fixture.composer_label);
        for (index, (region, label)) in [
            (&full, STATUS),
            (&left, &fixture.dock_probe),
            (&body, &fixture.transcript_probe),
            (&full, composer.as_str()),
            (&body, modal),
        ]
        .into_iter()
        .enumerate()
        {
            if surfaces[index].is_none() {
                surfaces[index] = region.fingerprint(screen, label);
            }
        }
        if !fixture.modal
            && ["awaiting decision", "awaiting permission"]
                .iter()
                .any(|label| body.text.contains(*label))
        {
            return Err(format!(
                "{} paints an unexpected modal: {}",
                fixture.name, body.text
            ));
        }
        for region in [&full, &left, &body] {
            text.push('\n');
            text.push_str(&region.text);
        }
        if fixture.needles.iter().all(|&needle| text.contains(needle))
            && surfaces[..4].iter().all(Option::is_some)
            && (!fixture.modal || surfaces[4].is_some())
        {
            let [status, dock, transcript, composer, modal] = surfaces;
            return Ok((
                text,
                SurfaceFingerprints {
                    status: status.expect("status"),
                    dock: dock.expect("dock"),
                    composer: composer.expect("composer"),
                    transcript: transcript.expect("transcript"),
                    modal: if fixture.modal {
                        modal.expect("modal")
                    } else {
                        "none".into()
                    },
                },
            ));
        }
        let mark = raw.len();
        tui.send(b"\x1b[6~")?;
        if tui
            .wait_settled_after("Review · Esc closes", mark, WAIT)
            .is_err()
        {
            break;
        }
    }
    Err(format!(
        "{} missing labels {:?}, surface samples {:?}; painted: {text}",
        fixture.name,
        fixture
            .needles
            .iter()
            .filter(|needle| !text.contains(**needle))
            .collect::<Vec<_>>(),
        surfaces
    ))
}

/// One packaged `--ui-review` run: environment in, final screen plus
/// fingerprints and emitted bytes out.
fn review_frame(
    fixture: &StateFixture,
    geometry: Geometry,
    env: &[(&str, &str)],
    label: &str,
) -> Result<ReviewFrame, String> {
    let mut tui = TuiPty::spawn_review(geometry, fixture.name, env)?;
    tui.wait_settled_after(STATUS, 0, WAIT)?;
    if geometry == Geometry::LiveResize {
        for (rows, cols) in [(40, 120), (20, 60)] {
            let mark = tui.bytes()?.len();
            tui.resize(rows, cols)?;
            tui.wait_settled_after(STATUS, mark, LIVE_RESIZE_WAIT)?;
        }
    }
    let (text, fingerprints) = inspect_review(&mut tui, fixture)?;
    tui.send(b"\x1b")?;
    let (bytes, code, data_root_opened) = tui.finish_review()?;
    if code != Some(0) {
        return Err(format!("{label} review exit {code:?}"));
    }
    if data_root_opened {
        return Err(format!("{label} review opened a data root"));
    }
    require_fullscreen_restore(&bytes)?;
    Ok(ReviewFrame {
        text,
        fingerprints,
        bytes,
    })
}

/// Renders one state in the default environment and returns its squashed
/// screen text; that text is the control every theme render must reproduce.
fn render_state(fixture: &StateFixture, geometry: Geometry) -> Result<String, String> {
    review_frame(fixture, geometry, &[], "state").map(|frame| frame.text)
}

/// One themed render: it must paint the same text as the default control and
/// every carrier must match the pinned token for its theme and surface.
fn observe_theme(
    state_index: usize,
    geometry: Geometry,
    theme: &'static str,
    control: &Result<String, String>,
) -> Result<ThemeObservation, String> {
    let control = control
        .as_ref()
        .map_err(|error| format!("control failed: {error}"))?;
    let fixture = state_fixture(state_index);
    let frame = review_frame(
        &fixture,
        geometry,
        &[("TERM", "xterm-256color"), ("RIVECT_THEME", theme)],
        theme,
    )?;
    if &frame.text != control {
        return Err(format!(
            "{theme} text differs from the default control: {:?} != {control:?}",
            frame.text
        ));
    }
    if !has_color_sgr(&frame.bytes) {
        return Err(format!("{theme} emitted no SGR color"));
    }
    for surface in ["status", "dock", "composer", "transcript"] {
        let expected = expected_fingerprint(theme, surface);
        let observed = frame.fingerprints.surface(surface);
        if observed != expected {
            return Err(format!(
                "{theme} {surface} fingerprint {observed:?} != expected {expected:?}"
            ));
        }
    }
    if fixture.modal {
        let expected = expected_fingerprint(theme, "modal");
        let observed = frame.fingerprints.modal.as_str();
        if observed != expected {
            return Err(format!(
                "{theme} modal fingerprint {observed:?} != expected {expected:?}"
            ));
        }
    } else if frame.fingerprints.modal != "none" {
        return Err(format!(
            "{theme} paints a modal in a state with none: {:?}",
            frame.fingerprints.modal
        ));
    }
    Ok(ThemeObservation {
        state: fixture.name,
        geometry: geometry.label(),
        theme,
        fingerprints: frame.fingerprints,
    })
}

/// The mono proof for one state, geometry and selected theme: `NO_COLOR`
/// strips every SGR color while the status token, dock row and composer row
/// stay verbatim; high contrast keeps its bold modifier.
fn mono_probe(
    fixture: &StateFixture,
    geometry: Geometry,
    theme: &'static str,
) -> Result<(), String> {
    let frame = review_frame(
        fixture,
        geometry,
        &[
            ("TERM", "xterm-256color"),
            ("NO_COLOR", "1"),
            ("RIVECT_THEME", theme),
        ],
        "mono",
    )?;
    if has_color_sgr(&frame.bytes) {
        return Err(format!("{theme} mono emitted an SGR color"));
    }
    if !frame.text.contains(STATUS) {
        return Err(format!("{theme} mono lost the status token {:?}", STATUS));
    }
    if !frame.text.contains(&support::squashed(&fixture.dock_probe)) {
        return Err(format!(
            "{theme} mono lost the dock row {:?}",
            fixture.dock_probe
        ));
    }
    if !frame
        .text
        .contains(&format!("{} Review · Esc closes", fixture.composer_label))
    {
        return Err(format!(
            "mono lost composer label {:?}",
            fixture.composer_label
        ));
    }
    let bold = theme == "high-contrast";
    for surface in ["status", "dock", "composer", "transcript"] {
        let expected = if bold {
            "fg=Default;bg=Default;bold=true"
        } else {
            "fg=Default;bg=Default;bold=false"
        };
        if frame.fingerprints.surface(surface) != expected {
            return Err(format!(
                "{theme} mono {surface} fingerprint {:?} != {expected:?}",
                frame.fingerprints.surface(surface)
            ));
        }
    }
    if fixture.modal {
        let expected = if bold {
            "fg=Default;bg=Default;bold=true"
        } else {
            "fg=Default;bg=Default;bold=false"
        };
        if frame.fingerprints.modal != expected {
            return Err(format!(
                "{theme} mono modal fingerprint {:?} != {expected:?}",
                frame.fingerprints.modal
            ));
        }
    }
    Ok(())
}

/// The per-state `TERM=dumb` label proof: no color, and the status/dock/
/// composer text still arrives verbatim.
fn dumb_probe(fixture: &StateFixture) -> Result<(), String> {
    let frame = review_frame(fixture, Geometry::W80H24, &[("TERM", "dumb")], "dumb")?;
    if has_color_sgr(&frame.bytes) {
        return Err("TERM=dumb emitted an SGR color".to_string());
    }
    if !frame.text.contains(STATUS) {
        return Err(format!("TERM=dumb lost the status token {:?}", STATUS));
    }
    if !frame.text.contains(&support::squashed(&fixture.dock_probe)) {
        return Err(format!(
            "TERM=dumb lost the dock row {:?}",
            fixture.dock_probe
        ));
    }
    if !frame
        .text
        .contains(&format!("{} Review · Esc closes", fixture.composer_label))
    {
        return Err(format!(
            "TERM=dumb lost composer label {:?}",
            fixture.composer_label
        ));
    }
    Ok(())
}

/// The theme input probes run one representative state; the per-state
/// observations carry the full 19×G×3 matrix.
fn palette_probe(geometry: Geometry, theme: &'static str) -> Result<(), String> {
    let fixture = state_fixture(2);
    let frame = review_frame(
        &fixture,
        geometry,
        &[("TERM", "xterm-256color"), ("RIVECT_THEME", theme)],
        theme,
    )?;
    if !has_color_sgr(&frame.bytes) {
        return Err(format!("{theme} emitted no SGR color"));
    }
    if !frame.text.contains(STATUS) {
        return Err(format!("{theme} lost the status token"));
    }
    if frame.fingerprints.surface("status") != expected_fingerprint(theme, "status") {
        return Err(format!(
            "{theme} status fingerprint {:?} != expected",
            frame.fingerprints.status
        ));
    }
    Ok(())
}

fn no_color_probe(geometry: Geometry) -> Result<(), String> {
    let fixture = state_fixture(2);
    let frame = review_frame(
        &fixture,
        geometry,
        &[("TERM", "xterm-256color"), ("NO_COLOR", "1")],
        "no-color",
    )?;
    if has_color_sgr(&frame.bytes) {
        return Err("NO_COLOR emitted an SGR color".to_string());
    }
    if !frame.text.contains(STATUS) {
        return Err("NO_COLOR lost the status token".to_string());
    }
    Ok(())
}

fn inline_fingerprint(tui: &TuiPty, bytes: &[u8], label: &str) -> Result<String, String> {
    let mut parser = vt100::Parser::new(tui.rows, tui.cols, 0);
    parser.process(bytes);
    PaintedRegion::read(parser.screen(), tui.rows, 0, tui.cols)
        .fingerprint(parser.screen(), label)
        .ok_or_else(|| {
            format!(
                "inline has no painted {label:?}:\n{}",
                parser.screen().contents()
            )
        })
}

/// Pin all five inline colors to text painted by the installed client.
fn inline_theme_probe(theme: &'static str) -> Result<(), String> {
    let mut tui = TuiPty::spawn(
        Geometry::W80H24,
        Some(RenderMode::Inline),
        &[("TERM", "xterm-256color"), ("RIVECT_THEME", theme)],
    )?;
    tui.wait("Message", WAIT)?;
    let mark = tui.bytes()?.len();
    tui.send(b"/help\r")?;
    tui.wait_settled_after("Status: Commands: Enter submits", mark, WAIT)?;
    let bytes = tui.bytes()?;
    // The live dock is secondary text and the live composer is always bold;
    // their fingerprints are pinned separately from the frozen review.
    let (dock, composer) = match theme {
        "light" => (
            "fg=Idx(4);bg=Default;bold=false",
            "fg=Idx(5);bg=Default;bold=true",
        ),
        "dark" => (
            "fg=Idx(6);bg=Default;bold=false",
            "fg=Idx(13);bg=Default;bold=true",
        ),
        "high-contrast" => (
            "fg=Idx(11);bg=Default;bold=true",
            "fg=Idx(14);bg=Default;bold=true",
        ),
        _ => return Err(format!("unknown inline theme {theme}")),
    };
    for (surface, needle, expected) in [
        (
            "status",
            "No processes",
            expected_fingerprint(theme, "status"),
        ),
        ("dock", "/accounting Session not connected", dock),
        ("composer", "Message → Main", composer),
        (
            "transcript",
            "Status: Commands: Enter submits",
            expected_fingerprint(theme, "transcript"),
        ),
    ] {
        let observed = inline_fingerprint(&tui, &bytes, needle)?;
        if observed != expected {
            return Err(format!(
                "inline {theme} {surface} fingerprint {observed:?} != {expected:?}"
            ));
        }
    }
    // A production decision title supplies the modal sample.
    let mark = tui.bytes()?.len();
    tui.send(b"/task inline palette probe\r")?;
    tui.wait_settled_after("focus 1/2", mark, WAIT)?;
    let observed = inline_fingerprint(&tui, &tui.bytes()?, "awaiting decision")?;
    let expected = expected_fingerprint(theme, "modal");
    if observed != expected {
        return Err(format!(
            "inline {theme} modal fingerprint {observed:?} != {expected:?}"
        ));
    }
    // The card refuses a key inside its consent floor (the first paint starts
    // a short clock); wait it out before dismissing.
    tui.pump(Duration::from_millis(400))?;
    tui.send_card_key(b"\x1b", DECISION_UNANSWERED, WAIT)?;
    tui.send(b"\x1b")?;
    let (bytes, code) = tui.finish()?;
    if code != Some(0) {
        return Err(format!("inline {theme} exit {code:?}"));
    }
    require_inline_restore(&bytes)
}

#[test]
#[ignore = "focused palette proof; every role also runs in the installed matrix"]
fn installed_inline_text_uses_fullscreen_palette_roles() {
    for theme in THEMES {
        inline_theme_probe(theme).expect("five colored inline text roles");
    }
    for geometry in Geometry::ALL {
        input_probe(InputMode::Plain, geometry).expect("plain inline text has no colors");
    }
}

fn has_color_sgr(bytes: &[u8]) -> bool {
    first_color_sgr(bytes).is_some()
}

fn first_color_sgr(bytes: &[u8]) -> Option<std::ops::Range<usize>> {
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
            for part in bytes[start..end].split(|byte| matches!(*byte, b';' | b':')) {
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
                    return Some(start - 2..end + 1);
                }
            }
        }
        offset = start;
    }
    None
}

#[test]
fn color_sgr_reports_first_explicit_color_after_terminal_controls() {
    let prefix = b"\x1b[0m\x1b[1m\x1b[39m\x1b[49m\x1b[>4;1m\x1b[40;1H";
    assert_eq!(first_color_sgr(prefix), None);
    let color = b"\x1b[1;38;5;13m";
    let bytes = [prefix.as_slice(), color, b"\x1b[48:2::10:20:30m"].concat();
    assert_eq!(
        first_color_sgr(&bytes),
        Some(prefix.len()..prefix.len() + color.len())
    );
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
    /// A deaf terminal reads cursor queries and drops them; the live
    /// waits keep pumping but never reply, like a real dumb emulator.
    deaf: bool,
}

impl TuiPty {
    fn spawn(
        geometry: Geometry,
        mode: Option<RenderMode>,
        env: &[(&str, &str)],
    ) -> Result<Self, String> {
        Self::spawn_with_config(geometry, mode, env, None)
    }

    fn spawn_with_config(
        geometry: Geometry,
        mode: Option<RenderMode>,
        env: &[(&str, &str)],
        config: Option<&str>,
    ) -> Result<Self, String> {
        let root = tempfile::TempDir::with_prefix("rivect-installed-tui-")
            .map_err(|error| format!("tui root: {error}"))?;
        let data = root.path().join("data");
        std::fs::create_dir_all(&data).map_err(|error| format!("data root: {error}"))?;
        if let Some(text) = config {
            std::fs::write(data.join("config.toml"), text).map_err(|e| e.to_string())?;
        }
        Self::spawn_at(geometry, mode, env, root, data)
    }

    fn spawn_at(
        geometry: Geometry,
        mode: Option<RenderMode>,
        env: &[(&str, &str)],
        root: tempfile::TempDir,
        data: PathBuf,
    ) -> Result<Self, String> {
        let bundle = support::release::baseline_bundle();
        let (cols, rows) = geometry.size();
        let mut command = support::pty_command(bundle.join("rivect"));
        command.env("HOME", root.path());
        command.env("TMPDIR", root.path());
        command.env("TERM", "xterm-256color");
        command.cwd(root.path());
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
            deaf: false,
        })
    }

    fn spawn_review(geometry: Geometry, state: &str, env: &[(&str, &str)]) -> Result<Self, String> {
        let bundle = support::release::baseline_bundle();
        let root = tempfile::TempDir::with_prefix("rivect-installed-review-")
            .map_err(|error| format!("review root: {error}"))?;
        let data = root.path().join("data");
        let (cols, rows) = geometry.size();
        let mut command = support::pty_command(bundle.join("rivect"));
        command.env("HOME", root.path());
        command.env("TMPDIR", root.path());
        command.env("TERM", "xterm-256color");
        command.cwd(root.path());
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
            deaf: false,
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
        if self.deaf {
            // The query is read and dropped; the mark moves past it so no
            // later path answers it out of time.
            self.cursor_at = bytes.len();
            return Ok(());
        }
        if let Some(reply) = support::cursor_query_reply(&mut self.cursor_at, &bytes) {
            self.pty
                .send(reply)
                .map_err(|error| format!("pty send: {error}"))?;
            if support::trace_enabled() {
                eprintln!("[cursor-trace {:?}] answered ESC[1;1R", support::trace_at());
            }
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
                if support::trace_enabled() {
                    let text = String::from_utf8_lossy(&bytes);
                    eprintln!(
                        "[cursor-trace {:?}] timeout for {needle:?}; cleanup-report={} alt-in={} alt-out={} cursor_at={}",
                        support::trace_at(),
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

    /// Waits until bytes beyond `mark` arrived (the resize redraw started), the
    /// needle is on screen, and the whole squashed screen has held identical
    /// for three consecutive reads. A resize capture never records a partially
    /// repainted or pre-resize frame.
    fn wait_settled_after(
        &mut self,
        needle: &str,
        mark: usize,
        timeout: Duration,
    ) -> Result<String, String> {
        let deadline = Instant::now() + timeout;
        let needle = support::squashed(needle);
        let mut previous: Option<String> = None;
        let mut stable = 0usize;
        loop {
            self.answer_cursor_query()?;
            let bytes = self.bytes()?;
            let screen = self.screen(&bytes);
            let squashed = support::squashed(&screen);
            if bytes.len() > mark && squashed.contains(&needle) {
                if previous.as_deref() == Some(squashed.as_str()) {
                    stable += 1;
                    if stable >= 2 {
                        return Ok(screen);
                    }
                } else {
                    stable = 0;
                }
                previous = Some(squashed);
            } else {
                stable = 0;
                previous = None;
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "timeout waiting for a settled {needle:?}; last screen:\n{screen}"
                ));
            }
            self.pty
                .pump_for(Duration::from_millis(25))
                .map_err(|error| format!("pty pump: {error}"))?;
        }
    }

    /// A card key can be eaten by the first-paint drain when load delays the
    /// drain past the visible paint: resend until the effect lands, while the
    /// card is still open, inside one real deadline. The attempt window is
    /// generous so a landed key's frame arrives before any resend — a stray
    /// Esc outside the card would quit the TUI.
    fn send_card_key(
        &mut self,
        key: &[u8],
        effect: &str,
        timeout: Duration,
    ) -> Result<String, String> {
        let deadline = Instant::now() + timeout;
        loop {
            self.send(key)?;
            let window =
                Duration::from_secs(5).min(deadline.saturating_duration_since(Instant::now()));
            match self.wait(effect, window) {
                Ok(screen) => return Ok(screen),
                Err(error) => {
                    let screen = support::squashed(&self.screen(&self.bytes()?));
                    if Instant::now() >= deadline || !screen.contains("focus") {
                        return Err(error);
                    }
                }
            }
        }
    }

    fn send(&mut self, bytes: &[u8]) -> Result<(), String> {
        if support::trace_enabled() {
            eprintln!(
                "[cursor-trace {:?}] send {:?}",
                support::trace_at(),
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

    /// The exit wait plays terminal too: a child that asks for the cursor
    /// position while leaving gets the same answer the live waits give.
    fn wait_exit_answering(&mut self) -> Result<Option<u32>, String> {
        let cursor_at = &mut self.cursor_at;
        self.pty
            .wait_exit_answering(WAIT, move |bytes| {
                support::cursor_query_reply(cursor_at, bytes)
            })
            .map_err(|error| format!("pty wait: {error}"))
    }

    fn finish_review(mut self) -> Result<(Vec<u8>, Option<u32>, bool), String> {
        let code = self.wait_exit_answering()?;
        let data_root_opened = self.pty.data_root().exists();
        let bytes = self.bytes()?;
        self.pty
            .finish()
            .map_err(|error| format!("pty teardown: {error}"))?;
        Ok((bytes, code, data_root_opened))
    }

    fn finish(mut self) -> Result<(Vec<u8>, Option<u32>), String> {
        let code = self.wait_exit_answering()?;
        let bytes = self.bytes()?;
        self.pty
            .finish()
            .map_err(|error| format!("pty teardown: {error}"))?;
        Ok((bytes, code))
    }
}

const CONTEXT_WARNING: &str = "% full (auto-compact off)";
const NOT_SHORTER: &str = "compaction would not shorten the history";
// Longer than the one-second remeasurement backstop and two dock refreshes.
const CONTEXT_BEATS: Duration = Duration::from_secs(2);

struct ContextFixture {
    root: tempfile::TempDir,
    session: SessionId,
}

impl ContextFixture {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("context data root");
        std::fs::create_dir(root.path().join("runtime")).expect("owner directory");
        let config = format!(
            "{}\n[context]\nauto_compact = false\n",
            support::base_config()
        );
        std::fs::write(root.path().join("config.toml"), config).expect("explicit context guard");
        let mut store =
            TaskStore::open(&root.path().join("runtime/rivect.db")).expect("open store");
        let (session, _, _, _) = store
            .open_session("context-seed", "installed", None)
            .expect("open session");
        Self { root, session }
    }

    // Only call between installed clients: the owner admits one writer.
    fn detached(&self) -> TaskStore {
        TaskStore::open(&self.root.path().join("runtime/rivect.db")).expect("detached task store")
    }

    fn task(&self, goal: &str) -> TaskId {
        self.detached()
            .create_task(
                &self.session,
                goal,
                "installed",
                goal,
                (&["read the rollout notes".to_owned()], &[]),
            )
            .expect("create context task")
            .task_id
    }

    fn fill(&self, task: &TaskId) -> (usize, [u8; 32]) {
        let mut store = self.detached();
        store
            .materialize_obligations(task)
            .expect("materialize criterion");
        let scope = format!("task:{}", task.0);
        let text = "a scoped line of the file ".repeat(1800);
        for index in 0..18 {
            let observation = format!("record {index:02}: {text}");
            let digest = format!("{:x}", Sha256::digest(observation.as_bytes()));
            store
                .insert_evidence(task, 0, &scope, &observation, &digest)
                .expect("store evidence");
        }
        let stamp = context_stamp(&store, task);
        assert!(
            stamp.0 * 100 / MODEL_WIRE_MAX_BYTES >= 80,
            "seed must independently earn a warning"
        );
        stamp
    }

    fn attach(&self, geometry: Geometry) -> TuiPty {
        let root = tempfile::tempdir().expect("isolated PTY home");
        let mut tui = TuiPty::spawn_at(
            geometry,
            Some(RenderMode::Fullscreen),
            &[],
            root,
            self.root.path().to_owned(),
        )
        .expect("installed context PTY");
        tui.wait("Message → Main", WAIT).expect("thread is ready");
        tui.send(format!("/resume {}\r", self.session.0).as_bytes())
            .expect("attach seeded session");
        tui
    }
}

fn context_stamp(store: &TaskStore, task: &TaskId) -> (usize, [u8; 32]) {
    let context = store
        .assembled_context(task)
        .expect("owner assembles context");
    (
        context.text.len(),
        Sha256::digest(context.text.as_bytes()).into(),
    )
}

fn detach_context(mut tui: TuiPty) {
    tui.send(b"/exit\r").expect("leave thread");
    let (bytes, code) = tui.finish().expect("reap installed owner");
    assert_eq!(code, Some(0));
    require_fullscreen_restore(&bytes).expect("restored PTY");
}

fn warning_line(frame: &str) -> &str {
    frame
        .lines()
        .find(|row| row.contains(CONTEXT_WARNING))
        .expect("one painted warning row")
}

fn context_frame_without(tui: &mut TuiPty, present: &str, absent: &str) -> String {
    let deadline = Instant::now() + WAIT;
    loop {
        let frame = tui.screen(&tui.bytes().expect("terminal bytes"));
        if support::squashed(&frame).contains(present) && !frame.contains(absent) {
            return frame;
        }
        assert!(
            Instant::now() < deadline,
            "expected {present:?} without {absent:?}: {frame}"
        );
        tui.pump(Duration::from_millis(25))
            .expect("next owner frame");
    }
}

fn quiet_context(tui: &mut TuiPty, witness: &str) {
    // Task IDs and the hidden count now live in the explicit accounting view.
    tui.wait("/accounting context", WAIT)
        .expect("owner measurement ready");
    tui.send(b"/accounting\r").expect("open full accounting");
    context_frame_without(tui, witness, CONTEXT_WARNING);
    tui.pump(CONTEXT_BEATS).expect("repeated measurements");
    let frame = tui.screen(&tui.bytes().expect("terminal bytes"));
    assert!(
        support::squashed(&frame).contains(witness) && !frame.contains(CONTEXT_WARNING),
        "{frame}"
    );
}

fn toggle_context_guard(tui: &mut TuiPty, previous: bool) {
    tui.send(b"/settings\r").expect("settings");
    tui.wait("context.auto_compact", WAIT)
        .expect("settings loaded");
    tui.send(b"/").expect("search");
    tui.wait("Search settings", WAIT).expect("search input");
    tui.send(b"context.auto_compact\r").expect("find guard");
    tui.wait("1 result", WAIT).expect("filtered guard");
    tui.wait(&format!("context.auto_compact = {previous}"), WAIT)
        .expect("effective guard");
    tui.send(b" ").expect("preview opposite value");
    tui.wait("Confirm change", WAIT)
        .expect("real settings proposal");
    tui.send(b"y").expect("confirm guard edit");
    tui.wait("Saved to user config", WAIT)
        .expect("owner published setting");
    tui.send(b"\x1b").expect("close settings");
    context_frame_without(tui, "Message → Main", "Settings Center");
}

fn dismiss_context_question(tui: &mut TuiPty) -> String {
    tui.wait("focus 1/2", WAIT).expect("real pending question");
    tui.send_card_key(b"\x1b", DECISION_UNANSWERED, WAIT)
        .expect("pending question dismissed")
}

#[test]
fn installed_context_warning_tracks_setting_without_rewriting_bytes_p1_p3() {
    let fixture = ContextFixture::new();
    let task = fixture.task("context guard check");
    let dock = format!("task {}:", task.0);
    assert!(context_stamp(&fixture.detached(), &task).0 * 100 / MODEL_WIRE_MAX_BYTES < 80);
    let mut tui = fixture.attach(Geometry::W80H24);
    quiet_context(&mut tui, &dock);
    detach_context(tui);

    let before = fixture.fill(&task);
    let mut tui = fixture.attach(Geometry::W80H24);
    let expected = format!(
        "{}{}",
        before.0 * 100 / MODEL_WIRE_MAX_BYTES,
        CONTEXT_WARNING
    );
    tui.wait(&expected, WAIT).expect("owner measurement paints");
    toggle_context_guard(&mut tui, false);
    quiet_context(&mut tui, &dock);
    toggle_context_guard(&mut tui, true);
    tui.wait(&expected, WAIT)
        .expect("unchanged full context warns again");
    tui.pump(CONTEXT_BEATS).expect("further measurement beats");
    tui.send(b"/rewind\r").expect("preview live owner context");
    let measured = tui
        .wait(&format!("{} assembled bytes", before.0), WAIT)
        .expect("owner reports same length");
    assert!(warning_line(&measured).contains(&expected));
    detach_context(tui);
    assert_eq!(
        context_stamp(&fixture.detached(), &task),
        before,
        "paint must preserve length and SHA-256"
    );
}

#[test]
fn installed_printed_compact_command_folds_and_clears_only_warning_p2_p8() {
    let fixture = ContextFixture::new();
    let task = fixture.task("compact this conversation");
    let before = fixture.fill(&task);
    let mut tui = fixture.attach(Geometry::W80H24);
    let warned = tui.wait(CONTEXT_WARNING, WAIT).expect("full context warns");
    let token = warning_line(&warned)
        .split_whitespace()
        .find(|word| word.starts_with('/'))
        .expect("printed continuation");
    tui.send(format!("{token}\r").as_bytes())
        .expect("submit exactly the offered command");
    tui.wait(&format!("Context compacted: {}", before.0), WAIT)
        .expect("owner's accepted fold");
    quiet_context(&mut tui, &format!("task {}:", task.0));
    detach_context(tui);
    let after = context_stamp(&fixture.detached(), &task);
    assert!(after.0 < before.0 && after.0 * 100 / MODEL_WIRE_MAX_BYTES < 80);
}

#[test]
fn installed_empty_compact_has_no_wire_field() {
    let fixture = ContextFixture::new();
    let mut tui = fixture.attach(Geometry::W80H24);
    tui.wait("Resumed session:", WAIT)
        .expect("attached empty session");
    tui.send(b"/compact\r").expect("empty compaction");
    let frame = tui
        .wait("No conversation to compact yet; submit a task first.", WAIT)
        .expect("plain note");
    assert!(!frame.contains("task_id"));
    detach_context(tui);
    assert!(
        fixture
            .detached()
            .projection_page(&fixture.session, None)
            .expect("empty session")
            .0
            .is_empty()
    );
}

#[test]
fn installed_compact_targets_newest_recovered_conversation_p10() {
    let fixture = ContextFixture::new();
    let older = fixture.task("settled rollout");
    fixture.fill(&older);
    let completed = fixture
        .detached()
        .complete_if_eligible(&fixture.session, &older)
        .expect("settle older task");
    assert_eq!(completed.lifecycle, Lifecycle::Completed);
    let older_before = context_stamp(&fixture.detached(), &older);
    assert!(older_before.0 * 100 / MODEL_WIRE_MAX_BYTES >= 80);
    let newer = fixture.task("newer rollout");
    let mut tui = fixture.attach(Geometry::W120H40);
    quiet_context(&mut tui, &format!("task {}:", newer.0));
    detach_context(tui);

    let before = fixture.fill(&newer);
    let mut tui = fixture.attach(Geometry::W160H50);
    tui.wait(CONTEXT_WARNING, WAIT)
        .expect("full newer conversation");
    let frame = tui
        .wait(&format!("task {}", newer.0), WAIT)
        .expect("fully painted context warning");
    let warning = warning_line(&frame);
    assert!(
        warning.contains(&format!("task {}", newer.0)) && !warning.contains(&older.0),
        "{warning}"
    );
    tui.send(b"/compact\r").expect("fold named task");
    tui.wait(&format!("Context compacted: {}", before.0), WAIT)
        .expect("named task's fold");
    quiet_context(&mut tui, &format!("task {}:", newer.0));
    detach_context(tui);
    let store = fixture.detached();
    assert!(context_stamp(&store, &newer).0 < before.0);
    assert_eq!(
        context_stamp(&store, &older),
        older_before,
        "older bytes unchanged"
    );
}

#[test]
fn installed_compact_retains_pending_subject_and_serves_input_after_refusal_p4_p10() {
    let fixture = ContextFixture::new();
    let mut tui = fixture.attach(Geometry::W120H40);
    tui.wait("Resumed session:", WAIT)
        .expect("attached session");
    tui.send(b"/task ledger\r")
        .expect("composer submits pending task");
    let card = tui
        .wait("focus 1/2", WAIT)
        .expect("accepted task has a question");
    let id = card
        .lines()
        .find_map(|row| row.split_once("task: "))
        .and_then(|(_, tail)| tail.split_whitespace().next())
        .expect("visible task identity");
    let pending = TaskId(id.to_owned());
    dismiss_context_question(&mut tui);
    tui.send(b"/compact\r")
        .expect("request fold on empty history");
    tui.wait(NOT_SHORTER, WAIT)
        .expect("owner's typed refusal is painted");
    tui.send(b"/help\r").expect("composer still serves input");
    tui.wait("Commands: Enter submits", WAIT)
        .expect("help after refusal");
    detach_context(tui);

    let pending_before = {
        let store = fixture.detached();
        assert_eq!(
            store
                .snapshot(&pending)
                .expect("composer receipt")
                .lifecycle,
            Lifecycle::Waiting
        );
        let stamp = context_stamp(&store, &pending);
        assert!(stamp.0 * 100 / MODEL_WIRE_MAX_BYTES < 80);
        stamp
    };
    let last = fixture.task("full conversation behind pending ledger");
    let last_before = fixture.fill(&last);
    let page = fixture
        .detached()
        .projection_page(&fixture.session, None)
        .expect("owner task order");
    assert!(!page.1 && page.0.len() == 2);
    assert_eq!(
        page.0[0].task_id, last,
        "newest durable row is independently full"
    );
    assert_eq!(page.0[1].task_id, pending);
    let mut tui = fixture.attach(Geometry::W120H40);
    let restored = tui
        .wait("focus 1/2", WAIT)
        .expect("reattached pending question");
    assert!(restored.contains(&format!("task: {}", pending.0)));
    dismiss_context_question(&mut tui);
    quiet_context(&mut tui, &format!("task {}:", last.0));
    tui.send(b"/compact\r")
        .expect("fold should follow pending, not newest");
    tui.wait(NOT_SHORTER, WAIT)
        .expect("pending history refused, newer one not folded");
    detach_context(tui);
    let store = fixture.detached();
    assert_eq!(
        context_stamp(&store, &last),
        last_before,
        "newest bytes and digest unchanged"
    );
    assert_eq!(
        context_stamp(&store, &pending),
        pending_before,
        "refusal changed pending bytes"
    );
}

fn transcript_band(tui: &mut TuiPty, entries: usize) -> usize {
    let first = "context transcript line 01";
    let last = format!("context transcript line {entries:02}");
    // Both ends exist, but don't fit together. Compare unique durable rows, not repeated labels.
    tui.wait("Resumed session:", WAIT)
        .expect("thread page loaded");
    tui.send(&b"\x1b[6~".repeat(30)).expect("scroll to newest");
    let bottom = tui.wait(&last, WAIT).expect("newest transcript row");
    assert!(
        !bottom.contains(first),
        "transcript must extend beyond viewport"
    );
    let mark = tui.bytes().expect("before page up").len();
    tui.send(&b"\x1b[5~".repeat(30)).expect("scroll to oldest");
    let top = tui
        .wait_settled_after(first, mark, WAIT)
        .expect("oldest transcript row");
    assert!(
        !top.contains(&last),
        "newest entry really scrolled offscreen"
    );
    let band = (1..=entries)
        .filter(|n| top.contains(&format!("context transcript line {n:02}")))
        .count();
    assert!(
        (1..entries).contains(&band),
        "only part of the transcript fits: {band}/{entries}"
    );
    band
}

#[test]
fn installed_context_warning_survives_overflow_and_fits_60_columns_p9() {
    let fixture = ContextFixture::new();
    for n in 1..=13 {
        fixture.task(&format!("context transcript line {n:02}"));
    }
    let mut tui = fixture.attach(Geometry::W80H24);
    let band = transcript_band(&mut tui, 13);
    detach_context(tui);
    for n in 14..=18 {
        fixture.task(&format!("context transcript line {n:02}"));
    }
    let last = fixture.task("context transcript line 19");
    let mut tui = fixture.attach(Geometry::W80H24);
    assert_eq!(
        transcript_band(&mut tui, 19),
        band,
        "six more entries cannot grow the visible band"
    );
    detach_context(tui);
    fixture.fill(&last);
    let mut tui = fixture.attach(Geometry::W80H24);
    tui.wait(CONTEXT_WARNING, WAIT)
        .expect("warning above overfull transcript");
    transcript_band(&mut tui, 19);
    let frame = tui.screen(&tui.bytes().expect("scrolled frame"));
    assert!(warning_line(&frame).contains("/compact"));
    tui.send(&b"\x1b[6~".repeat(30))
        .expect("scroll to newest before opening accounting");
    tui.wait("context transcript line 19", WAIT)
        .expect("newest row visible");
    toggle_context_guard(&mut tui, false);
    quiet_context(&mut tui, "+17 more");
    toggle_context_guard(&mut tui, true);
    tui.wait(CONTEXT_WARNING, WAIT)
        .expect("warning restored on long thread");
    detach_context(tui);

    let mut tui = fixture.attach(Geometry::W60H20);
    let warned = tui.wait(CONTEXT_WARNING, WAIT).expect("narrow warning");
    assert!(
        warning_line(&warned).trim_end().ends_with("/compact"),
        "{warned}"
    );
    let data = tui.pty.data_root().clone();
    support::with_unavailable_evidence(&data, || {
        let frame = tui
            .wait("dock refresh failed:", WAIT)
            .expect("actual failed dock poll");
        let (warning, row) = frame
            .lines()
            .enumerate()
            .find(|(_, row)| row.contains(CONTEXT_WARNING))
            .expect("failed poll must retain warning");
        let mark = frame
            .lines()
            .position(|row| row.contains("dock refresh failed:"))
            .expect("fault mark");
        assert!(row.trim_end().ends_with("/compact"), "{frame}");
        assert_ne!(warning, mark, "two independent notices need two rows");
    });
    let recovered = context_frame_without(&mut tui, CONTEXT_WARNING, "dock refresh failed:");
    assert!(warning_line(&recovered).trim_end().ends_with("/compact"));
    detach_context(tui);
}

fn exercise_resize(tui: &mut TuiPty, geometry: Geometry) -> Result<(), String> {
    if geometry != Geometry::LiveResize {
        return Ok(());
    }
    for (rows, cols) in [(40, 120), (20, 60)] {
        let mark = tui.bytes()?.len();
        tui.resize(rows, cols)?;
        tui.wait_settled_after("Message", mark, LIVE_RESIZE_WAIT)?;
    }
    Ok(())
}

#[test]
#[ignore = "focused installed input diagnostics; also exercised by the full matrix"]
fn installed_decision_mouse_and_paste_inputs_across_geometries() {
    let mut failures = Vec::new();
    for geometry in Geometry::ALL {
        for input in [InputMode::Vim, InputMode::Mouse, InputMode::Paste] {
            if let Err(reason) = input_probe(input, geometry) {
                failures.push(format!("{} {}: {reason}", geometry.label(), input.label()));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

fn input_probe(input: InputMode, geometry: Geometry) -> Result<(), String> {
    match input {
        InputMode::Keyboard => {
            let mut tui = TuiPty::spawn(geometry, Some(RenderMode::Fullscreen), &[])?;
            tui.wait("Message", WAIT)?;
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
            tui.wait("Message", WAIT)?;
            exercise_resize(&mut tui, geometry)?;
            tui.send("держ あ".as_bytes())?;
            tui.wait("держ あ", WAIT)?;
            tui.send(b"\x1b")?;
            let (bytes, code) = tui.finish()?;
            if code != Some(0) {
                return Err(format!("unicode exit {code:?}"));
            }
            require_fullscreen_restore(&bytes)
        }
        InputMode::Paste => {
            let mut tui = TuiPty::spawn(geometry, Some(RenderMode::Fullscreen), &[])?;
            tui.wait("Message", WAIT)?;
            exercise_resize(&mut tui, geometry)?;
            tui.send(b"\x1b[200~alpha\nbeta\x1b[201~")?;
            tui.wait("beta", WAIT)?;
            let mut parser = vt100::Parser::new(tui.rows, tui.cols, 0);
            parser.process(&tui.bytes()?);
            // UTF-8 offsets in rows include the Unicode rail and composer label.
            let screen = parser.screen();
            let region = PaintedRegion::read(screen, tui.rows, 0, tui.cols);
            if !region
                .position("alpha")
                .zip(region.position("beta"))
                .is_some_and(|((y, x), next)| next == (y + 1, x))
            {
                return Err(format!(
                    "paste did not paint consecutive aligned rows:\n{}",
                    screen.rows(0, tui.cols).collect::<Vec<_>>().join("\n")
                ));
            }
            tui.send(b"\x1b")?;
            let (bytes, code) = tui.finish()?;
            if code != Some(0) {
                return Err(format!("paste exit {code:?}"));
            }
            require_fullscreen_restore(&bytes)
        }
        InputMode::NoColor => no_color_probe(geometry),
        InputMode::Light => palette_probe(geometry, "light"),
        InputMode::Dark => palette_probe(geometry, "dark"),
        InputMode::HighContrast => palette_probe(geometry, "high-contrast"),
        InputMode::ReducedMotion => {
            let mut tui = TuiPty::spawn(
                geometry,
                Some(RenderMode::Fullscreen),
                &[("RIVECT_REDUCE_MOTION", "1")],
            )?;
            tui.wait("Message", WAIT)?;
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
            tui.wait("Message", WAIT)?;
            exercise_resize(&mut tui, geometry)?;
            tui.send(b"/help\r")?;
            tui.wait("Commands: Enter submits", WAIT)?;
            tui.send(b"\x1b")?;
            let (bytes, code) = tui.finish()?;
            if code != Some(0) {
                return Err(format!("plain exit {code:?}"));
            }
            if let Some(sgr) = first_color_sgr(&bytes) {
                let nearby = &bytes[sgr.start.saturating_sub(24)..(sgr.end + 24).min(bytes.len())];
                return Err(format!(
                    "plain emitted color {:?} at byte {} of {}; nearby {:?}",
                    String::from_utf8_lossy(&bytes[sgr.start..sgr.end]),
                    sgr.start,
                    bytes.len(),
                    String::from_utf8_lossy(nearby)
                ));
            }
            require_inline_restore(&bytes)
        }
        InputMode::Fullscreen => {
            let mut tui = TuiPty::spawn(geometry, Some(RenderMode::Fullscreen), &[])?;
            tui.wait("Message", WAIT)?;
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
            tui.wait("Message", WAIT)?;
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
            tui.wait("Message", WAIT)?;
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

fn inline_probe(geometry: Geometry) -> Result<(), String> {
    let mut tui = TuiPty::spawn(geometry, Some(RenderMode::Inline), &[])?;
    tui.wait("Message", WAIT)?;
    exercise_resize(&mut tui, geometry)?;
    tui.send(b"/help\r")?;
    tui.wait("Commands: Enter submits", WAIT)?;
    tui.send(b"draft text")?;
    tui.wait("draft text", WAIT)?;
    // The draft survives a surface switch: the key is outside the composer.
    let mark = tui.bytes()?.len();
    tui.send(b"\x14")?;
    tui.wait_settled_after("draft text", mark, WAIT)?;
    if !tui.bytes()?[mark..]
        .windows(8)
        .any(|part| part == b"\x1b[?1049h")
    {
        return Err("fullscreen switch did not enter alternate screen".into());
    }
    tui.wait("draft text", WAIT)?;
    let mark = tui.bytes()?.len();
    tui.send(b"\x14")?;
    tui.wait_settled_after("draft text", mark, WAIT)?;
    if !tui.bytes()?[mark..]
        .windows(8)
        .any(|part| part == b"\x1b[?1049l")
    {
        return Err("inline switch did not leave alternate screen".into());
    }
    tui.wait("draft text", WAIT)?;
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
    tui.wait("Message", WAIT)?;
    exercise_resize(&mut tui, geometry)?;
    tui.send(b"/task vim card probe\r")?;
    tui.wait("Begin the first step", WAIT)?;
    tui.wait("focus 1/2", WAIT)?;
    std::thread::sleep(Duration::from_millis(300));
    tui.send_card_key(b"j", "focus 2/2", WAIT)?;
    std::thread::sleep(Duration::from_millis(300));
    tui.send_card_key(b"\x1b", DECISION_UNANSWERED, WAIT)?;
    tui.send(b"\x1b")?;
    let (bytes, code) = tui.finish()?;
    if code != Some(0) {
        return Err(format!("vim exit {code:?}"));
    }
    require_fullscreen_restore(&bytes)
}

fn zero_send_and_approval() -> Result<(), String> {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).map_err(|e| e.to_string())?;
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    let endpoint = listener.local_addr().map_err(|e| e.to_string())?;
    let config = format!(
        "config_version = 1\n[connections.vllm]\nkind=\"local\"\nendpoint=\"http://{endpoint}/v1\"\n[models.defaults]\nmodel={{mode=\"fixed\",connection=\"vllm\",model_id=\"probe\"}}\neffort={{mode=\"auto\"}}\nfallback={{mode=\"off\"}}\n"
    );
    let mut tui = TuiPty::spawn_with_config(
        Geometry::W80H24,
        Some(RenderMode::Fullscreen),
        &[],
        Some(&config),
    )?;
    tui.wait("Message", WAIT)?;
    tui.send(b"/task inspect witnesses\r")?;
    tui.wait("focus 1/2", WAIT)?;
    let db = rusqlite::Connection::open_with_flags(
        tui.pty.data_root().join("runtime/rivect.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .map_err(|e| e.to_string())?;
    let no_effect = || -> Result<(), String> {
        let absent: bool = db.query_row("SELECT EXISTS(SELECT 1 FROM questions WHERE state='pending') AND NOT EXISTS(SELECT 1 FROM questions WHERE answer_json IS NOT NULL) AND NOT EXISTS(SELECT 1 FROM answer_attempts) AND NOT EXISTS(SELECT 1 FROM preapprovals) AND NOT EXISTS(SELECT 1 FROM usage_settlements)", [], |row| row.get(0)).map_err(|e| e.to_string())?;
        if !absent {
            return Err("inspection changed question, preapproval, or usage state".into());
        }
        match listener.accept() {
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(()),
            Err(e) => Err(e.to_string()),
            Ok(_) => Err("inspection contacted the provider".into()),
        }
    };
    tui.send(b"j")?;
    tui.wait("focus 2/2", WAIT)?;
    tui.send(b"k")?;
    tui.wait("focus 1/2", WAIT)?;
    no_effect()?;
    tui.pump(Duration::from_millis(250))?;
    tui.send(b"\x1b")?;
    tui.wait(DECISION_UNANSWERED, WAIT)?;
    tui.send(b"/permissions\r")?;
    tui.wait("Permissions:", WAIT)?;
    no_effect()?;
    tui.send(b"/exit\r")?;
    let (bytes, code) = tui.finish()?;
    if code != Some(0) {
        return Err(format!("inspection exit {code:?}"));
    }
    require_fullscreen_restore(&bytes)
}

fn headless_pipe_probe(geometry: Geometry, input: InputMode) -> Result<(), String> {
    let bundle = support::release::baseline_bundle();
    let root = tempfile::TempDir::with_prefix("rivect-installed-pipe-")
        .map_err(|error| format!("pipe root: {error}"))?;
    let data = root.path().join("data");
    std::fs::create_dir_all(&data).map_err(|error| format!("pipe data: {error}"))?;
    let mut command = std::process::Command::new(bundle.join("rivect"));
    command
        .env_clear()
        .env("HOME", root.path())
        .env("PATH", "/usr/bin:/bin")
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
const ZERO_SEND_CLAIM: &str = "NOT_RUN (owned by installed_focus_and_inspection_never_send_or_approve; packaged decision and read-only permission inspection)";
/// The theme inputs are rendered observations now: the report carries one
/// fingerprint per state, geometry and theme instead of a NOT_RUN family.
const THEME_CLAIM: &str = "rendered under every state and geometry; per-state status/dock/composer/modal fingerprint in theme_fingerprints";

const RENDERER_ONLY_CLAIM: &str = "renderer-only: this passive permission fixture does not initiate a request or confer authority";

const RENDERER_ONLY_OUTPUT_CLAIM: &str = "renderer-only: this seeded output tests presentation, not delivery by a running provider or tool";

/// The non-TTY state is not a TUI frame at all: a non-TTY entry routes to
/// the structured headless loop, so this cell proves the TUI renderer can
/// paint the seeded text, never that a terminal produces it.
const RENDERER_ONLY_NON_TTY_CLAIM: &str = "renderer-only: the non-TTY entry routes to the structured headless loop; the TUI cannot paint this state in production";

/// These matrix states are passive review fixtures, not producer or authority proofs.
fn renderer_only_claim(state: &str) -> Option<&'static str> {
    match state {
        "awaiting-permission" => Some(RENDERER_ONLY_CLAIM),
        "streaming-long-output" | "error-offline-partial" => Some(RENDERER_ONLY_OUTPUT_CLAIM),
        "non-tty" => Some(RENDERER_ONLY_NON_TTY_CLAIM),
        _ => None,
    }
}

/// Keep the claims about static fixtures distinct from separate runtime scenarios.
fn state_claims() -> Value {
    json!({
        "start-no-connection": "seeded disconnected start; no provider is contacted",
        "no-project-index": "same seeded start with no project or index selected",
        "awaiting-permission": RENDERER_ONLY_CLAIM,
        "streaming-long-output": RENDERER_ONLY_OUTPUT_CLAIM,
        "error-offline-partial": RENDERER_ONLY_OUTPUT_CLAIM,
        "non-tty": RENDERER_ONLY_NON_TTY_CLAIM,
        "success": "completion is observed in the seeded task lifecycle row",
    })
}

/// Everything one matrix run produced, so the writer and the verifier share
/// one carrier instead of a long argument list.
struct MatrixRun {
    cells: Vec<Value>,
    observations: Vec<Value>,
    pass: usize,
    fail: usize,
    theme_pass: usize,
    mono_pass: usize,
    dumb_pass: usize,
    inline_pass: usize,
    runtime_seconds: f64,
}

/// Writes the report first, with whatever the run actually produced. The
/// success invariants are asserted afterwards ([`verify_report`]), so a failed
/// run still leaves a FAIL/partial report instead of deleting the evidence.
fn write_report(bundle: &Path, run: &MatrixRun) -> Result<PathBuf, String> {
    let manifest = bundle.join("rivect.manifest.json");
    let digest = support::release::sha256_file(&manifest);
    let report = json!({
        "schema_version": 1,
        "candidate_manifest_sha256": digest,
        "states": STATES,
        "geometries": GEOMETRIES,
        "inputs": INPUTS,
        "cells": CELLS,
        "pass": run.pass,
        "fail": run.fail,
        "not_run": 0,
        "cell_verdicts": run.cells,
        "theme_observations": run.observations.len(),
        "theme_fingerprints": run.observations,
        "mono_probes": { "total": MONO_PROBES, "pass": run.mono_pass },
        "dumb_probes": { "total": DUMB_PROBES, "pass": run.dumb_pass },
        "inline_probes": { "total": THEMES.len(), "pass": run.inline_pass },
        "runtime_seconds": run.runtime_seconds,
        "restore": {
            "exit": RESTORE_EXIT_CLAIM,
            "cancel": RESTORE_CANCEL_CLAIM,
            "panic": RESTORE_PANIC_CLAIM,
            "inline_scrollback": INLINE_SCROLLBACK_CLAIM,
        },
        "zero_send_approval": ZERO_SEND_CLAIM,
        "state_claims": state_claims(),
        "input_mode_claims": {
            "no-color": "no SGR color emitted; status token and dock/composer labels asserted",
            "light": THEME_CLAIM,
            "dark": THEME_CLAIM,
            "high-contrast": THEME_CLAIM,
            "reduced-motion": "no spinner glyphs emitted (asserted)",
        },
        "platform_terminals": "NOT_RUN (no platform terminal is available on this host)",
    });
    let path = matrix_report_path();
    std::fs::write(
        &path,
        serde_json::to_string_pretty(&report)
            .map_err(|error| format!("matrix report encode: {error}"))?,
    )
    .map_err(|error| format!("matrix report write {}: {error}", path.display()))?;
    Ok(path)
}

/// The success invariants, asserted only after the report has been written.
fn verify_report(run: &MatrixRun) {
    assert_eq!(run.pass + run.fail, CELLS, "every cell is accounted");
    assert_eq!(run.pass, CELLS, "every installed UI cell passes");
    assert_eq!(run.fail, 0, "no installed UI cell failed");
    assert_eq!(
        run.theme_pass, THEME_OBSERVATIONS,
        "every state×geometry×theme observation passes"
    );
    assert_eq!(run.mono_pass, MONO_PROBES, "every mono label probe passes");
    assert_eq!(
        run.dumb_pass, DUMB_PROBES,
        "every TERM=dumb label probe passes"
    );
    assert_eq!(
        run.inline_pass,
        THEMES.len(),
        "every themed inline probe passes"
    );
    assert!(
        run.runtime_seconds < MATRIX_BUDGET_SECONDS,
        "matrix runtime {:.1}s exceeded the {MATRIX_BUDGET_SECONDS:.0}s gate",
        run.runtime_seconds
    );
    let mut seen = std::collections::BTreeSet::new();
    for observation in &run.observations {
        let state = observation["state"].as_str().expect("observation state");
        let geometry = observation["geometry"]
            .as_str()
            .expect("observation geometry");
        let theme = observation["theme"].as_str().expect("observation theme");
        for surface in ["status", "dock", "composer", "transcript"] {
            assert_eq!(
                observation[surface]
                    .as_str()
                    .expect("observation fingerprint"),
                expected_fingerprint(theme, surface),
                "{state}/{geometry}/{theme} {surface}"
            );
        }
        let modal_state = matches!(state, "awaiting-decision" | "awaiting-permission");
        assert_eq!(
            observation["modal"].as_str().expect("observation modal"),
            if modal_state {
                expected_fingerprint(theme, "modal")
            } else {
                "none"
            },
            "{state}/{geometry}/{theme} modal"
        );
        assert!(
            seen.insert((state.to_string(), geometry.to_string(), theme.to_string())),
            "observation repeats a coordinate: {state}/{geometry}/{theme}"
        );
    }
    assert_eq!(seen.len(), THEME_OBSERVATIONS);
    for state in rivect::ui::review::STATES {
        for theme in THEMES {
            assert_eq!(
                seen.iter()
                    .filter(|(cell_state, _, cell_theme)| cell_state == state
                        && cell_theme == theme)
                    .count(),
                GEOMETRIES,
                "{state}/{theme} has one observation per geometry"
            );
        }
    }
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
    for cell in &run.cells {
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
}

#[test]
fn installed_19_state_matrix_runs_on_the_packaged_artifact() {
    let started = Instant::now();
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

    // Input probes are independent packaged runs; keep a bounded worker set.
    let input_jobs: Vec<(Geometry, InputMode)> = Geometry::ALL
        .iter()
        .flat_map(|geometry| InputMode::ALL.iter().map(move |input| (*geometry, *input)))
        .collect();
    let input_verdicts: std::collections::HashMap<_, _> =
        parallel_map(&input_jobs, MATRIX_WORKERS, |(geometry, input)| {
            ((geometry, input), input_probe(input, geometry))
        })
        .into_iter()
        .collect();

    let state_geometries: Vec<(usize, Geometry)> = (0..STATES)
        .flat_map(|state| Geometry::ALL.iter().map(move |geometry| (state, *geometry)))
        .collect();
    let controls: std::collections::HashMap<_, _> = parallel_then_live(
        &state_geometries,
        MATRIX_WORKERS,
        LIVE_WORKERS,
        |(_, geometry)| geometry == Geometry::LiveResize,
        |(state, geometry)| {
            let fixture = state_fixture(state);
            ((state, geometry), render_state(&fixture, geometry))
        },
    )
    .into_iter()
    .collect();

    let theme_jobs: Vec<(usize, Geometry, &'static str)> = state_geometries
        .iter()
        .flat_map(|(state, geometry)| THEMES.map(|theme| (*state, *geometry, theme)))
        .collect();
    let theme_results = parallel_then_live(
        &theme_jobs,
        MATRIX_WORKERS,
        LIVE_WORKERS,
        |(_, geometry, _)| geometry == Geometry::LiveResize,
        |(state, geometry, theme)| {
            let control = controls
                .get(&(state, geometry))
                .cloned()
                .unwrap_or_else(|| Err("control probe missing".to_string()));
            let verdict = observe_theme(state, geometry, theme, &control)
                .map(|observation| observation.to_json());
            ((state, geometry, theme), verdict)
        },
    );
    let mut observations = Vec::with_capacity(THEME_OBSERVATIONS);
    let mut theme_verdicts = std::collections::HashMap::new();
    let mut theme_pass = 0usize;
    for (key, result) in theme_results {
        if result.is_ok() {
            theme_pass += 1;
        }
        theme_verdicts.insert(key, result.as_ref().map(|_| ()).map_err(Clone::clone));
        if let Ok(observation) = result {
            observations.push(observation);
        }
    }

    let mono_results = parallel_then_live(
        &theme_jobs,
        MATRIX_WORKERS,
        LIVE_WORKERS,
        |(_, geometry, _)| geometry == Geometry::LiveResize,
        |(state, geometry, theme)| {
            let fixture = state_fixture(state);
            (
                (state, geometry, theme),
                mono_probe(&fixture, geometry, theme),
            )
        },
    );
    let mut mono_verdicts = std::collections::HashMap::new();
    let mut mono_pass = 0usize;
    for (key, result) in mono_results {
        if result.is_ok() {
            mono_pass += 1;
        }
        mono_verdicts.insert(key, result);
    }

    let dumb_results = parallel_map(&(0..STATES).collect::<Vec<_>>(), MATRIX_WORKERS, |state| {
        let fixture = state_fixture(state);
        (state, dumb_probe(&fixture))
    });
    let mut dumb_verdicts = std::collections::HashMap::new();
    let mut dumb_pass = 0usize;
    for (state, result) in dumb_results {
        if result.is_ok() {
            dumb_pass += 1;
        }
        dumb_verdicts.insert(state, result);
    }

    let inline_results = parallel_map(&THEMES, THEMES.len(), |theme| {
        (theme, inline_theme_probe(theme))
    });
    let inline_pass = inline_results
        .iter()
        .filter(|(_, result)| result.is_ok())
        .count();
    for (theme, result) in &inline_results {
        if let Err(error) = result {
            println!("INLINE-THEME theme={theme} verdict=FAIL reason={error}");
        }
    }

    let mut pass = 0usize;
    let mut fail = 0usize;
    let mut cells = Vec::with_capacity(CELLS);
    for state in 0..STATES {
        let fixture = state_fixture(state);
        for geometry in Geometry::ALL {
            let state_verdict: Result<(), String> = controls
                .get(&(state, geometry))
                .map(|verdict| verdict.as_ref().map(|_| ()).map_err(Clone::clone))
                .unwrap_or_else(|| Err("control probe missing".to_string()));
            let mono_verdict = THEMES
                .iter()
                .find_map(|theme| {
                    mono_verdicts
                        .get(&(state, geometry, *theme))
                        .and_then(|verdict| verdict.as_ref().err())
                        .map(|error| format!("mono {theme}: {error}"))
                })
                .map_or(Ok(()), Err);
            let dumb_verdict = dumb_verdicts
                .get(&state)
                .map(|verdict| verdict.as_ref().map(|_| ()).map_err(Clone::clone))
                .unwrap_or_else(|| Err("dumb probe missing".to_string()));
            for input in InputMode::ALL {
                let input_verdict = input_verdicts
                    .get(&(geometry, input))
                    .cloned()
                    .unwrap_or_else(|| Err("input probe missing".to_string()));
                let theme_verdict = match input {
                    InputMode::Light => theme_verdicts.get(&(state, geometry, "light")).cloned(),
                    InputMode::Dark => theme_verdicts.get(&(state, geometry, "dark")).cloned(),
                    InputMode::HighContrast => theme_verdicts
                        .get(&(state, geometry, "high-contrast"))
                        .cloned(),
                    InputMode::NoColor => Some(mono_verdict.clone()),
                    InputMode::Plain => Some(state_verdict.clone().and(dumb_verdict.clone())),
                    _ => None,
                }
                .unwrap_or(Ok(()));
                let (verdict, reason) = match (state_verdict.clone(), input_verdict, theme_verdict)
                {
                    (Ok(()), Ok(()), Ok(())) => {
                        pass += 1;
                        ("PASS", String::new())
                    }
                    (state, input, theme) => {
                        fail += 1;
                        let mut reasons = Vec::new();
                        if let Err(reason) = state {
                            reasons.push(format!("state: {reason}"));
                        }
                        if let Err(reason) = input {
                            reasons.push(format!("input: {reason}"));
                        }
                        if let Err(reason) = theme {
                            reasons.push(format!("theme: {reason}"));
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

    let runtime = started.elapsed();
    let run = MatrixRun {
        cells,
        observations,
        pass,
        fail,
        theme_pass,
        mono_pass,
        dumb_pass,
        inline_pass,
        runtime_seconds: runtime.as_secs_f64(),
    };
    let path = write_report(bundle, &run).expect("matrix report written before success asserts");
    println!(
        "THEME-OBSERVATIONS total={THEME_OBSERVATIONS} pass={}",
        run.theme_pass
    );
    println!(
        "MONO-PROBES total={MONO_PROBES} pass={} DUMB-PROBES total={DUMB_PROBES} pass={}",
        run.mono_pass, run.dumb_pass
    );
    println!(
        "INLINE-PROBES total={} pass={}",
        THEMES.len(),
        run.inline_pass
    );
    println!(
        "UI-MATRIX runtime={:.1}s report={}",
        run.runtime_seconds,
        path.display()
    );
    println!(
        "UI-CELLS total={CELLS} pass={} fail={} not_run=0 report={}",
        run.pass,
        run.fail,
        path.display()
    );
    verify_report(&run);
}

/// An unknown `RIVECT_THEME` falls back to mono and earns exactly one stderr
/// note naming the accepted values, emitted before the alternate screen; a
/// known theme earns none.
#[test]
fn installed_unknown_theme_falls_back_to_mono_with_one_note() {
    const NOTE: &str = "rivect: unknown RIVECT_THEME; accepted values are light|dark|high-contrast; no theme applied";
    let fixture = state_fixture(2);
    let control = render_state(&fixture, Geometry::W80H24).expect("control frame");
    let unknown = review_frame(
        &fixture,
        Geometry::W80H24,
        &[("TERM", "xterm-256color"), ("RIVECT_THEME", "sepia")],
        "unknown-theme",
    )
    .expect("unknown theme falls back");
    let emitted = String::from_utf8_lossy(&unknown.bytes);
    assert_eq!(
        emitted.matches(NOTE).count(),
        1,
        "the unknown value earns exactly one note: {emitted:?}"
    );
    assert!(
        !emitted.contains("sepia"),
        "the note never echoes the untrusted value"
    );
    let note_at = emitted.find(NOTE).expect("the note reached the terminal");
    let alt_at = emitted
        .find("\u{1b}[?1049h")
        .expect("the review entered the alternate screen");
    assert!(
        note_at < alt_at,
        "the note is emitted before the alternate screen, so it survives restore"
    );
    assert_eq!(
        unknown.text, control,
        "the mono fallback changes no visible text"
    );
    assert_eq!(
        unknown.fingerprints.status, "fg=Default;bg=Default;bold=false",
        "an unknown value resolves to the mono palette"
    );
    let dark = review_frame(
        &fixture,
        Geometry::W80H24,
        &[("TERM", "xterm-256color"), ("RIVECT_THEME", "dark")],
        "dark-theme",
    )
    .expect("dark frame");
    let dark_emitted = String::from_utf8_lossy(&dark.bytes);
    assert!(
        !dark_emitted.contains("unknown RIVECT_THEME"),
        "a known theme earns no unknown-value note"
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
        // Settle the frame before the baseline capture: the needle can match
        // on the first PTY quantum while the modal's last rows are still in
        // flight, which would read as a key effect when no key changed anything.
        tui.wait_settled_after(needle, 0, WAIT)
            .expect("review state");
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
    tui.wait("Message", WAIT).expect("inline screen");
    for _ in 0..8 {
        tui.send(b"/help\r").expect("help");
    }
    tui.wait("Commands: Enter submits", WAIT)
        .expect("help transcript");
    tui.send(b"/clear\r").expect("clear");
    tui.wait("New conversation:", WAIT)
        .expect("clear announcement");
    tui.send(b"/settings\r").expect("settings");
    tui.wait("Settings Center", WAIT)
        .expect("settings after clear");
    tui.send(b"\x1b").expect("close settings");
    tui.wait("Message", WAIT).expect("composer");
    tui.send(b"/exit\r").expect("exit");
    let (bytes, code) = tui.finish().expect("teardown");
    assert_eq!(code, Some(0), "inline /clear exits 0");
    require_inline_restore(&bytes).expect("inline restore");
}

/// A terminal that never answers the cursor-position query must not kill
/// the inline surface: the transcript insert degrades to a query-free
/// repaint instead of exiting 1. The harness answers the startup query,
/// then goes deaf like a real dumb emulator before the first insert.
#[test]
fn installed_inline_survives_a_terminal_that_never_answers_cursor_queries() {
    let mut tui = TuiPty::spawn(
        Geometry::W120H40,
        Some(RenderMode::Inline),
        &[("TERM", "dumb")],
    )
    .expect("inline pty");
    tui.wait("Message", WAIT).expect("inline screen");
    tui.deaf = true;
    tui.send(b"/help\r").expect("help");
    tui.wait("Commands: Enter submits", WAIT)
        .expect("the transcript lands without a cursor answer");
    // The degraded insert repaints the pinned region in full: without the
    // query-free repaint the scroll leaves the status row blank.
    tui.wait("Message", WAIT)
        .expect("the pinned region survives the unanswered query");
    tui.send(b"\x1b").expect("exit");
    let (bytes, code) = tui.finish().expect("teardown");
    assert_eq!(code, Some(0), "the deaf-terminal session exits 0");
    require_inline_restore(&bytes).expect("inline restore");
}

/// The inline surface keeps the prompt and focused row visible and restores
/// the terminal after dismissing without an answer. The 199/200 ms boundary
/// is exercised with a manual renderer clock in tui/decision.test.tsx.
#[test]
fn installed_inline_decision_card_paints_and_admits_after_the_consent_floor() {
    let mut tui =
        TuiPty::spawn(Geometry::W80H24, Some(RenderMode::Inline), &[]).expect("inline pty");
    tui.wait("Message", WAIT).expect("inline screen");
    tui.send(b"/task inline card probe\r").expect("submit task");
    // The production first-question card: its prompt and focus counter are
    // both painted in the nine-row inline region, above the two-row footer.
    // The footer is the last row a card frame paints, so waiting on it
    // proves the whole frame — question line, focused row and footer —
    // landed, not just the first chunk of the diff.
    let opened = tui
        .wait("focus 1/2", WAIT)
        .expect("the inline pinned region paints the card footer");
    tui.send(b"j").expect("navigate card");
    let screen = support::squashed(&opened);
    assert!(
        screen.contains("Begin the first step"),
        "the inline card paints the question prompt: {screen}"
    );
    assert!(
        screen.contains("> 1."),
        "the inline card paints the focused row: {screen}"
    );

    tui.wait("focus 2/2", WAIT)
        .expect("the card handles navigation");
    // A PTY reader can be descheduled, so it can only guarantee a lower bound.
    tui.pump(Duration::from_millis(400))
        .expect("pump past the floor");
    tui.send(b"\x1b[27;1:1u").expect("dismiss card");
    tui.wait(DECISION_UNANSWERED, WAIT)
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
        tui.wait("Message · Enter submits · Ctrl+D exits", WAIT)
            .unwrap_or_else(|error| panic!("{label} linear screen: {error}"));
        tui.send(b"/help\r").expect("help");
        tui.wait("/exit · /new · /clear", WAIT)
            .unwrap_or_else(|error| panic!("{label} linear help: {error}"));
        tui.send(b"\x04").expect("exit");
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
        assert!(
            support::find_subsequence(&bytes, b"/resume [session]\r\n/decision").is_some(),
            "{label}: help separates session and decision commands with one physical newline"
        );
        let start = b"/cancel\r\nMessage ";
        assert!(
            support::find_subsequence(&bytes, start).is_some(),
            "{label}: consecutive transcript rows arrive intact: {}",
            String::from_utf8_lossy(&bytes)
        );
        assert!(
            support::find_subsequence(&bytes, "/exit · /new · /clear".as_bytes()).is_some(),
            "{label}: the help row arrives in the stream"
        );
    }
}

#[test]
fn installed_fresh_project_prepares_and_cancels_login() {
    let root = tempfile::TempDir::with_prefix("rivect-installed-onboarding-").expect("test root");
    let home = root.path().join("home");
    let project = root.path().join("project");
    let data = root.path().join("private-state");
    std::fs::create_dir(&home).expect("isolated HOME");
    std::fs::create_dir(&project).expect("project directory");
    let mut command = support::pty_command(support::release::baseline_bundle().join("rivect"));
    command.env_clear();
    command.env("PATH", "/usr/bin:/bin");
    command.env("TERM", "xterm-256color");
    command.env("TMPDIR", root.path());
    command.cwd(&project);
    command.env("HOME", &home);
    command.arg("--data-root");
    command.arg(&data);
    let pty =
        support::PtySession::spawn(command, 24, 120, root, data).expect("spawn packaged Rivect");
    let mut tui = TuiPty {
        pty,
        rows: 24,
        cols: 120,
        cursor_at: 0,
        deaf: false,
    };
    let fresh = tui
        .wait_settled_after("Message → Main", 0, WAIT)
        .expect("fresh thread");
    let mut rows = fresh.lines();
    let header = rows
        .find(|row| row.contains("Project:"))
        .expect("project label");
    let (sidebar, first) = header.split_once("Project:").expect("project label");
    let mut visible_path = first.trim().to_owned();
    let project = project.canonicalize().expect("canonical cwd");
    let path = project.to_str().expect("UTF-8 cwd");
    for row in rows {
        if visible_path.len() >= path.len() {
            break;
        }
        visible_path.extend(
            row.chars()
                .skip(sidebar.chars().count())
                .skip_while(|ch| *ch == ' '),
        );
        visible_path.truncate(visible_path.trim_end().len());
    }
    assert_eq!(visible_path, path, "{fresh}");
    assert!(
        fresh.contains("not connected") && fresh.contains("Run /login"),
        "{fresh}"
    );
    assert!(!fresh.contains("NOT_RUN"), "{fresh}");
    tui.send(b"/login\r").expect("prepare login");
    let pending = tui
        .wait_settled_after("Paste the callback URL", 0, WAIT)
        .expect("private callback prompt");
    assert!(
        pending.contains("Private login") && pending.contains("Login pending: https://"),
        "{pending}"
    );
    tui.send(b"\x1b")
        .expect("leave private entry without completing login");
    tui.wait("Login pending · /login cancel", WAIT)
        .expect("pending status and cancel action");
    tui.send(b"/login cancel\r").expect("cancel login");
    let cancelled = tui
        .wait_settled_after("Login cancelled.", 0, WAIT)
        .expect("cancelled receipt");
    assert!(
        cancelled.contains("not connected") && !cancelled.contains("Login pending"),
        "{cancelled}"
    );
    tui.send(b"/exit\r").expect("exit");
    let (bytes, code) = tui.finish().expect("teardown");
    assert_eq!(code, Some(0));
    require_fullscreen_restore(&bytes).expect("terminal restored");
}

#[test]
fn installed_terminal_restores_after_exit_cancel_and_panic() {
    // Exit and cancel run on the packaged artifact.
    let mut exit =
        TuiPty::spawn(Geometry::W80H24, Some(RenderMode::Fullscreen), &[]).expect("exit pty");
    exit.wait("Message", WAIT).expect("exit screen");
    exit.send(b"\x1b").expect("exit key");
    let (bytes, code) = exit.finish().expect("exit teardown");
    assert_eq!(code, Some(0), "Esc exits cleanly");
    require_fullscreen_restore(&bytes).expect("exit restore");

    let mut cancel =
        TuiPty::spawn(Geometry::W60H20, Some(RenderMode::Fullscreen), &[]).expect("cancel pty");
    cancel.wait("Message", WAIT).expect("cancel screen");
    cancel.send(b"\x03").expect("cancel key");
    let (bytes, code) = cancel.finish().expect("cancel teardown");
    assert_eq!(code, Some(130), "Ctrl-C cancels");
    require_fullscreen_restore(&bytes).expect("cancel restore");

    // The fatal handler has no packaged panic hook. Exercise the same renderer code in a private throw-only child.
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("tui/launch_test.py");
    let home = tempfile::tempdir().expect("panic probe home");
    let mut probe = std::process::Command::new("python3");
    probe
        .arg("-B")
        .arg(script)
        .arg(support::release::baseline_bundle().join("rivect"))
        .arg("Launch.test_uncaught_restores_terminal")
        .env_clear()
        .env("HOME", home.path())
        .env("TMPDIR", home.path());
    for key in ["PATH", "RIVECT_TEST_BUN", "CARGO_TARGET_DIR"] {
        if let Some(value) = std::env::var_os(key) {
            probe.env(key, value);
        }
    }
    let output = probe.output().expect("run OpenTUI crash PTY");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn installed_focus_and_inspection_never_send_or_approve() {
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
