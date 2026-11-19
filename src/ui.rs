//! Client-side domain projections shared by the runtime, CLI and passive review data.

use crate::commands::{Ingress, Runtime, dispatch_runtime_request};
use crate::config::Config;
use crate::contracts::Event;
use crate::owner::OwnerError;
use serde_json::{Value, json};
use std::{fmt, io, time::Duration};

pub mod review;

/// Which surface the TUI owns: the alternate screen, the terminal's own
/// scrollback with a pinned bottom region, or the append-only linear stream a
/// screen reader consumes (no alternate screen, no cursor addressing).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RenderMode {
    #[default]
    Fullscreen,
    Inline,
    Linear,
}

impl RenderMode {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Fullscreen => "fullscreen",
            Self::Inline => "inline",
            Self::Linear => "linear",
        }
    }
}

/// Minimum interval between first paint of a question and conscious consent.
pub const DECISION_CONSENT_DELAY: Duration = Duration::from_millis(200);

/// Start, no connection: input and help are available; login has not happened.
pub const STATUS_DISCONNECTED: &str = "Rivect · not connected · /help for help";
pub const DOCK_EMPTY: &str = "No tasks. Login is a separate explicit action.";
pub const TRANSCRIPT_INPUT: &str = "Input is available. Enter a task or a clarification.";
pub const TRANSCRIPT_NO_PROJECT: &str =
    "No project or index is selected; ordinary replies are not blocked.";

/// Builds the connected status from the main purpose selected by the serving config.
#[must_use]
pub fn connected_status(
    config: &Config,
    profile: &str,
) -> (String, Option<crate::config::ConfigError>) {
    match config.resolve_purpose("main") {
        Ok(purpose) => {
            let model = match &purpose.model {
                crate::config::ModelAssign::Fixed(pin) => &pin.model_id,
                crate::config::ModelAssign::Auto { .. } => "auto",
                crate::config::ModelAssign::Inherit => "inherit",
            };
            (
                format!("Rivect · connected · {profile} · model {model}"),
                None,
            )
        }
        Err(error) => (format!("Rivect · connected · {profile}"), Some(error)),
    }
}

/// Runs one login lifecycle step through the same RPC methods as the headless client.
///
/// # Errors
/// Returns the runtime refusal or a malformed response.
pub fn login_command(runtime: &mut Runtime, argument: Option<&str>) -> io::Result<Vec<String>> {
    let (method, params) = match argument {
        None => (
            "auth.login.begin",
            json!({ "schema_version": 1, "mode": "browser" }),
        ),
        Some("device") => (
            "auth.login.begin",
            json!({ "schema_version": 1, "mode": "device" }),
        ),
        Some("complete") => ("auth.login.complete", json!({ "schema_version": 1 })),
        Some("cancel") => ("auth.login.cancel", json!({ "schema_version": 1 })),
        Some(redirect) => (
            "auth.login.complete",
            json!({ "schema_version": 1, "redirect": redirect }),
        ),
    };
    let request = json!({"jsonrpc":"2.0", "id":1, "method":method, "params":params}).to_string();
    let response = dispatch_runtime_request(runtime, Ingress::Machine, "tui", &request);
    let frame: Value = serde_json::from_str(&response).map_err(io::Error::other)?;
    if let Some(error) = frame.get("error") {
        let message = error
            .pointer("/data/message")
            .or_else(|| error.get("message"))
            .and_then(Value::as_str)
            .unwrap_or("request rejected");
        return Err(io::Error::other(message.to_owned()));
    }
    let result = frame
        .get("result")
        .ok_or_else(|| io::Error::other("tui response omitted result"))?;
    if method == "auth.login.cancel" {
        let line = match result.get("state").and_then(Value::as_str) {
            Some("cancelled") => "Login cancelled.".to_string(),
            Some("none") => "No login is pending.".to_string(),
            _ => return Err(io::Error::other("login cancel answered no state")),
        };
        return Ok(vec![line]);
    }
    if method == "auth.login.begin" {
        let url = result
            .get("verification_url")
            .and_then(Value::as_str)
            .ok_or_else(|| io::Error::other("login begin omitted verification_url"))?;
        let mut lines = vec![format!("Login pending: {url}")];
        if let Some(code) = result.get("user_code").and_then(Value::as_str) {
            lines.push(format!("Enter code: {code}"));
            lines.push("Run /login complete to check authorization.".to_string());
        } else {
            lines.push("Open the link, then enter /login <callback URL>.".to_string());
        }
        return Ok(lines);
    }
    if let Some(profile) = result.get("profile").and_then(Value::as_str) {
        return Ok(vec![format!("Login complete: {profile}")]);
    }
    let state = result
        .get("state")
        .and_then(Value::as_str)
        .ok_or_else(|| io::Error::other("login complete omitted profile and state"))?;
    Ok(vec![format!("Login pending: {state}")])
}

/// Context-only owner errors display their source once; other errors own their message.
#[must_use]
pub fn failure_report<'a>(error: &'a (dyn std::error::Error + 'static)) -> impl fmt::Display + 'a {
    fmt::from_fn(move |out| {
        write!(out, "{error}")?;
        let mut current = error;
        while current.is::<OwnerError>() {
            let Some(source) = current.source() else {
                break;
            };
            write!(out, ": {source}")?;
            current = source;
        }
        Ok(())
    })
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
        lines.push(DOCK_EMPTY.to_string());
    }
    // The economy row is the dock's one dedicated projection row (AC-062):
    // it paints on every beat — with or without tasks — and its slot is
    // sized from its own wrapped height, so the task rows above it keep
    // their window while the row grows for the figures it must show.
    lines.push(economy_row(status.get("economy")));
    lines
}

/// The longest source/model/effort label one economy row carries before it
/// is elided on a char boundary.
const ECONOMY_LABEL_MAX: usize = 32;

/// The longest project/cwd tail the row carries. The row wraps inside its
/// own slot, and the tail keeps the part that names the workspace — a head
/// cut leaves every deep path reading `/home/brook…`, which tells nobody
/// which project the figures belong to.
const ECONOMY_PATH_MAX: usize = 24;

/// The widest reset time the row carries before it is elided. A full
/// timestamp would push the quota source past the narrow budget, so the
/// date head is what stays beside `reset`; the ellipsis marks the cut.
const ECONOMY_RESET_MAX: usize = 10;

/// The row painted while the status carries no economy projection.
const ECONOMY_UNKNOWN_ROW: &str = "economy: unknown";

/// Cuts `label` to at most `max` characters, ending with an ellipsis. The
/// head stays readable — the part that names the source — so an unknown
/// marker and its source survive a narrow row.
fn elide_label(label: &str, max: usize) -> String {
    if label.chars().count() <= max {
        return label.to_string();
    }
    let mut kept: String = label.chars().take(max.saturating_sub(1)).collect();
    kept.truncate(kept.trim_end().len());
    kept.push('…');
    kept
}

/// Keeps the last `max - 1` characters of a workspace path verbatim after
/// an ellipsis: a segment-only tail would spend the budget on the leaf and
/// render every project below the same parent identically, so the parent
/// that names the workspace survives beside it. A path already inside the
/// budget stays verbatim.
fn elide_path(path: &str, max: usize) -> String {
    let chars = path.chars().count();
    if chars <= max {
        return path.to_string();
    }
    let tail: String = path.chars().skip(chars - max.saturating_sub(1)).collect();
    format!("…{tail}")
}

/// One economy string field: absent stays `unknown`, a present value that is
/// not a string is a malformed projection rather than a silent absence.
fn economy_label(economy: &Value, key: &str, max: usize) -> String {
    match economy.get(key) {
        None | Some(Value::Null) => "unknown".to_string(),
        Some(Value::String(label)) => elide_label(label, max),
        Some(_) => "malformed".to_string(),
    }
}

/// One economy counter: absent stays `unknown`, and a value that is not a
/// non-negative integer is reported as malformed instead of being folded
/// into the same `unknown` spelling.
fn economy_number(economy: &Value, key: &str) -> String {
    match economy.get(key) {
        None | Some(Value::Null) => "unknown".to_string(),
        Some(value) => value
            .as_u64()
            .map_or_else(|| "malformed".to_string(), |number| number.to_string()),
    }
}

/// The cache figure the snapshot measured, or the honest unknown. A shape
/// that cannot be read is a malformed counter, never a measured zero.
fn economy_cache(economy: &Value) -> String {
    match economy.get("cache_rate") {
        None | Some(Value::Null) => "unknown".to_string(),
        Some(Value::Array(pair)) if pair.len() == 2 => match (pair[0].as_u64(), pair[1].as_u64()) {
            (Some(read), Some(input)) if input > 0 && read <= input => {
                format!("{read}/{input} tok")
            }
            _ => "malformed".to_string(),
        },
        Some(_) => "malformed".to_string(),
    }
}

/// One dock row for the economy projection (AC-062): the workspace, then
/// the five figures a narrow dock must keep — settled tokens, charged
/// units, agents, reset and quota, each with its unit and the source that
/// answers it — before the longer provenance (context, cache, model,
/// effort, purpose). The workspace leads because the figures belong to it;
/// the required figures lead the provenance because the capped slot cuts
/// its tail, never a figure the operator needs at the acceptance width.
/// Fields are space-separated because the slot is tight at that width and
/// a separator per field would spend the cells the sources need.
fn economy_row(economy: Option<&Value>) -> String {
    let Some(economy) = economy else {
        return ECONOMY_UNKNOWN_ROW.to_string();
    };
    let label = |key: &str| economy_label(economy, key, ECONOMY_LABEL_MAX);
    let cache = economy_cache(economy);
    let project = match economy.get("project") {
        Some(Value::String(path)) => elide_path(path, ECONOMY_PATH_MAX),
        Some(Value::Null) | None => "unknown".to_string(),
        Some(_) => "malformed".to_string(),
    };
    let cwd = match economy.get("cwd") {
        Some(Value::String(path)) => elide_path(path, ECONOMY_PATH_MAX),
        Some(Value::Null) | None => "unknown".to_string(),
        Some(_) => "malformed".to_string(),
    };
    if economy["settled_tokens"].is_null()
        && economy["charged_units"].is_null()
        && economy["context_tokens"].is_null()
        && economy["cache_rate"].is_null()
        && economy["quota_remaining"].is_null()
        && economy["reset_at"].is_null()
        && economy["model"].is_null()
        && economy["agents"].as_u64() == Some(0)
        && economy["pending_sends"].as_u64() == Some(0)
        && economy["settled_without_total"].as_u64() == Some(0)
    {
        return format!("economy: project {project}");
    }
    format!(
        "economy: project {project} cwd {cwd} settled {} tok ({}) charged {} units ({}) agents {} slots ({}) reset {} ({}) quota {} ({}) context {} tok ({}) cache {cache} ({}) model {} ({}) effort {} ({}) purpose {} scope {}",
        economy_number(economy, "settled_tokens"),
        label("settled_source"),
        economy_number(economy, "charged_units"),
        label("cost_source"),
        economy_number(economy, "agents"),
        label("agents_source"),
        economy_label(economy, "reset_at", ECONOMY_RESET_MAX),
        label("reset_source"),
        economy_number(economy, "quota_remaining"),
        label("quota_source"),
        economy_number(economy, "context_tokens"),
        label("context_source"),
        label("cache_source"),
        label("model"),
        label("source"),
        label("effort"),
        label("effort_source"),
        label("purpose"),
        label("connection"),
    )
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
        DOCK_EMPTY, ECONOMY_PATH_MAX, ECONOMY_UNKNOWN_ROW, elide_label, elide_path, task_dock,
    };
    use serde_json::json;

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
        assert_eq!(
            &dock[..dock.len() - 1],
            ["task task-1: blocked (outcome_unknown)"]
        );
        assert_eq!(dock.last().map(String::as_str), Some(ECONOMY_UNKNOWN_ROW));
    }

    #[test]
    fn task_dock_marks_a_pending_profile_switch_beside_the_active_binding() {
        let dock = task_dock(&json!({
            "todo": { "items": [] },
            "profile": { "pending": "p2", "active": "p1" }
        }));
        assert_eq!(&dock[..dock.len() - 1], ["profile: p1 active → p2 pending"]);

        let converged = task_dock(&json!({
            "todo": { "items": [] },
            "profile": { "pending": "p1", "active": "p1" }
        }));
        assert_eq!(&converged[..converged.len() - 1], ["profile: p1"]);

        // a pending profile with no active binding yet still shows —
        // tagged so it never reads as the bound one
        let pending_only = task_dock(&json!({
            "todo": { "items": [] },
            "profile": { "pending": "p2", "active": null }
        }));
        assert_eq!(
            &pending_only[..pending_only.len() - 1],
            ["profile: p2 pending"]
        );

        let active_only = task_dock(&json!({
            "todo": { "items": [] },
            "profile": { "pending": null, "active": "p1" }
        }));
        assert_eq!(&active_only[..active_only.len() - 1], ["profile: p1"]);

        let silent = task_dock(&json!({
            "todo": { "items": [] },
            "profile": { "pending": null, "active": null }
        }));
        assert_eq!(&silent[..silent.len() - 1], [DOCK_EMPTY]);
        for rows in [&dock, &converged, &pending_only, &active_only, &silent] {
            assert_eq!(rows.last().map(String::as_str), Some(ECONOMY_UNKNOWN_ROW));
        }
    }

    #[test]
    fn elided_label_trims_the_kept_prefix() {
        let elided = elide_label("alpha beta  gamma", 12);
        assert_eq!(
            elided, "alpha beta…",
            "the ellipsis follows the kept word, never a floating space: {elided}"
        );
    }

    #[test]
    fn deep_path_elision_keeps_the_workspace_parent_verbatim() {
        let workspace = "/home/brooke/Work/Rivect/src";
        let elided = elide_path(workspace, ECONOMY_PATH_MAX);
        assert!(
            elided.contains("Rivect") && elided.ends_with("/Rivect/src"),
            "the tail names the workspace and its leaf: {elided}"
        );
        assert_eq!(
            elided.chars().count(),
            ECONOMY_PATH_MAX,
            "the elided path spends exactly its budget: {elided}"
        );
        // The old segment-only tail rendered both of these as `…/src`; the
        // verbatim tail keeps the parent that distinguishes them.
        let alice = elide_path("/home/alice/Work/Rivect/src", ECONOMY_PATH_MAX);
        let bob = elide_path("/home/bob/Work/Rivect/src", ECONOMY_PATH_MAX);
        assert_ne!(alice, bob, "distinct workspaces render differently");
        assert!(
            elide_path("/home/brooke", ECONOMY_PATH_MAX) == "/home/brooke",
            "a path inside the budget stays verbatim"
        );
    }

    #[test]
    fn economy_row_is_visible_with_zero_and_three_todos() {
        let economy = json!({
            "project": "/home/brooke/Work/Rivect-checkout",
            "cwd": "/home/brooke/Work/Rivect/src",
            "model": "fixture-model",
            "connection": "local",
            "source": "fixed pin",
            "effort": "high",
            "effort_source": "sent setting; the endpoint reports no effective effort",
            "purpose": "main",
            "context_tokens": 128,
            "context_source": "latest settled attempt's reported prompt tokens",
            "settled_tokens": 18,
            "settled_source": "sum of 1 settled attempt's reported totals",
            "charged_units": 3,
            "cost_source": "the bound is retained unless a reported total is lower",
            "quota_remaining": null,
            "quota_source": "unknown: no quota endpoint reports remaining units",
            "reset_at": null,
            "reset_source": "unknown: the quota surface reports no reset",
            "agents": 2,
            "agents_source": "scheduler's running slots",
            "cache_rate": null,
            "cache_source": "unknown: settled cache and prompt legs are not both recorded"
        });
        let empty = task_dock(&json!({ "todo": { "items": [] }, "economy": economy }));
        let three = task_dock(&json!({
            "todo": { "items": [
                { "task_id": "a", "lifecycle": "running" },
                { "task_id": "b", "lifecycle": "running" },
                { "task_id": "c", "lifecycle": "running" }
            ]},
            "economy": economy
        }));
        // One fixed economy slot in both cases: the empty dock keeps its
        // placeholder row and the economy row sits below the todos.
        assert_eq!(empty.len(), 2);
        assert_eq!(three.len(), 4);
        for dock in [&empty, &three] {
            let row = dock.last().expect("the economy slot paints last");
            assert!(
                row.contains("unknown"),
                "an unreported quota keeps its marker: {row}"
            );
            assert!(row.contains("tok"), "the row names its unit: {row}");
            assert!(
                row.contains("unknown: no quota e"),
                "the unknown keeps its source: {row}"
            );
            let project = row
                .split("project ")
                .nth(1)
                .and_then(|rest| rest.split(" cwd ").next())
                .expect("the row names its project");
            let cwd = row
                .split(" cwd ")
                .nth(1)
                .and_then(|rest| rest.split(" settled ").next())
                .expect("the row names its cwd");
            assert!(
                project.starts_with('…') && cwd.starts_with('…'),
                "a deep path keeps its informative tail: {row}"
            );
            assert!(
                project.contains("Rivect") && cwd.contains("Rivect"),
                "the elided paths keep the workspace name: {row}"
            );
            assert_ne!(project, cwd, "the two paths stay distinguishable: {row}");
            assert!(
                cwd.ends_with("/Rivect/src"),
                "the cwd tail keeps its parent and segment: {row}"
            );
            assert!(row.contains('…'), "a long label is elided: {row}");
            assert!(
                row.contains("settled 18 tok") && row.contains("context 128 tok"),
                "occupancy and lifetime spend stay separately labelled: {row}"
            );
        }
    }

    #[test]
    fn economy_row_paints_measured_cache_and_malformed_counters() {
        let measured = json!({
            "cache_rate": [5, 10],
            "cache_source": "settled frozen cohort w-1 of 2026-11-05 over fixture-model",
        });
        let row = task_dock(&json!({ "todo": { "items": [] }, "economy": measured }))
            .pop()
            .expect("the economy slot paints");
        assert!(
            row.contains("cache 5/10 tok"),
            "a measured rate carries both counters and its unit: {row}"
        );
        assert!(
            row.contains("settled frozen coho"),
            "the measured rate keeps its source: {row}"
        );

        let malformed = json!({
            "cache_rate": "not-a-pair",
            "settled_tokens": "not-a-counter",
            "quota_remaining": -1,
        });
        let row = task_dock(&json!({ "todo": { "items": [] }, "economy": malformed }))
            .pop()
            .expect("the economy slot paints");
        assert!(
            row.contains("cache malformed") && row.contains("settled malformed tok"),
            "a malformed counter is named, never folded into unknown: {row}"
        );
        assert!(
            row.contains("quota malformed"),
            "a negative counter is malformed, never a figure: {row}"
        );
    }
}

#[cfg(test)]
#[path = "../tests/support/pty.rs"]
pub(crate) mod pty_support;

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
        faults.fail_next_read(INJECTED_READ);
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
        faults.fail_next_read(INJECTED_READ);
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
        faults.fail_next_read(INJECTED_READ);
        let pumped = session.pump_for(Duration::from_secs(1));
        let armed = faults.armed_read_faults();
        let finished = session.finish();
        let gone = !path.exists();
        assert!(
            matches!(&pumped, Err(PtyIoError::Read { source }) if source.to_string() == INJECTED_READ),
            "{pumped:?}"
        );
        assert_eq!(armed, 0, "that pump's read took the armed fault");
        assert!(
            finished.is_ok(),
            "the returned fault is not reported again: {finished:?}"
        );
        assert!(gone);
    }

    #[test]
    fn a_later_distinct_read_fault_neither_replaces_the_first_nor_stops_draining() {
        const FIRST: &str = "first injected pty read fault";
        const SECOND: &str = "second injected pty read fault";
        // The child writes its second marker only after the first fault is
        // stored, so that marker is the byte a pass after the fault reads.
        const LATE: &str = "printf ready; read line; printf late; exit 0";

        let (mut session, path, faults) = ready(LATE);
        // A pre-send pass proves the reader is still armed: it calls the
        // reader and takes its arming. It cannot prove anything about the
        // bytes, because "late" does not exist until the child sees the
        // line — the post-send pump is the one that can carry them.
        faults.fail_next_read(FIRST);
        session.pump_pass(b"late");
        assert_eq!(
            faults.armed_read_faults(),
            0,
            "the pass's read took its armed fault"
        );
        faults.fail_next_read(SECOND);
        session.pump_pass(b"late");
        assert_eq!(
            faults.armed_read_faults(),
            0,
            "the second pass's read took its armed fault too"
        );
        must(session.send(b"\n"), "pty send");
        let exit = session.wait_exit(Duration::from_secs(10));
        assert!(matches!(exit, Ok(Some(0))), "{exit:?}");

        // The post-send pump is authoritative: the bytes the child produced
        // after the stored fault reach the stream. Which pump read them is
        // not established here; what a stored fault must not do is stop
        // later pumping from yielding them.
        assert!(
            session.pump_pass(b"late"),
            "the stream carries the child's post-fault bytes"
        );

        let collected = session.collected();
        let finished = session.finish();
        let gone = !path.exists();
        assert!(
            matches!(&collected, Err(PtyIoError::Read { source }) if source.to_string() == FIRST),
            "the first stored fault is the one reported: {collected:?}"
        );
        assert!(
            finished.is_ok(),
            "the taken fault is not reported again: {finished:?}"
        );
        assert!(gone, "the root is removed after the reap");
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
