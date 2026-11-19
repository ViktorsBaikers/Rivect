//! Private, pipe-only task projections. This adapter never owns command authority.

mod actions;
pub mod boot;
mod completion;
mod composer;
mod permission;

use rivect::commands::{
    Ingress, LoopEvent, Runtime, UiAnswer, UiMessage, dispatch_runtime_request,
};
use rivect::contracts::{ErrorCode, Event, Lifecycle, SessionId, TaskId};
use rivect::resources::{Delivery, OutputSettlement, OutputStream};
use rivect::state::{StoreError, TaskActivity, TaskProjection};
use serde::{Deserialize, Serialize, Serializer};
use serde_json::{Value, json};
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};

fn decimal<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.collect_str(value)
}

#[derive(Serialize)]
struct Position<'a> {
    session_id: &'a SessionId,
    task_id: TaskId,
    lifecycle: Lifecycle,
    #[serde(serialize_with = "decimal")]
    revision: u64,
    #[serde(serialize_with = "decimal")]
    event_cursor: u64,
    // Event.cursor is global; TaskSnapshot.event_cursor is task-local.
    #[serde(serialize_with = "decimal")]
    outbox_cursor: u64,
    activity: Vec<TaskActivity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    proposed_diff: Option<&'a str>,
    goal: String,
    origin: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    reply: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    output: Option<Value>,
}

impl<'a> Position<'a> {
    fn new(
        runtime: &'a Runtime,
        session_id: &'a SessionId,
        mut row: TaskProjection,
    ) -> Result<Self, StoreError> {
        match runtime.terminal_result(session_id, &row.task_id, row.revision) {
            Some(Ok(reply)) => row.reply = Some(reply.to_owned()),
            Some(Err(code)) => row.error_code = Some(code.as_str().to_owned()),
            None => {}
        }
        let settlement = if row.reply.is_some() {
            Some(OutputSettlement::Complete)
        } else if let Some(code) = &row.error_code {
            Some(OutputSettlement::Failed {
                cause: code.replace('_', " "),
            })
        } else {
            runtime
                .store()
                .step_output(session_id, &row.task_id, row.revision)?
        };
        let mut stream = OutputStream::new();
        if let Some(reply) = &row.reply {
            stream.push_chunk(reply.as_bytes());
        }
        let output = settlement.map(|status| {
            stream.settle(status);
            json!({"status":stream.status_line(false)})
        });
        Ok(Self {
            activity: runtime.store().task_activity(session_id, &row.task_id)?,
            proposed_diff: runtime
                .proposed_diff(session_id, &row.task_id)?
                .map(|(summary, _)| summary),
            session_id,
            task_id: row.task_id,
            lifecycle: row.lifecycle,
            revision: row.revision,
            event_cursor: row.event_cursor,
            outbox_cursor: row.outbox_cursor,
            goal: row.goal,
            origin: row.origin,
            reply: row.reply.map(|_| stream.text().to_owned()),
            error_code: row.error_code,
            output,
        })
    }
}

#[derive(Serialize)]
struct HistoryEvent {
    event_id: String,
    event_type: String,
    category: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<String>,
}

impl From<Event> for HistoryEvent {
    fn from(mut event: Event) -> Self {
        let (prefix, _) = event.event_type.split_once('.').unwrap_or(("", ""));
        // Project core-minted action identities without exposing arguments or output.
        let question = if event.event_type == "question.published" && event.origin == "state" {
            event.delta["question_id"].as_str().unwrap_or("")
        } else {
            ""
        };
        let (category, summary) = match prefix {
            "question" if question.starts_with("run-check:") => {
                ("agent", Some("Verifier · waiting for check approval"))
            }
            "question" if question.starts_with("share-file:") => {
                ("tool", Some("Read file · disclosure requested"))
            }
            "question" if question.starts_with("write-file:") => {
                ("diff", Some("File replacement proposed"))
            }
            "question" => ("waiting", None),
            "agent" | "provider" => ("agent", None),
            "process" => ("process", None),
            "stage" => ("stage", None),
            "tool" => ("tool", None),
            "diff" => ("diff", None),
            "evidence" => ("evidence", None),
            _ if event.event_type == "task.waiting" => ("waiting", None),
            _ => ("task", None),
        };
        let text = match summary {
            Some(text) => Some(text.to_owned()),
            None if category == "diff" => event.delta["added"]
                .as_u64()
                .zip(event.delta["removed"].as_u64())
                .map(|(added, removed)| format!("+{added} −{removed}")),
            None => match event.delta.get_mut("lifecycle").map(Value::take) {
                Some(Value::String(state))
                    if matches!(
                        state.as_str(),
                        "running" | "waiting" | "paused" | "blocked" | "completed" | "cancelled"
                    ) =>
                {
                    Some(state)
                }
                _ => None,
            },
        };
        Self {
            event_id: event.event_id.0,
            event_type: event.event_type,
            category,
            text,
        }
    }
}

fn history(
    runtime: &Runtime,
    session: &SessionId,
    task: &TaskId,
) -> Result<Vec<HistoryEvent>, StoreError> {
    Ok(runtime
        .store()
        .recent_task_events(session, task)?
        .into_iter()
        .map(HistoryEvent::from)
        .collect())
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Frame<'a> {
    Snapshot {
        #[serde(flatten)]
        position: Position<'a>,
        events: Vec<HistoryEvent>,
    },
    Delta {
        #[serde(flatten)]
        position: Position<'a>,
        #[serde(serialize_with = "decimal")]
        after: u64,
        #[serde(flatten)]
        event: HistoryEvent,
    },
    ResyncMarker {
        #[serde(flatten)]
        position: Position<'a>,
    },
}

#[derive(Debug, thiserror::Error)]
enum Refusal {
    #[error("invalid private request")]
    Invalid,
    #[error("invalid operator action")]
    ActionInput(#[source] serde_json::Error),
    #[error("unsupported private protocol version")]
    Version,
    #[error("operation not admitted on private pipe")]
    Denied,
    #[error("terminal witness unavailable")]
    Witness(#[source] io::Error),
    #[error("private file read failed")]
    FileRead(#[source] io::Error),
    #[error("invalid core response")]
    Reply(#[from] serde_json::Error),
    #[error("invalid cursor")]
    Cursor(#[from] std::num::ParseIntError),
    #[error("incomplete command receipt")]
    Unknown,
    #[error("core refused operation: {0}")]
    Core(ErrorCode),
    #[error("projection unavailable after command")]
    AfterCommand(#[source] StoreError),
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl Refusal {
    fn code(&self) -> ErrorCode {
        match self {
            Self::Invalid | Self::ActionInput(_) | Self::Cursor(_) => ErrorCode::InvalidInput,
            Self::Version => ErrorCode::UnsupportedVersion,
            Self::Denied | Self::Witness(_) => ErrorCode::Denied,
            Self::Unknown | Self::Reply(_) | Self::AfterCommand(_) => ErrorCode::OutcomeUnknown,
            Self::FileRead(_) => ErrorCode::StorageUnavailable,
            Self::Core(code) => *code,
            Self::Store(source) => source.code(),
        }
    }
}

fn string<'a>(object: &'a Value, key: &str) -> Result<&'a str, Refusal> {
    object
        .get(key)
        .and_then(Value::as_str)
        .ok_or(Refusal::Invalid)
}

fn machine(runtime: &mut Runtime, raw: &str) -> Result<Value, Refusal> {
    dispatch_common(runtime, Ingress::Machine, raw)
}

fn dispatch_common(runtime: &mut Runtime, ingress: Ingress, raw: &str) -> Result<Value, Refusal> {
    let reply = dispatch_runtime_request(runtime, ingress, "ui-pipe", raw);
    let mut envelope: Value = serde_json::from_str(&reply)?;
    if let Some(code) = envelope.pointer_mut("/error/data/code") {
        return Err(Refusal::Core(serde_json::from_value(code.take())?));
    }
    envelope
        .get_mut("result")
        .map(Value::take)
        .ok_or(Refusal::Unknown)
}

fn position<'a>(
    runtime: &'a Runtime,
    session: &'a SessionId,
    task: &TaskId,
) -> Result<Position<'a>, Refusal> {
    let (mut rows, _) = runtime.store().projection_page(session, Some(task))?;
    let row = rows.pop().ok_or(Refusal::Core(ErrorCode::NotFound))?;
    Ok(Position::new(runtime, session, row)?)
}

fn committed_snapshot<'a>(
    runtime: &'a Runtime,
    session: &'a SessionId,
    task: &TaskId,
) -> Result<Frame<'a>, Refusal> {
    let (mut rows, _) = runtime
        .store()
        .projection_page(session, Some(task))
        .map_err(Refusal::AfterCommand)?;
    Ok(Frame::Snapshot {
        events: history(runtime, session, task).map_err(Refusal::AfterCommand)?,
        position: Position::new(runtime, session, rows.pop().ok_or(Refusal::Unknown)?)
            .map_err(Refusal::AfterCommand)?,
    })
}

fn task_frame(
    runtime: &Runtime,
    session: &SessionId,
    task: &TaskId,
    after: Option<u64>,
) -> Result<Value, Refusal> {
    let position = position(runtime, session, task)?;
    let delivery = if let Some(after) = after {
        if after > position.outbox_cursor {
            return Err(Refusal::Invalid);
        }
        // Only the latest task state is retained. Two outstanding events cannot both
        // be paired with that state as deltas: recover once from the owner's snapshot.
        let mut events = runtime
            .store()
            .events_after(session, Some(task), after, 2)?;
        if events.len() > 1 {
            Some(Delivery::ResyncMarker)
        } else {
            events.pop().map(Delivery::Event)
        }
    } else {
        None
    };
    let frame = match (delivery, after) {
        (Some(Delivery::Event(event)), Some(after)) => Frame::Delta {
            position,
            after,
            event: event.into(),
        },
        (Some(Delivery::ResyncMarker), _) => Frame::ResyncMarker { position },
        _ => Frame::Snapshot {
            position,
            events: history(runtime, session, task)?,
        },
    };
    Ok(json!({"frame":frame}))
}

#[derive(Default)]
pub struct PipeSession {
    active: Option<SessionId>,
    witness: bool,
    // Only the latest local producer keeps a body, never across an attach or process restart.
    output: Option<(String, String, u64, OutputStream)>,
}

impl PipeSession {
    /// Allows requesting an independent terminal witness, not approving an answer.
    pub fn terminal() -> Self {
        Self {
            witness: true,
            ..Self::default()
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    jsonrpc: String,
    id: Value,
    method: String,
    params: Value,
}

impl Request {
    fn validate(&self) -> Result<(), Refusal> {
        if !self.id.is_i64() && !self.id.as_str().is_some_and(|id| id.len() <= 256) {
            return Err(Refusal::Invalid);
        }
        if self.jsonrpc != "2.0"
            || self.params.get("schema_version").and_then(Value::as_u64) != Some(1)
        {
            return Err(Refusal::Version);
        }
        if self.method == "command.execute" {
            let command = &self.params["command"];
            if string(command, "kind")? != "session.new" {
                return Err(Refusal::Denied);
            }
            // session.new takes only its source session, never extra command arguments.
            if !self.params["session_id"].is_string()
                || self
                    .params
                    .as_object()
                    .is_none_or(|fields| fields.len() != 3)
                || command.as_object().is_none_or(|fields| fields.len() != 1)
            {
                return Err(Refusal::Invalid);
            }
        }
        Ok(())
    }
}

fn after(params: &Value) -> Result<u64, Refusal> {
    let value = string(params, "after")?;
    if value.is_empty()
        || (value.starts_with('0') && value.len() > 1)
        || !value.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(Refusal::Invalid);
    }
    Ok(value.parse()?)
}

fn recent_sessions(runtime: &Runtime) -> Result<Value, Refusal> {
    let page = runtime.store().sessions_page(20, None)?;
    let ids: Vec<_> = page.items.into_iter().map(|row| row.session_id).collect();
    Ok(json!({"sessions":ids}))
}

enum Work {
    Message(Box<UiMessage>),
    Answer(UiAnswer),
}

fn project(
    runtime: &mut Runtime,
    pipe: &PipeSession,
    launch: &mut Option<Work>,
    raw: &str,
    request: &Request,
) -> Result<Value, Refusal> {
    let params = &request.params;
    request.validate()?;
    if (request.method.starts_with("task.")
        || request.method.starts_with("operator.")
        || matches!(
            request.method.as_str(),
            "command.execute" | "composer.command" | "session.older"
        ))
        && pipe.active.as_ref().map(|s| s.0.as_str()) != Some(string(params, "session_id")?)
    {
        return Err(Refusal::Denied);
    }
    match request.method.as_str() {
        "runtime.boot" => {
            boot::check(request)?;
            Ok(
                json!({"recovery":boot::diagnostics(&runtime.boot_diagnostics),
                "login_available":runtime.config_for_broker().connections.contains_key(rivect::providers::openai_login::CANONICAL_PROFILE),
                "session_id":runtime.previous_project_session()?}),
            )
        }
        "operator.action" => actions::project(runtime, params),
        "operator.permission" if pipe.witness => permission::view(runtime, params),
        "operator.permission.resolve" if pipe.witness => permission::resolve(runtime, params),
        "operator.question" => actions::question(runtime, params, pipe.witness),
        "operator.diff" if pipe.witness => actions::reveal(runtime, params),
        "operator.answer" => actions::answer(runtime, params, pipe.witness, launch),
        "composer.command" => composer::command(runtime, params, pipe.witness),
        "composer.complete" => completion::candidates(params, Some(runtime)),
        "session.recent" => recent_sessions(runtime),
        "session.project" => {
            if params.as_object().is_none_or(|fields| fields.len() != 1) {
                return Err(Refusal::Invalid);
            }
            Ok(json!({"session_id":runtime.open_project_conversation(None)?}))
        }
        "session.open" => {
            let opened = machine(runtime, raw)?;
            Ok(json!({"session_id": opened["session_id"].as_str().ok_or(Refusal::Unknown)?}))
        }
        "command.execute" => {
            let next = match machine(runtime, raw) {
                Err(Refusal::Core(ErrorCode::Conflict)) => {
                    let session = SessionId(string(params, "session_id")?.to_owned());
                    let running = runtime
                        .session_switch_blocker(&session)?
                        .ok_or(Refusal::Core(ErrorCode::Conflict))?;
                    return Ok(json!({"running":running,"previous_session_id":session}));
                }
                result => result?,
            };
            let session = SessionId(string(&next, "session_id")?.to_owned());
            runtime
                .open_project_conversation(Some(&session))
                .map_err(Refusal::AfterCommand)?;
            Ok(
                json!({"session_id":session, "previous_session_id":string(&next, "previous_session_id")?}),
            )
        }
        "session.attach" | "session.older" => {
            let session = SessionId(string(params, "session_id")?.to_owned());
            let (rows, mut more) = if request.method == "session.older" {
                let before = TaskId(string(params, "before")?.to_owned());
                runtime.store().older_task_page(&session, &before)?
            } else {
                let attached = machine(runtime, raw)?;
                if attached["session_id"].as_str() != Some(session.0.as_str()) {
                    return Err(Refusal::Unknown);
                }
                runtime
                    .store()
                    .projection_page(&session, None)
                    .map_err(Refusal::AfterCommand)?
            };
            let mut tasks = Vec::with_capacity(rows.len());
            // Leave room for the envelope and the echoed request id.
            let mut remaining =
                rivect::contracts::REQUEST_MAX_BYTES.saturating_sub(raw.len() + 256);
            for row in rows {
                let events =
                    history(runtime, &session, &row.task_id).map_err(Refusal::AfterCommand)?;
                let position =
                    Position::new(runtime, &session, row).map_err(Refusal::AfterCommand)?;
                let frame = serde_json::to_value(Frame::Snapshot { position, events })?;
                let size = frame.to_string().len() + 1;
                if size > remaining {
                    if tasks.is_empty() {
                        return Err(Refusal::Invalid);
                    }
                    more = true;
                    break;
                }
                remaining -= size;
                tasks.push(frame);
            }
            // Transport starts from newest so a byte-limited page always advances.
            tasks.reverse();
            Ok(json!({"session_id":session,"tasks":tasks,"more":more}))
        }
        "task.message" => {
            let session = SessionId(string(params, "session_id")?.to_owned());
            let command = string(params, "command_id")?;
            let goal = string(params, "goal")?;
            if command.is_empty()
                || command.len() > rivect::contracts::TEXT_MAX_BYTES
                || goal.trim().is_empty()
            {
                return Err(Refusal::Invalid);
            }
            let (receipt, work) = runtime
                .begin_ui_message(&session, command, goal)
                .map_err(|error| Refusal::Core(error.error_code()))?;
            *launch = work.map(|message| Work::Message(Box::new(message)));
            let snapshot = committed_snapshot(runtime, &session, &receipt.task_id)?;
            Ok(json!({"status":receipt.status,"task_id":receipt.task_id,"snapshot":snapshot}))
        }
        "task.cancel" => {
            // The live send was signalled and joined before this read. An already
            // settled task is observed rather than cancelling unrelated work.
            let session = SessionId(string(params, "session_id")?.to_owned());
            let task = TaskId(string(params, "task_id")?.to_owned());
            task_frame(runtime, &session, &task, None)
        }
        "task.submit" if params.get("kind").and_then(Value::as_str) == Some("create") => {
            if params.get("parent_task_id").is_some() {
                return Err(Refusal::Denied);
            }
            let session = SessionId(string(params, "session_id")?.to_owned());
            let receipt = machine(runtime, raw)?;
            let task = TaskId(
                receipt["task_id"]
                    .as_str()
                    .ok_or(Refusal::Unknown)?
                    .to_owned(),
            );
            let snapshot = committed_snapshot(runtime, &session, &task)?;
            Ok(
                json!({"status":receipt["status"].as_str().ok_or(Refusal::Unknown)?, "task_id":task, "snapshot":snapshot}),
            )
        }
        "task.snapshot" | "task.changes" => {
            let session = SessionId(string(params, "session_id")?.to_owned());
            let task = TaskId(string(params, "task_id")?.to_owned());
            let after = if request.method == "task.changes" {
                Some(after(params)?)
            } else {
                None
            };
            let mut result = task_frame(runtime, &session, &task, after)?;
            if let Some((owner, id, revision, stream)) = &pipe.output
                && *owner == session.0
                && *id == task.0
                && string(&result["frame"], "revision")?.parse::<u64>()? == *revision
            {
                let frame = &mut result["frame"];
                frame["output"] = if frame.get("reply").is_some() {
                    json!({"status":stream.status_line(false)})
                } else {
                    json!({"status":stream.status_line(false),"text":stream.text()})
                };
            }
            Ok(result)
        }
        _ => Err(Refusal::Denied),
    }
}

fn envelope(id: Value, answer: Result<Value, Refusal>) -> Value {
    match answer {
        Ok(result) => json!({"jsonrpc":"2.0","id":id,"result":result}),
        Err(Refusal::Store(StoreError::Conflict(
            rivect::state::ConflictCause::CompactionNotShorter { .. },
        ))) => {
            json!({"jsonrpc":"2.0","id":id,"error":{"code":ErrorCode::Conflict,"cause":"compaction_not_shorter"}})
        }
        Err(error) => json!({"jsonrpc":"2.0","id":id,"error":{"code":error.code()}}),
    }
}

fn live_changes(
    frame: &Value,
    params: &Value,
    preview: &Mutex<(usize, OutputStream)>,
) -> Result<Value, Refusal> {
    let cursor = string(frame, "outbox_cursor")?.parse::<u64>()?;
    let after = after(params)?;
    if after > cursor {
        return Err(Refusal::Invalid);
    }
    let Some(offset) = params.get("preview_bytes").filter(|_| after == cursor) else {
        return Ok(json!({"frame":frame}));
    };
    let offset = offset
        .as_u64()
        .and_then(|n| usize::try_from(n).ok())
        .ok_or(Refusal::Invalid)?;
    let (suffix, status) = {
        let head = preview.lock().map_err(|_poison| Refusal::Unknown)?;
        (
            head.1
                .text()
                .get(offset..)
                .ok_or(Refusal::Invalid)?
                .to_owned(),
            head.1.status_line(false),
        )
    };
    Ok(json!({"frame": {
        "kind": "preview", "session_id": frame["session_id"], "task_id": frame["task_id"],
        "revision": frame["revision"], "event_cursor": frame["event_cursor"],
        "outbox_cursor": frame["outbox_cursor"], "offset": offset, "text": suffix, "status": status
    }}))
}

/// The scoped worker owns the writable runtime; previews never advance its committed frame.
pub fn serve(
    runtime: &mut Runtime,
    pipe: &mut PipeSession,
    raw: &str,
    inbox: &Receiver<LoopEvent>,
    wake: &SyncSender<LoopEvent>,
) -> io::Result<Option<LoopEvent>> {
    let request: Request = match serde_json::from_str(raw) {
        Ok(request) => request,
        Err(_) => {
            super::write_stdout(&envelope(Value::Null, Err(Refusal::Invalid)).to_string())?;
            return Ok(None);
        }
    };
    let mut launch = None;
    let answer = match project(runtime, pipe, &mut launch, raw, &request) {
        Err(error) if launch.is_some() => {
            // The receipt committed but no worker started. Release the owner so
            // recovery settles the task without repeating the send.
            super::write_stdout(&envelope(request.id, Err(Refusal::Unknown)).to_string())?;
            return Err(io::Error::other(error));
        }
        answer => answer,
    };
    if let Ok(result) = &answer
        && matches!(
            request.method.as_str(),
            "session.project" | "session.open" | "session.attach" | "command.execute"
        )
        && let Some(session) = result["session_id"].as_str()
    {
        pipe.output = None;
        pipe.active = Some(SessionId(session.to_owned()));
    }
    let response = envelope(request.id, answer);
    super::write_stdout(&response.to_string())?;
    let Some(work) = launch else { return Ok(None) };
    let accepted = &response["result"];
    let frame = &accepted["snapshot"];
    let session = string(frame, "session_id").map_err(io::Error::other)?;
    let task = string(frame, "task_id").map_err(io::Error::other)?;
    let live_views = actions::ActiveViews::capture(runtime, session, task);
    let recent = recent_sessions(runtime).map_err(|err| err.code());
    let ledger_pending = AtomicBool::new(false);
    let message = matches!(&work, Work::Message(_));
    let stop = Arc::new(AtomicBool::new(false));
    let done = AtomicBool::new(false);
    // One bounded prefix per in-flight send; polling never queues tokens or touches the ledger.
    let preview = Mutex::new((0usize, OutputStream::new()));
    let (next, settlement) = std::thread::scope(|scope| {
        let worker = std::thread::Builder::new()
            .name("ui-foreground".into())
            .spawn_scoped(scope, || {
                let observe = |text: &str| {
                    let mut head = preview
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    if let Some(suffix) = text.get(head.0..) {
                        head.1.push_chunk(suffix.as_bytes());
                        head.0 = text.len();
                    }
                };
                let result = match work {
                    Work::Answer(answer) => runtime.finish_terminal_answer(
                        answer,
                        Arc::clone(&stop),
                        &ledger_pending,
                        &observe,
                    ),
                    Work::Message(work) => {
                        runtime.finish_ui_message(*work, &stop, &ledger_pending, &observe)
                    }
                }
                .map_err(io::Error::other);
                done.store(true, Ordering::Release);
                // A full queue already wakes the driver. Otherwise ensure coalesced
                // index notifications reach serve_owed even if stdin remains idle.
                if matches!(
                    wake.try_send(LoopEvent::Index),
                    Err(TrySendError::Disconnected(_))
                ) {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "private input closed",
                    ));
                }
                result
            })?;
        let next: io::Result<Option<LoopEvent>> = (|| {
            loop {
                let event = inbox.recv().map_err(io::Error::other)?;
                if done.load(Ordering::Acquire) {
                    return Ok(Some(event));
                }
                match &event {
                    LoopEvent::Index => continue,
                    LoopEvent::Frame(raw) => {
                        let pending: Request = match serde_json::from_str(raw) {
                            Ok(request) => request,
                            Err(_) => {
                                super::write_stdout(
                                    &envelope(Value::Null, Err(Refusal::Invalid)).to_string(),
                                )?;
                                continue;
                            }
                        };
                        let p = &pending.params;
                        let same_session = p["session_id"] == frame["session_id"];
                        let same_task = same_session && p["task_id"] == frame["task_id"];
                        let valid = pending.validate();
                        if valid.is_ok() && same_task && pending.method == "task.cancel" {
                            return Ok(Some(event));
                        }
                        let answer = valid.and_then(|()| match pending.method.as_str() {
                            "command.execute" if same_session => Ok(json!({"running":frame["task_id"],"previous_session_id":frame["session_id"]})),
                            "composer.complete" => completion::candidates(p, None),
                            "session.recent" => recent.as_ref().cloned().map_err(|code| Refusal::Core(*code)),
                            "operator.action" if same_session => live_views.action(p, message.then(|| ledger_pending.load(Ordering::Acquire))),
                            "task.snapshot" if same_task => Ok(json!({"frame":frame})),
                            "task.changes" if same_task => live_changes(frame, p, &preview),
                            "task.message"
                                if message && same_session
                                    && p["command_id"] == request.params["command_id"]
                                    && p["goal"] == frame["goal"] =>
                            {
                                Ok(accepted.clone())
                            }
                            "task.snapshot" | "task.changes" | "task.cancel" => {
                                Err(Refusal::Core(ErrorCode::NotFound))
                            }
                            _ => Err(Refusal::Core(ErrorCode::Conflict)),
                        });
                        super::write_stdout(&envelope(pending.id, answer).to_string())?;
                    }
                    _ => return Ok(Some(event)),
                }
            }
        })();
        stop.store(true, Ordering::Release);
        // A panic payload is not a typed error and can contain request text.
        let settlement = worker
            .join()
            .map_err(|_payload| io::Error::other("message worker panicked"))??;
        next.map(|event| (event, settlement))
    })?;
    pipe.output = None;
    if let Some(settlement) = settlement {
        let (_, mut head) = preview
            .into_inner()
            .map_err(|_poison| io::Error::other("output unavailable"))?;
        head.settle(settlement);
        let task = string(frame, "task_id").map_err(io::Error::other)?;
        let revision = runtime
            .store()
            .snapshot(&TaskId(task.to_owned()))
            .map_err(io::Error::other)?
            .revision;
        pipe.output = Some((session.to_owned(), task.to_owned(), revision, head));
    }
    Ok(next)
}
