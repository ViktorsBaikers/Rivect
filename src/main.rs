//! `rivect` executable: the grammar in [`cli`] decides what one command line
//! asks for; a fullscreen TUI answers on a real terminal, the JSON-RPC
//! headless loop otherwise (machine stdout carries only LF-delimited JSON,
//! diagnostics go to stderr, no ANSI), and `rivect doctor` answers through
//! [`doctor`] before any runtime open.

// CLI boundary: this crate root owns process exit and stderr diagnostics; the
// workspace denies these lints everywhere else (docs/engineering-standards.md §8).
#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::exit,
    reason = "CLI boundary owns stderr output and process exit (standards §8)"
)]

mod cli;
mod doctor;

use crossterm::tty::IsTty;
use rivect::commands::{DispatchStep, Ingress, LoopEvent, OpenError, Runtime};
use std::io::{self, BufRead, ErrorKind, Read, StdinLock, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{SyncSender, sync_channel};

#[derive(Debug, thiserror::Error)]
enum CliError {
    #[error("runtime open failed")]
    Owner(#[source] rivect::owner::OwnerError),
    #[error("tui failed")]
    Tui(#[source] io::Error),
    #[error("stdin failed")]
    Stdin(#[source] io::Error),
    #[error("stdout failed")]
    Stdout(#[source] io::Error),
    #[error("stdin request exceeds {limit} bytes")]
    RequestTooLarge { limit: usize },
    #[error("index worker failed")]
    IndexWorker(#[source] io::Error),
}

fn main() {
    // The worker mode is exactly this one argument: combined with any
    // other flag it is unknown, and it never opens a runtime, a store or
    // the data root — only stdin, stdout and the query itself. `args_os`
    // reads it without requiring the program path to be UTF-8.
    if std::env::args_os()
        .skip(1)
        .eq([rivect::executor::INDEX_WORKER_FLAG])
    {
        let served = rivect::context::serve_index_worker(io::stdin().lock(), io::stdout().lock());
        if let Err(source) = served {
            report_cli_error(&CliError::IndexWorker(source));
            std::process::exit(1);
        }
        std::process::exit(0);
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    let invocation = match cli::parse(&args, default_data_root()) {
        Ok(invocation) => invocation,
        Err(error) => {
            eprintln!("{error}\n{}", cli::USAGE);
            std::process::exit(2);
        }
    };
    match invocation {
        cli::Invocation::Help => println!("{}", cli::help(&rivect::tools::describe())),
        cli::Invocation::Version => println!("{}", cli::version()),
        cli::Invocation::Completions { shell } => {
            print!(
                "{}",
                rivect::tools::completions(&rivect::tools::describe(), shell)
            );
        }
        cli::Invocation::Doctor { project, data_root } => {
            // The CLI is not the owner: a live election is another process's.
            let report = doctor::inspect(&data_root, project.as_deref(), false);
            println!("{}", report.to_json());
            std::process::exit(if report.ready() { 0 } else { 3 });
        }
        cli::Invocation::Command { kind, data_root } => {
            let code = run_command(&data_root, &kind);
            std::process::exit(code);
        }
        cli::Invocation::UiReview { state } => {
            // The review entry is terminal-only and opens nothing else: an
            // unknown state was refused by the grammar, and a non-TTY refuses
            // before the guard so no data root, store or provider is touched.
            if !(io::stdout().is_tty() && io::stdin().is_tty()) {
                eprintln!("ui review requires a terminal: {state}");
                std::process::exit(2);
            }
            match rivect::ui::review::ReviewState::run(&state) {
                Ok(code) => std::process::exit(code),
                Err(source) => {
                    eprintln!("ui review failed: {source}");
                    std::process::exit(2);
                }
            }
        }
        cli::Invocation::Run {
            headless,
            render,
            data_root,
        } => {
            let is_tty = io::stdout().is_tty() && io::stdin().is_tty();
            if !headless && is_tty {
                match rivect::ui::run_tui_with_mode(&data_root, render) {
                    Ok(code) => std::process::exit(code),
                    Err(source) => {
                        report_cli_error(&CliError::Tui(source));
                        std::process::exit(1);
                    }
                }
            }
            let code = run_headless(&data_root);
            std::process::exit(code);
        }
    }
}

/// Boot diagnostics write to stderr through the locked handle, the same
/// pattern the terminal cleanup path uses: a closed stderr loses the
/// line, never panics the open.
fn report_boot_diagnostic(line: &str) {
    let mut stderr = io::stderr().lock();
    if let Err(error) = stderr.write_all(format!("{line}\n").as_bytes()) {
        std::hint::black_box(error);
    }
}

fn default_data_root() -> PathBuf {
    std::env::var_os("RIVECT_DATA_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let home = std::env::var_os("HOME").unwrap_or_else(|| ".".into());
            PathBuf::from(home).join(".rivect")
        })
}

/// How many loop events may wait for the loop. Bounded, with the
/// overflow policy the standards require: a full channel stops the
/// producer rather than growing a queue nobody drains. A frame is never
/// lost to that — stdin is already buffered by the OS pipe, so a blocked
/// reader is a delayed read, not a dropped request.
const LOOP_CHANNEL_CAPACITY: usize = 8;

/// Reads stdin on its own thread and reports whole frames.
///
/// A blocking read is a blocking read: on the loop thread it would hold
/// the loop for as long as the producer stays quiet, which is exactly
/// the input and background coupling INV-011 forbids. The thread owns
/// nothing but the locked stdin handle and the channel, and the loop
/// joins it before it returns, so no frame is read by a thread that
/// outlives the loop.
fn read_stdin(events: SyncSender<LoopEvent>, mut reader: StdinLock<'static>) {
    let mut line = Vec::new();
    loop {
        line.clear();
        let read = {
            let mut bounded = reader
                .by_ref()
                .take((rivect::contracts::REQUEST_MAX_BYTES as u64) + 1);
            bounded.read_until(b'\n', &mut line)
        };
        match read {
            Ok(0) => {
                // A full channel means the loop has not drained yet, and
                // the frames are already in the OS pipe, so end of input
                // is reported after them rather than instead of them.
                let _reported = events.send(LoopEvent::InputClosed);
                return;
            }
            Ok(_) => {}
            Err(source) => {
                let _reported = events.send(LoopEvent::InputFailed(source.kind()));
                return;
            }
        }
        let mut frame = line.as_slice();
        if frame.last() == Some(&b'\n') {
            frame = &frame[..frame.len() - 1];
        }
        if frame.last() == Some(&b'\r') {
            frame = &frame[..frame.len() - 1];
        }
        if frame.len() > rivect::contracts::REQUEST_MAX_BYTES {
            // The same verdict the blocking read gave, on the same frame:
            // a request past the cap is a caller error the loop reports
            // and exits on, not a frame it tries to route.
            let _reported = events.send(LoopEvent::FrameTooLarge);
            return;
        }
        if frame.is_empty() {
            continue;
        }
        let Ok(request) = std::str::from_utf8(frame) else {
            // A frame that is not UTF-8 was a read failure for the
            // loop's purposes, and it carries the same kind the
            // blocking read always reported for it.
            let _reported = events.send(LoopEvent::InputFailed(ErrorKind::InvalidData));
            return;
        };
        if events.send(LoopEvent::Frame(request.to_string())).is_err() {
            return;
        }
    }
}

/// The headless entry opens through the configured factory: the provider is
/// built inside the open from the admitted config (TD-01), never from the
/// offline fixture, and the same factory is retained for config reloads.
fn open_headless(data_root: &Path) -> Result<Runtime, OpenError> {
    Runtime::open_configured(data_root, rivect::providers::configured_provider)
}

/// One catalog word run once through the dispatcher: attach a fresh session on
/// this connection, dispatch the word's kind, and answer its class. A row that
/// needs parameters answers its own typed refusal — never the grammar's usage
/// error — so every word the completion scripts offer is a dispatcher-level
/// request.
fn run_command(data_root: &Path, kind: &str) -> i32 {
    let mut runtime = match open_headless(data_root) {
        Ok(runtime) => runtime,
        Err(carrier) => {
            report_cli_error(&CliError::Owner(carrier.into_source()));
            return 1;
        }
    };
    for diagnostic in &runtime.boot_diagnostics {
        report_boot_diagnostic(diagnostic);
    }
    let bootstrap = rivect::contracts::AttachmentId::generate().0;
    let attach = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "session.attach",
        "params": { "schema_version": 1, "bootstrap_id": bootstrap },
    })
    .to_string();
    let attach_answer = rivect::commands::dispatch_runtime_request(
        &mut runtime,
        Ingress::Machine,
        "cli-1",
        &attach,
    );
    let session = serde_json::from_str::<serde_json::Value>(&attach_answer)
        .ok()
        .and_then(|frame| {
            frame
                .pointer("/result/session_id")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
        });
    let answer = match session {
        Some(session) => {
            let frame = serde_json::json!({
                "jsonrpc": "2.0", "id": 2, "method": "command.execute",
                "params": {
                    "schema_version": 1,
                    "session_id": session,
                    "command": { "kind": kind },
                },
            })
            .to_string();
            rivect::commands::dispatch_runtime_request(
                &mut runtime,
                Ingress::Machine,
                "cli-1",
                &frame,
            )
        }
        None => attach_answer,
    };
    let code = match write_stdout(&answer) {
        Ok(()) => i32::from(rivect::commands::response_status(&answer)),
        Err(source) => {
            report_cli_error(&CliError::Stdout(source));
            1
        }
    };
    release_runtime(runtime);
    code
}

fn run_headless(data_root: &Path) -> i32 {
    let (events, inbox) = sync_channel::<LoopEvent>(LOOP_CHANNEL_CAPACITY);
    let runtime_events = events.clone();
    // Doctor is answered before any runtime open: the request diagnoses the
    // data root, so opening it first would create the lock and the store the
    // answer is supposed to describe. Only a frame this module does not serve
    // reaches the open, and it keeps its place in the loop.
    // The reader is a tracked spawn: its handle is joined before this
    // function returns.
    let reader = std::thread::spawn(move || read_stdin(events, io::stdin().lock()));
    let mut exit = ExitClass::default();
    // The pre-open pass serves only frames that arrive. End of input with no
    // doctor frame is not an answer: the runtime still opens and reports its
    // own boot diagnostics, exactly as it did before this pass existed.
    let first = match answer_doctor_frames(&inbox, data_root, &mut exit) {
        Ok(event) => event,
        // A run that answered its doctor frames needs no runtime, and a reader
        // blocked in `read_until` on a live stdin owns no runtime state:
        // joining it here would hang the exit instead of reporting the answer.
        // The process exit ends it.
        Err(status) => return status,
    };
    let mut runtime = match open_headless(data_root) {
        Ok(runtime) => runtime,
        // The failed open already emitted the collected verdicts to
        // stderr and carries them for surfaces that need their own
        // channel — headless stderr is that channel, so only the source
        // failure joins the error line. The reader is not joined: a live
        // stdin keeps it in `read_until`, and the failure must exit 1
        // instead of hanging on a client that holds its pipe open.
        Err(carrier) => {
            report_cli_error(&CliError::Owner(carrier.into_source()));
            return 1;
        }
    };
    // The run's instruction scope is the directory it was started in (AC-076):
    // discovery walks that root's ancestors, so the project's own instruction
    // files reach the assembled request. A working directory that cannot be
    // read hands no root and discovers nothing — never a failed boot.
    runtime.set_instructions_root(std::env::current_dir().ok());
    if let Ok(cwd) = std::env::current_dir() {
        runtime.set_instructions_root(Some(cwd.clone()));
        // The same directory is the declared read scope a shipped `read_file`
        // addresses: the entry binds it here, so a real binary's read is
        // admitted under a real grant instead of `UnknownGrant`.
        runtime.bind_read_scope(cwd.clone());
        // The first-task target is the most specific instruction file inside
        // that grant, else the scope root itself (TD-13).
        runtime.bind_first_task_scope(cwd);
    } else {
        runtime.set_instructions_root(None);
    }
    // Boot recovery verdicts a human must resolve report on stderr —
    // machine stdout stays pure JSON.
    for diagnostic in &runtime.boot_diagnostics {
        report_boot_diagnostic(diagnostic);
    }
    // The index owner and the watch backend ping this same channel, so a
    // run answering or a batch arriving is noticed by a loop blocked on
    // input rather than by a poll.
    if !runtime.set_loop_wake(runtime_events) {
        report_cli_error(&CliError::Stdin(io::Error::other(
            "the runtime already holds a loop wake",
        )));
        release_runtime(runtime);
        return 1;
    }
    let mut pending = Some(first);
    let mut input_ended = false;
    loop {
        // Whatever the owner finished or the watch reported is answered
        // before the next request is routed, so a request id never has
        // two answers and the freshest state is served first.
        if let Err(source) = serve_owed(&mut runtime, &mut exit) {
            report_cli_error(&CliError::Stdout(source));
            exit.note(1);
            break;
        }
        // The frame the doctor pass held is served before the loop waits
        // again: it arrived first, so it is answered first. Every sender
        // gone afterwards means the reader has returned and the runtime is
        // being dropped, which unwinds this loop — but the loop is still
        // waiting to be *told* to stop, because the reader returning is not
        // the same as end of input.
        let event = match pending.take() {
            Some(event) => event,
            None => match inbox.recv() {
                Ok(event) => event,
                Err(_) => break,
            },
        };
        // An input that ended is the only stop that proves the reader
        // returned; a write failure stops the loop with the reader possibly
        // still blocked on a live stdin.
        input_ended = matches!(
            &event,
            LoopEvent::InputClosed | LoopEvent::InputFailed(_) | LoopEvent::FrameTooLarge
        );
        if let Step::Stop = handle_event(event, &mut runtime, data_root, &mut exit) {
            break;
        }
    }
    // The reader is joined before the runtime drops only when it reported the
    // end of input: a reader still blocked in `read_until` owns no runtime
    // state, and the process exit ends it.
    release_runtime(runtime);
    if input_ended {
        let _joined = reader.join();
    }
    i32::from(exit.status())
}

/// The one owner of a headless run's exit class: the most severe outcome the
/// loop served, under the published precedence, plus the answers the off-path
/// owner still owes.
#[derive(Debug, Default)]
struct ExitClass {
    status: u8,
    pending: u32,
}

impl ExitClass {
    /// Folds one class into the run. The published order is
    /// cancelled(130) > internal(1) > pending(4) > error(3) > usage(2) > 0, so
    /// a later success never erases an earlier failure.
    fn note(&mut self, status: u8) {
        if class_rank(status) > class_rank(self.status) {
            self.status = status;
        }
    }

    /// Records one answer the off-path owner still owes.
    fn defer(&mut self) {
        self.pending = self.pending.saturating_add(1);
    }

    /// Lands one owed answer: its own class replaces the pending state, so a
    /// deferred success exits 0 and a deferred error exits its own class
    /// instead of `pending`.
    fn landed(&mut self, response: &str) {
        self.pending = self.pending.saturating_sub(1);
        self.note(rivect::commands::response_status(response));
    }

    /// The class this run exits with: a still-owed answer is `pending` only
    /// while nothing more severe was served.
    fn status(&self) -> u8 {
        if self.pending > 0 && class_rank(rivect::commands::EXIT_PENDING) > class_rank(self.status)
        {
            rivect::commands::EXIT_PENDING
        } else {
            self.status
        }
    }
}

/// The published precedence of the exit classes.
fn class_rank(status: u8) -> u8 {
    match status {
        130 => 6,
        1 => 5,
        4 => 4,
        3 => 3,
        2 => 2,
        _ => 0,
    }
}

/// Writes one answer the off-path owner landed, if any, and folds its class
/// into the run. The write failure is the loop's stop.
fn serve_owed(runtime: &mut Runtime, exit: &mut ExitClass) -> io::Result<()> {
    if let Some(response) = runtime.pump_index() {
        write_stdout(&response)?;
        exit.landed(&response);
    }
    Ok(())
}

/// What one loop event did: keep serving, or end the run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    Continue,
    Stop,
}

/// One event the loop turns on. The response a request produced decides the
/// exit status: a result is success, an error frame is that error's own class,
/// and an answer still owed to the off-path owner is `pending`. Every branch
/// folds its class through [`ExitClass`], the run's one owner, so a later
/// success never erases an earlier failure and a doctor verdict is not dropped
/// when another frame follows it.
fn handle_event(
    event: LoopEvent,
    runtime: &mut Runtime,
    data_root: &Path,
    exit: &mut ExitClass,
) -> Step {
    match event {
        // End of input is not an abort. A request the loop has already
        // accepted is finished and its answer written, because a client that
        // closed stdin is owed exactly that and has no other way to learn the
        // outcome. Nothing new is started here: a watch repair has no surface
        // left to serve it, and beginning one would hold the exit open for a
        // build nobody is waiting for.
        LoopEvent::InputClosed => {
            while let Some(response) = runtime.pump_index_owed() {
                if let Err(source) = write_stdout(&response) {
                    report_cli_error(&CliError::Stdout(source));
                    exit.note(1);
                    break;
                }
                exit.landed(&response);
            }
            Step::Stop
        }
        LoopEvent::InputFailed(kind) => {
            report_cli_error(&CliError::Stdin(io::Error::from(kind)));
            exit.note(1);
            Step::Stop
        }
        LoopEvent::FrameTooLarge => {
            report_cli_error(&CliError::RequestTooLarge {
                limit: rivect::contracts::REQUEST_MAX_BYTES,
            });
            exit.note(1);
            Step::Stop
        }
        // The owner or the watch reported: nothing is owed yet, so the loop
        // turns and pumps at the top of the next pass.
        LoopEvent::Index => Step::Continue,
        LoopEvent::Frame(request) => {
            // Doctor answers the same way whenever it arrives, so a frame
            // that reaches an already-open runtime still gets the sessionless
            // report instead of the dispatcher's unavailable refusal. Its
            // verdict is the run's own class: a later frame must not drop it.
            if let doctor::DoctorFrame::Doctor { id, project } = doctor::classify_frame(&request) {
                // The loop answers inside the owner process, so this
                // process's own exclusive lock is not another writer.
                let report = doctor::inspect(data_root, project.as_deref(), true);
                return match write_stdout(&doctor::answer_frame(id, &report)) {
                    Ok(()) => {
                        exit.note(if report.ready() { 0 } else { 3 });
                        Step::Continue
                    }
                    Err(source) => {
                        report_cli_error(&CliError::Stdout(source));
                        exit.note(1);
                        Step::Stop
                    }
                };
            }
            let step =
                rivect::commands::dispatch_step(runtime, Ingress::Machine, "stdio-1", &request);
            if let DispatchStep::Ready(response) = &step
                && let Err(source) = write_stdout(response)
            {
                report_cli_error(&CliError::Stdout(source));
                exit.note(1);
                return Step::Stop;
            }
            match &step {
                // `DispatchStep::Deferred` writes nothing for this id: the
                // answer is owed to the off-path owner and the loop writes it
                // when the owner lands it — `pending` is that state's class
                // until the answer's own class replaces it.
                DispatchStep::Deferred => exit.defer(),
                DispatchStep::Ready(response) => {
                    exit.note(rivect::commands::response_status(response));
                }
            }
            Step::Continue
        }
    }
}

/// Serves the leading doctor frames of one headless run and returns the first
/// event the runtime has to handle. End of input after a doctor answer is that
/// answer's own class: the run needed no runtime, so it opens none. End of
/// input with no doctor frame is not an answer — the runtime still opens and
/// reports its own boot diagnostics.
fn answer_doctor_frames(
    inbox: &std::sync::mpsc::Receiver<LoopEvent>,
    data_root: &Path,
    exit: &mut ExitClass,
) -> Result<LoopEvent, i32> {
    let mut answered = false;
    loop {
        let event = match inbox.recv() {
            Ok(event) => event,
            Err(_receiver_gone) => {
                // The reader vanished without reporting end of input: that is
                // the loop's end too, and an answer already served is the
                // whole run.
                if answered {
                    return Err(i32::from(exit.status()));
                }
                return Ok(LoopEvent::InputClosed);
            }
        };
        match event {
            LoopEvent::Frame(request) => match doctor::classify_frame(&request) {
                doctor::DoctorFrame::Doctor { id, project } => {
                    // Pre-open: no election is held yet, so a live lock is
                    // another process's.
                    let report = doctor::inspect(data_root, project.as_deref(), false);
                    if let Err(source) = write_stdout(&doctor::answer_frame(id, &report)) {
                        report_cli_error(&CliError::Stdout(source));
                        return Err(1);
                    }
                    exit.note(if report.ready() { 0 } else { 3 });
                    answered = true;
                }
                doctor::DoctorFrame::Other => return Ok(LoopEvent::Frame(request)),
            },
            LoopEvent::InputClosed => {
                if answered {
                    return Err(i32::from(exit.status()));
                }
                return Ok(LoopEvent::InputClosed);
            }
            other => return Ok(other),
        }
    }
}

/// One response to machine stdout, flushed. The failure is the loop's
/// exit condition, exactly as the blocking write's was.
fn write_stdout(response: &str) -> io::Result<()> {
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "{response}").and_then(|_| stdout.flush())
}

/// The one printer of a source-bearing error: its own context, then `: `
/// and the operator report of its cause, so each text appears once.
fn report_cli_error(error: &CliError) {
    match std::error::Error::source(error) {
        Some(source) => eprintln!("{error}: {}", rivect::ui::failure_report(source)),
        None => eprintln!("{error}"),
    }
}

/// Ends the runtime and reports its lock release failures on stderr;
/// stdout stays pure JSON frames.
fn release_runtime(runtime: Runtime) {
    for line in runtime.release() {
        report_boot_diagnostic(&line);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One fixture config: a local peer the production set builds no adapter
    /// for, so the headless open never touches a wire — the factory path, not
    /// a send, is what the case observes.
    fn config_for(endpoint: &str) -> String {
        format!(
            "config_version = 1\n\
             [connections.fixture-local]\nkind = \"local\"\nendpoint = \"{endpoint}\"\n\
             [models.defaults]\n\
             model = {{ mode = \"fixed\", connection = \"fixture-local\", model_id = \"fixture-model\" }}\n\
             effort = {{ mode = \"auto\" }}\n\
             fallback = {{ mode = \"off\" }}\n"
        )
    }

    /// Counts the ledger seam's two calls, so "the denied dispatch settled
    /// nothing" has an oracle instead of a no-op that would report zero for
    /// any path.
    #[derive(Debug, Default)]
    struct CountingLedger {
        begun: u64,
        finished: u64,
    }

    impl rivect::model::Ledger for CountingLedger {
        fn begin_send(
            &mut self,
            _context: &rivect::model::SendContext,
            manifest: &rivect::model::RequestManifest,
        ) -> Result<rivect::model::SendTicket, rivect::model::LedgerError> {
            self.begun += 1;
            Ok(rivect::model::SendTicket {
                attempt_id: manifest.attempt_id.clone(),
                cost_bound: manifest.cost_bound,
                reserved: false,
            })
        }

        fn finish_send(
            &mut self,
            _ticket: &rivect::model::SendTicket,
            _outcome: &rivect::model::SendOutcome,
        ) -> Result<(), rivect::model::LedgerError> {
            self.finished += 1;
            Ok(())
        }
    }

    /// The headless entry builds its provider through the configured factory
    /// and a connection edited after admission denies typed before any send:
    /// the frozen entry, not the latest document, is what the request kept.
    #[test]
    fn headless_factory_denies_a_connection_edited_after_admission()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::TempDir::with_prefix("rivect-headless-activation-")?;
        std::fs::write(
            root.path().join("config.toml"),
            config_for("http://127.0.0.1:11434"),
        )?;
        let mut runtime = open_headless(root.path())?;
        assert_eq!(
            runtime.broker.provider_name(),
            "configured",
            "the headless open must install the configured provider set"
        );
        let manifest = runtime.broker.prepare(
            "main",
            &runtime.config_for_broker(),
            "/world/headless",
            "goal: fixture",
        )?;
        std::fs::write(
            root.path().join("config.toml"),
            config_for("http://127.0.0.1:11435"),
        )?;
        runtime.reload_config()?;
        let mut ledger = CountingLedger::default();
        match runtime
            .broker
            .dispatch(&mut ledger, "/world/headless", &manifest)
        {
            Err(rivect::model::ModelError::ConnectionChanged { connection, .. }) => {
                assert_eq!(connection, "fixture-local");
            }
            other => {
                return Err(
                    io::Error::other(format!("expected ConnectionChanged, got {other:?}")).into(),
                );
            }
        }
        assert_eq!(
            (ledger.begun, ledger.finished),
            (0, 0),
            "the denied dispatch never opened or closed a settlement"
        );
        assert_eq!(runtime.broker.accounted_requests(), 0);
        Ok(())
    }

    /// One headless runtime over a private root, with the session every local
    /// command needs attached through the real dispatcher.
    fn loop_runtime(
        tag: &str,
    ) -> Result<(tempfile::TempDir, Runtime, String), Box<dyn std::error::Error>> {
        let root = tempfile::TempDir::with_prefix(tag)?;
        let mut runtime = open_headless(root.path())?;
        let frame = serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "session.attach",
            "params": { "schema_version": 1, "bootstrap_id": format!("{tag}-session") }
        })
        .to_string();
        let answer = rivect::commands::dispatch_runtime_request(
            &mut runtime,
            Ingress::Machine,
            "loop-test",
            &frame,
        );
        let parsed: serde_json::Value = serde_json::from_str(&answer)?;
        let session = parsed
            .pointer("/result/session_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| io::Error::other(format!("attach failed: {answer}")))?
            .to_string();
        Ok((root, runtime, session))
    }

    /// One `command.execute` frame under a named kind.
    fn command_frame(session: &str, kind: &str, id: u64) -> String {
        serde_json::json!({
            "jsonrpc": "2.0", "id": id, "method": "command.execute",
            "params": {
                "schema_version": 1,
                "session_id": session,
                "command": { "kind": kind },
            }
        })
        .to_string()
    }

    /// The loop's classes are the run's own, folded through the one owner:
    /// a usage refusal, a typed error and a later success keep the most
    /// severe class instead of letting the last frame win.
    #[test]
    fn exit_classes_are_sticky_through_handle_event() -> Result<(), Box<dyn std::error::Error>> {
        let (root, mut runtime, session) = loop_runtime("rivect-loop-classes-")?;
        let mut exit = ExitClass::default();
        // usage (2): a required parameter is missing.
        let usage = command_frame(&session, "config.get", 1);
        assert_eq!(
            handle_event(
                LoopEvent::Frame(usage),
                &mut runtime,
                root.path(),
                &mut exit
            ),
            Step::Continue
        );
        assert_eq!(exit.status(), 2, "the usage refusal is the run's class");
        // error (3): a served row whose store lookup names no such task.
        let error = serde_json::json!({
            "jsonrpc": "2.0", "id": 2, "method": "command.execute",
            "params": {
                "schema_version": 1,
                "session_id": session,
                "command": { "kind": "context.view" },
                "task_id": "missing-task",
            }
        })
        .to_string();
        assert_eq!(
            handle_event(
                LoopEvent::Frame(error),
                &mut runtime,
                root.path(),
                &mut exit
            ),
            Step::Continue
        );
        assert_eq!(
            exit.status(),
            3,
            "a more severe class replaces the usage one"
        );
        // success (0): a later result never erases the earlier error.
        let success = command_frame(&session, "view.clear", 3);
        assert_eq!(
            handle_event(
                LoopEvent::Frame(success),
                &mut runtime,
                root.path(),
                &mut exit
            ),
            Step::Continue
        );
        assert_eq!(exit.status(), 3, "a later success never erases a failure");
        release_runtime(runtime);
        Ok(())
    }

    /// A doctor verdict is the run's class too: it survives a later frame, and
    /// a later frame's success does not clear it. The root is degraded after
    /// the open — a document the schema rejects — so the in-loop verdict is a
    /// real 3 rather than a healthy 0.
    #[test]
    fn a_doctor_verdict_survives_a_later_frame() -> Result<(), Box<dyn std::error::Error>> {
        let (root, mut runtime, session) = loop_runtime("rivect-loop-doctor-")?;
        std::fs::write(
            root.path().join("config.toml"),
            "config_version = \"not-a-number\"\n",
        )?;
        let mut exit = ExitClass::default();
        let doctor = serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "command.execute",
            "params": { "schema_version": 1, "command": { "kind": "doctor" } }
        })
        .to_string();
        assert_eq!(
            handle_event(
                LoopEvent::Frame(doctor),
                &mut runtime,
                root.path(),
                &mut exit
            ),
            Step::Continue
        );
        assert_eq!(exit.status(), 3, "the degraded root is not ready");
        let success = command_frame(&session, "view.clear", 2);
        assert_eq!(
            handle_event(
                LoopEvent::Frame(success),
                &mut runtime,
                root.path(),
                &mut exit
            ),
            Step::Continue
        );
        assert_eq!(
            exit.status(),
            3,
            "the doctor verdict is not dropped by the next frame"
        );
        release_runtime(runtime);
        Ok(())
    }

    /// A deferred request is `pending` while its answer is owed, and the
    /// answer's own class replaces that state when it lands. The run cannot
    /// start its worker, so the landed answer is a typed error.
    #[test]
    fn a_deferred_answer_lands_with_its_own_class() -> Result<(), Box<dyn std::error::Error>> {
        let (root, mut runtime, session) = loop_runtime("rivect-loop-deferred-")?;
        runtime.index.worker.program = PathBuf::from("/nonexistent/rivect-index-worker");
        runtime.index.worker.helper = PathBuf::from("/nonexistent/rivect-sandbox-helper");
        let mut exit = ExitClass::default();
        let deferred = command_frame(&session, "project.init", 1);
        assert_eq!(
            handle_event(
                LoopEvent::Frame(deferred),
                &mut runtime,
                root.path(),
                &mut exit
            ),
            Step::Continue
        );
        assert_eq!(
            exit.status(),
            rivect::commands::EXIT_PENDING,
            "the answer is still owed"
        );
        assert_eq!(
            handle_event(LoopEvent::InputClosed, &mut runtime, root.path(), &mut exit),
            Step::Stop
        );
        assert_eq!(
            exit.status(),
            3,
            "the landed error's own class replaced pending"
        );
        release_runtime(runtime);
        Ok(())
    }

    /// A landed success replaces the pending class with success: the loop does
    /// not keep the `pending` exit after the answer was written.
    #[test]
    fn a_landed_success_replaces_pending() {
        let mut exit = ExitClass::default();
        exit.defer();
        assert_eq!(exit.status(), rivect::commands::EXIT_PENDING);
        exit.landed("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}");
        assert_eq!(exit.status(), 0, "the landed answer's own class wins");
    }

    /// An error frame without the typed code is internal, never success: an
    /// unreadable refusal must not read as a clean run.
    #[test]
    fn an_untyped_error_frame_is_internal() {
        let frame =
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32000,\"message\":\"transport\"}}";
        assert_eq!(rivect::commands::response_status(frame), 1);
    }
}
