//! `rivect` executable: minimal fullscreen TUI on a real terminal,
//! JSON-RPC headless loop otherwise (machine stdout carries only LF-delimited
//! JSON, diagnostics go to stderr, no ANSI).

// CLI boundary: this crate root owns process exit and stderr diagnostics; the
// workspace denies these lints everywhere else (docs/engineering-standards.md §8).
#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::exit,
    reason = "CLI boundary owns stderr output and process exit (standards §8)"
)]

use crossterm::tty::IsTty;
use rivect::commands::{DispatchStep, Ingress, LoopEvent, Runtime};
use rivect::providers::LoopbackProvider;
use std::io::{self, BufRead, ErrorKind, Read, StdinLock, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{SyncSender, sync_channel};

const USAGE: &str = "rivect [--tui fullscreen] [--no-mouse] [--headless] [--data-root PATH]";

#[derive(Debug, thiserror::Error)]
enum CliError {
    #[error("unsupported render mode in this build: {mode}")]
    UnsupportedRenderMode { mode: String },
    #[error("missing value for --data-root")]
    MissingDataRoot,
    #[error("unknown flag {flag}")]
    UnknownFlag { flag: String },
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
    let mut headless = false;
    let mut data_root = default_data_root();

    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--tui" => {
                let mode = iter.next().unwrap_or_default();
                if mode != "fullscreen" {
                    eprintln!("{}", CliError::UnsupportedRenderMode { mode });
                    std::process::exit(2);
                }
            }
            "--no-mouse" => {}
            "--headless" => headless = true,
            "--data-root" => {
                let Some(root) = iter.next() else {
                    eprintln!("{}\n{USAGE}", CliError::MissingDataRoot);
                    std::process::exit(2);
                };
                data_root = PathBuf::from(root);
            }
            flag => {
                eprintln!(
                    "{}\n{USAGE}",
                    CliError::UnknownFlag {
                        flag: flag.to_string(),
                    }
                );
                std::process::exit(2);
            }
        }
    }
    let is_tty = io::stdout().is_tty() && io::stdin().is_tty();
    if !headless && is_tty {
        match rivect::ui::run_tui(&data_root) {
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

fn run_headless(data_root: &Path) -> i32 {
    let mut runtime = match Runtime::open(data_root, Box::new(LoopbackProvider::new())) {
        Ok(runtime) => runtime,
        // The failed open already emitted the collected verdicts to
        // stderr and carries them for surfaces that need their own
        // channel — headless stderr is that channel, so only the source
        // failure joins the error line.
        Err(carrier) => {
            report_cli_error(&CliError::Owner(carrier.into_source()));
            return 1;
        }
    };
    // Boot recovery verdicts a human must resolve report on stderr —
    // machine stdout stays pure JSON.
    for diagnostic in &runtime.boot_diagnostics {
        report_boot_diagnostic(diagnostic);
    }
    let (events, inbox) = sync_channel::<LoopEvent>(LOOP_CHANNEL_CAPACITY);
    // The index owner and the watch backend ping this same channel, so a
    // run answering or a batch arriving is noticed by a loop blocked on
    // input rather than by a poll.
    if !runtime.set_loop_wake(events.clone()) {
        report_cli_error(&CliError::Stdin(io::Error::other(
            "the runtime already holds a loop wake",
        )));
        release_runtime(runtime);
        return 1;
    }
    // The reader is a tracked spawn: its handle is joined before this
    // function returns.
    let reader = std::thread::spawn(move || read_stdin(events, io::stdin().lock()));
    let mut code = 0;
    loop {
        // Whatever the owner finished or the watch reported is answered
        // before the next request is routed, so a request id never has
        // two answers and the freshest state is served first.
        let owed = runtime.pump_index();
        if let Some(response) = owed {
            // An answer the owner owed is written before the loop waits
            // for anything else: the loop must not sit on a completed
            // run waiting for input that may never come.
            match write_stdout(&response) {
                Ok(()) => {}
                Err(source) => {
                    report_cli_error(&CliError::Stdout(source));
                    code = 1;
                    break;
                }
            }
        }
        // Every sender gone means the reader has returned and the runtime
        // is being dropped, which unwinds this loop — but the loop is
        // still waiting to be *told* to stop, because the reader
        // returning is not the same as end of input.
        let Ok(event) = inbox.recv() else {
            break;
        };
        match event {
            LoopEvent::InputClosed => {
                // End of input is not an abort. A request the loop has
                // already accepted is finished and its answer written,
                // because a client that closed stdin is owed exactly that
                // and has no other way to learn the outcome. Nothing new
                // is started here: a watch repair has no surface left to
                // serve it, and beginning one would hold the exit open for
                // a build nobody is waiting for.
                while let Some(response) = runtime.pump_index_owed() {
                    if let Err(source) = write_stdout(&response) {
                        report_cli_error(&CliError::Stdout(source));
                        code = 1;
                        break;
                    }
                }
                break;
            }
            LoopEvent::InputFailed(kind) => {
                report_cli_error(&CliError::Stdin(io::Error::from(kind)));
                code = 1;
                break;
            }
            LoopEvent::FrameTooLarge => {
                report_cli_error(&CliError::RequestTooLarge {
                    limit: rivect::contracts::REQUEST_MAX_BYTES,
                });
                code = 1;
                break;
            }
            // The owner or the watch reported: nothing is owed yet, so
            // the loop turns and pumps at the top of the next pass.
            LoopEvent::Index => continue,
            LoopEvent::Frame(request) => {
                let step = rivect::commands::dispatch_step(
                    &mut runtime,
                    Ingress::Machine,
                    "stdio-1",
                    &request,
                );
                if let DispatchStep::Ready(response) = step
                    && let Err(source) = write_stdout(&response)
                {
                    report_cli_error(&CliError::Stdout(source));
                    code = 1;
                    break;
                }
                // `DispatchStep::Deferred` writes nothing for this id:
                // the answer is owed to the off-path owner and the loop
                // writes it when the owner lands it.
            }
        }
    }
    // The reader is joined before the runtime drops, so stdin is not
    // read by a thread that outlives the loop; the runtime's own drop
    // then joins the index owner, and its release failures are reported.
    release_runtime(runtime);
    let _reader = reader.join();
    code
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
