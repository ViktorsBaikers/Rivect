//! `rivect` executable: minimal fullscreen TUI on a real terminal,
//! JSON-RPC headless loop otherwise (machine stdout carries only LF-delimited
//! JSON, diagnostics go to stderr, no ANSI).

use crossterm::tty::IsTty;
use rivect::commands::{Ingress, Runtime, dispatch_runtime_request};
use rivect::providers::LoopbackProvider;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

const USAGE: &str = "rivect [--tui fullscreen] [--no-mouse] [--headless] [--data-root PATH]";

#[derive(Debug, thiserror::Error)]
enum CliError {
    #[error("unsupported render mode in this build: {mode}")]
    UnsupportedRenderMode { mode: String },
    #[error("missing value for --data-root")]
    MissingDataRoot,
    #[error("unknown flag {flag}")]
    UnknownFlag { flag: String },
    #[error("owner election failed: {0}")]
    Owner(#[source] rivect::owner::OwnerError),
    #[error("tui failed: {0}")]
    Tui(#[source] io::Error),
    #[error("stdin failed: {0}")]
    Stdin(#[source] io::Error),
    #[error("stdout failed: {0}")]
    Stdout(#[source] io::Error),
}

fn main() {
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
        match rivect::ui::run_tui() {
            Ok(code) => std::process::exit(code),
            Err(source) => {
                eprintln!("{}", CliError::Tui(source));
                std::process::exit(1);
            }
        }
    }
    let code = run_headless(&data_root);
    std::process::exit(code);
}

fn default_data_root() -> PathBuf {
    std::env::var_os("RIVECT_DATA_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let home = std::env::var_os("HOME").unwrap_or_else(|| ".".into());
            PathBuf::from(home).join(".rivect")
        })
}

fn run_headless(data_root: &Path) -> i32 {
    let mut runtime = match Runtime::open(data_root, Box::new(LoopbackProvider::new())) {
        Ok(runtime) => runtime,
        Err(source) => {
            eprintln!("{}", CliError::Owner(source));
            return 1;
        }
    };
    let stdin = io::stdin();
    let mut line = String::new();
    let mut reader = stdin.lock();
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => return 0,
            Ok(_) => {}
            Err(source) => {
                eprintln!("{}", CliError::Stdin(source));
                return 1;
            }
        }
        let request = line.trim_end_matches(['\n', '\r']);
        if request.is_empty() {
            continue;
        }
        let response = dispatch_runtime_request(&mut runtime, Ingress::Machine, "stdio-1", request);
        let mut stdout = io::stdout().lock();
        if let Err(source) = writeln!(stdout, "{response}").and_then(|_| stdout.flush()) {
            eprintln!("{}", CliError::Stdout(source));
            return 1;
        }
    }
}

use std::io;
