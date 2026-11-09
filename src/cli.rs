//! The executable's own grammar: the run entry with its existing flags, the
//! `completions` and `doctor` subcommands, and one-shot catalog words.
//! Parsing is total and side-effect free — `main` executes the verdict — and
//! every word the banner and the scripts carry comes from the catalog page
//! ([`rivect::tools::describe`]), so a row the page drops disappears from
//! help and completion in the same build. Every word the scripts offer parses
//! here, which is what keeps a completion candidate from being a usage error.

use rivect::contracts::{CommandDescriptor, Page};
use rivect::tools::{self, Shell};
use std::path::PathBuf;

/// The grammar, one line per invocation shape. It names the subcommands and
/// the flags exactly as [`parse`] accepts them.
pub const USAGE: &str = "rivect [--tui fullscreen] [--no-mouse] [--headless] [--data-root PATH]\n\
       rivect <command> [--data-root PATH]\n\
       rivect doctor [--project PATH] [--data-root PATH]\n\
       rivect completions <bash|zsh|fish>\n\
       rivect --help | --version";

/// What one command line asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Invocation {
    /// Print [`help`] and exit 0.
    Help,
    /// Print [`version`] and exit 0.
    Version,
    /// Print one completion script and exit 0.
    Completions { shell: Shell },
    /// Run the sessionless doctor and exit with its readiness.
    Doctor {
        project: Option<PathBuf>,
        data_root: PathBuf,
    },
    /// Run one catalog word once through the dispatcher.
    Command { kind: String, data_root: PathBuf },
    /// Run the TUI on a terminal, the JSON-RPC loop otherwise.
    Run { headless: bool, data_root: PathBuf },
}

/// Every way one command line is refused. Each variant carries the exact word
/// that was wrong, and `main` prints it with the usage block.
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error("unsupported render mode in this build: {mode}")]
    UnsupportedRenderMode { mode: String },
    #[error("missing value for {flag}")]
    MissingValue { flag: &'static str },
    #[error("unknown flag {flag}")]
    UnknownFlag { flag: String },
    #[error("unknown command {command}")]
    UnknownCommand { command: String },
    #[error("completions needs exactly one shell: bash, zsh or fish")]
    MissingShell,
    #[error("unknown shell {shell}; known shells: bash, zsh, fish")]
    UnknownShell { shell: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Subcommand {
    Completions,
    Doctor,
}

/// Parses one command line. `default_data_root` is read only when the flags
/// name no root, so the environment is consulted exactly once per run.
pub fn parse(args: &[String], default_data_root: PathBuf) -> Result<Invocation, CliError> {
    let subcommand = match args.first().map(String::as_str) {
        Some("completions") => Some(Subcommand::Completions),
        Some("doctor") => Some(Subcommand::Doctor),
        // A leading word is a catalog command run once. An unknown word is a
        // grammar refusal, not a flag error: the caller named a command, not
        // a flag.
        Some(word) if !word.starts_with('-') => {
            return parse_command(word, &args[1..], default_data_root);
        }
        _ => None,
    };
    let rest: &[String] = if subcommand.is_some() {
        &args[1..]
    } else {
        args
    };
    // `completions` reads no data root: its one word is the shell. `--help`
    // belongs to every subcommand, so the shell check never answers
    // "unknown shell --help".
    if subcommand == Some(Subcommand::Completions) {
        if rest.iter().any(|word| word == "--help" || word == "-h") {
            return Ok(Invocation::Help);
        }
        let [shell] = rest else {
            return Err(CliError::MissingShell);
        };
        let Some(shell) = Shell::parse(shell) else {
            return Err(CliError::UnknownShell {
                shell: shell.clone(),
            });
        };
        return Ok(Invocation::Completions { shell });
    }
    let mut data_root = default_data_root;
    let mut headless = false;
    let mut project = None;
    let mut index = 0;
    while index < rest.len() {
        match rest[index].as_str() {
            "--help" | "-h" => return Ok(Invocation::Help),
            "--version" if subcommand.is_none() => return Ok(Invocation::Version),
            "--tui" if subcommand.is_none() => {
                index += 1;
                let Some(mode) = rest.get(index) else {
                    return Err(CliError::MissingValue { flag: "--tui" });
                };
                if mode != "fullscreen" {
                    return Err(CliError::UnsupportedRenderMode { mode: mode.clone() });
                }
            }
            "--no-mouse" if subcommand.is_none() => {}
            "--headless" if subcommand.is_none() => headless = true,
            "--data-root" => {
                index += 1;
                let Some(value) = rest.get(index) else {
                    return Err(CliError::MissingValue {
                        flag: "--data-root",
                    });
                };
                data_root = PathBuf::from(value);
            }
            "--project" if subcommand == Some(Subcommand::Doctor) => {
                index += 1;
                let Some(value) = rest.get(index) else {
                    return Err(CliError::MissingValue { flag: "--project" });
                };
                project = Some(PathBuf::from(value));
            }
            // A flag this subcommand does not own is refused, never silently
            // ignored: `doctor --headless` is a caller error, not a doctor
            // that quietly drops the word.
            flag => {
                return Err(CliError::UnknownFlag {
                    flag: flag.to_string(),
                });
            }
        }
        index += 1;
    }
    if subcommand == Some(Subcommand::Doctor) {
        return Ok(Invocation::Doctor { project, data_root });
    }
    Ok(Invocation::Run {
        headless,
        data_root,
    })
}

/// One catalog word with the only flag a one-shot command owns. The word is
/// resolved against the catalog, so a word the completion scripts never emit
/// cannot reach the dispatcher as a grammar error and an emitted word always
/// does.
fn parse_command(
    word: &str,
    rest: &[String],
    default_data_root: PathBuf,
) -> Result<Invocation, CliError> {
    if tools::catalog_row(word).is_none() {
        return Err(CliError::UnknownCommand {
            command: word.to_string(),
        });
    }
    let mut data_root = default_data_root;
    let mut index = 0;
    while index < rest.len() {
        match rest[index].as_str() {
            "--help" | "-h" => return Ok(Invocation::Help),
            "--data-root" => {
                index += 1;
                let Some(value) = rest.get(index) else {
                    return Err(CliError::MissingValue {
                        flag: "--data-root",
                    });
                };
                data_root = PathBuf::from(value);
            }
            flag => {
                return Err(CliError::UnknownFlag {
                    flag: flag.to_string(),
                });
            }
        }
        index += 1;
    }
    Ok(Invocation::Command {
        kind: word.to_string(),
        data_root,
    })
}

/// The help banner: the grammar's usage lines, then one line per catalog row.
/// The row lines are [`tools::help_lines`], so the banner cannot advertise a
/// row the page does not carry.
#[must_use]
pub fn help(page: &Page<CommandDescriptor>) -> String {
    let mut text = String::from("usage:\n");
    for line in USAGE.lines() {
        text.push_str("  ");
        text.push_str(line.trim_start());
        text.push('\n');
    }
    text.push_str("\ncommands:\n");
    for line in tools::help_lines(page) {
        text.push_str(&line);
        text.push('\n');
    }
    text
}

/// The build identity `--version` prints.
#[must_use]
pub fn version() -> String {
    format!(
        "rivect {} ({})",
        env!("CARGO_PKG_VERSION"),
        rivect::BUILD_ATTEMPT_ID
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every word a completion script offers is one this grammar resolves:
    /// a catalog word parses into a one-shot command, never a usage error.
    /// Dropping a row from the page removes its word from both surfaces in
    /// the same edit, so this sweep is the parity check between them.
    #[test]
    fn every_completion_word_parses() {
        let page = tools::describe();
        let mut failures = Vec::new();
        for word in tools::completion_words(&page) {
            match parse(std::slice::from_ref(&word), PathBuf::from("/data")) {
                Ok(Invocation::Command { kind, .. }) if kind == word => {}
                Ok(Invocation::Doctor { .. }) if word == "doctor" => {}
                Ok(other) => failures.push(format!("{word} parsed as {other:?}")),
                Err(error) => failures.push(format!("{word} refused: {error}")),
            }
        }
        assert!(failures.is_empty(), "{failures:?}");
    }

    /// The grammar owns its flags: a subcommand refuses a flag it does not
    /// own, and `--help` answers on every subcommand.
    #[test]
    fn a_subcommand_refuses_a_flag_it_does_not_own() {
        let doctor = parse(
            &["doctor".to_string(), "--headless".to_string()],
            PathBuf::from("/data"),
        );
        assert!(
            matches!(doctor, Err(CliError::UnknownFlag { .. })),
            "{doctor:?}"
        );
        let completions = parse(
            &["completions".to_string(), "--help".to_string()],
            PathBuf::from("/data"),
        );
        assert!(
            matches!(completions, Ok(Invocation::Help)),
            "{completions:?}"
        );
        let command = parse(
            &["session.new".to_string(), "--headless".to_string()],
            PathBuf::from("/data"),
        );
        assert!(
            matches!(command, Err(CliError::UnknownFlag { .. })),
            "{command:?}"
        );
    }
}
