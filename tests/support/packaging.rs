use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Cargo and the native toolchain inherit only the paths needed for a fixture build.
fn packaging_command(script: &Path) -> Command {
    let mut command = Command::new("sh");
    command.arg(script).env_clear().stdin(Stdio::null());
    for name in [
        "PATH",
        "HOME",
        "USER",
        "CARGO_HOME",
        "CARGO_TARGET_DIR",
        "RUSTUP_HOME",
        "RUSTUP_TOOLCHAIN",
        "CARGO_NET_OFFLINE",
        "TMPDIR",
        "LANG",
        "LC_ALL",
    ] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command.env("CARGO", env!("CARGO"));
    command
}

pub fn candidate_command(destination: &Path) -> Command {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"));
    let target =
        std::env::var_os("CARGO_TARGET_DIR").map_or_else(|| repo.join("target"), PathBuf::from);
    let mut command = packaging_command(&repo.join("scripts/package-release.sh"));
    command
        .arg(destination)
        .env("CARGO_TARGET_DIR", target.join("v2-fixture"));
    command
}
