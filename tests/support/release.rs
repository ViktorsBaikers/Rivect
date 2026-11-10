//! Installed-bundle fixture: one authentic package built outside the
//! checkout by the shipped script, copied per case, and run from a nested
//! Unicode/space working directory. The package is built once per test binary
//! and never mutated in place.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::LazyLock;

/// The only parent environment a packaged child or the packaging script
/// inherits: what cargo, the toolchain and a process need to locate their
/// roots (standards §10).
const PACKAGE_ENV: [&str; 11] = [
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
];

struct Baseline {
    // The baseline root outlives every copy and keeps the fixture honest.
    _root: tempfile::TempDir,
    bundle: PathBuf,
}

static BASELINE: LazyLock<Baseline> = LazyLock::new(|| {
    let root =
        tempfile::TempDir::with_prefix("rivect-release-baseline-").expect("baseline fixture root");
    let bundle = root
        .path()
        .join("nested release space")
        .join("юникод package");
    let output = package_into(&bundle);
    assert!(
        output.status.success(),
        "the packaged baseline refused: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Baseline {
        _root: root,
        bundle,
    }
});

/// The pristine authentic bundle every case copies.
pub fn baseline_bundle() -> &'static Path {
    &BASELINE.bundle
}

/// Runs the shipped packaging script into `destination`.
pub fn package_into(destination: &Path) -> Output {
    let script = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("scripts")
        .join("package-release.sh");
    let mut command = Command::new("sh");
    command
        .arg(script)
        .arg(destination)
        .env_clear()
        .stdin(Stdio::null());
    for name in PACKAGE_ENV {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command.env("CARGO", env!("CARGO"));
    command.output().expect("run package-release.sh")
}

/// Runs the packaged executable from `bundle` in `cwd` with a clean
/// environment and only the variables a process needs.
pub fn run_packaged(bundle: &Path, args: &[&str], cwd: &Path) -> Output {
    let mut command = Command::new(bundle.join("rivect"));
    command.args(args).current_dir(cwd).env_clear();
    for name in ["PATH", "HOME", "TMPDIR", "LANG", "LC_ALL"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command.output().expect("run the packaged rivect")
}

/// Copies the flat three-file bundle into `destination`, which must not exist.
pub fn copy_bundle(source: &Path, destination: &Path) {
    std::fs::create_dir_all(destination).expect("bundle copy destination");
    for entry in std::fs::read_dir(source).expect("bundle inventory") {
        let entry = entry.expect("bundle entry");
        std::fs::copy(entry.path(), destination.join(entry.file_name()))
            .expect("copy bundle artifact");
    }
}

/// Every path under `root` with its length, sorted: the zero-write oracle.
pub fn snapshot(root: &Path) -> Vec<(PathBuf, u64)> {
    let mut entries = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let Ok(read) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in read.flatten() {
            let path = entry.path();
            let Ok(metadata) = entry.metadata() else {
                continue;
            };
            entries.push((path.clone(), metadata.len()));
            if metadata.is_dir() {
                pending.push(path);
            }
        }
    }
    entries.sort();
    entries
}

pub fn stdout_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

pub fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// The SHA-256 of a file's bytes, streamed so a multi-megabyte binary never
/// becomes a test allocation.
pub fn sha256_file(path: &Path) -> String {
    use sha2::Digest as _;
    let mut file = std::fs::File::open(path).expect("hash file open");
    let mut hasher = sha2::Sha256::new();
    std::io::copy(&mut file, &mut hasher).expect("hash file read");
    rivect::config::hex(&hasher.finalize())
}
