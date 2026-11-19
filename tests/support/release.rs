//! One verified installed candidate, outside the checkout. A supplied
//! bundle and its installer's receipt stay untouched; cases mutate only copies.

use rivect::contracts::{RELEASE_MANIFEST_NAME, RELEASE_MANIFEST_SCHEMA_V2, ReleaseManifest};
use rivect::executor::verify_release_bundle;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::LazyLock;

#[path = "packaging.rs"]
mod packaging;
use packaging::candidate_command;

struct Baseline {
    // The baseline root outlives every copy and keeps the fixture honest.
    _root: tempfile::TempDir,
    bundle: PathBuf,
}

fn supplied_bundle() -> Option<PathBuf> {
    let configured = |key| {
        std::env::var_os(key).map(|value| {
            std::fs::canonicalize(value).unwrap_or_else(|err| panic!("invalid {key}: {err}"))
        })
    };
    match (
        configured("RIVECT_V2_TEST_BUNDLE"),
        configured("RIVECT_TEST_BUNDLE"),
    ) {
        (Some(explicit), Some(active)) => {
            assert_eq!(explicit, active, "the v2 candidate selectors disagree");
            Some(explicit)
        }
        (explicit, active) => explicit.or(active),
    }
}

fn baseline() -> Baseline {
    let root =
        tempfile::TempDir::with_prefix("rivect-release-baseline-").expect("baseline fixture root");
    let root_path = root.path().canonicalize().expect("canonical baseline root");
    let checkout = Path::new(env!("CARGO_MANIFEST_DIR"))
        .canonicalize()
        .expect("canonical checkout root");
    assert!(
        !root_path.starts_with(&checkout),
        "the baseline fixture must be outside the checkout"
    );
    let bundle = root_path
        .join("nested release space")
        .join("юникод package");
    let supplied = if let Some(source) = supplied_bundle() {
        assert!(
            !source.starts_with(&checkout),
            "the supplied release bundle must be outside the checkout"
        );
        let activation =
            verify_release_bundle(&source).expect("the supplied release bundle must be authentic");
        assert_schema(&source);
        copy_bundle(&source, &bundle);
        Some(activation)
    } else {
        let output = package_into(&bundle);
        assert!(
            output.status.success(),
            "the packaged baseline refused: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        None
    };
    let activation = verify_release_bundle(&bundle).expect("the private release must be authentic");
    assert_schema(&bundle);
    if let Some(supplied) = supplied {
        assert_eq!(activation, supplied, "copy changed the activation identity");
    }
    let expected_build = format!(
        "rivect {} ({})",
        env!("CARGO_PKG_VERSION"),
        rivect::BUILD_ATTEMPT_ID
    );
    assert_eq!(
        activation.build, expected_build,
        "the manifest must match the test build"
    );
    let version = run_packaged(&bundle, &["--version"], &root_path);
    assert!(
        version.status.success(),
        "version probe refused: {}",
        stderr_of(&version)
    );
    assert_eq!(
        stdout_of(&version).trim(),
        expected_build,
        "the executable must match the test build"
    );
    Baseline {
        _root: root,
        bundle,
    }
}

fn assert_schema(bundle: &Path) {
    let bytes = std::fs::read(bundle.join(RELEASE_MANIFEST_NAME)).expect("verified manifest");
    let manifest: ReleaseManifest = serde_json::from_slice(&bytes).expect("verified schema");
    assert_eq!(
        manifest.schema_version, RELEASE_MANIFEST_SCHEMA_V2,
        "wrong installed package format"
    );
}

/// The verified v2 candidate used by installed acceptance producers.
pub fn baseline_bundle() -> &'static Path {
    static CANDIDATE: LazyLock<Baseline> = LazyLock::new(baseline);
    &CANDIDATE.bundle
}

/// Packages a v2 bundle into a fresh destination.
pub fn package_into(destination: &Path) -> Output {
    candidate_command(destination)
        .output()
        .expect("run package-release.sh")
}

/// Runs the packaged executable from `bundle` in `cwd` with a clean
/// environment and only the variables a process needs.
pub fn run_packaged(bundle: &Path, args: &[&str], cwd: &Path) -> Output {
    let home = tempfile::tempdir().expect("private packaged process home");
    let mut command = Command::new(bundle.join("rivect"));
    command
        .args(args)
        .current_dir(cwd)
        .env_clear()
        .env("HOME", home.path())
        .env("TMPDIR", home.path());
    for name in ["PATH", "LANG", "LC_ALL"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command.output().expect("run the packaged rivect")
}

/// Copies a verified bundle and its external receipt into a fresh location.
pub fn copy_bundle(source: &Path, destination: &Path) {
    std::fs::create_dir_all(destination.parent().expect("bundle parent")).expect("copy parent");
    copy_directory(source, destination);
    let receipt = source.with_added_extension("manifest.sha256");
    let target = destination.with_added_extension("manifest.sha256");
    let mut input = std::fs::File::open(receipt).expect("source receipt");
    let mut output = std::fs::File::create_new(target).expect("fresh receipt destination");
    std::io::copy(&mut input, &mut output).expect("copy authoritative receipt");
}

fn copy_directory(source: &Path, destination: &Path) {
    std::fs::create_dir(destination).expect("fresh bundle directory");
    for entry in std::fs::read_dir(source).expect("bundle inventory") {
        let entry = entry.expect("bundle entry");
        let kind = entry.file_type().expect("bundle entry type");
        let target = destination.join(entry.file_name());
        if kind.is_dir() {
            copy_directory(&entry.path(), &target);
        } else {
            assert!(
                kind.is_file(),
                "bundle copy refuses links and special files"
            );
            std::fs::copy(entry.path(), target).expect("copy bundle artifact");
        }
    }
}

/// Every path under `root` with its length and content digest, sorted: the
/// zero-write oracle. The digest is what makes a same-length in-place rewrite
/// visible; a directory records the fixed `dir` marker.
pub fn snapshot(root: &Path) -> Vec<(PathBuf, u64, String)> {
    let mut entries = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(&directory).expect("snapshot inventory") {
            let entry = entry.expect("snapshot entry");
            let path = entry.path();
            let metadata = entry.metadata().expect("snapshot metadata");
            let digest = if metadata.is_dir() {
                "dir".to_string()
            } else {
                sha256_file(&path)
            };
            entries.push((path.clone(), metadata.len(), digest));
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
