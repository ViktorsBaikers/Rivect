//! Producer of the confined helper binary for every test that launches
//! it: the integration suites reach it through `support`, and the
//! in-crate tests through `src/executor.rs`, which includes this file by
//! `#[path]`.

use std::sync::Once;

/// The only parent environment the helper build inherits, copied by value
/// when set (standards §10): what cargo and rustup need to locate the
/// toolchain, the target directory and a temporary directory.
const HELPER_BUILD_ENV: [&str; 9] = [
    "PATH",
    "HOME",
    "CARGO_HOME",
    "CARGO_TARGET_DIR",
    "RUSTUP_HOME",
    "RUSTUP_TOOLCHAIN",
    "TMPDIR",
    "LANG",
    "LC_ALL",
];

pub fn ensure_helper() {
    static BUILD: Once = Once::new();
    BUILD.call_once(|| {
        let mut command = std::process::Command::new(env!("CARGO"));
        command
            .args([
                "build",
                "--locked",
                "--offline",
                "-p",
                "rivect-sandbox-helper",
            ])
            .env_clear();
        for name in HELPER_BUILD_ENV {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        let status = command.status().expect("spawn helper build");
        assert!(status.success(), "helper build failed: {status}");
    });
}
