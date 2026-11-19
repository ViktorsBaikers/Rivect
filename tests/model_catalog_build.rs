//! Exercise Cargo's actual build hook without rebuilding Rivect or mutating the checkout.

use std::error::Error;
use std::fs;
use std::path::Path;
use std::process::Command;

#[test]
fn cargo_rejects_invalid_model_catalog_rows() -> Result<(), Box<dyn Error>> {
    let project = tempfile::tempdir()?;
    let root = project.path();
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname='catalog-probe'\nversion='0.0.0'\nedition='2024'\n[lib]\npath='lib.rs'\n",
    )?;
    fs::write(root.join("lib.rs"), "")?;
    let source = Path::new(env!("CARGO_MANIFEST_DIR"));
    fs::copy(source.join("build.rs"), root.join("build.rs"))?;
    let dir = root.join("src/providers");
    fs::create_dir_all(&dir)?;
    let catalog = dir.join("models-v1.tsv");
    let shipped = fs::read_to_string(source.join("src/providers/models-v1.tsv"))?;
    let mut cargo = Command::new(env!("CARGO"));
    cargo
        .env_clear()
        .env("CARGO_HOME", root.join("cargo-home"))
        .args(["check", "--offline", "--quiet"])
        .current_dir(root);
    for name in ["PATH", "HOME", "RUSTUP_HOME", "RUSTUP_TOOLCHAIN", "TMPDIR"] {
        if let Some(value) = std::env::var_os(name) {
            cargo.env(name, value);
        }
    }
    fs::write(
        &catalog,
        format!("{shipped}\nopenai\toffline-probe\nmeta\toffline-probe\n"),
    )?;
    let valid = cargo.output()?;
    assert!(
        valid.status.success(),
        "{}",
        String::from_utf8_lossy(&valid.stderr)
    );
    for (row, diagnostic) in [
        ("openai\tgpt-5.2", "duplicate model key"),
        ("github-copilot\ttest-model\tmissing", "unknown dialect"),
        (
            "gitlab-duo\ttest-alias\tresponses\tclaude-opus-4-6",
            "conflicting alias target",
        ),
        (
            "gitlab-duo\tclaude-opus-4-6\tmessages\tanother",
            "conflicting alias target",
        ),
        ("github-copilot\ttest-model\tgemini", "unknown dialect"),
        ("nonexistent-provider\tprobe", "unknown provider"),
    ] {
        fs::write(&catalog, format!("{shipped}\n{row}\n"))?;
        let output = cargo.output()?;
        assert!(!output.status.success(), "cargo accepted {row}");
        let stderr = String::from_utf8(output.stderr)?;
        assert!(stderr.contains(diagnostic), "{stderr}");
    }
    Ok(())
}
