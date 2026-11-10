//! AC-001/AC-028/AC-080 (TD-03): one installed bundle outside the checkout
//! activates only its exact authentic candidate. The bundle carries exactly
//! `rivect`, `rivect-sandbox-helper` beside it and `rivect.manifest.json`; the
//! manifest's own byte digest is the binding installed producers consume, and
//! the two artifact digests are the activation identity. A changed, missing or
//! malformed candidate is refused before activation and the previous release
//! stays usable, while helper or manifest omission is the discriminating
//! control that a checkout success cannot satisfy. The sessionless doctor
//! answers ready/degraded on the packaged artifact with zero writes.
//!
//! No data-resource artifact is asserted because none is shipped. Installed TP
//! rows and the UI matrix are SLICE-011/012's and are not claimed here;
//! support-export/replay carriers are not owned here either.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::let_underscore_must_use,
    let_underscore_drop,
    clippy::redundant_clone,
    reason = "test assertions fail loudly with the observed payload; src/ stays strict (standards §14)"
)]

mod support;

use rivect::contracts::{
    RELEASE_EXECUTABLE_NAME, RELEASE_HELPER_NAME, RELEASE_MANIFEST_NAME, RELEASE_MANIFEST_SCHEMA,
    ReleaseManifest,
};
use rivect::executor::{ReleaseError, verify_release_bundle};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

/// The build identity the packaged executable prints; the manifest must name
/// it exactly rather than a substituted or remembered value.
fn expected_build() -> String {
    format!(
        "rivect {} ({})",
        env!("CARGO_PKG_VERSION"),
        rivect::BUILD_ATTEMPT_ID
    )
}

/// The three bundle names in sorted order.
fn inventory(bundle: &Path) -> Vec<String> {
    let mut names = std::fs::read_dir(bundle)
        .expect("bundle inventory")
        .map(|entry| {
            entry
                .expect("bundle entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect::<Vec<_>>();
    names.sort();
    names
}

/// Copies the authentic baseline bundle into a fresh nested path.
fn copied_bundle(root: &Path, relative: &str) -> PathBuf {
    let destination = root.join(relative);
    support::release::copy_bundle(support::release::baseline_bundle(), &destination);
    destination
}

/// Verifies a bundle that must be refused and proves the refusal wrote
/// nothing into the candidate.
fn refusal(bundle: &Path) -> ReleaseError {
    let before = support::release::snapshot(bundle);
    let error = verify_release_bundle(bundle).expect_err("the candidate must be refused");
    assert_eq!(
        support::release::snapshot(bundle),
        before,
        "an activation refusal writes nothing: {}",
        bundle.display()
    );
    error
}

/// A data root this build already opened and closed: every doctor check has
/// something real to inspect.
fn opened_data_root() -> tempfile::TempDir {
    let root = tempfile::TempDir::with_prefix("rivect-release-data-").expect("data root");
    {
        let mut world = support::open_world_at(root.path(), None);
        let session = world.open_session("release-doctor");
        let _ = world.create_task(&session, "release-doctor-task");
    }
    root
}

/// A working directory whose path carries spaces and non-ASCII bytes.
fn nested_cwd(root: &Path) -> PathBuf {
    let cwd = root.join("nested working dir").join("юникод cwd");
    std::fs::create_dir_all(&cwd).expect("nested cwd");
    cwd
}

#[test]
fn packaged_bundle_outside_the_checkout_has_the_exact_inventory_and_manifest_digest() {
    let root = tempfile::TempDir::with_prefix("rivect-release-inventory-").expect("fixture root");
    let bundle = copied_bundle(root.path(), "outside checkout/юникод bundle");
    assert!(
        !bundle.starts_with(env!("CARGO_MANIFEST_DIR")),
        "the bundle is outside the checkout: {}",
        bundle.display()
    );

    let activation = verify_release_bundle(&bundle).expect("the authentic bundle activates");
    assert_eq!(
        inventory(&bundle),
        vec![
            RELEASE_EXECUTABLE_NAME.to_string(),
            RELEASE_HELPER_NAME.to_string(),
            RELEASE_MANIFEST_NAME.to_string(),
        ],
        "the bundle carries exactly the executable, the helper beside it and the manifest"
    );

    let manifest_bytes = std::fs::read(bundle.join(RELEASE_MANIFEST_NAME)).expect("manifest");
    let manifest: ReleaseManifest =
        serde_json::from_slice(&manifest_bytes).expect("manifest schema");
    assert_eq!(manifest.schema_version, RELEASE_MANIFEST_SCHEMA);
    assert_eq!(manifest.build, expected_build());
    assert_eq!(manifest.executable.name, RELEASE_EXECUTABLE_NAME);
    assert_eq!(manifest.helper.name, RELEASE_HELPER_NAME);
    assert_eq!(
        manifest.executable.sha256,
        support::release::sha256_file(&bundle.join(RELEASE_EXECUTABLE_NAME)),
        "the executable digest names its own bytes"
    );
    assert_eq!(
        manifest.helper.sha256,
        support::release::sha256_file(&bundle.join(RELEASE_HELPER_NAME)),
        "the helper digest names its own bytes"
    );

    // The manifest's byte digest, not any self-named field, is the activation
    // binding the installed producers consume.
    assert_eq!(
        activation.manifest_sha256,
        support::sha256_hex(&manifest_bytes)
    );
    assert_eq!(
        activation.manifest_sha256,
        support::release::sha256_file(&bundle.join(RELEASE_MANIFEST_NAME))
    );
    assert_eq!(activation.executable_sha256, manifest.executable.sha256);
    assert_eq!(activation.helper_sha256, manifest.helper.sha256);
    println!("release manifest sha256: {}", activation.manifest_sha256);
}

#[test]
fn a_changed_candidate_is_refused_and_the_previous_release_stays_usable() {
    let root = tempfile::TempDir::with_prefix("rivect-release-changed-").expect("fixture root");
    let previous = copied_bundle(root.path(), "previous release/юникод");
    let candidate = copied_bundle(root.path(), "candidate release/юникод");
    assert!(
        verify_release_bundle(&previous).is_ok(),
        "the previous release starts authentic"
    );

    let helper = candidate.join(RELEASE_HELPER_NAME);
    let mut bytes = std::fs::read(&helper).expect("helper bytes");
    bytes.push(0);
    std::fs::write(&helper, bytes).expect("change the candidate helper");

    let refused = refusal(&candidate);
    assert!(
        matches!(&refused, ReleaseError::Digest { name } if *name == RELEASE_HELPER_NAME),
        "{refused}"
    );

    // The refusal left the previous release untouched and usable: the exact
    // authentic bytes still verify and still run their own doctor.
    let data = opened_data_root();
    let cwd = nested_cwd(root.path());
    let before = support::release::snapshot(&previous);
    let activated = verify_release_bundle(&previous).expect("the previous release still activates");
    let output = support::release::run_packaged(
        &previous,
        &[
            "doctor",
            "--data-root",
            data.path().to_str().expect("utf-8 data root"),
        ],
        &cwd,
    );
    assert!(
        output.status.success(),
        "the previous release still runs: {}",
        support::release::stderr_of(&output)
    );
    let report: Value =
        serde_json::from_str(support::release::stdout_of(&output).trim()).expect("doctor JSON");
    assert_eq!(report["ready"], true, "{report}");
    assert_eq!(support::release::snapshot(&previous), before);

    // Packaging never replaces a destination: the refused candidate attempt
    // cannot overwrite a previous release.
    let again = support::release::package_into(&previous);
    assert!(
        !again.status.success(),
        "an existing release destination is never overwritten"
    );
    assert_eq!(
        verify_release_bundle(&previous)
            .expect("the previous release is still authentic")
            .manifest_sha256,
        activated.manifest_sha256
    );
    println!(
        "previous release manifest sha256: {}",
        activated.manifest_sha256
    );
}

#[test]
fn helper_and_manifest_omission_are_discriminating_activation_refusals() {
    let root = tempfile::TempDir::with_prefix("rivect-release-omission-").expect("fixture root");

    let helper_omitted = copied_bundle(root.path(), "helper omitted");
    std::fs::remove_file(helper_omitted.join(RELEASE_HELPER_NAME)).expect("omit the helper");
    let refused = refusal(&helper_omitted);
    assert!(
        matches!(&refused, ReleaseError::Missing { name } if *name == RELEASE_HELPER_NAME),
        "{refused}"
    );

    let manifest_omitted = copied_bundle(root.path(), "manifest omitted");
    std::fs::remove_file(manifest_omitted.join(RELEASE_MANIFEST_NAME)).expect("omit the manifest");
    let refused = refusal(&manifest_omitted);
    assert!(
        matches!(&refused, ReleaseError::Missing { name } if *name == RELEASE_MANIFEST_NAME),
        "{refused}"
    );

    let executable_omitted = copied_bundle(root.path(), "executable omitted");
    std::fs::remove_file(executable_omitted.join(RELEASE_EXECUTABLE_NAME))
        .expect("omit the executable");
    let refused = refusal(&executable_omitted);
    assert!(
        matches!(&refused, ReleaseError::Missing { name } if *name == RELEASE_EXECUTABLE_NAME),
        "{refused}"
    );

    let extra_artifact = copied_bundle(root.path(), "extra artifact");
    std::fs::write(extra_artifact.join("rivect.data.sql"), b"not shipped").expect("extra file");
    let refused = refusal(&extra_artifact);
    assert!(
        matches!(&refused, ReleaseError::UnexpectedEntry { name } if name == "rivect.data.sql"),
        "{refused}"
    );

    let bad_manifest = copied_bundle(root.path(), "bad manifest");
    std::fs::write(bad_manifest.join(RELEASE_MANIFEST_NAME), b"{ not json")
        .expect("corrupt manifest");
    let refused = refusal(&bad_manifest);
    assert!(
        matches!(&refused, ReleaseError::ManifestJson { .. }),
        "{refused}"
    );

    let incompatible = copied_bundle(root.path(), "incompatible manifest");
    let path = incompatible.join(RELEASE_MANIFEST_NAME);
    let mut document: Value =
        serde_json::from_slice(&std::fs::read(&path).expect("manifest bytes")).expect("manifest");
    document["schema_version"] = json!(RELEASE_MANIFEST_SCHEMA + 1);
    std::fs::write(&path, document.to_string()).expect("incompatible manifest");
    let refused = refusal(&incompatible);
    assert!(
        matches!(
            &refused,
            ReleaseError::Schema { found, expected }
                if *found == RELEASE_MANIFEST_SCHEMA + 1 && *expected == RELEASE_MANIFEST_SCHEMA
        ),
        "{refused}"
    );

    // The control: the untouched bundle still activates, so each refusal
    // above is the omission or mutation, not a baseline that never worked.
    assert!(verify_release_bundle(support::release::baseline_bundle()).is_ok());
}

#[test]
fn sessionless_doctor_answers_ready_and_degraded_on_the_packaged_artifact_with_zero_writes() {
    let root = tempfile::TempDir::with_prefix("rivect-release-doctor-").expect("fixture root");
    let bundle = copied_bundle(root.path(), "installed bundle/юникод release");
    let cwd = nested_cwd(root.path());
    let data = opened_data_root();
    let data_argument = data.path().to_str().expect("utf-8 data root");

    let activation = verify_release_bundle(&bundle).expect("the packaged bundle activates");
    let before_bundle = support::release::snapshot(&bundle);
    let before_data = support::release::snapshot(data.path());
    let ready =
        support::release::run_packaged(&bundle, &["doctor", "--data-root", data_argument], &cwd);
    assert!(
        ready.status.success(),
        "the packaged doctor is ready: {}",
        support::release::stderr_of(&ready)
    );
    let report: Value =
        serde_json::from_str(support::release::stdout_of(&ready).trim()).expect("doctor JSON");
    assert_eq!(report["kind"], "doctor", "{report}");
    assert_eq!(report["ready"], true, "{report}");
    let release = report["checks"]
        .as_array()
        .expect("checks")
        .iter()
        .find(|check| check["name"] == "release")
        .expect("release check");
    assert_eq!(release["state"], "ready", "{release}");
    assert!(
        release["detail"]
            .as_str()
            .expect("release detail")
            .contains(&activation.manifest_sha256[..12]),
        "the doctor names the packaged manifest digest: {release}"
    );
    assert_eq!(
        support::release::snapshot(&bundle),
        before_bundle,
        "doctor wrote nothing into the packaged bundle"
    );
    assert_eq!(
        support::release::snapshot(data.path()),
        before_data,
        "doctor wrote nothing into the data root"
    );

    // Degraded: the same packaged artifact after its helper disappears.
    let broken = copied_bundle(root.path(), "broken bundle/юникод release");
    std::fs::remove_file(broken.join(RELEASE_HELPER_NAME)).expect("omit the helper");
    let before_broken = support::release::snapshot(&broken);
    let before_data = support::release::snapshot(data.path());
    let degraded =
        support::release::run_packaged(&broken, &["doctor", "--data-root", data_argument], &cwd);
    assert_eq!(
        degraded.status.code(),
        Some(3),
        "a degraded packaged artifact is not ready: {}",
        support::release::stderr_of(&degraded)
    );
    let report: Value =
        serde_json::from_str(support::release::stdout_of(&degraded).trim()).expect("doctor JSON");
    assert_eq!(report["ready"], false, "{report}");
    let release = report["checks"]
        .as_array()
        .expect("checks")
        .iter()
        .find(|check| check["name"] == "release")
        .expect("release check");
    assert_eq!(release["state"], "degraded", "{release}");
    assert!(
        release["detail"]
            .as_str()
            .expect("release detail")
            .contains("refused"),
        "the degraded release check names the refusal: {release}"
    );
    assert_eq!(
        support::release::snapshot(&broken),
        before_broken,
        "the degraded doctor wrote nothing into the bundle"
    );
    assert_eq!(
        support::release::snapshot(data.path()),
        before_data,
        "the degraded doctor wrote nothing into the data root"
    );
}
