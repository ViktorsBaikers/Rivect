//! AC-015 (REQ-012): a capability generation is published as a whole, or the
//! resources its prepare acquired are released. Each conjunct runs on the real
//! filesystem: every generation owns one root, and the assertion is the
//! directory's existence, not a bookkeeping flag. The launch cases drive the
//! entry the product calls: a generation is prepared before the first owned
//! artifact, published when the child starts, and released when the launch is
//! abandoned.

#![allow(
    clippy::expect_used,
    clippy::panic,
    reason = "test fixtures use expect for setup failures and panic on wrong outcomes (standards §14)"
)]

mod support;

use rivect::contracts::ErrorCode;
use rivect::executor::{LAUNCH_EXECUTOR, PreparedLaunch, launch_resource_scope};
#[cfg(target_os = "linux")]
use rivect::executor::{OwnedLaunchError, WorkerError, linux};
use rivect::resources::{
    CAPABILITY_GENERATION_RETENTION, CapabilityGenerations, ResourceError, ResourceHolderStatus,
    capability_generations,
};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Mutex, MutexGuard, PoisonError};

const EXECUTOR: &str = "rivect-executor";
const SCOPE: &str = "capability";

fn scratch() -> tempfile::TempDir {
    tempfile::tempdir().expect("a scratch capability root")
}

fn root_of(parent: &Path, generation: u64) -> PathBuf {
    CapabilityGenerations::generation_root(parent, SCOPE, generation)
}

/// One dependency root as it appears on disk for one generation.
fn dependency(parent: &Path, generation: u64, id: &str) -> PathBuf {
    root_of(parent, generation).join(id)
}

fn published(generations: &mut CapabilityGenerations, parent: &Path, dependencies: &[&str]) -> u64 {
    let prepared = generations
        .prepare(parent, EXECUTOR, SCOPE, dependencies)
        .expect("a dependency set with no repeats prepares");
    let generation = prepared.owner_generation;
    generations
        .publish(prepared)
        .expect("a freshly prepared generation publishes");
    generation
}

#[test]
fn failed_prepare_publishes_nothing_p1() {
    let scratch = scratch();
    let root = scratch.path();
    let mut generations = CapabilityGenerations::new();
    let first = published(&mut generations, root, &["read_file", "grep"]);

    // The second generation repeats one dependency, so its third acquisition
    // meets an existing root and fails at the substrate.
    let failure = generations
        .prepare(root, EXECUTOR, SCOPE, &["write_file", "grep", "write_file"])
        .expect_err("a generation that names one dependency twice cannot prepare");
    match &failure {
        ResourceError::Acquire {
            boundary,
            disposition,
            ..
        } => {
            assert_eq!(*boundary, "capability.prepare.dependency");
            assert_eq!(
                *disposition,
                ResourceHolderStatus::Terminated,
                "the failed prepare released every root it had acquired"
            );
        }
        other => panic!("an acquisition failure is the expected refusal: {other}"),
    }
    assert_eq!(failure.code(), ErrorCode::DependencyBlocked);

    assert_eq!(
        generations.current_generation(),
        Some(first),
        "a failed prepare publishes nothing"
    );
    let registration = generations
        .registered(EXECUTOR)
        .expect("the published generation still answers for its name");
    assert_eq!(registration.owner_generation, first);
    assert_eq!(
        registration.acquired(),
        [
            dependency(root, first, "read_file"),
            dependency(root, first, "grep")
        ],
        "no partially equipped executor is registered in its place"
    );

    assert!(
        !root_of(root, first + 1).exists(),
        "the resources the failed prepare acquired are absent from the filesystem"
    );
    assert!(
        dependency(root, first, "grep").is_dir(),
        "the published generation keeps its own dependencies"
    );

    // A reserved number is never reissued, so a root that already exists
    // refuses the prepare that would reuse the number.
    let reused = root_of(root, first + 2);
    std::fs::create_dir(&reused).expect("an occupant of the next number's root");
    let failure = generations
        .prepare(root, EXECUTOR, SCOPE, &["read_file"])
        .expect_err("a reused generation number cannot prepare");
    assert!(
        matches!(
            &failure,
            ResourceError::Acquire {
                boundary: "capability.prepare.root",
                ..
            }
        ),
        "the refusal names the root that was already taken: {failure}"
    );
    assert_eq!(generations.current_generation(), Some(first));
    std::fs::remove_dir_all(root_of(root, first + 2)).expect("the occupant is the fixture's");
}

#[test]
fn late_disposer_cannot_remove_the_new_registration_p2() {
    let scratch = scratch();
    let root = scratch.path();
    let mut generations = CapabilityGenerations::new();
    let first = published(&mut generations, root, &["read_file"]);
    let second = published(&mut generations, root, &["read_file", "grep"]);

    // Generation 1's disposer runs after generation 2 published.
    let refusal = generations
        .dispose(first)
        .expect_err("a disposer of the superseded generation is refused");
    assert!(
        matches!(refusal, ResourceError::AlreadyRetired { generation } if generation == first),
        "the refusal names the generation it carried: {refusal}"
    );
    assert_eq!(refusal.code(), ErrorCode::AlreadyTerminal);

    let registration = generations
        .registered(EXECUTOR)
        .expect("the newer registration of the same name stays available");
    assert_eq!(registration.owner_generation, second);
    assert_eq!(
        registration.acquired(),
        [
            dependency(root, second, "read_file"),
            dependency(root, second, "grep")
        ],
        "the stale disposer leaves the newer registration unchanged"
    );
    assert!(
        dependency(root, second, "grep").is_dir(),
        "and leaves its resources in place"
    );

    // The refusal grants nothing: the stale number stays retired, and the
    // current generation still disposes under its own number.
    assert!(matches!(
        generations.dispose(first),
        Err(ResourceError::AlreadyRetired { generation }) if generation == first
    ));
    assert_eq!(
        generations
            .dispose(second)
            .expect("the current generation disposes under its own number"),
        ResourceHolderStatus::Terminated
    );

    // A number this registry never made current is unknown, never answered
    // with another generation's registration.
    let unknown = generations
        .dispose(second + 7)
        .expect_err("a never-current number disposes nothing");
    assert!(
        matches!(unknown, ResourceError::Unknown { carried } if carried == second + 7),
        "the refusal names the number it could not place: {unknown}"
    );
    assert_eq!(unknown.code(), ErrorCode::NotFound);

    // The retired window is bounded: a number past it reports unknown rather
    // than a stale registration it cannot prove. The oldest number needs one
    // publish beyond the window's depth to be pushed out of it.
    let mut bounded = CapabilityGenerations::new();
    let oldest = published(&mut bounded, root, &["read_file"]);
    for _ in 0..=CAPABILITY_GENERATION_RETENTION {
        published(&mut bounded, root, &["read_file"]);
    }
    assert!(
        matches!(
            bounded.dispose(oldest),
            Err(ResourceError::Unknown { carried }) if carried == oldest
        ),
        "retention bounds the registry: a number past the window is unknown"
    );
}

#[test]
fn retired_generation_releases_owned_resources_p3() {
    let scratch = scratch();
    let root = scratch.path();
    let mut generations = CapabilityGenerations::new();
    let first = published(&mut generations, root, &["read_file"]);
    assert!(root_of(root, first).is_dir());
    assert!(dependency(root, first, "read_file").is_dir());

    let census_before = dependency(root, first, "read_file").exists();
    let second = published(&mut generations, root, &["read_file", "grep"]);

    assert!(census_before);
    assert!(
        !root_of(root, first).exists(),
        "the retired generation's owned resources are gone"
    );
    assert!(
        dependency(root, second, "read_file").is_dir() && dependency(root, second, "grep").is_dir(),
        "the current generation's resources remain"
    );
    assert_eq!(
        generations
            .registered(EXECUTOR)
            .map(|holder| holder.owner_generation),
        Some(second),
        "retirement moves the registration, it does not widen it"
    );

    // A prepare that is never published owns its roots until it is dropped.
    let unused = generations
        .prepare(root, "unused-executor", SCOPE, &["read_file"])
        .expect("a fresh generation prepares");
    assert!(root_of(root, unused.owner_generation).is_dir());
    let unused_root = root_of(root, unused.owner_generation);
    drop(unused);
    assert!(
        !unused_root.exists(),
        "prepared-but-unused owned resources are released"
    );
    assert_eq!(generations.current_generation(), Some(second));
}

#[test]
fn a_name_that_leaves_the_generation_root_is_refused_p5() {
    let scratch = scratch();
    let root = scratch.path();
    let mut generations = CapabilityGenerations::new();

    for (scope, dependencies) in [
        ("../../escape", &["read_file"][..]),
        (SCOPE, &["../escape"][..]),
        (SCOPE, &["a/b"][..]),
    ] {
        let refusal = generations
            .prepare(root, EXECUTOR, scope, dependencies)
            .expect_err("a name that is not one segment prepares nothing");
        assert!(
            matches!(refusal, ResourceError::NotOneSegment { .. }),
            "the refusal names the boundary it enforced: {refusal}"
        );
        assert_eq!(refusal.code(), ErrorCode::InvalidInput);
    }

    assert_eq!(
        generations.current_generation(),
        None,
        "a refused name publishes nothing"
    );
    assert!(
        !root.join("escape").exists() && !root.join("a").exists(),
        "and creates nothing outside a generation root"
    );
}

// ----- the launch path: prepare, publish, release -------------------------

/// The launch cases read one process-wide registry, so they run one at a time:
/// an interleaved case would publish between the generations another case
/// asserts.
static LAUNCH_CASES: Mutex<()> = Mutex::new(());

fn launch_case() -> MutexGuard<'static, ()> {
    LAUNCH_CASES.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The generation root one launch owns under the launch's resource scope.
fn launch_root(generation: u64) -> PathBuf {
    CapabilityGenerations::generation_root(
        &std::env::temp_dir(),
        launch_resource_scope(),
        generation,
    )
}

/// The published generation, read from the registry the launch published into.
fn published_generation() -> u64 {
    capability_generations()
        .current_generation()
        .expect("a started launch publishes its generation")
}

/// One real launch: a bounded child that exits at once, through the launch
/// entry the product calls.
fn started_launch() {
    let mut launch = PreparedLaunch::direct("/bin/true");
    launch
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let output = launch.run(&[]).expect("a bounded launch of /bin/true");
    assert!(
        output.status.success(),
        "the launched child ran to completion: {}",
        output.status
    );
}

#[cfg(target_os = "linux")]
#[test]
fn launch_abandon_releases_its_own_generation_p1() {
    let _serial = launch_case();
    support::ensure_helper();
    started_launch();
    let first = published_generation();

    // A payload for the helper that omits the `--` delimiter refuses after the
    // launch prepared its generation and before it starts a child.
    let trusted = rivect_sandbox_helper::owned_helper_binary()
        .expect("the installed native owner is present");
    let mut launch = PreparedLaunch::direct(trusted);
    launch.arg("launch");
    let error = launch
        .run(&[])
        .expect_err("a helper payload with no delimiter refuses before the child starts");
    assert!(
        matches!(
            &error,
            WorkerError::OwnedLaunch { source }
                if matches!(source.as_ref(), OwnedLaunchError::Observation { boundary: "owned.prepare.create", .. })
        ),
        "the refusal is the launch's own preparation boundary: {error}"
    );

    assert_eq!(
        published_generation(),
        first,
        "a launch that fails before the child starts publishes nothing"
    );
    let abandoned = first + 1;
    assert!(
        !launch_root(abandoned).exists(),
        "the roots the abandoned launch acquired are gone"
    );
    assert!(
        launch_root(first).is_dir(),
        "the generation a started launch published keeps its root"
    );

    // The abandoned number is retired, not merely unknown: the release ran
    // through the registry, so no later launch can publish it.
    let refusal = capability_generations()
        .dispose(abandoned)
        .expect_err("an abandoned generation is never current to dispose");
    assert!(
        matches!(refusal, ResourceError::AlreadyRetired { generation } if generation == abandoned),
        "the abandonment retired the number it had prepared: {refusal}"
    );

    started_launch();
    assert_eq!(
        published_generation(),
        abandoned + 1,
        "the next launch publishes the generation after the abandoned one"
    );
}

#[test]
fn launch_publishes_one_generation_p2() {
    let _serial = launch_case();
    support::ensure_helper();
    started_launch();
    let first = published_generation();
    assert!(
        launch_root(first).is_dir(),
        "the published generation owns the root the launch acquired"
    );
    assert_eq!(
        capability_generations()
            .registered(LAUNCH_EXECUTOR)
            .map(|holder| holder.owner_generation),
        Some(first),
        "the started launch registered the generation it published"
    );

    started_launch();
    assert_eq!(
        published_generation(),
        first + 1,
        "a started launch publishes exactly one generation"
    );
    assert!(
        !launch_root(first).exists(),
        "the replaced generation's roots are absent"
    );
    assert!(
        launch_root(first + 1).is_dir(),
        "the current generation keeps its own resources"
    );
}

#[test]
fn stale_disposer_refuses_through_the_launch_p3() {
    let _serial = launch_case();
    support::ensure_helper();
    started_launch();
    let first = published_generation();
    started_launch();
    let second = published_generation();
    assert_eq!(
        second,
        first + 1,
        "each launch publishes its own generation"
    );

    // A disposer carrying the replaced generation runs after the newer launch
    // published.
    let refusal = capability_generations()
        .dispose(first)
        .expect_err("a disposer of the replaced generation is refused");
    assert!(
        matches!(refusal, ResourceError::AlreadyRetired { generation } if generation == first),
        "the refusal names the generation it carried: {refusal}"
    );
    assert_eq!(refusal.code(), ErrorCode::AlreadyTerminal);

    let registered = {
        let registry = capability_generations();
        registry
            .registered(LAUNCH_EXECUTOR)
            .map(|holder| holder.owner_generation)
    };
    assert_eq!(
        registered,
        Some(second),
        "the stale disposer leaves the newer registration readable"
    );
    assert!(
        launch_root(second).is_dir(),
        "and leaves the newer generation's resources in place"
    );
    assert!(
        !launch_root(first).exists(),
        "the retired generation's owned resources are gone"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn production_entry_prepares_and_publishes_p4() {
    let _serial = launch_case();
    support::ensure_helper();
    let replaced = capability_generations().current_generation();

    let artifact = linux::denied_exec_control().expect("a worker-owned control program artifact");
    let outcome = linux::run_confined_owned(
        &linux::SandboxLauncher::default(),
        &linux::egress_confinement(),
        artifact,
        &[],
    )
    .expect("a confined run of a worker-owned control program");
    assert!(
        outcome.exit_ok,
        "the confined control program ran inside the boundary: {outcome:?}"
    );

    let published = published_generation();
    assert_eq!(
        published,
        replaced.unwrap_or(0) + 1,
        "the production entry published the generation after the previous one"
    );
    let registered = {
        let registry = capability_generations();
        registry
            .registered(LAUNCH_EXECUTOR)
            .map(|holder| holder.owner_generation)
    };
    assert_eq!(
        registered,
        Some(published),
        "the production entry registered the generation it published"
    );
    assert!(
        launch_root(published).is_dir(),
        "the published generation owns the root the production entry acquired"
    );
    if let Some(replaced) = replaced {
        assert!(
            !launch_root(replaced).exists(),
            "the replaced generation's roots are gone"
        );
    }
}

#[test]
fn stale_prepare_cannot_publish_over_a_newer_registration_p4() {
    let scratch = scratch();
    let root = scratch.path();
    let mut generations = CapabilityGenerations::new();
    let first = generations
        .prepare(root, EXECUTOR, SCOPE, &["read_file"])
        .expect("generation 1 prepares");
    let second = generations
        .prepare(root, EXECUTOR, SCOPE, &["read_file", "grep"])
        .expect("generation 2 prepares");
    generations.publish(second).expect("generation 2 publishes");

    // Generation 1's prepare finishes late, after generation 2 is current.
    let first_root = root_of(root, 1);
    let refusal = generations
        .publish(first)
        .expect_err("a stale generation cannot replace the current one");
    assert!(
        matches!(
            refusal,
            ResourceError::Superseded {
                carried: 1,
                current: 2
            }
        ),
        "the refusal names both generations: {refusal}"
    );
    assert_eq!(refusal.code(), ErrorCode::StaleIntent);
    assert_eq!(generations.current_generation(), Some(2));
    assert!(
        !first_root.exists(),
        "the refused generation released what it had prepared"
    );
    assert!(
        dependency(root, 2, "grep").is_dir(),
        "the current registration keeps its resources"
    );
}
