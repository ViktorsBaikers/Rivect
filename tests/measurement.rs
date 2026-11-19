//! Candidate-only package and headless measurements, not an AC-003 verdict.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::let_underscore_must_use,
    let_underscore_drop,
    clippy::redundant_clone,
    reason = "test code keeps unwrap/expect/panic/discard conveniences; src/ stays strict (standards §14)"
)]

mod support;

use rivect::contracts::{RELEASE_EXECUTABLE_NAME, RELEASE_HELPER_NAME, RELEASE_MANIFEST_NAME};
use rivect::resources::{
    CorpusLeg, KitMeasurement, LegLimit, LegSamples, LimitBreach, MeasurementGap, NotRun,
    OwnedSample, OwnedTotals, PROVIDER_CACHE_TRIALS, PROVIDER_LEGS, Platform, ReleaseLimits,
    ReleaseReport, ReleaseVerdict,
};
use rivect::state::CacheRate;
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{ChildStdin, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

const RESOURCE_PREREQUISITE: &str = "missing exact candidate resource observations";

/// The only parent environment an installed child inherits: what a process
/// needs to locate its roots and the toolchain, never a secret (standards §10).
const CHILD_ENV: [&str; 4] = ["PATH", "TMPDIR", "LANG", "LC_ALL"];

/// Linux `/proc/<pid>/stat` CPU accounting uses clock ticks, not nanoseconds.
const USER_HZ_NANOS: u64 = 10_000_000;

const SAMPLE_TIMEOUT: Duration = Duration::from_secs(300);

fn child_command(program: &Path, cwd: &Path) -> Command {
    let mut command = Command::new(program);
    command.current_dir(cwd).env_clear();
    for name in CHILD_ENV {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        command.process_group(0);
    }
    command
}

fn cpu_nanos(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // The comm field may carry spaces and parentheses; the fields after the
    // last ')' are fixed, and utime/stime are fields 14/15 of the record.
    let mut fields = stat.rsplit_once(')')?.1.split_whitespace();
    let utime: u64 = fields.nth(11)?.parse().ok()?;
    let stime: u64 = fields.next()?.parse().ok()?;
    Some(utime.saturating_add(stime).saturating_mul(USER_HZ_NANOS))
}

fn observe(observations: &mut Vec<OwnedSample>, leader: u32) -> u64 {
    // The leader is read before the group scan: a short sample can exit while
    // the scan itself runs, and its resident set is only readable before then.
    let mut group_rss = rivect_sandbox_helper::resident_bytes(leader).unwrap_or(0);
    if let Some(cpu_nanos) = cpu_nanos(leader) {
        observations.push(OwnedSample {
            pid: leader,
            cpu_nanos,
        });
    }
    let Ok(members) = rivect_sandbox_helper::process_group_members(leader) else {
        return group_rss;
    };
    for pid in members {
        if pid == leader {
            continue;
        }
        if let Some(cpu_nanos) = cpu_nanos(pid) {
            observations.push(OwnedSample { pid, cpu_nanos });
        }
        group_rss =
            group_rss.saturating_add(rivect_sandbox_helper::resident_bytes(pid).unwrap_or(0));
    }
    group_rss
}

#[derive(Debug, Clone, Copy)]
enum Dialogue {
    Cancel,
    Search,
    Index,
    LongSession { turns: usize },
}

struct Sample {
    nanos: u64,
    owned: Vec<OwnedSample>,
    peak_rss_bytes: u64,
}

fn request(
    stdin: &mut ChildStdin,
    reader: &mut BufReader<ChildStdout>,
    frame: &Value,
) -> std::io::Result<Value> {
    writeln!(stdin, "{frame}")?;
    stdin.flush()?;
    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "the installed candidate closed stdout before it answered",
        ));
    }
    let answer: Value = serde_json::from_str(&line)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    if let Some(error) = answer.get("error") {
        return Err(std::io::Error::other(format!(
            "the installed candidate refused a corpus frame: {error}"
        )));
    }
    Ok(answer)
}

fn attach(stdin: &mut ChildStdin, reader: &mut BufReader<ChildStdout>) -> std::io::Result<String> {
    let answer = request(
        stdin,
        reader,
        &json!({
            "jsonrpc": "2.0", "id": 1, "method": "session.attach",
            "params": { "schema_version": 1, "bootstrap_id": "measurement-corpus" }
        }),
    )?;
    answer
        .pointer("/result/session_id")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| std::io::Error::other("the attach answer names no session"))
}

fn create_task(
    stdin: &mut ChildStdin,
    reader: &mut BufReader<ChildStdout>,
    session: &str,
) -> std::io::Result<Value> {
    request(
        stdin,
        reader,
        &json!({
            "jsonrpc": "2.0", "id": 2, "method": "task.submit",
            "params": {
                "schema_version": 1, "command_id": "measurement-create",
                "session_id": session, "kind": "create",
                "goal": "Explain the measured topic.",
                "contract": {
                    "criteria": ["Give the measured explanation."],
                    "constraints": ["Do not change files."]
                },
                "attachments": []
            }
        }),
    )
}

fn dialogue_run(
    stdin: &mut ChildStdin,
    reader: &mut BufReader<ChildStdout>,
    dialogue: Dialogue,
) -> std::io::Result<()> {
    let session = attach(stdin, reader)?;
    match dialogue {
        Dialogue::Cancel => {
            let created = create_task(stdin, reader, &session)?;
            let task = created
                .pointer("/result/task_id")
                .and_then(Value::as_str)
                .ok_or_else(|| std::io::Error::other("the create answer names no task"))?;
            request(
                stdin,
                reader,
                &json!({
                    "jsonrpc": "2.0", "id": 3, "method": "task.submit",
                    "params": {
                        "schema_version": 1, "command_id": "measurement-cancel",
                        "session_id": session, "kind": "cancel",
                        "task_id": task, "expected_intent_revision": 1,
                        "reason": "measurement cancel"
                    }
                }),
            )?;
        }
        Dialogue::Search => {
            create_task(stdin, reader, &session)?;
            request(
                stdin,
                reader,
                &json!({
                    "jsonrpc": "2.0", "id": 3, "method": "command.execute",
                    "params": {
                        "schema_version": 1, "session_id": session,
                        "command": { "kind": "session.search" },
                        "query": "Explain", "page": { "page_size": 20 }
                    }
                }),
            )?;
        }
        Dialogue::Index => {
            request(
                stdin,
                reader,
                &json!({
                    "jsonrpc": "2.0", "id": 3, "method": "command.execute",
                    "params": {
                        "schema_version": 1, "session_id": session,
                        "command": { "kind": "project.init" }
                    }
                }),
            )?;
        }
        Dialogue::LongSession { turns } => {
            for turn in 0..turns {
                request(
                    stdin,
                    reader,
                    &json!({
                        "jsonrpc": "2.0", "id": 10 + turn, "method": "runtime.status",
                        "params": {
                            "schema_version": 1, "session_id": session,
                            "page": { "page_size": 20 }
                        }
                    }),
                )?;
            }
        }
    }
    Ok(())
}

/// Runs one installed sample, sampling the owned process group every
/// millisecond. A dialogue thread drives the piped JSON-RPC frames while this
/// thread observes; both are joined before the sample answers.
fn run_sample(program: &Path, args: &[&str], cwd: &Path, dialogue: Option<Dialogue>) -> Sample {
    let mut command = child_command(program, cwd);
    command.args(args).env("HOME", cwd).stderr(Stdio::null());
    if dialogue.is_some() {
        command.stdin(Stdio::piped()).stdout(Stdio::piped());
    } else {
        command.stdin(Stdio::null()).stdout(Stdio::null());
    }
    let started = Instant::now();
    let mut child = command.spawn().expect("the installed candidate spawns");
    let driver = dialogue.map(|dialogue| {
        let mut stdin = child.stdin.take().expect("the sample owns piped stdin");
        let mut reader = BufReader::new(child.stdout.take().expect("the sample owns piped stdout"));
        std::thread::spawn(move || dialogue_run(&mut stdin, &mut reader, dialogue))
    });
    let mut observations = Vec::new();
    let mut peak_rss_bytes = 0u64;
    let deadline = started + SAMPLE_TIMEOUT;
    let status = loop {
        if cfg!(target_os = "linux") {
            peak_rss_bytes = peak_rss_bytes.max(observe(&mut observations, child.id()));
        }
        match child
            .try_wait()
            .expect("the installed candidate is observable")
        {
            Some(status) => break status,
            None if Instant::now() > deadline => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("an installed corpus sample exceeded {SAMPLE_TIMEOUT:?}");
            }
            None => std::thread::sleep(Duration::from_millis(1)),
        }
    };
    if let Some(driver) = driver {
        driver
            .join()
            .expect("the dialogue thread joins")
            .expect("the dialogue answered every frame");
    }
    let nanos = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
    assert!(
        status.success(),
        "a corpus sample ({args:?} in {}) exited with {status}; the measured workflow must succeed",
        cwd.display()
    );
    Sample {
        nanos,
        owned: observations,
        peak_rss_bytes,
    }
}

fn seed_project(root: &Path) {
    std::fs::write(root.join("main.rs"), "fn main() {}\n").expect("the project's main file");
    std::fs::write(root.join("lib.rs"), "pub fn answer() -> u32 { 42 }\n")
        .expect("the project's library file");
    std::fs::write(root.join("notes.md"), "# measured project\n").expect("the project's notes");
}

fn tree_size(root: &Path) -> (u64, u64) {
    let mut files = 0;
    let mut total = 0u64;
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(directory).expect("measured directory") {
            let entry = entry.expect("measured entry");
            let metadata = entry.metadata().expect("measured metadata");
            if metadata.is_dir() {
                pending.push(entry.path());
            } else {
                files += 1;
                total = total.saturating_add(metadata.len());
            }
        }
    }
    (files, total)
}

fn measure_headless(bundle: &Path, scratch: &Path) -> Value {
    let executable = bundle.join(RELEASE_EXECUTABLE_NAME);
    let mut timings = serde_json::Map::new();
    let mut owned = Vec::new();
    let mut peak_rss_bytes = 0;
    for (name, dialogue) in [
        ("version", None),
        ("headless_cancel", Some(Dialogue::Cancel)),
        ("headless_search", Some(Dialogue::Search)),
        ("headless_index", Some(Dialogue::Index)),
        (
            "headless_status_polling",
            Some(Dialogue::LongSession { turns: 20 }),
        ),
    ] {
        let root = scratch.join(name);
        std::fs::create_dir(&root).expect("isolated measurement project");
        if matches!(dialogue, Some(Dialogue::Index)) {
            seed_project(&root);
        }
        let root_text = root.to_str().expect("scratch path is UTF-8");
        let sample = if dialogue.is_some() {
            run_sample(
                &executable,
                &["--headless", "--data-root", root_text],
                &root,
                dialogue,
            )
        } else {
            run_sample(&executable, &["--version"], &root, None)
        };
        timings.insert(name.to_string(), json!(sample.nanos));
        peak_rss_bytes = peak_rss_bytes.max(sample.peak_rss_bytes);
        owned.extend(sample.owned);
    }
    let totals = OwnedTotals::tally(&owned, peak_rss_bytes);
    json!({
        "elapsed_ns_one_sample_per_probe": timings,
        "owned_process_observations": if totals.counted > 0 && totals.rss_bytes > 0 {
            json!({
                "processes_observed": totals.counted,
                "sampled_cpu_ns": totals.cpu_nanos,
                "sampled_peak_rss_bytes": totals.rss_bytes,
            })
        } else {
            Value::Null
        },
    })
}

#[derive(serde::Serialize)]
struct PackageSize {
    build: String,
    manifest_sha256: String,
    payload_files: u64,
    payload_bytes: u64,
    receipt_bytes: u64,
    installed_bytes: u64,
    local_tar_gz_bytes: u64,
}

fn measure_package_size(bundle: &Path, archive: &Path) -> PackageSize {
    let manifest = std::fs::read(bundle.join(RELEASE_MANIFEST_NAME)).expect("verified manifest");
    let identity: rivect::contracts::ReleaseManifest =
        serde_json::from_slice(&manifest).expect("verified manifest schema");
    let (payload_files, payload_bytes) = tree_size(bundle);
    let receipt = bundle.with_added_extension("manifest.sha256");
    let receipt_bytes = std::fs::metadata(receipt)
        .expect("installed manifest receipt")
        .len();
    let mut tar = child_command(Path::new("tar"), bundle);
    tar.env("COPYFILE_DISABLE", "1")
        .arg("-czf")
        .arg(archive)
        .args([
            RELEASE_EXECUTABLE_NAME,
            RELEASE_HELPER_NAME,
            RELEASE_MANIFEST_NAME,
            "libexec",
        ]);
    let output = tar.output().expect("archive verified package");
    assert!(
        output.status.success(),
        "tar: {}",
        support::release::stderr_of(&output)
    );
    let local_tar_gz_bytes = std::fs::metadata(archive).expect("measured archive").len();
    assert!(local_tar_gz_bytes > 0);
    PackageSize {
        build: identity.build,
        manifest_sha256: support::sha256_hex(&manifest),
        payload_files,
        payload_bytes,
        receipt_bytes,
        installed_bytes: payload_bytes + receipt_bytes,
        local_tar_gz_bytes,
    }
}

#[test]
fn v2_installed_package_measurement() {
    support::not_run::reset("measurement.offline_corpus");
    support::not_run::record("measurement.offline_corpus", RESOURCE_PREREQUISITE);
    let temporary = tempfile::tempdir().expect("measurement scratch root");
    let bundle = support::release::baseline_bundle();
    let v2 = measure_package_size(bundle, &temporary.path().join("v2.tar.gz"));
    assert_eq!(v2.payload_files, 5);
    assert_eq!(v2.receipt_bytes, 65);
    let headless = measure_headless(bundle, temporary.path());
    let measurement = json!({
        "schema_version": 1,
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "archive": "local tar -czf of verified payload; not a signed download measurement",
        "installed": "regular file lengths in version directory plus adjacent receipt",
        "v2": v2,
        "headless": headless,
        "ac003": { "status": "NOT_RUN", "prerequisite": RESOURCE_PREREQUISITE },
    });
    println!("PACKAGE_SIZE_MEASUREMENT {measurement}");
}

// Synthetic verdict inputs exercise the evaluator, not candidate performance.
fn test_limits() -> ReleaseLimits {
    ReleaseLimits {
        legs: [LegLimit {
            p50_nanos: 10,
            p95_nanos: 20,
            p99_nanos: 30,
        }; CorpusLeg::ALL.len()],
        p99_min_samples: 2,
        owned_cpu_nanos: 10,
        owned_rss_bytes: 10,
        disk_bytes: 10,
        package_bytes: 10,
        package_files: 10,
        install_nanos: 10,
    }
}

fn synthetic_legs(limits: &ReleaseLimits) -> Vec<LegSamples> {
    let count = usize::try_from(limits.p99_min_samples).expect("the sample count fits");
    CorpusLeg::ALL
        .into_iter()
        .map(|leg| {
            let limit = limits.leg(leg);
            LegSamples::new(leg, vec![limit.p50_nanos / 2; count])
        })
        .collect()
}

fn complete_report(limits: &ReleaseLimits) -> ReleaseReport {
    ReleaseReport {
        candidate: "rivect probe candidate".to_string(),
        candidate_digest: "0".repeat(64),
        baseline: "frozen baseline".to_string(),
        conditions: "frozen conditions".to_string(),
        platform: Platform::Available {
            name: "linux".to_string(),
        },
        legs: synthetic_legs(limits),
        owned: OwnedTotals {
            counted: 1,
            cpu_nanos: 1,
            rss_bytes: 1,
        },
        kit: KitMeasurement {
            disk_bytes: 1,
            package_bytes: 1,
            package_files: 1,
            install_nanos: 1,
        },
        not_run: Vec::new(),
    }
}

#[test]
fn over_limit_fixture_is_blocked_not_pass() {
    let limits = test_limits();
    let mut report = complete_report(&limits);
    let over = limits.leg(CorpusLeg::Startup).p95_nanos + 1;
    report.legs[0] = LegSamples::new(
        CorpusLeg::Startup,
        vec![over; usize::try_from(limits.p99_min_samples).expect("the sample count")],
    );
    let verdict = report.verdict(&limits);
    assert!(
        matches!(
            &verdict,
            ReleaseVerdict::Blocked(breaches)
                if breaches.iter().any(|breach| matches!(
                    breach,
                    LimitBreach::Latency { leg: CorpusLeg::Startup, .. }
                ))
        ),
        "an over-limit measurement blocks the release: {verdict:?}"
    );
    assert!(!verdict.is_pass());
    assert!(
        !format!("{verdict:?}").contains("Pass,"),
        "the blocked verdict never reads as a PASS"
    );
}

#[test]
fn missing_leg_is_not_pass() {
    let limits = test_limits();
    let mut report = complete_report(&limits);
    report.legs.retain(|held| held.leg != CorpusLeg::Index);
    let verdict = report.verdict(&limits);
    assert!(
        matches!(
            &verdict,
            ReleaseVerdict::NotPass(gaps)
                if gaps.iter().any(|gap| matches!(
                    gap,
                    MeasurementGap::MissingLeg { leg: CorpusLeg::Index }
                ))
        ),
        "a missing corpus leg is not PASS: {verdict:?}"
    );
    assert!(!verdict.is_pass());
}

#[test]
fn unavailable_platform_is_not_pass() {
    println!("ROW 17 ok");
    let limits = test_limits();
    let mut report = complete_report(&limits);
    report.platform = Platform::Unavailable {
        reason: "no /proc process accounting".to_string(),
    };
    let verdict = report.verdict(&limits);
    assert!(
        matches!(
            &verdict,
            ReleaseVerdict::NotPass(gaps)
                if gaps
                    .iter()
                    .any(|gap| matches!(gap, MeasurementGap::PlatformUnavailable { .. }))
        ),
        "an unavailable platform earns no PASS: {verdict:?}"
    );
    assert!(!verdict.is_pass());
}

#[test]
fn ineligible_p99_is_not_pass() {
    let limits = test_limits();
    let mut report = complete_report(&limits);
    let short = usize::try_from(limits.p99_min_samples - 1).expect("the short count fits");
    report.legs[0] = LegSamples::new(CorpusLeg::Startup, vec![1; short]);
    let verdict = report.verdict(&limits);
    assert!(
        matches!(
            &verdict,
            ReleaseVerdict::NotPass(gaps)
                if gaps.iter().any(|gap| matches!(
                    gap,
                    MeasurementGap::IneligibleP99 { leg: CorpusLeg::Startup, required, .. }
                        if *required == limits.p99_min_samples
                ))
        ),
        "an under-populated p99 is not PASS: {verdict:?}"
    );
    assert!(!verdict.is_pass());
}

/// An unmeasured kit or owned RSS is a named gap, never a PASS: all-zero
/// figures were never observed, while a measured under-limit report passes.
#[test]
fn unmeasured_kit_or_owned_rss_is_not_pass() {
    let limits = test_limits();
    let mut report = complete_report(&limits);
    assert!(
        matches!(report.verdict(&limits), ReleaseVerdict::Pass),
        "a measured under-limit report passes"
    );

    report.kit = KitMeasurement::default();
    let verdict = report.verdict(&limits);
    assert!(
        matches!(
            &verdict,
            ReleaseVerdict::NotPass(gaps)
                if gaps
                    .iter()
                    .any(|gap| matches!(gap, MeasurementGap::KitUnmeasured { .. }))
        ),
        "an unmeasured kit earns no PASS: {verdict:?}"
    );
    assert!(!verdict.is_pass());

    // A partially measured kit is unmeasured too: one zero figure was never
    // observed, so no limit arm can read it as under budget.
    let mut report = complete_report(&limits);
    report.kit = KitMeasurement {
        disk_bytes: 1,
        package_bytes: 1,
        package_files: 1,
        install_nanos: 0,
    };
    let verdict = report.verdict(&limits);
    assert!(
        matches!(
            &verdict,
            ReleaseVerdict::NotPass(gaps)
                if gaps
                    .iter()
                    .any(|gap| matches!(gap, MeasurementGap::KitUnmeasured { .. }))
        ),
        "a partially measured kit earns no PASS: {verdict:?}"
    );
    assert!(!verdict.is_pass());

    // A counted owned group whose resident set was never observed is
    // unmeasured too, never taken as under budget.
    let mut report = complete_report(&limits);
    report.owned.rss_bytes = 0;
    let verdict = report.verdict(&limits);
    assert!(
        matches!(
            &verdict,
            ReleaseVerdict::NotPass(gaps)
                if gaps
                    .iter()
                    .any(|gap| matches!(gap, MeasurementGap::OwnedUnmeasured { .. }))
        ),
        "an unmeasured owned RSS earns no PASS: {verdict:?}"
    );
    assert!(!verdict.is_pass());
}

#[test]
fn only_provider_rows_may_stay_not_run_with_their_prerequisite() {
    let limits = test_limits();
    let mut report = complete_report(&limits);
    report.not_run = vec![
        NotRun::new(PROVIDER_CACHE_TRIALS, "provider account grant"),
        NotRun::new(PROVIDER_LEGS, "provider access grant"),
    ];
    assert!(
        matches!(report.verdict(&limits), ReleaseVerdict::Pass),
        "the two provider rows are the only permitted absences"
    );

    report
        .not_run
        .push(NotRun::new("AC-003 install leg", "missing install sample"));
    let verdict = report.verdict(&limits);
    assert!(
        matches!(
            &verdict,
            ReleaseVerdict::NotPass(gaps)
                if gaps.iter().any(|gap| matches!(
                    gap,
                    MeasurementGap::NotRunWithoutPrerequisite { name }
                        if name == "AC-003 install leg"
                ))
        ),
        "an unpermitted NOT_RUN row is not PASS: {verdict:?}"
    );
}

#[test]
fn local_cache_is_not_a_provider_cache() {
    let absent = CacheRate::default();
    assert!(
        matches!(absent, CacheRate::NotRun),
        "an empty cohort is NOT_RUN, never a local-hit rate"
    );
    assert!(absent.numerator_and_denominator().is_none());
    let source = absent.source();
    assert!(
        source.contains("NOT_RUN") && source.contains("provider cache"),
        "the row says the provider metric never ran: {source}"
    );
    assert!(
        !source.contains("PASS"),
        "an absent provider cohort is not PASS: {source}"
    );
}
