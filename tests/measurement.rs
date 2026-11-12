//! AC-003: the frozen offline corpus measures the exact installed candidate.
//!
//! The corpus, the repeat count, the p99 eligibility rule and every limit are
//! declared in `docs/release-budgets.md` before the candidate runs; the
//! declaration's SHA-256 is the pre-declaration anchor asserted here. Every
//! leg executes one fresh run of the packaged bundle produced by
//! `scripts/package-release.sh`, so a checkout-only success cannot stand in
//! for the installed artifact. The report carries the baseline and
//! conditions, p50/p95 beside an eligible p99 per leg, the CPU and RSS of
//! every owned process counted once, and the kit's disk/package/build-install
//! figures. An over-limit fixture is `blocked`, a missing leg or unavailable
//! platform is not PASS, and only the AC-058 provider-cache trials and the
//! AC-048 provider legs may stay `NOT_RUN` with their exact prerequisite.
//!
//! No provider request is involved: the local record is not a provider cache,
//! so the provider-cache metric stays NOT_RUN without being read as a low
//! result or a PASS.

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
use sha2::{Digest as _, Sha256};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{ChildStdin, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};
use toml_edit::{DocumentMut, Item};

/// The SHA-256 of the fenced declaration in `docs/release-budgets.md`, taken
/// before the first candidate measurement. A measurement that changes the
/// corpus or a limit after seeing a result fails this anchor.
const FROZEN_BUDGET_DIGEST: &str =
    "67030b59e1c8451c0124059b0ffb841de56743a777213ed4061c643dbf29662e";

/// The only parent environment an installed child inherits: what a process
/// needs to locate its roots and the toolchain, never a secret (standards §10).
const CHILD_ENV: [&str; 5] = ["PATH", "HOME", "TMPDIR", "LANG", "LC_ALL"];

/// The packaging script's own toolchain roots, beside the same allowlist.
const PACKAGE_ENV: [&str; 6] = [
    "CARGO_HOME",
    "CARGO_TARGET_DIR",
    "RUSTUP_HOME",
    "RUSTUP_TOOLCHAIN",
    "CARGO_NET_OFFLINE",
    "USER",
];

/// Linux `USER_HZ`: the `/proc/<pid>/stat` clock ticks every figure is scaled
/// by. The frozen conditions declare the 100 Hz figure.
const USER_HZ_NANOS: u64 = 10_000_000;

const SAMPLE_TIMEOUT: Duration = Duration::from_secs(300);

// ----- the frozen declaration -----

struct Frozen {
    block: String,
    digest: String,
}

impl Frozen {
    fn load() -> Self {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("docs")
            .join("release-budgets.md");
        let text = std::fs::read_to_string(&path).expect("the frozen budget document reads");
        let mut block = String::new();
        let mut inside = false;
        let mut closed = false;
        for line in text.lines() {
            if inside {
                if line.trim_end() == "```" {
                    closed = true;
                    break;
                }
                block.push_str(line);
                block.push('\n');
            } else if line.trim_end() == "```toml" {
                inside = true;
            }
        }
        assert!(
            inside && closed,
            "the frozen declaration is a fenced toml block in {}",
            path.display()
        );
        let digest = rivect::config::hex(&Sha256::digest(block.as_bytes()));
        Self { block, digest }
    }

    fn document(&self) -> DocumentMut {
        self.block
            .parse()
            .expect("the frozen declaration parses as TOML")
    }
}

fn item<'a>(doc: &'a DocumentMut, path: &[&str]) -> &'a Item {
    let mut current = doc.as_item();
    for key in path {
        current = current
            .as_table()
            .and_then(|table| table.get(key))
            .unwrap_or_else(|| panic!("the frozen declaration misses {}", path.join(".")));
    }
    current
}

fn integer(doc: &DocumentMut, path: &[&str]) -> u64 {
    item(doc, path)
        .as_integer()
        .and_then(|value| u64::try_from(value).ok())
        .unwrap_or_else(|| panic!("the frozen declaration's {} is not a count", path.join(".")))
}

fn text(doc: &DocumentMut, path: &[&str]) -> String {
    item(doc, path)
        .as_str()
        .unwrap_or_else(|| {
            panic!(
                "the frozen declaration's {} is not a string",
                path.join(".")
            )
        })
        .to_string()
}

fn millis(value: u64) -> u64 {
    value.saturating_mul(1_000_000)
}

fn frozen_limits(doc: &DocumentMut) -> ReleaseLimits {
    let mut legs = [LegLimit {
        p50_nanos: 0,
        p95_nanos: 0,
        p99_nanos: 0,
    }; CorpusLeg::ALL.len()];
    for (index, leg) in CorpusLeg::ALL.into_iter().enumerate() {
        legs[index] = LegLimit {
            p50_nanos: millis(integer(doc, &["limits", leg.as_str(), "p50_ms"])),
            p95_nanos: millis(integer(doc, &["limits", leg.as_str(), "p95_ms"])),
            p99_nanos: millis(integer(doc, &["limits", leg.as_str(), "p99_ms"])),
        };
    }
    ReleaseLimits {
        legs,
        p99_min_samples: integer(doc, &["p99_min_samples"]),
        owned_cpu_nanos: millis(integer(doc, &["owned", "cpu_ms"])),
        owned_rss_bytes: integer(doc, &["owned", "rss_bytes"]),
        disk_bytes: integer(doc, &["kit", "disk_bytes"]),
        package_bytes: integer(doc, &["kit", "package_bytes"]),
        package_files: integer(doc, &["kit", "package_files"]),
        install_nanos: millis(integer(doc, &["kit", "install_ms"])),
    }
}

fn repeats(doc: &DocumentMut) -> usize {
    usize::try_from(integer(doc, &["candidate_repeats"]))
        .expect("the frozen repeat count fits this host")
}

fn long_session_turns(doc: &DocumentMut) -> usize {
    usize::try_from(integer(doc, &["long_session_turns"]))
        .expect("the frozen turn count fits this host")
}

/// The two provider rows the frozen declaration allows to stay NOT_RUN, each
/// with the exact prerequisite it names.
fn frozen_not_run(doc: &DocumentMut) -> Vec<NotRun> {
    vec![
        NotRun::new(
            PROVIDER_CACHE_TRIALS,
            text(doc, &["not_run", "provider_cache"]),
        ),
        NotRun::new(PROVIDER_LEGS, text(doc, &["not_run", "provider_legs"])),
    ]
}

// ----- the installed candidate and its corpus -----

/// The platform declared in the frozen conditions: process CPU/RSS sampling
/// needs `/proc`, and an unavailable platform supplies no measurement.
fn platform() -> Platform {
    if cfg!(target_os = "linux") && Path::new("/proc/self/stat").is_file() {
        Platform::Available {
            name: "linux".to_string(),
        }
    } else {
        Platform::Unavailable {
            reason:
                "the declared corpus needs /proc process accounting; this platform supplies none"
                    .to_string(),
        }
    }
}

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
    command.args(args).stderr(Stdio::null());
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
        peak_rss_bytes = peak_rss_bytes.max(observe(&mut observations, child.id()));
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
    assert!(
        !observations.is_empty(),
        "the owned process group was observable for every sample"
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

fn tree_bytes(root: &Path) -> u64 {
    let mut total = 0u64;
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(metadata) = entry.metadata() else {
                continue;
            };
            if metadata.is_dir() {
                pending.push(entry.path());
            } else {
                total = total.saturating_add(metadata.len());
            }
        }
    }
    total
}

fn package_destination(scratch: &Path, index: usize) -> PathBuf {
    scratch.join(format!("install-{index}"))
}

fn run_install(scratch: &Path, index: usize) -> Sample {
    let destination = package_destination(scratch, index);
    let script = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("scripts")
        .join("package-release.sh");
    let mut command = child_command(Path::new("sh"), scratch);
    command
        .arg(script)
        .arg(&destination)
        .env("CARGO", env!("CARGO"))
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .stdout(Stdio::null());
    for name in PACKAGE_ENV {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    let started = Instant::now();
    let mut child = command.spawn().expect("the packaging script spawns");
    let mut observations = Vec::new();
    let mut peak_rss_bytes = 0u64;
    let deadline = started + SAMPLE_TIMEOUT;
    let status = loop {
        peak_rss_bytes = peak_rss_bytes.max(observe(&mut observations, child.id()));
        match child
            .try_wait()
            .expect("the packaging script is observable")
        {
            Some(status) => break status,
            None if Instant::now() > deadline => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("the install corpus sample exceeded {SAMPLE_TIMEOUT:?}");
            }
            None => std::thread::sleep(Duration::from_millis(1)),
        }
    };
    let nanos = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
    assert!(
        status.success(),
        "the packaging sample exited with {status}"
    );
    assert!(
        !observations.is_empty(),
        "the packaging group was observable"
    );
    Sample {
        nanos,
        owned: observations,
        peak_rss_bytes,
    }
}

struct Corpus {
    legs: Vec<LegSamples>,
    owned: OwnedTotals,
    kit: KitMeasurement,
}

fn collect_corpus(doc: &DocumentMut, bundle: &Path, scratch: &Path) -> Corpus {
    let executable = bundle.join(RELEASE_EXECUTABLE_NAME);
    let per_leg = repeats(doc);
    let turns = long_session_turns(doc);
    let mut owned = Vec::new();
    let mut peak_rss_bytes = 0u64;
    let mut legs = Vec::with_capacity(CorpusLeg::ALL.len());
    for leg in CorpusLeg::ALL {
        let mut nanos = Vec::with_capacity(per_leg);
        for index in 0..per_leg {
            let sample = match leg {
                CorpusLeg::Startup => run_sample(&executable, &["--version"], scratch, None),
                CorpusLeg::Input => {
                    let root = scratch.join(format!("input-{index}"));
                    std::fs::create_dir_all(&root).expect("the input data root");
                    let root_text = root.display().to_string();
                    run_sample(
                        &executable,
                        &["settings", "--data-root", &root_text],
                        &root,
                        None,
                    )
                }
                CorpusLeg::Cancel => {
                    let root = scratch.join(format!("cancel-{index}"));
                    std::fs::create_dir_all(&root).expect("the cancel data root");
                    let root_text = root.display().to_string();
                    run_sample(
                        &executable,
                        &["--headless", "--data-root", &root_text],
                        &root,
                        Some(Dialogue::Cancel),
                    )
                }
                CorpusLeg::Search => {
                    let root = scratch.join(format!("search-{index}"));
                    std::fs::create_dir_all(&root).expect("the search data root");
                    let root_text = root.display().to_string();
                    run_sample(
                        &executable,
                        &["--headless", "--data-root", &root_text],
                        &root,
                        Some(Dialogue::Search),
                    )
                }
                CorpusLeg::Index => {
                    let root = scratch.join(format!("index-{index}"));
                    std::fs::create_dir_all(&root).expect("the index data root");
                    seed_project(&root);
                    let root_text = root.display().to_string();
                    run_sample(
                        &executable,
                        &["--headless", "--data-root", &root_text],
                        &root,
                        Some(Dialogue::Index),
                    )
                }
                CorpusLeg::LongSession => {
                    let root = scratch.join(format!("long-session-{index}"));
                    std::fs::create_dir_all(&root).expect("the long-session data root");
                    let root_text = root.display().to_string();
                    run_sample(
                        &executable,
                        &["--headless", "--data-root", &root_text],
                        &root,
                        Some(Dialogue::LongSession { turns }),
                    )
                }
                CorpusLeg::Install => run_install(scratch, index),
            };
            nanos.push(sample.nanos);
            peak_rss_bytes = peak_rss_bytes.max(sample.peak_rss_bytes);
            owned.extend(sample.owned);
        }
        legs.push(LegSamples::new(leg, nanos));
    }

    // The kit was measured once around one fresh packaging run and one
    // ordinary run's data root; the repeats above measured the same script.
    let kit_destination = scratch.join("kit-install");
    let kit_started = Instant::now();
    let output = support::release::package_into(&kit_destination);
    assert!(
        output.status.success(),
        "the kit packaging run refused: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let install_nanos = u64::try_from(kit_started.elapsed().as_nanos()).unwrap_or(u64::MAX);
    let package_bytes = tree_bytes(&kit_destination);
    let package_files = std::fs::read_dir(&kit_destination)
        .expect("the kit inventory reads")
        .filter_map(Result::ok)
        .filter(|entry| entry.path().is_file())
        .count();
    let data_root_bytes = tree_bytes(&scratch.join("input-0"));
    let disk_bytes = tree_bytes(bundle).saturating_add(data_root_bytes);
    Corpus {
        legs,
        owned: OwnedTotals::tally(&owned, peak_rss_bytes),
        kit: KitMeasurement {
            disk_bytes,
            package_bytes,
            package_files: u64::try_from(package_files).unwrap_or(u64::MAX),
            install_nanos,
        },
    }
}

fn manifest_of(bundle: &Path) -> Value {
    let manifest = std::fs::read_to_string(bundle.join(RELEASE_MANIFEST_NAME))
        .expect("the installed manifest reads");
    serde_json::from_str(&manifest).expect("the installed manifest parses")
}

fn candidate_identity(bundle: &Path) -> (String, String) {
    let version = support::release::run_packaged(bundle, &["--version"], bundle);
    assert!(
        version.status.success(),
        "the installed candidate answers --version"
    );
    let candidate = String::from_utf8_lossy(&version.stdout).trim().to_string();
    let digest = support::release::sha256_file(&bundle.join(RELEASE_MANIFEST_NAME));
    (candidate, digest)
}

fn print_report(frozen: &Frozen, report: &ReleaseReport, min_samples: u64) {
    println!("frozen budget sha256 {}", frozen.digest);
    println!(
        "candidate {} manifest sha256 {}",
        report.candidate, report.candidate_digest
    );
    println!("baseline: {}", report.baseline);
    println!("conditions: {}", report.conditions);
    for samples in &report.legs {
        println!(
            "leg {} samples {} p50 {} ns p95 {} ns p99 {:?} ns",
            samples.leg.as_str(),
            samples.samples(),
            samples
                .percentile(rivect::resources::Percentile::P50)
                .unwrap_or(0),
            samples
                .percentile(rivect::resources::Percentile::P95)
                .unwrap_or(0),
            samples.eligible_p99(min_samples),
        );
    }
    println!(
        "owned processes {} cpu {} ns rss {} bytes",
        report.owned.counted, report.owned.cpu_nanos, report.owned.rss_bytes
    );
    println!(
        "kit disk {} bytes package {} bytes in {} files install {} ns",
        report.kit.disk_bytes,
        report.kit.package_bytes,
        report.kit.package_files,
        report.kit.install_nanos
    );
    for row in &report.not_run {
        println!("NOT_RUN {} prerequisite: {}", row.name, row.prerequisite);
    }
}

// ----- the proofs -----

#[test]
fn frozen_release_budgets_match_the_pinned_digest() {
    let frozen = Frozen::load();
    assert_eq!(
        frozen.digest, FROZEN_BUDGET_DIGEST,
        "the frozen declaration moved after it was pinned; a corpus or limit change is a new declaration"
    );
    let doc = frozen.document();
    assert_eq!(integer(&doc, &["schema_version"]), 1);
    assert_eq!(
        text(&doc, &["frozen_on"]),
        "2026-11-09",
        "the declaration names the date it was frozen"
    );
    let declared: Vec<String> = item(&doc, &["corpus"])
        .as_array()
        .expect("the corpus is an array")
        .iter()
        .filter_map(|value| value.as_str())
        .map(str::to_string)
        .collect();
    let expected: Vec<String> = CorpusLeg::ALL
        .into_iter()
        .map(|leg| leg.as_str().to_string())
        .collect();
    assert_eq!(declared, expected, "the corpus covers every mandatory leg");
    let limits = frozen_limits(&doc);
    for leg in CorpusLeg::ALL {
        let limit = limits.leg(leg);
        assert!(
            limit.p50_nanos > 0
                && limit.p50_nanos < limit.p95_nanos
                && limit.p95_nanos < limit.p99_nanos,
            "the {} limits are declared in order",
            leg.as_str()
        );
    }
    assert!(limits.p99_min_samples > 0);
    assert!(limits.owned_cpu_nanos > 0 && limits.owned_rss_bytes > 0);
    assert!(limits.disk_bytes > 0 && limits.package_bytes > 0 && limits.package_files > 0);
    for row in frozen_not_run(&doc) {
        assert!(
            !row.prerequisite.trim().is_empty(),
            "the {} row names the exact prerequisite that kept it out",
            row.name
        );
    }
    println!("frozen budget sha256 {}", frozen.digest);
}

#[test]
fn offline_corpus_measures_the_installed_candidate_against_the_frozen_limits() {
    println!("ROW A36 ok");
    support::not_run::reset("measurement.offline_corpus");
    let frozen = Frozen::load();
    assert_eq!(frozen.digest, FROZEN_BUDGET_DIGEST);
    let doc = frozen.document();
    let limits = frozen_limits(&doc);
    let bundle = support::release::baseline_bundle();
    let (candidate, candidate_digest) = candidate_identity(bundle);
    let manifest = manifest_of(bundle);
    assert_eq!(
        manifest["executable"]["sha256"],
        json!(support::release::sha256_file(
            &bundle.join(RELEASE_EXECUTABLE_NAME)
        )),
        "the manifest binds the executable's exact bytes"
    );
    assert_eq!(
        manifest["helper"]["sha256"],
        json!(support::release::sha256_file(
            &bundle.join(RELEASE_HELPER_NAME)
        )),
        "the manifest binds the helper's exact bytes"
    );

    // The corpus is declared for Linux with /proc accounting. An unavailable
    // platform supplies no measurement, and the fixture below proves that it
    // earns no PASS; nothing here invents one.
    let platform = platform();
    if let Platform::Unavailable { reason } = &platform {
        support::not_run::record(
            "measurement.offline_corpus",
            &format!("platform unavailable: {reason}"),
        );
        println!("corpus NOT_RUN on this platform: {reason}");
        return;
    }

    // The install corpus keeps ~96 bundles (about 2.7 GiB) for the whole run;
    // the default /tmp tmpfs can be too small, so the scratch root stays beside
    // the build artifacts and inherits their filesystem capacity.
    let scratch_root = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("target"))
        .join("measurement-scratch");
    std::fs::create_dir_all(&scratch_root).expect("the measurement scratch directory");
    let scratch = tempfile::TempDir::with_prefix_in("rivect-measurement-", &scratch_root)
        .expect("the measurement scratch root");
    let corpus = collect_corpus(&doc, bundle, scratch.path());
    let report = ReleaseReport {
        candidate,
        candidate_digest: candidate_digest.clone(),
        baseline: text(&doc, &["baseline"]),
        conditions: text(&doc, &["conditions"]),
        platform,
        legs: corpus.legs,
        owned: corpus.owned,
        kit: corpus.kit,
        not_run: frozen_not_run(&doc),
    };
    assert_eq!(
        report.candidate_digest,
        support::release::sha256_file(&bundle.join(RELEASE_MANIFEST_NAME)),
        "the report names the exact installed manifest it measured"
    );
    print_report(&frozen, &report, limits.p99_min_samples);

    let per_leg = repeats(&doc);
    for leg in CorpusLeg::ALL {
        let samples = report
            .legs
            .iter()
            .find(|held| held.leg == leg)
            .expect("every mandatory leg ran");
        assert_eq!(
            samples.samples(),
            per_leg,
            "the {} leg collected the frozen sample count",
            leg.as_str()
        );
        assert!(
            samples.eligible_p99(limits.p99_min_samples).is_some(),
            "the {} leg's p99 is eligible",
            leg.as_str()
        );
    }
    assert!(
        report.owned.counted > 0,
        "the owned process group was counted"
    );
    assert!(
        report.owned.rss_bytes > 0,
        "the owned group's resident set was observed at least once across the corpus"
    );
    let verdict = report.verdict(&limits);
    assert!(
        matches!(verdict, ReleaseVerdict::Pass),
        "the installed candidate is within its frozen limits: {verdict:?}"
    );
    assert!(verdict.is_pass());
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
    let frozen = Frozen::load();
    let limits = frozen_limits(&frozen.document());
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
    let frozen = Frozen::load();
    let limits = frozen_limits(&frozen.document());
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
    let frozen = Frozen::load();
    let limits = frozen_limits(&frozen.document());
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
    let frozen = Frozen::load();
    let limits = frozen_limits(&frozen.document());
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
    let frozen = Frozen::load();
    let limits = frozen_limits(&frozen.document());
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
    let frozen = Frozen::load();
    let limits = frozen_limits(&frozen.document());
    let mut report = complete_report(&limits);
    report.not_run = frozen_not_run(&frozen.document());
    assert!(
        matches!(report.verdict(&limits), ReleaseVerdict::Pass),
        "the two provider rows are the only permitted absences"
    );

    report.not_run.push(NotRun::new(
        "AC-003 install leg",
        "a prerequisite the frozen declaration never named",
    ));
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
    // The frozen provider-cache row names its exact missing grant; the local
    // record cannot stand in for provider-reported cache evidence.
    let frozen = Frozen::load();
    let doc = frozen.document();
    let rows = frozen_not_run(&doc);
    let cache = rows
        .iter()
        .find(|row| row.name == PROVIDER_CACHE_TRIALS)
        .expect("the provider-cache row is declared");
    let prerequisite = cache.prerequisite.to_lowercase();
    assert!(
        prerequisite.contains("provider account") && prerequisite.contains("frozen"),
        "the missing prerequisite is exact: {prerequisite}"
    );

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
