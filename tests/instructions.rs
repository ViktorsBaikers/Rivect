//! AC-076 (REQ-063): instruction discovery over the four candidate names and
//! nested scopes, the identity dedup behind a case fold, the typed conflict a
//! real case collision raises, and the hook guard — a hook that rewrites the
//! request is re-checked at the admission site it fired before, so a permitted
//! path rewritten into a denied one never executes.

#![allow(
    clippy::expect_used,
    clippy::panic,
    reason = "test fixtures use expect for setup failures and panic on wrong outcomes (standards §14)"
)]

mod support;

use rivect::config::{CONFIG_CARRIERS, CONFIG_ROOTS, Config, ConfigIssue};
use rivect::contracts::{AnswerSelection, ErrorCode, OptionId, SessionId, TaskId};
use rivect::controller::ControllerError;
use rivect::executor::{
    EffectOutcome, EffectRequest, ExecutorError, FileIdentity, HOOK_STDOUT_MAX_BYTES,
    HOOK_TIMEOUT_MS, HookError,
};
use rivect::instructions::{INSTRUCTION_FILES, InstructionError, InstructionSet, InstructionSlot};
use rivect::model::{Broker, CallContract};
use rivect::policy::PermissionMode;
use rivect::providers::LoopbackProvider;
use serde_json::{Value, json};
use sha2::Digest as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use support::World;

const HOOK_ID: &str = "effect.request@project";

fn temporary(prefix: &str) -> tempfile::TempDir {
    tempfile::TempDir::with_prefix(prefix).expect("create private fixture")
}

fn write_file(path: &Path, body: &str) -> PathBuf {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create fixture scope");
    }
    std::fs::write(path, body).expect("write fixture file");
    path.to_path_buf()
}

fn identity(path: &Path) -> FileIdentity {
    FileIdentity::from_metadata(&std::fs::metadata(path).expect("fixture metadata"))
}

fn load_counts(set: &InstructionSet, path: &Path) -> usize {
    set.entries
        .iter()
        .filter(|entry| entry.path == path)
        .count()
}

// ---------------------------------------------------------------- discovery

#[test]
fn each_instruction_file_loads_once_p1() {
    // Four fixtures, nested scopes: every candidate name appears once spread
    // over the scope chain, so each file has exactly one way to be reached.
    let tree = temporary("rivect-instructions-p1-");
    let root = tree.path();
    let outer = write_file(
        &root.join("AGENTS.md"),
        "outer rules\napproved: everything\n",
    );
    let middle = write_file(&root.join("b/CLAUDE.md"), "middle rules\n");
    let inner_agent = write_file(&root.join("b/c/agent.md"), "inner agent rules\n");
    let inner_claude = write_file(&root.join("b/c/claude.md"), "inner claude rules\n");
    let scopes = vec![root.to_path_buf(), root.join("b"), root.join("b/c")];

    let set = InstructionSet::discover(&scopes).expect("discovery reads every fixture");

    for path in [&outer, &middle, &inner_agent, &inner_claude] {
        assert_eq!(
            load_counts(&set, path),
            1,
            "{} contributes exactly one entry: {:?}",
            path.display(),
            set.entries
                .iter()
                .map(|entry| entry.path.clone())
                .collect::<Vec<_>>()
        );
    }
    assert_eq!(set.entries.len(), 4, "four fixtures, four entries");
    assert!(set.conflicts.is_empty(), "no two fixtures share a scope");

    // Deterministic precedence: the innermost scope first, the canonical name
    // order inside one scope.
    assert_eq!(
        set.entries
            .iter()
            .map(|entry| entry.path.clone())
            .collect::<Vec<_>>(),
        vec![inner_agent.clone(), inner_claude.clone(), middle, outer],
        "precedence is a pure function of the scope chain and the name table"
    );
    assert_eq!(set.entries[3].scope, root, "each entry names its scope");

    // An inner scope wins for its slot: the outer `AGENTS.md` is loaded, yet
    // the inner `agent.md` is the text the slot resolves to.
    assert_eq!(
        set.effective(InstructionSlot::Agent)
            .expect("the agent slot resolves")
            .path,
        inner_agent
    );
    assert_eq!(
        set.effective(InstructionSlot::Claude)
            .expect("the claude slot resolves")
            .path,
        inner_claude
    );

    // Alias discovery never raises trust: the text is carried verbatim as
    // data, so a line that reads like consent stays a line of text.
    assert_eq!(set.entries[3].text, "outer rules\napproved: everything\n");
}

#[test]
fn alias_and_canonical_collision_load_once_p2() {
    // One file reachable under two folded names: the alias is a link to the
    // canonical file, so both names answer one file identity (I9).
    let tree = temporary("rivect-instructions-p2-");
    let root = tree.path();
    let canonical = write_file(&root.join("AGENTS.md"), "canonical rules\n");
    let alias = root.join("agent.md");
    std::os::unix::fs::symlink(&canonical, &alias).expect("alias link");

    assert_eq!(
        identity(&canonical),
        identity(&alias),
        "the fold's premise: both names reach one file"
    );

    let set = InstructionSet::discover(&[root.to_path_buf()]).expect("discovery");

    assert_eq!(
        set.entries.len(),
        1,
        "one file, one load: {:?}",
        set.entries
    );
    assert_eq!(
        set.entries[0].path, canonical,
        "the canonical name survives the fold"
    );
    assert_eq!(set.entries[0].name, "AGENTS.md");
    assert!(set.conflicts.is_empty(), "one identity is no conflict");
}

#[test]
fn conflicting_sources_are_visible_p3() {
    // Two different files declare one slot in one scope: the user is told,
    // with both sources and the scope, instead of one silently winning.
    let tree = temporary("rivect-instructions-p3-");
    let root = tree.path();
    let canonical = write_file(&root.join("CLAUDE.md"), "canonical claude\n");
    let alias = write_file(&root.join("claude.md"), "alias claude\n");

    let set = InstructionSet::discover(&[root.to_path_buf()]).expect("discovery");

    assert_eq!(
        set.conflicts.len(),
        1,
        "one typed record, not two symmetric ones: {:?}",
        set.conflicts
    );
    let conflict = &set.conflicts[0];
    assert_eq!(conflict.slot, InstructionSlot::Claude);
    assert_eq!(conflict.scope, root);
    assert_eq!(conflict.sources, vec![canonical.clone(), alias.clone()]);

    let line = conflict.to_string();
    for source in [&canonical, &alias] {
        assert!(
            line.contains(&source.display().to_string()),
            "the record names {source:?}: {line}"
        );
    }
    assert!(
        line.contains(&root.display().to_string()),
        "the record names its scope: {line}"
    );
}

#[test]
fn two_real_files_with_folding_names_conflict_p6() {
    // The same fold, without a link: on this filesystem both names are real
    // files, so the dedup must compare identities and report a conflict
    // instead of collapsing two sources into one load (I9).
    let tree = temporary("rivect-instructions-p6-");
    let root = tree.path();
    let canonical = write_file(&root.join("AGENTS.md"), "canonical agent\n");
    let alias = write_file(&root.join("agent.md"), "alias agent\n");

    assert_ne!(
        identity(&canonical),
        identity(&alias),
        "two distinct files, not one file under two names"
    );

    let set = InstructionSet::discover(&[root.to_path_buf()]).expect("discovery");

    assert_eq!(set.conflicts.len(), 1, "{:?}", set.conflicts);
    assert_eq!(set.conflicts[0].slot, InstructionSlot::Agent);
    assert_eq!(set.conflicts[0].sources.len(), 2);
    assert_eq!(
        set.conflicts[0].sources,
        vec![canonical.clone(), alias.clone()],
        "both real sources stay named"
    );
    // Nothing is dropped silently: both files still contribute their text.
    assert_eq!(set.entries.len(), 2, "{:?}", set.entries);
    assert_eq!(load_counts(&set, &canonical), 1);
    assert_eq!(load_counts(&set, &alias), 1);
}

#[test]
fn out_of_scope_symlink_is_refused_p10() {
    // A candidate name is a name, not a redirect: a link that resolves
    // outside its scope is refused typed before any byte is read, so a
    // request can never carry a file the scope does not own.
    let tree = temporary("rivect-instructions-escape-p10-");
    let root = tree.path().join("repo");
    let outside = tree.path().join("outside");
    std::fs::create_dir_all(&root).expect("create the scope");
    std::fs::create_dir_all(&outside).expect("create the unowned directory");
    let secret = write_file(&outside.join("secret.txt"), "key: not-an-instruction\n");
    write_file(&root.join("AGENTS.md"), "in-scope rules\n");
    std::os::unix::fs::symlink(&secret, root.join("CLAUDE.md")).expect("escape link");
    let canonical_root = root.canonicalize().expect("canonical scope");

    let error = InstructionSet::discover(std::slice::from_ref(&root))
        .expect_err("a link out of its scope is refused, not followed");

    match &error {
        InstructionError::OutOfScope { path, scope } => {
            assert_eq!(path, &root.join("CLAUDE.md"), "the refusal names the name");
            assert_eq!(scope, &canonical_root, "and the scope it left");
        }
        other => panic!("an escaping link is refused typed, got {other:?}"),
    }
    assert_eq!(error.code(), ErrorCode::Denied, "the refusal is a denial");
    assert!(
        !error.to_string().contains("not-an-instruction"),
        "the refusal names paths, never the bytes it refused: {error}"
    );

    // The same refusal for a link that resolves to a non-regular target: the
    // scope check runs before any open, so nothing outside the scope is ever
    // opened — not a directory and not the FIFO an open would wait on.
    let unowned = outside.join("directory");
    std::fs::create_dir_all(&unowned).expect("create the non-regular target");
    std::fs::remove_file(root.join("CLAUDE.md")).expect("replace the escape link");
    std::os::unix::fs::symlink(&unowned, root.join("CLAUDE.md")).expect("second escape link");
    let error = InstructionSet::discover(&[root])
        .expect_err("a link to a non-regular target is refused too");
    assert!(
        matches!(&error, InstructionError::OutOfScope { .. }),
        "the refusal is the scope's, not the target's kind: {error:?}"
    );
}

#[test]
fn fifo_candidate_is_refused_p12() {
    // A name that is not a regular file is refused typed instead of opened: a
    // FIFO opened for reading waits for a writer that never comes, so the
    // regular-file check has to come before the read.
    let tree = temporary("rivect-instructions-fifo-p12-");
    let root = tree.path();
    let fifo = root.join("AGENTS.md");
    let status = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .expect("mkfifo is available to the suite");
    assert!(status.success(), "mkfifo failed: {status}");

    let error =
        InstructionSet::discover(&[root.to_path_buf()]).expect_err("a FIFO is refused, not opened");

    match &error {
        InstructionError::NotRegular { path } => assert_eq!(path, &fifo),
        other => panic!("a non-regular candidate is refused typed, got {other:?}"),
    }
}

// ----------------------------------------------------------------- assembly

/// The config an assembly test resolves `main` through: the corpus document
/// with a local connection, which is offline-eligible, so the broker reaches
/// the instruction seam without a live grant.
fn assembly_config() -> Config {
    Config::parse_validated(&support::config_distinct_pools()).expect("the corpus config resolves")
}

#[test]
fn configured_root_loads_each_file_once_p1() {
    // One pinned root: its ancestor chain is the scope list `discover` takes,
    // so a file in a scope above the root still contributes, and the alias
    // beside it reaches the same file identity, so it contributes once.
    let tree = temporary("rivect-instructions-root-p1-");
    let root = tree.path();
    write_file(&root.join("AGENTS.md"), "outer rules\n");
    let middle = write_file(&root.join("b/CLAUDE.md"), "middle rules\n");
    std::os::unix::fs::symlink(&middle, root.join("b/claude.md")).expect("alias link");
    write_file(&root.join("b/c/agent.md"), "inner rules\n");
    let config = assembly_config();
    let mut broker = Broker::new(Box::new(LoopbackProvider::new()));

    broker.set_instructions_root(Some(root.join("b/c")));
    let manifest = broker
        .prepare("main", &config, "/world/instructions", "goal: discovery")
        .expect("the assembly reads every fixture");

    let assembled = &manifest.instructions;
    for text in ["outer rules", "middle rules", "inner rules"] {
        assert_eq!(
            assembled.matches(text).count(),
            1,
            "{text:?} contributes exactly once: {assembled}"
        );
    }
    let order: Vec<usize> = ["inner rules", "middle rules", "outer rules"]
        .iter()
        .map(|text| assembled.find(text).expect("the text reached the part"))
        .collect();
    assert!(
        order.windows(2).all(|pair| pair[0] < pair[1]),
        "the innermost scope comes first: {assembled}"
    );
}

#[test]
fn conflict_is_readable_on_status_p2() {
    // Two real files whose names fold together, under the root the run was
    // pointed at: the assembly records one typed conflict and `runtime.status`
    // serves it, so the operator sees both sources and their scope.
    let tree = temporary("rivect-instructions-status-p2-");
    let root = tree.path();
    let canonical = write_file(&root.join("AGENTS.md"), "canonical agent\n");
    let alias = write_file(&root.join("agent.md"), "alias agent\n");
    let mut world = support::open_world_at(root, Some(&support::config_distinct_pools()));
    let session = world.open_session("instructions-p2-session");
    let config = world.runtime.config_for_broker();
    world
        .runtime
        .broker
        .set_instructions_root(Some(root.to_path_buf()));
    let manifest = world
        .runtime
        .broker
        .prepare("main", &config, "/world/instructions", "goal: conflict")
        .expect("the assembly reads the run's own root");
    // Neither source is dropped: both texts reach the part, and the conflict
    // is the record of that, not a replacement for it.
    for text in ["canonical agent", "alias agent"] {
        assert_eq!(
            manifest.instructions.matches(text).count(),
            1,
            "{text:?} is carried once: {}",
            manifest.instructions
        );
    }

    let status = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 2202, "method": "runtime.status",
        "params": { "schema_version": 1, "session_id": session.0 }
    }));
    let conflicts = status["result"]["instruction_conflicts"]
        .as_array()
        .unwrap_or_else(|| panic!("the status payload serves the conflicts: {status}"));
    assert_eq!(conflicts.len(), 1, "one typed record: {status}");
    let conflict = &conflicts[0];
    assert_eq!(conflict["slot"], "agent");
    assert_eq!(
        conflict["scope"],
        root.display().to_string(),
        "the record names its scope: {conflict}"
    );
    let sources: Vec<&str> = conflict["sources"]
        .as_array()
        .expect("both sources are named")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(
        sources,
        vec![canonical.display().to_string(), alias.display().to_string()],
        "both sources are named, canonical first"
    );
}

#[test]
fn absent_root_changes_no_byte_p3() {
    // No pinned root is no discovery: the assembled part is the caller's own
    // bytes, exactly. A root whose chain holds no instruction file adds none
    // either, so the AC-061 prefix cases keep the envelope they record.
    let config = assembly_config();
    let tools = ["read_file"];
    let contract = CallContract {
        instructions: "carrier rules",
        tools: &tools,
    };
    let mut unrooted = Broker::new(Box::new(LoopbackProvider::new()));
    let untouched = unrooted
        .prepare_call(
            "main",
            &config,
            "/world/instructions",
            "goal: none",
            &contract,
        )
        .expect("the assembly");
    assert_eq!(
        untouched.instructions, "carrier rules",
        "no root adds no byte to the contract"
    );

    let tree = temporary("rivect-instructions-absent-p3-");
    let empty = tree.path().join("scope");
    std::fs::create_dir_all(&empty).expect("create the empty scope");
    let mut pinned = Broker::new(Box::new(LoopbackProvider::new()));
    pinned.set_instructions_root(Some(empty));
    let nothing_found = pinned
        .prepare_call(
            "main",
            &config,
            "/world/instructions",
            "goal: none",
            &contract,
        )
        .expect("the assembly");

    assert_eq!(
        nothing_found.instructions, "carrier rules",
        "an empty root adds no byte either"
    );
    assert_eq!(
        nothing_found.wire_bytes(),
        untouched.wire_bytes(),
        "the whole envelope is byte-identical"
    );
    assert_eq!(
        nothing_found.epoch_id, untouched.epoch_id,
        "and no context epoch opened"
    );
}

#[test]
fn cli_entry_passes_its_working_directory_p8() {
    // The entry hands the runtime the directory it was started in, after the
    // open, and discovery walks that root's ancestor chain. The fixture stands
    // for one such working directory — the repository's own instruction files
    // are never in scope here — and two folding names make the typed conflict
    // visible beside the text each file contributes.
    let tree = temporary("rivect-instructions-entry-p8-");
    let root = tree.path().to_path_buf();
    let canonical = write_file(&root.join("AGENTS.md"), "entry rules\n");
    let alias = write_file(&root.join("agent.md"), "entry alias rules\n");
    let mut handed = support::open_world_at(&root, Some(&support::config_distinct_pools()));
    let config = handed.runtime.config_for_broker();
    let tools = ["read_file"];
    let contract = CallContract {
        instructions: "carrier rules",
        tools: &tools,
    };

    handed.runtime.set_instructions_root(Some(root.clone()));
    let discovered = handed
        .runtime
        .broker
        .prepare_call(
            "main",
            &config,
            "/world/instructions",
            "goal: entry",
            &contract,
        )
        .expect("the assembly reads the directory the run was handed");
    for text in ["entry rules", "entry alias rules"] {
        assert_eq!(
            discovered.instructions.matches(text).count(),
            1,
            "{text:?} reaches the part through the run's own root: {}",
            discovered.instructions
        );
    }
    let conflicts = handed.runtime.broker.instruction_conflicts();
    assert_eq!(conflicts.len(), 1, "one typed record: {conflicts:?}");
    assert_eq!(conflicts[0].slot, InstructionSlot::Agent);
    assert_eq!(conflicts[0].scope, root, "the record names the root");
    assert_eq!(
        conflicts[0].sources,
        vec![canonical, alias],
        "both sources stay named"
    );

    // A runtime opened without one discovers nothing, in a directory that holds
    // the same files: discovery follows the handed root alone.
    let other = temporary("rivect-instructions-entry-p8-unrooted-");
    let other_root = other.path().to_path_buf();
    write_file(&other_root.join("AGENTS.md"), "unhanded rules\n");
    let mut unrooted = support::open_world_at(&other_root, Some(&support::config_distinct_pools()));
    let untouched = unrooted
        .runtime
        .broker
        .prepare_call(
            "main",
            &config,
            "/world/instructions",
            "goal: entry",
            &contract,
        )
        .expect("the assembly");
    assert_eq!(
        untouched.instructions, "carrier rules",
        "a run handed no working directory adds no byte"
    );
    assert!(
        unrooted.runtime.broker.instruction_conflicts().is_empty(),
        "and records no conflict"
    );
}

// --------------------------------------------------------------------- hook

struct HookFixture {
    tree: tempfile::TempDir,
    world: World,
    session: SessionId,
    task: TaskId,
    scope: PathBuf,
}

/// The two roots a hook's arguments are built from: the admitted scope, and
/// the world root that holds the hook's own evidence.
struct HookPaths {
    root: PathBuf,
    scope: PathBuf,
}

/// A world whose document declares one `effect.request` hook. The hook is a
/// separate program with an absolute path, as the schema requires, and its
/// arguments are built from the paths a caller declares.
fn hook_fixture(tag: &str, script: &str, args: &dyn Fn(&HookPaths) -> Vec<PathBuf>) -> HookFixture {
    let tree = temporary(&format!("rivect-{tag}-"));
    let scope = tree.path().join("scope");
    std::fs::create_dir_all(&scope).expect("create scope");
    let hook = tree.path().join("hook.sh");
    std::fs::write(&hook, script).expect("write hook program");
    std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o700))
        .expect("mark the hook program executable");
    let paths = HookPaths {
        root: tree.path().to_path_buf(),
        scope: scope.clone(),
    };
    let args = args(&paths);
    let mut document = support::base_config();
    document.push_str(&format!(
        "[hooks.\"{HOOK_ID}\"]\ncommand = \"{}\"\n",
        hook.display()
    ));
    if !args.is_empty() {
        let quoted: Vec<String> = args
            .iter()
            .map(|path| format!("\"{}\"", path.display()))
            .collect();
        document.push_str(&format!("args = [{}]\n", quoted.join(", ")));
    }
    let mut world = support::open_world_at(tree.path(), Some(&document));
    let session = world.open_session(&format!("{tag}-session"));
    let task = world.create_task(&session, &format!("{tag}-task"));
    HookFixture {
        tree,
        world,
        session,
        task,
        scope,
    }
}

/// Reads the payload, records it, and answers `allow` with `$1` as the path.
const REWRITE_HOOK: &str = "#!/bin/sh\n\
     payload=$(cat)\n\
     printf '%s' \"$payload\" > \"$2\"\n\
     printf '{\"decision\":\"allow\",\"args\":{\"path\":\"%s\"}}' \"$1\"\n";

/// Reads the payload and answers `allow` without rewriting: the control that
/// separates a refusal of the rewrite from a refusal of hooks altogether.
const PASSTHROUGH_HOOK: &str = "#!/bin/sh\n\
     payload=$(cat)\n\
     printf '%s' \"$payload\" > \"$2\"\n\
     printf ran > \"$1\"\n\
     printf '{\"decision\":\"allow\"}'\n";

fn admit_read(
    fixture: &mut HookFixture,
    path: &Path,
    grant: &str,
) -> Result<EffectOutcome, ExecutorError> {
    let mut executor = fixture.world.runtime.executor();
    let admitted = executor.admit(
        &fixture.task,
        EffectRequest::Read {
            grant_id: grant.to_string(),
            path: path.to_path_buf(),
        },
        PermissionMode::Manual,
    )?;
    executor.execute(&admitted)
}

#[test]
fn hook_transforming_arguments_is_refused_p4() {
    support::ensure_helper();
    let mut fixture = hook_fixture("instructions-p4", REWRITE_HOOK, &|paths| {
        vec![
            paths.scope.join("denied.txt"),
            paths.root.join("payload.json"),
        ]
    });
    let permitted = write_file(&fixture.scope.join("permitted.txt"), "permitted");
    let denied = write_file(&fixture.scope.join("denied.txt"), "denied");
    let evidence = fixture.tree.path().join("payload.json");
    fixture
        .world
        .runtime
        .policy_writer()
        .enroll_deny(&denied)
        .expect("enroll the deny the hook rewrites into");
    let grant = fixture
        .world
        .runtime
        .set_read_scope(fixture.scope.clone(), permitted.clone());

    let error = admit_read(&mut fixture, &permitted, &grant)
        .expect_err("a permitted path rewritten into a denied one is refused");

    match &error {
        ExecutorError::HookTransform {
            hook,
            original,
            transformed,
        } => {
            assert_eq!(hook, HOOK_ID, "the refusal names the hook that rewrote");
            assert_eq!(original, &permitted.display().to_string());
            assert_eq!(transformed, &denied.display().to_string());
        }
        other => panic!("the rewrite must be refused at admission, got {other:?}"),
    }
    assert_eq!(
        fixture.world.worker_reads(),
        0,
        "nothing executed after the refusal"
    );
    assert_eq!(
        fixture
            .world
            .runtime
            .store()
            .latest_unresolved_attempt(&fixture.task)
            .expect("read the ledger"),
        None,
        "the refused attempt is settled, not left planned"
    );

    // The instrumented event and the arguments it carried are the ones the
    // contract names (I6): one event, the declared scope, the original path.
    let payload: Value =
        serde_json::from_str(&std::fs::read_to_string(&evidence).expect("hook payload"))
            .expect("payload is json");
    assert_eq!(payload["event"], "effect.request");
    assert_eq!(payload["scope"], "project");
    assert_eq!(
        payload["args"]["path"],
        permitted.display().to_string(),
        "the hook sees the request the caller admitted: {payload}"
    );
}

#[test]
fn hook_with_unchanged_arguments_still_runs_p5() {
    support::ensure_helper();
    let mut fixture = hook_fixture("instructions-p5", PASSTHROUGH_HOOK, &|paths| {
        vec![
            paths.root.join("marker.txt"),
            paths.root.join("payload.json"),
        ]
    });
    let target = write_file(&fixture.scope.join("target.txt"), "permitted");
    let grant = fixture
        .world
        .runtime
        .set_read_scope(fixture.scope.clone(), target.clone());

    let outcome = admit_read(&mut fixture, &target, &grant)
        .expect("an unchanged request is admitted and runs");

    assert!(
        matches!(&outcome, EffectOutcome::Read { bytes, .. } if bytes == b"permitted"),
        "the effect returned the file's bytes: {outcome:?}"
    );
    assert_eq!(fixture.world.worker_reads(), 1, "exactly one physical read");
    assert_eq!(
        std::fs::read_to_string(fixture.tree.path().join("marker.txt")).expect("the hook ran"),
        "ran",
        "the control is not vacuous: the hook really executed"
    );
}

/// Reads the payload, records it, and answers `stop`: one hook run has nothing
/// further to stop, so the request is refused.
const STOP_HOOK: &str = "#!/bin/sh\n\
     payload=$(cat)\n\
     printf '%s' \"$payload\" > \"$2\"\n\
     printf ran > \"$1\"\n\
     printf '{\"decision\":\"stop\"}'\n";

/// Answers past the cap from a background writer: the exchange drains the pipe
/// while the hook runs, so the cap — not the writer's own blocking write —
/// refuses the answer.
const OVERSIZED_HOOK: &str = "#!/bin/sh\n\
     cat > /dev/null\n\
     dd if=/dev/zero bs=65536 count=2 2>/dev/null &\n\
     exit 0\n";

/// Answers well-formed, but past the exchange's deadline.
const SLOW_HOOK: &str = "#!/bin/sh\n\
     cat > /dev/null\n\
     sleep 1\n\
     printf '{\"decision\":\"allow\"}'\n";

/// Answers outside the contract: not an answer, so it is not consent.
const MALFORMED_HOOK: &str = "#!/bin/sh\n\
     cat > /dev/null\n\
     printf 'decision: allow'\n";

/// Answers `allow` and exits, but leaves a descendant holding the answer pipe:
/// the read must end at the deadline, not at that descendant's EOF.
const HOLDING_HOOK: &str = "#!/bin/sh\n\
     cat > /dev/null\n\
     sleep 5 &\n\
     printf '{\"decision\":\"allow\"}'\n\
     exit 0\n";

/// Answers `allow` and exits while a forked descendant keeps running in the
/// hook's own process group. The descendant holds no answer pipe, so the run
/// ends on its answer — and the descendant must not outlive it.
const FORKING_HOOK: &str = "#!/bin/sh\n\
     cat > /dev/null\n\
     sleep 30 > /dev/null 2>&1 &\n\
     printf '%s' \"$!\" > \"$1\"\n\
     printf '{\"decision\":\"allow\"}'\n";

/// Whether `pid` is a running process: a live one reads its resident bytes, a
/// reaped one has no record left.
fn process_is_live(pid: u32) -> bool {
    matches!(rivect_sandbox_helper::resident_bytes(pid), Ok(bytes) if bytes > 0)
}

#[test]
fn hook_stop_answer_is_refused_p4() {
    support::ensure_helper();
    let mut fixture = hook_fixture("instructions-refuse-p4", STOP_HOOK, &|paths| {
        vec![
            paths.root.join("marker.txt"),
            paths.root.join("payload.json"),
        ]
    });
    let target = write_file(&fixture.scope.join("target.txt"), "permitted");
    let grant = fixture
        .world
        .runtime
        .set_read_scope(fixture.scope.clone(), target.clone());

    let error =
        admit_read(&mut fixture, &target, &grant).expect_err("a stop answer refuses the request");
    match &error {
        ExecutorError::HookDenied { hook, decision } => {
            assert_eq!(hook, HOOK_ID, "the refusal names the hook that answered");
            assert_eq!(*decision, "stop");
        }
        other => panic!("a stop answer is refused at admission, got {other:?}"),
    }
    assert_eq!(
        fixture.world.worker_reads(),
        0,
        "nothing executed after the refusal"
    );
    assert_eq!(
        std::fs::read_to_string(fixture.tree.path().join("marker.txt")).expect("the hook ran"),
        "ran",
        "the refusal is the answer's, not a hook that never ran"
    );
}

#[test]
fn hook_oversized_answer_is_refused_p5() {
    support::ensure_helper();
    let mut fixture = hook_fixture("instructions-refuse-p5", OVERSIZED_HOOK, &|_paths| {
        Vec::new()
    });
    let target = write_file(&fixture.scope.join("target.txt"), "permitted");
    let grant = fixture
        .world
        .runtime
        .set_read_scope(fixture.scope.clone(), target.clone());

    let error =
        admit_read(&mut fixture, &target, &grant).expect_err("an answer past the cap is refused");
    match &error {
        ExecutorError::Hook(HookError::OutputTooLarge { hook, limit }) => {
            assert_eq!(hook, HOOK_ID);
            assert_eq!(*limit, HOOK_STDOUT_MAX_BYTES);
        }
        other => panic!("an oversized answer is refused at the cap, got {other:?}"),
    }
    assert_eq!(
        fixture.world.worker_reads(),
        0,
        "nothing executed after the refusal"
    );
}

#[test]
fn hook_timeout_is_refused_p6() {
    support::ensure_helper();
    let mut fixture = hook_fixture("instructions-refuse-p6", SLOW_HOOK, &|_paths| Vec::new());
    let target = write_file(&fixture.scope.join("target.txt"), "permitted");
    let grant = fixture
        .world
        .runtime
        .set_read_scope(fixture.scope.clone(), target.clone());

    let error = admit_read(&mut fixture, &target, &grant)
        .expect_err("an answer past the deadline is refused");
    match &error {
        ExecutorError::Hook(HookError::TimedOut { hook, millis }) => {
            assert_eq!(hook, HOOK_ID);
            assert_eq!(*millis, HOOK_TIMEOUT_MS);
        }
        other => panic!("a silent hook is refused at its deadline, got {other:?}"),
    }
    assert_eq!(
        fixture.world.worker_reads(),
        0,
        "nothing executed after the refusal"
    );
}

#[test]
fn hook_answer_read_stays_inside_its_deadline_p5() {
    support::ensure_helper();
    let mut fixture = hook_fixture("instructions-refuse-p5-hold", HOLDING_HOOK, &|_paths| {
        Vec::new()
    });
    let target = write_file(&fixture.scope.join("target.txt"), "permitted");
    let grant = fixture
        .world
        .runtime
        .set_read_scope(fixture.scope.clone(), target.clone());

    let started = Instant::now();
    let error = admit_read(&mut fixture, &target, &grant)
        .expect_err("a hook that never closes its answer pipe is refused at its deadline");
    let elapsed = started.elapsed();
    match &error {
        ExecutorError::Hook(HookError::TimedOut { hook, millis }) => {
            assert_eq!(hook, HOOK_ID);
            assert_eq!(*millis, HOOK_TIMEOUT_MS);
        }
        other => panic!("the deadline, not the descendant, ends the read, got {other:?}"),
    }
    assert!(
        elapsed < Duration::from_millis(1000),
        "the read is bounded by the hook's {HOOK_TIMEOUT_MS} ms deadline, not by its \
         descendant's lifetime: {elapsed:?}"
    );
    assert_eq!(
        fixture.world.worker_reads(),
        0,
        "nothing executed after the refusal"
    );
}

#[test]
fn hook_child_tree_is_reaped_p6() {
    support::ensure_helper();
    let mut fixture = hook_fixture("instructions-reap-p6", FORKING_HOOK, &|paths| {
        vec![paths.root.join("descendant.pid")]
    });
    let target = write_file(&fixture.scope.join("target.txt"), "permitted");
    let grant = fixture
        .world
        .runtime
        .set_read_scope(fixture.scope.clone(), target.clone());

    let outcome = admit_read(&mut fixture, &target, &grant)
        .expect("the descendant holds no answer pipe, so the run ends on its answer");
    assert!(
        matches!(&outcome, EffectOutcome::Read { bytes, .. } if bytes == b"permitted"),
        "the effect returned the file's bytes: {outcome:?}"
    );
    let descendant: u32 = std::fs::read_to_string(fixture.tree.path().join("descendant.pid"))
        .expect("the hook reported the descendant it forked")
        .trim()
        .parse()
        .expect("the reported descendant is a pid");
    let deadline = Instant::now() + Duration::from_secs(2);
    while process_is_live(descendant) {
        assert!(
            Instant::now() < deadline,
            "the hook's forked descendant {descendant} outlived the run that started it"
        );
        rivect_sandbox_helper::wait_ready(&[], &[], Duration::from_millis(10))
            .expect("the bounded idle wait");
    }
}

#[test]
fn hook_malformed_answer_is_refused_p7() {
    support::ensure_helper();
    let mut fixture = hook_fixture("instructions-refuse-p7", MALFORMED_HOOK, &|_paths| {
        Vec::new()
    });
    let target = write_file(&fixture.scope.join("target.txt"), "permitted");
    let grant = fixture
        .world
        .runtime
        .set_read_scope(fixture.scope.clone(), target.clone());

    let error = admit_read(&mut fixture, &target, &grant)
        .expect_err("an answer outside the contract is refused");
    match &error {
        ExecutorError::Hook(HookError::Malformed { hook, detail }) => {
            assert_eq!(hook, HOOK_ID);
            assert!(
                !detail.is_empty(),
                "the refusal names what it could not read"
            );
        }
        other => panic!("a malformed answer is refused, got {other:?}"),
    }
    assert_eq!(
        fixture.world.worker_reads(),
        0,
        "nothing executed after the refusal"
    );
}

#[test]
fn transformed_arguments_are_rechecked_at_the_named_site_p8() {
    support::ensure_helper();
    let mut fixture = hook_fixture("instructions-p8", REWRITE_HOOK, &|paths| {
        vec![
            paths.scope.join("chosen.txt"),
            paths.root.join("payload.json"),
        ]
    });
    let admitted_path = write_file(&fixture.scope.join("admitted.txt"), "admitted");
    let chosen = write_file(&fixture.scope.join("chosen.txt"), "chosen");
    let grant = fixture
        .world
        .runtime
        .set_read_scope(fixture.scope.clone(), admitted_path.clone());

    // Permitted → permitted: the effect lands on the rewritten path, so the
    // admission and the effect both consumed the transformed arguments.
    let outcome = admit_read(&mut fixture, &admitted_path, &grant)
        .expect("a rewrite to a permitted path is admitted");
    let digest = match &outcome {
        EffectOutcome::Read { bytes, digest } => {
            assert_eq!(
                bytes, b"chosen",
                "the effect read the rewritten target, not the admitted one"
            );
            digest.clone()
        }
        other => panic!("the transformed read executes, got {other:?}"),
    };
    assert_eq!(
        digest,
        rivect::config::hex(&sha2::Sha256::digest(b"chosen")),
        "the confirmed digest is the rewritten file's"
    );

    // The same rewrite, denied: the rejection is the admission answer for the
    // transformed path, taken at the site the hook fired before.
    fixture
        .world
        .runtime
        .policy_writer()
        .enroll_deny(&chosen)
        .expect("deny the rewritten target");
    let error = admit_read(&mut fixture, &admitted_path, &grant)
        .expect_err("the denied rewrite is refused");
    assert!(
        matches!(&error, ExecutorError::HookTransform { transformed, .. } if transformed == &chosen.display().to_string()),
        "the refusal names the transformed target: {error:?}"
    );
    assert_eq!(
        fixture.world.worker_reads(),
        1,
        "the refused rewrite performs no second read"
    );
}

#[test]
fn machine_ingress_cannot_install_a_hook_p7() {
    // A hook entry is a program the executor runs, so the machine channel
    // never installs one (I7): the refusal is typed and names the key.
    let mut world = support::open_world("instructions-p7", Some(&support::base_config()));
    let session = world.open_session("p7-session");
    let key = "hooks.effect.request@project.command";
    let request = json!({
        "jsonrpc": "2.0", "id": 7107, "method": "command.execute",
        "params": { "schema_version": 1, "session_id": session.0,
                    "command": { "kind": "config.set" },
                    "key": key, "value": "/bin/true" }
    })
    .to_string();

    let machine = rivect::commands::dispatch_runtime_request(
        &mut world.runtime,
        rivect::commands::Ingress::Machine,
        support::CONNECTION_ID,
        &request,
    );
    let machine: Value = serde_json::from_str(&machine).expect("response is json");
    let message = machine["error"]["data"]["message"]
        .as_str()
        .expect("the machine install is refused");
    assert!(
        message.contains(key) && message.contains("machine ingress cannot install hook"),
        "the refusal names the key and the hook rule: {message}"
    );
    assert_eq!(
        machine["error"]["data"]["code"], "denied",
        "the refusal is a typed denial: {machine}"
    );

    // The human channel is refused too — by the edit domain, which is a
    // different cause, so the guard above is not a blanket refusal.
    let human = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 7108, "method": "command.execute",
        "params": { "schema_version": 1, "session_id": session.0,
                    "command": { "kind": "config.set" },
                    "key": key, "value": "/bin/true" }
    }));
    let human_message = human["error"]["data"]["message"]
        .as_str()
        .expect("the human install is refused by the edit domain");
    assert!(
        human_message.contains("not editable"),
        "the human cause is the document-only section: {human_message}"
    );

    // Nothing was installed on either channel.
    let document = std::fs::read_to_string(world.root.join("config.toml")).expect("config");
    assert!(!document.contains(key), "no edit landed: {document}");
    assert!(
        world
            .runtime
            .effective()
            .parsed
            .as_ref()
            .is_none_or(|config| config.hooks.is_empty()),
        "no hook reached the effective document"
    );
}

/// Answers `deny`: the declared hook refuses the request it was shown.
const DENY_HOOK: &str = "#!/bin/sh\n\
     cat > /dev/null\n\
     printf ran > \"$1\"\n\
     printf '{\"decision\":\"deny\"}'\n";

#[test]
fn scheduler_step_consults_the_declared_hook_p11() {
    // The declared hook is the document's, and the product's own step path is
    // where it must apply: a deny answer refuses the step's effect, not only
    // an executor a test built for itself.
    support::ensure_helper();
    let mut fixture = hook_fixture("instructions-p11", DENY_HOOK, &|paths| {
        vec![paths.root.join("marker.txt")]
    });
    let target = write_file(&fixture.scope.join("target.txt"), "permitted");
    let grant = fixture
        .world
        .runtime
        .set_read_scope(fixture.scope.clone(), target);

    let error = fixture
        .world
        .runtime
        .run_decision_step(
            &fixture.session,
            &fixture.task,
            &AnswerSelection::Option {
                option_id: OptionId("brief".to_string()),
            },
            &grant,
            false,
        )
        .expect_err("the declared hook's deny refuses the step's own admission");

    match &error {
        ControllerError::Executor(ExecutorError::HookDenied { hook, decision }) => {
            assert_eq!(hook, HOOK_ID, "the refusal names the hook that answered");
            assert_eq!(*decision, "deny");
        }
        other => panic!("the step consults the declared hook at admission, got {other:?}"),
    }
    assert_eq!(
        fixture.world.worker_reads(),
        0,
        "the denied effect never ran"
    );
    assert_eq!(
        std::fs::read_to_string(fixture.tree.path().join("marker.txt")).expect("the hook ran"),
        "ran",
        "the refusal is the answer's, not a hook that never ran"
    );
}

// ------------------------------------------------------------------- config

#[test]
fn unknown_root_key_names_legal_roots_p10() {
    // A near miss gets the whole legal root set and the nearest one.
    let text = format!("hook = 1\n{}", support::base_config());
    let error = Config::parse_validated(&text).expect_err("a near-miss root is refused");
    assert!(
        matches!(&error.issue, ConfigIssue::UnknownRootKey { key } if key == "hook"),
        "the rejection keeps the root spelling: {error}"
    );
    let message = error.to_string();
    assert!(
        message.contains("unknown root key hook"),
        "the refusal names the key: {message}"
    );
    for root in CONFIG_ROOTS {
        assert!(
            message.contains(root),
            "the refusal names the legal root {root}: {message}"
        );
    }
    assert!(
        message.contains("nearest key: hooks"),
        "the refusal names the nearest legal key: {message}"
    );

    // A spelling with no near match gets no misleading suggestion: the
    // distance decides, not the mere presence of a rejection.
    let far = Config::parse_validated(&format!("bogus_root = 1\n{}", support::base_config()))
        .expect_err("an unrelated root is refused");
    let far_message = far.to_string();
    assert_eq!(
        far_message, "schema bogus_root: unknown root key bogus_root",
        "an unrelated spelling invents no nearest key"
    );
}

#[test]
fn every_carrier_comes_from_one_table_p11() {
    // One hand-written fixture document; the carrier list under test comes
    // from `CONFIG_CARRIERS`, so a carrier added there is asserted here.
    let document = "config_version = 1\n\
                    [workflow]\nenabled = true\n\
                    [decisions]\nmode = \"ask\"\n\
                    [context]\nauto_compact = false\n\
                    [connections.openai]\n\
                    kind = \"api_key\"\n\
                    endpoint = \"https://api.openai.com/v1\"\n\
                    credential_ref = \"keyring:rivect/openai\"\n\
                    region = \"us-east-1\"\n\
                    profile = \"default\"\n\
                    [profiles.default]\n\
                    credential_ref = \"keyring:rivect/default\"\n\
                    [models.defaults]\n\
                    model = { mode = \"auto\" }\n\
                    effort = { mode = \"auto\" }\n\
                    fallback = { mode = \"auto\" }\n";
    let mut config = Config::parse_validated(document).expect("the carrier document parses");

    let hint = rivect::config::read_key_hint();
    for carrier in CONFIG_CARRIERS {
        assert!(
            rivect::config::is_readable_key(carrier.sample),
            "{} is in the read domain",
            carrier.sample
        );
        assert!(
            hint.contains(carrier.pattern),
            "the read hint descends from the table, missing {}: {hint}",
            carrier.pattern
        );
        let served = config
            .read_value(carrier.sample)
            .unwrap_or_else(|| panic!("{} serves a value", carrier.sample));
        config
            .set_wire(carrier.sample, &served)
            .unwrap_or_else(|error| panic!("{} is editable: {error}", carrier.sample));
        assert_eq!(
            config.read_value(carrier.sample),
            Some(served),
            "the read and the write agree on {}",
            carrier.sample
        );
    }

    // The table is the whole read domain, not a sample of it: a key outside
    // it is refused, so no second, hand-written list answers.
    assert!(!rivect::config::is_readable_key(
        "hooks.effect.request@project.command"
    ));
    assert!(!rivect::config::is_readable_key("models.defaults.model"));
}

#[test]
fn the_name_table_names_every_folded_slot() {
    // The four candidate names and the two slots they fold into, from the one
    // table the discovery compares before any file is loaded.
    assert_eq!(INSTRUCTION_FILES.len(), 4);
    let mut agent = 0;
    let mut claude = 0;
    for (name, slot) in INSTRUCTION_FILES {
        assert_eq!(
            rivect::instructions::fold(name),
            Some(slot),
            "{name} folds to the slot the table declares"
        );
        match slot {
            InstructionSlot::Agent => agent += 1,
            InstructionSlot::Claude => claude += 1,
        }
    }
    assert_eq!((agent, claude), (2, 2), "canonical and alias per slot");
    assert_eq!(rivect::instructions::fold("README.md"), None);
}
