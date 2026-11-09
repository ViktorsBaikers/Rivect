//! Activation proof surface: both production entrypoints open their one
//! runtime through `Runtime::open_configured`, whose factory runs on the
//! admitted effective config before the broker exists. A config edit never
//! rewrites an admitted request's wire target; a build runs before the
//! durable write, so a whole-build refusal leaves the file and the previous
//! pair untouched while a refused row installs the rest of the set without it
//! and reports its cause; a successful edit installs the rebuilt provider
//! before the view moves. The factory is the production one, so an ordinary
//! dispatch crosses the configured adapter to a loopback peer — never the
//! fixture.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::let_underscore_must_use,
    let_underscore_drop,
    clippy::redundant_clone,
    reason = "test code keeps unwrap/expect/panic/discard conveniences; src/ stays strict (standards §14)"
)]

mod support;

use rivect::commands::Runtime;
use rivect::config::{Config, ConfigIssue, DecisionModeValue, Stage};
use rivect::model::ModelError;
use rivect::owner::OwnerError;
use rivect::providers::ProviderError;
use serde_json::json;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// The pinned model the fixture config declares: a fixed pin sends without
/// a catalogue lookup, so one dispatch is exactly one wire request.
const MODEL: &str = "fixture-chat-model";

/// One configured `vllm` row pointing at a loopback peer: the kind is
/// `local`, the dialect comes from the literal id, and the endpoint carries
/// the API base's version segment the adapter's recorded paths append to.
fn config_for(endpoint: &str, region: Option<&str>) -> String {
    let region = region
        .map(|value| format!("region = \"{value}\"\n"))
        .unwrap_or_default();
    format!(
        "config_version = 1\n\
         [connections.vllm]\nkind = \"local\"\nendpoint = \"{endpoint}\"\n{region}\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"vllm\", model_id = \"{MODEL}\" }}\n\
         effort = {{ mode = \"auto\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    )
}

/// Two configured local peers with the pin on the first: an edit of the
/// default model is the provider-relevant key `config.set` can move, and the
/// endpoint the peer observed is the target the next dispatch really reached.
fn two_peer_config(first: &str, second: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.vllm]\nkind = \"local\"\nendpoint = \"{first}\"\n\
         [connections.\"llama.cpp\"]\nkind = \"local\"\nendpoint = \"{second}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"vllm\", model_id = \"{MODEL}\" }}\n\
         effort = {{ mode = \"auto\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    )
}

/// A profiled local row beside a keyless one: a `profiles.<name>` edit makes
/// the factory refuse the profiled row, while the keyless row keeps serving
/// and the refused row's own kind stays locally usable (so a request pinned
/// to it reaches the provider gate instead of failing eligibility).
fn profiled_config_for(endpoint: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.vllm]\nkind = \"local\"\nendpoint = \"{endpoint}\"\nprofile = \"p1\"\n\
         [connections.\"llama.cpp\"]\nkind = \"local\"\nendpoint = \"{endpoint}\"\n\
         [profiles.p1]\ncredential_ref = \"keyring:rivect-test/p1\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"llama.cpp\", model_id = \"{MODEL}\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    )
}

fn open_runtime(root: &Path) -> Result<Runtime, Box<dyn std::error::Error>> {
    Ok(Runtime::open_configured(
        root,
        rivect::providers::configured_provider,
    )?)
}

/// A pinned `vllm` row whose own entry carries a `profile`: a successful edit
/// can move that member while the endpoint and dialect stay identical, so the
/// adapter built before the edit names an entry the served view no longer has.
fn profiled_connection_config(endpoint: &str) -> String {
    format!(
        "config_version = 1\n\
         [profiles.pinned]\ncredential_ref = \"keyring:rivect-test/pinned\"\n\
         [connections.vllm]\nkind = \"local\"\nendpoint = \"{endpoint}\"\nprofile = \"pinned\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"vllm\", model_id = \"{MODEL}\" }}\n\
         effort = {{ mode = \"auto\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    )
}

/// Two local peers with the default pin on `vllm` and a second purpose on
/// `llama.cpp`: a `connections.vllm.region` edit moves the frozen entry and
/// has the build refuse that row, while the second-purpose row keeps serving.
fn entry_moving_config(first: &str, second: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.vllm]\nkind = \"local\"\nendpoint = \"{first}\"\n\
         [connections.\"llama.cpp\"]\nkind = \"local\"\nendpoint = \"{second}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"vllm\", model_id = \"{MODEL}\" }}\n\
         effort = {{ mode = \"auto\" }}\n\
         fallback = {{ mode = \"off\" }}\n\
         [models.purposes.spare]\n\
         model = {{ mode = \"fixed\", connection = \"llama.cpp\", model_id = \"{MODEL}\" }}\n\
         effort = {{ mode = \"auto\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    )
}

/// One profile-bound connection: the connection row itself carries no
/// credential, so a `profiles.<p>.credential_ref` edit moves only the frozen
/// credential the send resolves.
fn credential_bound_config(endpoint: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.vllm]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\nprofile = \"p1\"\n\
         [profiles.p1]\ncredential_ref = \"keyring:rivect-test/p1\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"vllm\", model_id = \"{MODEL}\" }}\n\
         effort = {{ mode = \"auto\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    )
}

/// One `command.execute` frame, admitted as the trusted human the config
/// carriers are the same for.
fn config_command(
    runtime: &mut Runtime,
    key: &str,
    value: serde_json::Value,
    command: &str,
) -> serde_json::Value {
    let request = json!({
        "jsonrpc": "2.0", "id": 1, "method": "command.execute",
        "params": { "schema_version": 1, "session_id": "activation-session",
                    "command": { "kind": command },
                    "key": key, "value": value }
    });
    serde_json::from_str(&rivect::commands::dispatch_runtime_request(
        runtime,
        rivect::commands::Ingress::TrustedHuman,
        "activation-connection",
        &request.to_string(),
    ))
    .expect("the answer is one frame")
}

/// The refused-row diagnostic the production build emits: the boot channel
/// carries it, so an entrypoint that installed the configured set reports it
/// and one that installed the fixture cannot.
const REFUSED_ROW_MARKER: &str = "provider build: connection vllm was not installed";

/// The headless entry consumes the production factory: a document whose
/// `vllm` row the build refuses still opens, and the refused row's typed
/// cause reaches the boot channel — a line only the configured factory can
/// produce, because the fixture carrier never reads the document at all.
#[test]
fn headless_entry_reports_the_refused_row_its_production_factory_recorded()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::TempDir::with_prefix("rivect-activation-headless-")?;
    std::fs::write(
        root.path().join("config.toml"),
        config_for("http://127.0.0.1:11434", Some("eu-west-1")),
    )?;

    let child = Command::new(support::rivect_binary())
        .arg("--headless")
        .arg("--data-root")
        .arg(root.path())
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", root.path())
        .stdin(Stdio::null())
        .output()?;

    assert!(
        child.status.success(),
        "a refused row must not fail the open: {child:?}"
    );
    let stderr = String::from_utf8_lossy(&child.stderr);
    assert!(
        stderr.contains(REFUSED_ROW_MARKER),
        "the headless entry must report the factory's refused row: {stderr}"
    );
    assert!(
        stderr.contains("region eu-west-1 is outside the dialect's endpoint contract"),
        "the reported cause is the factory's typed one: {stderr}"
    );
    assert!(
        child.stdout.is_empty(),
        "no request was made, so no frame is owed: {:?}",
        String::from_utf8_lossy(&child.stdout)
    );
    Ok(())
}

/// The TUI entry consumes the same production factory: its eager open runs
/// the configured build, so the refused row's diagnostic lands in the
/// transcript the first frame paints — the fixture carrier would open
/// silently.
#[test]
fn tui_entry_reports_the_refused_row_its_production_factory_recorded()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::TempDir::with_prefix("rivect-activation-tui-")?;
    std::fs::write(
        root.path().join("config.toml"),
        config_for("http://127.0.0.1:11434", Some("eu-west-1")),
    )?;
    let data_root = root.path().to_path_buf();
    let mut pty = support::spawn_pty_with_args(
        &support::rivect_binary(),
        40,
        120,
        root,
        &data_root,
        &data_root,
        &[],
    );
    assert!(
        pty.wait_for(b"\x1b[?1049h", Duration::from_secs(10))
            .expect("pty read"),
        "the TUI enters the alternate screen; got {:?}",
        String::from_utf8_lossy(&pty.collected().expect("pty read"))
    );
    let visible =
        support::wait_for_screen_text(&pty, 40, 120, REFUSED_ROW_MARKER, Duration::from_secs(10))
            .expect("pty read");
    assert!(
        visible.contains(REFUSED_ROW_MARKER),
        "the transcript must carry the factory's refused row; got {visible:?}"
    );
    pty.send(b"\x1b").expect("pty send");
    assert_eq!(
        pty.wait_exit(Duration::from_secs(10)).expect("pty wait"),
        Some(0)
    );
    pty.finish().expect("pty teardown");
    Ok(())
}

/// The production factory runs on the admitted effective config: the open
/// installs the one configured provider, and an ordinary dispatch crosses
/// the configured adapter to the peer it names.
#[test]
fn the_configured_open_dispatches_through_the_production_provider()
-> Result<(), Box<dyn std::error::Error>> {
    let peer = LocalPeer::start("configured peer answered");
    let root = tempfile::TempDir::with_prefix("rivect-activation-open-")?;
    std::fs::write(
        root.path().join("config.toml"),
        config_for(&peer.endpoint, None),
    )?;

    let mut runtime = open_runtime(root.path())?;
    assert_eq!(
        runtime.broker.provider_name(),
        "configured",
        "the open must install the production provider set, never a fixture"
    );

    let config = runtime.config_for_broker();
    let manifest =
        runtime
            .broker
            .prepare("main", &config, "/world/activation", "goal: configured run")?;
    let mut ledger = support::CountingLedger::new();
    let reply = runtime
        .broker
        .dispatch(&mut ledger, "/world/activation", &manifest)?;
    assert_eq!(reply.text, "configured peer answered");
    assert_eq!((ledger.begun, ledger.finished), (1, 1));

    let requests = peer.requests();
    assert_eq!(requests.len(), 1, "one physical send crossed the wire");
    assert!(
        requests[0].starts_with("POST /v1/chat/completions HTTP/1.1"),
        "the configured adapter sent the chat-completions request: {}",
        requests[0]
    );
    Ok(())
}

/// A connection no installed adapter serves denies typed before any send:
/// no adapter call, no reservation and no settlement.
#[test]
fn an_unserved_connection_denies_typed_with_zero_sends_and_settlements()
-> Result<(), Box<dyn std::error::Error>> {
    let peer = LocalPeer::start("must never answer");
    let root = tempfile::TempDir::with_prefix("rivect-activation-unserved-")?;
    let document = format!(
        "config_version = 1\n\
         [connections.mystery]\nkind = \"local\"\nendpoint = \"{}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"mystery\", model_id = \"{MODEL}\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n",
        peer.endpoint
    );
    std::fs::write(root.path().join("config.toml"), document)?;

    let mut runtime = open_runtime(root.path())?;
    let config = runtime.config_for_broker();
    let manifest =
        runtime
            .broker
            .prepare("main", &config, "/world/activation", "goal: unserved")?;
    let mut ledger = support::CountingLedger::new();
    let error = runtime
        .broker
        .dispatch(&mut ledger, "/world/activation", &manifest)
        .expect_err("an id no adapter serves must deny");
    match error {
        ModelError::Provider(ProviderError::DialectMismatch { connection }) => {
            assert_eq!(connection, "mystery");
        }
        other => panic!("expected the typed dialect denial, got {other:?}"),
    }
    assert_eq!((ledger.begun, ledger.finished), (0, 0));
    assert!(peer.requests().is_empty(), "the provider was never reached");
    assert_eq!(runtime.broker.accounted_requests(), 0);
    Ok(())
}

/// A config edit after admission freezes the old request on its admitted
/// entry: dispatch denies `ConnectionChanged` before any request, with zero
/// provider calls and zero settlements.
#[test]
fn a_connection_edited_after_admission_denies_changed_with_zero_sends()
-> Result<(), Box<dyn std::error::Error>> {
    let first = LocalPeer::start("first endpoint");
    let second = LocalPeer::start("second endpoint");
    let root = tempfile::TempDir::with_prefix("rivect-activation-changed-")?;
    let config_path = root.path().join("config.toml");
    std::fs::write(&config_path, config_for(&first.endpoint, None))?;

    let mut runtime = open_runtime(root.path())?;
    let config = runtime.config_for_broker();
    let manifest = runtime.broker.prepare(
        "main",
        &config,
        "/world/activation",
        "goal: edited connection",
    )?;

    std::fs::write(&config_path, config_for(&second.endpoint, None))?;
    runtime.reload_config()?;

    let mut ledger = support::CountingLedger::new();
    let error = runtime
        .broker
        .dispatch(&mut ledger, "/world/activation", &manifest)
        .expect_err("the edited entry must deny the admitted request");
    match error {
        ModelError::ConnectionChanged {
            attempt_id,
            connection,
        } => {
            assert_eq!(attempt_id, manifest.attempt_id);
            assert_eq!(connection, "vllm");
        }
        other => panic!("expected ConnectionChanged, got {other:?}"),
    }
    assert_eq!((ledger.begun, ledger.finished), (0, 0));
    assert!(first.requests().is_empty(), "the old entry was not sent to");
    assert!(
        second.requests().is_empty(),
        "the new entry was not sent to"
    );
    assert_eq!(runtime.broker.accounted_requests(), 0);
    Ok(())
}

/// A landed edit whose rebuilt set refuses one row still serves: the other
/// rows install, the moved config is the served one, the refused row is
/// reported in the command result and the diagnostics, and a request pinned
/// to it denies typed before any send.
#[test]
fn a_landed_edit_that_refuses_one_row_installs_the_set_without_it()
-> Result<(), Box<dyn std::error::Error>> {
    let peer = LocalPeer::start("the servable row answered");
    let root = tempfile::TempDir::with_prefix("rivect-activation-landed-refusal-")?;
    std::fs::write(
        root.path().join("config.toml"),
        profiled_config_for(&peer.endpoint),
    )?;

    let mut runtime = open_runtime(root.path())?;
    let mut ledger = support::CountingLedger::new();
    let config = runtime.config_for_broker();
    let servable =
        runtime
            .broker
            .prepare("main", &config, "/world/activation", "goal: servable row")?;
    assert_eq!(
        runtime
            .broker
            .dispatch(&mut ledger, "/world/activation", &servable)?
            .text,
        "the servable row answered"
    );

    // p1's ref moves to a scope naming another profile: the document
    // validates, the factory build refuses that row typed.
    let answered = config_command(
        &mut runtime,
        "profiles.p1.credential_ref",
        json!("keyring:rivect-test/p2"),
        "config.set",
    );
    assert!(
        answered.get("error").is_none(),
        "the edit is served while one row is refused: {answered}"
    );
    let diagnostics = answered["result"]["diagnostics"]
        .as_array()
        .expect("the result carries the refused rows");
    assert!(
        diagnostics.iter().any(|line| line
            .as_str()
            .is_some_and(|line| line.contains("binds profile p1"))),
        "the typed factory cause rides the result: {answered}"
    );
    assert!(
        runtime
            .boot_diagnostics
            .iter()
            .any(|line| line.contains("binds profile p1")),
        "the same cause joins the diagnostics: {:?}",
        runtime.boot_diagnostics
    );

    // The edited document is the served one; the refused row is uninstalled,
    // so a request pinned to it denies typed before any send.
    let config = runtime.config_for_broker();
    assert_eq!(
        config.profiles["p1"].credential_ref.as_deref(),
        Some("keyring:rivect-test/p2"),
        "the landed edit is the served config"
    );
    assert!(
        std::fs::read_to_string(root.path().join("config.toml"))?
            .contains("keyring:rivect-test/p2"),
        "the served edit is the one on disk"
    );
    let mut pinned = config.clone();
    if let Some(defaults) = pinned.models.defaults.as_mut() {
        defaults.model = rivect::config::ModelAssign::Fixed(rivect::config::FixedModel {
            connection: "vllm".to_string(),
            model_id: MODEL.to_string(),
        });
    }
    let refused =
        runtime
            .broker
            .prepare("main", &pinned, "/world/activation", "goal: refused row")?;
    match runtime
        .broker
        .dispatch(&mut ledger, "/world/activation", &refused)
    {
        Err(ModelError::Provider(ProviderError::DialectUnserved { connection, .. })) => {
            assert_eq!(connection, "vllm");
        }
        other => panic!("expected the refused row's typed denial, got {other:?}"),
    }

    // The unrelated row the edit left in scope still installs beside the
    // refused one: the rebuilt set is not only the changed and refused rows.
    let still_servable =
        runtime
            .broker
            .prepare("main", &config, "/world/activation", "goal: servable row")?;
    assert_eq!(
        runtime
            .broker
            .dispatch(&mut ledger, "/world/activation", &still_servable)?
            .text,
        "the servable row answered"
    );
    assert_eq!(
        (ledger.begun, ledger.finished),
        (2, 2),
        "the servable row opened and closed a settlement either side of the refusal"
    );
    assert_eq!(
        peer.requests().len(),
        2,
        "only the servable row crossed the wire"
    );
    Ok(())
}

/// A reload rebuilds the provider from the new config: after the endpoint
/// edit the next admitted request is served by the new endpoint's peer.
#[test]
fn reload_rebinds_the_provider_to_the_new_endpoint() -> Result<(), Box<dyn std::error::Error>> {
    let first = LocalPeer::start("first endpoint answered");
    let second = LocalPeer::start("second endpoint answered");
    let root = tempfile::TempDir::with_prefix("rivect-activation-reload-")?;
    let config_path = root.path().join("config.toml");
    std::fs::write(&config_path, config_for(&first.endpoint, None))?;

    let mut runtime = open_runtime(root.path())?;
    let config = runtime.config_for_broker();
    let before =
        runtime
            .broker
            .prepare("main", &config, "/world/activation", "goal: before reload")?;
    let mut ledger = support::CountingLedger::new();
    assert_eq!(
        runtime
            .broker
            .dispatch(&mut ledger, "/world/activation", &before)?
            .text,
        "first endpoint answered"
    );

    std::fs::write(&config_path, config_for(&second.endpoint, None))?;
    runtime.reload_config()?;
    assert_eq!(
        runtime.config_for_broker().connections["vllm"].endpoint,
        second.endpoint,
        "the admitted config moved with the reload"
    );
    let config = runtime.config_for_broker();
    let after =
        runtime
            .broker
            .prepare("main", &config, "/world/activation", "goal: after reload")?;
    assert_eq!(
        runtime
            .broker
            .dispatch(&mut ledger, "/world/activation", &after)?
            .text,
        "second endpoint answered"
    );

    assert_eq!((ledger.begun, ledger.finished), (2, 2));
    assert_eq!(first.requests().len(), 1, "the old endpoint served once");
    assert_eq!(
        second.requests().len(),
        1,
        "the rebound provider served once"
    );
    Ok(())
}

/// A reload whose rebuilt set refuses one row installs the rest and reports
/// the cause: the landed document is the served config, the refused row is
/// denied typed at its send gate while the second row the document still
/// declares serves its own peer, and the reload is a served edit rather than
/// a wedge that would refuse every later edit.
#[test]
fn a_reload_that_refuses_one_row_installs_the_set_without_it()
-> Result<(), Box<dyn std::error::Error>> {
    let first = LocalPeer::start("first pin answered");
    let second = LocalPeer::start("second pin answered");
    let root = tempfile::TempDir::with_prefix("rivect-activation-refused-")?;
    let config_path = root.path().join("config.toml");
    std::fs::write(
        &config_path,
        two_peer_config(&first.endpoint, &second.endpoint),
    )?;

    let mut runtime = open_runtime(root.path())?;
    let mut ledger = support::CountingLedger::new();
    let config = runtime.config_for_broker();
    let served = runtime.broker.prepare(
        "main",
        &config,
        "/world/activation",
        "goal: before the refused reload",
    )?;
    assert_eq!(
        runtime
            .broker
            .dispatch(&mut ledger, "/world/activation", &served)?
            .text,
        "first pin answered"
    );

    // A region on a local row is the recorded contradiction the local
    // adapter constructor refuses: the document validates, the build refuses
    // that row, and the second local row stays servable.
    std::fs::write(
        &config_path,
        format!(
            "config_version = 1\n\
             [connections.vllm]\nkind = \"local\"\nendpoint = \"{}\"\nregion = \"eu-west-1\"\n\
             [connections.\"llama.cpp\"]\nkind = \"local\"\nendpoint = \"{}\"\n\
             [models.defaults]\n\
             model = {{ mode = \"fixed\", connection = \"llama.cpp\", model_id = \"{MODEL}\" }}\n\
             effort = {{ mode = \"auto\" }}\n\
             fallback = {{ mode = \"off\" }}\n",
            first.endpoint, second.endpoint
        ),
    )?;
    runtime
        .reload_config()
        .expect("a refused row does not fail the reload");
    assert_eq!(
        runtime.config_for_broker().connections["vllm"]
            .region
            .as_deref(),
        Some("eu-west-1"),
        "the landed document is the served config"
    );
    assert!(
        runtime
            .boot_diagnostics
            .iter()
            .any(|line| line.contains(REFUSED_ROW_MARKER)),
        "the refused row's cause is reported: {:?}",
        runtime.boot_diagnostics
    );

    // The refused row is uninstalled, so a dispatch to it denies typed
    // before any send.
    let config = runtime.config_for_broker();
    let mut pinned = config.clone();
    if let Some(defaults) = pinned.models.defaults.as_mut() {
        defaults.model = rivect::config::ModelAssign::Fixed(rivect::config::FixedModel {
            connection: "vllm".to_string(),
            model_id: MODEL.to_string(),
        });
    }
    let refused =
        runtime
            .broker
            .prepare("main", &pinned, "/world/activation", "goal: refused row")?;
    match runtime
        .broker
        .dispatch(&mut ledger, "/world/activation", &refused)
    {
        Err(ModelError::Provider(ProviderError::DialectUnserved { connection, .. })) => {
            assert_eq!(connection, "vllm");
        }
        other => panic!("expected the refused row's typed denial, got {other:?}"),
    }

    // The second row the reload left in scope still installs and serves: the
    // rebuilt set is not only the refused row.
    let still_servable =
        runtime
            .broker
            .prepare("main", &config, "/world/activation", "goal: servable row")?;
    assert_eq!(
        runtime
            .broker
            .dispatch(&mut ledger, "/world/activation", &still_servable)?
            .text,
        "second pin answered"
    );
    assert_eq!(
        (ledger.begun, ledger.finished),
        (2, 2),
        "the pre-reload send and the servable row opened and closed settlements"
    );
    assert_eq!(first.requests().len(), 1, "the first peer served once");
    assert_eq!(
        second.requests().len(),
        1,
        "the rebuilt set served the second peer; the refused row never crossed the wire"
    );
    Ok(())
}

/// The configured set answers only for the connection entry it was built
/// from: a view that moved without a rebuild is refused at the adapter's own
/// gate, before the ledger or the wire — the second half of the dispatch
/// re-check's guarantee, so no divergence can silently send.
#[test]
fn the_configured_set_serves_only_the_entry_it_was_built_from()
-> Result<(), Box<dyn std::error::Error>> {
    let config = Config::parse_validated(&config_for("http://127.0.0.1:11434/v1", None))?;
    let store = rivect::providers::platform_credential_store();
    let build = rivect::providers::configured_provider(&config, &store)?;
    let entry = config.connections["vllm"].clone();
    assert!(
        build.provider.serves("vllm", &entry),
        "the built entry is served"
    );
    let mut moved = entry.clone();
    moved.endpoint = "http://127.0.0.1:11435/v1".to_string();
    assert!(
        !build.provider.serves("vllm", &moved),
        "an entry the adapter was not built from is refused"
    );
    assert!(
        !build.provider.serves("mystery", &entry),
        "a connection with no adapter is never served"
    );
    Ok(())
}

/// A whole-build refusal at the configured open fails the open with its typed
/// cause — readable through the open error's own accessor — and leaves no
/// half-open runtime: the corrected document opens the same root again.
#[test]
fn open_configured_refusal_carries_the_typed_cause_and_leaves_no_runtime()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::TempDir::with_prefix("rivect-activation-open-refused-")?;
    let config_path = root.path().join("config.toml");
    std::fs::write(&config_path, config_for("http://127.0.0.1:11434", None))?;

    let refusal = Runtime::open_configured(root.path(), |_config, _store| {
        Err(ProviderError::RegionMismatch {
            connection: "vllm".to_string(),
            region: "eu-west-1".to_string(),
        })
    })
    .expect_err("a factory that refuses the whole build fails the open");
    match refusal.provider_refusal() {
        Some(ProviderError::RegionMismatch { connection, region }) => {
            assert_eq!(connection, "vllm");
            assert_eq!(region, "eu-west-1");
        }
        other => panic!("the typed provider cause must be readable: {other:?}"),
    }
    match refusal.into_source() {
        OwnerError::Config { source, .. } => {
            assert_eq!(source.stage, Stage::Provider, "the class is the document's");
            // The typed cause is reachable through the `source()` walk, not
            // only the open error's own accessor.
            let issue = std::error::Error::source(&source)
                .expect("the config error carries its issue as its source");
            let cause = issue
                .source()
                .expect("the provider build issue carries its typed cause");
            assert!(
                cause.to_string().contains("region eu-west-1"),
                "the source walk reaches the typed provider refusal: {cause}"
            );
        }
        other => panic!("expected the provider build refusal, got {other:?}"),
    }

    // No half-open runtime: the failed open released its owner election and
    // store, so the corrected document opens the same root.
    let reopened = open_runtime(root.path())?;
    drop(reopened);
    Ok(())
}

/// A refused row does not brick the open: the set installs without it, its
/// typed cause is reported, a dispatch to it denies before any send, and the
/// rest of the set still serves.
#[test]
fn a_refused_row_leaves_the_open_and_the_other_rows_serving()
-> Result<(), Box<dyn std::error::Error>> {
    let peer = LocalPeer::start("the servable row answered");
    let root = tempfile::TempDir::with_prefix("rivect-activation-partial-")?;
    let document = format!(
        "config_version = 1\n\
         [connections.vllm]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:11434/v1\"\nregion = \"eu-west-1\"\n\
         [connections.\"llama.cpp\"]\nkind = \"local\"\nendpoint = \"{}\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"vllm\", model_id = \"{MODEL}\" }}\n\
         effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
         fallback = {{ mode = \"off\" }}\n",
        peer.endpoint
    );
    std::fs::write(root.path().join("config.toml"), document)?;

    let mut runtime = open_runtime(root.path())?;
    assert_eq!(runtime.broker.provider_name(), "configured");
    assert!(
        runtime
            .boot_diagnostics
            .iter()
            .any(|line| line.contains(REFUSED_ROW_MARKER)),
        "the refused row's cause is reported: {:?}",
        runtime.boot_diagnostics
    );

    // The refused row denies typed at its send gate; nothing is reserved.
    let config = runtime.config_for_broker();
    let refused =
        runtime
            .broker
            .prepare("main", &config, "/world/activation", "goal: refused row")?;
    let mut ledger = support::CountingLedger::new();
    match runtime
        .broker
        .dispatch(&mut ledger, "/world/activation", &refused)
    {
        Err(ModelError::Provider(ProviderError::DialectUnserved { connection, .. })) => {
            assert_eq!(connection, "vllm");
        }
        other => panic!("expected the refused row's typed denial, got {other:?}"),
    }
    assert_eq!((ledger.begun, ledger.finished), (0, 0));

    // The other row was built and serves: the pin moves onto it locally, and
    // the dispatch crosses that adapter to the peer.
    let mut servable = config.clone();
    if let Some(defaults) = servable.models.defaults.as_mut() {
        defaults.model = rivect::config::ModelAssign::Fixed(rivect::config::FixedModel {
            connection: "llama.cpp".to_string(),
            model_id: MODEL.to_string(),
        });
    }
    let manifest =
        runtime
            .broker
            .prepare("main", &servable, "/world/activation", "goal: servable row")?;
    assert_eq!(
        runtime
            .broker
            .dispatch(&mut ledger, "/world/activation", &manifest)?
            .text,
        "the servable row answered"
    );
    assert_eq!(
        peer.requests().len(),
        1,
        "the built row crossed the wire while the refused one did not"
    );
    Ok(())
}

/// The factory receives the resolved effective config: values the user's
/// document never states (the shipped defaults' workflow flag and decision
/// mode) are present, every typed section equals the config the broker
/// serves, and a reload repeats that with the new document.
#[test]
fn the_factory_receives_the_resolved_effective_config_and_a_reload_repeats_it()
-> Result<(), Box<dyn std::error::Error>> {
    let peer = LocalPeer::start("factory config answered");
    let root = tempfile::TempDir::with_prefix("rivect-activation-factory-config-")?;
    let config_path = root.path().join("config.toml");
    let document = config_for(&peer.endpoint, None);
    assert!(
        !document.contains("workflow") && !document.contains("decisions"),
        "the case only discriminates if those sections come from the shipped base"
    );
    std::fs::write(&config_path, &document)?;

    let captured: Arc<Mutex<Vec<Config>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&captured);
    let mut runtime = Runtime::open_configured(root.path(), move |config, store| {
        sink.lock().expect("factory log lock").push(config.clone());
        rivect::providers::configured_provider(config, store)
    })?;

    let first = {
        let captured = captured.lock().expect("factory log lock");
        assert_eq!(captured.len(), 1, "the open built through the factory once");
        captured[0].clone()
    };
    assert_eq!(
        first.workflow.enabled,
        Some(true),
        "the shipped base's workflow flag reached the factory"
    );
    assert_eq!(
        first.decisions.mode,
        Some(DecisionModeValue::Ask),
        "the shipped base's decision mode reached the factory"
    );
    let served = runtime.config_for_broker();
    assert_eq!(first.connections, served.connections, "connections");
    assert_eq!(first.profiles, served.profiles, "profiles");
    assert_eq!(first.models, served.models, "models");
    assert_eq!(first.workflow, served.workflow, "workflow");
    assert_eq!(first.decisions, served.decisions, "decisions");
    assert_eq!(first.context, served.context, "context");

    // The reload re-runs the factory on the new document: the endpoint is the
    // provider-relevant value a file edit moves without changing the row.
    let second = LocalPeer::start("factory config reloaded");
    std::fs::write(&config_path, config_for(&second.endpoint, None))?;
    runtime.reload_config()?;

    let (before_reload, after_reload) = {
        let captured = captured.lock().expect("factory log lock");
        assert_eq!(
            captured.len(),
            2,
            "the reload rebuilt through the factory once"
        );
        (captured[0].clone(), captured[1].clone())
    };
    assert_eq!(
        after_reload.connections["vllm"].endpoint, second.endpoint,
        "the factory saw the reloaded document"
    );
    let served = runtime.config_for_broker();
    assert_eq!(after_reload.connections, served.connections);
    assert_eq!(after_reload.models, served.models);
    assert_ne!(
        before_reload.connections, after_reload.connections,
        "the reload changed the config the factory saw"
    );
    Ok(())
}

/// A provider-relevant `config.set` rebuilds the provider before the view
/// moves: the next prepare/dispatch reaches the peer the NEW pin names, and a
/// set that refuses one row in the other direction installs without it and
/// reports the cause instead of refusing the edit.
#[test]
fn a_provider_relevant_config_set_moves_the_next_dispatch_to_the_new_peer()
-> Result<(), Box<dyn std::error::Error>> {
    let first = LocalPeer::start("first pin answered");
    let second = LocalPeer::start("second pin answered");
    let root = tempfile::TempDir::with_prefix("rivect-activation-crossing-")?;
    std::fs::write(
        root.path().join("config.toml"),
        two_peer_config(&first.endpoint, &second.endpoint),
    )?;

    let mut runtime = open_runtime(root.path())?;
    let mut ledger = support::CountingLedger::new();

    // The pinned row serves, and the peer that observed it is the first one.
    let config = runtime.config_for_broker();
    let before = runtime.broker.prepare(
        "main",
        &config,
        "/world/activation",
        "goal: before the edit",
    )?;
    assert_eq!(
        runtime
            .broker
            .dispatch(&mut ledger, "/world/activation", &before)?
            .text,
        "first pin answered"
    );
    assert_eq!(first.requests().len(), 1);
    assert!(second.requests().is_empty());

    // The refusal direction: a region on the local row makes the factory
    // refuse that row, so the served set installs without it and its cause
    // rides the result — the other row's adapter still serves.
    let refused = config_command(
        &mut runtime,
        "connections.vllm.region",
        json!("eu-west-1"),
        "config.set",
    );
    assert!(
        refused.get("error").is_none(),
        "the refused row does not fail the edit: {refused}"
    );
    assert!(
        refused["result"]["diagnostics"]
            .as_array()
            .is_some_and(|lines| lines.iter().any(|line| {
                line.as_str()
                    .is_some_and(|line| line.contains(REFUSED_ROW_MARKER))
            })),
        "the refused row's cause rides the result: {refused}"
    );
    assert_eq!(
        runtime.config_for_broker().connections["vllm"]
            .region
            .as_deref(),
        Some("eu-west-1"),
        "the landed edit moved the served config"
    );
    let still = runtime.broker.prepare(
        "main",
        &runtime.config_for_broker(),
        "/world/activation",
        "goal: after the refusal",
    )?;
    match runtime
        .broker
        .dispatch(&mut ledger, "/world/activation", &still)
    {
        Err(ModelError::Provider(ProviderError::DialectUnserved { connection, .. })) => {
            assert_eq!(connection, "vllm");
        }
        other => panic!("expected the refused row's typed denial, got {other:?}"),
    }
    assert_eq!(first.requests().len(), 1, "the refused row did not send");
    assert!(second.requests().is_empty());

    // The crossing: the default model moves to the second connection, and the
    // next admitted dispatch reaches that peer — observed on the wire.
    let crossed = config_command(
        &mut runtime,
        "models.defaults.model",
        json!({ "mode": "fixed", "connection": "llama.cpp", "model_id": MODEL }),
        "config.set",
    );
    assert!(
        crossed.get("error").is_none(),
        "the accepted edit answers success: {crossed}"
    );
    assert_eq!(
        runtime.config_for_broker().connections["vllm"].endpoint,
        first.endpoint
    );
    let after = runtime.broker.prepare(
        "main",
        &runtime.config_for_broker(),
        "/world/activation",
        "goal: after the crossing",
    )?;
    assert_eq!(
        runtime
            .broker
            .dispatch(&mut ledger, "/world/activation", &after)?
            .text,
        "second pin answered"
    );
    assert_eq!(
        second.requests().len(),
        1,
        "the rebuilt provider reached the new peer"
    );
    assert_eq!(first.requests().len(), 1, "the old peer saw nothing new");
    assert_eq!((ledger.begun, ledger.finished), (2, 2));
    Ok(())
}

/// A successful edit that moves the pinned connection's own entry is served
/// by the provider rebuilt from the landed document. The adapter built before
/// the edit names the profile-bearing row, so only the rebuilt set serves the
/// new entry — dropping `Broker::set_provider` (or installing `None`) leaves
/// the dispatch denied with the peer never reached.
#[test]
fn a_successful_entry_edit_is_served_only_by_the_rebuilt_provider()
-> Result<(), Box<dyn std::error::Error>> {
    let peer = LocalPeer::start("rebuilt provider answered");
    let root = tempfile::TempDir::with_prefix("rivect-activation-rebuild-")?;
    let config_path = root.path().join("config.toml");
    std::fs::write(&config_path, profiled_connection_config(&peer.endpoint))?;
    let mut runtime = open_runtime(root.path())?;

    // The edit moves an entry the opening build read: endpoint and dialect
    // stay identical, and the profile member leaves the row.
    let edited = config_command(
        &mut runtime,
        "connections.vllm.profile",
        json!(null),
        "config.unset",
    );
    assert!(
        edited.get("error").is_none(),
        "the entry edit is served: {edited}"
    );
    assert!(
        !std::fs::read_to_string(&config_path)?.contains("profile = \"pinned\""),
        "the accepted edit is the one on disk"
    );
    assert_eq!(
        edited["result"]["diagnostics"],
        json!([]),
        "the rebuilt row installs with nothing refused: {edited}"
    );
    assert_eq!(
        runtime.config_for_broker().connections["vllm"].profile,
        None,
        "the landed entry is the served one"
    );

    // Only a rebuilt adapter answers for the new entry.
    let mut ledger = support::CountingLedger::new();
    let config = runtime.config_for_broker();
    let after = runtime.broker.prepare(
        "main",
        &config,
        "/world/activation",
        "goal: after the entry edit",
    )?;
    assert_eq!(
        runtime
            .broker
            .dispatch(&mut ledger, "/world/activation", &after)?
            .text,
        "rebuilt provider answered"
    );
    assert_eq!(
        peer.requests().len(),
        1,
        "the rebuilt adapter is the one the dispatch crossed"
    );
    assert_eq!((ledger.begun, ledger.finished), (1, 1));
    Ok(())
}

/// A whole-build refusal from the factory refuses the edit before the managed
/// write: the document on disk is byte-identical, the previous pair keeps
/// serving, and the same factory's refusal still fails a reload closed.
#[test]
fn a_whole_build_refusal_refuses_the_edit_without_touching_the_file()
-> Result<(), Box<dyn std::error::Error>> {
    let peer = LocalPeer::start("previous pair answered");
    let root = tempfile::TempDir::with_prefix("rivect-activation-whole-build-")?;
    let config_path = root.path().join("config.toml");
    let document = config_for(&peer.endpoint, None);
    std::fs::write(&config_path, &document)?;

    let mut runtime = Runtime::open_configured(root.path(), |config, store| {
        if let Some(region) = config
            .connections
            .get("vllm")
            .and_then(|entry| entry.region.clone())
        {
            return Err(ProviderError::RegionMismatch {
                connection: "vllm".to_string(),
                region,
            });
        }
        rivect::providers::configured_provider(config, store)
    })?;

    let mut ledger = support::CountingLedger::new();
    let config = runtime.config_for_broker();
    let served = runtime.broker.prepare(
        "main",
        &config,
        "/world/activation",
        "goal: before the whole-build refusal",
    )?;
    assert_eq!(
        runtime
            .broker
            .dispatch(&mut ledger, "/world/activation", &served)?
            .text,
        "previous pair answered"
    );

    let refused = config_command(
        &mut runtime,
        "connections.vllm.region",
        json!("eu-west-1"),
        "config.set",
    );
    let error = refused
        .get("error")
        .unwrap_or_else(|| panic!("the whole-build refusal answers an error: {refused}"));
    assert_eq!(error["data"]["code"], json!("invalid_input"), "{error}");
    assert!(
        error["data"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("region eu-west-1")),
        "the factory's typed cause reaches the caller: {error}"
    );
    assert_eq!(
        std::fs::read(&config_path)?,
        document.as_bytes(),
        "a refused build never touches the document"
    );
    assert_eq!(
        runtime.config_for_broker().connections["vllm"].region,
        None,
        "the served config stayed the previous snapshot"
    );

    // The previous pair still serves after the refused command.
    let config = runtime.config_for_broker();
    let still = runtime.broker.prepare(
        "main",
        &config,
        "/world/activation",
        "goal: after the whole-build refusal",
    )?;
    assert_eq!(
        runtime
            .broker
            .dispatch(&mut ledger, "/world/activation", &still)?
            .text,
        "previous pair answered"
    );

    // The same factory's whole-build refusal fails a reload closed.
    std::fs::write(&config_path, config_for(&peer.endpoint, Some("eu-west-1")))?;
    let reload = runtime
        .reload_config()
        .expect_err("the whole-build refusal fails the reload closed");
    match &reload {
        OwnerError::Config { source, .. } => {
            assert_eq!(source.stage, Stage::Provider, "the class is the document's");
            assert!(
                matches!(
                    &source.issue,
                    ConfigIssue::ProviderBuild(error)
                        if matches!(
                            error.as_ref(),
                            ProviderError::RegionMismatch { connection, region }
                                if connection == "vllm" && region == "eu-west-1"
                        )
                ),
                "the typed factory cause stays the issue's source: {source}"
            );
        }
        other => panic!("expected the provider build refusal, got {other:?}"),
    }
    assert_eq!(
        runtime.config_for_broker().connections["vllm"].region,
        None,
        "the failed reload kept the previous config"
    );
    let config = runtime.config_for_broker();
    let after = runtime.broker.prepare(
        "main",
        &config,
        "/world/activation",
        "goal: after the refused reload",
    )?;
    assert_eq!(
        runtime
            .broker
            .dispatch(&mut ledger, "/world/activation", &after)?
            .text,
        "previous pair answered"
    );
    assert_eq!((ledger.begun, ledger.finished), (3, 3));
    assert_eq!(
        peer.requests().len(),
        3,
        "the previous pair served each time"
    );
    Ok(())
}

/// A refused row does not block later edits: an unrelated edit installs the
/// set without it and reports the cause, the servable row keeps serving, and
/// unsetting the offending key installs the row again.
#[test]
fn a_refused_row_does_not_block_later_edits_and_reinstalls_when_fixed()
-> Result<(), Box<dyn std::error::Error>> {
    let peer = LocalPeer::start("servable row answered");
    let root = tempfile::TempDir::with_prefix("rivect-activation-refused-edit-")?;
    let config_path = root.path().join("config.toml");
    std::fs::write(
        &config_path,
        format!(
            "config_version = 1\n\
             [connections.vllm]\nkind = \"local\"\nendpoint = \"{0}\"\nregion = \"eu-west-1\"\n\
             [connections.\"llama.cpp\"]\nkind = \"local\"\nendpoint = \"{0}\"\n\
             [models.defaults]\n\
             model = {{ mode = \"fixed\", connection = \"llama.cpp\", model_id = \"{MODEL}\" }}\n\
             effort = {{ mode = \"auto\" }}\n\
             fallback = {{ mode = \"off\" }}\n",
            peer.endpoint
        ),
    )?;
    let mut runtime = open_runtime(root.path())?;
    assert!(
        runtime
            .boot_diagnostics
            .iter()
            .any(|line| line.contains(REFUSED_ROW_MARKER)),
        "the open reports the refused row: {:?}",
        runtime.boot_diagnostics
    );

    // An unrelated edit is served: the set installs without the refused row
    // and the cause rides the result and the diagnostics.
    let edited = config_command(&mut runtime, "workflow.enabled", json!(false), "config.set");
    assert!(
        edited.get("error").is_none(),
        "an unrelated edit is served: {edited}"
    );
    let diagnostics = edited["result"]["diagnostics"]
        .as_array()
        .expect("the result carries the refused rows");
    assert!(
        diagnostics.iter().any(|line| {
            line.as_str()
                .is_some_and(|line| line.contains(REFUSED_ROW_MARKER))
        }),
        "the refused row's cause rides the result: {edited}"
    );
    assert!(
        runtime
            .boot_diagnostics
            .iter()
            .filter(|line| line.contains(REFUSED_ROW_MARKER))
            .count()
            >= 2,
        "the same cause joins the diagnostics: {:?}",
        runtime.boot_diagnostics
    );
    assert!(
        std::fs::read_to_string(&config_path)?.contains("enabled = false"),
        "the served edit is the one on disk"
    );

    // The servable row still serves; the refused row denies typed.
    let mut ledger = support::CountingLedger::new();
    let config = runtime.config_for_broker();
    let servable = runtime.broker.prepare(
        "main",
        &config,
        "/world/activation",
        "goal: servable row after the edit",
    )?;
    assert_eq!(
        runtime
            .broker
            .dispatch(&mut ledger, "/world/activation", &servable)?
            .text,
        "servable row answered"
    );
    let mut pinned = config.clone();
    if let Some(defaults) = pinned.models.defaults.as_mut() {
        defaults.model = rivect::config::ModelAssign::Fixed(rivect::config::FixedModel {
            connection: "vllm".to_string(),
            model_id: MODEL.to_string(),
        });
    }
    let refused = runtime.broker.prepare(
        "main",
        &pinned,
        "/world/activation",
        "goal: refused row after the edit",
    )?;
    match runtime
        .broker
        .dispatch(&mut ledger, "/world/activation", &refused)
    {
        Err(ModelError::Provider(ProviderError::DialectUnserved { connection, .. })) => {
            assert_eq!(connection, "vllm");
        }
        other => panic!("expected the refused row's typed denial, got {other:?}"),
    }
    assert_eq!((ledger.begun, ledger.finished), (1, 1));
    assert_eq!(peer.requests().len(), 1, "the refused row never sent");

    // Unsetting the offending key rebuilds the set with the row installed.
    let fixed = config_command(
        &mut runtime,
        "connections.vllm.region",
        json!(null),
        "config.unset",
    );
    assert!(fixed.get("error").is_none(), "the unset is served: {fixed}");
    assert_eq!(
        fixed["result"]["diagnostics"],
        json!([]),
        "nothing is left refused: {fixed}"
    );
    assert!(
        !std::fs::read_to_string(&config_path)?.contains("region = \"eu-west-1\""),
        "the unset removed the row's region on disk"
    );
    let config = runtime.config_for_broker();
    let mut reinstalled = config.clone();
    if let Some(defaults) = reinstalled.models.defaults.as_mut() {
        defaults.model = rivect::config::ModelAssign::Fixed(rivect::config::FixedModel {
            connection: "vllm".to_string(),
            model_id: MODEL.to_string(),
        });
    }
    let served = runtime.broker.prepare(
        "main",
        &reinstalled,
        "/world/activation",
        "goal: reinstalled row",
    )?;
    assert_eq!(
        runtime
            .broker
            .dispatch(&mut ledger, "/world/activation", &served)?
            .text,
        "servable row answered"
    );
    assert_eq!(
        peer.requests().len(),
        2,
        "the reinstalled row crossed the wire"
    );
    assert_eq!((ledger.begun, ledger.finished), (2, 2));
    Ok(())
}

/// `decisions.control` rides the same tolerant rebuild: a mode edit on a
/// runtime holding a refused row is served, the cause rides the recorded
/// result (and its replay), and the mode moves.
#[test]
fn a_decisions_control_edit_is_served_while_one_row_is_refused()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::TempDir::with_prefix("rivect-activation-decisions-")?;
    std::fs::write(
        root.path().join("config.toml"),
        format!(
            "config_version = 1\n\
             [connections.vllm]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:11434/v1\"\nregion = \"eu-west-1\"\n\
             [connections.\"llama.cpp\"]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:11434/v1\"\n\
             [models.defaults]\n\
             model = {{ mode = \"fixed\", connection = \"llama.cpp\", model_id = \"{MODEL}\" }}\n\
             effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
             fallback = {{ mode = \"off\" }}\n"
        ),
    )?;
    let mut runtime = open_runtime(root.path())?;
    let digest = runtime.effective().sources_digest.clone();
    let request = json!({
        "jsonrpc": "2.0", "id": 7, "method": "command.execute",
        "params": { "schema_version": 1, "session_id": "activation-session",
                    "command": { "kind": "decisions.control" }, "op": "auto",
                    "command_id": "activation-decisions", "expected_source_digest": digest }
    });
    let first: serde_json::Value =
        serde_json::from_str(&rivect::commands::dispatch_runtime_request(
            &mut runtime,
            rivect::commands::Ingress::TrustedHuman,
            "activation-connection",
            &request.to_string(),
        ))
        .expect("the answer is one frame");
    assert!(
        first.get("error").is_none(),
        "the mode edit is served while one row is refused: {first}"
    );
    assert_eq!(first["result"]["result"]["key"], "decisions.mode");
    assert!(
        first["result"]["result"]["diagnostics"]
            .as_array()
            .is_some_and(|lines| lines.iter().any(|line| {
                line.as_str()
                    .is_some_and(|line| line.contains(REFUSED_ROW_MARKER))
            })),
        "the refused row's cause rides the recorded result: {first}"
    );
    assert_eq!(
        runtime.effective().decisions_mode(),
        rivect::config::DecisionMode::Auto,
        "the landed mode is the served one"
    );

    // The receipt replays the recorded result verbatim, diagnostics included.
    let replay: serde_json::Value =
        serde_json::from_str(&rivect::commands::dispatch_runtime_request(
            &mut runtime,
            rivect::commands::Ingress::TrustedHuman,
            "activation-connection",
            &request.to_string(),
        ))
        .expect("the replay is one frame");
    assert_eq!(replay["result"], first["result"]);
    Ok(())
}

/// A document that refuses two rows reports both and serves the third; an
/// edit that fixes one installs that row while the other stays refused and
/// reported.
#[test]
fn a_document_refusing_two_rows_reports_both_and_serves_the_rest()
-> Result<(), Box<dyn std::error::Error>> {
    let peer = LocalPeer::start("the third row answered");
    let root = tempfile::TempDir::with_prefix("rivect-activation-two-refused-")?;
    std::fs::write(
        root.path().join("config.toml"),
        format!(
            "config_version = 1\n\
             [connections.vllm]\nkind = \"local\"\nendpoint = \"{0}\"\nregion = \"eu-west-1\"\n\
             [connections.\"llama.cpp\"]\nkind = \"local\"\nendpoint = \"{0}\"\nregion = \"us-east-1\"\n\
             [connections.\"lm-studio\"]\nkind = \"local\"\nendpoint = \"{0}\"\n\
             [models.defaults]\n\
             model = {{ mode = \"fixed\", connection = \"lm-studio\", model_id = \"{MODEL}\" }}\n\
             effort = {{ mode = \"auto\" }}\n\
             fallback = {{ mode = \"off\" }}\n",
            peer.endpoint
        ),
    )?;
    let mut runtime = open_runtime(root.path())?;
    for connection in ["vllm", "llama.cpp"] {
        let marker = format!("provider build: connection {connection} was not installed");
        assert!(
            runtime
                .boot_diagnostics
                .iter()
                .any(|line| line.contains(&marker)),
            "the open reports the refused {connection}: {:?}",
            runtime.boot_diagnostics
        );
    }

    // The third row serves.
    let mut ledger = support::CountingLedger::new();
    let config = runtime.config_for_broker();
    let served = runtime
        .broker
        .prepare("main", &config, "/world/activation", "goal: third row")?;
    assert_eq!(
        runtime
            .broker
            .dispatch(&mut ledger, "/world/activation", &served)?
            .text,
        "the third row answered"
    );

    // Fixing one row installs it; the other is still refused and reported.
    let fixed = config_command(
        &mut runtime,
        "connections.vllm.region",
        json!(null),
        "config.unset",
    );
    assert!(fixed.get("error").is_none(), "the unset is served: {fixed}");
    let diagnostics = fixed["result"]["diagnostics"]
        .as_array()
        .expect("the result carries the refused rows");
    assert!(
        diagnostics.iter().any(|line| {
            line.as_str()
                .is_some_and(|line| line.contains("connection llama.cpp was not installed"))
        }),
        "the unfixed row is still reported: {fixed}"
    );
    assert!(
        !diagnostics.iter().any(|line| {
            line.as_str()
                .is_some_and(|line| line.contains("connection vllm was not installed"))
        }),
        "the fixed row is no longer refused: {fixed}"
    );
    let landed = std::fs::read_to_string(root.path().join("config.toml"))?;
    assert!(
        !landed.contains("region = \"eu-west-1\""),
        "the fixed row's region left the document: {landed}"
    );
    assert!(
        landed.contains("region = \"us-east-1\""),
        "the unfixed row's region is still on disk: {landed}"
    );

    let config = runtime.config_for_broker();
    let mut pinned = config.clone();
    if let Some(defaults) = pinned.models.defaults.as_mut() {
        defaults.model = rivect::config::ModelAssign::Fixed(rivect::config::FixedModel {
            connection: "vllm".to_string(),
            model_id: MODEL.to_string(),
        });
    }
    let vllm =
        runtime
            .broker
            .prepare("main", &pinned, "/world/activation", "goal: the fixed row")?;
    assert_eq!(
        runtime
            .broker
            .dispatch(&mut ledger, "/world/activation", &vllm)?
            .text,
        "the third row answered"
    );
    assert_eq!(peer.requests().len(), 2);
    Ok(())
}

/// The crash window after the managed write: the receipt's failure keeps the
/// landed document served by the set built for it — on the fresh publication
/// and on the pending replay — so the next dispatch reaches the NEW peer while
/// the row waits, and the lifted jam heals the row without moving the pin.
#[test]
fn a_failed_receipt_installs_the_landed_set_and_the_replay_heals_it()
-> Result<(), Box<dyn std::error::Error>> {
    let first = LocalPeer::start("first pin answered");
    let second = LocalPeer::start("second pin answered");
    let root = tempfile::TempDir::with_prefix("rivect-activation-receipt-gap-")?;
    let config_path = root.path().join("config.toml");
    std::fs::write(
        &config_path,
        two_peer_config(&first.endpoint, &second.endpoint),
    )?;
    let mut runtime = open_runtime(root.path())?;
    let mut ledger = support::CountingLedger::new();
    let config = runtime.config_for_broker();
    let before = runtime.broker.prepare(
        "main",
        &config,
        "/world/activation",
        "goal: before the receipt gap",
    )?;
    assert_eq!(
        runtime
            .broker
            .dispatch(&mut ledger, "/world/activation", &before)?
            .text,
        "first pin answered"
    );

    // The managed write lands, then the journal receipt fails: an UPDATE
    // trigger jams exactly the receipt transition, never the staging read.
    let db = root.path().join("runtime").join("rivect.db");
    jam_publication_receipt(root.path())?;
    let pin = json!({ "mode": "fixed", "connection": "llama.cpp", "model_id": MODEL });
    let landed = config_command(
        &mut runtime,
        "models.defaults.model",
        pin.clone(),
        "config.set",
    );
    assert_eq!(
        landed["error"]["data"]["code"],
        json!("storage_unavailable"),
        "the lost receipt reports the store failure: {landed}"
    );
    let bytes = std::fs::read_to_string(&config_path)?;
    assert!(
        bytes.contains("connection = \"llama.cpp\""),
        "the managed write landed the bytes: {bytes}"
    );
    assert_eq!(
        pending_publications(&mut runtime),
        1,
        "the landed row waits for its receipt"
    );

    // The set built for the landed document serves it: the next dispatch
    // reaches the peer the new pin names, not the old provider's.
    let config = runtime.config_for_broker();
    let moved = runtime.broker.prepare(
        "main",
        &config,
        "/world/activation",
        "goal: landed pin after the receipt gap",
    )?;
    assert_eq!(
        runtime
            .broker
            .dispatch(&mut ledger, "/world/activation", &moved)?
            .text,
        "second pin answered"
    );
    assert_eq!(second.requests().len(), 1);

    // The retry lands on the pending row: the receipt still fails, the bytes
    // stay served, and no second journal row appears.
    let pending = config_command(
        &mut runtime,
        "models.defaults.model",
        pin.clone(),
        "config.set",
    );
    assert_eq!(
        pending["error"]["data"]["code"],
        json!("storage_unavailable"),
        "the pending replay keeps the typed receipt failure: {pending}"
    );
    assert_eq!(
        pending_publications(&mut runtime),
        1,
        "the replay takes the pending row instead of journaling a second"
    );
    let config = runtime.config_for_broker();
    let still = runtime.broker.prepare(
        "main",
        &config,
        "/world/activation",
        "goal: pending pin after the receipt gap",
    )?;
    assert_eq!(
        runtime
            .broker
            .dispatch(&mut ledger, "/world/activation", &still)?
            .text,
        "second pin answered"
    );
    assert_eq!(second.requests().len(), 2);

    // The lifted jam heals the row; the served pin stays put.
    {
        let conn = rusqlite::Connection::open(&db)?;
        conn.execute_batch("DROP TRIGGER jam_publication_receipt")?;
    }
    let healed = config_command(&mut runtime, "models.defaults.model", pin, "config.set");
    assert!(
        healed.get("error").is_none(),
        "the fresh-digest retry receipts the landed edit: {healed}"
    );
    assert_eq!(
        pending_publications(&mut runtime),
        0,
        "the healed row is receipted"
    );
    let config = runtime.config_for_broker();
    let after = runtime
        .broker
        .prepare("main", &config, "/world/activation", "goal: healed pin")?;
    assert_eq!(
        runtime
            .broker
            .dispatch(&mut ledger, "/world/activation", &after)?
            .text,
        "second pin answered"
    );
    assert_eq!(second.requests().len(), 3);
    assert_eq!((ledger.begun, ledger.finished), (4, 4));
    Ok(())
}

/// The pending-row count of this runtime's publication journal.
fn pending_publications(runtime: &mut Runtime) -> usize {
    runtime
        .store_writer()
        .store()
        .pending_publications()
        .expect("pending intents")
        .len()
}

/// Jams exactly the publication receipt transition: the managed write lands,
/// then the receipt UPDATE aborts and the row stays pending.
fn jam_publication_receipt(root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let conn = rusqlite::Connection::open(root.join("runtime").join("rivect.db"))?;
    conn.execute_batch(
        "CREATE TRIGGER jam_publication_receipt BEFORE UPDATE ON config_publications
         BEGIN SELECT RAISE(ABORT, 'publication receipt jammed'); END",
    )?;
    Ok(())
}

/// The receipt-failure tail installs the set the landed edit built. The edit
/// moves `vllm`'s frozen entry (and has the build refuse that row), so the
/// pre-edit admission must deny `ConnectionChanged` with no reservation and no
/// wire traffic at either peer, while a fresh prepare reaches the set's
/// servable row. The refused row's cause rides the command's own error on the
/// fresh publication and on the pending replay, so a client that never reads
/// the boot diagnostics still learns it.
#[test]
fn a_failed_receipt_after_an_entry_moving_edit_denies_the_pre_edit_manifest()
-> Result<(), Box<dyn std::error::Error>> {
    let first = LocalPeer::start("first pin answered");
    let second = LocalPeer::start("second pin answered");
    let root = tempfile::TempDir::with_prefix("rivect-activation-receipt-entry-")?;
    let config_path = root.path().join("config.toml");
    std::fs::write(
        &config_path,
        entry_moving_config(&first.endpoint, &second.endpoint),
    )?;
    let mut runtime = open_runtime(root.path())?;

    let config = runtime.config_for_broker();
    let before = runtime.broker.prepare(
        "main",
        &config,
        "/world/activation",
        "goal: before the entry-moving receipt gap",
    )?;
    assert_eq!(
        config.connections["vllm"].region, None,
        "the pre-edit row states no region"
    );

    jam_publication_receipt(root.path())?;
    let landed = config_command(
        &mut runtime,
        "connections.vllm.region",
        json!("eu-west-1"),
        "config.set",
    );
    assert_eq!(
        landed["error"]["data"]["code"],
        json!("storage_unavailable"),
        "the lost receipt reports the store failure: {landed}"
    );
    assert_eq!(
        pending_publications(&mut runtime),
        1,
        "the landed row waits for its receipt"
    );

    // The pre-edit admission names its frozen entry; the landed set serves the
    // moved one, so the dispatch denies before any reservation or send.
    let mut ledger = support::CountingLedger::new();
    match runtime
        .broker
        .dispatch(&mut ledger, "/world/activation", &before)
    {
        Err(ModelError::ConnectionChanged {
            attempt_id,
            connection,
        }) => {
            assert_eq!(attempt_id, before.attempt_id);
            assert_eq!(connection, "vllm");
        }
        other => panic!("expected ConnectionChanged, got {other:?}"),
    }
    assert_eq!((ledger.begun, ledger.finished), (0, 0));
    assert!(
        first.requests().is_empty() && second.requests().is_empty(),
        "the denied dispatch reaches no peer: first={:?} second={:?}",
        first.requests(),
        second.requests()
    );

    // The same answer names the refused row the landed set left out.
    let message = landed["error"]["data"]["message"]
        .as_str()
        .expect("the landed error names its cause");
    assert!(
        message.contains(REFUSED_ROW_MARKER)
            && message.contains("outside the dialect's endpoint contract"),
        "the refused row rides the command's own error: {message}"
    );

    // The pending replay keeps the typed failure and repeats the cause.
    let pending = config_command(
        &mut runtime,
        "connections.vllm.region",
        json!("eu-west-1"),
        "config.set",
    );
    assert_eq!(
        pending["error"]["data"]["code"],
        json!("storage_unavailable"),
        "the pending replay keeps the typed receipt failure: {pending}"
    );
    assert!(
        pending["error"]["data"]["message"]
            .as_str()
            .is_some_and(|message| message.contains(REFUSED_ROW_MARKER)),
        "the replay's error carries the refused row too: {pending}"
    );
    assert_eq!(
        pending_publications(&mut runtime),
        1,
        "the replay takes the pending row instead of journaling a second"
    );

    // A NEW prepare reaches the landed set's servable row: the peer the
    // second purpose names answers, and the pre-edit pin's peer stays silent.
    let config = runtime.config_for_broker();
    let fresh = runtime.broker.prepare(
        "spare",
        &config,
        "/world/activation",
        "goal: landed row after the receipt gap",
    )?;
    assert_eq!(
        runtime
            .broker
            .dispatch(&mut ledger, "/world/activation", &fresh)?
            .text,
        "second pin answered"
    );
    assert_eq!((ledger.begun, ledger.finished), (1, 1));
    assert_eq!(second.requests().len(), 1);
    assert!(
        first.requests().is_empty(),
        "the pre-edit peer never served"
    );
    Ok(())
}

/// The receipt-failure tail installs a rotated profile credential: the
/// connection row is byte-identical, so only the frozen credential comparison
/// denies the pre-edit admission — before any reservation or wire traffic.
#[test]
fn a_failed_receipt_after_a_credential_rotation_denies_the_pre_edit_manifest()
-> Result<(), Box<dyn std::error::Error>> {
    let peer = LocalPeer::start("must never answer");
    let root = tempfile::TempDir::with_prefix("rivect-activation-receipt-credential-")?;
    let config_path = root.path().join("config.toml");
    std::fs::write(&config_path, credential_bound_config(&peer.endpoint))?;
    let mut runtime = open_runtime(root.path())?;

    let config = runtime.config_for_broker();
    let before = runtime.broker.prepare(
        "main",
        &config,
        "/world/activation",
        "goal: before the credential rotation",
    )?;
    let admission = runtime
        .broker
        .admission(&before.attempt_id)
        .expect("the prepare admitted the request");
    assert_eq!(
        admission.credential.as_deref(),
        Some("keyring:rivect-test/p1"),
        "the ranking froze the profile's scoped credential"
    );

    jam_publication_receipt(root.path())?;
    let landed = config_command(
        &mut runtime,
        "profiles.p1.credential_ref",
        json!("keyring:rivect-rotated/p1"),
        "config.set",
    );
    assert_eq!(
        landed["error"]["data"]["code"],
        json!("storage_unavailable"),
        "the lost receipt reports the store failure: {landed}"
    );
    assert_eq!(
        runtime.config_for_broker().connections["vllm"],
        config.connections["vllm"],
        "the connection row is byte-identical, so only the credential moved"
    );

    let mut ledger = support::CountingLedger::new();
    match runtime
        .broker
        .dispatch(&mut ledger, "/world/activation", &before)
    {
        Err(ModelError::ConnectionChanged {
            attempt_id,
            connection,
        }) => {
            assert_eq!(attempt_id, before.attempt_id);
            assert_eq!(connection, "vllm");
        }
        other => panic!("expected ConnectionChanged, got {other:?}"),
    }
    assert_eq!((ledger.begun, ledger.finished), (0, 0));
    assert!(
        peer.requests().is_empty(),
        "the rotated credential reaches no wire: {:?}",
        peer.requests()
    );
    Ok(())
}

/// A refusal whose cause interpolates a config string crosses the diagnostic
/// boundary escaped as one line: the region's control byte reaches no surface
/// as one, and the whole line — not only the connection name — is escaped.
#[test]
fn a_refused_row_diagnostic_escapes_the_config_shaped_cause()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::TempDir::with_prefix("rivect-activation-escape-")?;
    std::fs::write(
        root.path().join("config.toml"),
        config_for("http://127.0.0.1:11434/v1", Some("eu\\u0007west")),
    )?;
    let runtime = open_runtime(root.path())?;
    let line = runtime
        .boot_diagnostics
        .iter()
        .find(|line| line.contains(REFUSED_ROW_MARKER))
        .unwrap_or_else(|| {
            panic!(
                "the refused row is diagnosed: {:?}",
                runtime.boot_diagnostics
            )
        });
    assert!(
        line.contains("region eu\\u0007west"),
        "the config-shaped cause is escaped in place: {line:?}"
    );
    assert!(
        !line.chars().any(char::is_control),
        "no control byte survives the render boundary: {line:?}"
    );
    Ok(())
}

/// One table line's cells, without the empty cells the leading and trailing
/// pipes produce. A non-table line answers no cells.
fn table_cells(line: &str) -> Vec<&str> {
    line.trim()
        .strip_prefix('|')
        .and_then(|rest| rest.strip_suffix('|'))
        .map(|rest| rest.split('|').map(str::trim).collect())
        .unwrap_or_default()
}

/// Whether one cell states a version: a dotted numeric token, with or without
/// the `v` prefix the Go/TypeScript releases use. A spec suffix (`+spec-…`) is
/// part of the version, so only the dotted numeric head is checked.
fn states_version(cell: &str) -> bool {
    cell.split(|character: char| {
        character.is_whitespace() || matches!(character, ';' | ',' | '/' | '(' | ')' | '*')
    })
    .any(|token| {
        let token = token.trim_start_matches('v');
        token.split_once('.').is_some_and(|(major, rest)| {
            !major.is_empty()
                && major.chars().all(|character| character.is_ascii_digit())
                && rest.starts_with(|character: char| character.is_ascii_digit())
        })
    })
}

/// The per-language comparison the research must carry: one row per concern
/// with a non-empty cell for Rust, Go and TypeScript, and versions in every
/// language's column — an absent column or a versionless set is not a
/// comparison of the full packages.
fn comparison_shape(research: &str) -> Result<(), String> {
    let mut lines = research.lines();
    let header = lines
        .find(|line| {
            line.trim_start().starts_with('|')
                && line.contains("Rust")
                && line.contains("Go")
                && line.contains("TypeScript")
        })
        .ok_or("the research carries no Rust/Go/TypeScript comparison table")?;
    let columns = table_cells(header);
    let column = |name: &str| {
        columns
            .iter()
            .position(|cell| cell.contains(name))
            .ok_or_else(|| format!("the comparison table has no {name} column"))
    };
    let (rust, go, typescript) = (column("Rust")?, column("Go")?, column("TypeScript")?);

    let mut rows = 0;
    let mut versions = [0_usize; 3];
    for line in lines {
        if !line.trim_start().starts_with('|') {
            break;
        }
        let cells = table_cells(line);
        if cells.iter().all(|cell| {
            cell.chars()
                .all(|character| character == '-' || character == ':')
        }) {
            continue;
        }
        rows += 1;
        for (slot, language) in [rust, go, typescript].into_iter().enumerate() {
            let cell = cells
                .get(language)
                .ok_or("a comparison row states no cell for a language")?;
            if cell.is_empty() {
                return Err("a comparison row states no language set".to_string());
            }
            if states_version(cell) {
                versions[slot] += 1;
            }
        }
    }
    if rows < 8 {
        return Err(format!("the comparison table carries only {rows} rows"));
    }
    for (slot, name) in ["Rust", "Go", "TypeScript"].into_iter().enumerate() {
        if versions[slot] < 6 {
            return Err(format!("the {name} column states too few versions"));
        }
    }
    Ok(())
}

/// The licence registry the research must carry: one row per selected
/// component pairing its id with a version and, for all but the single
/// versioned toolchain row, a licence, and naming both the primary source the
/// row was checked against and the constraint it leaves — a set without
/// sources or constraints is not addressable research.
fn licence_registry(research: &str) -> Result<(), String> {
    let mut lines = research.lines();
    let header = lines
        .find(|line| line.trim_start().starts_with('|') && line.contains("Версия / лицензия"))
        .ok_or("the research carries no version/licence registry")?;
    if !header.contains("MIT") && !header.contains("лицензия") {
        return Err("the registry states no licence column".to_string());
    }
    let columns = table_cells(header);
    let column = |needle: &str| {
        columns
            .iter()
            .position(|cell| cell.contains(needle))
            .ok_or_else(|| format!("the registry carries no {needle} column"))
    };
    let source = column("Первичный источник")?;
    let constraint = column("Применение")?;
    let mut rows = 0;
    let mut licenced = 0;
    for line in lines {
        let trimmed = line.trim_start();
        if !trimmed.starts_with("| SRC-") {
            if rows > 0 {
                break;
            }
            continue;
        }
        let cells = table_cells(line);
        let stated = cells
            .get(1)
            .ok_or("a registry row states no version/licence cell")?;
        if stated.is_empty() || !states_version(stated) {
            return Err("a registry row states no version".to_string());
        }
        let sourced = cells
            .get(source)
            .ok_or("a registry row states no primary-source cell")?;
        if sourced.is_empty() {
            return Err("a registry row states no primary source".to_string());
        }
        let bounded = cells
            .get(constraint)
            .ok_or("a registry row states no constraint cell")?;
        if bounded.is_empty() {
            return Err("a registry row states no constraint".to_string());
        }
        rows += 1;
        if [
            "MIT",
            "Apache",
            "BSD",
            "public domain",
            "Unlicense",
            "CC0",
            "ISC",
        ]
        .iter()
        .any(|licence| stated.contains(licence))
        {
            licenced += 1;
        }
    }
    if rows < 14 {
        return Err(format!("the registry carries only {rows} selected rows"));
    }
    if licenced < 12 {
        return Err(format!("only {licenced} registry rows state a licence"));
    }
    if !research.contains("MIT") || !research.contains("Apache") {
        return Err("the research states no licences".to_string());
    }
    Ok(())
}

/// The index of the registry column whose header carries `needle`.
fn registry_column(research: &str, needle: &str) -> usize {
    research
        .lines()
        .find(|line| line.trim_start().starts_with('|') && line.contains("Версия / лицензия"))
        .map(table_cells)
        .and_then(|cells| cells.iter().position(|cell| cell.contains(needle)))
        .expect("the registry names the column")
}

/// One registry row with the named cell blanked: a negative fixture proves the
/// cell is load-bearing rather than decorative.
fn blank_registry_cell(research: &str, id: &str, column: usize) -> String {
    let mut out = String::with_capacity(research.len());
    for line in research.lines() {
        if line.trim_start().starts_with(&format!("| {id} |")) {
            let mut cells = table_cells(line);
            if let Some(cell) = cells.get_mut(column) {
                *cell = "";
            }
            out.push('|');
            for cell in cells {
                out.push(' ');
                out.push_str(cell);
                out.push_str(" |");
            }
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    out
}

/// Whether the research presents a measurement it did not take or a
/// comparative prototype: the criterion forbids both outright, so their
/// presence is a refusal, not a footnote. An external measurement the
/// document names as external and disclaims is not a claim of its own.
fn forbidden_evidence_claim(research: &str) -> Option<String> {
    for line in research.lines() {
        let lower = line.to_lowercase();
        if lower.contains("прототип") || lower.contains("prototype") {
            return Some("the research describes a comparative prototype".to_string());
        }
        let measurement =
            lower.contains("benchmark") || lower.contains("замер") || lower.contains("измер");
        let borrowed =
            lower.contains("взят") || lower.contains("заимств") || lower.contains("borrowed");
        if measurement && borrowed {
            return Some("the research presents a borrowed measurement".to_string());
        }
    }
    None
}

/// The stack admission's three inputs, one check: the accepted ADR, the
/// research that compares the full Rust/Go/TypeScript sets with versions and
/// licences, and the ban list that keeps the forbidden crates out. Written as
/// a function over its inputs so the case below can prove it refuses a
/// missing, structurally incomplete or forbidden-claim input instead of
/// passing on whatever the repository happens to hold.
fn stack_admission(
    adr: Option<&str>,
    research: Option<&str>,
    deny: Option<&str>,
) -> Result<(), String> {
    let adr = adr.ok_or("docs/adr/0001-*.md is missing")?;
    let accepted = adr.lines().any(|line| {
        let line = line.trim().to_ascii_lowercase();
        line.starts_with("status:") && line.contains("accepted")
    });
    if !accepted {
        return Err("the ADR carries no accepted status".to_string());
    }
    let research = research.ok_or("research/stack-selection.md is missing")?;
    comparison_shape(research)?;
    licence_registry(research)?;
    if let Some(claim) = forbidden_evidence_claim(research) {
        return Err(claim);
    }
    let deny = deny.ok_or("deny.toml is missing")?;
    for banned in ["anyhow", "eyre", "diesel", "sqlx", "sea-orm"] {
        if !deny.contains(banned) {
            return Err(format!("deny.toml does not ban {banned}"));
        }
    }
    if !deny.contains("wildcards = \"deny\"") {
        return Err("deny.toml admits wildcard versions".to_string());
    }
    Ok(())
}

/// AC-002: the first product candidate is admitted only with addressable
/// stack research and an accepted ADR — all three inputs present and truthful
/// in this repository, the research's structure asserted (a full three-language
/// comparison and a version/licence registry), and the check itself refusing a
/// missing input, a dropped language set, a borrowed measurement and a
/// comparative prototype.
#[test]
fn the_stack_admission_inputs_are_present_and_accepted() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let adr = std::fs::read_dir(root.join("docs/adr"))
        .expect("the ADR directory is readable")
        .filter_map(Result::ok)
        .find(|entry| entry.file_name().to_string_lossy().starts_with("0001-"))
        .map(|entry| entry.path())
        .and_then(|path| std::fs::read_to_string(path).ok());
    let research = std::fs::read_to_string(root.join("research/stack-selection.md")).ok();
    let deny = std::fs::read_to_string(root.join("deny.toml")).ok();

    stack_admission(adr.as_deref(), research.as_deref(), deny.as_deref())
        .expect("the repository's stack admission inputs are complete");

    // The negative fixtures: each absent, structurally incomplete or
    // forbidden input is refused.
    assert!(
        stack_admission(None, research.as_deref(), deny.as_deref())
            .expect_err("a missing ADR is refused")
            .contains("0001-"),
    );
    assert!(
        stack_admission(
            Some("Status: superseded"),
            research.as_deref(),
            deny.as_deref()
        )
        .expect_err("an unaccepted ADR is refused")
        .contains("accepted"),
    );
    assert!(
        stack_admission(adr.as_deref(), None, deny.as_deref())
            .expect_err("missing research is refused")
            .contains("research"),
    );
    assert!(
        stack_admission(Some("Status: accepted"), None, deny.as_deref())
            .expect_err("a missing comparison is refused")
            .contains("research"),
    );
    assert!(
        stack_admission(adr.as_deref(), Some("Rust only"), deny.as_deref())
            .expect_err("a one-language comparison is refused")
            .contains("comparison"),
    );
    assert!(
        stack_admission(adr.as_deref(), research.as_deref(), Some("[bans]"))
            .expect_err("a ban list without the forbidden crates is refused")
            .contains("anyhow"),
    );

    // The structure is asserted, not the token presence: a research text that
    // also states a borrowed measurement or a comparative prototype — or that
    // dropped a language set — is refused.
    let research = research.as_deref().expect("the research text");
    let borrowed =
        format!("{research}\n## Замеры\nЗамер latency взят из чужого benchmark: 3x быстрее.\n");
    assert!(
        stack_admission(adr.as_deref(), Some(&borrowed), deny.as_deref())
            .expect_err("a borrowed measurement is refused")
            .contains("borrowed"),
    );
    let prototype = format!("{research}\n## Сравнительный прототип\nПрототип собран и измерен.\n");
    assert!(
        stack_admission(adr.as_deref(), Some(&prototype), deny.as_deref())
            .expect_err("a comparative prototype is refused")
            .contains("prototype"),
    );
    let no_go = research.replace("Go, viable alternative", "other alternatives");
    assert!(
        stack_admission(adr.as_deref(), Some(&no_go), deny.as_deref())
            .expect_err("a dropped language set is refused")
            .contains("Go"),
    );

    // AC-002 requires addressable research with stated constraints: a row
    // that lost its primary source, or one that lost its stated constraint,
    // is refused even though the table's overall shape still holds.
    let source = registry_column(research, "Первичный источник");
    let unsourced = blank_registry_cell(research, "SRC-001", source);
    assert!(
        stack_admission(adr.as_deref(), Some(&unsourced), deny.as_deref())
            .expect_err("a registry row without a primary source is refused")
            .contains("primary source"),
    );
    let constraint = registry_column(research, "Применение");
    let unbounded = blank_registry_cell(research, "SRC-001", constraint);
    assert!(
        stack_admission(adr.as_deref(), Some(&unbounded), deny.as_deref())
            .expect_err("a registry row without a stated constraint is refused")
            .contains("constraint"),
    );
}

/// The loopback fixture peer for one configured local endpoint: it records
/// every request it receives and answers one completed chat-completions
/// stream, so a dispatch is observed as real wire traffic and a denial as
/// no traffic at all.
struct LocalPeer {
    endpoint: String,
    requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl LocalPeer {
    fn start(reply: &str) -> Self {
        let listener =
            TcpListener::bind("127.0.0.1:0").expect("the fixture peer binds a loopback port");
        listener
            .set_nonblocking(true)
            .expect("the fixture listener polls");
        let endpoint = format!(
            "http://{}/v1",
            listener.local_addr().expect("the fixture has an address")
        );
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let body = stream_body(reply);
        let recorded = Arc::clone(&requests);
        let running = Arc::clone(&stop);
        let handle = std::thread::spawn(move || {
            while !running.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_secs(5)))
                            .expect("a request read is bounded");
                        let request = read_request(&mut stream);
                        recorded.lock().expect("request log lock").push(request);
                        let response = format!(
                            "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        if stream.write_all(response.as_bytes()).is_err()
                            || stream.shutdown(Shutdown::Both).is_err()
                        {
                            break;
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            endpoint,
            requests,
            stop,
            handle: Some(handle),
        }
    }

    fn requests(&self) -> Vec<String> {
        self.requests.lock().expect("request log lock").clone()
    }
}

impl Drop for LocalPeer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// One completed stream on the recorded chat-completions contract: the
/// content delta, the `stop` finish, then the `[DONE]` sentinel.
fn stream_body(reply: &str) -> String {
    let delta = json!({
        "id": "c1",
        "object": "chat.completion.chunk",
        "choices": [{"index": 0, "delta": {"role": "assistant", "content": reply}, "finish_reason": null}],
    });
    let finish = json!({
        "id": "c1",
        "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
    });
    format!("data: {delta}\n\ndata: {finish}\n\ndata: [DONE]\n\n")
}

fn read_request(stream: &mut std::net::TcpStream) -> String {
    let mut raw = Vec::new();
    let mut chunk = [0_u8; 4096];
    while !request_complete(&raw) {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => raw.extend_from_slice(&chunk[..read]),
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&raw).into_owned()
}

/// Whether the headers and the declared body have both arrived: the peer
/// answers only after the request it records is whole.
fn request_complete(raw: &[u8]) -> bool {
    let Some(header_end) = raw.windows(4).position(|window| window == b"\r\n\r\n") else {
        return false;
    };
    let headers = String::from_utf8_lossy(&raw[..header_end]);
    let length = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case("content-length") {
                value.trim().parse::<usize>().ok()
            } else {
                None
            }
        })
        .unwrap_or(0);
    raw.len() >= header_end + 4 + length
}
