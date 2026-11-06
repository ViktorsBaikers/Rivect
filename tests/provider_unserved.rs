//! The registered-but-unserved wire classes (AC-004/DEC-007): the
//! literal `cursor` and `devin` ids record their dialect so a control
//! request denies typed through the Broker's send gate — naming the
//! recorded class and the absent adapter — with zero requests and no
//! accounting. `gitlab-duo-agent` is served by its DWS adapter, so its
//! recorded wire is asserted in `provider_gitlab` instead.

#![allow(
    clippy::expect_used,
    clippy::panic,
    reason = "test code keeps expect/panic conveniences; src/ stays strict (standards §14)"
)]

use rivect::config::Config;
use rivect::model::{Broker, ModelError, NullLedger};
use rivect::providers::{Dialect, ProviderError, dialect_for};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

mod support;

use support::CountingProvider;

/// The scoped reference the fixture `cursor` connection binds: the
/// offline gate resolves the reference shape, never a store lookup.
const CREDENTIAL_REF: &str = "keyring:rivect-test/cursor";
const WORLD: &str = "/world/cursor";
const MODEL: &str = "cursor-agent-model";

/// The fixture `devin` connection's own scoped material, world and pin.
const DEVIN_CREDENTIAL_REF: &str = "keyring:rivect-test/devin";
const DEVIN_WORLD: &str = "/world/devin";
const DEVIN_MODEL: &str = "devin-agent-model";

/// One configured `connection`: `api_key` with scoped material
/// (DEC-011), so the fixed pin is offline-eligible and reaches the send
/// gate these tests prove.
fn unserved_config(connection: &str, credential_ref: &str, model: &str) -> Config {
    Config::parse_validated(&format!(
        "config_version = 1\n\
         [connections.{connection}]\nkind = \"api_key\"\nendpoint = \"\"\ncredential_ref = \"{credential_ref}\"\n\
         [models.defaults]\nmodel = {{ mode = \"auto\" }}\neffort = {{ mode = \"auto\" }}\nfallback = {{ mode = \"off\" }}\n\
         [models.purposes.main]\n\
         model = {{ mode = \"fixed\", connection = \"{connection}\", model_id = \"{model}\" }}\n\
         fallback = {{ mode = \"off\" }}\n"
    ))
    .expect("the scoped declaration validates")
}

/// Dispatches one prepared pin through the Broker and returns the
/// denial with the caller-held send counter and the Broker itself.
fn unserved_denial(
    connection: &str,
    credential_ref: &str,
    world: &str,
    model: &str,
) -> (ModelError, Arc<AtomicU64>, Broker) {
    let config = unserved_config(connection, credential_ref, model);
    let (provider, requests, _last_manifest) = CountingProvider::new();
    let mut broker = Broker::new(Box::new(provider));
    let manifest = broker
        .prepare("main", &config, world, &format!("goal: {connection} send"))
        .expect("the scoped material makes the pin offline-eligible");
    let error = broker
        .dispatch(&mut NullLedger, world, &manifest)
        .expect_err("the unserved dialect denies before any adapter leg");
    (error, requests, broker)
}

#[test]
fn cursor_send_denies_unserved_with_zero_requests() {
    let (error, requests, broker) = unserved_denial("cursor", CREDENTIAL_REF, WORLD, MODEL);
    assert!(
        matches!(
            &error,
            ModelError::Provider(ProviderError::DialectUnserved { connection, dialect })
                if connection == "cursor" && *dialect == Dialect::CursorAgent
        ),
        "the send gate names the recorded class: {error}"
    );
    assert_eq!(
        requests.load(Ordering::SeqCst),
        0,
        "no adapter leg ran: a silent peer or base is never contacted"
    );
    assert_eq!(
        broker.accounted_requests(),
        0,
        "a denied send is never accounted"
    );
}

#[test]
fn devin_send_denies_unserved_with_zero_requests() {
    let (error, requests, broker) =
        unserved_denial("devin", DEVIN_CREDENTIAL_REF, DEVIN_WORLD, DEVIN_MODEL);
    let ModelError::Provider(source) = &error else {
        panic!("expected ModelError::Provider: {error}");
    };
    assert!(
        matches!(
            source,
            ProviderError::DialectUnserved { connection, dialect }
                if connection == "devin" && *dialect == Dialect::DevinAgent
        ),
        "the send gate names the recorded class: {source}"
    );
    assert_eq!(
        source.to_string(),
        "connection devin is reserved for dialect devin-agent; no installed adapter serves it in this build",
        "the display names the recorded dialect and the absent adapter"
    );
    assert_eq!(dialect_for("devin"), Some(Dialect::DevinAgent));
    assert_eq!(Dialect::DevinAgent.to_string(), "devin-agent");
    assert_eq!(
        requests.load(Ordering::SeqCst),
        0,
        "no adapter leg ran: a silent peer or base is never contacted"
    );
    assert_eq!(
        broker.accounted_requests(),
        0,
        "a denied send is never accounted"
    );
}

#[test]
fn unserved_denial_names_the_recorded_transport() {
    assert_eq!(dialect_for("cursor"), Some(Dialect::CursorAgent));
    assert_eq!(Dialect::CursorAgent.to_string(), "cursor-agent");
    let error = unserved_denial("cursor", CREDENTIAL_REF, WORLD, MODEL).0;
    let ModelError::Provider(source) = &error else {
        panic!("expected ModelError::Provider: {error}");
    };
    assert_eq!(
        source.to_string(),
        "connection cursor is reserved for dialect cursor-agent; no installed adapter serves it in this build",
        "the display names the recorded dialect and the absent adapter"
    );
}
