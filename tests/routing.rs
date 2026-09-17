//! Routing proof surface: broker-boundary discriminators. SLICE-011
//! legs — unsupported effort surfaces as a typed rejection on both
//! config carriers, never silently dropped, and the transmitted effort
//! is never called confirmed without provider data (EDGE-006, AC-043).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::let_underscore_must_use,
    let_underscore_drop,
    clippy::redundant_clone,
    reason = "test code keeps unwrap/expect/panic/discard conveniences; src/ stays strict (standards §14)"
)]

use rivect::config::{Config, ConfigIssue, EffortAssign, EffortLevel, Stage};
use rivect::model::Broker;
use rivect::providers::LoopbackProvider;

fn local_fixed_config(effort_toml: &str) -> String {
    format!(
        "config_version = 1\n\
         [connections.local]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:11434\"\n\
         [models.defaults]\n\
         model = {{ mode = \"fixed\", connection = \"local\", model_id = \"fixture-model\" }}\n\
         effort = {effort_toml}\n\
         fallback = {{ mode = \"auto\" }}\n"
    )
}

#[test]
fn unsupported_effort_surfaces_on_both_carriers_never_drops() {
    // file carrier: the unsupported value is a typed schema rejection,
    // never a coercion or a silent drop
    let file_error = Config::parse_validated(&local_fixed_config(
        "{ mode = \"fixed\", value = \"ultra\" }",
    ))
    .expect_err("the file surface must reject the unsupported effort value");
    assert_eq!(file_error.stage, Stage::Schema);
    assert!(
        matches!(
            &file_error.issue,
            ConfigIssue::UnsupportedEffortValue { value } if value == "ultra"
        ),
        "wrong rejection issue: {file_error}"
    );

    // config.set carrier: the same rejection vocabulary
    let mut config =
        Config::parse_validated(&local_fixed_config("{ mode = \"auto\" }")).expect("valid");
    let wire_error = config
        .set_wire(
            "models.defaults.effort",
            &serde_json::json!({ "mode": "fixed", "value": "ultra" }),
        )
        .expect_err("the config.set surface must surface the unsupported value");
    assert!(
        matches!(
            &wire_error.issue,
            ConfigIssue::UnsupportedEffortValue { value } if value == "ultra"
        ),
        "wrong rejection issue: {wire_error}"
    );
    // the rejection coerces nothing: the retained assignment stays auto
    assert_eq!(
        config.resolve_purpose("main").expect("resolve").effort,
        EffortAssign::Auto
    );
}

#[test]
fn transmitted_effort_is_never_confirmed_without_provider_data() {
    // Each leg runs the full owner-brokered path: prepare freezes the
    // manifest, dispatch round-trips a real ProviderReply through the
    // offline loopback, and only after that reply does effort_explain
    // speak. The loopback carries no applied-effort data, so a
    // transmitted assignment must never surface as confirmed.

    // fixed leg: the resolved level rides the wire request verbatim
    let config = Config::parse_validated(&local_fixed_config(
        "{ mode = \"fixed\", value = \"high\" }",
    ))
    .expect("valid");
    let mut broker = Broker::new(Box::new(LoopbackProvider::new()));
    let manifest = broker
        .prepare("main", &config, "goal: fixture")
        .expect("manifest");
    assert_eq!(
        manifest.effort,
        EffortAssign::Fixed {
            value: EffortLevel::High
        },
        "the transmitted level rides the wire request verbatim"
    );
    let frozen = manifest.clone();
    let reply = broker.dispatch(&manifest).expect("offline dispatch");
    // the loopback really answered: fixture text, no tool calls
    assert!(!reply.text.is_empty(), "dispatch must return a real reply");
    assert!(reply.tool_calls.is_empty());
    assert_eq!(
        manifest, frozen,
        "dispatch never rewrites the frozen manifest"
    );
    let explain = broker.effort_explain(&manifest);
    assert_eq!(explain.transmitted, manifest.effort);
    assert!(
        explain.confirmed.is_none(),
        "a transmitted fixed level must not be called confirmed without provider data"
    );

    // auto leg: same round-trip discipline for the unresolved level
    let auto = Config::parse_validated(&local_fixed_config("{ mode = \"auto\" }")).expect("valid");
    let manifest = broker
        .prepare("main", &auto, "goal: fixture")
        .expect("manifest");
    let reply = broker.dispatch(&manifest).expect("offline dispatch");
    assert!(!reply.text.is_empty(), "dispatch must return a real reply");
    assert!(reply.tool_calls.is_empty());
    let explain = broker.effort_explain(&manifest);
    assert_eq!(explain.transmitted, manifest.effort);
    assert_eq!(explain.transmitted, EffortAssign::Auto);
    assert!(
        explain.confirmed.is_none(),
        "an auto assignment stays unconfirmed without provider data"
    );
}
