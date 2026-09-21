//! SLICE-001 configuration proof (TP-ADMISSION-PACKET 5a): 8 named
//! positives, 6 stage-correct negatives, 6 group controls through the
//! production `src/config.rs` schema and resolver.

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

use rivect::config::{
    Config, ConfigEdit, ConfigError, ConfigIssue, ConfigValue, ConnKind, EffortAssign,
    FallbackAssign, FixedModel, ModelAssign, Stage,
};

fn resolve_or_panic(config: &Config, purpose: &str) -> rivect::config::ResolvedPurpose {
    config
        .resolve_purpose(purpose)
        .unwrap_or_else(|err| panic!("{purpose}: {err}"))
}

fn expect_stage(err: &ConfigError, stage: Stage) {
    assert_eq!(err.stage, stage, "wrong rejection stage: {err}");
}

fn auto_no_pool() -> ModelAssign {
    ModelAssign::Auto { pool: None }
}

fn pool(names: &[&str]) -> ModelAssign {
    ModelAssign::Auto {
        pool: Some(names.iter().map(|s| s.to_string()).collect()),
    }
}

#[test]
fn all_roles_auto() {
    let config = Config::parse_validated(&support::config_all_roles_auto()).expect("valid");
    assert_eq!(config.version, 1);
    let primary = config.connections.get("primary").expect("primary");
    assert_eq!(primary.kind, ConnKind::ApiKey);
    assert_eq!(primary.credential_ref.as_deref(), Some("keyring:primary"));
    let resolved = resolve_or_panic(&config, "worker");
    assert_eq!(resolved.model, auto_no_pool());
    assert_eq!(resolved.effort, EffortAssign::Auto);
    assert_eq!(resolved.model_source, "models.defaults");
    assert_eq!(resolved.effort_source, "models.defaults");
}

#[test]
fn pinned_planner() {
    let config = Config::parse_validated(&support::config_pinned_planner()).expect("valid");
    let resolved = resolve_or_panic(&config, "planner");
    match &resolved.model {
        ModelAssign::Fixed(fixed) => {
            assert_eq!(fixed.connection, "primary");
            assert_eq!(fixed.model_id, "fixture-model");
        }
        other => panic!("expected fixed model, got {other:?}"),
    }
    assert_eq!(
        resolved.effort,
        EffortAssign::Fixed {
            value: rivect::config::EffortLevel::High
        }
    );
    assert_eq!(resolved.model_source, "models.purposes.planner");
    // defaults stay auto for purposes without an explicit pin
    let other = resolve_or_panic(&config, "worker");
    assert_eq!(other.model, auto_no_pool());
    assert_eq!(other.model_source, "models.defaults");
}

#[test]
fn distinct_pools() {
    let config = Config::parse_validated(&support::config_distinct_pools()).expect("valid");
    let backend = resolve_or_panic(&config, "backend_task");
    assert_eq!(backend.model, pool(&["local"]));
    assert_eq!(backend.model_source, "models.groups.backend");
    let frontend = resolve_or_panic(&config, "frontend_task");
    assert_eq!(frontend.model, pool(&["primary"]));
    assert_eq!(frontend.model_source, "models.groups.frontend");
    let vision = resolve_or_panic(&config, "vision");
    assert_eq!(vision.model, pool(&["primary"]));
    assert_eq!(vision.model_source, "models.purposes.vision");
}

#[test]
fn fixed_model_auto_effort() {
    let config =
        Config::parse_validated(&support::config_fixed_model_auto_effort()).expect("valid");
    let resolved = resolve_or_panic(&config, "main");
    assert!(
        matches!(&resolved.model, ModelAssign::Fixed(fixed) if fixed.model_id == "fixture-model")
    );
    assert_eq!(resolved.effort, EffortAssign::Auto);
    assert_eq!(resolved.model_source, "models.purposes.main");
    assert_eq!(resolved.effort_source, "models.purposes.main");
}

fn fixed(connection: &str, model_id: &str) -> ModelAssign {
    ModelAssign::Fixed(FixedModel {
        connection: connection.to_string(),
        model_id: model_id.to_string(),
    })
}

fn four_combination_config() -> String {
    "config_version = 1\n\
     [connections.primary]\nkind = \"api_key\"\nendpoint = \"https://api.openai.com/v1\"\ncredential_ref = \"keyring:primary\"\n\
     [connections.local]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:11434\"\n\
     [models.defaults]\n\
     model = { mode = \"fixed\", connection = \"local\", model_id = \"defaults-pin\" }\n\
     effort = { mode = \"fixed\", value = \"medium\" }\n\
     fallback = { mode = \"auto\" }\n\
     [models.purposes.fixed_fixed]\n\
     model = { mode = \"fixed\", connection = \"local\", model_id = \"ff-model\" }\n\
     effort = { mode = \"fixed\", value = \"high\" }\n\
     [models.purposes.fixed_auto]\n\
     model = { mode = \"fixed\", connection = \"local\", model_id = \"fa-model\" }\n\
     effort = { mode = \"auto\" }\n\
     [models.purposes.auto_fixed]\n\
     model = { mode = \"auto\", pool = [\"local\"] }\n\
     effort = { mode = \"fixed\", value = \"low\" }\n\
     [models.purposes.auto_auto]\n\
     model = { mode = \"auto\" }\n\
     effort = { mode = \"auto\" }\n"
        .to_string()
}

/// AC-043: the four fixed/auto combinations resolve independently — a
/// model pin never drags effort and vice versa — and the wire request
/// the broker freezes carries exactly the explained assignment.
#[test]
fn four_fixed_auto_combinations_match_on_wire_request_and_explain() {
    let config = Config::parse_validated(&four_combination_config()).expect("valid");
    let mut broker =
        rivect::model::Broker::new(Box::new(rivect::providers::LoopbackProvider::new()));
    let cases = [
        (
            "fixed_fixed",
            fixed("local", "ff-model"),
            EffortAssign::Fixed {
                value: rivect::config::EffortLevel::High,
            },
        ),
        ("fixed_auto", fixed("local", "fa-model"), EffortAssign::Auto),
        (
            "auto_fixed",
            pool(&["local"]),
            EffortAssign::Fixed {
                value: rivect::config::EffortLevel::Low,
            },
        ),
        ("auto_auto", auto_no_pool(), EffortAssign::Auto),
    ];
    for (purpose, model, effort) in cases {
        let resolved = resolve_or_panic(&config, purpose);
        assert_eq!(resolved.model, model, "{purpose}: explained model");
        assert_eq!(resolved.effort, effort, "{purpose}: explained effort");
        assert_eq!(resolved.model_source, format!("models.purposes.{purpose}"));
        assert_eq!(resolved.effort_source, format!("models.purposes.{purpose}"));
        let manifest = broker
            .prepare(purpose, &config, "/world/precedence", "goal: fixture")
            .unwrap_or_else(|err| panic!("{purpose}: {err}"));
        assert_eq!(manifest.model, model, "{purpose}: wire model");
        assert_eq!(manifest.effort, effort, "{purpose}: wire effort");
    }
    // the defaults pin survives for a purpose without its own binding,
    // while the more specific auto/auto above overrides it — both
    // directions of the precedence hold
    let plain = resolve_or_panic(&config, "unbound");
    assert_eq!(plain.model, fixed("local", "defaults-pin"));
    assert_eq!(
        plain.effort,
        EffortAssign::Fixed {
            value: rivect::config::EffortLevel::Medium
        }
    );
    assert_eq!(plain.model_source, "models.defaults");
    assert_eq!(plain.effort_source, "models.defaults");
}

fn profile_change_config() -> String {
    "config_version = 1\n\
     [connections.local]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:11434\"\n\
     [models.defaults]\n\
     model = { mode = \"fixed\", connection = \"local\", model_id = \"profile-one\" }\n\
     effort = { mode = \"fixed\", value = \"medium\" }\n\
     fallback = { mode = \"auto\" }\n\
     [models.groups.backend]\n\
     model = { mode = \"fixed\", connection = \"local\", model_id = \"group-one\" }\n\
     [models.purposes.pinned]\n\
     group = \"backend\"\n\
     model = { mode = \"fixed\", connection = \"local\", model_id = \"pinned-model\" }\n\
     effort = { mode = \"fixed\", value = \"high\" }\n\
     [models.purposes.backend_task]\n\
     group = \"backend\"\n"
        .to_string()
}

/// AC-047 contribution: changing the profile — the defaults and group
/// assignments — preserves an explicit purpose pin for both model and
/// effort, while unpinned purposes follow the change.
#[test]
fn profile_change_preserves_pinned_model_and_effort() {
    let mut config = Config::parse_validated(&profile_change_config()).expect("valid");
    config
        .set(
            "models.defaults.model",
            ConfigValue::Model(fixed("local", "profile-two")),
        )
        .expect("defaults model edit");
    config
        .set(
            "models.defaults.effort",
            ConfigValue::Effort(EffortAssign::Fixed {
                value: rivect::config::EffortLevel::Minimal,
            }),
        )
        .expect("defaults effort edit");
    config
        .set(
            "models.groups.backend.model",
            ConfigValue::Model(fixed("local", "group-two")),
        )
        .expect("group model edit");

    let pinned = resolve_or_panic(&config, "pinned");
    assert_eq!(pinned.model, fixed("local", "pinned-model"));
    assert_eq!(
        pinned.effort,
        EffortAssign::Fixed {
            value: rivect::config::EffortLevel::High
        }
    );
    assert_eq!(pinned.model_source, "models.purposes.pinned");
    assert_eq!(pinned.effort_source, "models.purposes.pinned");

    let follower = resolve_or_panic(&config, "backend_task");
    assert_eq!(follower.model, fixed("local", "group-two"));
    assert_eq!(follower.model_source, "models.groups.backend");

    let plain = resolve_or_panic(&config, "unbound");
    assert_eq!(plain.model, fixed("local", "profile-two"));
    assert_eq!(
        plain.effort,
        EffortAssign::Fixed {
            value: rivect::config::EffortLevel::Minimal
        }
    );
    assert_eq!(plain.model_source, "models.defaults");
}

fn purpose_pool_config(pool_line: &str, eligible_line: &str) -> String {
    format!(
        "{}\n[models.purposes.vision]\n{pool_line}\n{eligible_line}\n",
        support::base_config()
    )
}

/// The new `models.purposes.*` keys parse from the file and carry on
/// `PurposeDef` (DEC-012); malformed shapes surface the same two-issue
/// vocabulary the model `pool` field already uses.
#[test]
fn purpose_pool_and_eligible_keys_parse_from_the_file() {
    let config = Config::parse_validated(&purpose_pool_config(
        "pool = [\"local\", \"primary\"]",
        "eligible = [\"primary\"]",
    ))
    .expect("valid");
    let def = config.models.purposes.get("vision").expect("vision");
    assert_eq!(
        def.pool,
        Some(vec!["local".to_string(), "primary".to_string()])
    );
    assert_eq!(def.eligible, Some(vec!["primary".to_string()]));

    let shapes = [
        (
            "pool = \"local\"",
            "eligible = [\"primary\"]",
            ConfigIssue::PoolNotArray,
        ),
        (
            "pool = [1]",
            "eligible = [\"primary\"]",
            ConfigIssue::PoolEntryNotString,
        ),
        (
            "pool = [\"local\"]",
            "eligible = \"primary\"",
            ConfigIssue::EligibleNotArray,
        ),
        (
            "pool = [\"local\"]",
            "eligible = [1]",
            ConfigIssue::EligibleEntryNotString,
        ),
    ];
    for (pool_line, eligible_line, issue) in shapes {
        let err = Config::parse_validated(&purpose_pool_config(pool_line, eligible_line))
            .expect_err("malformed shape must reject");
        expect_stage(&err, Stage::Schema);
        assert!(
            std::mem::discriminant(&err.issue) == std::mem::discriminant(&issue),
            "wrong rejection issue: {err}"
        );
    }
}

/// The editability split the schema names: `pool` is file-only — the
/// `config.set` surface answers the read-only vocabulary — while
/// `eligible` edits, round-trips through the file schema and resets.
#[test]
fn purpose_pool_is_file_only_and_eligible_is_config_set_editable() {
    let mut config = Config::parse_validated(&purpose_pool_config(
        "pool = [\"local\"]",
        "eligible = [\"primary\"]",
    ))
    .expect("valid");

    let pool_error = config
        .set_wire("models.purposes.vision.pool", &json!(["primary"]))
        .expect_err("pool is file-only");
    assert!(
        matches!(
            &pool_error.issue,
            ConfigIssue::KeyNotEditable { key } if key == "models.purposes.vision.pool"
        ),
        "wrong rejection issue: {pool_error}"
    );

    let edit = config
        .set_wire(
            "models.purposes.vision.eligible",
            &json!(["primary", "local"]),
        )
        .expect("eligible edits through the wire carrier");
    let edited = Config::parse_validated(String::from_utf8_lossy(&edit.bytes).as_ref())
        .expect("edited document must validate");
    assert_eq!(
        edited
            .models
            .purposes
            .get("vision")
            .expect("vision")
            .eligible,
        Some(vec!["primary".to_string(), "local".to_string()])
    );

    let entry_error = config
        .set_wire("models.purposes.vision.eligible", &json!([1]))
        .expect_err("non-string entries surface the typed issue");
    assert!(
        matches!(&entry_error.issue, ConfigIssue::EligibleEntryNotString),
        "wrong rejection issue: {entry_error}"
    );
    let shape_error = config
        .set_wire("models.purposes.vision.eligible", &json!("primary"))
        .expect_err("non-array values are a type mismatch");
    assert!(
        matches!(
            &shape_error.issue,
            ConfigIssue::ValueTypeMismatch { key } if key == "models.purposes.vision.eligible"
        ),
        "wrong rejection issue: {shape_error}"
    );

    // the typed carrier keeps the slot split: names never land elsewhere
    let slot_error = config
        .set(
            "models.defaults.model",
            ConfigValue::Names(vec!["primary".to_string()]),
        )
        .expect_err("names never land on a model slot");
    assert!(
        matches!(
            &slot_error.issue,
            ConfigIssue::ValueTypeMismatch { key } if key == "models.defaults.model"
        ),
        "wrong rejection issue: {slot_error}"
    );

    let reset = config
        .reset("models.purposes.vision.eligible")
        .expect("eligible is an override reset removes");
    let reset_doc =
        Config::parse_validated(String::from_utf8_lossy(&reset.bytes).as_ref()).expect("valid");
    let vision = reset_doc.models.purposes.get("vision").expect("vision");
    assert_eq!(vision.eligible, None);
    // the file-only pool survives every edit above untouched
    assert_eq!(vision.pool, Some(vec!["local".to_string()]));
}

#[test]
fn explicit_chain() {
    let config = Config::parse_validated(&support::config_explicit_chain()).expect("valid");
    let resolved = resolve_or_panic(&config, "planner");
    let FallbackAssign::Auto { chain } = &resolved.fallback else {
        panic!("expected auto fallback with chain");
    };
    assert_eq!(chain.len(), 1);
    assert_eq!(chain[0].model_id, "fixture-reserve");
    // the fallback chain never rewrites the primary model pin
    assert!(
        matches!(&resolved.model, ModelAssign::Fixed(fixed) if fixed.model_id == "fixture-model")
    );
}

#[test]
fn manual_subscription() {
    let config = Config::parse_validated(&support::config_manual_subscription()).expect("valid");
    let subscription = config
        .connections
        .get("subscription")
        .expect("subscription");
    assert_eq!(subscription.kind, ConnKind::Subscription);
    let resolved = resolve_or_panic(&config, "main");
    assert!(
        matches!(&resolved.model, ModelAssign::Fixed(fixed) if fixed.connection == "subscription")
    );
    assert_eq!(resolved.fallback, FallbackAssign::Manual);
}

#[test]
fn one_provider() {
    let config = Config::parse_validated(&support::config_one_provider()).expect("valid");
    let resolved = resolve_or_panic(&config, "reviewer");
    assert_eq!(resolved.model, auto_no_pool());
    assert_eq!(resolved.effort, EffortAssign::Auto);
    assert_eq!(resolved.model_source, "models.defaults");
    assert_eq!(resolved.effort_source, "models.defaults");
}

#[test]
fn learned_role() {
    let config = Config::parse_validated(&support::config_learned_role()).expect("valid");
    assert!(
        config.models.purposes.contains_key("personal:api-review"),
        "learned role must stay in the registry"
    );
    let resolved = resolve_or_panic(&config, "personal:api-review");
    assert_eq!(resolved.model, auto_no_pool());
    assert_eq!(resolved.model_source, "models.defaults");
}

#[test]
fn n_model_id() {
    let (name, text) = support::negative_configs().remove(0);
    assert_eq!(name, "N-model-id");
    let mut parsed = Config::parse(&text).expect("toml parse must succeed");
    let err = parsed.validate().expect_err("schema must reject");
    expect_stage(&err, Stage::Schema);
    assert!(
        matches!(err.issue, ConfigIssue::FixedModelMissingId),
        "{err}"
    );
}

#[test]
fn n_effort_value() {
    let text = support::negative_configs()
        .iter()
        .find(|(n, _)| *n == "N-effort-value")
        .unwrap()
        .1
        .clone();
    let mut parsed = Config::parse(&text).expect("toml parse must succeed");
    let err = parsed.validate().expect_err("schema must reject");
    expect_stage(&err, Stage::Schema);
    assert!(
        matches!(err.issue, ConfigIssue::FixedEffortMissingValue),
        "{err}"
    );
}

#[test]
fn n_key() {
    let text = support::negative_configs()
        .iter()
        .find(|(n, _)| *n == "N-key")
        .unwrap()
        .1
        .clone();
    let mut parsed = Config::parse(&text).expect("toml parse must succeed");
    let err = parsed.validate().expect_err("schema must reject");
    expect_stage(&err, Stage::Schema);
    assert!(matches!(err.issue, ConfigIssue::UnknownKey { .. }), "{err}");
}

#[test]
fn n_fallback() {
    let text = support::negative_configs()
        .iter()
        .find(|(n, _)| *n == "N-fallback")
        .unwrap()
        .1
        .clone();
    let mut parsed = Config::parse(&text).expect("toml parse must succeed");
    let err = parsed.validate().expect_err("schema must reject");
    expect_stage(&err, Stage::Schema);
    assert!(
        matches!(err.issue, ConfigIssue::UnsupportedFallbackMode { .. }),
        "{err}"
    );
}

#[test]
fn n_secret() {
    let text = support::negative_configs()
        .iter()
        .find(|(n, _)| *n == "N-secret")
        .unwrap()
        .1
        .clone();
    let mut parsed = Config::parse(&text).expect("toml parse must succeed");
    let err = parsed.validate().expect_err("schema must reject");
    assert!(
        !err.to_string().contains(support::SECRET_CANARY),
        "diagnostic must never echo the secret: {err}"
    );
    assert!(matches!(err.issue, ConfigIssue::InlineCredential), "{err}");
}

#[test]
fn parse_error_does_not_echo_source_text() {
    let text = format!("api_key = \"{}\" trailing", support::SECRET_CANARY);
    let err = Config::parse(&text).expect_err("malformed TOML must fail");
    assert!(matches!(err.issue, ConfigIssue::Parser { .. }), "{err}");
    assert!(
        !err.to_string().contains(support::SECRET_CANARY),
        "parse diagnostic must never echo source text: {err}"
    );
}

/// The connection endpoint is a trust boundary: `https` on any host and
/// `http` on loopback only are admitted, the empty string stays the
/// local-dialect absent-override sentinel, and schemeless, non-loopback
/// `http`, credential-carrying or host-less forms are schema refusals —
/// never deferred to a wire attempt.
#[test]
fn connection_endpoint_enforces_the_trust_boundary() {
    for (endpoint, admitted) in [
        ("https://api.openai.com/v1", true),
        ("http://127.0.0.1:11434", true),
        ("http://localhost:11434/v1", true),
        ("http://[::1]:11434", true),
        ("", true),
        // whitespace-only shares the absent-override arm under the
        // recorded endpoint rules' trim
        ("   ", true),
        ("api.openai.com/v1", false),
        ("http://api.example.com/v1", false),
        ("http://10.0.0.5/v1", false),
        // a `127.`-prefixed dns name is not a loopback address
        ("http://127.0.0.1.evil.invalid", false),
        // credentials never ride the url
        ("https://user:pw@api.openai.com/v1", false),
        ("http://user@127.0.0.1:11434", false),
        // the authority must carry a host
        ("https://", false),
        ("http://", false),
        ("ftp://api.openai.com/v1", false),
    ] {
        let text = format!(
            "config_version = 1\n\
             [connections.c]\nkind = \"api_key\"\nendpoint = \"{endpoint}\"\ncredential_ref = \"keyring:rivect-test/c\"\n\
             [models.defaults]\n\
             model = {{ mode = \"fixed\", connection = \"c\", model_id = \"m\" }}\n\
             effort = {{ mode = \"fixed\", value = \"medium\" }}\n\
             fallback = {{ mode = \"off\" }}\n"
        );
        let mut parsed = Config::parse(&text).expect("toml parse must succeed");
        match (parsed.validate(), admitted) {
            (Ok(_), true) => {}
            (Ok(_), false) => panic!("endpoint {endpoint:?} must not be admitted"),
            (Err(err), true) => panic!("endpoint {endpoint:?} must be admitted: {err}"),
            (Err(err), false) => {
                expect_stage(&err, Stage::Schema);
                assert!(
                    matches!(err.issue, ConfigIssue::EndpointNotAllowed),
                    "endpoint {endpoint:?} must fail EndpointNotAllowed: {err}"
                );
            }
        }
    }
}

#[test]
fn n_duplicate() {
    let text = support::negative_configs()
        .iter()
        .find(|(n, _)| *n == "N-duplicate")
        .unwrap()
        .1
        .clone();
    let err = Config::parse(&text).expect_err("duplicate key is a parser rejection");
    expect_stage(&err, Stage::Parse);
    assert!(matches!(err.issue, ConfigIssue::Parser { .. }), "{err}");
}

#[test]
fn g_distinct() {
    let config = Config::parse_validated(&support::config_distinct_pools()).expect("valid");
    let backend = resolve_or_panic(&config, "backend_task");
    let frontend = resolve_or_panic(&config, "frontend_task");
    assert_ne!(
        backend.model, frontend.model,
        "two purposes must reach distinct pools"
    );
    assert_eq!(backend.model_source, "models.groups.backend");
    assert_eq!(frontend.model_source, "models.groups.frontend");
}

#[test]
fn g_exact() {
    let text = support::config_distinct_pools().replace(
        "[models.purposes.backend_task]\ngroup = \"backend\"\n",
        "[models.purposes.backend_task]\ngroup = \"backend\"\nmodel = { mode = \"auto\", pool = [\"primary\"] }\n",
    );
    let config = Config::parse_validated(&text).expect("valid");
    let backend = resolve_or_panic(&config, "backend_task");
    // exact-purpose override wins over the bound group
    assert_eq!(backend.model, pool(&["primary"]));
    assert_eq!(backend.model_source, "models.purposes.backend_task");
    // effort is still independently inherited from defaults
    assert_eq!(backend.effort, EffortAssign::Auto);
    assert_eq!(backend.effort_source, "models.defaults");
}

#[test]
fn g_absent() {
    let text = support::config_distinct_pools().replace(
        "[models.purposes.backend_task]\ngroup = \"backend\"\n",
        "[models.purposes.backend_task]\n",
    );
    let config = Config::parse_validated(&text).expect("valid");
    let backend = resolve_or_panic(&config, "backend_task");
    assert_eq!(backend.model, auto_no_pool());
    assert_eq!(backend.model_source, "models.defaults");
}

#[test]
fn g_unknown() {
    let text =
        support::config_distinct_pools().replace("group = \"backend\"", "group = \"missing\"");
    let mut config = Config::parse(&text).expect("parse");
    let err = config
        .validate()
        .expect_err("unknown group reference rejected");
    expect_stage(&err, Stage::Schema);
    assert!(
        matches!(
            err.issue,
            ConfigIssue::UnknownGroupReference { ref group } if group == "missing"
        ),
        "{err}"
    );
}

#[test]
fn g_array() {
    let text = support::config_distinct_pools()
        .replace("group = \"backend\"", "group = [\"backend\", \"frontend\"]");
    let mut parsed = Config::parse(&text).expect("toml parse succeeds on the array form");
    let err = parsed
        .validate()
        .expect_err("group array is a schema-stage type rejection");
    expect_stage(&err, Stage::Schema);
    assert!(
        matches!(err.issue, ConfigIssue::GroupReferenceNotString),
        "{err}"
    );
}

#[test]
fn g_conflict() {
    let base = Config::parse_validated(&support::config_distinct_pools()).expect("valid");
    let mut merged = base.clone();
    let other_text =
        support::config_distinct_pools().replace("group = \"backend\"", "group = \"frontend\"");
    let other = Config::parse_validated(&other_text).expect("valid");
    let err = merged
        .merge_purposes(&other)
        .expect_err("conflicting definitions rejected");
    expect_stage(&err, Stage::Resolve);
    assert!(
        matches!(err.issue, ConfigIssue::ConflictingPurposeDefinitions),
        "{err}"
    );
    // identical replay merges fine and is not a conflict
    let same = Config::parse_validated(&support::config_distinct_pools()).expect("valid");
    merged
        .merge_purposes(&same)
        .expect("identical binding replays without conflict");
}

fn lossless_edit_config() -> String {
    r#"config_version = 1
[connections.primary]
kind = "api_key"
endpoint = "https://api.openai.com/v1"
credential_ref = "keyring:primary"
[models.defaults]
model = {
  mode = "auto", # keep
}
effort = { mode = "auto" }
fallback = { mode = "auto" }
[models.purposes.planner]
fallback = { mode = "auto", chain = [{ mode = "fixed", connection = "primary", model_id = "reserve", order = 1 }] }
"#
    .to_string()
}

#[test]
fn typed_set_preserves_multiline_value_suffix_comment() {
    let mut config = Config::parse_validated(&lossless_edit_config().replace(", order = 1", ""))
        .expect("valid multiline inline table");
    let edit = config
        .set(
            "models.defaults.model",
            ConfigValue::Model(ModelAssign::Fixed(FixedModel {
                connection: "primary".to_string(),
                model_id: "edited".to_string(),
            })),
        )
        .expect("typed set");
    let bytes = String::from_utf8(edit.bytes).expect("edited TOML is utf-8");
    let model_start = bytes.find("model = {").expect("model assignment");
    let model_end = bytes[model_start..]
        .find('}')
        .map(|offset| model_start + offset)
        .expect("model table terminator");
    let model = &bytes[model_start..=model_end];
    assert!(
        model.contains("# keep"),
        "value suffix comment moved outside model table: {model}"
    );
}

#[test]
fn unknown_chain_key_rejected_but_sibling_set_keeps_original_entry() {
    let text = lossless_edit_config();
    let mut config = Config::parse(&text).expect("TOML parse");
    let err = config
        .validate()
        .expect_err("unknown chain key must reject");
    expect_stage(&err, Stage::Schema);
    assert_eq!(
        err.key.as_deref(),
        Some("models.purposes.planner.fallback.chain.order")
    );
    assert!(
        matches!(&err.issue, ConfigIssue::UnknownKey { key, .. } if key == "order"),
        "{err}"
    );

    let original_chain = "fallback = { mode = \"auto\", chain = [{ mode = \"fixed\", connection = \"primary\", model_id = \"reserve\", order = 1 }] }";
    let edit = config
        .set(
            "models.defaults.model",
            ConfigValue::Model(ModelAssign::Fixed(FixedModel {
                connection: "primary".to_string(),
                model_id: "edited".to_string(),
            })),
        )
        .expect("sibling set validates only its target");
    let bytes = String::from_utf8(edit.bytes).expect("edited TOML is utf-8");
    assert!(
        bytes.contains(original_chain),
        "unknown chain entry was rewritten: {bytes}"
    );
    assert!(
        bytes.contains("model_id = \"edited\""),
        "sibling assignment was not edited: {bytes}"
    );
}

#[test]
fn typed_set_ignores_unknown_key_on_unrelated_connection() {
    let text = lossless_edit_config().replace(
        "[models.defaults]",
        "[connections.sibling]\nkind = \"api_key\"\nendpoint = \"https://api.example.invalid/v1\"\ncredential_ref = \"keyring:sibling\"\nunknown = true\n\n[models.defaults]",
    );
    let mut config = Config::parse(&text).expect("TOML parse");
    let edit = config
        .set(
            "models.defaults.model",
            ConfigValue::Model(ModelAssign::Fixed(FixedModel {
                connection: "primary".to_string(),
                model_id: "edited".to_string(),
            })),
        )
        .expect("targeted set ignores invalid sibling connection");
    let bytes = String::from_utf8(edit.bytes).expect("edited TOML is utf-8");
    assert!(
        bytes.contains("unknown = true"),
        "sibling was rewritten: {bytes}"
    );
    assert!(
        bytes.contains("model_id = \"edited\""),
        "target was not edited: {bytes}"
    );
}

#[test]
fn typed_set_rewrites_targeted_unknown_chain_entry() {
    let mut config = Config::parse(&lossless_edit_config()).expect("TOML parse");
    let edit = config
        .set(
            "models.purposes.planner.fallback",
            ConfigValue::Fallback(FallbackAssign::Auto {
                chain: vec![FixedModel {
                    connection: "primary".to_string(),
                    model_id: "repaired".to_string(),
                }],
            }),
        )
        .expect("targeted set repairs unknown chain entry");
    let bytes = String::from_utf8(edit.bytes).expect("edited TOML is utf-8");
    assert!(
        bytes.contains("model_id = \"repaired\""),
        "targeted fallback was not replaced: {bytes}"
    );
    assert!(
        !bytes.contains("order = 1"),
        "targeted repair retained unknown key: {bytes}"
    );
}

#[test]
fn typed_set_preserves_surviving_non_last_value_suffix_comment() {
    let text = lossless_edit_config().replace(
        "model = {\n  mode = \"auto\", # keep\n}",
        "model = {\n  mode = \"auto\" # keep\n  , pool = [\"primary\"]\n}",
    );
    let mut config =
        Config::parse_validated(&text.replace(", order = 1", "")).expect("valid inline table");
    let edit = config
        .set(
            "models.defaults.model",
            ConfigValue::Model(ModelAssign::Auto {
                pool: Some(vec!["primary".to_string()]),
            }),
        )
        .expect("equal-valued typed set");
    let bytes = String::from_utf8(edit.bytes).expect("edited TOML is utf-8");
    let model_start = bytes.find("model = {").expect("model assignment");
    let model_end = bytes[model_start..]
        .find('}')
        .map(|offset| model_start + offset)
        .expect("model table terminator");
    let model = &bytes[model_start..=model_end];
    assert!(
        model.contains("# keep"),
        "surviving non-last suffix comment was lost: {model}"
    );
}

#[test]
fn typed_set_preserves_deleted_last_value_suffix_comment() {
    let text = lossless_edit_config().replace(
        "model = {\n  mode = \"auto\", # keep\n}",
        "model = {\n  mode = \"auto\",\n  pool = [\"primary\"] # keep\n}",
    );
    let mut config = Config::parse_validated(&text.replace(", order = 1", ""))
        .expect("valid shrinking inline table");
    let edit = config
        .set(
            "models.defaults.model",
            ConfigValue::Model(ModelAssign::Fixed(FixedModel {
                connection: "primary".to_string(),
                model_id: "edited".to_string(),
            })),
        )
        .expect("shrinking typed set");
    let bytes = String::from_utf8(edit.bytes).expect("edited TOML is utf-8");
    let model_start = bytes.find("model = {").expect("model assignment");
    let model_end = bytes[model_start..]
        .find('}')
        .map(|offset| model_start + offset)
        .expect("model table terminator");
    let model = &bytes[model_start..=model_end];
    assert!(
        model.contains("# keep"),
        "deleted last-value suffix comment was lost: {model}"
    );
}

#[test]
fn typed_set_preserves_both_suffix_comments_when_last_value_removed() {
    let text = lossless_edit_config().replace(
        "model = {\n  mode = \"auto\", # keep\n}",
        "model = {\n  mode = \"auto\" # mode keep\n  , pool = [\"primary\"] # pool keep\n}",
    );
    let mut config = Config::parse_validated(&text.replace(", order = 1", ""))
        .expect("valid shrinking inline table");
    let edit = config
        .set(
            "models.defaults.model",
            ConfigValue::Model(ModelAssign::Auto { pool: None }),
        )
        .expect("shrinking typed set");
    let bytes = String::from_utf8(edit.bytes).expect("edited TOML is utf-8");
    let model_start = bytes.find("model = {").expect("model assignment");
    let model_end = bytes[model_start..]
        .find('}')
        .map(|offset| model_start + offset)
        .expect("model table terminator");
    let model = &bytes[model_start..=model_end];
    assert!(
        model.contains("# mode keep"),
        "surviving comment was lost: {model}"
    );
    assert!(
        model.contains("# pool keep"),
        "deleted-value comment was lost: {model}"
    );
}

#[test]
fn typed_set_merges_deleted_suffix_into_existing_trailing_without_overwrite() {
    let text = r#"config_version = 1
[connections.primary]
kind = "api_key"
endpoint = "https://api.openai.com/v1"
credential_ref = "keyring:primary"
[models.defaults]
model = { mode = "auto" # mode keep
, model_id = "stale" # stale keep
, pool = ["primary"] # pool keep
}
effort = { mode = "auto" }
fallback = { mode = "auto" }
"#;
    let mut config = Config::parse_validated(text).expect("valid trailing-merge config");
    config
        .set(
            "models.defaults.model",
            ConfigValue::Model(ModelAssign::Fixed(FixedModel {
                connection: "primary".to_string(),
                model_id: "first".to_string(),
            })),
        )
        .expect("first typed set parks the pool comment in the table trailing");
    let edit = config
        .set(
            "models.defaults.model",
            ConfigValue::Model(ModelAssign::Inherit),
        )
        .expect("second typed set must merge, not overwrite, the trailing comment");
    let bytes = String::from_utf8(edit.bytes).expect("edited TOML is utf-8");
    Config::parse_validated(&bytes).expect("edited TOML stays valid");
    assert_comments_survive_once(&bytes, &["# mode keep", "# pool keep", "# stale keep"]);

    let edit = config
        .set(
            "models.defaults.model",
            ConfigValue::Model(ModelAssign::Auto {
                pool: Some(vec!["primary".to_string()]),
            }),
        )
        .expect("third typed set must keep the merged trailing intact");
    let bytes = String::from_utf8(edit.bytes).expect("edited TOML is utf-8");
    Config::parse_validated(&bytes).expect("edited TOML stays valid after third set");
    assert_comments_survive_once(&bytes, &["# mode keep", "# pool keep", "# stale keep"]);
}

fn assert_comments_survive_once(bytes: &str, comments: &[&str]) {
    let model_start = bytes.find("model = {").expect("model assignment");
    let model_end = bytes[model_start..]
        .find('}')
        .map(|offset| model_start + offset)
        .expect("model table terminator");
    let model = &bytes[model_start..=model_end];
    for comment in comments {
        assert_eq!(
            model.matches(comment).count(),
            1,
            "{comment} must survive exactly once: {model}"
        );
    }
}

#[test]
fn typed_set_preserves_no_comma_value_suffix_comment_inside_model() {
    let text = lossless_edit_config()
        .replace(", # keep", " # keep")
        .replace(", order = 1", "");
    let mut config = Config::parse_validated(&text).expect("valid no-comma inline table");
    let edit = config
        .set(
            "models.defaults.model",
            ConfigValue::Model(ModelAssign::Fixed(FixedModel {
                connection: "primary".to_string(),
                model_id: "edited".to_string(),
            })),
        )
        .expect("typed set");
    let bytes = String::from_utf8(edit.bytes).expect("edited TOML is utf-8");
    assert!(
        bytes.contains("# keep"),
        "value suffix comment was lost: {bytes}"
    );
    let model_start = bytes.find("model = {").expect("model assignment");
    let model_end = bytes[model_start..]
        .find('}')
        .map(|offset| model_start + offset)
        .expect("model table terminator");
    let model = &bytes[model_start..=model_end];
    assert!(
        model.contains("mode = \"fixed\""),
        "model was not replaced: {model}"
    );
    assert!(
        model.contains("model_id = \"edited\""),
        "model was not replaced: {model}"
    );
    assert!(
        model.contains("# keep"),
        "value suffix comment moved outside model table: {model}"
    );
}

#[test]
fn numeric_chain_mode_is_rejected() {
    let text = lossless_edit_config()
        .replace("mode = \"fixed\"", "mode = 1")
        .replace(", order = 1", "");
    let mut config = Config::parse(&text).expect("TOML parse");
    let err = config
        .validate()
        .expect_err("numeric chain mode must reject");
    expect_stage(&err, Stage::Schema);
    assert!(
        matches!(&err.issue, ConfigIssue::ExpectedString { field } if field == "mode"),
        "{err}"
    );
}

#[test]
fn table_chain_mode_is_rejected() {
    let text = lossless_edit_config()
        .replace("mode = \"fixed\"", "mode = { a = 1 }")
        .replace(", order = 1", "");
    let mut config = Config::parse(&text).expect("TOML parse");
    let err = config.validate().expect_err("table chain mode must reject");
    expect_stage(&err, Stage::Schema);
    assert!(
        matches!(&err.issue, ConfigIssue::ExpectedString { field } if field == "mode"),
        "{err}"
    );
}
#[test]
fn reset_rejects_required_key() {
    let mut config =
        Config::parse_validated(&support::config_all_roles_auto()).expect("valid config");
    let err = config
        .reset("models.defaults.model")
        .expect_err("required defaults must not be reset");

    expect_stage(&err, Stage::Schema);
    assert_eq!(err.key.as_deref(), Some("models.defaults.model"));
    assert!(
        matches!(
            &err.issue,
            ConfigIssue::RequiredNotResettable { key } if key == "models.defaults.model"
        ),
        "{err}"
    );
}

#[test]
fn reset_removes_override_preserving_sibling_comments() {
    let text = r#"config_version = 1
[connections.primary]
kind = "api_key"
endpoint = "https://api.openai.com/v1"
credential_ref = "keyring:primary"
[models.defaults]
model = { mode = "auto" }
effort = { mode = "auto" }
fallback = { mode = "auto" }
[models.purposes.planner]
model = { mode = "fixed", connection = "primary", model_id = "planner" } # remove
effort = { mode = "fixed", value = "high" } # preserve
"#;
    let mut config = Config::parse_validated(text).expect("valid override config");
    let edit = config
        .reset("models.purposes.planner.model")
        .expect("purpose override is resettable");
    let bytes = String::from_utf8(edit.bytes).expect("edited TOML is utf-8");

    assert!(
        !bytes.contains("model_id = \"planner\""),
        "override remained after reset: {bytes}"
    );
    assert!(
        bytes.contains("effort = { mode = \"fixed\", value = \"high\" } # preserve"),
        "sibling comment was lost: {bytes}"
    );
}

#[test]
fn reset_after_failed_validation_retains_document() {
    let text = lossless_edit_config();
    let mut config = Config::parse(&text).expect("TOML parse");
    let err = config
        .validate()
        .expect_err("unknown chain key must reject");
    expect_stage(&err, Stage::Schema);
    assert!(
        matches!(&err.issue, ConfigIssue::UnknownKey { key, .. } if key == "order"),
        "{err}"
    );

    let edit = config
        .reset("models.purposes.planner.fallback")
        .expect("reset must retain document after failed validation");
    let bytes = String::from_utf8(edit.bytes).expect("edited TOML is utf-8");
    assert!(
        !bytes.contains("order = 1"),
        "invalid chain entry remained after reset: {bytes}"
    );
    let planner = bytes
        .split_once("[models.purposes.planner]\n")
        .map(|(_, section)| section)
        .expect("planner section");
    assert!(
        !planner.contains("fallback ="),
        "override remained after reset: {planner}"
    );
    Config::parse_validated(&bytes).expect("reset document must validate");
}

// ----- crash-safe publication discriminator (AC-093) -----

use rivect::config::{
    PublicationError, PublicationVerdict, PublishIdentity, recover_publications, stage_publication,
};
use rivect::state::{ConflictCause, StoreError, TaskStore};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

const PUBLICATION_OWNER: &str = "file";

fn publication_root(tag: &str) -> PathBuf {
    support::temp_dir(&format!("publication-{tag}"))
}

fn staged_publication(tag: &str, old_text: &str) -> (PathBuf, TaskStore, ConfigEdit) {
    let root = publication_root(tag);
    let target = root.join("config.toml");
    std::fs::write(&target, old_text).expect("seed target bytes");
    let mut store = TaskStore::open(&root.join("state.db")).expect("open store");
    let mut config = Config::parse_validated(old_text).expect("valid config");
    let edit = config
        .set("workflow.enabled", ConfigValue::Bool(false))
        .expect("workflow edit");
    stage_publication(&mut store, PUBLICATION_OWNER, &target, &edit)
        .expect("stage publication intent");
    (target, store, edit)
}

fn foreign_toml() -> String {
    support::base_config().replace("https://api.openai.com/v1", "https://foreign.example/v1")
}

/// Atomic replace, the way a third-party editor saves: new inode at the path.
fn replace_target(target: &Path, bytes: &[u8]) {
    let swap = target.with_extension("toml.swap");
    std::fs::write(&swap, bytes).expect("write swap file");
    std::fs::rename(&swap, target).expect("atomic replace");
}

fn recovered_verdicts(store: &mut TaskStore) -> Vec<PublicationVerdict> {
    recover_publications(store)
        .expect("recover publications")
        .into_iter()
        .map(|recovery| recovery.verdict)
        .collect()
}

fn pending_intents(store: &mut TaskStore) -> usize {
    store.pending_publications().expect("pending intents").len()
}

#[test]
fn recovery_classifies_old_when_target_bytes_never_changed() {
    let (target, mut store, _edit) = staged_publication("old", &support::base_config());

    assert_eq!(
        recovered_verdicts(&mut store),
        vec![PublicationVerdict::Old]
    );
    assert_eq!(pending_intents(&mut store), 1, "old intent stays pending");
    assert_eq!(
        std::fs::read_to_string(&target).expect("target bytes"),
        support::base_config(),
        "recovery must not rewrite an unwritten target"
    );
}

#[test]
fn recovery_completes_receipt_when_bytes_match_staged_identity() {
    let (target, mut store, edit) = staged_publication("exactly-new", &support::base_config());
    // In-place write like the managed publisher: the staged inode survives.
    std::fs::write(&target, &edit.bytes).expect("crash after bytes, before receipt");

    assert_eq!(
        recovered_verdicts(&mut store),
        vec![PublicationVerdict::ExactlyNew]
    );
    assert_eq!(
        pending_intents(&mut store),
        0,
        "attributed write must receive its receipt"
    );
}

#[test]
fn recovery_keeps_byte_identical_third_unapplied() {
    let (target, mut store, edit) =
        staged_publication("byte-identical-third", &support::base_config());
    replace_target(&target, &edit.bytes);

    assert_eq!(
        recovered_verdicts(&mut store),
        vec![PublicationVerdict::ByteIdenticalThird]
    );
    assert_eq!(
        pending_intents(&mut store),
        1,
        "a third party's identical bytes must never be marked applied"
    );
}

#[test]
fn recovery_keeps_conflicting_foreign_bytes() {
    let (target, mut store, _edit) = staged_publication("conflicting", &support::base_config());
    let foreign = foreign_toml();
    replace_target(&target, foreign.as_bytes());

    assert_eq!(
        recovered_verdicts(&mut store),
        vec![PublicationVerdict::Conflicting]
    );
    assert_eq!(pending_intents(&mut store), 1, "conflict stays pending");
    assert_eq!(
        std::fs::read_to_string(&target).expect("target bytes"),
        foreign,
        "foreign bytes must be kept, never clobbered"
    );
}

#[test]
fn recovery_classifies_torn_bytes_as_unparseable() {
    let (target, mut store, edit) = staged_publication("torn", &support::base_config());
    let torn = edit.bytes[..edit.bytes.len() / 2].to_vec();
    std::fs::write(&target, torn).expect("tear the write");

    assert_eq!(
        recovered_verdicts(&mut store),
        vec![PublicationVerdict::TornOrUnparseable]
    );
    assert_eq!(pending_intents(&mut store), 1, "torn write stays pending");
}

#[test]
fn recovery_classifies_absent_target() {
    let (target, mut store, _edit) = staged_publication("absent", &support::base_config());
    std::fs::remove_file(&target).expect("remove target");

    assert_eq!(
        recovered_verdicts(&mut store),
        vec![PublicationVerdict::Absent]
    );
    assert_eq!(
        pending_intents(&mut store),
        1,
        "absent target stays pending"
    );
}

#[test]
fn recovery_leaves_identity_less_identical_bytes_unknown() {
    let root = publication_root("unknown");
    let target = root.join("config.toml");
    std::fs::write(&target, support::base_config()).expect("seed target bytes");
    let mut store = TaskStore::open(&root.join("state.db")).expect("open store");
    let mut config = Config::parse_validated(&support::base_config()).expect("valid config");
    let edit = config
        .set("workflow.enabled", ConfigValue::Bool(false))
        .expect("workflow edit");
    // Staging refuses absent targets and always records an identity, so
    // the only producer of an identity-less row is an older journal; model
    // that row directly to keep the arm covered.
    store
        .append_publication(
            PUBLICATION_OWNER,
            target.to_str().expect("utf-8 target"),
            &edit.digest,
            None,
            None,
        )
        .expect("journal an identity-less intent");
    // Identical bytes appear with no identity to attribute them to.
    std::fs::write(&target, &edit.bytes).expect("identical bytes appear");

    assert_eq!(
        recovered_verdicts(&mut store),
        vec![PublicationVerdict::Unknown]
    );
    assert_eq!(
        pending_intents(&mut store),
        1,
        "unknown must never silently map to applied"
    );
}

#[test]
fn staging_refuses_absent_target_without_journaling() {
    let root = publication_root("stage-absent");
    let target = root.join("fresh.toml");
    let mut store = TaskStore::open(&root.join("state.db")).expect("open store");
    let mut config = Config::parse_validated(&support::base_config()).expect("valid config");
    let edit = config
        .set("workflow.enabled", ConfigValue::Bool(false))
        .expect("workflow edit");

    let error = stage_publication(&mut store, PUBLICATION_OWNER, &target, &edit)
        .expect_err("staging must refuse an absent target: the managed write cannot create it");

    assert!(
        matches!(
            &error,
            PublicationError::TargetAbsent(key) if key == target.to_str().expect("utf-8 target")
        ),
        "wrong refusal error: {error}"
    );
    assert_eq!(
        pending_intents(&mut store),
        0,
        "a refused intent must not leave a journal row"
    );
}

#[test]
fn staging_refuses_fifo_target_without_hanging() -> Result<(), Box<dyn std::error::Error>> {
    let root = publication_root("stage-fifo");
    let target = root.join("pipe");
    let status = std::process::Command::new("mkfifo").arg(&target).status()?;
    assert!(status.success(), "mkfifo must create the pipe");
    let mut store = TaskStore::open(&root.join("state.db")).expect("open store");
    let mut config = Config::parse_validated(&support::base_config()).expect("valid config");
    let edit = config
        .set("workflow.enabled", ConfigValue::Bool(false))
        .expect("workflow edit");

    // No writer holds the other end: without the non-blocking open this
    // call would hang before the fd-level regular-file check rejects it.
    let error = stage_publication(&mut store, PUBLICATION_OWNER, &target, &edit)
        .expect_err("a FIFO target must be refused at staging");

    assert!(
        matches!(error, PublicationError::Target(_)),
        "wrong refusal error: {error}"
    );
    assert_eq!(
        pending_intents(&mut store),
        0,
        "no row for a non-regular target"
    );
    Ok(())
}

#[test]
fn recovery_treats_fifo_target_as_unknown_without_hanging() -> Result<(), Box<dyn std::error::Error>>
{
    let (target, mut store, _edit) = staged_publication("recover-fifo", &support::base_config());
    std::fs::remove_file(&target)?;
    let status = std::process::Command::new("mkfifo").arg(&target).status()?;
    assert!(status.success(), "mkfifo must create the pipe");

    // Recovery must classify, never block on the writerless pipe.
    assert_eq!(
        recovered_verdicts(&mut store),
        vec![PublicationVerdict::Unknown]
    );
    assert_eq!(pending_intents(&mut store), 1, "unknown stays pending");
    Ok(())
}

#[test]
fn recovery_reads_target_at_ceiling_and_rejects_one_past_it() {
    let (target, mut store, _edit) = staged_publication("ceiling", &support::base_config());
    // Exactly PUBLICATION_MAX_BYTES (1 MiB) bytes: still readable and
    // classifiable — zeros are not UTF-8, so the verdict is
    // torn/unparseable, not Unknown.
    std::fs::write(&target, vec![0u8; 1 << 20]).expect("write exactly at the ceiling");
    assert_eq!(
        recovered_verdicts(&mut store),
        vec![PublicationVerdict::TornOrUnparseable],
        "an exactly-ceiling target must still be read"
    );

    // One byte past the ceiling: the read bound must reject the target as
    // unattributable instead of pulling it into memory whole.
    std::fs::write(&target, vec![0u8; (1 << 20) + 1]).expect("write one byte past the ceiling");
    assert_eq!(
        recovered_verdicts(&mut store),
        vec![PublicationVerdict::Unknown],
        "past the ceiling the target is unattributable"
    );
}

/// Regression for the staging TOCTOU: the durable (identity, base digest)
/// pair must come from one opened handle, so it always describes a single
/// file even while another thread keeps swapping which inode the target
/// path names. A two-walk staging splices one inode onto the other file's
/// digest; that mixed pair is exactly what this asserts never lands in
/// the journal.
#[test]
fn staged_pair_stays_self_consistent_under_concurrent_path_swaps() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    let root = publication_root("swap-race");
    let target = root.join("config.toml");
    let other = root.join("other.toml");
    std::fs::write(&target, support::base_config()).expect("seed target");
    std::fs::write(&other, foreign_toml()).expect("seed other");
    let mut store = TaskStore::open(&root.join("state.db")).expect("open store");
    let mut config = Config::parse_validated(&support::base_config()).expect("valid config");
    let edit = config
        .set("workflow.enabled", ConfigValue::Bool(false))
        .expect("workflow edit");

    let stop = Arc::new(AtomicBool::new(false));
    let flipper = {
        let (target, other, stop) = (target.clone(), other.clone(), Arc::clone(&stop));
        std::thread::spawn(move || {
            let scratch = target.with_extension("toml.scratch");
            while !stop.load(Ordering::Relaxed) {
                std::fs::rename(&target, &scratch).expect("flip out");
                std::fs::rename(&other, &target).expect("flip in");
                std::fs::rename(&scratch, &other).expect("flip settle");
            }
        })
    };

    let mut staged = 0usize;
    let mut attempts = 0usize;
    while staged < 50 && attempts < 5000 {
        attempts += 1;
        // A refusal (the path is momentarily nameless mid-swap) is a skip,
        // never an inconsistent journal row.
        if stage_publication(&mut store, PUBLICATION_OWNER, &target, &edit).is_ok() {
            staged += 1;
        }
    }
    assert_eq!(
        staged, 50,
        "staging must keep landing while the path is swapped ({attempts} attempts)"
    );
    stop.store(true, Ordering::Relaxed);
    flipper.join().expect("flipper must not panic");

    // rename preserves (dev, ino) and content, so each seeded file keeps
    // the pair it was created with no matter which name it sits under now.
    let sight = |path: &Path| {
        use sha2::Digest;
        use std::os::unix::fs::MetadataExt;
        let metadata = std::fs::metadata(path).expect("sight metadata");
        let bytes = std::fs::read(path).expect("sight bytes");
        (
            PublishIdentity {
                dev: metadata.dev(),
                ino: metadata.ino(),
            },
            rivect::config::hex(&sha2::Sha256::digest(&bytes)),
        )
    };
    let pairs = [sight(&target), sight(&other)];

    for intent in store.pending_publications().expect("pending intents") {
        let identity = intent.publish_identity.expect("staged identity");
        let base = intent.base_digest.expect("staged base digest");
        let consistent = pairs.iter().any(|(sight_identity, sight_digest)| {
            *sight_identity == identity && *sight_digest == base
        });
        assert!(
            consistent,
            "journal spliced a path swap: identity {identity:?} with foreign base digest {base}"
        );
    }
}

#[test]
fn completing_an_unknown_intent_is_a_typed_conflict() {
    let root = publication_root("complete-miss");
    let mut store = TaskStore::open(&root.join("state.db")).expect("open store");

    let error = store
        .complete_publication(PUBLICATION_OWNER, "config.toml", 1)
        .expect_err("a zero-row receipt must not be a silent success");

    assert!(
        matches!(
            error,
            StoreError::Conflict(ConflictCause::PublicationNotPending { .. })
        ),
        "wrong completion error: {error}"
    );
}

#[test]
fn completing_an_already_receipted_intent_is_a_typed_conflict() {
    let (_target, mut store, _edit) = staged_publication("complete-twice", &support::base_config());
    let intent = store
        .pending_publications()
        .expect("pending intents")
        .pop()
        .expect("one staged intent");

    store
        .complete_publication(&intent.owner, &intent.target, intent.admission_seq)
        .expect("first receipt lands");

    let error = store
        .complete_publication(&intent.owner, &intent.target, intent.admission_seq)
        .expect_err("a second receipt must conflict");

    assert!(
        matches!(
            error,
            StoreError::Conflict(ConflictCause::PublicationNotPending { .. })
        ),
        "wrong completion error: {error}"
    );
}

/// EDGE-009 / AC-094: selection is admission order, never owner spelling.
/// Two intents pend on one target; the owner whose UUID sorts last is the
/// one admitted first — the journal must still list the older admission
/// first, which per-owner sequence numbers could never express.
#[test]
fn older_admission_wins_even_when_owner_uuid_order_reverses() {
    let root = publication_root("admission-order");
    let target = root.join("config.toml");
    std::fs::write(&target, support::base_config()).expect("seed target bytes");
    let mut store = TaskStore::open(&root.join("state.db")).expect("open store");
    let mut older = Config::parse_validated(&support::base_config()).expect("valid config");
    let older_edit = older
        .set("workflow.enabled", ConfigValue::Bool(false))
        .expect("older edit");
    let mut younger = Config::parse_validated(&support::base_config()).expect("valid config");
    let younger_edit = younger
        .set("workflow.enabled", ConfigValue::Bool(true))
        .expect("younger edit");
    // UUID spelling reversed from admission order: the older admission
    // carries the lexicographically last owner id.
    let older_owner = "ffffffff-ffff-4fff-8fff-ffffffffffff";
    let younger_owner = "00000000-0000-4000-8000-000000000000";
    stage_publication(&mut store, older_owner, &target, &older_edit).expect("stage older");
    stage_publication(&mut store, younger_owner, &target, &younger_edit).expect("stage younger");

    let pending = store.pending_publications().expect("pending intents");
    assert_eq!(pending.len(), 2, "both intents stay pending");
    assert_eq!(
        (pending[0].owner.as_str(), pending[0].admission_seq),
        (older_owner, 1),
        "uuid order must not decide selection: {:?}",
        pending
    );
    assert_eq!(
        (pending[1].owner.as_str(), pending[1].admission_seq),
        (younger_owner, 2),
        "the same target's counter admits the second intent after the first"
    );
}

/// AC-094's silent-recovery conjunct: a boot-time completion of the
/// ExactlyNew crash window (crash after bytes, before receipt) settles
/// entirely in the journal — a fresh `Runtime::open` receipts it before
/// any config surface serves. A zero `event_count` observes durable
/// `events` rows only: it proves no hook reached the outbox. Zero model
/// calls is a signature-level proof, not one this count can make —
/// recovery holds no provider/broker/UI handle, and `append_event` is
/// the only events writer.
#[test]
fn recovery_only_completion_emits_no_hooks() {
    let mut world = support::open_world("no-emit", Some(&support::base_config()));
    let target = world.root.join("config.toml");
    let mut file_config = Config::parse_validated(&support::base_config()).expect("valid config");
    let edit = file_config
        .set("workflow.enabled", ConfigValue::Bool(false))
        .expect("workflow edit");
    let intent = stage_publication(
        &mut world.runtime.owner.store,
        PUBLICATION_OWNER,
        &target,
        &edit,
    )
    .expect("stage publication intent");
    // Crash after the managed write, before the receipt: the staged inode
    // survives under the intended bytes.
    std::fs::write(&target, &edit.bytes).expect("crash after bytes, before receipt");

    // A fresh Runtime::open receipts the ExactlyNew crash window on boot.
    world.reopen();
    assert_eq!(
        pending_intents(&mut world.runtime.owner.store),
        0,
        "boot recovery receipts the attributed write"
    );
    assert_eq!(
        world
            .runtime
            .owner
            .store
            .applied_publications()
            .expect("applied intents"),
        vec![intent],
        "the crash-window row went terminal unchanged"
    );
    assert_eq!(
        world
            .runtime
            .owner
            .store
            .event_count()
            .expect("event count"),
        0,
        "recovery-only completion must emit no hooks"
    );
}

#[test]
fn preapproval_liveness_follows_expiry() {
    let root = publication_root("preapproval");
    let mut store = TaskStore::open(&root.join("state.db")).expect("open store");

    store
        .record_preapproval("write-config", "human", 3600)
        .expect("record live preapproval");
    store
        .record_preapproval("stale-grant", "human", -60)
        .expect("record expired preapproval");

    assert!(store.is_preapproved("write-config").expect("live lookup"));
    assert!(
        !store.is_preapproved("stale-grant").expect("expired lookup"),
        "an expired grant must not count as preapproved"
    );
    assert!(
        !store
            .is_preapproved("never-granted")
            .expect("absent lookup"),
        "an unknown scope must fail closed"
    );
}

// ----- file/CLI carrier singleflight (AC-095) -----

use serde_json::json;

fn carrier_world(tag: &str) -> (support::World, rivect::contracts::SessionId) {
    let mut world = support::open_world(tag, Some(&support::base_config()));
    let session = world.open_session(&format!("bootstrap-{tag}"));
    (world, session)
}

#[test]
fn cli_config_set_completes_a_typed_edit() {
    let (mut world, session) = carrier_world("cli-set");

    let response = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 7301, "method": "command.execute",
        "params": { "schema_version": 1, "session_id": session.0,
                    "command": { "kind": "config.set" },
                    "key": "workflow.enabled", "value": false }
    }));

    assert!(
        response["error"].is_null(),
        "config.set must answer a success response, not {response}"
    );
    // The exact edit the file surface produces for the same command.
    let mut expected = Config::parse_validated(&support::base_config()).expect("valid config");
    let expected_edit = expected
        .set("workflow.enabled", ConfigValue::Bool(false))
        .expect("typed edit");
    assert_eq!(
        response["result"]["digest"], expected_edit.digest,
        "the admitted edit must be the file surface's edit: {response}"
    );
    let parsed = world
        .runtime
        .effective
        .parsed
        .as_ref()
        .expect("retained document");
    assert_eq!(
        parsed.workflow.enabled,
        Some(false),
        "the retained view carries the accepted value"
    );

    // The command itself lands the publication: the exact file-surface
    // bytes are on disk and the journal row is receipted — no crash
    // window survives the success response.
    assert_eq!(
        std::fs::read(world.root.join("config.toml")).expect("published bytes"),
        expected_edit.bytes,
        "command.execute itself must change config.toml on disk"
    );
    assert_eq!(
        pending_intents(&mut world.runtime.owner.store),
        0,
        "the write's receipt completes the journaled intent"
    );
}

#[test]
fn cli_and_file_reject_the_same_unknown_key_with_one_known_keys_hint() {
    // File surface: `bogus` rides the trailing [models.defaults] table.
    let file_text = format!("{}bogus = 1\n", support::base_config());
    let file_error = Config::parse_validated(&file_text)
        .expect_err("the file surface must reject the unknown key");
    expect_stage(&file_error, Stage::Schema);
    assert!(
        matches!(
            &file_error.issue,
            ConfigIssue::UnknownKey { key, known }
                if key == "bogus" && *known == ["model", "effort", "fallback"]
        ),
        "wrong rejection issue: {file_error}"
    );

    let (mut world, session) = carrier_world("cli-unknown-key");
    let response = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 7302, "method": "command.execute",
        "params": { "schema_version": 1, "session_id": session.0,
                    "command": { "kind": "config.set" },
                    "key": "models.defaults.bogus", "value": 1 }
    }));

    let cli_message = response["error"]["data"]["message"]
        .as_str()
        .expect("typed ConfigIssue message");
    assert_eq!(
        response["error"]["data"]["code"], "invalid_input",
        "the rejection is a typed ConfigIssue, not a catalog stub: {response}"
    );
    assert_eq!(
        cli_message,
        "schema models.defaults.bogus: unknown key models.defaults.bogus; known keys: model, effort, fallback",
        "the CLI names the rejected key and the scope-local csv: {response}"
    );
    assert_eq!(
        file_error.to_string(),
        "schema models.defaults.bogus: unknown key bogus; known keys: model, effort, fallback",
        "the file surface answers the same level with the same csv"
    );
}

/// DEC-017 one-schema rule: a non-string chain-entry `mode` draws the
/// same typed rejection on the wire and file surfaces.
#[test]
fn cli_and_file_reject_the_same_non_string_chain_entry_mode() {
    // File surface twin: the defaults chain carries a numeric mode.
    let file_text = support::base_config().replace(
        r#"fallback = { mode = "auto" }"#,
        r#"fallback = { mode = "auto", chain = [{ mode = 5, connection = "c", model_id = "m" }] }"#,
    );
    let file_error = Config::parse_validated(&file_text)
        .expect_err("the file surface must reject the non-string chain mode");
    expect_stage(&file_error, Stage::Schema);
    assert_eq!(
        file_error.key.as_deref(),
        Some("models.defaults.fallback.chain.mode")
    );
    assert!(
        matches!(&file_error.issue, ConfigIssue::ExpectedString { field } if field == "mode"),
        "wrong rejection issue: {file_error}"
    );

    let (mut world, session) = carrier_world("cli-chain-mode-parity");
    let response = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 7380, "method": "command.execute",
        "params": { "schema_version": 1, "session_id": session.0,
                    "command": { "kind": "config.set" },
                    "key": "models.defaults.fallback",
                    "value": { "mode": "auto",
                               "chain": [{ "mode": 5, "connection": "c", "model_id": "m" }] } }
    }));

    let cli_message = response["error"]["data"]["message"]
        .as_str()
        .expect("typed ConfigIssue message");
    assert_eq!(
        cli_message, "schema models.defaults.fallback.chain.mode: mode must be a string",
        "the CLI must name the skipped mode field, not fall through to the connection reference: {response}"
    );
    assert_eq!(
        file_error.to_string(),
        "schema models.defaults.fallback.chain.mode: mode must be a string",
        "both surfaces answer the same rejection"
    );
}

#[test]
fn config_read_unknown_key_names_its_accepted_domain() {
    let (mut world, session) = carrier_world("read-domain");

    let response = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 7303, "method": "config.read",
        "params": { "schema_version": 1, "session_id": session.0, "keys": ["bogus"] }
    }));

    assert_eq!(
        response["error"]["data"]["message"],
        "unknown key bogus; known keys: workflow.enabled, connections.<id>.region, connections.<id>.profile, profiles.<name>.credential_ref"
    );
}

#[test]
fn cli_config_unset_of_required_key_is_a_typed_rejection() {
    let (mut world, session) = carrier_world("cli-unset-required");

    let response = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 7304, "method": "command.execute",
        "params": { "schema_version": 1, "session_id": session.0,
                    "command": { "kind": "config.unset" },
                    "key": "models.defaults.model" }
    }));

    assert_eq!(
        response["error"]["data"]["message"],
        "schema models.defaults.model: models.defaults.model is required, not an override; reset removes overrides only"
    );

    // Adjacent variant: a wire value that cannot inhabit the typed slot is
    // a typed rejection too, never a silent coercion.
    let mismatch = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 7305, "method": "command.execute",
        "params": { "schema_version": 1, "session_id": session.0,
                    "command": { "kind": "config.set" },
                    "key": "workflow.enabled", "value": "yes" }
    }));
    assert_eq!(
        mismatch["error"]["data"]["message"],
        "schema workflow.enabled: value type does not match workflow.enabled"
    );
}

#[test]
fn describe_lists_config_commands_available_with_write_policy() {
    let (mut world, session) = carrier_world("describe-write");

    let response = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 7306, "method": "command.describe",
        "params": { "schema_version": 1, "session_id": session.0 }
    }));

    let items = response["result"]["items"].as_array().expect("catalog");
    for kind in ["config.set", "config.unset"] {
        let row = items
            .iter()
            .find(|d| d["canonical_id"] == kind)
            .unwrap_or_else(|| panic!("{kind} needs a dedicated row"));
        assert_eq!(row["available"], json!(true), "{kind}: {row}");
        assert_eq!(row["busy_policy"], "WRITE", "{kind}: {row}");
        assert!(row["unavailability_reason"].is_null(), "{kind}: {row}");
    }
}

#[test]
fn cli_config_set_maps_object_values_through_the_typed_schema() {
    let (mut world, session) = carrier_world("cli-object");

    let response = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 7307, "method": "command.execute",
        "params": { "schema_version": 1, "session_id": session.0,
                    "command": { "kind": "config.set" },
                    "key": "models.defaults.model",
                    "value": { "mode": "fixed", "connection": "primary", "model_id": "fixture-model" } }
    }));

    assert!(response["error"].is_null(), "{response}");
    let parsed = world
        .runtime
        .effective
        .parsed
        .as_ref()
        .expect("retained document");
    assert_eq!(
        parsed.models.defaults.as_ref().expect("defaults").model,
        ModelAssign::Fixed(FixedModel {
            connection: "primary".to_string(),
            model_id: "fixture-model".to_string(),
        }),
        "the wire object must land through the typed schema"
    );
}

/// AC-095: the file surface opens the command (parse → typed edit →
/// journaled intent) and the CLI replays the same command while it is
/// still pending. The replay must observe the pending intent — one
/// journaled control event — and the later managed write completes the
/// command exactly once.
#[test]
fn file_and_cli_singleflight_completes_once_with_one_control_event() {
    let (mut world, session) = carrier_world("singleflight");
    let target = world.root.join("config.toml");

    // File surface: the same command, admitted through the config owner's
    // singleflight under the file owner spelling.
    let mut file_config = Config::parse_validated(&support::base_config()).expect("valid config");
    let edit = file_config
        .set("workflow.enabled", ConfigValue::Bool(false))
        .expect("typed edit");
    let file_intent = rivect::config::admit_publication(
        &mut world.runtime.owner.store,
        PUBLICATION_OWNER,
        &target,
        &edit,
    )
    .expect("file admission")
    .intent();

    // CLI surface replays the same command before the write lands.
    let response = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 7308, "method": "command.execute",
        "params": { "schema_version": 1, "session_id": session.0,
                    "command": { "kind": "config.set" },
                    "key": "workflow.enabled", "value": false }
    }));
    assert!(response["error"].is_null(), "{response}");
    assert_eq!(
        response["result"]["digest"], edit.digest,
        "both carriers admit one command: {response}"
    );
    // The singleflight loser observes the winner's pending intent.
    assert_eq!(response["result"]["owner"], PUBLICATION_OWNER);
    assert_eq!(
        response["result"]["admission_seq"],
        json!(file_intent.admission_seq)
    );
    assert_eq!(
        pending_intents(&mut world.runtime.owner.store),
        1,
        "one control event: the replay must not journal a second intent"
    );

    // The managed write lands; recovery completes the command exactly once.
    std::fs::write(&target, &edit.bytes).expect("managed write bytes");
    assert_eq!(
        recovered_verdicts(&mut world.runtime.owner.store),
        vec![PublicationVerdict::ExactlyNew],
        "exactly one completion"
    );
    assert_eq!(
        pending_intents(&mut world.runtime.owner.store),
        0,
        "the single completion receipts the one control event"
    );
}

/// AC-095/F5: a first attempt whose managed write cannot run leaves the
/// staged row pending. The retry must never answer success from the
/// retained document — it re-runs the write, lands the bytes, and
/// receipts the same row.
#[test]
fn cli_retry_after_failed_write_lands_the_bytes_and_completes_the_row() {
    let (mut world, session) = carrier_world("retry-failed-write");
    let target = world.root.join("config.toml");

    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o444))
        .expect("read-only target for the first attempt");
    let first = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 7325, "method": "command.execute",
        "params": { "schema_version": 1, "session_id": session.0,
                    "command": { "kind": "config.set" },
                    "key": "workflow.enabled", "value": false }
    }));
    assert!(
        !first["error"].is_null(),
        "the unwritable target must refuse the first attempt: {first}"
    );
    assert_eq!(
        pending_intents(&mut world.runtime.owner.store),
        1,
        "the refused write leaves its staged row pending"
    );
    assert_eq!(
        std::fs::read_to_string(&target).expect("target bytes"),
        support::base_config(),
        "no bytes landed on the first attempt"
    );

    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644))
        .expect("writable target for the retry");
    let retry = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 7326, "method": "command.execute",
        "params": { "schema_version": 1, "session_id": session.0,
                    "command": { "kind": "config.set" },
                    "key": "workflow.enabled", "value": false }
    }));
    assert!(retry["error"].is_null(), "{retry}");
    let mut expected = Config::parse_validated(&support::base_config()).expect("valid config");
    let expected_edit = expected
        .set("workflow.enabled", ConfigValue::Bool(false))
        .expect("typed edit");
    assert_eq!(
        retry["result"]["digest"], expected_edit.digest,
        "the retry answers the same command: {retry}"
    );
    assert_eq!(
        std::fs::read(&target).expect("published bytes"),
        expected_edit.bytes,
        "the retry must land the bytes it reports"
    );
    assert_eq!(
        pending_intents(&mut world.runtime.owner.store),
        0,
        "the healed write receipts the staged row"
    );
}

/// AC-095/F5: a crash between the journal append and the managed write
/// leaves this carrier's row pending over unchanged base bytes (Old).
/// The retry heals the row — the write lands — instead of answering
/// success from the retained document.
#[test]
fn cli_retry_after_crash_before_write_heals_the_pending_row() {
    let (mut world, session) = carrier_world("retry-crash-before-write");
    let target = world.root.join("config.toml");

    let mut staged = Config::parse_validated(&support::base_config()).expect("valid config");
    let edit = staged
        .set("workflow.enabled", ConfigValue::Bool(false))
        .expect("typed edit");
    stage_publication(&mut world.runtime.owner.store, "cli", &target, &edit)
        .expect("crash left the cli-owned row staged, unwritten");
    assert_eq!(
        recovered_verdicts(&mut world.runtime.owner.store),
        vec![PublicationVerdict::Old],
        "the crash scenario: base bytes, no write"
    );

    let response = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 7327, "method": "command.execute",
        "params": { "schema_version": 1, "session_id": session.0,
                    "command": { "kind": "config.set" },
                    "key": "workflow.enabled", "value": false }
    }));
    assert!(response["error"].is_null(), "{response}");
    assert_eq!(
        std::fs::read(&target).expect("published bytes"),
        edit.bytes,
        "the retry heals the unwritten row by landing its bytes"
    );
    assert_eq!(
        pending_intents(&mut world.runtime.owner.store),
        0,
        "the healed row is receipted, never re-journaled"
    );
}

/// AC-095/F5: a crash after the managed write but before the receipt
/// leaves an ExactlyNew pending row. The retry takes the receipt path —
/// the read-only target proves the retry attempted no second write.
#[test]
fn cli_retry_of_an_exactly_new_pending_row_receipts_without_a_second_write() {
    let (mut world, session) = carrier_world("retry-exactly-new");
    let target = world.root.join("config.toml");

    let mut staged = Config::parse_validated(&support::base_config()).expect("valid config");
    let edit = staged
        .set("workflow.enabled", ConfigValue::Bool(false))
        .expect("typed edit");
    stage_publication(&mut world.runtime.owner.store, "cli", &target, &edit)
        .expect("staged intent");
    std::fs::write(&target, &edit.bytes).expect("crash landed the bytes unreceipted");
    assert_eq!(
        pending_intents(&mut world.runtime.owner.store),
        1,
        "the crash scenario: intended bytes on disk, receipt missing"
    );

    // A retry that wrote would hit the read-only target and fail; only
    // the receipt path can answer success here.
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o444))
        .expect("read-only target for the retry");
    let response = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 7328, "method": "command.execute",
        "params": { "schema_version": 1, "session_id": session.0,
                    "command": { "kind": "config.set" },
                    "key": "workflow.enabled", "value": false }
    }));
    assert!(response["error"].is_null(), "{response}");
    assert_eq!(
        pending_intents(&mut world.runtime.owner.store),
        0,
        "the retry receipts the crashed row without a new journal row"
    );
    assert_eq!(
        std::fs::read(&target).expect("target bytes"),
        edit.bytes,
        "no second write touched the target"
    );
}

#[test]
fn cli_unknown_edit_key_names_the_scope_the_file_surface_names() {
    // File surface: the connection table rejects `bogus` with its own keys.
    let file_text = format!(
        "{}[connections.clone]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:11434\"\nbogus = 1\n",
        support::base_config()
    );
    let file_error = Config::parse_validated(&file_text)
        .expect_err("the file surface must reject the unknown connection key");
    expect_stage(&file_error, Stage::Schema);
    assert!(
        matches!(
            &file_error.issue,
            ConfigIssue::UnknownKey { key, known }
                if key == "bogus"
                    && *known == ["kind", "endpoint", "credential_ref", "region", "profile"]
        ),
        "wrong rejection issue: {file_error}"
    );

    // CLI surface: the same scope-local csv, never a root-level hint.
    let (mut world, session) = carrier_world("cli-connection-scope");
    let response = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 7309, "method": "command.execute",
        "params": { "schema_version": 1, "session_id": session.0,
                    "command": { "kind": "config.set" },
                    "key": "connections.primary.bogus", "value": 1 }
    }));
    assert_eq!(
        response["error"]["data"]["message"],
        "schema connections.primary.bogus: unknown key connections.primary.bogus; known keys: kind, endpoint, credential_ref, region, profile",
        "the CLI hint must walk the schema, not re-declare it: {response}"
    );
}

#[test]
fn cli_root_level_edit_miss_answers_unknown_root_key_like_the_file_surface() {
    // The file surface's vocabulary for a root-level miss.
    let file_text = format!("bogus_root = 1\n{}", support::base_config());
    let file_error = Config::parse_validated(&file_text).expect_err("unknown root key");
    assert!(
        matches!(&file_error.issue, ConfigIssue::UnknownRootKey { key } if key == "bogus_root"),
        "wrong rejection issue: {file_error}"
    );

    // `config_version` and `connections` are legal file-surface roots (the
    // corpus carries both), so the edit surface must never call them
    // unknown; they are known roots the targeted edit cannot address.
    let (mut world, session) = carrier_world("cli-root-miss");
    let response = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 7310, "method": "command.execute",
        "params": { "schema_version": 1, "session_id": session.0,
                    "command": { "kind": "config.set" },
                    "key": "bogus_root", "value": 1 }
    }));
    assert_eq!(
        response["error"]["data"]["message"], "schema bogus_root: unknown root key bogus_root",
        "a root-level miss uses the file surface's issue: {response}"
    );
    for key in ["config_version", "connections"] {
        let response = world.dispatch(&json!({
            "jsonrpc": "2.0", "id": 7310, "method": "command.execute",
            "params": { "schema_version": 1, "session_id": session.0,
                        "command": { "kind": "config.set" },
                        "key": key, "value": 1 }
        }));
        assert_eq!(
            response["error"]["data"]["message"],
            format!("schema {key}: key {key} is not editable"),
            "a legal root the edit surface cannot target is not an unknown root: {response}"
        );
    }
    let response = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 7310, "method": "command.execute",
        "params": { "schema_version": 1, "session_id": session.0,
                    "command": { "kind": "config.set" },
                    "key": "config_version.sub", "value": 1 }
    }));
    assert_eq!(
        response["error"]["data"]["message"],
        "schema config_version.sub: key config_version is not editable",
        "a dotted key under a legal root is not an unknown root either: {response}"
    );
}

/// F1: the edit surface's scope walk reaches every scope table the file
/// surface raises from — the models tree answers MODELS_KEYS, PURPOSE_KEYS
/// and GROUP_KEYS csvs, never a root-level miss.
#[test]
fn cli_edit_walk_answers_every_models_scope_the_file_surface_names() {
    // models.bogus — the file surface raises MODELS_KEYS' own csv.
    let file_text = support::base_config().replace(
        "[models.defaults]",
        "[models]\nbogus = 1\n[models.defaults]",
    );
    let file_error = Config::parse_validated(&file_text)
        .expect_err("the file surface must reject the unknown models key");
    expect_stage(&file_error, Stage::Schema);
    assert!(
        matches!(
            &file_error.issue,
            ConfigIssue::UnknownKey { key, known }
                if key == "bogus" && *known == ["defaults", "groups", "purposes"]
        ),
        "wrong rejection issue: {file_error}"
    );

    // models.purposes.<name>.bogus — PURPOSE_KEYS csv.
    let file_text = format!(
        "{}[models.purposes.planner]\nbogus = 1\n",
        support::base_config()
    );
    let purpose_error = Config::parse_validated(&file_text)
        .expect_err("the file surface must reject the unknown purpose key");
    assert!(
        matches!(
            &purpose_error.issue,
            ConfigIssue::UnknownKey { key, known }
                if key == "bogus"
                    && *known == ["group", "model", "effort", "fallback", "pool", "eligible"]
        ),
        "wrong rejection issue: {purpose_error}"
    );

    // models.groups.<name>.bogus — GROUP_KEYS csv.
    let file_text =
        support::config_distinct_pools().replace("[\"local\"] }\n", "[\"local\"] }\nbogus = 1\n");
    let group_error = Config::parse_validated(&file_text)
        .expect_err("the file surface must reject the unknown group key");
    assert!(
        matches!(
            &group_error.issue,
            ConfigIssue::UnknownKey { key, known } if key == "bogus" && *known == ["model"]
        ),
        "wrong rejection issue: {group_error}"
    );

    let (mut world, session) = carrier_world("cli-models-scopes");
    for (id, key, expected) in [
        (
            7330u64,
            "models.bogus",
            "schema models.bogus: unknown key models.bogus; known keys: defaults, groups, purposes",
        ),
        (
            7331,
            "models.purposes.planner.bogus",
            "schema models.purposes.planner.bogus: unknown key models.purposes.planner.bogus; known keys: group, model, effort, fallback, pool, eligible",
        ),
        (
            7332,
            "models.groups.backend.bogus",
            "schema models.groups.backend.bogus: unknown key models.groups.backend.bogus; known keys: model",
        ),
    ] {
        let response = world.dispatch(&json!({
            "jsonrpc": "2.0", "id": id, "method": "command.execute",
            "params": { "schema_version": 1, "session_id": session.0,
                        "command": { "kind": "config.set" },
                        "key": key, "value": 1 }
        }));
        assert_eq!(
            response["error"]["data"]["message"], expected,
            "the CLI must name the file surface's scope csv: {response}"
        );
    }
}

/// F1: one uniform rule for keys the edit surface cannot target — a key
/// that spells a legal schema location with no EditTarget is
/// `KeyNotEditable`, never "unknown": the file surface accepts every
/// spelling below.
#[test]
fn legal_keys_without_edit_targets_answer_not_editable_never_unknown() {
    // File twins: each spelling is legal TOML the corpus carries.
    Config::parse_validated(&support::base_config())
        .expect("models, connections and their fields are legal spellings");
    Config::parse_validated(&format!("{}[workflow]\n", support::base_config()))
        .expect("a bare workflow table is legal");
    Config::parse_validated(&format!("{}[models.purposes]\n", support::base_config()))
        .expect("a bare purposes table is legal");
    Config::parse_validated(&support::config_distinct_pools())
        .expect("purpose group fields are legal spellings");

    let (mut world, session) = carrier_world("cli-not-editable");
    for (offset, &(key, expected)) in [
        ("models", "schema models: key models is not editable"),
        (
            "models.defaults",
            "schema models.defaults: key models.defaults is not editable",
        ),
        (
            "models.purposes",
            "schema models.purposes: key models.purposes is not editable",
        ),
        (
            "models.purposes.planner",
            "schema models.purposes.planner: key models.purposes.planner is not editable",
        ),
        (
            "models.purposes.planner.group",
            "schema models.purposes.planner.group: key models.purposes.planner.group is not editable",
        ),
        (
            "models.groups",
            "schema models.groups: key models.groups is not editable",
        ),
        (
            "models.groups.backend",
            "schema models.groups.backend: key models.groups.backend is not editable",
        ),
        (
            "connections.primary",
            "schema connections.primary: key connections.primary is not editable",
        ),
        (
            "connections.primary.kind",
            "schema connections.primary.kind: key connections.primary.kind is not editable",
        ),
        (
            "connections.primary.endpoint",
            "schema connections.primary.endpoint: key connections.primary.endpoint is not editable",
        ),
        (
            "connections.primary.credential_ref",
            "schema connections.primary.credential_ref: key connections.primary.credential_ref is not editable",
        ),
        ("workflow", "schema workflow: key workflow is not editable"),
    ].iter().enumerate() {
        let response = world.dispatch(&json!({
            "jsonrpc": "2.0", "id": 7333 + offset as u64, "method": "command.execute",
            "params": { "schema_version": 1, "session_id": session.0,
                        "command": { "kind": "config.set" },
                        "key": key, "value": 1 }
        }));
        assert_eq!(
            response["error"]["data"]["message"], expected,
            "legal-but-untargetable must answer not-editable: {response}"
        );
    }
}

/// F1: the chain-entry scope is reachable from the edit surface too — a
/// miss below `.fallback.chain` answers CHAIN_ENTRY_KEYS, the csv the file
/// surface raises for the same TOML spot, and chain-entry fields are
/// legal-but-untargetable like every other read-only field.
#[test]
fn cli_edit_walk_reaches_the_fallback_chain_entry_scope() {
    let file_error = Config::parse_validated(&lossless_edit_config())
        .expect_err("the file surface must reject the unknown chain key");
    expect_stage(&file_error, Stage::Schema);
    assert!(
        matches!(
            &file_error.issue,
            ConfigIssue::UnknownKey { key, known }
                if key == "order" && *known == ["mode", "connection", "model_id"]
        ),
        "wrong rejection issue: {file_error}"
    );

    let (mut world, session) = carrier_world("cli-chain-scope");
    for (id, key, expected) in [
        (
            7346u64,
            "models.purposes.planner.fallback.chain.order",
            "schema models.purposes.planner.fallback.chain.order: unknown key models.purposes.planner.fallback.chain.order; known keys: mode, connection, model_id",
        ),
        (
            7347,
            "models.purposes.planner.fallback.chain.connection",
            "schema models.purposes.planner.fallback.chain.connection: key models.purposes.planner.fallback.chain.connection is not editable",
        ),
        (
            7348u64,
            "models.defaults.fallback.chain",
            "schema models.defaults.fallback.chain: key models.defaults.fallback.chain is not editable",
        ),
        (
            7349u64,
            "models.defaults.fallback.chain.order.mode",
            "schema models.defaults.fallback.chain.order.mode: unknown key models.defaults.fallback.chain.order.mode; known keys: mode, connection, model_id",
        ),
        (
            7350u64,
            "models.purposes.planner.fallback.chain.zzz.model_id",
            "schema models.purposes.planner.fallback.chain.zzz.model_id: unknown key models.purposes.planner.fallback.chain.zzz.model_id; known keys: mode, connection, model_id",
        ),
    ] {
        let response = world.dispatch(&json!({
            "jsonrpc": "2.0", "id": id, "method": "command.execute",
            "params": { "schema_version": 1, "session_id": session.0,
                        "command": { "kind": "config.set" },
                        "key": key, "value": 1 }
        }));
        assert_eq!(
            response["error"]["data"]["message"], expected,
            "the chain scope must answer the file surface's csv: {response}"
        );
    }
}

/// r4-F1: the assignment tables below a legal slot are permissive on the
/// file surface — it accepts their field spellings and even unknown
/// fields without a csv — so every descent below a slot is
/// legal-but-untargetable, never an unknown key.
#[test]
fn cli_edit_walk_descends_below_slot_assignments_as_not_editable() {
    // Positive control: the file surface accepts an unknown field inside a
    // slot assignment, which is why the edit surface has no csv to name
    // below a slot.
    let permissive = support::base_config().replace(
        r#"model = { mode = "auto" }"#,
        r#"model = { mode = "auto", bogus = 1 }"#,
    );
    Config::parse_validated(&permissive).expect("the file surface accepts any slot-table field");

    let (mut world, session) = carrier_world("cli-slot-descent");
    for (offset, &key) in [
        "models.defaults.model.mode",
        "models.defaults.model.connection",
        "models.defaults.model.model_id",
        "models.defaults.model.pool",
        "models.defaults.model.bogus",
        "models.defaults.effort.value",
        "models.defaults.fallback.mode",
        "models.groups.backend.model.mode",
        "models.purposes.planner.model.mode",
        "models.purposes.planner.effort.value",
        "models.purposes.planner.fallback.mode",
    ]
    .iter()
    .enumerate()
    {
        let response = world.dispatch(&json!({
            "jsonrpc": "2.0", "id": 7350 + offset as u64, "method": "command.execute",
            "params": { "schema_version": 1, "session_id": session.0,
                        "command": { "kind": "config.set" },
                        "key": key, "value": 1 }
        }));
        assert_eq!(
            response["error"]["data"]["message"],
            format!("schema {key}: key {key} is not editable"),
            "a file-legal descent below a slot assignment is not an unknown key: {response}"
        );
    }
}

/// r4-F2: `models.defaults.fallback` chain references were checked by the
/// targeted edit but accepted by the file surface — one schema must reject
/// the ghost chain on both carriers, exactly as purposes chains already
/// are.
#[test]
fn defaults_fallback_chain_reference_is_checked_on_the_file_surface_too() {
    let ghost = support::base_config().replace(
        r#"fallback = { mode = "auto" }"#,
        r#"fallback = { mode = "auto", chain = [{ mode = "fixed", connection = "nope", model_id = "fixture-reserve" }] }"#,
    );
    let file_error =
        Config::parse_validated(&ghost).expect_err("the file surface must reject the ghost chain");
    expect_stage(&file_error, Stage::Schema);
    assert_eq!(
        file_error.key.as_deref(),
        Some("models.defaults.fallback.chain")
    );
    assert!(
        matches!(
            &file_error.issue,
            ConfigIssue::UnknownConnectionReference { connection } if connection == "nope"
        ),
        "wrong rejection issue: {file_error}"
    );

    // Positive control: a declared connection admits the same chain.
    let declared = support::base_config().replace(
        r#"fallback = { mode = "auto" }"#,
        r#"fallback = { mode = "auto", chain = [{ mode = "fixed", connection = "primary", model_id = "fixture-reserve" }] }"#,
    );
    Config::parse_validated(&declared).expect("a declared defaults chain reference is valid");

    // The targeted-edit twin keeps rejecting the ghost: both surfaces agree.
    let mut config = Config::parse_validated(&support::base_config()).expect("valid config");
    let error = config
        .set_wire(
            "models.defaults.fallback",
            &json!({
                "mode": "auto",
                "chain": [{ "mode": "fixed", "connection": "nope", "model_id": "fixture-model" }]
            }),
        )
        .expect_err("an unknown chain reference must reject the targeted edit");
    assert!(
        matches!(
            &error.issue,
            ConfigIssue::UnknownConnectionReference { connection } if connection == "nope"
        ),
        "wrong rejection issue: {error}"
    );
}

/// r4-F3: a dotted key with an empty segment cannot be walked through the
/// scope tables; the rejection must still name the requested key instead
/// of an anonymous root miss.
#[test]
fn malformed_dotted_keys_name_the_rejected_key() {
    let (mut world, session) = carrier_world("cli-malformed-key");
    for (offset, &key) in [".models", ".", "", "workflow..enabled", "models."]
        .iter()
        .enumerate()
    {
        let response = world.dispatch(&json!({
            "jsonrpc": "2.0", "id": 7360 + offset as u64, "method": "command.execute",
            "params": { "schema_version": 1, "session_id": session.0,
                        "command": { "kind": "config.set" },
                        "key": key, "value": 1 }
        }));
        assert_eq!(
            response["error"]["data"]["message"],
            format!("schema {key}: malformed key {key}: empty segment"),
            "the malformed key is named, not an anonymous root miss: {response}"
        );
    }
}

/// T5: `workflow.bogus` answers the one WORKFLOW_KEYS csv on both
/// surfaces.
#[test]
fn workflow_unknown_field_answers_one_hint_on_both_surfaces() {
    let file_text = format!(
        "{}[workflow]\nenabled = true\nbogus = 1\n",
        support::base_config()
    );
    let file_error = Config::parse_validated(&file_text)
        .expect_err("the file surface must reject the unknown workflow key");
    expect_stage(&file_error, Stage::Schema);
    assert!(
        matches!(
            &file_error.issue,
            ConfigIssue::UnknownKey { key, known } if key == "bogus" && *known == ["enabled"]
        ),
        "wrong rejection issue: {file_error}"
    );
    assert_eq!(
        file_error.to_string(),
        "schema workflow.bogus: unknown key bogus; known keys: enabled"
    );

    let (mut world, session) = carrier_world("cli-workflow-miss");
    let response = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 7370, "method": "command.execute",
        "params": { "schema_version": 1, "session_id": session.0,
                    "command": { "kind": "config.set" },
                    "key": "workflow.bogus", "value": 1 }
    }));
    assert_eq!(
        response["error"]["data"]["message"],
        "schema workflow.bogus: unknown key workflow.bogus; known keys: enabled",
        "the edit surface names the same scope csv: {response}"
    );
}

#[test]
fn targeted_fallback_edit_checks_chain_connection_references() {
    let mut config = Config::parse_validated(&support::base_config()).expect("valid config");
    let error = config
        .set_wire(
            "models.purposes.worker.fallback",
            &json!({
                "mode": "auto",
                "chain": [{ "mode": "fixed", "connection": "nope", "model_id": "fixture-model" }]
            }),
        )
        .expect_err("an unknown chain reference must reject the targeted edit");
    expect_stage(&error, Stage::Schema);
    assert!(
        matches!(
            &error.issue,
            ConfigIssue::UnknownConnectionReference { connection } if connection == "nope"
        ),
        "wrong rejection issue: {error}"
    );

    // Positive control: a declared connection admits the same shape.
    let mut config = Config::parse_validated(&support::base_config()).expect("valid config");
    config
        .set_wire(
            "models.purposes.worker.fallback",
            &json!({
                "mode": "auto",
                "chain": [{ "mode": "fixed", "connection": "primary", "model_id": "fixture-model" }]
            }),
        )
        .expect("a declared chain reference is a valid targeted edit");
}

/// AC-095/F4: `/x/./config.toml` and `/x/config.toml` are one file. The
/// singleflight match keys on the opened `(dev, ino)` identity, so the
/// replay through the second spelling still observes the winner.
#[test]
fn singleflight_keys_the_match_on_file_identity_not_the_path_spelling() {
    let (mut world, session) = carrier_world("identity-key");
    let dotted = world.root.join(".").join("config.toml");

    let mut file_config = Config::parse_validated(&support::base_config()).expect("valid config");
    let edit = file_config
        .set("workflow.enabled", ConfigValue::Bool(false))
        .expect("typed edit");
    let winner = rivect::config::admit_publication(
        &mut world.runtime.owner.store,
        PUBLICATION_OWNER,
        &dotted,
        &edit,
    )
    .expect("file admission through the dotted spelling")
    .intent();

    // The CLI replays the same command through the clean spelling.
    let response = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 7311, "method": "command.execute",
        "params": { "schema_version": 1, "session_id": session.0,
                    "command": { "kind": "config.set" },
                    "key": "workflow.enabled", "value": false }
    }));
    assert!(response["error"].is_null(), "{response}");
    assert_eq!(
        response["result"]["owner"], PUBLICATION_OWNER,
        "same inode: the replay observes the winner's intent: {response}"
    );
    assert_eq!(
        response["result"]["admission_seq"],
        json!(winner.admission_seq),
        "same inode: the replay must not mint a second intent: {response}"
    );
    assert_eq!(
        pending_intents(&mut world.runtime.owner.store),
        1,
        "one control event for one file identity"
    );
}

/// AC-095: the spec's "singleflight loser observes terminal | no second
/// effect" row — a replay of an already-applied command returns the
/// winner's terminal result and journals nothing new.
#[test]
fn replay_after_completion_observes_the_terminal_result_without_a_second_row() {
    let (mut world, session) = carrier_world("terminal-replay");
    let target = world.root.join("config.toml");

    let mut file_config = Config::parse_validated(&support::base_config()).expect("valid config");
    let edit = file_config
        .set("workflow.enabled", ConfigValue::Bool(false))
        .expect("typed edit");
    let winner = rivect::config::admit_publication(
        &mut world.runtime.owner.store,
        PUBLICATION_OWNER,
        &target,
        &edit,
    )
    .expect("file admission")
    .intent();

    std::fs::write(&target, &edit.bytes).expect("managed write bytes");
    assert_eq!(
        recovered_verdicts(&mut world.runtime.owner.store),
        vec![PublicationVerdict::ExactlyNew],
        "the winner completes exactly once"
    );
    assert_eq!(pending_intents(&mut world.runtime.owner.store), 0);

    // The CLI replays the same command after the winner went terminal.
    let response = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 7312, "method": "command.execute",
        "params": { "schema_version": 1, "session_id": session.0,
                    "command": { "kind": "config.set" },
                    "key": "workflow.enabled", "value": false }
    }));
    assert!(response["error"].is_null(), "{response}");
    assert_eq!(
        response["result"]["owner"], PUBLICATION_OWNER,
        "the replay observes the winner's terminal result: {response}"
    );
    assert_eq!(
        response["result"]["admission_seq"],
        json!(winner.admission_seq),
        "terminal identity, not a fresh mint: {response}"
    );
    assert_eq!(
        pending_intents(&mut world.runtime.owner.store),
        0,
        "an already-applied command journals nothing new"
    );

    // A genuinely different edit is a fresh instance: new admission identity.
    let response = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 7313, "method": "command.execute",
        "params": { "schema_version": 1, "session_id": session.0,
                    "command": { "kind": "config.set" },
                    "key": "workflow.enabled", "value": true }
    }));
    assert!(response["error"].is_null(), "{response}");
    assert_eq!(
        response["result"]["owner"], "cli",
        "a new edit keeps its own admission identity: {response}"
    );
    assert_eq!(
        pending_intents(&mut world.runtime.owner.store),
        0,
        "a new edit publishes and receipts its own control event"
    );
}

/// AC-095: the terminal match requires the bytes the winner produced to
/// still hold. A target that moved on makes the same command a fresh
/// instance again.
#[test]
fn replay_after_the_target_moved_on_admits_a_fresh_instance() {
    let (mut world, session) = carrier_world("moved-on");
    let target = world.root.join("config.toml");

    let mut file_config = Config::parse_validated(&support::base_config()).expect("valid config");
    let edit = file_config
        .set("workflow.enabled", ConfigValue::Bool(false))
        .expect("typed edit");
    rivect::config::admit_publication(
        &mut world.runtime.owner.store,
        PUBLICATION_OWNER,
        &target,
        &edit,
    )
    .expect("file admission");
    std::fs::write(&target, &edit.bytes).expect("managed write bytes");
    assert_eq!(
        recovered_verdicts(&mut world.runtime.owner.store),
        vec![PublicationVerdict::ExactlyNew]
    );

    // A third party edits the file further; the winner's bytes no longer hold.
    std::fs::write(&target, foreign_toml()).expect("third-party bytes");

    let response = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 7314, "method": "command.execute",
        "params": { "schema_version": 1, "session_id": session.0,
                    "command": { "kind": "config.set" },
                    "key": "workflow.enabled", "value": false }
    }));
    assert!(response["error"].is_null(), "{response}");
    assert_eq!(
        response["result"]["owner"], "cli",
        "the state the winner produced no longer holds: fresh instance: {response}"
    );
    // The fresh instance publishes against the new base: the CLI's own
    // bytes replace the third-party edit and the row is receipted.
    assert_eq!(
        std::fs::read(&target).expect("target bytes"),
        edit.bytes,
        "the fresh instance lands its managed write"
    );
    assert_eq!(
        pending_intents(&mut world.runtime.owner.store),
        0,
        "the replay publishes its own control event against the new base"
    );
}

/// AC-095/F2: `admission_seq` counts per target *string*, so one file
/// journaled under two spellings carries two independent counters — the
/// terminal arm must not read max-seq as file chronology. The applied row
/// whose bytes still hold is the winner, whichever spelling journaled it.
#[test]
fn terminal_replay_across_two_spellings_observes_the_row_whose_bytes_hold() {
    let (mut world, session) = carrier_world("two-spelling-terminal");
    let dotted = world.root.join(".").join("config.toml");
    let clean = world.root.join("config.toml");

    let mut file_config = Config::parse_validated(&support::base_config()).expect("valid config");
    let edit = file_config
        .set("workflow.enabled", ConfigValue::Bool(false))
        .expect("typed edit");
    let winner = rivect::config::admit_publication(
        &mut world.runtime.owner.store,
        PUBLICATION_OWNER,
        &dotted,
        &edit,
    )
    .expect("file admission under the dotted spelling")
    .intent();

    std::fs::write(&clean, &edit.bytes).expect("managed write bytes");
    assert_eq!(
        recovered_verdicts(&mut world.runtime.owner.store),
        vec![PublicationVerdict::ExactlyNew],
        "the winner completes exactly once"
    );

    // Later applied rows under the clean spelling: their own per-string
    // counter runs past the dotted row's, but their bytes never held at
    // this file.
    let identity = winner.publish_identity;
    let clean_key = clean.to_str().expect("utf-8 target").to_string();
    for stale_digest in [
        "0000000000000000000000000000000000000000000000000000000000000001",
        "0000000000000000000000000000000000000000000000000000000000000002",
    ] {
        let seq = world
            .runtime
            .owner
            .store
            .append_publication(PUBLICATION_OWNER, &clean_key, stale_digest, None, identity)
            .expect("append stale applied row");
        world
            .runtime
            .owner
            .store
            .complete_publication(PUBLICATION_OWNER, &clean_key, seq)
            .expect("receipt stale applied row");
    }

    // The CLI replays the applied command through the clean spelling.
    let response = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 7317, "method": "command.execute",
        "params": { "schema_version": 1, "session_id": session.0,
                    "command": { "kind": "config.set" },
                    "key": "workflow.enabled", "value": false }
    }));
    assert!(response["error"].is_null(), "{response}");
    assert_eq!(
        response["result"]["owner"], PUBLICATION_OWNER,
        "the applied row whose bytes hold wins across spellings: {response}"
    );
    assert_eq!(
        response["result"]["admission_seq"],
        json!(winner.admission_seq),
        "the winner's own terminal identity, not a fresh mint: {response}"
    );
    assert_eq!(
        pending_intents(&mut world.runtime.owner.store),
        0,
        "an already-applied command journals nothing new"
    );
}

/// N1: after an accepted edit the read surface answers the retained doc —
/// pre-publication the retained doc is the effective view — so config.set
/// then config.read in one world never contradicts, and unsetting the
/// override falls back to the shipped default again.
#[test]
fn config_set_then_config_read_answers_the_retained_value() {
    let (mut world, session) = carrier_world("set-then-read");

    let set = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 7318, "method": "command.execute",
        "params": { "schema_version": 1, "session_id": session.0,
                    "command": { "kind": "config.set" },
                    "key": "workflow.enabled", "value": false }
    }));
    assert!(set["error"].is_null(), "{set}");

    let read = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 7319, "method": "config.read",
        "params": { "schema_version": 1, "session_id": session.0,
                    "keys": ["workflow.enabled"] }
    }));
    assert!(read["error"].is_null(), "{read}");
    let entry = &read["result"]["entries"]["items"][0];
    assert_eq!(entry["key"], "workflow.enabled", "{read}");
    assert_eq!(entry["effective"]["value"], false, "{read}");
    assert_eq!(entry["source"]["kind"], "user", "{read}");
    assert_eq!(
        entry["source"]["revision"], set["result"]["digest"],
        "{read}"
    );

    let unset = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 7320, "method": "command.execute",
        "params": { "schema_version": 1, "session_id": session.0,
                    "command": { "kind": "config.unset" },
                    "key": "workflow.enabled" }
    }));
    assert!(unset["error"].is_null(), "{unset}");

    let read = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 7321, "method": "config.read",
        "params": { "schema_version": 1, "session_id": session.0,
                    "keys": ["workflow.enabled"] }
    }));
    let entry = &read["result"]["entries"]["items"][0];
    assert_eq!(
        entry["effective"]["value"], true,
        "the removed override falls back to the shipped default: {read}"
    );
    assert_eq!(entry["source"]["kind"], "shipped", "{read}");
}

/// N1 (open half): a user file that carries the override serves it from
/// the first read — the boot-time entry derives from the same precedence
/// pass the retained doc rebuild uses.
#[test]
fn user_file_workflow_override_is_served_at_open() {
    let mut world = support::open_world(
        "open-override",
        Some(&format!(
            "{}[workflow]\nenabled = false\n",
            support::base_config()
        )),
    );
    let session = world.open_session("bootstrap-open-override");

    let read = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 7322, "method": "config.read",
        "params": { "schema_version": 1, "session_id": session.0,
                    "keys": ["workflow.enabled"] }
    }));
    assert!(read["error"].is_null(), "{read}");
    let entry = &read["result"]["entries"]["items"][0];
    assert_eq!(entry["effective"]["value"], false, "{read}");
    assert_eq!(entry["source"]["kind"], "user", "{read}");
}

/// N2: a rejected admission never moved the retained document — the
/// command was not journaled, so no surface may observe its edit.
#[test]
fn rejected_admission_restores_the_retained_view() {
    let (mut world, session) = carrier_world("admission-refused");
    std::fs::remove_file(world.root.join("config.toml")).expect("target deleted after open");

    let response = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 7323, "method": "command.execute",
        "params": { "schema_version": 1, "session_id": session.0,
                    "command": { "kind": "config.set" },
                    "key": "workflow.enabled", "value": false }
    }));
    let message = response["error"]["data"]["message"]
        .as_str()
        .expect("typed rejection");
    assert!(
        message.contains("publication target does not exist"),
        "the admission itself is refused: {response}"
    );
    assert_eq!(
        pending_intents(&mut world.runtime.owner.store),
        0,
        "nothing was journaled for the refused command"
    );

    let parsed = world
        .runtime
        .effective
        .parsed
        .as_ref()
        .expect("retained document still present");
    assert_eq!(
        parsed.workflow.enabled, None,
        "the retained view did not move: the command was never journaled"
    );

    // The read surface agrees: the pre-edit value still answers.
    let read = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 7324, "method": "config.read",
        "params": { "schema_version": 1, "session_id": session.0,
                    "keys": ["workflow.enabled"] }
    }));
    let entry = &read["result"]["entries"]["items"][0];
    assert_eq!(entry["effective"]["value"], true, "{read}");
    assert_eq!(entry["source"]["kind"], "shipped", "{read}");
}

#[test]
fn cli_config_unset_removes_a_purpose_override_and_completes_once() {
    let mut world = support::open_world(
        "cli-unset-override",
        Some(&support::config_fixed_model_auto_effort()),
    );
    let session = world.open_session("bootstrap-cli-unset-override");

    let response = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 7315, "method": "command.execute",
        "params": { "schema_version": 1, "session_id": session.0,
                    "command": { "kind": "config.unset" },
                    "key": "models.purposes.main.model" }
    }));
    assert!(response["error"].is_null(), "{response}");

    // The exact unset a file-surface reset of the same key produces.
    let mut expected =
        Config::parse_validated(&support::config_fixed_model_auto_effort()).expect("valid config");
    let expected_edit = expected
        .reset("models.purposes.main.model")
        .expect("typed reset");
    assert_eq!(
        response["result"]["digest"], expected_edit.digest,
        "the CLI unset must be the file surface's unset: {response}"
    );

    let parsed = world
        .runtime
        .effective
        .parsed
        .as_ref()
        .expect("retained document");
    let purpose = parsed.models.purposes.get("main").expect("main purpose");
    assert!(
        purpose.model.is_none(),
        "the override is gone from the retained view"
    );
    assert!(
        matches!(&purpose.effort, Some(EffortAssign::Auto)),
        "the sibling override survives the targeted unset"
    );

    // The command itself lands the publication once: the exact
    // file-surface bytes are on disk and the journal row is receipted.
    assert_eq!(
        std::fs::read(world.root.join("config.toml")).expect("published bytes"),
        expected_edit.bytes,
        "command.execute itself must change config.toml on disk"
    );
    assert_eq!(
        pending_intents(&mut world.runtime.owner.store),
        0,
        "the write's receipt completes the one journaled intent"
    );
}

#[test]
fn cli_config_set_without_a_retained_document_is_a_typed_rejection() {
    let mut world = support::open_world("cli-no-retained", None);
    let session = world.open_session("bootstrap-cli-no-retained");

    let response = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 7316, "method": "command.execute",
        "params": { "schema_version": 1, "session_id": session.0,
                    "command": { "kind": "config.set" },
                    "key": "workflow.enabled", "value": false }
    }));
    assert_eq!(
        response["error"]["data"]["code"], "invalid_input",
        "a missing retained document is a typed rejection: {response}"
    );
    assert_eq!(
        response["error"]["data"]["message"],
        "schema workflow.enabled: no configuration document is retained; parse one before editing",
        "{response}"
    );
    assert_eq!(
        pending_intents(&mut world.runtime.owner.store),
        0,
        "a rejected edit never journals an intent"
    );
}

// ----- publication failure wire codes (AC-093/AC-095) -----
// Every `PublicationError` variant the admit path can raise keeps its own
// wire code — a missing target is `not_found`, a broken write surfaces the
// executor's `denied` — instead of collapsing into `internal_error`. The
// variant the CLI carrier can stage but never trigger through one dispatch
// (`TargetNotUtf8` — the data root is always UTF-8 — and the `Journal`
// arm's own storage faults) stays pinned by the unit tests beside
// `publication_error`.

#[test]
fn cli_config_set_maps_staging_failures_to_their_wire_codes() {
    // An absent target is `not_found`: the managed write cannot create
    // it, and no generic fault should answer for it.
    let (mut world, session) = carrier_world("wire-absent");
    std::fs::remove_file(world.root.join("config.toml")).expect("remove the target");
    let response = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 7317, "method": "command.execute",
        "params": { "schema_version": 1, "session_id": session.0,
                    "command": { "kind": "config.set" },
                    "key": "workflow.enabled", "value": false }
    }));
    assert_eq!(
        response["error"]["data"]["code"], "not_found",
        "an absent publication target is not_found: {response}"
    );

    // A non-regular target is `storage_unavailable`: staging opens it,
    // observes it cannot carry bytes, and refuses.
    let (mut world, session) = carrier_world("wire-nonregular");
    let target = world.root.join("config.toml");
    std::fs::remove_file(&target).expect("remove the target");
    std::fs::create_dir(&target).expect("a directory occupies the target path");
    let response = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 7318, "method": "command.execute",
        "params": { "schema_version": 1, "session_id": session.0,
                    "command": { "kind": "config.set" },
                    "key": "workflow.enabled", "value": false }
    }));
    assert_eq!(
        response["error"]["data"]["code"], "storage_unavailable",
        "a non-regular publication target is storage_unavailable: {response}"
    );
}

#[test]
fn cli_config_set_pending_arm_maps_write_and_identity_failures() {
    // A pending own-carrier row replays through `resolve_pending_publication`
    // — the same fail-closed publication_error arm as the fresh write.
    let (mut world, session) = carrier_world("wire-write-denied");
    let target = world.root.join("config.toml");
    let mut file_config = Config::parse_validated(&support::base_config()).expect("valid config");
    let edit = file_config
        .set("workflow.enabled", ConfigValue::Bool(false))
        .expect("typed edit");
    stage_publication(&mut world.runtime.owner.store, "cli", &target, &edit)
        .expect("stage the carrier's own intent");
    // The managed write must fail: a read-only target refuses the
    // checked-fd write with `denied`, the executor's own wire code.
    let mut permissions = std::fs::metadata(&target)
        .expect("target metadata")
        .permissions();
    permissions.set_mode(0o444);
    std::fs::set_permissions(&target, permissions).expect("read-only target");
    let response = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 7319, "method": "command.execute",
        "params": { "schema_version": 1, "session_id": session.0,
                    "command": { "kind": "config.set" },
                    "key": "workflow.enabled", "value": false }
    }));
    assert_eq!(
        response["error"]["data"]["code"], "denied",
        "a refused managed write surfaces the executor's denied code: {response}"
    );
    assert_eq!(
        pending_intents(&mut world.runtime.owner.store),
        1,
        "the unlanded write leaves its intent pending for recovery"
    );
    let mut permissions = std::fs::metadata(&target)
        .expect("target metadata")
        .permissions();
    permissions.set_mode(0o644);
    std::fs::set_permissions(&target, permissions).expect("restore target permissions");

    // A staged row that carries no publish identity — only an older
    // journal produces one — cannot run its write at all.
    let (mut world, session) = carrier_world("wire-identity");
    let target = world.root.join("config.toml");
    world
        .runtime
        .owner
        .store
        .append_publication(
            "cli",
            target.to_str().expect("utf-8 target"),
            &edit.digest,
            None,
            None,
        )
        .expect("journal an identity-less intent");
    let response = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 7320, "method": "command.execute",
        "params": { "schema_version": 1, "session_id": session.0,
                    "command": { "kind": "config.set" },
                    "key": "workflow.enabled", "value": false }
    }));
    assert_eq!(
        response["error"]["data"]["code"], "internal_error",
        "a staged row without publish identity is internal_error: {response}"
    );
    assert_eq!(
        pending_intents(&mut world.runtime.owner.store),
        1,
        "the row the write never ran for stays pending"
    );
}

// ----- SLICE-014 legs --------------------------------------------------

/// AC-047 corpus: a profiled connection plus two declared credential
/// profiles — the switch surface `config.set connections.local.profile`
/// moves the pending binding between them, while the purpose pins stay
/// fixed and workflow stays off.
fn profiled_config() -> String {
    "config_version = 1\n\
     [workflow]\nenabled = false\n\
     [connections.local]\nkind = \"local\"\nendpoint = \"http://127.0.0.1:11434\"\nprofile = \"p1\"\n\
     [profiles.p1]\ncredential_ref = \"keyring:rivect/p1\"\n\
     [profiles.p2]\ncredential_ref = \"keyring:rivect/p2\"\n\
     [models.defaults]\nmodel = { mode = \"auto\" }\neffort = { mode = \"auto\" }\nfallback = { mode = \"auto\" }\n\
     [models.purposes.main]\n\
     model = { mode = \"fixed\", connection = \"local\", model_id = \"pinned-model\" }\n\
     effort = { mode = \"fixed\", value = \"high\" }\n"
        .to_string()
}

/// AC-047: a profile switch through the existing config.set carrier
/// preserves the pinned model/effort, the manual permission grants, the
/// workflow-off state, and the already-frozen in-flight manifest.
#[test]
fn profile_switch_preserves_pinned_model_effort_manual_permissions_and_workflow_off() {
    let mut world = support::open_world("profile-switch", Some(&profiled_config()));
    let session = world.open_session("profile-boot");
    // a manual permission the switch must preserve
    let scope = world.root.join("scope");
    std::fs::create_dir_all(&scope).expect("scope dir");
    let scoped_file = scope.join("allowed.txt");
    std::fs::write(&scoped_file, "marker\n").expect("scope file");
    let grant = world.runtime.set_read_scope(scope, scoped_file);
    let before = world
        .runtime
        .config_for_broker()
        .resolve_purpose("main")
        .expect("resolve");

    // bind p1: the prepared manifest freezes the in-use connection's
    // profile at admission
    let config = world.runtime.config_for_broker();
    let manifest = world
        .runtime
        .broker
        .prepare("main", &config, "/world/profile", "goal: pinned")
        .expect("manifest");
    world
        .runtime
        .broker
        .dispatch("/world/profile", &manifest)
        .expect("dispatch binds the profile");
    let bound = world
        .runtime
        .broker
        .bound_profile()
        .expect("a bound profile");
    assert_eq!(bound.connection, "local");
    assert_eq!(bound.profile.as_deref(), Some("p1"));

    // the profile switch rides the existing config.set carrier
    let response = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 9001, "method": "command.execute",
        "params": { "schema_version": 1, "session_id": session.0,
                    "command": { "kind": "config.set" },
                    "key": "connections.local.profile", "value": "p2" }
    }));
    assert!(
        response["error"].is_null(),
        "the typed edit is admitted: {response}"
    );

    let after = world
        .runtime
        .config_for_broker()
        .resolve_purpose("main")
        .expect("resolve");
    assert_eq!(
        after.model, before.model,
        "the pinned model survives the profile switch"
    );
    assert_eq!(after.effort, before.effort, "the pinned effort survives");
    assert_eq!(after.fallback, before.fallback);
    // workflow-off state is untouched by the profile edit
    assert_eq!(
        world
            .runtime
            .effective
            .parsed
            .as_ref()
            .expect("parsed")
            .workflow
            .enabled,
        Some(false)
    );
    // the manual permission survives untouched
    assert!(
        world.runtime.policy.grant(&grant).is_some(),
        "the scoped grant survives the switch"
    );
    // the in-flight manifest was never rewritten: the wire record is
    // exactly what prepare froze
    assert_eq!(world.last_manifest().as_ref(), Some(&manifest));
}

/// AC-047: the existing runtime.status surface carries the pending and
/// active profile pair — they diverge while an accepted edit waits for
/// the next request and converge once it binds.
#[test]
fn profile_switch_surfaces_pending_versus_active_on_the_existing_status_surface() {
    let mut world = support::open_world("profile-status", Some(&profiled_config()));
    let session = world.open_session("status-boot");

    // before any dispatch: no binding exists
    let status = world.dispatch(&support::corpus_status(&session));
    assert_eq!(status["result"]["profile"]["active"], json!(null));
    assert_eq!(status["result"]["profile"]["pending"], json!(null));

    // bind p1 by an actual dispatch
    let config = world.runtime.config_for_broker();
    let manifest = world
        .runtime
        .broker
        .prepare("main", &config, "/world/status", "goal: status")
        .expect("manifest");
    world
        .runtime
        .broker
        .dispatch("/world/status", &manifest)
        .expect("dispatch");
    let status = world.dispatch(&support::corpus_status(&session));
    assert_eq!(status["result"]["profile"]["active"], json!("p1"));
    assert_eq!(
        status["result"]["profile"]["pending"],
        json!("p1"),
        "no edit is pending before the switch"
    );

    // the switch is admitted: pending diverges from active until the
    // next request binds it
    let response = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 9002, "method": "command.execute",
        "params": { "schema_version": 1, "session_id": session.0,
                    "command": { "kind": "config.set" },
                    "key": "connections.local.profile", "value": "p2" }
    }));
    assert!(response["error"].is_null(), "{response}");
    let status = world.dispatch(&support::corpus_status(&session));
    assert_eq!(
        status["result"]["profile"]["active"],
        json!("p1"),
        "the bound manifest still names p1"
    );
    assert_eq!(
        status["result"]["profile"]["pending"],
        json!("p2"),
        "the accepted edit is pending"
    );

    // the next request binds p2; the surfaces converge again
    let config = world.runtime.config_for_broker();
    let next = world
        .runtime
        .broker
        .prepare("main", &config, "/world/status", "goal: status")
        .expect("manifest");
    world
        .runtime
        .broker
        .dispatch("/world/status", &next)
        .expect("dispatch");
    let status = world.dispatch(&support::corpus_status(&session));
    assert_eq!(status["result"]["profile"]["active"], json!("p2"));
    assert_eq!(status["result"]["profile"]["pending"], json!("p2"));
}

/// AC-047: a profile change never replaces draft or task state — the
/// task snapshot, the pending question, and the in-flight manifest all
/// survive the edit byte-for-byte.
#[test]
fn profile_change_does_not_replace_draft_or_task_state() {
    let mut world = support::open_world("profile-draft", Some(&profiled_config()));
    let session = world.open_session("draft-boot");
    let task = world.create_task(&session, "draft-task");

    // a pending decision — the draft state — plus an in-flight manifest
    let published = world.publish(&session, &task);
    let manifest = {
        let config = world.runtime.config_for_broker();
        world
            .runtime
            .broker
            .prepare("main", &config, "/world/draft", "goal: draft")
            .expect("manifest")
    };
    // snapshot after the draft exists: the edit — not the publish —
    // is what must leave the record untouched
    let before = world.runtime.owner.store.snapshot(&task).expect("snapshot");

    let response = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 9003, "method": "command.execute",
        "params": { "schema_version": 1, "session_id": session.0,
                    "command": { "kind": "config.set" },
                    "key": "connections.local.profile", "value": "p2" }
    }));
    assert!(response["error"].is_null(), "{response}");

    let after = world.runtime.owner.store.snapshot(&task).expect("snapshot");
    assert_eq!(after.task_id, before.task_id);
    assert_eq!(
        after.revision, before.revision,
        "the task record is untouched"
    );
    assert_eq!(after.intent_revision, before.intent_revision);
    assert_eq!(after.lifecycle, before.lifecycle);
    let (served, _) = world
        .runtime
        .owner
        .store
        .current_question(&task)
        .expect("question")
        .expect("pending");
    assert_eq!(
        served.question_id, published.question_id,
        "the pending decision is preserved"
    );
    // the frozen manifest still dispatches its own bytes — the edit
    // never reached back into an in-flight request
    world
        .runtime
        .broker
        .dispatch("/world/draft", &manifest)
        .expect("dispatch");
    assert_eq!(world.last_manifest().as_ref(), Some(&manifest));
}

/// DEC-013/AC-047: the additive connection `region`/`profile` keys and
/// the `profiles.<name>.credential_ref` table parse under the same
/// strict schema, reject unknown keys with their own csv, and refuse
/// raw secret material on both carriers — never a silent coercion.
#[test]
fn new_connection_and_profile_keys_are_additive_and_strict_validated() {
    let config = Config::parse_validated(&profiled_config()).expect("the additive keys parse");
    let local = config.connections.get("local").expect("local");
    assert_eq!(local.profile.as_deref(), Some("p1"));
    assert_eq!(local.region, None);
    assert_eq!(
        config
            .profiles
            .get("p1")
            .and_then(|profile| profile.credential_ref.as_deref()),
        Some("keyring:rivect/p1")
    );

    // strict validation holds on the new key domain: an unknown
    // profiles field names its own csv
    let bogus = profiled_config().replace("credential_ref = \"keyring:rivect/p1\"", "bogus = 1");
    let file_error = Config::parse_validated(&bogus).expect_err("unknown profiles key");
    assert!(
        matches!(&file_error.issue, ConfigIssue::UnknownKey { key, .. } if key == "bogus"),
        "wrong rejection: {file_error}"
    );
    // a raw secret is refused before any surface can observe it
    let secret = profiled_config().replace("keyring:rivect/p1", support::SECRET_CANARY);
    let secret_error =
        Config::parse_validated(&secret).expect_err("a raw secret is not a SecretRef");
    assert!(
        matches!(&secret_error.issue, ConfigIssue::SecretRefExpected { .. }),
        "wrong rejection: {secret_error}"
    );
    // a dangling profile reference is the same typed discipline the
    // connection references already enforce
    let dangling = profiled_config().replace("profile = \"p1\"", "profile = \"ghost\"");
    let dangling_error = Config::parse_validated(&dangling).expect_err("dangling profile ref");
    assert!(
        matches!(&dangling_error.issue, ConfigIssue::UnknownProfileReference { profile } if profile == "ghost"),
        "wrong rejection: {dangling_error}"
    );

    // a connection credential_ref carries the same scoped-secret shape
    // as a profile ref — a bare token is refused before any surface can
    // observe it, and the diagnostic names the key, never the value
    let unscoped = profiled_config().replace(
        "kind = \"local\"\nendpoint = \"http://127.0.0.1:11434\"\nprofile = \"p1\"",
        "kind = \"api_key\"\nendpoint = \"https://api.example.invalid/v1\"\ncredential_ref = \"not a scoped ref\"",
    );
    let unscoped_error = Config::parse_validated(&unscoped).expect_err("unscoped connection ref");
    assert!(
        matches!(&unscoped_error.issue, ConfigIssue::SecretRefExpected { key } if key == "connections.local.credential_ref"),
        "wrong rejection: {unscoped_error}"
    );
    assert!(
        !format!("{unscoped_error}").contains("not a scoped ref"),
        "the diagnostic never echoes the refused value"
    );
    // a local connection carries no credentials at all — even a
    // well-formed ref is refused
    let local_ref = profiled_config().replace(
        "profile = \"p1\"",
        "credential_ref = \"keyring:rivect/local\"",
    );
    let local_error = Config::parse_validated(&local_ref).expect_err("local credential ref");
    assert!(
        matches!(&local_error.issue, ConfigIssue::LocalCredentialsForbidden),
        "wrong rejection: {local_error}"
    );
    // and an api_key connection cannot omit its ref
    let missing_ref = profiled_config().replace(
        "kind = \"local\"\nendpoint = \"http://127.0.0.1:11434\"\nprofile = \"p1\"",
        "kind = \"api_key\"\nendpoint = \"https://api.example.invalid/v1\"",
    );
    let missing_error = Config::parse_validated(&missing_ref).expect_err("api_key needs a ref");
    assert!(
        matches!(&missing_error.issue, ConfigIssue::CredentialRefRequired { kind } if *kind == ConnKind::ApiKey),
        "wrong rejection: {missing_error}"
    );

    // set/unset/read on the new keys run the same typed path
    let mut config = Config::parse_validated(&profiled_config()).expect("valid");
    config
        .set(
            "connections.local.profile",
            ConfigValue::Text("p2".to_string()),
        )
        .expect("typed edit");
    assert_eq!(config.connections["local"].profile.as_deref(), Some("p2"));
    config
        .reset("connections.local.profile")
        .expect("override removes");
    assert_eq!(config.connections["local"].profile, None);
    config
        .set(
            "connections.local.region",
            ConfigValue::Text("eu-west-1".to_string()),
        )
        .expect("region edit");
    assert_eq!(
        config.connections["local"].region.as_deref(),
        Some("eu-west-1")
    );
    config
        .set(
            "profiles.p3.credential_ref",
            ConfigValue::Text("keyring:rivect/p3".to_string()),
        )
        .expect("a new profile is additive");
    assert_eq!(
        config.profiles["p3"].credential_ref.as_deref(),
        Some("keyring:rivect/p3")
    );
    // read domain: the new keys answer, unknowns stay out
    assert_eq!(
        config.read_value("connections.local.region"),
        Some(json!("eu-west-1"))
    );
    assert_eq!(
        config.read_value("connections.local.profile"),
        Some(json!(null))
    );
    assert_eq!(
        config.read_value("profiles.p3.credential_ref"),
        Some(json!("keyring:rivect/p3"))
    );
    assert_eq!(config.read_value("bogus.key"), None);

    // the wire surface speaks the same schema
    config
        .set_wire("connections.local.profile", &json!("p1"))
        .expect("wire edit");
    let wire_error = config
        .set_wire("profiles.p3.credential_ref", &json!(support::SECRET_CANARY))
        .expect_err("a wire secret is refused");
    assert!(
        matches!(&wire_error.issue, ConfigIssue::SecretRefExpected { .. }),
        "{wire_error}"
    );
    assert_eq!(
        config.profiles["p3"].credential_ref.as_deref(),
        Some("keyring:rivect/p3"),
        "the refused write left nothing"
    );
    // the shipped defaults document the complete commented profile
    // block — the connection header, region, profile binding, profile
    // table, and its scoped credential_ref — and nothing ships live
    let shipped = rivect::config::SHIPPED_DEFAULTS_TOML;
    assert!(
        shipped.contains(
            "# [connections.<id>]\n\
             # region = \"us-east-1\"\n\
             # profile = \"default\"\n\
             # [profiles.<name>]\n\
             # credential_ref = \"keyring:rivect/default\"\n"
        ),
        "the complete commented profile block ships verbatim"
    );
    for line in shipped.lines() {
        let trimmed = line.trim_start();
        let profile_key = ["region", "profile", "credential_ref"]
            .iter()
            .any(|key| trimmed.starts_with(key));
        assert!(
            !(profile_key && !trimmed.starts_with('#')),
            "a profile key shipped live: {line}"
        );
    }
}

/// DEC-014: `config.read` serves the additive profile keys over the wire —
/// one entry per requested key in request order, each carrying the
/// retained document's source attribution, and the revision an accepted
/// edit reported is the revision the entries name.
#[test]
fn config_read_serves_the_profile_keys_with_source_attribution() {
    let mut world = support::open_world("read-profile-keys", Some(&profiled_config()));
    let session = world.open_session("read-profile-boot");

    // set a region first so the served value is observable, not null
    let set = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 7330, "method": "command.execute",
        "params": { "schema_version": 1, "session_id": session.0,
                    "command": { "kind": "config.set" },
                    "key": "connections.local.region", "value": "eu-west-1" }
    }));
    assert!(set["error"].is_null(), "{set}");

    let read = world.dispatch(&json!({
        "jsonrpc": "2.0", "id": 7331, "method": "config.read",
        "params": { "schema_version": 1, "session_id": session.0,
                    "keys": ["connections.local.region", "profiles.p1.credential_ref"] }
    }));
    assert!(read["error"].is_null(), "{read}");
    let items = read["result"]["entries"]["items"]
        .as_array()
        .expect("one entry per key");
    assert_eq!(items.len(), 2, "{read}");

    let region = &items[0];
    assert_eq!(region["key"], "connections.local.region", "{region}");
    assert_eq!(region["effective"]["value"], json!("eu-west-1"), "{region}");
    assert_eq!(region["source"]["kind"], "user", "{region}");
    assert_eq!(
        region["source"]["revision"], set["result"]["digest"],
        "the entry names the retained document's revision: {region}"
    );

    let profile = &items[1];
    assert_eq!(profile["key"], "profiles.p1.credential_ref", "{profile}");
    assert_eq!(
        profile["effective"]["value"],
        json!("keyring:rivect/p1"),
        "{profile}"
    );
    assert_eq!(profile["source"]["kind"], "user", "{profile}");
    assert_eq!(
        profile["source"]["revision"], set["result"]["digest"],
        "{profile}"
    );
}
