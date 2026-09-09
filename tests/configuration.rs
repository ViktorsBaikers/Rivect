//! SLICE-001 configuration proof (TP-ADMISSION-PACKET 5a): 8 named
//! positives, 6 stage-correct negatives, 6 group controls through the
//! production `src/config.rs` schema and resolver.

mod support;

use rivect::config::{Config, ConfigError, EffortAssign, ModelAssign, Stage};

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
    assert_eq!(primary.kind, rivect::config::ConnKind::ApiKey);
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

#[test]
fn explicit_chain() {
    let config = Config::parse_validated(&support::config_explicit_chain()).expect("valid");
    let resolved = resolve_or_panic(&config, "planner");
    let rivect::config::FallbackAssign::Auto { chain } = &resolved.fallback else {
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
    assert_eq!(subscription.kind, rivect::config::ConnKind::Subscription);
    let resolved = resolve_or_panic(&config, "main");
    assert!(
        matches!(&resolved.model, ModelAssign::Fixed(fixed) if fixed.connection == "subscription")
    );
    assert_eq!(resolved.fallback, rivect::config::FallbackAssign::Manual);
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
        err.key.clone().unwrap_or_default().contains("model_id"),
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
        err.key.clone().unwrap_or_default().contains("effort"),
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
    assert!(err.message.contains("unknown key"), "{err}");
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
    assert!(err.message.contains("fallback mode"), "{err}");
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
    assert!(err.message.contains("credential"), "{err}");
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
    assert!(err.message.contains("missing"), "{err}");
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
    assert!(err.message.contains("single string reference"), "{err}");
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
        err.key.clone().unwrap_or_default().contains("backend_task"),
        "{err}"
    );
    // identical replay merges fine and is not a conflict
    let same = Config::parse_validated(&support::config_distinct_pools()).expect("valid");
    merged
        .merge_purposes(&same)
        .expect("identical binding replays without conflict");
}
