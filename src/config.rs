//! Configuration owner: single schema, typed TOML validation, purpose
//! resolution and the public ConfigEntry projection (architecture «Taskless
//! config»). Parser is `toml_edit` so later slices keep comment-preserving
//! edits; `parse` is syntax-only (duplicate keys are parser errors), every
//! typed/semantic rejection happens in `validate` and fails closed.

use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use toml_edit::{DocumentMut, Item, TableLike, TomlError};

pub const WORKFLOW_KEY: &str = "workflow.enabled";

pub const SHIPPED_DEFAULTS_TOML: &str = "config_version = 1\n[workflow]\nenabled = true\n[models.defaults]\nmodel = { mode = \"auto\" }\neffort = { mode = \"auto\" }\nfallback = { mode = \"auto\" }\n";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Parse,
    Schema,
    Resolve,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ConfigError {
    pub stage: Stage,
    pub key: Option<String>,
    pub message: String,
}

impl ConfigError {
    fn parse(message: impl Into<String>) -> Self {
        Self {
            stage: Stage::Parse,
            key: None,
            message: message.into(),
        }
    }

    fn schema(key: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            stage: Stage::Schema,
            key: Some(key.into()),
            message: message.into(),
        }
    }

    fn resolve(key: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            stage: Stage::Resolve,
            key: Some(key.into()),
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.key {
            Some(key) => write!(f, "{:?} {}: {}", self.stage, key, self.message),
            None => write!(f, "{:?}: {}", self.stage, self.message),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnKind {
    ApiKey,
    Local,
    Subscription,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Connection {
    pub kind: ConnKind,
    pub endpoint: String,
    pub credential_ref: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffortLevel {
    Minimal,
    Low,
    Medium,
    High,
    Xhigh,
}

impl EffortLevel {
    fn parse(raw: &str) -> Option<Self> {
        match raw {
            "minimal" => Some(Self::Minimal),
            "low" => Some(Self::Low),
            "medium" => Some(Self::Medium),
            "high" => Some(Self::High),
            "xhigh" => Some(Self::Xhigh),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixedModel {
    pub connection: String,
    pub model_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModelAssign {
    Inherit,
    Auto { pool: Option<Vec<String>> },
    Fixed(FixedModel),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EffortAssign {
    Inherit,
    Auto,
    Fixed { value: EffortLevel },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FallbackAssign {
    Auto { chain: Vec<FixedModel> },
    Manual,
    Off,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Defaults {
    pub model: ModelAssign,
    pub effort: EffortAssign,
    pub fallback: FallbackAssign,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GroupDef {
    pub model: ModelAssign,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct PurposeDef {
    pub group: Option<String>,
    pub model: Option<ModelAssign>,
    pub effort: Option<EffortAssign>,
    pub fallback: Option<FallbackAssign>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Models {
    pub defaults: Option<Defaults>,
    pub groups: BTreeMap<String, GroupDef>,
    pub purposes: BTreeMap<String, PurposeDef>,
}

#[derive(Debug, Clone, Default)]
pub struct Config {
    pub version: u64,
    pub connections: BTreeMap<String, Connection>,
    pub models: Models,
    raw: Option<DocumentMut>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedPurpose {
    pub model: ModelAssign,
    pub model_source: String,
    pub effort: EffortAssign,
    pub effort_source: String,
    pub fallback: FallbackAssign,
    pub fallback_source: String,
}

impl Config {
    /// Syntax stage only: `toml_edit` rejects malformed TOML and duplicate
    /// keys here. Typed and semantic rejections wait for `validate`.
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let doc: DocumentMut = text
            .parse()
            .map_err(|err: TomlError| ConfigError::parse(err.message().to_string()))?;
        Ok(Self {
            raw: Some(doc),
            ..Self::default()
        })
    }

    /// Typed/schema stage: unknown keys, missing typed fields, unsupported
    /// modes, inline credentials and broken references are all rejected
    /// here, populating the typed view.
    pub fn validate(&mut self) -> Result<(), ConfigError> {
        let Some(doc) = self.raw.take() else {
            return Ok(());
        };
        let mut version: Option<u64> = None;
        let mut connections = BTreeMap::new();
        let mut models = Models::default();
        for (key, item) in doc.iter() {
            match key {
                "config_version" => {
                    let value = item.as_integer().filter(|v| *v >= 0).ok_or_else(|| {
                        ConfigError::schema(
                            "config_version",
                            "config_version must be a non-negative integer",
                        )
                    })?;
                    version = Some(value as u64);
                }
                "connections" => {
                    let table = table_like(key, item)?;
                    for (name, entry) in table.iter() {
                        connections.insert(name.to_string(), connection(name, entry)?);
                    }
                }
                "models" => {
                    let table = table_like(key, item)?;
                    models = models_table(table)?;
                }
                other => {
                    return Err(ConfigError::schema(
                        other,
                        format!("unknown root key {other}"),
                    ));
                }
            }
        }
        let version = version
            .ok_or_else(|| ConfigError::schema("config_version", "config_version is required"))?;
        if version != 1 {
            return Err(ConfigError::schema(
                "config_version",
                "unsupported config_version",
            ));
        }
        if connections.is_empty() {
            return Err(ConfigError::schema(
                "connections",
                "at least one connection is required",
            ));
        }
        for (name, connection) in &connections {
            let key = format!("connections.{name}");
            match connection.kind {
                ConnKind::ApiKey | ConnKind::Subscription => {
                    if connection.credential_ref.is_none() {
                        return Err(ConfigError::schema(
                            format!("{key}.credential_ref"),
                            format!("{:?} connection requires credential_ref", connection.kind),
                        ));
                    }
                }
                ConnKind::Local => {
                    if connection.credential_ref.is_some() {
                        return Err(ConfigError::schema(
                            format!("{key}.credential_ref"),
                            "local connection must not carry credentials",
                        ));
                    }
                }
            }
        }
        let Some(defaults) = &models.defaults else {
            return Err(ConfigError::schema(
                "models.defaults",
                "models.defaults is required",
            ));
        };
        check_model_refs(&connections, &defaults.model, "models.defaults.model")?;
        for (name, group) in &models.groups {
            check_model_refs(
                &connections,
                &group.model,
                &format!("models.groups.{name}.model"),
            )?;
        }
        for (name, purpose) in &models.purposes {
            let key = format!("models.purposes.{name}");
            if let Some(group) = &purpose.group
                && !models.groups.contains_key(group)
            {
                return Err(ConfigError::schema(
                    format!("{key}.group"),
                    format!("unknown group reference: models.groups.{group}"),
                ));
            }
            if let Some(model) = &purpose.model {
                check_model_refs(&connections, model, &format!("{key}.model"))?;
            }
            if let Some(FallbackAssign::Auto { chain }) = &purpose.fallback {
                for entry in chain {
                    if !connections.contains_key(&entry.connection) {
                        return Err(ConfigError::schema(
                            format!("{key}.fallback.chain"),
                            format!(
                                "unknown connection reference: connections.{}",
                                entry.connection
                            ),
                        ));
                    }
                }
            }
        }
        self.version = version;
        self.connections = connections;
        self.models = models;
        Ok(())
    }

    pub fn parse_validated(text: &str) -> Result<Self, ConfigError> {
        let mut config = Self::parse(text)?;
        config.validate()?;
        Ok(config)
    }

    /// Assignment precedence: exact purpose override, then the single
    /// explicitly bound group, then defaults. Explicit `inherit` resolves
    /// through to the outer layer.
    pub fn resolve_purpose(&self, purpose: &str) -> Result<ResolvedPurpose, ConfigError> {
        let defaults = self.models.defaults.as_ref().ok_or_else(|| {
            ConfigError::resolve("models.defaults", "models.defaults is required")
        })?;
        let def = self.models.purposes.get(purpose);
        let (model, model_source) = match def.and_then(|d| d.model.clone()) {
            Some(model @ (ModelAssign::Auto { .. } | ModelAssign::Fixed(_))) => {
                (model, format!("models.purposes.{purpose}"))
            }
            _ => match def.and_then(|d| d.group.clone()) {
                Some(group) => {
                    let group_def = self.models.groups.get(&group).ok_or_else(|| {
                        ConfigError::resolve(
                            format!("models.purposes.{purpose}.group"),
                            format!("unknown group reference: models.groups.{group}"),
                        )
                    })?;
                    (group_def.model.clone(), format!("models.groups.{group}"))
                }
                None => (defaults.model.clone(), "models.defaults".to_string()),
            },
        };
        let (effort, effort_source) = match def.and_then(|d| d.effort.clone()) {
            Some(effort @ (EffortAssign::Auto | EffortAssign::Fixed { .. })) => {
                (effort, format!("models.purposes.{purpose}"))
            }
            _ => (defaults.effort.clone(), "models.defaults".to_string()),
        };
        let (fallback, fallback_source) = match def.and_then(|d| d.fallback.clone()) {
            Some(fallback) => (fallback, format!("models.purposes.{purpose}")),
            None => (defaults.fallback.clone(), "models.defaults".to_string()),
        };
        Ok(ResolvedPurpose {
            model,
            model_source,
            effort,
            effort_source,
            fallback,
            fallback_source,
        })
    }

    /// Source merge of purpose bindings: identical replay is accepted, two
    /// admitted definitions with different bindings conflict (this is not a
    /// TOML duplicate key).
    pub fn merge_purposes(&mut self, other: &Config) -> Result<(), ConfigError> {
        for (name, def) in &other.models.purposes {
            if let Some(existing) = self.models.purposes.get(name) {
                if existing != def {
                    return Err(ConfigError::resolve(
                        format!("models.purposes.{name}"),
                        "conflicting definitions for one purpose",
                    ));
                }
            } else {
                self.models.purposes.insert(name.clone(), def.clone());
            }
        }
        Ok(())
    }
}

fn table_like<'a>(key: &str, item: &'a Item) -> Result<&'a dyn TableLike, ConfigError> {
    item.as_table_like()
        .ok_or_else(|| ConfigError::schema(key, format!("{key} must be a table")))
}

fn string_field(
    table: &dyn TableLike,
    table_key: &str,
    field: &str,
) -> Result<Option<String>, ConfigError> {
    match table.get(field) {
        None => Ok(None),
        Some(item) => Ok(Some(item.as_str().map(str::to_string).ok_or_else(
            || {
                ConfigError::schema(
                    format!("{table_key}.{field}"),
                    format!("{field} must be a string"),
                )
            },
        )?)),
    }
}

fn connection(name: &str, item: &Item) -> Result<Connection, ConfigError> {
    let table = table_like(name, item)?;
    let key = format!("connections.{name}");
    let kind_raw = string_field(table, &key, "kind")?
        .ok_or_else(|| ConfigError::schema(format!("{key}.kind"), "kind is required"))?;
    let kind = match kind_raw.as_str() {
        "api_key" => ConnKind::ApiKey,
        "local" => ConnKind::Local,
        "subscription" => ConnKind::Subscription,
        other => {
            return Err(ConfigError::schema(
                format!("{key}.kind"),
                format!("unsupported connection kind {other}"),
            ));
        }
    };
    let endpoint = string_field(table, &key, "endpoint")?
        .ok_or_else(|| ConfigError::schema(format!("{key}.endpoint"), "endpoint is required"))?;
    let credential_ref = string_field(table, &key, "credential_ref")?;
    for field in table.iter().map(|(field, _)| field) {
        match field {
            "kind" | "endpoint" | "credential_ref" => {}
            "api_key" | "secret" | "token" | "password" => {
                // Never echo the value: diagnostics stay secret-free.
                return Err(ConfigError::schema(
                    format!("{key}.{field}"),
                    "inline credential values are rejected; use credential_ref",
                ));
            }
            other => {
                return Err(ConfigError::schema(
                    format!("{key}.{other}"),
                    format!("unknown key {other}"),
                ));
            }
        }
    }
    Ok(Connection {
        kind,
        endpoint,
        credential_ref,
    })
}

fn models_table(table: &dyn TableLike) -> Result<Models, ConfigError> {
    let mut models = Models::default();
    for (key, item) in table.iter() {
        match key {
            "defaults" => {
                let defaults = table_like("models.defaults", item)?;
                for field in defaults.iter().map(|(field, _)| field) {
                    if !matches!(field, "model" | "effort" | "fallback") {
                        return Err(ConfigError::schema(
                            format!("models.defaults.{field}"),
                            format!("unknown key {field}"),
                        ));
                    }
                }
                models.defaults = Some(Defaults {
                    model: model_assign(pick(defaults, "model")?, "models.defaults.model")?,
                    effort: effort_assign(pick(defaults, "effort")?, "models.defaults.effort")?,
                    fallback: fallback_assign(
                        pick(defaults, "fallback")?,
                        "models.defaults.fallback",
                    )?,
                });
            }
            "groups" => {
                let groups = table_like("models.groups", item)?;
                for (name, entry) in groups.iter() {
                    let group = table_like(name, entry)?;
                    for field in group.iter().map(|(field, _)| field) {
                        if field != "model" {
                            return Err(ConfigError::schema(
                                format!("models.groups.{name}.{field}"),
                                format!("unknown key {field}"),
                            ));
                        }
                    }
                    models.groups.insert(
                        name.to_string(),
                        GroupDef {
                            model: model_assign(
                                pick(group, "model")?,
                                &format!("models.groups.{name}.model"),
                            )?,
                        },
                    );
                }
            }
            "purposes" => {
                let purposes = table_like("models.purposes", item)?;
                for (name, entry) in purposes.iter() {
                    let purpose = table_like(name, entry)?;
                    let key = format!("models.purposes.{name}");
                    let mut def = PurposeDef::default();
                    for (field, value) in purpose.iter() {
                        match field {
                            "group" => {
                                def.group =
                                    Some(value.as_str().map(str::to_string).ok_or_else(|| {
                                        ConfigError::schema(
                                            format!("{key}.group"),
                                            "group must be a single string reference",
                                        )
                                    })?);
                            }
                            "model" => {
                                def.model = Some(model_assign(value, &format!("{key}.model"))?)
                            }
                            "effort" => {
                                def.effort = Some(effort_assign(value, &format!("{key}.effort"))?)
                            }
                            "fallback" => {
                                def.fallback =
                                    Some(fallback_assign(value, &format!("{key}.fallback"))?)
                            }
                            other => {
                                return Err(ConfigError::schema(
                                    format!("{key}.{other}"),
                                    format!("unknown key {other}"),
                                ));
                            }
                        }
                    }
                    models.purposes.insert(name.to_string(), def);
                }
            }
            other => {
                return Err(ConfigError::schema(
                    "models",
                    format!("unknown key {other}"),
                ));
            }
        }
    }
    Ok(models)
}

fn pick<'a>(table: &'a dyn TableLike, field: &str) -> Result<&'a Item, ConfigError> {
    table
        .get(field)
        .ok_or_else(|| ConfigError::schema(field, format!("{field} is required")))
}

fn model_assign(item: &Item, key: &str) -> Result<ModelAssign, ConfigError> {
    let table = item
        .as_table_like()
        .ok_or_else(|| ConfigError::schema(key, format!("{key} must be a table")))?;
    let Some(mode) = table.get("mode").and_then(Item::as_str) else {
        return Err(ConfigError::schema(
            format!("{key}.mode"),
            "mode is required",
        ));
    };
    match mode {
        "inherit" => Ok(ModelAssign::Inherit),
        "auto" => {
            let pool = match table.get("pool") {
                None => None,
                Some(value) => {
                    let items = value.as_array().ok_or_else(|| {
                        ConfigError::schema(
                            format!("{key}.pool"),
                            "pool must be an array of connection names",
                        )
                    })?;
                    let mut names = Vec::new();
                    for entry in items {
                        names.push(entry.as_str().map(str::to_string).ok_or_else(|| {
                            ConfigError::schema(
                                format!("{key}.pool"),
                                "pool entries must be strings",
                            )
                        })?);
                    }
                    Some(names)
                }
            };
            Ok(ModelAssign::Auto { pool })
        }
        "fixed" => {
            let connection = table
                .get("connection")
                .and_then(Item::as_str)
                .ok_or_else(|| {
                    ConfigError::schema(
                        format!("{key}.connection"),
                        "fixed model requires connection",
                    )
                })?
                .to_string();
            let model_id = table
                .get("model_id")
                .and_then(Item::as_str)
                .ok_or_else(|| {
                    ConfigError::schema(format!("{key}.model_id"), "fixed model requires model_id")
                })?
                .to_string();
            Ok(ModelAssign::Fixed(FixedModel {
                connection,
                model_id,
            }))
        }
        other => Err(ConfigError::schema(
            format!("{key}.mode"),
            format!("unsupported model mode {other}"),
        )),
    }
}

fn effort_assign(item: &Item, key: &str) -> Result<EffortAssign, ConfigError> {
    let table = item
        .as_table_like()
        .ok_or_else(|| ConfigError::schema(key, format!("{key} must be a table")))?;
    let Some(mode) = table.get("mode").and_then(Item::as_str) else {
        return Err(ConfigError::schema(
            format!("{key}.mode"),
            "mode is required",
        ));
    };
    match mode {
        "inherit" => Ok(EffortAssign::Inherit),
        "auto" => Ok(EffortAssign::Auto),
        "fixed" => {
            let raw = table.get("value").and_then(Item::as_str).ok_or_else(|| {
                ConfigError::schema(format!("{key}.value"), "fixed effort requires value")
            })?;
            let value = EffortLevel::parse(raw).ok_or_else(|| {
                ConfigError::schema(
                    format!("{key}.value"),
                    format!("unsupported effort value {raw}"),
                )
            })?;
            Ok(EffortAssign::Fixed { value })
        }
        other => Err(ConfigError::schema(
            format!("{key}.mode"),
            format!("unsupported effort mode {other}"),
        )),
    }
}

fn fallback_assign(item: &Item, key: &str) -> Result<FallbackAssign, ConfigError> {
    let table = item
        .as_table_like()
        .ok_or_else(|| ConfigError::schema(key, format!("{key} must be a table")))?;
    let Some(mode) = table.get("mode").and_then(Item::as_str) else {
        return Err(ConfigError::schema(
            format!("{key}.mode"),
            "mode is required",
        ));
    };
    match mode {
        "auto" => {
            let chain = match table.get("chain") {
                None => Vec::new(),
                Some(value) => {
                    let items = value.as_array().ok_or_else(|| {
                        ConfigError::schema(
                            format!("{key}.chain"),
                            "chain must be an array of fixed models",
                        )
                    })?;
                    let mut chain = Vec::new();
                    for entry in items {
                        let inline = entry.as_inline_table().ok_or_else(|| {
                            ConfigError::schema(
                                format!("{key}.chain"),
                                "chain entries must be tables",
                            )
                        })?;
                        let connection = inline
                            .get("connection")
                            .and_then(toml_edit::Value::as_str)
                            .ok_or_else(|| {
                                ConfigError::schema(
                                    format!("{key}.chain.connection"),
                                    "fixed chain entry requires connection",
                                )
                            })?
                            .to_string();
                        let model_id = inline
                            .get("model_id")
                            .and_then(toml_edit::Value::as_str)
                            .ok_or_else(|| {
                                ConfigError::schema(
                                    format!("{key}.chain.model_id"),
                                    "fixed chain entry requires model_id",
                                )
                            })?
                            .to_string();
                        chain.push(FixedModel {
                            connection,
                            model_id,
                        });
                    }
                    chain
                }
            };
            Ok(FallbackAssign::Auto { chain })
        }
        "manual" => Ok(FallbackAssign::Manual),
        "off" => Ok(FallbackAssign::Off),
        other => Err(ConfigError::schema(
            format!("{key}.mode"),
            format!("unsupported fallback mode {other}"),
        )),
    }
}

fn check_model_refs(
    connections: &BTreeMap<String, Connection>,
    model: &ModelAssign,
    key: &str,
) -> Result<(), ConfigError> {
    let referenced: Vec<&str> = match model {
        ModelAssign::Fixed(fixed) => vec![fixed.connection.as_str()],
        ModelAssign::Auto { pool: Some(pool) } => pool.iter().map(String::as_str).collect(),
        _ => Vec::new(),
    };
    for name in referenced {
        if !connections.contains_key(name) {
            return Err(ConfigError::schema(
                key,
                format!("unknown connection reference: connections.{name}"),
            ));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ConfigViewValue {
    Visible { value: Value },
    Redacted,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ConfigSource {
    pub kind: String,
    pub revision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ConfigEntry {
    pub key: String,
    pub effective: ConfigViewValue,
    pub source: ConfigSource,
}

/// Effective snapshot over the two precedence passes that exist today:
/// shipped defaults, then the user file.
#[derive(Debug, Clone)]
pub struct EffectiveConfig {
    pub sources_digest: String,
    pub parsed: Option<Config>,
    pub workflow_entry: ConfigEntry,
}

pub fn resolve_effective(user_toml: Option<&str>) -> Result<EffectiveConfig, ConfigError> {
    if let Some(text) = user_toml {
        Config::parse_validated(text)?;
    }
    let mut hasher = Sha256::new();
    hasher.update(SHIPPED_DEFAULTS_TOML.as_bytes());
    hasher.update(user_toml.unwrap_or("").as_bytes());
    let sources_digest = hex(&hasher.finalize());
    let shipped_revision = hex(&Sha256::digest(SHIPPED_DEFAULTS_TOML.as_bytes()));
    Ok(EffectiveConfig {
        sources_digest,
        parsed: user_toml.and_then(|text| Config::parse_validated(text).ok()),
        workflow_entry: ConfigEntry {
            key: WORKFLOW_KEY.to_string(),
            effective: ConfigViewValue::Visible {
                value: Value::Bool(true),
            },
            source: ConfigSource {
                kind: "shipped".to_string(),
                revision: shipped_revision,
                target: None,
            },
        },
    })
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
