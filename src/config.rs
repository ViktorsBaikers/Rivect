//! Configuration owner: single schema, typed TOML validation, purpose
//! resolution and the public ConfigEntry projection (architecture «Taskless
//! config»). Parser is `toml_edit` so later slices keep comment-preserving
//! edits; `parse` is syntax-only (duplicate keys are parser errors), every
//! typed/semantic rejection happens in `validate` and fails closed.

use crate::state::{StoreError, TaskStore};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use toml_edit::{Array, DocumentMut, InlineTable, Item, Table, TableLike, TomlError};

pub const WORKFLOW_KEY: &str = "workflow.enabled";

pub const SHIPPED_DEFAULTS_TOML: &str = "config_version = 1\n[workflow]\nenabled = true\n[models.defaults]\nmodel = { mode = \"auto\" }\neffort = { mode = \"auto\" }\nfallback = { mode = \"auto\" }\n";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Parse,
    Schema,
    Resolve,
}

impl std::fmt::Display for Stage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Parse => "parse",
            Self::Schema => "schema",
            Self::Resolve => "resolve",
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigIssue {
    #[error("invalid TOML: {message}")]
    Parser { message: String },
    #[error("config_version must be a non-negative integer")]
    ConfigVersionNotNonNegativeInteger,
    #[error("key {key} is not editable")]
    KeyNotEditable { key: String },
    #[error("malformed key {key}: empty segment")]
    EmptyKeySegment { key: String },
    #[error("unknown root key {key}")]
    UnknownRootKey { key: String },
    #[error("{field} is required")]
    Required { field: String },
    #[error("unsupported config_version")]
    UnsupportedConfigVersion,
    #[error("at least one connection is required")]
    MissingConnections,
    #[error("{kind} connection requires credential_ref")]
    CredentialRefRequired { kind: ConnKind },
    #[error("local connection must not carry credentials")]
    LocalCredentialsForbidden,
    #[error("unknown group reference: models.groups.{group}")]
    UnknownGroupReference { group: String },
    #[error("unknown connection reference: connections.{connection}")]
    UnknownConnectionReference { connection: String },
    #[error("conflicting definitions for one purpose")]
    ConflictingPurposeDefinitions,
    #[error("{key} must be a table")]
    ExpectedTable { key: String },
    #[error("{field} must be a string")]
    ExpectedString { field: String },
    #[error("unsupported connection kind {kind}")]
    UnsupportedConnectionKind { kind: String },
    #[error("inline credential values are rejected; use credential_ref")]
    InlineCredential,
    #[error("unknown key {key}; known keys: {}", .known.join(", "))]
    UnknownKey {
        key: String,
        known: &'static [&'static str],
    },
    #[error("group must be a single string reference")]
    GroupReferenceNotString,
    #[error("pool must be an array of connection names")]
    PoolNotArray,
    #[error("pool entries must be strings")]
    PoolEntryNotString,
    #[error("eligible must be an array of connection names")]
    EligibleNotArray,
    #[error("eligible entries must be strings")]
    EligibleEntryNotString,
    #[error("fixed model requires connection")]
    FixedModelMissingConnection,
    #[error("fixed model requires model_id")]
    FixedModelMissingId,
    #[error("unsupported model mode {mode}")]
    UnsupportedModelMode { mode: String },
    #[error("fixed effort requires value")]
    FixedEffortMissingValue,
    #[error("unsupported effort value {value}")]
    UnsupportedEffortValue { value: String },
    #[error("unsupported effort mode {mode}")]
    UnsupportedEffortMode { mode: String },
    #[error("chain must be an array of fixed models")]
    ChainNotArray,
    #[error("chain entries must be tables")]
    ChainEntryNotTable,
    #[error("fixed chain entry requires connection")]
    FixedChainEntryMissingConnection,
    #[error("fixed chain entry requires model_id")]
    FixedChainEntryMissingModelId,
    #[error("unsupported fallback mode {mode}")]
    UnsupportedFallbackMode { mode: String },
    #[error("workflow.enabled must be a boolean")]
    WorkflowEnabledNotBoolean,
    #[error("{key} is required, not an override; reset removes overrides only")]
    RequiredNotResettable { key: String },
    #[error("no configuration document is retained; parse one before editing")]
    NoRetainedDocument,
    #[error("value type does not match {key}")]
    ValueTypeMismatch { key: String },
}

#[derive(Debug)]
pub struct ConfigError {
    pub stage: Stage,
    pub key: Option<String>,
    pub issue: ConfigIssue,
}

impl ConfigError {
    fn parse(source: TomlError) -> Self {
        Self {
            stage: Stage::Parse,
            key: None,
            issue: ConfigIssue::Parser {
                message: source.message().to_string(),
            },
        }
    }

    fn schema(key: impl Into<String>, issue: ConfigIssue) -> Self {
        Self {
            stage: Stage::Schema,
            key: Some(key.into()),
            issue,
        }
    }

    fn resolve(key: impl Into<String>, issue: ConfigIssue) -> Self {
        Self {
            stage: Stage::Resolve,
            key: Some(key.into()),
            issue,
        }
    }
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.key {
            Some(key) => write!(f, "{} {key}: {}", self.stage, self.issue),
            None => write!(f, "{}: {}", self.stage, self.issue),
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.issue)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnKind {
    ApiKey,
    Local,
    Subscription,
}

impl std::fmt::Display for ConnKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::ApiKey => "api_key",
            Self::Local => "local",
            Self::Subscription => "subscription",
        })
    }
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
    /// File-only auto-selection pool (DEC-012): the `config.set`
    /// surface answers `KeyNotEditable` for it.
    pub pool: Option<Vec<String>>,
    /// Per-purpose eligibility input (DEC-012), editable through
    /// `config.set`.
    pub eligible: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Models {
    pub defaults: Option<Defaults>,
    pub groups: BTreeMap<String, GroupDef>,
    pub purposes: BTreeMap<String, PurposeDef>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Workflow {
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Default)]
pub struct Config {
    pub version: u64,
    pub workflow: Workflow,
    pub connections: BTreeMap<String, Connection>,
    pub models: Models,
    raw: Option<DocumentMut>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ConfigValue {
    Bool(bool),
    Model(ModelAssign),
    Effort(EffortAssign),
    Fallback(FallbackAssign),
    Names(Vec<String>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigEdit {
    pub bytes: Vec<u8>,
    pub digest: String,
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
        let doc: DocumentMut = text.parse().map_err(ConfigError::parse)?;
        Ok(Self {
            raw: Some(doc),
            ..Self::default()
        })
    }

    /// Typed/schema stage: unknown keys, missing typed fields, unsupported
    /// modes, inline credentials and broken references are all rejected
    /// here, populating the typed view.
    pub fn validate(&mut self) -> Result<(), ConfigError> {
        let Some(doc) = self.raw.as_ref() else {
            return Ok(());
        };
        let (version, workflow, connections, models) = validated_document(doc)?;
        self.version = version;
        self.workflow = workflow;
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
            ConfigError::resolve(
                "models.defaults",
                ConfigIssue::Required {
                    field: "models.defaults".to_string(),
                },
            )
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
                            ConfigIssue::UnknownGroupReference {
                                group: group.clone(),
                            },
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
                        ConfigIssue::ConflictingPurposeDefinitions,
                    ));
                }
            } else {
                self.models.purposes.insert(name.clone(), def.clone());
            }
        }
        Ok(())
    }

    pub fn set(&mut self, key: &str, value: ConfigValue) -> Result<ConfigEdit, ConfigError> {
        let target = edit_target(key)?;
        let item = match value {
            ConfigValue::Bool(enabled) => {
                if !matches!(&target, EditTarget::WorkflowEnabled) {
                    return Err(type_mismatch(key));
                }
                toml_edit::value(enabled)
            }
            ConfigValue::Model(model) => {
                if !matches!(
                    &target,
                    EditTarget::DefaultsModel
                        | EditTarget::GroupModel(_)
                        | EditTarget::PurposeModel(_)
                ) {
                    return Err(type_mismatch(key));
                }
                model_item(&model)
            }
            ConfigValue::Effort(effort) => {
                if !matches!(
                    &target,
                    EditTarget::DefaultsEffort | EditTarget::PurposeEffort(_)
                ) {
                    return Err(type_mismatch(key));
                }
                effort_item(&effort)
            }
            ConfigValue::Fallback(fallback) => {
                if !matches!(
                    &target,
                    EditTarget::DefaultsFallback | EditTarget::PurposeFallback(_)
                ) {
                    return Err(type_mismatch(key));
                }
                fallback_item(&fallback)
            }
            ConfigValue::Names(names) => {
                if !matches!(&target, EditTarget::PurposeEligible(_)) {
                    return Err(type_mismatch(key));
                }
                let mut array = Array::new();
                for name in &names {
                    array.push(name.clone());
                }
                Item::Value(toml_edit::Value::Array(array))
            }
        };
        let (path, field) = target_path(&target);
        let original = self.raw.clone();
        let edited = self.require_document(key).and_then(|doc| {
            ensure_table_like(doc.as_item_mut(), &path, key)
                .map(|table| set_field(table, field, item))
        });
        self.commit_edit(key, &target, original, edited)
    }

    pub fn reset(&mut self, key: &str) -> Result<ConfigEdit, ConfigError> {
        let target = edit_target(key)?;
        if !target.is_override() {
            return Err(ConfigError::schema(
                key,
                ConfigIssue::RequiredNotResettable {
                    key: key.to_string(),
                },
            ));
        }
        let original = self.raw.clone();
        let edited = self.require_document(key).map(|doc| {
            let mut node = doc.as_item_mut();
            for segment in target_path(&target).0 {
                let Some(next) = node
                    .as_table_like_mut()
                    .and_then(|table| table.get_mut(segment))
                else {
                    return;
                };
                node = next;
            }
            if let Some(table) = node.as_table_like_mut() {
                table.remove(target_path(&target).1);
            }
        });
        self.commit_edit(key, &target, original, edited)
    }

    /// Shared edit tail: the edited document must still validate against
    /// the target — a rejection restores the retained original so no
    /// surface ever observes the refused edit — then the view refreshes
    /// from the accepted document and the edit reports.
    fn commit_edit(
        &mut self,
        key: &str,
        target: &EditTarget,
        original: Option<DocumentMut>,
        edited: Result<(), ConfigError>,
    ) -> Result<ConfigEdit, ConfigError> {
        if let Err(error) = edited.and_then(|_| validate_target(self.raw.as_ref(), target, key)) {
            self.raw = original;
            return Err(error);
        }
        self.refresh_view_if_valid();
        Ok(self.finish_edit())
    }

    fn require_document(&mut self, key: &str) -> Result<&mut DocumentMut, ConfigError> {
        self.raw
            .as_mut()
            .ok_or_else(|| ConfigError::schema(key, ConfigIssue::NoRetainedDocument))
    }

    fn refresh_view_if_valid(&mut self) {
        let Some(doc) = self.raw.as_ref() else {
            return;
        };
        let Ok((version, workflow, connections, models)) = validated_document(doc) else {
            // Targeted edits intentionally remain usable while another path
            // still carries a rejected value; that value is never rewritten.
            return;
        };
        self.version = version;
        self.workflow = workflow;
        self.connections = connections;
        self.models = models;
    }

    fn finish_edit(&self) -> ConfigEdit {
        let bytes = self
            .raw
            .as_ref()
            .map(DocumentMut::to_string)
            .unwrap_or_default()
            .into_bytes();
        let digest = hex(&Sha256::digest(&bytes));
        ConfigEdit { bytes, digest }
    }

    /// Wire admission for `config.set`: maps one JSON value onto the typed
    /// slot the dotted key names, then applies the targeted edit. Only the
    /// targeted path is validated — never the whole document (DEC-013), so
    /// a doc holding a rejected value elsewhere still accepts edits on
    /// unrelated paths.
    pub fn set_wire(&mut self, key: &str, value: &Value) -> Result<ConfigEdit, ConfigError> {
        self.set(key, wire_value(key, value)?)
    }
}

fn validated_document(
    doc: &DocumentMut,
) -> Result<(u64, Workflow, BTreeMap<String, Connection>, Models), ConfigError> {
    let mut version = None;
    let mut workflow = Workflow::default();
    let mut connections = BTreeMap::new();
    let mut models = Models::default();
    for (key, item) in doc.iter() {
        match key {
            "config_version" => {
                let value = item
                    .as_integer()
                    .filter(|value| *value >= 0)
                    .ok_or_else(|| {
                        ConfigError::schema(
                            "config_version",
                            ConfigIssue::ConfigVersionNotNonNegativeInteger,
                        )
                    })?;
                version = Some(value as u64);
            }
            "workflow" => {
                let table = table_like(key, item)?;
                for (field, value) in table.iter() {
                    match field {
                        "enabled" => {
                            workflow.enabled = Some(value.as_bool().ok_or_else(|| {
                                ConfigError::schema(
                                    "workflow.enabled",
                                    ConfigIssue::WorkflowEnabledNotBoolean,
                                )
                            })?);
                        }
                        other => {
                            return Err(ConfigError::schema(
                                format!("workflow.{other}"),
                                ConfigIssue::UnknownKey {
                                    key: other.to_string(),
                                    known: WORKFLOW_KEYS,
                                },
                            ));
                        }
                    }
                }
            }
            "connections" => {
                let table = table_like(key, item)?;
                for (name, entry) in table.iter() {
                    connections.insert(name.to_string(), connection(name, entry)?);
                }
            }
            "models" => {
                models = models_table(table_like(key, item)?)?;
            }
            other => {
                return Err(ConfigError::schema(
                    other,
                    ConfigIssue::UnknownRootKey {
                        key: other.to_string(),
                    },
                ));
            }
        }
    }
    let version = version.ok_or_else(|| {
        ConfigError::schema(
            "config_version",
            ConfigIssue::Required {
                field: "config_version".to_string(),
            },
        )
    })?;
    if version != 1 {
        return Err(ConfigError::schema(
            "config_version",
            ConfigIssue::UnsupportedConfigVersion,
        ));
    }
    if connections.is_empty() {
        return Err(ConfigError::schema(
            "connections",
            ConfigIssue::MissingConnections,
        ));
    }
    for (name, connection) in &connections {
        let key = format!("connections.{name}");
        match connection.kind {
            ConnKind::ApiKey | ConnKind::Subscription => {
                if connection.credential_ref.is_none() {
                    return Err(ConfigError::schema(
                        format!("{key}.credential_ref"),
                        ConfigIssue::CredentialRefRequired {
                            kind: connection.kind,
                        },
                    ));
                }
            }
            ConnKind::Local => {
                if connection.credential_ref.is_some() {
                    return Err(ConfigError::schema(
                        format!("{key}.credential_ref"),
                        ConfigIssue::LocalCredentialsForbidden,
                    ));
                }
            }
        }
    }
    let Some(defaults) = &models.defaults else {
        return Err(ConfigError::schema(
            "models.defaults",
            ConfigIssue::Required {
                field: "models.defaults".to_string(),
            },
        ));
    };
    check_model_refs(&connections, &defaults.model, "models.defaults.model")?;
    check_chain_refs(
        &connections,
        &defaults.fallback,
        "models.defaults.fallback.chain",
    )?;
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
                ConfigIssue::UnknownGroupReference {
                    group: group.clone(),
                },
            ));
        }
        if let Some(model) = &purpose.model {
            check_model_refs(&connections, model, &format!("{key}.model"))?;
        }
        if let Some(fallback) = &purpose.fallback {
            check_chain_refs(&connections, fallback, &format!("{key}.fallback.chain"))?;
        }
    }
    Ok((version, workflow, connections, models))
}

#[derive(Debug)]
enum EditTarget {
    WorkflowEnabled,
    DefaultsModel,
    DefaultsEffort,
    DefaultsFallback,
    GroupModel(String),
    PurposeModel(String),
    PurposeEffort(String),
    PurposeFallback(String),
    PurposeEligible(String),
}

impl EditTarget {
    fn is_override(&self) -> bool {
        !matches!(
            self,
            Self::DefaultsModel
                | Self::DefaultsEffort
                | Self::DefaultsFallback
                | Self::GroupModel(_)
        )
    }
}

fn edit_target(key: &str) -> Result<EditTarget, ConfigError> {
    let segments: Vec<&str> = key.split('.').collect();
    if segments.iter().any(|segment| segment.is_empty()) {
        return Err(unknown_edit_key(key));
    }
    match segments.as_slice() {
        ["workflow", "enabled"] => Ok(EditTarget::WorkflowEnabled),
        ["models", "defaults", "model"] => Ok(EditTarget::DefaultsModel),
        ["models", "defaults", "effort"] => Ok(EditTarget::DefaultsEffort),
        ["models", "defaults", "fallback"] => Ok(EditTarget::DefaultsFallback),
        ["models", "groups", name, "model"] => Ok(EditTarget::GroupModel(name.to_string())),
        ["models", "purposes", name, "model"] => Ok(EditTarget::PurposeModel(name.to_string())),
        ["models", "purposes", name, "effort"] => Ok(EditTarget::PurposeEffort(name.to_string())),
        ["models", "purposes", name, "fallback"] => {
            Ok(EditTarget::PurposeFallback(name.to_string()))
        }
        ["models", "purposes", name, "eligible"] => {
            Ok(EditTarget::PurposeEligible(name.to_string()))
        }
        _ => Err(unknown_edit_key(key)),
    }
}

/// The schema's legal keys per scope, declared once: the file-surface
/// raise sites and the edit-surface scope walk below both name these, so
/// one key earns one hint on both carriers (DEC-017) — never a second,
/// divergent schema.
const WORKFLOW_KEYS: &[&str] = &["enabled"];
const CONNECTION_KEYS: &[&str] = &["kind", "endpoint", "credential_ref"];
const MODELS_KEYS: &[&str] = &["defaults", "groups", "purposes"];
const MODEL_SLOT_KEYS: &[&str] = &["model", "effort", "fallback"];
const GROUP_KEYS: &[&str] = &["model"];
const PURPOSE_KEYS: &[&str] = &["group", "model", "effort", "fallback", "pool", "eligible"];
const CHAIN_ENTRY_KEYS: &[&str] = &["mode", "connection", "model_id"];

fn unknown_edit_key(key: &str) -> ConfigError {
    // Walk the dotted key through the same scope tables the file parsers
    // raise from, so the edit surface names the scope-local csv the file
    // surface emits for the same key. Three total rules: a segment that
    // misses its scope's table is `UnknownKey` carrying that table's csv;
    // a key that spells a legal schema location with no EditTarget — a
    // bare root, a container or name level, a read-only field, or any
    // descent below a slot assignment, whose table the file surface
    // accepts permissively so no csv exists to mirror — is
    // `KeyNotEditable`: the file surface accepts its spelling, so it is
    // never "unknown"; and a key with an empty segment cannot be walked,
    // so it is diagnosed malformed while still naming the requested key.
    // `config_version` is a scalar root, so every descent from it
    // diagnoses the root itself.
    // `str::split('.')` always yields at least one segment — an empty key
    // splits to `[""]`, diagnosed as an empty segment just below — so the
    // root always exists without an unreachable-empty arm.
    let segments: Vec<&str> = key.split('.').collect();
    let (&root, rest) = segments.split_first().unwrap_or((&"", &[]));
    if root.is_empty() || rest.iter().any(|segment| segment.is_empty()) {
        return malformed_edit_key(key);
    }
    match root {
        // The scalar root carries the root spelling inside the issue while
        // the rejection still names the whole requested key.
        "config_version" => ConfigError::schema(
            key,
            ConfigIssue::KeyNotEditable {
                key: root.to_string(),
            },
        ),
        "workflow" => match rest {
            [] => not_editable_key(key),
            _ => unknown_scope_key(key, WORKFLOW_KEYS),
        },
        "connections" => match rest {
            [] | [_] => not_editable_key(key),
            [_, field] if CONNECTION_KEYS.contains(field) => not_editable_key(key),
            _ => unknown_scope_key(key, CONNECTION_KEYS),
        },
        "models" => match rest {
            [] => not_editable_key(key),
            ["defaults" | "groups" | "purposes"] | ["groups" | "purposes", _] => {
                not_editable_key(key)
            }
            ["defaults", "fallback", "chain", tail @ ..] => chain_scope(key, tail),
            ["defaults", "model" | "effort" | "fallback", ..] => not_editable_key(key),
            ["defaults", ..] => unknown_scope_key(key, MODEL_SLOT_KEYS),
            ["groups", _name, "model", ..] => not_editable_key(key),
            ["groups", _name, ..] => unknown_scope_key(key, GROUP_KEYS),
            // `pool` is a file-only field: read-only on the edit surface
            // through the same precedent `group` set.
            ["purposes", _name, "group" | "pool"] => not_editable_key(key),
            ["purposes", _name, "fallback", "chain", tail @ ..] => chain_scope(key, tail),
            [
                "purposes",
                _name,
                "model" | "effort" | "fallback" | "eligible",
                ..,
            ] => not_editable_key(key),
            ["purposes", _name, ..] => unknown_scope_key(key, PURPOSE_KEYS),
            _ => unknown_scope_key(key, MODELS_KEYS),
        },
        _ => unknown_root_key(key, root),
    }
}

fn not_editable_key(key: &str) -> ConfigError {
    ConfigError::schema(
        key,
        ConfigIssue::KeyNotEditable {
            key: key.to_string(),
        },
    )
}

fn malformed_edit_key(key: &str) -> ConfigError {
    ConfigError::schema(
        key,
        ConfigIssue::EmptyKeySegment {
            key: key.to_string(),
        },
    )
}

fn unknown_scope_key(key: &str, known: &'static [&'static str]) -> ConfigError {
    ConfigError::schema(
        key,
        ConfigIssue::UnknownKey {
            key: key.to_string(),
            known,
        },
    )
}

/// Below a legal `fallback` slot's `chain`: entries are addressed through
/// the fallback value, never through dotted keys, so a chain entry's own
/// field — the tail's first and only segment — is legal-but-untargetable,
/// and any deeper descent or unknown field names CHAIN_ENTRY_KEYS — the
/// csv the file surface raises for the same TOML spot.
fn chain_scope(key: &str, tail: &[&str]) -> ConfigError {
    match tail {
        [] => not_editable_key(key),
        [field] if CHAIN_ENTRY_KEYS.contains(field) => not_editable_key(key),
        _ => unknown_scope_key(key, CHAIN_ENTRY_KEYS),
    }
}

fn unknown_root_key(key: &str, root: &str) -> ConfigError {
    ConfigError::schema(
        key,
        ConfigIssue::UnknownRootKey {
            key: root.to_string(),
        },
    )
}

fn type_mismatch(key: &str) -> ConfigError {
    ConfigError::schema(
        key,
        ConfigIssue::ValueTypeMismatch {
            key: key.to_string(),
        },
    )
}

fn target_path(target: &EditTarget) -> (Vec<&str>, &str) {
    match target {
        EditTarget::WorkflowEnabled => (vec!["workflow"], "enabled"),
        EditTarget::DefaultsModel => (vec!["models", "defaults"], "model"),
        EditTarget::DefaultsEffort => (vec!["models", "defaults"], "effort"),
        EditTarget::DefaultsFallback => (vec!["models", "defaults"], "fallback"),
        EditTarget::GroupModel(name) => (vec!["models", "groups", name], "model"),
        EditTarget::PurposeModel(name) => (vec!["models", "purposes", name], "model"),
        EditTarget::PurposeEffort(name) => (vec!["models", "purposes", name], "effort"),
        EditTarget::PurposeFallback(name) => (vec!["models", "purposes", name], "fallback"),
        EditTarget::PurposeEligible(name) => (vec!["models", "purposes", name], "eligible"),
    }
}

fn ensure_table_like<'a>(
    node: &'a mut Item,
    path: &[&str],
    key: &str,
) -> Result<&'a mut dyn TableLike, ConfigError> {
    let mut node = node;
    for (index, segment) in path.iter().enumerate() {
        let inline_parent = matches!(node, Item::Value(toml_edit::Value::InlineTable(_)));
        let table = node.as_table_like_mut().ok_or_else(|| {
            ConfigError::schema(
                key,
                ConfigIssue::ExpectedTable {
                    key: key.to_string(),
                },
            )
        })?;
        if !table.contains_key(segment) {
            let created = if inline_parent {
                Item::Value(toml_edit::Value::InlineTable(InlineTable::new()))
            } else {
                let mut created = Table::new();
                created.set_implicit(index + 1 < path.len());
                Item::Table(created)
            };
            table.insert(segment, created);
        }
        node = table.get_mut(segment).ok_or_else(|| {
            ConfigError::schema(
                key,
                ConfigIssue::ExpectedTable {
                    key: key.to_string(),
                },
            )
        })?;
    }
    node.as_table_like_mut().ok_or_else(|| {
        ConfigError::schema(
            key,
            ConfigIssue::ExpectedTable {
                key: key.to_string(),
            },
        )
    })
}

/// Whether a raw decor suffix carries a comment: an unrendered suffix
/// counts conservatively — this code cannot prove what the parser kept
/// there is whitespace.
fn raw_suffix_is_comment(suffix: &toml_edit::RawString) -> bool {
    suffix
        .as_str()
        .is_none_or(|suffix| !suffix.trim().is_empty())
}

fn value_has_non_whitespace_suffix(value: &toml_edit::Value) -> bool {
    value.decor().suffix().is_some_and(raw_suffix_is_comment)
}

fn set_trailing_preserving(inline: &mut InlineTable, suffix: toml_edit::RawString) {
    let Some(existing) = inline.trailing().as_str() else {
        return;
    };
    let Some(suffix_text) = suffix.as_str() else {
        return;
    };
    let mut trailing = if existing.trim().is_empty() {
        suffix_text.to_owned()
    } else {
        let separator = if existing.ends_with('\n') || suffix_text.starts_with('\n') {
            ""
        } else {
            "\n"
        };
        format!("{existing}{separator}{suffix_text}")
    };
    if trailing.contains('#') && !trailing.ends_with('\n') {
        trailing.push('\n');
    }
    inline.set_trailing(trailing);
}

fn set_field(table: &mut dyn TableLike, field: &str, item: Item) {
    let Some(existing) = table.get_mut(field) else {
        table.insert(field, item);
        return;
    };
    let inline_trailing_comma = match &*existing {
        Item::Value(toml_edit::Value::InlineTable(inline)) => Some(inline.trailing_comma()),
        _ => None,
    };
    if let (Some(target), Some(new)) = (
        existing.as_table_like_mut(),
        item.as_value().and_then(toml_edit::Value::as_inline_table),
    ) {
        let old_last = target.iter().last().map(|(key, _)| key.to_owned());
        let new_last = new.iter().last().map(|(key, _)| key.to_string());
        let mut deleted_suffixes = if inline_trailing_comma == Some(false) {
            target
                .iter()
                .filter(|(key, _)| !new.contains_key(key))
                .filter_map(|(key, _)| {
                    target
                        .get(key)
                        .and_then(Item::as_value)
                        .and_then(|value| value.decor().suffix())
                        .filter(|suffix| raw_suffix_is_comment(suffix))
                        .cloned()
                })
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        let stale: Vec<String> = target
            .iter()
            .map(|(key, _)| key.to_owned())
            .filter(|key| !new.contains_key(key))
            .collect();
        for key in &stale {
            target.remove(key);
        }
        for (key, value) in new.iter() {
            let existed = target.contains_key(key);
            set_field(target, key, Item::Value(value.clone()));
            let Some(trailing_comma) = inline_trailing_comma else {
                continue;
            };
            let Some(value) = target.get_mut(key).and_then(Item::as_value_mut) else {
                continue;
            };
            if Some(key) != new_last.as_deref() || (!existed && trailing_comma) {
                let suffix_is_whitespace = !value_has_non_whitespace_suffix(value);
                if suffix_is_whitespace {
                    value.decor_mut().set_suffix("");
                }
            } else if existed
                && old_last.as_deref() != Some(key)
                && !trailing_comma
                && !value_has_non_whitespace_suffix(value)
            {
                value.decor_mut().set_suffix(" ");
            }
        }
        // Deleted values must not take their comments with them: the last
        // deleted suffix rides the new last value when it has no comment of
        // its own, earlier ones merge into the table trailing instead.
        if let Some(new_last) = new_last.as_deref()
            && target
                .get(new_last)
                .and_then(Item::as_value)
                .is_some_and(|value| !value_has_non_whitespace_suffix(value))
            && let Some(suffix) = deleted_suffixes.pop()
            && let Some(value) = target.get_mut(new_last).and_then(Item::as_value_mut)
        {
            value.decor_mut().set_suffix(suffix);
        }
        if !deleted_suffixes.is_empty()
            && let Some(inline) = existing
                .as_value_mut()
                .and_then(toml_edit::Value::as_inline_table_mut)
        {
            for suffix in deleted_suffixes {
                set_trailing_preserving(inline, suffix);
            }
        }
        return;
    }
    let old = std::mem::replace(existing, item);
    if let (Some(old), Some(new)) = (old.as_value(), existing.as_value_mut()) {
        *new.decor_mut() = old.decor().clone();
    }
}

fn model_item(model: &ModelAssign) -> Item {
    let mut table = InlineTable::new();
    match model {
        ModelAssign::Inherit => {
            table.insert("mode", "inherit".into());
        }
        ModelAssign::Auto { pool } => {
            table.insert("mode", "auto".into());
            if let Some(names) = pool {
                let mut array = Array::new();
                for name in names {
                    array.push(name.as_str());
                }
                table.insert("pool", toml_edit::Value::Array(array));
            }
        }
        ModelAssign::Fixed(fixed) => {
            table.insert("mode", "fixed".into());
            table.insert("connection", fixed.connection.as_str().into());
            table.insert("model_id", fixed.model_id.as_str().into());
        }
    };
    Item::Value(toml_edit::Value::InlineTable(table))
}

fn effort_item(effort: &EffortAssign) -> Item {
    let mut table = InlineTable::new();
    match effort {
        EffortAssign::Inherit => {
            table.insert("mode", "inherit".into());
        }
        EffortAssign::Auto => {
            table.insert("mode", "auto".into());
        }
        EffortAssign::Fixed { value } => {
            table.insert("mode", "fixed".into());
            table.insert("value", effort_level_name(*value).into());
        }
    };
    Item::Value(toml_edit::Value::InlineTable(table))
}

fn effort_level_name(level: EffortLevel) -> &'static str {
    match level {
        EffortLevel::Minimal => "minimal",
        EffortLevel::Low => "low",
        EffortLevel::Medium => "medium",
        EffortLevel::High => "high",
        EffortLevel::Xhigh => "xhigh",
    }
}

fn fallback_item(fallback: &FallbackAssign) -> Item {
    let mut table = InlineTable::new();
    match fallback {
        FallbackAssign::Auto { chain } => {
            table.insert("mode", "auto".into());
            let mut array = Array::new();
            for fixed in chain {
                let mut entry = InlineTable::new();
                entry.insert("mode", "fixed".into());
                entry.insert("connection", fixed.connection.as_str().into());
                entry.insert("model_id", fixed.model_id.as_str().into());
                array.push(toml_edit::Value::InlineTable(entry));
            }
            table.insert("chain", toml_edit::Value::Array(array));
        }
        FallbackAssign::Manual => {
            table.insert("mode", "manual".into());
        }
        FallbackAssign::Off => {
            table.insert("mode", "off".into());
        }
    };
    Item::Value(toml_edit::Value::InlineTable(table))
}

/// Maps one CLI wire value onto the typed slot `key` names, reusing the
/// same rejection vocabulary the TOML parsers emit so both carriers speak
/// one schema (AC-095, DEC-013).
fn wire_value(key: &str, value: &Value) -> Result<ConfigValue, ConfigError> {
    let target = edit_target(key)?;
    match (&target, value) {
        (EditTarget::WorkflowEnabled, Value::Bool(enabled)) => Ok(ConfigValue::Bool(*enabled)),
        (
            EditTarget::DefaultsModel | EditTarget::GroupModel(_) | EditTarget::PurposeModel(_),
            Value::Object(fields),
        ) => Ok(ConfigValue::Model(wire_model(fields, key)?)),
        (EditTarget::DefaultsEffort | EditTarget::PurposeEffort(_), Value::Object(fields)) => {
            Ok(ConfigValue::Effort(wire_effort(fields, key)?))
        }
        (EditTarget::DefaultsFallback | EditTarget::PurposeFallback(_), Value::Object(fields)) => {
            Ok(ConfigValue::Fallback(wire_fallback(fields, key)?))
        }
        (EditTarget::PurposeEligible(_), Value::Array(items)) => Ok(ConfigValue::Names(
            wire_name_array(items, key, ConfigIssue::EligibleEntryNotString)?,
        )),
        _ => Err(type_mismatch(key)),
    }
}

/// The `mode` discriminant every wire assignment carries; its absence is
/// the same required-field rejection the TOML surface emits.
fn wire_mode<'a>(
    fields: &'a serde_json::Map<String, Value>,
    key: &str,
) -> Result<&'a str, ConfigError> {
    fields.get("mode").and_then(Value::as_str).ok_or_else(|| {
        ConfigError::schema(
            format!("{key}.mode"),
            ConfigIssue::Required {
                field: "mode".to_string(),
            },
        )
    })
}

/// Strings of one wire (JSON) array of names, mirroring the rejection
/// vocabulary `name_array` carries so the CLI and TOML surfaces keep one
/// schema.
fn wire_name_array(
    items: &[Value],
    key: &str,
    entry_not_string: ConfigIssue,
) -> Result<Vec<String>, ConfigError> {
    let mut names = Vec::new();
    for entry in items {
        let Some(name) = entry.as_str() else {
            return Err(ConfigError::schema(key, entry_not_string));
        };
        names.push(name.to_string());
    }
    Ok(names)
}

fn wire_model(
    fields: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<ModelAssign, ConfigError> {
    let mode = wire_mode(fields, key)?;
    match mode {
        "inherit" => Ok(ModelAssign::Inherit),
        "auto" => {
            let pool = match fields.get("pool") {
                None => None,
                Some(value) => {
                    let items = value.as_array().ok_or_else(|| {
                        ConfigError::schema(format!("{key}.pool"), ConfigIssue::PoolNotArray)
                    })?;
                    Some(wire_name_array(
                        items,
                        &format!("{key}.pool"),
                        ConfigIssue::PoolEntryNotString,
                    )?)
                }
            };
            Ok(ModelAssign::Auto { pool })
        }
        "fixed" => {
            let connection = fields
                .get("connection")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    ConfigError::schema(
                        format!("{key}.connection"),
                        ConfigIssue::FixedModelMissingConnection,
                    )
                })?
                .to_string();
            let model_id = fields
                .get("model_id")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    ConfigError::schema(format!("{key}.model_id"), ConfigIssue::FixedModelMissingId)
                })?
                .to_string();
            Ok(ModelAssign::Fixed(FixedModel {
                connection,
                model_id,
            }))
        }
        other => Err(ConfigError::schema(
            format!("{key}.mode"),
            ConfigIssue::UnsupportedModelMode {
                mode: other.to_string(),
            },
        )),
    }
}

fn wire_effort(
    fields: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<EffortAssign, ConfigError> {
    let mode = wire_mode(fields, key)?;
    match mode {
        "inherit" => Ok(EffortAssign::Inherit),
        "auto" => Ok(EffortAssign::Auto),
        "fixed" => {
            let raw = fields.get("value").and_then(Value::as_str).ok_or_else(|| {
                ConfigError::schema(format!("{key}.value"), ConfigIssue::FixedEffortMissingValue)
            })?;
            let value = EffortLevel::parse(raw).ok_or_else(|| {
                ConfigError::schema(
                    format!("{key}.value"),
                    ConfigIssue::UnsupportedEffortValue {
                        value: raw.to_string(),
                    },
                )
            })?;
            Ok(EffortAssign::Fixed { value })
        }
        other => Err(ConfigError::schema(
            format!("{key}.mode"),
            ConfigIssue::UnsupportedEffortMode {
                mode: other.to_string(),
            },
        )),
    }
}

fn wire_fallback(
    fields: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<FallbackAssign, ConfigError> {
    let mode = wire_mode(fields, key)?;
    match mode {
        "auto" => {
            let mut chain = Vec::new();
            if let Some(value) = fields.get("chain") {
                let items = value.as_array().ok_or_else(|| {
                    ConfigError::schema(format!("{key}.chain"), ConfigIssue::ChainNotArray)
                })?;
                for entry in items {
                    // Chain entries stay as strict as the TOML surface.
                    let entry = entry.as_object().ok_or_else(|| {
                        ConfigError::schema(format!("{key}.chain"), ConfigIssue::ChainEntryNotTable)
                    })?;
                    for field in entry.keys() {
                        if !matches!(field.as_str(), "mode" | "connection" | "model_id") {
                            return Err(ConfigError::schema(
                                format!("{key}.chain.{field}"),
                                ConfigIssue::UnknownKey {
                                    key: field.clone(),
                                    known: CHAIN_ENTRY_KEYS,
                                },
                            ));
                        }
                    }
                    if let Some(mode) = entry.get("mode") {
                        let mode = mode.as_str().ok_or_else(|| {
                            ConfigError::schema(
                                format!("{key}.chain.mode"),
                                ConfigIssue::ExpectedString {
                                    field: "mode".to_string(),
                                },
                            )
                        })?;
                        if mode != "fixed" {
                            return Err(ConfigError::schema(
                                format!("{key}.chain.mode"),
                                ConfigIssue::UnsupportedModelMode {
                                    mode: mode.to_string(),
                                },
                            ));
                        }
                    }
                    let connection = entry
                        .get("connection")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            ConfigError::schema(
                                format!("{key}.chain.connection"),
                                ConfigIssue::FixedChainEntryMissingConnection,
                            )
                        })?
                        .to_string();
                    let model_id = entry
                        .get("model_id")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            ConfigError::schema(
                                format!("{key}.chain.model_id"),
                                ConfigIssue::FixedChainEntryMissingModelId,
                            )
                        })?
                        .to_string();
                    chain.push(FixedModel {
                        connection,
                        model_id,
                    });
                }
            }
            Ok(FallbackAssign::Auto { chain })
        }
        "manual" => Ok(FallbackAssign::Manual),
        "off" => Ok(FallbackAssign::Off),
        other => Err(ConfigError::schema(
            format!("{key}.mode"),
            ConfigIssue::UnsupportedFallbackMode {
                mode: other.to_string(),
            },
        )),
    }
}

fn validate_target(
    document: Option<&DocumentMut>,
    target: &EditTarget,
    key: &str,
) -> Result<(), ConfigError> {
    let Some(document) = document else {
        return Err(ConfigError::schema(key, ConfigIssue::NoRetainedDocument));
    };
    let (path, field) = target_path(target);
    let mut node = document.as_item();
    for segment in path {
        let Some(next) = node.as_table_like().and_then(|table| table.get(segment)) else {
            return Ok(());
        };
        node = next;
    }
    let Some(item) = node.as_table_like().and_then(|table| table.get(field)) else {
        return Ok(());
    };
    // Target-only validation lets callers repair a rejected entry without touching siblings.
    match target {
        EditTarget::WorkflowEnabled => {
            if item.as_bool().is_none() {
                return Err(ConfigError::schema(
                    key,
                    ConfigIssue::WorkflowEnabledNotBoolean,
                ));
            }
        }
        EditTarget::DefaultsModel | EditTarget::GroupModel(_) | EditTarget::PurposeModel(_) => {
            let assignment = model_assign(item, key)?;
            validate_model_reference(document, &assignment, key)?;
        }
        EditTarget::DefaultsEffort | EditTarget::PurposeEffort(_) => {
            effort_assign(item, key)?;
        }
        EditTarget::DefaultsFallback | EditTarget::PurposeFallback(_) => {
            let assignment = fallback_assign(item, key)?;
            validate_fallback_reference(document, &assignment, key)?;
        }
        EditTarget::PurposeEligible(_) => {
            name_array(
                item,
                key,
                ConfigIssue::EligibleNotArray,
                ConfigIssue::EligibleEntryNotString,
            )?;
        }
    }
    Ok(())
}

fn validate_model_reference(
    document: &DocumentMut,
    assignment: &ModelAssign,
    key: &str,
) -> Result<(), ConfigError> {
    let Some(connections) = document
        .as_item()
        .get("connections")
        .and_then(|item| item.as_table_like())
    else {
        return Ok(());
    };
    let mut typed = BTreeMap::new();
    for name in model_reference_names(assignment) {
        if let Some(item) = connections.get(name) {
            typed.insert(name.to_string(), connection(name, item)?);
        }
    }
    check_model_refs(&typed, assignment, key)
}

/// The targeted-edit twin of the whole-document fallback check: every
/// chain entry must reference a declared connection, exactly as
/// `parse_validated` enforces, so an admitted edit can never leave the
/// retained document unable to boot.
fn validate_fallback_reference(
    document: &DocumentMut,
    assignment: &FallbackAssign,
    key: &str,
) -> Result<(), ConfigError> {
    let FallbackAssign::Auto { chain } = assignment else {
        return Ok(());
    };
    let Some(connections) = document
        .as_item()
        .get("connections")
        .and_then(|item| item.as_table_like())
    else {
        return Ok(());
    };
    let mut typed = BTreeMap::new();
    for entry in chain {
        if let Some(item) = connections.get(entry.connection.as_str()) {
            typed.insert(
                entry.connection.clone(),
                connection(&entry.connection, item)?,
            );
        }
    }
    for entry in chain {
        check_model_refs(&typed, &ModelAssign::Fixed(entry.clone()), key)?;
    }
    Ok(())
}

fn table_like<'a>(key: &str, item: &'a Item) -> Result<&'a dyn TableLike, ConfigError> {
    item.as_table_like().ok_or_else(|| {
        ConfigError::schema(
            key,
            ConfigIssue::ExpectedTable {
                key: key.to_string(),
            },
        )
    })
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
                    ConfigIssue::ExpectedString {
                        field: field.to_string(),
                    },
                )
            },
        )?)),
    }
}

fn connection(name: &str, item: &Item) -> Result<Connection, ConfigError> {
    let table = table_like(name, item)?;
    let key = format!("connections.{name}");
    let kind_raw = string_field(table, &key, "kind")?.ok_or_else(|| {
        ConfigError::schema(
            format!("{key}.kind"),
            ConfigIssue::Required {
                field: "kind".to_string(),
            },
        )
    })?;
    let kind = match kind_raw.as_str() {
        "api_key" => ConnKind::ApiKey,
        "local" => ConnKind::Local,
        "subscription" => ConnKind::Subscription,
        other => {
            return Err(ConfigError::schema(
                format!("{key}.kind"),
                ConfigIssue::UnsupportedConnectionKind {
                    kind: other.to_string(),
                },
            ));
        }
    };
    let endpoint = string_field(table, &key, "endpoint")?.ok_or_else(|| {
        ConfigError::schema(
            format!("{key}.endpoint"),
            ConfigIssue::Required {
                field: "endpoint".to_string(),
            },
        )
    })?;
    let credential_ref = string_field(table, &key, "credential_ref")?;
    for field in table.iter().map(|(field, _)| field) {
        match field {
            "kind" | "endpoint" | "credential_ref" => {}
            "api_key" | "secret" | "token" | "password" => {
                // Never echo the value: diagnostics stay secret-free.
                return Err(ConfigError::schema(
                    format!("{key}.{field}"),
                    ConfigIssue::InlineCredential,
                ));
            }
            other => {
                return Err(ConfigError::schema(
                    format!("{key}.{other}"),
                    ConfigIssue::UnknownKey {
                        key: other.to_string(),
                        known: CONNECTION_KEYS,
                    },
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
                            ConfigIssue::UnknownKey {
                                key: field.to_string(),
                                known: MODEL_SLOT_KEYS,
                            },
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
                                ConfigIssue::UnknownKey {
                                    key: field.to_string(),
                                    known: GROUP_KEYS,
                                },
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
                                            ConfigIssue::GroupReferenceNotString,
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
                            "pool" => {
                                def.pool = Some(name_array(
                                    value,
                                    &format!("{key}.pool"),
                                    ConfigIssue::PoolNotArray,
                                    ConfigIssue::PoolEntryNotString,
                                )?);
                            }
                            "eligible" => {
                                def.eligible = Some(name_array(
                                    value,
                                    &format!("{key}.eligible"),
                                    ConfigIssue::EligibleNotArray,
                                    ConfigIssue::EligibleEntryNotString,
                                )?);
                            }
                            other => {
                                return Err(ConfigError::schema(
                                    format!("{key}.{other}"),
                                    ConfigIssue::UnknownKey {
                                        key: other.to_string(),
                                        known: PURPOSE_KEYS,
                                    },
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
                    ConfigIssue::UnknownKey {
                        key: other.to_string(),
                        known: MODELS_KEYS,
                    },
                ));
            }
        }
    }
    Ok(models)
}

fn pick<'a>(table: &'a dyn TableLike, field: &str) -> Result<&'a Item, ConfigError> {
    table.get(field).ok_or_else(|| {
        ConfigError::schema(
            field,
            ConfigIssue::Required {
                field: field.to_string(),
            },
        )
    })
}

/// Parses one purpose-level array of connection names (`pool`,
/// `eligible`), mirroring the two-issue rejection vocabulary the model
/// `pool` field carries so both surfaces keep one schema.
fn name_array(
    value: &Item,
    key: &str,
    not_array: ConfigIssue,
    entry_not_string: ConfigIssue,
) -> Result<Vec<String>, ConfigError> {
    let items = value
        .as_array()
        .ok_or_else(|| ConfigError::schema(key, not_array))?;
    let mut names = Vec::new();
    for entry in items {
        let Some(name) = entry.as_str() else {
            return Err(ConfigError::schema(key, entry_not_string));
        };
        names.push(name.to_string());
    }
    Ok(names)
}

fn model_assign(item: &Item, key: &str) -> Result<ModelAssign, ConfigError> {
    let table = item.as_table_like().ok_or_else(|| {
        ConfigError::schema(
            key,
            ConfigIssue::ExpectedTable {
                key: key.to_string(),
            },
        )
    })?;
    let Some(mode) = table.get("mode").and_then(Item::as_str) else {
        return Err(ConfigError::schema(
            format!("{key}.mode"),
            ConfigIssue::Required {
                field: "mode".to_string(),
            },
        ));
    };
    match mode {
        "inherit" => Ok(ModelAssign::Inherit),
        "auto" => {
            let pool = match table.get("pool") {
                None => None,
                Some(value) => {
                    let items = value.as_array().ok_or_else(|| {
                        ConfigError::schema(format!("{key}.pool"), ConfigIssue::PoolNotArray)
                    })?;
                    let mut names = Vec::new();
                    for entry in items {
                        names.push(entry.as_str().map(str::to_string).ok_or_else(|| {
                            ConfigError::schema(
                                format!("{key}.pool"),
                                ConfigIssue::PoolEntryNotString,
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
                        ConfigIssue::FixedModelMissingConnection,
                    )
                })?
                .to_string();
            let model_id = table
                .get("model_id")
                .and_then(Item::as_str)
                .ok_or_else(|| {
                    ConfigError::schema(format!("{key}.model_id"), ConfigIssue::FixedModelMissingId)
                })?
                .to_string();
            Ok(ModelAssign::Fixed(FixedModel {
                connection,
                model_id,
            }))
        }
        other => Err(ConfigError::schema(
            format!("{key}.mode"),
            ConfigIssue::UnsupportedModelMode {
                mode: other.to_string(),
            },
        )),
    }
}

fn effort_assign(item: &Item, key: &str) -> Result<EffortAssign, ConfigError> {
    let table = item.as_table_like().ok_or_else(|| {
        ConfigError::schema(
            key,
            ConfigIssue::ExpectedTable {
                key: key.to_string(),
            },
        )
    })?;
    let Some(mode) = table.get("mode").and_then(Item::as_str) else {
        return Err(ConfigError::schema(
            format!("{key}.mode"),
            ConfigIssue::Required {
                field: "mode".to_string(),
            },
        ));
    };
    match mode {
        "inherit" => Ok(EffortAssign::Inherit),
        "auto" => Ok(EffortAssign::Auto),
        "fixed" => {
            let raw = table.get("value").and_then(Item::as_str).ok_or_else(|| {
                ConfigError::schema(format!("{key}.value"), ConfigIssue::FixedEffortMissingValue)
            })?;
            let value = EffortLevel::parse(raw).ok_or_else(|| {
                ConfigError::schema(
                    format!("{key}.value"),
                    ConfigIssue::UnsupportedEffortValue {
                        value: raw.to_string(),
                    },
                )
            })?;
            Ok(EffortAssign::Fixed { value })
        }
        other => Err(ConfigError::schema(
            format!("{key}.mode"),
            ConfigIssue::UnsupportedEffortMode {
                mode: other.to_string(),
            },
        )),
    }
}

fn fallback_assign(item: &Item, key: &str) -> Result<FallbackAssign, ConfigError> {
    let table = item.as_table_like().ok_or_else(|| {
        ConfigError::schema(
            key,
            ConfigIssue::ExpectedTable {
                key: key.to_string(),
            },
        )
    })?;
    let Some(mode) = table.get("mode").and_then(Item::as_str) else {
        return Err(ConfigError::schema(
            format!("{key}.mode"),
            ConfigIssue::Required {
                field: "mode".to_string(),
            },
        ));
    };
    match mode {
        "auto" => {
            let chain = match table.get("chain") {
                None => Vec::new(),
                Some(value) => {
                    let items = value.as_array().ok_or_else(|| {
                        ConfigError::schema(format!("{key}.chain"), ConfigIssue::ChainNotArray)
                    })?;
                    let mut chain = Vec::new();
                    // Chain keys stay strict; other assignment tables stay permissive.
                    for entry in items {
                        let inline = entry.as_inline_table().ok_or_else(|| {
                            ConfigError::schema(
                                format!("{key}.chain"),
                                ConfigIssue::ChainEntryNotTable,
                            )
                        })?;
                        for field in inline.iter().map(|(field, _)| field) {
                            if !matches!(field, "mode" | "connection" | "model_id") {
                                return Err(ConfigError::schema(
                                    format!("{key}.chain.{field}"),
                                    ConfigIssue::UnknownKey {
                                        key: field.to_string(),
                                        known: CHAIN_ENTRY_KEYS,
                                    },
                                ));
                            }
                        }
                        if let Some(mode) = inline.get("mode") {
                            let mode = mode.as_str().ok_or_else(|| {
                                ConfigError::schema(
                                    format!("{key}.chain.mode"),
                                    ConfigIssue::ExpectedString {
                                        field: "mode".to_string(),
                                    },
                                )
                            })?;
                            if mode != "fixed" {
                                return Err(ConfigError::schema(
                                    format!("{key}.chain.mode"),
                                    ConfigIssue::UnsupportedModelMode {
                                        mode: mode.to_string(),
                                    },
                                ));
                            }
                        }
                        let connection = inline
                            .get("connection")
                            .and_then(toml_edit::Value::as_str)
                            .ok_or_else(|| {
                                ConfigError::schema(
                                    format!("{key}.chain.connection"),
                                    ConfigIssue::FixedChainEntryMissingConnection,
                                )
                            })?
                            .to_string();
                        let model_id = inline
                            .get("model_id")
                            .and_then(toml_edit::Value::as_str)
                            .ok_or_else(|| {
                                ConfigError::schema(
                                    format!("{key}.chain.model_id"),
                                    ConfigIssue::FixedChainEntryMissingModelId,
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
            ConfigIssue::UnsupportedFallbackMode {
                mode: other.to_string(),
            },
        )),
    }
}

fn model_reference_names(model: &ModelAssign) -> Vec<&str> {
    match model {
        ModelAssign::Fixed(fixed) => vec![fixed.connection.as_str()],
        ModelAssign::Auto { pool: Some(pool) } => pool.iter().map(String::as_str).collect(),
        _ => Vec::new(),
    }
}

fn check_model_refs(
    connections: &BTreeMap<String, Connection>,
    model: &ModelAssign,
    key: &str,
) -> Result<(), ConfigError> {
    for name in model_reference_names(model) {
        if !connections.contains_key(name) {
            return Err(ConfigError::schema(
                key,
                ConfigIssue::UnknownConnectionReference {
                    connection: name.to_string(),
                },
            ));
        }
    }
    Ok(())
}

/// A fallback chain's entries must reference declared connections on
/// every slot — defaults and purposes alike — so the file surface and its
/// targeted-edit twin (`validate_fallback_reference`) enforce one schema.
fn check_chain_refs(
    connections: &BTreeMap<String, Connection>,
    fallback: &FallbackAssign,
    key: &str,
) -> Result<(), ConfigError> {
    let FallbackAssign::Auto { chain } = fallback else {
        return Ok(());
    };
    for entry in chain {
        if !connections.contains_key(&entry.connection) {
            return Err(ConfigError::schema(
                key,
                ConfigIssue::UnknownConnectionReference {
                    connection: entry.connection.clone(),
                },
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
    let mut effective = EffectiveConfig {
        sources_digest,
        parsed: user_toml.and_then(|text| Config::parse_validated(text).ok()),
        workflow_entry: shipped_workflow_entry(),
    };
    effective.refresh_workflow_entry(&hex(&Sha256::digest(user_toml.unwrap_or("").as_bytes())));
    Ok(effective)
}

impl EffectiveConfig {
    /// Rebuilds the workflow entry the read surface serves from the
    /// retained document — pre-publication the retained doc is the
    /// effective view, so an accepted edit must move this entry with the
    /// doc. `revision` names the retained doc's byte digest; an absent
    /// `workflow.enabled` override keeps the shipped default.
    pub fn refresh_workflow_entry(&mut self, revision: &str) {
        self.workflow_entry = match self
            .parsed
            .as_ref()
            .and_then(|config| config.workflow.enabled)
        {
            Some(value) => user_workflow_entry(value, revision),
            None => shipped_workflow_entry(),
        };
    }
}

fn user_workflow_entry(value: bool, revision: &str) -> ConfigEntry {
    ConfigEntry {
        key: WORKFLOW_KEY.to_string(),
        effective: ConfigViewValue::Visible {
            value: Value::Bool(value),
        },
        source: ConfigSource {
            kind: "user".to_string(),
            revision: revision.to_string(),
            target: None,
        },
    }
}

fn shipped_workflow_entry() -> ConfigEntry {
    ConfigEntry {
        key: WORKFLOW_KEY.to_string(),
        effective: ConfigViewValue::Visible {
            value: Value::Bool(true),
        },
        source: ConfigSource {
            kind: "shipped".to_string(),
            revision: hex(&Sha256::digest(SHIPPED_DEFAULTS_TOML.as_bytes())),
            target: None,
        },
    }
}

// ----- crash-safe publication -----

/// Ceiling for reading a publication target; a larger path is treated as
/// unattributable instead of being pulled into memory whole.
const PUBLICATION_MAX_BYTES: usize = 1 << 20;

/// Darwin `O_NONBLOCK` (same value the executor read backend carries): a
/// FIFO swapped onto the target path must not block the open itself. The
/// regular-file check on the opened handle rejects it right after; regular
/// files ignore the flag.
const O_NONBLOCK: i32 = 0x0004;

/// `(dev, ino)` of a publication target. The managed write is in-place, so
/// a staged identity that still matches after a crash attributes the bytes
/// to our own write; a replaced inode never does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublishIdentity {
    pub dev: u64,
    pub ino: u64,
}

/// One journaled publication intent: the bytes we intended to publish, what
/// was at the target when the intent was staged, and the journal's
/// admission order key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicationIntent {
    pub owner: String,
    pub target: String,
    pub admission_seq: u64,
    pub intended_digest: String,
    pub base_digest: Option<String>,
    pub publish_identity: Option<PublishIdentity>,
}

/// Which singleflight arm one admission landed on: a fresh row the
/// caller must publish, or an existing row this admission observed
/// without journaling anything new.
#[derive(Debug, Clone, PartialEq)]
pub enum PublicationAdmission {
    /// `stage_publication` ran: the caller owns the managed write and
    /// the receipt that completes the row.
    Staged(PublicationIntent),
    /// A still-pending intent for the same command. A replay through
    /// another owner observes the winner's in-flight write and journals
    /// nothing; the owning carrier's replay resolves it instead — see
    /// [`resolve_pending_publication`].
    Pending(PublicationIntent),
    /// A terminal intent whose bytes still hold at the target: the
    /// historical outcome is the answer.
    Applied(PublicationIntent),
}

impl PublicationAdmission {
    /// The journal row this admission resolved to, whichever arm fired.
    pub fn intent(self) -> PublicationIntent {
        match self {
            Self::Staged(intent) | Self::Pending(intent) | Self::Applied(intent) => intent,
        }
    }
}

/// Closed classification of a pending intent against the bytes now at its
/// target, plus `Unknown` for everything that stays unattributable.
/// `ByteIdenticalThird` and `Unknown` are never receipts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicationVerdict {
    Old,
    ExactlyNew,
    ByteIdenticalThird,
    Conflicting,
    TornOrUnparseable,
    Absent,
    Unknown,
}

/// Result of recovering one pending intent: the intent and its verdict.
#[derive(Debug, Clone, PartialEq)]
pub struct PublicationRecovery {
    pub intent: PublicationIntent,
    pub verdict: PublicationVerdict,
}

#[derive(Debug, thiserror::Error)]
pub enum PublicationError {
    #[error("publication target: {0}")]
    Target(#[source] std::io::Error),
    #[error("publication target path is not valid UTF-8")]
    TargetNotUtf8,
    #[error("publication target does not exist: {0}")]
    TargetAbsent(String),
    #[error("publication journal: {0}")]
    Journal(#[source] StoreError),
    #[error("staged publication row carries no target identity")]
    IdentityMissing,
    #[error("publication write failed: {0}")]
    Write(#[from] crate::executor::WorkerError),
}

fn journal_error(error: StoreError) -> PublicationError {
    PublicationError::Journal(error)
}

fn target_too_large() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "publication target exceeds the size ceiling",
    )
}

fn target_not_regular() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "publication target is not a regular file",
    )
}

/// Stages one publication intent: journals the intended digest together
/// with the target's current bytes digest and `(dev, ino)` identity, so a
/// crash between bytes and receipt stays classifiable.
///
/// # Errors
/// Returns [`PublicationError::TargetAbsent`] when the target does not
/// exist — the managed write is in-place and cannot create it, so such an
/// intent could never be attributed later — [`PublicationError::Target`]
/// when the target cannot be observed through one handle, and
/// [`PublicationError::Journal`] when the journal append fails.
pub fn stage_publication(
    store: &mut TaskStore,
    owner: &str,
    target: &Path,
    edit: &ConfigEdit,
) -> Result<PublicationIntent, PublicationError> {
    let target_key = target
        .to_str()
        .ok_or(PublicationError::TargetNotUtf8)?
        .to_string();
    // One opened handle produces the whole durable pair, so no mid-staging
    // swap of the path can splice one inode onto another file's digest.
    let observation = read_target_once(&target_key).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            PublicationError::TargetAbsent(target_key.clone())
        } else {
            PublicationError::Target(error)
        }
    })?;
    let base_digest = Some(observation.digest);
    let publish_identity = Some(observation.identity);
    let admission_seq = store
        .append_publication(
            owner,
            &target_key,
            &edit.digest,
            base_digest.as_deref(),
            publish_identity,
        )
        .map_err(journal_error)?;
    Ok(PublicationIntent {
        owner: owner.to_string(),
        target: target_key,
        admission_seq,
        intended_digest: edit.digest.clone(),
        base_digest,
        publish_identity,
    })
}

/// Singleflight admission for one config command (AC-095): the file and
/// CLI carriers both admit here, keyed on the target's file identity and
/// the intended digest. A command that is still pending is never
/// journaled twice — the replay observes the pending intent (one control
/// event), so the command can later complete exactly once. A replay of a
/// command whose intent already went terminal returns that terminal
/// result, but only while the bytes the row intended still hold at the
/// file: the row that produced the current bytes is the terminal winner,
/// never a max over `admission_seq` — the counter is per target *string*,
/// so one file journaled under two spellings carries two counters and
/// cross-spelling seq order is not chronology. Anything else admits as a
/// fresh instance.
///
/// The returned row may carry a different target spelling than the one
/// this admission named: `(owner, admission_seq)` is an informational
/// echo, and recovery addresses the row's own target.
///
/// # Errors
/// Returns the [`PublicationError`] `stage_publication` returns for a
/// fresh admission, or [`PublicationError::Journal`] when the journal
/// cannot be read.
pub fn admit_publication(
    store: &mut TaskStore,
    owner: &str,
    target: &Path,
    edit: &ConfigEdit,
) -> Result<PublicationAdmission, PublicationError> {
    let target_key = target
        .to_str()
        .ok_or(PublicationError::TargetNotUtf8)?
        .to_string();
    // One observation keys every match on the file's `(dev, ino)` — two
    // spellings of one file are one target — and later confirms whether a
    // terminal row's bytes still hold.
    let sight = observe_target(&target_key);
    let pending = store.pending_publications().map_err(journal_error)?;
    for intent in pending {
        if intent.intended_digest == edit.digest && same_target_file(&intent, &sight, &target_key) {
            return Ok(PublicationAdmission::Pending(intent));
        }
    }
    let applied = store.applied_publications().map_err(journal_error)?;
    if let TargetSight::Present { digest, .. } = &sight
        && digest == &edit.digest
        && let Some(applied) = applied.iter().find(|intent| {
            intent.intended_digest == edit.digest && same_target_file(intent, &sight, &target_key)
        })
    {
        return Ok(PublicationAdmission::Applied(applied.clone()));
    }
    stage_publication(store, owner, target, edit).map(PublicationAdmission::Staged)
}

/// Publishes one freshly staged intent durably: the checked-fd managed
/// write lands the bytes in place against the identity the staging
/// observed, then the receipt completes the journal row. The row's own
/// target spelling addresses the write, exactly like recovery.
///
/// # Errors
/// Returns [`PublicationError::IdentityMissing`] or
/// [`PublicationError::Write`] when the bytes never landed — the row
/// stays pending, the crash-window recovery owns it — and
/// [`PublicationError::Journal`] when only the receipt failed: the bytes
/// are durable and the next boot's recovery receipts them.
pub fn publish_intent(
    store: &mut TaskStore,
    intent: &PublicationIntent,
    bytes: &[u8],
) -> Result<(), PublicationError> {
    let identity = intent
        .publish_identity
        .ok_or(PublicationError::IdentityMissing)?;
    let target = intent.target.as_str();
    let scope_root = Path::new(target)
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_default();
    crate::executor::macos::write_once(
        &scope_root,
        Path::new(target),
        crate::executor::FileIdentity {
            dev: identity.dev,
            ino: identity.ino,
        },
        bytes,
    )
    .map_err(PublicationError::Write)?;
    store
        .complete_publication(&intent.owner, target, intent.admission_seq)
        .map_err(journal_error)
}

/// Resolves one pending admission for a replaying carrier: a replay may
/// answer success only from bytes that hold at the target, never from
/// the retained document alone.
///
/// A row another owner admitted may still be mid-write, so the replay
/// observes it unchanged and never races the winner's managed write. A
/// row the caller itself admitted cannot be in flight — its dispatch
/// already returned — so the retry heals it: the receipt closes a crash
/// window the bytes already survived, and every other verdict re-runs
/// the managed write against the staged identity, which either lands
/// the bytes and receipts or fails with a typed error that leaves the
/// row pending for the next retry.
///
/// # Errors
/// Returns [`PublicationError::Journal`] when a receipt cannot be
/// recorded, and otherwise what [`publish_intent`] returns.
pub fn resolve_pending_publication(
    store: &mut TaskStore,
    owner: &str,
    intent: &PublicationIntent,
    bytes: &[u8],
) -> Result<PublicationIntent, PublicationError> {
    if intent.owner != owner {
        return Ok(intent.clone());
    }
    if classify_intent(intent) == PublicationVerdict::ExactlyNew {
        store
            .complete_publication(&intent.owner, &intent.target, intent.admission_seq)
            .map_err(journal_error)?;
        return Ok(intent.clone());
    }
    publish_intent(store, intent, bytes).map(|()| intent.clone())
}

/// Whether one journaled intent targets the same file this admission
/// names: the opened `(dev, ino)` identity decides; path spellings decide
/// only when that identity cannot be observed (the file is gone or
/// unreadable) or was never journaled.
fn same_target_file(intent: &PublicationIntent, sight: &TargetSight, target_key: &str) -> bool {
    match sight {
        TargetSight::Present {
            identity: Some(current),
            ..
        } => match intent.publish_identity {
            Some(staged) => staged == *current,
            None => intent.target == target_key,
        },
        _ => spelled_same_file(&intent.target, target_key),
    }
}

/// Lexical path equality for spellings of a target that cannot be opened:
/// `/x/./config.toml` and `/x/config.toml` still name one path.
fn spelled_same_file(a: &str, b: &str) -> bool {
    match (std::path::absolute(a), std::path::absolute(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

/// One consistent snapshot of the target: the identity and the digested
/// bytes were taken through the same opened handle.
struct TargetObservation {
    digest: String,
    identity: PublishIdentity,
    bytes: Vec<u8>,
}

/// Opens the target exactly once and reads it through that same handle,
/// mirroring the executor's bounded read: the open is non-blocking, the
/// opened handle itself must be a regular file (a FIFO swapped onto the
/// path can neither hang the open nor slip past the fd-level check), and
/// the read stops one byte past the ceiling so a file that grows past the
/// limit between `fstat` and the read is caught by the length re-check
/// instead of being read unbounded.
fn read_target_once(path: &str) -> std::io::Result<TargetObservation> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(target_not_regular());
    }
    if metadata.len() > PUBLICATION_MAX_BYTES as u64 {
        return Err(target_too_large());
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    file.take(PUBLICATION_MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > PUBLICATION_MAX_BYTES {
        return Err(target_too_large());
    }
    Ok(TargetObservation {
        digest: hex(&Sha256::digest(&bytes)),
        identity: PublishIdentity {
            dev: metadata.dev(),
            ino: metadata.ino(),
        },
        bytes,
    })
}

enum TargetSight {
    Absent,
    Present {
        digest: String,
        identity: Option<PublishIdentity>,
        bytes: Vec<u8>,
    },
    Unknown,
}

/// Observes the target through one opened handle, so the identity and the
/// bytes come from the same file even if the path is swapped mid-read.
fn observe_target(target: &str) -> TargetSight {
    match read_target_once(target) {
        Ok(observation) => TargetSight::Present {
            digest: observation.digest,
            identity: Some(observation.identity),
            bytes: observation.bytes,
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => TargetSight::Absent,
        // An unreadable, non-regular or oversized target leaves any write
        // unattributable — recovery classifies it, it never hangs on it.
        Err(_) => TargetSight::Unknown,
    }
}

/// Classifies one journaled intent against the bytes now at its target.
fn classify_intent(intent: &PublicationIntent) -> PublicationVerdict {
    match observe_target(&intent.target) {
        TargetSight::Absent => PublicationVerdict::Absent,
        TargetSight::Unknown => PublicationVerdict::Unknown,
        TargetSight::Present {
            digest,
            identity,
            bytes,
        } => {
            if digest == intent.intended_digest {
                return match (intent.publish_identity, identity) {
                    (Some(staged), Some(current)) if staged == current => {
                        PublicationVerdict::ExactlyNew
                    }
                    (Some(_), Some(_)) => PublicationVerdict::ByteIdenticalThird,
                    // Identical bytes with no comparable identity stay
                    // unattributed, never a receipt.
                    _ => PublicationVerdict::Unknown,
                };
            }
            if intent.base_digest.as_deref() == Some(digest.as_str()) {
                return PublicationVerdict::Old;
            }
            match std::str::from_utf8(&bytes) {
                // Parseable-but-different bytes cover both a foreign write
                // and our own crashed truncate-first write torn after a
                // parseable prefix; a surviving inode plus a digest
                // mismatch cannot separate the two, so the arm stays
                // fail-closed: downstream must treat Conflicting as "do
                // not touch, a human resolves it" — never as a proven
                // third-party write, and never as a retry signal.
                Ok(text) if text.parse::<DocumentMut>().is_ok() => PublicationVerdict::Conflicting,
                _ => PublicationVerdict::TornOrUnparseable,
            }
        }
    }
}

/// Recovers every pending publication intent: classifies each against the
/// bytes now at its target, records the receipt only for a write this
/// publisher can attribute to itself, and never rewrites the target —
/// foreign and unattributable bytes stay exactly as they are.
///
/// # Errors
/// Returns the underlying [`StoreError`] when the journal cannot be read
/// or the receipt cannot be recorded.
pub fn recover_publications(store: &mut TaskStore) -> Result<Vec<PublicationRecovery>, StoreError> {
    let pending = store.pending_publications()?;
    let mut recoveries = Vec::with_capacity(pending.len());
    for intent in pending {
        let verdict = classify_intent(&intent);
        if verdict == PublicationVerdict::ExactlyNew {
            // The only durable completion: our own in-place write that the
            // crash left unreceipted. Every other verdict stays pending.
            store.complete_publication(&intent.owner, &intent.target, intent.admission_seq)?;
        }
        recoveries.push(PublicationRecovery { intent, verdict });
    }
    Ok(recoveries)
}

pub fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[usize::from(b >> 4)] as char);
        out.push(HEX[usize::from(b & 0x0f)] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_field_preserves_existing_inline_trailing_comment() {
        let mut old = InlineTable::new();
        old.insert("mode", "auto".into());
        old.insert("stale", "old".into());
        old.set_trailing_comma(false);
        old.set_trailing(" # existing\n");
        old.get_mut("mode")
            .expect("mode value")
            .decor_mut()
            .set_suffix(" # mode");
        old.get_mut("stale")
            .expect("stale value")
            .decor_mut()
            .set_suffix(" # stale");

        let mut root = Table::new();
        root.insert("model", Item::Value(toml_edit::Value::InlineTable(old)));

        let mut document = DocumentMut::from(root);
        set_field(
            document.as_table_mut(),
            "model",
            model_item(&ModelAssign::Inherit),
        );

        let bytes = document.to_string();
        let reparsed: Result<DocumentMut, _> = bytes.parse();
        assert!(
            reparsed.is_ok(),
            "rendered inline table must remain valid TOML: {bytes}"
        );
        let model_start = bytes.find("model = {").expect("model assignment");
        let model_end = bytes[model_start..]
            .find('}')
            .map(|offset| model_start + offset)
            .expect("model table terminator");
        let model = &bytes[model_start..=model_end];
        assert!(model.contains("# existing"), "{model}");
        assert!(model.contains("# stale"), "{model}");
    }

    fn render_inline_table(inline: InlineTable) -> String {
        let mut root = Table::new();
        root.insert("model", Item::Value(toml_edit::Value::InlineTable(inline)));
        DocumentMut::from(root).to_string()
    }

    fn assert_valid_toml(rendered: &str) {
        assert!(
            rendered.parse::<DocumentMut>().is_ok(),
            "rendered inline table must remain valid TOML: {rendered}"
        );
    }

    #[test]
    fn set_trailing_preserving_handles_newline_suffix() {
        let mut inline = InlineTable::new();
        inline.insert("mode", "inherit".into());
        inline.set_trailing(" # existing");

        set_trailing_preserving(&mut inline, " # stale\n".into());

        let rendered = render_inline_table(inline);
        assert_valid_toml(&rendered);
        assert!(rendered.contains("# existing"), "{rendered}");
        assert!(rendered.contains("# stale"), "{rendered}");
    }

    #[test]
    fn set_trailing_preserving_terminates_comment_without_existing_trailing() {
        let mut inline = InlineTable::new();
        inline.insert("mode", "inherit".into());
        inline.set_trailing("");

        set_trailing_preserving(&mut inline, " # stale".into());

        let rendered = render_inline_table(inline);
        assert_valid_toml(&rendered);
        assert!(rendered.contains("# stale"), "{rendered}");
    }

    #[test]
    fn set_trailing_preserving_keeps_existing_trailing_for_unresolved_suffix() {
        let source: toml_edit::Document<&str> =
            toml_edit::Document::parse("model = { mode = \"auto\", stale = \"old\" }")
                .expect("source TOML");
        let suffix = source
            .as_table()
            .get("model")
            .and_then(Item::as_value)
            .and_then(toml_edit::Value::as_inline_table)
            .and_then(|table| table.get("stale"))
            .and_then(|value| value.decor().suffix())
            .cloned()
            .expect("stale suffix");
        assert!(suffix.as_str().is_none(), "fixture must keep suffix span");

        let mut inline = InlineTable::new();
        inline.insert("mode", "inherit".into());
        inline.set_trailing(" # existing");
        let before = render_inline_table(inline.clone());

        set_trailing_preserving(&mut inline, suffix);

        assert_eq!(render_inline_table(inline), before);
    }
}
