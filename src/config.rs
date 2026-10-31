//! Configuration owner: single schema, typed TOML validation, purpose
//! resolution and the public ConfigEntry projection (architecture «Taskless
//! config»). Parser is `toml_edit` so later slices keep comment-preserving
//! edits; `parse` is syntax-only (duplicate keys are parser errors), every
//! typed/semantic rejection happens in `validate` and fails closed.

use crate::contracts::ErrorCode;
use crate::executor::{FileIdentity, Unattested, WriteIdentity};
use crate::identity::{IdentityError, IdentityKind, IdentityMigration, IdentityRebind};
use crate::providers::{SecretRef, SecretRefError};
use crate::state::{StoreError, TaskStore};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use toml_edit::{Array, DocumentMut, InlineTable, Item, Table, TableLike, TomlError};

pub const WORKFLOW_KEY: &str = "workflow.enabled";
pub const DECISIONS_MODE_KEY: &str = "decisions.mode";
pub const CONTEXT_AUTO_COMPACT_KEY: &str = "context.auto_compact";

/// The document's legal root keys, named once (DX-I4): the file parser's
/// acceptance, the edit surface's root walk and the `unknown root key`
/// refusal all read this table, so a root one surface accepts is never
/// reported unknown by another.
pub const CONFIG_ROOTS: &[&str] = &[
    "config_version",
    "workflow",
    "decisions",
    "context",
    "connections",
    "profiles",
    "models",
    "hooks",
    "mcp",
];

/// How far a misspelled root may sit from a legal one and still earn the
/// nearest-key hint: a plausible slip gets the suggestion, an unrelated
/// spelling gets no invented answer.
const ROOT_KEY_HINT_DISTANCE: usize = 3;

/// The one instrumented hook event (AC-076, I6): the request is inspected
/// before admission, and a rewrite is re-checked at that same admission.
pub const HOOK_EVENT_EFFECT_REQUEST: &str = "effect.request";

/// The closed event vocabulary a `[hooks]` entry may declare. Widening it
/// is a product decision, not a config option.
pub const HOOK_EVENTS: &[&str] = &[HOOK_EVENT_EFFECT_REQUEST];

/// The fields one `[hooks.<event>@<scope>]` entry may carry (A5).
const HOOK_KEYS: &[&str] = &["command", "args"];

/// The fields one `[mcp.servers.<name>]` row may carry: the operator's own
/// declaration of a program, its arguments and its environment.
const MCP_SERVER_KEYS: &[&str] = &["origin", "program", "args", "env", "credential"];

/// The fields one `[mcp.servers.<name>.credential]` row may carry.
const MCP_CREDENTIAL_KEYS: &[&str] = &["reference", "origin", "variable"];

/// The base version this build compiles in (AC-054, INV-010a): the product
/// base's own identity. It is neither the store's schema generation
/// (`PRAGMA user_version`) nor `config_version`, and the base ledger records
/// it beside the digest it belongs to.
pub const SHIPPED_BASE_VERSION: u64 = 2;

pub const SHIPPED_DEFAULTS_TOML: &str = "config_version = 1\n[workflow]\nenabled = true\n[decisions]\nmode = \"ask\"\n[context]\n# auto_compact silences the near-full context warning; nothing compacts automatically in this build.\nauto_compact = false\n[models.defaults]\nmodel = { mode = \"auto\" }\neffort = { mode = \"auto\" }\nfallback = { mode = \"auto\" }\n# Declaring a connection takes the full row — kind, endpoint and a\n# scoped credential_ref (https on any host, or http on a loopback host):\n# [connections.openai]\n# kind = \"api_key\"\n# endpoint = \"https://api.openai.com/v1\"\n# credential_ref = \"keyring:rivect/openai\"\n# region = \"us-east-1\"\n# profile = \"default\"\n# [profiles.default]\n# credential_ref = \"keyring:rivect/default\"\n# A hook is a user-declared program the executor runs at one\n# instrumented event. It answers allow, deny or stop and may rewrite the\n# request's path; the rewritten request is re-checked by the same\n# admission before any effect, and only the file installs one:\n# [hooks.\"effect.request@project\"]\n# command = \"/usr/local/bin/rivect-hook\"\n# args = []\n# A declared MCP server is operator-owned too: the program, its args, its\n# environment and the origin its egress is admitted against come from this\n# file only, so a request names a server but never supplies one:\n# [mcp.servers.fixture]\n# origin = \"mcp+stdio://fixture\"\n# program = \"/usr/local/bin/rivect-mcp-fixture\"\n# args = []\n# [mcp.servers.fixture.credential]\n# reference = \"keyring:rivect/mcp-fixture\"\n# origin = \"mcp+stdio://fixture\"\n# variable = \"RIVECT_MCP_TOKEN\"\n";

// ----- the versioned base and the update its ledger records -----

/// A versioned product base document (AC-054, DEC-009): the first precedence
/// layer the effective config composes over. Its text is the document every
/// base value is read from; its version is the typed identity the store's base
/// ledger records (INV-010a), never the schema generation and never
/// `config_version`.
///
/// Production supplies [`SHIPPED_DEFAULTS_TOML`] through [`BaseSource::SHIPPED`],
/// a test supplies the next base; both are read by the same section schema as
/// the user's document, so a base cannot state a field the file schema rejects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BaseSource<'a> {
    version: u64,
    text: &'a str,
}

impl<'a> BaseSource<'a> {
    /// The base this build serves: the shipped defaults document and the base
    /// version compiled in beside it, so the two cannot state different
    /// values.
    pub const SHIPPED: BaseSource<'static> = BaseSource {
        version: SHIPPED_BASE_VERSION,
        text: SHIPPED_DEFAULTS_TOML,
    };

    /// A base document a caller supplies — the seam an update moves the base
    /// through.
    #[must_use]
    pub const fn new(version: u64, text: &'a str) -> Self {
        Self { version, text }
    }

    /// The base version this document carries.
    #[must_use]
    pub const fn version(self) -> u64 {
        self.version
    }

    /// The document's bytes — the layer values are read from this text and the
    /// sources digest names it.
    #[must_use]
    pub const fn text(self) -> &'a str {
        self.text
    }

    /// The document's byte digest — the revision a base-sourced entry names
    /// and the identity the ledger records beside the version.
    #[must_use]
    pub fn digest(self) -> String {
        hex(&Sha256::digest(self.text.as_bytes()))
    }

    /// The typed layer, read through the shared section schema.
    fn layer(self) -> Result<BaseLayer, ConfigError> {
        let doc: DocumentMut = self.text.parse().map_err(ConfigError::parse)?;
        let (workflow, decisions, context, models) = validated_base(&doc)?;
        Ok(BaseLayer {
            version: self.version,
            digest: self.digest(),
            workflow: workflow.enabled,
            decisions: decisions.mode,
            context,
            models,
        })
    }
}

/// The base layer's typed values (AC-054): what the base supplies, kept apart
/// from the user document so the layer that answered a read is never derived
/// from a comparison of values.
///
/// A base owns no connection, profile or hook. Of the default-bearing sections
/// it states, `[models.defaults]` merges slot by slot — a base default answers
/// where the user's document defers the slot or has no document at all — while
/// a purpose row the user writes stays the user's whole.
#[derive(Debug, Clone, PartialEq)]
pub struct BaseLayer {
    /// The base version this layer was read from (INV-010a).
    pub version: u64,
    /// The base document's byte digest.
    pub digest: String,
    pub workflow: Option<bool>,
    pub decisions: Option<DecisionModeValue>,
    pub context: Context,
    pub models: Models,
}

/// One base an update run offers the ledger: the version, the digest of the
/// document it was read from, and the two locations this build's other
/// persistent assets live at, so the receipt can name them (REQ-044).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaseInstall {
    pub version: u64,
    pub digest: String,
    pub config_path: PathBuf,
    pub workspace_root: PathBuf,
    /// The generation of the effective configuration this base is offered
    /// under: the `sources_digest` of the object the cutover was validated
    /// against. [`BaseInstall::new`] fills it with the digest of the base layer
    /// alone — the configuration a data root with no user document resolves to —
    /// and a caller that resolved a user document over the base replaces it with
    /// that object's digest (see [`BaseInstall::pinning`]), so an activated base
    /// always names a configuration that really exists.
    pub policy_generation: String,
    /// The two layers a scoped semantic conflict is judged between (REQ-004).
    /// `None` when this install was built without a resolved view, so the store
    /// records no conflict against a surface it never saw.
    pub(crate) semantics: Option<SemanticInputs>,
}

/// What one generation offers and what the user's own document states, kept as
/// the store's input for the scoped-conflict set: the purposes the base declares,
/// and each keyed purpose record of the user's layer with the fields it states
/// explicitly. Nothing here names a field the generation maps — the store reads
/// its own recorded rules and decides that.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SemanticInputs {
    pub(crate) base_purposes: Vec<String>,
    pub(crate) user_records: Vec<(String, Vec<String>)>,
}

impl SemanticInputs {
    /// The purposes the base declares and the fields of every user record, read
    /// from the one validated effective object the cutover pins.
    fn of(effective: &EffectiveConfig) -> Self {
        let base_purposes = effective.base.models.purposes.keys().cloned().collect();
        let user_records = effective
            .parsed
            .as_ref()
            .map(|user| {
                user.models
                    .purposes
                    .iter()
                    .map(|(key, def)| (key.clone(), stated_fields(def)))
                    .collect()
            })
            .unwrap_or_default();
        Self {
            base_purposes,
            user_records,
        }
    }
}

/// The fields one purpose row states explicitly, in the schema's own order so the
/// set is deterministic. A field the row leaves absent is not a value the user
/// owns at that key.
fn stated_fields(def: &PurposeDef) -> Vec<String> {
    let stated = [
        ("group", def.group.is_some()),
        ("model", def.model.is_some()),
        ("effort", def.effort.is_some()),
        ("fallback", def.fallback.is_some()),
        ("pool", def.pool.is_some()),
        ("eligible", def.eligible.is_some()),
    ];
    stated
        .into_iter()
        .filter(|(_, present)| *present)
        .map(|(field, _)| field.to_string())
        .collect()
}

/// One canonical blocker address: `learning/E(id)/E(column)` or
/// `config/E(record_pointer)/E(field_pointer)`, where `E` is the RFC 6901 token
/// escape (`~` → `~0`, `/` → `~1`). The owner is part of the identity, so a
/// native learning id and a keyed config record can never be confused, and no id
/// is reminted, case-folded, normalised, percent-decoded or truncated on the way
/// in.
#[must_use]
pub fn blocker_address(owner: &str, record: &str, field: &str) -> String {
    format!(
        "{owner}/{}/{}",
        pointer_escape(record),
        pointer_escape(field)
    )
}

/// The three parts of one canonical blocker address, or `None` when the value is
/// not one. Splitting on `/` is the escaping boundary — a `/` inside a token is
/// always `~1`, so exactly three segments exist — and each token decodes one
/// layer only, so one field can never be addressed by two spellings.
#[must_use]
pub fn blocker_address_parts(address: &str) -> Option<(String, String, String)> {
    let mut parts = address.split('/');
    let (Some(owner), Some(record), Some(field), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    let record = pointer_unescape(record)?;
    let field = pointer_unescape(field)?;
    match owner {
        // A native id and a column spelling: neither is a pointer, so neither
        // may start at a pointer root.
        "learning" if !record.is_empty() && !field.is_empty() => {
            if record.starts_with('/') || field.starts_with('/') {
                return None;
            }
        }
        // A keyed record and the field inside it, both canonical absolute
        // pointers.
        "config" if record.starts_with('/') && field.starts_with('/') => {}
        _ => return None,
    }
    if blocker_address(owner, &record, &field) != address {
        return None;
    }
    Some((owner.to_string(), record, field))
}

/// RFC 6901 token escaping: the spelling one pointer segment carries inside an
/// address token.
fn pointer_escape(token: &str) -> String {
    let mut escaped = String::with_capacity(token.len());
    for character in token.chars() {
        match character {
            '~' => escaped.push_str("~0"),
            '/' => escaped.push_str("~1"),
            other => escaped.push(other),
        }
    }
    escaped
}

/// One layer of RFC 6901 unescaping. A `~` introducing anything but `0` or `1` is
/// malformed rather than literal, so the decode is total only on well-formed
/// tokens.
fn pointer_unescape(token: &str) -> Option<String> {
    let mut decoded = String::with_capacity(token.len());
    let mut characters = token.chars();
    while let Some(character) = characters.next() {
        if character != '~' {
            decoded.push(character);
            continue;
        }
        match characters.next() {
            Some('0') => decoded.push('~'),
            Some('1') => decoded.push('/'),
            _ => return None,
        }
    }
    Some(decoded)
}

/// The absolute pointer of one keyed purpose record, as its own document path.
/// The address builder escapes it, so a key carrying `/` or `~` keeps one
/// spelling and a plain dotted display path never decides the segment.
#[must_use]
pub(crate) fn purpose_record_pointer(key: &str) -> String {
    format!("/models/purposes/{key}")
}

impl BaseInstall {
    /// The install of one base document. The digest is taken from the source
    /// itself, so the receipt can never name bytes the layer was not read
    /// from; the policy generation is the one this build resolves for that
    /// document over an absent user document, which is the honest value until a
    /// caller pins the object it validated.
    #[must_use]
    pub fn new(
        source: BaseSource<'_>,
        config_path: impl Into<PathBuf>,
        workspace_root: impl Into<PathBuf>,
    ) -> Self {
        Self {
            version: source.version(),
            digest: source.digest(),
            config_path: config_path.into(),
            workspace_root: workspace_root.into(),
            policy_generation: sources_digest_on(source, b""),
            semantics: None,
        }
    }

    /// The same install, pinned to the one validated effective configuration it
    /// was checked against: the digest recorded with the activated base is then
    /// the object the checks ran on, never a re-computation after them.
    #[must_use]
    pub fn pinning(mut self, effective: &EffectiveConfig) -> Self {
        self.policy_generation.clone_from(&effective.sources_digest);
        self.semantics = Some(SemanticInputs::of(effective));
        self
    }
}

/// One persistent asset this build writes (REQ-044, DEC-009). The installer's
/// artifact list and the full §12A.8 inventory belong to the release position,
/// so exactly the kinds that exist here are classified — nothing is named that
/// this build does not write.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateAsset {
    /// The user's `config.toml`: explicit settings are merged over the new
    /// base by meaning, never replaced by it.
    ConfigFile,
    /// The SQLite rows this store owns: tasks, attempts, deltas and their
    /// tombstones are preserved as they are.
    SqliteRows,
    /// The directory tree the runtime writes: preserved, because an update
    /// replaces a document and never a directory.
    WorkspaceDirectories,
    /// The index generations and their edges: derived data, rebuilt from the
    /// documents they describe instead of carried blindly.
    IndexRows,
}

impl UpdateAsset {
    /// The asset's stable name in the receipt and its rows.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConfigFile => "config_file",
            Self::SqliteRows => "sqlite_rows",
            Self::WorkspaceDirectories => "workspace_directories",
            Self::IndexRows => "index_rows",
        }
    }

    /// The asset one stored name spells; `None` for a name this build does not
    /// write.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "config_file" => Some(Self::ConfigFile),
            "sqlite_rows" => Some(Self::SqliteRows),
            "workspace_directories" => Some(Self::WorkspaceDirectories),
            "index_rows" => Some(Self::IndexRows),
            _ => None,
        }
    }

    /// The policy an update follows for this asset.
    #[must_use]
    pub fn policy(self) -> UpdatePolicy {
        match self {
            Self::ConfigFile => UpdatePolicy::MergeByMeaning,
            Self::SqliteRows | Self::WorkspaceDirectories => UpdatePolicy::Preserve,
            Self::IndexRows => UpdatePolicy::Rebuild,
        }
    }
}

/// The persistent assets this build writes, in the receipt's order (DEC-009).
/// One table, so the classification a reader sees and the classification an
/// update writes cannot disagree.
pub const UPDATE_ASSETS: &[UpdateAsset] = &[
    UpdateAsset::ConfigFile,
    UpdateAsset::SqliteRows,
    UpdateAsset::WorkspaceDirectories,
    UpdateAsset::IndexRows,
];

/// What an update does with one persistent asset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdatePolicy {
    /// Keep the asset's rows or bytes as they are.
    Preserve,
    /// Keep the user's explicit values over the new base's, by meaning.
    MergeByMeaning,
    /// Discard the derived content and re-derive it from its sources.
    Rebuild,
}

impl UpdatePolicy {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Preserve => "preserve",
            Self::MergeByMeaning => "merge_by_meaning",
            Self::Rebuild => "rebuild",
        }
    }

    /// The policy one stored name spells.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "preserve" => Some(Self::Preserve),
            "merge_by_meaning" => Some(Self::MergeByMeaning),
            "rebuild" => Some(Self::Rebuild),
            _ => None,
        }
    }
}

/// Where one base stands in its cutover (PROH-004): a staged base has arrived
/// but has not committed, so the previous base keeps serving.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateState {
    /// Written ahead of the cutover: the resumable checkpoint of an update
    /// that stopped between staging and commit.
    Staged,
    /// Serving the runtime now.
    Active,
    /// Replaced by a committed successor; its receipt stays readable.
    Retired,
}

impl UpdateState {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Staged => "staged",
            Self::Active => "active",
            Self::Retired => "retired",
        }
    }

    /// The state one stored name spells; `None` for a name this build does not
    /// write.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "staged" => Some(Self::Staged),
            "active" => Some(Self::Active),
            "retired" => Some(Self::Retired),
            _ => None,
        }
    }
}

/// The closed attempt phase (AC-055, REQ-001). `checked` is the validation
/// milestone — the effective policy and smoke checks passed and activation had
/// not committed — so it lives in the attempt's evidence and in this status
/// projection, never in a ledger row; `activated` is the row's own phase and
/// `rolled_back` belongs to a discarded attempt. JSON/SQL spelling is
/// `checked|activated|rolled_back`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdatePhase {
    Checked,
    Activated,
    RolledBack,
}

impl UpdatePhase {
    /// The phase one stored spelling names; `None` for a value this build does
    /// not write.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "checked" => Some(Self::Checked),
            "activated" => Some(Self::Activated),
            "rolled_back" => Some(Self::RolledBack),
            _ => None,
        }
    }
}

/// One classified asset of the update receipt.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ReceiptAsset {
    pub asset: UpdateAsset,
    /// Where the asset lives in this installation, as the write surface saw
    /// it.
    pub location: String,
    pub policy: UpdatePolicy,
}

/// The receipt one base's update wrote (REQ-044, DEC-009): the base it belongs
/// to, the state its cutover reached, every persistent asset this build
/// writes with the policy the update followed for it, and the identity rules the
/// base was released with (AC-056) — what the cutover placed, so the receipt
/// names what moved by meaning as well as what it classified.
///
/// The four optional fields are the durable metadata the base row carries, and each
/// one reports exactly what its column holds. All four are absent on a row written
/// before those columns existed — the one legacy shape. A row this build staged
/// carries `blockers` (the empty page included if its set is empty) and **no**
/// `phase`, `schema_generation` or `policy_generation`: a staged base has not been
/// activated, and a phase on it would claim a validation that never ran. Only an
/// activated or retired row carries `phase: activated` together with both
/// generations. A row that answers some but not the rest is not a shape either
/// producer writes, so reading it refuses instead of inventing the missing half.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct UpdateReceipt {
    pub base_version: u64,
    /// The base document's byte digest: the receipt belongs to these bytes.
    pub digest: String,
    pub state: UpdateState,
    pub assets: Vec<ReceiptAsset>,
    pub identity: IdentityRebind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phase: Option<UpdatePhase>,
    /// The base's blocker set as a bounded page: `snapshot_generation` is the
    /// base version the set is immutable under.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blockers: Option<crate::contracts::Page<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_generation: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_generation: Option<String>,
}

/// One base the ledger records.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct BaseDocument {
    pub version: u64,
    pub digest: String,
}

/// What the shipped write surface did to reach the base it serves: the receipt
/// of the base installed now, and the checkpoint a cutover had to abandon first
/// (EDGE-006) because it held a document this build cannot resume. The abandoned
/// checkpoint is reported, never made up: a resume discards nothing and answers
/// `None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaseServed {
    pub receipt: UpdateReceipt,
    pub abandoned: Option<BaseDocument>,
}

/// What one base cutover did (AC-054, AC-056): the base installed now — its
/// receipt names the rules the release carried and the bindings the transition
/// placed — the checkpoint a stopped cutover left behind, and the user document
/// once its pins moved with the base. `edit` is `None` when no binding moved, so
/// a second run over an installed base answers a document it did not touch.
#[derive(Debug, Clone, PartialEq)]
pub struct BaseCutover {
    pub served: BaseServed,
    pub edit: Option<ConfigEdit>,
}

/// The base ledger's served projection (AC-054, DEC-011): the base serving now
/// and the receipt of the newest base the ledger holds — staged while a cutover
/// waits, active when it serves. The receipt's own state names which.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct UpdateStatus {
    pub base_version: Option<u64>,
    pub receipt: Option<UpdateReceipt>,
    /// The phase of the newest attempt: `checked` while validation passed and
    /// activation has not committed, `activated` once the row says so,
    /// `rolled_back` for a discarded attempt. `None` for a row this build never
    /// touched.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phase: Option<UpdatePhase>,
    /// The base's blocker set as a bounded page, absent for a legacy row whose
    /// set was never recorded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blockers: Option<crate::contracts::Page<String>>,
    /// The schema generation the base was activated under.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_generation: Option<u64>,
    /// The digest of the effective configuration the base was validated against.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_generation: Option<String>,
    /// The original cause of the newest attempt that recorded one, after
    /// recovery as well as before it: the retained record is never rewritten by
    /// a later convergence, so the operator keeps the failure they still have to
    /// act on.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure: Option<crate::contracts::WireError>,
    /// The retained attempt record that cause (or the newest attempt when none
    /// recorded one) lives in, relative to the data root.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
    /// Set when part of this status could not be answered as asked, and the rest of
    /// the read still is — the refusal rides the success-shaped status instead of the
    /// RPC error envelope, so the other collections survive. It reports two
    /// conditions, and `blockers` tells them apart:
    ///
    /// - the requested blocker page cannot be served because its set is gone, was
    ///   re-created, or names a base the ledger does not hold — the page-scoped
    ///   refusal — and `blockers` is then absent;
    /// - the retained attempt-record tree under `reports/update` cannot be read or
    ///   decoded, so `failure`/`evidence` answer nothing — here `blockers` still
    ///   carries the page it could serve.
    ///
    /// A `page_conflict` the ledger already set for an invalidated cursor is never
    /// overwritten by the record-tree fault, so a caller holding a stale cursor is
    /// still told to restart.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page_conflict: Option<crate::contracts::WireError>,
    /// Set when this status projected only part of the retained attempt records: the
    /// tree under `reports/update` holds more records than one bounded read covers, so a
    /// cause older than the read's window is not reported here. The message names that
    /// directory and what went unread, because truncation and "no attempt ever ran" are
    /// different answers and the caller must be able to tell them apart. Absent when the
    /// read covered the whole tree, which is every tree at or below the count bound.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_truncated: Option<String>,
}

/// One `runtime.status` blocker-page request: the page size, the base whose set
/// is ranged (absent: the serving one) and the cursor the caller resumes at.
/// Sibling to the task collections' `page`, never flat inside it — one request
/// has two independent paged collections.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UpdatePage {
    /// One to [`crate::contracts::PAGE_MAX`], default
    /// [`crate::contracts::PAGE_DEFAULT`].
    pub page_size: u32,
    /// The requested base version; absent means the base serving now.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base: Option<u64>,
    /// `blk:<base_version>:<set_epoch>:offset:<offset>`; absent means the first
    /// page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

impl Default for UpdatePage {
    fn default() -> Self {
        Self {
            page_size: crate::contracts::PAGE_DEFAULT,
            base: None,
            cursor: None,
        }
    }
}

/// The base ledger's typed refusals (P-001, EDGE-005). A refusal never leaves
/// a half-applied cutover: the previous base keeps serving and the ledger row
/// the run tried to write is absent.
#[derive(Debug, thiserror::Error)]
pub enum BaseError {
    #[error("storage: {0}")]
    Store(#[from] StoreError),
    /// EDGE-005: the offered base's predecessor is not the recorded base, so a
    /// supported step is missing and nothing is applied.
    #[error("base version {offered} skips the recorded base {recorded}")]
    SkippedVersion { offered: u64, recorded: u64 },
    /// I-6: an older build must not write over a base a newer one recorded.
    /// Nothing this build can run rewrites the recorded row, so the refusal
    /// names the only step that serves: the runtime that recorded that base
    /// opens this data root and keeps serving it.
    #[error(
        "base version {offered} is older than the recorded base {recorded}; recovery: open this data root with a runtime compatible with the recorded base {recorded}"
    )]
    NewerRecorded { offered: u64, recorded: u64 },
    /// The recorded version arrived with other bytes: the ledger answers no
    /// receipt for a document this open did not compose, because the receipt
    /// names the bytes it was read from. Nothing an open can rewrite clears it,
    /// so the refusal names the recovery: the document that changed must arrive
    /// under a version that names it.
    #[error(
        "base version {version} is recorded with another document; recovery: ship the changed document under a new base version"
    )]
    DocumentChanged { version: u64 },
    /// Another document is already staged: a checkpoint belongs to the document
    /// that staged it and is never rewritten in place, so the run that wants
    /// other bytes abandons it first — the cutover does that for a checkpoint it
    /// cannot resume, and never for one a newer build staged.
    #[error(
        "base version {version} is already staged with another document; recovery: resume the staged document, or abandon the checkpoint before staging another"
    )]
    AlreadyStaged { version: u64 },
    /// The cutover names a base the ledger never staged.
    #[error("base version {version} is not staged for cutover")]
    NotStaged { version: u64 },
    /// The ledger holds the base but no receipt for it: the classification was
    /// never written, so it is not invented on read.
    #[error("base version {version} has no update receipt")]
    ReceiptMissing { version: u64 },
    /// The identity rules do not place as written: the cutover is refused before
    /// any row moves and the previous base keeps serving (AC-056).
    #[error("base cutover identity: {0}")]
    Identity(#[from] IdentityError),
    /// The user document cannot carry the pins its rules move — the row conflict
    /// [`Config::merge_purposes`] refuses. The cutover is refused before the
    /// ledger moves, so the previous base keeps serving.
    #[error("base cutover document: {0}")]
    Document(#[from] ConfigError),
    /// The requested blocker page names a set this ledger re-created under the
    /// same base version: the rows at the requested offset are not the ones the
    /// cursor was minted for, so the read restarts from the first page. Both
    /// epochs are named, and the variant — not its prose — separates this from
    /// the absent-set case below.
    #[error(
        "base {version} blocker set was re-created: requested epoch {requested}, stored epoch {stored}, restart from the first page"
    )]
    BlockerSetMoved {
        version: u64,
        requested: u64,
        stored: u64,
    },
    /// The requested base holds no blocker set at all (pruned, or abandoned and
    /// not yet restaged), so no offset into it exists and the read restarts from
    /// the first page.
    #[error(
        "base {version} holds no blocker set for requested epoch {requested}, restart from the first page"
    )]
    BlockerSetGone { version: u64, requested: u64 },
    /// The page request itself is outside its domain: a malformed or
    /// overflowing cursor, a cursor that names another base than the request
    /// does, or a page size outside its range. The caller's typo is
    /// `invalid_input`, never the store's `storage_unavailable`.
    #[error("base blocker page: {detail}")]
    InvalidPage { detail: &'static str },
    /// The explicit `ROLLBACK` of a refused activation reported an error: the
    /// connection is left in a transaction state this call cannot vouch for, so
    /// the store is quarantined and no further statement runs until a compatible
    /// reopen reads the whole tuple back. A destructor is not evidence of a
    /// rollback.
    #[error(
        "base version {version} rollback did not report success; the store stays closed until a compatible reopen reads its tuple"
    )]
    RollbackFailed { version: u64 },
    /// The activation's `COMMIT` answered with an error and the store could not
    /// establish which tuple it holds: neither an ended transaction with one whole
    /// tuple nor a readable one. The store is quarantined instead of retried blind.
    #[error(
        "base version {version} outcome could not be read back; the store stays closed until a compatible reopen reads its tuple"
    )]
    OutcomeUnread { version: u64 },
}

impl BaseError {
    /// The refusal's wire code. Every base-ledger refusal carries the base
    /// version domain's own code — never the store's schema-generation code —
    /// so a refusal names which version domain it belongs to.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Store(error) => error.code(),
            Self::Document(error) => match error.stage {
                Stage::Parse | Stage::Schema => ErrorCode::InvalidInput,
                Stage::Resolve => ErrorCode::Conflict,
            },
            Self::InvalidPage { .. } => ErrorCode::InvalidInput,
            // A failed rollback and an unreadable outcome are the store's own
            // state, not a caller's input: they report the same unavailable
            // class a closed store does, and the quarantine is what the next
            // compatible open clears.
            Self::RollbackFailed { .. } | Self::OutcomeUnread { .. } => {
                ErrorCode::StorageUnavailable
            }
            Self::NewerRecorded { .. }
            | Self::SkippedVersion { .. }
            | Self::AlreadyStaged { .. }
            | Self::DocumentChanged { .. }
            | Self::NotStaged { .. }
            | Self::ReceiptMissing { .. }
            | Self::BlockerSetMoved { .. }
            | Self::BlockerSetGone { .. }
            | Self::Identity { .. } => ErrorCode::Conflict,
        }
    }
}

/// One wire-addressable config carrier (DX-I3, DEC-014): the pattern the
/// read hint prints, one representative key, and the resolvers the wire
/// surfaces use. The read domain, the unknown-key hint and the wire edit
/// target all descend from this table, so a carrier cannot answer on one
/// surface while a second, hand-written list answers on another.
///
/// A document-only section — `[hooks]` (DEC-010), `models.purposes.<id>.pool`
/// — is deliberately absent: it is parsed and validated, never addressed
/// through `config.set`.
pub struct ConfigCarrier {
    /// The pattern spelling the unknown-key hint prints.
    pub pattern: &'static str,
    /// One concrete key this carrier addresses: the proof that every
    /// surface answers the same shape.
    pub sample: &'static str,
    /// The served value of one address, from the name captures.
    read: fn(&Config, &[&str]) -> Option<Value>,
    /// The edit target one address resolves to.
    target: fn(&[&str]) -> EditTarget,
}

impl ConfigCarrier {
    /// The name captures this address yields, or `None` when the key does
    /// not spell this carrier. A `<...>` segment captures exactly one
    /// non-empty key segment; every other segment is literal.
    fn names<'key>(&self, key: &'key str) -> Option<Vec<&'key str>> {
        let pattern: Vec<&str> = self.pattern.split('.').collect();
        let segments: Vec<&str> = key.split('.').collect();
        if pattern.len() != segments.len() {
            return None;
        }
        let mut names = Vec::new();
        for (expected, actual) in pattern.iter().zip(&segments) {
            if expected.starts_with('<') {
                if actual.is_empty() {
                    return None;
                }
                names.push(*actual);
            } else if expected != actual {
                return None;
            }
        }
        Some(names)
    }
}

/// Every config key the wire surfaces address, in the order the read hint
/// prints them.
pub const CONFIG_CARRIERS: &[ConfigCarrier] = &[
    ConfigCarrier {
        pattern: "workflow.enabled",
        sample: "workflow.enabled",
        read: |config, _| Some(Value::Bool(config.workflow.enabled.unwrap_or(true))),
        target: |_| EditTarget::WorkflowEnabled,
    },
    ConfigCarrier {
        pattern: "decisions.mode",
        sample: "decisions.mode",
        read: |config, _| {
            Some(
                config
                    .decisions
                    .mode
                    .map_or(Value::Null, |mode| Value::String(mode.as_str().to_string())),
            )
        },
        target: |_| EditTarget::DecisionsMode,
    },
    ConfigCarrier {
        pattern: "context.auto_compact",
        sample: "context.auto_compact",
        read: |config, _| Some(Value::Bool(config.auto_compact())),
        target: |_| EditTarget::ContextAutoCompact,
    },
    ConfigCarrier {
        pattern: "connections.<id>.region",
        sample: "connections.openai.region",
        read: |config, names| {
            Some(
                config
                    .connections
                    .get(first_name(names))
                    .and_then(|connection| connection.region.clone())
                    .map_or(Value::Null, Value::String),
            )
        },
        target: |names| EditTarget::ConnectionRegion(first_name(names).to_string()),
    },
    ConfigCarrier {
        pattern: "connections.<id>.profile",
        sample: "connections.openai.profile",
        read: |config, names| {
            Some(
                config
                    .connections
                    .get(first_name(names))
                    .and_then(|connection| connection.profile.clone())
                    .map_or(Value::Null, Value::String),
            )
        },
        target: |names| EditTarget::ConnectionProfile(first_name(names).to_string()),
    },
    ConfigCarrier {
        pattern: "profiles.<name>.credential_ref",
        sample: "profiles.default.credential_ref",
        read: |config, names| {
            Some(
                config
                    .profiles
                    .get(first_name(names))
                    .and_then(|profile| profile.credential_ref.clone())
                    .map_or(Value::Null, Value::String),
            )
        },
        target: |names| EditTarget::ProfileCredentialRef(first_name(names).to_string()),
    },
];

/// The two declared sections no wire surface addresses, in the shape both
/// carriers name them: a hook entry and a declared MCP server are the
/// document's own (DEC-010), so neither is a carrier.
const DOCUMENT_ONLY_SHAPES: &str = "hooks.<event>@<scope>, mcp.servers.<name>";

/// The name a name-bearing carrier captured. A pattern without a capture
/// never calls this, so the empty answer is unreachable rather than a
/// silent substitution.
fn first_name<'name>(names: &[&'name str]) -> &'name str {
    names.first().copied().unwrap_or_default()
}

/// The keys `config.read` serves, named once for the read surface's
/// unknown-key hint: the pattern of every carrier, in table order, then the
/// document-only sections. A name-bearing key prints its pattern form — a
/// connection or profile name is never itself a known key.
#[must_use]
pub fn read_key_hint() -> String {
    let carriers = CONFIG_CARRIERS
        .iter()
        .map(|carrier| carrier.pattern)
        .collect::<Vec<_>>()
        .join(", ");
    // The two declared sections follow the carriers (DEC-010): a `[hooks]` or
    // `[mcp.servers.<name>]` key is never addressable, so the hint names them
    // as the document's own and the file that can write them, instead of
    // leaving the asker with a list of unrelated carriers.
    format!("{carriers}; document-only, declare in the config file: {DOCUMENT_ONLY_SHAPES}")
}

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
    /// A declaration the document owns and the wire surfaces never write
    /// (DEC-010): `[hooks]` and `[mcp.servers.<name>]`. The answer names the
    /// file that can write it instead of refusing with no why and no next
    /// action.
    #[error(
        "{key} is document-only; declare it in the config file; not editable through config.set"
    )]
    DocumentOnlyKey { key: String },
    #[error("malformed key {key}: empty segment")]
    EmptyKeySegment { key: String },
    #[error("{}", unknown_root_message(key))]
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
    #[error("base may not claim id {id} of the reserved personal namespace")]
    PersonalNamespaceClaimed { id: String },
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
    #[error("context.auto_compact must be a boolean")]
    ContextAutoCompactNotBoolean,
    #[error("hook entry {key} must be named <event>@<scope>")]
    HookEntryNotAddressable { key: String },
    #[error("unsupported hook event {event}; known events: {}", HOOK_EVENTS.join(", "))]
    UnsupportedHookEvent { event: String },
    #[error("hook command must be an absolute program path")]
    HookCommandNotAbsolutePath { key: String },
    #[error("hook args must be an array of strings")]
    HookArgsInvalid { key: String },
    #[error("mcp server name {name} is not a bounded identifier")]
    McpServerNameInvalid { name: String },
    #[error("mcp server program must be an absolute program path")]
    McpProgramNotAbsolutePath { key: String },
    /// A declared origin is the destination the executor's egress admission
    /// binds, so it carries the runtime's own grammar at the parse site: the
    /// accepted form is named here instead of surfacing at the first call.
    #[error(
        "mcp server origin must be <scheme>://<host> over ASCII letters, digits or . _ - : / +, at most 128 characters"
    )]
    McpOriginInvalid { key: String },
    #[error("mcp server args must be an array of strings")]
    McpArgsInvalid { key: String },
    #[error("mcp server env must be a table of strings")]
    McpEnvInvalid { key: String },
    #[error("unsupported decisions.mode {mode}; known modes: ask, auto, inherit")]
    UnsupportedDecisionMode { mode: String },
    #[error("{key} is required, not an override; reset removes overrides only")]
    RequiredNotResettable { key: String },
    #[error("no configuration document is retained; parse one before editing")]
    NoRetainedDocument,
    #[error("value type does not match {key}")]
    ValueTypeMismatch { key: String },
    #[error(
        "{key} carries raw secret material; a scoped secret reference (store:scope) is required"
    )]
    SecretRefExpected { key: String },
    /// The reference is well-formed but its store label names no class
    /// this build serves — refused at ingress under the same grammar
    /// [`crate::providers::SecretRef::parse`] re-checks at the seam.
    #[error(
        "credential reference names an unsupported credential store: {store}; admitted stores: keyring, keychain, secret-service"
    )]
    UnsupportedCredentialStore { store: String },
    #[error("unknown profile reference: profiles.{profile}")]
    UnknownProfileReference { profile: String },
    #[error(
        "endpoint must be an https URL, an http URL on a loopback host, or empty for the class default"
    )]
    EndpointNotAllowed,
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
    /// Optional deployment region (DEC-013): provider dialects resolve
    /// its wire meaning; the schema carries it opaque.
    pub region: Option<String>,
    /// The credential profile this connection binds (AC-047): names a
    /// `[profiles.<name>]` entry — never a secret itself.
    pub profile: Option<String>,
}

/// One credential profile (DEC-013): the `credential_ref` is a scoped
/// secret reference (`store:scope`), never the secret itself — raw
/// material is refused at both carriers.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Profile {
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

    /// The level's wire name — config emission and provider dialects
    /// transmit the one spelling.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Minimal => "minimal",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Xhigh => "xhigh",
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

/// The context guard (DEC-013): `auto_compact` controls the near-full
/// warning only — nothing compacts automatically in this build.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Context {
    pub auto_compact: Option<bool>,
}

/// One declared hook (AC-076, DEC-010): a user-owned program the executor
/// runs at its one instrumented event. Its identity is event + scope +
/// command (DX-I1), addressed by the document key `hooks.<event>@<scope>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookEntry {
    pub event: String,
    pub scope: String,
    /// The program, as an absolute path: a hook is executed, never looked
    /// up through `PATH`.
    pub command: PathBuf,
    pub args: Vec<String>,
}

impl HookEntry {
    /// The record identity the document key and every refusal spell.
    #[must_use]
    pub fn id(&self) -> String {
        format!("{}@{}", self.event, self.scope)
    }
}

/// The `[hooks]` section: document-only (DEC-010, I7 option a). A hook is
/// a program the executor runs, so no wire channel — human or machine —
/// installs one; the file is the only writer, and an invalid entry is a
/// typed refusal naming its key.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Hooks {
    entries: BTreeMap<String, HookEntry>,
}

impl Hooks {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The entry one identity addresses.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&HookEntry> {
        self.entries.get(id)
    }

    /// The one entry declared for an event, in identity order so the
    /// choice never depends on document order: the executor runs at most
    /// one hook per event.
    #[must_use]
    pub fn for_event(&self, event: &str) -> Option<&HookEntry> {
        self.entries.values().find(|entry| entry.event == event)
    }
}

/// One declared MCP server (AC-075): `[mcp.servers.<name>]`. The row is the
/// operator's, never the caller's — a `tools/call` request names the server
/// and nothing else, so the program it launches, its arguments, its
/// environment and the origin its egress is admitted against come from this
/// document alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpServerDeclaration {
    /// The destination identity the executor's egress admission binds and the
    /// origin a credential reference must be enrolled for.
    pub origin: String,
    /// The program, as an absolute path: a declared server is executed, never
    /// looked up through `PATH`.
    pub program: PathBuf,
    pub args: Vec<String>,
    /// The declaration's own environment entries; the process is started with
    /// a cleared environment, so nothing is inherited but the base allowlist.
    pub env: BTreeMap<String, String>,
    pub credential: Option<McpCredentialDeclaration>,
}

/// The credential one declared server resolves for itself. The reference names
/// where material lives; `origin` is the origin the reference was *enrolled*
/// for, so a row copied from another server keeps its enrolled origin and the
/// mismatch is refused instead of resolving a foreign credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpCredentialDeclaration {
    pub reference: String,
    pub origin: String,
    /// The environment variable the material reaches the child under — never
    /// a frame field.
    pub variable: String,
}

/// The wire spelling of `decisions.mode`: `ask` and `auto` resolve
/// directly; `inherit` names the absent override — the layer below
/// (today the shipped `ask`) answers instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionModeValue {
    Ask,
    Auto,
    Inherit,
}

impl DecisionModeValue {
    /// The TOML/JSON spelling; `None` for anything else — the closed set
    /// is the same the file and wire surfaces reject against.
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "ask" => Some(Self::Ask),
            "auto" => Some(Self::Auto),
            "inherit" => Some(Self::Inherit),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ask => "ask",
            Self::Auto => "auto",
            Self::Inherit => "inherit",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Decisions {
    pub mode: Option<DecisionModeValue>,
}

/// The decision mode a material fork observes — `inherit` and the absent
/// override both land on the shipped `ask`; only an explicit `auto`
/// admits delegated machine resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionMode {
    Ask,
    Auto,
}

impl DecisionMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ask => "ask",
            Self::Auto => "auto",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Config {
    pub version: u64,
    pub workflow: Workflow,
    pub decisions: Decisions,
    pub context: Context,
    pub connections: BTreeMap<String, Connection>,
    /// Declared credential profiles (DEC-013): `connections.<id>.profile`
    /// references must resolve here — a dangling profile is the same
    /// schema violation a dangling connection reference is.
    pub profiles: BTreeMap<String, Profile>,
    pub models: Models,
    /// The `[hooks]` declarations (DEC-010): user-owned programs the
    /// executor runs at its one instrumented event.
    pub hooks: Hooks,
    /// The `[mcp.servers.<name>]` declarations (AC-075): operator-owned MCP
    /// programs a `tools/call` request may name. Document-only, like a hook:
    /// the program a child runs is never wire-supplied.
    pub mcp: BTreeMap<String, McpServerDeclaration>,
    raw: Option<DocumentMut>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ConfigValue {
    Bool(bool),
    DecisionMode(DecisionModeValue),
    Model(ModelAssign),
    Effort(EffortAssign),
    Fallback(FallbackAssign),
    Names(Vec<String>),
    /// A plain string value — the additive profile keys' carrier.
    Text(String),
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

/// The purpose moves a release's rules make: one identity is both the config row
/// that binds a purpose and the purpose a learned condition names, so a role rule
/// moves the document binding and the stored experience together (AC-056). An
/// action rule names a capability and moves no document row.
fn purpose_moves(rules: &[IdentityMigration]) -> impl Iterator<Item = (String, String)> + '_ {
    rules
        .iter()
        .filter(|rule| rule.kind == IdentityKind::Role)
        .map(|rule| (rule.old_id.clone(), rule.new_id.clone()))
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
        let parsed = validated_document(doc)?;
        self.version = parsed.version;
        self.workflow = parsed.workflow;
        self.decisions = parsed.decisions;
        self.context = parsed.context;
        self.connections = parsed.connections;
        self.profiles = parsed.profiles;
        self.models = parsed.models;
        self.hooks = parsed.hooks;
        self.mcp = parsed.mcp;
        Ok(())
    }

    /// Whether the near-full guard is silenced: only an explicit
    /// `auto_compact = true` does it, because nothing compacts
    /// automatically in this build (DEC-013, DEC-020).
    #[must_use]
    pub fn auto_compact(&self) -> bool {
        self.context.auto_compact.unwrap_or(false)
    }

    /// The mode a material fork observes: `inherit` resolves through to
    /// the shipped `ask`, an absent override stays `ask`; only an
    /// explicit `auto` admits delegated machine resolution.
    pub fn decisions_mode(&self) -> DecisionMode {
        match self.decisions.mode {
            Some(DecisionModeValue::Auto) => DecisionMode::Auto,
            _ => DecisionMode::Ask,
        }
    }

    /// Rebinds one purpose's binding to its migrated name (AC-056, REQ-046):
    /// the row moves by meaning, so a rename keeps the pin it carried. The
    /// source document key leaves with it — a moved value is never readable
    /// under the old name — and a target the document already binds differently
    /// is refused by [`Config::merge_purposes`] instead of collapsing two rows
    /// into one. An absent source row moves nothing and answers `None`.
    ///
    /// The row is read from the retained document by the same purpose schema the
    /// file surface uses, one row at a time, so a document holding a field the
    /// schema rejects elsewhere — a sibling purpose row, a connection, any
    /// other table — still moves its own binding instead of leaving it behind;
    /// those bytes are never rewritten, the targeted-edit discipline
    /// `Config::set` already keeps (DEC-013).
    ///
    /// A config with no retained document binds no purpose row at all, so a role
    /// rule has no pin to move and nothing to refuse: the answer is `None`, and
    /// the cutover that offers the rule still installs the base it serves.
    ///
    /// # Errors
    /// Returns the conflict [`Config::merge_purposes`] reports for two
    /// different bindings under one name, and the schema refusals the two rows
    /// this move reads carry.
    pub fn rebind_purpose(
        &mut self,
        from: &str,
        to: &str,
    ) -> Result<Option<ConfigEdit>, ConfigError> {
        let key = format!("models.purposes.{to}");
        {
            let Some(document) = self.raw.as_mut() else {
                return Ok(None);
            };
            let purposes = document
                .get("models")
                .and_then(Item::as_table_like)
                .and_then(|models| models.get("purposes"))
                .and_then(Item::as_table_like);
            let Some(purposes) = purposes else {
                return Ok(None);
            };
            let source_key = format!("models.purposes.{from}");
            let Some(binding) = purposes
                .get(from)
                .map(|entry| purpose_def(&source_key, from, entry))
                .transpose()?
            else {
                return Ok(None);
            };
            // The merge rule the two-document case already runs, applied to the
            // two rows this move touches: an identical binding replays, a
            // different one conflicts, and neither row is overwritten by the
            // other. No third row is judged, so an unknown field a sibling holds
            // keeps its bytes and does not refuse this move.
            let mut moved = Config::default();
            moved.models.purposes.insert(to.to_string(), binding);
            let mut held = Config::default();
            if let Some(target) = purposes
                .get(to)
                .map(|entry| purpose_def(&key, to, entry))
                .transpose()?
            {
                held.models.purposes.insert(to.to_string(), target);
            }
            held.merge_purposes(&moved)?;
        }
        if from != to {
            self.move_purpose_table(from, to)?;
        }
        self.refresh_view_if_valid();
        Ok(Some(self.finish_edit()))
    }

    /// The purpose moves a base release's role rules make, proven against a copy
    /// of this document (AC-056): a rule names one identity, so its config row
    /// moves where the stored experience moves, and a row the document does not
    /// bind is no move at all. The proof runs before the ledger moves — a
    /// document that cannot carry a pin refuses the cutover with the previous
    /// base still serving — and what it answers is what
    /// [`Config::move_purpose_bindings`] then applies.
    ///
    /// # Errors
    /// Returns the refusals [`Config::rebind_purpose`] reports for the moves this
    /// document cannot carry.
    pub(crate) fn planned_purpose_moves(
        &self,
        rules: &[IdentityMigration],
    ) -> Result<Vec<(String, String)>, ConfigError> {
        let mut proven = self.clone();
        let mut moves = Vec::new();
        for (from, to) in purpose_moves(rules) {
            if proven.rebind_purpose(&from, &to)?.is_some() {
                moves.push((from, to));
            }
        }
        Ok(moves)
    }

    /// Applies the moves [`Config::planned_purpose_moves`] proved, after the base
    /// they belong to committed: the document the cutover serves moves with the
    /// base it serves, and the last edit is the document to write back.
    ///
    /// # Errors
    /// Returns the refusals [`Config::rebind_purpose`] reports; a move the proof
    /// already passed cannot add one.
    pub(crate) fn move_purpose_bindings(
        &mut self,
        moves: &[(String, String)],
    ) -> Result<Option<ConfigEdit>, ConfigError> {
        let mut edit = None;
        for (from, to) in moves {
            if let Some(moved) = self.rebind_purpose(from, to)? {
                edit = Some(moved);
            }
        }
        Ok(edit)
    }

    /// Moves the retained document's `models.purposes.<from>` table onto `<to>`.
    /// The bytes move as one item, so the row's own comments and layout travel
    /// with the binding; a target the document already declares keeps its own
    /// row (the merge above proved the two bindings identical) and only the
    /// source key leaves.
    fn move_purpose_table(&mut self, from: &str, to: &str) -> Result<(), ConfigError> {
        let key = format!("models.purposes.{to}");
        let document = self.require_document(&key)?;
        let Some(purposes) = document
            .get_mut("models")
            .and_then(Item::as_table_like_mut)
            .and_then(|models| models.get_mut("purposes"))
            .and_then(Item::as_table_like_mut)
        else {
            return Ok(());
        };
        if purposes.contains_key(to) {
            purposes.remove(from);
            return Ok(());
        }
        let Some(binding) = purposes.remove(from) else {
            return Ok(());
        };
        purposes.insert(to, binding);
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
                if !matches!(
                    &target,
                    EditTarget::WorkflowEnabled | EditTarget::ContextAutoCompact
                ) {
                    return Err(type_mismatch(key));
                }
                toml_edit::value(enabled)
            }
            ConfigValue::DecisionMode(mode) => {
                if !matches!(&target, EditTarget::DecisionsMode) {
                    return Err(type_mismatch(key));
                }
                toml_edit::value(mode.as_str())
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
            ConfigValue::Text(text) => {
                if !matches!(
                    &target,
                    EditTarget::ConnectionRegion(_)
                        | EditTarget::ConnectionProfile(_)
                        | EditTarget::ProfileCredentialRef(_)
                ) {
                    return Err(type_mismatch(key));
                }
                toml_edit::value(text.as_str())
            }
        };
        let (path, field) = target_path(&target);
        let original = self.raw.clone();
        let edited = self.require_document(key).and_then(|doc| {
            require_declared_connection(doc, &target, key)?;
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
        let edited = self.require_document(key).and_then(|doc| {
            require_declared_connection(doc, &target, key)?;
            let mut node = doc.as_item_mut();
            for segment in target_path(&target).0 {
                let Some(next) = node
                    .as_table_like_mut()
                    .and_then(|table| table.get_mut(segment))
                else {
                    return Ok(());
                };
                node = next;
            }
            if let Some(table) = node.as_table_like_mut() {
                table.remove(target_path(&target).1);
            }
            Ok(())
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
        let Ok(parsed) = validated_document(doc) else {
            // Targeted edits intentionally remain usable while another path
            // still carries a rejected value; that value is never rewritten.
            return;
        };
        self.version = parsed.version;
        self.workflow = parsed.workflow;
        self.decisions = parsed.decisions;
        self.context = parsed.context;
        self.connections = parsed.connections;
        self.profiles = parsed.profiles;
        self.models = parsed.models;
        self.hooks = parsed.hooks;
        self.mcp = parsed.mcp;
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

    /// The served value of one readable key on this document (DEC-014):
    /// `Some` for an in-domain key — null when the field carries no
    /// value — `None` outside the read domain, where the surface answers
    /// with the unknown-key hint instead. The domain check is the same
    /// [`is_readable_key`] the wire surface gates on, so a rejected key
    /// can never read as an empty-name null here.
    pub fn read_value(&self, key: &str) -> Option<Value> {
        let carrier = carrier_for(key)?;
        let names = carrier.names(key)?;
        (carrier.read)(self, &names)
    }

    /// The byte digest of the retained document — the revision a read
    /// entry names as its source, matching the digest an admitted edit
    /// reports for the same document state.
    pub fn revision(&self) -> String {
        self.finish_edit().digest
    }
}

/// Whether `config.read` serves this key (DEC-014): the workflow flag
/// plus the additive profile keys. The shape domain is closed — a name
/// segment is never itself a known key, and an empty segment reads as
/// unknown.
pub fn is_readable_key(key: &str) -> bool {
    carrier_for(key).is_some()
}

/// The one carrier an address spells, from the table (DX-I3).
pub(crate) fn carrier_for(key: &str) -> Option<&'static ConfigCarrier> {
    CONFIG_CARRIERS
        .iter()
        .find(|carrier| carrier.names(key).is_some())
}

/// Whether the wire edit surfaces may address this key: a `[hooks]`
/// declaration is document-only (DEC-010), so nothing under `hooks` is.
pub fn is_hook_key(key: &str) -> bool {
    key == "hooks" || key.starts_with("hooks.")
}

/// Whether the document owns this key and no wire surface serves it: a
/// `[hooks]` declaration and a `[mcp.servers.<name>]` one are the file's own
/// (DEC-010), so a read of one answers the file instead of an unknown key.
pub fn is_document_only_key(key: &str) -> bool {
    is_hook_key(key) || key == "mcp.servers" || key.starts_with("mcp.servers.")
}

/// The document-only sentence, worded once for both carriers: the edit
/// surface raises it as a typed issue, the read surface answers the same
/// text for the same key.
#[must_use]
pub fn document_only_message(key: &str) -> String {
    ConfigIssue::DocumentOnlyKey {
        key: key.to_string(),
    }
    .to_string()
}

/// `credential_ref` ingress is the credential seam's own grammar (INV-006,
/// DEC-013): [`SecretRef::parse`] admits only the `store:scope` shape with
/// a store class this build serves, so an unadmitted label — `env:`,
/// `file:`, `vault:` — is refused where the value enters, not deferred to
/// a dispatch-time surprise. The value never enters diagnostics.
fn credential_ref_admitted(raw: &str, key: &str) -> Result<(), ConfigIssue> {
    match SecretRef::parse(raw) {
        Ok(_) => Ok(()),
        Err(SecretRefError::UnsupportedStore { store }) => {
            Err(ConfigIssue::UnsupportedCredentialStore { store })
        }
        Err(SecretRefError::NotScoped) => Err(ConfigIssue::SecretRefExpected {
            key: key.to_string(),
        }),
    }
}

/// The typed view `validated_document` extracts from the raw TOML:
/// version, workflow, decisions and context tables, connections,
/// credential profiles, the models section, the hook declarations and the
/// declared MCP servers, all schema-checked.
struct ParsedDocument {
    version: u64,
    workflow: Workflow,
    decisions: Decisions,
    context: Context,
    connections: BTreeMap<String, Connection>,
    profiles: BTreeMap<String, Profile>,
    models: Models,
    hooks: Hooks,
    mcp: BTreeMap<String, McpServerDeclaration>,
}

fn validated_document(doc: &DocumentMut) -> Result<ParsedDocument, ConfigError> {
    let mut version = None;
    let mut workflow = Workflow::default();
    let mut decisions = Decisions::default();
    let mut context = Context::default();
    let mut connections = BTreeMap::new();
    let mut profiles = BTreeMap::new();
    let mut models = Models::default();
    let mut hooks = Hooks::default();
    let mut mcp = BTreeMap::new();
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
                workflow = workflow_section(item)?;
            }
            "decisions" => {
                decisions = decisions_section(item)?;
            }
            "context" => {
                context = context_section(item)?;
            }
            "connections" => {
                let table = table_like(key, item)?;
                for (name, entry) in table.iter() {
                    connections.insert(name.to_string(), connection(name, entry)?);
                }
            }
            "profiles" => {
                let table = table_like(key, item)?;
                for (name, entry) in table.iter() {
                    profiles.insert(name.to_string(), profile(name, entry)?);
                }
            }
            "models" => {
                models = models_table(table_like(key, item)?)?;
            }
            "hooks" => {
                hooks = hooks_table(table_like(key, item)?)?;
            }
            "mcp" => {
                // The section names servers, so one more level is read here
                // and the row schema owns the rest.
                mcp = mcp_section(table_like(key, item)?)?;
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
    let version = document_config_version(version)?;
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
        // A present reference must be a scoped secret reference naming
        // an admitted store — the same grammar profiles enforce. Never
        // echo the value: diagnostics stay secret-free.
        if let Some(credential_ref) = &connection.credential_ref {
            credential_ref_admitted(credential_ref, &format!("{key}.credential_ref"))
                .map_err(|issue| ConfigError::schema(format!("{key}.credential_ref"), issue))?;
        }
        // A profile binding must name a declared profile — the same
        // referential discipline connection references already carry.
        if let Some(profile) = &connection.profile
            && !profiles.contains_key(profile)
        {
            return Err(ConfigError::schema(
                format!("{key}.profile"),
                ConfigIssue::UnknownProfileReference {
                    profile: profile.clone(),
                },
            ));
        }
    }
    if models.defaults.is_none() {
        return Err(ConfigError::schema(
            "models.defaults",
            ConfigIssue::Required {
                field: "models.defaults".to_string(),
            },
        ));
    }
    check_model_references(&connections, &models)?;
    Ok(ParsedDocument {
        version,
        workflow,
        decisions,
        context,
        connections,
        profiles,
        models,
        hooks,
        mcp,
    })
}

/// The referential checks a document's `[models]` section must pass: every fixed
/// model and fallback entry names a declared connection, and every purpose group
/// names a declared group. The file document and the composed document run this
/// one function, so a base that names a connection or group the installation
/// does not declare is refused where the layers meet instead of failing at
/// dispatch, far from the cause.
fn check_model_references(
    connections: &BTreeMap<String, Connection>,
    models: &Models,
) -> Result<(), ConfigError> {
    if let Some(defaults) = &models.defaults {
        check_model_refs(connections, &defaults.model, "models.defaults.model")?;
        check_chain_refs(
            connections,
            &defaults.fallback,
            "models.defaults.fallback.chain",
        )?;
    }
    for (name, group) in &models.groups {
        check_model_refs(
            connections,
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
            check_model_refs(connections, model, &format!("{key}.model"))?;
        }
        if let Some(fallback) = &purpose.fallback {
            check_chain_refs(connections, fallback, &format!("{key}.fallback.chain"))?;
        }
    }
    Ok(())
}

/// The `config_version` a document declares (DEC-010): absent and unsupported
/// are both refusals, and the base document is admitted by the same rule as the
/// user's so a base can never state a version the file schema rejects.
fn document_config_version(version: Option<u64>) -> Result<u64, ConfigError> {
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
    Ok(version)
}

fn workflow_section(item: &Item) -> Result<Workflow, ConfigError> {
    let mut workflow = Workflow::default();
    for (field, value) in table_like("workflow", item)?.iter() {
        match field {
            "enabled" => {
                workflow.enabled = Some(value.as_bool().ok_or_else(|| {
                    ConfigError::schema("workflow.enabled", ConfigIssue::WorkflowEnabledNotBoolean)
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
    Ok(workflow)
}

fn decisions_section(item: &Item) -> Result<Decisions, ConfigError> {
    let mut decisions = Decisions::default();
    for (field, value) in table_like("decisions", item)?.iter() {
        match field {
            "mode" => {
                let raw = value.as_str().ok_or_else(|| {
                    ConfigError::schema(
                        "decisions.mode",
                        ConfigIssue::ExpectedString {
                            field: "mode".to_string(),
                        },
                    )
                })?;
                decisions.mode = Some(DecisionModeValue::parse(raw).ok_or_else(|| {
                    ConfigError::schema(
                        "decisions.mode",
                        ConfigIssue::UnsupportedDecisionMode {
                            mode: raw.to_string(),
                        },
                    )
                })?);
            }
            other => {
                return Err(ConfigError::schema(
                    format!("decisions.{other}"),
                    ConfigIssue::UnknownKey {
                        key: other.to_string(),
                        known: DECISIONS_KEYS,
                    },
                ));
            }
        }
    }
    Ok(decisions)
}

fn context_section(item: &Item) -> Result<Context, ConfigError> {
    let mut context = Context::default();
    for (field, value) in table_like("context", item)?.iter() {
        match field {
            "auto_compact" => {
                context.auto_compact = Some(value.as_bool().ok_or_else(|| {
                    ConfigError::schema(
                        CONTEXT_AUTO_COMPACT_KEY,
                        ConfigIssue::ContextAutoCompactNotBoolean,
                    )
                })?);
            }
            other => {
                return Err(ConfigError::schema(
                    format!("context.{other}"),
                    ConfigIssue::UnknownKey {
                        key: other.to_string(),
                        known: CONTEXT_KEYS,
                    },
                ));
            }
        }
    }
    Ok(context)
}

/// The base document's sections, read by the same schema as the user's
/// document (AC-054): a base supplies defaults, so it may state the four
/// default-bearing sections and owns nothing a user owns — connections,
/// profiles and hooks stay the user's to declare, and a base that states one is
/// refused rather than silently trusted with it.
fn validated_base(
    doc: &DocumentMut,
) -> Result<(Workflow, Decisions, Context, Models), ConfigError> {
    let mut version = None;
    let mut workflow = Workflow::default();
    let mut decisions = Decisions::default();
    let mut context = Context::default();
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
            "workflow" => workflow = workflow_section(item)?,
            "decisions" => decisions = decisions_section(item)?,
            "context" => context = context_section(item)?,
            "models" => models = models_table(table_like(key, item)?)?,
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
    document_config_version(version)?;
    // The reserved user namespace (AC-056, REQ-046): a base is the release's
    // own document, so it may not name an id inside the namespace the user's
    // identities live in — a mapping that could name it could rebind or
    // overwrite the user's own experience. The user's own document keeps the
    // namespace; only this layout is refused.
    for name in models.purposes.keys() {
        if crate::identity::claims_personal_namespace(name) {
            return Err(ConfigError::schema(
                format!("models.purposes.{name}"),
                ConfigIssue::PersonalNamespaceClaimed { id: name.clone() },
            ));
        }
    }
    Ok((workflow, decisions, context, models))
}

#[derive(Debug)]
enum EditTarget {
    WorkflowEnabled,
    DecisionsMode,
    ContextAutoCompact,
    DefaultsModel,
    DefaultsEffort,
    DefaultsFallback,
    GroupModel(String),
    PurposeModel(String),
    PurposeEffort(String),
    PurposeFallback(String),
    PurposeEligible(String),
    ConnectionRegion(String),
    ConnectionProfile(String),
    ProfileCredentialRef(String),
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
    // The wire carriers answer from the one table (DX-I3); the model
    // assignment slots below keep their own arms — they are document-shaped
    // objects, not scalar wire carriers.
    if let Some(carrier) = carrier_for(key)
        && let Some(names) = carrier.names(key)
    {
        return Ok((carrier.target)(&names));
    }
    match segments.as_slice() {
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
const DECISIONS_KEYS: &[&str] = &["mode"];
const CONTEXT_KEYS: &[&str] = &["auto_compact"];
const CONNECTION_KEYS: &[&str] = &["kind", "endpoint", "credential_ref", "region", "profile"];
const PROFILE_KEYS: &[&str] = &["credential_ref"];
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
        "decisions" => match rest {
            [] => not_editable_key(key),
            _ => unknown_scope_key(key, DECISIONS_KEYS),
        },
        "context" => match rest {
            [] => not_editable_key(key),
            _ => unknown_scope_key(key, CONTEXT_KEYS),
        },
        "connections" => match rest {
            [] | [_] => not_editable_key(key),
            [_, field] if CONNECTION_KEYS.contains(field) => not_editable_key(key),
            _ => unknown_scope_key(key, CONNECTION_KEYS),
        },
        "profiles" => match rest {
            [] | [_] => not_editable_key(key),
            [_, field] if PROFILE_KEYS.contains(field) => not_editable_key(key),
            _ => unknown_scope_key(key, PROFILE_KEYS),
        },
        // A hook is a program the executor runs, so `[hooks]` is
        // document-only (DEC-010, I7a): every spelling below it is a legal
        // location the edit surface cannot target, and the answer names the
        // file that can.
        "hooks" => document_only_key(key),
        // A declared MCP server is a program the client launches and a
        // destination its egress is admitted against, so `[mcp]` is
        // document-only for the same reason `[hooks]` is.
        "mcp" => document_only_key(key),
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

fn document_only_key(key: &str) -> ConfigError {
    ConfigError::schema(
        key,
        ConfigIssue::DocumentOnlyKey {
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

/// The `unknown root key` refusal, with the diagnosis the root table makes
/// possible (DX-I4): the legal roots and the nearest one. The nearest key
/// is offered only for a plausible slip — a suggestion derived from an
/// unrelated word would be noise dressed as help.
fn unknown_root_message(key: &str) -> String {
    match nearest_root(key) {
        Some(nearest) => format!(
            "unknown root key {key}; known roots: {}; nearest key: {nearest}",
            CONFIG_ROOTS.join(", ")
        ),
        None => format!("unknown root key {key}"),
    }
}

fn nearest_root(key: &str) -> Option<&'static str> {
    CONFIG_ROOTS
        .iter()
        .copied()
        .map(|root| (edit_distance(key, root), root))
        .filter(|(distance, _)| *distance <= ROOT_KEY_HINT_DISTANCE)
        .min_by_key(|(distance, _)| *distance)
        .map(|(_, root)| root)
}

/// Character edit distance: one small dynamic program over two keys, so
/// the root hint needs no dependency and no allocation beyond the rows.
fn edit_distance(left: &str, right: &str) -> usize {
    let right: Vec<char> = right.chars().collect();
    let mut previous: Vec<usize> = (0..=right.len()).collect();
    let mut current = vec![0; right.len() + 1];
    for (row, left_char) in left.chars().enumerate() {
        current[0] = row + 1;
        for (column, right_char) in right.iter().enumerate() {
            let substitution = previous[column] + usize::from(left_char != *right_char);
            current[column + 1] = substitution
                .min(previous[column + 1] + 1)
                .min(current[column] + 1);
        }
        std::mem::swap(&mut previous, &mut current);
    }
    previous[right.len()]
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
        EditTarget::DecisionsMode => (vec!["decisions"], "mode"),
        EditTarget::ContextAutoCompact => (vec!["context"], "auto_compact"),
        EditTarget::DefaultsModel => (vec!["models", "defaults"], "model"),
        EditTarget::DefaultsEffort => (vec!["models", "defaults"], "effort"),
        EditTarget::DefaultsFallback => (vec!["models", "defaults"], "fallback"),
        EditTarget::GroupModel(name) => (vec!["models", "groups", name], "model"),
        EditTarget::PurposeModel(name) => (vec!["models", "purposes", name], "model"),
        EditTarget::PurposeEffort(name) => (vec!["models", "purposes", name], "effort"),
        EditTarget::PurposeFallback(name) => (vec!["models", "purposes", name], "fallback"),
        EditTarget::PurposeEligible(name) => (vec!["models", "purposes", name], "eligible"),
        EditTarget::ConnectionRegion(name) => (vec!["connections", name], "region"),
        EditTarget::ConnectionProfile(name) => (vec!["connections", name], "profile"),
        EditTarget::ProfileCredentialRef(name) => (vec!["profiles", name], "credential_ref"),
    }
}

/// The `connections.<name>.*` edit targets write onto a connection the
/// document already declares — the same referential discipline the file
/// surface and model/profile references carry (DEC-013). Checked before
/// any mutation: an edit that materialized `[connections.<name>]` from
/// nothing would publish a stub no valid document can hold — `kind` is
/// required and never editable. Other name-bearing targets keep their
/// auto-create semantics.
fn require_declared_connection(
    document: &DocumentMut,
    target: &EditTarget,
    key: &str,
) -> Result<(), ConfigError> {
    let (EditTarget::ConnectionRegion(name) | EditTarget::ConnectionProfile(name)) = target else {
        return Ok(());
    };
    let declared = document
        .as_item()
        .get("connections")
        .and_then(|item| item.as_table_like())
        .is_some_and(|connections| connections.contains_key(name.as_str()));
    if declared {
        return Ok(());
    }
    Err(ConfigError::schema(
        key,
        ConfigIssue::UnknownConnectionReference {
            connection: name.clone(),
        },
    ))
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
            table.insert("value", value.name().into());
        }
    };
    Item::Value(toml_edit::Value::InlineTable(table))
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
        // Both carriers answer one cause for the same value: a non-boolean
        // is the key's own refusal, not the generic type mismatch.
        (EditTarget::ContextAutoCompact, Value::Bool(enabled)) => Ok(ConfigValue::Bool(*enabled)),
        (EditTarget::ContextAutoCompact, _) => Err(ConfigError::schema(
            CONTEXT_AUTO_COMPACT_KEY,
            ConfigIssue::ContextAutoCompactNotBoolean,
        )),
        (EditTarget::DecisionsMode, Value::String(mode)) => Ok(ConfigValue::DecisionMode(
            DecisionModeValue::parse(mode).ok_or_else(|| {
                ConfigError::schema(
                    key,
                    ConfigIssue::UnsupportedDecisionMode { mode: mode.clone() },
                )
            })?,
        )),
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
        (
            EditTarget::ConnectionRegion(_)
            | EditTarget::ConnectionProfile(_)
            | EditTarget::ProfileCredentialRef(_),
            Value::String(text),
        ) => Ok(ConfigValue::Text(text.clone())),
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
        EditTarget::ContextAutoCompact => {
            if item.as_bool().is_none() {
                return Err(ConfigError::schema(
                    key,
                    ConfigIssue::ContextAutoCompactNotBoolean,
                ));
            }
        }
        EditTarget::DecisionsMode => {
            let Some(raw) = item.as_str() else {
                return Err(ConfigError::schema(
                    key,
                    ConfigIssue::ExpectedString {
                        field: "mode".to_string(),
                    },
                ));
            };
            if DecisionModeValue::parse(raw).is_none() {
                return Err(ConfigError::schema(
                    key,
                    ConfigIssue::UnsupportedDecisionMode {
                        mode: raw.to_string(),
                    },
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
        EditTarget::ConnectionRegion(_) => {
            if item.as_str().is_none() {
                return Err(ConfigError::schema(
                    key,
                    ConfigIssue::ExpectedString {
                        field: "region".to_string(),
                    },
                ));
            }
        }
        EditTarget::ConnectionProfile(_) => {
            let Some(raw) = item.as_str() else {
                return Err(ConfigError::schema(
                    key,
                    ConfigIssue::ExpectedString {
                        field: "profile".to_string(),
                    },
                ));
            };
            // The profile binding must resolve against the declared
            // profiles — the same discipline the file surface enforces
            // at parse.
            let declared = document
                .as_item()
                .get("profiles")
                .and_then(|item| item.as_table_like())
                .is_some_and(|profiles| profiles.get(raw).is_some());
            if !declared {
                return Err(ConfigError::schema(
                    key,
                    ConfigIssue::UnknownProfileReference {
                        profile: raw.to_string(),
                    },
                ));
            }
        }
        EditTarget::ProfileCredentialRef(_) => {
            let Some(raw) = item.as_str() else {
                return Err(ConfigError::schema(
                    key,
                    ConfigIssue::ExpectedString {
                        field: "credential_ref".to_string(),
                    },
                ));
            };
            // Never echo the value: diagnostics stay secret-free.
            credential_ref_admitted(raw, key).map_err(|issue| ConfigError::schema(key, issue))?;
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

/// The configured endpoint's trust boundary: `https` for any host,
/// `http` only for a loopback host, or an empty/whitespace-only string
/// — the absent-override sentinel a local-dialect connection id
/// resolves to its recorded class default. Anything else would let provider
/// traffic — and the bearer it carries — leave the configured trust
/// boundary unreviewed: a schemeless or non-loopback `http` endpoint
/// is refused, and a userinfo marker is refused the same way because
/// credentials never ride the URL.
fn endpoint_allowed(endpoint: &str) -> bool {
    // The adapter's endpoint rules trim before the empty check — the
    // sentinel and the scheme verdict both run on the trimmed form.
    let endpoint = endpoint.trim();
    let Some(rest) = endpoint
        .strip_prefix("https://")
        .or_else(|| endpoint.strip_prefix("http://"))
    else {
        return endpoint.is_empty();
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.is_empty() || authority.contains('@') {
        return false;
    }
    if endpoint.starts_with("https://") {
        return true;
    }
    let host = if let Some(bracketed) = authority.strip_prefix('[') {
        bracketed.split(']').next().unwrap_or_default()
    } else {
        authority.split(':').next().unwrap_or_default()
    };
    host == "localhost"
        || host
            .parse::<std::net::Ipv4Addr>()
            .is_ok_and(|ip| ip.is_loopback())
        || host
            .parse::<std::net::Ipv6Addr>()
            .is_ok_and(|ip| ip.is_loopback())
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
    if !endpoint_allowed(&endpoint) {
        return Err(ConfigError::schema(
            format!("{key}.endpoint"),
            ConfigIssue::EndpointNotAllowed,
        ));
    }
    let credential_ref = string_field(table, &key, "credential_ref")?;
    let region = string_field(table, &key, "region")?;
    let profile = string_field(table, &key, "profile")?;
    for field in table.iter().map(|(field, _)| field) {
        match field {
            "kind" | "endpoint" | "credential_ref" | "region" | "profile" => {}
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
        region,
        profile,
    })
}

fn profile(name: &str, item: &Item) -> Result<Profile, ConfigError> {
    let profile_table = table_like(name, item)?;
    let profile_key = format!("profiles.{name}");
    let mut credential_ref = None;
    for (field, value) in profile_table.iter() {
        match field {
            "credential_ref" => {
                let raw = value.as_str().ok_or_else(|| {
                    ConfigError::schema(
                        format!("{profile_key}.credential_ref"),
                        ConfigIssue::ExpectedString {
                            field: "credential_ref".to_string(),
                        },
                    )
                })?;
                // Never echo the value: diagnostics stay secret-free.
                credential_ref_admitted(raw, &format!("{profile_key}.credential_ref")).map_err(
                    |issue| ConfigError::schema(format!("{profile_key}.credential_ref"), issue),
                )?;
                credential_ref = Some(raw.to_string());
            }
            other => {
                return Err(ConfigError::schema(
                    format!("{profile_key}.{other}"),
                    ConfigIssue::UnknownKey {
                        key: other.to_string(),
                        known: PROFILE_KEYS,
                    },
                ));
            }
        }
    }
    Ok(Profile { credential_ref })
}

/// The `[hooks]` section: one entry per `<event>@<scope>` key, each a
/// program declaration. Every rejection names the key it refused — a hook
/// is a program the executor runs, so an entry this schema cannot read is
/// never skipped silently.
fn hooks_table(table: &dyn TableLike) -> Result<Hooks, ConfigError> {
    let mut hooks = Hooks::default();
    for (key, item) in table.iter() {
        let address = format!("hooks.{key}");
        let not_addressable = || {
            ConfigError::schema(
                &address,
                ConfigIssue::HookEntryNotAddressable {
                    key: address.clone(),
                },
            )
        };
        let Some((event, scope)) = key.split_once('@') else {
            return Err(not_addressable());
        };
        if event.is_empty() || scope.is_empty() {
            return Err(not_addressable());
        }
        if !HOOK_EVENTS.contains(&event) {
            return Err(ConfigError::schema(
                format!("{address}.event"),
                ConfigIssue::UnsupportedHookEvent {
                    event: event.to_string(),
                },
            ));
        }
        let entry = table_like(&address, item)?;
        let mut command = None;
        let mut args = Vec::new();
        for (field, value) in entry.iter() {
            match field {
                "command" => {
                    let raw = value.as_str().ok_or_else(|| {
                        ConfigError::schema(
                            format!("{address}.command"),
                            ConfigIssue::ExpectedString {
                                field: "command".to_string(),
                            },
                        )
                    })?;
                    let program = PathBuf::from(raw);
                    // A hook is executed, not resolved: a bare name would
                    // leave the program to `PATH` instead of the document.
                    if !program.is_absolute() {
                        return Err(ConfigError::schema(
                            format!("{address}.command"),
                            ConfigIssue::HookCommandNotAbsolutePath {
                                key: format!("{address}.command"),
                            },
                        ));
                    }
                    command = Some(program);
                }
                "args" => {
                    let args_key = format!("{address}.args");
                    let Some(items) = value.as_array() else {
                        return Err(ConfigError::schema(
                            &args_key,
                            ConfigIssue::HookArgsInvalid {
                                key: args_key.clone(),
                            },
                        ));
                    };
                    for item in items {
                        let Some(arg) = item.as_str() else {
                            return Err(ConfigError::schema(
                                &args_key,
                                ConfigIssue::HookArgsInvalid {
                                    key: args_key.clone(),
                                },
                            ));
                        };
                        args.push(arg.to_string());
                    }
                }
                other => {
                    return Err(ConfigError::schema(
                        format!("{address}.{other}"),
                        ConfigIssue::UnknownKey {
                            key: other.to_string(),
                            known: HOOK_KEYS,
                        },
                    ));
                }
            }
        }
        let Some(command) = command else {
            return Err(ConfigError::schema(
                format!("{address}.command"),
                ConfigIssue::Required {
                    field: format!("{address}.command"),
                },
            ));
        };
        hooks.entries.insert(
            key.to_string(),
            HookEntry {
                event: event.to_string(),
                scope: scope.to_string(),
                command,
                args,
            },
        );
    }
    Ok(hooks)
}

/// The `[mcp]` section: one declared server per `servers.<name>` row. Only
/// `servers` exists, so a row this schema cannot read is a refusal naming its
/// key instead of a server that silently disappears.
fn mcp_section(
    table: &dyn TableLike,
) -> Result<BTreeMap<String, McpServerDeclaration>, ConfigError> {
    let mut servers = BTreeMap::new();
    for (key, item) in table.iter() {
        match key {
            "servers" => servers = mcp_servers_table(table_like("mcp.servers", item)?)?,
            other => {
                return Err(ConfigError::schema(
                    format!("mcp.{other}"),
                    ConfigIssue::UnknownKey {
                        key: other.to_string(),
                        known: &["servers"],
                    },
                ));
            }
        }
    }
    Ok(servers)
}

/// The `[mcp.servers]` table: one operator-owned program declaration per name.
fn mcp_servers_table(
    table: &dyn TableLike,
) -> Result<BTreeMap<String, McpServerDeclaration>, ConfigError> {
    let mut servers = BTreeMap::new();
    for (name, item) in table.iter() {
        let address = format!("mcp.servers.{name}");
        if !is_bounded_server_name(name) {
            return Err(ConfigError::schema(
                &address,
                ConfigIssue::McpServerNameInvalid {
                    name: name.to_string(),
                },
            ));
        }
        servers.insert(name.to_string(), mcp_server_declaration(&address, item)?);
    }
    Ok(servers)
}

/// One `[mcp.servers.<name>]` row: the program the client launches, its
/// arguments, its environment, the origin its egress is admitted against and,
/// when declared, the credential reference this server alone resolves.
fn mcp_server_declaration(address: &str, item: &Item) -> Result<McpServerDeclaration, ConfigError> {
    let entry = table_like(address, item)?;
    let mut origin = None;
    let mut program = None;
    let mut args = Vec::new();
    let mut env = BTreeMap::new();
    let mut credential = None;
    for (field, value) in entry.iter() {
        let field_key = format!("{address}.{field}");
        match field {
            "origin" => origin = mcp_string(&field_key, value)?,
            "program" => {
                let raw = mcp_string(&field_key, value)?.ok_or_else(|| {
                    ConfigError::schema(
                        &field_key,
                        ConfigIssue::Required {
                            field: field_key.clone(),
                        },
                    )
                })?;
                let declared = PathBuf::from(raw);
                // A declared server is executed, never resolved: a bare name
                // would leave the program to `PATH` instead of the document.
                if !declared.is_absolute() {
                    return Err(ConfigError::schema(
                        field_key.clone(),
                        ConfigIssue::McpProgramNotAbsolutePath { key: field_key },
                    ));
                }
                program = Some(declared);
            }
            "args" => args = mcp_string_array(&field_key, value)?,
            "env" => env = mcp_env_table(&field_key, value)?,
            "credential" => credential = Some(mcp_credential_declaration(&field_key, value)?),
            other => {
                return Err(ConfigError::schema(
                    format!("{address}.{other}"),
                    ConfigIssue::UnknownKey {
                        key: other.to_string(),
                        known: MCP_SERVER_KEYS,
                    },
                ));
            }
        }
    }
    let origin = origin.ok_or_else(|| {
        ConfigError::schema(
            format!("{address}.origin"),
            ConfigIssue::Required {
                field: format!("{address}.origin"),
            },
        )
    })?;
    // The destination is the runtime's own grammar, checked here: a malformed
    // origin is refused with the document, never deferred to the first call.
    if !is_bounded_origin(&origin) {
        return Err(ConfigError::schema(
            format!("{address}.origin"),
            ConfigIssue::McpOriginInvalid {
                key: format!("{address}.origin"),
            },
        ));
    }
    let program = program.ok_or_else(|| {
        ConfigError::schema(
            format!("{address}.program"),
            ConfigIssue::Required {
                field: format!("{address}.program"),
            },
        )
    })?;
    Ok(McpServerDeclaration {
        origin,
        program,
        args,
        env,
        credential,
    })
}

/// One `[mcp.servers.<name>.credential]` row. The reference is the scoped
/// secret grammar every other credential carrier enforces, and `origin` is the
/// origin it was enrolled for — a mismatch with the server's own origin is
/// refused at resolution, so a foreign credential is never handed over.
fn mcp_credential_declaration(
    address: &str,
    item: &Item,
) -> Result<McpCredentialDeclaration, ConfigError> {
    let entry = table_like(address, item)?;
    let mut reference = None;
    let mut origin = None;
    let mut variable = None;
    for (field, value) in entry.iter() {
        let field_key = format!("{address}.{field}");
        match field {
            "reference" => reference = mcp_string(&field_key, value)?,
            "origin" => origin = mcp_string(&field_key, value)?,
            "variable" => variable = mcp_string(&field_key, value)?,
            other => {
                return Err(ConfigError::schema(
                    format!("{address}.{other}"),
                    ConfigIssue::UnknownKey {
                        key: other.to_string(),
                        known: MCP_CREDENTIAL_KEYS,
                    },
                ));
            }
        }
    }
    let required = |field: &str, value: Option<String>| {
        value.ok_or_else(|| {
            ConfigError::schema(
                format!("{address}.{field}"),
                ConfigIssue::Required {
                    field: format!("{address}.{field}"),
                },
            )
        })
    };
    let reference = required("reference", reference)?;
    credential_ref_admitted(&reference, &format!("{address}.reference"))
        .map_err(|issue| ConfigError::schema(format!("{address}.reference"), issue))?;
    Ok(McpCredentialDeclaration {
        reference,
        origin: required("origin", origin)?,
        variable: required("variable", variable)?,
    })
}

fn mcp_string(key: &str, value: &Item) -> Result<Option<String>, ConfigError> {
    match value.as_str() {
        Some(text) => Ok(Some(text.to_string())),
        None => Err(ConfigError::schema(
            key,
            ConfigIssue::ExpectedString {
                field: key.to_string(),
            },
        )),
    }
}

fn mcp_string_array(key: &str, value: &Item) -> Result<Vec<String>, ConfigError> {
    let Some(items) = value.as_array() else {
        return Err(ConfigError::schema(
            key,
            ConfigIssue::McpArgsInvalid {
                key: key.to_string(),
            },
        ));
    };
    let mut args = Vec::new();
    for item in items {
        let Some(arg) = item.as_str() else {
            return Err(ConfigError::schema(
                key,
                ConfigIssue::McpArgsInvalid {
                    key: key.to_string(),
                },
            ));
        };
        args.push(arg.to_string());
    }
    Ok(args)
}

fn mcp_env_table(key: &str, value: &Item) -> Result<BTreeMap<String, String>, ConfigError> {
    let Some(table) = value.as_table_like() else {
        return Err(ConfigError::schema(
            key,
            ConfigIssue::McpEnvInvalid {
                key: key.to_string(),
            },
        ));
    };
    let mut env = BTreeMap::new();
    for (name, item) in table.iter() {
        let Some(text) = item.as_str() else {
            return Err(ConfigError::schema(
                format!("{key}.{name}"),
                ConfigIssue::McpEnvInvalid {
                    key: format!("{key}.{name}"),
                },
            ));
        };
        env.insert(name.to_string(), text.to_string());
    }
    Ok(env)
}

/// A declared server's name. It reaches a file name, a retained record and the
/// process's own argv, so the grammar is the wire's bounded-token one.
fn is_bounded_server_name(raw: &str) -> bool {
    !raw.is_empty()
        && raw.len() <= 64
        && raw
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ':' | '/'))
}

/// A declared server's origin: the destination the executor's egress admission
/// binds and a credential reference is enrolled for. The grammar lives here,
/// where the document is parsed, so a spelling the runtime would refuse is a
/// load-time refusal; [`crate::mcp::McpCall::validate`] re-checks the same
/// bound at the seam for a server built outside the document.
pub(crate) fn is_bounded_origin(raw: &str) -> bool {
    !raw.is_empty()
        && raw.len() <= 128
        && raw.contains("://")
        && raw
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ':' | '/' | '+'))
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
                    let key = format!("models.purposes.{name}");
                    models
                        .purposes
                        .insert(name.to_string(), purpose_def(&key, name, entry)?);
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

/// One `models.purposes.<name>` row: the binding a purpose carries, judged by
/// the one purpose schema. The whole-table parse and the targeted rebinding
/// both read a row through this function, so a row is never judged by two
/// rule sets — and a move that names its own row reads that row alone instead
/// of every sibling ([`Config::rebind_purpose`]).
fn purpose_def(key: &str, name: &str, entry: &Item) -> Result<PurposeDef, ConfigError> {
    let purpose = table_like(name, entry)?;
    let mut def = PurposeDef::default();
    for (field, value) in purpose.iter() {
        match field {
            "group" => {
                def.group = Some(value.as_str().map(str::to_string).ok_or_else(|| {
                    ConfigError::schema(
                        format!("{key}.group"),
                        ConfigIssue::GroupReferenceNotString,
                    )
                })?);
            }
            "model" => def.model = Some(model_assign(value, &format!("{key}.model"))?),
            "effort" => def.effort = Some(effort_assign(value, &format!("{key}.effort"))?),
            "fallback" => def.fallback = Some(fallback_assign(value, &format!("{key}.fallback"))?),
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
    Ok(def)
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

fn toml_mode<'a>(table: &'a dyn TableLike, key: &str) -> Result<&'a str, ConfigError> {
    table.get("mode").and_then(Item::as_str).ok_or_else(|| {
        ConfigError::schema(
            format!("{key}.mode"),
            ConfigIssue::Required {
                field: "mode".to_string(),
            },
        )
    })
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
    let mode = toml_mode(table, key)?;
    match mode {
        "inherit" => Ok(ModelAssign::Inherit),
        "auto" => {
            let pool = match table.get("pool") {
                None => None,
                Some(value) => Some(name_array(
                    value,
                    &format!("{key}.pool"),
                    ConfigIssue::PoolNotArray,
                    ConfigIssue::PoolEntryNotString,
                )?),
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
    let mode = toml_mode(table, key)?;
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
    let mode = toml_mode(table, key)?;
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

/// Effective snapshot over the precedence passes: the base document this build
/// serves, then the user file. The layers are composed here and nowhere else —
/// a value's layer decides it, never a comparison against another layer's
/// value (DEC-009).
#[derive(Debug, Clone)]
pub struct EffectiveConfig {
    pub sources_digest: String,
    /// The base layer the effective view was composed over (AC-054): its
    /// version, its digest and the values it supplies.
    pub base: BaseLayer,
    pub parsed: Option<Config>,
    pub workflow_entry: ConfigEntry,
    pub decisions_entry: ConfigEntry,
    /// The context guard's served entry: the base answers an absent override,
    /// so a base that moves `auto_compact` moves this entry with it.
    pub context_entry: ConfigEntry,
}

/// The digest naming the configuration sources in order — the revision a
/// `config.read` result and a `decisions.control` mutation precondition
/// quote. Recomputed after every landed edit, so a stale precondition
/// always conflicts instead of overwriting a concurrent write.
pub fn sources_digest(user_bytes: &[u8]) -> String {
    sources_digest_on(BaseSource::SHIPPED, user_bytes)
}

/// [`sources_digest`] over an explicit base: the layer order and its identity
/// live in one place, so a base that differs from the shipped one is named by
/// the same recipe instead of by a second hasher.
pub fn sources_digest_on(base: BaseSource<'_>, user_bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(base.text().as_bytes());
    hasher.update(user_bytes);
    hex(&hasher.finalize())
}

pub fn resolve_effective(user_toml: Option<&str>) -> Result<EffectiveConfig, ConfigError> {
    resolve_effective_on(BaseSource::SHIPPED, user_toml)
}

/// [`resolve_effective`] over an explicit base (AC-054, DEC-009): production
/// passes [`BaseSource::SHIPPED`], a test passes the next base. Both are parsed
/// by the document schema before any value is read, so a base the schema would
/// reject never answers a read.
pub fn resolve_effective_on(
    base: BaseSource<'_>,
    user_toml: Option<&str>,
) -> Result<EffectiveConfig, ConfigError> {
    // The user document is parsed and validated once: a document the schema
    // refuses never answers a read, and the value this view keeps is the one
    // that passed — never a second parse whose refusal is discarded.
    let parsed = user_toml.map(Config::parse_validated).transpose()?;
    let layer = base.layer()?;
    let mut effective = EffectiveConfig {
        sources_digest: sources_digest_on(base, user_toml.unwrap_or("").as_bytes()),
        workflow_entry: base_flag_entry(
            WORKFLOW_KEY,
            layer.workflow.unwrap_or(true),
            &layer.digest,
        ),
        decisions_entry: base_decisions_entry(
            layer.decisions.unwrap_or(DecisionModeValue::Ask),
            &layer.digest,
        ),
        context_entry: base_flag_entry(
            CONTEXT_AUTO_COMPACT_KEY,
            layer.context.auto_compact.unwrap_or(false),
            &layer.digest,
        ),
        base: layer,
        parsed,
    };
    effective.refresh_mode_entries(&hex(&Sha256::digest(user_toml.unwrap_or("").as_bytes())));
    // The composed document is the one the runtime acts on, so it passes the
    // same referential checks a file document passes: a base that names a
    // connection or group the installation does not declare is refused here,
    // where the layers meet, instead of failing at dispatch.
    let composed = effective.composed();
    check_model_references(&composed.connections, &composed.models)?;
    Ok(effective)
}

impl EffectiveConfig {
    /// The base version the effective view was composed over (INV-010a).
    #[must_use]
    pub fn base_version(&self) -> u64 {
        self.base.version
    }

    /// The user's own document — the retained layer a read names as its
    /// source. A base value is never reported through it (AC-054), so a read
    /// surface can tell what the user set from what the base supplies.
    #[must_use]
    pub fn retained(&self) -> Config {
        self.parsed.clone().unwrap_or_default()
    }

    /// The config a dispatch prepares against (AC-054): the user document over
    /// the base layer. A user value wins its own slot even when it equals the
    /// base's, because the layer supplies each value — `workflow: false`, a pin
    /// and an explicit default all keep their provenance across a base change.
    /// The base fills what the user's document leaves to the layer below: an
    /// absent override, a purpose row it does not write, a default slot it
    /// defers.
    #[must_use]
    pub fn composed(&self) -> Config {
        let user = self.parsed.clone().unwrap_or_default();
        Config {
            version: user.version,
            workflow: Workflow {
                enabled: user.workflow.enabled.or(self.base.workflow),
            },
            decisions: Decisions {
                mode: user.decisions.mode.or(self.base.decisions),
            },
            context: Context {
                auto_compact: user.context.auto_compact.or(self.base.context.auto_compact),
            },
            connections: user.connections,
            profiles: user.profiles,
            models: compose_models(&self.base.models, user.models),
            hooks: user.hooks,
            mcp: user.mcp,
            raw: user.raw,
        }
    }

    /// Rebuilds the entries the read surface serves from the retained
    /// document — pre-publication the retained doc is the effective view,
    /// so an accepted edit must move these entries with the doc.
    /// `revision` names the retained doc's byte digest; an absent
    /// override keeps the base's value.
    pub fn refresh_mode_entries(&mut self, revision: &str) {
        self.workflow_entry = match self
            .parsed
            .as_ref()
            .and_then(|config| config.workflow.enabled)
        {
            Some(value) => user_flag_entry(WORKFLOW_KEY, value, revision),
            None => base_flag_entry(
                WORKFLOW_KEY,
                self.base.workflow.unwrap_or(true),
                &self.base.digest,
            ),
        };
        self.decisions_entry = match self
            .parsed
            .as_ref()
            .and_then(|config| config.decisions.mode)
        {
            Some(value) => user_decisions_entry(value, revision),
            None => base_decisions_entry(
                self.base.decisions.unwrap_or(DecisionModeValue::Ask),
                &self.base.digest,
            ),
        };
        self.context_entry = match self
            .parsed
            .as_ref()
            .and_then(|config| config.context.auto_compact)
        {
            Some(value) => user_flag_entry(CONTEXT_AUTO_COMPACT_KEY, value, revision),
            None => base_flag_entry(
                CONTEXT_AUTO_COMPACT_KEY,
                self.base.context.auto_compact.unwrap_or(false),
                &self.base.digest,
            ),
        };
    }

    /// The mode a material fork observes: the dispatch view's own answer, so the
    /// status surface and the fork path read one composition — an absent
    /// override resolves through the base layer, an explicit `inherit` still
    /// names the absent override.
    pub fn decisions_mode(&self) -> DecisionMode {
        self.composed().decisions_mode()
    }
}

/// The base layer's models beneath the user's (AC-054, DEC-009).
///
/// A row, a group or a default slot is the unit of precedence. A purpose row the
/// user writes is the user's whole: every resolved source names a document key,
/// so a base value under a key the user wrote would be attributed to the user,
/// and the user's own binding — one group or one model — would be replaced by
/// the base's other slot of the same choice. What the user's document leaves to
/// the layer below is the base's: a purpose row it does not write, a group it
/// does not declare, and a default slot it defers ([`ModelAssign::Inherit`] /
/// [`EffortAssign::Inherit`], the deferred spellings a required slot has).
fn compose_models(base: &Models, user: Models) -> Models {
    let mut groups = base.groups.clone();
    for (name, def) in user.groups {
        groups.insert(name, def);
    }
    let mut purposes = base.purposes.clone();
    for (name, def) in user.purposes {
        purposes.insert(name, def);
    }
    Models {
        defaults: compose_defaults(base.defaults.as_ref(), user.defaults),
        groups,
        purposes,
    }
}

/// The default slots: a slot the user states wins, a slot the user defers takes
/// the base's value, and a store with no user document reads the base as its
/// only layer rather than as a merge. `fallback` has no deferred spelling, so it
/// is the user's wherever a user document states it.
fn compose_defaults(base: Option<&Defaults>, user: Option<Defaults>) -> Option<Defaults> {
    let Some(mut defaults) = user else {
        return base.cloned();
    };
    if let Some(base) = base {
        if matches!(defaults.model, ModelAssign::Inherit) {
            defaults.model = base.model.clone();
        }
        if matches!(defaults.effort, EffortAssign::Inherit) {
            defaults.effort = base.effort.clone();
        }
    }
    Some(defaults)
}

/// A user-sourced read entry for one boolean carrier.
fn user_flag_entry(key: &str, value: bool, revision: &str) -> ConfigEntry {
    ConfigEntry {
        key: key.to_string(),
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

/// The digest of the shipped defaults — the revision a shipped-sourced
/// read entry names.
pub fn shipped_revision() -> String {
    BaseSource::SHIPPED.digest()
}

/// A base-sourced read entry for one boolean carrier: the value comes from the
/// base document and the revision names its bytes, so a base that moves the
/// value moves the entry with it.
fn base_flag_entry(key: &str, value: bool, revision: &str) -> ConfigEntry {
    ConfigEntry {
        key: key.to_string(),
        effective: ConfigViewValue::Visible {
            value: Value::Bool(value),
        },
        source: ConfigSource {
            kind: "shipped".to_string(),
            revision: revision.to_string(),
            target: None,
        },
    }
}

fn user_decisions_entry(value: DecisionModeValue, revision: &str) -> ConfigEntry {
    ConfigEntry {
        key: DECISIONS_MODE_KEY.to_string(),
        effective: ConfigViewValue::Visible {
            value: Value::String(value.as_str().to_string()),
        },
        source: ConfigSource {
            kind: "user".to_string(),
            revision: revision.to_string(),
            target: None,
        },
    }
}

fn base_decisions_entry(value: DecisionModeValue, revision: &str) -> ConfigEntry {
    ConfigEntry {
        key: DECISIONS_MODE_KEY.to_string(),
        effective: ConfigViewValue::Visible {
            value: Value::String(value.as_str().to_string()),
        },
        source: ConfigSource {
            kind: "shipped".to_string(),
            revision: revision.to_string(),
            target: None,
        },
    }
}

/// What `decisions.control` op `status` reports: the key's served entry
/// plus the mode a fork would actually observe — an `inherit` override
/// reads "inherit" in the entry but resolves "ask" here.
#[derive(Debug, Clone, Serialize)]
pub struct ConfigExplainResult {
    pub key: String,
    pub entry: ConfigEntry,
    pub effective: String,
    pub source_digest: String,
}

/// What a `decisions.control` mutation reports once the journaled
/// publication lands: the key, the edit's digest and the journal row's
/// owner/admission identity — the same facts `config.set` reports.
#[derive(Debug, Clone, Serialize)]
pub struct ConfigMutationResult {
    pub key: String,
    pub digest: String,
    pub owner: String,
    pub admission_seq: u64,
}

// ----- crash-safe publication -----

/// Ceiling for reading a publication target; a larger path is treated as
/// unattributable instead of being pulled into memory whole.
const PUBLICATION_MAX_BYTES: usize = 1 << 20;

/// `O_NONBLOCK` for the checked publication open, per platform
/// (asm-generic fcntl.h: Linux `1 << 11` = 0o4000; Darwin fcntl.h
/// 0x0004 — the same values the executor read backends carry): a FIFO
/// swapped onto the target path must not block the open itself. The
/// regular-file check on the opened handle rejects it right after;
/// regular files ignore the flag.
#[cfg(target_os = "linux")]
const O_NONBLOCK: i32 = 0o4000;
#[cfg(target_os = "macos")]
const O_NONBLOCK: i32 = 0x0004;

/// One journaled publication intent: the bytes we intended to publish, what
/// was at the target when the intent was staged — its digest and its write
/// identity, `(dev, ino)` plus the reuse token — and the journal's
/// admission order key. The managed write is in-place, so a staged
/// identity whose `(dev, ino)` and reuse token both still match after a
/// crash attributes the bytes to our own write; a replaced inode, a
/// reused pair under another token, or an identity without a token never
/// does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicationIntent {
    pub owner: String,
    pub target: String,
    pub admission_seq: u64,
    pub intended_digest: String,
    pub base_digest: Option<String>,
    pub publish_identity: Option<WriteIdentity>,
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
/// with the target's current bytes digest and write identity (`(dev, ino)`
/// plus the reuse token), so a crash between bytes and receipt stays
/// classifiable.
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
/// CLI carriers both admit here, keyed on the target's file identity —
/// `(dev, ino)` plus its reuse token — and the intended digest. A command that is still pending is never
/// journaled twice — the replay observes the pending intent (one control
/// event), so the command can later complete exactly once. A replay of a
/// command whose intent already went terminal returns that terminal
/// result, but only while the bytes the row intended still hold at the
/// file: the row that produced the current bytes is the terminal winner,
/// never a max over `admission_seq` — the counter is per target *string*,
/// so one file journaled under two spellings carries two counters and
/// cross-spelling seq order is not chronology. Anything else admits as a
/// fresh instance. A pending row whose match no reuse token confirms is
/// still the answer; a terminal one is refused rather than replayed or
/// restaged.
///
/// The returned row may carry a different target spelling than the one
/// this admission named: `(owner, admission_seq)` is an informational
/// echo, and recovery addresses the row's own target.
///
/// # Errors
/// Returns the [`PublicationError`] `stage_publication` returns for a
/// fresh admission, [`PublicationError::Journal`] when the journal
/// cannot be read, and [`PublicationError::Write`] carrying
/// [`crate::executor::WorkerError::WriteIdentityUnattested`] when a
/// terminal row may own the current bytes but no reuse token can confirm
/// it.
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
    // One observation keys every match on the file's `(dev, ino)` and
    // reuse token — two spellings of one file are one target — and later
    // confirms whether a terminal row's bytes still hold.
    let sight = observe_target(&target_key);
    let pending = store.pending_publications().map_err(journal_error)?;
    for intent in pending {
        // A pending row whose file match no reuse token can confirm is
        // still returned instead of staging a second row: its owning
        // publish or recovery refuses the unattested write itself.
        if intent.intended_digest == edit.digest
            && same_target_file(&intent, &sight, &target_key) != FileAttribution::Different
        {
            return Ok(PublicationAdmission::Pending(intent));
        }
    }
    let applied = store.applied_publications().map_err(journal_error)?;
    if let TargetSight::Present { digest, .. } = &sight
        && digest == &edit.digest
    {
        let mut unverifiable = None;
        for intent in applied
            .iter()
            .filter(|intent| intent.intended_digest == edit.digest)
        {
            match same_target_file(intent, &sight, &target_key) {
                FileAttribution::Same => return Ok(PublicationAdmission::Applied(intent.clone())),
                FileAttribution::Unverifiable(cause) => {
                    unverifiable.get_or_insert(cause);
                }
                FileAttribution::Different => {}
            }
        }
        // A terminal row that may own these bytes but cannot be confirmed
        // is neither the historical answer nor room for a fresh row.
        if let Some(cause) = unverifiable {
            return Err(PublicationError::Write(
                crate::executor::WorkerError::WriteIdentityUnattested { cause },
            ));
        }
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
    crate::executor::write_once(&scope_root, Path::new(target), identity, bytes)
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

/// How one staged write identity relates to the identity now at a target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileAttribution {
    /// Another file: a different `(dev, ino)`, or the same pair under a
    /// different reuse token — a later file reusing the pair.
    Different,
    /// The staged file itself: the same `(dev, ino)` and the same reuse
    /// token on both sides.
    Same,
    /// The same `(dev, ino)` (or, with no staged identity, the same
    /// spelling) that no reuse token can confirm.
    Unverifiable(Unattested),
}

/// Same-file attribution between a staged and a current identity: only an
/// equal `(dev, ino)` with equal reuse tokens on both sides proves it.
fn attribute(staged: WriteIdentity, current: WriteIdentity) -> FileAttribution {
    if staged.file() != current.file() {
        return FileAttribution::Different;
    }
    match (staged.reuse(), current.reuse()) {
        (Ok(staged), Ok(current)) if staged == current => FileAttribution::Same,
        (Ok(_), Ok(_)) => FileAttribution::Different,
        (Err(cause), _) | (_, Err(cause)) => FileAttribution::Unverifiable(cause),
    }
}

/// Whether one journaled intent targets the same file this admission
/// names: the opened `(dev, ino)` identity plus its reuse token decides,
/// and a side without a token leaves the match unverifiable; a row that
/// journaled no identity matches by spelling, unverifiably. Path
/// spellings decide alone only when the target cannot be observed (the
/// file is gone or unreadable) — such a sight never reaches a terminal
/// answer.
fn same_target_file(
    intent: &PublicationIntent,
    sight: &TargetSight,
    target_key: &str,
) -> FileAttribution {
    match sight {
        TargetSight::Present {
            identity: Some(current),
            ..
        } => match intent.publish_identity {
            Some(staged) => attribute(staged, *current),
            None if intent.target == target_key => {
                FileAttribution::Unverifiable(Unattested::Unrecorded)
            }
            None => FileAttribution::Different,
        },
        _ if spelled_same_file(&intent.target, target_key) => FileAttribution::Same,
        _ => FileAttribution::Different,
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

/// One consistent snapshot of the target: the write identity, its reuse
/// token included, and the digested bytes were taken through the same
/// opened handle.
struct TargetObservation {
    digest: String,
    identity: WriteIdentity,
    bytes: Vec<u8>,
}

/// Opens the target exactly once and reads it through that same handle,
/// mirroring the executor's bounded read: the open is non-blocking, the
/// opened handle itself must be a regular file (a FIFO swapped onto the
/// path can neither hang the open nor slip past the fd-level check), and
/// the read stops one byte past the ceiling so a file that grows past the
/// limit between `fstat` and the read is caught by the length re-check
/// instead of being read unbounded. The reuse token comes from that same
/// handle: a filesystem without one leaves the identity explicitly
/// unattested, and any other token failure fails the observation.
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
    let reuse = match rivect_sandbox_helper::reuse_token(&file) {
        Ok(token) => Ok(token),
        Err(rivect_sandbox_helper::ReuseTokenError::Unsupported) => Err(Unattested::Unsupported),
        Err(error) => return Err(std::io::Error::other(error)),
    };
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    file.take(PUBLICATION_MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > PUBLICATION_MAX_BYTES {
        return Err(target_too_large());
    }
    Ok(TargetObservation {
        digest: hex(&Sha256::digest(&bytes)),
        identity: WriteIdentity::new(FileIdentity::from_metadata(&metadata), reuse),
        bytes,
    })
}

enum TargetSight {
    Absent,
    Present {
        digest: String,
        identity: Option<WriteIdentity>,
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

/// Classifies one journaled intent against the bytes now at its target:
/// intended bytes are our own write only under the staged `(dev, ino)`
/// and reuse token.
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
                    (Some(staged), Some(current)) => match attribute(staged, current) {
                        FileAttribution::Same => PublicationVerdict::ExactlyNew,
                        FileAttribution::Different => PublicationVerdict::ByteIdenticalThird,
                        // The same `(dev, ino)` without a reuse token on
                        // both sides may be a later file reusing the pair.
                        FileAttribution::Unverifiable(_) => PublicationVerdict::Unknown,
                    },
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
