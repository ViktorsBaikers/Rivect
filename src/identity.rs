//! Semantic identity migration (AC-056, REQ-046, master §12A.9): the versioned
//! `old_id → new_id` rule set a product base is released with, the placement a
//! split routes each subject into, and the guard that keeps a release out of
//! the user's reserved `personal:` namespace.
//!
//! Identity is the key name, never an array position. A rule names the id an
//! experience was recorded under and the id it keeps, so rebinding follows the
//! meaning, and the order of a fallback or purpose list never decides what
//! moves. The types here are rules and pure placement (P-002): the store owns
//! every statement and every row the rules move, and the config owner moves
//! the purpose binding a role rule names.
//!
//! The unit one rule places is one subject of one kind — the purpose an
//! instruction was recorded for, the capability a selection condition
//! overrides — not one stored row. A release cannot route two experiences that
//! were recorded under one subject into two different parts: a second part
//! claiming the same subject is refused ([`IdentityError::Ambiguous`]), and
//! every binding of that subject moves to the one part the rule names. A rule
//! set therefore says where a subject goes; it cannot say that one row of a
//! subject stays while another leaves.

use crate::actions::weighed_capability;
use crate::contracts::ErrorCode;
use crate::state::StoreError;

/// The namespace the user's own identities live in (master §12A.9): a release
/// rule set and a base document may never claim an id inside it, because a
/// mapping that could name it could rebind or overwrite the user's own
/// experience. A user document keeps the namespace — it is the user's.
pub const PERSONAL_NAMESPACE: &str = "personal";

/// Whether `id` claims the reserved namespace: a `:`-separated segment equal to
/// [`PERSONAL_NAMESPACE`], case-folded, so `personal:mine`, `Personal:Mine` and
/// `role:personal:mine` are one claim and a word that merely contains the
/// letters is not.
#[must_use]
pub fn claims_personal_namespace(id: &str) -> bool {
    let segments = id.split(':').collect::<Vec<_>>();
    segments.len() > 1
        && segments
            .iter()
            .any(|segment| segment.eq_ignore_ascii_case(PERSONAL_NAMESPACE))
}

/// What kind of identity a rule speaks about. A role is a request purpose: the
/// config row that binds it (`models.purposes.<name>`) and the purpose a
/// learned condition names are one identity, so one role rule moves both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityKind {
    /// A catalog capability the selection weighs.
    Action,
    /// A request purpose: a configured role and the purpose experience binds.
    Role,
}

impl IdentityKind {
    /// The stored name and the error text.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Action => "action",
            Self::Role => "role",
        }
    }

    /// The kind a stored name spells, `None` outside the vocabulary.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "action" => Some(Self::Action),
            "role" => Some(Self::Role),
            _ => None,
        }
    }
}

impl std::fmt::Display for IdentityKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How one identity changed between two bases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationRule {
    /// One id keeps its meaning under a new name: every binding moves.
    Rename,
    /// One identity became several: each part inherits the subject it names,
    /// and a subject no part names stays for reconciliation. The inherited
    /// subject is the whole experience recorded under it — every binding of
    /// that subject and kind moves into the one part — because a rule states
    /// where a subject goes, not which of its rows goes where.
    Split,
    /// Several identities became one: the bindings of every source move, and
    /// no two of them are collapsed into one.
    Merge,
}

impl MigrationRule {
    /// The stored name and the error text.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rename => "rename",
            Self::Split => "split",
            Self::Merge => "merge",
        }
    }

    /// The rule a stored name spells, `None` outside the vocabulary.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "rename" => Some(Self::Rename),
            "split" => Some(Self::Split),
            "merge" => Some(Self::Merge),
            _ => None,
        }
    }
}

impl std::fmt::Display for MigrationRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One versioned mapping entry (master §12A.9). It belongs to the product base
/// that was released with it, so an older mapping never rebinds rows a newer
/// base already moved.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct IdentityMigration {
    /// The base version whose release ships this rule — the base ledger of the
    /// store names the one it serves.
    pub base_version: u64,
    pub kind: IdentityKind,
    pub old_id: String,
    pub new_id: String,
    pub rule: MigrationRule,
    /// The subject a split part inherits: a binding whose id is this subject
    /// moves into the part, and no other part may claim it. Only a split
    /// states one — a rename or a merge moves the whole binding.
    pub subject: Option<String>,
}

impl IdentityMigration {
    /// A rule that disagrees with its own shape: every refusal below names the
    /// two ids it read and the one thing about them it could not accept.
    fn malformed(&self, detail: &'static str) -> IdentityError {
        IdentityError::Malformed {
            old_id: self.old_id.clone(),
            new_id: self.new_id.clone(),
            detail,
        }
    }

    /// The typed refusals of one rule, checked before it is recorded: an
    /// unknown target and a claimed namespace are refused here, so a rule set
    /// the store admits never names an id this build cannot serve.
    ///
    /// # Errors
    /// Returns [`IdentityError::PersonalNamespace`] when either id claims the
    /// user's namespace, [`IdentityError::Malformed`] when the rule disagrees
    /// with its own shape and [`IdentityError::UnknownTarget`] when an action
    /// rule names a capability the selection does not weigh.
    pub fn validate(&self) -> Result<(), IdentityError> {
        for id in [&self.old_id, &self.new_id] {
            if claims_personal_namespace(id) {
                return Err(IdentityError::PersonalNamespace { id: id.clone() });
            }
        }
        if self.old_id.trim().is_empty() || self.new_id.trim().is_empty() {
            return Err(self.malformed("carries an empty id"));
        }
        if self.old_id == self.new_id {
            return Err(self.malformed("names one id as both source and target"));
        }
        match (self.rule, &self.subject) {
            (MigrationRule::Split, Some(subject)) => {
                if claims_personal_namespace(subject) {
                    return Err(IdentityError::PersonalNamespace {
                        id: subject.clone(),
                    });
                }
                if subject.trim().is_empty() {
                    return Err(self.malformed("names an empty subject"));
                }
                // A part inherits the experience bound to the id being split;
                // any other subject would be a rule nothing could ever place.
                if *subject != self.old_id {
                    return Err(self.malformed("splits an id other than the subject it inherits"));
                }
            }
            (MigrationRule::Split, None) => {
                return Err(self.malformed("splits without naming the subject it inherits"));
            }
            (MigrationRule::Rename | MigrationRule::Merge, Some(_)) => {
                return Err(self.malformed("names a subject without splitting"));
            }
            (MigrationRule::Rename | MigrationRule::Merge, None) => {}
        }
        if self.kind == IdentityKind::Action && !weighed_capability(&self.new_id) {
            return Err(IdentityError::UnknownTarget {
                old_id: self.old_id.clone(),
                new_id: self.new_id.clone(),
                kind: self.kind,
            });
        }
        Ok(())
    }
}

/// Where one stored subject belongs under a rule set (AC-056).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Placement {
    /// Exactly one rule claims the subject: the binding moves to this id.
    Rebound(String),
    /// No rule claims it: the subject stays where it was recorded and is named
    /// for reconciliation (EDGE-007). It is never mapped to a free id.
    Unassigned,
}

/// The rule set one base was released with. Construction is the gate: a set
/// that cannot be applied as written — two parts claiming one subject, a
/// foreign base, a claimed namespace — is refused before any row moves.
///
/// A split part inherits the whole subject its rule names, and a part the
/// release gives no inherited experience needs no rule. An experience the
/// mapping does not confirm therefore keeps its id and is reported for
/// reconciliation ([`NamedSubject`]) instead of being copied into a part it may
/// not belong to. The same holds for one subject carrying several
/// experiences: the mapping states one target for the subject, so all of them
/// move together, and a release that wanted them apart cannot express it here
/// rather than having half of them land somewhere it did not name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityRules {
    base_version: u64,
    migrations: Vec<IdentityMigration>,
}

impl IdentityRules {
    /// The rule set of one base, validated as a whole.
    ///
    /// # Errors
    /// Returns the refusal [`IdentityMigration::validate`] reports and
    /// [`IdentityError::UnknownBase`] for a rule of another base. Two rules
    /// claiming one subject are [`IdentityError::Ambiguous`]: copying one
    /// experience into both parts of a split is not expressible. The same rule
    /// offered twice is a replay, the way a restarted release re-records it.
    pub fn new(
        base_version: u64,
        migrations: Vec<IdentityMigration>,
    ) -> Result<Self, IdentityError> {
        let mut claimed: Vec<(IdentityKind, String, String)> = Vec::new();
        for migration in &migrations {
            if migration.base_version != base_version {
                return Err(IdentityError::UnknownBase {
                    offered: migration.base_version,
                    recorded: base_version,
                });
            }
            migration.validate()?;
            // The subject one rule claims is the id a stored binding carries:
            // the whole source id for a rename or merge, the inherited subject
            // for a split part.
            let subject = migration
                .subject
                .clone()
                .unwrap_or_else(|| migration.old_id.clone());
            if let Some((_, _, first)) = claimed
                .iter()
                .find(|(kind, claimed, _)| *kind == migration.kind && *claimed == subject)
            {
                // The same rule offered twice is the replay a restarted release
                // records again; two targets for one subject are the defect.
                if *first == migration.new_id {
                    continue;
                }
                return Err(IdentityError::Ambiguous {
                    kind: migration.kind,
                    subject,
                    first: first.clone(),
                    second: migration.new_id.clone(),
                });
            }
            claimed.push((migration.kind, subject, migration.new_id.clone()));
        }
        Ok(Self {
            base_version,
            migrations,
        })
    }

    /// The base version whose release shipped this set.
    #[must_use]
    pub const fn base_version(&self) -> u64 {
        self.base_version
    }

    /// The rules in the order they were recorded.
    #[must_use]
    pub fn migrations(&self) -> &[IdentityMigration] {
        &self.migrations
    }

    /// Where a binding whose id is `subject` belongs. A rename or a merge
    /// claims its whole source id; a split claims only the subject its part
    /// inherits — which [`IdentityMigration::validate`] forces to be that same
    /// source id — so a subject no part names stays unassigned instead of being
    /// copied into every part. The answer is per subject: every binding
    /// recorded under one subject of one kind reads the same placement.
    #[must_use]
    pub fn place(&self, kind: IdentityKind, subject: &str) -> Placement {
        self.migrations
            .iter()
            .find(|migration| migration.kind == kind && migration.old_id == subject)
            .map_or(Placement::Unassigned, |migration| {
                Placement::Rebound(migration.new_id.clone())
            })
    }
}

/// One row a rebinding pass moved: the delta, the id it was bound to and the
/// id it is bound to now.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ReboundSubject {
    pub delta_id: String,
    pub kind: IdentityKind,
    pub from: String,
    pub to: String,
}

/// One subject the rule set does not place (EDGE-007): the binding keeps the
/// id it was recorded under and waits for a rule that names it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct NamedSubject {
    pub kind: IdentityKind,
    pub subject: String,
}

/// What one rebinding pass did against the base it serves (AC-056): the rules
/// the base was released with, the rows they moved by meaning and the subjects
/// they left named for reconciliation. A receipt read back from the stored map
/// answers `migrations` — the rules a base carries are durable rows — while
/// `rebound` and `unassigned` are one transition's own account of what it did.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct IdentityRebind {
    pub base_version: u64,
    pub migrations: Vec<IdentityMigration>,
    pub rebound: Vec<ReboundSubject>,
    pub unassigned: Vec<NamedSubject>,
}

/// The typed refusals of the identity owner (P-001). Each one names the ids it
/// refused, so a caller can reconcile without parsing prose.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("storage: {0}")]
    Store(#[from] StoreError),
    /// The rule set is bound to another base than the one the ledger serves: a
    /// mapping is never applied across a base it does not describe.
    #[error("identity rule names base {offered}, but base {recorded} serves")]
    UnknownBase { offered: u64, recorded: u64 },
    /// The reserved user namespace: a release may not claim it (REQ-046).
    #[error("id {id} claims the reserved personal namespace")]
    PersonalNamespace { id: String },
    /// Two rules claim one subject — the shape that would copy an experience
    /// into both parts of a split.
    #[error("subject {subject} of {kind} is claimed by both {first} and {second}")]
    Ambiguous {
        kind: IdentityKind,
        subject: String,
        first: String,
        second: String,
    },
    /// A rule that cannot be applied as written.
    #[error("identity rule {old_id} -> {new_id} {detail}")]
    Malformed {
        old_id: String,
        new_id: String,
        detail: &'static str,
    },
    /// The target is not an id this build can serve, so applying the rule would
    /// activate content the runtime cannot weigh.
    #[error("identity rule {old_id} -> {new_id} names a {kind} this build does not know")]
    UnknownTarget {
        old_id: String,
        new_id: String,
        kind: IdentityKind,
    },
    /// The stored rule of this source and target states another meaning.
    #[error("identity {rule} rule {old_id} -> {new_id} is already recorded with another meaning")]
    Conflicting {
        old_id: String,
        new_id: String,
        rule: MigrationRule,
    },
    /// Two verified conclusions the rule set moves onto one subject disagree:
    /// the definition decides a capability by record order, so keeping both
    /// would silently drop one of them.
    #[error("identity rules would leave {first} and {second} on {kind} {subject} at once")]
    ConflictingBindings {
        kind: IdentityKind,
        subject: String,
        first: &'static str,
        second: &'static str,
    },
    /// The definition the rules would compose reaches past the bound every
    /// other definition-changing path refuses at.
    #[error(
        "the identity rules of base {base_version} compose a {size}-byte definition, over the {limit}-byte bound"
    )]
    CompositionExceeded {
        base_version: u64,
        size: usize,
        limit: usize,
    },
}

impl IdentityError {
    /// The wire code this refusal reports (P-001): a rule the release wrote
    /// wrong is invalid input, a rule that disagrees with the recorded set or
    /// with the definition it composes is a conflict.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Store(error) => error.code(),
            Self::PersonalNamespace { .. }
            | Self::Malformed { .. }
            | Self::UnknownTarget { .. } => ErrorCode::InvalidInput,
            Self::UnknownBase { .. }
            | Self::Ambiguous { .. }
            | Self::Conflicting { .. }
            | Self::ConflictingBindings { .. }
            | Self::CompositionExceeded { .. } => ErrorCode::Conflict,
        }
    }
}
