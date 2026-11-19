//! Disposable projection of one native walk. Scope IDs belong to a build, not a file.

use super::{
    BEARER_ENTRY_BYTES, FileStamp, IndexedSymbol, RowRole, SCOPE_NODE_BYTES, ScopeTable, SymbolOp,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::hash::{DefaultHasher, Hash as _, Hasher as _};
use std::path::{Path, PathBuf};

/// Source-body reads, parser calls and retained documents used by one worker.
#[derive(Default, Debug, Clone, Copy, Serialize, Deserialize)]
pub struct SymbolWork {
    pub read: u64,
    pub parsed: u64,
    pub reused: u64,
}

pub enum ProjectionMode {
    OneShot,
    Retain(Option<SymbolProjection>),
}

pub(super) type ScopeLayout = (usize, Option<Box<str>>);
pub(super) type CachedFile<'s> = (FileRows, &'s [ScopeLayout]);

/// A negative rules out the name, never a positive. False positives only
/// send a file through the ordinary parser. The producer executable is pinned.
#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize)]
pub(super) struct NameFilter([u64; 4]);

impl NameFilter {
    pub(super) fn bits(name: &str) -> [u8; 2] {
        let mut hasher = DefaultHasher::new();
        name.hash(&mut hasher);
        let bytes = hasher.finish().to_le_bytes();
        [bytes[0], bytes[4]]
    }

    pub(super) fn insert(&mut self, name: &str) {
        for bit in Self::bits(name) {
            self.0[usize::from(bit / 64)] |= 1 << (bit % 64);
        }
    }

    pub(super) fn excludes(&self, bits: [u8; 2]) -> bool {
        bits.into_iter()
            .any(|bit| self.0[usize::from(bit / 64)] & (1 << (bit % 64)) == 0)
    }
}

#[derive(Serialize, Deserialize)]
pub struct SymbolProjection {
    pub(super) root: PathBuf,
    pub(super) name: String,
    pub(super) op: SymbolOp,
    pub(super) files: BTreeMap<PathBuf, FileRows>,
    pub(super) scopes: Vec<ScopeLayout>,
}

impl SymbolProjection {
    pub fn for_root(&self, root: &Path) -> bool {
        self.root == root
    }
}

#[derive(Serialize, Deserialize)]
pub(super) struct FileRows {
    pub(super) stamp: FileStamp,
    pub(super) version: i32,
    pub(super) damaged: bool,
    pub(super) checks: u64,
    pub(super) names: NameFilter,
    pub(super) rows: Vec<IndexedSymbol>,
    pub(super) bearers: Vec<(usize, u8)>,
}

impl FileRows {
    /// Restore only scopes used by this document. Unrelated scopes from
    /// deleted or renamed files cannot participate in binding.
    pub(super) fn rebase(
        &mut self,
        old: &[ScopeLayout],
        scopes: &mut ScopeTable,
        document: usize,
        retained_left: &mut usize,
    ) -> bool {
        if self.rows.is_empty() && self.bearers.is_empty() {
            return true;
        }
        let mut needed = BTreeSet::new();
        let mut include = |mut id: usize| {
            while id >= 2 && needed.insert(id) {
                let Some((parent, _)) = old.get(id) else {
                    return false;
                };
                if *parent >= id {
                    return false;
                }
                id = *parent;
            }
            true
        };
        let mut cost = 0usize;
        for row in &self.rows {
            if !include(row.scope) {
                return false;
            }
            cost += row.name.as_deref().map_or(0, str::len);
            match &row.role {
                RowRole::Definition { type_ref: Some(ty) } => {
                    if !include(ty.scope) {
                        return false;
                    }
                    cost += ty.name.len() + ty.qualifier.as_deref().map_or(0, str::len);
                }
                RowRole::Reference {
                    spelling:
                        super::Spelling::Bindable {
                            qualifier: Some(q), ..
                        },
                } => cost += q.len(),
                _ => {}
            }
        }
        for &(id, _) in &self.bearers {
            if !include(id) {
                return false;
            }
        }
        cost += BEARER_ENTRY_BYTES * self.bearers.len();
        // If a conservative upper bound won't fit, let the ordinary walk
        // decide the budget rather than changing its coverage verdict.
        let maximum = needed.iter().fold(cost, |n, &id| {
            n + SCOPE_NODE_BYTES + 2 * old[id].1.as_deref().map_or(0, str::len)
        });
        if maximum > *retained_left {
            return false;
        }
        let mut remap = BTreeMap::from([(0, 0), (1, 1)]);
        for id in needed {
            let (parent, name) = &old[id];
            let parent = remap[parent];
            let (index, new) = match name {
                Some(name) => scopes.intern_named(parent, name),
                None => scopes.intern_anonymous(parent, (document, id)),
            };
            if new {
                cost += SCOPE_NODE_BYTES + 2 * name.as_deref().map_or(0, str::len);
            }
            remap.insert(id, index);
        }
        for &(id, flags) in &self.bearers {
            scopes.bearers.insert((document, remap[&id]), flags);
        }
        for row in &mut self.rows {
            row.document = document;
            row.scope = remap[&row.scope];
            if let RowRole::Definition { type_ref: Some(ty) } = &mut row.role {
                ty.scope = remap[&ty.scope];
            }
        }
        *retained_left -= cost;
        true
    }
}
