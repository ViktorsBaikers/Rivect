//! Effect policy: scoped grants, fail-closed admission and revocation.
//! Revocation takes effect before the next dispatch, without restart.

use crate::contracts::EffectClass;
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq)]
pub struct Grant {
    pub grant_id: String,
    pub scope_root: PathBuf,
    pub classes: Vec<EffectClass>,
    pub revoked: bool,
}

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum PolicyError {
    #[error("unknown grant {grant_id}")]
    UnknownGrant { grant_id: String },
    #[error("grant {grant_id} revoked")]
    Revoked { grant_id: String },
    #[error("grant {grant_id} does not admit {class:?} effects")]
    ClassNotAdmitted {
        grant_id: String,
        class: EffectClass,
    },
}

#[derive(Debug, Default)]
pub struct Policy {
    grants: BTreeMap<String, Grant>,
    next: u64,
}

impl Policy {
    pub fn grant_read(&mut self, scope_root: PathBuf) -> String {
        self.next += 1;
        let grant_id = format!("grant-{}", self.next);
        self.grants.insert(
            grant_id.clone(),
            Grant {
                grant_id: grant_id.clone(),
                scope_root,
                classes: vec![EffectClass::Read],
                revoked: false,
            },
        );
        grant_id
    }

    pub fn revoke(&mut self, grant_id: &str) {
        if let Some(grant) = self.grants.get_mut(grant_id) {
            grant.revoked = true;
        }
    }

    pub fn grant(&self, grant_id: &str) -> Option<&Grant> {
        self.grants.get(grant_id)
    }

    /// First admission check; the executor repeats it immediately before the
    /// effect as mutable admission.
    pub fn admit(&self, grant_id: &str, class: EffectClass) -> Result<&Grant, PolicyError> {
        let grant = self
            .grants
            .get(grant_id)
            .ok_or_else(|| PolicyError::UnknownGrant {
                grant_id: grant_id.to_string(),
            })?;
        if grant.revoked {
            return Err(PolicyError::Revoked {
                grant_id: grant_id.to_string(),
            });
        }
        if !grant.classes.contains(&class) {
            return Err(PolicyError::ClassNotAdmitted {
                grant_id: grant_id.to_string(),
                class,
            });
        }
        Ok(grant)
    }
}
