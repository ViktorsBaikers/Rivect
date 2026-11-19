//! Owner-issued permission requests. No UI or machine caller supplies the grant, scope or grantor.

use super::{StoreError, StoreWriter, TaskStore, sql, storage};
use crate::contracts::{EffectClass, SessionId};
use crate::executor::{MODE_ASK_REASON, terminal_witness};
use crate::policy::{canonical_preapproval_target, grant_id_is_key_safe};
use crate::resources::sanitize_status_cause;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::Serialize;
use serde_json::{Value, json};

pub(crate) const GRANTOR: &str = "human:tui-panel";
pub(crate) const TTL_SECONDS: i64 = 600;

/// Choices offered for exactly one retained request.
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionChoice {
    Deny,
    AllowOnce,
    LimitedGrant,
}

/// A failed admission of human consent, never permission to retry the original effect.
#[derive(Debug, thiserror::Error)]
pub enum PermissionError {
    #[error("permission request is no longer pending")]
    Stale,
    #[error("permission not confirmed; no grant recorded")]
    NotConfirmed,
    #[error("terminal witness unavailable")]
    Witness(#[source] std::io::Error),
    #[error("limited grant recording failed: grant id is not valid")]
    InvalidGrant,
    #[error("limited grant recording failed: scope is not valid unicode")]
    InvalidScope,
    #[error("permission recording failed")]
    Store(#[from] StoreError),
}

#[derive(PartialEq, Eq)]
struct Pending {
    attempt: String,
    task: String,
    class: String,
    grant: String,
    scope: Option<String>,
    expires: String,
}

fn pending(conn: &Connection, session: &SessionId) -> Result<Option<Pending>, StoreError> {
    conn.query_row(
        sql::LIVE_PERMISSION,
        params![session.0, MODE_ASK_REASON],
        |row| {
            Ok(Pending {
                attempt: row.get(0)?,
                task: row.get(1)?,
                class: row.get(2)?,
                grant: row.get(3)?,
                scope: row.get(4)?,
                expires: row.get(5)?,
            })
        },
    )
    .optional()
    .map_err(storage)
}

impl Pending {
    fn frame(&self, session: &SessionId) -> Value {
        let field = |s: &str| sanitize_status_cause(s).replace('\n', "^J");
        json!({"request_id":self.attempt,"session_id":session.0,"initiator":field(&self.task),
            "effect":self.class,"grant":field(&self.grant),"expiry":field(&self.expires),
            "scope":self.scope.as_deref().map_or_else(|| "[scope is not valid unicode]".to_owned(), field)})
    }
}

impl TaskStore {
    pub(crate) fn reject_asking_permission(
        &mut self,
        attempt: &str,
        class: EffectClass,
        grant: &str,
        target: &std::path::Path,
    ) -> Result<(), StoreError> {
        let scope = target
            .to_str()
            .and_then(|s| canonical_preapproval_target(class, s));
        let ttl = format!("+{TTL_SECONDS} seconds");
        let tx = self
            .conn_mut()?
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        if tx
            .execute(
                sql::UPDATE_ATTEMPT,
                params![attempt, "rejected", MODE_ASK_REASON],
            )
            .map_err(storage)?
            != 1
        {
            return Err(StoreError::missing_attempt(attempt));
        }
        tx.execute(
            sql::INSERT_PENDING_PERMISSION,
            params![attempt, grant, scope.as_deref(), ttl],
        )
        .map_err(storage)?;
        tx.commit().map_err(storage)
    }

    /// Projects the oldest live request in this session, without granting anything.
    ///
    /// # Errors
    /// Returns a storage error if the request cannot be read.
    pub fn pending_permission(&self, session: &SessionId) -> Result<Option<Value>, StoreError> {
        Ok(pending(self.conn()?, session)?.map(|row| row.frame(session)))
    }
}

impl StoreWriter<'_> {
    /// Resolves one owner-issued request only after fresh, independently witnessed terminal input.
    ///
    /// # Errors
    /// Refuses stale, expired, malformed and unwitnessed requests, and propagates storage failures.
    pub fn confirm_permission(
        &mut self,
        session: &SessionId,
        request: &str,
        choice: PermissionChoice,
    ) -> Result<(), PermissionError> {
        let row = pending(self.store.conn()?, session)?
            .filter(|row| row.attempt == request)
            .ok_or(PermissionError::Stale)?;
        let owner = json!({"permission": {"request_id":row.attempt,"session_id":session.0,"initiator":row.task,
            "effect":row.class,"grant":row.grant,"expiry":row.expires,"scope":row.scope}});
        if !terminal_witness::confirm(&owner, &json!({"choice":choice}))
            .map_err(PermissionError::Witness)?
        {
            return Err(PermissionError::NotConfirmed);
        }
        let tx = self
            .store
            .conn_mut()?
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        if pending(&tx, session)?.as_ref() != Some(&row) {
            return Err(PermissionError::Stale);
        }
        if matches!(choice, PermissionChoice::LimitedGrant) {
            if !grant_id_is_key_safe(&row.grant) {
                return Err(PermissionError::InvalidGrant);
            }
            let scope = row.scope.as_ref().ok_or(PermissionError::InvalidScope)?;
            // Already canonical at issue: never follow a new symlink while recording consent.
            let key = format!("{}:{}:{scope}", row.class, row.grant);
            tx.execute(
                sql::INSERT_PREAPPROVAL,
                params![key, GRANTOR, format!("+{TTL_SECONDS} seconds")],
            )
            .map_err(storage)?;
        }
        if tx
            .execute(sql::REMOVE_PENDING_PERMISSION, params![row.attempt])
            .map_err(storage)?
            != 1
        {
            return Err(PermissionError::Stale);
        }
        tx.commit().map_err(storage)?;
        Ok(())
    }
}
