//! Private terminal projection and resolution of owner-issued requests.
use super::{Refusal, string};
use rivect::commands::Runtime;
use rivect::contracts::SessionId;
use rivect::state::permission::{PermissionChoice, PermissionError};
use serde_json::{Value, json};

pub(super) fn view(rt: &Runtime, params: &Value) -> Result<Value, Refusal> {
    if params.as_object().is_none_or(|p| p.len() != 2) {
        return Err(Refusal::Invalid);
    }
    let session = SessionId(string(params, "session_id")?.to_owned());
    Ok(json!({"permission":rt.store().pending_permission(&session)?}))
}

pub(super) fn resolve(rt: &mut Runtime, params: &Value) -> Result<Value, Refusal> {
    if params.as_object().is_none_or(|p| p.len() != 4) {
        return Err(Refusal::Invalid);
    }
    let session = SessionId(string(params, "session_id")?.to_owned());
    let choice = match string(params, "choice")? {
        "deny" => PermissionChoice::Deny,
        "allow_once" => PermissionChoice::AllowOnce,
        "limited_grant" => PermissionChoice::LimitedGrant,
        _ => return Err(Refusal::Invalid),
    };
    let result =
        rt.store_writer()
            .confirm_permission(&session, string(params, "request_id")?, choice);
    let (closed, note) = match result {
        Ok(()) => (
            true,
            match choice {
                PermissionChoice::AllowOnce => "allowed once; no grant recorded",
                PermissionChoice::Deny => "permission denied; no grant recorded",
                PermissionChoice::LimitedGrant => "limited grant recorded",
            },
        ),
        Err(PermissionError::Stale) => (true, "permission request is no longer pending"),
        Err(PermissionError::NotConfirmed | PermissionError::Witness(_)) => {
            (false, "permission not confirmed; no grant recorded")
        }
        Err(PermissionError::InvalidGrant) => (
            false,
            "limited grant recording failed: grant id is not valid",
        ),
        Err(PermissionError::InvalidScope) => (
            false,
            "limited grant recording failed: scope is not valid unicode",
        ),
        Err(PermissionError::Store(source)) => {
            let operation = if matches!(choice, PermissionChoice::LimitedGrant) {
                "limited grant recording failed"
            } else {
                "permission recording failed"
            };
            return Ok(
                json!({"closed":false,"note": format!("{operation}: {}", source.code().as_str())}),
            );
        }
    };
    Ok(json!({"closed":closed,"note":note}))
}
