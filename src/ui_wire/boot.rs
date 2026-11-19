//! Data-root recovery diagnostics; these never belong to a task or grant authority.

use super::{Refusal, Request};
use rivect::commands::OpenError;
use rivect::contracts::ErrorCode;
use rivect::owner::OwnerError;
use serde_json::{Value, json};
use std::error::Error as _;
use std::io;

const BUDGET: usize = 64 * 1024;
const ROWS: usize = 256;

pub(super) fn diagnostics(lines: &[String]) -> Value {
    // The owner already escaped the diagnostic text. Budget by bytes and row
    // count before encoding, including empty rows; stderr retains the full list.
    let mut remaining = BUDGET;
    let shown = lines
        .iter()
        .take(ROWS)
        .take_while(|line| {
            if line.len() > remaining {
                return false;
            }
            remaining -= line.len();
            true
        })
        .count();
    json!({"lines": &lines[..shown], "omitted": lines.len() - shown})
}

/// Answers a valid private boot request even when no runtime could be acquired.
///
/// # Errors
/// Returns a failed response write; the original owner error is not terminal-safe.
pub fn failed_open(raw: &str, failure: &OpenError) -> io::Result<()> {
    let Ok(request) = serde_json::from_str::<Request>(raw) else {
        return Ok(());
    };
    if request.method != "runtime.boot" || check(&request).is_err() {
        return Ok(());
    }
    // Source diagnostics can include config input or arbitrary provider prose.
    // Send only the closed owner category alongside its vetted recovery lines.
    let (code, cause) = match failure
        .source()
        .and_then(|source| source.downcast_ref::<OwnerError>())
    {
        Some(OwnerError::AlreadyOwned) => (
            ErrorCode::Conflict,
            "another owner already holds this data root",
        ),
        Some(
            OwnerError::Config { .. }
            | OwnerError::ConfigTooLarge { .. }
            | OwnerError::ConfigRead { .. },
        ) => (ErrorCode::InvalidInput, "owner configuration failed"),
        Some(OwnerError::Store(_)) => (ErrorCode::StorageUnavailable, "owner storage failed"),
        Some(OwnerError::Io(_)) => (ErrorCode::StorageUnavailable, "owner i/o failed"),
        Some(OwnerError::SupervisorPolicy(_)) | None => {
            (ErrorCode::InternalError, "supervisor construction failed")
        }
    };
    let reply = json!({"jsonrpc":"2.0", "id":request.id, "error": {
        "code":code, "cause":cause, "recovery":diagnostics(failure.diagnostics())
    }});
    crate::write_stdout(&reply.to_string())
}

pub(super) fn check(request: &Request) -> Result<(), Refusal> {
    request.validate()?;
    if request
        .params
        .as_object()
        .is_none_or(|fields| fields.len() != 1)
    {
        return Err(Refusal::Invalid);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{BUDGET, ROWS, diagnostics};
    use serde_json::json;

    #[test]
    fn recovery_keeps_complete_rows_and_accounts_for_both_bounds() {
        let rows = vec![String::new(); ROWS + 2];
        assert_eq!(
            diagnostics(&rows),
            json!({"lines":rows[..ROWS],"omitted":2})
        );
        let exact = "界".repeat(BUDGET / 3) + "x";
        assert_eq!(exact.len(), BUDGET);
        let rows = [exact, "omitted".to_owned()];
        assert_eq!(diagnostics(&rows), json!({"lines":rows[..1],"omitted":1}));
        assert_eq!(
            diagnostics(&["x".repeat(BUDGET + 1)]),
            json!({"lines":[],"omitted":1})
        );
    }
}
