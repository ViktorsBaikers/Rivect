//! Muse subscription-key profile: the recorded external block. Library-level —
//! no CLI verb is added.
//!
//! The recorded subscription contract admits its credential only through the
//! Muse Code CLI signed in with a Meta Model API account, so a Rivect-issued
//! model key has no documented compatible route (q-2026-09-08-007) and Meta
//! PAYG never stands in for the subscription. The module therefore holds only
//! the denial and its class: no store handle, credential reference, key field,
//! device code or endpoint, so it cannot mint, write or reach the live service.
//! The `muse-code` send gate reads [`EXTERNAL_CLASS`] so both denials name one
//! class.

/// The recorded external block class: the producer denial and the
/// `muse-code` send gate share it as their single source.
pub const EXTERNAL_CLASS: &str = "BLOCKED_EXTERNAL";

/// The producer's owner-local denial. It carries no secret field, and no
/// credential material can reach it: the producer never holds any.
#[derive(Debug, thiserror::Error)]
pub enum LoginError {
    /// The subscription-key profile route stays blocked by the recorded
    /// external premise until a compatible documented route exists.
    #[error(
        "the muse subscription-key profile is externally blocked ({class}); no documented compatible route exists"
    )]
    ExternalBlocked { class: &'static str },
}

/// Invokes the Muse subscription-key producer. It takes no store and no
/// credential reference, so it cannot write by construction, and it never
/// reaches the live service: every invocation is the recorded external
/// denial.
///
/// # Errors
/// Always [`LoginError::ExternalBlocked`] carrying [`EXTERNAL_CLASS`].
pub fn begin_login() -> Result<(), LoginError> {
    Err(LoginError::ExternalBlocked {
        class: EXTERNAL_CLASS,
    })
}
