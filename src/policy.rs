//! Effect policy: scoped grants, fail-closed admission and revocation.
//! Revocation takes effect before the next dispatch, without restart.

use crate::contracts::EffectClass;
use focaccia::CaseFold;
use std::borrow::Cow;
use std::collections::{BTreeMap, VecDeque};
use std::ffi::OsString;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Component, Path, PathBuf};
use unicode_normalization::UnicodeNormalization;

/// Canonical permission modes (ids pinned by DEC-014). The default of a new
/// install is `manual` — YOLO is never the default. `auto` lives in the
/// permission-mode namespace and stays distinct from the model-assign
/// `mode = "auto"` config key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PermissionMode {
    #[default]
    Manual,
    AcceptEdits,
    ReadOnly,
    Auto,
    PreapprovedOnly,
    Yolo,
}

impl PermissionMode {
    pub fn from_id(id: &str) -> Option<Self> {
        match id {
            "manual" => Some(Self::Manual),
            "accept-edits" => Some(Self::AcceptEdits),
            "read-only" => Some(Self::ReadOnly),
            "auto" => Some(Self::Auto),
            "preapproved-only" => Some(Self::PreapprovedOnly),
            "yolo" => Some(Self::Yolo),
            _ => None,
        }
    }

    pub fn id(&self) -> &'static str {
        match self {
            Self::Manual => "manual",
            Self::AcceptEdits => "accept-edits",
            Self::ReadOnly => "read-only",
            Self::Auto => "auto",
            Self::PreapprovedOnly => "preapproved-only",
            Self::Yolo => "yolo",
        }
    }

    pub fn all() -> [Self; 6] {
        [
            Self::Manual,
            Self::AcceptEdits,
            Self::ReadOnly,
            Self::Auto,
            Self::PreapprovedOnly,
            Self::Yolo,
        ]
    }
}

/// Decision inputs assembled at the admit call sites (DEC-014). Only
/// preapproval is persisted (TaskStore); the mode selection carrier arrives
/// with the Settings surface, so call sites fix `manual` until then
/// (DEC-015). `dry_run` marks a preview-only submission: the verdict stays
/// the matrix answer while the executor records no effect.
#[expect(
    clippy::struct_excessive_bools,
    reason = "DEC-014 fixes this exact observable input set for the mode matrix"
)]
#[derive(Debug, Clone, PartialEq)]
pub struct AdmissionContext {
    pub mode: PermissionMode,
    pub in_grant_scope: bool,
    pub budget_remaining: bool,
    pub in_trusted_scope: bool,
    pub has_checkpoint: bool,
    pub previously_approved: bool,
    pub within_declared_bounds: bool,
    pub dry_run: bool,
}

/// Mode verdict for one request. The token is a verdict, not a user action:
/// the permission panel maps it to allow once / allow with limited grant /
/// deny (DEC-014).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModeDecision {
    Allow,
    Ask,
    Deny,
}

impl ModeDecision {
    /// Observable token set pinned by AC-089.
    pub fn token(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Ask => "ask",
            Self::Deny => "deny",
        }
    }
}

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
    #[error("path is not valid unicode")]
    InvalidPath,
    #[error("cannot inspect path")]
    PathInspection { kind: std::io::ErrorKind },
    #[error("cannot read symlink")]
    SymlinkRead { kind: std::io::ErrorKind },
    #[error("too many symlink expansions")]
    SymlinkLoop,
}

#[derive(Debug, Clone)]
struct CanonicalPath {
    components: Vec<String>,
    collapsed_missing_tail: bool,
}

#[derive(Debug, Clone)]
struct DenyRule {
    identity: CanonicalPath,
}

#[derive(Debug, Default)]
pub struct Policy {
    grants: BTreeMap<String, Grant>,
    denies: Vec<DenyRule>,
    raw_denies: Vec<String>,
    next: u64,
}

impl Policy {
    pub fn grant_read(&mut self, scope_root: PathBuf) -> String {
        self.grant_classes(scope_root, vec![EffectClass::Read])
    }

    /// Grants exactly the listed effect classes on a scope root. The
    /// read-only backend still rejects non-read effects structurally; the
    /// class-admitting form exists so the permission-mode consult can be
    /// exercised for write verdicts before the backend carrier arrives.
    pub fn grant_classes(&mut self, scope_root: PathBuf, classes: Vec<EffectClass>) -> String {
        self.next += 1;
        let grant_id = format!("grant-{}", self.next);
        self.grants.insert(
            grant_id.clone(),
            Grant {
                grant_id: grant_id.clone(),
                scope_root,
                classes,
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

    /// Records a deny rule using the shared lexical identity resolver.
    /// A percent-encoded spelling enrolls the literal encoded filename:
    /// request spellings decode before the consult, so encoding-blind
    /// coverage belongs to [`Policy::enroll_deny_target`].
    ///
    /// # Errors
    /// Returns [`PolicyError`] for non-absolute, non-Unicode, or unobservable paths.
    pub fn enroll_deny(&mut self, path: impl AsRef<Path>) -> Result<(), PolicyError> {
        let identity = canonicalize_path(path.as_ref())?;
        if let Some(rule) = self
            .denies
            .iter_mut()
            .find(|rule| same_components(&rule.identity, &identity))
        {
            if !identity.collapsed_missing_tail {
                rule.identity = identity;
            }
            return Ok(());
        }
        self.denies.push(DenyRule { identity });
        Ok(())
    }

    /// Records a deny rule for a non-filesystem target — an egress URL or
    /// another raw identifier. URL-shaped entries compare by normalized
    /// form at consult time (scheme and host case, the default port in
    /// any numeric spelling — leading zeros or empty — a query, a
    /// fragment, and userinfo are not distinct targets, and a request
    /// spelled without the `scheme://` separator still matches by host,
    /// port, and path); entries without a URL shape keep the exact raw
    /// comparison. An authority-only entry with no path separator
    /// (`evil.example`, `evil.example:8080`) is an identifier and never
    /// URL-matches, and no entry carries subtree covering — a `/admin`
    /// deny does not cover `/admin/x`. A URL can never canonicalize as
    /// a path, so these denies live outside the filesystem identity
    /// resolver.
    pub fn enroll_deny_target(&mut self, raw: &str) {
        if !self.raw_denies.iter().any(|denied| denied == raw) {
            self.raw_denies.push(raw.to_string());
        }
    }

    /// Removes the deny rule with the same component-set identity.
    ///
    /// # Errors
    /// Returns [`PolicyError`] for non-absolute, non-Unicode, or unobservable paths.
    pub fn revoke_deny(&mut self, path: impl AsRef<Path>) -> Result<(), PolicyError> {
        let identity = canonicalize_path(path.as_ref())?;
        self.denies
            .retain(|rule| !same_components(&rule.identity, &identity));
        Ok(())
    }

    /// Reports whether a request enters an explicitly denied canonical path.
    ///
    /// # Errors
    /// Returns [`PolicyError`] when path observation or canonicalization fails.
    pub fn covers_report(&self, path: impl AsRef<Path>) -> Result<bool, PolicyError> {
        let request = canonicalize_path(path.as_ref())?;
        Ok(self
            .denies
            .iter()
            .any(|rule| covers_identity(&rule.identity, &request)))
    }

    /// Returns whether a request is denied, failing closed on path errors.
    pub fn covers(&self, path: impl AsRef<Path>) -> bool {
        // Enrollment rejects non-UTF-8 identities; request observation denies on failure.
        self.covers_report(path).unwrap_or(true)
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

    /// Mode verdict for one request against the DEC-014 matrix (AC-089).
    /// The enrolled-deny override outranks every mode — deny is stronger
    /// than allow. The deny consult routes by effect class: an egress
    /// target matches the enrolled raw deny set by normalized URL form,
    /// and a filesystem-shaped egress spelling (an absolute path or a
    /// `file://` URL) also consults the filesystem deny set (DEC-012),
    /// so a real URL reaches the mode matrix instead of tripping the
    /// filesystem fail-closed; every other class runs the canonical
    /// filesystem check, which fails closed for relative and
    /// unobservable targets alike (DEC-018(2)). Matrix combinations the
    /// spec table leaves unspecified stay one step from silence: a mode
    /// that does not clearly allow asks (or, where the mode forbids new
    /// consent, denies).
    pub fn decide(&self, path: &Path, class: EffectClass, ctx: &AdmissionContext) -> ModeDecision {
        if self.target_denied(path, class) {
            return ModeDecision::Deny;
        }
        match ctx.mode {
            PermissionMode::Manual => match class {
                EffectClass::Read if ctx.in_grant_scope => ModeDecision::Allow,
                _ => ModeDecision::Ask,
            },
            PermissionMode::AcceptEdits => match class {
                EffectClass::Read => ModeDecision::Allow,
                EffectClass::Write if ctx.in_trusted_scope && ctx.has_checkpoint => {
                    ModeDecision::Allow
                }
                _ => ModeDecision::Ask,
            },
            PermissionMode::ReadOnly => match class {
                EffectClass::Read => ModeDecision::Allow,
                _ => ModeDecision::Deny,
            },
            PermissionMode::Auto => match class {
                EffectClass::Read if ctx.in_grant_scope => ModeDecision::Allow,
                EffectClass::Write if ctx.in_grant_scope && ctx.budget_remaining => {
                    ModeDecision::Allow
                }
                EffectClass::Exec | EffectClass::Egress if ctx.within_declared_bounds => {
                    ModeDecision::Allow
                }
                _ => ModeDecision::Ask,
            },
            PermissionMode::PreapprovedOnly => {
                // Without a recorded grant every class needs new consent,
                // which this mode forbids.
                if ctx.previously_approved {
                    ModeDecision::Allow
                } else {
                    ModeDecision::Deny
                }
            }
            PermissionMode::Yolo => ModeDecision::Allow,
        }
    }

    /// Enrolled-deny consult for one request target, routed by effect
    /// class. Egress targets match the enrolled raw denies by normalized
    /// URL form, and a filesystem-shaped egress spelling (an absolute
    /// path or a `file://` URL, percent-decoded) also consults the
    /// filesystem deny set — the request class never escapes an
    /// enrolled deny (DEC-012); a filesystem-shaped spelling that
    /// cannot resolve to a path denies like the canonical check's
    /// fail-closed. Every other class runs the canonical filesystem
    /// check, which fails closed for relative and unobservable targets
    /// alike — a relative spelling of an enrolled deny cannot bypass it.
    fn target_denied(&self, target: &Path, class: EffectClass) -> bool {
        if class == EffectClass::Egress {
            // The WHATWG input preprocessing runs before any
            // classification so every downstream consult — url, file,
            // identifier — sees the same cleaned bytes.
            let Some(raw) = target.to_str().map(preprocess_egress_target) else {
                return false;
            };
            if self.egress_denied(&raw) {
                return true;
            }
            return match egress_filesystem_shape(Path::new(&raw)) {
                EgressFsShape::Absolute(path) => self.covers(&path),
                EgressFsShape::Unresolvable => true,
                EgressFsShape::NotFilesystem => false,
            };
        }
        self.covers(target)
    }

    /// Raw-deny consult for one egress target. URL-shaped entries and
    /// requests compare by normalized form, percent-decoded once on
    /// each side at the comparison so an encoded spelling of an
    /// enrolled target cannot split the deny; a request or an enrolled
    /// entry the leading-scheme detector calls schemeless (`//host/`,
    /// `host/`, `host:port/`) retries under the default scheme and
    /// compares by authority and path; entries that do not parse as
    /// URLs keep the exact raw comparison. An entry that carries a
    /// leading scheme but a port that overflows u16 stays scheme-bound
    /// by its lexical port, matching only spellings of the same
    /// scheme.
    fn egress_denied(&self, raw: &str) -> bool {
        let request = normalize_egress_url(raw, SchemeKnowledge::Carried);
        let schemeless = if request.is_none() && !has_leading_scheme(raw) {
            schemeless_retry(raw)
        } else {
            None
        };
        // A schemeless deny folds either web default port, so a
        // schemeful request carrying the other scheme's default port
        // also compares by its any-default-folded form.
        let folded = normalize_egress_url(raw, SchemeKnowledge::Guessed);
        self.raw_denies.iter().any(|entry| {
            // The entry preprocesses exactly like the request, so one
            // target has one identity whichever side spelled it.
            let denied = preprocess_egress_target(entry);
            same_decoded_identity(&denied, raw)
                || if has_leading_scheme(&denied) {
                    normalize_egress_url(&denied, SchemeKnowledge::Carried)
                        .is_some_and(|form| url_form_matches(&request, &schemeless, &form))
                } else {
                    schemeless_deny_form(&denied)
                        .is_some_and(|form| url_key_matches(&request, &schemeless, &folded, &form))
                }
        })
    }
}

/// WHATWG input preprocessing for one egress target, applied before
/// any classification: tab/LF/CR drop anywhere and C0-control/space
/// trim at both ends (url 2.5.8), plus the special-scheme backslash
/// fold — `\` reads as `/` — for spellings that are already
/// web-shaped. Filesystem-shaped schemeless spellings keep their
/// backslashes: a Unix filename may carry one, and a Windows drive or
/// a relative name is an identifier, not a url.
fn preprocess_egress_target(raw: &str) -> String {
    let trimmed = raw
        .replace(['\t', '\n', '\r'], "")
        .trim_matches(|byte| byte <= ' ')
        .to_string();
    if web_shaped(&trimmed) {
        trimmed.replace('\\', "/")
    } else {
        trimmed
    }
}

/// Whether an egress spelling is web-shaped for the backslash fold:
/// it carries a special scheme (http, https, ws, wss, ftp, file —
/// WHATWG reads `\` as `/` exactly there), or it opens an authority
/// introduction — two separator bytes in any mix (`//`, `\\`, `\/`,
/// `/\`) — which is web-shaped outright, dotless host included. A
/// bare schemeless host is web-shaped when its host segment carries
/// a dot or an explicit port; a scheme-shaped prefix that is neither
/// special nor authority-opening leaves the spelling schemeless, so
/// `evil.example:8080\x` reaches that host test instead of reading
/// as a fake scheme. A Windows drive letter (`C:\x`), a single
/// leading separator, and bare relative names are filesystem shapes
/// or identifiers.
fn web_shaped(raw: &str) -> bool {
    if let Some((scheme, rest)) = split_leading_scheme(raw) {
        let special = is_special_scheme(scheme);
        if special || rest.starts_with("//") {
            return special;
        }
    }
    if has_authority_intro(raw) {
        return true;
    }
    !raw.starts_with('/') && {
        let host = until_first(raw, &['/', '\\']);
        host.contains('.') || port_shaped(host)
    }
}

/// Whether `scheme` is one the WHATWG backslash fold covers: `\`
/// reads as `/` only inside a special-scheme url (url 2.5.8).
fn is_special_scheme(scheme: &str) -> bool {
    matches!(
        scheme.to_ascii_lowercase().as_str(),
        "http" | "https" | "ws" | "wss" | "ftp" | "file"
    )
}

/// Whether a spelling opens with an authority introduction: two
/// separator bytes in any mix (`//`, `\\`, `\/`, `/\`). WHATWG folds
/// both separators before the host (url 2.5.8), so the introduction
/// opens an authority by itself and a single leading separator opens
/// none.
fn has_authority_intro(raw: &str) -> bool {
    let bytes = raw.as_bytes();
    bytes.len() >= 2 && bytes[..2].iter().all(|byte| matches!(byte, b'/' | b'\\'))
}

/// Whether a schemeless host segment carries an explicit port: a `:`
/// whose leading word is not a Windows drive letter and whose tail is
/// empty or all ASCII digits — `localhost:80` is a host spelling, `C:`
/// a drive, and `mailto:x` a scheme-shaped identifier, not a host.
fn port_shaped(host: &str) -> bool {
    host.split_once(':').is_some_and(|(word, tail)| {
        let mut bytes = word.bytes();
        !(bytes.next().is_some_and(|byte| byte.is_ascii_alphabetic()) && bytes.next().is_none())
            && (tail.is_empty() || tail.bytes().all(|byte| byte.is_ascii_digit()))
    })
}

/// Whether two egress spellings name the same target: each compares
/// as its single-pass percent-decoded identity — `/%61dmin` and
/// `/admin` are one — falling back to the raw spelling only when the
/// decode fails, so a malformed side still pairs with the side whose
/// decoded form spells its bytes (`https://h/100%` matches the
/// enrolled `https://h/100%25`). The pass is single — `%2520` is a
/// literal `%20`, never a space — and cross raw/decoded pairs of two
/// decodable spellings stay distinct targets. A URL-shaped spelling
/// splits before the decode — introduction, authority, and tail
/// compare as segments — and the authority keeps its raw `@`/`:`
/// structure: an encoded `%40` or `%3a` is a host byte, never a
/// userinfo or port delimiter, so `file://host%40x/abs` and
/// `file://host@x/abs` stay distinct targets.
fn same_decoded_identity(left: &str, right: &str) -> bool {
    match (url_blob_segments(left), url_blob_segments(right)) {
        (Some(left), Some(right)) => left == right,
        // A side without the url shape — identifier or schemeless —
        // keeps the whole-spelling identity.
        _ => decoded_identity(left) == decoded_identity(right),
    }
}

/// Single-pass percent-decoded identity of one whole spelling, the
/// raw spelling when the decode fails.
fn decoded_identity(raw: &str) -> Cow<'_, str> {
    percent_decode(raw).unwrap_or(Cow::Borrowed(raw))
}

/// Segment layout of a URL-shaped spelling — a `scheme://` or
/// protocol-relative `//` introduction, then authority and tail — for
/// the identity comparison; `None` for any other spelling.
#[derive(PartialEq)]
struct UrlBlobSegments<'a> {
    intro: &'a str,
    authority: Vec<AuthorityToken<'a>>,
    tail: Cow<'a, str>,
}

/// One piece of an authority's identity: a raw `@`/`:` delimiter, or
/// the decoded-else-raw run between delimiters — a decoded run may
/// itself carry `@`/`:` bytes, which is exactly the distinction from
/// a raw delimiter.
#[derive(PartialEq)]
enum AuthorityToken<'a> {
    Delimiter(char),
    Run(Cow<'a, str>),
}

/// Splits a URL-shaped spelling into introduction, authority tokens,
/// and tail; the authority ends at the first raw separator after the
/// introduction.
fn url_blob_segments(raw: &str) -> Option<UrlBlobSegments<'_>> {
    let (intro, body) = if let Some(body) = raw.strip_prefix("//") {
        ("//", body)
    } else {
        let (scheme, rest) = split_leading_scheme(raw)?;
        // The introduction is the scheme, its colon, and `//`; the
        // guard returns before the slice, so a tail shorter than the
        // separator pair cannot index past the end of `raw`.
        let body = rest.strip_prefix("//")?;
        (&raw[..scheme.len() + 3], body)
    };
    let authority = until_first(body, &['/', '?', '#']);
    let tail = &body[authority.len()..];
    Some(UrlBlobSegments {
        intro,
        authority: authority_tokens(authority),
        tail: decoded_identity(tail),
    })
}

/// Tokenizes an authority on its raw `@`/`:` delimiters, decoding
/// each run between them on its own.
fn authority_tokens(authority: &str) -> Vec<AuthorityToken<'_>> {
    let mut tokens = Vec::new();
    let mut start = 0;
    for (index, byte) in authority.bytes().enumerate() {
        if byte == b'@' || byte == b':' {
            tokens.push(AuthorityToken::Run(decoded_identity(
                &authority[start..index],
            )));
            tokens.push(AuthorityToken::Delimiter(char::from(byte)));
            start = index + 1;
        }
    }
    tokens.push(AuthorityToken::Run(decoded_identity(&authority[start..])));
    tokens
}

/// Whether the request's normalized or schemeless form matches an
/// enrolled deny's normalized form, each percent-decoded once: a
/// schemeful request compares full normalized forms, and a schemeless
/// request compares authority and path — it cannot be held to the
/// entry's scheme.
fn url_form_matches(request: &Option<String>, schemeless: &Option<String>, denied: &str) -> bool {
    match (request, schemeless) {
        (Some(request), _) => same_decoded_identity(request, denied),
        (None, Some(schemeless)) => same_decoded_identity(url_key(schemeless), url_key(denied)),
        (None, None) => false,
    }
}

/// Scheme-insensitive match for a deny enrolled without the
/// `scheme://` separator: the entry carries no scheme of its own (its
/// retry guessed one), so the request's scheme — carried or guessed —
/// cannot split the origin, and its explicit web-default port
/// compares both kept — the carrying scheme may not fold it — and
/// folded, because the entry cannot bind the port to one scheme's
/// default. The pinned semantics: a schemeless entry's explicit
/// web-default port binds the web-default port class {80, 443}, not
/// the literal port — the enrolled `evil.example:80/x` covers the
/// portless https origin and `evil.example:443/x` covers
/// `http://evil.example:80/x`.
fn url_key_matches(
    request: &Option<String>,
    schemeless: &Option<String>,
    folded: &Option<String>,
    denied: &str,
) -> bool {
    let denied_key = url_key(denied);
    [request.as_deref(), schemeless.as_deref(), folded.as_deref()]
        .into_iter()
        .flatten()
        .any(|spelling| same_decoded_identity(url_key(spelling), denied_key))
}

/// Filesystem consult outcome for an egress target's spelling.
enum EgressFsShape {
    /// Absolute decoded path for the filesystem deny consult.
    Absolute(PathBuf),
    /// A spelling that is path-shaped before the decode — `file:`
    /// formed or starting with `/` — but resolves to no absolute
    /// path, because its escapes do not decode or its decoded bytes
    /// are not absolute: the consult fails closed, the same verdict
    /// `covers` gives an unobservable path.
    Unresolvable,
    /// No filesystem shape: only the raw deny set gates the target.
    NotFilesystem,
}

/// Filesystem shape of an egress target: the absolute path carried by
/// a `file:` URL (any scheme case, any authority — RFC 8089) or an
/// absolute path spelled as the target itself. A `file:` spelling
/// truncates query and fragment on the still-encoded bytes — `%3f`
/// stays filename bytes — then splits authority and path on the first
/// unencoded `/` (RFC 3986: an encoded `%2f` inside the authority is
/// an authority byte) and percent-decodes each side on its own, so
/// the fs consult sees the path the URL visibly spells; an authority
/// with no unencoded `/` decodes as one unit, an absolute result
/// being the encoded-path spelling (`file://%2fetc%2fpasswd`). Raw
/// spellings decode before the shape check — `%2f` decodes to a
/// separator — and an undecodable escape fails closed when either the
/// strict decode or the lenient one (valid escapes decoded, malformed
/// kept literally) leaves an absolute path; otherwise it is an
/// identifier only the raw deny set gates. In a raw path `?` and `#`
/// are legal filename bytes. Network URLs and other raw identifiers
/// have no filesystem shape, so only the raw deny set gates them and
/// the mode matrix stays decisive.
fn egress_filesystem_shape(target: &Path) -> EgressFsShape {
    let Some(raw) = target.to_str() else {
        return EgressFsShape::NotFilesystem;
    };
    if let Some(rest) = file_scheme_rest(raw) {
        return match file_url_path(until_first(rest, &['?', '#'])) {
            Some(path) if Path::new(&path).is_absolute() => EgressFsShape::Absolute(path.into()),
            // A `file:` spelling that is not absolute names no
            // resolvable path.
            _ => EgressFsShape::Unresolvable,
        };
    }
    match percent_decode(raw) {
        Some(path) if Path::new(&*path).is_absolute() => {
            EgressFsShape::Absolute(path.into_owned().into())
        }
        // A relative raw spelling is an identifier, not a path.
        Some(_) => EgressFsShape::NotFilesystem,
        // An undecodable spelling whose lenient form still spells an
        // absolute path can never prove it is not one: fail closed;
        // any other is an identifier.
        None if Path::new(&percent_decode_lenient(raw)).is_absolute() => {
            EgressFsShape::Unresolvable
        }
        None => EgressFsShape::NotFilesystem,
    }
}

/// Percent-decodes `%XX` escapes — hex digits fold case, `%2f`
/// decodes to a separator, `%00` to a NUL byte. A malformed escape or
/// a byte sequence that is not valid UTF-8 has no decoded spelling:
/// the caller fails closed on `None` instead of guessing.
fn percent_decode(raw: &str) -> Option<Cow<'_, str>> {
    let Some(start) = raw.find('%') else {
        return Some(Cow::Borrowed(raw));
    };
    let bytes = raw.as_bytes();
    let mut decoded = Vec::with_capacity(raw.len());
    decoded.extend_from_slice(&bytes[..start]);
    let mut index = start;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let escape = bytes.get(index + 1..index + 3)?;
            decoded.push(hex_value(escape[0])? * 16 + hex_value(escape[1])?);
            index += 3;
            continue;
        }
        decoded.push(bytes[index]);
        index += 1;
    }
    match String::from_utf8(decoded) {
        // A byte sequence no path can spell in Unicode form.
        Ok(decoded) => Some(Cow::Owned(decoded)),
        Err(_) => None,
    }
}

/// Numeric value of one percent-escape hex digit.
fn hex_value(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        b'A'..=b'F' => Some(digit - b'A' + 10),
        _ => None,
    }
}

/// Percent-decode keeping malformed escapes literally: valid escapes
/// decode, a truncated or non-hex `%` sequence stays as written, and
/// bytes no valid UTF-8 string can spell replace lossily. The
/// fail-closed shape check uses this when the strict decode fails —
/// only the absolute-prefix question matters there.
fn percent_decode_lenient(raw: &str) -> String {
    let mut decoded = Vec::with_capacity(raw.len());
    let mut index = 0;
    while let Some(byte) = raw.as_bytes().get(index) {
        if *byte == b'%'
            && let Some(escape) = raw.as_bytes().get(index + 1..index + 3)
            && let (Some(high), Some(low)) = (hex_value(escape[0]), hex_value(escape[1]))
        {
            decoded.push(high * 16 + low);
            index += 3;
            continue;
        }
        decoded.push(*byte);
        index += 1;
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

/// The bytes after the `file:` scheme prefix, which matches
/// case-insensitively (RFC 3986); `None` for any other spelling.
fn file_scheme_rest(raw: &str) -> Option<&str> {
    let (scheme, rest) = raw.split_once(':')?;
    scheme.eq_ignore_ascii_case("file").then_some(rest)
}

/// Decoded path a `file:` URL names, `None` when its escapes do not
/// decode. The bytes after `file:` split on the first unencoded `/`
/// (RFC 3986: an encoded `%2f` inside the authority is an authority
/// byte, not a path separator), each side percent-decodes on its own,
/// and the fs consult uses the decoded path — the authority never
/// names the file. The `file:/path` and `file:path` forms carry no
/// authority: the rest is the path itself. An authority introduction
/// with no unencoded `/` decodes as one unit — an absolute result is
/// the encoded-path spelling, anything else an authority naming the
/// local root (RFC 8089).
fn file_url_path(rest: &str) -> Option<String> {
    let Some(after_intro) = rest.strip_prefix("//") else {
        return percent_decode(rest).map(|path| path.into_owned());
    };
    match after_intro.find('/') {
        Some(start) => percent_decode(&after_intro[start..]).map(|path| path.into_owned()),
        None => match percent_decode(after_intro) {
            Some(decoded) if decoded.starts_with('/') => Some(decoded.into_owned()),
            Some(_) => Some("/".to_string()),
            None => None,
        },
    }
}

/// Normalization retry for a request or enrolled-deny spelling the
/// scheme detector calls schemeless: a protocol-relative `//host/` —
/// the rest of a longer separator run consumed first, `///host/`
/// being `https://host/` (WHATWG special-authority-ignore-slashes) —
/// or bare `host/` retries under the default scheme. A single leading
/// separator opens no authority: the spelling is path-relative and
/// never retries. A `scheme:` opening never reaches the retry — the
/// leading-scheme detector routes it to the normalizer, whose
/// special-scheme slash tolerance reads it as the authority form
/// directly.
fn schemeless_retry(raw: &str) -> Option<String> {
    let candidate = match raw.strip_prefix("//") {
        Some(rest) => format!("https://{}", rest.trim_start_matches(['/', '\\'])),
        None if raw.starts_with(['/', '\\']) => return None,
        None => format!("https://{raw}"),
    };
    normalize_egress_url(&candidate, SchemeKnowledge::Guessed)
}

/// Schemeless retry for an enrolled deny entry, mirroring the request
/// side: `evil.example/` and `//evil.example/` cover their schemeful
/// request spellings. An entry with no path separator is a non-URL
/// identifier and never retries — the exact raw comparison is its
/// only match. An explicit web-default port binds the web-default
/// port class {80, 443}, not the literal port (see
/// [`url_key_matches`]).
fn schemeless_deny_form(denied: &str) -> Option<String> {
    if denied.contains('/') {
        schemeless_retry(denied)
    } else {
        None
    }
}

/// Splits a scheme-shaped prefix (RFC 3986: alpha, then
/// alphanumerics, `+`, `-`, `.`) off `raw` at its first `:`: the
/// scheme as written and the bytes after the colon. `None` when the
/// bytes before the first `:` are not a scheme — a `/` among them
/// (`evil.example/a://b`) or no colon at all.
fn split_leading_scheme(raw: &str) -> Option<(&str, &str)> {
    let (scheme, rest) = raw.split_once(':')?;
    let mut bytes = scheme.bytes();
    if !bytes.next().is_some_and(|byte| byte.is_ascii_alphabetic()) {
        return None;
    }
    bytes
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
        .then_some((scheme, rest))
}

/// Whether a spelling opens with a scheme the deny layer treats as
/// carried: a scheme-shaped prefix whose tail opens an authority —
/// `//` after any scheme, or any rest at all for the special schemes
/// (WHATWG reads `http:/host` and `http:host` as `http://host`). A
/// `://` deeper in the spelling (`evil.example/a://b`) is path bytes,
/// and a `host:port` spelling (`evil.example:8080/x`) opens no
/// authority: both stay schemeless.
fn has_leading_scheme(raw: &str) -> bool {
    let Some((scheme, rest)) = split_leading_scheme(raw) else {
        return false;
    };
    rest.starts_with("//") || is_special_scheme(scheme)
}

/// Scheme-insensitive comparison key (authority plus path) of a
/// normalized URL: a request spelling that carried no scheme separator
/// cannot be held to the enrolled entry's scheme.
fn url_key(normalized: &str) -> &str {
    normalized
        .split_once("://")
        .map_or(normalized, |(_, rest)| rest)
}

/// Trust in the scheme a spelling carries for port-default folding: a
/// carried scheme folds only its own scheme's default port, while a
/// scheme guessed by the schemeless retry cannot bind the port to a
/// default and folds either web default — the fail-closed direction.
#[derive(Clone, Copy)]
enum SchemeKnowledge {
    Carried,
    Guessed,
}

/// Lexical URL normalizer for the egress raw-deny consult: scheme and
/// host fold to lowercase, the empty port and a numeric port equal to
/// the scheme default (80/443) drop, and userinfo, query, and fragment
/// are ignored — scheme, host, an explicit non-default port, and path
/// decide the match. Host spellings compare lexically: IDN/punycode
/// and trailing-dot forms stay distinct targets (DEC-020(3) accepted
/// limitation). A `file:` URL never normalizes as a web origin:
/// every spelling folds to an authority-less local form (RFC 8089) and
/// never retries schemeless. The scheme is a leading scheme-shaped
/// prefix — a `://` deeper in the spelling is path bytes — and the
/// special schemes (http, https, ws, wss, ftp) open the authority
/// under any slash run (`http:/host` and `http:host` are
/// `http://host`, and `https:///host` is `https://host` — WHATWG
/// special-authority-ignore-slashes); every other scheme requires the
/// exact `//` separator. A port that overflows u16 keeps its lexical
/// spelling: the comparison stays host/port/path lexical so a schemeless entry
/// matches the same spelling under any scheme. Returns `None` for
/// input that opens with no such scheme — the consult then retries
/// schemeless spellings, and a non-numeric port tail is absorbed into
/// the host, not rejected.
fn normalize_egress_url(raw: &str, knowledge: SchemeKnowledge) -> Option<String> {
    if let Some((scheme, rest)) = raw.split_once(':')
        && scheme.eq_ignore_ascii_case("file")
    {
        return Some(normalize_file_url(rest));
    }
    let (raw_scheme, rest) = split_leading_scheme(raw)?;
    let scheme = raw_scheme.to_ascii_lowercase();
    let rest = match scheme.as_str() {
        // WHATWG special-authority-ignore-slashes: a special scheme
        // consumes every `/` and `\` before the host, so a separator
        // run of any length opens the same authority.
        "http" | "https" | "ws" | "wss" | "ftp" => rest.trim_start_matches(['/', '\\']),
        _ => rest.strip_prefix("//")?,
    };
    let authority = until_first(rest, &['/', '?', '#']);
    let tail = &rest[authority.len()..];
    let path = until_first(tail.strip_prefix('/').unwrap_or_default(), &['?', '#']);
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let (host, port) = split_host_port(host_port)?;
    let port = if port.is_empty() {
        // The empty port is no port (WHATWG: it equals the default).
        String::new()
    } else {
        match port.parse::<u16>() {
            // A default port folds away; an explicit non-default port
            // stays, separator included.
            Ok(number)
                if matches!(knowledge, SchemeKnowledge::Carried)
                    && is_default_port(&scheme, number) =>
            {
                String::new()
            }
            Ok(number)
                if matches!(knowledge, SchemeKnowledge::Guessed) && is_any_default_port(number) =>
            {
                String::new()
            }
            Ok(number) => format!(":{number}"),
            // An overflowing port has no u16 form: the lexical
            // spelling decides the match, never a fold.
            Err(_) => format!(":{port}"),
        }
    };
    Some(format!(
        "{scheme}://{}{port}/{path}",
        host.to_ascii_lowercase()
    ))
}

/// Canonical local form of a `file:` URL: the `file:`, `file:/`, and
/// `file://` spellings of one path are one target, and RFC 8089 folds
/// the `localhost` and loopback authorities into the empty authority —
/// userinfo and port are not part of a file authority, so they strip
/// before the fold — any other authority names a different origin and
/// stays. The authority and path split on the first unencoded `/`,
/// the same split the filesystem consult uses, so the encoded-path
/// spelling (`file://%2fx%2ftarget.txt`) shares one identity with
/// `file:///x/target.txt`; an authority with no unencoded `/` names
/// the local root. Query and fragment are ignored, matching the
/// web-scheme normalizer.
fn normalize_file_url(rest: &str) -> String {
    let rest = until_first(rest, &['?', '#']);
    let Some(after_intro) = rest.strip_prefix("//") else {
        // The `file:/path` and `file:path` forms carry no authority.
        return fold_file_authority("", rest);
    };
    match after_intro.find('/') {
        // The path begins at the first unencoded separator.
        Some(start) => fold_file_authority(&after_intro[..start], &after_intro[start..]),
        None => match percent_decode(after_intro) {
            // No unencoded separator and an absolute decode: the
            // encoded-path spelling, a local path with no authority.
            Some(decoded) if decoded.starts_with('/') => format!("file://{decoded}"),
            // RFC 8089: an authority with no path names the root.
            _ => fold_file_authority(after_intro, "/"),
        },
    }
}

/// Local form of one file-URL authority and path: userinfo and port
/// split on the raw authority — an encoded `%40` or `%3a` is a host
/// byte, not a delimiter — and only the host piece decodes, for the
/// local-host test: an encoded loopback spelling (`127%2e0%2e0%2e1`)
/// is still loopback, and an undecodable host keeps its raw spelling
/// as a distinct origin. The `localhost` names and any loopback
/// address fold into the empty authority; every other host is
/// emitted re-encoded — `%` becomes `%25` — so the identity
/// comparison's single decode pass yields the raw authority, not a
/// second decode. The path keeps its escapes.
fn fold_file_authority(authority: &str, path: &str) -> String {
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let raw_host = split_host_port(host_port).map_or(host_port, |(host, _)| host);
    let lowered = percent_decode(raw_host)
        .unwrap_or(Cow::Borrowed(raw_host))
        .to_ascii_lowercase();
    let host = match lowered.as_str() {
        "" | "localhost" | "localhost.localdomain" => String::new(),
        _ if is_loopback_authority(&lowered) => String::new(),
        _ => raw_host.to_ascii_lowercase().replace('%', "%25"),
    };
    format!("file://{host}{path}")
}

/// Whether a decoded file-URL authority names the local host: an
/// IPv4 address in the loopback range 127.0.0.0/8 in any WHATWG
/// number spelling — dotted decimal or the 1–4-part shorthands whose
/// last part fills the remaining bytes (`127.1`, `0x7f.1`,
/// `0x7f000001`, octal) — or the IPv6 loopback address in any
/// bracketed spelling `std::net` parses (compression, leading zeros,
/// the IPv4-mapped `::ffff:127.0.0.1`), with a `%zone` suffix — the
/// decode of `%25zone` — stripped first: a zone id scopes the
/// address to an interface and is not address bytes. A hostname that
/// is no address — an out-of-range part (`127.0.0.256`), a
/// non-numeric label — never folds.
fn is_loopback_authority(host: &str) -> bool {
    if let Some(v6) = host
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
    {
        let address = v6.rsplit_once('%').map_or(v6, |(addr, _)| addr);
        return address.parse::<Ipv6Addr>().is_ok_and(|addr| {
            addr.is_loopback() || addr.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        });
    }
    ipv4_number(host).is_some_and(|addr| addr.is_loopback())
}

/// WHATWG IPv4 number: one to four dot-separated parts, each decimal,
/// `0x`-prefixed hex, or `0`-leading octal, the last part filling the
/// bytes the earlier parts left (`127.1` is 127.0.0.1). `None` for a
/// hostname — any non-numeric or empty part, more than four parts, a
/// non-final part above 255, or a final part too large for the bytes
/// it fills makes the whole spelling a hostname, not an address.
fn ipv4_number(host: &str) -> Option<Ipv4Addr> {
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() > 4 {
        return None;
    }
    let numbers = parts
        .iter()
        .map(|part| ipv4_part(part))
        .collect::<Option<Vec<_>>>()?;
    let (heads, tail) = numbers.split_at(numbers.len() - 1);
    let fill = 5 - numbers.len();
    if heads.iter().any(|number| *number > 255) || tail[0] >= 1u64 << (8 * fill) {
        return None;
    }
    let mut octets = [0u8; 4];
    for (index, number) in heads.iter().enumerate() {
        octets[index] = u8::try_from(*number).ok()?;
    }
    let mut tail_value = tail[0];
    for slot in octets.iter_mut().skip(numbers.len() - 1).rev() {
        *slot = u8::try_from(tail_value & 0xff).ok()?;
        tail_value >>= 8;
    }
    Some(Ipv4Addr::from(octets))
}

/// Numeric value of one IPv4 part: decimal, `0x`/`0X` hex (a bare
/// prefix is zero), or `0`-leading octal.
fn ipv4_part(part: &str) -> Option<u64> {
    if part.is_empty() {
        return None;
    }
    let (digits, radix) =
        if let Some(hex) = part.strip_prefix("0x").or_else(|| part.strip_prefix("0X")) {
            (hex, 16)
        } else if part.len() > 1 && part.starts_with('0') {
            (&part[1..], 8)
        } else {
            (part, 10)
        };
    if digits.is_empty() {
        // A bare `0x` prefix is zero (WHATWG).
        return Some(0);
    }
    u64::from_str_radix(digits, radix).ok()
}

/// Whether `port` is the scheme's default port (RFC 3986 scheme-based
/// normalization: 80 for http, 443 for https). Recorded limitation
/// (DEC-020(2) amendment): ws/wss/ftp explicit-port spellings do not
/// fold to their scheme defaults — only the web pair 80/443 folds.
fn is_default_port(scheme: &str, port: u16) -> bool {
    matches!((scheme, port), ("http", 80) | ("https", 443))
}

/// Whether `port` equals either web scheme's default port: a schemeless
/// spelling retried under a guessed scheme carries no scheme of its
/// own, so both defaults fold.
fn is_any_default_port(port: u16) -> bool {
    matches!(port, 80 | 443)
}

/// Prefix of `raw` before its first byte matching any of `markers`.
fn until_first<'a>(raw: &'a str, markers: &[char]) -> &'a str {
    &raw[..raw.find(markers).unwrap_or(raw.len())]
}

/// Splits an authority into host and optional port, keeping IPv6
/// brackets intact; an empty port means no explicit port.
fn split_host_port(authority: &str) -> Option<(&str, &str)> {
    if let Some(rest) = authority.strip_prefix('[') {
        let end = rest.find(']')? + 1;
        let host = &authority[..=end];
        let port = authority[end + 1..].strip_prefix(':').unwrap_or("");
        return Some((host, port));
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if port.is_empty() || port.bytes().all(|b| b.is_ascii_digit()) => {
            Some((host, port))
        }
        _ => Some((authority, "")),
    }
}

/// Preapproval rows persist only a scope string, so the effect class is
/// folded into the key (`"<class>:<scope>"`): a consent recorded for a
/// write must never admit an exec or egress on the same string.
/// Filesystem classes canonicalize the path so `/var` and `/private/var`
/// (and other alias spellings) share one row; a missing path keeps the
/// caller spelling. Egress/model/control keys stay as given.
/// Canonical path bytes that are not valid UTF-8 cannot be keyed without
/// colliding via `display()` — skip preapproval (fail closed).
pub fn preapproval_scope(class: EffectClass, scope: &str) -> Option<String> {
    let scope = match class {
        EffectClass::Read | EffectClass::Write | EffectClass::Exec => {
            match Path::new(scope).canonicalize() {
                Ok(path) => path.to_str()?.to_string(),
                Err(_) => scope.to_string(),
            }
        }
        EffectClass::Egress | EffectClass::Model | EffectClass::Control => scope.to_string(),
    };
    Some(format!("{}:{scope}", class_key(class)))
}

fn class_key(class: EffectClass) -> &'static str {
    match class {
        EffectClass::Read => "read",
        EffectClass::Write => "write",
        EffectClass::Exec => "exec",
        EffectClass::Egress => "egress",
        EffectClass::Model => "model",
        EffectClass::Control => "control",
    }
}

fn canonicalize_path(path: &Path) -> Result<CanonicalPath, PolicyError> {
    if !path.is_absolute() {
        return Err(PolicyError::InvalidPath);
    }
    let mut pending = path_components(path);
    let mut resolved = PathBuf::from(std::path::MAIN_SEPARATOR.to_string());
    let mut components = Vec::new();
    let mut missing_depth = None;
    let mut missing_tail_collapsed = false;
    let mut symlink_expansions = 0_u8;

    while let Some(component) = pending.pop_front() {
        let name = component.to_str().ok_or(PolicyError::InvalidPath)?;
        if name == "." {
            continue;
        }
        if name == ".." {
            let before = components.len();
            pop_component(&mut components, &mut resolved);
            if before > components.len() {
                missing_tail_collapsed = true;
            }
            if let Some(depth) = missing_depth
                && components.len() <= depth
            {
                missing_depth = None;
            }
            continue;
        }

        if missing_depth.is_some() {
            push_component(name, &mut components, &mut resolved);
            missing_tail_collapsed = false;
            continue;
        }

        missing_tail_collapsed = false;
        let candidate = resolved.join(name);
        match std::fs::symlink_metadata(&candidate) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                if symlink_expansions >= 40 {
                    return Err(PolicyError::SymlinkLoop);
                }
                symlink_expansions += 1;
                let target = std::fs::read_link(&candidate)
                    .map_err(|error| PolicyError::SymlinkRead { kind: error.kind() })?;
                if target.is_absolute() {
                    components.clear();
                    resolved = PathBuf::from(std::path::MAIN_SEPARATOR.to_string());
                }
                let mut target_components = path_components(&target);
                target_components.append(&mut pending);
                pending = target_components;
            }
            Ok(_) => push_component(name, &mut components, &mut resolved),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                missing_depth = Some(components.len());
                push_component(name, &mut components, &mut resolved);
            }
            Err(error) => return Err(PolicyError::PathInspection { kind: error.kind() }),
        }
    }

    Ok(CanonicalPath {
        components,
        collapsed_missing_tail: missing_tail_collapsed,
    })
}

fn path_components(path: &Path) -> VecDeque<OsString> {
    path.components()
        .filter_map(|component| match component {
            Component::RootDir | Component::CurDir => None,
            Component::Normal(name) => Some(name.to_os_string()),
            Component::ParentDir => Some(OsString::from("..")),
            Component::Prefix(prefix) => Some(prefix.as_os_str().to_os_string()),
        })
        .collect()
}

fn push_component(name: &str, components: &mut Vec<String>, resolved: &mut PathBuf) {
    components.push(normalize_component(name));
    resolved.push(name);
}

fn pop_component(components: &mut Vec<String>, resolved: &mut PathBuf) {
    if components.pop().is_some() {
        resolved.pop();
    }
}

fn normalize_component(component: &str) -> String {
    component.nfd().collect()
}

fn same_components(left: &CanonicalPath, right: &CanonicalPath) -> bool {
    left.components.len() == right.components.len()
        && left
            .components
            .iter()
            .zip(&right.components)
            .all(|(left, right)| CaseFold::Full.case_eq(left, right))
}

fn covers_identity(denied: &CanonicalPath, request: &CanonicalPath) -> bool {
    if request.components.len() < denied.components.len() {
        return false;
    }
    if !denied
        .components
        .iter()
        .zip(&request.components)
        .all(|(denied, request)| CaseFold::Full.case_eq(denied, request))
    {
        return false;
    }
    if denied.collapsed_missing_tail {
        request.components.len() > denied.components.len()
    } else {
        true
    }
}
