//! Version-aware documentation retrieval (REQ-028, AC-037/AC-038): the
//! direct-source baseline answers a versioned snapshot without a key or paid
//! overage, and every incompatible latest bump, stale answer, 304, redirect or
//! refused credential lands in one typed unknown instead of a fabricated
//! current API. The scoped cache is derived data — bounded, disposable and
//! keyed by package, version and origin, so one source's answer can never
//! refresh another's.

use crate::contracts::ErrorCode;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// The owner every docs projection names.
pub const DOCS_OWNER: &str = "src/docs.rs";

/// The largest cached entry set: the cache is derived data and disposable.
pub const CACHE_MAX_ENTRIES: usize = 64;

/// How long one cached representation stays usable without revalidation.
pub const CACHE_MAX_AGE: Duration = Duration::from_secs(24 * 60 * 60);

/// The largest docs body this build accepts; an external document is untrusted
/// input and is bounded like every other one.
pub const DOC_BODY_MAX_BYTES: usize = 1024 * 1024;

/// The source class the offline baseline speaks: a versioned on-disk snapshot
/// that needs no account. A network source would be another class, never a
/// fallback under this one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceClass {
    DirectLocal,
}

impl SourceClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DirectLocal => "direct_local",
        }
    }
}

/// The account facts a status answer may report. A service this build has no
/// account for is `Unknown`, never a fabricated zero balance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Quota {
    Known { remaining: u64 },
    Unknown,
}

/// One docs request: the installed version the caller runs, the source's base
/// URL and the origin a credential belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request<'a> {
    pub package: &'a str,
    pub installed: &'a str,
    pub base_url: &'a str,
    /// The credential's own origin; a plan attaches it only when the request
    /// origin matches, so a redirect can never carry it elsewhere.
    pub credential_origin: Option<&'a str>,
}

/// Whether the outbound plan carries a credential header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Authorization {
    None,
    /// The credential belongs to the request origin.
    Scoped,
    /// The credential belongs to another origin, so the header is dropped.
    Withheld,
}

/// One outbound plan. The token itself never enters this shape: only whether
/// the header is attached, which is the fact the isolation proof reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub method: &'static str,
    pub url: String,
    pub accept: String,
    pub authorization: Authorization,
}

/// One response as the transport observed it. The classifier trusts nothing
/// here: status, origin, declared version and validators are all checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    /// The origin the answer actually came from, after any redirect.
    pub origin: String,
    pub body: Vec<u8>,
    pub etag: Option<String>,
    pub location: Option<String>,
}

/// One document's declared header; the body's own words, parsed before any
/// byte is treated as documentation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DocumentHeader {
    package: String,
    version: String,
    body: String,
}

/// One cached representation bound to the exact scope it was fetched for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedDoc {
    pub package: String,
    pub version: String,
    pub origin: String,
    pub etag: String,
    pub body: String,
    pub fetched_at: u64,
}

/// How current a served document is. A revalidated entry reports when the
/// source confirmed it; nothing here turns a stale or foreign answer fresh.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Freshness {
    Fetched { as_of: u64 },
    Revalidated { as_of: u64 },
}

/// One served document with its exact provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceDoc {
    pub package: String,
    pub version: String,
    pub origin: String,
    pub freshness: Freshness,
    pub body: String,
    pub etag: Option<String>,
}

/// Why an answer is not a document. Each cause is typed; none is a silently
/// empty or best-effort body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum Unknown {
    /// The exact installed version is not in the source; the latest one is not
    /// a substitute.
    VersionUnavailable {
        requested: String,
    },
    /// The source offers another version (often the latest API) than the one
    /// installed.
    VersionMismatch {
        installed: String,
        offered: String,
    },
    /// The document claims a package or version its location does not name.
    PoisonedSource {
        package: String,
        version: String,
    },
    /// A 304 without a matching scoped cache entry proves nothing.
    Stale,
    /// The answer came from another origin than the request.
    ForeignOrigin {
        origin: String,
    },
    /// One same-origin redirect must be re-planned; it is not an answer.
    Redirect {
        url: String,
    },
    /// A redirect left the request origin.
    CrossOriginRedirect {
        origin: String,
    },
    /// The source refused the credential; no other key is tried.
    Denied {
        status: u16,
    },
    /// The account's quota is exhausted; the direct baseline stays usable.
    QuotaExhausted,
    Upstream {
        status: u16,
    },
    Malformed,
    TooLarge {
        limit: usize,
    },
}

/// One docs answer: an applicable source or an explicit unknown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Answer {
    Source(Box<SourceDoc>),
    Unknown(Unknown),
}

impl Answer {
    /// The served document, when this answer is one.
    pub fn source(&self) -> Option<&SourceDoc> {
        match self {
            Self::Source(doc) => Some(doc),
            Self::Unknown(_) => None,
        }
    }

    /// The explicit unknown, when this answer is one.
    pub fn unknown(&self) -> Option<&Unknown> {
        match self {
            Self::Source(_) => None,
            Self::Unknown(reason) => Some(reason),
        }
    }
}

/// Failures of a docs read that are not a docs answer: an unreadable snapshot
/// or a request whose identifiers cannot be a URL/path segment.
#[derive(Debug, thiserror::Error)]
pub enum DocsError {
    #[error("docs request field {field} is not a bounded identifier")]
    InvalidRequest { field: &'static str },
    #[error("docs snapshot {} could not be read: {source}", path.display())]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("docs snapshot {} is larger than {limit} bytes", path.display())]
    TooLarge { path: PathBuf, limit: usize },
}

impl DocsError {
    /// The wire code this failure reports: a malformed request is the
    /// caller's, an unreadable or oversized source is a blocked dependency.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::InvalidRequest { .. } => ErrorCode::InvalidInput,
            Self::Read { .. } | Self::TooLarge { .. } => ErrorCode::DependencyBlocked,
        }
    }
}

/// The origin of one hierarchical URL in WHATWG serialization; `None` for a
/// string that names no origin.
fn origin_of(url: &str) -> Option<String> {
    let parsed = reqwest::Url::parse(url).ok()?;
    parsed.host_str()?;
    Some(parsed.origin().ascii_serialization())
}

/// The origin one redirect location resolves to against the request origin,
/// by the WHATWG rules a client applies: backslashes read as slashes and
/// repeated slashes collapse, so `/\evil` and `\\evil` name their own
/// authority instead of a same-origin path. `None` when the location or the
/// request origin does not parse, so an unresolvable location is refused
/// rather than followed as if it were a path.
fn location_origin(request_origin: &str, location: &str) -> Option<String> {
    let base = reqwest::Url::parse(request_origin).ok()?;
    let resolved = base.join(location).ok()?;
    resolved.host_str()?;
    Some(resolved.origin().ascii_serialization())
}

/// Whether one value can be a single URL path segment or file name.
fn bounded_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value != "."
        && value != ".."
        && !value.contains(['/', '\\', '\0'])
}

/// The outbound plan for one request: the URL pins the installed version, so
/// "latest" is never what this build asks for, and the credential header is
/// attached only on its own origin.
pub fn plan(request: &Request<'_>) -> Result<Plan, DocsError> {
    if !bounded_identifier(request.package) {
        return Err(DocsError::InvalidRequest { field: "package" });
    }
    if !bounded_identifier(request.installed) {
        return Err(DocsError::InvalidRequest { field: "installed" });
    }
    let request_origin =
        origin_of(request.base_url).ok_or(DocsError::InvalidRequest { field: "base_url" })?;
    let authorization = match request.credential_origin {
        None => Authorization::None,
        Some(origin) if origin.eq_ignore_ascii_case(&request_origin) => Authorization::Scoped,
        Some(_) => Authorization::Withheld,
    };
    Ok(Plan {
        method: "GET",
        url: format!(
            "{}/{}/{}",
            request.base_url.trim_end_matches('/'),
            request.package,
            request.installed
        ),
        accept: "application/json".to_string(),
        authorization,
    })
}

/// One redirect decision. `Follow` keeps the credential only while the origin
/// is unchanged; a cross-origin hop is refused rather than followed
/// unauthenticated or with the header attached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Redirect {
    Follow {
        url: String,
        authorization: Authorization,
    },
    Refused {
        origin: String,
        authorization: Authorization,
    },
}

/// Follow one redirect from `request_origin` to `location`, scoped to the
/// credential's own origin.
pub fn redirect(request_origin: &str, location: &str, credential_origin: Option<&str>) -> Redirect {
    let target = location_origin(request_origin, location);
    let authorization = match credential_origin {
        None => Authorization::None,
        Some(origin) => match &target {
            Some(target) if origin.eq_ignore_ascii_case(target) => Authorization::Scoped,
            Some(_) | None => Authorization::Withheld,
        },
    };
    match target {
        Some(target) if target.eq_ignore_ascii_case(request_origin) => Redirect::Follow {
            url: location.to_string(),
            authorization,
        },
        Some(origin) => Redirect::Refused {
            origin,
            authorization,
        },
        // Neither side resolves to an origin, so the hop cannot be proven
        // same-origin: it is refused and no credential follows it.
        None => Redirect::Refused {
            origin: location.to_string(),
            authorization: match credential_origin {
                Some(_) => Authorization::Withheld,
                None => Authorization::None,
            },
        },
    }
}

/// The direct-source baseline: a versioned snapshot directory that answers
/// offline, with no account and no egress. The exact installed version is the
/// only one it serves; a missing one is an explicit unknown.
#[derive(Debug, Clone, Copy)]
pub struct DirectSource<'a> {
    root: &'a Path,
}

impl<'a> DirectSource<'a> {
    pub fn new(root: &'a Path) -> Self {
        Self { root }
    }

    /// Read the snapshot for exactly `version`. A snapshot whose own header
    /// names another package is poisoned; a same-package snapshot declaring
    /// another version is the installed/latest trap and is never served.
    pub fn retrieve(&self, package: &str, version: &str) -> Result<Answer, DocsError> {
        if !bounded_identifier(package) {
            return Err(DocsError::InvalidRequest { field: "package" });
        }
        if !bounded_identifier(version) {
            return Err(DocsError::InvalidRequest { field: "version" });
        }
        let path = self.root.join(package).join(format!("{version}.json"));
        let length = match std::fs::metadata(&path) {
            Ok(metadata) if metadata.is_file() => metadata.len(),
            Ok(_) => {
                return Err(DocsError::Read {
                    path,
                    source: std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "snapshot is not a regular file",
                    ),
                });
            }
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Answer::Unknown(Unknown::VersionUnavailable {
                    requested: version.to_string(),
                }));
            }
            Err(source) => return Err(DocsError::Read { path, source }),
        };
        let file = match std::fs::File::open(&path) {
            Ok(file) => file,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Answer::Unknown(Unknown::VersionUnavailable {
                    requested: version.to_string(),
                }));
            }
            Err(source) => return Err(DocsError::Read { path, source }),
        };
        if length > DOC_BODY_MAX_BYTES as u64 {
            return Err(DocsError::TooLarge {
                path,
                limit: DOC_BODY_MAX_BYTES,
            });
        }
        // The take bound holds even when the file grows after the length
        // check, and a stream that never reaches EOF is refused at the bound
        // instead of read forever.
        let mut bytes = Vec::with_capacity(length as usize);
        let mut bounded = file.take(DOC_BODY_MAX_BYTES as u64 + 1);
        if let Err(source) = bounded.read_to_end(&mut bytes) {
            return Err(DocsError::Read { path, source });
        }
        if bytes.len() > DOC_BODY_MAX_BYTES {
            return Err(DocsError::TooLarge {
                path,
                limit: DOC_BODY_MAX_BYTES,
            });
        }
        let header: DocumentHeader = match serde_json::from_slice(&bytes) {
            Ok(header) => header,
            Err(_) => return Ok(Answer::Unknown(Unknown::Malformed)),
        };
        if header.package != package {
            return Ok(Answer::Unknown(Unknown::PoisonedSource {
                package: header.package,
                version: header.version,
            }));
        }
        if header.version != version {
            return Ok(Answer::Unknown(Unknown::VersionMismatch {
                installed: version.to_string(),
                offered: header.version,
            }));
        }
        Ok(Answer::Source(Box::new(SourceDoc {
            package: header.package,
            version: header.version,
            origin: self.root.to_string_lossy().into_owned(),
            freshness: Freshness::Fetched { as_of: 0 },
            body: header.body,
            etag: None,
        })))
    }
}

/// The classifier every transport lands in: a 200 is served only when its
/// declared version is the installed one and its origin is the request's; a
/// 304 is fresh only against a matching scoped cache entry; a redirect is
/// refused across origins; a refusal or exhausted quota is an explicit
/// unknown, never a stale body.
pub fn classify(
    request: &Request<'_>,
    response: &Response,
    cached: Option<&CachedDoc>,
    as_of: u64,
) -> Answer {
    let Some(request_origin) = origin_of(request.base_url) else {
        return Answer::Unknown(Unknown::Malformed);
    };
    if !response.origin.eq_ignore_ascii_case(&request_origin) {
        return Answer::Unknown(Unknown::ForeignOrigin {
            origin: response.origin.clone(),
        });
    }
    match response.status {
        200 => classify_document(request, response, as_of),
        304 => {
            let Some(cached) = cached else {
                return Answer::Unknown(Unknown::Stale);
            };
            if cached.package != request.package
                || cached.version != request.installed
                || !cached.origin.eq_ignore_ascii_case(&response.origin)
            {
                return Answer::Unknown(Unknown::Stale);
            }
            if response.etag.as_deref() != Some(cached.etag.as_str()) {
                return Answer::Unknown(Unknown::Stale);
            }
            Answer::Source(Box::new(SourceDoc {
                package: cached.package.clone(),
                version: cached.version.clone(),
                origin: cached.origin.clone(),
                freshness: Freshness::Revalidated { as_of },
                body: cached.body.clone(),
                etag: Some(cached.etag.clone()),
            }))
        }
        301 | 302 | 303 | 307 | 308 => match response.location.as_deref() {
            Some(location) => match location_origin(&request_origin, location) {
                Some(origin) if origin.eq_ignore_ascii_case(&request_origin) => {
                    Answer::Unknown(Unknown::Redirect {
                        url: location.to_string(),
                    })
                }
                Some(origin) => Answer::Unknown(Unknown::CrossOriginRedirect { origin }),
                // A location that names no resolvable origin is never read as
                // a same-origin re-plan; it is refused as a foreign hop.
                None => Answer::Unknown(Unknown::CrossOriginRedirect {
                    origin: location.to_string(),
                }),
            },
            None => Answer::Unknown(Unknown::Malformed),
        },
        401 | 403 => Answer::Unknown(Unknown::Denied {
            status: response.status,
        }),
        429 => Answer::Unknown(Unknown::QuotaExhausted),
        status => Answer::Unknown(Unknown::Upstream { status }),
    }
}

/// A 200 is served only when its body declares the installed version of the
/// requested package; the body's own header is the authority the trap reads.
fn classify_document(request: &Request<'_>, response: &Response, as_of: u64) -> Answer {
    if response.body.len() > DOC_BODY_MAX_BYTES {
        return Answer::Unknown(Unknown::TooLarge {
            limit: DOC_BODY_MAX_BYTES,
        });
    }
    let header: DocumentHeader = match serde_json::from_slice(&response.body) {
        Ok(header) => header,
        Err(_) => return Answer::Unknown(Unknown::Malformed),
    };
    if header.package != request.package {
        return Answer::Unknown(Unknown::PoisonedSource {
            package: header.package,
            version: header.version,
        });
    }
    if header.version != request.installed {
        return Answer::Unknown(Unknown::VersionMismatch {
            installed: request.installed.to_string(),
            offered: header.version,
        });
    }
    Answer::Source(Box::new(SourceDoc {
        package: header.package,
        version: header.version,
        origin: response.origin.clone(),
        freshness: Freshness::Fetched { as_of },
        body: header.body,
        etag: response.etag.clone(),
    }))
}

/// The scoped cache: entries are keyed by package, version and origin, and the
/// oldest entry is dropped when the bound is reached. A 304 may only read the
/// exact entry its scope and validator name.
#[derive(Debug, Default)]
pub struct Cache {
    entries: BTreeMap<String, CachedDoc>,
}

impl Cache {
    fn scope(package: &str, version: &str, origin: &str) -> String {
        format!("{}\n{}\n{}", package, version, origin.to_ascii_lowercase())
    }

    /// Store one served document under its exact scope.
    pub fn store(&mut self, doc: CachedDoc) {
        let key = Self::scope(&doc.package, &doc.version, &doc.origin);
        if self.entries.len() >= CACHE_MAX_ENTRIES
            && !self.entries.contains_key(&key)
            && let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.fetched_at)
                .map(|(key, _)| key.clone())
        {
            self.entries.remove(&oldest);
        }
        self.entries.insert(key, doc);
    }

    /// The entry for exactly this scope, when one was stored.
    pub fn get(&self, package: &str, version: &str, origin: &str) -> Option<&CachedDoc> {
        self.entries.get(&Self::scope(package, version, origin))
    }

    /// How many representations are cached.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the cache holds nothing.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// The cache facts a status answer carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheStatus {
    pub max_entries: usize,
    pub max_age_secs: u64,
    pub cached_entries: usize,
}

/// One status projection: the owner's declared source class, version policy,
/// cache bounds and the account facts this build can honestly report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusResult {
    pub schema_version: u32,
    pub kind: String,
    pub owner: String,
    pub source_classes: Vec<String>,
    pub version_aware: bool,
    pub cache: CacheStatus,
    pub quota: Quota,
}

/// The docs owner's status. `docs.status` is a pure read: it reports the
/// owner's declared policy and the live cache count, never an external
/// refresh. Quota has no account in this build, so it stays `unknown`.
pub fn status() -> StatusResult {
    status_for(&Cache::default())
}

/// The same projection over a caller-held cache.
pub fn status_for(cache: &Cache) -> StatusResult {
    StatusResult {
        schema_version: 1,
        kind: "docs.status".to_string(),
        owner: DOCS_OWNER.to_string(),
        source_classes: vec![SourceClass::DirectLocal.as_str().to_string()],
        version_aware: true,
        cache: CacheStatus {
            max_entries: CACHE_MAX_ENTRIES,
            max_age_secs: CACHE_MAX_AGE.as_secs(),
            cached_entries: cache.len(),
        },
        quota: Quota::Unknown,
    }
}
