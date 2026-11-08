//! Vertex application default credentials (AC-005): the recorded source
//! order, the three ADC file types, and one shared refresh cache.
//!
//! Sources are tried in the recorded order (`google-auth.ts`, pinned
//! `0133f7ff`): the file `GOOGLE_APPLICATION_CREDENTIALS` names, the user
//! ADC file at `~/.config/gcloud/application_default_credentials.json`,
//! then the admitted metadata endpoint under its 2 s bound. A raw access
//! token from the operator environment is refused — this module resolves
//! credentials only from those recorded sources (INV-001).
//!
//! The file's `type` selects the exchange: `service_account` signs an
//! RS256 assertion whose `aud` is the token endpoint and whose lifetime is
//! 3600 s, through the platform's own safe signing API (OpenSSL off Apple,
//! Security.framework on macOS) — never project-owned RSA arithmetic;
//! `authorized_user` posts its refresh token; and
//! `impersonated_service_account` resolves its own source credential first
//! and then targets `projects/-/serviceAccounts/{target}` on the recorded
//! IAM host — never the host the file's own URL names.
//!
//! Tokens are cached per source and endpoint and refreshed 60 s before
//! expiry. One resolution runs at a time under a single absolute 30 s
//! budget that starts before the wait, so a parked caller and every leg
//! share the same remaining time. Secret material — tokens, the
//! private key, client secrets and refresh tokens — never enters `Debug`,
//! `Display` or a diagnostic, and the resolved profile is written only
//! through the create-only [`CredentialStore::login`] seam.

use super::login_common::{self, Body};
use super::{CredentialStore, ProviderError, SecretRef, read_catalog_body, resolve_credential};
use crate::config::Config;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

/// The environment variable naming the operator's credential file.
pub const GAC_ENV: &str = "GOOGLE_APPLICATION_CREDENTIALS";

/// The recorded OAuth token endpoint (`google-auth.ts:23`).
pub const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";

/// The recorded metadata token endpoint (`google-auth.ts:24`).
pub const METADATA_URL: &str =
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token";

/// The recorded IAM credentials base (`google-auth.ts:230`).
pub const IAM_URL: &str = "https://iamcredentials.googleapis.com/v1";

/// The user ADC file, relative to the operator's home directory
/// (`google-auth.ts:70`).
pub const USER_ADC_FILE: &str = ".config/gcloud/application_default_credentials.json";

/// The recorded cloud-platform scope (`google-auth.ts:25`).
const CLOUD_PLATFORM_SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";

/// The recorded bearer grant (`google-auth.ts:26`).
const JWT_BEARER_GRANT: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

/// The service-account assertion's lifetime (`google-auth.ts:140`).
const ASSERTION_LIFETIME: u64 = 3600;

/// The recorded refresh skew: a cached token is refreshed this long
/// before its own expiry (`google-auth.ts:65-67`).
const REFRESH_SKEW: Duration = Duration::from_secs(60);

/// The one absolute resolution budget: it starts before the single-flight
/// wait and covers source selection/read, the signing and exchange chain,
/// response parsing and the publication decision
/// (`google-auth.ts:277`).
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(30);

/// The metadata leg's own short bound (`google-auth.ts:168`).
const METADATA_TIMEOUT: Duration = Duration::from_secs(2);

/// The metadata leg's recorded flavor header name (`google-auth.ts:173`).
const METADATA_FLAVOR: &str = "Metadata-Flavor";

/// The three endpoints the ADC legs reach. [`AdcEndpoints::recorded`] is
/// the production form; an offline caller passes its own loopback contract
/// peers.
#[derive(Clone)]
pub struct AdcEndpoints {
    /// The OAuth token exchange.
    pub token: String,
    /// The metadata token endpoint.
    pub metadata: String,
    /// The IAM credentials base (`projects/-/...` is appended to it).
    pub iam: String,
}

impl AdcEndpoints {
    /// The recorded production endpoints.
    #[must_use]
    pub fn recorded() -> Self {
        Self {
            token: TOKEN_URL.to_string(),
            metadata: METADATA_URL.to_string(),
            iam: IAM_URL.to_string(),
        }
    }
}

/// The ADC chain's inputs: the two recorded files, the explicit
/// project/location, the refused raw-token flag and the endpoints.
///
/// [`AdcSources::from_environment`] is the operator form; a caller that
/// owns the environment (an offline probe) passes the same fields
/// explicitly.
#[derive(Clone)]
pub struct AdcSources {
    /// The file `GOOGLE_APPLICATION_CREDENTIALS` names; a named file that
    /// is missing denies instead of falling through.
    pub gac_file: Option<PathBuf>,
    /// The user ADC file; a missing file falls through to the metadata
    /// leg.
    pub user_adc_file: Option<PathBuf>,
    /// The explicit project the credential is bound to.
    pub project: Option<String>,
    /// The explicit location the credential is bound to.
    pub location: Option<String>,
    /// Set when the operator environment carries a raw access token,
    /// which this resolver refuses as a credential source.
    pub raw_env_token: bool,
    /// The endpoints the legs reach.
    pub endpoints: AdcEndpoints,
}

impl AdcSources {
    /// The operator environment: the recorded variable names, the two
    /// recorded file paths and the recorded endpoints.
    #[must_use]
    pub fn from_environment() -> Self {
        let home = std::env::var_os("HOME").map(PathBuf::from);
        Self {
            gac_file: std::env::var_os(GAC_ENV)
                .map(PathBuf::from)
                .filter(|path| !path.as_os_str().is_empty()),
            user_adc_file: home.map(|home| home.join(USER_ADC_FILE)),
            project: ambient(&["GOOGLE_CLOUD_PROJECT", "GCP_PROJECT", "GCLOUD_PROJECT"]),
            location: ambient(&[
                "GOOGLE_VERTEX_LOCATION",
                "GOOGLE_CLOUD_LOCATION",
                "VERTEX_LOCATION",
            ]),
            raw_env_token: ambient(&["GOOGLE_CLOUD_ACCESS_TOKEN", "CLOUDSDK_AUTH_ACCESS_TOKEN"])
                .is_some(),
            endpoints: AdcEndpoints::recorded(),
        }
    }
}

/// The first non-blank value among `names`; a blank or unreadable value is
/// absent.
fn ambient(names: &[&str]) -> Option<String> {
    ambient_from(names, |name| std::env::var(name).ok())
}

fn ambient_from(names: &[&str], lookup: impl Fn(&str) -> Option<String>) -> Option<String> {
    for name in names {
        let Some(value) = lookup(name) else {
            continue;
        };
        let value = value.trim();
        if !value.is_empty() {
            return Some(value.to_string());
        }
    }
    None
}

/// The endpoint class a denial names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointClass {
    /// The OAuth token exchange.
    Token,
    /// The metadata token endpoint.
    Metadata,
    /// The IAM credentials exchange.
    Impersonation,
}

impl fmt::Display for EndpointClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Token => "token",
            Self::Metadata => "metadata",
            Self::Impersonation => "impersonation",
        })
    }
}

/// The ADC source a credential came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialSource {
    /// The file `GOOGLE_APPLICATION_CREDENTIALS` names.
    GacFile,
    /// The user ADC file.
    UserAdcFile,
    /// The admitted metadata endpoint.
    Metadata,
}

impl fmt::Display for CredentialSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::GacFile => "GOOGLE_APPLICATION_CREDENTIALS",
            Self::UserAdcFile => "user adc",
            Self::Metadata => "metadata",
        })
    }
}

/// The resolved Vertex credential — the producer artifact the adapter
/// consumes through this same struct. The token never renders.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VertexCredential {
    source: CredentialSource,
    project: String,
    location: String,
    access_token: String,
    expires_at: u64,
}

impl fmt::Debug for VertexCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VertexCredential")
            .field("source", &self.source)
            .field("project", &self.project)
            .field("location", &self.location)
            .field("access_token", &login_common::redacted(&self.access_token))
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl VertexCredential {
    /// The ADC source the credential came from.
    #[must_use]
    pub fn source(&self) -> CredentialSource {
        self.source
    }

    /// The explicit project the credential is bound to.
    #[must_use]
    pub fn project(&self) -> &str {
        &self.project
    }

    /// The explicit location the credential is bound to.
    #[must_use]
    pub fn location(&self) -> &str {
        &self.location
    }

    /// The bearer the Vertex adapter sends.
    #[must_use]
    pub fn access_token(&self) -> &str {
        &self.access_token
    }

    /// The token's expiry in seconds since the Unix epoch, with the
    /// recorded skew already subtracted.
    #[must_use]
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }
}

/// One ADC resolution failure. Display text is English and lowercase, and
/// never carries a path, a URL, a token or stored bytes.
#[derive(Debug, thiserror::Error)]
pub enum LoginError {
    /// The operator environment carries a raw access token, which is not a
    /// recorded credential source.
    #[error("a raw environment access token is not an application default credential source")]
    RawTokenRefused,
    /// The named `GOOGLE_APPLICATION_CREDENTIALS` file does not exist.
    #[error("the GOOGLE_APPLICATION_CREDENTIALS file is missing")]
    GacFileMissing,
    /// A credential file could not be read.
    #[error("the {class} credential file could not be read")]
    CredentialFileUnreadable {
        /// The file class the failure belongs to.
        class: CredentialSource,
        /// The platform's own failure class; it names no path.
        #[source]
        cause: std::io::Error,
    },
    /// A credential file is not the JSON its recorded shape needs.
    #[error("the {class} credential file is not the recorded shape: {reason}")]
    CredentialFileMalformed {
        /// The file class the failure belongs to.
        class: CredentialSource,
        /// The parse failure's class — serde's message could quote bytes.
        reason: &'static str,
    },
    /// A credential file declares a type this build does not exchange.
    #[error("the {class} credential file declares no supported credential type")]
    UnsupportedCredentialType {
        /// The file class the failure belongs to.
        class: CredentialSource,
    },
    /// A credential file omitted a field its exchange needs.
    #[error("the credential file carries no {field}")]
    MissingField {
        /// The recorded field name.
        field: &'static str,
    },
    /// The credential is bound to no project.
    #[error("no project is configured for the vertex connection")]
    MissingProject,
    /// The credential is bound to no location.
    #[error("no location is configured for the vertex connection")]
    MissingLocation,
    /// An endpoint outside the recorded contract or a loopback peer.
    #[error("the {class} endpoint is outside the admitted contract")]
    EndpointNotAdmitted {
        /// The endpoint class that was refused.
        class: EndpointClass,
    },
    /// A leg answered a non-success status; the body is never read.
    #[error("the {class} exchange was rejected with http status {status}")]
    ExchangeRejected {
        /// The endpoint class that rejected the exchange.
        class: EndpointClass,
        /// The peer's status code.
        status: u16,
    },
    /// A 2xx reply was not the JSON object the contract records.
    #[error("the credential reply is not the recorded shape: {reason}")]
    MalformedResponse {
        /// The parse failure's class — serde's message could quote bytes.
        reason: &'static str,
    },
    /// The impersonation URL names no target service account.
    #[error("the impersonation url names no target service account")]
    ImpersonatedTargetMissing,
    /// The impersonation URL's target is not a plain service-account name,
    /// so it could rewrite the IAM path it is spliced into.
    #[error("the impersonation url names a malformed target service account")]
    ImpersonatedTargetMalformed,
    /// The private key is not the PKCS#8 RSA key the assertion needs.
    #[error("the service-account private key is not a pkcs#8 rsa key")]
    PrivateKeyUnusable,
    /// The impersonation reply's expiry is not the recorded UTC form.
    #[error("the impersonation reply carries no readable expiry")]
    ExpiryUnreadable,
    /// Every recorded source was exhausted.
    #[error("no application default credentials are available")]
    CredentialsMissing,
    /// The shared resolution budget was exhausted, so no further leg may
    /// start and no result may be published.
    #[error("the credential resolution ran out of its shared budget")]
    ResolutionTimedOut,
    /// The system clock is before the Unix epoch, so no expiry applies.
    #[error("system clock is before the unix epoch")]
    Clock {
        /// The platform's clock failure.
        #[source]
        cause: std::time::SystemTimeError,
    },
    /// The resolved credential could not be encoded for the store.
    #[error("the vertex credential could not be serialized")]
    Serialization {
        /// The encoder failure.
        #[source]
        cause: serde_json::Error,
    },
    /// The material at the scope is not a vertex credential.
    #[error("the stored credential is not a vertex credential: {reason}")]
    StoredCredentialMalformed {
        /// The parse failure's class — serde's message could quote bytes.
        reason: &'static str,
    },
    /// The credential seam's typed denial.
    #[error(transparent)]
    Provider(#[from] ProviderError),
}

/// One live cached token, keyed by source and endpoints.
struct CachedToken {
    access_token: String,
    expires_at: u64,
}

/// The single shared resolution slot: one ADC resolution runs at a time,
/// so a concurrent caller waits for and reuses its result.
static RESOLUTION: Mutex<()> = Mutex::new(());

/// The token cache the skew governs.
static TOKENS: Mutex<BTreeMap<CacheKey, CachedToken>> = Mutex::new(BTreeMap::new());

/// One absolute resolution budget. It starts before the single-flight
/// wait, so a parked caller and every downstream leg consume the same
/// remaining time; an exhausted budget denies instead of starting a leg
/// with a zero bound or publishing a late result.
struct ResolutionBudget {
    deadline: Instant,
    /// The reading the budget consumes. Tests inject it so a spent leg and
    /// a parked caller are proved without wall-clock sleeps; production
    /// reads the system clock.
    #[cfg(test)]
    now: std::sync::Arc<dyn Fn() -> Instant + Send + Sync>,
}

impl ResolutionBudget {
    #[cfg(not(test))]
    fn start() -> Self {
        Self {
            deadline: Instant::now() + RESOLVE_TIMEOUT,
        }
    }

    #[cfg(test)]
    fn start() -> Self {
        Self::at(Instant::now() + RESOLVE_TIMEOUT)
    }

    /// A budget that ends at `deadline`, read from `now`.
    #[cfg(test)]
    fn with_clock(deadline: Instant, now: impl Fn() -> Instant + Send + Sync + 'static) -> Self {
        Self {
            deadline,
            now: std::sync::Arc::new(now),
        }
    }

    /// A budget that ends at `deadline` under the system clock.
    #[cfg(test)]
    fn at(deadline: Instant) -> Self {
        Self::with_clock(deadline, Instant::now)
    }

    #[cfg(not(test))]
    fn now(&self) -> Instant {
        Instant::now()
    }

    #[cfg(test)]
    fn now(&self) -> Instant {
        (self.now)()
    }

    /// The time left for the next leg or publication decision.
    ///
    /// # Errors
    /// [`LoginError::ResolutionTimedOut`] once the budget is exhausted.
    fn remaining(&self) -> Result<Duration, LoginError> {
        self.deadline
            .checked_duration_since(self.now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(LoginError::ResolutionTimedOut)
    }
}

/// Resolves the ADC credential for one Vertex connection: the recorded
/// source order, the file-type exchange, the 60 s refresh skew and the one
/// shared resolution.
///
/// `connection` names the configured connection in transport diagnostics;
/// it is never used to look anything up.
///
/// # Errors
/// [`LoginError::RawTokenRefused`] before any read when the environment
/// carries a raw access token; [`LoginError::MissingProject`]/
/// [`LoginError::MissingLocation`] before any read when the binding is
/// incomplete; [`LoginError::GacFileMissing`] when the named file is
/// absent; the file-shape denials; [`LoginError::CredentialsMissing`] when
/// no source answers; [`LoginError::ResolutionTimedOut`] when the one 30 s
/// budget ends before a leg or the cache publication; and the typed
/// exchange denials.
pub fn resolve(connection: &str, sources: &AdcSources) -> Result<VertexCredential, LoginError> {
    resolve_within(connection, sources, &ResolutionBudget::start())
}

/// One resolution under the caller's budget; the wait, the source read,
/// every leg and the cache publication each consume what is left.
fn resolve_within(
    connection: &str,
    sources: &AdcSources,
    budget: &ResolutionBudget,
) -> Result<VertexCredential, LoginError> {
    if sources.raw_env_token {
        return Err(LoginError::RawTokenRefused);
    }
    let Some(project) = non_blank(sources.project.as_deref()) else {
        return Err(LoginError::MissingProject);
    };
    let Some(location) = non_blank(sources.location.as_deref()) else {
        return Err(LoginError::MissingLocation);
    };
    let _flight = RESOLUTION.lock().unwrap_or_else(PoisonError::into_inner);
    budget.remaining()?;
    // shortcut: a credential-file read is not interruptible, so the budget
    // is re-checked right after it and no leg starts on spent time; upgrade
    // if a blocking (non-regular) source path is ever admitted.
    let loaded = load(sources)?;
    budget.remaining()?;
    let source = loaded.source();
    let key = cache_key(source, loaded.file(), sources);
    if let Some(cached) = cached_token(&key)? {
        return Ok(credential(source, project, location, cached));
    }
    let token = match &loaded {
        Loaded::File(_, _, file) => token_for(connection, sources, file, budget)?,
        Loaded::Metadata => {
            metadata_token(connection, sources, budget)?.ok_or(LoginError::CredentialsMissing)?
        }
    };
    budget.remaining()?;
    remember(key, &token);
    Ok(credential(source, project, location, token))
}

/// Resolves the ADC credential and writes it at the connection's scoped
/// reference — the producer's only write path, through
/// [`CredentialStore::login`], which refuses an occupied scope.
///
/// # Errors
/// [`LoginError::Provider`] for an unknown connection or an unresolvable
/// binding, the [`resolve`] denials (including
/// [`LoginError::ResolutionTimedOut`], which the publication step can also
/// return), and the store's typed denial (including
/// [`ProviderError::CredentialOccupied`] on an enrolled scope).
pub fn login(
    config: &Config,
    connection: &str,
    sources: &AdcSources,
    store: &dyn CredentialStore,
) -> Result<String, LoginError> {
    login_within(
        config,
        connection,
        sources,
        store,
        &ResolutionBudget::start(),
    )
}

/// [`login`] under the caller's budget; the exchange and the publication
/// decision each consume what is left.
fn login_within(
    config: &Config,
    connection: &str,
    sources: &AdcSources,
    store: &dyn CredentialStore,
    budget: &ResolutionBudget,
) -> Result<String, LoginError> {
    let reference = resolve_credential(config, connection)?;
    let credential = resolve_within(connection, sources, budget)?;
    budget.remaining()?;
    store.login(&reference, &serialize(&credential)?)?;
    Ok(reference.profile().to_string())
}

/// Explicitly refreshes the stored Vertex credential: it re-runs the
/// recorded source chain for a fresh token while the stored project and
/// location stay untouched, so `source`, `access_token` and `expires_at`
/// are rewritten to describe the artifact actually obtained. A failed or
/// exhausted exchange writes nothing; the store's own scoped `refresh` is
/// the only write path.
///
/// # Errors
/// [`LoginError::Provider`] when the scope is empty or the store fails,
/// [`LoginError::StoredCredentialMalformed`] when the material is not a
/// vertex credential, and the [`resolve`] denials (including
/// [`LoginError::ResolutionTimedOut`], which the publication step can also
/// return).
pub fn refresh(
    store: &dyn CredentialStore,
    reference: &SecretRef,
    sources: &AdcSources,
) -> Result<String, LoginError> {
    refresh_within(store, reference, sources, &ResolutionBudget::start())
}

/// [`refresh`] under the caller's budget; the exchange and the
/// publication decision each consume what is left.
fn refresh_within(
    store: &dyn CredentialStore,
    reference: &SecretRef,
    sources: &AdcSources,
    budget: &ResolutionBudget,
) -> Result<String, LoginError> {
    let stored = read(store, reference)?;
    let mut bound = sources.clone();
    bound.project = Some(stored.project.clone());
    bound.location = Some(stored.location.clone());
    let fresh = resolve_within(reference.profile(), &bound, budget)?;
    let updated = VertexCredential {
        source: fresh.source,
        project: stored.project,
        location: stored.location,
        access_token: fresh.access_token,
        expires_at: fresh.expires_at,
    };
    budget.remaining()?;
    store.refresh(reference, &serialize(&updated)?)?;
    Ok(reference.profile().to_string())
}

/// Reads the vertex credential at a scoped reference — the seam the Vertex
/// adapter consumes the producer artifact through. Parsing is strict:
/// foreign material is a typed denial, never a guess.
///
/// # Errors
/// [`LoginError::Provider`] when the scope is empty or the store fails, and
/// [`LoginError::StoredCredentialMalformed`] when the material is not a
/// vertex credential.
pub fn read(
    store: &dyn CredentialStore,
    reference: &SecretRef,
) -> Result<VertexCredential, LoginError> {
    let bytes = store.resolve(reference)?;
    serde_json::from_slice(&bytes).map_err(|cause| LoginError::StoredCredentialMalformed {
        reason: login_common::malformed_reason(&cause),
    })
}

/// One selected source: a credential file with its class, or the metadata
/// endpoint.
enum Loaded {
    File(CredentialSource, PathBuf, AdcFile),
    Metadata,
}

impl Loaded {
    fn source(&self) -> CredentialSource {
        match self {
            Self::File(class, _, _) => *class,
            Self::Metadata => CredentialSource::Metadata,
        }
    }

    fn file(&self) -> Option<&Path> {
        match self {
            Self::File(_, path, _) => Some(path),
            Self::Metadata => None,
        }
    }
}

/// The recorded ADC file shapes. The enum has no `Debug` and no file bytes
/// leave this module.
enum AdcFile {
    ServiceAccount(ServiceAccountFile),
    AuthorizedUser(AuthorizedUserFile),
    Impersonated {
        url: String,
        delegates: Vec<String>,
        source: Box<AdcFile>,
    },
}

#[derive(Deserialize)]
struct ServiceAccountFile {
    client_email: String,
    private_key: String,
    #[serde(default)]
    private_key_id: Option<String>,
}

#[derive(Deserialize)]
struct AuthorizedUserFile {
    client_id: String,
    client_secret: String,
    refresh_token: String,
}

#[derive(Deserialize)]
struct ImpersonatedFile {
    service_account_impersonation_url: String,
    source_credentials: Value,
    #[serde(default)]
    delegates: Vec<String>,
}

/// One live token the legs share.
struct TokenReply {
    access_token: String,
    expires_at: u64,
}

/// The recorded source order: the named file (a missing file denies), the
/// user ADC file (a missing file falls through), then the metadata leg.
fn load(sources: &AdcSources) -> Result<Loaded, LoginError> {
    if let Some(path) = &sources.gac_file {
        let file = read_file(path, CredentialSource::GacFile, true)?;
        return file
            .map(|file| Loaded::File(CredentialSource::GacFile, path.clone(), file))
            .ok_or(LoginError::GacFileMissing);
    }
    if let Some(path) = &sources.user_adc_file
        && let Some(file) = read_file(path, CredentialSource::UserAdcFile, false)?
    {
        return Ok(Loaded::File(
            CredentialSource::UserAdcFile,
            path.clone(),
            file,
        ));
    }
    Ok(Loaded::Metadata)
}

/// Reads and parses one ADC file. `required` is the named-file rule: its
/// absence denies instead of falling through to the next source.
fn read_file(
    path: &Path,
    class: CredentialSource,
    required: bool,
) -> Result<Option<AdcFile>, LoginError> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(cause) if cause.kind() == std::io::ErrorKind::NotFound => {
            return if required {
                Err(LoginError::GacFileMissing)
            } else {
                Ok(None)
            };
        }
        Err(cause) => return Err(LoginError::CredentialFileUnreadable { class, cause }),
    };
    let value: Value =
        serde_json::from_slice(&bytes).map_err(|cause| LoginError::CredentialFileMalformed {
            class,
            reason: login_common::malformed_reason(&cause),
        })?;
    parse_file(value, class).map(Some)
}

/// Dispatches on the file's own `type`, so an unrecorded type denies
/// rather than being read as the refresh form.
fn parse_file(value: Value, class: CredentialSource) -> Result<AdcFile, LoginError> {
    let kind = value.get("type").and_then(Value::as_str).map(str::to_owned);
    let Some(kind) = kind else {
        return Err(LoginError::UnsupportedCredentialType { class });
    };
    let malformed = |cause: serde_json::Error| LoginError::CredentialFileMalformed {
        class,
        reason: login_common::malformed_reason(&cause),
    };
    match kind.as_str() {
        "service_account" => serde_json::from_value(value)
            .map(AdcFile::ServiceAccount)
            .map_err(malformed),
        "authorized_user" => serde_json::from_value(value)
            .map(AdcFile::AuthorizedUser)
            .map_err(malformed),
        "impersonated_service_account" => {
            let file: ImpersonatedFile = serde_json::from_value(value).map_err(malformed)?;
            let source = parse_source_credential(file.source_credentials, class)?;
            Ok(AdcFile::Impersonated {
                url: file.service_account_impersonation_url,
                delegates: file.delegates,
                source: Box::new(source),
            })
        }
        _ => Err(LoginError::UnsupportedCredentialType { class }),
    }
}

/// An impersonation source is one of the two direct file types; the
/// recorded flow has no nested impersonation target.
fn parse_source_credential(value: Value, class: CredentialSource) -> Result<AdcFile, LoginError> {
    match parse_file(value, class)? {
        AdcFile::Impersonated { .. } => Err(LoginError::UnsupportedCredentialType { class }),
        direct => Ok(direct),
    }
}

/// The token one selected source yields.
fn token_for(
    connection: &str,
    sources: &AdcSources,
    file: &AdcFile,
    budget: &ResolutionBudget,
) -> Result<TokenReply, LoginError> {
    match file {
        AdcFile::ServiceAccount(account) => {
            service_account_exchange(connection, sources, account, budget)
        }
        AdcFile::AuthorizedUser(user) => {
            authorized_user_exchange(connection, sources, user, budget)
        }
        AdcFile::Impersonated {
            url,
            delegates,
            source,
        } => impersonation_exchange(connection, sources, url, delegates, source, budget),
    }
}

/// Signs the recorded assertion and exchanges it for an access token.
fn service_account_exchange(
    connection: &str,
    sources: &AdcSources,
    account: &ServiceAccountFile,
    budget: &ResolutionBudget,
) -> Result<TokenReply, LoginError> {
    if account.client_email.is_empty() {
        return Err(LoginError::MissingField {
            field: "client_email",
        });
    }
    if account.private_key.is_empty() {
        return Err(LoginError::MissingField {
            field: "private_key",
        });
    }
    admit(&sources.endpoints.token, TOKEN_URL, EndpointClass::Token)?;
    let timeout = budget.remaining()?;
    let assertion = jwt_assertion(account, &sources.endpoints.token)?;
    let fields = [
        ("grant_type", JWT_BEARER_GRANT),
        ("assertion", assertion.as_str()),
    ];
    let reply = post_reply(
        connection,
        &sources.endpoints.token,
        EndpointClass::Token,
        timeout,
        Body::Form(&fields),
        &[],
    )?;
    token_reply(&reply)
}

/// Posts the recorded refresh form for an authorized user.
fn authorized_user_exchange(
    connection: &str,
    sources: &AdcSources,
    user: &AuthorizedUserFile,
    budget: &ResolutionBudget,
) -> Result<TokenReply, LoginError> {
    admit(&sources.endpoints.token, TOKEN_URL, EndpointClass::Token)?;
    let timeout = budget.remaining()?;
    let fields = [
        ("client_id", user.client_id.as_str()),
        ("client_secret", user.client_secret.as_str()),
        ("refresh_token", user.refresh_token.as_str()),
        ("grant_type", "refresh_token"),
    ];
    let reply = post_reply(
        connection,
        &sources.endpoints.token,
        EndpointClass::Token,
        timeout,
        Body::Form(&fields),
        &[],
    )?;
    token_reply(&reply)
}

/// Resolves the source credential, then exchanges it at the recorded IAM
/// host for the target service account's access token. The source leg
/// consumes the shared budget, so the IAM leg runs only on what is left.
fn impersonation_exchange(
    connection: &str,
    sources: &AdcSources,
    url: &str,
    delegates: &[String],
    source: &AdcFile,
    budget: &ResolutionBudget,
) -> Result<TokenReply, LoginError> {
    admit(
        &sources.endpoints.iam,
        IAM_URL,
        EndpointClass::Impersonation,
    )?;
    let target = impersonated_target(url)?;
    let source_token = token_for(connection, sources, source, budget)?;
    let timeout = budget.remaining()?;
    let base = sources.endpoints.iam.trim_end_matches('/');
    let endpoint = format!("{base}/projects/-/serviceAccounts/{target}:generateAccessToken");
    let payload = serde_json::json!({
        "delegates": delegates,
        "scope": [CLOUD_PLATFORM_SCOPE],
        "lifetime": "3600s",
    });
    let authorization = format!("Bearer {}", source_token.access_token);
    let reply = post_reply(
        connection,
        &endpoint,
        EndpointClass::Impersonation,
        timeout,
        Body::Json(&payload),
        &[("authorization", authorization.as_str())],
    )?;
    let access_token =
        login_common::text_field(&reply, "accessToken").ok_or(LoginError::MissingField {
            field: "accessToken",
        })?;
    let expire =
        reply
            .get("expireTime")
            .and_then(Value::as_str)
            .ok_or(LoginError::MissingField {
                field: "expireTime",
            })?;
    let expire_at = rfc3339_seconds(expire).ok_or(LoginError::ExpiryUnreadable)?;
    let now = clock_seconds()?;
    Ok(TokenReply {
        access_token,
        expires_at: expires_at(expire_at.saturating_sub(now))?,
    })
}

/// The target service account a recorded impersonation URL names. Only the
/// path's target is used: the URL's own host never receives the request.
fn impersonated_target(url: &str) -> Result<String, LoginError> {
    let Ok(parsed) = reqwest::Url::parse(url) else {
        return Err(LoginError::ImpersonatedTargetMalformed);
    };
    let last = parsed
        .path_segments()
        .and_then(|mut segments| segments.next_back())
        .ok_or(LoginError::ImpersonatedTargetMissing)?;
    let target = last
        .strip_suffix(":generateAccessToken")
        .or_else(|| last.strip_suffix(":generateIdToken"))
        .ok_or(LoginError::ImpersonatedTargetMissing)?;
    if target.is_empty() {
        return Err(LoginError::ImpersonatedTargetMissing);
    }
    let plain = target
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'@' | b'.' | b'-' | b'_'));
    if !plain {
        return Err(LoginError::ImpersonatedTargetMalformed);
    }
    Ok(target.to_string())
}

/// The metadata leg under `min(2 s, remaining)`. An unreachable or
/// non-success endpoint is the recorded no-source fallback; an already
/// exhausted shared budget denies typed before the leg starts.
fn metadata_token(
    connection: &str,
    sources: &AdcSources,
    budget: &ResolutionBudget,
) -> Result<Option<TokenReply>, LoginError> {
    admit(
        &sources.endpoints.metadata,
        METADATA_URL,
        EndpointClass::Metadata,
    )?;
    let timeout = budget.remaining()?.min(METADATA_TIMEOUT);
    let started = Instant::now();
    let Ok(client) = login_common::client(connection, timeout) else {
        return Ok(None);
    };
    let Ok(mut response) = client
        .get(&sources.endpoints.metadata)
        .header(METADATA_FLAVOR, "Google")
        .send()
    else {
        return Ok(None);
    };
    if !response.status().is_success() {
        return Ok(None);
    }
    let body = match read_catalog_body(connection, timeout, &mut response, started) {
        Ok(body) => body,
        // A partial read of an unreachable endpoint is the same no-source
        // fallback as an unanswered connection.
        Err(ProviderError::Transport { .. }) => return Ok(None),
        Err(cause) => return Err(LoginError::Provider(cause)),
    };
    let reply: Value =
        serde_json::from_slice(&body).map_err(|cause| LoginError::MalformedResponse {
            reason: login_common::malformed_reason(&cause),
        })?;
    Ok(Some(token_reply(&reply)?))
}

/// One POST under the remaining budget, parsed as the recorded reply
/// object.
fn post_reply(
    connection: &str,
    endpoint: &str,
    class: EndpointClass,
    timeout: Duration,
    body: Body<'_>,
    headers: &[(&str, &str)],
) -> Result<Value, LoginError> {
    let (mut response, started) = login_common::post(connection, endpoint, timeout, body, headers)?;
    if !response.status().is_success() {
        return Err(LoginError::ExchangeRejected {
            class,
            status: response.status().as_u16(),
        });
    }
    let body = read_catalog_body(connection, timeout, &mut response, started)?;
    serde_json::from_slice(&body).map_err(|cause| LoginError::MalformedResponse {
        reason: login_common::malformed_reason(&cause),
    })
}

/// The recorded token reply: `access_token` plus `expires_in` under the
/// refresh skew.
fn token_reply(reply: &Value) -> Result<TokenReply, LoginError> {
    let access_token =
        login_common::text_field(reply, "access_token").ok_or(LoginError::MissingField {
            field: "access_token",
        })?;
    let expires_in =
        reply
            .get("expires_in")
            .and_then(Value::as_u64)
            .ok_or(LoginError::MissingField {
                field: "expires_in",
            })?;
    Ok(TokenReply {
        access_token,
        expires_at: expires_at(expires_in)?,
    })
}

/// The recorded assertion: RS256 over the recorded claims, with the token
/// endpoint as `aud` and a 3600 s lifetime.
fn jwt_assertion(account: &ServiceAccountFile, audience: &str) -> Result<String, LoginError> {
    let now = clock_seconds()?;
    let header = match &account.private_key_id {
        Some(key_id) if !key_id.is_empty() => serde_json::json!({
            "alg": "RS256",
            "typ": "JWT",
            "kid": key_id,
        }),
        _ => serde_json::json!({ "alg": "RS256", "typ": "JWT" }),
    };
    let claims = serde_json::json!({
        "iss": account.client_email,
        "scope": CLOUD_PLATFORM_SCOPE,
        "aud": audience,
        "exp": now.saturating_add(ASSERTION_LIFETIME),
        "iat": now,
    });
    let unsigned = format!("{}.{}", encode_json(&header)?, encode_json(&claims)?);
    let signature = sign_sha256(&account.private_key, unsigned.as_bytes())?;
    Ok(format!(
        "{unsigned}.{}",
        login_common::base64url(&signature)
    ))
}

fn encode_json(value: &Value) -> Result<String, LoginError> {
    let bytes = serde_json::to_vec(value).map_err(|cause| LoginError::Serialization { cause })?;
    Ok(login_common::base64url(&bytes))
}

/// Admits the endpoint before a leg sends: the recorded constant or a
/// loopback contract peer.
fn admit(endpoint: &str, recorded: &str, class: EndpointClass) -> Result<(), LoginError> {
    if login_common::admitted_endpoint(endpoint, recorded) {
        return Ok(());
    }
    Err(LoginError::EndpointNotAdmitted { class })
}

fn clock_seconds() -> Result<u64, LoginError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|age| age.as_secs())
        .map_err(|cause| LoginError::Clock { cause })
}

/// The stored expiry with the recorded skew already subtracted.
fn expires_at(expires_in: u64) -> Result<u64, LoginError> {
    Ok(clock_seconds()?
        .saturating_add(expires_in)
        .saturating_sub(REFRESH_SKEW.as_secs()))
}

fn serialize(credential: &VertexCredential) -> Result<Vec<u8>, LoginError> {
    serde_json::to_vec(credential).map_err(|cause| LoginError::Serialization { cause })
}

fn non_blank(value: Option<&str>) -> Option<&str> {
    value.filter(|value| !value.trim().is_empty())
}

fn credential(
    source: CredentialSource,
    project: &str,
    location: &str,
    token: TokenReply,
) -> VertexCredential {
    VertexCredential {
        source,
        project: project.to_string(),
        location: location.to_string(),
        access_token: token.access_token,
        expires_at: token.expires_at,
    }
}

/// The cache key: the resolved source, the file it came from and the
/// endpoints it exchanged with, so one profile's token is never served to
/// another source, file or endpoint.
type CacheKey = (CredentialSource, Option<PathBuf>, String, String, String);

fn cache_key(source: CredentialSource, file: Option<&Path>, sources: &AdcSources) -> CacheKey {
    (
        source,
        file.map(Path::to_path_buf),
        sources.endpoints.token.clone(),
        sources.endpoints.metadata.clone(),
        sources.endpoints.iam.clone(),
    )
}

/// The live cached token, if the skew has not reached its expiry.
fn cached_token(key: &CacheKey) -> Result<Option<TokenReply>, LoginError> {
    let now = clock_seconds()?;
    let mut tokens = TOKENS.lock().unwrap_or_else(PoisonError::into_inner);
    let live = tokens
        .get(key)
        .filter(|cached| cached.expires_at > now)
        .map(|cached| TokenReply {
            access_token: cached.access_token.clone(),
            expires_at: cached.expires_at,
        });
    if live.is_none() {
        tokens.remove(key);
    }
    drop(tokens);
    Ok(live)
}

fn remember(key: CacheKey, token: &TokenReply) {
    let mut tokens = TOKENS.lock().unwrap_or_else(PoisonError::into_inner);
    tokens.insert(
        key,
        CachedToken {
            access_token: token.access_token.clone(),
            expires_at: token.expires_at,
        },
    );
}

/// The UTC-seconds value of an RFC 3339 `…Z` instant. The IAM reply is the
/// only caller and always emits that form; an offset form is a typed
/// denial rather than a guess.
fn rfc3339_seconds(raw: &str) -> Option<u64> {
    let core = raw.trim().strip_suffix('Z')?;
    let (date, clock) = core.split_once('T')?;
    let mut date = date.split('-');
    let year = date.next()?.parse::<i64>().ok()?;
    let month = date.next()?.parse::<i64>().ok()?;
    let day = date.next()?.parse::<i64>().ok()?;
    let mut clock = clock.split(':');
    let hour = clock.next()?.parse::<i64>().ok()?;
    let minute = clock.next()?.parse::<i64>().ok()?;
    let second = clock.next()?.split('.').next()?.parse::<i64>().ok()?;
    if date.next().is_some() || clock.next().is_some() {
        return None;
    }
    let days = days_from_civil(year, month, day)?;
    let seconds = days
        .checked_mul(86_400)?
        .checked_add(hour.checked_mul(3_600)?)?
        .checked_add(minute.checked_mul(60)?)?
        .checked_add(second)?;
    u64::try_from(seconds).ok()
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Hinnant's civil
/// calendar algorithm); a month or day outside the calendar answers `None`.
fn days_from_civil(year: i64, month: i64, day: i64) -> Option<i64> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let day_of_year = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    Some(era * 146_097 + day_of_era - 719_468)
}

/// The DER bytes of the service account's unencrypted PKCS#8 key: PEM
/// armor stripped, or the bare base64 body an ADC file may carry.
#[cfg(not(target_os = "macos"))]
fn key_der(pem: &str) -> Result<Vec<u8>, LoginError> {
    let mut body = String::with_capacity(pem.len());
    for line in pem.lines() {
        let line = line.trim();
        if line.starts_with("-----") {
            continue;
        }
        body.push_str(line);
    }
    if body.is_empty() {
        return Err(LoginError::PrivateKeyUnusable);
    }
    login_common::base64url_decode(&body).ok_or(LoginError::PrivateKeyUnusable)
}

/// The RS256 signer the service-account exchange needs: a PKCS#8 RSA key
/// in, an RSASSA-PKCS1-v1_5/SHA-256 signature out. A direct service-account
/// file and the service-account source of an impersonation chain use this
/// one signer, and no project-owned RSA arithmetic exists anywhere.
///
/// Off Apple the admitted safe API is OpenSSL: PKCS#8 import plus a
/// SHA-256, PKCS#1 v1.5 `Signer`.
#[cfg(not(target_os = "macos"))]
fn sign_sha256(pem: &str, message: &[u8]) -> Result<Vec<u8>, LoginError> {
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::rsa::Padding;
    use openssl::sign::Signer;

    let Ok(key) = PKey::private_key_from_pkcs8(&key_der(pem)?) else {
        return Err(LoginError::PrivateKeyUnusable);
    };
    let Ok(mut signer) = Signer::new(MessageDigest::sha256(), &key) else {
        return Err(LoginError::PrivateKeyUnusable);
    };
    // A non-RSA key and any other padding class are refused here, before a
    // signature exists.
    let Ok(()) = signer.set_rsa_padding(Padding::PKCS1) else {
        return Err(LoginError::PrivateKeyUnusable);
    };
    let Ok(()) = signer.update(message) else {
        return Err(LoginError::PrivateKeyUnusable);
    };
    let Ok(signature) = signer.sign_to_vec() else {
        return Err(LoginError::PrivateKeyUnusable);
    };
    Ok(signature)
}

/// On macOS the admitted safe API is Security.framework: an import of the
/// armored bytes that names no keychain destination, then
/// `RSASignatureMessagePKCS1v15SHA256`. The null keychain is a source
/// fact; non-persistence is HZN-106 proof, not inferred here.
#[cfg(target_os = "macos")]
fn sign_sha256(pem: &str, message: &[u8]) -> Result<Vec<u8>, LoginError> {
    use security_framework::key::Algorithm;
    use security_framework::os::macos::import_export::{ImportOptions, SecItems};

    let mut items = SecItems::default();
    let Ok(()) = ImportOptions::new()
        .filename("key.pem")
        .items(&mut items)
        .import(&armored(pem))
    else {
        return Err(LoginError::PrivateKeyUnusable);
    };
    let Some(key) = items.keys.first() else {
        return Err(LoginError::PrivateKeyUnusable);
    };
    let Ok(signature) = key.create_signature(Algorithm::RSASignatureMessagePKCS1v15SHA256, message)
    else {
        return Err(LoginError::PrivateKeyUnusable);
    };
    Ok(signature)
}

/// The bytes `SecItemImport` reads: a bare base64 body is wrapped in the
/// same armor, so both existing key forms import.
#[cfg(target_os = "macos")]
fn armored(pem: &str) -> Vec<u8> {
    if pem.contains("-----BEGIN") {
        return pem.as_bytes().to_vec();
    }
    let label = "PRIVATE KEY";
    format!("-----BEGIN {label}-----\n{pem}\n-----END {label}-----\n").into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::StoreKind;

    /// A 2048-bit PKCS#8 RSA fixture (test-only, openssl generated).
    const FIXTURE_KEY: &str = concat!(
        "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDNnqxT6Ut6ZKZj4pcF+NXyp+LB5qM51NS4bl2aLwYnm91ZtM8fmSWtQX81N1hrBs7xDtWgwxYxi175XCf23eo/XjvlSMrEQyKvcVV+r05w/Ckl0Ha0OhT3MKgDS3zkeYDpC+WMVsx5wgo/rs/f/Xi2m9gcpvIIzFcO0VFVCyW8Fma7lzBEpiYzUtpZa5QZ+AGrTENN/FKHQRw5o96/cmT8iR59X4UTFKm5NX0F/OEh5/E/8XGq2rxONB03UiQT95rD+mCMUYv6QWzi0LcY+JwoG5/NuOU1czcoD4FA66kgKYJYFB1yeolVH4Ccl1/d86j2lNW6axGXLUE7GUF45cu/AgMBAAECggEATGjknSIa3Fa+xmuTt7JqvwvIZknw6jK/AfJxcjR7UwjGzukz9wgQSjwGq53vi4YyLL5YgK8+dhbWqk+mwkRhIj9Afsn4H8ra/ttc7AD1Y2MxX04CbqMO23UHWoIY3UaRswiquuYegjirWlL6CMDGtQVg3/TiCIb26xi54qKL2ULG92Oc+aMi2eT1NgDegk+vHqlteH/mTOywgBFutItPHQrf5nJCwoRBdLn8OVZ3E9gm2UaiqkhYl5tUEimj8gwLvFISvvO373b9fFplnUdTlDE9PisStmqxCO0NxHFqIyj5wkvLvzqYX7R+Zpwsna0P+0wWtw5wMIDIHuA4f5oo0QKBgQD0qfI/mLZ+Oql14zeKOGXZbR+z9SwsvkCkLAH6zoZbZZKcSQxlBOXVJ/pfSJad6p6TXQoCnfk0M0WsFAi6HJWVbLNbZ2Ec8xq/HYXixXrL2AUN8sKfKuacejfKg8tqG14x3BTtEnwFdWa5FtRc5WoF16hstf835AmmMAIIlR5ptQKBgQDXJZw7kHUmCXCzwFSTwpoGn4GDctNQTnfNi/uWo45ssIb9zqIztDa8QQ3dOgSa8VRQBFuA89TolNMy/50FsFMN+kXKHww89Yt/CvxO1PwXYF9hEQ0t/vjA50GUXv4TyfWf4DLCLnBW0WVWR5xry1dPp52oM3rulkOTT3RnX774IwKBgFFs2d2Ggn3CIjHEu/A5UtQouBtZJimB69t3dfU1lIuIY2G2AfUAy0jEdFQPwWiu87WRikpSruRLiA174WenKbVAJvTtk+lhku418iAFnxeGPjBlMZZtXbCIEFdKw4D9uLyZRTGdLD9Y0iYZTfXYuA9XtYrwiw7bysZPRe37StLdAoGAekrCl4jxTgGnskTszmCbNJCOCa3HN6qipo+fHm0xk85zrOk7gbA6PJ+txcYov/nVNvaDHLV8nAecVSy+kHE9hIByEwW66xuXg0s3R4gBEziQfpg2qaJ4uw24VSH5wj3WBF5n+8Bx0qeLtpNV8l/O7VQVZXp9sghvuNg9DlV6M4kCgYBj7Pyfz3AFR51TcU4GQvZuvKN9tltMACcWr+Glr5OuGT11MoEec9j9wWryRf4Ae5XltbVFSiuXsdob+NNFIPFA/PNSz0B6PPna8Bse6dIkqi1MGrGx2k/ySMrAS6Pjpoq7yieByakpqLWYyZvB9FJXsyLUmIabMpF1u+/wr/7dGg==",
        "\n",
    );

    /// The fixture wrapped in the PEM armor `gcloud` writes.
    fn fixture_pem() -> String {
        let label = "PRIVATE KEY";
        format!("-----BEGIN {label}-----\n{FIXTURE_KEY}-----END {label}-----\n")
    }

    #[test]
    fn signature_matches_the_openssl_vector() {
        // openssl dgst -sha256 -sign over the same message and fixture key.
        let expected = login_common::base64url_decode(
            "oqVUUavrPqZeGMMeYgFEFljC7azyn5T4QH2VlTT+4qfo46Ie+kLunbF7Dp8FT16+bX1BIJlAN8iImm0zlnhmJc/LhVMhqSB9hTh5CA8en/kefIgAsK0UHmLMApeszmmNSYjkMdjBkXAsl6pi+S8+KLJHEmO/5KL3gfOGe8smfkMPtRIzbONQIp9d6/Nyz0D5fKbt+llRiS15pRuRqIV4gC6RmaJXoA6sWBTOkLP59l7OOoC5MX+EaTzeFBi6lBvoN6TUeUZ9cKxPl9pD7pJms53HMTYTMUOthGRw/Ri0/RBURyuyMjNtrf7NT75bSp2eL4h+IUIe+N/BU+DxobffNw==",
        )
        .expect("the vector decodes");
        let message = b"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJmaXh0dXJlIn0";
        let signature = sign_sha256(&fixture_pem(), message).expect("the fixture key signs");
        assert_eq!(
            signature, expected,
            "the signature matches the openssl vector"
        );
        let other = sign_sha256(&fixture_pem(), b"another message").expect("the same key signs");
        assert_ne!(other, expected, "the vector discriminates the message");
    }

    #[test]
    fn a_pem_without_key_material_is_refused() {
        let label = "PRIVATE KEY";
        let empty = format!("-----BEGIN {label}-----\n-----END {label}-----\n");
        assert!(matches!(
            sign_sha256(&empty, b"x"),
            Err(LoginError::PrivateKeyUnusable)
        ));
    }

    /// A PKCS#8 EC key (test-only, openssl generated): the signer must
    /// refuse anything that is not RSA.
    const EC_FIXTURE_KEY: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgzCzurki+F2E2cxXc8yR0sUGz+h0sDYxcx/1TWMPcgWChRANCAATpAoQbpTOYNiKLyYnEinso7DFjkEjbahxFFAscXKXY6Q3opa9Lei2WP+E8bg1D2wEdAeC52qDnG8bKOsnhDcGE";

    #[test]
    fn a_non_rsa_key_is_refused_without_leaking_it() {
        match sign_sha256(EC_FIXTURE_KEY, b"x") {
            Ok(_signature) => unreachable!("an ec key must not produce an rs256 signature"),
            Err(error) => {
                assert!(matches!(error, LoginError::PrivateKeyUnusable), "{error}");
                assert!(!error.to_string().contains(EC_FIXTURE_KEY), "{error}");
            }
        }
    }

    #[test]
    fn a_truncated_der_is_refused_without_leaking_it() {
        // Decodes as base64 but is not a whole PKCS#8 structure.
        let truncated = &FIXTURE_KEY[..48];
        match sign_sha256(truncated, b"x") {
            Ok(_signature) => unreachable!("a truncated der must not sign"),
            Err(error) => {
                assert!(matches!(error, LoginError::PrivateKeyUnusable), "{error}");
                assert!(!error.to_string().contains(truncated), "{error}");
            }
        }
    }

    /// The fixture key re-encrypted as a PKCS#8 `EncryptedPrivateKeyInfo`
    /// (test-only; `openssl pkcs8 -topk8 -inform DER -v2 aes-256-cbc`). The
    /// signer is given no passphrase, so the import must deny instead of
    /// prompting or guessing.
    const ENCRYPTED_FIXTURE_KEY: &str = concat!(
        "MIIFNTBfBgkqhkiG9w0BBQ0wUjAxBgkqhkiG9w0BBQwwJAQQ6qSB8x71XhDHloqve6D9UwICCAAwDAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEELbj/ngB9XJV0H/e3SMsDrgEggTQcc9IudIOfZfa/MUOb0iT9Iw0sHX3cYySxYPvfTGn5+ZR8xcoPSGQNn3b3qMbYXj0D+RMizd8aPi9yz6WYLbJCT12Oe+92Dp4Lczemi6ed/tBLOwNyOdCskRqmAhwqWHNoaI0NiuGQNBAwWXeGTUx6xZ7uWZKJVQtVajGIXvYo73AnOLVS0zSvVc3UZV4M43FyTAfv5goKA6bsL0M/mIm7X20Z7jFD+kdX9Z8YpY7Emz553HNmdnuptdow1UVPiezk1XSg14i0N8/xUj/lhp8oI76IFFrsdOgEaEIyDo90nN774r1LeNYGVwVSINPg2Nkfazd8fefKfuCfWt7l351VTlFkKgRElK5FCe6D0Fld42SUwxEgfNESm9jCHdOoSr2Q4/ra2ROLFV6tZalr5Yg1BYNXzggyBccmLOYB4jWHt8T6m5L51OOwWzt18aAVsXP+9S33uqUjJd0h7xg9+BKZ5Ml7dWYR3ez24j9Ra1yod8ih1OS3Kk+TY+Gw6d2yJtJaqttIk62kXMl3iZsHRl7sUYXqzPjsjR7LVtuD/XAaMpJfglfypRmwTYJyYUB6wuXYWeD5QxZSgDUfK7HfzZtpQ1gEKbhZKjYYu+tvFaIk+647p+4ZSWd7usBlH9dW/L9BaTEM/rLJBRhDTvueFT84ynVdlk3n9u0cZOKIHELxZ3E14so8zMPoazvugfiRMHxhIDzgMGvgN0XIpStJpK9SFdniyOxaVWJUBudONodkd+uKAvsyfhLEV9s5MGmNomre1xbaC9WdE2XF2XEA0pbsNumxoB4yLRDvQG8emp5/EZ67zWVAqnfTavzGPkr4DSjgSJ8mUh/lod45/lsR4etzyZZ3pP8SzoOy1wJbpbyaqlp9KfQ1QwbsWr7TVo6XiBubxJhdivSNS2fQvsbCv2jgMkb+ixakzgnXjUA+/2uBh/8XleOBnHgJ0Q4KrJmGI+opLmZDegr/OZCPp5e9cSLQaGRlyueSolPU3/Q5D0nMTgMGxRmDUbSLmyjiA9EPMfoGmwFrViq1FjDrNS3qvMwR/Vc0f5l75hB547pwcqjoIQAkVtEy4w8nHmYz5BoszcmfzB1mZJr3DfFye9GsPLP5xV3M0eZhk3BXHeC+RmEFjqyG2n+jdETSBZDyrWO7Bwo9s8QsYKEE1fiKqK4WcaE5kcpy/UyGCVoNKMX3grpPwE5LH6uz/bYrNNDxc0uUla8QivsEgvF34vR94phLjNtEGE6jfQuY8LXT7F0XeOd5zTyvLQW154Ld2wO3H358/7MMkgCpOx+sCfShsl+HIlwE4ayoeVAaVYB2+9o1Blg9z3tSrOgVgFrGjRmPPlKA+3u/bcy3EpFwrEEhnCdTXVTU4nwLH448LQT7lHmBLUhmiWns3CZG0T2f6W6yV6QwGD2p08+f9heCEWl6X8MOcxDLSkOwnV75V+5CgsrSWLTMc/noKEHsu2FW+raSLp7jzMxjilX3jkj6Q62FF6zNQAaUqRWX5QmbApvc9rIkwlJAUUZ2MrCKylf/2UL7YhzUmYzYhu7lJff/3QHRNIr61jCbCSMFujL26xpKQA5Oli8rhr06HhGEYccQb1YVSWwL+JcxlK3J+Vidpu9WE5jWiUxV9nPDuuX0wJ4dtLHSISI+gg=",
        "\n",
    );

    #[test]
    fn an_encrypted_key_without_a_passphrase_is_refused() {
        match sign_sha256(ENCRYPTED_FIXTURE_KEY, b"x") {
            Ok(_signature) => unreachable!("an encrypted key must not sign without a passphrase"),
            Err(error) => {
                assert!(matches!(error, LoginError::PrivateKeyUnusable), "{error}");
                assert!(
                    !error.to_string().contains(ENCRYPTED_FIXTURE_KEY),
                    "{error}"
                );
            }
        }
    }

    #[test]
    fn rfc3339_reads_the_recorded_utc_form_only() {
        assert_eq!(rfc3339_seconds("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(rfc3339_seconds("2026-11-06T12:00:00Z"), Some(1_793_966_400));
        assert_eq!(
            rfc3339_seconds("2026-11-06T12:00:00.500Z"),
            Some(1_793_966_400)
        );
        assert_eq!(rfc3339_seconds("2026-11-06T12:00:00+01:00"), None);
        assert_eq!(rfc3339_seconds("2026-13-06T12:00:00Z"), None);
    }

    #[test]
    fn ambient_names_prefer_the_first_present_value() {
        let lookup = |name: &str| match name {
            "first" => Some("  ".to_string()),
            "second" => Some("value".to_string()),
            _ => None,
        };
        assert_eq!(
            ambient_from(&["first", "second", "third"], lookup).as_deref(),
            Some("value")
        );
        assert_eq!(ambient_from(&["third"], lookup), None);
    }

    /// The sources a budget test needs: a named file that does not exist,
    /// so a read would surface as [`LoginError::GacFileMissing`] instead of
    /// the budget denial under test.
    fn absent_file_sources() -> AdcSources {
        AdcSources {
            gac_file: Some(PathBuf::from("absent-key.json")),
            user_adc_file: None,
            project: Some("fixture-project".to_string()),
            location: Some("us-central1".to_string()),
            raw_env_token: false,
            endpoints: AdcEndpoints::recorded(),
        }
    }

    fn adc_file(directory: &Path, value: &Value) -> PathBuf {
        let path = directory.join("gac.json");
        std::fs::write(
            &path,
            serde_json::to_vec(value).expect("the fixture serializes"),
        )
        .expect("the fixture writes");
        path
    }

    fn authorized_user_fixture() -> Value {
        serde_json::json!({
            "type": "authorized_user",
            "client_id": "fixture-client-id",
            "client_secret": "fixture-client-secret",
            "refresh_token": "fixture-refresh",
        })
    }

    fn service_account_fixture() -> Value {
        serde_json::json!({
            "type": "service_account",
            "client_email": "fixture@example.iam.gserviceaccount.com",
            "private_key": fixture_pem(),
            "private_key_id": "fixture-key-id",
        })
    }

    fn token_payload() -> String {
        serde_json::json!({"access_token": "token-fixture-refresh", "expires_in": 3600}).to_string()
    }

    /// The sources one file-backed resolution needs, pointed at `base`.
    fn file_sources(path: &Path, base: &str) -> AdcSources {
        AdcSources {
            gac_file: Some(path.to_path_buf()),
            user_adc_file: None,
            project: Some("fixture-project".to_string()),
            location: Some("us-central1".to_string()),
            raw_env_token: false,
            endpoints: AdcEndpoints {
                token: format!("{base}/token"),
                metadata: format!("{base}/metadata"),
                iam: format!("{base}/iam"),
            },
        }
    }

    /// The sources that fall through to the metadata leg of `base`.
    fn metadata_sources(base: &str) -> AdcSources {
        AdcSources {
            gac_file: None,
            user_adc_file: None,
            project: Some("fixture-project".to_string()),
            location: Some("us-central1".to_string()),
            raw_env_token: false,
            endpoints: AdcEndpoints {
                token: format!("{base}/token"),
                metadata: format!("{base}/metadata"),
                iam: format!("{base}/iam"),
            },
        }
    }

    fn vertex_config() -> Config {
        Config::parse_validated(
            "config_version = 1\n\
             [connections.vertex]\n\
             kind = \"api_key\"\n\
             endpoint = \"https://us-central1-aiplatform.googleapis.com\"\n\
             credential_ref = \"keychain:rivect-test/vertex\"\n\
             [models.defaults]\n\
             model = { mode = \"auto\" }\n\
             effort = { mode = \"auto\" }\n\
             fallback = { mode = \"auto\" }\n",
        )
        .expect("the vertex config parses")
    }

    /// A budget whose clock advances by `step` on every reading, so a
    /// named guard can be spent without wall-clock sleeps: the readings
    /// below `deadline` pass and the one at `deadline` denies.
    fn step_budget(base: Instant, step: Duration, deadline: Duration) -> ResolutionBudget {
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        ResolutionBudget::with_clock(base + deadline, move || {
            base + step * calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        })
    }

    /// One loopback peer that records each request line and answers it; the
    /// accept loop stops when [`TestPeer::finish`] or its drop runs.
    struct TestPeer {
        base: String,
        seen: std::sync::Arc<Mutex<Vec<String>>>,
        stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
        handle: Option<std::thread::JoinHandle<()>>,
    }

    impl TestPeer {
        fn start(answer: impl Fn(&str) -> String + Send + Sync + 'static) -> Option<Self> {
            use std::io::Write as _;
            use std::sync::Arc;
            use std::sync::atomic::{AtomicBool, Ordering};

            let listener = std::net::TcpListener::bind("127.0.0.1:0").ok()?;
            listener.set_nonblocking(true).ok()?;
            let base = format!("http://{}", listener.local_addr().ok()?);
            let seen = Arc::new(Mutex::new(Vec::new()));
            let recorded = Arc::clone(&seen);
            let stop = Arc::new(AtomicBool::new(false));
            let flag = Arc::clone(&stop);
            let handle = std::thread::Builder::new()
                .spawn(move || {
                    while !flag.load(Ordering::SeqCst) {
                        match listener.accept() {
                            Ok((mut stream, _address)) => {
                                // Darwin inherits the listener's nonblocking flag on accept.
                                stream
                                    .set_nonblocking(false)
                                    .expect("blocking loopback stream");
                                let Some(line) = read_request_line(&mut stream) else {
                                    continue;
                                };
                                recorded
                                    .lock()
                                    .unwrap_or_else(PoisonError::into_inner)
                                    .push(line.clone());
                                let payload = answer(&line);
                                let response = format!(
                                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                                     Content-Length: {}\r\nConnection: close\r\n\r\n{payload}",
                                    payload.len()
                                );
                                drop(stream.write_all(response.as_bytes()));
                            }
                            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                                std::thread::park_timeout(Duration::from_millis(1));
                            }
                            Err(_error) => break,
                        }
                    }
                })
                .ok()?;
            Some(Self {
                base,
                seen,
                stop,
                handle: Some(handle),
            })
        }

        fn requests(&self) -> Vec<String> {
            self.seen
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        }

        /// Stops the accept loop and joins its thread, so every request the
        /// test made is recorded before it reads the list.
        fn finish(&mut self) {
            use std::sync::atomic::Ordering;

            self.stop.store(true, Ordering::SeqCst);
            if let Some(handle) = self.handle.take() {
                drop(handle.join());
            }
        }
    }

    impl Drop for TestPeer {
        fn drop(&mut self) {
            self.finish();
        }
    }

    /// A peer whose answer waits out `delay`: a leg bounded by less than
    /// that ends only by its own budget.
    fn slow_answer_peer(delay: Duration) -> Option<TestPeer> {
        TestPeer::start(move |_line| {
            wait_for(delay);
            token_payload()
        })
    }

    /// Waits out the whole duration; `park_timeout` may wake spuriously.
    fn wait_for(delay: Duration) {
        let deadline = Instant::now() + delay;
        while let Some(left) = deadline
            .checked_duration_since(Instant::now())
            .filter(|left| !left.is_zero())
        {
            std::thread::park_timeout(left);
        }
    }

    /// Reads one request's head and body and answers its request line, so
    /// the client's write never blocks.
    fn read_request_line(stream: &mut std::net::TcpStream) -> Option<String> {
        use std::io::Read as _;

        stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 4096];
        let head_end = loop {
            let read = stream.read(&mut chunk).ok()?;
            if read == 0 {
                return None;
            }
            buffer.extend_from_slice(&chunk[..read]);
            if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
                break position;
            }
        };
        let head = String::from_utf8_lossy(&buffer[..head_end]).to_string();
        let length = head
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
            .unwrap_or(0);
        let body_start = head_end + 4;
        while buffer.len() < body_start + length {
            let read = stream.read(&mut chunk).ok()?;
            if read == 0 {
                break;
            }
            buffer.extend_from_slice(&chunk[..read]);
        }
        head.lines().next().map(str::to_string)
    }

    const STORE_SCOPE: &str = "rivect-test/vertex";
    const STORED_VERTEX: &str = "{\"source\":\"gac_file\",\"project\":\"fixture-project\",\"location\":\"us-central1\",\"access_token\":\"stale-token\",\"expires_at\":1}";

    /// A create-only in-memory store: the publication proofs read their
    /// prior bytes back.
    struct TestStore {
        entries: Mutex<BTreeMap<String, Vec<u8>>>,
    }

    impl TestStore {
        fn empty() -> Self {
            Self {
                entries: Mutex::new(BTreeMap::new()),
            }
        }

        fn with(scope: &str, secret: &[u8]) -> Self {
            let store = Self::empty();
            store
                .entries
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(scope.to_string(), secret.to_vec());
            store
        }

        fn bytes(&self, scope: &str) -> Option<Vec<u8>> {
            self.entries
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get(scope)
                .cloned()
        }
    }

    impl CredentialStore for TestStore {
        fn kind(&self) -> StoreKind {
            StoreKind::Keychain
        }

        fn occupied(&self, credential: &SecretRef) -> Result<bool, ProviderError> {
            Ok(self
                .entries
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .contains_key(credential.scope()))
        }

        fn entry_accounts(&self, _service: &str) -> Result<Vec<String>, ProviderError> {
            Ok(Vec::new())
        }

        fn login(&self, credential: &SecretRef, secret: &[u8]) -> Result<(), ProviderError> {
            let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
            if entries.contains_key(credential.scope()) {
                return Err(ProviderError::CredentialOccupied {
                    scope: credential.scope().to_string(),
                });
            }
            entries.insert(credential.scope().to_string(), secret.to_vec());
            drop(entries);
            Ok(())
        }

        fn resolve(&self, credential: &SecretRef) -> Result<Vec<u8>, ProviderError> {
            self.bytes(credential.scope())
                .ok_or_else(|| ProviderError::CredentialAbsent {
                    scope: credential.scope().to_string(),
                })
        }

        fn refresh(&self, credential: &SecretRef, secret: &[u8]) -> Result<(), ProviderError> {
            self.entries
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(credential.scope().to_string(), secret.to_vec());
            Ok(())
        }

        fn revoke(&self, credential: &SecretRef) -> Result<(), ProviderError> {
            self.entries
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(credential.scope())
                .map(|_| ())
                .ok_or_else(|| ProviderError::CredentialAbsent {
                    scope: credential.scope().to_string(),
                })
        }

        fn logout(&self, credential: &SecretRef) -> Result<(), ProviderError> {
            self.revoke(credential)
        }
    }

    #[test]
    fn an_exhausted_budget_denies_before_any_source_read() {
        let budget = ResolutionBudget::at(Instant::now());

        let result = resolve_within("vertex", &absent_file_sources(), &budget);

        assert!(matches!(result, Err(LoginError::ResolutionTimedOut)));
    }

    #[test]
    fn a_budget_spent_while_the_source_is_read_denies() {
        let Some(peer) = TestPeer::start(|_line| token_payload()) else {
            unreachable!("a loopback peer is required");
        };
        let directory = tempfile::tempdir().expect("a temporary directory");
        let path = adc_file(directory.path(), &authorized_user_fixture());
        let sources = file_sources(&path, &peer.base);
        // A cached token makes the re-check after the read the only guard
        // between the wait and a successful resolution.
        let warm = ResolutionBudget::at(Instant::now() + Duration::from_secs(30));
        resolve_within("vertex", &sources, &warm).expect("the token is cached");
        let base = Instant::now();
        let budget = step_budget(base, Duration::from_secs(20), Duration::from_secs(15));

        let error =
            resolve_within("vertex", &sources, &budget).expect_err("the read spends the budget");

        assert!(matches!(error, LoginError::ResolutionTimedOut), "{error}");
        assert_eq!(
            peer.requests().len(),
            1,
            "the cached token needs no exchange"
        );
    }

    #[test]
    fn a_parked_caller_consumes_its_own_budget() {
        let base = Instant::now();
        let waited = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let observed = std::sync::Arc::clone(&waited);
        let budget = ResolutionBudget::with_clock(base + Duration::from_millis(150), move || {
            base + Duration::from_millis(observed.load(std::sync::atomic::Ordering::SeqCst))
        });
        let sources = absent_file_sources();
        let (announced, hearing) = std::sync::mpsc::sync_channel(1);
        let guard = RESOLUTION.lock().unwrap_or_else(PoisonError::into_inner);
        let handle = std::thread::Builder::new()
            .spawn(move || {
                announced.send(()).expect("the announce lands");
                resolve_within("vertex", &sources, &budget)
            })
            .expect("the parked caller starts");

        // The announce arrives while this thread holds the slot, so the
        // caller is waiting when the clock moves past its whole budget.
        hearing
            .recv()
            .expect("the caller announces before it waits");
        waited.store(250, std::sync::atomic::Ordering::SeqCst);
        drop(guard);

        match handle.join() {
            Ok(result) => assert!(matches!(result, Err(LoginError::ResolutionTimedOut))),
            Err(_panic) => unreachable!("the parked caller thread panicked"),
        }
    }

    #[test]
    fn the_token_leg_is_bounded_by_the_injected_budget() {
        let Some(mut peer) = slow_answer_peer(Duration::from_secs(2)) else {
            unreachable!("a loopback peer is required");
        };
        let directory = tempfile::tempdir().expect("a temporary directory");
        let path = adc_file(directory.path(), &authorized_user_fixture());
        let sources = file_sources(&path, &peer.base);
        let paused = Instant::now();
        let budget =
            ResolutionBudget::with_clock(paused + Duration::from_millis(500), move || paused);

        let error =
            resolve_within("vertex", &sources, &budget).expect_err("the leg's own budget ends it");

        peer.finish();
        assert!(
            matches!(error, LoginError::Provider(ProviderError::Transport { .. })),
            "{error}"
        );
        assert_eq!(
            peer.requests(),
            vec!["POST /token HTTP/1.1".to_string()],
            "the leg's one bounded exchange"
        );
    }

    #[test]
    fn a_source_leg_that_spends_the_budget_stops_the_iam_leg() {
        let elapsed = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let spent = std::sync::Arc::clone(&elapsed);
        let Some(peer) = TestPeer::start(move |_line| {
            spent.store(120_000, std::sync::atomic::Ordering::SeqCst);
            token_payload()
        }) else {
            unreachable!("a loopback peer is required");
        };
        let directory = tempfile::tempdir().expect("a temporary directory");
        let file = serde_json::json!({
            "type": "impersonated_service_account",
            "service_account_impersonation_url": format!(
                "{}/v1/projects/-/serviceAccounts/target@example.iam.gserviceaccount.com:generateAccessToken",
                peer.base
            ),
            "source_credentials": service_account_fixture(),
        });
        let path = adc_file(directory.path(), &file);
        let sources = file_sources(&path, &peer.base);
        let base = Instant::now();
        let observed = std::sync::Arc::clone(&elapsed);
        let budget = ResolutionBudget::with_clock(base + Duration::from_secs(30), move || {
            base + Duration::from_millis(observed.load(std::sync::atomic::Ordering::SeqCst))
        });

        let error = resolve_within("vertex", &sources, &budget)
            .expect_err("the source leg spends the budget");

        assert!(matches!(error, LoginError::ResolutionTimedOut), "{error}");
        let requests = peer.requests();
        assert_eq!(requests.len(), 1, "only the source exchange ran");
        assert!(
            !requests
                .iter()
                .any(|line| line.contains(":generateAccessToken")),
            "the iam leg never started: {requests:?}"
        );
    }

    #[test]
    fn a_budget_spent_at_the_exchange_is_neither_cached_nor_written() {
        let elapsed = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let spent = std::sync::Arc::clone(&elapsed);
        let Some(peer) = TestPeer::start(move |_line| {
            spent.store(120_000, std::sync::atomic::Ordering::SeqCst);
            token_payload()
        }) else {
            unreachable!("a loopback peer is required");
        };
        let directory = tempfile::tempdir().expect("a temporary directory");
        let path = adc_file(directory.path(), &authorized_user_fixture());
        let sources = file_sources(&path, &peer.base);
        let base = Instant::now();
        let observed = std::sync::Arc::clone(&elapsed);
        let budget = ResolutionBudget::with_clock(base + Duration::from_secs(30), move || {
            base + Duration::from_millis(observed.load(std::sync::atomic::Ordering::SeqCst))
        });
        let store = TestStore::empty();
        let config = vertex_config();

        let error = login_within(&config, "vertex", &sources, &store, &budget)
            .expect_err("the exchange spends the budget before publication");

        assert!(matches!(error, LoginError::ResolutionTimedOut), "{error}");
        assert!(store.bytes(STORE_SCOPE).is_none(), "nothing is published");
        let live = ResolutionBudget::at(Instant::now() + Duration::from_secs(30));
        resolve_within("vertex", &sources, &live).expect("the live budget resolves");
        assert_eq!(
            peer.requests().len(),
            2,
            "the spent exchange left no cached token"
        );
    }

    #[test]
    fn a_budget_spent_before_login_writes_nothing() {
        let Some(peer) = TestPeer::start(|_line| token_payload()) else {
            unreachable!("a loopback peer is required");
        };
        let directory = tempfile::tempdir().expect("a temporary directory");
        let path = adc_file(directory.path(), &authorized_user_fixture());
        let sources = file_sources(&path, &peer.base);
        let warm = ResolutionBudget::at(Instant::now() + Duration::from_secs(30));
        resolve_within("vertex", &sources, &warm).expect("the token is cached");
        let store = TestStore::with(STORE_SCOPE, STORED_VERTEX.as_bytes());
        // Two readings fit before the cached token returns; the publication
        // reading is past the deadline.
        let budget = step_budget(
            Instant::now(),
            Duration::from_secs(10),
            Duration::from_secs(15),
        );

        let error = login_within(&vertex_config(), "vertex", &sources, &store, &budget)
            .expect_err("the publication budget is spent");

        assert!(matches!(error, LoginError::ResolutionTimedOut), "{error}");
        assert_eq!(
            store.bytes(STORE_SCOPE),
            Some(STORED_VERTEX.as_bytes().to_vec()),
            "the prior bytes are untouched"
        );
        assert_eq!(
            peer.requests().len(),
            1,
            "the cached token serves the resolve"
        );
    }

    #[test]
    fn a_budget_spent_before_refresh_writes_nothing() {
        let Some(peer) = TestPeer::start(|_line| token_payload()) else {
            unreachable!("a loopback peer is required");
        };
        let directory = tempfile::tempdir().expect("a temporary directory");
        let path = adc_file(directory.path(), &authorized_user_fixture());
        let sources = file_sources(&path, &peer.base);
        let warm = ResolutionBudget::at(Instant::now() + Duration::from_secs(30));
        resolve_within("vertex", &sources, &warm).expect("the token is cached");
        let store = TestStore::with(STORE_SCOPE, STORED_VERTEX.as_bytes());
        let reference = SecretRef::parse("keychain:rivect-test/vertex").expect("the reference");
        let budget = step_budget(
            Instant::now(),
            Duration::from_secs(10),
            Duration::from_secs(15),
        );

        let error = refresh_within(&store, &reference, &sources, &budget)
            .expect_err("the publication budget is spent");

        assert!(matches!(error, LoginError::ResolutionTimedOut), "{error}");
        assert_eq!(
            store.bytes(STORE_SCOPE),
            Some(STORED_VERTEX.as_bytes().to_vec()),
            "the prior bytes are untouched"
        );
        assert_eq!(
            peer.requests().len(),
            1,
            "the cached token serves the resolve"
        );
    }

    #[test]
    fn the_metadata_leg_is_bounded_by_the_remaining_budget() {
        let Some(mut peer) = slow_answer_peer(Duration::from_millis(1_500)) else {
            unreachable!("a loopback peer is required");
        };
        let sources = metadata_sources(&peer.base);
        let paused = Instant::now();
        let budget =
            ResolutionBudget::with_clock(paused + Duration::from_millis(300), move || paused);

        let result = resolve_within("vertex", &sources, &budget);

        peer.finish();
        assert!(
            matches!(result, Err(LoginError::CredentialsMissing)),
            "the metadata leg ran past the remaining budget"
        );
        assert_eq!(
            peer.requests(),
            vec!["GET /metadata HTTP/1.1".to_string()],
            "the leg's one bounded metadata request"
        );
    }

    #[test]
    fn the_metadata_leg_stops_at_its_recorded_bound() {
        assert_eq!(
            METADATA_TIMEOUT,
            Duration::from_secs(2),
            "the recorded metadata bound"
        );
        let Some(mut peer) = slow_answer_peer(Duration::from_secs(3)) else {
            unreachable!("a loopback peer is required");
        };
        let sources = metadata_sources(&peer.base);
        let budget = ResolutionBudget::at(Instant::now() + Duration::from_secs(10));

        let result = resolve_within("vertex", &sources, &budget);

        peer.finish();
        assert!(
            matches!(result, Err(LoginError::CredentialsMissing)),
            "the metadata leg ran past its 2 s bound"
        );
    }
}
