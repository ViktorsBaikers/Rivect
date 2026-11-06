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
//! 3600 s; `authorized_user` posts its refresh token; and
//! `impersonated_service_account` resolves its own source credential first
//! and then targets `projects/-/serviceAccounts/{target}` on the recorded
//! IAM host — never the host the file's own URL names.
//!
//! Tokens are cached per source and endpoint and refreshed 60 s before
//! expiry; one resolution runs at a time under a 30 s leg bound, so
//! concurrent callers share the result. Secret material — tokens, the
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

/// The shared resolution bound every exchange leg runs under
/// (`google-auth.ts:277`).
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(30);

/// The metadata leg's own short bound (`google-auth.ts:168`).
const METADATA_TIMEOUT: Duration = Duration::from_secs(2);

/// The metadata leg's recorded flavor header name (`google-auth.ts:173`).
const METADATA_FLAVOR: &str = "Metadata-Flavor";

/// The three endpoints the ADC legs reach. [`AdcEndpoints::recorded`] is
/// the production form; an offline caller passes its own loopback contract
/// peers.
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
/// no source answers; and the typed exchange denials.
pub fn resolve(connection: &str, sources: &AdcSources) -> Result<VertexCredential, LoginError> {
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
    let loaded = load(sources)?;
    let source = loaded.source();
    let key = cache_key(source, loaded.file(), sources);
    if let Some(cached) = cached_token(&key)? {
        return Ok(credential(source, project, location, cached));
    }
    let token = match &loaded {
        Loaded::File(_, _, file) => token_for(connection, sources, file)?,
        Loaded::Metadata => {
            metadata_token(connection, sources)?.ok_or(LoginError::CredentialsMissing)?
        }
    };
    remember(key, &token);
    Ok(credential(source, project, location, token))
}

/// Resolves the ADC credential and writes it at the connection's scoped
/// reference — the producer's only write path, through
/// [`CredentialStore::login`], which refuses an occupied scope.
///
/// # Errors
/// [`LoginError::Provider`] for an unknown connection or an unresolvable
/// binding, the [`resolve`] denials, and the store's typed denial
/// (including [`ProviderError::CredentialOccupied`] on an enrolled scope).
pub fn login(
    config: &Config,
    connection: &str,
    sources: &AdcSources,
    store: &dyn CredentialStore,
) -> Result<String, LoginError> {
    let reference = resolve_credential(config, connection)?;
    let credential = resolve(connection, sources)?;
    store.login(&reference, &serialize(&credential)?)?;
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
) -> Result<TokenReply, LoginError> {
    match file {
        AdcFile::ServiceAccount(account) => service_account_exchange(connection, sources, account),
        AdcFile::AuthorizedUser(user) => authorized_user_exchange(connection, sources, user),
        AdcFile::Impersonated {
            url,
            delegates,
            source,
        } => impersonation_exchange(connection, sources, url, delegates, source),
    }
}

/// Signs the recorded assertion and exchanges it for an access token.
fn service_account_exchange(
    connection: &str,
    sources: &AdcSources,
    account: &ServiceAccountFile,
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
    let assertion = jwt_assertion(account, &sources.endpoints.token)?;
    let fields = [
        ("grant_type", JWT_BEARER_GRANT),
        ("assertion", assertion.as_str()),
    ];
    let reply = post_reply(
        connection,
        &sources.endpoints.token,
        EndpointClass::Token,
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
) -> Result<TokenReply, LoginError> {
    admit(&sources.endpoints.token, TOKEN_URL, EndpointClass::Token)?;
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
        Body::Form(&fields),
        &[],
    )?;
    token_reply(&reply)
}

/// Resolves the source credential, then exchanges it at the recorded IAM
/// host for the target service account's access token.
fn impersonation_exchange(
    connection: &str,
    sources: &AdcSources,
    url: &str,
    delegates: &[String],
    source: &AdcFile,
) -> Result<TokenReply, LoginError> {
    admit(
        &sources.endpoints.iam,
        IAM_URL,
        EndpointClass::Impersonation,
    )?;
    let target = impersonated_target(url)?;
    let source_token = token_for(connection, sources, source)?;
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

/// The metadata leg under its 2 s bound. An unreachable or non-success
/// endpoint is the recorded no-source fallback, not an error.
fn metadata_token(
    connection: &str,
    sources: &AdcSources,
) -> Result<Option<TokenReply>, LoginError> {
    admit(
        &sources.endpoints.metadata,
        METADATA_URL,
        EndpointClass::Metadata,
    )?;
    let started = Instant::now();
    let Ok(client) = login_common::client(connection, METADATA_TIMEOUT) else {
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
    let body = match read_catalog_body(connection, METADATA_TIMEOUT, &mut response, started) {
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

/// One bounded POST parsed as the recorded reply object.
fn post_reply(
    connection: &str,
    endpoint: &str,
    class: EndpointClass,
    body: Body<'_>,
    headers: &[(&str, &str)],
) -> Result<Value, LoginError> {
    let (mut response, started) =
        login_common::post(connection, endpoint, RESOLVE_TIMEOUT, body, headers)?;
    if !response.status().is_success() {
        return Err(LoginError::ExchangeRejected {
            class,
            status: response.status().as_u16(),
        });
    }
    let body = read_catalog_body(connection, RESOLVE_TIMEOUT, &mut response, started)?;
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
    let signature = rsa::sign_sha256(&account.private_key, unsigned.as_bytes())?;
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

/// The RS256 signer the service-account exchange needs: a PKCS#8 RSA key
/// in, an RSASSA-PKCS1-v1_5/SHA-256 signature out.
///
/// `sha2` is the shipped hash and no admitted crate exposes raw RSA
/// signing, so the modulus arithmetic is the project's own: `u64` limbs
/// over the Montgomery form, only as wide as one key.
mod rsa {
    use super::LoginError;
    use sha2::Digest as _;
    use std::cmp::Ordering;

    /// The DigestInfo prefix for SHA-256 (RFC 8017 §9.2).
    const SHA256_DIGEST_INFO: [u8; 19] = [
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20,
    ];

    /// One parsed key: the modulus width in bytes and both operands.
    struct RsaKey {
        size: usize,
        modulus: Vec<u64>,
        private_exponent: Vec<u64>,
    }

    /// Signs `message` with the PEM-wrapped PKCS#8 private key.
    pub(super) fn sign_sha256(pem: &str, message: &[u8]) -> Result<Vec<u8>, LoginError> {
        let key = private_key(pem)?;
        let digest = sha2::Sha256::digest(message);
        let em = encode_sha256(&digest, key.size)?;
        let signature = mod_pow(&limbs(&em), &key.private_exponent, &key.modulus);
        Ok(to_bytes(&signature, key.size))
    }

    /// The PKCS#1 v1.5 encoding: `00 01 FF.. 00 || DigestInfo || digest`.
    fn encode_sha256(digest: &[u8], size: usize) -> Result<Vec<u8>, LoginError> {
        let tail = SHA256_DIGEST_INFO.len() + digest.len();
        let padding = size
            .checked_sub(3 + tail)
            .filter(|padding| *padding >= 8)
            .ok_or(LoginError::PrivateKeyUnusable)?;
        let mut em = Vec::with_capacity(size);
        em.extend_from_slice(&[0x00, 0x01]);
        em.extend(std::iter::repeat_n(0xff, padding));
        em.push(0x00);
        em.extend_from_slice(&SHA256_DIGEST_INFO);
        em.extend_from_slice(digest);
        Ok(em)
    }

    /// The modulus and private exponent of a PEM-wrapped PKCS#8 RSA key.
    fn private_key(pem: &str) -> Result<RsaKey, LoginError> {
        let body = pem_body(pem)?;
        let der =
            super::login_common::base64url_decode(&body).ok_or(LoginError::PrivateKeyUnusable)?;
        let inner = pkcs8_private_key(&der).ok_or(LoginError::PrivateKeyUnusable)?;
        let (modulus, exponent) = rsap_private_key(inner).ok_or(LoginError::PrivateKeyUnusable)?;
        Ok(RsaKey {
            size: modulus.len(),
            modulus: limbs(modulus),
            private_exponent: limbs(exponent),
        })
    }

    /// The armor-free PEM body; a body with no content is refused.
    fn pem_body(pem: &str) -> Result<String, LoginError> {
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
        Ok(body)
    }

    /// The PKCS#8 `PrivateKeyInfo`'s inner `RSAPrivateKey` OCTET STRING.
    fn pkcs8_private_key(der: &[u8]) -> Option<&[u8]> {
        let (tag, outer, _) = tlv(der)?;
        if tag != 0x30 {
            return None;
        }
        let (tag, _version, rest) = tlv(outer)?;
        if tag != 0x02 {
            return None;
        }
        let (tag, _algorithm, rest) = tlv(rest)?;
        if tag != 0x30 {
            return None;
        }
        let (tag, inner, _) = tlv(rest)?;
        if tag != 0x04 {
            return None;
        }
        Some(inner)
    }

    /// The `RSAPrivateKey`'s modulus and private exponent; every member is
    /// a positive DER INTEGER, so a truncated or negative one is refused.
    fn rsap_private_key(der: &[u8]) -> Option<(&[u8], &[u8])> {
        let (tag, body, _) = tlv(der)?;
        if tag != 0x30 {
            return None;
        }
        let (tag, _version, rest) = tlv(body)?;
        if tag != 0x02 {
            return None;
        }
        let (tag, modulus, rest) = tlv(rest)?;
        if tag != 0x02 {
            return None;
        }
        let (tag, _public_exponent, rest) = tlv(rest)?;
        if tag != 0x02 {
            return None;
        }
        let (tag, private_exponent, _) = tlv(rest)?;
        if tag != 0x02 {
            return None;
        }
        Some((
            positive_integer(modulus)?,
            positive_integer(private_exponent)?,
        ))
    }

    /// `tag, value, rest` of one DER element; definite lengths only.
    fn tlv(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
        let (&tag, rest) = input.split_first()?;
        let (&first, rest) = rest.split_first()?;
        let (length, rest) = if first & 0x80 == 0 {
            (usize::from(first), rest)
        } else {
            let count = usize::from(first & 0x7f);
            if count == 0 || count > 4 {
                return None;
            }
            let (bytes, rest) = rest.split_at_checked(count)?;
            let mut length = 0usize;
            for &byte in bytes {
                length = (length << 8) | usize::from(byte);
            }
            (length, rest)
        };
        let (value, rest) = rest.split_at_checked(length)?;
        Some((tag, value, rest))
    }

    /// A positive INTEGER without its sign padding; a negative or zero
    /// INTEGER is refused.
    fn positive_integer(integer: &[u8]) -> Option<&[u8]> {
        let (&first, _) = integer.split_first()?;
        if first & 0x80 != 0 {
            return None;
        }
        let start = integer.iter().position(|byte| *byte != 0)?;
        Some(&integer[start..])
    }

    /// Big-endian bytes as little-endian `u64` limbs.
    fn limbs(bytes: &[u8]) -> Vec<u64> {
        let mut limbs = Vec::with_capacity(bytes.len().div_ceil(8));
        for chunk in bytes.rchunks(8) {
            let mut limb = 0u64;
            for &byte in chunk {
                limb = (limb << 8) | u64::from(byte);
            }
            limbs.push(limb);
        }
        limbs
    }

    /// A limb vector as fixed-width big-endian bytes.
    fn to_bytes(limbs: &[u64], width: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; width];
        for (index, limb) in limbs.iter().enumerate() {
            for byte in 0..8 {
                let position = index * 8 + byte;
                if position < width {
                    bytes[width - 1 - position] = ((limb >> (byte * 8)) & 0xff) as u8;
                }
            }
        }
        bytes
    }

    /// `base^exponent mod modulus` over `u64` limbs. Both operands are
    /// already reduced and the modulus is odd, so the Montgomery form
    /// applies.
    pub(super) fn mod_pow(base: &[u64], exponent: &[u64], modulus: &[u64]) -> Vec<u64> {
        let width = modulus.len();
        let inverse = mont_inverse(modulus[0]);
        let r_squared = r_squared(modulus);
        let mut one = vec![0u64; width];
        one[0] = 1;
        let base = mont_mul(base, &r_squared, modulus, inverse);
        let mut accumulator = mont_mul(&one, &r_squared, modulus, inverse);
        for limb in exponent.iter().rev() {
            for bit in (0..64).rev() {
                accumulator = mont_mul(&accumulator, &accumulator, modulus, inverse);
                if (limb >> bit) & 1 == 1 {
                    accumulator = mont_mul(&accumulator, &base, modulus, inverse);
                }
            }
        }
        mont_mul(&accumulator, &one, modulus, inverse)
    }

    /// `-n0^{-1} mod 2^64`, the Montgomery reduction factor.
    fn mont_inverse(n0: u64) -> u64 {
        let mut inverse = 1u64;
        for _ in 0..6 {
            inverse = inverse.wrapping_mul(2u64.wrapping_sub(n0.wrapping_mul(inverse)));
        }
        inverse.wrapping_neg()
    }

    /// `a * b * R^{-1} mod n` for inputs below `n`.
    fn mont_mul(a: &[u64], b: &[u64], n: &[u64], inverse: u64) -> Vec<u64> {
        let width = n.len();
        let mut wide = vec![0u64; 2 * width + 2];
        for i in 0..width {
            let mut carry = 0u128;
            for j in 0..width {
                let sum = u128::from(a[i]) * u128::from(b[j]) + u128::from(wide[i + j]) + carry;
                wide[i + j] = sum as u64;
                carry = sum >> 64;
            }
            add_at(&mut wide, i + width, carry);
        }
        for i in 0..width {
            let factor = wide[i].wrapping_mul(inverse);
            let mut carry = 0u128;
            for j in 0..width {
                let sum = u128::from(factor) * u128::from(n[j]) + u128::from(wide[i + j]) + carry;
                wide[i + j] = sum as u64;
                carry = sum >> 64;
            }
            add_at(&mut wide, i + width, carry);
        }
        let mut result = wide[width..=(2 * width)].to_vec();
        if result[width] != 0 || compare(&result[..width], n) != Ordering::Less {
            subtract(&mut result, n);
        }
        result.truncate(width);
        result
    }

    /// Adds a 128-bit value at `index`, carrying upward. The wide buffer
    /// always has room for the final carry.
    fn add_at(wide: &mut [u64], index: usize, value: u128) {
        let mut carry = value;
        let mut i = index;
        while carry != 0 {
            let Some(slot) = wide.get_mut(i) else {
                return;
            };
            let sum = u128::from(*slot) + (carry & u128::from(u64::MAX));
            *slot = sum as u64;
            carry = (carry >> 64) + (sum >> 64);
            i += 1;
        }
    }

    /// `result -= n` with the borrow absorbed by the wider `result`.
    fn subtract(result: &mut [u64], n: &[u64]) {
        let mut borrow = 0u64;
        for (index, slot) in result.iter_mut().enumerate() {
            let word = n.get(index).copied().unwrap_or(0);
            let (difference, first) = slot.overflowing_sub(word);
            let (difference, second) = difference.overflowing_sub(borrow);
            *slot = difference;
            borrow = u64::from(first | second);
        }
    }

    /// Big-endian limb comparison of two equally wide vectors.
    fn compare(left: &[u64], right: &[u64]) -> Ordering {
        for (a, b) in left.iter().rev().zip(right.iter().rev()) {
            match a.cmp(b) {
                Ordering::Equal => {}
                other => return other,
            }
        }
        Ordering::Equal
    }

    /// `R^2 mod n`, built by two rounds of modular doubling over `R`.
    fn r_squared(n: &[u64]) -> Vec<u64> {
        let mut value = vec![0u64; n.len()];
        value[0] = 1;
        for _ in 0..(2 * 64 * n.len()) {
            value = double_mod(&value, n);
        }
        value
    }

    /// `2 * value mod n`.
    fn double_mod(value: &[u64], n: &[u64]) -> Vec<u64> {
        let width = n.len();
        let mut wide = vec![0u64; width + 1];
        let mut carry = 0u64;
        for i in 0..width {
            wide[i] = (value[i] << 1) | carry;
            carry = value[i] >> 63;
        }
        wide[width] = carry;
        if wide[width] != 0 || compare(&wide[..width], n) != Ordering::Less {
            subtract(&mut wide, n);
        }
        wide.truncate(width);
        wide
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn tiny_modulus_pow_matches_the_textbook_vector() {
        // The textbook key: n = 3233, e = 17, d = 2753; 2790^2753 = 65.
        assert_eq!(rsa::mod_pow(&[65], &[17], &[3233]), vec![2790]);
        assert_eq!(rsa::mod_pow(&[2790], &[2753], &[3233]), vec![65]);
    }

    #[test]
    fn signature_matches_the_openssl_vector() {
        // openssl dgst -sha256 -sign over the same message and fixture key.
        let expected = login_common::base64url_decode(
            "oqVUUavrPqZeGMMeYgFEFljC7azyn5T4QH2VlTT+4qfo46Ie+kLunbF7Dp8FT16+bX1BIJlAN8iImm0zlnhmJc/LhVMhqSB9hTh5CA8en/kefIgAsK0UHmLMApeszmmNSYjkMdjBkXAsl6pi+S8+KLJHEmO/5KL3gfOGe8smfkMPtRIzbONQIp9d6/Nyz0D5fKbt+llRiS15pRuRqIV4gC6RmaJXoA6sWBTOkLP59l7OOoC5MX+EaTzeFBi6lBvoN6TUeUZ9cKxPl9pD7pJms53HMTYTMUOthGRw/Ri0/RBURyuyMjNtrf7NT75bSp2eL4h+IUIe+N/BU+DxobffNw==",
        );
        let signature = rsa::sign_sha256(
            &fixture_pem(),
            b"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJmaXh0dXJlIn0",
        )
        .ok();
        assert_eq!(
            signature, expected,
            "the signature matches the openssl vector"
        );
    }

    #[test]
    fn a_pem_without_key_material_is_refused() {
        let label = "PRIVATE KEY";
        let empty = format!("-----BEGIN {label}-----\n-----END {label}-----\n");
        assert!(matches!(
            rsa::sign_sha256(&empty, b"x"),
            Err(LoginError::PrivateKeyUnusable)
        ));
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
}
