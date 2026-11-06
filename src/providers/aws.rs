//! AWS store material, region resolution and SigV4 signing for the Bedrock
//! connection ids. The scoped store is the only credential source: parsing
//! reads the supplied bytes alone — never the environment, a shared
//! credentials file or a credential process (INV-002). The one environment
//! read is the non-secret region fallback in [`ambient_region`].
//!
//! Recorded material classes are a Bearer token — raw or
//! `{"bearer_token": "…"}` — and the static-key object
//! `{"access_key_id", "secret_access_key", "session_token"?, "region"?}`.
//! Every other object is a blocked source class (web identity, SSO, ECS,
//! EC2 or `credential_process`) and denies before a wire leg exists.
//!
//! Region precedence is configured, then the material's region, then an
//! ARN's embedded region, then the model's geo prefix (an ambient region
//! counts only when it serves that geo), then `us-east-1`. A geo model's
//! configured region outside its geo is a typed denial, never a silent
//! relocation.
//!
//! [`sign_v4`] signs the caller's header set over the exact body bytes and
//! the canonical double-encoded path. It binds `host` without returning it,
//! so the HTTP client owns the one `Host` header. The AWS `get-vanilla`
//! vector signs no content hash while the Bedrock vector binds
//! `x-amz-content-sha256`, so neither the service nor the signed header set
//! is assumed by this module.

use super::ProviderError;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// The region a non-geo model falls back to when nothing else names one.
const DEFAULT_REGION: &str = "us-east-1";

/// Headers the signer owns; a caller-supplied copy never overrides them.
const SIGNER_OWNED_HEADERS: &[&str] = &[
    "host",
    "x-amz-date",
    "x-amz-security-token",
    "authorization",
];

/// One parsed AWS credential: the store material resolved to a wire class.
/// `Debug` names the class only — token, key and secret never render.
#[derive(Clone, PartialEq, Eq)]
pub enum AwsMaterial {
    /// A Bearer token the write path stores as-is.
    Bearer(String),
    /// The recorded static-key form; `region` is the material's own
    /// region fact, not a configured connection region.
    StaticKeys {
        access_key_id: String,
        secret_access_key: String,
        session_token: Option<String>,
        region: Option<String>,
    },
}

impl std::fmt::Debug for AwsMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bearer(_) => f.write_str("AwsMaterial::Bearer(<redacted>)"),
            Self::StaticKeys {
                session_token,
                region,
                ..
            } => f
                .debug_struct("AwsMaterial::StaticKeys")
                .field("access_key_id", &"<redacted>")
                .field("secret_access_key", &"<redacted>")
                .field(
                    "session_token",
                    &session_token.as_ref().map(|_| "<redacted>"),
                )
                .field("region", region)
                .finish(),
        }
    }
}

/// The closed JSON Bearer form; any additional member is a different class.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BearerForm {
    bearer_token: String,
}

/// The closed JSON static-key form; every optional member may be null.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StaticKeyForm {
    access_key_id: String,
    secret_access_key: String,
    session_token: Option<String>,
    region: Option<String>,
}

/// Parses one store payload into a recorded AWS credential class.
///
/// Only the bytes handed in are read: the credential's environment, a shared
/// credentials file and a credential process are never consulted, so a
/// descriptor naming one of them denies instead of resolving.
///
/// # Errors
/// [`ProviderError::CredentialMalformed`] when the payload is empty, not
/// UTF-8, an unparseable object, or a recorded form with a blank member;
/// [`ProviderError::UnsupportedCredentialClass`] for every other object,
/// classified by its recorded descriptor key.
pub fn parse_material(connection: &str, raw: &[u8]) -> Result<AwsMaterial, ProviderError> {
    let Ok(text) = std::str::from_utf8(raw) else {
        return Err(malformed(connection));
    };
    let text = text.trim();
    if text.is_empty() {
        return Err(malformed(connection));
    }
    if !text.starts_with('{') {
        return Ok(AwsMaterial::Bearer(text.to_owned()));
    }
    if let Ok(form) = serde_json::from_str::<BearerForm>(text) {
        let token = form.bearer_token.trim();
        if token.is_empty() {
            return Err(malformed(connection));
        }
        return Ok(AwsMaterial::Bearer(token.to_owned()));
    }
    if let Ok(form) = serde_json::from_str::<StaticKeyForm>(text) {
        return static_keys(connection, form);
    }
    // The parser's own message can echo the payload, so it is not retained.
    let Ok(value) = serde_json::from_str::<Value>(text) else {
        return Err(malformed(connection));
    };
    Err(ProviderError::UnsupportedCredentialClass {
        connection: connection.to_owned(),
        class: credential_class(&value),
    })
}

fn static_keys(connection: &str, form: StaticKeyForm) -> Result<AwsMaterial, ProviderError> {
    let access_key_id = form.access_key_id.trim();
    let secret_access_key = form.secret_access_key.trim();
    if access_key_id.is_empty() || secret_access_key.is_empty() {
        return Err(malformed(connection));
    }
    Ok(AwsMaterial::StaticKeys {
        access_key_id: access_key_id.to_owned(),
        secret_access_key: secret_access_key.to_owned(),
        session_token: optional_member(form.session_token),
        region: optional_member(form.region),
    })
}

fn optional_member(member: Option<String>) -> Option<String> {
    member
        .map(|member| member.trim().to_owned())
        .filter(|member| !member.is_empty())
}

fn malformed(connection: &str) -> ProviderError {
    ProviderError::CredentialMalformed {
        connection: connection.to_owned(),
    }
}

/// The recorded descriptor class of an object outside the closed forms; a
/// hint-only classification, never a source this build could resolve.
fn credential_class(value: &Value) -> &'static str {
    let Some(object) = value.as_object() else {
        return "unknown";
    };
    if object.contains_key("web_identity_token_file") {
        "web-identity"
    } else if object.keys().any(|key| key.starts_with("sso_")) {
        "sso"
    } else if object.contains_key("container_credentials") {
        "ecs"
    } else if object.contains_key("ec2_metadata") {
        "ec2"
    } else if object.contains_key("credential_process") {
        "credential-process"
    } else {
        "unknown"
    }
}

/// Resolves the region one Bedrock send targets.
///
/// Precedence is configured, material, an ARN's embedded region, then the
/// model's geo prefix: an ambient region is taken only when it serves that
/// geo, otherwise the geo's recorded default stands. A `global.` model and
/// every non-geo id take the configured, material or ambient region and fall
/// back to `us-east-1`. Only the configured region is checked against the
/// model's geo — material and ARN regions are explicit recorded facts.
///
/// Every selected source must match the strict AWS region grammar before
/// it can reach a base builder; an empty or malformed value is a typed
/// denial, and the hostile value itself never renders.
///
/// # Errors
/// [`ProviderError::UnsendableRequest`] when a selected region is not a
/// valid AWS region; [`ProviderError::RegionMismatch`] when a configured
/// region does not serve the model's geo prefix.
pub fn resolve_region(
    connection: &str,
    model_id: &str,
    configured: Option<&str>,
    material_region: Option<&str>,
    ambient: Option<&str>,
) -> Result<String, ProviderError> {
    let geo = geo_prefix(model_table_id(model_id));
    if let Some(region) = configured {
        let region = admit_region(connection, region)?;
        if let Some(geo) = geo
            && !region_serves_geo(geo, region)
        {
            return Err(ProviderError::RegionMismatch {
                connection: connection.to_owned(),
                region: region.to_owned(),
            });
        }
        return Ok(region.to_owned());
    }
    if let Some(region) = material_region {
        return Ok(admit_region(connection, region)?.to_owned());
    }
    if let Some(region) = model_region_from_arn(model_id) {
        return Ok(admit_region(connection, region)?.to_owned());
    }
    let ambient = ambient
        .map(|region| admit_region(connection, region))
        .transpose()?;
    if let Some(geo) = geo {
        if let Some(region) = ambient.filter(|region| region_serves_geo(geo, region)) {
            return Ok(region.to_owned());
        }
        return Ok(geo_default(geo).to_owned());
    }
    Ok(ambient.unwrap_or(DEFAULT_REGION).to_owned())
}

/// The strict AWS region grammar: two letters, an optional `-gov`
/// partition marker, a lowercase name and a numeric index.
fn valid_region(region: &str) -> bool {
    let bytes = region.as_bytes();
    if bytes.len() < 5
        || !bytes[0].is_ascii_lowercase()
        || !bytes[1].is_ascii_lowercase()
        || bytes[2] != b'-'
    {
        return false;
    }
    let rest = &region[3..];
    let rest = rest.strip_prefix("gov-").unwrap_or(rest);
    let Some((name, index)) = rest.rsplit_once('-') else {
        return false;
    };
    !name.is_empty()
        && name.bytes().all(|byte| byte.is_ascii_lowercase())
        && !index.is_empty()
        && index.bytes().all(|byte| byte.is_ascii_digit())
}

/// A region source admitted for a base builder, or a typed denial that
/// never echoes the rejected value.
fn admit_region<'a>(connection: &str, region: &'a str) -> Result<&'a str, ProviderError> {
    if valid_region(region) {
        return Ok(region);
    }
    Err(ProviderError::UnsendableRequest {
        connection: connection.to_owned(),
        reason: "region is not a valid AWS region".to_owned(),
    })
}

/// The non-secret region ambient lookup: `AWS_REGION` first, then
/// `AWS_DEFAULT_REGION`; a blank or unreadable value is absent.
#[must_use]
pub fn ambient_region() -> Option<String> {
    ambient_region_from(|name| std::env::var(name).ok())
}

fn ambient_region_from(lookup: impl Fn(&str) -> Option<String>) -> Option<String> {
    for name in ["AWS_REGION", "AWS_DEFAULT_REGION"] {
        let Some(value) = lookup(name) else {
            continue;
        };
        let value = value.trim();
        if !value.is_empty() {
            return Some(value.to_owned());
        }
    }
    None
}

/// The model's geo prefix, when the literal before the first dot is one of
/// the recorded geos. A `global.` id and every non-geo id answer `None`.
fn geo_prefix(model_id: &str) -> Option<&str> {
    let (prefix, _) = model_id.split_once('.')?;
    matches!(prefix, "us" | "us-gov" | "eu" | "apac" | "au" | "jp").then_some(prefix)
}

/// The recorded region that serves a geo when no ambient region does.
fn geo_default(geo: &str) -> &'static str {
    match geo {
        "us-gov" => "us-gov-west-1",
        "eu" => "eu-west-1",
        "apac" => "ap-southeast-1",
        "au" => "ap-southeast-2",
        "jp" => "ap-northeast-1",
        _ => DEFAULT_REGION,
    }
}

/// Whether `region` is inside `geo`; the `us` geo excludes the government
/// partition, and the `ap-` regions only serve `au`/`jp` where recorded.
fn region_serves_geo(geo: &str, region: &str) -> bool {
    match geo {
        "us-gov" => region.starts_with("us-gov-"),
        "us" => region.starts_with("us-") && !region.starts_with("us-gov-"),
        "eu" => region.starts_with("eu-"),
        "apac" => region.starts_with("ap-"),
        "au" => matches!(region, "ap-southeast-2" | "ap-southeast-4"),
        "jp" => matches!(region, "ap-northeast-1" | "ap-northeast-3"),
        _ => false,
    }
}

/// The region embedded in a Bedrock ARN, if the model id is one.
#[must_use]
pub fn model_region_from_arn(model_id: &str) -> Option<&str> {
    bed_arn(model_id).map(|(region, _)| region)
}

/// The table id of a model: an ARN's `foundation-model/` or
/// `inference-profile/` resource id, else the id verbatim.
#[must_use]
pub fn model_table_id(model_id: &str) -> &str {
    match bed_arn(model_id) {
        Some((_, table_id)) => table_id,
        None => model_id,
    }
}

fn bed_arn(model_id: &str) -> Option<(&str, &str)> {
    let mut parts = model_id.splitn(6, ':');
    if parts.next()? != "arn" {
        return None;
    }
    let partition = parts.next()?;
    if partition.is_empty() || parts.next()? != "bedrock" {
        return None;
    }
    let region = parts.next()?;
    parts.next()?;
    let resource = parts.next()?;
    let table_id = resource
        .strip_prefix("foundation-model/")
        .or_else(|| resource.strip_prefix("inference-profile/"))?;
    (!region.is_empty() && !table_id.is_empty()).then_some((region, table_id))
}

/// The recorded regional Converse base.
#[must_use]
pub fn bedrock_base(region: &str) -> String {
    format!("https://bedrock-runtime.{region}.amazonaws.com")
}

/// The recorded regional Mantle OpenAI-compatible base.
#[must_use]
pub fn mantle_base(region: &str) -> String {
    format!("https://bedrock-mantle.{region}.api.aws/openai/v1")
}

/// The recorded regional Mantle discovery listing.
#[must_use]
pub fn mantle_discovery_base(region: &str) -> String {
    format!("https://bedrock-mantle.{region}.api.aws/v1/models")
}

/// One SigV4 signing input. `headers` is the extra header set the caller
/// binds into the signature; the signer adds `host` and `x-amz-date`.
pub struct SigV4Request<'a> {
    /// The connection id a denial names.
    pub connection: &'a str,
    /// The HTTP verb the signature binds.
    pub method: &'a str,
    /// The `host` value the signature binds; the HTTP client sets it.
    pub host: &'a str,
    /// The request path, signed under the AWS canonical URI rules.
    pub path: &'a str,
    /// The query string, signed verbatim.
    pub query: &'a str,
    /// The exact body bytes the payload hash covers.
    pub body: &'a [u8],
    /// The region in the signing scope.
    pub region: &'a str,
    /// The service in the signing scope.
    pub service: &'a str,
    /// The access key the authorization header names.
    pub access_key_id: &'a str,
    /// The secret the signing key derives from.
    pub secret_access_key: &'a str,
    /// The session token, signed only when non-empty.
    pub session_token: Option<&'a str>,
    /// The `YYYYMMDDTHHMMSSZ` stamp the signature binds.
    pub timestamp: &'a str,
    /// Extra headers to bind; the signer owns the rest.
    pub headers: BTreeMap<String, String>,
}

/// Signs one request with AWS Signature Version 4 and returns the headers the
/// wire leg carries: `authorization`, `x-amz-date`, `x-amz-content-sha256`
/// and, with a session token, `x-amz-security-token`. `host` is bound into
/// the signature but never returned — the HTTP client owns the one `Host`
/// header, so a caller cannot emit a duplicate.
///
/// The payload hash is computed over the exact body bytes. A caller-supplied
/// `x-amz-content-sha256` is normalized to that hash and is signed, which is
/// the Bedrock form; without it the header is still returned but stays
/// outside the signed set, which is the AWS `get-vanilla` form.
///
/// # Errors
/// [`ProviderError::UnsendableRequest`] when the timestamp is not an
/// `YYYYMMDDTHHMMSSZ` value.
pub fn sign_v4(request: SigV4Request<'_>) -> Result<BTreeMap<String, String>, ProviderError> {
    let Some(date) = timestamp_date(request.timestamp) else {
        return Err(ProviderError::UnsendableRequest {
            connection: request.connection.to_owned(),
            reason: "sigv4 timestamp is not in amz-date form".to_owned(),
        });
    };
    let payload_hash = sha256_hex(request.body);
    let signed = signed_header_map(&request, &payload_hash);
    let signed_names = signed_header_names(&signed);
    let canonical = canonical_request(&request, &signed, &signed_names, &payload_hash);
    let scope = format!("{date}/{}/{}/aws4_request", request.region, request.service);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{scope}\n{}",
        request.timestamp,
        sha256_hex(canonical.as_bytes())
    );
    let key = signing_key(
        request.secret_access_key,
        date,
        request.region,
        request.service,
    );
    let signature = crate::config::hex(&hmac_sha256(&key, string_to_sign.as_bytes()));
    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_names}, Signature={signature}",
        request.access_key_id
    );
    let mut headers = signed;
    // The client owns `Host`; returning the signed copy would let a caller
    // emit it twice.
    headers.remove("host");
    headers.insert("x-amz-content-sha256".to_owned(), payload_hash);
    headers.insert("authorization".to_owned(), authorization);
    Ok(headers)
}

fn timestamp_date(timestamp: &str) -> Option<&str> {
    let bytes = timestamp.as_bytes();
    if bytes.len() != 16
        || bytes.get(8) != Some(&b'T')
        || bytes.get(15) != Some(&b'Z')
        || !bytes[..8].iter().all(u8::is_ascii_digit)
        || !bytes[9..15].iter().all(u8::is_ascii_digit)
    {
        return None;
    }
    timestamp.get(..8)
}

fn signed_header_map(request: &SigV4Request<'_>, payload_hash: &str) -> BTreeMap<String, String> {
    let mut signed = BTreeMap::new();
    signed.insert("host".to_owned(), request.host.trim().to_owned());
    signed.insert("x-amz-date".to_owned(), request.timestamp.to_owned());
    if let Some(token) = request
        .session_token
        .map(str::trim)
        .filter(|token| !token.is_empty())
    {
        signed.insert("x-amz-security-token".to_owned(), token.to_owned());
    }
    for (name, value) in &request.headers {
        let name = name.trim().to_ascii_lowercase();
        if name.is_empty() || SIGNER_OWNED_HEADERS.contains(&name.as_str()) {
            continue;
        }
        let value = if name == "x-amz-content-sha256" {
            payload_hash.to_owned()
        } else {
            value.trim().to_owned()
        };
        signed.insert(name, value);
    }
    signed
}

fn signed_header_names(signed: &BTreeMap<String, String>) -> String {
    let mut names = String::new();
    for name in signed.keys() {
        if !names.is_empty() {
            names.push(';');
        }
        names.push_str(name);
    }
    names
}

/// The AWS default canonical URI: each path segment is URI-encoded once
/// more, so an already-encoded `%3A` signs as `%253A` while `/` and the
/// unreserved set stay literal. The wire path is unchanged.
fn canonical_path(path: &str) -> String {
    path.split('/')
        .map(super::percent_encode_component)
        .collect::<Vec<String>>()
        .join("/")
}

fn canonical_request(
    request: &SigV4Request<'_>,
    signed: &BTreeMap<String, String>,
    signed_names: &str,
    payload_hash: &str,
) -> String {
    let path = canonical_path(request.path);
    let mut canonical = String::new();
    for line in [request.method, path.as_str(), request.query] {
        canonical.push_str(line);
        canonical.push('\n');
    }
    for (name, value) in signed {
        canonical.push_str(name);
        canonical.push(':');
        canonical.push_str(value);
        canonical.push('\n');
    }
    canonical.push('\n');
    canonical.push_str(signed_names);
    canonical.push('\n');
    canonical.push_str(payload_hash);
    canonical
}

fn signing_key(secret: &str, date: &str, region: &str, service: &str) -> [u8; 32] {
    let mut seeded = String::with_capacity(4 + secret.len());
    seeded.push_str("AWS4");
    seeded.push_str(secret);
    let mut key = hmac_sha256(seeded.as_bytes(), date.as_bytes());
    for part in [region, service, "aws4_request"] {
        key = hmac_sha256(&key, part.as_bytes());
    }
    key
}

/// HMAC-SHA256 over the 64-byte SHA-256 block, with `sha2` as the only
/// primitive.
fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut block = [0u8; 64];
    if key.len() > block.len() {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0x36u8; 64];
    let mut outer_pad = [0x5cu8; 64];
    for (index, byte) in block.iter().enumerate() {
        inner_pad[index] ^= byte;
        outer_pad[index] ^= byte;
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(data);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner);
    let digest = outer.finalize();
    let mut signature = [0u8; 32];
    signature.copy_from_slice(&digest);
    signature
}

/// The lowercase hex SHA-256 of exactly these bytes.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    crate::config::hex(&Sha256::digest(bytes))
}

/// Formats a wall-clock instant as the SigV4 `YYYYMMDDTHHMMSSZ` stamp.
/// Instants before the Unix epoch clamp to the epoch — the signing contract
/// only ever sees current time.
#[must_use]
pub fn format_amz_date(time: SystemTime) -> String {
    let seconds = match time.duration_since(UNIX_EPOCH) {
        Ok(elapsed) => elapsed.as_secs(),
        Err(_) => 0,
    };
    let days = seconds / 86_400;
    let clock = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}{month:02}{day:02}T{:02}{:02}{:02}Z",
        clock / 3_600,
        (clock % 3_600) / 60,
        clock % 60
    )
}

/// The UTC civil date of a day count since 1970-01-01 (Howard Hinnant's
/// `civil_from_days`, valid for every non-negative day).
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let day_of_era = z % 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_part = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_part + 2) / 5 + 1;
    let month = if month_part < 10 {
        month_part + 3
    } else {
        month_part - 9
    };
    (if month <= 2 { year + 1 } else { year }, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    type RegionCase<'a> = (
        &'a str,
        Option<&'a str>,
        Option<&'a str>,
        Option<&'a str>,
        &'a str,
    );
    type AmbientCase<'a> = (&'a [(&'a str, &'a str)], Option<&'a str>);

    fn region(
        model: &str,
        configured: Option<&str>,
        material: Option<&str>,
        ambient: Option<&str>,
    ) -> Result<String, ProviderError> {
        resolve_region("amazon-bedrock", model, configured, material, ambient)
    }

    fn request<'a>(body: &'a [u8], timestamp: &'a str) -> SigV4Request<'a> {
        SigV4Request {
            connection: "amazon-bedrock",
            method: "GET",
            host: "example.amazonaws.com",
            path: "/",
            query: "",
            body,
            region: "us-east-1",
            service: "service",
            access_key_id: "AKIDEXAMPLE",
            secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            session_token: None,
            timestamp,
            headers: BTreeMap::new(),
        }
    }

    #[test]
    fn aws_material_parses_bearer_and_static_key_forms() {
        assert_eq!(
            parse_material("amazon-bedrock", b"  raw-token\n").expect("raw bearer"),
            AwsMaterial::Bearer("raw-token".to_owned())
        );
        assert_eq!(
            parse_material("amazon-bedrock", br#"{"bearer_token":"json-token"}"#)
                .expect("json bearer"),
            AwsMaterial::Bearer("json-token".to_owned())
        );
        assert_eq!(
            parse_material(
                "amazon-bedrock",
                br#"{"access_key_id":"AKIDEXAMPLE","secret_access_key":"secret-value","session_token":null,"region":null}"#,
            )
            .expect("static keys"),
            AwsMaterial::StaticKeys {
                access_key_id: "AKIDEXAMPLE".to_owned(),
                secret_access_key: "secret-value".to_owned(),
                session_token: None,
                region: None,
            }
        );
        assert_eq!(
            parse_material(
                "amazon-bedrock",
                br#"{"access_key_id":"AKIDEXAMPLE","secret_access_key":"secret-value","session_token":"session","region":"eu-west-2"}"#,
            )
            .expect("static keys with optionals"),
            AwsMaterial::StaticKeys {
                access_key_id: "AKIDEXAMPLE".to_owned(),
                secret_access_key: "secret-value".to_owned(),
                session_token: Some("session".to_owned()),
                region: Some("eu-west-2".to_owned()),
            }
        );

        let malformed: &[&[u8]] = &[
            b"",
            b"   \n",
            b"\xff\xfe",
            br#"{"access_key_id":"AKIDEXAMPLE","secret_access_key":"  "}"#,
            b"{not json",
        ];
        for raw in malformed {
            assert!(
                matches!(
                    parse_material("amazon-bedrock", raw),
                    Err(ProviderError::CredentialMalformed { .. })
                ),
                "{raw:?}"
            );
        }

        let bearer = parse_material("amazon-bedrock", b"raw-token").expect("bearer");
        assert!(!format!("{bearer:?}").contains("raw-token"));
        let keys = parse_material(
            "amazon-bedrock",
            br#"{"access_key_id":"AKIDEXAMPLE","secret_access_key":"super-secret"}"#,
        )
        .expect("static keys");
        let debug = format!("{keys:?}");
        assert!(!debug.contains("super-secret"));
        assert!(!debug.contains("AKIDEXAMPLE"));
    }

    #[test]
    fn aws_material_rejects_unsupported_sources_without_reads() {
        // Readable file: a resolver that honoured the path would return these keys.
        let token = tempfile::NamedTempFile::new().expect("temp token file");
        std::fs::write(
            token.path(),
            br#"{"access_key_id":"AKIDEXAMPLE","secret_access_key":"secret-value","region":"eu-west-2"}"#,
        )
        .expect("static keys in token file");
        let token_path = std::fs::canonicalize(token.path()).expect("absolute token path");
        let token_path_text = token_path.display().to_string();

        // Live loopback endpoint: a resolver that read metadata would connect here.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("loopback listener");
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        let metadata_port = listener.local_addr().expect("listener address").port();

        let web_identity = serde_json::json!({
            "web_identity_token_file": token_path_text,
            "role_arn": "arn:aws:iam::123456789012:role/rivect",
        })
        .to_string();
        let ec2_metadata = format!(r#"{{"ec2_metadata":"http://127.0.0.1:{metadata_port}"}}"#);

        let cases: &[(&str, &str)] = &[
            (web_identity.as_str(), "web-identity"),
            (ec2_metadata.as_str(), "ec2"),
            (
                r#"{"sso_start_url":"https://example.awsapps.com/start","sso_account_id":"123456789012"}"#,
                "sso",
            ),
            (
                r#"{"container_credentials":"http://169.254.170.2/v2/credentials"}"#,
                "ecs",
            ),
            (
                r#"{"credential_process":"/usr/bin/aws-credential-helper"}"#,
                "credential-process",
            ),
            (r#"{"api_key":"raw"}"#, "unknown"),
        ];
        for (raw, class) in cases {
            let error = parse_material("amazon-bedrock", raw.as_bytes()).expect_err("denied");
            let message = error.to_string();
            match error {
                ProviderError::UnsupportedCredentialClass {
                    connection,
                    class: denied,
                } => {
                    assert_eq!(connection, "amazon-bedrock");
                    assert_eq!(denied, *class, "{raw}");
                }
                other => assert!(
                    matches!(other, ProviderError::UnsupportedCredentialClass { .. }),
                    "expected unsupported class, got {other:?}"
                ),
            }
            assert!(!message.contains(&token_path_text));
            assert!(!message.contains("secret-value"));
            assert!(!message.contains("169.254"));
            assert!(!message.contains("/usr/bin"));
        }

        let result = listener.accept();
        assert!(
            matches!(&result, Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
            "unexpected metadata connection: {result:?}"
        );
    }

    #[test]
    fn aws_region_matches_the_recorded_precedence() {
        let cases: &[RegionCase<'_>] = &[
            (
                "eu.anthropic.claude",
                Some("eu-west-3"),
                None,
                None,
                "eu-west-3",
            ),
            (
                "arn:aws:bedrock:ap-southeast-3:123456789012:foundation-model/us.anthropic.claude",
                None,
                None,
                Some("eu-west-1"),
                "ap-southeast-3",
            ),
            (
                "us.anthropic.claude",
                None,
                None,
                Some("us-gov-west-1"),
                "us-east-1",
            ),
            ("us-gov.anthropic.claude", None, None, None, "us-gov-west-1"),
            (
                "eu.anthropic.claude",
                None,
                None,
                Some("eu-central-1"),
                "eu-central-1",
            ),
            (
                "apac.anthropic.claude",
                None,
                None,
                Some("us-east-1"),
                "ap-southeast-1",
            ),
            (
                "au.anthropic.claude",
                None,
                None,
                Some("ap-southeast-4"),
                "ap-southeast-4",
            ),
            ("au.anthropic.claude", None, None, None, "ap-southeast-2"),
            (
                "jp.anthropic.claude",
                None,
                None,
                Some("ap-northeast-3"),
                "ap-northeast-3",
            ),
            ("jp.anthropic.claude", None, None, None, "ap-northeast-1"),
            (
                "global.anthropic.claude",
                None,
                None,
                Some("ap-northeast-1"),
                "ap-northeast-1",
            ),
            (
                "anthropic.claude",
                None,
                None,
                Some("sa-east-1"),
                "sa-east-1",
            ),
            ("anthropic.claude", None, None, None, "us-east-1"),
            (
                "arn:aws:bedrock:us-west-2:123456789012:inference-profile/eu.anthropic.claude",
                None,
                None,
                None,
                "us-west-2",
            ),
        ];
        for (model, configured, material, ambient, expected) in cases {
            assert_eq!(
                region(model, *configured, *material, *ambient).expect("region"),
                *expected,
                "{model}"
            );
        }
    }

    #[test]
    fn aws_ambient_region_prefers_aws_region_and_skips_blanks() {
        let cases: &[AmbientCase<'_>] = &[
            (
                &[
                    ("AWS_REGION", "eu-west-1"),
                    ("AWS_DEFAULT_REGION", "us-west-2"),
                ],
                Some("eu-west-1"),
            ),
            (&[("AWS_DEFAULT_REGION", "us-west-2")], Some("us-west-2")),
            (
                &[("AWS_REGION", "  "), ("AWS_DEFAULT_REGION", "us-west-2")],
                Some("us-west-2"),
            ),
            (&[("AWS_REGION", "eu-west-1 ")], Some("eu-west-1")),
            (&[("AWS_REGION", " "), ("AWS_DEFAULT_REGION", "\t")], None),
            (&[], None),
        ];
        for (table, expected) in cases {
            let region = ambient_region_from(|name| {
                table
                    .iter()
                    .find(|(key, _)| *key == name)
                    .map(|(_, value)| (*value).to_owned())
            });
            assert_eq!(region.as_deref(), *expected, "{table:?}");
        }
    }

    #[test]
    fn aws_material_region_sits_between_configured_and_arn() {
        let model =
            "arn:aws:bedrock:eu-central-1:123456789012:foundation-model/eu.anthropic.claude";
        assert_eq!(model_region_from_arn(model), Some("eu-central-1"));
        assert_eq!(model_table_id(model), "eu.anthropic.claude");
        let gov = "arn:aws-us-gov:bedrock:us-gov-west-1:123456789012:inference-profile/\
                   us-gov.anthropic.claude-fable-5";
        assert_eq!(model_region_from_arn(gov), Some("us-gov-west-1"));
        assert_eq!(model_table_id(gov), "us-gov.anthropic.claude-fable-5");
        assert_eq!(model_region_from_arn("eu.anthropic.claude"), None);
        assert_eq!(model_table_id("eu.anthropic.claude"), "eu.anthropic.claude");

        assert_eq!(
            region(model, Some("eu-west-1"), Some("eu-west-2"), None).expect("configured"),
            "eu-west-1"
        );
        assert_eq!(
            region(model, None, Some("eu-west-2"), None).expect("material"),
            "eu-west-2"
        );
        assert_eq!(
            region(model, None, None, None).expect("arn"),
            "eu-central-1"
        );
    }

    #[test]
    fn aws_sigv4_matches_the_get_vanilla_vector() {
        let request = request(b"", "20150830T123600Z");
        let payload_hash = sha256_hex(request.body);
        let signed = signed_header_map(&request, &payload_hash);
        let signed_names = signed_header_names(&signed);
        assert_eq!(signed_names, "host;x-amz-date");
        let canonical = canonical_request(&request, &signed, &signed_names, &payload_hash);
        assert_eq!(
            sha256_hex(canonical.as_bytes()),
            "bb579772317eb040ac9ed261061d46c1f17a8133879d6129b6e1c25292927e63"
        );

        let headers = sign_v4(request).expect("signature");
        assert_eq!(
            headers["authorization"],
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
             SignedHeaders=host;x-amz-date, \
             Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
        );
        assert_eq!(headers["x-amz-date"], "20150830T123600Z");
        assert_eq!(headers["x-amz-content-sha256"], payload_hash);
        assert!(!headers.contains_key("x-amz-security-token"));
        assert!(
            !headers.contains_key("host"),
            "the signer never returns a second Host"
        );
    }

    /// The exogenous vector: the canonical path re-encodes the wire's
    /// `%3A` as `%253A`; the pinned signature was computed independently
    /// from the AWS SigV4 definition.
    #[test]
    fn aws_sigv4_double_encodes_the_canonical_path() {
        let body = br#"{"messages":[]}"#;
        let mut request = request(body, "20150830T123600Z");
        request.method = "POST";
        request.host = "bedrock-runtime.us-east-1.amazonaws.com";
        request.path = "/model/anthropic.claude-3-5-haiku-20241022-v1%3A0/converse-stream";
        request.service = "bedrock";
        request
            .headers
            .insert("content-type".to_owned(), "application/json".to_owned());
        request
            .headers
            .insert("x-amz-content-sha256".to_owned(), sha256_hex(body));

        let payload_hash = sha256_hex(request.body);
        let signed = signed_header_map(&request, &payload_hash);
        let signed_names = signed_header_names(&signed);
        let canonical = canonical_request(&request, &signed, &signed_names, &payload_hash);
        assert!(
            canonical
                .contains("/model/anthropic.claude-3-5-haiku-20241022-v1%253A0/converse-stream\n"),
            "the canonical path double-encodes the wire escape: {canonical}"
        );
        assert_eq!(
            sha256_hex(canonical.as_bytes()),
            "663fdf72353df7119020fa5071ac6fcfe01d28474d9c21902aaa79b026901ecf"
        );

        let headers = sign_v4(request).expect("signature");
        assert_eq!(
            headers["authorization"],
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/bedrock/aws4_request, \
             SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date, \
             Signature=2a6d14a6ce9be5a231cd3a79930eb73a8072cea122399d4ec25d3ef40374d77e"
        );
    }

    #[test]
    fn aws_sigv4_bedrock_vector_includes_content_hash() {
        let body = br#"{"messages":[]}"#;
        let mut request = request(body, "20150830T123600Z");
        request.method = "POST";
        request.host = "bedrock-runtime.us-east-1.amazonaws.com";
        request.path = "/model/x/converse-stream";
        request.service = "bedrock";
        request
            .headers
            .insert("content-type".to_owned(), "application/json".to_owned());
        request
            .headers
            .insert("x-amz-content-sha256".to_owned(), sha256_hex(body));

        let payload_hash = sha256_hex(request.body);
        let signed = signed_header_map(&request, &payload_hash);
        let signed_names = signed_header_names(&signed);
        assert_eq!(
            signed_names,
            "content-type;host;x-amz-content-sha256;x-amz-date"
        );
        let canonical = canonical_request(&request, &signed, &signed_names, &payload_hash);
        assert_eq!(
            sha256_hex(canonical.as_bytes()),
            "503119d479c7d2acdd34ce45693c6a6d61a7a1701f8e2467010fdfc1a97d65ab"
        );

        let headers = sign_v4(request).expect("signature");
        assert_eq!(
            headers["authorization"],
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/bedrock/aws4_request, \
             SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date, \
             Signature=475ed2dd3048558ef161ab88c76355abcb9f44d5733bf8442bf98a7b32587f23"
        );
        assert_eq!(headers["x-amz-content-sha256"], payload_hash);
        assert_eq!(
            payload_hash,
            "5e4ce7b36ba37b78a5d5f9fd08e6b7b54ba6879d651aa46ec9e1d6fa24ebe30a"
        );
    }

    #[test]
    fn aws_sigv4_session_token_is_signed_and_redacted() {
        let mut request = request(b"", "20150830T123600Z");
        request.session_token = Some("SESSIONTOKEN");

        let payload_hash = sha256_hex(request.body);
        let signed = signed_header_map(&request, &payload_hash);
        let signed_names = signed_header_names(&signed);
        assert_eq!(signed_names, "host;x-amz-date;x-amz-security-token");
        let canonical = canonical_request(&request, &signed, &signed_names, &payload_hash);
        assert_eq!(
            sha256_hex(canonical.as_bytes()),
            "6225a548c04e1e24acaf3ccefb3773eaab0444bab25c029dee088bfded51ebe5"
        );

        let headers = sign_v4(request).expect("signature");
        assert_eq!(headers["x-amz-security-token"], "SESSIONTOKEN");
        assert!(
            headers["authorization"].contains("SignedHeaders=host;x-amz-date;x-amz-security-token")
        );
        assert!(headers["authorization"].contains(
            "Signature=831f504ffe1f73db58488947b64663e56c2079d26b901b8d9d918a81c769e922"
        ));

        let material = parse_material(
            "amazon-bedrock",
            br#"{"access_key_id":"AKIDEXAMPLE","secret_access_key":"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY","session_token":"SESSIONTOKEN"}"#,
        )
        .expect("static keys with session token");
        let debug = format!("{material:?}");
        assert!(!debug.contains("SESSIONTOKEN"));
        assert!(!debug.contains("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"));
        assert!(!debug.contains("AKIDEXAMPLE"));
    }

    #[test]
    fn aws_sigv4_rejects_a_non_date_timestamp() {
        for timestamp in [
            "abcdefghT123456Z",
            "20150830TabcdefZ",
            "20150830X123600Z",
            "20150830T123600X",
            "20150830T12360Z",
        ] {
            let error =
                sign_v4(request(b"", timestamp)).expect_err("timestamp should be unsendable");
            assert!(
                matches!(&error, ProviderError::UnsendableRequest { .. }),
                "expected unsendable request for {timestamp}, got {error:?}"
            );
            if let ProviderError::UnsendableRequest { connection, .. } = error {
                assert_eq!(connection, "amazon-bedrock");
            }
        }
    }

    #[test]
    fn aws_wrong_configured_region_denies() {
        for (model, region) in [
            ("eu.anthropic.claude", "us-west-2"),
            ("au.anthropic.claude", "ap-southeast-1"),
            ("jp.anthropic.claude", "ap-southeast-2"),
        ] {
            let error = resolve_region("amazon-bedrock", model, Some(region), None, None)
                .expect_err("region denial");
            assert!(
                matches!(&error, ProviderError::RegionMismatch { .. }),
                "expected region mismatch for {model}, got {error:?}"
            );
            if let ProviderError::RegionMismatch {
                connection,
                region: denied,
            } = error
            {
                assert_eq!(connection, "amazon-bedrock");
                assert_eq!(denied, region);
            }
        }
    }

    /// Every region source is admitted by the strict grammar before a base
    /// builder sees it; the denial names no rejected value.
    #[test]
    fn aws_region_sources_must_match_the_strict_grammar() {
        for valid in ["us-east-1", "us-gov-west-1", "ap-southeast-2", "cn-north-1"] {
            assert!(valid_region(valid), "{valid}");
            assert_eq!(
                resolve_region(
                    "amazon-bedrock",
                    "anthropic.claude",
                    Some(valid),
                    None,
                    None
                )
                .expect("a valid configured region"),
                valid
            );
        }
        let hostile = ["eu-evil.com/", "x.y", ""];
        for raw in hostile {
            assert!(!valid_region(raw), "{raw:?}");
            let cases = [
                resolve_region("amazon-bedrock", "anthropic.claude", Some(raw), None, None)
                    .expect_err("configured"),
                resolve_region("amazon-bedrock", "anthropic.claude", None, Some(raw), None)
                    .expect_err("material"),
                resolve_region("amazon-bedrock", "anthropic.claude", None, None, Some(raw))
                    .expect_err("ambient"),
            ];
            for error in cases {
                match error {
                    ProviderError::UnsendableRequest { connection, reason } => {
                        assert_eq!(connection, "amazon-bedrock");
                        assert_eq!(reason, "region is not a valid AWS region");
                    }
                    other => assert!(
                        matches!(other, ProviderError::UnsendableRequest { .. }),
                        "expected the region denial, got {other:?}"
                    ),
                }
            }
        }
        for raw in ["eu-evil.com/", "x.y"] {
            let arn = format!(
                "arn:aws:bedrock:{raw}:123456789012:foundation-model/anthropic.claude-opus-4-6-v1"
            );
            let error = resolve_region("amazon-bedrock", &arn, None, None, None)
                .expect_err("an ARN's region is admitted too");
            assert!(
                matches!(
                    error,
                    ProviderError::UnsendableRequest { reason, .. }
                        if reason == "region is not a valid AWS region"
                ),
                "{raw}"
            );
        }
        for invalid in ["us-east", "us-east-1a", "US-EAST-1", "us--1"] {
            assert!(!valid_region(invalid), "{invalid}");
        }
    }

    #[test]
    fn aws_amz_date_renders_the_utc_civil_form() {
        assert_eq!(
            format_amz_date(UNIX_EPOCH + Duration::from_secs(1_440_938_160)),
            "20150830T123600Z"
        );
        assert_eq!(
            format_amz_date(UNIX_EPOCH + Duration::from_secs(1_709_164_800)),
            "20240229T000000Z"
        );
    }
}
