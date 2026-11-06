//! The GitHub Copilot CAPI owner (DEC-004/DEC-016): one adapter over
//! the shipped Messages, Responses and Chat Completions codecs for
//! `github-copilot`.
//!
//! The recorded 44-id catalogue table is both the model gate and the
//! route source: a `claude-*` row rides Messages, the recorded
//! `gpt-5*`/`grok-4.5`/`grok-4.6`/`mai-*` rows ride Responses, every
//! other row rides the Chat Completions default, and a model outside the
//! table has no route at all. The catalogue is the CAPI `/models`
//! listing filtered to that table.
//!
//! The API base and the CAPI identity come from the stored credential,
//! never a fixed proxy: `api_endpoint` wins when it is an https origin,
//! else `https://copilot-api.{enterprise}` for a normalized enterprise
//! host, else `https://api.githubcopilot.com`. A loopback base is
//! admitted only through [`CopilotProvider::with_base_override`]. Each
//! send resolves the scoped material once — the producer's closed JSON
//! profile or a raw bearer token — then builds its route codec from that
//! send's own base, token and CAPI headers, so no codec or credential
//! survives a send.
//!
//! Only this owner builds the id: the direct codec constructors and
//! [`super::routed::RoutedProvider`] deny `github-copilot`.

use super::anthropic::MessagesProvider;
use super::copilot_login::StoredCredential;
use super::local::ChatCompletionsProvider;
use super::openai::OpenAiProvider;
use super::{
    CatalogModel, CredentialStore, Dialect, Provider, ProviderError, ProviderReply, SecretRef,
    WireAuth, check_deadline, loopback_base, resolve_credential, routed_wire_model,
};
use crate::config::{Config, ConnKind, FixedModel, ModelAssign};
use crate::model::RequestManifest;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The literal connection id this adapter serves.
const CONNECTION: &str = "github-copilot";

/// The recorded public CAPI base.
const PUBLIC_BASE: &str = "https://api.githubcopilot.com";

/// The enterprise API host prefix the recorded normalization uses.
const ENTERPRISE_API_PREFIX: &str = "copilot-api";

/// The diagnostic marker a refused endpoint renders when it is not a URL
/// and so has no safe scheme/host half to show.
const UNPARSED_BASE: &str = "<unparsed endpoint>";

/// The whole-request budget one physical send may take.
const REQUEST_DEADLINE: Duration = Duration::from_secs(120);

/// The recorded CAPI identity headers. These are public protocol
/// constants, not secrets; they ride every catalogue and wire leg.
const CAPI_IDENTITY: [(&str, &str); 6] = [
    ("user-agent", "copilot/1.0.82"),
    ("editor-version", "copilot/1.0.82"),
    ("copilot-integration-id", "copilot-developer-cli"),
    ("copilot-harness-id", "copilot-sdk"),
    ("openai-intent", "conversation-agent"),
    ("x-github-api-version", "2026-08-01"),
];

fn identity_headers() -> BTreeMap<String, String> {
    CAPI_IDENTITY
        .iter()
        .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
        .collect()
}

/// One built sub-codec for a resolved route; the owner builds it per send.
enum RouteCodec {
    Messages(MessagesProvider),
    Responses(OpenAiProvider),
    Chat(ChatCompletionsProvider),
}

impl RouteCodec {
    fn send(&mut self, manifest: &RequestManifest) -> Result<ProviderReply, ProviderError> {
        match self {
            Self::Messages(provider) => provider.send(manifest),
            Self::Responses(provider) => provider.send(manifest),
            Self::Chat(provider) => provider.send(manifest),
        }
    }

    fn catalog_models(&self) -> Result<Vec<CatalogModel>, ProviderError> {
        match self {
            Self::Messages(provider) => provider.catalog_models(),
            Self::Responses(provider) => provider.catalog_models(),
            Self::Chat(provider) => provider.catalog(),
        }
    }
}

/// The credential-derived material one send uses: the resolved token,
/// its CAPI identity headers and the base the route codecs send to.
struct SendMaterial {
    base: String,
    auth: WireAuth,
}

/// The GitHub Copilot CAPI adapter: model → recorded route → one shipped
/// codec, built per send from the stored credential's base and identity.
pub struct CopilotProvider {
    connection: String,
    config: Config,
    store: Arc<dyn CredentialStore>,
    credential: SecretRef,
    /// The loopback-only test override; production resolves the
    /// credential's own base.
    base_override: Option<String>,
    deadline: Duration,
}

impl std::fmt::Debug for CopilotProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CopilotProvider")
            .field("connection", &self.connection)
            .field("credential", &self.credential)
            .field("base_override", &self.base_override)
            .field("deadline", &self.deadline)
            .finish_non_exhaustive()
    }
}

impl CopilotProvider {
    /// Builds the adapter for the literal `github-copilot` connection.
    ///
    /// # Errors
    /// [`ProviderError::DialectMismatch`] for another connection id,
    /// [`ProviderError::UnknownConnection`] for an undeclared id,
    /// [`ProviderError::RegionMismatch`] for a configured region,
    /// [`ProviderError::LocalProfileDeclared`] for a `local` declaration
    /// binding a profile, [`ProviderError::CredentialUnresolved`] for a
    /// `local` declaration or an unresolved scoped binding.
    pub fn new(
        config: &Config,
        connection: &str,
        store: Arc<dyn CredentialStore>,
    ) -> Result<Self, ProviderError> {
        Self::build(config, connection, store, REQUEST_DEADLINE, None)
    }

    /// The same adapter under an explicit whole-request deadline.
    ///
    /// # Errors
    /// [`Self::new`]'s contract.
    pub fn with_deadline(
        config: &Config,
        connection: &str,
        store: Arc<dyn CredentialStore>,
        deadline: Duration,
    ) -> Result<Self, ProviderError> {
        Self::build(config, connection, store, deadline, None)
    }

    /// Builds the adapter for an offline contract peer. The override is
    /// admitted only for a literal loopback host over http(s); any other
    /// value is refused before any send.
    ///
    /// # Errors
    /// [`Self::new`]'s contract, plus
    /// [`ProviderError::UnsendableRequest`] when the override is not a
    /// loopback URL.
    pub fn with_base_override(
        config: &Config,
        connection: &str,
        store: Arc<dyn CredentialStore>,
        deadline: Duration,
        base_override: Option<String>,
    ) -> Result<Self, ProviderError> {
        Self::build(config, connection, store, deadline, base_override)
    }

    fn build(
        config: &Config,
        connection: &str,
        store: Arc<dyn CredentialStore>,
        deadline: Duration,
        base_override: Option<String>,
    ) -> Result<Self, ProviderError> {
        if connection != CONNECTION {
            return Err(ProviderError::DialectMismatch {
                connection: connection.to_string(),
            });
        }
        let conn =
            config
                .connections
                .get(connection)
                .ok_or_else(|| ProviderError::UnknownConnection {
                    connection: connection.to_string(),
                })?;
        if let Some(region) = &conn.region {
            return Err(ProviderError::RegionMismatch {
                connection: connection.to_string(),
                region: region.clone(),
            });
        }
        // CAPI is a credentialled class: a `local` declaration cannot
        // serve it, and a profile beside that kind is the contradictory
        // half to fix first. Both deny before the credential resolves.
        if conn.kind == ConnKind::Local && conn.profile.is_some() {
            return Err(ProviderError::LocalProfileDeclared {
                connection: connection.to_string(),
            });
        }
        if conn.kind == ConnKind::Local {
            return Err(ProviderError::CredentialUnresolved {
                connection: connection.to_string(),
                scope: format!("connections.{connection}.kind"),
                cause: None,
            });
        }
        let credential = resolve_credential(config, connection)?;
        let base_override = match base_override {
            Some(base) => Some(loopback_base(connection, &base)?),
            None => None,
        };
        Ok(Self {
            connection: connection.to_string(),
            config: config.clone(),
            store,
            credential,
            base_override,
            deadline,
        })
    }

    /// The base this adapter resolves for the stored credential: the
    /// admitted loopback override, else the credential's own recorded
    /// origin. Proof reads it without opening a wire leg.
    ///
    /// # Errors
    /// The store's typed denials, [`ProviderError::CredentialMalformed`]
    /// for material outside the recorded forms (a JSON profile outside
    /// the producer's shape, or a blank or non-graphic token), and
    /// [`ProviderError::CredentialBaseMismatch`] for an endpoint that is
    /// not an admitted https base.
    #[doc(hidden)]
    pub fn resolved_base(&self) -> Result<String, ProviderError> {
        self.material().map(|material| material.base)
    }

    /// The model and recorded route for one manifest; a closed-table miss
    /// denies before the credential is resolved or a body exists. A
    /// one-member auto pool naming this connection resolves the closed
    /// table's sorted-first id, the recorded auto semantic.
    fn resolve_model(
        &self,
        manifest: &RequestManifest,
    ) -> Result<(String, Dialect), ProviderError> {
        let model_id = match &manifest.model {
            ModelAssign::Fixed(fixed) => {
                if fixed.connection != self.connection {
                    return Err(ProviderError::DialectMismatch {
                        connection: fixed.connection.clone(),
                    });
                }
                fixed.model_id.as_str()
            }
            ModelAssign::Auto { pool: Some(pool) }
                if pool.len() == 1 && pool[0] == self.connection =>
            {
                super::copilot_first_model().ok_or_else(|| ProviderError::UnpinnedModel {
                    connection: self.connection.clone(),
                })?
            }
            _ => {
                return Err(ProviderError::UnpinnedModel {
                    connection: self.connection.clone(),
                });
            }
        };
        routed_wire_model(&self.connection, model_id).ok_or_else(|| {
            ProviderError::UnsupportedParameter {
                connection: self.connection.clone(),
                parameter: "model",
                model: model_id.to_owned(),
            }
        })
    }

    /// Resolves the scoped profile once: its token, its CAPI identity and
    /// the base the route codecs send to. The store call is the only read
    /// of secret material in one send.
    fn material(&self) -> Result<SendMaterial, ProviderError> {
        let bytes = self.store.resolve(&self.credential)?;
        let (token, credential) = parse_material(&self.connection, &bytes)?;
        let base = match (&self.base_override, credential) {
            (Some(base), _) => base.clone(),
            (None, Some(credential)) => credential_base(&self.connection, &credential)?,
            (None, None) => PUBLIC_BASE.to_string(),
        };
        Ok(SendMaterial {
            base,
            auth: WireAuth::Resolved {
                token,
                headers: identity_headers(),
            },
        })
    }

    /// The config clone one codec builds against: the CAPI base replaces
    /// the configured endpoint, so the codec's recorded paths append to
    /// the credential-derived host.
    fn codec_config(&self, base: &str) -> Config {
        let mut config = self.config.clone();
        if let Some(conn) = config.connections.get_mut(&self.connection) {
            conn.endpoint = base.to_string();
        }
        config
    }

    fn build_codec(
        &self,
        route: Dialect,
        material: SendMaterial,
        deadline: Duration,
    ) -> Result<RouteCodec, ProviderError> {
        let config = self.codec_config(&material.base);
        let store = Arc::clone(&self.store);
        match route {
            Dialect::Messages => MessagesProvider::with_route(
                &config,
                &self.connection,
                store,
                deadline,
                material.auth,
            )
            .map(RouteCodec::Messages),
            Dialect::Responses => OpenAiProvider::with_route(
                &config,
                &self.connection,
                store,
                deadline,
                material.auth,
            )
            .map(RouteCodec::Responses),
            Dialect::ChatCompletions => ChatCompletionsProvider::with_route(
                &config,
                &self.connection,
                store,
                deadline,
                material.auth,
            )
            .map(RouteCodec::Chat),
            _ => Err(ProviderError::DialectMismatch {
                connection: self.connection.clone(),
            }),
        }
    }

    /// The catalogue ids in deterministic sorted order.
    ///
    /// # Errors
    /// [`Self::catalog_models`]'s typed denials.
    pub fn catalog(&self) -> Result<Vec<String>, ProviderError> {
        Ok(self
            .catalog_models()?
            .into_iter()
            .map(|model| model.id)
            .collect())
    }

    /// The CAPI `/models` listing filtered to the closed 44-id table and
    /// its recorded route, under the send's base and identity headers.
    ///
    /// # Errors
    /// The credential and store denials, [`ProviderError::Transport`] for
    /// a failed or non-success leg or an expired budget, and the codec's
    /// typed stream denials for an unreadable listing.
    pub fn catalog_models(&self) -> Result<Vec<CatalogModel>, ProviderError> {
        let started = Instant::now();
        check_deadline(&self.connection, self.deadline, started)?;
        let material = self.material()?;
        let remaining = self.deadline.saturating_sub(started.elapsed());
        check_deadline(&self.connection, self.deadline, started)?;
        let mut models = self
            .build_codec(Dialect::ChatCompletions, material, remaining)?
            .catalog_models()?;
        models.retain(|model| routed_wire_model(&self.connection, &model.id).is_some());
        models.sort_by(|a, b| a.id.cmp(&b.id));
        models.dedup_by(|a, b| a.id == b.id);
        Ok(models)
    }
}

impl Provider for CopilotProvider {
    fn name(&self) -> &'static str {
        "copilot-capi"
    }

    fn serves(&self, connection: &str, _entry: &crate::config::Connection) -> bool {
        connection == self.connection
    }

    /// Sends the frozen manifest through its recorded CAPI route.
    ///
    /// # Errors
    /// [`ProviderError::UnpinnedModel`] for an assignment outside a fixed
    /// pin or a one-member auto pool naming this connection,
    /// [`ProviderError::DialectMismatch`] for a pin naming another
    /// connection, [`ProviderError::UnsupportedParameter`] for a model
    /// outside the closed table, the credential and store denials, and
    /// the chosen codec's send contract.
    fn send(&mut self, manifest: &RequestManifest) -> Result<ProviderReply, ProviderError> {
        let started = Instant::now();
        check_deadline(&self.connection, self.deadline, started)?;
        let (wire_model, route) = self.resolve_model(manifest)?;
        let material = self.material()?;
        let mut routed = manifest.clone();
        routed.model = ModelAssign::Fixed(FixedModel {
            connection: self.connection.clone(),
            model_id: wire_model,
        });
        let remaining = self.deadline.saturating_sub(started.elapsed());
        check_deadline(&self.connection, self.deadline, started)?;
        self.build_codec(route, material, remaining)?.send(&routed)
    }
}

/// The stored material: the producer's closed JSON profile, or a raw
/// bearer token — the shape a hand-enrolled or pasted scope may hold
/// (mirroring [`super::aws::parse_material`]). Returns the trimmed token
/// and the profile when the material is JSON.
fn parse_material(
    connection: &str,
    raw: &[u8],
) -> Result<(String, Option<StoredCredential>), ProviderError> {
    let Ok(text) = std::str::from_utf8(raw) else {
        return Err(malformed_credential(connection));
    };
    let text = text.trim();
    if !text.starts_with('{') {
        return admitted_token(connection, text).map(|token| (token, None));
    }
    let credential: StoredCredential =
        serde_json::from_str(text).map_err(|_json| malformed_credential(connection))?;
    let token = admitted_token(connection, credential.token())?;
    Ok((token, Some(credential)))
}

/// The one bearer-token grammar both stored forms share: non-empty ASCII
/// graphic bytes, whitespace-trimmed at the edges.
fn admitted_token(connection: &str, raw: &str) -> Result<String, ProviderError> {
    let token = raw.trim();
    if token.is_empty() || !token.chars().all(|c| c.is_ascii_graphic()) {
        return Err(malformed_credential(connection));
    }
    Ok(token.to_string())
}

fn malformed_credential(connection: &str) -> ProviderError {
    ProviderError::CredentialMalformed {
        connection: connection.to_string(),
    }
}

/// The credential's recorded base precedence: an admitted https
/// `api_endpoint`, else the enterprise `copilot-api` host, else the
/// public CAPI base.
fn credential_base(
    connection: &str,
    credential: &StoredCredential,
) -> Result<String, ProviderError> {
    if let Some(endpoint) = credential.api_endpoint() {
        return https_base(connection, endpoint);
    }
    if let Some(enterprise) = credential.enterprise_url() {
        return enterprise_base(connection, enterprise);
    }
    Ok(PUBLIC_BASE.to_string())
}

/// A credential-named API base: https only, a usable host, no userinfo,
/// query or fragment, and never a loopback host — loopback is the test
/// override's seam alone.
fn https_base(connection: &str, raw: &str) -> Result<String, ProviderError> {
    let base = raw.trim().trim_end_matches('/');
    let url = reqwest::Url::parse(base).map_err(|_url| base_mismatch(connection, base))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || super::is_loopback_url(&url)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(base_mismatch(connection, base));
    }
    Ok(base.to_string())
}

/// The enterprise base: the normalized host under the recorded
/// `copilot-api.` prefix. A host carrying a scheme, port, path or other
/// URL material is not the normalized enterprise origin.
fn enterprise_base(connection: &str, raw: &str) -> Result<String, ProviderError> {
    let host = raw
        .trim()
        .strip_prefix(&format!("{ENTERPRISE_API_PREFIX}."))
        .unwrap_or(raw.trim());
    if host.is_empty()
        || !host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'))
    {
        return Err(base_mismatch(connection, raw));
    }
    https_base(
        connection,
        &format!("https://{ENTERPRISE_API_PREFIX}.{host}"),
    )
}

/// The rendering a refused endpoint gets in diagnostics: scheme, host and
/// port only — never the path, query, fragment or userinfo, each of which
/// can carry secret material — or a fixed marker when the value is not a
/// URL at all.
fn refused_base(raw: &str) -> String {
    reqwest::Url::parse(raw.trim()).map_or_else(
        |_url| UNPARSED_BASE.to_string(),
        |url| url.origin().ascii_serialization(),
    )
}

fn base_mismatch(connection: &str, raw: &str) -> ProviderError {
    ProviderError::CredentialBaseMismatch {
        connection: connection.to_string(),
        enrolled: refused_base(raw),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stored(raw: &str) -> Result<StoredCredential, serde_json::Error> {
        serde_json::from_str(raw)
    }

    /// The recorded precedence is credential data, not a fixed proxy:
    /// the enrolled https API endpoint wins, the enterprise host folds
    /// onto its CAPI name, and the public profile lands on the public
    /// base. The one-way refuses are http, loopback and a non-host
    /// enterprise value.
    #[test]
    fn credential_base_uses_the_recorded_precedence() -> Result<(), Box<dyn std::error::Error>> {
        let endpoint = stored(
            r#"{"token":"t","api_endpoint":"https://copilot-api.enterprise.example/","expires_at":1}"#,
        )?;
        assert_eq!(
            credential_base(CONNECTION, &endpoint)?,
            "https://copilot-api.enterprise.example"
        );

        let enterprise =
            stored(r#"{"token":"t","enterprise_url":"ghe.example.com","expires_at":1}"#)?;
        assert_eq!(
            credential_base(CONNECTION, &enterprise)?,
            "https://copilot-api.ghe.example.com"
        );

        let prefixed = stored(
            r#"{"token":"t","enterprise_url":"copilot-api.ghe.example.com","expires_at":1}"#,
        )?;
        assert_eq!(
            credential_base(CONNECTION, &prefixed)?,
            "https://copilot-api.ghe.example.com"
        );

        let public = stored(r#"{"token":"t","expires_at":1}"#)?;
        assert_eq!(credential_base(CONNECTION, &public)?, PUBLIC_BASE);

        for raw in [
            r#"{"token":"t","api_endpoint":"http://api.example.com","expires_at":1}"#,
            r#"{"token":"t","api_endpoint":"https://127.0.0.1:9","expires_at":1}"#,
            r#"{"token":"t","enterprise_url":"ghe.example.com/path","expires_at":1}"#,
        ] {
            let credential = stored(raw)?;
            assert!(
                matches!(
                    credential_base(CONNECTION, &credential),
                    Err(ProviderError::CredentialBaseMismatch { .. })
                ),
                "{raw}"
            );
        }
        Ok(())
    }
}
