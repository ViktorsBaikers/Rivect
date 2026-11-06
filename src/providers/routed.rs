//! The routed owner (DEC-017): one [`Provider`] over the shipped codecs
//! for ids whose recorded wire route depends on the model. A routed id's
//! fixed/auto model resolves first, then the recorded route table names
//! the codec — an alias outside a closed table denies before any wire leg.
//!
//! `gitlab-duo` is a two-leg proxy: the scoped PAT/OAuth material is
//! exchanged for a short-lived token plus headers, and only that token
//! rides the proxy leg. Both legs share one whole-send deadline, the
//! returned headers are forwarded only when their name is `x-gitlab-*`,
//! and the alias is translated to its recorded `upstreamModelId` on the
//! wire. `opencode-go` and `opencode-zen` resolve their scoped key once
//! per send and add the recorded gateway attribution headers to every
//! catalogue and wire leg. Every send builds its codec from the resolved
//! route — the exchanged token and the world-scoped attribution are
//! per-send material, so no codec survives a send. Production proxy bases
//! are the recorded fixed origins; an offline contract peer is admitted
//! only through a loopback origin.

use super::anthropic::MessagesProvider;
use super::gemini::GeminiProvider;
use super::local::ChatCompletionsProvider;
use super::openai::OpenAiProvider;
use super::{
    CatalogModel, CredentialStore, Dialect, Provider, ProviderError, ProviderReply, WireAuth,
    check_deadline, is_loopback_url, open_proxy_connection, read_catalog_body,
    resolve_admitted_credential_in, route_for, routed_catalog, routed_wire_model, routes_for,
    transport, transport_status, violation, wire_body,
};
use crate::config::{Config, ConnKind, FixedModel, ModelAssign};
use crate::model::RequestManifest;
use serde_json::{Value, json};
use sha2::Digest as _;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

const REQUEST_DEADLINE: Duration = Duration::from_secs(120);

const GITLAB_DUO: &str = "gitlab-duo";
const GITLAB_DEFAULT_BASE: &str = "https://gitlab.com";
const GITLAB_PROXY_ORIGIN: &str = "https://cloud.gitlab.com";
const GITLAB_MESSAGES_PROXY_PATH: &str = "/ai/v1/proxy/anthropic";
const GITLAB_OPENAI_PROXY_PATH: &str = "/ai/v1/proxy/openai/v1";
const GITLAB_EXCHANGE_PATH: &str = "/api/v4/ai/third_party_agents/direct_access";

const OPENCODE_GO: &str = "opencode-go";
const OPENCODE_GO_DEFAULT_BASE: &str = "https://opencode.ai/zen/go";
const OPENCODE_ZEN: &str = "opencode-zen";
const OPENCODE_ZEN_DEFAULT_BASE: &str = "https://opencode.ai/zen";

/// Whether `connection` is one of the OpenCode gateways: their scoped key
/// resolves once per send and their attribution is world-scoped, so both
/// build their codec per send and seed the catalogue session from the
/// connection id.
fn is_opencode(connection: &str) -> bool {
    connection == OPENCODE_GO || connection == OPENCODE_ZEN
}

/// The OpenCode attribution headers (DEC-014/DEC-017): the crate UA and a
/// stable session — the first 16 hex chars of the SHA-256 of the send's
/// frozen world, or of the connection id on a catalogue that has no
/// manifest. The gateway keys its session on them, so every catalogue and
/// wire leg carries the pair.
fn opencode_headers(session: &str) -> BTreeMap<String, String> {
    let digest = crate::config::hex(&sha2::Sha256::digest(session.as_bytes()));
    BTreeMap::from([
        (
            "user-agent".to_string(),
            format!("rivect/{}", env!("CARGO_PKG_VERSION")),
        ),
        (
            "x-opencode-session".to_string(),
            digest.chars().take(16).collect(),
        ),
    ])
}

/// One built sub-codec for a resolved route; the owner builds it per send.
enum RouteCodec {
    Messages(MessagesProvider),
    Responses(OpenAiProvider),
    Chat(ChatCompletionsProvider),
    Gemini(GeminiProvider),
}

impl RouteCodec {
    fn send(&mut self, manifest: &RequestManifest) -> Result<ProviderReply, ProviderError> {
        match self {
            Self::Messages(provider) => provider.send(manifest),
            Self::Responses(provider) => provider.send(manifest),
            Self::Chat(provider) => provider.send(manifest),
            Self::Gemini(provider) => provider.send(manifest),
        }
    }

    fn catalog_models(&self) -> Result<Vec<CatalogModel>, ProviderError> {
        match self {
            Self::Messages(provider) => provider.catalog_models(),
            Self::Responses(provider) => provider.catalog_models(),
            Self::Chat(provider) => provider.catalog(),
            Self::Gemini(provider) => Ok(provider
                .catalog()?
                .into_iter()
                .map(|id| CatalogModel {
                    id,
                    ..CatalogModel::default()
                })
                .collect()),
        }
    }
}

/// The routed adapter: model → recorded dialect → the shipped codec for
/// that dialect. Every send builds its codec from the send's own resolved
/// material, so no codec or catalogue is cached across sends.
pub struct RoutedProvider {
    connection: String,
    config: Config,
    store: Arc<dyn CredentialStore>,
    /// The scoped material the exchange leg spends; it never reaches the
    /// proxy leg.
    auth: WireAuth,
    /// The GitLab REST base the exchange posts to.
    exchange_base: String,
    /// The origin the fixed proxy paths are appended to: the recorded
    /// cloud origin, or a loopback override admitted for offline proof.
    proxy_origin: String,
    client: reqwest::blocking::Client,
    deadline: Duration,
}

impl std::fmt::Debug for RoutedProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RoutedProvider")
            .field("connection", &self.connection)
            .field("exchange_base", &self.exchange_base)
            .field("proxy_origin", &self.proxy_origin)
            .field("deadline", &self.deadline)
            .finish_non_exhaustive()
    }
}

impl RoutedProvider {
    /// Builds the routed adapter with the recorded fixed proxy bases.
    ///
    /// # Errors
    /// [`ProviderError::DialectMismatch`] for an id with no recorded
    /// route table, [`ProviderError::UnknownConnection`] for an
    /// undeclared id, [`ProviderError::RegionMismatch`] for a configured
    /// region, [`ProviderError::LocalProfileDeclared`] for a local
    /// declaration binding a profile,
    /// [`ProviderError::CredentialUnresolved`] for a local declaration
    /// outside the admitted absent-binding classes, the credential seam's
    /// typed denials, and [`ProviderError::Transport`] when the HTTP
    /// client cannot build.
    pub fn new(
        config: &Config,
        connection: &str,
        store: Arc<dyn CredentialStore>,
    ) -> Result<Self, ProviderError> {
        Self::with_proxy_origin(config, connection, store, REQUEST_DEADLINE, None)
    }

    /// The same adapter under an explicit whole-send deadline.
    ///
    /// # Errors
    /// [`Self::new`]'s contract.
    pub fn with_deadline(
        config: &Config,
        connection: &str,
        store: Arc<dyn CredentialStore>,
        deadline: Duration,
    ) -> Result<Self, ProviderError> {
        Self::with_proxy_origin(config, connection, store, deadline, None)
    }

    /// Builds the adapter for an offline contract peer. The recorded
    /// proxy origins stay fixed in production; `proxy_origin` overrides
    /// only the origin (paths stay recorded) and is admitted only for a
    /// loopback literal host. Any other override denies typed — never a
    /// silent fallback to the recorded host.
    ///
    /// # Errors
    /// [`Self::new`]'s contract, plus
    /// [`ProviderError::EndpointRequired`] for a non-loopback override.
    pub fn with_proxy_origin(
        config: &Config,
        connection: &str,
        store: Arc<dyn CredentialStore>,
        deadline: Duration,
        proxy_origin: Option<String>,
    ) -> Result<Self, ProviderError> {
        if routes_for(connection).is_empty() {
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
        // The sibling adapters' local-declaration gates (DEC-023) run here
        // too: a routed id is never an admitted absent-binding class, so a
        // `local` declaration can neither bind a profile nor reach the
        // credential seam or a wire leg.
        if conn.kind == ConnKind::Local && conn.profile.is_some() {
            return Err(ProviderError::LocalProfileDeclared {
                connection: connection.to_string(),
            });
        }
        if conn.kind == ConnKind::Local && !open_proxy_connection(connection) {
            return Err(ProviderError::CredentialUnresolved {
                connection: connection.to_string(),
                scope: format!("connections.{connection}.kind"),
                cause: None,
            });
        }
        let exchange_base = {
            let trimmed = conn.endpoint.trim().trim_end_matches('/');
            if trimmed.is_empty() {
                GITLAB_DEFAULT_BASE.to_string()
            } else {
                trimmed.to_string()
            }
        };
        let proxy_origin = match proxy_origin {
            Some(origin) => {
                loopback_origin(&origin).ok_or_else(|| ProviderError::EndpointRequired {
                    connection: connection.to_string(),
                })?
            }
            None => GITLAB_PROXY_ORIGIN.to_string(),
        };
        let credential =
            resolve_admitted_credential_in(&config.connections, &config.profiles, connection)?;
        let client = reqwest::blocking::Client::builder()
            .timeout(deadline.saturating_mul(2))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|err| transport(connection, err))?;
        Ok(Self {
            connection: connection.to_string(),
            config: config.clone(),
            store,
            auth: WireAuth::Store(credential),
            exchange_base,
            proxy_origin,
            client,
            deadline,
        })
    }

    /// The routed catalogue: GitLab's closed alias table, or the OpenCode
    /// gateway's one keyed listing filtered by its route table.
    ///
    /// # Errors
    /// The codecs' typed catalogue denials.
    pub fn catalog_models(&self) -> Result<Vec<CatalogModel>, ProviderError> {
        let auth = if is_opencode(&self.connection) {
            self.credential_for(&self.connection)?
        } else {
            self.auth.clone()
        };
        self.catalog_with(&auth, self.deadline)
    }

    /// The catalogue under one already-resolved wire material and the
    /// send's clock: a standalone catalogue has no manifest, so the
    /// gateway session seeds from the connection id while the wire leg
    /// seeds from the frozen world.
    fn catalog_with(
        &self,
        auth: &WireAuth,
        deadline: Duration,
    ) -> Result<Vec<CatalogModel>, ProviderError> {
        if let Some(mut models) = routed_catalog(&self.connection) {
            models.sort_by(|a, b| a.id.cmp(&b.id));
            return Ok(models);
        }
        // Every remaining routed id is an OpenCode gateway: its catalogue
        // is the one keyed listing its route table filters.
        let mut models = self
            .build_codec(Dialect::ChatCompletions, auth.clone(), deadline)?
            .catalog_models()?;
        models.retain(|model| route_for(&self.connection, &model.id).is_some());
        models.sort_by(|a, b| a.id.cmp(&b.id));
        models.dedup_by(|a, b| a.id == b.id);
        Ok(models)
    }

    /// The model catalogue ids in deterministic sorted order.
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

    /// The pinned or auto-resolved model and its recorded route. A
    /// closed-table miss denies before any wire leg.
    fn resolve_model(
        &self,
        manifest: &RequestManifest,
        auth: &WireAuth,
        deadline: Duration,
    ) -> Result<(String, Dialect), ProviderError> {
        let model = match &manifest.model {
            ModelAssign::Fixed(fixed) => {
                if fixed.connection != self.connection {
                    return Err(ProviderError::DialectMismatch {
                        connection: fixed.connection.clone(),
                    });
                }
                fixed.model_id.clone()
            }
            ModelAssign::Auto { pool: Some(pool) }
                if pool.len() == 1 && pool[0] == self.connection =>
            {
                self.catalog_with(auth, deadline)?
                    .into_iter()
                    .next()
                    .map(|model| model.id)
                    .ok_or_else(|| ProviderError::UnpinnedModel {
                        connection: self.connection.clone(),
                    })?
            }
            _ => {
                return Err(ProviderError::UnpinnedModel {
                    connection: self.connection.clone(),
                });
            }
        };
        routed_wire_model(&self.connection, &model).ok_or_else(|| {
            ProviderError::UnsupportedParameter {
                connection: self.connection.clone(),
                parameter: "model",
                model,
            }
        })
    }

    /// The wire material one send authenticates with. An `opencode-zen`
    /// send resolves its scoped credential exactly once and adds the
    /// recorded attribution headers, so the chosen codec's catalogue
    /// and wire legs carry the same pair.
    fn credential_for(&self, session: &str) -> Result<WireAuth, ProviderError> {
        if !is_opencode(&self.connection) {
            return Ok(self.auth.clone());
        }
        let WireAuth::Store(Some(reference)) = &self.auth else {
            return Err(ProviderError::CredentialUnresolved {
                connection: self.connection.clone(),
                scope: format!("connections.{}.credential_ref", self.connection),
                cause: None,
            });
        };
        let material = self.store.resolve(reference)?;
        let token =
            String::from_utf8(material).map_err(|_utf8| ProviderError::CredentialMalformed {
                connection: self.connection.clone(),
            })?;
        Ok(WireAuth::Resolved {
            token,
            headers: opencode_headers(session),
        })
    }

    /// The fixed proxy base for one recorded route.
    fn proxy_base(&self, route: Dialect) -> Result<String, ProviderError> {
        let path = match route {
            Dialect::Messages => GITLAB_MESSAGES_PROXY_PATH,
            Dialect::Responses | Dialect::ChatCompletions => GITLAB_OPENAI_PROXY_PATH,
            _ => {
                return Err(ProviderError::DialectMismatch {
                    connection: self.connection.clone(),
                });
            }
        };
        Ok(format!("{}{path}", self.proxy_origin))
    }

    /// The config clone one codec builds against: GitLab's configured
    /// endpoint is the exchange base, so the codec receives the fixed
    /// proxy base instead; an OpenCode gateway's configured endpoint is
    /// the gateway base path, so every route receives `{base}/v1`.
    fn codec_config(&self, route: Dialect) -> Result<Config, ProviderError> {
        let mut config = self.config.clone();
        if self.connection == GITLAB_DUO {
            let base = self.proxy_base(route)?;
            if let Some(conn) = config.connections.get_mut(&self.connection) {
                conn.endpoint = base;
            }
        } else if is_opencode(&self.connection) {
            let endpoint = format!("{}/v1", self.opencode_base());
            if let Some(conn) = config.connections.get_mut(&self.connection) {
                conn.endpoint = endpoint;
            }
        }
        Ok(config)
    }

    /// The recorded OpenCode base path: the configured endpoint with its
    /// trailing `/v1` stripped, or the id's recorded default.
    fn opencode_base(&self) -> String {
        let configured = self
            .config
            .connections
            .get(&self.connection)
            .map_or("", |conn| conn.endpoint.trim());
        let base = configured.trim_end_matches('/');
        if base.is_empty() {
            let default = if self.connection == OPENCODE_GO {
                OPENCODE_GO_DEFAULT_BASE
            } else {
                OPENCODE_ZEN_DEFAULT_BASE
            };
            default.to_string()
        } else {
            base.strip_suffix("/v1").unwrap_or(base).to_string()
        }
    }

    fn build_codec(
        &self,
        route: Dialect,
        auth: WireAuth,
        deadline: Duration,
    ) -> Result<RouteCodec, ProviderError> {
        let config = self.codec_config(route)?;
        let store = Arc::clone(&self.store);
        match route {
            Dialect::Messages => {
                MessagesProvider::with_route(&config, &self.connection, store, deadline, auth)
                    .map(RouteCodec::Messages)
            }
            Dialect::Responses => {
                OpenAiProvider::with_route(&config, &self.connection, store, deadline, auth)
                    .map(RouteCodec::Responses)
            }
            Dialect::ChatCompletions => ChatCompletionsProvider::with_route(
                &config,
                &self.connection,
                store,
                deadline,
                auth,
            )
            .map(RouteCodec::Chat),
            Dialect::Gemini => {
                GeminiProvider::with_route(&config, &self.connection, store, deadline, auth)
                    .map(RouteCodec::Gemini)
            }
            _ => Err(ProviderError::DialectMismatch {
                connection: self.connection.clone(),
            }),
        }
    }

    /// The GitLab exchange under the send's deadline: the PAT is spent
    /// here only, and the returned `{token, headers}` becomes the proxy
    /// leg's material. Only `x-gitlab-*` header names are forwarded.
    fn exchange(&self, started: Instant) -> Result<WireAuth, ProviderError> {
        check_deadline(&self.connection, self.deadline, started)?;
        let WireAuth::Store(Some(reference)) = &self.auth else {
            return Err(ProviderError::CredentialUnresolved {
                connection: self.connection.clone(),
                scope: format!("connections.{}.credential_ref", self.connection),
                cause: None,
            });
        };
        let material = self.store.resolve(reference)?;
        let pat =
            String::from_utf8(material).map_err(|_utf8| ProviderError::CredentialMalformed {
                connection: self.connection.clone(),
            })?;
        let body = wire_body(
            &self.connection,
            &json!({ "feature_flags": { "DuoAgentPlatformNext": true } }),
        )?;
        let mut response = self
            .client
            .post(format!("{}{GITLAB_EXCHANGE_PATH}", self.exchange_base))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::ACCEPT, "application/json")
            .bearer_auth(&pat)
            .body(body)
            .send()
            .map_err(|err| transport(&self.connection, err))?;
        if !response.status().is_success() {
            return Err(transport_status(&self.connection, response.status()));
        }
        let body = read_catalog_body(&self.connection, self.deadline, &mut response, started)?;
        let payload: Value = serde_json::from_slice(&body)
            .map_err(|_parse| violation(&self.connection, "direct access response is not json"))?;
        let token = payload
            .get("token")
            .and_then(Value::as_str)
            .filter(|token| !token.is_empty())
            .ok_or_else(|| {
                violation(&self.connection, "direct access response carries no token")
            })?;
        let headers = payload
            .get("headers")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                violation(
                    &self.connection,
                    "direct access response carries no headers",
                )
            })?;
        let forwarded = headers
            .iter()
            .filter(|(name, _)| name.to_ascii_lowercase().starts_with("x-gitlab-"))
            .filter_map(|(name, value)| {
                value
                    .as_str()
                    .map(|value| (name.clone(), value.to_string()))
            })
            .collect();
        Ok(WireAuth::Resolved {
            token: token.to_string(),
            headers: forwarded,
        })
    }
}

impl Provider for RoutedProvider {
    fn name(&self) -> &'static str {
        "routed"
    }

    fn serves(&self, connection: &str, _entry: &crate::config::Connection) -> bool {
        connection == self.connection
    }

    /// Sends the frozen manifest through the model's recorded route.
    ///
    /// # Errors
    /// [`ProviderError::UnpinnedModel`] for a model this adapter cannot
    /// pin, [`ProviderError::DialectMismatch`] for a pin naming another
    /// connection, [`ProviderError::UnsupportedParameter`] for a model
    /// outside a closed recorded table, the exchange's typed denials on
    /// GitLab, the credential seam's typed denials on the OpenCode
    /// gateways, and the chosen codec's send contract.
    fn send(&mut self, manifest: &RequestManifest) -> Result<ProviderReply, ProviderError> {
        let started = Instant::now();
        check_deadline(&self.connection, self.deadline, started)?;
        let auth = self.credential_for(&manifest.world)?;
        // Model resolution owns its own catalogue leg, so the wire codec
        // inherits only the budget still left on this one clock.
        let remaining = self.deadline.saturating_sub(started.elapsed());
        check_deadline(&self.connection, self.deadline, started)?;
        let (wire_model, route) = self.resolve_model(manifest, &auth, remaining)?;
        let mut routed = manifest.clone();
        routed.model = ModelAssign::Fixed(FixedModel {
            connection: self.connection.clone(),
            model_id: wire_model,
        });
        let auth = if self.connection == GITLAB_DUO {
            self.exchange(started)?
        } else {
            auth
        };
        let remaining = self.deadline.saturating_sub(started.elapsed());
        check_deadline(&self.connection, self.deadline, started)?;
        let mut codec = self.build_codec(route, auth, remaining)?;
        codec.send(&routed)
    }
}

/// A loopback proxy origin: a parsed `http`/`https` URL whose host is a
/// loopback address, with no userinfo, path, query or fragment. The
/// answer is the canonical origin, never the raw input.
fn loopback_origin(raw: &str) -> Option<String> {
    let url = reqwest::Url::parse(raw.trim()).ok()?;
    if !url.username().is_empty() || url.password().is_some() {
        return None;
    }
    if !matches!(url.scheme(), "http" | "https") {
        return None;
    }
    if url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
        return None;
    }
    is_loopback_url(&url).then(|| url.origin().ascii_serialization())
}
