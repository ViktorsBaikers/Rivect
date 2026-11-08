//! The `google-vertex` connection's adapter — the recorded dual-class
//! Vertex projection (DEC-007/HZN-008). Dialect selection keys on the
//! literal connection id; the wire class is resolved from the pinned
//! model's recorded catalogue `api` owner, never from the model-name
//! family or the credential form. Only `google-vertex` (the publisher
//! `streamGenerateContent` resource) and `anthropic-messages` (the
//! regional `streamRawPredict` resource) are native classes here, and a
//! row outside them denies [`ProviderError::ModelClassUnresolved`]
//! before any request.
//!
//! Two credential forms stay separately usable (SLICE-162): the ADC
//! producer artifact read through [`vertex_login::read`] rides
//! `Authorization: Bearer` with its project and location in the
//! resource path, while a raw API key rides `x-goog-api-key` on the
//! publisher resource and has no project or location to address. The
//! request/stream codecs are not re-implemented here: the publisher
//! class consumes the extracted Gemini codec and the Anthropic class the
//! extracted Messages codec, so replay, tool and usage rules cannot
//! drift from their Messages and Gemini owners.
//!
//! The accepted pins are the closed catalogue's native rows only. The
//! publisher class admits `gemini-2.5-flash`, `gemini-2.5-pro`,
//! `gemini-3-flash-preview`, `gemini-3-pro-preview` and
//! `gemini-3.1-pro-preview`; the regional `streamRawPredict` class admits
//! `claude-haiku-4-5`, `claude-opus-4-5`, `claude-opus-4-8` and
//! `claude-sonnet-4-5`. The catalogue's third row carries the upstream
//! `openai-completions` owner (`meta/llama-3.3-70b-instruct-maas`) and
//! has no native class here. `class_for` admits exactly the
//! `google-vertex` and `anthropic-messages` owners `VERTEX_MODELS`
//! records and refuses every other row; the shared catalogue variant's
//! class names are its own local pin record, and this adapter never
//! re-projects a Vertex `api` owner onto them.
//!
//! The raw API-key form is one token in the recorded grammar: non-empty
//! and inside `[A-Za-z0-9_-]`. The ADC artifact is JSON, so it can never
//! satisfy that grammar and be mistaken for a key.
//!
//! Secret material crosses only from [`CredentialStore`] into the
//! request header per send — never into config, manifests, diagnostics
//! or this type's `Debug` (INV-001/INV-006).

use super::anthropic::{ANTHROPIC_VERSION, MessagesCodec, THINKING_BINDING_BETA};
use super::gemini::GeminiCodec;
use super::vertex_login::{self, LoginError, VertexCredential};
use super::{
    CredentialStore, Dialect, Provider, ProviderError, ProviderReply, RequestManifest, WireAuth,
    check_deadline, dialect_for, percent_encode_component, resolve_credential, transport,
    transport_status, wire_body,
};
use crate::config::{Config, Connection, FixedModel, ModelAssign};
use serde_json::json;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The whole-request budget one Vertex send shares.
const REQUEST_DEADLINE: Duration = Duration::from_secs(120);

/// The recorded global service root an API-key call reaches when the
/// connection names no endpoint: the key form carries no location, so
/// nothing derives a regional host for it.
const VERTEX_KEY_BASE: &str = "https://aiplatform.googleapis.com";

/// The recorded protocol version a `streamRawPredict` body carries. It
/// is body-only; the `anthropic-version` header keeps the Messages
/// dialect's own value.
const VERTEX_MESSAGES_VERSION: &str = "vertex-2023-10-16";

/// The closed `google-vertex` catalogue with each row's recorded `api`
/// owner. Only `google-vertex` and `anthropic-messages` select a native
/// wire class; the `openai-completions` row is the upstream third class
/// this adapter refuses rather than re-projects.
const VERTEX_MODELS: &[(&str, &str)] = &[
    ("claude-haiku-4-5", "anthropic-messages"),
    ("claude-opus-4-5", "anthropic-messages"),
    ("claude-opus-4-8", "anthropic-messages"),
    ("claude-sonnet-4-5", "anthropic-messages"),
    ("gemini-2.5-flash", "google-vertex"),
    ("gemini-2.5-pro", "google-vertex"),
    ("gemini-3-flash-preview", "google-vertex"),
    ("gemini-3-pro-preview", "google-vertex"),
    ("gemini-3.1-pro-preview", "google-vertex"),
    ("meta/llama-3.3-70b-instruct-maas", "openai-completions"),
];

/// The two native wire classes a catalogue row's `api` owner selects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ModelClass {
    /// The publisher `streamGenerateContent` resource.
    Gemini,
    /// The regional `streamRawPredict` resource.
    Messages,
}

/// The class one pinned model resolves through its recorded catalogue
/// row; a row outside the two native classes denies typed.
fn class_for(connection: &str, model: &str) -> Result<ModelClass, ProviderError> {
    let owner = VERTEX_MODELS
        .iter()
        .find(|(id, _)| *id == model)
        .map(|(_, api)| *api);
    match owner {
        Some("google-vertex") => Ok(ModelClass::Gemini),
        Some("anthropic-messages") => Ok(ModelClass::Messages),
        _ => Err(ProviderError::ModelClassUnresolved {
            connection: connection.to_string(),
            model: model.to_string(),
        }),
    }
}

/// The stored material in one of its two separately usable forms: the
/// ADC producer artifact, or the raw API key the publisher class
/// authenticates with.
enum Material {
    ApiKey(String),
    Adc(VertexCredential),
}

/// The `google-vertex` adapter. Constructed per connection; the Broker
/// owns the handle. Its accepted pin set, raw API-key grammar and the
/// shared-catalogue projection are the module contract above.
pub struct VertexProvider {
    /// The literal connection id this adapter serves.
    connection: String,
    /// The configured service root, trailing slashes and a trailing
    /// version segment trimmed; empty resolves the recorded host.
    endpoint: String,
    /// The scoped credential binding resolved under DEC-013
    /// precedence — material is read from the store per send so a
    /// rotation is honoured without rebuilding the adapter.
    auth: WireAuth,
    store: Arc<dyn CredentialStore>,
    client: reqwest::blocking::Client,
    /// The one budget credential resolution and the stream share.
    deadline: Duration,
    /// The publisher class's request and stream codec.
    gemini: GeminiCodec,
    /// The Anthropic class's request and stream codec.
    messages: MessagesCodec,
}

impl VertexProvider {
    /// Builds the adapter for one connection id: the id must record the
    /// Vertex dialect, the connection must be declared, carry no
    /// configured region — the location is the ADC artifact's binding —
    /// and resolve a scoped credential under DEC-013 precedence.
    ///
    /// # Errors
    /// [`ProviderError::DialectMismatch`] for a connection id without
    /// the Vertex source class; [`ProviderError::UnknownConnection`]
    /// for an undeclared id; [`ProviderError::RegionMismatch`] for a
    /// configured region; [`ProviderError::CredentialUnresolved`] for
    /// an absent or malformed binding, and
    /// [`ProviderError::Transport`] when the HTTP client cannot be
    /// built.
    pub fn new(
        config: &Config,
        connection: &str,
        store: Arc<dyn CredentialStore>,
    ) -> Result<Self, ProviderError> {
        Self::build(config, connection, store, REQUEST_DEADLINE)
    }

    /// The same adapter under an explicit whole-request deadline — the
    /// bound is adapter policy; proof legs pin a short one so the
    /// budget is exercised deterministically.
    ///
    /// # Errors
    /// [`Self::new`]'s contract.
    pub fn with_deadline(
        config: &Config,
        connection: &str,
        store: Arc<dyn CredentialStore>,
        deadline: Duration,
    ) -> Result<Self, ProviderError> {
        Self::build(config, connection, store, deadline)
    }

    fn build(
        config: &Config,
        connection: &str,
        store: Arc<dyn CredentialStore>,
        deadline: Duration,
    ) -> Result<Self, ProviderError> {
        if dialect_for(connection) != Some(Dialect::Vertex) {
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
            // The location is the ADC artifact's binding; a second,
            // divergent one in config could rewrite the host.
            return Err(ProviderError::RegionMismatch {
                connection: connection.to_string(),
                region: region.clone(),
            });
        }
        let auth = WireAuth::Store(Some(resolve_credential(config, connection)?));
        let client = reqwest::blocking::Client::builder()
            .timeout(deadline.saturating_mul(2))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|err| transport(connection, err))?;
        Ok(Self {
            connection: connection.to_string(),
            endpoint: service_root(&conn.endpoint),
            auth,
            store,
            client,
            deadline,
            gemini: GeminiCodec::new(connection),
            messages: MessagesCodec::new(connection),
        })
    }

    /// The material this send authenticates with — the only place secret
    /// bytes cross the store boundary. The ADC artifact parses through
    /// the producer's own reader; anything else must be a raw API key
    /// (the publisher form), and a malformed artifact is a typed denial
    /// rather than a credential guess.
    fn material(&self) -> Result<Material, ProviderError> {
        let WireAuth::Store(Some(reference)) = &self.auth else {
            // This adapter reads its own store binding; no routed owner
            // constructs it with preflight material in this build.
            return Err(ProviderError::CredentialUnresolved {
                connection: self.connection.clone(),
                scope: format!("connections.{}.credential_ref", self.connection),
                cause: None,
            });
        };
        match vertex_login::read(self.store.as_ref(), reference) {
            Ok(credential) => Ok(Material::Adc(credential)),
            Err(LoginError::Provider(error)) => Err(error),
            Err(LoginError::StoredCredentialMalformed { .. }) => {
                let bytes = self.store.resolve(reference)?;
                let Ok(key) = String::from_utf8(bytes) else {
                    return Err(self.malformed());
                };
                if !valid_api_key(&key) {
                    return Err(self.malformed());
                }
                Ok(Material::ApiKey(key))
            }
            // The reader resolves and parses only: it reaches neither.
            Err(_denial) => Err(self.malformed()),
        }
    }

    fn malformed(&self) -> ProviderError {
        ProviderError::CredentialMalformed {
            connection: self.connection.clone(),
        }
    }

    /// The ADC artifact's location, which must be a plain host label:
    /// any other value could rewrite the regional host the production
    /// base is derived from.
    fn location<'credential>(
        &self,
        credential: &'credential VertexCredential,
    ) -> Result<&'credential str, ProviderError> {
        let location = credential.location();
        let plain = !location.is_empty()
            && location
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
        if plain {
            return Ok(location);
        }
        Err(ProviderError::RegionMismatch {
            connection: self.connection.clone(),
            region: location.to_string(),
        })
    }

    /// The ADC artifact's project, which must be one plain resource-path
    /// segment: an empty value or a dot segment would be resolved away by
    /// the URL parser and address another resource.
    fn project<'credential>(
        &self,
        credential: &'credential VertexCredential,
    ) -> Result<&'credential str, ProviderError> {
        let project = credential.project();
        if !project.is_empty() && project != "." && project != ".." {
            return Ok(project);
        }
        Err(ProviderError::UnsendableRequest {
            connection: self.connection.clone(),
            reason: "the credential project is not a usable resource-path segment".to_string(),
        })
    }

    /// The pinned model. An auto assignment is refused typed: this
    /// adapter serves two classes, so the lexical pick of a mixed-class
    /// pool could resolve a class the credential form cannot serve, and
    /// the class is never inferred from the model-name family.
    ///
    /// # Errors
    /// [`ProviderError::UnpinnedModel`] for an auto or unpinned
    /// assignment, [`ProviderError::DialectMismatch`] when the pin names
    /// another connection.
    fn fixed_model(&self, manifest: &RequestManifest) -> Result<FixedModel, ProviderError> {
        let fixed = match &manifest.model {
            ModelAssign::Fixed(fixed) => fixed.clone(),
            _ => {
                return Err(ProviderError::UnpinnedModel {
                    connection: self.connection.clone(),
                });
            }
        };
        if fixed.connection != self.connection {
            return Err(ProviderError::DialectMismatch {
                connection: fixed.connection,
            });
        }
        Ok(fixed)
    }

    /// Sends the frozen manifest through the class its catalogue row
    /// records. The class resolves before the credential or any wire
    /// leg, so a model outside the two native classes never reaches a
    /// post.
    ///
    /// # Errors
    /// [`ProviderError::ModelClassUnresolved`] for a model without a
    /// native class, [`ProviderError::UnpinnedModel`],
    /// [`ProviderError::DialectMismatch`],
    /// [`ProviderError::RegionMismatch`] for a location that could
    /// rewrite the host, the credential seam's typed denials,
    /// [`ProviderError::CredentialMalformed`] for a form that cannot
    /// serve the resolved class, [`ProviderError::Transport`],
    /// [`ProviderError::ProviderFailed`],
    /// [`ProviderError::UnknownTerminal`],
    /// [`ProviderError::StreamViolation`],
    /// [`ProviderError::IncompatibleOutput`] and
    /// [`ProviderError::ReasoningProvenance`] as the shared codecs
    /// document.
    fn send_manifest(
        &mut self,
        manifest: &RequestManifest,
    ) -> Result<ProviderReply, ProviderError> {
        let started = Instant::now();
        check_deadline(&self.connection, self.deadline, started)?;
        let fixed = self.fixed_model(manifest)?;
        let class = class_for(&self.connection, &fixed.model_id)?;
        let material = self.material()?;
        match class {
            ModelClass::Gemini => self.send_gemini(manifest, &fixed, material, started),
            ModelClass::Messages => self.send_messages(manifest, &fixed, material, started),
        }
    }

    /// The publisher `streamGenerateContent` leg: the API-key form rides
    /// `x-goog-api-key` on the `publishers/google` resource, and the ADC
    /// form rides `Authorization: Bearer` on the
    /// `projects/{project}/locations/{location}/publishers/google`
    /// resource — never one form's header on the other's path.
    fn send_gemini(
        &mut self,
        manifest: &RequestManifest,
        fixed: &FixedModel,
        material: Material,
        started: Instant,
    ) -> Result<ProviderReply, ProviderError> {
        let body = self.gemini.request_body(manifest)?;
        let body_bytes = wire_body(&self.connection, &body)?;
        check_deadline(&self.connection, self.deadline, started)?;
        let url = match &material {
            Material::ApiKey(_) => gemini_key_url(&self.endpoint, &fixed.model_id),
            Material::Adc(credential) => gemini_adc_url(
                &self.endpoint,
                self.project(credential)?,
                self.location(credential)?,
                &fixed.model_id,
            ),
        };
        let request = self
            .client
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::ACCEPT, "text/event-stream")
            .body(body_bytes);
        let request = match &material {
            Material::ApiKey(key) => request.header("x-goog-api-key", key),
            Material::Adc(credential) => request.bearer_auth(credential.access_token()),
        };
        let response = request
            .send()
            .map_err(|err| transport(&self.connection, err))?;
        if !response.status().is_success() {
            return Err(transport_status(&self.connection, response.status()));
        }
        self.gemini
            .read_stream(manifest, response, self.deadline, started)
    }

    /// The regional `streamRawPredict` leg: the model rides the resource
    /// path only, the body states the Vertex protocol version, betas
    /// ride the body (never an `anthropic-beta` header), and the URL is
    /// never the standalone `/v1/messages` path. The class addresses a
    /// project and location, so the API-key form cannot serve it.
    fn send_messages(
        &mut self,
        manifest: &RequestManifest,
        fixed: &FixedModel,
        material: Material,
        started: Instant,
    ) -> Result<ProviderReply, ProviderError> {
        let Material::Adc(credential) = &material else {
            return Err(self.malformed());
        };
        let location = self.location(credential)?;
        let project = self.project(credential)?;
        let binding = self.messages.binding(manifest, &fixed.model_id);
        let mut body = self.messages.request_body(manifest, fixed, &binding);
        if let Some(object) = body.as_object_mut() {
            // `streamRawPredict` names the model in the resource path; a
            // body copy would be a second, unread model claim.
            object.remove("model");
        }
        body["anthropic_version"] = json!(VERTEX_MESSAGES_VERSION);
        if binding.drop_block {
            // Vertex reads betas from the body; the Messages header is
            // not part of this resource's contract.
            body["anthropic_beta"] = json!([THINKING_BINDING_BETA]);
        }
        let body_bytes = wire_body(&self.connection, &body)?;
        check_deadline(&self.connection, self.deadline, started)?;
        let url = messages_url(&self.endpoint, project, location, &fixed.model_id);
        let response = self
            .client
            .post(url)
            .bearer_auth(credential.access_token())
            .header("anthropic-version", ANTHROPIC_VERSION)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::ACCEPT, "text/event-stream")
            .body(body_bytes)
            .send()
            .map_err(|err| transport(&self.connection, err))?;
        if !response.status().is_success() {
            return Err(transport_status(&self.connection, response.status()));
        }
        self.messages
            .read_stream(manifest, &fixed.model_id, response, self.deadline, started)
    }
}

/// The configured service root with trailing slashes and a trailing
/// version segment trimmed: the adapter appends its own `/v1/...` paths,
/// so `https://host` and `https://host/v1/` name the same root.
fn service_root(configured: &str) -> String {
    configured
        .trim()
        .trim_end_matches('/')
        .trim_end_matches("/v1")
        .trim_end_matches('/')
        .to_string()
}

/// The publisher resource an API-key send reaches: the key form carries
/// no location, so an absent endpoint resolves the recorded global root.
fn gemini_key_url(endpoint: &str, model: &str) -> String {
    format!(
        "{}/v1/publishers/google/models/{model}:streamGenerateContent?alt=sse",
        key_base(endpoint)
    )
}

/// The publisher resource an ADC send reaches: an absent endpoint
/// resolves the recorded regional root from the bound location.
/// `location()` restricts that charset already, so its encoding here is
/// defensive.
fn gemini_adc_url(endpoint: &str, project: &str, location: &str, model: &str) -> String {
    format!(
        "{}/v1/projects/{}/locations/{}/publishers/google/models/{model}:streamGenerateContent?alt=sse",
        adc_base(endpoint, location),
        percent_encode_component(project),
        percent_encode_component(location)
    )
}

/// The regional `streamRawPredict` resource: the model rides the path
/// only. `location()` already restricts its charset, so encoding it is
/// defensive (a no-op today); the project is the segment that varies.
fn messages_url(endpoint: &str, project: &str, location: &str, model: &str) -> String {
    format!(
        "{}/v1/projects/{}/locations/{}/publishers/anthropic/models/{model}:streamRawPredict",
        adc_base(endpoint, location),
        percent_encode_component(project),
        percent_encode_component(location)
    )
}

/// The ADC class's root: the configured endpoint wins, and an absent one
/// derives the recorded regional host from the bound location.
fn adc_base(root: &str, location: &str) -> String {
    if root.is_empty() {
        format!("https://{location}-aiplatform.googleapis.com")
    } else {
        root.to_string()
    }
}

/// The API-key class's root: the configured endpoint wins, and an absent
/// one resolves the recorded global host because this form carries no
/// location.
fn key_base(root: &str) -> String {
    if root.is_empty() {
        VERTEX_KEY_BASE.to_string()
    } else {
        root.to_string()
    }
}

/// A raw Vertex API key is one token: non-empty, inside the recorded
/// key charset. The strict ADC artifact is JSON, so it can never pass
/// this grammar and be mistaken for a key.
fn valid_api_key(key: &str) -> bool {
    !key.is_empty()
        && key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

impl std::fmt::Debug for VertexProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The scoped ref is the visible token — the store and its
        // material never enter diagnostics (INV-001).
        f.debug_struct("VertexProvider")
            .field("connection", &self.connection)
            .field("endpoint", &self.endpoint)
            .field("auth", &self.auth)
            .field("deadline", &self.deadline)
            .finish_non_exhaustive()
    }
}

impl Provider for VertexProvider {
    fn name(&self) -> &'static str {
        "google-vertex"
    }

    /// The adapter serves only the literal connection id its dialect was
    /// constructed for (DEC-007).
    fn serves(&self, connection: &str, _entry: &Connection) -> bool {
        connection == self.connection
    }

    fn send(&mut self, manifest: &RequestManifest) -> Result<ProviderReply, ProviderError> {
        self.send_manifest(manifest)
    }
}

#[cfg(test)]
mod tests {
    use super::{adc_base, gemini_adc_url, gemini_key_url, key_base, messages_url, service_root};

    /// The send-path URLs an absent endpoint derives: the ADC form builds
    /// the regional host from the bound location, the API-key form has no
    /// location and builds the recorded global root, and the configured
    /// loopback endpoint wins. Swapping either base reds this check.
    #[test]
    fn recorded_production_roots_derive_from_the_credential_form() {
        assert_eq!(
            gemini_key_url("", "gemini-3.1-pro-preview"),
            "https://aiplatform.googleapis.com/v1/publishers/google/models/gemini-3.1-pro-preview:streamGenerateContent?alt=sse"
        );
        assert_eq!(
            gemini_adc_url("", "rvct-proj", "us-central1", "gemini-3.1-pro-preview"),
            "https://us-central1-aiplatform.googleapis.com/v1/projects/rvct-proj/locations/us-central1/publishers/google/models/gemini-3.1-pro-preview:streamGenerateContent?alt=sse"
        );
        assert_eq!(
            messages_url("", "rvct-proj", "us-central1", "claude-sonnet-4-5"),
            "https://us-central1-aiplatform.googleapis.com/v1/projects/rvct-proj/locations/us-central1/publishers/anthropic/models/claude-sonnet-4-5:streamRawPredict"
        );
        assert_eq!(
            gemini_adc_url(
                "http://127.0.0.1:9",
                "rvct-proj",
                "us-central1",
                "gemini-3.1-pro-preview"
            ),
            "http://127.0.0.1:9/v1/projects/rvct-proj/locations/us-central1/publishers/google/models/gemini-3.1-pro-preview:streamGenerateContent?alt=sse"
        );
        assert_eq!(
            adc_base("", "us-central1"),
            "https://us-central1-aiplatform.googleapis.com"
        );
        assert_eq!(key_base(""), "https://aiplatform.googleapis.com");
        assert_eq!(
            service_root("https://us-central1-aiplatform.googleapis.com/v1/"),
            "https://us-central1-aiplatform.googleapis.com"
        );
        assert_eq!(service_root(""), "");
    }
}
