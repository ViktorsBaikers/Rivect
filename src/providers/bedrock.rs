//! The Amazon Bedrock Converse event-stream adapter.
//!
//! `amazon-bedrock` is the one literal id this module serves. The scoped
//! store material is parsed once per send by [`aws::parse_material`] and
//! is either a Bearer token or the recorded static-key object; the latter
//! signs the exact serialized body with SigV4 service `bedrock`. The base
//! resolves the recorded configured → material → ARN → geo/ambient region
//! precedence, and the model path carries the percent-encoded wire id.
//!
//! The response is an AWS event stream decoded by the bounded framing
//! decoder: a frame split across reads is
//! buffered, a `messageStop` is mandatory, a tool block is complete only
//! at its `contentBlockStop`, and `metadata.usage` is the only usage
//! source. An exception frame, a truncation, an oversized frame, a
//! partial tool block or an unclassified terminal is a typed denial,
//! never a fabricated reply.

use crate::config::{Config, ConnKind, Connection, EffortAssign, FixedModel, ModelAssign};
use crate::model::RequestManifest;
use crate::providers::aws::{self, AwsMaterial};
use crate::providers::eventstream::{EventStreamDecoder, EventStreamError, Frame};
use crate::providers::{
    CatalogModel, CredentialStore, Dialect, Provider, ProviderError, ProviderReply, SecretRef,
    ToolCall, bounded_reason, check_deadline, dialect_for, loopback_base, read_chunk, transport,
    transport_status, violation, wire_body,
};
use crate::resources::UsageDelta;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

/// The recorded Converse request headers.
const CONTENT_TYPE: &str = "application/json";
const ACCEPT: &str = "application/vnd.amazon.eventstream";

/// The recorded SigV4 service for the Converse runtime.
const SIGV4_SERVICE: &str = "bedrock";

/// The one recorded stop-reason set; a terminal outside it is unknown.
const CLASSIFIED_STOP_REASONS: &[&str] = &[
    "end_turn",
    "tool_use",
    "max_tokens",
    "stop_sequence",
    "guardrail_intervened",
    "content_filtered",
];

/// The closed recorded Converse model table as
/// `(id, context_window, max_tokens)` rows; no listing leg adds a row.
const BEDROCK_MODELS: &[(&str, u64, u64)] = &[
    ("anthropic.claude-3-5-haiku-20241022-v1:0", 200000, 8192),
    ("anthropic.claude-3-5-sonnet-20240620-v1:0", 200000, 8192),
    ("anthropic.claude-3-5-sonnet-20241022-v2:0", 200000, 8192),
    ("anthropic.claude-3-haiku-20240307-v1:0", 200000, 4096),
    ("anthropic.claude-3-opus-20240229-v1:0", 200000, 4096),
    ("anthropic.claude-3-sonnet-20240229-v1:0", 200000, 4096),
    ("anthropic.claude-opus-4-6-v1", 1000000, 128000),
    ("anthropic.claude-opus-4-7", 1000000, 128000),
    ("anthropic.claude-opus-4-8", 1000000, 128000),
    ("anthropic.claude-opus-5", 1000000, 128000),
    ("anthropic.claude-sonnet-5", 1000000, 128000),
    ("au.anthropic.claude-haiku-4-5-20251001-v1:0", 200000, 64000),
    ("au.anthropic.claude-opus-4-6-v1", 1000000, 128000),
    ("au.anthropic.claude-opus-4-8", 1000000, 128000),
    ("au.anthropic.claude-opus-5", 1000000, 128000),
    (
        "au.anthropic.claude-sonnet-4-5-20250929-v1:0",
        200000,
        64000,
    ),
    ("au.anthropic.claude-sonnet-4-6", 1000000, 128000),
    ("au.anthropic.claude-sonnet-5", 1000000, 128000),
    ("cohere.command-r-plus-v1:0", 128000, 4096),
    ("cohere.command-r-v1:0", 128000, 4096),
    ("deepseek.v3-v1:0", 163840, 81920),
    ("deepseek.v3.2", 163840, 81920),
    ("deepseek.v3.2-v1:0", 163840, 81920),
    ("eu.anthropic.claude-3-5-haiku-20241022-v1:0", 200000, 8192),
    ("eu.anthropic.claude-3-5-sonnet-20240620-v1:0", 200000, 8192),
    ("eu.anthropic.claude-3-5-sonnet-20241022-v2:0", 200000, 8192),
    ("eu.anthropic.claude-3-7-sonnet-20250219-v1:0", 200000, 8192),
    ("eu.anthropic.claude-3-haiku-20240307-v1:0", 200000, 4096),
    ("eu.anthropic.claude-3-opus-20240229-v1:0", 200000, 4096),
    ("eu.anthropic.claude-3-sonnet-20240229-v1:0", 200000, 4096),
    ("eu.anthropic.claude-fable-5", 1000000, 128000),
    ("eu.anthropic.claude-fable-5-1", 1000000, 128000),
    ("eu.anthropic.claude-haiku-4-5-20251001-v1:0", 200000, 64000),
    ("eu.anthropic.claude-opus-4-1-20250805-v1:0", 200000, 32000),
    ("eu.anthropic.claude-opus-4-20250514-v1:0", 200000, 32000),
    ("eu.anthropic.claude-opus-4-5-20251101-v1:0", 200000, 64000),
    ("eu.anthropic.claude-opus-4-6-v1", 1000000, 128000),
    ("eu.anthropic.claude-opus-4-7", 1000000, 128000),
    ("eu.anthropic.claude-opus-4-8", 1000000, 128000),
    ("eu.anthropic.claude-opus-5", 1000000, 128000),
    ("eu.anthropic.claude-sonnet-4-20250514-v1:0", 200000, 64000),
    (
        "eu.anthropic.claude-sonnet-4-5-20250929-v1:0",
        200000,
        64000,
    ),
    ("eu.anthropic.claude-sonnet-4-6", 1000000, 64000),
    ("eu.anthropic.claude-sonnet-5", 1000000, 128000),
    ("global.amazon.nova-2-lite-v1:0", 128000, 4096),
    ("global.anthropic.claude-fable-5", 1000000, 128000),
    ("global.anthropic.claude-fable-5-1", 1000000, 128000),
    (
        "global.anthropic.claude-haiku-4-5-20251001-v1:0",
        200000,
        64000,
    ),
    (
        "global.anthropic.claude-opus-4-5-20251101-v1:0",
        200000,
        64000,
    ),
    ("global.anthropic.claude-opus-4-6-v1", 1000000, 128000),
    ("global.anthropic.claude-opus-4-7", 1000000, 128000),
    ("global.anthropic.claude-opus-4-8", 1000000, 128000),
    ("global.anthropic.claude-opus-5", 1000000, 128000),
    (
        "global.anthropic.claude-sonnet-4-20250514-v1:0",
        200000,
        64000,
    ),
    (
        "global.anthropic.claude-sonnet-4-5-20250929-v1:0",
        200000,
        64000,
    ),
    ("global.anthropic.claude-sonnet-4-6", 1000000, 64000),
    ("global.anthropic.claude-sonnet-5", 1000000, 128000),
    ("global.openai.gpt-5.6-luna", 1050000, 128000),
    ("global.openai.gpt-5.6-sol", 1050000, 128000),
    ("global.openai.gpt-5.6-terra", 1050000, 128000),
    ("google.gemma-3-27b-it", 202752, 8192),
    ("google.gemma-3-4b-it", 128000, 4096),
    ("jp.anthropic.claude-haiku-4-5-20251001-v1:0", 200000, 64000),
    ("jp.anthropic.claude-opus-4-7", 1000000, 128000),
    ("jp.anthropic.claude-opus-4-8", 1000000, 128000),
    (
        "jp.anthropic.claude-sonnet-4-5-20250929-v1:0",
        200000,
        64000,
    ),
    ("jp.anthropic.claude-sonnet-4-6", 1000000, 64000),
    ("jp.anthropic.claude-sonnet-5", 1000000, 128000),
    ("meta.llama3-1-405b-instruct-v1:0", 128000, 4096),
    ("meta.llama3-1-70b-instruct-v1:0", 128000, 4096),
    ("meta.llama3-1-8b-instruct-v1:0", 128000, 4096),
    ("minimax.minimax-m2", 204608, 128000),
    ("minimax.minimax-m2.1", 204800, 131072),
    ("minimax.minimax-m2.5", 196608, 98304),
    ("mistral.devstral-2-123b", 256000, 8192),
    ("mistral.magistral-small-2509", 128000, 40000),
    ("mistral.ministral-3-14b-instruct", 128000, 4096),
    ("mistral.ministral-3-3b-instruct", 256000, 8192),
    ("mistral.ministral-3-8b-instruct", 128000, 4096),
    ("mistral.mistral-large-2402-v1:0", 128000, 4096),
    ("mistral.mistral-large-3-675b-instruct", 256000, 8192),
    ("mistral.pixtral-large-2502-v1:0", 128000, 8192),
    ("mistral.voxtral-mini-3b-2507", 128000, 4096),
    ("mistral.voxtral-small-24b-2507", 32000, 8192),
    ("moonshot.kimi-k2-thinking", 262143, 16000),
    ("moonshotai.kimi-k2.5", 262143, 16000),
    ("nvidia.nemotron-nano-12b-v2", 128000, 4096),
    ("nvidia.nemotron-nano-3-30b", 128000, 4096),
    ("nvidia.nemotron-nano-9b-v2", 128000, 4096),
    ("nvidia.nemotron-super-3-120b", 262144, 131072),
    ("openai.gpt-oss-120b", 128000, 16384),
    ("openai.gpt-oss-120b-1:0", 128000, 16384),
    ("openai.gpt-oss-20b", 128000, 16384),
    ("openai.gpt-oss-20b-1:0", 128000, 16384),
    ("openai.gpt-oss-safeguard-120b", 128000, 16384),
    ("openai.gpt-oss-safeguard-20b", 128000, 16384),
    ("qwen.qwen3-235b-a22b-2507-v1:0", 262144, 131072),
    ("qwen.qwen3-32b-v1:0", 16384, 16384),
    ("qwen.qwen3-coder-30b-a3b-v1:0", 262144, 131072),
    ("qwen.qwen3-coder-480b-a35b-v1:0", 131072, 65536),
    ("qwen.qwen3-coder-next", 131072, 65536),
    ("qwen.qwen3-next-80b-a3b", 262000, 262000),
    ("qwen.qwen3-vl-235b-a22b", 262000, 262000),
    ("us-gov.anthropic.claude-fable-5", 1000000, 128000),
    ("us-gov.anthropic.claude-fable-5-1", 1000000, 128000),
    (
        "us-gov.anthropic.claude-haiku-4-5-20251001-v1:0",
        200000,
        64000,
    ),
    (
        "us-gov.anthropic.claude-opus-4-1-20250805-v1:0",
        200000,
        32000,
    ),
    (
        "us-gov.anthropic.claude-opus-4-5-20251101-v1:0",
        200000,
        64000,
    ),
    ("us-gov.anthropic.claude-opus-4-6-v1", 1000000, 128000),
    ("us-gov.anthropic.claude-opus-4-7", 1000000, 128000),
    ("us-gov.anthropic.claude-opus-4-8", 1000000, 128000),
    ("us-gov.anthropic.claude-opus-5", 1000000, 128000),
    (
        "us-gov.anthropic.claude-sonnet-4-5-20250929-v1:0",
        200000,
        64000,
    ),
    ("us-gov.anthropic.claude-sonnet-4-6", 1000000, 64000),
    ("us-gov.anthropic.claude-sonnet-5", 1000000, 128000),
    ("us.amazon.nova-lite-v1:0", 300000, 8192),
    ("us.amazon.nova-micro-v1:0", 128000, 8192),
    ("us.amazon.nova-premier-v1:0", 1000000, 16384),
    ("us.amazon.nova-pro-v1:0", 300000, 8192),
    ("us.anthropic.claude-3-7-sonnet-20250219-v1:0", 200000, 8192),
    ("us.anthropic.claude-fable-5", 1000000, 128000),
    ("us.anthropic.claude-fable-5-1", 1000000, 128000),
    ("us.anthropic.claude-haiku-4-5-20251001-v1:0", 200000, 64000),
    ("us.anthropic.claude-opus-4-1-20250805-v1:0", 200000, 32000),
    ("us.anthropic.claude-opus-4-20250514-v1:0", 200000, 32000),
    ("us.anthropic.claude-opus-4-5-20251101-v1:0", 200000, 64000),
    ("us.anthropic.claude-opus-4-6-v1", 1000000, 128000),
    ("us.anthropic.claude-opus-4-7", 1000000, 128000),
    ("us.anthropic.claude-opus-4-8", 1000000, 128000),
    ("us.anthropic.claude-opus-5", 1000000, 128000),
    ("us.anthropic.claude-sonnet-4-20250514-v1:0", 200000, 64000),
    (
        "us.anthropic.claude-sonnet-4-5-20250929-v1:0",
        200000,
        64000,
    ),
    ("us.anthropic.claude-sonnet-4-6", 1000000, 64000),
    ("us.anthropic.claude-sonnet-5", 1000000, 128000),
    ("us.deepseek.r1-v1:0", 128000, 32768),
    ("us.meta.llama3-2-11b-instruct-v1:0", 128000, 4096),
    ("us.meta.llama3-2-1b-instruct-v1:0", 131000, 4096),
    ("us.meta.llama3-2-3b-instruct-v1:0", 131000, 4096),
    ("us.meta.llama3-2-90b-instruct-v1:0", 128000, 4096),
    ("us.meta.llama3-3-70b-instruct-v1:0", 128000, 4096),
    ("us.meta.llama4-maverick-17b-instruct-v1:0", 1000000, 16384),
    ("us.meta.llama4-scout-17b-instruct-v1:0", 3500000, 16384),
    ("writer.palmyra-x4-v1:0", 122880, 8192),
    ("writer.palmyra-x5-v1:0", 1040000, 8192),
    ("xai.grok-4.3", 1000000, 131072),
    ("xai.grok-4.6", 500000, 500000),
    ("zai.glm-4.7", 204800, 131072),
    ("zai.glm-4.7-flash", 200000, 131072),
    ("zai.glm-5", 202752, 101376),
];

/// The Converse adapter over one configured `amazon-bedrock` connection.
pub struct BedrockProvider {
    connection: String,
    credential: SecretRef,
    store: Arc<dyn CredentialStore>,
    configured_region: Option<String>,
    base_override: Option<String>,
    signing_timestamp: Option<String>,
    ambient_region_override: Option<String>,
    client: reqwest::blocking::Client,
    deadline: Duration,
}

impl std::fmt::Debug for BedrockProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BedrockProvider")
            .field("connection", &self.connection)
            .field("credential", &self.credential)
            .field("base_override", &self.base_override)
            .field("deadline", &self.deadline)
            .finish_non_exhaustive()
    }
}

impl BedrockProvider {
    /// Builds the adapter for one literal `amazon-bedrock` connection.
    ///
    /// # Errors
    /// [`ProviderError::DialectMismatch`] for a connection id outside the
    /// Converse dialect; [`ProviderError::UnknownConnection`] for an
    /// undeclared id; the credential seam's typed denials for an
    /// unresolvable binding; and [`ProviderError::Transport`] when the
    /// HTTP client cannot build.
    pub fn new(
        config: &Config,
        connection: &str,
        store: Arc<dyn CredentialStore>,
        deadline: Duration,
    ) -> Result<Self, ProviderError> {
        Self::build(config, connection, store, deadline, None)
    }

    /// Builds the adapter with a loopback base override for offline proof.
    ///
    /// The override is admitted only for a literal loopback host; a
    /// non-loopback value is refused before any send.
    ///
    /// # Errors
    /// [`Self::new`]'s contract, and
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
        if dialect_for(connection) != Some(Dialect::Converse) {
            return Err(ProviderError::DialectMismatch {
                connection: connection.to_string(),
            });
        }
        let declared =
            config
                .connections
                .get(connection)
                .ok_or_else(|| ProviderError::UnknownConnection {
                    connection: connection.to_string(),
                })?;
        // Converse is a credentialled class: a `local` declaration cannot
        // serve it, and a profile beside that kind is the contradictory
        // half to fix first. Both deny before the credential resolves.
        if declared.kind == ConnKind::Local && declared.profile.is_some() {
            return Err(ProviderError::LocalProfileDeclared {
                connection: connection.to_string(),
            });
        }
        if declared.kind == ConnKind::Local {
            return Err(ProviderError::CredentialUnresolved {
                connection: connection.to_string(),
                scope: format!("connections.{connection}.kind"),
                cause: None,
            });
        }
        let credential = crate::providers::resolve_credential(config, connection)?;
        let base_override = match base_override {
            Some(base) => Some(loopback_base(connection, &base)?),
            None => None,
        };
        let client = reqwest::blocking::Client::builder()
            .timeout(deadline.saturating_mul(2))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|err| transport(connection, err))?;
        Ok(Self {
            connection: connection.to_string(),
            credential,
            store,
            configured_region: declared.region.clone(),
            base_override,
            signing_timestamp: None,
            ambient_region_override: None,
            client,
            deadline,
        })
    }

    /// The recorded static catalogue as the adapter's offer set.
    #[must_use]
    pub fn catalog_models(&self) -> Vec<CatalogModel> {
        BEDROCK_MODELS
            .iter()
            .map(|row| CatalogModel {
                id: row.0.to_owned(),
                context_window: Some(row.1),
                max_output_tokens: Some(row.2),
                ..CatalogModel::default()
            })
            .collect()
    }

    /// Pins the SigV4 `x-amz-date` value; production signs with the clock.
    #[doc(hidden)]
    #[must_use]
    pub fn with_signing_timestamp(mut self, timestamp: &str) -> Self {
        self.signing_timestamp = Some(timestamp.to_owned());
        self
    }

    /// Pins the ambient region the send reads; production follows the
    /// process environment.
    #[doc(hidden)]
    #[must_use]
    pub fn with_ambient_region(mut self, region: &str) -> Self {
        self.ambient_region_override = Some(region.to_owned());
        self
    }

    /// The ambient region the send reads: the proof-pinned one, else the
    /// process environment.
    fn ambient_region(&self) -> Option<String> {
        self.ambient_region_override
            .clone()
            .or_else(aws::ambient_region)
    }

    /// The Converse base this adapter sends to: the admitted override or
    /// the recorded regional endpoint, without a trailing slash.
    #[doc(hidden)]
    #[must_use]
    pub fn resolved_base(&self, region: &str) -> String {
        match &self.base_override {
            Some(base) => base.trim_end_matches('/').to_owned(),
            None => aws::bedrock_base(region).trim_end_matches('/').to_owned(),
        }
    }
}

impl Provider for BedrockProvider {
    fn name(&self) -> &'static str {
        "bedrock-converse"
    }

    fn serves(&self, connection: &str, _entry: &Connection) -> bool {
        connection == self.connection && dialect_for(connection) == Some(Dialect::Converse)
    }

    /// Sends the frozen manifest as one physical Converse event-stream
    /// request.
    ///
    /// # Errors
    /// [`ProviderError::UnpinnedModel`] for an assignment without a fixed
    /// pin or a one-member auto pool naming this connection,
    /// [`ProviderError::DialectMismatch`] for a pin naming another
    /// connection, [`ProviderError::UnsupportedParameter`] for a pinned
    /// effort or a model outside the recorded table,
    /// [`ProviderError::CredentialAbsent`]/the store's typed denials, the
    /// material parser's typed denials, [`ProviderError::RegionMismatch`]
    /// for a configured region outside the model's geo,
    /// [`ProviderError::Transport`] for a failed or refused send, and the
    /// typed [`ProviderError::ProviderFailed`],
    /// [`ProviderError::UnknownTerminal`], [`ProviderError::StreamViolation`]
    /// and [`ProviderError::IncompatibleOutput`] stream denials.
    fn send(&mut self, manifest: &RequestManifest) -> Result<ProviderReply, ProviderError> {
        let started = Instant::now();
        check_deadline(&self.connection, self.deadline, started)?;
        // A fixed pin names connection and model verbatim. A one-member
        // auto pool naming this connection is the broker's pinned choice:
        // the model resolves from the closed table's sorted-first id.
        let fixed = match &manifest.model {
            ModelAssign::Fixed(fixed) => fixed.clone(),
            ModelAssign::Auto { pool: Some(pool) }
                if pool.len() == 1 && pool[0] == self.connection =>
            {
                let model_id = BEDROCK_MODELS
                    .iter()
                    .map(|row| row.0)
                    .min()
                    .ok_or_else(|| ProviderError::UnpinnedModel {
                        connection: self.connection.clone(),
                    })?;
                FixedModel {
                    connection: self.connection.clone(),
                    model_id: model_id.to_owned(),
                }
            }
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
        if matches!(&manifest.effort, EffortAssign::Fixed { .. }) {
            return Err(ProviderError::UnsupportedParameter {
                connection: self.connection.clone(),
                parameter: "effort",
                model: fixed.model_id,
            });
        }
        let Some(row) = model_row(&fixed.model_id) else {
            return Err(ProviderError::UnsupportedParameter {
                connection: self.connection.clone(),
                parameter: "model",
                model: fixed.model_id,
            });
        };
        let material_bytes = self.store.resolve(&self.credential)?;
        let material = aws::parse_material(&self.connection, &material_bytes)?;
        let material_region = match &material {
            AwsMaterial::Bearer(_) => None,
            AwsMaterial::StaticKeys { region, .. } => region.as_deref(),
        };
        let ambient = self.ambient_region();
        let region = aws::resolve_region(
            &self.connection,
            &fixed.model_id,
            self.configured_region.as_deref(),
            material_region,
            ambient.as_deref(),
        )?;
        let base = self.resolved_base(&region);
        let body = request_body(manifest, row.2);
        let body_bytes = wire_body(&self.connection, &body)?;
        let timestamp = self
            .signing_timestamp
            .clone()
            .unwrap_or_else(|| aws::format_amz_date(SystemTime::now()));
        check_deadline(&self.connection, self.deadline, started)?;
        let url = reqwest::Url::parse(&base)
            .map_err(|_url| unsendable(&self.connection, "the resolved base is not a URL"))?;
        let host = request_host(&url)
            .ok_or_else(|| unsendable(&self.connection, "the resolved base has no host"))?;
        let encoded = super::percent_encode_component(&fixed.model_id);
        let path = format!(
            "{}/model/{encoded}/converse-stream",
            url.path().trim_end_matches('/')
        );
        let request_url = format!("{base}/model/{encoded}/converse-stream");
        let auth_headers = wire_headers(
            &self.connection,
            &material,
            &region,
            &host,
            &path,
            &body_bytes,
            &timestamp,
        )?;
        let mut request = self
            .client
            .post(request_url)
            .header(reqwest::header::ACCEPT, ACCEPT)
            .body(body_bytes);
        for (name, value) in auth_headers {
            request = request.header(name, value);
        }
        let mut response = request
            .send()
            .map_err(|err| transport(&self.connection, err))?;
        if !response.status().is_success() {
            return Err(transport_status(&self.connection, response.status()));
        }
        read_response(
            &self.connection,
            self.deadline,
            &mut response,
            started,
            manifest,
        )
    }
}

fn model_row(model_id: &str) -> Option<&'static (&'static str, u64, u64)> {
    let table_id = aws::model_table_id(model_id);
    BEDROCK_MODELS.iter().find(|row| row.0 == table_id)
}

/// The configured body: system instruction block, one user message, the
/// declared tool spec set, and the recorded per-model output bound.
fn request_body(manifest: &RequestManifest, max_tokens: u64) -> Value {
    let mut body = json!({
        "messages": [{
            "role": "user",
            "content": [{"text": manifest.inputs}],
        }],
        "inferenceConfig": {"maxTokens": max_tokens},
    });
    if !manifest.instructions.is_empty() {
        body["system"] = json!([{"text": manifest.instructions}]);
    }
    if !manifest.tools.is_empty() {
        let tools: Vec<Value> = manifest
            .tools
            .iter()
            .map(|name| {
                json!({
                    "toolSpec": {
                        "name": name,
                        "description": "",
                        "inputSchema": {"json": {"type": "object"}},
                    }
                })
            })
            .collect();
        body["toolConfig"] = json!({"tools": tools});
    }
    body
}

fn wire_headers(
    connection: &str,
    material: &AwsMaterial,
    region: &str,
    host: &str,
    path: &str,
    body: &[u8],
    timestamp: &str,
) -> Result<BTreeMap<String, String>, ProviderError> {
    let mut headers = BTreeMap::new();
    headers.insert("content-type".to_owned(), CONTENT_TYPE.to_owned());
    match material {
        AwsMaterial::Bearer(token) => {
            headers.insert("authorization".to_owned(), format!("Bearer {token}"));
        }
        AwsMaterial::StaticKeys {
            access_key_id,
            secret_access_key,
            session_token,
            ..
        } => {
            let mut signed_request_headers = BTreeMap::new();
            signed_request_headers.insert("content-type".to_owned(), CONTENT_TYPE.to_owned());
            signed_request_headers.insert("x-amz-content-sha256".to_owned(), aws::sha256_hex(body));
            let signed = aws::sign_v4(aws::SigV4Request {
                connection,
                method: "POST",
                host,
                path,
                query: "",
                body,
                region,
                service: SIGV4_SERVICE,
                access_key_id,
                secret_access_key,
                session_token: session_token.as_deref(),
                timestamp,
                headers: signed_request_headers,
            })?;
            for (name, value) in signed {
                headers.insert(name, value);
            }
        }
    }
    Ok(headers)
}

fn read_response(
    connection: &str,
    deadline: Duration,
    response: &mut reqwest::blocking::Response,
    started: Instant,
    manifest: &RequestManifest,
) -> Result<ProviderReply, ProviderError> {
    let mut decoder = EventStreamDecoder::new();
    let mut state = StreamState::default();
    let mut chunk = vec![0u8; super::STREAM_CHUNK_BYTES];
    loop {
        let read = read_chunk(connection, deadline, response, &mut chunk, started)?;
        if read == 0 {
            break;
        }
        let frames = decoder
            .feed(&chunk[..read])
            .map_err(|error| stream_error(connection, error))?;
        for frame in frames {
            state.apply(connection, manifest, &frame)?;
        }
    }
    decoder
        .finish()
        .map_err(|error| stream_error(connection, error))?;
    check_deadline(connection, deadline, started)?;
    state.finish(connection)
}

fn stream_error(connection: &str, error: EventStreamError) -> ProviderError {
    violation(connection, error.to_string())
}

#[derive(Default)]
struct StreamState {
    text: String,
    blocks: BTreeMap<u64, Block>,
    tool_calls: Vec<ToolCall>,
    stop_reason: Option<String>,
    usage: Option<UsageDelta>,
}

enum Block {
    Text,
    Tool { name: String, input: String },
}

impl StreamState {
    fn apply(
        &mut self,
        connection: &str,
        manifest: &RequestManifest,
        frame: &Frame,
    ) -> Result<(), ProviderError> {
        match frame.message_type.as_deref() {
            Some("event") => self.on_event(connection, manifest, frame),
            Some("exception" | "error") => Err(ProviderError::ProviderFailed {
                connection: connection.to_owned(),
                reason: bounded_reason(exception_reason(frame)),
            }),
            Some(_) | None => Err(violation(
                connection,
                "event-stream message carries no classifiable type",
            )),
        }
    }

    fn on_event(
        &mut self,
        connection: &str,
        manifest: &RequestManifest,
        frame: &Frame,
    ) -> Result<(), ProviderError> {
        let Some(event_type) = frame.event_type.as_deref() else {
            return Err(violation(connection, "event carries no event type"));
        };
        if self.stop_reason.is_some() && event_type != "metadata" {
            return Err(violation(
                connection,
                "stream carried an event after messageStop",
            ));
        }
        let payload = payload_json(connection, frame)?;
        match event_type {
            "messageStart" => Ok(()),
            "contentBlockStart" => self.content_block_start(connection, payload),
            "contentBlockDelta" => self.content_block_delta(connection, payload),
            "contentBlockStop" => self.content_block_stop(connection, manifest, payload),
            "messageStop" => self.message_stop(connection, payload),
            "metadata" => {
                self.usage = Some(usage_of(connection, &payload)?);
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn content_block_start(
        &mut self,
        connection: &str,
        payload: Value,
    ) -> Result<(), ProviderError> {
        let index = block_index(connection, &payload)?;
        match self.blocks.entry(index) {
            Entry::Occupied(_) => Err(violation(connection, "content block started twice")),
            Entry::Vacant(slot) => {
                let block = match payload.get("start").and_then(|start| start.get("toolUse")) {
                    Some(tool) => {
                        let name = tool
                            .get("name")
                            .and_then(Value::as_str)
                            .ok_or_else(|| violation(connection, "tool block carries no name"))?;
                        Block::Tool {
                            name: name.to_owned(),
                            input: String::new(),
                        }
                    }
                    None => Block::Text,
                };
                slot.insert(block);
                Ok(())
            }
        }
    }

    fn content_block_delta(
        &mut self,
        connection: &str,
        payload: Value,
    ) -> Result<(), ProviderError> {
        let index = block_index(connection, &payload)?;
        if !self.blocks.contains_key(&index) {
            return Err(violation(connection, "delta without a content block"));
        }
        let delta = payload
            .get("delta")
            .ok_or_else(|| violation(connection, "delta event carries no delta"))?;
        let tool = matches!(self.blocks.get(&index), Some(Block::Tool { .. }));
        if tool {
            if let Some(input) = delta
                .get("toolUse")
                .and_then(|tool_use| tool_use.get("input"))
                .and_then(Value::as_str)
                && let Some(Block::Tool {
                    input: accumulated, ..
                }) = self.blocks.get_mut(&index)
            {
                accumulated.push_str(input);
            }
        } else if let Some(text) = delta.get("text").and_then(Value::as_str) {
            self.text.push_str(text);
        }
        Ok(())
    }

    fn content_block_stop(
        &mut self,
        connection: &str,
        manifest: &RequestManifest,
        payload: Value,
    ) -> Result<(), ProviderError> {
        let index = block_index(connection, &payload)?;
        let block = self
            .blocks
            .remove(&index)
            .ok_or_else(|| violation(connection, "content block stopped without a start"))?;
        if let Block::Tool { name, input } = block {
            self.tool_calls
                .push(finish_tool(connection, manifest, name, input)?);
        }
        Ok(())
    }

    fn message_stop(&mut self, connection: &str, payload: Value) -> Result<(), ProviderError> {
        if self.stop_reason.is_some() {
            return Err(violation(
                connection,
                "stream carried two messageStop events",
            ));
        }
        let reason = payload
            .get("stopReason")
            .and_then(Value::as_str)
            .ok_or_else(|| violation(connection, "messageStop carries no stop reason"))?;
        if !CLASSIFIED_STOP_REASONS.contains(&reason) {
            return Err(ProviderError::UnknownTerminal {
                connection: connection.to_owned(),
            });
        }
        self.stop_reason = Some(reason.to_owned());
        Ok(())
    }

    fn finish(self, connection: &str) -> Result<ProviderReply, ProviderError> {
        let Some(stop_reason) = self.stop_reason else {
            return Err(ProviderError::UnknownTerminal {
                connection: connection.to_owned(),
            });
        };
        if !self.blocks.is_empty() {
            return Err(violation(connection, "stream ended mid content block"));
        }
        if stop_reason == "tool_use" && self.tool_calls.is_empty() {
            return Err(violation(
                connection,
                "tool_use terminal carried no tool call",
            ));
        }
        if stop_reason != "tool_use" && !self.tool_calls.is_empty() {
            return Err(violation(
                connection,
                "tool call arrived on a non-tool terminal",
            ));
        }
        Ok(ProviderReply {
            text: self.text,
            tool_calls: self.tool_calls,
            usage: self.usage.unwrap_or(UsageDelta::Unknown),
            wire_retries: 0,
            dropped_reasoning: 0,
        })
    }
}

fn block_index(connection: &str, payload: &Value) -> Result<u64, ProviderError> {
    payload
        .get("contentBlockIndex")
        .and_then(Value::as_u64)
        .ok_or_else(|| violation(connection, "event carries no content block index"))
}

fn payload_json(connection: &str, frame: &Frame) -> Result<Value, ProviderError> {
    serde_json::from_slice(&frame.payload)
        .map_err(|_json| violation(connection, "event payload is not json"))
}

fn finish_tool(
    connection: &str,
    manifest: &RequestManifest,
    name: String,
    input: String,
) -> Result<ToolCall, ProviderError> {
    if !manifest.tools.iter().any(|declared| declared == &name) {
        return Err(ProviderError::IncompatibleOutput {
            connection: connection.to_owned(),
            reason: bounded_reason(format!("tool block names undeclared tool {name}")),
        });
    }
    let input = input.trim();
    let parsed: Value = if input.is_empty() {
        json!({})
    } else {
        serde_json::from_str(input)
            .map_err(|_json| violation(connection, "tool block carries an incomplete json input"))?
    };
    let arguments = parsed
        .as_object()
        .ok_or_else(|| violation(connection, "tool input is not an object"))?;
    Ok(ToolCall {
        tool: name,
        path: arguments
            .get("path")
            .and_then(Value::as_str)
            .map(str::to_owned),
    })
}

fn usage_of(connection: &str, payload: &Value) -> Result<UsageDelta, ProviderError> {
    let Some(usage) = payload.get("usage") else {
        return Ok(UsageDelta::Unknown);
    };
    let prompt_tokens = usage.get("inputTokens").and_then(Value::as_u64);
    let completion_tokens = usage.get("outputTokens").and_then(Value::as_u64);
    let total_tokens = usage.get("totalTokens").and_then(Value::as_u64);
    let cache_read = usage.get("cacheReadInputTokens").and_then(Value::as_u64);
    let cache_write = usage.get("cacheWriteInputTokens").and_then(Value::as_u64);
    match (prompt_tokens, completion_tokens, total_tokens) {
        (Some(prompt_tokens), Some(completion_tokens), Some(total_tokens)) => {
            Ok(UsageDelta::from_reported(
                prompt_tokens,
                completion_tokens,
                total_tokens,
                None,
                cache_read,
                cache_write,
            ))
        }
        _ => Err(violation(
            connection,
            "metadata usage is not a readable token shape",
        )),
    }
}

fn exception_reason(frame: &Frame) -> String {
    serde_json::from_slice::<Value>(&frame.payload)
        .ok()
        .as_ref()
        .and_then(|payload| payload.get("message"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| frame.exception_type.clone())
        .unwrap_or_else(|| "event-stream exception".to_owned())
}

fn request_host(url: &reqwest::Url) -> Option<String> {
    let host = url.host_str()?;
    Some(match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    })
}

fn unsendable(connection: &str, reason: &str) -> ProviderError {
    ProviderError::UnsendableRequest {
        connection: connection.to_owned(),
        reason: reason.to_owned(),
    }
}
