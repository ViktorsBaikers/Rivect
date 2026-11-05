# Provider connections

Recorded connection contracts this build serves. A row names the literal
connection id, its dialect, the base its arm records, the credential form its
requests carry, and the catalogue rule its offer set obeys. An empty configured
`endpoint` resolves the row's recorded base.

| id | dialect | recorded base | credential | catalogue |
| --- | --- | --- | --- | --- |
| `vercel-ai-gateway` | Messages | `https://ai-gateway.vercel.sh` | `api_key` bearer | keyed `/v1/models`, `tool-use` marker |

## vercel-ai-gateway

The Vercel AI Gateway serves the Anthropic Messages API on its recorded root, so
inference is `POST {endpoint}/v1/messages` and the catalogue is
`GET {endpoint}/v1/models`. A configured `endpoint` wins verbatim.

The gateway key is declared as a scoped `credential_ref` and rides
`Authorization: Bearer <key>` beside the mandatory `anthropic-version` header —
never `x-api-key`. A configured region denies typed: no record names a region
default, so no region is invented.

The offer set is the keyed listing's rows whose `tags` array carries
`tool-use`. The marker is a recorded field, not an HTTP 200: a row without it is
neither offered nor sent, and a pinned model outside the tagged set denies with
no inference request. The wire model keeps its gateway id, prefix included.

The Messages envelope is the dialect's: top-level `system`, the mandatory
`max_tokens`, paired content blocks, and `message_stop` as the only terminal.
A partial tool block, an unknown terminal, or a repeated usage report never
reports a second outcome.

`kind`, `endpoint` and `credential_ref` are the connection document's own. The
edit surface refuses them with the document-only answer naming `config.toml`;
declare them in that file instead.

The offline proof runs against a loopback Messages peer. A live send stays
`NOT_RUN`.
