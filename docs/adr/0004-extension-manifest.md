# ADR-0004: Extension manifest v1 schema

- Status: accepted
- Date: 2026-09-22
- Workspace: `rivect-native-cli-05-actions-workflow-sources` (DEC-009, promoted at `/rite-vet`)

## Context

Extensions are untrusted input files. The manifest is the parse contract that
gates permission/executable scope → consent (INV-008, PROH-005) and drives the
full lifecycle — discovery, install, inspect, enable, disable, update, remove,
doctor — with honest installed/enabled/allowed/available/active distinction
(master prompt §14.8, REQ-061, AC-074). Because it is a security/data boundary
and a cross-slice interface, the schema is pinned here, not left
implementation-local.

## Decision

Manifest v1 semantic fields (per §14.8):

- `id` — unique identifier; case-sensitive alias namespace, collisions visible
  and denied.
- `name`, `version` — human-readable identity and version.
- `source` — kind (`local` | `pinned` | `git` | `registry`) plus pin
  (rev/hash/version bound) recorded verbatim.
- `permissions` — declared permission scopes; consent records reference this
  set and a superset in a later version requires fresh consent.
- `executables` — declared executable entry points; new executables in an
  update are new scope requiring fresh consent.
- `compatibility` — declared version/host constraints evaluated at inspect,
  install, enable, update and doctor.

Parse rules:

- Strict typed parse with diagnostics; an invalid manifest yields diagnostics,
  never a fake installed-ready state.
- Unknown fields are preserved verbatim on round-trip (A32) — import/migration
  never silently drops user or forward-versioned data.
- Unsupported allowlist/read-only fields are never discarded; they are reported
  as unsupported, not activated.

## Consequences

- Old consent never activates new rights: any manifest diff widening
  permissions or executables re-enters the versioned `Question` consent seam.
- `disable`/`remove` drop only the extension's own registrations; project,
  settings and experience survive.
- Canonical manifest fixtures live in `tests/support/mod.rs` and are consumed
  by both the parse legs and the lifecycle legs in `tests/extensions.rs`.
- Schema changes land as new manifest versions; v1 rows must keep parsing.
