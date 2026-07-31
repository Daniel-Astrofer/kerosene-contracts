# Administrative API contract

Administrative clients are untrusted callers. Possession of `kerosene-rsctl`
or `kerosene-jctl` grants no authority; every service authenticates, authorizes
and audits each request.

## Version

Current: `0.1.0`

Version `0.1.0` defines common error, status, and ledger responses. JSON uses
snake_case on the wire. Java records use idiomatic field names and must configure
Jackson's snake-case strategy.

Profiles and responses must never contain private keys, tokens, FROST shares,
nonces, macaroons or full financial identity data.

## Contract types

### Common

| Type | Domain | Signable | Use |
|---|---|---|---|
| `AdminErrorEnvelopeV1` | admin/common | Yes | Structured error responses |
| `AuditReferenceV1` | admin/common | Yes | Audit trail entries |

### Node admin

| Type | Domain | Signable | Use |
|---|---|---|---|
| `NodeAdminStatusV1` | admin/node | Yes | Node health and membership status |

### Vault admin

| Type | Domain | Signable | Use |
|---|---|---|---|
| `VaultAdminStatusV1` | admin/vault | Yes | Vault readiness and ceremony status |

### Core admin (ledger, P2P, on-ramp, reconciliation, providers)

| Type | Domain | Signable | Use |
|---|---|---|---|
| `LedgerAccountV1` | admin/core | Yes | Ledger account read model |
| `LedgerJournalV1` | admin/core | Yes | Ledger journal entry for reconciliation |

## Versioning policy

All contracts carry a `contract_version` field constrained to the current
version constant. Breaking changes use a two-phase rollout:

1. Publish the new version (e.g. `0.2.0`) while retaining the old version.
2. Servers accept both versions.
3. Migrate all consumers to the new version.
4. Verify that the old version has no remaining consumers.
5. Remove the old version in a later release.

## Deprecation

A contract version enters deprecation when a newer version exists and all
consumers have migrated. Deprecated versions:

- Keep their JSON schema in the repository with a `deprecated` annotation.
- Receive no further updates.
- Are removed two full minor releases after their replacement stabilises.

## Canonical signing

Types marked as "Signable" implement `CanonicalSignable` with a
domain-separated binary representation. Signatures are calculated over
`signing_bytes()`, never over an arbitrary JSON serialization.

Domain prefixes follow the pattern `KEROSENE_<TYPE>_V<version>` and are
defined as constants at the crate level.

## Test vectors

Test vectors are stored in `test-vectors/` and contain:

- Representative JSON payloads for each contract type.
- Expected canonical hashes for signing verification.

These vectors enable cross-language compatibility testing between Rust and Java
implementations.

## JSON schemas

JSON Schema (draft 2020-12) definitions live in `schemas/admin/` organised by
domain:

- `schemas/admin/common/` — shared types
- `schemas/admin/node/` — node admin types
- `schemas/admin/vault/` — vault admin types
- `schemas/admin/core/` — core/admin types (ledger, P2P, etc.)
