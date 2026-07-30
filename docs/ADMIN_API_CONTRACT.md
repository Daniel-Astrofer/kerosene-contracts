# Administrative API contract

Administrative clients are untrusted callers. Possession of `kerosene-rsctl`
or `kerosene-jctl` grants no authority; every service authenticates, authorizes
and audits each request.

Version `0.1.0` defines common error and status responses. JSON uses snake_case
on the wire. Java records use idiomatic field names and must configure Jackson's
snake-case strategy.

Profiles and responses must never contain private keys, tokens, FROST shares,
nonces, macaroons or full financial identity data.

## Schema index

### `admin/common`

| Schema | Description |
|---|---|
| `error-envelope-v1.schema.json` | Standard error envelope returned by all admin endpoints. |

### `admin/node`

| Schema | Description |
|---|---|
| `status-v1.schema.json` | Node health and consensus status (`NodeAdminStatusV1`). |

### `admin/vault`

| Schema | Description |
|---|---|
| `status-v1.schema.json` | Vault operational status (`VaultAdminStatusV1`). |

### `admin/core`

| Schema | Description |
|---|---|
| `ledger-account-v1.schema.json` | Ledger account details for financial inspection (`LedgerAccountV1`). |
| `ledger-journal-v1.schema.json` | Ledger journal entry for transaction audit trails (`LedgerJournalV1`). |
| `p2p-order-v1.schema.json` | P2P order details for trade inspection (`P2pOrderV1`). |
| `onramp-order-v1.schema.json` | On-ramp order details for fiat-to-crypto inspection (`OnrampOrderV1`). |
| `reconciliation-status-v1.schema.json` | Reconciliation state and discrepancy counts (`ReconciliationStatusV1`). |
| `provider-connection-validation-v1.schema.json` | Provider connectivity, authentication and functional health check (`ProviderConnectionValidationV1`). |
