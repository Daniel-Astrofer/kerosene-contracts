# Secure service contracts v1

Contract version: `0.3.0`. Status: published shape, not production rollout.

## Invariants

- X.509 SVID rotation does not change a workload identity. Certificate
  fingerprints are deliberately absent.
- A SPIFFE ID is authenticated from the exact URI SAN on the current mTLS
  connection. A JSON field, endpoint, DNS name or IP never proves identity.
- A service roster is authorized by a previously trusted, stable discovery
  manifest. Its signatures cannot define their own authority.
- Roster members and signatures are strictly sorted by their identifier.
- Endpoints are HTTPS routing data only and must never become an arbitrary URL
  fetch surface.
- `SigningIntentV1` authorizes only `sign_psbt`; generic message signing is
  outside this contract.

## Required verification

Consumers must validate the JSON schema, semantic validator, roster hash chain,
authority manifest hash and quorum, every Ed25519 signature, current time,
network, exact caller/audience SPIFFE IDs and both roster entries.

`psbt_sha256` is SHA-256 over the exact decoded PSBT bytes transported to the
Vault, before parsing or normalization. `authorization_hash` is SHA-256 over
the exact ASCII compact-JWS authorization evidence. The change descriptor hash
uses its canonical descriptor including checksum.

Replay state is durable and transactional:

- `(network_id, issuer_workload_id, request_id)` identifies one request attempt;
- `(network_id, issuer_workload_id, intent_id)` identifies one financial intent;
- nonce is single-use;
- sequence is strictly increasing per `(network_id, issuer_workload_id, wallet_id)`;
- an exact retry returns the stored result, while changed bytes fail closed.

The intent lifetime is at most 60 seconds. Consumers still need an explicit
clock-skew policy and must reject intents outside roster validity.

## Boundary

These types do not implement TLS, signature verification, durable replay
storage, PSBT policy validation or discovery transport. They define the bytes
those implementations must agree on. Production remains blocked until KFE,
Vault, Node and Deploy prove the negative tests and rollout gates.
