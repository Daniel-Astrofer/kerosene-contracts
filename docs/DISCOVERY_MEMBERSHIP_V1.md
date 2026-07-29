# Discovery and membership v1

Contract version: `0.2.0`.

Identity is derived from the root Ed25519 public key:

`member_id = hex(SHA-256(network_id || root_public_key))`

The onion endpoint is routing data and is never an identity.

## Planes

Bank and Vault discovery are separate planes. A signed object from one plane
cannot authorize membership in the other because the plane is included in the
canonical signature transcript.

## Peer hello

`PeerHelloV1` is signed over the `KEROSENE_PEER_HELLO_V1` domain, network,
plane, member identity, challenge, issuance time and onion endpoint. Challenges
are single-use and bounded by time. A hello is authenticated before it can be
checked against membership; authentication alone does not grant membership.

## Membership manifest

`MembershipManifestV1` is hash-chained by `previous_manifest_hash`. Signatures
are excluded from the manifest hash so multiple peers can independently append
their quorum signatures.

Stable updates require the current threshold. A membership change must first
publish a `joint` manifest accepted by both the old and proposed rosters. The
following stable manifest activates the new roster. Direct old-to-new
replacement is invalid.

## Endpoint policy

Production endpoints are `https://<56-character-v3-service-id>.onion` with an
optional port. Consumers must use a Tor SOCKS proxy with remote name
resolution, mTLS, and certificate identity binding. There is no clearnet or
Kubernetes Service DNS fallback.
