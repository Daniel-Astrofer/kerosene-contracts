# Kerosene Contracts

Canonical, versioned protocol contracts for Java, Rust and Dart consumers.

The initial extraction contains the existing Java DTO contracts and legacy LND
protobuf definitions. New bank, Vault, identity and rail protocols must be
defined here with compatibility tests and test vectors.

## Compatibility policy

Breaking changes use a two-phase rollout:

1. publish v2;
2. servers accept v1 and v2;
3. migrate Vaults and clients;
4. verify that v1 has no consumers;
5. remove v1 in a later release.
