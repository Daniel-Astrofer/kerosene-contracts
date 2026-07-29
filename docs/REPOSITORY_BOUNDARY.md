# Repository boundary

This repository is the only canonical source for cross-repository Kerosene
protocols, schemas and test vectors.

Generated Java, Rust and Dart artifacts must come from the same versioned
source. Copies that remain in consumers are migration shims, not independent
protocol sources, and must be removed after version `0.1.0` is published and
adopted.

Contracts must not depend on Core, Vault, Node, Clients, Deploy or the archived
monorepo.
