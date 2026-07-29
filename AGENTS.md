# Agent rules

- This repository is the source of truth for cross-repository protocols.
- Never duplicate a schema independently in Core, Vault, Node or Clients.
- Maintain semantic versions and a compatibility matrix.
- Breaking changes require dual-version rollout and test vectors.
- Generated Java, Rust and Dart packages must derive from the same source.
- Do not include secrets or environment-specific endpoints.
