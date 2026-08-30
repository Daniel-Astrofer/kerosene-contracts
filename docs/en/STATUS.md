# Status

Last reviewed: 2026-08-28.

| Area | State | Evidence / next action |
| --- | --- | --- |
| Repository authority | Defined | `REPOSITORY_BOUNDARY.md` assigns cross-repository protocol ownership here. |
| Discovery/membership v1 | Documented | JSON schemas and Rust types exist; consumers must pin the same released revision. |
| Secure service contracts v1 | Implemented in Contracts | Schema, Java/Rust canonical encodings and cross-language KATs exist; service adoption and runtime controls remain pending. |
| Administrative contracts | Documented | Contract documents and schemas require compatibility tests in consuming services. |
| Multi-language artifacts | Partial | Java, Rust and Dart consumers must be generated or validated from one versioned source. |
| Consumer version alignment | Pending | Core, Node, Vault and Clients must adopt one release matrix before production. |
| Historical DTO inventory | Deprecated | `DTO_SCHEMA_INDEX.md` points to service-owned DTO history and must not define new contracts. |

Breaking changes follow the compatibility policy in the repository README.
