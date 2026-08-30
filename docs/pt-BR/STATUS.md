# Estado atual

Última revisão: 28/08/2026.

| Área | Estado | Evidência e próxima ação |
| --- | --- | --- |
| Autoridade do repositório | Definida | `REPOSITORY_BOUNDARY.md` atribui a este repositório os protocolos entre projetos. |
| Discovery/membership v1 | Documentado | Existem schemas JSON e tipos Rust; todos os consumidores precisam fixar a mesma revisão publicada. |
| Contratos seguros entre serviços v1 | Implementados em Contracts | Existem schemas, codificação canônica Java/Rust e KATs entre linguagens; adoção e controles de runtime continuam pendentes. |
| Contratos administrativos | Documentados | Documentos e schemas precisam de testes de compatibilidade nos serviços consumidores. |
| Artefatos para várias linguagens | Parcial | Java, Rust e Dart devem ser gerados ou validados a partir da mesma fonte versionada. |
| Alinhamento de versões | Pendente | Core, Node, Vault e Clients precisam adotar uma matriz única antes da produção. |
| Inventário histórico de DTOs | Depreciado | `DTO_SCHEMA_INDEX.md` registra DTOs pertencentes aos serviços e não deve definir contratos novos. |

Mudanças incompatíveis seguem a política de compatibilidade do README do
repositório.
