# Architecture decision records

- [ADR-001-modular-monolith](ADR-001-modular-monolith.md) — Modular monolith first
- [ADR-002-security-stack](ADR-002-security-stack.md) — Integrate the open-source security stack instead of rebuilding it
- [ADR-003-postgres-job-queue](ADR-003-postgres-job-queue.md) — PostgreSQL job queue instead of a separate broker
- [ADR-004-canonical-event-model](ADR-004-canonical-event-model.md) — Canonical event model with deterministic ids
- [ADR-005-postgresql](ADR-005-postgresql.md) — PostgreSQL for application state and as the default event store
- [ADR-006-opensearch-optional](ADR-006-opensearch-optional.md) — OpenSearch as optional high-volume search sink
- [ADR-007-ollama](ADR-007-ollama.md) — Ollama for the local AI runtime; cloud models refused
- [ADR-008-sigma](ADR-008-sigma.md) — Sigma as the rule format with an in-process evaluator
- [ADR-009-mitre-attack](ADR-009-mitre-attack.md) — MITRE ATT&CK from official STIX data
- [ADR-010-multi-tenancy](ADR-010-multi-tenancy.md) — Multi-tenancy with row-level security
- [ADR-011-ai-grounding](ADR-011-ai-grounding.md) — Evidence-grounding strategy for the AI analyst
- [ADR-012-local-auth-and-oidc](ADR-012-local-auth-and-oidc.md) — Local accounts by default, Keycloak OIDC optional (BFF pattern)
