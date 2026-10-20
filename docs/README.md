# SentinelX documentation

New here? Read [How an organization uses SentinelX](organization-use.md) first. It walks through the
product in plain English, without assuming a security background.

## Architecture

- [Architecture overview](architecture/overview.md), with the component diagram in [ARCHITECTURE.md](../ARCHITECTURE.md)
- [Correlation](architecture/correlation.md): alert de-duplication, Sigma correlations, incident building
- [Risk model](architecture/risk-model.md): how the 0–100 score and its confidence are computed
- [AI analyst](architecture/ai-analyst.md): evidence grounding, prompt-injection defenses, evaluation
- [Machine learning](architecture/ml.md): behavioral baseline and explanations
- [Architecture decision records](adr/README.md)

## Running SentinelX

- [Deployment](deployment/README.md): Docker Compose profiles, native install, production checklist
- [Operations](operations/README.md): integrations, Sigma rules, threat intel, tenants, backups,
  Ollama, incident response and troubleshooting

## Security

- [Threat model](security/threat-model.md)
- [Reporting a vulnerability](../SECURITY.md)
