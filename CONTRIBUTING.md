# Contributing

Thanks for helping make security operations accessible.

1. Read [ARCHITECTURE.md](ARCHITECTURE.md) and the ADRs. Architectural changes need an ADR in `docs/adr/`.
2. Setup: `./scripts/setup.sh`, then `make dev`.
3. Every change ships with tests (`make test`) and passes `make lint`.
4. Detection rules: standard Sigma, with `falsepositives`, ATT&CK tags that exist in the current catalog,
   and a fixture-backed test when possible.
5. Never commit secrets, real customer telemetry or personal data. Fixtures must be synthetic.
6. Keep AI features additive: core detection must work with Ollama switched off.
