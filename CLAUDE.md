# CLAUDE.md

Guidance for Claude Code (and other AI coding assistants) working in this repository.

## What this is

SentinelX is an open-source SOC platform. It ingests Wazuh, Suricata and Zeek telemetry, detects with
Sigma rules, correlates alerts into explainable incidents, scores risk transparently, maps to MITRE
ATT&CK, and offers an optional local AI analyst (Ollama) that must cite evidence for every claim.

- `apps/api` is the backend: FastAPI + SQLAlchemy 2 (async) + PostgreSQL, package `sentinelx` under `src/`.
  The same process serves the API, runs the background worker, and serves the built UI from `apps/web/dist`.
- `apps/web` is the UI: React 19, TypeScript, Vite, Tailwind 4, TanStack Query.
- `security/` holds the bundled Sigma rules and the compact MITRE ATT&CK dataset.
- `docs/adr` records the major design decisions. Read the relevant ADR before changing architecture,
  and add a new one for any architectural change.

`ARCHITECTURE.md` has the component diagram and a code map of the backend modules.

## Commands

```bash
make setup                # native install + DB role + UI build (scripts/setup.sh)
make dev                  # API with reload on :8000 + Vite on :5173
make start                # production-style single process on :8000
make test                 # backend tests (needs PostgreSQL, see below)
make lint                 # ruff check + ruff format --check + tsc + oxlint
make typecheck            # mypy + tsc
make format               # ruff format + autofix

cd apps/api && uv run --no-sync pytest tests/unit/test_sigma.py -q    # a single test file
cd apps/web && npx tsc -b && npm run build                            # UI type check + build
```

On macOS, uv's editable `.pth` file can get the `hidden` flag and Python then skips it
("No module named sentinelx"). The project works around this: pytest uses `pythonpath = ["src"]`,
Alembic uses `prepend_sys_path = src`, and scripts run `PYTHONPATH=src uv run --no-sync python -m sentinelx.cli ...`.
Keep using that form in scripts and docs.

## Tests

- Tests need a real PostgreSQL. They use a `sentinelx_test` database owned by the `sentinelx` role on the
  same server as `DATABASE_URL` from `.env`, or `TEST_DATABASE_URL` if set. The schema is rebuilt from
  migrations once per session.
- Layout: `tests/unit`, `tests/integration`, `tests/security` (auth, RBAC, tenant isolation),
  `tests/e2e` (demo scenarios end to end). Fixtures are in `tests/fixtures` and must stay synthetic.
- Ollama is pointed at a closed port in tests; AI behavior is tested with mocks. Core features must pass
  with the AI unavailable.
- Every behavior change ships with a test. Run `make test` and `make lint` before calling work done.

## Invariants (do not break these)

- **Never connect as a PostgreSQL superuser.** Superusers bypass row-level security. The app role is
  `NOSUPERUSER NOBYPASSRLS`.
- **Tenant isolation is two layers:** every query filters by `tenant_id`, and RLS policies (migration
  `0002`) enforce it again. New tenant-scoped tables need both a `tenant_id` column and an RLS policy.
- **The audit log is append-only** (database trigger). Don't add update/delete paths for it.
- **Permissions are enforced server-side** via `api/deps.require(Perm.X)`. The UI's `RequirePerm` only
  hides things. New endpoints need a permission and a row in `tests/security/test_rbac.py`.
- **Detection never depends on the AI.** The AI is on-request, cannot change risk scores, and cannot take
  actions.
- **AI grounding:** every claim cites `E01`-style references that map to real events; the validator
  rejects unknown references, indicators or ATT&CK IDs. Fields flagged as prompt injection are withheld
  from the model, and a `likely_benign` verdict is rejected when injection flags exist. Keep both defenses.
- **Local models only.** Ollama models ending in `:cloud` or served remotely are blocked in `ai/ollama.py`
  and again at the API route. Don't relax this.
- **No remote command execution.** Response actions are tasks, notes and watchlist entries only.
- **Demo data lives in its own `demo-lab` tenant** and uses reserved documentation IP ranges and fictitious
  domains.

## Design decisions worth knowing

- PostgreSQL is the event store; OpenSearch is an optional sink (ADR-005, ADR-006).
- The job queue is PostgreSQL (`FOR UPDATE SKIP LOCKED` + `LISTEN/NOTIFY`), not Redis (ADR-003).
- Sigma rules are evaluated by an in-process compiler in `detection/sigma/`; pySigma is only used in tests
  for validation (ADR-008).
- Event ids are deterministic UUIDv5s, so re-ingesting the same data is idempotent (ADR-004).
- MITRE ATT&CK data is v19.2. Defense evasion was split into `stealth` and `defense-impairment`, and
  log clearing is `T1685.005` (`T1070.001` no longer exists). Rule tags must exist in the current catalog.
- Python's `ipaddress.is_private` treats RFC 5737 documentation ranges as private, so internal networks
  are an explicit list in `domain/events.py`.
- Database sessions are pinned to UTC; date bucketing breaks otherwise.

## Code style

- Python: ruff (line length 120), full type hints, `from __future__ import annotations`. Module docstrings
  say what the module does in a line or two; comments explain *why*, not *what*.
- TypeScript: strict mode, function components, data fetching through TanStack Query and `lib/api.ts`.
- Keep the UI plain-spoken and uncluttered. It is meant for IT generalists, not only security specialists.
  Severity is never conveyed by color alone.
- Never commit secrets, real customer telemetry or personal data.
