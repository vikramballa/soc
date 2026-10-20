# Troubleshooting

| Symptom | Fix |
|---|---|
| `sentinelx doctor` shows ✗ | Follow the hint printed under it |
| "Core detection: degraded" | The worker is not running: use `sentinelx serve` (embedded worker) or start `sentinelx worker` |
| "AI Analyst: unavailable" | Start Ollama (`ollama serve`) and `ollama pull <model>`; detection is unaffected |
| `No module named sentinelx` (macOS) | Run with `PYTHONPATH=src` or `chflags nohidden apps/api/.venv/lib/python3.*/site-packages/*.pth` |
| Events quarantined | Integrations → Quarantined events shows the parse error and payload |
| No incidents despite alerts | Alerts below the promotion policy stay low-signal groups (*Show low-signal groups*); check rules are enabled |
| Login locked | Wait 15 min or `sentinelx reset-password <email>` |
| Production refuses to start | Set a strong `APP_SECRET` and serve over HTTPS with `SESSION_COOKIE_SECURE=true` |
| Port 5432 in use by another PostgreSQL | `PGPORT=5434 ./scripts/setup.sh` (and use that port in `DATABASE_URL`) |
