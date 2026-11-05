"""SentinelX command line: ``sentinelx --help``."""

from __future__ import annotations

import asyncio
import json
import os
import sys
import uuid
from pathlib import Path
from typing import Any

import typer

app = typer.Typer(help="SentinelX — open-source SOC platform", no_args_is_help=True, add_completion=False)
API_DIR = Path(__file__).resolve().parents[2]


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


def _alembic_upgrade() -> None:
    from alembic import command
    from alembic.config import Config

    cfg = Config(str(API_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(API_DIR / "migrations"))
    cfg.attributes["configure_logger"] = False
    command.upgrade(cfg, "head")
    # least-privilege runtime role (ADR-013): re-applied after every migration so new tables are covered
    from sentinelx.persistence.grants import apply_runtime_grants

    result = _run(apply_runtime_grants())
    if result.get("applied"):
        typer.echo(
            f"✓ runtime role '{result['runtime_role']}' granted data access only (owner: {result['owner_role']})"
        )


@app.command()
def migrate() -> None:
    """Apply database migrations."""
    _alembic_upgrade()
    typer.echo("✓ database schema is up to date")


@app.command()
def init(demo: bool = typer.Option(False, help="Also build the synthetic Demo Lab organization")) -> None:
    """Migrate, load MITRE ATT&CK + rules, create the first admin (idempotent)."""
    _alembic_upgrade()
    from sentinelx.services.bootstrap import bootstrap

    async def go() -> dict[str, Any]:
        out = await bootstrap()
        if demo:
            from sentinelx.demo.loader import load_demo

            out["demo"] = await load_demo(reset=True)
        from sentinelx.persistence.db import dispose_engine

        await dispose_engine()
        return out

    out = _run(go())
    typer.echo(
        f"✓ schema migrated · {out['mitre_techniques']} ATT&CK techniques · "
        f"{out['rules']['total']} detection rules ({out['rules']['rejected']} rejected)"
    )
    if out.get("demo"):
        d = out["demo"]
        typer.echo(f"✓ Demo Lab built: {d['accepted']} synthetic events")
    if out["admin"]:
        creds = out["admin"]
        cred_file = API_DIR.parents[1] / ".sentinelx-admin.txt"
        cred_file.write_text(f"email: {creds['email']}\npassword: {creds['password']}\n")
        os.chmod(cred_file, 0o600)
        typer.secho("\n  First administrator created", bold=True)
        typer.echo(f"  email:    {creds['email']}")
        typer.echo(f"  password: {creds['password']}")
        typer.echo(f"  (also saved to {cred_file} — delete it after you sign in and change the password)\n")


@app.command()
def serve(
    host: str = "127.0.0.1",
    port: int = 8000,
    worker: bool = typer.Option(True, help="Run the worker in-process"),
    reload: bool = False,
) -> None:
    """Run the API (+ built web UI, + embedded background worker)."""
    import uvicorn

    os.environ["EMBEDDED_WORKER"] = "true" if worker else "false"
    uvicorn.run(
        "sentinelx.main:app",
        host=host,
        port=port,
        reload=reload,
        proxy_headers=True,
        forwarded_allow_ips="127.0.0.1",
        log_level="warning",
        access_log=False,
    )


@app.command("worker")
def run_worker(concurrency: int = 2) -> None:
    """Run a standalone background worker."""
    from sentinelx.config import get_settings
    from sentinelx.jobs.worker import Worker
    from sentinelx.logging import configure_logging

    s = get_settings()
    configure_logging(s.log_level, s.log_json)

    async def go() -> None:
        w = Worker(concurrency=concurrency)
        import signal

        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, w.stop)
        await w.run()

    _run(go())


@app.command()
def demo() -> None:
    """(Re)build the synthetic Demo Lab organization."""
    from sentinelx.demo.loader import load_demo

    out = _run(load_demo(reset=True))
    typer.echo(json.dumps({k: v for k, v in out.items() if k != "ml"}, default=str))


@app.command("create-user")
def create_user(
    email: str,
    role: str = "SECURITY_ANALYST",
    name: str = "",
    tenant: str = "default",
    password: str = typer.Option(..., prompt=True, hide_input=True, confirmation_prompt=True),
) -> None:
    """Create a local user."""
    from sqlalchemy import select

    from sentinelx.persistence.db import system_session
    from sentinelx.persistence.models import Tenant, User
    from sentinelx.security.passwords import hash_password, password_problems
    from sentinelx.security.rbac import Role

    if role not in Role.__members__:
        raise typer.BadParameter(f"role must be one of {', '.join(Role.__members__)}")
    if problems := password_problems(password):
        raise typer.BadParameter("password " + "; ".join(problems))

    async def go() -> None:
        async with system_session() as s:
            t = (await s.execute(select(Tenant).where(Tenant.slug == tenant))).scalar_one_or_none()
            if t is None:
                raise typer.BadParameter(f"unknown tenant {tenant}")
            s.add(
                User(
                    id=uuid.uuid4(),
                    tenant_id=t.id,
                    email=email.lower(),
                    display_name=name or email,
                    role=role,
                    password_hash=hash_password(password),
                )
            )

    _run(go())
    typer.echo(f"✓ user {email} created with role {role}")


@app.command("reset-password")
def reset_password(
    email: str, password: str = typer.Option(..., prompt=True, hide_input=True, confirmation_prompt=True)
) -> None:
    """Reset a local user's password (and unlock the account)."""
    from sqlalchemy import update

    from sentinelx.persistence.db import system_session
    from sentinelx.persistence.models import User
    from sentinelx.security.passwords import hash_password, password_problems

    if problems := password_problems(password):
        raise typer.BadParameter("password " + "; ".join(problems))

    async def go() -> int:
        async with system_session() as s:
            r = await s.execute(
                update(User)
                .where(User.email == email.lower())
                .values(password_hash=hash_password(password), failed_logins=0, locked_until=None)
            )
            return r.rowcount or 0

    n = _run(go())
    typer.echo("✓ password reset" if n else "no such user")


@app.command("ingest-file")
def ingest_file(source: str, path: Path, tenant: str = "default", log_type: str | None = None) -> None:
    """Ingest a file of Suricata EVE / Zeek / Wazuh / canonical JSON lines."""
    from sqlalchemy import select

    from sentinelx.ingestion.parsers import zeek
    from sentinelx.ingestion.pipeline import ingest
    from sentinelx.persistence.db import system_session, tenant_session
    from sentinelx.persistence.models import Tenant

    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    if source == "zeek" and lines and lines[0].startswith("#"):
        records: list[Any] = list(zeek.iter_tsv(iter(lines)))
        log_type = log_type or zeek.log_type_from_filename(path.name)
    else:
        records = [json.loads(x) for x in lines if x.strip()]
        if len(records) == 1 and isinstance(records[0], list):
            records = records[0]

    async def go() -> dict[str, Any]:
        async with system_session() as s:
            tid = (await s.execute(select(Tenant.id).where(Tenant.slug == tenant))).scalar_one()
        total: dict[str, Any] = {"accepted": 0, "duplicates": 0, "quarantined": 0}
        for i in range(0, len(records), 1000):
            async with tenant_session(tid) as s:
                r = await ingest(s, tid, source, records[i : i + 1000], log_type, run_detection_inline=True)
            for k in total:
                total[k] += getattr(r, k)
        return total

    typer.echo(json.dumps(_run(go())))


@app.command("ai-eval")
def ai_eval(runs: int = 1, model: str | None = None) -> None:
    """Evaluate the local AI analyst on the Demo Lab scenarios (validity, grounding, injection resistance)."""
    from sentinelx.ai.evaluate import evaluate

    out = _run(evaluate(runs=runs, model=model))
    summary = {k: v for k, v in out.items() if k != "runs"}
    typer.echo(json.dumps(summary, indent=2, default=str))
    for r in out["runs"]:
        typer.echo(
            f"  {r['category']:<20} {r['status']:<10} attempts={r['attempts']} {r['seconds']}s "
            f"verdict={r['verdict']} errors={r['errors']}"
        )


@app.command("sync-rules")
def sync_rules() -> None:
    """Reload Sigma rules from security/sigma-rules into the database (with versioning)."""
    from sentinelx.detection.engine import sync_rules_to_db
    from sentinelx.persistence.db import system_session

    async def go() -> dict[str, int]:
        async with system_session() as s:
            return await sync_rules_to_db(s, actor="cli")

    typer.echo(json.dumps(_run(go())))


@app.command()
def doctor() -> None:
    """Check that everything SentinelX needs is reachable and configured."""
    from sentinelx.config import get_settings

    s = get_settings()
    ok = True

    def line(good: bool, label: str, hint: str = "") -> None:
        nonlocal ok
        ok = ok and good
        typer.echo(f"  {'✓' if good else '✗'} {label}" + (f"\n      → {hint}" if hint and not good else ""))

    async def checks() -> None:
        from sqlalchemy import text

        from sentinelx.ai.ollama import OllamaClient
        from sentinelx.persistence.db import dispose_engine, system_session

        try:
            async with system_session() as db:
                rev = (await db.execute(text("SELECT version_num FROM alembic_version"))).scalar_one_or_none()
                superuser = (
                    await db.execute(text("SELECT rolsuper FROM pg_roles WHERE rolname = current_user"))
                ).scalar_one()
            line(True, "PostgreSQL reachable")
            line(rev is not None, f"database migrated (revision {rev})", "run: sentinelx init")
            line(
                not superuser,
                "connected as a non-superuser role (row-level security is enforced)",
                "superusers bypass RLS — use the dedicated sentinelx role",
            )
            from sentinelx.persistence.db import get_engine
            from sentinelx.persistence.grants import privilege_report

            async with get_engine().connect() as conn:
                priv = await privilege_report(conn)
            line(not priv["bypass_rls"], "runtime role cannot bypass row-level security", "ALTER ROLE ... NOBYPASSRLS")
            owner_ok = priv["owned_tables"] == 0 and not priv["audit_update"] and not priv["audit_delete"]
            line(
                owner_ok or not s.is_production,
                "runtime role owns no tables and cannot rewrite the audit trail"
                + ("" if owner_ok else " (development: single-role install)"),
                "set DATABASE_OWNER_URL for migrations and connect the app as a separate role - "
                "scripts/harden-db.sh does this (docs/adr/ADR-013-least-privilege-database-roles.md)",
            )
            from sentinelx.services.audit_chain import verify_chain

            async with system_session() as db:
                chain = await verify_chain(db)
            line(
                chain.ok,
                f"audit trail hash chain intact ({chain.rows_checked} records, head {chain.head_hash[:12]}…)",
                f"{len(chain.problems)} problem(s): {chain.problems[:2]}",
            )
        except Exception as e:
            line(False, "PostgreSQL reachable", f"{type(e).__name__}: check DATABASE_URL ({e})")
        st = await OllamaClient().status(s.ollama_model)
        line(
            st.get("available", False),
            f"Ollama model '{s.ollama_model}' available (optional — only the AI analyst depends on it)",
            st.get("reason", ""),
        )
        await dispose_engine()

    typer.echo("SentinelX environment check")
    _run(checks())
    from sentinelx.detection.engine import get_rules

    rs = get_rules().ruleset
    line(
        not rs.errors,
        f"{len(rs.rules)} Sigma rules + {len(rs.correlations)} correlations loaded",
        f"{len(rs.errors)} rule(s) rejected: {rs.errors[:2]}",
    )
    line(s.mitre_data_file.exists(), "MITRE ATT&CK dataset present", "run scripts/build_mitre_dataset.py")
    web = API_DIR.parents[0] / "web" / "dist" / "index.html"
    line(web.exists(), "web UI built", "run: cd apps/web && npm install && npm run build")
    for p in s.validate_for_production():
        line(False, "production settings", p)
    sys.exit(0 if ok else 1)


@app.command("audit-verify")
def audit_verify(as_json: bool = typer.Option(False, "--json", help="Machine-readable output")) -> None:
    """Check the tamper-evident audit trail. Store the printed head hash outside SentinelX (ticket, WORM
    storage) - a later run with a different history for the same sequence number reveals a rewrite."""

    async def go() -> dict[str, Any]:
        from sentinelx.persistence.db import dispose_engine, system_session
        from sentinelx.services.audit_chain import verify_chain

        async with system_session() as s:
            rep = await verify_chain(s)
        await dispose_engine()
        return rep.as_dict()

    rep = _run(go())
    if as_json:
        typer.echo(json.dumps(rep, indent=2))
    else:
        typer.echo(
            f"{'✓' if rep['ok'] else '✗'} {rep['rows_checked']} audit records checked · "
            f"head #{rep['head_seq']} {rep['head_hash']}"
        )
        for p in rep["problems"]:
            typer.echo(f"  ✗ seq {p['seq']}: {p['kind']} - {p['detail']}")
    sys.exit(0 if rep["ok"] else 1)


@app.command("sigma-import")
def sigma_import(
    path: Path = typer.Argument(..., help="Directory of Sigma rules, e.g. a clone of github.com/SigmaHQ/sigma/rules"),
    min_status: str = typer.Option("test", help="experimental | test | stable"),
    min_level: str = typer.Option("medium", help="informational | low | medium | high | critical"),
    disabled: bool = typer.Option(False, help="Import rules switched off (review, then enable)"),
    dry_run: bool = typer.Option(False, help="Only report what would be imported"),
    source: str = typer.Option("SigmaHQ", help="Attribution label"),
) -> None:
    """Import community Sigma rules as custom rules (each one compiled and validated first)."""
    if not path.is_dir():
        typer.echo(f"✗ {path} is not a directory")
        sys.exit(2)

    async def go() -> dict[str, Any]:
        from sentinelx.detection.sigma.importer import import_directory
        from sentinelx.persistence.db import dispose_engine, system_session

        async with system_session() as s:
            rep = await import_directory(
                s,
                path,
                source=source,
                min_status=min_status,
                min_level=min_level,
                enable=not disabled,
                dry_run=dry_run,
            )
        await dispose_engine()
        return rep.as_dict()

    rep = _run(go())
    typer.echo(json.dumps(rep, indent=2))


@app.command("validate-detections")
def validate_detections(as_json: bool = typer.Option(False, "--json")) -> None:
    """Replay the synthetic attack scenarios in security/attack-replay through the real pipeline and
    report which detections fired (exit code 1 if any expected detection is missing)."""

    async def go() -> list[dict[str, Any]]:
        from sentinelx.detection.engine import sync_rules_to_db
        from sentinelx.detection.replay import run_all
        from sentinelx.persistence.db import dispose_engine, system_session

        async with system_session() as s:
            await sync_rules_to_db(s, actor="validate-detections")
        out = [r.as_dict() for r in await run_all()]
        await dispose_engine()
        return out

    results = _run(go())
    if as_json:
        typer.echo(json.dumps(results, indent=2))
    else:
        for r in results:
            mark = "✓" if r["passed"] else "✗"
            typer.echo(f"  {mark} {r['name']}" + (f"  — missing: {', '.join(r['missing'])}" if r["missing"] else ""))
        passed = sum(r["passed"] for r in results)
        typer.echo(f"{passed}/{len(results)} attack scenarios detected")
    sys.exit(0 if all(r["passed"] for r in results) else 1)


if __name__ == "__main__":
    app()
