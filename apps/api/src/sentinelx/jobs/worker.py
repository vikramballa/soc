"""Background worker: claims jobs from PostgreSQL, runs periodic tasks, publishes a heartbeat.

Two lanes so slow LLM generations never delay detection:
  * ``fast`` lane (N slots) - process_events, ti_enrich, ml_*, retention, ingestion, demo
  * ``ai`` lane (1 slot)    - ai_investigate
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import socket
import traceback
import uuid
from datetime import UTC, datetime
from typing import Any

import asyncpg
from sqlalchemy import select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert

from sentinelx.config import get_settings
from sentinelx.jobs.queue import CLAIM_SQL, enqueue
from sentinelx.logging import get_logger
from sentinelx.metrics import JOBS_PROCESSED, QUEUE_DEPTH
from sentinelx.persistence.db import system_session, tenant_session
from sentinelx.persistence.models import Tenant, WorkerHeartbeat

log = get_logger("sentinelx.worker")

AI_KINDS = ["ai_investigate"]
FAST_KINDS = [
    "process_events",
    "ti_enrich",
    "ml_train",
    "ml_score",
    "retention",
    "tail_files",
    "wazuh_poll",
    "load_demo",
]


async def _handle(kind: str, tenant_id: uuid.UUID | None, payload: dict[str, Any]) -> dict[str, Any]:
    if kind == "process_events":
        from sentinelx.processing import process_events

        assert tenant_id
        async with tenant_session(tenant_id) as s:
            return await process_events(s, tenant_id, [uuid.UUID(x) for x in payload["event_ids"]])
    if kind == "ai_investigate":
        from sentinelx.ai.service import run_investigation

        assert tenant_id
        return await run_investigation(tenant_id, uuid.UUID(payload["investigation_id"]))
    if kind == "ti_enrich":
        from sentinelx.correlation.incidents import recompute_incident
        from sentinelx.processing import enrich_incidents

        assert tenant_id
        inc = uuid.UUID(payload["incident_id"])
        async with tenant_session(tenant_id) as s:
            changed = await enrich_incidents(s, tenant_id, {inc}, local_only=False)
            for i in changed:
                await recompute_incident(s, tenant_id, i)
        return {"changed": len(changed)}
    if kind == "ml_train":
        from sentinelx.ml.service import train_model

        assert tenant_id
        async with tenant_session(tenant_id) as s:
            return await train_model(s, tenant_id)
    if kind == "ml_score":
        from sentinelx.ml.service import score_recent

        assert tenant_id
        async with tenant_session(tenant_id) as s:
            return await score_recent(s, tenant_id, hours=int(payload.get("hours", 2)))
    if kind == "retention":
        from sentinelx.services.retention import run_retention

        return await run_retention()
    if kind == "tail_files":
        from sentinelx.ingestion.tailer import tail_configured_sources

        return await tail_configured_sources()
    if kind == "wazuh_poll":
        from sentinelx.ingestion.wazuh_indexer import poll_wazuh_indexer

        return await poll_wazuh_indexer()
    if kind == "load_demo":
        from sentinelx.demo.loader import load_demo

        return await load_demo(reset=True)
    raise ValueError(f"unknown job kind {kind}")


class Worker:
    def __init__(self, concurrency: int = 2):
        self.id = f"{socket.gethostname()}-{os.getpid()}-{uuid.uuid4().hex[:6]}"
        self.concurrency = max(1, concurrency)
        self._stop = asyncio.Event()
        self._wake = asyncio.Event()
        self.jobs_done = 0
        self.started = datetime.now(UTC)

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()

    async def run(self) -> None:
        log.info("worker_started", worker=self.id, concurrency=self.concurrency)
        tasks = [asyncio.create_task(self._lane(FAST_KINDS)) for _ in range(self.concurrency)]
        tasks.append(asyncio.create_task(self._lane(AI_KINDS)))
        tasks.append(asyncio.create_task(self._listen()))
        tasks.append(asyncio.create_task(self._scheduler()))
        await self._stop.wait()
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        log.info("worker_stopped", worker=self.id)

    async def _listen(self) -> None:
        dsn = get_settings().database_url.replace("postgresql+asyncpg://", "postgresql://")
        while not self._stop.is_set():
            conn = None
            try:
                conn = await asyncpg.connect(dsn)
                await conn.add_listener("sentinelx_jobs", lambda *_: self._wake.set())
                while not self._stop.is_set():
                    await asyncio.sleep(30)
                    await conn.execute("SELECT 1")
            except (OSError, asyncpg.PostgresError) as e:
                log.warning("listen_connection_lost", error=str(e))
                await asyncio.sleep(5)
            finally:
                if conn is not None:
                    with contextlib.suppress(Exception):
                        await conn.close()

    async def _claim(self, kinds: list[str]) -> dict[str, Any] | None:
        async with system_session() as s:
            row = (await s.execute(CLAIM_SQL, {"worker": self.id, "kinds": kinds})).mappings().first()
            return dict(row) if row else None

    async def _finish(self, job_id: int, ok: bool, error: str | None, attempts: int, max_attempts: int) -> None:
        async with system_session() as s:
            if ok:
                await s.execute(
                    text("UPDATE jobs SET status='done', finished_at=now(), last_error=NULL WHERE id=:i"), {"i": job_id}
                )
            elif attempts < max_attempts:
                backoff = min(300, 5 * 2**attempts)
                await s.execute(
                    text(
                        "UPDATE jobs SET status='queued', locked_by=NULL, last_error=:e, "
                        "run_after = now() + make_interval(secs => :b) WHERE id=:i"
                    ),
                    {"i": job_id, "e": (error or "")[:4000], "b": backoff},
                )
            else:
                await s.execute(
                    text("UPDATE jobs SET status='failed', finished_at=now(), last_error=:e WHERE id=:i"),
                    {"i": job_id, "e": (error or "")[:4000]},
                )

    async def _lane(self, kinds: list[str]) -> None:
        poll = get_settings().worker_poll_seconds
        while not self._stop.is_set():
            try:
                job = await self._claim(kinds)
            except Exception as e:
                log.warning("claim_failed", error=str(e))
                await asyncio.sleep(poll * 2)
                continue
            if job is None:
                self._wake.clear()
                with contextlib.suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(self._wake.wait(), timeout=poll)
                continue
            kind = job["kind"]
            try:
                result = await _handle(kind, job["tenant_id"], job["payload"] or {})
                await self._finish(job["id"], True, None, job["attempts"], job["max_attempts"])
                JOBS_PROCESSED.labels(kind=kind, status="done").inc()
                self.jobs_done += 1
                if kind not in ("tail_files", "wazuh_poll"):
                    log.info("job_done", kind=kind, job_id=job["id"], result=_short(result))
            except Exception as e:
                err = f"{type(e).__name__}: {e}"
                log.error(
                    "job_failed", kind=kind, job_id=job["id"], error=err, trace=traceback.format_exc(limit=5)[-2000:]
                )
                JOBS_PROCESSED.labels(kind=kind, status="error").inc()
                await self._finish(job["id"], False, err, job["attempts"], job["max_attempts"])

    async def _scheduler(self) -> None:
        """Periodic duties. Dedup keys make this safe with several workers running."""
        s = get_settings()
        tick = 0
        while not self._stop.is_set():
            try:
                await self._heartbeat()
                now = datetime.now(UTC)
                async with system_session() as db:
                    if tick % 3 == 0:
                        await db.execute(
                            text(
                                "UPDATE jobs SET status='queued', locked_by=NULL WHERE status='running' "
                                "AND locked_at < now() - interval '15 minutes' AND kind <> 'ai_investigate'"
                            )
                        )
                        await db.execute(
                            text(
                                "UPDATE jobs SET status='failed', last_error='timed out' WHERE status='running' "
                                "AND locked_at < now() - interval '15 minutes' AND kind = 'ai_investigate'"
                            )
                        )
                        await db.execute(
                            text(
                                "UPDATE ai_investigations SET status='failed', error='worker restarted or timed out' "
                                "WHERE status IN ('queued','running') AND created_at < now() - interval '20 minutes'"
                            )
                        )
                        await db.execute(
                            text("DELETE FROM jobs WHERE status = 'done' AND finished_at < now() - interval '1 day'")
                        )
                        await db.execute(
                            text("DELETE FROM jobs WHERE status = 'failed' AND finished_at < now() - interval '7 days'")
                        )
                        for kind, n in (
                            await db.execute(
                                text("SELECT kind, count(*) FROM jobs WHERE status='queued' GROUP BY kind")
                            )
                        ).all():
                            QUEUE_DEPTH.labels(kind=kind).set(n)
                    if s.suricata_eve_path or s.zeek_log_dir or s.wazuh_alerts_path:
                        await enqueue(db, "tail_files", {}, dedup_key="tail_files", max_attempts=1)
                    if s.wazuh_indexer_url and tick % 2 == 0:
                        await enqueue(db, "wazuh_poll", {}, dedup_key="wazuh_poll", max_attempts=1)
                    hour = now.strftime("%Y%m%d%H")
                    tenants = (await db.execute(select(Tenant.id))).scalars().all()
                    for t in tenants:
                        # score the current and previous hour every ~5 minutes, retrain daily
                        if tick % 60 == 0:
                            await enqueue(
                                db,
                                "ml_score",
                                {"hours": 2},
                                tenant_id=t,
                                once=True,
                                dedup_key=f"ml_score:{t}:{hour}:{now.minute // 5}",
                            )
                        await enqueue(
                            db, "ml_train", {}, tenant_id=t, dedup_key=f"ml_train:{t}:{now:%Y%m%d}", once=True
                        )
                    await enqueue(db, "retention", {}, dedup_key=f"retention:{hour}", once=True)
            except Exception as e:
                log.warning("scheduler_error", error=str(e))
            tick += 1
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(self._stop.wait(), timeout=5)

    async def _heartbeat(self) -> None:
        async with system_session() as db:
            stmt = pg_insert(WorkerHeartbeat).values(
                worker_id=self.id,
                started_at=self.started,
                last_seen=datetime.now(UTC),
                jobs_done=self.jobs_done,
                info={"concurrency": self.concurrency, "pid": os.getpid()},
            )
            await db.execute(
                stmt.on_conflict_do_update(
                    index_elements=["worker_id"],
                    set_={"last_seen": stmt.excluded.last_seen, "jobs_done": stmt.excluded.jobs_done},
                )
            )
            await db.execute(text("DELETE FROM worker_heartbeats WHERE last_seen < now() - interval '1 day'"))


def _short(result: Any) -> Any:
    if isinstance(result, dict):
        return {k: v for k, v in result.items() if not isinstance(v, list | dict)}
    return None
