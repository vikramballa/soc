"""File tailing for single-node / lab deployments: Suricata eve.json, Zeek log directory, Wazuh alerts.json.

Checkpoints store (inode, offset) per file in ``ingestion_checkpoints`` so restarts neither skip nor
duplicate (and deterministic event ids make any overlap harmless). Rotation is detected by inode change
or truncation.
"""

from __future__ import annotations

import asyncio
import json
import os
import uuid
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from sentinelx.config import get_settings
from sentinelx.ingestion.parsers import zeek
from sentinelx.ingestion.pipeline import ingest
from sentinelx.logging import get_logger
from sentinelx.persistence.db import system_session, tenant_session
from sentinelx.persistence.models import IngestionCheckpoint, Tenant

log = get_logger(__name__)
MAX_BYTES_PER_PASS = 8 * 1024 * 1024
MAX_LINES_PER_PASS = 5000


async def _tenant_id() -> uuid.UUID | None:
    slug = get_settings().file_ingest_tenant
    async with system_session() as s:
        return (await s.execute(select(Tenant.id).where(Tenant.slug == slug))).scalar_one_or_none()


def _read_new_lines(path: Path, pos: dict[str, Any]) -> tuple[list[str], dict[str, Any]]:
    st = path.stat()
    offset = int(pos.get("offset", 0))
    if pos.get("inode") != st.st_ino or st.st_size < offset:
        offset = 0  # rotated or truncated
    if st.st_size == offset:
        return [], {"inode": st.st_ino, "offset": offset}
    with path.open("rb") as f:
        f.seek(offset)
        chunk = f.read(MAX_BYTES_PER_PASS)
    end = chunk.rfind(b"\n")
    if end < 0:
        return [], {"inode": st.st_ino, "offset": offset}  # wait for a complete line
    raw_lines = chunk[:end].split(b"\n")[:MAX_LINES_PER_PASS]
    consumed = sum(len(x) + 1 for x in raw_lines)
    lines = [x.decode("utf-8", errors="replace").rstrip("\r") for x in raw_lines]
    return lines, {"inode": st.st_ino, "offset": offset + consumed}


async def _tail(tenant_id: uuid.UUID, source: str, path: Path, log_type: str | None = None) -> int:
    key = f"file:{source}:{path}"
    async with tenant_session(tenant_id) as s:
        cp = (
            await s.execute(select(IngestionCheckpoint).where(IngestionCheckpoint.source_key == key))
        ).scalar_one_or_none()
        pos = cp.position if cp else {}
        try:
            lines, new_pos = await asyncio.to_thread(_read_new_lines, path, pos)  # file I/O off the event loop
        except FileNotFoundError:
            return 0
        if not lines:
            return 0
        if source == "zeek" and any(x.startswith("#") for x in lines[:5]):
            records: list[Any] = list(zeek.iter_tsv(iter(lines)))
        else:
            records = []
            for ln in lines:
                if not ln.strip():
                    continue
                try:
                    records.append(json.loads(ln))
                except json.JSONDecodeError:
                    records.append({"__unparseable__": ln[:2000]})
        res = await ingest(s, tenant_id, source, records, log_type)
        stmt = pg_insert(IngestionCheckpoint).values(
            id=uuid.uuid4(), tenant_id=tenant_id, source_key=key, position=new_pos
        )
        await s.execute(stmt.on_conflict_do_update(index_elements=["source_key"], set_={"position": new_pos}))
        return res.accepted


def _discover() -> list[tuple[str, Path, str | None]]:
    """Configured files that currently exist (blocking filesystem calls - run in a thread)."""
    s = get_settings()
    found: list[tuple[str, Path, str | None]] = []
    if s.suricata_eve_path and s.suricata_eve_path.exists():
        found.append(("suricata", s.suricata_eve_path.absolute(), None))
    if s.wazuh_alerts_path and s.wazuh_alerts_path.exists():
        found.append(("wazuh", s.wazuh_alerts_path.absolute(), None))
    if s.zeek_log_dir and s.zeek_log_dir.is_dir():
        for p in sorted(s.zeek_log_dir.iterdir()):
            lt = zeek.log_type_from_filename(p.name)
            if lt and p.is_file() and p.suffix in (".log", ".json") and not os.path.islink(p):
                found.append(("zeek", p.absolute(), lt))
    return found


async def tail_configured_sources() -> dict[str, Any]:
    tid = await _tenant_id()
    if tid is None:
        return {"status": "no_tenant"}
    out: dict[str, int] = {}
    for source, path, lt in await asyncio.to_thread(_discover):
        key = f"zeek:{lt}" if source == "zeek" else source
        out[key] = out.get(key, 0) + await _tail(tid, source, path, lt)
    return out
