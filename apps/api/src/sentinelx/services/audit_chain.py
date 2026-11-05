"""Verification of the tamper-evident audit hash chain.

Every audit row stores ``row_hash = sha256(prev_hash | seq | fields...)`` (computed by a database
trigger, migration 0003). This module recomputes each hash *in Python*, independent of the database
function, and checks that sequence numbers are gap-free and that each row links to its predecessor.
An edit, a deletion, a reordering or a forged row breaks the chain at that point. Recording the head
hash somewhere outside the database (``sentinelx audit-verify --json`` in a ticket, a WORM bucket)
also detects a wholesale rewrite by someone who controls the database.
"""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

GENESIS = "0" * 64
_BATCH = 5000

_ROWS_SQL = text(
    """
    SELECT seq, prev_hash, row_hash, id::text, coalesce(tenant_id::text, ''), coalesce(actor_id::text, ''),
           actor, action, resource_type, coalesce(resource_id, ''), result, details::text,
           coalesce(source_ip, ''), coalesce(request_id, ''),
           to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US')
    FROM audit_logs WHERE seq > :after ORDER BY seq LIMIT :n
    """
)


@dataclass
class ChainReport:
    ok: bool
    rows_checked: int
    head_seq: int
    head_hash: str
    unchained_rows: int = 0
    problems: list[dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def row_hash(prev: str, fields: tuple[Any, ...]) -> str:
    seq, *rest = fields
    canonical = "|".join([prev, str(seq), *[str(x) for x in rest]])
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


async def verify_chain(session: AsyncSession, max_problems: int = 20) -> ChainReport:
    """Walk the whole chain. ``session`` must be able to read every organization's rows (system session)."""
    problems: list[dict[str, Any]] = []
    prev, expected_seq, checked, last = GENESIS, 1, 0, 0

    def problem(seq: int | None, kind: str, detail: str) -> None:
        if len(problems) < max_problems:
            problems.append({"seq": seq, "kind": kind, "detail": detail})

    while True:
        rows = (await session.execute(_ROWS_SQL, {"after": last, "n": _BATCH})).all()
        if not rows:
            break
        for r in rows:
            seq, stored_prev, stored_hash, *fields = r
            if seq != expected_seq:
                problem(seq, "gap", f"expected sequence {expected_seq}, found {seq} (rows removed)")
            if stored_prev != prev:
                problem(seq, "broken_link", "previous-hash does not match the preceding row")
            recomputed = row_hash(stored_prev or "", (seq, *fields))
            if recomputed != stored_hash:
                problem(seq, "altered", "row content does not match its hash (row edited)")
            prev, expected_seq, last = stored_hash, seq + 1, seq
            checked += 1

    head = (await session.execute(text("SELECT seq, hash FROM audit_chain_head WHERE id = 1"))).first()
    unchained = (await session.execute(text("SELECT count(*) FROM audit_logs WHERE seq IS NULL"))).scalar_one()
    if head is None:
        problem(None, "head_missing", "audit chain head row is missing")
        head_seq, head_hash = last, prev
    else:
        head_seq, head_hash = int(head[0]), str(head[1])
        if head_seq != last or head_hash != prev:
            problem(head_seq, "head_mismatch", f"chain head (seq {head_seq}) does not match the last row ({last})")
    if unchained:
        problem(None, "unchained", f"{unchained} audit row(s) carry no chain hash")
    return ChainReport(
        ok=not problems,
        rows_checked=checked,
        head_seq=head_seq,
        head_hash=head_hash,
        unchained_rows=int(unchained),
        problems=problems,
    )


async def verify_and_alert() -> dict[str, Any]:
    """Scheduled check. A broken chain is reported into every organization as a platform event, which the
    critical "Audit Trail Tampering" rule turns into an incident."""
    from sqlalchemy import select

    from sentinelx.logging import get_logger
    from sentinelx.persistence.db import system_session
    from sentinelx.persistence.models import Tenant
    from sentinelx.services import selfmon

    async with system_session() as s:
        report = await verify_chain(s)
        if not report.ok:
            get_logger(__name__).error("audit_chain_broken", problems=report.problems[:5])
            for tid in (await s.execute(select(Tenant.id))).scalars().all():
                await selfmon.emit(
                    s,
                    tid,
                    "audit.chain_broken",
                    f"SentinelX audit trail failed its integrity check: {report.problems[0]['detail']}",
                    outcome="failure",
                    severity=90,
                    details={"problems": report.problems[:5], "head_seq": report.head_seq},
                )
    return {"ok": report.ok, "rows": report.rows_checked, "problems": len(report.problems)}
