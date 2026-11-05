"""Self-monitoring: security-relevant actions on SentinelX itself become events in the organization's
own telemetry, so the normal detection pipeline (Sigma rules under ``security/sigma-rules/platform``)
watches the watcher. An intruder who turns off rules, mints ingest tokens or brute-forces the console
produces alerts like any other attacker activity.

Events use ``source_type = sentinelx`` with ``event_category = sentinelx_platform``; rules select them
with ``logsource.product: sentinelx_platform``.
"""

from __future__ import annotations

import ipaddress
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from sentinelx.logging import get_logger

log = get_logger(__name__)

PLATFORM_CATEGORY = "sentinelx_platform"
PLATFORM_HOST = "sentinelx"

# action -> canonical event type (everything else is "other")
_EVENT_TYPES = {
    "auth.login": "authentication",
    "auth.mfa": "authentication",
    "auth.reauth": "authentication",
    "user.create": "iam",
    "user.update": "iam",
    "user.mfa_reset": "iam",
    "auth.mfa_disabled": "iam",
}


async def emit(
    session: AsyncSession,
    tenant_id: uuid.UUID | None,
    action: str,
    summary: str,
    *,
    actor: str | None = None,
    src_ip: str | None = None,
    outcome: str = "success",
    severity: int = 20,
    details: dict[str, Any] | None = None,
) -> None:
    """Record a platform event and queue it for detection. Never raises: monitoring must not break the
    action being monitored."""
    if tenant_id is None:
        return
    try:
        src_ip = str(ipaddress.ip_address(src_ip)) if src_ip else None
    except ValueError:
        src_ip = None
    from sentinelx.ingestion.pipeline import ingest

    record = {
        "event_id": f"selfmon|{uuid.uuid4()}",
        "timestamp": datetime.now(UTC).isoformat(),
        "event_type": _EVENT_TYPES.get(action, "other"),
        "event_action": action[:64],
        "event_category": PLATFORM_CATEGORY,
        "outcome": outcome,
        "severity": severity,
        "hostname": PLATFORM_HOST,
        "username": (actor or "")[:255] or None,
        "src_ip": src_ip,
        "summary": summary[:1000],
        "metadata": {"platform": True, **(details or {})},
    }
    try:
        async with session.begin_nested():
            await ingest(session, tenant_id, "sentinelx", [record])
    except Exception as e:  # pragma: no cover - defensive
        log.warning("selfmon_emit_failed", action=action, error=str(e))
