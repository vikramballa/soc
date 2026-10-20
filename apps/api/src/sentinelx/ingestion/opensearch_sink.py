"""Optional OpenSearch sink for high-volume telemetry search (ADR-006).

PostgreSQL remains the system of record for detection, correlation and evidence. When ``OPENSEARCH_URL`` is
set, every accepted event is also bulk-indexed into daily ``sentinelx-events-YYYY.MM.DD`` indices so large
deployments can run long-range hunting queries in OpenSearch Dashboards. Every document carries
``tenant_id`` so that any search over these indices can (and must) filter by organization.
Failures never block ingestion: they are logged and counted.
"""

from __future__ import annotations

import json
from datetime import UTC
from typing import Any

import httpx

from sentinelx.config import get_settings
from sentinelx.domain.events import CanonicalEvent
from sentinelx.logging import get_logger
from sentinelx.metrics import DATABASE_ERRORS
from sentinelx.threat_intel.providers import validate_integration_url

log = get_logger(__name__)

INDEX_TEMPLATE: dict[str, Any] = {
    "index_patterns": ["sentinelx-events-*"],
    "template": {
        "settings": {"number_of_shards": 1, "number_of_replicas": 0, "refresh_interval": "5s"},
        "mappings": {
            "dynamic": False,
            "properties": {
                "tenant_id": {"type": "keyword"},
                "timestamp": {"type": "date"},
                "source_type": {"type": "keyword"},
                "event_type": {"type": "keyword"},
                "event_action": {"type": "keyword"},
                "outcome": {"type": "keyword"},
                "severity": {"type": "short"},
                "hostname": {"type": "keyword"},
                "username": {"type": "keyword"},
                "src_ip": {"type": "ip"},
                "dest_ip": {"type": "ip"},
                "src_port": {"type": "integer"},
                "dest_port": {"type": "integer"},
                "protocol": {"type": "keyword"},
                "process_name": {"type": "keyword"},
                "process_command_line": {"type": "text"},
                "domain": {"type": "keyword"},
                "url": {"type": "text"},
                "file_path": {"type": "keyword"},
                "file_hash": {"type": "keyword"},
                "rule_id": {"type": "keyword"},
                "rule_name": {"type": "text"},
                "mitre_techniques": {"type": "keyword"},
                "summary": {"type": "text"},
            },
        },
    },
}

_template_ready = False


def _doc(ev: CanonicalEvent) -> dict[str, Any]:
    d = ev.model_dump(mode="json", exclude={"raw_event", "metadata"})
    d["event_id"] = str(ev.event_id)
    d["tenant_id"] = str(ev.tenant_id)
    return d


async def index_events(events: list[CanonicalEvent], transport: httpx.AsyncBaseTransport | None = None) -> int:
    global _template_ready
    s = get_settings()
    if not s.opensearch_url or not events:
        return 0
    base = validate_integration_url(s.opensearch_url, allow_http=not s.is_production)
    auth = (
        (s.opensearch_username, s.opensearch_password.get_secret_value())
        if s.opensearch_username and s.opensearch_password
        else None
    )
    lines: list[str] = []
    for ev in events:
        index = f"sentinelx-events-{ev.timestamp.astimezone(UTC):%Y.%m.%d}"
        lines.append(json.dumps({"index": {"_index": index, "_id": str(ev.event_id)}}))
        lines.append(json.dumps(_doc(ev), default=str))
    body = "\n".join(lines) + "\n"
    try:
        async with httpx.AsyncClient(
            timeout=15, auth=auth, verify=s.opensearch_verify_tls, follow_redirects=False, transport=transport
        ) as c:
            if not _template_ready:
                r = await c.put(f"{base}/_index_template/sentinelx-events", json=INDEX_TEMPLATE)
                r.raise_for_status()
                _template_ready = True
            r = await c.post(f"{base}/_bulk", content=body, headers={"Content-Type": "application/x-ndjson"})
            r.raise_for_status()
            data = r.json()
    except (httpx.HTTPError, ValueError) as e:
        DATABASE_ERRORS.inc()
        log.warning("opensearch_index_failed", error=type(e).__name__)
        return 0
    failed = sum(1 for it in data.get("items", []) if it.get("index", {}).get("error"))
    return len(events) - failed
