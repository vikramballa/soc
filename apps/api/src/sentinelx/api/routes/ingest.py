"""HTTP ingestion for shippers (Fluent Bit, Vector, Filebeat, Wazuh integrations, scripts).

Auth: ``Authorization: Bearer sxi_...`` ingest token (scoped to one tenant), or a signed-in user with
``ingest:write``. Bodies: JSON array, single JSON object, NDJSON, or Zeek TSV (``text/plain``).
"""

from __future__ import annotations

import ipaddress
import json
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request, status
from sqlalchemy import select

from sentinelx.api.deps import client_ip, get_principal
from sentinelx.config import get_settings
from sentinelx.ingestion.parsers import zeek
from sentinelx.ingestion.pipeline import SOURCES, ingest
from sentinelx.persistence.db import system_session, tenant_session
from sentinelx.persistence.models import IngestToken
from sentinelx.security.passwords import token_hash
from sentinelx.security.ratelimit import limiter
from sentinelx.security.rbac import Perm
from sentinelx.services import selfmon
from sentinelx.services.audit import audit

MAX_KNOWN_IPS = 20

router = APIRouter(prefix="/ingest", tags=["ingest"])


def _ip_allowed(ip: str | None, cidrs: list[str]) -> bool:
    if not cidrs:
        return True
    try:
        addr = ipaddress.ip_address(ip or "")
    except ValueError:
        return False
    return any(addr in ipaddress.ip_network(c, strict=False) for c in cidrs)


async def _tenant_from_request(request: Request, source: str) -> tuple[Any, str]:
    auth = request.headers.get("authorization", "")
    raw: str | None = None
    if auth.lower().startswith("bearer sxi_"):
        raw = auth[7:].strip()
    elif source == "canarytokens" and request.query_params.get("token", "").startswith("sxi_"):
        # Canarytokens webhooks cannot send headers; the token rides in the URL (scope it to this source)
        raw = request.query_params["token"]
    if raw is not None:
        ip = client_ip(request)
        violation: str | None = None
        async with system_session() as s:
            tok = (
                await s.execute(
                    select(IngestToken)
                    .where(IngestToken.token_hash == token_hash(raw), IngestToken.revoked_at.is_(None))
                    .with_for_update()
                )
            ).scalar_one_or_none()
            if tok is None:
                raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or revoked ingest token")
            if tok.allowed_sources and source not in tok.allowed_sources:
                violation = f"source {source!r} is outside this token's scope"
            elif not _ip_allowed(ip, tok.allowed_cidrs or []):
                violation = f"address {ip} is outside this token's allowed networks"
            if violation:
                await audit(
                    s,
                    action="ingest_token.denied",
                    resource_type="ingest_token",
                    resource_id=tok.id,
                    actor=f"token:{tok.prefix}",
                    tenant_id=tok.tenant_id,
                    result="denied",
                    details={"reason": violation, "source": source},
                    source_ip=ip,
                )
                await selfmon.emit(
                    s,
                    tok.tenant_id,
                    "ingest_token.denied",
                    f"Ingest token {tok.name} was used outside its scope: {violation}",
                    actor=f"token:{tok.prefix}",
                    src_ip=ip,
                    outcome="failure",
                    severity=60,
                    details={"token_name": tok.name, "reason": violation},
                )
            else:
                known = list(tok.known_ips or [])
                if ip and ip not in known:
                    if known:
                        await selfmon.emit(
                            s,
                            tok.tenant_id,
                            "ingest_token.new_address",
                            f"Ingest token {tok.name} used from a new address {ip}",
                            actor=f"token:{tok.prefix}",
                            src_ip=ip,
                            severity=40,
                            details={"token_name": tok.name, "known_ips": known[-5:]},
                        )
                    tok.known_ips = [*known, ip][-MAX_KNOWN_IPS:]
                tok.last_used_at = datetime.now(UTC)
                tok.last_used_ip = ip
                tenant_id, actor = tok.tenant_id, f"token:{tok.prefix}"
        if violation:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "This ingest token is not allowed here")
        return tenant_id, actor
    principal = await get_principal(request)
    if not principal.can(Perm.INGEST_WRITE):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Missing permission: ingest:write")
    return principal.tenant_id, principal.email


def parse_body(raw: bytes, source: str) -> list[Any]:
    text = raw.decode("utf-8", errors="replace").strip()
    if not text:
        return []
    if source == "zeek" and text.startswith("#separator"):
        return list(zeek.iter_tsv(iter(text.splitlines())))
    if text[0] == "[":
        data = json.loads(text)
        if not isinstance(data, list):
            raise ValueError("expected a JSON array")
        return data
    if text[0] == "{":
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            pass  # not a single (possibly pretty-printed) object; fall through to NDJSON
        else:
            return [data]
    # NDJSON: every line is parsed on its own so one bad line is quarantined instead of
    # rejecting the whole batch.
    out = []
    for i, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            out.append({"__unparseable_line__": i, "content": line[:2000]})
    return out


@router.post("/{source}")
async def ingest_events(
    source: str, request: Request, log_type: str | None = Query(None, description="Zeek log type (conn, dns, http, …)")
) -> dict:
    s = get_settings()
    if source not in SOURCES:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Unknown source. Use one of: {', '.join(SOURCES)}")
    if source == "zeek" and log_type is not None and log_type not in zeek.SUPPORTED:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Unsupported Zeek log type")
    length = int(request.headers.get("content-length") or 0)
    if length > s.ingest_max_body_bytes:
        raise HTTPException(status.HTTP_413_CONTENT_TOO_LARGE, "Batch too large; split it into smaller requests")
    tenant_id, _actor = await _tenant_from_request(request, source)
    if not limiter.allow(f"ingest:{tenant_id}", 600):
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS, "Ingest rate limit exceeded", headers={"Retry-After": "5"}
        )
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        chunks.append(chunk)
        total += len(chunk)
        if total > s.ingest_max_body_bytes:
            raise HTTPException(status.HTTP_413_CONTENT_TOO_LARGE, "Batch too large")
    body = b"".join(chunks)
    try:
        records = parse_body(body, source)
    except (ValueError, json.JSONDecodeError) as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Body is not valid JSON/NDJSON: {e}") from e
    if len(records) > s.ingest_max_events_per_request:
        raise HTTPException(
            status.HTTP_413_CONTENT_TOO_LARGE, f"At most {s.ingest_max_events_per_request} events per request"
        )
    async with tenant_session(tenant_id) as db:
        res = await ingest(db, tenant_id, source, records, log_type)
    return {**res.as_dict(), "source": source}
