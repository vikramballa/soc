"""Authentication, authorization, tenant isolation and web security tests."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select, text

from sentinelx.persistence.db import system_session, tenant_session
from sentinelx.persistence.models import AuditLog, Incident
from sentinelx.security.ratelimit import limiter
from tests.helpers import PASSWORD, client, login, make_tenant, make_user, signed_in


@pytest.fixture(autouse=True)
def _reset_limits() -> None:
    limiter.reset()


async def _incident(tenant_id: uuid.UUID, title: str = "Test incident") -> uuid.UUID:
    from datetime import UTC, datetime

    iid = uuid.uuid4()
    now = datetime.now(UTC)
    async with tenant_session(tenant_id) as s:
        s.add(
            Incident(
                id=iid,
                tenant_id=tenant_id,
                number=1,
                title=title,
                promoted=True,
                first_event_at=now,
                last_event_at=now,
                status="new",
                severity="high",
                risk_score=80,
                risk_breakdown=[],
                confidence_factors=[],
                mitre_techniques=[],
                tactics=[],
                source_types=[],
            )
        )
    return iid


async def test_unauthenticated_requests_are_rejected() -> None:
    async with client() as c:
        for path in ("/api/v1/incidents", "/api/v1/dashboard/summary", "/api/v1/events", "/api/v1/admin/users"):
            assert (await c.get(path)).status_code == 401


async def test_login_logout_and_session_revocation() -> None:
    tid = await make_tenant()
    email = await make_user(tid, "SECURITY_ANALYST")
    async with client() as c:
        r = await login(c, email)
        assert r.status_code == 200
        cookie = r.headers["set-cookie"].lower()
        assert "httponly" in cookie and "samesite=lax" in cookie
        me = (await c.get("/api/v1/auth/me")).json()
        assert me["user"]["role"] == "SECURITY_ANALYST" and "ai:investigate" in me["permissions"]
        assert (await c.post("/api/v1/auth/logout")).status_code == 200
        assert (await c.get("/api/v1/auth/me")).status_code == 401


async def test_wrong_password_is_generic_and_audited() -> None:
    tid = await make_tenant()
    email = await make_user(tid, "VIEWER")
    async with client() as c:
        r1 = await login(c, email, "wrong-password-123")
        r2 = await login(c, "nobody@example.test", "wrong-password-123")
    assert r1.status_code == r2.status_code == 401
    assert r1.json()["detail"] == r2.json()["detail"]  # no account enumeration
    async with system_session() as s:
        rows = (
            (await s.execute(select(AuditLog).where(AuditLog.actor == email, AuditLog.result == "failure")))
            .scalars()
            .all()
        )
    assert rows


async def test_account_lockout_after_repeated_failures() -> None:
    tid = await make_tenant()
    email = await make_user(tid, "VIEWER")
    async with client() as c:
        for _ in range(8):
            await login(c, email, "nope-nope-nope-1")
        r = await login(c, email, PASSWORD)  # correct password, but locked
    assert r.status_code == 401
    assert "locked" in r.json()["detail"].lower()


async def test_login_rate_limit() -> None:
    import os

    from sentinelx.config import get_settings

    os.environ["RATE_LIMIT_LOGIN_PER_MINUTE"] = "5"
    get_settings.cache_clear()
    try:
        async with client() as c:
            codes = [(await login(c, "rate@example.test", "x-password-123")).status_code for _ in range(7)]
        assert 429 in codes
    finally:
        os.environ["RATE_LIMIT_LOGIN_PER_MINUTE"] = "1000"
        get_settings.cache_clear()


async def test_viewer_gets_403_on_write_endpoints() -> None:
    tid = await make_tenant()
    iid = await _incident(tid)
    async with signed_in(tid, "VIEWER") as c:
        assert (await c.get(f"/api/v1/incidents/{iid}")).status_code == 200
        assert (await c.patch(f"/api/v1/incidents/{iid}", json={"status": "triaged"})).status_code == 403
        assert (await c.post(f"/api/v1/incidents/{iid}/investigate")).status_code == 403
        assert (await c.get("/api/v1/admin/users")).status_code == 403
    async with system_session() as s:
        denied = (
            (
                await s.execute(
                    select(AuditLog).where(AuditLog.tenant_id == tid, AuditLog.action == "authorization.denied")
                )
            )
            .scalars()
            .all()
        )
    assert len(denied) >= 3


async def test_cross_tenant_access_is_rejected() -> None:
    a, b = await make_tenant("A"), await make_tenant("B")
    inc_b = await _incident(b, "Tenant B secret incident")
    async with signed_in(a, "TENANT_ADMIN") as c:
        assert (await c.get(f"/api/v1/incidents/{inc_b}")).status_code == 404
        listing = (await c.get("/api/v1/incidents")).json()
        assert all(i["id"] != str(inc_b) for i in listing["items"])
        # a tenant admin cannot switch tenants via the header
        r = await c.get("/api/v1/incidents", headers={"X-SentinelX-Tenant": str(b)})
        assert r.status_code == 403


async def test_super_admin_can_switch_tenants_explicitly() -> None:
    a, b = await make_tenant("A"), await make_tenant("B")
    inc_b = await _incident(b)
    async with signed_in(a, "SUPER_ADMIN") as c:
        assert (await c.get(f"/api/v1/incidents/{inc_b}")).status_code == 404
        r = await c.get(f"/api/v1/incidents/{inc_b}", headers={"X-SentinelX-Tenant": str(b)})
        assert r.status_code == 200
        r = await c.get("/api/v1/incidents", headers={"X-SentinelX-Tenant": str(uuid.uuid4())})
        assert r.status_code == 404


async def test_row_level_security_blocks_unfiltered_queries() -> None:
    """Defense in depth: even a query WITHOUT a tenant filter only sees the session tenant's rows."""
    a, b = await make_tenant("A"), await make_tenant("B")
    await _incident(a, "visible")
    await _incident(b, "hidden")
    async with tenant_session(a) as s:
        titles = set((await s.execute(text("SELECT title FROM incidents"))).scalars().all())
    assert "visible" in titles and "hidden" not in titles
    async with tenant_session(a) as s:
        with pytest.raises(Exception, match="row-level security"):
            await s.execute(
                text(
                    "INSERT INTO incidents (id, tenant_id, number, title, description, category, "
                    "severity, risk_score, risk_breakdown, confidence, confidence_factors, status, "
                    "promoted, first_event_at, last_event_at, mitre_techniques, tactics, alert_count, "
                    "event_count, source_types) VALUES (gen_random_uuid(), :b, 9, 'x', '', 'x', 'low', "
                    "0, '[]', 0, '[]', 'new', false, now(), now(), '{}', '{}', 0, 0, '{}')"
                ),
                {"b": b},
            )


async def test_audit_log_is_append_only() -> None:
    async with system_session() as s:
        s.add(AuditLog(id=uuid.uuid4(), actor="test", action="test.append", resource_type="test"))
    async with system_session() as s:
        with pytest.raises(Exception, match="append-only"):
            await s.execute(text("UPDATE audit_logs SET actor = 'tampered' WHERE action = 'test.append'"))
    async with system_session() as s:
        with pytest.raises(Exception, match="append-only"):
            await s.execute(text("DELETE FROM audit_logs WHERE action = 'test.append'"))


async def test_csrf_header_required_for_cookie_writes() -> None:
    tid = await make_tenant()
    iid = await _incident(tid)
    async with signed_in(tid, "SECURITY_ANALYST") as c:
        r = await c.patch(f"/api/v1/incidents/{iid}", json={"status": "triaged"}, headers={"X-Requested-With": ""})
        assert r.status_code == 403
        r = await c.patch(f"/api/v1/incidents/{iid}", json={"status": "triaged"})
        assert r.status_code == 200


async def test_security_headers_present() -> None:
    async with client() as c:
        r = await c.get("/live")
    for h in ("x-content-type-options", "x-frame-options", "content-security-policy", "x-request-id"):
        assert h in r.headers


async def test_sql_injection_payloads_are_inert() -> None:
    tid = await make_tenant()
    await _incident(tid, "normal")
    async with signed_in(tid, "SECURITY_ANALYST") as c:
        for payload in ("' OR 1=1 --", "x'; DROP TABLE incidents; --", "%' UNION SELECT password_hash FROM users --"):
            r = await c.get("/api/v1/incidents", params={"q": payload})
            assert r.status_code == 200
            assert r.json()["total"] == 0
            r = await c.get("/api/v1/events", params={"q": payload, "host": payload})
            assert r.status_code == 200
    async with tenant_session(tid) as s:
        assert (await s.execute(text("SELECT count(*) FROM incidents"))).scalar_one() == 1


async def test_malformed_and_oversized_payloads() -> None:
    tid = await make_tenant()
    async with signed_in(tid, "TENANT_ADMIN") as c:
        r = await c.post("/api/v1/ingest/suricata", content=b"{not json", headers={"content-type": "application/json"})
        assert r.status_code == 200 and r.json()["quarantined"] == 1
        r = await c.post("/api/v1/ingest/suricata", content=b"[1,2", headers={"content-type": "application/json"})
        assert r.status_code == 400
        big = b"[" + b",".join([b'{"a":1}'] * 10) + b"]"
        r = await c.post("/api/v1/ingest/suricata", content=big, headers={"content-length": str(50 * 1024 * 1024)})
        assert r.status_code == 413
        r = await c.post("/api/v1/incidents", json={"title": "x" * 5000})
        assert r.status_code == 422
        r = await c.post("/api/v1/ingest/unknown-source", json=[])
        assert r.status_code == 404


async def test_ingest_token_scoped_to_tenant() -> None:
    tid = await make_tenant()
    async with signed_in(tid, "TENANT_ADMIN") as c:
        tok = (await c.post("/api/v1/admin/ingest-tokens", json={"name": "fluent-bit"})).json()["token"]
    async with client() as anon:
        rec = {
            "timestamp": "2026-10-06T10:00:00.000000+0000",
            "flow_id": 1,
            "event_type": "dns",
            "src_ip": "10.0.0.5",
            "dest_ip": "10.0.0.2",
            "dns": {"type": "query", "rrname": "example.com", "rrtype": "A"},
        }
        r = await anon.post("/api/v1/ingest/suricata", json=[rec], headers={"Authorization": f"Bearer {tok}"})
        assert r.status_code == 200 and r.json()["accepted"] == 1
        r = await anon.post("/api/v1/ingest/suricata", json=[rec], headers={"Authorization": f"Bearer {tok}"})
        assert r.json()["duplicates"] == 1  # idempotent
        r = await anon.post("/api/v1/ingest/suricata", json=[rec], headers={"Authorization": "Bearer sxi_forged"})
        assert r.status_code == 401


async def test_role_escalation_is_prevented() -> None:
    tid = await make_tenant()
    async with signed_in(tid, "TENANT_ADMIN") as c:
        r = await c.post(
            "/api/v1/admin/users",
            json={
                "email": "boss@example.test",
                "display_name": "Boss",
                "role": "SUPER_ADMIN",
                "password": "Strong-Pass-123",
            },
        )
        assert r.status_code == 403
        r = await c.post(
            "/api/v1/admin/users",
            json={"email": "weak@example.test", "display_name": "Weak", "role": "VIEWER", "password": "short"},
        )
        assert r.status_code == 422


async def test_spa_path_traversal_is_blocked(tmp_path) -> None:
    async with client() as c:
        for p in ("/../../etc/passwd", "/..%2f..%2fetc/passwd", "/assets/../../../apps/api/alembic.ini"):
            r = await c.get(p)
            assert "root:" not in r.text and "script_location" not in r.text


async def test_health_endpoints() -> None:
    async with client() as c:
        assert (await c.get("/live")).status_code == 200
        assert (await c.get("/ready")).json()["database"] is True
        h = await c.get("/health")
        assert h.status_code == 200
        body = h.json()
        assert body["application"] == "running" and "core_detection" in body and "ai_analyst" in body
        assert (await c.get("/metrics")).status_code == 200
        assert (await c.get("/api/v1/does-not-exist")).status_code == 404
