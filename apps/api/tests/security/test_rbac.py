"""Role-based access control: full role × endpoint matrix plus regression tests for RBAC flaws."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import select

from sentinelx.persistence.db import system_session, tenant_session
from sentinelx.persistence.models import Alert, Incident, User
from sentinelx.security.ratelimit import limiter
from sentinelx.security.rbac import ROLE_PERMISSIONS, Perm, Role
from tests.helpers import make_tenant, make_user, signed_in

ROLES = ["VIEWER", "IT_OPERATOR", "SECURITY_ANALYST", "TENANT_ADMIN", "SUPER_ADMIN"]


@pytest.fixture(autouse=True)
def _reset() -> None:
    limiter.reset()


async def _incident(tid: uuid.UUID, number: int = 1) -> uuid.UUID:
    iid = uuid.uuid4()
    now = datetime.now(UTC)
    async with tenant_session(tid) as s:
        s.add(
            Incident(
                id=iid,
                tenant_id=tid,
                number=number,
                title="t",
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


async def _alert(tid: uuid.UUID, incident_id: uuid.UUID | None = None) -> uuid.UUID:
    aid = uuid.uuid4()
    now = datetime.now(UTC)
    async with tenant_session(tid) as s:
        s.add(
            Alert(
                id=aid,
                tenant_id=tid,
                rule_uid="r",
                title="a",
                source="sigma",
                severity=50,
                level="medium",
                dedup_key=str(aid),
                first_event_at=now,
                last_event_at=now,
                incident_id=incident_id,
                hostname="h1",
                details={},
                mitre_techniques=[],
                source_types=[],
            )
        )
    return aid


# (method, path template, json body, required permission) - ``{inc}`` is replaced with a real incident id.
MATRIX: list[tuple[str, str, Any, Perm | None]] = [
    ("GET", "/api/v1/incidents", None, Perm.INCIDENT_READ),
    ("GET", "/api/v1/incidents/{inc}", None, Perm.INCIDENT_READ),
    ("GET", "/api/v1/dashboard/summary", None, Perm.INCIDENT_READ),
    ("GET", "/api/v1/alerts", None, Perm.ALERT_READ),
    ("GET", "/api/v1/events", None, Perm.EVENT_READ),
    ("GET", "/api/v1/assets", None, Perm.ASSET_READ),
    ("GET", "/api/v1/detections", None, Perm.RULE_READ),
    ("GET", "/api/v1/threat-intel/indicators", None, Perm.THREATINTEL_READ),
    ("PATCH", "/api/v1/incidents/{inc}", {"status": "triaged"}, Perm.INCIDENT_UPDATE),
    ("POST", "/api/v1/incidents/{inc}/notes", {"body": "x"}, Perm.INCIDENT_UPDATE),
    ("POST", "/api/v1/incidents", {"title": "manual"}, Perm.INCIDENT_CREATE),
    ("POST", "/api/v1/incidents/{inc}/responses", {"kind": "task", "title": "do it"}, Perm.RESPONSE_EXECUTE),
    ("GET", "/api/v1/incidents/{inc}/report", None, Perm.REPORT_GENERATE),
    ("POST", "/api/v1/threat-intel/indicators", {"value": "198.51.100.200"}, Perm.THREATINTEL_MANAGE),
    ("PATCH", "/api/v1/detections/ee71e69d-9a6d-45ba-b784-e94261bb0053", {"enabled": True}, Perm.RULE_MANAGE),
    ("GET", "/api/v1/admin/users", None, Perm.ADMIN_MANAGE),
    ("GET", "/api/v1/admin/settings", None, Perm.ADMIN_MANAGE),
    ("GET", "/api/v1/admin/audit-logs", None, Perm.AUDIT_READ),
    ("POST", "/api/v1/detections/sync", None, Perm.PLATFORM_MANAGE),
    ("POST", "/api/v1/admin/tenants", {"name": "X Org", "slug": "x-org-{n}"}, Perm.PLATFORM_MANAGE),
]


@pytest.mark.parametrize("role", ROLES)
async def test_permission_matrix(role: str) -> None:
    """Every role gets exactly the access its permission set grants - no more, no less."""
    tid = await make_tenant(f"M{role}")
    inc = await _incident(tid)
    granted = ROLE_PERMISSIONS[Role(role)]
    async with signed_in(tid, role) as c:
        for i, (method, path, body, perm) in enumerate(MATRIX):
            url = path.replace("{inc}", str(inc))
            if isinstance(body, dict):
                body = {
                    k: (v.replace("{n}", uuid.uuid4().hex[:6]) if isinstance(v, str) else v) for k, v in body.items()
                }
            r = await c.request(method, url, json=body)
            allowed = perm is None or perm in granted
            if allowed:
                assert r.status_code < 400 or r.status_code == 422, (role, i, method, url, r.status_code, r.text)
            else:
                assert r.status_code == 403, (role, i, method, url, r.status_code, r.text)


async def test_ingest_requires_ingest_permission_for_sessions() -> None:
    tid = await make_tenant("Ingest")
    for role, ok in (("SECURITY_ANALYST", False), ("TENANT_ADMIN", True)):
        async with signed_in(tid, role) as c:
            r = await c.post("/api/v1/ingest/sentinelx", json=[])
            assert (r.status_code == 200) is ok, (role, r.status_code)


async def test_it_operator_cannot_record_verdicts_or_merge() -> None:
    """Dispositions (true/false positive) and merges are analyst judgements, not operator actions."""
    tid = await make_tenant("Op")
    a, b = await _incident(tid, 1), await _incident(tid, 2)
    async with signed_in(tid, "IT_OPERATOR") as c:
        assert (await c.patch(f"/api/v1/incidents/{a}", json={"status": "contained"})).status_code == 200
        assert (await c.patch(f"/api/v1/incidents/{a}", json={"disposition": "false_positive"})).status_code == 403
        assert (await c.patch(f"/api/v1/incidents/{a}", json={"status": "resolved"})).status_code == 403
        assert (await c.post(f"/api/v1/incidents/{a}/merge/{b}")).status_code == 403
    async with signed_in(tid, "SECURITY_ANALYST") as c:
        assert (await c.patch(f"/api/v1/incidents/{a}", json={"disposition": "false_positive"})).status_code == 200
        assert (await c.post(f"/api/v1/incidents/{a}/merge/{b}")).status_code == 200


async def test_assignee_must_belong_to_the_organization() -> None:
    a, b = await make_tenant("A"), await make_tenant("B")
    inc = await _incident(a)
    outsider = await make_user(b, "SECURITY_ANALYST")
    async with system_session() as s:
        outsider_id = (await s.execute(select(User.id).where(User.email == outsider))).scalar_one()
        member = await make_user(a, "VIEWER")
        member_id = (await s.execute(select(User.id).where(User.email == member))).scalar_one()
    async with signed_in(a, "SECURITY_ANALYST") as c:
        r = await c.patch(f"/api/v1/incidents/{inc}", json={"assigned_to": str(outsider_id)})
        assert r.status_code == 422
        r = await c.patch(f"/api/v1/incidents/{inc}", json={"assigned_to": str(uuid.uuid4())})
        assert r.status_code == 422
        r = await c.patch(f"/api/v1/incidents/{inc}", json={"assigned_to": str(member_id)})
        assert r.status_code == 200
        assert (await c.get("/api/v1/incidents/assignees")).status_code == 200


async def test_admin_cannot_modify_peers_or_higher_roles() -> None:
    tid = await make_tenant("Peers")
    other_admin = await make_user(tid, "TENANT_ADMIN")
    async with system_session() as s:
        other_id = (await s.execute(select(User.id).where(User.email == other_admin))).scalar_one()
    async with signed_in(tid, "TENANT_ADMIN") as c:
        r = await c.patch(f"/api/v1/admin/users/{other_id}", json={"is_active": False})
        assert r.status_code == 403  # an admin cannot lock out another admin of the same level
        r = await c.post(
            "/api/v1/admin/users",
            json={
                "email": "an@example.test",
                "display_name": "A",
                "role": "TENANT_ADMIN",
                "password": "Strong-Pass-123",
            },
        )
        assert r.status_code == 403  # admins create analysts/operators/viewers; admins are created by super admin
        r = await c.post(
            "/api/v1/admin/users",
            json={
                "email": "an2@example.test",
                "display_name": "A",
                "role": "SECURITY_ANALYST",
                "password": "Strong-Pass-123",
            },
        )
        assert r.status_code == 201
    async with signed_in(tid, "SUPER_ADMIN") as c:
        r = await c.patch(f"/api/v1/admin/users/{other_id}", json={"role": "SECURITY_ANALYST"})
        assert r.status_code == 200


async def test_role_change_and_deactivation_take_effect_immediately() -> None:
    tid = await make_tenant("Live")
    async with signed_in(tid, "SECURITY_ANALYST") as c:
        me = (await c.get("/api/v1/auth/me")).json()["user"]
        async with system_session() as s:
            user = await s.get(User, uuid.UUID(me["id"]))
            assert user is not None
            user.role = "VIEWER"
        assert (await c.post("/api/v1/incidents", json={"title": "manual"})).status_code == 403
        async with system_session() as s:
            user = await s.get(User, uuid.UUID(me["id"]))
            assert user is not None
            user.is_active = False
        assert (await c.get("/api/v1/incidents")).status_code == 401


async def test_manual_incident_recomputes_the_incident_alerts_came_from() -> None:
    tid = await make_tenant("Move")
    old = await _incident(tid, 1)
    aid = await _alert(tid, old)
    async with signed_in(tid, "SECURITY_ANALYST") as c:
        r = await c.post("/api/v1/incidents", json={"title": "Split out", "alert_ids": [str(aid)]})
        assert r.status_code == 201
    async with tenant_session(tid) as s:
        old_inc = await s.get(Incident, old)
        assert old_inc is not None and old_inc.alert_count == 0


async def test_platform_audit_scope_is_super_admin_only() -> None:
    tid = await make_tenant("Audit")
    async with signed_in(tid, "TENANT_ADMIN") as c:
        await c.post("/api/v1/auth/login", json={"email": "ghost@example.test", "password": "nope-nope-123"})
        assert (await c.get("/api/v1/admin/audit-logs", params={"scope": "platform"})).status_code == 403
    async with signed_in(tid, "SUPER_ADMIN") as c:
        r = await c.get("/api/v1/admin/audit-logs", params={"scope": "platform", "actor": "ghost@"})
        assert r.status_code == 200 and r.json()["total"] >= 1
