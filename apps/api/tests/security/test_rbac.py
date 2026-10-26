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
from tests.helpers import client, login, make_tenant, make_user, signed_in

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


async def _user_id(email: str) -> uuid.UUID:
    async with system_session() as s:
        return (await s.execute(select(User.id).where(User.email == email))).scalar_one()


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
    ("POST", "/api/v1/admin/users/{viewer}/unlock", None, Perm.ADMIN_MANAGE),
    ("POST", "/api/v1/admin/users/{viewer}/reset-password", {"password": "Temp-Password-2026"}, Perm.ADMIN_MANAGE),
    ("GET", "/api/v1/auth/sessions", None, None),
    ("POST", "/api/v1/auth/sessions/revoke-others", None, None),
]


@pytest.mark.parametrize("role", ROLES)
async def test_permission_matrix(role: str) -> None:
    """Every role gets exactly the access its permission set grants - no more, no less."""
    tid = await make_tenant(f"M{role}")
    inc = await _incident(tid)
    viewer = await _user_id(await make_user(tid, "VIEWER"))
    granted = ROLE_PERMISSIONS[Role(role)]
    async with signed_in(tid, role) as c:
        for i, (method, path, body, perm) in enumerate(MATRIX):
            url = path.replace("{inc}", str(inc)).replace("{viewer}", str(viewer))
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
        assert r.status_code == 422  # a viewer cannot work the incident, so cannot own it
        worker_id = await _user_id(await make_user(a, "IT_OPERATOR"))
        r = await c.patch(f"/api/v1/incidents/{inc}", json={"assigned_to": str(worker_id)})
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


async def test_assignees_match_who_may_be_assigned() -> None:
    """The picker and the server-side check agree: everyone listed can be assigned, viewers are not listed."""
    tid = await make_tenant("Pick")
    inc = await _incident(tid)
    await make_user(tid, "VIEWER")
    async with signed_in(tid, "SECURITY_ANALYST") as c:
        people = (await c.get("/api/v1/incidents/assignees")).json()
        assert people and all(p["role"] != "VIEWER" for p in people)
        for p in people:
            assert (await c.patch(f"/api/v1/incidents/{inc}", json={"assigned_to": p["id"]})).status_code == 200


async def test_assigned_to_me_filter() -> None:
    tid = await make_tenant("Mine")
    mine, other = await _incident(tid, 1), await _incident(tid, 2)
    async with signed_in(tid, "SECURITY_ANALYST") as c:
        me = (await c.get("/api/v1/auth/me")).json()["user"]["id"]
        assert (await c.patch(f"/api/v1/incidents/{mine}", json={"assigned_to": me})).status_code == 200
        ids = {i["id"] for i in (await c.get("/api/v1/incidents", params={"assignee": "me"})).json()["items"]}
        assert ids == {str(mine)}
        ids = {i["id"] for i in (await c.get("/api/v1/incidents", params={"assignee": "unassigned"})).json()["items"]}
        assert ids == {str(other)}
        assert (await c.get("/api/v1/incidents", params={"assignee": "nobody"})).status_code == 422


async def test_only_tasks_can_be_toggled() -> None:
    """A watchlist entry is a record of something done; it must not be flipped back to an open to-do."""
    tid = await make_tenant("Tasks")
    inc = await _incident(tid)
    async with signed_in(tid, "SECURITY_ANALYST") as c:
        base = f"/api/v1/incidents/{inc}/responses"
        task = (await c.post(base, json={"kind": "task", "title": "Reimage host"})).json()
        watch = (
            await c.post(
                base, json={"kind": "watchlist_ioc", "title": "Watch C2", "payload": {"value": "198.51.100.9"}}
            )
        ).json()
        assert (await c.patch(f"{base}/{task['id']}")).json()["status"] == "completed"
        assert (await c.patch(f"{base}/{watch['id']}")).status_code == 409


async def test_admin_password_reset_and_unlock() -> None:
    tid = await make_tenant("Reset")
    email = await make_user(tid, "SECURITY_ANALYST")
    uid = await _user_id(email)
    async with client() as victim:
        assert (await login(victim, email)).status_code == 200
        async with system_session() as s:
            u = await s.get(User, uid)
            assert u is not None
            u.locked_until, u.failed_logins = datetime.now(UTC).replace(year=2099), 9
        async with signed_in(tid, "TENANT_ADMIN") as admin:
            r = await admin.post(f"/api/v1/admin/users/{uid}/unlock")
            assert r.status_code == 200 and r.json()["locked_until"] is None
            r = await admin.post(f"/api/v1/admin/users/{uid}/reset-password", json={"password": "short"})
            assert r.status_code == 422
            r = await admin.post(f"/api/v1/admin/users/{uid}/reset-password", json={"password": "Brand-New-Pass-77"})
            assert r.status_code == 200
            me = (await admin.get("/api/v1/auth/me")).json()["user"]["id"]
            r = await admin.post(f"/api/v1/admin/users/{me}/reset-password", json={"password": "Brand-New-Pass-77"})
            assert r.status_code == 400  # own password goes through /auth/password (needs the current one)
        # the reset signs the user out everywhere, and only the new password works
        assert (await victim.get("/api/v1/auth/me")).status_code == 401
        assert (await login(victim, email)).status_code == 401
        assert (await login(victim, email, "Brand-New-Pass-77")).status_code == 200
        logs = []
        async with tenant_session(tid) as s:
            from sentinelx.persistence.models import AuditLog

            logs = list((await s.execute(select(AuditLog.action).where(AuditLog.tenant_id == tid))).scalars())
        assert "user.password_reset" in logs and "user.unlock" in logs


async def test_admin_cannot_reset_peers_or_other_orgs() -> None:
    a, b = await make_tenant("RA"), await make_tenant("RB")
    peer = await _user_id(await make_user(a, "TENANT_ADMIN"))
    outsider = await _user_id(await make_user(b, "VIEWER"))
    body = {"password": "Brand-New-Pass-77"}
    async with signed_in(a, "TENANT_ADMIN") as c:
        assert (await c.post(f"/api/v1/admin/users/{peer}/reset-password", json=body)).status_code == 403
        assert (await c.post(f"/api/v1/admin/users/{peer}/unlock")).status_code == 403
        assert (await c.post(f"/api/v1/admin/users/{outsider}/reset-password", json=body)).status_code == 404
    async with signed_in(a, "SUPER_ADMIN") as c:
        assert (await c.post(f"/api/v1/admin/users/{peer}/reset-password", json=body)).status_code == 200


async def test_sessions_are_self_service_and_scoped_to_the_user() -> None:
    tid = await make_tenant("Sess")
    email = await make_user(tid, "VIEWER")
    async with client() as laptop, client() as phone:
        assert (await login(laptop, email)).status_code == 200
        assert (await login(phone, email)).status_code == 200
        sessions = (await laptop.get("/api/v1/auth/sessions")).json()
        assert len(sessions) == 2 and sum(s["current"] for s in sessions) == 1
        current = next(s["id"] for s in sessions if s["current"])
        other = next(s["id"] for s in sessions if not s["current"])
        # someone else cannot see or end these sessions
        async with signed_in(tid, "TENANT_ADMIN") as admin:
            assert other not in {s["id"] for s in (await admin.get("/api/v1/auth/sessions")).json()}
            assert (await admin.delete(f"/api/v1/auth/sessions/{other}")).status_code == 404
        assert (await phone.get("/api/v1/auth/me")).status_code == 200
        assert (await laptop.delete(f"/api/v1/auth/sessions/{current}")).status_code == 400
        assert (await laptop.delete(f"/api/v1/auth/sessions/{other}")).status_code == 204
        assert (await phone.get("/api/v1/auth/me")).status_code == 401
        assert (await login(phone, email)).status_code == 200
        assert (await laptop.post("/api/v1/auth/sessions/revoke-others")).json()["revoked"] == 1
        assert (await phone.get("/api/v1/auth/me")).status_code == 401
        assert (await laptop.get("/api/v1/auth/me")).status_code == 200


async def test_me_explains_access_in_plain_language() -> None:
    tid = await make_tenant("Explain")
    async with signed_in(tid, "IT_OPERATOR") as c:
        access = {a["permission"]: a for a in (await c.get("/api/v1/auth/me")).json()["access"]}
        assert set(access) == {str(p) for p in Perm}
        assert access["incident:update"]["granted"] and not access["incident:close"]["granted"]
        assert all(a["description"] for a in access.values())


async def test_service_addresses_are_hidden_from_non_admins(monkeypatch: pytest.MonkeyPatch) -> None:
    from sentinelx.config import get_settings

    monkeypatch.setattr(get_settings(), "misp_url", "https://misp.internal.example.test")
    tid = await make_tenant("Addr")
    async with signed_in(tid, "VIEWER") as c:
        text = (await c.get("/api/v1/admin/integrations")).text + (await c.get("/api/v1/ai/status")).text
        assert "misp.internal" not in text and "127.0.0.1:9" not in text
    async with signed_in(tid, "TENANT_ADMIN") as c:
        assert "misp.internal" in (await c.get("/api/v1/admin/integrations")).text
