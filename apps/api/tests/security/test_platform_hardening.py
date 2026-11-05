"""Hardening of SentinelX itself: least-privilege DB role, tamper-evident audit chain, two-step
verification, step-up re-authentication, scoped ingest tokens and self-monitoring."""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from sqlalchemy import select, text, update
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

from sentinelx.config import get_settings
from sentinelx.persistence.db import system_session, tenant_session
from sentinelx.persistence.models import Alert, AuditLog, SecurityEvent, User
from sentinelx.persistence.models import Session as DbSession
from sentinelx.processing import process_events
from sentinelx.security import totp
from sentinelx.security.ratelimit import limiter
from sentinelx.services.audit_chain import verify_chain
from tests.helpers import PASSWORD, login, make_tenant, make_user, signed_in

SUSPICIOUS_PS_RULE = "ee71e69d-9a6d-45ba-b784-e94261bb0053"


@pytest.fixture(autouse=True)
def _reset() -> None:
    limiter.reset()


def _client(ip: str = "127.0.0.1") -> httpx.AsyncClient:
    from sentinelx.main import app

    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, client=(ip, 40000)),
        base_url="http://testserver",
        headers={"X-Requested-With": "SentinelX"},
    )


async def _platform_events(tid: uuid.UUID, action: str) -> list[SecurityEvent]:
    async with tenant_session(tid) as s:
        return list(
            (
                await s.execute(
                    select(SecurityEvent).where(
                        SecurityEvent.tenant_id == tid,
                        SecurityEvent.event_category == "sentinelx_platform",
                        SecurityEvent.event_action == action,
                    )
                )
            ).scalars()
        )


async def _detect(tid: uuid.UUID, events: list[SecurityEvent]) -> set[str]:
    async with tenant_session(tid) as s:
        await process_events(s, tid, [e.id for e in events])
    async with tenant_session(tid) as s:
        return set((await s.execute(select(Alert.title).where(Alert.tenant_id == tid))).scalars())


# --- least-privilege runtime role ---------------------------------------------------------------


@pytest.mark.skipif(not os.environ.get("DATABASE_OWNER_URL"), reason="single-role installation")
async def test_runtime_role_cannot_switch_off_security_controls() -> None:
    """A compromised application connection must not be able to disable triggers or row-level security."""
    for stmt in (
        "ALTER TABLE audit_logs DISABLE TRIGGER audit_logs_immutable",
        "ALTER TABLE incidents NO FORCE ROW LEVEL SECURITY",
        "DROP POLICY tenant_isolation ON security_events",
        "UPDATE audit_chain_head SET hash = 'x'",
        "TRUNCATE audit_logs",
    ):
        async with system_session() as s:
            with pytest.raises(Exception, match=r"must be owner|permission denied|append-only"):
                await s.execute(text(stmt))


# --- audit hash chain --------------------------------------------------------------------------------


async def test_audit_chain_is_intact_and_detects_tampering() -> None:
    async with system_session() as s:
        for i in range(3):
            s.add(AuditLog(id=uuid.uuid4(), actor="chain-test", action=f"test.chain.{i}", resource_type="test"))
    async with system_session() as s:
        report = await verify_chain(s)
    assert report.ok, report.problems
    assert report.rows_checked >= 3 and report.head_seq == report.rows_checked

    # Tamper as the schema owner inside a transaction that is rolled back afterwards.
    engine = create_async_engine(os.environ.get("DATABASE_OWNER_URL") or os.environ["DATABASE_URL"])
    try:
        async with engine.connect() as conn:
            trans = await conn.begin()
            session = AsyncSession(bind=conn)
            await session.execute(text("SELECT set_config('app.rls_bypass', 'on', true)"))
            await session.execute(text("ALTER TABLE audit_logs DISABLE TRIGGER audit_logs_immutable"))
            await session.execute(text("UPDATE audit_logs SET actor = 'mallory' WHERE action = 'test.chain.1'"))
            altered = await verify_chain(session)
            await session.execute(text("DELETE FROM audit_logs WHERE action = 'test.chain.0'"))
            removed = await verify_chain(session)
            await trans.rollback()
    finally:
        await engine.dispose()
    assert not altered.ok and {p["kind"] for p in altered.problems} == {"altered"}
    assert not removed.ok and "gap" in {p["kind"] for p in removed.problems}

    async with system_session() as s:
        assert (await verify_chain(s)).ok


# --- two-step verification ---------------------------------------------------------------------------


async def _enable_mfa(c: httpx.AsyncClient) -> tuple[str, list[str]]:
    r = await c.post("/api/v1/auth/mfa/setup")
    assert r.status_code == 200, r.text
    secret = r.json()["secret"]
    assert r.json()["otpauth_uri"].startswith("otpauth://totp/")
    r = await c.post("/api/v1/auth/mfa/enable", json={"code": "000000"})
    assert r.status_code == 400
    r = await c.post("/api/v1/auth/mfa/enable", json={"code": totp.code_at(secret, totp.current_step())})
    assert r.status_code == 200, r.text
    return secret, r.json()["recovery_codes"]


async def test_mfa_login_requires_second_factor_and_blocks_replay() -> None:
    tid = await make_tenant()
    email = await make_user(tid, "SECURITY_ANALYST")
    async with _client() as c:
        assert (await login(c, email)).status_code == 200
        secret, recovery = await _enable_mfa(c)
        assert len(recovery) == 8
        await c.post("/api/v1/auth/logout")

    async with _client() as c:
        r = await login(c, email)
        assert r.status_code == 200 and r.json() == {"ok": False, "mfa_required": True}
        assert (await c.get("/api/v1/auth/me")).status_code == 401  # password alone grants nothing
        assert (await c.get("/api/v1/incidents")).status_code == 401
        assert (await c.post("/api/v1/auth/mfa/verify", json={"code": "123456"})).status_code == 401
        # the code used at enrolment (same 30 s step) cannot be replayed
        replay = await c.post("/api/v1/auth/mfa/verify", json={"code": totp.code_at(secret, totp.current_step())})
        assert replay.status_code == 401
        r = await c.post("/api/v1/auth/mfa/verify", json={"code": recovery[0]})
        assert r.status_code == 200, r.text
        me = (await c.get("/api/v1/auth/me")).json()
        assert me["user"]["mfa_enabled"] is True and me["reauth_valid"] is True

    async with _client() as c:  # a recovery code works once only
        await login(c, email)
        assert (await c.post("/api/v1/auth/mfa/verify", json={"code": recovery[0]})).status_code == 401
        assert (await c.post("/api/v1/auth/mfa/verify", json={"code": recovery[1]})).status_code == 200

    failures = await _platform_events(tid, "auth.mfa")
    assert any(e.outcome == "failure" for e in failures)


async def test_wrong_second_factor_codes_lock_the_account() -> None:
    tid = await make_tenant()
    email = await make_user(tid, "VIEWER")
    async with _client() as c:
        await login(c, email)
        await _enable_mfa(c)
        await c.post("/api/v1/auth/logout")
    # Failures accumulate per account: after 5 a pending session is revoked on the next wrong code, and at
    # 8 the account locks - an attacker who knows the password gets only a handful of guesses.
    guesses = 0
    for _ in range(10):
        async with _client() as c:
            r = await login(c, email)
            if r.status_code == 401:
                assert "locked" in r.json()["detail"]
                break
            for _ in range(5):
                v = await c.post("/api/v1/auth/mfa/verify", json={"code": "000000"})
                limiter.reset()
                if "expired" in v.text:
                    break
                guesses += 1
    else:
        raise AssertionError("account never locked")
    assert guesses == get_settings().login_max_failures


async def test_mfa_enrolment_enforced_for_admins_when_required() -> None:
    s = get_settings()
    s.mfa_required_for_admins = True
    try:
        tid = await make_tenant()
        async with signed_in(tid, "TENANT_ADMIN") as c:
            r = await c.get("/api/v1/incidents")
            assert r.status_code == 403 and "mfa_enrollment_required" in r.json()["detail"]
            me = (await c.get("/api/v1/auth/me")).json()
            assert me["user"]["mfa_enrollment_required"] is True
            await _enable_mfa(c)
            assert (await c.get("/api/v1/incidents")).status_code == 200
        async with signed_in(tid, "SECURITY_ANALYST") as c:  # analysts are not forced
            assert (await c.get("/api/v1/incidents")).status_code == 200
    finally:
        s.mfa_required_for_admins = None


# --- step-up re-authentication -----------------------------------------------------------------------


async def test_sensitive_changes_need_a_recent_password_check() -> None:
    tid = await make_tenant()
    email = await make_user(tid, "TENANT_ADMIN")
    async with _client() as c:
        assert (await login(c, email)).status_code == 200
        async with system_session() as s:
            uid = (await s.execute(select(User.id).where(User.email == email))).scalar_one()
            await s.execute(
                update(DbSession)
                .where(DbSession.user_id == uid)
                .values(reauth_at=datetime.now(UTC) - timedelta(hours=2))
            )
        r = await c.patch(f"/api/v1/detections/{SUSPICIOUS_PS_RULE}", json={"enabled": False})
        assert r.status_code == 403 and r.headers.get("x-sentinelx-reauth") == "required"
        assert (await c.post("/api/v1/auth/reauth", json={"password": "wrong-password"})).status_code == 400
        assert (await c.post("/api/v1/auth/reauth", json={"password": PASSWORD})).status_code == 200
        r = await c.patch(f"/api/v1/detections/{SUSPICIOUS_PS_RULE}", json={"enabled": False})
        assert r.status_code == 200, r.text
    assert await _platform_events(tid, "auth.reauth")


# --- self-monitoring ---------------------------------------------------------------------------------


async def test_disabling_rules_is_itself_detected_and_tamper_rules_are_locked() -> None:
    from sentinelx.detection.engine import get_rules

    tid = await make_tenant()
    protected = next(r.uid for r in get_rules().ruleset.rules if r.title == "SentinelX Detection Rule Disabled")
    async with signed_in(tid, "TENANT_ADMIN") as c:
        r = await c.patch(f"/api/v1/detections/{protected}", json={"enabled": False})
        assert r.status_code == 400 and "cannot be turned off" in r.json()["detail"]
        r = await c.patch(f"/api/v1/detections/{SUSPICIOUS_PS_RULE}", json={"enabled": False})
        assert r.status_code == 200
    events = await _platform_events(tid, "rule.disable")
    assert len(events) == 1 and events[0].hostname == "sentinelx"
    titles = await _detect(tid, events)
    assert "SentinelX Detection Rule Disabled" in titles


async def test_brute_force_against_the_console_feeds_detection() -> None:
    tid = await make_tenant()
    email = await make_user(tid, "VIEWER")
    async with _client() as c:
        for _ in range(3):
            assert (await login(c, email, "not-the-password")).status_code == 401
    failures = await _platform_events(tid, "auth.login")
    assert len(failures) == 3 and all(e.outcome == "failure" and e.username == email for e in failures)


# --- ingest token scope ------------------------------------------------------------------------------


async def test_ingest_tokens_are_limited_to_their_sources_and_networks() -> None:
    tid = await make_tenant()
    async with signed_in(tid, "TENANT_ADMIN") as c:
        r = await c.post("/api/v1/admin/ingest-tokens", json={"name": "bad", "allowed_cidrs": ["not-a-net"]})
        assert r.status_code == 422
        r = await c.post(
            "/api/v1/admin/ingest-tokens",
            json={"name": "suricata-sensor", "allowed_sources": ["suricata"], "allowed_cidrs": ["10.9.9.0/24"]},
        )
        scoped = r.json()["token"]
        r = await c.post(
            "/api/v1/admin/ingest-tokens", json={"name": "lab", "allowed_sources": ["suricata"], "allowed_cidrs": []}
        )
        lab = r.json()["token"]
    body = (
        '{"timestamp":"2026-11-05T10:00:00+0000","event_type":"dns","src_ip":"10.9.9.4","dns":{"rrname":"a.example"}}'
    )
    async with _client("10.9.9.7") as c:
        auth = {"Authorization": f"Bearer {scoped}"}
        assert (await c.post("/api/v1/ingest/wazuh", content=body, headers=auth)).status_code == 403
        assert (await c.post("/api/v1/ingest/suricata", content=body, headers=auth)).status_code == 200
    async with _client("192.0.2.10") as c:
        r = await c.post("/api/v1/ingest/suricata", content=body, headers={"Authorization": f"Bearer {scoped}"})
        assert r.status_code == 403
    denied = await _platform_events(tid, "ingest_token.denied")
    assert len(denied) == 2
    assert "SentinelX Ingest Token Used Outside Its Scope" in await _detect(tid, denied)

    async with _client("10.1.1.1") as c:
        assert (
            await c.post("/api/v1/ingest/suricata", content=body, headers={"Authorization": f"Bearer {lab}"})
        ).status_code == 200
    async with _client("10.1.1.99") as c:
        assert (
            await c.post("/api/v1/ingest/suricata", content=body, headers={"Authorization": f"Bearer {lab}"})
        ).status_code == 200
    assert len(await _platform_events(tid, "ingest_token.new_address")) == 1


async def test_canarytokens_webhook_raises_a_critical_alert() -> None:
    tid = await make_tenant()
    async with signed_in(tid, "TENANT_ADMIN") as c:
        r = await c.post("/api/v1/admin/ingest-tokens", json={"name": "canary", "allowed_sources": ["canarytokens"]})
        token = r.json()["token"]
    payload = {
        "manage_url": "https://canary.example/manage",
        "memo": "Decoy AWS key in the deploy wiki",
        "channel": "HTTP",
        "src_ip": "198.51.100.77",
        "time": "2026-11-05 09:30:00 (UTC)",
        "token": "abc123canary",
    }
    async with _client() as c:
        r = await c.post(f"/api/v1/ingest/canarytokens?token={token}", json=payload)
        assert r.status_code == 200 and r.json()["accepted"] == 1
        # the same token cannot push other telemetry
        assert (await c.post(f"/api/v1/ingest/wazuh?token={token}", json={})).status_code in (401, 403)
    async with tenant_session(tid) as s:
        ev = (await s.execute(select(SecurityEvent).where(SecurityEvent.tenant_id == tid))).scalars().all()
    canary = [e for e in ev if e.source_type == "canarytokens"]
    titles = await _detect(tid, canary)
    assert any(t.startswith("Canarytoken triggered") for t in titles)
