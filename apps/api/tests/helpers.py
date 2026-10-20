"""Shared test helpers: users per role, authenticated API clients."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import httpx

from sentinelx.persistence.db import system_session
from sentinelx.persistence.models import Tenant, User
from sentinelx.security.passwords import hash_password

PASSWORD = "Correct-Horse-42"

# Synthetic sample telemetry in native Wazuh / Suricata / Zeek formats
FIXTURES = Path(__file__).parent / "fixtures"


async def make_tenant(name: str = "Org") -> uuid.UUID:
    tid = uuid.uuid4()
    async with system_session() as s:
        s.add(Tenant(id=tid, slug=f"{name.lower()}-{tid.hex[:8]}", name=name, settings={}))
    return tid


async def make_user(tenant_id: uuid.UUID, role: str) -> str:
    email = f"{role.lower()}-{uuid.uuid4().hex[:8]}@example.test"
    async with system_session() as s:
        s.add(
            User(
                id=uuid.uuid4(),
                tenant_id=tenant_id,
                email=email,
                display_name=role.title(),
                role=role,
                password_hash=hash_password(PASSWORD),
            )
        )
    return email


def client() -> httpx.AsyncClient:
    from sentinelx.main import app

    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver", headers={"X-Requested-With": "SentinelX"}
    )


async def login(c: httpx.AsyncClient, email: str, password: str = PASSWORD) -> httpx.Response:
    return await c.post("/api/v1/auth/login", json={"email": email, "password": password})


@asynccontextmanager
async def signed_in(tenant_id: uuid.UUID, role: str) -> AsyncIterator[httpx.AsyncClient]:
    async with client() as c:
        r = await login(c, await make_user(tenant_id, role))
        assert r.status_code == 200, r.text
        yield c
