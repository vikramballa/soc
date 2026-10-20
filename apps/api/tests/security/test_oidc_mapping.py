"""OIDC identities must never be able to take over local accounts or use unverified emails."""

from __future__ import annotations

import uuid

import pytest

from sentinelx.config import get_settings
from sentinelx.persistence.db import system_session
from sentinelx.persistence.models import Tenant
from sentinelx.security.oidc import provision_user
from tests.helpers import make_user


@pytest.fixture
async def org() -> str:
    slug = f"sso-{uuid.uuid4().hex[:8]}"
    async with system_session() as s:
        s.add(Tenant(id=uuid.uuid4(), slug=slug, name="SSO org", settings={}))
    return slug


def claims(email: str, slug: str, **extra: object) -> dict[str, object]:
    prefix = get_settings().oidc_role_claim_prefix
    return {
        "sub": str(uuid.uuid4()),
        "email": email,
        "email_verified": True,
        "tenant": slug,
        "realm_access": {"roles": [f"{prefix}SECURITY_ANALYST"]},
        **extra,
    }


async def test_new_sso_user_is_provisioned(org: str) -> None:
    user = await provision_user(claims(f"new-{uuid.uuid4().hex[:6]}@example.test", org))
    assert user is not None and user.auth_provider == "oidc" and user.role == "SECURITY_ANALYST"


async def test_unverified_email_is_refused(org: str) -> None:
    assert await provision_user(claims(f"u-{uuid.uuid4().hex[:6]}@example.test", org, email_verified=False)) is None


async def test_sso_cannot_take_over_a_local_account(org: str) -> None:
    async with system_session() as s:
        from sqlalchemy import select

        tid = (await s.execute(select(Tenant.id).where(Tenant.slug == org))).scalar_one()
    local_email = await make_user(tid, "TENANT_ADMIN")
    assert await provision_user(claims(local_email, org)) is None


async def test_sso_identity_is_bound_to_its_subject(org: str) -> None:
    email = f"bound-{uuid.uuid4().hex[:6]}@example.test"
    first = await provision_user(claims(email, org))
    assert first is not None
    # a different Keycloak subject presenting the same email is a different person
    assert await provision_user(claims(email, org)) is None
    again = await provision_user({**claims(email, org), "sub": first.external_id})
    assert again is not None and again.id == first.id


async def test_sso_cannot_grant_super_admin_by_default(org: str) -> None:
    prefix = get_settings().oidc_role_claim_prefix
    c = claims(f"sa-{uuid.uuid4().hex[:6]}@example.test", org, realm_access={"roles": [f"{prefix}SUPER_ADMIN"]})
    user = await provision_user(c)
    assert user is not None and user.role == "TENANT_ADMIN"  # capped unless OIDC_ALLOW_SUPER_ADMIN=true
