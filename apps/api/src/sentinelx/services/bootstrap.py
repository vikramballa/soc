"""Idempotent first-run setup: default tenant, MITRE dataset, rule repository sync, first admin."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from sentinelx.config import get_settings
from sentinelx.detection.engine import sync_rules_to_db
from sentinelx.mitre.catalog import get_catalog
from sentinelx.persistence.db import system_session
from sentinelx.persistence.models import MitreTactic, MitreTechnique, Tenant, User
from sentinelx.security.passwords import generate_password, hash_password

DEFAULT_SLUG = "default"


async def import_mitre() -> int:
    cat = get_catalog()
    async with system_session() as s:
        for t in cat.tactics:
            stmt = pg_insert(MitreTactic).values(
                id=t.id, shortname=t.shortname, name=t.name, description=t.description, order=t.order, url=t.url
            )
            await s.execute(
                stmt.on_conflict_do_update(
                    index_elements=["id"],
                    set_={
                        "name": stmt.excluded.name,
                        "description": stmt.excluded.description,
                        "order": stmt.excluded.order,
                        "url": stmt.excluded.url,
                        "shortname": stmt.excluded.shortname,
                    },
                )
            )
        rows = [
            {
                "id": t.id,
                "name": t.name,
                "description": t.description,
                "tactics": list(t.tactics),
                "platforms": list(t.platforms),
                "is_subtechnique": t.is_subtechnique,
                "parent_id": t.parent_id,
                "url": t.url,
                "detection": t.detection,
            }
            for t in cat.techniques.values()
        ]
        for i in range(0, len(rows), 200):
            stmt = pg_insert(MitreTechnique).values(rows[i : i + 200])
            await s.execute(
                stmt.on_conflict_do_update(
                    index_elements=["id"],
                    set_={
                        k: stmt.excluded[k]
                        for k in (
                            "name",
                            "description",
                            "tactics",
                            "platforms",
                            "is_subtechnique",
                            "parent_id",
                            "url",
                            "detection",
                        )
                    },
                )
            )
    return len(rows)


async def ensure_default_tenant() -> uuid.UUID:
    async with system_session() as s:
        t = (await s.execute(select(Tenant).where(Tenant.slug == DEFAULT_SLUG))).scalar_one_or_none()
        if t is None:
            t = Tenant(id=uuid.uuid4(), slug=DEFAULT_SLUG, name="My Organization", settings={})
            s.add(t)
        return t.id


async def ensure_admin(tenant_id: uuid.UUID) -> dict[str, Any] | None:
    """Create the first SUPER_ADMIN if no users exist. Returns credentials only when newly created."""
    s_ = get_settings()
    async with system_session() as s:
        if (await s.execute(select(func.count()).select_from(User))).scalar_one() > 0:
            return None
        password = (
            s_.bootstrap_admin_password.get_secret_value() if s_.bootstrap_admin_password else generate_password()
        )
        s.add(
            User(
                id=uuid.uuid4(),
                tenant_id=tenant_id,
                email=s_.bootstrap_admin_email.lower(),
                display_name="Administrator",
                role="SUPER_ADMIN",
                password_hash=hash_password(password),
            )
        )
        return {"email": s_.bootstrap_admin_email.lower(), "password": password}


async def bootstrap() -> dict[str, Any]:
    tenant_id = await ensure_default_tenant()
    techniques = await import_mitre()
    async with system_session() as s:
        rules = await sync_rules_to_db(s)
    admin = await ensure_admin(tenant_id)
    return {"tenant_id": str(tenant_id), "mitre_techniques": techniques, "rules": rules, "admin": admin}
