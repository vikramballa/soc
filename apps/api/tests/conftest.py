"""Test harness: a dedicated PostgreSQL database rebuilt from migrations once per session."""

from __future__ import annotations

import os
import uuid
from collections.abc import AsyncIterator

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import create_async_engine

from sentinelx.config import Settings, get_settings

if "TEST_DATABASE_URL" not in os.environ:
    # Same server and credentials as the app (from .env), separate database.
    app_url = make_url(Settings().database_url)
    os.environ["TEST_DATABASE_URL"] = app_url.set(database="sentinelx_test").render_as_string(hide_password=False)
os.environ["DATABASE_URL"] = os.environ["TEST_DATABASE_URL"]
os.environ["APP_ENV"] = "test"
os.environ["LOG_JSON"] = "false"
os.environ["LOG_LEVEL"] = "WARNING"
os.environ["EMBEDDED_WORKER"] = "false"
os.environ["MISP_URL"] = ""
os.environ["RATE_LIMIT_LOGIN_PER_MINUTE"] = "1000"
os.environ["OLLAMA_URL"] = "http://127.0.0.1:9"  # unreachable unless a test mocks it

get_settings.cache_clear()
API_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _alembic_config() -> Config:
    cfg = Config(os.path.join(API_DIR, "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(API_DIR, "migrations"))
    cfg.attributes["configure_logger"] = False
    cfg.attributes["database_url"] = os.environ["DATABASE_URL"]
    return cfg


@pytest.fixture(scope="session", autouse=True)
async def database() -> AsyncIterator[None]:
    engine = create_async_engine(os.environ["DATABASE_URL"])
    async with engine.begin() as conn:
        await conn.execute(text("DROP SCHEMA public CASCADE"))
        await conn.execute(text("CREATE SCHEMA public"))
    await engine.dispose()
    import asyncio

    await asyncio.to_thread(command.upgrade, _alembic_config(), "head")
    from sentinelx.services.bootstrap import bootstrap

    await bootstrap()
    yield
    from sentinelx.persistence.db import dispose_engine

    await dispose_engine()


@pytest.fixture
async def tenant() -> uuid.UUID:
    from sentinelx.persistence.db import system_session
    from sentinelx.persistence.models import Tenant

    tid = uuid.uuid4()
    async with system_session() as s:
        s.add(Tenant(id=tid, slug=f"t-{tid.hex[:10]}", name="Test tenant", settings={}))
    return tid
