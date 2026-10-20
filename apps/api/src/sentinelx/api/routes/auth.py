"""Authentication: local accounts (Argon2id + server-side sessions) and optional Keycloak SSO."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field
from sqlalchemy import select, update

from sentinelx import __version__
from sentinelx.api.deps import Principal, client_ip, get_principal
from sentinelx.config import get_settings
from sentinelx.persistence.db import system_session, tenant_session
from sentinelx.persistence.models import Session as DbSession
from sentinelx.persistence.models import Tenant, User
from sentinelx.security import oidc
from sentinelx.security.passwords import hash_password, new_token, password_problems, token_hash, verify_password
from sentinelx.security.ratelimit import limiter
from sentinelx.security.rbac import ROLE_DESCRIPTIONS, Perm, Role
from sentinelx.services.audit import audit

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginIn(BaseModel):
    email: str = Field(min_length=3, max_length=320, pattern=r"^[^@\s]+@[^@\s]+$")
    password: str = Field(min_length=1, max_length=256)


class PasswordChangeIn(BaseModel):
    current_password: str = Field(max_length=256)
    new_password: str = Field(min_length=12, max_length=256)


def _set_cookie(response: Response, token: str) -> None:
    s = get_settings()
    response.set_cookie(
        s.session_cookie_name,
        token,
        max_age=s.session_ttl_minutes * 60,
        httponly=True,
        secure=s.session_cookie_secure,
        samesite="lax",
        path="/",
    )


async def create_session(user_id: uuid.UUID, tenant_id: uuid.UUID, request: Request) -> str:
    s = get_settings()
    token = new_token()
    async with system_session() as db:
        db.add(
            DbSession(
                id=uuid.uuid4(),
                tenant_id=tenant_id,
                user_id=user_id,
                token_hash=token_hash(token),
                expires_at=datetime.now(UTC) + timedelta(minutes=s.session_ttl_minutes),
                ip=client_ip(request),
                user_agent=(request.headers.get("user-agent") or "")[:300],
            )
        )
        await db.execute(
            update(User)
            .where(User.id == user_id)
            .values(last_login_at=datetime.now(UTC), failed_logins=0, locked_until=None)
        )
    return token


@router.get("/config")
async def auth_config() -> dict[str, Any]:
    s = get_settings()
    return {
        "local_login": s.auth_mode in ("local", "both"),
        "sso": oidc.oidc_enabled(),
        "version": __version__,
        "environment": s.app_env,
    }


@router.post("/login")
async def login(body: LoginIn, request: Request, response: Response) -> dict[str, Any]:
    s = get_settings()
    if s.auth_mode == "oidc":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Local login is disabled; use single sign-on")
    ip = client_ip(request) or "unknown"
    email = body.email.lower()
    if not limiter.allow(f"login-ip:{ip}", s.rate_limit_login_per_minute) or not limiter.allow(
        f"login-user:{email}", s.rate_limit_login_per_minute
    ):
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "Too many sign-in attempts. Try again in a minute.",
            headers={"Retry-After": "60"},
        )
    now = datetime.now(UTC)
    failure: str | None = None
    async with system_session() as db:  # commit the failure counter + audit even when sign-in fails
        user = (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()
        locked = user is not None and user.locked_until is not None and user.locked_until > now
        ok = verify_password(body.password, user.password_hash if user and user.auth_provider == "local" else None)
        if user is None or not ok or not user.is_active or locked:
            failure = "locked" if locked else "invalid_credentials"
            if user is not None and not locked:
                user.failed_logins += 1
                if user.failed_logins >= s.login_max_failures:
                    user.locked_until = now + timedelta(minutes=s.login_lockout_minutes)
            await audit(
                db,
                action="auth.login",
                resource_type="user",
                resource_id=user.id if user else None,
                actor=email,
                tenant_id=user.tenant_id if user else None,
                result="failure",
                details={"reason": failure},
                source_ip=ip,
            )
        else:
            await audit(
                db,
                action="auth.login",
                resource_type="user",
                resource_id=user.id,
                actor=email,
                actor_id=user.id,
                tenant_id=user.tenant_id,
                source_ip=ip,
            )
            user_id, tenant_id = user.id, user.tenant_id
    if failure:
        # identical message for unknown user / wrong password (no account enumeration)
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Account temporarily locked after repeated failures"
            if failure == "locked"
            else "Email or password is incorrect",
        )
    token = await create_session(user_id, tenant_id, request)
    _set_cookie(response, token)
    return {"ok": True}


@router.post("/logout")
async def logout(request: Request, response: Response, principal: Principal = Depends(get_principal)) -> dict[str, Any]:
    s = get_settings()
    token = request.cookies.get(s.session_cookie_name)
    async with system_session() as db:
        if token:
            await db.execute(
                update(DbSession).where(DbSession.token_hash == token_hash(token)).values(revoked_at=datetime.now(UTC))
            )
        await audit(
            db,
            action="auth.logout",
            resource_type="user",
            resource_id=principal.user_id,
            actor=principal.email,
            actor_id=principal.user_id,
            tenant_id=principal.home_tenant_id,
            source_ip=client_ip(request),
        )
    response.delete_cookie(s.session_cookie_name, path="/")
    return {"ok": True}


@router.get("/me")
async def me(principal: Principal = Depends(get_principal)) -> dict[str, Any]:
    async with system_session() as db:
        tenant = await db.get(Tenant, principal.tenant_id)
        tenants = []
        if principal.can(Perm.TENANT_SWITCH):
            tenants = [
                {
                    "id": str(t.id),
                    "name": t.name,
                    "slug": t.slug,
                    "demo": bool((t.settings or {}).get("demo")),
                    "demo_loaded_at": (t.settings or {}).get("demo_loaded_at"),
                }
                for t in (await db.execute(select(Tenant).order_by(Tenant.created_at))).scalars()
            ]
        user = await db.get(User, principal.user_id)
    return {
        "user": {
            "id": str(principal.user_id),
            "email": principal.email,
            "display_name": principal.display_name,
            "role": principal.role,
            "role_description": ROLE_DESCRIPTIONS.get(Role(principal.role), ""),
            "auth_provider": user.auth_provider if user else "local",
        },
        "permissions": sorted(str(p) for p in principal.permissions),
        "tenant": {
            "id": str(tenant.id),
            "name": tenant.name,
            "slug": tenant.slug,
            "demo": bool((tenant.settings or {}).get("demo")),
        }
        if tenant
        else None,
        "home_tenant_id": str(principal.home_tenant_id),
        "tenants": tenants,
    }


@router.post("/password")
async def change_password(
    body: PasswordChangeIn, request: Request, principal: Principal = Depends(get_principal)
) -> dict[str, Any]:
    problems = password_problems(body.new_password)
    if problems:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "New password " + "; ".join(problems))
    async with system_session() as db:
        user = await db.get(User, principal.user_id)
        if (
            user is None
            or user.auth_provider != "local"
            or not verify_password(body.current_password, user.password_hash)
        ):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Current password is incorrect")
        user.password_hash = hash_password(body.new_password)
        # revoke every other session of this user
        await db.execute(
            update(DbSession)
            .where(DbSession.user_id == user.id, DbSession.id != principal.session_id, DbSession.revoked_at.is_(None))
            .values(revoked_at=datetime.now(UTC))
        )
    async with tenant_session(principal.home_tenant_id) as db:
        await audit(
            db,
            action="auth.password_changed",
            resource_type="user",
            resource_id=principal.user_id,
            actor=principal.email,
            actor_id=principal.user_id,
            tenant_id=principal.home_tenant_id,
            source_ip=client_ip(request),
        )
    return {"ok": True}


@router.get("/oidc/login")
async def oidc_login(request: Request) -> RedirectResponse:
    if not oidc.oidc_enabled():
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Single sign-on is not configured")
    redirect_uri = str(request.url_for("oidc_callback"))
    url, cookie = oidc.start_login(redirect_uri)
    resp = RedirectResponse(url, status_code=302)
    resp.set_cookie(
        "sx_oidc",
        cookie,
        max_age=600,
        httponly=True,
        secure=get_settings().session_cookie_secure,
        samesite="lax",
        path="/api/v1/auth/oidc",
    )
    return resp


@router.get("/oidc/callback", name="oidc_callback")
async def oidc_callback(request: Request, code: str, state: str) -> RedirectResponse:
    if not oidc.oidc_enabled():
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Single sign-on is not configured")
    claims = await oidc.finish_login(code, state, request.cookies.get("sx_oidc"), str(request.url_for("oidc_callback")))
    base = get_settings().app_base_url.rstrip("/")
    if claims is None:
        return RedirectResponse(f"{base}/login?error=sso_failed", status_code=302)
    user = await oidc.provision_user(claims)
    if user is None:
        return RedirectResponse(f"{base}/login?error=sso_not_authorized", status_code=302)
    token = await create_session(user.id, user.tenant_id, request)
    async with tenant_session(user.tenant_id) as db:
        await audit(
            db,
            action="auth.login",
            resource_type="user",
            resource_id=user.id,
            actor=user.email,
            actor_id=user.id,
            tenant_id=user.tenant_id,
            details={"method": "oidc"},
            source_ip=client_ip(request),
        )
    resp = RedirectResponse(f"{base}/", status_code=302)
    _set_cookie(resp, token)
    resp.delete_cookie("sx_oidc", path="/api/v1/auth/oidc")
    return resp
