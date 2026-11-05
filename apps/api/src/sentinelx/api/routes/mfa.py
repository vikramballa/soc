"""Two-step verification (TOTP) and step-up re-authentication for local accounts."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select, update

from sentinelx.api.deps import MFA_ROLES, Principal, client_ip, get_principal, require_fresh
from sentinelx.config import get_settings
from sentinelx.persistence.db import system_session
from sentinelx.persistence.models import Session as DbSession
from sentinelx.persistence.models import User
from sentinelx.security import totp
from sentinelx.security.passwords import token_hash, verify_password
from sentinelx.security.ratelimit import limiter
from sentinelx.security.rbac import Perm, can_manage
from sentinelx.security.secretbox import open_sealed, seal
from sentinelx.services import selfmon
from sentinelx.services.audit import audit

router = APIRouter(prefix="/auth", tags=["auth"])
admin_router = APIRouter(prefix="/admin", tags=["admin"])

_PURPOSE = "totp"
MAX_PENDING_FAILURES = 5


class CodeIn(BaseModel):
    code: str = Field(min_length=6, max_length=32)


class ReauthIn(BaseModel):
    password: str = Field(min_length=1, max_length=256)
    code: str | None = Field(None, max_length=32)


class DisableIn(BaseModel):
    password: str = Field(min_length=1, max_length=256)
    code: str = Field(min_length=6, max_length=32)


def _check_second_factor(user: User, code: str) -> bool:
    """Accept a current TOTP code (once) or an unused recovery code (consumed)."""
    if not user.mfa_secret:
        return False
    step = totp.verify(open_sealed(user.mfa_secret, _PURPOSE), code, user.mfa_last_step)
    if step is not None:
        user.mfa_last_step = step
        return True
    h = totp.recovery_hash(code)
    if h in (user.mfa_recovery_hashes or []):
        user.mfa_recovery_hashes = [x for x in user.mfa_recovery_hashes if x != h]
        return True
    return False


def _rate_limit(key: str) -> None:
    if not limiter.allow(key, 10):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many attempts. Try again in a minute.")


@router.post("/mfa/verify")
async def verify_login(body: CodeIn, request: Request) -> dict[str, Any]:
    """Second step of sign-in: turns a password-only (pending) session into a full one."""
    s = get_settings()
    token = request.cookies.get(s.session_cookie_name)
    if not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Sign in with your password first")
    ip = client_ip(request) or "unknown"
    _rate_limit(f"mfa-ip:{ip}")
    now = datetime.now(UTC)
    failed = False
    async with system_session() as db:
        row = (
            await db.execute(
                select(DbSession, User)
                .join(User, User.id == DbSession.user_id)
                .where(
                    DbSession.token_hash == token_hash(token),
                    DbSession.mfa_pending.is_(True),
                    DbSession.revoked_at.is_(None),
                    DbSession.expires_at > now,
                    User.is_active.is_(True),
                )
                .with_for_update()
            )
        ).first()
        if row is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Your sign-in expired. Enter your password again.")
        sess, user = row
        if _check_second_factor(user, body.code):
            sess.mfa_pending = False
            sess.reauth_at = now
            sess.expires_at = now + _ttl()
            user.last_login_at, user.failed_logins, user.locked_until = now, 0, None
            await audit(
                db,
                action="auth.mfa",
                resource_type="user",
                resource_id=user.id,
                actor=user.email,
                actor_id=user.id,
                tenant_id=user.tenant_id,
                source_ip=ip,
            )
            await selfmon.emit(
                db, user.tenant_id, "auth.login", f"Signed in to SentinelX: {user.email}", actor=user.email, src_ip=ip
            )
        else:
            failed = True
            user.failed_logins += 1
            if user.failed_logins >= MAX_PENDING_FAILURES:
                sess.revoked_at = now
            # wrong codes count towards the normal lockout, so the 10^6 code space cannot be walked
            # by repeating the (known) password step
            if user.failed_logins >= s.login_max_failures:
                user.locked_until = now + timedelta(minutes=s.login_lockout_minutes)
            await audit(
                db,
                action="auth.mfa",
                resource_type="user",
                resource_id=user.id,
                actor=user.email,
                actor_id=user.id,
                tenant_id=user.tenant_id,
                result="failure",
                source_ip=ip,
            )
            # a correct password followed by wrong codes suggests the password is known to someone else
            await selfmon.emit(
                db,
                user.tenant_id,
                "auth.mfa",
                f"Wrong two-step verification code for {user.email} after a correct password",
                actor=user.email,
                src_ip=ip,
                outcome="failure",
            )
    if failed:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "That code is not valid")
    return {"ok": True}


def _ttl() -> timedelta:
    return timedelta(minutes=get_settings().session_ttl_minutes)


@router.get("/mfa")
async def mfa_status(principal: Principal = Depends(get_principal)) -> dict[str, Any]:
    async with system_session() as db:
        user = await db.get(User, principal.user_id)
        assert user is not None
        return {
            "enabled": user.mfa_enabled_at is not None,
            "enabled_at": user.mfa_enabled_at,
            "recovery_codes_left": len(user.mfa_recovery_hashes or []),
            "required": get_settings().mfa_enforced_for_admins and user.role in MFA_ROLES,
            "available": user.auth_provider == "local",
        }


@router.post("/mfa/setup")
async def mfa_setup(principal: Principal = Depends(get_principal)) -> dict[str, Any]:
    """Start enrolment: a new secret that becomes active only once a code from it is confirmed."""
    async with system_session() as db:
        user = await db.get(User, principal.user_id)
        assert user is not None
        if user.auth_provider != "local":
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Single sign-on accounts use the identity provider's MFA")
        if user.mfa_enabled_at is not None:
            raise HTTPException(status.HTTP_409_CONFLICT, "Two-step verification is already on")
        secret = totp.new_secret()
        user.mfa_secret = seal(secret, _PURPOSE)
        user.mfa_last_step = None
    return {"secret": secret, "otpauth_uri": totp.provisioning_uri(secret, principal.email, get_settings().mfa_issuer)}


@router.post("/mfa/enable")
async def mfa_enable(body: CodeIn, request: Request, principal: Principal = Depends(get_principal)) -> dict[str, Any]:
    _rate_limit(f"mfa-enable:{principal.user_id}")
    codes = totp.new_recovery_codes()
    async with system_session() as db:
        user = await db.get(User, principal.user_id)
        assert user is not None
        if user.mfa_enabled_at is not None:
            raise HTTPException(status.HTTP_409_CONFLICT, "Two-step verification is already on")
        if not user.mfa_secret:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Start setup first")
        step = totp.verify(open_sealed(user.mfa_secret, _PURPOSE), body.code, None)
        if step is None:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "That code is not valid - check the time on your phone")
        user.mfa_last_step = step
        user.mfa_enabled_at = datetime.now(UTC)
        user.mfa_recovery_hashes = [totp.recovery_hash(c) for c in codes]
        await audit(
            db,
            action="auth.mfa_enabled",
            resource_type="user",
            resource_id=user.id,
            actor=user.email,
            actor_id=user.id,
            tenant_id=user.tenant_id,
            source_ip=client_ip(request),
        )
    return {"enabled": True, "recovery_codes": codes, "note": "Store these recovery codes safely. Each works once."}


@router.post("/mfa/disable")
async def mfa_disable(
    body: DisableIn, request: Request, principal: Principal = Depends(require_fresh())
) -> dict[str, Any]:
    async with system_session() as db:
        user = await db.get(User, principal.user_id)
        assert user is not None
        if user.mfa_enabled_at is None:
            return {"enabled": False}
        if get_settings().mfa_enforced_for_admins and user.role in MFA_ROLES:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Two-step verification is required for your role")
        if not verify_password(body.password, user.password_hash) or not _check_second_factor(user, body.code):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Password or code is incorrect")
        user.mfa_secret, user.mfa_enabled_at, user.mfa_recovery_hashes, user.mfa_last_step = None, None, [], None
        ip = client_ip(request)
        await audit(
            db,
            action="auth.mfa_disabled",
            resource_type="user",
            resource_id=user.id,
            actor=user.email,
            actor_id=user.id,
            tenant_id=user.tenant_id,
            source_ip=ip,
        )
        await selfmon.emit(
            db,
            user.tenant_id,
            "auth.mfa_disabled",
            f"{user.email} turned off two-step verification",
            actor=user.email,
            src_ip=ip,
            severity=40,
        )
    return {"enabled": False}


@router.post("/reauth")
async def reauth(body: ReauthIn, request: Request, principal: Principal = Depends(get_principal)) -> dict[str, Any]:
    """Confirm the password (and code, if two-step verification is on) before a sensitive change."""
    ip = client_ip(request) or "unknown"
    _rate_limit(f"reauth:{principal.user_id}")
    if principal.session_id is None:
        return {"ok": True}
    now = datetime.now(UTC)
    ok = False
    async with system_session() as db:
        user = await db.get(User, principal.user_id)
        assert user is not None
        ok = user.auth_provider == "local" and verify_password(body.password, user.password_hash)
        if ok and user.mfa_enabled_at is not None:
            ok = bool(body.code) and _check_second_factor(user, body.code or "")
        if ok:
            await db.execute(update(DbSession).where(DbSession.id == principal.session_id).values(reauth_at=now))
        await audit(
            db,
            action="auth.reauth",
            resource_type="user",
            resource_id=user.id,
            actor=user.email,
            actor_id=user.id,
            tenant_id=user.tenant_id,
            result="success" if ok else "failure",
            source_ip=ip,
        )
        if not ok:
            await selfmon.emit(
                db,
                user.tenant_id,
                "auth.reauth",
                f"Failed password confirmation for {user.email} inside a signed-in session",
                actor=user.email,
                src_ip=ip,
                outcome="failure",
            )
    if not ok:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Password or code is incorrect")
    return {"ok": True, "valid_minutes": get_settings().reauth_window_minutes}


@admin_router.post("/users/{user_id}/mfa-reset")
async def admin_reset_mfa(
    user_id: uuid.UUID, request: Request, principal: Principal = Depends(require_fresh(Perm.ADMIN_MANAGE))
) -> dict[str, Any]:
    """For a lost phone: switches two-step verification off so the user can enrol again."""
    async with system_session() as db:
        user = await db.get(User, user_id)
        if user is None or user.tenant_id != principal.tenant_id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
        if user.id == principal.user_id or not can_manage(principal.role, user.role):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "You can only reset users with a lower role than yours")
        user.mfa_secret, user.mfa_enabled_at, user.mfa_recovery_hashes, user.mfa_last_step = None, None, [], None
        # the user's existing sessions were authenticated with the old factor
        await db.execute(
            update(DbSession)
            .where(DbSession.user_id == user.id, DbSession.revoked_at.is_(None))
            .values(revoked_at=datetime.now(UTC))
        )
        ip = client_ip(request)
        await audit(
            db,
            action="user.mfa_reset",
            resource_type="user",
            resource_id=user.id,
            actor=principal.email,
            actor_id=principal.user_id,
            tenant_id=principal.tenant_id,
            source_ip=ip,
        )
        await selfmon.emit(
            db,
            principal.tenant_id,
            "user.mfa_reset",
            f"{principal.email} reset two-step verification for {user.email}",
            actor=principal.email,
            src_ip=ip,
            severity=40,
            details={"target_user": user.email},
        )
    return {"ok": True}
