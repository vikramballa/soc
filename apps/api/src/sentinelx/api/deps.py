"""Request authentication, tenant resolution and authorization dependencies."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Callable, Coroutine
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelx.config import get_settings
from sentinelx.logging import tenant_id_var
from sentinelx.persistence.db import system_session, tenant_session
from sentinelx.persistence.models import Session as DbSession
from sentinelx.persistence.models import Tenant, User
from sentinelx.security.passwords import token_hash
from sentinelx.security.rbac import Perm, permissions_for
from sentinelx.services.audit import audit

TENANT_HEADER = "X-SentinelX-Tenant"
REAUTH_HEADER = "X-SentinelX-Reauth"
MFA_ROLES = ("SUPER_ADMIN", "TENANT_ADMIN")
# Paths an admin who still has to enrol in two-step verification may use.
_ENROLMENT_PATHS = ("/api/v1/auth/",)


@dataclass
class Principal:
    user_id: uuid.UUID
    email: str
    display_name: str
    role: str
    home_tenant_id: uuid.UUID
    tenant_id: uuid.UUID  # effective tenant for this request
    session_id: uuid.UUID | None
    permissions: frozenset[Perm]
    reauth_at: datetime | None = None
    mfa_enabled: bool = False
    mfa_enrollment_required: bool = False

    def can(self, perm: Perm) -> bool:
        return perm in self.permissions

    def recently_authenticated(self) -> bool:
        """Step-up check for sensitive changes. SSO (bearer) principals re-authenticate at the IdP."""
        if self.session_id is None:
            return True
        if self.reauth_at is None:
            return False
        window = timedelta(minutes=get_settings().reauth_window_minutes)
        return datetime.now(UTC) - self.reauth_at <= window


def client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


async def _principal_from_session(request: Request) -> Principal | None:
    s = get_settings()
    token = request.cookies.get(s.session_cookie_name)
    if not token:
        return None
    now = datetime.now(UTC)
    async with system_session() as db:
        row = (
            await db.execute(
                select(DbSession, User)
                .join(User, User.id == DbSession.user_id)
                .where(
                    DbSession.token_hash == token_hash(token),
                    DbSession.revoked_at.is_(None),
                    DbSession.expires_at > now,
                    DbSession.mfa_pending.is_(False),
                    User.is_active.is_(True),
                )
            )
        ).first()
        if row is None:
            return None
        sess, user = row
        # sliding expiry: extend when less than half the TTL remains
        ttl = timedelta(minutes=s.session_ttl_minutes)
        if sess.expires_at - now < ttl / 2:
            sess.expires_at = now + ttl
            request.state.refresh_session = True
        mfa_enabled = user.mfa_enabled_at is not None
        return Principal(
            user.id,
            user.email,
            user.display_name,
            user.role,
            user.tenant_id,
            user.tenant_id,
            sess.id,
            permissions_for(user.role),
            reauth_at=sess.reauth_at,
            mfa_enabled=mfa_enabled,
            mfa_enrollment_required=(
                s.mfa_enforced_for_admins
                and user.role in MFA_ROLES
                and user.auth_provider == "local"
                and not mfa_enabled
            ),
        )


async def get_principal(request: Request) -> Principal:
    principal = getattr(request.state, "principal", None)
    if principal is None:
        principal = await _principal_from_session(request)
        if principal is None:
            from sentinelx.security.oidc import principal_from_bearer

            principal = await principal_from_bearer(request)
        if principal is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not signed in")
        if principal.mfa_enrollment_required and not request.url.path.startswith(_ENROLMENT_PATHS):
            raise HTTPException(
                status.HTTP_403_FORBIDDEN, "mfa_enrollment_required: set up two-step verification to continue"
            )
        requested = request.headers.get(TENANT_HEADER)
        if requested and requested != str(principal.tenant_id):
            # Never trust a browser-supplied tenant id: only SUPER_ADMIN may switch, and the tenant must exist.
            if not principal.can(Perm.TENANT_SWITCH):
                raise HTTPException(status.HTTP_403_FORBIDDEN, "You cannot access another organization")
            try:
                tid = uuid.UUID(requested)
            except ValueError as e:
                raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid tenant id") from e
            async with system_session() as db:
                if await db.get(Tenant, tid) is None:
                    raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")
            principal.tenant_id = tid
        request.state.principal = principal
        tenant_id_var.set(str(principal.tenant_id))
    return principal


def require(*perms: Perm) -> Callable[..., Coroutine[Any, Any, Principal]]:
    async def dep(request: Request, principal: Principal = Depends(get_principal)) -> Principal:
        missing = [p for p in perms if not principal.can(p)]
        if missing:
            async with tenant_session(principal.tenant_id) as db:
                await audit(
                    db,
                    action="authorization.denied",
                    resource_type="endpoint",
                    resource_id=request.url.path[:120],
                    actor=principal.email,
                    actor_id=principal.user_id,
                    tenant_id=principal.tenant_id,
                    result="denied",
                    details={"missing": [str(p) for p in missing], "method": request.method},
                    source_ip=client_ip(request),
                )
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"Missing permission: {', '.join(missing)}")
        return principal

    return dep


def require_fresh(*perms: Perm) -> Callable[..., Coroutine[Any, Any, Principal]]:
    """Like ``require`` but also demands a recent password (and second-factor) check. A stolen session
    cookie alone is then not enough to disable rules, mint tokens or change roles."""
    base = require(*perms)

    async def dep(request: Request, principal: Principal = Depends(base)) -> Principal:
        if not principal.recently_authenticated():
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                "reauth_required: confirm your password to make this change",
                headers={REAUTH_HEADER: "required"},
            )
        return principal

    return dep


async def deny(request: Request, principal: Principal, perm: Perm, what: str) -> HTTPException:
    """Audit a fine-grained (in-handler) permission denial in its own transaction - the request's
    transaction is rolled back when the error is raised - and return the exception to raise."""
    async with tenant_session(principal.tenant_id) as db:
        await audit(
            db,
            action="authorization.denied",
            resource_type="endpoint",
            resource_id=request.url.path[:120],
            actor=principal.email,
            actor_id=principal.user_id,
            tenant_id=principal.tenant_id,
            result="denied",
            details={"missing": [str(perm)], "attempted": what, "method": request.method},
            source_ip=client_ip(request),
        )
    return HTTPException(status.HTTP_403_FORBIDDEN, f"Missing permission: {perm} ({what})")


async def get_db(principal: Principal = Depends(get_principal)) -> AsyncIterator[AsyncSession]:
    async with tenant_session(principal.tenant_id) as session:
        yield session
