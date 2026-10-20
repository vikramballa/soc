"""Optional Keycloak / OIDC support.

Two integration paths:
* **Backend-for-frontend login** (browser): authorization-code + PKCE handled by the API; tokens never
  reach the browser - after validation the user gets the same HttpOnly session cookie as local login.
* **Bearer tokens** (API clients): ``Authorization: Bearer <access token>`` validated against the realm JWKS.

Role mapping: realm roles named ``sentinelx:<ROLE>``; tenant mapping: a ``tenant`` claim holding the slug.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import secrets
import time
import uuid
from functools import lru_cache
from typing import Any

import jwt
from fastapi import Request
from sqlalchemy import select

from sentinelx.config import get_settings
from sentinelx.persistence.db import system_session
from sentinelx.persistence.models import Tenant, User
from sentinelx.security.rbac import Role, permissions_for

ROLE_ORDER = [Role.VIEWER, Role.IT_OPERATOR, Role.SECURITY_ANALYST, Role.TENANT_ADMIN, Role.SUPER_ADMIN]


def oidc_enabled() -> bool:
    s = get_settings()
    return s.auth_mode in ("oidc", "both") and bool(s.keycloak_url)


def issuer() -> str:
    s = get_settings()
    return f"{str(s.keycloak_url).rstrip('/')}/realms/{s.keycloak_realm}"


@lru_cache
def _jwks_client() -> jwt.PyJWKClient:
    return jwt.PyJWKClient(f"{issuer()}/protocol/openid-connect/certs", cache_keys=True, lifespan=3600)


async def decode_token(token: str, audience: str | None = None) -> dict[str, Any]:
    s = get_settings()
    key = await asyncio.to_thread(lambda: _jwks_client().get_signing_key_from_jwt(token).key)
    return jwt.decode(
        token,
        key,
        algorithms=["RS256", "ES256", "PS256"],
        issuer=issuer(),
        audience=audience or s.keycloak_client_id,
        options={"require": ["exp", "iat", "iss", "sub"], "verify_aud": True},
    )


def role_from_claims(claims: dict[str, Any]) -> Role | None:
    prefix = get_settings().oidc_role_claim_prefix
    roles = set((claims.get("realm_access") or {}).get("roles", []))
    for client in (claims.get("resource_access") or {}).values():
        roles |= set(client.get("roles", []))
    granted = [Role(r[len(prefix) :]) for r in roles if r.startswith(prefix) and r[len(prefix) :] in Role.__members__]
    return max(granted, key=ROLE_ORDER.index) if granted else None


async def provision_user(claims: dict[str, Any]) -> User | None:
    """Create/update the local user record for an OIDC identity. Returns None if not authorized.

    Safety rules:
    * the identity provider must assert ``email_verified``;
    * an SSO identity is bound to its subject (``sub``) - a different subject presenting the same email is
      refused, and an SSO login can never take over a local (password) account;
    * SUPER_ADMIN cannot be granted from the identity provider unless ``OIDC_ALLOW_SUPER_ADMIN=true``.
    """
    s = get_settings()
    role = role_from_claims(claims)
    email = str(claims.get("email") or "").lower()
    sub = str(claims.get("sub") or "")
    slug = claims.get(s.oidc_tenant_claim) or "default"
    if role is None or not email or not sub or claims.get("email_verified") is not True:
        return None
    if role == Role.SUPER_ADMIN and not s.oidc_allow_super_admin:
        role = Role.TENANT_ADMIN
    async with system_session() as db:
        tenant = (await db.execute(select(Tenant).where(Tenant.slug == str(slug)))).scalar_one_or_none()
        if tenant is None:
            return None
        user = (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()
        if user is None:
            user = User(
                id=uuid.uuid4(),
                tenant_id=tenant.id,
                email=email,
                display_name=str(claims.get("name") or email),
                role=role.value,
                auth_provider="oidc",
                external_id=sub,
                is_active=True,  # set explicitly: column defaults only apply at INSERT time
            )
            db.add(user)
            await db.flush()
        elif user.auth_provider != "oidc" or user.external_id != sub:
            return None
        else:
            user.role, user.tenant_id = role.value, tenant.id
        if not user.is_active:
            return None
        return user


async def principal_from_bearer(request: Request) -> Any:
    from sentinelx.api.deps import Principal

    auth = request.headers.get("authorization", "")
    if not oidc_enabled() or not auth.lower().startswith("bearer "):
        return None
    try:
        claims = await decode_token(auth[7:].strip())
    except (jwt.PyJWTError, OSError):
        return None
    user = await provision_user(claims)
    if user is None:
        return None
    return Principal(
        user.id,
        user.email,
        user.display_name,
        user.role,
        user.tenant_id,
        user.tenant_id,
        None,
        permissions_for(user.role),
    )


# --- PKCE + signed state cookie for the BFF login flow -------------------------------------------------


def _sign(payload: dict[str, Any]) -> str:
    key = get_settings().app_secret.get_secret_value().encode()
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
    mac = hmac.new(key, body.encode(), hashlib.sha256).hexdigest()
    return f"{body}.{mac}"


def _unsign(value: str, max_age: int = 600) -> dict[str, Any] | None:
    key = get_settings().app_secret.get_secret_value().encode()
    try:
        body, mac = value.rsplit(".", 1)
    except ValueError:
        return None
    if not hmac.compare_digest(mac, hmac.new(key, body.encode(), hashlib.sha256).hexdigest()):
        return None
    data = json.loads(base64.urlsafe_b64decode(body.encode()))
    if time.time() - data.get("ts", 0) > max_age:
        return None
    return data


def start_login(redirect_uri: str) -> tuple[str, str]:
    s = get_settings()
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    state = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(24)
    from urllib.parse import urlencode

    url = f"{issuer()}/protocol/openid-connect/auth?" + urlencode(
        {
            "client_id": s.keycloak_client_id,
            "response_type": "code",
            "scope": "openid email profile",
            "redirect_uri": redirect_uri,
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
    )
    cookie = _sign({"state": state, "nonce": nonce, "verifier": verifier, "ts": time.time()})
    return url, cookie


async def finish_login(code: str, state: str, cookie: str | None, redirect_uri: str) -> dict[str, Any] | None:
    import httpx

    s = get_settings()
    data = _unsign(cookie or "")
    if not data or not hmac.compare_digest(data["state"], state):
        return None
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": s.keycloak_client_id,
        "code_verifier": data["verifier"],
    }
    if s.keycloak_client_secret:
        form["client_secret"] = s.keycloak_client_secret.get_secret_value()
    async with httpx.AsyncClient(timeout=10, follow_redirects=False) as client:
        r = await client.post(f"{issuer()}/protocol/openid-connect/token", data=form)
        if r.status_code != 200:
            return None
        tokens = r.json()
    claims = await decode_token(tokens["id_token"], audience=s.keycloak_client_id)
    if claims.get("nonce") != data["nonce"]:
        return None
    return claims
