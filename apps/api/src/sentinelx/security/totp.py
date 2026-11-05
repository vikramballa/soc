"""RFC 6238 time-based one-time passwords (the codes authenticator apps show) and recovery codes."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote, urlencode

STEP_SECONDS = 30
DIGITS = 6
# accept the previous and next 30 s step to tolerate clock drift on the phone
DRIFT_STEPS = 1


def new_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _key(secret_b32: str) -> bytes:
    pad = "=" * (-len(secret_b32) % 8)
    return base64.b32decode(secret_b32.upper() + pad)


def code_at(secret_b32: str, step: int) -> str:
    digest = hmac.new(_key(secret_b32), struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10**DIGITS).zfill(DIGITS)


def current_step(now: float | None = None) -> int:
    return int((time.time() if now is None else now) // STEP_SECONDS)


def verify(secret_b32: str, code: str, last_step: int | None, now: float | None = None) -> int | None:
    """Return the matched time step, or None. A step at or before ``last_step`` is rejected (no replay)."""
    code = "".join(ch for ch in code if ch.isdigit())
    if len(code) != DIGITS:
        return None
    now_step = current_step(now)
    for step in range(now_step - DRIFT_STEPS, now_step + DRIFT_STEPS + 1):
        if last_step is not None and step <= last_step:
            continue
        if hmac.compare_digest(code_at(secret_b32, step), code):
            return step
    return None


def provisioning_uri(secret_b32: str, account: str, issuer: str) -> str:
    label = quote(f"{issuer}:{account}")
    query = urlencode({"secret": secret_b32, "issuer": issuer, "algorithm": "SHA1", "digits": DIGITS, "period": 30})
    return f"otpauth://totp/{label}?{query}"


def new_recovery_codes(n: int = 8) -> list[str]:
    alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
    return ["-".join("".join(secrets.choice(alphabet) for _ in range(5)) for _ in range(2)) for _ in range(n)]


def recovery_hash(code: str) -> str:
    return hashlib.sha256(code.strip().lower().replace(" ", "").encode()).hexdigest()
