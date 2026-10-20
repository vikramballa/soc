"""Password hashing (Argon2id) and token helpers."""

from __future__ import annotations

import hashlib
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

_ph = PasswordHasher()  # Argon2id with library defaults (RFC 9106 recommended parameters)
_DUMMY = _ph.hash("timing-equalizer-not-a-password")

MIN_PASSWORD_LENGTH = 12


def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(password: str, hashed: str | None) -> bool:
    """Constant-ish time: always runs one Argon2 verification even when the user doesn't exist."""
    try:
        return _ph.verify(hashed or _DUMMY, password) and hashed is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def password_problems(password: str) -> list[str]:
    problems = []
    if len(password) < MIN_PASSWORD_LENGTH:
        problems.append(f"must be at least {MIN_PASSWORD_LENGTH} characters")
    classes = sum(bool(any(f(c) for c in password)) for f in (str.islower, str.isupper, str.isdigit))
    if classes < 2:
        problems.append("must mix letters and digits or upper/lower case")
    return problems


def new_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def generate_password() -> str:
    return secrets.token_urlsafe(12) + "A7"
