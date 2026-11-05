"""Authenticated encryption of small secrets stored in the database (AES-256-GCM, key from APP_SECRET).

A database dump alone therefore does not reveal TOTP secrets; the attacker also needs APP_SECRET.
"""

from __future__ import annotations

import base64
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from sentinelx.config import get_settings

_PREFIX = "v1:"


def _key(purpose: str) -> bytes:
    secret = get_settings().app_secret.get_secret_value().encode()
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=b"sentinelx-secretbox", info=purpose.encode()).derive(secret)


def seal(plaintext: str, purpose: str) -> str:
    nonce = os.urandom(12)
    ct = AESGCM(_key(purpose)).encrypt(nonce, plaintext.encode(), purpose.encode())
    return _PREFIX + base64.urlsafe_b64encode(nonce + ct).decode()


def open_sealed(sealed: str, purpose: str) -> str:
    if not sealed.startswith(_PREFIX):
        raise ValueError("unknown secret format")
    raw = base64.urlsafe_b64decode(sealed[len(_PREFIX) :])
    return AESGCM(_key(purpose)).decrypt(raw[:12], raw[12:], purpose.encode()).decode()
