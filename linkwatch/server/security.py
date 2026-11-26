"""Secrets: encryption at rest, hashed keys and tokens."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from typing import Any

from cryptography.fernet import Fernet, InvalidToken


class Vault:
    """Encrypts JSON blobs (SNMP credentials, API secrets) with Fernet."""

    def __init__(self, key: str):
        self.f = Fernet(key.encode() if isinstance(key, str) else key)

    def seal(self, data: dict[str, Any]) -> str:
        return self.f.encrypt(json.dumps(data).encode()).decode()

    def open(self, token: str | None) -> dict[str, Any]:
        if not token:
            return {}
        try:
            return json.loads(self.f.decrypt(token.encode()))
        except (InvalidToken, ValueError):
            return {}


def sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def new_secret(prefix: str, nbytes: int = 32) -> str:
    return f"{prefix}_{secrets.token_urlsafe(nbytes)}"


def mask(value: str | None) -> str:
    if not value:
        return ""
    return "••••••" + value[-4:] if len(value) > 8 else "••••••"


# user passwords: scrypt from the standard library -----------------------------
_N, _R, _P = 2 ** 14, 8, 1


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=_N, r=_R, p=_P, dklen=32)
    return f"scrypt${_N}${_R}${_P}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def verify_password(password: str, stored: str | None) -> bool:
    try:
        algo, n, r, p, salt, dk = (stored or "").split("$")
        if algo != "scrypt":
            return False
        want = base64.b64decode(dk)
        got = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p), dklen=len(want))
        return hmac.compare_digest(got, want)
    except (ValueError, TypeError):
        return False
