"""Secrets: encryption at rest, hashed keys and tokens."""
from __future__ import annotations

import hashlib
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
