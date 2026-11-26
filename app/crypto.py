"""Encryption of API secrets at rest with Fernet."""
from __future__ import annotations

from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken


def load_fernet(secret_key: str | None, data_dir: Path) -> Fernet:
    """Use TOOLBOX_SECRET_KEY if given, otherwise a key file kept in the data dir."""
    if secret_key:
        return Fernet(secret_key.encode())
    key_file = data_dir / "secret.key"
    if not key_file.exists():
        data_dir.mkdir(parents=True, exist_ok=True)
        key_file.write_bytes(Fernet.generate_key())
        key_file.chmod(0o600)
    return Fernet(key_file.read_bytes().strip())


def encrypt(f: Fernet, value: str) -> str:
    return f.encrypt(value.encode()).decode()


def decrypt(f: Fernet, token: str) -> str | None:
    try:
        return f.decrypt(token.encode()).decode()
    except InvalidToken:
        return None
