"""Server configuration from environment variables."""
from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Config:
    database_url: str
    secret_key: str            # Fernet key: encrypts stored credentials and signs sessions
    admin_password: str | None
    public_url: str
    poll_interval: int
    raw_days: int
    hourly_days: int
    background: bool = True    # run sync/rollup loops (off in tests)
    nss_dir: str = ""          # Zscaler Cloud NSS log segments; empty: next to a SQLite database, else ./data/nss

    @classmethod
    def from_env(cls) -> "Config":
        key = os.environ.get("LW_SECRET_KEY", "")
        if not key:
            raise SystemExit(
                "LW_SECRET_KEY is not set. Generate one with:\n"
                "  python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\"")
        return cls(
            database_url=os.environ.get("LW_DATABASE_URL", "sqlite:///./data/linkwatch.db"),
            secret_key=key,
            admin_password=os.environ.get("LW_ADMIN_PASSWORD") or None,
            public_url=os.environ.get("LW_PUBLIC_URL", "http://localhost:8080").rstrip("/"),
            poll_interval=max(60, int(os.environ.get("LW_POLL_INTERVAL", "300"))),
            raw_days=max(1, int(os.environ.get("LW_RAW_DAYS", "7"))),
            hourly_days=max(7, int(os.environ.get("LW_HOURLY_DAYS", "365"))),
            nss_dir=os.environ.get("LW_NSS_DIR", ""),
        )
