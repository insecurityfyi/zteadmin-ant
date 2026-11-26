"""Runtime configuration read from environment variables."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Config:
    data_dir: Path
    secret_key: str | None
    password: str | None
    demo: bool
    sync_minutes: int

    @classmethod
    def from_env(cls) -> "Config":
        return cls(
            data_dir=Path(os.environ.get("TOOLBOX_DATA_DIR", "./data")),
            secret_key=os.environ.get("TOOLBOX_SECRET_KEY") or None,
            password=os.environ.get("TOOLBOX_PASSWORD") or None,
            demo=os.environ.get("TOOLBOX_DEMO", "1") not in ("0", "false", "no"),
            sync_minutes=max(5, int(os.environ.get("TOOLBOX_SYNC_MINUTES", "60"))),
        )
