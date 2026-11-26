"""On-disk buffer for result batches the server has not acknowledged yet.

Each batch is written before it is sent and deleted when the server acks it,
so a dropped connection or a poller restart never loses polled data. When the
spool exceeds ``max_batches`` the oldest batches are dropped.
"""
from __future__ import annotations

import json
import os
from pathlib import Path


class Spool:
    def __init__(self, directory: Path, max_batches: int = 5000):
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.max_batches = max_batches

    def _path(self, batch_id: str) -> Path:
        safe = "".join(c for c in batch_id if c.isalnum() or c in "-_")
        return self.dir / f"{safe}.json"

    def put(self, batch: dict) -> None:
        tmp = self._path(batch["batch_id"]).with_suffix(".tmp")
        tmp.write_text(json.dumps(batch, separators=(",", ":")))
        os.replace(tmp, self._path(batch["batch_id"]))
        self._trim()

    def ack(self, batch_id: str) -> None:
        self._path(batch_id).unlink(missing_ok=True)

    def pending(self) -> list[dict]:
        out = []
        for p in sorted(self.dir.glob("*.json")):
            try:
                out.append(json.loads(p.read_text()))
            except (OSError, ValueError):
                p.unlink(missing_ok=True)
        return out

    def __len__(self) -> int:
        return sum(1 for _ in self.dir.glob("*.json"))

    def _trim(self) -> None:
        files = sorted(self.dir.glob("*.json"))
        for p in files[: max(0, len(files) - self.max_batches)]:
            p.unlink(missing_ok=True)
