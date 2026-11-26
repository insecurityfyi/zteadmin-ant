"""SQLite storage: settings, API snapshots and imported log events."""
from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS snapshots (
    kind TEXT PRIMARY KEY, fetched_at TEXT NOT NULL, demo INTEGER NOT NULL DEFAULT 0, data TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS log_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    user TEXT,
    department TEXT,
    location TEXT,
    client_ip TEXT,
    destination TEXT,
    category TEXT,
    action TEXT,
    policy_type TEXT,
    rule_label TEXT,
    bytes_in INTEGER DEFAULT 0,
    bytes_out INTEGER DEFAULT 0,
    import_id INTEGER,
    raw TEXT
);
CREATE INDEX IF NOT EXISTS ix_log_ts ON log_events(ts);
CREATE INDEX IF NOT EXISTS ix_log_user ON log_events(user);
CREATE INDEX IF NOT EXISTS ix_log_rule ON log_events(rule_label);
CREATE TABLE IF NOT EXISTS imports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    feed TEXT NOT NULL,
    rows INTEGER NOT NULL,
    skipped INTEGER NOT NULL,
    unmapped TEXT,
    demo INTEGER NOT NULL DEFAULT 0,
    imported_at TEXT NOT NULL
);
"""

LOG_COLUMNS = (
    "ts", "user", "department", "location", "client_ip", "destination", "category",
    "action", "policy_type", "rule_label", "bytes_in", "bytes_out", "import_id", "raw",
)


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Store:
    def __init__(self, path: Path | str):
        if str(path) != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            self._conn.executescript(SCHEMA)

    # settings -----------------------------------------------------------
    def get_setting(self, key: str, default: str | None = None) -> str | None:
        row = self._conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return row["value"] if row else default

    def set_setting(self, key: str, value: str) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )

    # snapshots ----------------------------------------------------------
    def put_snapshot(self, kind: str, data: Any, demo: bool = False) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO snapshots(kind,fetched_at,demo,data) VALUES(?,?,?,?) "
                "ON CONFLICT(kind) DO UPDATE SET fetched_at=excluded.fetched_at, demo=excluded.demo, data=excluded.data",
                (kind, utcnow(), int(demo), json.dumps(data)),
            )

    def get_snapshot(self, kind: str) -> dict | None:
        row = self._conn.execute("SELECT * FROM snapshots WHERE kind=?", (kind,)).fetchone()
        if not row:
            return None
        return {"kind": kind, "fetched_at": row["fetched_at"], "demo": bool(row["demo"]), "data": json.loads(row["data"])}

    def snapshot_data(self, kind: str, default: Any = None) -> Any:
        snap = self.get_snapshot(kind)
        return snap["data"] if snap else default

    def has_live_data(self) -> bool:
        return self._conn.execute("SELECT 1 FROM snapshots WHERE demo=0 LIMIT 1").fetchone() is not None

    def clear_demo(self) -> None:
        with self._lock, self._conn:
            self._conn.execute("DELETE FROM snapshots WHERE demo=1")
            self._conn.execute("DELETE FROM log_events WHERE import_id IN (SELECT id FROM imports WHERE demo=1)")
            self._conn.execute("DELETE FROM imports WHERE demo=1")

    # logs ---------------------------------------------------------------
    def add_import(self, filename: str, feed: str, rows: int, skipped: int, unmapped: list[str], demo: bool = False) -> int:
        with self._lock, self._conn:
            cur = self._conn.execute(
                "INSERT INTO imports(filename,feed,rows,skipped,unmapped,demo,imported_at) VALUES(?,?,?,?,?,?,?)",
                (filename, feed, rows, skipped, json.dumps(unmapped), int(demo), utcnow()),
            )
            return int(cur.lastrowid)

    def update_import_counts(self, import_id: int, rows: int, skipped: int) -> None:
        with self._lock, self._conn:
            self._conn.execute("UPDATE imports SET rows=?, skipped=? WHERE id=?", (rows, skipped, import_id))

    def add_events(self, events: Iterable[dict]) -> int:
        rows = [tuple(e.get(c) for c in LOG_COLUMNS) for e in events]
        with self._lock, self._conn:
            self._conn.executemany(
                f"INSERT INTO log_events({','.join(LOG_COLUMNS)}) VALUES({','.join('?' * len(LOG_COLUMNS))})", rows
            )
        return len(rows)

    def imports(self) -> list[dict]:
        rows = self._conn.execute("SELECT * FROM imports ORDER BY id DESC").fetchall()
        return [dict(r) | {"unmapped": json.loads(r["unmapped"] or "[]")} for r in rows]

    def query(self, sql: str, params: Iterable[Any] = ()) -> list[dict]:
        return [dict(r) for r in self._conn.execute(sql, tuple(params)).fetchall()]

    def prune_events(self, before_iso: str) -> int:
        with self._lock, self._conn:
            return self._conn.execute("DELETE FROM log_events WHERE ts < ?", (before_iso,)).rowcount
