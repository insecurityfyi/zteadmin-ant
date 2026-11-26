"""Engine, sessions and first-run seeding."""
from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from sqlalchemy import create_engine, event, inspect, select, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from .models import AlertRule, Base, Setting

DEFAULT_RULES = [
    # key, name, description, severity, threshold, polls
    ("device_down", "Device down", "No ping and no SNMP or API answer, or the platform reports it offline", "crit", None, 2),
    ("device_warn", "Platform reports a problem", "An integration reports the object as alerting or degraded", "warn", None, 1),
    ("high_cpu", "High CPU", "CPU above the threshold (%)", "warn", 85, 3),
    ("high_mem", "High memory", "Memory above the threshold (%)", "warn", 90, 3),
    ("port_down", "Port down", "Port is admin up but operationally down (only ports marked 'alert if down')", "crit", None, 1),
    ("port_errors", "Port errors", "In or out errors per poll above the threshold", "warn", 100, 1),
    ("bandwidth", "High bandwidth", "Port utilization above the threshold (%)", "warn", 85, 2),
    ("integration_failed", "Integration failing", "An API integration could not sync", "warn", None, 1),
    ("poller_offline", "Poller offline", "A poller has not been heard from for three poll intervals", "crit", None, 1),
]


def make_engine(url: str) -> Engine:
    kw: dict = {"future": True, "pool_pre_ping": True}
    if url.startswith("sqlite"):
        path = url.split("///", 1)[-1]
        if path and path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        kw["connect_args"] = {"check_same_thread": False}
        if path in ("", ":memory:"):
            from sqlalchemy.pool import StaticPool
            kw["poolclass"] = StaticPool
    engine = create_engine(url, **kw)
    if url.startswith("sqlite"):
        @event.listens_for(engine, "connect")
        def _fk(conn, _rec):  # enforce ON DELETE CASCADE in SQLite
            cur = conn.cursor()
            cur.execute("PRAGMA foreign_keys=ON")
            cur.execute("PRAGMA journal_mode=WAL")
            cur.close()
    return engine


class Database:
    def __init__(self, url: str):
        self.engine = make_engine(url)
        self.Session = sessionmaker(self.engine, expire_on_commit=False)

    def init(self) -> None:
        Base.metadata.create_all(self.engine)
        self.add_missing_columns()
        with self.session() as s:
            have = set(s.scalars(select(AlertRule.key)))
            for key, name, desc, sev, thr, polls in DEFAULT_RULES:
                if key not in have:
                    s.add(AlertRule(key=key, name=name, description=desc, severity=sev, threshold=thr, polls=polls))

    def add_missing_columns(self) -> None:
        """create_all() makes new tables but not new columns on old ones. Add nullable columns that are missing."""
        insp = inspect(self.engine)
        existing_tables = set(insp.get_table_names())
        with self.engine.begin() as conn:
            for table in Base.metadata.sorted_tables:
                if table.name not in existing_tables:
                    continue
                have = {c["name"] for c in insp.get_columns(table.name)}
                for col in table.columns:
                    if col.name in have or not col.nullable or col.primary_key:
                        continue
                    ddl = col.type.compile(dialect=self.engine.dialect)
                    conn.execute(text(f'ALTER TABLE {table.name} ADD COLUMN {col.name} {ddl}'))

    @contextmanager
    def session(self) -> Iterator[Session]:
        s = self.Session()
        try:
            yield s
            s.commit()
        except Exception:
            s.rollback()
            raise
        finally:
            s.close()


def get_setting(s: Session, key: str, default: str | None = None) -> str | None:
    row = s.get(Setting, key)
    return row.value if row else default


def set_setting(s: Session, key: str, value: str) -> None:
    row = s.get(Setting, key)
    if row:
        row.value = value
    else:
        s.add(Setting(key=key, value=value))
