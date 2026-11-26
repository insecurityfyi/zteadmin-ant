"""Database tables (SQLAlchemy 2.0). PostgreSQL in production, SQLite for tests and local runs."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    """Naive UTC; every timestamp in the database is UTC."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Base(DeclarativeBase):
    pass


class Setting(Base):
    __tablename__ = "settings"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text)


class Site(Base):
    __tablename__ = "sites"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True)


class Poller(Base):
    __tablename__ = "pollers"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    key_hash: Mapped[str] = mapped_column(String(64), unique=True)
    hostname: Mapped[str | None] = mapped_column(String(255))
    version: Mapped[str | None] = mapped_column(String(32))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime)
    last_ip: Mapped[str | None] = mapped_column(String(64))
    last_cycle_ms: Mapped[int | None] = mapped_column(Integer)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)


class EnrollToken(Base):
    __tablename__ = "enroll_tokens"
    id: Mapped[int] = mapped_column(primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    hint: Mapped[str] = mapped_column(String(16))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    used_at: Mapped[datetime | None] = mapped_column(DateTime)
    poller_id: Mapped[int | None] = mapped_column(ForeignKey("pollers.id", ondelete="SET NULL"))


class SnmpProfile(Base):
    """A named set of SNMP credentials shared by many devices. Stored encrypted."""
    __tablename__ = "snmp_profiles"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    version: Mapped[str] = mapped_column(String(4))
    config_enc: Mapped[str] = mapped_column(Text)


class Integration(Base):
    __tablename__ = "integrations"
    id: Mapped[int] = mapped_column(primary_key=True)
    kind: Mapped[str] = mapped_column(String(32))
    name: Mapped[str] = mapped_column(String(120))
    config_enc: Mapped[str] = mapped_column(Text)
    poller_id: Mapped[int | None] = mapped_column(ForeignKey("pollers.id", ondelete="SET NULL"))
    site_id: Mapped[int | None] = mapped_column(ForeignKey("sites.id", ondelete="SET NULL"))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_sync: Mapped[datetime | None] = mapped_column(DateTime)
    status: Mapped[str] = mapped_column(String(16), default="never")   # never | ok | partial | error
    last_error: Mapped[str | None] = mapped_column(Text)
    object_count: Mapped[int] = mapped_column(Integer, default=0)
    poller: Mapped[Poller | None] = relationship()


class DiscoveryJob(Base):
    """A subnet scan run by a poller: ping sweep plus an SNMP probe with saved credentials."""
    __tablename__ = "discovery_jobs"
    id: Mapped[int] = mapped_column(primary_key=True)
    poller_id: Mapped[int | None] = mapped_column(ForeignKey("pollers.id", ondelete="SET NULL"))
    targets: Mapped[str] = mapped_column(Text)
    profile_ids: Mapped[list] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(16), default="queued")   # queued | running | done | failed
    total: Mapped[int] = mapped_column(Integer, default=0)
    scanned: Mapped[int] = mapped_column(Integer, default=0)
    results: Mapped[list] = mapped_column(JSON, default=list)
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime)
    poller: Mapped[Poller | None] = relationship()


class Device(Base):
    __tablename__ = "devices"
    __table_args__ = (UniqueConstraint("integration_id", "external_id", name="uq_device_external"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    hostname: Mapped[str] = mapped_column(String(255))
    ip: Mapped[str | None] = mapped_column(String(255), index=True)
    type: Mapped[str] = mapped_column(String(40), default="Network")
    platform: Mapped[str | None] = mapped_column(String(255))
    site_id: Mapped[int | None] = mapped_column(ForeignKey("sites.id", ondelete="SET NULL"))
    poller_id: Mapped[int | None] = mapped_column(ForeignKey("pollers.id", ondelete="SET NULL"))
    snmp_profile_id: Mapped[int | None] = mapped_column(ForeignKey("snmp_profiles.id", ondelete="SET NULL"))
    ping: Mapped[bool] = mapped_column(Boolean, default=True)
    disabled: Mapped[bool] = mapped_column(Boolean, default=False)
    # set when the device came from (or was matched to) an API integration
    integration_id: Mapped[int | None] = mapped_column(ForeignKey("integrations.id", ondelete="SET NULL"))
    external_id: Mapped[str | None] = mapped_column(String(255))
    source: Mapped[str] = mapped_column(String(32), default="snmp")   # snmp | ping | <integration kind>
    status: Mapped[str] = mapped_column(String(16), default="unknown")  # up | down | warn | unknown | off
    status_since: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    status_reason: Mapped[str | None] = mapped_column(String(255))
    fail_count: Mapped[int] = mapped_column(Integer, default=0)
    last_polled: Mapped[datetime | None] = mapped_column(DateTime)
    poll_ms: Mapped[int | None] = mapped_column(Integer)
    sys_descr: Mapped[str | None] = mapped_column(Text)
    sys_object_id: Mapped[str | None] = mapped_column(String(255))
    sys_name: Mapped[str | None] = mapped_column(String(255))
    sys_location: Mapped[str | None] = mapped_column(String(255))
    serial: Mapped[str | None] = mapped_column(String(128))
    uptime_s: Mapped[int | None] = mapped_column(Integer)
    cpu: Mapped[float | None] = mapped_column(Float)
    mem: Mapped[float | None] = mapped_column(Float)
    ping_ms: Mapped[float | None] = mapped_column(Float)
    loss_pct: Mapped[float | None] = mapped_column(Float)
    detail: Mapped[str | None] = mapped_column(String(500))
    extra: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    site: Mapped[Site | None] = relationship()
    poller: Mapped[Poller | None] = relationship()
    snmp_profile: Mapped[SnmpProfile | None] = relationship()
    integration: Mapped[Integration | None] = relationship()
    ports: Mapped[list["Port"]] = relationship(back_populates="device", cascade="all, delete-orphan", order_by="Port.ifindex")


class Port(Base):
    __tablename__ = "ports"
    __table_args__ = (UniqueConstraint("device_id", "ifindex", name="uq_port_ifindex"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    ifindex: Mapped[int] = mapped_column(Integer)
    name: Mapped[str] = mapped_column(String(255))
    alias: Mapped[str | None] = mapped_column(String(255))
    speed_mbps: Mapped[int | None] = mapped_column(Integer)
    admin: Mapped[str | None] = mapped_column(String(16))
    oper: Mapped[str | None] = mapped_column(String(16))
    alert_on_down: Mapped[bool] = mapped_column(Boolean, default=False)
    in_bps: Mapped[float | None] = mapped_column(Float)
    out_bps: Mapped[float | None] = mapped_column(Float)
    in_err_rate: Mapped[float | None] = mapped_column(Float)    # errors per poll interval
    out_err_rate: Mapped[float | None] = mapped_column(Float)
    util_pct: Mapped[float | None] = mapped_column(Float)
    last_in_octets: Mapped[float | None] = mapped_column(Float)
    last_out_octets: Mapped[float | None] = mapped_column(Float)
    last_in_errors: Mapped[float | None] = mapped_column(Float)
    last_out_errors: Mapped[float | None] = mapped_column(Float)
    last_ts: Mapped[float | None] = mapped_column(Float)
    device: Mapped[Device] = relationship(back_populates="ports")


class DeviceMetric(Base):
    __tablename__ = "device_metrics"
    __table_args__ = (Index("ix_devmet_dev_ts", "device_id", "ts"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"))
    ts: Mapped[datetime] = mapped_column(DateTime)
    hourly: Mapped[bool] = mapped_column(Boolean, default=False)
    cpu: Mapped[float | None] = mapped_column(Float)
    mem: Mapped[float | None] = mapped_column(Float)
    ping_ms: Mapped[float | None] = mapped_column(Float)
    loss_pct: Mapped[float | None] = mapped_column(Float)


class PortMetric(Base):
    __tablename__ = "port_metrics"
    __table_args__ = (Index("ix_portmet_port_ts", "port_id", "ts"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    port_id: Mapped[int] = mapped_column(ForeignKey("ports.id", ondelete="CASCADE"))
    ts: Mapped[datetime] = mapped_column(DateTime)
    hourly: Mapped[bool] = mapped_column(Boolean, default=False)
    in_bps: Mapped[float | None] = mapped_column(Float)
    out_bps: Mapped[float | None] = mapped_column(Float)
    in_err: Mapped[float | None] = mapped_column(Float)
    out_err: Mapped[float | None] = mapped_column(Float)


class AlertRule(Base):
    __tablename__ = "alert_rules"
    id: Mapped[int] = mapped_column(primary_key=True)
    key: Mapped[str] = mapped_column(String(40), unique=True)
    name: Mapped[str] = mapped_column(String(120))
    description: Mapped[str] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(8))       # crit | warn | info
    threshold: Mapped[float | None] = mapped_column(Float)
    polls: Mapped[int] = mapped_column(Integer, default=1)  # consecutive polls before it fires
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (Index("ix_alert_state", "state"), Index("ix_alert_ref", "rule_key", "ref"))
    id: Mapped[int] = mapped_column(primary_key=True)
    rule_key: Mapped[str] = mapped_column(String(40))
    ref: Mapped[str] = mapped_column(String(80))            # what it is about, e.g. "device:12", "port:301"
    device_id: Mapped[int | None] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"))
    severity: Mapped[str] = mapped_column(String(8))
    title: Mapped[str] = mapped_column(String(255))
    detail: Mapped[str | None] = mapped_column(String(500))
    state: Mapped[str] = mapped_column(String(10), default="open")   # open | ack | resolved
    opened_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime)
    acked_at: Mapped[datetime | None] = mapped_column(DateTime)
    notified: Mapped[str | None] = mapped_column(String(255))
    device: Mapped[Device | None] = relationship()


class Transport(Base):
    __tablename__ = "transports"
    id: Mapped[int] = mapped_column(primary_key=True)
    kind: Mapped[str] = mapped_column(String(16))           # email | teams | slack | webhook
    name: Mapped[str] = mapped_column(String(120))
    config_enc: Mapped[str] = mapped_column(Text)
    min_severity: Mapped[str] = mapped_column(String(8), default="warn")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_result: Mapped[str | None] = mapped_column(String(255))


class ApiKey(Base):
    __tablename__ = "api_keys"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    prefix: Mapped[str] = mapped_column(String(16))
    key_hash: Mapped[str] = mapped_column(String(64), unique=True)
    scope: Mapped[str] = mapped_column(String(4), default="ro")   # ro | rw
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_used: Mapped[datetime | None] = mapped_column(DateTime)


class ProcessedBatch(Base):
    """Batch IDs already ingested, so a batch resent after a reconnect is not counted twice."""
    __tablename__ = "processed_batches"
    batch_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    poller_id: Mapped[int] = mapped_column(Integer)
    at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
