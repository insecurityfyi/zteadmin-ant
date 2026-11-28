"""Database tables (SQLAlchemy 2.0). PostgreSQL in production, SQLite for tests and local runs."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    BigInteger,
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
    integrations: Mapped[list | None] = mapped_column(JSON)    # integration kinds its image supports (None = too old to say)
    features: Mapped[list | None] = mapped_column(JSON)        # optional tools its image has, e.g. ["mtr"]
    build: Mapped[str | None] = mapped_column(String(64))       # image build id (e.g. sha-0123abcd4567), "dev" for local builds


class PollerCommand(Base):
    """A command pushed to a poller from the Pollers page (reload config, update) and how it ended."""
    __tablename__ = "poller_commands"
    id: Mapped[int] = mapped_column(primary_key=True)
    poller_id: Mapped[int] = mapped_column(ForeignKey("pollers.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(16))                  # reload | update
    state: Mapped[str] = mapped_column(String(12), default="pending")   # pending | ok | failed
    detail: Mapped[str | None] = mapped_column(String(1000))
    username: Mapped[str | None] = mapped_column(String(64))
    requested_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime)
    before: Mapped[str | None] = mapped_column(String(120))        # version/build when it was sent
    after: Mapped[str | None] = mapped_column(String(120))         # version/build it reported back


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
    data: Mapped[dict | None] = mapped_column(JSON)    # latest extra payload (UniFi clients, SSIDs, WAN)
    poller: Mapped[Poller | None] = relationship()


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    full_name: Mapped[str | None] = mapped_column(String(120))
    email: Mapped[str | None] = mapped_column(String(255))
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16), default="viewer")   # admin | viewer
    disabled: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_login: Mapped[datetime | None] = mapped_column(DateTime)
    password_changed_at: Mapped[datetime | None] = mapped_column(DateTime)
    auth_source: Mapped[str | None] = mapped_column(String(16))      # None/local | saml (no usable password)
    external_id: Mapped[str | None] = mapped_column(String(255))     # Entra object ID for SSO users
    theme: Mapped[str | None] = mapped_column(String(16))           # None = the site default
    layout: Mapped[str | None] = mapped_column(String(16))          # top | sidebar; None = the site default or the theme's
    dashboard: Mapped[list | None] = mapped_column(JSON)            # widget layout; None = the site default


class AuditEvent(Base):
    """Who did what: sign-ins and every change made in the web UI."""
    __tablename__ = "audit_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    username: Mapped[str | None] = mapped_column(String(64))
    ip: Mapped[str | None] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(120))
    detail: Mapped[str | None] = mapped_column(String(500))


class Event(Base):
    """The event log: what happened to devices, ports, alerts, pollers and integrations, newest first."""
    __tablename__ = "events"
    __table_args__ = (Index("ix_event_dev_at", "device_id", "at"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    kind: Mapped[str] = mapped_column(String(16))          # device | port | alert | config | poller | integration
    severity: Mapped[str] = mapped_column(String(8), default="info")   # ok | info | warn | crit
    device_id: Mapped[int | None] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"))
    port_id: Mapped[int | None] = mapped_column(ForeignKey("ports.id", ondelete="SET NULL"))
    message: Mapped[str] = mapped_column(String(500))
    username: Mapped[str | None] = mapped_column(String(64))
    device: Mapped["Device | None"] = relationship()


class DiscoveryRule(Base):
    """A saved scan: address ranges, poller and credentials, optionally on a schedule with auto-add."""
    __tablename__ = "discovery_rules"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    targets: Mapped[str] = mapped_column(Text)
    poller_id: Mapped[int | None] = mapped_column(ForeignKey("pollers.id", ondelete="SET NULL"))
    profile_ids: Mapped[list] = mapped_column(JSON, default=list)
    interval_hours: Mapped[int] = mapped_column(Integer, default=0)      # 0 = only when run by hand
    auto_add: Mapped[str] = mapped_column(String(8), default="off")      # off | snmp | all
    site_name: Mapped[str | None] = mapped_column(String(120))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_run: Mapped[datetime | None] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
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
    rule_id: Mapped[int | None] = mapped_column(ForeignKey("discovery_rules.id", ondelete="SET NULL"))
    added: Mapped[int | None] = mapped_column(Integer)
    poller: Mapped[Poller | None] = relationship()
    rule: Mapped["DiscoveryRule | None"] = relationship()


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
    inventory: Mapped[list | None] = mapped_column(JSON)    # ENTITY-MIB parts: chassis, modules, PSUs, fans
    access: Mapped[str | None] = mapped_column(String(8))   # remote access override: ssh | rdp | both | none (None = by OS)
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
    in_disc_rate: Mapped[float | None] = mapped_column(Float)   # discards per poll interval
    out_disc_rate: Mapped[float | None] = mapped_column(Float)
    last_in_discards: Mapped[float | None] = mapped_column(Float)
    last_out_discards: Mapped[float | None] = mapped_column(Float)
    last_ts: Mapped[float | None] = mapped_column(Float)
    device: Mapped[Device] = relationship(back_populates="ports")


class Sensor(Base):
    """A health reading on a device: temperature, fan, voltage, power, a state (fan/PSU OK), or storage use."""
    __tablename__ = "sensors"
    __table_args__ = (UniqueConstraint("device_id", "key", name="uq_sensor_key"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    key: Mapped[str] = mapped_column(String(80))
    # temperature | fan | voltage | current | power | humidity | state | storage | system | diskio | custom
    kind: Mapped[str] = mapped_column(String(24))
    name: Mapped[str] = mapped_column(String(255))
    unit: Mapped[str] = mapped_column(String(16), default="")
    value: Mapped[float | None] = mapped_column(Float)
    high: Mapped[float | None] = mapped_column(Float)   # the device's own threshold, when it reports one
    status: Mapped[str] = mapped_column(String(8), default="ok")   # ok | warn | crit
    extra: Mapped[dict | None] = mapped_column(JSON)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    device: Mapped["Device"] = relationship()


class SensorMetric(Base):
    __tablename__ = "sensor_metrics"
    __table_args__ = (Index("ix_senmet_sensor_ts", "sensor_id", "ts"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    sensor_id: Mapped[int] = mapped_column(ForeignKey("sensors.id", ondelete="CASCADE"))
    ts: Mapped[datetime] = mapped_column(DateTime)
    hourly: Mapped[bool] = mapped_column(Boolean, default=False)
    value: Mapped[float | None] = mapped_column(Float)


class Neighbor(Base):
    """A link seen over LLDP or CDP (or reported by an integration): this device's port to a remote device's port."""
    __tablename__ = "neighbors"
    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"), index=True)
    port_id: Mapped[int | None] = mapped_column(ForeignKey("ports.id", ondelete="SET NULL"))
    protocol: Mapped[str] = mapped_column(String(12))    # lldp | cdp | unifi | meraki
    local_port: Mapped[str | None] = mapped_column(String(255))
    remote_name: Mapped[str | None] = mapped_column(String(255))
    remote_port: Mapped[str | None] = mapped_column(String(255))
    remote_ip: Mapped[str | None] = mapped_column(String(64))
    remote_chassis: Mapped[str | None] = mapped_column(String(64))
    remote_platform: Mapped[str | None] = mapped_column(String(255))
    remote_device_id: Mapped[int | None] = mapped_column(ForeignKey("devices.id", ondelete="SET NULL"))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    device: Mapped["Device"] = relationship(foreign_keys=[device_id])
    remote_device: Mapped["Device | None"] = relationship(foreign_keys=[remote_device_id])
    port: Mapped["Port | None"] = relationship()


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
    in_disc: Mapped[float | None] = mapped_column(Float)
    out_disc: Mapped[float | None] = mapped_column(Float)


class IntegrationMetric(Base):
    """Time series an integration reports beyond devices and ports, e.g. "wan:WAN1", "ssid:Office", "client:<mac>".

    a / b / c depend on the key: for wan, ssid, ap and client keys a = download b/s, b = upload b/s;
    c = latency ms (wan), clients (ssid, ap) or signal dBm (client). For "clients": a = total, b = wireless, c = wired.
    """
    __tablename__ = "integration_metrics"
    __table_args__ = (Index("ix_intmet_key_ts", "integration_id", "key", "ts"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    integration_id: Mapped[int] = mapped_column(ForeignKey("integrations.id", ondelete="CASCADE"))
    key: Mapped[str] = mapped_column(String(160))
    ts: Mapped[datetime] = mapped_column(DateTime)
    hourly: Mapped[bool] = mapped_column(Boolean, default=False)
    a: Mapped[float | None] = mapped_column(Float)
    b: Mapped[float | None] = mapped_column(Float)
    c: Mapped[float | None] = mapped_column(Float)


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
    # custom rules (built with the rule builder) set these; built-in rules leave them empty
    entity: Mapped[str | None] = mapped_column(String(16))      # device | port | sensor
    metric: Mapped[str | None] = mapped_column(String(32))
    op: Mapped[str | None] = mapped_column(String(4))           # > >= < <= == !=
    value_text: Mapped[str | None] = mapped_column(String(64))  # for state metrics (status, link state)
    scope: Mapped[dict | None] = mapped_column(JSON)            # type, site, name, source, port, sensor_kind, sensor_name
    created_by: Mapped[str | None] = mapped_column(String(64))


class AlertPending(Base):
    """Consecutive polls a custom rule has matched for one object, until it reaches the rule's poll count."""
    __tablename__ = "alert_pending"
    rule_key: Mapped[str] = mapped_column(String(40), primary_key=True)
    ref: Mapped[str] = mapped_column(String(80), primary_key=True)
    hits: Mapped[int] = mapped_column(Integer, default=0)


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


class PushSubscription(Base):
    """One browser or installed app that gets alert notifications (Web Push), signed in as a user."""
    __tablename__ = "push_subscriptions"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    endpoint: Mapped[str] = mapped_column(Text)
    endpoint_hash: Mapped[str] = mapped_column(String(64), unique=True)
    p256dh: Mapped[str] = mapped_column(String(200))
    auth: Mapped[str] = mapped_column(String(64))
    label: Mapped[str | None] = mapped_column(String(120))       # "iPhone · Safari", from the user agent
    min_severity: Mapped[str] = mapped_column(String(8), default="warn")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_sent: Mapped[datetime | None] = mapped_column(DateTime)
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


class PathProbe(Base):
    """A hop-by-hop path test (mtr) that one or more pollers run against a target on a schedule."""
    __tablename__ = "path_probes"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    target: Mapped[str] = mapped_column(String(255))
    protocol: Mapped[str] = mapped_column(String(4), default="icmp")    # icmp | udp | tcp
    port: Mapped[int | None] = mapped_column(Integer)
    count: Mapped[int] = mapped_column(Integer, default=10)              # packets per hop per run
    interval_s: Mapped[int] = mapped_column(Integer, default=300)
    poller_ids: Mapped[list | None] = mapped_column(JSON)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    loss_pct: Mapped[float | None] = mapped_column(Float)                # alert thresholds; empty = the built-in rule's
    latency_ms: Mapped[float | None] = mapped_column(Float)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class PathResult(Base):
    """One run of a path probe from one poller. hops: [{n, ip, loss, sent, last, avg, best, worst, stdev, jitter}]."""
    __tablename__ = "path_results"
    __table_args__ = (Index("ix_pathres_probe_ts", "probe_id", "poller_id", "ts"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    probe_id: Mapped[int] = mapped_column(ForeignKey("path_probes.id", ondelete="CASCADE"))
    poller_id: Mapped[int] = mapped_column(Integer)
    ts: Mapped[datetime] = mapped_column(DateTime)
    ok: Mapped[bool] = mapped_column(Boolean, default=False)
    error: Mapped[str | None] = mapped_column(String(500))
    hops: Mapped[list | None] = mapped_column(JSON)
    reached: Mapped[bool] = mapped_column(Boolean, default=False)
    hop_count: Mapped[int | None] = mapped_column(Integer)
    loss_pct: Mapped[float | None] = mapped_column(Float)      # at the target (last hop)
    avg_ms: Mapped[float | None] = mapped_column(Float)
    best_ms: Mapped[float | None] = mapped_column(Float)
    worst_ms: Mapped[float | None] = mapped_column(Float)
    jitter_ms: Mapped[float | None] = mapped_column(Float)
    path_hash: Mapped[str | None] = mapped_column(String(16))
    asns: Mapped[list | None] = mapped_column(JSON)            # AS path, consecutive duplicates removed
    changed: Mapped[str | None] = mapped_column(String(8))     # route | asn, compared with the previous run


class AsnInfo(Base):
    """Cached origin AS and holder for an address seen on a path (RIPEstat)."""
    __tablename__ = "asn_info"
    ip: Mapped[str] = mapped_column(String(45), primary_key=True)
    asn: Mapped[int | None] = mapped_column(Integer)
    holder: Mapped[str | None] = mapped_column(String(255))
    prefix: Mapped[str | None] = mapped_column(String(64))
    fetched_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class ProcessedBatch(Base):
    """Batch IDs already ingested, so a batch resent after a reconnect is not counted twice."""
    __tablename__ = "processed_batches"
    batch_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    poller_id: Mapped[int] = mapped_column(Integer)
    at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)


class SshTarget(Base):
    """A host an admin has opened an SSH console to through a poller: its pinned host key and, if saved, the login.

    The host key is trusted on first use and checked on every later connection. Saved credentials are sealed
    with the server's Fernet key (``cred_enc``); only the user name is kept readable, to prefill the form."""
    __tablename__ = "ssh_targets"
    __table_args__ = (UniqueConstraint("poller_id", "host", "port", name="uq_ssh_target"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    poller_id: Mapped[int] = mapped_column(ForeignKey("pollers.id", ondelete="CASCADE"))
    host: Mapped[str] = mapped_column(String(255))
    port: Mapped[int] = mapped_column(Integer, default=22)
    device_id: Mapped[int | None] = mapped_column(ForeignKey("devices.id", ondelete="SET NULL"))
    host_key: Mapped[str | None] = mapped_column(Text)              # OpenSSH public key line
    fingerprint: Mapped[str | None] = mapped_column(String(128))    # SHA256:...
    username: Mapped[str | None] = mapped_column(String(128))
    cred_enc: Mapped[str | None] = mapped_column(Text)              # sealed {"password", "key", "passphrase"}
    cred_saved_by: Mapped[str | None] = mapped_column(String(64))
    cred_saved_at: Mapped[datetime | None] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_used: Mapped[datetime | None] = mapped_column(DateTime)
    last_user: Mapped[str | None] = mapped_column(String(64))


class CustomOid(Base):
    """An OID people added themselves. Pollers read it from every device in scope; each value becomes a sensor
    (kind "custom"), so it is graphed on the device's Health tab and can drive alert rules."""
    __tablename__ = "custom_oids"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    oid: Mapped[str] = mapped_column(String(255))                   # numeric, no leading dot
    mib_name: Mapped[str | None] = mapped_column(String(255))       # e.g. ACME-MIB::acmeCpuLoad, for display
    mode: Mapped[str] = mapped_column(String(8), default="get")     # get (one value) | walk (a table column)
    label_oid: Mapped[str | None] = mapped_column(String(255))      # walk only: the column that names each row
    value_type: Mapped[str] = mapped_column(String(12), default="gauge")   # gauge | counter | state | text
    scale: Mapped[float | None] = mapped_column(Float)              # multiply the reading (or the rate) by this
    unit: Mapped[str | None] = mapped_column(String(16))
    states: Mapped[dict | None] = mapped_column(JSON)               # state: {"1": "up", "2": "down"}
    ok_values: Mapped[str | None] = mapped_column(String(120))      # state: "1" or "1,3"; anything else is critical
    category: Mapped[str | None] = mapped_column(String(60))        # heading on the Health tab (default "Custom")
    match_type: Mapped[str | None] = mapped_column(String(40))      # device type, e.g. Firewall
    match_sys_oid: Mapped[str | None] = mapped_column(String(255))  # sysObjectID prefix, e.g. 1.3.6.1.4.1.9 (Cisco)
    match_name: Mapped[str | None] = mapped_column(String(255))     # hostname or IP globs, comma separated
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    description: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class MibModule(Base):
    """A MIB file someone uploaded, compiled to a list of its objects so names can be turned into OIDs."""
    __tablename__ = "mib_modules"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True)     # the module name inside the file
    filename: Mapped[str | None] = mapped_column(String(255))
    text: Mapped[str] = mapped_column(Text)
    objects: Mapped[list | None] = mapped_column(JSON)              # [{name, oid, node, type, units, access, states, descr}]
    error: Mapped[str | None] = mapped_column(Text)                 # why it could not be compiled (often a missing import)
    uploaded_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class NssToken(Base):
    """A bearer token a Zscaler Cloud NSS feed sends to push logs to /api/nss/ingest. Only the hash is kept."""
    __tablename__ = "nss_tokens"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    prefix: Mapped[str] = mapped_column(String(16))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_used: Mapped[datetime | None] = mapped_column(DateTime)
    last_ip: Mapped[str | None] = mapped_column(String(64))
    events: Mapped[int | None] = mapped_column(BigInteger, default=0)  # records accepted with this token
