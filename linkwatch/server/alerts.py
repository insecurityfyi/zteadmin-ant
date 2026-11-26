"""Alert evaluation. Alerts open when a rule's condition holds and resolve on their own when it clears."""
from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import events
from .models import Alert, AlertRule, Device, DeviceMetric, PortMetric, utcnow

SEVERITY_ORDER = {"info": 0, "warn": 1, "crit": 2}


@dataclass
class AlertEvent:
    kind: str          # opened | resolved
    alert_id: int
    severity: str
    title: str
    detail: str | None
    device: str | None


class Alerter:
    """Collects alert changes during one database session; events are sent after commit."""

    def __init__(self, s: Session):
        self.s = s
        self.rules = {r.key: r for r in s.scalars(select(AlertRule))}
        self.events: list[AlertEvent] = []
        self.open = {(a.rule_key, a.ref): a for a in s.scalars(select(Alert).where(Alert.state.in_(("open", "ack"))))}

    def rule(self, key: str) -> AlertRule | None:
        r = self.rules.get(key)
        return r if r and r.enabled else None

    def set(self, key: str, ref: str, active: bool, title: str = "", detail: str | None = None,
            device: Device | None = None) -> None:
        rule = self.rules.get(key)
        if rule is None:
            return
        active = active and rule.enabled
        current = self.open.get((key, ref))
        if active and current is None:
            alert = Alert(rule_key=key, ref=ref, device_id=device.id if device else None, severity=rule.severity,
                          title=title or rule.name, detail=(detail or "")[:500] or None, state="open", opened_at=utcnow())
            self.s.add(alert)
            self.s.flush()
            self.open[(key, ref)] = alert
            events.log(self.s, "alert", f"Alert opened: {alert.title}", alert.severity, device)
            self.events.append(AlertEvent("opened", alert.id, alert.severity, alert.title, alert.detail,
                                          device.hostname if device else None))
        elif active and current is not None:
            if detail and current.detail != detail[:500]:
                current.detail = detail[:500]
        elif not active and current is not None:
            current.state = "resolved"
            current.resolved_at = utcnow()
            del self.open[(key, ref)]
            events.log(self.s, "alert", f"Alert resolved: {current.title}", "ok", device or current.device_id)
            self.events.append(AlertEvent("resolved", current.id, current.severity, current.title, current.detail,
                                          device.hostname if device else None))

    # device rules -----------------------------------------------------------
    def evaluate_device(self, dev: Device) -> None:
        ref = f"device:{dev.id}"
        if dev.disabled:
            for key in ("device_down", "device_warn", "high_cpu", "high_mem"):
                self.set(key, ref, False, device=dev)
            return
        down = dev.status == "down"
        self.set("device_down", ref, down, f"Device down: {dev.hostname}", dev.status_reason, dev)
        self.set("device_warn", ref, dev.status == "warn" and dev.source not in ("snmp", "ping"),
                 f"Problem reported: {dev.hostname}", dev.status_reason or dev.detail, dev)
        for key, attr, label in (("high_cpu", "cpu", "CPU"), ("high_mem", "mem", "Memory")):
            rule = self.rule(key)
            if not rule or rule.threshold is None or down:
                self.set(key, ref, False, device=dev)
                continue
            recent = self.s.scalars(select(getattr(DeviceMetric, attr)).where(
                DeviceMetric.device_id == dev.id, DeviceMetric.hourly.is_(False)).order_by(DeviceMetric.ts.desc()).limit(rule.polls)).all()
            hot = len(recent) >= rule.polls and all(v is not None and v > rule.threshold for v in recent)
            self.set(key, ref, hot, f"High {label.lower()}: {dev.hostname}",
                     f"{label} {recent[0]:.0f}% for {rule.polls} polls, threshold {rule.threshold:.0f}%" if hot else None, dev)
        self.evaluate_ports(dev)
        self.evaluate_sensors(dev)

    def evaluate_sensors(self, dev: Device) -> None:
        from .models import Sensor
        rule, disk = self.rule("sensor"), self.rule("storage_full")
        open_refs = {ref for (key, ref) in self.open if key in ("sensor", "storage_full")}
        live = set()
        for sen in self.s.scalars(select(Sensor).where(Sensor.device_id == dev.id)):
            ref = f"sensor:{sen.id}"
            live.add(ref)
            label = f"{dev.hostname} {sen.name}"
            if sen.kind == "storage":
                full = bool(disk and disk.threshold is not None and sen.value is not None and sen.value > disk.threshold)
                self.set("storage_full", ref, full, f"Storage nearly full: {label}",
                         f"{sen.value:.0f}% used, threshold {disk.threshold:.0f}%" if full else None, dev)
                continue
            hot = sen.kind == "temperature" and sen.value is not None and (
                (sen.high is not None and sen.value >= sen.high) or
                (rule is not None and rule.threshold is not None and sen.value > rule.threshold))
            bad = sen.status in ("warn", "crit") or hot
            unit = f" {sen.unit}" if sen.unit else ""
            self.set("sensor", ref, bool(rule and bad), f"Sensor problem: {label}",
                     (f"{sen.status}, reading {sen.value:g}{unit}" if sen.value is not None else sen.status) if bad else None, dev)
        for key, ref in [(k, r) for (k, r) in list(self.open) if k in ("sensor", "storage_full")]:
            if ref in open_refs and ref not in live and self.open[(key, ref)].device_id == dev.id:
                self.set(key, ref, False, device=dev)        # the sensor went away

    def evaluate_ports(self, dev: Device) -> None:
        down_rule, err_rule, bw_rule = self.rule("port_down"), self.rule("port_errors"), self.rule("bandwidth")
        dev_down = dev.status == "down"
        for p in dev.ports:
            ref = f"port:{p.id}"
            label = f"{dev.hostname} {p.name}"
            self.set("port_down", ref, bool(down_rule and p.alert_on_down and not dev_down and p.admin == "up" and p.oper != "up"),
                     f"Port down: {label}", f"{p.alias or 'No description'}, oper {p.oper}", dev)
            errs = max(p.in_err_rate or 0, p.out_err_rate or 0)
            self.set("port_errors", ref, bool(err_rule and err_rule.threshold is not None and errs > err_rule.threshold),
                     f"Port errors: {label}", f"{p.in_err_rate or 0:.0f} in / {p.out_err_rate or 0:.0f} out errors per poll", dev)
            hot = False
            if bw_rule and bw_rule.threshold is not None and p.speed_mbps and (p.util_pct or 0) > bw_rule.threshold:
                recent = self.s.execute(select(PortMetric.in_bps, PortMetric.out_bps).where(
                    PortMetric.port_id == p.id, PortMetric.hourly.is_(False)).order_by(PortMetric.ts.desc()).limit(bw_rule.polls)).all()
                cap = p.speed_mbps * 1e6
                hot = len(recent) >= bw_rule.polls and all(max(a or 0, b or 0) / cap * 100 > bw_rule.threshold for a, b in recent)
            self.set("bandwidth", ref, hot, f"High bandwidth: {label}",
                     f"{p.util_pct or 0:.0f}% of {p.speed_mbps} Mb/s" if hot else None, dev)
