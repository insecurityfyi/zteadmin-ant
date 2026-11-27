"""Alert rules people build themselves: "when <metric> of a <device|port|sensor> in <scope> is <op> <value> for N polls".

Custom rules are ``AlertRule`` rows with ``entity`` set. They are evaluated with the built-in rules every time a device
is polled or synced, open alerts through the same ``Alerter`` (so notifications, the event log and auto-resolve all work
the same), and count consecutive matching polls in ``alert_pending``.
"""
from __future__ import annotations

import fnmatch
import secrets
from dataclasses import dataclass
from typing import Any, Callable, Iterator

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .models import AlertPending, AlertRule, Device, Sensor


@dataclass(frozen=True)
class Metric:
    label: str
    get: Callable[[Any], Any]
    unit: str = ""
    states: tuple = ()           # non-empty: a state metric compared with == / !=
    when_down: bool = False      # still meaningful while the device is down


def _ports_down(d: Device) -> int:
    return sum(1 for p in d.ports if p.admin == "up" and p.oper not in (None, "up"))


METRICS: dict[str, dict[str, Metric]] = {
    "device": {
        "status": Metric("Status", lambda d: d.status, states=("up", "down", "warn", "unknown"), when_down=True),
        "cpu": Metric("CPU", lambda d: d.cpu, "%"),
        "mem": Metric("Memory", lambda d: d.mem, "%"),
        "ping_ms": Metric("Latency", lambda d: d.ping_ms, "ms", when_down=True),
        "loss_pct": Metric("Packet loss", lambda d: d.loss_pct, "%", when_down=True),
        "uptime_min": Metric("Uptime", lambda d: None if d.uptime_s is None else d.uptime_s / 60.0, "minutes"),
        "ports_down": Metric("Ports down", _ports_down, "ports"),
    },
    "port": {
        "util_pct": Metric("Utilisation", lambda p: p.util_pct, "%"),
        "in_mbps": Metric("Inbound traffic", lambda p: None if p.in_bps is None else p.in_bps / 1e6, "Mb/s"),
        "out_mbps": Metric("Outbound traffic", lambda p: None if p.out_bps is None else p.out_bps / 1e6, "Mb/s"),
        "errors": Metric("Errors per poll", lambda p: None if p.in_err_rate is None and p.out_err_rate is None
                         else (p.in_err_rate or 0) + (p.out_err_rate or 0), "errors"),
        "discards": Metric("Discards per poll", lambda p: None if p.in_disc_rate is None and p.out_disc_rate is None
                           else (p.in_disc_rate or 0) + (p.out_disc_rate or 0), "discards"),
        "oper": Metric("Link state", lambda p: p.oper, states=("up", "down")),
        "admin": Metric("Admin state", lambda p: p.admin, states=("up", "down")),
    },
    "sensor": {
        "value": Metric("Reading", lambda x: x.value),
        "status": Metric("Status", lambda x: x.status, states=("ok", "warn", "crit")),
    },
}
ENTITIES = {"device": "Device", "port": "Port", "sensor": "Health sensor"}
NUM_OPS = {">": "above", ">=": "at or above", "<": "below", "<=": "at or below", "==": "equal to", "!=": "not equal to"}
STATE_OPS = {"==": "is", "!=": "is not"}
SENSOR_KINDS = ("temperature", "fan", "power", "voltage", "current", "humidity", "state", "storage", "system", "diskio", "custom")
SCOPE_KEYS = ("type", "site", "name", "source", "port", "sensor_kind", "sensor_name")


def new_key() -> str:
    return "custom_" + secrets.token_hex(5)


def is_custom(rule: AlertRule) -> bool:
    return bool(rule.entity)


def metric_of(rule: AlertRule) -> Metric | None:
    return METRICS.get(rule.entity or "", {}).get(rule.metric or "")


def _globs(text: str | None) -> list[str]:
    return [g.strip().lower() for g in (text or "").split(",") if g.strip()]


def _matches(value: str | None, patterns: list[str]) -> bool:
    v = (value or "").lower()
    return any(fnmatch.fnmatchcase(v, p if any(c in p for c in "*?[") else f"*{p}*") for p in patterns)


def device_in_scope(rule: AlertRule, d: Device) -> bool:
    sc = rule.scope or {}
    if d.disabled:
        return False
    if sc.get("type") and d.type != sc["type"]:
        return False
    if sc.get("site") and (d.site.name if d.site else "") != sc["site"]:
        return False
    if sc.get("source") and d.source != sc["source"]:
        return False
    names = _globs(sc.get("name"))
    return not names or _matches(d.hostname, names) or _matches(d.ip, names)


def condition(rule: AlertRule, value: Any) -> bool:
    if value is None:
        return False
    m = metric_of(rule)
    if m and m.states:
        want = (rule.value_text or "").lower()
        return (str(value).lower() == want) if rule.op != "!=" else (str(value).lower() != want)
    if rule.threshold is None:
        return False
    v, t = float(value), float(rule.threshold)
    return {">": v > t, ">=": v >= t, "<": v < t, "<=": v <= t, "==": v == t, "!=": v != t}.get(rule.op or ">", False)


def objects(s: Session, rule: AlertRule, d: Device) -> Iterator[tuple[str, str, Any, str]]:
    """(ref, label, current value, link) for every object of this device the rule covers."""
    m = metric_of(rule)
    if m is None or not device_in_scope(rule, d):
        return
    sc = rule.scope or {}
    if rule.entity == "device":
        yield f"device:{d.id}", d.hostname, m.get(d), f"/devices/{d.id}"
    elif rule.entity == "port":
        pats = _globs(sc.get("port"))
        for p in d.ports:
            if not pats or _matches(p.name, pats) or _matches(p.alias, pats):
                yield f"port:{p.id}", f"{d.hostname} {p.name}" + (f" ({p.alias})" if p.alias else ""), m.get(p), f"/ports/{p.id}"
    elif rule.entity == "sensor":
        q = select(Sensor).where(Sensor.device_id == d.id)
        if sc.get("sensor_kind"):
            q = q.where(Sensor.kind == sc["sensor_kind"])
        pats = _globs(sc.get("sensor_name"))
        for x in s.scalars(q):
            if not pats or _matches(x.name, pats):
                yield f"sensor:{x.id}", f"{d.hostname} {x.name}", m.get(x), f"/devices/{d.id}?tab=health"


def fmt(rule: AlertRule, value: Any) -> str:
    m = metric_of(rule)
    if value is None:
        return "no data"
    if m and m.states:
        return str(value)
    unit = m.unit if m else ""
    v = float(value)
    text = f"{v:.0f}" if abs(v) >= 100 or v == int(v) or (unit == "%" and abs(v) >= 10) else f"{v:.1f}"
    return f"{text}{'%' if unit == '%' else (' ' + unit if unit else '')}"


def describe(rule: AlertRule) -> str:
    """A sentence for the rules table: 'Port utilisation above 80% for 3 polls, ports matching "uplink*"'."""
    m = metric_of(rule)
    if m is None:
        return rule.description or ""
    if m.states:
        cond = f"{m.label.lower()} {STATE_OPS.get(rule.op or '==', 'is')} {rule.value_text}"
    else:
        cond = f"{m.label.lower()} {NUM_OPS.get(rule.op or '>', rule.op)} {fmt(rule, rule.threshold)}"
    sc = rule.scope or {}
    where = []
    if sc.get("type"):
        where.append(f"type {sc['type']}")
    if sc.get("site"):
        where.append(f"site {sc['site']}")
    if sc.get("source"):
        where.append(f"from {sc['source']}")
    if sc.get("name"):
        where.append(f'devices matching "{sc["name"]}"')
    if sc.get("port"):
        where.append(f'ports matching "{sc["port"]}"')
    if sc.get("sensor_kind"):
        where.append(f"{sc['sensor_kind']} sensors")
    if sc.get("sensor_name"):
        where.append(f'sensors matching "{sc["sensor_name"]}"')
    polls = f" for {rule.polls} polls" if (rule.polls or 1) > 1 else ""
    return f"{ENTITIES.get(rule.entity, rule.entity)} {cond}{polls}" + (f"; {', '.join(where)}" if where else "")


def evaluate(alerter, dev: Device) -> None:
    """Open, keep or resolve custom-rule alerts for one device. Called from Alerter.evaluate_device."""
    s = alerter.s
    rules = [r for r in alerter.rules.values() if is_custom(r)]
    if not rules:
        return
    pending = alerter.pending()
    for rule in rules:
        m = metric_of(rule)
        seen = set()
        if rule.enabled and m is not None:
            usable = dev.status != "down" or m.when_down
            for ref, label, value, _ in objects(s, rule, dev):
                seen.add(ref)
                hit = usable and condition(rule, value)
                key = (rule.key, ref)
                n = pending.get(key, 0) + 1 if hit else 0
                if n != pending.get(key, 0):
                    alerter.set_pending(rule.key, ref, n)
                alerter.set(rule.key, ref, hit and n >= max(1, rule.polls or 1), f"{rule.name}: {label}",
                            f"{m.label} {fmt(rule, value)}, rule: {describe(rule)}" if hit else None, dev)
        for (key, ref), a in list(alerter.open.items()):      # out of scope now, disabled, or the object went away
            if key == rule.key and a.device_id == dev.id and ref not in seen:
                alerter.set(key, ref, False, device=dev)
                alerter.set_pending(key, ref, 0)


def preview(s: Session, rule: AlertRule, limit: int = 50) -> dict:
    """What the rule would match right now, ignoring the poll count."""
    from sqlalchemy.orm import selectinload
    devs = s.scalars(select(Device).options(selectinload(Device.site), selectinload(Device.ports))
                     .where(Device.disabled.is_(False)).order_by(Device.hostname)).all()
    m = metric_of(rule)
    total, hits = 0, []
    for d in devs:
        usable = m is not None and (d.status != "down" or m.when_down)
        for ref, label, value, url in objects(s, rule, d):
            total += 1
            if usable and condition(rule, value):
                hits.append({"label": label, "value": fmt(rule, value), "url": url})
    return {"checked": total, "matching": len(hits), "rows": hits[:limit], "text": describe(rule)}


def rule_from_form(form, rule: AlertRule | None = None) -> tuple[AlertRule, list[str]]:
    """Fill a (new or existing) custom rule from the builder form. Returns the rule and any problems."""
    problems: list[str] = []
    rule = rule or AlertRule(key=new_key(), name="", description="", severity="warn", polls=1, enabled=True)
    entity = str(form.get("entity") or "")
    metric = str(form.get("metric") or "")
    if entity not in METRICS:
        problems.append("Choose what the rule watches.")
        entity = "device"
    if metric not in METRICS[entity]:
        problems.append("Choose a metric.")
        metric = next(iter(METRICS[entity]))
    m = METRICS[entity][metric]
    rule.entity, rule.metric = entity, metric
    op = str(form.get("op") or "")
    rule.name = str(form.get("name") or "").strip()[:120] or f"{ENTITIES[entity]} {m.label.lower()}"
    if m.states:
        rule.op = op if op in STATE_OPS else "=="
        rule.value_text = str(form.get("value_text") or "")
        if rule.value_text not in m.states:
            problems.append(f"Choose a {m.label.lower()} value.")
        rule.threshold = None
    else:
        rule.op = op if op in NUM_OPS else ">"
        rule.value_text = None
        try:
            rule.threshold = float(str(form.get("threshold") or "").strip())
        except ValueError:
            problems.append("The value must be a number.")
            rule.threshold = None
    sev = str(form.get("severity") or "warn")
    rule.severity = sev if sev in ("crit", "warn", "info") else "warn"
    try:
        rule.polls = max(1, min(60, int(str(form.get("polls") or "1"))))
    except ValueError:
        rule.polls = 1
    rule.enabled = form.get("enabled") == "on"
    # the device-name pattern is posted as "name_q", since "name" is the rule's own name
    scope = {k: str(form.get("name_q" if k == "name" else k) or "").strip()[:200] for k in SCOPE_KEYS}
    if entity != "port":
        scope.pop("port")
    if entity != "sensor":
        scope.pop("sensor_kind")
        scope.pop("sensor_name")
    rule.scope = {k: v for k, v in scope.items() if v}
    rule.description = describe(rule)[:255]
    return rule, problems


def forget(s: Session, key: str) -> None:
    s.execute(delete(AlertPending).where(AlertPending.rule_key == key))


__all__ = ["METRICS", "ENTITIES", "NUM_OPS", "STATE_OPS", "SENSOR_KINDS", "evaluate", "preview", "describe",
           "rule_from_form", "is_custom", "forget"]
