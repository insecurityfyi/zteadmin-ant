"""The event log: a plain record of what changed, shown on the Event log page and each device's Events tab."""
from __future__ import annotations

from sqlalchemy.orm import Session, object_session

from .models import Device, Event, Port, utcnow

STATUS_SEVERITY = {"up": "ok", "down": "crit", "warn": "warn", "unknown": "info", "off": "info"}


def log(s: Session | None, kind: str, message: str, severity: str = "info", device: Device | int | None = None,
        port: Port | None = None, username: str | None = None) -> None:
    if s is None:
        return
    dev_id = device if isinstance(device, int) or device is None else device.id
    s.add(Event(at=utcnow(), kind=kind, severity=severity, device_id=dev_id, port_id=port.id if port is not None else None,
                message=message[:500], username=username))


def device_status_changed(dev: Device, old: str, new: str, reason: str | None) -> None:
    if dev.id is None:
        return
    text = f"Device {new}" if old == "unknown" else f"Device {new} (was {old})"
    if reason and new in ("down", "warn", "unknown"):
        text += f": {reason}"
    log(object_session(dev), "device", text, STATUS_SEVERITY.get(new, "info"), dev)


def port_status_changed(s: Session, dev: Device, p: Port, old: str | None, new: str | None) -> None:
    if p.id is None or not old or old == new:
        return
    label = f"{p.name}{' (' + p.alias + ')' if p.alias else ''}"
    sev = "ok" if new == "up" else ("warn" if p.admin == "up" else "info")
    log(s, "port", f"Port {label} {new or 'unknown'} (was {old})", sev, dev, p)
