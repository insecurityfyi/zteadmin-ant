"""Custom OIDs: definitions people add in the UI, which pollers read and the server turns into sensors.

Flow: a ``CustomOid`` row -> ``poller_defs`` puts the ones in scope on each device in the poller's config -> the
poller reads them (snmp_extra.custom_oids) and sends back raw values -> ``sensor_rows`` applies the type, scale,
names and healthy states -> ingest.update_sensors stores each value as a sensor of kind "custom" with history.

Because they are sensors, custom values show on the device's Health tab with graphs, on Health > Custom OIDs, in the
dashboard's sensor widget, and in alert rules ("Health sensor", type "custom OID"). A state OID with healthy values
set also raises the built-in "Sensor problem" alert when it leaves them.
"""
from __future__ import annotations

import fnmatch
import re
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import CustomOid, Device

VALUE_TYPES = {"gauge": "Gauge (the value as read)", "counter": "Counter (rate per second)",
               "state": "State (numbers that mean up, down, ...)", "text": "Text"}
MODES = {"get": "One value", "walk": "Table column (one value per row)"}
OID_RE = re.compile(r"^\d+(\.\d+)+$")
MAX_DEFS = 200

# sysObjectID prefixes for the scope field's suggestions (enterprise numbers from IANA)
VENDORS = [("1.3.6.1.4.1.9", "Cisco"), ("1.3.6.1.4.1.2636", "Juniper"), ("1.3.6.1.4.1.12356", "Fortinet"),
           ("1.3.6.1.4.1.25461", "Palo Alto Networks"), ("1.3.6.1.4.1.8741", "SonicWall"), ("1.3.6.1.4.1.11", "HP / HPE"),
           ("1.3.6.1.4.1.14823", "Aruba"), ("1.3.6.1.4.1.41112", "Ubiquiti"), ("1.3.6.1.4.1.14988", "MikroTik"),
           ("1.3.6.1.4.1.6574", "Synology"), ("1.3.6.1.4.1.24681", "QNAP"), ("1.3.6.1.4.1.318", "APC / Schneider"),
           ("1.3.6.1.4.1.534", "Eaton"), ("1.3.6.1.4.1.8072", "Net-SNMP (Linux, BSD, pfSense, Proxmox)"),
           ("1.3.6.1.4.1.311", "Microsoft Windows"), ("1.3.6.1.4.1.6876", "VMware"), ("1.3.6.1.4.1.674", "Dell"),
           ("1.3.6.1.4.1.30065", "Arista"), ("1.3.6.1.4.1.1916", "Extreme"), ("1.3.6.1.4.1.3375", "F5")]

# One-click starting points. Standard counters (load, TCP/IP, discards, disk I/O) are polled without adding anything.
PRESETS: list[dict[str, Any]] = [
    {"name": "Cisco CPU (1 min)", "oid": "1.3.6.1.4.1.9.9.109.1.1.1.1.7", "mib_name": "CISCO-PROCESS-MIB::cpmCPUTotal1minRev",
     "mode": "walk", "value_type": "gauge", "unit": "%", "match_sys_oid": "1.3.6.1.4.1.9"},
    {"name": "FortiGate sessions", "oid": "1.3.6.1.4.1.12356.101.4.1.8.0", "mib_name": "FORTINET-FORTIGATE-MIB::fgSysSesCount",
     "mode": "get", "value_type": "gauge", "unit": "", "match_sys_oid": "1.3.6.1.4.1.12356"},
    {"name": "FortiGate CPU", "oid": "1.3.6.1.4.1.12356.101.4.1.3.0", "mib_name": "FORTINET-FORTIGATE-MIB::fgSysCpuUsage",
     "mode": "get", "value_type": "gauge", "unit": "%", "match_sys_oid": "1.3.6.1.4.1.12356"},
    {"name": "Palo Alto active sessions", "oid": "1.3.6.1.4.1.25461.2.1.2.3.3.0", "mib_name": "PAN-COMMON-MIB::panSessionActive",
     "mode": "get", "value_type": "gauge", "unit": "", "match_sys_oid": "1.3.6.1.4.1.25461"},
    {"name": "Palo Alto session table use", "oid": "1.3.6.1.4.1.25461.2.1.2.3.1.0",
     "mib_name": "PAN-COMMON-MIB::panSessionUtilization", "mode": "get", "value_type": "gauge", "unit": "%",
     "match_sys_oid": "1.3.6.1.4.1.25461"},
    {"name": "Juniper CPU", "oid": "1.3.6.1.4.1.2636.3.1.13.1.8", "mib_name": "JUNIPER-MIB::jnxOperatingCPU", "mode": "walk",
     "label_oid": "1.3.6.1.4.1.2636.3.1.13.1.5", "value_type": "gauge", "unit": "%", "match_sys_oid": "1.3.6.1.4.1.2636"},
    {"name": "UPS battery charge", "oid": "1.3.6.1.2.1.33.1.2.4.0", "mib_name": "UPS-MIB::upsEstimatedChargeRemaining",
     "mode": "get", "value_type": "gauge", "unit": "%"},
    {"name": "APC battery runtime", "oid": "1.3.6.1.4.1.318.1.1.1.2.2.3.0", "mib_name": "PowerNet-MIB::upsAdvBatteryRunTimeRemaining",
     "mode": "get", "value_type": "gauge", "scale": 0.01 / 60, "unit": "min", "match_sys_oid": "1.3.6.1.4.1.318"},
    {"name": "APC output load", "oid": "1.3.6.1.4.1.318.1.1.1.4.2.3.0", "mib_name": "PowerNet-MIB::upsAdvOutputLoad",
     "mode": "get", "value_type": "gauge", "unit": "%", "match_sys_oid": "1.3.6.1.4.1.318"},
    {"name": "Synology system temperature", "oid": "1.3.6.1.4.1.6574.1.2.0", "mib_name": "SYNOLOGY-SYSTEM-MIB::temperature",
     "mode": "get", "value_type": "gauge", "unit": "°C", "match_sys_oid": "1.3.6.1.4.1.8072"},
    {"name": "Disk use (UCD)", "oid": "1.3.6.1.4.1.2021.9.1.9", "mib_name": "UCD-SNMP-MIB::dskPercent", "mode": "walk",
     "label_oid": "1.3.6.1.4.1.2021.9.1.2", "value_type": "gauge", "unit": "%"},
    {"name": "Interface unicast packets in", "oid": "1.3.6.1.2.1.31.1.1.1.7", "mib_name": "IF-MIB::ifHCInUcastPkts",
     "mode": "walk", "label_oid": "1.3.6.1.2.1.31.1.1.1.1", "value_type": "counter", "unit": "pkts/s"},
    {"name": "Script output (nsExtend)", "oid": "1.3.6.1.4.1.8072.1.3.2.3.1.1", "mib_name": "NET-SNMP-EXTEND-MIB::nsExtendOutput1Line",
     "mode": "walk", "value_type": "gauge", "unit": "", "match_sys_oid": "1.3.6.1.4.1.8072"},
]


def _globs(text: str | None) -> list[str]:
    return [g.strip().lower() for g in (text or "").split(",") if g.strip()]


def _sys_oid_ok(prefix: str | None, sys_oid: str | None) -> bool:
    p = str(prefix or "").strip().strip(".")
    o = str(sys_oid or "").strip().strip(".")
    return not p or o == p or o.startswith(p + ".")


def in_scope(c: CustomOid, d: Device, unknown_sys_oid_ok: bool = True) -> bool:
    """Does this definition apply to this device? A device whose sysObjectID is not known yet stays in scope (the
    poller checks the prefix against the live sysObjectID) unless ``unknown_sys_oid_ok`` is False."""
    if c.match_type and d.type != c.match_type:
        return False
    names = _globs(c.match_name)
    if names:
        vals = [(d.hostname or "").lower(), (d.ip or "").lower(), (d.sys_name or "").lower()]
        if not any(fnmatch.fnmatchcase(v, p if any(ch in p for ch in "*?[") else f"*{p}*") for p in names for v in vals if v):
            return False
    if c.match_sys_oid:
        if d.sys_object_id:
            return _sys_oid_ok(c.match_sys_oid, d.sys_object_id)
        return unknown_sys_oid_ok
    return True


def enabled_defs(s: Session) -> list[CustomOid]:
    return list(s.scalars(select(CustomOid).where(CustomOid.enabled.is_(True)).order_by(CustomOid.id).limit(MAX_DEFS)))


def poller_defs(defs: list[CustomOid], d: Device) -> list[dict[str, Any]]:
    """The part of each in-scope definition a poller needs (it never sees names, types or scaling)."""
    return [{"id": c.id, "oid": c.oid, "mode": c.mode, "label_oid": c.label_oid or None,
             "sys_object_id": (c.match_sys_oid or "").strip(".") or None} for c in defs if in_scope(c, d)]


def _num(v: Any) -> float | None:
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return float(v)
    try:
        return float(str(v).strip().split()[0])     # "12.5", "12.5 C"
    except (TypeError, ValueError, IndexError):
        return None


def _ok_values(c: CustomOid) -> set[str]:
    return {x.strip() for x in (c.ok_values or "").split(",") if x.strip()}


def sensor_rows(s: Session, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Turn a poller's raw custom OID values into sensor rows for ingest.update_sensors."""
    ids = {int(r["id"]) for r in rows if isinstance(r, dict) and isinstance(r.get("id"), int)}
    defs = {c.id: c for c in s.scalars(select(CustomOid).where(CustomOid.id.in_(ids)))} if ids else {}
    out = []
    for r in rows:
        c = defs.get(r.get("id")) if isinstance(r, dict) else None
        if c is None or not c.enabled:
            continue
        idx = str(r.get("index") or "")
        label = r.get("label")
        name = c.name if not idx else f"{c.name} {label if label not in (None, '') else idx}"
        row: dict[str, Any] = {"key": f"oid{c.id}" + (f".{idx}" if idx else ""), "kind": "custom", "name": name[:255],
                               "unit": (c.unit or "")[:16], "status": "ok",
                               "extra": {"oid_id": c.id, "label": c.category or "", "oid": c.oid + (f".{idx}" if idx else "")}}
        raw, scale = r.get("value"), (c.scale if c.scale not in (None, 0) else 1.0)
        if c.value_type == "counter":
            row.update(counter=True, raw=_num(raw), scale=scale, bits=64)
        elif c.value_type == "text":
            row["value"] = None
            row["extra"]["text"] = str(raw)[:200]
        else:
            v = _num(raw)
            row["value"] = None if v is None else round(v * scale, 4)
            if c.value_type == "state":
                key = str(int(v)) if v is not None and v == int(v) else str(raw)
                row["value"] = v
                row["extra"]["state"] = (c.states or {}).get(key) or key
                ok = _ok_values(c)
                if ok and key not in ok:
                    row["status"] = "crit"
            elif v is None and raw not in (None, ""):
                row["extra"]["text"] = str(raw)[:200]          # a gauge that came back as words
        out.append(row)
    return out


def def_from_form(s: Session, form, c: CustomOid | None = None) -> tuple[CustomOid, list[str]]:
    """Fill a (new or existing) definition from the form. Names like IF-MIB::ifHCInOctets are resolved via MIBs."""
    from . import mibs
    problems: list[str] = []
    c = c or CustomOid(name="", oid="", mode="get", value_type="gauge", enabled=True)
    text = str(form.get("oid") or "").strip()
    obj = None
    try:
        oid, obj = mibs.find(s, text)
    except mibs.MibError as exc:
        problems.append(str(exc))
        oid = text.strip(".")
    mode = str(form.get("mode") or "")
    c.mode = mode if mode in MODES else ("walk" if obj and obj.get("node") == "column" else "get")
    if obj and obj.get("node") in ("table", "row"):
        problems.append(f"{obj['name']} is a whole table. Pick one of its columns instead.")
    if obj and obj.get("node") == "scalar" and c.mode == "get" and oid == obj["oid"]:
        oid += ".0"                                     # a scalar's value lives at .0
    if oid and not OID_RE.match(oid):
        problems.append("The OID must be numbers separated by dots, like 1.3.6.1.2.1.1.3.0.")
    c.oid = oid[:255]
    c.mib_name = (str(form.get("mib_name") or "").strip() or (f"{obj['module']}::{obj['name']}" if obj else None) or None)
    if c.mib_name:
        c.mib_name = c.mib_name[:255]
    label = str(form.get("label_oid") or "").strip()
    c.label_oid = None
    if c.mode == "walk" and label:
        try:
            c.label_oid, _ = mibs.find(s, label)
        except mibs.MibError as exc:
            problems.append(f"Row names: {exc}")
    vt = str(form.get("value_type") or "")
    c.value_type = vt if vt in VALUE_TYPES else "gauge"
    try:
        sc = str(form.get("scale") or "").strip()
        c.scale = float(sc) if sc else None
        if c.scale == 0:
            problems.append("The multiplier cannot be 0.")
    except ValueError:
        problems.append("The multiplier must be a number, such as 0.01 or 1024.")
        c.scale = None
    c.unit = str(form.get("unit") or "").strip()[:16] or None
    c.category = str(form.get("category") or "").strip()[:60] or None
    c.ok_values = str(form.get("ok_values") or "").strip()[:120] or None if c.value_type == "state" else None
    states = str(form.get("states") or "").strip()
    c.states = None
    if c.value_type == "state":
        parsed = {}
        for part in re.split(r"[,\n]", states):
            k, sep, v = part.partition("=")
            if sep and k.strip() and v.strip():
                parsed[k.strip()] = v.strip()[:40]
        c.states = parsed or ((obj or {}).get("states") or None)
    c.match_type = str(form.get("match_type") or "").strip()[:40] or None
    sys_oid = str(form.get("match_sys_oid") or "").strip().strip(".")
    if sys_oid and not OID_RE.match(sys_oid):
        problems.append("The sysObjectID prefix must be a numeric OID such as 1.3.6.1.4.1.9.")
    c.match_sys_oid = sys_oid[:255] or None
    c.match_name = str(form.get("match_name") or "").strip()[:255] or None
    c.enabled = form.get("enabled") == "on"
    c.description = str(form.get("description") or "").strip()[:2000] or None
    c.name = str(form.get("name") or "").strip()[:120] or (obj["name"] if obj else "") or c.oid
    if not c.name:
        problems.append("Give it a name.")
    return c, problems


def describe_scope(c: CustomOid) -> str:
    parts = []
    if c.match_type:
        parts.append(f"type {c.match_type}")
    if c.match_sys_oid:
        vendor = dict(VENDORS).get(c.match_sys_oid)
        parts.append(vendor or f"sysObjectID {c.match_sys_oid}.*")
    if c.match_name:
        parts.append(f'names matching "{c.match_name}"')
    return ", ".join(parts) or "every SNMP device"
