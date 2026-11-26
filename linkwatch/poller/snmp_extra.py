"""The rest of an SNMP poll: health sensors, hardware inventory, storage and LLDP/CDP neighbours.

Every function takes a session with ``walk(base) -> {index_suffix: value}`` and ``get(oids) -> {oid: value}`` and
never raises: a device that doesn't implement a MIB simply returns nothing for it.

MIBs: ENTITY-MIB and ENTITY-SENSOR-MIB (standard), CISCO-ENVMON-MIB, LM-SENSORS-MIB (net-snmp on Linux),
HOST-RESOURCES-MIB storage, LLDP-MIB and CISCO-CDP-MIB.
"""
from __future__ import annotations

import ipaddress
import logging
from typing import Any

log = logging.getLogger("linkwatch.snmp")

ENT = "1.3.6.1.2.1.47.1.1.1.1"
ENT_COLS = {"descr": 2, "contained_in": 4, "class": 5, "name": 7, "hw": 8, "fw": 9, "sw": 10, "serial": 11, "mfg": 12, "model": 13}
ENT_CLASS = {1: "other", 2: "unknown", 3: "chassis", 4: "backplane", 5: "container", 6: "power supply", 7: "fan",
             8: "sensor", 9: "module", 10: "port", 11: "stack", 12: "cpu"}
SENSOR = "1.3.6.1.2.1.99.1.1.1"     # entPhySensorTable: .1 type .2 scale .3 precision .4 value .5 oper status
SENSOR_TYPE = {3: ("voltage", "V AC"), 4: ("voltage", "V"), 5: ("current", "A"), 6: ("power", "W"), 7: ("frequency", "Hz"),
               8: ("temperature", "°C"), 9: ("humidity", "%"), 10: ("fan", "rpm"), 11: ("airflow", "CMM"), 12: ("state", "")}
SCALE = {1: -24, 2: -21, 3: -18, 4: -15, 5: -12, 6: -9, 7: -6, 8: -3, 9: 0, 10: 3, 11: 6, 12: 9, 13: 12, 14: 15, 15: 18, 16: 21, 17: 24}
CISCO_TEMP = "1.3.6.1.4.1.9.9.13.1.3.1"   # .2 descr .3 value .4 threshold .6 state
CISCO_FAN = "1.3.6.1.4.1.9.9.13.1.4.1"    # .2 descr .3 state
CISCO_PSU = "1.3.6.1.4.1.9.9.13.1.5.1"    # .2 descr .3 state
CISCO_STATE = {1: "ok", 2: "warn", 3: "crit", 4: "crit", 5: None, 6: "crit"}
LM = "1.3.6.1.4.1.2021.13.16"             # .2 temperature (m°C), .3 fan (rpm), .4 voltage (mV); .1.2 device .1.3 value
HR_STORAGE = "1.3.6.1.2.1.25.2.3.1"       # .2 type .3 descr .4 units .5 size .6 used
HR_DISK_TYPES = {"1.3.6.1.2.1.25.2.1.4": "disk", "1.3.6.1.2.1.25.2.1.10": "network disk", "1.3.6.1.2.1.25.2.1.9": "flash"}
LLDP_REM = "1.0.8802.1.1.2.1.4.1.1"       # .5 chassis id .7 port id .8 port desc .9 sys name .10 sys desc
LLDP_LOC_PORT = "1.0.8802.1.1.2.1.3.7.1"  # .3 port id .4 port desc
LLDP_MAN = "1.0.8802.1.1.2.1.4.2.1.3"     # lldpRemManAddrIfSubtype, the address is in the index
CDP = "1.3.6.1.4.1.9.9.23.1.2.1.1"        # .4 address .6 device id .7 device port .8 platform
MAX_ROWS = 2000


async def _walk(s, base: str) -> dict[str, Any]:
    try:
        return await s.walk(base, max_rows=MAX_ROWS)
    except TypeError:            # test doubles without max_rows
        return await s.walk(base)
    except Exception as exc:     # noqa: BLE001 - an unanswered MIB is normal
        log.debug("walk %s failed: %s", base, exc)
        return {}


async def _cols(s, base: str, cols: dict[str, int]) -> dict[str, dict[str, Any]]:
    """Walk several columns of one table and return {row_index: {name: value}}."""
    rows: dict[str, dict[str, Any]] = {}
    for name, col in cols.items():
        for idx, v in (await _walk(s, f"{base}.{col}")).items():
            rows.setdefault(idx, {})[name] = v
    return rows


def _int(v) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


# ------------------------------------------------------------------ inventory and sensors
async def entities(s) -> dict[str, dict[str, Any]]:
    return await _cols(s, ENT, ENT_COLS)


def inventory_from(ents: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """Physical parts worth listing: chassis, stack members, modules, power supplies, fans, CPUs (not ports or sensors)."""
    out = []
    for idx, e in sorted(ents.items(), key=lambda kv: _int(kv[0]) or 0):
        cls = ENT_CLASS.get(_int(e.get("class")) or 0, "other")
        if cls in ("port", "sensor", "container", "backplane") and not e.get("serial"):
            continue
        if not any(e.get(k) for k in ("descr", "name", "serial", "model")):
            continue
        out.append({"index": _int(idx), "class": cls, "name": e.get("name") or e.get("descr"), "descr": e.get("descr"),
                    "model": e.get("model") or None, "serial": e.get("serial") or None, "hw": e.get("hw") or None,
                    "fw": e.get("fw") or None, "sw": e.get("sw") or None, "mfg": e.get("mfg") or None,
                    "parent": _int(e.get("contained_in"))})
    return out[:500]


async def sensors(s, ents: dict[str, dict[str, Any]], sys_object_id: str = "") -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    rows = await _cols(s, SENSOR, {"type": 1, "scale": 2, "precision": 3, "value": 4, "status": 5})
    for idx, r in rows.items():
        kind, unit = SENSOR_TYPE.get(_int(r.get("type")) or 0, (None, ""))
        raw = _int(r.get("value"))
        if kind is None or raw is None:
            continue
        status = {1: "ok", 2: None, 3: "crit"}.get(_int(r.get("status")) or 0, None)
        if status is None and _int(r.get("status")) == 2:
            continue                                      # "unavailable": nothing plugged in there
        value = raw * (10 ** SCALE.get(_int(r.get("scale")) or 9, 0)) / (10 ** (_int(r.get("precision")) or 0))
        e = ents.get(idx) or {}
        out.append({"key": f"ent.{idx}", "kind": kind, "name": e.get("name") or e.get("descr") or f"Sensor {idx}",
                    "unit": unit, "value": round(value, 3), "status": status or "ok"})
    if sys_object_id.startswith("1.3.6.1.4.1.9."):
        temps = await _cols(s, CISCO_TEMP, {"descr": 2, "value": 3, "threshold": 4, "state": 6})
        for idx, r in temps.items():
            st = CISCO_STATE.get(_int(r.get("state")) or 0, "ok")
            if st is None or _int(r.get("value")) is None:
                continue
            out.append({"key": f"ciscotemp.{idx}", "kind": "temperature", "name": r.get("descr") or f"Temperature {idx}",
                        "unit": "°C", "value": float(r["value"]), "high": _int(r.get("threshold")), "status": st})
        for base, kind in ((CISCO_FAN, "fan state"), (CISCO_PSU, "power supply")):
            for idx, r in (await _cols(s, base, {"descr": 2, "state": 3})).items():
                st = CISCO_STATE.get(_int(r.get("state")) or 0, "ok")
                if st is None:
                    continue
                out.append({"key": f"cisco{'fan' if 'fan' in kind else 'psu'}.{idx}", "kind": "state", "name": r.get("descr") or kind,
                            "unit": "", "value": {"ok": 1, "warn": 2, "crit": 3}[st], "status": st, "label": kind})
    if not out:
        for col, kind, unit, div in ((2, "temperature", "°C", 1000), (3, "fan", "rpm", 1), (4, "voltage", "V", 1000)):
            for idx, r in (await _cols(s, f"{LM}.{col}.1", {"name": 2, "value": 3})).items():
                v = _int(r.get("value"))
                if v is None or (kind == "temperature" and not 0 < v < 150_000):
                    continue
                out.append({"key": f"lm{col}.{idx}", "kind": kind, "name": r.get("name") or f"{kind} {idx}", "unit": unit,
                            "value": round(v / div, 2), "status": "ok"})
    return out[:300]


async def storage(s) -> list[dict[str, Any]]:
    out = []
    rows = await _cols(s, HR_STORAGE, {"type": 2, "descr": 3, "units": 4, "size": 5, "used": 6})
    for idx, r in rows.items():
        kind = HR_DISK_TYPES.get(str(r.get("type") or ""))
        units, size, used = _int(r.get("units")) or 0, _int(r.get("size")) or 0, _int(r.get("used"))
        if kind is None or size <= 0 or used is None:
            continue
        out.append({"key": f"hr.{idx}", "name": r.get("descr") or f"Storage {idx}", "kind": kind,
                    "size": size * units, "used": used * units, "pct": round(100.0 * used / size, 1)})
    return out[:100]


# ------------------------------------------------------------------ neighbours
def _mac(v) -> str | None:
    if not v:
        return None
    t = str(v).lower()
    parts = t.replace("-", ":").split(":")
    if len(parts) == 6 and all(len(p) == 2 for p in parts):
        return ":".join(parts)
    return t


def _ip_from_octets(v) -> str | None:
    if not v:
        return None
    t = str(v)
    try:
        if ":" in t:                                     # "0a:00:00:01" from a non-printable OctetString
            octets = bytes(int(x, 16) for x in t.split(":"))
            if len(octets) in (4, 16):
                return str(ipaddress.ip_address(octets))
        return str(ipaddress.ip_address(t))
    except ValueError:
        return None


async def neighbours(s, ports: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_name = {}
    for p in ports:
        for k in ("name", "alias"):
            if p.get(k):
                by_name.setdefault(str(p[k]).lower(), p["ifindex"])
    out: list[dict[str, Any]] = []

    rem = await _cols(s, LLDP_REM, {"chassis": 5, "port_id": 7, "port_desc": 8, "sys_name": 9, "sys_desc": 10})
    if rem:
        loc = await _cols(s, LLDP_LOC_PORT, {"port_id": 3, "port_desc": 4})
        addrs: dict[tuple[str, str], str] = {}
        for idx in await _walk(s, LLDP_MAN):
            parts = idx.split(".")       # timeMark.localPort.remIndex.addrSubtype.len.octets...
            if len(parts) >= 9 and parts[3] == "1" and parts[4] == "4":
                addrs.setdefault((parts[1], parts[2]), ".".join(parts[5:9]))
        for idx, r in rem.items():
            parts = idx.split(".")
            if len(parts) < 3:
                continue
            lport, rindex = parts[1], parts[2]
            lp = loc.get(lport) or {}
            local_name = lp.get("port_desc") or lp.get("port_id") or lport
            ifindex = by_name.get(str(lp.get("port_id") or "").lower()) or by_name.get(str(lp.get("port_desc") or "").lower())
            if ifindex is None and lport.isdigit() and any(p["ifindex"] == int(lport) for p in ports):
                ifindex = int(lport)
            out.append({"protocol": "lldp", "local_port": str(local_name), "ifindex": ifindex,
                        "remote_name": r.get("sys_name") or None, "remote_port": r.get("port_desc") or r.get("port_id") or None,
                        "remote_chassis": _mac(r.get("chassis")), "remote_ip": addrs.get((lport, rindex)),
                        "remote_platform": (str(r.get("sys_desc") or "").splitlines() or [None])[0]})

    cdp = await _cols(s, CDP, {"address": 4, "device_id": 6, "device_port": 7, "platform": 8})
    seen = {(n["ifindex"], (n["remote_name"] or "").lower().split(".")[0]) for n in out}
    for idx, r in cdp.items():
        ifx = _int(idx.split(".")[0])
        name = r.get("device_id") or None
        if (ifx, (name or "").lower().split(".")[0]) in seen:
            continue                                     # same neighbour already seen over LLDP
        port = next((p for p in ports if p["ifindex"] == ifx), None)
        out.append({"protocol": "cdp", "local_port": (port or {}).get("name") or str(ifx), "ifindex": ifx,
                    "remote_name": name, "remote_port": r.get("device_port") or None, "remote_chassis": None,
                    "remote_ip": _ip_from_octets(r.get("address")), "remote_platform": r.get("platform") or None})
    return out[:500]


async def collect_extra(s, result: dict[str, Any]) -> None:
    """Add sensors, inventory, storage and neighbours to a poll result."""
    oid = str((result.get("system") or {}).get("sys_object_id") or "")
    ents = await entities(s)
    result["inventory"] = inventory_from(ents)
    result["sensors"] = await sensors(s, ents, oid)
    result["storage"] = await storage(s)
    result["neighbors"] = await neighbours(s, result.get("ports") or [])
