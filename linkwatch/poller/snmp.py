"""SNMP v2c / v3 collection with pysnmp's asyncio API.

Collects the system group, interface table (64-bit counters where the device
has them, plus errors and discards), CPU and memory. CPU and memory are tried in this order:
HOST-RESOURCES-MIB, UCD-SNMP-MIB (Linux, Proxmox, Synology, many appliances),
then Cisco's process and memory pool MIBs.
"""
from __future__ import annotations

import time
from typing import Any

from pysnmp.hlapi.v3arch.asyncio import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    UsmUserData,
    bulk_walk_cmd,
    get_cmd,
    usmAesCfb128Protocol,
    usmAesCfb192Protocol,
    usmAesCfb256Protocol,
    usmDESPrivProtocol,
    usmHMAC128SHA224AuthProtocol,
    usmHMAC192SHA256AuthProtocol,
    usmHMAC256SHA384AuthProtocol,
    usmHMAC384SHA512AuthProtocol,
    usmHMACMD5AuthProtocol,
    usmHMACSHAAuthProtocol,
    usmNoAuthProtocol,
    usmNoPrivProtocol,
)

SYS = {
    "sys_descr": "1.3.6.1.2.1.1.1.0",
    "sys_object_id": "1.3.6.1.2.1.1.2.0",
    "uptime": "1.3.6.1.2.1.1.3.0",
    "sys_name": "1.3.6.1.2.1.1.5.0",
    "sys_location": "1.3.6.1.2.1.1.6.0",
}
IF = {
    "descr": "1.3.6.1.2.1.2.2.1.2",
    "speed": "1.3.6.1.2.1.2.2.1.5",
    "admin": "1.3.6.1.2.1.2.2.1.7",
    "oper": "1.3.6.1.2.1.2.2.1.8",
    "in_octets32": "1.3.6.1.2.1.2.2.1.10",
    "in_discards": "1.3.6.1.2.1.2.2.1.13",
    "in_errors": "1.3.6.1.2.1.2.2.1.14",
    "out_octets32": "1.3.6.1.2.1.2.2.1.16",
    "out_discards": "1.3.6.1.2.1.2.2.1.19",
    "out_errors": "1.3.6.1.2.1.2.2.1.20",
    "name": "1.3.6.1.2.1.31.1.1.1.1",
    "in_octets": "1.3.6.1.2.1.31.1.1.1.6",
    "out_octets": "1.3.6.1.2.1.31.1.1.1.10",
    "high_speed": "1.3.6.1.2.1.31.1.1.1.15",
    "alias": "1.3.6.1.2.1.31.1.1.1.18",
}
HR_CPU = "1.3.6.1.2.1.25.3.3.1.2"
HR_STORAGE_TYPE = "1.3.6.1.2.1.25.2.3.1.2"
HR_STORAGE_UNITS = "1.3.6.1.2.1.25.2.3.1.4"
HR_STORAGE_SIZE = "1.3.6.1.2.1.25.2.3.1.5"
HR_STORAGE_USED = "1.3.6.1.2.1.25.2.3.1.6"
HR_RAM = "1.3.6.1.2.1.25.2.1.2"
UCD = {
    "cpu_idle": "1.3.6.1.4.1.2021.11.11.0",
    "mem_total": "1.3.6.1.4.1.2021.4.5.0",
    "mem_avail": "1.3.6.1.4.1.2021.4.6.0",
    "mem_buffer": "1.3.6.1.4.1.2021.4.14.0",
    "mem_cached": "1.3.6.1.4.1.2021.4.15.0",
}
CISCO_CPU_5MIN = "1.3.6.1.4.1.9.9.109.1.1.1.1.8"
CISCO_MEM_USED = "1.3.6.1.4.1.9.9.48.1.1.1.5"
CISCO_MEM_FREE = "1.3.6.1.4.1.9.9.48.1.1.1.6"
# SONICWALL-FIREWALL-IP-STATISTICS-MIB (enterprise 8741)
SONICWALL = {
    "max_connections": "1.3.6.1.4.1.8741.1.3.1.1.0",
    "connections": "1.3.6.1.4.1.8741.1.3.1.2.0",
    "cpu": "1.3.6.1.4.1.8741.1.3.1.3.0",
    "ram": "1.3.6.1.4.1.8741.1.3.1.4.0",
}
STATUS = {1: "up", 2: "down", 3: "testing", 4: "unknown", 5: "dormant", 6: "notPresent", 7: "lowerLayerDown"}

AUTH = {
    "MD5": usmHMACMD5AuthProtocol, "SHA": usmHMACSHAAuthProtocol, "SHA224": usmHMAC128SHA224AuthProtocol,
    "SHA256": usmHMAC192SHA256AuthProtocol, "SHA384": usmHMAC256SHA384AuthProtocol, "SHA512": usmHMAC384SHA512AuthProtocol,
}
PRIV = {"DES": usmDESPrivProtocol, "AES": usmAesCfb128Protocol, "AES128": usmAesCfb128Protocol,
        "AES192": usmAesCfb192Protocol, "AES256": usmAesCfb256Protocol}


class SnmpError(RuntimeError):
    pass


def auth_data(creds: dict[str, Any]):
    version = str(creds.get("version", "2c"))
    if version in ("1", "2c", "v2c", "v1"):
        return CommunityData(creds.get("community") or "public", mpModel=0 if version in ("1", "v1") else 1)
    level = creds.get("level", "authPriv")
    user = creds.get("username") or ""
    if level == "noAuthNoPriv":
        return UsmUserData(user, authProtocol=usmNoAuthProtocol, privProtocol=usmNoPrivProtocol)
    auth = AUTH.get(str(creds.get("auth_protocol", "SHA")).upper(), usmHMACSHAAuthProtocol)
    if level == "authNoPriv":
        return UsmUserData(user, creds.get("auth_key"), authProtocol=auth, privProtocol=usmNoPrivProtocol)
    priv = PRIV.get(str(creds.get("priv_protocol", "AES")).upper(), usmAesCfb128Protocol)
    return UsmUserData(user, creds.get("auth_key"), creds.get("priv_key"), authProtocol=auth, privProtocol=priv)


def _val(v) -> Any:
    """Turn a pysnmp value into a plain Python value (None for noSuchObject etc.)."""
    name = v.__class__.__name__
    if name in ("NoSuchObject", "NoSuchInstance", "EndOfMibView", "Null"):
        return None
    if name in ("Integer", "Integer32", "Counter32", "Counter64", "Gauge32", "Unsigned32", "TimeTicks"):
        return int(v)
    if name == "ObjectIdentifier":
        return str(v)
    if name == "OctetString":
        raw = bytes(v)
        try:
            text = raw.decode("utf-8")
            if text.isprintable() or all(c.isprintable() or c in "\r\n\t" for c in text):
                return text.strip("\x00").strip()
        except UnicodeDecodeError:
            pass
        return raw.hex(":")
    return v.prettyPrint()


class SnmpSession:
    def __init__(self, host: str, creds: dict[str, Any], engine: SnmpEngine | None = None,
                 port: int = 161, timeout: float = 2.0, retries: int = 1):
        self.host, self.port = host, int(creds.get("port") or port)
        self.auth = auth_data(creds)
        self.engine = engine or SnmpEngine()
        self.timeout, self.retries = timeout, retries
        self._target = None

    async def target(self):
        if self._target is None:
            self._target = await UdpTransportTarget.create((self.host, self.port), timeout=self.timeout, retries=self.retries)
        return self._target

    async def get(self, oids: list[str]) -> dict[str, Any]:
        err_ind, err_stat, _idx, binds = await get_cmd(
            self.engine, self.auth, await self.target(), ContextData(),
            *[ObjectType(ObjectIdentity(o)) for o in oids], lookupMib=False)
        if err_ind:
            raise SnmpError(str(err_ind))
        if err_stat:
            # v1 agents fail the whole request on one missing OID; callers fall back
            return {o: None for o in oids}
        return {str(name): _val(val) for name, val in binds}

    async def walk(self, base: str, max_rows: int = 5000) -> dict[str, Any]:
        """Walk one column; returns {index_suffix: value}."""
        out: dict[str, Any] = {}
        prefix = base + "."
        async for err_ind, err_stat, _idx, binds in bulk_walk_cmd(
                self.engine, self.auth, await self.target(), ContextData(), 0, 40,
                ObjectType(ObjectIdentity(base)), lexicographicMode=False, lookupMib=False):
            if err_ind:
                raise SnmpError(str(err_ind))
            if err_stat:
                break
            for name, val in binds:
                oid = str(name)
                if not oid.startswith(prefix):
                    return out
                out[oid[len(prefix):]] = _val(val)
                if len(out) >= max_rows:
                    return out
        return out


async def poll_device(session: SnmpSession, oids: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """One full poll. Raises SnmpError if the device does not answer at all.

    ``oids`` are the custom OIDs the server assigned to this device (see snmp_extra.custom_oids)."""
    started = time.monotonic()
    sysv = await session.get(list(SYS.values()))
    if all(v is None for v in sysv.values()):
        raise SnmpError("No response to system group")
    by = {k: sysv.get(o) for k, o in SYS.items()}
    result: dict[str, Any] = {
        "system": {
            "sys_descr": by["sys_descr"], "sys_object_id": by["sys_object_id"], "sys_name": by["sys_name"],
            "sys_location": by["sys_location"], "uptime_s": (by["uptime"] or 0) // 100 if by["uptime"] is not None else None,
        },
        "cpu": None, "mem": None, "ports": [],
    }

    cols: dict[str, dict[str, Any]] = {}
    for key, oid in IF.items():
        try:
            cols[key] = await session.walk(oid)
        except SnmpError:
            cols[key] = {}
        if key == "descr" and not cols[key]:
            break  # no ifTable at all (e.g. some UPS cards)
    for idx in sorted(cols.get("descr", {}), key=lambda s: int(s) if s.isdigit() else 0):
        c = lambda k: cols.get(k, {}).get(idx)  # noqa: E731
        hs = c("high_speed")
        result["ports"].append({
            "ifindex": int(idx) if idx.isdigit() else idx,
            "name": c("name") or c("descr"), "alias": c("alias") or "",
            "speed_mbps": hs if hs else ((c("speed") or 0) // 1_000_000),
            "admin": STATUS.get(c("admin"), "unknown"), "oper": STATUS.get(c("oper"), "unknown"),
            "in_octets": c("in_octets") if c("in_octets") is not None else c("in_octets32"),
            "out_octets": c("out_octets") if c("out_octets") is not None else c("out_octets32"),
            "counter_bits": 64 if c("in_octets") is not None else 32,
            "in_errors": c("in_errors"), "out_errors": c("out_errors"),
            "in_discards": c("in_discards"), "out_discards": c("out_discards"),
        })

    oid = str(by["sys_object_id"] or "")
    if oid.startswith("1.3.6.1.4.1.8741."):
        await _sonicwall(session, result)
    if result["cpu"] is None or result["mem"] is None:
        cpu, mem = await _cpu_mem(session)
        result["cpu"] = result["cpu"] if result["cpu"] is not None else cpu
        result["mem"] = result["mem"] if result["mem"] is not None else mem
    from .snmp_extra import collect_extra
    await collect_extra(session, result, oids)
    result["poll_ms"] = int((time.monotonic() - started) * 1000)
    return result


async def _sonicwall(s: SnmpSession, result: dict[str, Any]) -> None:
    try:
        got = await s.get(list(SONICWALL.values()))
    except SnmpError:
        return
    v = {k: got.get(o) for k, o in SONICWALL.items()}
    if isinstance(v["cpu"], int):
        result["cpu"] = float(v["cpu"])
    if isinstance(v["ram"], int):
        result["mem"] = float(v["ram"])
    if isinstance(v["connections"], int):
        result["vendor"] = {"connections": v["connections"], "max_connections": v["max_connections"]}


async def _cpu_mem(s: SnmpSession) -> tuple[float | None, float | None]:
    cpu = mem = None
    try:
        loads = [v for v in (await s.walk(HR_CPU)).values() if isinstance(v, int)]
        if loads:
            cpu = round(sum(loads) / len(loads), 1)
    except SnmpError:
        pass
    ucd = {}
    try:
        got = await s.get(list(UCD.values()))
        ucd = {k: got.get(o) for k, o in UCD.items()}
    except SnmpError:
        pass
    if cpu is None and isinstance(ucd.get("cpu_idle"), int):
        cpu = float(100 - ucd["cpu_idle"])
    if isinstance(ucd.get("mem_total"), int) and ucd["mem_total"] > 0 and isinstance(ucd.get("mem_avail"), int):
        used = ucd["mem_total"] - ucd["mem_avail"] - (ucd.get("mem_buffer") or 0) - (ucd.get("mem_cached") or 0)
        mem = round(100.0 * max(used, 0) / ucd["mem_total"], 1)
    if mem is None:
        try:
            types = await s.walk(HR_STORAGE_TYPE)
            ram = [i for i, t in types.items() if t == HR_RAM]
            if ram:
                i = ram[0]
                size = (await s.get([f"{HR_STORAGE_SIZE}.{i}", f"{HR_STORAGE_USED}.{i}"]))
                total, used = size.get(f"{HR_STORAGE_SIZE}.{i}"), size.get(f"{HR_STORAGE_USED}.{i}")
                if total:
                    mem = round(100.0 * (used or 0) / total, 1)
        except SnmpError:
            pass
    if cpu is None:
        try:
            vals = [v for v in (await s.walk(CISCO_CPU_5MIN)).values() if isinstance(v, int)]
            if vals:
                cpu = float(max(vals))
        except SnmpError:
            pass
    if mem is None:
        try:
            used, free = await s.walk(CISCO_MEM_USED), await s.walk(CISCO_MEM_FREE)
            if used.get("1") is not None and free.get("1") is not None and (used["1"] + free["1"]):
                mem = round(100.0 * used["1"] / (used["1"] + free["1"]), 1)
        except SnmpError:
            pass
    return cpu, mem
