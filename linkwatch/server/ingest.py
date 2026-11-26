"""Turn poller and integration results into device state, metrics and alerts."""
from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, or_, select, update
from sqlalchemy.orm import Session

from . import events
from .alerts import Alerter
from .models import Device, DeviceMetric, Integration, IntegrationMetric, Port, PortMetric, ProcessedBatch, Site, utcnow

COUNTER32 = 2**32


def from_epoch(ts: float | None) -> datetime:
    if not ts:
        return utcnow()
    return datetime.fromtimestamp(float(ts), timezone.utc).replace(tzinfo=None)


def site_by_name(s: Session, name: str | None) -> Site | None:
    name = (name or "").strip()
    if not name:
        return None
    site = s.scalar(select(Site).where(Site.name == name))
    if site is None:
        site = Site(name=name)
        s.add(site)
        s.flush()
    return site


def set_status(dev: Device, status: str, reason: str | None = None) -> None:
    if dev.status != status:
        old, dev.status = dev.status, status
        dev.status_since = utcnow()
        events.device_status_changed(dev, old, status, reason)
    dev.status_reason = reason[:255] if reason else None


def counter_delta(new: float | None, old: float | None, bits: int = 64) -> float | None:
    """Difference between two counter readings, handling a 32-bit wrap. A 64-bit decrease is a reset."""
    if new is None or old is None:
        return None
    if new >= old:
        return new - old
    if bits == 32 and old < COUNTER32:
        return new + COUNTER32 - old
    return None


# ---------------------------------------------------------------- devices
def ingest_device(s: Session, alerter: Alerter, poller_id: int, item: dict[str, Any]) -> Device | None:
    dev = s.get(Device, int(item.get("device_id") or 0))
    if dev is None or dev.poller_id != poller_id:
        return None
    ts = from_epoch(item.get("ts"))
    dev.last_polled = ts
    has_snmp = dev.snmp_profile_id is not None
    ping = item.get("ping") or None
    ping_ok = bool(ping and ping.get("loss_pct", 100) < 100)
    if ping:
        dev.ping_ms, dev.loss_pct = ping.get("rtt_ms"), ping.get("loss_pct")

    snmp_ok = bool(item.get("ok")) and has_snmp
    if snmp_ok:
        sysinfo = item.get("system") or {}
        for field in ("sys_descr", "sys_object_id", "sys_name", "sys_location", "uptime_s"):
            if sysinfo.get(field) is not None:
                setattr(dev, field, sysinfo[field])
        if not dev.platform and dev.sys_descr:
            dev.platform = dev.sys_descr.splitlines()[0][:255]
        dev.cpu, dev.mem = item.get("cpu"), item.get("mem")
        dev.poll_ms = item.get("poll_ms")
        if isinstance(item.get("vendor"), dict):     # e.g. SonicWall connection counts
            dev.extra = {**(dev.extra or {}), "vendor": item["vendor"]}
        _update_ports(s, dev, item.get("ports") or [], float(item.get("ts") or ts.timestamp()), ts)

    if (has_snmp and snmp_ok) or (not has_snmp and ping_ok):
        dev.fail_count = 0
        set_status(dev, "up")
    elif has_snmp and ping_ok:
        dev.fail_count = 0
        set_status(dev, "warn", item.get("error") or "SNMP is not answering")
    else:
        dev.fail_count += 1
        rule = alerter.rules.get("device_down")
        if dev.fail_count >= (rule.polls if rule else 2) or dev.status == "unknown":
            set_status(dev, "down", item.get("error") or ("No ping reply" if ping else "No answer"))

    if dev.cpu is not None or dev.mem is not None or ping:
        s.add(DeviceMetric(device_id=dev.id, ts=ts, cpu=dev.cpu if snmp_ok else None, mem=dev.mem if snmp_ok else None,
                           ping_ms=dev.ping_ms if ping else None, loss_pct=dev.loss_pct if ping else None))
    s.flush()
    alerter.evaluate_device(dev)
    return dev


def _update_ports(s: Session, dev: Device, ports: list[dict], ts_epoch: float, ts: datetime) -> None:
    existing = {p.ifindex: p for p in dev.ports}
    seen: set[int] = set()
    for data in ports:
        try:
            idx = int(data["ifindex"])
        except (KeyError, TypeError, ValueError):
            continue
        seen.add(idx)
        p = existing.get(idx)
        if p is None:
            p = Port(device_id=dev.id, ifindex=idx, name=str(data.get("name") or idx)[:255])
            dev.ports.append(p)
            existing[idx] = p
        p.name = str(data.get("name") or p.name)[:255]
        p.alias = (data.get("alias") or "")[:255]
        p.speed_mbps = data.get("speed_mbps") or None
        old_oper = p.oper
        p.admin, p.oper = data.get("admin"), data.get("oper")
        events.port_status_changed(s, dev, p, old_oper, p.oper)
        bits = int(data.get("counter_bits") or 64)
        dt = ts_epoch - p.last_ts if p.last_ts else None
        if dt and dt > 0:
            d_in = counter_delta(data.get("in_octets"), p.last_in_octets, bits)
            d_out = counter_delta(data.get("out_octets"), p.last_out_octets, bits)
            e_in = counter_delta(data.get("in_errors"), p.last_in_errors, 32)
            e_out = counter_delta(data.get("out_errors"), p.last_out_errors, 32)
            p.in_bps = d_in * 8 / dt if d_in is not None else None
            p.out_bps = d_out * 8 / dt if d_out is not None else None
            p.in_err_rate, p.out_err_rate = e_in, e_out
            p.util_pct = (max(p.in_bps or 0, p.out_bps or 0) / (p.speed_mbps * 1e6) * 100) if p.speed_mbps else None
            if p.id is None:
                s.flush()
            if p.in_bps is not None or p.out_bps is not None:
                s.add(PortMetric(port_id=p.id, ts=ts, in_bps=p.in_bps, out_bps=p.out_bps, in_err=e_in, out_err=e_out))
        p.last_in_octets, p.last_out_octets = data.get("in_octets"), data.get("out_octets")
        p.last_in_errors, p.last_out_errors = data.get("in_errors"), data.get("out_errors")
        p.last_ts = ts_epoch
    if ports:
        for idx, p in existing.items():
            if idx not in seen:
                dev.ports.remove(p)


# ---------------------------------------------------------------- integrations
def ingest_integration(s: Session, alerter: Alerter, integ: Integration, item: dict[str, Any]) -> None:
    ts = from_epoch(item.get("ts"))
    integ.last_sync = ts
    ref = f"integration:{integ.id}"
    old_status = integ.status
    if not item.get("ok"):
        err = item.get("error") or "Unknown error"
        if "Unknown integration type" in err:
            from ..integrations import REGISTRY
            from .gateway import outdated_poller_message
            cls = REGISTRY.get(integ.kind)
            err = outdated_poller_message(integ.poller.name if integ.poller else "the poller", cls.label if cls else integ.kind)
        integ.status, integ.last_error = "error", err[:2000]
        if old_status != "error":
            events.log(s, "integration", f"{integ.name}: sync failing: {integ.last_error[:300]}", "crit")
        alerter.set("integration_failed", ref, True, f"Integration failing: {integ.name}", integ.last_error)
        return
    records = item.get("records") or []
    warnings = item.get("warnings") or []
    integ.status = "partial" if warnings else "ok"
    if old_status == "error":
        events.log(s, "integration", f"{integ.name}: syncing again", "ok")
    integ.last_error = "; ".join(warnings)[:2000] or None
    integ.object_count = len(records)
    alerter.set("integration_failed", ref, False)

    current = {d.external_id: d for d in s.scalars(select(Device).where(Device.integration_id == integ.id))}
    seen: set[str] = set()
    for rec in records:
        ext = str(rec.get("external_id") or "")
        if not ext:
            continue
        seen.add(ext)
        dev = current.get(ext)
        if dev is None or dev.source == integ.kind:
            # the same box polled over SNMP: put the API data on it instead of keeping two devices
            local = match_local_device(s, rec)
            if local is not None:
                if dev is not None:
                    merge_into(s, dev, local)
                local.integration_id, local.external_id = integ.id, ext
                events.log(s, "config", f"Matched to {integ.name} device {rec.get('hostname') or ext}; its API data now shows here",
                           "info", local)
                dev = current[ext] = local
        if dev is None:
            dev = Device(hostname=str(rec.get("hostname") or ext)[:255], source=integ.kind, integration_id=integ.id,
                         external_id=ext, ping=False, extra={})
            s.add(dev)
        _apply_record(s, dev, integ, rec, ts)
        s.flush()
        if rec.get("ports") and dev.source == integ.kind:   # SNMP-polled boxes keep their SNMP ports
            _update_ports(s, dev, rec["ports"], float(item.get("ts") or time.time()), ts)
        if dev.cpu is not None or dev.mem is not None:
            s.add(DeviceMetric(device_id=dev.id, ts=ts, cpu=dev.cpu, mem=dev.mem))
        alerter.evaluate_device(dev)

    for ext, dev in current.items():
        if ext not in seen and dev.source == integ.kind and dev.status != "unknown":
            set_status(dev, "unknown", f"No longer reported by {integ.name}")
            alerter.evaluate_device(dev)
    counts = {k: sum(1 for r in records if r.get("status") == k) for k in ("up", "warn", "down")}
    s.add(IntegrationMetric(integration_id=integ.id, key="objects", ts=ts, a=counts["up"], b=len(records),
                            c=counts["warn"] + counts["down"]))
    if item.get("data"):
        ingest_integration_data(s, integ, item["data"], ts)


MAX_CLIENT_SERIES = 1000


Point = tuple[str, "float | None", "float | None", "float | None"]


def integration_series(data: dict[str, Any]) -> list[Point]:
    """Time-series points from an integration's extra payload (see IntegrationMetric for what a/b/c mean).
    Items that get their own graph are tagged with a "series" key so pages can link to it."""
    kind = data.get("type")
    if kind in SERIES:
        return SERIES[kind](data)
    return _unifi_series(data)


def _num(v) -> float | None:
    try:
        return None if v is None or v == "" else float(v)
    except (TypeError, ValueError):
        return None


def _zscaler_series(d: dict[str, Any]) -> list[Point]:
    out: list[Point] = []
    zia, zpa, zdx, zcc, ztb = (d.get(k) or {} for k in ("zia", "zpa", "zdx", "zcc", "ztb"))
    if zia:
        out.append(("zia:inventory", len(zia.get("locations") or []), len(zia.get("tunnels") or []), None))
    if zpa:
        conns = zpa.get("connectors") or []
        out.append(("zpa:connectors", zpa.get("healthy"), len(conns), zpa.get("outdated")))
    for app in zdx.get("apps") or []:
        app["series"] = f"zdx:{app.get('id')}"
        out.append((app["series"], _num(app.get("score")), _num(app.get("users")), None))
    if zdx.get("apps"):
        scores = [a["score"] for a in zdx["apps"] if a.get("score") is not None]
        out.append(("zdx:average", sum(scores) / len(scores) if scores else None, min(scores) if scores else None, len(scores)))
    if zcc:
        registered = sum(n for st, n in zcc.get("states") or [] if str(st).lower() == "registered")
        out.append(("zcc:devices", zcc.get("total"), registered, None))
    if ztb:
        sites = ztb.get("sites") or []
        up = sum(1 for x in sites if x.get("status") in ("up", "online", "active", "healthy", "connected"))
        out.append(("ztb:sites", up, len(sites), None))
    return out


def _meraki_series(d: dict[str, Any]) -> list[Point]:
    out: list[Point] = []
    c = d.get("clients") or {}
    if c:
        out.append(("clients", _num(c.get("total")), _num(c.get("down_bps")), _num(c.get("up_bps"))))
    for u in d.get("loss_latency") or []:
        u["series"] = f"uplink:{u.get('serial')}/{u.get('uplink')}"
        out.append((u["series"], _num(u.get("latency_ms")), _num(u.get("loss_pct")), None))
    return out


def _panos_series(d: dict[str, Any]) -> list[Point]:
    out: list[Point] = []
    ss = d.get("sessions") or {}
    if ss:
        out.append(("sessions", _num(ss.get("active")), _num(ss.get("cps")), _num(ss.get("throughput_bps"))))
    if "globalprotect" in d:
        out.append(("gp:users", d["globalprotect"].get("count"), None, None))
    if d.get("tunnels") is not None:
        t = d["tunnels"]
        out.append(("tunnels", sum(1 for x in t if x.get("state") == "active"), len(t), None))
    return out


def _fortigate_series(d: dict[str, Any]) -> list[Point]:
    out: list[Point] = []
    r = d.get("resources") or {}
    if r:
        out.append(("sessions", _num(r.get("session")), _num(r.get("setuprate")), None))
    t = d.get("tunnels") or []
    out.append(("tunnels", sum(1 for x in t if x.get("phase2_up")), len(t), None))
    if "sslvpn" in d:
        out.append(("sslvpn:users", len(d["sslvpn"]), None, None))
    return out


def _sonicwall_series(d: dict[str, Any]) -> list[Point]:
    out: list[Point] = []
    if "sslvpn" in d:
        out.append(("sslvpn:users", len(d["sslvpn"]), None, None))
    if d.get("tunnels") is not None:
        t = d["tunnels"]
        out.append(("tunnels", sum(1 for x in t if x.get("up")), len(t), None))
    return out


def _proxmox_series(d: dict[str, Any]) -> list[Point]:
    g = d.get("guests") or {}
    out: list[Point] = [("guests", _num(g.get("running")), _num(g.get("total")), None)]
    for st in d.get("storage") or []:
        if st.get("size"):
            st["series"] = f"storage:{st.get('node')}/{st.get('name')}"
            out.append((st["series"], round(100.0 * (st.get("used") or 0) / st["size"], 1), _num(st.get("used")), _num(st.get("size"))))
    return out


def _unifi_series(data: dict[str, Any]) -> list[Point]:
    out: list[Point] = []
    summ = data.get("summary") or {}
    if "clients" in summ:
        out.append(("clients", summ.get("clients"), summ.get("wireless"), summ.get("wired")))
    if data.get("wans"):
        out.append(("wan:total", summ.get("down_bps"), summ.get("up_bps"), summ.get("latency_ms")))
    for w in data.get("wans") or []:
        w["series"] = f"wan:{w['device']}/{w.get('name')}" if w.get("device") else f"wan:{w.get('name')}"
        out.append((w["series"], w.get("down_bps"), w.get("up_bps"), None))
    multi = len(summ.get("sites") or []) > 1
    for x in data.get("ssids") or []:
        x["series"] = f"ssid:{x.get('site')} / {x.get('name')}" if multi else f"ssid:{x.get('name')}"
        out.append((x["series"], x.get("down_bps"), x.get("up_bps"), x.get("clients")))
    for x in data.get("aps") or []:
        if x.get("mac"):
            x["series"] = f"ap:{x['mac']}"
            out.append((x["series"], x.get("down_bps"), x.get("up_bps"), x.get("clients")))
    for x in (data.get("clients") or [])[:MAX_CLIENT_SERIES]:
        if x.get("mac"):
            x["series"] = f"client:{x['mac']}"
            out.append((x["series"], x.get("down_bps"), x.get("up_bps"), x.get("signal")))
    return out


SERIES = {"zscaler": _zscaler_series, "meraki": _meraki_series, "panos": _panos_series, "fortigate": _fortigate_series,
          "sonicwall": _sonicwall_series, "proxmox": _proxmox_series, "unifi": _unifi_series}


def ingest_integration_data(s: Session, integ: Integration, data: dict[str, Any], ts: datetime) -> None:
    if not isinstance(data, dict):
        return
    points = integration_series(data)      # also tags each item with its series key
    integ.data = {**data, "ts": ts.isoformat() + "Z"}
    for key, a, b, c in points:
        s.add(IntegrationMetric(integration_id=integ.id, key=key[:160], ts=ts, a=a, b=b, c=c))


def _norm(v) -> str:
    return str(v or "").strip().lower()


def match_local_device(s: Session, rec: dict) -> Device | None:
    """An SNMP or ping device (not yet tied to an integration) that is the same box as an API record.

    Tried in order: serial number, any of the record's IP addresses (LAN, WAN, management), then the name, which
    must match exactly one device's sysName or hostname.
    """
    pool = select(Device).where(Device.integration_id.is_(None), Device.source.in_(("snmp", "ping")))
    extra = rec.get("extra") or {}
    serial = _norm(rec.get("serial"))
    if serial:
        dev = s.scalar(pool.where(func.lower(Device.serial) == serial).limit(1))
        if dev is not None:
            return dev
    ips = [ip for ip in [rec.get("ip"), *(extra.get("ips") or [])] if ip]
    if ips:
        dev = s.scalar(pool.where(Device.ip.in_(ips)).order_by(Device.id).limit(1))
        if dev is not None:
            return dev
    mac = _norm(extra.get("mac")).replace("-", ":")
    if mac:
        for dev in s.scalars(pool.where(Device.extra.is_not(None))):
            if _norm((dev.extra or {}).get("mac")).replace("-", ":") == mac:
                return dev
    name = _norm(rec.get("hostname"))
    if name and name != serial:
        hits = s.scalars(pool.where(or_(func.lower(Device.sys_name) == name, func.lower(Device.hostname) == name)).limit(2)).all()
        if len(hits) == 1:
            return hits[0]
    return None


def merge_into(s: Session, api_dev: Device, local: Device) -> None:
    """Fold a device that only came from an API into the SNMP device for the same box, keeping its history."""
    from .models import Alert, Event
    for model in (DeviceMetric, Alert, Event):
        s.execute(update(model).where(model.device_id == api_dev.id).values(device_id=local.id))
    if not local.site_id:
        local.site_id = api_dev.site_id
    s.delete(api_dev)
    s.flush()


def _apply_record(s: Session, dev: Device, integ: Integration, rec: dict, ts: datetime) -> None:
    merged = dev.source != integ.kind      # an SNMP device enriched by API data
    extra = dict(dev.extra or {})
    if merged:
        extra["api"] = {"integration": integ.name, "detail": rec.get("detail"), "status": rec.get("status"),
                        **(rec.get("extra") or {})}
        if rec.get("cpu") is not None and dev.cpu is None:
            dev.cpu = rec.get("cpu")
        if rec.get("mem") is not None and dev.mem is None:
            dev.mem = rec.get("mem")
        descr_line = (dev.sys_descr or "").splitlines()[0][:255] if dev.sys_descr else None
        if rec.get("platform") and (not dev.platform or dev.platform == descr_line):
            dev.platform = rec["platform"][:255]   # "Proxmox VE" reads better than a raw sysDescr
        dev.serial = dev.serial or rec.get("serial")
        dev.detail = rec.get("detail") or dev.detail
        if not dev.site_id:
            site = site_by_name(s, rec.get("site"))
            dev.site_id = site.id if site else integ.site_id
    else:
        dev.hostname = str(rec.get("hostname") or dev.hostname)[:255]
        dev.ip = rec.get("ip")
        dev.type = rec.get("type") or dev.type
        dev.platform = (rec.get("platform") or "")[:255] or None
        dev.cpu, dev.mem = rec.get("cpu"), rec.get("mem")
        dev.uptime_s = rec.get("uptime_s")
        dev.serial = rec.get("serial")
        dev.detail = (rec.get("detail") or "")[:500] or None
        extra = dict(rec.get("extra") or {})
        status = rec.get("status") if rec.get("status") in ("up", "down", "warn", "unknown", "off") else "unknown"
        set_status(dev, status, rec.get("detail") if status in ("down", "warn") else None)
        dev.last_polled = ts
        site = site_by_name(s, rec.get("site"))
        dev.site_id = site.id if site else (integ.site_id or dev.site_id)
    dev.extra = extra


# ---------------------------------------------------------------- batches
def ingest_batch(s: Session, poller_id: int, batch: dict[str, Any]) -> Alerter | None:
    """Apply one poller batch. Returns the alerter (for notifications) or None if it was a duplicate."""
    batch_id = str(batch.get("batch_id") or "")[:64]
    if not batch_id or s.get(ProcessedBatch, batch_id):
        return None
    s.add(ProcessedBatch(batch_id=batch_id, poller_id=poller_id))
    alerter = Alerter(s)
    for item in batch.get("items") or []:
        if item.get("kind") == "device":
            ingest_device(s, alerter, poller_id, item)
        elif item.get("kind") == "integration":
            integ = s.get(Integration, int(item.get("integration_id") or 0))
            if integ is not None and integ.poller_id == poller_id:
                ingest_integration(s, alerter, integ, item)
    return alerter
