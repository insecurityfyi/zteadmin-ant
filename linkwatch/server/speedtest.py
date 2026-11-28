"""Scheduled internet speed tests: per-poller settings, ingest, ISP labelling, data caps and the series for charts.

Each poller runs librespeed-cli on its own schedule (see linkwatch/poller/speedtest.py). A poller has one or more
*lanes*: the default route, or a source address the gateway routes out a particular WAN. Every result is filed under
an ISP, worked out in this order (the first that answers wins):

1. the ISP typed for that lane;
2. Settings > Internet providers: the public address inside one of those ranges;
3. the map: a gateway WAN whose address is the public address the test server saw;
4. the cached RDAP lookup of that address (the same cache the map uses);
5. the network owner the speed test server reported ("AS14593 Space Exploration Technologies" reads Starlink).
"""
from __future__ import annotations

import ipaddress
import logging
import re
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from . import events
from . import isp as ispmod
from .models import Poller, SpeedTest, utcnow

log = logging.getLogger("linkwatch.speedtest")

INTERVALS = {1: "Every hour", 2: "Every 2 hours", 3: "Every 3 hours", 4: "Every 4 hours", 6: "Every 6 hours",
             8: "Every 8 hours", 12: "Every 12 hours", 24: "Once a day"}
JITTERS = {0: "None", 10: "± 10 minutes", 20: "± 20 minutes", 30: "± 30 minutes", 60: "± 1 hour"}
DURATIONS = {5: "5 seconds (light)", 10: "10 seconds", 15: "15 seconds (librespeed default)"}
DEFAULTS: dict[str, Any] = {"enabled": False, "interval_h": 6, "jitter_min": 20, "server_ids": [], "server_json": "",
                            "lanes": [{"source": "", "isp": "", "duration": 10, "cap_gb": None, "no_upload": False}]}
MAX_LANES = 4
KEEP_DAYS = 400
METRICS = {"download": ("download_mbps", "Download", "Mbps"), "upload": ("upload_mbps", "Upload", "Mbps"),
           "latency": ("ping_ms", "Latency", "ms"), "jitter": ("jitter_ms", "Jitter", "ms"), "loss": ("loss_pct", "Packet loss", "%")}
RANGES = {"24h": timedelta(hours=24), "7d": timedelta(days=7), "30d": timedelta(days=30), "90d": timedelta(days=90),
          "6h": timedelta(days=2)}           # the dashboard's 6h choice: too short for tests every few hours
PALETTE = ["var(--s1)", "var(--s2)", "#d97706", "#db2777", "#0d9488", "#7c3aed", "#64748b", "#65a30d"]   # --s3 is only set in dark themes
UNKNOWN = "Unknown ISP"


# ------------------------------------------------------------------ settings
def settings(p: Poller) -> dict[str, Any]:
    """The poller's speed test settings with defaults filled in."""
    cur = p.speedtest if isinstance(p.speedtest, dict) else {}
    out = {**DEFAULTS, **{k: v for k, v in cur.items() if k in DEFAULTS}}
    out["lanes"] = [dict(DEFAULTS["lanes"][0], **ln) for ln in (cur.get("lanes") or DEFAULTS["lanes"]) if isinstance(ln, dict)] \
        or [dict(DEFAULTS["lanes"][0])]
    return out


def lane_key(lane: dict) -> str:
    return str(lane.get("source") or "").strip() or "default"


def read_form(form) -> tuple[dict[str, Any], list[str]]:
    """Settings from the speed test form. Returns (settings, problems)."""
    problems: list[str] = []

    def pick(name: str, choices: dict, default: int) -> int:
        try:
            v = int(form.get(name) or default)
        except (TypeError, ValueError):
            return default
        return v if v in choices else default

    cfg: dict[str, Any] = {"enabled": form.get("enabled") is not None, "interval_h": pick("interval_h", INTERVALS, 6),
                           "jitter_min": pick("jitter_min", JITTERS, 20)}
    ids = []
    for tok in re.split(r"[\s,]+", str(form.get("server_ids") or "").strip()):
        if not tok:
            continue
        if tok.isdigit() and 0 < int(tok) < 100000:
            ids.append(int(tok))
        else:
            problems.append(f"Server IDs are numbers from librespeed-cli --list; {tok!r} isn't one.")
    cfg["server_ids"] = ids[:10]
    sj = str(form.get("server_json") or "").strip()[:300]
    if sj and (urlparse(sj).scheme not in ("http", "https") or not urlparse(sj).hostname):
        problems.append("The server list must be an http:// or https:// URL to a LibreSpeed servers JSON file.")
    cfg["server_json"] = sj
    lanes, seen = [], set()
    for i in range(MAX_LANES):
        src = str(form.get(f"lane{i}_source") or "").strip()
        label = str(form.get(f"lane{i}_isp") or "").strip()[:80]
        cap_raw = str(form.get(f"lane{i}_cap_gb") or "").strip()
        used = i == 0 or src or label or cap_raw
        if not used:
            continue
        if src and src.lower() != "default":
            try:
                src = str(ipaddress.ip_address(src))
            except ValueError:
                problems.append(f"Lane {i + 1}: the source must be an IP address on the poller host, such as 192.168.20.5.")
                continue
        else:
            src = ""
        key = src or "default"
        if key in seen:
            problems.append(f"Lane {i + 1}: two lanes use {'the default route' if key == 'default' else key}.")
            continue
        seen.add(key)
        cap = None
        if cap_raw:
            try:
                cap = float(cap_raw)
                if not 0 < cap <= 100000:
                    raise ValueError
            except ValueError:
                problems.append(f"Lane {i + 1}: the monthly cap is a number of GB, such as 50.")
                cap = None
        dur = pick(f"lane{i}_duration", DURATIONS, 10)
        lanes.append({"source": src, "isp": label, "duration": dur, "cap_gb": cap,
                      "no_upload": form.get(f"lane{i}_no_upload") is not None})
    cfg["lanes"] = lanes or [dict(DEFAULTS["lanes"][0])]
    return cfg, problems


# ------------------------------------------------------------------ data caps
def month_start(now: datetime | None = None) -> datetime:
    now = now or utcnow()
    return now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


def month_usage(s: Session, poller_id: int) -> dict[str, int]:
    """Bytes used by speed tests this calendar month (UTC), per lane."""
    rows = s.execute(select(SpeedTest.lane, func.sum(SpeedTest.bytes_used))
                     .where(SpeedTest.poller_id == poller_id, SpeedTest.ts >= month_start())
                     .group_by(SpeedTest.lane)).all()
    return {lane: int(n or 0) for lane, n in rows}


def avg_bytes(s: Session, poller_id: int, lane: str) -> int | None:
    rows = s.scalars(select(SpeedTest.bytes_used).where(SpeedTest.poller_id == poller_id, SpeedTest.lane == lane,
                                                        SpeedTest.ok.is_(True), SpeedTest.bytes_used.is_not(None))
                     .order_by(SpeedTest.ts.desc()).limit(10)).all()
    return int(sum(rows) / len(rows)) if rows else None


def projection(cfg: dict, lane: dict, per_test: int | None) -> int | None:
    """Bytes a month at this schedule, from the average of recent tests."""
    if per_test is None:
        return None
    return int(per_test * (30 * 24 / max(1, cfg["interval_h"])))


def poller_config(s: Session, poller: Poller) -> dict[str, Any]:
    """What the poller gets in its config: schedule, server choice and lanes, with lanes over their cap blocked."""
    cfg = settings(poller)
    used = month_usage(s, poller.id)
    lanes = []
    for ln in cfg["lanes"]:
        key = lane_key(ln)
        out = {"key": key, "source": ln["source"] or None, "duration": ln["duration"], "no_upload": bool(ln["no_upload"])}
        if ln.get("cap_gb"):
            cap = int(float(ln["cap_gb"]) * 1e9)
            out["budget_bytes"] = max(0, cap - used.get(key, 0))
            if used.get(key, 0) >= cap:
                out["blocked"] = True
                out["blocked_reason"] = f"Monthly data cap of {float(ln['cap_gb']):g} GB reached"
        lanes.append(out)
    return {"enabled": cfg["enabled"], "interval_h": cfg["interval_h"], "jitter_min": cfg["jitter_min"],
            "server_ids": cfg["server_ids"], "server_json": cfg["server_json"], "lanes": lanes}


# ------------------------------------------------------------------ ISP labels
def _owner(org: str | None) -> str:
    """'AS14593 Space Exploration Technologies Corporation' -> 'Starlink'."""
    return ispmod.tidy(re.sub(r"^AS\d+\s+", "", (org or "").strip()))


def map_isps(s: Session) -> dict[str, str]:
    """WAN address -> ISP from the map, for gateways that hold the public address themselves."""
    try:
        from .topology import build_map
        return {str(l["wan_ip"]).split("/")[0]: l["isp"] for l in build_map(s)["links"]
                if l.get("protocol") == "wan" and l.get("wan_ip") and l.get("isp")}
    except Exception:  # noqa: BLE001 - labelling must never lose a result
        log.exception("Could not read WAN ISPs from the map")
        return {}


def resolve_isp(s: Session, typed: str | None, public_ip: str | None, org: str | None,
                wan_isps: dict[str, str] | None = None) -> tuple[str, str]:
    """(ISP, how) for one result; see the module docstring for the order."""
    if typed:
        return typed, "manual"
    if public_ip:
        hit = ispmod.by_range(ispmod.ranges(s), public_ip)
        if hit:
            return hit, "range"
        hit = (map_isps(s) if wan_isps is None else wan_isps).get(public_ip)
        if hit:
            return hit, "map"
        hit = ispmod.cached(s, public_ip)
        if hit:
            return hit, "lookup"
    hit = _owner(org)
    if hit:
        return hit, "speedtest"
    return UNKNOWN, ""


# ------------------------------------------------------------------ ingest
def _num(v, lo: float = 0, hi: float = 1e6) -> float | None:
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    return round(max(lo, min(hi, f)), 3)


def ingest(s: Session, poller_id: int, item: dict[str, Any]) -> SpeedTest | None:
    from .ingest import from_epoch
    poller = s.get(Poller, poller_id)
    if poller is None:
        return None
    lane = item.get("lane") if isinstance(item.get("lane"), dict) else {}
    key = str(lane.get("key") or "default")[:64]
    cfg = settings(poller)
    conf = next((ln for ln in cfg["lanes"] if lane_key(ln) == key), {})
    ip = str(item.get("public_ip") or "")[:45] or None
    if ip:
        try:
            ip = str(ipaddress.ip_address(ip))
        except ValueError:
            ip = None
    server = item.get("server") if isinstance(item.get("server"), dict) else {}
    r = SpeedTest(poller_id=poller_id, ts=from_epoch(item.get("ts")), ok=bool(item.get("ok")), skipped=bool(item.get("skipped")),
                  error=str(item["error"])[:500] if item.get("error") else None,
                  trigger="manual" if item.get("trigger") == "manual" else "schedule", lane=key, public_ip=ip,
                  org=str(item.get("org") or "")[:120] or None, server=str(server.get("name") or "")[:120] or None,
                  server_url=str(server.get("url") or "")[:300] or None,
                  download_mbps=_num(item.get("download_mbps"), 0, 1e5), upload_mbps=_num(item.get("upload_mbps"), 0, 1e5),
                  ping_ms=_num(item.get("ping_ms"), 0, 1e5), jitter_ms=_num(item.get("jitter_ms"), 0, 1e5),
                  loss_pct=_num(item.get("loss_pct"), 0, 100),
                  latency_from=item.get("latency_from") if item.get("latency_from") in ("icmp", "http") else None,
                  duration_s=_num(item.get("duration_s"), 0, 3600))
    used = int(_num(item.get("bytes_sent"), 0, 1e12) or 0) + int(_num(item.get("bytes_received"), 0, 1e12) or 0)
    r.bytes_used = used or None
    if r.ok or ip or conf.get("isp"):
        r.isp, r.isp_source = resolve_isp(s, conf.get("isp"), ip, r.org)
    before = month_usage(s, poller_id).get(key, 0)
    s.add(r)
    s.flush()
    cap = conf.get("cap_gb")
    if cap and used and before < cap * 1e9 <= before + used:
        events.log(s, "poller", f"Speed tests from {poller.name} on {r.isp or key} paused until next month: "
                                f"{(before + used) / 1e9:.1f} of {float(cap):g} GB used", "warn")
    return r


def prune(s: Session) -> None:
    s.execute(delete(SpeedTest).where(SpeedTest.ts < utcnow() - timedelta(days=KEEP_DAYS)))


# ------------------------------------------------------------------ views
def isp_summary(s: Session, poller_id: int | None = None, days: int = 30) -> list[dict[str, Any]]:
    """Per ISP: the latest good result, the 7-day averages and how many tests, newest ISPs included only if seen in
    ``days``. Sorted by name, so colours stay put."""
    q = select(SpeedTest).where(SpeedTest.ok.is_(True), SpeedTest.ts >= utcnow() - timedelta(days=days))
    if poller_id:
        q = q.where(SpeedTest.poller_id == poller_id)
    rows = s.scalars(q.order_by(SpeedTest.ts.desc())).all()
    week = utcnow() - timedelta(days=7)
    by: dict[str, dict[str, Any]] = {}
    for r in rows:
        name = r.isp or UNKNOWN
        g = by.setdefault(name, {"isp": name, "latest": r, "n": 0, "week": []})
        g["n"] += 1
        if r.ts >= week:
            g["week"].append(r)
    out = []
    for i, name in enumerate(sorted(by, key=lambda n: (n == UNKNOWN, n.lower()))):
        g = by[name]

        def avg(attr: str):
            vals = [getattr(x, attr) for x in g["week"] if getattr(x, attr) is not None]
            return sum(vals) / len(vals) if vals else None
        g.update({"key": series_key(name), "color": PALETTE[i % len(PALETTE)], "avg_down": avg("download_mbps"),
                  "avg_up": avg("upload_mbps"), "avg_ping": avg("ping_ms"), "kind": _kind(name)})
        g["spec"] = {"key": g["key"], "color": g["color"], "area": False}
        out.append(g)
    return out


def _kind(name: str) -> str:
    from .topology import isp_kind
    return isp_kind(name)


def series_key(isp: str | None) -> str:
    """A stable key for an ISP's series in chart data: 'Starlink Satellite' -> 'starlink_satellite'."""
    return "isp_" + (re.sub(r"[^a-z0-9]+", "_", (isp or UNKNOWN).lower()).strip("_") or "unknown")


def series(s: Session, metric: str, range_: str, poller_id: int | None = None) -> dict[str, Any]:
    """One point per test, one series per ISP (keyed by ``series_key``); other ISPs' points are null there."""
    col = METRICS.get(metric, METRICS["download"])[0]
    q = select(SpeedTest.ts, SpeedTest.isp, getattr(SpeedTest, col)).where(
        SpeedTest.ok.is_(True), SpeedTest.ts >= utcnow() - RANGES.get(range_, RANGES["7d"]))
    if poller_id:
        q = q.where(SpeedTest.poller_id == poller_id)
    rows = s.execute(q.order_by(SpeedTest.ts)).all()
    keys = sorted({series_key(isp) for _, isp, _ in rows})
    out: dict[str, Any] = {"ts": [], **{k: [] for k in keys}}
    for ts, isp, v in rows:
        k = series_key(isp)
        out["ts"].append(ts.isoformat() + "Z")
        for kk in keys:
            out[kk].append(v if kk == k else None)
    return out
