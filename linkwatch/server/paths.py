"""Path probes: hop-by-hop mtr results from pollers, AS/provider lookup, route-change detection and alerts."""
from __future__ import annotations

import hashlib
import ipaddress
import logging
import re
import time
from datetime import timedelta
from typing import Any

import httpx
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from . import events
from .alerts import Alerter
from .models import AsnInfo, PathProbe, PathResult, Poller, utcnow

log = logging.getLogger("linkwatch.paths")

PROTOCOLS = {"icmp": "ICMP (ping)", "udp": "UDP", "tcp": "TCP"}
INTERVALS = {60: "Every minute", 300: "Every 5 minutes", 600: "Every 10 minutes", 900: "Every 15 minutes",
             1800: "Every 30 minutes", 3600: "Every hour"}
TARGET = re.compile(r"^[A-Za-z0-9.:\-_]{1,253}$")
RIPESTAT = "https://stat.ripe.net/data/prefix-overview/data.json"
ASN_TTL = timedelta(days=30)
ASN_MISS_TTL = timedelta(days=1)
KEEP_DAYS = 30
_backoff_until = 0.0      # after a failed lookup, stop trying for a while (offline or blocked servers)

SPECIAL = [(ipaddress.ip_network(n), label) for n, label in (
    ("10.0.0.0/8", "Private network"), ("172.16.0.0/12", "Private network"), ("192.168.0.0/16", "Private network"),
    ("100.64.0.0/10", "Carrier-grade NAT"), ("127.0.0.0/8", "Loopback"), ("169.254.0.0/16", "Link-local"),
    ("fc00::/7", "Private network"), ("fe80::/10", "Link-local"), ("::1/128", "Loopback"))]


# ------------------------------------------------------------------ AS lookup
def special(ip: str | None) -> str | None:
    """A label for addresses that have no public AS (private, CGNAT...), or None for a public address."""
    try:
        addr = ipaddress.ip_address(ip or "")
    except ValueError:
        return "Unknown"
    for net, label in SPECIAL:
        if addr.version == net.version and addr in net:
            return label
    return None if addr.is_global else "Reserved"


def fetch_asn(ip: str, timeout: float = 4.0) -> dict[str, Any]:
    """Origin AS for an address from RIPEstat. Raises httpx errors when the service can't be reached."""
    r = httpx.get(RIPESTAT, params={"resource": ip, "sourceapp": "linkwatch"}, timeout=timeout)
    r.raise_for_status()
    data = r.json().get("data") or {}
    asns = data.get("asns") or []
    first = asns[0] if asns else {}
    return {"asn": int(first["asn"]) if first.get("asn") else None, "holder": (first.get("holder") or None),
            "prefix": data.get("resource") if data.get("announced") else None}


def lookup(s: Session, ips: list[str], budget: int = 16) -> dict[str, AsnInfo]:
    """Cached AS info for public addresses, fetching at most ``budget`` that are missing or stale."""
    global _backoff_until
    want = sorted({ip for ip in ips if ip and special(ip) is None})
    if not want:
        return {}
    have = {a.ip: a for a in s.scalars(select(AsnInfo).where(AsnInfo.ip.in_(want)))}
    now = utcnow()
    for ip in want:
        row = have.get(ip)
        fresh = row is not None and now - row.fetched_at < (ASN_TTL if row.asn else ASN_MISS_TTL)
        if fresh or budget <= 0 or time.monotonic() < _backoff_until:
            continue
        budget -= 1
        try:
            info = fetch_asn(ip)
        except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
            log.info("AS lookup for %s failed (%s); trying again in 10 minutes", ip, exc.__class__.__name__)
            _backoff_until = time.monotonic() + 600
            continue
        if row is None:
            row = AsnInfo(ip=ip)
            s.add(row)
            have[ip] = row
        row.asn, row.holder, row.prefix, row.fetched_at = info["asn"], (info["holder"] or "")[:255] or None, info["prefix"], now
    s.flush()
    return have


def provider(holder: str | None) -> str:
    """'CLOUDFLARENET - Cloudflare, Inc.' -> 'Cloudflare, Inc.'"""
    if not holder:
        return ""
    name = holder.split(" - ", 1)[1] if " - " in holder else holder
    return re.sub(r",?\s+[A-Z]{2}$", "", name).strip()


def network_of(ip: str | None, cache: dict[str, AsnInfo]) -> dict[str, Any]:
    """What to show for a hop's network: {key, asn, name, holder, prefix}."""
    if not ip:
        return {"key": None, "asn": None, "name": "No reply", "holder": None, "prefix": None}
    label = special(ip)
    if label:
        return {"key": label, "asn": None, "name": label, "holder": None, "prefix": None}
    row = cache.get(ip)
    if row is None or row.asn is None:
        return {"key": "?", "asn": None, "name": "Looking up…" if row is None else "Not announced", "holder": None,
                "prefix": row.prefix if row else None}
    return {"key": f"AS{row.asn}", "asn": row.asn, "name": provider(row.holder) or f"AS{row.asn}", "holder": row.holder,
            "prefix": row.prefix}


# ------------------------------------------------------------------ ingest
def _num(v, lo: float = 0, hi: float = 1e6) -> float | None:
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    return max(lo, min(hi, f))


def clean_hops(raw) -> list[dict[str, Any]]:
    hops = []
    for h in (raw or [])[:64]:
        if not isinstance(h, dict):
            continue
        ip = str(h.get("ip") or "")[:45] or None
        if ip:
            try:
                ip = str(ipaddress.ip_address(ip))
            except ValueError:
                ip = None
        hops.append({"n": int(_num(h.get("n"), 1, 255) or len(hops) + 1), "ip": ip,
                     "loss": 100.0 if ip is None else (_num(h.get("loss"), 0, 100) or 0.0),
                     "sent": int(_num(h.get("sent"), 0, 10000) or 0),
                     **{k: (_num(h.get(k)) if ip else None) for k in ("last", "avg", "best", "worst", "stdev", "jitter")}})
    return hops


def path_hash(hops: list[dict]) -> str:
    seq = [h["ip"] or "*" for h in hops]
    while seq and seq[-1] == "*":
        seq.pop()
    return hashlib.sha1("|".join(seq).encode()).hexdigest()[:16]


def as_path(hops: list[dict], cache: dict[str, AsnInfo]) -> list[str] | None:
    """Networks crossed, in order (AS numbers or labels such as 'Private network'). None if some are still unknown."""
    out: list[str] = []
    for h in hops:
        if not h["ip"]:
            continue
        key = network_of(h["ip"], cache)["key"]
        if key == "?":
            row = cache.get(h["ip"])
            if row is None:
                return None
            continue                           # looked up, not announced: ignore
        if not out or out[-1] != key:
            out.append(key)
    return out


def ingest_probe(s: Session, alerter: Alerter, poller_id: int, item: dict[str, Any]) -> PathResult | None:
    from .ingest import from_epoch
    probe = s.get(PathProbe, int(item.get("probe_id") or 0))
    if probe is None or poller_id not in (probe.poller_ids or []):
        return None
    hops = clean_hops(item.get("hops"))
    r = PathResult(probe_id=probe.id, poller_id=poller_id, ts=from_epoch(item.get("ts")), ok=bool(item.get("ok")) and bool(hops),
                   error=str(item["error"])[:500] if item.get("error") else None, hops=hops, hop_count=len(hops))
    if hops:
        last = hops[-1]
        r.reached = bool(last["ip"]) and last["loss"] < 100
        r.loss_pct = last["loss"]
        r.avg_ms, r.best_ms, r.worst_ms, r.jitter_ms = last["avg"], last["best"], last["worst"], last["jitter"]
        r.path_hash = path_hash(hops)
        cache = lookup(s, [h["ip"] for h in hops if h["ip"]])
        r.asns = as_path(hops, cache)
    prev = s.scalar(select(PathResult).where(PathResult.probe_id == probe.id, PathResult.poller_id == poller_id,
                                             PathResult.ok.is_(True), PathResult.ts < r.ts).order_by(PathResult.ts.desc()).limit(1))
    if r.ok and prev is not None:
        if r.asns is not None and prev.asns is not None and r.asns != prev.asns:
            r.changed = "asn"
            poller = s.get(Poller, poller_id)
            events.log(s, "path", f"Path {probe.name} from {poller.name if poller else 'a poller'} now crosses "
                                  f"{' > '.join(r.asns) or 'no public networks'} (was {' > '.join(prev.asns) or 'none'})", "warn")
        elif r.path_hash != prev.path_hash:
            r.changed = "route"
    s.add(r)
    s.flush()
    evaluate(s, alerter, probe, poller_id)
    return r


# ------------------------------------------------------------------ alerts
def ref(probe_id: int, poller_id: int) -> str:
    return f"path:{probe_id}:{poller_id}"


def evaluate(s: Session, alerter: Alerter, probe: PathProbe, poller_id: int) -> None:
    key = ref(probe.id, poller_id)
    poller = s.get(Poller, poller_id)
    where = f"{probe.name} from {poller.name if poller else 'poller'}"
    rules = {k: alerter.rule(k) for k in ("path_loss", "path_latency", "path_change")}
    n = max([r.polls for r in rules.values() if r] + [1])
    recent = s.scalars(select(PathResult).where(PathResult.probe_id == probe.id, PathResult.poller_id == poller_id)
                       .order_by(PathResult.ts.desc()).limit(n)).all()

    def held(polls: int, test) -> bool:
        rows = recent[:polls]
        return len(rows) >= polls and all(x.ok and test(x) for x in rows)

    if probe.enabled:
        rl = rules["path_loss"]
        thr = probe.loss_pct if probe.loss_pct is not None else (rl.threshold if rl else None)
        hot = bool(rl and thr is not None and held(rl.polls, lambda x: (x.loss_pct or 0) > thr))
        alerter.set("path_loss", key, hot, f"Path loss: {where}",
                    f"{recent[0].loss_pct:.0f}% loss to {probe.target} for {rl.polls} runs, threshold {thr:g}%" if hot else None)
        rl = rules["path_latency"]
        thr = probe.latency_ms if probe.latency_ms is not None else (rl.threshold if rl else None)
        hot = bool(rl and thr is not None and held(rl.polls, lambda x: x.avg_ms is not None and x.avg_ms > thr))
        alerter.set("path_latency", key, hot, f"Path latency: {where}",
                    f"{recent[0].avg_ms:.0f} ms to {probe.target} for {rl.polls} runs, threshold {thr:g} ms" if hot else None)
        rl = rules["path_change"]
        changed = bool(rl and any(x.changed == "asn" for x in recent[:rl.polls]))
        last_change = next((x for x in recent if x.changed == "asn"), None)
        alerter.set("path_change", key, changed, f"Path changed networks: {where}",
                    f"Now via {' > '.join(last_change.asns or [])}" if changed and last_change else None)
    else:
        for k in rules:
            alerter.set(k, key, False)


def clear_alerts(alerter: Alerter, probe_id: int, keep_pollers: set[int] = frozenset()) -> None:
    """Resolve a probe's alerts for pollers no longer running it (or all of them when the probe is deleted)."""
    prefix = f"path:{probe_id}:"
    for k, r in list(alerter.open):
        if r.startswith(prefix) and int(r.rsplit(":", 1)[1]) not in keep_pollers:
            alerter.set(k, r, False)


# ------------------------------------------------------------------ config, retention
def poller_probes(s: Session, poller_id: int) -> list[dict[str, Any]]:
    return [{"id": p.id, "target": p.target, "protocol": p.protocol, "port": p.port, "count": p.count, "interval": p.interval_s}
            for p in s.scalars(select(PathProbe).where(PathProbe.enabled.is_(True)).order_by(PathProbe.id))
            if poller_id in (p.poller_ids or [])]


def prune(s: Session) -> None:
    s.execute(delete(PathResult).where(PathResult.ts < utcnow() - timedelta(days=KEEP_DAYS)))
    s.execute(delete(AsnInfo).where(AsnInfo.fetched_at < utcnow() - timedelta(days=90)))


# ------------------------------------------------------------------ diagram
PALETTE = [212, 160, 32, 280, 350, 190, 100, 250]


def diagram(hops: list[dict], cache: dict[str, AsnInfo], source: str, target: str) -> dict[str, Any]:
    """Layout for the hop-by-hop SVG: nodes left to right, with a band behind each run of hops in the same network."""
    step, pad = 150, 80
    final_loss = hops[-1]["loss"] if hops else 0
    nodes = [{"x": pad, "kind": "source", "label": source, "sub": "Poller", "health": "ok"}]
    for i, h in enumerate(hops):
        net = network_of(h["ip"], cache)
        if not h["ip"]:
            health = "none"
        elif h["loss"] > 0 and final_loss > 0 and i == len(hops) - 1:
            health = "bad"
        elif h["loss"] > 0 and final_loss > 0:
            health = "bad" if h["loss"] >= final_loss * 0.5 else "warn"
        elif h["loss"] > 0:
            health = "limited"       # loss here only: the router rate-limits replies, traffic is fine
        else:
            health = "ok"
        prev = next((x for x in reversed(hops[:i]) if x["avg"] is not None), None)
        delta = (h["avg"] - prev["avg"]) if h["avg"] is not None and prev else None
        nodes.append({"x": pad + (i + 1) * step, "kind": "target" if i == len(hops) - 1 else "hop", "hop": h, "net": net,
                      "health": health, "delta": delta, "label": h["ip"] or "* * *"})
    keys = [n["net"]["key"] if n.get("net") else None for n in nodes]
    for i in range(1, len(keys)):       # a silent hop between two hops of the same network belongs to it
        if keys[i] is None:
            nxt = next((k for k in keys[i + 1:] if k is not None), None)
            if nxt is not None and nxt == keys[i - 1]:
                keys[i] = nxt
    bands, i = [], 1
    while i < len(nodes):
        k = keys[i]
        j = i
        while j + 1 < len(nodes) and keys[j + 1] == k:
            j += 1
        if k is not None:
            net = next((nodes[x]["net"] for x in range(i, j + 1) if nodes[x]["net"]["key"] == k), {})
            hue = PALETTE[int(hashlib.md5(k.encode()).hexdigest(), 16) % len(PALETTE)] if k.startswith("AS") else None
            bands.append({"x": nodes[i]["x"] - step / 2 + 6, "w": (j - i + 1) * step - 12, "key": k, "hue": hue,
                          "title": k if k.startswith("AS") else net.get("name", k),
                          "name": net.get("name", "") if k.startswith("AS") else "", "holder": net.get("holder")})
        i = j + 1
    return {"nodes": nodes, "bands": bands, "width": pad * 2 + len(hops) * step, "target": target}
