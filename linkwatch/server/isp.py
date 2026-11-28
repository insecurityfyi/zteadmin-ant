"""Working out which ISP a WAN uplink goes to.

In order, the first that answers wins:

1. the name an admin typed for that WAN under the map (``topology.isp_names``);
2. the IP ranges under Settings > Internet providers: the WAN's address inside a CIDR names its ISP
   (handy for CGNAT and private hand-off addresses, which no lookup can place);
3. the ISP the gateway itself reports (UniFi, Meraki);
4. an RDAP lookup of the WAN's public address (the registered network owner, e.g. "SpaceX Services" for
   Starlink), done in the background and cached for a week, so the map never waits on it.

Registry names are tidied with a short alias list ("CHARTER-COMMUNICATIONS" reads "Spectrum").
"""
from __future__ import annotations

import ipaddress
import json
import logging
import re
import time
from typing import Any

import httpx
from sqlalchemy.orm import Session

from .db import get_setting, set_setting

log = logging.getLogger("linkwatch.isp")

RANGES_SETTING = "isp_ranges"          # [{"cidr": "100.64.0.0/10", "isp": "Starlink Satellite"}, ...]
CACHE_SETTING = "isp_lookup_cache"     # {"203.0.113.5": {"isp": "Brightspeed", "ts": 1700000000}}
LOOKUP_SETTING = "isp_lookup"          # "on" (default) | "off"
CACHE_TTL = 7 * 86400
MISS_TTL = 86400                       # retry an address that found nothing once a day
RDAP = "https://rdap.org/ip/{ip}"

# registry / ASN owner names -> what people call the ISP
ALIASES = [
    (r"spacex|starlink", "Starlink"),
    (r"brightspeed", "Brightspeed"),
    (r"charter|spectrum|time warner|twc", "Spectrum"),
    (r"comcast|xfinity", "Comcast"),
    (r"centurylink|lumen|qwest|level 3", "Lumen"),
    (r"at&t|att-internet|sbc|bellsouth", "AT&T"),
    (r"verizon|cellco|mci communications", "Verizon"),
    (r"t-mobile|tmobile", "T-Mobile"),
    (r"cox communications|cox-", "Cox"),
    (r"frontier", "Frontier"),
    (r"windstream|kinetic", "Windstream"),
    (r"altice|optimum|cablevision|suddenlink", "Optimum"),
    (r"mediacom", "Mediacom"),
    (r"google fiber", "Google Fiber"),
    (r"viasat", "Viasat"),
    (r"hughes", "HughesNet"),
]


def tidy(name: str | None) -> str:
    """'CHARTER-COMMUNICATIONS' -> 'Spectrum'; anything unknown comes back trimmed."""
    n = (name or "").strip()
    if not n:
        return ""
    for pat, nice in ALIASES:
        if re.search(pat, n, re.IGNORECASE):
            return nice
    return n[:80]


# ---------------------------------------------------------------- IP ranges (Settings)
def ranges(s: Session) -> list[dict]:
    try:
        v = json.loads(get_setting(s, RANGES_SETTING) or "[]")
    except (TypeError, ValueError):
        return []
    return [r for r in v if isinstance(r, dict) and r.get("cidr") and r.get("isp")] if isinstance(v, list) else []


def parse_ranges(text: str) -> tuple[list[dict], list[str]]:
    """One 'CIDR = ISP name' per line (a comma or tab works too). Returns (rows, problems)."""
    rows, bad = [], []
    for raw in (text or "").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        m = re.match(r"^([0-9a-fA-F:.]+(?:/\d{1,3})?)\s*(?:=|,|\t|\s)\s*(.+)$", line)
        if not m:
            bad.append(raw.strip())
            continue
        try:
            net = ipaddress.ip_network(m.group(1), strict=False)
        except ValueError:
            bad.append(raw.strip())
            continue
        rows.append({"cidr": str(net), "isp": m.group(2).strip()[:80]})
    return rows, bad


def ranges_text(rows: list[dict]) -> str:
    return "\n".join(f"{r['cidr']} = {r['isp']}" for r in rows)


def set_ranges(s: Session, rows: list[dict]) -> None:
    set_setting(s, RANGES_SETTING, json.dumps(rows))


def by_range(rows: list[dict], ip: str | None) -> str:
    """The ISP of the most specific range that holds ``ip``."""
    try:
        addr = ipaddress.ip_address(str(ip or "").split("/")[0].strip())
    except ValueError:
        return ""
    best, plen = "", -1
    for r in rows:
        try:
            net = ipaddress.ip_network(r["cidr"], strict=False)
        except ValueError:
            continue
        if addr.version == net.version and addr in net and net.prefixlen > plen:
            best, plen = r["isp"], net.prefixlen
    return best


# ---------------------------------------------------------------- online lookup (cached)
def is_public(ip: str | None) -> bool:
    try:
        return ipaddress.ip_address(str(ip or "").split("/")[0].strip()).is_global
    except ValueError:
        return False


def lookup_enabled(s: Session) -> bool:
    return (get_setting(s, LOOKUP_SETTING, "on") or "on") != "off"


def cache(s: Session) -> dict[str, dict]:
    try:
        v = json.loads(get_setting(s, CACHE_SETTING) or "{}")
        return v if isinstance(v, dict) else {}
    except (TypeError, ValueError):
        return {}


def cached(s: Session, ip: str | None, now: float | None = None) -> str:
    row = cache(s).get(str(ip or ""))
    return str(row.get("isp") or "") if isinstance(row, dict) else ""


def rdap_owner(body: dict[str, Any]) -> str:
    """The network owner from an RDAP ip answer: the registrant's name, else the network's name."""
    def fn(ent: dict) -> str:
        card = ent.get("vcardArray")
        if isinstance(card, list) and len(card) > 1:
            for f in card[1]:
                if isinstance(f, list) and len(f) > 3 and f[0] == "fn" and f[3]:
                    return str(f[3])
        return ""

    ents = [e for e in body.get("entities") or [] if isinstance(e, dict)]
    for role in ("registrant", "administrative", "abuse"):
        for e in ents:
            if role in (e.get("roles") or []) and fn(e):
                return fn(e)
    return str(body.get("name") or "")


def lookup(ip: str, http: httpx.Client | None = None) -> str:
    own = http is None
    http = http or httpx.Client(timeout=10.0, follow_redirects=True, headers={"Accept": "application/rdap+json"})
    try:
        r = http.get(RDAP.format(ip=ip))
        if r.status_code != 200:
            return ""
        return tidy(rdap_owner(r.json()))
    except (httpx.HTTPError, ValueError):
        return ""
    finally:
        if own:
            http.close()


def refresh(s: Session, ips: list[str], http: httpx.Client | None = None, limit: int = 10) -> int:
    """Look up the public WAN addresses that are not cached (or have gone stale). Returns how many were looked up."""
    if not lookup_enabled(s):
        return 0
    now = time.time()
    c = cache(s)
    todo = []
    for ip in dict.fromkeys(i for i in ips if is_public(i)):
        row = c.get(ip) or {}
        ttl = CACHE_TTL if row.get("isp") else MISS_TTL
        if not row or now - float(row.get("ts") or 0) > ttl:
            todo.append(ip)
    for ip in todo[:limit]:
        c[ip] = {"isp": lookup(ip, http), "ts": int(now)}
    if todo:
        if len(c) > 500:      # keep the newest
            c = dict(sorted(c.items(), key=lambda kv: -float(kv[1].get("ts") or 0))[:500])
        set_setting(s, CACHE_SETTING, json.dumps(c, sort_keys=True))
    return len(todo[:limit])


def refresh_job(app_state) -> None:
    """Background: find the WAN addresses on the map and look up any that are new."""
    from .topology import build_map
    with app_state.db.session() as s:
        if not lookup_enabled(s):
            return
        ips = [l.get("wan_ip") for l in build_map(s)["links"] if l.get("protocol") == "wan" and l.get("wan_ip")]
    if not any(is_public(i) for i in ips):
        return
    with app_state.db.session() as s:
        n = refresh(s, ips)
        if n:
            log.info("Looked up the ISP of %d WAN address(es)", n)
