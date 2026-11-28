"""The network map's nodes and links.

Devices reach the database from several places: SNMP polling, discovery, and API integrations (UniFi, Meraki,
Proxmox, PAN-OS, Synology, pfSense, ...). The same box often turns up more than once: an SNMP device and the
UniFi record for it, an FQDN and a short name, a second integration that sees a box the first one already
claimed. Nothing is merged in the database here. The map groups the rows that are the same box (same serial,
MAC, management address, or name) into one node, so nothing is lost and every row keeps its own history.

Links come from:

* LLDP/CDP neighbours polled over SNMP, and the uplinks integrations report (stored as ``Neighbor`` rows);
* neighbours that could not be tied to a device when they were polled, matched again here by address, MAC or name;
* UniFi switch ports: a monitored box seen as the client (or the LLDP neighbour) of a UniFi port, which is how
  API-only devices such as Proxmox hosts and Palo Alto firewalls get linked;
* links an admin drew by hand (``protocol = "manual"``).

Gateways get one link per WAN uplink: from UniFi WANs, Meraki appliance uplinks,
pfSense/VyOS gateways, ports an admin marked as Internet uplinks, or ports whose name says WAN/Internet. Each
WAN ends at a circle for its ISP: the name an admin gave that WAN on the map page, else the ISP the API reports.
"""
from __future__ import annotations

import ipaddress
import json
import re
from typing import Any, Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from .db import get_setting, set_setting
from .models import Device, Integration, Neighbor, Port

# Types drawn even when nothing links them yet; anything else needs a link (or "all").
INFRA = {"Switch", "Router", "Firewall", "Hypervisor", "NAS", "Storage", "Wireless"}
# Never merged with or linked as infrastructure: guests share their host's port and often its name.
GUESTS = {"VM", "Container"}
# Not boxes at all, or boxes whose address is someone else's (a GRE tunnel's source is the gateway's public IP).
_NO_GROUP = GUESTS | {"VPN tunnel"}
_NO_IP_KEY = {"Zscaler"}
WAN_SETTING = "map_wan_ports"
ISP_SETTING = "map_wan_isps"       # {"<gateway host>|<wan name>": "Brightspeed Fiber", ...}
_WAN_NAME = re.compile(r"(^|[^a-z])(wan\d*|internet|isp\d*)([^a-z]|$)", re.IGNORECASE)
_PORT_PREFIX = [("tengigabitethernet", "te"), ("twentyfivegige", "twe"), ("fortygigabitethernet", "fo"),
                ("hundredgige", "hu"), ("gigabitethernet", "gi"), ("fastethernet", "fa"), ("ethernet", "eth"),
                ("interface", ""), ("port", "")]
_BAD_SERIAL = {"", "0", "none", "null", "unknown", "n/a", "na", "default", "string", "serial", "123456789", "0123456789"}


# ---------------------------------------------------------------- normalising
def short(name: str | None) -> str:
    """Host name without the domain, lower case. IP addresses and MACs are not names."""
    n = (name or "").strip().lower()
    if not n or is_ip(n) or norm_mac(n):
        return ""
    return n.split(".")[0]


def is_ip(v: str | None) -> bool:
    try:
        ipaddress.ip_address(str(v or "").strip())
        return True
    except ValueError:
        return False


def norm_ip(v: Any) -> str:
    s = str(v or "").strip().split("/")[0]
    return s if is_ip(s) else ""


def norm_mac(v: Any) -> str:
    h = re.sub(r"[^0-9a-f]", "", str(v or "").lower())
    if len(h) != 12 or h in ("000000000000", "ffffffffffff"):
        return ""
    return ":".join(h[i:i + 2] for i in range(0, 12, 2))


def norm_port(v: Any) -> str:
    """'GigabitEthernet1/0/1', 'Gi1/0/1' and 'gi 1/0/1' are the same port; so are 'Port 5' and 'port 5'."""
    p = re.sub(r"\s+", "", str(v or "").lower())
    for long, ab in _PORT_PREFIX:
        if p.startswith(long):
            p = ab + p[len(long):]
            break
    return p


def _extra(d: Device) -> dict:
    return d.extra if isinstance(d.extra, dict) else {}


def _api(d: Device) -> dict:
    a = _extra(d).get("api")
    return a if isinstance(a, dict) else {}


def device_macs(d: Device) -> set[str]:
    ex, api = _extra(d), _api(d)
    vals = [ex.get("mac"), api.get("mac"), *(ex.get("macs") or []), *(api.get("macs") or [])]
    vals += [p.get("mac") for p in (ex.get("interfaces") or []) if isinstance(p, dict)]
    return {m for m in (norm_mac(v) for v in vals) if m}


def device_ips(d: Device) -> set[str]:
    ex, api = _extra(d), _api(d)
    vals = [d.ip, *(ex.get("ips") or []), *(api.get("ips") or [])]
    return {i for i in (norm_ip(v) for v in vals) if i}


def device_names(d: Device) -> set[str]:
    names = {short(d.hostname), short(d.sys_name)}
    if d.ip and not is_ip(d.ip):       # added by DNS name
        names.add(short(d.ip))
    return {n for n in names if n}


def _serial(d: Device) -> str:
    s = re.sub(r"\s+", "", str(d.serial or "").lower())
    return "" if s in _BAD_SERIAL or len(s) < 4 else s


def speed_label(mbps: float | None) -> str:
    if not mbps:
        return ""
    if mbps >= 1000:
        g = mbps / 1000
        return f"{g:g}G" if g == int(g) or g < 10 else f"{round(g)}G"
    return f"{int(mbps)}M"


# ---------------------------------------------------------------- grouping duplicates
class _UF:
    def __init__(self) -> None:
        self.parent: dict[int, int] = {}

    def find(self, x: int) -> int:
        self.parent.setdefault(x, x)
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[max(ra, rb)] = min(ra, rb)


def _rank(d: Device) -> tuple:
    """Which row of a group speaks for it: the one a poller polls, then the one with ports, then the oldest."""
    return (0 if d.source in ("snmp", "ping") else 1, 0 if d.ports else 1, 0 if d.status in ("up", "warn", "down") else 1, d.id)


def group_duplicates(devs: Iterable[Device]) -> dict[int, int]:
    """Map every device id to the id of the device that represents its group (itself when it has no twin).

    Two rows are the same box when they share a serial number, a MAC, a management address, or a name (sysName,
    host name or DNS name without the domain) and are not at two different sites. Guests (VMs, containers) are
    left alone: a VM often carries its host's name or sits on its host's address.
    """
    devs = [d for d in devs if d.type not in _NO_GROUP]
    uf = _UF()
    by: dict[tuple[str, str], list[Device]] = {}
    for d in devs:
        uf.find(d.id)
        keys = [("serial", _serial(d))] + [("mac", m) for m in {norm_mac(_extra(d).get("mac")), norm_mac(_api(d).get("mac"))}]
        keys += [("ip", "" if d.type in _NO_IP_KEY else norm_ip(d.ip))] + [("name", n) for n in device_names(d)]
        for k in keys:
            if k[1]:
                by.setdefault(k, []).append(d)
    for (kind, _), rows in by.items():
        if len(rows) < 2:
            continue
        first = rows[0]
        for other in rows[1:]:
            if kind in ("name", "ip") and first.site_id and other.site_id and first.site_id != other.site_id:
                continue        # "gw" at two sites, or 192.168.1.1 behind two NATs, are two boxes
            uf.union(first.id, other.id)
    groups: dict[int, list[Device]] = {}
    for d in devs:
        groups.setdefault(uf.find(d.id), []).append(d)
    rep: dict[int, int] = {}
    for rows in groups.values():
        head = min(rows, key=_rank)
        for d in rows:
            rep[d.id] = head.id
    return rep


# ---------------------------------------------------------------- the map
class _Index:
    """Find a group by address, MAC or name."""

    def __init__(self, devs: dict[int, Device], rep: dict[int, int]):
        self.ip: dict[str, int] = {}
        self.mac: dict[str, int] = {}
        self.name: dict[str, set[int]] = {}
        self.host: dict[str, int] = {}
        for d in devs.values():
            g = rep.get(d.id)
            if g is None:
                continue
            for i in device_ips(d):
                self.ip.setdefault(i, g)
            for m in device_macs(d):
                self.mac.setdefault(m, g)
            for n in device_names(d):
                self.name.setdefault(n, set()).add(g)
            self.host.setdefault((d.hostname or "").strip().lower(), g)

    def find(self, ip: Any = None, mac: Any = None, name: Any = None) -> int | None:
        i, m = norm_ip(ip), norm_mac(mac)
        if i and i in self.ip:
            return self.ip[i]
        if m and m in self.mac:
            return self.mac[m]
        exact = self.host.get(str(name or "").strip().lower())
        if exact is not None:
            return exact
        hits = self.name.get(short(name), set())
        return next(iter(hits)) if len(hits) == 1 else None


def _ports_by_group(devs: dict[int, Device], rep: dict[int, int]) -> dict[int, dict[str, Port]]:
    out: dict[int, dict[str, Port]] = {}
    for d in devs.values():
        g = rep.get(d.id)
        if g is None:
            continue
        tbl = out.setdefault(g, {})
        for p in d.ports:
            for k in (norm_port(p.name), norm_port(p.alias)):
                if k:
                    tbl.setdefault(k, p)
    return out


def _port_stats(p: Port | None) -> dict:
    if p is None:
        return {}
    bps = max(p.in_bps or 0, p.out_bps or 0) if (p.in_bps is not None or p.out_bps is not None) else None
    return {"speed": p.speed_mbps, "util": p.util_pct, "bps": bps}


def wan_port_ids(s: Session) -> set[int]:
    try:
        return {int(x) for x in json.loads(get_setting(s, WAN_SETTING) or "[]")}
    except (TypeError, ValueError):
        return set()


def set_wan_port(s: Session, port_id: int, on: bool) -> None:
    ids = wan_port_ids(s)
    ids = ids | {port_id} if on else ids - {port_id}
    set_setting(s, WAN_SETTING, json.dumps(sorted(ids)))


def wan_key(gateway: str | None, wan: str | None) -> str:
    return f"{(gateway or '').strip().lower()}|{(wan or '').strip().lower()}"[:200]


def isp_names(s: Session) -> dict[str, str]:
    try:
        v = json.loads(get_setting(s, ISP_SETTING) or "{}")
        return {str(k): str(n) for k, n in v.items() if n} if isinstance(v, dict) else {}
    except (TypeError, ValueError):
        return {}


def set_isp_names(s: Session, names: dict[str, str]) -> None:
    """Set (or with an empty name, clear) the ISP shown for each WAN, keyed by ``wan_key``."""
    cur = isp_names(s)
    for k, n in names.items():
        n = (n or "").strip()[:80]
        if n:
            cur[k[:200]] = n
        else:
            cur.pop(k[:200], None)
    set_setting(s, ISP_SETTING, json.dumps(cur, sort_keys=True))


def isp_kind(name: str) -> str:
    """Which glyph an ISP circle gets: satellite, fiber, cable, cellular, or a plain globe."""
    n = (name or "").lower()
    for kind, words in (("satellite", ("starlink", "satellite", "viasat", "hughes", "oneweb", "kuiper")),
                        ("cellular", ("lte", "5g", "4g", "cellular", "t-mobile", "verizon wireless", "mobile")),
                        ("fiber", ("fiber", "fibre", "ftth", "fios", "brightspeed")),
                        ("cable", ("cable", "spectrum", "comcast", "xfinity", "cox", "docsis", "optimum"))):
        if any(w in n for w in words):
            return kind
    return "globe"


def _isp_id(name: str) -> str:
    return "isp:" + re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


def build_map(s: Session, site: str = "", external: bool = False, show_all: bool = False, hide_aps: bool = False) -> dict:
    devs = {d.id: d for d in s.scalars(select(Device).options(selectinload(Device.site), selectinload(Device.ports))
                                       .where(Device.disabled.is_(False)))}
    rep = group_duplicates(devs.values())
    for d in devs.values():                       # guests stand alone
        rep.setdefault(d.id, d.id)
    members: dict[int, list[Device]] = {}
    for did, g in rep.items():
        members.setdefault(g, []).append(devs[did])
    in_view = {g for g, rows in members.items()
               if (not site or any(d.site and d.site.name == site for d in rows))
               and not (hide_aps and devs[g].type == "Wireless")}
    idx = _Index(devs, rep)
    ports = _ports_by_group(devs, rep)

    links: list[dict] = []
    ghosts: dict[str, dict] = {}

    def add(a, b, a_port, b_port, protocol, speed=None, util=None, bps=None, mesh=False, **more):
        if a == b or a is None or b is None:
            return
        links.append({"source": a, "target": b, "a_port": a_port or None, "b_port": b_port or None, "protocol": protocol,
                      "mesh": mesh, "speed": speed, "util": util, "bps": bps, **more})

    # 1. stored neighbours: LLDP/CDP, integration uplinks, links drawn by hand
    rows = s.scalars(select(Neighbor).options(selectinload(Neighbor.port))).all()
    for n in rows:
        a = rep.get(n.device_id)
        if a is None:
            continue
        b = rep.get(n.remote_device_id) if n.remote_device_id else None
        if b is None:
            b = idx.find(n.remote_ip, n.remote_chassis, n.remote_name)
        if b is None:
            if not (external and (n.remote_name or n.remote_chassis)):
                continue
            label = n.remote_name or n.remote_chassis
            b = "x:" + label.lower()
            ghosts.setdefault(b, {"id": b, "name": label, "status": "external", "type": (n.remote_platform or "")[:40],
                                  "ip": n.remote_ip, "site": devs[a].site.name if devs[a].site else None})
        st = _port_stats(n.port)
        add(a, b, n.local_port, n.remote_port, n.protocol, mesh=n.protocol.endswith("-mesh"), **st,
            ab_bps=n.port.out_bps if n.port is not None else None, ba_bps=n.port.in_bps if n.port is not None else None)

    # 2. UniFi switch ports: a monitored box seen on a port (as its client or LLDP neighbour) hangs off that port
    integs = s.scalars(select(Integration).where(Integration.enabled.is_(True))).all()
    for integ in integs:
        data = integ.data if isinstance(integ.data, dict) else {}
        if integ.kind != "unifi":
            continue
        for row in data.get("switch_ports") or []:
            sw = idx.find(mac=row.get("switch_mac"), name=row.get("switch"))
            if sw is None or row.get("role") in ("uplink", "unifi", "empty", "down"):
                continue
            targets: set[int] = set()
            if row.get("role") == "neighbour" and row.get("neighbour"):
                t = idx.find(mac=row["neighbour"], name=row["neighbour"])
                if t is not None:
                    targets.add(t)
            elif row.get("role") in ("client", "shared", "phone"):
                for c in row.get("clients") or []:
                    t = idx.find(ip=c.get("ip"), mac=c.get("mac"))
                    if t is not None and devs[t].type not in GUESTS:
                        targets.add(t)
            for t in targets:
                add(sw, t, f"Port {row.get('port')}", None, "unifi-port", speed=row.get("speed_mbps"))

    # 3. merge the same physical link seen from both ends (or by two sources) and fill in speed from either end
    merged: dict[tuple, list[dict]] = {}
    for l in links:
        pair = tuple(sorted((str(l["source"]), str(l["target"]))))
        ends = {str(l["source"]): norm_port(l["a_port"]), str(l["target"]): norm_port(l["b_port"])}
        bucket = merged.setdefault(pair, [])
        for cur in bucket:
            ce = cur["_ends"]
            if all(not ends[k] or not ce[k] or ends[k] == ce[k] for k in pair):
                _merge_link(cur, l, ends)
                break
        else:
            l["_ends"] = ends
            l["sources"] = [l["protocol"]]
            bucket.append(l)
    out_links = [l for bucket in merged.values() for l in bucket]
    for l in out_links:
        l.pop("_ends", None)
        for end, port in ((l["source"], l["a_port"]), (l["target"], l["b_port"])):
            p = ports.get(end, {}).get(norm_port(port)) if isinstance(end, int) and port else None
            st = _port_stats(p)
            if p is not None and l.get("ab_bps") is None and l.get("ba_bps") is None and (p.in_bps is not None or p.out_bps is not None):
                # a port's out is traffic leaving its own end
                l["ab_bps"], l["ba_bps"] = (p.out_bps, p.in_bps) if end == l["source"] else (p.in_bps, p.out_bps)
            if st.get("speed") and not l.get("speed"):
                l["speed"] = st["speed"]
            if st.get("util") is not None and (l.get("util") is None or st["util"] > l["util"]):
                l["util"], l["bps"] = st["util"], st["bps"]
            elif st.get("bps") is not None and l.get("bps") is None:
                l["bps"] = st["bps"]
        if l.get("util") is None and l.get("bps") is not None and l.get("speed"):
            l["util"] = round(l["bps"] / (l["speed"] * 1e6) * 100, 1)
        l["speed_label"] = speed_label(l.get("speed"))

    out_links = [l for l in out_links if _visible(l["source"], in_view) and _visible(l["target"], in_view)]

    # 4. Internet uplinks
    wans = _wan_links(s, devs, rep, idx, ports, integs, in_view)
    out_links += wans

    linked = {x for l in out_links for x in (l["source"], l["target"])}
    nodes = []
    for g in sorted(in_view):
        head, rows = devs[g], members[g]
        if not (show_all or g in linked or head.type == "Wireless" or any(d.type in INFRA for d in rows)):
            continue
        nodes.append(_node(head, rows))
    node_ids = {n["id"] for n in nodes}
    isps: dict[str, dict] = {}
    for l in out_links:
        if l["protocol"] == "wan" and l["source"] in node_ids:
            isps.setdefault(l["target"], {"id": l["target"], "name": l["isp_label"], "status": "up", "type": "ISP", "isp": True,
                                          "kind": isp_kind(l.get("isp") or ""), "named": bool(l.get("isp")), "up": False})
            isps[l["target"]]["up"] |= l.get("up") is not False
    for n in isps.values():
        n["status"] = "up" if n.pop("up") else "down"
    out_links = [l for l in out_links if (l["source"] in node_ids or l["source"] in ghosts or l["source"] in isps)
                 and (l["target"] in node_ids or l["target"] in ghosts or l["target"] in isps)]
    extra_nodes = [g for k, g in ghosts.items() if any(k in (l["source"], l["target"]) for l in out_links)]
    extra_nodes += list(isps.values())
    return {"nodes": nodes + extra_nodes, "links": out_links}


def _visible(end, in_view: set) -> bool:
    return not isinstance(end, int) or end in in_view


def _merge_link(cur: dict, new: dict, ends: dict) -> None:
    pair = (str(cur["source"]), str(cur["target"]))
    for k in pair:
        if ends[k] and not cur["_ends"][k]:
            cur["_ends"][k] = ends[k]
            port = new["a_port"] if str(new["source"]) == k else new["b_port"]
            cur["a_port" if str(cur["source"]) == k else "b_port"] = port
    for k in ("speed", "bps"):
        if cur.get(k) is None and new.get(k) is not None:
            cur[k] = new[k]
    same = str(new["source"]) == str(cur["source"])          # traffic each way, turned round if seen from the far end
    ab, ba = (new.get("ab_bps"), new.get("ba_bps")) if same else (new.get("ba_bps"), new.get("ab_bps"))
    if cur.get("ab_bps") is None and cur.get("ba_bps") is None and (ab is not None or ba is not None):
        cur["ab_bps"], cur["ba_bps"] = ab, ba
    if new.get("util") is not None and (cur.get("util") is None or new["util"] > cur["util"]):
        cur.update(util=new["util"], bps=new.get("bps"), speed=new.get("speed") or cur.get("speed"))
    cur["mesh"] = cur["mesh"] and new["mesh"]
    if new["protocol"] not in cur["sources"]:
        cur["sources"].append(new["protocol"])
    if cur["protocol"] == "unifi-port" and new["protocol"] != "unifi-port":
        cur["protocol"] = new["protocol"]


def _node(head: Device, rows: list[Device]) -> dict:
    status = head.status
    if status in (None, "unknown"):
        status = next((d.status for d in rows if d.status in ("up", "warn", "down")), status)
    sources = []
    for d in sorted(rows, key=_rank):
        src = d.integration.name if d.integration_id and d.integration and d.source not in ("snmp", "ping") else d.source
        sources.append({"id": d.id, "name": d.hostname, "source": src})
    return {"id": head.id, "name": head.hostname, "status": status, "type": head.type, "ip": head.ip,
            "site": head.site.name if head.site else next((d.site.name for d in rows if d.site), None),
            "platform": head.platform, "ap": head.type == "Wireless",
            "clients": _clients(head) if head.type == "Wireless" else None,
            "merged": sources if len(rows) > 1 else []}


def _clients(d: Device) -> int | None:
    ex = _extra(d)
    v = ex.get("clients", _api(d).get("clients"))
    try:
        return int(v) if v is not None else None
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------- Internet uplinks
def _wan_links(s: Session, devs: dict[int, Device], rep: dict[int, int], idx: _Index, ports: dict[int, dict[str, Port]],
               integs: list[Integration], in_view: set[int]) -> list[dict]:
    marked: dict[int, list[dict]] = {}       # gateway group -> uplinks from ports an admin marked
    api: dict[int, list[dict]] = {}          # from integrations
    auto: dict[int, list[dict]] = {}         # from port names
    marks = wan_port_ids(s)

    def port_wan(p: Port, g: int) -> dict:
        st = _port_stats(p)
        return {"name": p.alias or p.name, "port": p.name, "up": p.oper == "up" if p.oper else None, "speed": st.get("speed"),
                "down_bps": p.in_bps, "up_bps": p.out_bps}

    for d in devs.values():
        g = rep.get(d.id)
        if g is None:
            continue
        for p in d.ports:
            if p.id in marks:
                marked.setdefault(g, []).append(port_wan(p, g))
            elif d.type in ("Router", "Firewall") and p.admin != "down" and \
                    (_WAN_NAME.search(p.name or "") or _WAN_NAME.search(p.alias or "")):
                auto.setdefault(g, []).append(port_wan(p, g))

    for integ in integs:
        data = integ.data if isinstance(integ.data, dict) else {}
        own = [d for d in devs.values() if d.integration_id == integ.id]
        if integ.kind == "unifi":
            wans = [w for w in data.get("wans") or [] if isinstance(w, dict)]
            sites_with_dev = {w.get("site") for w in wans if w.get("device")}
            for w in wans:
                if w.get("device"):
                    g = idx.find(name=w["device"])
                elif w.get("site") not in sites_with_dev:
                    gws = {rep.get(d.id) for d in own if d.type == "Router" and (not w.get("site") or (d.site and d.site.name == w["site"]))}
                    g = next(iter(gws)) if len(gws) == 1 else None
                else:
                    continue
                if g is not None:
                    api.setdefault(g, []).append({"name": w.get("name") or "WAN", "up": w.get("up"), "speed": w.get("speed_mbps"),
                                                  "down_bps": w.get("down_bps"), "up_bps": w.get("up_bps"), "isp": w.get("isp"),
                                                  "ip": w.get("ip")})
        elif integ.kind == "meraki":
            for u in data.get("uplinks") or []:
                if str(u.get("status") or "").lower() in ("not connected", "not_connected"):
                    continue
                dev = next((d for d in own if d.external_id == u.get("serial")), None)
                g = rep.get(dev.id) if dev else idx.find(name=u.get("device"))
                if g is not None:
                    api.setdefault(g, []).append({"name": str(u.get("interface") or "WAN").upper(),
                                                  "up": str(u.get("status") or "").lower() in ("active", "ready"),
                                                  "isp": u.get("provider"), "ip": u.get("public_ip") or u.get("ip")})
        elif integ.kind in ("pfsense", "vyos"):
            heads = [d for d in own if d.type in ("Router", "Firewall")] or own
            if not heads or rep.get(heads[0].id) is None:
                continue
            g = rep[heads[0].id]
            ifaces = [i for i in data.get("interfaces") or [] if isinstance(i, dict)]
            for gw in data.get("gateways") or []:
                if not isinstance(gw, dict) or gw.get("inactive"):
                    continue
                iface = next((i for i in ifaces if gw.get("name") and gw["name"] in (i.get("gateway"), i.get("name"), i.get("id"))), None)
                pname = (iface or {}).get("device") or (iface or {}).get("name") or gw.get("name")
                p = ports.get(g, {}).get(norm_port(pname))
                st = _port_stats(p)
                api.setdefault(g, []).append({"name": gw.get("name") or "WAN", "up": gw.get("state") in ("up", None),
                                              "speed": st.get("speed"), "port": p.name if p else None,
                                              "down_bps": p.in_bps if p else None, "up_bps": p.out_bps if p else None,
                                              "ip": (iface or {}).get("ip") or gw.get("source"),
                                              "latency_ms": gw.get("delay_ms"), "loss_pct": gw.get("loss_pct")})

    from . import isp as ispmod
    names, ranges, lookups = isp_names(s), ispmod.ranges(s), ispmod.cache(s)
    out: list[dict] = []
    for g in set(marked) | set(api) | set(auto):
        if g not in in_view:
            continue
        chosen = marked.get(g) or _enrich(api.get(g), auto.get(g)) or auto.get(g) or []
        seen = set()
        for w in chosen:
            key = (w.get("name") or "").lower()
            if key in seen:
                continue
            seen.add(key)
            speed = w.get("speed")
            busiest = max(w.get("down_bps") or 0, w.get("up_bps") or 0) if (w.get("down_bps") is not None or w.get("up_bps") is not None) else None
            util = round(busiest / (speed * 1e6) * 100, 1) if busiest is not None and speed else None
            key = wan_key(devs[g].hostname, w.get("name"))
            # the ISP: typed for this WAN > an IP range under Settings > what the gateway reports > an RDAP lookup
            ip = w.get("ip")
            found = [("manual", names.get(key, "")), ("range", ispmod.by_range(ranges, ip)),
                     ("gateway", ispmod.tidy(w.get("isp")) if w.get("isp") else ""),
                     ("lookup", str((lookups.get(str(ip or "")) or {}).get("isp") or ""))]
            how, isp = next(((h, n) for h, n in found if n), ("", ""))
            dsrc, detected = next(((h, n) for h, n in found[1:] if n), ("", ""))
            label = isp or f"{w.get('name') or 'WAN'} ISP"
            target = _isp_id(isp) if isp else _isp_id(f"unnamed {devs[g].hostname} {w.get('name')}")
            out.append({"source": g, "target": target, "a_port": w.get("port") or w.get("name"), "b_port": None, "protocol": "wan",
                        "sources": ["wan"], "mesh": False, "wan": w.get("name"), "isp": isp or None, "isp_label": label,
                        "isp_detected": detected, "isp_source": how, "detected_source": dsrc, "wan_key": key, "gateway": devs[g].hostname, "wan_ip": w.get("ip"),
                        "up": w.get("up"), "speed": speed, "speed_label": speed_label(speed), "util": util, "bps": busiest,
                        "down_bps": w.get("down_bps"), "up_bps": w.get("up_bps"),
                        "latency_ms": w.get("latency_ms"), "loss_pct": w.get("loss_pct")})
    return out


def _enrich(api_wans: list[dict] | None, port_wans: list[dict] | None) -> list[dict] | None:
    """API uplinks, with speed and traffic filled in from a WAN port of the same name when the API leaves them out."""
    if not api_wans:
        return None
    by = {norm_port(w.get("name")): w for w in port_wans or []}
    for w in api_wans:
        p = by.get(norm_port(w.get("name")))
        if p:
            for k in ("speed", "down_bps", "up_bps", "port"):
                if w.get(k) is None:
                    w[k] = p.get(k)
    return api_wans
