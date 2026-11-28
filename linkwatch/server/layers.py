"""The Layer 3 (subnets) and Layer 2 (VLANs) maps drawn under the network map.

Where the facts come from:

* SNMP polls: ``ipAddrTable`` (each interface address and mask) and Q-BRIDGE-MIB, or Cisco's VTP and
  VLAN-membership MIBs (the VLANs on a switch, their names, and which ports carry each one). The poller
  sends them as ``ip_addrs`` and ``vlans``; ingest keeps them in ``Device.extra``.
* Firewall and router integrations (pfSense, VyOS, PAN-OS, FortiGate, SonicWall): their interface table,
  with addresses, masks and VLAN tags.
* UniFi: each client's network name and VLAN, the switch or access point it hangs off, and the VLAN of
  each SSID.

The two views tie together: a subnet on a VLAN interface (``Vlan10``, ``eth0.10``, ``ethernet1/1.10``)
names that VLAN, and a device whose address falls in such a subnet is placed on that VLAN.

Both maps reuse the network map's duplicate grouping, so a box seen over SNMP and an API is one node.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from .models import Device, Integration
from .topology import GUESTS, INFRA, _Index, _node, group_duplicates

ROUTED_KINDS = ("pfsense", "vyos", "panos", "fortigate", "sonicwall")
MAX_CLIENT_NODES = 300       # beyond this, clients are counted on their bubble instead of drawn
_VLAN_IN_NAME = re.compile(r"(?:^vlan[-_ ]?(?:interface)?\s*|^vl|[.:]v?|^br-?vlan)(\d{1,4})$", re.IGNORECASE)


def vlan_from_name(name: Any) -> int | None:
    """``Vlan10``, ``vlan-interface10``, ``eth0.10``, ``ethernet1/1.10``, ``X0:V10`` -> 10."""
    m = _VLAN_IN_NAME.search(str(name or "").strip())
    if not m:
        return None
    v = int(m.group(1))
    return v if 1 <= v <= 4094 else None


def _vid(v: Any) -> int | None:
    try:
        n = int(str(v).strip())
    except (TypeError, ValueError):
        return None
    return n if 1 <= n <= 4094 else None


def _iface(ip: Any, prefix: Any = None, mask: Any = None) -> ipaddress.IPv4Interface | ipaddress.IPv6Interface | None:
    """An interface address from "10.0.0.1/24", or an address plus a prefix length or a dotted mask."""
    t = str(ip or "").strip()
    if not t or t.lower() in ("n/a", "none", "-", "dhcp"):
        return None
    try:
        if "/" not in t:
            if prefix not in (None, ""):
                t = f"{t}/{int(prefix)}"
            elif mask not in (None, ""):
                t = f"{t}/{mask}"
            else:
                return None
        i = ipaddress.ip_interface(t)
    except (TypeError, ValueError):
        return None
    a = i.ip
    if a.is_loopback or a.is_link_local or a.is_unspecified or i.network.prefixlen in (0, i.max_prefixlen):
        return None
    return i


# ---------------------------------------------------------------- gathering
def _rows(d: Device, integ_by_id: dict[int, Integration]) -> list[dict]:
    """Every routed interface we know on one device: {ifname, iface, vlan, label}."""
    ex = d.extra or {}
    out: list[dict] = []
    names = {p.ifindex: (p.name, p.alias) for p in d.ports}
    for r in ex.get("ip_addrs") or []:
        if not isinstance(r, dict):
            continue
        i = _iface(r.get("ip"), r.get("prefix"))
        if i is None:
            continue
        name, alias = names.get(r.get("ifindex"), (None, None))
        out.append({"ifname": name or (f"if{r['ifindex']}" if r.get("ifindex") is not None else ""), "iface": i,
                    "vlan": vlan_from_name(name), "label": alias or None})
    integ = integ_by_id.get(d.integration_id or 0)
    if integ is not None and integ.kind in ROUTED_KINDS and d.source == integ.kind:
        for r in (integ.data or {}).get("interfaces") or []:
            if not isinstance(r, dict):
                continue
            hw = r.get("device") or r.get("name")
            vlan = _vid(r.get("vlan")) or _vid(r.get("tag")) or vlan_from_name(hw) or vlan_from_name(r.get("name"))
            label = r.get("alias") or r.get("description") or r.get("comment") or (r.get("name") if r.get("device") else r.get("zone"))
            addrs = r.get("addresses") if isinstance(r.get("addresses"), list) else [r.get("ip")]
            for a in addrs:
                i = _iface(a, r.get("subnet"), r.get("mask"))
                if i is not None:
                    out.append({"ifname": str(hw or ""), "iface": i, "vlan": vlan, "label": str(label) if label else None})
    seen, uniq = set(), []
    for r in out:
        k = str(r["iface"])
        if k not in seen:
            seen.add(k)
            uniq.append(r)
    return uniq


class _Ctx:
    """Devices, their duplicate groups and the site filter, shared by both maps."""

    def __init__(self, s: Session, site: str = ""):
        self.devs = {d.id: d for d in s.scalars(select(Device).options(selectinload(Device.site), selectinload(Device.ports),
                                                                        selectinload(Device.integration))
                                                 .where(Device.disabled.is_(False)))}
        self.rep = group_duplicates(self.devs.values())
        for d in self.devs.values():
            self.rep.setdefault(d.id, d.id)
        self.members: dict[int, list[Device]] = {}
        for did, g in self.rep.items():
            self.members.setdefault(g, []).append(self.devs[did])
        self.in_view = {g for g, rows in self.members.items()
                        if not site or any(d.site and d.site.name == site for d in rows)}
        self.integs = {i.id: i for i in s.scalars(select(Integration).where(Integration.enabled.is_(True)))}
        self.idx = _Index(self.devs, self.rep)
        self.site = site
        # routed interfaces per group
        self.ifaces: dict[int, list[dict]] = {}
        for d in self.devs.values():
            rows = _rows(d, self.integs)
            if rows:
                have = {str(r["iface"]) for r in self.ifaces.get(self.rep[d.id], [])}
                self.ifaces.setdefault(self.rep[d.id], []).extend(r for r in rows if str(r["iface"]) not in have)

    def node(self, g: int) -> dict:
        return {**_node(self.devs[g], self.members[g]), "id": str(g), "kind": "device"}

    def subnets(self) -> dict[str, dict]:
        """{cidr: {net, vlan, label, gateways: [(group, ip, ifname)]}} for subnets on devices in view."""
        nets: dict[str, dict] = {}
        for g, rows in self.ifaces.items():
            if g not in self.in_view:
                continue
            for r in rows:
                net = r["iface"].network
                n = nets.setdefault(str(net), {"net": net, "vlan": None, "label": None, "gateways": []})
                n["vlan"] = n["vlan"] or r["vlan"]
                n["label"] = n["label"] or r["label"]
                n["gateways"].append((g, str(r["iface"].ip), r["ifname"]))
        return nets

    def subnet_of(self, nets: dict[str, dict], ip: Any) -> str | None:
        try:
            a = ipaddress.ip_address(str(ip or "").split("/")[0].strip())
        except ValueError:
            return None
        best, plen = None, -1
        for k, n in nets.items():
            if a.version == n["net"].version and a in n["net"] and n["net"].prefixlen > plen:
                best, plen = k, n["net"].prefixlen
        return best


# ---------------------------------------------------------------- Layer 3
def build_l3(s: Session, site: str = "", hosts: bool = False) -> dict:
    """Subnets as bubbles, routers / firewalls / L3 switches linked to each subnet they have an address in
    (the link is labelled with that address), and the other monitored boxes inside each subnet."""
    c = _Ctx(s, site)
    nets = c.subnets()
    nodes: dict[str, dict] = {}
    links: list[dict] = []
    for cidr, n in sorted(nets.items(), key=lambda kv: (kv[1]["net"].version, kv[1]["net"])):
        nid = f"net:{cidr}"
        nodes[nid] = {"id": nid, "kind": "subnet", "name": cidr, "vlan": n["vlan"], "label": n["label"],
                      "gateways": [ip for _, ip, _ in n["gateways"]], "hosts": 0, "host_names": []}
        for g, ip, ifname in n["gateways"]:
            nodes.setdefault(str(g), c.node(g))
            nodes[str(g)]["routed"] = True
            links.append({"source": str(g), "target": nid, "kind": "gateway", "label": ip, "port": ifname})
    # boxes that sit inside a subnet (by their management address)
    linked = {(l["source"], l["target"]) for l in links}
    for g in sorted(c.in_view):
        d = c.devs[g]
        if d.type in GUESTS and not hosts:
            continue
        cidr = c.subnet_of(nets, d.ip)
        if not cidr or (str(g), f"net:{cidr}") in linked:
            continue
        sub = nodes[f"net:{cidr}"]
        if d.type in INFRA or hosts:
            nodes.setdefault(str(g), c.node(g))
            links.append({"source": str(g), "target": f"net:{cidr}", "kind": "host", "label": d.ip, "port": None})
        else:
            sub["hosts"] += 1
            if len(sub["host_names"]) < 12:
                sub["host_names"].append(d.hostname)
    return {"nodes": list(nodes.values()), "links": links,
            "summary": {"subnets": len(nets), "routers": sum(1 for n in nodes.values() if n.get("routed"))}}


# ---------------------------------------------------------------- Layer 2
def _port_names(d: Device, ifindexes: list[int]) -> list[str]:
    by = {p.ifindex: p.name for p in d.ports}
    return [by.get(i) or str(i) for i in ifindexes]


def _ports_text(names: list[str], tagged: bool) -> str:
    if not names:
        return ""
    head = ", ".join(names[:3]) + (f" +{len(names) - 3}" if len(names) > 3 else "")
    return f"{'tagged ' if tagged else ''}{head}"


def build_l2(s: Session, site: str = "", clients: bool = False) -> dict:
    """VLANs as bubbles named "<name> · <id>", with every switch, AP, router and host that carries or sits on
    each one. UniFi clients are drawn on their VLAN when ``clients`` is set, and counted on the bubble otherwise."""
    c = _Ctx(s, site)
    nets = c.subnets()
    vlans: dict[str, dict] = {}
    edges: dict[tuple[int, str], dict] = {}

    def vlan(vid: int | None, name: Any = None) -> str:
        # an untagged network (UniFi's "Default", a firewall's plain LAN port) is the native VLAN 1
        vid = vid or 1
        key = str(vid)
        v = vlans.setdefault(key, {"id": f"vlan:{key}", "kind": "vlan", "vid": vid, "name": None, "subnets": [], "ssids": [],
                                   "clients": 0, "devices": 0})
        if name and not v["name"]:
            v["name"] = str(name)[:64]
        return key

    def edge(g: int, key: str, why: str) -> None:
        if g not in c.in_view:
            return
        e = edges.setdefault((g, key), {"untagged": [], "tagged": [], "why": set(), "clients": 0})
        e["why"].add(why)

    # 1. VLAN tables polled over SNMP
    for d in c.devs.values():
        g = c.rep[d.id]
        for v in (d.extra or {}).get("vlans") or []:
            vid = _vid(v.get("id")) if isinstance(v, dict) else None
            if vid is None:
                continue
            key = vlan(vid, v.get("name"))
            edge(g, key, "switch")
            e = edges.get((g, key))
            if e is not None:
                e["untagged"] += _port_names(d, v.get("untagged") or [])
                e["tagged"] += _port_names(d, v.get("tagged") or [])
    # 2. routed VLAN interfaces (the VLAN's gateway), and the subnet each VLAN carries
    for cidr, n in nets.items():
        if not n["vlan"]:
            continue
        key = vlan(n["vlan"], n["label"])
        if cidr not in vlans[key]["subnets"]:
            vlans[key]["subnets"].append(cidr)
        for g, ip, _ in n["gateways"]:
            edge(g, key, f"gateway {ip}")
    # 3. UniFi: SSIDs and clients
    client_nodes: list[dict] = []
    for integ in c.integs.values():
        if integ.kind != "unifi":
            continue
        data = integ.data or {}
        if site and site not in (data.get("summary") or {}).get("sites", [site]):
            continue
        for ssid in data.get("ssids") or []:
            if isinstance(ssid, dict) and _vid(ssid.get("vlan")):
                key = vlan(_vid(ssid["vlan"]))
                if ssid.get("name") and ssid["name"] not in vlans[key]["ssids"]:
                    vlans[key]["ssids"].append(ssid["name"])
        for cl in data.get("clients") or []:
            if not isinstance(cl, dict) or (site and cl.get("site") not in (None, site)):
                continue
            vid = _vid(cl.get("vlan"))
            if vid is None:
                cidr = c.subnet_of(nets, cl.get("ip"))
                vid = nets[cidr]["vlan"] if cidr else None
            key = vlan(vid, cl.get("network"))
            vlans[key]["clients"] += 1
            mine = c.idx.find(mac=cl.get("mac"), ip=cl.get("ip"))
            if mine is not None:                      # a monitored box: drawn below as a host
                edge(mine, key, "host")
                continue
            via = c.idx.find(mac=cl.get("ap_mac") or cl.get("switch_mac"))
            if via is not None:
                edge(via, key, "ap" if cl.get("ap_mac") else "switch")
                if (via, key) in edges:
                    edges[(via, key)]["clients"] += 1
            if clients:
                client_nodes.append({"id": f"cl:{cl.get('mac')}", "kind": "client", "name": cl.get("name") or cl.get("mac"),
                                     "ip": cl.get("ip"), "wired": bool(cl.get("wired")), "vlan": f"vlan:{key}",
                                     "signal": cl.get("signal"), "ssid": cl.get("ssid")})
    # 4. monitored boxes by address: a host in a subnet that is on a VLAN
    for g in c.in_view:
        if any(k[0] == g for k in edges):
            continue
        d = c.devs[g]
        if d.type in GUESTS:
            continue
        cidr = c.subnet_of(nets, d.ip)
        if cidr and nets[cidr]["vlan"]:
            edge(g, vlan(nets[cidr]["vlan"], nets[cidr]["label"]), "host")

    nodes: dict[str, dict] = {}
    links: list[dict] = []
    for key, v in vlans.items():
        if not any(k[1] == key for k in edges) and not v["clients"]:
            continue
        if not v["name"]:
            v["name"] = "Default" if v["vid"] == 1 else f"VLAN {v['vid']}"
        nodes[v["id"]] = v
    for (g, key), e in sorted(edges.items(), key=lambda kv: (kv[0][1], kv[0][0])):
        vid = vlans[key]["id"]
        if vid not in nodes:
            continue
        nodes.setdefault(str(g), c.node(g))
        vlans[key]["devices"] += 1
        why = sorted(e["why"])
        bits = []
        if e["untagged"]:
            bits.append(_ports_text(sorted(set(e["untagged"])), False))
        if e["tagged"]:
            bits.append(_ports_text(sorted(set(e["tagged"])), True))
        bits += [w for w in why if w.startswith("gateway")]
        if e["clients"]:
            bits.append(f"{e['clients']} client{'s' if e['clients'] != 1 else ''}")
        links.append({"source": str(g), "target": vid, "kind": "gateway" if any(w.startswith("gateway") for w in why)
                      else "trunk" if e["tagged"] and not e["untagged"] else "host" if why == ["host"] else "access",
                      "label": " · ".join(b for b in bits if b)})
    drawn = 0
    for cl in client_nodes:
        if cl["vlan"] in nodes and drawn < MAX_CLIENT_NODES:
            nodes[cl["id"]] = cl
            links.append({"source": cl["id"], "target": cl["vlan"], "kind": "client", "label": ""})
            drawn += 1
    return {"nodes": list(nodes.values()), "links": links,
            "summary": {"vlans": sum(1 for n in nodes.values() if n["kind"] == "vlan"),
                        "clients_hidden": max(0, len(client_nodes) - drawn)}}
