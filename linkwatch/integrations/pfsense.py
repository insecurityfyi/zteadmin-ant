"""pfSense CE and Plus through the pfSense REST API package (pfrest, v2), called by a poller.

pfSense has no built-in REST API of its own, so this uses the community package from pfrest.org, installed on the
firewall with pkg-static (see docs/pfsense.md). VisCon1 signs in with an API key in the ``X-API-Key`` header. The key
carries the privileges of the user that created it, so give that user GET access to the endpoints below and nothing
else.

Every response is wrapped as {"code", "status", "response_id", "message", "data"}.

Paths (all GET, from the pfrest endpoint reference):
  /api/v2/status/system               platform, serial, uptime, CPU, memory, disk, temperature
  /api/v2/system/version              pfSense version
  /api/v2/system/hostname             host name and domain (best effort)
  /api/v2/status/interfaces           interface status, addresses and byte/error counters
  /api/v2/status/gateways             gateway status, delay, jitter and loss
  /api/v2/firewall/states/size        current and maximum firewall states
  /api/v2/status/dhcp_server/leases   DHCP leases
  /api/v2/status/ipsec/sas            IPsec SAs
  /api/v2/status/openvpn/servers      OpenVPN servers and their connected clients
  /api/v2/status/openvpn/clients      OpenVPN client instances
  /api/v2/status/wireguard/tunnels    WireGuard tunnels and peers
  /api/v2/status/services             services and whether they run
  /api/v2/status/carp                 CARP (HA) status

Field names inside some status objects come straight from the underlying tools (strongSwan, OpenVPN, wg), so they are
read defensively.
"""
from __future__ import annotations

import zlib
from typing import Any

import httpx

from .base import Field, Integration, IntegrationError, Record, host_url, verify_field

API = "/api/v2"
LEASE_LIMIT = 5000
GW_BAD = {"down", "offline", "force_down"}
GW_WARN = {"loss", "delay", "highloss", "highdelay", "warning"}


def _pick(d: Any, *keys, default=None):
    for k in keys:
        v = d.get(k) if isinstance(d, dict) else None
        if v not in (None, "", [], {}):
            return v
    return default


def _num(v: Any) -> float | None:
    """'12.3ms', '0.0%', 4 or None -> float."""
    if v is None or isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return float(v)
    s = str(v).strip().rstrip("%").removesuffix("ms").strip()
    try:
        return float(s)
    except ValueError:
        return None


def port_index(name: str) -> int:
    """A stable made-up ifindex for an API-reported interface (the APIs have none)."""
    return 40000 + zlib.crc32(str(name).encode()) % 50000


def _list(v: Any) -> list[dict]:
    if isinstance(v, dict):
        v = list(v.values())
    return [x for x in v or [] if isinstance(x, dict)] if isinstance(v, list) else []


class PfSense(Integration):
    kind = "pfsense"
    label = "pfSense"
    runs_on = "poller"
    description = ("pfSense REST API package: system, gateways and WAN status, interfaces, firewall states, DHCP leases, "
                   "IPsec, OpenVPN and WireGuard, services and CARP.")
    fields = [
        Field("host", "Firewall address", help="Management IP or hostname, with :port if the web interface isn't on 443."),
        Field("api_key", "REST API key", "password",
              help="System > REST API > Keys on the firewall, created by a user with read-only (GET) privileges. See the setup steps."),
        verify_field(),
    ]

    def __init__(self, config: dict[str, Any], http: httpx.Client | None = None):
        super().__init__(config, http)
        self.base = host_url(config["host"]) + API

    # http ---------------------------------------------------------------
    def _api(self, path: str, params: dict | None = None) -> Any:
        url = f"{self.base}{path}"
        try:
            r = self.http.get(url, params=params, headers={"X-API-Key": self.config["api_key"], "Accept": "application/json"})
        except httpx.HTTPError as exc:
            raise IntegrationError(f"Could not reach {httpx.URL(url).host}: {exc.__class__.__name__}") from exc
        body: Any
        try:
            body = r.json()
        except ValueError:
            body = None
        msg = (body.get("message") if isinstance(body, dict) else None) or r.reason_phrase
        if r.status_code == 401:
            raise IntegrationError("The firewall refused the API key (HTTP 401). Check the key under System > REST API > Keys, "
                                   "and that API key authentication is enabled in System > REST API > Settings.")
        if r.status_code == 403:
            raise IntegrationError(f"GET {API}{path} was refused (HTTP 403): the key's user lacks the privilege for it")
        if r.status_code == 404 and body is None:
            raise IntegrationError("The REST API package doesn't answer at this address (HTTP 404). Install pfSense-pkg-RESTAPI "
                                   "on the firewall, or reinstall it after a pfSense upgrade.")
        if r.status_code >= 400:
            raise IntegrationError(f"GET {API}{path} returned HTTP {r.status_code}: {str(msg)[:200]}")
        if body is None:
            raise IntegrationError(f"GET {API}{path} did not return JSON. Is this the pfSense web interface address?")
        return body.get("data") if isinstance(body, dict) and "data" in body else body

    def _optional(self, label: str, fn):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - one missing panel, not a failed sync
            text = str(exc)
            if "HTTP 404" in text:
                self.data["not_offered"].append(label)
            else:
                self.data["unavailable"].append(f"{label}: {text}")
            return None

    # collection ---------------------------------------------------------
    def collect(self) -> list[Record]:
        self.data = {"type": "pfsense", "unavailable": [], "not_offered": []}
        sysst = self._api("/status/system") or {}
        ver = self._optional("Version", lambda: self._api("/system/version")) or {}
        hn = self._optional("Host name", lambda: self._api("/system/hostname")) or {}
        host = self.config["host"]
        name = ".".join(x for x in (_pick(hn, "hostname"), _pick(hn, "domain")) if x) or host
        load = sysst.get("cpu_load_avg") if isinstance(sysst.get("cpu_load_avg"), list) else []
        system = {
            "hostname": name, "platform": _pick(sysst, "platform"), "serial": _pick(sysst, "serial"),
            "netgate_id": _pick(sysst, "netgate_id"), "version": _pick(ver, "version"), "patch": _pick(ver, "patch"),
            "buildtime": _pick(ver, "buildtime"), "uptime": _pick(sysst, "uptime"), "cpu_model": _pick(sysst, "cpu_model"),
            "cpu_count": _pick(sysst, "cpu_count"), "cpu": _num(sysst.get("cpu_usage")), "mem": _num(sysst.get("mem_usage")),
            "swap": _num(sysst.get("swap_usage")), "disk": _num(sysst.get("disk_usage")), "mbuf": _num(sysst.get("mbuf_usage")),
            "temp_c": _num(sysst.get("temp_c")), "load": load[:3],
        }
        self.data["system"] = system

        ports = self._interfaces()
        self._gateways()
        size = self._optional("Firewall states", lambda: self._api("/firewall/states/size"))
        if isinstance(size, dict):
            self.data["states"] = {"current": size.get("currentstates"), "max": size.get("maximumstates") or size.get("defaultmaximumstates")}
        self._leases()
        self._ipsec()
        self._openvpn()
        self._wireguard()
        self._services()
        carp = self._optional("CARP", lambda: self._api("/status/carp"))
        if isinstance(carp, dict) and (carp.get("enable") or _list(carp.get("vips"))):
            self.data["carp"] = {"enabled": bool(carp.get("enable")), "maintenance": bool(carp.get("maintenance_mode")),
                                 "vips": [{"interface": _pick(v, "interface"), "vhid": _pick(v, "vhid"), "ip": _pick(v, "subnet", "ip"),
                                           "status": _pick(v, "status")} for v in _list(carp.get("vips"))]}

        problems = []
        gws = self.data.get("gateways") or []
        down = [g["name"] for g in gws if g["state"] == "down"]
        if down:
            problems.append(f"gateway down: {', '.join(down[:3])}")
        stopped = [x["name"] for x in self.data.get("services") or [] if x.get("enabled") and x.get("running") is False]
        if stopped:
            problems.append(f"stopped: {', '.join(stopped[:3])}")
        tun = self.data.get("tunnels") or []
        bits = [f"pfSense {system['version'] or ''}".strip()]
        if gws:
            bits.append(f"{sum(1 for g in gws if g['state'] == 'up')}/{len(gws)} gateways up")
        if self.data.get("states"):
            bits.append(f"{self.data['states'].get('current') or 0} states")
        if tun:
            bits.append(f"{sum(1 for t in tun if t['up'])}/{len(tun)} tunnels up")
        serial = system["serial"] or system["netgate_id"]
        rec = Record(
            external_id=serial or host, hostname=str(name), ip=host_url(host).split("://", 1)[1].split(":")[0],
            type="Firewall", platform=f"pfSense {system['platform'] or ''} {system['version'] or ''}".replace("  ", " ").strip(),
            site=None, status="warn" if problems else "up", cpu=system["cpu"], mem=system["mem"], serial=system["serial"],
            detail=", ".join(bits + problems),
            extra={"version": system["version"], "uptime": system["uptime"], "states": (self.data.get("states") or {}).get("current"),
                   "temp_c": system["temp_c"], "ips": [i["ip"] for i in self.data.get("interfaces") or [] if i.get("ip")]},
        )
        if ports:
            rec["ports"] = ports
        return [rec]

    def _interfaces(self) -> list[dict]:
        rows = _list(self._optional("Interfaces", lambda: self._api("/status/interfaces")))
        table, ports = [], []
        for r in rows:
            st = str(_pick(r, "status", default="")).lower()
            up = st in ("up", "associated")
            enabled = r.get("enable") is not False
            label = _pick(r, "descr", "name") or "?"
            table.append({"name": label, "id": _pick(r, "name"), "device": _pick(r, "hwif", "if"), "status": st or None,
                          "enabled": enabled, "ip": _pick(r, "ipaddr"), "subnet": _pick(r, "subnet"), "ipv6": _pick(r, "ipaddrv6"),
                          "mac": _pick(r, "macaddr"), "media": _pick(r, "media"), "gateway": _pick(r, "gateway"),
                          "in_bytes": _num(r.get("inbytes")), "out_bytes": _num(r.get("outbytes")),
                          "in_errors": _num(r.get("inerrs")), "out_errors": _num(r.get("outerrs"))})
            ports.append({"ifindex": port_index(_pick(r, "hwif", "if", "name") or label), "name": _pick(r, "hwif", "if", "name") or label, "alias": label,
                          "admin": "up" if enabled else "down", "oper": "up" if up else "down", "mac": _pick(r, "macaddr"),
                          "in_octets": r.get("inbytes"), "out_octets": r.get("outbytes"),
                          "in_errors": r.get("inerrs"), "out_errors": r.get("outerrs"), "counter_bits": 64})
        self.data["interfaces"] = table
        return ports

    def _gateways(self) -> None:
        rows = self._optional("Gateways", lambda: self._api("/status/gateways"))
        if rows is None:
            return
        out = []
        for g in _list(rows):
            raw = str(_pick(g, "status", default="")).lower()
            sub = str(_pick(g, "substatus", default="")).lower()
            state = "down" if raw in GW_BAD or sub in GW_BAD else "warn" if raw in GW_WARN or sub in GW_WARN else \
                    "up" if raw in ("online", "none", "up") else "unknown"
            out.append({"name": _pick(g, "name"), "state": state, "status": raw or None, "substatus": sub or None,
                        "monitor": _pick(g, "monitorip"), "source": _pick(g, "srcip"),
                        "delay_ms": _num(g.get("delay")), "stddev_ms": _num(g.get("stddev")), "loss_pct": _num(g.get("loss"))})
        self.data["gateways"] = out

    def _leases(self) -> None:
        rows = self._optional("DHCP leases", lambda: self._api("/status/dhcp_server/leases", {"limit": LEASE_LIMIT}))
        if rows is None:
            return
        self.data["leases"] = [{
            "ip": _pick(r, "ip"), "mac": _pick(r, "mac"), "hostname": _pick(r, "hostname"), "interface": _pick(r, "if"),
            "descr": _pick(r, "descr"), "starts": _pick(r, "starts"), "ends": _pick(r, "ends"),
            "state": _pick(r, "active_status"), "online": _pick(r, "online_status"),
        } for r in _list(rows)]

    def _ipsec(self) -> None:
        rows = self._optional("IPsec", lambda: self._api("/status/ipsec/sas"))
        if rows is None:
            return
        out = []
        for r in _list(rows):
            child = _list(_pick(r, "child_sas", "child-sas"))
            state = str(_pick(r, "state", default="")).upper()
            out.append({"kind": "IPsec", "name": _pick(r, "con_id", "con-id", "name", "uniqueid"),
                        "remote": _pick(r, "remote_host", "remote-host", "remote_id", "remote-id"),
                        "up": state == "ESTABLISHED", "state": state.lower() or None,
                        "children_up": sum(1 for c in child if str(_pick(c, "state", default="")).upper() == "INSTALLED"),
                        "children": len(child),
                        "in_bytes": sum(_num(_pick(c, "bytes_in", "bytes-in")) or 0 for c in child) or None,
                        "out_bytes": sum(_num(_pick(c, "bytes_out", "bytes-out")) or 0 for c in child) or None})
        self.data.setdefault("tunnels", []).extend(out)

    def _openvpn(self) -> None:
        servers = self._optional("OpenVPN servers", lambda: self._api("/status/openvpn/servers"))
        users = []
        if servers is not None:
            srv = []
            for s in _list(servers):
                conns = _list(_pick(s, "conns", "connections"))
                srv.append({"name": _pick(s, "name", "description"), "mode": _pick(s, "mode"), "port": _pick(s, "port"),
                            "clients": len(conns)})
                for c in conns:
                    users.append({"user": _pick(c, "common_name", "user_name"), "remote": _pick(c, "real_address", "remote_host"),
                                  "tunnel_ip": _pick(c, "virtual_addr", "virtual_address"), "server": _pick(s, "name"),
                                  "since": _pick(c, "connect_time", "connected_since"),
                                  "bytes_in": _pick(c, "bytes_recv"), "bytes_out": _pick(c, "bytes_sent")})
            self.data["openvpn_servers"] = srv
            self.data["vpn_users"] = users
        clients = self._optional("OpenVPN clients", lambda: self._api("/status/openvpn/clients"))
        for c in _list(clients):
            st = str(_pick(c, "status", "state", default="")).lower()
            self.data.setdefault("tunnels", []).append({
                "kind": "OpenVPN", "name": _pick(c, "name", "description"), "remote": _pick(c, "remote_host", "server_addr"),
                "up": st in ("up", "connected"), "state": st or None,
                "in_bytes": _num(_pick(c, "bytes_recv")), "out_bytes": _num(_pick(c, "bytes_sent"))})

    def _wireguard(self) -> None:
        rows = self._optional("WireGuard", lambda: self._api("/status/wireguard/tunnels"))
        if rows is None:
            return
        for t in _list(rows):
            peers = _list(_pick(t, "peers"))
            alive = [p for p in peers if _pick(p, "latest_handshake", "handshake") not in (None, 0, "0")]
            self.data.setdefault("tunnels", []).append({
                "kind": "WireGuard", "name": _pick(t, "name", "descr"), "remote": f"{len(peers)} peer{'s' if len(peers) != 1 else ''}",
                "up": bool(alive), "state": f"{len(alive)}/{len(peers)} peers with a handshake" if peers else "no peers",
                "in_bytes": sum(_num(_pick(p, "transfer_rx")) or 0 for p in peers) or None,
                "out_bytes": sum(_num(_pick(p, "transfer_tx")) or 0 for p in peers) or None})

    def _services(self) -> None:
        rows = self._optional("Services", lambda: self._api("/status/services"))
        if rows is None:
            return
        self.data["services"] = [{"name": _pick(r, "name"), "description": _pick(r, "description"),
                                  "enabled": r.get("enabled") is not False,
                                  "running": r.get("status") if isinstance(r.get("status"), bool) else
                                  (str(r.get("status")).lower() in ("running", "true", "1") if r.get("status") is not None else None)}
                                 for r in _list(rows)]
