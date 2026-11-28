"""VyOS 1.3, 1.4 and 1.5 over its HTTPS API, called by a poller.

The API is POST only, with two form fields: ``key`` (the API key) and ``data`` (a JSON string). Replies are
{"success": bool, "data": ..., "error": str|null}.

  POST /retrieve  {"op": "showConfig", "path": []}     the whole configuration as JSON (host name, interfaces, VPN peers)
  POST /show      {"op": "show", "path": [...]}        an operational-mode command; ``data`` is the command's text output

Operational commands read (text, parsed defensively; any that a version lacks are skipped):
  show version                 version, hardware model and serial
  show system uptime           uptime and load averages
  show system memory           total and used memory
  show interfaces              addresses, state/link and descriptions
  show interfaces counters     per-interface bytes, packets and errors (newer versions)
  show ip route 0.0.0.0/0      default gateways
  show vpn ipsec sa            IPsec SAs
  show openvpn server          OpenVPN clients connected to each server interface
  show interfaces wireguard <wgX> summary   WireGuard peers and handshakes
  show dhcp server leases      DHCP leases
  show conntrack statistics    connection-tracking counters (best effort)

Every VyOS API key has full rights (there's no read-only key), but VisCon1 only uses /retrieve and /show.
"""
from __future__ import annotations

import json
import re
from typing import Any

import httpx

from .base import Field, Integration, IntegrationError, Record, host_url, verify_field
from .pfsense import port_index

UNITS = {"b": 1, "kb": 1e3, "mb": 1e6, "gb": 1e9, "tb": 1e12, "kib": 1024, "mib": 1024**2, "gib": 1024**3, "tib": 1024**4,
         "k": 1e3, "m": 1e6, "g": 1e9, "t": 1e12, "bytes": 1, "byte": 1}


def parse_table(text: str, first: str) -> list[dict[str, str]]:
    """Rows of a tabulate-style table whose header line starts with ``first``.

    Column bounds come from the dashes line under the header when there is one, else from the header words.
    Indented lines that follow a row (a second address on an interface) are folded into that row as ``_more``.
    """
    lines = (text or "").splitlines()
    for h, line in enumerate(lines):
        if line.strip().lower().startswith(first.lower()):
            break
    else:
        return []
    header = lines[h]
    rest = lines[h + 1:]
    if rest and set(rest[0].strip()) <= {"-", " "} and rest[0].strip():
        spans = [m.start() for m in re.finditer(r"-+", rest[0])]
        rest = rest[1:]
    else:
        spans = [m.start() for m in re.finditer(r"\S+(?: \S+)*", header)]
    names = [header[a:b].strip() for a, b in zip(spans, spans[1:] + [None])]
    rows: list[dict[str, str]] = []
    for line in rest:
        if not line.strip():
            if rows:
                break
            continue
        cells = [line[a:b].strip() if a < len(line) else "" for a, b in zip(spans, spans[1:] + [None])]
        if line[:1].isspace() and rows:
            rows[-1].setdefault("_more", []).append([c for c in cells if c])
            continue
        rows.append(dict(zip(names, cells)))
    return rows


def col(row: dict, *names: str) -> str | None:
    """A cell by any of several header spellings, ignoring case."""
    low = {k.lower(): v for k, v in row.items() if isinstance(v, str)}
    for n in names:
        v = low.get(n.lower())
        if v not in (None, "", "n/a", "-"):
            return v
    return None


def to_bytes(v: str | None) -> float | None:
    """'1.2 MB', '532K', '3457' -> bytes."""
    if not v:
        return None
    m = re.match(r"^\s*([\d.,]+)\s*([A-Za-z]*)", v)
    if not m:
        return None
    try:
        n = float(m.group(1).replace(",", ""))
    except ValueError:
        return None
    return n * UNITS.get(m.group(2).lower(), 1)


def kv(text: str) -> dict[str, str]:
    """'Key: value' lines -> {'key': 'value'} (lower-cased keys)."""
    out = {}
    for line in (text or "").splitlines():
        k, sep, v = line.partition(":")
        if sep and k.strip() and len(k) < 40:
            out.setdefault(k.strip().lower(), v.strip())
    return out


class VyOS(Integration):
    kind = "vyos"
    label = "VyOS"
    runs_on = "poller"
    description = "HTTPS API: system, interfaces, gateways, IPsec, OpenVPN and WireGuard, DHCP leases and connection tracking."
    fields = [
        Field("host", "Router address", help="Management IP or hostname, with :port if 'service https port' isn't 443."),
        Field("api_key", "API key", "password", help="The key from 'set service https api keys id linkwatch key ...'. See the setup steps."),
        verify_field(),
    ]

    def __init__(self, config: dict[str, Any], http: httpx.Client | None = None):
        super().__init__(config, http)
        self.base = host_url(config["host"])
        self._info_cache: dict | None = None

    # http ---------------------------------------------------------------
    def _call(self, endpoint: str, payload: dict) -> Any:
        url = f"{self.base}/{endpoint}"
        try:
            r = self.http.post(url, data={"data": json.dumps(payload), "key": self.config["api_key"]})
        except httpx.HTTPError as exc:
            raise IntegrationError(f"Could not reach {httpx.URL(url).host}: {exc.__class__.__name__}") from exc
        try:
            body = r.json()
        except ValueError:
            body = None
        err = (body or {}).get("error") if isinstance(body, dict) else None
        if r.status_code in (401, 403):
            raise IntegrationError(f"The router refused the API key (HTTP {r.status_code}). Check 'service https api keys'.")
        if r.status_code == 404:
            raise IntegrationError(self._not_found(endpoint))
        if body is None:
            raise IntegrationError(f"POST /{endpoint} returned HTTP {r.status_code} without JSON")
        if r.status_code >= 400 or body.get("success") is False:
            raise IntegrationError(f"POST /{endpoint} {' '.join(payload.get('path') or [])}: {str(err or r.reason_phrase)[:200]}")
        return body.get("data")

    def _info(self) -> dict:
        """GET /info: version and host name, without a key (VyOS 1.5 and newer). Empty when it isn't there."""
        if self._info_cache is None:
            self._info_cache = {}
            try:
                r = self.http.get(f"{self.base}/info")
                body = r.json() if r.status_code == 200 else None
                if isinstance(body, dict) and isinstance(body.get("data"), dict):
                    self._info_cache = body["data"]
            except Exception:  # noqa: BLE001 - optional; older versions have no /info
                pass
        return self._info_cache

    def _not_found(self, endpoint: str) -> str:
        ver = self._info().get("version")
        if ver:
            return (f"VyOS {ver} is answering, but its REST API is turned off (POST /{endpoint} returned 404). In configuration "
                    "mode run 'set service https api rest' (VyOS 1.5 and newer need it), keep your key under "
                    "'service https api keys id <name> key <key>', then commit and save.")
        return (f"The router's HTTPS API isn't answering (POST /{endpoint} returned 404). Configure "
                "'set service https api keys id linkwatch key <key>' and, on VyOS 1.5 and newer, also "
                "'set service https api rest'; then commit and save.")

    def _show(self, *path: str) -> str:
        out = self._call("show", {"op": "show", "path": list(path)})
        return out if isinstance(out, str) else ""

    def _optional(self, label: str, fn):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - one missing panel, not a failed sync
            text = str(exc)
            if re.search(r"invalid command|not found|incomplete command|no such|does not exist", text, re.IGNORECASE):
                self.data["not_offered"].append(label)
            else:
                self.data["unavailable"].append(f"{label}: {text}")
            return None

    # collection ---------------------------------------------------------
    def collect(self) -> list[Record]:
        self.data = {"type": "vyos", "unavailable": [], "not_offered": []}
        cfg = self._call("retrieve", {"op": "showConfig", "path": []}) or {}
        if not isinstance(cfg, dict):
            cfg = {}
        sysc = cfg.get("system") or {}
        host = self.config["host"]
        info = self._info()
        name = ".".join(x for x in (sysc.get("host-name"), sysc.get("domain-name")) if isinstance(x, str) and x) \
            or info.get("hostname") or host

        ver = kv(self._optional("Version", lambda: self._show("version")) or "")
        up_text = self._optional("Uptime", lambda: self._show("system", "uptime")) or ""
        upkv = kv(up_text)
        loads = re.findall(r"(\d+)\s*minutes?:\s*([\d.]+)%?", up_text)
        mem = kv(self._optional("Memory", lambda: self._show("system", "memory")) or "")
        mb = lambda v: to_bytes(v + " MB") if v and re.fullmatch(r"[\d.]+", v.strip()) else to_bytes(v)
        total, used = mb(mem.get("total")), mb(mem.get("used"))
        mem_pct = round(100.0 * used / total, 1) if total and used is not None else None
        system = {"hostname": name, "version": re.sub(r"^vyos\s+", "", ver.get("version") or info.get("version") or "", flags=re.IGNORECASE) or None, "release": ver.get("release train"),
                  "built": ver.get("built on"), "model": ver.get("hardware model"), "vendor": ver.get("hardware vendor"),
                  "serial": ver.get("hardware s/n"), "uuid": ver.get("hardware uuid"),
                  "uptime": upkv.get("uptime") or ver.get("uptime"), "load": {m: float(v) for m, v in loads},
                  "mem_total_mb": round(total / 1e6) if total else None, "mem": mem_pct}
        self.data["system"] = system
        cpu = system["load"].get("1")

        ports = self._interfaces(cfg)
        self._gateways()
        self._ipsec(cfg)
        self._openvpn()
        self._wireguard(cfg)
        self._leases()
        ct = self._optional("Connection tracking", lambda: self._show("conntrack", "statistics"))
        if ct:
            found = [int(x) for x in re.findall(r"\bfound[=:\s]+(\d+)", ct)]
            entries = re.search(r"(?:entries|count)[=:\s]+(\d+)", ct, re.IGNORECASE)
            self.data["conntrack"] = {"entries": int(entries.group(1)) if entries else None, "found": sum(found) if found else None}

        gws = self.data.get("gateways") or []
        tun = self.data.get("tunnels") or []
        wan_down = [i["name"] for i in self.data.get("interfaces") or [] if i.get("wan") and i.get("state") == "down"]
        bits = [f"VyOS {system['version'] or ''}".strip()]
        if gws:
            bits.append(f"{len(gws)} default gateway{'s' if len(gws) != 1 else ''}")
        if tun:
            bits.append(f"{sum(1 for t in tun if t['up'])}/{len(tun)} tunnels up")
        problems = [f"WAN down: {', '.join(wan_down[:3])}"] if wan_down else []
        serial = system["serial"] if system["serial"] and system["serial"].lower() not in ("unknown", "none", "") else None
        rec = Record(
            external_id=serial or host, hostname=str(name), ip=host_url(host).split("://", 1)[1].split(":")[0],
            type="Router", platform=f"VyOS {system['version'] or ''}".strip(), site=None,
            status="warn" if problems else "up", cpu=cpu, mem=mem_pct, serial=serial,
            detail=", ".join(bits + problems),
            extra={"version": system["version"], "uptime": system["uptime"],
                   "ips": [a.split("/")[0] for i in self.data.get("interfaces") or [] for a in i.get("addresses") or [] if "/" in a]},
        )
        if ports:
            rec["ports"] = ports
        return [rec]

    def _interfaces(self, cfg: dict) -> list[dict]:
        conf: dict[str, dict] = {}
        for typ, items in (cfg.get("interfaces") or {}).items():
            for ifname, c in (items or {}).items() if isinstance(items, dict) else []:
                c = c if isinstance(c, dict) else {}
                conf[ifname] = {"type": typ, "description": c.get("description"), "disabled": "disable" in c,
                                "dhcp": "dhcp" in (c.get("address") if isinstance(c.get("address"), list) else [c.get("address")])}
        text = self._optional("Interfaces", lambda: self._show("interfaces")) or ""
        rows = parse_table(text, "Interface")
        counters = {}
        ctext = self._optional("Interface counters", lambda: self._show("interfaces", "counters"))
        for r in parse_table(ctext or "", "Interface"):
            n = col(r, "Interface")
            if n:
                counters[n] = r
        wan_names = {i for i, c in conf.items() if re.search(r"\bwan\b|internet|uplink|isp", str(c.get("description") or ""), re.IGNORECASE)}
        table, ports = [], []
        for r in rows:
            n = col(r, "Interface")
            if not n or n == "lo":
                continue
            sl = (col(r, "S/L") or "").lower()
            admin_up = not sl.startswith("a") and not conf.get(n, {}).get("disabled")
            oper_up = sl == "u/u"
            addrs = [x for x in [col(r, "IP Address")] + [m[0] for m in r.get("_more") or [] if m and "/" in m[0]] if x and x != "-"]
            cnt = counters.get(n) or {}
            c = conf.get(n, {})
            row = {"name": n, "type": c.get("type"), "description": col(r, "Description") or c.get("description"),
                   "addresses": addrs, "mac": col(r, "MAC"), "mtu": col(r, "MTU"), "vrf": col(r, "VRF"),
                   "state": "up" if oper_up else "admin down" if not admin_up else "down", "dhcp": c.get("dhcp"),
                   "wan": n in wan_names,
                   "in_bytes": to_bytes(col(cnt, "Rx Bytes")), "out_bytes": to_bytes(col(cnt, "Tx Bytes")),
                   "in_errors": to_bytes(col(cnt, "Rx Errors")), "out_errors": to_bytes(col(cnt, "Tx Errors"))}
            table.append(row)
            ports.append({"ifindex": port_index(n), "name": n, "alias": row["description"] or "",
                          "admin": "up" if admin_up else "down", "oper": "up" if oper_up else "down", "mac": row["mac"],
                          "in_octets": row["in_bytes"], "out_octets": row["out_bytes"],
                          "in_errors": row["in_errors"], "out_errors": row["out_errors"], "counter_bits": 64})
        self.data["interfaces"] = table
        return ports

    def _gateways(self) -> None:
        text = self._optional("Default gateways", lambda: self._show("ip", "route", "0.0.0.0/0"))
        if text is None:
            return
        out, seen = [], set()
        for line in text.splitlines():
            # FRR prints "* 203.0.113.1, via eth0" (newer) or "* via 203.0.113.1, eth0" (older)
            m = re.search(r"(\d+\.\d+\.\d+\.\d+),\s*via\s+([\w.\-@]+)", line) or \
                re.search(r"via\s+(\d+\.\d+\.\d+\.\d+),\s*([\w.\-@]+)", line)
            if m and (m.group(1), m.group(2)) not in seen:
                seen.add((m.group(1), m.group(2)))
                out.append({"name": m.group(2), "gateway": m.group(1), "selected": line.lstrip().startswith("*"),
                            "state": "up", "inactive": "inactive" in line})
        proto = re.search(r"Known via \"([\w-]+)\"", text)
        for g in out:
            g["protocol"] = proto.group(1) if proto else None
        self.data["gateways"] = out

    def _ipsec(self, cfg: dict) -> None:
        peers = ((((cfg.get("vpn") or {}).get("ipsec") or {}).get("site-to-site") or {}).get("peer") or {})
        if not peers and "ipsec" not in (cfg.get("vpn") or {}):
            return
        text = self._optional("IPsec", lambda: self._show("vpn", "ipsec", "sa"))
        if text is None:
            return
        out = []
        for r in parse_table(text, "Connection"):
            inout = (col(r, "Bytes In/Out") or "").split("/")
            state = (col(r, "State") or "").lower()
            out.append({"kind": "IPsec", "name": col(r, "Connection"), "remote": col(r, "Remote address", "Remote ID"),
                        "up": state == "up", "state": state or None, "uptime": col(r, "Uptime"),
                        "in_bytes": to_bytes(inout[0]) if inout and inout[0] else None,
                        "out_bytes": to_bytes(inout[1]) if len(inout) > 1 else None, "proposal": col(r, "Proposal")})
        listed = {str(t["name"]).split("-tunnel")[0] for t in out}
        for p, pc in peers.items():                 # configured peers with no SA are down
            if p not in listed and not any(str(t["name"]).startswith(p) for t in out):
                out.append({"kind": "IPsec", "name": p, "remote": (pc or {}).get("remote-address") if isinstance(pc, dict) else None,
                            "up": False, "state": "no SA"})
        self.data.setdefault("tunnels", []).extend(out)

    def _openvpn(self) -> None:
        text = self._optional("OpenVPN", lambda: self._show("openvpn", "server"))
        if not text:
            return
        users = []
        for block in re.split(r"(?=OpenVPN status on )", text):
            iface = re.match(r"OpenVPN status on (\S+)", block)
            for r in parse_table(block, "Client CN"):
                users.append({"user": col(r, "Client CN"), "remote": col(r, "Remote Host"), "tunnel_ip": col(r, "Tunnel IP"),
                              "server": iface.group(1) if iface else None, "since": col(r, "Connected Since"),
                              "bytes_in": to_bytes(col(r, "RX bytes")), "bytes_out": to_bytes(col(r, "TX bytes"))})
        self.data["vpn_users"] = users

    def _wireguard(self, cfg: dict) -> None:
        wgs = ((cfg.get("interfaces") or {}).get("wireguard") or {})
        for wg, c in wgs.items() if isinstance(wgs, dict) else []:
            text = self._optional(f"WireGuard {wg}", lambda wg=wg: self._show("interfaces", "wireguard", wg, "summary"))
            if text is None:
                continue
            peers = re.split(r"(?m)^\s*peer:\s*", text)[1:]
            configured = len((c or {}).get("peer") or {}) if isinstance(c, dict) else 0
            alive = [p for p in peers if re.search(r"latest handshake:", p)]
            rx = sum(to_bytes(m) or 0 for m in re.findall(r"transfer:\s*([\d.]+\s*\w+)\s*received", text))
            tx = sum(to_bytes(m) or 0 for m in re.findall(r"received,\s*([\d.]+\s*\w+)\s*sent", text))
            n = max(len(peers), configured)
            self.data.setdefault("tunnels", []).append({
                "kind": "WireGuard", "name": wg, "remote": f"{n} peer{'s' if n != 1 else ''}", "up": bool(alive),
                "state": f"{len(alive)}/{n} peers with a handshake" if n else "no peers",
                "in_bytes": rx or None, "out_bytes": tx or None})

    def _leases(self) -> None:
        text = self._optional("DHCP leases", lambda: self._show("dhcp", "server", "leases"))
        if text is None:
            return
        self.data["leases"] = [{
            "ip": col(r, "IP Address", "IP address"), "mac": col(r, "MAC address", "Hardware address"),
            "hostname": col(r, "Hostname"), "interface": col(r, "Pool"), "state": col(r, "State"),
            "starts": col(r, "Lease start"), "ends": col(r, "Lease expiration"), "remaining": col(r, "Remaining"),
        } for r in parse_table(text, "IP Address")]
