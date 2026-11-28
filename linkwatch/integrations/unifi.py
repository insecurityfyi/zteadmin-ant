"""UniFi Network on a local console or self-hosted controller (called by a poller).

Reads the Network application's local API, which has the live statistics the
newer ``integration/v1`` API leaves out:

* ``stat/device``  access points, switches and gateways: CPU, memory, uptime,
  ports with byte counters, radios, SSIDs per AP and the WAN links
* ``stat/sta``     connected clients: SSID, AP or switch port, signal, link
  rate, current download/upload rate and totals

Each client is also marked directly attached or not. A Wi-Fi client associated
to a UniFi AP is direct. A wired client is direct only when it is the one MAC
seen on an access port of a UniFi switch: not an uplink, not a port another UniFi
device hangs off, and no other LLDP neighbour on it. Everything else (MACs
learned through a downstream switch, a hub or a phone's PC port, or seen only by
the gateway) is kept but marked with the reason.
* ``rest/wlanconf`` the configured SSIDs (so idle ones show up too)
* ``stat/health``  WAN/ISP summary and internet latency
* ``stat/event``   the last hour of Wi-Fi connects, disconnects, roams and failures (optional: newer
  Network releases may return nothing, and then those counts stay empty)

Wireless detail for the Wireless dashboard rides along: per client signal, noise, SNR, link rates, retry
and roam counters; per radio channel utilization (own traffic and interference), noise floor, TX power,
retry and drop counters. Counters are cumulative; the server turns them into rates between polls.

Sign-in is an API key (UniFi OS consoles with Network 9.0 or later:
Settings > Control Plane > Integrations) sent as ``X-API-KEY``. A local
username and password also works, which is the only option on a self-hosted
controller (port 8443) or older firmware.

Besides device records the collector leaves a ``data`` dict (clients, SSIDs,
APs, WAN links, totals). The poller sends it with the records and the server
keeps the latest snapshot plus time series for the UniFi dashboard.
"""
from __future__ import annotations

import re
from typing import Any

import httpx

from .base import Field, Integration, IntegrationError, Record, host_url, verify_field

# stat/device "state"
STATE = {0: "down", 1: "up", 2: "off", 4: "warn", 5: "warn", 6: "down", 7: "warn", 9: "warn", 10: "warn", 11: "down"}
STATE_TEXT = {0: "Offline", 2: "Pending adoption", 4: "Upgrading", 5: "Provisioning", 6: "Heartbeat missed",
              7: "Adopting", 9: "Adoption failed", 10: "Isolated", 11: "Disconnected"}
KIND = {"uap": "Wireless", "usw": "Switch", "ugw": "Router", "udm": "Router", "uxg": "Router", "uck": "Server"}
BAND = {"ng": "2.4 GHz", "na": "5 GHz", "6e": "6 GHz", "ad": "60 GHz"}
MAX_CLIENTS = 2000
KEY_HELP = ("Use an API key from UniFi Network > Settings > Control Plane > Integrations (Network 9.0 or later), "
            "or a local admin username and password.")


def _num(v: Any) -> float | None:
    try:
        return None if v is None or v == "" else float(v)
    except (TypeError, ValueError):
        return None


def _bps(bytes_per_s: Any) -> float | None:
    v = _num(bytes_per_s)
    return None if v is None else round(v * 8, 1)


class UniFi(Integration):
    kind = "unifi"
    label = "UniFi Network"
    runs_on = "poller"
    description = ("Access points, switches and gateways with ports and radios, every client (SSID, AP, signal, "
                   "bandwidth), per-SSID bandwidth and WAN throughput.")
    fields = [
        Field("host", "UniFi console address", help="e.g. 192.168.1.1 for a UDM/UCG/Cloud Key, or 10.0.0.5:8443 for a self-hosted controller."),
        Field("api_key", "API key", "password", required=False,
              help="UniFi Network > Settings > Control Plane > Integrations > Create API key. Leave blank to sign in with a username instead."),
        Field("username", "Local username", required=False, help="Only if you don't use an API key: a local (not ui.com) read-only admin."),
        Field("password", "Local password", "password", required=False),
        Field("site", "Site", required=False, help="Blank reads every site. Otherwise the site name or ID, e.g. default."),
        verify_field(),
    ]

    def __init__(self, config: dict[str, Any], http: httpx.Client | None = None):
        super().__init__(config, http)
        self.base = host_url(config["host"])
        self.key = str(config.get("api_key") or "").strip()
        self.username = str(config.get("username") or "").strip()
        self.password = str(config.get("password") or "")
        if not self.key and not (self.username and self.password):
            raise IntegrationError("Enter an API key, or a local username and password.")
        self.prefix: str | None = None      # "/proxy/network" on UniFi OS, "" on a classic controller
        self.headers = {"Accept": "application/json"}
        self.data: dict[str, Any] = {}
        self.errors: list[str] = []
        self._events_ok = False

    # ------------------------------------------------------------ sign-in
    def _login(self) -> None:
        body = {"username": self.username, "password": self.password, "remember": False}
        try:
            r = self.http.post(f"{self.base}/api/auth/login", json=body, headers={"Accept": "application/json"})
            if r.status_code == 404:          # not UniFi OS: a classic controller
                r = self.http.post(f"{self.base}/api/login", json=body, headers={"Accept": "application/json"})
                self.prefix = ""
            else:
                self.prefix = "/proxy/network"
        except httpx.HTTPError as exc:
            raise IntegrationError(f"Could not reach {httpx.URL(self.base).host}: {exc.__class__.__name__}") from exc
        if r.status_code in (400, 401, 403):
            raise IntegrationError(f"{httpx.URL(self.base).host} refused the username or password (HTTP {r.status_code}). "
                                   "Use a local account, not a ui.com login with two-factor.")
        if r.status_code >= 400:
            raise IntegrationError(f"Sign-in returned HTTP {r.status_code}")
        csrf = r.headers.get("x-csrf-token") or r.headers.get("x-updated-csrf-token")
        if csrf:
            self.headers["X-CSRF-Token"] = csrf

    def _connect(self) -> None:
        if self.prefix is not None:
            return
        if self.key:
            self.headers["X-API-KEY"] = self.key
            self.prefix = "/proxy/network"
            try:
                self._get(f"{self.base}{self.prefix}/api/self/sites", headers=self.headers)
                return
            except IntegrationError as exc:
                if not (self.username and self.password):
                    if "rejected the credentials" in str(exc):
                        raise IntegrationError(f"{exc}. {KEY_HELP}") from exc
                    raise
                self.headers.pop("X-API-KEY", None)
                self.prefix = None
        self._login()

    def _api(self, path: str) -> list[dict]:
        self._connect()
        body = self._get(f"{self.base}{self.prefix}/api{path}", headers=self.headers).json()
        meta = body.get("meta") or {}
        if meta.get("rc") not in (None, "ok"):
            raise IntegrationError(f"UniFi said {meta.get('msg') or meta.get('rc')} for {path}")
        return body.get("data") or []

    def _sites(self) -> list[dict]:
        sites = self._api("/self/sites")
        want = str(self.config.get("site") or "").strip().lower()
        if want:
            sites = [s for s in sites if want in (str(s.get("name", "")).lower(), str(s.get("desc", "")).lower(), str(s.get("_id", "")).lower())]
            if not sites:
                raise IntegrationError(f"No UniFi site called '{self.config['site']}'")
        return sites

    # ------------------------------------------------------------ collect
    def collect(self) -> list[Record]:
        records: list[Record] = []
        clients: list[dict] = []
        aps: list[dict] = []
        wans: list[dict] = []
        ssids: dict[str, dict] = {}
        switch_ports: list[dict] = []
        health: dict[str, Any] = {}
        wifi_events: list[dict] = []
        sites = self._sites()
        multi = len(sites) > 1
        for site in sites:
            sid, sname = site.get("name") or "default", site.get("desc") or site.get("name") or "Default"
            devices = self._api(f"/s/{sid}/stat/device")
            names = {d.get("mac"): (d.get("name") or d.get("mac")) for d in devices}
            for d in devices:
                records.append(self._record(d, sname, wans))
                if d.get("type") == "uap":
                    aps.append(self._ap(d, sname))
            for w in self._safe(f"/s/{sid}/rest/wlanconf"):
                name = w.get("name")
                if name:
                    ssids.setdefault(self._ssid_key(name, sname, multi), {
                        "name": name, "site": sname, "enabled": bool(w.get("enabled", True)), "security": w.get("security"),
                        "band": w.get("wlan_band"), "vlan": w.get("vlan") if w.get("vlan_enabled") else None,
                        "guest": bool(w.get("is_guest")), "clients": 0, "down_bps": 0.0, "up_bps": 0.0, "aps": set()})
            site_clients = [self._client(c, sname, names) for c in self._api(f"/s/{sid}/stat/sta")]
            wifi_events.extend(self._events(sid, sname, names))
            switch_ports.extend(attachment(devices, site_clients, sname, names))
            clients.extend(site_clients)
            for h in self._safe(f"/s/{sid}/stat/health"):
                sub = h.get("subsystem")
                if sub == "wan" and not health.get("isp"):
                    health.update(isp=h.get("isp_name") or h.get("isp_organization"), wan_ip=h.get("wan_ip"),
                                  gateway=h.get("gw_name"), wan_status=h.get("status"))
                    if not any(w["site"] == sname for w in wans) and (h.get("rx_bytes-r") is not None):
                        wans.append({"name": "WAN", "site": sname, "up": h.get("status") == "ok", "ip": h.get("wan_ip"),
                                     "down_bps": _bps(h.get("rx_bytes-r")), "up_bps": _bps(h.get("tx_bytes-r")), "isp": health.get("isp")})
                elif sub == "www":
                    health.update(latency_ms=_num(h.get("latency")), speedtest_down=_num(h.get("xput_down")),
                                  speedtest_up=_num(h.get("xput_up")), speedtest_ping=_num(h.get("speedtest_ping")),
                                  internet_status=h.get("status"))

        # per-SSID and per-AP figures from the clients
        by_ap = {a["mac"]: a for a in aps}
        for c in clients:
            if c["wired"] or not c.get("ssid"):
                continue
            s = ssids.setdefault(self._ssid_key(c["ssid"], c["site"], multi), {
                "name": c["ssid"], "site": c["site"], "enabled": True, "security": None, "band": None, "vlan": None,
                "guest": False, "clients": 0, "down_bps": 0.0, "up_bps": 0.0, "aps": set()})
            s["clients"] += 1
            s["down_bps"] += c.get("down_bps") or 0
            s["up_bps"] += c.get("up_bps") or 0
            if c.get("ap"):
                s["aps"].add(c["ap"])
            ap = by_ap.get(c.get("ap_mac"))
            if ap is not None:
                ap["down_bps"] += c.get("down_bps") or 0
                ap["up_bps"] += c.get("up_bps") or 0
        for s in ssids.values():
            s["aps"] = sorted(s["aps"])
        _count_events(ssids, wifi_events, multi)
        clients.sort(key=lambda c: -((c.get("down_bps") or 0) + (c.get("up_bps") or 0)))
        wireless = sum(1 for c in clients if not c["wired"])
        self.data = {
            "type": "unifi",
            "summary": {"clients": len(clients), "wireless": wireless, "wired": len(clients) - wireless,
                        "direct": sum(1 for c in clients if c.get("direct")),
                        "direct_wired": sum(1 for c in clients if c.get("direct") and c["wired"]),
                        "guests": sum(1 for c in clients if c.get("guest")),
                        "aps": len(aps), "aps_up": sum(1 for a in aps if a["status"] == "up"),
                        "down_bps": sum(w.get("down_bps") or 0 for w in wans if w.get("up") is not False),
                        "up_bps": sum(w.get("up_bps") or 0 for w in wans if w.get("up") is not False),
                        "sites": [s.get("desc") or s.get("name") for s in sites], **health},
            "wans": wans,
            "ssids": sorted(ssids.values(), key=lambda s: (-s["clients"], s["name"])),
            "aps": sorted(aps, key=lambda a: -a["clients"]),
            "clients": clients[:MAX_CLIENTS],
            "switch_ports": switch_ports,
            "events_ok": bool(wifi_events) or self._events_ok,
        }
        if len(clients) > MAX_CLIENTS:
            self.errors.append(f"Only the {MAX_CLIENTS} busiest of {len(clients)} clients are kept")
        return records

    def test(self) -> str:
        records = self.collect()
        s = self.data.get("summary", {})
        return (f"Connected. Found {len(records)} UniFi devices, {s.get('clients', 0)} clients "
                f"and {len(self.data.get('ssids', []))} SSIDs.")

    def _safe(self, path: str) -> list[dict]:
        """Optional endpoints: a failure becomes a warning instead of failing the sync."""
        try:
            return self._api(path)
        except IntegrationError as exc:
            self.errors.append(f"{path.split('/', 3)[-1]}: {exc}")
            return []

    def _events(self, sid: str, site: str, names: dict) -> list[dict]:
        """Wi-Fi events from the last hour. Silent on failure: newer releases moved these to the system log."""
        try:
            rows = self._api(f"/s/{sid}/stat/event?within=1&_limit=3000")
        except IntegrationError:
            return []
        self._events_ok = True
        out = []
        for e in rows:
            kind = event_kind(e.get("key"), e.get("msg"))
            if kind:
                out.append({"kind": kind, "site": site, "ssid": e.get("ssid"), "mac": e.get("user") or e.get("guest"),
                            "ap": names.get(e.get("ap") or e.get("ap_to")) or e.get("ap_name"), "time": e.get("time")})
        return out

    @staticmethod
    def _ssid_key(name: str, site: str, multi: bool) -> str:
        return f"{site} / {name}" if multi else name

    # ------------------------------------------------------------ shaping
    def _record(self, d: dict, site: str, wans: list[dict]) -> Record:
        mac = d.get("mac")
        state = int(d.get("state") or 0)
        status = STATE.get(state, "unknown")
        stats = d.get("system-stats") or {}
        kind = KIND.get(d.get("type"), "Network")
        notes = [f"Firmware {d.get('version') or '?'}"]
        if d.get("num_sta") is not None:
            notes.append(f"{int(d.get('num_sta') or 0)} clients")
        if state in STATE_TEXT:
            notes.insert(0, STATE_TEXT[state])
        extra: dict[str, Any] = {"mac": mac, "model": d.get("model"), "clients": d.get("num_sta"),
                                 "satisfaction": d.get("satisfaction")}
        uplink = d.get("uplink") or {}
        if uplink.get("uplink_mac") or uplink.get("type"):
            up_name = uplink.get("uplink_device_name") or uplink.get("uplink_mac") or ""
            port = uplink.get("uplink_remote_port")
            extra["uplink"] = " ".join(str(x) for x in (uplink.get("type"), up_name, f"port {port}" if port else "") if x)
            extra["uplink_mac"], extra["uplink_port"] = uplink.get("uplink_mac"), port
            extra["uplink_name"] = uplink.get("uplink_device_name")
            extra["uplink_wireless"] = uplink.get("type") == "wireless"     # a mesh AP hanging off another AP
        if d.get("type") == "uap":
            extra["radios"] = ", ".join(self._radio_text(r) for r in self._radios(d))
        for key in ("wan1", "wan2", "wan3"):
            w = d.get(key)
            if not isinstance(w, dict) or not (w.get("ip") or w.get("up") is not None):
                continue
            wan = {"name": key.upper(), "site": site, "device": d.get("name") or mac, "up": bool(w.get("up")),
                   "ip": w.get("ip"), "down_bps": _bps(w.get("rx_bytes-r")), "up_bps": _bps(w.get("tx_bytes-r")),
                   "speed_mbps": w.get("speed"), "isp": w.get("isp_name")}
            wans.append(wan)
            extra[key] = f"{'up' if wan['up'] else 'DOWN'} {wan['ip'] or ''}".strip()
            if not wan["up"] and status == "up" and w.get("enable", True):
                status = "warn"
                notes.insert(0, f"{key.upper()} down")
        rec = Record(
            external_id=mac or d.get("_id"), hostname=d.get("name") or mac, ip=d.get("ip"), type=kind,
            platform=f"UniFi {d.get('model') or ''}".strip(), site=site, status=status,
            cpu=_num(stats.get("cpu")), mem=_num(stats.get("mem")), uptime_s=int(d["uptime"]) if d.get("uptime") else None,
            serial=d.get("serial"), detail=" · ".join(notes), extra={k: v for k, v in extra.items() if v not in (None, "")},
        )
        ports = [self._port(p) for p in d.get("port_table") or [] if p.get("port_idx") is not None]
        if ports:
            rec["ports"] = ports
        return rec

    @staticmethod
    def _port(p: dict) -> dict:
        up, enabled = bool(p.get("up")), p.get("enable", True) is not False
        alias = p.get("name") if p.get("name") and p.get("name") != f"Port {p.get('port_idx')}" else ""
        if p.get("poe_power") not in (None, "", "0.00"):
            alias = (alias + f" · PoE {p['poe_power']} W").strip(" ·")
        return {"ifindex": int(p["port_idx"]), "name": f"Port {p['port_idx']}", "alias": alias,
                "speed_mbps": int(p["speed"]) if up and p.get("speed") else None,
                "admin": "up" if enabled else "down", "oper": "up" if up else "down",
                "in_octets": _num(p.get("rx_bytes")), "out_octets": _num(p.get("tx_bytes")),
                "in_errors": _num(p.get("rx_errors")), "out_errors": _num(p.get("tx_errors")), "counter_bits": 64}

    @staticmethod
    def _radios(d: dict) -> list[dict]:
        stats = {r.get("name"): r for r in d.get("radio_table_stats") or []}
        # drops and retries per radio come from the SSIDs (VAPs) on it
        vaps: dict[str, dict[str, float]] = {}
        for v in d.get("vap_table") or []:
            agg = vaps.setdefault(v.get("radio") or "", {"tx_dropped": 0.0, "rx_dropped": 0.0, "found": 0.0})
            for k in ("tx_dropped", "rx_dropped"):
                agg[k] += _num(v.get(k)) or 0
            agg["found"] = 1.0
        out = []
        for r in d.get("radio_table") or []:
            st = stats.get(r.get("name"), {})
            total, rx, tx = _num(st.get("cu_total")), _num(st.get("cu_self_rx")), _num(st.get("cu_self_tx"))
            interference = max(0.0, round(total - (rx or 0) - (tx or 0), 1)) if total is not None and (rx is not None or tx is not None) else None
            vap = vaps.get(r.get("radio") or "", {})
            out.append({"band": BAND.get(r.get("radio"), r.get("radio")), "radio": r.get("radio"), "name": r.get("name"),
                        "channel": st.get("channel") or r.get("channel"),
                        "width": r.get("ht"), "tx_power": _num(st.get("tx_power")), "clients": st.get("num_sta"),
                        "utilization": total, "self_rx": rx, "self_tx": tx, "interference": interference,
                        "noise": _num(st.get("noise") if st.get("noise") is not None else r.get("noise")),
                        "tx_packets": _num(st.get("tx_packets")), "tx_retries": _num(st.get("tx_retries")),
                        "tx_dropped": vap.get("tx_dropped") if vap.get("found") else None,
                        "rx_dropped": vap.get("rx_dropped") if vap.get("found") else None,
                        "satisfaction": st.get("satisfaction")})
        return out

    @staticmethod
    def _radio_text(r: dict) -> str:
        bits = [f"{r['band']} ch {r['channel']}" if r.get("channel") else str(r["band"])]
        if r.get("utilization") is not None:
            bits.append(f"{r['utilization']:.0f}% busy")
        if r.get("clients") is not None:
            bits.append(f"{r['clients']} clients")
        return " ".join(bits[:1]) + (f" ({', '.join(bits[1:])})" if len(bits) > 1 else "")

    def _ap(self, d: dict, site: str) -> dict:
        return {"mac": d.get("mac"), "name": d.get("name") or d.get("mac"), "site": site, "model": d.get("model"),
                "status": STATE.get(int(d.get("state") or 0), "unknown"), "ip": d.get("ip"),
                "clients": int(d.get("num_sta") or 0), "satisfaction": d.get("satisfaction"),
                "radios": self._radios(d), "down_bps": 0.0, "up_bps": 0.0,
                "uptime_s": int(d["uptime"]) if d.get("uptime") else None,
                "ssids": sorted({v.get("essid") for v in d.get("vap_table") or [] if v.get("essid")})}

    @staticmethod
    def _client(c: dict, site: str, names: dict) -> dict:
        wired = bool(c.get("is_wired"))
        # stat/sta byte counts are from the network's side: tx = sent to the client (its download)
        down = c.get("wired-tx_bytes-r") if wired and c.get("wired-tx_bytes-r") is not None else c.get("tx_bytes-r")
        up = c.get("wired-rx_bytes-r") if wired and c.get("wired-rx_bytes-r") is not None else c.get("rx_bytes-r")
        sw = c.get("sw_mac")
        return {
            "mac": c.get("mac"), "name": c.get("name") or c.get("hostname") or c.get("mac"), "hostname": c.get("hostname"),
            "ip": c.get("ip") or c.get("last_ip"), "site": site, "wired": wired, "guest": bool(c.get("is_guest")),
            "vendor": c.get("oui"), "network": c.get("network"), "vlan": c.get("vlan"),
            "ssid": None if wired else c.get("essid"), "ap_mac": c.get("ap_mac"), "ap": names.get(c.get("ap_mac")) if c.get("ap_mac") else None,
            "switch": names.get(sw, sw) if sw else None, "switch_mac": sw, "switch_port": c.get("sw_port"),
            "band": BAND.get(c.get("radio"), c.get("radio")), "channel": c.get("channel"), "proto": c.get("radio_proto"),
            "signal": _num(c.get("signal")), "rssi": _num(c.get("rssi")), "noise": _num(c.get("noise")),
            "satisfaction": _num(c.get("satisfaction")),
            "tx_rate_mbps": round(c["tx_rate"] / 1000, 1) if c.get("tx_rate") else None,
            "rx_rate_mbps": round(c["rx_rate"] / 1000, 1) if c.get("rx_rate") else None,
            "down_bps": _bps(down), "up_bps": _bps(up),
            "down_bytes": _num(c.get("wired-tx_bytes") if wired else c.get("tx_bytes")),
            "up_bytes": _num(c.get("wired-rx_bytes") if wired else c.get("rx_bytes")),
            "uptime_s": c.get("uptime"),
            **({} if wired else _wifi_detail(c)),
        }


def _wifi_detail(c: dict) -> dict:
    """Wireless counters and quality figures for one client (rates are worked out by the server between polls)."""
    signal, noise = _num(c.get("signal")), _num(c.get("noise"))
    out = {"snr": round(signal - noise, 1) if signal is not None and noise is not None else None,
           "bssid": c.get("bssid"), "tx_retries": _num(c.get("tx_retries")), "tx_packets": _num(c.get("tx_packets")),
           "tx_attempts": _num(c.get("wifi_tx_attempts")), "roam_count": _num(c.get("roam_count")),
           "idle_s": _num(c.get("idletime")), "retry_pct": None}
    pct = _num(c.get("wifi_tx_retries_percentage"))
    if pct is not None:
        out["retry_pct"] = round(pct, 1)
    return out


EVENT_KINDS = (
    ("auth_fail", re.compile(r"auth.{0,24}fail|fail.{0,24}auth|wpa.{0,24}fail|radius.{0,24}(reject|fail)|eap.{0,24}fail|wrong.?(password|psk)", re.I)),
    ("assoc_fail", re.compile(r"assoc.{0,24}(fail|reject)|fail.{0,24}assoc", re.I)),
    ("dhcp_fail", re.compile(r"dhcp.{0,24}(fail|time)|fail.{0,24}dhcp|no ip address", re.I)),
    ("roam", re.compile(r"^EVT_WU_Roam", re.I)),
    ("connect", re.compile(r"^EVT_W[UG]_Connected", re.I)),
    ("disconnect", re.compile(r"^EVT_W[UG]_Disconnected", re.I)),
)


def event_kind(key: Any, msg: Any = None) -> str | None:
    """auth_fail, assoc_fail, dhcp_fail, roam, connect or disconnect for a UniFi event, else None."""
    key, msg = str(key or ""), str(msg or "")
    if not key.startswith(("EVT_WU", "EVT_WG", "EVT_AP")) and "fail" not in (key + msg).lower():
        return None
    for kind, rx in EVENT_KINDS:
        if rx.search(key) or (kind.endswith("_fail") and rx.search(msg)):
            return kind
    return None


def _count_events(ssids: dict[str, dict], events: list[dict], multi: bool) -> None:
    for s in ssids.values():
        s.setdefault("events", {k: 0 for k, _ in EVENT_KINDS})
    for e in events:
        if not e.get("ssid"):
            continue
        s = ssids.get(UniFi._ssid_key(e["ssid"], e["site"], multi))
        if s is not None:
            s["events"][e["kind"]] = s["events"].get(e["kind"], 0) + 1


def _mac(v: Any) -> str:
    return str(v or "").strip().lower()


PHONE_VENDORS = ("polycom", "poly ", "plantronics", "yealink", "avaya", "mitel", "aastra", "grandstream", "snom", "cisco spa",
                 "fanvil", "htek", "obihai", "panasonic", "unify", "siemens enterprise", "alcatel-lucent ent", "shoretel",
                 "nec platforms", "spectralink", "algo")
PHONE_NAME = re.compile(r"(^|[-_. ])(phone|voip|sip|vvx|polycom|yealink|deskphone)([-_. 0-9]|$)|^sep[0-9a-f]{12}$|^cp-?\d{4}", re.IGNORECASE)


def _phone_score(c: dict, lldp_macs: set[str]) -> int:
    """How sure we are this is a desk phone: it speaks LLDP on the port (LLDP-MED) 3, phone vendor 2, phone-like name 1."""
    if _mac(c.get("mac")) in lldp_macs:
        return 3
    vendor = f" {str(c.get('vendor') or '').lower()} "
    if any(v in vendor for v in PHONE_VENDORS):
        return 2
    return 1 if any(PHONE_NAME.search(str(c.get(k) or "")) for k in ("name", "hostname")) else 0


def _is_phone(c: dict, lldp_macs: set[str]) -> bool:
    return _phone_score(c, lldp_macs) > 0


def attachment(devices: list[dict], clients: list[dict], site: str, names: dict) -> list[dict]:
    """Marks each client direct or not (sets ``direct``, ``attach`` and ``attach_note``) and returns one row per switch port.

    ``attach`` is one of: wifi, port, phone (direct); behind_phone, uplink, unifi, shared, neighbour, gateway (not direct).
    A desk phone with a PC plugged into it counts as direct; the PC behind it doesn't.
    """
    by_mac = {_mac(d.get("mac")): d for d in devices}
    # ports that lead to another UniFi device: that device reports which port of which switch it hangs off
    downlinks: dict[tuple[str, int], str] = {}
    for d in devices:
        up = d.get("uplink") or {}
        if up.get("uplink_mac") and up.get("uplink_remote_port") is not None:
            try:
                downlinks[(_mac(up["uplink_mac"]), int(up["uplink_remote_port"]))] = str(d.get("name") or d.get("mac"))
            except (TypeError, ValueError):
                pass
    on_port: dict[tuple[str, int], list[dict]] = {}
    for c in clients:
        if c["wired"] and c.get("switch_mac") and c.get("switch_port") is not None:
            try:
                on_port.setdefault((_mac(c["switch_mac"]), int(c["switch_port"])), []).append(c)
            except (TypeError, ValueError):
                pass

    info: dict[tuple[str, int], dict] = {}
    rows: list[dict] = []
    for d in devices:
        dmac = _mac(d.get("mac"))
        lldp: dict[int, list[dict]] = {}
        for n in d.get("lldp_table") or []:
            try:
                lldp.setdefault(int(n.get("local_port_idx")), []).append(n)
            except (TypeError, ValueError):
                continue
        for p in d.get("port_table") or []:
            if p.get("port_idx") is None:
                continue
            idx = int(p["port_idx"])
            key = (dmac, idx)
            here = on_port.get(key, [])
            macs = {_mac(c["mac"]) for c in here}
            others = [n for n in lldp.get(idx, []) if _mac(n.get("chassis_id")) not in macs]
            neighbour = next((str(n.get("system_name") or n.get("chassis_name") or n.get("chassis_id") or "") for n in others), None)
            phone = None
            if len(here) == 2:
                lldp_macs = {_mac(n.get("chassis_id")) for n in lldp.get(idx, [])}
                a, b = (_phone_score(c, lldp_macs) for c in here)
                phone = here[0] if a > b else here[1] if b > a else None      # a tie means we can't tell which is the phone
            if p.get("is_uplink"):
                role, note = "uplink", "Uplink port"
            elif key in downlinks:
                role, note = "unifi", f"Port to {downlinks[key]}"
            elif others:
                role, note = "neighbour", f"LLDP neighbour {neighbour}"
            elif phone is not None:
                pc = next(c for c in here if c is not phone)
                role, note = "phone", f"Desk phone {phone['name']} with {pc['name']} plugged into it"
                phone["attach_role"], pc["attach_role"] = "phone", "behind_phone"
                pc["attach_via"] = phone["name"]
            elif len(here) > 1:
                role, note = "shared", f"{len(here)} MACs on this port: a switch or hub"
            elif here:
                role, note = "client", ""
            else:
                role, note = ("empty" if p.get("up") else "down"), ""
            info[key] = {"role": role, "note": note}
            if phone is not None:   # phone first, then the PC behind it
                here = [phone] + [c for c in here if c is not phone]
            if d.get("type") in ("usw", "udm", "uxg", "ugw") or here or p.get("is_uplink"):
                alias = p.get("name") if p.get("name") and p.get("name") != f"Port {idx}" else ""
                rows.append({"switch": names.get(d.get("mac")) or d.get("name") or d.get("mac"), "switch_mac": d.get("mac"), "site": site,
                             "port": idx, "name": alias, "up": bool(p.get("up")), "enabled": p.get("enable", True) is not False,
                             "speed_mbps": int(p["speed"]) if p.get("up") and p.get("speed") else None,
                             "poe_w": _num(p.get("poe_power")) or None, "role": role, "note": note, "neighbour": neighbour,
                             "clients": [{"mac": c["mac"], "name": c["name"], "ip": c.get("ip")} for c in here[:8]], "client_count": len(here)})

    for c in clients:
        if not c["wired"]:
            c["attach"], c["attach_note"] = ("wifi", "") if c.get("ap_mac") else ("unknown", "No access point reported")
        elif not c.get("switch_mac") or c.get("switch_port") is None:
            c["attach"], c["attach_note"] = "gateway", "Seen by the gateway only, not on a UniFi switch port"
        else:
            try:
                key = (_mac(c["switch_mac"]), int(c["switch_port"]))
            except (TypeError, ValueError):
                key = ("", 0)
            role = info.get(key, {"role": "client" if key[0] in by_mac else "gateway", "note": ""})
            if role["role"] == "phone":
                c["attach"] = c.pop("attach_role")
                c["attach_note"] = f"Plugged into desk phone {c.pop('attach_via')}" if c["attach"] == "behind_phone" else "Desk phone"
            else:
                c["attach"] = "port" if role["role"] == "client" else role["role"]
                c["attach_note"] = role["note"] or ("" if c["attach"] == "port" else "Switch port not reported")
        c["direct"] = c["attach"] in ("wifi", "port", "phone")
    return rows
