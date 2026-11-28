"""SonicWall SonicOS REST API (SonicOS 6.5.4+ and 7.x, on-prem, called by a poller).

Sign-in is HTTP Basic: POST /api/sonicos/auth, then the same credentials on each GET, then DELETE /api/sonicos/auth so
the firewall's admin session is freed straight away (SonicOS allows one configuring admin at a time).

Paths used:
  documented (SonicOS API reference / SonicWall community):
    /api/sonicos/auth                              POST sign in, DELETE sign out
    /api/sonicos/interfaces/ipv4                   interface settings (name, zone, addressing)
    /api/sonicos/reporting/ssl-vpn/sessions        connected SSL VPN users
    /api/sonicos/reporting/license/security-services   licence and security service status
  best effort (offered by some firmware builds; skipped quietly when missing):
    /api/sonicos/version                           model, serial, firmware, uptime
    /api/sonicos/reporting/high-availability/status
    /api/sonicos/reporting/vpn/ipsec/tunnels

SonicOS's REST API has little live telemetry, so CPU, memory, connection counts and interface traffic come from SNMP:
add the firewall as an SNMP device too and VisCon1 shows both on one device (matched on serial or IP).
"""
from __future__ import annotations

from typing import Any

import httpx

from .base import Field, Integration, IntegrationError, Record, host_url, verify_field

API = "/api/sonicos"
JSON = {"Accept": "application/json", "Content-Type": "application/json"}


def _pick(d: dict, *keys, default=None):
    """First present, non-empty value among several possible field names (they differ between firmware builds)."""
    for k in keys:
        v = d.get(k) if isinstance(d, dict) else None
        if v not in (None, "", [], {}):
            return v
    return default


def _rows(body: Any, *keys: str) -> list[dict]:
    """The list inside a SonicOS response, whether it's the body itself or under one of a few wrapper keys."""
    if isinstance(body, list):
        return [r for r in body if isinstance(r, dict)]
    if isinstance(body, dict):
        for k in keys:
            v = body.get(k)
            if isinstance(v, list):
                return [r for r in v if isinstance(r, dict)]
            if isinstance(v, dict):
                return _rows(v, *keys)
    return []


class SonicWall(Integration):
    kind = "sonicwall"
    label = "SonicWall"
    runs_on = "poller"
    description = "SonicOS API: system, interfaces, SSL VPN users, licences and security services. Pair with SNMP for CPU, memory and traffic."
    fields = [
        Field("host", "Firewall address", help="Management IP or hostname, with :port if the HTTPS management port isn't 443."),
        Field("username", "Admin username", help="A dedicated admin for VisCon1 (see the setup steps). Don't reuse your own: "
                                                 "an API sign-in can end a web session for the same account."),
        Field("password", "Password", "password"),
        verify_field(),
    ]

    def __init__(self, config: dict[str, Any], http: httpx.Client | None = None):
        super().__init__(config, http)
        self.base = host_url(config["host"]) + API
        self.auth = httpx.BasicAuth(config["username"], config["password"])

    # http ---------------------------------------------------------------
    def _login(self) -> None:
        try:
            r = self.http.post(f"{self.base}/auth", auth=self.auth, headers=JSON, json={"override": False})
        except httpx.HTTPError as exc:
            raise IntegrationError(f"Could not reach {httpx.URL(self.base).host}: {exc.__class__.__name__}") from exc
        if r.status_code in (401, 403):
            raise IntegrationError(
                "The firewall refused the sign-in (HTTP %d). Check the username and password, that the SonicOS API is "
                "enabled with RFC-2617 HTTP Basic authentication, and that HTTPS management is allowed on that "
                "interface." % r.status_code)
        if r.status_code == 503:
            raise IntegrationError("The firewall has no free API sessions (HTTP 503). Try again shortly.")
        if r.status_code >= 400:
            raise IntegrationError(f"Sign-in returned HTTP {r.status_code}: {self._message(r)}")
        body = self._json(r)
        status = (body.get("status") or {}) if isinstance(body, dict) else {}
        if status and status.get("success") is False:
            raise IntegrationError(f"Sign-in refused: {self._message(r)}")

    def _logout(self) -> None:
        try:
            self.http.delete(f"{self.base}/auth", auth=self.auth, headers=JSON)
        except httpx.HTTPError:
            pass

    @staticmethod
    def _json(r: httpx.Response) -> Any:
        try:
            return r.json()
        except ValueError:
            return {}

    def _message(self, r: httpx.Response) -> str:
        body = self._json(r)
        info = ((body.get("status") or {}).get("info") or [{}]) if isinstance(body, dict) else [{}]
        msg = info[0].get("message") if info and isinstance(info[0], dict) else None
        return str(msg or r.reason_phrase or "no detail")[:300]

    def _api(self, path: str) -> Any:
        try:
            r = self.http.get(f"{self.base}{path}", auth=self.auth, headers=JSON)
        except httpx.HTTPError as exc:
            raise IntegrationError(f"Could not reach {httpx.URL(self.base).host}: {exc.__class__.__name__}") from exc
        if r.status_code in (401, 403):
            raise IntegrationError(f"GET {path} was refused (HTTP {r.status_code}); the admin account may lack access")
        if r.status_code >= 400:
            raise IntegrationError(f"GET {path} returned HTTP {r.status_code}")
        return self._json(r)

    def _optional(self, label: str, fn, quiet: bool = False):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - one missing panel, not a failed sync
            if quiet and "HTTP 404" in str(exc):
                self.data["not_offered"].append(label)
            else:
                self.data["unavailable"].append(f"{label}: {exc}")
            return None

    # collection ---------------------------------------------------------
    def collect(self) -> list[Record]:
        self.data = {"type": "sonicwall", "unavailable": [], "not_offered": []}
        self._login()
        try:
            return self._collect()
        finally:
            self._logout()

    def _collect(self) -> list[Record]:
        ver = self._optional("Version and serial", lambda: self._api("/version"), quiet=True) or {}
        system = {
            "model": _pick(ver, "model", "product_name", "model_name"),
            "serial": _pick(ver, "serial_number", "serial"),
            "firmware": _pick(ver, "firmware_version", "sonicos_version", "version"),
            "rom": _pick(ver, "rom_version"),
            "uptime": _pick(ver, "system_uptime", "uptime"),
            "time": _pick(ver, "system_time"),
        }
        self.data["system"] = system

        ifaces = self._optional("Interfaces", lambda: self._api("/interfaces/ipv4")) or {}
        table = []
        for row in _rows(ifaces, "interfaces"):
            i = row.get("ipv4") if isinstance(row.get("ipv4"), dict) else row
            assign = i.get("ip_assignment") or {}
            mode = assign.get("mode") or {}
            static = mode.get("static") if isinstance(mode, dict) else None
            kind = next(iter(mode), None) if isinstance(mode, dict) else None
            table.append({"name": i.get("name"), "zone": assign.get("zone"), "mode": kind,
                          "ip": (static or {}).get("ip"), "mask": (static or {}).get("netmask"),
                          "comment": i.get("comment"), "mtu": i.get("mtu"),
                          "vlan": i.get("vlan"), "shutdown": bool(i.get("shutdown_port"))})
        self.data["interfaces"] = table

        sessions = self._optional("SSL VPN users", lambda: self._api("/reporting/ssl-vpn/sessions"))
        if sessions is not None:
            self.data["sslvpn"] = [{
                "user": _pick(s, "user_name", "username", "user", "name"),
                "remote": _pick(s, "client_wan_ip", "client_ip", "remote_ip", "ip_address", "public_ip"),
                "tunnel_ip": _pick(s, "virtual_ip", "client_virtual_ip", "vpn_ip", "assigned_ip"),
                "since": _pick(s, "login_time", "logged_in", "connected_since", "start_time"),
                "bytes_in": _pick(s, "bytes_in", "rx_bytes"), "bytes_out": _pick(s, "bytes_out", "tx_bytes"),
            } for s in _rows(sessions, "ssl_vpn_sessions", "sessions", "ssl_vpn", "users")]

        lic = self._optional("Licences and security services", lambda: self._api("/reporting/license/security-services"))
        if lic is not None:
            rows = _rows(lic, "security_services", "licenses", "services")
            if not rows and isinstance(lic, dict):     # some builds return {"gateway_anti_virus": {...}, ...}
                rows = [{"name": k, **v} for k, v in lic.items() if isinstance(v, dict) and k != "status"]
            self.data["licenses"] = [{
                "name": str(_pick(r, "name", "service", "feature", default="?")).replace("_", " "),
                "status": _pick(r, "status", "state", "licensed"),
                "expires": _pick(r, "expiration", "expiration_date", "expires", "expiry"),
            } for r in rows]
            if lic == [] or (isinstance(lic, dict) and not rows):
                self.data["unavailable"].append("Licences and security services: the firewall returned an empty list "
                                                "(a known issue on some early SonicOS 7.0 builds)")

        ha = self._optional("High availability", lambda: self._api("/reporting/high-availability/status"), quiet=True)
        if isinstance(ha, dict) and ha:
            h = ha.get("high_availability") if isinstance(ha.get("high_availability"), dict) else ha
            self.data["ha"] = {"mode": _pick(h, "mode", "ha_mode"), "state": _pick(h, "state", "status", "local_state"),
                               "peer": _pick(h, "peer_state", "backup_state"), "synchronized": _pick(h, "synchronized", "sync_status")}

        tunnels = self._optional("IPsec tunnels", lambda: self._api("/reporting/vpn/ipsec/tunnels"), quiet=True)
        if tunnels is not None:
            self.data["tunnels"] = [{
                "name": _pick(t, "name", "policy", "vpn_policy"),
                "remote": _pick(t, "peer_gateway", "remote_gateway", "gateway", "peer"),
                "up": str(_pick(t, "status", "state", default="")).lower() in ("up", "active", "connected", "true"),
                "in_bytes": _pick(t, "bytes_in", "rx_bytes"), "out_bytes": _pick(t, "bytes_out", "tx_bytes"),
            } for t in _rows(tunnels, "tunnels", "ipsec", "vpn")]

        host = self.config["host"]
        name = _pick(ver, "firewall_name", "name", "hostname") or host
        n_vpn = len(self.data.get("sslvpn") or [])
        bits = [system["firmware"] or "SonicOS", f"{n_vpn} SSL VPN user{'s' if n_vpn != 1 else ''}"]
        expired = [x["name"] for x in self.data.get("licenses") or [] if str(x.get("status") or "").lower() in ("expired", "not licensed")]
        if expired:
            bits.append(f"expired: {', '.join(expired[:3])}")
        return [Record(
            external_id=system["serial"] or host, hostname=str(name), ip=host_url(host).split("://", 1)[1].split(":")[0],
            type="Firewall", platform=f"SonicWall {system['model'] or ''} {system['firmware'] or ''}".strip(),
            site=None, status="warn" if expired else "up", serial=system["serial"],
            detail=", ".join(bits),
            extra={"firmware": system["firmware"], "uptime": system["uptime"], "ssl_vpn_users": n_vpn,
                   "ha": (self.data.get("ha") or {}).get("state")},
        )]
