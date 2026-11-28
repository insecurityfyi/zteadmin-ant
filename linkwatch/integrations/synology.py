"""Synology DiskStation Manager (DSM 7.x; 6.2 mostly works), over the DSM Web API, called by a poller.

The NAS is reached with a dedicated DSM account (see docs/synology.md). Each sync collects the system, utilisation,
storage (pools, volumes, disks with SMART state), UPS, fans, shares and their snapshots, packages, Container Manager
containers, Virtual Machine Manager guests, Hyper Backup tasks, connected users, Security Advisor and the DSM update
state. Parts whose package isn't installed, or that the account can't read, are listed as unavailable instead of
failing the sync.

The server sends on-demand requests through the poller (protocol message ``rpc``, see
``linkwatch.common.protocol``), which land in :meth:`Synology.action`:

* ``disk_smart`` is read-only;
* everything in ``ACTIONS`` changes the NAS and only runs when *Allow control actions* is ticked on the integration.

How DSM's API works, in short: ``/webapi/query.cgi`` (``SYNO.API.Info``) says which CGI path and versions each API
has; ``SYNO.API.Auth`` logs in and returns a session ID (``sid``) that later calls pass as ``_sid``. Every answer is
``{"success": true, "data": ...}`` or ``{"success": false, "error": {"code": N}}``. Newer APIs read their parameters
as JSON, so string values are sent JSON-quoted (``name="docker"``), the way DSM's own web UI sends them.

Nothing here has been run against a real NAS yet; the API names follow DSM 7.2's web UI traffic, Synology's published
API guides (Auth, VMM) and community clients, and are covered by tests against those shapes only.
"""
from __future__ import annotations

import hashlib
import json
import re
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable

import httpx

from .base import Field, Integration, IntegrationError, Record, host_url, verify_field

SESSION_NAME = "Linkwatch"
SESSION_TTL = 20 * 60          # reuse a login for this long; DSM's own idle timeout is longer by default

PKG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+\-]{0,63}$")
CONTAINER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,127}$")
GUEST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9\-]{0,63}$")
POOL_RE = re.compile(r"^[A-Za-z0-9_\-]{1,40}$")
DISK_RE = re.compile(r"^[A-Za-z0-9_\-]{1,32}$")
SHARE_RE = re.compile(r"^[^\x00-\x1f/\\:*?\"<>|]{1,64}$")
SNAP_RE = re.compile(r"^GMT[+-]\d{1,2}(:?\d{2})?-\d{4}\.\d{2}\.\d{2}-\d{2}\.\d{2}\.\d{2}$")

# DSM's error codes. Common ones apply to every API; the auth ones only to SYNO.API.Auth.
COMMON_ERRORS = {
    100: "unknown error", 101: "a parameter is missing or invalid", 102: "the API doesn't exist on this NAS",
    103: "the method doesn't exist", 104: "this API version isn't supported", 105: "the DSM account lacks permission",
    106: "the session timed out", 107: "the session was interrupted by a duplicate login", 108: "file upload failed",
    114: "a parameter is missing", 117: "the NAS is busy (another request is running)", 119: "the session ID was not found",
    120: "a parameter is invalid", 150: "the request's source IP doesn't match the login IP",
}
AUTH_ERRORS = {
    400: "DSM rejected the account name or password", 401: "the DSM account is disabled", 402: "permission denied",
    403: "this account needs a 2-step verification code. Exempt it from 2FA or add a device token (see docs/synology.md)",
    404: "the 2-step verification code or device token was rejected",
    406: "2-step verification is enforced for this account. Exempt it or add a device token (see docs/synology.md)",
    407: "DSM has blocked the poller's IP address (Auto Block). Unblock it under Control Panel > Security > Protection",
    408: "the account's password has expired", 409: "the account's password has expired", 410: "the account must change its password",
}
SESSION_ERRORS = (106, 107, 119)

# what DSM calls healthy
GOOD = {"normal", "healthy", "ok", "running", "initialized", ""}


@dataclass(frozen=True)
class Action:
    """One thing an admin can do. ``confirm``: None (no prompt), "yes" (an are-you-sure dialog) or "typed" (the admin
    types the NAS's name). ``target`` is the form field that names what it acts on."""
    label: str
    section: str                     # system | packages | containers | vms | backups | storage | shares | security
    confirm: str | None = None
    target: str | None = None
    help: str = ""


ACTIONS: dict[str, Action] = {
    "system_reboot": Action("Reboot NAS", "system", "typed", help="Every share, app, container and VM on the NAS goes down until it is back."),
    "system_shutdown": Action("Shut down NAS", "system", "typed", help="Someone has to power it back on (or use Wake-on-LAN)."),
    "package_start": Action("Start", "packages", target="package"),
    "package_stop": Action("Stop", "packages", "yes", target="package", help="Anything that depends on this package stops working."),
    "container_start": Action("Start", "containers", target="container"),
    "container_stop": Action("Stop", "containers", "yes", target="container"),
    "container_restart": Action("Restart", "containers", "yes", target="container"),
    "vm_poweron": Action("Power on", "vms", target="guest"),
    "vm_shutdown": Action("Shut down", "vms", "yes", target="guest", help="Asks the guest OS to shut down (ACPI)."),
    "vm_poweroff": Action("Force power off", "vms", "yes", target="guest", help="Pulls the plug: unsaved work in the VM is lost."),
    "backup_run": Action("Back up now", "backups", target="task"),
    "backup_cancel": Action("Cancel backup", "backups", "yes", target="task", help="The running backup version is discarded."),
    "scrub_start": Action("Run data scrubbing", "storage", "yes", target="pool",
                          help="Reads every block on the pool; the NAS is slower until it finishes, which can take hours."),
    "scrub_stop": Action("Stop data scrubbing", "storage", "yes", target="pool"),
    "snapshot_create": Action("Take snapshot", "shares", target="share"),
    "snapshot_delete": Action("Delete snapshot", "shares", "yes", target="share", help="Cannot be undone."),
    "security_scan": Action("Run Security Advisor", "security"),
}
READ_OPS = ("disk_smart",)

# one login per NAS and account, shared by the sync and the actions that run in the same poller process
_SESSIONS: dict[tuple, dict[str, Any]] = {}
_LOCK = threading.Lock()


def js(value: Any) -> str:
    return json.dumps(value)


def _match(rx: re.Pattern, v: Any, what: str) -> str:
    s = str(v or "").strip()
    if not rx.match(s):
        raise IntegrationError(f"Invalid {what}: {s[:60]!r}")
    return s


def _int(v: Any, lo: int, hi: int, what: str) -> int:
    try:
        n = int(str(v).strip())
    except (TypeError, ValueError):
        raise IntegrationError(f"{what} must be a number.") from None
    if not lo <= n <= hi:
        raise IntegrationError(f"{what} must be between {lo} and {hi}.")
    return n


def _flag(v: Any) -> bool:
    return str(v).lower() in ("1", "true", "on", "yes")


def _num(v: Any) -> float | None:
    try:
        return None if v is None or v == "" else float(v)
    except (TypeError, ValueError):
        return None


def _uptime(v: Any) -> int | None:
    """DSM reports uptime as seconds or as 'H:M:S' with unbounded hours ('1234:05:06')."""
    if v is None or v == "":
        return None
    if isinstance(v, (int, float)):
        return int(v)
    parts = str(v).strip().split(":")
    try:
        if len(parts) == 3:
            return int(parts[0]) * 3600 + int(parts[1]) * 60 + int(float(parts[2]))
        return int(float(parts[0]))
    except ValueError:
        return None


def _size(d: Any) -> tuple[float | None, float | None]:
    """A DSM size block {"total": "123", "used": "45"} (strings of bytes) -> (used, total)."""
    if not isinstance(d, dict):
        return None, None
    return _num(d.get("used")), _num(d.get("total"))


def _pct(used: float | None, total: float | None) -> float | None:
    return round(100.0 * used / total, 1) if used is not None and total else None


class DsmError(IntegrationError):
    def __init__(self, message: str, code: int | None = None):
        super().__init__(message)
        self.code = code


class Synology(Integration):
    kind = "synology"
    label = "Synology NAS"
    runs_on = "poller"
    description = ("DSM Web API: volumes, pools and disks with SMART, temperatures, UPS, shares and snapshots, packages, "
                   "containers, VMs, Hyper Backup, users, Security Advisor and updates, with reboot, package, container, "
                   "VM, backup, scrub and snapshot controls from the NAS menu. Add it over SNMP too for fans, power and ports.")
    fields = [
        Field("host", "NAS address", help="e.g. 10.10.5.20 or nas.lan. HTTPS on port 5001 is assumed; add :port if you changed it."),
        Field("username", "DSM account", help="A dedicated account in the administrators group. See docs/synology.md."),
        Field("password", "Password", "password"),
        Field("device_token", "2FA device token", "password", required=False,
              help="Only if the account has 2-step verification. Get one with: python -m linkwatch.integrations.synology pair"),
        Field("allow_control", "Allow control actions", "bool", required=False, default=False,
              help="Lets admins reboot or shut down the NAS, start and stop packages, containers and VMs, run and cancel "
                   "backups and scrubbing, and take or delete snapshots. Every action is confirmed and written to the audit log."),
        verify_field(),
    ]

    def __init__(self, config: dict[str, Any], http: httpx.Client | None = None):
        super().__init__(config, http)
        self.unavailable: list[str] = []

    # ------------------------------------------------------------------ HTTP
    @property
    def base(self) -> str:
        return host_url(self.config["host"], 5001)

    @property
    def _key(self) -> tuple:
        secret = hashlib.sha256(f"{self.config.get('password')}\0{self.config.get('device_token') or ''}".encode()).hexdigest()
        return (self.base, str(self.config.get("username")), secret)

    def _request(self, path: str, params: dict[str, Any], post: bool = False) -> Any:
        url = f"{self.base}/webapi/{path}"
        try:
            if post:
                resp = self.http.post(url, data=params)
            else:
                resp = self.http.get(url, params=params)
        except httpx.HTTPError as exc:
            raise IntegrationError(f"Could not reach {httpx.URL(url).host}: {exc.__class__.__name__}") from None
        if resp.status_code >= 400:
            raise IntegrationError(f"DSM answered HTTP {resp.status_code} for {params.get('api')}")
        try:
            body = resp.json()
        except ValueError:
            raise IntegrationError(f"DSM sent something that isn't JSON for {params.get('api')}. Is this a Synology NAS?") from None
        if not isinstance(body, dict):
            raise IntegrationError(f"Unexpected answer from DSM for {params.get('api')}.")
        return body

    def _session(self, fresh: bool = False) -> dict[str, Any]:
        with _LOCK:
            sess = _SESSIONS.get(self._key)
            if sess and not fresh and time.time() - sess["at"] < SESSION_TTL:
                return sess
        sess = self._login()
        with _LOCK:
            _SESSIONS[self._key] = sess
        return sess

    def _apis(self) -> dict[str, dict]:
        body = self._request("query.cgi", {"api": "SYNO.API.Info", "version": 1, "method": "query", "query": "all"})
        data = body.get("data") if body.get("success") else None
        if not isinstance(data, dict) or "SYNO.API.Auth" not in data:
            raise IntegrationError("The address answered but doesn't look like DSM (no SYNO.API.Info).")
        return data

    def _login(self) -> dict[str, Any]:
        apis = self._apis()
        auth = apis["SYNO.API.Auth"]
        version = min(int(auth.get("maxVersion") or 3), 6)
        params: dict[str, Any] = {"api": "SYNO.API.Auth", "version": version, "method": "login",
                                  "account": self.config["username"], "passwd": self.config["password"],
                                  "session": SESSION_NAME, "format": "sid"}
        if self.config.get("device_token"):
            params.update(device_id=str(self.config["device_token"]).strip(), device_name=SESSION_NAME)
        body = self._request(auth.get("path") or "auth.cgi", params, post=True)
        if not body.get("success"):
            code = (body.get("error") or {}).get("code")
            msg = AUTH_ERRORS.get(code) or COMMON_ERRORS.get(code) or f"error {code}"
            raise DsmError(f"DSM login failed: {msg}.", code)
        sid = (body.get("data") or {}).get("sid")
        if not sid:
            raise IntegrationError("DSM login returned no session ID.")
        return {"sid": sid, "apis": apis, "at": time.time()}

    def call(self, api: str, method: str, version: int | None = None, post: bool = False, **params: Any) -> Any:
        """Call one DSM API and return its ``data``. Re-logs in once if DSM says the session is gone."""
        for attempt in (0, 1):
            sess = self._session(fresh=attempt == 1)
            info = sess["apis"].get(api)
            if info is None:
                raise DsmError(f"{api} isn't on this NAS (package not installed or DSM too old)", 102)
            lo, hi = int(info.get("minVersion") or 1), int(info.get("maxVersion") or 1)
            ver = max(lo, min(hi, version or hi))
            q = {"api": api, "version": ver, "method": method, "_sid": sess["sid"]}
            for k, v in params.items():
                if v is None:
                    continue
                q[k] = js(v) if isinstance(v, (dict, list, bool)) else v
            body = self._request(info.get("path") or "entry.cgi", q, post=post)
            if body.get("success"):
                return body.get("data")
            code = (body.get("error") or {}).get("code")
            if code in SESSION_ERRORS and attempt == 0:
                continue
            msg = COMMON_ERRORS.get(code) or f"error {code}"
            if code == 105:
                msg += " (the account must be in the administrators group; see docs/synology.md)"
            raise DsmError(f"{api} {method}: {msg}", code)
        raise IntegrationError("DSM kept dropping the session.")  # pragma: no cover

    def has(self, api: str) -> bool:
        return api in self._session()["apis"]

    def _try(self, what: str, fn: Callable[[], Any], default: Any = None) -> Any:
        try:
            return fn()
        except IntegrationError as exc:
            self.unavailable.append(f"{what}: {exc}")
            return default

    # ------------------------------------------------------------------ inventory
    def collect(self) -> list[Record]:
        self.unavailable = []
        info = self.call("SYNO.Core.System", "info") or {}
        util = self._try("Utilisation", lambda: self.call("SYNO.Core.System.Utilization", "get"), {}) or {}
        storage = self._try("Storage", lambda: self.call("SYNO.Storage.CGI.Storage", "load_info", version=1), {}) or {}
        network = self._try("Network", lambda: self.call("SYNO.Core.System", "info", type="network"), {}) or {}
        disks = [self._disk(d) for d in storage.get("disks") or [] if isinstance(d, dict)]
        pools = [self._pool(p) for p in storage.get("storagePools") or [] if isinstance(p, dict)]
        volumes = [self._volume(v) for v in storage.get("volumes") or [] if isinstance(v, dict)]
        shares = self._optional("Shares", "SYNO.Core.Share", self._shares, [])
        data: dict[str, Any] = {
            "type": "synology", "control": bool(self.config.get("allow_control")),
            "system": self._system(info, network),
            "util": self._util(util),
            "disks": disks, "pools": pools, "volumes": volumes,
            "fan": self._optional("Fans", "SYNO.Core.Hardware.FanSpeed", lambda: self.call("SYNO.Core.Hardware.FanSpeed", "get") or {}, {}),
            "ups": self._optional("UPS", "SYNO.Core.ExternalDevice.UPS", self._ups, None),
            "interfaces": self._optional("Network interfaces", "SYNO.Core.Network.Interface", self._interfaces, []),
            "shares": shares,
            "packages": self._optional("Packages", "SYNO.Core.Package", self._packages, []),
            "containers": self._optional("Containers", "SYNO.Docker.Container", self._containers, None),
            "projects": self._optional("Container projects", "SYNO.Docker.Project", self._projects, None),
            "vms": self._optional("Virtual machines", "SYNO.Virtualization.API.Guest", self._vms, None),
            "backups": self._optional("Hyper Backup", "SYNO.Backup.Task", self._backups, None),
            "connections": self._optional("Connected users", "SYNO.Core.CurrentConnection", self._connections, []),
            "security": self._optional("Security Advisor", "SYNO.Core.SecurityScan.Status", self._security, None),
            "dsm_update": self._optional("DSM update", "SYNO.Core.Upgrade.Server", self._update, None),
        }
        data["problems"] = problems(data)
        data["unavailable"] = self.unavailable
        self.data = data
        s, u = data["system"], data["util"]
        host = str(self.config["host"]).strip()
        ip_literal = re.sub(r"^https?://", "", host).split("/")[0].rsplit(":", 1)[0] if host.count(":") <= 2 else None
        ip = ip_literal if ip_literal and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip_literal) else (s.get("ip") or None)
        vol_used = sum(v["used"] or 0 for v in volumes)
        vol_total = sum(v["total"] or 0 for v in volumes)
        detail = f"{len(volumes)} volume{'s' if len(volumes) != 1 else ''}, {len(disks)} disk{'s' if len(disks) != 1 else ''}"
        if vol_total:
            detail += f", {_pct(vol_used, vol_total)}% used"
        if data["problems"]:
            detail = data["problems"][0] + (f" (+{len(data['problems']) - 1} more)" if len(data["problems"]) > 1 else "")
        name = s.get("hostname") or s.get("model") or host
        return [Record(
            external_id=f"nas-{s.get('serial') or name}", hostname=name, ip=ip, type="NAS",
            platform=f"Synology {s.get('model') or ''} {s.get('version') or ''}".strip(), site=None,
            status="warn" if data["problems"] else "up", cpu=u.get("cpu"), mem=u.get("mem"), uptime_s=s.get("uptime_s"),
            serial=s.get("serial"), detail=detail,
            extra={"model": s.get("model"), "dsm": s.get("version"), "temp_c": s.get("temp_c"), "volumes": len(volumes),
                   "disks": len(disks), "problems": data["problems"][:10]},
        )]

    def _optional(self, what: str, api: str, fn: Callable[[], Any], default: Any) -> Any:
        """Collect a panel whose API may be missing (package not installed): missing is quietly None, failure is listed."""
        try:
            if not self.has(api):
                return default
            return fn()
        except IntegrationError as exc:
            self.unavailable.append(f"{what}: {exc}")
            return default

    # parsers ---------------------------------------------------------------
    @staticmethod
    def _system(info: dict, network: dict) -> dict:
        temp = _num(info.get("sys_temp"))
        return {"model": info.get("model"), "serial": info.get("serial"),
                "version": info.get("firmware_ver") or info.get("version_string"),
                "uptime_s": _uptime(info.get("up_time") if info.get("up_time") is not None else info.get("uptime")),
                "temp_c": temp, "temp_warning": bool(info.get("temperature_warning") or info.get("sys_tempwarn")),
                "ram_mb": _num(info.get("ram_size")), "cpu": " ".join(str(x) for x in (info.get("cpu_vendor"), info.get("cpu_family"),
                                                                                        info.get("cpu_series")) if x) or None,
                "cpu_cores": info.get("cpu_cores"), "cpu_mhz": info.get("cpu_clock_speed"),
                "hostname": network.get("server_name") or info.get("server_name") or info.get("hostname"),
                "ip": next((n.get("ip") for n in network.get("nif") or [] if isinstance(n, dict) and n.get("ip")), None),
                "time": info.get("time"), "timezone": info.get("time_zone_desc") or info.get("time_zone")}

    @staticmethod
    def _util(u: dict) -> dict:
        cpu = u.get("cpu") or {}
        mem = u.get("memory") or {}
        load = [_num(cpu.get(k)) for k in ("user_load", "system_load", "other_load")]
        nets = [n for n in u.get("network") or [] if isinstance(n, dict)]
        total = next((n for n in nets if n.get("device") == "total"), None)
        disk = (u.get("disk") or {}).get("total") or {}
        return {"cpu": round(sum(x or 0 for x in load), 1) if any(x is not None for x in load) else None,
                "load1": _num(cpu.get("1min_load")), "load5": _num(cpu.get("5min_load")), "load15": _num(cpu.get("15min_load")),
                "mem": _num(mem.get("real_usage")),
                "mem_total": (_num(mem.get("total_real")) or 0) * 1024 or None,
                "mem_avail": (_num(mem.get("avail_real")) or 0) * 1024 or None,
                "swap": _num(mem.get("swap_usage")),
                "rx_bps": (_num(total.get("rx")) or 0) * 8 if total else None,
                "tx_bps": (_num(total.get("tx")) or 0) * 8 if total else None,
                "nets": [{"device": n.get("device"), "rx_bps": (_num(n.get("rx")) or 0) * 8, "tx_bps": (_num(n.get("tx")) or 0) * 8}
                         for n in nets if n.get("device") != "total"],
                "disk_read": _num(disk.get("read_byte")), "disk_write": _num(disk.get("write_byte")),
                "disk_util": _num(disk.get("utilization"))}

    @staticmethod
    def _disk(d: dict) -> dict:
        life = d.get("remain_life")
        if isinstance(life, dict):
            life = life.get("value")
        life = _num(life)
        return {"id": d.get("id"), "name": d.get("longName") or d.get("name") or d.get("id"), "model": str(d.get("model") or "").strip(),
                "vendor": str(d.get("vendor") or "").strip(), "serial": d.get("serial"), "firmware": d.get("firm"),
                "size": _num(d.get("size_total")), "type": d.get("diskType"), "ssd": bool(d.get("isSsd")),
                "status": d.get("overview_status") or d.get("status"), "smart": d.get("smart_status"),
                "temp_c": _num(d.get("temp")), "bad_sectors": _num(d.get("unc")),
                "life_pct": life if life is not None and life >= 0 else None,
                "used_by": d.get("used_by"), "slot": d.get("slot_id"),
                "enclosure": (d.get("container") or {}).get("str") if isinstance(d.get("container"), dict) else None,
                "warnings": [k for k in ("below_remain_life_thr", "exceed_bad_sector_thr", "sb_days_left_below_show_thres")
                             if d.get(k)]}

    @staticmethod
    def _pool(p: dict) -> dict:
        used, total = _size(p.get("size"))
        scrub = p.get("scrubbingStatus") or p.get("data_scrubbing") or {}
        progress = p.get("progress") if isinstance(p.get("progress"), dict) else {}
        scrubbing = bool(p.get("is_scrubbing") or (isinstance(scrub, dict) and scrub.get("status") == "running")
                         or "scrub" in str(progress.get("step") or "").lower())
        return {"id": p.get("id"), "num": p.get("num_id"), "name": p.get("desc") or f"Storage Pool {p.get('num_id') or p.get('id')}",
                "status": p.get("status"), "raid": p.get("device_type") or p.get("raidType"), "used": used, "total": total,
                "pct": _pct(used, total), "disks": [str(x) for x in p.get("disks") or []],
                "scrubbing": scrubbing, "progress": _num(progress.get("percent")),
                "last_scrub": (scrub.get("last_time") or scrub.get("last_scrub_time")) if isinstance(scrub, dict) else None}

    @staticmethod
    def _volume(v: dict) -> dict:
        used, total = _size(v.get("size"))
        return {"id": v.get("id"), "path": v.get("vol_path"), "name": v.get("display_name") or v.get("vol_path") or v.get("id"),
                "status": v.get("status"), "fs": v.get("fs_type"), "pool": v.get("pool_path"), "used": used, "total": total,
                "pct": _pct(used, total), "desc": v.get("description") or ""}

    def _ups(self) -> dict | None:
        u = self.call("SYNO.Core.ExternalDevice.UPS", "get") or {}
        if not u.get("enable") and not u.get("usb_ups_connect"):
            return {"enabled": False}
        status = str(u.get("status") or "")
        return {"enabled": True, "model": u.get("model"), "status": status.replace("usb_ups_status_", "").replace("_", " ") or None,
                "on_battery": "battery" in status or "OB" in status.split(), "charge": _num(u.get("charge")),
                "runtime_s": _num(u.get("runtime")), "mode": u.get("mode"), "manufacturer": u.get("manufacture") or u.get("manufacturer")}

    def _interfaces(self) -> list[dict]:
        rows = self.call("SYNO.Core.Network.Interface", "list") or []
        return [{"name": n.get("ifname"), "ip": n.get("ip"), "mask": n.get("mask"), "speed": n.get("speed"), "status": n.get("status"),
                 "type": n.get("type"), "dhcp": bool(n.get("use_dhcp"))} for n in rows if isinstance(n, dict)]

    def _shares(self) -> list[dict]:
        rows = (self.call("SYNO.Core.Share", "list", additional=["hidden", "encryption", "vol_path", "share_quota", "share_quota_used",
                                                                  "enable_recycle_bin", "support_snapshot", "enable_share_compress"])
                or {}).get("shares") or []
        out = []
        for s in rows:
            if not isinstance(s, dict):
                continue
            out.append({"name": s.get("name"), "path": s.get("vol_path"), "desc": s.get("desc") or "",
                        "encrypted": bool(s.get("encryption")), "hidden": bool(s.get("hidden")),
                        "recycle_bin": bool(s.get("enable_recycle_bin")), "snapshots_supported": bool(s.get("support_snapshot")),
                        "quota_mb": _num(s.get("share_quota")), "used_mb": _num(s.get("share_quota_used")),
                        "snapshots": None, "snapshot_count": None})
        if self.has("SYNO.Core.Share.Snapshot"):
            for s in [s for s in out if s["snapshots_supported"]][:40]:
                snaps = self._try(f"Snapshots of {s['name']}", lambda s=s: self.call(
                    "SYNO.Core.Share.Snapshot", "list", name=js(s["name"]), additional=["desc", "lock", "schedule_snapshot"]), None)
                if isinstance(snaps, dict):
                    rows_ = [x for x in snaps.get("snapshots") or [] if isinstance(x, dict)]
                    rows_.sort(key=lambda x: str(x.get("time") or ""), reverse=True)
                    s["snapshot_count"] = snaps.get("total", len(rows_))
                    s["snapshots"] = [{"time": x.get("time"), "desc": x.get("desc") or "", "locked": bool(x.get("lock")),
                                       "scheduled": bool(x.get("schedule_snapshot"))} for x in rows_[:25]]
        return out

    def _packages(self) -> list[dict]:
        rows = (self.call("SYNO.Core.Package", "list", additional=["status", "startable", "description"]) or {}).get("packages") or []
        out = []
        for p in rows:
            if not isinstance(p, dict):
                continue
            add = p.get("additional") or {}
            status = add.get("status") or p.get("status") or ""
            out.append({"id": p.get("id"), "name": p.get("name") or p.get("id"), "version": p.get("version"),
                        "status": {"start": "running", "stop": "stopped", "": "unknown"}.get(status, status),
                        "startable": add.get("startable", True) is not False})
        return sorted(out, key=lambda p: str(p["name"]).lower())

    def _containers(self) -> list[dict]:
        rows = (self.call("SYNO.Docker.Container", "list", limit=-1, offset=0, type=js("all")) or {}).get("containers") or []
        usage: dict[str, dict] = {}
        if self.has("SYNO.Docker.Container.Resource"):
            res = self._try("Container CPU and memory", lambda: self.call("SYNO.Docker.Container.Resource", "get"), {}) or {}
            usage = {r.get("name"): r for r in res.get("resources") or [] if isinstance(r, dict)}
        out = []
        for c in rows:
            if not isinstance(c, dict):
                continue
            state = c.get("State") if isinstance(c.get("State"), dict) else {}
            status = str(c.get("status") or state.get("Status") or "").lower()
            u = usage.get(c.get("name")) or {}
            out.append({"name": c.get("name"), "image": c.get("image"), "status": status or "unknown",
                        "running": status == "running" or bool(state.get("Running")),
                        "started": state.get("StartedAt"), "up_s": _num(c.get("up_time")),
                        "cpu": _num(u.get("cpu")), "mem": _num(u.get("memory")), "mem_pct": _num(u.get("memoryPercent")),
                        "project": (c.get("labels") or {}).get("com.docker.compose.project") if isinstance(c.get("labels"), dict) else None,
                        "package": bool(c.get("is_package"))})
        return sorted(out, key=lambda c: str(c["name"]).lower())

    def _projects(self) -> list[dict]:
        data = self.call("SYNO.Docker.Project", "list") or {}
        rows = data.values() if isinstance(data, dict) else data
        return sorted(({"id": p.get("id"), "name": p.get("name"), "status": str(p.get("status") or "").lower(),
                        "path": p.get("path"), "containers": len(p.get("containerIds") or [])}
                       for p in rows if isinstance(p, dict)), key=lambda p: str(p["name"]).lower())

    def _vms(self) -> list[dict]:
        rows = (self.call("SYNO.Virtualization.API.Guest", "list") or {}).get("guests") or []
        return sorted(({"id": g.get("guest_id"), "name": g.get("guest_name"), "status": g.get("status"),
                        "running": g.get("status") == "running", "vcpu": g.get("vcpu_num"), "ram_mb": _num(g.get("vram_size")),
                        "autorun": g.get("autorun"), "desc": g.get("desc") or "", "storage": g.get("storage_name"),
                        "disks": len(g.get("vdisks") or []), "nics": len(g.get("vnics") or [])}
                       for g in rows if isinstance(g, dict)), key=lambda g: str(g["name"]).lower())

    def _backups(self) -> list[dict]:
        rows = (self.call("SYNO.Backup.Task", "list", additional=["last_bkp_time", "next_bkp_time", "last_bkp_result",
                                                                    "last_bkp_progress", "last_bkp_success_time", "is_modified"])
                or {}).get("task_list") or []
        out = []
        for t in rows:
            if not isinstance(t, dict):
                continue
            last = t.get("last_bkp_result") or ""
            prog = t.get("last_bkp_progress") if isinstance(t.get("last_bkp_progress"), dict) else {}
            status = str(t.get("status") or "")
            running = status in ("backup", "backing_up", "detect", "waiting", "preparing", "version_deleting") or status.startswith("backup")
            out.append({"id": t.get("task_id"), "name": t.get("name"), "state": t.get("state"), "status": status, "running": running,
                        "progress": _num(prog.get("percent")) if running else None, "target": t.get("target_type") or t.get("type"),
                        "last_time": t.get("last_bkp_time"), "last_result": last, "last_success": t.get("last_bkp_success_time"),
                        "next_time": t.get("next_bkp_time"), "ok": last in ("done", "success", "")})
        return out

    def _connections(self) -> list[dict]:
        rows = (self.call("SYNO.Core.CurrentConnection", "list", offset=0, limit=200, sort_by=js("time"), sort_direction=js("DESC"))
                or {}).get("items") or []
        return [{"user": c.get("who"), "type": c.get("type"), "from": c.get("from"), "time": c.get("time"), "what": c.get("descr")}
                for c in rows if isinstance(c, dict)]

    def _security(self) -> dict:
        s = self.call("SYNO.Core.SecurityScan.Status", "system_get") or {}
        cats = []
        for k, v in (s.get("items") or {}).items() if isinstance(s.get("items"), dict) else []:
            if not isinstance(v, dict):
                continue
            fail = v.get("fail") if isinstance(v.get("fail"), dict) else {}
            cats.append({"name": k, "severity": v.get("failSeverity") or "safe",
                         "danger": int(_num(fail.get("danger")) or 0), "warning": int(_num(fail.get("warning")) or 0),
                         "risk": int(_num(fail.get("risk")) or 0), "outdated": int(_num(fail.get("outOfDate")) or 0)})
        return {"status": s.get("sysStatus"), "progress": _num(s.get("sysProgress")), "last_scan": s.get("lastScanTime"),
                "categories": sorted(cats, key=lambda c: c["name"])}

    def _update(self) -> dict:
        u = self.call("SYNO.Core.Upgrade.Server", "check") or {}
        upd = u.get("update") if isinstance(u.get("update"), dict) else u
        return {"available": bool(upd.get("available")), "version": upd.get("version"),
                "reboot": upd.get("reboot") not in (None, "none", False), "type": upd.get("type")}

    # ------------------------------------------------------------------ on-demand requests
    def action(self, name: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Run one read-only lookup or control action. Raises IntegrationError with a message for the admin."""
        p = dict(params or {})
        if name in READ_OPS:
            return getattr(self, f"op_{name}")(p)
        act = ACTIONS.get(name)
        if act is None:
            raise IntegrationError(f"Unknown Synology action {name!r}.")
        if not self.config.get("allow_control"):
            raise IntegrationError("Control actions are turned off for this integration. An admin can tick "
                                   "“Allow control actions” in its settings.")
        return getattr(self, f"op_{name}")(p)

    @staticmethod
    def _done(message: str) -> dict[str, Any]:
        return {"message": message}

    def op_system_reboot(self, p):
        self.call("SYNO.Core.System", "reboot", version=1, post=True, force=False, local=True)
        return self._done("The NAS is rebooting.")

    def op_system_shutdown(self, p):
        self.call("SYNO.Core.System", "shutdown", version=1, post=True, force=False, local=True)
        return self._done("The NAS is shutting down.")

    def op_package_start(self, p):
        pkg = _match(PKG_RE, p.get("package"), "package")
        self.call("SYNO.Core.Package.Control", "start", version=1, post=True, id=js(pkg))
        return self._done(f"Starting {pkg}.")

    def op_package_stop(self, p):
        pkg = _match(PKG_RE, p.get("package"), "package")
        self.call("SYNO.Core.Package.Control", "stop", version=1, post=True, id=js(pkg))
        return self._done(f"Stopping {pkg}.")

    def _container(self, verb: str, p: dict) -> dict:
        name = _match(CONTAINER_RE, p.get("container"), "container name")
        self.call("SYNO.Docker.Container", verb, version=1, post=True, name=js(name))
        return self._done(f"{verb.capitalize()} sent to container {name}.")

    def op_container_start(self, p):
        return self._container("start", p)

    def op_container_stop(self, p):
        return self._container("stop", p)

    def op_container_restart(self, p):
        return self._container("restart", p)

    def _vm(self, verb: str, p: dict, message: str) -> dict:
        gid = _match(GUEST_RE, p.get("guest"), "VM ID")
        self.call("SYNO.Virtualization.API.Guest.Action", verb, version=1, post=True, guest_id=gid)
        return self._done(message)

    def op_vm_poweron(self, p):
        return self._vm("poweron", p, "Powering on the VM.")

    def op_vm_shutdown(self, p):
        return self._vm("shutdown", p, "Asked the VM to shut down.")

    def op_vm_poweroff(self, p):
        return self._vm("poweroff", p, "Powered off the VM.")

    def op_backup_run(self, p):
        tid = _int(p.get("task"), 0, 10_000_000, "Backup task ID")
        self.call("SYNO.Backup.Task", "backup", version=1, post=True, task_id=tid)
        return self._done(f"Backup task {tid} started.")

    def op_backup_cancel(self, p):
        tid = _int(p.get("task"), 0, 10_000_000, "Backup task ID")
        self.call("SYNO.Backup.Task", "cancel", version=1, post=True, task_id=[tid])
        return self._done(f"Cancelling backup task {tid}.")

    def op_scrub_start(self, p):
        pool = _match(POOL_RE, p.get("pool"), "storage pool")
        self.call("SYNO.Storage.CGI.Pool", "data_scrubbing", version=1, post=True, pool_path=js(pool))
        return self._done(f"Data scrubbing started on {pool}.")

    def op_scrub_stop(self, p):
        pool = _match(POOL_RE, p.get("pool"), "storage pool")
        self.call("SYNO.Storage.CGI.Pool", "cancel_data_scrubbing", version=1, post=True, pool_path=js(pool))
        return self._done(f"Data scrubbing stopped on {pool}.")

    def op_snapshot_create(self, p):
        share = _match(SHARE_RE, p.get("share"), "shared folder")
        info = {"desc": str(p.get("description") or "Taken from Linkwatch")[:255], "lock": _flag(p.get("lock"))}
        out = self.call("SYNO.Core.Share.Snapshot", "create", version=1, post=True, name=js(share), snapinfo=info)
        return self._done(f"Snapshot of {share} taken" + (f" ({out})." if isinstance(out, str) else "."))

    def op_snapshot_delete(self, p):
        share = _match(SHARE_RE, p.get("share"), "shared folder")
        snap = _match(SNAP_RE, p.get("snapshot"), "snapshot")
        self.call("SYNO.Core.Share.Snapshot", "delete", version=1, post=True, name=js(share), snapshots=[snap])
        return self._done(f"Deleted snapshot {snap} of {share}.")

    def op_security_scan(self, p):
        self.call("SYNO.Core.SecurityScan.Operation", "start", version=1, post=True, items=js("ALL"), notify=False)
        return self._done("Security Advisor scan started. Results show after the next sync once it finishes.")

    def op_disk_smart(self, p):
        disk = _match(DISK_RE, p.get("disk"), "disk")
        out = self.call("SYNO.Storage.CGI.Smart", "get_smart_info", version=1, device=js(f"/dev/{disk}")) or {}
        rows = out.get("smart_info") or out.get("smartInfo") or out.get("attributes") or []
        attrs = [{"id": a.get("id"), "name": a.get("name"), "current": a.get("current"), "worst": a.get("worst"),
                  "threshold": a.get("threshold"), "raw": a.get("raw"), "status": a.get("status")}
                 for a in rows if isinstance(a, dict)]
        return {"disk": disk, "health": out.get("healthInfo") or out.get("overview") or out.get("health"), "attributes": attrs[:80]}


def problems(d: dict[str, Any]) -> list[str]:
    """Plain-language list of what needs attention, worst first. Drives the device's warn state and the overview banner."""
    out: list[str] = []
    for v in d.get("volumes") or []:
        if str(v.get("status") or "").lower() not in GOOD:
            out.append(f"{v.get('name') or v.get('id')} is {v.get('status')}")
    for p in d.get("pools") or []:
        if str(p.get("status") or "").lower() not in GOOD:
            out.append(f"{p.get('name')} is {p.get('status')}")
    for x in d.get("disks") or []:
        st = str(x.get("status") or "").lower()
        smart = str(x.get("smart") or "").lower()
        if st not in GOOD and st not in ("not_use", "notuse", "not_initialized", "uninitialized", "unknown"):
            out.append(f"{x.get('name')} is {x.get('status')}")
        elif smart not in GOOD and smart not in ("unknown", "not_support", "none"):
            out.append(f"{x.get('name')} SMART: {x.get('smart')}")
        elif x.get("warnings"):
            out.append(f"{x.get('name')}: " + ", ".join(w.replace("_", " ") for w in x["warnings"]))
    for v in d.get("volumes") or []:
        if v.get("pct") is not None and v["pct"] >= 90:
            out.append(f"{v.get('name')} is {v['pct']:.0f}% full")
    s = d.get("system") or {}
    if s.get("temp_warning"):
        out.append(f"System temperature warning ({s.get('temp_c')} °C)")
    ups = d.get("ups") or {}
    if ups.get("on_battery"):
        out.append("Running on UPS battery" + (f" ({ups['charge']:.0f}%)" if ups.get("charge") is not None else ""))
    for b in d.get("backups") or []:
        if not b.get("ok"):
            out.append(f"Backup {b.get('name')} last result: {b.get('last_result')}")
    sec = d.get("security") or {}
    if str(sec.get("status") or "").lower() in ("danger", "risk"):
        out.append(f"Security Advisor: {sec.get('status')}")
    return out


def expected_confirm(d: dict[str, Any] | None, fallback: str) -> str:
    """What an admin types to confirm a NAS-wide action: the NAS's DSM server name."""
    s = (d or {}).get("system") or {}
    return str(s.get("hostname") or fallback)


def pair(argv: list[str] | None = None) -> None:  # pragma: no cover - interactive helper
    """Log in once with a 2-step verification code and print a device token for the integration's settings.

    python -m linkwatch.integrations.synology pair https://nas.lan:5001 linkwatch
    """
    import getpass
    import sys
    args = list(sys.argv[1:] if argv is None else argv)
    if args[:1] == ["pair"]:
        args = args[1:]
    if len(args) < 2:
        raise SystemExit("Usage: python -m linkwatch.integrations.synology pair <nas address> <account> [--insecure]")
    insecure = "--insecure" in args
    host, user = [a for a in args if a != "--insecure"][:2]
    pw = getpass.getpass(f"Password for {user}: ")
    otp = input("6-digit code from the authenticator app: ").strip()
    base = host_url(host, 5001)
    with httpx.Client(verify=not insecure, timeout=30) as c:
        apis = c.get(f"{base}/webapi/query.cgi", params={"api": "SYNO.API.Info", "version": 1, "method": "query",
                                                          "query": "SYNO.API.Auth"}).json()["data"]
        auth = apis["SYNO.API.Auth"]
        body = c.post(f"{base}/webapi/{auth['path']}", data={
            "api": "SYNO.API.Auth", "version": min(int(auth["maxVersion"]), 6), "method": "login", "account": user, "passwd": pw,
            "otp_code": otp, "enable_device_token": "yes", "device_name": SESSION_NAME, "session": SESSION_NAME, "format": "sid"}).json()
    if not body.get("success"):
        code = (body.get("error") or {}).get("code")
        raise SystemExit(f"Login failed: {AUTH_ERRORS.get(code) or COMMON_ERRORS.get(code) or code}")
    did = (body.get("data") or {}).get("did") or (body.get("data") or {}).get("device_id")
    if not did:
        raise SystemExit("DSM did not return a device token. Is 2-step verification on for this account?")
    print("Device token (paste it into the integration's “2FA device token” field):")
    print(did)


if __name__ == "__main__":  # pragma: no cover
    pair()
