"""Zscaler Endpoint AI Security (formerly SquareX), over its public API v1.

The console lives at ``https://console.<domain>``, where the domain is ``zsai.sqrx.io`` or ``endpoint-ai.zscaler.com``.
An admin creates an API credential under Administration > API Access (client ID and secret, a role and an expiry).
VisCon1 swaps it for a short-lived bearer token at ``https://id.<domain>/v1/auth/token`` (OAuth2 client
credentials) and calls the tenant's regional host ``https://<region>.api.<domain>/api/v1/...``. The region (use2,
usw2, euc1, apse1, ...) is shown on the API Access page.

Paths, fields and behaviour follow the tenant's own OpenAPI document (``/api/v1/openapi.yaml``, API v1.0.0).
Lists are ``{"items": [...], "next_cursor": ...}`` paged with ``limit`` and ``cursor``. Errors are
``{"error", "message", "detail", "request_id"}``. Analytics calls allow two at a time per tenant, so they run one
after another here. Within v1 Zscaler only adds fields and enum values, so everything is parsed permissively.

What the integration shows: the device fleet and its health, AI activity for the last 24 hours (events, users,
severities and the latest high-severity events), AI assistants, MCP servers, local models and AI browser
extensions, policies, setting profiles, enrollment tokens, managed users and the audit log.

What admins can change, once *Allow control actions* is ticked (each one confirmed and audited by the server):
revoke or delete a device, bind or unbind its user, turn automatic identity on or off; create, extend or revoke
enrollment tokens; create, edit, enable or disable, retarget and delete policies (with a validation dry run); enable,
disable or edit setting profiles; turn managed users' sign-in off or on.
"""
from __future__ import annotations

import json
import re
import time
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import quote

import httpx

from .base import Field, Integration, IntegrationError, Record

DOMAINS = ("zsai.sqrx.io", "endpoint-ai.zscaler.com")
REGION_RE = re.compile(r"^[a-z]{2,6}\d{0,2}$")
DEVICE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_\-.:]{0,127}$")
INT_ID_RE = re.compile(r"^\d{1,18}$")
EMAIL_RE = re.compile(r"^[^@\s/\\?#]{1,128}@[^@\s/\\?#]{1,190}$")
MAX_JSON = 256 * 1024
MAX_DEVICES = 5000
# Fields of a policy or setting profile the editor may send back; everything else the API manages itself.
POLICY_FIELDS = ("name", "enabled", "priority", "os_platforms", "rules", "change_note")
POLICY_CREATE_FIELDS = POLICY_FIELDS + ("assignments",)
PROFILE_FIELDS = ("name", "enabled", "priority", "os_platforms", "settings", "change_note")
ASSIGN_FIELDS = ("tenant_wide", "users", "groups", "device_groups", "exclusions", "change_note")
SEVERE = ("high", "critical")


@dataclass(frozen=True)
class Action:
    """One thing an admin can do. ``confirm`` is None, "yes" or "typed" (the object's name typed)."""
    label: str
    scope: str                       # device | token | policy | profile | user
    confirm: str | None = None
    help: str = ""


ACTIONS: dict[str, Action] = {
    "device_revoke": Action("Revoke device", "device", "typed",
                            help="Its next check-in is refused. A managed agent re-enrolls by itself within about an hour "
                                 "while its fleet token is valid, so revoke that token too to keep it out."),
    "device_delete": Action("Delete device", "device", "typed",
                            help="Revokes the device and removes it from the fleet. Its events stay. It reappears if it enrolls again."),
    "device_auto_identity": Action("Change automatic identity", "device", "yes",
                                   help="Automatic identity lets the device report who is using it."),
    "device_bind_user": Action("Bind user to device", "device", "yes",
                               help="Outranks every identity the device reports and turns automatic identity off."),
    "device_unbind_user": Action("Unbind user from device", "device", "yes", help="The device keeps its credential."),
    "token_create": Action("Create enrollment token", "token", help="The secret is shown once."),
    "token_extend": Action("Extend enrollment token", "token", "yes", help="Adds days to the later of now and its expiry."),
    "token_revoke": Action("Revoke enrollment token", "token", "typed",
                           help="Permanent. Devices it already enrolled are unaffected."),
    "policy_create": Action("Create policy", "policy", help="Devices pick it up on their next configuration check."),
    "policy_update": Action("Save policy", "policy", "yes", help="Devices pick the change up on their next configuration check."),
    "policy_enable": Action("Enable policy", "policy", "yes", help="Devices start enforcing it on their next configuration check."),
    "policy_disable": Action("Disable policy", "policy", "yes", help="Devices stop enforcing it on their next configuration check."),
    "policy_assign": Action("Change who the policy applies to", "policy", "yes", help="Replaces its targeting, exclusions included."),
    "policy_delete": Action("Delete policy", "policy", "typed", help="Removes the policy and its assignments. Its history stays readable."),
    "profile_update": Action("Save setting profile", "profile", "yes", help="Devices pick the change up on their next configuration check."),
    "profile_enable": Action("Enable setting profile", "profile", "yes"),
    "profile_disable": Action("Disable setting profile", "profile", "yes"),
    "user_disable": Action("Turn off sign-in", "user", "yes",
                           help="New sign-ins are refused; open sessions are not ended."),
    "user_enable": Action("Turn sign-in back on", "user", "yes"),
}
READ_OPS = ("policy_get", "policy_validate", "profile_get", "device_get")


def _match(rx: re.Pattern, v: Any, what: str) -> str:
    s = str(v if v is not None else "").strip()
    if not rx.match(s):
        raise IntegrationError(f"Invalid {what}: {s[:60]!r}")
    return s


def _flag(v: Any) -> bool:
    return str(v).strip().lower() in ("1", "true", "on", "yes")


def _int(v: Any, lo: int, hi: int, what: str) -> int:
    try:
        n = int(str(v).strip())
    except (TypeError, ValueError):
        raise IntegrationError(f"{what} must be a number.") from None
    if not lo <= n <= hi:
        raise IntegrationError(f"{what} must be between {lo} and {hi}.")
    return n


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _counts(rows: Any) -> list[tuple[str, int]]:
    out = []
    for r in rows or []:
        if isinstance(r, dict):
            key = r.get("value") or r.get("band") or r.get("severity") or r.get("name")
            out.append((str(key or "unknown"), int(r.get("count") or 0)))
    return out


class EndpointAI(Integration):
    kind = "zsai"
    label = "Zscaler Endpoint AI Security"
    runs_on = "server"
    description = ("Endpoint AI Security (formerly SquareX) API v1: devices, AI activity, AI assistants, MCP servers, local "
                   "models and extensions, policies and enrollment tokens, with optional control.")
    fields = [
        Field("domain", "Console domain", required=False, default="zsai.sqrx.io",
              help="zsai.sqrx.io or endpoint-ai.zscaler.com: the domain in your console's address."),
        Field("region", "Region", default="use2",
              help="Shown on Administration > API Access, e.g. use2, usw2, euc1 or apse1."),
        Field("client_id", "API client ID", help="Create a credential under Administration > API Access."),
        Field("client_secret", "API client secret", "password",
              help="A read-only role is enough to monitor. Control actions need a role that can write."),
        Field("allow_control", "Allow control actions", "bool", required=False, default=False,
              help="Lets admins revoke and delete devices, manage enrollment tokens, change policies and setting profiles, "
                   "and turn managed users' sign-in off. Every action is confirmed and written to the audit log. "
                   "See docs/zscaler-endpoint-ai.md."),
    ]

    def __init__(self, config: dict[str, Any], http: httpx.Client | None = None):
        super().__init__(config, http)
        domain = str(config.get("domain") or DOMAINS[0]).strip().lower().removeprefix("console.").removeprefix("https://").rstrip("/")
        domain = domain.removeprefix("console.")
        if domain not in DOMAINS:
            raise IntegrationError(f"Console domain must be one of {', '.join(DOMAINS)}.")
        region = str(config.get("region") or "").strip().lower()
        if not REGION_RE.match(region):
            raise IntegrationError("Region must look like use2, usw2, euc1 or apse1.")
        self.domain, self.region = domain, region
        self.base = f"https://{region}.api.{domain}"
        self.token_url = f"https://id.{domain}/v1/auth/token"
        self._token: str | None = None
        self._token_exp = 0.0
        self.errors: list[str] = []
        self.data: dict[str, Any] = {"type": "zsai", "products": {}, "unavailable": []}

    # ------------------------------------------------------------------ HTTP
    def _headers(self) -> dict[str, str]:
        if not self._token or time.time() > self._token_exp - 60:
            try:
                resp = self.http.post(self.token_url, data={"grant_type": "client_credentials",
                                                            "client_id": self.config["client_id"],
                                                            "client_secret": self.config["client_secret"]},
                                      headers={"Accept": "application/json"})
            except httpx.HTTPError as exc:
                raise IntegrationError(f"Could not reach id.{self.domain}: {exc.__class__.__name__}") from exc
            if resp.status_code != 200:
                raise IntegrationError(f"The token request failed with HTTP {resp.status_code}{self._why(resp)}. "
                                       "Check the domain, client ID and secret, and that the credential hasn't expired.")
            body = resp.json()
            self._token = body["access_token"]
            self._token_exp = time.time() + int(body.get("expires_in") or 900)
        return {"Authorization": f"Bearer {self._token}", "Accept": "application/json"}

    @staticmethod
    def _why(resp: httpx.Response) -> str:
        try:
            body = resp.json()
        except ValueError:
            return ""
        if not isinstance(body, dict):
            return ""
        msg = body.get("message") or body.get("error_description") or body.get("error")
        errs = ((body.get("detail") or {}).get("errors") if isinstance(body.get("detail"), dict) else None) or []
        extra = "; ".join(str(e.get("message") if isinstance(e, dict) else e) for e in errs[:5])
        text = ": ".join(x for x in (str(msg or "").strip(), extra) if x)
        return f" ({text[:400]})" if text else ""

    def call(self, method: str, path: str, params: dict | None = None, body: Any = None,
             if_match: str | None = None) -> tuple[Any, httpx.Headers]:
        url = self.base + path
        reauthed = False
        for attempt in range(5):
            headers = self._headers()
            if if_match:
                headers["If-Match"] = if_match
            try:
                resp = self.http.request(method, url, params=params, json=body, headers=headers)
            except httpx.HTTPError as exc:
                raise IntegrationError(f"Could not reach {self.base}: {exc.__class__.__name__}") from exc
            if resp.status_code == 429 and attempt < 4:
                try:
                    wait = float(resp.headers.get("Retry-After", 2 ** attempt))
                except ValueError:
                    wait = 2.0
                self._sleep(min(max(wait, 0.5), 30))
                continue
            if resp.status_code == 401 and not reauthed:
                self._token, reauthed = None, True
                continue
            if resp.status_code == 403:
                raise IntegrationError(f"{method} {path} was refused (HTTP 403){self._why(resp)}. The credential's role doesn't allow it.")
            if resp.status_code == 412:
                raise IntegrationError("Someone changed it since this page loaded. Reload and try again.")
            if resp.status_code >= 400:
                raise IntegrationError(f"{method} {path} returned HTTP {resp.status_code}{self._why(resp)}")
            return (resp.json() if resp.content else None), resp.headers
        raise IntegrationError(f"{method} {path} kept returning HTTP 429")

    def get(self, path: str, params: dict | None = None) -> Any:
        return self.call("GET", path, params=params)[0]

    def paged(self, path: str, params: dict | None = None, cap: int = 1000) -> list[dict]:
        items: list[dict] = []
        seen: set = set()
        cursor = None
        while len(items) < cap:
            q = {**(params or {}), "limit": min(200, cap - len(items))}
            if cursor:
                q["cursor"] = cursor
            body = self.get(path, q) or {}
            for it in body.get("items") or []:
                key = it.get("id") if isinstance(it, dict) else None
                if key is not None and key in seen:
                    continue
                seen.add(key)
                items.append(it)
            cursor = body.get("next_cursor")
            if not cursor or not body.get("items"):
                break
        return items

    @staticmethod
    def _sleep(seconds: float) -> None:
        time.sleep(seconds)

    def _optional(self, label: str, fn):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - one missing panel isn't a failed sync
            self.data["unavailable"].append(f"{label}: {exc}")
            return None

    # ------------------------------------------------------------------ collection
    def collect(self) -> list[Record]:
        self.errors = []
        self.data = {"type": "zsai", "products": {}, "unavailable": [], "control": bool(self.config.get("allow_control")),
                     "domain": self.domain, "region": self.region, "console": f"https://console.{self.domain}"}
        stats = self.get("/api/v1/devices/stats") or {}     # the one call that must work: proves the credential
        now = datetime.now(timezone.utc)
        day = {"since": _iso(now - timedelta(hours=24)), "until": _iso(now)}
        week = {"since": _iso(now - timedelta(days=7)), "until": _iso(now)}

        devices = self._optional("Devices", lambda: self.paged("/api/v1/devices", {"status": "active,revoked"}, MAX_DEVICES)) or []
        self.data["fleet"] = {"total": stats.get("total"), "active": stats.get("active"), "online": stats.get("online"),
                              "new_this_week": stats.get("new_this_week"), "health": _counts(stats.get("health")),
                              "os": _counts(stats.get("os"))[:10], "agent_version": _counts(stats.get("agent_version"))[:10],
                              "agent_mode": _counts(stats.get("agent_mode"))}
        self.data["devices"] = [{
            "id": d.get("id"), "hostname": d.get("hostname"), "os": d.get("os"), "arch": d.get("arch"), "status": d.get("status"),
            "agent_version": d.get("agent_version"), "agent_mode": d.get("agent_mode"), "serial": d.get("serial_number"),
            "last_seen": d.get("last_seen_at"), "enrolled": d.get("enrolled_at"), "lab": bool(d.get("lab")),
            "users": [str(u.get("email") if isinstance(u, dict) else u) for u in d.get("users") or []][:5],
            "zcc": bool(d.get("zscaler_client_connector")), "monitoring_off_until": d.get("monitoring_off_until"),
            "full_disk_access": d.get("full_disk_access")} for d in devices if isinstance(d, dict)]
        self.data["products"]["devices"] = {"ok": True, "objects": len(self.data["devices"])}

        # AI activity. Analytics calls allow two at a time per tenant: run them one after another.
        summary = self._optional("Activity summary", lambda: self.get("/api/v1/events/summary", day))
        sev = self._optional("Events by severity", lambda: self.get("/api/v1/events/severities", day))
        severe = self._optional("High-severity events", lambda: (self.get("/api/v1/events", {**day, "pattern_severity": ",".join(SEVERE),
                                                                                              "limit": 50}) or {}).get("items") or [])
        blocked = self._optional("Blocked events", lambda: (self.get("/api/v1/events", {**day, "verdict": "block", "limit": 50}) or {}).get("items") or [])
        if summary is not None or sev is not None or severe is not None:
            self.data["activity"] = {"window_hours": 24, "summary": summary or {}, "severities": _counts((sev or {}).get("bands")),
                                     "total": (sev or {}).get("total"),
                                     "severe": [self._event_row(e) for e in severe or []],
                                     "blocked": [self._event_row(e) for e in blocked or []]}
            self.data["products"]["activity"] = {"ok": True, "objects": len(severe or [])}

        assistants = self._optional("AI assistants", lambda: self.paged("/api/v1/ai-assistants", week, 500))
        mcp = self._optional("MCP servers", lambda: self.paged("/api/v1/ai-assistants/mcp-servers", week, 500))
        models = self._optional("Local AI models", lambda: self.paged("/api/v1/ai-models", week, 500))
        exts = self._optional("AI browser extensions", lambda: self.paged("/api/v1/browser-extensions", {**week, "ai": "true"}, 500))
        if any(x is not None for x in (assistants, mcp, models, exts)):
            fw = Counter(str(a.get("framework") or "unknown") for a in assistants or [])
            self.data["ai"] = {
                "assistants": [{"framework": a.get("framework"), "user": a.get("email") or a.get("os_username"), "host": a.get("hostname"),
                                "environment": a.get("environment_name") or a.get("environment"), "running": bool(a.get("running")),
                                "mcp": a.get("mcp_server_count") or 0, "skills": a.get("skill_count") or 0,
                                "suspicious": (a.get("suspicious_mcp_server_count") or 0) + (a.get("suspicious_skill_count") or 0),
                                "last_seen": a.get("last_seen_at")} for a in (assistants or [])[:500]] if assistants is not None else None,
                "frameworks": fw.most_common(15),
                "mcp_servers": sorted(({"name": m.get("name") or m.get("id"), "transport": m.get("transport"), "risk": m.get("risk"),
                                        "severity": m.get("max_severity"), "findings": m.get("findings_count") or 0, "users": m.get("users") or 0,
                                        "endpoint": m.get("endpoint") or m.get("url") or m.get("command"), "frameworks": m.get("frameworks") or [],
                                        "last_seen": m.get("last_seen_at")} for m in mcp or []),
                                      key=lambda m: (-(m["findings"] or 0), -(m["users"] or 0)))[:300] if mcp is not None else None,
                "models": sorted(({"name": m.get("name"), "platform": m.get("platform"), "vendor": m.get("vendor") or m.get("developer"),
                                   "country": m.get("country"), "size": m.get("size_bytes"), "users": m.get("users") or 0,
                                   "license": m.get("license"), "last_seen": m.get("last_seen_at")} for m in models or []),
                                 key=lambda m: -(m["users"] or 0))[:300] if models is not None else None,
                "extensions": sorted(({"name": e.get("name") or e.get("identifier"), "id": e.get("identifier"), "risk": e.get("risk_rating"),
                                       "users": e.get("users") or 0, "devices": e.get("devices") or 0, "browsers": e.get("browsers") or [],
                                       "last_seen": e.get("last_seen_at")} for e in exts or []),
                                     key=lambda e: -(e["users"] or 0))[:300] if exts is not None else None}
            self.data["products"]["ai"] = {"ok": True, "objects": len(assistants or []) + len(mcp or []) + len(models or [])}

        policies = self._optional("Policies", lambda: self.paged("/api/v1/policies", None, 500))
        profiles = self._optional("Setting profiles", lambda: self.paged("/api/v1/setting-profiles", None, 200))
        tokens = self._optional("Enrollment tokens", lambda: self.paged("/api/v1/enroll-tokens", None, 300))
        users = self._optional("Managed users", lambda: self.paged("/api/v1/managed-users", None, 500))
        if any(x is not None for x in (policies, profiles, tokens, users)):
            self.data["policy"] = {
                "policies": [{"id": p.get("id"), "name": p.get("name"), "enabled": p.get("enabled"), "priority": p.get("priority"),
                              "os": p.get("os_platforms") or [], "rules": len(p.get("rules") or []) if isinstance(p.get("rules"), list) else None,
                              "version": p.get("version"), "updated": p.get("updated_at"), "updated_by": p.get("updated_by")}
                             for p in policies or []] if policies is not None else None,
                "profiles": [{"id": p.get("id"), "name": p.get("name"), "enabled": p.get("enabled"), "default": bool(p.get("is_default")),
                              "priority": p.get("priority"), "os": p.get("os_platforms") or [], "version": p.get("version"),
                              "updated": p.get("updated_at")} for p in profiles or []] if profiles is not None else None,
                "tokens": [{"id": t.get("id"), "label": t.get("label"), "type": t.get("type"), "status": t.get("status"),
                            "preview": t.get("token_preview"), "uses": t.get("use_count"), "max_uses": t.get("max_uses"),
                            "expires": t.get("expires_at"), "user": t.get("user_email"), "created_by": t.get("created_by")}
                           for t in tokens or []] if tokens is not None else None,
                "users": [{"id": u.get("id"), "login": u.get("login_id"), "email": u.get("primary_email"), "disabled": bool(u.get("disabled")),
                           "created": u.get("created_at")} for u in users or []] if users is not None else None}
            self.data["products"]["policy"] = {"ok": True, "objects": len(policies or []) + len(profiles or [])}

        audit = self._optional("Audit log", lambda: (self.get("/api/v1/audit-log", {"limit": 100}) or {}).get("items") or [])
        if audit is not None:
            self.data["audit"] = [{"at": a.get("occurred_at"), "actor": a.get("actor"), "action": a.get("action"),
                                   "details": json.dumps(a.get("details"), default=str)[:300] if a.get("details") not in (None, "", {}) else ""}
                                  for a in audit]
            self.data["products"]["audit"] = {"ok": True, "objects": len(audit)}
        return self._records(stats)

    @staticmethod
    def _event_row(e: dict) -> dict:
        return {"id": e.get("id"), "at": e.get("event_time"), "user": e.get("user_email"), "host": e.get("hostname"),
                "source": e.get("source"), "tool": e.get("tool_name"), "type": e.get("event_type"), "category": e.get("category"),
                "severity": e.get("severity"), "verdict": e.get("verdict"),
                "patterns": [str(p.get("name") or p.get("pattern") or p.get("id")) if isinstance(p, dict) else str(p)
                             for p in e.get("pattern_matches") or []][:5]}

    def _records(self, stats: dict) -> list[Record]:
        act = self.data.get("activity") or {}
        severe = sum(n for k, n in act.get("severities") or [] if k.lower() in SEVERE)
        health = dict(self.data["fleet"]["health"])
        out = [Record(external_id="zsai-fleet", hostname="Endpoint AI fleet", ip=None, type="Zscaler",
                      platform="Zscaler Endpoint AI Security", site=None, status="warn" if severe else "up",
                      detail=f"{stats.get('total') or 0} devices, {stats.get('online') or 0} online"
                             + (f", {severe} high-severity AI events in 24 hours" if act else ""),
                      extra={"product": "devices", "total": stats.get("total"), "online": stats.get("online"),
                             "stale": health.get("stale"), "revoked": health.get("revoked"), "severe_24h": severe})]
        return out

    # ------------------------------------------------------------------ on-demand
    def action(self, name: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        p = dict(params or {})
        if name in READ_OPS:
            return getattr(self, f"op_{name}")(p)
        if name not in ACTIONS:
            raise IntegrationError(f"Unknown Endpoint AI action {name!r}.")
        if not self.config.get("allow_control"):
            raise IntegrationError("Control actions are turned off for this integration. An admin can tick "
                                   "“Allow control actions” in its settings.")
        return getattr(self, f"op_{name}")(p)

    @staticmethod
    def _typed(p: dict, expect: str, what: str) -> None:
        if str(p.get("confirm_text") or "").strip() != expect:
            raise IntegrationError(f"Type {expect} to {what}.")

    @staticmethod
    def _json(text: Any) -> dict:
        raw = str(text or "")
        if len(raw) > MAX_JSON:
            raise IntegrationError("The JSON is larger than 256 KB.")
        try:
            obj = json.loads(raw)
        except ValueError as exc:
            raise IntegrationError(f"That isn't valid JSON: {exc}") from None
        if not isinstance(obj, dict):
            raise IntegrationError("The JSON must be one object, in braces.")
        return obj

    # devices
    def op_device_get(self, p: dict) -> dict:
        did = _match(DEVICE_ID_RE, p.get("device_id"), "device ID")
        return {"device": self.get(f"/api/v1/devices/{quote(did, safe='')}") or {}, "message": "ok"}

    def _device(self, p: dict) -> tuple[str, dict]:
        did = _match(DEVICE_ID_RE, p.get("device_id"), "device ID")
        dev = self.get(f"/api/v1/devices/{quote(did, safe='')}")
        if not isinstance(dev, dict):
            raise IntegrationError(f"No device {did}.")
        return did, dev

    def op_device_revoke(self, p: dict) -> dict:
        did, dev = self._device(p)
        name = str(dev.get("hostname") or did)
        self._typed(p, name, "revoke this device")
        self.call("POST", f"/api/v1/devices/{quote(did, safe='')}/revoke")
        return {"message": f"Revoked {name}. A managed agent re-enrolls within about an hour unless its fleet token is revoked too.",
                "what": f"device {name} ({did})"}

    def op_device_delete(self, p: dict) -> dict:
        did, dev = self._device(p)
        name = str(dev.get("hostname") or did)
        self._typed(p, name, "delete this device")
        self.call("DELETE", f"/api/v1/devices/{quote(did, safe='')}")
        return {"message": f"Deleted {name} from the fleet.", "what": f"device {name} ({did})"}

    def op_device_auto_identity(self, p: dict) -> dict:
        did, dev = self._device(p)
        on = _flag(p.get("enabled"))
        self.call("PUT", f"/api/v1/devices/{quote(did, safe='')}/auto-identity", body={"enabled": on})
        return {"message": f"Automatic identity {'on' if on else 'off'} for {dev.get('hostname') or did}.",
                "what": f"device {dev.get('hostname') or did} ({did}) automatic identity {'on' if on else 'off'}"}

    def op_device_bind_user(self, p: dict) -> dict:
        did, dev = self._device(p)
        email = _match(EMAIL_RE, p.get("email"), "email address")
        self.call("POST", f"/api/v1/devices/{quote(did, safe='')}/users", body={"email": email})
        return {"message": f"Bound {email} to {dev.get('hostname') or did}.", "what": f"device {dev.get('hostname') or did} ({did}) user {email}"}

    def op_device_unbind_user(self, p: dict) -> dict:
        did, dev = self._device(p)
        email = _match(EMAIL_RE, p.get("email"), "email address")
        self.call("DELETE", f"/api/v1/devices/{quote(did, safe='')}/users/{quote(email, safe='@')}")
        return {"message": f"Unbound {email} from {dev.get('hostname') or did}.", "what": f"device {dev.get('hostname') or did} ({did}) user {email}"}

    # enrollment tokens
    def op_token_create(self, p: dict) -> dict:
        label = str(p.get("label") or "").strip()
        if not label or len(label) > 200:
            raise IntegrationError("Give the token a label of up to 200 characters.")
        body: dict[str, Any] = {"label": label, "ttl_hours": _int(p.get("ttl_hours") or 168, 1, 17280, "Lifetime in hours")}
        if str(p.get("max_uses") or "").strip():
            body["max_uses"] = _int(p.get("max_uses"), 1, 1_000_000, "Maximum uses")
        if str(p.get("email") or "").strip():
            body["email"] = _match(EMAIL_RE, p.get("email"), "email address")
        got = self.call("POST", "/api/v1/enroll-tokens", body=body)[0] or {}
        return {"message": f"Created enrollment token {label}.", "secret": got.get("token"), "expires": got.get("expires_at"),
                "what": f"enrollment token {label} (ID {got.get('id')})"}

    def _token_row(self, p: dict) -> tuple[str, dict]:
        tid = _match(INT_ID_RE, p.get("token_id"), "token ID")
        for t in self.paged("/api/v1/enroll-tokens", None, 2000):
            if str(t.get("id")) == tid:
                return tid, t
        raise IntegrationError(f"No enrollment token {tid}.")

    def op_token_extend(self, p: dict) -> dict:
        tid, tok = self._token_row(p)
        days = _int(p.get("days") or 30, 1, 720, "Days")
        got = self.call("POST", f"/api/v1/enroll-tokens/{tid}/extend", body={"days": days})[0] or {}
        return {"message": f"Extended {tok.get('label') or tid} to {str(got.get('expires_at') or '?')[:10]}.",
                "what": f"enrollment token {tok.get('label') or ''} (ID {tid}) +{days} days"}

    def op_token_revoke(self, p: dict) -> dict:
        tid, tok = self._token_row(p)
        name = str(tok.get("label") or tid)
        self._typed(p, name, "revoke this token")
        self.call("POST", f"/api/v1/enroll-tokens/{tid}/revoke")
        return {"message": f"Revoked enrollment token {name}.", "what": f"enrollment token {name} (ID {tid})"}

    # policies
    def op_policy_get(self, p: dict) -> dict:
        pid = _match(INT_ID_RE, p.get("policy_id"), "policy ID")
        body, headers = self.call("GET", f"/api/v1/policies/{pid}")
        assign = None
        try:
            assign = self.get(f"/api/v1/policies/{pid}/assignments")
        except IntegrationError:
            pass
        return {"policy": body or {}, "etag": headers.get("etag"), "assignments": assign, "message": "ok"}

    def op_policy_validate(self, p: dict) -> dict:
        doc = self._json(p.get("json"))
        body: dict[str, Any] = {"rules": doc.get("rules", doc)}
        if p.get("policy_id"):
            body["policy_id"] = int(_match(INT_ID_RE, p.get("policy_id"), "policy ID"))
        got = self.call("POST", "/api/v1/policies/validate", body=body)[0] or {}
        errs = [str(e.get("message") if isinstance(e, dict) else e) for e in got.get("errors") or []]
        return {"valid": bool(got.get("valid")), "errors": errs[:50],
                "message": "The rules are valid." if got.get("valid") else f"{len(errs)} problem{'s' if len(errs) != 1 else ''}: " + "; ".join(errs[:5])}

    def op_policy_create(self, p: dict) -> dict:
        doc = self._json(p.get("json"))
        body = {k: v for k, v in doc.items() if k in POLICY_CREATE_FIELDS}
        if not str(body.get("name") or "").strip():
            raise IntegrationError("The policy needs a name.")
        if "rules" not in body:
            raise IntegrationError("The policy needs rules.")
        got = self.call("POST", "/api/v1/policies", body=body)[0] or {}
        return {"message": f"Created policy {body['name']}.", "id": got.get("id"), "what": f"policy {body['name']} (ID {got.get('id')})"}

    def _policy(self, p: dict) -> tuple[str, dict, str | None]:
        pid = _match(INT_ID_RE, p.get("policy_id"), "policy ID")
        body, headers = self.call("GET", f"/api/v1/policies/{pid}")
        if not isinstance(body, dict):
            raise IntegrationError(f"No policy {pid}.")
        # An ETag from the page the admin edited wins, so a change someone made since is caught (HTTP 412).
        return pid, body, str(p.get("etag") or "").strip() or headers.get("etag")

    def op_policy_update(self, p: dict) -> dict:
        pid, pol, etag = self._policy(p)
        doc = self._json(p.get("json"))
        body = {k: v for k, v in doc.items() if k in POLICY_FIELDS}
        if not body:
            raise IntegrationError(f"Nothing to change. The editor can change {', '.join(POLICY_FIELDS)}.")
        self.call("PATCH", f"/api/v1/policies/{pid}", body=body, if_match=etag)
        return {"message": f"Saved policy {body.get('name') or pol.get('name')}.", "what": f"policy {pol.get('name')} (ID {pid}): {', '.join(sorted(body))}"}

    def op_policy_enable(self, p: dict) -> dict:
        return self._policy_state(p, True)

    def op_policy_disable(self, p: dict) -> dict:
        return self._policy_state(p, False)

    def _policy_state(self, p: dict, on: bool) -> dict:
        pid, pol, etag = self._policy(p)
        self.call("PATCH", f"/api/v1/policies/{pid}", body={"enabled": on, "change_note": f"{'Enabled' if on else 'Disabled'} from VisCon1"},
                  if_match=etag)
        return {"message": f"{'Enabled' if on else 'Disabled'} policy {pol.get('name')}.", "what": f"policy {pol.get('name')} (ID {pid})"}

    def op_policy_assign(self, p: dict) -> dict:
        pid, pol, etag = self._policy(p)
        doc = self._json(p.get("json"))
        body = {k: v for k, v in doc.items() if k in ASSIGN_FIELDS}
        if not body:
            raise IntegrationError(f"Give the targeting as JSON with {', '.join(ASSIGN_FIELDS[:-1])}.")
        self.call("PUT", f"/api/v1/policies/{pid}/assignments", body=body, if_match=etag)
        scope = "everyone" if body.get("tenant_wide") else ", ".join(f"{len(body.get(k) or [])} {k.replace('_', ' ')}" for k in ("users", "groups", "device_groups"))
        return {"message": f"Policy {pol.get('name')} now applies to {scope}.", "what": f"policy {pol.get('name')} (ID {pid}) targeting: {scope}"}

    def op_policy_delete(self, p: dict) -> dict:
        pid, pol, etag = self._policy(p)
        name = str(pol.get("name") or pid)
        self._typed(p, name, "delete this policy")
        self.call("DELETE", f"/api/v1/policies/{pid}", if_match=etag)
        return {"message": f"Deleted policy {name}.", "what": f"policy {name} (ID {pid})"}

    # setting profiles
    def op_profile_get(self, p: dict) -> dict:
        pid = _match(INT_ID_RE, p.get("profile_id"), "profile ID")
        body, headers = self.call("GET", f"/api/v1/setting-profiles/{pid}")
        return {"profile": body or {}, "etag": headers.get("etag"), "message": "ok"}

    def _profile(self, p: dict) -> tuple[str, dict, str | None]:
        pid = _match(INT_ID_RE, p.get("profile_id"), "profile ID")
        body, headers = self.call("GET", f"/api/v1/setting-profiles/{pid}")
        if not isinstance(body, dict):
            raise IntegrationError(f"No setting profile {pid}.")
        if body.get("is_default"):
            raise IntegrationError("The default setting profile is changed in the console (Policies > Setting profiles).")
        return pid, body, str(p.get("etag") or "").strip() or headers.get("etag")

    def op_profile_update(self, p: dict) -> dict:
        pid, prof, etag = self._profile(p)
        doc = self._json(p.get("json"))
        body = {k: v for k, v in doc.items() if k in PROFILE_FIELDS}
        if not body:
            raise IntegrationError(f"Nothing to change. The editor can change {', '.join(PROFILE_FIELDS)}.")
        self.call("PATCH", f"/api/v1/setting-profiles/{pid}", body=body, if_match=etag)
        return {"message": f"Saved setting profile {body.get('name') or prof.get('name')}.",
                "what": f"setting profile {prof.get('name')} (ID {pid}): {', '.join(sorted(body))}"}

    def op_profile_enable(self, p: dict) -> dict:
        return self._profile_state(p, True)

    def op_profile_disable(self, p: dict) -> dict:
        return self._profile_state(p, False)

    def _profile_state(self, p: dict, on: bool) -> dict:
        pid, prof, etag = self._profile(p)
        self.call("PATCH", f"/api/v1/setting-profiles/{pid}", body={"enabled": on}, if_match=etag)
        return {"message": f"{'Enabled' if on else 'Disabled'} setting profile {prof.get('name')}.", "what": f"setting profile {prof.get('name')} (ID {pid})"}

    # managed users
    def op_user_disable(self, p: dict) -> dict:
        return self._user_state(p, False)

    def op_user_enable(self, p: dict) -> dict:
        return self._user_state(p, True)

    def _user_state(self, p: dict, on: bool) -> dict:
        uid = _match(INT_ID_RE, p.get("user_id"), "user ID")
        got = self.call("POST", f"/api/v1/managed-users/{uid}/{'enable' if on else 'disable'}")[0] or {}
        who = got.get("login_id") or uid
        return {"message": f"Sign-in {'on' if on else 'off'} for {who}.", "what": f"managed user {who} (ID {uid})"}
