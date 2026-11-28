"""Shared base for cloud SSE / SASE platforms (Netskope, Cato, Prisma Access, Cloudflare Zero Trust).

Every SSE integration fills the same ``data`` payload, so one set of page tabs, graphs and
alerts serves them all. Each platform only says how to call its API and maps the answers
onto these sections:

``sites``    branch sites and the tunnels that carry them (IPsec / GRE / sockets), with live state
             where the API has it
``private``  private-access connectors (Netskope publishers, Prisma ZTNA connectors and service
             connections, Cloudflare tunnels)
``users``    the endpoint fleet (agents / WARP / GlobalProtect / Cato clients) and connected users
``policy``   rule bases: internet / web / firewall / private-access rules, in order
``apps``     SaaS and generative AI app usage, with the policy that applies where we can tell
``dlp``      DLP profiles and rules, and incidents where the API exposes them

A platform can add sections of its own (Cloudflare: gateway, access, dex, zones, audit). Their
data goes under the section key, the page includes ``views/<kind>_<section>.html`` for them, and
the same file name is appended to a shared tab to add platform-specific panels to it. Extra graphs
go in ``data["metrics"]`` as ``[key, a, b, c]`` rows.

Shape of ``data`` (every key is optional; a section that failed is absent and its error sits
in ``products``)::

    {"type": kind, "sse": True, "vendor": "Netskope",
     "products": {"sites": {"ok": True, "objects": 3}, "dlp": {"ok": False, "error": "..."}},
     "unavailable": ["optional panel: reason", ...],
     "gaps": {"apps": [["What isn't exposed", "Why / where to get it"], ...], ...},
     "labels": {"private": "Publishers", ...},
     "sites": {"items": [{"name", "type", "status", "pop", "location", "detail", "last_change",
                          "tunnels": [{"name", "status", "peer", "pop", "detail"}],
                          "rtt_ms", "loss_pct", "jitter_ms", "down_bps", "up_bps"}]},
     "private": {"items": [{"name", "group", "status", "version", "expected", "ip", "public_ip",
                            "location", "last_seen", "detail"}], "apps": int | None},
     "users": {"total", "connected", "versions": [[v, n]], "os": [[os, n]], "states": [[s, n]],
               "devices": [{"hostname", "user", "os", "version", "state", "last_seen"}]},
     "policy": {"rulebases": [{"name", "rules": [{"order", "name", "enabled", "action", "match",
                                                   "scope", "description"}]}]},
     "apps": {"window": {"days", "end"}, "refreshed", "items": [{"name", "category", "ai", "users",
              "bytes", "up", "down", "events", "risk", "sanctioned", "action", "rule"}],
              "categories_seen": [[cat, n]]},
     "dlp": {"profiles": [{"name", "type", "enabled", "detail"}], "rules": [{"name", "action",
             "enabled", "covers"}], "incidents": [{"time", "user", "app", "policy", "profile",
             "severity", "action"}], "by_severity": [[sev, n]]}}
"""
from __future__ import annotations

import re
import time
from collections import Counter
from collections.abc import Callable
from typing import Any, ClassVar

import httpx

from .base import Field, Integration, IntegrationError, Record

SECTIONS: list[tuple[str, str]] = [
    ("sites", "Sites & tunnels"), ("private", "Private access"), ("users", "Users & devices"),
    ("policy", "Policies"), ("apps", "Apps & AI"), ("dlp", "DLP"),
]
SECTION_HELP = {
    "sites": "Branch sites and their IPsec / GRE tunnels.",
    "private": "Private-access connectors.",
    "users": "Endpoint agents and connected users.",
    "policy": "Security rules, read only.",
    "apps": "SaaS and generative AI app usage. Refreshed hourly.",
    "dlp": "DLP profiles, rules and incidents. Refreshed hourly.",
}
UP = {"up", "connected", "online", "active", "healthy", "ok", "established", "running"}
DOWN = {"down", "disconnected", "offline", "inactive", "failed", "unhealthy", "error", "not registered", "unreachable"}
WARN = {"degraded", "warning", "partial", "partially connected", "pending"}

# Apps and DLP move slowly and some platforms meter their analytics APIs, so they are fetched hourly.
SLOW_SECTIONS = {"apps": 3600, "dlp": 3600}
_CACHE: dict[tuple, tuple[float, Any, list, list]] = {}

AI_CATEGORY = re.compile(r"\b(ai|ml|gen ?ai)\b|artificial|generative|machine learning|llm|chatbot", re.IGNORECASE)
AI_APPS = {re.sub(r"[^a-z0-9]", "", n.lower()) for n in (
    "ChatGPT", "OpenAI", "Claude", "Anthropic", "Google Gemini", "Gemini", "Bard", "Microsoft Copilot", "Copilot",
    "GitHub Copilot", "Perplexity", "DeepSeek", "Mistral", "Le Chat", "Grok", "Character.AI", "Poe", "Hugging Face",
    "Midjourney", "Jasper", "Writesonic", "Cohere", "Meta AI", "You.com", "Notion AI", "Grammarly", "Otter.ai",
    "Copy.ai", "Quillbot", "Stability AI", "Runway", "ElevenLabs", "Cursor", "Replit", "Tabnine", "Codeium")}


def norm(name: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(name or "").lower())


def is_ai(category: Any = None, name: Any = None, ai_category: str = "") -> bool:
    """An app counts as generative AI if its category says so (or equals the configured one), or it's a known AI app."""
    if ai_category:
        if str(category or "").strip().lower() == ai_category.strip().lower():
            return True
    elif category and AI_CATEGORY.search(str(category)):
        return True
    return norm(name) in AI_APPS


def status_of(raw: Any) -> str:
    """Map a vendor's state word to up / down / warn / unknown."""
    v = str(raw if raw is not None else "").strip().lower().replace("_", " ")
    if v in UP or v == "true":
        return "up"
    if v in DOWN or v == "false":
        return "down"
    if v in WARN:
        return "warn"
    return "unknown"


def num(v) -> float | None:
    try:
        return None if v is None or v == "" else float(v)
    except (TypeError, ValueError):
        return None


def worst(statuses: list[str]) -> str:
    """Roll tunnel states up to a site: all down is down, any trouble is warn."""
    real = [x for x in statuses if x in ("up", "down", "warn")]
    if not real:
        return "unknown"
    if all(x == "down" for x in real):
        return "down"
    return "warn" if any(x != "up" for x in real) else "up"


def section_fields(sections: list[str], labels: dict[str, str] | None = None, defaults: dict[str, bool] | None = None,
                   help: dict[str, str] | None = None) -> list[Field]:
    """One on/off box per section, named after the section key."""
    names = dict(SECTIONS) | (labels or {})
    return [Field(k, names.get(k, k.title()), "bool", required=False, default=(defaults or {}).get(k, True),
                  help=(help or {}).get(k, SECTION_HELP.get(k, ""))) for k in sections]


def counts(values) -> list[list]:
    return [[k, n] for k, n in Counter(str(v or "unknown") for v in values).most_common()]


class SSEIntegration(Integration):
    """Collect each enabled section into ``data``; a failing section is reported, not fatal."""

    sse: ClassVar[bool] = True
    vendor: ClassVar[str] = ""
    sections: ClassVar[list[str]] = []          # which of SECTIONS this platform offers
    labels: ClassVar[dict[str, str]] = {}       # per-platform tab names, e.g. {"private": "Publishers"}
    gaps: ClassVar[dict[str, list[tuple[str, str]]]] = {}   # what the API doesn't expose, per section
    slow: ClassVar[dict[str, int]] = SLOW_SECTIONS   # sections refreshed at most every N seconds
    record_type: ClassVar[str] = ""             # Device.type for records; defaults to vendor
    max_retries: ClassVar[int] = 4

    @classmethod
    def tab_label(cls, key: str) -> str:
        return cls.labels.get(key) or dict(SECTIONS).get(key, key.title())

    def __init__(self, config: dict[str, Any], http: httpx.Client | None = None):
        super().__init__(config, http)
        self.errors: list[str] = []
        self.data: dict[str, Any] = self._blank()

    def _blank(self) -> dict[str, Any]:
        return {"type": self.kind, "sse": True, "vendor": self.vendor or self.label, "products": {}, "unavailable": [],
                "gaps": {k: [list(g) for g in v] for k, v in self.gaps.items()},
                "labels": {k: self.tab_label(k) for k in self.sections}}

    # config ------------------------------------------------------------------
    def enabled(self, section: str) -> bool:
        default = next((f.default for f in self.fields if f.name == section), True)
        return bool(self.config.get(section, default))

    def secret(self, name: str) -> str:
        """A pasted secret minus whitespace and a stray 'Bearer ' prefix."""
        v = re.sub(r"\s+", "", str(self.config.get(name) or ""))
        return v[6:] if v.lower().startswith("bearer") else v

    def cache_key(self) -> tuple:
        """What identifies one tenant + credential for the hourly cache. Override if needed."""
        return tuple(str(self.config.get(f.name) or "") for f in self.fields if f.kind != "bool")

    # HTTP --------------------------------------------------------------------
    def auth_headers(self) -> dict[str, str]:  # pragma: no cover - per platform
        return {}

    def reset_auth(self) -> bool:
        """Drop a cached token after a 401. Return True if retrying could help."""
        return False

    def request(self, method: str, url: str, *, params: dict | None = None, json: Any = None,
                headers: dict | None = None, what: str | None = None) -> Any:
        label = what or f"{method} {httpx.URL(url).path}"
        reauthed = False
        for attempt in range(self.max_retries + 1):
            try:
                resp = self.http.request(method, url, params=params, json=json, headers={**self.auth_headers(), **(headers or {})})
            except httpx.HTTPError as exc:
                raise IntegrationError(f"Could not reach {httpx.URL(url).host}: {exc.__class__.__name__}") from exc
            if resp.status_code == 429 and attempt < self.max_retries:
                try:
                    wait = float(resp.headers.get("Retry-After", 2 ** attempt))
                except ValueError:
                    wait = 2.0
                self._sleep(min(max(wait, 0.5), 30))
                continue
            if resp.status_code == 401 and not reauthed and self.reset_auth():
                reauthed = True
                continue
            if resp.status_code in (401, 403):
                raise IntegrationError(f"{label} was refused (HTTP {resp.status_code}). Check the credential's read-only scopes for this area.")
            if resp.status_code == 404:
                raise IntegrationError(f"{label} returned HTTP 404: not available on this tenant or API version")
            if resp.status_code >= 400:
                raise IntegrationError(f"{label} returned HTTP {resp.status_code}{self._error_text(resp)}")
            if not resp.content:
                return None
            try:
                return resp.json()
            except ValueError:
                raise IntegrationError(f"{label} didn't return JSON") from None
        raise IntegrationError(f"{label} kept returning HTTP 429 (rate limited)")

    @staticmethod
    def _error_text(resp: httpx.Response) -> str:
        try:
            body = resp.json()
        except ValueError:
            return ""
        msg = None
        if isinstance(body, dict):
            msg = body.get("message") or body.get("error_description") or body.get("error") or body.get("errors")
        if isinstance(msg, list) and msg:
            msg = msg[0].get("message") if isinstance(msg[0], dict) else msg[0]
        return f": {str(msg)[:200]}" if msg else ""

    @staticmethod
    def _sleep(seconds: float) -> None:
        time.sleep(seconds)

    def optional(self, label: str, fn: Callable[[], Any]) -> Any:
        """Extra detail some licences or scopes lack: a failure is noted on the page, not an error."""
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - any failure here only hides one panel
            self.data["unavailable"].append(f"{label}: {exc}")
            return None

    # collection --------------------------------------------------------------
    def collect(self) -> list[Record]:
        self.errors = []
        self.data = self._blank()
        records: list[Record] = []
        self.prepare()
        for section in self.sections:
            if not self.enabled(section):
                continue
            try:
                got = self._run_section(section)
                records.extend(got)
                self.data["products"][section] = {"ok": True, "objects": len(got)}
            except IntegrationError as exc:
                self.errors.append(f"{self.tab_label(section)}: {exc}")
                self.data["products"][section] = {"ok": False, "error": str(exc)}
        if self.errors and not records and not any(p.get("ok") for p in self.data["products"].values()):
            raise IntegrationError("; ".join(self.errors))
        return records

    def prepare(self) -> None:
        """Called once per collect before the sections, e.g. to fetch a token or resolve an account."""

    def _run_section(self, section: str) -> list[Record]:
        fn = getattr(self, f"collect_{section}")
        ttl = self.slow.get(section)
        if not ttl:
            return fn()
        key = (self.kind, self.cache_key(), section)
        hit = _CACHE.get(key)
        if hit and time.time() - hit[0] < ttl:
            self.data[section] = hit[1]
            self.data["unavailable"].extend(hit[2])
            return [dict(r) for r in hit[3]]  # type: ignore[misc]
        before = len(self.data["unavailable"])
        records = fn()
        if section in self.data:
            self.data[section].setdefault("refreshed", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
            _CACHE[key] = (time.time(), self.data[section], list(self.data["unavailable"][before:]), [dict(r) for r in records])
        return records

    # record helpers -------------------------------------------------------------
    def record(self, section: str, ext: str, name: str, platform: str, status: str = "unknown", detail: str = "",
               site: str | None = None, ip: str | None = None, **extra) -> Record:
        return Record(external_id=f"{section}-{ext}", hostname=name, ip=ip or None, type=self.record_type or self.vendor or self.label,
                      platform=platform, site=site, status=status, detail=detail, extra={"product": section, **extra})

    def site_records(self, items: list[dict], platform: str) -> list[Record]:
        return [self.record("sites", str(x.get("id") or x["name"]), x["name"], x.get("platform") or platform, x.get("status") or "unknown",
                            x.get("detail") or ", ".join(f"{t.get('name')} {t.get('status')}" for t in x.get("tunnels") or [])[:200],
                            site=x.get("site") or x["name"], ip=x.get("ip"), pop=x.get("pop")) for x in items]

    def private_records(self, items: list[dict], platform: str) -> list[Record]:
        return [self.record("private", str(x.get("id") or x["name"]), x["name"], x.get("platform") or platform, x.get("status") or "unknown",
                            x.get("detail") or "", site=x.get("group"), ip=x.get("ip")) for x in items]

    def fleet_record(self, users: dict, platform: str) -> Record:
        total, connected = users.get("total") or 0, users.get("connected")
        detail = f"{total:,} devices" + (f", {connected:,} connected" if connected is not None else "")
        return self.record("users", "summary", f"{self.vendor} endpoint fleet", platform, "up", detail,
                           devices=total, connected=connected)

    def summary_record(self, section: str, name: str, platform: str, detail: str, status: str = "up", **extra) -> Record:
        return self.record(section, "summary", name, platform, status, detail, **extra)

    @staticmethod
    def fleet(devices: list[dict], connected: int | None = None, keep: int = 1000) -> dict[str, Any]:
        """Roll a device list (hostname, user, os, version, state, last_seen) up into the users section."""
        return {"total": len(devices), "connected": connected,
                "versions": counts(d.get("version") for d in devices)[:15],
                "os": counts(str(d.get("os") or "unknown").split(" ")[0] for d in devices)[:10],
                "states": counts(d.get("state") for d in devices),
                "devices": devices[:keep]}

    def apps_record(self, apps: dict) -> Record:
        items = apps.get("items") or []
        ai = [a for a in items if a.get("ai")]
        users = max((a.get("users") or 0 for a in ai), default=0)
        risky = sum(1 for a in ai if str(a.get("sanctioned") or "").startswith("unsanc"))
        return self.summary_record("apps", "Generative AI usage", f"{self.vendor} app usage",
                                   f"{len(ai)} AI apps of {len(items)} apps seen" + (f", up to {users} users on one" if users else ""),
                                   "warn" if risky else "up", ai_apps=len(ai), apps=len(items))

    def window(self, days: int = 7) -> tuple[int, int, dict]:
        """(start, end) epoch seconds for usage queries, ending now, plus the label shown on the page."""
        end = int(time.time())
        return end - days * 86400, end, {"days": days, "end": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(end))}

    def ai_category(self) -> str:
        return str(self.config.get("ai_category") or "").strip()

    @staticmethod
    def ai_category_field() -> Field:
        return Field("ai_category", "App category for generative AI", required=False,
                     help="Leave blank to treat any category with AI, ML, generative or LLM in its name, and well-known AI apps, as AI.")
