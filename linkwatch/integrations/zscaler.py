"""Zscaler platform over OneAPI: ZIA, ZPA, ZDX, Client Connector and Zero Trust Branch.

One ZIdentity API client authenticates every product. Tokens come from
``https://<vanity>.zslogin.net/oauth2/v1/token`` (client-credentials grant,
audience ``https://api.zscaler.com``) and are sent as a Bearer token to
``https://api.zsapi.net`` (or ``https://api.<cloud>.zsapi.net`` for non
production clouds). Paths follow Zscaler's own Python SDK:

* ZIA   /zia/api/v1/locations, /zia/api/v1/greTunnels
* ZPA   /zpa/mgmtconfig/v1/admin/customers/{customerId}/connector
* ZDX   /zdx/v1/apps
* ZCC   /zcc/papi/public/v1/getDevices
* ZTB   /ztb/api/v2/Site/   (marked experimental in the SDK as well)
* AI    POST /zins/graphql (Z-Insights SHADOW_IT), /zia/api/v1/webApplicationRules/AI_ML,
        /zia/api/v1/cloudApplications/policy?appClass=AI_ML, /zia/api/v1/webDlpRules, /aiguard/v1/...
"""
from __future__ import annotations

import re
import time
from collections import Counter
from typing import Any

import httpx

from .base import Field, Integration, IntegrationError, Record
from .zscaler_ai_control import AIControl

TOKEN_AUDIENCE = "https://api.zscaler.com"


def _epoch(v) -> str | None:
    """ZPA sends epoch seconds or milliseconds as strings. Returns ISO UTC."""
    from datetime import datetime, timezone
    try:
        n = float(v)
    except (TypeError, ValueError):
        return None
    if n <= 0:
        return None
    if n > 1e11:
        n /= 1000
    return datetime.fromtimestamp(n, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# Generative AI ---------------------------------------------------------------
# Zscaler has no dedicated "AI telemetry" API. What OneAPI does expose:
#  * Z-Insights SHADOW_IT: per-app bytes, users, risk and sanctioned state, with a 24-48 hour delay
#  * ZIA Cloud App Control rules of type AI_ML: allow / caution / block / isolate, prompt capture
#  * ZIA's cloud application catalogue for the AI_ML class, and DLP rules naming those apps
#  * AI Guard: configuration (policies, LLM applications and providers), not detections
AI_REFRESH_S = 3600
AI_WINDOW_DAYS = 7
_AI_CACHE: dict[tuple, tuple[float, dict, list]] = {}

AI_NOT_EXPOSED = [
    ("Prompts and responses", "Prompt capture is a rule setting; the captured prompts are only viewable in the admin portal."),
    ("Allowed versus blocked requests per AI app", "Z-Insights web traffic can't be grouped by app, so counts of blocked or cautioned requests aren't available."),
    ("Top users and departments per AI app", "Only the admin portal's Shadow IT CSV export breaks an app down by user, and it is limited to a few reports an hour."),
    ("DLP incidents on AI prompts", "The API exposes DLP rules, not the incidents they raise. Send incidents to a SIEM with Nanolog Streaming Service."),
    ("Isolation sessions", "Only isolation profiles are exposed, not sessions."),
    ("AI Guard detections", "AI Guard's API lists its configuration and scans content on request; it has no history of detections."),
]

AI_ACTIONS = {"ALLOW": "allow", "CAUTION": "caution", "DENY": "block", "BLOCK": "block", "ISOLATE": "isolate"}

# AI Guard lists: (label for "not available" notes, OneAPI path, key in data["ai"]["aiguard"])
AIGUARD_LISTS = (("AI Guard policies", "/aiguard/v1/detections/policies", "policies"),
                 ("AI Guard policy match rules", "/aiguard/v1/detections/policy-match-rules", "rules"),
                 ("AI Guard LLM applications", "/aiguard/v1/llm-applications", "applications"),
                 ("AI Guard LLM providers", "/aiguard/v1/llm-providers", "providers"),
                 ("AI Guard application credentials", "/aiguard/v1/llm-application-credentials", "app_credentials"))


def aiguard_rows(body: Any) -> list[dict]:
    """AI Guard wraps lists in {"items": [...]}; older answers used records/list/content/data or a bare list."""
    if isinstance(body, list):
        rows = body
    elif isinstance(body, dict):
        rows = next((body[k] for k in ("items", "records", "list", "content", "data") if isinstance(body.get(k), list)), [])
    else:
        rows = []
    return [r for r in rows if isinstance(r, dict)]

APPS_QUERY = """query ShadowITApps($startTime: Long!, $endTime: Long!, $limit: Int, $orderBy: [ShadowITAppsOrderBy]) {
  SHADOW_IT { apps(start_time: $startTime, end_time: $endTime) {
    entries(limit: $limit, order_by: $orderBy) {
      application application_category risk_index sanctioned_state data_consumed data_uploaded data_downloaded
      authenticated_users last_access_time } } } }"""

SUMMARY_QUERY = """query ShadowITSummary($startTime: Long!, $endTime: Long!) {
  SHADOW_IT { shadow_it_summary(start_time: $startTime, end_time: $endTime) {
    total_bytes total_apps
    group_by_app_cat_for_app { obfuscated entries { name total } }
    group_by_app_cat_for_user_count { obfuscated entries { name total } }
    group_by_app_cat_for_upload_bytes { obfuscated entries { name total } }
    group_by_app_cat_for_download_bytes { obfuscated entries { name total } }
    group_by_app_cat_for_total_bytes { obfuscated entries { name total } } } } }"""


def _norm(name: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(name or "").lower())


def _pretty_app(app_id: str) -> str:
    """CHATGPT_AI -> Chatgpt; used only when the catalogue didn't give a display name."""
    return re.sub(r"_AI$", "", str(app_id)).replace("_", " ").title()


def _action(actions: list) -> str:
    for a in actions or []:
        for key, label in AI_ACTIONS.items():
            if str(a).upper().startswith(key):
                return label
    return "other"


def _num0(v) -> float:
    try:
        return float(v or 0)
    except (TypeError, ValueError):
        return 0.0


def _names(items) -> list[str]:
    return [str(i.get("name")) for i in items or [] if isinstance(i, dict) and i.get("name")]


class AITelemetry:
    """The Zscaler integration's AI tab. Mixed into Zscaler, which provides api(), graphql() and _optional()."""

    def _collect_ai(self) -> list[Record]:
        key = self._ai_cache_key()
        cached = _AI_CACHE.get(key)
        if cached and time.time() - cached[0] < AI_REFRESH_S:
            self.data["ai"] = cached[1]
            self.data["unavailable"].extend(cached[2])
            return [self._ai_record(cached[1])]
        before = len(self.data["unavailable"])
        ai: dict[str, Any] = {"refreshed": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "not_exposed": AI_NOT_EXPOSED}

        catalog = self._optional("AI app catalogue", self._ai_catalog)
        names = {str(c.get("app")): str(c.get("appName") or _pretty_app(c.get("app"))) for c in catalog or [] if c.get("app")}
        ai["catalog"] = sorted(set(names.values())) if catalog is not None else None
        app_name = lambda app_id: names.get(str(app_id)) or _pretty_app(app_id)

        rules = self._optional("AI & ML Cloud App Control rules", lambda: self.api("/zia/api/v1/webApplicationRules/AI_ML"))
        if rules is not None:
            ai["rules"] = self._ai_rules(rules, names)
        ai["app_names"] = names
        ai_category = str(self.config.get("ai_category") or "").strip().lower()
        is_ai_cat = (lambda c: str(c or "").strip().lower() == ai_category) if ai_category else \
            (lambda c: bool(re.search(r"\b(ai|ml|gen ?ai)\b|artificial|generative|machine learning|llm", str(c or ""), re.IGNORECASE)))
        known = {_norm(n) for n in names.values()}
        end = int(time.time() // 86400 * 86400 - 86400) * 1000   # Z-Insights lags a day or more; end at midnight UTC yesterday
        window = {"startTime": end - AI_WINDOW_DAYS * 86400000, "endTime": end}
        ai["window"] = {"days": AI_WINDOW_DAYS, "end": time.strftime("%Y-%m-%d", time.gmtime(end / 1000))}

        def shadow_apps():
            data = self.graphql("ShadowITApps", APPS_QUERY, {**window, "limit": 1000, "orderBy": [{"data_consumed": "DESC"}]})
            return (((data.get("SHADOW_IT") or {}).get("apps") or {}).get("entries")) or []
        entries = self._optional("Shadow IT apps (Z-Insights)", shadow_apps)
        if entries is not None:
            cats = Counter(str(e.get("application_category") or "Unknown") for e in entries)
            ai["categories_seen"] = cats.most_common()
            apps = [e for e in entries if is_ai_cat(e.get("application_category")) or _norm(e.get("application")) in known]
            ai["matched_categories"] = sorted({str(e.get("application_category")) for e in apps if e.get("application_category")})
            policy = self._ai_policy_by_app(ai.get("rules"), names)
            ai["apps"] = [{"name": e.get("application"), "category": e.get("application_category"),
                           "sanctioned": str(e.get("sanctioned_state") or "").replace("_", " ").lower() or None,
                           "risk": e.get("risk_index"), "users": int(_num0(e.get("authenticated_users"))),
                           "bytes": _num0(e.get("data_consumed")), "up": _num0(e.get("data_uploaded")), "down": _num0(e.get("data_downloaded")),
                           "last_access": _epoch(e.get("last_access_time")), **(policy.get(_norm(e.get("application"))) or policy.get("") or {})}
                          for e in apps]

        def summary():
            data = self.graphql("ShadowITSummary", SUMMARY_QUERY, window)
            return (data.get("SHADOW_IT") or {}).get("shadow_it_summary") or {}
        summ = self._optional("Shadow IT summary (Z-Insights)", summary)
        if summ:
            def cat_total(group: str) -> float:
                return sum(_num0(e.get("total")) for e in (summ.get(group) or {}).get("entries") or [] if is_ai_cat(e.get("name")))
            ai["summary"] = {"total_bytes": _num0(summ.get("total_bytes")), "total_apps": int(_num0(summ.get("total_apps"))),
                             "apps": int(cat_total("group_by_app_cat_for_app")), "users": int(cat_total("group_by_app_cat_for_user_count")),
                             "up": cat_total("group_by_app_cat_for_upload_bytes"), "down": cat_total("group_by_app_cat_for_download_bytes"),
                             "bytes": cat_total("group_by_app_cat_for_total_bytes")}

        dlp = self._optional("DLP rules", lambda: self.api("/zia/api/v1/webDlpRules"))
        if dlp is not None:
            ai_ids = set(names) | {a for r in ai.get("rules") or [] for a in r["app_ids"]}
            cats = {"AI_ML_APPS": "AI & ML apps", "GENERAL_AI_ML": "General AI & ML"}
            out = []
            for r in dlp if isinstance(dlp, list) else []:
                apps = [str(a.get("id") if isinstance(a, dict) else a) for a in r.get("cloudApplications") or []]
                urlcats = [str(c.get("id") if isinstance(c, dict) else c) for c in r.get("urlCategories") or []]
                hit_apps = [a for a in apps if a in ai_ids or a.endswith("_AI")]
                hit_cats = [c for c in urlcats if c in cats]
                if hit_apps or hit_cats:
                    out.append({"name": r.get("name"), "order": r.get("order") or 0, "action": str(r.get("action") or "").replace("_", " ").lower(),
                                "enabled": str(r.get("state", "ENABLED")).upper() != "DISABLED",
                                "apps": [app_name(a) for a in hit_apps], "categories": [cats[c] for c in hit_cats],
                                "engines": _names(r.get("dlpEngines"))})
            ai["dlp_rules"] = sorted(out, key=lambda r: r["order"])

        ai["aiguard"], ai["aiguard_items"] = self._ai_guard()
        if self.config.get("allow_control"):
            status = self._optional("ZIA activation status", lambda: self.api("/zia/api/v1/status"))
            ai["activation"] = status.get("status") if isinstance(status, dict) else None
        if all(ai.get(k) is None for k in ("catalog", "rules", "apps", "summary", "dlp_rules", "aiguard")):
            raise IntegrationError("None of the AI sources answered. " + "; ".join(self.data["unavailable"][before:])[:400])
        notes = self.data["unavailable"][before:]
        _AI_CACHE[key] = (time.time(), ai, list(notes))
        self.data["ai"] = ai
        return [self._ai_record(ai)]

    def _ai_cache_key(self) -> tuple:
        return (self.base, str(self.config.get("vanity_domain")), str(self.config.get("client_id")), str(self.config.get("ai_category") or ""))

    def refresh_ai_policy(self, ai: dict | None) -> dict:
        """After a control action: re-read the rules, AI Guard and activation state (cheap GETs) and merge them into the
        AI tab's data, keeping the hourly Shadow IT figures. Also updates the hourly cache, so the next sync agrees."""
        ai = dict(ai or {})
        self.data.setdefault("unavailable", [])
        names = ai.get("app_names") or {}
        rules = self._optional("AI & ML Cloud App Control rules", lambda: self.api("/zia/api/v1/webApplicationRules/AI_ML"))
        if rules is not None:
            ai["rules"] = self._ai_rules(rules, names)
            if ai.get("apps"):
                policy = self._ai_policy_by_app(ai["rules"], names)
                ai["apps"] = [{**{k: v for k, v in a.items() if k not in ("action", "rule", "prompt_capture")},
                               **(policy.get(_norm(a.get("name"))) or policy.get("") or {})} for a in ai["apps"]]
        ai["aiguard"], ai["aiguard_items"] = self._ai_guard()
        status = self._optional("ZIA activation status", lambda: self.api("/zia/api/v1/status"))
        ai["activation"] = status.get("status") if isinstance(status, dict) else ai.get("activation")
        ai["policy_refreshed"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        cached = _AI_CACHE.get(self._ai_cache_key())
        if cached:
            _AI_CACHE[self._ai_cache_key()] = (cached[0], ai, cached[2])
        return ai

    def _ai_rules(self, rules: list, names: dict[str, str]) -> list[dict]:
        app_name = lambda app_id: names.get(str(app_id)) or _pretty_app(app_id)
        return sorted(({
            "id": r.get("id"), "name": r.get("name"), "order": r.get("order") or r.get("rank") or 0,
            "enabled": str(r.get("state", "ENABLED")).upper() != "DISABLED",
            "action": _action(r.get("actions")), "actions": [str(a) for a in r.get("actions") or []],
            "apps": [app_name(a) for a in r.get("applications") or []],
            "app_ids": [str(a) for a in r.get("applications") or []], "all_apps": not r.get("applications"),
            "prompt_capture": bool(r.get("promptCaptureEnabled")), "has_prompt_capture": "promptCaptureEnabled" in r,
            "isolation": (r.get("cbiProfile") or {}).get("name"),
            "time_quota": r.get("timeQuota"), "size_quota": r.get("sizeQuota"),
            "scope": {k: _names(r.get(k)) for k in ("users", "groups", "departments", "locations") if r.get(k)},
            "description": r.get("description")} for r in rules if isinstance(r, dict)), key=lambda r: r["order"])

    def _ai_guard(self) -> tuple[dict | None, dict | None]:
        """AI Guard configuration: names per kind (for the summary) and id/name/enabled rows (for the control buttons)."""
        guard: dict[str, Any] = {}
        items: dict[str, Any] = {}
        for label, path, field in AIGUARD_LISTS:
            got = self._optional(label, lambda path=path: self.api(path, {"page": 1, "pageSize": 200}))
            if got is not None:
                rows = aiguard_rows(got)
                guard[field] = [str(i.get("name") or i.get("id")) for i in rows]
                items[field] = [{"id": i.get("id"), "name": str(i.get("name") or i.get("id")),
                                 "enabled": i.get("enabled") if isinstance(i.get("enabled"), bool) else None,
                                 "order": i.get("ruleOrder"), "policy_id": i.get("policyId"),
                                 "type": i.get("providerType") or i.get("type"),
                                 "description": str(i.get("description") or "")[:200] or None} for i in rows]
        return (guard or None), (items or None)

    def _ai_catalog(self) -> list[dict]:
        """ZIA's cloud apps in the AI_ML class. If the filter were ignored we'd get the whole catalogue, so cap it."""
        apps = self._zia_paged("/zia/api/v1/cloudApplications/policy", extra={"appClass": "AI_ML"}, max_pages=4)
        if len(apps) >= 2000:
            raise IntegrationError("the appClass=AI_ML filter wasn't applied, so the catalogue isn't used")
        return apps

    def _ai_policy_by_app(self, rules: list | None, names: dict[str, str]) -> dict[str, dict]:
        """Action of the first enabled rule (lowest order) that names each app, or that covers every AI app."""
        out: dict[str, dict] = {}
        blanket = None
        for r in [r for r in rules or [] if r["enabled"]]:
            if r["all_apps"]:
                blanket = blanket or r
            for app_id, name in zip(r["app_ids"], r["apps"]):
                for k in {_norm(name), _norm(names.get(app_id)), _norm(_pretty_app(app_id))} - {""}:
                    out.setdefault(k, {"action": r["action"], "rule": r["name"], "prompt_capture": r["prompt_capture"]})
        if blanket:
            out[""] = {"action": blanket["action"], "rule": blanket["name"], "prompt_capture": blanket["prompt_capture"]}
        return out

    def _ai_record(self, ai: dict) -> Record:
        apps = ai.get("apps") or []
        unsanctioned = sum(1 for a in apps if (a.get("sanctioned") or "").startswith("unsanc"))
        users = (ai.get("summary") or {}).get("users") or max((a["users"] for a in apps), default=0)
        detail = f"{len(apps)} AI apps in use over {AI_WINDOW_DAYS} days, {users} users" if ai.get("apps") is not None else \
            f"{len(ai.get('rules') or [])} AI & ML rules"
        return Record(external_id="ai-summary", hostname="Generative AI usage", ip=None, type="Zscaler", platform="ZIA AI & ML apps",
                      site=None, status="warn" if unsanctioned else "up", detail=detail,
                      extra={"product": "ai", "apps": len(apps), "unsanctioned": unsanctioned, "rules": len(ai.get("rules") or [])})


PRODUCTS = ("zia", "zpa", "zdx", "zcc", "ztb", "ai")


class Zscaler(AIControl, AITelemetry, Integration):
    kind = "zscaler"
    label = "Zscaler"
    runs_on = "server"
    description = "One OneAPI connection for ZIA, ZPA, ZDX, Client Connector, Zero Trust Branch and AI app usage."
    fields = [
        Field("vanity_domain", "ZIdentity vanity domain", help="The 'acme' in acme.zslogin.net."),
        Field("client_id", "API client ID"),
        Field("client_secret", "API client secret", "password"),
        Field("cloud", "Cloud", required=False, help="Leave blank for production. Set e.g. 'beta' for api.beta.zsapi.net."),
        Field("zpa_customer_id", "ZPA customer ID", required=False, help="Needed for ZPA. Shown in the ZPA admin portal under Public API."),
        Field("zia", "ZIA locations and tunnels", "bool", required=False, default=True),
        Field("zpa", "ZPA App Connectors", "bool", required=False, default=True),
        Field("zdx", "ZDX application scores", "bool", required=False, default=True),
        Field("zcc", "Client Connector device counts", "bool", required=False, default=True),
        Field("ztb", "Zero Trust Branch sites (experimental)", "bool", required=False, default=False),
        Field("ai", "Generative AI usage and policy", "bool", required=False, default=True,
              help="AI apps seen by Shadow IT (Z-Insights), AI & ML Cloud App Control rules, DLP rules that cover AI apps, and AI Guard. Refreshed hourly."),
        Field("ai_category", "Shadow IT category for AI apps", required=False,
              help="Leave blank to treat any Shadow IT category with AI or ML in its name, and every app in ZIA's AI & ML catalogue, as AI."),
        Field("allow_control", "Allow control actions", "bool", required=False, default=False,
              help="Lets admins change AI & ML Cloud App Control rules, mark apps sanctioned, activate ZIA changes and manage "
                   "AI Guard policies, match rules, LLM applications and providers from the AI tab. Every action is confirmed "
                   "and written to the audit log. See docs/zscaler-ai.md for the API client roles."),
        Field("aiguard_api_key", "AI Guard API key (optional)", "password", required=False,
              help="Only for the AI tab's Scan text box. Create it in the AI Guard portal; the detection API isn't on OneAPI."),
        Field("aiguard_cloud", "AI Guard cloud", required=False, default="us1",
              help="The 'us1' in api.us1.zseclipse.net. Leave blank for us1."),
        Field("ztb_api_key", "ZTB API key (optional)", "password", required=False,
              help="If ZTB refuses the OneAPI client: create an API key in the ZTB admin portal and paste it here."),
        Field("ztb_tenant", "ZTB portal address", required=False,
              help="Needed with a ZTB API key: the 'acme' in acme.goairgap.com, or the full https:// address."),
    ]

    def __init__(self, config: dict[str, Any], http: httpx.Client | None = None):
        super().__init__(config, http)
        cloud = str(config.get("cloud") or "").strip().strip(".")
        self.base = f"https://api.{cloud}.zsapi.net" if cloud else "https://api.zsapi.net"
        self._token: str | None = None
        self._token_exp = 0.0
        self.errors: list[str] = []
        self.data: dict[str, Any] = {"type": "zscaler", "products": {}, "unavailable": []}
        self._last_error_body: str | None = None

    def _optional(self, label: str, fn):
        """Extra detail that some tenants or licences don't have: a failure is noted on the page, not an error."""
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - any failure here only hides one panel
            self.data["unavailable"].append(f"{label}: {exc}")
            return None

    # auth ---------------------------------------------------------------
    @property
    def token_url(self) -> str:
        return f"https://{self.config['vanity_domain'].strip()}.zslogin.net/oauth2/v1/token"

    def _headers(self) -> dict[str, str]:
        if not self._token or time.time() > self._token_exp - 60:
            try:
                resp = self.http.post(self.token_url, data={
                    "grant_type": "client_credentials",
                    "client_id": self.config["client_id"],
                    "client_secret": self.config["client_secret"],
                    "audience": TOKEN_AUDIENCE,
                })
            except httpx.HTTPError as exc:
                raise IntegrationError(f"Could not reach ZIdentity: {exc.__class__.__name__}") from exc
            if resp.status_code != 200:
                raise IntegrationError(f"ZIdentity token request failed with HTTP {resp.status_code}. Check the vanity domain, client ID and secret.")
            body = resp.json()
            self._token = body["access_token"]
            self._token_exp = time.time() + int(body.get("expires_in", 3600))
        return {"Authorization": f"Bearer {self._token}"}

    def api(self, path: str, params: dict | None = None) -> Any:
        return self._request("GET", path, params=params)

    def _request(self, method: str, path: str, params: dict | None = None, json: Any = None) -> Any:
        url = self.base + path
        reauthed = False
        for attempt in range(5):
            try:
                resp = self.http.request(method, url, params=params, json=json, headers=self._headers())
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
            self._last_error_body = self._error_text(resp) if resp.status_code >= 400 else None
            if resp.status_code in (401, 403):
                raise IntegrationError(f"{method} {path} was refused (HTTP {resp.status_code}). Check the API client's roles for this product.")
            if resp.status_code >= 400:
                raise IntegrationError(f"{method} {path} returned HTTP {resp.status_code}")
            return resp.json() if resp.content else None
        raise IntegrationError(f"{method} {path} kept returning HTTP 429")

    @staticmethod
    def _error_text(resp: httpx.Response) -> str | None:
        """Zscaler's own explanation of a refused request ({"code": ..., "message": ...}), trimmed for the page."""
        try:
            body = resp.json()
        except ValueError:
            return None
        if isinstance(body, dict):
            msg = body.get("message") or body.get("error_description") or body.get("error") or body.get("reason")
            if isinstance(msg, str) and msg.strip():
                return msg.strip()[:300]
        return None

    def graphql(self, operation: str, query: str, variables: dict) -> dict:
        """Z-Insights: POST /zins/graphql. GraphQL reports errors in the body with HTTP 200."""
        body = self._request("POST", "/zins/graphql", json={"query": query, "variables": variables, "operationName": operation}) or {}
        if body.get("errors"):
            first = body["errors"][0]
            msg = first.get("message") if isinstance(first, dict) else str(first)
            raise IntegrationError(f"Z-Insights {operation}: {str(msg)[:200]}")
        return body.get("data") or {}

    @staticmethod
    def _sleep(seconds: float) -> None:
        time.sleep(seconds)

    def _enabled(self, product: str) -> bool:
        default = next(f.default for f in self.fields if f.name == product)
        return bool(self.config.get(product, default))

    # collection ---------------------------------------------------------
    def collect(self) -> list[Record]:
        records: list[Record] = []
        self.errors = []
        self.data = {"type": "zscaler", "products": {}, "unavailable": []}
        for product in PRODUCTS:
            if not self._enabled(product):
                continue
            try:
                got = getattr(self, f"_collect_{product}")()
                records.extend(got)
                self.data["products"][product] = {"ok": True, "objects": len(got)}
            except IntegrationError as exc:
                self.errors.append(f"{product.upper()}: {exc}")
                self.data["products"][product] = {"ok": False, "error": str(exc)}
        if self.errors and not records:
            raise IntegrationError("; ".join(self.errors))
        return records

    def _collect_zia(self) -> list[Record]:
        out: list[Record] = []
        locations = self._zia_paged("/zia/api/v1/locations")
        tunnels = self._zia_paged("/zia/api/v1/greTunnels")
        status = self._optional("ZIA activation status", lambda: self.api("/zia/api/v1/status")) or {}
        self.data["zia"] = {
            "activation": status.get("status") if isinstance(status, dict) else None,
            "locations": [{"id": loc.get("id"), "name": loc.get("name"), "country": loc.get("country"), "tz": loc.get("tz"),
                           "ips": loc.get("ipAddresses") or [], "vpn_credentials": len(loc.get("vpnCredentials") or []),
                           "up_kbps": loc.get("upBandwidth"), "down_kbps": loc.get("dnBandwidth"),
                           "firewall": loc.get("ofwEnabled"), "ssl_scan": loc.get("sslScanEnabled"),
                           "auth": loc.get("authRequired"), "xff": loc.get("xffForwardEnabled"),
                           "sub": bool(loc.get("parentId"))} for loc in locations],
            "tunnels": [{"id": t.get("id"), "source_ip": t.get("sourceIp"), "comment": t.get("comment"),
                         "primary": (t.get("primaryDestVip") or {}).get("datacenter"),
                         "primary_vip": (t.get("primaryDestVip") or {}).get("virtualIp"),
                         "secondary": (t.get("secondaryDestVip") or {}).get("datacenter"),
                         "secondary_vip": (t.get("secondaryDestVip") or {}).get("virtualIp"),
                         "inside": t.get("internalIpRange")} for t in tunnels],
        }
        for loc in locations:
            out.append(Record(
                external_id=f"zia-loc-{loc.get('id')}", hostname=f"ZIA location {loc.get('name', loc.get('id'))}",
                ip=None, type="Zscaler", platform="ZIA location", site=loc.get("name"), status="unknown",
                detail=", ".join(loc.get("ipAddresses") or []) or "No static IPs",
                extra={"product": "zia", "country": loc.get("country"), "vpnCredentials": len(loc.get("vpnCredentials") or [])},
            ))
        for t in tunnels:
            src = t.get("sourceIp", "")
            out.append(Record(
                external_id=f"zia-gre-{t.get('id')}", hostname=f"ZIA GRE {src}", ip=src or None, type="Zscaler",
                platform="ZIA GRE tunnel", site=None, status="unknown",
                detail=f"Primary {((t.get('primaryDestVip') or {}).get('datacenter') or '?')}, "
                       f"secondary {((t.get('secondaryDestVip') or {}).get('datacenter') or '?')}",
                extra={"product": "zia", "comment": t.get("comment")},
            ))
        return out

    def _zia_paged(self, path: str, page_size: int = 500, extra: dict | None = None, max_pages: int = 49) -> list[dict]:
        items: list[dict] = []
        for page in range(1, max_pages + 1):
            chunk = self.api(path, {**(extra or {}), "page": page, "pageSize": page_size}) or []
            items.extend(chunk)
            if len(chunk) < page_size:
                break
        return items

    def _collect_zpa(self) -> list[Record]:
        cid = str(self.config.get("zpa_customer_id") or "").strip()
        if not cid:
            raise IntegrationError("ZPA customer ID is not set")
        base = f"/zpa/mgmtconfig/v1/admin/customers/{cid}"
        path = f"{base}/connector"
        out: list[Record] = []
        connectors: list[dict] = []
        page, pages = 1, 1
        while page <= pages and page <= 50:
            body = self.api(path, {"page": page, "pagesize": 500}) or {}
            pages = int(body.get("totalPages") or 1)
            for c in body.get("list", []):
                healthy = c.get("controlChannelStatus") == "ZPN_STATUS_AUTHENTICATED"
                connectors.append({"id": c.get("id"), "name": c.get("name"), "group": c.get("appConnectorGroupName"),
                                   "enabled": c.get("enabled", True) is not False, "healthy": healthy,
                                   "channel": str(c.get("controlChannelStatus", "unknown")).replace("ZPN_STATUS_", "").lower(),
                                   "version": c.get("currentVersion"), "expected": c.get("expectedVersion"),
                                   "upgrade": c.get("upgradeStatus"), "private_ip": c.get("privateIp"), "public_ip": c.get("publicIp"),
                                   "location": c.get("location"), "os": c.get("runtimeOS") or c.get("platform"),
                                   "last_connect": _epoch(c.get("lastBrokerConnectTime"))})
                out.append(Record(
                    external_id=f"zpa-ac-{c.get('id')}", hostname=c.get("name") or f"connector {c.get('id')}",
                    ip=c.get("privateIp") or None, type="Zscaler",
                    platform=f"ZPA App Connector {c.get('currentVersion') or ''}".strip(),
                    site=c.get("appConnectorGroupName"), status="up" if healthy else ("off" if c.get("enabled") is False else "down"),
                    detail=f"Control channel {str(c.get('controlChannelStatus', 'unknown')).replace('ZPN_STATUS_', '').lower()}, "
                           f"public IP {c.get('publicIp') or '?'}",
                    extra={"product": "zpa", "expectedVersion": c.get("expectedVersion"), "upgradeStatus": c.get("upgradeStatus")},
                ))
            page += 1
        count = lambda sub: int(((self.api(f"{base}/{sub}", {"page": 1, "pagesize": 1}) or {}).get("totalCount")) or 0)
        self.data["zpa"] = {"connectors": connectors,
                            "groups": self._optional("ZPA connector groups", lambda: count("appConnectorGroup")),
                            "applications": self._optional("ZPA application segments", lambda: count("application")),
                            "healthy": sum(1 for c in connectors if c["healthy"]),
                            "outdated": sum(1 for c in connectors if c["expected"] and c["version"] and c["expected"] != c["version"])}
        return out

    def _collect_zdx(self) -> list[Record]:
        out: list[Record] = []
        apps = self.api("/zdx/v1/apps", {"since": 2}) or []
        self.data["zdx"] = {"apps": [{"id": a.get("id"), "name": a.get("name"), "score": a.get("score"), "users": a.get("total_users"),
                                      "region": (a.get("most_impacted_region") or {}).get("country")
                                      if isinstance(a.get("most_impacted_region"), dict) else a.get("most_impacted_region")}
                                     for a in apps]}
        for app in apps:
            score = app.get("score")
            status = "unknown" if score is None else ("up" if score >= 66 else "warn" if score >= 34 else "down")
            out.append(Record(
                external_id=f"zdx-app-{app.get('id')}", hostname=f"ZDX {app.get('name')}", ip=None, type="Zscaler",
                platform="ZDX application", site=None, status=status,
                detail=f"Score {score if score is not None else 'n/a'} across {app.get('total_users', '?')} users",
                extra={"product": "zdx", "score": score, "most_impacted_region": app.get("most_impacted_region")},
            ))
        return out

    def _collect_zcc(self) -> list[Record]:
        devices: list[dict] = []
        for page in range(1, 40):
            chunk = self.api("/zcc/papi/public/v1/getDevices", {"page": page, "pageSize": 5000}) or []
            devices.extend(chunk)
            if len(chunk) < 5000:
                break
        versions = Counter(str(d.get("agentVersion") or "unknown") for d in devices)
        oses = Counter(str(d.get("osVersion") or d.get("type") or "unknown").split(" ")[0] for d in devices)
        states = Counter(str(d.get("registrationState") or "unknown") for d in devices)
        self.data["zcc"] = {"total": len(devices), "versions": versions.most_common(15), "os": oses.most_common(10),
                            "states": states.most_common(), "devices": [
                                {"hostname": d.get("machineHostname") or d.get("hostname"), "user": d.get("user") or d.get("userName"),
                                 "os": d.get("osVersion") or d.get("type"), "version": d.get("agentVersion"),
                                 "state": d.get("registrationState"), "model": d.get("deviceModel"),
                                 "last_seen": d.get("lastSeenTime") or d.get("last_seen_time")} for d in devices[:1000]]}
        return [Record(
            external_id="zcc-summary", hostname="Client Connector fleet", ip=None, type="Zscaler",
            platform="Zscaler Client Connector", site=None, status="up",
            detail=f"{len(devices)} enrolled devices, {len(versions)} agent versions",
            extra={"product": "zcc", "devices": len(devices), "versions": dict(versions.most_common(10)), "os": dict(oses.most_common(10))},
        )]

    def _ztb_legacy(self, path: str) -> Any:
        """ZTB's own API key flow: POST /api/v3/api-key-auth/login -> delegate_token -> Bearer."""
        tenant = str(self.config.get("ztb_tenant") or "").strip().rstrip("/")
        if not tenant:
            raise IntegrationError("Set 'ZTB portal address' (the 'acme' in acme.goairgap.com) to use the ZTB API key")
        base = tenant if tenant.startswith("https://") else f"https://{tenant.removesuffix('.goairgap.com')}.goairgap.com"
        key = re.sub(r"\s+", "", str(self.config.get("ztb_api_key") or ""))
        try:
            login = self.http.post(f"{base}/api/v3/api-key-auth/login", json={"api_key": key})
        except httpx.HTTPError as exc:
            raise IntegrationError(f"Could not reach {httpx.URL(base).host}: {exc.__class__.__name__}") from exc
        if login.status_code != 200:
            raise IntegrationError(f"ZTB API key login failed (HTTP {login.status_code}). Check the key and the portal address.")
        try:
            token = (login.json().get("result") or {})["delegate_token"]
        except (ValueError, KeyError, AttributeError, TypeError):
            raise IntegrationError("ZTB login answered without a delegate_token") from None
        resp = self._get(f"{base}{path}", headers={"Authorization": f"Bearer {token}"})
        return resp.json() if resp.content else None

    def _collect_ztb(self) -> list[Record]:
        if str(self.config.get("ztb_api_key") or "").strip():
            body = self._ztb_legacy("/api/v2/Site/")
        else:
            try:
                body = self.api("/ztb/api/v2/Site/")
            except IntegrationError as exc:
                if "refused (HTTP 401)" in str(exc) or "refused (HTTP 403)" in str(exc):
                    raise IntegrationError(
                        "OneAPI refused /ztb/api/v2/Site/ (HTTP 401/403). Your ZIdentity API client has no ZTB access, or the "
                        "ZTB tenant isn't linked to ZIdentity yet. Either add ZTB to the API client's roles in ZIdentity, or "
                        "create an API key in the ZTB portal and fill in 'ZTB API key' and 'ZTB portal address'.") from None
                raise
        sites = body if isinstance(body, list) else (body or {}).get("result") or (body or {}).get("data") or (body or {}).get("sites") or []
        out: list[Record] = []
        self.data["ztb"] = {"sites": []}
        for s in sites:
            raw = str(s.get("status") or s.get("state") or s.get("health") or "").lower()
            self.data["ztb"]["sites"].append({
                "name": s.get("display_name") or s.get("name") or s.get("siteName") or s.get("id"),
                "status": raw or "unknown", "gateway": s.get("gatewayType") or s.get("gateway_type"),
                "location": s.get("location") or s.get("city") or s.get("address"),
                "details": {k: v for k, v in s.items() if isinstance(v, (str, int, float, bool)) and k not in ("id", "name", "display_name")}})
            status = "up" if raw in ("up", "online", "active", "healthy", "connected") else \
                     "down" if raw in ("down", "offline", "disconnected", "unhealthy") else "unknown"
            sid = s.get("id") or s.get("siteId") or s.get("site_id") or s.get("name")
            out.append(Record(
                external_id=f"ztb-site-{sid}", hostname=f"ZTB {s.get('display_name') or s.get('name') or s.get('siteName') or sid}", ip=None,
                type="Zscaler", platform="Zero Trust Branch site", site=s.get("display_name") or s.get("name") or s.get("siteName"), status=status,
                detail=f"Gateway type {s.get('gatewayType') or s.get('gateway_type') or '?'}", extra={"product": "ztb"},
            ))
        return out

