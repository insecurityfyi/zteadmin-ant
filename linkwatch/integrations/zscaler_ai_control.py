"""Control actions for the Zscaler integration's AI tab: ZIA generative AI policy and AI Guard.

Everything here goes through the same OneAPI client as the rest of the Zscaler integration, except the AI Guard
content scan, which Zscaler only offers on the AI Guard detection API with its own API key.

What an admin can change (paths follow Zscaler's Python SDK, ``zscaler-sdk-python`` 1.11):

* ZIA AI & ML Cloud App Control rules (``/zia/api/v1/webApplicationRules/AI_ML[/{id}]``): create, edit, enable or
  disable, change the action (allow, caution, block, isolate), turn prompt capture on or off, delete;
* the sanctioned state of a cloud app (``PUT /zia/api/v1/cloudApplications/bulkUpdate``);
* activation of pending ZIA changes (``POST /zia/api/v1/status/activate``). ZIA changes made through the API stay
  pending until activated, exactly as in the admin portal;
* AI Guard detection policies, policy match rules, LLM applications and LLM providers
  (``/aiguard/v1/detections/policies``, ``/aiguard/v1/detections/policy-match-rules``, ``/aiguard/v1/llm-applications``,
  ``/aiguard/v1/llm-providers``): create, edit (as JSON), delete; enable or disable match rules;
* AI Guard application credentials (``/aiguard/v1/llm-application-credentials``): regenerate or delete.

Read-only helpers (``rule_get``, ``guard_get``, ``scan``) work without *Allow control actions*; everything that
changes the tenant refuses to run unless it is ticked. Every value that ends up in an API path is checked against a
strict pattern first, so nothing the browser sends can reach a different endpoint.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

import httpx

from .base import IntegrationError

RULE_TYPE = "AI_ML"
RULES_PATH = f"/zia/api/v1/webApplicationRules/{RULE_TYPE}"
ID_RE = re.compile(r"^\d{1,18}$")
APP_ID_RE = re.compile(r"^[A-Za-z0-9_]{1,100}$")
ACTION_RE = re.compile(r"^[A-Z0-9_]{3,80}$")
# What ZIA offers for AI & ML rules when it can't be asked (availableActions is tried first).
DEFAULT_RULE_ACTIONS = ["ALLOW_AI_ML_WEB_USE", "CAUTION_AI_ML_WEB_USE", "DENY_AI_ML_WEB_USE", "ISOLATE_AI_ML_WEB_USE"]
SIMPLE_ACTIONS = {"allow": "ALLOW_AI_ML_WEB_USE", "caution": "CAUTION_AI_ML_WEB_USE", "block": "DENY_AI_ML_WEB_USE",
                  "isolate": "ISOLATE_AI_ML_WEB_USE"}
MAX_NAME = 127
MAX_DESC = 10240
MAX_JSON = 64 * 1024
MAX_SCAN = 32 * 1024

# AI Guard object kinds an admin can see and change: label, OneAPI path, whether it can be edited as JSON.
GUARD_KINDS: dict[str, tuple[str, str, bool]] = {
    "policies": ("Detection policy", "/aiguard/v1/detections/policies", True),
    "rules": ("Policy match rule", "/aiguard/v1/detections/policy-match-rules", True),
    "applications": ("LLM application", "/aiguard/v1/llm-applications", True),
    "providers": ("LLM provider", "/aiguard/v1/llm-providers", True),
    "app_credentials": ("Application credential", "/aiguard/v1/llm-application-credentials", False),
}
# Fields the API manages itself; dropped from an edited object before it is sent back.
GUARD_READONLY = {"createdAt", "updatedAt", "createdBy", "updatedBy", "lastModifiedTime", "lastModifiedBy", "createdTime",
                  "modifiedTime", "modifiedBy"}
# Keys whose values are never shown or sent back from the editor (provider API keys and the like).
SECRET_KEY_RE = re.compile(r"(secret|password|api_?key|token|credential_?value)$", re.IGNORECASE)


@dataclass(frozen=True)
class Action:
    """One thing an admin can do. ``confirm`` is None (no prompt), "yes" (an "are you sure" dialog) or "typed"
    (the admin types the object's name). ``scope`` says which object the action needs: rule, app, guard or zia."""
    label: str
    scope: str
    confirm: str | None = None
    help: str = ""


ACTIONS: dict[str, Action] = {
    # ZIA AI & ML Cloud App Control
    "rule_create": Action("Create AI & ML rule", "zia", help="The new rule is pending until ZIA changes are activated."),
    "rule_update": Action("Save AI & ML rule", "rule", "yes", help="Replaces the rule's settings. Pending until activated."),
    "rule_enable": Action("Enable rule", "rule", "yes", help="Pending until ZIA changes are activated."),
    "rule_disable": Action("Disable rule", "rule", "yes",
                           help="Traffic the rule matched falls through to the next rule. Pending until activated."),
    "rule_set_action": Action("Change rule action", "rule", "yes", help="Pending until ZIA changes are activated."),
    "rule_prompt_capture": Action("Change prompt capture", "rule", "yes",
                                  help="Prompt capture records the prompts users send to this rule's AI apps."),
    "rule_delete": Action("Delete AI & ML rule", "rule", "typed", help="Cannot be undone once ZIA changes are activated."),
    "app_sanction": Action("Mark app sanctioned", "app", "yes", help="Changes the app's state in ZIA's Shadow IT report."),
    "app_unsanction": Action("Mark app unsanctioned", "app", "yes", help="Changes the app's state in ZIA's Shadow IT report."),
    "zia_activate": Action("Activate ZIA changes", "zia", "yes",
                           help="Pushes every pending ZIA change to the cloud, including changes other admins made."),
    # AI Guard
    "guard_create": Action("Create AI Guard object", "guard", help="Takes effect straight away; AI Guard has no activation step."),
    "guard_update": Action("Save AI Guard object", "guard", "yes", help="Takes effect straight away."),
    "guard_enable": Action("Enable match rule", "guard", "yes", help="Takes effect straight away."),
    "guard_disable": Action("Disable match rule", "guard", "yes", help="Applications it covered fall through to other rules."),
    "guard_delete": Action("Delete AI Guard object", "guard", "typed", help="Takes effect straight away and cannot be undone."),
    "guard_regenerate": Action("Regenerate credential", "guard", "typed",
                               help="The old secret stops working at once. Every app using it must be given the new one."),
}
READ_OPS = ("rule_get", "rule_available_actions", "guard_get", "scan")


def _id(v: Any, what: str = "ID") -> str:
    s = str(v if v is not None else "").strip()
    if not ID_RE.match(s):
        raise IntegrationError(f"Invalid {what}: {s[:40]!r}")
    return s


def _flag(v: Any) -> bool:
    return str(v).strip().lower() in ("1", "true", "on", "yes")


def _text(v: Any, limit: int, what: str, required: bool = False) -> str:
    s = str(v or "").strip()
    if required and not s:
        raise IntegrationError(f"{what} is required.")
    if len(s) > limit:
        raise IntegrationError(f"{what} is longer than {limit} characters.")
    if any(ord(c) < 32 and c not in "\n\t" for c in s):
        raise IntegrationError(f"{what} contains control characters.")
    return s


def _list(v: Any) -> list[str]:
    """A form field that may be a list, a comma or newline separated string, or empty."""
    if isinstance(v, (list, tuple)):
        items = [str(x) for x in v]
    else:
        items = re.split(r"[\s,]+", str(v or ""))
    return [x.strip() for x in items if x and x.strip()]


def guard_kind(v: Any) -> tuple[str, str, bool]:
    kind = str(v or "")
    if kind not in GUARD_KINDS:
        raise IntegrationError(f"Unknown AI Guard object type {kind[:30]!r}.")
    return GUARD_KINDS[kind]


def strip_secrets(obj: Any) -> Any:
    """Copy of an API object with secret-looking values replaced, for display and the editor."""
    if isinstance(obj, dict):
        return {k: ("••••••" if SECRET_KEY_RE.search(str(k)) and isinstance(v, str) and v else strip_secrets(v))
                for k, v in obj.items()}
    if isinstance(obj, list):
        return [strip_secrets(x) for x in obj]
    return obj


def _restore_secrets(edited: Any, original: Any) -> Any:
    """Put back secrets the editor showed masked, so saving a provider doesn't overwrite its API key with dots."""
    if isinstance(edited, dict) and isinstance(original, dict):
        out = {}
        for k, v in edited.items():
            if v == "••••••" and SECRET_KEY_RE.search(str(k)):
                if k in original:
                    out[k] = original[k]
                continue
            out[k] = _restore_secrets(v, original.get(k))
        return out
    if isinstance(edited, list) and isinstance(original, list):
        return [_restore_secrets(e, original[i] if i < len(original) else None) for i, e in enumerate(edited)]
    return edited


class AIControl:
    """Mixed into Zscaler, which provides _request(), api() and config."""

    # ------------------------------------------------------------------ HTTP for writes
    def _write(self, method: str, path: str, body: Any = None, params: dict | None = None) -> Any:
        """Like _request, but passes Zscaler's error message on to the admin: a refused write is usually a
        validation problem they can fix (a missing isolation profile, a duplicate name)."""
        try:
            return self._request(method, path, params=params, json=body)
        except IntegrationError as exc:
            detail = getattr(self, "_last_error_body", None)
            if detail:
                raise IntegrationError(f"{exc}: {detail}") from None
            raise

    # ------------------------------------------------------------------ entry point
    def action(self, name: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Run one read-only lookup or control action. Returns {"message": ...} plus any data the page shows.
        Raises IntegrationError with a message for the admin."""
        p = dict(params or {})
        if name in READ_OPS:
            return getattr(self, f"op_{name}")(p)
        if name not in ACTIONS:
            raise IntegrationError(f"Unknown Zscaler AI action {name!r}.")
        if not self.config.get("allow_control"):
            raise IntegrationError("Control actions are turned off for this integration. An admin can tick "
                                   "“Allow control actions” in its settings.")
        return getattr(self, f"op_{name}")(p)

    # ------------------------------------------------------------------ ZIA rules: reads
    def op_rule_get(self, p: dict) -> dict:
        rid = _id(p.get("rule_id"), "rule ID")
        rule = self.api(f"{RULES_PATH}/{rid}")
        if not isinstance(rule, dict):
            raise IntegrationError("ZIA returned no rule.")
        return {"rule": rule, "message": "ok"}

    def op_rule_available_actions(self, p: dict) -> dict:
        apps = [a for a in _list(p.get("apps")) if APP_ID_RE.match(a)][:200]
        try:
            got = self._request("POST", f"{RULES_PATH}/availableActions", json={"cloudApps": apps})
            actions = [str(a) for a in got if isinstance(a, str) and ACTION_RE.match(a)] if isinstance(got, list) else []
        except IntegrationError:
            actions = []
        return {"actions": actions or list(DEFAULT_RULE_ACTIONS), "from_zia": bool(actions), "message": "ok"}

    # ------------------------------------------------------------------ ZIA rules: writes
    def _rule(self, p: dict) -> tuple[str, dict]:
        rid = _id(p.get("rule_id"), "rule ID")
        rule = self.api(f"{RULES_PATH}/{rid}")
        if not isinstance(rule, dict) or not rule:
            raise IntegrationError(f"ZIA has no AI & ML rule {rid}.")
        return rid, rule

    def _put_rule(self, rid: str, rule: dict) -> dict:
        body = {k: v for k, v in rule.items() if k not in ("lastModifiedTime", "lastModifiedBy")}
        body["type"] = RULE_TYPE
        self._write("PUT", f"{RULES_PATH}/{rid}", body)
        return body

    @staticmethod
    def _rule_fields(p: dict, rule: dict, creating: bool) -> dict:
        """Apply the editor's fields to a rule body. Only fields present in the form change."""
        out = dict(rule)
        if creating or "name" in p:
            out["name"] = _text(p.get("name"), MAX_NAME, "Rule name", required=True)
        if "description" in p:
            out["description"] = _text(p.get("description"), MAX_DESC, "Description")
        if "order" in p and str(p.get("order") or "").strip():
            try:
                order = int(str(p["order"]).strip())
            except ValueError:
                raise IntegrationError("Rule order must be a number.") from None
            if not 1 <= order <= 10_000:
                raise IntegrationError("Rule order must be between 1 and 10000.")
            out["order"] = order
        elif creating:
            out["order"] = 1
        if creating:
            out.setdefault("rank", 7)
        if "enabled" in p:
            out["state"] = "ENABLED" if _flag(p.get("enabled")) else "DISABLED"
        elif creating:
            out["state"] = "ENABLED"
        if "actions" in p or "simple_action" in p:
            acts = _list(p.get("actions"))
            if p.get("simple_action"):
                simple = SIMPLE_ACTIONS.get(str(p["simple_action"]).lower())
                if not simple:
                    raise IntegrationError("Action must be allow, caution, block or isolate.")
                acts = [simple]
            bad = [a for a in acts if not ACTION_RE.match(a)]
            if bad:
                raise IntegrationError(f"Invalid action {bad[0][:40]!r}.")
            if not acts:
                raise IntegrationError("Pick at least one action.")
            out["actions"] = acts
        elif creating:
            raise IntegrationError("Pick at least one action.")
        if "applications" in p:
            apps = _list(p.get("applications"))
            bad = [a for a in apps if not APP_ID_RE.match(a)]
            if bad:
                raise IntegrationError(f"Invalid app ID {bad[0][:40]!r}. Use ZIA's app IDs, such as CHATGPT_AI.")
            out["applications"] = apps[:500]
        if "prompt_capture" in p:
            out["promptCaptureEnabled"] = _flag(p.get("prompt_capture"))
        if any(str(a).startswith("ISOLATE") for a in out.get("actions") or []) and not out.get("cbiProfile"):
            raise IntegrationError("Isolating needs an isolation profile on the rule. Set one in the ZIA admin portal "
                                   "first, then change the action here.")
        return out

    def op_rule_create(self, p: dict) -> dict:
        body = self._rule_fields(p, {"type": RULE_TYPE}, creating=True)
        got = self._write("POST", RULES_PATH, body)
        rid = got.get("id") if isinstance(got, dict) else None
        return {"message": f"Created rule {body['name']}. Activate ZIA changes to apply it.", "rule_id": rid,
                "pending": True, "what": f"rule {body['name']}" + (f" (ID {rid})" if rid else "")}

    def op_rule_update(self, p: dict) -> dict:
        rid, rule = self._rule(p)
        body = self._put_rule(rid, self._rule_fields(p, rule, creating=False))
        return {"message": f"Saved rule {body.get('name')}. Activate ZIA changes to apply it.", "pending": True,
                "what": f"rule {body.get('name')} (ID {rid})"}

    def op_rule_enable(self, p: dict) -> dict:
        return self._rule_state(p, True)

    def op_rule_disable(self, p: dict) -> dict:
        return self._rule_state(p, False)

    def _rule_state(self, p: dict, on: bool) -> dict:
        rid, rule = self._rule(p)
        rule["state"] = "ENABLED" if on else "DISABLED"
        self._put_rule(rid, rule)
        return {"message": f"{'Enabled' if on else 'Disabled'} rule {rule.get('name')}. Activate ZIA changes to apply it.",
                "pending": True, "what": f"rule {rule.get('name')} (ID {rid})"}

    def op_rule_set_action(self, p: dict) -> dict:
        rid, rule = self._rule(p)
        if not p.get("simple_action"):
            raise IntegrationError("Pick allow, caution, block or isolate.")
        body = self._put_rule(rid, self._rule_fields({"simple_action": p.get("simple_action")}, rule, creating=False))
        return {"message": f"Rule {body.get('name')} now {str(p['simple_action']).lower()}s. Activate ZIA changes to apply it.",
                "pending": True, "what": f"rule {body.get('name')} (ID {rid}) -> {str(p['simple_action']).lower()}"}

    def op_rule_prompt_capture(self, p: dict) -> dict:
        rid, rule = self._rule(p)
        if "promptCaptureEnabled" not in rule:
            raise IntegrationError("ZIA didn't return a prompt capture setting for this rule, so it can't be changed "
                                   "here. Your tenant may not have prompt capture.")
        on = _flag(p.get("prompt_capture"))
        rule["promptCaptureEnabled"] = on
        self._put_rule(rid, rule)
        return {"message": f"Prompt capture {'on' if on else 'off'} for rule {rule.get('name')}. Activate ZIA changes to apply it.",
                "pending": True, "what": f"rule {rule.get('name')} (ID {rid}) prompt capture {'on' if on else 'off'}"}

    def op_rule_delete(self, p: dict) -> dict:
        rid, rule = self._rule(p)
        expect = str(rule.get("name") or rid)
        if str(p.get("confirm_text") or "").strip() != expect:
            raise IntegrationError(f"Type the rule name, {expect}, to delete it.")
        self._write("DELETE", f"{RULES_PATH}/{rid}")
        return {"message": f"Deleted rule {expect}. Activate ZIA changes to apply it.", "pending": True,
                "what": f"rule {expect} (ID {rid})"}

    # ------------------------------------------------------------------ ZIA apps and activation
    def _cloud_app_id(self, name: str) -> str:
        """Shadow IT bulkUpdate wants ZIA's numeric app ID; Z-Insights gives the app's name. Look it up."""
        want = re.sub(r"[^a-z0-9]", "", name.lower())
        for page in range(40):
            chunk = self.api("/zia/api/v1/cloudApplications/lite", {"pageNumber": page, "limit": 1000}) or []
            for a in chunk if isinstance(chunk, list) else []:
                if isinstance(a, dict) and re.sub(r"[^a-z0-9]", "", str(a.get("name") or "").lower()) == want and a.get("id") is not None:
                    return _id(a.get("id"), "app ID")
            if not isinstance(chunk, list) or len(chunk) < 1000:
                break
        raise IntegrationError(f"ZIA's cloud application list has no app called {name!r}.")

    def op_app_sanction(self, p: dict) -> dict:
        return self._sanction(p, "SANCTIONED")

    def op_app_unsanction(self, p: dict) -> dict:
        return self._sanction(p, "UN_SANCTIONED")

    def _sanction(self, p: dict, state: str) -> dict:
        name = _text(p.get("app"), 200, "App name", required=True)
        app_id = _id(p["app_id"], "app ID") if p.get("app_id") else self._cloud_app_id(name)
        self._write("PUT", "/zia/api/v1/cloudApplications/bulkUpdate", {"sanctionedState": state, "applicationIds": [int(app_id)]})
        word = "sanctioned" if state == "SANCTIONED" else "unsanctioned"
        return {"message": f"{name} is now {word}.", "what": f"app {name} (ID {app_id}) -> {word}", "app": name, "sanctioned": word}

    def op_zia_activate(self, p: dict) -> dict:
        got = self._write("POST", "/zia/api/v1/status/activate")
        status = got.get("status") if isinstance(got, dict) else None
        return {"message": f"ZIA changes activated{f' ({str(status).lower()})' if status else ''}.", "activation": status,
                "what": "pending ZIA changes"}

    # ------------------------------------------------------------------ AI Guard
    def op_guard_get(self, p: dict) -> dict:
        label, path, editable = guard_kind(p.get("kind"))
        oid = _id(p.get("id"))
        obj = self.api(f"{path}/{oid}")
        if not isinstance(obj, dict):
            raise IntegrationError(f"AI Guard returned no {label.lower()} {oid}.")
        return {"object": strip_secrets(obj), "editable": editable, "message": "ok"}

    @staticmethod
    def _parse_json(text: Any) -> dict:
        raw = str(text or "")
        if len(raw) > MAX_JSON:
            raise IntegrationError("The JSON is larger than 64 KB.")
        try:
            obj = json.loads(raw)
        except ValueError as exc:
            raise IntegrationError(f"That isn't valid JSON: {exc}") from None
        if not isinstance(obj, dict):
            raise IntegrationError("The JSON must be one object, in braces.")
        return obj

    def op_guard_create(self, p: dict) -> dict:
        label, path, editable = guard_kind(p.get("kind"))
        if not editable:
            raise IntegrationError(f"{label}s are created in the AI Guard portal.")
        body = {k: v for k, v in self._parse_json(p.get("json")).items() if k not in GUARD_READONLY and k != "id"}
        if not str(body.get("name") or "").strip():
            raise IntegrationError("The object needs a name.")
        got = self._write("POST", path, body)
        oid = got.get("id") if isinstance(got, dict) else None
        return {"message": f"Created {label.lower()} {body['name']}.", "id": oid,
                "what": f"{label.lower()} {body['name']}" + (f" (ID {oid})" if oid else "")}

    def op_guard_update(self, p: dict) -> dict:
        label, path, editable = guard_kind(p.get("kind"))
        if not editable:
            raise IntegrationError(f"{label}s can't be edited here.")
        oid = _id(p.get("id"))
        original = self.api(f"{path}/{oid}")
        edited = self._parse_json(p.get("json"))
        if "id" in edited and str(edited["id"]) != oid:
            raise IntegrationError("The JSON's id doesn't match the object being saved.")
        body = _restore_secrets({k: v for k, v in edited.items() if k not in GUARD_READONLY}, original if isinstance(original, dict) else {})
        body["id"] = int(oid)
        self._write("PUT", f"{path}/{oid}", body)
        return {"message": f"Saved {label.lower()} {body.get('name') or oid}.", "what": f"{label.lower()} {body.get('name') or ''} (ID {oid})"}

    def op_guard_enable(self, p: dict) -> dict:
        return self._guard_toggle(p, True)

    def op_guard_disable(self, p: dict) -> dict:
        return self._guard_toggle(p, False)

    def _guard_toggle(self, p: dict, on: bool) -> dict:
        if p.get("kind") != "rules":
            raise IntegrationError("Only policy match rules can be enabled or disabled.")
        _, path, _ = GUARD_KINDS["rules"]
        oid = _id(p.get("id"))
        rule = self.api(f"{path}/{oid}")
        if not isinstance(rule, dict):
            raise IntegrationError(f"AI Guard has no policy match rule {oid}.")
        body = {k: v for k, v in rule.items() if k not in GUARD_READONLY}
        body["enabled"] = on
        self._write("PUT", f"{path}/{oid}", body)
        return {"message": f"{'Enabled' if on else 'Disabled'} match rule {rule.get('name') or oid}.",
                "what": f"policy match rule {rule.get('name') or ''} (ID {oid})"}

    def op_guard_delete(self, p: dict) -> dict:
        label, path, _ = guard_kind(p.get("kind"))
        oid = _id(p.get("id"))
        obj = self.api(f"{path}/{oid}")
        expect = str((obj or {}).get("name") or oid) if isinstance(obj, dict) else oid
        if str(p.get("confirm_text") or "").strip() != expect:
            raise IntegrationError(f"Type {expect} to delete this {label.lower()}.")
        self._write("DELETE", f"{path}/{oid}")
        return {"message": f"Deleted {label.lower()} {expect}.", "what": f"{label.lower()} {expect} (ID {oid})"}

    def op_guard_regenerate(self, p: dict) -> dict:
        _, path, _ = GUARD_KINDS["app_credentials"]
        oid = _id(p.get("id"))
        obj = self.api(f"{path}/{oid}")
        expect = str((obj or {}).get("name") or oid) if isinstance(obj, dict) else oid
        if str(p.get("confirm_text") or "").strip() != expect:
            raise IntegrationError(f"Type {expect} to regenerate this credential.")
        got = self._write("POST", f"{path}/{oid}/regenerate")
        secret = None
        if isinstance(got, dict):
            secret = next((got[k] for k in ("apiKey", "secret", "key", "token", "value", "credential") if isinstance(got.get(k), str)), None)
        # The secret goes back to the page once; it is never logged (see "what").
        return {"message": f"Regenerated credential {expect}.", "secret": secret, "what": f"application credential {expect} (ID {oid})"}

    # ------------------------------------------------------------------ AI Guard content scan
    @property
    def aiguard_detection_base(self) -> str:
        cloud = str(self.config.get("aiguard_cloud") or "us1").strip().lower()
        if not re.match(r"^[a-z]{2,4}\d{1,2}$", cloud):
            raise IntegrationError("AI Guard cloud must look like us1 or eu1.")
        return f"https://api.{cloud}.zseclipse.net"

    def op_scan(self, p: dict) -> dict:
        """Scan a prompt (IN) or a model response (OUT) with AI Guard. Read-only for the tenant, but AI Guard records
        the scan as a detection event like any other."""
        key = re.sub(r"\s+", "", str(self.config.get("aiguard_api_key") or ""))
        if not key:
            raise IntegrationError("Scanning needs an AI Guard API key in the integration settings. Zscaler only offers "
                                   "the detection API with its own key, not through OneAPI.")
        content = str(p.get("content") or "")
        if not content.strip():
            raise IntegrationError("Paste some text to scan.")
        if len(content) > MAX_SCAN:
            raise IntegrationError("Text to scan is limited to 32 KB here.")
        direction = "OUT" if str(p.get("direction") or "").upper() == "OUT" else "IN"
        body: dict[str, Any] = {"content": content, "direction": direction}
        path = "/v1/detection/resolve-and-execute-policy"
        if p.get("policy_id"):
            body["policyId"] = int(_id(p.get("policy_id"), "policy ID"))
            path = "/v1/detection/execute-policy"
        url = self.aiguard_detection_base + path
        try:
            resp = self.http.post(url, json=body, headers={"Authorization": f"Bearer {key}"})
        except httpx.HTTPError as exc:
            raise IntegrationError(f"Could not reach AI Guard: {exc.__class__.__name__}") from exc
        if resp.status_code in (401, 403):
            raise IntegrationError(f"AI Guard rejected the API key (HTTP {resp.status_code}).")
        if resp.status_code == 429:
            raise IntegrationError("AI Guard is rate limiting this key. Try again in a minute.")
        if resp.status_code >= 400:
            raise IntegrationError(f"AI Guard scan returned HTTP {resp.status_code}.")
        try:
            got = resp.json()
        except ValueError:
            raise IntegrationError("AI Guard answered with something that isn't JSON.") from None
        detectors = []
        for name, d in ((got.get("detectorResponses") or {}).items() if isinstance(got.get("detectorResponses"), dict) else []):
            if isinstance(d, dict):
                detectors.append({"name": name, "triggered": bool(d.get("triggered")), "action": d.get("action"),
                                  "severity": d.get("severity"), "error": d.get("errorMsg")})
        detectors.sort(key=lambda d: (not d["triggered"], d["name"]))
        return {"message": "ok", "scan": {"action": got.get("action"), "severity": got.get("severity"),
                                          "policy": got.get("policyName") or got.get("policyId"), "direction": direction,
                                          "transaction": got.get("transactionId"), "detectors": detectors,
                                          "length": len(content)}}
