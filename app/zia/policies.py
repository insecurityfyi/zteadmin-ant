"""ZIA policy endpoints and normalisation of their rules into one shape.

Each ZIA policy type returns rules with different field names. The toolbox
flattens them so the UI and the log correlation can treat them alike.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from .client import ZiaApiError, ZiaClient

# policy type label -> ZIA v1 path
POLICY_ENDPOINTS: dict[str, str] = {
    "URL filtering": "urlFilteringRules",
    "Cloud firewall": "firewallFilteringRules",
    "DNS control": "firewallDnsRules",
    "IPS control": "firewallIpsRules",
    "SSL inspection": "sslInspectionRules",
    "File type control": "fileTypeRules",
    "Sandbox": "sandboxRules",
    "DLP": "webDlpRules",
}
CLOUD_APP = "Cloud app control"
POLICY_TYPES = ["URL filtering", CLOUD_APP, *[t for t in POLICY_ENDPOINTS if t != "URL filtering"]]

# Criteria fields worth showing, in display order, with a friendly label.
CRITERIA_FIELDS = [
    ("urlCategories", "URL categories"),
    ("applications", "Applications"),
    ("nwServices", "Network services"),
    ("nwServiceGroups", "Network service groups"),
    ("nwApplications", "Network applications"),
    ("destIpCategories", "Destination categories"),
    ("destAddresses", "Destination addresses"),
    ("destCountries", "Destination countries"),
    ("threatCategories", "Threat categories"),
    ("fileTypes", "File types"),
    ("dlpEngines", "DLP engines"),
    ("protocols", "Protocols"),
    ("requestMethods", "Request methods"),
]
SCOPE_FIELDS = [
    ("users", "Users"), ("groups", "Groups"), ("departments", "Departments"),
    ("locations", "Locations"), ("locationGroups", "Location groups"),
]


@dataclass
class Rule:
    id: str
    policy_type: str
    name: str
    order: int | None
    state: str
    action: str           # Allowed | Blocked | Isolated | Caution | Other
    raw_action: str
    applies_to: str
    criteria: list[tuple[str, str]] = field(default_factory=list)
    description: str = ""
    last_modified: str | None = None
    last_modified_by: str | None = None
    isolation_profile: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def classify_action(raw: str) -> str:
    """Map ZIA action strings (ALLOW, BLOCK_DROP, ISOLATE_WEBMAIL_VIEW, DO_NOT_DECRYPT...) to four buckets."""
    a = (raw or "").upper()
    if "ISOLATE" in a:
        return "Isolated"
    if "CAUTION" in a:
        return "Caution"
    if "BLOCK" in a or a in ("DROP", "RESET", "QUARANTINE") or "DENY" in a:
        return "Blocked"
    if "ALLOW" in a or "DECRYPT" in a or a in ("BYPASS_IPS", "REDIR_REQ", "REDIR_RES", "EVAL_NWAPP"):
        return "Allowed"
    return "Other" if a else "Other"


def _names(value: Any) -> list[str]:
    if not value:
        return []
    if isinstance(value, list):
        out = []
        for v in value:
            if isinstance(v, dict):
                out.append(str(v.get("name") or v.get("id")))
            else:
                out.append(str(v))
        return out
    if isinstance(value, dict):
        return [str(value.get("name") or value.get("id"))]
    return [str(value)]


def _summarise(values: list[str], limit: int = 6) -> str:
    if len(values) <= limit:
        return ", ".join(values)
    return ", ".join(values[:limit]) + f" and {len(values) - limit} more"


def _raw_action(rule: dict) -> str:
    for key in ("action", "filteringAction", "baRuleAction"):
        val = rule.get(key)
        if isinstance(val, dict):  # SSL inspection: {"type": "DECRYPT", ...}
            return str(val.get("type", ""))
        if isinstance(val, str):
            return val
    actions = rule.get("actions")  # cloud app control: list of action strings
    if isinstance(actions, list) and actions:
        # A rule that isolates or blocks anything is reported by its strongest action.
        for bucket in ("ISOLATE", "BLOCK", "CAUTION"):
            hit = next((x for x in actions if bucket in str(x).upper()), None)
            if hit:
                return str(hit)
        return str(actions[0])
    return ""


def _ts(epoch: Any) -> str | None:
    try:
        return datetime.fromtimestamp(int(epoch), tz=timezone.utc).isoformat(timespec="seconds")
    except (TypeError, ValueError, OSError):
        return None


def normalise_rule(policy_type: str, rule: dict) -> Rule:
    raw = _raw_action(rule)
    scope = []
    for key, label in SCOPE_FIELDS:
        names = _names(rule.get(key))
        if names:
            scope.append(f"{label}: {_summarise(names, 4)}")
    criteria = []
    for key, label in CRITERIA_FIELDS:
        names = _names(rule.get(key))
        if names:
            criteria.append((label, _summarise(names)))
    cbi = rule.get("cbiProfile") or {}
    return Rule(
        id=str(rule.get("id", "")),
        policy_type=policy_type,
        name=str(rule.get("name", "")),
        order=rule.get("order"),
        state=str(rule.get("state", "ENABLED")),
        action=classify_action(raw),
        raw_action=raw,
        applies_to="; ".join(scope) or "All",
        criteria=criteria,
        description=str(rule.get("description") or ""),
        last_modified=_ts(rule.get("lastModifiedTime")),
        last_modified_by=(_names(rule.get("lastModifiedBy")) or [None])[0],
        isolation_profile=cbi.get("name") if isinstance(cbi, dict) else None,
    )


def fetch_all_rules(client: ZiaClient) -> tuple[list[dict], dict[str, str]]:
    """Fetch every policy type. Returns normalised rules and per-type errors (missing licence, no role...)."""
    rules: list[Rule] = []
    errors: dict[str, str] = {}
    for ptype, path in POLICY_ENDPOINTS.items():
        try:
            for r in client.get(path) or []:
                rules.append(normalise_rule(ptype, r))
        except ZiaApiError as e:
            errors[ptype] = str(e)
    # Cloud app control rules are listed per rule type (WEBMAIL, STREAMING_MEDIA, AI_ML, ...).
    try:
        mapping = client.get("webApplicationRules/ruleTypeMapping") or {}
        rule_types = list(mapping.values()) if isinstance(mapping, dict) else list(mapping)
        for rtype in rule_types:
            for r in client.get(f"webApplicationRules/{rtype}") or []:
                rules.append(normalise_rule(CLOUD_APP, r))
    except ZiaApiError as e:
        errors[CLOUD_APP] = str(e)
    rules.sort(key=lambda r: (POLICY_TYPES.index(r.policy_type), r.order if r.order is not None else 1 << 30))
    return [r.to_dict() for r in rules], errors
