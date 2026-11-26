"""Import ZIA log exports (CSV or JSON lines) so log lines can be joined to rules.

Without Cloud NSS, ZIA logs leave the portal as exports from the Insights
views (web, firewall, DNS). Column names differ between views and between
portal releases, so headers are matched loosely against a list of aliases.
NSS-style field names (rulelabel, urlfilterrulelabel, dnsreqrulelabel...) are
accepted too, so a future NSS feed can reuse this path.
"""
from __future__ import annotations

import csv
import io
import json
import re
from datetime import datetime, timezone
from typing import Iterable, Iterator

FEEDS = {"web": "Web", "firewall": "Firewall", "dns": "DNS"}
FEED_DEFAULT_POLICY = {"web": "URL filtering", "firewall": "Cloud firewall", "dns": "DNS control"}

ALIASES: dict[str, list[str]] = {
    "ts": ["time", "datetime", "timestamp", "eventtime", "logtime", "date", "datetimeutc", "epochtime"],
    "user": ["user", "login", "username", "userid", "useremail", "userlogin", "email"],
    "department": ["department", "dept"],
    "location": ["location", "locationname"],
    "client_ip": ["clientip", "cip", "sourceip", "srcip", "clientipaddress", "internalip", "csip", "clientsourceip"],
    "destination": ["url", "host", "hostname", "destination", "destinationhost", "dst", "destinationip", "serverip",
                    "sip", "cdip", "domain", "dnsrequest", "request", "req", "query", "sdomain", "dnsreq"],
    "category": ["urlcategory", "category", "urlcat", "dnsreqcat", "dnsrequestcategory", "destinationcategory"],
    "action": ["action", "policyaction", "reqaction", "dnsrequestaction", "dnsaction", "transactionaction"],
    "policy_type": ["ruletype", "policytype", "policy"],
    "bytes_in": ["receivedbytes", "respsize", "responsesize", "responsebytes", "inbytes", "bytesreceived", "inboundbytes"],
    "bytes_out": ["sentbytes", "reqsize", "requestsize", "requestbytes", "outbytes", "bytessent", "outboundbytes"],
    "bytes_total": ["totalbytes", "bytes", "totalsize", "transactionsize"],
}

# Rule columns, most specific first, with the policy type each implies.
RULE_COLUMNS: list[tuple[str, str | None]] = [
    ("urlfilterrulelabel", "URL filtering"), ("urlfilterrule", "URL filtering"), ("urlfilteringrule", "URL filtering"),
    ("urlfilteringrulename", "URL filtering"),
    ("cloudapprule", "Cloud app control"), ("cloudappcontrolrule", "Cloud app control"), ("apprulelabel", "Cloud app control"),
    ("dlprulename", "DLP"), ("dlprule", "DLP"),
    ("dnsreqrulelabel", "DNS control"), ("dnsresrulelabel", "DNS control"), ("dnsrule", "DNS control"),
    ("dnscontrolrule", "DNS control"), ("dnsrequestrule", "DNS control"), ("dnsresponserule", "DNS control"),
    ("firewallrule", "Cloud firewall"), ("fwrule", "Cloud firewall"), ("firewallrulename", "Cloud firewall"),
    ("ipsrulelabel", "IPS control"), ("ipsrule", "IPS control"),
    ("sslrule", "SSL inspection"), ("sslinspectionrule", "SSL inspection"),
    ("filetyperule", "File type control"), ("sandboxrule", "Sandbox"),
    ("rulelabel", None), ("rulename", None), ("rule", None), ("policyname", None),
]

TS_FORMATS = (
    "%a %b %d %H:%M:%S %Y",      # NSS default: Mon Jun 20 15:29:11 2022
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%m/%d/%Y %H:%M:%S",
    "%m/%d/%Y %I:%M:%S %p",
    "%m/%d/%Y %H:%M",
    "%d/%m/%Y %H:%M:%S",
    "%b %d, %Y %I:%M:%S %p",
    "%B %d, %Y %I:%M:%S %p",
)


def norm(header: str) -> str:
    return re.sub(r"[^a-z0-9]", "", header.lower())


def parse_ts(value: str) -> str | None:
    """Return ISO-8601 UTC. Values without a zone are taken as UTC."""
    v = (value or "").strip()
    if not v:
        return None
    if re.fullmatch(r"\d{10}(\d{3})?", v):
        n = int(v)
        return datetime.fromtimestamp(n / 1000 if n > 1e11 else n, tz=timezone.utc).isoformat(timespec="seconds")
    try:
        dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        dt = None
        cleaned = re.sub(r"\s+(UTC|GMT)$", "", v)
        for fmt in TS_FORMATS:
            try:
                dt = datetime.strptime(cleaned, fmt)
                break
            except ValueError:
                continue
        if dt is None:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


def normalise_action(value: str) -> str:
    v = (value or "").strip().lower()
    if not v:
        return "Other"
    if "isolat" in v:
        return "Isolated"
    if "caution" in v:
        return "Caution"
    if any(w in v for w in ("block", "drop", "deny", "reset", "quarantine", "denied")):
        return "Blocked"
    if any(w in v for w in ("allow", "permit", "pass", "accept")):
        return "Allowed"
    return "Other"


def _int(value) -> int:
    try:
        return int(float(str(value).replace(",", "")))
    except (TypeError, ValueError):
        return 0


class ColumnMap:
    def __init__(self, headers: Iterable[str]):
        self.headers = list(headers)
        by_norm = {norm(h): h for h in self.headers}
        self.fields: dict[str, str] = {}
        for field, aliases in ALIASES.items():
            for a in aliases:
                if a in by_norm:
                    self.fields[field] = by_norm[a]
                    break
        self.rule_cols = [(by_norm[n], pt) for n, pt in RULE_COLUMNS if n in by_norm]
        used = set(self.fields.values()) | {h for h, _ in self.rule_cols}
        self.unmapped = [h for h in self.headers if h not in used]

    @property
    def usable(self) -> bool:
        return "ts" in self.fields and (bool(self.rule_cols) or "action" in self.fields)

    def missing(self) -> list[str]:
        out = []
        if "ts" not in self.fields:
            out.append("a time column")
        if not self.rule_cols:
            out.append("a rule name column")
        if "user" not in self.fields:
            out.append("a user column")
        return out


def to_event(row: dict, cmap: ColumnMap, feed: str, import_id: int | None) -> dict | None:
    g = lambda f: (row.get(cmap.fields[f]) or "").strip() if f in cmap.fields else ""
    ts = parse_ts(g("ts"))
    if not ts:
        return None
    rule_label, policy_type = "", g("policy_type") or None
    for col, implied in cmap.rule_cols:
        val = (row.get(col) or "").strip()
        if val and val.lower() not in ("none", "n/a", "-", "null"):
            rule_label = val
            policy_type = policy_type or implied
            break
    bytes_in, bytes_out = _int(g("bytes_in")), _int(g("bytes_out"))
    if not bytes_in and not bytes_out:
        bytes_in = _int(g("bytes_total"))
    return {
        "ts": ts,
        "user": g("user") or None,
        "department": g("department") or None,
        "location": g("location") or None,
        "client_ip": g("client_ip") or None,
        "destination": g("destination") or None,
        "category": g("category") or None,
        "action": normalise_action(g("action")),
        "policy_type": policy_type or FEED_DEFAULT_POLICY.get(feed),
        "rule_label": rule_label or None,
        "bytes_in": bytes_in,
        "bytes_out": bytes_out,
        "import_id": import_id,
        "raw": json.dumps(row, default=str)[:4000],
    }


def read_rows(content: bytes) -> tuple[list[str], Iterator[dict]]:
    text = content.decode("utf-8-sig", errors="replace")
    stripped = text.lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        if stripped.startswith("["):
            records = json.loads(stripped)
        else:
            records = [json.loads(line) for line in text.splitlines() if line.strip()]
        records = [r.get("event", r) if isinstance(r, dict) else {} for r in records]
        headers = sorted({k for r in records for k in r})
        return headers, iter([{k: ("" if v is None else str(v)) for k, v in r.items()} for r in records])
    # Portal exports sometimes start with report-title lines before the header row.
    lines = text.splitlines()
    start = 0
    for i, line in enumerate(lines[:30]):
        if line.count(",") >= 3 and any(norm(c) in ALIASES["ts"] for c in next(csv.reader([line]))):
            start = i
            break
    reader = csv.DictReader(io.StringIO("\n".join(lines[start:])))
    return list(reader.fieldnames or []), reader


def parse_upload(content: bytes, feed: str, import_id: int | None = None) -> tuple[list[dict], int, ColumnMap]:
    headers, rows = read_rows(content)
    cmap = ColumnMap(headers)
    if not cmap.usable:
        return [], 0, cmap
    events, skipped = [], 0
    for row in rows:
        ev = to_event(row, cmap, feed, import_id)
        if ev:
            events.append(ev)
        else:
            skipped += 1
    return events, skipped, cmap
