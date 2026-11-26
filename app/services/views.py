"""Shape stored data for each page."""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from ..db import Store
from ..zia.policies import POLICY_TYPES

ACTIONS = ["Allowed", "Blocked", "Isolated", "Caution", "Other"]


def _parse(iso: str) -> datetime:
    return datetime.fromisoformat(iso)


def window_end(store: Store) -> datetime:
    """Windows end at the newest log event, so an export from last week still fills a 7-day view."""
    row = store.query("SELECT MAX(ts) AS m FROM log_events")[0]
    now = datetime.now(timezone.utc)
    if row["m"]:
        return min(now, _parse(row["m"]))
    return now


def rule_index(store: Store) -> tuple[list[dict], dict[tuple[str, str], dict], dict[str, list[dict]]]:
    rules = store.snapshot_data("rules", []) or []
    by_type_name = {(r["policy_type"], r["name"].lower()): r for r in rules}
    by_name: dict[str, list[dict]] = defaultdict(list)
    for r in rules:
        by_name[r["name"].lower()].append(r)
    return rules, by_type_name, by_name


def match_rule(ev: dict, by_type_name, by_name) -> dict | None:
    label = (ev.get("rule_label") or "").lower()
    if not label:
        return None
    hit = by_type_name.get((ev.get("policy_type"), label))
    if hit:
        return hit
    candidates = by_name.get(label) or []
    return candidates[0] if len(candidates) == 1 else (candidates[0] if candidates else None)


def events_in_window(store: Store, hours: int, end: datetime | None = None) -> list[dict]:
    end = end or window_end(store)
    start = end - timedelta(hours=hours)
    return store.query("SELECT * FROM log_events WHERE ts > ? AND ts <= ? ORDER BY ts DESC",
                       (start.isoformat(timespec="seconds"), end.isoformat(timespec="seconds")))


def bandwidth_series(store: Store, end: datetime) -> tuple[list[dict], str]:
    """Hourly bytes for 7 days. Z-Insights when synced, else summed from imported logs."""
    snap = store.get_snapshot("bandwidth")
    if snap and snap["data"]:
        pts = [{"t": p["t"], "down": p["bytes"], "up": 0} for p in snap["data"]]
        return pts, "Z-Insights" + (" (sample)" if snap["demo"] else "")
    buckets: dict[int, list[int]] = defaultdict(lambda: [0, 0])
    for ev in events_in_window(store, 168, end):
        hour = int(_parse(ev["ts"]).replace(minute=0, second=0).timestamp() * 1000)
        buckets[hour][0] += ev["bytes_in"] or 0
        buckets[hour][1] += ev["bytes_out"] or 0
    start = int((end - timedelta(hours=167)).replace(minute=0, second=0, microsecond=0).timestamp() * 1000)
    pts = [{"t": start + i * 3600_000, "down": buckets[start + i * 3600_000][0], "up": buckets[start + i * 3600_000][1]}
           for i in range(168)]
    return (pts if any(p["down"] or p["up"] for p in pts) else []), "imported logs"


def overview(store: Store) -> dict:
    end = window_end(store)
    events = events_in_window(store, 168, end)
    rules, by_tn, by_n = rule_index(store)
    users_dir = store.snapshot_data("users", []) or []
    locations = store.snapshot_data("locations", []) or []
    tunnels = store.snapshot_data("gre_tunnels", []) or []

    by_type: dict[str, Counter] = defaultdict(Counter)
    rule_blocks: Counter = Counter()
    loc_users: dict[str, set] = defaultdict(set)
    loc_bytes: Counter = Counter()
    total_bytes = 0
    for ev in events:
        by_type[ev["policy_type"] or "Unknown"][ev["action"]] += 1
        b = (ev["bytes_in"] or 0) + (ev["bytes_out"] or 0)
        total_bytes += b
        if ev["location"]:
            loc_users[ev["location"]].add(ev["user"])
            loc_bytes[ev["location"]] += b
        if ev["action"] in ("Blocked", "Isolated"):
            rule_blocks[(ev["policy_type"], ev["rule_label"])] += 1

    hits = Counter((ev["policy_type"], (ev["rule_label"] or "").lower()) for ev in events)
    unused = [r for r in rules if r["state"] == "ENABLED" and not hits.get((r["policy_type"], r["name"].lower()))
              and not r["name"].lower().startswith("default")] if events else []
    disabled = [r for r in rules if r["state"] != "ENABLED"]
    activation = store.snapshot_data("activation", {}) or {}
    blocked = sum(c["Blocked"] for c in by_type.values())
    isolated = sum(c["Isolated"] for c in by_type.values())
    series, series_src = bandwidth_series(store, end)
    bw_total = sum(p["down"] + p["up"] for p in series) if series_src.startswith("Z-Insights") else total_bytes

    type_rows = []
    for t in POLICY_TYPES + sorted(set(by_type) - set(POLICY_TYPES)):
        c = by_type.get(t)
        if c:
            type_rows.append({"type": t, "counts": {a: c[a] for a in ACTIONS}, "total": sum(c.values())})
    return {
        "end": end,
        "kpis": {
            "users_seen": len({e["user"] for e in events if e["user"]}),
            "users_directory": len(users_dir),
            "bandwidth": bw_total,
            "transactions": len(events),
            "blocked_pct": (blocked / len(events) * 100) if events else None,
            "isolated": isolated,
            "rules": len(rules),
            "locations": len(locations),
        },
        "series": series,
        "series_source": series_src,
        "by_type": type_rows,
        "top_blockers": [{"policy_type": k[0], "rule": k[1] or "(no rule label)", "count": v}
                         for k, v in rule_blocks.most_common(8)],
        "locations": sorted(
            [{"name": loc["name"], "country": loc.get("country"), "users": len(loc_users.get(loc["name"], ())),
              "bytes": loc_bytes.get(loc["name"], 0), "tunnels": len(loc.get("vpn_credentials") or [])}
             for loc in locations], key=lambda x: -x["bytes"])[:10],
        "tunnels": tunnels,
        "health": {
            "unused": unused,
            "disabled": disabled,
            "activation": activation.get("status") if isinstance(activation, dict) else None,
            "has_logs": bool(events),
        },
    }


def users(store: Store, hours: int, q: str = "") -> dict:
    end = window_end(store)
    directory = {(u.get("email") or u.get("name") or "").lower(): u for u in store.snapshot_data("users", []) or []}
    agg: dict[str, dict] = {}
    for ev in events_in_window(store, hours, end):
        if not ev["user"]:
            continue
        a = agg.setdefault(ev["user"], {"user": ev["user"], "department": ev["department"], "location": ev["location"],
                                        "last_seen": ev["ts"], "first_seen": ev["ts"], "tx": 0, "bytes": 0,
                                        "Blocked": 0, "Isolated": 0, "Caution": 0})
        a["tx"] += 1
        a["bytes"] += (ev["bytes_in"] or 0) + (ev["bytes_out"] or 0)
        a["first_seen"] = ev["ts"]  # events come newest first
        if ev["action"] in a:
            a[ev["action"]] += 1
        a["location"] = a["location"] or ev["location"]
    rows = []
    for a in agg.values():
        d = directory.get(a["user"].lower())
        if d:
            a["department"] = a["department"] or d.get("department")
            a["display_name"] = d.get("name")
            a["groups"] = d.get("groups") or []
        if q and q.lower() not in json.dumps(a).lower():
            continue
        rows.append(a)
    rows.sort(key=lambda r: r["last_seen"], reverse=True)
    return {"end": end, "rows": rows, "directory_count": len(directory), "hours": hours}


def logs(store: Store, policy_type: str = "", action: str = "", q: str = "", limit: int = 300) -> dict:
    sql, params = "SELECT * FROM log_events WHERE 1=1", []
    if policy_type:
        sql += " AND policy_type = ?"
        params.append(policy_type)
    if action:
        sql += " AND action = ?"
        params.append(action)
    if q:
        sql += " AND (user LIKE ? OR destination LIKE ? OR rule_label LIKE ? OR client_ip LIKE ?)"
        params += [f"%{q}%"] * 4
    total = store.query(sql.replace("SELECT *", "SELECT COUNT(*) AS n"), params)[0]["n"]
    rows = store.query(sql + " ORDER BY ts DESC LIMIT ?", [*params, limit])
    _, by_tn, by_n = rule_index(store)
    for r in rows:
        r["rule"] = match_rule(r, by_tn, by_n)
        r["raw"] = json.loads(r["raw"] or "{}")
    return {"rows": rows, "total": total}


def rules_with_hits(store: Store, policy_type: str = "") -> dict:
    end = window_end(store)
    events = events_in_window(store, 168, end)
    hits: Counter = Counter()
    last: dict = {}
    for ev in events:
        key = (ev["policy_type"], (ev["rule_label"] or "").lower())
        hits[key] += 1
        last.setdefault(key, ev["ts"])
    rules = store.snapshot_data("rules", []) or []
    rows = []
    for r in rules:
        if policy_type and r["policy_type"] != policy_type:
            continue
        key = (r["policy_type"], r["name"].lower())
        rows.append(r | {"hits": hits.get(key, 0), "last_hit": last.get(key)})
    return {"rows": rows, "has_logs": bool(events), "end": end}
