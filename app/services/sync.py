"""Pull ZIA configuration into the store."""
from __future__ import annotations

import logging
from typing import Any

from ..db import Store, utcnow
from ..zia.client import ZiaApiError, ZiaClient
from ..zia.insights import InsightsError, fetch_bandwidth_trend
from ..zia.auth import AuthError, OneApiAuth
from ..zia.policies import fetch_all_rules
from .settings import Settings

log = logging.getLogger(__name__)


def _name(v: Any) -> str | None:
    if isinstance(v, dict):
        return v.get("name")
    return v


def slim_user(u: dict) -> dict:
    return {
        "id": u.get("id"),
        "name": u.get("name"),
        "email": u.get("email"),
        "department": _name(u.get("department")),
        "groups": [g.get("name") for g in u.get("groups") or [] if isinstance(g, dict)],
        "type": u.get("type"),
    }


def slim_location(loc: dict) -> dict:
    return {
        "id": loc.get("id"),
        "name": loc.get("name"),
        "country": loc.get("country"),
        "ip_addresses": loc.get("ipAddresses") or [],
        "vpn_credentials": [_name(v) or v.get("fqdn") for v in loc.get("vpnCredentials") or [] if isinstance(v, dict)],
        "ssl_scan": loc.get("sslScanEnabled"),
        "auth_required": loc.get("authRequired"),
        "parent_id": loc.get("parentId"),
    }


def slim_tunnel(t: dict) -> dict:
    p, s = t.get("primaryDestVip") or {}, t.get("secondaryDestVip") or {}
    return {
        "id": t.get("id"),
        "source_ip": t.get("sourceIp"),
        "comment": t.get("comment"),
        "primary": f"{p.get('datacenter', '')} {p.get('virtualIp', '')}".strip(),
        "secondary": f"{s.get('datacenter', '')} {s.get('virtualIp', '')}".strip(),
    }


def run_sync(store: Store, settings: Settings, client: ZiaClient | None = None) -> dict:
    """Fetch everything the module shows. Partial failures are recorded, not raised."""
    client = client or settings.build_client()
    status: dict[str, Any] = {"started_at": utcnow(), "errors": {}, "counts": {}}
    store.clear_demo()

    def step(kind: str, fn):
        try:
            data = fn()
            store.put_snapshot(kind, data)
            status["counts"][kind] = len(data) if hasattr(data, "__len__") else 1
        except (ZiaApiError, AuthError, InsightsError) as e:
            status["errors"][kind] = str(e)
            log.warning("sync %s failed: %s", kind, e)

    try:
        def rules():
            data, errs = fetch_all_rules(client)
            for k, v in errs.items():
                status["errors"][f"rules: {k}"] = v
            return data

        step("rules", rules)
        step("users", lambda: [slim_user(u) for u in client.get_paged("users")])
        step("groups", lambda: [{"id": g.get("id"), "name": g.get("name")} for g in client.get_paged("groups")])
        step("departments", lambda: [{"id": d.get("id"), "name": d.get("name")} for d in client.get_paged("departments")])
        step("locations", lambda: [slim_location(x) for x in client.get_paged("locations")])
        step("gre_tunnels", lambda: [slim_tunnel(x) for x in client.get_paged("greTunnels")])
        step("activation", lambda: client.get("status") or {})
        if isinstance(client.auth, OneApiAuth) and settings.insights_enabled == "1":
            step("bandwidth", lambda: fetch_bandwidth_trend(client.auth, client.http, query=settings.insights_query or None))
    finally:
        client.close()
    status["finished_at"] = utcnow()
    status["ok"] = not status["errors"]
    store.put_snapshot("sync_status", status)
    return status


def test_connection(settings: Settings, client: ZiaClient | None = None) -> tuple[bool, str]:
    client = client or settings.build_client()
    try:
        rules = client.get("urlFilteringRules") or []
        return True, f"Connected. Read {len(rules)} URL filtering rules."
    except (ZiaApiError, AuthError) as e:
        return False, str(e)
    except Exception as e:  # network errors, bad vanity domain
        return False, f"Could not reach ZIA: {type(e).__name__}"
    finally:
        client.close()
