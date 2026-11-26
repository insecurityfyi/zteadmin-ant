"""Z-Insights analytics (GraphQL over OneAPI) for traffic trends.

EXPERIMENTAL: the query below follows Zscaler's published Z-Insights examples
but has not been verified against a live tenant yet. The query text can be
overridden on the API setup page, and any failure is shown there rather than
breaking the dashboard; bandwidth then falls back to imported logs.
"""
from __future__ import annotations

import time
from typing import Any

import httpx

from .auth import OneApiAuth

ZINS_URL = "https://api.zsapi.net/zins/graphql"

DEFAULT_QUERY = """
query ($start: Long!, $end: Long!) {
  WEB_TRAFFIC {
    no_grouping(start_time: $start, end_time: $end, traffic_unit: BYTES) {
      entries { name total trend { time_stamp values } }
    }
  }
}
""".strip()


class InsightsError(RuntimeError):
    pass


def fetch_bandwidth_trend(auth: OneApiAuth, http: httpx.Client, days: int = 7, query: str | None = None,
                          url: str = ZINS_URL) -> list[dict[str, Any]]:
    """Return [{"t": epoch_ms, "bytes": n}, ...] for the last ``days`` days."""
    end = int(time.time() * 1000)
    start = end - days * 86400 * 1000
    resp = http.post(url, json={"query": query or DEFAULT_QUERY, "variables": {"start": start, "end": end}},
                     headers=auth.headers(http))
    if resp.status_code != 200:
        raise InsightsError(f"Z-Insights returned HTTP {resp.status_code}")
    body = resp.json()
    if body.get("errors"):
        raise InsightsError("Z-Insights query error: " + "; ".join(str(e.get("message")) for e in body["errors"]))
    return parse_trend(body)


def parse_trend(body: dict) -> list[dict[str, Any]]:
    """Find the first ``trend`` block anywhere in the response and flatten it."""
    def walk(node: Any):
        if isinstance(node, dict):
            if "trend" in node and isinstance(node["trend"], dict):
                yield node["trend"]
            for v in node.values():
                yield from walk(v)
        elif isinstance(node, list):
            for v in node:
                yield from walk(v)

    for trend in walk(body.get("data", {})):
        stamps = trend.get("time_stamp") or []
        values = trend.get("values") or []
        return [{"t": int(t), "bytes": float(v or 0)} for t, v in zip(stamps, values)]
    raise InsightsError("Z-Insights response had no trend data")
