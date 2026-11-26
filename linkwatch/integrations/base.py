"""Shared pieces for API integrations.

An integration talks to one platform's API and returns a list of ``Record``
dicts, the same shape for every platform. Integrations marked
``runs_on = "poller"`` reach on-prem gear and are executed by a poller inside
the LAN; ``runs_on = "server"`` ones call cloud APIs from the VPS.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, ClassVar, TypedDict

import httpx

USER_AGENT = "linkwatch/0.1"
STATUSES = ("up", "down", "warn", "unknown", "off")


class IntegrationError(RuntimeError):
    pass


class Record(TypedDict, total=False):
    external_id: str          # stable ID on the platform; required
    hostname: str             # display name; required
    ip: str | None
    type: str                 # Switch, Firewall, Hypervisor, VM, Zscaler...
    platform: str             # model / product and version
    site: str | None
    status: str               # one of STATUSES
    cpu: float | None         # percent
    mem: float | None         # percent
    uptime_s: int | None
    serial: str | None
    detail: str               # one line shown in the UI
    extra: dict[str, Any]


@dataclass(frozen=True)
class Field:
    name: str
    label: str
    kind: str = "text"        # text | password | bool | number
    required: bool = True
    help: str = ""
    default: Any = ""


def verify_field() -> Field:
    return Field("verify_tls", "Verify the TLS certificate", "bool", required=False, default=True,
                 help="Untick for devices that use a self-signed certificate.")


class Integration:
    kind: ClassVar[str] = ""
    label: ClassVar[str] = ""
    runs_on: ClassVar[str] = "server"
    description: ClassVar[str] = ""
    fields: ClassVar[list[Field]] = []

    def __init__(self, config: dict[str, Any], http: httpx.Client | None = None):
        self.config = config
        missing = [f.label for f in self.fields if f.required and f.kind != "bool" and not str(config.get(f.name, "")).strip()]
        if missing:
            raise IntegrationError("Missing: " + ", ".join(missing))
        self._own_http = http is None
        self.http = http or httpx.Client(
            timeout=30.0,
            verify=bool(config.get("verify_tls", True)),
            headers={"User-Agent": USER_AGENT},
            follow_redirects=False,
        )

    def collect(self) -> list[Record]:  # pragma: no cover - abstract
        raise NotImplementedError

    def test(self) -> str:
        records = self.collect()
        return f"Connected. Found {len(records)} object{'s' if len(records) != 1 else ''}."

    def close(self) -> None:
        if self._own_http:
            self.http.close()

    # helpers ------------------------------------------------------------
    def _get(self, url: str, **kw) -> httpx.Response:
        try:
            resp = self.http.get(url, **kw)
        except httpx.HTTPError as exc:
            raise IntegrationError(f"Could not reach {httpx.URL(url).host}: {exc.__class__.__name__}") from exc
        if resp.status_code in (401, 403):
            raise IntegrationError(f"{httpx.URL(url).host} rejected the credentials (HTTP {resp.status_code})")
        if resp.status_code >= 400:
            raise IntegrationError(f"GET {httpx.URL(url).path} returned HTTP {resp.status_code}")
        return resp


def host_url(value: str, default_port: int | None = None) -> str:
    """Accept '10.0.0.1', '10.0.0.1:8006' or 'https://10.0.0.1:8006/' and return 'https://host[:port]'."""
    v = value.strip().rstrip("/")
    if not v.startswith(("http://", "https://")):
        v = "https://" + v
    url = httpx.URL(v)
    port = url.port or default_port
    return f"{url.scheme}://{url.host}" + (f":{port}" if port else "")


def pct(used: float | None, total: float | None) -> float | None:
    if not used or not total:
        return None if total in (None, 0) else 0.0
    return round(100.0 * float(used) / float(total), 1)
