"""Read-only ZIA API client with paging and rate-limit handling."""
from __future__ import annotations

import re
import time
from typing import Any, Callable

import httpx

from .auth import LegacyAuth, OneApiAuth

Auth = OneApiAuth | LegacyAuth


class ZiaApiError(RuntimeError):
    def __init__(self, path: str, status: int, detail: str = ""):
        super().__init__(f"GET {path} returned HTTP {status} {detail}".strip())
        self.path = path
        self.status = status


def _retry_after_seconds(resp: httpx.Response) -> float:
    """ZIA sends Retry-After as a header, or in the body as e.g. {"Retry-After": "2 seconds"}."""
    raw = resp.headers.get("Retry-After")
    if raw is None:
        try:
            raw = str(resp.json().get("Retry-After", ""))
        except ValueError:
            raw = ""
    m = re.search(r"\d+(\.\d+)?", raw or "")
    return min(float(m.group()) if m else 2.0, 60.0)


class ZiaClient:
    def __init__(
        self,
        auth: Auth,
        http: httpx.Client | None = None,
        max_retries: int = 4,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self.auth = auth
        self.http = http or httpx.Client(timeout=30.0, headers={"User-Agent": "zteadmin-ant/0.1"})
        self.max_retries = max_retries
        self._sleep = sleep

    @property
    def base_url(self) -> str:
        return self.auth.base_url.rstrip("/")

    def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        url = f"{self.base_url}/{path.lstrip('/')}"
        reauthed = False
        for attempt in range(self.max_retries + 1):
            resp = self.http.get(url, params=params, headers=self.auth.headers(self.http))
            if resp.status_code == 429 and attempt < self.max_retries:
                self._sleep(_retry_after_seconds(resp))
                continue
            if resp.status_code == 401 and not reauthed:
                self.auth.invalidate()
                reauthed = True
                continue
            if resp.status_code >= 400:
                raise ZiaApiError(path, resp.status_code)
            return resp.json() if resp.content else None
        raise ZiaApiError(path, 429, "after retries")

    def get_paged(self, path: str, page_size: int = 500, max_pages: int = 200, params: dict | None = None) -> list:
        """ZIA list endpoints page with ``page`` (1-based) and ``pageSize``."""
        items: list = []
        for page in range(1, max_pages + 1):
            chunk = self.get(path, params={**(params or {}), "page": page, "pageSize": page_size})
            if not chunk:
                break
            items.extend(chunk)
            if len(chunk) < page_size:
                break
        return items

    def close(self) -> None:
        self.auth.close(self.http)
        self.http.close()
