"""Authentication for the ZIA API.

Two modes are supported:

* OneAPI: an OAuth 2.0 client-credentials token from ZIdentity
  (``https://<vanity>.zslogin.net/oauth2/v1/token``), sent as a Bearer token to
  ``https://api.zsapi.net/zia/api/v1``.
* Legacy: an obfuscated API key, admin username and password posted to
  ``https://zsapi.<cloud>/api/v1/authenticatedSession``; the returned
  JSESSIONID cookie authenticates later calls.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

import httpx

ONEAPI_AUDIENCE = "https://api.zscaler.com"
ONEAPI_DEFAULT_BASE = "https://api.zsapi.net/zia/api/v1"

ZIA_CLOUDS = (
    "zscaler.net", "zscalerone.net", "zscalertwo.net", "zscalerthree.net",
    "zscloud.net", "zscalerbeta.net", "zscalergov.net", "zscalerten.net", "zspreview.net",
)


class AuthError(RuntimeError):
    pass


def obfuscate_api_key(api_key: str, timestamp_ms: int) -> str:
    """Zscaler's documented key obfuscation for the legacy authenticatedSession call."""
    now = str(timestamp_ms)
    n = now[-6:]
    r = str(int(n) >> 1).zfill(6)
    key = "".join(api_key[int(c)] for c in n)
    key += "".join(api_key[int(c) + 2] for c in r)
    return key


@dataclass
class OneApiAuth:
    vanity_domain: str
    client_id: str
    client_secret: str
    base_url: str = ONEAPI_DEFAULT_BASE
    _token: str | None = field(default=None, repr=False)
    _expires_at: float = 0.0

    @property
    def token_url(self) -> str:
        return f"https://{self.vanity_domain}.zslogin.net/oauth2/v1/token"

    def headers(self, http: httpx.Client) -> dict[str, str]:
        if not self._token or time.time() > self._expires_at - 60:
            self._refresh(http)
        return {"Authorization": f"Bearer {self._token}"}

    def _refresh(self, http: httpx.Client) -> None:
        resp = http.post(
            self.token_url,
            data={
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "audience": ONEAPI_AUDIENCE,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if resp.status_code != 200:
            raise AuthError(f"ZIdentity token request failed with HTTP {resp.status_code}")
        body = resp.json()
        self._token = body["access_token"]
        self._expires_at = time.time() + int(body.get("expires_in", 3600))

    def invalidate(self) -> None:
        self._token = None

    def close(self, http: httpx.Client) -> None:  # nothing to revoke
        self._token = None


@dataclass
class LegacyAuth:
    cloud: str
    username: str
    password: str
    api_key: str
    _cookie: str | None = field(default=None, repr=False)
    _logged_in_at: float = 0.0

    @property
    def base_url(self) -> str:
        return f"https://zsapi.{self.cloud}/api/v1"

    def headers(self, http: httpx.Client) -> dict[str, str]:
        # Legacy sessions idle out after about 30 minutes; renew well before that.
        if not self._cookie or time.time() - self._logged_in_at > 25 * 60:
            self._login(http)
        return {"Cookie": f"JSESSIONID={self._cookie}"}

    def _login(self, http: httpx.Client) -> None:
        ts = int(time.time() * 1000)
        resp = http.post(
            f"{self.base_url}/authenticatedSession",
            json={
                "apiKey": obfuscate_api_key(self.api_key, ts),
                "username": self.username,
                "password": self.password,
                "timestamp": ts,
            },
        )
        if resp.status_code != 200 or "JSESSIONID" not in resp.cookies:
            raise AuthError(f"ZIA legacy login failed with HTTP {resp.status_code}")
        self._cookie = resp.cookies["JSESSIONID"]
        self._logged_in_at = time.time()

    def invalidate(self) -> None:
        self._cookie = None

    def close(self, http: httpx.Client) -> None:
        if self._cookie:
            try:
                http.delete(f"{self.base_url}/authenticatedSession", headers={"Cookie": f"JSESSIONID={self._cookie}"})
            except httpx.HTTPError:
                pass
            self._cookie = None
