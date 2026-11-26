"""Connection settings kept in the store, with secrets encrypted."""
from __future__ import annotations

from dataclasses import dataclass

import httpx
from cryptography.fernet import Fernet

from ..crypto import decrypt, encrypt
from ..db import Store
from ..zia.auth import ONEAPI_DEFAULT_BASE, LegacyAuth, OneApiAuth
from ..zia.client import ZiaClient

PLAIN = ("mode", "vanity_domain", "client_id", "oneapi_base", "cloud", "username", "insights_enabled",
         "insights_query", "log_retention_days")
SECRET = ("client_secret", "password", "api_key")


@dataclass
class Settings:
    mode: str = "oneapi"          # oneapi | legacy
    vanity_domain: str = ""
    client_id: str = ""
    client_secret: str = ""
    oneapi_base: str = ONEAPI_DEFAULT_BASE
    cloud: str = "zscaler.net"
    username: str = ""
    password: str = ""
    api_key: str = ""
    insights_enabled: str = "1"
    insights_query: str = ""
    log_retention_days: str = "30"

    @property
    def configured(self) -> bool:
        if self.mode == "legacy":
            return all([self.cloud, self.username, self.password, self.api_key])
        return all([self.vanity_domain, self.client_id, self.client_secret])

    def build_auth(self) -> OneApiAuth | LegacyAuth:
        if self.mode == "legacy":
            return LegacyAuth(self.cloud, self.username, self.password, self.api_key)
        return OneApiAuth(self.vanity_domain, self.client_id, self.client_secret, self.oneapi_base or ONEAPI_DEFAULT_BASE)

    def build_client(self, http: httpx.Client | None = None) -> ZiaClient:
        return ZiaClient(self.build_auth(), http=http)


def load_settings(store: Store, f: Fernet) -> Settings:
    s = Settings()
    for k in PLAIN:
        v = store.get_setting(k)
        if v is not None:
            setattr(s, k, v)
    for k in SECRET:
        v = store.get_setting(k)
        if v:
            setattr(s, k, decrypt(f, v) or "")
    return s


def save_settings(store: Store, f: Fernet, form: dict[str, str]) -> None:
    """Blank secret fields keep the stored value so the page never has to echo secrets back."""
    for k in PLAIN:
        if k in form:
            store.set_setting(k, form[k].strip())
    for k in SECRET:
        v = form.get(k, "")
        if v:
            store.set_setting(k, encrypt(f, v))
