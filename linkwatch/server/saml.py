"""SAML 2.0 single sign-on (service provider side), written for Microsoft Entra ID.

Flow: /saml/login sends the browser to the IdP with a signed-nothing AuthnRequest
(HTTP-Redirect binding; Entra doesn't need it signed). The IdP posts a
SAMLResponse to /saml/acs. We only trust what is inside the XML signature that
verifies against the IdP certificate from its metadata, so a forged or wrapped
assertion is ignored, then check issuer, audience, recipient, time window,
InResponseTo (against requests we started) and replay.

Settings live in the settings table as JSON under "saml". None of them are
secret: the IdP certificate is public.
"""
from __future__ import annotations

import base64
import json
import secrets
import threading
import time
import zlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlencode

from lxml import etree
from signxml import InvalidInput, InvalidSignature, XMLVerifier
from sqlalchemy.orm import Session

from .db import get_setting, set_setting

NS = {"md": "urn:oasis:names:tc:SAML:2.0:metadata", "ds": "http://www.w3.org/2000/09/xmldsig#",
      "samlp": "urn:oasis:names:tc:SAML:2.0:protocol", "saml": "urn:oasis:names:tc:SAML:2.0:assertion"}
REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"
SKEW = timedelta(minutes=3)

CLAIM_GROUPS = "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"
CLAIM_ROLES = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role"
CLAIM_GROUPS_LINK = "http://schemas.microsoft.com/claims/groups.link"
CLAIM_UPN = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"
CLAIM_EMAIL = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
CLAIM_DISPLAY = "http://schemas.microsoft.com/identity/claims/displayname"
CLAIM_GIVEN = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"
CLAIM_SURNAME = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"
CLAIM_OID = "http://schemas.microsoft.com/identity/claims/objectidentifier"

_PARSER = etree.XMLParser(resolve_entities=False, no_network=True, huge_tree=False, remove_comments=True, load_dtd=False)


class SamlError(ValueError):
    """A sign-in that must be refused. The message is safe to show to the user."""


# ------------------------------------------------------------------ settings
@dataclass
class SamlSettings:
    enabled: bool = False
    metadata_url: str = ""
    idp_entity_id: str = ""
    idp_sso_url: str = ""
    idp_certs: list[str] = field(default_factory=list)       # base64 DER, as in the metadata
    metadata_fetched: str | None = None                     # ISO time of the last good fetch
    sp_entity_id: str = ""                                  # blank: <public url>/saml/metadata
    button_label: str = "Sign in with Microsoft"
    admin_values: list[str] = field(default_factory=list)   # group object IDs or app role values
    viewer_values: list[str] = field(default_factory=list)
    default_role: str = "none"                              # none | viewer, when nothing matches
    jit: bool = True                                        # create users on first sign-in
    sync_role: bool = True                                  # update the role from the IdP at every sign-in
    local_login: str = "all"                                # all | admins: who may still use a password
    allow_idp_initiated: bool = False

    @classmethod
    def load(cls, s: Session) -> "SamlSettings":
        try:
            raw = json.loads(get_setting(s, "saml") or "{}")
        except ValueError:
            raw = {}
        known = {k: v for k, v in raw.items() if k in cls.__dataclass_fields__}
        return cls(**known)

    def save(self, s: Session) -> None:
        set_setting(s, "saml", json.dumps(self.__dict__))

    def sp_entity(self, public_url: str) -> str:
        return self.sp_entity_id.strip() or f"{public_url.rstrip('/')}/saml/metadata"

    @property
    def ready(self) -> bool:
        return bool(self.enabled and self.idp_sso_url and self.idp_certs and self.idp_entity_id)


def acs_url(public_url: str) -> str:
    return f"{public_url.rstrip('/')}/saml/acs"


def split_values(text: str) -> list[str]:
    return [v.strip() for v in text.replace(";", ",").replace("\n", ",").split(",") if v.strip()]


# ------------------------------------------------------------------ IdP metadata
def parse_metadata(xml: str | bytes) -> dict[str, Any]:
    """Entity ID, redirect sign-in URL and signing certificates from IdP federation metadata."""
    try:
        root = etree.fromstring(xml.encode() if isinstance(xml, str) else xml, _PARSER)
    except etree.XMLSyntaxError as exc:
        raise SamlError(f"That isn't valid XML: {exc.msg}") from exc
    ed = root if etree.QName(root).localname == "EntityDescriptor" else root.find(".//md:EntityDescriptor", NS)
    if ed is None:
        raise SamlError("No EntityDescriptor in the metadata")
    idp = ed.find("md:IDPSSODescriptor", NS)
    if idp is None:
        raise SamlError("The metadata has no IDPSSODescriptor (is it the app's federation metadata?)")
    sso = next((e.get("Location") for e in idp.findall("md:SingleSignOnService", NS) if e.get("Binding") == REDIRECT), None)
    certs = []
    for kd in idp.findall("md:KeyDescriptor", NS):
        if kd.get("use") in (None, "signing"):
            for c in kd.findall(".//ds:X509Certificate", NS):
                val = "".join((c.text or "").split())
                if val and val not in certs:
                    certs.append(val)
    if not sso:
        raise SamlError("The metadata has no HTTP-Redirect SingleSignOnService")
    if not sso.startswith("https://"):
        raise SamlError("The IdP sign-in URL must use https")
    if not certs:
        raise SamlError("The metadata has no signing certificate")
    return {"idp_entity_id": ed.get("entityID") or "", "idp_sso_url": sso, "idp_certs": certs}


def apply_metadata(cfg: SamlSettings, meta: dict[str, Any]) -> None:
    cfg.idp_entity_id, cfg.idp_sso_url, cfg.idp_certs = meta["idp_entity_id"], meta["idp_sso_url"], meta["idp_certs"]
    cfg.metadata_fetched = datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def fetch_metadata(url: str, http=None) -> dict[str, Any]:
    import httpx
    if not url.startswith("https://"):
        raise SamlError("The metadata URL must start with https://")
    try:
        client = http or httpx.Client(timeout=20, follow_redirects=True)
        try:
            resp = client.get(url)
        finally:
            if http is None:
                client.close()
    except httpx.HTTPError as exc:
        raise SamlError(f"Could not download the metadata: {exc.__class__.__name__}") from exc
    if resp.status_code != 200:
        raise SamlError(f"Downloading the metadata returned HTTP {resp.status_code}")
    return parse_metadata(resp.content)


def sp_metadata(cfg: SamlSettings, public_url: str) -> str:
    return (
        '<?xml version="1.0"?>\n'
        f'<md:EntityDescriptor xmlns:md="{NS["md"]}" entityID="{_attr(cfg.sp_entity(public_url))}">\n'
        f'  <md:SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="{NS["samlp"]}">\n'
        '    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>\n'
        f'    <md:AssertionConsumerService Binding="{POST}" Location="{_attr(acs_url(public_url))}" index="0" isDefault="true"/>\n'
        '  </md:SPSSODescriptor>\n'
        '</md:EntityDescriptor>\n')


def _attr(v: str) -> str:
    return v.replace("&", "&amp;").replace('"', "&quot;").replace("<", "&lt;")


# ------------------------------------------------------------------ requests we started, and replays
class _Store:
    """Pending AuthnRequests (by RelayState) and assertion IDs already used. In memory: one web process."""

    def __init__(self):
        self.lock = threading.Lock()
        self.pending: dict[str, tuple[str, str, float]] = {}   # relay -> (request id, next, expires)
        self.used: dict[str, float] = {}

    def _prune(self, now: float) -> None:
        self.pending = {k: v for k, v in self.pending.items() if v[2] > now}
        self.used = {k: v for k, v in self.used.items() if v > now}

    def add(self, req_id: str, next_url: str) -> str:
        relay = secrets.token_urlsafe(24)
        with self.lock:
            now = time.time()
            self._prune(now)
            if len(self.pending) > 5000:
                raise SamlError("Too many sign-ins in progress. Try again in a few minutes.")
            self.pending[relay] = (req_id, next_url, now + 600)
        return relay

    def take(self, relay: str | None) -> tuple[str, str] | None:
        with self.lock:
            item = self.pending.pop(relay or "", None)
        if item is None or item[2] < time.time():
            return None
        return item[0], item[1]

    def use_once(self, assertion_id: str, until: float) -> bool:
        with self.lock:
            self._prune(time.time())
            if assertion_id in self.used:
                return False
            self.used[assertion_id] = until
            return True


STORE = _Store()


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def login_redirect(cfg: SamlSettings, public_url: str, next_url: str = "/") -> str:
    req_id = "_" + secrets.token_hex(20)
    xml = (f'<samlp:AuthnRequest xmlns:samlp="{NS["samlp"]}" xmlns:saml="{NS["saml"]}" ID="{req_id}" Version="2.0" '
           f'IssueInstant="{_now_iso()}" Destination="{_attr(cfg.idp_sso_url)}" ProtocolBinding="{POST}" '
           f'AssertionConsumerServiceURL="{_attr(acs_url(public_url))}">'
           f'<saml:Issuer>{_attr(cfg.sp_entity(public_url))}</saml:Issuer></samlp:AuthnRequest>')
    deflated = zlib.compress(xml.encode())[2:-4]     # raw DEFLATE, as the redirect binding wants
    relay = STORE.add(req_id, next_url)
    sep = "&" if "?" in cfg.idp_sso_url else "?"
    return cfg.idp_sso_url + sep + urlencode({"SAMLRequest": base64.b64encode(deflated).decode(), "RelayState": relay})


# ------------------------------------------------------------------ the response
@dataclass
class Identity:
    name_id: str
    attributes: dict[str, list[str]]

    def first(self, *claims: str) -> str | None:
        for c in claims:
            vals = self.attributes.get(c)
            if vals and vals[0].strip():
                return vals[0].strip()
        return None

    @property
    def username(self) -> str:
        upn = self.first(CLAIM_UPN) or self.name_id
        if "#EXT#" in upn and self.first(CLAIM_EMAIL):     # a guest: john_gmail.com#EXT#@tenant -> their email
            return self.first(CLAIM_EMAIL) or upn
        return (upn or self.first(CLAIM_EMAIL) or "").strip()

    @property
    def email(self) -> str | None:
        return self.first(CLAIM_EMAIL) or (self.username if "@" in self.username else None)

    @property
    def full_name(self) -> str | None:
        display = self.first(CLAIM_DISPLAY)
        if display:
            return display
        parts = [p for p in (self.first(CLAIM_GIVEN), self.first(CLAIM_SURNAME)) if p]
        return " ".join(parts) or None

    @property
    def object_id(self) -> str | None:
        return self.first(CLAIM_OID)

    @property
    def role_values(self) -> set[str]:
        return {v.strip().lower() for v in self.attributes.get(CLAIM_GROUPS, []) + self.attributes.get(CLAIM_ROLES, []) if v.strip()}


def _time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        v = value.strip().replace("Z", "+00:00")
        if "." in v:     # Entra sends 7 fractional digits; Python takes 6
            head, rest = v.split(".", 1)
            frac = "".join(ch for ch in rest if ch.isdigit())
            tz = rest[len(frac):]
            v = f"{head}.{frac[:6]}{tz}"
        dt = datetime.fromisoformat(v)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise SamlError("The response has an unreadable timestamp") from exc


def _pem(b64der: str) -> str:
    body = "\n".join(b64der[i:i + 64] for i in range(0, len(b64der), 64))
    return f"-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n"


def _verified_assertion(xml: bytes, certs: list[str]) -> etree._Element:
    """The Assertion element that is covered by a signature from one of the IdP certificates."""
    last: Exception | None = None
    for cert in certs:
        try:
            result = XMLVerifier().verify(xml, x509_cert=_pem(cert))
        except (InvalidSignature, InvalidInput) as exc:
            last = exc
            continue
        signed = result.signed_xml
        if signed is None:
            continue
        if etree.QName(signed).localname == "Assertion":
            return signed
        if etree.QName(signed).localname == "Response":
            found = signed.findall("saml:Assertion", NS)
            if len(found) == 1:
                return found[0]
        raise SamlError("The signature doesn't cover exactly one assertion")
    raise SamlError("The response signature didn't verify against the IdP certificate. If the certificate was "
                    "renewed in Entra, refresh the metadata in Administration > Single sign-on.") from last


def validate_response(cfg: SamlSettings, public_url: str, saml_response: str, relay_state: str | None,
                      now: datetime | None = None) -> tuple[Identity, str]:
    """Check a posted SAMLResponse. Returns the identity and the page to go to next."""
    if not cfg.ready:
        raise SamlError("Single sign-on isn't set up")
    now = now or datetime.now(timezone.utc)
    try:
        xml = base64.b64decode(saml_response, validate=False)
        root = etree.fromstring(xml, _PARSER)
    except (ValueError, etree.XMLSyntaxError) as exc:
        raise SamlError("The sign-in response couldn't be read") from exc
    if root.tag != f"{{{NS['samlp']}}}Response":
        raise SamlError("That isn't a SAML response")
    status = root.find("samlp:Status/samlp:StatusCode", NS)
    if status is None or status.get("Value") != SUCCESS:
        msg = root.findtext("samlp:Status/samlp:StatusMessage", default="", namespaces=NS).strip()
        raise SamlError("Entra refused the sign-in" + (f": {msg.splitlines()[0][:300]}" if msg else ""))
    if root.find(".//saml:EncryptedAssertion", NS) is not None:
        raise SamlError("The assertion is encrypted. Turn off token encryption for this app in Entra.")
    acs = acs_url(public_url)
    if root.get("Destination") and root.get("Destination") != acs:
        raise SamlError(f"The response was meant for {root.get('Destination')}, not {acs}")

    a = _verified_assertion(xml, cfg.idp_certs)
    pending = STORE.take(relay_state)

    issuer = (a.findtext("saml:Issuer", default="", namespaces=NS) or "").strip()
    if issuer != cfg.idp_entity_id:
        raise SamlError("The assertion comes from a different identity provider")
    cond = a.find("saml:Conditions", NS)
    if cond is None:
        raise SamlError("The assertion has no conditions")
    nb, noa = _time(cond.get("NotBefore")), _time(cond.get("NotOnOrAfter"))
    if (nb and now + SKEW < nb) or (noa and now - SKEW >= noa):
        raise SamlError("The sign-in response has expired or isn't valid yet. Check this server's clock.")
    audiences = {(x.text or "").strip() for x in cond.findall("saml:AudienceRestriction/saml:Audience", NS)}
    sp_entity = cfg.sp_entity(public_url)
    if sp_entity not in audiences:
        raise SamlError(f"The assertion is for {', '.join(sorted(audiences)) or 'no audience'}, not {sp_entity}. "
                        "The Identifier (Entity ID) in Entra must match.")

    subject = a.find("saml:Subject", NS)
    name_id = (subject.findtext("saml:NameID", default="", namespaces=NS) if subject is not None else "").strip()
    confirmed = False
    in_response_to = None
    for sc in (subject.findall("saml:SubjectConfirmation", NS) if subject is not None else []):
        if sc.get("Method") != "urn:oasis:names:tc:SAML:2.0:cm:bearer":
            continue
        d = sc.find("saml:SubjectConfirmationData", NS)
        if d is None:
            continue
        exp = _time(d.get("NotOnOrAfter"))
        if d.get("Recipient") != acs or (exp and now - SKEW >= exp):
            continue
        confirmed, in_response_to = True, d.get("InResponseTo")
        break
    if not confirmed:
        raise SamlError(f"The assertion isn't addressed to {acs}. The Reply URL in Entra must match it exactly.")

    next_url = "/"
    if pending is not None:
        if in_response_to != pending[0]:
            raise SamlError("This response doesn't belong to the sign-in that was started. Try again.")
        next_url = pending[1]
    elif in_response_to or not cfg.allow_idp_initiated:
        raise SamlError("This sign-in wasn't started here, or took longer than 10 minutes. Start again from the VisCon1 sign-in page.")

    expires = noa or (now + timedelta(hours=1))
    if not STORE.use_once(a.get("ID") or "", expires.timestamp() + SKEW.total_seconds()):
        raise SamlError("This sign-in response was already used")

    attrs: dict[str, list[str]] = {}
    for at in a.findall("saml:AttributeStatement/saml:Attribute", NS):
        attrs.setdefault(at.get("Name") or "", []).extend((v.text or "") for v in at.findall("saml:AttributeValue", NS))
    if not name_id and not attrs.get(CLAIM_UPN):
        raise SamlError("The assertion has no user name")
    return Identity(name_id=name_id, attributes=attrs), next_url


def role_for(cfg: SamlSettings, ident: Identity) -> str | None:
    """admin, viewer, or None (not allowed in) from the groups and app roles in the assertion."""
    have = ident.role_values
    if have & {v.lower() for v in cfg.admin_values}:
        return "admin"
    if have & {v.lower() for v in cfg.viewer_values}:
        return "viewer"
    return "viewer" if cfg.default_role == "viewer" else None
