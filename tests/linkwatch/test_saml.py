"""Entra-style SAML sign-in, with responses signed by a throwaway IdP key."""
import base64
import copy
import datetime as dt
import re
import zlib
from urllib.parse import parse_qs, urlparse

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from lxml import etree
from signxml import XMLSigner
from sqlalchemy import select

from linkwatch.server.models import User
from linkwatch.server.saml import (CLAIM_DISPLAY, CLAIM_EMAIL, CLAIM_GROUPS, CLAIM_OID, CLAIM_ROLES, CLAIM_UPN,
                                   SamlError, SamlSettings, parse_metadata, validate_response)

TENANT = "11111111-2222-3333-4444-555555555555"
IDP_ENTITY = f"https://sts.windows.net/{TENANT}/"
IDP_SSO = f"https://login.microsoftonline.com/{TENANT}/saml2"
PUBLIC = "http://testserver"
ACS = f"{PUBLIC}/saml/acs"
SP_ENTITY = f"{PUBLIC}/saml/metadata"


def make_idp(cn="Microsoft Azure Federated SSO Certificate"):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=365)).sign(key, hashes.SHA256()))
    pem_key = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    pem_cert = cert.public_bytes(serialization.Encoding.PEM)
    b64 = base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()
    return pem_key, pem_cert, b64


IDP = make_idp()


def metadata(b64cert=IDP[2]):
    return f"""<?xml version="1.0" encoding="utf-8"?>
<EntityDescriptor ID="_x" entityID="{IDP_ENTITY}" xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
 <RoleDescriptor xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="fed:SecurityTokenServiceType" xmlns:fed="http://docs.oasis-open.org/wsfed/federation/200706"/>
 <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
  <KeyDescriptor use="signing"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>{b64cert}</X509Certificate></X509Data></KeyInfo></KeyDescriptor>
  <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{IDP_SSO}"/>
  <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{IDP_SSO}"/>
  <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{IDP_SSO}"/>
 </IDPSSODescriptor>
</EntityDescriptor>"""


def iso(t):
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + "1234567Z"     # Entra's 7-digit fractions


def response(in_response_to="_req", upn="ada@contoso.com", roles=("Linkwatch.Admin",), groups=(), audience=SP_ENTITY,
             recipient=ACS, issuer=IDP_ENTITY, key=IDP, minutes=60, aid="_a1", oid="oid-ada", tamper=None, wrap=False):
    now = dt.datetime.now(dt.timezone.utc)
    irt = f' InResponseTo="{in_response_to}"' if in_response_to else ""
    attrs = [(CLAIM_UPN, [upn]), (CLAIM_EMAIL, [upn]), (CLAIM_DISPLAY, ["Ada Lovelace"]), (CLAIM_OID, [oid]),
             (CLAIM_ROLES, list(roles)), (CLAIM_GROUPS, list(groups))]
    attr_xml = "".join(f'<Attribute Name="{n}">' + "".join(f"<AttributeValue>{v}</AttributeValue>" for v in vals) + "</Attribute>"
                       for n, vals in attrs if vals)
    assertion = etree.fromstring(f"""<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="{aid}" IssueInstant="{iso(now)}" Version="2.0">
  <Issuer>{issuer}</Issuer>
  <Subject><NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{upn}</NameID>
   <SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><SubjectConfirmationData{irt} NotOnOrAfter="{iso(now + dt.timedelta(minutes=5))}" Recipient="{recipient}"/></SubjectConfirmation></Subject>
  <Conditions NotBefore="{iso(now - dt.timedelta(minutes=5))}" NotOnOrAfter="{iso(now + dt.timedelta(minutes=minutes))}"><AudienceRestriction><Audience>{audience}</Audience></AudienceRestriction></Conditions>
  <AttributeStatement>{attr_xml}</AttributeStatement>
  <AuthnStatement AuthnInstant="{iso(now)}" SessionIndex="{aid}"><AuthnContext><AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</AuthnContextClassRef></AuthnContext></AuthnStatement>
</Assertion>""")
    signed = XMLSigner(c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#").sign(assertion, key=key[0], cert=key[1])
    if tamper:
        tamper(signed)
    resp = etree.fromstring(f"""<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r1" Version="2.0" IssueInstant="{iso(now)}" Destination="{ACS}"{irt}>
  <Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">{issuer}</Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status></samlp:Response>""")
    if wrap:   # signature-wrapping attempt: an unsigned evil assertion placed before the signed one
        evil = copy.deepcopy(signed)
        evil.set("ID", "_evil")
        for sig in evil.findall("{http://www.w3.org/2000/09/xmldsig#}Signature"):
            evil.remove(sig)
        for v in evil.iter("{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue"):
            if v.text == upn:
                v.text = "mallory@contoso.com"
        evil.find("{urn:oasis:names:tc:SAML:2.0:assertion}Subject/{urn:oasis:names:tc:SAML:2.0:assertion}NameID").text = "mallory@contoso.com"
        resp.append(evil)
    resp.append(signed)
    return base64.b64encode(etree.tostring(resp)).decode()


def cfg(**kw):
    c = SamlSettings(enabled=True, admin_values=["Linkwatch.Admin"], viewer_values=["Linkwatch.ReadOnly", "grp-viewers"], **kw)
    c.idp_entity_id, c.idp_sso_url, c.idp_certs = IDP_ENTITY, IDP_SSO, [IDP[2]]
    return c


def start(c):
    """Begin a sign-in and return (relay, request ID)."""
    from linkwatch.server.saml import login_redirect
    q = parse_qs(urlparse(login_redirect(c, PUBLIC, "/devices")).query)
    req = zlib.decompress(base64.b64decode(q["SAMLRequest"][0]), -15).decode()
    return q["RelayState"][0], re.search(r'ID="([^"]+)"', req).group(1), req


def test_parse_entra_metadata():
    m = parse_metadata(metadata())
    assert m == {"idp_entity_id": IDP_ENTITY, "idp_sso_url": IDP_SSO, "idp_certs": [IDP[2]]}
    with pytest.raises(SamlError, match="valid XML"):
        parse_metadata("<nope")
    with pytest.raises(SamlError, match="IDPSSODescriptor"):
        parse_metadata('<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="x"/>')


def test_authn_request_and_valid_response():
    c = cfg()
    relay, req_id, req = start(c)
    assert f'AssertionConsumerServiceURL="{ACS}"' in req and f"<saml:Issuer>{SP_ENTITY}</saml:Issuer>" in req
    ident, nxt = validate_response(c, PUBLIC, response(req_id), relay)
    assert (ident.username, ident.full_name, ident.object_id, nxt) == ("ada@contoso.com", "Ada Lovelace", "oid-ada", "/devices")
    from linkwatch.server.saml import role_for
    assert role_for(c, ident) == "admin"


@pytest.mark.parametrize("kw, match", [
    ({"audience": "https://other/app"}, "Identifier"),
    ({"recipient": "https://evil/acs"}, "Reply URL"),
    ({"issuer": "https://sts.windows.net/other/"}, "different identity provider"),
    ({"minutes": -10}, "expired"),
    ({"key": make_idp()}, "didn't verify"),
    ({"tamper": lambda a: a.find(".//{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue").__setattr__("text", "eve@contoso.com")}, "didn't verify"),
])
def test_bad_responses_are_refused(kw, match):
    c = cfg()
    relay, req_id, _ = start(c)
    with pytest.raises(SamlError, match=match):
        validate_response(c, PUBLIC, response(req_id, aid=f"_{abs(hash(match))}", **kw), relay)


def test_wrapping_replay_and_unsolicited():
    c = cfg()
    relay, req_id, _ = start(c)
    ident, _ = validate_response(c, PUBLIC, response(req_id, aid="_w1", wrap=True), relay)
    assert ident.username == "ada@contoso.com"           # only the signed assertion counts
    relay, req_id, _ = start(c)
    good = response(req_id, aid="_w2")
    validate_response(c, PUBLIC, good, relay)
    with pytest.raises(SamlError, match="wasn't started here"):  # same relay again
        validate_response(c, PUBLIC, good, relay)
    with pytest.raises(SamlError, match="wasn't started here"):  # IdP-initiated is off by default
        validate_response(c, PUBLIC, response(None, aid="_w3"), None)
    c.allow_idp_initiated = True
    validate_response(c, PUBLIC, response(None, aid="_w4"), None)
    with pytest.raises(SamlError, match="already used"):
        validate_response(c, PUBLIC, response(None, aid="_w4"), None)
    relay, req_id, _ = start(c)
    with pytest.raises(SamlError, match="doesn't belong"):
        validate_response(c, PUBLIC, response("_someone_else", aid="_w5"), relay)


# ------------------------------------------------------------------ through the web app
def setup_sso(logged_in, **extra):
    data = {"metadata_url": "", "metadata_xml": metadata(), "admin_values": "Linkwatch.Admin",
            "viewer_values": "Linkwatch.ReadOnly, grp-viewers", "default_role": "none", "jit": "on", "sync_role": "on",
            "local_login": "all", "enabled": "on", **extra}
    r = logged_in.post("/admin/sso", data=data)
    assert r.status_code == 200 and "Single sign-on settings saved" in r.text
    page = logged_in.get("/admin/sso").text
    assert ACS in page and SP_ENTITY in page and IDP_SSO in page


def sso_login(client, **kw):
    r = client.get("/saml/login?next=/devices", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith(IDP_SSO)
    q = parse_qs(urlparse(r.headers["location"]).query)
    req_id = re.search(r'ID="([^"]+)"', zlib.decompress(base64.b64decode(q["SAMLRequest"][0]), -15).decode()).group(1)
    return client.post("/saml/acs", data={"SAMLResponse": response(req_id, **kw), "RelayState": q["RelayState"][0]},
                       follow_redirects=False)


def test_sso_end_to_end(logged_in, app):
    setup_sso(logged_in)
    logged_in.post("/logout")
    assert "Sign in with Microsoft" in logged_in.get("/login").text
    assert "linkwatch-sp-metadata" in logged_in.get("/saml/metadata").headers["content-disposition"]
    assert f'Location="{ACS}"' in logged_in.get("/saml/metadata").text

    r = sso_login(logged_in, aid="_e1", roles=("Linkwatch.ReadOnly",))
    assert r.status_code == 303 and r.headers["location"] == "/devices"
    assert logged_in.get("/devices").status_code == 200
    with app.state.lw.db.session() as s:
        u = s.scalar(select(User).where(User.username == "ada@contoso.com"))
        assert (u.role, u.auth_source, u.external_id, u.full_name) == ("viewer", "saml", "oid-ada", "Ada Lovelace")
    assert logged_in.post("/settings/interval", data={"interval": "60"}, follow_redirects=False).status_code == 303  # read-only: bounced
    assert "no Linkwatch password" in logged_in.get("/account").text

    logged_in.post("/logout")
    assert sso_login(logged_in, aid="_e2", roles=("Linkwatch.Admin",)).status_code == 303
    assert logged_in.get("/admin").status_code == 200               # role synced up to admin
    logged_in.post("/logout")
    r = sso_login(logged_in, aid="_e3", roles=(), groups=("some-other-group",))
    assert r.status_code == 403 and "allowed into Linkwatch" in r.text
    r = logged_in.post("/login", data={"username": "ada@contoso.com", "password": "anything-at-all"})
    assert r.status_code == 403 and "single sign-on" in r.text


def test_sso_group_ids_jit_off_and_break_glass(logged_in, app):
    from linkwatch.server.security import hash_password
    with app.state.lw.db.session() as s:
        s.add(User(username="viewer1", role="viewer", password_hash=hash_password("viewer-password-1")))
    setup_sso(logged_in, jit="", local_login="admins")
    logged_in.post("/logout")
    r = sso_login(logged_in, aid="_g1", roles=(), groups=("grp-viewers",))
    assert r.status_code == 403 and "no Linkwatch account" in r.text
    r = logged_in.post("/login", data={"username": "viewer1", "password": "viewer-password-1"})
    assert r.status_code == 403 and "limited to administrators" in r.text
    r = logged_in.post("/login", data={"username": "admin", "password": "pw-for-tests"}, follow_redirects=False)
    assert r.status_code == 303                                       # break-glass admin still works
    events = logged_in.get("/admin").text
    assert "SSO sign-in failed" in events


def test_sso_needs_metadata_before_it_turns_on(logged_in):
    r = logged_in.post("/admin/sso", data={"metadata_url": "", "metadata_xml": "", "enabled": "on"})
    assert "Add the Entra federation metadata" in r.text
    assert logged_in.get("/saml/login", follow_redirects=False).status_code == 404
    r = logged_in.post("/admin/sso", data={"metadata_xml": "<broken"})
    assert "Not saved" in r.text
