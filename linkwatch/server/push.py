"""Web Push: alert notifications to the installed VisCon1 app on phones and desktops.

Standards only, no third-party push library: VAPID (RFC 8292) to identify this server to the browser's push
service, and aes128gcm message encryption (RFC 8291 / RFC 8188) so the push service can't read the alert.
The server's VAPID key pair is made on first use and kept, encrypted, in the settings table.
"""
from __future__ import annotations

import base64
import json
import logging
import os
import struct
import time
from typing import Any
from urllib.parse import urlsplit

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from sqlalchemy.orm import Session

from .db import get_setting, set_setting

log = logging.getLogger("linkwatch.push")
VAPID_SETTING = "push_vapid"
RECORD_SIZE = 4096


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64u(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def _raw_public(key: ec.EllipticCurvePublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def _hkdf(salt: bytes, ikm: bytes, info: bytes, length: int) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)


class Vapid:
    """This server's VAPID identity."""

    def __init__(self, private_key: ec.EllipticCurvePrivateKey, subject: str):
        self.key, self.subject = private_key, subject
        self.public_key = b64u(_raw_public(private_key.public_key()))   # what the browser needs as applicationServerKey

    @classmethod
    def load(cls, s: Session, vault, public_url: str) -> "Vapid":
        stored = vault.open(get_setting(s, VAPID_SETTING))
        if stored.get("d"):
            key = ec.derive_private_key(int.from_bytes(unb64u(stored["d"]), "big"), ec.SECP256R1())
        else:
            key = ec.generate_private_key(ec.SECP256R1())
            d = key.private_numbers().private_value.to_bytes(32, "big")
            set_setting(s, VAPID_SETTING, vault.seal({"d": b64u(d)}))
            s.flush()
        return cls(key, contact(public_url))

    def authorization(self, endpoint: str, ttl: int = 12 * 3600) -> str:
        parts = urlsplit(endpoint)
        claims = {"aud": f"{parts.scheme}://{parts.netloc}", "exp": int(time.time()) + ttl, "sub": self.subject}
        signing_input = b64u(json.dumps({"typ": "JWT", "alg": "ES256"}).encode()) + "." + \
            b64u(json.dumps(claims, separators=(",", ":")).encode())
        r, s = decode_dss_signature(self.key.sign(signing_input.encode(), ec.ECDSA(hashes.SHA256())))
        jwt = signing_input + "." + b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))
        return f"vapid t={jwt}, k={self.public_key}"


def contact(public_url: str) -> str:
    """The VAPID 'sub': who push services contact about this sender. Apple requires mailto: or https:."""
    mail = os.environ.get("LW_PUSH_CONTACT", "").strip()
    if mail:
        return mail if mail.startswith(("mailto:", "https://")) else f"mailto:{mail}"
    if public_url.startswith("https://"):
        return public_url
    return "mailto:viscon1@example.invalid"


def encrypt(payload: bytes, p256dh: str, auth: str) -> bytes:
    """aes128gcm-encrypt one push message for a subscription (RFC 8291), header included."""
    ua_public = unb64u(p256dh)
    auth_secret = unb64u(auth)
    ua_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), ua_public)
    as_private = ec.generate_private_key(ec.SECP256R1())
    as_public = _raw_public(as_private.public_key())
    ecdh_secret = as_private.exchange(ec.ECDH(), ua_key)
    ikm = _hkdf(auth_secret, ecdh_secret, b"WebPush: info\x00" + ua_public + as_public, 32)
    salt = os.urandom(16)
    cek = _hkdf(salt, ikm, b"Content-Encoding: aes128gcm\x00", 16)
    nonce = _hkdf(salt, ikm, b"Content-Encoding: nonce\x00", 12)
    if len(payload) > RECORD_SIZE - 17 - 86:
        raise ValueError("push payload too large")
    ciphertext = AESGCM(cek).encrypt(nonce, payload + b"\x02", None)     # \x02: the last (only) record
    return salt + struct.pack("!IB", RECORD_SIZE, len(as_public)) + as_public + ciphertext


class Gone(Exception):
    """The push service says this subscription no longer exists: forget it."""


def send(vapid: Vapid, sub: Any, message: dict[str, Any], http: httpx.Client, ttl: int = 3600,
         urgency: str = "normal") -> None:
    """Deliver one message to one subscription (anything with endpoint, p256dh and auth)."""
    body = encrypt(json.dumps(message, separators=(",", ":")).encode(), sub.p256dh, sub.auth)
    resp = http.post(sub.endpoint, content=body, headers={
        "Authorization": vapid.authorization(sub.endpoint), "Content-Encoding": "aes128gcm",
        "Content-Type": "application/octet-stream", "TTL": str(ttl), "Urgency": urgency})
    if resp.status_code in (404, 410):
        raise Gone(resp.status_code)
    resp.raise_for_status()
