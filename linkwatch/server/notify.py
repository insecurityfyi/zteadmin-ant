"""Send alert notifications: email, Microsoft Teams, Slack or a generic webhook."""
from __future__ import annotations

import logging
import smtplib
import ssl
import threading
from email.message import EmailMessage
from typing import Any, Iterable

import httpx
from sqlalchemy import select

from .alerts import SEVERITY_ORDER, AlertEvent
from .models import Transport

log = logging.getLogger("linkwatch.notify")
LABEL = {"crit": "CRITICAL", "warn": "WARNING", "info": "INFO"}
KINDS = {
    "email": ("Email (SMTP)", ["host", "port", "username", "password", "starttls", "sender", "recipients"]),
    "teams": ("Microsoft Teams (Workflows webhook)", ["url"]),
    "slack": ("Slack (incoming webhook)", ["url"]),
    "webhook": ("Generic webhook (JSON POST)", ["url"]),
}


def headline(ev: AlertEvent) -> str:
    state = "RESOLVED" if ev.kind == "resolved" else LABEL.get(ev.severity, ev.severity.upper())
    return f"[{state}] {ev.title}"


def send_one(kind: str, cfg: dict[str, Any], ev: AlertEvent, public_url: str, http: httpx.Client | None = None) -> None:
    text = headline(ev) + (f"\n{ev.detail}" if ev.detail else "")
    link = f"{public_url}/alerts"
    if kind == "email":
        msg = EmailMessage()
        msg["Subject"] = headline(ev)
        msg["From"] = cfg["sender"]
        msg["To"] = cfg["recipients"]
        msg.set_content(f"{text}\n\n{link}\n")
        port = int(cfg.get("port") or 587)
        if port == 465:
            server = smtplib.SMTP_SSL(cfg["host"], port, timeout=20, context=ssl.create_default_context())
        else:
            server = smtplib.SMTP(cfg["host"], port, timeout=20)
            if cfg.get("starttls", True):
                server.starttls(context=ssl.create_default_context())
        with server:
            if cfg.get("username"):
                server.login(cfg["username"], cfg.get("password") or "")
            server.send_message(msg)
        return
    if kind == "teams":
        payload: dict[str, Any] = {"type": "message", "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {"type": "AdaptiveCard", "version": "1.4", "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "body": [{"type": "TextBlock", "text": headline(ev), "weight": "Bolder", "wrap": True},
                                 {"type": "TextBlock", "text": ev.detail or "", "wrap": True}],
                        "actions": [{"type": "Action.OpenUrl", "title": "Open alerts", "url": link}]}}]}
    elif kind == "slack":
        payload = {"text": f"{text}\n<{link}|Open alerts>"}
    else:
        payload = {"event": ev.kind, "severity": ev.severity, "title": ev.title, "detail": ev.detail,
                   "device": ev.device, "alert_id": ev.alert_id, "url": link}
    client = http or httpx.Client(timeout=15)
    try:
        resp = client.post(cfg["url"], json=payload)
        resp.raise_for_status()
    finally:
        if http is None:
            client.close()


class Notifier:
    def __init__(self, db, vault, public_url: str):
        self.db, self.vault, self.public_url = db, vault, public_url

    def dispatch(self, events: Iterable[AlertEvent], background: bool = True) -> None:
        events = list(events)
        if not events:
            return
        if background:
            threading.Thread(target=self._send, args=(events,), daemon=True).start()
        else:
            self._send(events)

    def _send(self, events: list[AlertEvent]) -> None:
        with self.db.session() as s:
            transports = s.scalars(select(Transport).where(Transport.enabled.is_(True))).all()
            for t in transports:
                cfg = self.vault.open(t.config_enc)
                for ev in events:
                    if SEVERITY_ORDER.get(ev.severity, 0) < SEVERITY_ORDER.get(t.min_severity, 1):
                        continue
                    try:
                        send_one(t.kind, cfg, ev, self.public_url)
                        t.last_result = f"Sent: {headline(ev)}"[:255]
                    except Exception as exc:  # report, never crash ingestion
                        log.warning("Transport %s failed: %s", t.name, exc)
                        t.last_result = f"Failed: {exc.__class__.__name__}: {exc}"[:255]
