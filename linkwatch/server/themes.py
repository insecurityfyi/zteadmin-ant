"""Colour themes. The site default is set under Administration; each user can pick their own under their account."""
from __future__ import annotations

from sqlalchemy.orm import Session

from .db import get_setting

THEMES = {
    "auto": "Linkwatch (follows the device's light or dark setting)",
    "midnight": "Midnight NOC (dark)",
    "light": "Classic Light",
    "zscaler": "Zscaler Blue (dark)",
    "graphite": "Graphite + Orange (dark)",
}


def site_theme(s: Session) -> str:
    v = get_setting(s, "theme", "auto") or "auto"
    return v if v in THEMES else "auto"


def theme_for(s: Session, user) -> str:
    mine = getattr(user, "theme", None) if user is not None else None
    return mine if mine in THEMES else site_theme(s)
