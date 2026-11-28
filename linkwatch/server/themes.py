"""Colour themes. The site default is set under Administration; each user can pick their own under their account."""
from __future__ import annotations

from sqlalchemy.orm import Session

from .db import get_setting

THEMES = {
    "auto": "VisCon1 (follows the device's light or dark setting)",
    "midnight": "Midnight NOC (dark)",
    "light": "Classic Light",
    "zscaler": "Zscaler Blue (dark)",
    "graphite": "Graphite + Orange (dark)",
    "navy": "Navy console (dark, left sidebar)",
    "as400": "AS/400 phosphor green (dark)",
}
LAYOUTS = {"top": "Top menu", "sidebar": "Left sidebar"}
THEME_LAYOUT = {"navy": "sidebar"}       # a theme's own menu layout, used unless the site or the user picks one
# which logo (static/brand/viscon1-<family>.svg) each theme shows; "auto" swaps light/dark with the device setting
THEME_LOGO = {"light": "light", "as400": "green"}


def logo_for(theme: str) -> str:
    """'light', 'dark' or 'green'; 'auto' for the device-dependent default theme."""
    if theme == "auto":
        return "auto"
    return THEME_LOGO.get(theme, "dark")


def site_theme(s: Session) -> str:
    v = get_setting(s, "theme", "auto") or "auto"
    return v if v in THEMES else "auto"


def theme_for(s: Session, user) -> str:
    mine = getattr(user, "theme", None) if user is not None else None
    return mine if mine in THEMES else site_theme(s)


def site_layout(s: Session) -> str:
    """'' means each theme's own layout."""
    v = get_setting(s, "layout", "") or ""
    return v if v in LAYOUTS else ""


def layout_for(s: Session, user, theme: str) -> str:
    mine = getattr(user, "layout", None) if user is not None else None
    if mine in LAYOUTS:
        return mine
    return site_layout(s) or THEME_LAYOUT.get(theme, "top")
