"""User accounts, roles and the audit log."""
from __future__ import annotations

import logging
import re

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .db import get_setting, set_setting
from .models import AuditEvent, User, utcnow
from .security import hash_password, verify_password

log = logging.getLogger("linkwatch.users")
ROLES = {"admin": "Admin", "viewer": "Read-only"}
USERNAME = re.compile(r"^[A-Za-z0-9._@-]{2,64}$")
MIN_PASSWORD = 12


def password_problem(password: str) -> str | None:
    if len(password or "") < MIN_PASSWORD:
        return f"Use at least {MIN_PASSWORD} characters."
    if "\n" in password:
        return "The password can't contain a line break."
    return None


def audit(s: Session, username: str | None, ip: str | None, action: str, detail: str | None = None) -> None:
    s.add(AuditEvent(username=(username or None) and username[:64], ip=(ip or None) and ip[:64],
                     action=action[:120], detail=(detail or None) and detail[:500]))


def active_admins(s: Session, excluding: int | None = None) -> int:
    q = select(func.count(User.id)).where(User.role == "admin", User.disabled.is_(False))
    if excluding is not None:
        q = q.where(User.id != excluding)
    return s.scalar(q) or 0


def sync_admin_from_env(db, env_password: str | None) -> None:
    """LW_ADMIN_PASSWORD is the way back in: the first start creates user 'admin' with it, and whenever it
    changes (reset-password.sh) the 'admin' user gets it as its password and is re-enabled as an admin."""
    if not env_password:
        return
    with db.session() as s:
        admin = s.scalar(select(User).where(User.username == "admin"))
        if admin is not None and verify_password(env_password, get_setting(s, "env_admin_hash")):
            return  # unchanged since we last applied it
        if admin is None:
            admin = User(username="admin", full_name="Administrator", role="admin", password_hash=hash_password(env_password))
            s.add(admin)
            log.info("Created user 'admin' from LW_ADMIN_PASSWORD")
        else:
            admin.password_hash, admin.role, admin.disabled = hash_password(env_password), "admin", False
            log.warning("LW_ADMIN_PASSWORD changed: reset the password of user 'admin'")
        admin.password_changed_at = utcnow()
        set_setting(s, "env_admin_hash", hash_password(env_password))
        audit(s, "system", None, "admin password set from LW_ADMIN_PASSWORD")
