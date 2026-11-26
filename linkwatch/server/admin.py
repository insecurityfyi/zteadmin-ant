"""Administration (admins only, enforced by the login middleware) and each user's own account page."""
from __future__ import annotations

import platform

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import func, select

from .. import __version__
from .app import flash
from .models import AuditEvent, Device, Integration, Poller, User, utcnow
from .security import hash_password, verify_password
from .users import MIN_PASSWORD, ROLES, USERNAME, active_admins, audit, password_problem
from .db import set_setting
from .themes import THEMES, site_theme
from .web import back, render, st

router = APIRouter(include_in_schema=False)


def ip_of(request: Request) -> str | None:
    return request.headers.get("x-real-ip") or (request.client.host if request.client else None)


@router.get("/admin", response_class=HTMLResponse)
def admin_page(request: Request, audit_q: str = ""):
    with st(request).db.session() as s:
        users = s.scalars(select(User).order_by(func.lower(User.username))).all()
        q = select(AuditEvent).order_by(AuditEvent.id.desc()).limit(200)
        if audit_q.strip():
            like = f"%{audit_q.strip()}%"
            q = q.where(AuditEvent.username.ilike(like) | AuditEvent.action.ilike(like) | AuditEvent.ip.ilike(like))
        events = s.scalars(q).all()
        counts = {"devices": s.scalar(select(func.count(Device.id))) or 0,
                  "pollers": s.scalar(select(func.count(Poller.id)).where(Poller.revoked.is_(False))) or 0,
                  "integrations": s.scalar(select(func.count(Integration.id))) or 0}
        dialect = s.bind.dialect.name
        theme = site_theme(s)
    system = {"version": __version__, "python": platform.python_version(), "database": dialect,
              "public_url": st(request).config.public_url}
    return render(request, "admin.html", {"users": users, "events": events, "roles": ROLES, "audit_q": audit_q,
                                          "counts": counts, "system": system, "min_password": MIN_PASSWORD,
                                          "themes": THEMES, "site_theme": theme})


@router.post("/admin/theme")
async def admin_theme(request: Request):
    form = await request.form()
    theme = str(form.get("theme") or "auto")
    if theme not in THEMES:
        theme = "auto"
    with st(request).db.session() as s:
        set_setting(s, "theme", theme)
        audit(s, request.state.user.username, ip_of(request), "changed the site theme", theme)
    flash(request, f"Site theme set to {THEMES[theme].split(' (')[0]}. Users who picked their own theme keep it.")
    return back("/admin#appearance")


@router.post("/admin/users")
async def user_create(request: Request):
    form = await request.form()
    username = str(form.get("username") or "").strip()
    password = str(form.get("password") or "")
    role = str(form.get("role") or "viewer")
    if not USERNAME.match(username):
        flash(request, "Usernames are 2 to 64 letters, digits or . _ @ -", "warn")
        return back("/admin")
    if role not in ROLES:
        role = "viewer"
    if err := password_problem(password):
        flash(request, err, "warn")
        return back("/admin")
    with st(request).db.session() as s:
        if s.scalar(select(User.id).where(func.lower(User.username) == username.lower())):
            flash(request, f"There is already a user called {username}.", "warn")
            return back("/admin")
        s.add(User(username=username, full_name=str(form.get("full_name") or "").strip()[:120] or None,
                   email=str(form.get("email") or "").strip()[:255] or None, role=role,
                   password_hash=hash_password(password), password_changed_at=utcnow()))
        audit(s, request.state.user.username, ip_of(request), "created user", f"{username} ({ROLES[role]})")
    flash(request, f"Created {username}. Give them their password in person or over a secure channel.")
    return back("/admin")


@router.get("/admin/users/{uid}", response_class=HTMLResponse)
def user_edit_page(request: Request, uid: int):
    with st(request).db.session() as s:
        user = s.get(User, uid)
        if user is None:
            raise HTTPException(404)
        events = s.scalars(select(AuditEvent).where(AuditEvent.username == user.username)
                           .order_by(AuditEvent.id.desc()).limit(25)).all()
    return render(request, "admin_user.html", {"u": user, "roles": ROLES, "events": events, "min_password": MIN_PASSWORD})


@router.post("/admin/users/{uid}")
async def user_update(request: Request, uid: int):
    form = await request.form()
    me = request.state.user
    with st(request).db.session() as s:
        user = s.get(User, uid)
        if user is None:
            raise HTTPException(404)
        role = str(form.get("role") or user.role)
        role = role if role in ROLES else user.role
        disabled = form.get("disabled") == "on"
        if user.id == me.id and (role != "admin" or disabled):
            flash(request, "You can't remove your own admin role or disable yourself. Ask another admin.", "warn")
            return back(f"/admin/users/{uid}")
        if user.role == "admin" and (role != "admin" or disabled) and not active_admins(s, excluding=user.id):
            flash(request, "That would leave no active admin.", "warn")
            return back(f"/admin/users/{uid}")
        changes = []
        if role != user.role:
            changes.append(f"role {ROLES[user.role]} -> {ROLES[role]}")
        if disabled != user.disabled:
            changes.append("disabled" if disabled else "enabled")
        user.role, user.disabled = role, disabled
        user.full_name = str(form.get("full_name") or "").strip()[:120] or None
        user.email = str(form.get("email") or "").strip()[:255] or None
        audit(s, me.username, ip_of(request), "updated user", f"{user.username}: {', '.join(changes) or 'details'}")
        name = user.username
    flash(request, f"Saved {name}.")
    return back("/admin")


@router.post("/admin/users/{uid}/password")
async def user_reset_password(request: Request, uid: int):
    form = await request.form()
    password = str(form.get("password") or "")
    if err := password_problem(password):
        flash(request, err, "warn")
        return back(f"/admin/users/{uid}")
    with st(request).db.session() as s:
        user = s.get(User, uid)
        if user is None:
            raise HTTPException(404)
        if user.auth_source == "saml":
            flash(request, f"{user.username} signs in with single sign-on and has no password here.", "warn")
            return back(f"/admin/users/{uid}")
        user.password_hash, user.password_changed_at = hash_password(password), utcnow()
        audit(s, request.state.user.username, ip_of(request), "reset password", user.username)
        name, own = user.username, user.id == request.state.user.id
    if own:   # keep this browser signed in after changing our own password here
        from .security import sha256
        request.session["pwv"] = sha256("pwv:" + user.password_hash)[:20]
    flash(request, f"Set a new password for {name}. Their other sessions are signed out.")
    return back("/admin")


@router.post("/admin/users/{uid}/delete")
async def user_delete(request: Request, uid: int):
    form = await request.form()
    me = request.state.user
    with st(request).db.session() as s:
        user = s.get(User, uid)
        if user is None:
            raise HTTPException(404)
        if user.id == me.id:
            flash(request, "You can't delete yourself.", "warn")
            return back("/admin")
        if user.role == "admin" and not user.disabled and not active_admins(s, excluding=user.id):
            flash(request, "That would leave no active admin.", "warn")
            return back("/admin")
        if form.get("confirm") != "on":
            flash(request, "Tick Confirm to delete the user.", "warn")
            return back(f"/admin/users/{uid}")
        name = user.username
        s.delete(user)
        audit(s, me.username, ip_of(request), "deleted user", name)
    flash(request, f"Deleted {name}.")
    return back("/admin")


# ------------------------------------------------------------------ own account (every role)
@router.get("/account", response_class=HTMLResponse)
def account_page(request: Request):
    with st(request).db.session() as s:
        default = site_theme(s)
    return render(request, "account.html", {"roles": ROLES, "min_password": MIN_PASSWORD, "themes": THEMES,
                                            "site_theme": default})


@router.post("/account/theme")
async def account_theme(request: Request):
    form = await request.form()
    theme = str(form.get("theme") or "")
    with st(request).db.session() as s:
        user = s.get(User, request.state.user.id)
        user.theme = theme if theme in THEMES else None
    flash(request, "Theme saved.")
    return back("/account")


@router.post("/account/password")
async def account_password(request: Request):
    form = await request.form()
    current, new, again = (str(form.get(k) or "") for k in ("current", "password", "password2"))
    me = request.state.user
    if me.auth_source == "saml":
        flash(request, "You sign in with single sign-on, so there is no password to change here.", "warn")
        return back("/account")
    if not verify_password(current, me.password_hash):
        flash(request, "Your current password is wrong.", "warn")
        return back("/account")
    if new != again:
        flash(request, "The new passwords don't match.", "warn")
        return back("/account")
    if err := password_problem(new):
        flash(request, err, "warn")
        return back("/account")
    with st(request).db.session() as s:
        user = s.get(User, me.id)
        user.password_hash, user.password_changed_at = hash_password(new), utcnow()
        from .security import sha256
        request.session["pwv"] = sha256("pwv:" + user.password_hash)[:20]
        audit(s, user.username, ip_of(request), "changed own password")
    flash(request, "Password changed. Your other sessions are signed out.")
    return back("/account")
