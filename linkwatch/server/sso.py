"""Single sign-on routes: /saml/login, /saml/acs, /saml/metadata and Administration > Single sign-on."""
from __future__ import annotations

import logging
import secrets

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy import func, select

from .app import flash
from .models import User, utcnow
from .saml import (
    CLAIM_GROUPS_LINK,
    SamlError,
    SamlSettings,
    acs_url,
    apply_metadata,
    fetch_metadata,
    login_redirect,
    parse_metadata,
    role_for,
    sp_metadata,
    split_values,
    validate_response,
)
from .security import sha256
from .users import ROLES, audit
from .web import back, render, st

log = logging.getLogger("linkwatch.sso")
router = APIRouter(include_in_schema=False)


def ip_of(request: Request) -> str | None:
    return request.headers.get("x-real-ip") or (request.client.host if request.client else None)


def safe_next(url: str | None) -> str:
    url = url or "/"
    return url if url.startswith("/") and not url.startswith("//") and "\\" not in url else "/"


def settings(request: Request) -> SamlSettings:
    with st(request).db.session() as s:
        return SamlSettings.load(s)


def _login_error(request: Request, message: str, status: int = 403) -> HTMLResponse:
    from .app import login_context
    ctx = login_context(request, "/")
    ctx["error"] = message
    return st(request).templates.TemplateResponse(request, "login.html", ctx, status_code=status)


# ------------------------------------------------------------------ sign-in
@router.get("/saml/login")
def saml_login(request: Request, next: str = "/"):
    cfg = settings(request)
    if not cfg.ready:
        return _login_error(request, "Single sign-on isn't set up. Sign in with a password.", 404)
    try:
        return RedirectResponse(login_redirect(cfg, st(request).config.public_url, safe_next(next)), status_code=303)
    except SamlError as exc:
        return _login_error(request, str(exc), 503)


@router.post("/saml/acs")
def saml_acs(request: Request, SAMLResponse: str = Form(""), RelayState: str | None = Form(None)):
    cfg = settings(request)
    ip = ip_of(request)
    public_url = st(request).config.public_url
    try:
        ident, next_url = validate_response(cfg, public_url, SAMLResponse, RelayState)
    except SamlError as exc:
        log.warning("SSO sign-in refused from %s: %s", ip, exc)
        with st(request).db.session() as s:
            audit(s, None, ip, "SSO sign-in failed", str(exc))
        return _login_error(request, f"Single sign-on failed: {exc}")

    role = role_for(cfg, ident)
    username = ident.username
    with st(request).db.session() as s:
        user = None
        if ident.object_id:
            user = s.scalar(select(User).where(User.external_id == ident.object_id))
        if user is None:
            user = s.scalar(select(User).where(func.lower(User.username) == username.lower()))
        problem = None
        if user is None:
            if not cfg.jit:
                problem = f"There's no VisCon1 account for {username}. Ask an admin to add one."
            elif role is None:
                problem = _no_role(username, ident)
            elif len(username) > 64:
                problem = "Your user name is longer than 64 characters."
            else:
                user = User(username=username, full_name=(ident.full_name or "")[:120] or None, email=(ident.email or "")[:255] or None,
                            role=role, password_hash="!saml:" + secrets.token_hex(16), auth_source="saml",
                            external_id=ident.object_id)
                s.add(user)
                s.flush()
                audit(s, "system", ip, "user created by SSO", f"{username} as {ROLES[role]}")
        elif user.disabled:
            problem = "Your VisCon1 account is disabled."
        elif user.auth_source == "saml":
            if role is None:
                problem = _no_role(username, ident)
            elif cfg.sync_role and user.role != role:
                audit(s, "system", ip, "role changed by SSO", f"{user.username}: {ROLES[user.role]} to {ROLES[role]}")
                user.role = role
        if problem:
            audit(s, username, ip, "SSO sign-in failed", problem)
            ok = False
        else:
            ok = True
            if ident.object_id and not user.external_id:
                user.external_id = ident.object_id
            if ident.full_name and not user.full_name:
                user.full_name = ident.full_name[:120]
            if ident.email and not user.email:
                user.email = ident.email[:255]
            user.last_login = utcnow()
            audit(s, user.username, ip, "signed in with SSO")
            uid, pwv = user.id, sha256("pwv:" + user.password_hash)[:20]
    if not ok:
        return _login_error(request, problem)
    request.session.clear()
    request.session["uid"], request.session["pwv"] = uid, pwv
    return RedirectResponse(safe_next(next_url), status_code=303)


def _no_role(username: str, ident) -> str:
    msg = f"{username} isn't in an Entra group or app role that is allowed into VisCon1."
    if ident.attributes.get(CLAIM_GROUPS_LINK) and not ident.role_values:
        msg += (" Entra sent a group link instead of groups because you're in too many groups; "
                "use app roles or 'Groups assigned to the application' in the groups claim.")
    return msg


@router.get("/saml/metadata")
def saml_metadata(request: Request):
    xml = sp_metadata(settings(request), st(request).config.public_url)
    return Response(xml, media_type="application/samlmetadata+xml",
                    headers={"Content-Disposition": 'inline; filename="linkwatch-sp-metadata.xml"'})


# ------------------------------------------------------------------ Administration > Single sign-on
@router.get("/admin/sso", response_class=HTMLResponse)
def sso_page(request: Request):
    cfg = settings(request)
    public_url = st(request).config.public_url
    with st(request).db.session() as s:
        sso_users = s.scalar(select(func.count(User.id)).where(User.auth_source == "saml")) or 0
    return render(request, "admin_sso.html", {"cfg": cfg, "acs": acs_url(public_url), "sp_entity": cfg.sp_entity(public_url),
                                              "metadata_link": f"{public_url.rstrip('/')}/saml/metadata",
                                              "sign_on_url": f"{public_url.rstrip('/')}/saml/login", "sso_users": sso_users})


@router.post("/admin/sso")
async def sso_save(request: Request):
    form = await request.form()
    cfg = settings(request)
    metadata_url = str(form.get("metadata_url") or "").strip()
    metadata_xml = str(form.get("metadata_xml") or "").strip()
    try:
        if metadata_xml:
            apply_metadata(cfg, parse_metadata(metadata_xml))
            cfg.metadata_url = metadata_url
        elif metadata_url and (metadata_url != cfg.metadata_url or not cfg.idp_certs):
            apply_metadata(cfg, fetch_metadata(metadata_url))
            cfg.metadata_url = metadata_url
        elif not metadata_url:
            cfg.metadata_url = ""
    except SamlError as exc:
        flash(request, f"Not saved: {exc}", "bad")
        return back("/admin/sso")
    cfg.sp_entity_id = str(form.get("sp_entity_id") or "").strip()
    cfg.button_label = str(form.get("button_label") or "").strip()[:60] or "Sign in with Microsoft"
    cfg.admin_values = split_values(str(form.get("admin_values") or ""))
    cfg.viewer_values = split_values(str(form.get("viewer_values") or ""))
    cfg.default_role = "viewer" if form.get("default_role") == "viewer" else "none"
    cfg.jit = bool(form.get("jit"))
    cfg.sync_role = bool(form.get("sync_role"))
    cfg.local_login = "admins" if form.get("local_login") == "admins" else "all"
    cfg.allow_idp_initiated = bool(form.get("allow_idp_initiated"))
    want_on = bool(form.get("enabled"))
    if want_on and not (cfg.idp_sso_url and cfg.idp_certs):
        flash(request, "Add the Entra federation metadata before turning single sign-on on.", "warn")
        want_on = False
    if want_on and not (cfg.admin_values or cfg.viewer_values or cfg.default_role == "viewer"):
        flash(request, "Saved, but nobody can sign in with SSO yet: add an admin or read-only group or app role.", "warn")
    cfg.enabled = want_on
    with st(request).db.session() as s:
        cfg.save(s)
        audit(s, request.state.user.username, ip_of(request), "single sign-on settings changed",
              f"{'on' if cfg.enabled else 'off'}, local passwords: {cfg.local_login}")
    flash(request, "Single sign-on settings saved.")
    return back("/admin/sso")


@router.post("/admin/sso/refresh")
def sso_refresh(request: Request):
    cfg = settings(request)
    if not cfg.metadata_url:
        flash(request, "There's no metadata URL to refresh from. Paste new metadata XML instead.", "warn")
        return back("/admin/sso")
    try:
        apply_metadata(cfg, fetch_metadata(cfg.metadata_url))
    except SamlError as exc:
        flash(request, str(exc), "bad")
        return back("/admin/sso")
    with st(request).db.session() as s:
        cfg.save(s)
        audit(s, request.state.user.username, ip_of(request), "SSO metadata refreshed")
    flash(request, f"Metadata refreshed: {len(cfg.idp_certs)} signing certificate{'s' if len(cfg.idp_certs) != 1 else ''}.")
    return back("/admin/sso")


def refresh_metadata_job(app_state) -> None:
    """Daily: pick up Entra certificate rollovers from the metadata URL."""
    from datetime import datetime, timedelta, timezone
    with app_state.db.session() as s:
        cfg = SamlSettings.load(s)
    if not (cfg.enabled and cfg.metadata_url):
        return
    last = datetime.fromisoformat(cfg.metadata_fetched) if cfg.metadata_fetched else None
    if last and datetime.now(timezone.utc) - last < timedelta(hours=24):
        return
    try:
        meta = fetch_metadata(cfg.metadata_url)
    except SamlError as exc:
        log.warning("Could not refresh SSO metadata: %s", exc)
        return
    with app_state.db.session() as s:
        cfg = SamlSettings.load(s)
        apply_metadata(cfg, meta)
        cfg.save(s)
