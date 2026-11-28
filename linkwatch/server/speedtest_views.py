"""Speed test pages: results by ISP with history, per-poller settings, "Run now", and the chart data."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import select

from . import events, speedtest
from .models import Poller, SpeedTest
from .web import _who, back, flash, render, st

router = APIRouter(include_in_schema=False)


def _safe_next(url: str | None, default: str = "/speedtests") -> str:
    url = str(url or "")
    return url if url.startswith("/") and not url.startswith("//") else default


@router.get("/speedtests", response_class=HTMLResponse)
def speedtest_page(request: Request, poller: int = 0, edit: int = 0):
    hub = st(request).hub
    with st(request).db.session() as s:
        pollers = list(s.scalars(select(Poller).where(Poller.revoked.is_(False)).order_by(Poller.name)))
        isps = speedtest.isp_summary(s, poller or None, days=90)
        q = select(SpeedTest).order_by(SpeedTest.ts.desc()).limit(30)
        if poller:
            q = q.where(SpeedTest.poller_id == poller)
        history = s.scalars(q).all()
        cards = []
        for p in pollers:
            cfg = speedtest.settings(p)
            used = speedtest.month_usage(s, p.id)
            lanes = []
            for ln in cfg["lanes"]:
                key = speedtest.lane_key(ln)
                per = speedtest.avg_bytes(s, p.id, key)
                last = s.scalar(select(SpeedTest).where(SpeedTest.poller_id == p.id, SpeedTest.lane == key)
                                .order_by(SpeedTest.ts.desc()).limit(1))
                cap = int(float(ln["cap_gb"]) * 1e9) if ln.get("cap_gb") else None
                lanes.append({**ln, "key": key, "used": used.get(key, 0), "cap": cap, "per_test": per,
                              "projected": speedtest.projection(cfg, ln, per), "last": last,
                              "blocked": bool(cap and used.get(key, 0) >= cap)})
            cards.append({"p": p, "cfg": cfg, "lanes": lanes, "online": p.id in hub.conns,
                          "supported": "speedtest" in (p.features or []), "seen": p.last_seen is not None})
        names = {p.id: p.name for p in s.scalars(select(Poller))}
        s.expunge_all()
    from .gateway import update_command
    return render(request, "speedtests.html", {
        "pollers": pollers, "cards": cards, "isps": isps, "history": history, "names": names, "chosen": poller,
        "edit": edit, "intervals": speedtest.INTERVALS, "jitters": speedtest.JITTERS, "durations": speedtest.DURATIONS,
        "max_lanes": speedtest.MAX_LANES, "metrics": speedtest.METRICS, "update_cmd": update_command()})


@router.post("/speedtests/{poller_id}/settings")
async def speedtest_save(request: Request, poller_id: int):
    form = await request.form()
    cfg, problems = speedtest.read_form(form)
    if problems:
        for msg in problems:
            flash(request, msg, "warn")
        return back(f"/speedtests?edit={poller_id}#poller-{poller_id}")
    with st(request).db.session() as s:
        p = s.get(Poller, poller_id)
        if p is None or p.revoked:
            raise HTTPException(404, "No such poller")
        p.speedtest = cfg
        name = p.name
        what = (f"every {cfg['interval_h']}h on {len(cfg['lanes'])} lane{'s' if len(cfg['lanes']) != 1 else ''}"
                if cfg["enabled"] else "off")
        events.log(s, "config", f"Speed tests on poller {name} set to {what} by {_who(request)}", "info", username=_who(request))
    st(request).hub.push_config_soon(poller_id)
    flash(request, f"Speed test settings for {name} saved." + (" The first scheduled test runs within 15 minutes."
                                                                if cfg["enabled"] else ""))
    return back(f"/speedtests#poller-{poller_id}")


@router.post("/speedtests/run")
async def speedtest_run(request: Request):
    """Run now: one poller (and optionally one lane), or every poller that can run speed tests."""
    form = await request.form()
    nxt = _safe_next(form.get("next"))
    pid = int(form.get("poller_id") or 0) if str(form.get("poller_id") or "").isdigit() else 0
    lane = str(form.get("lane") or "").strip()[:64] or None
    hub = st(request).hub
    with st(request).db.session() as s:
        q = select(Poller).where(Poller.revoked.is_(False))
        if pid:
            q = q.where(Poller.id == pid)
        targets = [(p.id, p.name, "speedtest" in (p.features or []), speedtest.poller_config(s, p))
                   for p in s.scalars(q)]
    sent, old, capped, offline = [], [], [], []
    for p_id, name, ok, cfg in targets:
        if not ok:
            old.append(name)
            continue
        lanes = [ln for ln in cfg["lanes"] if lane is None or ln["key"] == lane]
        if lanes and all(ln.get("blocked") for ln in lanes):
            capped.append(name)
            continue
        if hub.send_soon(p_id, {"type": "speedtest_now", "lane": lane}):
            sent.append(name)
        else:
            offline.append(name)
    if sent:
        flash(request, f"Speed test started on {', '.join(sent)}. Results arrive in about a minute; refresh to see them.")
    if capped:
        flash(request, f"{', '.join(capped)}: this month's data cap is used up, so no test was started.", "warn")
    if old:
        flash(request, f"{', '.join(old)} can't run speed tests yet. Update the poller first.", "warn")
    if offline:
        flash(request, f"{', '.join(offline)} {'is' if len(offline) == 1 else 'are'} not connected right now.", "warn")
    if not targets:
        flash(request, "There is no poller to run a speed test on.", "warn")
    return back(nxt)


@router.get("/ui/metrics/speedtest", include_in_schema=False)
def speedtest_series(request: Request, metric: str = "download", range: str = "7d", poller: int = 0):
    with st(request).db.session() as s:
        return speedtest.series(s, metric, range, poller or None)
