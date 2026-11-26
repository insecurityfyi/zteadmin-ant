"""Path probe pages: the list, the settings form, and the hop-by-hop detail page with history."""
from __future__ import annotations

from datetime import timedelta
from types import SimpleNamespace

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import select

from . import events, paths
from .alerts import Alerter
from .models import Alert, PathProbe, PathResult, Poller, utcnow
from .web import _who, back, flash, render, st

router = APIRouter(include_in_schema=False)
RANGES = {"6h": (timedelta(hours=6), 0), "24h": (timedelta(hours=24), 900), "7d": (timedelta(days=7), 3600),
          "30d": (timedelta(days=30), 4 * 3600)}


def _pollers(s) -> list[Poller]:
    return list(s.scalars(select(Poller).where(Poller.revoked.is_(False)).order_by(Poller.name)))


def _latest(s, probe_id: int) -> dict[int, PathResult]:
    out: dict[int, PathResult] = {}
    for r in s.scalars(select(PathResult).where(PathResult.probe_id == probe_id, PathResult.ts >= utcnow() - timedelta(days=2))
                       .order_by(PathResult.ts.desc()).limit(200)):
        out.setdefault(r.poller_id, r)
    return out


def status(r: PathResult | None, probe: PathProbe, s=None) -> str:
    if r is None:
        return "unknown"
    if not r.ok:
        return "error"
    if not r.reached:
        return "down"
    if (r.loss_pct or 0) > (probe.loss_pct if probe.loss_pct is not None else 0) or (
            probe.latency_ms is not None and (r.avg_ms or 0) > probe.latency_ms):
        return "warn"
    return "up"


@router.get("/probes", response_class=HTMLResponse)
def probe_list(request: Request):
    with st(request).db.session() as s:
        pollers = {p.id: p for p in _pollers(s)}
        rows = []
        for p in s.scalars(select(PathProbe).order_by(PathProbe.name)):
            latest = _latest(s, p.id)
            cache = paths.lookup(s, [h["ip"] for r in latest.values() for h in (r.hops or []) if h["ip"]], budget=0)
            per = []
            for pid in p.poller_ids or []:
                r = latest.get(pid)
                nets = []
                for h in (r.hops if r else []) or []:
                    n = paths.network_of(h["ip"], cache)
                    if h["ip"] and n["key"] not in (None, "?") and (not nets or nets[-1]["key"] != n["key"]):
                        nets.append(n)
                per.append({"poller": pollers.get(pid), "poller_id": pid, "r": r, "status": status(r, p), "nets": nets})
            rows.append({"p": p, "per": per})
        open_refs = {a.ref for a in s.scalars(select(Alert).where(Alert.rule_key.like("path_%"), Alert.state.in_(("open", "ack"))))}
        for row in rows:
            row["alerts"] = sum(1 for x in row["per"] if paths.ref(row["p"].id, x["poller_id"]) in open_refs)
    return render(request, "probes.html", {"rows": rows, "protocols": paths.PROTOCOLS, "intervals": paths.INTERVALS})


def _form(request: Request, probe, problems=(), status_code=200):
    with st(request).db.session() as s:
        pollers = _pollers(s)
        for p in pollers:
            s.expunge(p)
    return render(request, "probe_form.html", {"probe": probe, "pollers": pollers, "problems": list(problems),
                                               "protocols": paths.PROTOCOLS, "intervals": paths.INTERVALS},
                  status_code=status_code)


def _blank() -> SimpleNamespace:
    return SimpleNamespace(id=None, name="", target="", protocol="icmp", port=None, count=10, interval_s=300, poller_ids=[],
                           enabled=True, loss_pct=None, latency_ms=None)


def _read(form, probe) -> list[str]:
    problems = []
    probe.name = str(form.get("name") or "").strip()[:120]
    probe.target = str(form.get("target") or "").strip()[:253]
    probe.protocol = form.get("protocol") if form.get("protocol") in paths.PROTOCOLS else "icmp"
    if not probe.name:
        problems.append("Give the probe a name.")
    if not paths.TARGET.match(probe.target) or probe.target.startswith("-"):
        problems.append("Target must be a host name or IP address, such as 8.8.8.8 or www.example.com.")

    def num(field, lo, hi, kind=int, required=False):
        raw = str(form.get(field) or "").strip()
        if not raw:
            if required:
                problems.append(f"{field.replace('_', ' ').capitalize()} is required.")
            return None
        try:
            v = kind(raw)
        except ValueError:
            problems.append(f"{field.replace('_', ' ').capitalize()} must be a number.")
            return None
        if not lo <= v <= hi:
            problems.append(f"{field.replace('_', ' ').capitalize()} must be between {lo} and {hi}.")
            return None
        return v
    probe.port = num("port", 1, 65535, required=probe.protocol == "tcp") if probe.protocol != "icmp" else None
    probe.count = num("count", 1, 100) or 10
    iv = num("interval_s", 60, 86400) or 300
    probe.interval_s = iv if iv in paths.INTERVALS else 300
    probe.loss_pct = num("loss_pct", 0, 100, float)
    probe.latency_ms = num("latency_ms", 1, 60000, float)
    probe.poller_ids = sorted({int(x) for x in form.getlist("poller_id") if str(x).isdigit()})
    probe.enabled = form.get("enabled") is not None
    if not probe.poller_ids:
        problems.append("Pick at least one poller to run it from.")
    return problems


def _push(request: Request, poller_ids) -> None:
    for pid in set(poller_ids or []):
        st(request).hub.push_config_soon(pid)


@router.get("/probes/new", response_class=HTMLResponse)
def probe_new(request: Request, target: str = ""):
    probe = _blank()
    probe.target = target[:253]
    with st(request).db.session() as s:
        live = [p.id for p in _pollers(s)]
    probe.poller_ids = live[:1]
    return _form(request, probe)


@router.post("/probes/new")
async def probe_create(request: Request):
    form = await request.form()
    probe = PathProbe()
    problems = _read(form, probe)
    if problems:
        return _form(request, probe, problems, 400)
    with st(request).db.session() as s:
        valid = {p.id for p in _pollers(s)}
        probe.poller_ids = [p for p in probe.poller_ids if p in valid]
        s.add(probe)
        s.flush()
        pid = probe.id
        events.log(s, "config", f"Path probe '{probe.name}' to {probe.target} created by {_who(request)}", "info", username=_who(request))
    _push(request, probe.poller_ids)
    flash(request, f"Path probe '{probe.name}' saved. The first result arrives within a minute.")
    return back(f"/probes/{pid}")


@router.get("/probes/{probe_id}/edit", response_class=HTMLResponse)
def probe_edit(request: Request, probe_id: int):
    with st(request).db.session() as s:
        probe = s.get(PathProbe, probe_id)
        if probe is None:
            raise HTTPException(404, "No such path probe")
        s.expunge(probe)
    return _form(request, probe)


@router.post("/probes/{probe_id}/edit")
async def probe_update(request: Request, probe_id: int):
    form = await request.form()
    with st(request).db.session() as s:
        probe = s.get(PathProbe, probe_id)
        if probe is None:
            raise HTTPException(404, "No such path probe")
        before = set(probe.poller_ids or [])
        problems = _read(form, probe)
        if problems:
            s.expunge(probe)
            return _form(request, probe, problems, 400)
        alerter = Alerter(s)
        paths.clear_alerts(alerter, probe.id, set(probe.poller_ids) if probe.enabled else set())
        events.log(s, "config", f"Path probe '{probe.name}' changed by {_who(request)}", "info", username=_who(request))
        after = set(probe.poller_ids)
    st(request).notifier.dispatch(alerter.events)
    _push(request, before | after)
    flash(request, f"Path probe '{probe.name}' saved.")
    return back(f"/probes/{probe_id}")


@router.post("/probes/{probe_id}/delete")
def probe_delete(request: Request, probe_id: int):
    with st(request).db.session() as s:
        probe = s.get(PathProbe, probe_id)
        if probe is None:
            raise HTTPException(404, "No such path probe")
        name, pollers = probe.name, list(probe.poller_ids or [])
        alerter = Alerter(s)
        paths.clear_alerts(alerter, probe.id)
        s.delete(probe)
        events.log(s, "config", f"Path probe '{name}' deleted by {_who(request)}", "info", username=_who(request))
    st(request).notifier.dispatch(alerter.events)
    _push(request, pollers)
    flash(request, f"Path probe '{name}' deleted.")
    return back("/probes")


@router.post("/probes/{probe_id}/run")
def probe_run(request: Request, probe_id: int):
    with st(request).db.session() as s:
        probe = s.get(PathProbe, probe_id)
        if probe is None:
            raise HTTPException(404, "No such path probe")
        sent = [pid for pid in probe.poller_ids or [] if st(request).hub.send_soon(pid, {"type": "probe_now", "probe_id": probe.id})]
    flash(request, "Running now. Refresh in a few seconds to see the result." if sent else
          "None of this probe's pollers is connected right now.", "ok" if sent else "warn")
    return back(f"/probes/{probe_id}")


@router.get("/probes/{probe_id}", response_class=HTMLResponse)
def probe_detail(request: Request, probe_id: int, poller: int = 0, result: int = 0):
    with st(request).db.session() as s:
        probe = s.get(PathProbe, probe_id)
        if probe is None:
            raise HTTPException(404, "No such path probe")
        all_pollers = {p.id: p for p in s.scalars(select(Poller))}
        latest = _latest(s, probe.id)
        chosen = poller if poller in (probe.poller_ids or []) else ((probe.poller_ids or [0])[0])
        shown = None
        if result:
            shown = s.get(PathResult, result)
            if shown is None or shown.probe_id != probe.id:
                shown = None
            else:
                chosen = shown.poller_id
        if shown is None:
            shown = latest.get(chosen)
        last_ok = shown if shown is not None and shown.ok else s.scalar(
            select(PathResult).where(PathResult.probe_id == probe.id, PathResult.poller_id == chosen, PathResult.ok.is_(True))
            .order_by(PathResult.ts.desc()).limit(1))
        hops = (last_ok.hops if last_ok else None) or []
        cache = paths.lookup(s, [h["ip"] for h in hops if h["ip"]], budget=4)
        src = all_pollers.get(chosen)
        dia = paths.diagram(hops, cache, src.name if src else "Poller", probe.target) if hops else None
        table = [dict(h, net=paths.network_of(h["ip"], cache)) for h in hops]
        changes = s.scalars(select(PathResult).where(PathResult.probe_id == probe.id, PathResult.poller_id == chosen,
                                                     PathResult.changed.is_not(None)).order_by(PathResult.ts.desc()).limit(25)).all()
        alerts = s.scalars(select(Alert).where(Alert.ref == paths.ref(probe.id, chosen), Alert.state.in_(("open", "ack")))).all()
        missing = [all_pollers[p].name for p in probe.poller_ids or []
                   if p in all_pollers and all_pollers[p].last_seen and "mtr" not in (all_pollers[p].features or [])]
        nets = []
        for h in table:
            if h["ip"] and h["net"]["key"] not in (None, "?") and (not nets or nets[-1]["key"] != h["net"]["key"]):
                nets.append(h["net"])
        ctx = {"probe": probe, "pollers": all_pollers, "chosen": chosen, "latest": latest, "shown": shown, "last_ok": last_ok,
               "dia": dia, "table": table, "changes": changes, "alerts": alerts, "missing": missing, "nets": nets,
               "status": status(shown, probe), "protocols": paths.PROTOCOLS, "intervals": paths.INTERVALS,
               "is_latest": shown is not None and latest.get(chosen) is not None and shown.id == latest[chosen].id,
               "statuses": {pid: status(latest.get(pid), probe) for pid in probe.poller_ids or []},
               "update_cmd": None}
        if missing:
            from .gateway import update_command
            ctx["update_cmd"] = update_command()
        s.expunge_all()
    return render(request, "probe.html", ctx)


@router.get("/ui/metrics/probe/{probe_id}/{poller}", include_in_schema=False)
def probe_series(request: Request, probe_id: int, poller: int, range: str = "24h"):
    span, step = RANGES.get(range, RANGES["24h"])
    with st(request).db.session() as s:
        rows = s.execute(select(PathResult.ts, PathResult.avg_ms, PathResult.worst_ms, PathResult.jitter_ms, PathResult.loss_pct,
                                PathResult.hop_count)
                         .where(PathResult.probe_id == probe_id, PathResult.poller_id == poller, PathResult.ok.is_(True),
                                PathResult.ts >= utcnow() - span).order_by(PathResult.ts)).all()
    keys = ("avg", "worst", "jitter", "loss", "hops")
    if step:
        buckets: dict[int, list] = {}
        for r in rows:
            buckets.setdefault(int(r[0].timestamp()) // step, []).append(r)
        out = {"ts": [], **{k: [] for k in keys}}
        for b in sorted(buckets):
            grp = buckets[b]
            out["ts"].append(grp[0][0].isoformat() + "Z")
            for i, k in enumerate(keys, 1):
                vals = [g[i] for g in grp if g[i] is not None]
                out[k].append(round((max(vals) if k == "worst" else sum(vals) / len(vals)), 2) if vals else None)
        return out
    return {"ts": [r[0].isoformat() + "Z" for r in rows], **{k: [r[i] for r in rows] for i, k in enumerate(keys, 1)}}
