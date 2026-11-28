"""The Wireless dashboard: every Wi-Fi client, radio and SSID with quality figures, filters and history."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from sqlalchemy import select

from . import wireless as W
from .models import Alert
from .unifi_views import _ctx, _unifi
from .web import render, st

router = APIRouter(include_in_schema=False)

BAND_ORDER = {"2.4 GHz": 0, "5 GHz": 1, "6 GHz": 2, "60 GHz": 3}


def _chan_key(v: Any) -> tuple:
    try:
        return (0, int(v))
    except (TypeError, ValueError):
        return (1, str(v))


def wireless_context(data: dict) -> dict[str, Any]:
    clients = [c for c in data.get("clients") or [] if not c.get("wired")]
    aps = data.get("aps") or []
    radios = []
    for a in aps:
        for r in a.get("radios") or []:
            radios.append({**r, "ap": a.get("name"), "ap_mac": a.get("mac"), "site": a.get("site"), "ap_status": a.get("status"),
                           "ssids": a.get("ssids") or [], "model": a.get("model")})
    radios.sort(key=lambda r: (-(r.get("utilization") or 0)))
    bands = sorted({x.get("band") for x in clients + radios if x.get("band")}, key=lambda b: BAND_ORDER.get(b, 9))
    channels: dict[str, dict[str, dict]] = {}
    for r in radios:
        if not r.get("band") or not r.get("channel"):
            continue
        ch = channels.setdefault(r["band"], {}).setdefault(str(r["channel"]), {"channel": r["channel"], "aps": [], "clients": 0, "util": None})
        ch["aps"].append(r.get("ap"))
        ch["clients"] += int(r.get("clients") or 0)
        if r.get("utilization") is not None:
            ch["util"] = max(ch["util"] or 0, r["utilization"])
    channel_bands = [(b, sorted(channels[b].values(), key=lambda c: _chan_key(c["channel"]))) for b in bands if b in channels]
    return {
        "w": (data.get("wifi") or {}).get("summary") or W.summarize(clients, radios, aps, [], _now()),
        "wclients": clients, "radios": radios, "wssids": data.get("ssids") or [], "aps": aps,
        "reboots": list(reversed((data.get("wifi") or {}).get("reboots") or []))[:50],
        "f_sites": sorted({x.get("site") for x in clients + radios if x.get("site")}),
        "f_ssids": sorted({s.get("name") for s in data.get("ssids") or [] if s.get("name")} | {c.get("ssid") for c in clients if c.get("ssid")}),
        "f_bands": bands,
        "f_channels": [(b, sorted({str(x.get("channel")) for x in clients + radios if x.get("band") == b and x.get("channel")}, key=_chan_key)) for b in bands],
        "f_aps": sorted(((a.get("mac"), a.get("name")) for a in aps if a.get("mac")), key=lambda x: str(x[1]).lower()),
        "channel_bands": channel_bands, "sticky": [c for c in clients if c.get("sticky")],
        "events_ok": bool(data.get("events_ok")),
        "T": {"rssi_good": W.RSSI_GOOD, "rssi_weak": W.RSSI_WEAK, "snr_good": W.SNR_GOOD, "snr_poor": W.SNR_POOR,
              "retry_warn": W.RETRY_WARN, "retry_bad": W.RETRY_BAD, "util_warn": W.UTIL_WARN, "util_bad": W.UTIL_BAD},
    }


def _now():
    from .models import utcnow
    return utcnow()


@router.get("/wireless", response_class=HTMLResponse)
def wireless_home(request: Request, i: int | None = None):
    with st(request).db.session() as s:
        integ, others = _unifi(s, i)
        if integ is None:
            return render(request, "wireless.html", {"integ": None, "others": []})
        ctx = _ctx(s, integ, others)
        refs = (f"wifi:{integ.id}:", f"radio:{integ.id}:")
        ctx["alerts"] = [a for a in s.scalars(select(Alert).where(Alert.state.in_(("open", "ack")), Alert.rule_key.in_(W.ALERT_KEYS))
                                               .order_by(Alert.opened_at.desc()).limit(200)) if a.ref.startswith(refs)]
    ctx.update(wireless_context(ctx["data"]))
    return render(request, "wireless.html", ctx)
