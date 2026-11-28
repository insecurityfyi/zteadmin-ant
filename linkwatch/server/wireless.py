"""Wireless quality: rates between polls, roll-ups for the Wireless dashboard, its time series and its alerts.

The UniFi collector reports cumulative counters (retries, packets, drops, roams) and point-in-time figures
(signal, noise, utilization). ``enrich`` compares each snapshot with the previous one to work out retry
rates, drops per poll, roams, sticky clients and AP reboots, and leaves the results in the snapshot.

Good / bad thresholds follow the usual Wi-Fi design guidance:
RSSI -67 dBm or better is good, SNR 25 dB or more is good, retries above 10-15 % hurt,
channel utilization above 50-60 % is congested.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from statistics import median
from typing import Any

RSSI_GOOD, RSSI_WEAK = -67.0, -75.0
SNR_GOOD, SNR_POOR = 25.0, 15.0
RETRY_WARN, RETRY_BAD = 10.0, 15.0
UTIL_WARN, UTIL_BAD = 50.0, 60.0
STICKY_POLLS = 3          # weak on the same AP for this many polls while another AP serves the SSID
REBOOT_KEEP_DAYS = 7
ALERT_KEYS = ("wifi_low_rssi", "wifi_retries", "wifi_congestion")

Point = tuple[str, "float | None", "float | None", "float | None"]


def _num(v: Any) -> float | None:
    try:
        return None if v is None or v == "" else float(v)
    except (TypeError, ValueError):
        return None


def _delta(new: Any, old: Any) -> float | None:
    a, b = _num(new), _num(old)
    if a is None or b is None or a < b:      # counter reset (reconnect, reboot)
        return None
    return a - b


def _avg(vals: list[float]) -> float | None:
    return round(sum(vals) / len(vals), 1) if vals else None


def radio_id(ap_mac: str | None, r: dict) -> str:
    return f"{ap_mac}/{r.get('radio') or r.get('band')}"


# ---------------------------------------------------------------- normalize
CLIENT_KEYS = ("snr", "noise", "retry_pct", "roam_count", "tx_retries", "tx_packets", "tx_attempts", "bssid", "idle_s", "proto",
               "signal", "channel", "band", "ssid", "ap", "ap_mac", "satisfaction", "tx_rate_mbps", "rx_rate_mbps", "uptime_s")
RADIO_KEYS = ("radio", "name", "band", "channel", "width", "tx_power", "clients", "utilization", "self_rx", "self_tx", "interference",
              "noise", "tx_packets", "tx_retries", "tx_dropped", "rx_dropped", "satisfaction", "retry_pct", "drops", "avg_signal")
EVENT_KEYS = ("auth_fail", "assoc_fail", "dhcp_fail", "roam", "connect", "disconnect")


def normalize(data: dict) -> dict:
    """Fill in every field the Wireless pages read, so a snapshot from an older poller (or one UniFi left gaps in)
    renders instead of failing. Works in place and returns ``data``."""
    if not isinstance(data, dict):
        return {}
    for c in data.get("clients") or []:
        if c.get("wired"):
            continue
        for k in CLIENT_KEYS:
            c.setdefault(k, None)
        for k in ("signal", "noise", "snr", "retry_pct", "roam_count", "satisfaction", "tx_rate_mbps", "rx_rate_mbps"):
            c[k] = _num(c.get(k))
        if c["snr"] is None and c["signal"] is not None and c["noise"] is not None:
            c["snr"] = round(c["signal"] - c["noise"], 1)
        c.setdefault("roamed", False)
        c.setdefault("sticky", False)
        c.setdefault("weak_polls", 0)
        c["flags"] = [f for f in c.get("flags") or flags(c) if f in ("weak", "low_snr", "retries", "sticky")]
    for a in data.get("aps") or []:
        a.setdefault("uptime_s", None)
        a.setdefault("reboots_7d", 0)
        a["ssids"] = [x for x in a.get("ssids") or [] if x]
        a["radios"] = [r for r in a.get("radios") or [] if isinstance(r, dict)]
        for r in a["radios"]:
            for k in RADIO_KEYS:
                r.setdefault(k, None)
            for k in ("tx_power", "utilization", "self_rx", "self_tx", "interference", "noise", "retry_pct", "drops", "avg_signal"):
                r[k] = _num(r.get(k))
            r["clients"] = None if _num(r.get("clients")) is None else int(_num(r["clients"]))
            r.setdefault("congested", (r["utilization"] or 0) >= UTIL_BAD)
    for x in data.get("ssids") or []:
        ev = x.get("events") if isinstance(x.get("events"), dict) else {}
        x["events"] = {k: int(_num(ev.get(k)) or 0) for k in EVENT_KEYS}
        for k in ("avg_signal", "avg_retry"):
            x[k] = _num(x.get(k))
        x["weak"] = int(_num(x.get("weak")) or 0)
        for k in ("series", "band", "security", "site", "vlan"):
            x.setdefault(k, None)
        if not isinstance(x.get("band"), str):
            x["band"] = None
        x.setdefault("enabled", True)
        x.setdefault("guest", False)
        x["aps"] = [a for a in x.get("aps") or [] if a]
    data.setdefault("events_ok", False)
    return data


# ---------------------------------------------------------------- enrich
def enrich(prev: dict | None, data: dict, ts: datetime) -> None:
    """Work out rates and experience figures from two snapshots; writes into ``data`` (and ``data["wifi"]``)."""
    prev = prev if isinstance(prev, dict) else {}
    normalize(data)
    prev_clients = {c.get("mac"): c for c in prev.get("clients") or [] if c.get("mac") and not c.get("wired")}
    prev_aps = {a.get("mac"): a for a in prev.get("aps") or [] if a.get("mac")}
    prev_radios = {radio_id(a.get("mac"), r): r for a in prev.get("aps") or [] for r in a.get("radios") or []}
    clients = [c for c in data.get("clients") or [] if not c.get("wired")]

    # APs serving each SSID per site, so a weak client with nowhere better to go is not called sticky
    ssid_aps: dict[tuple, set] = {}
    for a in data.get("aps") or []:
        for name in a.get("ssids") or []:
            ssid_aps.setdefault((a.get("site"), name), set()).add(a.get("mac"))

    for c in clients:
        p = prev_clients.get(c.get("mac")) or {}
        same_ap = bool(p) and p.get("ap_mac") == c.get("ap_mac")
        if c.get("retry_pct") is None:
            if same_ap:
                d_retry = _delta(c.get("tx_retries"), p.get("tx_retries"))
                d_att = _delta(c.get("tx_attempts"), p.get("tx_attempts"))
                if d_att is None:
                    d_pk = _delta(c.get("tx_packets"), p.get("tx_packets"))
                    d_att = d_pk + d_retry if d_pk is not None and d_retry is not None else None
                if d_retry is not None and d_att:
                    c["retry_pct"] = round(min(100.0, 100.0 * d_retry / d_att), 1)
                elif d_att == 0:
                    c["retry_pct"] = p.get("retry_pct")      # idle this poll: keep the last figure
            if c.get("retry_pct") is None and c.get("tx_retries") is not None:
                att = _num(c.get("tx_attempts")) or ((_num(c.get("tx_packets")) or 0) + (_num(c.get("tx_retries")) or 0))
                if att >= 50:
                    c["retry_pct"] = round(min(100.0, 100.0 * c["tx_retries"] / att), 1)
        c["roamed"] = bool(p) and p.get("ap_mac") not in (None, c.get("ap_mac"))
        sig = _num(c.get("signal"))
        weak = sig is not None and sig < RSSI_WEAK
        c["weak_polls"] = (int(p.get("weak_polls") or 0) + 1 if same_ap else 1) if weak else 0
        others = ssid_aps.get((c.get("site"), c.get("ssid")), set()) - {c.get("ap_mac")}
        c["sticky"] = bool(weak and c["weak_polls"] >= STICKY_POLLS and others)
        c["flags"] = flags(c)

    wifi = dict(prev.get("wifi") or {})
    reboots = [r for r in wifi.get("reboots") or []
               if _when(r.get("at")) and _when(r["at"]) > ts - timedelta(days=REBOOT_KEEP_DAYS)]
    for a in data.get("aps") or []:
        pa = prev_aps.get(a.get("mac")) or {}
        up, pup = _num(a.get("uptime_s")), _num(pa.get("uptime_s"))
        if up is not None and pup is not None and up < pup:
            reboots.append({"at": ts.isoformat() + "Z", "ap": a.get("name"), "mac": a.get("mac"), "site": a.get("site")})
        a["reboots_7d"] = sum(1 for r in reboots if r.get("mac") == a.get("mac"))
        ap_clients = [c for c in clients if c.get("ap_mac") == a.get("mac")]
        for r in a.get("radios") or []:
            pr = prev_radios.get(radio_id(a.get("mac"), r)) or {}
            d_retry, d_pk = _delta(r.get("tx_retries"), pr.get("tx_retries")), _delta(r.get("tx_packets"), pr.get("tx_packets"))
            if d_retry is not None and d_pk is not None and d_pk + d_retry > 0:
                r["retry_pct"] = round(100.0 * d_retry / (d_pk + d_retry), 1)
            elif r.get("tx_retries") is not None and (r.get("tx_packets") or 0) > 0:
                r["retry_pct"] = round(100.0 * r["tx_retries"] / (r["tx_packets"] + r["tx_retries"]), 1)
            else:
                r["retry_pct"] = None
            dt, dr = _delta(r.get("tx_dropped"), pr.get("tx_dropped")), _delta(r.get("rx_dropped"), pr.get("rx_dropped"))
            r["drops"] = (dt or 0) + (dr or 0) if dt is not None or dr is not None else None
            on_radio = [c for c in ap_clients if c.get("band") == r.get("band")]
            if r.get("noise") is None:       # no radio noise figure: the AP's noise as its clients report it
                noise = [c["noise"] for c in on_radio if c.get("noise") is not None]
                r["noise"] = median(noise) if noise else None
            sig = [c["signal"] for c in on_radio if c.get("signal") is not None]
            r["avg_signal"] = _avg(sig)
            if r.get("clients") is None:
                r["clients"] = len(on_radio)
            r["congested"] = (r.get("utilization") or 0) >= UTIL_BAD
    wifi["reboots"] = reboots[-200:]
    wifi["summary"] = summarize(clients, [r for a in data.get("aps") or [] for r in a.get("radios") or []], data.get("aps") or [], reboots, ts)
    data["wifi"] = wifi

    for s in data.get("ssids") or []:
        mine = [c for c in clients if c.get("ssid") == s.get("name") and c.get("site") == s.get("site")]
        s["avg_signal"] = _avg([c["signal"] for c in mine if c.get("signal") is not None])
        s["avg_retry"] = _avg([c["retry_pct"] for c in mine if c.get("retry_pct") is not None])
        s["weak"] = sum(1 for c in mine if (c.get("signal") or 0) < RSSI_GOOD and c.get("signal") is not None)


def _when(v: Any) -> datetime | None:
    try:
        return datetime.fromisoformat(str(v).rstrip("Z"))
    except ValueError:
        return None


def flags(c: dict) -> list[str]:
    out = []
    sig, snr, retry = _num(c.get("signal")), _num(c.get("snr")), _num(c.get("retry_pct"))
    if sig is not None and sig < RSSI_GOOD:
        out.append("weak")
    if snr is not None and snr < SNR_GOOD:
        out.append("low_snr")
    if retry is not None and retry > RETRY_WARN:
        out.append("retries")
    if c.get("sticky"):
        out.append("sticky")
    return out


def summarize(clients: list[dict], radios: list[dict], aps: list[dict], reboots: list[dict], ts: datetime) -> dict:
    sig = [c["signal"] for c in clients if c.get("signal") is not None]
    snr = [c["snr"] for c in clients if c.get("snr") is not None]
    retry = [c["retry_pct"] for c in clients if c.get("retry_pct") is not None]
    util = [r["utilization"] for r in radios if r.get("utilization") is not None]
    day = ts - timedelta(days=1)
    return {"clients": len(clients), "avg_signal": _avg(sig), "good_signal_pct": round(100.0 * sum(1 for v in sig if v >= RSSI_GOOD) / len(sig), 1) if sig else None,
            "weak": sum(1 for v in sig if v < RSSI_GOOD), "avg_snr": _avg(snr), "avg_retry": _avg(retry),
            "high_retry": sum(1 for v in retry if v > RETRY_BAD), "radios": len(radios), "congested": sum(1 for v in util if v >= UTIL_BAD),
            "avg_util": _avg(util), "max_util": max(util) if util else None, "sticky": sum(1 for c in clients if c.get("sticky")),
            "roamed": sum(1 for c in clients if c.get("roamed")),
            "aps": len(aps), "aps_up": sum(1 for a in aps if a.get("status") == "up"),
            "reboots_24h": sum(1 for r in reboots if (_when(r.get("at")) or day) > day),
            "by_band": {b: sum(1 for c in clients if c.get("band") == b) for b in sorted({c.get("band") for c in clients if c.get("band")})}}


# ---------------------------------------------------------------- series
def scopes(c: dict) -> list[str]:
    """The roll-ups a client counts towards: everything, its SSID, band, channel and AP."""
    out = ["all"]
    if c.get("ssid"):
        out.append(f"ssid:{c['ssid']}")
    if c.get("band"):
        out.append(f"band:{c['band']}")
        if c.get("channel"):
            out.append(f"chan:{c['band']}/{c['channel']}")
    if c.get("ap_mac"):
        out.append(f"ap:{c['ap_mac']}")
    return out


def series(data: dict, max_clients: int = 1000) -> list[Point]:
    """Wireless time series. Keys (a / b / c):

    * ``wq:<scope>``  average signal dBm / average retry % / weak clients (signal below -67 dBm)
    * ``wn:<scope>``  clients / average SNR dB / sticky clients
    * ``wu:<scope>``  average channel utilization % / highest utilization % / average interference %
    * ``radio:<ap mac>/<radio>``  utilization % / interference % / noise floor dBm
    * ``radiox:<ap mac>/<radio>`` clients / retry % / drops per poll
    * ``wclient:<mac>``  signal dBm / SNR dB / retry %
    * ``wev:<ssid>`` and ``wev:all``  auth failures / association failures / DHCP failures (last hour)

    ``<scope>`` is ``all``, ``ssid:<name>``, ``band:<band>``, ``chan:<band>/<channel>`` or ``ap:<mac>``.
    """
    out: list[Point] = []
    clients = [c for c in data.get("clients") or [] if not c.get("wired")]
    groups: dict[str, list[dict]] = {"all": []}
    for c in clients:
        for sc in scopes(c):
            groups.setdefault(sc, []).append(c)
    radio_groups: dict[str, list[dict]] = {"all": []}
    for a in data.get("aps") or []:
        for r in a.get("radios") or []:
            for sc in ["all", f"ap:{a.get('mac')}"] + ([f"band:{r['band']}"] if r.get("band") else []) + \
                      ([f"chan:{r['band']}/{r['channel']}"] if r.get("band") and r.get("channel") else []) + \
                      [f"ssid:{n}" for n in a.get("ssids") or []]:
                radio_groups.setdefault(sc, []).append(r)
            if a.get("mac"):
                key = radio_id(a["mac"], r)
                r["series"] = f"radio:{key}"
                out.append((f"radio:{key}", r.get("utilization"), r.get("interference"), r.get("noise")))
                out.append((f"radiox:{key}", _num(r.get("clients")), r.get("retry_pct"), r.get("drops")))
    for sc, cs in groups.items():
        sig = [c["signal"] for c in cs if c.get("signal") is not None]
        out.append((f"wq:{sc}", _avg(sig), _avg([c["retry_pct"] for c in cs if c.get("retry_pct") is not None]),
                    float(sum(1 for v in sig if v < RSSI_GOOD))))
        out.append((f"wn:{sc}", float(len(cs)), _avg([c["snr"] for c in cs if c.get("snr") is not None]),
                    float(sum(1 for c in cs if c.get("sticky")))))
    for sc, rs in radio_groups.items():
        util = [r["utilization"] for r in rs if r.get("utilization") is not None]
        out.append((f"wu:{sc}", _avg(util), max(util) if util else None,
                    _avg([r["interference"] for r in rs if r.get("interference") is not None])))
    for c in clients[:max_clients]:
        if c.get("mac"):
            out.append((f"wclient:{c['mac']}", c.get("signal"), c.get("snr"), c.get("retry_pct")))
    if data.get("events_ok"):
        tot = [0.0, 0.0, 0.0]
        for s in data.get("ssids") or []:
            ev = s.get("events") or {}
            row = [float(ev.get(k, 0)) for k in ("auth_fail", "assoc_fail", "dhcp_fail")]
            tot = [x + y for x, y in zip(tot, row)]
            out.append((f"wev:{s.get('name')}", *row))
        out.append(("wev:all", *tot))
    return out


# ---------------------------------------------------------------- alerts
def evaluate(alerter, integ, data: dict, devices: dict[str, Any] | None = None) -> None:
    """Weak signal and high retries per client, congestion per radio. Each must hold for the rule's poll count."""
    devices = devices or {}
    live: set[tuple[str, str]] = set()
    prefix = f"wifi:{integ.id}:"

    def check(key: str, ref: str, bad: bool, title: str, detail: str, device=None) -> None:
        rule = alerter.rule(key)
        live.add((key, ref))
        if rule is None:
            alerter.set(key, ref, False)
            return
        old = alerter.pending().get((key, ref), 0)
        hits = old + 1 if bad else 0
        if hits != old:
            alerter.set_pending(key, ref, hits)
        alerter.set(key, ref, bad and hits >= max(1, rule.polls), title, detail, device)

    rssi, retry, cong = (alerter.rule(k) for k in ALERT_KEYS)
    for c in data.get("clients") or []:
        if c.get("wired") or not c.get("mac"):
            continue
        ref = f"{prefix}{c['mac']}"[:80]
        where = f"{c.get('ssid') or 'Wi-Fi'} on {c.get('ap') or 'an AP'}, {c.get('band') or ''} ch {c.get('channel') or '?'}"
        sig = _num(c.get("signal"))
        thr = rssi.threshold if rssi and rssi.threshold is not None else RSSI_WEAK
        check("wifi_low_rssi", ref, sig is not None and sig < thr, f"Weak Wi-Fi signal: {c.get('name')}",
              f"{sig:.0f} dBm (threshold {thr:.0f} dBm), {where}" if sig is not None else where)
        rp = _num(c.get("retry_pct"))
        thr = retry.threshold if retry and retry.threshold is not None else RETRY_BAD
        check("wifi_retries", ref, rp is not None and rp > thr, f"High Wi-Fi retries: {c.get('name')}",
              f"{rp:.0f}% of frames retried (threshold {thr:.0f}%), {where}" if rp is not None else where)
    thr = cong.threshold if cong and cong.threshold is not None else UTIL_BAD
    for a in data.get("aps") or []:
        for r in a.get("radios") or []:
            ref = f"radio:{integ.id}:{radio_id(a.get('mac'), r)}"[:80]
            u = _num(r.get("utilization"))
            check("wifi_congestion", ref, u is not None and u > thr, f"Congested channel: {a.get('name')} {r.get('band')} ch {r.get('channel')}",
                  f"{u:.0f}% busy (threshold {thr:.0f}%), interference {r.get('interference') if r.get('interference') is not None else '?'}%, "
                  f"{r.get('clients') or 0} clients" if u is not None else "", devices.get(a.get("mac")))
    # clients that left and radios that went away: clear their alerts and counters
    mine = (prefix, f"radio:{integ.id}:")
    for key, ref in list(alerter.open):
        if key in ALERT_KEYS and ref.startswith(mine) and (key, ref) not in live:
            alerter.set(key, ref, False)
    for key, ref in list(alerter.pending()):
        if key in ALERT_KEYS and ref.startswith(mine) and (key, ref) not in live:
            alerter.set_pending(key, ref, 0)
