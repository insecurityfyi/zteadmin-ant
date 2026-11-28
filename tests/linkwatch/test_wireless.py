"""Wireless dashboard: UniFi wireless detail, rates between polls, roll-up series, alerts, the page and map clients."""
import copy
import time
from datetime import datetime

import httpx
import respx
from sqlalchemy import select

from linkwatch.integrations import build
from linkwatch.integrations.unifi import event_kind
from linkwatch.server import wireless
from tests.linkwatch.test_integrations import UNIFI, UNIFI_CLIENTS, UNIFI_DEVICES, mock_unifi


def collect(devices=None, clients=None):
    with respx.mock:
        mock_unifi()
        if devices is not None or clients is not None:
            ok = lambda d: httpx.Response(200, json={"meta": {"rc": "ok"}, "data": d})  # noqa: E731
            respx.get(f"{UNIFI}/s/default/stat/device").mock(return_value=ok(devices if devices is not None else UNIFI_DEVICES))
            respx.get(f"{UNIFI}/s/default/stat/sta").mock(return_value=ok(clients if clients is not None else UNIFI_CLIENTS))
        c = build("unifi", {"host": "192.168.1.1", "api_key": "k"})
        recs = c.collect()
    return recs, c.data, c.errors


def test_event_kinds():
    assert event_kind("EVT_WU_Connected") == "connect"
    assert event_kind("EVT_WU_RoamRadio") == "roam"
    assert event_kind("EVT_WU_Disconnected", "DHCP timeout") == "dhcp_fail"
    assert event_kind("EVT_WU_AssocFail") == "assoc_fail"
    assert event_kind("EVT_WU_Something", "WPA authentication failed") == "auth_fail"
    assert event_kind("EVT_SW_Lost_Contact", "switch lost") is None


def test_collector_reports_wireless_detail():
    _, data, errors = collect()
    laptop = next(c for c in data["clients"] if c["mac"] == "cc:00:00:00:00:01")
    assert laptop["snr"] == 40 and laptop["roam_count"] == 2 and laptop["tx_retries"] == 200 and laptop["retry_pct"] is None
    phone = next(c for c in data["clients"] if c["mac"] == "cc:00:00:00:00:02")
    assert phone["retry_pct"] == 22.5 and phone["snr"] == 12
    nas = next(c for c in data["clients"] if c["wired"])
    assert "snr" not in nas
    ng, na = data["aps"][0]["radios"]
    assert (ng["utilization"], ng["interference"], ng["tx_power"], ng["tx_dropped"]) == (72, 50, 17, 10)
    assert (na["interference"], na["tx_dropped"], na["rx_dropped"]) == (3, 3, 1)
    assert data["aps"][0]["uptime_s"] == 86400
    by = {s["name"]: s for s in data["ssids"]}
    assert by["Office"]["events"]["connect"] == 1 and by["Office"]["events"]["roam"] == 1
    assert by["Guest"]["events"]["auth_fail"] == 1 and by["Guest"]["events"]["dhcp_fail"] == 1
    assert data["events_ok"] is True and not errors


def test_missing_event_log_is_silent():
    with respx.mock:
        mock_unifi()
        respx.get(url__startswith=f"{UNIFI}/s/default/stat/event").mock(return_value=httpx.Response(404))
        c = build("unifi", {"host": "192.168.1.1", "api_key": "k"})
        c.collect()
    assert c.data["events_ok"] is False and c.errors == []


def test_enrich_works_out_rates_roams_sticky_and_reboots():
    _, d1, _ = collect()
    t = datetime(2026, 11, 28, 12, 0)
    wireless.enrich(None, d1, t)
    laptop = next(c for c in d1["clients"] if c["mac"] == "cc:00:00:00:00:01")
    assert laptop["retry_pct"] == 2.0                    # cumulative on the first poll: 200 / (10000 + 200)
    assert d1["aps"][0]["radios"][0]["retry_pct"] == 10.0 and d1["aps"][0]["radios"][0]["congested"] is True
    assert d1["wifi"]["summary"]["congested"] == 1 and d1["wifi"]["summary"]["weak"] == 1

    # second AP so the weak phone has somewhere better to go; counters move; the first AP reboots
    devices = copy.deepcopy(UNIFI_DEVICES)
    ap2 = copy.deepcopy(devices[0])
    ap2.update(mac="aa:aa:aa:00:00:09", name="ap-hall", _id="9")
    devices[0]["uptime"] = 60
    devices[0]["radio_table_stats"][0].update(tx_packets=10000, tx_retries=1400)
    devices.append(ap2)
    clients = copy.deepcopy(UNIFI_CLIENTS)
    clients[0].update(tx_packets=10900, tx_retries=300)
    prev = d1
    for i in range(1, 4):
        _, d, _ = collect(devices, clients)
        wireless.enrich(prev, d, t.replace(minute=5 * i))
        prev = d
    laptop = next(c for c in d["clients"] if c["mac"] == "cc:00:00:00:00:01")
    phone = next(c for c in d["clients"] if c["mac"] == "cc:00:00:00:00:02")
    assert laptop["retry_pct"] == 10.0       # counters unchanged after poll 2: keeps that poll's figure
    assert phone["sticky"] and phone["weak_polls"] == 4 and "sticky" in phone["flags"]
    assert d["wifi"]["summary"]["sticky"] == 1
    assert len(d["wifi"]["reboots"]) == 1 and d["aps"][0]["reboots_7d"] == 1

    # the rate between two polls
    _, d2, _ = collect(devices, clients)
    wireless.enrich(d1, d2, t.replace(minute=5))
    laptop = next(c for c in d2["clients"] if c["mac"] == "cc:00:00:00:00:01")
    assert laptop["retry_pct"] == 10.0       # 100 retries over 900 packets + 100 retries
    assert d2["aps"][0]["radios"][0]["retry_pct"] == 28.6     # 400 / (1000 + 400)


def test_roam_is_seen_when_the_ap_changes():
    _, d1, _ = collect()
    wireless.enrich(None, d1, datetime(2026, 11, 28))
    clients = copy.deepcopy(UNIFI_CLIENTS)
    clients[0]["ap_mac"] = "aa:aa:aa:00:00:09"
    _, d2, _ = collect(clients=clients)
    wireless.enrich(d1, d2, datetime(2026, 11, 28, 0, 5))
    assert next(c for c in d2["clients"] if c["mac"] == "cc:00:00:00:00:01")["roamed"] is True


def _ingest(app, integ_id=None, clients=None, ts=None):
    from linkwatch.server.alerts import Alerter
    from linkwatch.server.ingest import ingest_integration
    from linkwatch.server.models import Integration
    recs, data, _ = collect(clients=clients)
    with app.state.lw.db.session() as s:
        if integ_id is None:
            integ = Integration(kind="unifi", name="Home UniFi", config_enc=app.state.lw.vault.seal({"host": "192.168.1.1", "api_key": "k"}))
            s.add(integ)
            s.flush()
        else:
            integ = s.get(Integration, integ_id)
        ingest_integration(s, Alerter(s), integ, {"ok": True, "records": recs, "data": data, "ts": ts or time.time()})
        return integ.id


def test_alerts_series_page_and_map(logged_in, app):
    from linkwatch.server.models import Alert
    t0 = time.time() - 900
    iid = _ingest(app, ts=t0)
    with app.state.lw.db.session() as s:
        assert not s.scalars(select(Alert).where(Alert.rule_key.like("wifi_%"))).all()     # needs 3 polls
    _ingest(app, iid, ts=t0 + 300)
    _ingest(app, iid, ts=t0 + 600)
    with app.state.lw.db.session() as s:
        open_ = {(a.rule_key, a.ref) for a in s.scalars(select(Alert).where(Alert.state == "open"))}
    assert ("wifi_low_rssi", f"wifi:{iid}:cc:00:00:00:00:02") in open_       # -78 dBm
    assert ("wifi_retries", f"wifi:{iid}:cc:00:00:00:00:02") in open_        # 22.5 %
    assert ("wifi_low_rssi", f"wifi:{iid}:cc:00:00:00:00:01") not in open_
    assert ("wifi_congestion", f"radio:{iid}:aa:aa:aa:00:00:01/ng") in open_  # 72 % busy

    # roll-up series for the graphs
    q = logged_in.get(f"/ui/metrics/integration/{iid}/wq%3Aall").json()
    assert q["a"][-1] == -66.5 and q["c"][-1] == 1.0
    assert logged_in.get(f"/ui/metrics/integration/{iid}/wu%3Aband%3A2.4 GHz").json()["a"][-1] == 72
    assert logged_in.get(f"/ui/metrics/integration/{iid}/wclient%3Acc:00:00:00:00:01").json()["b"][-1] == 40
    assert logged_in.get(f"/ui/metrics/integration/{iid}/wev%3AGuest").json()["a"][-1] == 1

    page = logged_in.get("/wireless").text
    assert "<h1>Wireless</h1>" in page and 'data-f="ssid"' in page and 'data-f="ch"' in page and 'data-f="ap"' in page
    assert 'data-ch-pick="2.4 GHz/6"' in page and "Congested channel" in page and "Weak Wi-Fi signal" in page
    assert 'data-wtable="clients"' in page and 'data-rssi="-78.0"' in page and "sticky" in page
    assert 'href="/wireless?i=' in page          # nav entry
    assert "SNR and retries" in logged_in.get(f"/unifi/{iid}/clients/cc:00:00:00:00:01").text

    # the phone leaves: its alerts clear
    _ingest(app, iid, clients=[c for c in UNIFI_CLIENTS if c["mac"] != "cc:00:00:00:00:02"], ts=t0 + 900)
    with app.state.lw.db.session() as s:
        still = {(a.rule_key, a.ref) for a in s.scalars(select(Alert).where(Alert.state == "open"))}
    assert not any(ref.endswith("cc:00:00:00:00:02") for _, ref in still)

    # map: clients only when asked for, on their AP with signal and band
    plain = logged_in.get("/ui/map").json()
    assert not any(n.get("client") for n in plain["nodes"])
    m = logged_in.get("/ui/map?clients=1").json()
    laptop = next(n for n in m["nodes"] if n["id"] == "c:cc:00:00:00:00:01")
    link = next(l for l in m["links"] if l["target"] == laptop["id"])
    assert link["protocol"] == "wifi" and link["rssi"] == -55 and link["band"] == "5 GHz"
    assert laptop["href"] == f"/unifi/{iid}/clients/cc:00:00:00:00:01"
    assert 'name="clients"' in logged_in.get("/map").text


def test_wireless_page_without_unifi(logged_in):
    r = logged_in.get("/wireless")
    assert r.status_code == 200 and "No wireless source yet" in r.text
