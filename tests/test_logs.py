from app.services import views
from app.services.logs_import import ColumnMap, normalise_action, parse_ts, parse_upload
from app.zia.policies import normalise_rule

PORTAL_CSV = b"""Web Insights Logs
Generated on 11/25/2026
Time,User,URL,Policy Action,URL Category,URL Filter Rule,Cloud App Rule,Sent Bytes,Received Bytes,Location
11/24/2026 14:05:10,ana@acme.example,bad.example/login,Blocked,Phishing,Block phishing,,512,0,London
11/24/2026 14:06:00,ben@acme.example,mail.google.com,Isolate,Web Mail,,Isolate webmail,1200,90000,Austin
not a date,ben@acme.example,x.example,Allowed,,Allow all,,1,1,Austin
"""


def test_parse_ts_formats():
    assert parse_ts("Mon Jun 20 15:29:11 2022") == "2022-06-20T15:29:11+00:00"
    assert parse_ts("2026-11-24T10:00:00-05:00") == "2026-11-24T15:00:00+00:00"
    assert parse_ts("1700000000000") == "2023-11-14T22:13:20+00:00"
    assert parse_ts("11/24/2026 02:05:10 PM") == "2026-11-24T14:05:10+00:00"
    assert parse_ts("garbage") is None


def test_normalise_action():
    assert [normalise_action(a) for a in ("Allowed", "Blocked", "Isolate", "Caution", "Drop", "")] == \
        ["Allowed", "Blocked", "Isolated", "Caution", "Blocked", "Other"]


def test_portal_csv_with_title_lines():
    events, skipped, cmap = parse_upload(PORTAL_CSV, "web", import_id=1)
    assert skipped == 1 and len(events) == 2
    a, b = events
    assert a["rule_label"] == "Block phishing" and a["policy_type"] == "URL filtering" and a["action"] == "Blocked"
    assert b["rule_label"] == "Isolate webmail" and b["policy_type"] == "Cloud app control" and b["action"] == "Isolated"
    assert b["bytes_in"] == 90000 and b["bytes_out"] == 1200 and b["location"] == "Austin"
    assert cmap.unmapped == []


def test_nss_style_json_lines():
    content = b'{"event":{"datetime":"Mon Nov 23 10:00:00 2026","login":"c@acme.example","action":"Blocked","dnsreqrulelabel":"Block DoH","req":"dns.example"}}\n'
    events, _, _ = parse_upload(content, "dns")
    assert events[0]["rule_label"] == "Block DoH" and events[0]["policy_type"] == "DNS control"
    assert events[0]["destination"] == "dns.example"


def test_unusable_file_reports_missing_columns():
    events, _, cmap = parse_upload(b"a,b,c\n1,2,3\n", "web")
    assert events == [] and "a time column" in cmap.missing()


def test_column_map_is_loose_about_header_spelling():
    cmap = ColumnMap(["Date Time", "User Name", "Rule-Label", "Policy Action"])
    assert cmap.fields["ts"] == "Date Time" and cmap.fields["user"] == "User Name"
    assert cmap.rule_cols == [("Rule-Label", None)]


def test_views_join_logs_to_rules_and_count_hits(store):
    store.put_snapshot("rules", [
        normalise_rule("URL filtering", {"id": 1, "name": "Block phishing", "order": 1, "action": "BLOCK"}).to_dict(),
        normalise_rule("Cloud app control", {"id": 2, "name": "Isolate webmail", "order": 1, "actions": ["ISOLATE_WEBMAIL_VIEW"]}).to_dict(),
        normalise_rule("URL filtering", {"id": 3, "name": "Unused", "order": 2, "action": "ALLOW"}).to_dict(),
    ])
    events, _, _ = parse_upload(PORTAL_CSV, "web", import_id=1)
    store.add_events(events)

    data = views.logs(store)
    assert data["total"] == 2
    assert {r["rule"]["id"] for r in data["rows"]} == {"1", "2"}

    hits = {r["name"]: r["hits"] for r in views.rules_with_hits(store)["rows"]}
    assert hits == {"Block phishing": 1, "Isolate webmail": 1, "Unused": 0}

    o = views.overview(store)
    assert o["kpis"]["users_seen"] == 2 and o["kpis"]["isolated"] == 1
    assert [r["name"] for r in o["health"]["unused"]] == ["Unused"]

    u = views.users(store, 48)
    assert [r["user"] for r in u["rows"]] == ["ben@acme.example", "ana@acme.example"]
    assert u["rows"][0]["Isolated"] == 1
