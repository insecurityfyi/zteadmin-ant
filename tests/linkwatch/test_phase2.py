"""Health sensors, hardware inventory, storage, LLDP/CDP neighbours and the network map."""
import asyncio

from sqlalchemy import select

from linkwatch.poller import snmp_extra
from linkwatch.server.ingest import ingest_batch
from linkwatch.server.models import Alert, Device, Event, Neighbor, Sensor, SensorMetric

from .test_ingest import batch, make_db, snmp_item


class FakeSnmp:
    """walk(base) returns {suffix: value} for every OID under base."""
    def __init__(self, table):
        self.table = table

    async def walk(self, base, max_rows=5000):
        pre = base + "."
        return {oid[len(pre):]: v for oid, v in self.table.items() if oid.startswith(pre)}

    async def get(self, oids):
        return {o: self.table.get(o) for o in oids}


ENT = "1.3.6.1.2.1.47.1.1.1.1"
TABLE = {
    # ENTITY-MIB: chassis 1, PSU 2, temperature sensor 3, port 4
    f"{ENT}.2.1": "Catalyst 9300 48-port", f"{ENT}.5.1": 3, f"{ENT}.7.1": "Switch 1", f"{ENT}.11.1": "FOC1234X0AB", f"{ENT}.13.1": "C9300-48P",
    f"{ENT}.10.1": "17.9.4",
    f"{ENT}.2.2": "Power Supply A", f"{ENT}.5.2": 6, f"{ENT}.7.2": "PSU A", f"{ENT}.11.2": "LIT0001",
    f"{ENT}.2.3": "Inlet temperature", f"{ENT}.5.3": 8, f"{ENT}.7.3": "Inlet",
    f"{ENT}.2.4": "GigabitEthernet1/0/1", f"{ENT}.5.4": 10,
    # ENTITY-SENSOR-MIB: index 3 is 41.5 C (value 415, precision 1, scale units); index 5 is a fan at 4800 rpm; 6 unavailable
    "1.3.6.1.2.1.99.1.1.1.1.3": 8, "1.3.6.1.2.1.99.1.1.1.2.3": 9, "1.3.6.1.2.1.99.1.1.1.3.3": 1, "1.3.6.1.2.1.99.1.1.1.4.3": 415, "1.3.6.1.2.1.99.1.1.1.5.3": 1,
    "1.3.6.1.2.1.99.1.1.1.1.5": 10, "1.3.6.1.2.1.99.1.1.1.2.5": 9, "1.3.6.1.2.1.99.1.1.1.3.5": 0, "1.3.6.1.2.1.99.1.1.1.4.5": 4800, "1.3.6.1.2.1.99.1.1.1.5.5": 1,
    "1.3.6.1.2.1.99.1.1.1.1.6": 8, "1.3.6.1.2.1.99.1.1.1.4.6": 0, "1.3.6.1.2.1.99.1.1.1.5.6": 2,
    # Cisco ENVMON PSU failed
    "1.3.6.1.4.1.9.9.13.1.5.1.2.1": "PS1", "1.3.6.1.4.1.9.9.13.1.5.1.3.1": 3,
    # HOST-RESOURCES storage: flash 75% used, RAM ignored
    "1.3.6.1.2.1.25.2.3.1.2.1": "1.3.6.1.2.1.25.2.1.9", "1.3.6.1.2.1.25.2.3.1.3.1": "flash:", "1.3.6.1.2.1.25.2.3.1.4.1": 1024,
    "1.3.6.1.2.1.25.2.3.1.5.1": 1000, "1.3.6.1.2.1.25.2.3.1.6.1": 750,
    "1.3.6.1.2.1.25.2.3.1.2.2": "1.3.6.1.2.1.25.2.1.2", "1.3.6.1.2.1.25.2.3.1.5.2": 100, "1.3.6.1.2.1.25.2.3.1.6.2": 50,
    # LLDP: local port 1 (Gi1/0/1) sees core-rtr Gi0/0/1 at 10.0.0.1
    "1.0.8802.1.1.2.1.3.7.1.3.1": "Gi1/0/1", "1.0.8802.1.1.2.1.3.7.1.4.1": "GigabitEthernet1/0/1",
    "1.0.8802.1.1.2.1.4.1.1.5.0.1.1": "00:11:22:33:44:55", "1.0.8802.1.1.2.1.4.1.1.7.0.1.1": "Gi0/0/1",
    "1.0.8802.1.1.2.1.4.1.1.8.0.1.1": "GigabitEthernet0/0/1", "1.0.8802.1.1.2.1.4.1.1.9.0.1.1": "core-rtr.example.lan",
    "1.0.8802.1.1.2.1.4.1.1.10.0.1.1": "Cisco IOS XE Software\nVersion 17.9",
    "1.0.8802.1.1.2.1.4.2.1.3.0.1.1.1.4.10.0.0.1": 2,
    # CDP: the same router (skipped as a duplicate) and an IP phone on ifIndex 2
    "1.3.6.1.4.1.9.9.23.1.2.1.1.6.1.1": "core-rtr.example.lan", "1.3.6.1.4.1.9.9.23.1.2.1.1.7.1.1": "GigabitEthernet0/0/1",
    "1.3.6.1.4.1.9.9.23.1.2.1.1.4.2.1": "0a:00:00:63", "1.3.6.1.4.1.9.9.23.1.2.1.1.6.2.1": "SEP001122334455",
    "1.3.6.1.4.1.9.9.23.1.2.1.1.7.2.1": "Port 1", "1.3.6.1.4.1.9.9.23.1.2.1.1.8.2.1": "Cisco IP Phone 8845",
}
PORTS = [{"ifindex": 1, "name": "Gi1/0/1", "alias": ""}, {"ifindex": 2, "name": "Gi1/0/2", "alias": ""}]


def collect():
    result = {"system": {"sys_object_id": "1.3.6.1.4.1.9.1.2694"}, "ports": PORTS}
    asyncio.run(snmp_extra.collect_extra(FakeSnmp(TABLE), result))
    return result


def test_poller_collects_sensors_inventory_storage_and_neighbours():
    r = collect()
    inv = {e["name"]: e for e in r["inventory"]}
    assert inv["Switch 1"]["class"] == "chassis" and inv["Switch 1"]["serial"] == "FOC1234X0AB" and inv["Switch 1"]["sw"] == "17.9.4"
    assert "PSU A" in inv and "Inlet" not in inv and "GigabitEthernet1/0/1" not in inv
    sens = {x["key"]: x for x in r["sensors"]}
    assert sens["ent.3"]["value"] == 41.5 and sens["ent.3"]["kind"] == "temperature" and sens["ent.3"]["name"] == "Inlet"
    assert sens["ent.5"]["kind"] == "fan" and sens["ent.5"]["value"] == 4800
    assert "ent.6" not in sens
    assert sens["ciscopsu.1"]["status"] == "crit" and sens["ciscopsu.1"]["kind"] == "state"
    assert r["storage"] == [{"key": "hr.1", "name": "flash:", "kind": "flash", "size": 1024000, "used": 768000, "pct": 75.0}]
    lldp = [n for n in r["neighbors"] if n["protocol"] == "lldp"]
    cdp = [n for n in r["neighbors"] if n["protocol"] == "cdp"]
    assert lldp == [{"protocol": "lldp", "local_port": "GigabitEthernet1/0/1", "ifindex": 1, "remote_name": "core-rtr.example.lan",
                     "remote_port": "GigabitEthernet0/0/1", "remote_chassis": "00:11:22:33:44:55", "remote_ip": "10.0.0.1",
                     "remote_platform": "Cisco IOS XE Software"}]
    assert len(cdp) == 1 and cdp[0]["remote_name"] == "SEP001122334455" and cdp[0]["remote_ip"] == "10.0.0.99" and cdp[0]["ifindex"] == 2


def test_server_stores_sensors_neighbours_and_alerts(tmp_path):
    db = make_db(tmp_path)
    extra = collect()
    with db.session() as s:
        s.add(Device(id=30, hostname="core-rtr", ip="10.0.0.1", extra={}))
    for ts in (1000, 1300):
        item = snmp_item(ts, ts, ts)
        item.update(inventory=extra["inventory"], sensors=extra["sensors"], storage=extra["storage"], neighbors=extra["neighbors"])
        with db.session() as s:
            ingest_batch(s, 1, batch(item))
    with db.session() as s:
        dev = s.get(Device, 10)
        assert dev.serial == "FOC1234X0AB" and len(dev.inventory) == 2
        sensors = {x.key: x for x in s.scalars(select(Sensor).where(Sensor.device_id == 10))}
        assert sensors["ent.3"].value == 41.5 and sensors["hr.1"].kind == "storage" and sensors["hr.1"].value == 75.0
        assert s.scalar(select(SensorMetric.id).where(SensorMetric.sensor_id == sensors["ent.3"].id))
        nb = s.scalars(select(Neighbor).where(Neighbor.device_id == 10).order_by(Neighbor.protocol)).all()
        assert [(n.protocol, n.remote_device_id) for n in nb] == [("cdp", None), ("lldp", 30)]
        assert nb[1].port_id is not None
        alerts = {a.title for a in s.scalars(select(Alert).where(Alert.state == "open"))}
        assert "Sensor problem: sw1 PS1" in alerts
    # the PSU recovers and the temperature passes the 70 C threshold
    fixed = [dict(x, status="ok") if x["key"] == "ciscopsu.1" else (dict(x, value=75.0) if x["key"] == "ent.3" else x) for x in extra["sensors"]]
    for ts in (1600, 1900):
        item = snmp_item(ts, ts, ts)
        item.update(sensors=fixed, storage=extra["storage"], neighbors=[])
        with db.session() as s:
            ingest_batch(s, 1, batch(item))
    with db.session() as s:
        alerts = {a.title for a in s.scalars(select(Alert).where(Alert.state == "open"))}
        assert "Sensor problem: sw1 PS1" not in alerts and "Sensor problem: sw1 Inlet" in alerts
        assert s.scalar(select(Event.id).where(Event.message.like("PS1: ok (was crit)%")))
        assert s.scalars(select(Neighbor).where(Neighbor.device_id == 10)).all() == []


def test_pages_and_map(logged_in, app):
    from linkwatch.server.models import Port
    with app.state.lw.db.session() as s:
        a = Device(hostname="sw-a", ip="10.1.0.1", status="up", type="Switch", extra={}, inventory=[{"class": "chassis", "name": "Switch 1", "serial": "X1"}])
        b = Device(hostname="sw-b", ip="10.1.0.2", status="down", type="Switch", extra={})
        lone = Device(hostname="lonely", ip="10.1.0.3", status="up", extra={})
        s.add_all([a, b, lone])
        s.flush()
        p = Port(device_id=a.id, ifindex=1, name="Gi1/0/48", speed_mbps=10000, util_pct=91.0, in_bps=9.1e9, out_bps=1e9, admin="up", oper="up")
        s.add(p)
        s.flush()
        s.add(Neighbor(device_id=a.id, port_id=p.id, protocol="lldp", local_port="Gi1/0/48", remote_name="sw-b", remote_port="Te1/1/1", remote_device_id=b.id))
        s.add(Neighbor(device_id=b.id, protocol="lldp", local_port="Te1/1/1", remote_name="sw-a", remote_port="Gi1/0/48", remote_device_id=a.id))
        s.add(Neighbor(device_id=a.id, protocol="cdp", local_port="Gi1/0/2", remote_name="SEP0011", remote_platform="Cisco IP Phone"))
        s.add(Sensor(device_id=a.id, key="ent.1", kind="temperature", name="Inlet", unit="°C", value=38.0, status="ok"))
        s.add(Sensor(device_id=a.id, key="hr.1", kind="storage", name="flash:", unit="%", value=40.0, status="ok", extra={"size": 1e9, "used": 4e8}))
        s.add(Sensor(device_id=a.id, key="psu.1", kind="state", name="PSU A", value=1, status="ok"))
        s.flush()
        aid, bid, sid = a.id, b.id, s.scalar(select(Sensor.id).where(Sensor.key == "ent.1"))
    for tab in ("health", "inventory", "neighbours", "overview"):
        r = logged_in.get(f"/devices/{aid}?tab={tab}")
        assert r.status_code == 200, tab
    assert "Inlet" in logged_in.get(f"/devices/{aid}?tab=health").text
    inv = logged_in.get(f"/devices/{aid}?tab=inventory").text
    assert "Switch 1" in inv and "flash:" in inv
    nb = logged_in.get(f"/devices/{aid}?tab=neighbours").text
    assert "sw-b" in nb and "SEP0011" in nb and "not monitored" in nb
    for m in ("temperature", "storage", "state", "fan"):
        assert logged_in.get(f"/health?metric={m}").status_code == 200, m
    assert "Inlet" in logged_in.get("/health?metric=temperature").text
    assert logged_in.get(f"/ui/metrics/sensor/{sid}").json() == {"ts": [], "value": []}
    assert logged_in.get("/map").status_code == 200
    m = logged_in.get("/ui/map").json()
    assert {n["name"] for n in m["nodes"]} == {"sw-a", "sw-b"}
    assert len(m["links"]) == 1 and m["links"][0]["util"] == 91.0 and m["links"][0]["speed"] == 10000
    m = logged_in.get("/ui/map?external=1&all=1").json()
    assert {n["name"] for n in m["nodes"]} == {"sw-a", "sw-b", "lonely", "SEP0011"}
