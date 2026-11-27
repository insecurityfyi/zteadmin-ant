"""Messages exchanged between a poller and the server over the WebSocket.

Every message is a JSON object with a ``type``. The poller always opens the
connection (outbound HTTPS); the server only ever answers on that connection.

Server -> poller
    config        {"type": "config", "interval": 300, "devices": [...], "integrations": [...]}
                  Each SNMP device carries "oids": the custom OIDs in its scope,
                  [{"id": 3, "oid": "1.3.6...", "mode": "get"|"walk", "label_oid": null, "sys_object_id": "1.3.6.1.4.1.9"}].
                  The poller skips one whose sys_object_id prefix does not match the device's live sysObjectID.
    poll_now      {"type": "poll_now", "device_id": 12}
    ack           {"type": "ack", "batch_id": "..."}
    ping          {"type": "ping"}
    snmp_test     {"type": "snmp_test", "req": "...", "device_id": 12, "oid": "1.3.6...", "mode": "get"|"walk", "label_oid": null}
                  Read one OID now; answered with snmp_test_result.
    tunnel_open   {"type": "tunnel_open", "sid": "...", "host": "10.0.0.1", "port": 22}
                  The poller opens a second outbound WebSocket to /api/poller/ws/tunnel/<sid> (same Bearer key),
                  connects to host:port, sends {"ok": true} or {"ok": false, "error": "..."} as a text frame,
                  then relays raw TCP bytes as binary frames both ways until either side closes.

Poller -> server
    hello         {"type": "hello", "version": "0.1.0", "hostname": "...", "features": ["mtr", "ssh"]}
    results       {"type": "results", "batch_id": "...", "items": [DeviceResult | IntegrationResult]}
    pong          {"type": "pong"}
    snmp_test_result {"type": "snmp_test_result", "req": "...", "rows": [{"index": "", "value": 42, "label": null}], "error": null}

A ``DeviceResult`` (kind "device") carries one SNMP/ICMP poll of one device:

    {"kind": "device", "device_id": 12, "ts": 1732590000.0, "ok": true, "error": null,
     "poll_ms": 640,
     "system": {"sys_descr": "...", "sys_object_id": "...", "sys_name": "...",
                "sys_location": "...", "uptime_s": 1234},
     "cpu": 12.0, "mem": 55.0,
     "ping": {"rtt_ms": 1.2, "loss_pct": 0.0},
     "ports": [{"ifindex": 1, "name": "Gi1/0/1", "alias": "", "speed_mbps": 1000,
                "oper": "up", "admin": "up", "in_octets": 0, "out_octets": 0,
                "in_errors": 0, "out_errors": 0, "in_discards": 0, "out_discards": 0}],
     "system_stats": [SensorRow], "disk_io": [SensorRow],
     "custom": [{"id": 3, "index": "", "value": 42, "label": null}]}

A ``SensorRow`` is ``{"key", "kind", "name", "unit", "value"}``, or for a counter ``{..., "counter": true, "raw": 123,
"bits": 32|64, "scale": 1}``: the server turns two raw readings into a per-second rate.

An ``IntegrationResult`` (kind "integration") carries one API collection run:

    {"kind": "integration", "integration_id": 3, "ts": ..., "ok": true, "error": null,
     "records": [Record, ...]}

A ``Record`` is the normalized shape every integration returns (see
``linkwatch.integrations.base.Record``).
"""

PROTOCOL_VERSION = 1
