"""Messages exchanged between a poller and the server over the WebSocket.

Every message is a JSON object with a ``type``. The poller always opens the
connection (outbound HTTPS); the server only ever answers on that connection.

Server -> poller
    config        {"type": "config", "interval": 300, "devices": [...], "integrations": [...]}
    poll_now      {"type": "poll_now", "device_id": 12}
    ack           {"type": "ack", "batch_id": "..."}
    ping          {"type": "ping"}
    tunnel_open   {"type": "tunnel_open", "sid": "...", "host": "10.0.0.1", "port": 22}
                  The poller opens a second outbound WebSocket to /api/poller/ws/tunnel/<sid> (same Bearer key),
                  connects to host:port, sends {"ok": true} or {"ok": false, "error": "..."} as a text frame,
                  then relays raw TCP bytes as binary frames both ways until either side closes.
    pve_term_open {"type": "pve_term_open", "sid": "...", "integration_id": 3, "node": "pve-01",
                   "vmtype": "lxc" | "qemu" | null, "vmid": 105, "cols": 120, "rows": 40}
                  Like tunnel_open, but the poller opens a Proxmox text console itself (see poller/pveterm.py) and
                  relays terminal bytes; text frames on the tunnel carry {"type": "resize", ...}.
    rpc           {"type": "rpc", "id": "...", "op": "integration_action", "integration_id": 3,
                   "action": "shutdown", "params": {"node": "pve-01", "type": "qemu", "vmid": 101}, "refresh": true}
                  Runs Integration.action(action, params) for an integration assigned to this poller. With
                  "refresh" the poller collects that integration again a few seconds later.

Poller -> server
    hello         {"type": "hello", "version": "0.1.0", "hostname": "...", "features": ["mtr", "ssh", "pveterm", "rpc"]}
    results       {"type": "results", "batch_id": "...", "items": [DeviceResult | IntegrationResult]}
    pong          {"type": "pong"}
    rpc_result    {"type": "rpc_result", "id": "...", "ok": true, "result": {...}} or {"ok": false, "error": "..."}

A ``DeviceResult`` (kind "device") carries one SNMP/ICMP poll of one device:

    {"kind": "device", "device_id": 12, "ts": 1732590000.0, "ok": true, "error": null,
     "poll_ms": 640,
     "system": {"sys_descr": "...", "sys_object_id": "...", "sys_name": "...",
                "sys_location": "...", "uptime_s": 1234},
     "cpu": 12.0, "mem": 55.0,
     "ping": {"rtt_ms": 1.2, "loss_pct": 0.0},
     "ports": [{"ifindex": 1, "name": "Gi1/0/1", "alias": "", "speed_mbps": 1000,
                "oper": "up", "admin": "up", "in_octets": 0, "out_octets": 0,
                "in_errors": 0, "out_errors": 0}]}

An ``IntegrationResult`` (kind "integration") carries one API collection run:

    {"kind": "integration", "integration_id": 3, "ts": ..., "ok": true, "error": null,
     "records": [Record, ...]}

A ``Record`` is the normalized shape every integration returns (see
``linkwatch.integrations.base.Record``).
"""

PROTOCOL_VERSION = 1
