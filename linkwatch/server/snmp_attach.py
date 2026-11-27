"""Adding SNMP polling to devices that came from an API integration.

A device an integration created (source = the integration's kind) is only as good as that API: often no interface
counters, sensors or LLDP. Attaching SNMP credentials turns it into the same shape as an SNMP device that an
integration matched on its own: ``source`` becomes "snmp", the poller polls it, and the next syncs keep putting
the API's view under ``extra["api"]``. If an SNMP device for the same box already exists, the API device is folded
into that one instead, so there is never a duplicate.
"""
from __future__ import annotations

from typing import Any

from sqlalchemy import delete, select

from . import events
from .ingest import match_local_device, merge_into
from .models import Device, Sensor, SnmpProfile

SNMP_AUTH = ["SHA", "SHA224", "SHA256", "SHA384", "SHA512", "MD5"]
SNMP_PRIV = ["AES", "AES192", "AES256", "DES"]
# kept at the top level of ``extra`` after the move to extra["api"], because pages key off them
_KEEP_TOP = ("mac", "product")


def api_only(d: Device) -> bool:
    """Came from an integration and nothing polls it over SNMP or ping yet."""
    return d.integration_id is not None and d.source not in ("snmp", "ping")


def read_snmp_creds(form) -> tuple[dict[str, Any] | None, str | None]:
    """SNMP v2c / v3 credentials from a submitted form. Returns (config, None) or (None, what is wrong)."""
    version = form.get("version") or "2c"
    if version == "2c":
        cfg: dict[str, Any] = {"version": "2c", "community": form.get("community") or ""}
        if not cfg["community"]:
            return None, "Enter the community string."
    else:
        cfg = {"version": "3", "username": form.get("username") or "", "level": form.get("level") or "authPriv",
               "auth_protocol": form.get("auth_protocol") or "SHA", "auth_key": form.get("auth_key") or "",
               "priv_protocol": form.get("priv_protocol") or "AES", "priv_key": form.get("priv_key") or ""}
        if cfg["level"] not in ("noAuthNoPriv", "authNoPriv", "authPriv"):
            cfg["level"] = "authPriv"
        if not cfg["username"] or (cfg["level"] != "noAuthNoPriv" and len(cfg["auth_key"]) < 8) or \
                (cfg["level"] == "authPriv" and len(cfg["priv_key"]) < 8):
            return None, "SNMPv3 needs a username, and passphrases of at least 8 characters."
    port = str(form.get("port") or "").strip()
    if port:
        if not port.isdigit() or not 0 < int(port) < 65536:
            return None, "The SNMP port must be a number from 1 to 65535."
        cfg["port"] = int(port)
    return cfg, None


def twin_of(s, d: Device, ip: str | None = None) -> Device | None:
    """An SNMP or ping device already monitored that is the same box as API device ``d``.

    Same order as the automatic match on sync: serial, any of its addresses (including ``ip``, the address the
    person typed), MAC, then a name that matches exactly one device."""
    extra = d.extra or {}
    ips = [x for x in dict.fromkeys([ip, d.ip, *(extra.get("ips") or [])]) if x]
    rec = {"serial": d.serial, "ip": ips[0] if ips else None, "hostname": d.hostname,
           "extra": {"ips": ips[1:], "mac": extra.get("mac")}}
    return match_local_device(s, rec)


def ip_in_use(s, ip: str, not_id: int) -> Device | None:
    """A device other than ``not_id`` that a poller already polls at this address."""
    return s.scalar(select(Device).where(Device.ip == ip, Device.id != not_id, Device.source.in_(("snmp", "ping")))
                    .limit(1))


def _api_extra(d: Device) -> dict[str, Any]:
    old = dict(d.extra or {})
    api = {"integration": d.integration.name if d.integration else d.source, "detail": d.detail,
           "status": d.status, **{k: v for k, v in old.items() if k != "api"}}
    return {**{k: old[k] for k in _KEEP_TOP if k in old}, "api": api}


def attach(s, d: Device, *, poller_id: int, profile: SnmpProfile, ip: str, ping: bool, who: str) -> Device:
    """Start polling API device ``d`` over SNMP. It keeps its id, history and integration link."""
    d.extra = _api_extra(d)
    d.source = "snmp"
    d.ip = ip[:255]
    d.poller_id, d.snmp_profile_id, d.ping = poller_id, profile.id, ping
    d.fail_count = 0
    events.log(s, "config", f"SNMP polling added by {who} ({profile.name}); "
                            f"{d.extra['api']['integration']} data now shows alongside it", "info", d, username=who)
    return d


def merge_with(s, d: Device, twin: Device, who: str) -> Device:
    """Fold API device ``d`` into ``twin``, the SNMP device for the same box, keeping the API device's history."""
    integration_id, external_id, name = d.integration_id, d.external_id, d.hostname
    api = _api_extra(d)
    d.external_id = None          # free the (integration, external_id) pair before the twin takes it
    s.flush()
    twin.integration_id, twin.external_id = integration_id, external_id
    twin.extra = {**(twin.extra or {}), **{k: v for k, v in api.items() if k not in (twin.extra or {}) or k == "api"}}
    twin.serial = twin.serial or d.serial
    if d.platform and (not twin.platform or twin.platform == (twin.sys_descr or "").splitlines()[0][:255]):
        twin.platform = d.platform
    merge_into(s, d, twin)
    events.log(s, "config", f"Merged with {api['api']['integration']} device {name} by {who}; its API data now shows here",
               "info", twin, username=who)
    return twin


def detach(s, d: Device, who: str) -> Device:
    """Stop SNMP polling on a device an integration created, going back to API data only.

    Its SNMP interfaces and sensors are removed (the API may report its own); the next sync refreshes the rest."""
    api = dict((d.extra or {}).get("api") or {})
    for k in ("integration", "detail", "status"):
        api.pop(k, None)
    d.extra = api
    d.source = d.integration.kind if d.integration else d.source
    d.snmp_profile_id, d.ping, d.poller_id = None, False, None
    s.execute(delete(Sensor).where(Sensor.device_id == d.id))
    d.ports.clear()
    events.log(s, "config", f"SNMP polling removed by {who}; back to {d.integration.name if d.integration else 'API'} data only",
               "info", d, username=who)
    return d
