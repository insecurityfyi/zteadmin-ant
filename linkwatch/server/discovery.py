"""Discovery on the server side: starting scans, saved/scheduled scans, credential order and adding found devices."""
from __future__ import annotations

import json
import logging
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..common.discovery import expand_targets, guess_type
from .db import get_setting, set_setting
from .ingest import site_by_name
from .models import Device, DiscoveryJob, DiscoveryRule, SnmpProfile, utcnow

log = logging.getLogger("linkwatch.discovery")
DEVICE_TYPES = ["Switch", "Router", "Firewall", "Wireless", "Server", "Hypervisor", "Storage", "Power", "Printer", "Camera", "Network", "Other"]
SCHEDULES = {0: "Only when run by hand", 6: "Every 6 hours", 24: "Daily", 168: "Weekly"}
AUTO_ADD = {"off": "Don't add; I'll review the results", "snmp": "Add new devices that answer SNMP", "all": "Add everything new that answers"}


def ordered_profiles(s: Session) -> list[SnmpProfile]:
    """SNMP credential sets in the order discovery should try them (Discovery settings), then by name."""
    try:
        order = [int(x) for x in json.loads(get_setting(s, "snmp_order", "[]") or "[]")]
    except (ValueError, TypeError):
        order = []
    rank = {pid: i for i, pid in enumerate(order)}
    return sorted(s.scalars(select(SnmpProfile)).all(), key=lambda p: (rank.get(p.id, 10_000), p.name.lower()))


def move_profile(s: Session, pid: int, direction: str) -> None:
    ids = [p.id for p in ordered_profiles(s)]
    if pid not in ids:
        return
    i = ids.index(pid)
    j = i - 1 if direction == "up" else i + 1
    if 0 <= j < len(ids):
        ids[i], ids[j] = ids[j], ids[i]
    set_setting(s, "snmp_order", json.dumps(ids))


def in_order(s: Session, profile_ids: list[int]) -> list[SnmpProfile]:
    wanted = set(profile_ids)
    return [p for p in ordered_profiles(s) if p.id in wanted]


def start_job(state, s: Session, poller_id: int, targets: str, profiles: list[SnmpProfile], rule_id: int | None = None) -> DiscoveryJob:
    """Create the job and send it to the poller. If the poller is offline the job is marked failed."""
    hosts = expand_targets(targets)
    job = DiscoveryJob(poller_id=poller_id, targets=targets[:5000], profile_ids=[p.id for p in profiles],
                       total=len(hosts), results=[], rule_id=rule_id)
    s.add(job)
    s.flush()
    msg = {"type": "discover", "job_id": job.id, "targets": targets,
           "profiles": [{"id": p.id, "creds": state.vault.open(p.config_enc)} for p in profiles]}
    if not state.hub.send_soon(poller_id, msg):
        job.status, job.error, job.finished_at = "failed", "The poller is not connected.", utcnow()
    return job


def add_from_job(s: Session, job: DiscoveryJob, ips: set[str] | None = None, site_name: str | None = None,
                 types: dict[str, str] | None = None, only_snmp: bool = False) -> int:
    """Create devices for found hosts that aren't monitored yet. ips=None means every result."""
    existing = set(s.scalars(select(Device.ip).where(Device.ip.is_not(None))))
    site = site_by_name(s, site_name)
    valid_profiles = set(s.scalars(select(SnmpProfile.id)))
    added = 0
    for r in job.results or []:
        ip = r.get("ip")
        if not ip or ip in existing or (ips is not None and ip not in ips):
            continue
        prof = r.get("profile_id") if r.get("profile_id") in valid_profiles else None
        if only_snmp and not prof:
            continue
        kind = (types or {}).get(ip) or guess_type(r.get("sys_descr"), r.get("sys_object_id"))
        s.add(Device(hostname=(r.get("sys_name") or ip)[:255], ip=ip, type=kind if kind in DEVICE_TYPES else "Network",
                     site_id=site.id if site else None, poller_id=job.poller_id, snmp_profile_id=prof, ping=True,
                     source="snmp" if prof else "ping", sys_descr=r.get("sys_descr"), extra={}))
        existing.add(ip)
        added += 1
    return added


def auto_add(s: Session, job: DiscoveryJob) -> int:
    """Called when a scan from a saved rule finishes."""
    rule = s.get(DiscoveryRule, job.rule_id) if job.rule_id else None
    if rule is None or rule.auto_add not in ("snmp", "all"):
        return 0
    n = add_from_job(s, job, None, rule.site_name, None, only_snmp=rule.auto_add == "snmp")
    job.added = n
    if n:
        log.info("Discovery rule %s added %d devices", rule.name, n)
    return n


def due_rules(s: Session, connected: set[int]) -> list[DiscoveryRule]:
    now = utcnow()
    out = []
    for r in s.scalars(select(DiscoveryRule).where(DiscoveryRule.enabled.is_(True), DiscoveryRule.interval_hours > 0)):
        if r.poller_id not in connected:
            continue
        if r.last_run and now - r.last_run < timedelta(hours=r.interval_hours):
            continue
        busy = s.scalar(select(DiscoveryJob.id).where(DiscoveryJob.rule_id == r.id, DiscoveryJob.status.in_(("queued", "running")),
                                                      DiscoveryJob.created_at > now - timedelta(hours=2)))
        if not busy:
            out.append(r)
    return out


def run_rule(state, s: Session, rule: DiscoveryRule) -> DiscoveryJob:
    job = start_job(state, s, rule.poller_id, rule.targets, in_order(s, rule.profile_ids or []), rule_id=rule.id)
    rule.last_run = utcnow()
    return job
