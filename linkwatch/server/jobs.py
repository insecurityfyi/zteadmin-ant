"""Background loops on the server: cloud integrations, poller health, rollups and retention."""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta

from sqlalchemy import delete, func, select

from ..integrations import REGISTRY, IntegrationError, build
from .alerts import Alerter
from .db import get_setting, set_setting
from .ingest import ingest_integration
from .models import DeviceMetric, Integration, IntegrationMetric, Poller, PortMetric, utcnow

log = logging.getLogger("linkwatch.jobs")


def run_server_integration(app_state, integration_id: int) -> None:
    """Collect one cloud integration (Zscaler, Meraki) and ingest it."""
    db, vault = app_state.db, app_state.vault
    with db.session() as s:
        integ = s.get(Integration, integration_id)
        if integ is None:
            return
        kind, cfg = integ.kind, vault.open(integ.config_enc)
    item = {"ok": False, "error": None, "records": [], "warnings": []}
    try:
        client = build(kind, cfg)
        try:
            item["records"] = client.collect()
            item["warnings"] = list(getattr(client, "errors", []) or [])
            item["data"] = getattr(client, "data", None)
            item["ok"] = True
        finally:
            client.close()
    except IntegrationError as exc:
        item["error"] = str(exc)
    except Exception as exc:
        log.exception("Integration %s crashed", integration_id)
        item["error"] = f"{exc.__class__.__name__}: {exc}"
    with db.session() as s:
        integ = s.get(Integration, integration_id)
        if integ is None:
            return
        alerter = Alerter(s)
        ingest_integration(s, alerter, integ, item)
    app_state.notifier.dispatch(alerter.events)


def check_pollers(app_state) -> None:
    with app_state.db.session() as s:
        interval = app_state.hub.interval(s)
        alerter = Alerter(s)
        cutoff = utcnow() - timedelta(seconds=interval * 3)
        for p in s.scalars(select(Poller).where(Poller.revoked.is_(False))):
            offline = p.id not in app_state.hub.conns and (p.last_seen is None or p.last_seen < cutoff)
            # a poller that never connected is "waiting for install", not an outage
            alerter.set("poller_offline", f"poller:{p.id}", offline and p.last_seen is not None,
                        f"Poller offline: {p.name}", f"Last heard from {p.last_seen:%Y-%m-%d %H:%M} UTC" if p.last_seen else None)
    app_state.notifier.dispatch(alerter.events)


def rollup_and_prune(app_state) -> None:
    """Average raw 5-minute samples into hourly rows, then delete what is past retention."""
    cfg = app_state.config
    now = utcnow()
    hour_end = now.replace(minute=0, second=0, microsecond=0)
    with app_state.db.session() as s:
        last = get_setting(s, "rollup_until")
        start = datetime.fromisoformat(last) if last else hour_end - timedelta(days=cfg.raw_days)
        if start >= hour_end:
            return
        if s.bind.dialect.name == "postgresql":
            bucket_d = func.date_trunc("hour", DeviceMetric.ts)
            bucket_p = func.date_trunc("hour", PortMetric.ts)
        else:
            bucket_d = func.strftime("%Y-%m-%d %H:00:00", DeviceMetric.ts)
            bucket_p = func.strftime("%Y-%m-%d %H:00:00", PortMetric.ts)
        rows = s.execute(select(DeviceMetric.device_id, bucket_d, func.avg(DeviceMetric.cpu), func.avg(DeviceMetric.mem),
                                func.avg(DeviceMetric.ping_ms), func.avg(DeviceMetric.loss_pct))
                         .where(DeviceMetric.hourly.is_(False), DeviceMetric.ts >= start, DeviceMetric.ts < hour_end)
                         .group_by(DeviceMetric.device_id, bucket_d)).all()
        for dev_id, b, cpu, mem, png, loss in rows:
            s.add(DeviceMetric(device_id=dev_id, ts=_as_dt(b), hourly=True, cpu=cpu, mem=mem, ping_ms=png, loss_pct=loss))
        rows = s.execute(select(PortMetric.port_id, bucket_p, func.avg(PortMetric.in_bps), func.avg(PortMetric.out_bps),
                                func.sum(PortMetric.in_err), func.sum(PortMetric.out_err),
                                func.sum(PortMetric.in_disc), func.sum(PortMetric.out_disc))
                         .where(PortMetric.hourly.is_(False), PortMetric.ts >= start, PortMetric.ts < hour_end)
                         .group_by(PortMetric.port_id, bucket_p)).all()
        for port_id, b, i, o, ei, eo, di, do in rows:
            s.add(PortMetric(port_id=port_id, ts=_as_dt(b), hourly=True, in_bps=i, out_bps=o, in_err=ei, out_err=eo,
                             in_disc=di, out_disc=do))
        bucket_i = func.date_trunc("hour", IntegrationMetric.ts) if s.bind.dialect.name == "postgresql" \
            else func.strftime("%Y-%m-%d %H:00:00", IntegrationMetric.ts)
        rows = s.execute(select(IntegrationMetric.integration_id, IntegrationMetric.key, bucket_i, func.avg(IntegrationMetric.a),
                                func.avg(IntegrationMetric.b), func.avg(IntegrationMetric.c))
                         .where(IntegrationMetric.hourly.is_(False), IntegrationMetric.ts >= start, IntegrationMetric.ts < hour_end)
                         .group_by(IntegrationMetric.integration_id, IntegrationMetric.key, bucket_i)).all()
        for iid, key, b, va, vb, vc in rows:
            s.add(IntegrationMetric(integration_id=iid, key=key, ts=_as_dt(b), hourly=True, a=va, b=vb, c=vc))
        from .models import SensorMetric
        bucket_s = func.date_trunc("hour", SensorMetric.ts) if s.bind.dialect.name == "postgresql" \
            else func.strftime("%Y-%m-%d %H:00:00", SensorMetric.ts)
        rows = s.execute(select(SensorMetric.sensor_id, bucket_s, func.avg(SensorMetric.value))
                         .where(SensorMetric.hourly.is_(False), SensorMetric.ts >= start, SensorMetric.ts < hour_end)
                         .group_by(SensorMetric.sensor_id, bucket_s)).all()
        for sid, b, v in rows:
            s.add(SensorMetric(sensor_id=sid, ts=_as_dt(b), hourly=True, value=v))
        set_setting(s, "rollup_until", hour_end.isoformat())
        raw_cut, hourly_cut = now - timedelta(days=cfg.raw_days), now - timedelta(days=cfg.hourly_days)
        from .models import SensorMetric
        for model in (DeviceMetric, PortMetric, IntegrationMetric, SensorMetric):
            s.execute(delete(model).where(model.hourly.is_(False), model.ts < raw_cut))
            s.execute(delete(model).where(model.hourly.is_(True), model.ts < hourly_cut))
        from .paths import prune
        prune(s)
        from .speedtest import prune as prune_speedtests
        prune_speedtests(s)
    log.info("Rollup done up to %s", hour_end)


def _as_dt(bucket):
    return bucket if isinstance(bucket, datetime) else datetime.fromisoformat(str(bucket))


def run_scheduled_discovery(app_state) -> None:
    from .discovery import due_rules, run_rule
    with app_state.db.session() as s:
        for rule in due_rules(s, set(app_state.hub.conns)):
            job = run_rule(app_state, s, rule)
            log.info("Scheduled discovery '%s' started as job %s", rule.name, job.id)


def prune_audit(app_state) -> None:
    from .models import AuditEvent, Event
    with app_state.db.session() as s:
        s.execute(delete(AuditEvent).where(AuditEvent.at < utcnow() - timedelta(days=365)))
        s.execute(delete(Event).where(Event.at < utcnow() - timedelta(days=180)))


async def background(app_state) -> None:
    """Runs for the life of the web process."""
    last_sync: dict[int, float] = {}
    last_rollup = 0.0
    last_isp = -1e9
    loop = asyncio.get_running_loop()
    while True:
        try:
            now = loop.time()
            with app_state.db.session() as s:
                interval = app_state.hub.interval(s)
                due = [i.id for i in s.scalars(select(Integration).where(Integration.enabled.is_(True)))
                       if REGISTRY.get(i.kind) and REGISTRY[i.kind].runs_on == "server"
                       and now - last_sync.get(i.id, -1e9) >= interval]
            for iid in due:
                last_sync[iid] = now
                await asyncio.to_thread(run_server_integration, app_state, iid)
            await asyncio.to_thread(check_pollers, app_state)
            await asyncio.to_thread(run_scheduled_discovery, app_state)
            if now - last_isp >= 600:       # WAN public addresses -> ISP names, cached (see isp.py)
                last_isp = now
                from .isp import refresh_job
                await asyncio.to_thread(refresh_job, app_state)
            if now - last_rollup >= 3600:
                last_rollup = now
                await asyncio.to_thread(rollup_and_prune, app_state)
                await asyncio.to_thread(prune_audit, app_state)
                from .sso import refresh_metadata_job
                await asyncio.to_thread(refresh_metadata_job, app_state)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("Background job failed")
        await asyncio.sleep(30)
