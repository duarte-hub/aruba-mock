"""Background SNMP poller. Runs in-process via APScheduler."""
from __future__ import annotations

import asyncio
import datetime as dt
import logging

from apscheduler.schedulers.asyncio import AsyncIOScheduler

from app.config import get_settings
from app.db import session_scope
from app.models import Device, DeviceStatus, DeviceType, Sample
from app.services.snmp import poll_device
from app.services.insights import recompute_insights

log = logging.getLogger("aruba.poller")


def _classify_device_type(sys_descr: str | None, sys_object_id: str | None) -> DeviceType | None:
    if not sys_descr and not sys_object_id:
        return None
    blob = " ".join(filter(None, [sys_descr or "", sys_object_id or ""])).lower()
    if any(t in blob for t in ("controller", "wlsx", "mobility")):
        return DeviceType.CONTROLLER
    if any(t in blob for t in ("ap-", "aruba ap", "instant", "iap")):
        return DeviceType.AP
    if any(t in blob for t in ("switch", "procurve", "aruba os-cx", "comware")):
        return DeviceType.SWITCH
    if any(t in blob for t in ("gateway", "branch")):
        return DeviceType.GATEWAY
    return None


async def _poll_one(device_id: int, timeout: int) -> None:
    # Re-read the device inside its own session to avoid sharing across tasks
    with session_scope() as s:
        device = s.get(Device, device_id)
        if device is None or not device.enabled:
            return
        # detached snapshot (won't be modified) — capture creds we need
        snapshot = device

    result = await poll_device(snapshot, timeout=timeout)

    with session_scope() as s:
        device = s.get(Device, device_id)
        if device is None:
            return

        sample = Sample(
            device_id=device.id,
            timestamp=dt.datetime.now(dt.timezone.utc),
            reachable=result.reachable,
            sys_descr=result.sys_descr,
            sys_uptime_s=result.sys_uptime_s,
            cpu_pct=result.cpu_pct,
            mem_used_pct=result.mem_used_pct,
            client_count=result.client_count,
            raw=result.raw or {},
        )
        s.add(sample)

        if result.reachable:
            device.status = DeviceStatus.ONLINE
            device.last_seen = sample.timestamp
            device.last_error = None
            if result.sys_descr and not device.firmware:
                device.firmware = result.sys_descr[:128]
            inferred = _classify_device_type(result.sys_descr, result.sys_object_id)
            if inferred and device.device_type == DeviceType.OTHER:
                device.device_type = inferred
        else:
            device.status = DeviceStatus.OFFLINE
            device.last_error = result.error or "unreachable"


async def poll_all_once() -> None:
    settings = get_settings()
    with session_scope() as s:
        device_ids = [d.id for d in s.query(Device).filter(Device.enabled.is_(True)).all()]

    log.info("poll cycle: %d devices", len(device_ids))
    if not device_ids:
        return

    sem = asyncio.Semaphore(8)

    async def _bounded(did: int) -> None:
        async with sem:
            try:
                await _poll_one(did, settings.poll_timeout)
            except Exception:  # noqa: BLE001
                log.exception("poll failed for device %d", did)

    await asyncio.gather(*(_bounded(d) for d in device_ids))

    # After polling, regenerate insights based on latest state.
    try:
        recompute_insights()
    except Exception:  # noqa: BLE001
        log.exception("insight recompute failed")


_scheduler: AsyncIOScheduler | None = None


def start_scheduler() -> None:
    global _scheduler
    settings = get_settings()
    if not settings.enable_poller:
        log.info("poller disabled by config")
        return
    if _scheduler and _scheduler.running:
        return
    _scheduler = AsyncIOScheduler(timezone="UTC")
    _scheduler.add_job(
        poll_all_once,
        "interval",
        seconds=settings.poll_interval,
        next_run_time=dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=5),
        max_instances=1,
        coalesce=True,
    )
    _scheduler.start()
    log.info("poller started, interval=%ss", settings.poll_interval)


def stop_scheduler() -> None:
    global _scheduler
    if _scheduler and _scheduler.running:
        _scheduler.shutdown(wait=False)
        _scheduler = None
