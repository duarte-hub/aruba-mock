"""Rule-based AI Insights engine.

The "AI" framing is in keeping with how Aruba Central markets it; under the
hood real ARM/AirMatch is heuristic-with-ML-tuned-thresholds. Here we run a
pure heuristic rule set over the most recent samples + radio observations.

Rules emit Insight rows. We replace the active set on every recompute.
"""
from __future__ import annotations

import datetime as dt
import logging
from collections import defaultdict
from dataclasses import dataclass
from typing import Iterable

from sqlalchemy import select

from app.db import session_scope
from app.models import Device, DeviceStatus, DeviceType, Insight, InsightSeverity, Radio, Sample

log = logging.getLogger("aruba.insights")


@dataclass
class Finding:
    code: str
    severity: InsightSeverity
    title: str
    detail: str
    recommendation: str
    device_id: int | None = None


# Thresholds (intentionally conservative — homelab devices are noisy)
CPU_WARN = 70.0
CPU_CRIT = 90.0
MEM_WARN = 75.0
MEM_CRIT = 92.0
CHAN_UTIL_WARN = 60.0
CHAN_UTIL_CRIT = 80.0
NOISE_WARN_DBM = -75.0  # higher (less negative) is worse


def _latest_sample(session, device_id: int) -> Sample | None:
    return session.execute(
        select(Sample)
        .where(Sample.device_id == device_id)
        .order_by(Sample.timestamp.desc())
        .limit(1)
    ).scalar_one_or_none()


def _evaluate_device(session, device: Device) -> list[Finding]:
    findings: list[Finding] = []

    if device.status == DeviceStatus.OFFLINE:
        findings.append(Finding(
            code="device.offline",
            severity=InsightSeverity.CRITICAL,
            title=f"{device.name} is offline",
            detail=device.last_error or "Device did not respond to SNMP poll.",
            recommendation="Verify reachability, SNMP credentials, and that the device is powered on.",
            device_id=device.id,
        ))
        return findings

    if device.status != DeviceStatus.ONLINE:
        return findings

    sample = _latest_sample(session, device.id)
    if sample is None:
        return findings

    # CPU
    if sample.cpu_pct is not None:
        if sample.cpu_pct >= CPU_CRIT:
            findings.append(Finding(
                code="cpu.critical",
                severity=InsightSeverity.CRITICAL,
                title=f"{device.name} CPU at {sample.cpu_pct:.0f}%",
                detail=f"Sustained CPU above {CPU_CRIT}% can cause control-plane delays.",
                recommendation="Investigate top processes via SSH (`show process cpu` / `show tech-support`).",
                device_id=device.id,
            ))
        elif sample.cpu_pct >= CPU_WARN:
            findings.append(Finding(
                code="cpu.high",
                severity=InsightSeverity.WARNING,
                title=f"{device.name} CPU elevated ({sample.cpu_pct:.0f}%)",
                detail=f"CPU exceeded the warning threshold of {CPU_WARN}%.",
                recommendation="Watch the trend; correlate with client count and traffic.",
                device_id=device.id,
            ))

    # Memory
    if sample.mem_used_pct is not None:
        if sample.mem_used_pct >= MEM_CRIT:
            findings.append(Finding(
                code="mem.critical",
                severity=InsightSeverity.CRITICAL,
                title=f"{device.name} memory at {sample.mem_used_pct:.0f}%",
                detail="Memory pressure can lead to dropped packets or daemon restarts.",
                recommendation="Identify memory-hungry processes; consider firmware upgrade.",
                device_id=device.id,
            ))
        elif sample.mem_used_pct >= MEM_WARN:
            findings.append(Finding(
                code="mem.high",
                severity=InsightSeverity.WARNING,
                title=f"{device.name} memory elevated ({sample.mem_used_pct:.0f}%)",
                detail=f"Memory exceeded {MEM_WARN}%.",
                recommendation="Track over time. If trending up, schedule a planned reboot window.",
                device_id=device.id,
            ))

    # Radios — RF saturation
    for radio in device.radios:
        if radio.channel_utilization_pct is not None:
            if radio.channel_utilization_pct >= CHAN_UTIL_CRIT:
                findings.append(Finding(
                    code="rf.saturation",
                    severity=InsightSeverity.CRITICAL,
                    title=f"{device.name} {radio.band}GHz ch{radio.channel} saturated ({radio.channel_utilization_pct:.0f}%)",
                    detail="Channel utilization above 80% causes high airtime contention and retries.",
                    recommendation="Run AirMatch to reassign channel. Consider lowering legacy data rates.",
                    device_id=device.id,
                ))
            elif radio.channel_utilization_pct >= CHAN_UTIL_WARN:
                findings.append(Finding(
                    code="rf.busy",
                    severity=InsightSeverity.WARNING,
                    title=f"{device.name} {radio.band}GHz ch{radio.channel} busy ({radio.channel_utilization_pct:.0f}%)",
                    detail="Sustained busy channel affects throughput.",
                    recommendation="Check neighboring APs; AirMatch may suggest a quieter channel.",
                    device_id=device.id,
                ))
        if radio.noise_floor_dbm is not None and radio.noise_floor_dbm > NOISE_WARN_DBM:
            findings.append(Finding(
                code="rf.noise",
                severity=InsightSeverity.WARNING,
                title=f"{device.name} {radio.band}GHz elevated noise ({radio.noise_floor_dbm:.0f} dBm)",
                detail="Noise floor higher than -75 dBm degrades effective SNR.",
                recommendation="Investigate non-WiFi interferers (microwaves, BT, video bridges).",
                device_id=device.id,
            ))

    return findings


def _evaluate_global(session) -> list[Finding]:
    """Cross-device findings: e.g. co-channel contention on 2.4GHz."""
    findings: list[Finding] = []

    # 2.4GHz APs only — co-channel matters most there
    radios = session.execute(
        select(Radio).join(Device).where(Device.device_type == DeviceType.AP)
    ).scalars().all()
    by_band_chan: dict[tuple[str, int], list[Radio]] = defaultdict(list)
    for r in radios:
        if r.channel is None or r.band not in ("2.4", "5", "6"):
            continue
        by_band_chan[(r.band, r.channel)].append(r)

    for (band, chan), group in by_band_chan.items():
        if len(group) >= 3:
            findings.append(Finding(
                code="rf.cochannel",
                severity=InsightSeverity.WARNING,
                title=f"{len(group)} APs share {band}GHz channel {chan}",
                detail="Co-channel contention reduces effective capacity for all APs on the channel.",
                recommendation="Run AirMatch to spread APs across non-overlapping channels (1/6/11 on 2.4GHz).",
            ))
    return findings


def recompute_insights() -> int:
    """Replace the live insight set. Returns the number of insights written."""
    now = dt.datetime.now(dt.timezone.utc)
    written = 0
    with session_scope() as s:
        # Clear current findings (preserve acknowledged ones >24h old? keep simple: clear all)
        s.query(Insight).delete()
        s.flush()

        all_findings: list[Finding] = []
        for device in s.query(Device).all():
            all_findings.extend(_evaluate_device(s, device))
        all_findings.extend(_evaluate_global(s))

        for f in all_findings:
            s.add(Insight(
                device_id=f.device_id,
                severity=f.severity,
                code=f.code,
                title=f.title,
                detail=f.detail,
                recommendation=f.recommendation,
                created_at=now,
            ))
            written += 1
    log.info("insights recomputed: %d", written)
    return written
