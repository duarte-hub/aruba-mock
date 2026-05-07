"""ARM / AirMatch heuristic channel & power planner.

Real Aruba ARM/AirMatch uses neighbor reports + historical airtime to solve a
graph-coloring-ish optimization problem with DFS, regulatory, and EIRP
constraints. We mimic the *shape* of that here with a tractable heuristic:

  * Score each candidate channel per AP using:
      - current channel utilization (worse = higher cost)
      - co-channel & adjacent-channel neighbors (neighbor density)
      - noise floor on that channel (if known)
  * Iterate APs in descending "trouble" order (busiest first) and assign each
    its lowest-cost channel given assignments made so far.
  * Cap tx-power so neighbors don't exceed a target overlap (-65 dBm RX
    estimate via free-space rule of thumb).

The output is a *plan* — we never push it to devices automatically.
"""
from __future__ import annotations

import datetime as dt
import logging
import math
from dataclasses import dataclass
from typing import Iterable, Sequence

from sqlalchemy import select

from app.db import session_scope
from app.models import AirMatchRun, Device, DeviceType, Radio

log = logging.getLogger("aruba.airmatch")


# Channel sets per band (US/non-DFS-friendly defaults; keep editable in code)
CHANNELS_24 = [1, 6, 11]
CHANNELS_5 = [36, 40, 44, 48, 149, 153, 157, 161, 165]  # UNII-1 + UNII-3
CHANNELS_5_DFS = [52, 56, 60, 64, 100, 104, 108, 112, 116, 132, 136, 140]
CHANNELS_6 = [1, 5, 9, 13, 17, 21, 25, 29, 33, 37, 41, 45, 49, 53, 57, 61]


@dataclass
class RadioInput:
    radio_id: int
    device_id: int
    device_name: str
    band: str
    current_channel: int | None
    current_tx_power: float | None
    channel_utilization_pct: float | None
    noise_floor_dbm: float | None
    neighbors: list[int]  # device IDs heard


@dataclass
class RadioPlan:
    radio_id: int
    device_id: int
    device_name: str
    band: str
    old_channel: int | None
    new_channel: int
    old_tx_power: float | None
    new_tx_power: float
    rationale: str


def _candidate_channels(band: str, allow_dfs: bool) -> Sequence[int]:
    if band == "2.4":
        return CHANNELS_24
    if band == "5":
        return CHANNELS_5 + (CHANNELS_5_DFS if allow_dfs else [])
    if band == "6":
        return CHANNELS_6
    return []


def _is_adjacent(band: str, a: int, b: int) -> bool:
    """Adjacent or overlapping. On 2.4GHz, overlap rules are infamous."""
    if band == "2.4":
        # Channels 1/6/11 are non-overlapping; anything within 4 channels overlaps.
        return abs(a - b) <= 4 and a != b
    if band == "5":
        # 20MHz channels are 4 apart in the channel-number scheme; "adjacent" = same channel-pair
        return abs(a - b) <= 4 and a != b
    if band == "6":
        return abs(a - b) <= 4 and a != b
    return False


def _channel_cost(
    band: str,
    candidate: int,
    radio: RadioInput,
    assignments: dict[int, int],
    radios_by_id: dict[int, RadioInput],
) -> float:
    """Lower is better."""
    cost = 0.0

    # Self contribution: prefer staying on the current channel slightly if it's already low-util,
    # to minimize churn.
    if radio.current_channel == candidate and (radio.channel_utilization_pct or 0) < 40:
        cost -= 5.0

    # Channel utilization on this AP — proxy for "how bad is this channel right now".
    util = radio.channel_utilization_pct
    if util is not None and radio.current_channel == candidate:
        cost += util  # 0..100

    # Noise floor penalty (only if we have a per-channel reading; we treat per-radio noise as approx)
    if radio.noise_floor_dbm is not None and radio.current_channel == candidate:
        # noise above -75 dBm is bad: every dB above -90 adds cost
        cost += max(0.0, radio.noise_floor_dbm + 90)  # -90 -> 0, -75 -> 15

    # Neighbor cost: sum of overlaps with already-assigned neighbors
    for nb_id in radio.neighbors:
        nb = radios_by_id.get(nb_id)
        if nb is None or nb.band != band:
            continue
        nb_chan = assignments.get(nb_id, nb.current_channel)
        if nb_chan is None:
            continue
        if nb_chan == candidate:
            cost += 25.0  # co-channel
        elif _is_adjacent(band, nb_chan, candidate):
            cost += 10.0  # adjacent-channel interference

    return cost


def _trouble_score(r: RadioInput) -> float:
    """Higher = needs attention sooner."""
    util = r.channel_utilization_pct or 0
    neighbors = len(r.neighbors)
    return util + neighbors * 5


def _suggest_tx_power(r: RadioInput, neighbors_assigned: int) -> float:
    """Heuristic: aim for moderate cell size; back off when surrounded."""
    base = 15.0  # dBm (approx 32 mW)
    if neighbors_assigned >= 4:
        base -= 4
    elif neighbors_assigned >= 2:
        base -= 2
    if r.band == "2.4":
        base -= 2  # 2.4GHz tends to over-reach
    return max(6.0, min(base, 23.0))


def _gather_radios(session, band: str | None) -> list[RadioInput]:
    """Pull radios for APs.

    APs that have never been polled (no rows in the radios table) get
    synthetic RadioInput entries with null channel/power/util so AirMatch
    can still produce a plan for them.
    """
    # Fetch real radio records joined to AP devices
    q = (
        select(Radio, Device)
        .join(Device, Radio.device_id == Device.id)
        .where(Device.enabled.is_(True))
        .where(Device.device_type == DeviceType.AP)
    )
    rows = session.execute(q).all()

    by_site: dict[str, list[int]] = {}
    radios: list[RadioInput] = []
    devices_with_radio: set[int] = set()  # any band

    for radio, device in rows:
        devices_with_radio.add(device.id)
        if band and radio.band != band:
            continue
        radios.append(RadioInput(
            radio_id=radio.id,
            device_id=device.id,
            device_name=device.name,
            band=radio.band,
            current_channel=radio.channel,
            current_tx_power=radio.tx_power_dbm,
            channel_utilization_pct=radio.channel_utilization_pct,
            noise_floor_dbm=radio.noise_floor_dbm,
            neighbors=[],
        ))
        if device.id not in by_site.get(device.site, []):
            by_site.setdefault(device.site, []).append(device.id)

    # Add synthetic entries for APs that have no Radio rows at all
    all_aps = session.execute(
        select(Device)
        .where(Device.enabled.is_(True))
        .where(Device.device_type == DeviceType.AP)
    ).scalars().all()

    for device in all_aps:
        if device.id in devices_with_radio:
            continue
        for b in ([band] if band else ["2.4", "5"]):
            radios.append(RadioInput(
                radio_id=-(device.id * 10 + {"2.4": 1, "5": 2, "6": 3}.get(b, 0)),
                device_id=device.id,
                device_name=device.name,
                band=b,
                current_channel=None,
                current_tx_power=None,
                channel_utilization_pct=None,
                noise_floor_dbm=None,
                neighbors=[],
            ))
        if device.id not in by_site.get(device.site, []):
            by_site.setdefault(device.site, []).append(device.id)

    # Neighbor approximation: every AP at the same site, on the same band, hears every other AP
    by_id_band = {(r.device_id, r.band): r for r in radios}
    for r in radios:
        site_devs = next(
            (devs for devs in by_site.values() if r.device_id in devs), []
        )
        r.neighbors = [
            d for d in site_devs
            if d != r.device_id and (d, r.band) in by_id_band
        ]
    return radios


def plan_airmatch(band: str, allow_dfs: bool = False) -> dict:
    """Run a planning pass for a given band. Returns the plan as a dict."""
    candidates = _candidate_channels(band, allow_dfs=allow_dfs)
    if not candidates:
        return {"band": band, "error": f"unknown band {band}", "radios": []}

    with session_scope() as session:
        radios = _gather_radios(session, band=band)
        if not radios:
            return {"band": band, "radios": [], "summary": "No APs on this band."}

        radios.sort(key=_trouble_score, reverse=True)
        radios_by_id = {r.radio_id: r for r in radios}
        device_to_radio = {r.device_id: r for r in radios}
        # Map neighbors (device_id) → radio_id within same band for cost lookups
        for r in radios:
            r.neighbors = [
                device_to_radio[d].radio_id for d in r.neighbors if d in device_to_radio
            ]

        assignments: dict[int, int] = {}  # radio_id -> channel
        plans: list[RadioPlan] = []

        for r in radios:
            scored = [
                (c, _channel_cost(band, c, r, assignments, radios_by_id))
                for c in candidates
            ]
            scored.sort(key=lambda kv: kv[1])
            best_chan, best_cost = scored[0]
            neighbors_assigned = sum(1 for nb in r.neighbors if nb in assignments)
            tx = _suggest_tx_power(r, neighbors_assigned)

            rationale_parts = [f"cost={best_cost:.1f}"]
            if r.current_channel != best_chan:
                rationale_parts.append(f"move ch{r.current_channel}→ch{best_chan}")
            else:
                rationale_parts.append(f"stay on ch{best_chan}")
            if r.channel_utilization_pct is not None:
                rationale_parts.append(f"util={r.channel_utilization_pct:.0f}%")
            if r.neighbors:
                rationale_parts.append(f"{len(r.neighbors)} neighbors")

            assignments[r.radio_id] = best_chan
            plans.append(RadioPlan(
                radio_id=r.radio_id,
                device_id=r.device_id,
                device_name=r.device_name,
                band=r.band,
                old_channel=r.current_channel,
                new_channel=best_chan,
                old_tx_power=r.current_tx_power,
                new_tx_power=tx,
                rationale=", ".join(rationale_parts),
            ))

        moved = sum(1 for p in plans if p.old_channel != p.new_channel)
        summary = f"Planned {len(plans)} radios on {band}GHz; {moved} channel changes."

        run = AirMatchRun(
            band=band,
            summary=summary,
            plan={
                "band": band,
                "allow_dfs": allow_dfs,
                "radios": [p.__dict__ for p in plans],
            },
        )
        session.add(run)
        session.flush()
        return {
            "id": run.id,
            "band": band,
            "summary": summary,
            "radios": [p.__dict__ for p in plans],
            "started_at": run.started_at.isoformat(),
        }
