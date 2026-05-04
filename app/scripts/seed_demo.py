"""Seed a few example APs and radios for trying out AirMatch / Insights without
real hardware. Run once with:

    docker exec -it aruba-mock python -m app.scripts.seed_demo
"""
from __future__ import annotations

import datetime as dt

from app.db import session_scope
from app.models import Device, DeviceStatus, DeviceType, Radio


SAMPLE_APS = [
    # (name, ip, site, ch24, util24, ch5, util5)
    ("ap-lab-1",   "10.10.10.11", "lab",   1,  35,  36, 22),
    ("ap-lab-2",   "10.10.10.12", "lab",   1,  72,  40, 51),
    ("ap-lab-3",   "10.10.10.13", "lab",   6,  18, 149, 12),
    ("ap-lab-4",   "10.10.10.14", "lab",  11,  66,  44, 64),
    ("ap-lab-5",   "10.10.10.15", "lab",   1,  82,  36, 78),
    ("ap-house-1", "10.10.20.11", "house", 6,  20,  44, 14),
    ("ap-house-2", "10.10.20.12", "house",11,  31, 149, 25),
]


def main() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    with session_scope() as s:
        for name, ip, site, ch24, util24, ch5, util5 in SAMPLE_APS:
            existing = s.query(Device).filter(Device.ip_address == ip).first()
            if existing:
                device = existing
            else:
                device = Device(
                    name=name,
                    hostname=name,
                    ip_address=ip,
                    device_type=DeviceType.AP,
                    site=site,
                    snmp_version="2c",
                    snmp_community="public",
                    status=DeviceStatus.ONLINE,
                    last_seen=now,
                    enabled=True,
                )
                s.add(device)
                s.flush()

            # wipe & re-create radios
            for r in list(device.radios):
                s.delete(r)
            s.flush()

            s.add(Radio(
                device_id=device.id,
                band="2.4",
                channel=ch24,
                channel_width_mhz=20,
                tx_power_dbm=15.0,
                channel_utilization_pct=float(util24),
                noise_floor_dbm=-78.0,
                associated_clients=max(0, util24 // 5),
            ))
            s.add(Radio(
                device_id=device.id,
                band="5",
                channel=ch5,
                channel_width_mhz=40,
                tx_power_dbm=18.0,
                channel_utilization_pct=float(util5),
                noise_floor_dbm=-85.0,
                associated_clients=max(0, util5 // 4),
            ))
    print(f"seeded {len(SAMPLE_APS)} demo APs")


if __name__ == "__main__":
    main()
