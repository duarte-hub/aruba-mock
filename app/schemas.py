"""Pydantic schemas for API request/response."""
from __future__ import annotations

import datetime as dt
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field

from app.models import DeviceStatus, DeviceType, InsightSeverity


class DeviceCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    hostname: str
    ip_address: str
    device_type: DeviceType = DeviceType.OTHER
    site: str = "default"

    snmp_version: str = "2c"
    snmp_community: Optional[str] = "public"
    snmp_user: Optional[str] = None
    snmp_auth_protocol: Optional[str] = None
    snmp_auth_password: Optional[str] = None
    snmp_priv_protocol: Optional[str] = None
    snmp_priv_password: Optional[str] = None
    snmp_port: int = 161

    ssh_user: Optional[str] = None
    ssh_password: Optional[str] = None
    ssh_port: int = 22
    ssh_device_type: str = "aruba_os"

    enabled: bool = True


class DeviceUpdate(DeviceCreate):
    """Same fields as create — used for full update."""


class DeviceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    hostname: str
    ip_address: str
    device_type: DeviceType
    site: str
    model: Optional[str]
    serial: Optional[str]
    firmware: Optional[str]
    status: DeviceStatus
    last_seen: Optional[dt.datetime]
    last_error: Optional[str]
    enabled: bool


class InsightOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    device_id: Optional[int]
    severity: InsightSeverity
    code: str
    title: str
    detail: Optional[str]
    recommendation: Optional[str]
    created_at: dt.datetime
    acknowledged: bool


class RadioOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    device_id: int
    band: str
    channel: Optional[int]
    channel_width_mhz: Optional[int]
    tx_power_dbm: Optional[float]
    channel_utilization_pct: Optional[float]
    noise_floor_dbm: Optional[float]
    associated_clients: Optional[int]
    last_updated: dt.datetime
