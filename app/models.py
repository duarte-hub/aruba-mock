"""ORM models."""
from __future__ import annotations

import datetime as dt
import enum
from typing import Optional

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


class DeviceType(str, enum.Enum):
    AP = "ap"
    SWITCH = "switch"
    GATEWAY = "gateway"
    CONTROLLER = "controller"
    OTHER = "other"


class DeviceStatus(str, enum.Enum):
    UNKNOWN = "unknown"
    ONLINE = "online"
    OFFLINE = "offline"
    DEGRADED = "degraded"


class InsightSeverity(str, enum.Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False)
    ip_address: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    device_type: Mapped[DeviceType] = mapped_column(
        Enum(DeviceType, native_enum=False), default=DeviceType.OTHER
    )
    site: Mapped[str] = mapped_column(String(128), default="default")
    model: Mapped[Optional[str]] = mapped_column(String(128))
    serial: Mapped[Optional[str]] = mapped_column(String(128))
    firmware: Mapped[Optional[str]] = mapped_column(String(128))

    # SNMP
    snmp_version: Mapped[str] = mapped_column(String(8), default="2c")
    snmp_community: Mapped[Optional[str]] = mapped_column(String(128))
    snmp_user: Mapped[Optional[str]] = mapped_column(String(128))
    snmp_auth_protocol: Mapped[Optional[str]] = mapped_column(String(16))
    snmp_auth_password: Mapped[Optional[str]] = mapped_column(String(255))
    snmp_priv_protocol: Mapped[Optional[str]] = mapped_column(String(16))
    snmp_priv_password: Mapped[Optional[str]] = mapped_column(String(255))
    snmp_port: Mapped[int] = mapped_column(Integer, default=161)

    # SSH
    ssh_user: Mapped[Optional[str]] = mapped_column(String(128))
    ssh_password: Mapped[Optional[str]] = mapped_column(String(255))
    ssh_port: Mapped[int] = mapped_column(Integer, default=22)
    ssh_device_type: Mapped[str] = mapped_column(String(64), default="aruba_os")

    # State
    status: Mapped[DeviceStatus] = mapped_column(
        Enum(DeviceStatus, native_enum=False), default=DeviceStatus.UNKNOWN
    )
    last_seen: Mapped[Optional[dt.datetime]] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[Optional[str]] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)

    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )

    samples: Mapped[list["Sample"]] = relationship(
        back_populates="device", cascade="all, delete-orphan"
    )
    insights: Mapped[list["Insight"]] = relationship(
        back_populates="device", cascade="all, delete-orphan"
    )
    radios: Mapped[list["Radio"]] = relationship(
        back_populates="device", cascade="all, delete-orphan"
    )


class Sample(Base):
    """A single point-in-time poll result for a device."""

    __tablename__ = "samples"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), index=True
    )
    timestamp: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, index=True
    )
    reachable: Mapped[bool] = mapped_column(Boolean, default=False)
    sys_descr: Mapped[Optional[str]] = mapped_column(Text)
    sys_uptime_s: Mapped[Optional[int]] = mapped_column(Integer)
    cpu_pct: Mapped[Optional[float]] = mapped_column(Float)
    mem_used_pct: Mapped[Optional[float]] = mapped_column(Float)
    client_count: Mapped[Optional[int]] = mapped_column(Integer)
    raw: Mapped[dict] = mapped_column(JSON, default=dict)

    device: Mapped[Device] = relationship(back_populates="samples")


class Radio(Base):
    """A radio (AP) — typically two per AP: 2.4GHz and 5GHz."""

    __tablename__ = "radios"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), index=True
    )
    band: Mapped[str] = mapped_column(String(8))  # "2.4" or "5" or "6"
    channel: Mapped[Optional[int]] = mapped_column(Integer)
    channel_width_mhz: Mapped[Optional[int]] = mapped_column(Integer)
    tx_power_dbm: Mapped[Optional[float]] = mapped_column(Float)
    channel_utilization_pct: Mapped[Optional[float]] = mapped_column(Float)
    noise_floor_dbm: Mapped[Optional[float]] = mapped_column(Float)
    associated_clients: Mapped[Optional[int]] = mapped_column(Integer)
    last_updated: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )

    device: Mapped[Device] = relationship(back_populates="radios")


class Insight(Base):
    __tablename__ = "insights"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), index=True
    )
    severity: Mapped[InsightSeverity] = mapped_column(
        Enum(InsightSeverity, native_enum=False), default=InsightSeverity.INFO
    )
    code: Mapped[str] = mapped_column(String(64), index=True)
    title: Mapped[str] = mapped_column(String(255))
    detail: Mapped[Optional[str]] = mapped_column(Text)
    recommendation: Mapped[Optional[str]] = mapped_column(Text)
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, index=True
    )
    acknowledged: Mapped[bool] = mapped_column(Boolean, default=False)

    device: Mapped[Optional[Device]] = relationship(back_populates="insights")


class AirMatchRun(Base):
    """A persisted AirMatch (channel/power planning) run."""

    __tablename__ = "airmatch_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    started_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    band: Mapped[str] = mapped_column(String(8))
    summary: Mapped[Optional[str]] = mapped_column(Text)
    plan: Mapped[dict] = mapped_column(JSON, default=dict)
    applied: Mapped[bool] = mapped_column(Boolean, default=False)
