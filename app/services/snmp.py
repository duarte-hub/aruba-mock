"""SNMP polling service.

Uses pysnmp's high-level hlapi.v3arch.asyncio API. Supports SNMPv2c and SNMPv3.

We deliberately keep the OID list small and well-known. Aruba devices expose
detail through WLSX-WLAN-MIB / WLSX-IFEXT-MIB / WLSX-SYSEXT-MIB (controllers)
and AI-AP-MIB (APs). Many homelab devices won't have those — we degrade
gracefully and just report what we can.

Standard OIDs used:
  sysDescr.0      1.3.6.1.2.1.1.1.0
  sysObjectID.0   1.3.6.1.2.1.1.2.0
  sysUpTime.0     1.3.6.1.2.1.1.3.0
  sysName.0       1.3.6.1.2.1.1.5.0
  ifNumber.0      1.3.6.1.2.1.2.1.0

Aruba-specific (controllers / APs) — these are best-effort:
  wlsxSysExtMemoryUsedPercent  1.3.6.1.4.1.14823.2.2.1.2.1.30.0
  wlsxSysExtCpuUsedPercent     1.3.6.1.4.1.14823.2.2.1.2.1.29.0
  wlsxTotalNumOfUsers          1.3.6.1.4.1.14823.2.2.1.4.1.1.0
  apChannelNoise               1.3.6.1.4.1.14823.2.3.3.1.2.1.1.7
  apChannelBusy                1.3.6.1.4.1.14823.2.3.3.1.2.1.1.6
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any, Optional

from pysnmp.hlapi.v3arch.asyncio import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    UsmUserData,
    get_cmd,
    bulk_walk_cmd,
    usmHMACMD5AuthProtocol,
    usmHMACSHAAuthProtocol,
    usmDESPrivProtocol,
    usmAesCfb128Protocol,
)

log = logging.getLogger("aruba.snmp")


# ----- OIDs ---------------------------------------------------------------

SYS_DESCR = "1.3.6.1.2.1.1.1.0"
SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"
SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
SYS_NAME = "1.3.6.1.2.1.1.5.0"
IF_NUMBER = "1.3.6.1.2.1.2.1.0"

# Aruba enterprise (vendor 14823)
WLSX_CPU_PCT = "1.3.6.1.4.1.14823.2.2.1.2.1.29.0"
WLSX_MEM_PCT = "1.3.6.1.4.1.14823.2.2.1.2.1.30.0"
WLSX_TOTAL_USERS = "1.3.6.1.4.1.14823.2.2.1.4.1.1.0"

# AP radio table prefixes (walked, not got)
WLSX_AP_RADIO_TABLE = "1.3.6.1.4.1.14823.2.3.3.1.2.1.1"  # apChannelTable-ish

# Common alternate "host resources" CPU/Memory used by HPE/Cisco gear
HR_PROCESSOR_LOAD_TABLE = "1.3.6.1.2.1.25.3.3.1.2"  # walked
HR_STORAGE_TABLE = "1.3.6.1.2.1.25.2.3.1"  # walked

# IF-MIB — switch port discovery
IF_DESCR_TABLE        = "1.3.6.1.2.1.2.2.1.2"     # ifDescr
IF_TYPE_TABLE         = "1.3.6.1.2.1.2.2.1.3"     # ifType (int)
IF_SPEED_TABLE        = "1.3.6.1.2.1.2.2.1.5"     # ifSpeed bits/s
IF_ADMIN_STATUS_TABLE = "1.3.6.1.2.1.2.2.1.7"     # 1=up 2=down
IF_OPER_STATUS_TABLE  = "1.3.6.1.2.1.2.2.1.8"     # 1=up 2=down
IF_ALIAS_TABLE        = "1.3.6.1.2.1.31.1.1.1.18" # ifAlias (description)

# Q-BRIDGE-MIB — VLAN discovery
DOT1Q_VLAN_STATIC_NAME = "1.3.6.1.2.1.17.7.1.4.3.1.1"  # {vlan_id → name}
DOT1Q_PVID_TABLE        = "1.3.6.1.2.1.17.7.1.4.5.1.1"  # {bridge_port → pvid}

# ifType values that represent physical/LAG switch ports
_PHYSICAL_IF_TYPES = {"6", "161", "ethernetCsmacd", "ieee8023adLag"}


_AUTH_PROTOCOLS = {
    "md5": usmHMACMD5AuthProtocol,
    "sha": usmHMACSHAAuthProtocol,
    "sha1": usmHMACSHAAuthProtocol,
}
_PRIV_PROTOCOLS = {
    "des": usmDESPrivProtocol,
    "aes": usmAesCfb128Protocol,
    "aes128": usmAesCfb128Protocol,
}


@dataclass
class DiscoveredPort:
    name: str
    description: str = ""
    link_up: bool = False
    admin_up: bool = True
    speed_mbps: Optional[int] = None
    access_vlan: Optional[int] = None


@dataclass
class DiscoveredVlan:
    vlan_id: int
    name: str


@dataclass
class SnmpResult:
    reachable: bool = False
    error: Optional[str] = None
    sys_descr: Optional[str] = None
    sys_name: Optional[str] = None
    sys_object_id: Optional[str] = None
    sys_uptime_s: Optional[int] = None
    cpu_pct: Optional[float] = None
    mem_used_pct: Optional[float] = None
    client_count: Optional[int] = None
    interface_count: Optional[int] = None
    raw: dict[str, Any] = field(default_factory=dict)


def _auth_data(device) -> CommunityData | UsmUserData:
    if device.snmp_version in ("1", "2c"):
        return CommunityData(
            device.snmp_community or "public",
            mpModel=0 if device.snmp_version == "1" else 1,
        )
    # v3
    auth_proto = _AUTH_PROTOCOLS.get((device.snmp_auth_protocol or "").lower())
    priv_proto = _PRIV_PROTOCOLS.get((device.snmp_priv_protocol or "").lower())
    return UsmUserData(
        device.snmp_user or "",
        authKey=device.snmp_auth_password,
        privKey=device.snmp_priv_password,
        authProtocol=auth_proto,
        privProtocol=priv_proto,
    )


async def _get(engine, auth, target, ctx, oid: str) -> Optional[Any]:
    try:
        err_ind, err_status, err_idx, var_binds = await get_cmd(
            engine, auth, target, ctx, ObjectType(ObjectIdentity(oid))
        )
    except Exception as exc:  # noqa: BLE001
        log.debug("SNMP get %s failed: %s", oid, exc)
        return None
    if err_ind or err_status:
        log.debug("SNMP get %s err=%s status=%s", oid, err_ind, err_status)
        return None
    for _, val in var_binds:
        s = val.prettyPrint()
        if s in ("", "No Such Object currently exists at this OID",
                 "No Such Instance currently exists at this OID"):
            return None
        return s
    return None


async def _walk(engine, auth, target, ctx, oid: str, max_rows: int = 64) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    try:
        async for (err_ind, err_status, err_idx, var_binds) in bulk_walk_cmd(
            engine, auth, target, ctx, 0, 25,
            ObjectType(ObjectIdentity(oid)),
            lexicographicMode=False,
        ):
            if err_ind or err_status:
                log.debug("SNMP walk %s err=%s status=%s", oid, err_ind, err_status)
                break
            for vb_oid, vb_val in var_binds:
                rows.append((str(vb_oid), vb_val.prettyPrint()))
                if len(rows) >= max_rows:
                    return rows
    except Exception as exc:  # noqa: BLE001
        log.debug("SNMP walk %s failed: %s", oid, exc)
    return rows


def _to_int(v: Optional[str]) -> Optional[int]:
    if v is None:
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _to_float(v: Optional[str]) -> Optional[float]:
    if v is None:
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


async def poll_device(device, timeout: int = 5) -> SnmpResult:
    """Poll a device once. Never raises."""
    res = SnmpResult()
    if device.snmp_version not in ("1", "2c", "3"):
        res.error = f"unsupported snmp_version {device.snmp_version}"
        return res

    engine = SnmpEngine()
    try:
        target = await UdpTransportTarget.create(
            (device.ip_address, device.snmp_port),
            timeout=timeout,
            retries=1,
        )
    except Exception as exc:  # noqa: BLE001
        res.error = f"transport setup failed: {exc}"
        return res

    auth = _auth_data(device)
    ctx = ContextData()

    # Standard MIB-II
    descr = await _get(engine, auth, target, ctx, SYS_DESCR)
    if descr is None:
        res.error = "no response to sysDescr (timeout / wrong community / unreachable)"
        return res

    res.reachable = True
    res.sys_descr = descr
    res.sys_object_id = await _get(engine, auth, target, ctx, SYS_OBJECT_ID)
    res.sys_name = await _get(engine, auth, target, ctx, SYS_NAME)

    uptime_ticks = _to_int(await _get(engine, auth, target, ctx, SYS_UPTIME))
    if uptime_ticks is not None:
        res.sys_uptime_s = uptime_ticks // 100  # TimeTicks are 1/100s

    res.interface_count = _to_int(await _get(engine, auth, target, ctx, IF_NUMBER))

    # Aruba-specific (best effort)
    res.cpu_pct = _to_float(await _get(engine, auth, target, ctx, WLSX_CPU_PCT))
    res.mem_used_pct = _to_float(await _get(engine, auth, target, ctx, WLSX_MEM_PCT))
    res.client_count = _to_int(await _get(engine, auth, target, ctx, WLSX_TOTAL_USERS))

    # Fallback CPU via HOST-RESOURCES if Aruba MIB silent
    if res.cpu_pct is None:
        cpu_rows = await _walk(engine, auth, target, ctx, HR_PROCESSOR_LOAD_TABLE, max_rows=8)
        cpus = [_to_float(v) for _, v in cpu_rows if _to_float(v) is not None]
        if cpus:
            res.cpu_pct = sum(cpus) / len(cpus)

    # Walk a few rows of the AP radio table for visibility (not parsed deeply here)
    ap_rows = await _walk(engine, auth, target, ctx, WLSX_AP_RADIO_TABLE, max_rows=32)
    if ap_rows:
        res.raw["ap_radio_rows"] = ap_rows[:16]

    return res


# ----- switch discovery ---------------------------------------------------

def _tail(oid_str: str) -> str:
    """Return the last dotted component of an OID string (the table index)."""
    return oid_str.rsplit(".", 1)[-1]


def _status_up(val: str) -> bool:
    return val in ("1", "up")


async def discover_switch(
    device, timeout: int = 10
) -> tuple[list[DiscoveredPort], list[DiscoveredVlan]]:
    """Walk IF-MIB and Q-BRIDGE-MIB to discover ports and VLANs.

    Returns (ports, vlans). Never raises — returns empty lists on any failure.
    Uses last OID component as table index, which assumes bridge_port == ifIndex
    (true for most managed Aruba/HP switches).
    """
    engine = SnmpEngine()
    try:
        target = await UdpTransportTarget.create(
            (device.ip_address, device.snmp_port), timeout=timeout, retries=1
        )
    except Exception as exc:
        log.warning("discover_switch %s transport: %s", device.ip_address, exc)
        return [], []

    auth = _auth_data(device)
    ctx = ContextData()
    MAX = 512  # enough for a 48-port switch with 200 VLANs

    def _tbl(rows: list[tuple[str, str]]) -> dict[str, str]:
        return {_tail(oid): val for oid, val in rows}

    if_descr = _tbl(await _walk(engine, auth, target, ctx, IF_DESCR_TABLE, MAX))
    if not if_descr:
        log.debug("discover_switch %s: no ifDescr rows, skipping", device.ip_address)
        return [], []

    if_type  = _tbl(await _walk(engine, auth, target, ctx, IF_TYPE_TABLE, MAX))
    if_speed = _tbl(await _walk(engine, auth, target, ctx, IF_SPEED_TABLE, MAX))
    if_admin = _tbl(await _walk(engine, auth, target, ctx, IF_ADMIN_STATUS_TABLE, MAX))
    if_oper  = _tbl(await _walk(engine, auth, target, ctx, IF_OPER_STATUS_TABLE, MAX))
    if_alias = _tbl(await _walk(engine, auth, target, ctx, IF_ALIAS_TABLE, MAX))
    pvid     = _tbl(await _walk(engine, auth, target, ctx, DOT1Q_PVID_TABLE, MAX))

    # VLANs
    vlans: list[DiscoveredVlan] = []
    for oid, val in await _walk(engine, auth, target, ctx, DOT1Q_VLAN_STATIC_NAME, MAX):
        if not val or "No Such" in val:
            continue
        try:
            vlan_id = int(_tail(oid))
        except ValueError:
            continue
        if 1 <= vlan_id <= 4094:
            vlans.append(DiscoveredVlan(vlan_id=vlan_id, name=val or f"VLAN{vlan_id}"))

    # Ports
    ports: list[DiscoveredPort] = []
    for idx, name in if_descr.items():
        itype = if_type.get(idx, "")
        if itype not in _PHYSICAL_IF_TYPES:
            continue

        speed_bps = _to_int(if_speed.get(idx))
        speed_mbps = speed_bps // 1_000_000 if speed_bps else None

        desc = if_alias.get(idx, "") or ""
        if "No Such" in desc:
            desc = ""

        vlan_id = _to_int(pvid.get(idx))
        if vlan_id == 0:
            vlan_id = None

        ports.append(DiscoveredPort(
            name=name,
            description=desc,
            link_up=_status_up(if_oper.get(idx, "2")),
            admin_up=_status_up(if_admin.get(idx, "1")),
            speed_mbps=speed_mbps,
            access_vlan=vlan_id,
        ))

    log.info(
        "discover_switch %s: %d ports, %d VLANs",
        device.ip_address, len(ports), len(vlans),
    )
    return ports, vlans
