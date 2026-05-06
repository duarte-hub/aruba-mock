"""SNMP polling + switch discovery service.

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

import httpx

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
IF_IN_DISCARDS_TABLE  = "1.3.6.1.2.1.2.2.1.13"    # ifInDiscards
IF_IN_ERRORS_TABLE    = "1.3.6.1.2.1.2.2.1.14"    # ifInErrors
IF_OUT_DISCARDS_TABLE = "1.3.6.1.2.1.2.2.1.19"    # ifOutDiscards
IF_OUT_ERRORS_TABLE   = "1.3.6.1.2.1.2.2.1.20"    # ifOutErrors
IF_ALIAS_TABLE        = "1.3.6.1.2.1.31.1.1.1.18" # ifAlias (description)

# BRIDGE-MIB — FDB (forwarding database) — connected device MACs
DOT1D_TP_FDB_PORT      = "1.3.6.1.2.1.17.4.3.1.2"  # {mac → bridge_port}  indexed by 6-octet MAC
DOT1D_TP_FDB_STATUS    = "1.3.6.1.2.1.17.4.3.1.3"  # {mac → status}  3=learned, 4=self
DOT1D_BASE_PORT_IF_IDX = "1.3.6.1.2.1.17.1.4.1.2"  # {bridge_port → ifIndex}

# Q-BRIDGE-MIB — VLAN discovery
DOT1Q_VLAN_STATIC_NAME = "1.3.6.1.2.1.17.7.1.4.3.1.1"  # {vlan_id → name}
DOT1Q_PVID_TABLE        = "1.3.6.1.2.1.17.7.1.4.5.1.1"  # {bridge_port → pvid}

# LLDP-MIB — neighbor discovery (IEEE 802.1AB; index: timeMark.localPortNum.remIndex)
LLDP_REM_PORT_ID  = "1.0.8802.1.1.2.1.4.1.1.7"  # lldpRemPortId
LLDP_REM_SYS_NAME = "1.0.8802.1.1.2.1.4.1.1.9"  # lldpRemSysName

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
    mac_address: Optional[str] = None
    mac_vendor: Optional[str] = None
    lldp_neighbor: Optional[str] = None
    lldp_neighbor_port: Optional[str] = None
    in_errors: Optional[int] = None
    out_errors: Optional[int] = None
    in_discards: Optional[int] = None


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


def _fdb_mac_from_oid(oid_str: str, col_oid: str) -> Optional[str]:
    """Extract MAC address from a BRIDGE-MIB FDB OID (index = 6 decimal octets).

    e.g. '1.3.6.1.2.1.17.4.3.1.2.170.187.204.221.238.255'
          → 'aa:bb:cc:dd:ee:ff'
    """
    prefix = col_oid + "."
    if not oid_str.startswith(prefix):
        return None
    parts = oid_str[len(prefix):].split(".")
    if len(parts) != 6:
        return None
    try:
        mac = ":".join(f"{int(p):02x}" for p in parts)
    except ValueError:
        return None
    return None if mac == "00:00:00:00:00:00" else mac


def _lldp_local_port(oid_str: str, col_oid: str) -> Optional[str]:
    """Extract localPortNum from an LLDP OID (index: timeMark.localPortNum.remIndex)."""
    prefix = col_oid + "."
    if not oid_str.startswith(prefix):
        return None
    parts = oid_str[len(prefix):].split(".")
    # Index has exactly 3 components; localPortNum is index 1
    return parts[1] if len(parts) >= 3 else None


async def _lookup_mac_vendor(oui: str) -> Optional[str]:
    """Query macvendors.com for a 6-hex-char OUI. Returns None on any failure."""
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            r = await client.get(f"https://api.macvendors.com/{oui}")
            if r.status_code == 200:
                return r.text.strip()[:128]
    except Exception as exc:
        log.debug("MAC vendor lookup %s: %s", oui, exc)
    return None


async def discover_switch(
    device, timeout: int = 10
) -> tuple[list[DiscoveredPort], list[DiscoveredVlan]]:
    """Walk IF-MIB, Q-BRIDGE-MIB, and LLDP-MIB to discover ports and VLANs.

    Returns (ports, vlans). Never raises — returns empty lists on any failure.
    Assumes bridge_port == ifIndex (true for most Aruba/HP switches).
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
    MAX = 512  # enough for a 48-port switch with many VLANs

    def _tbl(rows: list[tuple[str, str]]) -> dict[str, str]:
        return {_tail(oid): val for oid, val in rows}

    if_descr = _tbl(await _walk(engine, auth, target, ctx, IF_DESCR_TABLE, MAX))
    if not if_descr:
        log.debug("discover_switch %s: no ifDescr rows", device.ip_address)
        return [], []

    # Walk all tables in parallel
    (
        if_type_rows, if_speed_rows, if_admin_rows,
        if_oper_rows, if_alias_rows, if_in_err_rows, if_out_err_rows,
        if_in_dis_rows, pvid_rows, vlan_name_rows,
        lldp_sys_rows, lldp_port_rows,
        fdb_port_rows, fdb_status_rows, bridge_if_rows,
    ) = await asyncio.gather(
        _walk(engine, auth, target, ctx, IF_TYPE_TABLE, MAX),
        _walk(engine, auth, target, ctx, IF_SPEED_TABLE, MAX),
        _walk(engine, auth, target, ctx, IF_ADMIN_STATUS_TABLE, MAX),
        _walk(engine, auth, target, ctx, IF_OPER_STATUS_TABLE, MAX),
        _walk(engine, auth, target, ctx, IF_ALIAS_TABLE, MAX),
        _walk(engine, auth, target, ctx, IF_IN_ERRORS_TABLE, MAX),
        _walk(engine, auth, target, ctx, IF_OUT_ERRORS_TABLE, MAX),
        _walk(engine, auth, target, ctx, IF_IN_DISCARDS_TABLE, MAX),
        _walk(engine, auth, target, ctx, DOT1Q_PVID_TABLE, MAX),
        _walk(engine, auth, target, ctx, DOT1Q_VLAN_STATIC_NAME, MAX),
        _walk(engine, auth, target, ctx, LLDP_REM_SYS_NAME, MAX),
        _walk(engine, auth, target, ctx, LLDP_REM_PORT_ID, MAX),
        _walk(engine, auth, target, ctx, DOT1D_TP_FDB_PORT, MAX),
        _walk(engine, auth, target, ctx, DOT1D_TP_FDB_STATUS, MAX),
        _walk(engine, auth, target, ctx, DOT1D_BASE_PORT_IF_IDX, MAX),
    )

    if_type    = _tbl(if_type_rows)
    if_speed   = _tbl(if_speed_rows)
    if_admin   = _tbl(if_admin_rows)
    if_oper    = _tbl(if_oper_rows)
    if_alias   = _tbl(if_alias_rows)
    if_in_err  = _tbl(if_in_err_rows)
    if_out_err = _tbl(if_out_err_rows)
    if_in_dis  = _tbl(if_in_dis_rows)
    pvid       = _tbl(pvid_rows)

    # FDB: build {ifIndex → first learned device MAC}
    # Step 1: mac → bridge_port (only status=3 learned entries)
    fdb_status: dict[str, str] = {
        _fdb_mac_from_oid(oid, DOT1D_TP_FDB_STATUS): val
        for oid, val in fdb_status_rows
        if _fdb_mac_from_oid(oid, DOT1D_TP_FDB_STATUS)
    }
    # Step 2: bridge_port → ifIndex
    bridge_to_if: dict[str, str] = _tbl(bridge_if_rows)  # {bridge_port → ifIndex}
    # Step 3: ifIndex → first learned device MAC
    if_mac: dict[str, str] = {}
    for oid, bridge_port in fdb_port_rows:
        mac = _fdb_mac_from_oid(oid, DOT1D_TP_FDB_PORT)
        if not mac:
            continue
        if fdb_status.get(mac, "") != "3":  # 3 = learned (not self/mgmt)
            continue
        ifidx = bridge_to_if.get(bridge_port)
        if ifidx and ifidx not in if_mac:
            if_mac[ifidx] = mac

    # LLDP neighbors: {localPortNum → sys_name / port_id} — take first per port
    lldp_sys: dict[str, str] = {}
    for oid, val in lldp_sys_rows:
        port_num = _lldp_local_port(oid, LLDP_REM_SYS_NAME)
        if port_num and port_num not in lldp_sys and val and "No Such" not in val:
            lldp_sys[port_num] = val

    lldp_port: dict[str, str] = {}
    for oid, val in lldp_port_rows:
        port_num = _lldp_local_port(oid, LLDP_REM_PORT_ID)
        if port_num and port_num not in lldp_port and val and "No Such" not in val:
            lldp_port[port_num] = val

    # VLANs
    vlans: list[DiscoveredVlan] = []
    for oid, val in vlan_name_rows:
        if not val or "No Such" in val:
            continue
        try:
            vlan_id = int(_tail(oid))
        except ValueError:
            continue
        if 1 <= vlan_id <= 4094:
            vlans.append(DiscoveredVlan(vlan_id=vlan_id, name=val))

    # Ports
    ports: list[DiscoveredPort] = []
    for idx, name in if_descr.items():
        if if_type.get(idx, "") not in _PHYSICAL_IF_TYPES:
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
            mac_address=if_mac.get(idx),
            lldp_neighbor=lldp_sys.get(idx),
            lldp_neighbor_port=lldp_port.get(idx),
            in_errors=_to_int(if_in_err.get(idx)),
            out_errors=_to_int(if_out_err.get(idx)),
            in_discards=_to_int(if_in_dis.get(idx)),
        ))

    # MAC vendor lookup — deduplicate OUIs, run in parallel
    unique_ouis = {
        p.mac_address.replace(":", "")[:6].upper()
        for p in ports if p.mac_address
    }
    if unique_ouis:
        vendor_results = await asyncio.gather(
            *[_lookup_mac_vendor(oui) for oui in unique_ouis],
            return_exceptions=True,
        )
        vendor_cache = {
            oui: v
            for oui, v in zip(unique_ouis, vendor_results)
            if isinstance(v, str)
        }
        for p in ports:
            if p.mac_address:
                oui = p.mac_address.replace(":", "")[:6].upper()
                p.mac_vendor = vendor_cache.get(oui)

    log.info(
        "discover_switch %s: %d ports, %d VLANs",
        device.ip_address, len(ports), len(vlans),
    )
    return ports, vlans
