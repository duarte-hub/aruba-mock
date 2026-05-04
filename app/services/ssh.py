"""SSH command runner for managed devices.

Uses Netmiko, which already speaks Aruba ArubaOS, ArubaOS-CX, and many other
vendor flavours. Commands are allowlisted to read-only "show" / "display"
families to keep accidental misconfiguration off the table.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Optional

from netmiko import ConnectHandler  # type: ignore[import-untyped]
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

log = logging.getLogger("aruba.ssh")


_ALLOWED_PREFIXES = (
    "show ",
    "display ",
    "get ",
    "ping ",  # bounded by netmiko prompt timeout
)

_DENIED_PATTERNS = (
    re.compile(r"\b(no|delete|erase|clear\s+config|write|reload|reboot|shutdown)\b", re.I),
    re.compile(r";|\|\s*sh\b|`|\$\("),  # injection-ish
)


class SSHCommandError(RuntimeError):
    pass


@dataclass
class SSHResult:
    ok: bool
    output: str
    error: Optional[str] = None


def is_safe_command(cmd: str) -> bool:
    cmd = cmd.strip()
    if not cmd:
        return False
    if not any(cmd.lower().startswith(p) for p in _ALLOWED_PREFIXES):
        return False
    if any(p.search(cmd) for p in _DENIED_PATTERNS):
        return False
    return True


def run_command(device, command: str, timeout: int = 10) -> SSHResult:
    if not is_safe_command(command):
        return SSHResult(ok=False, output="", error="command not allowed")

    if not device.ssh_user or not device.ssh_password:
        return SSHResult(ok=False, output="", error="ssh credentials not configured")

    params = {
        "device_type": device.ssh_device_type or "aruba_os",
        "host": device.ip_address,
        "username": device.ssh_user,
        "password": device.ssh_password,
        "port": device.ssh_port,
        "fast_cli": False,
        "timeout": timeout,
        "auth_timeout": timeout,
        "banner_timeout": timeout,
    }
    try:
        with ConnectHandler(**params) as conn:
            output = conn.send_command(command, read_timeout=timeout)
        return SSHResult(ok=True, output=output)
    except NetmikoAuthenticationException as exc:
        return SSHResult(ok=False, output="", error=f"auth failed: {exc}")
    except NetmikoTimeoutException as exc:
        return SSHResult(ok=False, output="", error=f"timeout: {exc}")
    except Exception as exc:  # noqa: BLE001
        log.exception("ssh run_command unexpected failure")
        return SSHResult(ok=False, output="", error=str(exc))
