"""On-demand actions: poll a device, run AirMatch, run an SSH show command."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Body
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.auth import require_user
from app.db import get_session
from app.models import Device
from app.services import airmatch as airmatch_svc
from app.services import insights as insights_svc
from app.services.snmp import poll_device
from app.services.ssh import run_command, is_safe_command

router = APIRouter(prefix="/api", tags=["actions"])


class CommandRequest(BaseModel):
    command: str


@router.post("/devices/{device_id}/poll")
async def poll_now(
    device_id: int,
    db: Session = Depends(get_session),
    _: str = Depends(require_user),
):
    device = db.get(Device, device_id)
    if not device:
        raise HTTPException(404)
    result = await poll_device(device)
    return {
        "reachable": result.reachable,
        "error": result.error,
        "sys_descr": result.sys_descr,
        "sys_uptime_s": result.sys_uptime_s,
        "cpu_pct": result.cpu_pct,
        "mem_used_pct": result.mem_used_pct,
        "client_count": result.client_count,
    }


@router.post("/devices/{device_id}/ssh")
def ssh_run(
    device_id: int,
    payload: CommandRequest,
    db: Session = Depends(get_session),
    _: str = Depends(require_user),
):
    device = db.get(Device, device_id)
    if not device:
        raise HTTPException(404)
    if not is_safe_command(payload.command):
        raise HTTPException(400, detail="command not allowed; use 'show' / 'display' commands")
    result = run_command(device, payload.command)
    return {"ok": result.ok, "output": result.output, "error": result.error}


@router.post("/airmatch/run")
def airmatch_run(
    band: str = Body(..., embed=True),
    allow_dfs: bool = Body(False, embed=True),
    _: str = Depends(require_user),
):
    if band not in ("2.4", "5", "6"):
        raise HTTPException(400, "band must be one of 2.4, 5, 6")
    plan = airmatch_svc.plan_airmatch(band=band, allow_dfs=allow_dfs)
    return plan


@router.post("/insights/recompute")
def insights_recompute(_: str = Depends(require_user)):
    n = insights_svc.recompute_insights()
    return {"insights": n}
