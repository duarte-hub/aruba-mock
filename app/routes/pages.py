"""HTML page handlers (HTMX + Jinja)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth import (
    clear_session,
    current_user,
    issue_session,
    require_user,
    verify_login,
)
from app.db import get_session
from app.models import Device, DeviceStatus, Insight, InsightSeverity, Sample
from app.services import airmatch as airmatch_svc
from app.services import insights as insights_svc
from app.services.snmp import poll_device
from app.services.ssh import is_safe_command, run_command

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


# ---- auth ----------------------------------------------------------------

@router.get("/login", response_class=HTMLResponse)
def login_form(request: Request, error: str | None = None):
    return templates.TemplateResponse("login.html", {"request": request, "error": error})


@router.post("/login", response_class=HTMLResponse)
def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    if not verify_login(username, password):
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Invalid credentials"},
            status_code=401,
        )
    response = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    issue_session(response, username)
    return response


@router.get("/logout")
def logout():
    response = RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    clear_session(response)
    return response


# ---- dashboard -----------------------------------------------------------

@router.get("/", response_class=HTMLResponse)
def dashboard(
    request: Request,
    db: Session = Depends(get_session),
    user: str = Depends(require_user),
):
    devices = db.query(Device).order_by(Device.last_seen.desc().nullslast()).limit(8).all()
    insights = (
        db.query(Insight)
        .order_by(
            (Insight.severity == InsightSeverity.CRITICAL).desc(),
            (Insight.severity == InsightSeverity.WARNING).desc(),
            Insight.created_at.desc(),
        )
        .limit(5)
        .all()
    )

    total = db.query(Device).count()
    online = db.query(Device).filter(Device.status == DeviceStatus.ONLINE).count()
    offline = db.query(Device).filter(Device.status == DeviceStatus.OFFLINE).count()
    crit = db.query(Insight).filter(Insight.severity == InsightSeverity.CRITICAL).count()

    tiles = [
        {"label": "Devices", "value": total, "color": "text-slate-100"},
        {"label": "Online", "value": online, "color": "text-emerald-400"},
        {"label": "Offline", "value": offline, "color": "text-red-400"},
        {"label": "Critical insights", "value": crit, "color": "text-orange-400"},
    ]

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "user": user,
            "active": "dashboard",
            "tiles": tiles,
            "top_insights": [
                {
                    "title": i.title,
                    "recommendation": i.recommendation,
                    "severity": i.severity.value,
                }
                for i in insights
            ],
            "devices": devices,
        },
    )


# ---- devices -------------------------------------------------------------

@router.get("/devices", response_class=HTMLResponse)
def devices_list(
    request: Request,
    db: Session = Depends(get_session),
    user: str = Depends(require_user),
):
    devices = db.query(Device).order_by(Device.name).all()
    return templates.TemplateResponse(
        "devices.html",
        {"request": request, "user": user, "active": "devices", "devices": devices},
    )


@router.post("/devices")
def devices_create(
    name: str = Form(...),
    hostname: str = Form(...),
    ip_address: str = Form(...),
    device_type: str = Form("other"),
    site: str = Form("default"),
    snmp_version: str = Form("2c"),
    snmp_community: str = Form("public"),
    snmp_port: int = Form(161),
    ssh_user: str = Form(""),
    ssh_password: str = Form(""),
    ssh_port: int = Form(22),
    ssh_device_type: str = Form("aruba_os"),
    db: Session = Depends(get_session),
    _: str = Depends(require_user),
):
    if db.query(Device).filter(Device.ip_address == ip_address).first():
        return RedirectResponse(url="/devices?error=duplicate", status_code=303)
    device = Device(
        name=name,
        hostname=hostname,
        ip_address=ip_address,
        device_type=device_type,
        site=site,
        snmp_version=snmp_version,
        snmp_community=snmp_community or None,
        snmp_port=snmp_port,
        ssh_user=ssh_user or None,
        ssh_password=ssh_password or None,
        ssh_port=ssh_port,
        ssh_device_type=ssh_device_type or "aruba_os",
    )
    db.add(device)
    db.flush()
    return RedirectResponse(url="/devices", status_code=303)


@router.post("/devices/{device_id}/delete")
def devices_delete(
    device_id: int,
    db: Session = Depends(get_session),
    _: str = Depends(require_user),
):
    device = db.get(Device, device_id)
    if device:
        db.delete(device)
    return RedirectResponse(url="/devices", status_code=303)


@router.get("/devices/{device_id}", response_class=HTMLResponse)
def device_detail(
    request: Request,
    device_id: int,
    db: Session = Depends(get_session),
    user: str = Depends(require_user),
):
    device = db.get(Device, device_id)
    if not device:
        return RedirectResponse(url="/devices", status_code=303)
    latest = (
        db.execute(
            select(Sample).where(Sample.device_id == device_id)
            .order_by(Sample.timestamp.desc()).limit(1)
        ).scalar_one_or_none()
    )
    return templates.TemplateResponse(
        "device_detail.html",
        {
            "request": request,
            "user": user,
            "active": "devices",
            "device": device,
            "latest": latest,
            "ssh_output": None,
        },
    )


@router.post("/devices/{device_id}/poll")
async def device_poll(
    device_id: int,
    db: Session = Depends(get_session),
    _: str = Depends(require_user),
):
    device = db.get(Device, device_id)
    if not device:
        return RedirectResponse(url="/devices", status_code=303)
    result = await poll_device(device)
    sample = Sample(
        device_id=device.id,
        reachable=result.reachable,
        sys_descr=result.sys_descr,
        sys_uptime_s=result.sys_uptime_s,
        cpu_pct=result.cpu_pct,
        mem_used_pct=result.mem_used_pct,
        client_count=result.client_count,
        raw=result.raw or {},
    )
    db.add(sample)
    if result.reachable:
        device.status = DeviceStatus.ONLINE
        device.last_error = None
        if result.sys_descr and not device.firmware:
            device.firmware = result.sys_descr[:128]
    else:
        device.status = DeviceStatus.OFFLINE
        device.last_error = result.error or "unreachable"
    db.flush()
    return RedirectResponse(url=f"/devices/{device_id}", status_code=303)


@router.post("/devices/{device_id}/ssh", response_class=HTMLResponse)
def device_ssh(
    request: Request,
    device_id: int,
    command: str = Form(...),
    db: Session = Depends(get_session),
    user: str = Depends(require_user),
):
    device = db.get(Device, device_id)
    if not device:
        return RedirectResponse(url="/devices", status_code=303)

    if not is_safe_command(command):
        output = "Refused: only read-only commands ('show', 'display', 'get') are allowed."
    else:
        result = run_command(device, command)
        output = result.output if result.ok else f"Error: {result.error}"

    latest = (
        db.execute(
            select(Sample).where(Sample.device_id == device_id)
            .order_by(Sample.timestamp.desc()).limit(1)
        ).scalar_one_or_none()
    )
    return templates.TemplateResponse(
        "device_detail.html",
        {
            "request": request,
            "user": user,
            "active": "devices",
            "device": device,
            "latest": latest,
            "ssh_output": output,
        },
    )


# ---- insights ------------------------------------------------------------

@router.get("/insights", response_class=HTMLResponse)
def insights_view(
    request: Request,
    db: Session = Depends(get_session),
    user: str = Depends(require_user),
):
    insights = (
        db.query(Insight)
        .order_by(
            (Insight.severity == InsightSeverity.CRITICAL).desc(),
            (Insight.severity == InsightSeverity.WARNING).desc(),
            Insight.created_at.desc(),
        )
        .all()
    )
    return templates.TemplateResponse(
        "insights.html",
        {"request": request, "user": user, "active": "insights", "insights": insights},
    )


@router.post("/insights/recompute")
def insights_recompute_form(_: str = Depends(require_user)):
    insights_svc.recompute_insights()
    return RedirectResponse(url="/insights", status_code=303)


# ---- airmatch ------------------------------------------------------------

@router.get("/airmatch", response_class=HTMLResponse)
def airmatch_view(
    request: Request,
    user: str = Depends(require_user),
):
    return templates.TemplateResponse(
        "airmatch.html",
        {"request": request, "user": user, "active": "airmatch", "plan": None},
    )


@router.post("/airmatch/run", response_class=HTMLResponse)
def airmatch_run_form(
    request: Request,
    band: str = Form(...),
    allow_dfs: str | None = Form(None),
    user: str = Depends(require_user),
):
    plan = airmatch_svc.plan_airmatch(band=band, allow_dfs=bool(allow_dfs))
    return templates.TemplateResponse(
        "airmatch.html",
        {"request": request, "user": user, "active": "airmatch", "plan": plan},
    )
