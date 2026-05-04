"""REST API for device CRUD."""
from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.auth import require_user
from app.db import get_session
from app.models import Device
from app.schemas import DeviceCreate, DeviceOut, DeviceUpdate

router = APIRouter(prefix="/api/devices", tags=["devices"])


@router.get("", response_model=List[DeviceOut])
def list_devices(db: Session = Depends(get_session), _: str = Depends(require_user)):
    return db.query(Device).order_by(Device.name).all()


@router.post("", response_model=DeviceOut, status_code=201)
def create_device(
    payload: DeviceCreate,
    db: Session = Depends(get_session),
    _: str = Depends(require_user),
):
    if db.query(Device).filter(Device.ip_address == payload.ip_address).first():
        raise HTTPException(status_code=409, detail="device with that IP already exists")
    device = Device(**payload.model_dump())
    db.add(device)
    db.flush()
    return device


@router.get("/{device_id}", response_model=DeviceOut)
def get_device(
    device_id: int,
    db: Session = Depends(get_session),
    _: str = Depends(require_user),
):
    device = db.get(Device, device_id)
    if not device:
        raise HTTPException(status_code=404)
    return device


@router.put("/{device_id}", response_model=DeviceOut)
def update_device(
    device_id: int,
    payload: DeviceUpdate,
    db: Session = Depends(get_session),
    _: str = Depends(require_user),
):
    device = db.get(Device, device_id)
    if not device:
        raise HTTPException(status_code=404)
    for k, v in payload.model_dump().items():
        setattr(device, k, v)
    db.flush()
    return device


@router.delete("/{device_id}", status_code=204)
def delete_device(
    device_id: int,
    db: Session = Depends(get_session),
    _: str = Depends(require_user),
):
    device = db.get(Device, device_id)
    if not device:
        raise HTTPException(status_code=404)
    db.delete(device)
