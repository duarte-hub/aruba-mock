"""FastAPI application entrypoint."""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import RedirectResponse

from app.config import get_settings
from app.routes import api_actions, api_devices, pages
from app.services.poller import start_scheduler, stop_scheduler

log = logging.getLogger("aruba")


def _configure_logging() -> None:
    level = get_settings().log_level.upper()
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # Tame chatty libs
    logging.getLogger("apscheduler").setLevel(logging.WARNING)
    logging.getLogger("pysnmp").setLevel(logging.WARNING)
    logging.getLogger("paramiko").setLevel(logging.WARNING)


@asynccontextmanager
async def lifespan(app: FastAPI):
    _configure_logging()
    log.info("starting aruba-mock")
    start_scheduler()
    try:
        yield
    finally:
        stop_scheduler()
        log.info("aruba-mock stopped")


app = FastAPI(
    title="Aruba Mock",
    version="0.1.0",
    description="Self-hosted Aruba-Central-style dashboard for homelab use.",
    lifespan=lifespan,
)

app.include_router(pages.router)
app.include_router(api_devices.router)
app.include_router(api_actions.router)


@app.get("/healthz", include_in_schema=False)
def healthz():
    return {"status": "ok"}


@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    return RedirectResponse(url="data:,", status_code=302)
