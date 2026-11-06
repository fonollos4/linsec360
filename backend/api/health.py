"""Liveness and readiness endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Response, status

from .. import __version__
from ..config import get_settings
from ..db import database_is_ready

router = APIRouter(tags=["health"])


@router.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "service": get_settings().app_name,
        "version": __version__,
    }


@router.get("/ready")
def ready(response: Response) -> dict:
    if not database_is_ready():
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {"status": "not_ready", "checks": {"database": "fail"}}
    return {"status": "ready", "checks": {"database": "ok"}}
