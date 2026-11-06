"""Patch exposure, Uyuni control-plane and kernel live-patch endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from .. import models
from ..db import get_db
from ..schemas import LivepatchIn, LivepatchOut, PatchFindingOut
from ..security import get_current_user, require_roles
from ..services import (
    audit_service,
    kpi_service,
    livepatch_service,
    patch_service,
    uyuni_service,
    wazuh_service,
)

router = APIRouter(prefix="/patching", tags=["patching"])


@router.get("/findings", response_model=list[PatchFindingOut])
def list_findings(
    host_name: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    source: str | None = None,
    limit: int = Query(default=200, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> list[PatchFindingOut]:
    findings = patch_service.list_findings(
        db,
        host_name=host_name,
        severity=severity,
        status=status,
        source=source,
        limit=limit,
        offset=offset,
    )
    return [PatchFindingOut.model_validate(item) for item in findings]


@router.get("/summary")
def patch_summary(
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> dict:
    return {
        "patches": patch_service.summary(db),
        "livepatch": livepatch_service.summary(db),
    }


@router.post("/findings/{finding_id}/resolve", response_model=PatchFindingOut)
def resolve_finding(
    finding_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_roles("admin", "operator")),
) -> PatchFindingOut:
    finding = patch_service.resolve(db, finding_id)
    audit_service.record(
        db,
        actor=user,
        action="patch.resolve",
        target_type="patch_finding",
        target_id=str(finding.id),
        data={"host": finding.host_name, "package": finding.package},
        request=request,
    )
    db.commit()
    kpi_service.capture_snapshot(db)
    return PatchFindingOut.model_validate(finding)


@router.post("/wazuh/sync")
def sync_from_wazuh(
    request: Request,
    host_name: str | None = None,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_roles("admin", "operator")),
) -> dict:
    result = wazuh_service.sync_vulnerabilities(
        db, host_names=[host_name] if host_name else None
    )
    audit_service.record(
        db,
        actor=user,
        action="patching.wazuh.sync",
        target_type="integration",
        target_id="wazuh",
        data=result,
        request=request,
    )
    db.commit()
    kpi_service.capture_snapshot(db)
    return result


@router.get("/uyuni")
def list_uyuni_systems(
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> list[dict]:
    systems = db.query(models.UyuniSystem).order_by(models.UyuniSystem.host_name).all()
    return [
        {
            "id": system.id,
            "host_id": system.host_id,
            "host_name": system.host_name,
            "uyuni_system_id": system.uyuni_system_id,
            "status": system.status,
            "channels": system.channels,
            "last_sync": system.last_sync,
        }
        for system in systems
    ]


@router.post("/uyuni/sync")
def sync_uyuni(
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_roles("admin", "operator")),
) -> dict:
    systems = uyuni_service.sync_systems(db)
    errata = uyuni_service.sync_patch_findings(db)
    audit_service.record(
        db,
        actor=user,
        action="patching.uyuni.sync",
        target_type="integration",
        target_id="uyuni",
        data={"systems": systems, "errata": errata},
        request=request,
    )
    db.commit()
    kpi_service.capture_snapshot(db)
    return {"systems": systems, "errata": errata}


@router.get("/livepatch", response_model=list[LivepatchOut])
def list_livepatch(
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> list[LivepatchOut]:
    return [
        livepatch_service.serialize(item)
        for item in livepatch_service.list_latest(db)
    ]


@router.post("/livepatch", response_model=LivepatchOut, status_code=201)
def ingest_livepatch(
    payload: LivepatchIn,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_roles("admin", "operator")),
) -> LivepatchOut:
    record = livepatch_service.ingest(db, payload)
    audit_service.record(
        db,
        actor=user,
        action="livepatch.ingest",
        target_type="host",
        target_id=payload.host_name,
        data=payload.model_dump(),
        request=request,
    )
    db.commit()
    kpi_service.capture_snapshot(db)
    return livepatch_service.serialize(record)
