"""OpenSCAP compliance scan ingestion and reporting."""

from __future__ import annotations

import csv
import io
from typing import Literal

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse, StreamingResponse
from sqlalchemy.orm import Session

from .. import models
from ..config import get_settings
from ..db import get_db
from ..errors import DomainError
from ..schemas import (
    ComplianceScanCreate,
    ComplianceScanDetail,
    ComplianceScanOut,
)
from ..security import get_current_user, require_roles
from ..services import audit_service, kpi_service, oscap_service

router = APIRouter(prefix="/compliance", tags=["compliance"])


@router.get("/scans", response_model=list[ComplianceScanOut])
def list_scans(
    host_name: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> list[ComplianceScanOut]:
    scans = oscap_service.list_scans(
        db, host_name=host_name, limit=limit, offset=offset
    )
    return [oscap_service.serialize(scan) for scan in scans]


@router.get("/scans/export", response_model=None)
def export_scans(
    format: Literal["json", "csv"] = "json",
    host_name: str | None = None,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> JSONResponse | StreamingResponse:
    scans = oscap_service.list_scans(db, host_name=host_name, limit=500)
    details = [
        oscap_service.serialize(scan, include_findings=True).model_dump(mode="json")
        for scan in scans
    ]

    if format == "json":
        return JSONResponse(
            content=details,
            headers={
                "Content-Disposition": 'attachment; filename="openscap-scans.json"'
            },
        )

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "scan_id",
            "host_name",
            "profile",
            "status",
            "score",
            "rule_id",
            "title",
            "result",
            "severity",
            "remediation",
        ]
    )
    for scan in details:
        findings = scan["findings"] or [None]
        for finding in findings:
            writer.writerow(
                [
                    scan["id"],
                    scan["host_name"],
                    scan["profile"],
                    scan["status"],
                    scan["score"],
                    finding["rule_id"] if finding else "",
                    finding["title"] if finding else "",
                    finding["result"] if finding else "",
                    finding["severity"] if finding else "",
                    finding["remediation"] if finding else "",
                ]
            )

    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": 'attachment; filename="openscap-scans.csv"'
        },
    )


@router.post("/scans", response_model=ComplianceScanDetail, status_code=201)
def create_scan(
    payload: ComplianceScanCreate,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_roles("admin", "operator")),
) -> ComplianceScanDetail:
    if bool(payload.content) == bool(payload.artifact_path):
        raise DomainError("provide exactly one of content or artifact_path")
    content = (
        payload.content.encode("utf-8")
        if payload.content
        else oscap_service.read_artifact(payload.artifact_path or "")
    )
    scan = oscap_service.ingest_scan(
        db,
        host_name=payload.host_name,
        content=content,
        profile=payload.profile,
        artifact_path=payload.artifact_path,
    )
    audit_service.record(
        db,
        actor=user,
        action="compliance.scan.ingest",
        target_type="compliance_scan",
        target_id=scan.id,
        data={
            "host": scan.host_name,
            "profile": scan.profile,
            "score": scan.score,
        },
        request=request,
    )
    db.commit()
    kpi_service.capture_snapshot(db)
    return oscap_service.serialize(scan, include_findings=True)


@router.get("/scans/{scan_id}", response_model=ComplianceScanDetail)
def get_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> ComplianceScanDetail:
    return oscap_service.serialize(
        oscap_service.get_scan(db, scan_id), include_findings=True
    )


@router.get("/profiles", response_model=list[str])
def list_profiles(
    user: models.User = Depends(get_current_user),
) -> list[str]:
    directory = get_settings().openscap_profile_dir
    if not directory.is_dir():
        return []
    return sorted(path.name for path in directory.iterdir() if path.is_file())


@router.get("/summary")
def compliance_summary(
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> dict:
    scans = oscap_service.list_scans(db, limit=500)
    latest: dict[str, models.ComplianceScan] = {}
    for scan in scans:
        latest.setdefault(scan.host_name, scan)
    scored = [scan.score for scan in latest.values() if scan.score is not None]
    worst = [
        {"host": host, "score": score}
        for host, score in sorted(
            (
                (scan.host_name, scan.score)
                for scan in latest.values()
                if scan.score is not None
            ),
            key=lambda item: item[1] if item[1] is not None else 0.0,
        )[:10]
    ]
    return {
        "hosts_scanned": len(latest),
        "average_score": (sum(scored) / len(scored)) if scored else None,
        "worst_hosts": worst,
    }
