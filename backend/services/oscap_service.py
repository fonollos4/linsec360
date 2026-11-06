"""OpenSCAP (XCCDF/ARF) result ingestion and compliance scoring."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path
from xml.etree import ElementTree

from sqlalchemy.orm import Session

from .. import models
from ..config import get_settings
from ..errors import DomainError, NotFoundError
from ..schemas import (
    ComplianceFindingOut,
    ComplianceScanDetail,
    ComplianceScanOut,
)

MAX_ARTIFACT_BYTES = 25 * 1024 * 1024
RESULT_ALIASES = {
    "pass": "pass",
    "fail": "fail",
    "error": "error",
    "unknown": "unknown",
    "notapplicable": "not_applicable",
    "notchecked": "not_checked",
    "informational": "informational",
    "fixed": "fixed",
}


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _child_text(element: ElementTree.Element, name: str) -> str | None:
    for child in element:
        if _local(child.tag) == name:
            text = (child.text or "").strip()
            return text or None
    return None


def _iter_local(root: ElementTree.Element, name: str):
    for element in root.iter():
        if _local(element.tag) == name:
            yield element


def _rule_metadata(root: ElementTree.Element) -> dict[str, dict]:
    metadata: dict[str, dict] = {}
    for rule in _iter_local(root, "Rule"):
        rule_id = rule.get("id")
        if not rule_id:
            continue
        metadata[rule_id] = {
            "title": _child_text(rule, "title"),
            "description": _child_text(rule, "description"),
            "remediation": _child_text(rule, "fixtext"),
            "severity": rule.get("severity"),
        }
    return metadata


def parse_xccdf(content: str | bytes, *, profile_hint: str | None = None) -> dict:
    """Parse an XCCDF/ARF document into a normalized scan result.

    Both plain XCCDF results and ARF (Asset Reporting Format) wrappers are
    accepted because ``oscap xccdf eval --results`` can emit either.
    """
    try:
        root = ElementTree.fromstring(content)
    except ElementTree.ParseError as exc:
        raise DomainError(f"invalid OpenSCAP XML: {exc}") from exc

    metadata = _rule_metadata(root)
    test_results = list(_iter_local(root, "TestResult"))
    test_result = test_results[-1] if test_results else root

    profile = (
        test_result.get("profile")
        or test_result.get("id")
        or profile_hint
        or "default"
    )
    explicit_score: float | None = None
    for element in test_result:
        if _local(element.tag) == "score":
            try:
                explicit_score = float((element.text or "").strip())
            except ValueError:
                explicit_score = None
            break

    findings: list[dict] = []
    passed = failed = 0
    for element in _iter_local(test_result, "rule-result"):
        rule_id = element.get("idref") or element.get("id")
        if not rule_id:
            continue
        result = (_child_text(element, "result") or "unknown").strip().lower()
        normalized = RESULT_ALIASES.get(result, "unknown")
        if normalized == "pass":
            passed += 1
        elif normalized == "fail":
            failed += 1
        rule = metadata.get(rule_id, {})
        findings.append(
            {
                "rule_id": rule_id,
                "title": rule.get("title") or rule_id,
                "result": normalized,
                "severity": element.get("severity") or rule.get("severity"),
                "description": rule.get("description"),
                "remediation": rule.get("remediation"),
            }
        )

    score = explicit_score
    if score is None:
        evaluated = passed + failed
        score = (passed / evaluated * 100) if evaluated else None

    return {
        "profile": profile,
        "score": round(score, 2) if score is not None else None,
        "passed": passed,
        "failed": failed,
        "findings": findings,
    }


def _out(scan: models.ComplianceScan) -> ComplianceScanOut:
    return ComplianceScanOut.model_validate(scan)


def serialize(scan: models.ComplianceScan, *, include_findings: bool = False):
    if include_findings:
        return ComplianceScanDetail(
            **_out(scan).model_dump(),
            findings=[
                ComplianceFindingOut.model_validate(item)
                for item in sorted(scan.findings, key=lambda item: item.id)
            ],
        )
    return _out(scan)


def read_artifact(path_value: str) -> bytes:
    settings = get_settings()
    root = settings.artifacts_dir.resolve()
    path = Path(path_value).resolve()
    if not path.is_relative_to(root):
        raise DomainError("artifact path is outside the configured artifact directory")
    if not path.exists() or not path.is_file():
        raise NotFoundError("OpenSCAP artifact not found")
    if path.stat().st_size > MAX_ARTIFACT_BYTES:
        raise DomainError("OpenSCAP artifact is too large")
    return path.read_bytes()


def ingest_scan(
    db: Session,
    *,
    host_name: str,
    content: str | bytes,
    profile: str | None = None,
    artifact_path: str | None = None,
) -> models.ComplianceScan:
    content_bytes = (
        content.encode("utf-8") if isinstance(content, str) else content
    )
    if len(content_bytes) > MAX_ARTIFACT_BYTES:
        raise DomainError("OpenSCAP result is too large")

    host = (
        db.query(models.Host).filter(models.Host.name == host_name).one_or_none()
    )
    if host is None:
        raise NotFoundError("host not found")

    parsed = parse_xccdf(content_bytes, profile_hint=profile)
    now = datetime.now(UTC)
    scan = models.ComplianceScan(
        id=str(uuid.uuid4()),
        host_id=host.id,
        host_name=host.name,
        profile=profile or parsed["profile"],
        status="completed",
        score=parsed["score"],
        started_at=now,
        finished_at=now,
        artifact_path=artifact_path,
    )
    scan.findings = [
        models.ComplianceFinding(**finding) for finding in parsed["findings"]
    ]
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def list_scans(
    db: Session,
    *,
    host_name: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[models.ComplianceScan]:
    query = db.query(models.ComplianceScan)
    if host_name:
        query = query.filter(models.ComplianceScan.host_name == host_name)
    return (
        query.order_by(models.ComplianceScan.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )


def get_scan(db: Session, scan_id: str) -> models.ComplianceScan:
    scan = db.get(models.ComplianceScan, scan_id)
    if scan is None:
        raise NotFoundError("compliance scan not found")
    return scan


def latest_for_host(db: Session, host_id: int) -> models.ComplianceScan | None:
    return (
        db.query(models.ComplianceScan)
        .filter(models.ComplianceScan.host_id == host_id)
        .order_by(models.ComplianceScan.created_at.desc())
        .first()
    )
