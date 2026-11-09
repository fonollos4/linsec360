"""Host inventory endpoints."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from .. import models
from ..config import get_settings
from ..db import get_db
from ..errors import ConflictError
from ..schemas import (
    AgentOut,
    HardeningCheckOut,
    HostCreate,
    HostImportOut,
    HostImportRequest,
    HostOut,
    HostPosture,
    HostUpdate,
    Message,
    PatchFindingOut,
    SSHFingerprintApproval,
    SSHPublicKeyOut,
    SSHTestOut,
)
from ..security import get_current_user, require_roles
from ..services import (
    hardening_service,
    host_service,
    livepatch_service,
    oscap_service,
    patch_service,
    ssh_service,
    wazuh_service,
)

router = APIRouter(prefix="/hosts", tags=["hosts"])


@router.get("/ssh/public-key", response_model=SSHPublicKeyOut)
def get_ansible_public_key(
    user: models.User = Depends(get_current_user),
) -> SSHPublicKeyOut:
    key = ssh_service.public_key()
    return SSHPublicKeyOut(
        public_key=key,
        private_key_path="/opt/linsec/.ssh/id_ed25519",
    )


@router.get("", response_model=list[HostOut])
def list_hosts(
    environment: str | None = None,
    status: str | None = None,
    q: str | None = None,
    limit: int = Query(default=200, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> list[HostOut]:
    hosts = host_service.list_hosts(
        db,
        environment=environment,
        status=status,
        query=q,
        limit=limit,
        offset=offset,
    )
    return [host_service.serialize(host) for host in hosts]


@router.post("", response_model=HostOut, status_code=201)
def create_host(
    payload: HostCreate,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_roles("admin", "operator")),
) -> HostOut:
    host = host_service.create_host(db, payload=payload, actor=user, request=request)
    return host_service.serialize(host)


@router.post("/import", response_model=HostImportOut)
def import_hosts(
    payload: HostImportRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_roles("admin", "operator")),
) -> HostImportOut:
    imported: list[HostOut] = []
    failed = []
    for row, host_payload in enumerate(payload.hosts, start=2):
        try:
            host = host_service.create_host(
                db, payload=host_payload, actor=user, request=request
            )
        except ConflictError as exc:
            failed.append(
                {"row": row, "name": host_payload.name, "detail": exc.message}
            )
        else:
            imported.append(host_service.serialize(host))
    return HostImportOut(imported=imported, failed=failed)


@router.get("/{host_id}", response_model=HostOut)
def get_host(
    host_id: int,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> HostOut:
    return host_service.serialize(host_service.get_host(db, host_id))


@router.get("/{host_id}/posture", response_model=HostPosture)
def get_host_posture(
    host_id: int,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> HostPosture:
    host = host_service.get_host(db, host_id)
    scan = oscap_service.latest_for_host(db, host.id)
    checks = hardening_service.host_checks(db, host.id)
    findings = patch_service.list_findings(db, host_name=host.name, limit=200)
    livepatch = livepatch_service.latest_for_host(db, host.id)

    agent: AgentOut | None = None
    if get_settings().wazuh_configured:
        try:
            for item in wazuh_service.get_client().list_agents():
                if item["id"] == host.agent_id or item["name"] == host.name:
                    agent = AgentOut(**item, host_id=host.id)
                    break
        except Exception:
            agent = None

    return HostPosture(
        host_id=host.id,
        host_name=host.name,
        compliance=oscap_service.serialize(scan) if scan else None,
        hardening=[
            HardeningCheckOut.model_validate(check) for check in checks
        ],
        patch_findings=[
            PatchFindingOut.model_validate(finding) for finding in findings
        ],
        livepatch=(
            livepatch_service.serialize(livepatch) if livepatch else None
        ),
        agent=agent,
    )


@router.patch("/{host_id}", response_model=HostOut)
def update_host(
    host_id: int,
    payload: HostUpdate,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_roles("admin", "operator")),
) -> HostOut:
    host = host_service.get_host(db, host_id)
    host = host_service.update_host(
        db, host=host, payload=payload, actor=user, request=request
    )
    return host_service.serialize(host)


@router.post("/{host_id}/ssh/accept-fingerprint", response_model=SSHTestOut)
def accept_host_ssh_fingerprint(
    host_id: int,
    payload: SSHFingerprintApproval,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_roles("admin")),
) -> SSHTestOut:
    host = host_service.get_host(db, host_id)
    scanned = ssh_service.scan_host_key(host.ip, host.ansible_port)
    if scanned is None:
        raise ConflictError("unable to determine the SSH host fingerprint")
    _, current_fingerprint = scanned
    if current_fingerprint != payload.fingerprint:
        raise ConflictError(
            "live SSH fingerprint differs from the out-of-band verified fingerprint"
        )
    previous = host.ssh_fingerprint
    host.ssh_fingerprint = payload.fingerprint
    host.ssh_status = "pending"
    host.ssh_error = None
    db.commit()

    from ..services import audit_service

    audit_service.record(
        db,
        actor=user,
        action="host.ssh_fingerprint_accept",
        target_type="host",
        target_id=host.id,
        data={"previous": previous, "accepted": payload.fingerprint},
        request=request,
    )
    db.commit()
    return SSHTestOut(
        reachable=False,
        ssh_status="pending",
        fingerprint=payload.fingerprint,
        fingerprint_changed=False,
        message="Verified SSH fingerprint saved; run the SSH connection test again",
    )


@router.post("/{host_id}/ssh/test", response_model=SSHTestOut)
def test_host_ssh(
    host_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_roles("admin", "operator")),
) -> SSHTestOut:
    host = host_service.get_host(db, host_id)
    scanned = ssh_service.scan_host_key(host.ip, host.ansible_port)
    if scanned is None:
        host.ssh_status = "failed"
        host.ssh_error = "Unable to scan SSH fingerprint; connection was not attempted"
        host.last_ssh_test_at = datetime.now(UTC)
        db.commit()
        db.refresh(host)
        return SSHTestOut(
            reachable=False,
            ssh_status=host.ssh_status,
            fingerprint=None,
            message=host.ssh_error,
        )
    known_hosts_entry, fingerprint = scanned
    if host.ssh_fingerprint is None:
        host.ssh_status = "fingerprint_pending"
        host.ssh_error = None
        host.last_ssh_test_at = datetime.now(UTC)
        db.commit()
        db.refresh(host)
        from ..services import audit_service

        audit_service.record(
            db,
            actor=user,
            action="host.ssh_fingerprint_discovered",
            target_type="host",
            target_id=host.id,
            data={"fingerprint": fingerprint},
            request=request,
        )
        db.commit()
        return SSHTestOut(
            reachable=False,
            ssh_status=host.ssh_status,
            fingerprint=fingerprint,
            fingerprint_changed=False,
            message=(
                "Fingerprint discovered; compare it with a trusted source, "
                "then approve the exact value"
            ),
        )
    changed = bool(
        host.ssh_fingerprint != fingerprint
    )
    if changed:
        host.ssh_status = "fingerprint_changed"
        host.ssh_error = "SSH host fingerprint changed; approval required"
        host.last_ssh_test_at = datetime.now(UTC)
        db.commit()
        db.refresh(host)
        from ..services import audit_service

        audit_service.record(
            db,
            actor=user,
            action="host.ssh_fingerprint_changed",
            target_type="host",
            target_id=host.id,
            data={"previous": host.ssh_fingerprint, "current": fingerprint},
            request=request,
        )
        db.commit()
        return SSHTestOut(
            reachable=False,
            ssh_status=host.ssh_status,
            fingerprint=fingerprint,
            fingerprint_changed=True,
            message="Fingerprint changed; SSH connection blocked",
        )

    reachable, output, message = ssh_service.test_connection(
        host_name=host.name,
        ip=host.ip,
        ansible_user=host.ansible_user,
        ansible_port=host.ansible_port,
        known_hosts_entry=known_hosts_entry,
    )
    host.last_ssh_test_at = datetime.now(UTC)
    host.ssh_status = "reachable" if reachable else "failed"
    host.ssh_error = None if reachable else output[:512]
    if reachable and fingerprint:
        host.ssh_fingerprint = fingerprint
    db.commit()
    db.refresh(host)

    from ..services import audit_service

    audit_service.record(
        db,
        actor=user,
        action="host.ssh_test",
        target_type="host",
        target_id=host.id,
        data={"reachable": reachable, "fingerprint": fingerprint},
        request=request,
    )
    db.commit()
    return SSHTestOut(
        reachable=reachable,
        ssh_status=host.ssh_status,
        fingerprint=fingerprint,
        fingerprint_changed=False,
        message=message if reachable else output[:2000],
    )


@router.delete("/{host_id}", response_model=Message)
def delete_host(
    host_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_roles("admin")),
) -> Message:
    host = host_service.get_host(db, host_id)
    name = host.name
    host_service.delete_host(db, host=host, actor=user, request=request)
    return Message(message=f"host {name} deleted")
