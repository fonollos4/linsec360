"""Connection status and tests for external control planes."""

from __future__ import annotations

import shutil
import subprocess

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from .. import models
from ..config import get_settings
from ..db import get_db
from ..schemas import IntegrationState, IntegrationStatus
from ..security import get_current_user, require_roles
from ..services import (
    audit_service,
    kpi_service,
    uyuni_service,
    wazuh_service,
)

router = APIRouter(prefix="/integrations", tags=["integrations"])


@router.get("/status", response_model=IntegrationStatus)
def status(user: models.User = Depends(get_current_user)) -> IntegrationStatus:
    settings = get_settings()
    return IntegrationStatus(
        wazuh=IntegrationState(configured=settings.wazuh_configured),
        uyuni=IntegrationState(configured=settings.uyuni_configured),
        ansible=IntegrationState(
            configured=bool(settings.ansible_playbook_bin),
            available=shutil.which(settings.ansible_playbook_bin) is not None,
        ),
    )


@router.post("/wazuh/test", response_model=IntegrationState)
def test_wazuh(
    user: models.User = Depends(require_roles("admin", "operator")),
) -> IntegrationState:
    settings = get_settings()
    if not settings.wazuh_configured:
        return IntegrationState(configured=False, reachable=False)
    try:
        wazuh_service.get_client().test_connection()
    except Exception:
        return IntegrationState(
            configured=True, reachable=False,
            detail="Le test de connexion Wazuh a échoué.",
        )
    return IntegrationState(configured=True, reachable=True)


@router.post("/uyuni/test", response_model=IntegrationState)
def test_uyuni(
    user: models.User = Depends(require_roles("admin", "operator")),
) -> IntegrationState:
    settings = get_settings()
    if not settings.uyuni_configured:
        return IntegrationState(configured=False, reachable=False)
    try:
        uyuni_service.get_client().test_connection()
    except Exception:
        return IntegrationState(
            configured=True, reachable=False,
            detail="Le test de connexion Uyuni a échoué.",
        )
    return IntegrationState(configured=True, reachable=True)


@router.post("/ansible/test", response_model=IntegrationState)
def test_ansible(
    user: models.User = Depends(require_roles("admin", "operator")),
) -> IntegrationState:
    settings = get_settings()
    binary = shutil.which(settings.ansible_playbook_bin)
    if binary is None:
        return IntegrationState(
            configured=bool(settings.ansible_playbook_bin),
            available=False,
            reachable=False,
            detail="ansible-playbook est introuvable dans l'environnement de l'API.",
        )
    try:
        result = subprocess.run(
            [binary, "--version"],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return IntegrationState(
            configured=True,
            available=True,
            reachable=False,
            detail="Le test de version Ansible a dépassé le délai de 3 secondes.",
        )
    except OSError:
        return IntegrationState(
            configured=True,
            available=False,
            reachable=False,
            detail="Impossible de lancer ansible-playbook dans l'environnement de l'API.",
        )
    if result.returncode != 0:
        return IntegrationState(
            configured=True,
            available=True,
            reachable=False,
            detail="La vérification de version Ansible a échoué.",
        )
    version = next(
        (line.strip() for line in result.stdout.splitlines() if line.strip()),
        "Ansible installé",
    )
    return IntegrationState(
        configured=True, available=True, reachable=True, detail=version[:200]
    )


@router.post("/wazuh/sync")
def sync_wazuh(
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_roles("admin", "operator")),
) -> dict:
    agents = wazuh_service.sync_agents(db)
    alerts = wazuh_service.sync_alerts(db)
    vulnerabilities = wazuh_service.sync_vulnerabilities(db)
    result = {
        "agents": agents,
        "alerts": alerts,
        "vulnerabilities": vulnerabilities,
    }
    audit_service.record(
        db,
        actor=user,
        action="integrations.wazuh.sync",
        target_type="integration",
        target_id="wazuh",
        data=result,
        request=request,
    )
    db.commit()
    kpi_service.capture_snapshot(db)
    return result
