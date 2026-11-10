"""Connection status and tests for external control planes."""

from __future__ import annotations

import logging
import shutil
import subprocess

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from .. import models
from ..config import get_settings
from ..db import get_db
from ..errors import IntegrationNotConfigured, IntegrationUnavailable
from ..schemas import (
    IntegrationState,
    IntegrationStatus,
    StackConfiguration,
    StackConfigurationUpdate,
)
from ..security import get_current_user, require_roles
from ..services import (
    audit_service,
    kpi_service,
    runtime_configuration_service,
    stack_service,
    uyuni_service,
    wazuh_service,
)

router = APIRouter(prefix="/integrations", tags=["integrations"])
logger = logging.getLogger(__name__)


@router.get("/status", response_model=IntegrationStatus)
def status(
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> IntegrationStatus:
    settings = runtime_configuration_service.effective_settings(db, get_settings())
    wazuh = IntegrationState(configured=settings.wazuh_configured)
    uyuni = IntegrationState(configured=settings.uyuni_configured)
    ansible = IntegrationState(
        configured=bool(settings.ansible_playbook_bin),
        available=shutil.which(settings.ansible_playbook_bin) is not None,
    )
    return IntegrationStatus(
        wazuh=wazuh,
        uyuni=uyuni,
        ansible=ansible,
        stack=stack_service.components(
            settings,
            wazuh=wazuh,
            uyuni=uyuni,
            ansible=ansible,
        ),
    )


@router.get("/config", response_model=StackConfiguration)
def get_configuration(
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> StackConfiguration:
    return runtime_configuration_service.read(db)


@router.put("/config", response_model=StackConfiguration)
def update_configuration(
    payload: StackConfigurationUpdate,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_roles("admin")),
) -> StackConfiguration:
    result = runtime_configuration_service.save(
        db,
        payload,
        updated_by_id=user.id,
    )
    audit_service.record(
        db,
        actor=user,
        action="integrations.config.update",
        target_type="integration_config",
        target_id="stack",
        data={"fields": sorted(payload.model_fields_set)},
        request=request,
    )
    db.commit()
    return result


@router.delete("/config", response_model=StackConfiguration)
def reset_configuration(
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_roles("admin")),
) -> StackConfiguration:
    result = runtime_configuration_service.reset(db)
    audit_service.record(
        db,
        actor=user,
        action="integrations.config.reset",
        target_type="integration_config",
        target_id="stack",
        request=request,
    )
    db.commit()
    return result


@router.post("/wazuh/test", response_model=IntegrationState)
def test_wazuh(
    db: Session = Depends(get_db),
    user: models.User = Depends(require_roles("admin", "operator")),
) -> IntegrationState:
    base_settings = get_settings()
    settings = runtime_configuration_service.effective_settings(db, base_settings)
    if not settings.wazuh_configured:
        return IntegrationState(configured=False, reachable=False)
    try:
        client = (
            wazuh_service.get_client()
            if settings is base_settings
            else wazuh_service.get_client(settings=settings)
        )
        agents = client.test_connection()
    except (IntegrationNotConfigured, IntegrationUnavailable) as exc:
        logger.warning("Wazuh API connectivity test failed: %s", exc)
        return IntegrationState(
            configured=True,
            reachable=False,
            detail=str(exc)[:300],
        )
    return IntegrationState(
        configured=True,
        reachable=True,
        detail=f"API accessible ; {agents} agent(s) Wazuh récupéré(s).",
    )


@router.post("/uyuni/test", response_model=IntegrationState)
def test_uyuni(
    db: Session = Depends(get_db),
    user: models.User = Depends(require_roles("admin", "operator")),
) -> IntegrationState:
    base_settings = get_settings()
    settings = runtime_configuration_service.effective_settings(db, base_settings)
    if not settings.uyuni_configured:
        return IntegrationState(configured=False, reachable=False)
    try:
        client = (
            uyuni_service.get_client()
            if settings is base_settings
            else uyuni_service.get_client(settings=settings)
        )
        systems = client.test_connection()
    except (IntegrationNotConfigured, IntegrationUnavailable) as exc:
        logger.warning("Uyuni XML-RPC connectivity test failed: %s", exc)
        return IntegrationState(
            configured=True,
            reachable=False,
            detail=str(exc)[:300],
        )
    return IntegrationState(
        configured=True,
        reachable=True,
        detail=f"XML-RPC accessible ; {systems} système(s) Uyuni récupéré(s).",
    )


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
    settings = runtime_configuration_service.effective_settings(db)
    client = wazuh_service.get_client(settings=settings)
    agents = wazuh_service.sync_agents(db, client=client)
    alerts = wazuh_service.sync_alerts(db, client=client)
    vulnerabilities = wazuh_service.sync_vulnerabilities(db, client=client)
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
