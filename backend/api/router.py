"""v1 API router aggregation."""

from fastapi import APIRouter

from . import (
    agents,
    alerts,
    audit,
    auth,
    compliance,
    deployments,
    hardening,
    hosts,
    integrations,
    kpis,
    operations,
    patching,
    playbooks,
    tokens,
)

api_router = APIRouter()
api_router.include_router(auth.router)
api_router.include_router(tokens.router)
api_router.include_router(hosts.router)
api_router.include_router(playbooks.router)
api_router.include_router(deployments.router)
api_router.include_router(kpis.router)
api_router.include_router(audit.router)
api_router.include_router(agents.router)
api_router.include_router(alerts.router)
api_router.include_router(compliance.router)
api_router.include_router(patching.router)
api_router.include_router(hardening.router)
api_router.include_router(integrations.router)
api_router.include_router(operations.router)
