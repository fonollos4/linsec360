"""v1 API router aggregation."""

from fastapi import APIRouter

from . import audit, auth, deployments, hosts, kpis, playbooks

api_router = APIRouter()
api_router.include_router(auth.router)
api_router.include_router(hosts.router)
api_router.include_router(playbooks.router)
api_router.include_router(deployments.router)
api_router.include_router(kpis.router)
api_router.include_router(audit.router)
