"""Compatibility layer for legacy imports.

This module is intentionally kept as a thin shim so older imports continue to work
while the actual implementation lives in the `services` package.
"""

from services.deployment_service import DeploymentService
from services.event_service import EventService
from services.inventory_service import InventoryService
from services.playbook_service import PlaybookService
from services.validation_service import ValidationService

__all__ = [
    "DeploymentService",
    "EventService",
    "InventoryService",
    "PlaybookService",
    "ValidationService",
]
