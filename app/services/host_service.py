from repositories.host_repository import HostRepository
from repositories.stats_repository import StatsRepository
from services.inventory_service import InventoryService
from services.validation_service import ValidationService


class HostService:
    """Business logic for host lifecycle operations."""

    @staticmethod
    def list_hosts():
        return [dict(host) for host in HostRepository.list_all()]

    @staticmethod
    def create_host(host_data):
        if not isinstance(host_data, dict):
            raise ValueError("Données d'hôte invalides")
        if not ValidationService.validate_host_name(host_data.get("name")):
            raise ValueError("Nom d'hôte invalide")
        if not ValidationService.validate_ip(host_data.get("ip")):
            raise ValueError("Adresse IP invalide")
        if not ValidationService.validate_environment_name(host_data.get("environment")):
            raise ValueError("Environnement invalide")
        if not ValidationService.validate_security_level(host_data.get("security_level")):
            raise ValueError("Niveau de sécurité invalide")

        groups = host_data.get("groups", "")
        if not isinstance(groups, str):
            raise ValueError("Liste de groupes invalide")
        group_names = [group.strip() for group in groups.split(",") if group.strip()]
        if any(not ValidationService.validate_group_name(group) for group in group_names):
            raise ValueError("Nom de groupe invalide")
        host_data["groups"] = ",".join(dict.fromkeys(group_names))

        HostRepository.create(host_data)
        StatsRepository.refresh()
        InventoryService.save_host_to_inventory(host_data)

        return host_data

    @staticmethod
    def delete_host(host_id):
        host_data = HostRepository.delete(host_id)
        if not host_data:
            raise ValueError("Hôte non trouvé")

        StatsRepository.refresh()
        InventoryService.remove_host_from_inventory(host_data)
        return host_data
