import os
import tempfile
import yaml
from config import Config
from services.validation_service import ValidationService

class InventoryService:
    @staticmethod
    def save_host_to_inventory(host_data):
        InventoryService._validate_host_data(host_data)
        env_dir = os.path.join(Config.INVENTORY_DIR, host_data['environment'])
        os.makedirs(env_dir, mode=0o700, exist_ok=True)

        inv_path = Config.get_inventory_path(host_data['environment'])
        inventory = InventoryService._read_inventory(inv_path)
        children = inventory['all']['children']

        raw_groups = host_data.get('groups', '')
        if not isinstance(raw_groups, str):
            raise ValueError("Liste de groupes invalide")
        groups = raw_groups.split(',') if raw_groups else []
        for group in groups:
            if not ValidationService.validate_group_name(group):
                raise ValueError("Nom de groupe invalide")
            if group not in children:
                children[group] = {'hosts': {}}
            if not isinstance(children[group], dict):
                raise ValueError(f"Groupe d'inventaire invalide: {group}")
            if 'hosts' not in children[group]:
                children[group]['hosts'] = {}
            if not isinstance(children[group]['hosts'], dict):
                raise ValueError(f"Liste d'hôtes invalide pour le groupe: {group}")

            children[group]['hosts'][host_data['name']] = {
                'ansible_host': host_data['ip'],
                'linsec_security_level': host_data['security_level']
            }

        InventoryService._write_inventory(inv_path, inventory)

    @staticmethod
    def remove_host_from_inventory(host_data):
        InventoryService._validate_host_data(host_data)
        inv_path = Config.get_inventory_path(host_data['environment'])
        if not os.path.exists(inv_path):
            return

        inventory = InventoryService._read_inventory(inv_path)

        host_name = host_data['name']
        for group in inventory['all']['children'].values():
            if host_name in group['hosts']:
                del group['hosts'][host_name]
        InventoryService._write_inventory(inv_path, inventory)

    @staticmethod
    def _validate_host_data(host_data):
        if not isinstance(host_data, dict):
            raise ValueError("Données d'hôte invalides pour l'inventaire")
        if (
            not ValidationService.validate_host_name(host_data.get('name'))
            or not ValidationService.validate_environment_name(
                host_data.get('environment')
            )
            or not ValidationService.validate_ip(host_data.get('ip'))
            or not ValidationService.validate_security_level(
                host_data.get('security_level')
            )
            or not isinstance(host_data.get('groups', ''), str)
        ):
            raise ValueError("Données d'hôte invalides pour l'inventaire")

    @staticmethod
    def _read_inventory(path):
        if not os.path.exists(path):
            return {'all': {'children': {}}}
        with open(path, 'r', encoding='utf-8') as inventory_file:
            inventory = yaml.safe_load(inventory_file) or {'all': {'children': {}}}
        if not isinstance(inventory, dict):
            raise ValueError("Fichier d'inventaire invalide")
        all_group = inventory.setdefault('all', {})
        if not isinstance(all_group, dict):
            raise ValueError("Structure de l'inventaire invalide")
        children = all_group.setdefault('children', {})
        if not isinstance(children, dict):
            raise ValueError("Groupes d'inventaire invalides")
        for group in children.values():
            if not isinstance(group, dict) or not isinstance(
                group.setdefault('hosts', {}),
                dict,
            ):
                raise ValueError("Entrée de groupe d'inventaire invalide")
        return inventory

    @staticmethod
    def _write_inventory(path, inventory):
        directory = os.path.dirname(path)
        descriptor, temporary_path = tempfile.mkstemp(
            prefix='.hosts-',
            suffix='.yml',
            dir=directory,
        )
        try:
            with os.fdopen(descriptor, 'w', encoding='utf-8') as inventory_file:
                yaml.safe_dump(
                    inventory,
                    inventory_file,
                    default_flow_style=False,
                    sort_keys=False,
                )
                inventory_file.flush()
                os.fsync(inventory_file.fileno())
            os.replace(temporary_path, path)
        except Exception:
            try:
                os.unlink(temporary_path)
            except FileNotFoundError:
                pass
            raise
