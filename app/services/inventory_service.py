import os
import yaml
from config import Config
from flask import current_app

class InventoryService:
    @staticmethod
    def save_host_to_inventory(host_data):
        env_dir = os.path.join(Config.INVENTORY_DIR, host_data['environment'])
        os.makedirs(env_dir, exist_ok=True)

        inv_path = Config.get_inventory_path(host_data['environment'])
        inventory = {'all': {'children': {}}}
        if os.path.exists(inv_path):
            with open(inv_path, 'r') as f:
                existing = yaml.safe_load(f)
                if existing:
                    inventory = existing

        if 'children' not in inventory['all']:
            inventory['all']['children'] = {}

        groups = host_data['groups'].split(',') if host_data['groups'] else []
        for group in groups:
            if group not in inventory['all']['children']:
                inventory['all']['children'][group] = {'hosts': {}}
            if 'hosts' not in inventory['all']['children'][group]:
                inventory['all']['children'][group]['hosts'] = {}

            inventory['all']['children'][group]['hosts'][host_data['name']] = {
                'ansible_host': host_data['ip'],
                'linsec_security_level': host_data['security_level']
            }

        with open(inv_path, 'w') as f:
            yaml.safe_dump(inventory, f, default_flow_style=False, sort_keys=False)

    @staticmethod
    def remove_host_from_inventory(host_data):
        inv_path = Config.get_inventory_path(host_data['environment'])
        if not os.path.exists(inv_path):
            return

        try:
            with open(inv_path, 'r') as f:
                inventory = yaml.safe_load(f) or {'all': {'children': {}}}

            host_name = host_data['name']
            for group in inventory['all']['children'].values():
                if 'hosts' in group and host_name in group['hosts']:
                    del group['hosts'][host_name]


            with open(inv_path, 'w') as f:
                yaml.safe_dump(inventory, f, default_flow_style=False, sort_keys=False)
        except Exception as e:
            current_app.logger.error(f"Erreur lors de la suppression de l'hôte: {str(e)}")
