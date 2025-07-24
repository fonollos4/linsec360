import os
from flask import current_app

class Config:
    """Configuration centralisée de l'application"""
    SECRET_KEY = os.environ.get('FLASK_SECRET', 'supersecretkey')
    
    # Répertoires
    INVENTORY_DIR = "/ansible/inventories"
    ANSIBLE_DIR = "/ansible"
    PLAYBOOKS_DIR = os.path.join(ANSIBLE_DIR, "playbooks")
    LOG_DIR = "/var/log/linsec"
    
    @staticmethod
    def get_database_path():
        """Retourne le chemin de la base de données"""
        return os.path.join(current_app.instance_path, 'linsec.db')
    
    @staticmethod
    def get_inventory_path(environment):
        """Retourne le chemin de l'inventaire pour un environnement"""
        return os.path.join(Config.INVENTORY_DIR, environment, 'hosts.yml')
    
    @staticmethod
    def get_playbook_path(playbook_name):
        """Retourne le chemin complet d'un playbook"""
        return os.path.join(Config.PLAYBOOKS_DIR, playbook_name)