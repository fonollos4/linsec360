import os
from flask import current_app

class Config:
    """Configuration centralisée de l'application"""
    SECRET_KEY = os.environ.get('FLASK_SECRET', 'development-secret')
    DATABASE_PATH = os.environ.get('LINSEC_DB_PATH')
    ANSIBLE_DIR = os.environ.get('LINSEC_ANSIBLE_DIR', '/opt/linsec/taskengine')
    INVENTORY_DIR = os.environ.get(
        'LINSEC_INVENTORY_DIR',
        os.path.join(ANSIBLE_DIR, 'inventories')
    )
    PLAYBOOKS_DIR = os.environ.get(
        'LINSEC_PLAYBOOKS_DIR',
        os.path.join(ANSIBLE_DIR, 'playbooks')
    )
    LOG_DIR = os.environ.get('LINSEC_LOG_DIR', '/opt/linsec/logs')
    LOG_API_TOKEN = os.environ.get('LINSEC_LOG_API_TOKEN')
    
    @staticmethod
    def get_database_path():
        """Retourne le chemin de la base de données"""
        return current_app.config.get('DATABASE_PATH') or os.path.join(
            current_app.instance_path,
            'linsec.db'
        )
    
    @staticmethod
    def get_inventory_path(environment):
        """Retourne le chemin de l'inventaire pour un environnement"""
        return os.path.join(Config.INVENTORY_DIR, environment, 'hosts.yml')
    
    @staticmethod
    def get_playbook_path(playbook_name):
        """Retourne le chemin complet d'un playbook"""
        return os.path.join(Config.PLAYBOOKS_DIR, playbook_name)