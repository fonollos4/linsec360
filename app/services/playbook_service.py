import os
from config import Config
from services.validation_service import ValidationService

class PlaybookService:
    @staticmethod
    def list_playbooks():
        os.makedirs(Config.PLAYBOOKS_DIR, exist_ok=True)
        return [
            f for f in os.listdir(Config.PLAYBOOKS_DIR)
            if f.endswith('.yml') or f.endswith('.yaml')
        ]

    @staticmethod
    def create_playbook(filename, content):
        if not ValidationService.validate_playbook_name(filename):
            raise ValueError("Le nom du fichier doit se terminer par .yml ou .yaml")
        filepath = Config.get_playbook_path(filename)
        if os.path.exists(filepath):
            raise ValueError("Le playbook existe déjà")
        with open(filepath, 'w') as f:
            f.write(content)

    @staticmethod
    def update_playbook(filename, content):
        if not ValidationService.validate_playbook_name(filename):
            raise ValueError("Nom de playbook invalide")
        filepath = Config.get_playbook_path(filename)
        if not os.path.exists(filepath):
            raise ValueError("Playbook non trouvé")
        with open(filepath, 'w') as f:
            f.write(content)

    @staticmethod
    def delete_playbook(filename):
        if not ValidationService.validate_playbook_name(filename):
            raise ValueError("Nom de playbook invalide")
        filepath = Config.get_playbook_path(filename)
        if not os.path.exists(filepath):
            raise ValueError("Playbook non trouvé")
        os.remove(filepath)
