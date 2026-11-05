import os
from config import Config
from services.validation_service import ValidationService

class PlaybookService:
    @staticmethod
    def get_playbook(filename):
        if not ValidationService.validate_playbook_name(filename):
            raise ValueError("Nom de playbook invalide")
        filepath = Config.get_playbook_path(filename)
        if not os.path.isfile(filepath) or os.path.islink(filepath):
            raise ValueError("Playbook non trouvé")
        try:
            with open(filepath, "r", encoding="utf-8") as playbook_file:
                return playbook_file.read()
        except UnicodeDecodeError as exc:
            raise ValueError("Le playbook n'est pas un fichier texte valide") from exc

    @staticmethod
    def list_playbooks():
        os.makedirs(Config.PLAYBOOKS_DIR, exist_ok=True)
        return sorted(
            filename
            for filename in os.listdir(Config.PLAYBOOKS_DIR)
            if (
                ValidationService.validate_playbook_name(filename)
                and os.path.isfile(os.path.join(Config.PLAYBOOKS_DIR, filename))
                and not os.path.islink(os.path.join(Config.PLAYBOOKS_DIR, filename))
            )
        )

    @staticmethod
    def create_playbook(filename, content):
        if not ValidationService.validate_playbook_name(filename):
            raise ValueError("Nom de playbook invalide")
        if not isinstance(content, str):
            raise ValueError("Le contenu du playbook doit être du texte")
        filepath = Config.get_playbook_path(filename)
        try:
            descriptor = os.open(
                filepath,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
        except FileExistsError as exc:
            raise ValueError("Le playbook existe déjà") from exc
        with os.fdopen(descriptor, 'w') as playbook_file:
            playbook_file.write(content)

    @staticmethod
    def update_playbook(filename, content):
        if not ValidationService.validate_playbook_name(filename):
            raise ValueError("Nom de playbook invalide")
        if not isinstance(content, str):
            raise ValueError("Le contenu du playbook doit être du texte")
        filepath = Config.get_playbook_path(filename)
        if not os.path.isfile(filepath) or os.path.islink(filepath):
            raise ValueError("Playbook non trouvé")
        descriptor = os.open(
            filepath,
            os.O_WRONLY | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, 'w') as playbook_file:
            playbook_file.write(content)

    @staticmethod
    def delete_playbook(filename):
        if not ValidationService.validate_playbook_name(filename):
            raise ValueError("Nom de playbook invalide")
        filepath = Config.get_playbook_path(filename)
        if not os.path.exists(filepath):
            raise ValueError("Playbook non trouvé")
        os.remove(filepath)
