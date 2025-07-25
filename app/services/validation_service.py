class ValidationService:
    """Service pour valider les données"""

    @staticmethod
    def validate_ip(ip):
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        for part in parts:
            if not part.isdigit():
                return False
            num = int(part)
            if num < 0 or num > 255:
                return False
        return True

    @staticmethod
    def validate_playbook_name(filename):
        return filename and (filename.endswith('.yml') or filename.endswith('.yaml'))
