import ipaddress
import re


class ValidationService:
    """Validate values before they reach inventory or playbook files."""

    IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}\Z")
    PLAYBOOK_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]*\.ya?ml\Z")

    @staticmethod
    def validate_ip(ip):
        if not isinstance(ip, str):
            return False
        try:
            return isinstance(ipaddress.ip_address(ip), ipaddress.IPv4Address)
        except ValueError:
            return False

    @staticmethod
    def validate_host_name(name):
        return ValidationService._validate_identifier(name)

    @staticmethod
    def validate_environment_name(environment):
        return ValidationService._validate_identifier(environment)

    @staticmethod
    def validate_group_name(group):
        return ValidationService._validate_identifier(group)

    @staticmethod
    def validate_security_level(level):
        return isinstance(level, str) and level in {
            "low",
            "medium",
            "high",
            "critical",
        }

    @staticmethod
    def validate_playbook_name(filename):
        return (
            isinstance(filename, str)
            and ValidationService.PLAYBOOK_PATTERN.fullmatch(filename) is not None
        )

    @staticmethod
    def _validate_identifier(value):
        return (
            isinstance(value, str)
            and ValidationService.IDENTIFIER_PATTERN.fullmatch(value) is not None
        )
