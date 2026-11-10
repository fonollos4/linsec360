"""Encrypt host credentials before they are stored in the database."""

from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken

from ..config import get_settings
from ..errors import IntegrationUnavailable


def _fernet() -> Fernet:
    key = get_settings().credential_encryption_key
    if key is None:
        raise IntegrationUnavailable(
            "host credential encryption is not configured"
        )
    try:
        return Fernet(key.get_secret_value().encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise IntegrationUnavailable(
            "host credential encryption key is invalid"
        ) from exc


def encrypt_password(password: str) -> str:
    return _fernet().encrypt(password.encode("utf-8")).decode("ascii")


def decrypt_password(encrypted_password: str) -> str:
    try:
        return _fernet().decrypt(encrypted_password.encode("ascii")).decode("utf-8")
    except (InvalidToken, UnicodeDecodeError, ValueError) as exc:
        raise IntegrationUnavailable(
            "stored host credentials could not be decrypted; check the encryption key"
        ) from exc
