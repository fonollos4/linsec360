"""Encrypt host credentials before they are stored in the database."""

from __future__ import annotations

import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken

from ..config import get_settings
from ..errors import IntegrationUnavailable


def normalize_key(key: str) -> str:
    """Accept both padded and unpadded url-safe base64 representations."""
    value = key.strip()
    if len(value) == 43 and not value.endswith("="):
        return value + "="
    return value


def fernet_for_key(key: str) -> Fernet:
    try:
        return Fernet(normalize_key(key).encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise IntegrationUnavailable(
            "host credential encryption key is invalid"
        ) from exc


def key_fingerprint(key: str) -> str:
    """Non-secret identifier for the key that encrypted a stored blob."""
    raw = base64.urlsafe_b64decode(normalize_key(key).encode("ascii"))
    return hashlib.sha256(raw).hexdigest()[:16]


def _fernet() -> Fernet:
    key = get_settings().credential_encryption_key
    if key is None or not key.get_secret_value().strip():
        raise IntegrationUnavailable(
            "host credential encryption is not configured"
        )
    return fernet_for_key(key.get_secret_value())


def encrypt_secret(secret: str) -> str:
    """Encrypt any operator-supplied secret with the platform Fernet key."""
    return _fernet().encrypt(secret.encode("utf-8")).decode("ascii")


def decrypt_secret(encrypted_secret: str) -> str:
    try:
        return _fernet().decrypt(encrypted_secret.encode("ascii")).decode("utf-8")
    except (InvalidToken, UnicodeDecodeError, ValueError) as exc:
        raise IntegrationUnavailable(
            "stored secret could not be decrypted; check the encryption key"
        ) from exc


def encrypt_password(password: str) -> str:
    return encrypt_secret(password)


def decrypt_password(encrypted_password: str) -> str:
    try:
        return decrypt_secret(encrypted_password)
    except IntegrationUnavailable as exc:
        # Keep the host-specific message used by the credential recovery CLI.
        raise IntegrationUnavailable(
            "stored host credentials could not be decrypted; check the encryption key"
        ) from exc


def decrypt_password_with_key(encrypted_password: str, key: str) -> str:
    """Try an operator-supplied previous key without changing settings."""
    try:
        return (
            fernet_for_key(key)
            .decrypt(encrypted_password.encode("ascii"))
            .decode("utf-8")
        )
    except (InvalidToken, UnicodeDecodeError, ValueError) as exc:
        raise IntegrationUnavailable(
            "stored host credentials could not be decrypted with the supplied key"
        ) from exc


def password_status(encrypted_password: str | None) -> str:
    """Return a non-secret status for a stored credential blob."""
    if not encrypted_password:
        return "not_configured"
    try:
        decrypt_password(encrypted_password)
    except IntegrationUnavailable:
        return "undecryptable"
    return "ok"
