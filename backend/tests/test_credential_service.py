import pytest

from backend.errors import IntegrationUnavailable
from backend.services import credential_service


def test_password_encryption_round_trips_without_plaintext_storage():
    password = "temporary-SSH-and-sudo-password"

    encrypted = credential_service.encrypt_password(password)

    assert password not in encrypted
    assert credential_service.decrypt_password(encrypted) == password


def test_password_decryption_rejects_tampered_ciphertext():
    encrypted = credential_service.encrypt_password("temporary-password")
    tampered = ("A" if encrypted[10] != "A" else "B") + encrypted[1:]

    with pytest.raises(IntegrationUnavailable, match="could not be decrypted"):
        credential_service.decrypt_password(tampered)
