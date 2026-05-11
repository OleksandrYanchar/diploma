"""Unit tests for app.core.totp and app.core.mfa_encryption."""

import base64
import binascii

import pyotp
import pytest
from cryptography.fernet import Fernet, InvalidToken

from app.core.mfa_encryption import decrypt_mfa_secret, encrypt_mfa_secret
from app.core.totp import (
    generate_qr_code_base64,
    generate_totp_secret,
    verify_totp_code,
)

_TEST_KEY: str = Fernet.generate_key().decode()


def test_generate_totp_secret_returns_nonempty_string() -> None:
    """Secret must be a non-empty string."""
    secret = generate_totp_secret()
    assert isinstance(secret, str)
    assert len(secret) > 0


def test_generate_totp_secret_is_valid_base32() -> None:
    """Secret must be valid Base32 — decodable without error."""
    secret = generate_totp_secret()
    try:
        base64.b32decode(secret, casefold=True)
    except binascii.Error as exc:
        raise AssertionError(f"Secret is not valid Base32: {exc}") from exc


def test_verify_totp_code_valid_current_code_returns_true() -> None:
    """A code generated from the same secret must verify as True."""
    secret = generate_totp_secret()
    current_code: str = pyotp.TOTP(secret).now()
    assert verify_totp_code(secret, current_code) is True


def test_verify_totp_code_wrong_code_returns_false() -> None:
    """A wrong 6-digit code must verify as False."""
    secret = generate_totp_secret()
    wrong_code = "000000"
    # Both "000000" and "111111" cannot be valid simultaneously.
    if pyotp.TOTP(secret).verify(wrong_code, valid_window=1):
        wrong_code = "111111"
    assert verify_totp_code(secret, wrong_code) is False


def test_generate_qr_code_base64_returns_nonempty_string() -> None:
    """QR output must be a non-empty string."""
    secret = generate_totp_secret()
    result = generate_qr_code_base64(secret, "user@example.com", "TestIssuer")
    assert isinstance(result, str)
    assert len(result) > 0


def test_generate_qr_code_base64_is_valid_base64() -> None:
    """QR output must be decodable as standard Base64."""
    secret = generate_totp_secret()
    result = generate_qr_code_base64(secret, "user@example.com", "TestIssuer")
    try:
        base64.b64decode(result, validate=True)
    except binascii.Error as exc:
        raise AssertionError(f"Output is not valid Base64: {exc}") from exc


def test_generate_qr_code_base64_decoded_bytes_are_png() -> None:
    """Decoded Base64 bytes must begin with the PNG magic bytes."""
    png_magic = b"\x89PNG"
    secret = generate_totp_secret()
    result = generate_qr_code_base64(secret, "user@example.com", "TestIssuer")
    decoded = base64.b64decode(result)
    assert (
        decoded[:4] == png_magic
    ), f"Expected PNG magic bytes {png_magic!r}, got {decoded[:4]!r}"


# ---------------------------------------------------------------------------
# mfa_encryption — encrypt / decrypt round-trip tests (TD-09, SR-04)
# ---------------------------------------------------------------------------


def test_encrypt_mfa_secret_returns_string() -> None:
    """encrypt_mfa_secret must return a non-empty string."""
    secret = generate_totp_secret()
    ciphertext = encrypt_mfa_secret(secret, _TEST_KEY)
    assert isinstance(ciphertext, str)
    assert len(ciphertext) > 0


def test_encrypt_mfa_secret_is_not_plaintext() -> None:
    """The encrypted value must differ from the original Base32 secret (SR-04)."""
    secret = generate_totp_secret()
    ciphertext = encrypt_mfa_secret(secret, _TEST_KEY)
    assert ciphertext != secret, "Ciphertext must not equal the plaintext secret"


def test_decrypt_mfa_secret_round_trip() -> None:
    """Decrypt(Encrypt(secret)) must equal the original secret."""
    secret = generate_totp_secret()
    ciphertext = encrypt_mfa_secret(secret, _TEST_KEY)
    recovered = decrypt_mfa_secret(ciphertext, _TEST_KEY)
    assert recovered == secret


def test_decrypt_with_wrong_key_raises_invalid_token() -> None:
    """Decrypting with the wrong key must raise InvalidToken."""
    secret = generate_totp_secret()
    ciphertext = encrypt_mfa_secret(secret, _TEST_KEY)
    wrong_key = Fernet.generate_key().decode()
    with pytest.raises(InvalidToken):
        decrypt_mfa_secret(ciphertext, wrong_key)


def test_decrypt_plaintext_raises_invalid_token() -> None:
    """Passing a raw Base32 secret to decrypt must raise InvalidToken.

    This guards against accidentally passing a legacy plaintext value
    written before encryption was introduced.
    """
    secret = generate_totp_secret()
    with pytest.raises(InvalidToken):
        decrypt_mfa_secret(secret, _TEST_KEY)


def test_encrypted_secret_passes_totp_verify_after_decrypt() -> None:
    """The encrypt → decrypt → verify round-trip must return True for a current code."""
    secret = generate_totp_secret()
    ciphertext = encrypt_mfa_secret(secret, _TEST_KEY)
    recovered = decrypt_mfa_secret(ciphertext, _TEST_KEY)
    current_code = pyotp.TOTP(secret).now()
    assert verify_totp_code(recovered, current_code) is True
