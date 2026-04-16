"""Unit tests for app.core.totp.

Covers secret generation, code verification, and QR code export.
All tests are synchronous; no database or Redis state is required.
"""

from __future__ import annotations

import base64
import binascii

import pyotp

from app.core.totp import (
    generate_qr_code_base64,
    generate_totp_secret,
    verify_totp_code,
)

# ---------------------------------------------------------------------------
# generate_totp_secret
# ---------------------------------------------------------------------------


def test_generate_totp_secret_returns_nonempty_string() -> None:
    """Secret must be a non-empty string."""
    secret = generate_totp_secret()
    assert isinstance(secret, str)
    assert len(secret) > 0


def test_generate_totp_secret_is_valid_base32() -> None:
    """Secret must be valid Base32 — decodable without error."""
    secret = generate_totp_secret()
    # base64.b32decode raises binascii.Error if the input is not valid Base32.
    # casefold=True accepts both upper- and lower-case letters.
    try:
        base64.b32decode(secret, casefold=True)
    except binascii.Error as exc:
        raise AssertionError(f"Secret is not valid Base32: {exc}") from exc


# ---------------------------------------------------------------------------
# verify_totp_code
# ---------------------------------------------------------------------------


def test_verify_totp_code_valid_current_code_returns_true() -> None:
    """A code generated from the same secret must verify as True."""
    secret = generate_totp_secret()
    # Generate the current valid code using pyotp directly.
    current_code: str = pyotp.TOTP(secret).now()
    assert verify_totp_code(secret, current_code) is True


def test_verify_totp_code_wrong_code_returns_false() -> None:
    """A hardcoded wrong 6-digit code must verify as False."""
    secret = generate_totp_secret()
    # "000000" is an extremely unlikely valid TOTP code for any random secret
    # at any given moment, making this a reliable negative-case fixture.
    wrong_code = "000000"
    # On the astronomically rare chance "000000" is the current valid code,
    # fall back to "111111".  Both cannot be valid simultaneously.
    if pyotp.TOTP(secret).verify(wrong_code, valid_window=1):
        wrong_code = "111111"
    assert verify_totp_code(secret, wrong_code) is False


# ---------------------------------------------------------------------------
# generate_qr_code_base64
# ---------------------------------------------------------------------------


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
