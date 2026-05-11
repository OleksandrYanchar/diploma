"""TOTP secret encryption utilities.

Provides a symmetric encrypt/decrypt pair for TOTP secrets stored in the
database.  Fernet (AES-128-CBC with HMAC-SHA256 authentication) is used
with a server-held key loaded from ``MFA_SECRET_ENCRYPTION_KEY``.

The raw Base32 TOTP secret is never written to the database — only the
Fernet-encrypted ciphertext is stored.  Decryption occurs only at the
point of TOTP verification, minimising the in-memory exposure window.

Security property enforced: SR-04 (TOTP secret stored encrypted at rest).
"""

from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken

__all__ = ["InvalidToken", "decrypt_mfa_secret", "encrypt_mfa_secret"]


def encrypt_mfa_secret(plaintext_secret: str, key: str) -> str:
    """Encrypt a Base32 TOTP secret and return a Fernet token string.

    Expects:
        plaintext_secret: the raw Base32-encoded TOTP secret to encrypt.
        key:              URL-safe base64-encoded 32-byte Fernet key from
                          ``settings.mfa_secret_encryption_key``.

    Returns a UTF-8 Fernet token (~140 chars) suitable for storage in
    ``users.mfa_secret``.

    Security property: Fernet tokens are authenticated (HMAC-SHA256) so
    ciphertext tampering is detected on decryption.
    """
    return Fernet(key.encode()).encrypt(plaintext_secret.encode()).decode()


def decrypt_mfa_secret(encrypted_secret: str, key: str) -> str:
    """Decrypt a Fernet-encrypted TOTP secret back to its Base32 plaintext.

    Expects:
        encrypted_secret: Fernet token string stored in ``users.mfa_secret``.
        key:              URL-safe base64-encoded 32-byte Fernet key from
                          ``settings.mfa_secret_encryption_key``.

    Returns the original Base32-encoded TOTP secret.

    Raises:
        cryptography.fernet.InvalidToken: if the token is corrupted, the key
            is wrong, or the stored value is not a valid Fernet token (e.g.
            a legacy plaintext secret written before encryption was added).
            Callers must treat this as an MFA configuration error requiring
            re-enrollment.
    """
    return Fernet(key.encode()).decrypt(encrypted_secret.encode()).decode()
