"""TOTP utility module.

Provides the three cryptographic primitives needed for TOTP-based MFA:
secret generation, code verification, and QR code export.

This module has no side effects, no I/O, and no business logic.
It is a thin wrapper over pyotp and qrcode that enforces consistent
security parameters across the codebase.
"""

import base64
import io

import pyotp
import qrcode


def generate_totp_secret() -> str:
    """Generate a cryptographically random TOTP secret.

    Returns: a Base32-encoded string produced by pyotp.random_base32(),
    which uses os.urandom internally, providing 160 bits of entropy
    (20 bytes) encoded as a 32-character Base32 string — sufficient
    for RFC 6238 TOTP.

    Security property: the secret is unique per call and unpredictable;
    it must be stored encrypted (or hashed-encrypted) at rest and never
    returned to the client after initial setup.
    """
    return pyotp.random_base32()


def verify_totp_code(secret: str, code: str) -> bool:
    """Verify a user-supplied TOTP code against the stored secret.

    Expects:
        secret: the Base32-encoded TOTP secret associated with the user.
        code:   the 6-digit code submitted by the user.

    Returns True if the code matches the current or adjacent 30-second
    window (valid_window=1 allows one window before and one after the
    current window to accommodate clock skew of up to 30 seconds).

    Security property: uses pyotp's constant-time HMAC comparison, so
    this function is not vulnerable to timing attacks.

    RESIDUAL REPLAY RISK: valid_window=1 means a code remains valid for
    up to ~90 seconds (one window before + current + one window after).
    Within that window a captured code can be replayed. To eliminate this
    risk entirely, record the last accepted code and reject any reuse of
    the same (secret, code, window-timestamp) tuple — this is deferred to
    the MFA service layer, which has access to the Redis store.
    """
    return pyotp.TOTP(secret).verify(code, valid_window=1)


def generate_qr_code_base64(secret: str, email: str, issuer: str) -> str:
    """Build a TOTP provisioning URI and return it as a base64-encoded PNG.

    Expects:
        secret: the Base32-encoded TOTP secret to encode in the URI.
        email:  the account identifier (typically the user's email address)
                shown inside the authenticator app.
        issuer: the application name shown in the authenticator app
                (e.g. "ZeroTrustBank").

    Returns: a UTF-8 base64-encoded string whose decoded bytes are a PNG
    image. The caller can embed this directly in an HTML src attribute as
    `data:image/png;base64,<returned_string>`.

    Security property: the provisioning URI is generated entirely server-
    side and returned only once during MFA setup. It must be transmitted
    over TLS and never cached or logged. The QR image contains the raw
    secret, so it is as sensitive as the secret itself.
    """
    provisioning_uri: str = pyotp.TOTP(secret).provisioning_uri(
        name=email,
        issuer_name=issuer,
    )

    image = qrcode.make(provisioning_uri)

    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    buffer.seek(0)

    return base64.b64encode(buffer.read()).decode("utf-8")
