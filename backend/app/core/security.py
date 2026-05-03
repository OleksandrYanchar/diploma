"""Core cryptographic and token utilities.

This module implements all low-level security primitives used by the
authentication layer:

- Password hashing and verification (Argon2id, SR-02)
- Password strength policy enforcement (SR-01)
- JWT access token creation and decoding (SR-06)
- Step-up token creation and decoding (SR-13, SR-14)
- Refresh token generation and hashing (SR-07)
- Generic token hashing for DB storage (SR-03, SR-07, SR-18)

Nothing in this module performs I/O or holds application state.  All
functions are pure transformations that receive their inputs explicitly,
making them straightforward to test in isolation.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from jwt import InvalidTokenError  # noqa: F401  (re-exported for callers)
from passlib.context import CryptContext

from app.core.config import Settings

# Argon2id context (SR-02): memory_cost=65536 KB, time_cost=3, parallelism=4.
_pwd_context = CryptContext(
    schemes=["argon2"],
    deprecated="auto",
    argon2__memory_cost=65536,
    argon2__time_cost=3,
    argon2__parallelism=4,
)


def hash_password(plain: str) -> str:
    """Hash a plaintext password with Argon2id and return the hash string.

    Enforces SR-02: passwords are stored as Argon2id hashes only — the
    plaintext password is never persisted or logged.

    The returned string is in passlib's portable hash format, which embeds
    the algorithm identifier, parameters, salt, and digest.
    """
    return _pwd_context.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    """Verify a plaintext password against a stored Argon2id hash.

    Enforces SR-02: uses passlib's constant-time comparison, which prevents
    timing attacks that could allow an attacker to distinguish between a wrong
    password and an invalid hash format.

    This function never raises — any exception from a malformed hash or
    algorithm mismatch is caught and treated as a verification failure.
    """
    try:
        return _pwd_context.verify(plain, hashed)
    except Exception:  # noqa: BLE001
        return False


def is_password_strong(password: str) -> bool:
    """Check whether a password satisfies the SR-01 strength policy.

    Enforces SR-01: passwords must meet a minimum complexity requirement to
    reduce the risk of successful brute force and dictionary attacks.

    Policy requirements (all must be satisfied):
    - Minimum length: 12 characters
    - At least one uppercase letter (A–Z)
    - At least one lowercase letter (a–z)
    - At least one decimal digit (0–9)
    - At least one special character (any character that is not a letter or digit)

    This function returns False on policy violation; it does NOT raise.  The
    caller (typically the registration or password-change service) is
    responsible for translating a False return into an appropriate HTTP 422
    response.
    """
    if len(password) < 12:
        return False
    if not any(c.isupper() for c in password):
        return False
    if not any(c.islower() for c in password):
        return False
    if not any(c.isdigit() for c in password):
        return False
    if not any(not c.isalnum() for c in password):
        return False
    return True


def create_access_token(
    subject: str,
    role: str,
    session_id: str,
    settings: Settings,
) -> str:
    """Create a signed JWT access token for the given identity.

    Enforces SR-06: access tokens are short-lived (TTL from
    ``settings.access_token_expire_minutes``, maximum 15 minutes per policy).

    The ``typ="access"`` claim is critical: step-up tokens share the same
    signing key but carry ``typ="step_up"``.  Without this check, a step-up
    token could be submitted as a bearer token to bypass TOTP re-verification.
    """
    now = datetime.now(tz=timezone.utc)
    expire = now + timedelta(minutes=settings.access_token_expire_minutes)

    payload: dict[str, Any] = {
        "sub": subject,
        "role": role,
        "session_id": session_id,
        "jti": str(uuid.uuid4()),
        "typ": "access",
        "iat": now,
        "exp": expire,
    }

    return jwt.encode(
        payload,
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
    )


def decode_access_token(token: str, settings: Settings) -> dict[str, Any]:
    """Decode and validate a JWT access token, returning its payload.

    Enforces SR-06 (expiry validation) and guards against step-up token reuse
    as a bearer token by checking ``typ == "access"``.

    The ``typ`` check is mandatory: step-up tokens are signed with the same
    key and algorithm.  A token that passes signature and expiry checks but
    carries ``typ="step_up"`` must be rejected here.

    Raises:
        InvalidTokenError: On expired, tampered, wrong algorithm, or wrong typ.
    """
    payload: dict[str, Any] = jwt.decode(
        token,
        settings.jwt_secret_key,
        algorithms=[settings.jwt_algorithm],
    )

    if payload.get("typ") != "access":
        raise InvalidTokenError("Token type is not 'access'.")

    return payload


def create_step_up_token(subject: str, settings: Settings) -> tuple[str, str]:
    """Create a signed JWT step-up token for elevated-privilege operations.

    Enforces SR-13 (step-up authentication for sensitive transfers) and
    SR-14 (step-up token is single-use, tracked by JTI in Redis).

    The ``typ="step_up"`` claim is critical: ``decode_access_token`` rejects
    this type, so a step-up token cannot be submitted as a regular bearer token.
    Returns a (token, jti) tuple; caller stores the JTI in Redis for single-use
    consumption by ``require_step_up``.
    """
    now = datetime.now(tz=timezone.utc)
    expire = now + timedelta(minutes=settings.step_up_token_expire_minutes)
    jti = str(uuid.uuid4())

    payload: dict[str, Any] = {
        "sub": subject,
        "jti": jti,
        "typ": "step_up",
        "iat": now,
        "exp": expire,
    }

    token = jwt.encode(
        payload,
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
    )
    return token, jti


def decode_step_up_token(token: str, settings: Settings) -> dict[str, Any]:
    """Decode and validate a JWT step-up token, returning its payload.

    Enforces SR-13 (step-up token must be valid and unexpired) and guards
    against regular access tokens being submitted in place of a step-up
    token by checking ``typ == "step_up"``.

    The ``typ`` check mirrors ``decode_access_token``: both token types share
    the same signing key, so the type claim is the only guard against
    cross-type substitution attacks.

    Raises:
        InvalidTokenError: On expired, tampered, wrong algorithm, or wrong typ.
    """
    payload: dict[str, Any] = jwt.decode(
        token,
        settings.jwt_secret_key,
        algorithms=[settings.jwt_algorithm],
    )

    if payload.get("typ") != "step_up":
        raise InvalidTokenError("Token type is not 'step_up'.")

    return payload


def generate_refresh_token() -> str:
    """Generate a cryptographically random opaque refresh token.

    Returns a URL-safe base64-encoded string of 32 random bytes (256 bits of
    entropy), suitable for use as an opaque bearer credential.

    Never stored directly — callers must pass the result through ``hash_token``
    before persistence (SR-07).
    """
    return secrets.token_urlsafe(32)


def hash_token(raw_token: str) -> str:
    """Return the SHA-256 hex digest of a raw token string.

    Used to produce a deterministic, fixed-length representation of a raw
    token for database storage and lookup.  This function is intentionally
    deterministic: given the same input it always returns the same output,
    which allows the application to look up a refresh token or email
    verification token in the database by hashing the value received from the
    client and querying for the hash.

    Applied to:
    - Refresh tokens before insertion into ``refresh_tokens`` (SR-07)
    - Email verification tokens before insertion into ``users`` (SR-03)
    - Password reset tokens before insertion into ``users`` (SR-18)

    SHA-256 is safe here because the input tokens have 256 bits of entropy
    (``secrets.token_urlsafe(32)``), making preimage attacks infeasible.
    This is a lookup hash, not a password hash.
    """
    return hashlib.sha256(raw_token.encode()).hexdigest()  # noqa: S324
