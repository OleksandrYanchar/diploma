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

# ---------------------------------------------------------------------------
# Password hashing context
#
# CryptContext is immutable after construction and is safe to use as a
# module-level constant.  The Argon2id scheme meets OWASP minimum parameters:
#   memory_cost = 65536 KB (64 MB)
#   time_cost   = 3 iterations
#   parallelism = 4 threads
#
# passlib's argon2 backend wraps argon2-cffi and handles salt generation and
# canonical hash string formatting automatically.
# ---------------------------------------------------------------------------
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
    the algorithm identifier, parameters, salt, and digest.  This string is
    suitable for direct storage in the ``hashed_password`` column.

    Args:
        plain: The plaintext password to hash.

    Returns:
        A passlib-formatted Argon2id hash string starting with ``$argon2``.
    """
    return _pwd_context.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    """Verify a plaintext password against a stored Argon2id hash.

    Enforces SR-02: uses passlib's constant-time comparison, which prevents
    timing attacks that could allow an attacker to distinguish between a wrong
    password and an invalid hash format.

    This function never raises — any exception from a malformed hash or
    algorithm mismatch is caught and treated as a verification failure.  The
    caller always receives a plain boolean.

    Args:
        plain:   The plaintext password supplied by the user.
        hashed:  The Argon2id hash string retrieved from the database.

    Returns:
        True if ``plain`` matches ``hashed``, False in all other cases
        (wrong password, malformed hash, unsupported algorithm).
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

    Args:
        password: The plaintext password to evaluate.

    Returns:
        True if all policy requirements are met, False otherwise.
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

    The token payload carries:
    - ``sub``        — user ID (the authenticated principal)
    - ``role``       — RBAC role string; checked by ``require_role`` dependency
    - ``session_id`` — links the token to a Redis session record (SR-10)
    - ``jti``        — unique token ID (UUID4); used for blacklisting on logout
                       and step-up token tracking
    - ``typ``        — fixed to ``"access"``; guards against step-up tokens
                       being accepted as bearer tokens by ``decode_access_token``
    - ``iat``        — issued-at timestamp (UTC)
    - ``exp``        — expiry timestamp (UTC, iat + TTL)

    The ``typ="access"`` claim is a critical defence: step-up tokens share the
    same signing key and algorithm but carry ``typ="step_up"``.  Without this
    check, a step-up token could be submitted as a bearer token to bypass the
    TOTP re-verification requirement for sensitive operations.

    Args:
        subject:    String representation of the user's UUID.
        role:       The user's RBAC role value (e.g. ``"user"``, ``"admin"``).
        session_id: The active session UUID string stored in Redis (SR-10).
        settings:   Application settings providing the signing key, algorithm,
                    and token lifetime.

    Returns:
        A compact JWS string (header.payload.signature).
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
    carries ``typ="step_up"`` must be rejected here so that the step-up token
    cannot be submitted to any bearer-authenticated endpoint.

    Raises ``InvalidTokenError`` (from ``jwt``) on:
    - Expired token (``exp`` in the past)
    - Invalid or tampered signature
    - Wrong algorithm (algorithm confusion attack protection)
    - Missing or wrong ``typ`` claim
    - Any other decoding failure

    Args:
        token:    The compact JWT string to validate.
        settings: Application settings providing the signing key and algorithm.

    Returns:
        The decoded payload dict if all checks pass.

    Raises:
        InvalidTokenError: On any validation failure.  Callers should treat
            this as an unauthenticated request.
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

    The token payload carries:
    - ``sub``  — user ID (must match the bearer token sub on the transfer request)
    - ``jti``  — UUID4; the ``require_step_up`` dependency stores this in Redis
                 as a one-time-use flag and deletes it on first consumption
    - ``typ``  — fixed to ``"step_up"``; ``decode_access_token`` rejects this
                 type so the token cannot be submitted as a regular bearer token
    - ``iat``  — issued-at timestamp (UTC)
    - ``exp``  — expiry timestamp (UTC, iat + step_up_token_expire_minutes)

    The ``typ`` separation is a critical security control: both access tokens
    and step-up tokens share the same signing key and algorithm.  Without the
    ``typ`` check, a step-up token could be submitted as a bearer token on any
    protected endpoint, bypassing the TOTP re-verification requirement.

    Args:
        subject:  String representation of the authenticated user's UUID.
        settings: Application settings providing the signing key, algorithm,
                  and step-up token lifetime.

    Returns:
        A 2-tuple of (compact JWS string, jti string).  The caller stores the
        JTI in Redis under ``step_up:{jti}`` with TTL equal to the token
        lifetime so that the ``require_step_up`` dependency can locate and
        consume it exactly once.
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

    The ``typ`` check mirrors the guard in ``decode_access_token``: because
    both token types share the same signing key, the type claim is the only
    mechanism preventing cross-type substitution attacks.

    Raises ``InvalidTokenError`` on:
    - Expired token (``exp`` in the past)
    - Invalid or tampered signature
    - Wrong algorithm
    - Missing or wrong ``typ`` claim (e.g. an access token submitted here)
    - Any other decoding failure

    Args:
        token:    The compact JWT string to validate.
        settings: Application settings providing the signing key and algorithm.

    Returns:
        The decoded payload dict if all checks pass.  Callers must then
        verify the JTI against Redis to enforce single-use semantics (SR-14).

    Raises:
        InvalidTokenError: On any validation failure.
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

    This raw token is returned to the client (typically stored in an httpOnly
    cookie).  It is NEVER stored directly in the database — callers must pass
    the return value through ``hash_token`` before persistence (SR-07).

    Returns:
        A 43-character URL-safe base64 string with no whitespace.
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

    SHA-256 is appropriate here because the input tokens have at least 256
    bits of entropy (``secrets.token_urlsafe(32)``), making preimage attacks
    infeasible.  This is a lookup hash, not a password hash — the attacker
    cannot invert it without the raw token.

    Args:
        raw_token: The plaintext token string to hash.

    Returns:
        A 64-character lowercase hex string (SHA-256 digest).
    """
    return hashlib.sha256(raw_token.encode()).hexdigest()  # noqa: S324
