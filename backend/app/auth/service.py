"""Authentication service functions — registration and email verification.

This module implements the core business logic for user registration and
email address verification.  It has no HTTP concerns: no Request or Response
objects, no dependency injection containers.  All inputs are plain Python
values; the caller (router) is responsible for extracting them from the
HTTP layer.

Security properties enforced:
- SR-01: Password strength validated via ``is_password_strong`` before hashing.
- SR-02: Passwords stored as Argon2id hash only — plaintext is never persisted.
- SR-03: Email verification token stored as SHA-256 hash; raw token delivered
  out-of-band (console in demo mode).
- SR-16: Audit log entries created for REGISTER and EMAIL_VERIFIED events.
"""

from __future__ import annotations

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.security import (
    generate_refresh_token,
    hash_password,
    hash_token,
    is_password_strong,
)
from app.models.audit_log import AuditLog
from app.models.user import User, UserRole


async def register_user(
    email: str,
    password: str,
    db: AsyncSession,
    settings: Settings,  # noqa: ARG001  (reserved for future SMTP / policy use)
) -> User:
    """Create a new user account and issue an email verification token.

    Enforces SR-01 (password strength), SR-02 (Argon2id hashing), SR-03
    (email verification token stored as hash only), and SR-16 (audit log on
    REGISTER event).

    The raw verification token is printed to stdout in demo mode so that
    integration tests and manual testing can complete the verification flow
    without a real email server.  In production this print statement must be
    replaced with an SMTP send.

    Args:
        email:    The email address supplied by the registering user.
        password: The plaintext password supplied by the registering user.
        db:       An async SQLAlchemy session for the current request.
        settings: Application settings (reserved for future use by SMTP
                  dispatch and policy parameters).

    Returns:
        The newly created and committed ``User`` ORM object.

    Raises:
        HTTPException 422: If the password does not meet the SR-01 strength
            policy (min 12 chars, upper, lower, digit, special character).
        HTTPException 409: If the email address is already registered.
    """
    # SR-01: Reject weak passwords before any DB interaction.
    if not is_password_strong(password):
        raise HTTPException(
            status_code=422,
            detail="Password does not meet strength requirements",
        )

    # SR-03: Reject duplicate email addresses.
    existing = await db.execute(select(User).where(User.email == email))
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(
            status_code=409,
            detail="Email already registered",
        )

    # SR-02: Store only the Argon2id hash — never the plaintext password.
    hashed = hash_password(password)

    # SR-03: Generate a random verification token, store only its SHA-256 hash.
    raw_verification_token = generate_refresh_token()
    hashed_verification_token = hash_token(raw_verification_token)

    user = User(
        email=email,
        hashed_password=hashed,
        role=UserRole.USER,
        is_active=True,
        is_verified=False,
        email_verification_token_hash=hashed_verification_token,
    )
    db.add(user)

    # Flush so that user.id is populated before the AuditLog FK is set.
    await db.flush()

    # SR-16: Audit log entry for the REGISTER event.
    audit = AuditLog(
        user_id=user.id,
        action="REGISTER",
        ip_address=None,
        details={"email": email},
    )
    db.add(audit)

    await db.commit()
    await db.refresh(user)

    # DEMO MODE: replace with real SMTP in production.
    print(  # noqa: T201
        f"[DEMO MODE] Email verification token for {email}: {raw_verification_token}"
    )

    return user


async def verify_email(token: str, db: AsyncSession) -> None:
    """Mark a user's email address as verified after token validation.

    Enforces SR-03 (email verification required before protected resource
    access) and SR-16 (audit log on EMAIL_VERIFIED event).

    The incoming token is hashed with SHA-256 and compared against the stored
    hash.  This avoids any timing oracle: the DB query uses an exact equality
    match on a fixed-length hex string, and the token is single-use (cleared
    immediately on success).

    Args:
        token: The raw verification token received from the client query
               parameter.
        db:    An async SQLAlchemy session for the current request.

    Raises:
        HTTPException 400: If no unverified user matches the token hash, or if
            the token has already been used (user.is_verified is True or
            email_verification_token_hash is None).
    """
    hashed = hash_token(token)

    result = await db.execute(
        select(User).where(
            User.email_verification_token_hash == hashed,
            User.is_verified.is_(False),
        )
    )
    user = result.scalar_one_or_none()

    if user is None:
        raise HTTPException(
            status_code=400,
            detail="Invalid or already used verification token",
        )

    # Consume the token: mark verified and clear the hash so it cannot be reused.
    user.is_verified = True
    user.email_verification_token_hash = None

    # SR-16: Audit log entry for the EMAIL_VERIFIED event.
    audit = AuditLog(
        user_id=user.id,
        action="EMAIL_VERIFIED",
        ip_address=None,
        details={"email": user.email},
    )
    db.add(audit)

    await db.commit()
