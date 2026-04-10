"""Authentication service functions — registration, email verification, and login.

This module implements the core business logic for user registration, email
address verification, and login with session creation.  It has no HTTP concerns:
no Request or Response objects, no dependency injection containers.  All inputs
are plain Python values; the caller (router) is responsible for extracting them
from the HTTP layer.

Security properties enforced:
- SR-01: Password strength validated via ``is_password_strong`` before hashing.
- SR-02: Passwords stored as Argon2id hash only — plaintext is never persisted.
- SR-03: Email verification token stored as SHA-256 hash; raw token delivered
  out-of-band (console in demo mode).
- SR-05: Account lockout after N consecutive failed login attempts.
- SR-06: Access tokens are short-lived JWTs issued on successful login.
- SR-07: Refresh tokens stored as SHA-256 hash; raw token returned to client once.
- SR-10: Redis session created on login keyed by session_id.
- SR-16: Audit log entries created for REGISTER, EMAIL_VERIFIED, LOGIN_SUCCESS,
  and LOGIN_FAILED events.
"""

from __future__ import annotations

import uuid
from datetime import datetime as _dt
from datetime import timedelta, timezone

from fastapi import HTTPException
from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.security import (
    create_access_token,
    generate_refresh_token,
    hash_password,
    hash_token,
    is_password_strong,
    verify_password,
)
from app.models.audit_log import AuditLog
from app.models.refresh_token import RefreshToken
from app.models.user import User, UserRole

# ---------------------------------------------------------------------------
# Anti-timing constant
#
# A dummy Argon2id hash computed once at module import time.  Used in the login
# flow when the requested email does not exist: ``verify_password`` is called
# against this hash so that the response time is indistinguishable from a real
# failed password check, preventing email enumeration via timing analysis.
# ---------------------------------------------------------------------------
_DUMMY_HASH: str = hash_password("__dummy_password_for_timing__")


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


async def login(
    email: str,
    password: str,
    db: AsyncSession,
    redis: Redis,  # type: ignore[type-arg]
    settings: Settings,
) -> tuple[str, str]:
    """Authenticate a user and create a new session, issuing JWT + refresh token.

    Enforces SR-02 (Argon2id verification), SR-05 (lockout after N failures),
    SR-06 (short-lived JWT access token), SR-07 (hashed refresh token in DB),
    SR-10 (Redis session keyed by session_id), and SR-16 (audit log on both
    success and failure).

    The email lookup uses a dummy hash comparison when the user is not found to
    prevent timing-based email enumeration: the Argon2id computation always
    runs, making the response time independent of whether the email exists.

    Args:
        email:    The email address supplied by the authenticating user.
        password: The plaintext password supplied by the authenticating user.
        db:       An async SQLAlchemy session for the current request.
        redis:    The shared async Redis client for session storage (SR-10).
        settings: Application settings supplying token lifetimes and lockout policy.

    Returns:
        A 2-tuple ``(access_token, raw_refresh_token)`` where ``access_token``
        is a compact JWT string and ``raw_refresh_token`` is the opaque token
        that must be returned to the client and never stored plaintext server-side.

    Raises:
        HTTPException 401: If credentials are invalid (wrong email or password).
            The same message is returned in both cases to prevent enumeration.
        HTTPException 403: If the account is deactivated or temporarily locked.
        HTTPException 200: If the password is correct but MFA is enabled on the
            account (mfa_required signal to the client to supply a TOTP code).
    """

    def _utcnow() -> _dt:
        return _dt.now(timezone.utc)

    # ------------------------------------------------------------------
    # Step 2: Fetch user by email.  If not found, run dummy hash to
    # prevent timing-based email enumeration, then reject (SR-05).
    # ------------------------------------------------------------------
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()

    if user is None:
        # Anti-timing: always perform a hash comparison so response time is
        # consistent whether or not the email exists in the database.
        verify_password(password, _DUMMY_HASH)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # ------------------------------------------------------------------
    # Step 3: Deactivated accounts are rejected before any credential check.
    # ------------------------------------------------------------------
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is deactivated")

    # ------------------------------------------------------------------
    # Step 4: Locked account check.  Compare with timezone-aware utcnow.
    # SQLite returns DateTime columns as naive datetimes; PostgreSQL returns
    # them as timezone-aware.  To keep the comparison safe across both
    # backends, we attach UTC to a naive locked_until value if needed.
    # ------------------------------------------------------------------
    if user.locked_until is not None:
        locked_until = user.locked_until
        if locked_until.tzinfo is None:
            locked_until = locked_until.replace(tzinfo=timezone.utc)
    if user.locked_until is not None and locked_until > _utcnow():
        raise HTTPException(
            status_code=403,
            detail="Account is temporarily locked",
        )

    # ------------------------------------------------------------------
    # Step 5: Verify the supplied password.  On failure, increment the
    # failure counter and potentially lock the account (SR-05).
    # ------------------------------------------------------------------
    valid = verify_password(password, user.hashed_password)
    if not valid:
        user.failed_login_count += 1

        if user.failed_login_count >= settings.max_failed_login_attempts:
            # Threshold reached: lock the account and reset the counter.
            user.locked_until = _utcnow() + timedelta(
                minutes=settings.account_lockout_minutes
            )
            user.failed_login_count = 0

        audit_fail = AuditLog(
            user_id=user.id,
            action="LOGIN_FAILED",
            ip_address=None,
            details={"reason": "invalid_password"},
        )
        db.add(audit_fail)
        await db.commit()
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # ------------------------------------------------------------------
    # Step 6: MFA gate — if the account has MFA enabled, signal the client
    # to supply a TOTP code.  The TOTP verification path is Phase 3.
    # ------------------------------------------------------------------
    if user.mfa_enabled:
        raise HTTPException(
            status_code=200,
            detail={
                "mfa_required": True,
                "message": "TOTP code required to complete login.",
            },
        )

    # ------------------------------------------------------------------
    # Steps 7–16: Successful authentication path.
    # ------------------------------------------------------------------

    # Step 7: Reset lockout state after a successful password verification.
    user.failed_login_count = 0
    user.locked_until = None

    # Step 8: Generate a unique session identifier.
    session_id = str(uuid.uuid4())

    # Step 9: Mint a short-lived JWT access token (SR-06).
    access_token = create_access_token(
        subject=str(user.id),
        role=user.role.value,
        session_id=session_id,
        settings=settings,
    )

    # Step 10: Generate the opaque refresh token; store only its hash (SR-07).
    raw_refresh = generate_refresh_token()
    refresh_hash = hash_token(raw_refresh)

    # Step 11: Compute absolute expiry for the refresh token record.
    expires_at = _utcnow() + timedelta(days=settings.refresh_token_expire_days)

    # Step 12: Persist the refresh token record (hashed, never raw).
    refresh_token_record = RefreshToken(
        user_id=user.id,
        token_hash=refresh_hash,
        session_id=uuid.UUID(session_id),
        expires_at=expires_at,
    )
    db.add(refresh_token_record)

    # Step 13: Write a live session record to Redis (SR-10).
    # TTL matches the refresh token lifetime so the session expires naturally.
    session_ttl_seconds = settings.refresh_token_expire_days * 86400
    await redis.set(
        f"session:{session_id}",
        str(user.id),
        ex=session_ttl_seconds,
    )

    # Step 14: Audit log for the successful login event (SR-16).
    audit_success = AuditLog(
        user_id=user.id,
        action="LOGIN_SUCCESS",
        ip_address=None,
        details={"session_id": session_id},
    )
    db.add(audit_success)

    # Step 15: Commit all DB writes atomically.
    await db.commit()

    # Step 16: Return tokens to the caller (router formats the HTTP response).
    return access_token, raw_refresh
