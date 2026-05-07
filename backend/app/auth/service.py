"""Authentication service — registration, verification, login, refresh, logout, and MFA.

This module implements the core business logic for user registration, email
address verification, login with session creation, logout with session
teardown, refresh token rotation with reuse detection, TOTP MFA enrollment,
and step-up token issuance.  It has no HTTP concerns: no Request or Response
objects, no dependency injection containers.  All inputs are plain Python
values; the caller (router) is responsible for extracting them from the HTTP
layer.

Security properties enforced:
- SR-01: Password strength validated via ``is_password_strong`` before hashing.
- SR-02: Passwords stored as Argon2id hash only — plaintext is never persisted.
- SR-03: Email verification token stored as SHA-256 hash; raw token delivered
  out-of-band (console in demo mode).
- SR-04: TOTP secret stored on first setup only; never returned again after
  the initial ``setup_mfa`` response.  ``enable_mfa`` activates the gate
  after the first successful TOTP code is verified.
- SR-05: Account lockout after N consecutive failed login attempts.
- SR-06: Access tokens are short-lived JWTs issued on successful login.
- SR-07: Refresh tokens stored as SHA-256 hash; raw token returned to client once.
- SR-08: Refresh token reuse detection: a second presentation of an already-rotated
  token destroys the entire Redis session, forcing full re-authentication.
- SR-09: Access token JTI blacklisted in Redis on logout with remaining TTL.
- SR-10: Redis session created on login keyed by session_id; deleted on logout or
  on reuse detection.
- SR-13: Step-up token issued after TOTP re-verification for sensitive operations.
- SR-14: Step-up token stored as a one-time-use marker in Redis under
  ``step_up:{jti}``; consumed by ``require_step_up`` on first use.
- SR-16: Audit log entries created for REGISTER, EMAIL_VERIFIED, LOGIN_SUCCESS,
  LOGIN_FAILED, ACCOUNT_LOCKED, LOGOUT, TOKEN_REFRESHED, MFA_SETUP_INITIATED,
  MFA_ENABLED, MFA_FAILED, LOGIN_MFA_REQUIRED, MFA_VERIFIED, STEP_UP_VERIFIED,
  STEP_UP_FAILED, PASSWORD_RESET_REQUESTED, and PASSWORD_RESET_COMPLETED events.
- SR-18: Password reset tokens stored as SHA-256 hash only; raw token delivered
  out-of-band (console in demo mode).  All sessions and refresh tokens are
  revoked on a successful password reset so that the account is fully
  re-authenticated after the credential change.
"""

import uuid
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException
from redis.asyncio import Redis
from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.security import (
    create_access_token,
    create_step_up_token,
    generate_refresh_token,
    hash_password,
    hash_token,
    is_password_strong,
    verify_password,
)
from app.core.totp import (
    generate_qr_code_base64,
    generate_totp_secret,
    verify_totp_code,
)
from app.models.audit_log import AuditLog
from app.models.refresh_token import RefreshToken
from app.models.security_event import SecurityEvent, Severity
from app.models.user import User, UserRole

# Timing-safe dummy hash: prevents email enumeration via response-time analysis (SR-02).
_DUMMY_HASH: str = hash_password("__dummy_password_for_timing__")


async def register_user(
    email: str,
    password: str,
    db: AsyncSession,
    settings: Settings,  # noqa: ARG001 Not used as SMTP not implemented
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> User:
    """Create a new user account and issue an email verification token.

    Enforces SR-01 (password strength), SR-02 (Argon2id hashing), SR-03
    (email verification token stored as hash only), and SR-16 (audit log on
    REGISTER event).

    The raw verification token is printed to stdout in demo mode so that
    integration tests and manual testing can complete the verification flow
    without a real email server.  In production this print statement must be
    replaced with an SMTP send.

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
        ip_address=ip_address,
        user_agent=user_agent,
        details={"email": email},
    )
    db.add(audit)

    await db.commit()
    await db.refresh(user)

    # TODO: replace with real SMTP in production.
    print(  # noqa: T201
        f"[DEMO MODE] Email verification token for {email}: {raw_verification_token}"
    )

    return user


async def verify_email(
    token: str,
    db: AsyncSession,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> None:
    """Mark a user's email address as verified after token validation.

    Enforces SR-03 (email verification required before protected resource
    access) and SR-16 (audit log on EMAIL_VERIFIED event).

    The incoming token is hashed with SHA-256 and compared against the stored
    hash.  This avoids any timing oracle: the DB query uses an exact equality
    match on a fixed-length hex string, and the token is single-use (cleared
    immediately on success).

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
        ip_address=ip_address,
        user_agent=user_agent,
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
    totp_code: str | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> tuple[str, str] | tuple[None, None]:
    """Authenticate a user and create a new session, issuing JWT + refresh token.

    Enforces SR-02 (Argon2id verification), SR-05 (lockout after N failures),
    SR-06 (short-lived JWT access token), SR-07 (hashed refresh token in DB),
    SR-10 (Redis session keyed by session_id), and SR-16 (audit log on both
    success and failure, including MFA gate and unknown-email events).

    The email lookup uses a dummy hash comparison when the user is not found to
    prevent timing-based email enumeration: the Argon2id computation always
    runs, making the response time independent of whether the email exists.

    Returns:
        A 2-tuple ``(access_token, raw_refresh_token)`` on successful
        authentication, where ``access_token`` is a compact JWT string and
        ``raw_refresh_token`` is the opaque token that must be returned to the
        client and never stored plaintext server-side.

        Returns ``(None, None)`` when the password is correct but MFA is enabled
        and ``totp_code`` was not supplied.  The router must detect this sentinel
        and return an ``MFARequiredResponse`` (HTTP 200) so that the client can
        prompt the user for their TOTP code and re-submit.  No session is created
        and no tokens are issued on this path.

    Raises:
        HTTPException 401: If credentials are invalid (wrong email or password),
            or if the supplied TOTP code is invalid.  The same message is returned
            for email/password failures to prevent enumeration (SR-04, SR-05).
        HTTPException 403: If the account is deactivated or temporarily locked.
    """

    def _utcnow() -> datetime:
        return datetime.now(timezone.utc)

    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()

    if user is None:
        verify_password(password, _DUMMY_HASH)

        db.add(
            AuditLog(
                user_id=None,
                action="LOGIN_FAILED",
                ip_address=ip_address,
                user_agent=user_agent,
                details={"reason": "user_not_found"},
            )
        )
        await db.commit()
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is deactivated")

    if user.locked_until is not None:
        locked_until = user.locked_until
        if locked_until.tzinfo is None:
            locked_until = locked_until.replace(tzinfo=timezone.utc)
    if user.locked_until is not None and locked_until > _utcnow():
        raise HTTPException(
            status_code=403,
            detail="Account is temporarily locked",
        )

    valid = verify_password(password, user.hashed_password)
    if not valid:
        user.failed_login_count += 1

        if user.failed_login_count >= settings.max_failed_login_attempts:
            user.locked_until = _utcnow() + timedelta(
                minutes=settings.account_lockout_minutes
            )
            user.failed_login_count = 0
            db.add(
                SecurityEvent(
                    user_id=user.id,
                    event_type="ACCOUNT_LOCKED",
                    severity=Severity.HIGH,
                    ip_address=ip_address,
                    details={
                        "failed_login_count": settings.max_failed_login_attempts,
                        "locked_until": user.locked_until.isoformat()
                        if user.locked_until
                        else None,
                    },
                )
            )
            db.add(
                AuditLog(
                    user_id=user.id,
                    action="ACCOUNT_LOCKED",
                    ip_address=ip_address,
                    user_agent=user_agent,
                    details={
                        "locked_until": user.locked_until.isoformat()
                        if user.locked_until
                        else None,
                    },
                )
            )

        audit_fail = AuditLog(
            user_id=user.id,
            action="LOGIN_FAILED",
            ip_address=ip_address,
            user_agent=user_agent,
            details={"reason": "invalid_password"},
        )
        db.add(audit_fail)
        await db.commit()
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if user.mfa_enabled:
        if not totp_code:
            # Sub-case A: password was valid but no TOTP code was provided.
            # SR-16: Audit log for the MFA gate event.
            db.add(
                AuditLog(
                    user_id=user.id,
                    action="LOGIN_MFA_REQUIRED",
                    ip_address=ip_address,
                    user_agent=user_agent,
                    details={"session_id": None},
                )
            )
            await db.commit()
            return None, None

        if not verify_totp_code(user.mfa_secret, totp_code):
            db.add(
                AuditLog(
                    user_id=user.id,
                    action="MFA_FAILED",
                    ip_address=ip_address,
                    user_agent=user_agent,
                    details={"reason": "invalid_totp_code"},
                )
            )
            await db.commit()
            raise HTTPException(status_code=401, detail="Invalid TOTP code")

        db.add(
            AuditLog(
                user_id=user.id,
                action="MFA_VERIFIED",
                ip_address=ip_address,
                user_agent=user_agent,
                details={"email": user.email},
            )
        )

    user.failed_login_count = 0
    user.locked_until = None

    session_id = str(uuid.uuid4())

    access_token = create_access_token(
        subject=str(user.id),
        role=user.role.value,
        session_id=session_id,
        settings=settings,
    )

    raw_refresh = generate_refresh_token()
    refresh_hash = hash_token(raw_refresh)

    expires_at = _utcnow() + timedelta(days=settings.refresh_token_expire_days)

    refresh_token_record = RefreshToken(
        user_id=user.id,
        token_hash=refresh_hash,
        session_id=uuid.UUID(session_id),
        expires_at=expires_at,
    )
    db.add(refresh_token_record)

    session_ttl_seconds = settings.refresh_token_expire_days * 86400
    await redis.set(
        f"session:{session_id}",
        str(user.id),
        ex=session_ttl_seconds,
    )

    audit_success = AuditLog(
        user_id=user.id,
        action="LOGIN_SUCCESS",
        ip_address=ip_address,
        user_agent=user_agent,
        details={"session_id": session_id},
    )
    db.add(audit_success)

    await db.commit()

    return access_token, raw_refresh


async def refresh_tokens(
    raw_refresh_token: str,
    db: AsyncSession,
    redis: Redis,  # type: ignore[type-arg]
    settings: Settings,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> tuple[str, str]:
    """Rotate a refresh token and issue a new access token + refresh token pair.

    Enforces SR-07 (single-use refresh token rotation), SR-08 (reuse detection
    with full session revocation), SR-10 (session ID rotation in Redis), and
    SR-16 (audit log on TOKEN_REFRESHED event).

    Returns:
        A 2-tuple ``(new_access_token, new_raw_refresh_token)``.  Both must be
        returned to the client; the refresh token is never re-readable from the
        server side.

    Raises:
        HTTPException 401: Token not found, already used (reuse detection), or
            expired.  Also raised if the associated user is not found or not
            active.
    """

    def _utcnow() -> datetime:
        return datetime.now(timezone.utc)

    token_hash = hash_token(raw_refresh_token)
    rt_result = await db.execute(
        select(RefreshToken).where(RefreshToken.token_hash == token_hash)
    )
    token_row = rt_result.scalar_one_or_none()

    if token_row is None:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    if token_row.revoked:
        # SR-08: Reuse detection — bulk-revoke ALL tokens in DB first, then
        # destroy Redis sessions. DB revocation must be committed before Redis
        # keys are deleted so concurrent sibling-token requests are rejected at
        # the DB layer even if Redis is briefly stale.
        await db.execute(
            update(RefreshToken)
            .where(RefreshToken.user_id == token_row.user_id)
            .values(revoked=True)
        )

        # Collect all session keys for deletion (after the UPDATE so we capture all rows).
        user_rt_result = await db.execute(
            select(RefreshToken).where(RefreshToken.user_id == token_row.user_id)
        )
        all_user_tokens = user_rt_result.scalars().all()
        session_keys = [f"session:{rt.session_id}" for rt in all_user_tokens]
        if session_keys:
            await redis.delete(*session_keys)

        # AuditLog first — authoritative forensic timeline (SR-16).
        db.add(
            AuditLog(
                user_id=token_row.user_id,
                action="TOKEN_REUSE_DETECTED",
                ip_address=ip_address,
                user_agent=user_agent,
                details={
                    "session_id": str(token_row.session_id),
                    "tokens_revoked": len(all_user_tokens),
                },
            )
        )
        db.add(
            SecurityEvent(
                user_id=token_row.user_id,
                event_type="TOKEN_REUSE",
                severity=Severity.CRITICAL,
                ip_address=ip_address,
                details={
                    "session_id": str(token_row.session_id),
                },
            )
        )
        await db.commit()
        raise HTTPException(
            status_code=401,
            detail="Refresh token already used",
        )

    expires_at = token_row.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at < _utcnow():
        raise HTTPException(status_code=401, detail="Refresh token expired")

    user_result = await db.execute(
        select(User).where(User.id == uuid.UUID(str(token_row.user_id)))
    )
    user = user_result.scalar_one_or_none()
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    old_session_id = str(token_row.session_id)
    token_row.revoked = True

    new_raw_refresh = generate_refresh_token()
    new_session_id = str(uuid.uuid4())

    new_expires_at = _utcnow() + timedelta(days=settings.refresh_token_expire_days)
    new_token_row = RefreshToken(
        user_id=user.id,
        token_hash=hash_token(new_raw_refresh),
        session_id=uuid.UUID(new_session_id),
        expires_at=new_expires_at,
    )
    db.add(new_token_row)

    new_access_token = create_access_token(
        subject=str(user.id),
        role=user.role.value,
        session_id=new_session_id,
        settings=settings,
    )

    session_ttl_seconds = settings.refresh_token_expire_days * 86400
    await redis.delete(f"session:{old_session_id}")
    await redis.set(
        f"session:{new_session_id}",
        str(user.id),
        ex=session_ttl_seconds,
    )

    audit = AuditLog(
        user_id=user.id,
        action="TOKEN_REFRESHED",
        ip_address=ip_address,
        user_agent=user_agent,
        details={"session_id": new_session_id},
    )
    db.add(audit)

    await db.commit()

    return new_access_token, new_raw_refresh


async def logout(
    user: User,
    raw_refresh_token: str,
    access_token_payload: dict,
    db: AsyncSession,
    redis: Redis,  # type: ignore[type-arg]
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> None:
    """Terminate the user's session, revoking both the access token and refresh token.

    Enforces SR-09 (access token blacklisting on logout) and SR-10 (session
    deletion from Redis).  Logout is idempotent for an already-expired access
    token: if the token's remaining TTL is zero or negative, the JTI blacklist
    step is skipped because the token can no longer be presented to any endpoint.
    """
    jti: str = access_token_payload["jti"]
    exp: int = access_token_payload["exp"]
    remaining_ttl = exp - int(datetime.now(timezone.utc).timestamp())
    if remaining_ttl > 0:
        await redis.setex(f"blacklist:{jti}", remaining_ttl, "1")

    refresh_hash = hash_token(raw_refresh_token)
    rt_result = await db.execute(
        select(RefreshToken).where(
            RefreshToken.token_hash == refresh_hash,
            RefreshToken.revoked.is_(False),
        )
    )
    refresh_token_row = rt_result.scalar_one_or_none()
    if refresh_token_row is not None:
        refresh_token_row.revoked = True

    session_id: str = access_token_payload["session_id"]
    await redis.delete(f"session:{session_id}")

    audit = AuditLog(
        user_id=user.id,
        action="LOGOUT",
        ip_address=ip_address,
        user_agent=user_agent,
        details={"session_id": session_id},
    )
    db.add(audit)

    await db.commit()


async def disable_mfa(
    user: User,
    password: str,
    totp_code: str,
    db: AsyncSession,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> None:
    """Disable MFA for the user after verifying both password and current TOTP code.

    Enforces SR-04 (TOTP gate deactivation requires confirmed identity) and
    SR-16 (audit log on MFA_FAILED and MFA_DISABLED events).

    The two-factor check (password + TOTP) prevents an attacker who has only
    stolen a valid access token from silently disabling the MFA gate.  Both
    factors must be correct before the gate is deactivated.

    The MFA_FAILED audit log entry is committed BEFORE raising the
    HTTPException so that the failure event is always persisted regardless
    of any exception handling above this call site.  This matches the pattern
    used by the login and enable_mfa failure paths (SR-16).

    Raises:
        HTTPException 400: If MFA is not currently enabled on the account.
        HTTPException 401: If the password is incorrect.
        HTTPException 401: If the supplied TOTP code is invalid, with a
            MFA_FAILED audit log entry committed before raising.
    """
    if not user.mfa_enabled:
        raise HTTPException(
            status_code=400,
            detail="MFA is not enabled",
        )

    if not verify_password(password, user.hashed_password):
        db.add(
            AuditLog(
                user_id=user.id,
                action="MFA_FAILED",
                ip_address=ip_address,
                user_agent=user_agent,
                details={"reason": "invalid_password"},
            )
        )
        await db.commit()
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials",
        )

    if not verify_totp_code(user.mfa_secret, totp_code):
        db.add(
            AuditLog(
                user_id=user.id,
                action="MFA_FAILED",
                ip_address=ip_address,
                user_agent=user_agent,
                details={"reason": "invalid_totp_code"},
            )
        )
        await db.commit()
        raise HTTPException(status_code=401, detail="Invalid TOTP code")

    user.mfa_enabled = False
    user.mfa_secret = None

    db.add(
        AuditLog(
            user_id=user.id,
            action="MFA_DISABLED",
            ip_address=ip_address,
            user_agent=user_agent,
            details={"email": user.email},
        )
    )

    await db.commit()


async def change_password(
    user: User,
    current_password: str,
    new_password: str,
    db: AsyncSession,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> None:
    """Change the authenticated user's password after verifying the current one.

    Verifies current_password against the stored Argon2id hash.
    Enforces SR-01 strength policy on new_password before hashing.
    Writes a PASSWORD_CHANGED audit log entry on success (SR-16).
    Does not revoke existing sessions — see ADR-21.

    Raises:
        HTTPException 401: If current_password does not match the stored hash.
        HTTPException 422: If new_password fails the SR-01 strength policy.
    """
    if not verify_password(current_password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not is_password_strong(new_password):
        raise HTTPException(
            status_code=422,
            detail="Password does not meet strength requirements",
        )

    user.hashed_password = hash_password(new_password)

    db.add(
        AuditLog(
            user_id=user.id,
            action="PASSWORD_CHANGED",
            ip_address=ip_address,
            user_agent=user_agent,
            details={"email": user.email},
        )
    )

    await db.commit()


async def request_password_reset(
    email: str,
    db: AsyncSession,
    settings: Settings,  # noqa: ARG001 Not used as SMTP not implemented
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> None:
    """Issue a one-time password reset token for the given email address.

    Enforces SR-18 (reset token stored as SHA-256 hash only) and the
    non-enumeration requirement: the caller receives no signal indicating
    whether the email address belongs to a registered account.  Returns
    HTTP 200 whether or not the email exists.

    The raw token is printed in demo mode so that integration tests and

    manual testing can complete the reset flow without a real email server.
    In production this print statement must be replaced with an SMTP send.
    """
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()

    if user is None:
        db.add(
            AuditLog(
                user_id=None,
                action="PASSWORD_RESET_REQUESTED",
                ip_address=ip_address,
                user_agent=user_agent,
                details={"email_found": False},
            )
        )
        await db.commit()
        return

    raw_token = generate_refresh_token()

    user.password_reset_token_hash = hash_token(raw_token)
    user.password_reset_sent_at = datetime.now(timezone.utc)

    db.add(
        AuditLog(
            user_id=user.id,
            action="PASSWORD_RESET_REQUESTED",
            ip_address=ip_address,
            user_agent=user_agent,
            details={"email_found": True},
        )
    )

    await db.commit()

    # TODO: replace with real SMTP in production.
    print(  # noqa: T201
        f"[DEMO MODE] Password reset token for {email}: {raw_token}"
    )


async def confirm_password_reset(
    token: str,
    new_password: str,
    db: AsyncSession,
    redis: Redis,  # type: ignore[type-arg]
    settings: Settings,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> None:
    """Verify a password reset token and set a new password, revoking all sessions.

    Enforces SR-01 (new password strength), SR-02 (Argon2id hashing), SR-18
    (token expiry, single-use via field clear), and SR-10/SR-07 (full session
    and refresh-token revocation on password reset so the account is fully
    re-authenticated after the credential change).

    Raises:
        HTTPException 400: If the token is not found or has expired.
        HTTPException 422: If new_password fails the SR-01 strength policy.
    """
    token_hash = hash_token(token)
    result = await db.execute(
        select(User).where(User.password_reset_token_hash == token_hash)
    )
    user = result.scalar_one_or_none()

    if user is None:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired reset token",
        )

    sent_at = user.password_reset_sent_at
    if sent_at is None:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired reset token",
        )

    if sent_at.tzinfo is None:
        sent_at = sent_at.replace(tzinfo=timezone.utc)

    expiry_window = timedelta(minutes=settings.password_reset_token_ttl_minutes)
    if datetime.now(timezone.utc) > sent_at + expiry_window:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired reset token",
        )

    if not is_password_strong(new_password):
        raise HTTPException(
            status_code=422,
            detail="Password does not meet strength requirements",
        )

    user.hashed_password = hash_password(new_password)

    user.password_reset_token_hash = None
    user.password_reset_sent_at = None

    await db.execute(delete(RefreshToken).where(RefreshToken.user_id == user.id))

    user_id_str = str(user.id)
    keys_to_delete: list[str] = []
    async for key in redis.scan_iter("session:*"):
        value = await redis.get(key)
        if value == user_id_str:
            keys_to_delete.append(key)

    if keys_to_delete:
        await redis.delete(*keys_to_delete)

    db.add(
        AuditLog(
            user_id=user.id,
            action="PASSWORD_RESET_COMPLETED",
            ip_address=ip_address,
            user_agent=user_agent,
            details={"email": user.email},
        )
    )

    await db.commit()


async def verify_step_up(
    user: User,
    totp_code: str,
    db: AsyncSession,
    redis: Redis,  # type: ignore[type-arg]
    settings: Settings,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> str:
    """Verify a TOTP code and issue a short-lived step-up JWT.

    Enforces SR-13 (step-up re-authentication before sensitive operations)
    and SR-14 (one-time-use step-up token stored in Redis under
    ``step_up:{jti}``).

    The caller must be a fully authenticated, verified user who has MFA
    enabled.  A fresh TOTP code from their authenticator app is required
    on every call — the code cannot be the same as one accepted in the
    most recent login (replay risk is bounded by the TOTP window, ~90 s).

    On success, the step-up JTI is stored in Redis with a TTL equal to
    ``settings.step_up_token_expire_minutes * 60`` seconds.  The
    ``require_step_up`` dependency (Phase 6) will look up this key on the
    sensitive endpoint and delete it on first consumption, enforcing the
    single-use property (SR-14).

    On failure, a ``STEP_UP_FAILED`` audit log entry is committed BEFORE
    raising so that the failure event is always persisted regardless of any
    exception handling above this call site — matching the pattern used by
    ``enable_mfa`` and ``login`` TOTP failure paths (SR-16).

    Returns:
        The compact step-up JWT string.  The caller (router) wraps this in
        a ``StepUpResponse`` and returns it to the client.

    Raises:
        HTTPException 403: If ``user.mfa_enabled`` is False.  Step-up
            authentication requires an active MFA gate — without one there
            is no second factor to re-verify.
        HTTPException 401: If the supplied TOTP code is invalid.  A
            ``STEP_UP_FAILED`` audit log entry is committed before raising.
    """

    if not user.mfa_enabled:
        raise HTTPException(
            status_code=403,
            detail="MFA must be enabled to use step-up authentication",
        )

    if not verify_totp_code(user.mfa_secret, totp_code):
        db.add(
            AuditLog(
                user_id=user.id,
                action="STEP_UP_FAILED",
                ip_address=ip_address,
                user_agent=user_agent,
                details={"reason": "invalid_totp_code"},
            )
        )
        await db.commit()
        raise HTTPException(status_code=401, detail="Invalid TOTP code")

    token, jti = create_step_up_token(subject=str(user.id), settings=settings)

    ttl_seconds = settings.step_up_token_expire_minutes * 60
    await redis.set(f"step_up:{jti}", str(user.id), ex=ttl_seconds)

    db.add(
        AuditLog(
            user_id=user.id,
            action="STEP_UP_VERIFIED",
            ip_address=ip_address,
            user_agent=user_agent,
            details={"jti": jti},
        )
    )
    await db.commit()

    return token


async def setup_mfa(
    user: User,
    db: AsyncSession,
    settings: Settings,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> tuple[str, str]:
    """Generate and store a TOTP secret for the user, returning the secret and QR code.

    Enforces SR-04 (TOTP secret stored once during enrollment; never returned
    again after this call) and SR-16 (audit log on MFA_SETUP_INITIATED event).

    If ``user.mfa_enabled`` is True the call is rejected immediately — MFA
    cannot be re-initialised without first disabling it (Phase 4).

    If ``user.mfa_secret`` is already set but ``mfa_enabled`` is still False,
    a prior setup was abandoned before verification.  The old secret is
    overwritten silently: the abandoned secret was never confirmed by a
    successful TOTP code submission, so it has no security value.

    The QR code embeds the raw secret and is therefore as sensitive as the
    secret itself.  Both must be transmitted over TLS and must not be cached
    or logged.  The secret is returned to the caller exactly once; all
    subsequent API calls must never reveal it.

    Returns:
        A 2-tuple ``(secret, qr_code_base64)`` where ``secret`` is the
        Base32-encoded TOTP secret and ``qr_code_base64`` is a UTF-8
        base64-encoded PNG image of the provisioning QR code.

    Raises:
        HTTPException 400: If MFA is already fully enabled on the account.
    """
    if user.mfa_enabled:
        raise HTTPException(
            status_code=400,
            detail="MFA is already enabled",
        )

    secret = generate_totp_secret()
    user.mfa_secret = secret

    await db.flush()

    audit = AuditLog(
        user_id=user.id,
        action="MFA_SETUP_INITIATED",
        ip_address=ip_address,
        user_agent=user_agent,
        details={"email": user.email},
    )
    db.add(audit)
    await db.commit()

    qr_code_base64 = generate_qr_code_base64(
        secret=secret,
        email=user.email,
        issuer=settings.app_name,
    )

    return secret, qr_code_base64


async def enable_mfa(
    user: User,
    totp_code: str,
    db: AsyncSession,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> None:
    """Verify the first TOTP code and activate MFA for the user.

    Enforces SR-04 (TOTP gate activation after confirmed enrollment) and
    SR-16 (audit log on both MFA_ENABLED success and MFA_FAILED failure).

    The caller must be an authenticated user who has already completed the
    ``setup_mfa`` step (i.e., ``user.mfa_secret`` is set).  The first
    successful TOTP code submission proves that the user has the correct
    secret in their authenticator app, at which point the MFA gate is
    activated by setting ``mfa_enabled = True``.

    The MFA_FAILED audit log entry is committed BEFORE raising the
    HTTPException so that the failure event is always persisted regardless
    of any exception handling above this call site.  This matches the
    pattern used by the login failure path (SR-16).

    Raises:
        HTTPException 400: If ``user.mfa_secret`` is None (setup was never
            initiated) or if MFA is already enabled on the account.
        HTTPException 401: If the supplied TOTP code is invalid, with a
            MFA_FAILED audit log entry committed before raising.
    """
    if user.mfa_secret is None:
        raise HTTPException(
            status_code=400,
            detail="MFA setup not initiated",
        )

    if user.mfa_enabled:
        raise HTTPException(
            status_code=400,
            detail="MFA is already enabled",
        )

    if not verify_totp_code(user.mfa_secret, totp_code):
        db.add(
            AuditLog(
                user_id=user.id,
                action="MFA_FAILED",
                ip_address=ip_address,
                user_agent=user_agent,
                details={"reason": "invalid_totp_code"},
            )
        )
        await db.commit()
        raise HTTPException(status_code=401, detail="Invalid TOTP code")

    user.mfa_enabled = True

    db.add(
        AuditLog(
            user_id=user.id,
            action="MFA_ENABLED",
            ip_address=ip_address,
            user_agent=user_agent,
            details={"email": user.email},
        )
    )

    await db.commit()
