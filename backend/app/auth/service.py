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

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException
from redis.asyncio import Redis
from sqlalchemy import delete, select
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
    totp_code: str | None = None,
) -> tuple[str, str] | tuple[None, None]:
    """Authenticate a user and create a new session, issuing JWT + refresh token.

    Enforces SR-02 (Argon2id verification), SR-05 (lockout after N failures),
    SR-06 (short-lived JWT access token), SR-07 (hashed refresh token in DB),
    SR-10 (Redis session keyed by session_id), and SR-16 (audit log on both
    success and failure, including MFA gate and unknown-email events).

    The email lookup uses a dummy hash comparison when the user is not found to
    prevent timing-based email enumeration: the Argon2id computation always
    runs, making the response time independent of whether the email exists.

    Args:
        email:     The email address supplied by the authenticating user.
        password:  The plaintext password supplied by the authenticating user.
        db:        An async SQLAlchemy session for the current request.
        redis:     The shared async Redis client for session storage (SR-10).
        settings:  Application settings supplying token lifetimes and lockout policy.
        totp_code: Optional six-to-eight-digit TOTP code.  Must be supplied when
                   the account has MFA enabled; ignored otherwise (SR-04).

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

        # SR-16: Audit log for the unknown-email path.  Written AFTER the dummy
        # hash so that the anti-timing protection is never short-circuited.
        db.add(
            AuditLog(
                user_id=None,
                action="LOGIN_FAILED",
                ip_address=None,
                details={"reason": "user_not_found"},
            )
        )
        await db.commit()
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
            # SR-17: Write a HIGH-severity SecurityEvent for the lockout so
            # that automated monitoring and the admin role can detect brute-
            # force attacks without scanning the full audit log (SR-16).
            db.add(
                SecurityEvent(
                    user_id=user.id,
                    event_type="ACCOUNT_LOCKED",
                    severity=Severity.HIGH,
                    ip_address=None,
                    details={
                        "failed_login_count": settings.max_failed_login_attempts,
                        "locked_until": user.locked_until.isoformat()
                        if user.locked_until
                        else None,
                    },
                )
            )
            # SR-16: AuditLog entry for the lockout event (human-readable trail).
            # The SecurityEvent above serves automated monitoring; this entry
            # ensures the lockout appears in audit log queries as well.
            db.add(
                AuditLog(
                    user_id=user.id,
                    action="ACCOUNT_LOCKED",
                    ip_address=None,
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
            ip_address=None,
            details={"reason": "invalid_password"},
        )
        db.add(audit_fail)
        await db.commit()
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # ------------------------------------------------------------------
    # Step 6: MFA gate — if the account has MFA enabled, either verify the
    # supplied TOTP code or signal the client to supply one.
    #
    # Sub-case A (no totp_code supplied):
    #   Return the sentinel (None, None) so the router can issue HTTP 200
    #   with MFARequiredResponse.  A LOGIN_MFA_REQUIRED audit log is written
    #   to record the password-verified, TOTP-pending state (SR-16).
    #
    # Sub-case B (totp_code supplied but invalid):
    #   Write a MFA_FAILED audit log, commit it BEFORE raising so the failure
    #   is always persisted regardless of exception handling above this call
    #   site, then raise HTTPException 401 (SR-04, SR-16).
    #
    # Sub-case C (totp_code supplied and valid):
    #   Write a MFA_VERIFIED audit log and fall through to token issuance.
    #   The audit entry is committed with the session/token writes below so
    #   that the success record and the session are always atomic (SR-16).
    # ------------------------------------------------------------------
    if user.mfa_enabled:
        if not totp_code:
            # Sub-case A: password was valid but no TOTP code was provided.
            # SR-16: Audit log for the MFA gate event.
            db.add(
                AuditLog(
                    user_id=user.id,
                    action="LOGIN_MFA_REQUIRED",
                    ip_address=None,
                    details={"session_id": None},
                )
            )
            await db.commit()
            return None, None

        # Sub-case B/C: a TOTP code was supplied — verify it (SR-04).
        if not verify_totp_code(user.mfa_secret, totp_code):
            # Sub-case B: invalid TOTP code.
            # Commit the audit entry BEFORE raising so the failure event is
            # always persisted (SR-16), matching the LOGIN_FAILED pattern.
            db.add(
                AuditLog(
                    user_id=user.id,
                    action="MFA_FAILED",
                    ip_address=None,
                    details={"reason": "invalid_totp_code"},
                )
            )
            await db.commit()
            raise HTTPException(status_code=401, detail="Invalid TOTP code")

        # Sub-case C: TOTP code is valid.  Stage the success audit log — it
        # will be committed atomically with the session/token writes below.
        db.add(
            AuditLog(
                user_id=user.id,
                action="MFA_VERIFIED",
                ip_address=None,
                details={"email": user.email},
            )
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


async def refresh_tokens(
    raw_refresh_token: str,
    db: AsyncSession,
    redis: Redis,  # type: ignore[type-arg]
    settings: Settings,
) -> tuple[str, str]:
    """Rotate a refresh token and issue a new access token + refresh token pair.

    Enforces SR-07 (single-use refresh token rotation), SR-08 (reuse detection
    with full session revocation), SR-10 (session ID rotation in Redis), and
    SR-16 (audit log on TOKEN_REFRESHED event).

    Algorithm:
    1. Hash the incoming raw token and look up the RefreshToken row.
    2. If not found, raise 401 (invalid token).
    3. If ``revoked == True``, the token was already consumed or explicitly
       revoked.  Per SR-08, the Redis session for the associated session_id is
       deleted immediately before raising 401 so that even the legitimate client
       (whose new tokens reference the rotated session) is forced to
       re-authenticate.  This prevents a silent attacker who captured a
       pre-rotation token from maintaining access after the victim rotates.
    4. If ``expires_at`` is in the past, raise 401 (expired).
    5. Verify the associated user is still active.
    6. Mark the old token row as revoked (consumed by rotation).
    7. Generate a new refresh token and a new session_id (session rotation).
    8. Insert a new RefreshToken row with the new hash and new session_id.
    9. Issue a new access token bound to the new session_id.
    10. Update Redis: delete the old session key, set the new session key.
    11. Write a TOKEN_REFRESHED audit log entry (SR-16).
    12. Return (new_access_token, new_raw_refresh_token).

    Args:
        raw_refresh_token: The opaque refresh token received from the client.
        db:                An async SQLAlchemy session for the current request.
        redis:             The shared async Redis client for session storage.
        settings:          Application settings supplying token lifetimes and
                           signing key.

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

    # ------------------------------------------------------------------
    # Step 1: Hash the incoming token and look up the DB row.
    # ------------------------------------------------------------------
    token_hash = hash_token(raw_refresh_token)
    rt_result = await db.execute(
        select(RefreshToken).where(RefreshToken.token_hash == token_hash)
    )
    token_row = rt_result.scalar_one_or_none()

    # ------------------------------------------------------------------
    # Step 2: Not found → invalid token.
    # ------------------------------------------------------------------
    if token_row is None:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    # ------------------------------------------------------------------
    # Step 3: Reuse detection (SR-08).
    #
    # A revoked token arriving here means either:
    # a) The legitimate client is replaying an old token (bug or race), or
    # b) An attacker captured a pre-rotation token and is replaying it.
    #
    # In both cases the correct response is to destroy every active session
    # for this user so that neither the legitimate client nor an attacker can
    # continue using any existing credentials.  The legitimate client will
    # receive 401 on their next request and must re-authenticate, which is the
    # correct outcome — the credential theft window is fully closed.
    #
    # We cannot only delete the old session (token_row.session_id): after a
    # successful prior rotation the old session no longer exists in Redis.  The
    # live session belongs to the *successor* refresh token row.  Instead we
    # delete all ``session:{session_id}`` keys for every refresh token row
    # belonging to this user, regardless of revocation state.  This covers
    # both the original session and any sessions established by subsequent
    # rotations.
    # ------------------------------------------------------------------
    if token_row.revoked:
        user_rt_result = await db.execute(
            select(RefreshToken).where(RefreshToken.user_id == token_row.user_id)
        )
        all_user_tokens = user_rt_result.scalars().all()
        session_keys = [f"session:{rt.session_id}" for rt in all_user_tokens]
        if session_keys:
            await redis.delete(*session_keys)
        # SR-17: Write a CRITICAL-severity SecurityEvent for token reuse so
        # that the incident is distinguishable from normal 401s in automated
        # monitoring dashboards.  All sessions for this user have already been
        # revoked above; this write records the event for forensic correlation.
        db.add(
            SecurityEvent(
                user_id=token_row.user_id,
                event_type="TOKEN_REUSE",
                severity=Severity.CRITICAL,
                ip_address=None,
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

    # ------------------------------------------------------------------
    # Step 4: Expiry check (ADR-17: normalize naive datetimes from SQLite).
    # ------------------------------------------------------------------
    expires_at = token_row.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at < _utcnow():
        raise HTTPException(status_code=401, detail="Refresh token expired")

    # ------------------------------------------------------------------
    # Step 5: Load and validate the associated user.
    # ------------------------------------------------------------------
    user_result = await db.execute(
        select(User).where(User.id == uuid.UUID(str(token_row.user_id)))
    )
    user = user_result.scalar_one_or_none()
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    # ------------------------------------------------------------------
    # Step 6: Mark the old token row as revoked (consumed by rotation).
    # ------------------------------------------------------------------
    old_session_id = str(token_row.session_id)
    token_row.revoked = True

    # ------------------------------------------------------------------
    # Step 7: Generate new credentials with a fresh session ID.
    #
    # Rotating the session_id on every refresh ensures that a stolen old
    # access token (still within its short lifetime) cannot be associated
    # with the newly rotated session — the new session_id must match the
    # Redis key, so the old access token is automatically invalidated at
    # the next get_current_user check.
    # ------------------------------------------------------------------
    new_raw_refresh = generate_refresh_token()
    new_session_id = str(uuid.uuid4())

    # ------------------------------------------------------------------
    # Step 8: Persist the new RefreshToken row.
    # ------------------------------------------------------------------
    new_expires_at = _utcnow() + timedelta(days=settings.refresh_token_expire_days)
    new_token_row = RefreshToken(
        user_id=user.id,
        token_hash=hash_token(new_raw_refresh),
        session_id=uuid.UUID(new_session_id),
        expires_at=new_expires_at,
    )
    db.add(new_token_row)

    # ------------------------------------------------------------------
    # Step 9: Issue the new access token bound to the new session.
    # ------------------------------------------------------------------
    new_access_token = create_access_token(
        subject=str(user.id),
        role=user.role.value,
        session_id=new_session_id,
        settings=settings,
    )

    # ------------------------------------------------------------------
    # Step 10: Rotate the Redis session (SR-10).
    #
    # Delete the old session key first so there is no window where both the
    # old and new session are simultaneously live.  Then set the new key with
    # a fresh TTL matching the new refresh token lifetime.
    # ------------------------------------------------------------------
    session_ttl_seconds = settings.refresh_token_expire_days * 86400
    await redis.delete(f"session:{old_session_id}")
    await redis.set(
        f"session:{new_session_id}",
        str(user.id),
        ex=session_ttl_seconds,
    )

    # ------------------------------------------------------------------
    # Step 11: Audit log entry for the TOKEN_REFRESHED event (SR-16).
    # ------------------------------------------------------------------
    audit = AuditLog(
        user_id=user.id,
        action="TOKEN_REFRESHED",
        ip_address=None,
        details={"session_id": new_session_id},
    )
    db.add(audit)

    # ------------------------------------------------------------------
    # Step 12: Commit all DB mutations atomically.
    # ------------------------------------------------------------------
    await db.commit()

    return new_access_token, new_raw_refresh


async def logout(
    user: User,
    raw_refresh_token: str,
    access_token_payload: dict,
    db: AsyncSession,
    redis: Redis,  # type: ignore[type-arg]
) -> None:
    """Terminate the user's session, revoking both the access token and refresh token.

    Enforces SR-09 (access token blacklisting on logout) and SR-10 (session
    deletion from Redis).  Logout is idempotent for an already-expired access
    token: if the token's remaining TTL is zero or negative, the JTI blacklist
    step is skipped because the token can no longer be presented to any endpoint.

    Operations performed, in order:
    1. Blacklist the access token JTI in Redis with remaining TTL (SR-09).
       Skipped if the token is already past its expiry.
    2. Revoke the matching refresh token row in the database (SR-07).
       If no unrevoked row is found (already revoked or never issued), the step
       is skipped silently — the operation remains safe.
    3. Delete the Redis session record (SR-10).
    4. Write a LOGOUT audit log entry (SR-16).
    5. Commit all database mutations atomically.

    Args:
        user:                 The authenticated User performing the logout.
        raw_refresh_token:    The raw opaque refresh token supplied in the
                              request body; hashed with SHA-256 for DB lookup.
        access_token_payload: The decoded JWT payload dict from the current
                              access token.  Must contain ``jti``, ``exp``, and
                              ``session_id`` claims.
        db:                   An async SQLAlchemy session for the current request.
        redis:                The shared async Redis client.
    """
    # ------------------------------------------------------------------
    # Step 1: Blacklist the access token JTI with remaining TTL (SR-09).
    #
    # The JTI blacklist ensures that a logout is effective immediately even
    # though the access token's cryptographic signature remains valid until
    # its natural expiry.  The Redis TTL is set to the remaining lifetime so
    # the blacklist entry is automatically cleaned up once the token expires.
    # ------------------------------------------------------------------
    jti: str = access_token_payload["jti"]
    exp: int = access_token_payload["exp"]
    remaining_ttl = exp - int(datetime.now(timezone.utc).timestamp())
    if remaining_ttl > 0:
        await redis.setex(f"blacklist:{jti}", remaining_ttl, "1")

    # ------------------------------------------------------------------
    # Step 2: Revoke the refresh token in the database (SR-07).
    #
    # The raw token is hashed to look up the DB row.  The row is NOT deleted
    # so that the audit trail is preserved (SR-16).  Setting revoked=True
    # ensures the token cannot be used again.  If the row is not found (e.g.
    # already revoked by a prior logout or rotation), we skip silently — the
    # logout operation is still correct.
    # ------------------------------------------------------------------
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

    # ------------------------------------------------------------------
    # Step 3: Delete the Redis session (SR-10).
    #
    # Removing the session record from Redis immediately invalidates any
    # request that arrives after this point, even if it carries a still-valid
    # JWT that was not yet caught by the JTI blacklist (e.g. a concurrent
    # request that slipped through before the blacklist write).
    # ------------------------------------------------------------------
    session_id: str = access_token_payload["session_id"]
    await redis.delete(f"session:{session_id}")

    # ------------------------------------------------------------------
    # Step 4: Write audit log entry for the LOGOUT event (SR-16).
    # ------------------------------------------------------------------
    audit = AuditLog(
        user_id=user.id,
        action="LOGOUT",
        ip_address=None,
        details={"session_id": session_id},
    )
    db.add(audit)

    # ------------------------------------------------------------------
    # Step 5: Commit all database mutations atomically.
    # ------------------------------------------------------------------
    await db.commit()


async def disable_mfa(
    user: User,
    password: str,
    totp_code: str,
    db: AsyncSession,
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

    Args:
        user:      The authenticated User requesting MFA deactivation.
        password:  The plaintext password to verify against the stored hash.
        totp_code: The six-to-eight-digit TOTP code to verify against the
                   stored secret.
        db:        An async SQLAlchemy session for the current request.

    Raises:
        HTTPException 400: If MFA is not currently enabled on the account.
        HTTPException 401: If the password is incorrect.
        HTTPException 401: If the supplied TOTP code is invalid, with a
            MFA_FAILED audit log entry committed before raising.
    """
    # ------------------------------------------------------------------
    # Step 1: Reject if MFA is not currently active.
    # There is nothing to disable on an account that has not enrolled.
    # ------------------------------------------------------------------
    if not user.mfa_enabled:
        raise HTTPException(
            status_code=400,
            detail="MFA is not enabled",
        )

    # ------------------------------------------------------------------
    # Step 2: Verify the supplied password.
    # This prevents an attacker who holds a stolen access token from
    # silently disabling MFA without knowing the account password.
    # Commit the MFA_FAILED audit entry BEFORE raising so the failure is
    # always persisted regardless of any exception handling above this
    # call site (SR-16), matching the pattern used for TOTP failures.
    # ------------------------------------------------------------------
    if not verify_password(password, user.hashed_password):
        db.add(
            AuditLog(
                user_id=user.id,
                action="MFA_FAILED",
                ip_address=None,
                details={"reason": "invalid_password"},
            )
        )
        await db.commit()
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials",
        )

    # ------------------------------------------------------------------
    # Step 3: Verify the TOTP code.
    # On failure: commit the audit entry BEFORE raising so the event is
    # always persisted (SR-16), matching the pattern used in enable_mfa
    # and in the login MFA gate.
    # ------------------------------------------------------------------
    if not verify_totp_code(user.mfa_secret, totp_code):
        db.add(
            AuditLog(
                user_id=user.id,
                action="MFA_FAILED",
                ip_address=None,
                details={"reason": "invalid_totp_code"},
            )
        )
        await db.commit()
        raise HTTPException(status_code=401, detail="Invalid TOTP code")

    # ------------------------------------------------------------------
    # Step 4: Deactivate the MFA gate and clear the stored secret.
    # Both mutations and the success audit entry are committed atomically
    # so that the user state and the audit record are always consistent
    # (SR-04, SR-16).
    # ------------------------------------------------------------------
    user.mfa_enabled = False
    user.mfa_secret = None

    db.add(
        AuditLog(
            user_id=user.id,
            action="MFA_DISABLED",
            ip_address=None,
            details={"email": user.email},
        )
    )

    await db.commit()


async def change_password(
    user: User,
    current_password: str,
    new_password: str,
    db: AsyncSession,
) -> None:
    """Change the authenticated user's password after verifying the current one.

    Verifies current_password against the stored Argon2id hash.
    Enforces SR-01 strength policy on new_password before hashing.
    Writes a PASSWORD_CHANGED audit log entry on success (SR-16).
    Does not revoke existing sessions — see ADR-21.

    Args:
        user:             The authenticated User whose password is being changed.
        current_password: The plaintext current password to verify against the
                          stored Argon2id hash.
        new_password:     The plaintext new password.  Must satisfy SR-01.
        db:               An async SQLAlchemy session for the current request.

    Raises:
        HTTPException 401: If current_password does not match the stored hash.
        HTTPException 422: If new_password fails the SR-01 strength policy.
    """
    # ------------------------------------------------------------------
    # Step 1: Verify the supplied current password (SR-02).
    # verify_password uses passlib's constant-time Argon2id comparison.
    # ------------------------------------------------------------------
    if not verify_password(current_password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # ------------------------------------------------------------------
    # Step 2: Enforce the SR-01 strength policy on the new password.
    # Checked before hashing to avoid burning Argon2 cost on a password
    # that will be rejected anyway.
    # ------------------------------------------------------------------
    if not is_password_strong(new_password):
        raise HTTPException(
            status_code=422,
            detail="Password does not meet strength requirements",
        )

    # ------------------------------------------------------------------
    # Step 3: Hash and store the new password (SR-02).
    # The plaintext new_password is never persisted.
    # ------------------------------------------------------------------
    user.hashed_password = hash_password(new_password)

    # ------------------------------------------------------------------
    # Step 4: Write the PASSWORD_CHANGED audit log entry (SR-16).
    # The audit row and the password update are committed atomically so
    # the user state and the audit record are always consistent.
    # ------------------------------------------------------------------
    db.add(
        AuditLog(
            user_id=user.id,
            action="PASSWORD_CHANGED",
            ip_address=None,
            details={"email": user.email},
        )
    )

    # ------------------------------------------------------------------
    # Step 5: Commit both the password update and the audit entry.
    # Session revocation is intentionally omitted — see ADR-21.
    # ------------------------------------------------------------------
    await db.commit()


async def request_password_reset(
    email: str,
    db: AsyncSession,
    settings: Settings,  # noqa: ARG001  (reserved for future SMTP use)
) -> None:
    """Issue a one-time password reset token for the given email address.

    Enforces SR-18 (reset token stored as SHA-256 hash only) and the
    non-enumeration requirement: the caller receives no signal indicating
    whether the email address belongs to a registered account.

    Algorithm:
    1. Look up the user by email.
    2. If not found: write a PASSWORD_RESET_REQUESTED audit log with
       ``{"email_found": False}`` and return silently.  The HTTP response
       is always 200 so that an attacker cannot enumerate accounts by
       observing different responses for known vs unknown emails (SR-18).
    3. If found: generate a random token, store only its SHA-256 hash in
       ``user.password_reset_token_hash``, set ``password_reset_sent_at``
       to the current UTC timestamp, commit, and print the raw token to
       stdout in demo mode.  Write a PASSWORD_RESET_REQUESTED audit log
       with ``{"email_found": True}``.

    The raw token is printed in demo mode so that integration tests and
    manual testing can complete the reset flow without a real email server.
    In production this print statement must be replaced with an SMTP send.

    Args:
        email:    The email address for which a reset is requested.
        db:       An async SQLAlchemy session for the current request.
        settings: Application settings (reserved for future SMTP dispatch).

    Returns:
        None.  The caller always returns HTTP 200 regardless of whether the
        email was found, enforcing non-enumeration (SR-18).
    """
    # ------------------------------------------------------------------
    # Step 1: Look up the user by email.
    # ------------------------------------------------------------------
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()

    # ------------------------------------------------------------------
    # Step 2: Unknown email — write audit and return silently (SR-18).
    #
    # Do NOT raise an exception or change the response for an unknown
    # email.  The caller must return HTTP 200 regardless so that an
    # attacker cannot enumerate valid accounts by observing error codes.
    # ------------------------------------------------------------------
    if user is None:
        db.add(
            AuditLog(
                user_id=None,
                action="PASSWORD_RESET_REQUESTED",
                ip_address=None,
                details={"email_found": False},
            )
        )
        await db.commit()
        return

    # ------------------------------------------------------------------
    # Step 3: Known email — generate token, store hash, commit (SR-18).
    # ------------------------------------------------------------------

    # Generate a cryptographically random opaque token (256 bits entropy).
    raw_token = generate_refresh_token()

    # Store only the SHA-256 hash — the raw token is never persisted.
    user.password_reset_token_hash = hash_token(raw_token)
    user.password_reset_sent_at = datetime.now(timezone.utc)

    db.add(
        AuditLog(
            user_id=user.id,
            action="PASSWORD_RESET_REQUESTED",
            ip_address=None,
            details={"email_found": True},
        )
    )

    await db.commit()

    # DEMO MODE: replace with real SMTP in production.
    print(  # noqa: T201
        f"[DEMO MODE] Password reset token for {email}: {raw_token}"
    )


async def confirm_password_reset(
    token: str,
    new_password: str,
    db: AsyncSession,
    redis: Redis,  # type: ignore[type-arg]
    settings: Settings,
) -> None:
    """Verify a password reset token and set a new password, revoking all sessions.

    Enforces SR-01 (new password strength), SR-02 (Argon2id hashing), SR-18
    (token expiry, single-use via field clear), and SR-10/SR-07 (full session
    and refresh-token revocation on password reset so the account is fully
    re-authenticated after the credential change).

    Algorithm:
    1. Hash the submitted token with SHA-256 and look up the user by hash.
    2. If not found: raise HTTP 400 with a generic error (no enumeration).
    3. Enforce expiry window via ``settings.password_reset_token_ttl_minutes``.
       Apply ADR-17 timezone normalisation for SQLite naive datetimes.
    4. Validate new password strength (SR-01) → raise 422 if weak.
    5. Hash and store the new password (SR-02).
    6. Clear ``password_reset_token_hash`` and ``password_reset_sent_at`` so
       the token cannot be reused.
    7. Bulk-delete all ``RefreshToken`` rows for this user (SR-07).
    8. Scan Redis for all ``session:*`` keys whose stored value equals
       ``str(user.id)`` and delete them (SR-10).
    9. Commit all DB changes atomically.
    10. Write a PASSWORD_RESET_COMPLETED audit log (SR-16).

    Args:
        token:        The raw reset token received from the client.
        new_password: The plaintext new password to set.
        db:           An async SQLAlchemy session for the current request.
        redis:        The shared async Redis client for session revocation.
        settings:     Application settings supplying the token TTL and policies.

    Returns:
        None.

    Raises:
        HTTPException 400: If the token is not found or has expired.
        HTTPException 422: If new_password fails the SR-01 strength policy.
    """
    # ------------------------------------------------------------------
    # Step 1: Hash the submitted token and look up the user by hash.
    # ------------------------------------------------------------------
    token_hash = hash_token(token)
    result = await db.execute(
        select(User).where(User.password_reset_token_hash == token_hash)
    )
    user = result.scalar_one_or_none()

    # ------------------------------------------------------------------
    # Step 2: Token not found → reject with a generic message.
    #
    # The error message is intentionally identical to the expiry error
    # below so that an attacker cannot distinguish between an invalid
    # token and an expired one (no oracle).
    # ------------------------------------------------------------------
    if user is None:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired reset token",
        )

    # ------------------------------------------------------------------
    # Step 3: Expiry check (ADR-17: normalise naive datetimes from SQLite).
    #
    # SQLite returns DateTime(timezone=True) columns as naive datetimes.
    # Attaching UTC ensures the comparison is safe across both SQLite
    # (tests) and PostgreSQL (production).
    # ------------------------------------------------------------------
    sent_at = user.password_reset_sent_at
    if sent_at is None:
        # Defensive guard: hash present but timestamp missing — treat as expired.
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

    # ------------------------------------------------------------------
    # Step 4: Validate new password strength (SR-01).
    # Checked before any DB mutation so no state is changed on rejection.
    # ------------------------------------------------------------------
    if not is_password_strong(new_password):
        raise HTTPException(
            status_code=422,
            detail="Password does not meet strength requirements",
        )

    # ------------------------------------------------------------------
    # Step 5: Hash and store the new password (SR-02).
    # The plaintext new_password is never persisted.
    # ------------------------------------------------------------------
    user.hashed_password = hash_password(new_password)

    # ------------------------------------------------------------------
    # Step 6: Consume the reset token — clear both fields so the same
    # raw token cannot be reused even if the attacker captured it.
    # ------------------------------------------------------------------
    user.password_reset_token_hash = None
    user.password_reset_sent_at = None

    # ------------------------------------------------------------------
    # Step 7: Bulk-delete all refresh tokens for this user (SR-07).
    #
    # A direct DELETE statement is used rather than ORM iteration so that
    # all rows are removed in a single round-trip regardless of how many
    # active sessions the user has.
    # ------------------------------------------------------------------
    await db.execute(delete(RefreshToken).where(RefreshToken.user_id == user.id))

    # ------------------------------------------------------------------
    # Step 8: Revoke all Redis sessions for this user (SR-10).
    #
    # Sessions are stored under keys "session:{session_id}" with the value
    # set to str(user.id) (see login() above).  We scan for all session
    # keys and delete those whose stored value matches this user's ID.
    # scan_iter is non-blocking and works correctly on FakeRedis in tests.
    # ------------------------------------------------------------------
    user_id_str = str(user.id)
    keys_to_delete: list[str] = []
    async for key in redis.scan_iter("session:*"):
        value = await redis.get(key)
        if value == user_id_str:
            keys_to_delete.append(key)

    if keys_to_delete:
        await redis.delete(*keys_to_delete)

    # ------------------------------------------------------------------
    # Step 9: Write audit log entry and commit all DB mutations atomically.
    # The audit row, password update, token clear, and RT deletions are
    # all committed in a single transaction so they are always consistent.
    # ------------------------------------------------------------------
    db.add(
        AuditLog(
            user_id=user.id,
            action="PASSWORD_RESET_COMPLETED",
            ip_address=None,
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

    Args:
        user:      The authenticated, verified User requesting step-up.
        totp_code: The six-to-eight-digit TOTP code from the authenticator app.
        db:        An async SQLAlchemy session for the current request.
        redis:     The shared async Redis client for step-up token storage.
        settings:  Application settings supplying token lifetime and signing key.

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
    # ------------------------------------------------------------------
    # Step 1: Enforce the MFA prerequisite.
    # Step-up is meaningless without an enrolled second factor.  An account
    # that never enrolled MFA cannot prove elevated intent via TOTP.
    # ------------------------------------------------------------------
    if not user.mfa_enabled:
        raise HTTPException(
            status_code=403,
            detail="MFA must be enabled to use step-up authentication",
        )

    # ------------------------------------------------------------------
    # Step 2: Verify the TOTP code (SR-13).
    # On failure: commit the audit entry BEFORE raising so the event is
    # always persisted (SR-16), matching the pattern used for login and
    # enable_mfa failure paths.
    # ------------------------------------------------------------------
    if not verify_totp_code(user.mfa_secret, totp_code):
        db.add(
            AuditLog(
                user_id=user.id,
                action="STEP_UP_FAILED",
                ip_address=None,
                details={"reason": "invalid_totp_code"},
            )
        )
        await db.commit()
        raise HTTPException(status_code=401, detail="Invalid TOTP code")

    # ------------------------------------------------------------------
    # Step 3: Mint the step-up JWT (SR-13).
    # ``create_step_up_token`` returns (token, jti).  The ``typ="step_up"``
    # claim ensures that ``decode_access_token`` rejects this token if it
    # is submitted as a regular bearer credential.
    # ------------------------------------------------------------------
    token, jti = create_step_up_token(subject=str(user.id), settings=settings)

    # ------------------------------------------------------------------
    # Step 4: Store the one-time-use marker in Redis (SR-14).
    # The key is ``step_up:{jti}``.  The TTL matches the token lifetime so
    # the marker is automatically cleaned up when the token expires.
    # ``require_step_up`` will delete this key on first consumption.
    # ------------------------------------------------------------------
    ttl_seconds = settings.step_up_token_expire_minutes * 60
    await redis.set(f"step_up:{jti}", str(user.id), ex=ttl_seconds)

    # ------------------------------------------------------------------
    # Step 5: Write the success audit log entry (SR-16) and commit.
    # The audit row and the Redis write are not transactional together;
    # the Redis write is the authoritative record for the one-time-use
    # check.  The audit row exists for the human-readable audit trail.
    # ------------------------------------------------------------------
    db.add(
        AuditLog(
            user_id=user.id,
            action="STEP_UP_VERIFIED",
            ip_address=None,
            details={"jti": jti},
        )
    )
    await db.commit()

    return token


async def setup_mfa(
    user: User,
    db: AsyncSession,
    settings: Settings,
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

    Args:
        user:     The authenticated User requesting MFA enrollment.
        db:       An async SQLAlchemy session for the current request.
        settings: Application settings supplying ``app_name`` as the TOTP
                  issuer name shown inside the authenticator app.

    Returns:
        A 2-tuple ``(secret, qr_code_base64)`` where ``secret`` is the
        Base32-encoded TOTP secret and ``qr_code_base64`` is a UTF-8
        base64-encoded PNG image of the provisioning QR code.

    Raises:
        HTTPException 400: If MFA is already fully enabled on the account.
    """
    # ------------------------------------------------------------------
    # Step 1: Reject if MFA is already active (SR-04).
    # An already-enabled account must go through disable first (Phase 4).
    # ------------------------------------------------------------------
    if user.mfa_enabled:
        raise HTTPException(
            status_code=400,
            detail="MFA is already enabled",
        )

    # ------------------------------------------------------------------
    # Step 2: Generate a fresh TOTP secret (SR-04).
    # Any previously abandoned secret (mfa_secret set, mfa_enabled False)
    # is overwritten.  The old secret was never confirmed by a valid TOTP
    # code, so discarding it is the correct behaviour.
    # ------------------------------------------------------------------
    secret = generate_totp_secret()
    user.mfa_secret = secret

    # Flush so the mfa_secret write is part of the same DB transaction
    # before the audit log is appended.
    await db.flush()

    # ------------------------------------------------------------------
    # Step 3: Write the audit log entry BEFORE committing (SR-16).
    # Committing once with both the secret update and the audit row
    # ensures the two are always consistent — either both land or neither.
    # ------------------------------------------------------------------
    audit = AuditLog(
        user_id=user.id,
        action="MFA_SETUP_INITIATED",
        ip_address=None,
        details={"email": user.email},
    )
    db.add(audit)
    await db.commit()

    # ------------------------------------------------------------------
    # Step 4: Generate the QR code after committing.
    # The provisioning URI is built from the confirmed-saved secret.
    # The issuer name comes from settings.app_name (SR-04).
    # ------------------------------------------------------------------
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

    Args:
        user:      The authenticated User requesting MFA activation.
        totp_code: The six-to-eight-digit TOTP code submitted by the user.
        db:        An async SQLAlchemy session for the current request.

    Raises:
        HTTPException 400: If ``user.mfa_secret`` is None (setup was never
            initiated) or if MFA is already enabled on the account.
        HTTPException 401: If the supplied TOTP code is invalid, with a
            MFA_FAILED audit log entry committed before raising.
    """
    # ------------------------------------------------------------------
    # Step 1: Reject if no setup was ever initiated.
    # mfa_secret is None until setup_mfa is called.  An enable attempt
    # before setup has no secret to verify against — reject immediately.
    # ------------------------------------------------------------------
    if user.mfa_secret is None:
        raise HTTPException(
            status_code=400,
            detail="MFA setup not initiated",
        )

    # ------------------------------------------------------------------
    # Step 2: Reject if MFA is already active.
    # Re-enabling an already-enabled account is a no-op at best and a
    # mistake at worst.  The user must disable first (Phase 4).
    # ------------------------------------------------------------------
    if user.mfa_enabled:
        raise HTTPException(
            status_code=400,
            detail="MFA is already enabled",
        )

    # ------------------------------------------------------------------
    # Step 3 & 4: Verify the TOTP code.
    # verify_totp_code uses pyotp's constant-time HMAC comparison (SR-04).
    # On failure: commit the audit log entry BEFORE raising so the event
    # is always persisted (SR-16).
    # ------------------------------------------------------------------
    if not verify_totp_code(user.mfa_secret, totp_code):
        db.add(
            AuditLog(
                user_id=user.id,
                action="MFA_FAILED",
                ip_address=None,
                details={"reason": "invalid_totp_code"},
            )
        )
        await db.commit()
        raise HTTPException(status_code=401, detail="Invalid TOTP code")

    # ------------------------------------------------------------------
    # Step 5: Activate the MFA gate and write the success audit log.
    # Both mutations are committed in a single atomic transaction so the
    # user state and the audit record are always consistent (SR-16).
    # ------------------------------------------------------------------
    user.mfa_enabled = True

    db.add(
        AuditLog(
            user_id=user.id,
            action="MFA_ENABLED",
            ip_address=None,
            details={"email": user.email},
        )
    )

    await db.commit()
