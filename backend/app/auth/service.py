"""Authentication service — registration, verification, login, refresh, and logout.

This module implements the core business logic for user registration, email
address verification, login with session creation, logout with session
teardown, and refresh token rotation with reuse detection.  It has no HTTP
concerns: no Request or Response objects, no dependency injection containers.
All inputs are plain Python values; the caller (router) is responsible for
extracting them from the HTTP layer.

Security properties enforced:
- SR-01: Password strength validated via ``is_password_strong`` before hashing.
- SR-02: Passwords stored as Argon2id hash only — plaintext is never persisted.
- SR-03: Email verification token stored as SHA-256 hash; raw token delivered
  out-of-band (console in demo mode).
- SR-05: Account lockout after N consecutive failed login attempts.
- SR-06: Access tokens are short-lived JWTs issued on successful login.
- SR-07: Refresh tokens stored as SHA-256 hash; raw token returned to client once.
- SR-08: Refresh token reuse detection: a second presentation of an already-rotated
  token destroys the entire Redis session, forcing full re-authentication.
- SR-09: Access token JTI blacklisted in Redis on logout with remaining TTL.
- SR-10: Redis session created on login keyed by session_id; deleted on logout or
  on reuse detection.
- SR-16: Audit log entries created for REGISTER, EMAIL_VERIFIED, LOGIN_SUCCESS,
  LOGIN_FAILED, LOGOUT, and TOKEN_REFRESHED events.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

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
        email:    The email address supplied by the authenticating user.
        password: The plaintext password supplied by the authenticating user.
        db:       An async SQLAlchemy session for the current request.
        redis:    The shared async Redis client for session storage (SR-10).
        settings: Application settings supplying token lifetimes and lockout policy.

    Returns:
        A 2-tuple ``(access_token, raw_refresh_token)`` on successful
        authentication, where ``access_token`` is a compact JWT string and
        ``raw_refresh_token`` is the opaque token that must be returned to the
        client and never stored plaintext server-side.

        Returns ``(None, None)`` when the password is correct but MFA is enabled
        on the account.  The router must detect this sentinel and return an
        ``MFARequiredResponse`` (HTTP 200) instead of a ``TokenResponse``.  No
        session is created and no tokens are issued on this path.

    Raises:
        HTTPException 401: If credentials are invalid (wrong email or password).
            The same message is returned in both cases to prevent enumeration.
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
    #
    # Returning (None, None) rather than raising an HTTPException avoids the
    # incorrect pattern of using HTTP 200 as an exception status code, which
    # bypasses FastAPI's response_model serialization.  The router detects the
    # sentinel and returns an MFARequiredResponse with HTTP 200.  No session is
    # created and no tokens are issued on this path.
    # ------------------------------------------------------------------
    if user.mfa_enabled:
        # SR-16: Audit log for the MFA gate event (password verified, TOTP pending).
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
