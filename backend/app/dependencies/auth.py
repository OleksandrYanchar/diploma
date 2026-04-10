"""FastAPI authentication dependency — get_current_user.

Provides the ``get_current_user`` dependency, which is the Zero Trust
gate on every authenticated endpoint.  No request reaches protected
business logic without passing all seven verification steps defined here.

Security properties enforced:
- SR-06: JWT signature and expiry validated on every request.
- SR-09: JTI blacklist checked so that logged-out tokens are immediately
  rejected, even within their remaining lifetime.
- SR-10: Redis session presence verified on every request so that forced
  logouts and admin-initiated session revocations take effect immediately.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import InvalidTokenError
from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.core.database import get_db
from app.core.redis import get_redis
from app.core.security import decode_access_token
from app.models.user import User


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer()),
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis),  # type: ignore[type-arg]
    settings: Settings = Depends(get_settings),
) -> User:
    """Authenticate and return the User for the incoming request.

    This dependency is the central Zero Trust verification gate.  It must
    be declared on every endpoint that requires an authenticated caller.
    All seven steps must pass; failure at any step raises an appropriate
    HTTPException and the request is rejected.

    Validation steps (strictly in order):

    1. JWT decode — ``decode_access_token`` validates the signature, expiry,
       algorithm, and ``typ=="access"`` claim.  Raises 401 on any failure.
       Enforces SR-06 (short-lived access tokens).

    2. Extract claims — ``sub`` (user_id), ``session_id``, and ``jti`` are
       pulled from the validated payload.

    3. JTI blacklist check — Redis is queried for ``blacklist:{jti}``.  If
       the key exists, the token was revoked on logout and is rejected with
       401.  Enforces SR-09 (access token blacklisting on logout).

    4. Redis session lookup — Redis is queried for ``session:{session_id}``.
       If the key is absent, the session has expired or been administratively
       revoked, and the request is rejected with 401.  If the stored value
       does not match the ``sub`` claim, a session mismatch is detected and
       the request is rejected with 401.  Enforces SR-10 (session validity
       check on every request).

    5. DB user lookup — the User row is fetched by primary key.  If no row
       exists, the token references a deleted account and is rejected with 401.

    6. User state checks — the loaded User is checked for deactivation and
       active lockout.  A deactivated account returns 403.  An account whose
       ``locked_until`` is still in the future returns 403.  Naive
       ``locked_until`` datetimes (SQLite) are normalised to UTC before
       comparison (ADR-17).

    7. Return the authenticated User to the route handler.

    Args:
        credentials: Bearer token extracted from the ``Authorization`` header
                     by ``HTTPBearer``.  HTTPBearer returns 403 when the header
                     is absent.
        db:          Injected async database session.
        redis:       Injected async Redis client.
        settings:    Injected application settings (signing key, algorithm).

    Returns:
        The authenticated and active ``User`` ORM object.

    Raises:
        HTTPException 401: Token is invalid, expired, revoked, or references a
            missing session or deleted user.
        HTTPException 403: Account is deactivated or temporarily locked.
    """
    # ------------------------------------------------------------------
    # Step 1: Decode and validate the JWT.
    # decode_access_token checks signature, expiry, algorithm, and
    # typ=="access".  Any failure raises InvalidTokenError.
    # ------------------------------------------------------------------
    try:
        payload = decode_access_token(credentials.credentials, settings)
    except InvalidTokenError as exc:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token",
        ) from exc

    # ------------------------------------------------------------------
    # Step 2: Extract required claims from the validated payload.
    # ------------------------------------------------------------------
    user_id: str = payload["sub"]
    session_id: str = payload["session_id"]
    jti: str = payload["jti"]

    # ------------------------------------------------------------------
    # Step 3: JTI blacklist check (SR-09).
    # A non-None result means the token was placed on the blacklist at
    # logout.  Reject it even though the JWT itself is still valid.
    # ------------------------------------------------------------------
    blacklisted = await redis.get(f"blacklist:{jti}")
    if blacklisted is not None:
        raise HTTPException(
            status_code=401,
            detail="Token has been revoked",
        )

    # ------------------------------------------------------------------
    # Step 4: Redis session lookup (SR-10).
    # Every request must prove that a live session exists.  A valid JWT
    # is not sufficient — the session may have been administratively
    # revoked after the token was issued.
    # ------------------------------------------------------------------
    session_value = await redis.get(f"session:{session_id}")
    if session_value is None:
        raise HTTPException(
            status_code=401,
            detail="Session not found or expired",
        )
    if session_value != user_id:
        raise HTTPException(
            status_code=401,
            detail="Session mismatch",
        )

    # ------------------------------------------------------------------
    # Step 5: Database user lookup.
    # The token may reference a user that has since been hard-deleted.
    #
    # The JWT sub claim is a plain string; the User.id column is defined
    # as UUID(as_uuid=True), which requires a uuid.UUID object for the
    # SQLite dialect's type processor (it calls .hex on the bound value).
    # Convert explicitly to avoid a StatementError on SQLite in tests.
    # ------------------------------------------------------------------
    try:
        user_uuid = uuid.UUID(user_id)
    except ValueError as exc:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token",
        ) from exc

    result = await db.execute(select(User).where(User.id == user_uuid))
    user: User | None = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(
            status_code=401,
            detail="User not found",
        )

    # ------------------------------------------------------------------
    # Step 6: User state checks.
    # Deactivated accounts are rejected with 403 (not 401) because the
    # credential itself is valid — the account has been disabled by an
    # administrator.  Lockout is similarly a 403: the user's session is
    # authentic but the account is temporarily unavailable.
    #
    # ADR-17: SQLite stores DateTime without timezone info.  Normalise a
    # naive locked_until to UTC before comparing with aware utcnow().
    # ------------------------------------------------------------------
    if not user.is_active:
        raise HTTPException(
            status_code=403,
            detail="Account is deactivated",
        )

    if user.locked_until is not None:
        locked_until = user.locked_until
        if locked_until.tzinfo is None:
            # Normalise naive datetime from SQLite to UTC-aware (ADR-17).
            locked_until = locked_until.replace(tzinfo=timezone.utc)
        if locked_until > datetime.now(tz=timezone.utc):
            raise HTTPException(
                status_code=403,
                detail="Account is temporarily locked",
            )

    # ------------------------------------------------------------------
    # Step 7: All checks passed — return the authenticated user.
    # ------------------------------------------------------------------
    return user
