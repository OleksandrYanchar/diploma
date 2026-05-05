"""FastAPI authentication dependencies — get_current_user and require_verified.

Provides:
- ``get_current_user``: the Zero Trust gate on every authenticated endpoint.
  No request reaches protected business logic without passing all seven
  verification steps defined here.
- ``require_verified``: a secondary dependency that enforces email
  verification.  Must be declared on every endpoint where an unverified
  account must not have access (SR-03).

Security properties enforced:
- SR-03: Email verification status checked via ``require_verified``.
- SR-06: JWT signature and expiry validated on every request.
- SR-09: JTI blacklist checked so that logged-out tokens are immediately
  rejected, even within their remaining lifetime.
- SR-10: Redis session presence verified on every request so that forced
  logouts and admin-initiated session revocations take effect immediately.
"""

import uuid
from collections.abc import Awaitable, Callable
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
from app.models.user import User, UserRole


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer()),
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis),  # type: ignore[type-arg]
    settings: Settings = Depends(get_settings),
) -> User:
    """Authenticate and return the User for the incoming request.

    This dependency is the central Zero Trust verification gate.  It must
    be declared on every endpoint that requires an authenticated caller.
    Checks JWT signature+expiry (SR-06), JTI blacklist (SR-09), Redis
    session presence (SR-10), DB user existence, and account state.

    Raises:
        HTTPException 401: Token is invalid, expired, revoked, or references a
            missing session or deleted user.
        HTTPException 403: Account is deactivated or temporarily locked.
    """

    try:
        payload = decode_access_token(credentials.credentials, settings)
    except InvalidTokenError as exc:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token",
        ) from exc

    user_id: str = payload["sub"]
    session_id: str = payload["session_id"]
    jti: str = payload["jti"]

    blacklisted = await redis.get(f"blacklist:{jti}")
    if blacklisted is not None:
        raise HTTPException(
            status_code=401,
            detail="Token has been revoked",
        )

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

    if not user.is_active:
        raise HTTPException(
            status_code=403,
            detail="Account is deactivated",
        )

    if user.locked_until is not None:
        locked_until = user.locked_until
        if locked_until.tzinfo is None:
            locked_until = locked_until.replace(tzinfo=timezone.utc)
        if locked_until > datetime.now(tz=timezone.utc):
            raise HTTPException(
                status_code=403,
                detail="Account is temporarily locked",
            )

    return user


async def require_verified(
    current_user: User = Depends(get_current_user),
) -> None:
    """Enforce that the authenticated user has a verified email address.

    This dependency is a secondary guard that must be declared alongside
    ``get_current_user`` on any endpoint where unverified accounts must be
    blocked (SR-03).  It does not return anything useful — it is a
    side-effect-only dependency used to gate access.

    ``get_current_user`` is still required separately when the route needs
    the ``User`` object.  ``require_verified`` only raises or returns None.

    Raises:
        HTTPException 403: If ``current_user.is_verified`` is False (SR-03).
    """
    if not current_user.is_verified:
        raise HTTPException(
            status_code=403,
            detail="Email address is not verified",
        )


def require_role(*roles: UserRole) -> Callable[[User], Awaitable[None]]:
    """Factory that returns an async dependency enforcing RBAC role membership.

    Primary mechanism for enforcing SR-11 (RBAC) on protected endpoints.
    Declare alongside ``get_current_user``; reads ``current_user.role``
    without an extra DB query.

    Raises (inner callable):
        HTTPException 403: If ``current_user.role`` is not in ``roles`` (SR-11).
    """

    async def _check_role(
        current_user: User = Depends(get_current_user),
    ) -> None:
        """Raise 403 if the authenticated user's role is not in the captured roles."""
        if current_user.role not in roles:
            raise HTTPException(
                status_code=403,
                detail="Insufficient permissions",
            )

    return _check_role
