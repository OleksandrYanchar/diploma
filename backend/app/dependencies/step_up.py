"""FastAPI step-up authentication dependency.

Provides ``require_step_up``, a side-effect-only dependency that enforces
the single-use step-up token gate on sensitive endpoints (e.g., fund
transfers).  It must be declared alongside ``get_current_user`` in any route
handler that requires step-up re-verification.

Security properties enforced:
- SR-13: The caller must present a valid, unexpired step-up JWT in the
  ``X-Step-Up-Token`` header.  The token must have been issued by
  ``verify_step_up`` (POST /auth/step-up) after TOTP re-verification.
- SR-14: Each step-up token is single-use.  The JTI is stored in Redis as a
  one-time-use marker.  ``require_step_up`` atomically consumes the marker via
  ``getdel``; any subsequent presentation of the same token finds the Redis key
  absent and is rejected with 403.
- SR-16: A ``STEP_UP_BYPASS_ATTEMPT`` audit log entry and a HIGH-severity
  ``SecurityEvent`` row are both committed before raising on any
  subject-mismatch attempt, ensuring the events are always persisted
  regardless of exception handling above this call site.
"""

from fastapi import Depends, Header, HTTPException, Request
from jwt import InvalidTokenError
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.core.database import get_db
from app.core.redis import get_redis
from app.core.security import decode_step_up_token
from app.dependencies.auth import get_current_user
from app.models.audit_log import AuditLog
from app.models.security_event import SecurityEvent, Severity
from app.models.user import User


async def require_step_up(
    request: Request,
    x_step_up_token: str | None = Header(default=None, alias="X-Step-Up-Token"),
    current_user: User = Depends(get_current_user),
    redis: Redis = Depends(get_redis),  # type: ignore[type-arg]
    settings: Settings = Depends(get_settings),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Enforce that the caller holds a valid, unconsumed step-up token.

    Side-effect-only gate for SR-13/SR-14: validates the step-up token
    (signature, expiry, ``typ=="step_up"``), checks subject binding, and
    atomically consumes the single-use Redis marker via ``getdel``.

    Raises:
        HTTPException 403: If the step-up token is absent, invalid, expired,
            bound to a different user, or has already been consumed.
    """
    if x_step_up_token is None:
        raise HTTPException(
            status_code=403,
            detail="Step-up authentication required",
            headers={"X-Step-Up-Required": "true"},
        )

    try:
        payload = decode_step_up_token(x_step_up_token, settings)
    except InvalidTokenError as exc:
        raise HTTPException(
            status_code=403,
            detail="Invalid or expired step-up token",
        ) from exc

    jti: str = payload["jti"]
    sub: str = payload["sub"]

    if sub != str(current_user.id):
        ip_address: str | None = request.headers.get("X-Real-IP") or (
            request.client.host if request.client else None
        )
        user_agent: str | None = request.headers.get("User-Agent")
        db.add(
            AuditLog(
                user_id=current_user.id,
                action="STEP_UP_BYPASS_ATTEMPT",
                ip_address=ip_address,
                user_agent=user_agent,
                details={
                    "reason": "subject_mismatch",
                    "token_sub": sub,
                    "current_user_id": str(current_user.id),
                },
            )
        )

        db.add(
            SecurityEvent(
                user_id=current_user.id,
                event_type="STEP_UP_BYPASS_ATTEMPT",
                severity=Severity.HIGH,
                ip_address=ip_address,
                details={
                    "reason": "subject_mismatch",
                    "token_sub": sub,
                },
            )
        )
        await db.commit()
        raise HTTPException(
            status_code=403,
            detail="Step-up token subject mismatch",
        )

    consumed = await redis.getdel(f"step_up:{jti}")
    if consumed is None:
        raise HTTPException(
            status_code=403,
            detail="Step-up token has already been used or expired",
        )

    return None
