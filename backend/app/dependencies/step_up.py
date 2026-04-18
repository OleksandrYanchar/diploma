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
- SR-16: A ``STEP_UP_BYPASS_ATTEMPT`` audit log entry is committed before
  raising on any subject-mismatch attempt, ensuring the event is always
  persisted regardless of exception handling above this call site.
"""

from __future__ import annotations

from fastapi import Depends, Header, HTTPException
from jwt import InvalidTokenError
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.core.database import get_db
from app.core.redis import get_redis
from app.core.security import decode_step_up_token
from app.dependencies.auth import get_current_user
from app.models.audit_log import AuditLog
from app.models.user import User


async def require_step_up(
    x_step_up_token: str | None = Header(default=None, alias="X-Step-Up-Token"),
    current_user: User = Depends(get_current_user),
    redis: Redis = Depends(get_redis),  # type: ignore[type-arg]
    settings: Settings = Depends(get_settings),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Enforce that the caller holds a valid, unconsumed step-up token.

    This dependency is a side-effect-only gate for sensitive endpoints that
    require step-up re-verification (SR-13, SR-14).  It must be declared
    alongside ``get_current_user`` in route handler signatures — it does not
    return the user object.

    Validation steps (strictly in order):

    1. Header presence — if ``X-Step-Up-Token`` is absent, raise 403 with
       response header ``X-Step-Up-Required: true`` so the client knows to
       initiate a step-up flow before retrying.

    2. JWT decode and type check — ``decode_step_up_token`` validates the
       signature, expiry, algorithm, and ``typ=="step_up"`` claim.  Raises 403
       on any failure (InvalidTokenError).

    3. Claim extraction — ``jti`` (token ID) and ``sub`` (user ID) are pulled
       from the validated payload.

    4. Subject binding check — ``sub`` must equal ``str(current_user.id)``.  A
       mismatch means the step-up token was issued for a different user.  A
       ``STEP_UP_BYPASS_ATTEMPT`` audit log entry is committed BEFORE raising
       the exception so the event is always persisted (SR-16).

    5. Atomic single-use consumption — ``redis.getdel(f"step_up:{jti}")``
       atomically reads and deletes the Redis marker in a single operation.  If
       the result is None (key absent, already consumed, or TTL-expired), the
       token has already been used and the request is rejected with 403.  On a
       non-None result the key is gone — concurrent requests with the same
       token see None and are rejected (SR-14).

    6. Return None — the dependency has no return value; it is used solely for
       its side effect of raising HTTPException when any check fails.

    Usage in a route handler signature::

        @router.post("/transfers")
        async def initiate_transfer(
            current_user: User = Depends(get_current_user),
            _verified: None = Depends(require_verified),
            _step_up: None = Depends(require_step_up),
        ) -> ...:

    Args:
        x_step_up_token: Raw JWT from the ``X-Step-Up-Token`` request header.
                         FastAPI injects ``None`` when the header is absent.
        current_user:    The authenticated User provided by ``get_current_user``.
                         ``get_current_user`` must pass all seven Zero Trust
                         checks before this dependency is evaluated.
        redis:           Injected async Redis client (used for ``getdel``).
        settings:        Injected application settings (signing key, algorithm).
        db:              Injected async database session (used for audit log on
                         subject mismatch).

    Returns:
        None (used solely for its side effect).

    Raises:
        HTTPException 403: If the step-up token is absent, invalid, expired,
            bound to a different user, or has already been consumed.
    """
    # ------------------------------------------------------------------
    # Step 1: Header presence check.
    # The X-Step-Up-Required response header signals to the client that it
    # must complete the step-up flow (POST /auth/step-up) before retrying.
    # ------------------------------------------------------------------
    if x_step_up_token is None:
        raise HTTPException(
            status_code=403,
            detail="Step-up authentication required",
            headers={"X-Step-Up-Required": "true"},
        )

    # ------------------------------------------------------------------
    # Step 2: JWT decode and type validation.
    # decode_step_up_token checks signature, expiry, algorithm, and
    # typ=="step_up".  An access token submitted here is rejected by the
    # typ check — the two token types share the same signing key but are
    # not interchangeable.
    # ------------------------------------------------------------------
    try:
        payload = decode_step_up_token(x_step_up_token, settings)
    except InvalidTokenError as exc:
        raise HTTPException(
            status_code=403,
            detail="Invalid or expired step-up token",
        ) from exc

    # ------------------------------------------------------------------
    # Step 3: Extract claims from the validated payload.
    # ------------------------------------------------------------------
    jti: str = payload["jti"]
    sub: str = payload["sub"]

    # ------------------------------------------------------------------
    # Step 4: Subject binding check.
    # The step-up token sub must match the bearer token sub (current_user).
    # A mismatch indicates an attempt to use another user's step-up token.
    # Commit the audit entry BEFORE raising so the event is always
    # persisted regardless of exception handling above this call site
    # (SR-16) — matching the pattern used for STEP_UP_FAILED and MFA_FAILED.
    # ------------------------------------------------------------------
    if sub != str(current_user.id):
        db.add(
            AuditLog(
                user_id=current_user.id,
                action="STEP_UP_BYPASS_ATTEMPT",
                ip_address=None,
                details={
                    "reason": "subject_mismatch",
                    "token_sub": sub,
                    "current_user_id": str(current_user.id),
                },
            )
        )
        await db.commit()
        raise HTTPException(
            status_code=403,
            detail="Step-up token subject mismatch",
        )

    # ------------------------------------------------------------------
    # Step 5: Atomic single-use consumption (SR-14).
    # getdel atomically reads and deletes the key in one Redis round-trip.
    # If the key is absent (already consumed or TTL-expired), result is
    # None and the token is rejected.  There is no TOCTOU window between
    # the check and the delete because both happen in the same command.
    # ------------------------------------------------------------------
    consumed = await redis.getdel(f"step_up:{jti}")
    if consumed is None:
        raise HTTPException(
            status_code=403,
            detail="Step-up token has already been used or expired",
        )

    # ------------------------------------------------------------------
    # Step 6: All checks passed — return None (side-effect dependency).
    # ------------------------------------------------------------------
    return None
