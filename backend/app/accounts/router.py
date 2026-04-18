"""Accounts router — Phase 5.

Exposes:
  GET /accounts/me — return the authenticated verified user's account.

Route handlers are intentionally thin: HTTP concerns only.  All business
logic lives in ``accounts/service.py``.

Security note: this endpoint requires both authentication (``get_current_user``)
and email verification (``require_verified``).  Unverified users may not access
financial resources (SR-03, SR-12).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.accounts.service import get_or_create_account, write_account_viewed_audit
from app.core.database import get_db
from app.dependencies.auth import get_current_user, require_verified
from app.models.user import User
from app.schemas.account import AccountResponse

router = APIRouter(prefix="/accounts", tags=["accounts"])


@router.get(
    "/me",
    response_model=AccountResponse,
    status_code=200,
    summary="Return the authenticated user's account",
)
async def get_account_me(
    current_user: User = Depends(get_current_user),
    _verified: None = Depends(require_verified),
    db: AsyncSession = Depends(get_db),
) -> AccountResponse:
    """Return the authenticated verified user's single account.

    If the user has no account yet (first access after email verification),
    one is created automatically with a demo seed balance.  Account creation
    is idempotent: concurrent calls for the same user are safe because the DB
    enforces uniqueness on ``accounts.user_id`` (SR-12, migration 0004).

    An ACCOUNT_VIEWED audit log entry is written on every successful response
    (SR-16).

    Args:
        current_user: Authenticated ``User`` from ``get_current_user``.
        _verified:    Side-effect dependency that raises 403 if the user's
                      email is not verified (SR-03).
        db:           Injected async database session.

    Returns:
        The user's ``AccountResponse`` with HTTP 200.

    Raises:
        HTTPException 401: Token is invalid, expired, revoked, or session absent.
        HTTPException 403: Authorization header missing, account deactivated,
            locked, or email not verified.
    """
    account = await get_or_create_account(user=current_user, db=db)
    await write_account_viewed_audit(
        user_id=current_user.id,
        account_id=account.id,
        db=db,
    )
    return AccountResponse.model_validate(account)
