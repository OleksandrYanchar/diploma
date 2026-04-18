"""Transactions router — Phase 5.

Exposes:
  POST /transactions/transfer — execute a fund transfer between two accounts.

Route handlers are intentionally thin: HTTP concerns only.  All business
logic lives in ``transactions/service.py``.

Security notes:
- Every request must pass the Zero Trust gate (``get_current_user``).
- Email verification is required before any financial operation (``require_verified``,
  SR-03).
- The step-up authentication threshold is enforced server-side in the service
  layer.  The route accepts the optional ``X-Step-Up-Token`` header and passes
  it through; the service decides whether it is required based on the transfer
  amount (SR-13, SR-14).
- The ``X-Step-Up-Token`` header is NOT declared as a FastAPI dependency here
  because the requirement is conditional on the amount — an unconditional
  ``require_step_up`` dependency would block all transfers regardless of size.
  The service enforces the gate only when ``amount >= threshold``.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Header
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.core.database import get_db
from app.core.redis import get_redis
from app.dependencies.auth import get_current_user, require_verified
from app.models.user import User
from app.schemas.transaction import TransactionResponse, TransferRequest
from app.transactions.service import execute_transfer

router = APIRouter(prefix="/transactions", tags=["transactions"])


@router.post(
    "/transfer",
    response_model=TransactionResponse,
    status_code=200,
    summary="Execute a fund transfer between two accounts",
)
async def transfer(
    request: TransferRequest,
    current_user: User = Depends(get_current_user),
    _verified: None = Depends(require_verified),
    x_step_up_token: str | None = Header(default=None, alias="X-Step-Up-Token"),
    db: AsyncSession = Depends(get_db),
    redis: Redis = Depends(get_redis),  # type: ignore[type-arg]
    settings: Settings = Depends(get_settings),
) -> TransactionResponse:
    """Execute a fund transfer from the authenticated user's account.

    Transfers at or above the configured threshold
    (``settings.step_up_transfer_threshold``) require a valid, single-use
    step-up token in the ``X-Step-Up-Token`` header.  The threshold decision
    is enforced server-side in ``execute_transfer`` — clients cannot bypass it
    by omitting the header on a below-threshold amount.

    Ownership of the source account is derived from the authenticated user
    (SR-12).  The destination is resolved by public ``account_number`` to
    prevent IDOR enumeration (T-02).

    Args:
        request:         Validated ``TransferRequest`` (destination, amount,
                         description).
        current_user:    Authenticated User from the Zero Trust gate.
        _verified:       Side-effect dependency that raises 403 if the user's
                         email is not verified (SR-03).
        x_step_up_token: Optional raw JWT from the ``X-Step-Up-Token`` header.
                         Required by the service when amount >= threshold.
        db:              Injected async database session.
        redis:           Injected async Redis client.
        settings:        Injected application settings.

    Returns:
        The completed ``TransactionResponse`` with HTTP 200.

    Raises:
        HTTPException 400: Source account absent or not ACTIVE, destination
            absent or not ACTIVE, or insufficient balance.
        HTTPException 403: Email not verified, or step-up token absent /
            invalid / expired / already consumed (when amount >= threshold).
        HTTPException 422: Self-transfer attempt, or invalid request body.
    """
    transaction = await execute_transfer(
        current_user=current_user,
        request=request,
        x_step_up_token=x_step_up_token,
        db=db,
        redis=redis,
        settings=settings,
    )
    return TransactionResponse.model_validate(transaction)
