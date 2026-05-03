"""Transactions router — Phase 5.

Exposes:
  POST /transactions/transfer  — execute a fund transfer between two accounts.
  GET  /transactions/history   — paginated transaction history for the
                                  authenticated user's account.

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
- Transaction history is scoped to the authenticated user's account inside the
  service layer; no account identifier is accepted from the client (SR-12).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Header, Query, Request
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.core.database import get_db
from app.core.redis import get_redis
from app.dependencies.auth import get_current_user, require_verified
from app.models.user import User
from app.schemas.transaction import (
    TransactionHistoryResponse,
    TransactionResponse,
    TransferRequest,
)
from app.transactions.service import execute_transfer, get_transaction_history

router = APIRouter(prefix="/transactions", tags=["transactions"])


@router.post(
    "/transfer",
    response_model=TransactionResponse,
    status_code=200,
    summary="Execute a fund transfer between two accounts",
)
async def transfer(
    body: TransferRequest,
    http_request: Request,
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

    IP address and user agent are extracted from the Nginx-forwarded headers
    (``X-Real-IP``, ``User-Agent``) and passed as plain strings to the service
    layer for audit log capture (SR-16).

    Args:
        body:            Validated ``TransferRequest`` (destination, amount,
                         description).
        http_request:    FastAPI ``Request`` object used to extract IP and UA
                         headers for audit log capture (SR-16).
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
    ip_address = http_request.headers.get("X-Real-IP") or (
        http_request.client.host if http_request.client else None
    )
    user_agent = http_request.headers.get("User-Agent")
    transaction = await execute_transfer(
        current_user=current_user,
        request=body,
        x_step_up_token=x_step_up_token,
        db=db,
        redis=redis,
        settings=settings,
        ip_address=ip_address,
        user_agent=user_agent,
    )
    return TransactionResponse.model_validate(transaction)


@router.get(
    "/history",
    response_model=TransactionHistoryResponse,
    status_code=200,
    summary="Retrieve the authenticated user's paginated transaction history",
)
async def get_history(
    http_request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    _verified: None = Depends(require_verified),
    db: AsyncSession = Depends(get_db),
) -> TransactionHistoryResponse:
    """Return a paginated transaction history for the authenticated user.

    Transactions are scoped to the user's own account server-side — no account
    identifier is accepted from the client, preventing horizontal access to
    other users' financial records (SR-12).

    Pagination query parameters:
    - ``page``      — 1-indexed page number; must be >= 1.
    - ``page_size`` — number of rows per page; must be between 1 and 100.

    A TRANSACTIONS_VIEWED audit log entry is written on every successful
    request, including requests that return an empty list (SR-16).

    IP address and user agent are extracted from the Nginx-forwarded headers
    (``X-Real-IP``, ``User-Agent``) and passed as plain strings to the service
    layer for audit log capture (SR-16).

    Args:
        http_request: FastAPI ``Request`` object used to extract IP and UA
                      headers for audit log capture (SR-16).
        page:         Requested page number (default 1, minimum 1).
        page_size:    Rows per page (default 20, range 1–100).
        current_user: Authenticated User from the Zero Trust gate.
        _verified:    Side-effect dependency that raises 403 if the user's
                      email is not verified (SR-03).
        db:           Injected async database session.

    Returns:
        ``TransactionHistoryResponse`` with ``items``, ``total``, ``page``,
        and ``page_size`` fields.

    Raises:
        HTTPException 401/403: No valid bearer token, or email not verified.
        HTTPException 422:     ``page`` < 1 or ``page_size`` outside 1–100.
    """
    ip_address = http_request.headers.get("X-Real-IP") or (
        http_request.client.host if http_request.client else None
    )
    user_agent = http_request.headers.get("User-Agent")
    return await get_transaction_history(
        current_user=current_user,
        db=db,
        page=page,
        page_size=page_size,
        ip_address=ip_address,
        user_agent=user_agent,
    )
