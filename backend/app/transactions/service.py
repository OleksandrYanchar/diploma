"""Transactions service — transfer execution with step-up threshold gate.

Implements the business logic for the transactions module:

Security properties enforced:
- SR-12: Source account is looked up by ``user_id = current_user.id`` — no
  account identifier is accepted from the client for the source side.
- SR-13/SR-14: Transfers at or above ``settings.step_up_transfer_threshold``
  require a valid, unconsumed step-up token presented in the request.  The
  step-up token is validated inline using the same primitives as
  ``require_step_up`` (``decode_step_up_token`` + ``redis.getdel``).
- SR-16: Audit log entries are written for every transfer outcome
  (TRANSFER_INITIATED, TRANSFER_COMPLETED, TRANSFER_REJECTED).
- SR-20: Balance arithmetic uses Python ``Decimal`` exclusively.  The account
  ``balance`` column is ``Numeric(18,2)``; SQLAlchemy returns ``Decimal`` for
  that type, so no float coercion ever occurs.
- T-02: Destination is resolved by public ``account_number`` — internal UUIDs
  are never accepted from the client, preventing IDOR enumeration.
"""

import uuid
from decimal import Decimal

from fastapi import HTTPException
from jwt import InvalidTokenError
from redis.asyncio import Redis
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.security import decode_step_up_token
from app.models.account import Account, AccountStatus
from app.models.audit_log import AuditLog
from app.models.security_event import SecurityEvent, Severity
from app.models.transaction import Transaction, TransactionStatus, TransactionType
from app.models.user import User
from app.schemas.transaction import (
    TransactionHistoryResponse,
    TransactionResponse,
    TransferRequest,
)


async def _write_audit(
    db: AsyncSession,
    user_id: uuid.UUID,
    action: str,
    details: dict,  # type: ignore[type-arg]
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> None:
    """Append an audit log entry and commit it immediately.

    Committing immediately ensures the record is persisted even if the calling
    code raises an exception afterwards.  This matches the pattern used by the
    auth service for MFA_FAILED and STEP_UP_BYPASS_ATTEMPT entries (SR-16).
    """
    db.add(
        AuditLog(
            user_id=user_id,
            action=action,
            ip_address=ip_address,
            user_agent=user_agent,
            details=details,
        )
    )
    await db.commit()


async def _validate_step_up_token(
    x_step_up_token: str | None,
    current_user: User,
    redis: Redis,  # type: ignore[type-arg]
    settings: Settings,
    db: AsyncSession,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> None:
    """Validate the step-up token when a transfer meets the threshold.

    Replicates the same validation logic as ``require_step_up`` without being
    a FastAPI dependency.  Called only when ``request.amount >= threshold``.

    Raises:
        HTTPException 403: If the token is absent, invalid, expired, bound to
            a different user, or has already been consumed (SR-13, SR-14).
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
        await _write_audit(
            db=db,
            user_id=current_user.id,
            action="STEP_UP_BYPASS_ATTEMPT",
            details={
                "reason": "subject_mismatch",
                "token_sub": sub,
                "current_user_id": str(current_user.id),
            },
            ip_address=ip_address,
            user_agent=user_agent,
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


async def execute_transfer(
    current_user: User,
    request: TransferRequest,
    x_step_up_token: str | None,
    db: AsyncSession,
    redis: Redis,  # type: ignore[type-arg]
    settings: Settings,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> Transaction:
    """Execute a fund transfer from the authenticated user's account.

    Enforces every validation check in a strict order and writes audit log
    entries for both successful and rejected transfers (SR-16).  Balance
    arithmetic is performed atomically inside a savepoint (SR-20).

    The step-up threshold is enforced server-side: if ``request.amount`` is at
    or above ``settings.step_up_transfer_threshold`` (expressed in cents), the
    caller must supply a valid, unconsumed step-up token in ``x_step_up_token``
    (SR-13, SR-14).

    Returns:
        The newly created ``Transaction`` row with status COMPLETED.

    Raises:
        HTTPException 400: Source account absent, INACTIVE/FROZEN, destination
            absent, destination INACTIVE/FROZEN, or insufficient balance.
        HTTPException 403: Step-up token absent, invalid, expired, bound to
            a different user, or already consumed (when amount >= threshold).
        HTTPException 422: Self-transfer attempt.
    """
    await _write_audit(
        db=db,
        user_id=current_user.id,
        action="TRANSFER_INITIATED",
        details={
            "to_account_number": request.to_account_number,
            "amount": str(request.amount),
        },
        ip_address=ip_address,
        user_agent=user_agent,
    )

    result = await db.execute(select(Account).where(Account.user_id == current_user.id))
    from_account: Account | None = result.scalar_one_or_none()

    if from_account is None:
        await _write_audit(
            db=db,
            user_id=current_user.id,
            action="TRANSFER_REJECTED",
            details={"reason": "no_account"},
            ip_address=ip_address,
            user_agent=user_agent,
        )
        raise HTTPException(status_code=400, detail="No account found")

    # Only ACTIVE accounts may initiate transfers (T-02).
    if from_account.status != AccountStatus.ACTIVE:
        await _write_audit(
            db=db,
            user_id=current_user.id,
            action="TRANSFER_REJECTED",
            details={
                "reason": "account_not_active",
                "account_id": str(from_account.id),
            },
            ip_address=ip_address,
            user_agent=user_agent,
        )
        raise HTTPException(status_code=400, detail="Account is not active")

    dest_result = await db.execute(
        select(Account).where(Account.account_number == request.to_account_number)
    )
    to_account: Account | None = dest_result.scalar_one_or_none()

    if to_account is None:
        await _write_audit(
            db=db,
            user_id=current_user.id,
            action="TRANSFER_REJECTED",
            details={
                "reason": "destination_not_found",
                "to_account_number": request.to_account_number,
            },
            ip_address=ip_address,
            user_agent=user_agent,
        )
        raise HTTPException(status_code=400, detail="Destination account not found")

    if from_account.id == to_account.id:
        await _write_audit(
            db=db,
            user_id=current_user.id,
            action="TRANSFER_REJECTED",
            details={
                "reason": "self_transfer",
                "account_id": str(from_account.id),
            },
            ip_address=ip_address,
            user_agent=user_agent,
        )
        raise HTTPException(status_code=422, detail="Cannot transfer to own account")

    # Reject transfers to INACTIVE or FROZEN destination accounts (T-02).
    if to_account.status != AccountStatus.ACTIVE:
        await _write_audit(
            db=db,
            user_id=current_user.id,
            action="TRANSFER_REJECTED",
            details={
                "reason": "destination_not_active",
                "to_account_number": request.to_account_number,
            },
            ip_address=ip_address,
            user_agent=user_agent,
        )
        raise HTTPException(status_code=400, detail="Destination account is not active")

    threshold: Decimal = Decimal(settings.step_up_transfer_threshold) / Decimal(100)
    if request.amount >= threshold:
        try:
            await _validate_step_up_token(
                x_step_up_token=x_step_up_token,
                current_user=current_user,
                redis=redis,
                settings=settings,
                db=db,
                ip_address=ip_address,
                user_agent=user_agent,
            )
        except HTTPException:
            await _write_audit(
                db=db,
                user_id=current_user.id,
                action="TRANSFER_REJECTED",
                details={
                    "reason": "step_up_required"
                    if x_step_up_token is None
                    else "invalid_step_up",
                    "amount": str(request.amount),
                    "threshold": str(threshold),
                },
                ip_address=ip_address,
                user_agent=user_agent,
            )
            raise

    if from_account.balance < request.amount:
        await _write_audit(
            db=db,
            user_id=current_user.id,
            action="TRANSFER_REJECTED",
            details={
                "reason": "insufficient_balance",
                "balance": str(from_account.balance),
                "requested": str(request.amount),
            },
            ip_address=ip_address,
            user_agent=user_agent,
        )
        raise HTTPException(status_code=400, detail="Insufficient balance")

    transaction: Transaction
    async with db.begin_nested():
        from_account.balance -= request.amount
        to_account.balance += request.amount

        transaction = Transaction(
            from_account_id=from_account.id,
            to_account_id=to_account.id,
            amount=request.amount,
            transaction_type=TransactionType.TRANSFER,
            status=TransactionStatus.COMPLETED,
            description=request.description,
        )
        db.add(transaction)
        await db.flush()

    await db.commit()
    await db.refresh(transaction)

    await _write_audit(
        db=db,
        user_id=current_user.id,
        action="TRANSFER_COMPLETED",
        details={
            "transaction_id": str(transaction.id),
            "from_account_id": str(from_account.id),
            "to_account_id": str(to_account.id),
            "amount": str(request.amount),
        },
        ip_address=ip_address,
        user_agent=user_agent,
    )

    return transaction


async def get_transaction_history(
    current_user: User,
    db: AsyncSession,
    page: int,
    page_size: int,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> TransactionHistoryResponse:
    """Return a paginated list of transactions for the authenticated user.

    User scoping: the account is always resolved by ``user_id = current_user.id``.
    The client never supplies an account ID, which prevents horizontal access to
    other users' transaction history (SR-12).

    If the user has no account, an empty response is returned — this is not an
    error, it simply means the user has not yet opened an account.

    Pagination: ``page`` is 1-indexed; ``page_size`` controls the number of rows
    returned.  Both are validated at the route layer before this function is
    called.

    An audit log entry (TRANSACTIONS_VIEWED) is written after every successful
    fetch — including empty ones — and committed immediately (SR-16).

    Returns:
        ``TransactionHistoryResponse`` containing a paginated list of
        ``TransactionResponse`` items, the total count, current page, and
        page size.
    """
    account_result = await db.execute(
        select(Account).where(Account.user_id == current_user.id)
    )
    account: Account | None = account_result.scalar_one_or_none()

    if account is None:
        await _write_audit(
            db=db,
            user_id=current_user.id,
            action="TRANSACTIONS_VIEWED",
            details={"page": page, "page_size": page_size, "total": 0},
            ip_address=ip_address,
            user_agent=user_agent,
        )
        return TransactionHistoryResponse(
            items=[],
            total=0,
            page=page,
            page_size=page_size,
        )

    count_result = await db.execute(
        select(func.count()).where(
            (Transaction.from_account_id == account.id)
            | (Transaction.to_account_id == account.id)
        )
    )
    total: int = count_result.scalar_one()

    offset = (page - 1) * page_size
    rows_result = await db.execute(
        select(Transaction)
        .where(
            (Transaction.from_account_id == account.id)
            | (Transaction.to_account_id == account.id)
        )
        .order_by(Transaction.created_at.desc())
        .limit(page_size)
        .offset(offset)
    )
    rows = rows_result.scalars().all()

    await _write_audit(
        db=db,
        user_id=current_user.id,
        action="TRANSACTIONS_VIEWED",
        details={
            "page": page,
            "page_size": page_size,
            "total": total,
            "account_id": str(account.id),
        },
        ip_address=ip_address,
        user_agent=user_agent,
    )

    return TransactionHistoryResponse(
        items=[TransactionResponse.model_validate(t) for t in rows],
        total=total,
        page=page,
        page_size=page_size,
    )
