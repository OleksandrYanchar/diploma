"""Transactions service — transfer execution with step-up threshold gate.

Implements the business logic for the transactions module:

- ``execute_transfer``: validates source and destination accounts, enforces
  the step-up authentication threshold, atomically updates both balances,
  creates a Transaction row, and writes audit log entries for every outcome.

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

from __future__ import annotations

import uuid
from decimal import Decimal

from fastapi import HTTPException
from jwt import InvalidTokenError
from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.security import decode_step_up_token
from app.models.account import Account, AccountStatus
from app.models.audit_log import AuditLog
from app.models.transaction import Transaction, TransactionStatus, TransactionType
from app.models.user import User
from app.schemas.transaction import TransferRequest


async def _write_audit(
    db: AsyncSession,
    user_id: uuid.UUID,
    action: str,
    details: dict,  # type: ignore[type-arg]
) -> None:
    """Append an audit log entry and commit it immediately.

    Committing immediately ensures the record is persisted even if the calling
    code raises an exception afterwards.  This matches the pattern used by the
    auth service for MFA_FAILED and STEP_UP_BYPASS_ATTEMPT entries (SR-16).

    Args:
        db:       The active async database session.
        user_id:  UUID of the user performing the action.
        action:   Audit action string (e.g. ``"TRANSFER_INITIATED"``).
        details:  Arbitrary JSON-serialisable dict attached to the log entry.
    """
    db.add(
        AuditLog(
            user_id=user_id,
            action=action,
            details=details,
        )
    )
    await db.commit()


async def _validate_step_up_token(
    x_step_up_token: str | None,
    current_user: User,
    redis: Redis,  # type: ignore[type-arg]
    settings: Settings,
) -> None:
    """Validate the step-up token when a transfer meets the threshold.

    Replicates the same validation logic as ``require_step_up`` without being
    a FastAPI dependency.  Called only when ``request.amount >= threshold``.

    Steps (mirroring ``require_step_up``):
    1. Header presence — raise 403 with ``X-Step-Up-Required: true`` if absent.
    2. JWT decode and type validation via ``decode_step_up_token``.
    3. Subject binding — ``sub`` must equal ``str(current_user.id)``.
    4. Atomic single-use consumption via ``redis.getdel``.

    Note: subject-mismatch audit is not written here because the service has
    already committed TRANSFER_INITIATED at that point.  The 403 response is
    sufficient to surface the attempted bypass.

    Args:
        x_step_up_token: Raw JWT from the ``X-Step-Up-Token`` request header,
                         or ``None`` when the header was absent.
        current_user:    The authenticated User performing the transfer.
        redis:           Async Redis client used for the ``getdel`` operation.
        settings:        Application settings (signing key, algorithm).

    Raises:
        HTTPException 403: If the token is absent, invalid, expired, bound to
            a different user, or has already been consumed (SR-13, SR-14).
    """
    # Step 1: Header presence.
    if x_step_up_token is None:
        raise HTTPException(
            status_code=403,
            detail="Step-up authentication required",
            headers={"X-Step-Up-Required": "true"},
        )

    # Step 2: JWT decode and type validation.
    try:
        payload = decode_step_up_token(x_step_up_token, settings)
    except InvalidTokenError as exc:
        raise HTTPException(
            status_code=403,
            detail="Invalid or expired step-up token",
        ) from exc

    # Step 3: Extract claims and verify subject binding.
    jti: str = payload["jti"]
    sub: str = payload["sub"]

    if sub != str(current_user.id):
        raise HTTPException(
            status_code=403,
            detail="Step-up token subject mismatch",
        )

    # Step 4: Atomic single-use consumption (SR-14).
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
) -> Transaction:
    """Execute a fund transfer from the authenticated user's account.

    Enforces every validation check in a strict order and writes audit log
    entries for both successful and rejected transfers (SR-16).  Balance
    arithmetic is performed atomically inside a savepoint (SR-20).

    The step-up threshold is enforced server-side: if ``request.amount`` is at
    or above ``settings.step_up_transfer_threshold`` (expressed in cents), the
    caller must supply a valid, unconsumed step-up token in ``x_step_up_token``
    (SR-13, SR-14).

    Validation order (strictly enforced):
    1. Write TRANSFER_INITIATED audit log and commit.
    2. Load source account by ``user_id = current_user.id``; reject if absent.
    3. Verify source account status is ACTIVE.
    4. Load destination account by ``account_number``; reject if absent.
    5. Reject self-transfers (source == destination).
    6. Verify destination account status is ACTIVE.
    7. Check sufficient balance.
    8. Enforce step-up token gate if ``amount >= threshold``.
    9. Atomically deduct/credit balances and create Transaction row.
    10. Write TRANSFER_COMPLETED audit log and commit.
    11. Return the Transaction row.

    Args:
        current_user:    The authenticated and verified User initiating the
                         transfer.  Source account ownership is derived from
                         ``current_user.id`` — not accepted from the request.
        request:         Validated ``TransferRequest`` containing destination
                         account number, amount, and optional description.
        x_step_up_token: Raw JWT from the ``X-Step-Up-Token`` request header,
                         or ``None`` when the header is absent.  Required when
                         ``request.amount >= threshold``.
        db:              Active async database session.
        redis:           Async Redis client (step-up token consumption).
        settings:        Application settings (threshold, signing key).

    Returns:
        The newly created ``Transaction`` row with status COMPLETED.

    Raises:
        HTTPException 400: Source account absent, INACTIVE/FROZEN, destination
            absent, destination INACTIVE/FROZEN, or insufficient balance.
        HTTPException 403: Step-up token absent, invalid, expired, bound to
            a different user, or already consumed (when amount >= threshold).
        HTTPException 422: Self-transfer attempt.
    """
    # ------------------------------------------------------------------
    # Step 1: Write TRANSFER_INITIATED audit log.
    # This is committed immediately so the attempt is recorded regardless
    # of what happens in subsequent validation steps (SR-16).
    # ------------------------------------------------------------------
    await _write_audit(
        db=db,
        user_id=current_user.id,
        action="TRANSFER_INITIATED",
        details={
            "to_account_number": request.to_account_number,
            "amount": str(request.amount),
        },
    )

    # ------------------------------------------------------------------
    # Step 2: Load source account.
    # Filtered by user_id to enforce ownership — the client never specifies
    # the source account directly (SR-12).
    # ------------------------------------------------------------------
    result = await db.execute(select(Account).where(Account.user_id == current_user.id))
    from_account: Account | None = result.scalar_one_or_none()

    if from_account is None:
        await _write_audit(
            db=db,
            user_id=current_user.id,
            action="TRANSFER_REJECTED",
            details={"reason": "no_account"},
        )
        raise HTTPException(status_code=400, detail="No account found")

    # ------------------------------------------------------------------
    # Step 3: Source account status check.
    # Only ACTIVE accounts may initiate transfers (T-02).
    # ------------------------------------------------------------------
    if from_account.status != AccountStatus.ACTIVE:
        await _write_audit(
            db=db,
            user_id=current_user.id,
            action="TRANSFER_REJECTED",
            details={
                "reason": "account_not_active",
                "account_id": str(from_account.id),
            },
        )
        raise HTTPException(status_code=400, detail="Account is not active")

    # ------------------------------------------------------------------
    # Step 4: Load destination account by public account_number.
    # Using the public identifier rather than an internal UUID prevents IDOR
    # enumeration of other users' account UUIDs (T-02).
    # ------------------------------------------------------------------
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
        )
        raise HTTPException(status_code=400, detail="Destination account not found")

    # ------------------------------------------------------------------
    # Step 5: Self-transfer check.
    # Transferring to one's own account is a no-op that could be used to
    # inflate audit trail noise or exploit rounding behaviour.
    # ------------------------------------------------------------------
    if from_account.id == to_account.id:
        await _write_audit(
            db=db,
            user_id=current_user.id,
            action="TRANSFER_REJECTED",
            details={
                "reason": "self_transfer",
                "account_id": str(from_account.id),
            },
        )
        raise HTTPException(status_code=422, detail="Cannot transfer to own account")

    # ------------------------------------------------------------------
    # Step 6: Destination account status check.
    # Reject transfers to INACTIVE or FROZEN destination accounts (T-02).
    # ------------------------------------------------------------------
    if to_account.status != AccountStatus.ACTIVE:
        await _write_audit(
            db=db,
            user_id=current_user.id,
            action="TRANSFER_REJECTED",
            details={
                "reason": "destination_not_active",
                "to_account_number": request.to_account_number,
            },
        )
        raise HTTPException(status_code=400, detail="Destination account is not active")

    # ------------------------------------------------------------------
    # Step 7: Balance check.
    # The balance column is Numeric(18,2) — SQLAlchemy returns Decimal.
    # request.amount is Decimal (validated by the Pydantic schema).
    # No float arithmetic is performed (SR-20).
    # ------------------------------------------------------------------
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
        )
        raise HTTPException(status_code=400, detail="Insufficient balance")

    # ------------------------------------------------------------------
    # Step 8: Step-up token gate (SR-13, SR-14).
    # The threshold is stored in integer cents (e.g. 100000 = $1000.00).
    # Convert to Decimal dollars before comparing with request.amount.
    # This decision is enforced server-side — the client cannot bypass it.
    # ------------------------------------------------------------------
    threshold: Decimal = Decimal(settings.step_up_transfer_threshold) / Decimal(100)
    if request.amount >= threshold:
        try:
            await _validate_step_up_token(
                x_step_up_token=x_step_up_token,
                current_user=current_user,
                redis=redis,
                settings=settings,
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
            )
            raise

    # ------------------------------------------------------------------
    # Step 9: Atomic balance update and transaction creation.
    # Both balance mutations and the Transaction INSERT happen inside a
    # single savepoint so they are committed as one unit.  If the flush
    # raises (e.g. a constraint violation), only the savepoint rolls back;
    # the outer session, which already holds the audit logs, is unaffected.
    # ------------------------------------------------------------------
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

    # ------------------------------------------------------------------
    # Step 10: Write TRANSFER_COMPLETED audit log.
    # ------------------------------------------------------------------
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
    )

    # ------------------------------------------------------------------
    # Step 11: Return the completed Transaction row.
    # ------------------------------------------------------------------
    return transaction
