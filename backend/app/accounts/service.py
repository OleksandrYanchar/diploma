"""Accounts service — account retrieval and lazy seeding.

Implements the business logic for the accounts module:

- ``get_or_create_account``: returns the authenticated user's single account,
  creating it on first access.  Account creation is safe under concurrency: the
  DB-level unique index on ``accounts.user_id`` (migration 0004) means that if
  two concurrent requests both pass the initial SELECT and both attempt INSERT,
  exactly one INSERT succeeds and the other raises ``IntegrityError``.  The
  loser catches the error, rolls back its failed INSERT, and re-fetches the row
  committed by the winner.

Security properties enforced:
- SR-12: all account queries are filtered by ``user_id = current_user.id``; no
  route parameter is accepted from the client.
- SR-16: every successful account access writes an ACCOUNT_VIEWED audit log entry.
"""

import uuid

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.account import Account, AccountStatus
from app.models.audit_log import AuditLog
from app.models.user import User


async def get_or_create_account(
    user: User,
    db: AsyncSession,
) -> Account:
    """Return the user's account, creating it on first access.

    Performs a SELECT first.  If no account exists, attempts an INSERT.  If the
    INSERT raises ``IntegrityError`` (a concurrent request already committed an
    account for the same user), rolls back the failed INSERT and re-fetches the
    row committed by the winner.  This guarantees exactly one account per user
    without relying on a single-writer assumption.

    The initial balance is 1000.00 USD so that the demo account can execute
    transfers immediately without a separate deposit flow.  # DEMO MODE: replace
    with a real onboarding flow in production.

    Args:
        user: The authenticated and verified ``User`` whose account is requested.
        db:   The active async database session.

    Returns:
        The user's ``Account`` row (created if absent, fetched if already present).
    """
    result = await db.execute(select(Account).where(Account.user_id == user.id))
    account: Account | None = result.scalar_one_or_none()

    if account is not None:
        return account

    try:
        async with db.begin_nested():
            account = Account(
                user_id=user.id,
                status=AccountStatus.ACTIVE,
                balance=1000,  # DEMO MODE: seed balance for transfer demos
                currency="USD",
            )
            db.add(account)

            await db.flush()

        await db.commit()
        await db.refresh(account)
        return account

    except IntegrityError:
        await db.rollback()
        result = await db.execute(select(Account).where(Account.user_id == user.id))
        account = result.scalar_one()
        return account


async def write_account_viewed_audit(
    user_id: uuid.UUID,
    account_id: uuid.UUID,
    db: AsyncSession,
) -> None:
    """Append an ACCOUNT_VIEWED audit log entry.

    Enforces SR-16: every account access produces an immutable audit record.
    Called after the account has been successfully retrieved or created.

    Args:
        user_id:    UUID of the authenticated user performing the access.
        account_id: UUID of the account that was accessed.
        db:         The active async database session.
    """
    db.add(
        AuditLog(
            user_id=user_id,
            action="ACCOUNT_VIEWED",
            details={"account_id": str(account_id)},
        )
    )
    await db.commit()
