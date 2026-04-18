"""Integration tests for GET /accounts/me.

Covers:
- Authentication and verification gates (SR-03, SR-11)
- Lazy account creation on first access
- Idempotency of account creation (same account returned on repeat calls)
- Correct response fields
- ACCOUNT_VIEWED audit log entry written on each access (SR-16)
"""

from __future__ import annotations

import uuid

from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.account import Account, AccountStatus
from app.models.audit_log import AuditLog
from tests.helpers import make_orm_user

ACCOUNTS_ME_URL = "/api/v1/accounts/me"


async def test_get_account_unauthenticated(async_client: AsyncClient) -> None:
    """Unauthenticated request returns 401.

    Security property (SR-11): every protected endpoint must reject requests
    that do not carry a valid bearer token.
    """
    response = await async_client.get(ACCOUNTS_ME_URL)
    assert response.status_code in (401, 403)


async def test_get_account_unverified_user(
    async_client: AsyncClient,
    db_session: AsyncSession,
    fake_redis: object,
) -> None:
    """Unverified user is rejected with 403.

    Security property (SR-03): unverified accounts must not access financial
    resources until they have confirmed their email address.
    """
    _, token = await make_orm_user(
        db_session,
        fake_redis,
        email=f"unverified_{uuid.uuid4()}@example.com",
        is_verified=False,
    )
    response = await async_client.get(
        ACCOUNTS_ME_URL,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 403


async def test_get_account_creates_on_first_access(
    async_client: AsyncClient,
    db_session: AsyncSession,
    fake_redis: object,
) -> None:
    """First call for a verified user creates an account and returns 200.

    Security property (SR-12): the account is created and scoped to the
    authenticated user — no account ID is accepted from the client.
    """
    user, token = await make_orm_user(
        db_session,
        fake_redis,
        email=f"user_{uuid.uuid4()}@example.com",
    )

    response = await async_client.get(
        ACCOUNTS_ME_URL,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200

    body = response.json()
    assert "id" in body
    assert "account_number" in body
    assert body["currency"] == "USD"
    assert body["status"] == AccountStatus.ACTIVE.value
    assert float(body["balance"]) > 0

    # Confirm the account row exists in the DB, scoped to the correct user.
    result = await db_session.execute(select(Account).where(Account.user_id == user.id))
    db_account: Account | None = result.scalar_one_or_none()
    assert db_account is not None
    assert str(db_account.id) == body["id"]


async def test_get_account_idempotent(
    async_client: AsyncClient,
    db_session: AsyncSession,
    fake_redis: object,
) -> None:
    """Repeated calls return the same account — no duplicate rows created.

    Security property (SR-12 + migration 0004): the DB-level unique index on
    accounts.user_id ensures that concurrent or sequential creates produce
    exactly one account per user.
    """
    user, token = await make_orm_user(
        db_session,
        fake_redis,
        email=f"user_{uuid.uuid4()}@example.com",
    )
    headers = {"Authorization": f"Bearer {token}"}

    first = await async_client.get(ACCOUNTS_ME_URL, headers=headers)
    second = await async_client.get(ACCOUNTS_ME_URL, headers=headers)

    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json()["id"] == second.json()["id"]
    assert first.json()["account_number"] == second.json()["account_number"]

    # Confirm only one account row in the DB for this user.
    result = await db_session.execute(select(Account).where(Account.user_id == user.id))
    rows = result.scalars().all()
    assert len(rows) == 1


async def test_get_account_audit_log_written(
    async_client: AsyncClient,
    db_session: AsyncSession,
    fake_redis: object,
) -> None:
    """A successful account access writes an ACCOUNT_VIEWED audit log entry.

    Security property (SR-16): every access to a financial resource must be
    recorded in the audit log to support non-repudiation claims.
    """
    user, token = await make_orm_user(
        db_session,
        fake_redis,
        email=f"user_{uuid.uuid4()}@example.com",
    )

    response = await async_client.get(
        ACCOUNTS_ME_URL,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    account_id = response.json()["id"]

    result = await db_session.execute(
        select(AuditLog).where(
            AuditLog.user_id == user.id,
            AuditLog.action == "ACCOUNT_VIEWED",
        )
    )
    log: AuditLog | None = result.scalar_one_or_none()
    assert log is not None
    assert log.details is not None
    assert log.details.get("account_id") == account_id
