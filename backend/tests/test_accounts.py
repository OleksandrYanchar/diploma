"""Integration tests for GET /accounts/me.

Covers:
- Authentication and verification gates (SR-03, SR-11)
- Lazy account creation on first access
- Idempotency of account creation (same account returned on repeat calls)
- Correct response fields
- ACCOUNT_VIEWED audit log entry written on each access (SR-16)
"""

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


async def test_get_account_scoped_to_authenticated_user(
    async_client: AsyncClient,
    db_session: AsyncSession,
    fake_redis: object,
) -> None:
    """Two users each see only their own account via GET /accounts/me (T-11).

    Security property (SR-12): the endpoint must scope strictly by the
    authenticated user.  No route parameter is accepted, and the account is
    looked up by ``user_id = current_user.id``.  Neither user's response may
    contain the other user's account identifier.
    """
    user_a, token_a = await make_orm_user(
        db_session,
        fake_redis,
        email=f"user_a_{uuid.uuid4()}@example.com",
    )
    user_b, token_b = await make_orm_user(
        db_session,
        fake_redis,
        email=f"user_b_{uuid.uuid4()}@example.com",
        session_id=f"00000000-0000-0000-0000-{uuid.uuid4().hex[:12]}",
    )

    resp_a = await async_client.get(
        ACCOUNTS_ME_URL,
        headers={"Authorization": f"Bearer {token_a}"},
    )
    resp_b = await async_client.get(
        ACCOUNTS_ME_URL,
        headers={"Authorization": f"Bearer {token_b}"},
    )
    assert resp_a.status_code == 200
    assert resp_b.status_code == 200

    body_a = resp_a.json()
    body_b = resp_b.json()

    # Each user must receive a distinct account.
    assert body_a["id"] != body_b["id"]
    assert body_a["account_number"] != body_b["account_number"]

    # Confirm DB-side ownership: each returned account belongs to the caller.
    db_a_result = await db_session.execute(
        select(Account).where(Account.user_id == user_a.id)
    )
    db_account_a = db_a_result.scalar_one()
    db_b_result = await db_session.execute(
        select(Account).where(Account.user_id == user_b.id)
    )
    db_account_b = db_b_result.scalar_one()

    assert str(db_account_a.id) == body_a["id"]
    assert str(db_account_b.id) == body_b["id"]

    # Cross-check: neither response leaks the other user's account id.
    assert body_a["id"] != str(db_account_b.id)
    assert body_b["id"] != str(db_account_a.id)


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
