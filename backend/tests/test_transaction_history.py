"""Integration tests for GET /transactions/history.

Covers:
- Authentication and verification gates (SR-06, SR-03)
- Empty history: no account, and account with no transactions
- Own-transaction visibility: outgoing and incoming rows both returned
- Cross-user isolation: user B cannot see user A's transactions (SR-12)
- Pagination: page/page_size slicing, correct total regardless of page
- Audit log: TRANSACTIONS_VIEWED entry written on every request (SR-16)

Account and Transaction rows are inserted directly via ORM — no HTTP
round-trip is used for setup, keeping tests isolated from the accounts module.
"""

from __future__ import annotations

import uuid
from decimal import Decimal

from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.account import Account, AccountStatus
from app.models.audit_log import AuditLog
from app.models.transaction import Transaction, TransactionStatus, TransactionType
from tests.helpers import make_orm_user

HISTORY_URL = "/api/v1/transactions/history"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _make_account(
    db: AsyncSession,
    user_id: uuid.UUID,
    balance: Decimal = Decimal("1000.00"),
    status: AccountStatus = AccountStatus.ACTIVE,
) -> Account:
    """Insert an Account row directly and return it."""
    account = Account(
        user_id=user_id,
        status=status,
        balance=balance,
        currency="USD",
    )
    db.add(account)
    await db.commit()
    await db.refresh(account)
    return account


async def _make_transaction(
    db: AsyncSession,
    from_account_id: uuid.UUID | None,
    to_account_id: uuid.UUID | None,
    amount: Decimal = Decimal("50.00"),
) -> Transaction:
    """Insert a completed TRANSFER Transaction row directly and return it."""
    tx = Transaction(
        from_account_id=from_account_id,
        to_account_id=to_account_id,
        amount=amount,
        transaction_type=TransactionType.TRANSFER,
        status=TransactionStatus.COMPLETED,
    )
    db.add(tx)
    await db.commit()
    await db.refresh(tx)
    return tx


# ---------------------------------------------------------------------------
# Authentication and verification gates
# ---------------------------------------------------------------------------


async def test_history_unauthenticated(async_client: AsyncClient) -> None:
    """Request without a bearer token is rejected with 401 or 403.

    Security property (SR-06): the Zero Trust gate must reject any request
    that does not carry a valid access token.
    """
    response = await async_client.get(HISTORY_URL)
    assert response.status_code in (401, 403)


async def test_history_unverified(
    async_client: AsyncClient,
    db_session: AsyncSession,
    fake_redis: object,
) -> None:
    """Unverified user is rejected with 403.

    Security property (SR-03): unverified accounts must not access financial
    resources until email is confirmed.
    """
    _, token = await make_orm_user(
        db_session,
        fake_redis,
        email=f"unverified_{uuid.uuid4()}@example.com",
        is_verified=False,
    )
    response = await async_client.get(
        HISTORY_URL,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 403


# ---------------------------------------------------------------------------
# Empty-history cases
# ---------------------------------------------------------------------------


async def test_history_empty_no_account(
    async_client: AsyncClient,
    db_session: AsyncSession,
    fake_redis: object,
) -> None:
    """Verified user with no account receives an empty list with total=0.

    This is a legitimate state (registered user who has not yet opened an
    account).  The service returns an empty response, not an error.
    """
    _, token = await make_orm_user(
        db_session,
        fake_redis,
        email=f"noaccount_{uuid.uuid4()}@example.com",
    )
    response = await async_client.get(
        HISTORY_URL,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["items"] == []
    assert body["total"] == 0
    assert body["page"] == 1
    assert body["page_size"] == 20


async def test_history_empty_with_account(
    async_client: AsyncClient,
    db_session: AsyncSession,
    fake_redis: object,
) -> None:
    """Verified user with an account but no transactions receives an empty list.

    Confirms that the service handles an empty result set without error and
    still returns a well-formed paginated response.
    """
    user, token = await make_orm_user(
        db_session,
        fake_redis,
        email=f"emptyaccount_{uuid.uuid4()}@example.com",
    )
    await _make_account(db_session, user.id)

    response = await async_client.get(
        HISTORY_URL,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["items"] == []
    assert body["total"] == 0
    assert body["page"] == 1
    assert body["page_size"] == 20


# ---------------------------------------------------------------------------
# Own-transaction visibility
# ---------------------------------------------------------------------------


async def test_history_returns_own_transactions(
    async_client: AsyncClient,
    db_session: AsyncSession,
    fake_redis: object,
) -> None:
    """User sees both outgoing and incoming transactions; total=2.

    Verifies that the OR filter on from_account_id/to_account_id correctly
    surfaces both sides of the ledger.
    """
    user, token = await make_orm_user(
        db_session,
        fake_redis,
        email=f"owner_{uuid.uuid4()}@example.com",
    )
    other, _ = await make_orm_user(
        db_session,
        fake_redis,
        email=f"other_{uuid.uuid4()}@example.com",
        session_id=f"00000000-0000-0000-0000-{uuid.uuid4().hex[:12]}",
    )
    account = await _make_account(db_session, user.id)
    other_account = await _make_account(db_session, other.id)

    # Outgoing: user → other
    await _make_transaction(
        db_session,
        from_account_id=account.id,
        to_account_id=other_account.id,
        amount=Decimal("100.00"),
    )
    # Incoming: other → user
    await _make_transaction(
        db_session,
        from_account_id=other_account.id,
        to_account_id=account.id,
        amount=Decimal("200.00"),
    )

    response = await async_client.get(
        HISTORY_URL,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 2
    assert len(body["items"]) == 2


# ---------------------------------------------------------------------------
# Cross-user isolation (SR-12)
# ---------------------------------------------------------------------------


async def test_history_no_cross_user_leakage(
    async_client: AsyncClient,
    db_session: AsyncSession,
    fake_redis: object,
) -> None:
    """User B's history does not include user A's transactions.

    Security property (SR-12): account scoping must prevent horizontal access
    to another user's financial records.  User B sees only their own empty
    history even though user A has transactions.
    """
    user_a, _ = await make_orm_user(
        db_session,
        fake_redis,
        email=f"usera_{uuid.uuid4()}@example.com",
        session_id=f"00000000-0000-0000-aaaa-{uuid.uuid4().hex[:12]}",
    )
    user_b, token_b = await make_orm_user(
        db_session,
        fake_redis,
        email=f"userb_{uuid.uuid4()}@example.com",
        session_id=f"00000000-0000-0000-bbbb-{uuid.uuid4().hex[:12]}",
    )
    account_a = await _make_account(db_session, user_a.id)
    # user B has an account but no transactions
    await _make_account(db_session, user_b.id)

    # Insert transactions that belong exclusively to user A.
    dummy_user, _ = await make_orm_user(
        db_session,
        fake_redis,
        email=f"dummy_{uuid.uuid4()}@example.com",
        session_id=f"00000000-0000-0000-cccc-{uuid.uuid4().hex[:12]}",
    )
    dummy_account = await _make_account(db_session, dummy_user.id)
    await _make_transaction(
        db_session,
        from_account_id=account_a.id,
        to_account_id=dummy_account.id,
    )
    await _make_transaction(
        db_session,
        from_account_id=dummy_account.id,
        to_account_id=account_a.id,
    )

    # User B queries their own history.
    response = await async_client.get(
        HISTORY_URL,
        headers={"Authorization": f"Bearer {token_b}"},
    )
    assert response.status_code == 200
    body = response.json()
    # User B must see zero transactions — none of user A's rows should leak.
    assert body["total"] == 0
    assert body["items"] == []


# ---------------------------------------------------------------------------
# Pagination
# ---------------------------------------------------------------------------


async def test_history_pagination(
    async_client: AsyncClient,
    db_session: AsyncSession,
    fake_redis: object,
) -> None:
    """Pagination slices results correctly; total reflects the full count.

    Inserts 5 transactions for the user and verifies:
    - page=1, page_size=2 → 2 items, total=5
    - page=2, page_size=2 → 2 items, total=5
    - page=3, page_size=2 → 1 item,  total=5
    """
    user, token = await make_orm_user(
        db_session,
        fake_redis,
        email=f"pager_{uuid.uuid4()}@example.com",
    )
    other, _ = await make_orm_user(
        db_session,
        fake_redis,
        email=f"pager_other_{uuid.uuid4()}@example.com",
        session_id=f"00000000-0000-0000-dddd-{uuid.uuid4().hex[:12]}",
    )
    account = await _make_account(db_session, user.id)
    other_account = await _make_account(db_session, other.id)

    # Insert 5 outgoing transactions.
    for i in range(5):
        await _make_transaction(
            db_session,
            from_account_id=account.id,
            to_account_id=other_account.id,
            amount=Decimal(f"{(i + 1) * 10}.00"),
        )

    # Page 1: 2 items
    r1 = await async_client.get(
        HISTORY_URL,
        params={"page": 1, "page_size": 2},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r1.status_code == 200
    b1 = r1.json()
    assert len(b1["items"]) == 2
    assert b1["total"] == 5
    assert b1["page"] == 1
    assert b1["page_size"] == 2

    # Page 2: 2 items
    r2 = await async_client.get(
        HISTORY_URL,
        params={"page": 2, "page_size": 2},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r2.status_code == 200
    b2 = r2.json()
    assert len(b2["items"]) == 2
    assert b2["total"] == 5
    assert b2["page"] == 2

    # Page 3: 1 remaining item
    r3 = await async_client.get(
        HISTORY_URL,
        params={"page": 3, "page_size": 2},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r3.status_code == 200
    b3 = r3.json()
    assert len(b3["items"]) == 1
    assert b3["total"] == 5
    assert b3["page"] == 3


# ---------------------------------------------------------------------------
# Audit log assertion (SR-16)
# ---------------------------------------------------------------------------


async def test_history_audit_log_written(
    async_client: AsyncClient,
    db_session: AsyncSession,
    fake_redis: object,
) -> None:
    """A TRANSACTIONS_VIEWED audit log entry is written after GET /transactions/history.

    Security property (SR-16): every access to transaction history must produce
    an audit record so that read access is traceable.
    """
    user, token = await make_orm_user(
        db_session,
        fake_redis,
        email=f"audited_{uuid.uuid4()}@example.com",
    )
    await _make_account(db_session, user.id)

    response = await async_client.get(
        HISTORY_URL,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200

    result = await db_session.execute(
        select(AuditLog).where(
            AuditLog.user_id == user.id,
            AuditLog.action == "TRANSACTIONS_VIEWED",
        )
    )
    log: AuditLog | None = result.scalar_one_or_none()
    assert log is not None, "Expected TRANSACTIONS_VIEWED audit log entry"
