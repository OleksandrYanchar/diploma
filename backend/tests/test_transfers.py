"""Integration tests for POST /transactions/transfer.

Covers:
- Authentication and verification gates (SR-03, SR-06)
- Schema-level validation (amount > 0, 2 decimal places)
- Business rule rejections: destination not found, self-transfer, insufficient balance
- Below-threshold transfer without step-up token (SR-13 — threshold not reached)
- Above-threshold transfer missing step-up token (SR-13 — 403 + X-Step-Up-Required)
- Above-threshold transfer with a valid step-up token (SR-13, SR-14)
- Single-use enforcement: reusing a consumed step-up token (SR-14)
- Audit log entries: TRANSFER_INITIATED and TRANSFER_COMPLETED written on success
  (SR-16)

Account setup: Account rows are inserted directly via ORM rather than going
through GET /accounts/me, so tests are isolated from the accounts module and
run faster (no HTTP round-trip for setup).
"""

from __future__ import annotations

import uuid
from decimal import Decimal

from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_step_up_token
from app.models.account import Account, AccountStatus
from app.models.audit_log import AuditLog
from tests.conftest import _TEST_SETTINGS
from tests.helpers import make_orm_user

TRANSFER_URL = "/api/v1/transactions/transfer"

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


# ---------------------------------------------------------------------------
# Authentication and verification gates
# ---------------------------------------------------------------------------


async def test_transfer_unauthenticated(async_client: AsyncClient) -> None:
    """Request without a bearer token is rejected with 401 or 403.

    Security property (SR-06): the Zero Trust gate must reject any request
    that does not carry a valid access token.
    """
    response = await async_client.post(
        TRANSFER_URL,
        json={
            "to_account_number": "AABBCCDD11223344",
            "amount": "50.00",
        },
    )
    assert response.status_code in (401, 403)


async def test_transfer_unverified(
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
    response = await async_client.post(
        TRANSFER_URL,
        json={"to_account_number": "AABBCCDD11223344", "amount": "50.00"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 403


# ---------------------------------------------------------------------------
# Schema-level validation (rejected before the service is called)
# ---------------------------------------------------------------------------


async def test_transfer_invalid_amount_zero(
    async_client: AsyncClient,
    db_session: AsyncSession,
    fake_redis: object,
) -> None:
    """amount=0 is rejected at the Pydantic schema layer with 422.

    Security property (SR-20): the schema enforces ``gt=0`` so zero-value
    transfers never reach the service layer.
    """
    user, token = await make_orm_user(
        db_session,
        fake_redis,
        email=f"user_{uuid.uuid4()}@example.com",
    )
    await _make_account(db_session, user.id)

    response = await async_client.post(
        TRANSFER_URL,
        json={"to_account_number": "AABBCCDD11223344", "amount": "0"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 422


async def test_transfer_invalid_amount_negative(
    async_client: AsyncClient,
    db_session: AsyncSession,
    fake_redis: object,
) -> None:
    """Negative amounts are rejected at the Pydantic schema layer with 422.

    Security property (SR-20): the schema enforces ``gt=0`` — negative amounts
    must never reach the service layer where they could reverse balance logic.
    """
    user, token = await make_orm_user(
        db_session,
        fake_redis,
        email=f"user_{uuid.uuid4()}@example.com",
    )
    await _make_account(db_session, user.id)

    response = await async_client.post(
        TRANSFER_URL,
        json={"to_account_number": "AABBCCDD11223344", "amount": "-10.00"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 422


# ---------------------------------------------------------------------------
# Service-level business rule rejections
# ---------------------------------------------------------------------------


async def test_transfer_destination_not_found(
    async_client: AsyncClient,
    db_session: AsyncSession,
    fake_redis: object,
) -> None:
    """Transfer to a non-existent account_number is rejected with 400.

    Security property (T-02): destination is resolved by public account_number;
    a lookup miss returns a generic 400 that does not reveal whether the account
    number has ever existed.
    """
    user, token = await make_orm_user(
        db_session,
        fake_redis,
        email=f"user_{uuid.uuid4()}@example.com",
    )
    await _make_account(db_session, user.id)

    response = await async_client.post(
        TRANSFER_URL,
        json={
            "to_account_number": "DOESNOTEXIST0000",
            "amount": "50.00",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 400
    assert "Destination account not found" in response.json()["detail"]


async def test_transfer_self_transfer(
    async_client: AsyncClient,
    db_session: AsyncSession,
    fake_redis: object,
) -> None:
    """Transferring to one's own account is rejected with 422.

    Prevents no-op transfers that could be used to inflate audit noise or
    exploit any future rounding logic.
    """
    user, token = await make_orm_user(
        db_session,
        fake_redis,
        email=f"user_{uuid.uuid4()}@example.com",
    )
    account = await _make_account(db_session, user.id)

    response = await async_client.post(
        TRANSFER_URL,
        json={
            "to_account_number": account.account_number,
            "amount": "50.00",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 422
    assert "Cannot transfer to own account" in response.json()["detail"]


async def test_transfer_insufficient_balance(
    async_client: AsyncClient,
    db_session: AsyncSession,
    fake_redis: object,
) -> None:
    """Transfer amount exceeding balance is rejected with 400.

    Security property (SR-20): the service must check balance before mutating
    any DB state.
    """
    sender, sender_token = await make_orm_user(
        db_session,
        fake_redis,
        email=f"sender_{uuid.uuid4()}@example.com",
    )
    recipient, _ = await make_orm_user(
        db_session,
        fake_redis,
        email=f"recipient_{uuid.uuid4()}@example.com",
        session_id=f"00000000-0000-0000-0000-{uuid.uuid4().hex[:12]}",
    )
    await _make_account(db_session, sender.id, balance=Decimal("100.00"))
    dest_account = await _make_account(db_session, recipient.id)

    response = await async_client.post(
        TRANSFER_URL,
        json={
            "to_account_number": dest_account.account_number,
            "amount": "500.00",  # more than the 100.00 balance
        },
        headers={"Authorization": f"Bearer {sender_token}"},
    )
    assert response.status_code == 400
    assert "Insufficient balance" in response.json()["detail"]


# ---------------------------------------------------------------------------
# Step-up threshold logic
# ---------------------------------------------------------------------------


async def test_transfer_below_threshold_no_step_up(
    async_client: AsyncClient,
    db_session: AsyncSession,
    fake_redis: object,
) -> None:
    """Transfer below $1000 threshold succeeds without a step-up token.

    Security property (SR-13): step-up authentication is only required at or
    above the threshold.  A below-threshold transfer must not be blocked when
    no X-Step-Up-Token header is present.
    """
    sender, sender_token = await make_orm_user(
        db_session,
        fake_redis,
        email=f"sender_{uuid.uuid4()}@example.com",
    )
    recipient, _ = await make_orm_user(
        db_session,
        fake_redis,
        email=f"recipient_{uuid.uuid4()}@example.com",
        session_id=f"00000000-0000-0000-ffff-{uuid.uuid4().hex[:12]}",
    )
    sender_account = await _make_account(
        db_session, sender.id, balance=Decimal("1000.00")
    )
    dest_account = await _make_account(
        db_session, recipient.id, balance=Decimal("0.00")
    )

    amount = Decimal("50.00")  # well below the $1000 threshold
    response = await async_client.post(
        TRANSFER_URL,
        json={
            "to_account_number": dest_account.account_number,
            "amount": str(amount),
        },
        headers={"Authorization": f"Bearer {sender_token}"},
    )
    assert response.status_code == 200

    body = response.json()
    assert body["status"] == "completed"
    assert Decimal(body["amount"]) == amount

    # Verify balances were updated in the DB.
    await db_session.refresh(sender_account)
    await db_session.refresh(dest_account)
    assert sender_account.balance == Decimal("950.00")
    assert dest_account.balance == Decimal("50.00")


async def test_transfer_above_threshold_missing_step_up(
    async_client: AsyncClient,
    db_session: AsyncSession,
    fake_redis: object,
) -> None:
    """Transfer >= $1000 without X-Step-Up-Token is rejected with 403.

    Security property (SR-13): the server enforces the threshold gate
    regardless of what the client sends.  The response must include the
    ``X-Step-Up-Required: true`` header so the client knows to initiate
    the step-up flow.
    """
    sender, sender_token = await make_orm_user(
        db_session,
        fake_redis,
        email=f"sender_{uuid.uuid4()}@example.com",
    )
    recipient, _ = await make_orm_user(
        db_session,
        fake_redis,
        email=f"recipient_{uuid.uuid4()}@example.com",
        session_id=f"00000000-0000-0000-eeee-{uuid.uuid4().hex[:12]}",
    )
    await _make_account(db_session, sender.id, balance=Decimal("2000.00"))
    dest_account = await _make_account(db_session, recipient.id)

    response = await async_client.post(
        TRANSFER_URL,
        json={
            "to_account_number": dest_account.account_number,
            "amount": "1500.00",  # above the $1000 threshold
        },
        headers={"Authorization": f"Bearer {sender_token}"},
        # No X-Step-Up-Token header
    )
    assert response.status_code == 403
    assert response.headers.get("x-step-up-required") == "true"


async def test_transfer_above_threshold_with_valid_step_up(
    async_client: AsyncClient,
    db_session: AsyncSession,
    fake_redis: object,
) -> None:
    """Transfer >= $1000 with a valid step-up token succeeds with 200.

    Security property (SR-13, SR-14): a properly issued, unconsumed step-up
    token unlocks the elevated threshold.
    """
    sender, sender_token = await make_orm_user(
        db_session,
        fake_redis,
        email=f"sender_{uuid.uuid4()}@example.com",
    )
    recipient, _ = await make_orm_user(
        db_session,
        fake_redis,
        email=f"recipient_{uuid.uuid4()}@example.com",
        session_id=f"00000000-0000-0000-dddd-{uuid.uuid4().hex[:12]}",
    )
    sender_account = await _make_account(
        db_session, sender.id, balance=Decimal("2000.00")
    )
    dest_account = await _make_account(
        db_session, recipient.id, balance=Decimal("0.00")
    )

    # Create a step-up token for the sender and seed the Redis marker.
    step_up_jwt, jti = create_step_up_token(str(sender.id), _TEST_SETTINGS)
    await fake_redis.set(f"step_up:{jti}", "1")  # type: ignore[union-attr]

    amount = Decimal("1500.00")
    response = await async_client.post(
        TRANSFER_URL,
        json={
            "to_account_number": dest_account.account_number,
            "amount": str(amount),
        },
        headers={
            "Authorization": f"Bearer {sender_token}",
            "X-Step-Up-Token": step_up_jwt,
        },
    )
    assert response.status_code == 200

    body = response.json()
    assert body["status"] == "completed"
    assert Decimal(body["amount"]) == amount

    # Verify balances were updated.
    await db_session.refresh(sender_account)
    await db_session.refresh(dest_account)
    assert sender_account.balance == Decimal("500.00")
    assert dest_account.balance == Decimal("1500.00")

    # The step-up marker must have been consumed from Redis.
    marker = await fake_redis.get(f"step_up:{jti}")  # type: ignore[union-attr]
    assert marker is None


async def test_transfer_above_threshold_consumed_step_up(
    async_client: AsyncClient,
    db_session: AsyncSession,
    fake_redis: object,
) -> None:
    """Reusing an already-consumed step-up token is rejected with 403.

    Security property (SR-14): each step-up token is single-use.  The Redis
    marker is deleted atomically on first consumption; a second presentation
    finds the key absent and must be rejected.
    """
    sender, sender_token = await make_orm_user(
        db_session,
        fake_redis,
        email=f"sender_{uuid.uuid4()}@example.com",
    )
    recipient, _ = await make_orm_user(
        db_session,
        fake_redis,
        email=f"recipient_{uuid.uuid4()}@example.com",
        session_id=f"00000000-0000-0000-cccc-{uuid.uuid4().hex[:12]}",
    )
    await _make_account(db_session, sender.id, balance=Decimal("4000.00"))
    dest_account = await _make_account(
        db_session, recipient.id, balance=Decimal("0.00")
    )

    # Seed one step-up token.
    step_up_jwt, jti = create_step_up_token(str(sender.id), _TEST_SETTINGS)
    await fake_redis.set(f"step_up:{jti}", "1")  # type: ignore[union-attr]

    headers = {
        "Authorization": f"Bearer {sender_token}",
        "X-Step-Up-Token": step_up_jwt,
    }
    payload = {
        "to_account_number": dest_account.account_number,
        "amount": "1500.00",
    }

    # First use — must succeed and consume the token.
    first = await async_client.post(TRANSFER_URL, json=payload, headers=headers)
    assert first.status_code == 200

    # Second use of the same token — must be rejected.
    second = await async_client.post(TRANSFER_URL, json=payload, headers=headers)
    assert second.status_code == 403


# ---------------------------------------------------------------------------
# Audit log assertions
# ---------------------------------------------------------------------------


async def test_transfer_audit_logs_written(
    async_client: AsyncClient,
    db_session: AsyncSession,
    fake_redis: object,
) -> None:
    """Successful transfer writes TRANSFER_INITIATED and TRANSFER_COMPLETED logs.

    Security property (SR-16): every transfer attempt must produce an audit
    record regardless of outcome.  A completed transfer additionally produces
    a TRANSFER_COMPLETED entry.
    """
    sender, sender_token = await make_orm_user(
        db_session,
        fake_redis,
        email=f"sender_{uuid.uuid4()}@example.com",
    )
    recipient, _ = await make_orm_user(
        db_session,
        fake_redis,
        email=f"recipient_{uuid.uuid4()}@example.com",
        session_id=f"00000000-0000-0000-bbbb-{uuid.uuid4().hex[:12]}",
    )
    await _make_account(db_session, sender.id, balance=Decimal("1000.00"))
    dest_account = await _make_account(db_session, recipient.id)

    response = await async_client.post(
        TRANSFER_URL,
        json={
            "to_account_number": dest_account.account_number,
            "amount": "50.00",
        },
        headers={"Authorization": f"Bearer {sender_token}"},
    )
    assert response.status_code == 200

    # Both TRANSFER_INITIATED and TRANSFER_COMPLETED must be present.
    for action in ("TRANSFER_INITIATED", "TRANSFER_COMPLETED"):
        result = await db_session.execute(
            select(AuditLog).where(
                AuditLog.user_id == sender.id,
                AuditLog.action == action,
            )
        )
        log: AuditLog | None = result.scalar_one_or_none()
        assert log is not None, f"Expected audit log entry for action='{action}'"
