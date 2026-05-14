"""Tests for SecurityEvent row writes across three security-critical paths.

All tests assert both the SecurityEvent row (new behaviour) and the existing
AuditLog row (regression guard) to ensure neither write was broken.

Test isolation: each test uses a fresh SQLite + FakeRedis via the ``async_client``
and ``db_session`` fixtures, or ``make_orm_user`` for direct ORM setup.
"""

import uuid
from decimal import Decimal

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_step_up_token, hash_token
from app.models.account import Account, AccountStatus
from app.models.audit_log import AuditLog
from app.models.refresh_token import RefreshToken
from app.models.security_event import SecurityEvent, Severity
from tests.conftest import _TEST_SETTINGS
from tests.helpers import make_orm_user, register_verify_login

_LOGIN_URL = "/api/v1/auth/login"
_REGISTER_URL = "/api/v1/auth/register"
_VERIFY_URL = "/api/v1/auth/verify-email"
_REFRESH_URL = "/api/v1/auth/refresh"
_TRANSFER_URL = "/api/v1/transactions/transfer"

_STRONG_PASSWORD = "StrongPass1!"


async def _register_and_verify(
    async_client: AsyncClient,
    capsys: pytest.CaptureFixture[str],
    email: str,
) -> str:
    """Register and email-verify a user.  Returns the registered user's ID."""
    resp = await async_client.post(
        _REGISTER_URL,
        json={"email": email, "password": _STRONG_PASSWORD},
    )
    assert resp.status_code == 201
    user_id: str = resp.json()["id"]

    raw_token = capsys.readouterr().out.strip().rsplit(": ", maxsplit=1)[-1]
    verify_resp = await async_client.get(_VERIFY_URL, params={"token": raw_token})
    assert verify_resp.status_code == 200

    return user_id


async def _make_account(
    db: AsyncSession,
    user_id: uuid.UUID,
    balance: Decimal = Decimal("5000.00"),
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


@pytest.mark.asyncio
async def test_account_locked_creates_high_security_event(
    async_client: AsyncClient,
    db_session: AsyncSession,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """After 5 consecutive failures a HIGH SecurityEvent with
    event_type=ACCOUNT_LOCKED is written; LOGIN_FAILED AuditLog
    row still exists (SR-05, SR-16, SR-17)."""
    email = f"lockout_event_{uuid.uuid4().hex[:8]}@example.com"
    user_id_str = await _register_and_verify(async_client, capsys, email)
    user_id = uuid.UUID(user_id_str)

    for attempt in range(5):
        resp = await async_client.post(
            _LOGIN_URL,
            json={"email": email, "password": "WrongPassword9!"},
        )
        assert (
            resp.status_code == 401
        ), f"Expected 401 on attempt {attempt + 1}, got {resp.status_code}"

    locked_resp = await async_client.post(
        _LOGIN_URL,
        json={"email": email, "password": _STRONG_PASSWORD},
    )
    assert locked_resp.status_code == 403

    result = await db_session.execute(
        select(SecurityEvent).where(
            SecurityEvent.event_type == "ACCOUNT_LOCKED",
            SecurityEvent.user_id == user_id,
        )
    )
    event = result.scalar_one_or_none()

    assert (
        event is not None
    ), "Expected a SecurityEvent row with event_type=ACCOUNT_LOCKED"
    assert (
        event.severity == Severity.HIGH
    ), f"ACCOUNT_LOCKED event must have severity=HIGH, got {event.severity}"
    assert event.user_id == user_id
    assert event.details is not None
    assert "locked_until" in event.details

    audit_result = await db_session.execute(
        select(AuditLog).where(
            AuditLog.action == "LOGIN_FAILED",
            AuditLog.user_id == user_id,
        )
    )
    audit_entries = audit_result.scalars().all()
    assert (
        len(audit_entries) > 0
    ), "At least one LOGIN_FAILED AuditLog row must exist (SR-16 regression guard)"

    locked_audit_result = await db_session.execute(
        select(AuditLog).where(
            AuditLog.action == "ACCOUNT_LOCKED",
            AuditLog.user_id == user_id,
        )
    )
    locked_audit = locked_audit_result.scalar_one_or_none()
    assert (
        locked_audit is not None
    ), "AuditLog row with action=ACCOUNT_LOCKED must exist for the locked user (SR-16)"
    assert locked_audit.details is not None
    assert "locked_until" in locked_audit.details


@pytest.mark.asyncio
async def test_token_reuse_creates_critical_security_event(
    async_client: AsyncClient,
    db_session: AsyncSession,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """T-20: Replaying a revoked refresh token writes a CRITICAL
    TOKEN_REUSE SecurityEvent; TOKEN_REFRESHED AuditLog still
    present (SR-08, SR-16, SR-17)."""
    email = f"token_reuse_event_{uuid.uuid4().hex[:8]}@example.com"
    user_id_str, _access = await register_verify_login(async_client, capsys, email)
    # The refresh token is now in the zt_rt HttpOnly cookie (SR-07).
    refresh_token_1 = async_client.cookies.get("zt_rt")
    assert refresh_token_1 is not None
    user_id = uuid.UUID(user_id_str)

    # Rotate — the httpx client sends the cookie automatically.
    rotate_resp = await async_client.post(_REFRESH_URL)
    assert rotate_resp.status_code == 200

    token_hash = hash_token(refresh_token_1)
    rt_result = await db_session.execute(
        select(RefreshToken).where(RefreshToken.token_hash == token_hash)
    )
    revoked_row = rt_result.scalar_one_or_none()
    assert revoked_row is not None
    assert revoked_row.revoked is True, "Token must be revoked after rotation"

    # Replay the old (now-revoked) token explicitly via cookie.
    reuse_resp = await async_client.post(
        _REFRESH_URL,
        cookies={"zt_rt": refresh_token_1},
    )
    assert reuse_resp.status_code == 401

    se_result = await db_session.execute(
        select(SecurityEvent).where(
            SecurityEvent.event_type == "TOKEN_REUSE",
            SecurityEvent.user_id == user_id,
        )
    )
    event = se_result.scalar_one_or_none()

    assert event is not None, "Expected a SecurityEvent row with event_type=TOKEN_REUSE"
    assert (
        event.severity == Severity.CRITICAL
    ), f"TOKEN_REUSE event must have severity=CRITICAL, got {event.severity}"
    assert event.user_id == user_id
    assert event.details is not None
    assert (
        "session_id" in event.details
    ), "TOKEN_REUSE event details must include session_id for forensic correlation"

    audit_result = await db_session.execute(
        select(AuditLog).where(
            AuditLog.action == "TOKEN_REFRESHED",
            AuditLog.user_id == user_id,
        )
    )
    audit_entry = audit_result.scalar_one_or_none()
    assert (
        audit_entry is not None
    ), "TOKEN_REFRESHED AuditLog row must still exist (SR-16 regression guard)"


@pytest.mark.asyncio
async def test_step_up_bypass_attempt_creates_security_event(
    async_client: AsyncClient,
    db_session: AsyncSession,
    fake_redis: object,
) -> None:
    """User A's step-up token presented by user B writes a HIGH
    STEP_UP_BYPASS_ATTEMPT SecurityEvent attributed to user B;
    AuditLog row still present (SR-13, SR-16, SR-17)."""
    user_a, _token_a = await make_orm_user(
        db_session,
        fake_redis,
        email=f"bypass_se_user_a_{uuid.uuid4().hex[:8]}@example.com",
    )
    step_up_token_for_a, jti_a = create_step_up_token(
        subject=str(user_a.id),
        settings=_TEST_SETTINGS,
    )
    await fake_redis.set(f"step_up:{jti_a}", str(user_a.id), ex=300)  # type: ignore[union-attr]

    user_b, token_b = await make_orm_user(
        db_session,
        fake_redis,
        email=f"bypass_se_user_b_{uuid.uuid4().hex[:8]}@example.com",
        session_id=f"00000000-0000-0000-5555-{uuid.uuid4().hex[:12]}",
    )
    await _make_account(db_session, user_b.id, balance=Decimal("5000.00"))

    recipient, _ = await make_orm_user(
        db_session,
        fake_redis,
        email=f"bypass_se_recipient_{uuid.uuid4().hex[:8]}@example.com",
        session_id=f"00000000-0000-0000-4444-{uuid.uuid4().hex[:12]}",
    )
    dest_account = await _make_account(
        db_session, recipient.id, balance=Decimal("0.00")
    )

    response = await async_client.post(
        _TRANSFER_URL,
        json={
            "to_account_number": dest_account.account_number,
            "amount": "1500.00",
        },
        headers={
            "Authorization": f"Bearer {token_b}",
            "X-Step-Up-Token": step_up_token_for_a,
        },
    )
    assert response.status_code == 403
    assert "mismatch" in response.json()["detail"].lower()

    se_result = await db_session.execute(
        select(SecurityEvent).where(
            SecurityEvent.event_type == "STEP_UP_BYPASS_ATTEMPT",
            SecurityEvent.user_id == user_b.id,
        )
    )
    event = se_result.scalar_one_or_none()
    assert (
        event is not None
    ), "Expected SecurityEvent STEP_UP_BYPASS_ATTEMPT attributed to user B"
    assert (
        event.severity == Severity.HIGH
    ), f"STEP_UP_BYPASS_ATTEMPT event must have severity=HIGH, got {event.severity}"
    assert event.user_id == user_b.id
    assert event.details is not None
    assert event.details.get("reason") == "subject_mismatch"
    assert event.details.get("token_sub") == str(user_a.id)

    audit_result = await db_session.execute(
        select(AuditLog).where(
            AuditLog.action == "STEP_UP_BYPASS_ATTEMPT",
            AuditLog.user_id == user_b.id,
        )
    )
    audit_entry = audit_result.scalar_one_or_none()
    assert (
        audit_entry is not None
    ), "STEP_UP_BYPASS_ATTEMPT AuditLog row must still exist (SR-16 regression guard)"
    assert audit_entry.details is not None
    assert audit_entry.details.get("reason") == "subject_mismatch"
    assert audit_entry.details.get("token_sub") == str(user_a.id)


# Registered by test_require_step_up at import time;
# available here via pytest collection order.
_STEP_UP_CHECK_URL = "/api/v1/test/step-up-check"


@pytest.mark.asyncio
async def test_step_up_bypass_via_dependency_writes_security_event(
    async_client: AsyncClient,
    db_session: AsyncSession,
    fake_redis: object,
) -> None:
    """require_step_up subject-mismatch writes a HIGH
    STEP_UP_BYPASS_ATTEMPT SecurityEvent and AuditLog row
    for user B (SR-13, SR-16, SR-17)."""
    import tests.test_require_step_up  # noqa: F401 — registers the test route

    user_a, _token_a = await make_orm_user(
        db_session,
        fake_redis,
        email=f"dep_bypass_se_a_{uuid.uuid4().hex[:8]}@example.com",
    )
    step_up_token_for_a, jti_a = create_step_up_token(
        subject=str(user_a.id),
        settings=_TEST_SETTINGS,
    )
    await fake_redis.set(f"step_up:{jti_a}", str(user_a.id), ex=300)  # type: ignore[union-attr]

    user_b, token_b = await make_orm_user(
        db_session,
        fake_redis,
        email=f"dep_bypass_se_b_{uuid.uuid4().hex[:8]}@example.com",
        session_id=f"00000000-0000-0000-6666-{uuid.uuid4().hex[:12]}",
    )

    response = await async_client.get(
        _STEP_UP_CHECK_URL,
        headers={
            "Authorization": f"Bearer {token_b}",
            "X-Step-Up-Token": step_up_token_for_a,
        },
    )
    assert response.status_code == 403
    assert "mismatch" in response.json()["detail"].lower()

    se_result = await db_session.execute(
        select(SecurityEvent).where(
            SecurityEvent.event_type == "STEP_UP_BYPASS_ATTEMPT",
            SecurityEvent.user_id == user_b.id,
        )
    )
    event = se_result.scalar_one_or_none()
    assert (
        event is not None
    ), "require_step_up subject-mismatch must write a SecurityEvent row (SR-17)"
    assert (
        event.severity == Severity.HIGH
    ), f"STEP_UP_BYPASS_ATTEMPT event must have severity=HIGH, got {event.severity}"
    assert event.user_id == user_b.id
    assert event.details is not None
    assert event.details.get("reason") == "subject_mismatch"
    assert event.details.get("token_sub") == str(user_a.id)

    audit_result = await db_session.execute(
        select(AuditLog).where(
            AuditLog.action == "STEP_UP_BYPASS_ATTEMPT",
            AuditLog.user_id == user_b.id,
        )
    )
    audit_entry = audit_result.scalar_one_or_none()
    assert (
        audit_entry is not None
    ), "require_step_up subject-mismatch must also write an AuditLog row (SR-16)"
    assert audit_entry.details is not None
    assert audit_entry.details.get("reason") == "subject_mismatch"
    assert audit_entry.details.get("token_sub") == str(user_a.id)
