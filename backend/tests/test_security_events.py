"""Tests for SecurityEvent row writes across three security-critical paths.

Covers:
- ACCOUNT_LOCKED (severity=HIGH): written after the Nth consecutive failed login
  locks the account (SR-05, SR-17).
- TOKEN_REUSE (severity=CRITICAL): written when a revoked refresh token is
  re-presented, triggering full-session revocation (SR-08, SR-17).
- STEP_UP_BYPASS_ATTEMPT (severity=HIGH): written when a step-up token whose
  ``sub`` claim belongs to a different user is presented in a transfer request
  (SR-13, SR-17).

All tests assert both the SecurityEvent row (new behaviour) and the existing
AuditLog row (regression guard) to ensure neither write was broken.

Test isolation: each test uses a fresh SQLite + FakeRedis via the ``async_client``
and ``db_session`` fixtures, or ``make_orm_user`` for direct ORM setup.
"""

from __future__ import annotations

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

# ---------------------------------------------------------------------------
# URL constants
# ---------------------------------------------------------------------------

_LOGIN_URL = "/api/v1/auth/login"
_REGISTER_URL = "/api/v1/auth/register"
_VERIFY_URL = "/api/v1/auth/verify-email"
_REFRESH_URL = "/api/v1/auth/refresh"
_TRANSFER_URL = "/api/v1/transactions/transfer"

_STRONG_PASSWORD = "StrongPass1!"


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Event 1: ACCOUNT_LOCKED (severity=HIGH)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_account_locked_creates_high_security_event(
    async_client: AsyncClient,
    db_session: AsyncSession,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """After max_failed_login_attempts (5) consecutive failures a HIGH SecurityEvent
    with event_type="ACCOUNT_LOCKED" is written for the locked user (SR-05, SR-17).

    Also asserts that the existing AuditLog row for LOGIN_FAILED still exists,
    confirming the new SecurityEvent write does not break the audit trail (SR-16).
    """
    email = f"lockout_event_{uuid.uuid4().hex[:8]}@example.com"
    user_id_str = await _register_and_verify(async_client, capsys, email)
    user_id = uuid.UUID(user_id_str)

    # Exhaust the failure threshold (default: 5).
    # See Settings.max_failed_login_attempts.
    for attempt in range(5):
        resp = await async_client.post(
            _LOGIN_URL,
            json={"email": email, "password": "WrongPassword9!"},
        )
        assert (
            resp.status_code == 401
        ), f"Expected 401 on attempt {attempt + 1}, got {resp.status_code}"

    # The account should now be locked; the correct password returns 403.
    locked_resp = await async_client.post(
        _LOGIN_URL,
        json={"email": email, "password": _STRONG_PASSWORD},
    )
    assert locked_resp.status_code == 403

    # Assert the SecurityEvent row exists scoped to the correct user (ADR-18).
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

    # Regression guard: the existing AuditLog entry for the failure path must
    # still be written (SR-16 must not have been broken by the new write).
    audit_result = await db_session.execute(
        select(AuditLog).where(
            AuditLog.action == "LOGIN_FAILED",
            AuditLog.user_id == user_id,
        )
    )
    # Multiple LOGIN_FAILED rows are expected (one per failed attempt); at least
    # one must exist.
    audit_entries = audit_result.scalars().all()
    assert (
        len(audit_entries) > 0
    ), "At least one LOGIN_FAILED AuditLog row must exist (SR-16 regression guard)"

    # Assert the ACCOUNT_LOCKED AuditLog entry was also written (SR-16).
    # The SecurityEvent row satisfies SR-17 (automated monitoring); this entry
    # satisfies SR-16 (human-readable audit trail) — both must be present.
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


# ---------------------------------------------------------------------------
# Event 2: TOKEN_REUSE (severity=CRITICAL) — T-20
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_token_reuse_creates_critical_security_event(
    async_client: AsyncClient,
    db_session: AsyncSession,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """T-20: Re-presenting an already-rotated refresh token writes a CRITICAL
    SecurityEvent with event_type="TOKEN_REUSE" for the affected user (SR-08, SR-17).

    Scenario:
    1. Register, verify, login → obtain refresh_token_1.
    2. Rotate → refresh_token_1 is now revoked.
    3. Re-present refresh_token_1 → 401 (reuse detection).
    4. Assert SecurityEvent row exists with event_type="TOKEN_REUSE" and
       severity=CRITICAL, scoped to the correct user (ADR-18).

    Also asserts the existing TOKEN_REFRESHED AuditLog row written on the
    successful rotation is still present (SR-16 regression guard).
    """
    email = f"token_reuse_event_{uuid.uuid4().hex[:8]}@example.com"
    user_id_str, _access, refresh_token_1 = await register_verify_login(
        async_client, capsys, email
    )
    user_id = uuid.UUID(user_id_str)

    # Step 2: Successful rotation — refresh_token_1 is now revoked.
    rotate_resp = await async_client.post(
        _REFRESH_URL,
        json={"refresh_token": refresh_token_1},
    )
    assert rotate_resp.status_code == 200

    # Confirm the old token is actually revoked in the DB so the scenario is
    # set up correctly.
    token_hash = hash_token(refresh_token_1)
    rt_result = await db_session.execute(
        select(RefreshToken).where(RefreshToken.token_hash == token_hash)
    )
    revoked_row = rt_result.scalar_one_or_none()
    assert revoked_row is not None
    assert revoked_row.revoked is True, "Token must be revoked after rotation"

    # Step 3: Re-present the revoked token → reuse detection → 401.
    reuse_resp = await async_client.post(
        _REFRESH_URL,
        json={"refresh_token": refresh_token_1},
    )
    assert reuse_resp.status_code == 401

    # Step 4: Assert the CRITICAL SecurityEvent row.
    # ADR-18: scope by both event_type and user_id.
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

    # Regression guard: the TOKEN_REFRESHED AuditLog row from the successful
    # rotation must still exist (SR-16 must not have been broken).
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


# ---------------------------------------------------------------------------
# Event 3: STEP_UP_BYPASS_ATTEMPT (severity=HIGH)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_step_up_bypass_attempt_creates_security_event(
    async_client: AsyncClient,
    db_session: AsyncSession,
    fake_redis: object,
) -> None:
    """Presenting a step-up token issued for user A while authenticating as user B
    writes a HIGH SecurityEvent with event_type="STEP_UP_BYPASS_ATTEMPT" attributed
    to user B (SR-13, SR-17).

    The setup mirrors
    test_transfer_rejected_and_bypass_audit_on_step_up_subject_mismatch in
    test_transfers.py.  This test adds assertions on the SecurityEvent row and
    verifies the existing STEP_UP_BYPASS_ATTEMPT AuditLog row is still present
    (SR-16 regression guard).
    """
    # User A — the step-up token is issued for this user.
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

    # User B — authenticated caller who presents user A's step-up token.
    user_b, token_b = await make_orm_user(
        db_session,
        fake_redis,
        email=f"bypass_se_user_b_{uuid.uuid4().hex[:8]}@example.com",
        session_id=f"00000000-0000-0000-5555-{uuid.uuid4().hex[:12]}",
    )
    await _make_account(db_session, user_b.id, balance=Decimal("5000.00"))

    # Recipient account for the transfer payload.
    recipient, _ = await make_orm_user(
        db_session,
        fake_redis,
        email=f"bypass_se_recipient_{uuid.uuid4().hex[:8]}@example.com",
        session_id=f"00000000-0000-0000-4444-{uuid.uuid4().hex[:12]}",
    )
    dest_account = await _make_account(
        db_session, recipient.id, balance=Decimal("0.00")
    )

    # Attempt a transfer above the $1000 threshold using user A's step-up token
    # while authenticated as user B.  Must return 403 (subject mismatch).
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

    # Assert the HIGH SecurityEvent row exists, attributed to user B (ADR-18).
    se_result = await db_session.execute(
        select(SecurityEvent).where(
            SecurityEvent.event_type == "STEP_UP_BYPASS_ATTEMPT",
            SecurityEvent.user_id == user_b.id,
        )
    )
    event = se_result.scalar_one_or_none()

    assert event is not None, (
        "Expected a SecurityEvent row with event_type=STEP_UP_BYPASS_ATTEMPT "
        "attributed to user B (the caller)"
    )
    assert (
        event.severity == Severity.HIGH
    ), f"STEP_UP_BYPASS_ATTEMPT event must have severity=HIGH, got {event.severity}"
    assert event.user_id == user_b.id
    assert event.details is not None
    assert event.details.get("reason") == "subject_mismatch"
    assert event.details.get("token_sub") == str(user_a.id)

    # Regression guard: the existing STEP_UP_BYPASS_ATTEMPT AuditLog row
    # (written by _validate_step_up_token via _write_audit) must still exist.
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


# ---------------------------------------------------------------------------
# Event 4: STEP_UP_BYPASS_ATTEMPT via require_step_up dependency (severity=HIGH)
# ---------------------------------------------------------------------------

# The test route /api/v1/test/step-up-check is registered by test_require_step_up
# at module import time.  pytest collects that module before running tests in this
# module, so the route is present in the app when these tests execute.
_STEP_UP_CHECK_URL = "/api/v1/test/step-up-check"


@pytest.mark.asyncio
async def test_step_up_bypass_via_dependency_writes_security_event(
    async_client: AsyncClient,
    db_session: AsyncSession,
    fake_redis: object,
) -> None:
    """Subject-mismatch in require_step_up writes a HIGH-severity SecurityEvent.

    This test exercises the ``require_step_up`` FastAPI dependency (not the
    ``_validate_step_up_token`` helper in transactions/service.py).  It verifies
    that Item 2 of the Phase 6 audit was correctly applied: both an AuditLog row
    and a SecurityEvent row are committed when the step-up token's ``sub`` claim
    does not match the authenticated user (SR-13, SR-17).

    Setup:
    - User A: step-up token is issued for this user and seeded in Redis.
    - User B: makes the protected request using user A's step-up token.

    Expected outcome: 403 (subject mismatch), SecurityEvent row for user B, and
    a regression-guard AuditLog row for user B.
    """
    import tests.test_require_step_up  # noqa: F401 — registers the test route

    # User A — the step-up token is issued for this user.
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

    # User B — authenticated caller who presents user A's step-up token.
    user_b, token_b = await make_orm_user(
        db_session,
        fake_redis,
        email=f"dep_bypass_se_b_{uuid.uuid4().hex[:8]}@example.com",
        session_id=f"00000000-0000-0000-6666-{uuid.uuid4().hex[:12]}",
    )

    # Hit the test-only protected endpoint with user B's bearer token but
    # user A's step-up token.  require_step_up must detect the mismatch.
    response = await async_client.get(
        _STEP_UP_CHECK_URL,
        headers={
            "Authorization": f"Bearer {token_b}",
            "X-Step-Up-Token": step_up_token_for_a,
        },
    )
    assert (
        response.status_code == 403
    ), "Subject-mismatch in require_step_up must return 403"
    assert "mismatch" in response.json()["detail"].lower()

    # SecurityEvent row must be present for user B (Item 2 — require_step_up).
    se_result = await db_session.execute(
        select(SecurityEvent).where(
            SecurityEvent.event_type == "STEP_UP_BYPASS_ATTEMPT",
            SecurityEvent.user_id == user_b.id,
        )
    )
    event = se_result.scalar_one_or_none()
    assert event is not None, (
        "require_step_up subject-mismatch must write a SecurityEvent row "
        "(SR-17; Item 2 of Phase 6 audit)"
    )
    assert (
        event.severity == Severity.HIGH
    ), f"STEP_UP_BYPASS_ATTEMPT event must have severity=HIGH, got {event.severity}"
    assert event.user_id == user_b.id
    assert event.details is not None
    assert event.details.get("reason") == "subject_mismatch"
    assert event.details.get("token_sub") == str(user_a.id)

    # Regression guard: AuditLog row must also exist (SR-16).
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
