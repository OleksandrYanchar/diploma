"""Tests for password-related auth service functions.

Phase 4 Step 4 — POST /auth/password/change
Phase 6 Step 2 — request_password_reset / confirm_password_reset service layer

Coverage:
- Correct current_password + strong new_password → 200; PASSWORD_CHANGED audit
  log written; old password no longer works; new password works (SR-01, SR-02,
  SR-16).
- Wrong current_password → 401; no PASSWORD_CHANGED audit log written.
- Weak new_password (fails SR-01) → 422; no PASSWORD_CHANGED audit log written.
- No Authorization header → 403 (HTTPBearer behaviour).
- Existing session is NOT revoked after password change (ADR-21 behaviour).

All tests create users inline with unique emails to avoid the UNIQUE constraint
issue documented in conftest.py.  The verified_user fixture is not used to
prevent email collisions across test modules.

Integration test pattern:
- Create a User via ``make_orm_user`` (ORM + Redis session seeding).
- Call the endpoint via async_client.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import fakeredis.aioredis as fakeredis_aioredis
import pytest
from fastapi import HTTPException
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.service import confirm_password_reset, request_password_reset
from app.core.security import (
    generate_refresh_token,
    hash_password,
    hash_token,
    verify_password,
)
from app.models.audit_log import AuditLog
from app.models.refresh_token import RefreshToken
from app.models.user import User, UserRole
from tests.conftest import _TEST_SETTINGS
from tests.helpers import make_orm_user

_PASSWORD_CHANGE_URL = "/api/v1/auth/password/change"
_USERS_ME_URL = "/api/v1/users/me"

_STRONG_PASSWORD = "StrongPass1!"
_NEW_STRONG_PASSWORD = "N3wStr0ngP@ss!"


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_password_change_success(
    async_client: AsyncClient,
    db_session: AsyncSession,
    fake_redis,
) -> None:
    """Correct current_password + strong new_password → 200 with audit log.

    Happy-path confirmation that:
    1. The endpoint returns HTTP 200 with the success detail.
    2. A PASSWORD_CHANGED audit log entry is committed to the database (SR-16).
    3. The old password no longer verifies against the stored hash.
    4. The new password verifies correctly against the stored hash (SR-02).
    """
    email = f"pw_change_ok_{uuid.uuid4().hex[:8]}@example.com"
    user, access_token = await make_orm_user(
        db_session, fake_redis, email, password=_STRONG_PASSWORD
    )

    response = await async_client.post(
        _PASSWORD_CHANGE_URL,
        json={
            "current_password": _STRONG_PASSWORD,
            "new_password": _NEW_STRONG_PASSWORD,
        },
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert response.status_code == 200
    assert response.json().get("detail") == "Password changed successfully"

    # Reload the user from DB to inspect the updated hash.
    result = await db_session.execute(select(User).where(User.id == user.id))
    updated_user: User | None = result.scalar_one_or_none()
    assert updated_user is not None

    # Old password must no longer match (SR-02).
    assert not verify_password(
        _STRONG_PASSWORD, updated_user.hashed_password
    ), "Old password must not verify after change"

    # New password must match (SR-02).
    assert verify_password(
        _NEW_STRONG_PASSWORD, updated_user.hashed_password
    ), "New password must verify after change"

    # A PASSWORD_CHANGED audit log entry must exist for this user (SR-16).
    audit_result = await db_session.execute(
        select(AuditLog).where(
            AuditLog.action == "PASSWORD_CHANGED",
            AuditLog.user_id == user.id,
        )
    )
    log_entry: AuditLog | None = audit_result.scalar_one_or_none()
    assert log_entry is not None, "Expected a PASSWORD_CHANGED audit log entry"
    assert log_entry.details is not None
    assert log_entry.details.get("email") == email


@pytest.mark.asyncio
async def test_password_change_wrong_current_password_returns_401(
    async_client: AsyncClient,
    db_session: AsyncSession,
    fake_redis,
) -> None:
    """Wrong current_password → 401; no PASSWORD_CHANGED audit log written.

    The service must reject an incorrect current password immediately (SR-02).
    No audit log entry must be written on failure — audit on success path only.
    """
    email = f"pw_change_wrong_pw_{uuid.uuid4().hex[:8]}@example.com"
    user, access_token = await make_orm_user(
        db_session, fake_redis, email, password=_STRONG_PASSWORD
    )

    response = await async_client.post(
        _PASSWORD_CHANGE_URL,
        json={
            "current_password": "WrongPassword99!",
            "new_password": _NEW_STRONG_PASSWORD,
        },
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert response.status_code == 401
    assert "invalid" in response.json()["detail"].lower()

    # No PASSWORD_CHANGED audit log must exist for this user.
    audit_result = await db_session.execute(
        select(AuditLog).where(
            AuditLog.action == "PASSWORD_CHANGED",
            AuditLog.user_id == user.id,
        )
    )
    log_entry: AuditLog | None = audit_result.scalar_one_or_none()
    assert log_entry is None, "No PASSWORD_CHANGED audit log must be written on failure"


@pytest.mark.asyncio
async def test_password_change_weak_new_password_returns_422(
    async_client: AsyncClient,
    db_session: AsyncSession,
    fake_redis,
) -> None:
    """Correct current_password but weak new_password → 422; no audit log.

    The SR-01 strength policy must be enforced on the new password.  A password
    that fails the policy (e.g. too short, no special character) must be rejected
    with HTTP 422.  No PASSWORD_CHANGED audit entry must be written.
    """
    email = f"pw_change_weak_{uuid.uuid4().hex[:8]}@example.com"
    user, access_token = await make_orm_user(
        db_session, fake_redis, email, password=_STRONG_PASSWORD
    )

    # "password123" fails SR-01: no uppercase, no special character.
    response = await async_client.post(
        _PASSWORD_CHANGE_URL,
        json={
            "current_password": _STRONG_PASSWORD,
            "new_password": "password123",
        },
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert response.status_code == 422

    # No PASSWORD_CHANGED audit log must exist for this user.
    audit_result = await db_session.execute(
        select(AuditLog).where(
            AuditLog.action == "PASSWORD_CHANGED",
            AuditLog.user_id == user.id,
        )
    )
    log_entry: AuditLog | None = audit_result.scalar_one_or_none()
    assert log_entry is None, "No PASSWORD_CHANGED audit log must be written on failure"


@pytest.mark.asyncio
async def test_password_change_unauthenticated_returns_403(
    async_client: AsyncClient,
) -> None:
    """POST /auth/password/change without Authorization header returns 403.

    ``HTTPBearer`` raises HTTP 403 (not 401) when the Authorization header is
    entirely absent.  The endpoint must not be accessible without a valid
    Bearer credential.
    """
    response = await async_client.post(
        _PASSWORD_CHANGE_URL,
        json={
            "current_password": _STRONG_PASSWORD,
            "new_password": _NEW_STRONG_PASSWORD,
        },
    )

    assert response.status_code == 403


@pytest.mark.asyncio
async def test_password_change_does_not_revoke_existing_session(
    async_client: AsyncClient,
    db_session: AsyncSession,
    fake_redis,
) -> None:
    """Existing session remains valid after a password change (ADR-21).

    The password change endpoint explicitly does NOT revoke active sessions.
    After a successful password change, a request to GET /users/me using the
    same access token and session must still return HTTP 200.

    This test documents and asserts the ADR-21 behaviour: session revocation
    on password change is deferred to Phase 6 (password reset flow).
    """
    email = f"pw_change_no_revoke_{uuid.uuid4().hex[:8]}@example.com"
    user, access_token = await make_orm_user(
        db_session, fake_redis, email, password=_STRONG_PASSWORD
    )

    # Change the password.
    change_resp = await async_client.post(
        _PASSWORD_CHANGE_URL,
        json={
            "current_password": _STRONG_PASSWORD,
            "new_password": _NEW_STRONG_PASSWORD,
        },
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert change_resp.status_code == 200

    # The original access token must still be accepted — session is intact
    # (ADR-21: session revocation is NOT performed on password change).
    me_resp = await async_client.get(
        _USERS_ME_URL,
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert (
        me_resp.status_code == 200
    ), "Session must remain valid after password change (ADR-21 behaviour)"


@pytest.mark.asyncio
async def test_password_change_missing_new_password_returns_422(
    async_client: AsyncClient,
    db_session: AsyncSession,
    fake_redis,
) -> None:
    """POST /auth/password/change without new_password in body returns 422.

    The ``PasswordChangeRequest`` schema requires both ``current_password`` and
    ``new_password``. Omitting either must trigger Pydantic validation failure.
    """
    email = f"pw_missing_{uuid.uuid4().hex[:8]}@example.com"
    user, access_token = await make_orm_user(
        db_session, fake_redis, email, password=_STRONG_PASSWORD
    )

    resp = await async_client.post(
        _PASSWORD_CHANGE_URL,
        json={"current_password": _STRONG_PASSWORD},
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_password_change_unverified_user_allowed(
    async_client: AsyncClient,
    db_session: AsyncSession,
    fake_redis,
) -> None:
    """Unverified users can change their password (no require_verified).

    Per the implementation, POST /auth/password/change depends only on
    get_current_user, not require_verified. An unverified user with a valid
    session must be able to change their password.
    """
    email = f"pw_unverified_{uuid.uuid4().hex[:8]}@example.com"
    user, token = await make_orm_user(
        db_session,
        fake_redis,
        email,
        password=_STRONG_PASSWORD,
        is_verified=False,
    )

    resp = await async_client.post(
        _PASSWORD_CHANGE_URL,
        json={
            "current_password": _STRONG_PASSWORD,
            "new_password": _NEW_STRONG_PASSWORD,
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Login with old password after password change
# ---------------------------------------------------------------------------

_LOGIN_URL = "/api/v1/auth/login"


@pytest.mark.asyncio
async def test_login_with_old_password_fails_after_change(
    async_client: AsyncClient,
    db_session: AsyncSession,
    fake_redis,
) -> None:
    """After a password change, the old password must be rejected (SR-02).

    This is a high-value regression guard: if password hashing or storage
    is broken, both old and new passwords might succeed.  We verify that
    only the new password works and the old one returns 401.
    """
    email = f"pw_old_login_{uuid.uuid4().hex[:8]}@example.com"
    user, access_token = await make_orm_user(
        db_session, fake_redis, email, password=_STRONG_PASSWORD
    )

    change = await async_client.post(
        _PASSWORD_CHANGE_URL,
        json={
            "current_password": _STRONG_PASSWORD,
            "new_password": _NEW_STRONG_PASSWORD,
        },
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert change.status_code == 200

    old_pw_login = await async_client.post(
        _LOGIN_URL,
        json={"email": email, "password": _STRONG_PASSWORD},
    )
    assert old_pw_login.status_code == 401

    new_pw_login = await async_client.post(
        _LOGIN_URL,
        json={"email": email, "password": _NEW_STRONG_PASSWORD},
    )
    assert new_pw_login.status_code == 200


# ---------------------------------------------------------------------------
# Phase 6 Step 2 — request_password_reset / confirm_password_reset
#
# These tests call the service functions directly (no HTTP endpoints yet).
# Router endpoint tests will be added when endpoints are wired in the next step.
#
# ADR-18: AuditLog queries always filter by both action AND user_id.
# SR-18: Non-enumeration — request always returns None; caller sees no
#         difference between found and not-found email.
# ---------------------------------------------------------------------------

_RESET_STRONG_PASSWORD = "R3setStr0ng@Pass!"
_RESET_WEAK_PASSWORD = "weak"


# ---------------------------------------------------------------------------
# request_password_reset
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_password_reset_request_nonexistent_email_is_silent(
    db_session: AsyncSession,
    fake_redis,
) -> None:
    """Requesting reset for unknown email does not raise; audit has email_found=False.

    SR-18: the caller must always return HTTP 200 regardless of whether the
    email exists.  This test confirms the service raises nothing and that the
    audit log records email_found=False so the security trail is intact.
    """
    unknown_email = f"no_such_user_{uuid.uuid4().hex[:8]}@example.com"

    # Must not raise.
    await request_password_reset(unknown_email, db_session, _TEST_SETTINGS)

    # An audit log entry must exist with email_found=False.
    audit_result = await db_session.execute(
        select(AuditLog).where(
            AuditLog.action == "PASSWORD_RESET_REQUESTED",
            AuditLog.user_id.is_(None),
        )
    )
    entries = audit_result.scalars().all()
    # At least one entry for this call must have email_found=False.
    assert any(
        e.details is not None and e.details.get("email_found") is False for e in entries
    ), "Expected an audit log entry with email_found=False for unknown email"


@pytest.mark.asyncio
async def test_password_reset_request_known_email_stores_hash(
    db_session: AsyncSession,
    fake_redis,
) -> None:
    """Requesting reset for a valid email sets password_reset_token_hash and sent_at.

    Verifies that:
    - password_reset_token_hash is populated (non-None).
    - password_reset_sent_at is set to a recent UTC timestamp.
    - An audit log entry with email_found=True is written (SR-16).
    """
    email = f"reset_known_{uuid.uuid4().hex[:8]}@example.com"
    user, _ = await make_orm_user(db_session, fake_redis, email)

    before = datetime.now(timezone.utc)
    await request_password_reset(email, db_session, _TEST_SETTINGS)
    after = datetime.now(timezone.utc)

    # Reload from DB to check persisted state.
    result = await db_session.execute(select(User).where(User.id == user.id))
    updated: User = result.scalar_one()

    assert (
        updated.password_reset_token_hash is not None
    ), "password_reset_token_hash must be set after reset request"
    assert (
        updated.password_reset_sent_at is not None
    ), "password_reset_sent_at must be set after reset request"

    # Normalise for SQLite (ADR-17).
    sent_at = updated.password_reset_sent_at
    if sent_at.tzinfo is None:
        sent_at = sent_at.replace(tzinfo=timezone.utc)
    assert (
        before <= sent_at <= after
    ), "password_reset_sent_at must be within the test's time window"

    # Audit log entry must exist for this user with email_found=True (ADR-18).
    audit_result = await db_session.execute(
        select(AuditLog).where(
            AuditLog.action == "PASSWORD_RESET_REQUESTED",
            AuditLog.user_id == user.id,
        )
    )
    entry = audit_result.scalar_one_or_none()
    assert entry is not None, "Expected PASSWORD_RESET_REQUESTED audit entry"
    assert entry.details is not None
    assert entry.details.get("email_found") is True


# ---------------------------------------------------------------------------
# confirm_password_reset — rejection paths
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_password_reset_confirm_invalid_token_raises_400(
    db_session: AsyncSession,
    fake_redis,
) -> None:
    """Presenting a token whose hash is not in the DB raises HTTPException 400."""
    bogus_token = "this-token-does-not-exist-in-the-database-at-all"

    with pytest.raises(HTTPException) as exc_info:
        await confirm_password_reset(
            bogus_token, _RESET_STRONG_PASSWORD, db_session, fake_redis, _TEST_SETTINGS
        )

    assert exc_info.value.status_code == 400
    assert "invalid or expired" in exc_info.value.detail.lower()


@pytest.mark.asyncio
async def test_password_reset_confirm_expired_token_raises_400(
    db_session: AsyncSession,
    fake_redis,
) -> None:
    """A token whose password_reset_sent_at is beyond the TTL raises HTTPException 400.

    The service must reject a token that was issued more than
    settings.password_reset_token_ttl_minutes ago, even if the hash matches.
    """
    email = f"reset_expired_{uuid.uuid4().hex[:8]}@example.com"
    user, _ = await make_orm_user(db_session, fake_redis, email)

    raw_token = generate_refresh_token()

    # Manually set an expired sent_at (31 minutes ago).
    user.password_reset_token_hash = hash_token(raw_token)
    user.password_reset_sent_at = datetime.now(timezone.utc) - timedelta(minutes=31)
    await db_session.commit()

    with pytest.raises(HTTPException) as exc_info:
        await confirm_password_reset(
            raw_token, _RESET_STRONG_PASSWORD, db_session, fake_redis, _TEST_SETTINGS
        )

    assert exc_info.value.status_code == 400
    assert "invalid or expired" in exc_info.value.detail.lower()


@pytest.mark.asyncio
async def test_password_reset_confirm_weak_password_raises_422(
    db_session: AsyncSession,
    fake_redis,
) -> None:
    """A valid token paired with a weak new password raises HTTPException 422 (SR-01).

    The SR-01 password strength policy is enforced before any state mutation.
    """
    email = f"reset_weak_pw_{uuid.uuid4().hex[:8]}@example.com"
    user, _ = await make_orm_user(db_session, fake_redis, email)

    raw_token = generate_refresh_token()
    user.password_reset_token_hash = hash_token(raw_token)
    user.password_reset_sent_at = datetime.now(timezone.utc)
    await db_session.commit()

    with pytest.raises(HTTPException) as exc_info:
        await confirm_password_reset(
            raw_token, _RESET_WEAK_PASSWORD, db_session, fake_redis, _TEST_SETTINGS
        )

    assert exc_info.value.status_code == 422
    assert "strength" in exc_info.value.detail.lower()


# ---------------------------------------------------------------------------
# confirm_password_reset — success path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_password_reset_confirm_valid_token_sets_new_password(
    db_session: AsyncSession,
    fake_redis,
) -> None:
    """T-18 (partial): a valid token changes the password and clears reset fields.

    Verifies:
    - hashed_password is updated (new password verifies; old password does not).
    - password_reset_token_hash is cleared to None (SR-18 single-use).
    - password_reset_sent_at is cleared to None.
    - A PASSWORD_RESET_COMPLETED audit log entry is written (SR-16, ADR-18).
    """
    email = f"reset_ok_{uuid.uuid4().hex[:8]}@example.com"
    original_password = "OriginalP@ss1!"
    user, _ = await make_orm_user(
        db_session, fake_redis, email, password=original_password
    )

    raw_token = generate_refresh_token()
    user.password_reset_token_hash = hash_token(raw_token)
    user.password_reset_sent_at = datetime.now(timezone.utc)
    await db_session.commit()

    await confirm_password_reset(
        raw_token, _RESET_STRONG_PASSWORD, db_session, fake_redis, _TEST_SETTINGS
    )

    result = await db_session.execute(select(User).where(User.id == user.id))
    updated: User = result.scalar_one()

    # New password must verify (SR-02).
    assert verify_password(
        _RESET_STRONG_PASSWORD, updated.hashed_password
    ), "New password must verify after reset"
    # Old password must no longer verify (SR-02).
    assert not verify_password(
        original_password, updated.hashed_password
    ), "Old password must not verify after reset"

    # Reset fields must be cleared (SR-18 single-use token).
    assert updated.password_reset_token_hash is None
    assert updated.password_reset_sent_at is None

    # Audit log entry must exist for this user (SR-16, ADR-18).
    audit_result = await db_session.execute(
        select(AuditLog).where(
            AuditLog.action == "PASSWORD_RESET_COMPLETED",
            AuditLog.user_id == user.id,
        )
    )
    entry = audit_result.scalar_one_or_none()
    assert entry is not None, "Expected a PASSWORD_RESET_COMPLETED audit log entry"


@pytest.mark.asyncio
async def test_password_reset_confirm_revokes_refresh_tokens(
    db_session: AsyncSession,
    fake_redis,
) -> None:
    """T-18 (core): after confirm, all RefreshToken rows for the user are deleted.

    Creates two RefreshToken rows for the user, then calls confirm_password_reset.
    Both rows must be gone from the database afterwards (SR-07).
    """
    email = f"reset_rt_{uuid.uuid4().hex[:8]}@example.com"
    user, _ = await make_orm_user(db_session, fake_redis, email)

    # Insert two refresh token rows directly to simulate two active sessions.
    rt1 = RefreshToken(
        user_id=user.id,
        token_hash=hash_token(generate_refresh_token()),
        session_id=uuid.uuid4(),
        expires_at=datetime.now(timezone.utc) + timedelta(days=7),
    )
    rt2 = RefreshToken(
        user_id=user.id,
        token_hash=hash_token(generate_refresh_token()),
        session_id=uuid.uuid4(),
        expires_at=datetime.now(timezone.utc) + timedelta(days=7),
    )
    db_session.add(rt1)
    db_session.add(rt2)

    # Set a valid reset token.
    raw_token = generate_refresh_token()
    user.password_reset_token_hash = hash_token(raw_token)
    user.password_reset_sent_at = datetime.now(timezone.utc)
    await db_session.commit()

    await confirm_password_reset(
        raw_token, _RESET_STRONG_PASSWORD, db_session, fake_redis, _TEST_SETTINGS
    )

    # No RefreshToken rows must remain for this user (SR-07).
    rt_result = await db_session.execute(
        select(RefreshToken).where(RefreshToken.user_id == user.id)
    )
    remaining = rt_result.scalars().all()
    assert (
        len(remaining) == 0
    ), "All RefreshToken rows must be deleted after password reset (SR-07)"


@pytest.mark.asyncio
async def test_password_reset_confirm_revokes_redis_sessions(
    db_session: AsyncSession,
) -> None:
    """After confirm, all Redis session keys for the user are removed (SR-10).

    Seeds two session keys for the user (and one decoy key for another user)
    in a fresh FakeRedis instance.  After confirm, both user session keys must
    be absent while the decoy remains intact.
    """
    # Use a dedicated FakeRedis instance for precise key control.
    redis = fakeredis_aioredis.FakeRedis(decode_responses=True)

    email = f"reset_redis_{uuid.uuid4().hex[:8]}@example.com"
    # Create the user directly — do not use make_orm_user so we control
    # exactly which session keys exist in Redis.
    user = User(
        email=email,
        hashed_password=hash_password("OriginalP@ss1!"),
        role=UserRole.USER,
        is_active=True,
        is_verified=True,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)

    session_a = f"session:{uuid.uuid4()}"
    session_b = f"session:{uuid.uuid4()}"
    decoy_session = f"session:{uuid.uuid4()}"

    await redis.set(session_a, str(user.id))
    await redis.set(session_b, str(user.id))
    await redis.set(decoy_session, str(uuid.uuid4()))  # Different user — must survive.

    raw_token = generate_refresh_token()
    user.password_reset_token_hash = hash_token(raw_token)
    user.password_reset_sent_at = datetime.now(timezone.utc)
    await db_session.commit()

    await confirm_password_reset(
        raw_token, _RESET_STRONG_PASSWORD, db_session, redis, _TEST_SETTINGS
    )

    # Both user session keys must be gone (SR-10).
    assert await redis.get(session_a) is None, "session_a must be deleted after reset"
    assert await redis.get(session_b) is None, "session_b must be deleted after reset"

    # Decoy for a different user must still exist.
    assert (
        await redis.get(decoy_session) is not None
    ), "Decoy session for another user must not be deleted"

    await redis.aclose()
