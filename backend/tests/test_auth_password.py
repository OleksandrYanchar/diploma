"""Tests for password-related auth service functions and HTTP endpoints.

Coverage:
- Correct current_password + strong new_password → 200; PASSWORD_CHANGED audit
  log written; old password no longer works; new password works (SR-01, SR-02,
  SR-16).
- Wrong current_password → 401; no PASSWORD_CHANGED audit log written.
- Weak new_password (fails SR-01) → 422; no PASSWORD_CHANGED audit log written.
- No Authorization header → 403 (HTTPBearer behaviour).
- Existing session is NOT revoked after password change (ADR-21 behaviour).
- T-17: POST /auth/password/reset/request always returns 200 (SR-18 non-enumeration).
- T-18: POST /auth/password/reset/confirm revokes all sessions and refresh tokens
  after a successful reset (SR-07, SR-10).

All tests create users inline with unique emails to avoid the UNIQUE constraint
issue documented in conftest.py.  The verified_user fixture is not used to
prevent email collisions across test modules.

Integration test pattern:
- Create a User via ``make_orm_user`` (ORM + Redis session seeding).
- Call the endpoint via async_client.
"""

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


@pytest.mark.asyncio
async def test_password_change_success(
    async_client: AsyncClient,
    db_session: AsyncSession,
    fake_redis,
) -> None:
    """Correct current_password + strong new_password → 200;
    audit log; old hash replaced (SR-02, SR-16)."""
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

    assert not verify_password(
        _STRONG_PASSWORD, updated_user.hashed_password
    ), "Old password must not verify after change"

    assert verify_password(
        _NEW_STRONG_PASSWORD, updated_user.hashed_password
    ), "New password must verify after change"

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
    """Wrong current_password → 401; no PASSWORD_CHANGED audit log written (SR-02)."""
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
    """Correct current_password but weak new_password → 422; no audit log (SR-01)."""
    email = f"pw_change_weak_{uuid.uuid4().hex[:8]}@example.com"
    user, access_token = await make_orm_user(
        db_session, fake_redis, email, password=_STRONG_PASSWORD
    )

    response = await async_client.post(
        _PASSWORD_CHANGE_URL,
        json={
            "current_password": _STRONG_PASSWORD,
            "new_password": "password123",
        },
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert response.status_code == 422

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
    """POST /auth/password/change without Authorization header
    returns 403 (HTTPBearer)."""
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
    """Existing session remains valid after a password change
    (ADR-21: no revocation on change)."""
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
    """POST /auth/password/change without new_password
    returns 422 (Pydantic validation)."""
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
    """Unverified users can change their password
    — endpoint has no require_verified guard."""
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


_LOGIN_URL = "/api/v1/auth/login"


@pytest.mark.asyncio
async def test_login_with_old_password_fails_after_change(
    async_client: AsyncClient,
    db_session: AsyncSession,
    fake_redis,
) -> None:
    """After a password change, old password returns 401
    and new password returns 200 (SR-02)."""
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


_RESET_STRONG_PASSWORD = "R3setStr0ng@Pass!"
_RESET_WEAK_PASSWORD = "weak"


@pytest.mark.asyncio
async def test_password_reset_request_nonexistent_email_is_silent(
    db_session: AsyncSession,
    fake_redis,
) -> None:
    """Unknown email: service does not raise;
    audit records email_found=False (SR-18)."""
    unknown_email = f"no_such_user_{uuid.uuid4().hex[:8]}@example.com"

    await request_password_reset(unknown_email, db_session, _TEST_SETTINGS)

    audit_result = await db_session.execute(
        select(AuditLog).where(
            AuditLog.action == "PASSWORD_RESET_REQUESTED",
            AuditLog.user_id.is_(None),
        )
    )
    entries = audit_result.scalars().all()
    assert any(
        e.details is not None and e.details.get("email_found") is False for e in entries
    ), "Expected an audit log entry with email_found=False for unknown email"


@pytest.mark.asyncio
async def test_password_reset_request_known_email_stores_hash(
    db_session: AsyncSession,
    fake_redis,
) -> None:
    """Known email: password_reset_token_hash set; sent_at within test window;
    email_found=True audit (SR-16)."""
    email = f"reset_known_{uuid.uuid4().hex[:8]}@example.com"
    user, _ = await make_orm_user(db_session, fake_redis, email)

    before = datetime.now(timezone.utc)
    await request_password_reset(email, db_session, _TEST_SETTINGS)
    after = datetime.now(timezone.utc)

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
    """Token with expired sent_at (beyond TTL) raises HTTPException 400."""
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
    """Valid token + weak new_password raises HTTPException 422
    (SR-01 enforced before mutation)."""
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


@pytest.mark.asyncio
async def test_password_reset_confirm_valid_token_sets_new_password(
    db_session: AsyncSession,
    fake_redis,
) -> None:
    """T-18 (partial): valid token sets new password, clears reset fields,
    writes audit (SR-16, SR-18)."""
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

    assert verify_password(
        _RESET_STRONG_PASSWORD, updated.hashed_password
    ), "New password must verify after reset"
    assert not verify_password(
        original_password, updated.hashed_password
    ), "Old password must not verify after reset"

    assert updated.password_reset_token_hash is None
    assert updated.password_reset_sent_at is None

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
    """T-18 (core): after confirm, all RefreshToken rows
    for the user are deleted (SR-07)."""
    email = f"reset_rt_{uuid.uuid4().hex[:8]}@example.com"
    user, _ = await make_orm_user(db_session, fake_redis, email)

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

    raw_token = generate_refresh_token()
    user.password_reset_token_hash = hash_token(raw_token)
    user.password_reset_sent_at = datetime.now(timezone.utc)
    await db_session.commit()

    await confirm_password_reset(
        raw_token, _RESET_STRONG_PASSWORD, db_session, fake_redis, _TEST_SETTINGS
    )

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
    """After confirm, all Redis session keys for the user are removed;
    decoy key survives (SR-10)."""
    redis = fakeredis_aioredis.FakeRedis(decode_responses=True)

    email = f"reset_redis_{uuid.uuid4().hex[:8]}@example.com"
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
    await redis.set(decoy_session, str(uuid.uuid4()))

    raw_token = generate_refresh_token()
    user.password_reset_token_hash = hash_token(raw_token)
    user.password_reset_sent_at = datetime.now(timezone.utc)
    await db_session.commit()

    await confirm_password_reset(
        raw_token, _RESET_STRONG_PASSWORD, db_session, redis, _TEST_SETTINGS
    )

    assert await redis.get(session_a) is None, "session_a must be deleted after reset"
    assert await redis.get(session_b) is None, "session_b must be deleted after reset"

    assert (
        await redis.get(decoy_session) is not None
    ), "Decoy session for another user must not be deleted"

    await redis.aclose()


_RESET_REQUEST_URL = "/api/v1/auth/password/reset/request"
_RESET_CONFIRM_URL = "/api/v1/auth/password/reset/confirm"
_REFRESH_URL = "/api/v1/auth/refresh"


@pytest.mark.asyncio
async def test_reset_request_nonexistent_email_returns_200(
    async_client: AsyncClient,
) -> None:
    """T-17: POST /reset/request with unknown email returns 200
    — non-enumeration (SR-18)."""
    response = await async_client.post(
        _RESET_REQUEST_URL,
        json={"email": f"no_such_{uuid.uuid4().hex[:8]}@example.com"},
    )

    assert response.status_code == 200
    assert response.json() == {
        "message": "If that email is registered, a reset link has been sent"
    }


@pytest.mark.asyncio
async def test_reset_request_known_email_returns_200(
    async_client: AsyncClient,
    db_session: AsyncSession,
    fake_redis,
) -> None:
    """T-17 (complementary): POST /reset/request with a known email
    returns the same 200 body (SR-18)."""
    email = f"reset_http_known_{uuid.uuid4().hex[:8]}@example.com"
    await make_orm_user(db_session, fake_redis, email)

    response = await async_client.post(_RESET_REQUEST_URL, json={"email": email})

    assert response.status_code == 200
    assert response.json() == {
        "message": "If that email is registered, a reset link has been sent"
    }


@pytest.mark.asyncio
async def test_reset_request_stores_hash_on_known_email(
    async_client: AsyncClient,
    db_session: AsyncSession,
    fake_redis,
) -> None:
    """After POST /reset/request, password_reset_token_hash is stored in the DB."""
    email = f"reset_http_hash_{uuid.uuid4().hex[:8]}@example.com"
    user, _ = await make_orm_user(db_session, fake_redis, email)

    assert user.password_reset_token_hash is None

    response = await async_client.post(_RESET_REQUEST_URL, json={"email": email})
    assert response.status_code == 200

    result = await db_session.execute(select(User).where(User.id == user.id))
    updated: User = result.scalar_one()
    assert (
        updated.password_reset_token_hash is not None
    ), "password_reset_token_hash must be populated after /reset/request"
    assert (
        updated.password_reset_sent_at is not None
    ), "password_reset_sent_at must be set after /reset/request"


@pytest.mark.asyncio
async def test_reset_confirm_valid_token_returns_200(
    async_client: AsyncClient,
    db_session: AsyncSession,
    fake_redis,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """POST /reset/confirm with a valid token returns HTTP 200."""
    email = f"reset_http_ok_{uuid.uuid4().hex[:8]}@example.com"
    await make_orm_user(db_session, fake_redis, email)

    await request_password_reset(email=email, db=db_session, settings=_TEST_SETTINGS)
    captured = capsys.readouterr()
    raw_token = captured.out.strip().rsplit(": ", maxsplit=1)[-1]

    response = await async_client.post(
        _RESET_CONFIRM_URL,
        json={"token": raw_token, "new_password": _RESET_STRONG_PASSWORD},
    )

    assert response.status_code == 200
    assert response.json() == {"message": "Password reset successful"}


@pytest.mark.asyncio
async def test_reset_confirm_invalid_token_returns_400(
    async_client: AsyncClient,
) -> None:
    """POST /reset/confirm with a bogus token returns HTTP 400."""
    response = await async_client.post(
        _RESET_CONFIRM_URL,
        json={
            "token": "totally-bogus-token-that-does-not-exist",
            "new_password": _RESET_STRONG_PASSWORD,
        },
    )

    assert response.status_code == 400
    assert "invalid or expired" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_reset_confirm_expired_token_returns_400(
    async_client: AsyncClient,
    db_session: AsyncSession,
    fake_redis,
) -> None:
    """POST /reset/confirm with an expired token (sent_at + 31 min) returns HTTP 400."""
    email = f"reset_http_expired_{uuid.uuid4().hex[:8]}@example.com"
    user, _ = await make_orm_user(db_session, fake_redis, email)

    raw_token = generate_refresh_token()
    user.password_reset_token_hash = hash_token(raw_token)
    user.password_reset_sent_at = datetime.now(timezone.utc) - timedelta(minutes=31)
    await db_session.commit()

    response = await async_client.post(
        _RESET_CONFIRM_URL,
        json={"token": raw_token, "new_password": _RESET_STRONG_PASSWORD},
    )

    assert response.status_code == 400
    assert "invalid or expired" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_reset_confirm_weak_password_returns_422(
    async_client: AsyncClient,
    db_session: AsyncSession,
    fake_redis,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """POST /reset/confirm with weak new_password returns 422 (SR-01)."""
    email = f"reset_http_weak_{uuid.uuid4().hex[:8]}@example.com"
    await make_orm_user(db_session, fake_redis, email)

    await request_password_reset(email=email, db=db_session, settings=_TEST_SETTINGS)
    captured = capsys.readouterr()
    raw_token = captured.out.strip().rsplit(": ", maxsplit=1)[-1]

    response = await async_client.post(
        _RESET_CONFIRM_URL,
        json={"token": raw_token, "new_password": "weak"},
    )

    assert response.status_code == 422


@pytest.mark.asyncio
async def test_reset_confirm_revokes_sessions(
    async_client: AsyncClient,
    db_session: AsyncSession,
    fake_redis,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """T-18: after POST /reset/confirm, pre-reset refresh token
    is rejected (SR-07, SR-10)."""
    import uuid as _uuid

    email = f"reset_http_revoke_{uuid.uuid4().hex[:8]}@example.com"
    user, _ = await make_orm_user(db_session, fake_redis, email)

    raw_refresh = generate_refresh_token()
    session_id = str(_uuid.uuid4())
    rt_row = RefreshToken(
        user_id=user.id,
        token_hash=hash_token(raw_refresh),
        session_id=_uuid.UUID(session_id),
        expires_at=datetime.now(timezone.utc) + timedelta(days=7),
    )
    db_session.add(rt_row)
    await db_session.commit()
    await fake_redis.set(f"session:{session_id}", str(user.id))

    await request_password_reset(email=email, db=db_session, settings=_TEST_SETTINGS)
    captured = capsys.readouterr()
    raw_token = captured.out.strip().rsplit(": ", maxsplit=1)[-1]

    confirm_resp = await async_client.post(
        _RESET_CONFIRM_URL,
        json={"token": raw_token, "new_password": _RESET_STRONG_PASSWORD},
    )
    assert confirm_resp.status_code == 200

    refresh_resp = await async_client.post(
        _REFRESH_URL,
        json={"refresh_token": raw_refresh},
    )
    assert (
        refresh_resp.status_code == 401
    ), "Refresh token issued before password reset must be rejected after reset (T-18)"


@pytest.mark.asyncio
async def test_reset_confirm_audit_log_written(
    async_client: AsyncClient,
    db_session: AsyncSession,
    fake_redis,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """After POST /reset/confirm, PASSWORD_RESET_COMPLETED audit log exists (SR-16)."""
    email = f"reset_http_audit_{uuid.uuid4().hex[:8]}@example.com"
    user, _ = await make_orm_user(db_session, fake_redis, email)

    await request_password_reset(email=email, db=db_session, settings=_TEST_SETTINGS)
    captured = capsys.readouterr()
    raw_token = captured.out.strip().rsplit(": ", maxsplit=1)[-1]

    response = await async_client.post(
        _RESET_CONFIRM_URL,
        json={"token": raw_token, "new_password": _RESET_STRONG_PASSWORD},
    )
    assert response.status_code == 200

    audit_result = await db_session.execute(
        select(AuditLog).where(
            AuditLog.action == "PASSWORD_RESET_COMPLETED",
            AuditLog.user_id == user.id,
        )
    )
    entry = audit_result.scalar_one_or_none()
    assert entry is not None, "Expected a PASSWORD_RESET_COMPLETED audit log entry"
    assert entry.details is not None
    assert entry.details.get("email") == email


@pytest.mark.asyncio
async def test_change_password_wrong_password_triggers_lockout(
    async_client: AsyncClient,
    db_session: AsyncSession,
    fake_redis,
) -> None:
    """Repeated wrong-password calls to change_password trigger lockout (M-3/SR-05)."""
    email = f"cpw_lockout_{uuid.uuid4().hex[:8]}@example.com"
    user, access_token = await make_orm_user(
        db_session, fake_redis, email, password=_STRONG_PASSWORD
    )

    max_attempts = _TEST_SETTINGS.max_failed_login_attempts
    headers = {"Authorization": f"Bearer {access_token}"}

    for _ in range(max_attempts):
        resp = await async_client.post(
            _PASSWORD_CHANGE_URL,
            json={
                "current_password": "WrongPassword99!",
                "new_password": "NewPass123!@",
            },
            headers=headers,
        )
        assert resp.status_code == 401

    # After max_attempts failures, account should be locked.
    result = await db_session.execute(select(User).where(User.id == user.id))
    locked_user = result.scalar_one()
    assert (
        locked_user.locked_until is not None
    ), "Account must be locked after repeated wrong-password submissions (M-3)"


@pytest.mark.asyncio
async def test_password_reset_token_is_single_use(
    async_client: AsyncClient,
    db_session: AsyncSession,
    fake_redis,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A password reset token can only be used once.

    SR-18: the reset token hash is cleared on successful use.  A second call
    with the same token must return 400 (invalid or already-used token) rather
    than resetting the password a second time.

    Regression guard: if confirm_password_reset failed to clear the hash, an
    attacker who intercepts the reset link could reset the password again after
    the legitimate user has already completed the flow.
    """
    email = f"reset_single_use_{uuid.uuid4().hex[:8]}@example.com"
    await make_orm_user(db_session, fake_redis, email)

    # Request a reset token (DEMO MODE prints it to stdout).
    await request_password_reset(email=email, db=db_session, settings=_TEST_SETTINGS)
    captured = capsys.readouterr()
    raw_token = captured.out.strip().rsplit(": ", maxsplit=1)[-1]

    # First use — must succeed (HTTP 200).
    first_response = await async_client.post(
        _RESET_CONFIRM_URL,
        json={"token": raw_token, "new_password": _RESET_STRONG_PASSWORD},
    )
    assert (
        first_response.status_code == 200
    ), "First use of a valid reset token must return 200"

    # Second use of the same token — must be rejected (HTTP 400).
    second_response = await async_client.post(
        _RESET_CONFIRM_URL,
        json={"token": raw_token, "new_password": "An0therStr0ng@Pass!"},
    )
    assert (
        second_response.status_code == 400
    ), "Reusing a password reset token after successful use must return 400 (SR-18)"


# ---------------------------------------------------------------------------
# TD-13: confirm_password_reset failure paths must write AuditLog entries
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_confirm_password_reset_invalid_token_writes_failed_audit(
    db_session: AsyncSession,
    fake_redis,
) -> None:
    """Token hash not found in DB writes PASSWORD_RESET_FAILED audit with user_id=None.

    TD-13 / SR-16.
    """
    with pytest.raises(HTTPException) as exc_info:
        await confirm_password_reset(
            "bogus-token-that-has-no-matching-hash",
            _RESET_STRONG_PASSWORD,
            db_session,
            fake_redis,
            _TEST_SETTINGS,
        )

    assert exc_info.value.status_code == 400

    result = await db_session.execute(
        select(AuditLog).where(
            AuditLog.action == "PASSWORD_RESET_FAILED",
            AuditLog.user_id.is_(None),
        )
    )
    entries = result.scalars().all()
    assert (
        entries
    ), "Expected at least one PASSWORD_RESET_FAILED audit entry for unknown token"
    reasons = [e.details["reason"] for e in entries if e.details]
    assert "token_not_found" in reasons, f"Expected reason=token_not_found in {reasons}"


@pytest.mark.asyncio
async def test_confirm_password_reset_expired_token_writes_failed_audit(
    db_session: AsyncSession,
    fake_redis,
) -> None:
    """Expired token writes PASSWORD_RESET_FAILED audit with reason=token_expired.

    TD-13 / SR-16.
    """
    email = f"reset_expired_audit_{uuid.uuid4().hex[:8]}@example.com"
    user, _ = await make_orm_user(db_session, fake_redis, email)

    raw_token = generate_refresh_token()
    user.password_reset_token_hash = hash_token(raw_token)
    user.password_reset_sent_at = datetime.now(timezone.utc) - timedelta(minutes=31)
    await db_session.commit()

    with pytest.raises(HTTPException) as exc_info:
        await confirm_password_reset(
            raw_token,
            _RESET_STRONG_PASSWORD,
            db_session,
            fake_redis,
            _TEST_SETTINGS,
        )

    assert exc_info.value.status_code == 400

    result = await db_session.execute(
        select(AuditLog).where(
            AuditLog.action == "PASSWORD_RESET_FAILED",
            AuditLog.user_id == user.id,
        )
    )
    entry = result.scalar_one_or_none()
    assert (
        entry is not None
    ), "Expected PASSWORD_RESET_FAILED audit entry for expired token"
    assert entry.details is not None
    assert entry.details["reason"] == "token_expired"


@pytest.mark.asyncio
async def test_confirm_password_reset_weak_password_writes_policy_audit(
    db_session: AsyncSession,
    fake_redis,
) -> None:
    """Valid token + weak password writes PASSWORD_RESET_POLICY_FAILED.

    Token must remain unconsumed so the user can retry. TD-13 / SR-16.
    """
    email = f"reset_policy_audit_{uuid.uuid4().hex[:8]}@example.com"
    user, _ = await make_orm_user(db_session, fake_redis, email)

    raw_token = generate_refresh_token()
    token_hash = hash_token(raw_token)
    user.password_reset_token_hash = token_hash
    user.password_reset_sent_at = datetime.now(timezone.utc)
    await db_session.commit()

    with pytest.raises(HTTPException) as exc_info:
        await confirm_password_reset(
            raw_token,
            _RESET_WEAK_PASSWORD,
            db_session,
            fake_redis,
            _TEST_SETTINGS,
        )

    assert exc_info.value.status_code == 422

    # Policy failure audit must be written.
    result = await db_session.execute(
        select(AuditLog).where(
            AuditLog.action == "PASSWORD_RESET_POLICY_FAILED",
            AuditLog.user_id == user.id,
        )
    )
    entry = result.scalar_one_or_none()
    assert entry is not None, "Expected PASSWORD_RESET_POLICY_FAILED audit entry"
    assert entry.details is not None
    assert entry.details["reason"] == "weak_new_password"

    # Token must NOT be consumed — user can retry with a strong password.
    await db_session.refresh(user)
    assert (
        user.password_reset_token_hash == token_hash
    ), "Token must remain set after policy failure"

    # SUCCESS audit must not have been written.
    completed = await db_session.execute(
        select(AuditLog).where(
            AuditLog.action == "PASSWORD_RESET_COMPLETED",
            AuditLog.user_id == user.id,
        )
    )
    assert (
        completed.scalar_one_or_none() is None
    ), "PASSWORD_RESET_COMPLETED must not be written on policy failure"


@pytest.mark.asyncio
async def test_confirm_password_reset_missing_sent_at_writes_failed_audit(
    db_session: AsyncSession,
    fake_redis,
) -> None:
    """Token hash present but sent_at is None writes PASSWORD_RESET_FAILED.

    TD-13 / SR-16.
    """
    email = f"reset_missing_ts_{uuid.uuid4().hex[:8]}@example.com"
    user, _ = await make_orm_user(db_session, fake_redis, email)

    raw_token = generate_refresh_token()
    user.password_reset_token_hash = hash_token(raw_token)
    user.password_reset_sent_at = None  # defensive branch
    await db_session.commit()

    with pytest.raises(HTTPException) as exc_info:
        await confirm_password_reset(
            raw_token,
            _RESET_STRONG_PASSWORD,
            db_session,
            fake_redis,
            _TEST_SETTINGS,
        )

    assert exc_info.value.status_code == 400

    result = await db_session.execute(
        select(AuditLog).where(
            AuditLog.action == "PASSWORD_RESET_FAILED",
            AuditLog.user_id == user.id,
        )
    )
    entry = result.scalar_one_or_none()
    assert (
        entry is not None
    ), "Expected PASSWORD_RESET_FAILED audit entry for missing sent_at"
    assert entry.details is not None
    assert entry.details["reason"] == "missing_sent_at"
