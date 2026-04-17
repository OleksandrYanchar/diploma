"""Tests for POST /auth/password/change (Phase 4 Step 4).

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

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import verify_password
from app.models.audit_log import AuditLog
from app.models.user import User
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
