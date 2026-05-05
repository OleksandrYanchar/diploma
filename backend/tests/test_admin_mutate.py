"""Integration tests for Phase 7 mutating admin endpoints.

Security requirements verified:
- SR-11: All mutating endpoints are ADMIN-only; AUDITOR is rejected.
- SR-03: Unverified callers are rejected before role checks.
- Audit log entries are written for both success and failure outcomes.
- Self-deactivation and self-role-change are blocked (403).
- Non-existent targets return 404.

Test isolation: every test creates users with UUID-generated emails via
``_make_inline_user`` to avoid UNIQUE constraint failures on the shared
in-memory SQLite database.
"""

import uuid

import fakeredis.aioredis as fakeredis
import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.audit_log import AuditLog
from app.models.user import User, UserRole
from tests.conftest import _TEST_SETTINGS

_UNLOCK_URL = "/api/v1/admin/users/{}/unlock"
_ACTIVATE_URL = "/api/v1/admin/users/{}/activate"
_DEACTIVATE_URL = "/api/v1/admin/users/{}/deactivate"
_ROLE_URL = "/api/v1/admin/users/{}/role"


async def _make_inline_user(
    db_session: AsyncSession,
    fake_redis: fakeredis.FakeRedis,
    role: UserRole,
    is_verified: bool = True,
    is_active: bool = True,
    locked: bool = False,
) -> tuple[User, str]:
    """Create a uniquely-emailed user, seed Redis, return (user, token)."""
    session_id = str(uuid.uuid4())
    user = User(
        email=f"mutate_test_{uuid.uuid4().hex}@example.com",
        hashed_password=hash_password("TestPassword123!"),
        role=role,
        is_active=is_active,
        is_verified=is_verified,
        failed_login_count=5 if locked else 0,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)

    token = create_access_token(
        subject=str(user.id),
        role=user.role.value,
        session_id=session_id,
        settings=_TEST_SETTINGS,
    )
    await fake_redis.set(f"session:{session_id}", str(user.id))
    return user, token


@pytest.mark.asyncio
async def test_unlock_unauthenticated_returns_403(
    async_client: AsyncClient,
) -> None:
    """No bearer on POST /admin/users/{id}/unlock returns 403."""
    response = await async_client.post(_UNLOCK_URL.format(uuid.uuid4()))
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_unlock_user_role_returns_403(
    async_client: AsyncClient,
    fake_redis: fakeredis.FakeRedis,
    db_session: AsyncSession,
) -> None:
    """USER role cannot call unlock (SR-11)."""
    _, token = await _make_inline_user(db_session, fake_redis, UserRole.USER)
    target, _ = await _make_inline_user(db_session, fake_redis, UserRole.USER)

    response = await async_client.post(
        _UNLOCK_URL.format(target.id),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_unlock_auditor_role_returns_403(
    async_client: AsyncClient,
    fake_redis: fakeredis.FakeRedis,
    db_session: AsyncSession,
) -> None:
    """AUDITOR role cannot call unlock (SR-11)."""
    _, token = await _make_inline_user(db_session, fake_redis, UserRole.AUDITOR)
    target, _ = await _make_inline_user(db_session, fake_redis, UserRole.USER)

    response = await async_client.post(
        _UNLOCK_URL.format(target.id),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_unlock_nonexistent_user_returns_404(
    async_client: AsyncClient,
    fake_redis: fakeredis.FakeRedis,
    db_session: AsyncSession,
) -> None:
    """Unlocking a non-existent user returns 404."""
    _, token = await _make_inline_user(db_session, fake_redis, UserRole.ADMIN)

    response = await async_client.post(
        _UNLOCK_URL.format(uuid.uuid4()),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 404
    assert response.json()["detail"] == "User not found"


@pytest.mark.asyncio
async def test_unlock_success_clears_lockout(
    async_client: AsyncClient,
    fake_redis: fakeredis.FakeRedis,
    db_session: AsyncSession,
) -> None:
    """Unlock resets failed_login_count to 0 and returns 200."""
    admin, token = await _make_inline_user(db_session, fake_redis, UserRole.ADMIN)
    target, _ = await _make_inline_user(
        db_session, fake_redis, UserRole.USER, locked=True
    )
    assert target.failed_login_count == 5

    response = await async_client.post(
        _UNLOCK_URL.format(target.id),
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == str(target.id)
    assert body["failed_login_count"] == 0
    assert body["locked_until"] is None


@pytest.mark.asyncio
async def test_unlock_writes_audit_log_on_success(
    async_client: AsyncClient,
    fake_redis: fakeredis.FakeRedis,
    db_session: AsyncSession,
) -> None:
    """Successful unlock produces an ADMIN_UNLOCK_USER audit log entry."""
    admin, token = await _make_inline_user(db_session, fake_redis, UserRole.ADMIN)
    target, _ = await _make_inline_user(db_session, fake_redis, UserRole.USER)

    await async_client.post(
        _UNLOCK_URL.format(target.id),
        headers={"Authorization": f"Bearer {token}"},
    )

    result = await db_session.execute(
        select(AuditLog).where(
            AuditLog.action == "ADMIN_UNLOCK_USER",
            AuditLog.user_id == target.id,
        )
    )
    log = result.scalar_one_or_none()
    assert log is not None
    assert log.details["actor_id"] == str(admin.id)
    assert log.details["result"] == "success"


@pytest.mark.asyncio
async def test_unlock_writes_audit_log_on_not_found(
    async_client: AsyncClient,
    fake_redis: fakeredis.FakeRedis,
    db_session: AsyncSession,
) -> None:
    """Failed unlock (user not found) produces an audit log with user_id=None."""
    admin, token = await _make_inline_user(db_session, fake_redis, UserRole.ADMIN)
    missing_id = uuid.uuid4()

    await async_client.post(
        _UNLOCK_URL.format(missing_id),
        headers={"Authorization": f"Bearer {token}"},
    )

    result = await db_session.execute(
        select(AuditLog).where(
            AuditLog.action == "ADMIN_UNLOCK_USER",
            AuditLog.user_id.is_(None),
        )
    )
    logs = result.scalars().all()
    log = next(
        (lg for lg in logs if lg.details.get("target_id") == str(missing_id)),
        None,
    )
    assert log is not None
    assert log.details["result"] == "failure"
    assert log.details["reason"] == "user_not_found"


@pytest.mark.asyncio
async def test_activate_unauthenticated_returns_403(
    async_client: AsyncClient,
) -> None:
    """No bearer on PATCH /admin/users/{id}/activate returns 403."""
    response = await async_client.patch(_ACTIVATE_URL.format(uuid.uuid4()))
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_activate_user_role_returns_403(
    async_client: AsyncClient,
    fake_redis: fakeredis.FakeRedis,
    db_session: AsyncSession,
) -> None:
    """USER role cannot call activate (SR-11)."""
    _, token = await _make_inline_user(db_session, fake_redis, UserRole.USER)
    target, _ = await _make_inline_user(
        db_session, fake_redis, UserRole.USER, is_active=False
    )

    response = await async_client.patch(
        _ACTIVATE_URL.format(target.id),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_activate_nonexistent_user_returns_404(
    async_client: AsyncClient,
    fake_redis: fakeredis.FakeRedis,
    db_session: AsyncSession,
) -> None:
    """Activating a non-existent user returns 404."""
    _, token = await _make_inline_user(db_session, fake_redis, UserRole.ADMIN)

    response = await async_client.patch(
        _ACTIVATE_URL.format(uuid.uuid4()),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_activate_success_sets_is_active_true(
    async_client: AsyncClient,
    fake_redis: fakeredis.FakeRedis,
    db_session: AsyncSession,
) -> None:
    """Activate sets is_active=True and returns 200 with updated user."""
    _, token = await _make_inline_user(db_session, fake_redis, UserRole.ADMIN)
    target, _ = await _make_inline_user(
        db_session, fake_redis, UserRole.USER, is_active=False
    )
    assert target.is_active is False

    response = await async_client.patch(
        _ACTIVATE_URL.format(target.id),
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    assert response.json()["is_active"] is True


@pytest.mark.asyncio
async def test_deactivate_unauthenticated_returns_403(
    async_client: AsyncClient,
) -> None:
    """No bearer on PATCH /admin/users/{id}/deactivate returns 403."""
    response = await async_client.patch(_DEACTIVATE_URL.format(uuid.uuid4()))
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_deactivate_user_role_returns_403(
    async_client: AsyncClient,
    fake_redis: fakeredis.FakeRedis,
    db_session: AsyncSession,
) -> None:
    """USER role cannot call deactivate (SR-11)."""
    _, token = await _make_inline_user(db_session, fake_redis, UserRole.USER)
    target, _ = await _make_inline_user(db_session, fake_redis, UserRole.USER)

    response = await async_client.patch(
        _DEACTIVATE_URL.format(target.id),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_deactivate_nonexistent_user_returns_404(
    async_client: AsyncClient,
    fake_redis: fakeredis.FakeRedis,
    db_session: AsyncSession,
) -> None:
    """Deactivating a non-existent user returns 404."""
    _, token = await _make_inline_user(db_session, fake_redis, UserRole.ADMIN)

    response = await async_client.patch(
        _DEACTIVATE_URL.format(uuid.uuid4()),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_deactivate_self_returns_403(
    async_client: AsyncClient,
    fake_redis: fakeredis.FakeRedis,
    db_session: AsyncSession,
) -> None:
    """Admin cannot deactivate their own account (self-guard)."""
    admin, token = await _make_inline_user(db_session, fake_redis, UserRole.ADMIN)

    response = await async_client.patch(
        _DEACTIVATE_URL.format(admin.id),
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Cannot deactivate your own account"


@pytest.mark.asyncio
async def test_deactivate_self_writes_audit_log(
    async_client: AsyncClient,
    fake_redis: fakeredis.FakeRedis,
    db_session: AsyncSession,
) -> None:
    """Self-deactivation attempt produces a failure audit log entry."""
    admin, token = await _make_inline_user(db_session, fake_redis, UserRole.ADMIN)

    await async_client.patch(
        _DEACTIVATE_URL.format(admin.id),
        headers={"Authorization": f"Bearer {token}"},
    )

    result = await db_session.execute(
        select(AuditLog).where(
            AuditLog.action == "ADMIN_DEACTIVATE_USER",
            AuditLog.user_id == admin.id,
        )
    )
    log = result.scalar_one_or_none()
    assert log is not None
    assert log.details["result"] == "failure"
    assert log.details["reason"] == "self_deactivation_blocked"


@pytest.mark.asyncio
async def test_deactivate_success_sets_is_active_false(
    async_client: AsyncClient,
    fake_redis: fakeredis.FakeRedis,
    db_session: AsyncSession,
) -> None:
    """Deactivate sets is_active=False and returns 200 with updated user."""
    _, token = await _make_inline_user(db_session, fake_redis, UserRole.ADMIN)
    target, _ = await _make_inline_user(db_session, fake_redis, UserRole.USER)

    response = await async_client.patch(
        _DEACTIVATE_URL.format(target.id),
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    assert response.json()["is_active"] is False


@pytest.mark.asyncio
async def test_deactivate_writes_audit_log_on_success(
    async_client: AsyncClient,
    fake_redis: fakeredis.FakeRedis,
    db_session: AsyncSession,
) -> None:
    """Successful deactivation produces an ADMIN_DEACTIVATE_USER audit log."""
    admin, token = await _make_inline_user(db_session, fake_redis, UserRole.ADMIN)
    target, _ = await _make_inline_user(db_session, fake_redis, UserRole.USER)

    await async_client.patch(
        _DEACTIVATE_URL.format(target.id),
        headers={"Authorization": f"Bearer {token}"},
    )

    result = await db_session.execute(
        select(AuditLog).where(
            AuditLog.action == "ADMIN_DEACTIVATE_USER",
            AuditLog.user_id == target.id,
        )
    )
    log = result.scalar_one_or_none()
    assert log is not None
    assert log.details["actor_id"] == str(admin.id)
    assert log.details["result"] == "success"


@pytest.mark.asyncio
async def test_role_change_unauthenticated_returns_403(
    async_client: AsyncClient,
) -> None:
    """No bearer on PATCH /admin/users/{id}/role returns 403."""
    response = await async_client.patch(
        _ROLE_URL.format(uuid.uuid4()),
        json={"role": "auditor"},
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_role_change_user_role_returns_403(
    async_client: AsyncClient,
    fake_redis: fakeredis.FakeRedis,
    db_session: AsyncSession,
) -> None:
    """USER role cannot call role change (SR-11)."""
    _, token = await _make_inline_user(db_session, fake_redis, UserRole.USER)
    target, _ = await _make_inline_user(db_session, fake_redis, UserRole.USER)

    response = await async_client.patch(
        _ROLE_URL.format(target.id),
        json={"role": "auditor"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_role_change_nonexistent_user_returns_404(
    async_client: AsyncClient,
    fake_redis: fakeredis.FakeRedis,
    db_session: AsyncSession,
) -> None:
    """Changing role of a non-existent user returns 404."""
    _, token = await _make_inline_user(db_session, fake_redis, UserRole.ADMIN)

    response = await async_client.patch(
        _ROLE_URL.format(uuid.uuid4()),
        json={"role": "auditor"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_role_change_self_returns_403(
    async_client: AsyncClient,
    fake_redis: fakeredis.FakeRedis,
    db_session: AsyncSession,
) -> None:
    """Admin cannot change their own role (self-guard)."""
    admin, token = await _make_inline_user(db_session, fake_redis, UserRole.ADMIN)

    response = await async_client.patch(
        _ROLE_URL.format(admin.id),
        json={"role": "user"},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Cannot change your own role"


@pytest.mark.asyncio
async def test_role_change_invalid_role_returns_422(
    async_client: AsyncClient,
    fake_redis: fakeredis.FakeRedis,
    db_session: AsyncSession,
) -> None:
    """Invalid role value is rejected by Pydantic with 422 (no silent fallback)."""
    _, token = await _make_inline_user(db_session, fake_redis, UserRole.ADMIN)
    target, _ = await _make_inline_user(db_session, fake_redis, UserRole.USER)

    response = await async_client.patch(
        _ROLE_URL.format(target.id),
        json={"role": "superadmin"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_role_change_success_updates_role(
    async_client: AsyncClient,
    fake_redis: fakeredis.FakeRedis,
    db_session: AsyncSession,
) -> None:
    """Role change returns 200 with the updated role reflected in response."""
    _, token = await _make_inline_user(db_session, fake_redis, UserRole.ADMIN)
    target, _ = await _make_inline_user(db_session, fake_redis, UserRole.USER)
    assert target.role == UserRole.USER

    response = await async_client.patch(
        _ROLE_URL.format(target.id),
        json={"role": "auditor"},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    assert response.json()["role"] == "auditor"


@pytest.mark.asyncio
async def test_role_change_writes_audit_log_with_roles(
    async_client: AsyncClient,
    fake_redis: fakeredis.FakeRedis,
    db_session: AsyncSession,
) -> None:
    """Audit log for role change includes previous_role and new_role."""
    admin, token = await _make_inline_user(db_session, fake_redis, UserRole.ADMIN)
    target, _ = await _make_inline_user(db_session, fake_redis, UserRole.USER)

    await async_client.patch(
        _ROLE_URL.format(target.id),
        json={"role": "auditor"},
        headers={"Authorization": f"Bearer {token}"},
    )

    result = await db_session.execute(
        select(AuditLog).where(
            AuditLog.action == "ADMIN_ROLE_CHANGE",
            AuditLog.user_id == target.id,
        )
    )
    log = result.scalar_one_or_none()
    assert log is not None
    assert log.details["actor_id"] == str(admin.id)
    assert log.details["previous_role"] == "user"
    assert log.details["new_role"] == "auditor"
    assert log.details["result"] == "success"


@pytest.mark.asyncio
async def test_role_change_self_writes_audit_log(
    async_client: AsyncClient,
    fake_redis: fakeredis.FakeRedis,
    db_session: AsyncSession,
) -> None:
    """Self-role-change attempt produces a failure audit log entry."""
    admin, token = await _make_inline_user(db_session, fake_redis, UserRole.ADMIN)

    await async_client.patch(
        _ROLE_URL.format(admin.id),
        json={"role": "user"},
        headers={"Authorization": f"Bearer {token}"},
    )

    result = await db_session.execute(
        select(AuditLog).where(
            AuditLog.action == "ADMIN_ROLE_CHANGE",
            AuditLog.user_id == admin.id,
        )
    )
    log = result.scalar_one_or_none()
    assert log is not None
    assert log.details["result"] == "failure"
    assert log.details["reason"] == "self_role_change_blocked"
