"""Tests for the require_role dependency factory (Phase 4, Step 1).

These are unit-level tests that call the inner callable produced by
``require_role`` directly, using lightweight mock user objects.  No production
routes are needed because the dependency is tested in isolation from FastAPI's
routing layer.

Security requirement enforced: SR-11 (Role-Based Access Control).

One integration test verifies that a missing Authorization header on an
existing protected endpoint returns the expected HTTP status code, confirming
that ``get_current_user`` handles the unauthenticated case before
``require_role`` is ever evaluated.
"""

import types

import fakeredis.aioredis as fakeredis
import pytest
from fastapi import HTTPException
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.security import create_access_token, hash_password
from app.dependencies.auth import require_role
from app.models.user import User, UserRole
from tests.conftest import (
    _ADMIN_SESSION_ID,
    _AUDITOR_SESSION_ID,
    _VERIFIED_SESSION_ID,
)

# Alias for the verified_user fixture session ID (kept for backward-compat
# with tests that seed Redis manually for that role).
_FIXTURE_SESSION_ID = _VERIFIED_SESSION_ID

# A session ID used when creating inline users in integration tests, distinct
# from all fixture session IDs so both sessions coexist in FakeRedis.
_SECOND_SESSION_ID = "00000000-0000-0000-0000-000000000010"

# Test settings matching the overrides installed by async_client in conftest.py
# so that tokens issued inline here are accepted by get_current_user.
_TEST_SETTINGS = Settings(
    database_url="postgresql+asyncpg://test:test@localhost:5432/test",  # type: ignore[arg-type]
    redis_url="redis://:testpass@localhost:6379/0",  # type: ignore[arg-type]
    jwt_secret_key="test-secret-key-that-is-at-least-32-chars-long-for-hs256",
    environment="test",
    debug=True,
)


def _make_user(role: UserRole) -> types.SimpleNamespace:
    """Return a minimal user-like namespace with only the ``role`` attribute
    (sufficient for require_role)."""
    return types.SimpleNamespace(role=role)


@pytest.mark.asyncio
async def test_require_role_accepts_correct_role() -> None:
    """require_role passes (returns None) when the user holds the required role."""
    dep = require_role(UserRole.USER)
    user = _make_user(UserRole.USER)

    result = await dep(current_user=user)  # type: ignore[arg-type]

    assert result is None


@pytest.mark.asyncio
async def test_require_role_rejects_wrong_role_with_403() -> None:
    """require_role raises HTTPException 403 (not 401)
    when the user's role is insufficient (SR-11)."""
    dep = require_role(UserRole.ADMIN)
    user = _make_user(UserRole.USER)

    with pytest.raises(HTTPException) as exc_info:
        await dep(current_user=user)  # type: ignore[arg-type]

    assert exc_info.value.status_code == 403


@pytest.mark.asyncio
async def test_require_role_detail_string() -> None:
    """require_role detail is exactly 'Insufficient permissions'
    — referenced by downstream tests."""
    dep = require_role(UserRole.ADMIN)
    user = _make_user(UserRole.USER)

    with pytest.raises(HTTPException) as exc_info:
        await dep(current_user=user)  # type: ignore[arg-type]

    assert exc_info.value.detail == "Insufficient permissions"


@pytest.mark.asyncio
async def test_require_role_multi_role_accepts_any_matching_role() -> None:
    """require_role with multiple roles accepts any matching role;
    rejects roles outside the set."""
    dep = require_role(UserRole.USER, UserRole.ADMIN)

    user_user = _make_user(UserRole.USER)
    user_admin = _make_user(UserRole.ADMIN)
    user_auditor = _make_user(UserRole.AUDITOR)

    assert await dep(current_user=user_user) is None  # type: ignore[arg-type]
    assert await dep(current_user=user_admin) is None  # type: ignore[arg-type]

    with pytest.raises(HTTPException) as exc_info:
        await dep(current_user=user_auditor)  # type: ignore[arg-type]

    assert exc_info.value.status_code == 403


@pytest.mark.asyncio
async def test_require_role_closure_independence() -> None:
    """Two require_role callables with different roles are independent
    — no shared closure state."""
    dep_admin = require_role(UserRole.ADMIN)
    dep_user = require_role(UserRole.USER)

    user_role_user = _make_user(UserRole.USER)
    user_role_admin = _make_user(UserRole.ADMIN)

    assert await dep_user(current_user=user_role_user) is None  # type: ignore[arg-type]
    with pytest.raises(HTTPException) as exc_info:
        await dep_admin(current_user=user_role_user)  # type: ignore[arg-type]
    assert exc_info.value.status_code == 403

    assert await dep_admin(current_user=user_role_admin) is None  # type: ignore[arg-type]
    with pytest.raises(HTTPException) as exc_info:
        await dep_user(current_user=user_role_admin)  # type: ignore[arg-type]
    assert exc_info.value.status_code == 403


@pytest.mark.asyncio
async def test_require_role_raises_403_not_401() -> None:
    """require_role raises exactly 403 on role mismatch
    — 401 would be semantically wrong (SR-11)."""
    dep = require_role(UserRole.AUDITOR)
    user = _make_user(UserRole.USER)

    with pytest.raises(HTTPException) as exc_info:
        await dep(current_user=user)  # type: ignore[arg-type]

    assert exc_info.value.status_code == 403
    assert exc_info.value.status_code != 401


@pytest.mark.asyncio
async def test_unauthenticated_request_returns_403(
    async_client: AsyncClient,
) -> None:
    """No Authorization header on a protected route returns 403
    — get_current_user gates before require_role."""
    response = await async_client.post("/api/v1/auth/mfa/setup")
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_admin_ping_admin_role_returns_200(
    async_client: AsyncClient,
    fake_redis: fakeredis.FakeRedis,
    admin_user: tuple[User, str],
) -> None:
    """GET /admin/ping returns 200 for a verified ADMIN-role user (SR-11)."""
    user, token = admin_user

    await fake_redis.set(f"session:{_ADMIN_SESSION_ID}", str(user.id))

    response = await async_client.get(
        "/api/v1/admin/ping",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["role"] == "admin"


@pytest.mark.asyncio
async def test_admin_ping_user_role_returns_403(
    async_client: AsyncClient,
    fake_redis: fakeredis.FakeRedis,
    db_session: AsyncSession,
) -> None:
    """GET /admin/ping returns 403 for a USER-role caller
    — require_role(ADMIN) rejects (T-09, SR-11)."""
    user = User(
        email="admin_ping_regular_user@example.com",
        hashed_password=hash_password("TestPassword123!"),
        role=UserRole.USER,
        is_active=True,
        is_verified=True,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)

    token = create_access_token(
        subject=str(user.id),
        role=user.role.value,
        session_id=_SECOND_SESSION_ID,
        settings=_TEST_SETTINGS,
    )
    await fake_redis.set(f"session:{_SECOND_SESSION_ID}", str(user.id))

    response = await async_client.get(
        "/api/v1/admin/ping",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 403


@pytest.mark.asyncio
async def test_admin_ping_auditor_role_returns_403(
    async_client: AsyncClient,
    fake_redis: fakeredis.FakeRedis,
    auditor_user: tuple[User, str],
) -> None:
    """GET /admin/ping returns 403 for an AUDITOR-role caller (SR-11)."""
    user, token = auditor_user

    await fake_redis.set(f"session:{_AUDITOR_SESSION_ID}", str(user.id))

    response = await async_client.get(
        "/api/v1/admin/ping",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 403


@pytest.mark.asyncio
async def test_admin_ping_unauthenticated_returns_403(
    async_client: AsyncClient,
) -> None:
    """GET /admin/ping returns 403 with no Authorization header (T-10, HTTPBearer)."""
    response = await async_client.get("/api/v1/admin/ping")

    assert response.status_code == 403


@pytest.mark.asyncio
async def test_admin_ping_unverified_admin_returns_403(
    async_client: AsyncClient,
    fake_redis: fakeredis.FakeRedis,
    db_session: AsyncSession,
) -> None:
    """GET /admin/ping returns 403 for an unverified ADMIN
    — require_verified gates before require_role (SR-03, SR-11)."""
    unverified_admin = User(
        email="unverified_admin@example.com",
        hashed_password=hash_password("TestPassword123!"),
        role=UserRole.ADMIN,
        is_active=True,
        is_verified=False,
    )
    db_session.add(unverified_admin)
    await db_session.commit()
    await db_session.refresh(unverified_admin)

    token = create_access_token(
        subject=str(unverified_admin.id),
        role=unverified_admin.role.value,
        session_id=_SECOND_SESSION_ID,
        settings=_TEST_SETTINGS,
    )

    await fake_redis.set(f"session:{_SECOND_SESSION_ID}", str(unverified_admin.id))

    response = await async_client.get(
        "/api/v1/admin/ping",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 403


@pytest.mark.asyncio
async def test_admin_ping_response_body_structure(
    async_client: AsyncClient,
    fake_redis: fakeredis.FakeRedis,
    db_session: AsyncSession,
) -> None:
    """GET /admin/ping response body contains exactly {status, role}
    — no extra fields."""
    admin = User(
        email="admin_body_check@example.com",
        hashed_password=hash_password("TestPassword123!"),
        role=UserRole.ADMIN,
        is_active=True,
        is_verified=True,
    )
    db_session.add(admin)
    await db_session.commit()
    await db_session.refresh(admin)

    token = create_access_token(
        subject=str(admin.id),
        role=admin.role.value,
        session_id=_SECOND_SESSION_ID,
        settings=_TEST_SETTINGS,
    )
    await fake_redis.set(f"session:{_SECOND_SESSION_ID}", str(admin.id))

    response = await async_client.get(
        "/api/v1/admin/ping",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    body = response.json()
    assert set(body.keys()) == {"status", "role"}
    assert body["status"] == "ok"
    assert body["role"] == "admin"
