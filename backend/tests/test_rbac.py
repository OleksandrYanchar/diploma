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

from __future__ import annotations

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

# ---------------------------------------------------------------------------
# Helper: minimal user-like object
# ---------------------------------------------------------------------------
# ``require_role`` only accesses ``current_user.role``.  Using SimpleNamespace
# avoids SQLAlchemy session requirements while keeping the test readable.
# ---------------------------------------------------------------------------


def _make_user(role: UserRole) -> types.SimpleNamespace:
    """Return a minimal user-like object with the given role.

    The inner callable produced by ``require_role`` reads only
    ``current_user.role``, so a ``SimpleNamespace`` with that single attribute
    is sufficient for unit testing.

    Args:
        role: The ``UserRole`` value to assign to the mock user.

    Returns:
        A ``SimpleNamespace`` instance with a ``role`` attribute.
    """
    return types.SimpleNamespace(role=role)


# ---------------------------------------------------------------------------
# Unit tests — call the inner callable directly
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_require_role_accepts_correct_role() -> None:
    """require_role passes when the user holds the required role.

    Creates a USER-role guard and calls it with a USER-role user.
    No exception must be raised and the return value must be None
    (side-effect-only dependency).
    """
    dep = require_role(UserRole.USER)
    user = _make_user(UserRole.USER)

    result = await dep(current_user=user)  # type: ignore[arg-type]

    assert result is None


@pytest.mark.asyncio
async def test_require_role_rejects_wrong_role_with_403() -> None:
    """require_role raises HTTPException 403 for a user whose role is not allowed.

    Creates an ADMIN-only guard and calls it with a USER-role user.
    The dependency must raise HTTPException with status_code 403 (Forbidden),
    not 401 (Unauthorized) — the credential is valid but the role is
    insufficient (SR-11).
    """
    dep = require_role(UserRole.ADMIN)
    user = _make_user(UserRole.USER)

    with pytest.raises(HTTPException) as exc_info:
        await dep(current_user=user)  # type: ignore[arg-type]

    assert exc_info.value.status_code == 403


@pytest.mark.asyncio
async def test_require_role_detail_string() -> None:
    """require_role uses the exact detail string 'Insufficient permissions'.

    The detail string is referenced by downstream tests (e.g. error message
    assertions in Step 3 route tests) so its exact value must be stable.
    """
    dep = require_role(UserRole.ADMIN)
    user = _make_user(UserRole.USER)

    with pytest.raises(HTTPException) as exc_info:
        await dep(current_user=user)  # type: ignore[arg-type]

    assert exc_info.value.detail == "Insufficient permissions"


@pytest.mark.asyncio
async def test_require_role_multi_role_accepts_any_matching_role() -> None:
    """require_role with multiple roles accepts any user whose role appears in the set.

    A route guarded by ``require_role(UserRole.USER, UserRole.ADMIN)`` must
    allow both USER-role and ADMIN-role users without raising.  AUDITOR-role
    users must still be rejected.
    """
    dep = require_role(UserRole.USER, UserRole.ADMIN)

    user_user = _make_user(UserRole.USER)
    user_admin = _make_user(UserRole.ADMIN)
    user_auditor = _make_user(UserRole.AUDITOR)

    # Both USER and ADMIN pass without exception.
    assert await dep(current_user=user_user) is None  # type: ignore[arg-type]
    assert await dep(current_user=user_admin) is None  # type: ignore[arg-type]

    # AUDITOR is not in the allowed set.
    with pytest.raises(HTTPException) as exc_info:
        await dep(current_user=user_auditor)  # type: ignore[arg-type]

    assert exc_info.value.status_code == 403


@pytest.mark.asyncio
async def test_require_role_closure_independence() -> None:
    """Two require_role callables with different roles are completely independent.

    Verifies that Python closure capture is correct: ``dep_admin`` and
    ``dep_user`` each hold their own ``roles`` tuple from their respective
    ``require_role(...)`` calls and do not share state.

    Concretely:
    - A USER-role user must pass dep_user and be rejected by dep_admin.
    - An ADMIN-role user must pass dep_admin and be rejected by dep_user.
    """
    dep_admin = require_role(UserRole.ADMIN)
    dep_user = require_role(UserRole.USER)

    user_role_user = _make_user(UserRole.USER)
    user_role_admin = _make_user(UserRole.ADMIN)

    # USER passes dep_user, fails dep_admin.
    assert await dep_user(current_user=user_role_user) is None  # type: ignore[arg-type]
    with pytest.raises(HTTPException) as exc_info:
        await dep_admin(current_user=user_role_user)  # type: ignore[arg-type]
    assert exc_info.value.status_code == 403

    # ADMIN passes dep_admin, fails dep_user.
    assert await dep_admin(current_user=user_role_admin) is None  # type: ignore[arg-type]
    with pytest.raises(HTTPException) as exc_info:
        await dep_user(current_user=user_role_admin)  # type: ignore[arg-type]
    assert exc_info.value.status_code == 403


@pytest.mark.asyncio
async def test_require_role_raises_403_not_401() -> None:
    """require_role raises exactly 403, never 401, on a role mismatch.

    403 (Forbidden) is the correct status for an authenticated user who lacks
    the required role.  401 (Unauthorized) would be semantically wrong and
    could mislead clients into re-authenticating when a role change is actually
    required.

    This test pins the exact status code to prevent future refactoring from
    accidentally introducing 401 responses for role failures.
    """
    dep = require_role(UserRole.AUDITOR)
    user = _make_user(UserRole.USER)

    with pytest.raises(HTTPException) as exc_info:
        await dep(current_user=user)  # type: ignore[arg-type]

    assert exc_info.value.status_code == 403
    assert exc_info.value.status_code != 401


# ---------------------------------------------------------------------------
# Integration test — missing Authorization header on a real production route
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unauthenticated_request_returns_403(
    async_client: AsyncClient,
) -> None:
    """A request with no Authorization header to a protected endpoint returns 403.

    FastAPI's ``HTTPBearer`` security scheme returns HTTP 403 (not 401) when
    the Authorization header is entirely absent.  This confirms that
    ``get_current_user`` handles the unauthenticated case before
    ``require_role`` is evaluated — ``require_role`` never receives an
    unauthenticated caller.

    Uses ``POST /api/v1/auth/mfa/setup``, an existing protected route that
    requires authentication, without providing any credentials.
    """
    response = await async_client.post("/api/v1/auth/mfa/setup")
    assert response.status_code == 403


# ---------------------------------------------------------------------------
# Integration tests — GET /api/v1/admin/ping (Phase 4, Step 3)
# ---------------------------------------------------------------------------
# These tests verify that the RBAC gate on the admin ping endpoint correctly
# enforces the combined require_verified + require_role(ADMIN) dependency
# chain (SR-11, T-09, T-10).
#
# Each test seeds FakeRedis with the user's session before calling the
# endpoint, satisfying get_current_user's session check (SR-10).
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_admin_ping_admin_role_returns_200(
    async_client: AsyncClient,
    fake_redis: fakeredis.FakeRedis,
    admin_user: tuple[User, str],
) -> None:
    """GET /admin/ping returns HTTP 200 for a verified ADMIN-role user.

    The response body must contain ``status="ok"`` and ``role="admin"``,
    confirming that the endpoint is reachable when all RBAC gates pass
    (SR-11).
    """
    user, token = admin_user

    # Seed the Redis session required by get_current_user step 4 (SR-10).
    # The admin_user fixture embeds _ADMIN_SESSION_ID in its access token.
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
    """GET /admin/ping returns HTTP 403 for a verified USER-role caller (T-09).

    A USER-role account is authenticated and email-verified but does not hold
    the ADMIN role.  The require_role(ADMIN) dependency must reject the request
    with 403 (Forbidden), not 401 (SR-11).

    The user is created inline (not via the verified_user fixture) to avoid a
    UNIQUE constraint collision: the verified_user fixture commits a fixed email
    address to the session-scoped SQLite engine and only one test per session
    may consume that slot (see conftest.py and test_users_me.py docstrings).
    """
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
    """GET /admin/ping returns HTTP 403 for a verified AUDITOR-role caller.

    An AUDITOR-role account has read-only access to audit logs (Phase 7) but
    must not reach admin endpoints.  The require_role(ADMIN) dependency must
    reject the request with 403 (SR-11).
    """
    user, token = auditor_user

    # The auditor_user fixture embeds _AUDITOR_SESSION_ID in its access token.
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
    """GET /admin/ping returns HTTP 403 when no Authorization header is provided (T-10).

    FastAPI's ``HTTPBearer`` dependency returns 403 (not 401) when the
    Authorization header is entirely absent.  No Redis seeding is needed
    because the request is rejected before any token validation occurs.
    """
    response = await async_client.get("/api/v1/admin/ping")

    assert response.status_code == 403


@pytest.mark.asyncio
async def test_admin_ping_unverified_admin_returns_403(
    async_client: AsyncClient,
    fake_redis: fakeredis.FakeRedis,
    db_session: AsyncSession,
) -> None:
    """GET /admin/ping returns HTTP 403 for an unverified ADMIN-role user.

    An account with role=ADMIN but is_verified=False must be rejected by
    the require_verified dependency before require_role is evaluated (SR-03).
    This confirms that email verification is a mandatory prerequisite for
    admin access, independent of role assignment (SR-11).

    The user is created inline (not via the unverified_user fixture) because
    that fixture uses role=USER.  A unique email is used to avoid UNIQUE
    constraint conflicts with other fixtures in the same session.
    """
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

    # Seed the Redis session so that get_current_user passes steps 1–6 and
    # the request reaches the require_verified dependency.
    await fake_redis.set(f"session:{_SECOND_SESSION_ID}", str(unverified_admin.id))

    response = await async_client.get(
        "/api/v1/admin/ping",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 403


# ---------------------------------------------------------------------------
# Response body structure
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_admin_ping_response_body_structure(
    async_client: AsyncClient,
    fake_redis: fakeredis.FakeRedis,
    db_session: AsyncSession,
) -> None:
    """GET /admin/ping response contains exactly {status, role} with no extras.

    Verifies the contract: only ``status`` and ``role`` keys are present.
    Unexpected extra fields could leak internal state to the admin caller.
    """
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
