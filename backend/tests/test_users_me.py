"""Tests for GET /api/v1/users/me (Phase 4, Step 2).

Verifies that the endpoint:
- Returns the authenticated user's own profile (SR-11, I-06).
- Excludes sensitive fields from the response (SR-02, SR-04).
- Allows unverified users to read their own profile (Phase 4 policy).
- Rejects unauthenticated requests with HTTP 403 (HTTPBearer behaviour).
- Returns only the caller's profile, not another user's.

Security requirement: SR-11 (authenticated users can read their own profile),
SR-02 (hashed_password never exposed), SR-04 (mfa_secret never exposed).

Design note: the ``verified_user`` fixture commits a user with a hardcoded
email (``testuser_verified@example.com``) to the shared in-memory SQLite
engine.  Because ``db_session.rollback()`` cannot undo a committed transaction,
only one test per session may use that fixture.  Tests that need additional
users create them inline with unique per-test email addresses to avoid UNIQUE
constraint violations.
"""

from __future__ import annotations

import fakeredis.aioredis as fakeredis
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.security import create_access_token, hash_password
from app.models.user import User, UserRole
from tests.conftest import (
    _UNVERIFIED_SESSION_ID,
    _VERIFIED_SESSION_ID,
)

# Aliases matching the per-role session IDs now defined in conftest.
_FIXTURE_SESSION_ID = _VERIFIED_SESSION_ID

# A session ID for tests that create additional users inline, distinct from
# all fixture session IDs so sessions coexist in FakeRedis without collision.
_SECOND_SESSION_ID = "00000000-0000-0000-0000-000000000010"

# Test settings shared by inline token issuance, matching the overrides in
# conftest.py so that tokens issued here are accepted by get_current_user.
_TEST_SETTINGS = Settings(
    database_url="postgresql+asyncpg://test:test@localhost:5432/test",  # type: ignore[arg-type]
    redis_url="redis://:testpass@localhost:6379/0",  # type: ignore[arg-type]
    jwt_secret_key="test-secret-key-that-is-at-least-32-chars-long-for-hs256",
    environment="test",
    debug=True,
)


@pytest.mark.asyncio
async def test_get_me_returns_own_profile(
    async_client: AsyncClient,
    fake_redis: fakeredis.FakeRedis,
    verified_user: tuple[User, str],
) -> None:
    """GET /users/me returns the authenticated user's own profile.

    Asserts that the response id, email, and role match the fixture user.
    The Redis session must be seeded so that get_current_user's session
    check (SR-10) passes.
    """
    user, token = verified_user

    # Seed the Redis session required by get_current_user step 4 (SR-10).
    await fake_redis.set(f"session:{_FIXTURE_SESSION_ID}", str(user.id))

    response = await async_client.get(
        "/api/v1/users/me",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == str(user.id)
    assert body["email"] == user.email
    assert body["role"] == user.role.value


@pytest.mark.asyncio
async def test_get_me_excludes_sensitive_fields(
    async_client: AsyncClient,
    fake_redis: fakeredis.FakeRedis,
    db_session: AsyncSession,
) -> None:
    """GET /users/me excludes sensitive ORM fields from the response.

    Confirms the serialization boundary enforced by ``response_model=UserResponse``:
    ``hashed_password`` (SR-02), ``mfa_secret`` (SR-04),
    ``failed_login_count``, and ``locked_until`` must not appear in the body.

    A unique email is used here rather than the ``verified_user`` fixture
    because that fixture commits a fixed email address, and only one test
    per session may commit that same address (see module docstring).
    """
    user = User(
        email="testuser_sensitive_fields@example.com",
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
        "/api/v1/users/me",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    body = response.json()
    assert "hashed_password" not in body
    assert "mfa_secret" not in body
    assert "failed_login_count" not in body
    assert "locked_until" not in body


@pytest.mark.asyncio
async def test_get_me_unverified_user_returns_200(
    async_client: AsyncClient,
    fake_redis: fakeredis.FakeRedis,
    unverified_user: tuple[User, str],
) -> None:
    """GET /users/me returns HTTP 200 for an unverified user.

    Per Phase 4 policy, email verification is NOT required to read one's own
    profile.  Unverified users must be able to see their own account state
    (including is_verified=False) so they can act on it.
    """
    user, token = unverified_user

    # The unverified_user fixture embeds _UNVERIFIED_SESSION_ID in its token.
    await fake_redis.set(f"session:{_UNVERIFIED_SESSION_ID}", str(user.id))

    response = await async_client.get(
        "/api/v1/users/me",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["email"] == user.email
    assert body["is_verified"] is False


@pytest.mark.asyncio
async def test_get_me_unauthenticated_returns_403(
    async_client: AsyncClient,
) -> None:
    """GET /users/me returns HTTP 403 when no Authorization header is provided.

    FastAPI's HTTPBearer dependency returns 403 (not 401) when the
    Authorization header is entirely absent.  This is consistent with the
    behaviour confirmed in test_rbac.py for other protected endpoints.
    """
    response = await async_client.get("/api/v1/users/me")

    assert response.status_code == 403


@pytest.mark.asyncio
async def test_get_me_response_is_own_profile_not_another_users(
    async_client: AsyncClient,
    fake_redis: fakeredis.FakeRedis,
    db_session: AsyncSession,
) -> None:
    """GET /users/me with user A's token returns user A's profile, not user B's.

    Creates two users directly via the ORM with distinct emails and session
    IDs.  Calls the endpoint with user A's token and asserts that the returned
    email matches user A, not user B.  This verifies that the endpoint is
    scoped to the authenticated caller and cannot be used to read another
    user's profile (I-06, Zero Trust isolation).
    """
    user_a = User(
        email="testuser_me_a@example.com",
        hashed_password=hash_password("TestPassword123!"),
        role=UserRole.USER,
        is_active=True,
        is_verified=True,
    )
    user_b = User(
        email="testuser_me_b@example.com",
        hashed_password=hash_password("TestPassword123!"),
        role=UserRole.USER,
        is_active=True,
        is_verified=True,
    )
    db_session.add(user_a)
    db_session.add(user_b)
    await db_session.commit()
    await db_session.refresh(user_a)
    await db_session.refresh(user_b)

    # Issue separate tokens with separate session IDs so both sessions can
    # coexist in FakeRedis without overwriting each other.
    token_a = create_access_token(
        subject=str(user_a.id),
        role=user_a.role.value,
        session_id=_FIXTURE_SESSION_ID,
        settings=_TEST_SETTINGS,
    )
    token_b = create_access_token(
        subject=str(user_b.id),
        role=user_b.role.value,
        session_id=_SECOND_SESSION_ID,
        settings=_TEST_SETTINGS,
    )
    await fake_redis.set(f"session:{_FIXTURE_SESSION_ID}", str(user_a.id))
    await fake_redis.set(f"session:{_SECOND_SESSION_ID}", str(user_b.id))

    # Call the endpoint with user A's token only.
    response = await async_client.get(
        "/api/v1/users/me",
        headers={"Authorization": f"Bearer {token_a}"},
    )

    assert response.status_code == 200
    body = response.json()

    # The response must reflect user A's identity, not user B's.
    assert body["email"] == user_a.email
    assert body["email"] != user_b.email

    # Confirm user B's token also returns the correct profile (bidirectional).
    response_b = await async_client.get(
        "/api/v1/users/me",
        headers={"Authorization": f"Bearer {token_b}"},
    )
    assert response_b.status_code == 200
    assert response_b.json()["email"] == user_b.email
    assert response_b.json()["email"] != user_a.email


@pytest.mark.asyncio
async def test_get_me_contains_all_expected_fields_and_no_internal_fields(
    async_client: AsyncClient,
    fake_redis: fakeredis.FakeRedis,
    db_session: AsyncSession,
) -> None:
    """GET /users/me response contains the public UserResponse fields only.

    Verifies that all expected public fields are present and all internal/sensitive
    ORM fields are absent from the serialised response. This is the single
    authoritative field-boundary test (SR-02, SR-04).
    """
    user = User(
        email="testuser_field_check@example.com",
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

    resp = await async_client.get(
        "/api/v1/users/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    body = resp.json()

    expected_keys = {
        "id",
        "email",
        "role",
        "is_active",
        "is_verified",
        "mfa_enabled",
        "created_at",
        "updated_at",
    }
    missing = expected_keys - body.keys()
    assert not missing, f"Missing expected public fields: {missing}"

    forbidden_keys = {
        "hashed_password",
        "mfa_secret",
        "failed_login_count",
        "locked_until",
        "email_verification_token_hash",
    }
    leaked = forbidden_keys & body.keys()
    assert not leaked, f"Internal fields leaked in response: {leaked}"
