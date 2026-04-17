"""Tests for the get_current_user dependency (Step 5).

A minimal test-only route ``GET /test-protected`` is registered at module
level on the live ``app`` instance so that the dependency can be exercised
through the full FastAPI request/response stack.  This route is not part of
the production API surface — it exists solely to provide a protected endpoint
in the absence of any real protected routes at this stage of the project.

Covers:
- Missing Authorization header returns 403 (HTTPBearer behaviour)
- Malformed / invalid token returns 401 (Step 1 failure)
- Expired token returns 401 (Step 1 failure — exp claim)
- Valid token + live session returns 200 with user_id (happy path)
- Session deleted from Redis returns 401 (Step 4 failure — SR-10)
- Blacklisted JTI in Redis returns 401 (Step 3 failure — SR-09)
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import jwt as pyjwt
import pytest
from fastapi import Depends
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.dependencies.auth import get_current_user
from app.main import app
from app.models.user import User

# ---------------------------------------------------------------------------
# Test-only protected route
#
# Registered once at module import time on the shared ``app`` instance.
# Declaring it here (rather than in conftest) keeps it scoped to this test
# module and makes it obvious that it is a test artefact, not a real endpoint.
# ---------------------------------------------------------------------------
_PROTECTED_URL = "/test-protected"


@app.get(_PROTECTED_URL)
async def _test_protected(
    current_user: User = Depends(get_current_user),
) -> dict[str, str]:
    """Test-only route: return the authenticated user's ID."""
    return {"user_id": str(current_user.id)}


# ---------------------------------------------------------------------------
# URL constants for setup helpers
# ---------------------------------------------------------------------------
_REGISTER_URL = "/api/v1/auth/register"
_VERIFY_URL = "/api/v1/auth/verify-email"
_LOGIN_URL = "/api/v1/auth/login"
_STRONG_PASSWORD = "StrongPass1!"


# ---------------------------------------------------------------------------
# Helper: register, verify, and login — returns the access_token string
# ---------------------------------------------------------------------------


async def _register_verify_login(
    async_client: AsyncClient,
    capsys: pytest.CaptureFixture[str],
    email: str,
) -> str:
    """Register a user, verify their email, and log them in.

    Returns the access_token string from the login response.

    Args:
        async_client: Test HTTP client fixture.
        capsys:       pytest stdout capture fixture.
        email:        Email address to register.

    Returns:
        The raw access_token JWT string.
    """
    # Register
    reg_resp = await async_client.post(
        _REGISTER_URL,
        json={"email": email, "password": _STRONG_PASSWORD},
    )
    assert reg_resp.status_code == 201

    # Capture the verification token printed to stdout (DEMO MODE)
    captured = capsys.readouterr()
    raw_token = captured.out.strip().rsplit(": ", maxsplit=1)[-1]

    # Verify email
    verify_resp = await async_client.get(_VERIFY_URL, params={"token": raw_token})
    assert verify_resp.status_code == 200

    # Login
    login_resp = await async_client.post(
        _LOGIN_URL,
        json={"email": email, "password": _STRONG_PASSWORD},
    )
    assert login_resp.status_code == 200

    return login_resp.json()["access_token"]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_protected_endpoint_rejects_no_token(
    async_client: AsyncClient,
) -> None:
    """GET /test-protected with no Authorization header returns 403.

    HTTPBearer raises HTTP 403 (not 401) when the Authorization header is
    entirely absent.  This is FastAPI's built-in behaviour: the client has
    not even attempted to present a credential, which is a different
    condition from presenting an invalid one.
    """
    response = await async_client.get(_PROTECTED_URL)
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_protected_endpoint_rejects_invalid_token(
    async_client: AsyncClient,
) -> None:
    """GET /test-protected with a malformed Bearer token returns 401.

    A token that cannot be decoded (wrong format, bad signature) must be
    rejected at Step 1 of get_current_user validation.
    """
    response = await async_client.get(
        _PROTECTED_URL,
        headers={"Authorization": "Bearer invalid.token.here"},
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_protected_endpoint_rejects_expired_token(
    async_client: AsyncClient,
) -> None:
    """GET /test-protected with an expired JWT returns 401.

    An expired token has a cryptographically valid signature but an ``exp``
    claim in the past.  PyJWT raises ``ExpiredSignatureError`` (a subclass of
    ``InvalidTokenError``) inside ``decode_access_token``, which get_current_user
    catches and converts to HTTP 401.  Enforces SR-06.
    """
    settings = Settings()  # type: ignore[call-arg]
    now = datetime.now(tz=timezone.utc)
    expired_payload = {
        "sub": "00000000-0000-0000-0000-000000000001",
        "role": "user",
        "session_id": "00000000-0000-0000-0000-000000000002",
        "jti": "00000000-0000-0000-0000-000000000003",
        "typ": "access",
        "iat": now - timedelta(minutes=30),
        "exp": now - timedelta(minutes=15),  # already expired
    }
    expired_token = pyjwt.encode(
        expired_payload,
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
    )

    response = await async_client.get(
        _PROTECTED_URL,
        headers={"Authorization": f"Bearer {expired_token}"},
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_protected_endpoint_accepts_valid_token(
    async_client: AsyncClient,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """GET /test-protected with a valid token and live session returns 200.

    Happy-path test: a freshly issued access token, backed by a live Redis
    session, must pass all seven validation steps and return the user_id.
    Enforces SR-06, SR-09, SR-10 (nothing blocking the request).
    """
    email = "dep_valid@example.com"
    access_token = await _register_verify_login(async_client, capsys, email)

    response = await async_client.get(
        _PROTECTED_URL,
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert "user_id" in data
    assert len(data["user_id"]) > 0


@pytest.mark.asyncio
async def test_protected_endpoint_rejects_missing_redis_session(
    async_client: AsyncClient,
    capsys: pytest.CaptureFixture[str],
    fake_redis: object,
) -> None:
    """GET /test-protected returns 401 after the Redis session is deleted.

    Simulates a forced logout or admin session revocation: the Redis session
    key is manually deleted after login.  Even though the JWT is still
    cryptographically valid, the absence of the session record must cause
    get_current_user to reject the request at Step 4.  Enforces SR-10.
    """
    email = "dep_no_session@example.com"
    access_token = await _register_verify_login(async_client, capsys, email)

    # Decode the JWT without verifying expiry to extract the session_id claim.
    settings = Settings()  # type: ignore[call-arg]
    decoded = pyjwt.decode(
        access_token,
        settings.jwt_secret_key,
        algorithms=[settings.jwt_algorithm],
        options={"verify_exp": False},
    )
    session_id = decoded["session_id"]

    # Manually evict the session from FakeRedis.
    await fake_redis.delete(f"session:{session_id}")  # type: ignore[union-attr]

    response = await async_client.get(
        _PROTECTED_URL,
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_protected_endpoint_rejects_blacklisted_token(
    async_client: AsyncClient,
    capsys: pytest.CaptureFixture[str],
    fake_redis: object,
) -> None:
    """GET /test-protected returns 401 when the token's JTI is blacklisted.

    Simulates the post-logout state: after logout the access token's JTI is
    written to ``blacklist:{jti}`` in Redis.  get_current_user must detect the
    blacklisted JTI at Step 3 and reject the request with 401, even though the
    JWT signature and session are both still valid.  Enforces SR-09.
    """
    email = "dep_blacklisted@example.com"
    access_token = await _register_verify_login(async_client, capsys, email)

    # Decode the JWT without verifying expiry to extract the jti claim.
    settings = Settings()  # type: ignore[call-arg]
    decoded = pyjwt.decode(
        access_token,
        settings.jwt_secret_key,
        algorithms=[settings.jwt_algorithm],
        options={"verify_exp": False},
    )
    jti = decoded["jti"]

    # Manually blacklist this JTI, simulating what the logout endpoint will do.
    await fake_redis.set(f"blacklist:{jti}", "1")  # type: ignore[union-attr]

    response = await async_client.get(
        _PROTECTED_URL,
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# Deactivated / locked user rejection (Steps 6–7 of get_current_user)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_protected_endpoint_rejects_deactivated_user(
    async_client: AsyncClient,
    db_session: AsyncSession,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A deactivated user's valid token is rejected with 403 by get_current_user.

    Even if the JWT is cryptographically valid and the Redis session exists,
    a user with is_active=False must be rejected at step 6 (SR-05).
    """
    email = "dep_deactivated@example.com"
    access_token = await _register_verify_login(async_client, capsys, email)

    result = await db_session.execute(select(User).where(User.email == email))
    user = result.scalar_one()
    user.is_active = False
    await db_session.commit()

    resp = await async_client.get(
        _PROTECTED_URL,
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_protected_endpoint_rejects_locked_user(
    async_client: AsyncClient,
    db_session: AsyncSession,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A locked user's valid token is rejected with 403 by get_current_user.

    Even if the JWT and Redis session are valid, a user whose locked_until
    is in the future must be rejected at step 7 (SR-05).
    """
    email = "dep_locked@example.com"
    access_token = await _register_verify_login(async_client, capsys, email)

    result = await db_session.execute(select(User).where(User.email == email))
    user = result.scalar_one()
    user.locked_until = datetime.now(tz=timezone.utc) + timedelta(hours=1)
    await db_session.commit()

    resp = await async_client.get(
        _PROTECTED_URL,
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert resp.status_code == 403
