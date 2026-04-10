"""Tests for the POST /auth/logout endpoint (Step 6).

Covers:
- Successful logout returns 200 with message (SR-09, SR-10, SR-16)
- Access token is blacklisted after logout (SR-09)
- Refresh token is marked revoked in the database (SR-07)
- Redis session is deleted after logout (SR-10)
- LOGOUT audit log entry is written (SR-16)
- Missing Authorization header returns 403 (HTTPBearer behaviour)

All tests use the register → verify-email → login helper pattern to produce
a valid session before exercising the logout endpoint.  Each test is fully
isolated via the ``async_client`` fixture (fresh SQLite + FakeRedis per test).
"""

from __future__ import annotations

import uuid

import jwt as pyjwt
import pytest
from fastapi import Depends
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.security import hash_token
from app.dependencies.auth import get_current_user
from app.main import app
from app.models.audit_log import AuditLog
from app.models.refresh_token import RefreshToken
from app.models.user import User

# ---------------------------------------------------------------------------
# Test-only protected route for post-logout token rejection test
#
# Registered once at module import time.  Uses a distinct path to avoid
# colliding with the route defined in test_get_current_user.py.
# ---------------------------------------------------------------------------
_PROTECTED_LOGOUT_URL = "/test-protected-logout"


@app.get(_PROTECTED_LOGOUT_URL)
async def _test_protected_logout(
    current_user: User = Depends(get_current_user),
) -> dict[str, str]:
    """Test-only route: return the authenticated user's ID."""
    return {"user_id": str(current_user.id)}


# ---------------------------------------------------------------------------
# URL constants
# ---------------------------------------------------------------------------
_REGISTER_URL = "/api/v1/auth/register"
_VERIFY_URL = "/api/v1/auth/verify-email"
_LOGIN_URL = "/api/v1/auth/login"
_LOGOUT_URL = "/api/v1/auth/logout"

_STRONG_PASSWORD = "StrongPass1!"


# ---------------------------------------------------------------------------
# Helper: register, verify email, and login — returns (access_token, refresh_token)
# ---------------------------------------------------------------------------


async def _register_verify_login(
    async_client: AsyncClient,
    capsys: pytest.CaptureFixture[str],
    email: str,
) -> tuple[str, str]:
    """Register a user, verify their email, and log them in.

    Returns both the access_token and refresh_token from the login response so
    that logout tests can supply both the Authorization header and the request body.

    Args:
        async_client: Test HTTP client fixture.
        capsys:       pytest stdout capture fixture (captures DEMO MODE token).
        email:        Email address to register.

    Returns:
        A 2-tuple ``(access_token, refresh_token)``.
    """
    # Register
    reg_resp = await async_client.post(
        _REGISTER_URL,
        json={"email": email, "password": _STRONG_PASSWORD},
    )
    assert reg_resp.status_code == 201

    # Capture the raw verification token printed to stdout (DEMO MODE)
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
    data = login_resp.json()
    return data["access_token"], data["refresh_token"]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_logout_returns_200(
    async_client: AsyncClient,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """POST /auth/logout with valid tokens returns 200 and a success message.

    Happy-path confirmation that the endpoint is reachable, correctly wired,
    and returns the expected response shape (SR-09, SR-10).
    """
    email = "logout_200@example.com"
    access_token, refresh_token = await _register_verify_login(
        async_client, capsys, email
    )

    response = await async_client.post(
        _LOGOUT_URL,
        json={"refresh_token": refresh_token},
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert response.status_code == 200
    data = response.json()
    assert "message" in data


@pytest.mark.asyncio
async def test_logout_blacklists_access_token(
    async_client: AsyncClient,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Access token is rejected after logout (SR-09: JTI blacklist).

    After a successful logout the same access token must be refused by any
    protected endpoint.  This proves that the JTI was written to the Redis
    blacklist and that ``get_current_user`` (Step 3) rejects it with 401.
    """
    email = "logout_blacklist@example.com"
    access_token, refresh_token = await _register_verify_login(
        async_client, capsys, email
    )

    logout_resp = await async_client.post(
        _LOGOUT_URL,
        json={"refresh_token": refresh_token},
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert logout_resp.status_code == 200

    # The same access token must now be rejected.
    protected_resp = await async_client.get(
        _PROTECTED_LOGOUT_URL,
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert protected_resp.status_code == 401


@pytest.mark.asyncio
async def test_logout_revokes_refresh_token(
    async_client: AsyncClient,
    db_session: AsyncSession,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Refresh token row is marked revoked=True in the database after logout.

    Queries the ``refresh_tokens`` table directly to confirm the ``revoked``
    flag is set.  The row must not be deleted — the audit trail must be
    preserved (SR-07, SR-16).
    """
    email = "logout_revoke_rt@example.com"
    access_token, refresh_token = await _register_verify_login(
        async_client, capsys, email
    )

    logout_resp = await async_client.post(
        _LOGOUT_URL,
        json={"refresh_token": refresh_token},
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert logout_resp.status_code == 200

    # Compute the hash that was stored at login time and look it up directly.
    token_hash = hash_token(refresh_token)
    result = await db_session.execute(
        select(RefreshToken).where(RefreshToken.token_hash == token_hash)
    )
    rt_row = result.scalar_one_or_none()

    assert rt_row is not None, "RefreshToken row must exist (not deleted)"
    assert rt_row.revoked is True, "RefreshToken must be marked revoked after logout"


@pytest.mark.asyncio
async def test_logout_deletes_redis_session(
    async_client: AsyncClient,
    fake_redis: object,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Redis session key is deleted after logout (SR-10).

    Decodes the access token to extract the session_id claim and then checks
    that ``session:{session_id}`` no longer exists in FakeRedis.
    """
    email = "logout_redis@example.com"
    access_token, refresh_token = await _register_verify_login(
        async_client, capsys, email
    )

    # Decode the JWT (skip expiry check) to extract session_id.
    settings = Settings()  # type: ignore[call-arg]
    decoded = pyjwt.decode(
        access_token,
        settings.jwt_secret_key,
        algorithms=[settings.jwt_algorithm],
        options={"verify_exp": False},
    )
    session_id = decoded["session_id"]

    logout_resp = await async_client.post(
        _LOGOUT_URL,
        json={"refresh_token": refresh_token},
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert logout_resp.status_code == 200

    # The session key must be absent from Redis after logout.
    session_value = await fake_redis.get(f"session:{session_id}")  # type: ignore[union-attr]
    assert session_value is None, "Redis session must be deleted after logout"


@pytest.mark.asyncio
async def test_logout_audit_log_written(
    async_client: AsyncClient,
    db_session: AsyncSession,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A LOGOUT audit log entry is written after a successful logout (SR-16).

    Queries the ``audit_logs`` table scoped by action and user_id (ADR-18) to
    confirm that the LOGOUT event was recorded for this specific user.
    """
    email = "logout_audit@example.com"

    # Register separately to capture user_id from the response.
    reg_resp = await async_client.post(
        _REGISTER_URL,
        json={"email": email, "password": _STRONG_PASSWORD},
    )
    assert reg_resp.status_code == 201
    user_id = reg_resp.json()["id"]

    # Complete email verification.
    captured = capsys.readouterr()
    raw_token = captured.out.strip().rsplit(": ", maxsplit=1)[-1]
    verify_resp = await async_client.get(_VERIFY_URL, params={"token": raw_token})
    assert verify_resp.status_code == 200

    # Login.
    login_resp = await async_client.post(
        _LOGIN_URL,
        json={"email": email, "password": _STRONG_PASSWORD},
    )
    assert login_resp.status_code == 200
    login_data = login_resp.json()
    access_token = login_data["access_token"]
    refresh_token = login_data["refresh_token"]

    logout_resp = await async_client.post(
        _LOGOUT_URL,
        json={"refresh_token": refresh_token},
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert logout_resp.status_code == 200

    # ADR-18: scope the audit log query by both action and user_id to avoid
    # false matches from other tests sharing the same in-memory database.
    result = await db_session.execute(
        select(AuditLog).where(
            AuditLog.action == "LOGOUT",
            AuditLog.user_id == uuid.UUID(user_id),
        )
    )
    log_entry = result.scalar_one_or_none()

    assert log_entry is not None, "Expected a LOGOUT audit log entry"
    assert log_entry.details is not None
    assert "session_id" in log_entry.details


@pytest.mark.asyncio
async def test_logout_requires_authentication(
    async_client: AsyncClient,
) -> None:
    """POST /auth/logout without Authorization header returns 403.

    ``HTTPBearer`` raises HTTP 403 (not 401) when the Authorization header is
    entirely absent.  The logout endpoint must not be accessible without a
    valid credential.
    """
    response = await async_client.post(
        _LOGOUT_URL,
        json={"refresh_token": "some-token-value"},
    )
    assert response.status_code == 403
