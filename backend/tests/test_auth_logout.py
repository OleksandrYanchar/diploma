"""Tests for the POST /auth/logout endpoint (Step 6).

Covers:
- Successful logout returns 200 with message (SR-09, SR-10, SR-16)
- Access token is blacklisted after logout (SR-09)
- Refresh token is marked revoked in the database (SR-07)
- Redis session is deleted after logout (SR-10)
- LOGOUT audit log entry is written (SR-16)
- Missing Authorization header returns 403 (HTTPBearer behaviour)
- Missing zt_rt cookie results in idempotent 200 (empty string → no-op revocation)

The refresh token is delivered via an HttpOnly ``Set-Cookie: zt_rt=...``
header (SR-07).  Tests that need the raw refresh token value read it from the
httpx cookie jar.  Tests that exercise logout without a cookie pass no
``zt_rt`` cookie, which triggers the idempotent no-op path in the service.

All tests are fully isolated via the ``async_client`` fixture
(fresh SQLite + FakeRedis per test).
"""

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
from tests.helpers import (
    LOGIN_URL,
    REGISTER_URL,
    STRONG_PASSWORD,
    VERIFY_URL,
    register_verify_login,
)

# Distinct path avoids collision with the route registered in test_get_current_user.py.
_PROTECTED_LOGOUT_URL = "/test-protected-logout"


@app.get(_PROTECTED_LOGOUT_URL)
async def _test_protected_logout(
    current_user: User = Depends(get_current_user),
) -> dict[str, str]:
    """Test-only route: return the authenticated user's ID."""
    return {"user_id": str(current_user.id)}


_LOGOUT_URL = "/api/v1/auth/logout"


@pytest.mark.asyncio
async def test_logout_returns_200(
    async_client: AsyncClient,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """POST /auth/logout with valid tokens returns 200 and a success message.

    Happy-path confirmation that the endpoint is reachable, correctly wired,
    and returns the expected response shape (SR-09, SR-10).

    The refresh token is sent automatically via the zt_rt HttpOnly cookie that
    was set during login.
    """
    email = "logout_200@example.com"
    _, access_token = await register_verify_login(async_client, capsys, email)

    # The httpx client sends the zt_rt cookie automatically from the login response.
    response = await async_client.post(
        _LOGOUT_URL,
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
    _, access_token = await register_verify_login(async_client, capsys, email)

    logout_resp = await async_client.post(
        _LOGOUT_URL,
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert logout_resp.status_code == 200

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
    _, access_token = await register_verify_login(async_client, capsys, email)

    # Capture the refresh token from the cookie before logout clears it.
    refresh_token = async_client.cookies.get("zt_rt")
    assert refresh_token is not None

    logout_resp = await async_client.post(
        _LOGOUT_URL,
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert logout_resp.status_code == 200

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
    _, access_token = await register_verify_login(async_client, capsys, email)

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
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert logout_resp.status_code == 200

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

    reg_resp = await async_client.post(
        REGISTER_URL,
        json={"email": email, "password": STRONG_PASSWORD},
    )
    assert reg_resp.status_code == 201
    user_id = reg_resp.json()["id"]

    captured = capsys.readouterr()
    raw_token = captured.out.strip().rsplit(": ", maxsplit=1)[-1]
    verify_resp = await async_client.get(VERIFY_URL, params={"token": raw_token})
    assert verify_resp.status_code == 200

    login_resp = await async_client.post(
        LOGIN_URL,
        json={"email": email, "password": STRONG_PASSWORD},
    )
    assert login_resp.status_code == 200
    access_token = login_resp.json()["access_token"]
    # refresh token is in the cookie jar automatically.

    logout_resp = await async_client.post(
        _LOGOUT_URL,
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert logout_resp.status_code == 200

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
    response = await async_client.post(_LOGOUT_URL)
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_logout_missing_cookie_is_idempotent(
    async_client: AsyncClient,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """POST /auth/logout without the zt_rt cookie returns 200 (idempotent).

    The logout endpoint reads the refresh token from the ``zt_rt`` HttpOnly
    cookie (SR-07).  When the cookie is absent, an empty string is passed to
    the service.  The SHA-256 hash of an empty string does not match any
    stored token hash, so ``scalar_one_or_none`` returns None and the
    revocation step is silently skipped.  The access token JTI is still
    blacklisted normally.  The response is HTTP 200 — logout is idempotent
    with respect to a missing refresh token cookie.
    """
    email = "logout_missing_rt@example.com"
    _, access_token = await register_verify_login(async_client, capsys, email)

    # Send the request without the zt_rt cookie by explicitly clearing it.
    resp = await async_client.post(
        _LOGOUT_URL,
        headers={"Authorization": f"Bearer {access_token}"},
        cookies={"zt_rt": ""},
    )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_logout_blacklisted_token_rejected_on_subsequent_request(
    async_client: AsyncClient,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """After logout, using the blacklisted access token to logout again returns 401.

    The JTI blacklist (SR-09) must prevent any reuse of the access token,
    including a second logout attempt.
    """
    email = "logout_double@example.com"
    _, access_token = await register_verify_login(async_client, capsys, email)

    first = await async_client.post(
        _LOGOUT_URL,
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert first.status_code == 200

    second = await async_client.post(
        _LOGOUT_URL,
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert second.status_code == 401
