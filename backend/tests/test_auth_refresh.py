"""Tests for the POST /auth/refresh endpoint (Step 7).

Covers:
- Successful rotation returns new access_token and new refresh_token (SR-07)
- Old refresh token is rejected after rotation (SR-07)
- Reuse detection destroys the Redis session (SR-08)
- Invalid (random) refresh token returns 401
- Expired refresh token returns 401

All tests use the register → verify-email → login helper pattern to produce
a valid session before exercising the refresh endpoint.  Each test is fully
isolated via the ``async_client`` fixture (fresh SQLite + FakeRedis per test).
"""

import uuid
from datetime import datetime, timezone

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
from tests.helpers import register_verify_login

_REFRESH_URL = "/api/v1/auth/refresh"
_PROTECTED_REFRESH_URL = "/test-protected-refresh"


@app.get(_PROTECTED_REFRESH_URL)
async def _test_protected_refresh(
    current_user: User = Depends(get_current_user),
) -> dict[str, str]:
    """Test-only route: return the authenticated user's ID."""
    return {"user_id": str(current_user.id)}


@pytest.mark.asyncio
async def test_refresh_returns_new_tokens(
    async_client: AsyncClient,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """POST /auth/refresh returns 200 with a new access_token
    and refresh_token (SR-07)."""
    email = "refresh_new_tokens@example.com"
    _, orig_access, orig_refresh = await register_verify_login(
        async_client, capsys, email
    )

    resp = await async_client.post(
        _REFRESH_URL,
        json={"refresh_token": orig_refresh},
    )

    assert resp.status_code == 200
    data = resp.json()

    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"
    assert data["expires_in"] > 0

    assert data["access_token"] != orig_access, "New access token must differ"
    assert data["refresh_token"] != orig_refresh, "New refresh token must differ"

    settings = Settings()  # type: ignore[call-arg]
    decoded = pyjwt.decode(
        data["access_token"],
        settings.jwt_secret_key,
        algorithms=[settings.jwt_algorithm],
        options={"verify_exp": False},
    )
    assert decoded["typ"] == "access"
    assert "session_id" in decoded
    assert "jti" in decoded


@pytest.mark.asyncio
async def test_refresh_old_token_rejected_after_rotation(
    async_client: AsyncClient,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Original refresh token is rejected after rotation
    — single-use semantics (SR-07)."""
    email = "refresh_old_rejected@example.com"
    _, _access, orig_refresh = await register_verify_login(async_client, capsys, email)

    first_resp = await async_client.post(
        _REFRESH_URL,
        json={"refresh_token": orig_refresh},
    )
    assert first_resp.status_code == 200

    reuse_resp = await async_client.post(
        _REFRESH_URL,
        json={"refresh_token": orig_refresh},
    )
    assert reuse_resp.status_code == 401


@pytest.mark.asyncio
async def test_refresh_reuse_detection_revokes_session(
    async_client: AsyncClient,
    fake_redis: object,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """SR-08: replaying a revoked refresh token destroys the current session.

    Scenario: login → rotate → replay old token → 401 → new access token also rejected.
    Proves that reuse detection invalidates the victim's current session, not just
    the replayed one.
    """
    email = "refresh_reuse_session@example.com"
    _, access_token_1, refresh_token_1 = await register_verify_login(
        async_client, capsys, email
    )

    rotate_resp = await async_client.post(
        _REFRESH_URL,
        json={"refresh_token": refresh_token_1},
    )
    assert rotate_resp.status_code == 200
    access_token_2 = rotate_resp.json()["access_token"]

    settings = Settings()  # type: ignore[call-arg]
    decoded_2 = pyjwt.decode(
        access_token_2,
        settings.jwt_secret_key,
        algorithms=[settings.jwt_algorithm],
        options={"verify_exp": False},
    )
    new_session_id = decoded_2["session_id"]

    session_before = await fake_redis.get(f"session:{new_session_id}")  # type: ignore[union-attr]
    assert session_before is not None, "New session must exist before reuse detection"

    reuse_resp = await async_client.post(
        _REFRESH_URL,
        json={"refresh_token": refresh_token_1},
    )
    assert reuse_resp.status_code == 401

    session_after = await fake_redis.get(f"session:{new_session_id}")  # type: ignore[union-attr]
    assert session_after is None, "Redis session must be deleted after reuse detection"

    protected_resp = await async_client.get(
        _PROTECTED_REFRESH_URL,
        headers={"Authorization": f"Bearer {access_token_2}"},
    )
    assert protected_resp.status_code == 401


@pytest.mark.asyncio
async def test_refresh_with_invalid_token(
    async_client: AsyncClient,
) -> None:
    """POST /auth/refresh with a random string returns 401 (SR-07)."""
    resp = await async_client.post(
        _REFRESH_URL,
        json={"refresh_token": "this-token-was-never-issued"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_refresh_with_expired_token(
    async_client: AsyncClient,
    db_session: AsyncSession,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """POST /auth/refresh with an expired token returns 401 (SR-07)."""
    email = "refresh_expired@example.com"
    _, _access, refresh_token = await register_verify_login(async_client, capsys, email)

    token_hash = hash_token(refresh_token)
    result = await db_session.execute(
        select(RefreshToken).where(RefreshToken.token_hash == token_hash)
    )
    token_row = result.scalar_one_or_none()
    assert token_row is not None

    token_row.expires_at = datetime(2000, 1, 1, tzinfo=timezone.utc)
    await db_session.commit()

    resp = await async_client.post(
        _REFRESH_URL,
        json={"refresh_token": refresh_token},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_refresh_audit_log_written(
    async_client: AsyncClient,
    db_session: AsyncSession,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A TOKEN_REFRESHED audit log entry is written on successful rotation (SR-16)."""
    email = "refresh_audit@example.com"
    user_id, _access, refresh_token = await register_verify_login(
        async_client, capsys, email
    )

    refresh_resp = await async_client.post(
        _REFRESH_URL,
        json={"refresh_token": refresh_token},
    )
    assert refresh_resp.status_code == 200

    result = await db_session.execute(
        select(AuditLog).where(
            AuditLog.action == "TOKEN_REFRESHED",
            AuditLog.user_id == uuid.UUID(user_id),
        )
    )
    log_entry = result.scalar_one_or_none()

    assert log_entry is not None, "Expected a TOKEN_REFRESHED audit log entry"
    assert log_entry.details is not None
    assert "session_id" in log_entry.details


@pytest.mark.asyncio
async def test_refresh_missing_token_returns_422(
    async_client: AsyncClient,
) -> None:
    """POST /auth/refresh without refresh_token in body returns 422."""
    resp = await async_client.post(_REFRESH_URL, json={})
    assert resp.status_code == 422
