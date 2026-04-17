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

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import jwt as pyjwt
import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.security import hash_token
from app.models.audit_log import AuditLog
from app.models.refresh_token import RefreshToken

# ---------------------------------------------------------------------------
# URL constants
# ---------------------------------------------------------------------------
_REGISTER_URL = "/api/v1/auth/register"
_VERIFY_URL = "/api/v1/auth/verify-email"
_LOGIN_URL = "/api/v1/auth/login"
_REFRESH_URL = "/api/v1/auth/refresh"

_STRONG_PASSWORD = "StrongPass1!"

# ---------------------------------------------------------------------------
# Test-only protected route for post-refresh token rejection test
#
# Registered once at module import time.  Uses a distinct path to avoid
# colliding with the route defined in test_auth_logout.py.
# ---------------------------------------------------------------------------
from fastapi import Depends  # noqa: E402

from app.dependencies.auth import get_current_user  # noqa: E402
from app.main import app  # noqa: E402
from app.models.user import User  # noqa: E402

_PROTECTED_REFRESH_URL = "/test-protected-refresh"


@app.get(_PROTECTED_REFRESH_URL)
async def _test_protected_refresh(
    current_user: User = Depends(get_current_user),
) -> dict[str, str]:
    """Test-only route: return the authenticated user's ID."""
    return {"user_id": str(current_user.id)}


# ---------------------------------------------------------------------------
# Helper: register, verify email, and login
# ---------------------------------------------------------------------------


async def _register_verify_login(
    async_client: AsyncClient,
    capsys: pytest.CaptureFixture[str],
    email: str,
) -> tuple[str, str]:
    """Register a user, verify their email, and log them in.

    Returns ``(access_token, refresh_token)`` from the login response.

    Args:
        async_client: Test HTTP client fixture.
        capsys:       pytest stdout capture fixture (captures DEMO MODE token).
        email:        Email address to register.

    Returns:
        A 2-tuple ``(access_token, refresh_token)``.
    """
    reg_resp = await async_client.post(
        _REGISTER_URL,
        json={"email": email, "password": _STRONG_PASSWORD},
    )
    assert reg_resp.status_code == 201

    captured = capsys.readouterr()
    raw_token = captured.out.strip().rsplit(": ", maxsplit=1)[-1]

    verify_resp = await async_client.get(_VERIFY_URL, params={"token": raw_token})
    assert verify_resp.status_code == 200

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
async def test_refresh_returns_new_tokens(
    async_client: AsyncClient,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """POST /auth/refresh returns 200 with a new access_token and refresh_token.

    The response tokens must differ from the originals: the access token carries
    a new JWT payload (different JTI, new session_id) and the refresh token is a
    new opaque value (SR-07).
    """
    email = "refresh_new_tokens@example.com"
    orig_access, orig_refresh = await _register_verify_login(
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

    # Both tokens must be distinct from the originals.
    assert data["access_token"] != orig_access, "New access token must differ"
    assert data["refresh_token"] != orig_refresh, "New refresh token must differ"

    # The new access token must decode to a valid JWT payload.
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
    """The original refresh token is rejected after a successful rotation (SR-07).

    After one successful call to /auth/refresh, the original refresh token must
    return 401 on any subsequent attempt.  This enforces single-use semantics.
    """
    email = "refresh_old_rejected@example.com"
    _, orig_refresh = await _register_verify_login(async_client, capsys, email)

    # First rotation succeeds.
    first_resp = await async_client.post(
        _REFRESH_URL,
        json={"refresh_token": orig_refresh},
    )
    assert first_resp.status_code == 200

    # Presenting the original token again must be rejected.
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
    """Reuse detection (SR-08): replaying an old refresh token destroys the session.

    Scenario:
    1. Login to obtain access_token_1 and refresh_token_1.
    2. Rotate to obtain access_token_2 and refresh_token_2.
       (refresh_token_1 is now revoked; session has been rotated.)
    3. Present refresh_token_1 again → 401 (reuse detected).
       The service must delete the Redis session for the session_id associated
       with refresh_token_1 — which is the *new* session from step 2.
    4. access_token_2, which carries the new session_id, must now be rejected
       by get_current_user because its session key was deleted in step 3.

    This proves that SR-08 breaks the attacker's ability to maintain access
    after the victim rotates: even if the attacker captured refresh_token_1
    before the rotation, triggering reuse detection invalidates the victim's
    current session.
    """
    email = "refresh_reuse_session@example.com"
    access_token_1, refresh_token_1 = await _register_verify_login(
        async_client, capsys, email
    )

    # Step 2: successful rotation.
    rotate_resp = await async_client.post(
        _REFRESH_URL,
        json={"refresh_token": refresh_token_1},
    )
    assert rotate_resp.status_code == 200
    access_token_2 = rotate_resp.json()["access_token"]

    # Decode to get the new session_id so we can verify it disappears.
    settings = Settings()  # type: ignore[call-arg]
    decoded_2 = pyjwt.decode(
        access_token_2,
        settings.jwt_secret_key,
        algorithms=[settings.jwt_algorithm],
        options={"verify_exp": False},
    )
    new_session_id = decoded_2["session_id"]

    # Confirm the new session exists in Redis before triggering reuse.
    session_before = await fake_redis.get(f"session:{new_session_id}")  # type: ignore[union-attr]
    assert session_before is not None, "New session must exist before reuse detection"

    # Step 3: replay the original refresh token → reuse detection.
    reuse_resp = await async_client.post(
        _REFRESH_URL,
        json={"refresh_token": refresh_token_1},
    )
    assert reuse_resp.status_code == 401

    # Step 4: the new session's Redis key must now be gone (SR-08).
    session_after = await fake_redis.get(f"session:{new_session_id}")  # type: ignore[union-attr]
    assert session_after is None, "Redis session must be deleted after reuse detection"

    # access_token_2 must now be rejected because its session is gone.
    protected_resp = await async_client.get(
        _PROTECTED_REFRESH_URL,
        headers={"Authorization": f"Bearer {access_token_2}"},
    )
    assert protected_resp.status_code == 401


@pytest.mark.asyncio
async def test_refresh_with_invalid_token(
    async_client: AsyncClient,
) -> None:
    """POST /auth/refresh with a random string returns 401 (SR-07).

    A token that was never issued cannot match any stored hash; the endpoint
    must return 401 without leaking any information about the token store.
    """
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
    """POST /auth/refresh with an expired token returns 401 (SR-07).

    Manually backdates ``expires_at`` on the RefreshToken row so the service
    treats it as expired.  The endpoint must return 401 without rotating or
    issuing new tokens.
    """
    email = "refresh_expired@example.com"
    _, refresh_token = await _register_verify_login(async_client, capsys, email)

    # Look up the token row and set expires_at to a past timestamp.
    token_hash = hash_token(refresh_token)
    result = await db_session.execute(
        select(RefreshToken).where(RefreshToken.token_hash == token_hash)
    )
    token_row = result.scalar_one_or_none()
    assert token_row is not None

    # Backdate expiry to a fixed point in the past so the token is clearly expired.
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
    """A TOKEN_REFRESHED audit log entry is written on successful rotation (SR-16).

    Queries the ``audit_logs`` table scoped by action and user_id (ADR-18) to
    confirm that the event was recorded for the specific user.
    """
    email = "refresh_audit@example.com"

    # Register separately to capture user_id from the response.
    reg_resp = await async_client.post(
        _REGISTER_URL,
        json={"email": email, "password": _STRONG_PASSWORD},
    )
    assert reg_resp.status_code == 201
    user_id = reg_resp.json()["id"]

    captured = capsys.readouterr()
    raw_token = captured.out.strip().rsplit(": ", maxsplit=1)[-1]
    verify_resp = await async_client.get(_VERIFY_URL, params={"token": raw_token})
    assert verify_resp.status_code == 200

    login_resp = await async_client.post(
        _LOGIN_URL,
        json={"email": email, "password": _STRONG_PASSWORD},
    )
    assert login_resp.status_code == 200
    refresh_token = login_resp.json()["refresh_token"]

    refresh_resp = await async_client.post(
        _REFRESH_URL,
        json={"refresh_token": refresh_token},
    )
    assert refresh_resp.status_code == 200

    # ADR-18: scope by both action and user_id.
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
    """POST /auth/refresh without refresh_token in the body returns 422.

    The ``RefreshRequest`` schema requires a ``refresh_token`` field. Omitting
    it must trigger Pydantic validation failure (422).
    """
    resp = await async_client.post(_REFRESH_URL, json={})
    assert resp.status_code == 422
