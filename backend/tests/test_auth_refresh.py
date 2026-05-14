"""Tests for the POST /auth/refresh endpoint (Step 7).

Covers:
- Successful rotation returns new access_token and rotated zt_rt cookie (SR-07)
- Old refresh token (presented via cookie) is rejected after rotation (SR-07)
- Reuse detection destroys the Redis session (SR-08)
- Invalid (random) refresh token returns 401
- Expired refresh token returns 401
- Missing zt_rt cookie returns 401 (not 422 — no body schema involved)

All tests use the register → verify-email → login helper pattern to produce
a valid session before exercising the refresh endpoint.  Each test is fully
isolated via the ``async_client`` fixture (fresh SQLite + FakeRedis per test).

The refresh token is delivered via an HttpOnly ``Set-Cookie: zt_rt=...``
header (SR-07).  Tests that need to present or inspect the refresh token do
so via the httpx cookie API rather than the JSON body.
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
    """POST /auth/refresh returns 200 with a new access_token and rotated
    zt_rt cookie (SR-07).

    The refresh token must not appear in the JSON body — it is delivered
    exclusively via HttpOnly cookie so that JavaScript cannot read it.
    """
    email = "refresh_new_tokens@example.com"
    _, orig_access = await register_verify_login(async_client, capsys, email)

    # After login the httpx client cookie jar holds the zt_rt cookie.
    orig_refresh = async_client.cookies.get("zt_rt")
    assert orig_refresh is not None, "zt_rt cookie must be set after login"

    # The httpx client sends the stored cookie automatically.
    resp = await async_client.post(_REFRESH_URL)

    assert resp.status_code == 200
    data = resp.json()

    assert "access_token" in data
    # SR-07: refresh token must be in the cookie, not the JSON body.
    assert (
        "refresh_token" not in data
    ), "refresh_token must not appear in the JSON body (SR-07)"
    assert data["token_type"] == "bearer"
    assert data["expires_in"] > 0

    assert data["access_token"] != orig_access, "New access token must differ"

    # Verify the rotated cookie is different from the original.
    new_refresh = resp.cookies.get("zt_rt")
    assert new_refresh is not None, "Rotated zt_rt cookie must be set after refresh"
    assert new_refresh != orig_refresh, "New refresh token must differ from original"
    # Assert rotated cookie retains security attributes (SR-07).
    set_cookie_header = resp.headers.get("set-cookie", "")
    assert (
        "HttpOnly" in set_cookie_header
    ), "Rotated zt_rt cookie must be HttpOnly (SR-07)"
    assert (
        "Path=/api/v1/auth" in set_cookie_header
    ), "Rotated zt_rt cookie must be scoped to /api/v1/auth (SR-07)"
    assert (
        "samesite=lax" in set_cookie_header.lower()
    ), "Rotated zt_rt cookie must have SameSite=lax (SR-07)"

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
    _, _access = await register_verify_login(async_client, capsys, email)

    orig_refresh = async_client.cookies.get("zt_rt")
    assert orig_refresh is not None

    first_resp = await async_client.post(_REFRESH_URL)
    assert first_resp.status_code == 200

    # Present the old (now-revoked) token explicitly via cookie.
    reuse_resp = await async_client.post(
        _REFRESH_URL,
        cookies={"zt_rt": orig_refresh},
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
    _, access_token_1 = await register_verify_login(async_client, capsys, email)
    refresh_token_1 = async_client.cookies.get("zt_rt")
    assert refresh_token_1 is not None

    rotate_resp = await async_client.post(_REFRESH_URL)
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

    # Replay the original (now-revoked) token.
    reuse_resp = await async_client.post(
        _REFRESH_URL,
        cookies={"zt_rt": refresh_token_1},
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
    """POST /auth/refresh with a random string in the cookie returns 401 (SR-07)."""
    resp = await async_client.post(
        _REFRESH_URL,
        cookies={"zt_rt": "this-token-was-never-issued"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_refresh_with_expired_token(
    async_client: AsyncClient,
    db_session: AsyncSession,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """POST /auth/refresh with an expired token in the cookie returns 401 (SR-07)."""
    email = "refresh_expired@example.com"
    _, _access = await register_verify_login(async_client, capsys, email)

    refresh_token = async_client.cookies.get("zt_rt")
    assert refresh_token is not None

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
        cookies={"zt_rt": refresh_token},
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
    user_id, _access = await register_verify_login(async_client, capsys, email)

    # The httpx client sends the zt_rt cookie automatically.
    refresh_resp = await async_client.post(_REFRESH_URL)
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
async def test_refresh_missing_cookie_returns_401(
    async_client: AsyncClient,
) -> None:
    """POST /auth/refresh with no zt_rt cookie returns 401.

    The endpoint reads the refresh token from the HttpOnly cookie (SR-07).
    When the cookie is absent there is no body schema to validate, so the
    response is HTTP 401 (not 422) — the server cannot proceed without the
    credential.
    """
    # No login → no cookie in the jar → no zt_rt sent.
    resp = await async_client.post(_REFRESH_URL)
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_logout_clears_refresh_cookie(
    async_client: AsyncClient,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """POST /auth/logout responds with Set-Cookie that clears the zt_rt cookie (SR-07).

    The backend must set zt_rt to an empty value with Max-Age=0 (or equivalent)
    and the correct Path, so the browser is instructed to delete the cookie.
    """
    email = "logout_clear_cookie@example.com"
    _, access = await register_verify_login(async_client, capsys, email)

    logout_resp = await async_client.post(
        "/api/v1/auth/logout",
        headers={"Authorization": f"Bearer {access}"},
    )
    assert logout_resp.status_code == 200

    set_cookie_header = logout_resp.headers.get("set-cookie", "")
    assert (
        "zt_rt" in set_cookie_header
    ), "Logout must include a Set-Cookie header for zt_rt"
    assert (
        "Path=/api/v1/auth" in set_cookie_header
    ), "Logout Set-Cookie must include Path=/api/v1/auth to clear the correct cookie"
    # FastAPI's delete_cookie sets Max-Age=0 to expire the cookie immediately.
    assert (
        "max-age=0" in set_cookie_header.lower()
    ), "Logout must set Max-Age=0 to instruct the browser to delete the cookie"


@pytest.mark.asyncio
async def test_refresh_reuse_detection_revokes_sibling_db_token(
    async_client: AsyncClient,
    db_session: AsyncSession,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Reuse detection must mark sibling DB refresh tokens as revoked (H-5/SR-08).

    An attacker holding a non-replayed sibling token must be rejected after
    reuse detection fires, not just after their Redis session is deleted.
    """
    email = f"sibling_revoke_{uuid.uuid4().hex[:8]}@example.com"
    user_id_str, _access = await register_verify_login(async_client, capsys, email)
    refresh_token_1 = async_client.cookies.get("zt_rt")
    assert refresh_token_1 is not None

    # Rotate once — token_1 is revoked, token_2 is the live sibling.
    rotate_resp = await async_client.post(_REFRESH_URL)
    assert rotate_resp.status_code == 200
    refresh_token_2 = rotate_resp.cookies.get("zt_rt")
    assert refresh_token_2 is not None

    # Replay the already-rotated token_1 — triggers reuse detection.
    reuse_resp = await async_client.post(
        _REFRESH_URL, cookies={"zt_rt": refresh_token_1}
    )
    assert reuse_resp.status_code == 401

    # The sibling token_2 must now be rejected (revoked in DB by bulk UPDATE).
    sibling_resp = await async_client.post(
        _REFRESH_URL, cookies={"zt_rt": refresh_token_2}
    )
    assert (
        sibling_resp.status_code == 401
    ), "Sibling refresh token must be rejected after reuse detection"

    # Verify the DB row for token_2 is marked revoked.
    token_2_hash = hash_token(refresh_token_2)
    result = await db_session.execute(
        select(RefreshToken).where(RefreshToken.token_hash == token_2_hash)
    )
    sibling_row = result.scalar_one_or_none()
    assert sibling_row is not None
    assert sibling_row.revoked is True, "Sibling DB token must be marked revoked"


@pytest.mark.asyncio
async def test_refresh_reuse_detection_writes_audit_log(
    async_client: AsyncClient,
    db_session: AsyncSession,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """TOKEN_REUSE_DETECTED AuditLog written on refresh token replay (TD-12/SR-16)."""
    email = f"reuse_audit_{uuid.uuid4().hex[:8]}@example.com"
    user_id_str, _access = await register_verify_login(async_client, capsys, email)
    refresh_token_1 = async_client.cookies.get("zt_rt")
    assert refresh_token_1 is not None

    # Rotate so token_1 becomes revoked.
    rotate_resp = await async_client.post(_REFRESH_URL)
    assert rotate_resp.status_code == 200

    # Replay the revoked token.
    reuse_resp = await async_client.post(
        _REFRESH_URL, cookies={"zt_rt": refresh_token_1}
    )
    assert reuse_resp.status_code == 401

    # AuditLog must contain TOKEN_REUSE_DETECTED for this user.
    result = await db_session.execute(
        select(AuditLog).where(
            AuditLog.action == "TOKEN_REUSE_DETECTED",
            AuditLog.user_id == uuid.UUID(user_id_str),
        )
    )
    log_entry = result.scalar_one_or_none()
    assert log_entry is not None, "Expected TOKEN_REUSE_DETECTED audit log entry"
    assert log_entry.details is not None
    assert "session_id" in log_entry.details
    assert "tokens_revoked" in log_entry.details
