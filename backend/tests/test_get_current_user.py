"""Tests for the get_current_user dependency (Step 5).

A minimal test-only route ``GET /test-protected`` is registered at module
level on the live ``app`` instance so that the dependency can be exercised
through the full FastAPI request/response stack.  This route is not part of
the production API surface — it exists solely to provide a protected endpoint
in the absence of any real protected routes at this stage of the project.
"""

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
from tests.helpers import register_verify_login

# Test-only protected route — scoped to this module, not a real endpoint.
_PROTECTED_URL = "/test-protected"


@app.get(_PROTECTED_URL)
async def _test_protected(
    current_user: User = Depends(get_current_user),
) -> dict[str, str]:
    """Test-only route: return the authenticated user's ID."""
    return {"user_id": str(current_user.id)}


@pytest.mark.asyncio
async def test_protected_endpoint_rejects_no_token(
    async_client: AsyncClient,
) -> None:
    """GET /test-protected with no Authorization header returns 403 (HTTPBearer)."""
    response = await async_client.get(_PROTECTED_URL)
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_protected_endpoint_rejects_invalid_token(
    async_client: AsyncClient,
) -> None:
    """GET /test-protected with a malformed Bearer token returns 401."""
    response = await async_client.get(
        _PROTECTED_URL,
        headers={"Authorization": "Bearer invalid.token.here"},
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_protected_endpoint_rejects_expired_token(
    async_client: AsyncClient,
) -> None:
    """GET /test-protected with an expired JWT returns 401 (SR-06)."""
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
    """GET /test-protected with a valid token and live session
    returns 200 (SR-06, SR-09, SR-10)."""
    email = "dep_valid@example.com"
    _, access_token, _ = await register_verify_login(async_client, capsys, email)

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
    """GET /test-protected returns 401 when the Redis session key is absent (SR-10)."""
    email = "dep_no_session@example.com"
    _, access_token, _ = await register_verify_login(async_client, capsys, email)

    settings = Settings()  # type: ignore[call-arg]
    decoded = pyjwt.decode(
        access_token,
        settings.jwt_secret_key,
        algorithms=[settings.jwt_algorithm],
        options={"verify_exp": False},
    )
    session_id = decoded["session_id"]

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
    """GET /test-protected returns 401 when the JTI is blacklisted in Redis (SR-09)."""
    email = "dep_blacklisted@example.com"
    _, access_token, _ = await register_verify_login(async_client, capsys, email)

    settings = Settings()  # type: ignore[call-arg]
    decoded = pyjwt.decode(
        access_token,
        settings.jwt_secret_key,
        algorithms=[settings.jwt_algorithm],
        options={"verify_exp": False},
    )
    jti = decoded["jti"]

    await fake_redis.set(f"blacklist:{jti}", "1")  # type: ignore[union-attr]

    response = await async_client.get(
        _PROTECTED_URL,
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_protected_endpoint_rejects_deactivated_user(
    async_client: AsyncClient,
    db_session: AsyncSession,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Deactivated user's valid token is rejected with 403 (SR-05)."""
    email = "dep_deactivated@example.com"
    _, access_token, _ = await register_verify_login(async_client, capsys, email)

    result = await db_session.execute(select(User).where(User.email == email))
    user = result.scalar_one()
    user.is_active = False
    await db_session.commit()

    resp = await async_client.get(
        _PROTECTED_URL,
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert resp.status_code == 403
    assert resp.json()["detail"] == "Account is deactivated"


@pytest.mark.asyncio
async def test_protected_endpoint_rejects_locked_user(
    async_client: AsyncClient,
    db_session: AsyncSession,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Locked user's valid token is rejected with 403 (SR-05)."""
    email = "dep_locked@example.com"
    _, access_token, _ = await register_verify_login(async_client, capsys, email)

    result = await db_session.execute(select(User).where(User.email == email))
    user = result.scalar_one()
    user.locked_until = datetime.now(tz=timezone.utc) + timedelta(hours=1)
    await db_session.commit()

    resp = await async_client.get(
        _PROTECTED_URL,
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert resp.status_code == 403
    assert resp.json()["detail"] == "Account is temporarily locked"


@pytest.mark.asyncio
async def test_locked_user_rejected_via_orm_fixture(
    async_client: AsyncClient,
    db_session: AsyncSession,
    fake_redis: object,
) -> None:
    """Locked user rejected via ORM fixture — ensures coverage.py
    can trace the locked_until branch."""
    from tests.helpers import make_orm_user

    user, access_token = await make_orm_user(
        db_session, fake_redis, "locked_orm@example.com"
    )
    user.locked_until = datetime.now(tz=timezone.utc) + timedelta(hours=1)
    await db_session.commit()

    resp = await async_client.get(
        _PROTECTED_URL,
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert resp.status_code == 403
    assert resp.json()["detail"] == "Account is temporarily locked"


@pytest.mark.asyncio
async def test_deactivated_user_rejected_via_orm_fixture(
    async_client: AsyncClient,
    db_session: AsyncSession,
    fake_redis: object,
) -> None:
    """Deactivated user rejected via ORM fixture — ensures coverage.py
    can trace the is_active=False branch."""
    from tests.helpers import make_orm_user

    user, access_token = await make_orm_user(
        db_session, fake_redis, "deactivated_orm@example.com"
    )
    user.is_active = False
    await db_session.commit()

    resp = await async_client.get(
        _PROTECTED_URL,
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert resp.status_code == 403
    assert resp.json()["detail"] == "Account is deactivated"
