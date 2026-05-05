"""Integration tests for the ``require_step_up`` dependency.

A test-only FastAPI router is mounted inside this module to expose a minimal
protected endpoint (GET /test/step-up-check) that declares ``require_step_up``
as a dependency.  This is the most reliable approach for this codebase: it
tests the dependency through the full ASGI stack with real dependency injection,
rather than calling the function directly with mocked arguments.

The test router is included in the application inside the ``async_client``
fixture and removed after every test via ``app.dependency_overrides.clear()``.
Cleanup is handled by the existing conftest infrastructure — the test router
must be removed from ``app.routes`` after each test to prevent bleed.
"""

import uuid

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_step_up_token
from app.dependencies.step_up import require_step_up
from app.main import app
from app.models.audit_log import AuditLog
from tests.conftest import _TEST_SETTINGS
from tests.helpers import make_orm_user

_test_step_up_router = APIRouter()


@_test_step_up_router.get("/test/step-up-check")
async def _step_up_check_endpoint(
    _step_up: None = Depends(require_step_up),
) -> JSONResponse:
    """Minimal protected endpoint used exclusively in require_step_up tests."""
    return JSONResponse({"ok": True})


app.include_router(_test_step_up_router, prefix="/api/v1")

_PROTECTED_URL = "/api/v1/test/step-up-check"


async def _make_user_with_step_up_token(
    db: AsyncSession,
    redis: object,
    email: str,
) -> tuple[str, str, str]:
    """Create a verified user, issue a step-up token, seed Redis.
    Returns (access_token, step_up_token, jti)."""
    user, access_token = await make_orm_user(db, redis, email=email)

    step_up_token, jti = create_step_up_token(
        subject=str(user.id),
        settings=_TEST_SETTINGS,
    )

    await redis.set(f"step_up:{jti}", str(user.id), ex=300)  # type: ignore[union-attr]

    return access_token, step_up_token, jti


async def test_require_step_up_missing_header(
    async_client: AsyncClient,
    db_session: AsyncSession,
    fake_redis: object,
) -> None:
    """No X-Step-Up-Token header → 403 with
    X-Step-Up-Required: true response header (SR-13)."""
    _, access_token = await make_orm_user(
        db_session,
        fake_redis,
        email=f"step_up_missing_{uuid.uuid4()}@example.com",
    )

    response = await async_client.get(
        _PROTECTED_URL,
        headers={"Authorization": f"Bearer {access_token}"},
    )

    assert response.status_code == 403
    assert response.headers.get("x-step-up-required") == "true", (
        "X-Step-Up-Required: true must be present in the 403 response so "
        "the client can identify this as a step-up gate rejection."
    )


async def test_require_step_up_invalid_token(
    async_client: AsyncClient,
    db_session: AsyncSession,
    fake_redis: object,
) -> None:
    """Malformed step-up token string → 403 (SR-13)."""
    _, access_token = await make_orm_user(
        db_session,
        fake_redis,
        email=f"step_up_invalid_{uuid.uuid4()}@example.com",
    )

    response = await async_client.get(
        _PROTECTED_URL,
        headers={
            "Authorization": f"Bearer {access_token}",
            "X-Step-Up-Token": "this.is.not.a.valid.jwt",
        },
    )

    assert response.status_code == 403
    assert "invalid" in response.json()["detail"].lower()


async def test_require_step_up_access_token_rejected_as_step_up(
    async_client: AsyncClient,
    db_session: AsyncSession,
    fake_redis: object,
) -> None:
    """Access token submitted as step-up token is rejected
    — typ mismatch prevents token confusion (SR-13, SR-14)."""
    _, access_token = await make_orm_user(
        db_session,
        fake_redis,
        email=f"step_up_type_confusion_{uuid.uuid4()}@example.com",
    )

    response = await async_client.get(
        _PROTECTED_URL,
        headers={
            "Authorization": f"Bearer {access_token}",
            "X-Step-Up-Token": access_token,
        },
    )

    assert response.status_code == 403


async def test_require_step_up_sub_mismatch(
    async_client: AsyncClient,
    db_session: AsyncSession,
    fake_redis: object,
) -> None:
    """Step-up token for user A presented by user B → 403;
    STEP_UP_BYPASS_ATTEMPT audit committed (SR-13, SR-16)."""
    user_a, _access_token_a = await make_orm_user(
        db_session,
        fake_redis,
        email=f"step_up_user_a_{uuid.uuid4()}@example.com",
    )

    step_up_token_for_a, jti_a = create_step_up_token(
        subject=str(user_a.id),
        settings=_TEST_SETTINGS,
    )
    await fake_redis.set(f"step_up:{jti_a}", str(user_a.id), ex=300)  # type: ignore[union-attr]

    _user_b, access_token_b = await make_orm_user(
        db_session,
        fake_redis,
        email=f"step_up_user_b_{uuid.uuid4()}@example.com",
        session_id="00000000-0000-0000-0000-200000000002",
    )

    response = await async_client.get(
        _PROTECTED_URL,
        headers={
            "Authorization": f"Bearer {access_token_b}",
            "X-Step-Up-Token": step_up_token_for_a,
        },
    )

    assert response.status_code == 403
    assert "mismatch" in response.json()["detail"].lower()

    result = await db_session.execute(
        select(AuditLog).where(AuditLog.action == "STEP_UP_BYPASS_ATTEMPT")
    )
    audit = result.scalars().first()
    assert audit is not None, (
        "STEP_UP_BYPASS_ATTEMPT audit log must be committed before raising "
        "the HTTPException so the event survives even if the transaction "
        "is later rolled back by the caller."
    )
    assert audit.details is not None
    assert audit.details.get("reason") == "subject_mismatch"


async def test_require_step_up_already_consumed(
    async_client: AsyncClient,
    db_session: AsyncSession,
    fake_redis: object,
) -> None:
    """Valid step-up JWT but Redis key absent → 403
    — simulates already-consumed token (SR-14)."""
    user, access_token = await make_orm_user(
        db_session,
        fake_redis,
        email=f"step_up_consumed_{uuid.uuid4()}@example.com",
    )

    step_up_token, _jti = create_step_up_token(
        subject=str(user.id),
        settings=_TEST_SETTINGS,
    )
    # Redis key intentionally not seeded — simulates an already-consumed token.

    response = await async_client.get(
        _PROTECTED_URL,
        headers={
            "Authorization": f"Bearer {access_token}",
            "X-Step-Up-Token": step_up_token,
        },
    )

    assert response.status_code == 403
    assert "already been used" in response.json()["detail"].lower()


async def test_require_step_up_valid(
    async_client: AsyncClient,
    db_session: AsyncSession,
    fake_redis: object,
) -> None:
    """Valid token + correct user + Redis key present → 200;
    Redis key atomically deleted (SR-13, SR-14)."""
    access_token, step_up_token, jti = await _make_user_with_step_up_token(
        db_session,
        fake_redis,
        email=f"step_up_valid_{uuid.uuid4()}@example.com",
    )

    pre_val = await fake_redis.get(f"step_up:{jti}")  # type: ignore[union-attr]
    assert pre_val is not None, "Redis key must exist before the step-up gate is hit"

    response = await async_client.get(
        _PROTECTED_URL,
        headers={
            "Authorization": f"Bearer {access_token}",
            "X-Step-Up-Token": step_up_token,
        },
    )

    assert response.status_code == 200
    assert response.json() == {"ok": True}

    post_val = await fake_redis.get(f"step_up:{jti}")  # type: ignore[union-attr]
    assert post_val is None, (
        f"Redis key step_up:{jti} must be deleted after first consumption. "
        "A second request with the same token must be rejected."
    )


async def test_require_step_up_second_use_rejected(
    async_client: AsyncClient,
    db_session: AsyncSession,
    fake_redis: object,
) -> None:
    """First use succeeds; second use of the same token returns 403
    — single-use end-to-end (SR-14)."""
    access_token, step_up_token, jti = await _make_user_with_step_up_token(
        db_session,
        fake_redis,
        email=f"step_up_reuse_{uuid.uuid4()}@example.com",
    )

    headers = {
        "Authorization": f"Bearer {access_token}",
        "X-Step-Up-Token": step_up_token,
    }

    first = await async_client.get(_PROTECTED_URL, headers=headers)
    assert first.status_code == 200

    second = await async_client.get(_PROTECTED_URL, headers=headers)
    assert second.status_code == 403
    assert "already been used" in second.json()["detail"].lower()
