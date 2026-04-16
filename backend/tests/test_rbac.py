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

import pytest
from fastapi import HTTPException
from httpx import AsyncClient

from app.dependencies.auth import require_role
from app.models.user import UserRole

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
