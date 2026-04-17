"""Admin router — Phase 4.

This module contains a single placeholder endpoint used as an RBAC test
anchor. Real admin functionality (audit log queries, user management,
security event views) is deferred to Phase 7.

Endpoints:
  GET /admin/ping — health check for admin-role access (SR-11).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from app.dependencies.auth import get_current_user, require_role, require_verified
from app.models.user import User, UserRole

router = APIRouter(prefix="/admin", tags=["admin"])


@router.get("/ping")
async def admin_ping(
    current_user: User = Depends(get_current_user),
    _verified: None = Depends(require_verified),
    _admin: None = Depends(require_role(UserRole.ADMIN)),
) -> dict[str, str]:
    """Admin liveness check. Requires a verified account with ADMIN role.

    Returns a minimal success payload. This endpoint exists solely to provide
    a real production route for RBAC integration tests (SR-11, T-09, T-10).
    No business logic is performed.

    Args:
        current_user: Authenticated ``User`` provided by ``get_current_user``.
                      All seven Zero Trust checks are enforced before this
                      handler is reached.
        _verified:    Side-effect dependency that raises 403 if the user's
                      email address is not verified (SR-03).
        _admin:       Side-effect dependency that raises 403 if the user's
                      role is not ADMIN (SR-11).

    Returns:
        A dict with ``status="ok"`` and the caller's role value.

    Raises:
        HTTPException 401/403: If the request is unauthenticated.
        HTTPException 403: If the user is not email-verified.
        HTTPException 403: If the user's role is not ADMIN.
    """
    return {"status": "ok", "role": current_user.role.value}
