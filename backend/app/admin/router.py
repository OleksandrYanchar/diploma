"""Admin router — Phase 7 read-only endpoints.

Implements read-only admin and auditor endpoints for user inspection, audit
log querying, and security event querying.  Mutating admin endpoints
(activate, deactivate, role change) are Phase 7 follow-up work.

All endpoints require a verified email address (``require_verified``, SR-03).

Security properties:
- Response schemas explicitly exclude sensitive fields: ``hashed_password``,
  ``mfa_secret``, ``email_verification_token_hash``,
  ``password_reset_token_hash``, ``password_reset_sent_at`` (SR-02, SR-04).
- Pagination uses caller-supplied ``limit`` (1–200) and ``offset`` (≥ 0)
  query parameters; defaults are 50 and 0 respectively.
"""

import uuid

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.admin import service
from app.core.database import get_db
from app.dependencies.auth import get_current_user, require_role, require_verified
from app.models.user import User, UserRole
from app.schemas.admin import AuditLogResponse, SecurityEventResponse
from app.schemas.user import UserAdminView, UserUpdateRole

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

    Returns:
        A dict with ``status="ok"`` and the caller's role value.

    Raises:
        HTTPException 401/403: If the request is unauthenticated.
        HTTPException 403: If the user is not email-verified.
        HTTPException 403: If the user's role is not ADMIN.
    """
    return {"status": "ok", "role": current_user.role.value}


@router.get(
    "/users",
    response_model=list[UserAdminView],
    status_code=200,
    summary="List all users with security metadata (ADMIN only)",
)
async def list_users(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    _current_user: User = Depends(get_current_user),
    _verified: None = Depends(require_verified),
    _admin: None = Depends(require_role(UserRole.ADMIN)),
    db: AsyncSession = Depends(get_db),
) -> list[UserAdminView]:
    """Return all registered users with admin-relevant security metadata.

    Exposes ``failed_login_count`` and ``locked_until`` (via
    ``UserAdminView``) so admins can identify and respond to ongoing
    brute-force attempts.  Sensitive fields (``hashed_password``,
    ``mfa_secret``, token hashes) are excluded from the response schema.

    Restricted to ADMIN role — auditors must not see aggregate user
    security state such as failed login counts across all accounts.

    Returns:
        A list of ``UserAdminView`` objects.

    Raises:
        HTTPException 401/403: Unauthenticated, unverified, or wrong role.
        HTTPException 422: ``limit`` or ``offset`` outside allowed range.
    """
    users = await service.list_users(db=db, limit=limit, offset=offset)
    return [UserAdminView.model_validate(u) for u in users]


@router.get(
    "/audit-logs",
    response_model=list[AuditLogResponse],
    status_code=200,
    summary="List audit log entries (ADMIN or AUDITOR)",
)
async def list_audit_logs(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    _current_user: User = Depends(get_current_user),
    _verified: None = Depends(require_verified),
    _role: None = Depends(require_role(UserRole.ADMIN, UserRole.AUDITOR)),
    db: AsyncSession = Depends(get_db),
) -> list[AuditLogResponse]:
    """Return audit log entries ordered newest-first.

    Accessible to both ADMIN and AUDITOR roles (SR-11).  The audit log
    table contains no secrets — all columns (action, ip_address,
    user_agent, details, user_id) are safe to expose to authorised callers.

    Returns:
        A list of ``AuditLogResponse`` objects.

    Raises:
        HTTPException 401/403: Unauthenticated, unverified, or wrong role.
        HTTPException 422: ``limit`` or ``offset`` outside allowed range.
    """
    logs = await service.list_audit_logs(db=db, limit=limit, offset=offset)
    return [AuditLogResponse.model_validate(log) for log in logs]


@router.get(
    "/security-events",
    response_model=list[SecurityEventResponse],
    status_code=200,
    summary="List security events (ADMIN or AUDITOR)",
)
async def list_security_events(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    _current_user: User = Depends(get_current_user),
    _verified: None = Depends(require_verified),
    _role: None = Depends(require_role(UserRole.ADMIN, UserRole.AUDITOR)),
    db: AsyncSession = Depends(get_db),
) -> list[SecurityEventResponse]:
    """Return security event records ordered newest-first.

    Accessible to both ADMIN and AUDITOR roles (SR-11).  Security event
    records contain anomaly metadata (event type, severity, IP address,
    details) — no user credentials or secret material.

    Returns:
        A list of ``SecurityEventResponse`` objects.

    Raises:
        HTTPException 401/403: Unauthenticated, unverified, or wrong role.
        HTTPException 422: ``limit`` or ``offset`` outside allowed range.
    """
    events = await service.list_security_events(db=db, limit=limit, offset=offset)
    return [SecurityEventResponse.model_validate(event) for event in events]


@router.post(
    "/users/{user_id}/unlock",
    response_model=UserAdminView,
    status_code=200,
    summary="Unlock a user account (ADMIN only)",
)
async def unlock_user(
    user_id: uuid.UUID,
    request: Request,
    current_user: User = Depends(get_current_user),
    _verified: None = Depends(require_verified),
    _admin: None = Depends(require_role(UserRole.ADMIN)),
    db: AsyncSession = Depends(get_db),
) -> UserAdminView:
    """Reset ``failed_login_count`` and ``locked_until`` on the target user.

    Raises:
        HTTPException 401/403: Unauthenticated, unverified, or wrong role.
        HTTPException 404: Target user does not exist.
    """
    ip = request.client.host if request.client else None
    user = await service.unlock_user(
        db=db, actor=current_user, user_id=user_id, ip_address=ip
    )
    return UserAdminView.model_validate(user)


@router.patch(
    "/users/{user_id}/activate",
    response_model=UserAdminView,
    status_code=200,
    summary="Activate a user account (ADMIN only)",
)
async def activate_user(
    user_id: uuid.UUID,
    request: Request,
    current_user: User = Depends(get_current_user),
    _verified: None = Depends(require_verified),
    _admin: None = Depends(require_role(UserRole.ADMIN)),
    db: AsyncSession = Depends(get_db),
) -> UserAdminView:
    """Set ``is_active = True`` on the target user.

    Raises:
        HTTPException 401/403: Unauthenticated, unverified, or wrong role.
        HTTPException 404: Target user does not exist.
    """
    ip = request.client.host if request.client else None
    user = await service.activate_user(
        db=db, actor=current_user, user_id=user_id, ip_address=ip
    )
    return UserAdminView.model_validate(user)


@router.patch(
    "/users/{user_id}/deactivate",
    response_model=UserAdminView,
    status_code=200,
    summary="Deactivate a user account (ADMIN only)",
)
async def deactivate_user(
    user_id: uuid.UUID,
    request: Request,
    current_user: User = Depends(get_current_user),
    _verified: None = Depends(require_verified),
    _admin: None = Depends(require_role(UserRole.ADMIN)),
    db: AsyncSession = Depends(get_db),
) -> UserAdminView:
    """Set ``is_active = False`` on the target user.

    Raises:
        HTTPException 401/403: Unauthenticated, unverified, or wrong role.
        HTTPException 403: Admin attempted to deactivate their own account.
        HTTPException 404: Target user does not exist.
    """
    ip = request.client.host if request.client else None
    user = await service.deactivate_user(
        db=db, actor=current_user, user_id=user_id, ip_address=ip
    )
    return UserAdminView.model_validate(user)


@router.patch(
    "/users/{user_id}/role",
    response_model=UserAdminView,
    status_code=200,
    summary="Change a user's role (ADMIN only)",
)
async def change_user_role(
    user_id: uuid.UUID,
    body: UserUpdateRole,
    request: Request,
    current_user: User = Depends(get_current_user),
    _verified: None = Depends(require_verified),
    _admin: None = Depends(require_role(UserRole.ADMIN)),
    db: AsyncSession = Depends(get_db),
) -> UserAdminView:
    """Change the role of the target user.

    Invalid role values are rejected by Pydantic (422). Audit log includes
    the previous and new role on success.

    Raises:
        HTTPException 401/403: Unauthenticated, unverified, or wrong role.
        HTTPException 403: Admin attempted to change their own role.
        HTTPException 404: Target user does not exist.
        HTTPException 422: ``role`` value is not a valid ``UserRole``.
    """
    ip = request.client.host if request.client else None
    user = await service.change_user_role(
        db=db,
        actor=current_user,
        user_id=user_id,
        new_role=body.role,
        ip_address=ip,
    )
    return UserAdminView.model_validate(user)
