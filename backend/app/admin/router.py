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

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.admin import service
from app.core.database import get_db
from app.dependencies.auth import get_current_user, require_role, require_verified
from app.models.user import User, UserRole
from app.schemas.admin import AuditLogResponse, SecurityEventResponse
from app.schemas.user import UserAdminView

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
