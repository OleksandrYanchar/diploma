"""Admin service — read-only queries for admin and auditor endpoints.

All functions perform SELECT-only operations; no user state is mutated here.
Mutating admin operations (activate, deactivate, role change) are deferred
to Phase 7 follow-up work.

Security properties:
- SR-11: Every caller is gated by ``require_role`` before reaching these
  functions.  Service functions do not re-check role authorisation.
- Results are ordered newest-first so the most recent events surface at the
  top of the default view without client-side sorting.
"""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_log import AuditLog
from app.models.security_event import SecurityEvent
from app.models.user import User


async def list_users(
    db: AsyncSession,
    limit: int,
    offset: int,
) -> list[User]:
    """Return a page of all users ordered by creation time, newest first.

    Intended for the ADMIN-only GET /admin/users endpoint.  Callers must
    hold the ADMIN role; this function does not re-check authorisation.

    Args:
        db:     Injected async database session.
        limit:  Maximum number of rows to return (caller-validated 1–200).
        offset: Number of rows to skip for offset-based paging.

    Returns:
        A list of User ORM instances with no lazy-loaded relationships.
    """
    result = await db.execute(
        select(User).order_by(User.created_at.desc()).limit(limit).offset(offset)
    )
    return list(result.scalars().all())


async def list_audit_logs(
    db: AsyncSession,
    limit: int,
    offset: int,
) -> list[AuditLog]:
    """Return a page of audit log entries ordered by creation time, newest first.

    Available to both ADMIN and AUDITOR roles.  Callers are gated by
    ``require_role`` before this function is reached.

    Args:
        db:     Injected async database session.
        limit:  Maximum number of rows to return (caller-validated 1–200).
        offset: Number of rows to skip for offset-based paging.

    Returns:
        A list of AuditLog ORM instances.
    """
    result = await db.execute(
        select(AuditLog)
        .order_by(AuditLog.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    return list(result.scalars().all())


async def list_security_events(
    db: AsyncSession,
    limit: int,
    offset: int,
) -> list[SecurityEvent]:
    """Return a page of security events ordered by creation time, newest first.

    Available to both ADMIN and AUDITOR roles.  Callers are gated by
    ``require_role`` before this function is reached.

    Args:
        db:     Injected async database session.
        limit:  Maximum number of rows to return (caller-validated 1–200).
        offset: Number of rows to skip for offset-based paging.

    Returns:
        A list of SecurityEvent ORM instances.
    """
    result = await db.execute(
        select(SecurityEvent)
        .order_by(SecurityEvent.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    return list(result.scalars().all())
