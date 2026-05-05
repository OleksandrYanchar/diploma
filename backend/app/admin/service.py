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

import uuid

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_log import AuditLog
from app.models.security_event import SecurityEvent
from app.models.user import User, UserRole


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


async def unlock_user(
    db: AsyncSession,
    actor: User,
    user_id: uuid.UUID,
    ip_address: str | None,
) -> User:
    """Clear the lockout state of a target user (ADMIN action).

    Resets ``failed_login_count`` to 0 and ``locked_until`` to None.
    Emits an audit log entry for both success and failure outcomes.

    Raises:
        HTTPException 404: Target user does not exist.
    """
    result = await db.execute(select(User).where(User.id == user_id))
    target: User | None = result.scalar_one_or_none()

    if target is None:
        db.add(
            AuditLog(
                user_id=None,
                action="ADMIN_UNLOCK_USER",
                ip_address=ip_address,
                details={
                    "actor_id": str(actor.id),
                    "target_id": str(user_id),
                    "result": "failure",
                    "reason": "user_not_found",
                },
            )
        )
        await db.commit()
        raise HTTPException(status_code=404, detail="User not found")

    target.failed_login_count = 0
    target.locked_until = None
    db.add(
        AuditLog(
            user_id=target.id,
            action="ADMIN_UNLOCK_USER",
            ip_address=ip_address,
            details={"actor_id": str(actor.id), "result": "success"},
        )
    )
    await db.commit()
    await db.refresh(target)
    return target


async def activate_user(
    db: AsyncSession,
    actor: User,
    user_id: uuid.UUID,
    ip_address: str | None,
) -> User:
    """Set ``is_active = True`` on a target user (ADMIN action).

    Emits an audit log entry for both success and failure outcomes.

    Raises:
        HTTPException 404: Target user does not exist.
    """
    result = await db.execute(select(User).where(User.id == user_id))
    target: User | None = result.scalar_one_or_none()

    if target is None:
        db.add(
            AuditLog(
                user_id=None,
                action="ADMIN_ACTIVATE_USER",
                ip_address=ip_address,
                details={
                    "actor_id": str(actor.id),
                    "target_id": str(user_id),
                    "result": "failure",
                    "reason": "user_not_found",
                },
            )
        )
        await db.commit()
        raise HTTPException(status_code=404, detail="User not found")

    target.is_active = True
    db.add(
        AuditLog(
            user_id=target.id,
            action="ADMIN_ACTIVATE_USER",
            ip_address=ip_address,
            details={"actor_id": str(actor.id), "result": "success"},
        )
    )
    await db.commit()
    await db.refresh(target)
    return target


async def deactivate_user(
    db: AsyncSession,
    actor: User,
    user_id: uuid.UUID,
    ip_address: str | None,
) -> User:
    """Set ``is_active = False`` on a target user (ADMIN action).

    Emits an audit log entry for success, 404, and self-guard failure.

    Raises:
        HTTPException 404: Target user does not exist.
        HTTPException 403: Admin attempted to deactivate their own account.
    """
    result = await db.execute(select(User).where(User.id == user_id))
    target: User | None = result.scalar_one_or_none()

    if target is None:
        db.add(
            AuditLog(
                user_id=None,
                action="ADMIN_DEACTIVATE_USER",
                ip_address=ip_address,
                details={
                    "actor_id": str(actor.id),
                    "target_id": str(user_id),
                    "result": "failure",
                    "reason": "user_not_found",
                },
            )
        )
        await db.commit()
        raise HTTPException(status_code=404, detail="User not found")

    if actor.id == target.id:
        db.add(
            AuditLog(
                user_id=target.id,
                action="ADMIN_DEACTIVATE_USER",
                ip_address=ip_address,
                details={
                    "actor_id": str(actor.id),
                    "result": "failure",
                    "reason": "self_deactivation_blocked",
                },
            )
        )
        await db.commit()
        raise HTTPException(
            status_code=403,
            detail="Cannot deactivate your own account",
        )

    target.is_active = False
    db.add(
        AuditLog(
            user_id=target.id,
            action="ADMIN_DEACTIVATE_USER",
            ip_address=ip_address,
            details={"actor_id": str(actor.id), "result": "success"},
        )
    )
    await db.commit()
    await db.refresh(target)
    return target


async def change_user_role(
    db: AsyncSession,
    actor: User,
    user_id: uuid.UUID,
    new_role: UserRole,
    ip_address: str | None,
) -> User:
    """Change the role of a target user (ADMIN action).

    Audit log details include ``previous_role`` and ``new_role`` on success.

    Raises:
        HTTPException 404: Target user does not exist.
        HTTPException 403: Admin attempted to change their own role.
    """
    result = await db.execute(select(User).where(User.id == user_id))
    target: User | None = result.scalar_one_or_none()

    if target is None:
        db.add(
            AuditLog(
                user_id=None,
                action="ADMIN_ROLE_CHANGE",
                ip_address=ip_address,
                details={
                    "actor_id": str(actor.id),
                    "target_id": str(user_id),
                    "result": "failure",
                    "reason": "user_not_found",
                },
            )
        )
        await db.commit()
        raise HTTPException(status_code=404, detail="User not found")

    if actor.id == target.id:
        db.add(
            AuditLog(
                user_id=target.id,
                action="ADMIN_ROLE_CHANGE",
                ip_address=ip_address,
                details={
                    "actor_id": str(actor.id),
                    "result": "failure",
                    "reason": "self_role_change_blocked",
                },
            )
        )
        await db.commit()
        raise HTTPException(
            status_code=403,
            detail="Cannot change your own role",
        )

    previous_role = target.role.value
    target.role = new_role
    db.add(
        AuditLog(
            user_id=target.id,
            action="ADMIN_ROLE_CHANGE",
            ip_address=ip_address,
            details={
                "actor_id": str(actor.id),
                "previous_role": previous_role,
                "new_role": new_role.value,
                "result": "success",
            },
        )
    )
    await db.commit()
    await db.refresh(target)
    return target
