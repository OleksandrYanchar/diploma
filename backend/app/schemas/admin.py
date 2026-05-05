"""Pydantic response schemas for admin and auditor endpoints.

Security properties:
- ``AuditLogResponse`` exposes only the fields stored in the ``audit_logs``
  table.  The table contains no credentials or secrets; all columns are safe
  to expose to admin/auditor callers.
- ``SecurityEventResponse`` similarly exposes only event metadata.  Neither
  schema includes raw user credentials, hashed passwords, or token material.
- Admin-facing user schema (``UserAdminView``) lives in ``schemas/user.py``
  alongside all other user-related schemas.
"""

import uuid
from datetime import datetime

from pydantic import BaseModel

from app.models.security_event import Severity


class AuditLogResponse(BaseModel):
    """Admin/auditor view of a single audit log entry (SR-16)."""

    model_config = {"from_attributes": True}

    id: uuid.UUID
    user_id: uuid.UUID | None
    action: str
    ip_address: str | None
    user_agent: str | None
    details: dict | None  # type: ignore[type-arg]
    created_at: datetime


class SecurityEventResponse(BaseModel):
    """Admin/auditor view of a single security event record (SR-17)."""

    model_config = {"from_attributes": True}

    id: uuid.UUID
    user_id: uuid.UUID | None
    event_type: str
    severity: Severity
    ip_address: str | None
    details: dict | None  # type: ignore[type-arg]
    created_at: datetime
