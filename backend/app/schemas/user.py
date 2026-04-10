"""Pydantic schemas for User resources.

These schemas define the contract between the HTTP layer and the service layer
for user-related data.  They are separate from the SQLAlchemy ``User`` model
in ``app/models/user.py``.

Security properties:
- ``hashed_password`` is never included in any response schema — the ORM
  model's field is excluded at the serialization boundary (SR-02).
- ``mfa_secret`` is never included in any response schema (SR-04).
- ``UserCreate`` enforces password presence at the input boundary; strength
  validation is applied in the service layer (SR-01).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, EmailStr, Field

from app.models.user import UserRole


class UserCreate(BaseModel):
    """Request body for user registration.

    Password strength validation (SR-01) is applied in ``auth/service.py``,
    not here, because the strength rules are a security policy decision rather
    than a schema-level constraint.  The schema ensures the field is present
    and non-empty.
    """

    email: EmailStr = Field(
        description="Valid email address used for login and verification.",
    )
    password: str = Field(
        min_length=12,
        description=(
            "User password. Must meet strength requirements "
            "enforced by the service layer."
        ),
    )


class UserResponse(BaseModel):
    """Public representation of a user returned to the authenticated subject.

    Sensitive fields (``hashed_password``, ``mfa_secret``) are absent (SR-02,
    SR-04).  Internal security state (``failed_login_count``, ``locked_until``)
    is also excluded — exposing lockout state to the subject leaks information
    about ongoing brute-force activity against their account.
    """

    model_config = {"from_attributes": True}

    id: uuid.UUID
    email: str
    role: UserRole
    is_active: bool
    is_verified: bool
    mfa_enabled: bool
    created_at: datetime
    updated_at: datetime


class UserUpdateRole(BaseModel):
    """Request body for an admin changing a user's role."""

    role: UserRole = Field(description="New role to assign to the target user.")


class UserAdminView(UserResponse):
    """Extended user view available to admin and auditor roles only.

    Adds internal security state fields that must not be exposed to regular
    users: ``failed_login_count`` reveals ongoing brute-force attempts;
    ``locked_until`` reveals the exact lockout expiry.
    """

    failed_login_count: int
    locked_until: datetime | None
