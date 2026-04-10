"""User ORM model and UserRole enum.

Defines the ``users`` table.  This model is the central identity record for
the system.  All other models that carry a user context reference this table
via foreign key.

Security properties:
- ``hashed_password`` stores the Argon2id hash only — never plaintext (SR-02).
- ``failed_login_count`` and ``locked_until`` support account lockout (SR-05).
- ``is_verified`` gates access to protected endpoints until email verification
  is complete (SR-03).
- ``mfa_secret`` is nullable; it is only populated during TOTP enrollment and
  is never returned to the client after the initial setup response (SR-04).
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Enum, Integer, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class UserRole(str, enum.Enum):
    """Role assigned to a user account.

    Three roles are defined per SR-11 (RBAC):
    - ``user``: standard customer account; can view own accounts and initiate
      transfers.
    - ``auditor``: read-only access to audit logs and security events; cannot
      modify user state.
    - ``admin``: full access including user management and security event
      querying.
    """

    USER = "user"
    AUDITOR = "auditor"
    ADMIN = "admin"


class User(Base):
    """Represents a registered user of the financial platform."""

    __tablename__ = "users"

    # Primary key: UUID v4, generated server-side to avoid enumerable IDs.
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        nullable=False,
    )

    # Unique email address used for login and verification.
    email: Mapped[str] = mapped_column(
        String(320),  # RFC 5321 maximum email length
        unique=True,
        index=True,
        nullable=False,
    )

    # Argon2id hash of the user's password.  Raw password is NEVER stored.
    hashed_password: Mapped[str] = mapped_column(
        String(1024),
        nullable=False,
    )

    # RBAC role.  Defaults to USER (least privilege).
    role: Mapped[UserRole] = mapped_column(
        Enum(UserRole, name="userrole"),
        nullable=False,
        default=UserRole.USER,
    )

    # Soft-delete / deactivation flag.  Deactivated users cannot log in.
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
    )

    # Email verification status (SR-03).
    is_verified: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
    )

    # MFA state (SR-04).
    mfa_enabled: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
    )

    # Base32-encoded TOTP secret.  Null until MFA enrollment is completed.
    # In production this should be encrypted at rest.
    mfa_secret: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        default=None,
    )

    # Consecutive failed login count for account lockout (SR-05).
    failed_login_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )

    # Timestamp until which the account is locked.  Null means not locked.
    locked_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        default=None,
    )

    # Audit timestamps.
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    # Relationships — defined here for ORM convenience; not loaded eagerly.
    accounts: Mapped[list["Account"]] = relationship(  # noqa: F821
        "Account",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="noload",
    )

    refresh_tokens: Mapped[list["RefreshToken"]] = relationship(  # noqa: F821
        "RefreshToken",
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="noload",
    )

    audit_logs: Mapped[list["AuditLog"]] = relationship(  # noqa: F821
        "AuditLog",
        back_populates="user",
        lazy="noload",
    )

    security_events: Mapped[list["SecurityEvent"]] = relationship(  # noqa: F821
        "SecurityEvent",
        back_populates="user",
        lazy="noload",
    )

    def __repr__(self) -> str:
        return f"<User id={self.id} email={self.email} role={self.role}>"
