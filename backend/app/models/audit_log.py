"""AuditLog ORM model.

Defines the ``audit_logs`` table.  Every security-relevant action produces an
audit log entry covering both success and failure outcomes.

Security properties:
- Audit log entries are append-only; there is no update or delete path in the
  service layer (SR-16).
- ``user_id`` is nullable to allow logging unauthenticated events (e.g., a
  failed login attempt where the user cannot be identified).
- ``ip_address`` and ``user_agent`` are recorded for forensic traceability.
- ``details`` is a JSON field for structured, action-specific metadata.
"""

import uuid
from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class AuditLog(Base):
    """Records security-relevant actions performed by or on behalf of users."""

    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        nullable=False,
    )

    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # Kept as astring rather than an enum to allow new types without migrations
    action: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        index=True,
    )

    ip_address: Mapped[str | None] = mapped_column(
        String(45),  # IPv6 max length
        nullable=True,
    )

    # Raw User-Agent header for browser/client fingerprinting.
    user_agent: Mapped[str | None] = mapped_column(
        String(512),
        nullable=True,
    )

    # Structured JSON payload; content is action-dependent.
    # The Alembic migration renders this as JSONB in PostgreSQL.
    details: Mapped[dict | None] = mapped_column(
        JSON,
        nullable=True,
        default=None,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        index=True,
    )

    user: Mapped["User | None"] = relationship(  # noqa: F821
        "User",
        back_populates="audit_logs",
        lazy="noload",
    )

    def __repr__(self) -> str:
        return f"<AuditLog id={self.id} action={self.action} user_id={self.user_id}>"
