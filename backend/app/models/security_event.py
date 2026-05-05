"""SecurityEvent ORM model and Severity enum.

Defines the ``security_events`` table.  Security events represent detected
anomalies or attacks, as opposed to audit logs which record all actions.

Security properties:
- Events are append-only; they are never modified after creation (SR-17).
- ``severity`` categorises the urgency of the event to support triage.
- ``user_id`` is nullable for events involving unidentified actors.
- ``details`` stores structured JSON for machine-readable correlation.

Defined event types (added as string constants, not an enum, for extensibility):
  BRUTE_FORCE, ACCOUNT_LOCKED, TOKEN_REUSE, STEP_UP_BYPASS_ATTEMPT,
  RATE_LIMIT_EXCEEDED, SUSPICIOUS_LOGIN.
"""

import enum
import uuid
from datetime import datetime

from sqlalchemy import JSON, DateTime, Enum, ForeignKey, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class Severity(str, enum.Enum):
    """Severity classification for security events.

    Levels correspond to NIST threat severity vocabulary and are used to
    prioritise investigation by the admin/auditor role.
    """

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class SecurityEvent(Base):
    """Records a detected security anomaly or attack indicator."""

    __tablename__ = "security_events"

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

    event_type: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        index=True,
    )

    severity: Mapped[Severity] = mapped_column(
        Enum(Severity, name="severity"),
        nullable=False,
        index=True,
    )

    ip_address: Mapped[str | None] = mapped_column(
        String(45),
        nullable=True,
    )

    # SQLAlchemy JSON type is used here for SQLite test compatibility.
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
        back_populates="security_events",
        lazy="noload",
    )

    def __repr__(self) -> str:
        return (
            f"<SecurityEvent id={self.id} type={self.event_type} "
            f"severity={self.severity} user_id={self.user_id}>"
        )
