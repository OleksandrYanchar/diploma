"""RefreshToken ORM model.

Defines the ``refresh_tokens`` table.  This table stores SHA-256 hashes of
issued refresh tokens, never the raw token values.

Security properties:
- ``token_hash`` is the SHA-256 digest of the raw token (SR-07).  The raw
  token is generated in memory, returned to the client once, and never
  persisted.  If the database is compromised, raw tokens cannot be recovered
  from hashes.
- ``session_id`` links the token to the Redis session record, enabling
  immediate session invalidation on logout or password reset (SR-10).
- ``revoked`` is set to True on every use, enforcing rotation (SR-07) and
  enabling reuse detection (SR-08).
- ``expires_at`` caps the token lifetime independently of the revoked flag.
"""

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class RefreshToken(Base):
    """Stores metadata for issued refresh tokens."""

    __tablename__ = "refresh_tokens"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        nullable=False,
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    token_hash: Mapped[str] = mapped_column(
        String(64),  # SHA-256 produces a 64-character hex string
        unique=True,
        index=True,
        nullable=False,
    )

    session_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        index=True,
    )

    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    revoked: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    user: Mapped["User"] = relationship(  # noqa: F821
        "User",
        back_populates="refresh_tokens",
        lazy="noload",
    )

    def __repr__(self) -> str:
        return (
            f"<RefreshToken id={self.id} user_id={self.user_id} "
            f"revoked={self.revoked} expires_at={self.expires_at}>"
        )
