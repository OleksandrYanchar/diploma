"""Transaction ORM model and related enums.

Defines the ``transactions`` table.  Each row represents a single financial
movement: a transfer between accounts, a deposit, or a withdrawal.

Security properties:
- Transactions are immutable once written; there is no update path in the
  service layer (append-only financial record).
- ``from_account_id`` and ``to_account_id`` are both FK-validated, preventing
  references to non-existent accounts.
- ``amount`` uses Numeric to avoid floating-point errors (SR-20).
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime
from decimal import Decimal

from sqlalchemy import DateTime, Enum, ForeignKey, Numeric, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class TransactionType(str, enum.Enum):
    """Classifies the direction and nature of a financial movement."""

    TRANSFER = "transfer"
    DEPOSIT = "deposit"
    WITHDRAWAL = "withdrawal"


class TransactionStatus(str, enum.Enum):
    """Lifecycle status of a transaction record."""

    PENDING = "pending"
    COMPLETED = "completed"
    FAILED = "failed"


class Transaction(Base):
    """Represents a single financial transaction."""

    __tablename__ = "transactions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        nullable=False,
    )

    # Source account.  Null for deposits (external source).
    from_account_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("accounts.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # Destination account.  Null for withdrawals (external destination).
    to_account_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("accounts.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # Transfer amount.  Must be positive; validated at the schema layer (SR-20).
    amount: Mapped[Decimal] = mapped_column(
        Numeric(precision=18, scale=2),
        nullable=False,
    )

    transaction_type: Mapped[TransactionType] = mapped_column(
        Enum(
            TransactionType,
            name="transactiontype",
            values_callable=lambda obj: [e.value for e in obj],
        ),
        nullable=False,
    )

    status: Mapped[TransactionStatus] = mapped_column(
        Enum(
            TransactionStatus,
            name="transactionstatus",
            values_callable=lambda obj: [e.value for e in obj],
        ),
        nullable=False,
        default=TransactionStatus.PENDING,
    )

    # Optional human-readable note.  Never used for business logic decisions.
    description: Mapped[str | None] = mapped_column(
        String(512),
        nullable=True,
        default=None,
    )

    # Immutable creation timestamp.
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    # Relationships
    from_account: Mapped["Account | None"] = relationship(  # noqa: F821
        "Account",
        foreign_keys=[from_account_id],
        back_populates="outgoing_transactions",
        lazy="noload",
    )

    to_account: Mapped["Account | None"] = relationship(  # noqa: F821
        "Account",
        foreign_keys=[to_account_id],
        back_populates="incoming_transactions",
        lazy="noload",
    )

    def __repr__(self) -> str:
        return (
            f"<Transaction id={self.id} type={self.transaction_type} "
            f"amount={self.amount} status={self.status}>"
        )
