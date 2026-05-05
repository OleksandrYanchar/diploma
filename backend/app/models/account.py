"""Account ORM model.

Defines the ``accounts`` table.  Each user may have one or more accounts.
All financial balance operations on this table must use ACID transactions to
prevent race conditions (SR-20).

Security properties:
- ``user_id`` FK enforces ownership; service-layer queries always filter by
  ``user_id = current_user.id`` (SR-12).
- ``balance`` uses ``Numeric(18, 2)`` to avoid floating-point representation
  errors in financial calculations.
"""

import enum
import secrets
import uuid
from datetime import datetime
from decimal import Decimal

from sqlalchemy import DateTime, Enum, ForeignKey, Numeric, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class AccountStatus(str, enum.Enum):
    """Lifecycle status of a financial account.

    ACTIVE   — normal operating state; transfers in/out are permitted.
    INACTIVE — account is closed or dormant; transfers are rejected (T-02 mitigation).
    FROZEN   — account is administratively locked pending review; transfers rejected.
    """

    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    FROZEN = "FROZEN"


def _generate_account_number() -> str:
    """Return a random 16-character uppercase hex account number."""
    return secrets.token_hex(8).upper()


class Account(Base):
    """Represents a financial account belonging to a user."""

    __tablename__ = "accounts"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        nullable=False,
    )

    # Human-readable unique account identifier used in transfer destinations.
    account_number: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        unique=True,
        default=_generate_account_number,
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )

    status: Mapped[AccountStatus] = mapped_column(
        Enum(AccountStatus, name="accountstatus"),
        nullable=False,
        default=AccountStatus.ACTIVE,
        server_default=AccountStatus.ACTIVE.value,
    )

    # Balance stored with 18 integer digits and 2 decimal places.
    balance: Mapped[Decimal] = mapped_column(
        Numeric(precision=18, scale=2),
        nullable=False,
        default=0,
    )

    # ISO 4217 currency code.
    currency: Mapped[str] = mapped_column(
        String(3),
        nullable=False,
        default="USD",
    )

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

    # Relationships
    user: Mapped["User"] = relationship(  # noqa: F821
        "User",
        back_populates="accounts",
        lazy="noload",
    )

    outgoing_transactions: Mapped[list["Transaction"]] = relationship(  # noqa: F821
        "Transaction",
        foreign_keys="Transaction.from_account_id",
        back_populates="from_account",
        lazy="noload",
    )

    incoming_transactions: Mapped[list["Transaction"]] = relationship(  # noqa: F821
        "Transaction",
        foreign_keys="Transaction.to_account_id",
        back_populates="to_account",
        lazy="noload",
    )

    def __repr__(self) -> str:
        return (
            f"<Account id={self.id} user_id={self.user_id} "
            f"balance={self.balance} {self.currency}>"
        )
