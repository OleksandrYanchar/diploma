"""Pydantic schemas for Transaction resources.

Security properties:
- ``TransferRequest`` enforces a positive ``amount`` at the schema level
  (SR-20).  Additional threshold and balance checks happen in the service.
- ``TransferRequest`` accepts ``to_account_number`` (the public identifier)
  rather than an internal UUID, preventing IDOR enumeration (T-02).
- Response schemas do not expose account ownership details beyond what the
  requesting user already knows (their own account IDs).
"""

import uuid
from datetime import datetime
from decimal import Decimal

from pydantic import BaseModel, Field, field_validator

from app.models.transaction import TransactionStatus, TransactionType


class TransferRequest(BaseModel):
    """Request body for POST /transactions/transfer.

    ``from_account_id`` is not accepted from the client — it is derived from
    the authenticated user's account in the service layer (SR-12).

    ``to_account_number`` is the public account identifier (T-02 mitigation):
    the service layer resolves it to an internal account and enforces that the
    destination account is ACTIVE before executing the transfer.
    """

    to_account_number: str = Field(
        min_length=16,
        max_length=16,
        description=(
            "Public account number of the destination account. "
            "Account numbers are 16-character uppercase hex strings "
            "(generated as ``secrets.token_hex(8).upper()``). "
            "The service resolves this to an internal account and rejects "
            "transfers to INACTIVE or FROZEN accounts (T-02)."
        ),
    )
    amount: Decimal = Field(
        gt=0,
        description="Amount to transfer.  Must be a positive value greater than zero.",
    )
    description: str | None = Field(
        default=None,
        max_length=512,
        description="Optional human-readable note attached to the transaction.",
    )

    @field_validator("amount")
    @classmethod
    def amount_must_have_at_most_two_decimal_places(cls, value: Decimal) -> Decimal:
        """Reject amounts with more than 2 decimal places.

        Prevents precision issues and potential rounding exploits (SR-20).
        """
        if value != value.quantize(Decimal("0.01")):
            msg = "Amount must have at most 2 decimal places."
            raise ValueError(msg)
        return value


class TransactionResponse(BaseModel):
    """Representation of a completed or pending transaction."""

    model_config = {"from_attributes": True}

    id: uuid.UUID
    from_account_id: uuid.UUID | None
    to_account_id: uuid.UUID | None
    amount: Decimal
    transaction_type: TransactionType
    status: TransactionStatus
    description: str | None
    created_at: datetime


class TransactionHistoryResponse(BaseModel):
    """Paginated list of transactions for the requesting user's account."""

    items: list[TransactionResponse]
    total: int = Field(description="Total number of transactions matching the query.")
    page: int
    page_size: int
