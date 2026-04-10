"""Pydantic schemas for Account resources.

Security properties:
- Response schemas never expose the ``user_id`` FK directly to regular users;
  the service layer enforces that a user can only see their own accounts (SR-12).
- ``balance`` is serialised as a string to preserve decimal precision across
  JSON serialisation boundaries (floating-point representation is lossy).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal

from pydantic import BaseModel, Field

from app.models.account import AccountStatus


class AccountResponse(BaseModel):
    """Public representation of an account returned to the owning user."""

    model_config = {"from_attributes": True}

    id: uuid.UUID
    account_number: str = Field(
        description="Unique account identifier used in transfers."
    )
    status: AccountStatus = Field(description="Lifecycle status of the account.")
    balance: Decimal = Field(description="Current account balance.")
    currency: str = Field(description="ISO 4217 currency code, e.g. 'USD'.")
    created_at: datetime
    updated_at: datetime


class AccountAdminView(AccountResponse):
    """Extended account view for admin/auditor roles.

    Includes the ``user_id`` FK so that an admin can correlate accounts to
    users without relying on the route parameter alone.
    """

    user_id: uuid.UUID
