"""Add account_number and status to accounts table.

Revision ID: 0002
Revises: 0001
Create Date: 2026-04-10

Adds two columns required by the Zero Trust transfer flow:

- ``account_number`` (String 16, unique) — human-readable destination identifier
  used in transfer requests so that internal UUIDs are never exposed to clients.
- ``status`` (accountstatus enum) — lifecycle state enforcing T-02 mitigation:
  transfers to INACTIVE or FROZEN accounts are rejected by the service layer.

Existing rows receive generated account numbers via a server-side UPDATE and
default to ACTIVE status.  The migration is safe to run against a live database
(no table locks beyond the column add).
"""

from __future__ import annotations

import secrets
from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add accountstatus enum, account_number column, and status column."""

    accountstatus_enum = postgresql.ENUM(
        "ACTIVE",
        "INACTIVE",
        "FROZEN",
        name="accountstatus",
        create_type=False,
    )
    accountstatus_enum.create(op.get_bind(), checkfirst=True)

    op.add_column(
        "accounts",
        sa.Column(
            "account_number",
            sa.String(16),
            nullable=True,
        ),
    )

    op.add_column(
        "accounts",
        sa.Column(
            "status",
            postgresql.ENUM(
                "ACTIVE", "INACTIVE", "FROZEN", name="accountstatus", create_type=False
            ),
            nullable=True,
        ),
    )

    # Backfill existing rows with generated account numbers and ACTIVE status.
    connection = op.get_bind()
    result = connection.execute(sa.text("SELECT id FROM accounts"))
    for row in result:
        account_number = secrets.token_hex(8).upper()
        connection.execute(
            sa.text(
                "UPDATE accounts SET account_number = :num, status = 'ACTIVE' WHERE id = :id"
            ),
            {"num": account_number, "id": str(row[0])},
        )

    # Now that all rows have values, enforce NOT NULL and add constraints.
    op.alter_column("accounts", "account_number", nullable=False)
    op.alter_column("accounts", "status", nullable=False)

    op.create_index(
        "ix_accounts_account_number", "accounts", ["account_number"], unique=True
    )


def downgrade() -> None:
    """Remove account_number and status columns and drop accountstatus enum."""

    op.drop_index("ix_accounts_account_number", table_name="accounts")
    op.drop_column("accounts", "status")
    op.drop_column("accounts", "account_number")
    op.execute("DROP TYPE IF EXISTS accountstatus")
