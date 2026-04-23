"""Enforce one-account-per-user uniqueness on accounts.user_id.

Revision ID: 0004
Revises: 0003
Create Date: 2026-04-18

Replaces the plain ``ix_accounts_user_id`` index with a unique index so that
the database itself rejects a second account row for the same user.

Without this constraint, two concurrent requests arriving before either has
committed could both pass a service-layer "select then insert" check and
produce duplicate rows.  The unique index makes the DB the final authority:
the second INSERT raises IntegrityError, which the accounts service catches
and converts into a re-fetch of the row already committed by the first writer.

The old index is dropped first because PostgreSQL does not support converting
a non-unique index to a unique one in-place.
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "0004"
down_revision: Union[str, None] = "0003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Drop the plain user_id index and replace it with a unique index."""

    op.drop_index("ix_accounts_user_id", table_name="accounts")
    op.create_index(
        "uq_accounts_user_id",
        "accounts",
        ["user_id"],
        unique=True,
    )


def downgrade() -> None:
    """Restore the plain (non-unique) user_id index."""

    op.drop_index("uq_accounts_user_id", table_name="accounts")
    op.create_index("ix_accounts_user_id", "accounts", ["user_id"])
