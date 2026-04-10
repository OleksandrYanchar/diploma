"""Add email_verification_token_hash to users table.

Revision ID: 0003
Revises: 0002
Create Date: 2026-04-10

Adds a single nullable column to the ``users`` table to support the
email verification flow (SR-03):

- ``email_verification_token_hash`` (String 64, nullable) — stores the
  SHA-256 hex digest of the one-time verification token that is sent to
  the user on registration.  The raw token is never persisted; only its
  hash is stored so that a database read cannot be used to reconstruct a
  valid verification link.  The column is cleared (set to NULL) after
  successful verification.

Design decision: ``email_verification_sent_at`` is intentionally omitted
here.  That column will be added in Phase 6 alongside the re-send and
password-reset flows (ADR-15).  Migration 0003 adds exactly this one
column.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: Union[str, None] = "0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add email_verification_token_hash column to users."""

    op.add_column(
        "users",
        sa.Column(
            "email_verification_token_hash",
            sa.String(64),
            nullable=True,
        ),
    )


def downgrade() -> None:
    """Remove email_verification_token_hash column from users."""

    op.drop_column("users", "email_verification_token_hash")
