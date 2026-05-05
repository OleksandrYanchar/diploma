"""Add password reset token hash and sent_at timestamp columns to users.

Revision ID: 0005
Revises: 0004
Create Date: 2026-04-25

Adds three nullable columns to the ``users`` table to support the
password reset flow (Phase 6, SR-18) and email re-send rate limiting
(ADR-15):

- ``password_reset_token_hash`` (String 64, nullable) — stores the
  SHA-256 hex digest of the one-time password reset token.  The raw
  token is never persisted.  Cleared after successful reset.

- ``password_reset_sent_at`` (TIMESTAMPTZ, nullable) — records when the
  reset token was issued.  The service enforces a 30-minute validity
  window by comparing this value against the current UTC time (SR-18).

- ``email_verification_sent_at`` (TIMESTAMPTZ, nullable) — deferred from
  Phase 2 per ADR-15.  Records when the verification email was last
  dispatched so that a re-send rate limit can be enforced in Phase 6.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "0005"
down_revision: Union[str, None] = "0004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add password_reset_token_hash, password_reset_sent_at, email_verification_sent_at."""

    op.add_column(
        "users",
        sa.Column(
            "password_reset_token_hash",
            sa.String(64),
            nullable=True,
        ),
    )
    op.add_column(
        "users",
        sa.Column(
            "password_reset_sent_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "users",
        sa.Column(
            "email_verification_sent_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )


def downgrade() -> None:
    """Remove the three password-reset and re-send timestamp columns."""

    op.drop_column("users", "email_verification_sent_at")
    op.drop_column("users", "password_reset_sent_at")
    op.drop_column("users", "password_reset_token_hash")
