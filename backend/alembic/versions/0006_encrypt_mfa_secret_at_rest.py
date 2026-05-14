"""Widen mfa_secret column and invalidate legacy plaintext secrets.

Revision ID: 0006
Revises: 0005
Create Date: 2026-05-11

Implements TD-09 (TOTP secret stored encrypted at rest, SR-04).

Schema change:
    ``users.mfa_secret`` is widened from String(64) to String(255) so it
    can store Fernet ciphertext (~140 chars) in addition to the legacy
    Base32 secret (32 chars).

Data change:
    All existing rows with a non-null ``mfa_secret`` are invalidated:
    ``mfa_secret`` is set to NULL and ``mfa_enabled`` is set to false.
    These rows contained plaintext Base32 secrets which are incompatible
    with the new encrypted storage format — the application would raise
    ``InvalidToken`` on any attempt to decrypt them.

    Affected users must re-enroll MFA after this migration runs.  In
    development and test environments this is the expected behaviour; the
    test suite uses fresh, in-memory SQLite databases so no persistent
    data is lost.

Downgrade:
    On downgrade the column is narrowed back to String(64).  Any
    encrypted ciphertext stored after the upgrade would not fit and would
    be lost; existing rows are set to NULL/false before the column
    is narrowed to avoid truncation errors.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "0006"
down_revision: Union[str, None] = "0005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Widen mfa_secret column and NULL out legacy plaintext secrets."""
    # Widen the column first so the UPDATE below works on all dialects.
    with op.batch_alter_table("users") as batch_op:
        batch_op.alter_column(
            "mfa_secret",
            existing_type=sa.String(64),
            type_=sa.String(255),
            existing_nullable=True,
        )

    # Invalidate all existing plaintext TOTP secrets.  The application can no
    # longer decrypt them, so users must re-enroll MFA after this migration.
    op.execute(
        "UPDATE users SET mfa_secret = NULL, mfa_enabled = false "
        "WHERE mfa_secret IS NOT NULL"
    )


def downgrade() -> None:
    """Narrow mfa_secret column back to String(64).

    Any encrypted ciphertext written after the upgrade cannot survive a
    downgrade — it is too long for String(64).  All secrets are cleared
    before the column is narrowed so that the ALTER does not raise a
    truncation or overflow error.
    """
    op.execute(
        "UPDATE users SET mfa_secret = NULL, mfa_enabled = false "
        "WHERE mfa_secret IS NOT NULL"
    )

    with op.batch_alter_table("users") as batch_op:
        batch_op.alter_column(
            "mfa_secret",
            existing_type=sa.String(255),
            type_=sa.String(64),
            existing_nullable=True,
        )
