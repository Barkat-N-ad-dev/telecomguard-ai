"""Add password_hash column to users table.

Revision ID: 0002_user_password_hash
Revises: 0001_initial_schema
Create Date: 2026-11-26
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0002_user_password_hash"
down_revision = "0001_initial_schema"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    cols = {c["name"] for c in inspector.get_columns("users")}
    if "password_hash" not in cols:
        op.add_column("users", sa.Column("password_hash", sa.String(length=256), nullable=True))


def downgrade() -> None:
    op.drop_column("users", "password_hash")
