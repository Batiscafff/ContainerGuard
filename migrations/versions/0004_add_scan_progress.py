"""add progress and stage to scans

Revision ID: 0004
Revises: 0003
"""

from alembic import op
import sqlalchemy as sa

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("progress", sa.Integer, nullable=False, server_default="0"))
    op.add_column("scans", sa.Column("stage", sa.String(120), nullable=True))


def downgrade() -> None:
    op.drop_column("scans", "stage")
    op.drop_column("scans", "progress")
