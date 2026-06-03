"""add scan_mode to scans

Revision ID: 0005
Revises: 0004
"""

from alembic import op
import sqlalchemy as sa

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column("scan_mode", sa.String(20), nullable=False, server_default="image"),
    )


def downgrade() -> None:
    op.drop_column("scans", "scan_mode")
