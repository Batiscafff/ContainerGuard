"""add secrets table

Revision ID: 0002
Revises: 0001
"""

from alembic import op
import sqlalchemy as sa

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "secrets",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("scan_id", sa.String(36), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("detector_name", sa.String(100), nullable=False),
        sa.Column("verified", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("raw_redacted", sa.Text, nullable=True),
        sa.Column("file_path", sa.Text, nullable=True),
        sa.Column("layer", sa.String(100), nullable=True),
        sa.Column("line", sa.Integer, nullable=True),
        sa.Column("decoder_name", sa.String(50), nullable=True),
    )
    op.create_index("idx_secrets_scan_id", "secrets", ["scan_id"])
    op.create_index("idx_secrets_verified", "secrets", ["verified"])


def downgrade() -> None:
    op.drop_table("secrets")
