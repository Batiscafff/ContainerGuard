from alembic import op
import sqlalchemy as sa

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("scans", sa.Column("image_digest", sa.String(100), nullable=True))
    op.create_index("ix_scans_image_digest", "scans", ["image_digest"])


def downgrade():
    op.drop_index("ix_scans_image_digest", table_name="scans")
    op.drop_column("scans", "image_digest")
