from alembic import op
import sqlalchemy as sa

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("users", sa.Column("is_active", sa.Boolean(), nullable=False, server_default="false"))
    op.add_column("users", sa.Column("is_admin", sa.Boolean(), nullable=False, server_default="false"))


def downgrade():
    op.drop_column("users", "is_admin")
    op.drop_column("users", "is_active")
