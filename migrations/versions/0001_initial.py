"""initial schema

Revision ID: 0001
Revises:
"""

from alembic import op
import sqlalchemy as sa

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scans",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("image_name", sa.String(255), nullable=False),
        sa.Column(
            "status",
            sa.Enum("pending", "running", "completed", "failed", name="scan_status"),
            nullable=False,
            server_default="pending",
        ),
        sa.Column("security_score", sa.Integer, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_message", sa.Text, nullable=True),
    )

    op.create_table(
        "vulnerabilities",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("scan_id", sa.String(36), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("cve_id", sa.String(30), nullable=False),
        sa.Column("package_name", sa.String(255), nullable=False),
        sa.Column("installed_ver", sa.String(100), nullable=True),
        sa.Column("fixed_ver", sa.String(100), nullable=True),
        sa.Column(
            "severity",
            sa.Enum("critical", "high", "medium", "low", "negligible", name="vuln_severity"),
            nullable=False,
        ),
        sa.Column("source", sa.String(20), nullable=False),
        sa.Column("title", sa.Text, nullable=True),
        sa.Column("url", sa.Text, nullable=True),
    )
    op.create_index("idx_vuln_scan_id", "vulnerabilities", ["scan_id"])
    op.create_index("idx_vuln_severity", "vulnerabilities", ["severity"])
    op.create_index("idx_vuln_cve_id", "vulnerabilities", ["cve_id"])

    op.create_table(
        "sbom_components",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("scan_id", sa.String(36), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("version", sa.String(100), nullable=True),
        sa.Column("type", sa.String(50), nullable=True),
        sa.Column("purl", sa.Text, nullable=True),
    )
    op.create_index("idx_sbom_scan_id", "sbom_components", ["scan_id"])

    op.create_table(
        "dockerfile_issues",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("scan_id", sa.String(36), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("rule", sa.String(20), nullable=False),
        sa.Column(
            "severity",
            sa.Enum("error", "warning", "info", name="issue_severity"),
            nullable=False,
        ),
        sa.Column("line", sa.Integer, nullable=True),
        sa.Column("message", sa.Text, nullable=False),
    )
    op.create_index("idx_issues_scan_id", "dockerfile_issues", ["scan_id"])


def downgrade() -> None:
    op.drop_table("dockerfile_issues")
    op.drop_table("sbom_components")
    op.drop_table("vulnerabilities")
    op.drop_table("scans")
    op.execute("DROP TYPE IF EXISTS issue_severity")
    op.execute("DROP TYPE IF EXISTS vuln_severity")
    op.execute("DROP TYPE IF EXISTS scan_status")
