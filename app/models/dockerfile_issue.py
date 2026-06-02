import uuid

from sqlalchemy import Enum, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class DockerfileIssue(Base):
    __tablename__ = "dockerfile_issues"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    rule: Mapped[str] = mapped_column(String(20), nullable=False)
    severity: Mapped[str] = mapped_column(
        Enum("error", "warning", "info", name="issue_severity"), nullable=False
    )
    line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    message: Mapped[str] = mapped_column(Text, nullable=False)

    scan: Mapped["DockerfileIssue"] = relationship(
        "Scan", back_populates="dockerfile_issues"
    )
