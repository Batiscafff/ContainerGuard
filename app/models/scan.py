import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, Enum, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    image_name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(
        Enum("pending", "running", "completed", "failed", name="scan_status"),
        default="pending",
        nullable=False,
    )
    security_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    progress: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False)
    stage: Mapped[str | None] = mapped_column(String(120), nullable=True)
    scan_mode: Mapped[str] = mapped_column(String(20), default="image", server_default="image", nullable=False)
    image_digest: Mapped[str | None] = mapped_column(String(100), nullable=True)

    vulnerabilities: Mapped[list] = relationship(
        "Vulnerability", back_populates="scan", cascade="all, delete-orphan"
    )
    sbom_components: Mapped[list] = relationship(
        "SbomComponent", back_populates="scan", cascade="all, delete-orphan"
    )
    dockerfile_issues: Mapped[list] = relationship(
        "DockerfileIssue", back_populates="scan", cascade="all, delete-orphan"
    )
