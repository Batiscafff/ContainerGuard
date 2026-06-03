import uuid

from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, Text

from app.database import Base


class Secret(Base):
    __tablename__ = "secrets"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    detector_name = Column(String(100), nullable=False)
    verified = Column(Boolean, nullable=False, default=False)
    raw_redacted = Column(Text, nullable=True)
    file_path = Column(Text, nullable=True)
    layer = Column(String(100), nullable=True)
    line = Column(Integer, nullable=True)
    decoder_name = Column(String(50), nullable=True)
    raw_value = Column(Text, nullable=True)
