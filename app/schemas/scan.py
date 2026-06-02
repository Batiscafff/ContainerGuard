from datetime import datetime

from pydantic import BaseModel


class ScanCreate(BaseModel):
    image_name: str
    dockerfile_content: str | None = None


class ScanStatus(BaseModel):
    id: str
    status: str
    security_score: int | None
    created_at: datetime
    finished_at: datetime | None
    error_message: str | None

    model_config = {"from_attributes": True}


class ScanListItem(BaseModel):
    id: str
    image_name: str
    status: str
    security_score: int | None
    created_at: datetime

    model_config = {"from_attributes": True}


class VulnSummary(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    negligible: int = 0
    total: int = 0


class ScanSummary(BaseModel):
    security_score: int | None
    vuln_summary: VulnSummary
