import uuid

from celery import Celery
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.scan import Scan

celery_app = Celery(broker=settings.celery_broker_url, backend=settings.celery_result_backend)


async def create_scan(db: AsyncSession, image_name: str, dockerfile_content: str | None) -> Scan:
    scan = Scan(id=str(uuid.uuid4()), image_name=image_name)
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    celery_app.send_task(
        "scan_image",
        args=[scan.id, image_name, dockerfile_content],
    )
    return scan
