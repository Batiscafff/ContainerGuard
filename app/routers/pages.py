from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.scan import Scan
from app.services.scan_service import create_scan

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


@router.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@router.post("/scan")
async def start_scan(
    request: Request,
    image_name: str = Form(...),
    dockerfile_content: str = Form(default=""),
    db: AsyncSession = Depends(get_db),
):
    content = dockerfile_content.strip() or None
    scan = await create_scan(db, image_name.strip(), content)
    return RedirectResponse(url=f"/results/{scan.id}", status_code=303)


@router.get("/results/{scan_id}", response_class=HTMLResponse)
async def results(request: Request, scan_id: str, db: AsyncSession = Depends(get_db)):
    scan = await db.get(Scan, scan_id)
    if not scan:
        return HTMLResponse("Scan not found", status_code=404)
    return templates.TemplateResponse("results.html", {"request": request, "scan": scan})


@router.get("/history", response_class=HTMLResponse)
async def history(request: Request, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Scan).order_by(Scan.created_at.desc()).limit(50)
    )
    scans = result.scalars().all()
    return templates.TemplateResponse("history.html", {"request": request, "scans": scans})
