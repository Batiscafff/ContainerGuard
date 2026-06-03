from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import require_session
from app.models.scan import Scan
from app.services.scan_service import create_scan

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


@router.get("/", response_class=HTMLResponse)
async def index(request: Request, _: str = Depends(require_session)):
    return templates.TemplateResponse("index.html", {"request": request})


@router.post("/scan")
async def start_scan(
    request: Request,
    scan_mode: str = Form(default="image"),
    image_name: str = Form(default=""),
    dockerfile_content: str = Form(default=""),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_session),
):
    mode = scan_mode if scan_mode in ("image", "dockerfile") else "image"
    content = dockerfile_content.strip() or None

    if mode == "dockerfile":
        if not content:
            return HTMLResponse("Dockerfile не може бути порожнім", status_code=400)
        display_name = "Dockerfile"
    else:
        display_name = image_name.strip()
        if not display_name:
            return HTMLResponse("Назва образу не може бути порожньою", status_code=400)

    scan = await create_scan(db, display_name, content, scan_mode=mode)
    return RedirectResponse(url=f"/results/{scan.id}", status_code=303)


@router.get("/results/{scan_id}", response_class=HTMLResponse)
async def results(
    request: Request,
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_session),
):
    scan = await db.get(Scan, scan_id)
    if not scan:
        return HTMLResponse("Scan not found", status_code=404)
    return templates.TemplateResponse("results.html", {"request": request, "scan": scan})


@router.get("/history", response_class=HTMLResponse)
async def history(
    request: Request,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_session),
):
    result = await db.execute(
        select(Scan).order_by(Scan.created_at.desc()).limit(50)
    )
    scans = result.scalars().all()
    return templates.TemplateResponse("history.html", {"request": request, "scans": scans})
