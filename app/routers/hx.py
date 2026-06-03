from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.dockerfile_issue import DockerfileIssue
from app.models.sbom import SbomComponent
from app.models.scan import Scan
from app.models.secret import Secret
from app.models.vulnerability import Vulnerability

router = APIRouter(prefix="/hx")
templates = Jinja2Templates(directory="app/templates")


async def _scan(scan_id: str, db: AsyncSession) -> Scan:
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise ValueError("not found")
    return scan


@router.get("/scan/{scan_id}/summary", response_class=HTMLResponse)
async def hx_summary(request: Request, scan_id: str, db: AsyncSession = Depends(get_db)):
    scan = await _scan(scan_id, db)
    result = await db.execute(
        select(Vulnerability.severity).where(Vulnerability.scan_id == scan_id)
    )
    severities = result.scalars().all()
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "negligible": 0}
    for s in severities:
        counts[s] = counts.get(s, 0) + 1
    return templates.TemplateResponse(
        "partials/summary.html", {"request": request, "scan": scan, "counts": counts}
    )


@router.get("/scan/{scan_id}/vulnerabilities", response_class=HTMLResponse)
async def hx_vulns(
    request: Request,
    scan_id: str,
    severity: str | None = Query(default=None),
    source: str | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
):
    q = select(Vulnerability).where(Vulnerability.scan_id == scan_id)
    if severity:
        q = q.where(Vulnerability.severity == severity)
    if source:
        q = q.where(Vulnerability.source.contains(source))
    result = await db.execute(q.order_by(Vulnerability.severity))
    vulns = result.scalars().all()
    return templates.TemplateResponse(
        "partials/vuln_table.html", {"request": request, "vulns": vulns}
    )


@router.get("/scan/{scan_id}/sbom", response_class=HTMLResponse)
async def hx_sbom(request: Request, scan_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(SbomComponent).where(SbomComponent.scan_id == scan_id)
    )
    components = result.scalars().all()
    return templates.TemplateResponse(
        "partials/sbom_table.html", {"request": request, "components": components}
    )


@router.get("/scan/{scan_id}/dockerfile", response_class=HTMLResponse)
async def hx_dockerfile(request: Request, scan_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(DockerfileIssue)
        .where(DockerfileIssue.scan_id == scan_id)
        .order_by(DockerfileIssue.line)
    )
    issues = result.scalars().all()
    return templates.TemplateResponse(
        "partials/dockerfile_table.html", {"request": request, "issues": issues}
    )


@router.get("/scan/{scan_id}/secrets", response_class=HTMLResponse)
async def hx_secrets(request: Request, scan_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Secret).where(Secret.scan_id == scan_id).order_by(Secret.verified.desc())
    )
    secrets = result.scalars().all()
    return templates.TemplateResponse(
        "partials/secrets_table.html", {"request": request, "secrets": secrets}
    )


@router.get("/scan/{scan_id}/charts", response_class=HTMLResponse)
async def hx_charts(request: Request, scan_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Vulnerability).where(Vulnerability.scan_id == scan_id)
    )
    vulns = result.scalars().all()

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "negligible": 0}
    for v in vulns:
        counts[v.severity] = counts.get(v.severity, 0) + 1

    pkg_counts: dict[str, int] = {}
    for v in vulns:
        pkg_counts[v.package_name] = pkg_counts.get(v.package_name, 0) + 1
    top_packages = sorted(pkg_counts.items(), key=lambda x: x[1], reverse=True)[:12]

    fixed = sum(1 for v in vulns if v.fixed_ver)
    unfixed = len(vulns) - fixed

    source_counts: dict[str, int] = {}
    for v in vulns:
        source_counts[v.source] = source_counts.get(v.source, 0) + 1

    return templates.TemplateResponse(
        "partials/charts.html",
        {
            "request": request,
            "counts": counts,
            "top_packages": list(top_packages),
            "fixed": fixed,
            "unfixed": unfixed,
            "source_counts": source_counts,
            "total": len(vulns),
        },
    )
