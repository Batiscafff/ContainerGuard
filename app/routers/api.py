import json

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.dockerfile_issue import DockerfileIssue
from app.models.sbom import SbomComponent
from app.models.scan import Scan
from app.models.vulnerability import Vulnerability
from app.schemas.scan import ScanStatus, ScanSummary, VulnSummary
from app.schemas.vulnerability import DockerfileIssueOut, SbomComponentOut, VulnerabilityOut

router = APIRouter(prefix="/api")


async def _get_scan_or_404(scan_id: str, db: AsyncSession) -> Scan:
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("/scan/{scan_id}/status", response_model=ScanStatus)
async def scan_status(scan_id: str, db: AsyncSession = Depends(get_db)):
    scan = await _get_scan_or_404(scan_id, db)
    return ScanStatus.model_validate(scan)


@router.get("/scan/{scan_id}/summary", response_model=ScanSummary)
async def scan_summary(scan_id: str, db: AsyncSession = Depends(get_db)):
    scan = await _get_scan_or_404(scan_id, db)

    result = await db.execute(
        select(Vulnerability.severity).where(Vulnerability.scan_id == scan_id)
    )
    severities = result.scalars().all()

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "negligible": 0}
    for s in severities:
        counts[s] = counts.get(s, 0) + 1

    summary = VulnSummary(**counts, total=len(severities))
    return ScanSummary(security_score=scan.security_score, vuln_summary=summary)


@router.get("/scan/{scan_id}/vulnerabilities", response_model=list[VulnerabilityOut])
async def scan_vulnerabilities(
    scan_id: str,
    severity: str | None = Query(default=None),
    source: str | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
):
    await _get_scan_or_404(scan_id, db)

    q = select(Vulnerability).where(Vulnerability.scan_id == scan_id)
    if severity:
        q = q.where(Vulnerability.severity == severity)
    if source:
        q = q.where(Vulnerability.source.contains(source))

    result = await db.execute(q.order_by(Vulnerability.severity))
    return [VulnerabilityOut.model_validate(v) for v in result.scalars().all()]


@router.get("/scan/{scan_id}/sbom", response_model=list[SbomComponentOut])
async def scan_sbom(scan_id: str, db: AsyncSession = Depends(get_db)):
    await _get_scan_or_404(scan_id, db)
    result = await db.execute(
        select(SbomComponent).where(SbomComponent.scan_id == scan_id)
    )
    return [SbomComponentOut.model_validate(c) for c in result.scalars().all()]


@router.get("/scan/{scan_id}/sbom/download")
async def sbom_download(scan_id: str, db: AsyncSession = Depends(get_db)):
    await _get_scan_or_404(scan_id, db)
    result = await db.execute(
        select(SbomComponent).where(SbomComponent.scan_id == scan_id)
    )
    components = result.scalars().all()

    cyclonedx = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "components": [
            {
                "type": c.type or "library",
                "name": c.name,
                "version": c.version,
                "purl": c.purl,
            }
            for c in components
        ],
    }
    return Response(
        content=json.dumps(cyclonedx, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=sbom-{scan_id}.json"},
    )


@router.delete("/scan/{scan_id}", status_code=204)
async def delete_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    scan = await _get_scan_or_404(scan_id, db)
    await db.delete(scan)
    await db.commit()
    return Response(status_code=204)


@router.get("/scan/{scan_id}/dockerfile", response_model=list[DockerfileIssueOut])
async def scan_dockerfile(scan_id: str, db: AsyncSession = Depends(get_db)):
    await _get_scan_or_404(scan_id, db)
    result = await db.execute(
        select(DockerfileIssue)
        .where(DockerfileIssue.scan_id == scan_id)
        .order_by(DockerfileIssue.line)
    )
    return [DockerfileIssueOut.model_validate(i) for i in result.scalars().all()]
