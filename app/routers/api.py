import csv
import io
import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.dockerfile_issue import DockerfileIssue
from app.models.sbom import SbomComponent
from app.models.scan import Scan
from app.models.vulnerability import Vulnerability
from app.models.secret import Secret
from app.schemas.scan import ScanStatus, ScanSummary, VulnSummary
from app.schemas.vulnerability import DockerfileIssueOut, SbomComponentOut, SecretOut, VulnerabilityOut
from app.services.scan_service import create_scan

router = APIRouter(prefix="/api")


class ScanCreateRequest(BaseModel):
    image_name: str
    dockerfile_content: str | None = None
    scan_mode: str = "image"


class ScanCreateResponse(BaseModel):
    id: str
    image_name: str
    status: str
    scan_mode: str


@router.post("/scan", response_model=ScanCreateResponse, status_code=201)
async def api_create_scan(body: ScanCreateRequest, db: AsyncSession = Depends(get_db)):
    mode = body.scan_mode if body.scan_mode in ("image", "dockerfile") else "image"

    if mode == "dockerfile":
        if not body.dockerfile_content or not body.dockerfile_content.strip():
            raise HTTPException(status_code=400, detail="dockerfile_content is required for dockerfile mode")
        image_name = "Dockerfile"
    else:
        if not body.image_name or not body.image_name.strip():
            raise HTTPException(status_code=400, detail="image_name is required for image mode")
        image_name = body.image_name.strip()

    scan = await create_scan(db, image_name, body.dockerfile_content, scan_mode=mode)
    return ScanCreateResponse(id=scan.id, image_name=scan.image_name, status=scan.status, scan_mode=scan.scan_mode)


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


@router.get("/scan/{scan_id}/secrets", response_model=list[SecretOut])
async def scan_secrets(scan_id: str, db: AsyncSession = Depends(get_db)):
    await _get_scan_or_404(scan_id, db)
    result = await db.execute(
        select(Secret).where(Secret.scan_id == scan_id).order_by(Secret.verified.desc())
    )
    return [SecretOut.model_validate(s) for s in result.scalars().all()]


@router.get("/scan/{scan_id}/report")
async def download_report(scan_id: str, db: AsyncSession = Depends(get_db)):
    scan = await _get_scan_or_404(scan_id, db)

    vulns_res = await db.execute(
        select(Vulnerability).where(Vulnerability.scan_id == scan_id).order_by(Vulnerability.severity)
    )
    vulns = vulns_res.scalars().all()

    sbom_res = await db.execute(select(SbomComponent).where(SbomComponent.scan_id == scan_id))
    sbom = sbom_res.scalars().all()

    issues_res = await db.execute(
        select(DockerfileIssue).where(DockerfileIssue.scan_id == scan_id).order_by(DockerfileIssue.line)
    )
    issues = issues_res.scalars().all()

    secrets_res = await db.execute(
        select(Secret).where(Secret.scan_id == scan_id).order_by(Secret.verified.desc())
    )
    secrets = secrets_res.scalars().all()

    counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "negligible": 0}
    for v in vulns:
        counts[v.severity] = counts.get(v.severity, 0) + 1

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scan": {
            "id": scan.id,
            "image_name": scan.image_name,
            "status": scan.status,
            "security_score": scan.security_score,
            "created_at": scan.created_at.isoformat() if scan.created_at else None,
            "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
            "error_message": scan.error_message,
        },
        "summary": {
            "total_vulnerabilities": len(vulns),
            "by_severity": counts,
            "fixed_available": sum(1 for v in vulns if v.fixed_ver),
            "sbom_components": len(sbom),
            "dockerfile_issues": len(issues),
            "secrets_found": len(secrets),
            "secrets_verified": sum(1 for s in secrets if s.verified),
        },
        "vulnerabilities": [
            {
                "cve_id": v.cve_id,
                "package_name": v.package_name,
                "installed_ver": v.installed_ver,
                "fixed_ver": v.fixed_ver,
                "severity": v.severity,
                "source": v.source,
                "title": v.title,
                "url": v.url,
            }
            for v in vulns
        ],
        "sbom": [
            {"name": c.name, "version": c.version, "type": c.type, "purl": c.purl}
            for c in sbom
        ],
        "dockerfile_issues": [
            {"rule": i.rule, "severity": i.severity, "line": i.line, "message": i.message}
            for i in issues
        ],
        "secrets": [
            {
                "detector_name": s.detector_name,
                "verified": s.verified,
                "raw_redacted": s.raw_redacted,
                "file_path": s.file_path,
                "layer": s.layer,
                "line": s.line,
                "decoder_name": s.decoder_name,
            }
            for s in secrets
        ],
    }

    safe_name = scan.image_name.replace(":", "-").replace("/", "-")
    filename = f"containergard-{safe_name}-{scan.id[:8]}.json"
    return Response(
        content=json.dumps(report, indent=2, ensure_ascii=False),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/scan/{scan_id}/vulnerabilities/csv")
async def download_vulnerabilities_csv(scan_id: str, db: AsyncSession = Depends(get_db)):
    await _get_scan_or_404(scan_id, db)

    result = await db.execute(
        select(Vulnerability).where(Vulnerability.scan_id == scan_id).order_by(Vulnerability.severity)
    )
    vulns = result.scalars().all()

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["CVE ID", "Package", "Installed Version", "Fixed Version", "Severity", "Source", "Title", "URL"])
    for v in vulns:
        writer.writerow([v.cve_id, v.package_name, v.installed_ver or "", v.fixed_ver or "",
                         v.severity, v.source, v.title or "", v.url or ""])

    scan = await db.get(Scan, scan_id)
    safe_name = scan.image_name.replace(":", "-").replace("/", "-")
    filename = f"vulnerabilities-{safe_name}-{scan.id[:8]}.csv"
    return Response(
        content=buf.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
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
