import json

from worker.scanners.base import BaseScanner

DOCKER_IMAGE = "aquasec/trivy:latest"

_SEVERITY_MAP = {"critical", "high", "medium", "low", "negligible"}


def _norm_severity(s: str) -> str:
    s = s.lower()
    return s if s in _SEVERITY_MAP else "negligible"


class TrivyScanner(BaseScanner):
    def run(self, image_name: str) -> dict:
        raw = self._docker_run(
            DOCKER_IMAGE,
            ["image", "--format", "json", "--quiet", image_name],
            mount_docker=True,
        )
        return self.parse(raw)

    def parse(self, raw: str) -> dict:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return {"vulnerabilities": []}

        vulns = []
        for result in data.get("Results", []):
            for v in result.get("Vulnerabilities") or []:
                vulns.append({
                    "cve_id": v.get("VulnerabilityID", ""),
                    "package_name": v.get("PkgName", ""),
                    "installed_ver": v.get("InstalledVersion"),
                    "fixed_ver": v.get("FixedVersion"),
                    "severity": _norm_severity(v.get("Severity", "unknown")),
                    "title": v.get("Title"),
                    "url": v.get("PrimaryURL"),
                    "source": "trivy",
                })
        return {"vulnerabilities": vulns}
