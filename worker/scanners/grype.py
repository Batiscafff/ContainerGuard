import json

from worker.scanners.base import BaseScanner

DOCKER_IMAGE = "anchore/grype:latest"

_SEVERITY_MAP = {"critical", "high", "medium", "low", "negligible"}


def _norm_severity(s: str) -> str:
    s = s.lower()
    return s if s in _SEVERITY_MAP else "negligible"


class GrypeScanner(BaseScanner):
    def run(self, image_name: str) -> dict:
        raw = self._docker_run(
            DOCKER_IMAGE,
            [image_name, "-o", "json"],
            mount_docker=True,
        )
        return self.parse(raw)

    def parse(self, raw: str) -> dict:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return {"vulnerabilities": []}

        vulns = []
        for match in data.get("matches", []):
            vuln = match.get("vulnerability", {})
            artifact = match.get("artifact", {})
            fix_versions = (vuln.get("fix") or {}).get("versions") or []
            urls = vuln.get("urls") or []
            vulns.append({
                "cve_id": vuln.get("id", ""),
                "package_name": artifact.get("name", ""),
                "installed_ver": artifact.get("version"),
                "fixed_ver": fix_versions[0] if fix_versions else None,
                "severity": _norm_severity(vuln.get("severity", "unknown")),
                "title": vuln.get("description"),
                "url": urls[0] if urls else None,
                "source": "grype",
            })
        return {"vulnerabilities": vulns}
