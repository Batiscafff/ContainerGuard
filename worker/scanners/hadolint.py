import json

from worker.scanners.base import BaseScanner

DOCKER_IMAGE = "hadolint/hadolint:latest"

_LEVEL_MAP = {"error": "error", "warning": "warning", "info": "info", "style": "info"}


class HadolintScanner(BaseScanner):
    def run(self, dockerfile_content: str) -> dict:
        raw = self._docker_run(
            DOCKER_IMAGE,
            ["hadolint", "--format", "json", "-"],
            stdin=dockerfile_content,
        )
        return self.parse(raw)

    def parse(self, raw: str) -> dict:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return {"issues": []}

        issues = []
        for item in data if isinstance(data, list) else []:
            issues.append({
                "rule": item.get("code", ""),
                "severity": _LEVEL_MAP.get(item.get("level", "info"), "info"),
                "line": item.get("line"),
                "message": item.get("message", ""),
            })
        return {"issues": issues}
