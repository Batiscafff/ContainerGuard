import json

from worker.scanners.base import BaseScanner

DOCKER_IMAGE = "anchore/syft:latest"


class SyftScanner(BaseScanner):
    def run(self, image_name: str) -> dict:
        raw = self._docker_run(
            DOCKER_IMAGE,
            [image_name, "-o", "cyclonedx-json"],
        )
        return self.parse(raw)

    def parse(self, raw: str) -> dict:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return {"components": []}

        components = []
        for c in data.get("components", []):
            components.append({
                "name": c.get("name", ""),
                "version": c.get("version"),
                "type": c.get("type"),
                "purl": c.get("purl"),
            })
        return {"components": components}
