import json

from worker.scanners.base import BaseScanner

DOCKER_IMAGE = "trufflesecurity/trufflehog:latest"


class TruffleHogScanner(BaseScanner):
    def run(self, image_name: str) -> dict:
        raw = self._docker_run(
            DOCKER_IMAGE,
            ["docker", "--image", image_name, "--json", "--no-update"],
            mount_docker=True,
        )
        return self.parse(raw)

    def parse(self, raw: str) -> dict:
        secrets = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            docker_meta = (
                data.get("SourceMetadata", {})
                .get("Data", {})
                .get("Docker", {})
            )

            raw_val = data.get("Raw", "")
            redacted = data.get("Redacted") or ""
            if not redacted and raw_val:
                visible = max(2, min(6, len(raw_val) // 4))
                redacted = raw_val[:visible] + "****"

            secrets.append({
                "detector_name": data.get("DetectorName", "Unknown"),
                "verified": bool(data.get("Verified", False)),
                "raw_redacted": redacted or None,
                "raw_value": raw_val or None,
                "file_path": docker_meta.get("file"),
                "layer": docker_meta.get("layer"),
                "line": docker_meta.get("line"),
                "decoder_name": data.get("DecoderName"),
            })

        return {"secrets": secrets}
