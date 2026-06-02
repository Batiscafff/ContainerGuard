import subprocess
from abc import ABC, abstractmethod


class BaseScanner(ABC):
    def _docker_run(
        self, image: str, args: list[str], stdin: str | None = None, mount_docker: bool = False
    ) -> str:
        cmd = ["docker", "run", "--rm"]
        if mount_docker:
            cmd += ["-v", "/var/run/docker.sock:/var/run/docker.sock"]
        if stdin is not None:
            cmd.append("-i")
        cmd += [image] + args

        result = subprocess.run(
            cmd,
            input=stdin,
            capture_output=True,
            text=True,
            timeout=300,
        )
        if result.returncode != 0 and not result.stdout:
            raise RuntimeError(f"{image} failed: {result.stderr[:500]}")
        return result.stdout

    @abstractmethod
    def run(self, *args, **kwargs) -> dict:
        ...

    @abstractmethod
    def parse(self, raw: str) -> dict:
        ...
