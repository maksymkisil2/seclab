"""Thin wrapper over the docker/podman CLI. No SDK dependency."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass


class ContainerError(RuntimeError):
    pass


def detect_runtime() -> str:
    forced = os.environ.get("SECLAB_RUNTIME")
    if forced:
        if not shutil.which(forced):
            raise ContainerError(f"runtime '{forced}' not found in PATH")
        return forced
    for candidate in ("docker", "podman"):
        if shutil.which(candidate):
            return candidate
    raise ContainerError("neither docker nor podman found in PATH")


@dataclass
class Runtime:
    binary: str

    @classmethod
    def detect(cls) -> Runtime:
        return cls(detect_runtime())

    def run(self, *args: str, check: bool = True, timeout: int = 120,
            stdin: str | None = None) -> subprocess.CompletedProcess:
        proc = subprocess.run([self.binary, *args], capture_output=True, text=True, timeout=timeout, input=stdin)
        if check and proc.returncode != 0:
            raise ContainerError(
                f"{self.binary} {' '.join(args)} -> exit {proc.returncode}: {proc.stderr.strip()}"
            )
        return proc

    def available(self) -> bool:
        try:
            return self.run("info", check=False, timeout=15).returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            return False

    def container_ids(self, label: str) -> list[str]:
        return self.run("ps", "-aq", "--filter", f"label={label}").stdout.split()

    def network_ids(self, label: str) -> list[str]:
        return self.run("network", "ls", "-q", "--filter", f"label={label}").stdout.split()

    def inspect(self, kind: str, name: str) -> dict:
        return json.loads(self.run(kind, "inspect", name).stdout)[0]

    def image_exists(self, image: str) -> bool:
        return self.run("image", "inspect", image, check=False).returncode == 0

    def ensure_image(self, image: str) -> None:
        if not self.image_exists(image):
            self.run("pull", image, timeout=600)

    def logs(self, name: str, tail: int = 30) -> str:
        p = self.run("logs", "--tail", str(tail), name, check=False)
        return (p.stdout + p.stderr).strip()
