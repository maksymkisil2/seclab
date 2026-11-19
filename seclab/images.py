"""Image references and the local multi-purpose node image (router, netinit, probe, service, ssh)."""
from __future__ import annotations

import os
import platform
import shutil
import tempfile
from importlib import resources
from pathlib import Path

from .runtime import Runtime

NODE_TAG = "seclab/node:0.2"
AGENT_TAG = "seclab/agent:0.6"
AGENT_DOCKERFILE = """\
FROM scratch
COPY seclab-agent /seclab-agent
USER 65534:65534
ENTRYPOINT ["/seclab-agent"]
"""

NODE_DOCKERFILE = """\
FROM alpine:3.20
RUN apk add --no-cache nftables iproute2 openssh-server openssh-keygen openssh-client socat netcat-openbsd \\
 && adduser -D -u 1000 -s /bin/sh lab \\
 && sed -i 's/^lab:!/lab:*/' /etc/shadow \\
 && mkdir -p /etc/seclab /var/empty \\
 && rm -f /etc/ssh/ssh_host_*
"""


def web_image() -> str:
    return os.environ.get("SECLAB_WEB_IMAGE", "nginx:1.27-alpine")


def node_image() -> str:
    return os.environ.get("SECLAB_NODE_IMAGE", NODE_TAG)


def build_node_image(rt: Runtime, tag: str = NODE_TAG) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        (Path(tmp) / "Dockerfile").write_text(NODE_DOCKERFILE)
        rt.run("build", "-q", "-t", tag, tmp, timeout=900)


def agent_image() -> str:
    return os.environ.get("SECLAB_AGENT_IMAGE", AGENT_TAG)


def agent_binary() -> Path:
    arch = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(platform.machine().lower())
    if not arch:
        raise RuntimeError(f"unsupported CPU architecture {platform.machine()}")
    path = Path(str(resources.files("seclab") / "bin" / f"seclab-agent-linux-{arch}"))
    if not path.is_file():
        raise RuntimeError(f"{path.name} missing: run agent/build.sh (needs Go) or use a release archive")
    return path


def build_agent_image(rt: Runtime, tag: str = AGENT_TAG) -> None:
    """FROM scratch + the bundled static binary: no registry access needed."""
    with tempfile.TemporaryDirectory() as tmp:
        (Path(tmp) / "Dockerfile").write_text(AGENT_DOCKERFILE)
        shutil.copy(agent_binary(), Path(tmp) / "seclab-agent")
        os.chmod(Path(tmp) / "seclab-agent", 0o755)
        rt.run("build", "-q", "-t", tag, tmp, timeout=300)


def ensure_images(rt: Runtime, need_agent: bool = False) -> None:
    node = node_image()
    if not rt.image_exists(node):
        if node != NODE_TAG:
            raise RuntimeError(f"image {node} not found")
        build_node_image(rt)
    rt.ensure_image(web_image())
    if need_agent and not rt.image_exists(agent_image()):
        if agent_image() != AGENT_TAG:
            raise RuntimeError(f"image {agent_image()} not found")
        build_agent_image(rt)
