"""Image references and the local multi-purpose node image (router, netinit, probe, service, ssh)."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

from .runtime import Runtime

NODE_TAG = "seclab/node:0.2"

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


def ensure_images(rt: Runtime) -> None:
    node = node_image()
    if not rt.image_exists(node):
        if node != NODE_TAG:
            raise RuntimeError(f"image {node} not found")
        build_node_image(rt)
    rt.ensure_image(web_image())
