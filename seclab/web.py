"""Isolated two-tier web contour.

    host 127.0.0.1:{http,https} --> [edge net] web (TLS reverse proxy) --> [backend net, internal] app (static origin)

backend is an internal network: no egress, app is never published.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import socket
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import nginx
from .hardening import LABEL_MANAGED, container_flags, lab_label
from .pki import ensure_pki
from .profiles import Profile, get_profile
from .runtime import ContainerError, Runtime

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,30}$")


def default_image() -> str:
    return os.environ.get("SECLAB_WEB_IMAGE", "nginx:1.27-alpine")


def seclab_home() -> Path:
    return Path(os.environ.get("SECLAB_HOME", Path.home() / ".seclab"))


def validate_name(lab: str) -> str:
    if not NAME_RE.match(lab):
        raise ValueError("lab name: lowercase letters, digits, '-', max 31 chars")
    return lab


@dataclass
class WebLab:
    name: str
    profile: Profile
    http_port: int = 8080
    https_port: int = 8443
    image: str = field(default_factory=default_image)

    def __post_init__(self) -> None:
        validate_name(self.name)
        for port in (self.http_port, self.https_port):
            if not 1024 <= port <= 65535:
                raise ValueError(f"host port {port} out of range 1024-65535")
        if self.http_port == self.https_port:
            raise ValueError("http and https ports must differ")

    # ---- naming -------------------------------------------------------------
    @property
    def prefix(self) -> str:
        return f"seclab-{self.name}"

    @property
    def edge_net(self) -> str:
        return f"{self.prefix}-edge"

    @property
    def backend_net(self) -> str:
        return f"{self.prefix}-backend"

    @property
    def app_name(self) -> str:
        return f"{self.prefix}-app"

    @property
    def web_name(self) -> str:
        return f"{self.prefix}-web"

    @property
    def lab_dir(self) -> Path:
        return seclab_home() / "labs" / self.name

    # ---- state --------------------------------------------------------------
    def to_state(self) -> dict:
        return {"kind": "web", "name": self.name, "profile": self.profile.name,
                "http_port": self.http_port, "https_port": self.https_port, "image": self.image}

    @classmethod
    def from_state(cls, state: dict) -> "WebLab":
        return cls(name=state["name"], profile=get_profile(state["profile"]),
                   http_port=state["http_port"], https_port=state["https_port"], image=state["image"])

    @classmethod
    def load(cls, lab: str) -> "WebLab":
        path = seclab_home() / "labs" / validate_name(lab) / "lab.json"
        if not path.exists():
            raise FileNotFoundError(f"no saved state for lab '{lab}' ({path})")
        return cls.from_state(json.loads(path.read_text()))

    # ---- files --------------------------------------------------------------
    def prepare_files(self) -> None:
        d = self.lab_dir
        d.mkdir(parents=True, exist_ok=True)
        os.chmod(d, 0o700)
        (d / "edge.conf").write_text(nginx.render_edge(self.profile, self.app_name, self.https_port))
        (d / "app.conf").write_text(nginx.render_app(self.profile))
        ensure_pki(d / "tls")
        www = d / "www"
        if www.exists():
            shutil.rmtree(www)
        www.mkdir()
        (www / "index.html").write_text(
            f"<!doctype html><html><head><meta charset=\"utf-8\"><title>seclab {self.name}</title></head>"
            f"<body><h1>seclab: {self.name}</h1><p>profile: {self.profile.name}</p></body></html>\n"
        )
        if self.profile.name == "vulnerable":
            # Planted exposures for audit practice (dummy data only).
            (www / "backup").mkdir()
            (www / "backup" / "db.sql.bak").write_text("-- seclab dummy dump\nINSERT INTO users VALUES ('admin','dummy');\n")
            (www / ".git").mkdir()
            (www / ".git" / "config").write_text("[remote \"origin\"]\n\turl = https://example.invalid/seclab.git\n")
        for path in [www, *www.rglob("*")]:
            os.chmod(path, 0o755 if path.is_dir() else 0o644)
        for conf in ("edge.conf", "app.conf"):
            os.chmod(d / conf, 0o644)
        (d / "lab.json").write_text(json.dumps(self.to_state(), indent=2) + "\n")

    # ---- container args (pure, unit-tested) ----------------------------------
    def _base_args(self, cname: str, role: str) -> list[str]:
        return ["run", "-d", *container_flags(cname, self.name, role, self.profile.container)]

    def _entry(self) -> list[str]:
        return ["--entrypoint", "nginx", self.image, "-c", nginx.CONF_PATH, "-g", "daemon off;"]

    def app_args(self) -> list[str]:
        d = self.lab_dir
        return self._base_args(self.app_name, "app") + [
            "--network", self.backend_net,
            "-v", f"{d / 'app.conf'}:{nginx.CONF_PATH}:ro",
            "-v", f"{d / 'www'}:{nginx.WEBROOT}:ro",
        ] + self._entry()

    def web_args(self) -> list[str]:
        d = self.lab_dir
        return self._base_args(self.web_name, "web") + [
            "--network", self.edge_net, "--network", self.backend_net,
            "-p", f"127.0.0.1:{self.http_port}:{nginx.HTTP_PORT}",
            "-p", f"127.0.0.1:{self.https_port}:{nginx.HTTPS_PORT}",
            "-v", f"{d / 'edge.conf'}:{nginx.CONF_PATH}:ro",
            "-v", f"{d / 'tls' / 'server.crt'}:{nginx.TLS_CRT}:ro",
            "-v", f"{d / 'tls' / 'server.key'}:{nginx.TLS_KEY}:ro",
        ] + self._entry()

    def network_args(self) -> list[list[str]]:
        common = ["--driver", "bridge", "--label", LABEL_MANAGED, "--label", lab_label(self.name)]
        return [
            ["network", "create", *common, self.edge_net],
            ["network", "create", *common, "--internal", self.backend_net],
        ]

    # ---- lifecycle ----------------------------------------------------------
    def up(self, rt: Runtime, ready_timeout: float = 30.0) -> None:
        if rt.container_ids(lab_label(self.name)) or rt.network_ids(lab_label(self.name)):
            raise ContainerError(f"lab '{self.name}' already exists; run 'down' or 'reset' first")
        taken = []
        for port in (self.http_port, self.https_port):
            with socket.socket() as sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    sock.bind(("127.0.0.1", port))
                except OSError:
                    taken.append(port)
        if taken:
            raise ContainerError(f"host port(s) {taken} already in use: choose other --http-port/--https-port")
        rt.ensure_image(self.image)
        self.prepare_files()
        try:
            for net in self.network_args():
                rt.run(*net)
            rt.run(*self.app_args())
            rt.run(*self.web_args())
            self.wait_ready(rt, ready_timeout)
        except Exception:
            diag = "\n".join(f"--- {n} ---\n{rt.logs(n)}" for n in (self.app_name, self.web_name))
            teardown(rt, self.name, purge=False)
            raise ContainerError(f"lab '{self.name}' failed to start; logs:\n{diag}") from None

    def wait_ready(self, rt: Runtime, timeout: float) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for cname in (self.app_name, self.web_name):
                state = rt.inspect("container", cname)["State"]
                if not state["Running"]:
                    raise ContainerError(f"{cname} exited (code {state.get('ExitCode')})")
            if _http_answers("127.0.0.1", self.http_port):
                return
            time.sleep(0.5)
        raise ContainerError(f"lab '{self.name}' not ready within {timeout}s")


def _http_answers(host: str, port: int) -> bool:
    # A bare TCP connect is not enough: docker-proxy accepts before nginx listens.
    try:
        with socket.create_connection((host, port), timeout=1) as s:
            s.settimeout(1)
            s.sendall(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
            return s.recv(12).startswith(b"HTTP/")
    except OSError:
        return False


def teardown(rt: Runtime, lab: str, purge: bool) -> None:
    label = lab_label(validate_name(lab))
    ids = rt.container_ids(label)
    if ids:
        rt.run("rm", "-f", "-v", *ids)
    nets = rt.network_ids(label)
    if nets:
        rt.run("network", "rm", *nets)
    if purge:
        shutil.rmtree(seclab_home() / "labs" / lab, ignore_errors=True)


def status(rt: Runtime, lab: str | None) -> str:
    label = lab_label(validate_name(lab)) if lab else LABEL_MANAGED
    fmt = '{{.Label "seclab.lab"}}\t{{.Names}}\t{{.Status}}\t{{.Ports}}'
    out = rt.run("ps", "-a", "--filter", f"label={label}", "--format", fmt).stdout.strip()
    return out or "no seclab containers"


def reset(rt: Runtime, lab: str) -> WebLab:
    web = WebLab.load(lab)
    teardown(rt, lab, purge=True)
    web.up(rt)
    return web

