"""Live tests against docker/podman.

Real mode (default): nginx:1.27-alpine + seclab/node:0.2 probe -> full checks incl. TLS/headers.
Stub mode (SECLAB_STUB=1, SECLAB_WEB_IMAGE/SECLAB_PROBE_IMAGE=seclab/stub:local): offline;
container hardening, limits, isolation, egress, lifecycle are checked for real, nginx semantics skipped.
"""
from __future__ import annotations

import os
import socket
import ssl
import subprocess
import threading

import pytest

from seclab.profiles import get_profile
from seclab.runtime import Runtime
from seclab.web import WebLab, lab_label, reset, teardown

pytestmark = pytest.mark.integration

STUB = os.environ.get("SECLAB_STUB") == "1"
PROBE_IMAGE = os.environ.get("SECLAB_PROBE_IMAGE", "seclab/node:0.2")
nginx_only = pytest.mark.skipif(STUB, reason="stub mode: nginx semantics not emulated")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def rt(tmp_path_factory):
    try:
        r = Runtime.detect()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(str(exc))
    if not r.available():
        pytest.skip(f"{r.binary} daemon not reachable")
    try:
        r.ensure_image(PROBE_IMAGE)
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"probe image unavailable: {exc}")
    os.environ.setdefault("SECLAB_HOME", str(tmp_path_factory.mktemp("seclab-home")))
    return r


@pytest.fixture(scope="module", params=["hardened", "vulnerable"])
def lab(request, rt):
    web = WebLab(f"it-{request.param}-{os.getpid() % 10000}", get_profile(request.param),
                 _free_port(), _free_port())
    web.up(rt)
    yield web
    teardown(rt, web.name, purge=True)
    assert rt.container_ids(lab_label(web.name)) == []
    assert rt.network_ids(lab_label(web.name)) == []


def probe(rt: Runtime, net: str, host: str, port: int) -> bool:
    return rt.run(
        "run", "--rm", "--network", net, "--memory", "16m", "--pids-limit", "16", "--cap-drop", "ALL",
        "--entrypoint", "nc", PROBE_IMAGE, "-z", "-w", "2", host, str(port), check=False, timeout=60,
    ).returncode == 0


# ---- container hardening & limits ---------------------------------------------
def test_resource_limits(rt, lab):
    for name in (lab.app_name, lab.web_name):
        hc = rt.inspect("container", name)["HostConfig"]
        assert hc["Memory"] == 64 * 1024 * 1024
        assert hc["NanoCpus"] == 250_000_000
        assert hc["PidsLimit"] == 64


def test_container_lockdown_matches_profile(rt, lab):
    locked = lab.profile.container.read_only
    for name in (lab.app_name, lab.web_name):
        info = rt.inspect("container", name)
        hc = info["HostConfig"]
        assert hc["ReadonlyRootfs"] is locked
        assert ("ALL" in (hc.get("CapDrop") or [])) is locked
        assert ("no-new-privileges:true" in (hc.get("SecurityOpt") or [])) is locked
        assert (info["Config"]["User"] == "101:101") is locked
        assert info["State"]["Running"]


def test_only_web_published_and_only_on_loopback(rt, lab):
    web_ports = rt.inspect("container", lab.web_name)["HostConfig"]["PortBindings"]
    binds = [b for v in web_ports.values() for b in v]
    assert {b["HostIp"] for b in binds} == {"127.0.0.1"}
    assert {int(b["HostPort"]) for b in binds} == {lab.http_port, lab.https_port}
    assert not rt.inspect("container", lab.app_name)["HostConfig"]["PortBindings"]


# ---- network isolation ----------------------------------------------------------
def test_backend_is_internal(rt, lab):
    assert rt.inspect("network", lab.backend_net)["Internal"] is True
    assert rt.inspect("network", lab.edge_net)["Internal"] is False


def test_segmentation(rt, lab):
    app_ip = rt.inspect("container", lab.app_name)["NetworkSettings"]["Networks"][lab.backend_net]["IPAddress"]
    assert probe(rt, lab.edge_net, lab.web_name, 8443), "edge -> web:8443 must work"
    assert probe(rt, lab.backend_net, lab.app_name, 8080), "backend -> app:8080 must work"
    assert not probe(rt, lab.edge_net, app_ip, 8080), "edge must not reach app"


def test_backend_has_no_egress(rt, lab):
    gw = rt.inspect("network", lab.edge_net)["IPAM"]["Config"][0]["Gateway"]
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", 0))
    srv.listen(8)
    port = srv.getsockname()[1]
    stop = threading.Event()

    def accept_loop():
        srv.settimeout(0.5)
        while not stop.is_set():
            try:
                srv.accept()[0].close()
            except OSError:
                pass

    t = threading.Thread(target=accept_loop, daemon=True)
    t.start()
    try:
        assert probe(rt, lab.edge_net, gw, port), "control: edge must reach host listener"
        assert not probe(rt, lab.backend_net, gw, port), "backend must have no egress"
    finally:
        stop.set()
        t.join()
        srv.close()


# ---- nginx semantics (real image only) --------------------------------------------
def _curl(lab: WebLab, *args: str) -> str:
    ca = lab.lab_dir / "tls" / "ca.crt"
    return subprocess.run(["curl", "-sS", "--cacert", str(ca), *args],
                          capture_output=True, text=True, timeout=15).stdout


def _handshake(port: int, version: ssl.TLSVersion) -> bool:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
        ctx.minimum_version = version
        ctx.maximum_version = version
    except (ssl.SSLError, ValueError):
        pytest.skip(f"local OpenSSL client cannot offer {version.name}")
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=5) as s, ctx.wrap_socket(s) as tls:
            return tls.version() is not None
    except (ssl.SSLError, OSError):
        return False


@nginx_only
def test_http_behaviour(lab):
    code = _curl(lab, "-o", "/dev/null", "-w", "%{http_code}", f"http://127.0.0.1:{lab.http_port}/")
    if lab.profile.http.redirect_to_https:
        assert code == "301"
        loc = _curl(lab, "-o", "/dev/null", "-w", "%{redirect_url}", f"http://127.0.0.1:{lab.http_port}/x")
        assert loc == f"https://127.0.0.1:{lab.https_port}/x"
    else:
        assert code == "200"


@nginx_only
def test_https_headers(lab):
    head = _curl(lab, "-D", "-", "-o", "/dev/null", f"https://127.0.0.1:{lab.https_port}/").lower()
    lines = [line.strip() for line in head.splitlines()]
    assert lines[0].startswith(("http/2 200", "http/1.1 200"))
    fields = {k.strip(): v.strip() for k, sep, v in (line.partition(":") for line in lines[1:]) if sep}
    for name, _ in lab.profile.http.headers:
        assert name.lower() in fields
    if lab.profile.http.server_tokens:
        assert fields["server"].startswith("nginx/")
    else:
        assert fields["server"] == "nginx"


@nginx_only
def test_tls_protocols(lab):
    allowed = set(lab.profile.tls.protocols)
    for proto, ver in (("TLSv1.2", ssl.TLSVersion.TLSv1_2), ("TLSv1.3", ssl.TLSVersion.TLSv1_3)):
        assert _handshake(lab.https_port, ver) is (proto in allowed)
    if "TLSv1.1" not in allowed:
        assert _handshake(lab.https_port, ssl.TLSVersion.TLSv1_1) is False


@nginx_only
def test_profile_specific_exposure(lab):
    base = f"https://127.0.0.1:{lab.https_port}"
    git = _curl(lab, "-o", "/dev/null", "-w", "%{http_code}", f"{base}/.git/config")
    post = _curl(lab, "-o", "/dev/null", "-w", "%{http_code}", "-X", "POST", f"{base}/")
    if lab.profile.name == "vulnerable":
        assert git == "200"
        assert "db.sql.bak" in _curl(lab, f"{base}/backup/")
    else:
        assert git == "403"
        assert post == "405"


# ---- lifecycle --------------------------------------------------------------------
def test_reset_recreates_clean(rt, lab):
    old = rt.inspect("container", lab.web_name)["Id"]
    reset(rt, lab.name)
    info = rt.inspect("container", lab.web_name)
    assert info["Id"] != old and info["State"]["Running"]
    assert len(rt.container_ids(lab_label(lab.name))) == 2
