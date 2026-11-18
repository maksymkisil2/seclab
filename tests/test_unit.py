"""Offline tests: config rendering, profile invariants, container args, PKI."""
from __future__ import annotations

import shutil
import subprocess

import pytest

from seclab import nginx
from seclab.profiles import PROFILES, get_profile
from seclab.web import WebLab

ALL = list(PROFILES)


def _balanced(conf: str) -> bool:
    depth = 0
    for ch in conf:
        depth += ch == "{"
        depth -= ch == "}"
        if depth < 0:
            return False
    return depth == 0


@pytest.mark.parametrize("name", ALL)
def test_configs_are_well_formed(name):
    p = get_profile(name)
    for conf in (nginx.render_edge(p, "up", 9443), nginx.render_app(p)):
        assert _balanced(conf)
        assert "pid /tmp/nginx.pid;" in conf
        for line in conf.splitlines():
            s = line.strip()
            if s and not s.endswith(("{", "}", ";")):
                pytest.fail(f"unterminated directive: {s!r}")


def test_hardened_tls_and_headers():
    conf = nginx.render_edge(get_profile("hardened"), "up", 9443)
    assert "ssl_protocols TLSv1.2 TLSv1.3;" in conf
    assert "TLSv1.1" not in conf and "TLSv1 " not in conf
    assert "ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256;" in conf
    assert "server_tokens off;" in conf
    assert "return 301 https://$host:9443$request_uri;" in conf
    assert "ssl_session_tickets off;" in conf
    for h in ("Strict-Transport-Security", "Content-Security-Policy", "X-Content-Type-Options",
              "X-Frame-Options", "Referrer-Policy", "Permissions-Policy"):
        assert f"add_header {h} " in conf
    assert "^(GET|HEAD)$" in conf
    assert "limit_req zone=perip" in conf


def test_vulnerable_is_weak_on_purpose():
    p = get_profile("vulnerable")
    edge = nginx.render_edge(p, "up", 9443)
    assert "ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;" in edge
    assert "@SECLEVEL=0" in edge
    assert "server_tokens on;" in edge
    assert "add_header" not in edge
    assert "return 301" not in edge
    assert "autoindex on;" in nginx.render_app(p)


@pytest.mark.parametrize("name", ALL)
def test_container_args_always_capped_and_local(name, tmp_path, monkeypatch):
    monkeypatch.setenv("SECLAB_HOME", str(tmp_path))
    lab = WebLab("t1", get_profile(name), 18080, 18443, image="img")
    for args in (lab.app_args(), lab.web_args()):
        assert args[args.index("--memory") + 1] == "64m"
        assert args[args.index("--memory-swap") + 1] == "64m"
        assert args[args.index("--cpus") + 1] == "0.25"
        assert args[args.index("--pids-limit") + 1] == "64"
    web = lab.web_args()
    published = [web[i + 1] for i, a in enumerate(web) if a == "-p"]
    assert published == ["127.0.0.1:18080:8080", "127.0.0.1:18443:8443"]
    assert "-p" not in lab.app_args()
    assert lab.app_args().count("--network") == 1
    assert "--internal" in lab.network_args()[1]
    assert "--internal" not in lab.network_args()[0]


@pytest.mark.parametrize("name", ["baseline", "hardened"])
def test_container_lockdown(name, tmp_path, monkeypatch):
    monkeypatch.setenv("SECLAB_HOME", str(tmp_path))
    args = WebLab("t2", get_profile(name), image="img").web_args()
    assert "--read-only" in args
    assert args[args.index("--cap-drop") + 1] == "ALL"
    assert "no-new-privileges:true" in args
    assert args[args.index("--user") + 1] == "101:101"


def test_vulnerable_container_not_locked(tmp_path, monkeypatch):
    monkeypatch.setenv("SECLAB_HOME", str(tmp_path))
    args = WebLab("t3", get_profile("vulnerable"), image="img").web_args()
    assert "--read-only" not in args and "--cap-drop" not in args and "--user" not in args


@pytest.mark.parametrize("bad", ["", "UPPER", "a" * 40, "x_y", "-lead"])
def test_lab_name_validation(bad):
    with pytest.raises(ValueError):
        WebLab(bad, get_profile("baseline"), image="img")


def test_port_validation():
    with pytest.raises(ValueError):
        WebLab("ok", get_profile("baseline"), 80, 8443, image="img")
    with pytest.raises(ValueError):
        WebLab("ok", get_profile("baseline"), 9000, 9000, image="img")


@pytest.mark.skipif(not shutil.which("openssl"), reason="openssl missing")
def test_prepare_files_and_pki(tmp_path, monkeypatch):
    monkeypatch.setenv("SECLAB_HOME", str(tmp_path))
    lab = WebLab("pki", get_profile("vulnerable"), image="img")
    lab.prepare_files()
    d = lab.lab_dir
    assert (d.stat().st_mode & 0o777) == 0o700
    assert (d / "tls" / "ca.key").stat().st_mode & 0o777 == 0o600
    verify = subprocess.run(["openssl", "verify", "-CAfile", d / "tls" / "ca.crt", d / "tls" / "server.crt"],
                            capture_output=True, text=True)
    assert verify.returncode == 0, verify.stderr
    text = subprocess.run(["openssl", "x509", "-in", d / "tls" / "server.crt", "-noout", "-text"],
                          capture_output=True, text=True).stdout
    assert "DNS:localhost" in text and "IP Address:127.0.0.1" in text
    assert "prime256v1" in text or "P-256" in text
    assert (d / "www" / "backup" / "db.sql.bak").exists()
    loaded = WebLab.load("pki")
    assert loaded.to_state() == lab.to_state()
