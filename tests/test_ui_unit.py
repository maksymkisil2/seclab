"""UI server security and API contract, no container daemon needed (fake runtime)."""
from __future__ import annotations

import http.client
import json
import subprocess
import threading

import pytest

from seclab import ui


class FakeRuntime:
    binary = "docker"

    def run(self, *args, check=True, timeout=120, stdin=None):
        return subprocess.CompletedProcess(args, 0, "", "")


@pytest.fixture()
def server(tmp_path, monkeypatch):
    monkeypatch.setenv("SECLAB_HOME", str(tmp_path))
    httpd, token, url = ui.make_server(0, rt=FakeRuntime(), token="tok_" + "x" * 20)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield httpd.server_address[1], token, url
    httpd.shutdown()
    httpd.server_close()


def req(port, method, path, *, token=None, body=None, host=None, ctype="application/json"):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    headers = {"Host": host or f"127.0.0.1:{port}"}
    if token:
        headers["X-Seclab-Token"] = token
    data = None
    if body is not None:
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        headers["Content-Type"] = ctype
    c.request(method, path, body=data, headers=headers)
    r = c.getresponse()
    payload = r.read()
    c.close()
    return r.status, dict(r.getheaders()), payload


def test_binds_loopback_and_url_has_token_in_fragment(server):
    port, token, url = server
    assert url == f"http://127.0.0.1:{port}/#t={token}"


def test_static_served_with_security_headers(server):
    port, _, _ = server
    for path in ("/", "/app.js", "/style.css", "/favicon.svg"):
        status, headers, body = req(port, "GET", path)
        assert status == 200 and body
        assert "script-src 'self'" in headers["Content-Security-Policy"]
        assert "unsafe-inline" not in headers["Content-Security-Policy"]
        assert headers["X-Frame-Options"] == "DENY" and headers["X-Content-Type-Options"] == "nosniff"
        assert "Python" not in headers.get("Server", "")


def test_api_requires_token(server):
    port, token, _ = server
    assert req(port, "GET", "/api/labs")[0] == 401
    assert req(port, "GET", "/api/labs", token="wrong")[0] == 401
    assert req(port, "GET", "/api/labs", token=token)[0] == 200


@pytest.mark.parametrize("host", ["evil.example:80", "127.0.0.1", "attacker.localhost"])
def test_dns_rebinding_guard(server, host):
    port, token, _ = server
    assert req(port, "GET", "/api/labs", token=token, host=host)[0] == 421
    assert req(port, "GET", "/", host=host)[0] == 421


def test_post_requires_json_content_type(server):
    port, token, _ = server
    status, _, _ = req(port, "POST", "/api/labs", token=token, body=b"scenario=dmz",
                       ctype="application/x-www-form-urlencoded")
    assert status == 415


def test_body_validation(server):
    port, token, _ = server
    assert req(port, "POST", "/api/labs", token=token, body=b"[1,2]")[0] == 400
    assert req(port, "POST", "/api/labs", token=token, body=b"{bad")[0] == 400
    big = json.dumps({"x": "a" * (ui.MAX_BODY + 10)}).encode()
    assert req(port, "POST", "/api/labs", token=token, body=big)[0] == 413


def test_route_names_are_validated(server):
    port, token, _ = server
    assert req(port, "POST", "/api/labs/..%2Fetc/down", token=token, body={})[0] == 404
    assert req(port, "POST", "/api/labs/UPPER/down", token=token, body={})[0] == 404
    assert req(port, "GET", "/api/labs/nolab/fw", token=token)[0] == 404


def test_scenarios_contract(server):
    port, token, _ = server
    status, _, body = req(port, "GET", "/api/scenarios", token=token)
    data = json.loads(body)
    assert status == 200
    names = [s["name"] for s in data]
    assert names[0] == "web" and {"dmz", "office"} <= set(names)
    dmz = next(s for s in data if s["name"] == "dmz")
    assert {n["name"] for n in dmz["nodes"]} == {"web", "app", "db", "cache", "bastion"}


def test_up_unknown_scenario_fails_as_job(server):
    port, token, _ = server
    status, _, body = req(port, "POST", "/api/labs", token=token, body={"scenario": "nope", "profile": "hardened"})
    assert status == 200
    job = json.loads(body)
    for _ in range(50):
        _, _, b = req(port, "GET", f"/api/jobs/{job['id']}", token=token)
        j = json.loads(b)
        if j["state"] != "running":
            break
        threading.Event().wait(0.05)
    assert j["state"] == "error" and "unknown scenario" in j["error"]
