"""Generated corporate network with real vulnweb (seclab/agent image is built from the bundled static binary,
so this runs for real even in stub mode)."""
from __future__ import annotations

import os
import re
import socket
import urllib.parse
import urllib.request

import pytest

from seclab import generator
from seclab.hardening import lab_label
from seclab.lab import Lab, check
from seclab.profiles import get_profile
from seclab.runtime import Runtime
from seclab.web import seclab_home, teardown

pytestmark = pytest.mark.integration
OFFSET = 24000 + os.getpid() % 500
UNION = "zz' UNION SELECT name, value FROM secrets WHERE name LIKE '"


@pytest.fixture(scope="module")
def rt(tmp_path_factory):
    r = Runtime.detect()
    if not r.available():
        pytest.skip("docker not reachable")
    os.environ.setdefault("SECLAB_HOME", str(tmp_path_factory.mktemp("corp-home")))
    with pytest.MonkeyPatch.context() as mp:
        if os.environ.get("SECLAB_STUB") == "1":
            from seclab.images import node_image
            real = Lab.entry
            mp.setattr(Lab, "entry", lambda self, n: ["--entrypoint", "socat", node_image(), "TCP-LISTEN:22,fork", "x"]
                       if n.role == "ssh" else real(self, n))

            def stub_key(self, _rt):
                d = self.lab_dir / "ssh"
                d.mkdir(exist_ok=True)
                (d / "id_ecdsa.pub").write_text("ecdsa-sha2-nistp384 AAAAstub x\n")
            mp.setattr(Lab, "_ensure_client_key", stub_key)
        yield r


def _lab(rt, profile, difficulty, name):
    params = generator.Params(name=name, departments=1, hosts_per_dept=1, sites=2, public_sites=1,
                              mail=False, guest=True, base=130, seed=5)
    path = generator.save(generator.generate(params), seclab_home())
    lab = Lab(name, generator.build(params), get_profile(profile), str(path), OFFSET, difficulty, seed=99)
    teardown(rt, name, purge=True)
    lab.up(rt)
    return lab


def _get(port, path):
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=5) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def test_vulnerable_easy_sqli_flag_and_score(rt):
    lab = _lab(rt, "vulnerable", "easy", f"corpe{os.getpid() % 100}")
    try:
        port = lab.host_port("portal", 8080)
        status, body = _get(port, "/directory?q=" + urllib.parse.quote(UNION))
        flag = re.search(r"FLAG\{sqli-[0-9a-f]{12}\}", body)
        assert status == 200 and flag, body[:400]
        assert flag.group(0) == lab.flags()["portal"]["sqli"]
        assert "Apache/2.4.29" in urllib.request.urlopen(f"http://127.0.0.1:{port}/").headers["Server"]
        assert lab.submit_flag("FLAG{nope}") is None
        assert lab.submit_flag(flag.group(0)) == "portal/sqli"
        score = lab.score()
        assert score["solved"] == ["portal/sqli"] and len(score["total"]) == 8
        info = rt.inspect("container", lab.cname("portal"))
        assert info["Config"]["User"] == "65534:65534" and not info["HostConfig"]["PortBindings"]
        lab.reset(rt)                                                  # same seed: same flags, score kept
        assert lab.score()["solved"] == ["portal/sqli"]
        _, body = _get(port, "/directory?q=" + urllib.parse.quote(UNION))
        assert flag.group(0) in body
    finally:
        teardown(rt, lab.name, purge=True)
        assert not rt.container_ids(lab_label(lab.name))


def test_hardened_is_secure_and_meets_policy(rt):
    lab = _lab(rt, "hardened", "hard", f"corph{os.getpid() % 100}")
    try:
        port = lab.host_port("wiki", 8080)
        _, body = _get(port, "/directory?q=" + urllib.parse.quote(UNION))
        assert "FLAG{" not in body
        _, body = _get(port, "/files?name=%252e%252e%252fprivate%252fflag.txt")
        assert "FLAG{" not in body
        assert lab.vulnweb_level() == "secure" and lab.holes() == []
        bad = [r for r in check(rt, lab) if not r.ok]
        assert not bad, bad
    finally:
        teardown(rt, lab.name, purge=True)


def test_busy_port_is_rejected_before_anything_is_created(rt):
    name = f"corpb{os.getpid() % 100}"
    params = generator.Params(name=name, departments=1, hosts_per_dept=0, sites=1, public_sites=0,
                              database=False, fileserver=False, mgmt=False, guest=False, base=131)
    lab = Lab(name, generator.build(params), get_profile("vulnerable"), "x", OFFSET + 50, "easy", 1)
    port = lab.topo.forwards[0].host_port + lab.port_offset
    with socket.socket() as blocker:
        blocker.bind(("127.0.0.1", port))
        blocker.listen(1)
        with pytest.raises(Exception, match=f"{port}.*in use"):
            lab.up(rt)
    assert not rt.container_ids(lab_label(name)) and not rt.network_ids(lab_label(name))


def test_builtin_attack_runner_captures_and_scores(rt):
    lab = _lab(rt, "vulnerable", "easy", f"atk{os.getpid() % 100}")
    try:
        results = lab.attack()
        hits = {(r["node"], r["category"]) for r in results if r.get("captured")}
        # both generated sites, every category lands at easy
        sites = [n.name for n in lab.topo.nodes.values() if n.role == "vulnweb"]
        for site in sites:
            for cat in ("sqli", "idor", "traversal", "admin"):
                assert (site, cat) in hits, (site, cat, results)
        # captured flags went to the scoreboard
        assert set(lab.score()["solved"]) >= {f"{s}/sqli" for s in sites}
        # scoped: refuses to aim anywhere but loopback (checked at the binary)
        import subprocess
        from seclab.images import agent_binary
        p = subprocess.run([str(agent_binary()), "attack", "-target", "http://10.0.0.5:80"],
                           capture_output=True, text=True)
        assert p.returncode == 2 and "loopback" in p.stderr
    finally:
        teardown(rt, lab.name, purge=True)


def test_per_vuln_toggle_removes_a_class_end_to_end(rt):
    name = f"tog{os.getpid() % 100}"
    params = generator.Params(name=name, departments=1, hosts_per_dept=0, sites=1, public_sites=0,
                              database=False, fileserver=False, mgmt=False, guest=False, base=132)
    path = generator.save(generator.generate(params), seclab_home())
    lab = Lab(name, generator.build(params), get_profile("vulnerable"), str(path), OFFSET + 70, "easy",
              seed=5, vulns=("idor", "traversal"))
    teardown(rt, name, purge=True)
    lab.up(rt)
    try:
        hits = {r["category"] for r in lab.attack() if r.get("captured")}
        assert "idor" in hits and "traversal" in hits
        assert "sqli" not in hits and "admin" not in hits  # disabled classes behave securely
    finally:
        teardown(rt, name, purge=True)


def test_detection_sees_attack_even_when_hardened(rt):
    # Hardened: the attack captures nothing, but the attempts are logged and detection flags them.
    lab = _lab(rt, "hardened", "hard", f"det{os.getpid() % 100}")
    try:
        assert not [r for r in lab.attack(("sqli", "traversal")) if r.get("captured")]
        rep = lab.detect(rt)
        rules = {a["rule"] for a in rep["alerts"]}
        assert "http-sqli" in rules and "http-traversal" in rules, rep
        assert rep["events"] > 0 and rep["by_kind"].get("http", 0) > 0
        assert any(a["technique"] == "T1190" for a in rep["alerts"])        # ATT&CK mapping
        # severities present and sane
        assert all(a["severity"] in ("info", "low", "medium", "high", "critical") for a in rep["alerts"])
    finally:
        teardown(rt, lab.name, purge=True)


def test_detection_min_severity_filter(rt):
    lab = _lab(rt, "vulnerable", "easy", f"dsv{os.getpid() % 100}")
    try:
        lab.attack()
        all_alerts = lab.detect(rt, "info")["alerts"]
        high_only = lab.detect(rt, "high")["alerts"]
        assert len(high_only) <= len(all_alerts)
        assert all(a["severity"] in ("high", "critical") for a in high_only)
        assert any(a["rule"] == "http-sqli" for a in high_only)             # sqli is high
    finally:
        teardown(rt, lab.name, purge=True)
