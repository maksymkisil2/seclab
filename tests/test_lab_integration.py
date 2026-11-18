"""Live multi-segment lab tests (Docker >= 28).

Real mode: seclab/node:0.2 (built automatically) + nginx:1.27-alpine.
Stub mode (SECLAB_STUB=1, SECLAB_NODE_IMAGE/SECLAB_WEB_IMAGE=seclab/stub:local): routing, nftables
(host nft binary), isolation, lockdown, ingress DNAT and the audit loop run for real; sshd is replaced by
a TCP listener on :22 and the client key by a dummy file.
"""
from __future__ import annotations

import os
import re
import socket
import ssl

import pytest

from seclab import firewall
from seclab.hardening import lab_label
from seclab.lab import Lab, check, format_report
from seclab.profiles import get_profile
from seclab.runtime import Runtime
from seclab.topology import load
from seclab.web import teardown

pytestmark = pytest.mark.integration
STUB = os.environ.get("SECLAB_STUB") == "1"
OFFSET = 20000 + os.getpid() % 1000


@pytest.fixture(scope="module")
def rt(tmp_path_factory):
    try:
        r = Runtime.detect()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(str(exc))
    if not r.available():
        pytest.skip("container daemon not reachable")
    os.environ.setdefault("SECLAB_HOME", str(tmp_path_factory.mktemp("seclab-home")))
    with pytest.MonkeyPatch.context() as mp:
        if STUB:
            real_entry = Lab.entry

            def stub_entry(self, node):
                if node.role == "ssh":
                    from seclab.images import node_image
                    return ["--entrypoint", "socat", node_image(), "TCP-LISTEN:22,fork", "x"]
                return real_entry(self, node)

            def stub_key(self, _rt):
                d = self.lab_dir / "ssh"
                d.mkdir(exist_ok=True)
                (d / "id_ecdsa").write_text("stub\n")
                (d / "id_ecdsa.pub").write_text("ecdsa-sha2-nistp384 AAAAstub seclab\n")

            mp.setattr(Lab, "entry", stub_entry)
            mp.setattr(Lab, "_ensure_client_key", stub_key)
        yield r


def _up(rt, scenario, profile, name):
    lab = Lab(name, load(scenario), get_profile(profile), scenario, OFFSET)
    teardown(rt, name, purge=True)
    lab.up(rt)
    return lab


@pytest.fixture(scope="module")
def dmz(rt):
    lab = _up(rt, "dmz", "hardened", f"itdmz{os.getpid() % 1000}")
    yield lab
    teardown(rt, lab.name, purge=True)
    assert not rt.container_ids(lab_label(lab.name)) and not rt.network_ids(lab_label(lab.name))


def _caps(values):
    return {v.upper().removeprefix("CAP_") for v in values or []}


def _findings(results):
    return {(r.kind, r.src, r.dst, r.port) for r in results if not r.ok}


def test_hardened_meets_target_policy(rt, dmz):
    results = check(rt, dmz)
    assert not _findings(results), format_report(results)
    kinds = {r.kind for r in results}
    assert kinds == {"route", "egress", "ingress"}
    assert any(r.kind == "route" and r.expected for r in results)       # allowed flows really pass
    assert any(r.kind == "route" and not r.expected for r in results)


def test_router_lockdown(rt, dmz):
    info = rt.inspect("container", dmz.router)
    hc = info["HostConfig"]
    assert _caps(hc["CapAdd"]) == {"NET_ADMIN"} and "ALL" in _caps(hc["CapDrop"])
    assert hc["ReadonlyRootfs"] and hc["Memory"] == 32 * 1024 * 1024 and hc["PidsLimit"] == 32
    assert hc["Sysctls"]["net.ipv4.ip_forward"] == "1"
    binds = [b for v in hc["PortBindings"].values() for b in v]
    assert {b["HostIp"] for b in binds} == {"127.0.0.1"} and len(binds) == 3


def test_nodes_unpublished_and_locked(rt, dmz):
    for node in dmz.topo.nodes.values():
        info = rt.inspect("container", dmz.cname(node.name))
        hc = info["HostConfig"]
        assert not hc["PortBindings"]
        assert hc["ReadonlyRootfs"] and "ALL" in _caps(hc["CapDrop"])
        assert hc["Memory"] == 64 * 1024 * 1024 and hc["NanoCpus"] == 250_000_000
        assert "NET_ADMIN" not in _caps(hc.get("CapAdd"))
        if node.role == "service":
            assert info["Config"]["User"] == "65534:65534"


def test_segments_have_no_host_gateway(rt, dmz):
    for seg in dmz.topo.segments:
        net = rt.inspect("network", dmz.net(seg))
        opts = net["Options"]
        assert opts["com.docker.network.bridge.gateway_mode_ipv4"] == "routed"
        assert opts["com.docker.network.bridge.inhibit_ipv4"] == "true"
        assert opts["com.docker.network.bridge.enable_ip_masquerade"] == "false"


def test_training_loop_flat_then_fixed(rt, dmz):
    dmz.apply_firewall(rt, firewall.render(dmz.topo, "vulnerable"))
    flat = _findings(check(rt, dmz))
    assert ("route", "web", "db", 5432) in flat          # DMZ compromise reaches the database
    assert ("route", "web", "cache", 6379) in flat
    assert not any(k == "egress" for k, *_ in flat)      # boundary holds even when flat
    dmz.apply_firewall(rt, firewall.render(dmz.topo, "hardened"))
    assert not _findings(check(rt, dmz))
    assert re.search(r"counter packets \d+ bytes \d+ drop", dmz.show_firewall(rt))


LEAK = """
table ip leak {
    chain post {
        type nat hook postrouting priority srcnat; policy accept;
        ip saddr 10.90.0.0/16 ip daddr != 10.90.0.0/16 masquerade
    }
}
"""


def test_boundary_blocks_masquerade_leak(rt, dmz):
    flat = firewall.render(dmz.topo, "vulnerable")
    dmz.apply_firewall(rt, flat + LEAK)
    assert not any(k == "egress" for k, *_ in _findings(check(rt, dmz)))
    unbounded = "\n".join(line for line in flat.splitlines() if "!= @lab_nets" not in line) + "\n"
    dmz.apply_firewall(rt, unbounded + LEAK)
    leaked = {s for k, s, *_ in _findings(check(rt, dmz)) if k == "egress"}
    dmz.apply_firewall(rt, firewall.render(dmz.topo, "hardened"))
    assert dmz.foreign_tables(rt) == []                  # apply removed the hand-made table
    assert not _findings(check(rt, dmz))
    if not leaked:
        pytest.skip("no NAT path out of the lab even with masquerade in the router (ingress is not masqueraded): "
                    "boundary is a second layer here, leak not reproducible")
    assert leaked == set(dmz.topo.nodes)


def test_ingress_https_end_to_end(dmz):
    port = dmz.host_port("web", 8443)
    ctx = ssl.create_default_context(cafile=str(dmz.lab_dir / "tls" / "ca.crt"))
    with socket.create_connection(("127.0.0.1", port), timeout=5) as raw, \
            ctx.wrap_socket(raw, server_hostname="localhost") as tls:
        tls.sendall(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
        assert tls.recv(64).startswith(b"HTTP/")


def test_ingress_check_detects_missing_dnat(rt, dmz):
    hardened = firewall.render(dmz.topo, "hardened")
    no_nat = hardened.split("table ip seclab_nat {")[0]
    dmz.apply_firewall(rt, no_nat)
    bad = _findings(check(rt, dmz))
    dmz.apply_firewall(rt, hardened)
    assert {(k, p) for k, _, _, p in bad} == {("ingress", f.host_port + OFFSET) for f in dmz.topo.forwards}


def test_invalid_ruleset_rejected_and_old_kept(rt, dmz):
    with pytest.raises(Exception):
        dmz.apply_firewall(rt, "table inet seclab { chain broken { nonsense } }\n")
    assert not _findings(check(rt, dmz))


def test_office_vulnerable_has_findings(rt):
    lab = _up(rt, "office", "vulnerable", f"itoff{os.getpid() % 1000}")
    try:
        bad = _findings(check(rt, lab))
        assert ("route", "guest1", "files", 445) in bad
        assert ("route", "guest1", "ldap", 636) in bad
        assert not any(k in ("egress", "ingress") for k, *_ in bad)
        lab.apply_firewall(rt, firewall.render(lab.topo, "baseline"))
        assert not _findings(check(rt, lab))
    finally:
        teardown(rt, lab.name, purge=True)
