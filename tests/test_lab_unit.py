"""Offline tests: scenario parsing, addressing, firewall rendering, sshd config, docker args."""
from __future__ import annotations

import shutil
import subprocess

import pytest

from seclab import firewall, sshd
from seclab.lab import Lab, plan_routes
from seclab.profiles import PROFILES, get_profile
from seclab.topology import SpecError, builtin_scenarios, load, parse

BASE = {
    "name": "t",
    "segments": {"a": "10.80.1.0/24", "b": "10.80.2.0/24"},
    "nodes": {"x": {"role": "service", "segment": "a", "port": 5000},
              "y": {"role": "service", "segment": "b", "port": 6000}},
}


def spec(**over):
    d = {k: (v.copy() if isinstance(v, dict) else v) for k, v in BASE.items()}
    d.update(over)
    return d


@pytest.mark.parametrize("name", sorted(builtin_scenarios()))
def test_builtin_scenarios_parse(name):
    t = load(name)
    assert t.nodes and t.segments and t.allows


def test_addressing_is_deterministic():
    t = parse(spec())
    assert t.nodes["x"].ip == "10.80.1.10" and t.nodes["y"].ip == "10.80.2.10"
    assert t.segments["a"].router_ip == "10.80.1.254"


@pytest.mark.parametrize("bad, msg", [
    ({"segments": {"a": "10.80.0.0/16", "b": "10.80.2.0/24"}}, "overlaps"),
    ({"segments": {"a": "8.8.8.0/24"}}, "private"),
    ({"segments": {"ingress": "10.80.1.0/24"}}, "invalid name"),
    ({"nodes": {"x": {"role": "nope", "segment": "a"}}}, "role"),
    ({"nodes": {"x": {"role": "service", "segment": "zz", "port": 1}}}, "unknown segment"),
    ({"nodes": {"x": {"role": "service", "segment": "a"}}}, "port"),
    ({"nodes": {"x": {"role": "service", "segment": "a", "port": 1, "ip": "10.80.1.254"}}}, "not usable"),
    ({"nodes": {"x": {"role": "web-proxy", "segment": "a"}}}, "upstream"),
    ({"forward": [{"host_port": 9000, "node": "x", "port": 1}]}, "does not exist"),
    ({"forward": [{"host_port": 80, "node": "x", "port": 5000}]}, "host_port"),
    ({"allow": [{"from": "x", "to": "nobody", "ports": [1]}]}, "segment or node"),
    ({"name": "Bad"}, "name"),
])
def test_spec_validation(bad, msg):
    with pytest.raises(SpecError, match=msg):
        parse(spec(**bad))


def test_allowed_semantics_and_plan():
    t = parse(spec(allow=[{"from": "a", "to": "y", "ports": [6000]}]))
    x, y = t.nodes["x"], t.nodes["y"]
    assert t.allowed(x, y, 6000) and not t.allowed(y, x, 5000) and not t.allowed(x, y, 6001)
    plan = {(s.name, d.name, p): e for s, d, p, e in plan_routes(t)}
    assert plan == {("x", "y", 6000): True, ("y", "x", 5000): False}


def test_firewall_levels():
    t = load("dmz")
    vul = firewall.render(t, "vulnerable")
    base = firewall.render(t, "baseline")
    hard = firewall.render(t, "hardened")
    assert "policy accept;" in vul.split("chain forward")[1].split("}")[0]
    assert "chain input" not in vul
    for rs in (base, hard):
        fwd = rs.split("chain forward")[1].split("}")[0]
        assert "policy drop;" in fwd and "ct state established,related accept" in fwd
        assert "ip saddr 10.90.10.10/32 ip daddr 10.90.20.10/32 tcp dport 8080" in fwd
    assert "fib saddr . iif oif missing" in hard and "fib saddr" not in base
    for rs in (vul, base, hard):
        assert "ip daddr != @lab_nets counter drop" in rs          # boundary in every level
        assert "fib daddr type local tcp dport 2222 dnat to 10.90.30.10:22" in rs
        assert "flush ruleset" not in rs                          # keeps Docker DNS rules
        assert rs.count("{") == rs.count("}")


@pytest.mark.skipif(not shutil.which("nft"), reason="nft missing")
@pytest.mark.parametrize("level", list(PROFILES))
@pytest.mark.parametrize("name", sorted(builtin_scenarios()))
def test_firewall_passes_nft_check(name, level):
    # 'nft -c' parses and validates against the kernel without committing; needs CAP_NET_ADMIN.
    rs = firewall.render(load(name), level)
    p = subprocess.run(["nft", "-c", "-f", "-"], input=rs, capture_output=True, text=True)
    if "Operation not permitted" in p.stderr:
        pytest.skip("no CAP_NET_ADMIN")
    assert p.returncode == 0, p.stderr


def test_sshd_profiles():
    v = sshd.render(get_profile("vulnerable"))
    h = sshd.render(get_profile("hardened"))
    b = sshd.render(get_profile("baseline"))
    assert "PermitRootLogin yes" in v and "PasswordAuthentication yes" in v and "aes128-cbc" in v
    for conf in (b, h):
        assert "PermitRootLogin no" in conf and "PasswordAuthentication no" in conf
        assert "AuthenticationMethods publickey" in conf
    assert "curve25519" not in h and "chacha20" not in h and "-cbc" not in h and "sha1" not in h
    assert "KexAlgorithms ecdh-sha2-nistp521" in h
    assert "chpasswd" in sshd.start_script(get_profile("vulnerable"))
    assert "chpasswd" not in sshd.start_script(get_profile("hardened"))


def _lab(tmp_path, monkeypatch, profile="hardened", offset=0):
    monkeypatch.setenv("SECLAB_HOME", str(tmp_path))
    return Lab("dmz", load("dmz"), get_profile(profile), "dmz", offset)


def test_segment_networks_are_routed_without_host_gateway(tmp_path, monkeypatch):
    nets = _lab(tmp_path, monkeypatch).network_args()
    assert "--subnet" not in nets[0]  # ingress: plain bridge, but never masquerading
    assert "com.docker.network.bridge.enable_ip_masquerade=false" in nets[0]
    for n in nets[1:]:
        assert "com.docker.network.bridge.gateway_mode_ipv4=routed" in n
        assert "com.docker.network.bridge.inhibit_ipv4=true" in n
        assert "com.docker.network.bridge.enable_ip_masquerade=false" in n


def test_router_args(tmp_path, monkeypatch):
    args = _lab(tmp_path, monkeypatch, offset=100).router_args()
    assert args[args.index("--cap-add") + 1] == "NET_ADMIN" and args.count("--cap-add") == 1
    assert "--read-only" in args and "net.ipv4.ip_forward=1" in args
    published = [args[i + 1] for i, a in enumerate(args) if a == "-p"]
    assert published == ["127.0.0.1:8180:8080", "127.0.0.1:8543:8443", "127.0.0.1:2322:2222"]


@pytest.mark.parametrize("profile", list(PROFILES))
def test_node_args(tmp_path, monkeypatch, profile):
    lab = _lab(tmp_path, monkeypatch, profile)
    for node in lab.topo.nodes.values():
        args = lab.node_args(node)
        assert "-p" not in args
        assert args[args.index("--ip") + 1] == node.ip
        assert args[args.index("--memory") + 1] == "64m"
        if profile == "vulnerable":
            assert "--cap-drop" not in args
            continue
        assert "--read-only" in args and "--cap-drop" in args
        if node.role == "service":
            assert args[args.index("--user") + 1] == "65534:65534"
        if node.role == "ssh":
            assert "--user" not in args and "SYS_CHROOT" in args and "NET_ADMIN" not in args


def test_netinit_targets_segment_router(tmp_path, monkeypatch):
    lab = _lab(tmp_path, monkeypatch)
    args = lab.netinit_args(lab.topo.nodes["db"])
    assert args[-4:] == ["replace", "default", "via", "10.90.20.254"]
    assert "container:seclab-dmz-db" in args
