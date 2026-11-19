"""Generator, difficulty and flags: offline."""
from __future__ import annotations

import tomllib

import pytest

from seclab import firewall, generator
from seclab.lab import Lab, plan_routes
from seclab.profiles import get_profile
from seclab.topology import parse


def test_default_network_shape():
    t = generator.build(generator.Params())
    assert {"dmz", "servers", "mgmt", "guest"} <= set(t.segments)
    roles = [n.role for n in t.nodes.values()]
    assert roles.count("vulnweb") == 2 and roles.count("web-proxy") == 1
    assert not any(a.src == "guest" or a.src == "guest1" for a in t.allows)          # guest isolated


@pytest.mark.parametrize("kw", [dict(departments=0), dict(departments=7), dict(sites=0), dict(sites=6),
                                dict(public_sites=3, sites=2), dict(hosts_per_dept=9), dict(base=300),
                                dict(departments=6, hosts_per_dept=8)])
def test_limits(kw):
    with pytest.raises(ValueError):
        generator.generate(generator.Params(**kw))


def test_seed_determinism_and_toml_roundtrip():
    a = generator.generate(generator.Params(seed=3, departments=3))
    b = generator.generate(generator.Params(seed=3, departments=3))
    c = generator.generate(generator.Params(seed=4, departments=3))
    assert a == b and a["segments"] != c["segments"]
    again = parse(tomllib.loads(generator.to_toml(a)))
    assert {n: (x.ip, x.role, x.title) for n, x in parse(a).nodes.items()} == \
           {n: (x.ip, x.role, x.title) for n, x in again.nodes.items()}


def test_estimate_matches_topology():
    p = generator.Params(departments=3, hosts_per_dept=3, sites=3, public_sites=2, mail=True)
    est = generator.estimate(p)
    assert est["containers"] == len(generator.build(p).nodes) + 1                     # + router
    assert est["ram_limit_mb"] == est["containers"] * 64


def test_params_from_coerces_types():
    p = generator.params_from({"departments": "3", "guest": 0, "name": "x", "unknown": 1})
    assert p.departments == 3 and p.guest is False and p.name == "x"


def _lab(tmp_path, monkeypatch, profile="vulnerable", difficulty="medium", seed=11, name="g"):
    monkeypatch.setenv("SECLAB_HOME", str(tmp_path))
    return Lab(name, generator.build(generator.Params(departments=2)), get_profile(profile), "x", 0, difficulty, seed)


def test_difficulty_holes(tmp_path, monkeypatch):
    easy = _lab(tmp_path, monkeypatch, difficulty="easy")
    med = _lab(tmp_path, monkeypatch, difficulty="medium")
    hard = _lab(tmp_path, monkeypatch, difficulty="hard")
    assert easy.holes() == [] and "policy accept;" in easy.deployed_ruleset().split("chain forward")[1]
    assert len(med.holes()) == 6 and len(hard.holes()) == 2
    assert med.holes() == _lab(tmp_path, monkeypatch, difficulty="medium").holes()   # same seed, same holes
    assert med.holes() != _lab(tmp_path, monkeypatch, difficulty="medium", seed=12).holes()
    forbidden = {(s.name, d.name, p) for s, d, p, ok in plan_routes(med.topo) if not ok}
    assert all((h.src, h.dst, h.ports[0]) in forbidden for h in med.holes())
    rs = med.deployed_ruleset()
    assert "policy drop;" in rs.split("chain forward")[1]
    assert all(f"# {h.src} -> {h.dst}" in rs for h in med.holes())                  # look like normal rules
    assert _lab(tmp_path, monkeypatch, profile="hardened").holes() == []


def test_vulnweb_level_mapping(tmp_path, monkeypatch):
    assert _lab(tmp_path, monkeypatch, difficulty="hard").vulnweb_level() == "hard"
    for prof in ("baseline", "hardened"):
        assert _lab(tmp_path, monkeypatch, profile=prof).vulnweb_level() == "secure"


def test_flags_unique_and_scored(tmp_path, monkeypatch):
    lab = _lab(tmp_path, monkeypatch)
    flags = lab.flags()
    values = [v for kinds in flags.values() for v in kinds.values()]
    assert len(values) == 8 and len(set(values)) == 8
    assert flags == _lab(tmp_path, monkeypatch).flags()
    assert flags != _lab(tmp_path, monkeypatch, seed=12).flags()
    lab.lab_dir.mkdir(parents=True)
    assert lab.submit_flag("FLAG{nope}") is None
    assert lab.submit_flag(" " + values[0] + "\n") is not None
    assert lab.submit_flag(values[0]) is not None                                    # idempotent
    assert len(lab.score()["solved"]) == 1


def test_vulnweb_args(tmp_path, monkeypatch):
    lab = _lab(tmp_path, monkeypatch, difficulty="hard")
    node = next(n for n in lab.topo.nodes.values() if n.role == "vulnweb")
    args = lab.node_args(node)
    assert args[args.index("-level") + 1] == "hard" and "-p" not in args
    assert any(a.endswith(":/etc/seclab/flags.json:ro") for a in args)
    assert any(a.startswith("/tmp:") for a in args)                                   # scratch has no /tmp


def test_firewall_extra_rules_render():
    t = generator.build(generator.Params())
    from seclab.topology import Allow
    rs = firewall.render(t, "baseline", [Allow("guest1", "db", (5432,))])
    assert "tcp dport 5432 ct state new accept  # guest1 -> db" in rs


@pytest.mark.parametrize("profile, difficulty", [("vulnerable", "easy"), ("vulnerable", "medium"),
                                                 ("vulnerable", "hard"), ("baseline", "medium"),
                                                 ("hardened", "medium")])
def test_generated_rulesets_pass_nft_check(tmp_path, monkeypatch, profile, difficulty):
    import shutil
    import subprocess
    if not shutil.which("nft"):
        pytest.skip("nft missing")
    monkeypatch.setenv("SECLAB_HOME", str(tmp_path))
    big = generator.Params(departments=6, hosts_per_dept=3, sites=5, public_sites=3, mail=True)
    lab = Lab("big", generator.build(big), get_profile(profile), "x", 0, difficulty, 5)
    p = subprocess.run(["nft", "-c", "-f", "-"], input=lab.deployed_ruleset(), capture_output=True, text=True)
    if "Operation not permitted" in p.stderr:
        pytest.skip("no CAP_NET_ADMIN")
    assert p.returncode == 0, p.stderr
