"""nftables ruleset for the lab router.

Tables owned by seclab (Docker's own 'ip nat' DNS table in the netns is left untouched):
    inet seclab      boundary (lab never routes to/from outside, except ingress DNAT flows),
                     forward policy, router input, anti-spoofing
    ip   seclab_nat  ingress DNAT for [[forward]] entries

Firewall levels follow the lab profile:
    vulnerable  flat network: forward policy accept, router input open
    baseline    default-deny forward, allow-list from the spec, stateful, invalid dropped, input closed
    hardened    baseline + reverse-path anti-spoofing + per-rule counters + counted final drop
"""
from __future__ import annotations

from .topology import Topology

TABLES = ("inet seclab", "ip seclab_nat")


def _prologue() -> list[str]:
    # Idempotent reload without 'flush ruleset' (which would kill Docker's embedded DNS rules).
    out = []
    for t in TABLES:
        out += [f"table {t}", f"delete table {t}"]
    return out


def _ports(ports: tuple[int, ...]) -> str:
    return str(ports[0]) if len(ports) == 1 else "{ " + ", ".join(map(str, ports)) + " }"


def render(topo: Topology, level: str) -> str:
    if level not in ("vulnerable", "baseline", "hardened"):
        raise ValueError(f"unknown firewall level '{level}'")
    strict = level != "vulnerable"
    hardened = level == "hardened"
    cnt = "counter " if hardened else ""
    lab_nets = ", ".join(str(s.subnet) for s in topo.segments.values())

    lines = _prologue()
    lines += [
        "",
        "table inet seclab {",
        "    set lab_nets {",
        "        type ipv4_addr; flags interval;",
        f"        elements = {{ {lab_nets} }}",
        "    }",
        "",
        "    chain boundary {",
        "        type filter hook forward priority -10; policy accept;",
        "        ct status dnat accept",
        "        ip saddr != @lab_nets counter drop",
        "        ip daddr != @lab_nets counter drop",
        "    }",
    ]
    if hardened:
        lines += [
            "",
            "    chain antispoof {",
            "        type filter hook prerouting priority -150; policy accept;",
            "        fib saddr . iif oif missing counter drop",
            "    }",
        ]
    lines += [
        "",
        "    chain forward {",
        f"        type filter hook forward priority 0; policy {'drop' if strict else 'accept'};",
    ]
    if strict:
        lines += ["        ct state established,related accept", "        ct state invalid counter drop"]
    for f in topo.forwards:
        node = topo.nodes[f.node]
        lines.append(f"        ct status dnat ip daddr {node.ip} tcp dport {f.port} {cnt}accept  # ingress :{f.host_port}")
    if strict:
        for a in topo.allows:
            lines.append(
                f"        ip saddr {topo.cidr(a.src)} ip daddr {topo.cidr(a.dst)} "
                f"tcp dport {_ports(a.ports)} ct state new {cnt}accept  # {a.src} -> {a.dst}"
            )
        if not hardened:
            lines.append("        icmp type echo-request ip saddr @lab_nets ip daddr @lab_nets limit rate 5/second accept")
    if hardened:
        lines.append("        counter drop")
    lines.append("    }")
    if strict:
        lines += [
            "",
            "    chain input {",
            "        type filter hook input priority 0; policy drop;",
            '        iif "lo" accept',
            "        ct state established,related accept",
            "        icmp type echo-request limit rate 5/second accept",
        ]
        lines += ["        counter drop", "    }"] if hardened else ["    }"]
    lines.append("}")

    if topo.forwards:
        lines += [
            "",
            "table ip seclab_nat {",
            "    chain prerouting {",
            "        type nat hook prerouting priority dstnat; policy accept;",
        ]
        for f in topo.forwards:
            node = topo.nodes[f.node]
            lines.append(f"        fib daddr type local tcp dport {f.host_port} dnat to {node.ip}:{f.port}  # -> {f.node}")
        lines += ["    }", "}"]
    return "\n".join(lines) + "\n"
