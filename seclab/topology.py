"""Scenario spec (TOML) -> validated topology with deterministic addressing.

Spec:
    name, description
    [segments]            seg = "10.90.10.0/24"   (/16../28, private, non-overlapping)
    [nodes.<n>]           role = web-proxy|web-static|vulnweb|service|ssh, segment, upstream (web-proxy),
                          port (service: one TCP listener), title (vulnweb), ip (optional)
    [[forward]]           host_port, node, port     host 127.0.0.1:host_port -> router DNAT -> node:port
    [[allow]]             from, to (segment or node), ports   target firewall policy
"""
from __future__ import annotations

import ipaddress
import re
import tomllib
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path

ROLES = ("web-proxy", "web-static", "vulnweb", "service", "ssh")
ROLE_PORTS = {"web-proxy": (8080, 8443), "web-static": (8080,), "vulnweb": (8080,), "ssh": (22,)}
UPSTREAM_ROLES = ("web-static", "vulnweb")
NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,14}$")
ROUTER_HOST = -2  # .254 in a /24: last usable address
FIRST_NODE_HOST = 10


class SpecError(ValueError):
    pass


@dataclass(frozen=True)
class Segment:
    name: str
    subnet: ipaddress.IPv4Network

    @property
    def router_ip(self) -> str:
        return str(self.subnet[ROUTER_HOST])


@dataclass(frozen=True)
class Node:
    name: str
    role: str
    segment: str
    ip: str
    ports: tuple[int, ...]
    upstream: str | None = None
    title: str | None = None


@dataclass(frozen=True)
class Forward:
    host_port: int
    node: str
    port: int


@dataclass(frozen=True)
class Allow:
    src: str
    dst: str
    ports: tuple[int, ...]


@dataclass
class Topology:
    name: str
    description: str
    segments: dict[str, Segment]
    nodes: dict[str, Node]
    forwards: list[Forward] = field(default_factory=list)
    allows: list[Allow] = field(default_factory=list)

    # -- resolution helpers -------------------------------------------------
    def members(self, ref: str) -> list[Node]:
        """Nodes referenced by a segment or node name."""
        if ref in self.segments:
            return [n for n in self.nodes.values() if n.segment == ref]
        return [self.nodes[ref]]

    def cidr(self, ref: str) -> str:
        return str(self.segments[ref].subnet) if ref in self.segments else f"{self.nodes[ref].ip}/32"

    def allowed(self, src: Node, dst: Node, port: int) -> bool:
        if src.segment == dst.segment:
            return True  # same L2 segment: not routed, not filterable by the router
        return any(
            port in a.ports and src in self.members(a.src) and dst in self.members(a.dst)
            for a in self.allows
        )

    def public_port(self, node: str, port: int) -> int | None:
        for f in self.forwards:
            if f.node == node and f.port == port:
                return f.host_port
        return None


def _ports(raw, where: str) -> tuple[int, ...]:
    if not isinstance(raw, list) or not raw or not all(isinstance(p, int) and 1 <= p <= 65535 for p in raw):
        raise SpecError(f"{where}: ports must be a non-empty list of 1-65535")
    return tuple(sorted(set(raw)))


def parse(data: dict) -> Topology:
    name = data.get("name", "")
    if not NAME_RE.match(name):
        raise SpecError("name: lowercase, starts with a letter, max 15 chars")

    segments: dict[str, Segment] = {}
    for seg, cidr in (data.get("segments") or {}).items():
        if not NAME_RE.match(seg) or seg == "ingress":
            raise SpecError(f"segment '{seg}': invalid name")
        try:
            net = ipaddress.IPv4Network(cidr)
        except ValueError as exc:
            raise SpecError(f"segment '{seg}': {exc}") from None
        if not net.is_private or not 16 <= net.prefixlen <= 28:
            raise SpecError(f"segment '{seg}': must be a private /16../28")
        for other in segments.values():
            if net.overlaps(other.subnet):
                raise SpecError(f"segment '{seg}' overlaps '{other.name}'")
        segments[seg] = Segment(seg, net)
    if not segments:
        raise SpecError("at least one segment required")

    nodes: dict[str, Node] = {}
    next_host = {s: FIRST_NODE_HOST for s in segments}
    used_ips: set[str] = set()
    for nname, nd in (data.get("nodes") or {}).items():
        if not NAME_RE.match(nname) or nname in segments:
            raise SpecError(f"node '{nname}': invalid or clashes with a segment name")
        role = nd.get("role")
        if role not in ROLES:
            raise SpecError(f"node '{nname}': role must be one of {ROLES}")
        seg = nd.get("segment")
        if seg not in segments:
            raise SpecError(f"node '{nname}': unknown segment '{seg}'")
        subnet = segments[seg].subnet
        if "ip" in nd:
            try:
                ip = ipaddress.IPv4Address(nd["ip"])
            except ValueError as exc:
                raise SpecError(f"node '{nname}': {exc}") from None
            if ip not in subnet or ip in (subnet.network_address, subnet.broadcast_address,
                                          subnet[1], subnet[ROUTER_HOST]):
                raise SpecError(f"node '{nname}': ip {ip} not usable in {subnet}")
        else:
            ip = subnet[next_host[seg]]
            next_host[seg] += 1
            while str(ip) in used_ips:
                ip = subnet[next_host[seg]]
                next_host[seg] += 1
        if str(ip) in used_ips:
            raise SpecError(f"node '{nname}': duplicate ip {ip}")
        used_ips.add(str(ip))
        if role == "service":
            port = nd.get("port")
            if not isinstance(port, int) or not 1 <= port <= 65535:
                raise SpecError(f"node '{nname}': service needs 'port' (1-65535)")
            ports: tuple[int, ...] = (port,)
        else:
            ports = ROLE_PORTS[role]
        title = nd.get("title")
        if title is not None and (not isinstance(title, str) or not 0 < len(title) <= 40):
            raise SpecError(f"node '{nname}': title must be 1-40 chars")
        nodes[nname] = Node(nname, role, seg, str(ip), ports, nd.get("upstream"), title)
    if not nodes:
        raise SpecError("at least one node required")

    for n in nodes.values():
        if n.role == "web-proxy":
            up = nodes.get(n.upstream or "")
            if not up or up.role not in UPSTREAM_ROLES:
                raise SpecError(f"node '{n.name}': upstream must name a web-static or vulnweb node")

    forwards: list[Forward] = []
    seen_ports: set[int] = set()
    for f in data.get("forward") or []:
        hp, node, port = f.get("host_port"), f.get("node"), f.get("port")
        if node not in nodes or port not in nodes[node].ports:
            raise SpecError(f"forward {f}: node/port does not exist")
        if not isinstance(hp, int) or not 1024 <= hp <= 65535 or hp in seen_ports:
            raise SpecError(f"forward {f}: host_port must be unique 1024-65535")
        seen_ports.add(hp)
        forwards.append(Forward(hp, node, port))

    allows: list[Allow] = []
    for a in data.get("allow") or []:
        for key in ("from", "to"):
            if a.get(key) not in segments and a.get(key) not in nodes:
                raise SpecError(f"allow {a}: '{key}' must be a segment or node")
        allows.append(Allow(a["from"], a["to"], _ports(a.get("ports"), f"allow {a}")))

    return Topology(name, data.get("description", ""), segments, nodes, forwards, allows)


def load_file(path: Path) -> Topology:
    with open(path, "rb") as fh:
        return parse(tomllib.load(fh))


def builtin_scenarios() -> dict[str, Path]:
    root = resources.files("seclab") / "scenarios"
    return {Path(str(p)).stem: Path(str(p)) for p in root.iterdir() if str(p).endswith(".toml")}


def load(ref: str) -> Topology:
    """Load a built-in scenario by name, or a spec file by path."""
    scenarios = builtin_scenarios()
    if ref in scenarios:
        return load_file(scenarios[ref])
    path = Path(ref)
    if path.is_file():
        return load_file(path)
    raise SpecError(f"unknown scenario '{ref}' (built-in: {', '.join(sorted(scenarios))})")
