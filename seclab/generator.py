"""Corporate network generator: size, sites and services -> scenario spec (dict / TOML).

Layout (10.<base>.<n>.0/24 per segment):
    dmz        public reverse proxies (one per public site) -> intranet sites
    servers    intranet sites (vulnweb), database, file server, mail
    <dept>     workstations (ssh) per department
    mgmt       admin jump host           (optional)
    guest      guest network, no access  (optional)

Target policy: departments -> intranet sites :8080, file server :445, mail :25;
sites -> database :5432; public proxies -> their site :8080; jump -> workstations :22;
guest -> nothing. Difficulty is applied at deploy time (Lab.difficulty), not here.
"""
from __future__ import annotations

import random
from dataclasses import asdict, dataclass

from pathlib import Path

from .topology import Topology, parse

DEPARTMENTS = ("sales", "hr", "finance", "dev", "support", "marketing")
SITE_NAMES = ("portal", "wiki", "crm", "hrportal", "shop")
SITE_TITLES = {"portal": "Corp Portal", "wiki": "Team Wiki", "crm": "Customer CRM",
               "hrportal": "HR Self-Service", "shop": "Online Shop"}
NODE_LIMIT_MB = 64
MAX_NODES = 40


@dataclass
class Params:
    name: str = "corp"
    departments: int = 2
    hosts_per_dept: int = 2
    sites: int = 2
    public_sites: int = 1
    database: bool = True
    fileserver: bool = True
    mail: bool = False
    mgmt: bool = True
    guest: bool = True
    base: int = 120          # second octet: 10.<base>.x.0/24
    seed: int = 1

    def validate(self) -> None:
        checks = [
            (1 <= self.departments <= len(DEPARTMENTS), f"departments 1-{len(DEPARTMENTS)}"),
            (0 <= self.hosts_per_dept <= 8, "hosts_per_dept 0-8"),
            (1 <= self.sites <= len(SITE_NAMES), f"sites 1-{len(SITE_NAMES)}"),
            (0 <= self.public_sites <= self.sites, "public_sites 0..sites"),
            (16 <= self.base <= 250, "base 16-250"),
        ]
        for ok, msg in checks:
            if not ok:
                raise ValueError(msg)


def node_count(p: Params) -> int:
    return (p.departments * p.hosts_per_dept + p.sites + p.public_sites + p.database + p.fileserver
            + p.mail + p.mgmt + p.guest + 1)  # + router


def estimate(p: Params) -> dict:
    n = node_count(p)
    return {"containers": n, "ram_limit_mb": n * NODE_LIMIT_MB, "ram_typical_mb": n * 12,
            "segments": 2 + p.departments + p.mgmt + p.guest}


def generate(p: Params) -> dict:
    """Return a scenario spec dict (same shape as the TOML files)."""
    p.validate()
    if node_count(p) > MAX_NODES:
        raise ValueError(f"{node_count(p)} containers > limit {MAX_NODES}: reduce size")
    rng = random.Random(p.seed)
    depts = rng.sample(DEPARTMENTS, p.departments)
    sites = list(SITE_NAMES[: p.sites])
    segs: dict[str, str] = {}

    def seg(name: str) -> str:
        segs[name] = f"10.{p.base}.{len(segs) + 1}.0/24"
        return name

    nodes: dict[str, dict] = {}
    forwards: list[dict] = []
    allows: list[dict] = []
    seg("dmz")
    seg("servers")
    for s in sites:
        nodes[s] = {"role": "vulnweb", "segment": "servers", "title": SITE_TITLES[s]}
        forwards.append({"host_port": 8081 + len(forwards), "node": s, "port": 8080})
    for i, s in enumerate(sites[: p.public_sites]):
        proxy = f"pub-{s}"[:15]
        nodes[proxy] = {"role": "web-proxy", "segment": "dmz", "upstream": s}
        forwards.append({"host_port": 8443 + 1000 * i, "node": proxy, "port": 8443})
        allows.append({"from": proxy, "to": s, "ports": [8080]})
    if p.database:
        nodes["db"] = {"role": "service", "segment": "servers", "port": 5432}
        allows += [{"from": s, "to": "db", "ports": [5432]} for s in sites]
    if p.fileserver:
        nodes["files"] = {"role": "service", "segment": "servers", "port": 445}
    if p.mail:
        nodes["mail"] = {"role": "service", "segment": "servers", "port": 25}
    for d in depts:
        seg(d)
        for h in range(1, p.hosts_per_dept + 1):
            nodes[f"{d}-ws{h}"] = {"role": "ssh", "segment": d}
        allows.append({"from": d, "to": "servers", "ports": sorted({8080} | ({445} if p.fileserver else set())
                                                                    | ({25} if p.mail else set()))})
    if p.mgmt:
        seg("mgmt")
        nodes["jump"] = {"role": "ssh", "segment": "mgmt"}
        forwards.append({"host_port": 2222, "node": "jump", "port": 22})
        allows += [{"from": "jump", "to": d, "ports": [22]} for d in depts if p.hosts_per_dept]
        if p.database:
            allows.append({"from": "jump", "to": "db", "ports": [5432]})
    if p.guest:
        seg("guest")
        nodes["guest1"] = {"role": "ssh", "segment": "guest"}
        forwards.append({"host_port": 2223, "node": "guest1", "port": 22})
    return {"name": p.name[:15], "description": describe(p), "segments": segs, "nodes": nodes,
            "forward": forwards, "allow": allows}


def describe(p: Params) -> str:
    return (f"Generated corp: {p.departments} dept x {p.hosts_per_dept} hosts, {p.sites} sites "
            f"({p.public_sites} public), seed {p.seed}")


def build(p: Params) -> Topology:
    return parse(generate(p))


def to_toml(spec: dict) -> str:
    def val(v) -> str:
        if isinstance(v, bool):
            return "true" if v else "false"
        if isinstance(v, (int, float)):
            return str(v)
        if isinstance(v, list):
            return "[" + ", ".join(val(x) for x in v) + "]"
        s = str(v).replace("\\", "\\\\").replace('"', '\\"')
        return f'"{s}"'

    out = [f"name = {val(spec['name'])}", f"description = {val(spec.get('description', ''))}", "", "[segments]"]
    out += [f"{k} = {val(v)}" for k, v in spec["segments"].items()]
    for name, nd in spec["nodes"].items():
        out += ["", f"[nodes.{name}]"] + [f"{k} = {val(v)}" for k, v in nd.items()]
    for table in ("forward", "allow"):
        for item in spec.get(table, []):
            key_map = {"from": "from", "to": "to"}
            out += ["", f"[[{table}]]"] + [f"{key_map.get(k, k)} = {val(v)}" for k, v in item.items()]
    return "\n".join(out) + "\n"


def params_from(d: dict) -> Params:
    known = {k: d[k] for k in asdict(Params()) if k in d}
    p = Params(**known)
    for k, v in asdict(Params()).items():
        cur = getattr(p, k)
        if isinstance(v, bool):
            setattr(p, k, bool(cur))
        elif isinstance(v, int):
            setattr(p, k, int(cur))
        else:
            setattr(p, k, str(cur))
    return p


def save(spec: dict, home: Path) -> Path:
    """Persist a generated spec so the lab can be reset/reloaded later."""
    d = home / "specs"
    d.mkdir(parents=True, exist_ok=True)
    path = d / f"{spec['name']}.toml"
    path.write_text(to_toml(spec))
    return path
