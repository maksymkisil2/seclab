"""Multi-segment lab lifecycle: segments + router/firewall + nodes, audit check, firewall reload.

Data plane:
    host 127.0.0.1:<host_port> -> [ingress net] router --DNAT--> node
    segment <-> router <-> segment  (nodes: default route via router, set by a one-shot netinit container)
Segment networks: Docker bridge, gateway_mode_ipv4=routed, no bridge IP on the host, no masquerade,
so the only L3 path out of a segment is the router, whose nftables policy is the system under training.
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

from . import firewall, nginx, sshd
from .hardening import container_flags, lab_label
from .images import ensure_images, node_image, web_image
from .pki import ensure_pki
from .profiles import ContainerPolicy, Profile, get_profile
from .runtime import ContainerError, Runtime
from .topology import Node, Topology, load
from .web import seclab_home, teardown, validate_name

ROUTER_POLICY = ContainerPolicy(read_only=True, drop_all_caps=True, no_new_privileges=True, user=None,
                                memory="32m", cpus="0.25", pids=32)
PROBE_FLAGS = ["--memory", "16m", "--memory-swap", "16m", "--pids-limit", "16", "--cap-drop", "ALL",
               "--label", "seclab.managed=1"]
DOCKER_TABLES = {"nat", "filter", "raw", "mangle", "security"}  # iptables-nft tables Docker manages
SEGMENT_OPTS = [
    "-o", "com.docker.network.bridge.gateway_mode_ipv4=routed",
    "-o", "com.docker.network.bridge.inhibit_ipv4=true",
    "-o", "com.docker.network.bridge.enable_ip_masquerade=false",
]


def egress_target() -> tuple[str, int]:
    host, _, port = os.environ.get("SECLAB_EGRESS_PROBE", "1.1.1.1:443").rpartition(":")
    return host, int(port)


@dataclass
class Lab:
    name: str
    topo: Topology
    profile: Profile
    scenario: str
    port_offset: int = 0

    def __post_init__(self) -> None:
        validate_name(self.name)
        for f in self.topo.forwards:
            if not 1024 <= f.host_port + self.port_offset <= 65535:
                raise ValueError(f"host port {f.host_port + self.port_offset} out of range")

    # ---- naming -----------------------------------------------------------
    @property
    def prefix(self) -> str:
        return f"seclab-{self.name}"

    def net(self, segment: str) -> str:
        return f"{self.prefix}-net-{segment}"

    @property
    def ingress_net(self) -> str:
        return f"{self.prefix}-ingress"

    def cname(self, node: str) -> str:
        return f"{self.prefix}-{node}"

    @property
    def router(self) -> str:
        return f"{self.prefix}-router"

    @property
    def lab_dir(self) -> Path:
        return seclab_home() / "labs" / self.name

    def host_port(self, node: str, port: int) -> int | None:
        hp = self.topo.public_port(node, port)
        return None if hp is None else hp + self.port_offset

    # ---- state ------------------------------------------------------------
    def to_state(self) -> dict:
        return {"kind": "topology", "name": self.name, "scenario": self.scenario,
                "profile": self.profile.name, "port_offset": self.port_offset}

    @classmethod
    def from_state(cls, st: dict) -> "Lab":
        return cls(st["name"], load(st["scenario"]), get_profile(st["profile"]), st["scenario"],
                   st.get("port_offset", 0))

    @classmethod
    def load_state(cls, lab: str) -> "Lab":
        path = seclab_home() / "labs" / validate_name(lab) / "lab.json"
        if not path.exists():
            raise FileNotFoundError(f"no saved state for lab '{lab}'")
        st = json.loads(path.read_text())
        if st.get("kind") != "topology":
            raise ValueError(f"lab '{lab}' is not a topology lab")
        return cls.from_state(st)

    # ---- files ------------------------------------------------------------
    def node_dir(self, node: str) -> Path:
        return self.lab_dir / "nodes" / node

    def prepare_files(self, rt: Runtime) -> None:
        d = self.lab_dir
        d.mkdir(parents=True, exist_ok=True)
        os.chmod(d, 0o700)
        (d / "router.nft").write_text(firewall.render(self.topo, self.profile.name))
        (d / "target.nft").write_text(firewall.render(self.topo, "hardened"))
        (d / "lab.json").write_text(json.dumps(self.to_state(), indent=2) + "\n")
        needs_tls = any(n.role == "web-proxy" for n in self.topo.nodes.values())
        if needs_tls:
            ensure_pki(d / "tls")
        for node in self.topo.nodes.values():
            nd = self.node_dir(node.name)
            nd.mkdir(parents=True, exist_ok=True)
            if node.role == "web-proxy":
                up = self.topo.nodes[node.upstream]
                public = self.host_port(node.name, 8443) or 8443
                _write(nd / "nginx.conf", nginx.render_edge(self.profile, up.ip, public))
            elif node.role == "web-static":
                _write(nd / "nginx.conf", nginx.render_app(self.profile))
                www = nd / "www"
                www.mkdir(exist_ok=True)
                _write(www / "index.html", f"<!doctype html><title>{node.name}</title><h1>seclab {self.name}/{node.name}</h1>\n")
                os.chmod(www, 0o755)
            elif node.role == "ssh":
                _write(nd / "sshd_config", sshd.render(self.profile))
                if self.profile.name != "vulnerable":
                    self._ensure_client_key(rt)
                    shutil.copy(d / "ssh" / "id_ecdsa.pub", nd / "authorized_keys")
                    os.chmod(nd / "authorized_keys", 0o644)

    def _ensure_client_key(self, rt: Runtime) -> None:
        keydir = self.lab_dir / "ssh"
        if (keydir / "id_ecdsa").exists():
            return
        keydir.mkdir(exist_ok=True)
        os.chmod(keydir, 0o700)
        # ssh-keygen needs a passwd entry for its uid, so run as root and hand the files back to the caller.
        owner = f"{os.getuid()}:{os.getgid()}"
        script = (f"ssh-keygen -q -t ecdsa -b 384 -N '' -C seclab-{self.name} -f /out/id_ecdsa"
                  f" && chown {owner} /out/id_ecdsa /out/id_ecdsa.pub")
        rt.run("run", "--rm", *PROBE_FLAGS, "--cap-add", "CHOWN", "--cap-add", "DAC_OVERRIDE", "--network", "none",
               "-v", f"{keydir}:/out", "--entrypoint", "sh", node_image(), "-c", script)

    # ---- docker args (pure) -----------------------------------------------
    def network_args(self) -> list[list[str]]:
        labels = ["--label", "seclab.managed=1", "--label", lab_label(self.name)]
        # No masquerade on ingress: with br_netfilter, Docker's MASQUERADE rule would rewrite DNAT'd flows
        # the router forwards into a segment, and replies would never find their way back.
        out = [["network", "create", "--driver", "bridge", *labels,
                "-o", "com.docker.network.bridge.enable_ip_masquerade=false", self.ingress_net]]
        for seg in self.topo.segments.values():
            out.append(["network", "create", "--driver", "bridge", *labels, "--subnet", str(seg.subnet),
                        *SEGMENT_OPTS, self.net(seg.name)])
        return out

    def router_args(self) -> list[str]:
        args = ["create", *container_flags(self.router, self.name, "router", ROUTER_POLICY, cap_add=("NET_ADMIN",)),
                "--sysctl", "net.ipv4.ip_forward=1", "--network", self.ingress_net]
        for f in self.topo.forwards:
            hp = f.host_port + self.port_offset
            args += ["-p", f"127.0.0.1:{hp}:{f.host_port}"]
        return args + ["--entrypoint", "tail", node_image(), "-f", "/dev/null"]

    def node_policy(self, node: Node) -> ContainerPolicy:
        c = self.profile.container
        if node.role == "service" and c.user:
            return ContainerPolicy(c.read_only, c.drop_all_caps, c.no_new_privileges, "65534:65534",
                                   c.memory, c.cpus, c.pids)
        if node.role == "ssh" and c.user:
            return ContainerPolicy(c.read_only, c.drop_all_caps, c.no_new_privileges, None,
                                   c.memory, c.cpus, c.pids)
        return c

    def entry(self, node: Node) -> list[str]:
        if node.role in ("web-proxy", "web-static"):
            return ["--entrypoint", "nginx", web_image(), "-c", nginx.CONF_PATH, "-g", "daemon off;"]
        if node.role == "service":
            return ["--entrypoint", "socat", node_image(), f"TCP-LISTEN:{node.ports[0]},fork,reuseaddr",
                    f"SYSTEM:echo seclab-{node.name}"]
        return ["--entrypoint", "sh", node_image(), "-c", sshd.start_script(self.profile)]

    def node_args(self, node: Node) -> list[str]:
        policy = self.node_policy(node)
        caps = sshd.SSH_CAPS if node.role == "ssh" else ()
        args = ["run", "-d", *container_flags(self.cname(node.name), self.name, node.name, policy, cap_add=caps),
                "--network", self.net(node.segment), "--ip", node.ip]
        nd = self.node_dir(node.name)
        if node.role in ("web-proxy", "web-static"):
            args += ["-v", f"{nd / 'nginx.conf'}:{nginx.CONF_PATH}:ro"]
        if node.role == "web-proxy":
            tls = self.lab_dir / "tls"
            args += ["-v", f"{tls / 'server.crt'}:{nginx.TLS_CRT}:ro", "-v", f"{tls / 'server.key'}:{nginx.TLS_KEY}:ro"]
        elif node.role == "web-static":
            args += ["-v", f"{nd / 'www'}:{nginx.WEBROOT}:ro"]
        elif node.role == "ssh":
            args += ["-v", f"{nd / 'sshd_config'}:{sshd.CONF}:ro"]
            if self.profile.name != "vulnerable":
                args += ["-v", f"{nd / 'authorized_keys'}:{sshd.AUTH_KEYS_SRC}:ro",
                         "--tmpfs", f"{sshd.KEY_DIR}:rw,noexec,nosuid,nodev,size=1m,mode=0755"]
        return args + self.entry(node)

    def netinit_args(self, node: Node) -> list[str]:
        gw = self.topo.segments[node.segment].router_ip
        return ["run", "--rm", "--network", f"container:{self.cname(node.name)}", *PROBE_FLAGS,
                "--cap-add", "NET_ADMIN", "--entrypoint", "ip", node_image(), "route", "replace", "default", "via", gw]

    # ---- lifecycle ----------------------------------------------------------
    def up(self, rt: Runtime, ready_timeout: float = 45.0) -> None:
        require_routed_networks(rt)
        label = lab_label(self.name)
        if rt.container_ids(label) or rt.network_ids(label):
            raise ContainerError(f"lab '{self.name}' already exists; run 'down' or 'reset' first")
        ensure_images(rt)
        self.prepare_files(rt)
        try:
            for net in self.network_args():
                rt.run(*net)
            rt.run(*self.router_args())
            for seg in self.topo.segments.values():
                rt.run("network", "connect", "--ip", seg.router_ip, self.net(seg.name), self.router)
            rt.run("start", self.router)
            self.apply_firewall(rt, (self.lab_dir / "router.nft").read_text())
            for node in self.topo.nodes.values():
                rt.run(*self.node_args(node))
            for node in self.topo.nodes.values():
                rt.run(*self.netinit_args(node))
            self.wait_ready(rt, ready_timeout)
        except Exception as exc:
            names = [self.router, *(self.cname(n) for n in self.topo.nodes)]
            diag = "\n".join(f"--- {n} ---\n{rt.logs(n)}" for n in names)
            teardown(rt, self.name, purge=False)
            raise ContainerError(f"lab '{self.name}' failed: {exc}\n{diag}") from None

    def wait_ready(self, rt: Runtime, timeout: float) -> None:
        pending = {(n.name, n.ip, p) for n in self.topo.nodes.values() for p in n.ports}
        deadline = time.monotonic() + timeout
        while pending and time.monotonic() < deadline:
            for cname in [self.router, *(self.cname(n) for n in self.topo.nodes)]:
                st = rt.inspect("container", cname)["State"]
                if not st["Running"]:
                    raise ContainerError(f"{cname} exited (code {st.get('ExitCode')})")
            for item in list(pending):
                _, ip, port = item
                if rt.run("exec", self.router, "nc", "-z", "-w", "1", ip, str(port), check=False).returncode == 0:
                    pending.discard(item)
            if pending:
                time.sleep(0.5)
        if pending:
            raise ContainerError(f"not listening after {timeout}s: {sorted(pending)}")

    def foreign_tables(self, rt: Runtime) -> list[str]:
        """Tables in the router netns not owned by seclab or Docker (e.g. added by hand)."""
        out = rt.run("exec", self.router, "nft", "list", "tables").stdout
        found = []
        for line in out.splitlines():
            parts = line.split()
            if len(parts) == 3 and parts[0] == "table":
                ref = f"{parts[1]} {parts[2]}"
                if ref not in firewall.TABLES and parts[2] not in DOCKER_TABLES:
                    found.append(ref)
        return found

    def apply_firewall(self, rt: Runtime, ruleset: str) -> None:
        """Authoritative reload: validate, then replace every non-Docker table atomically."""
        prologue = "".join(f"delete table {t}\n" for t in self.foreign_tables(rt))
        rt.run("exec", "-i", self.router, "nft", "-c", "-f", "-", stdin=prologue + ruleset)
        rt.run("exec", "-i", self.router, "nft", "-f", "-", stdin=prologue + ruleset)

    def show_firewall(self, rt: Runtime) -> str:
        out = rt.run("exec", self.router, "nft", "list", "table", "inet", "seclab").stdout
        nat = rt.run("exec", self.router, "nft", "list", "table", "ip", "seclab_nat", check=False)
        return out + (nat.stdout if nat.returncode == 0 else "")


def _write(path: Path, text: str) -> None:
    path.write_text(text)
    os.chmod(path, 0o644)


def require_routed_networks(rt: Runtime) -> None:
    if rt.binary != "docker" and not rt.binary.endswith("/docker"):
        raise ContainerError("topology labs need Docker >= 28 (bridge gateway_mode_ipv4=routed); "
                             "podman is supported only for 'seclab web'")
    ver = rt.run("version", "--format", "{{.Server.Version}}").stdout.strip()
    try:
        major = int(ver.split(".")[0])
    except ValueError:
        major = 0
    if major < 28:
        raise ContainerError(f"Docker server {ver or '?'} too old: need >= 28")


# ---- audit check -----------------------------------------------------------------
@dataclass(frozen=True)
class Result:
    kind: str       # route | egress | ingress
    src: str
    dst: str
    port: int
    expected: bool
    actual: bool

    @property
    def ok(self) -> bool:
        return self.expected == self.actual


def plan_routes(topo: Topology) -> list[tuple[Node, Node, int, bool]]:
    plan = []
    for src in topo.nodes.values():
        for dst in topo.nodes.values():
            if dst.segment == src.segment:
                continue
            for port in dst.ports:
                plan.append((src, dst, port, topo.allowed(src, dst, port)))
    return plan


def _probe_from(rt: Runtime, lab: Lab, src: str, ip: str, port: int) -> bool:
    return rt.run("run", "--rm", "--network", f"container:{lab.cname(src)}", *PROBE_FLAGS,
                  "--entrypoint", "nc", node_image(), "-z", "-w", "2", ip, str(port),
                  check=False, timeout=60).returncode == 0


def _ingress_open(port: int) -> bool:
    """True only if the backend really answers: docker-proxy accepts TCP even when the path is broken.

    Waits for a server banner (ssh, service); if none, sends an HTTP request, which both plain HTTP and
    TLS endpoints answer (TLS ones with a 400 / alert).
    """
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=3) as s:
            s.settimeout(1.5)
            try:
                if s.recv(1):
                    return True
                return False
            except socket.timeout:
                pass
            s.settimeout(3)
            s.sendall(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
            return s.recv(1) != b""
    except OSError:
        return False


def check(rt: Runtime, lab: Lab, workers: int = 6) -> list[Result]:
    jobs = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for src, dst, port, expected in plan_routes(lab.topo):
            fut = pool.submit(_probe_from, rt, lab, src.name, dst.ip, port)
            jobs.append(("route", src.name, dst.name, port, expected, fut))
        eh, ep = egress_target()
        for node in lab.topo.nodes.values():
            fut = pool.submit(_probe_from, rt, lab, node.name, eh, ep)
            jobs.append(("egress", node.name, eh, ep, False, fut))
        for f in lab.topo.forwards:
            fut = pool.submit(_ingress_open, f.host_port + lab.port_offset)
            jobs.append(("ingress", "host", f"{f.node}:{f.port}", f.host_port + lab.port_offset, True, fut))
        return [Result(k, s, d, p, e, fut.result()) for k, s, d, p, e, fut in jobs]


def format_report(results: list[Result]) -> str:
    rows = [f"{'':4} {'kind':7} {'from':10} {'to':22} {'port':>5}  expected  actual"]
    for r in sorted(results, key=lambda r: (r.ok, r.kind, r.src, r.dst, r.port)):
        rows.append(f"{'PASS' if r.ok else 'FAIL'} {r.kind:7} {r.src:10} {r.dst:22} {r.port:>5}  "
                    f"{'open' if r.expected else 'closed':8}  {'open' if r.actual else 'closed'}")
    bad = sum(not r.ok for r in results)
    rows.append(f"\n{len(results) - bad}/{len(results)} passed, {bad} finding(s)")
    return "\n".join(rows)
