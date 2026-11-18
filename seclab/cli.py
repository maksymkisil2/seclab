"""seclab CLI: profiles, images, web (single web contour), lab (multi-segment scenarios)."""
from __future__ import annotations

import argparse
import sys

from . import firewall, nginx
from .images import NODE_TAG, build_node_image
from .lab import Lab, check, format_report
from .profiles import PROFILES, get_profile
from .runtime import ContainerError, Runtime
from .topology import SpecError, builtin_scenarios, load
from .web import WebLab, reset, status, teardown


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="seclab", description="Local hardening / audit training lab")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("profiles", help="list security profiles")

    web = sub.add_parser("web", help="isolated two-tier web contour").add_subparsers(dest="action", required=True)
    up = web.add_parser("up")
    up.add_argument("--lab", required=True)
    up.add_argument("--profile", default="hardened", choices=list(PROFILES))
    up.add_argument("--http-port", type=int, default=8080)
    up.add_argument("--https-port", type=int, default=8443)
    up.add_argument("--image", default=None, help="override web image (default: $SECLAB_WEB_IMAGE or nginx:1.27-alpine)")

    down = web.add_parser("down")
    down.add_argument("--lab", required=True)
    down.add_argument("--purge", action="store_true", help="also delete configs/certs")

    rs = web.add_parser("reset", help="purge and recreate from saved state")
    rs.add_argument("--lab", required=True)

    st = web.add_parser("status")
    st.add_argument("--lab")

    rd = web.add_parser("render", help="print generated nginx.conf")
    rd.add_argument("--profile", default="hardened", choices=list(PROFILES))
    rd.add_argument("--role", default="edge", choices=["edge", "app"])
    rd.add_argument("--https-port", type=int, default=8443)

    img = sub.add_parser("images", help="local images").add_subparsers(dest="action", required=True)
    img.add_parser("build", help=f"build {NODE_TAG} (router/probe/service/ssh)")

    lab = sub.add_parser("lab", help="multi-segment scenarios with router firewall").add_subparsers(
        dest="action", required=True)
    lab.add_parser("list", help="built-in scenarios")
    lu = lab.add_parser("up")
    lu.add_argument("scenario", help="built-in name or path to .toml")
    lu.add_argument("--name", help="lab instance name (default: scenario name)")
    lu.add_argument("--profile", default="vulnerable", choices=list(PROFILES))
    lu.add_argument("--port-offset", type=int, default=0, help="added to every forwarded host port")
    for name, hlp in (("down", None), ("reset", "purge and recreate"), ("check", "audit reachability vs target policy")):
        sp = lab.add_parser(name, help=hlp)
        sp.add_argument("--name", required=True)
        if name == "down":
            sp.add_argument("--purge", action="store_true")
    ls = lab.add_parser("status")
    ls.add_argument("--name")
    fw = lab.add_parser("fw", help="router firewall").add_subparsers(dest="fw_action", required=True)
    fs = fw.add_parser("show")
    fs.add_argument("--name", required=True)
    fa = fw.add_parser("apply", help="validate and load a ruleset (default: <lab>/router.nft)")
    fa.add_argument("--name", required=True)
    src = fa.add_mutually_exclusive_group()
    src.add_argument("--file", help="nft ruleset file")
    src.add_argument("--level", choices=list(PROFILES), help="load the generated ruleset for this level")
    fr = fw.add_parser("render")
    fr.add_argument("scenario")
    fr.add_argument("--level", default="hardened", choices=list(PROFILES))
    return p


def _lab_cmd(a) -> int:
    if a.action == "list":
        for name, path in sorted(builtin_scenarios().items()):
            t = load(str(path))
            print(f"{name:<10} {len(t.segments)} seg / {len(t.nodes)} nodes  {t.description}")
        return 0
    if a.action == "fw" and a.fw_action == "render":
        print(firewall.render(load(a.scenario), a.level), end="")
        return 0
    rt = Runtime.detect()
    if a.action == "up":
        topo = load(a.scenario)
        lab = Lab(a.name or topo.name, topo, get_profile(a.profile), a.scenario, a.port_offset)
        lab.up(rt)
        print(f"up {lab.name}  scenario={a.scenario}  profile={lab.profile.name}  dir={lab.lab_dir}")
        for f in topo.forwards:
            print(f"  127.0.0.1:{f.host_port + lab.port_offset:<5} -> {f.node}:{f.port}")
        return 0
    if a.action == "status":
        print(status(rt, a.name))
        return 0
    if a.action == "down":
        teardown(rt, a.name, a.purge)
        print(f"down {a.name}{' (purged)' if a.purge else ''}")
        return 0
    lab = Lab.load_state(a.name)
    if a.action == "reset":
        teardown(rt, a.name, purge=True)
        lab.up(rt)
        print(f"reset {lab.name} profile={lab.profile.name}")
        return 0
    if a.action == "check":
        results = check(rt, lab)
        print(format_report(results))
        return 0 if all(r.ok for r in results) else 2
    if a.fw_action == "show":
        print(lab.show_firewall(rt), end="")
        return 0
    path = lab.lab_dir / "router.nft"
    if a.level:
        ruleset = firewall.render(lab.topo, a.level)
    elif a.file:
        with open(a.file, encoding="utf-8") as fh:
            ruleset = fh.read()
    else:
        ruleset = path.read_text()
    lab.apply_firewall(rt, ruleset)  # validates first; file is updated only on success
    path.write_text(ruleset)
    print(f"applied -> {path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    a = _parser().parse_args(argv)
    try:
        if a.cmd == "lab":
            return _lab_cmd(a)
        if a.cmd == "images":
            build_node_image(Runtime.detect())
            print(f"built {NODE_TAG}")
            return 0
        if a.cmd == "profiles":
            for prof in PROFILES.values():
                print(f"{prof.name:<11} {prof.description}")
            return 0
        if a.action == "render":
            prof = get_profile(a.profile)
            print(nginx.render_edge(prof, "seclab-render-app", a.https_port) if a.role == "edge" else nginx.render_app(prof), end="")
            return 0
        rt = Runtime.detect()
        if a.action == "up":
            kw = {"image": a.image} if a.image else {}
            lab = WebLab(a.lab, get_profile(a.profile), a.http_port, a.https_port, **kw)
            lab.up(rt)
            print(f"up  {lab.name}  profile={lab.profile.name}  "
                  f"http://127.0.0.1:{lab.http_port}  https://127.0.0.1:{lab.https_port}  ca={lab.lab_dir / 'tls' / 'ca.crt'}")
        elif a.action == "down":
            teardown(rt, a.lab, a.purge)
            print(f"down {a.lab}{' (purged)' if a.purge else ''}")
        elif a.action == "reset":
            lab = reset(rt, a.lab)
            print(f"reset {lab.name} profile={lab.profile.name}")
        elif a.action == "status":
            print(status(rt, a.lab))
        return 0
    except (ContainerError, SpecError, ValueError, FileNotFoundError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
