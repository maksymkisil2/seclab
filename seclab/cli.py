"""seclab CLI: web up|down|reset|status|render, profiles."""
from __future__ import annotations

import argparse
import sys

from . import nginx
from .profiles import PROFILES, get_profile
from .runtime import ContainerError, Runtime
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
    return p


def main(argv: list[str] | None = None) -> int:
    a = _parser().parse_args(argv)
    try:
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
    except (ContainerError, ValueError, FileNotFoundError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
