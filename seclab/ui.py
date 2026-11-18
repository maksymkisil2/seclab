"""Local web UI: stdlib HTTP server + JSON API over the same engine as the CLI.

Security model (the UI drives docker, so it is treated as a privileged local endpoint):
  * binds 127.0.0.1 only
  * every /api call needs the per-run random token (X-Seclab-Token), printed once in the start URL
  * Host header must be 127.0.0.1:<port> or localhost:<port> (DNS-rebinding guard)
  * mutating calls must be POST with Content-Type application/json (no simple-request CSRF)
  * strict CSP, no inline script, no third-party assets
"""
from __future__ import annotations

import json
import re
import secrets
import threading
import time
import traceback
import uuid
from dataclasses import asdict
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources

from . import firewall
from .hardening import LABEL_MANAGED
from .lab import Lab, check
from .profiles import PROFILES, get_profile
from .runtime import Runtime
from .topology import builtin_scenarios, load
from .web import WebLab, seclab_home, teardown, validate_name

STATIC = {"/": ("index.html", "text/html; charset=utf-8"),
          "/app.js": ("app.js", "text/javascript; charset=utf-8"),
          "/style.css": ("style.css", "text/css; charset=utf-8"),
          "/favicon.svg": ("favicon.svg", "image/svg+xml"),
          "/favicon.ico": ("favicon.svg", "image/svg+xml")}
SEC_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
                               "img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cache-Control": "no-store",
}
WEB_SCENARIO = "web"
MAX_BODY = 256 * 1024


class ApiError(Exception):
    def __init__(self, status: int, msg: str):
        super().__init__(msg)
        self.status = status


# ---- jobs -----------------------------------------------------------------------
class Jobs:
    """Background operations; one running job per lab."""

    def __init__(self) -> None:
        self._jobs: dict[str, dict] = {}
        self._busy: set[str] = set()
        self._lock = threading.Lock()

    def start(self, lab: str, action: str, fn) -> dict:
        with self._lock:
            if lab in self._busy:
                raise ApiError(HTTPStatus.CONFLICT, f"lab '{lab}' is busy")
            self._busy.add(lab)
            job = {"id": uuid.uuid4().hex[:12], "lab": lab, "action": action, "state": "running",
                   "started": time.time(), "finished": None, "result": None, "error": None}
            self._jobs[job["id"]] = job

        def run():
            try:
                job["result"] = fn()
                job["state"] = "done"
            except Exception as exc:  # noqa: BLE001 - surfaced to the UI
                job["state"] = "error"
                job["error"] = str(exc) or traceback.format_exc(limit=1)
            finally:
                job["finished"] = time.time()
                with self._lock:
                    self._busy.discard(lab)

        threading.Thread(target=run, daemon=True).start()
        return job

    def get(self, job_id: str) -> dict:
        try:
            return self._jobs[job_id]
        except KeyError:
            raise ApiError(HTTPStatus.NOT_FOUND, "no such job") from None

    def busy(self, lab: str) -> bool:
        with self._lock:
            return lab in self._busy


# ---- engine adapters --------------------------------------------------------------
def scenario_info(name: str) -> dict:
    t = load(name)
    return {
        "name": name, "kind": "topology", "description": t.description,
        "segments": [{"name": s.name, "subnet": str(s.subnet), "router_ip": s.router_ip} for s in t.segments.values()],
        "nodes": [{"name": n.name, "role": n.role, "segment": n.segment, "ip": n.ip, "ports": list(n.ports)}
                  for n in t.nodes.values()],
        "forwards": [asdict(f) for f in t.forwards],
        "allows": [{"from": a.src, "to": a.dst, "ports": list(a.ports)} for a in t.allows],
    }


def web_scenario_info() -> dict:
    return {"name": WEB_SCENARIO, "kind": "web",
            "description": "Single web contour: TLS edge proxy -> internal static app",
            "segments": [{"name": "edge", "subnet": "docker", "router_ip": ""},
                         {"name": "backend", "subnet": "docker (internal)", "router_ip": ""}],
            "nodes": [{"name": "web", "role": "web-proxy", "segment": "edge", "ip": "", "ports": [8080, 8443]},
                      {"name": "app", "role": "web-static", "segment": "backend", "ip": "", "ports": [8080]}],
            "forwards": [{"host_port": 8080, "node": "web", "port": 8080},
                         {"host_port": 8443, "node": "web", "port": 8443}],
            "allows": [{"from": "web", "to": "app", "ports": [8080]}]}


class Engine:
    def __init__(self, rt: Runtime):
        self.rt = rt

    def scenarios(self) -> list[dict]:
        return [web_scenario_info()] + [scenario_info(n) for n in sorted(builtin_scenarios())]

    def containers(self) -> dict[str, list[dict]]:
        fmt = '{{.Label "seclab.lab"}}\t{{.Label "seclab.role"}}\t{{.Names}}\t{{.State}}\t{{.Status}}'
        out = self.rt.run("ps", "-a", "--filter", f"label={LABEL_MANAGED}", "--format", fmt).stdout
        by_lab: dict[str, list[dict]] = {}
        for line in out.splitlines():
            parts = line.split("\t")
            if len(parts) == 5 and parts[0]:
                by_lab.setdefault(parts[0], []).append(
                    {"role": parts[1], "name": parts[2], "state": parts[3], "status": parts[4]})
        return by_lab

    def labs(self) -> list[dict]:
        running = self.containers()
        root = seclab_home() / "labs"
        states = {}
        if root.is_dir():
            for p in sorted(root.glob("*/lab.json")):
                try:
                    states[p.parent.name] = json.loads(p.read_text())
                except (OSError, ValueError):
                    continue
        out = []
        for name in sorted(set(states) | set(running)):
            st = states.get(name, {})
            cs = sorted(running.get(name, []), key=lambda c: c["role"])
            up = bool(cs) and all(c["state"] == "running" for c in cs)
            out.append({
                "name": name, "kind": st.get("kind", "?"),
                "scenario": st.get("scenario", WEB_SCENARIO if st.get("kind") == "web" else "?"),
                "profile": st.get("profile", "?"), "port_offset": st.get("port_offset", 0),
                "http_port": st.get("http_port"), "https_port": st.get("https_port"),
                "state": "up" if up else ("degraded" if cs else "down"),
                "containers": cs, "dir": str(root / name),
            })
        return out

    def _state(self, name: str) -> dict:
        p = seclab_home() / "labs" / validate_name(name) / "lab.json"
        if not p.exists():
            raise ApiError(HTTPStatus.NOT_FOUND, f"lab '{name}' not found")
        return json.loads(p.read_text())

    def topo_lab(self, name: str) -> Lab:
        st = self._state(name)
        if st.get("kind") != "topology":
            raise ApiError(HTTPStatus.BAD_REQUEST, "only topology labs support this action")
        return Lab.from_state(st)

    def up(self, body: dict) -> dict:
        scenario = body.get("scenario")
        profile = get_profile(body.get("profile", "vulnerable"))
        offset = int(body.get("port_offset") or 0)
        if scenario == WEB_SCENARIO:
            name = validate_name(body.get("name") or "web")
            lab = WebLab(name, profile, 8080 + offset, 8443 + offset)
            lab.up(self.rt)
            return {"name": name}
        if scenario not in builtin_scenarios():
            raise ApiError(HTTPStatus.BAD_REQUEST, f"unknown scenario '{scenario}'")
        topo = load(scenario)
        lab = Lab(validate_name(body.get("name") or topo.name), topo, profile, scenario, offset)
        lab.up(self.rt)
        return {"name": lab.name}

    def reset(self, name: str) -> dict:
        st = self._state(name)
        teardown(self.rt, name, purge=True)
        if st.get("kind") == "web":
            WebLab.from_state(st).up(self.rt)
        else:
            Lab.from_state(st).up(self.rt)
        return {"name": name}

    def check(self, name: str) -> dict:
        lab = self.topo_lab(name)
        results = check(self.rt, lab)
        rows = [{**asdict(r), "ok": r.ok} for r in results]
        return {"results": rows, "passed": sum(r.ok for r in results), "total": len(results)}

    def fw_show(self, name: str) -> dict:
        lab = self.topo_lab(name)
        saved = (lab.lab_dir / "router.nft")
        return {"live": lab.show_firewall(self.rt), "file": saved.read_text() if saved.exists() else "",
                "levels": list(PROFILES)}

    def fw_apply(self, name: str, body: dict) -> dict:
        lab = self.topo_lab(name)
        if body.get("level"):
            ruleset = firewall.render(lab.topo, body["level"])
        elif isinstance(body.get("ruleset"), str) and body["ruleset"].strip():
            ruleset = body["ruleset"]
        else:
            raise ApiError(HTTPStatus.BAD_REQUEST, "need 'level' or 'ruleset'")
        lab.apply_firewall(self.rt, ruleset)
        (lab.lab_dir / "router.nft").write_text(ruleset)
        return {"applied": True}


# ---- HTTP -------------------------------------------------------------------------
ROUTES = [
    ("GET", re.compile(r"^/api/scenarios$"), "scenarios"),
    ("GET", re.compile(r"^/api/labs$"), "labs"),
    ("POST", re.compile(r"^/api/labs$"), "up"),
    ("POST", re.compile(r"^/api/labs/(?P<name>[a-z0-9-]+)/down$"), "down"),
    ("POST", re.compile(r"^/api/labs/(?P<name>[a-z0-9-]+)/reset$"), "reset"),
    ("POST", re.compile(r"^/api/labs/(?P<name>[a-z0-9-]+)/check$"), "check"),
    ("GET", re.compile(r"^/api/labs/(?P<name>[a-z0-9-]+)/fw$"), "fw_show"),
    ("POST", re.compile(r"^/api/labs/(?P<name>[a-z0-9-]+)/fw$"), "fw_apply"),
    ("GET", re.compile(r"^/api/jobs/(?P<job>[a-f0-9]{12})$"), "job"),
]


def make_handler(engine: Engine, jobs: Jobs, token: str, port: int):
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}

    class Handler(BaseHTTPRequestHandler):
        server_version = "seclab-ui"
        sys_version = ""

        def log_message(self, fmt, *args):  # quiet: one line per API call
            if self.path.startswith("/api/"):
                super().log_message(fmt, *args)

        def _send(self, status: int, body: bytes, ctype: str) -> None:
            self.send_response(status)
            for k, v in SEC_HEADERS.items():
                self.send_header(k, v)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _json(self, status: int, obj) -> None:
            self._send(status, json.dumps(obj).encode(), "application/json")

        def _guard_host(self) -> bool:
            if self.headers.get("Host") not in allowed_hosts:
                self._send(HTTPStatus.MISDIRECTED_REQUEST, b"bad host", "text/plain")
                return False
            return True

        def do_GET(self):
            if not self._guard_host():
                return
            path = self.path.split("?", 1)[0]
            if path in STATIC:
                fname, ctype = STATIC[path]
                data = (resources.files("seclab") / "ui_static" / fname).read_bytes()
                return self._send(HTTPStatus.OK, data, ctype)
            self._api("GET", path)

        def do_POST(self):
            if not self._guard_host():
                return
            self._api("POST", self.path.split("?", 1)[0])

        def _body(self) -> dict:
            if self.headers.get("Content-Type", "").split(";")[0].strip() != "application/json":
                raise ApiError(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "application/json required")
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY:
                raise ApiError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "body too large")
            raw = self.rfile.read(length) if length else b"{}"
            try:
                data = json.loads(raw or b"{}")
            except ValueError:
                raise ApiError(HTTPStatus.BAD_REQUEST, "invalid json") from None
            if not isinstance(data, dict):
                raise ApiError(HTTPStatus.BAD_REQUEST, "json object required")
            return data

        def _api(self, method: str, path: str) -> None:
            if not path.startswith("/api/"):
                return self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            if not secrets.compare_digest(self.headers.get("X-Seclab-Token", ""), token):
                return self._json(HTTPStatus.UNAUTHORIZED, {"error": "missing or bad token"})
            for m, rx, action in ROUTES:
                match = rx.match(path)
                if match and m == method:
                    break
            else:
                return self._json(HTTPStatus.NOT_FOUND, {"error": "no route"})
            try:
                body = self._body() if method == "POST" else {}
                self._json(HTTPStatus.OK, self._dispatch(action, match.groupdict(), body))
            except ApiError as exc:
                self._json(exc.status, {"error": str(exc)})
            except (ValueError, FileNotFoundError, RuntimeError) as exc:
                self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})

        def _dispatch(self, action: str, params: dict, body: dict):
            name = params.get("name")
            if action == "scenarios":
                return engine.scenarios()
            if action == "labs":
                labs = engine.labs()
                for lab in labs:
                    lab["busy"] = jobs.busy(lab["name"])
                return labs
            if action == "job":
                return jobs.get(params["job"])
            if action == "up":
                label = validate_name(body.get("name") or ("web" if body.get("scenario") == WEB_SCENARIO
                                                           else str(body.get("scenario") or "x")))
                return jobs.start(label, "up", lambda: engine.up({**body, "name": label}))
            if action == "down":
                purge = bool(body.get("purge"))
                return jobs.start(name, "down", lambda: teardown(engine.rt, name, purge) or {"name": name})
            if action == "reset":
                return jobs.start(name, "reset", lambda: engine.reset(name))
            if action == "check":
                engine.topo_lab(name)  # fail fast for web labs / unknown labs
                return jobs.start(name, "check", lambda: engine.check(name))
            if action == "fw_show":
                return engine.fw_show(name)
            if action == "fw_apply":
                if jobs.busy(name):
                    raise ApiError(HTTPStatus.CONFLICT, f"lab '{name}' is busy")
                return engine.fw_apply(name, body)
            raise ApiError(HTTPStatus.NOT_FOUND, "no route")

    return Handler


def make_server(port: int = 8765, rt: Runtime | None = None, token: str | None = None):
    token = token or secrets.token_urlsafe(24)
    engine = Engine(rt or Runtime.detect())
    httpd = ThreadingHTTPServer(("127.0.0.1", port), make_handler(engine, Jobs(), token, port))
    httpd.daemon_threads = True
    real_port = httpd.server_address[1]
    if real_port != port:  # port=0 -> rebuild handler with the real port for the Host guard
        httpd.RequestHandlerClass = make_handler(engine, Jobs(), token, real_port)
    return httpd, token, f"http://127.0.0.1:{real_port}/#t={token}"


def serve(port: int = 8765) -> None:
    httpd, _token, url = make_server(port)
    print(f"seclab ui: {url}\n(Ctrl+C to stop; the token in the URL is required for every API call)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()

