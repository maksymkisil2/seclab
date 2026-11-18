"""nginx.conf rendering for the edge (TLS reverse proxy) and app (static origin) roles."""
from __future__ import annotations

from .profiles import Profile

CONF_PATH = "/etc/nginx/nginx.conf"
TLS_CRT = "/etc/nginx/tls/server.crt"
TLS_KEY = "/etc/nginx/tls/server.key"
WEBROOT = "/usr/share/nginx/html"
HTTP_PORT = 8080   # in-container ports are unprivileged -> no NET_BIND_SERVICE needed
HTTPS_PORT = 8443


def _onoff(flag: bool) -> str:
    return "on" if flag else "off"


def _prelude(p: Profile) -> list[str]:
    h = p.http
    lines = [
        "worker_processes 1;",
        "pid /tmp/nginx.pid;",
        "error_log /dev/stderr warn;",
        "events { worker_connections 256; }",
        "http {",
        "    include /etc/nginx/mime.types;",
        "    default_type application/octet-stream;",
        "    access_log /dev/stdout;",
        "    client_body_temp_path /tmp/client_body;",
        "    proxy_temp_path /tmp/proxy;",
        "    fastcgi_temp_path /tmp/fastcgi;",
        "    uwsgi_temp_path /tmp/uwsgi;",
        "    scgi_temp_path /tmp/scgi;",
        "    sendfile on;",
        f"    server_tokens {_onoff(h.server_tokens)};",
        f"    client_max_body_size {h.client_max_body_size};",
    ]
    if h.tight_timeouts:
        lines += [
            "    keepalive_timeout 15s;",
            "    client_header_timeout 10s;",
            "    client_body_timeout 10s;",
            "    send_timeout 10s;",
            "    large_client_header_buffers 4 8k;",
        ]
    if h.rate_limit_rps:
        lines += [
            f"    limit_req_zone $binary_remote_addr zone=perip:1m rate={h.rate_limit_rps}r/s;",
            "    limit_req_status 429;",
        ]
    return lines


def _guards(p: Profile, indent: str = "        ") -> list[str]:
    h = p.http
    out = [f'{indent}add_header {k} "{v}" always;' for k, v in h.headers]
    if h.allowed_methods:
        out.append(f"{indent}if ($request_method !~ ^({'|'.join(h.allowed_methods)})$) {{ return 405; }}")
    if h.rate_limit_rps:
        out.append(f"{indent}limit_req zone=perip burst={h.rate_limit_rps * 2} nodelay;")
    if h.deny_dotfiles:
        out.append(f"{indent}location ~ /\\. {{ deny all; }}")
    return out


def _proxy_location(upstream: str) -> list[str]:
    return [
        "        location / {",
        f"            proxy_pass http://{upstream}:{HTTP_PORT};",
        "            proxy_http_version 1.1;",
        "            proxy_set_header Host $host;",
        "            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
        "            proxy_set_header X-Forwarded-Proto $scheme;",
        "            proxy_hide_header X-Powered-By;",
        "        }",
    ]


def render_edge(p: Profile, upstream: str, public_https_port: int) -> str:
    t = p.tls
    lines = _prelude(p)
    lines += ["    server {", f"        listen {HTTP_PORT} default_server;", "        server_name _;"]
    if p.http.redirect_to_https:
        lines.append(f"        return 301 https://$host:{public_https_port}$request_uri;")
    else:
        lines += _guards(p) + _proxy_location(upstream)
    lines.append("    }")
    lines += [
        "    server {",
        f"        listen {HTTPS_PORT} ssl default_server;",
        "        http2 on;",
        "        server_name _;",
        f"        ssl_certificate {TLS_CRT};",
        f"        ssl_certificate_key {TLS_KEY};",
        f"        ssl_protocols {' '.join(t.protocols)};",
        f"        ssl_ciphers {t.ciphers};",
        f"        ssl_prefer_server_ciphers {_onoff(t.prefer_server_ciphers)};",
        f"        ssl_session_tickets {_onoff(t.session_tickets)};",
        "        ssl_session_cache shared:TLS:1m;",
        "        ssl_session_timeout 1h;",
    ]
    if t.ecdh_curve:
        lines.append(f"        ssl_ecdh_curve {t.ecdh_curve};")
    lines += _guards(p) + _proxy_location(upstream) + ["    }", "}", ""]
    return "\n".join(lines)


def render_app(p: Profile) -> str:
    lines = _prelude(p)
    lines += [
        "    server {",
        f"        listen {HTTP_PORT} default_server;",
        "        server_name _;",
        f"        root {WEBROOT};",
        "        index index.html;",
        f"        autoindex {_onoff(p.http.autoindex)};",
    ]
    if p.http.deny_dotfiles:
        lines.append("        location ~ /\\. { deny all; }")
    lines += ["    }", "}", ""]
    return "\n".join(lines)
