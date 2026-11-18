# seclab

Local lab for hardening and audit practice. Python 3.10+ stdlib only, docker or podman CLI, openssl CLI.

## Layout
```
seclab/
  runtime.py    docker/podman CLI wrapper
  profiles.py   vulnerable | baseline | hardened  (TLS, HTTP, container policy)
  nginx.py      nginx.conf rendering (edge TLS proxy, app origin)
  pki.py        per-lab CA (P-384) + server cert (P-256, SAN localhost/127.0.0.1)
  web.py        web contour lifecycle: up / down / reset / status
  cli.py
tests/
  test_unit.py         offline
  test_integration.py  live (docker/podman)
selftest/
  run.sh               unit + integration (+ --stub for offline)
  stub/                scratch image stand-in for nginx/alpine (no registry)
```

## Web contour
```
127.0.0.1:{http,https} -> [edge] web (nginx TLS proxy) -> [backend, --internal] app (nginx static)
```
Every profile: 64 MiB RAM, swap off, 0.25 CPU, 64 PIDs, published on 127.0.0.1 only.

| profile | TLS | HTTP | container |
|---|---|---|---|
| vulnerable | TLS1.0-1.3, `ALL:@SECLEVEL=0` | server_tokens, autoindex, no headers, no redirect, exposed `/.git`, `/backup` | root, rw rootfs, all default caps |
| baseline | TLS1.2/1.3 Mozilla intermediate | redirect, HSTS, CSP, nosniff, XFO, Referrer-Policy | uid 101, ro rootfs, cap-drop ALL, no-new-privileges |
| hardened | TLS1.2/1.3 BSI TR-02102-2 (ECDHE-ECDSA AES-GCM, P-384/P-256), no tickets | + strict CSP, COOP/CORP, Permissions-Policy, GET/HEAD only, 10 r/s limit, timeouts | same as baseline |

## Usage
```sh
python3 -m seclab profiles
python3 -m seclab web up --lab demo --profile hardened        # 127.0.0.1:8080 / 8443
python3 -m seclab web status
python3 -m seclab web reset --lab demo
python3 -m seclab web down --lab demo --purge
python3 -m seclab web render --profile vulnerable --role edge
```
State: `$SECLAB_HOME` (default `~/.seclab/labs/<lab>`). CA for clients: `~/.seclab/labs/<lab>/tls/ca.crt`.
Env: `SECLAB_RUNTIME=docker|podman`, `SECLAB_WEB_IMAGE`, `SECLAB_PROBE_IMAGE`.

## Self-test
```sh
./selftest/run.sh          # real nginx:1.27-alpine + alpine:3.20
./selftest/run.sh --stub   # offline, needs Go; skips nginx-semantic checks
```
