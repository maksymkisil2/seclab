# seclab

Local lab for hardening and audit practice. Python 3.11+ (stdlib only), Docker ≥ 28, openssl CLI.
`seclab web` also runs on Podman.

## Install
```sh
tar xzf seclab-*.tar.gz && cd seclab
pip install -e .            # optional: gives the `seclab` command; otherwise use `python3 -m seclab`
seclab images build         # seclab/node:0.2 (alpine + nftables, iproute2, openssh, socat, nc), once
./selftest/run.sh           # full self-test on real images
```

## Modes
| command | what |
|---|---|
| `seclab web …` | single two-tier web contour (edge TLS proxy → internal app) |
| `seclab lab …` | multi-segment scenario: segments, router/firewall (nftables), nodes, audit check |

Profiles (`seclab profiles`) drive everything at once: TLS, HTTP headers, sshd, container lockdown, firewall.

| | vulnerable | baseline | hardened |
|---|---|---|---|
| TLS | 1.0–1.3, `ALL:@SECLEVEL=0` | 1.2/1.3 Mozilla intermediate | 1.2/1.3 BSI TR-02102-2 (ECDHE-ECDSA AES-GCM) |
| HTTP | tokens, autoindex, `/.git`, `/backup`, no headers | redirect, HSTS, CSP, nosniff, XFO | strict CSP, COOP/CORP, Permissions-Policy, GET/HEAD, rate limit |
| sshd | root:toor, lab:lab, password, SHA-1/CBC | pubkey only, no root | BSI TR-02102-4 algorithms, no forwarding, tight limits |
| firewall | flat (forward accept) | default-deny + allow-list, stateful | + anti-spoofing (fib), counters |
| container | root, rw, default caps | non-root, ro rootfs, cap-drop ALL, no-new-privileges | same |

Always on: 64 MiB / 0.25 CPU / 64 PIDs per node, publish on 127.0.0.1 only, no egress from segments.

## Lab topology
```
127.0.0.1:<port> ─▶ [ingress] router ─DNAT─▶ node
                 segment ◀─▶ router ◀─▶ segment
```
Segments are Docker bridges with `gateway_mode_ipv4=routed`, no host IP, no masquerade.
Nodes get their default route via the router (one-shot `netinit` container, nodes keep zero caps).
Router: `cap-drop ALL` + `NET_ADMIN`, read-only. Its `boundary` chain drops anything to/from outside the lab.
Traffic inside one segment is L2 and not filtered by the router (by design, as in real networks).

## Training loop
```sh
seclab lab list
seclab lab up dmz --profile vulnerable          # deploy weak target
seclab lab check --name dmz                     # audit vs target policy -> FAIL rows = findings, exit 2
seclab lab fw show --name dmz                   # live ruleset with counters
$EDITOR ~/.seclab/labs/dmz/router.nft           # fix the firewall yourself
seclab lab fw apply --name dmz                  # validated (nft -c) then applied atomically
seclab lab check --name dmz                     # repeat until 0 findings
seclab lab fw apply --name dmz --level hardened # or load the reference solution (target.nft)
seclab lab reset --name dmz                     # back to the deployed profile
seclab lab down --name dmz --purge
```
`fw apply` is authoritative: every table except Docker's own is replaced.
Ports clash between labs → `--port-offset 1000`.

Access:
- web: `curl --cacert ~/.seclab/labs/dmz/tls/ca.crt https://localhost:8443/`
- ssh (vulnerable): `ssh -p 2222 root@127.0.0.1` (toor)
- ssh (baseline/hardened): `ssh -i ~/.seclab/labs/dmz/ssh/id_ecdsa -p 2222 lab@127.0.0.1`
- shell on a node: `docker exec -it seclab-dmz-bastion sh` (router: `seclab-dmz-router`)

## Scenarios (`seclab/scenarios/*.toml`, or any file: `seclab lab up ./my.toml`)
- `dmz`: web proxy in DMZ, app/db/cache internal, ssh bastion in mgmt
- `office`: staff LAN, server zone, isolated guest network, admin jump host

```toml
name = "mini"
[segments]
front = "10.95.1.0/24"
back = "10.95.2.0/24"
[nodes.proxy]                # roles: web-proxy (upstream=web-static), web-static, service (port=N), ssh
role = "web-proxy"
segment = "front"
upstream = "site"
[nodes.site]
role = "web-static"
segment = "back"
[[forward]]                  # 127.0.0.1:host_port -> node:port via router DNAT
host_port = 18443
node = "proxy"
port = 8443
[[allow]]                    # target policy; from/to = segment or node
from = "proxy"
to = "site"
ports = [8080]
```

## Self-test
```sh
./selftest/run.sh          # real images; pulls nginx:1.27-alpine and alpine:3.20 (for the node build)
./selftest/run.sh --stub   # offline: scratch stub (Go) + host nft; skips nginx/sshd semantics
```
