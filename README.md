# seclab

Local corporate-network simulator for administration and security practice: segmented networks with an
nftables router, generated companies of configurable size, vulnerable web apps with difficulty levels and
flags, reachability audit, desktop app. Python 3.11+ (stdlib only), Docker ≥ 28, Go agent (static binary).
`seclab web` also runs on Podman.

## Install

Release archive (engine, agent binaries, desktop installers in `dist/`):

| OS | command | result |
|---|---|---|
| Windows 10/11 | `powershell -ExecutionPolicy Bypass -File .\install\install.ps1` (as Administrator) | WSL2 distro `seclab` with Docker Engine + engine, **seclab** app in Start menu |
| Linux | `./install/install.sh` | Docker ≥ 28 (get.docker.com if needed), engine in `~/.local/share/seclab`, **seclab** app in the menu |

Requirements: 8 GB RAM is enough for small networks, 16 GB for the largest generated ones (≤ 40 containers,
64 MiB cap each, ~12 MiB typical). Internet is needed once (Docker, alpine, nginx).

From source: `./agent/build.sh` (Go ≥ 1.24) → `pip install -e .` → `seclab images build`.
Desktop app: `cd desktop && npm install && npm run dist` (or take it from CI artifacts).

## Desktop app

Electron shell around the local UI. On Linux it starts `seclab ui` directly; on Windows it starts it inside
WSL2 (`wsl.exe -d seclab -u root -- seclab ui …`). The engine stops when the window closes (stdin EOF).
The window only shows the local UI; every other link opens in the system browser.
No Electron? `seclab ui` serves the same interface in any browser.

## Corporate network generator

```sh
seclab lab generate --departments 3 --hosts-per-dept 2 --sites 3 --public-sites 1 --mail true --seed 7
seclab lab up ~/.seclab/specs/corp.toml --profile vulnerable --difficulty medium
```
UI: *Generate corporate network* (live container/RAM estimate, invalid sizes are rejected before launch).

| segment | content |
|---|---|
| dmz | public reverse proxies (TLS) for public sites |
| servers | intranet sites (vulnerable web app), database :5432, file server :445, mail :25 |
| per department | workstations (sshd) |
| mgmt | admin jump host |
| guest | guest network, no access anywhere |

Target policy: departments → sites/files/mail, sites → database, proxies → their site, jump → workstations.

## Difficulty

Applies to the `vulnerable` profile (`baseline` / `hardened` deploy secure apps and the target firewall):

| | easy | medium | hard |
|---|---|---|---|
| firewall | flat (any → any) | target policy + 6 planted holes | target policy + 2 planted holes |
| web apps | raw SQLi/XSS/IDOR/traversal, verbose SQL errors, admin:admin, trusted role cookie | naive filters (bypass: `#` comments, `<img onerror>`, `....//`), leaked backup creds | stronger filters (bypass: `/**/` comments, attribute breakout, base64 refs, double URL-encoding) |

Planted holes and flags are derived from `--seed`: same seed, same lab. `lab check` lists exactly the holes.

### Vulnerability types

Beyond the level, each site's vulnerability classes can be toggled independently: `sqli`, `xss`, `idor`,
`traversal`, `admin`. A disabled class behaves as hardened regardless of level.
```sh
seclab lab up corp --profile vulnerable --difficulty easy --vulns idor,traversal   # only these two
seclab lab up corp --profile vulnerable --vulns none                               # all classes secure
```
UI: *site vulns* checkboxes on the generator form (default: all on).

## Flags

Every vulnerable site (`seclab-agent vulnweb`) hides 4 flags: `sqli` (secrets table via UNION),
`idor` (another user's note), `traversal` (file outside the web root), `admin` (admin panel).
```sh
seclab lab flag --name corp 'FLAG{sqli-…}'
seclab lab score --name corp
```
UI: *Flags* tab. Flags are per lab (HMAC of name + seed); `docker inspect` can reveal them: play fair.

## Attacks (validate your own defenses)

A built-in exploit catalogue runs the training techniques against your lab's **own** sites and reports
which land; captured flags go to the scoreboard. It targets only `127.0.0.1:<forwarded port>` of the
current lab — any other host is refused.
```sh
seclab lab attack --name corp                 # all categories
seclab lab attack --name corp --only sqli,idor
```
UI: *Attacks* tab — pick categories, *Run attacks*, read the results table. Categories: `sqli`, `idor`,
`traversal`, `admin`, `creds`.

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

## Web UI
```sh
seclab ui                   # prints http://127.0.0.1:8765/#t=<token>; open that exact URL
```
Launch scenarios with a profile, see labs and containers, topology with audit verdicts per node,
run the audit, edit/validate/apply the router ruleset, reset/down/purge.
The UI drives Docker, so it is locked down: 127.0.0.1 only, per-run token (URL fragment, never logged),
Host-header check against DNS rebinding, JSON-only POST, strict CSP, no external assets.

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
- generated: any size, see *Corporate network generator*

```toml
name = "mini"
[segments]
front = "10.95.1.0/24"
back = "10.95.2.0/24"
[nodes.proxy]                # roles: web-proxy (upstream=web-static|vulnweb), web-static, vulnweb (title=…),
                             #        service (port=N), ssh
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

## Roadmap
- phase 2: admin services (DNS, DHCP, mail, SMB shares) and a domain (Samba AD: users, groups, policies, Kerberos)
- phase 3: blue team (central logs, flow sensor / IDS on the router, alerts and incident drills)

## Self-test
```sh
./selftest/run.sh          # real images; pulls nginx:1.27-alpine and alpine:3.20 (for the node build)
./selftest/run.sh --stub   # offline: scratch stub (Go) + host nft; skips nginx/sshd semantics
pip install playwright && playwright install chromium   # optional: enables the browser UI test
python3 selftest/bench.py  # lifecycle timings on a 23-container network (stub images)
```
