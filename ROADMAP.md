# Roadmap

Small, ordered tasks that bring seclab to a finished, verifiable state: a
lightweight CLI for a local training lab built only from minimal containers
with hard resource limits and documented hardening. Core first; the desktop
UI follows the core.

Each task fits into one working session and is done only when its acceptance
criterion is covered by an automated check that passes in CI. Rules for every
task: no features outside this list, no secrets in the repository, update the
README (English and German) where behaviour changes, and tick the box in the
same pull request.

## P1 — Core: green and checked

- [x] **Fix the failing integration test.** `tests/test_integration.py::test_https_headers` expects `"server: nginx\r"`, but the captured headers end in `\n`. Compare header lines instead of raw text, so the check works with either line ending. The *integration* job is green.
- [x] **Linting in CI.** Add a `[tool.ruff]` configuration to `pyproject.toml`, fix the current findings, and run `ruff check` in the *unit* job.
- [ ] **Formatting in CI.** Apply `ruff format` to the whole code base in one commit that changes nothing else, add the commit to `.git-blame-ignore-revs`, and run `ruff format --check` in the *unit* job.
- [ ] **Type checking in CI.** Add mypy for the `seclab` package (start non-strict, `disallow_untyped_defs` for new modules) and run it in the *unit* job. Fix every error.
- [ ] **Pinned and current actions.** Pin every GitHub Action to a commit SHA with a version comment, move to releases that run on Node 24, and add `.github/dependabot.yml` for actions, pip, gomod and npm.
- [ ] **Python version matrix.** The Python unit tests run on 3.11, 3.12 and 3.13, matching `requires-python`.
- [ ] **Resource-limit invariant.** A unit test builds the container specifications of every built-in scenario and of generated networks (smallest and largest size) and asserts for each container: memory limit, equal swap limit, pids limit, CPU limit, `--cap-drop ALL`, `no-new-privileges`. A container without a limit fails the test.
- [ ] **Image policy.** A unit test asserts that every image seclab builds or pulls is Alpine-based or `FROM scratch` with a static binary. The policy and its reason are recorded in `docs/adr/0001-image-policy.md`.
- [ ] **Host budget check.** `seclab lab up` refuses to start when the sum of memory limits exceeds a budget (default: half of the host RAM, configurable). Unit test with a mocked host.
- [ ] **`seclab doctor`.** A command that checks runtime and version (Docker ≥ 28 or Podman), nftables, free RAM and free ports, and prints one line per check with a fix hint. Unit tests with a mocked runtime.
- [ ] **Hardening traceability.** `docs/HARDENING.md` maps every control applied by the profiles (container flags, nginx TLS and headers, sshd settings, firewall policy) to CIS Docker Benchmark, OWASP Secure Headers or BSI TR-02102-2. A unit test asserts that every control in `profiles.py`, `hardening.py` and `sshd.py` has a row.

## P2 — Administration services

- [ ] **DNS.** An optional DNS service (Alpine, `unbound` or `dnsmasq`) in the *servers* segment serves the lab's host names; generator option `--dns`. Integration test resolves every host name from a workstation.
- [ ] **DHCP.** An optional `dnsmasq` DHCP service on a dedicated training segment; a client container gets a lease with `udhcpc`. Integration test checks the lease range and the advertised DNS server.
- [ ] **Mail.** Replace the placeholder on port 25 with Postfix on Alpine. The *vulnerable* profile is an open relay, *hardened* rejects relaying and offers STARTTLS. Integration test asserts both behaviours.
- [ ] **File shares.** Replace the placeholder on port 445 with Samba on Alpine. *Hardened*: SMB1 off, signing required, no guest access; *vulnerable*: guest share. Integration test with `smbclient`.

## P3 — Web attacks

- [ ] **Command injection and SSRF in vulnweb.** Two new vulnerability classes, simulated inside the agent (no real shell, no real outbound requests), with easy, medium and hard variants and a flag each. Go tests extend the exploit matrix.
- [ ] **CSRF and open redirect in vulnweb.** Same structure as the task above.
- [ ] **Attack runner coverage.** `seclab lab attack` includes exploits for the four new classes; Go tests assert that each exploit succeeds on *easy* and fails when the class is disabled.

## P4 — Monitoring and blue team

- [ ] **Central log collection.** A syslog collector (Alpine) receives logs from nginx, sshd, the router and the new services; `seclab lab detect` reads from it. Integration test asserts that a login attempt on a workstation reaches the collector.
- [ ] **Detection rules for the new attacks.** Rules for the four new web classes and for mail relay abuse, each mapped to a MITRE ATT&CK technique. Go tests with recorded log samples.
- [ ] **Incident drill.** `seclab lab drill <scenario>` runs a scripted attack, then checks which steps the detection engine reported, and prints a score. Unit tests for the scoring.

## P5 — Domain (Active Directory)

- [ ] **Samba AD domain controller.** Optional service on Alpine (`samba-dc`) with its own documented memory limit; provisions a domain with seeded users and groups from `--seed`. Integration test with `ldapsearch` and `kinit`.
- [ ] **Domain logins on workstations.** Workstations authenticate SSH logins against the domain (Kerberos). Integration test logs in with a seeded domain user.

## P6 — Desktop UI (after the core)

- [ ] **New services in the UI.** The generator form exposes DNS, DHCP, mail, shares and the domain with the live resource estimate. Playwright test in `tests/test_ui_e2e.py`.
