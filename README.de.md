# seclab

[English](README.md) · **Deutsch**

Lokaler Simulator eines Unternehmensnetzes für Administration und Sicherheitsübungen: segmentierte Netze mit
einem nftables-Router, generierte Firmen beliebiger Größe, verwundbare Webanwendungen mit Schwierigkeitsstufen
und Flags, Erreichbarkeits-Audit, Desktop-App. Python 3.11+ (nur Standardbibliothek), Docker ≥ 28,
Go-Agent (statische Binärdatei). `seclab web` läuft auch unter Podman.

## Installation

Release-Archiv (Engine, Agent-Binärdateien, Desktop-Installer in `dist/`):

| Betriebssystem | Befehl | Ergebnis |
|---|---|---|
| Windows 10/11 | `powershell -ExecutionPolicy Bypass -File .\install\install.ps1` (als Administrator) | WSL2-Distribution `seclab` mit Docker Engine + Engine, App **seclab** im Startmenü |
| Linux | `./install/install.sh` | Docker ≥ 28 (bei Bedarf über get.docker.com), Engine in `~/.local/share/seclab`, App **seclab** im Menü |

Voraussetzungen: 8 GB RAM genügen für kleine Netze, 16 GB für die größten generierten (≤ 40 Container,
je 64 MiB Obergrenze, typisch ~12 MiB). Internet wird einmalig benötigt (Docker, Alpine, nginx).

Aus dem Quellcode: `./agent/build.sh` (Go ≥ 1.24) → `pip install -e .` → `seclab images build`.
Desktop-App: `cd desktop && npm install && npm run dist` (oder aus den CI-Artefakten beziehen).

## Desktop-App

Electron-Hülle um die lokale Oberfläche. Unter Linux startet sie `seclab ui` direkt; unter Windows startet sie
es innerhalb von WSL2 (`wsl.exe -d seclab -u root -- seclab ui …`). Die Engine stoppt beim Schließen des
Fensters (stdin-EOF). Das Fenster zeigt nur die lokale Oberfläche; jeder andere Link öffnet sich im
Systembrowser. Kein Electron? `seclab ui` liefert dieselbe Oberfläche in jedem Browser.

## Generator für Unternehmensnetze

```sh
seclab lab generate --departments 3 --hosts-per-dept 2 --sites 3 --public-sites 1 --mail true --seed 7
seclab lab up ~/.seclab/specs/corp.toml --profile vulnerable --difficulty medium
```
Oberfläche: *Generate corporate network* (laufende Schätzung von Containern/RAM, ungültige Größen werden vor
dem Start abgelehnt).

| Segment | Inhalt |
|---|---|
| dmz | öffentliche Reverse-Proxys (TLS) für öffentliche Sites |
| servers | Intranet-Sites (verwundbare Webanwendung), Datenbank :5432, Dateiserver :445, Mail :25 |
| je Abteilung | Arbeitsstationen (sshd) |
| mgmt | Admin-Sprunghost (Jump Host) |
| guest | Gastnetz, kein Zugriff auf irgendetwas |

Zielrichtlinie: Abteilungen → Sites/Dateien/Mail, Sites → Datenbank, Proxys → ihre Site, Jump Host → Arbeitsstationen.

## Schwierigkeit

Gilt für das Profil `vulnerable` (`baseline` / `hardened` stellen sichere Anwendungen und die Ziel-Firewall bereit):

| | easy | medium | hard |
|---|---|---|---|
| Firewall | flach (any → any) | Zielrichtlinie + 6 eingebaute Lücken | Zielrichtlinie + 2 eingebaute Lücken |
| Webanwendungen | rohes SQLi/XSS/IDOR/Traversal, ausführliche SQL-Fehler, admin:admin, vertrautes Rollen-Cookie | naive Filter (Umgehung: `#`-Kommentare, `<img onerror>`, `....//`), geleakte Backup-Zugangsdaten | stärkere Filter (Umgehung: `/**/`-Kommentare, Attribut-Ausbruch, Base64-Referenzen, doppelte URL-Kodierung) |

Eingebaute Lücken und Flags leiten sich aus `--seed` ab: gleicher Seed, gleiches Lab. `lab check` listet genau
die Lücken auf.

### Verwundbarkeitstypen

Über die Stufe hinaus lassen sich die Verwundbarkeitsklassen jeder Site einzeln an- und abschalten: `sqli`,
`xss`, `idor`, `traversal`, `admin`. Eine deaktivierte Klasse verhält sich unabhängig von der Stufe wie gehärtet.
```sh
seclab lab up corp --profile vulnerable --difficulty easy --vulns idor,traversal   # nur diese beiden
seclab lab up corp --profile vulnerable --vulns none                               # alle Klassen sicher
```
Oberfläche: Kontrollkästchen *site vulns* im Generatorformular (Standard: alle an).

## Flags

Jede verwundbare Site (`seclab-agent vulnweb`) verbirgt 4 Flags: `sqli` (secrets-Tabelle via UNION),
`idor` (Notiz eines anderen Nutzers), `traversal` (Datei außerhalb des Web-Roots), `admin` (Admin-Panel).
```sh
seclab lab flag --name corp 'FLAG{sqli-…}'
seclab lab score --name corp
```
Oberfläche: Reiter *Flags*. Flags sind pro Lab eindeutig (HMAC aus Name + Seed); `docker inspect` kann sie
offenlegen: fair bleiben.

## Angriffe (die eigene Verteidigung prüfen)

Ein eingebauter Exploit-Katalog führt die Übungstechniken gegen die **eigenen** Sites des Labs aus und meldet,
welche greifen; erbeutete Flags gehen in die Wertung. Ziel ist ausschließlich `127.0.0.1:<weitergeleiteter Port>`
des aktuellen Labs — jeder andere Host wird abgelehnt.
```sh
seclab lab attack --name corp                 # alle Kategorien
seclab lab attack --name corp --only sqli,idor
```
Oberfläche: Reiter *Attacks* — Kategorien wählen, *Run attacks*, Ergebnistabelle lesen. Kategorien: `sqli`,
`idor`, `traversal`, `admin`, `creds`.

## Erkennung (Blue Team)

Eine Erkennungs-Engine (`seclab-agent monitor`) sammelt die Logs des Labs — Site-Zugriffslogs, sshd-Auth-Zeilen,
den Firewall-Drop-Zähler des Routers —, normalisiert sie zu Ereignissen und wendet Regeln mit Signaturen,
Schwellenwerten über gleitende Zeitfenster und MITRE-ATT&CK-Zuordnung an. Führe einen Angriff oder ein Audit aus,
dann die Erkennung: Die Versuche erscheinen als Meldungen (Alerts), **auch wenn die gehärtete Verteidigung sie
geblockt hat**.
```sh
seclab lab detect --name corp                  # alle Alerts
seclab lab detect --name corp --min-severity high
```
Oberfläche: Reiter *Detection* — *Run detection*, die Alerts lesen (Schweregrad, Regel, ATT&CK, Quelle, Beleg).

| Regel | Signal | Schweregrad | ATT&CK |
|---|---|---|---|
| http-sqli / http-traversal / http-xss | Angriffssignatur in einer einzelnen Anfrage | high / high / medium | T1190 / T1083 / T1059 |
| http-enum | Häufung von 401/403/404 oder Durchprobieren von Notizen aus einer Quelle | medium | T1595 |
| http-admin-probe | wiederholte Zugriffe auf /admin, /backup, robots.txt | medium | T1595 |
| ssh-bruteforce | ≥5 fehlgeschlagene Logins aus einer Quelle in 60 s | high | T1110 |
| ssh-root-login | erfolgreicher Root-Login über SSH | medium | T1078 |
| fw-denied-flows | ≥10 geblockte segmentübergreifende Pakete (Scan / laterale Bewegung) | high | T1046 |

Die Erkennung arbeitet im Stapel (sammeln und auswerten), wie Audit und Angriffe; sie nutzt die seit dem Start
des Labs angesammelten Logs (`reset` setzt die Ausgangsbasis zurück).

## Betriebsarten
| Befehl | Zweck |
|---|---|
| `seclab web …` | einzelne zweistufige Web-Kontur (TLS-Edge-Proxy → interne Anwendung) |
| `seclab lab …` | mehrsegmentiges Szenario: Segmente, Router/Firewall (nftables), Knoten, Audit |

Profile (`seclab profiles`) steuern alles auf einmal: TLS, HTTP-Header, sshd, Container-Härtung, Firewall.

| | vulnerable | baseline | hardened |
|---|---|---|---|
| TLS | 1.0–1.3, `ALL:@SECLEVEL=0` | 1.2/1.3 Mozilla intermediate | 1.2/1.3 BSI TR-02102-2 (ECDHE-ECDSA AES-GCM) |
| HTTP | Tokens, autoindex, `/.git`, `/backup`, keine Header | Redirect, HSTS, CSP, nosniff, XFO | strenge CSP, COOP/CORP, Permissions-Policy, GET/HEAD, Rate-Limit |
| sshd | root:toor, lab:lab, Passwort, SHA-1/CBC | nur Public Key, kein Root | Algorithmen nach BSI TR-02102-4, kein Forwarding, enge Limits |
| Firewall | flach (forward accept) | default-deny + Allowlist, zustandsbehaftet | + Anti-Spoofing (fib), Zähler |
| Container | root, rw, Standard-Caps | non-root, ro-Rootfs, cap-drop ALL, no-new-privileges | ebenso |

Immer aktiv: 64 MiB / 0,25 CPU / 64 PIDs pro Knoten, Veröffentlichung nur auf 127.0.0.1, kein Ausgang aus den
Segmenten.

## Web-Oberfläche
```sh
seclab ui                   # gibt http://127.0.0.1:8765/#t=<token> aus; genau diese URL öffnen
```
Szenarien mit einem Profil starten, Labs und Container ansehen, Topologie mit Audit-Verdikt je Knoten, Audit
ausführen, das Router-Regelwerk bearbeiten/prüfen/anwenden, reset/down/purge.
Die Oberfläche steuert Docker und ist deshalb abgeschottet: nur 127.0.0.1, Token pro Lauf (im URL-Fragment, nie
geloggt), Host-Header-Prüfung gegen DNS-Rebinding, POST nur als JSON, strenge CSP, keine externen Ressourcen.

## Lab-Topologie
```
127.0.0.1:<Port> ─▶ [ingress] Router ─DNAT─▶ Knoten
                 Segment ◀─▶ Router ◀─▶ Segment
```
Segmente sind Docker-Bridges mit `gateway_mode_ipv4=routed`, ohne Host-IP, ohne Masquerade.
Knoten erhalten ihre Standardroute über den Router (einmaliger `netinit`-Container, Knoten behalten keinerlei
Capabilities). Router: `cap-drop ALL` + `NET_ADMIN`, nur lesbar. Seine `boundary`-Kette verwirft alles von/zu
außerhalb des Labs. Verkehr innerhalb eines Segments ist L2 und wird vom Router nicht gefiltert (so gewollt,
wie in echten Netzen).

## Übungsablauf
```sh
seclab lab list
seclab lab up dmz --profile vulnerable          # schwaches Ziel ausrollen
seclab lab check --name dmz                     # Audit gegen Zielrichtlinie -> FAIL-Zeilen = Funde, exit 2
seclab lab fw show --name dmz                   # aktives Regelwerk mit Zählern
$EDITOR ~/.seclab/labs/dmz/router.nft           # die Firewall selbst korrigieren
seclab lab fw apply --name dmz                  # geprüft (nft -c), dann atomar angewendet
seclab lab check --name dmz                     # wiederholen, bis 0 Funde
seclab lab fw apply --name dmz --level hardened # oder die Musterlösung laden (target.nft)
seclab lab reset --name dmz                     # zurück zum ausgerollten Profil
seclab lab down --name dmz --purge
```
`fw apply` ist maßgeblich: jede Tabelle außer Dockers eigener wird ersetzt.
Portkonflikt zwischen Labs → `--port-offset 1000`.

Zugriff:
- Web: `curl --cacert ~/.seclab/labs/dmz/tls/ca.crt https://localhost:8443/`
- SSH (vulnerable): `ssh -p 2222 root@127.0.0.1` (toor)
- SSH (baseline/hardened): `ssh -i ~/.seclab/labs/dmz/ssh/id_ecdsa -p 2222 lab@127.0.0.1`
- Shell auf einem Knoten: `docker exec -it seclab-dmz-bastion sh` (Router: `seclab-dmz-router`)

## Szenarien (`seclab/scenarios/*.toml` oder eine beliebige Datei: `seclab lab up ./my.toml`)
- `dmz`: Web-Proxy in der DMZ, App/DB/Cache intern, SSH-Bastion in mgmt
- `office`: Mitarbeiter-LAN, Serverzone, isoliertes Gastnetz, Admin-Jump-Host
- generiert: beliebige Größe, siehe *Generator für Unternehmensnetze*

```toml
name = "mini"
[segments]
front = "10.95.1.0/24"
back = "10.95.2.0/24"
[nodes.proxy]                # Rollen: web-proxy (upstream=web-static|vulnweb), web-static, vulnweb (title=…),
                             #         service (port=N), ssh
role = "web-proxy"
segment = "front"
upstream = "site"
[nodes.site]
role = "web-static"
segment = "back"
[[forward]]                  # 127.0.0.1:host_port -> node:port via Router-DNAT
host_port = 18443
node = "proxy"
port = 8443
[[allow]]                    # Zielrichtlinie; from/to = Segment oder Knoten
from = "proxy"
to = "site"
ports = [8080]
```

## Roadmap
Als geordnete Checkliste in [ROADMAP.md](ROADMAP.md) (Englisch): zuerst die Qualität des Kerns, dann
Admin-Dienste (DNS, DHCP, Mail, SMB-Freigaben), Web-Angriffe, Blue Team, eine Samba-AD-Domäne und die
Desktop-Oberfläche. Ein [automatisierter Workflow](.github/autodev/AGENT.md) nimmt an jedem Werktag die erste
offene Aufgabe und schlägt sie als Pull Request vor; jede Änderung wird von Hand geprüft und gemergt.

## Selbsttest
```sh
./selftest/run.sh          # echte Images; lädt nginx:1.27-alpine und alpine:3.20 (für den Node-Build)
./selftest/run.sh --stub   # offline: Scratch-Stub (Go) + Host-nft; überspringt nginx/sshd-Semantik
pip install playwright && playwright install chromium   # optional: aktiviert den Browser-UI-Test
python3 selftest/bench.py  # Laufzeitmessung eines Netzes mit 23 Containern (Stub-Images)
```
