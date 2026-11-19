#!/usr/bin/env bash
# seclab installer for Linux (Debian/Ubuntu, Fedora, Arch) and for the WSL2 side of install.ps1.
#
#   ./install/install.sh               engine + Docker + images + desktop app (if a build is in dist/)
#   ./install/install.sh --no-docker   do not install/upgrade Docker (must already be >= 28)
#   ./install/install.sh --no-desktop  engine only
#   ./install/install.sh --wsl         called by install.ps1 inside WSL (root, systemd required)
#   ./install/install.sh --uninstall   remove engine, launcher and desktop entry (labs: seclab lab down --purge first)
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
WANT_DOCKER=1 WANT_DESKTOP=1 WSL=0 UNINSTALL=0
for arg in "$@"; do
    case "$arg" in
        --no-docker) WANT_DOCKER=0 ;;
        --no-desktop) WANT_DESKTOP=0 ;;
        --wsl) WSL=1 WANT_DESKTOP=0 ;;
        --uninstall) UNINSTALL=1 ;;
        *) echo "unknown option: $arg" >&2; exit 2 ;;
    esac
done

if [ "$(id -u)" -eq 0 ]; then
    SUDO="" PREFIX=${SECLAB_PREFIX:-/opt/seclab} BINDIR=/usr/local/bin
    APPDIR=/usr/share/applications
else
    SUDO="sudo" PREFIX=${SECLAB_PREFIX:-$HOME/.local/share/seclab} BINDIR=$HOME/.local/bin
    APPDIR=$HOME/.local/share/applications
fi

say()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarn:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

if [ "$UNINSTALL" -eq 1 ]; then
    rm -rf "$PREFIX" "$BINDIR/seclab" "$APPDIR/seclab.desktop"
    say "removed engine from $PREFIX (Docker and ~/.seclab labs left untouched)"
    exit 0
fi

pkg_install() {
    if command -v apt-get >/dev/null; then $SUDO apt-get update -qq && $SUDO apt-get install -y -qq "$@"
    elif command -v dnf >/dev/null; then $SUDO dnf install -y -q "$@"
    elif command -v pacman >/dev/null; then $SUDO pacman -Sy --noconfirm --needed "$@"
    else die "no supported package manager (apt, dnf, pacman); install manually: $*"
    fi
}

# ---- 1. Python >= 3.11 ------------------------------------------------------------------------
python_ok() { command -v python3 >/dev/null && python3 -c 'import sys, venv; sys.exit(sys.version_info < (3, 11))' 2>/dev/null; }
if ! python_ok; then
    say "installing Python 3 (>= 3.11) + venv"
    if command -v apt-get >/dev/null; then pkg_install python3 python3-venv; else pkg_install python3; fi
    python_ok || die "Python >= 3.11 with venv is required (found: $(python3 --version 2>&1 || echo none))"
fi
if command -v apt-get >/dev/null && ! python3 -c 'import ensurepip' 2>/dev/null; then pkg_install python3-venv; fi

# ---- 2. Docker >= 28 -------------------------------------------------------------------------
docker_major() { docker version --format '{{.Server.Version}}' 2>/dev/null | cut -d. -f1; }
if [ "$WSL" -eq 1 ] && [ "$(ps -p 1 -o comm= 2>/dev/null)" != "systemd" ]; then
    die "systemd is not running in this WSL distro (install.ps1 enables it; run 'wsl --shutdown' and retry)"
fi
if [ "$WANT_DOCKER" -eq 1 ]; then
    major=$(docker_major || true)
    if [ -z "$major" ] || [ "$major" -lt 28 ]; then
        command -v curl >/dev/null || pkg_install curl
        say "installing Docker Engine (get.docker.com); found server major='${major:-none}'"
        curl -fsSL https://get.docker.com | $SUDO sh
    fi
    $SUDO systemctl enable --now docker >/dev/null 2>&1 || $SUDO service docker start || true
fi
DOCKER="docker"
if [ "$(id -u)" -ne 0 ] && ! docker info >/dev/null 2>&1; then
    if ! id -nG "$USER" | grep -qw docker; then
        say "adding $USER to the docker group (log out and back in once afterwards)"
        $SUDO usermod -aG docker "$USER"
    fi
    DOCKER="sg docker -c"
fi
major=$(docker_major 2>/dev/null || $SUDO docker version --format '{{.Server.Version}}' | cut -d. -f1)
[ "${major:-0}" -ge 28 ] || die "Docker server >= 28 required (found '${major:-none}')"

# ---- 3. engine (venv, no system site-packages) --------------------------------------------------
if ! ls "$ROOT"/seclab/bin/seclab-agent-linux-* >/dev/null 2>&1; then
    command -v go >/dev/null || die "seclab/bin is empty and Go is missing: use a release archive or install Go >= 1.24"
    say "building seclab-agent"
    "$ROOT/agent/build.sh" >/dev/null
fi
say "installing engine into $PREFIX"
mkdir -p "$PREFIX" "$BINDIR"
python3 -m venv --clear "$PREFIX/venv"
"$PREFIX/venv/bin/pip" install -q --upgrade pip
"$PREFIX/venv/bin/pip" install -q "$ROOT"
ln -sf "$PREFIX/venv/bin/seclab" "$BINDIR/seclab"
case ":$PATH:" in *":$BINDIR:"*) ;; *) warn "$BINDIR is not in PATH; add it to your shell profile" ;; esac

# ---- 4. images ------------------------------------------------------------------------------
say "building lab images (first run downloads alpine + nginx, ~60 MB)"
if [ "$DOCKER" = "docker" ]; then
    "$PREFIX/venv/bin/seclab" images build
else
    sg docker -c "'$PREFIX/venv/bin/seclab' images build"
fi

# ---- 5. desktop app ---------------------------------------------------------------------------
if [ "$WANT_DESKTOP" -eq 1 ]; then
    appimage=$(ls "$ROOT"/dist/seclab-*.AppImage 2>/dev/null | sort -V | tail -1 || true)
    icon="$ROOT/desktop/build/icon.png"
    mkdir -p "$APPDIR"
    if [ -n "$appimage" ]; then
        install -m 0755 "$appimage" "$PREFIX/seclab.AppImage"
        exec_line="env SECLAB_BIN=$PREFIX/venv/bin/seclab $PREFIX/seclab.AppImage"
        say "desktop app installed: $PREFIX/seclab.AppImage"
    else
        cat > "$PREFIX/seclab-open" <<EOF
#!/usr/bin/env sh
# Fallback launcher without the Electron build: start the UI and open it in the default browser.
"$PREFIX/venv/bin/seclab" ui --port 0 --json | while read -r line; do
    url=\$(printf '%s' "\$line" | sed -n 's/.*"url": "\([^"]*\)".*/\1/p')
    [ -n "\$url" ] && xdg-open "\$url" >/dev/null 2>&1 &
done
EOF
        chmod 0755 "$PREFIX/seclab-open"
        exec_line="$PREFIX/seclab-open"
        warn "no Electron build in dist/ (see desktop/README); installed browser launcher instead"
    fi
    install -m 0644 "$icon" "$PREFIX/icon.png"
    cat > "$APPDIR/seclab.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=seclab
Comment=Corporate network lab: administration and security training
Exec=$exec_line
Icon=$PREFIX/icon.png
Terminal=false
Categories=Development;Network;Security;
EOF
fi

# ---- 6. self-check ---------------------------------------------------------------------------
"$PREFIX/venv/bin/seclab" lab list >/dev/null
say "done. Start: the 'seclab' app in your menu, or 'seclab ui'. Self-test: ./selftest/run.sh"
