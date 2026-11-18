#!/usr/bin/env sh
# seclab self-test.
#   ./selftest/run.sh          unit + integration on nginx:1.27-alpine / alpine:3.20 (pulls if needed)
#   ./selftest/run.sh --stub   unit + integration on a locally built scratch stub (no registry needed)
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
RT=${SECLAB_RUNTIME:-$(command -v docker >/dev/null 2>&1 && echo docker || echo podman)}

echo "== unit"
python3 -m pytest -q tests/test_unit.py

if [ "${1:-}" = "--stub" ]; then
    echo "== build stub image"
    (cd selftest/stub && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o stub . \
        && "$RT" build -q -t seclab/stub:local . >/dev/null)
    export SECLAB_STUB=1 SECLAB_WEB_IMAGE=seclab/stub:local SECLAB_PROBE_IMAGE=seclab/stub:local
fi

echo "== integration (${SECLAB_WEB_IMAGE:-nginx:1.27-alpine})"
SECLAB_HOME=$(mktemp -d)
export SECLAB_HOME
trap 'rm -rf "$SECLAB_HOME"' EXIT
python3 -m pytest -q -rs tests/test_integration.py

echo "== leftovers"
left=$("$RT" ps -aq --filter label=seclab.managed=1; "$RT" network ls -q --filter label=seclab.managed=1)
[ -z "$left" ] && echo "none" || { echo "FAIL: leftover resources: $left"; exit 1; }
