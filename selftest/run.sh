#!/usr/bin/env sh
# seclab self-test.
#   ./selftest/run.sh          unit + integration on real images (nginx:1.27-alpine, seclab/node:0.2 built locally)
#   ./selftest/run.sh --stub   unit + integration on a locally built scratch stub (no registry; needs Go + host nft)
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
RT=${SECLAB_RUNTIME:-$(command -v docker >/dev/null 2>&1 && echo docker || echo podman)}

echo "== unit"
python3 -m pytest -q tests/test_unit.py tests/test_lab_unit.py tests/test_ui_unit.py

if [ "${1:-}" = "--stub" ]; then
    echo "== build stub image"
    ./selftest/stub/build.sh
    export SECLAB_STUB=1 SECLAB_WEB_IMAGE=seclab/stub:local SECLAB_PROBE_IMAGE=seclab/stub:local \
           SECLAB_NODE_IMAGE=seclab/stub:local
else
    echo "== images"
    "$RT" image inspect seclab/node:0.2 >/dev/null 2>&1 || python3 -m seclab images build
    export SECLAB_PROBE_IMAGE=${SECLAB_PROBE_IMAGE:-seclab/node:0.2}
fi

SECLAB_HOME=$(mktemp -d)
export SECLAB_HOME
trap 'rm -rf "$SECLAB_HOME"' EXIT
echo "== integration: web contour"
python3 -m pytest -q -rs tests/test_integration.py
echo "== integration: multi-segment labs"
python3 -m pytest -q -rs tests/test_lab_integration.py

echo "== integration: web UI (browser; skipped without playwright)"
python3 -m pytest -q -rs tests/test_ui_e2e.py

echo "== leftovers"
left=$("$RT" ps -aq --filter label=seclab.managed=1; "$RT" network ls -q --filter label=seclab.managed=1)
[ -z "$left" ] && echo "none" || { echo "FAIL: leftover resources: $left"; exit 1; }
