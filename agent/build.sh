#!/usr/bin/env sh
# Build static seclab-agent binaries into seclab/bin (linux amd64 + arm64). Needs Go >= 1.24.
set -eu
cd "$(dirname "$0")"
for arch in amd64 arm64; do
    CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath -ldflags="-s -w" -o "../seclab/bin/seclab-agent-linux-$arch" .
done
ls -la ../seclab/bin
