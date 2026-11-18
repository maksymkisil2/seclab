#!/usr/bin/env sh
# Build the offline stub image seclab/stub:local:
#   static Go multi-call binary (nginx|nc|ip|socat|tail) + host nft with its shared libs.
set -eu
cd "$(dirname "$0")"
RT=${SECLAB_RUNTIME:-$(command -v docker >/dev/null 2>&1 && echo docker || echo podman)}
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o stub .
rm -rf rootfs && mkdir -p rootfs/usr/sbin rootfs/usr/bin rootfs/etc/seclab rootfs/tmp
for a in nginx; do cp stub rootfs/usr/sbin/$a; done
for a in nc ip socat tail; do cp stub rootfs/usr/bin/$a; done
NFT=$(command -v nft || true)
if [ -n "$NFT" ]; then
    cp "$NFT" rootfs/usr/sbin/nft
    ldd "$NFT" | awk '/=>/ {print $3} /ld-linux/ {print $1}' | while read -r lib; do
        [ -f "$lib" ] || continue
        mkdir -p "rootfs$(dirname "$lib")"
        cp -L "$lib" "rootfs$lib"
    done
else
    echo "warn: nft not on host; firewall tests will fail in stub mode" >&2
fi
chmod 1777 rootfs/tmp
"$RT" build -q -t seclab/stub:local . >/dev/null
echo "built seclab/stub:local"
