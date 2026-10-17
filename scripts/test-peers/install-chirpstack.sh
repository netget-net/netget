#!/bin/sh
# Install ChirpStack v4 (the SQLite build, so no PostgreSQL is needed) and the ChirpStack
# Gateway Bridge — the independent network server and Semtech UDP front end for NetGet's
# LoRaWAN gateway client — plus a Python venv with the official chirpstack-api gRPC client,
# which the test uses to provision a device and queue a downlink.
#
# Both are Linux-only release tarballs from artifacts.chirpstack.io, checked against pinned
# SHA-256s. Nothing is installed system-wide and nothing needs root. Redis and Mosquitto come
# from the system (Ubuntu: redis-server mosquitto mosquitto-clients).
#
# Usage: sh scripts/test-peers/install-chirpstack.sh /absolute/owned/directory
# Prints the NETGET_CHIRPSTACK* variables tests/client/lorawan/real_server_test.rs reads.
set -eu
base=${1:?Supply an owned absolute directory}
case "$base" in /*) ;; *) echo 'An absolute directory is required' >&2; exit 2;; esac
[ "$(uname -s)" = Linux ] || { echo 'ChirpStack publishes Linux binaries only' >&2; exit 2; }
cs_version=4.19.2
bridge_version=4.1.2
case "$(uname -m)" in
    x86_64)
        arch=amd64
        cs_sha=2b2edc5310083b978f1a74b2be0e64187ba51ab40210a33e2f16550226005769
        bridge_sha=113c7e5bd42d06c66272506827d323ef6469980007500e8f161754ea4e6d2596
        ;;
    aarch64|arm64)
        arch=arm64
        cs_sha=5c7056f75ab560c3dcbb34ab2d90d948b374cfac9c359ae1b57048d80df805aa
        bridge_sha=cc844c7a320e32d09eb92748e8cd5b352f978ecf56b90c58b6f19b8100bd7094
        ;;
    *) echo "no ChirpStack build pinned for $(uname -m)" >&2; exit 2;;
esac
mkdir -p "$base/bin"
fetch() {
    file=$1 sha=$2 url=$3
    if [ ! -f "$base/$file" ]; then
        curl -fsSL -o "$base/$file" "$url"
    fi
    echo "$sha  $base/$file" | sha256sum -c -
    tar -xzf "$base/$file" -C "$base/bin"
}
fetch "chirpstack_${cs_version}_sqlite_linux_${arch}.tar.gz" "$cs_sha" \
    "https://artifacts.chirpstack.io/downloads/chirpstack/chirpstack_${cs_version}_sqlite_linux_${arch}.tar.gz"
fetch "chirpstack-gateway-bridge_${bridge_version}_linux_${arch}.tar.gz" "$bridge_sha" \
    "https://artifacts.chirpstack.io/downloads/chirpstack-gateway-bridge/chirpstack-gateway-bridge_${bridge_version}_linux_${arch}.tar.gz"
"$base/bin/chirpstack" --version
"$base/bin/chirpstack-gateway-bridge" version
python3 -m venv "$base/venv"
"$base/venv/bin/pip" install -q 'chirpstack-api==4.19.0' 'grpcio>=1.60'
"$base/venv/bin/python" -c 'import chirpstack_api, grpc; print("chirpstack-api", "ok")'
echo "NETGET_CHIRPSTACK=$base/bin/chirpstack"
echo "NETGET_CHIRPSTACK_GATEWAY_BRIDGE=$base/bin/chirpstack-gateway-bridge"
echo "NETGET_CHIRPSTACK_PYTHON=$base/venv/bin/python"
