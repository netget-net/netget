#!/bin/sh
# Build LWN Simulator (UniCT-ARSLab, Go): simulated LoRaWAN 1.0.3 end devices behind a virtual
# Semtech UDP packet forwarder, with the device-side crypto from brocaar/lorawan (ChirpStack's
# Go library). It is the independent gateway and device for NetGet's LoRaWAN network server.
#
# There is no current release binary for macOS or arm64, so it is built from a pinned commit.
# Needs Go >= 1.21 and git; nothing needs root.
#
# Usage: sh scripts/test-peers/build-lwn-simulator.sh /absolute/owned/directory
# Prints NETGET_LWN_SIMULATOR for tests/server/lorawan/lwn_test.rs.
set -eu
base=${1:?Supply an owned absolute directory}
case "$base" in /*) ;; *) echo 'An absolute directory is required' >&2; exit 2;; esac
commit=ba1730292c913a6aad7bda13b1e9cbd4136d88e6
mkdir -p "$base"
src="$base/LWN-Simulator"
if [ ! -d "$src/.git" ]; then
    git clone -q https://github.com/UniCT-ARSLab/LWN-Simulator.git "$src"
fi
git -C "$src" fetch -q origin "$commit" 2>/dev/null || true
git -C "$src" checkout -q "$commit"
export GOPATH="$base/gopath" GOFLAGS=-modcacherw
go install github.com/rakyll/statik@v0.1.7
# The web UI is baked into the binary with statik, as the project's Makefile does.
(cd "$src/webserver" && "$GOPATH/bin/statik" -f -src=public)
(cd "$src" && go build -o "$base/bin/lwnsimulator" cmd/main.go)
test -x "$base/bin/lwnsimulator"
echo "NETGET_LWN_SIMULATOR=$base/bin/lwnsimulator"
