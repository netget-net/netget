#!/bin/sh
# Build the Simple Open EtherCAT Master (SOEM, rt-labs / OpenEtherCATsociety) and its sample
# programs, the independent masters the EtherCAT slave's real-peer test drives: slaveinfo
# (scan, SII, PDO mapping over CoE) and simple_ng (walk to OP, cyclic process data, working
# counter). Linux only (raw AF_PACKET sockets).
#
# Pinned to the v2.0.1 tag. No patches.
#
# Usage: sh scripts/test-peers/build-soem.sh /absolute/owned/directory
# Prints SOEM_BIN=<directory holding slaveinfo and simple_ng>.
set -eu
base=${1:?Supply an owned absolute directory}
case "$base" in /*) ;; *) echo 'An absolute directory is required' >&2; exit 2;; esac
commit=49fc34923b973c17700592319159af22157350c9
src="$base/SOEM"
mkdir -p "$base"
if [ ! -d "$src/.git" ]; then
    git clone --quiet https://github.com/OpenEtherCATsociety/SOEM.git "$src"
fi
git -C "$src" checkout --quiet "$commit"
cmake -S "$src" -B "$base/build" -DCMAKE_BUILD_TYPE=Release -DSOEM_BUILD_SAMPLES=ON >/dev/null
cmake --build "$base/build" --target slaveinfo simple_ng -j "$(nproc)" >/dev/null
mkdir -p "$base/bin"
cp "$(find "$base/build" -type f -name slaveinfo -perm -u+x | head -1)" "$base/bin/"
cp "$(find "$base/build" -type f -name simple_ng -perm -u+x | head -1)" "$base/bin/"
test -x "$base/bin/slaveinfo"
test -x "$base/bin/simple_ng"
echo "SOEM_BIN=$base/bin"
