#!/bin/sh
# Build KickCAT's network_simulator (leducp/KickCAT): a software EtherCAT Slave Controller
# (registers, SyncManagers, FMMUs, SII EEPROM compiled from an ESI XML) driven by KickCAT's own
# slave stack with a CoE object dictionary — the independent slave the EtherCAT master's
# real-server test drives over a veth. It runs the emulated CiA 402 drive in
# simulation/slave_configs/ecat402-drive.json. Linux only.
#
# Pinned by commit. No patches. KickCAT's own build goes through Conan; this one does not:
# tinyxml2 and nlohmann-json come from the distribution (apt-get install libtinyxml2-dev
# nlohmann-json3-dev), and argparse 3.2 — newer than Ubuntu's — is installed into the build
# directory from its pinned tag.
#
# Usage: sh scripts/test-peers/build-kickcat.sh /absolute/owned/directory
# Prints KICKCAT_SIM=<path to network_simulator> and KICKCAT_CONFIGS=<slave_configs dir>.
set -eu
base=${1:?Supply an owned absolute directory}
case "$base" in /*) ;; *) echo 'An absolute directory is required' >&2; exit 2;; esac
commit=cb2e1a192ac11ffaa58f08945053b8129abf94cb
argparse_tag=v3.2
src="$base/KickCAT"
mkdir -p "$base"
if [ ! -d "$base/argparse/.git" ]; then
    git clone --quiet --depth 1 --branch "$argparse_tag" https://github.com/p-ranav/argparse.git "$base/argparse"
fi
cmake -S "$base/argparse" -B "$base/argparse-build" -DARGPARSE_BUILD_TESTS=OFF \
    -DARGPARSE_BUILD_SAMPLES=OFF -DCMAKE_INSTALL_PREFIX="$base/prefix" >/dev/null
cmake --install "$base/argparse-build" >/dev/null
if [ ! -d "$src/.git" ]; then
    git clone --quiet https://github.com/leducp/KickCAT.git "$src"
fi
git -C "$src" checkout --quiet "$commit"
cmake -S "$src" -B "$base/build" -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_PREFIX_PATH="$base/prefix" \
    -DBUILD_SIMULATION=ON -DENABLE_ESI_PARSER=ON \
    -DBUILD_MASTER_EXAMPLES=OFF -DBUILD_SLAVE_EXAMPLES=OFF -DBUILD_TOOLS=OFF \
    -DBUILD_UNIT_TESTS=OFF -DKICKCAT_INSTALL=OFF >/dev/null
cmake --build "$base/build" --target network_simulator -j "$(nproc)" >/dev/null
sim=$(find "$base/build" -type f -name network_simulator -perm -u+x | head -1)
test -x "$sim"
test -f "$src/simulation/slave_configs/ecat402-drive.json"
echo "KICKCAT_SIM=$sim"
echo "KICKCAT_CONFIGS=$src/simulation/slave_configs"
