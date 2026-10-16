#!/bin/sh
# Build rt-labs' p-net PROFINET IO device stack and its sample application (pn_dev), the
# independent device the PROFINET controller's real-server test drives. Linux only.
#
# Source: the last public p-net tree that still carries the build system and the sample
# application — github.com/kolonialno/profinet, a mirror of rtlabs-com/p-net upstream as of
# November 2023 (rt-labs' own public branch has since dropped both). Pinned by commit; its
# cmake-tools submodule and the OSAL it fetches are pinned by the tree itself.
#
# Two patches, the same ones profinet-py's own p-net integration image applies:
#   * pf_cmdev_check_pdev: p-net refuses a Connect when the port is not a 100 Mbit/s-class
#     link it can map to a PROFINET MAU type; a veth reports 10 Gbit/s. The check is about
#     real hardware, not about the protocol, so it is made to pass.
#   * -Werror is removed: the 2023 sources predate warnings newer GCCs add.
#
# Usage: sh scripts/test-peers/build-pnet.sh /absolute/owned/directory
# Prints PNET_DEV=<path to pn_dev>; set_network_parameters and set_profinet_leds sit beside
# it, which is where pn_dev looks for them.
set -eu
base=${1:?Supply an owned absolute directory}
case "$base" in /*) ;; *) echo 'An absolute directory is required' >&2; exit 2;; esac
commit=ea5e5540b2be55c4dfadffda39b948632c104daa
src="$base/p-net"
mkdir -p "$base"
if [ ! -d "$src/.git" ]; then
    git clone --quiet https://github.com/kolonialno/profinet.git "$src"
fi
git -C "$src" checkout --quiet "$commit"
git -C "$src" submodule update --init --quiet --depth 1
sed -i 's/return (pf_pdport_is_a_fast_port_in_use (net)) ? 0 : -1;/return 0; \/* netget: veth reports 10 Gbit\/s *\//' \
    "$src/src/device/pf_cmdev.c"
grep -q 'netget: veth reports' "$src/src/device/pf_cmdev.c"
find "$src" -type f \( -name CMakeLists.txt -o -name '*.cmake' \) -exec sed -i 's/-Werror//g' {} +
cmake -S "$src" -B "$base/build" -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF \
    -DPNET_MAX_AR=2 -DPNET_MAX_SLOTS=5 -DPNET_MAX_SUBSLOTS=4 -DPNET_MAX_PHYSICAL_PORTS=1 \
    -DLOG_LEVEL=INFO >/dev/null
cmake --build "$base/build" --target pn_dev -j "$(nproc)" >/dev/null
test -x "$base/build/pn_dev"
test -x "$base/build/set_profinet_leds"
test -x "$base/build/set_network_parameters"
echo "PNET_DEV=$base/build/pn_dev"
