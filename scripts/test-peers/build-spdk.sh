#!/bin/sh
# Build SPDK v26.09 (Linux): spdk_nvme_identify, spdk_nvme_perf and spdk_dd (a userspace
# NVMe/TCP host independent of the kernel's, for the NVMe/TCP target) and nvmf_tgt (a userspace
# NVMe/TCP target, for the host). The tests run them with --no-huge, so no hugepages are needed.
#
# The clone is checked against the tag's pinned commit. SPDK's own scripts/pkgdep.sh installs
# its build dependencies (it needs sudo); its code generator runs on the system python3, which
# needs python3-yaml, python3-jinja2 and python3-pyelftools as well.
#
# Usage: sh scripts/test-peers/build-spdk.sh /absolute/owned/directory
# Builds <dir>/spdk (skipped when <dir>/spdk/build/bin/nvmf_tgt already exists, as from a
# cache, though pkgdep.sh still runs for the runtime libraries) and prints <dir>/spdk, the value
# for NETGET_SPDK_DIR.
set -eu
base=${1:?Supply an owned absolute directory}
case "$base" in /*) ;; *) echo 'An absolute directory is required' >&2; exit 2;; esac
tag=v26.09
commit=0bbb7fe4dccfb31e8d446da8822360704949d1e9
mkdir -p "$base"
cd "$base"
if [ ! -d spdk ]; then
    git clone --quiet --depth 1 --branch "$tag" --recurse-submodules --shallow-submodules \
        https://github.com/spdk/spdk spdk >&2
fi
cd spdk
test "$(git rev-parse HEAD)" = "$commit"
sudo -n DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    python3-yaml python3-jinja2 python3-pyelftools >/dev/null
sudo -n ./scripts/pkgdep.sh >"$base/pkgdep.log" 2>&1 || { tail -40 "$base/pkgdep.log" >&2; exit 1; }
# A cached build may run on another CPU: on x86-64 build for the v2 baseline, not -march=native.
arch=
if [ "$(uname -m)" = x86_64 ]; then arch=--target-arch=x86-64-v2; fi
if [ ! -x build/bin/nvmf_tgt ]; then
    ./configure --disable-tests --disable-unit-tests --disable-examples $arch \
        --without-crypto --without-vhost --without-virtio >"$base/configure.log" 2>&1 \
        || { tail -40 "$base/configure.log" >&2; exit 1; }
    make -j"$(nproc)" >"$base/make.log" 2>&1 || { tail -60 "$base/make.log" >&2; exit 1; }
fi
for b in nvmf_tgt spdk_nvme_identify spdk_nvme_perf spdk_dd; do
    test -x "build/bin/$b"
done
test -f scripts/rpc.py
pwd
