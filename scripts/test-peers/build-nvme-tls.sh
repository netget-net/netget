#!/bin/sh
# Build the Linux side of an NVMe/TCP secure channel (Linux): tlshd from ktls-utils 1.5.0, which
# runs the kernel's TLS handshakes as host and as target, and nvme-cli 3.1, which makes and
# inserts the keys. Ubuntu 24.04's packages cannot stand in for either: its nvme-cli 2.8 (libnvme
# 1.8 on OpenSSL 3.0) derives every key from an HKDF info of the host NQN alone, which nothing
# that follows the specification matches, and its tlshd 0.9 cannot find a key on the target side.
#
# Each clone is checked against the tag's pinned commit. The caller installs the build
# dependencies (autoconf, automake, libtool, libgnutls28-dev, libkeyutils-dev, libnl-3-dev,
# libnl-genl-3-dev, libglib2.0-dev, meson, ninja-build, libjson-c-dev, libssl-dev, uuid-dev).
#
# Usage: sh scripts/test-peers/build-nvme-tls.sh /absolute/owned/directory
# Installs tlshd to /usr/local/sbin (sudo), leaves nvme-cli in <dir>/nvme-cli/.build and prints
# the nvme binary's path, the value for NETGET_NVME_CLI.
set -eu
base=${1:?Supply an owned absolute directory}
case "$base" in /*) ;; *) echo 'An absolute directory is required' >&2; exit 2;; esac
mkdir -p "$base"
cd "$base"

checkout() { # name url tag commit
    if [ ! -d "$1" ]; then
        git clone --quiet --depth 1 --branch "$3" "$2" "$1" >&2
    fi
    got=$(git -C "$1" rev-parse HEAD)
    if [ "$got" != "$4" ]; then
        echo "$1: tag $3 is $got, not the pinned $4" >&2
        exit 1
    fi
}

checkout ktls-utils https://github.com/oracle/ktls-utils ktls-utils-1.5.0 \
    d0b4de1ba000fe6baf739e85f17bca33b821a16f
(
    cd ktls-utils
    ./autogen.sh >&2
    ./configure --prefix=/usr/local >&2
    make -j"$(nproc)" >&2
    sudo make install >&2
)

checkout nvme-cli https://github.com/linux-nvme/nvme-cli v3.1 \
    f73ecd53751cd74bc8e46b60c973ea63edf41403
(
    cd nvme-cli
    [ -d .build ] || meson setup .build -Ddocs=false >&2
    ninja -C .build >&2
)
"$base/nvme-cli/.build/nvme" version >&2
echo "$base/nvme-cli/.build/nvme"
