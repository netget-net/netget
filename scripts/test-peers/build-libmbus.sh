#!/bin/sh
# Build rSCADA libmbus and its M-Bus/IP tools, the independent M-Bus masters the M-Bus slave's
# real-peer test drives: mbus-tcp-scan (primary-address scan), mbus-tcp-scan-secondary
# (secondary-address wildcard search), mbus-tcp-request-data (REQ_UD2 -> RSP_UD, printed as
# XML), mbus-tcp-request-data-multi-reply (FCB-toggled multi-telegram readout),
# mbus-tcp-application-reset and mbus-tcp-raw-send. Neither Homebrew nor Ubuntu packages libmbus, so it is built
# from source with the system C compiler, without autotools: the library is four C files and
# its only generated header carries the version string.
#
# Pinned to the 0.10.3 release commit. No patches.
#
# Usage: sh scripts/test-peers/build-libmbus.sh /absolute/owned/directory
# Prints LIBMBUS_BIN=<directory holding the mbus-tcp-* tools>.
set -eu
base=${1:?Supply an owned absolute directory}
case "$base" in /*) ;; *) echo 'An absolute directory is required' >&2; exit 2;; esac
commit=d617bd2bf654fc1b0d291a340672727440853142
src="$base/libmbus"
mkdir -p "$base"
if [ ! -d "$src/.git" ]; then
    git clone --quiet https://github.com/rscada/libmbus.git "$src"
fi
git -C "$src" checkout --quiet "$commit"
printf '#define VERSION "0.10.3"\n' > "$src/config.h"
cc=${CC:-cc}
mkdir -p "$base/bin"
for tool in mbus-tcp-scan mbus-tcp-scan-secondary mbus-tcp-request-data mbus-tcp-raw-send \
    mbus-tcp-request-data-multi-reply mbus-tcp-application-reset; do
    "$cc" -O1 -w -I"$src" -I"$src/mbus" -o "$base/bin/$tool" "$src/bin/$tool.c" \
        "$src/mbus/mbus.c" "$src/mbus/mbus-protocol.c" "$src/mbus/mbus-protocol-aux.c" \
        "$src/mbus/mbus-tcp.c" "$src/mbus/mbus-serial.c" -lm
    test -x "$base/bin/$tool"
done
echo "LIBMBUS_BIN=$base/bin"
