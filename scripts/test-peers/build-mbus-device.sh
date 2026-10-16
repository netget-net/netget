#!/bin/sh
# Build Addiva Elektronik's mbus-device, an independent wired M-Bus slave (it answers SND_NKE,
# REQ_UD2 with a configurable RSP_UD, and secondary-address selection), on top of Addiva's
# fork of libmbus, which adds the slave-side receive path upstream libmbus lacks. It is the
# second independent slave the M-Bus master's real-server test drives; it speaks to a serial
# device, so the test bridges a pty to TCP the way an M-Bus/IP gateway bridges its bus.
#
# Pinned commits, no patches. No autotools: the library is five C files and the one generated
# header carries the version string and the platform's math/strdup availability.
#
# Usage: sh scripts/test-peers/build-mbus-device.sh /absolute/owned/directory
# Prints MBUS_DEVICE=<path to the mbus-device binary>.
set -eu
base=${1:?Supply an owned absolute directory}
case "$base" in /*) ;; *) echo 'An absolute directory is required' >&2; exit 2;; esac
lib_commit=756ab8eae728f8100cfbe9382076fdb498c4a4d6
dev_commit=2364bdac698e2c448dd54fa8df1117518940d1d8
lib="$base/addiva-libmbus"
dev="$base/mbus-device"
mkdir -p "$base"
if [ ! -d "$lib/.git" ]; then
    git clone --quiet https://github.com/addiva-elektronik/libmbus.git "$lib"
fi
if [ ! -d "$dev/.git" ]; then
    git clone --quiet https://github.com/addiva-elektronik/mbus-device.git "$dev"
fi
git -C "$lib" checkout --quiet "$lib_commit"
git -C "$dev" checkout --quiet "$dev_commit"
inc="$base/addiva-include"
mkdir -p "$inc/mbus"
cp "$lib"/mbus/*.h "$inc/mbus/"
printf '#define VERSION "addiva-%s"\n#define HAVE_MATH_H 1\n#define HAVE_POW 1\n#define HAVE_STRDUP 1\n#define HAVE_TERMIOS_H 1\n' \
    "$lib_commit" > "$inc/config.h"
cc=${CC:-cc}
mkdir -p "$base/bin"
"$cc" -O1 -w -DHAVE_CONFIG_H -I"$inc" -I"$inc/mbus" -o "$base/bin/mbus-device" \
    "$dev/mbus-device.c" "$lib/mbus/mbus.c" "$lib/mbus/mbus-protocol.c" \
    "$lib/mbus/mbus-protocol-aux.c" "$lib/mbus/mbus-tcp.c" "$lib/mbus/mbus-serial.c" -lm
test -x "$base/bin/mbus-device"
echo "MBUS_DEVICE=$base/bin/mbus-device"
