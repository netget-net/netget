#!/bin/sh
# Build netatalk 4.6.1 with its AFP test suite: afpd (the independent AFP server the AFP
# client's real-server test drives) and afparg and asip-status (independent AFP clients the AFP
# server's real-peer test drives). Ubuntu packages netatalk 3.x without the test clients, so it
# is built from the release tarball, checked against a pinned SHA-256, with meson. Homebrew's
# netatalk 4.6.1 bottle already includes all three (`brew install netatalk`).
#
# Only what the tests need is enabled: the sqlite CNID backend (no cnid_metad), no PAM, LDAP,
# Zeroconf, Spotlight, ACLs, Kerberos or CUPS, no init scripts. Everything installs under
# <dir>/install, state directory included, so afpd runs unprivileged.
#
# Build dependencies (Ubuntu 24.04): build-essential meson ninja-build pkg-config libevent-dev
#   libgcrypt20-dev libsqlite3-dev libiniparser-dev libdb-dev
#
# Usage: sh scripts/test-peers/build-netatalk.sh /absolute/owned/directory
# Prints NETATALK_BIN=<dir with afparg, asip-status> and NETATALK_SBIN=<dir with afpd>.
set -eu
base=${1:?Supply an owned absolute directory}
case "$base" in /*) ;; *) echo 'An absolute directory is required' >&2; exit 2;; esac
version=4.6.1
sha256=c97412f7f4bbbbfa922664f52b9d6a5f75282b99a52fe0463134bb477fea715e
url="https://github.com/Netatalk/netatalk/releases/download/netatalk-4-6-1/netatalk-$version.tar.xz"
mkdir -p "$base"
tarball="$base/netatalk-$version.tar.xz"
if [ ! -f "$tarball" ]; then
    curl -fsSL -o "$tarball" "$url"
fi
if command -v sha256sum >/dev/null 2>&1; then
    echo "$sha256  $tarball" | sha256sum -c -
else
    echo "$sha256  $tarball" | shasum -a 256 -c -
fi
rm -rf "$base/src"
mkdir -p "$base/src"
tar -xJf "$tarball" -C "$base/src" --strip-components=1
prefix="$base/install"
meson setup "$base/build" "$base/src" --wipe \
    -Dprefix="$prefix" \
    -Dwith-testsuite=true \
    -Dwith-cnid-backends=sqlite \
    -Dwith-init-style=none \
    -Dwith-install-hooks=false \
    -Dwith-statedir-path="$prefix/var" \
    -Dwith-pam=false \
    -Dwith-ldap=false \
    -Dwith-zeroconf=false \
    -Dwith-spotlight=false \
    -Dwith-acls=false \
    -Dwith-kerberos=false \
    -Dwith-gssapi=false \
    -Dwith-cups=false \
    -Dwith-quota=false \
    -Dwith-dtrace=false \
    -Dwith-docs= \
    >"$base/meson-setup.log" 2>&1 || { cat "$base/meson-setup.log"; exit 1; }
ninja -C "$base/build" install >"$base/ninja.log" 2>&1 || { tail -100 "$base/ninja.log"; exit 1; }
mkdir -p "$prefix/var/netatalk"
for tool in "$prefix/bin/afparg" "$prefix/bin/asip-status" "$prefix/sbin/afpd"; do
    test -x "$tool"
done
"$prefix/sbin/afpd" -v | head -1
echo "NETATALK_BIN=$prefix/bin"
echo "NETATALK_SBIN=$prefix/sbin"
