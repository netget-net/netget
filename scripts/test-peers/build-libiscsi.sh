#!/bin/sh
# Build libiscsi 1.20.3's tools: iscsi-ls, iscsi-inq, iscsi-readcapacity16, iscsi-md5sum and the
# iscsi-test-cu compliance suite (independent initiators for the iSCSI target). Ubuntu 24.04's
# libiscsi-bin is 1.19, which has no iscsi-md5sum; Homebrew's libiscsi is 1.20.3
# (`brew install libiscsi`), the version the tests were written against.
#
# The tag's source archive is checked against a pinned SHA-256.
#
# Build dependencies (Ubuntu 24.04): build-essential autoconf automake libtool libcunit1-dev
#
# Usage: sh scripts/test-peers/build-libiscsi.sh /absolute/owned/directory
# Installs <dir>/install/bin/iscsi-*, and prints that directory.
set -eu
base=${1:?Supply an owned absolute directory}
case "$base" in /*) ;; *) echo 'An absolute directory is required' >&2; exit 2;; esac
version=1.20.3
sha256=212f6e1fd8e7ddb4b02208aafc6de600f6f330f40359babeefdd83b0c79d47a1
url="https://codeload.github.com/sahlberg/libiscsi/tar.gz/refs/tags/$version"
mkdir -p "$base"
tarball="$base/libiscsi-$version.tar.gz"
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
tar -xzf "$tarball" -C "$base/src" --strip-components=1
prefix="$base/install"
cd "$base/src"
./autogen.sh >/dev/null 2>&1
./configure --prefix="$prefix" --disable-werror --disable-manpages >/dev/null
make -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu)" >/dev/null
make install >/dev/null
test -x "$prefix/bin/iscsi-test-cu"
test -x "$prefix/bin/iscsi-md5sum"
echo "$prefix/bin"
