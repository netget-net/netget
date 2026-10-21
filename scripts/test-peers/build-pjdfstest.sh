#!/bin/sh
# Build pjdfstest's C suite (the POSIX filesystem conformance tests FreeBSD, ZFS and fuser run)
# for the FUSE server's compliance test. The pinned commit's source archive is checked against a
# SHA-256, and the suite is run with prove from the checkout: tests/server/fuse/pjdfstest_test.rs
# reads its location from NETGET_PJDFSTEST.
#
# Build dependencies (Ubuntu 24.04): build-essential autoconf automake. Running it needs perl
# (prove) and openssl: the suite names its files with `openssl md5`, and without openssl its name
# generator loops forever, which looks exactly like a filesystem hang.
#
# Usage: sh scripts/test-peers/build-pjdfstest.sh /absolute/owned/directory
# Builds <dir>/src/pjdfstest and prints <dir>/src.
set -eu
base=${1:?Supply an owned absolute directory}
case "$base" in /*) ;; *) echo 'An absolute directory is required' >&2; exit 2;; esac
commit=85a8aea9e685999ef0540392fd80535f873d7ff7
sha256=2005cdd83b76204177cf136792b1f2058a7418b4fc5b203f51274a698547d754
url="https://codeload.github.com/pjd/pjdfstest/tar.gz/$commit"
mkdir -p "$base"
tarball="$base/pjdfstest-$commit.tar.gz"
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
cd "$base/src"
autoreconf -ifs >/dev/null 2>&1
./configure >/dev/null
make pjdfstest >/dev/null
test -x "$base/src/pjdfstest"
# The suite is run by root from inside the mount; its scripts must be readable by everyone.
chmod -R a+rX "$base/src"
echo "$base/src"
