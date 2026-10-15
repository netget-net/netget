#!/bin/sh
# Install the Apache Hadoop the YARN client is tested against into an owned ROOT:
#
#   ROOT/hadoop-3.5.0   the official binary distribution, its SHA-512 pinned below
#
# The tests run its ResourceManager and NodeManager as a single-node YARN on loopback ports
# (configuration written into a temporary directory per test; fs.defaultFS is file:///, so no
# HDFS), run the distributed-shell example application on it, and read YARN's own view back
# through the `yarn` command line. Needs a JDK 17 (JAVA_HOME, or `java` on PATH).
#
# A tarball already in ROOT with the right checksum is reused (CI caches ROOT/*.tar.gz).
#
# Usage: sh tests/client/yarn/install_peers.sh /absolute/owned/root
# Prints the NETGET_HADOOP_HOME export tests/client/yarn/real_server_test.rs reads.
set -eu

ROOT=${1:?usage: install_peers.sh /absolute/owned/root}
VERSION=3.5.0
NAME=hadoop-$VERSION
SHA512=04ab94496cc00c8b7a28d03f6308eff8d2a4e7f37a9da5e8e086e4d6fc990e7a94d661908f6a6136039536efb362614b8aecdef185b5fb8ed588f0b152c7aa16

sha512_of() {
  if command -v sha512sum >/dev/null 2>&1; then
    sha512sum "$1" | cut -d' ' -f1
  else
    shasum -a 512 "$1" | cut -d' ' -f1
  fi
}

mkdir -p "$ROOT"
TGZ="$ROOT/$NAME.tar.gz"
if [ ! -f "$TGZ" ] || [ "$(sha512_of "$TGZ")" != "$SHA512" ]; then
  rm -f "$TGZ"
  # downloads.apache.org carries only current releases; archive.apache.org keeps every one.
  for url in \
    "https://downloads.apache.org/hadoop/common/$NAME/$NAME.tar.gz" \
    "https://archive.apache.org/dist/hadoop/common/$NAME/$NAME.tar.gz"; do
    if curl -fsSL --retry 3 -o "$TGZ.part" "$url"; then
      mv -f "$TGZ.part" "$TGZ"
      break
    fi
    rm -f "$TGZ.part"
  done
fi
[ -f "$TGZ" ] || { echo "could not download $NAME.tar.gz" >&2; exit 1; }
GOT=$(sha512_of "$TGZ")
if [ "$GOT" != "$SHA512" ]; then
  echo "SHA-512 mismatch for $TGZ: got $GOT, want $SHA512" >&2
  exit 1
fi

rm -rf "${ROOT:?}/$NAME"
tar -xzf "$TGZ" -C "$ROOT"
if ! "$ROOT/$NAME/bin/yarn" version 2>&1 | grep -q "Hadoop $VERSION"; then
  echo "$ROOT/$NAME/bin/yarn does not run; is a JDK 17 on JAVA_HOME or PATH?" >&2
  "$ROOT/$NAME/bin/yarn" version >&2 || true
  exit 1
fi

echo "export NETGET_HADOOP_HOME=$ROOT/$NAME"
