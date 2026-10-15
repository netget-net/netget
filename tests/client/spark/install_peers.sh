#!/bin/sh
# Install the Apache Spark the Spark client is tested against into an owned ROOT:
#
#   ROOT/spark-4.2.0-bin-hadoop3   the official binary distribution, its SHA-512 pinned below
#
# The tests run a small PySpark application from it (the live driver UI, `spark.ui.port`) and
# Spark's own History Server over the event log that application writes. Needs a JDK 17 or 21
# (JAVA_HOME, or `java` on PATH) and python3 3.10+; nothing is installed with pip — the
# distribution carries pyspark and py4j itself.
#
# A tarball already in ROOT with the right checksum is reused (CI caches ROOT/*.tgz).
#
# Usage: sh tests/client/spark/install_peers.sh /absolute/owned/root
# Prints the NETGET_SPARK_HOME export tests/client/spark/real_server_test.rs reads.
set -eu

ROOT=${1:?usage: install_peers.sh /absolute/owned/root}
VERSION=4.2.0
NAME=spark-$VERSION-bin-hadoop3
SHA512=3a6559e8546ff387db8fe7a04b8fe4008853b467b972c2e343df8e14a81450534777719fc5d4998dd96519a86fdf9de140cee753c61e2e94db044d5f9555ddc4

sha512_of() {
  if command -v sha512sum >/dev/null 2>&1; then
    sha512sum "$1" | cut -d' ' -f1
  else
    shasum -a 512 "$1" | cut -d' ' -f1
  fi
}

mkdir -p "$ROOT"
TGZ="$ROOT/$NAME.tgz"
if [ ! -f "$TGZ" ] || [ "$(sha512_of "$TGZ")" != "$SHA512" ]; then
  rm -f "$TGZ"
  # downloads.apache.org carries only current releases; archive.apache.org keeps every one.
  for url in \
    "https://downloads.apache.org/spark/spark-$VERSION/$NAME.tgz" \
    "https://archive.apache.org/dist/spark/spark-$VERSION/$NAME.tgz"; do
    if curl -fsSL --retry 3 -o "$TGZ.part" "$url"; then
      mv -f "$TGZ.part" "$TGZ"
      break
    fi
    rm -f "$TGZ.part"
  done
fi
[ -f "$TGZ" ] || { echo "could not download $NAME.tgz" >&2; exit 1; }
GOT=$(sha512_of "$TGZ")
if [ "$GOT" != "$SHA512" ]; then
  echo "SHA-512 mismatch for $TGZ: got $GOT, want $SHA512" >&2
  exit 1
fi

rm -rf "${ROOT:?}/$NAME"
tar -xzf "$TGZ" -C "$ROOT"
if ! "$ROOT/$NAME/bin/spark-submit" --version 2>&1 | grep -q "version $VERSION"; then
  echo "$ROOT/$NAME/bin/spark-submit does not run; is a JDK 17 or 21 on JAVA_HOME or PATH?" >&2
  "$ROOT/$NAME/bin/spark-submit" --version >&2 || true
  exit 1
fi

echo "export NETGET_SPARK_HOME=$ROOT/$NAME"
