#!/bin/sh
# Install the two independent Snowflake-protocol servers the Snowflake client is tested
# against, and Snowflake's official Python driver, into an owned ROOT:
#
#   ROOT/venv  fakesnow[server] 0.11.22 (Python, DuckDB underneath) and
#              snowflake-connector-python 4.8.0 (reads fakesnow back; drives NetGet's server)
#   ROOT/bin/snowflake-emulator  nnnkkk7/snowflake-emulator v0.0.9 (Go, DuckDB underneath),
#              built with `go install`, whose module checksum the Go checksum database pins
#
# Needs python3 (3.10+) with venv, and Go 1.24+ with a C toolchain (the DuckDB binding is cgo).
#
# Usage: sh tests/client/snowflake/install_peers.sh /absolute/owned/root
# Prints the NETGET_SNOWFLAKE_PEERS export tests/client/snowflake/peers.rs reads.
set -eu

ROOT=${1:?usage: install_peers.sh /absolute/owned/root}
FAKESNOW_VERSION=0.11.22
CONNECTOR_VERSION=4.8.0
EMULATOR_VERSION=v0.0.9

mkdir -p "$ROOT/bin"
python3 -m venv "$ROOT/venv"
"$ROOT/venv/bin/python" -m pip install --quiet --upgrade pip
"$ROOT/venv/bin/python" -m pip install --quiet \
  "fakesnow[server]==$FAKESNOW_VERSION" "snowflake-connector-python==$CONNECTOR_VERSION"
"$ROOT/venv/bin/python" -I -c 'import fakesnow, snowflake.connector'

GOBIN="$ROOT/bin" go install "github.com/nnnkkk7/snowflake-emulator/cmd/server@$EMULATOR_VERSION"
mv -f "$ROOT/bin/server" "$ROOT/bin/snowflake-emulator"

echo "export NETGET_SNOWFLAKE_PEERS=$ROOT"
