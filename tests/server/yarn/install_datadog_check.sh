#!/bin/sh
# Install Datadog's YARN integration — an independent consumer of the YARN ResourceManager REST
# API — into an owned ROOT, to drive NetGet's YARN server with:
#
#   ROOT/venv   datadog-checks-base[deps] 38.5.0 (the check needs >=37.33.0 and nothing else)
#   ROOT/check/datadog_checks/yarn   the check itself, DataDog/integrations-core tag yarn-8.4.2
#               (commit below), each file's SHA-256 pinned. Datadog publishes the check only
#               inside its Agent and as source.
#
# Needs python3.12 or newer with venv.
#
# Usage: sh tests/server/yarn/install_datadog_check.sh /absolute/owned/root
# Prints the NETGET_DATADOG_YARN export tests/server/yarn/datadog_check_test.rs reads.
set -eu

ROOT=${1:?usage: install_datadog_check.sh /absolute/owned/root}
PYTHON=${PYTHON:-python3}
COMMIT=0ee740bd4f295508247ab517b6d842ae91e9e79c
BASE=https://raw.githubusercontent.com/DataDog/integrations-core/$COMMIT/yarn/datadog_checks/yarn

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

"$PYTHON" -c 'import sys; assert sys.version_info >= (3, 12), sys.version' || {
  echo "the Datadog check needs python 3.12+; set PYTHON=" >&2
  exit 1
}
mkdir -p "$ROOT/check/datadog_checks/yarn/config_models"
"$PYTHON" -m venv "$ROOT/venv"
"$ROOT/venv/bin/python" -m pip install --quiet --upgrade pip
"$ROOT/venv/bin/python" -m pip install --quiet "datadog-checks-base[deps]==38.5.0"

while read -r sum file; do
  [ -n "$file" ] || continue
  dest="$ROOT/check/datadog_checks/yarn/$file"
  curl -fsSL --retry 3 -o "$dest" "$BASE/$file"
  got=$(sha256_of "$dest")
  if [ "$got" != "$sum" ]; then
    echo "SHA-256 mismatch for $file: got $got, want $sum" >&2
    exit 1
  fi
done <<'FILES'
b0e357bad6ac39851f6ed9efeff0f6643fc3c7d7b71f65f2ea79df1b6f7b2054 __about__.py
73df4ceba7e0f21c6c5916a869bc7f79ca8a6e53a61f43a0d52d075cf87998fa __init__.py
747f3163a9da1a8313b38cae6ef656ca1d9f5ae4512ec143ebf33013481e5c8d yarn.py
c9cf5c66894430e7edbb00d00613b58ccfd38360f2fe490a23c17cf71ed294dc config_models/__init__.py
4e6384126e19a7c06d995007c028762f350297fb92e7cae7d68b80381617ea38 config_models/defaults.py
cd77f64995d47a35977505a23806a9e2f65c10da6448e900071dd17bc433ae0a config_models/instance.py
a82ae2b7a2fbc238ef71b998ab164cfe57792d3fde1203f40260123638310aca config_models/shared.py
0424fe17778b76e1b589b9564d0d543d1b71dba1edd6e5d71a7c528dddf68e0b config_models/validators.py
FILES

"$ROOT/venv/bin/python" -I -c 'import sys; sys.path.insert(0, sys.argv[1]); from datadog_checks.yarn import YarnCheck' "$ROOT/check"
echo "export NETGET_DATADOG_YARN=$ROOT"
