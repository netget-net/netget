#!/bin/sh
# Install Datadog's Spark integration — an independent consumer of the Spark monitoring REST API
# — into an owned ROOT, to drive NetGet's Spark server with:
#
#   ROOT/venv   datadog-checks-base[deps] 38.5.0 and beautifulsoup4 4.15.0 (the check's own pin)
#   ROOT/check/datadog_checks/spark   the check itself, DataDog/integrations-core tag
#               spark-7.8.0 (commit below), each file's SHA-256 pinned. Datadog publishes the
#               check only inside its Agent and as source; the PyPI name is a placeholder.
#
# Needs python3.12 or newer with venv.
#
# Usage: sh tests/server/spark/install_datadog_check.sh /absolute/owned/root
# Prints the NETGET_DATADOG_SPARK export tests/server/spark/datadog_check_test.rs reads.
set -eu

ROOT=${1:?usage: install_datadog_check.sh /absolute/owned/root}
PYTHON=${PYTHON:-python3}
COMMIT=bd26bcbbce80591de341e2d2c964d39bfb79da3e
BASE=https://raw.githubusercontent.com/DataDog/integrations-core/$COMMIT/spark/datadog_checks/spark

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
mkdir -p "$ROOT/check/datadog_checks/spark/config_models"
"$PYTHON" -m venv "$ROOT/venv"
"$ROOT/venv/bin/python" -m pip install --quiet --upgrade pip
"$ROOT/venv/bin/python" -m pip install --quiet \
  "datadog-checks-base[deps]==38.5.0" "beautifulsoup4==4.15.0"

while read -r sum file; do
  [ -n "$file" ] || continue
  dest="$ROOT/check/datadog_checks/spark/$file"
  curl -fsSL --retry 3 -o "$dest" "$BASE/$file"
  got=$(sha256_of "$dest")
  if [ "$got" != "$sum" ]; then
    echo "SHA-256 mismatch for $file: got $got, want $sum" >&2
    exit 1
  fi
done <<'FILES'
4be6684468b59ac4a7b3def81568071ec053ffca1fe676660de9a1a7a5478066 __about__.py
3d6b00930cad818d9fbd466a7820aea214b016c4321e3b605926a01fba23651c __init__.py
52649e3144bf8425bae0c2ec50ba6dd49991f1fc91f09d7f13aa08aac153dbb7 constants.py
4806811cbbe1609a87a5a043b5db5919f5affc92ada4cd9023ea38af72238259 spark.py
c9cf5c66894430e7edbb00d00613b58ccfd38360f2fe490a23c17cf71ed294dc config_models/__init__.py
52e0a0b954a5bfbe00c42fc4e5140e865844862f31ad2135cc2da3b28e6753fc config_models/defaults.py
90be899770d4a5d563ec0728229152cafacc9059c3d9235a4ac745fdd4b61e03 config_models/instance.py
6aeb47e93fb5c0a0ff0e0202bb3bb3cf1ae045eadb5749c34337df9abbf78c84 config_models/shared.py
0424fe17778b76e1b589b9564d0d543d1b71dba1edd6e5d71a7c528dddf68e0b config_models/validators.py
FILES

PYTHONPATH="$ROOT/check" "$ROOT/venv/bin/python" -I -c 'import sys; sys.path.insert(0, sys.argv[1]); from datadog_checks.spark import SparkCheck' "$ROOT/check"
echo "export NETGET_DATADOG_SPARK=$ROOT"
