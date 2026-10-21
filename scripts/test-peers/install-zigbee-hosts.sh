#!/bin/sh
# Install the two independent Zigbee hosts the zigbee server suite drives: zigpy's bellows
# (Python, EZSP over ASH via socket:// device paths) in a venv, and zigbee-herdsman — the
# library Zigbee2MQTT runs on, whose `ember` adapter speaks EZSP over tcp:// — from npm.
# Both are pinned with their dependencies' versions resolved at those pins; nothing is
# installed system-wide and nothing needs root.
#
# Usage: sh scripts/test-peers/install-zigbee-hosts.sh /absolute/owned/directory
# Prints the NETGET_ZIGBEE_* variables tests/server/zigbee reads.
set -eu
base=${1:?Supply an owned absolute directory}
case "$base" in /*) ;; *) echo 'An absolute directory is required' >&2; exit 2;; esac
python=${PYTHON:-python3}
bellows_version=0.46.2
zigpy_version=0.84.0
# zigpy 0.84 accepts aiosqlite 0.22, whose Connection is no longer a thread, and then fails
# to close its database on shutdown; 0.21.0 is the last release it closes cleanly.
aiosqlite_version=0.21.0
herdsman_version=11.1.1
mkdir -p "$base"
"$python" -m venv "$base/venv" >&2
"$base/venv/bin/pip" install --quiet --disable-pip-version-check \
    "bellows==$bellows_version" "zigpy==$zigpy_version" "aiosqlite==$aiosqlite_version" >&2
"$base/venv/bin/bellows" --help >/dev/null
mkdir -p "$base/herdsman"
(
    cd "$base/herdsman"
    [ -f package.json ] || printf '{"name":"netget-zigbee-peers","private":true}\n' > package.json
    npm install --no-audit --no-fund --save-exact "zigbee-herdsman@$herdsman_version" >&2
)
node -e "require('$base/herdsman/node_modules/zigbee-herdsman')" >&2
echo "export NETGET_ZIGBEE_BELLOWS_VENV=$base/venv"
echo "export NETGET_ZIGBEE_HERDSMAN=$base/herdsman"
