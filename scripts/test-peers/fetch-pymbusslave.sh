#!/bin/sh
# Fetch pyMbusSlave (Stuart Longland / packom.net), a sample wired M-Bus slave in Python with
# its own frame encoder: it answers SND_NKE, REQ_UD2 (a RSP_UD with a voltage and a volume
# record) and secondary-address selection, and since 2023 listens on a TCP socket directly
# (`--device tcp:<addr>:<port>`), as an M-Bus/IP gateway would. It is one of the two
# independent slaves the M-Bus master's real-server test drives. It needs pyserial.
#
# Pinned commit, no patches.
#
# Usage: sh scripts/test-peers/fetch-pymbusslave.sh /absolute/owned/directory
# Prints PYMBUSSLAVE=<path to slave.py>.
set -eu
base=${1:?Supply an owned absolute directory}
case "$base" in /*) ;; *) echo 'An absolute directory is required' >&2; exit 2;; esac
commit=062f43e11e64a46f41ba14e68124c33b2e2af22a
src="$base/pyMbusSlave"
mkdir -p "$base"
if [ ! -d "$src/.git" ]; then
    git clone --quiet https://github.com/sjlongland/pyMbusSlave.git "$src"
fi
git -C "$src" checkout --quiet "$commit"
test -f "$src/slave.py"
echo "PYMBUSSLAVE=$src/slave.py"
