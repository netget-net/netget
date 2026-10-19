#!/bin/bash
# Regenerate every prompt snapshot from the current code.
#
# Writes tests/prompt/snapshots/*.snap.md and tests/prompt_snapshots/snapshots/*.snap.md
# through snapshot_util's UPDATE_SNAPSHOTS=1 mode, which overwrites each compared snapshot
# and passes. There are no feature flags to choose: every build compiles every protocol,
# and the parts of a prompt that depend on the compiled set are normalised in
# tests/prompt/mod.rs before comparison.
#
# A regenerated snapshot proves nothing by itself. Read the diff before committing it.
set -euo pipefail

cd "$(dirname "$0")/../.."

UPDATE_SNAPSHOTS=1 ./cargo-isolated.sh test --test prompt --test prompt_snapshots

echo
echo "Snapshots regenerated. Review them before committing:"
git status --short -- tests/prompt/snapshots tests/prompt_snapshots/snapshots
