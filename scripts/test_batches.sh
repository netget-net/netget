#!/usr/bin/env bash
# Run every top-level test target (tests/*.rs other than server.rs and client.rs), a batch at a
# time, deleting each batch's test executables before building the next.
#
# Why: every protocol is compiled into every build, so each test binary links the whole
# library — about 870 MB unoptimised even without debug info, and there are ~230 targets. All
# of them at once is ~200 GB, more than a CI runner or most laptops have. A batch of 10 needs
# ~9 GB on top of the shared ~7 GB of dependencies (with incremental compilation off).
#
# Usage: scripts/test_batches.sh [cargo test options]
#   e.g. scripts/test_batches.sh --locked --no-default-features --features mcp-stdio,sqlite
# Env:   BATCH (default 10), TEST_THREADS (default 32), CARGO_TARGET_DIR (default target).
# Exits non-zero if any batch failed; every batch still runs.
set -uo pipefail
cd "$(dirname "$0")/.."

batch=${BATCH:-10}
threads=${TEST_THREADS:-32}
deps="${CARGO_TARGET_DIR:-target}/debug/deps"
targets=()
while IFS= read -r t; do targets+=("$t"); done < <(ls tests/*.rs | xargs -n1 basename | sed 's/\.rs$//' | grep -vxE 'server|client')

status=0
for ((i = 0; i < ${#targets[@]}; i += batch)); do
    chunk=("${targets[@]:i:batch}")
    args=()
    for t in "${chunk[@]}"; do args+=(--test "$t"); done
    echo "::group::tests $((i + 1))-$((i + ${#chunk[@]})) of ${#targets[@]}: ${chunk[*]}"
    cargo test --no-fail-fast "$@" "${args[@]}" -- --test-threads="$threads" || status=1
    echo "::endgroup::"
    # Test executables only: libraries and build-script outputs are shared by every batch.
    find "$deps" -maxdepth 1 -type f -perm -u+x ! -name 'lib*' ! -name '*.d' -size +20M -delete 2>/dev/null
done
exit $status
