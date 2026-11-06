#!/usr/bin/env bash
# Run one real-client evidence group from the precompiled all-feature test binaries.
#
#   run-evidence-group.sh <blocking|advisory> <filter>
#
# `<p>::<file>` is a real third-party client against a NetGet server, run from the `server`
# test target; `client/<p>::<file>` is a NetGet client against a real third-party server, run
# from the `client` target. The result lands in $EVIDENCE_DIR/<tier>/ as a `.status` row and a
# `.log`, which .github/scripts/summarize-evidence.py reads. The script exits non-zero when the
# group failed, timed out, or ran no test: a filter that matches nothing is not evidence.
set -uo pipefail

tier=$1
filter=$2
case "$tier" in
  blocking) annotation=error ;;
  advisory) annotation=warning ;;
  *) echo "unknown evidence tier: $tier" >&2; exit 2 ;;
esac

target=server
test_filter=$filter
case "$filter" in
  client/*) target=client ; test_filter=${filter#client/} ;;
esac

dir="$EVIDENCE_DIR/$tier"
mkdir -p "$dir"
result_file="$dir/${filter//[:\/]/_}"
printf 'running\t%s\n' "$filter" > "$result_file.status"

# Each group has a bounded runtime, so a stuck client cannot consume the whole step. pipefail
# keeps a cargo or timeout failure visible through tee.
if timeout --signal=TERM --kill-after=10s 5m \
     cargo test --locked --all-features --test "$target" -- \
     --test-threads=32 --nocapture "$test_filter" 2>&1 | tee "$result_file.log" \
   && grep -Eq '^test result: ok\. [1-9][0-9]* passed;' "$result_file.log"; then
  printf 'passed\t%s\n' "$filter" > "$result_file.status"
  exit 0
fi
printf 'FAILED\t%s\n' "$filter" > "$result_file.status"
echo "::$annotation::$filter ($tier) failed or ran no tests - a maturity rating rests on this test"
exit 1
