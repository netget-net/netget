#!/bin/zsh
cd /tmp/lane3-work/dict
for v in master v1 v2 v3; do
  python3 /tmp/lane3-replay.py define.req.json $v.txt dict_nomatch_strict 1-40 --par 4 > tally-$v.txt
done
grep -h TALLY tally-*.txt
