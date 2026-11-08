#!/bin/zsh
cd /tmp/lane3-work/dict
for v in master v2; do
  python3 /tmp/lane3-replay.py glimmer.req.json glimmer-$v.txt dict_define_glimmer 1-20 --par 4 > tally-glimmer-$v.txt
done
python3 /tmp/lane3-replay.py define.req.json master.txt dict_nomatch_harness 1-40 --par 4 > tally-harness-master.txt
python3 /tmp/lane3-replay.py define.req.json v2.txt dict_nomatch_harness 1-40 --par 4 > tally-harness-v2.txt
grep -h TALLY tally-glimmer-*.txt tally-harness-*.txt
