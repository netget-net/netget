#!/bin/zsh
cd /tmp/lane3-work/prom
python3 /tmp/lane3-variant.py master.txt p1.txt p1.json
python3 /tmp/lane3-variant.py master.txt p3.txt p3.json
for v in master p1 p3; do
  python3 /tmp/lane3-replay.py scrape.req.json $v.txt prom_hist_ok 1-20 --par 4 > tally-$v.txt
done
grep -h TALLY tally-*.txt
