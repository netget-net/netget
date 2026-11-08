#!/bin/zsh
cd /tmp/lane3-work/ftp
for h in 45 46; do
  for v in master f2; do
    python3 /tmp/lane3-replay.py pass$h.req.json pass$h-$v.txt ftp_pass_230 1-20 --par 4 > tally-pass$h-$v.txt
  done
done
grep -h TALLY tally-pass45-*.txt tally-pass46-*.txt
