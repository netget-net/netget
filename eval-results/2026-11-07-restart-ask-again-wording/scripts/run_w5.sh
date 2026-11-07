#!/bin/zsh
# Full seeded runs of the reworded ask-again on the three restart-check cases.
cd /tmp/telnet-line
for c in quiz redis again; do
  python3 /tmp/telnet-line/harness.py /tmp/telnet-line/netget-w5 $c w5 42 43 44 45 46 47 48 49
done
