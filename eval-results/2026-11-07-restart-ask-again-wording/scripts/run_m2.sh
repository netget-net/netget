#!/bin/zsh
# Baseline for the ask-again wording: master b6bb3786d, three cases, each through a recording
# proxy so the ask-again prompts can be replayed.
cd /tmp/telnet-line
for c in quiz redis again; do
  python3 /Users/matus/dev/netget/.claude/worktrees/agent-a0ad90bb110db51f6/eval-results/2026-11-06-seed-bisect/scripts/recproxy.py 21999 /tmp/telnet-line/rec-m2-$c > /tmp/telnet-line/proxy-$c.log 2>&1 &
  PROXY=$!
  sleep 1
  OLLAMA_URL=http://127.0.0.1:21999 python3 /tmp/telnet-line/harness.py /tmp/telnet-line/netget-m2 $c m2 42 43 44 45 46 47 48 49
  kill $PROXY
  sleep 1
done
