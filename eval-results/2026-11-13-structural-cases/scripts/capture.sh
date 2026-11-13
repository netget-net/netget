#!/bin/zsh
# usage: capture.sh <outdir> <proxyport> <protocol> <seed> <instruction> -- <client command with {PORT}>
# Runs a copy of netget (/tmp/netget-r3-l4/bin/netget) for one protocol behind a recording proxy,
# drives it with the client command, and lets netget exit by itself (--exit-after-events).
OUT=$1; PP=$2; PROTO=$3; SEED=$4; INSTR=$5; shift 5
[ "$1" = "--" ] && shift
CLIENT="$*"
mkdir -p "$OUT"
rm -f "$OUT/ready.json"
python3 /Users/matus/dev/netget/.claude/worktrees/agent-a2baecd9a48ad917c/eval-results/2026-11-06-seed-bisect/scripts/recproxy.py "$PP" "$OUT/cap" > "$OUT/proxy.log" 2>&1 &
PROXY=$!
sleep 1
/tmp/netget-r3-l4/bin/netget --model llama3.1:8b --log-level info --no-scripts \
  --server "$PROTO" --port 0 --llm-seed "$SEED" --llm-request-timeout 600 \
  --ollama-url "http://127.0.0.1:$PP" --ready-file "$OUT/ready.json" \
  --exit-after-events "${EVENTS:-1}" "$INSTR" > "$OUT/netget.log" 2>&1 &
NG=$!
for i in $(seq 1 300); do [ -s "$OUT/ready.json" ] && break; sleep 0.2; done
PORT=$(python3 -c "import json,sys;d=json.load(open('$OUT/ready.json'));s=d['servers'][0];print(s.get('port') or s['address'].rsplit(':',1)[1])")
echo "port $PORT"
CMD=${CLIENT//\{PORT\}/$PORT}
zsh -c "$CMD" > "$OUT/client.out" 2>&1
echo "client exit $?" >> "$OUT/client.out"
for i in $(seq 1 600); do kill -0 $NG 2>/dev/null || break; sleep 0.5; done
kill $PROXY
cat "$OUT/client.out"
