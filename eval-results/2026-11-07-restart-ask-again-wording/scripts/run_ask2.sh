#!/bin/zsh
# Second round: W4/W5, and more seeds on the redis prompts (the regression risk).
cd /tmp/telnet-line
python3 /tmp/telnet-line/variants/ask.py > /dev/null
V=/tmp/telnet-line/variants
for req in rec-m2-redis/00004 rec-m2-redis/00007; do
  for v in - $V/ask_W3.py; do
    python3 replay_ask.py $req-api_generate.req.json $v 21-40
  done
  for v in $V/ask_W4.py $V/ask_W5.py; do
    python3 replay_ask.py $req-api_generate.req.json $v 1-40
  done
done
for req in rec-m2-quiz/00040 rec-m2-again/00008 rec-master/00004; do
  for v in $V/ask_W4.py $V/ask_W5.py; do
    python3 replay_ask.py $req-api_generate.req.json $v 1-20
  done
done
