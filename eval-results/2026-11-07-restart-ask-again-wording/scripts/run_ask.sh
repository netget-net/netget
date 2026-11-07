#!/bin/zsh
# Ask-again wording replays, seeds 1-20, master sentence and W1-W3.
cd /tmp/telnet-line
python3 /tmp/telnet-line/variants/ask.py > /dev/null
python3 /tmp/telnet-line/variants/ask_combo.py > /dev/null
V=/tmp/telnet-line/variants
# Quiz Q1 ask-again with the old telnet wording (where master sent send_text 22/30).
for v in - $V/ask_W1.py $V/ask_W2.py $V/ask_W3.py; do
  python3 replay_ask.py rec-master/00004-api_generate.req.json $v 1-20
done
# The same prompt with the current telnet wording.
for v in cur cur_W1 cur_W2 cur_W3; do
  python3 replay_ask.py rec-master/00004-api_generate.req.json $V/combo_$v.py 1-20
done
# Current master captures: quiz BYE, quiz "Please answer", redis PONG, redis hello, again DONE.
for req in rec-m2-quiz/00040 rec-m2-quiz/00043 rec-m2-redis/00004 rec-m2-redis/00007 rec-m2-again/00008; do
  for v in - $V/ask_W1.py $V/ask_W2.py $V/ask_W3.py; do
    python3 replay_ask.py $req-api_generate.req.json $v 1-20
  done
done
