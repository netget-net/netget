#!/bin/zsh
# W5 on the current-wording quiz Q1 ask-again and the quiz "Please answer the question." prompt.
cd /tmp/telnet-line
V=/tmp/telnet-line/variants
python3 replay_ask.py rec-master/00004-api_generate.req.json $V/combo_cur_W5.py 1-20
python3 replay_ask.py rec-m2-quiz/00043-api_generate.req.json $V/ask_W5.py 1-20
