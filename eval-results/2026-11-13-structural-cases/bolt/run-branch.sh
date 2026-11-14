#!/bin/zsh
cd /tmp/netget-r3-l4/work/bolt
python3 /tmp/netget-r3-l4/scripts/lane3-replay.py login-branch.req.json login-branch.txt bolt_login_accept 1-40 --par 4 > tally40-login-branch.txt
python3 /tmp/netget-r3-l4/scripts/lane3-replay.py login-people-branch.req.json login-people-branch.txt bolt_login_accept 1-40 --par 4 > tally40-login-people-branch.txt
grep -h TALLY tally40-*branch*.txt
