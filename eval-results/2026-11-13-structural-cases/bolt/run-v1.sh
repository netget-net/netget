#!/bin/zsh
cd /tmp/netget-r3-l4/work/bolt
for v in n1 p1 np1; do
  python3 /tmp/netget-r3-l4/scripts/lane3-replay.py login.req.json login-$v.txt bolt_login_accept 1-40 --par 4 > tally40-login-$v.txt
  python3 /tmp/netget-r3-l4/scripts/lane3-replay.py login-people.req.json login-people-$v.txt bolt_login_accept 1-40 --par 4 > tally40-login-people-$v.txt
done
grep -h TALLY tally40-*.txt
