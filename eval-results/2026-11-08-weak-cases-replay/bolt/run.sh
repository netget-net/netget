#!/bin/zsh
cd /tmp/lane3-work/bolt
for v in master l1 l2 l3; do
  python3 /tmp/lane3-replay.py login.req.json login-$v.txt bolt_login_accept 1-20 --par 4 > tally-login-$v.txt
  python3 /tmp/lane3-replay.py login-people.req.json login-people-$v.txt bolt_login_accept 1-20 --par 4 > tally-login-people-$v.txt
done
for v in master q1 q2; do
  python3 /tmp/lane3-replay.py query.req.json query-$v.txt bolt_count 1-20 --par 4 > tally-query-$v.txt
  python3 /tmp/lane3-replay.py query-people.req.json query-people-$v.txt bolt_people 1-20 --par 4 > tally-query-people-$v.txt
done
grep -h TALLY tally-*.txt
