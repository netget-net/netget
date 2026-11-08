#!/bin/zsh
# usage: lane3-run-rm.sh <bindir> <outdir> <runs> <seed> [protocols...]
# Runs the real-model harness test binary directly, with the environment run-eval.sh exports.
BIN=$1; OUT=$2; RUNS=$3; SEED=$4; shift 4
ALL=(http dns whois gopher finger dict gemini beanstalkd zabbix gearman nsq redis postgresql mysql
    ldap ipp syslog ntp telnet tcp ftp udp
    prometheus otlp docker vault bolt
    smtp pop3 imap nntp memcached mqtt coap modbus snmp sip websocket nostr
    lmtp rsync)
if [ $# -gt 0 ]; then P=("$@"); else P=("${ALL[@]}"); fi
LIST=${(j:,:)P}
mkdir -p "$OUT"
cd /Users/matus/dev/netget/.claude/worktrees/agent-ae1163dd9c910a9f9
export NETGET_USE_OLLAMA=1
export NETGET_LLM_TEST_MODEL=llama3.1:8b
export NETGET_EVAL_RUNS=$RUNS
export NETGET_EVAL_PROTOCOLS=$LIST
export NETGET_EVAL_SEED=$SEED
export NETGET_EVAL_TEMPERATURE=
export NETGET_EVAL_OUT_DIR=$OUT
export OLLAMA_BASE_URL=${OLLAMA_BASE_URL:-http://127.0.0.1:11434}
export CARGO_BIN_EXE_netget=$BIN/netget
date -u +%FT%TZ > "$OUT/started.txt"
"$BIN/rmtest" real_model_eval --exact --nocapture --test-threads=1 > "$OUT/run.log" 2>&1
echo "exit $?" >> "$OUT/started.txt"
date -u +%FT%TZ >> "$OUT/started.txt"
