#!/usr/bin/env bash
#
# run-eval.sh — the real-model eval harness.
#
# Every other test in this repository drives a MOCK model whose answers the test
# author wrote. This one drives a REAL local model, with a REAL third-party
# client (dig, curl, redis-cli, psql, ldapsearch, ipptool, whois, ftp), and
# scores whether the model could serve a plain-English operator instruction.
#
# It costs real model time. It must never gate a PR. Every run pins the model's
# sampler seed (--seed, default 42), which makes an identical prompt answer
# identically; each run's prompt still carries its own ports and ids, so the
# report measures how often the runs agreed rather than assuming they did.
# See tests/eval/mod.rs for the design and EVAL_RESULTS.md for the output.
#
# Usage:
#   ./run-eval.sh                       # every protocol in the default set
#   ./run-eval.sh http dns tcp          # just these
#   ./run-eval.sh --runs 5 http         # 5 runs per instruction
#   ./run-eval.sh --model llama3.1:8b   # pick the model explicitly
#   ./run-eval.sh --seed 7              # sampler seed (default 42; 'none' = unpinned)
#   ./run-eval.sh --temperature 0       # also pin the temperature (default: model's own)
#   ./run-eval.sh --out /tmp/ipp ipp    # write the two artefacts there, not over the baseline
#   ./run-eval.sh --list                # what would run, and with what client
#
# Output: eval-results/latest.json and EVAL_RESULTS.md, regenerated together
# (or DIR/latest.json and DIR/EVAL_RESULTS.md with --out DIR).

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m'
BLUE=$'\033[0;34m'
NC=$'\033[0m'

# Every protocol with an instruction set in tests/eval/suites.rs. Protocol name
# and Cargo feature name are the same for all of these; if that ever stops being
# true this list grows a mapping.
ALL_PROTOCOLS=(
    http dns whois gopher finger dict gemini beanstalkd zabbix gearman nsq redis postgresql mysql
    ldap ipp syslog ntp telnet tcp ftp udp
    prometheus otlp docker vault bolt
    smtp pop3 imap nntp memcached mqtt coap modbus snmp sip websocket nostr
)

# The default model. Chosen deliberately, and the reasoning matters:
#
#  * It is the smallest and fastest model on this machine (~12s per answer
#    against ~20s for qwen3.8:27b and ~30s for gemma4:31b), and this harness
#    makes hundreds of calls per run.
#  * A weak-but-competent model is the right instrument. A strong model papers
#    over a misleading action description by guessing what was meant; the whole
#    point here is to find descriptions that do not carry a model on their own.
#
# Override with --model or NETGET_LLM_TEST_MODEL. The model is recorded in every
# artefact, because a score is only comparable within one model.
MODEL="${NETGET_LLM_TEST_MODEL:-llama3.1:8b}"
RUNS="${NETGET_EVAL_RUNS:-3}"
SEED="${NETGET_EVAL_SEED:-42}"
TEMPERATURE="${NETGET_EVAL_TEMPERATURE:-}"
OUT_DIR="${NETGET_EVAL_OUT_DIR:-}"

# A LITERAL IP, not `localhost`, and this is load-bearing rather than tidiness.
# `reqwest` hands the URL host to its resolver unconditionally and `hyper-util`'s
# GaiResolver does not special-case a dotted quad, so on macOS `localhost` goes
# through mDNSResponder — one system-wide daemon that serialises under
# concurrency. `ollama_client::client_for_endpoint` bypasses the resolver only
# when the host parses as an IpAddr. With `localhost`, five of eleven cases in
# the first smoke run failed as "Ollama not reachable" against an Ollama that was
# up and answering; with 127.0.0.1 the bypass engages and they do not.
OLLAMA_URL="${OLLAMA_BASE_URL:-http://127.0.0.1:11434}"
export OLLAMA_BASE_URL="$OLLAMA_URL"
PROTOCOLS=()
LIST_ONLY=false

while [ $# -gt 0 ]; do
    case "$1" in
        --runs)
            RUNS="$2"
            shift 2
            ;;
        --model)
            MODEL="$2"
            shift 2
            ;;
        --seed)
            SEED="$2"
            shift 2
            ;;
        --temperature)
            TEMPERATURE="$2"
            shift 2
            ;;
        --out)
            OUT_DIR="$2"
            shift 2
            ;;
        --list)
            LIST_ONLY=true
            shift
            ;;
        --help | -h)
            sed -n '2,28p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        -*)
            echo "${RED}Unknown option: $1${NC}" >&2
            exit 1
            ;;
        *)
            PROTOCOLS+=("$1")
            shift
            ;;
    esac
done

if [ ${#PROTOCOLS[@]} -eq 0 ]; then
    PROTOCOLS=("${ALL_PROTOCOLS[@]}")
fi

# The test binary's working directory is not this one; hand it an absolute path.
case "$OUT_DIR" in
    "" | /*) ;;
    *) OUT_DIR="$PROJECT_ROOT/$OUT_DIR" ;;
esac

# Validate before spending a minute on a build.
for proto in "${PROTOCOLS[@]}"; do
    found=false
    for known in "${ALL_PROTOCOLS[@]}"; do
        [ "$proto" = "$known" ] && found=true && break
    done
    if [ "$found" = false ]; then
        echo "${RED}No eval instruction set for '${proto}'.${NC}" >&2
        echo "Known: ${ALL_PROTOCOLS[*]}" >&2
        echo "Add one in tests/eval/suites.rs and list it in ALL_PROTOCOLS here." >&2
        exit 1
    fi
done

PROTO_LIST=$(printf '%s,' "${PROTOCOLS[@]}")
PROTO_LIST="${PROTO_LIST%,}"

if [ "$LIST_ONLY" = true ]; then
    echo "${BLUE}Protocols:${NC} ${PROTOCOLS[*]}"
    echo "${BLUE}Model:${NC}     $MODEL"
    echo "${BLUE}Runs:${NC}      $RUNS per instruction"
    echo "${BLUE}Seed:${NC}      $SEED   ${BLUE}Temperature:${NC} ${TEMPERATURE:-model default}"
    echo ""
    echo "Instruction sets live in tests/eval/suites.rs."
    exit 0
fi

# --- Preconditions. Each one fails loudly, because a harness that quietly
# --- measures nothing is exactly the defect this repository keeps finding.

echo "${BLUE}Checking Ollama at ${OLLAMA_URL}…${NC}"
if ! TAGS=$(curl -sS -m 10 "${OLLAMA_URL}/api/tags" 2>&1); then
    echo "${RED}Ollama is not reachable at ${OLLAMA_URL}.${NC}" >&2
    echo "Start it (\`ollama serve\`) or set OLLAMA_BASE_URL." >&2
    exit 1
fi

if ! printf '%s' "$TAGS" | grep -q "\"${MODEL}\""; then
    echo "${RED}Model '${MODEL}' is not pulled.${NC}" >&2
    echo "Available:" >&2
    printf '%s' "$TAGS" | grep -oE '"name":"[^"]+"' | sed 's/"name":"/  /;s/"$//' >&2
    echo "Pull it with: ollama pull ${MODEL}" >&2
    exit 1
fi
echo "${GREEN}✓${NC} ${MODEL} is available"

# Report which third-party clients are missing up front. A missing client makes
# its cases 'client-missing' in the results rather than silently absent.
echo "${BLUE}Checking third-party clients…${NC}"
for bin in curl dig whois redis-cli psql mysql ldapsearch ipptool nc ftp python3 \
    mosquitto_sub coap-client snmpget sipsak websocat; do
    if command -v "$bin" >/dev/null 2>&1; then
        echo "  ${GREEN}✓${NC} $bin"
    else
        echo "  ${YELLOW}✗${NC} $bin — its cases will be recorded as client-missing"
    fi
done

echo ""
echo "${BLUE}Protocols:${NC} ${PROTOCOLS[*]}"
echo "${BLUE}Model:${NC}     ${MODEL}"
echo "${BLUE}Runs:${NC}      ${RUNS} per instruction (the score is a rate; the report says"
echo "           whether the runs agreed)"
echo "${BLUE}Seed:${NC}      ${SEED}   ${BLUE}Temperature:${NC} ${TEMPERATURE:-model default}"
[ -n "$OUT_DIR" ] && echo "${BLUE}Output:${NC}    ${OUT_DIR}"
echo ""

export NETGET_USE_OLLAMA=1
export NETGET_LLM_TEST_MODEL="$MODEL"
export NETGET_EVAL_RUNS="$RUNS"
export NETGET_EVAL_PROTOCOLS="$PROTO_LIST"
export NETGET_EVAL_SEED="$SEED"
export NETGET_EVAL_TEMPERATURE="$TEMPERATURE"
export NETGET_EVAL_OUT_DIR="$OUT_DIR"

# A separate target dir by default: sharing target/ means contending on the lock
# with every other agent in this repo. Every protocol is compiled in; the eval
# picks its protocols through NETGET_EVAL_PROTOCOLS.
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/netget-eval-target}"

set +e
./cargo-isolated.sh test \
    --no-default-features \
    --test=eval \
    -- --nocapture --test-threads=1
STATUS=$?
set -e

echo ""
RESULTS_JSON="${OUT_DIR:-eval-results}/latest.json"
if [ -f "$RESULTS_JSON" ]; then
    echo "${GREEN}Results:${NC} ${RESULTS_JSON} and ${OUT_DIR:-.}/EVAL_RESULTS.md"
else
    echo "${RED}No results file was written — the harness did not complete.${NC}" >&2
fi

# A low score is a finding about an action description, not a broken build, so
# it is not this script's job to turn one into a non-zero exit. A non-zero exit
# here means the harness itself could not run.
exit $STATUS
