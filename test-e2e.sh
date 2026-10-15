#!/bin/bash
# E2E Test Runner for NetGet
# Runs each protocol's server and client suites by test-name filter. Protocols are not Cargo
# features: every protocol is compiled in, so a protocol's tests are selected by module path
# (`server::<protocol>::`, `client::<protocol>::`).
#
# Usage:
#   ./test-e2e.sh                    # Run all E2E tests
#   ./test-e2e.sh whois dns http     # Run specific protocol tests
#   ./test-e2e.sh --list             # List available protocols
#
# Features:
# - A protocol is any tests/server/<protocol>/ or tests/client/<protocol>/ directory
# - Uses cargo-isolated.sh for build isolation
# - Automatically sets OLLAMA_LOCK_PATH for concurrent test safety
# - Fails fast if invalid protocol specified

set -e

# Color output for better readability
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Determine project root
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

# Parse arguments
PROTOCOLS=()
VERBOSE=false
DRY_RUN=false
USE_OLLAMA=false  # Default: use mocks (no Ollama)

# Process arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --use-ollama)
            USE_OLLAMA=true
            shift
            ;;
        --verbose|-v)
            VERBOSE=true
            shift
            ;;
        --dry-run|-n)
            DRY_RUN=true
            shift
            ;;
        --help|-h)
            echo "E2E Test Runner for NetGet"
            echo ""
            echo "Usage:"
            echo "  $0 [OPTIONS] [PROTOCOLS...]"
            echo ""
            echo "Options:"
            echo "  --use-ollama     Use real Ollama instead of mocks (requires Ollama running)"
            echo "  --verbose, -v    Show detailed test output"
            echo "  --dry-run, -n    Show what would be run without executing"
            echo "  --help, -h       Show this help message"
            echo ""
            echo "Test Modes:"
            echo "  Default          Use mock LLM responses (no Ollama required)"
            echo "  --use-ollama     Use real Ollama (requires Ollama running)"
            echo ""
            echo "Examples:"
            echo "  $0                          # List available E2E test protocols"
            echo "  $0 all                      # Run all E2E tests with mocks"
            echo "  $0 amqp tcp                 # Run AMQP and TCP tests with mocks"
            echo "  $0 --use-ollama whois       # Run WHOIS tests with real Ollama"
            echo ""
            echo "For the scored real-model eval (pass rates, failure diagnoses, a"
            echo "published results file) see ./run-eval.sh, which is a different thing:"
            echo "this script runs the pass/fail suites, that one measures whether a"
            echo "model can drive a protocol from its own action descriptions."
            echo "  $0 --dry-run tor            # Preview what would be executed"
            exit 0
            ;;
        -*)
            echo -e "${RED}Error: Unknown option: $1${NC}" >&2
            echo "Use --help for usage information" >&2
            exit 1
            ;;
        *)
            PROTOCOLS+=("$1")
            shift
            ;;
    esac
done

# Protocols with a suite: every directory under tests/server/ or tests/client/. The directory
# name is the test module name, so it is also the filter.
get_e2e_protocols() {
    find "$PROJECT_ROOT/tests/server" "$PROJECT_ROOT/tests/client" -mindepth 1 -maxdepth 1 -type d \
        | xargs -n1 basename | sort -u
}

# If no protocols specified, show list and exit
if [ ${#PROTOCOLS[@]} -eq 0 ]; then
    echo -e "${BLUE}Protocols with E2E suites:${NC}"
    get_e2e_protocols | sed 's/^/  /'
    echo ""
    echo -e "${BLUE}Total:${NC} $(get_e2e_protocols | wc -l | tr -d ' ')"
    echo ""
    echo -e "${BLUE}Usage:${NC}"
    echo "  $0 all                # Run all E2E tests"
    echo "  $0 whois dns tor      # Run specific protocol tests"
    exit 0
fi

# Handle "all" keyword to run all tests
if [ ${#PROTOCOLS[@]} -eq 1 ] && [ "${PROTOCOLS[0]}" = "all" ]; then
    echo -e "${BLUE}Running all E2E tests...${NC}"
    PROTOCOLS=($(get_e2e_protocols))
    echo -e "${BLUE}Found ${#PROTOCOLS[@]} protocols with E2E suites${NC}"
fi

# Validate every protocol named has a suite BEFORE running any tests
MISSING_TESTS=()
for protocol in "${PROTOCOLS[@]}"; do
    if ! get_e2e_protocols | grep -qx "$protocol"; then
        MISSING_TESTS+=("$protocol")
    fi
done
if [ ${#MISSING_TESTS[@]} -gt 0 ]; then
    echo -e "${RED}Error: no tests/server/<protocol>/ or tests/client/<protocol>/ for:${NC}" >&2
    for protocol in "${MISSING_TESTS[@]}"; do
        echo -e "  ${RED}✗${NC} $protocol" >&2
    done
    echo "" >&2
    echo "Protocols with E2E suites:" >&2
    get_e2e_protocols | sed 's/^/  /' >&2
    exit 1
fi

echo -e "${GREEN}All validations passed!${NC}"
echo ""

# Export flag for tests if using Ollama
if [ "$USE_OLLAMA" = true ]; then
    export NETGET_USE_OLLAMA=1
    echo -e "${BLUE}Test Mode:${NC} Real (using Ollama)"
    echo -e "  ${YELLOW}→${NC} Using real Ollama (requires Ollama running)"
else
    echo -e "${BLUE}Test Mode:${NC} Mock (default)"
    echo -e "  ${YELLOW}→${NC} Using mock LLM responses (no Ollama required)"
fi
echo ""

# Setup Ollama lock for concurrent test safety
OLLAMA_LOCK_PATH="${OLLAMA_LOCK_PATH:-./netget-ollama.lock}"
export OLLAMA_LOCK_PATH
echo -e "${BLUE}Using Ollama lock:${NC} $OLLAMA_LOCK_PATH"
echo ""

# Track results
PASSED=0
FAILED=0
FAILED_PROTOCOLS=()

# Run tests for each protocol
for protocol in "${PROTOCOLS[@]}"; do
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}Testing protocol: ${GREEN}$protocol${NC}"
    echo -e "${BLUE}========================================${NC}"

    TEST_CMD=(
        ./cargo-isolated.sh
        test
        --test server
        --test client
        --
        "server::${protocol}::"
        "client::${protocol}::"
    )

    # Real-Ollama mode travels in NETGET_USE_OLLAMA (exported above), never as a
    # test argument.
    #
    # This script used to append `-- --use-ollama`, and that did not merely fail
    # to help — it broke the mode it was advertising. libtest parses everything
    # after `--` itself and rejects an unknown flag outright:
    #
    #     $ <test-binary> --use-ollama
    #     error: Unrecognized option: 'use-ollama'
    #
    # so the process exited before a single test ran, and the script reported the
    # protocol FAILED. `./test-e2e.sh --use-ollama <protocol>` could not work in
    # that form. `tests/helpers/netget.rs` documents the same trap, and the arg
    # scan it keeps is only for a custom harness that forwards unknown flags.
    if [ "$VERBOSE" = true ]; then
        TEST_CMD+=(--nocapture --test-threads=1)
    fi

    # Run the test (or show what would be run in dry-run mode)
    if [ "$DRY_RUN" = true ]; then
        echo -e "${YELLOW}[DRY RUN]${NC} Would execute: ${TEST_CMD[*]}"
        echo -e "${YELLOW}[DRY RUN]${NC} Skipping actual test execution"
        PASSED=$((PASSED + 1))
    else
        if "${TEST_CMD[@]}" 2>&1; then
            echo -e "${GREEN}✓ $protocol E2E tests PASSED${NC}"
            PASSED=$((PASSED + 1))
        else
            echo -e "${RED}✗ $protocol E2E tests FAILED${NC}"
            FAILED=$((FAILED + 1))
            FAILED_PROTOCOLS+=("$protocol")
        fi
    fi
    echo ""
done

# Print summary
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}E2E Test Summary${NC}"
echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}Passed:${NC} $PASSED"
if [ $FAILED -gt 0 ]; then
    echo -e "${RED}Failed:${NC} $FAILED"
    echo ""
    echo -e "${RED}Failed protocols:${NC}"
    for protocol in "${FAILED_PROTOCOLS[@]}"; do
        echo -e "  ${RED}✗${NC} $protocol"
    done
fi
echo ""

# Exit with appropriate code
if [ $FAILED -gt 0 ]; then
    exit 1
else
    echo -e "${GREEN}All E2E tests passed!${NC}"
    exit 0
fi
