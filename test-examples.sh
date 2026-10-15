#!/bin/bash
# Test script for Protocol Examples
#
# Runs both static validation tests and E2E example tests:
# 1. startup_examples_validation_test - Validates JSON structure
# 2. examples/coverage_test - Verifies test coverage
# 3. E2E example tests (*example*) - Actually runs protocols with examples
#
# Usage:
#   ./test-examples.sh                    # Run all example tests
#   ./test-examples.sh --static-only      # Run only static validation
#   ./test-examples.sh --e2e-only         # Run only E2E tests
#   ./test-examples.sh tcp http dns       # Run specific protocol E2E tests

# Don't use set -e - we want to track failures and report at the end

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Track failures
FAILED_TESTS=()
PASSED_TESTS=()

# Parse arguments
STATIC_ONLY=false
E2E_ONLY=false
PROTOCOLS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --static-only)
            STATIC_ONLY=true
            shift
            ;;
        --e2e-only)
            E2E_ONLY=true
            shift
            ;;
        --help|-h)
            echo "Protocol Examples Test Runner"
            echo ""
            echo "Usage:"
            echo "  $0 [OPTIONS] [PROTOCOLS...]"
            echo ""
            echo "Options:"
            echo "  --static-only    Run only static validation tests"
            echo "  --e2e-only       Run only E2E example tests"
            echo "  --help, -h       Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0                # Run all example tests"
            echo "  $0 --static-only  # Run only static validation"
            echo "  $0 tcp http dns   # Run E2E tests for specific protocols"
            exit 0
            ;;
        *)
            PROTOCOLS+=("$1")
            shift
            ;;
    esac
done

echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║              Protocol Examples Tests                           ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
echo

# Every protocol is compiled in; --all-features adds the system-library ones too.
FEATURE_FLAGS="--all-features"
echo -e "${BLUE}Feature flags: ${FEATURE_FLAGS}${NC}"
echo

# Phase 1: Static Validation Tests
if [ "$E2E_ONLY" = false ]; then
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}Phase 1: Static Validation Tests${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo

    echo -e "${YELLOW}Running startup_examples_validation_test...${NC}"
    echo "─────────────────────────────────────────────────────────────────"
    if ./cargo-isolated.sh test $FEATURE_FLAGS --test startup_examples_validation_test -- --test-threads=100 --nocapture; then
        echo -e "${GREEN}✓ Static validation tests passed${NC}"
        PASSED_TESTS+=("Static validation")
    else
        echo -e "${RED}✗ Static validation tests FAILED${NC}"
        FAILED_TESTS+=("Static validation")
    fi
    echo
fi

# Phase 2: Coverage Verification
if [ "$E2E_ONLY" = false ]; then
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}Phase 2: Coverage Verification${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo

    echo -e "${YELLOW}Running coverage tests...${NC}"
    echo "─────────────────────────────────────────────────────────────────"
    if ./cargo-isolated.sh test $FEATURE_FLAGS coverage_test -- --test-threads=100 --nocapture 2>/dev/null; then
        echo -e "${GREEN}✓ Coverage tests passed${NC}"
        PASSED_TESTS+=("Coverage verification")
    else
        echo -e "${RED}✗ Coverage tests FAILED${NC}"
        FAILED_TESTS+=("Coverage verification")
    fi
    echo
fi

# Phase 3: E2E Example Tests
if [ "$STATIC_ONLY" = false ]; then
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}Phase 3: E2E Example Tests${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo

    if [ ${#PROTOCOLS[@]} -gt 0 ]; then
        # Run specific protocol tests
        echo -e "${YELLOW}Running E2E example tests for: ${PROTOCOLS[*]}${NC}"
        echo "─────────────────────────────────────────────────────────────────"

        for protocol in "${PROTOCOLS[@]}"; do
            echo -e "${BLUE}Testing protocol: $protocol${NC}"
            if ./cargo-isolated.sh test --test examples -- "${protocol}_examples_test" \
                --test-threads=100 --nocapture; then
                echo -e "${GREEN}✓ $protocol example tests passed${NC}"
                PASSED_TESTS+=("$protocol E2E")
            else
                echo -e "${RED}✗ $protocol example tests FAILED${NC}"
                FAILED_TESTS+=("$protocol E2E")
            fi
            echo
        done
    else
        # Run all E2E example tests
        echo -e "${YELLOW}Running all E2E example tests...${NC}"
        echo "─────────────────────────────────────────────────────────────────"

        # Run all tests in the examples module (includes both example_test_* and test_all_protocols_*)
        # Using --test examples runs all tests in tests/examples/
        if ./cargo-isolated.sh test $FEATURE_FLAGS --test examples -- --test-threads=100 --nocapture; then
            echo -e "${GREEN}✓ E2E example tests passed${NC}"
            PASSED_TESTS+=("E2E examples")
        else
            echo -e "${RED}✗ E2E example tests FAILED${NC}"
            FAILED_TESTS+=("E2E examples")
        fi
    fi
    echo
fi

# Final Summary
echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
if [ ${#FAILED_TESTS[@]} -eq 0 ]; then
    echo -e "${BLUE}║${GREEN}                    All Tests Passed                            ${BLUE}║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo
    echo -e "${GREEN}Summary:${NC}"
    echo -e "  Passed: ${#PASSED_TESTS[@]}"
    for test in "${PASSED_TESTS[@]}"; do
        echo -e "    ${GREEN}✓${NC} $test"
    done
    echo
    exit 0
else
    echo -e "${BLUE}║${RED}                    Some Tests Failed                           ${BLUE}║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo
    echo -e "${RED}Summary:${NC}"
    echo -e "  Passed: ${#PASSED_TESTS[@]}"
    for test in "${PASSED_TESTS[@]}"; do
        echo -e "    ${GREEN}✓${NC} $test"
    done
    echo -e "  ${RED}Failed: ${#FAILED_TESTS[@]}${NC}"
    for test in "${FAILED_TESTS[@]}"; do
        echo -e "    ${RED}✗${NC} $test"
    done
    echo
    exit 1
fi
