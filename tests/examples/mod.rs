//! E2E tests for protocol examples
//!
//! This module contains tests that verify protocol examples work correctly.
//! Unlike static validation tests, these tests actually start servers,
//! trigger events, and verify that example responses execute successfully.
//!
//! ## Test Naming Convention
//!
//! All tests follow the pattern `example_test_{protocol}_protocol` to allow
//! filtering with `--test '*example*'`.
//!
//! ## Running Tests
//!
//! ```bash
//! # Run all example tests
//! ./test-examples.sh
//!
//! # Run specific protocol example test
//! ./cargo-isolated.sh test --no-default-features --features tcp \
//!     --test '*example*' -- example_test_tcp_protocol
//! ```
//!
//! ## Test Structure
//!
//! Each protocol has its own test file that:
//! 1. Uses `ProtocolExampleTest` builder from the framework
//! 2. Configures mock responses from the protocol's `response_example` values
//! 3. Triggers events using the appropriate `EventTrigger`
//! 4. Verifies mock expectations were met

// Feature-gated protocol example tests
// Each test file tests a single protocol's examples

pub mod tcp_examples_test;

pub mod dns_examples_test;

pub mod http_examples_test;

// Comprehensive tests that read ACTUAL protocol examples from protocol definitions
// These tests use get_startup_examples() and response_example values directly
#[cfg(test)]
pub mod protocol_examples_test;

// Runnability harness: classifies every protocol's startup examples into concrete problem
// categories (placeholder script code, unknown static actions, empty llm instruction) and
// enforces a shrink-only allowlist of currently-broken protocols. Runs with all features to
// see every protocol; harmless on subset builds.
#[cfg(test)]
pub mod example_runnability_test;

// Coverage test runs with all features to verify all protocols have tests
#[cfg(test)]
pub mod coverage_test;
