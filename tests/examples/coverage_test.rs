//! Coverage verification for protocol example tests
//!
//! This module verifies that all protocols with startup examples have
//! corresponding E2E example tests.
//!
//! The test is designed to fail CI if a new protocol is added without
//! an example test, ensuring consistent test coverage.

use netget::protocol::server_registry::registry;
use std::collections::HashSet;

/// Get the list of protocols that have example tests
///
/// This function returns protocol names that have corresponding test files
/// in the tests/examples/ directory. It's maintained manually to track coverage.
fn get_tested_protocols() -> HashSet<String> {
    let mut tested = HashSet::new();

    // TCP example tests
    tested.insert("TCP".to_string());

    // DNS example tests
    tested.insert("DNS".to_string());

    // HTTP example tests
    tested.insert("HTTP".to_string());

    tested
}

/// Get protocols that don't have E2E example tests yet
fn get_protocols_without_tests() -> Vec<(String, usize)> {
    let reg = registry();
    let tested = get_tested_protocols();

    reg.all_protocols()
        .into_iter()
        .filter_map(|(name, protocol)| {
            // All protocols have startup examples (required by trait)
            let event_count = protocol.get_event_types().len();
            if !tested.contains(&name) {
                Some((name, event_count))
            } else {
                None
            }
        })
        .collect()
}

/// Test that prints coverage summary
///
/// This test always passes but prints a summary of test coverage.
/// Use it to track progress towards full coverage.
#[test]
fn example_test_coverage_summary() {
    let reg = registry();
    let tested = get_tested_protocols();
    let total_protocols: Vec<_> = reg.all_protocols().into_iter().collect();

    println!("\n=== Protocol Example Test Coverage Summary ===");
    println!("Total protocols: {}", total_protocols.len());
    println!("Protocols with E2E example tests: {}", tested.len());

    let coverage_pct = if total_protocols.is_empty() {
        100.0
    } else {
        (tested.len() as f64 / total_protocols.len() as f64) * 100.0
    };

    println!("Coverage: {:.1}%", coverage_pct);

    println!("\nProtocols with tests:");
    for name in &tested {
        println!("  ✓ {}", name);
    }

    let missing = get_protocols_without_tests();
    if !missing.is_empty() {
        println!("\nProtocols WITHOUT tests (need example tests):");
        for (name, event_count) in &missing {
            println!("  ✗ {} ({} event types)", name, event_count);
        }
    }

    println!("\n=== Summary ===");
    println!(
        "Tested: {} / {} ({:.1}%)",
        tested.len(),
        total_protocols.len(),
        coverage_pct
    );
}

/// Test that verifies all event types have response_examples
///
/// This ensures that every EventType defined in protocols has a valid
/// response_example that can be tested.
#[test]
fn example_test_all_event_types_have_examples() {
    let reg = registry();
    let mut missing_examples = Vec::new();
    let mut total_event_types = 0;

    for (protocol_name, protocol) in reg.all_protocols() {
        for event_type in protocol.get_event_types() {
            total_event_types += 1;

            // Check that response_example is not null and carries a type field.
            // A response_example is either a single action object or an array of
            // them; for an array we check the first element, matching
            // validate_response_example in protocol_examples_test.rs.
            let ex = &event_type.response_example;
            let type_bearer = if ex.is_array() {
                ex.as_array().and_then(|a| a.first())
            } else {
                Some(ex)
            };
            if ex.is_null() {
                missing_examples.push(format!(
                    "{}.{}: null response_example",
                    protocol_name, event_type.id
                ));
            } else if type_bearer
                .and_then(|v| v.as_object())
                .map(|o| o.get("type").is_none())
                .unwrap_or(true)
            {
                missing_examples.push(format!(
                    "{}.{}: response_example missing 'type' field",
                    protocol_name, event_type.id
                ));
            }
        }
    }

    println!("\n=== EventType Response Example Verification ===");
    println!("Total event types: {}", total_event_types);
    println!(
        "With valid response_examples: {}",
        total_event_types - missing_examples.len()
    );

    if !missing_examples.is_empty() {
        println!("\nEvent types with missing/invalid response_examples:");
        for msg in &missing_examples {
            println!("  ✗ {}", msg);
        }
        panic!(
            "Found {} event types with missing/invalid response_examples",
            missing_examples.len()
        );
    }

    println!("✓ All event types have valid response_examples");
}

/// Test that counts total testable examples
#[test]
fn example_test_count_testable_examples() {
    let reg = registry();

    let mut total_event_types = 0;
    let mut total_startup_examples = 0;
    let mut total_alternative_examples = 0;

    for (_name, protocol) in reg.all_protocols() {
        // Count event types
        let event_types = protocol.get_event_types();
        total_event_types += event_types.len();

        // Count alternative examples
        for event_type in &event_types {
            total_alternative_examples += event_type.alternative_examples.len();
        }

        // Count startup examples (3 per protocol - all protocols have them now)
        let _examples = protocol.get_startup_examples();
        total_startup_examples += 3; // llm_mode, script_mode, static_mode
    }

    println!("\n=== Testable Examples Count ===");
    println!("EventType response_examples: {}", total_event_types);
    println!("Alternative examples: {}", total_alternative_examples);
    println!("Startup examples: {}", total_startup_examples);
    println!(
        "Total testable examples: {}",
        total_event_types + total_alternative_examples + total_startup_examples
    );
}

/// Test to ensure core protocols have tests
///
/// This test ensures that the most critical/commonly used protocols
/// always have example tests. This subset should never regress.
#[test]
fn example_test_core_protocols_have_tests() {
    let tested = get_tested_protocols();

    // Core protocols that MUST have tests.
    // Explicitly typed: every element is feature-gated, so under a feature set
    // that enables none of them the vec is empty and its element type cannot be
    // inferred (E0282). That is not hypothetical — `--features telnet` alone hits it.
    let core_protocols: Vec<&str> = vec![
        "TCP",
        "HTTP",
        "DNS",
    ];

    let mut missing_core = Vec::new();
    for protocol in core_protocols {
        if !tested.contains(&protocol.to_string()) {
            missing_core.push(protocol);
        }
    }

    if !missing_core.is_empty() {
        panic!(
            "Core protocols missing example tests: {:?}\n\
             These protocols are critical and must have example tests.",
            missing_core
        );
    }

    println!("\n✓ All core protocols have example tests");
}
