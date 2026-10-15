//! Comprehensive E2E tests for protocol examples
//!
//! These tests verify that the ACTUAL examples defined in protocols work correctly:
//! - StartupExamples (llm_mode, script_mode, static_mode) from `get_startup_examples()`
//! - EventType `response_example` values from `get_event_types()`
//! - EventType `alternative_examples` values
//!
//! Unlike the manual tests in tcp_examples_test.rs, etc., these tests READ the
//! actual examples from the protocol definitions and use them directly.

#![cfg(test)]

use crate::helpers::{start_netget_server, E2EResult, NetGetConfig};
use netget::llm::actions::Server;
use netget::protocol::server_registry::registry;
use serde_json::json;
use std::time::Duration;

/// Helper to modify a startup example to use port 0 (dynamic allocation)
/// This prevents port conflicts when running tests in parallel
fn with_port_zero(example: &serde_json::Value) -> serde_json::Value {
    let mut modified = example.clone();
    if let Some(obj) = modified.as_object_mut() {
        obj.insert("port".to_string(), json!(0));
    }
    modified
}

/// Why a protocol cannot start on the host running the test, if it cannot.
///
/// A few protocols are genuinely bound to one operating system and refuse to start elsewhere —
/// deliberately, because reporting `Running` while being unable to do the one thing the
/// protocol exists for is worse than refusing. Counting that refusal as a startup failure would
/// make the sweep below assert the opposite of what the protocol promises, so those are skipped
/// with the reason printed.
///
/// Keep this list short and specific. It is for *platform* impossibility only, never for a
/// protocol that is merely flaky or unfinished.
fn unsupported_on_this_platform(protocol_name: &str) -> Option<&'static str> {
    // Privilege the host does not have is the same category as platform impossibility, and is
    // asked of the existing machinery rather than kept as a name list, so it cannot go stale.
    //
    // `server_startup` refuses to spawn a protocol whose declared `privilege_requirement` is
    // not met — deliberately, because a server sitting in `Running` having captured nothing is
    // worse than one that refuses. Counting that refusal as a startup failure makes this sweep
    // assert the opposite of what the privilege gate promises. OSPF (raw IP sockets) is the
    // case that surfaced it on an unprivileged runner.
    if let Some(meta) = registry().metadata(protocol_name) {
        let caps = netget::privilege::SystemCapabilities::detect();
        if !meta.privilege_requirement.is_met_by(&caps) {
            return Some("the host lacks the privilege this protocol declares");
        }
    }

    match protocol_name {
        // A beacon is its advertising payload. Only BlueZ lets an application set
        // ManufacturerData/ServiceData; CoreBluetooth documents every advertising key other
        // than the local name and service UUIDs as ignored, so macOS cannot emit a beacon at
        // all and `spawn()` returns an error there by design.
        "BLUETOOTH_BLE_BEACON" if !cfg!(target_os = "linux") => {
            Some("BLE advertising payloads require Linux/BlueZ")
        }
        // N2 is SCTP (TS 38.412) and NGAP's examples use it; a host with no SCTP stack (macOS,
        // or Linux without the sctp module) refuses to start it by name. Probed, not inferred.
        "NGAP" if !host_has_sctp() => Some("NGAP's transport is SCTP, which this host lacks"),
        // M3UA is SIGTRAN, SCTP by RFC 4666, and its examples ask for it the same way.
        "M3UA" if !host_has_sctp() => Some("M3UA's transport is SCTP, which this host lacks"),
        _ => None,
    }
}

/// Whether the kernel will open an SCTP socket for this process.
fn host_has_sctp() -> bool {
    socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::STREAM,
        Some(socket2::Protocol::from(132)),
    )
    .is_ok()
}

/// Test that reads and validates all startup examples from all protocols
///
/// This test iterates over all registered protocols and verifies their
/// startup examples have valid structure.
#[test]
fn test_all_startup_examples_structure() {
    let reg = registry();

    println!("\n=== Validating Startup Examples Structure ===\n");

    let mut valid_count = 0;
    let mut invalid_count = 0;
    let mut errors = Vec::new();

    for (name, protocol) in reg.all_protocols() {
        let examples = protocol.get_startup_examples();

        // Validate LLM mode example
        if let Err(e) = validate_startup_example(&examples.llm_mode, "llm_mode") {
            errors.push(format!("{} llm_mode: {}", name, e));
            invalid_count += 1;
        } else {
            valid_count += 1;
        }

        // Validate script mode example
        if let Err(e) = validate_startup_example(&examples.script_mode, "script_mode") {
            errors.push(format!("{} script_mode: {}", name, e));
            invalid_count += 1;
        } else {
            valid_count += 1;
        }

        // Validate static mode example
        if let Err(e) = validate_startup_example(&examples.static_mode, "static_mode") {
            errors.push(format!("{} static_mode: {}", name, e));
            invalid_count += 1;
        } else {
            valid_count += 1;
        }
    }

    println!("Valid startup examples: {}", valid_count);
    println!("Invalid startup examples: {}", invalid_count);

    if !errors.is_empty() {
        println!("\nErrors:");
        for error in &errors {
            println!("  ✗ {}", error);
        }
        panic!("Found {} invalid startup examples", errors.len());
    }

    println!("\n✓ All startup examples have valid structure");
}

/// Validate a startup example has required fields
fn validate_startup_example(example: &serde_json::Value, mode: &str) -> Result<(), String> {
    // Can be a single action or array of actions
    let actions = if example.is_array() {
        example.as_array().unwrap().clone()
    } else {
        vec![example.clone()]
    };

    if actions.is_empty() {
        return Err(format!("{}: empty actions", mode));
    }

    // First action should be open_server or contain it
    let first = &actions[0];
    let action_type = first.get("type").and_then(|t| t.as_str());

    if action_type != Some("open_server") {
        return Err(format!(
            "{}: first action should be 'open_server', got {:?}",
            mode, action_type
        ));
    }

    // open_server requires base_stack
    if first.get("base_stack").is_none() {
        return Err(format!("{}: missing 'base_stack' in open_server", mode));
    }

    Ok(())
}

/// Test that validates all response_examples have required fields
#[test]
fn test_all_response_examples_structure() {
    let reg = registry();

    println!("\n=== Validating Response Examples Structure ===\n");

    let mut valid_count = 0;
    let mut invalid_count = 0;
    let mut errors = Vec::new();

    for (name, protocol) in reg.all_protocols() {
        for event_type in protocol.get_event_types() {
            if let Err(e) = validate_response_example(&event_type.response_example) {
                errors.push(format!("{}.{}: {}", name, event_type.id, e));
                invalid_count += 1;
            } else {
                valid_count += 1;
            }

            // Also validate alternative examples
            for (i, alt) in event_type.alternative_examples.iter().enumerate() {
                if let Err(e) = validate_response_example(alt) {
                    errors.push(format!(
                        "{}.{} alternative[{}]: {}",
                        name, event_type.id, i, e
                    ));
                    invalid_count += 1;
                } else {
                    valid_count += 1;
                }
            }
        }
    }

    println!("Valid response examples: {}", valid_count);
    println!("Invalid response examples: {}", invalid_count);

    if !errors.is_empty() {
        println!("\nErrors:");
        for error in &errors {
            println!("  ✗ {}", error);
        }
        panic!("Found {} invalid response examples", errors.len());
    }

    println!("\n✓ All response examples have valid structure");
}

/// Validate a response example has required fields
fn validate_response_example(example: &serde_json::Value) -> Result<(), String> {
    if example.is_null() {
        return Err("null response_example".to_string());
    }

    // Can be a single action or array
    let action = if example.is_array() {
        example.as_array().and_then(|a| a.first())
    } else {
        Some(example)
    };

    let action = action.ok_or_else(|| "empty actions array".to_string())?;

    // Must have a "type" field
    if action.get("type").is_none() {
        return Err("missing 'type' field".to_string());
    }

    Ok(())
}

/// Test that prints a comprehensive summary of all protocol examples
#[test]
fn test_protocol_examples_summary() {
    let reg = registry();

    println!("\n=== Protocol Examples Summary ===\n");

    let mut total_events = 0;
    let mut total_alternatives = 0;
    let mut total_protocols = 0;

    for (name, protocol) in reg.all_protocols() {
        total_protocols += 1;
        let events = protocol.get_event_types();
        let event_count = events.len();
        let alt_count: usize = events.iter().map(|e| e.alternative_examples.len()).sum();

        total_events += event_count;
        total_alternatives += alt_count;

        println!(
            "{}: {} events, {} alternatives",
            name, event_count, alt_count
        );
    }

    println!("\n--- Totals ---");
    println!("Protocols: {}", total_protocols);
    println!("Event types: {}", total_events);
    println!("Alternative examples: {}", total_alternatives);
    println!(
        "Total testable examples: {}",
        total_events + total_alternatives + (total_protocols * 3) // 3 startup modes per protocol
    );
}

// =============================================================================
// Comprehensive E2E Tests for ALL Protocols
// =============================================================================

/// E2E test that starts ALL protocols using their actual llm_mode startup examples
///
/// This test iterates over every protocol in the registry and:
/// 1. Reads the actual `get_startup_examples().llm_mode` value
/// 2. Starts a server using that exact example (with port 0 for dynamic allocation)
/// 3. Verifies the server starts successfully
///
/// This ensures ALL protocol startup examples actually work.
#[tokio::test]
async fn test_all_protocols_llm_mode_startup() -> E2EResult<()> {
    println!("\n=== E2E Test: ALL Protocols LLM Mode Startup ===\n");

    let reg = registry();
    let all_protocols: Vec<_> = reg.all_protocols().into_iter().collect();

    println!("Testing {} protocols...\n", all_protocols.len());

    let mut passed = 0;
    let mut failed = 0;
    let mut errors: Vec<(String, String)> = Vec::new();

    let mut skipped = 0;

    for (name, protocol) in &all_protocols {
        if let Some(reason) = unsupported_on_this_platform(name) {
            println!("  - {} - skipped: {}", name, reason);
            skipped += 1;
            continue;
        }
        let startup_examples = protocol.get_startup_examples();
        let llm_mode_with_port_0 = with_port_zero(&startup_examples.llm_mode);

        // Create config for this protocol
        let prompt = format!("Start a {} server on port 0", name);
        let config = NetGetConfig::new(&prompt)
            .with_log_level("warn") // Reduce noise
            .with_mock(|mock| {
                mock.on_instruction_containing(&format!("Start a {} server", name))
                    .respond_with_actions(llm_mode_with_port_0.clone())
                    .and()
                    // Add a catch-all for any events (just acknowledge them)
                    .on_event("*")
                    .respond_with_actions(
                        json!({"type": "show_message", "message": "Event received"}),
                    )
                    .and()
            });

        // Try to start the server
        match start_netget_server(config).await {
            Ok(server) => {
                // A started server is the pass condition; the port is incidental.
                //
                // This used to require `port > 0`, which is false by design for around 25
                // protocols: the BLE profiles advertise rather than listen, `ssh_agent` and
                // `socket_file` bind a Unix socket, `isis` and `datalink` capture at layer 2.
                // They report the `0.0.0.0:0` "no listening socket" placeholder, and this
                // sweep counted each as a failure — asserting the opposite of what those
                // protocols promise. `protocol_startup_smoke_test` is the test that
                // classifies sockets properly (LISTENING / running-without-socket /
                // refused-cleanly); this one only asks whether the documented startup example
                // starts the protocol at all.
                if server.port > 0 {
                    println!("  ✓ {} - started on port {}", name, server.port);
                } else {
                    println!("  ✓ {} - started (no listening socket)", name);
                }
                passed += 1;
                // The mock answered this protocol's startup; check it was not left
                // unverified. The sweep sets no per-protocol expectation (a protocol that
                // fails to start is counted, not asserted), so this catches a rule that
                // over- or under-fired rather than one that never ran.
                if let Err(e) = server.verify_mocks().await {
                    println!("  ! {} - mock verification: {}", name, e);
                }
                // Stop the server
                let _ = server.stop().await;
            }
            Err(e) => {
                println!("  ✗ {} - failed: {}", name, e);
                failed += 1;
                errors.push((name.clone(), e.to_string()));
            }
        }
    }

    let attempted = all_protocols.len() - skipped;
    println!("\n=== Results ===");
    println!("Passed: {}/{}", passed, attempted);
    println!("Failed: {}/{}", failed, attempted);
    println!("Skipped (platform): {}", skipped);

    if !errors.is_empty() {
        println!("\nFailed protocols:");
        for (name, error) in &errors {
            println!("  - {}: {}", name, error);
        }
    }

    // Allow some failures for protocols that may have special requirements
    // but fail if more than 20% fail
    let failure_threshold = attempted / 5;
    if failed > failure_threshold {
        let failed_list: Vec<String> = errors
            .iter()
            .map(|(name, err)| format!("{}: {}", name, err))
            .collect();
        panic!(
            "Too many LLM mode startup failures: {}/{} (threshold: {})\n\nFailed protocols:\n  - {}",
            failed,
            attempted,
            failure_threshold,
            failed_list.join("\n  - ")
        );
    }

    println!("\n✓ All protocol LLM mode startup tests completed\n");
    Ok(())
}

/// E2E test that validates ALL protocols' static mode startup examples
///
/// This test verifies that every protocol's static_mode example:
/// 1. Has valid event_handlers configuration
/// 2. Can be parsed and the server can be started
#[tokio::test]
async fn test_all_protocols_static_mode_startup() -> E2EResult<()> {
    println!("\n=== E2E Test: ALL Protocols Static Mode Startup ===\n");

    let reg = registry();
    let all_protocols: Vec<_> = reg.all_protocols().into_iter().collect();

    println!("Testing {} protocols...\n", all_protocols.len());

    let mut passed = 0;
    let mut failed = 0;
    let mut errors: Vec<(String, String)> = Vec::new();

    let mut skipped = 0;

    for (name, protocol) in &all_protocols {
        if let Some(reason) = unsupported_on_this_platform(name) {
            println!("  - {} - skipped: {}", name, reason);
            skipped += 1;
            continue;
        }
        let startup_examples = protocol.get_startup_examples();
        let static_mode_with_port_0 = with_port_zero(&startup_examples.static_mode);

        // Create config for this protocol
        let prompt = format!("Start a {} server on port 0 with static handler", name);
        let config = NetGetConfig::new(&prompt)
            .with_log_level("warn")
            .with_mock(|mock| {
                mock.on_instruction_containing(&format!("Start a {} server", name))
                    .respond_with_actions(static_mode_with_port_0.clone())
                    .and()
            });

        // Try to start the server
        match start_netget_server(config).await {
            Ok(server) => {
                // A started server is the pass condition; the port is incidental.
                //
                // This used to require `port > 0`, which is false by design for around 25
                // protocols: the BLE profiles advertise rather than listen, `ssh_agent` and
                // `socket_file` bind a Unix socket, `isis` and `datalink` capture at layer 2.
                // They report the `0.0.0.0:0` "no listening socket" placeholder, and this
                // sweep counted each as a failure — asserting the opposite of what those
                // protocols promise. `protocol_startup_smoke_test` is the test that
                // classifies sockets properly (LISTENING / running-without-socket /
                // refused-cleanly); this one only asks whether the documented startup example
                // starts the protocol at all.
                if server.port > 0 {
                    println!("  ✓ {} - started on port {}", name, server.port);
                } else {
                    println!("  ✓ {} - started (no listening socket)", name);
                }
                passed += 1;
                // See the llm_mode sweep above: the mock is checked rather than left
                // configured-and-forgotten, but it is reported, not asserted, because the
                // sweep's own pass criterion is the failure threshold below.
                if let Err(e) = server.verify_mocks().await {
                    println!("  ! {} - mock verification: {}", name, e);
                }
                let _ = server.stop().await;
            }
            Err(e) => {
                println!("  ✗ {} - failed: {}", name, e);
                failed += 1;
                errors.push((name.clone(), e.to_string()));
            }
        }
    }

    let attempted = all_protocols.len() - skipped;
    println!("\n=== Results ===");
    println!("Passed: {}/{}", passed, attempted);
    println!("Failed: {}/{}", failed, attempted);
    println!("Skipped (platform): {}", skipped);

    if !errors.is_empty() {
        println!("\nFailed protocols:");
        for (name, error) in &errors {
            println!("  - {}: {}", name, error);
        }
    }

    let failure_threshold = attempted / 5;
    if failed > failure_threshold {
        let failed_list: Vec<String> = errors
            .iter()
            .map(|(name, err)| format!("{}: {}", name, err))
            .collect();
        panic!(
            "Too many static mode startup failures: {}/{} (threshold: {})\n\nFailed protocols:\n  - {}",
            failed,
            attempted,
            failure_threshold,
            failed_list.join("\n  - ")
        );
    }

    println!("\n✓ All protocol static mode startup tests completed\n");
    Ok(())
}

// =============================================================================
// E2E Tests Using Actual Protocol Examples
// =============================================================================

/// E2E test for TCP using actual protocol examples
#[tokio::test]
async fn test_tcp_actual_examples() -> E2EResult<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    println!("\n=== E2E Test: TCP Actual Examples ===\n");

    let reg = registry();
    let protocol = reg.get("TCP").expect("TCP protocol should exist");

    // Get ACTUAL startup example from protocol
    let startup_examples = protocol.get_startup_examples();
    println!(
        "LLM mode example: {}",
        serde_json::to_string_pretty(&startup_examples.llm_mode)?
    );

    // Get ACTUAL response examples from protocol
    let event_types = protocol.get_event_types();
    for event_type in &event_types {
        println!(
            "Event '{}' response_example: {}",
            event_type.id,
            serde_json::to_string_pretty(&event_type.response_example)?
        );
    }

    // Find the tcp_connection_opened event
    let conn_opened_event = event_types.iter().find(|e| e.id == "tcp_connection_opened");

    // Find the tcp_data_received event
    let data_received_event = event_types.iter().find(|e| e.id == "tcp_data_received");

    // Build mock using ACTUAL examples from protocol (with port 0 for dynamic allocation)
    let llm_mode_with_port_0 = with_port_zero(&startup_examples.llm_mode);

    let config = NetGetConfig::new("Start a TCP server on port 0")
        .with_log_level("debug")
        .with_mock(|mock| {
            let mut builder = mock
                .on_instruction_containing("Start a TCP server")
                .respond_with_actions(llm_mode_with_port_0.clone())
                .and();

            // Add mock for tcp_connection_opened using ACTUAL response_example
            if let Some(event) = conn_opened_event {
                let response = if event.response_example.is_array() {
                    event.response_example.clone()
                } else {
                    json!([event.response_example.clone()])
                };
                builder = builder
                    .on_event("tcp_connection_opened")
                    .respond_with_actions(response)
                    .and();
            }

            // Add mock for tcp_data_received using ACTUAL response_example
            if let Some(event) = data_received_event {
                let response = if event.response_example.is_array() {
                    event.response_example.clone()
                } else {
                    json!([event.response_example.clone()])
                };
                builder = builder
                    .on_event("tcp_data_received")
                    .respond_with_actions(response)
                    .and();
            }

            builder
        });

    let server = start_netget_server(config).await?;
    let port = server.port;
    println!("TCP server started on port {}", port);

    // Wait for server to be ready
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Connect and verify
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port)).await?;
    println!("✓ TCP connection established");

    // Try to read welcome banner (if server sends first)
    let mut buf = vec![0u8; 1024];
    match tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {
            let response = String::from_utf8_lossy(&buf[..n]);
            println!("✓ Received response: {}", response.trim());
        }
        _ => {
            // Server may not send first - that's OK, send data to trigger response
            stream.write_all(b"Hello").await?;
            stream.flush().await?;
            println!("✓ Sent test data");

            match tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => {
                    let response = String::from_utf8_lossy(&buf[..n]);
                    println!("✓ Received response: {}", response.trim());
                }
                _ => println!("⚠ No response received (may be expected)"),
            }
        }
    }

    server.verify_mocks().await?;
    server.stop().await?;

    println!("\n✓ TCP actual examples test completed\n");
    Ok(())
}

/// E2E test for HTTP using actual protocol examples
#[tokio::test]
async fn test_http_actual_examples() -> E2EResult<()> {
    println!("\n=== E2E Test: HTTP Actual Examples ===\n");

    let reg = registry();
    let protocol = reg.get("HTTP").expect("HTTP protocol should exist");

    // Get ACTUAL startup example from protocol
    let startup_examples = protocol.get_startup_examples();
    println!(
        "LLM mode example: {}",
        serde_json::to_string_pretty(&startup_examples.llm_mode)?
    );

    // Get ACTUAL response examples from protocol
    let event_types = protocol.get_event_types();
    for event_type in &event_types {
        println!(
            "Event '{}' response_example: {}",
            event_type.id,
            serde_json::to_string_pretty(&event_type.response_example)?
        );
    }

    // Find the http_request event
    let http_request_event = event_types
        .iter()
        .find(|e| e.id == "http_request")
        .expect("http_request event should exist");

    // Build mock using ACTUAL examples from protocol (with port 0 for dynamic allocation)
    let llm_mode_with_port_0 = with_port_zero(&startup_examples.llm_mode);

    let response_example = if http_request_event.response_example.is_array() {
        http_request_event.response_example.clone()
    } else {
        json!([http_request_event.response_example.clone()])
    };

    let config = NetGetConfig::new("Start an HTTP server on port 0")
        .with_log_level("debug")
        .with_mock(|mock| {
            mock.on_instruction_containing("Start an HTTP server")
                .respond_with_actions(llm_mode_with_port_0.clone())
                .and()
                .on_event("http_request")
                .respond_with_actions(response_example.clone())
                .and()
        });

    let server = start_netget_server(config).await?;
    let port = server.port;
    println!("HTTP server started on port {}", port);

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Make HTTP request
    let client = reqwest::Client::new();
    let response = client
        .get(format!("http://127.0.0.1:{}/", port))
        .timeout(Duration::from_secs(10))
        .send()
        .await?;

    println!("✓ HTTP response status: {}", response.status());

    let body = response.text().await?;
    println!("✓ HTTP response body: {}", body);

    server.verify_mocks().await?;
    server.stop().await?;

    println!("\n✓ HTTP actual examples test completed\n");
    Ok(())
}

/// E2E test for DNS using actual protocol examples
#[tokio::test]
async fn test_dns_actual_examples() -> E2EResult<()> {
    use hickory_client::client::{AsyncClient, ClientHandle};
    use hickory_client::rr::{DNSClass, Name, RecordType};
    use hickory_client::udp::UdpClientStream;
    use std::net::SocketAddr;
    use std::str::FromStr;

    println!("\n=== E2E Test: DNS Actual Examples ===\n");

    let reg = registry();
    let protocol = reg.get("DNS").expect("DNS protocol should exist");

    // Get ACTUAL startup example from protocol
    let startup_examples = protocol.get_startup_examples();
    println!(
        "LLM mode example: {}",
        serde_json::to_string_pretty(&startup_examples.llm_mode)?
    );

    // Get ACTUAL response examples from protocol
    let event_types = protocol.get_event_types();
    for event_type in &event_types {
        println!(
            "Event '{}' response_example: {}",
            event_type.id,
            serde_json::to_string_pretty(&event_type.response_example)?
        );
    }

    // Find the dns_query event
    let dns_query_event = event_types
        .iter()
        .find(|e| e.id == "dns_query")
        .expect("dns_query event should exist");

    // Build mock using ACTUAL examples from protocol (with port 0 for dynamic allocation)
    let llm_mode_with_port_0 = with_port_zero(&startup_examples.llm_mode);

    // DNS requires dynamic query_id matching - extract from actual example
    let base_response = dns_query_event.response_example.clone();

    let config = NetGetConfig::new("Start a DNS server on port 0")
        .with_log_level("debug")
        .with_mock(|mock| {
            mock.on_instruction_containing("Start a DNS server")
                .respond_with_actions(llm_mode_with_port_0.clone())
                .and()
                // DNS needs dynamic query_id - use respond_with_actions_from_event
                .on_event("dns_query")
                .respond_with_actions_from_event(move |event_data| {
                    let query_id = event_data["query_id"].as_u64().unwrap_or(0);

                    // Use the actual response_example but inject the dynamic query_id
                    let mut response = base_response.clone();
                    if let Some(obj) = response.as_object_mut() {
                        obj.insert("query_id".to_string(), json!(query_id));
                    }

                    json!([response])
                })
                .and()
        });

    let server = start_netget_server(config).await?;
    let port = server.port;
    println!("DNS server started on port {}", port);

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Query using hickory-client
    let address: SocketAddr = format!("127.0.0.1:{}", port).parse()?;
    let stream = UdpClientStream::<tokio::net::UdpSocket>::new(address);
    let (mut client, bg) = AsyncClient::connect(stream).await?;
    tokio::spawn(bg);

    let name = Name::from_str("example.com.")?;
    let response = client.query(name, DNSClass::IN, RecordType::A).await?;

    println!("✓ DNS response received");
    let answers = response.answers();
    println!("✓ DNS answers: {} records", answers.len());

    for record in answers {
        println!("  Record: {:?}", record);
    }

    server.verify_mocks().await?;
    server.stop().await?;

    println!("\n✓ DNS actual examples test completed\n");
    Ok(())
}

/// Test static mode startup examples actually work
#[tokio::test]
async fn test_tcp_static_mode_example() -> E2EResult<()> {
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpStream;

    println!("\n=== E2E Test: TCP Static Mode Actual Example ===\n");

    let reg = registry();
    let protocol = reg.get("TCP").expect("TCP protocol should exist");

    // Get ACTUAL static mode example from protocol
    let startup_examples = protocol.get_startup_examples();
    println!(
        "Static mode example: {}",
        serde_json::to_string_pretty(&startup_examples.static_mode)?
    );

    // Use the ACTUAL static mode example (with port 0 for dynamic allocation)
    let static_mode_with_port_0 = with_port_zero(&startup_examples.static_mode);

    let config = NetGetConfig::new("Start a TCP server on port 0 with static handler")
        .with_log_level("debug")
        .with_mock(|mock| {
            mock.on_instruction_containing("Start a TCP server")
                .respond_with_actions(static_mode_with_port_0.clone())
                .expect_calls(1)
                .and()
        });

    let server = start_netget_server(config).await?;
    let port = server.port;
    println!("TCP server started on port {}", port);

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Connect and try to read static response
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port)).await?;
    println!("✓ TCP connection established");

    let mut buf = vec![0u8; 1024];
    match tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {
            let response = String::from_utf8_lossy(&buf[..n]);
            println!("✓ Static response received: {}", response.trim());
        }
        _ => {
            println!("⚠ No static response received (may need data to trigger)");
        }
    }

    // Without this the mock was configured and never checked, so nothing here asserted
    // that the documented static-mode example is what actually started the server.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;

    println!("\n✓ TCP static mode test completed\n");
    Ok(())
}

/// Test HTTP static mode startup example
#[tokio::test]
async fn test_http_static_mode_example() -> E2EResult<()> {
    println!("\n=== E2E Test: HTTP Static Mode Actual Example ===\n");

    let reg = registry();
    let protocol = reg.get("HTTP").expect("HTTP protocol should exist");

    // Get ACTUAL static mode example from protocol
    let startup_examples = protocol.get_startup_examples();
    println!(
        "Static mode example: {}",
        serde_json::to_string_pretty(&startup_examples.static_mode)?
    );

    // Use the ACTUAL static mode example (with port 0 for dynamic allocation)
    let static_mode_with_port_0 = with_port_zero(&startup_examples.static_mode);

    let config = NetGetConfig::new("Start an HTTP server on port 0 with static handler")
        .with_log_level("debug")
        .with_mock(|mock| {
            mock.on_instruction_containing("Start an HTTP server")
                .respond_with_actions(static_mode_with_port_0.clone())
                .expect_calls(1)
                .and()
        });

    let server = start_netget_server(config).await?;
    let port = server.port;
    println!("HTTP server started on port {}", port);

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Make HTTP request to trigger static handler
    let client = reqwest::Client::new();
    let response = client
        .get(format!("http://127.0.0.1:{}/", port))
        .timeout(Duration::from_secs(10))
        .send()
        .await?;

    println!("✓ HTTP response status: {}", response.status());
    let body = response.text().await?;
    println!("✓ HTTP response body: {}", body);

    // Without this the mock was configured and never checked, so nothing here asserted
    // that the documented static-mode example is what actually started the server.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;

    println!("\n✓ HTTP static mode test completed\n");
    Ok(())
}

/// Test alternative examples for TCP
#[tokio::test]
async fn test_tcp_alternative_examples() -> E2EResult<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    println!("\n=== E2E Test: TCP Alternative Examples ===\n");

    let reg = registry();
    let protocol = reg.get("TCP").expect("TCP protocol should exist");

    let event_types = protocol.get_event_types();

    // Find events with alternative examples
    for event_type in &event_types {
        if event_type.alternative_examples.is_empty() {
            continue;
        }

        println!(
            "Event '{}' has {} alternative examples:",
            event_type.id,
            event_type.alternative_examples.len()
        );

        for (i, alt) in event_type.alternative_examples.iter().enumerate() {
            println!("  Alternative {}: {}", i, serde_json::to_string(alt)?);
        }
    }

    // Test the wait_for_more alternative (if exists)
    let data_received_event = event_types.iter().find(|e| e.id == "tcp_data_received");

    if let Some(event) = data_received_event {
        if !event.alternative_examples.is_empty() {
            // Test first alternative (usually wait_for_more)
            let alt_example = &event.alternative_examples[0];
            println!(
                "\nTesting alternative example: {}",
                serde_json::to_string(alt_example)?
            );

            let startup_examples = protocol.get_startup_examples();
            let llm_mode_with_port_0 = with_port_zero(&startup_examples.llm_mode);

            let config = NetGetConfig::new("Start a TCP server on port 0")
                .with_log_level("debug")
                .with_mock(|mock| {
                    mock.on_instruction_containing("Start a TCP server")
                        .respond_with_actions(llm_mode_with_port_0.clone())
                        .expect_calls(1)
                        .and()
                        // No expectation: `tcp_connection_opened` is raised from
                        // `send_banner`, which runs for `send_first` servers only, and this
                        // startup example sets no `send_first`. The rule is kept so a future
                        // example that does speak first is answered rather than falling
                        // through, but it cannot fire here and pinning it asserted a lie.
                        .on_event("tcp_connection_opened")
                        .respond_with_actions(json!({"type": "wait_for_more"}))
                        .and()
                        // The point of the test: the alternative example the protocol
                        // documents must be the answer the server is actually given.
                        // Every assertion below is a println, so this count is the only
                        // thing here that can fail.
                        .on_event("tcp_data_received")
                        .respond_with_actions(json!([alt_example.clone()]))
                        .expect_at_least(1)
                        .and()
                });

            let server = start_netget_server(config).await?;
            let port = server.port;

            tokio::time::sleep(Duration::from_millis(500)).await;

            let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port)).await?;
            stream.write_all(b"Test data").await?;
            stream.flush().await?;
            println!("✓ Sent test data");

            // For wait_for_more, the server shouldn't respond yet
            let mut buf = vec![0u8; 1024];
            match tokio::time::timeout(Duration::from_millis(500), stream.read(&mut buf)).await {
                Ok(Ok(0)) | Err(_) => {
                    println!("✓ No immediate response (wait_for_more working)");
                }
                Ok(Ok(n)) => {
                    let response = String::from_utf8_lossy(&buf[..n]);
                    println!("✓ Received response: {}", response.trim());
                }
                Ok(Err(e)) => {
                    println!("⚠ Read error: {}", e);
                }
            }

            server.wait_for_mocks(30).await;
            server.verify_mocks().await?;
            server.stop().await?;
        }
    }

    println!("\n✓ TCP alternative examples test completed\n");
    Ok(())
}
