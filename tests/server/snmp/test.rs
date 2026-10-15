//! End-to-end SNMP tests for NetGet
//!
//! These tests spawn the actual NetGet binary with SNMP prompts
//! and validate the responses using the snmp Rust client library.


// Helper module imported from parent

use super::super::super::helpers::{self, E2EResult, NetGetConfig};

#[tokio::test]
async fn test_snmp_basic_get() -> E2EResult<()> {
    println!("\n=== E2E Test: SNMP Basic GET ===");

    // PROMPT: Tell the LLM to act as an SNMP agent
    // The real listener chooses its port atomically.
    let port = 0u16;
    let prompt = format!("listen on port {} via snmp. For OID 1.3.6.1.2.1.1.1.0 (sysDescr) return 'NetGet SNMP Server v1.0'. For OID 1.3.6.1.2.1.1.5.0 (sysName) return 'netget.local'", port);

    // Start the server with debug logging and mocks
    let server = helpers::start_netget_server(
        NetGetConfig::new(&prompt)
            .with_log_level("debug")
            .with_mock(|mock| {
                mock
                    // Mock 1: Server startup (user command)
                    .on_instruction_containing("listen on port")
                    .and_instruction_containing("snmp")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": port,
                            "base_stack": "SNMP",
                            "instruction": "For OID 1.3.6.1.2.1.1.1.0 (sysDescr) return 'NetGet SNMP Server v1.0'. For OID 1.3.6.1.2.1.1.5.0 (sysName) return 'netget.local'"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 2: SNMP GET for sysDescr (1.3.6.1.2.1.1.1.0) - DYNAMIC request_id
                    .on_event("snmp_request")
                    .and_event_data_contains("request_type", "GetRequest")
                    // Matches only when the event carries the per-request hint, which names
                    // each OID (these are sysDescr and sysName) and how many to return.
                    .and_event_data_contains(
                        "answer_with",
                        "send_snmp_response with exactly 1 variable,",
                    )
                    .respond_with_actions_from_event(|event_data| {
                        // Check which OID was requested and return appropriate response
                        let oids = event_data["oids"].as_array().unwrap();
                        if oids.iter().any(|oid| oid.as_str() == Some("1.3.6.1.2.1.1.1.0")) {
                            serde_json::json!([
                                {
                                    "type": "send_snmp_response",
                                    "variables": [
                                        {
                                            "oid": "1.3.6.1.2.1.1.1.0",
                                            "type": "string",
                                            "value": "NetGet SNMP Server v1.0"
                                        }
                                    ]
                                }
                            ])
                        } else if oids.iter().any(|oid| oid.as_str() == Some("1.3.6.1.2.1.1.5.0")) {
                            serde_json::json!([
                                {
                                    "type": "send_snmp_response",
                                    "variables": [
                                        {
                                            "oid": "1.3.6.1.2.1.1.5.0",
                                            "type": "string",
                                            "value": "netget.local"
                                        }
                                    ]
                                }
                            ])
                        } else {
                            serde_json::json!([
                                {
                                    "type": "send_snmp_error",
                                    "error_message": "Unknown OID"
                                }
                            ])
                        }
                    })
                    .expect_calls(2)
                    .and()
            })
    ).await?;
    println!("Server started on port {}", server.port);
    // No sleep: `spawn_with_llm_actions` binds the UDP socket and only then logs
    // "SNMP agent ... listening on", which is what `start_netget_server` waits for. The
    // socket is therefore already accepting datagrams by the time this line runs.
    // VALIDATION: Use command-line snmpget tool (more reliable than Rust snmp crate)
    println!("Querying sysDescr OID with snmpget...");
    let output = tokio::process::Command::new("snmpget")
        .args(&[
            // -On prints OIDs numerically and -Oe prints enums as bare numbers, so the
            // assertions below do not depend on which MIB files happen to be installed:
            // without these, ifOperStatus renders as "INTEGER: up(1)" on one machine and
            // "INTEGER: 1" on another, and sysDescr as "SNMPv2-MIB::sysDescr.0".
            "-On",
            "-Oe",
            "-v",
            "2c",
            "-c",
            "public",
            "-t",
            "3",
            &format!("localhost:{}", server.port),
            "1.3.6.1.2.1.1.1.0",
        ])
        .output()
        .await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(format!("snmpget failed:\nstdout: {}\nstderr: {}", stdout, stderr).into());
    }

    let response_str = String::from_utf8_lossy(&output.stdout);
    println!("SNMP response: {}", response_str);

    // net-snmp prints the decoded type and value, so asserting on its rendering checks the
    // whole path: our hand-rolled BER encoder produced an OCTET STRING that a real manager
    // decoded back to exactly the bytes the model supplied. The previous assertion ended in
    // `|| !response_str.is_empty()`, which a successful snmpget can never fail - it asserted
    // that snmpget had run, not that the agent answered correctly.
    assert!(
        response_str.contains("STRING: NetGet SNMP Server v1.0")
            || response_str.contains("STRING: \"NetGet SNMP Server v1.0\""),
        "sysDescr should decode as the exact string the model returned, got: {}",
        response_str
    );
    println!("✓ SNMP GET succeeded");

    // Query sysName (1.3.6.1.2.1.1.5.0)
    println!("Querying sysName OID with snmpget...");
    let output2 = tokio::process::Command::new("snmpget")
        .args(&[
            // -On prints OIDs numerically and -Oe prints enums as bare numbers, so the
            // assertions below do not depend on which MIB files happen to be installed:
            // without these, ifOperStatus renders as "INTEGER: up(1)" on one machine and
            // "INTEGER: 1" on another, and sysDescr as "SNMPv2-MIB::sysDescr.0".
            "-On",
            "-Oe",
            "-v",
            "2c",
            "-c",
            "public",
            "-t",
            "3",
            &format!("localhost:{}", server.port),
            "1.3.6.1.2.1.1.5.0",
        ])
        .output()
        .await?;

    if !output2.status.success() {
        let stderr = String::from_utf8_lossy(&output2.stderr);
        let stdout = String::from_utf8_lossy(&output2.stdout);
        return Err(format!(
            "sysName query failed:\nstdout: {}\nstderr: {}",
            stdout, stderr
        )
        .into());
    }

    let response_str2 = String::from_utf8_lossy(&output2.stdout);
    println!("sysName response: {}", response_str2);
    assert!(
        response_str2.contains("STRING: netget.local")
            || response_str2.contains("STRING: \"netget.local\""),
        "sysName should decode as the exact string the model returned, got: {}",
        response_str2
    );
    println!("✓ sysName query succeeded");

    // Verify mock expectations were met
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    server.stop().await?;
    println!("=== Test completed ===\n");
    Ok(())
}

#[tokio::test]
async fn test_snmp_get_next() -> E2EResult<()> {
    println!("\n=== E2E Test: SNMP GETNEXT ===");

    // PROMPT: Tell the LLM to handle GETNEXT requests
    // The real listener chooses its port atomically.
    let port = 0u16;
    let prompt = format!("listen on port {} via snmp. Support GETNEXT requests. \
        When queried with 1.3.6.1.2.1.1, return the next OID 1.3.6.1.2.1.1.1.0 with value 'NetGet SNMP'", port);

    // Start the server with mocks
    let server = helpers::start_netget_server(
        NetGetConfig::new(&prompt)
            .with_mock(|mock| {
                mock
                    // Mock 1: Server startup (user command)
                    .on_instruction_containing("listen on port")
                    .and_instruction_containing("snmp")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": port,
                            "base_stack": "SNMP",
                            "instruction": "Support GETNEXT requests. When queried with 1.3.6.1.2.1.1, return the next OID 1.3.6.1.2.1.1.1.0 with value 'NetGet SNMP'"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 2: SNMP GETNEXT
                    .on_event("snmp_request")
                    .and_event_data_contains("request_type", "GetNextRequest")
                    .respond_with_actions_from_event(|_event_data| {
                        serde_json::json!([
                            {
                                "type": "send_snmp_response",
                                "variables": [
                                    {
                                        "oid": "1.3.6.1.2.1.1.1.0",
                                        "type": "string",
                                        "value": "NetGet SNMP"
                                    }
                                ]
                            }
                        ])
                    })
                    .expect_calls(1)
                    .and()
            })
    ).await?;
    println!("Server started on port {}", server.port);
    // No sleep: the socket is bound before `start_netget_server` returns - see above.

    // VALIDATION: Use snmpgetnext command-line tool (more reliable than Rust snmp crate)
    println!("Querying with snmpgetnext...");
    let output = tokio::process::Command::new("snmpgetnext")
        .args(&[
            // -On prints OIDs numerically and -Oe prints enums as bare numbers, so the
            // assertions below do not depend on which MIB files happen to be installed:
            // without these, ifOperStatus renders as "INTEGER: up(1)" on one machine and
            // "INTEGER: 1" on another, and sysDescr as "SNMPv2-MIB::sysDescr.0".
            "-On",
            "-Oe",
            "-v",
            "2c",
            "-c",
            "public",
            "-t",
            "5",
            &format!("127.0.0.1:{}", server.port),
            "1.3.6.1.2.1.1",
        ])
        .output()
        .await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(format!(
            "snmpgetnext query failed:\nstdout: {}\nstderr: {}",
            stdout, stderr
        )
        .into());
    }

    let response_str = String::from_utf8_lossy(&output.stdout);
    println!("GETNEXT response: {}", response_str);
    // GETNEXT must come back naming the OID that *follows* the one asked for, carrying the
    // model's value. Asserting only that snmpgetnext exited 0 would pass on any answer at all,
    // including one for the queried OID itself - the exact confusion this test exists to catch.
    assert!(
        response_str.contains("1.3.6.1.2.1.1.1.0") || response_str.contains(".1.3.6.1.2.1.1.1.0"),
        "GETNEXT should answer for the next OID 1.3.6.1.2.1.1.1.0, got: {}",
        response_str
    );
    assert!(
        response_str.contains("STRING: NetGet SNMP")
            || response_str.contains("STRING: \"NetGet SNMP\""),
        "GETNEXT should carry the model's value, got: {}",
        response_str
    );
    println!("✓ SNMP GETNEXT verified");

    // Verify mock expectations were met
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    server.stop().await?;
    println!("=== Test completed ===\n");
    Ok(())
}

#[tokio::test]
async fn test_snmp_interface_stats() -> E2EResult<()> {
    println!("\n=== E2E Test: SNMP Interface Statistics ===");

    // PROMPT: Tell the LLM to provide network interface statistics
    // The real listener chooses its port atomically.
    let port = 0u16;
    let prompt = format!(
        "listen on port {} via snmp. Provide interface statistics: \
        1.3.6.1.2.1.2.2.1.1.1 = 1 (ifIndex), \
        1.3.6.1.2.1.2.2.1.2.1 = 'eth0' (ifDescr), \
        1.3.6.1.2.1.2.2.1.3.1 = 6 (ifType: ethernetCsmacd), \
        1.3.6.1.2.1.2.2.1.5.1 = 1000000000 (ifSpeed: 1 Gbps), \
        1.3.6.1.2.1.2.2.1.8.1 = 1 (ifOperStatus: up)",
        port
    );

    // Start the server with mocks
    let server = helpers::start_netget_server(
        NetGetConfig::new(&prompt)
            .with_mock(|mock| {
                mock
                    // Mock 1: Server startup
                    .on_instruction_containing("snmp")
                    .and_instruction_containing("interface statistics")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": port,
                            "base_stack": "SNMP",
                            "instruction": "Provide interface statistics for queries"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 2: Handle all interface stat queries
                    .on_event("snmp_request")
                    .and_event_data_contains("request_type", "GetRequest")
                    .respond_with_actions_from_event(|event_data| {
                        let oids = event_data["oids"].as_array().unwrap();

                        // Determine which OID was requested and return appropriate response
                        if oids.iter().any(|oid| oid.as_str() == Some("1.3.6.1.2.1.2.2.1.1.1")) {
                            // ifIndex
                            serde_json::json!([{
                                "type": "send_snmp_response",
                                "variables": [{"oid": "1.3.6.1.2.1.2.2.1.1.1", "type": "integer", "value": 1}]
                            }])
                        } else if oids.iter().any(|oid| oid.as_str() == Some("1.3.6.1.2.1.2.2.1.2.1")) {
                            // ifDescr
                            serde_json::json!([{
                                "type": "send_snmp_response",
                                "variables": [{"oid": "1.3.6.1.2.1.2.2.1.2.1", "type": "string", "value": "eth0"}]
                            }])
                        } else if oids.iter().any(|oid| oid.as_str() == Some("1.3.6.1.2.1.2.2.1.5.1")) {
                            // ifSpeed
                            serde_json::json!([{
                                "type": "send_snmp_response",
                                "variables": [{"oid": "1.3.6.1.2.1.2.2.1.5.1", "type": "gauge", "value": 1000000000}]
                            }])
                        } else if oids.iter().any(|oid| oid.as_str() == Some("1.3.6.1.2.1.2.2.1.8.1")) {
                            // ifOperStatus
                            serde_json::json!([{
                                "type": "send_snmp_response",
                                "variables": [{"oid": "1.3.6.1.2.1.2.2.1.8.1", "type": "integer", "value": 1}]
                            }])
                        } else {
                            serde_json::json!([{
                                "type": "send_snmp_error",
                                "error_message": "Unknown OID"
                            }])
                        }
                    })
                    .expect_calls(4)
                    .and()
            })
    ).await?;
    println!("Server started on port {}", server.port);
    // No sleep: the socket is bound before `start_netget_server` returns - see above.

    // VALIDATION: Query interface statistics using command-line snmpget (more reliable)
    // The third element is what net-snmp must print. It pins the *type tag* as well as the
    // value, which is the part our hand-rolled BER encoder can get wrong silently: a Gauge32
    // written with the INTEGER tag decodes to the same number and would pass a value-only
    // check, while a real monitoring system would treat it as a different kind of quantity.
    let oids = vec![
        ("1.3.6.1.2.1.2.2.1.1.1", "ifIndex", "INTEGER: 1"),
        ("1.3.6.1.2.1.2.2.1.2.1", "ifDescr", "STRING: eth0"),
        ("1.3.6.1.2.1.2.2.1.5.1", "ifSpeed", "Gauge32: 1000000000"),
        ("1.3.6.1.2.1.2.2.1.8.1", "ifOperStatus", "INTEGER: 1"),
    ];

    for (oid, name, expected) in oids {
        println!("Querying {} ...", name);
        let output = tokio::process::Command::new("snmpget")
            .args(&[
                // See the note on -On/-Oe above: pin the rendering, not the local MIB set.
                "-On",
                "-Oe",
                "-v",
                "2c",
                "-c",
                "public",
                "-t",
                "5",
                &format!("127.0.0.1:{}", server.port),
                oid,
            ])
            .output()
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            return Err(format!(
                "{} query failed:\nstdout: {}\nstderr: {}",
                name, stdout, stderr
            )
            .into());
        }

        let response_str = String::from_utf8_lossy(&output.stdout);
        println!("  {}: {}", name, response_str.trim());
        assert!(
            response_str.contains(expected)
                || response_str.contains(&expected.replace(": ", ": \"").to_string()),
            "{} should decode as `{}`, got: {}",
            name,
            expected,
            response_str
        );
        println!("  ✓ {} retrieved", name);
    }

    // Verify mock expectations were met
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    server.stop().await?;
    println!("=== Test completed ===\n");
    Ok(())
}

#[tokio::test]
async fn test_snmp_custom_mib() -> E2EResult<()> {
    println!("\n=== E2E Test: Custom MIB Support ===");

    // PROMPT: Tell the LLM to support custom enterprise MIB
    // The real listener chooses its port atomically.
    let port = 0u16;
    let prompt = format!(
        "listen on port {} via snmp. Support custom enterprise OID tree 1.3.6.1.4.1.99999: \
        1.3.6.1.4.1.99999.1.1.0 = 'Custom Application v1.0', \
        1.3.6.1.4.1.99999.1.2.0 = 42 (counter), \
        1.3.6.1.4.1.99999.1.3.0 = 'active' (status)",
        port
    );

    // Start the server with mocks
    let server = helpers::start_netget_server(
        NetGetConfig::new(&prompt)
            .with_mock(|mock| {
                mock
                    // Mock 1: Server startup
                    .on_instruction_containing("snmp")
                    .and_instruction_containing("custom enterprise OID")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "open_server",
                            "port": port,
                            "base_stack": "SNMP",
                            "instruction": "Support custom enterprise OID tree 1.3.6.1.4.1.99999"
                        }
                    ]))
                    .expect_calls(1)
                    .and()
                    // Mock 2: Handle all custom MIB queries
                    .on_event("snmp_request")
                    .and_event_data_contains("request_type", "GetRequest")
                    .respond_with_actions_from_event(|event_data| {
                        let oids = event_data["oids"].as_array().unwrap();

                        // Determine which OID was requested and return appropriate response
                        if oids.iter().any(|oid| oid.as_str() == Some("1.3.6.1.4.1.99999.1.1.0")) {
                            // Application Name
                            serde_json::json!([{
                                "type": "send_snmp_response",
                                "variables": [{"oid": "1.3.6.1.4.1.99999.1.1.0", "type": "string", "value": "Custom Application v1.0"}]
                            }])
                        } else if oids.iter().any(|oid| oid.as_str() == Some("1.3.6.1.4.1.99999.1.2.0")) {
                            // Counter
                            serde_json::json!([{
                                "type": "send_snmp_response",
                                "variables": [{"oid": "1.3.6.1.4.1.99999.1.2.0", "type": "counter", "value": 42}]
                            }])
                        } else if oids.iter().any(|oid| oid.as_str() == Some("1.3.6.1.4.1.99999.1.3.0")) {
                            // Status
                            serde_json::json!([{
                                "type": "send_snmp_response",
                                "variables": [{"oid": "1.3.6.1.4.1.99999.1.3.0", "type": "string", "value": "active"}]
                            }])
                        } else {
                            serde_json::json!([{
                                "type": "send_snmp_error",
                                "error_message": "Unknown OID"
                            }])
                        }
                    })
                    .expect_calls(3)
                    .and()
            })
    ).await?;
    println!("Server started on port {}", server.port);
    // No sleep: the socket is bound before `start_netget_server` returns - see above.

    // VALIDATION: Query custom enterprise OIDs using command-line snmpget (more reliable)
    // As above: the expected rendering pins the type tag too - `counter` must reach the manager
    // as Counter32, not as a plain INTEGER carrying the same 42.
    let custom_oids = vec![
        (
            "1.3.6.1.4.1.99999.1.1.0",
            "Application Name",
            "STRING: Custom Application v1.0",
        ),
        ("1.3.6.1.4.1.99999.1.2.0", "Counter", "Counter32: 42"),
        ("1.3.6.1.4.1.99999.1.3.0", "Status", "STRING: active"),
    ];

    for (oid, name, expected) in custom_oids {
        println!("Querying custom OID {} ...", name);
        let output = tokio::process::Command::new("snmpget")
            .args(&[
                // See the note on -On/-Oe above: pin the rendering, not the local MIB set.
                "-On",
                "-Oe",
                "-v",
                "2c",
                "-c",
                "public",
                "-t",
                "5",
                &format!("127.0.0.1:{}", server.port),
                oid,
            ])
            .output()
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            return Err(format!(
                "{} query failed:\nstdout: {}\nstderr: {}",
                name, stdout, stderr
            )
            .into());
        }

        let response_str = String::from_utf8_lossy(&output.stdout);
        println!("  {}: {}", name, response_str.trim());
        assert!(
            response_str.contains(expected)
                || response_str.contains(&expected.replace(": ", ": \"").to_string()),
            "{} should decode as `{}`, got: {}",
            name,
            expected,
            response_str
        );
        println!("  ✓ Custom OID retrieved");
    }

    // Verify mock expectations were met
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    server.stop().await?;
    println!("=== Test completed ===\n");
    Ok(())
}
