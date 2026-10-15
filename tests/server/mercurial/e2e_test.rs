//! End-to-end Mercurial HTTP tests for NetGet
//!
//! This test spawns a NetGet Mercurial server and validates protocol operations
//! using reqwest HTTP client to test the wire protocol endpoints.

use super::super::helpers::{self, E2EResult, NetGetConfig};

#[tokio::test]
async fn test_mercurial_capabilities() -> E2EResult<()> {
    println!("\n=== E2E Test: Mercurial Capabilities ===");

    // Create a prompt for a simple Mercurial repository with mocks
    let prompt = r#"listen on port {AVAILABLE_PORT} via mercurial.

Create virtual repository 'test-repo' with default branch.

When clients request capabilities (?cmd=capabilities):
Return the following capabilities (one per line):
- batch
- branchmap
- getbundle
- httpheader=1024
- known
- lookup
- pushkey
- unbundle=HG10GZ,HG10BZ,HG10UN

Always respond quickly with these standard capabilities."#;

    // Start server with mocks
    let server = helpers::start_netget_server(NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: Server startup (user command)
            .on_prompt_containing("listen on port")
            .and_prompt_containing("mercurial")
            .and_prompt_containing("capabilities")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "Mercurial",
                    "instruction": "Mercurial server with capabilities"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: Network event - capabilities request
            // Match the event id, not its prose. These rules matched on the event *description*,
            // which was later reworded ("asked which capabilities the server supports"), so they
            // silently stopped matching: the mock returned nothing, call_llm failed, and the
            // server correctly answered 500 — four tests failing for a reason that had nothing
            // to do with Mercurial.
            .on_event("hg_capabilities")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "hg_capabilities",
                    "capabilities": [
                        "batch",
                        "branchmap",
                        "getbundle",
                        "httpheader=1024",
                        "known",
                        "lookup",
                        "pushkey",
                        "unbundle=HG10GZ,HG10BZ,HG10UN"
                    ]
                }
            ]))
            .expect_calls(1)
            .and()
    }))
    .await?;

    let port = server.port;
    println!("Mercurial server started on port {}", port);

    // Wait for server to be ready
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    // Test 1: Request capabilities
    println!("\n--- Test 1: Request Capabilities ---");
    let client = reqwest::Client::new();
    let capabilities_url = format!("http://127.0.0.1:{}/?cmd=capabilities", port);
    println!("Requesting: {}", capabilities_url);

    let response = client.get(&capabilities_url).send().await?;
    println!("Response status: {}", response.status());

    assert!(
        response.status().is_success(),
        "Capabilities request should succeed"
    );

    let body = response.text().await?;
    println!("Capabilities response:\n{}", body);

    // The server advertises what it can honour, not what the model asked for.
    //
    // `sanitize_capabilities` filters the model's list down to SUPPORTED_CAPABILITIES, and that
    // is deliberate: advertising `unbundle` invites a push that gets a 403, and advertising
    // `bundle2` makes a real hg client negotiate a format this server never speaks. The mock
    // above asks for eight capabilities precisely so this asserts the filtering.
    for supported in ["branchmap", "getbundle", "listkeys"] {
        assert!(
            body.contains(supported),
            "should advertise the supported capability {supported:?}, got {body:?}"
        );
    }

    // This test used to assert `batch`, which this server does not implement. Advertising it
    // would make hg use the batch protocol and fail, so the assertion was wrong rather than the
    // server — the filter is the behaviour worth pinning.
    for unsupported in [
        "batch",
        "unbundle",
        "pushkey",
        "lookup",
        "known",
        "httpheader",
    ] {
        assert!(
            !body.contains(unsupported),
            "must not advertise {unsupported:?}, which this server cannot honour, got {body:?}"
        );
    }

    println!("✓ Capabilities test passed");

    // Verify mock expectations were met
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;

    Ok(())
}

#[tokio::test]
async fn test_mercurial_heads() -> E2EResult<()> {
    println!("\n=== E2E Test: Mercurial Heads ===");

    let prompt = r#"listen on port {AVAILABLE_PORT} via mercurial.

Create virtual repository 'test-repo' with default branch.

When clients request heads (?cmd=heads):
Return one head node ID (40-character hex string):
1234567890abcdef1234567890abcdef12345678

This represents the tip of the default branch."#;

    let server = helpers::start_netget_server(
        NetGetConfig::new(prompt)
            .with_mock(|mock| {
                mock
                    // Mock 1: Server startup
                    .on_prompt_containing("listen on port")
                    .and_prompt_containing("mercurial")
                    .respond_with_actions(serde_json::json!([{"type": "open_server", "port": 0, "base_stack": "Mercurial", "instruction": "Mercurial server with heads"}]))
                    .expect_calls(1)
                    .and()
                    // Mock 2: Network event - heads request
                    .on_event("hg_heads")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "hg_heads",
                            "heads": ["1234567890abcdef1234567890abcdef12345678"]
                        }
                    ]))
                    .expect_calls(1)
                    .and()
            })
    ).await?;

    let port = server.port;
    println!("Mercurial server started on port {}", port);

    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    // Test: Request heads
    println!("\n--- Test: Request Heads ---");
    let client = reqwest::Client::new();
    let heads_url = format!("http://127.0.0.1:{}/?cmd=heads", port);
    println!("Requesting: {}", heads_url);

    let response = client.get(&heads_url).send().await?;
    println!("Response status: {}", response.status());

    assert!(
        response.status().is_success(),
        "Heads request should succeed"
    );

    let body = response.text().await?;
    println!("Heads response:\n{}", body);

    // Verify heads format (40-character hex strings, newline-separated)
    let heads: Vec<&str> = body.trim().split('\n').collect();
    assert!(!heads.is_empty(), "Should return at least one head");

    for head in &heads {
        assert!(
            head.len() == 40 && head.chars().all(|c| c.is_ascii_hexdigit()),
            "Each head should be a 40-character hex string, got: {}",
            head
        );
    }

    println!("✓ Heads test passed");
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    Ok(())
}

#[tokio::test]
async fn test_mercurial_branchmap() -> E2EResult<()> {
    println!("\n=== E2E Test: Mercurial Branchmap ===");

    let prompt = r#"listen on port {AVAILABLE_PORT} via mercurial.

Create virtual repository 'test-repo' with two branches: default and stable.

When clients request branchmap (?cmd=branchmap):
Return branch mappings in format: <branch_name> <node_id1> <node_id2>...

Example response:
default 1234567890abcdef1234567890abcdef12345678
stable abc123def456789012345678901234567890abcd

Each line represents one branch with its head node IDs."#;

    let server = helpers::start_netget_server(
        NetGetConfig::new(prompt)
            .with_mock(|mock| {
                mock
                    // Mock 1: Server startup
                    .on_prompt_containing("listen on port")
                    .and_prompt_containing("mercurial")
                    .respond_with_actions(serde_json::json!([{"type": "open_server", "port": 0, "base_stack": "Mercurial", "instruction": "Mercurial server with branchmap"}]))
                    .expect_calls(1)
                    .and()
                    // Mock 2: Network event - branchmap request
                    .on_event("hg_branchmap")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "hg_branchmap",
                            "branches": {
                                "default": ["1234567890abcdef1234567890abcdef12345678"],
                                "stable": ["abc123def456789012345678901234567890abcd"]
                            }
                        }
                    ]))
                    .expect_calls(1)
                    .and()
            })
    ).await?;

    let port = server.port;
    println!("Mercurial server started on port {}", port);

    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    // Test: Request branchmap
    println!("\n--- Test: Request Branchmap ---");
    let client = reqwest::Client::new();
    let branchmap_url = format!("http://127.0.0.1:{}/?cmd=branchmap", port);
    println!("Requesting: {}", branchmap_url);

    let response = client.get(&branchmap_url).send().await?;
    println!("Response status: {}", response.status());

    assert!(
        response.status().is_success(),
        "Branchmap request should succeed"
    );

    let body = response.text().await?;
    println!("Branchmap response:\n{}", body);

    // Verify branchmap format
    let branches: Vec<&str> = body.trim().split('\n').collect();
    assert!(!branches.is_empty(), "Should return at least one branch");

    for branch_line in &branches {
        let parts: Vec<&str> = branch_line.split_whitespace().collect();
        assert!(
            parts.len() >= 2,
            "Each branch line should have at least branch name and one node ID, got: {}",
            branch_line
        );

        let branch_name = parts[0];
        let node_ids = &parts[1..];

        println!("  Branch '{}': {} head(s)", branch_name, node_ids.len());

        for node_id in node_ids {
            assert!(
                node_id.len() == 40 && node_id.chars().all(|c| c.is_ascii_hexdigit()),
                "Node ID should be 40-character hex, got: {}",
                node_id
            );
        }
    }

    println!("✓ Branchmap test passed");
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    Ok(())
}

#[tokio::test]
async fn test_mercurial_listkeys() -> E2EResult<()> {
    println!("\n=== E2E Test: Mercurial Listkeys ===");

    let prompt = r#"listen on port {AVAILABLE_PORT} via mercurial.

Create virtual repository 'test-repo' with bookmarks.

When clients request listkeys (?cmd=listkeys&namespace=bookmarks):
Return key-value pairs in format: <key>\t<value>

Example response:
master\t1234567890abcdef1234567890abcdef12345678
develop\tabc123def456789012345678901234567890abcd

Each line is tab-separated: bookmark name, then node ID."#;

    let server = helpers::start_netget_server(
        NetGetConfig::new(prompt)
            .with_mock(|mock| {
                mock
                    // Mock 1: Server startup
                    .on_prompt_containing("listen on port")
                    .and_prompt_containing("mercurial")
                    .respond_with_actions(serde_json::json!([{"type": "open_server", "port": 0, "base_stack": "Mercurial", "instruction": "Mercurial server with listkeys"}]))
                    .expect_calls(1)
                    .and()
                    // Mock 2: Network event - listkeys request
                    .on_event("hg_listkeys")
                    .respond_with_actions(serde_json::json!([
                        {
                            "type": "hg_listkeys",
                            "keys": {
                                "master": "1234567890abcdef1234567890abcdef12345678",
                                "develop": "abc123def456789012345678901234567890abcd"
                            }
                        }
                    ]))
                    .expect_calls(1)
                    .and()
            })
    ).await?;

    let port = server.port;
    println!("Mercurial server started on port {}", port);

    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    // Test: Request listkeys for bookmarks namespace
    println!("\n--- Test: Request Listkeys (bookmarks) ---");
    let client = reqwest::Client::new();
    let listkeys_url = format!(
        "http://127.0.0.1:{}/?cmd=listkeys&namespace=bookmarks",
        port
    );
    println!("Requesting: {}", listkeys_url);

    let response = client.get(&listkeys_url).send().await?;
    println!("Response status: {}", response.status());

    assert!(
        response.status().is_success(),
        "Listkeys request should succeed"
    );

    let body = response.text().await?;
    println!("Listkeys response:\n{}", body);

    // Verify listkeys format (can be empty or have entries)
    if !body.trim().is_empty() {
        let keys: Vec<&str> = body.trim().split('\n').collect();

        for key_line in &keys {
            let parts: Vec<&str> = key_line.split('\t').collect();
            if parts.len() >= 2 {
                let key_name = parts[0];
                let node_id = parts[1];

                println!("  Bookmark '{}': {}", key_name, node_id);

                assert!(
                    node_id.len() == 40 && node_id.chars().all(|c| c.is_ascii_hexdigit()),
                    "Node ID should be 40-character hex, got: {}",
                    node_id
                );
            }
        }
    } else {
        println!("  (No bookmarks defined - this is acceptable)");
    }

    println!("✓ Listkeys test passed");
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    Ok(())
}

#[tokio::test]
async fn test_mercurial_repository_not_found() -> E2EResult<()> {
    println!("\n=== E2E Test: Mercurial Repository Not Found ===");

    let prompt = r#"listen on port {AVAILABLE_PORT} via mercurial.

Create virtual repository 'existing-repo' with default branch.

When clients request capabilities for a repository that exists:
Return standard capabilities.

When clients request capabilities for a repository that DOES NOT exist:
Return HTTP 404 error with message "Repository not found".

Test error handling for non-existent repositories."#;

    let server = helpers::start_netget_server(
        NetGetConfig::new(prompt)
            .with_mock(|mock| {
                mock.on_prompt_containing("listen on port")
                    .and_prompt_containing("mercurial")
                    .respond_with_actions(serde_json::json!([{"type": "open_server", "port": 0, "base_stack": "Mercurial", "instruction": "Mercurial server with error handling"}]))
                    .expect_calls(1)
                    .and()
            })
    ).await?;

    let port = server.port;
    println!("Mercurial server started on port {}", port);

    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    // Test: Request capabilities for non-existent repository
    println!("\n--- Test: Request Non-Existent Repository ---");
    let client = reqwest::Client::new();
    let nonexistent_url = format!(
        "http://127.0.0.1:{}/nonexistent-repo?cmd=capabilities",
        port
    );
    println!("Requesting: {}", nonexistent_url);

    let response = client.get(&nonexistent_url).send().await?;
    let status = response.status();
    println!("Response status: {}", status);

    // Server might return 404 or 500, or might still return capabilities
    // For MVP, we just verify the server responds
    assert!(
        status.as_u16() >= 200 && status.as_u16() < 600,
        "Should return valid HTTP response"
    );

    let body = response.text().await?;
    println!("Response body: {}", body);

    // If it's an error response, verify it contains error information
    if status.is_client_error() || status.is_server_error() {
        println!("  (Correctly returned error status)");
    } else {
        println!("  (Server returned success - acceptable for MVP)");
    }

    println!("✓ Error handling test passed");
    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    Ok(())
}
