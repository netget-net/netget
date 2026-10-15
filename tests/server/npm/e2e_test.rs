//! End-to-end NPM registry tests for NetGet
//!
//! These tests spawn the actual NetGet binary with NPM registry prompts
//! and validate the responses using HTTP clients and npm CLI.


use crate::server::helpers::{self, E2EResult, NetGetConfig};
use serde_json::{json, Value};
use std::fs;
use std::process::Command;
use std::time::Duration;
use tempfile::TempDir;
use tokio::time::timeout;

/// Run an `npm` subcommand under a wall-clock bound.
///
/// `std::process::Command::output()` blocks the async worker and waits forever. npm
/// retries an unresponsive registry with its own backoff, so a registry that answers
/// wrongly does not fail the test -- it hangs it, and a hung test in a suite run with
/// `--test-threads=100` takes the whole suite with it. This one could not be run to
/// completion at all until it was skipped.
///
/// Bounded, a broken registry produces a failure that names the step and the timeout.
async fn npm(args: &[&str], dir: &std::path::Path, what: &str) -> E2EResult<std::process::Output> {
    let out = timeout(
        Duration::from_secs(60),
        tokio::process::Command::new("npm")
            .args(args)
            .current_dir(dir)
            .output(),
    )
    .await
    .map_err(|_| format!("npm {what} did not finish within 60s"))??;
    Ok(out)
}

#[tokio::test]
async fn test_npm_package_metadata() -> E2EResult<()> {
    println!("\n=== E2E Test: NPM Package Metadata ===");

    // Start NPM registry server
    let prompt = r#"Open NPM registry on port {AVAILABLE_PORT}.
When a client requests package metadata for "express", return this JSON:
{
  "name": "express",
  "version": "4.18.2",
  "description": "Fast, unopinionated, minimalist web framework",
  "main": "index.js",
  "keywords": ["framework", "web", "http"],
  "license": "MIT",
  "dist": {
    "tarball": "http://localhost:{AVAILABLE_PORT}/express/-/express-4.18.2.tgz"
  }
}

For any other package, return a 404 error with: {"error": "Package not found"}"#;

    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: Server startup
            .on_instruction_containing("Open NPM registry")
            .and_instruction_containing("port")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "NPM",
                    "instruction": "NPM registry - serve package metadata"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: package metadata request.
            //
            // The event id is NPM_PACKAGE_REQUEST and the field is `path`. These rules said
            // `http_request` / `uri`, neither of which this protocol ever emits, so they never
            // matched: the mock answered nothing, the request failed, and the failure surfaced
            // as an assertion on the HTTP status rather than on the mock.
            .on_event("NPM_PACKAGE_REQUEST")
            .and_event_data_contains("path", "/express")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "npm_package_metadata",
                    "metadata": json!({
                        "name": "express",
                        "version": "4.18.2",
                        "description": "Fast, unopinionated, minimalist web framework",
                        "main": "index.js",
                        "keywords": ["framework", "web", "http"],
                        "license": "MIT",
                        "dist": {
                            "tarball": "http://localhost:0/express/-/express-4.18.2.tgz"
                        }
                    })
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let mut server = timeout(
        Duration::from_secs(30),
        helpers::start_netget_server(config),
    )
    .await
    .map_err(|_| "Server startup timeout")??;
    println!("NPM registry started on port {}", server.port);

    // Wait for server to be ready
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Request package metadata
    println!("Requesting package metadata for 'express'...");

    let client = reqwest::Client::new();
    let response = match tokio::time::timeout(
        Duration::from_secs(15),
        client
            .get(format!("http://127.0.0.1:{}/express", server.port))
            .send(),
    )
    .await
    {
        Ok(Ok(resp)) => {
            println!("✓ Received HTTP response: {}", resp.status());
            resp
        }
        Ok(Err(e)) => {
            println!("✗ HTTP request error: {}", e);
            return Err(e.into());
        }
        Err(_) => {
            println!("✗ HTTP request timeout");
            return Err("Request timeout".into());
        }
    };

    assert_eq!(response.status(), 200, "Expected HTTP 200 OK");

    // Parse JSON response
    let json: Value = response.json().await?;
    println!("Package metadata: {}", serde_json::to_string_pretty(&json)?);

    // Validate package metadata format
    assert_eq!(
        json.get("name").and_then(|v| v.as_str()),
        Some("express"),
        "Expected package name to be 'express'"
    );

    assert_eq!(
        json.get("version").and_then(|v| v.as_str()),
        Some("4.18.2"),
        "Expected version to be '4.18.2'"
    );

    assert!(
        json.get("description").and_then(|v| v.as_str()).is_some(),
        "Expected description field"
    );

    assert!(
        json.get("dist").and_then(|v| v.get("tarball")).is_some(),
        "Expected dist.tarball field"
    );

    println!("✓ NPM Package Metadata test completed\n");

    // Verify mock expectations were met
    timeout(Duration::from_secs(30), server.verify_mocks())
        .await
        .map_err(|_| "Mock verification timeout")??;

    Ok(())
}

#[tokio::test]
async fn test_npm_package_not_found() -> E2EResult<()> {
    println!("\n=== E2E Test: NPM Package Not Found ===");

    let prompt = r#"Open NPM registry on port {AVAILABLE_PORT}.
When a client requests any package, return a 404 error with JSON: {"error": "Package not found"}"#;

    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: Server startup
            .on_instruction_containing("Open NPM registry")
            .and_instruction_containing("port")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "NPM",
                    "instruction": "NPM registry - return 404 for all packages"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: request for a non-existent package
            .on_event("NPM_PACKAGE_REQUEST")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "npm_error",
                    "error": "Package not found",
                    "status_code": 404
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let mut server = timeout(
        Duration::from_secs(30),
        helpers::start_netget_server(config),
    )
    .await
    .map_err(|_| "Server startup timeout")??;
    println!("NPM registry started on port {}", server.port);

    tokio::time::sleep(Duration::from_millis(500)).await;

    println!("Requesting non-existent package 'nonexistent-pkg'...");

    let client = reqwest::Client::new();
    let response = match tokio::time::timeout(
        Duration::from_secs(15),
        client
            .get(format!("http://127.0.0.1:{}/nonexistent-pkg", server.port))
            .send(),
    )
    .await
    {
        Ok(Ok(resp)) => {
            println!("✓ Received HTTP response: {}", resp.status());
            resp
        }
        Ok(Err(e)) => {
            println!("✗ HTTP request error: {}", e);
            return Err(e.into());
        }
        Err(_) => {
            println!("✗ HTTP request timeout");
            return Err("Request timeout".into());
        }
    };

    assert_eq!(response.status(), 404, "Expected HTTP 404 Not Found");

    let json: Value = response.json().await?;
    println!("Error response: {}", serde_json::to_string_pretty(&json)?);

    assert!(
        json.get("error").and_then(|v| v.as_str()).is_some(),
        "Expected error field in response"
    );

    println!("✓ NPM Package Not Found test completed\n");

    // Verify mock expectations were met
    timeout(Duration::from_secs(30), server.verify_mocks())
        .await
        .map_err(|_| "Mock verification timeout")??;

    Ok(())
}

#[tokio::test]
async fn test_npm_with_real_cli() -> E2EResult<()> {
    println!("\n=== E2E Test: NPM with Real npm CLI ===");

    // The npm CLI *is* the evidence this test exists to produce - it is what makes NPM's
    // Beta rating honest. A machine without it must say so, not report a silent pass: a
    // vacuous green here is exactly how a maturity claim outlives the thing that justified
    // it.
    let npm_version = Command::new("npm").arg("--version").output();
    match npm_version {
        Ok(out) if out.status.success() => {
            println!("npm CLI {}", String::from_utf8_lossy(&out.stdout).trim())
        }
        Ok(out) => {
            return Err(format!(
                "`npm --version` exited {}: this test's whole point is driving the real npm CLI",
                out.status
            )
            .into())
        }
        Err(e) => {
            return Err(format!(
                "npm CLI not available ({e}): this test's whole point is driving the real npm \
                 CLI against NetGet's registry, and skipping it would leave NPM's maturity \
                 rating resting on nothing"
            )
            .into())
        }
    }

    // Create a minimal valid npm tarball for testing
    let temp_dir = TempDir::new()?;
    let pkg_dir = temp_dir.path().join("test-package");
    fs::create_dir(&pkg_dir)?;

    // Create package.json
    let package_json = json!({
        "name": "netget-test-pkg",
        "version": "1.0.0",
        "description": "Test package for NetGet NPM registry",
        "main": "index.js"
    });
    fs::write(
        pkg_dir.join("package.json"),
        serde_json::to_string_pretty(&package_json)?,
    )?;

    // Create index.js
    fs::write(
        pkg_dir.join("index.js"),
        "module.exports = 'Hello from NetGet';\n",
    )?;

    // Create tarball using tar command
    let tarball_path = temp_dir.path().join("netget-test-pkg-1.0.0.tgz");
    let tar_status = Command::new("tar")
        .arg("-czf")
        .arg(&tarball_path)
        .arg("-C")
        .arg(&pkg_dir)
        .arg(".")
        .status()?;

    if !tar_status.success() {
        println!("✗ Failed to create tarball");
        return Err("Tarball creation failed".into());
    }

    // Read tarball and encode as base64
    let tarball_data = fs::read(&tarball_path)?;
    let tarball_base64 = base64::encode(&tarball_data);
    println!(
        "✓ Created test tarball: {} bytes (base64: {} chars)",
        tarball_data.len(),
        tarball_base64.len()
    );

    // Start NPM registry server with the tarball
    let prompt = format!(
        r#"Open NPM registry on port {{AVAILABLE_PORT}}.

When a client requests package metadata for "netget-test-pkg", return:
{{
  "name": "netget-test-pkg",
  "version": "1.0.0",
  "description": "Test package for NetGet NPM registry",
  "main": "index.js",
  "dist": {{
    "tarball": "http://127.0.0.1:{{AVAILABLE_PORT}}/netget-test-pkg/-/netget-test-pkg-1.0.0.tgz"
  }}
}}

When a client requests the tarball at /netget-test-pkg/-/netget-test-pkg-1.0.0.tgz,
use action npm_package_tarball with this base64 data:
{}

For any other package, return 404 error."#,
        tarball_base64
    );

    // The tarball URL in the packument has to name the port the server actually bound,
    // which is not known until it starts -- and the mocks are configured before that. The
    // response closure captures this cell and the test fills it in once the port is known.
    let served_port = std::sync::Arc::new(std::sync::atomic::AtomicU16::new(0));
    let metadata_port = served_port.clone();

    let config = NetGetConfig::new(&prompt)
        .with_mock(move |mock| {
            mock
                // Mock 1: Server startup
                .on_instruction_containing("Open NPM registry")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "NPM",
                        "instruction": "NPM registry - serve package and tarball"
                    }
                ]))
                .expect_calls(1)
                .and()
                // Mock 2: Package metadata request
                .on_event("NPM_PACKAGE_REQUEST")
                .and_event_data_contains("path", "/netget-test-pkg")
                .respond_with_actions_from_event(move |_e| {
                    // A registry packument, not a package.json.
                    //
                    // `GET /<pkg>` must return `dist-tags` and a `versions` map. This used
                    // to return a flat {name, version, description, dist} object, which is
                    // what a package.json looks like -- npm found no versions in it,
                    // printed nothing, and exited 0. `npm view --json` then produced empty
                    // stdout and the test failed inside serde with "EOF while parsing a
                    // value", which names the parser rather than the problem.
                    let port = metadata_port.load(std::sync::atomic::Ordering::SeqCst);
                    serde_json::json!([
                        {
                            "type": "npm_package_metadata",
                            "metadata": json!({
                                "name": "netget-test-pkg",
                                "dist-tags": { "latest": "1.0.0" },
                                "versions": {
                                    "1.0.0": {
                                        "name": "netget-test-pkg",
                                        "version": "1.0.0",
                                        "description": "Test package for NetGet NPM registry",
                                        "main": "index.js",
                                        "dist": {
                                            "tarball": format!("http://127.0.0.1:{port}/netget-test-pkg/-/netget-test-pkg-1.0.0.tgz")
                                        }
                                    }
                                }
                            })
                        }
                    ])
                })
                // npm fetches the packument once for `view` and again for `install`.
                .expect_at_least(1)
                .and()
                // Mock 3: Tarball download request
                .on_event("NPM_TARBALL_REQUEST")
                .and_event_data_contains("path", ".tgz")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "npm_package_tarball",
                        "tarball_data": tarball_base64.clone()
                    }
                ]))
                .expect_at_most(1)
                .and()
        });

    let mut server = timeout(
        Duration::from_secs(30),
        helpers::start_netget_server(config),
    )
    .await
    .map_err(|_| "Server startup timeout")??;
    println!("NPM registry started on port {}", server.port);

    // Now the packument's tarball URL can name a port that exists.
    served_port.store(server.port, std::sync::atomic::Ordering::SeqCst);

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Create a temporary directory for npm install
    let npm_test_dir = TempDir::new()?;
    println!("Created test directory: {:?}", npm_test_dir.path());

    // Configure npm to use our registry
    let npm_config = format!("http://127.0.0.1:{}", server.port);
    println!("Setting npm registry to: {}", npm_config);

    let config_out = npm(
        &[
            "config",
            "set",
            "registry",
            &npm_config,
            "--location=project",
        ],
        npm_test_dir.path(),
        "config set registry",
    )
    .await?;
    let config_status = config_out.status;

    if !config_status.success() {
        println!("✗ Failed to configure npm registry");
        return Err("npm config failed".into());
    }

    // Test: npm view (get package metadata)
    println!("\nTesting: npm view netget-test-pkg...");
    let view_output = npm(
        &[
            "view",
            "netget-test-pkg",
            "--json",
            "--registry",
            &npm_config,
        ],
        npm_test_dir.path(),
        "view netget-test-pkg",
    )
    .await?;

    assert!(
        view_output.status.success(),
        "`npm view` failed against NetGet's registry ({}): {}",
        view_output.status,
        String::from_utf8_lossy(&view_output.stderr)
    );
    // Report what npm actually said before trying to parse it. `npm view --json` can
    // exit 0 having written nothing to stdout, and `serde_json` then fails with
    // "EOF while parsing a value" -- which names the parser and not the problem.
    assert!(
        !view_output.stdout.is_empty(),
        "npm view exited {} with empty stdout. stderr: {}",
        view_output.status,
        String::from_utf8_lossy(&view_output.stderr)
    );
    let view_json: Value = serde_json::from_slice(&view_output.stdout)?;
    assert_eq!(
        view_json.get("name").and_then(|v| v.as_str()),
        Some("netget-test-pkg"),
        "npm resolved a different package than the registry served: {view_json}"
    );
    assert_eq!(
        view_json.get("version").and_then(|v| v.as_str()),
        Some("1.0.0"),
        "npm resolved a different version than the packument's dist-tags named: {view_json}"
    );
    println!("✓ npm view resolved netget-test-pkg@1.0.0 from NetGet");

    // Test: npm install
    println!("\nTesting: npm install netget-test-pkg...");
    let install_output = npm(
        &["install", "netget-test-pkg", "--registry", &npm_config],
        npm_test_dir.path(),
        "install netget-test-pkg",
    )
    .await?;

    assert!(
        install_output.status.success(),
        "`npm install` failed against NetGet's registry ({}): {}",
        install_output.status,
        String::from_utf8_lossy(&install_output.stderr)
    );

    // Installing is the assertion that matters: it means npm fetched the packument, chose a
    // version, downloaded the tarball NetGet served, verified its integrity and unpacked it.
    // A `view` alone only proves the metadata endpoint answers.
    let installed = npm_test_dir
        .path()
        .join("node_modules")
        .join("netget-test-pkg");
    assert!(
        installed.is_dir(),
        "npm install exited 0 but node_modules/netget-test-pkg does not exist. stderr: {}",
        String::from_utf8_lossy(&install_output.stderr)
    );
    let installed_pkg_json = installed.join("package.json");
    assert!(
        installed_pkg_json.is_file(),
        "the installed package has no package.json - the tarball NetGet served did not unpack"
    );
    let unpacked: Value = serde_json::from_slice(&fs::read(&installed_pkg_json)?)?;
    assert_eq!(
        unpacked.get("name").and_then(|v| v.as_str()),
        Some("netget-test-pkg"),
        "the unpacked package.json is not the one the test tarball contained: {unpacked}"
    );
    println!("✓ npm install unpacked NetGet's tarball into node_modules/");

    println!("✓ NPM with Real CLI test completed\n");

    // Verify mock expectations were met
    timeout(Duration::from_secs(30), server.verify_mocks())
        .await
        .map_err(|_| "Mock verification timeout")??;

    Ok(())
}

#[tokio::test]
async fn test_npm_search() -> E2EResult<()> {
    println!("\n=== E2E Test: NPM Search ===");

    let prompt = r#"Open NPM registry on port {AVAILABLE_PORT}.

When a client requests search at /-/v1/search?text=express, return:
{
  "objects": [
    {
      "package": {
        "name": "express",
        "version": "4.18.2",
        "description": "Fast, unopinionated, minimalist web framework",
        "keywords": ["framework", "web", "http"]
      },
      "score": {
        "final": 0.95,
        "detail": {
          "quality": 0.9,
          "popularity": 0.98,
          "maintenance": 0.97
        }
      }
    }
  ],
  "total": 1,
  "time": "Mon Jan 01 2024 00:00:00 GMT+0000"
}

For any other search query, return empty results: {"objects": [], "total": 0}"#;

    let config = NetGetConfig::new(prompt).with_mock(|mock| {
        mock
            // Mock 1: Server startup
            .on_instruction_containing("Open NPM registry")
            .and_instruction_containing("port")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "NPM",
                    "instruction": "NPM registry - handle search requests"
                }
            ]))
            .expect_calls(1)
            .and()
            // Mock 2: Search request
            .on_event("NPM_SEARCH_REQUEST")
            .and_event_data_contains("path", "/search")
            .respond_with_actions(serde_json::json!([
                {
                    // NPM's own verb. `send_http_response` is not in this protocol's
                    // vocabulary, so the server rejected it and answered its fallback.
                    "type": "npm_package_search",
                    "results": json!({
                        "objects": [
                            {
                                "package": {
                                    "name": "express",
                                    "version": "4.18.2",
                                    "description": "Fast, unopinionated, minimalist web framework",
                                    "keywords": ["framework", "web", "http"]
                                },
                                "score": {
                                    "final": 0.95,
                                    "detail": {
                                        "quality": 0.9,
                                        "popularity": 0.98,
                                        "maintenance": 0.97
                                    }
                                }
                            }
                        ],
                        "total": 1,
                        "time": "Mon Jan 01 2024 00:00:00 GMT+0000"
                    })
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let mut server = timeout(
        Duration::from_secs(30),
        helpers::start_netget_server(config),
    )
    .await
    .map_err(|_| "Server startup timeout")??;
    println!("NPM registry started on port {}", server.port);

    tokio::time::sleep(Duration::from_millis(500)).await;

    println!("Searching for 'express'...");

    let client = reqwest::Client::new();
    let response = match tokio::time::timeout(
        Duration::from_secs(15),
        client
            .get(format!(
                "http://127.0.0.1:{}/-/v1/search?text=express",
                server.port
            ))
            .send(),
    )
    .await
    {
        Ok(Ok(resp)) => {
            println!("✓ Received HTTP response: {}", resp.status());
            resp
        }
        Ok(Err(e)) => {
            println!("✗ HTTP request error: {}", e);
            return Err(e.into());
        }
        Err(_) => {
            println!("✗ HTTP request timeout");
            return Err("Request timeout".into());
        }
    };

    assert_eq!(response.status(), 200, "Expected HTTP 200 OK");

    let json: Value = response.json().await?;
    println!("Search results: {}", serde_json::to_string_pretty(&json)?);

    // Validate search results format
    assert!(
        json.get("objects").and_then(|v| v.as_array()).is_some(),
        "Expected 'objects' array"
    );

    let objects = json["objects"].as_array().unwrap();
    assert_eq!(objects.len(), 1, "Expected 1 search result");

    let first_result = &objects[0];
    assert_eq!(
        first_result
            .get("package")
            .and_then(|p| p.get("name"))
            .and_then(|v| v.as_str()),
        Some("express"),
        "Expected package name 'express'"
    );

    println!("✓ NPM Search test completed\n");

    // Verify mock expectations were met
    timeout(Duration::from_secs(30), server.verify_mocks())
        .await
        .map_err(|_| "Mock verification timeout")??;

    Ok(())
}
